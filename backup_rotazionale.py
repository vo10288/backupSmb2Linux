#!/usr/bin/env python3
"""
═══════════════════════════════════════════════════════════════
  SISTEMA DI BACKUP ROTAZIONALE v2.0
═══════════════════════════════════════════════════════════════
  Funzionalità:
    ✓ Mount share Windows CIFS (sola lettura)
    ✓ Partizione giornaliera rotazionale (1=Lun … 7=Dom)
    ✓ Crittografia LUKS con key file
    ✓ Anomaly/Ransomware detection pre-backup
    ✓ Backup incrementale rsync con retry
    ✓ Verifica integrità post-backup (hash SHA256)
    ✓ Snapshot mensili con retention
    ✓ Pre-check sorgenti (ping + SMB)
    ✓ Parallelismo configurabile
    ✓ Report JSON + storico
    ✓ Notifiche email + webhook
    ✓ Dashboard web
    ✓ Healthcheck endpoint
    ✓ Restore interattivo

  Requisiti:
    Python 3.10+, rsync, cifs-utils, cryptsetup, smbclient, flask, pyyaml

  Eseguire come root.
═══════════════════════════════════════════════════════════════
"""

import sys
import os
import signal
import logging
import fcntl
import time
from datetime import datetime
from pathlib import Path

import yaml

# Aggiungi la directory dello script al path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from backup_core import (
    mount_luks_partition, umount_luks_partition,
    ensure_all_destinations_offline, free_space_gb
)
from backup_rsync import backup_sources_parallel, BackupResult
from backup_retention import create_monthly_snapshot
from backup_notify import save_report, send_all_notifications


WEEKDAY_NAMES = {
    1: "Lunedì", 2: "Martedì", 3: "Mercoledì", 4: "Giovedì",
    5: "Venerdì", 6: "Sabato", 7: "Domenica",
}


# ═════════════════════════════════════════════════════════════
#  CONFIG + LOGGING
# ═════════════════════════════════════════════════════════════

def load_config(path: str) -> dict:
    config_path = Path(path)
    if not config_path.exists():
        sys.exit(f"[FATAL] Config non trovata: {path}")
    with open(config_path, "r", encoding="utf-8") as fh:
        cfg = yaml.safe_load(fh)

    assert "sources" in cfg, "Sezione 'sources' mancante"
    assert "destinations" in cfg, "Sezione 'destinations' mancante"
    today = datetime.now().isoweekday()
    assert today in cfg["destinations"]["partitions"], \
        f"Nessuna partizione per il giorno {today}"
    return cfg


def setup_logging(cfg: dict) -> logging.Logger:
    log_dir = Path(cfg["general"].get("log_dir", "/var/log/backup_system"))
    log_dir.mkdir(parents=True, exist_ok=True)
    log_file = log_dir / f"backup_{datetime.now():%Y%m%d_%H%M%S}.log"

    logger = logging.getLogger("backup_system")
    logger.setLevel(getattr(logging, cfg["general"].get("log_level", "INFO")))

    fmt = logging.Formatter(
        "%(asctime)s [%(levelname)-7s] %(message)s", datefmt="%Y-%m-%d %H:%M:%S"
    )

    fh = logging.FileHandler(log_file, encoding="utf-8")
    fh.setFormatter(fmt)
    logger.addHandler(fh)

    sh = logging.StreamHandler(sys.stdout)
    sh.setFormatter(fmt)
    logger.addHandler(sh)

    return logger


# ═════════════════════════════════════════════════════════════
#  LOCK FILE
# ═════════════════════════════════════════════════════════════

class LockFile:
    def __init__(self, path: str):
        self.path = path
        self._fh = None

    def acquire(self) -> bool:
        try:
            self._fh = open(self.path, "w")
            fcntl.flock(self._fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self._fh.write(str(os.getpid()))
            self._fh.flush()
            return True
        except (IOError, OSError):
            return False

    def release(self):
        if self._fh:
            try:
                fcntl.flock(self._fh, fcntl.LOCK_UN)
                self._fh.close()
                os.unlink(self.path)
            except OSError:
                pass


# ═════════════════════════════════════════════════════════════
#  MAIN
# ═════════════════════════════════════════════════════════════

def main(config_path: str = "/etc/backup_system/config.yaml"):
    cfg = load_config(config_path)
    logger = setup_logging(cfg)
    dry_run = cfg["general"].get("dry_run", False)
    state_dir = cfg["general"].get("state_dir", "/var/lib/backup_system")
    Path(state_dir).mkdir(parents=True, exist_ok=True)

    today = datetime.now().isoweekday()
    day_name = WEEKDAY_NAMES.get(today, "?")

    logger.info("=" * 60)
    logger.info(f"BACKUP ROTAZIONALE v2.0 — {day_name} (giorno {today})")
    logger.info(f"Avvio: {datetime.now():%Y-%m-%d %H:%M:%S}")
    logger.info(f"Sorgenti configurate: {len(cfg['sources'])}")
    if dry_run:
        logger.info("*** DRY-RUN ***")
    logger.info("=" * 60)

    # Lock
    lock = LockFile(cfg["general"].get("lock_file", "/var/run/backup_system.lock"))
    if not lock.acquire():
        logger.error("Altra istanza in esecuzione. Esco.")
        sys.exit(1)

    results: list[BackupResult] = []
    dest_mount_point = ""
    dest_part = cfg["destinations"]["partitions"][today]
    cfg_security = cfg.get("security", {})
    cfg_resilience = cfg.get("resilience", {})

    try:
        # ── FASE 1: Tutte le destinazioni offline ──
        logger.info("Fase 1 — Verifica tutte le destinazioni offline …")
        ensure_all_destinations_offline(cfg, dry_run)

        # ── FASE 2: Mount partizione del giorno (LUKS + mount) ──
        base = cfg["destinations"]["base_mount_point"]
        dest_mount_point = os.path.join(base, f"day_{today}")

        logger.info(
            f"Fase 2 — Mount giorno {today}: "
            f"{dest_part['device']} → {dest_mount_point}"
        )
        mount_retries = cfg_resilience.get("mount_retries", 3)
        mount_delay = cfg_resilience.get("mount_retry_base_delay", 5)

        if not mount_luks_partition(
            dest_part, dest_mount_point, cfg_security, dry_run,
            retries=mount_retries, retry_delay=mount_delay
        ):
            raise RuntimeError(
                f"Impossibile montare {dest_part['device']} per giorno {today}"
            )

        # Verifica spazio disco
        if not dry_run:
            free = free_space_gb(dest_mount_point)
            min_free = cfg_resilience.get("min_free_space_gb", 10)
            logger.info(f"  Spazio libero: {free:.1f} GB (minimo: {min_free} GB)")
            if free < min_free:
                raise RuntimeError(
                    f"Spazio insufficiente: {free:.1f} GB < {min_free} GB"
                )

        # ── FASE 3: Backup sorgenti ──
        logger.info(f"Fase 3 — Backup {len(cfg['sources'])} sorgenti …")
        workers = cfg["general"].get("parallel_workers", 1)
        results = backup_sources_parallel(
            cfg["sources"], dest_mount_point, cfg, dry_run, workers
        )

        # ── FASE 4: Snapshot mensile ──
        logger.info("Fase 4 — Snapshot mensile …")
        create_monthly_snapshot(dest_mount_point, cfg, dry_run)

    except Exception as exc:
        logger.critical(f"ERRORE CRITICO: {exc}", exc_info=True)
        # Aggiungi un result di errore generico
        if not results:
            results.append(BackupResult(
                source_name="SISTEMA",
                error_message=str(exc),
            ))
    finally:
        # ── FASE 5: Smontaggio totale ──
        logger.info("Fase 5 — Smontaggio …")

        if dest_mount_point:
            time.sleep(2)
            umount_luks_partition(dest_part, dest_mount_point, cfg_security, dry_run)

        # Controllo paranoico
        ensure_all_destinations_offline(cfg, dry_run)
        lock.release()

    # ── FASE 6: Report e notifiche ──
    logger.info("Fase 6 — Report e notifiche …")

    all_ok = all(
        r.success for r in results
        if not r.skipped and not r.anomaly_blocked
    )
    blocked = [r for r in results if r.anomaly_blocked]

    save_report(results, today, state_dir)

    logger.info("=" * 60)
    logger.info("RIEPILOGO")
    logger.info("=" * 60)

    for r in results:
        if r.anomaly_blocked:
            icon = "🚫"
        elif r.skipped:
            icon = "⏭️ "
        elif r.success:
            icon = "✅"
        else:
            icon = "❌"

        elapsed = f" ({r.elapsed_seconds:.0f}s)" if r.elapsed_seconds else ""
        line = f"  {icon} {r.source_name}{elapsed}"
        if r.error_message:
            line += f" — {r.error_message[:80]}"
        if r.skip_reason:
            line += f" — {r.skip_reason}"
        logger.info(line)

    if blocked:
        logger.critical(
            f"⚠️  {len(blocked)} sorgenti BLOCCATE per anomalia! "
            "Verificare manualmente."
        )

    if all_ok and not blocked:
        logger.info("Tutti i backup completati con successo. ✅")
    else:
        logger.warning("Ci sono errori o blocchi — controllare il log.")

    logger.info(f"Fine: {datetime.now():%Y-%m-%d %H:%M:%S}")
    logger.info("=" * 60)

    send_all_notifications(cfg, results, today)

    sys.exit(0 if (all_ok and not blocked) else 1)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="Sistema di Backup Rotazionale v2.0"
    )
    parser.add_argument(
        "-c", "--config",
        default="/etc/backup_system/config.yaml",
        help="Percorso file di configurazione",
    )
    args = parser.parse_args()
    main(args.config)
