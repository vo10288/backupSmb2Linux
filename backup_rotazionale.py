#!/usr/bin/env python3
"""
SISTEMA DI BACKUP ROTAZIONALE v2.0

SECURITY:
  - Input validation su tutti i path
  - Logging sanitizzato (no log injection)
  - Nessun uso di shell=True
  - Protezione path traversal
  - XSS protection nella dashboard

Requisiti:
  Python 3.10+, rsync, cifs-utils, cryptsetup, smbclient, flask, pyyaml

Eseguire come root.
"""

import sys
import os
import logging
import fcntl
import time
from datetime import datetime
from pathlib import Path

import yaml

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from backup_core import (
    mount_luks_partition, umount_luks_partition,
    ensure_all_destinations_offline, free_space_gb,
    sanitize_log_message, validate_path
)
from backup_rsync import backup_sources_parallel, BackupResult
from backup_retention import create_monthly_snapshot
from backup_notify import save_report, send_all_notifications


WEEKDAY_NAMES = {
    1: "Lunedi", 2: "Martedi", 3: "Mercoledi", 4: "Giovedi",
    5: "Venerdi", 6: "Sabato", 7: "Domenica",
}


def load_config(path: str) -> dict:
    """Carica e valida la configurazione."""
    try:
        config_path = validate_path(path)
    except ValueError as e:
        sys.exit(f"[FATAL] Path config non valido: {e}")
    
    if not Path(config_path).exists():
        sys.exit(f"[FATAL] Config non trovata: {config_path}")
    
    with open(config_path, "r", encoding="utf-8") as fh:
        cfg = yaml.safe_load(fh)

    if not cfg or not isinstance(cfg, dict):
        sys.exit("[FATAL] Config vuota o non valida")
    
    if "sources" not in cfg:
        sys.exit("[FATAL] Sezione 'sources' mancante")
    if "destinations" not in cfg:
        sys.exit("[FATAL] Sezione 'destinations' mancante")
    
    today = datetime.now().isoweekday()
    if today not in cfg["destinations"].get("partitions", {}):
        sys.exit(f"[FATAL] Nessuna partizione per il giorno {today}")
    
    return cfg


def setup_logging(cfg: dict) -> logging.Logger:
    """Configura il logging in modo sicuro."""
    log_dir_str = cfg.get("general", {}).get("log_dir", "/var/log/backup_system")
    
    try:
        log_dir = Path(validate_path(log_dir_str))
    except ValueError:
        log_dir = Path("/var/log/backup_system")
    
    log_dir.mkdir(parents=True, exist_ok=True)
    
    safe_timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_file = log_dir / f"backup_{safe_timestamp}.log"

    logger = logging.getLogger("backup_system")
    log_level = cfg.get("general", {}).get("log_level", "INFO")
    
    valid_levels = ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL")
    if log_level.upper() not in valid_levels:
        log_level = "INFO"
    
    logger.setLevel(getattr(logging, log_level.upper()))

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


class LockFile:
    """Gestione lock file per evitare esecuzioni parallele."""
    
    def __init__(self, path: str):
        try:
            self.path = validate_path(path)
        except ValueError:
            self.path = "/var/run/backup_system.lock"
        self._fh = None

    def acquire(self) -> bool:
        try:
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
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


def main(config_path: str = "/etc/backup_system/config.yaml"):
    """Entry point principale."""
    cfg = load_config(config_path)
    logger = setup_logging(cfg)
    dry_run = cfg.get("general", {}).get("dry_run", False)
    state_dir = cfg.get("general", {}).get("state_dir", "/var/lib/backup_system")
    
    try:
        validated_state_dir = validate_path(state_dir)
        Path(validated_state_dir).mkdir(parents=True, exist_ok=True)
    except ValueError:
        validated_state_dir = "/var/lib/backup_system"
        Path(validated_state_dir).mkdir(parents=True, exist_ok=True)

    today = datetime.now().isoweekday()
    day_name = WEEKDAY_NAMES.get(today, "?")

    logger.info("=" * 60)
    logger.info(f"BACKUP ROTAZIONALE v2.0 - {day_name} (giorno {today})")
    logger.info(f"Avvio: {datetime.now():%Y-%m-%d %H:%M:%S}")
    logger.info(f"Sorgenti configurate: {len(cfg.get('sources', []))}")
    if dry_run:
        logger.info("*** DRY-RUN ***")
    logger.info("=" * 60)

    lock_path = cfg.get("general", {}).get("lock_file", "/var/run/backup_system.lock")
    lock = LockFile(lock_path)
    if not lock.acquire():
        logger.error("Altra istanza in esecuzione. Esco.")
        sys.exit(1)

    results = []
    dest_mount_point = ""
    dest_part = cfg["destinations"]["partitions"][today]
    cfg_security = cfg.get("security", {})
    cfg_resilience = cfg.get("resilience", {})

    try:
        logger.info("Fase 1 - Verifica tutte le destinazioni offline")
        ensure_all_destinations_offline(cfg, dry_run)

        base = cfg["destinations"]["base_mount_point"]
        try:
            validated_base = validate_path(base)
        except ValueError as e:
            raise RuntimeError(f"Base mount point non valido: {e}")
        
        dest_mount_point = os.path.join(validated_base, f"day_{today}")

        device = dest_part.get("device", "")
        logger.info(f"Fase 2 - Mount giorno {today}: {sanitize_log_message(device)} -> {sanitize_log_message(dest_mount_point)}")
        
        mount_retries = int(cfg_resilience.get("mount_retries", 3))
        mount_delay = int(cfg_resilience.get("mount_retry_base_delay", 5))

        if not mount_luks_partition(
            dest_part, dest_mount_point, cfg_security, dry_run,
            retries=mount_retries, retry_delay=mount_delay
        ):
            raise RuntimeError(f"Impossibile montare {device} per giorno {today}")

        if not dry_run:
            try:
                free = free_space_gb(dest_mount_point)
                min_free = float(cfg_resilience.get("min_free_space_gb", 10))
                logger.info(f"  Spazio libero: {free:.1f} GB (minimo: {min_free} GB)")
                if free < min_free:
                    raise RuntimeError(f"Spazio insufficiente: {free:.1f} GB < {min_free} GB")
            except Exception as e:
                if "Spazio insufficiente" in str(e):
                    raise
                logger.warning(f"Errore verifica spazio: {sanitize_log_message(str(e))}")

        logger.info(f"Fase 3 - Backup {len(cfg.get('sources', []))} sorgenti")
        workers = int(cfg.get("general", {}).get("parallel_workers", 1))
        results = backup_sources_parallel(
            cfg.get("sources", []), dest_mount_point, cfg, dry_run, workers
        )

        logger.info("Fase 4 - Snapshot mensile")
        create_monthly_snapshot(dest_mount_point, cfg, dry_run)

    except Exception as exc:
        logger.critical(f"ERRORE CRITICO: {sanitize_log_message(str(exc))}", exc_info=True)
        if not results:
            results.append(BackupResult(
                source_name="SISTEMA",
                error_message=sanitize_log_message(str(exc))[:500],
            ))
    finally:
        logger.info("Fase 5 - Smontaggio")
        if dest_mount_point:
            time.sleep(2)
            umount_luks_partition(dest_part, dest_mount_point, cfg_security, dry_run)
        ensure_all_destinations_offline(cfg, dry_run)
        lock.release()

    logger.info("Fase 6 - Report e notifiche")

    all_ok = all(
        getattr(r, 'success', False) for r in results
        if not getattr(r, 'skipped', False) and not getattr(r, 'anomaly_blocked', False)
    )
    blocked = [r for r in results if getattr(r, 'anomaly_blocked', False)]

    save_report(results, today, validated_state_dir)

    logger.info("=" * 60)
    logger.info("RIEPILOGO")
    logger.info("=" * 60)

    for r in results:
        if getattr(r, 'anomaly_blocked', False):
            icon = "[BLOCKED]"
        elif getattr(r, 'skipped', False):
            icon = "[SKIP]"
        elif getattr(r, 'success', False):
            icon = "[OK]"
        else:
            icon = "[FAIL]"

        elapsed = getattr(r, 'elapsed_seconds', 0)
        elapsed_str = f" ({elapsed:.0f}s)" if elapsed else ""
        source_name = sanitize_log_message(getattr(r, 'source_name', 'unknown'))
        line = f"  {icon} {source_name}{elapsed_str}"
        
        error_msg = getattr(r, 'error_message', '')
        skip_reason = getattr(r, 'skip_reason', '')
        
        if error_msg:
            line += f" - {sanitize_log_message(error_msg)[:80]}"
        if skip_reason:
            line += f" - {sanitize_log_message(skip_reason)}"
        logger.info(line)

    if blocked:
        logger.critical(f"!!! {len(blocked)} sorgenti BLOCCATE per anomalia! Verificare manualmente.")

    if all_ok and not blocked:
        logger.info("Tutti i backup completati con successo.")
    else:
        logger.warning("Ci sono errori o blocchi - controllare il log.")

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
