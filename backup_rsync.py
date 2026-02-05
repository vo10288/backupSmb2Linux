"""
backup_rsync.py — Esecuzione rsync con retry, parsing statistiche, parallelismo.
"""

import os
import subprocess
import time
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional
from concurrent.futures import ThreadPoolExecutor, as_completed

logger = logging.getLogger("backup_system")


@dataclass
class BackupResult:
    source_name: str
    success: bool = False
    start_time: datetime = field(default_factory=datetime.now)
    end_time: Optional[datetime] = None
    files_transferred: int = 0
    files_total: int = 0
    bytes_transferred: int = 0
    bytes_total: int = 0
    error_message: str = ""
    skipped: bool = False
    skip_reason: str = ""
    integrity_verified: int = 0
    integrity_errors: int = 0
    anomaly_blocked: bool = False

    @property
    def elapsed_seconds(self) -> float:
        if self.end_time and self.start_time:
            return (self.end_time - self.start_time).total_seconds()
        return 0

    @property
    def speed_mbps(self) -> float:
        if self.elapsed_seconds > 0 and self.bytes_transferred > 0:
            return (self.bytes_transferred / (1024 ** 2)) / self.elapsed_seconds
        return 0

    def to_dict(self) -> dict:
        return {
            "source_name": self.source_name,
            "success": self.success,
            "start_time": self.start_time.isoformat() if self.start_time else None,
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "elapsed_seconds": round(self.elapsed_seconds, 1),
            "files_transferred": self.files_transferred,
            "files_total": self.files_total,
            "bytes_transferred": self.bytes_transferred,
            "bytes_total": self.bytes_total,
            "speed_mbps": round(self.speed_mbps, 2),
            "error_message": self.error_message,
            "skipped": self.skipped,
            "skip_reason": self.skip_reason,
            "integrity_verified": self.integrity_verified,
            "integrity_errors": self.integrity_errors,
            "anomaly_blocked": self.anomaly_blocked,
        }


def parse_rsync_stats(output: str) -> dict:
    """Parsing avanzato delle statistiche rsync."""
    stats = {
        "files_transferred": 0,
        "files_total": 0,
        "bytes_transferred": 0,
        "bytes_total": 0,
    }

    for line in output.splitlines():
        stripped = line.strip().lower()

        # Number of files: 1,234 (reg: 1,000, dir: 200, ...)
        m = re.search(r"number of files:\s*([\d,]+)", stripped)
        if m:
            stats["files_total"] = int(m.group(1).replace(",", ""))

        # Number of regular files transferred: 456
        m = re.search(r"number of regular files transferred:\s*([\d,]+)", stripped)
        if m:
            stats["files_transferred"] = int(m.group(1).replace(",", ""))

        # Total transferred file size: 1,234,567 bytes
        m = re.search(r"total transferred file size:\s*([\d,]+)", stripped)
        if m:
            stats["bytes_transferred"] = int(m.group(1).replace(",", ""))

        # Total file size: 9,876,543 bytes
        m = re.search(r"total file size:\s*([\d,]+)", stripped)
        if m:
            stats["bytes_total"] = int(m.group(1).replace(",", ""))

    return stats


def run_rsync(source_path: str, dest_path: str, excludes: list,
              cfg_rsync: dict, dry_run: bool = False,
              retries: int = 1, retry_delay: int = 30) -> BackupResult:
    """Esegue rsync incrementale con retry."""
    result = BackupResult(source_name=source_path)
    result.start_time = datetime.now()

    dest = Path(dest_path)
    dest.mkdir(parents=True, exist_ok=True)

    cmd = [
        "rsync",
        "-avh",               # archive + verbose + human-readable
        "--delete",            # incrementale: cancella file rimossi dalla sorgente
        "--delete-during",     # cancella durante il trasferimento (più veloce)
        "--stats",             # statistiche dettagliate
        "--partial",           # mantieni file parziali (resume)
        "--partial-dir=.rsync-partial",
        "--info=progress2",
        "--itemize-changes",   # mostra cosa cambia (utile per i log)
        "--numeric-ids",       # mantieni UID/GID numerici
    ]

    bw = cfg_rsync.get("bandwidth_limit_kbps", 0)
    if bw and bw > 0:
        cmd.append(f"--bwlimit={bw}")

    for pattern in excludes:
        cmd += ["--exclude", pattern]

    for extra in cfg_rsync.get("extra_args", []):
        cmd.append(extra)

    timeout = cfg_rsync.get("timeout_seconds", 14400)

    # Trailing slash per rsync (copia il CONTENUTO, non la directory stessa)
    src = source_path.rstrip("/") + "/"
    cmd += [src, dest_path.rstrip("/") + "/"]

    for attempt in range(1, retries + 1):
        logger.info(f"  rsync (tentativo {attempt}/{retries}): {source_path} → {dest_path}")
        logger.debug(f"  CMD: {' '.join(cmd)}")

        if dry_run:
            result.success = True
            result.end_time = datetime.now()
            return result

        try:
            proc = subprocess.run(
                cmd, capture_output=True, text=True, timeout=timeout
            )
            result.end_time = datetime.now()

            # Parsing statistiche
            stats = parse_rsync_stats(proc.stdout)
            result.files_transferred = stats["files_transferred"]
            result.files_total = stats["files_total"]
            result.bytes_transferred = stats["bytes_transferred"]
            result.bytes_total = stats["bytes_total"]

            if proc.returncode == 0:
                result.success = True
                logger.info(
                    f"  rsync OK — {result.files_transferred:,} file trasferiti "
                    f"({result.bytes_transferred / (1024**2):,.1f} MB) in "
                    f"{result.elapsed_seconds:.0f}s "
                    f"({result.speed_mbps:.1f} MB/s)"
                )
                return result

            elif proc.returncode == 24:
                # "Vanished files" — normale su share Windows attive
                result.success = True
                logger.warning(
                    "  rsync codice 24 (file scomparsi durante copia, ignorato)"
                )
                return result

            else:
                result.error_message = proc.stderr.strip()[-500:]
                logger.warning(
                    f"  rsync fallito (rc={proc.returncode}): {result.error_message}"
                )

        except subprocess.TimeoutExpired:
            result.error_message = f"Timeout dopo {timeout}s"
            result.end_time = datetime.now()
            logger.error(f"  rsync TIMEOUT ({timeout}s)")

        except Exception as exc:
            result.error_message = str(exc)
            result.end_time = datetime.now()
            logger.error(f"  rsync ECCEZIONE: {exc}")

        # Retry
        if attempt < retries:
            logger.info(f"  Attendo {retry_delay}s prima del prossimo tentativo …")
            time.sleep(retry_delay)

    result.success = False
    if not result.end_time:
        result.end_time = datetime.now()
    logger.error(f"  rsync FALLITO dopo {retries} tentativi: {source_path}")
    return result


def backup_source(src: dict, dest_mount_point: str, cfg: dict,
                  dry_run: bool = False) -> list[BackupResult]:
    """
    Esegue il backup completo di una singola sorgente.
    Ritorna una lista di BackupResult (uno per ogni include_path o uno totale).
    """
    from backup_core import mount_source, safe_umount, pre_check_source, free_space_gb
    from backup_security import scan_source_for_anomalies, verify_integrity

    name = src["name"]
    results = []
    cfg_rsync = cfg.get("rsync", {})
    cfg_res = cfg.get("resilience", {})
    cfg_sec = cfg.get("security", {})
    state_dir = cfg["general"].get("state_dir", "/var/lib/backup_system")

    logger.info(f"═══ Sorgente: {name} ═══")

    # 1. Pre-check
    ok, msg = pre_check_source(src, cfg_res)
    if not ok:
        res = BackupResult(source_name=name, skipped=True, skip_reason=msg)
        res.end_time = datetime.now()
        logger.error(f"  Pre-check fallito: {msg}")
        results.append(res)
        return results

    # 2. Mount sorgente
    retries = cfg_res.get("mount_retries", 3)
    delay = cfg_res.get("mount_retry_base_delay", 5)
    if not mount_source(src, retries=retries, retry_delay=delay, dry_run=dry_run):
        res = BackupResult(source_name=name, skipped=True,
                           skip_reason="Mount sorgente fallito")
        res.end_time = datetime.now()
        results.append(res)
        return results

    try:
        # 3. Anomaly detection
        cfg_anomaly = cfg_sec.get("anomaly_detection", {})
        safe, anomaly_msg = scan_source_for_anomalies(
            src["mount_point"], name, cfg_anomaly, state_dir, dry_run
        )
        if not safe:
            res = BackupResult(
                source_name=name, anomaly_blocked=True,
                error_message=anomaly_msg
            )
            res.end_time = datetime.now()
            logger.critical(f"  BACKUP BLOCCATO per anomalia: {anomaly_msg}")
            results.append(res)
            return results

        # 4. Verifica spazio disco
        min_free = cfg_res.get("min_free_space_gb", 10)
        if not dry_run:
            free = free_space_gb(dest_mount_point)
            if free < min_free:
                res = BackupResult(
                    source_name=name, skipped=True,
                    skip_reason=f"Spazio insufficiente: {free:.1f} GB < {min_free} GB"
                )
                res.end_time = datetime.now()
                logger.error(f"  Spazio insufficiente: {free:.1f} GB liberi")
                results.append(res)
                return results

        # 5. Rsync
        include_paths = src.get("include_paths", [])
        excludes = src.get("exclude_patterns", [])
        dest_base = os.path.join(dest_mount_point, name)
        rsync_retries = cfg_res.get("rsync_retries", 2)
        rsync_delay = cfg_res.get("rsync_retry_delay", 30)

        if include_paths:
            for subpath in include_paths:
                src_full = os.path.join(src["mount_point"], subpath)
                dst_full = os.path.join(dest_base, subpath)
                res = run_rsync(
                    src_full, dst_full, excludes, cfg_rsync,
                    dry_run, rsync_retries, rsync_delay
                )
                res.source_name = f"{name}/{subpath}"
                results.append(res)
        else:
            res = run_rsync(
                src["mount_point"], dest_base, excludes, cfg_rsync,
                dry_run, rsync_retries, rsync_delay
            )
            res.source_name = name
            results.append(res)

        # 6. Verifica integrità post-backup
        cfg_integrity = cfg_sec.get("integrity", {})
        if cfg_integrity.get("enabled", False) and any(r.success for r in results):
            integrity = verify_integrity(dest_base, cfg_integrity, dry_run)
            for r in results:
                r.integrity_verified = integrity["verified"]
                r.integrity_errors = integrity["errors"]

    finally:
        # Smonta sorgente
        safe_umount(src["mount_point"], dry_run)

    return results


def backup_sources_parallel(sources: list, dest_mount_point: str,
                            cfg: dict, dry_run: bool = False,
                            max_workers: int = 1) -> list[BackupResult]:
    """Esegue il backup di più sorgenti in parallelo."""
    all_results = []

    # Ordina per priorità
    sorted_sources = sorted(sources, key=lambda s: s.get("priority", 5))

    if max_workers <= 1:
        # Sequenziale
        for src in sorted_sources:
            results = backup_source(src, dest_mount_point, cfg, dry_run)
            all_results.extend(results)
    else:
        # Parallelo
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {
                executor.submit(backup_source, src, dest_mount_point, cfg, dry_run): src
                for src in sorted_sources
            }
            for future in as_completed(futures):
                src = futures[future]
                try:
                    results = future.result()
                    all_results.extend(results)
                except Exception as exc:
                    logger.error(f"  Eccezione per {src['name']}: {exc}")
                    res = BackupResult(
                        source_name=src["name"],
                        error_message=str(exc)
                    )
                    res.end_time = datetime.now()
                    all_results.append(res)

    return all_results
