"""
backup_retention.py — Snapshot mensili e politiche di retention.
"""

import os
import json
import shutil
import logging
from pathlib import Path
from datetime import datetime, timedelta

from backup_core import (
    safe_mount, safe_umount, mount_luks_partition, umount_luks_partition,
    is_mounted, free_space_gb
)

logger = logging.getLogger("backup_system")


def get_state_file(state_dir: str) -> str:
    return os.path.join(state_dir, "retention_state.json")


def load_retention_state(state_dir: str) -> dict:
    path = get_state_file(state_dir)
    if os.path.exists(path):
        try:
            with open(path) as f:
                return json.load(f)
        except (json.JSONDecodeError, OSError):
            pass
    return {"monthly_snapshots": {}}


def save_retention_state(state_dir: str, state: dict):
    Path(state_dir).mkdir(parents=True, exist_ok=True)
    with open(get_state_file(state_dir), "w") as f:
        json.dump(state, f, indent=2)


def should_create_monthly_snapshot(state: dict) -> bool:
    """Il primo backup del mese crea uno snapshot mensile."""
    now = datetime.now()
    month_key = now.strftime("%Y-%m")
    return month_key not in state.get("monthly_snapshots", {})


def create_monthly_snapshot(today_dest_path: str, cfg: dict,
                            dry_run: bool = False) -> bool:
    """
    Copia il backup del giorno corrente nella partizione degli snapshot mensili.
    """
    retention = cfg.get("retention", {}).get("monthly_snapshots", {})
    if not retention.get("enabled", False):
        return True

    state_dir = cfg["general"].get("state_dir", "/var/lib/backup_system")
    state = load_retention_state(state_dir)

    if not should_create_monthly_snapshot(state):
        logger.info("  Snapshot mensile: già creato per questo mese, salto.")
        return True

    now = datetime.now()
    month_key = now.strftime("%Y-%m")
    logger.info(f"  Creazione snapshot mensile per {month_key} …")

    if dry_run:
        state.setdefault("monthly_snapshots", {})[month_key] = {
            "date": now.isoformat(),
            "dry_run": True,
        }
        save_retention_state(state_dir, state)
        return True

    # Monta la partizione snapshot
    snap_dir = retention.get("snapshot_dir", "/mnt/backup_archive/monthly")
    part_info = {
        "device": retention["device"],
        "luks_name": retention.get("luks_name", ""),
        "fstype": retention.get("fstype", "ext4"),
        "mount_options": retention.get("mount_options", ""),
    }
    cfg_security = cfg.get("security", {})

    if not mount_luks_partition(part_info, snap_dir, cfg_security, dry_run):
        logger.error("  Impossibile montare partizione snapshot mensile!")
        return False

    try:
        # Crea directory mese
        month_dir = os.path.join(snap_dir, month_key)
        Path(month_dir).mkdir(parents=True, exist_ok=True)

        # Rsync dal backup giornaliero allo snapshot mensile
        import subprocess
        cmd = [
            "rsync", "-avh", "--delete",
            today_dest_path.rstrip("/") + "/",
            month_dir.rstrip("/") + "/",
        ]
        logger.info(f"  rsync snapshot: {' '.join(cmd)}")
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=14400)

        if result.returncode not in (0, 24):
            logger.error(f"  Snapshot rsync fallito: {result.stderr.strip()[:300]}")
            return False

        # Aggiorna stato
        state.setdefault("monthly_snapshots", {})[month_key] = {
            "date": now.isoformat(),
            "path": month_dir,
        }
        save_retention_state(state_dir, state)
        logger.info(f"  Snapshot mensile {month_key} creato in {month_dir}")

        # Pulizia vecchi snapshot
        purge_old_monthly(snap_dir, retention.get("keep_months", 6), state, state_dir)

        return True

    finally:
        umount_luks_partition(part_info, snap_dir, cfg_security, dry_run)


def purge_old_monthly(snap_dir: str, keep_months: int, state: dict, state_dir: str):
    """Elimina snapshot mensili più vecchi di keep_months."""
    now = datetime.now()
    cutoff = now - timedelta(days=keep_months * 31)
    cutoff_key = cutoff.strftime("%Y-%m")

    monthly = state.get("monthly_snapshots", {})
    to_remove = []

    for month_key, info in monthly.items():
        if month_key < cutoff_key:
            path = info.get("path", "")
            if path and os.path.isdir(path):
                logger.info(f"  Pulizia snapshot vecchio: {month_key} ({path})")
                try:
                    shutil.rmtree(path)
                except OSError as e:
                    logger.error(f"  Errore pulizia {path}: {e}")
            to_remove.append(month_key)

    for key in to_remove:
        del monthly[key]

    if to_remove:
        save_retention_state(state_dir, state)
        logger.info(f"  Rimossi {len(to_remove)} snapshot mensili obsoleti.")
