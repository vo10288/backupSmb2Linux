"""
backup_retention.py — Snapshot mensili e politiche di retention.

SECURITY:
- Path validati contro traversal
- Nomi file sanitizzati
- Logging sanitizzato
"""

import os
import json
import shutil
import logging
import re
from pathlib import Path
from datetime import datetime, timedelta

from backup_core import (
    safe_mount, safe_umount, mount_luks_partition, umount_luks_partition,
    is_mounted, free_space_gb, sanitize_log_message, validate_path
)

logger = logging.getLogger("backup_system")


# ═════════════════════════════════════════════════════════════
#  SECURITY: PATH VALIDATION
# ═════════════════════════════════════════════════════════════

def validate_month_key(key: str) -> str:
    """
    Valida una chiave mese nel formato YYYY-MM.
    Previene injection di path malevoli.
    """
    if not key:
        raise ValueError("Chiave mese vuota")
    
    # Deve essere esattamente nel formato YYYY-MM
    if not re.match(r'^\d{4}-\d{2}$', key):
        raise ValueError(f"Formato chiave mese non valido: {key}")
    
    # Verifica che sia un mese valido
    try:
        year, month = map(int, key.split('-'))
        if not (1 <= month <= 12 and 2000 <= year <= 2100):
            raise ValueError(f"Mese/anno non valido: {key}")
    except (ValueError, TypeError):
        raise ValueError(f"Chiave mese non valida: {key}")
    
    return key


def validate_state_dir(state_dir: str) -> str:
    """Valida e normalizza la directory di stato."""
    return validate_path(state_dir)


def get_state_file(state_dir: str) -> str:
    """Ottiene il path del file di stato retention."""
    validated_dir = validate_state_dir(state_dir)
    return os.path.join(validated_dir, "retention_state.json")


def load_retention_state(state_dir: str) -> dict:
    """Carica lo stato retention in modo sicuro."""
    try:
        path = get_state_file(state_dir)
    except ValueError as e:
        logger.error(f"State dir non valida: {sanitize_log_message(str(e))}")
        return {"monthly_snapshots": {}}
    
    if os.path.exists(path):
        try:
            with open(path, encoding="utf-8") as f:
                data = json.load(f)
                if not isinstance(data, dict):
                    return {"monthly_snapshots": {}}
                # Valida la struttura
                if "monthly_snapshots" not in data:
                    data["monthly_snapshots"] = {}
                return data
        except (json.JSONDecodeError, OSError) as e:
            logger.warning(f"Errore caricamento stato retention: {sanitize_log_message(str(e))}")
    
    return {"monthly_snapshots": {}}


def save_retention_state(state_dir: str, state: dict):
    """Salva lo stato retention in modo sicuro."""
    try:
        validated_dir = validate_state_dir(state_dir)
        Path(validated_dir).mkdir(parents=True, exist_ok=True)
        
        state_file = get_state_file(state_dir)
        
        with open(state_file, "w", encoding="utf-8") as f:
            json.dump(state, f, indent=2)
    except (ValueError, OSError) as e:
        logger.error(f"Errore salvataggio stato retention: {sanitize_log_message(str(e))}")


def should_create_monthly_snapshot(state: dict) -> bool:
    """Il primo backup del mese crea uno snapshot mensile."""
    now = datetime.now()
    month_key = now.strftime("%Y-%m")
    
    try:
        validate_month_key(month_key)
    except ValueError:
        return False
    
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
    
    try:
        validate_state_dir(state_dir)
    except ValueError as e:
        logger.error(f"State dir non valida: {sanitize_log_message(str(e))}")
        return False
    
    state = load_retention_state(state_dir)

    if not should_create_monthly_snapshot(state):
        logger.info("  Snapshot mensile: già creato per questo mese, salto.")
        return True

    now = datetime.now()
    month_key = now.strftime("%Y-%m")
    
    try:
        validate_month_key(month_key)
    except ValueError as e:
        logger.error(f"Chiave mese non valida: {sanitize_log_message(str(e))}")
        return False
    
    logger.info(f"  Creazione snapshot mensile per {month_key} …")

    if dry_run:
        state.setdefault("monthly_snapshots", {})[month_key] = {
            "date": now.isoformat(),
            "dry_run": True,
        }
        save_retention_state(state_dir, state)
        return True

    # Valida path sorgente
    try:
        validated_src = validate_path(today_dest_path)
    except ValueError as e:
        logger.error(f"Path sorgente non valido: {sanitize_log_message(str(e))}")
        return False

    # Monta la partizione snapshot
    snap_dir = retention.get("snapshot_dir", "/mnt/backup_archive/monthly")
    
    try:
        validate_path(snap_dir)
    except ValueError as e:
        logger.error(f"Snapshot dir non valida: {sanitize_log_message(str(e))}")
        return False
    
    device = retention.get("device", "")
    if not device:
        logger.error("  Device per snapshot mensile non configurato!")
        return False
    
    part_info = {
        "device": device,
        "luks_name": retention.get("luks_name", ""),
        "fstype": retention.get("fstype", "ext4"),
        "mount_options": retention.get("mount_options", ""),
    }
    cfg_security = cfg.get("security", {})

    if not mount_luks_partition(part_info, snap_dir, cfg_security, dry_run):
        logger.error("  Impossibile montare partizione snapshot mensile!")
        return False

    try:
        # Crea directory mese (usa month_key già validato)
        month_dir = os.path.join(snap_dir, month_key)
        
        try:
            validated_month_dir = validate_path(month_dir)
        except ValueError as e:
            logger.error(f"Path mese non valido: {sanitize_log_message(str(e))}")
            return False
        
        Path(validated_month_dir).mkdir(parents=True, exist_ok=True)

        # Rsync dal backup giornaliero allo snapshot mensile
        import subprocess
        cmd = [
            "rsync", "-avh", "--delete",
            validated_src.rstrip("/") + "/",
            validated_month_dir.rstrip("/") + "/",
        ]
        logger.info(f"  rsync snapshot: {sanitize_log_message(validated_src)} → {sanitize_log_message(validated_month_dir)}")
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=14400)

        if result.returncode not in (0, 24):
            logger.error(f"  Snapshot rsync fallito: {sanitize_log_message(result.stderr.strip()[:300])}")
            return False

        # Aggiorna stato
        state.setdefault("monthly_snapshots", {})[month_key] = {
            "date": now.isoformat(),
            "path": validated_month_dir,
        }
        save_retention_state(state_dir, state)
        logger.info(f"  Snapshot mensile {month_key} creato in {sanitize_log_message(validated_month_dir)}")

        # Pulizia vecchi snapshot
        keep_months = max(1, int(retention.get("keep_months", 6)))
        purge_old_monthly(snap_dir, keep_months, state, state_dir)

        return True

    except Exception as e:
        logger.error(f"  Errore creazione snapshot: {sanitize_log_message(str(e))}")
        return False

    finally:
        umount_luks_partition(part_info, snap_dir, cfg_security, dry_run)


def purge_old_monthly(snap_dir: str, keep_months: int, state: dict, state_dir: str):
    """Elimina snapshot mensili più vecchi di keep_months."""
    now = datetime.now()
    cutoff = now - timedelta(days=keep_months * 31)
    cutoff_key = cutoff.strftime("%Y-%m")

    try:
        validate_month_key(cutoff_key)
    except ValueError:
        return

    monthly = state.get("monthly_snapshots", {})
    to_remove = []

    for month_key, info in list(monthly.items()):
        # Valida la chiave
        try:
            validate_month_key(month_key)
        except ValueError:
            # Chiave non valida, rimuovila
            to_remove.append(month_key)
            continue
        
        if month_key < cutoff_key:
            path = info.get("path", "")
            if path:
                try:
                    validated_path = validate_path(path)
                    # Verifica che il path sia effettivamente sotto snap_dir
                    validated_snap_dir = validate_path(snap_dir)
                    
                    if not validated_path.startswith(validated_snap_dir):
                        logger.warning(f"  Path snapshot fuori dalla directory: {sanitize_log_message(path)}")
                        to_remove.append(month_key)
                        continue
                    
                    if os.path.isdir(validated_path):
                        logger.info(f"  Pulizia snapshot vecchio: {month_key} ({sanitize_log_message(validated_path)})")
                        shutil.rmtree(validated_path)
                except ValueError as e:
                    logger.warning(f"  Path non valido per snapshot {month_key}: {sanitize_log_message(str(e))}")
                except OSError as e:
                    logger.error(f"  Errore pulizia {sanitize_log_message(path)}: {sanitize_log_message(str(e))}")
            
            to_remove.append(month_key)

    for key in to_remove:
        if key in monthly:
            del monthly[key]

    if to_remove:
        save_retention_state(state_dir, state)
        logger.info(f"  Rimossi {len(to_remove)} snapshot mensili obsoleti.")
