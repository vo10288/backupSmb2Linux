"""
backup_security.py — Integrità file, rilevamento anomalie e ransomware.
"""

import os
import json
import random
import hashlib
import logging
from pathlib import Path
from datetime import datetime

logger = logging.getLogger("backup_system")


# ═════════════════════════════════════════════════════════════
#  MANIFEST DI INTEGRITÀ (hash dei file)
# ═════════════════════════════════════════════════════════════

def hash_file(filepath: str, algorithm: str = "sha256",
              block_size: int = 65536) -> str:
    """Calcola l'hash di un file."""
    h = hashlib.new(algorithm)
    try:
        with open(filepath, "rb") as f:
            while True:
                block = f.read(block_size)
                if not block:
                    break
                h.update(block)
        return h.hexdigest()
    except (OSError, IOError) as e:
        logger.warning(f"  Hash fallito per {filepath}: {e}")
        return ""


def collect_file_list(base_path: str) -> list[dict]:
    """Raccoglie la lista di tutti i file con dimensione e mtime."""
    files = []
    base = Path(base_path)
    if not base.exists():
        return files

    for root, dirs, filenames in os.walk(base):
        for fname in filenames:
            fpath = os.path.join(root, fname)
            try:
                st = os.stat(fpath)
                files.append({
                    "path": os.path.relpath(fpath, base_path),
                    "size": st.st_size,
                    "mtime": st.st_mtime,
                })
            except OSError:
                pass
    return files


def verify_integrity(dest_path: str, cfg_integrity: dict,
                     dry_run: bool = False) -> dict:
    """
    Verifica integrità post-backup.
    Calcola hash su un campione casuale di file e salva il manifest.
    Ritorna: {"verified": int, "errors": int, "manifest_path": str}
    """
    result = {"verified": 0, "errors": 0, "manifest_path": "", "error_files": []}

    if not cfg_integrity.get("enabled", False):
        return result

    algorithm = cfg_integrity.get("algorithm", "sha256")
    sample_pct = cfg_integrity.get("sample_percent", 5)

    logger.info(f"  Verifica integrità ({algorithm}, campione {sample_pct}%) …")

    if dry_run:
        return result

    all_files = collect_file_list(dest_path)
    if not all_files:
        logger.warning("  Nessun file trovato per la verifica integrità!")
        return result

    # Seleziona campione casuale
    sample_size = max(1, int(len(all_files) * sample_pct / 100))
    sample = random.sample(all_files, min(sample_size, len(all_files)))

    manifest = {}
    for finfo in sample:
        fpath = os.path.join(dest_path, finfo["path"])
        h = hash_file(fpath, algorithm)
        if h:
            manifest[finfo["path"]] = {
                "hash": h,
                "size": finfo["size"],
                "algorithm": algorithm,
            }
            result["verified"] += 1

            # Ri-leggi e verifica (doppio check)
            h2 = hash_file(fpath, algorithm)
            if h != h2:
                logger.error(f"  INTEGRITÀ FALLITA: {finfo['path']} (hash non corrisponde alla rilettura)")
                result["errors"] += 1
                result["error_files"].append(finfo["path"])
        else:
            result["errors"] += 1
            result["error_files"].append(finfo["path"])

    # Salva manifest
    if cfg_integrity.get("save_manifest", True):
        manifest_path = os.path.join(dest_path, f".backup_manifest_{datetime.now():%Y%m%d_%H%M%S}.json")
        try:
            with open(manifest_path, "w") as f:
                json.dump({
                    "timestamp": datetime.now().isoformat(),
                    "algorithm": algorithm,
                    "sample_size": len(sample),
                    "total_files": len(all_files),
                    "files": manifest,
                }, f, indent=2)
            result["manifest_path"] = manifest_path
            logger.info(f"  Manifest salvato: {manifest_path}")
        except OSError as e:
            logger.error(f"  Impossibile salvare manifest: {e}")

    logger.info(
        f"  Integrità: {result['verified']} file verificati, "
        f"{result['errors']} errori su {len(all_files)} totali"
    )
    return result


# ═════════════════════════════════════════════════════════════
#  ANOMALY DETECTION — Rilevamento ransomware
# ═════════════════════════════════════════════════════════════

def load_previous_snapshot(state_dir: str, source_name: str) -> dict | None:
    """Carica lo snapshot precedente di una sorgente."""
    snap_file = os.path.join(state_dir, f"snapshot_{source_name}.json")
    if not os.path.exists(snap_file):
        return None
    try:
        with open(snap_file, "r") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return None


def save_snapshot(state_dir: str, source_name: str, snapshot: dict):
    """Salva lo snapshot corrente di una sorgente."""
    Path(state_dir).mkdir(parents=True, exist_ok=True)
    snap_file = os.path.join(state_dir, f"snapshot_{source_name}.json")
    with open(snap_file, "w") as f:
        json.dump(snapshot, f)


def scan_source_for_anomalies(source_path: str, source_name: str,
                              cfg_anomaly: dict, state_dir: str,
                              dry_run: bool = False) -> tuple[bool, str]:
    """
    Analizza una sorgente PRIMA del backup per rilevare anomalie.
    Ritorna: (safe, message)
      safe=True → procedi con il backup
      safe=False → BLOCCA il backup (possibile ransomware)
    """
    if not cfg_anomaly.get("enabled", False):
        return True, "anomaly detection disabilitata"

    logger.info(f"  Scansione anomalie su {source_name} …")

    if dry_run:
        return True, "dry-run"

    # Raccogli stato attuale
    current_files = collect_file_list(source_path)
    current_snapshot = {
        "timestamp": datetime.now().isoformat(),
        "total_files": len(current_files),
        "total_size": sum(f["size"] for f in current_files),
        "extensions": {},
    }

    # Conta estensioni
    for f in current_files:
        ext = Path(f["path"]).suffix.lower()
        current_snapshot["extensions"][ext] = current_snapshot["extensions"].get(ext, 0) + 1

    # Cerca estensioni sospette
    suspicious = cfg_anomaly.get("suspicious_extensions", [])
    found_suspicious = {}
    for ext in suspicious:
        count = current_snapshot["extensions"].get(ext, 0)
        if count > 0:
            found_suspicious[ext] = count

    if found_suspicious:
        msg = (
            f"ATTENZIONE: trovate estensioni sospette (possibile ransomware): "
            f"{found_suspicious}"
        )
        logger.critical(msg)
        return False, msg

    # Confronta con snapshot precedente
    prev = load_previous_snapshot(state_dir, source_name)
    if prev is None:
        logger.info(f"  Nessuno snapshot precedente per {source_name}, salvo il primo.")
        save_snapshot(state_dir, source_name, current_snapshot)
        return True, "primo snapshot salvato"

    # Analisi variazione
    prev_total = prev.get("total_files", 0)
    curr_total = current_snapshot["total_files"]
    prev_size = prev.get("total_size", 0)
    curr_size = current_snapshot["total_size"]

    warnings = []

    # % di file cambiati (approssimazione: confronta conteggio)
    if prev_total > 0:
        file_change_pct = abs(curr_total - prev_total) / prev_total * 100
        max_change = cfg_anomaly.get("max_change_percent", 40)
        if file_change_pct > max_change:
            warnings.append(
                f"Variazione file: {file_change_pct:.1f}% (soglia: {max_change}%)"
            )

    # Riduzione dimensione totale
    if prev_size > 0:
        shrink_pct = (prev_size - curr_size) / prev_size * 100
        max_shrink = cfg_anomaly.get("max_shrink_percent", 30)
        if shrink_pct > max_shrink:
            warnings.append(
                f"Riduzione dimensione: {shrink_pct:.1f}% (soglia: {max_shrink}%)"
            )

    if warnings:
        msg = f"ANOMALIE RILEVATE su {source_name}: " + "; ".join(warnings)
        logger.critical(msg)
        # NON aggiornare lo snapshot (conserva il riferimento "buono")
        return False, msg

    # Tutto ok: aggiorna snapshot
    save_snapshot(state_dir, source_name, current_snapshot)
    logger.info(
        f"  Anomaly check OK: {curr_total} file, "
        f"{curr_size / (1024**3):.2f} GB (delta: "
        f"{curr_total - prev_total:+d} file, "
        f"{(curr_size - prev_size) / (1024**2):+.1f} MB)"
    )
    return True, "ok"
