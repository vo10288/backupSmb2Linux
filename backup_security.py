"""
backup_security.py — Integrità file, rilevamento anomalie e ransomware.

SECURITY:
- I nomi file per snapshot sono sanitizzati (no path traversal)
- I path vengono validati prima dell'uso
- Il logging è sanitizzato
"""

import os
import json
import random
import hashlib
import logging
import re
from pathlib import Path
from datetime import datetime

logger = logging.getLogger("backup_system")


# ═════════════════════════════════════════════════════════════
#  SECURITY: SANITIZATION
# ═════════════════════════════════════════════════════════════

def sanitize_log_message(msg: str) -> str:
    """Sanitizza un messaggio per il log."""
    if msg is None:
        return ""
    sanitized = str(msg).replace('\n', '\\n').replace('\r', '\\r')
    sanitized = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', '', sanitized)
    return sanitized


def sanitize_source_name(name: str) -> str:
    """
    Sanitizza un nome sorgente per uso come nome file.
    Previene path traversal e caratteri pericolosi.
    """
    if not name:
        return "unknown"
    
    # Rimuovi path traversal
    sanitized = name.replace('..', '_').replace('/', '_').replace('\\', '_')
    
    # Mantieni solo caratteri sicuri: alfanumerici, underscore, trattino, punto
    sanitized = re.sub(r'[^a-zA-Z0-9_.-]', '_', sanitized)
    
    # Rimuovi underscore multipli
    sanitized = re.sub(r'_+', '_', sanitized)
    
    # Limita lunghezza
    sanitized = sanitized[:100]
    
    # Assicurati che non sia vuoto
    return sanitized.strip('_') or "unknown"


def validate_path(path: str, base_path: str = None) -> str:
    """
    Valida e normalizza un path.
    Se base_path è specificato, verifica che path sia sotto di esso.
    """
    if not path:
        raise ValueError("Path vuoto")
    
    normalized = os.path.normpath(os.path.abspath(path))
    
    if base_path:
        base_normalized = os.path.normpath(os.path.abspath(base_path))
        if not normalized.startswith(base_normalized + os.sep) and normalized != base_normalized:
            raise ValueError(f"Path fuori dalla directory consentita")
    
    return normalized


# ═════════════════════════════════════════════════════════════
#  MANIFEST DI INTEGRITÀ (hash dei file)
# ═════════════════════════════════════════════════════════════

def hash_file(filepath: str, algorithm: str = "sha256",
              block_size: int = 65536) -> str:
    """Calcola l'hash di un file."""
    # Valida algoritmo
    allowed_algorithms = ("sha256", "sha512", "sha384", "sha1", "md5")
    if algorithm not in allowed_algorithms:
        logger.warning(f"Algoritmo non supportato: {algorithm}, uso sha256")
        algorithm = "sha256"
    
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
        logger.warning(f"  Hash fallito per {sanitize_log_message(filepath)}: {sanitize_log_message(str(e))}")
        return ""


def collect_file_list(base_path: str, max_files: int = 500000) -> list[dict]:
    """
    Raccoglie la lista di tutti i file con dimensione e mtime.
    Limita il numero di file per prevenire DoS.
    """
    files = []
    
    try:
        validated_base = validate_path(base_path)
    except ValueError as e:
        logger.warning(f"Path non valido: {sanitize_log_message(str(e))}")
        return files
    
    base = Path(validated_base)
    if not base.exists():
        return files

    file_count = 0
    for root, dirs, filenames in os.walk(validated_base):
        # Ignora directory nascoste
        dirs[:] = [d for d in dirs if not d.startswith('.')]
        
        for fname in filenames:
            if file_count >= max_files:
                logger.warning(f"  Raggiunto limite file ({max_files}), scansione troncata")
                return files
            
            # Ignora file nascosti
            if fname.startswith('.'):
                continue
            
            fpath = os.path.join(root, fname)
            
            # Non seguire symlink
            if os.path.islink(fpath):
                continue
            
            try:
                st = os.stat(fpath)
                rel_path = os.path.relpath(fpath, validated_base)
                
                # Verifica che il path relativo non contenga traversal
                if '..' in rel_path.split(os.sep):
                    continue
                
                files.append({
                    "path": rel_path,
                    "size": st.st_size,
                    "mtime": st.st_mtime,
                })
                file_count += 1
            except OSError:
                pass
    
    return files


def verify_integrity(dest_path: str, cfg_integrity: dict,
                     dry_run: bool = False) -> dict:
    """
    Verifica integrità post-backup.
    Calcola hash su un campione casuale di file e salva il manifest.
    """
    result = {"verified": 0, "errors": 0, "manifest_path": "", "error_files": []}

    if not cfg_integrity.get("enabled", False):
        return result

    algorithm = cfg_integrity.get("algorithm", "sha256")
    # Valida algoritmo
    if algorithm not in ("sha256", "sha512", "sha384", "sha1", "md5"):
        algorithm = "sha256"
    
    sample_pct = min(100, max(1, int(cfg_integrity.get("sample_percent", 5))))

    logger.info(f"  Verifica integrità ({algorithm}, campione {sample_pct}%) …")

    if dry_run:
        return result

    try:
        validated_dest = validate_path(dest_path)
    except ValueError as e:
        logger.error(f"  Path destinazione non valido: {sanitize_log_message(str(e))}")
        return result

    all_files = collect_file_list(validated_dest)
    if not all_files:
        logger.warning("  Nessun file trovato per la verifica integrità!")
        return result

    # Seleziona campione casuale
    sample_size = max(1, int(len(all_files) * sample_pct / 100))
    sample = random.sample(all_files, min(sample_size, len(all_files)))

    manifest = {}
    for finfo in sample:
        # Costruisci path in modo sicuro
        fpath = os.path.join(validated_dest, finfo["path"])
        
        # Verifica che sia ancora sotto dest
        try:
            validated_fpath = validate_path(fpath, validated_dest)
        except ValueError:
            continue
        
        h = hash_file(validated_fpath, algorithm)
        if h:
            manifest[finfo["path"]] = {
                "hash": h,
                "size": finfo["size"],
                "algorithm": algorithm,
            }
            result["verified"] += 1

            # Ri-leggi e verifica (doppio check)
            h2 = hash_file(validated_fpath, algorithm)
            if h != h2:
                logger.error(f"  INTEGRITÀ FALLITA: {sanitize_log_message(finfo['path'])} (hash non corrisponde alla rilettura)")
                result["errors"] += 1
                result["error_files"].append(finfo["path"])
        else:
            result["errors"] += 1
            result["error_files"].append(finfo["path"])

    # Salva manifest
    if cfg_integrity.get("save_manifest", True):
        safe_timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        manifest_filename = f".backup_manifest_{safe_timestamp}.json"
        manifest_path = os.path.join(validated_dest, manifest_filename)
        
        try:
            with open(manifest_path, "w", encoding="utf-8") as f:
                json.dump({
                    "timestamp": datetime.now().isoformat(),
                    "algorithm": algorithm,
                    "sample_size": len(sample),
                    "total_files": len(all_files),
                    "files": manifest,
                }, f, indent=2)
            result["manifest_path"] = manifest_path
            logger.info(f"  Manifest salvato: {sanitize_log_message(manifest_path)}")
        except OSError as e:
            logger.error(f"  Impossibile salvare manifest: {sanitize_log_message(str(e))}")

    logger.info(
        f"  Integrità: {result['verified']} file verificati, "
        f"{result['errors']} errori su {len(all_files)} totali"
    )
    return result


# ═════════════════════════════════════════════════════════════
#  ANOMALY DETECTION — Rilevamento ransomware
# ═════════════════════════════════════════════════════════════

def get_snapshot_path(state_dir: str, source_name: str) -> str:
    """Ottiene il path per il file snapshot di una sorgente."""
    safe_name = sanitize_source_name(source_name)
    return os.path.join(state_dir, f"snapshot_{safe_name}.json")


def load_previous_snapshot(state_dir: str, source_name: str) -> dict | None:
    """Carica lo snapshot precedente di una sorgente."""
    try:
        validated_state_dir = validate_path(state_dir)
    except ValueError:
        return None
    
    snap_file = get_snapshot_path(validated_state_dir, source_name)
    
    if not os.path.exists(snap_file):
        return None
    
    try:
        with open(snap_file, "r", encoding="utf-8") as f:
            data = json.load(f)
            if not isinstance(data, dict):
                return None
            return data
    except (json.JSONDecodeError, OSError):
        return None


def save_snapshot(state_dir: str, source_name: str, snapshot: dict):
    """Salva lo snapshot corrente di una sorgente."""
    try:
        validated_state_dir = validate_path(state_dir)
    except ValueError as e:
        logger.error(f"State dir non valido: {sanitize_log_message(str(e))}")
        return
    
    Path(validated_state_dir).mkdir(parents=True, exist_ok=True)
    snap_file = get_snapshot_path(validated_state_dir, source_name)
    
    try:
        with open(snap_file, "w", encoding="utf-8") as f:
            json.dump(snapshot, f, indent=2)
    except OSError as e:
        logger.error(f"Errore salvataggio snapshot: {sanitize_log_message(str(e))}")


def scan_source_for_anomalies(source_path: str, source_name: str,
                              cfg_anomaly: dict, state_dir: str,
                              dry_run: bool = False) -> tuple[bool, str]:
    """
    Analizza una sorgente PRIMA del backup per rilevare anomalie.
    
    Returns:
        (safe, message)
        safe=True → procedi con il backup
        safe=False → BLOCCA il backup (possibile ransomware)
    """
    if not cfg_anomaly.get("enabled", False):
        return True, "anomaly detection disabilitata"

    safe_source_name = sanitize_log_message(source_name)
    logger.info(f"  Scansione anomalie su {safe_source_name} …")

    if dry_run:
        return True, "dry-run"

    try:
        validated_source = validate_path(source_path)
    except ValueError as e:
        return False, f"path sorgente non valido: {sanitize_log_message(str(e))}"

    # Raccogli stato attuale
    current_files = collect_file_list(validated_source)
    current_snapshot = {
        "timestamp": datetime.now().isoformat(),
        "total_files": len(current_files),
        "total_size": sum(f["size"] for f in current_files),
        "extensions": {},
    }

    # Conta estensioni
    for f in current_files:
        ext = Path(f["path"]).suffix.lower()
        # Sanitizza estensione (max 20 caratteri)
        ext = ext[:20]
        current_snapshot["extensions"][ext] = current_snapshot["extensions"].get(ext, 0) + 1

    # Cerca estensioni sospette
    suspicious = cfg_anomaly.get("suspicious_extensions", [])
    found_suspicious = {}
    for ext in suspicious:
        # Normalizza estensione
        ext_clean = ext.lower().strip()[:20]
        count = current_snapshot["extensions"].get(ext_clean, 0)
        if count > 0:
            found_suspicious[ext_clean] = count

    if found_suspicious:
        msg = (
            f"ATTENZIONE: trovate estensioni sospette (possibile ransomware): "
            f"{found_suspicious}"
        )
        logger.critical(sanitize_log_message(msg))
        return False, msg

    # Confronta con snapshot precedente
    prev = load_previous_snapshot(state_dir, source_name)
    if prev is None:
        logger.info(f"  Nessuno snapshot precedente per {safe_source_name}, salvo il primo.")
        save_snapshot(state_dir, source_name, current_snapshot)
        return True, "primo snapshot salvato"

    # Analisi variazione
    prev_total = int(prev.get("total_files", 0))
    curr_total = current_snapshot["total_files"]
    prev_size = int(prev.get("total_size", 0))
    curr_size = current_snapshot["total_size"]

    warnings = []

    # % di file cambiati (approssimazione: confronta conteggio)
    if prev_total > 0:
        file_change_pct = abs(curr_total - prev_total) / prev_total * 100
        max_change = float(cfg_anomaly.get("max_change_percent", 40))
        if file_change_pct > max_change:
            warnings.append(
                f"Variazione file: {file_change_pct:.1f}% (soglia: {max_change}%)"
            )

    # Riduzione dimensione totale
    if prev_size > 0:
        shrink_pct = (prev_size - curr_size) / prev_size * 100
        max_shrink = float(cfg_anomaly.get("max_shrink_percent", 30))
        if shrink_pct > max_shrink:
            warnings.append(
                f"Riduzione dimensione: {shrink_pct:.1f}% (soglia: {max_shrink}%)"
            )

    if warnings:
        msg = f"ANOMALIE RILEVATE su {safe_source_name}: " + "; ".join(warnings)
        logger.critical(sanitize_log_message(msg))
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
