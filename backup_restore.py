#!/usr/bin/env python3
"""
backup_restore.py — Tool interattivo per il ripristino dei backup.

SECURITY:
- Tutti gli input utente vengono validati contro path traversal
- I path vengono normalizzati e controllati prima dell'uso
- Nessun dato utente viene passato direttamente a comandi shell
"""

import os
import re
import sys
import subprocess
from pathlib import Path
from datetime import datetime

import yaml

sys.path.insert(0, os.path.dirname(__file__))
from backup_core import (
    mount_luks_partition, umount_luks_partition,
    is_mounted, safe_umount,
    sanitize_log_message, validate_path
)

WEEKDAY_NAMES = {
    1: "Lunedì", 2: "Martedì", 3: "Mercoledì", 4: "Giovedì",
    5: "Venerdì", 6: "Sabato", 7: "Domenica",
}


# ═════════════════════════════════════════════════════════════
#  SECURITY: INPUT VALIDATION
# ═════════════════════════════════════════════════════════════

def sanitize_filename(name: str) -> str:
    """
    Sanitizza un nome file/directory.
    Rimuove caratteri pericolosi e previene path traversal.
    """
    if not name:
        return ""
    # Rimuovi ../ e ./
    sanitized = re.sub(r'\.\.+[/\\]', '', name)
    sanitized = re.sub(r'^[./\\]+', '', sanitized)
    # Rimuovi caratteri non sicuri (mantieni solo alfanumerici, -, _, ., spazi)
    sanitized = re.sub(r'[^\w\s.\-]', '', sanitized, flags=re.UNICODE)
    return sanitized.strip()


def validate_subpath(subpath: str, base_path: str) -> str:
    """
    Valida un sottopercorso inserito dall'utente.
    Previene path traversal verificando che il risultato sia sotto base_path.
    
    Returns:
        Il path completo validato
        
    Raises:
        ValueError se il path non è sicuro
    """
    if not subpath:
        raise ValueError("Percorso vuoto")
    
    # Normalizza il subpath (rimuovi ../ ecc)
    # Nota: NON usare os.path.join con input non validato!
    clean_subpath = os.path.normpath(subpath)
    
    # Rifiuta path assoluti
    if os.path.isabs(clean_subpath):
        raise ValueError("Percorsi assoluti non consentiti")
    
    # Rifiuta se contiene .. dopo la normalizzazione
    if '..' in clean_subpath.split(os.sep):
        raise ValueError("Path traversal non consentito")
    
    # Costruisci il path completo
    full_path = os.path.normpath(os.path.join(base_path, clean_subpath))
    
    # Verifica che sia effettivamente sotto base_path
    base_resolved = os.path.realpath(base_path)
    full_resolved = os.path.realpath(full_path)
    
    if not full_resolved.startswith(base_resolved + os.sep) and full_resolved != base_resolved:
        raise ValueError(f"Path traversal rilevato: accesso fuori dalla directory consentita")
    
    return full_path


def load_config(path: str) -> dict:
    """Carica la configurazione con validazione del path."""
    validated_path = validate_path(path)
    with open(validated_path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def choose(prompt: str, options: list[str]) -> int:
    """
    Mostra un menu e ritorna l'indice scelto (0-based).
    Gestisce input non validi in modo sicuro.
    """
    print(f"\n{prompt}")
    for i, opt in enumerate(options, 1):
        # Sanitizza le opzioni prima di stamparle
        safe_opt = sanitize_log_message(opt)
        print(f"  {i}. {safe_opt}")
    
    while True:
        try:
            raw_input = input("\nScelta: ")
            # Limita lunghezza input
            if len(raw_input) > 10:
                print("Input troppo lungo.")
                continue
            # Solo numeri
            if not raw_input.strip().isdigit():
                print("Inserisci un numero.")
                continue
            
            choice = int(raw_input.strip()) - 1
            if 0 <= choice < len(options):
                return choice
        except (ValueError, EOFError, KeyboardInterrupt):
            print("\nOperazione annullata.")
            sys.exit(0)
        print("Scelta non valida, riprova.")


def list_sources_in_backup(backup_path: str) -> list[str]:
    """
    Elenca le sorgenti presenti nel backup.
    Filtra nomi di directory non sicuri.
    """
    try:
        validated_path = validate_path(backup_path)
    except ValueError:
        return []
    
    if not os.path.isdir(validated_path):
        return []
    
    sources = []
    try:
        for d in os.listdir(validated_path):
            full_path = os.path.join(validated_path, d)
            # Ignora file nascosti e symlink
            if d.startswith("."):
                continue
            if os.path.islink(full_path):
                continue
            if os.path.isdir(full_path):
                # Sanitizza il nome
                safe_name = sanitize_filename(d)
                if safe_name and safe_name == d:  # Accetta solo nomi già puliti
                    sources.append(d)
    except OSError:
        pass
    
    return sorted(sources)


def browse_directory(path: str, depth: int = 0, max_depth: int = 2):
    """
    Mostra l'albero di una directory fino a max_depth livelli.
    Sicuro: non segue symlink e valida i path.
    """
    if depth > max_depth:
        return
    
    try:
        validated_path = validate_path(path)
    except ValueError:
        return
    
    indent = "  " * depth
    try:
        entries = sorted(os.listdir(validated_path))
    except OSError:
        return

    dirs = []
    files = []
    
    for e in entries:
        # Salta file nascosti
        if e.startswith("."):
            continue
        
        full = os.path.join(validated_path, e)
        
        # Non seguire symlink
        if os.path.islink(full):
            continue
        
        if os.path.isdir(full):
            dirs.append(e)
        else:
            try:
                size = os.path.getsize(full)
                files.append((e, size))
            except OSError:
                files.append((e, 0))

    for d in dirs:
        safe_name = sanitize_log_message(d)
        print(f"{indent}📁 {safe_name}/")
        browse_directory(os.path.join(validated_path, d), depth + 1, max_depth)
    
    for f, size in files[:20]:  # Limita i file mostrati
        safe_name = sanitize_log_message(f)
        sz = f"{size / 1024:.1f}K" if size < 1024 * 1024 else f"{size / (1024**2):.1f}M"
        print(f"{indent}   {safe_name}  ({sz})")
    
    if len(files) > 20:
        print(f"{indent}   … e altri {len(files) - 20} file")


def safe_rsync(src: str, dest: str) -> bool:
    """
    Esegue rsync in modo sicuro.
    Valida i path prima dell'esecuzione.
    """
    try:
        validated_src = validate_path(src)
        validated_dest = validate_path(dest)
    except ValueError as e:
        print(f"Errore validazione path: {e}")
        return False
    
    # Assicurati che le directory esistano
    Path(validated_dest).mkdir(parents=True, exist_ok=True)
    
    # Costruisci il comando rsync
    cmd = [
        "rsync", "-avh", "--progress",
        validated_src.rstrip("/") + "/",
        validated_dest.rstrip("/") + "/",
    ]
    
    print(f"Eseguo: rsync {validated_src} → {validated_dest}")
    
    try:
        result = subprocess.run(cmd, check=False)
        return result.returncode == 0
    except Exception as e:
        print(f"Errore rsync: {e}")
        return False


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Restore interattivo")
    parser.add_argument("-c", "--config", default="/etc/backup_system/config.yaml")
    args = parser.parse_args()

    try:
        cfg = load_config(args.config)
    except (ValueError, FileNotFoundError, yaml.YAMLError) as e:
        print(f"Errore caricamento config: {e}")
        sys.exit(1)
    
    sec = cfg.get("security", {})
    dry_run = False

    print("=" * 55)
    print("  RESTORE INTERATTIVO — Backup Rotazionale v2.0")
    print("=" * 55)

    # 1. Scegli il giorno
    parts = cfg["destinations"]["partitions"]
    day_options = [
        f"Giorno {d} — {WEEKDAY_NAMES.get(d, '?')} ({parts[d].get('label', 'N/A')})"
        for d in sorted(parts.keys())
    ]
    day_idx = choose("Da quale giorno vuoi ripristinare?", day_options)
    day_num = sorted(parts.keys())[day_idx]
    part = parts[day_num]

    # 2. Monta la partizione
    base = cfg["destinations"]["base_mount_point"]
    
    try:
        mp = validate_path(os.path.join(base, f"day_{day_num}"))
    except ValueError as e:
        print(f"Errore path: {e}")
        sys.exit(1)

    print(f"\nMonto la partizione del {WEEKDAY_NAMES.get(day_num)} …")
    if not mount_luks_partition(part, mp, sec, dry_run):
        print("ERRORE: impossibile montare la partizione!")
        sys.exit(1)

    try:
        # 3. Scegli la sorgente
        sources = list_sources_in_backup(mp)
        if not sources:
            print("Nessuna sorgente trovata nel backup!")
            return

        src_idx = choose("Quale sorgente vuoi ripristinare?", sources)
        src_name = sources[src_idx]
        
        try:
            src_path = validate_subpath(src_name, mp)
        except ValueError as e:
            print(f"Errore: {e}")
            return

        # 4. Mostra contenuto
        print(f"\nContenuto di {sanitize_log_message(src_name)}:")
        print("-" * 40)
        browse_directory(src_path)
        print("-" * 40)

        # 5. Scegli cosa ripristinare
        action = choose("Cosa vuoi fare?", [
            "Ripristinare TUTTO nella directory di staging",
            "Ripristinare una sottocartella specifica",
            "Copiare singoli file manualmente (ti mostro il path)",
        ])

        staging = cfg.get("restore", {}).get("staging_dir", "/mnt/restore_staging")
        try:
            validated_staging = validate_path(staging)
            Path(validated_staging).mkdir(parents=True, exist_ok=True)
        except ValueError as e:
            print(f"Errore staging dir: {e}")
            return

        if action == 0:
            # Restore completo
            dest = os.path.join(validated_staging, sanitize_filename(src_name))
            print(f"\nRipristino {sanitize_log_message(src_name)} → {dest}")
            confirm = input("Confermi? (s/N): ").strip().lower()
            if confirm == "s":
                if safe_rsync(src_path, dest):
                    print(f"\n✅ Ripristino completato in: {dest}")
                else:
                    print("\n❌ Ripristino fallito!")
            else:
                print("Annullato.")

        elif action == 1:
            # Sottocartella
            subdir = input("Inserisci il percorso relativo della sottocartella: ").strip()
            
            # Limita lunghezza input
            if len(subdir) > 500:
                print("Percorso troppo lungo.")
                return
            
            try:
                sub_full = validate_subpath(subdir, src_path)
            except ValueError as e:
                print(f"Errore: {e}")
                return
            
            if not os.path.exists(sub_full):
                print(f"Percorso non trovato.")
                return
            
            dest = os.path.join(validated_staging, sanitize_filename(src_name), 
                               sanitize_filename(os.path.basename(subdir)))
            
            print(f"\nRipristino {sanitize_log_message(subdir)} → {dest}")
            confirm = input("Confermi? (s/N): ").strip().lower()
            if confirm == "s":
                if safe_rsync(sub_full, dest):
                    print(f"\n✅ Ripristino completato in: {dest}")
                else:
                    print("\n❌ Ripristino fallito!")
            else:
                print("Annullato.")

        elif action == 2:
            print(f"\nLa partizione è montata in: {mp}")
            print(f"Il backup è in: {src_path}")
            print("Puoi copiare i file manualmente con cp o rsync.")
            input("\nPremi INVIO quando hai finito per smontare la partizione …")

    finally:
        # 6. Smonta
        print("Smonto la partizione …")
        umount_luks_partition(part, mp, sec, dry_run)
        print("Partizione smontata. ✅")


if __name__ == "__main__":
    main()
