#!/usr/bin/env python3
"""
backup_restore.py — Tool interattivo per il ripristino dei backup.
"""

import os
import sys
import subprocess
from pathlib import Path
from datetime import datetime

import yaml

sys.path.insert(0, os.path.dirname(__file__))
from backup_core import (
    mount_luks_partition, umount_luks_partition,
    is_mounted, safe_umount
)

WEEKDAY_NAMES = {
    1: "Lunedì", 2: "Martedì", 3: "Mercoledì", 4: "Giovedì",
    5: "Venerdì", 6: "Sabato", 7: "Domenica",
}


def load_config(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def choose(prompt: str, options: list[str]) -> int:
    """Mostra un menu e ritorna l'indice scelto (0-based)."""
    print(f"\n{prompt}")
    for i, opt in enumerate(options, 1):
        print(f"  {i}. {opt}")
    while True:
        try:
            choice = int(input("\nScelta: ")) - 1
            if 0 <= choice < len(options):
                return choice
        except (ValueError, EOFError):
            pass
        print("Scelta non valida, riprova.")


def list_sources_in_backup(backup_path: str) -> list[str]:
    """Elenca le sorgenti presenti nel backup."""
    if not os.path.isdir(backup_path):
        return []
    return sorted([
        d for d in os.listdir(backup_path)
        if os.path.isdir(os.path.join(backup_path, d))
        and not d.startswith(".")
    ])


def browse_directory(path: str, depth: int = 0, max_depth: int = 2):
    """Mostra l'albero di una directory fino a max_depth livelli."""
    if depth > max_depth:
        return
    indent = "  " * depth
    try:
        entries = sorted(os.listdir(path))
    except OSError:
        return

    dirs = []
    files = []
    for e in entries:
        full = os.path.join(path, e)
        if os.path.isdir(full):
            dirs.append(e)
        else:
            size = os.path.getsize(full) if os.path.exists(full) else 0
            files.append((e, size))

    for d in dirs:
        print(f"{indent}📁 {d}/")
        browse_directory(os.path.join(path, d), depth + 1, max_depth)
    for f, size in files[:20]:  # Limita i file mostrati
        sz = f"{size / 1024:.1f}K" if size < 1024 * 1024 else f"{size / (1024**2):.1f}M"
        print(f"{indent}   {f}  ({sz})")
    if len(files) > 20:
        print(f"{indent}   … e altri {len(files) - 20} file")


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Restore interattivo")
    parser.add_argument("-c", "--config", default="/etc/backup_system/config.yaml")
    args = parser.parse_args()

    cfg = load_config(args.config)
    sec = cfg.get("security", {})
    dry_run = False

    print("=" * 55)
    print("  RESTORE INTERATTIVO — Backup Rotazionale v2.0")
    print("=" * 55)

    # 1. Scegli il giorno
    parts = cfg["destinations"]["partitions"]
    day_options = [
        f"Giorno {d} — {WEEKDAY_NAMES.get(d, '?')} ({parts[d]['label']})"
        for d in sorted(parts.keys())
    ]
    day_idx = choose("Da quale giorno vuoi ripristinare?", day_options)
    day_num = sorted(parts.keys())[day_idx]
    part = parts[day_num]

    # 2. Monta la partizione
    base = cfg["destinations"]["base_mount_point"]
    mp = os.path.join(base, f"day_{day_num}")

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
        src_path = os.path.join(mp, src_name)

        # 4. Mostra contenuto
        print(f"\nContenuto di {src_name}:")
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
        Path(staging).mkdir(parents=True, exist_ok=True)

        if action == 0:
            # Restore completo
            dest = os.path.join(staging, src_name)
            print(f"\nRipristino {src_name} → {dest}")
            confirm = input("Confermi? (s/N): ").strip().lower()
            if confirm == "s":
                cmd = ["rsync", "-avh", "--progress",
                       src_path.rstrip("/") + "/",
                       dest.rstrip("/") + "/"]
                subprocess.run(cmd)
                print(f"\n✅ Ripristino completato in: {dest}")
            else:
                print("Annullato.")

        elif action == 1:
            # Sottocartella
            subdir = input("Inserisci il percorso relativo della sottocartella: ").strip()
            sub_full = os.path.join(src_path, subdir)
            if not os.path.exists(sub_full):
                print(f"Percorso non trovato: {sub_full}")
                return
            dest = os.path.join(staging, src_name, subdir)
            print(f"\nRipristino {subdir} → {dest}")
            confirm = input("Confermi? (s/N): ").strip().lower()
            if confirm == "s":
                cmd = ["rsync", "-avh", "--progress",
                       sub_full.rstrip("/") + "/",
                       dest.rstrip("/") + "/"]
                subprocess.run(cmd)
                print(f"\n✅ Ripristino completato in: {dest}")
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
