"""
backup_core.py — Funzioni fondamentali: mount, umount, LUKS, pre-check, spazio disco.
"""

import os
import subprocess
import time
import logging
from pathlib import Path

logger = logging.getLogger("backup_system")


# ═════════════════════════════════════════════════════════════
#  UTILITÀ DI BASE
# ═════════════════════════════════════════════════════════════

def run_cmd(cmd: list[str], timeout: int = 60, check: bool = False,
            capture: bool = True) -> subprocess.CompletedProcess:
    """Wrapper per subprocess.run con logging."""
    logger.debug(f"CMD: {' '.join(cmd)}")
    return subprocess.run(
        cmd, capture_output=capture, text=True, timeout=timeout, check=check
    )


def is_mounted(mount_point: str) -> bool:
    result = run_cmd(["mountpoint", "-q", mount_point], timeout=5)
    return result.returncode == 0


def free_space_gb(path: str) -> float:
    """Spazio libero in GB su un mount point."""
    st = os.statvfs(path)
    return (st.f_bavail * st.f_frsize) / (1024 ** 3)


# ═════════════════════════════════════════════════════════════
#  PRE-CHECK SORGENTI
# ═════════════════════════════════════════════════════════════

def ping_host(host: str, timeout: int = 3) -> bool:
    result = run_cmd(["ping", "-c", "1", "-W", str(timeout), host], timeout=timeout + 2)
    return result.returncode == 0


def check_smb_share(unc: str, credentials_file: str, timeout: int = 10) -> bool:
    """Verifica che la share SMB sia raggiungibile con smbclient."""
    cmd = [
        "smbclient", unc, "--authentication-file", credentials_file,
        "-c", "exit", "--timeout", str(timeout),
    ]
    result = run_cmd(cmd, timeout=timeout + 5)
    return result.returncode == 0


def pre_check_source(src: dict, cfg_resilience: dict) -> tuple[bool, str]:
    """Esegue pre-check su una sorgente. Ritorna (ok, messaggio)."""
    if not cfg_resilience.get("pre_check", {}).get("enabled", False):
        return True, "pre-check disabilitato"

    host = src.get("host", "")
    if not host:
        # Estrai host da UNC
        unc = src.get("unc", "")
        parts = unc.replace("\\", "/").strip("/").split("/")
        host = parts[0] if parts else ""

    if not host:
        return True, "nessun host configurato per il check"

    ping_tout = cfg_resilience["pre_check"].get("ping_timeout", 3)
    if not ping_host(host, ping_tout):
        return False, f"host {host} non raggiungibile (ping timeout {ping_tout}s)"

    if src.get("type") == "cifs":
        smb_tout = cfg_resilience["pre_check"].get("smb_timeout", 10)
        cred = src.get("credentials_file", "")
        if cred and not check_smb_share(src["unc"], cred, smb_tout):
            return False, f"share {src['unc']} non accessibile (smbclient timeout {smb_tout}s)"

    return True, "ok"


# ═════════════════════════════════════════════════════════════
#  MOUNT / UMOUNT CON RETRY
# ═════════════════════════════════════════════════════════════

def safe_mount(device: str, mount_point: str, fstype: str = "",
               options: str = "", dry_run: bool = False,
               retries: int = 1, retry_delay: int = 5) -> bool:
    """Monta con retry e backoff esponenziale."""
    mp = Path(mount_point)
    mp.mkdir(parents=True, exist_ok=True)

    if is_mounted(mount_point):
        logger.info(f"  Già montato: {mount_point}")
        return True

    cmd = ["mount"]
    if fstype:
        cmd += ["-t", fstype]
    if options:
        cmd += ["-o", options]
    cmd += [device, mount_point]

    for attempt in range(1, retries + 1):
        logger.info(f"  Mount (tentativo {attempt}/{retries}): {' '.join(cmd)}")
        if dry_run:
            return True

        result = run_cmd(cmd, timeout=60)
        if result.returncode == 0:
            return True

        err = result.stderr.strip()
        logger.warning(f"  Mount fallito: {err}")

        if attempt < retries:
            delay = retry_delay * (2 ** (attempt - 1))
            logger.info(f"  Attendo {delay}s prima del prossimo tentativo …")
            time.sleep(delay)

    logger.error(f"  Mount FALLITO dopo {retries} tentativi: {device}")
    return False


def safe_umount(mount_point: str, dry_run: bool = False, force: bool = False) -> bool:
    if not is_mounted(mount_point):
        return True

    cmd = ["umount"]
    if force:
        cmd.append("-l")
    cmd.append(mount_point)

    logger.info(f"  Umount: {' '.join(cmd)}")
    if dry_run:
        return True

    result = run_cmd(cmd, timeout=60)
    if result.returncode != 0:
        if not force:
            logger.warning(f"  Umount fallito, riprovo con lazy …")
            return safe_umount(mount_point, dry_run, force=True)
        logger.error(f"  Umount FALLITO: {mount_point}")
        return False
    return True


# ═════════════════════════════════════════════════════════════
#  LUKS — Crittografia partizioni
# ═════════════════════════════════════════════════════════════

def luks_is_open(luks_name: str) -> bool:
    return Path(f"/dev/mapper/{luks_name}").exists()


def luks_open(device: str, luks_name: str, key_file: str,
              timeout: int = 30, dry_run: bool = False) -> bool:
    """Apre un volume LUKS con key file."""
    if luks_is_open(luks_name):
        logger.info(f"  LUKS già aperto: {luks_name}")
        return True

    if not Path(key_file).exists():
        logger.error(f"  LUKS key file non trovato: {key_file}")
        return False

    cmd = [
        "cryptsetup", "luksOpen", device, luks_name,
        "--key-file", key_file,
        "--timeout", str(timeout),
    ]

    logger.info(f"  LUKS open: {device} → /dev/mapper/{luks_name}")
    if dry_run:
        return True

    result = run_cmd(cmd, timeout=timeout + 10)
    if result.returncode != 0:
        logger.error(f"  LUKS open FALLITO: {result.stderr.strip()}")
        return False
    return True


def luks_close(luks_name: str, dry_run: bool = False) -> bool:
    """Chiude un volume LUKS."""
    if not luks_is_open(luks_name):
        return True

    cmd = ["cryptsetup", "luksClose", luks_name]
    logger.info(f"  LUKS close: {luks_name}")
    if dry_run:
        return True

    result = run_cmd(cmd, timeout=30)
    if result.returncode != 0:
        logger.error(f"  LUKS close FALLITO: {result.stderr.strip()}")
        return False
    return True


def mount_luks_partition(part: dict, mount_point: str, cfg_security: dict,
                         dry_run: bool, retries: int = 1,
                         retry_delay: int = 5) -> bool:
    """Apre LUKS (se abilitato) e monta la partizione."""
    luks_cfg = cfg_security.get("luks", {})
    device = part["device"]

    if luks_cfg.get("enabled", False):
        luks_name = part.get("luks_name", "")
        if not luks_name:
            logger.error("  LUKS abilitato ma luks_name non configurato!")
            return False

        if not luks_open(
            device, luks_name, luks_cfg["key_file"],
            luks_cfg.get("open_timeout", 30), dry_run
        ):
            return False
        # Il device reale diventa il mapper
        device = f"/dev/mapper/{luks_name}"

    return safe_mount(
        device=device,
        mount_point=mount_point,
        fstype=part.get("fstype", "ext4"),
        options=part.get("mount_options", ""),
        dry_run=dry_run,
        retries=retries,
        retry_delay=retry_delay,
    )


def umount_luks_partition(part: dict, mount_point: str, cfg_security: dict,
                          dry_run: bool) -> bool:
    """Smonta partizione e chiude LUKS se abilitato."""
    ok = safe_umount(mount_point, dry_run)

    luks_cfg = cfg_security.get("luks", {})
    if luks_cfg.get("enabled", False):
        luks_name = part.get("luks_name", "")
        if luks_name:
            # Piccolo ritardo per permettere al kernel di rilasciare il device
            time.sleep(1)
            luks_close(luks_name, dry_run)

    return ok


def ensure_all_destinations_offline(cfg: dict, dry_run: bool, except_day: int = -1):
    """Smonta e chiude LUKS per tutte le partizioni tranne except_day."""
    base = cfg["destinations"]["base_mount_point"]
    sec = cfg.get("security", {})
    for day_num, part in cfg["destinations"]["partitions"].items():
        if day_num == except_day:
            continue
        mp = os.path.join(base, f"day_{day_num}")
        if is_mounted(mp):
            logger.warning(f"  Partizione giorno {day_num} montata! Smonto …")
            umount_luks_partition(part, mp, sec, dry_run)
        # Chiudi LUKS anche se non montato (potrebbe essere rimasto aperto)
        luks_name = part.get("luks_name", "")
        if luks_name and luks_is_open(luks_name) and day_num != except_day:
            luks_close(luks_name, dry_run)


# ═════════════════════════════════════════════════════════════
#  MOUNT SORGENTI
# ═════════════════════════════════════════════════════════════

def mount_source(src: dict, retries: int = 1, retry_delay: int = 5,
                 dry_run: bool = False) -> bool:
    src_type = src.get("type", "cifs")
    if src_type == "local":
        return True

    if src_type == "cifs":
        cred = src.get("credentials_file", "")
        opts_parts = []
        if cred:
            opts_parts.append(f"credentials={cred}")
        extra = src.get("mount_options", "")
        if extra:
            opts_parts.append(extra)
        return safe_mount(
            device=src["unc"],
            mount_point=src["mount_point"],
            fstype="cifs",
            options=",".join(opts_parts),
            dry_run=dry_run,
            retries=retries,
            retry_delay=retry_delay,
        )
    elif src_type == "nfs":
        return safe_mount(
            device=src["unc"],
            mount_point=src["mount_point"],
            fstype="nfs",
            options=src.get("mount_options", ""),
            dry_run=dry_run,
            retries=retries,
            retry_delay=retry_delay,
        )

    logger.error(f"  Tipo sorgente sconosciuto: {src_type}")
    return False
