"""
backup_core.py — Funzioni fondamentali: mount, umount, LUKS, pre-check, spazio disco.

SECURITY:
- Tutti i path vengono validati contro path traversal
- Logging sanitizzato per prevenire log injection
- Comandi costruiti con liste (no shell=True)
"""

import os
import re
import subprocess
import time
import logging
from pathlib import Path

logger = logging.getLogger("backup_system")


# ═════════════════════════════════════════════════════════════
#  SECURITY: SANITIZATION FUNCTIONS
# ═════════════════════════════════════════════════════════════

def sanitize_log_message(msg: str) -> str:
    """
    Sanitizza un messaggio per il log.
    Rimuove newline e caratteri di controllo che potrebbero causare log injection.
    """
    if msg is None:
        return ""
    # Rimuovi newline e carriage return (log injection)
    sanitized = str(msg).replace('\n', '\\n').replace('\r', '\\r')
    # Rimuovi altri caratteri di controllo
    sanitized = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', '', sanitized)
    return sanitized


def validate_path(path: str, allowed_base: str = None) -> str:
    """
    Valida e normalizza un path.
    Se allowed_base è specificato, verifica che il path sia sotto quella directory.
    Previene path traversal (../).
    """
    if not path:
        raise ValueError("Path vuoto non consentito")
    
    # Normalizza il path
    normalized = os.path.normpath(os.path.abspath(path))
    
    # Se c'è una base consentita, verifica che il path sia sotto di essa
    if allowed_base:
        base_normalized = os.path.normpath(os.path.abspath(allowed_base))
        if not normalized.startswith(base_normalized + os.sep) and normalized != base_normalized:
            raise ValueError(f"Path traversal rilevato: {path} non è sotto {allowed_base}")
    
    return normalized


def sanitize_device_name(name: str) -> str:
    """
    Sanitizza un nome di device o LUKS mapper.
    Consente solo caratteri alfanumerici, underscore e trattini.
    """
    if not name:
        return ""
    # Solo a-z, A-Z, 0-9, _, -
    sanitized = re.sub(r'[^a-zA-Z0-9_-]', '', name)
    if sanitized != name:
        logger.warning(f"Nome device sanitizzato: '{sanitize_log_message(name)}' → '{sanitized}'")
    return sanitized


def validate_unc_path(unc: str) -> str:
    """
    Valida un percorso UNC per share Windows.
    Formato atteso: //host/share o \\\\host\\share
    """
    if not unc:
        raise ValueError("UNC path vuoto")
    
    # Normalizza backslash a forward slash
    normalized = unc.replace("\\", "/")
    
    # Pattern UNC valido
    if not re.match(r'^//[a-zA-Z0-9._-]+/[a-zA-Z0-9$._-]+(/[a-zA-Z0-9._-]*)*$', normalized):
        raise ValueError(f"UNC path non valido: {sanitize_log_message(unc)}")
    
    return normalized


# ═════════════════════════════════════════════════════════════
#  UTILITÀ DI BASE
# ═════════════════════════════════════════════════════════════

def run_cmd(cmd: list[str], timeout: int = 60, check: bool = False,
            capture: bool = True) -> subprocess.CompletedProcess:
    """
    Wrapper per subprocess.run con logging.
    SECURITY: cmd deve essere una lista (mai shell=True).
    """
    # Sanitizza il comando per il log
    safe_cmd = [sanitize_log_message(c) for c in cmd]
    logger.debug(f"CMD: {' '.join(safe_cmd)}")
    
    return subprocess.run(
        cmd, capture_output=capture, text=True, timeout=timeout, check=check
    )


def is_mounted(mount_point: str) -> bool:
    """Verifica se un path è un mount point attivo."""
    try:
        validated_mp = validate_path(mount_point)
        result = run_cmd(["mountpoint", "-q", validated_mp], timeout=5)
        return result.returncode == 0
    except ValueError:
        return False


def free_space_gb(path: str) -> float:
    """Spazio libero in GB su un mount point."""
    validated_path = validate_path(path)
    st = os.statvfs(validated_path)
    return (st.f_bavail * st.f_frsize) / (1024 ** 3)


# ═════════════════════════════════════════════════════════════
#  PRE-CHECK SORGENTI
# ═════════════════════════════════════════════════════════════

def ping_host(host: str, timeout: int = 3) -> bool:
    """Verifica raggiungibilità di un host via ping."""
    # Valida hostname (no injection)
    if not re.match(r'^[a-zA-Z0-9._-]+$', host):
        logger.error(f"Hostname non valido: {sanitize_log_message(host)}")
        return False
    
    result = run_cmd(["ping", "-c", "1", "-W", str(int(timeout)), host], timeout=timeout + 2)
    return result.returncode == 0


def check_smb_share(unc: str, credentials_file: str, timeout: int = 10) -> bool:
    """Verifica che la share SMB sia raggiungibile con smbclient."""
    try:
        validated_unc = validate_unc_path(unc)
        validated_creds = validate_path(credentials_file)
        
        if not os.path.isfile(validated_creds):
            logger.error(f"File credenziali non trovato: {sanitize_log_message(validated_creds)}")
            return False
        
        cmd = [
            "smbclient", validated_unc, 
            "--authentication-file", validated_creds,
            "-c", "exit", 
            "--timeout", str(int(timeout)),
        ]
        result = run_cmd(cmd, timeout=timeout + 5)
        return result.returncode == 0
    except ValueError as e:
        logger.error(f"Validazione SMB fallita: {sanitize_log_message(str(e))}")
        return False


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

    ping_tout = int(cfg_resilience["pre_check"].get("ping_timeout", 3))
    if not ping_host(host, ping_tout):
        return False, f"host {sanitize_log_message(host)} non raggiungibile (ping timeout {ping_tout}s)"

    if src.get("type") == "cifs":
        smb_tout = int(cfg_resilience["pre_check"].get("smb_timeout", 10))
        cred = src.get("credentials_file", "")
        unc = src.get("unc", "")
        if cred:
            try:
                if not check_smb_share(unc, cred, smb_tout):
                    return False, f"share {sanitize_log_message(unc)} non accessibile (smbclient timeout {smb_tout}s)"
            except ValueError as e:
                return False, f"configurazione non valida: {sanitize_log_message(str(e))}"

    return True, "ok"


# ═════════════════════════════════════════════════════════════
#  MOUNT / UMOUNT CON RETRY
# ═════════════════════════════════════════════════════════════

def safe_mount(device: str, mount_point: str, fstype: str = "",
               options: str = "", dry_run: bool = False,
               retries: int = 1, retry_delay: int = 5) -> bool:
    """Monta con retry e backoff esponenziale."""
    try:
        validated_mp = validate_path(mount_point)
    except ValueError as e:
        logger.error(f"Mount point non valido: {sanitize_log_message(str(e))}")
        return False

    mp = Path(validated_mp)
    mp.mkdir(parents=True, exist_ok=True)

    if is_mounted(validated_mp):
        logger.info(f"  Già montato: {sanitize_log_message(validated_mp)}")
        return True

    cmd = ["mount"]
    if fstype:
        # Valida fstype (solo caratteri sicuri)
        safe_fstype = re.sub(r'[^a-zA-Z0-9._-]', '', fstype)
        cmd += ["-t", safe_fstype]
    if options:
        # Le opzioni mount sono validate dal kernel, ma sanitizziamo comunque
        # Rimuovi caratteri pericolosi
        safe_options = re.sub(r'[;&|`$]', '', options)
        cmd += ["-o", safe_options]
    cmd += [device, validated_mp]

    for attempt in range(1, retries + 1):
        logger.info(f"  Mount (tentativo {attempt}/{retries}): {sanitize_log_message(device)} → {sanitize_log_message(validated_mp)}")
        if dry_run:
            return True

        result = run_cmd(cmd, timeout=60)
        if result.returncode == 0:
            return True

        err = sanitize_log_message(result.stderr.strip())
        logger.warning(f"  Mount fallito: {err}")

        if attempt < retries:
            delay = retry_delay * (2 ** (attempt - 1))
            logger.info(f"  Attendo {delay}s prima del prossimo tentativo …")
            time.sleep(delay)

    logger.error(f"  Mount FALLITO dopo {retries} tentativi: {sanitize_log_message(device)}")
    return False


def safe_umount(mount_point: str, dry_run: bool = False, force: bool = False) -> bool:
    """Smonta un mount point in modo sicuro."""
    try:
        validated_mp = validate_path(mount_point)
    except ValueError as e:
        logger.error(f"Mount point non valido: {sanitize_log_message(str(e))}")
        return False

    if not is_mounted(validated_mp):
        return True

    cmd = ["umount"]
    if force:
        cmd.append("-l")
    cmd.append(validated_mp)

    logger.info(f"  Umount: {sanitize_log_message(validated_mp)}")
    if dry_run:
        return True

    result = run_cmd(cmd, timeout=60)
    if result.returncode != 0:
        if not force:
            logger.warning("  Umount fallito, riprovo con lazy …")
            return safe_umount(validated_mp, dry_run, force=True)
        logger.error(f"  Umount FALLITO: {sanitize_log_message(validated_mp)}")
        return False
    return True


# ═════════════════════════════════════════════════════════════
#  LUKS — Crittografia partizioni
# ═════════════════════════════════════════════════════════════

def luks_is_open(luks_name: str) -> bool:
    """Verifica se un volume LUKS è aperto."""
    safe_name = sanitize_device_name(luks_name)
    if not safe_name:
        return False
    return Path(f"/dev/mapper/{safe_name}").exists()


def luks_open(device: str, luks_name: str, key_file: str,
              timeout: int = 30, dry_run: bool = False) -> bool:
    """Apre un volume LUKS con key file."""
    # Sanitizza nome LUKS
    safe_name = sanitize_device_name(luks_name)
    if not safe_name:
        logger.error("Nome LUKS vuoto o non valido")
        return False

    if luks_is_open(safe_name):
        logger.info(f"  LUKS già aperto: {safe_name}")
        return True

    try:
        validated_keyfile = validate_path(key_file)
    except ValueError as e:
        logger.error(f"Key file non valido: {sanitize_log_message(str(e))}")
        return False

    if not Path(validated_keyfile).exists():
        logger.error(f"  LUKS key file non trovato: {sanitize_log_message(validated_keyfile)}")
        return False

    cmd = [
        "cryptsetup", "luksOpen", device, safe_name,
        "--key-file", validated_keyfile,
        "--timeout", str(int(timeout)),
    ]

    logger.info(f"  LUKS open: {sanitize_log_message(device)} → /dev/mapper/{safe_name}")
    if dry_run:
        return True

    result = run_cmd(cmd, timeout=timeout + 10)
    if result.returncode != 0:
        logger.error(f"  LUKS open FALLITO: {sanitize_log_message(result.stderr.strip())}")
        return False
    return True


def luks_close(luks_name: str, dry_run: bool = False) -> bool:
    """Chiude un volume LUKS."""
    safe_name = sanitize_device_name(luks_name)
    if not safe_name:
        return True

    if not luks_is_open(safe_name):
        return True

    cmd = ["cryptsetup", "luksClose", safe_name]
    logger.info(f"  LUKS close: {safe_name}")
    if dry_run:
        return True

    result = run_cmd(cmd, timeout=30)
    if result.returncode != 0:
        logger.error(f"  LUKS close FALLITO: {sanitize_log_message(result.stderr.strip())}")
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
        safe_name = sanitize_device_name(luks_name)
        if not safe_name:
            logger.error("  LUKS abilitato ma luks_name non configurato o non valido!")
            return False

        try:
            key_file = validate_path(luks_cfg["key_file"])
        except ValueError as e:
            logger.error(f"Key file non valido: {sanitize_log_message(str(e))}")
            return False

        if not luks_open(
            device, safe_name, key_file,
            luks_cfg.get("open_timeout", 30), dry_run
        ):
            return False
        # Il device reale diventa il mapper
        device = f"/dev/mapper/{safe_name}"

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
        safe_name = sanitize_device_name(luks_name)
        if safe_name:
            # Piccolo ritardo per permettere al kernel di rilasciare il device
            time.sleep(1)
            luks_close(safe_name, dry_run)

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
        safe_name = sanitize_device_name(luks_name)
        if safe_name and luks_is_open(safe_name) and day_num != except_day:
            luks_close(safe_name, dry_run)


# ═════════════════════════════════════════════════════════════
#  MOUNT SORGENTI
# ═════════════════════════════════════════════════════════════

def mount_source(src: dict, retries: int = 1, retry_delay: int = 5,
                 dry_run: bool = False) -> bool:
    """Monta una sorgente remota."""
    src_type = src.get("type", "cifs")
    if src_type == "local":
        return True

    if src_type == "cifs":
        try:
            validated_unc = validate_unc_path(src["unc"])
            cred = src.get("credentials_file", "")
            opts_parts = []
            if cred:
                validated_cred = validate_path(cred)
                if os.path.isfile(validated_cred):
                    opts_parts.append(f"credentials={validated_cred}")
            extra = src.get("mount_options", "")
            if extra:
                # Sanitizza opzioni mount
                safe_extra = re.sub(r'[;&|`$]', '', extra)
                opts_parts.append(safe_extra)
            
            return safe_mount(
                device=validated_unc,
                mount_point=src["mount_point"],
                fstype="cifs",
                options=",".join(opts_parts),
                dry_run=dry_run,
                retries=retries,
                retry_delay=retry_delay,
            )
        except ValueError as e:
            logger.error(f"Errore validazione CIFS: {sanitize_log_message(str(e))}")
            return False
            
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

    logger.error(f"  Tipo sorgente sconosciuto: {sanitize_log_message(src_type)}")
    return False
