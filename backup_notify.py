"""
backup_notify.py — Notifiche email, webhook, e generazione report.

SECURITY:
- I dati per webhook vengono codificati JSON correttamente (no template injection)
- I messaggi email sono sanitizzati
- I nomi file sono validati
"""

import os
import json
import smtplib
import logging
import re
import urllib.request
import urllib.error
from pathlib import Path
from datetime import datetime
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

logger = logging.getLogger("backup_system")

WEEKDAY_NAMES = {
    1: "Lunedì", 2: "Martedì", 3: "Mercoledì", 4: "Giovedì",
    5: "Venerdì", 6: "Sabato", 7: "Domenica",
}


# ═════════════════════════════════════════════════════════════
#  SECURITY: SANITIZATION
# ═════════════════════════════════════════════════════════════

def sanitize_for_log(text: str) -> str:
    """Sanitizza testo per log (rimuove newline e caratteri di controllo)."""
    if text is None:
        return ""
    sanitized = str(text).replace('\n', '\\n').replace('\r', '\\r')
    sanitized = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', '', sanitized)
    return sanitized


def sanitize_for_json(text: str, max_length: int = 500) -> str:
    """
    Sanitizza testo per inclusione in JSON.
    - Tronca a max_length
    - Rimuove caratteri di controllo
    """
    if text is None:
        return ""
    sanitized = str(text)[:max_length]
    # Rimuovi caratteri che potrebbero rompere JSON
    sanitized = re.sub(r'[\x00-\x1f\x7f]', '', sanitized)
    return sanitized


def sanitize_for_email(text: str) -> str:
    """Sanitizza testo per email (mantiene newline ma rimuove altri controlli)."""
    if text is None:
        return ""
    # Mantieni newline e tab, rimuovi altri caratteri di controllo
    sanitized = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', '', str(text))
    return sanitized


def validate_state_dir(state_dir: str) -> str:
    """Valida e normalizza la directory di stato."""
    normalized = os.path.normpath(os.path.abspath(state_dir))
    # Verifica che sia un path ragionevole
    if '..' in normalized.split(os.sep):
        raise ValueError(f"Path traversal rilevato: {state_dir}")
    return normalized


def format_bytes(n: int) -> str:
    """Formatta bytes in formato leggibile."""
    n = int(n)  # Assicura che sia un intero
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} PB"


def format_duration(seconds: float) -> str:
    """Formatta durata in formato leggibile."""
    seconds = float(seconds)  # Assicura che sia un float
    if seconds < 60:
        return f"{seconds:.0f}s"
    m, s = divmod(int(seconds), 60)
    h, m = divmod(m, 60)
    if h:
        return f"{h}h {m}m {s}s"
    return f"{m}m {s}s"


# ═════════════════════════════════════════════════════════════
#  REPORT JSON + STORICO
# ═════════════════════════════════════════════════════════════

def save_report(results: list, day: int, state_dir: str,
                extra_info: dict = None) -> str:
    """Salva un report JSON e aggiunge allo storico."""
    try:
        validated_state_dir = validate_state_dir(state_dir)
    except ValueError as e:
        logger.error(f"State dir non valida: {e}")
        return ""
    
    Path(validated_state_dir).mkdir(parents=True, exist_ok=True)

    now = datetime.now()
    
    # Calcola statistiche (usa valori default sicuri)
    total_ok = sum(1 for r in results if getattr(r, 'success', False))
    total_fail = sum(1 for r in results if not getattr(r, 'success', False) and not getattr(r, 'skipped', False))
    total_skip = sum(1 for r in results if getattr(r, 'skipped', False))
    total_blocked = sum(1 for r in results if getattr(r, 'anomaly_blocked', False))

    # Costruisci report con dati sanitizzati
    report = {
        "timestamp": now.isoformat(),
        "day_number": int(day),
        "day_name": WEEKDAY_NAMES.get(int(day), "?"),
        "total_sources": len(results),
        "success": total_ok,
        "failed": total_fail,
        "skipped": total_skip,
        "anomaly_blocked": total_blocked,
        "all_ok": total_fail == 0 and total_blocked == 0,
        "total_files_transferred": sum(getattr(r, 'files_transferred', 0) for r in results),
        "total_bytes_transferred": sum(getattr(r, 'bytes_transferred', 0) for r in results),
        "total_elapsed_seconds": sum(getattr(r, 'elapsed_seconds', 0) for r in results),
        "sources": [],
    }
    
    # Sanitizza i dati delle sorgenti
    for r in results:
        source_data = {}
        if hasattr(r, 'to_dict'):
            raw_data = r.to_dict()
            # Sanitizza ogni campo stringa
            for key, value in raw_data.items():
                if isinstance(value, str):
                    source_data[key] = sanitize_for_json(value)
                else:
                    source_data[key] = value
        else:
            source_data = {
                "source_name": sanitize_for_json(getattr(r, 'source_name', 'unknown')),
                "success": bool(getattr(r, 'success', False)),
                "error_message": sanitize_for_json(getattr(r, 'error_message', '')),
            }
        report["sources"].append(source_data)

    if extra_info:
        # Sanitizza extra_info
        for key, value in extra_info.items():
            if isinstance(value, str):
                report[key] = sanitize_for_json(value)
            else:
                report[key] = value

    # Salva report singolo con nome file sicuro
    safe_timestamp = now.strftime("%Y%m%d_%H%M%S")
    report_filename = f"report_{safe_timestamp}.json"
    report_file = os.path.join(validated_state_dir, report_filename)
    
    try:
        with open(report_file, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
    except (OSError, IOError) as e:
        logger.error(f"Errore salvataggio report: {sanitize_for_log(str(e))}")
        return ""

    # Aggiorna storico (ultimi 90 giorni)
    history_file = os.path.join(validated_state_dir, "history.json")
    history = []
    if os.path.exists(history_file):
        try:
            with open(history_file, encoding="utf-8") as f:
                history = json.load(f)
                if not isinstance(history, list):
                    history = []
        except (json.JSONDecodeError, OSError):
            history = []

    # Summary per lo storico (senza dettagli per fonte)
    summary = {k: v for k, v in report.items() if k != "sources"}
    history.append(summary)

    # Tieni solo ultimi 90 giorni
    if len(history) > 90:
        history = history[-90:]

    try:
        with open(history_file, "w", encoding="utf-8") as f:
            json.dump(history, f, indent=2, ensure_ascii=False)
    except (OSError, IOError) as e:
        logger.error(f"Errore salvataggio storico: {sanitize_for_log(str(e))}")

    logger.info(f"  Report salvato: {sanitize_for_log(report_file)}")
    return report_file


# ═════════════════════════════════════════════════════════════
#  EMAIL
# ═════════════════════════════════════════════════════════════

def build_email_body(results: list, day: int) -> str:
    """Costruisce il corpo dell'email di riepilogo."""
    lines = []
    now = datetime.now()
    day_name = WEEKDAY_NAMES.get(int(day), "?")

    total_ok = sum(1 for r in results if getattr(r, 'success', False))
    total_fail = sum(1 for r in results if not getattr(r, 'success', False) and not getattr(r, 'skipped', False))
    total_skip = sum(1 for r in results if getattr(r, 'skipped', False))
    total_blocked = sum(1 for r in results if getattr(r, 'anomaly_blocked', False))

    lines.append(f"BACKUP ROTAZIONALE — {day_name} {now:%Y-%m-%d %H:%M}")
    lines.append("=" * 55)
    lines.append("")
    lines.append(f"Risultato: {total_ok} OK / {total_fail} errori / "
                 f"{total_skip} saltati / {total_blocked} bloccati")
    lines.append(f"File trasferiti: {sum(getattr(r, 'files_transferred', 0) for r in results):,}")
    lines.append(f"Dati trasferiti: {format_bytes(sum(getattr(r, 'bytes_transferred', 0) for r in results))}")
    lines.append(f"Durata totale:   {format_duration(sum(getattr(r, 'elapsed_seconds', 0) for r in results))}")
    lines.append("")
    lines.append("-" * 55)

    for r in results:
        source_name = sanitize_for_email(getattr(r, 'source_name', 'unknown'))
        
        if getattr(r, 'anomaly_blocked', False):
            icon = "🚫"
            status = "BLOCCATO (anomalia)"
        elif getattr(r, 'skipped', False):
            icon = "⏭️"
            skip_reason = sanitize_for_email(getattr(r, 'skip_reason', 'N/A'))
            status = f"SALTATO: {skip_reason}"
        elif getattr(r, 'success', False):
            icon = "✅"
            files = getattr(r, 'files_transferred', 0)
            bytes_tr = getattr(r, 'bytes_transferred', 0)
            elapsed = getattr(r, 'elapsed_seconds', 0)
            status = f"OK ({files:,} file, {format_bytes(bytes_tr)}, {format_duration(elapsed)})"
        else:
            icon = "❌"
            error_msg = sanitize_for_email(getattr(r, 'error_message', 'Errore sconosciuto'))
            status = f"ERRORE: {error_msg[:100]}"

        lines.append(f"  {icon} {source_name}")
        lines.append(f"     {status}")

        integrity_verified = getattr(r, 'integrity_verified', 0)
        if integrity_verified > 0:
            integrity_errors = getattr(r, 'integrity_errors', 0)
            int_status = "✓" if integrity_errors == 0 else f"⚠ {integrity_errors} errori"
            lines.append(f"     Integrità: {integrity_verified} file verificati [{int_status}]")

        lines.append("")

    lines.append("-" * 55)
    lines.append("Sistema di Backup Rotazionale v2.0")
    return "\n".join(lines)


def send_email(cfg: dict, results: list, day: int):
    """Invia notifica email."""
    email_cfg = cfg.get("notifications", {}).get("email", {})
    if not email_cfg.get("enabled", False):
        return

    all_ok = all(getattr(r, 'success', False) for r in results if not getattr(r, 'skipped', False))
    if email_cfg.get("only_on_error", False) and all_ok:
        return

    day_name = WEEKDAY_NAMES.get(int(day), "?")
    status = "OK" if all_ok else "ERRORI"
    subject = f"[Backup] {day_name} — {status}"

    body = build_email_body(results, day)

    msg = MIMEMultipart()
    msg["Subject"] = subject
    msg["From"] = email_cfg.get("smtp_user", "")
    
    recipients = email_cfg.get("recipients", [])
    if isinstance(recipients, str):
        recipients = [recipients]
    msg["To"] = ", ".join(recipients)
    
    msg.attach(MIMEText(body, "plain", "utf-8"))

    try:
        smtp_server = email_cfg.get("smtp_server", "")
        smtp_port = int(email_cfg.get("smtp_port", 587))
        
        with smtplib.SMTP(smtp_server, smtp_port) as srv:
            if email_cfg.get("smtp_tls", True):
                srv.starttls()
            srv.login(
                email_cfg.get("smtp_user", ""), 
                email_cfg.get("smtp_password", "")
            )
            srv.sendmail(email_cfg.get("smtp_user", ""), recipients, msg.as_string())
        logger.info("  Email inviata.")
    except Exception as e:
        logger.error(f"  Invio email fallito: {sanitize_for_log(str(e))}")


# ═════════════════════════════════════════════════════════════
#  WEBHOOK (Slack, Teams, Telegram …)
# ═════════════════════════════════════════════════════════════

def send_webhook(cfg: dict, results: list, day: int):
    """
    Invia notifica via webhook generico.
    SECURITY: Usa json.dumps per costruire il payload (previene injection).
    """
    wh_cfg = cfg.get("notifications", {}).get("webhook", {})
    if not wh_cfg.get("enabled", False):
        return

    all_ok = all(getattr(r, 'success', False) for r in results if not getattr(r, 'skipped', False))
    day_name = WEEKDAY_NAMES.get(int(day), "?")
    status_emoji = "✅" if all_ok else "❌"
    status_text = "OK" if all_ok else "ERRORI"

    total_ok = sum(1 for r in results if getattr(r, 'success', False))
    total_fail = sum(1 for r in results if not getattr(r, 'success', False) and not getattr(r, 'skipped', False))

    # Costruisci gli errori in modo sicuro
    errors_list = []
    for r in results:
        if not getattr(r, 'success', False) and not getattr(r, 'skipped', False):
            source = sanitize_for_json(getattr(r, 'source_name', 'unknown'), 50)
            error = sanitize_for_json(getattr(r, 'error_message', 'errore'), 50)
            errors_list.append(f"{source}: {error}")
    
    errors = "; ".join(errors_list) if errors_list else "nessuno"

    # SECURITY: Costruisci il payload come dizionario Python e usa json.dumps
    # Questo previene template injection
    webhook_type = wh_cfg.get("type", "generic").lower()
    
    if webhook_type == "slack":
        payload = {
            "text": f"*Backup {day_name}*: {status_emoji} {status_text}",
            "attachments": [{
                "color": "good" if all_ok else "danger",
                "fields": [
                    {"title": "Risultato", "value": f"{total_ok} OK, {total_fail} errori", "short": True},
                    {"title": "Errori", "value": errors[:200], "short": False},
                ]
            }]
        }
    elif webhook_type == "discord":
        payload = {
            "content": f"**Backup {day_name}**: {status_emoji} {status_text}\n{total_ok} OK, {total_fail} errori"
        }
    elif webhook_type == "teams":
        payload = {
            "@type": "MessageCard",
            "summary": f"Backup {day_name}: {status_text}",
            "themeColor": "00FF00" if all_ok else "FF0000",
            "title": f"Backup {day_name}: {status_emoji} {status_text}",
            "sections": [{
                "facts": [
                    {"name": "Risultato", "value": f"{total_ok} OK, {total_fail} errori"},
                    {"name": "Errori", "value": errors[:200]},
                ]
            }]
        }
    else:
        # Generic webhook
        payload = {
            "text": f"Backup {day_name}: {status_emoji} {status_text} - {total_ok} OK, {total_fail} errori",
            "status": status_text,
            "day": day_name,
            "summary": f"{total_ok} OK, {total_fail} errori",
            "errors": errors[:200],
        }

    url = wh_cfg.get("url", "")
    if not url:
        logger.warning("  Webhook URL non configurato")
        return

    try:
        # Serializza il payload in modo sicuro
        payload_bytes = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        
        req = urllib.request.Request(
            url, 
            data=payload_bytes,
            headers={"Content-Type": "application/json"},
        )
        
        with urllib.request.urlopen(req, timeout=15) as resp:
            if resp.status < 300:
                logger.info("  Webhook inviato.")
            else:
                logger.warning(f"  Webhook risposta HTTP {resp.status}")
    except urllib.error.URLError as e:
        logger.error(f"  Webhook fallito: {sanitize_for_log(str(e))}")
    except Exception as e:
        logger.error(f"  Webhook errore: {sanitize_for_log(str(e))}")


def send_all_notifications(cfg: dict, results: list, day: int):
    """Invia tutte le notifiche configurate."""
    send_email(cfg, results, day)
    send_webhook(cfg, results, day)
