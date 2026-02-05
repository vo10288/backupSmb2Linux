"""
backup_notify.py — Notifiche email, webhook, e generazione report.
"""

import os
import json
import smtplib
import logging
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


def format_bytes(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} PB"


def format_duration(seconds: float) -> str:
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
    Path(state_dir).mkdir(parents=True, exist_ok=True)

    now = datetime.now()
    total_ok = sum(1 for r in results if r.success)
    total_fail = sum(1 for r in results if not r.success and not r.skipped)
    total_skip = sum(1 for r in results if r.skipped)
    total_blocked = sum(1 for r in results if r.anomaly_blocked)

    report = {
        "timestamp": now.isoformat(),
        "day_number": day,
        "day_name": WEEKDAY_NAMES.get(day, "?"),
        "total_sources": len(results),
        "success": total_ok,
        "failed": total_fail,
        "skipped": total_skip,
        "anomaly_blocked": total_blocked,
        "all_ok": total_fail == 0 and total_blocked == 0,
        "total_files_transferred": sum(r.files_transferred for r in results),
        "total_bytes_transferred": sum(r.bytes_transferred for r in results),
        "total_elapsed_seconds": sum(r.elapsed_seconds for r in results),
        "sources": [r.to_dict() for r in results],
    }

    if extra_info:
        report.update(extra_info)

    # Salva report singolo
    report_file = os.path.join(state_dir, f"report_{now:%Y%m%d_%H%M%S}.json")
    with open(report_file, "w") as f:
        json.dump(report, f, indent=2)

    # Aggiorna storico (ultimi 90 giorni)
    history_file = os.path.join(state_dir, "history.json")
    history = []
    if os.path.exists(history_file):
        try:
            with open(history_file) as f:
                history = json.load(f)
        except (json.JSONDecodeError, OSError):
            history = []

    # Summary per lo storico (senza dettagli per fonte)
    summary = {k: v for k, v in report.items() if k != "sources"}
    history.append(summary)

    # Tieni solo ultimi 90 giorni
    if len(history) > 90:
        history = history[-90:]

    with open(history_file, "w") as f:
        json.dump(history, f, indent=2)

    logger.info(f"  Report salvato: {report_file}")
    return report_file


# ═════════════════════════════════════════════════════════════
#  EMAIL
# ═════════════════════════════════════════════════════════════

def build_email_body(results: list, day: int) -> str:
    """Costruisce il corpo dell'email di riepilogo."""
    lines = []
    now = datetime.now()
    day_name = WEEKDAY_NAMES.get(day, "?")

    total_ok = sum(1 for r in results if r.success)
    total_fail = sum(1 for r in results if not r.success and not r.skipped)
    total_skip = sum(1 for r in results if r.skipped)
    total_blocked = sum(1 for r in results if r.anomaly_blocked)

    lines.append(f"BACKUP ROTAZIONALE — {day_name} {now:%Y-%m-%d %H:%M}")
    lines.append("=" * 55)
    lines.append("")
    lines.append(f"Risultato: {total_ok} OK / {total_fail} errori / "
                 f"{total_skip} saltati / {total_blocked} bloccati")
    lines.append(f"File trasferiti: {sum(r.files_transferred for r in results):,}")
    lines.append(f"Dati trasferiti: {format_bytes(sum(r.bytes_transferred for r in results))}")
    lines.append(f"Durata totale:   {format_duration(sum(r.elapsed_seconds for r in results))}")
    lines.append("")
    lines.append("-" * 55)

    for r in results:
        if r.anomaly_blocked:
            icon = "🚫"
            status = "BLOCCATO (anomalia)"
        elif r.skipped:
            icon = "⏭️"
            status = f"SALTATO: {r.skip_reason}"
        elif r.success:
            icon = "✅"
            status = f"OK ({r.files_transferred:,} file, {format_bytes(r.bytes_transferred)}, {format_duration(r.elapsed_seconds)})"
        else:
            icon = "❌"
            status = f"ERRORE: {r.error_message[:100]}"

        lines.append(f"  {icon} {r.source_name}")
        lines.append(f"     {status}")

        if r.integrity_verified > 0:
            int_status = "✓" if r.integrity_errors == 0 else f"⚠ {r.integrity_errors} errori"
            lines.append(f"     Integrità: {r.integrity_verified} file verificati [{int_status}]")

        lines.append("")

    lines.append("-" * 55)
    lines.append("Sistema di Backup Rotazionale v2.0")
    return "\n".join(lines)


def send_email(cfg: dict, results: list, day: int):
    """Invia notifica email."""
    email_cfg = cfg.get("notifications", {}).get("email", {})
    if not email_cfg.get("enabled", False):
        return

    all_ok = all(r.success for r in results if not r.skipped)
    if email_cfg.get("only_on_error", False) and all_ok:
        return

    day_name = WEEKDAY_NAMES.get(day, "?")
    status = "OK" if all_ok else "ERRORI"
    subject = f"[Backup] {day_name} — {status}"

    body = build_email_body(results, day)

    msg = MIMEMultipart()
    msg["Subject"] = subject
    msg["From"] = email_cfg["smtp_user"]
    msg["To"] = ", ".join(email_cfg["recipients"])
    msg.attach(MIMEText(body, "plain", "utf-8"))

    try:
        with smtplib.SMTP(email_cfg["smtp_server"], email_cfg["smtp_port"]) as srv:
            if email_cfg.get("smtp_tls", True):
                srv.starttls()
            srv.login(email_cfg["smtp_user"], email_cfg["smtp_password"])
            srv.sendmail(email_cfg["smtp_user"], email_cfg["recipients"], msg.as_string())
        logger.info("  Email inviata.")
    except Exception as e:
        logger.error(f"  Invio email fallito: {e}")


# ═════════════════════════════════════════════════════════════
#  WEBHOOK (Slack, Teams, Telegram …)
# ═════════════════════════════════════════════════════════════

def send_webhook(cfg: dict, results: list, day: int):
    """Invia notifica via webhook generico."""
    wh_cfg = cfg.get("notifications", {}).get("webhook", {})
    if not wh_cfg.get("enabled", False):
        return

    all_ok = all(r.success for r in results if not r.skipped)
    day_name = WEEKDAY_NAMES.get(day, "?")
    status = "✅ OK" if all_ok else "❌ ERRORI"

    total_ok = sum(1 for r in results if r.success)
    total_fail = sum(1 for r in results if not r.success and not r.skipped)

    summary = f"{total_ok} OK, {total_fail} errori"
    errors = "; ".join(
        f"{r.source_name}: {r.error_message[:50]}"
        for r in results if not r.success and not r.skipped
    ) or "nessuno"

    template = wh_cfg.get("template", '{{"text": "Backup {day}: {status}"}}')
    payload = (
        template
        .replace("{status}", status)
        .replace("{day}", day_name)
        .replace("{summary}", summary)
        .replace("{errors}", errors)
    )

    url = wh_cfg["url"]
    try:
        req = urllib.request.Request(
            url, data=payload.encode("utf-8"),
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=15) as resp:
            if resp.status < 300:
                logger.info("  Webhook inviato.")
            else:
                logger.warning(f"  Webhook risposta HTTP {resp.status}")
    except urllib.error.URLError as e:
        logger.error(f"  Webhook fallito: {e}")


def send_all_notifications(cfg: dict, results: list, day: int):
    """Invia tutte le notifiche configurate."""
    send_email(cfg, results, day)
    send_webhook(cfg, results, day)
