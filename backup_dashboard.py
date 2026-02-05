#!/usr/bin/env python3
"""
backup_dashboard.py — Dashboard web per monitorare i backup.
Leggera, single-file, basata su Flask.
"""

import os
import json
import hashlib
import functools
import logging
from pathlib import Path
from datetime import datetime

from flask import Flask, render_template_string, jsonify, request, Response

logger = logging.getLogger("backup_dashboard")

app = Flask(__name__)

# ─── Config globale (impostata da main) ─────────────────────
DASHBOARD_CFG = {}
STATE_DIR = "/var/lib/backup_system"

WEEKDAY_NAMES = {
    1: "Lunedì", 2: "Martedì", 3: "Mercoledì", 4: "Giovedì",
    5: "Venerdì", 6: "Sabato", 7: "Domenica",
}


# ═════════════════════════════════════════════════════════════
#  AUTH
# ═════════════════════════════════════════════════════════════

def check_auth(username: str, password: str) -> bool:
    auth_cfg = DASHBOARD_CFG.get("auth", {})
    if not auth_cfg.get("enabled", False):
        return True
    expected_user = auth_cfg.get("username", "admin")
    expected_hash = auth_cfg.get("password_sha256", "")
    actual_hash = hashlib.sha256(password.encode()).hexdigest()
    return username == expected_user and actual_hash == expected_hash


def require_auth(f):
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        auth_cfg = DASHBOARD_CFG.get("auth", {})
        if not auth_cfg.get("enabled", False):
            return f(*args, **kwargs)
        auth = request.authorization
        if not auth or not check_auth(auth.username, auth.password):
            return Response(
                "Autenticazione richiesta", 401,
                {"WWW-Authenticate": 'Basic realm="Backup Dashboard"'},
            )
        return f(*args, **kwargs)
    return decorated


# ═════════════════════════════════════════════════════════════
#  DATI
# ═════════════════════════════════════════════════════════════

def load_history() -> list[dict]:
    path = os.path.join(STATE_DIR, "history.json")
    if not os.path.exists(path):
        return []
    try:
        with open(path) as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return []


def load_latest_report() -> dict | None:
    """Carica il report più recente."""
    reports = sorted(Path(STATE_DIR).glob("report_*.json"), reverse=True)
    if not reports:
        return None
    try:
        with open(reports[0]) as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return None


def get_partition_status() -> list[dict]:
    """Verifica lo stato di mount di ogni partizione."""
    statuses = []
    with open("/proc/mounts", "r") as f:
        mounts = f.read()

    for day in range(1, 8):
        mp = f"/mnt/backup/day_{day}"
        statuses.append({
            "day": day,
            "name": WEEKDAY_NAMES.get(day, "?"),
            "mounted": mp in mounts,
            "mount_point": mp,
        })
    return statuses


# ═════════════════════════════════════════════════════════════
#  TEMPLATE HTML
# ═════════════════════════════════════════════════════════════

DASHBOARD_HTML = """
<!DOCTYPE html>
<html lang="it">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Backup Dashboard</title>
<style>
  :root {
    --bg: #0f172a; --surface: #1e293b; --surface2: #334155;
    --text: #e2e8f0; --muted: #94a3b8; --accent: #38bdf8;
    --green: #22c55e; --red: #ef4444; --yellow: #eab308; --orange: #f97316;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: 'Segoe UI', system-ui, sans-serif; background: var(--bg); color: var(--text); padding: 1.5rem; }
  h1 { font-size: 1.5rem; font-weight: 600; margin-bottom: 1.5rem; display: flex; align-items: center; gap: .5rem; }
  h1 span { color: var(--accent); }
  .grid { display: grid; gap: 1rem; }
  .grid-4 { grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); }
  .grid-7 { grid-template-columns: repeat(auto-fit, minmax(120px, 1fr)); }
  .card { background: var(--surface); border-radius: .75rem; padding: 1.25rem; }
  .card h3 { font-size: .75rem; text-transform: uppercase; letter-spacing: .08em; color: var(--muted); margin-bottom: .5rem; }
  .card .big { font-size: 1.75rem; font-weight: 700; }
  .status-ok { color: var(--green); }
  .status-err { color: var(--red); }
  .status-warn { color: var(--yellow); }
  .status-off { color: var(--muted); }
  .day-card { text-align: center; padding: 1rem; }
  .day-card .dot { width: 12px; height: 12px; border-radius: 50%; display: inline-block; margin-bottom: .5rem; }
  .dot-mounted { background: var(--green); box-shadow: 0 0 8px var(--green); }
  .dot-unmounted { background: var(--surface2); }
  table { width: 100%; border-collapse: collapse; margin-top: 1rem; font-size: .875rem; }
  th { text-align: left; padding: .6rem .75rem; color: var(--muted); font-weight: 500; font-size: .75rem; text-transform: uppercase; letter-spacing: .06em; border-bottom: 1px solid var(--surface2); }
  td { padding: .6rem .75rem; border-bottom: 1px solid var(--surface2); }
  tr:hover td { background: rgba(56,189,248,.04); }
  .badge { padding: .15rem .5rem; border-radius: 9999px; font-size: .7rem; font-weight: 600; }
  .badge-ok { background: rgba(34,197,94,.15); color: var(--green); }
  .badge-err { background: rgba(239,68,68,.15); color: var(--red); }
  .badge-skip { background: rgba(234,179,8,.15); color: var(--yellow); }
  .badge-block { background: rgba(249,115,22,.15); color: var(--orange); }
  .chart-bar { height: 28px; border-radius: 4px; margin: 2px 0; min-width: 2px; display: inline-block; vertical-align: middle; }
  .refresh { color: var(--muted); font-size: .75rem; float: right; cursor: pointer; }
  .refresh:hover { color: var(--accent); }
  .section { margin-top: 2rem; }
  .section h2 { font-size: 1.1rem; font-weight: 600; margin-bottom: 1rem; }
  .flex { display: flex; gap: .5rem; align-items: center; }
</style>
</head>
<body>

<h1>🛡️ <span>Backup Dashboard</span> <a class="refresh" onclick="location.reload()">⟳ Aggiorna</a></h1>

<!-- KPI -->
<div class="grid grid-4">
  <div class="card">
    <h3>Ultimo Backup</h3>
    <div class="big" id="last-date">—</div>
    <div style="color:var(--muted);font-size:.8rem" id="last-status"></div>
  </div>
  <div class="card">
    <h3>Tasso di Successo (30g)</h3>
    <div class="big" id="success-rate">—</div>
  </div>
  <div class="card">
    <h3>Dati Trasferiti (ultimo)</h3>
    <div class="big" id="last-data">—</div>
  </div>
  <div class="card">
    <h3>Durata (ultimo)</h3>
    <div class="big" id="last-duration">—</div>
  </div>
</div>

<!-- Partizioni -->
<div class="section">
  <h2>Partizioni</h2>
  <div class="grid grid-7" id="partitions"></div>
</div>

<!-- Storico 30 giorni -->
<div class="section">
  <h2>Storico (ultimi 30 giorni)</h2>
  <div id="history-chart" style="display:flex;align-items:end;gap:3px;height:120px;padding:1rem 0;"></div>
</div>

<!-- Dettaglio ultimo backup -->
<div class="section">
  <h2>Dettaglio ultimo backup</h2>
  <table>
    <thead><tr><th>Sorgente</th><th>Stato</th><th>File</th><th>Dati</th><th>Durata</th><th>Integrità</th></tr></thead>
    <tbody id="detail-table"></tbody>
  </table>
</div>

<script>
function fmt(bytes) {
  if (bytes < 1024) return bytes + ' B';
  if (bytes < 1048576) return (bytes/1024).toFixed(1) + ' KB';
  if (bytes < 1073741824) return (bytes/1048576).toFixed(1) + ' MB';
  return (bytes/1073741824).toFixed(2) + ' GB';
}
function fmtDur(s) {
  if (!s) return '—';
  if (s < 60) return Math.round(s) + 's';
  let m = Math.floor(s/60), sec = Math.round(s%60);
  let h = Math.floor(m/60); m = m%60;
  return h ? h+'h '+m+'m' : m+'m '+sec+'s';
}

async function loadData() {
  try {
    const [hist, latest, parts] = await Promise.all([
      fetch('/api/history').then(r=>r.json()),
      fetch('/api/latest').then(r=>r.json()),
      fetch('/api/partitions').then(r=>r.json()),
    ]);

    // KPI
    if (latest) {
      const d = new Date(latest.timestamp);
      document.getElementById('last-date').textContent = latest.day_name || '—';
      document.getElementById('last-status').textContent =
        d.toLocaleDateString('it') + ' ' + d.toLocaleTimeString('it',{hour:'2-digit',minute:'2-digit'});
      document.getElementById('last-status').className =
        latest.all_ok ? 'status-ok' : 'status-err';
      document.getElementById('last-data').textContent = fmt(latest.total_bytes_transferred||0);
      document.getElementById('last-duration').textContent = fmtDur(latest.total_elapsed_seconds);
    }

    // Success rate
    if (hist.length > 0) {
      let last30 = hist.slice(-30);
      let ok = last30.filter(h => h.all_ok).length;
      let pct = Math.round(ok/last30.length*100);
      let el = document.getElementById('success-rate');
      el.textContent = pct + '%';
      el.className = 'big ' + (pct >= 90 ? 'status-ok' : pct >= 70 ? 'status-warn' : 'status-err');
    }

    // Partitions
    let pHTML = '';
    parts.forEach(p => {
      let cls = p.mounted ? 'dot-mounted' : 'dot-unmounted';
      let today = new Date().getDay(); // 0=Sun
      let isoDay = today === 0 ? 7 : today;
      let isToday = p.day === isoDay;
      pHTML += '<div class="card day-card' + (isToday ? '" style="border:1px solid var(--accent)"' : '"') + '>' +
        '<div class="dot '+cls+'"></div>' +
        '<div style="font-weight:600">' + p.name + '</div>' +
        '<div style="font-size:.75rem;color:var(--muted)">' + (p.mounted ? '🟢 Online' : '⚫ Offline') + '</div>' +
        '</div>';
    });
    document.getElementById('partitions').innerHTML = pHTML;

    // History chart
    let chartHTML = '';
    let last30 = hist.slice(-30);
    let maxBytes = Math.max(...last30.map(h=>h.total_bytes_transferred||1));
    last30.forEach(h => {
      let height = Math.max(4, ((h.total_bytes_transferred||0)/maxBytes)*100);
      let color = h.all_ok ? 'var(--green)' : (h.failed > 0 ? 'var(--red)' : 'var(--yellow)');
      let d = new Date(h.timestamp);
      let tip = d.toLocaleDateString('it',{day:'2-digit',month:'2-digit'}) + ': ' +
        (h.all_ok ? 'OK' : h.failed+' errori');
      chartHTML += '<div title="'+tip+'" style="flex:1;display:flex;flex-direction:column;justify-content:end;align-items:center">' +
        '<div class="chart-bar" style="width:100%;height:'+height+'px;background:'+color+'"></div>' +
        '<div style="font-size:.6rem;color:var(--muted);margin-top:2px">'+d.getDate()+'</div></div>';
    });
    document.getElementById('history-chart').innerHTML = chartHTML;

    // Detail table
    if (latest && latest.sources) {
      let rows = '';
      latest.sources.forEach(s => {
        let badge = '';
        if (s.anomaly_blocked) badge = '<span class="badge badge-block">BLOCCATO</span>';
        else if (s.skipped) badge = '<span class="badge badge-skip">SALTATO</span>';
        else if (s.success) badge = '<span class="badge badge-ok">OK</span>';
        else badge = '<span class="badge badge-err">ERRORE</span>';

        let integrity = '—';
        if (s.integrity_verified > 0) {
          integrity = s.integrity_errors > 0
            ? '<span class="status-err">⚠ '+s.integrity_errors+'/'+s.integrity_verified+'</span>'
            : '<span class="status-ok">✓ '+s.integrity_verified+'</span>';
        }

        rows += '<tr><td>'+s.source_name+'</td><td>'+badge+'</td>' +
          '<td>'+(s.files_transferred||0).toLocaleString()+'</td>' +
          '<td>'+fmt(s.bytes_transferred||0)+'</td>' +
          '<td>'+fmtDur(s.elapsed_seconds)+'</td>' +
          '<td>'+integrity+'</td></tr>';
      });
      document.getElementById('detail-table').innerHTML = rows;
    }

  } catch(e) { console.error('Errore caricamento dati:', e); }
}

loadData();
setInterval(loadData, 60000);
</script>
</body>
</html>
"""


# ═════════════════════════════════════════════════════════════
#  ROUTES
# ═════════════════════════════════════════════════════════════

@app.route("/")
@require_auth
def dashboard():
    return render_template_string(DASHBOARD_HTML)


@app.route("/api/history")
@require_auth
def api_history():
    return jsonify(load_history())


@app.route("/api/latest")
@require_auth
def api_latest():
    report = load_latest_report()
    return jsonify(report or {})


@app.route("/api/partitions")
@require_auth
def api_partitions():
    try:
        return jsonify(get_partition_status())
    except Exception:
        return jsonify([])


@app.route("/api/health")
def api_health():
    """Healthcheck (senza auth, per monitoring esterno)."""
    history = load_history()
    if not history:
        return jsonify({"status": "unknown", "message": "Nessun backup registrato"}), 200

    last = history[-1]
    if last.get("all_ok", False):
        return jsonify({"status": "healthy", "last_backup": last.get("timestamp")}), 200
    else:
        return jsonify({
            "status": "unhealthy",
            "last_backup": last.get("timestamp"),
            "failed": last.get("failed", 0),
        }), 503


# ═════════════════════════════════════════════════════════════
#  MAIN
# ═════════════════════════════════════════════════════════════

def run_dashboard(cfg: dict):
    global DASHBOARD_CFG, STATE_DIR

    dash_cfg = cfg.get("dashboard", {})
    DASHBOARD_CFG = dash_cfg
    STATE_DIR = cfg.get("general", {}).get("state_dir", "/var/lib/backup_system")

    host = dash_cfg.get("host", "0.0.0.0")
    port = dash_cfg.get("port", 8847)

    logger.info(f"Dashboard avviata su http://{host}:{port}")
    app.run(host=host, port=port, debug=False)


if __name__ == "__main__":
    import argparse
    import yaml

    parser = argparse.ArgumentParser(description="Backup Dashboard")
    parser.add_argument("-c", "--config", default="/etc/backup_system/config.yaml")
    args = parser.parse_args()

    with open(args.config) as f:
        cfg = yaml.safe_load(f)

    logging.basicConfig(level=logging.INFO)
    run_dashboard(cfg)
