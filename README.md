<img width="1200" height="1500" alt="infrastruttura_backup_linkedin" src="https://github.com/user-attachments/assets/26dddc8b-cdf2-4399-bbab-ede2504dd178" />

<div align="center">

# 🛡️ Backup Rotazionale

**Automated daily rotating backup system for mixed Linux/Windows environments**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/Python-3.10+-3776AB.svg?logo=python&logoColor=white)](https://python.org)
[![Linux](https://img.shields.io/badge/Platform-Linux-FCC624.svg?logo=linux&logoColor=black)](https://kernel.org)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](CONTRIBUTING.md)

*Mount Windows CIFS shares · LUKS encryption · Ransomware detection · Incremental rsync · Web dashboard*

[Features](#features) · [Quick Start](#quick-start) · [Configuration](#configuration) · [Dashboard](#dashboard) · [Italiano 🇮🇹](#italiano)

</div>

---

## Overview

Backup Rotazionale is a Python-based backup system designed for small/medium businesses (10–50 sources) that need to back up Windows domain machines onto a Linux server. It uses **7 rotating destination partitions** — one per day of the week — keeping only today's partition mounted and all others offline at all times.

This design ensures that even in the event of a ransomware attack, at most 1 out of 7 backup copies can be compromised.

```
  Windows Machines (CIFS)           Linux Backup Server
  ┌──────────────┐                 ┌──────────────────────────────────┐
  │ //srv/Share   │──mount cifs──▶ │ /mnt/source/srv_share            │
  │ //pc01/C$     │──mount cifs──▶ │ /mnt/source/pc01                 │
  │ //pc02/C$     │──mount cifs──▶ │ /mnt/source/pc02                 │
  └──────────────┘                 │                                  │
                                   │  rsync (incremental, --delete)   │
                                   │          │                       │
                                   │          ▼                       │
                                   │  /mnt/backup/day_N  (1 of 7)    │
                                   │   ┌──────┐                       │
                                   │   │ sdb1 │ Mon  ← MOUNTED       │
                                   │   │ sdb2 │ Tue  ← offline       │
                                   │   │ sdb3 │ Wed  ← offline       │
                                   │   │ sdb4 │ Thu  ← offline       │
                                   │   │ sdc1 │ Fri  ← offline       │
                                   │   │ sdc2 │ Sat  ← offline       │
                                   │   │ sdc3 │ Sun  ← offline       │
                                   │   └──────┘                       │
                                   └──────────────────────────────────┘
```

## Features

### 🔒 Security
- **LUKS encryption** on all destination partitions with auto key file
- **SHA-256 integrity verification** on a random sample of files after each backup
- **Ransomware/anomaly detection** — blocks backup if suspicious file extensions are found or file counts change anomalously, preserving the last known-good copy
- CIFS sources mounted **read-only**
- Credential files with strict permissions (`600`)

### 🔄 Resilience
- **Retry with exponential backoff** on mount and rsync operations
- **Pre-check** each source with ping + smbclient before attempting mount
- **Disk space verification** before starting rsync
- Lock file prevents concurrent executions
- Rsync exit code 24 (vanished files) handled gracefully

### 📊 Monitoring
- **Web dashboard** (Flask) with real-time partition status, 30-day history chart, per-source detail table
- **Healthcheck endpoint** (`/api/health`) for external uptime monitors — no auth required
- **JSON reports** + 90-day rolling history
- Email and webhook (Slack/Teams/Telegram) notifications

### 📦 Functionality
- **Monthly snapshots** with configurable retention (first backup of each month)
- **Interactive restore tool** — guided CLI wizard to browse and restore from any day
- **Parallel backup** of multiple sources (configurable worker count)
- Per-source **priority** ordering
- Per-source **include/exclude** path filtering

## Quick Start

### Prerequisites

- Linux server (Ubuntu 22.04+ / Debian 12+ recommended)
- Python 3.10+
- Root access
- Dedicated partitions for backups (7 daily + 1 optional monthly)

### Installation

```bash
# 1. Clone the repository
git clone https://github.com/YOUR_USERNAME/backup-rotazionale.git
cd backup-rotazionale

# 2. Run the setup script (as root)
sudo bash setup.sh

# 3. Edit configuration
sudo nano /etc/backup_system/config.yaml

# 4. Edit Windows credentials
sudo nano /etc/backup_system/creds_fileserver
sudo nano /etc/backup_system/creds_domain_admin

# 5. (Optional) Set up LUKS encryption
sudo bash docs/setup_luks.sh

# 6. Test in dry-run mode
# Set dry_run: true in config.yaml, then:
sudo python3 /opt/backup_system/backup_rotazionale.py

# 7. Start the dashboard
sudo systemctl start backup-dashboard
# Open http://your-server:8847
```

### Partition Setup

Format 7 partitions with recognizable labels. **Do not** add them to `/etc/fstab`.

```bash
# Without LUKS
mkfs.ext4 -L BACKUP_MON /dev/sdb1
mkfs.ext4 -L BACKUP_TUE /dev/sdb2
# ... etc

# With LUKS (recommended)
KEYFILE=/etc/backup_system/luks.key
for dev label name in \
    /dev/sdb1 BACKUP_MON backup_mon \
    /dev/sdb2 BACKUP_TUE backup_tue \
    /dev/sdb3 BACKUP_WED backup_wed \
    /dev/sdb4 BACKUP_THU backup_thu \
    /dev/sdc1 BACKUP_FRI backup_fri \
    /dev/sdc2 BACKUP_SAT backup_sat \
    /dev/sdc3 BACKUP_SUN backup_sun; do
    cryptsetup luksFormat "$dev" --key-file "$KEYFILE" --batch-mode
    cryptsetup luksOpen "$dev" "$name" --key-file "$KEYFILE"
    mkfs.ext4 -L "$label" "/dev/mapper/$name"
    cryptsetup luksClose "$name"
done
```

## Configuration

All settings live in a single YAML file (`/etc/backup_system/config.yaml`). See [`examples/config.yaml`](examples/config.yaml) for a fully commented example.

### Key Sections

| Section | Purpose |
|---|---|
| `general` | Log directory, lock file, parallelism, dry-run toggle |
| `security.luks` | LUKS encryption on/off, key file path |
| `security.integrity` | Post-backup hash verification settings |
| `security.anomaly_detection` | Ransomware detection thresholds and suspicious extensions |
| `resilience` | Retry counts, pre-check toggle, minimum free space |
| `sources` | List of Windows shares (CIFS) or NFS/local paths to back up |
| `destinations.partitions` | The 7 daily partitions (device, LUKS name, filesystem) |
| `rsync` | Bandwidth limit, timeout, extra arguments |
| `retention` | Monthly snapshot settings and retention period |
| `dashboard` | Web UI host, port, basic auth credentials |
| `notifications` | Email SMTP and/or webhook configuration |

## Dashboard

The built-in web dashboard provides a real-time overview:

- **KPI cards** — last backup date/status, 30-day success rate, data transferred, duration
- **Partition status** — 7 indicators showing which partition is currently online
- **History chart** — bar chart of the last 30 backups (green = OK, red = error)
- **Detail table** — per-source breakdown with status badges, file count, data size, integrity check results

Access it at `http://your-server:8847` (default). Protected by basic auth (configurable).

### Healthcheck

```bash
curl -s http://your-server:8847/api/health
# {"status": "healthy", "last_backup": "2026-02-05T01:45:00"}
```

Returns HTTP 200 if healthy, 503 if the last backup had errors. No authentication required — ideal for external monitoring services.

## Restore

```bash
sudo python3 /opt/backup_system/backup_restore.py
```

The interactive wizard guides you through:
1. Choosing the day (partition) to restore from
2. Selecting the source
3. Browsing the directory tree
4. Restoring everything, a specific subfolder, or copying files manually

## Project Structure

```
backup-rotazionale/
├── src/
│   ├── backup_rotazionale.py  # Main orchestrator (cron entry point)
│   ├── backup_core.py         # Mount/umount, LUKS, pre-check, retry
│   ├── backup_rsync.py        # Rsync execution, parallelism, stats
│   ├── backup_security.py     # Integrity hashing, anomaly detection
│   ├── backup_retention.py    # Monthly snapshots, cleanup
│   ├── backup_notify.py       # Email, webhook, JSON reports
│   ├── backup_dashboard.py    # Flask web dashboard
│   └── backup_restore.py      # Interactive restore wizard
├── examples/
│   └── config.yaml            # Fully commented example configuration
├── docs/
│   ├── ARCHITETTURA.md        # Architecture details (Italian)
│   └── setup_luks.sh          # LUKS setup helper script
├── setup.sh                   # Automated installer
├── requirements.txt
├── .gitignore
├── LICENSE
├── CONTRIBUTING.md
└── README.md
```

## Requirements

| Package | Purpose |
|---|---|
| `rsync` | Incremental file transfer |
| `cifs-utils` | Mount Windows shares |
| `smbclient` | Pre-check share availability |
| `cryptsetup` | LUKS encryption (optional) |
| `python3-yaml` / `PyYAML` | Configuration parsing |
| `flask` | Web dashboard |

All installed automatically by `setup.sh`.

---

## Italiano

<details>
<summary>🇮🇹 Clicca per la documentazione in italiano</summary>

### Panoramica

Sistema di backup automatico per ambienti misti Linux/Windows. Monta le share CIFS dei PC e server Windows a dominio, esegue backup incrementale con rsync, e salva su 7 partizioni rotazionali (una per giorno della settimana). Solo la partizione del giorno corrente viene montata; le altre restano sempre offline per protezione da ransomware.

### Installazione rapida

```bash
git clone https://github.com/YOUR_USERNAME/backup-rotazionale.git
cd backup-rotazionale
sudo bash setup.sh
sudo nano /etc/backup_system/config.yaml
sudo nano /etc/backup_system/creds_fileserver
```

### Funzionalità principali

- **Crittografia LUKS** sulle partizioni di destinazione
- **Rilevamento ransomware** pre-backup (estensioni sospette + variazioni anomale)
- **Verifica integrità** SHA-256 post-backup
- **Retry automatici** con backoff esponenziale
- **Dashboard web** su porta 8847
- **Snapshot mensili** con retention configurabile
- **Restore interattivo** guidato da CLI
- **Notifiche** email e webhook (Slack/Teams/Telegram)

### Comandi principali

```bash
# Backup manuale
sudo python3 /opt/backup_system/backup_rotazionale.py

# Dashboard
sudo systemctl start backup-dashboard

# Restore
sudo python3 /opt/backup_system/backup_restore.py

# Log
tail -f /var/log/backup_system/backup_*.log
```

</details>

---

## Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.
