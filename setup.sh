#!/usr/bin/env bash
# ============================================================
#  SETUP — Backup Rotazionale v2.0
#  Run as root:  sudo bash setup.sh
# ============================================================
set -euo pipefail

INSTALL_DIR="/opt/backup_system"
CONFIG_DIR="/etc/backup_system"
LOG_DIR="/var/log/backup_system"
STATE_DIR="/var/lib/backup_system"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SRC_DIR="$SCRIPT_DIR/src"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

echo ""
echo -e "${CYAN}============================================${NC}"
echo -e "${CYAN}  Backup Rotazionale v2.0 — Setup${NC}"
echo -e "${CYAN}============================================${NC}"
echo ""

if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}ERROR: run as root (sudo bash setup.sh)${NC}"
    exit 1
fi

# ─── 1. Dependencies ─────────────────────────────────────
echo -e "${GREEN}[1/8]${NC} Installing dependencies …"
apt-get update -qq
apt-get install -y -qq \
    rsync \
    cifs-utils \
    smbclient \
    cryptsetup \
    python3 \
    python3-pip \
    python3-yaml \
    python3-flask 2>/dev/null || true

python3 -c "import flask" 2>/dev/null || pip3 install flask --break-system-packages 2>/dev/null || pip3 install flask

# ─── 2. Directories ──────────────────────────────────────
echo -e "${GREEN}[2/8]${NC} Creating directories …"
mkdir -p "$INSTALL_DIR"
mkdir -p "$CONFIG_DIR"
mkdir -p "$LOG_DIR"
mkdir -p "$STATE_DIR"
mkdir -p /mnt/source
mkdir -p /mnt/backup/day_{1,2,3,4,5,6,7}
mkdir -p /mnt/backup_archive/monthly
mkdir -p /mnt/restore_staging

# ─── 3. Copy scripts ─────────────────────────────────────
echo -e "${GREEN}[3/8]${NC} Copying scripts to $INSTALL_DIR …"
for PY_FILE in backup_rotazionale.py backup_core.py backup_rsync.py \
               backup_security.py backup_retention.py backup_notify.py \
               backup_dashboard.py backup_restore.py; do
    if [[ -f "$SRC_DIR/$PY_FILE" ]]; then
        cp "$SRC_DIR/$PY_FILE" "$INSTALL_DIR/"
        chmod 700 "$INSTALL_DIR/$PY_FILE"
        echo "  ✓ $PY_FILE"
    else
        echo -e "  ${YELLOW}⚠ $PY_FILE not found in $SRC_DIR${NC}"
    fi
done

# ─── 4. Configuration ────────────────────────────────────
echo -e "${GREEN}[4/8]${NC} Configuration …"
if [[ ! -f "$CONFIG_DIR/config.yaml" ]]; then
    if [[ -f "$SCRIPT_DIR/examples/config.yaml" ]]; then
        cp "$SCRIPT_DIR/examples/config.yaml" "$CONFIG_DIR/"
        echo -e "  ${YELLOW}→ config.yaml copied — EDIT IT before first run!${NC}"
    else
        echo -e "  ${YELLOW}→ No example config found. Create $CONFIG_DIR/config.yaml manually.${NC}"
    fi
else
    echo "  → config.yaml already exists, not overwritten."
fi

# ─── 5. Credentials ──────────────────────────────────────
echo -e "${GREEN}[5/8]${NC} Credential files …"
for CRED in creds_fileserver creds_domain_admin; do
    CRED_PATH="$CONFIG_DIR/$CRED"
    if [[ ! -f "$CRED_PATH" ]]; then
        cat > "$CRED_PATH" <<'CRED'
username=backup_user
password=CHANGE_ME
domain=WORKGROUP
CRED
        chmod 600 "$CRED_PATH"
        echo -e "  ${YELLOW}→ Created $CRED_PATH (edit before use!)${NC}"
    else
        echo "  → $CRED already exists."
    fi
done

# ─── 5b. LUKS key ────────────────────────────────────────
LUKS_KEY="$CONFIG_DIR/luks.key"
if [[ ! -f "$LUKS_KEY" ]]; then
    echo -e "${GREEN}[5b]${NC} Generating LUKS key …"
    dd if=/dev/urandom of="$LUKS_KEY" bs=4096 count=1 2>/dev/null
    chmod 600 "$LUKS_KEY"
    echo -e "  ${YELLOW}→ LUKS key generated: $LUKS_KEY${NC}"
    echo ""
    echo -e "  ${CYAN}To set up LUKS on each partition:${NC}"
    echo "    cryptsetup luksFormat /dev/sdXN --key-file $LUKS_KEY"
    echo "    cryptsetup luksOpen /dev/sdXN luks_name --key-file $LUKS_KEY"
    echo "    mkfs.ext4 -L LABEL /dev/mapper/luks_name"
    echo "    cryptsetup luksClose luks_name"
    echo ""
    echo "  Or disable LUKS in config.yaml: security.luks.enabled: false"
    echo ""
else
    echo "  → LUKS key already exists."
fi

# ─── 6. Crontab ──────────────────────────────────────────
echo -e "${GREEN}[6/8]${NC} Crontab …"
CRON_LINE="30 1 * * * /usr/bin/python3 $INSTALL_DIR/backup_rotazionale.py -c $CONFIG_DIR/config.yaml >> $LOG_DIR/cron.log 2>&1"
(crontab -l 2>/dev/null | grep -v "backup_rotazionale" || true; echo "$CRON_LINE") | crontab -
echo "  → Backup scheduled: every night at 01:30"

# ─── 7. Logrotate ────────────────────────────────────────
echo -e "${GREEN}[7/8]${NC} Logrotate …"
cat > /etc/logrotate.d/backup_system <<'LR'
/var/log/backup_system/*.log {
    weekly
    rotate 12
    compress
    delaycompress
    missingok
    notifempty
    create 640 root root
}
LR
echo "  → Logrotate configured (12 weeks retention)"

# ─── 8. Systemd service ──────────────────────────────────
echo -e "${GREEN}[8/8]${NC} Systemd service for dashboard …"
cat > /etc/systemd/system/backup-dashboard.service <<EOF
[Unit]
Description=Backup Rotazionale — Web Dashboard
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 $INSTALL_DIR/backup_dashboard.py -c $CONFIG_DIR/config.yaml
Restart=on-failure
RestartSec=10
User=root

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable backup-dashboard.service 2>/dev/null || true
echo "  → Service created (start with: systemctl start backup-dashboard)"

# ─── Done ─────────────────────────────────────────────────
echo ""
echo -e "${CYAN}============================================${NC}"
echo -e "${GREEN}  Installation complete!${NC}"
echo -e "${CYAN}============================================${NC}"
echo ""
echo "  NEXT STEPS:"
echo ""
echo "  1. Edit configuration:"
echo "     nano $CONFIG_DIR/config.yaml"
echo ""
echo "  2. Edit Windows credentials:"
echo "     nano $CONFIG_DIR/creds_fileserver"
echo "     nano $CONFIG_DIR/creds_domain_admin"
echo ""
echo "  3. (Optional) Set up LUKS encryption:"
echo "     See: docs/setup_luks.sh"
echo ""
echo "  4. Test in dry-run mode:"
echo "     Set dry_run: true in config.yaml, then:"
echo "     python3 $INSTALL_DIR/backup_rotazionale.py"
echo ""
echo "  5. Start the dashboard:"
echo "     systemctl start backup-dashboard"
echo "     → http://\$(hostname -I | awk '{print \$1}'):8847"
echo ""
echo "  6. Interactive restore:"
echo "     python3 $INSTALL_DIR/backup_restore.py"
echo ""
echo -e "${CYAN}============================================${NC}"
