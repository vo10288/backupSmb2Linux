#!/usr/bin/env bash
# ============================================================
#  LUKS Setup Helper — Backup Rotazionale
# ============================================================
#  Formats all 7 daily partitions + 1 monthly with LUKS.
#  Run as root. DESTRUCTIVE — all data on these partitions
#  will be erased!
#
#  Usage:  sudo bash docs/setup_luks.sh
#
#  Edit the PARTITIONS array below to match your system.
# ============================================================
set -euo pipefail

KEYFILE="/etc/backup_system/luks.key"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# ─── EDIT THESE TO MATCH YOUR SYSTEM ─────────────────────
# Format: "device  luks_name  label"
PARTITIONS=(
    "/dev/sdb1  backup_lun  BACKUP_LUN"
    "/dev/sdb2  backup_mar  BACKUP_MAR"
    "/dev/sdb3  backup_mer  BACKUP_MER"
    "/dev/sdb4  backup_gio  BACKUP_GIO"
    "/dev/sdc1  backup_ven  BACKUP_VEN"
    "/dev/sdc2  backup_sab  BACKUP_SAB"
    "/dev/sdc3  backup_dom  BACKUP_DOM"
    # Uncomment for monthly partition:
    # "/dev/sdd1  backup_monthly  BACKUP_MONTHLY"
)
# ──────────────────────────────────────────────────────────

if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}ERROR: run as root${NC}"
    exit 1
fi

if [[ ! -f "$KEYFILE" ]]; then
    echo -e "${RED}LUKS key not found: $KEYFILE${NC}"
    echo "Run setup.sh first, or create it manually:"
    echo "  dd if=/dev/urandom of=$KEYFILE bs=4096 count=1"
    echo "  chmod 600 $KEYFILE"
    exit 1
fi

echo ""
echo -e "${RED}╔══════════════════════════════════════════════╗${NC}"
echo -e "${RED}║  WARNING: This will ERASE all data on the   ║${NC}"
echo -e "${RED}║  listed partitions!                          ║${NC}"
echo -e "${RED}╚══════════════════════════════════════════════╝${NC}"
echo ""
echo "Partitions to format:"
for entry in "${PARTITIONS[@]}"; do
    read -r dev name label <<< "$entry"
    echo "  $dev → LUKS($name) → ext4($label)"
done
echo ""
read -p "Type 'YES' to proceed: " confirm
if [[ "$confirm" != "YES" ]]; then
    echo "Aborted."
    exit 0
fi

echo ""
for entry in "${PARTITIONS[@]}"; do
    read -r dev name label <<< "$entry"
    echo -e "${GREEN}━━━ $dev ($label) ━━━${NC}"

    # Check if LUKS is open
    if [[ -e "/dev/mapper/$name" ]]; then
        echo "  Closing existing LUKS mapping …"
        cryptsetup luksClose "$name" || true
    fi

    # Format LUKS
    echo "  LUKS format …"
    cryptsetup luksFormat "$dev" --key-file "$KEYFILE" --batch-mode

    # Open
    echo "  LUKS open …"
    cryptsetup luksOpen "$dev" "$name" --key-file "$KEYFILE"

    # Create filesystem
    echo "  Creating ext4 filesystem (label: $label) …"
    mkfs.ext4 -L "$label" "/dev/mapper/$name" -q

    # Close
    echo "  LUKS close …"
    cryptsetup luksClose "$name"

    echo -e "  ${GREEN}✓ Done${NC}"
    echo ""
done

echo -e "${GREEN}All partitions formatted successfully!${NC}"
echo ""
echo "Make sure your config.yaml has:"
echo "  security.luks.enabled: true"
echo "  security.luks.key_file: $KEYFILE"
echo ""
echo "And each partition has the correct luks_name set."
