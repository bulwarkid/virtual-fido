#!/usr/bin/env bash
set -euo pipefail

# Setup script for Virtual FIDO on Linux (UHID transport)
# Enables non-root access to /dev/uhid via plugdev group or uaccess

RULE_FILE="/etc/udev/rules.d/70-virtual-fido-uhid.rules"

echo "=== Virtual FIDO Linux UHID Setup ==="

if [ "$(id -u)" -ne 0 ]; then
    echo "This script requires sudo to configure udev rules."
    echo "Running: sudo bash $0"
    exec sudo bash "$0" "$@"
fi

TARGET_USER="${SUDO_USER:-$USER}"

echo "1. Adding udev rule for /dev/uhid..."
cat << 'EOF' > "$RULE_FILE"
# Allow plugdev group and active console sessions to access /dev/uhid for Virtual FIDO
KERNEL=="uhid", SUBSYSTEM=="misc", GROUP="plugdev", MODE="0660", TAG+="uaccess"
EOF

echo "2. Ensuring group plugdev exists..."
groupadd -f plugdev

if [ -n "$TARGET_USER" ]; then
    echo "3. Adding user $TARGET_USER to plugdev group..."
    usermod -a -G plugdev "$TARGET_USER"
fi

echo "4. Reloading udev rules..."
udevadm control --reload-rules
udevadm trigger --name-match=uhid || true

echo "5. Adjusting current /dev/uhid permissions..."
if [ -e /dev/uhid ]; then
    chgrp plugdev /dev/uhid || true
    chmod 0660 /dev/uhid || true
fi

echo "=== Done! /dev/uhid is now accessible to plugdev members. ==="
echo "If your user was just added to plugdev, you may need to log out and back in,"
echo "or run: newgrp plugdev"
