#!/usr/bin/env bash
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
INSTALL_DIR="/opt/so-ops"
SYSTEMD_DIR="/etc/systemd/system"
SERVICE_USER="soops"

if [[ $EUID -ne 0 ]]; then
    echo "Run as root: sudo bash systemd/install.sh" >&2
    exit 1
fi

# Create service user if it doesn't exist
if ! id "$SERVICE_USER" &>/dev/null; then
    useradd --system --no-create-home --shell /sbin/nologin "$SERVICE_USER"
    echo "Created user: $SERVICE_USER"
fi

# Add soops to docker group so it can run docker compose
usermod -aG docker "$SERVICE_USER"
echo "Added $SERVICE_USER to docker group"

# Copy repo to /opt/so-ops (skip if already there)
if [[ "$REPO_DIR" != "$INSTALL_DIR" ]]; then
    mkdir -p "$INSTALL_DIR"
    cp -r "$REPO_DIR"/. "$INSTALL_DIR/"
    chown -R "$SERVICE_USER:$SERVICE_USER" "$INSTALL_DIR"
    echo "Copied repo to $INSTALL_DIR"
fi

# Install unit files
for f in "$REPO_DIR"/systemd/*.service "$REPO_DIR"/systemd/*.timer; do
    cp "$f" "$SYSTEMD_DIR/"
done
echo "Installed unit files to $SYSTEMD_DIR"

systemctl daemon-reload

# Enable and start timers (services are triggered by timers, not started directly)
TIMERS=(so-triage.timer so-health.timer so-vulnscan-nmap.timer so-vulnscan-nuclei.timer)
for timer in "${TIMERS[@]}"; do
    systemctl enable --now "$timer"
    echo "Enabled: $timer"
done

echo ""
echo "Done. Active timers:"
systemctl list-timers so-*.timer
