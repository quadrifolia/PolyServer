#!/bin/bash
# Fix SSH ProtectSystem=strict read-write paths on running bastion
# This adds missing writable paths for system services

set -e

echo "===== Fixing SSH ProtectSystem Read-Write Paths ====="
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "❌ This script must be run as root"
    echo "   Run: su - (then enter root password)"
    echo "   Then: bash fix-sshd-readonly-paths.sh"
    exit 1
fi

# Backup existing config
if [ -f /etc/systemd/system/ssh.service.d/watchdog.conf ]; then
    cp /etc/systemd/system/ssh.service.d/watchdog.conf \
       /etc/systemd/system/ssh.service.d/watchdog.conf.backup-$(date +%Y%m%d-%H%M%S)
    echo "✅ Backed up existing configuration"
fi

# Show current configuration
echo "Current ReadWritePaths:"
grep "ReadWritePaths" /etc/systemd/system/ssh.service.d/watchdog.conf || echo "(not found)"
echo ""

# Update the configuration
echo "Updating ReadWritePaths to include /var/spool /var/tmp /var/lib /tmp..."

sed -i 's|^ReadWritePaths=.*|ReadWritePaths=/var/log /var/run /run /var/spool /var/tmp /var/lib /tmp|' \
    /etc/systemd/system/ssh.service.d/watchdog.conf

echo "✅ Updated configuration"
echo ""

# Show new configuration
echo "New ReadWritePaths:"
grep "ReadWritePaths" /etc/systemd/system/ssh.service.d/watchdog.conf
echo ""

# Reload systemd and restart SSH
echo "Reloading systemd daemon..."
systemctl daemon-reload

echo ""
echo "⚠️  SSH service needs to be restarted for changes to take effect."
echo "   This will disconnect your current SSH session!"
echo ""
read -p "Restart SSH now? (yes/no): " -r
if [[ "$REPLY" =~ ^[Yy]es$ ]]; then
    echo "Restarting SSH service in 3 seconds..."
    sleep 3
    systemctl restart ssh
    echo "✅ SSH service restarted"
else
    echo "⚠️  SSH NOT restarted - changes will not take effect until restart"
    echo "   Run: systemctl restart ssh"
fi

echo ""
echo "===== Fix Complete ====="
echo ""
echo "New SSH sessions will have access to write to:"
echo "  - /var/log (logs)"
echo "  - /var/run and /run (runtime files)"
echo "  - /var/spool (mail queues, cron, etc.)"
echo "  - /var/tmp (temporary files)"
echo "  - /var/lib (application data)"
echo "  - /tmp (temporary files)"
echo ""
echo "All other paths remain read-only for security (ProtectSystem=strict)"
