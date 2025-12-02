#!/bin/bash
# fix-aide-exclude-logs.sh - Exclude /var/log from AIDE monitoring
# Run on existing bastion servers to reduce AIDE noise from log file changes

set -Eeuo pipefail

if [ "$EUID" -ne 0 ]; then
    echo "❌ This script must be run as root"
    exit 1
fi

echo "=================================================="
echo "Excluding /var/log from AIDE monitoring"
echo "=================================================="
echo ""

# Update AIDE exclusions
echo "Updating AIDE exclusions..."
cat > /etc/aide/aide.conf.d/99-bastion-exclusions << 'EOF'
# Bastion-specific AIDE exclusions
# Exclude entire /var/log directory - logs change constantly by design
# Monitoring log files with AIDE creates excessive noise without security value
!/var/log
EOF

echo "✅ AIDE exclusions updated"
echo ""
echo "⚠️  IMPORTANT: You need to reinitialize the AIDE database"
echo "   This will take several minutes and will reset the baseline."
echo ""
read -p "Reinitialize AIDE database now? (yes/no): " -r

if [[ "$REPLY" =~ ^[Yy]es$ ]]; then
    echo ""
    echo "Reinitializing AIDE database (this may take 5-10 minutes)..."

    # Stop the check timer during reinitialization
    systemctl stop aide-check.timer 2>/dev/null || true

    # Reinitialize database
    nice -n 19 aide --config=/etc/aide/aide.conf --init

    # Replace old database with new one
    if [ -f /var/lib/aide/aide.db.new ]; then
        mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
        echo "✅ AIDE database reinitialized successfully"
    else
        echo "❌ Failed to create new AIDE database"
        exit 1
    fi

    # Restart the timer
    systemctl start aide-check.timer 2>/dev/null || true

    echo ""
    echo "✅ Complete! /var/log is now excluded from AIDE monitoring"
    echo "   Future reports will no longer include log file changes"
else
    echo ""
    echo "⚠️  Skipped database reinitialization"
    echo "   Run manually: sudo /usr/local/bin/aide-update"
fi

echo ""
