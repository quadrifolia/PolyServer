#!/bin/bash
# Fix: Filter out intrusion sensor alarms from cron mail
# Issue: Hardware intrusion sensors showing false ALARM state causing email spam
# This script updates /usr/local/bin/log-sensors to exclude intrusion alarms

set -e

echo "Fixing intrusion sensor alarm spam..."

# Check if log-sensors script exists
if [ ! -f /usr/local/bin/log-sensors ]; then
    echo "❌ /usr/local/bin/log-sensors not found. This fix is not needed."
    exit 1
fi

# Backup the original script
cp /usr/local/bin/log-sensors /usr/local/bin/log-sensors.bak
echo "✅ Backed up original script to /usr/local/bin/log-sensors.bak"

# Create updated log-sensors script
cat > /usr/local/bin/log-sensors << 'EOF'
#!/bin/bash
# Log sensor data for logwatch analysis
LOGFILE="/var/log/sensors/sensors.log"
DATE=$(date '+%Y-%m-%d %H:%M:%S')

# Ensure log directory exists
mkdir -p /var/log/sensors

# Log current sensor readings
echo "[$DATE] Sensor readings:" >> "$LOGFILE"
sensors >> "$LOGFILE" 2>/dev/null
echo "" >> "$LOGFILE"

# Check for critical temperatures and log alerts
# Exclude: intrusion sensors (false positives), unconfigured voltage sensors (min/max = 0V), zero-threshold temps
if sensors 2>/dev/null | grep -E "CRITICAL|ALARM" | grep -v "intrusion" | grep -v "max =  +0.00 V" | grep -v "high =  +0.0°C" | grep -v "+0.0" | grep -q .; then
    echo "[$DATE] CRITICAL: Sensor alerts detected!" >> "$LOGFILE"
    sensors 2>/dev/null | grep -E "CRITICAL|ALARM" | grep -v "intrusion" | grep -v "max =  +0.00 V" | grep -v "high =  +0.0°C" >> "$LOGFILE"
    echo "" >> "$LOGFILE"
fi

# Rotate log if it gets too large (keep last 1000 lines)
if [ -f "$LOGFILE" ] && [ $(wc -l < "$LOGFILE") -gt 1000 ]; then
    tail -n 500 "$LOGFILE" > "${LOGFILE}.tmp" && mv "${LOGFILE}.tmp" "$LOGFILE"
fi
EOF

# Set executable permissions
chmod +x /usr/local/bin/log-sensors

echo "✅ Updated /usr/local/bin/log-sensors to filter out intrusion sensor alarms"
echo ""
echo "Changes made:"
echo "  • Intrusion sensor ALARMS filtered (common false positives)"
echo "  • Unconfigured voltage sensor ALARMS filtered (min/max = 0V)"
echo "  • Unconfigured temperature threshold ALARMS filtered (high = 0°C)"
echo "  • All sensor data still logged to /var/log/sensors/sensors.log"
echo "  • Only REAL critical temperature/voltage issues will trigger emails"
echo ""
echo "To restore the original script: sudo mv /usr/local/bin/log-sensors.bak /usr/local/bin/log-sensors"
