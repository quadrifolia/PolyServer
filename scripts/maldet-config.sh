#!/bin/bash
# Configure Linux Malware Detect (maldet) with secure settings

# Stop script on any error
set -e

# Configure systemd resource limits for maldet
mkdir -p /etc/systemd/system/maldet.service.d
cat > /etc/systemd/system/maldet.service.d/resource-limits.conf << 'EOF'
[Service]
# Resource limits to prevent maldet from overwhelming system
CPUQuota=30%
MemoryMax=512M
MemoryHigh=400M
Nice=15
IOSchedulingClass=2
IOSchedulingPriority=4
OOMPolicy=kill
OOMScoreAdjust=300

# Security and isolation
PrivateTmp=true
ProtectSystem=strict
NoNewPrivileges=true
ReadWritePaths=/usr/local/maldetect /var/log/maldet /tmp

# Restart policy
Restart=on-failure
RestartSec=60
TimeoutStartSec=300
TimeoutStopSec=30

# Watchdog configuration
WatchdogSec=600
NotifyAccess=main
EOF

# Configure maldet for optimal security with resource awareness
cat > /usr/local/maldetect/conf.maldet << EOF
# Linux Malware Detect v1.6.x
# Configuration File

# Enable Email Alerting (1 = enabled, 0 = disabled)
email_alert="1"

# Email Address in which you want to receive scan reports and alerts
# Separate multiple email addresses with a space: "user@domain.com user2@domain.com"
email_addr="root"

# Use with ClamAV (1 = enabled, 0 = disabled)
clamav_scan="1"

# Quarantine malicious files (1 = enabled, 0 = disabled)
quarantine_hits="1"

# Clean/Delete malicious files (1 = enabled, 0 = disabled)
quarantine_clean="0"

# Clean/Delete suspicious files (1 = enabled, 0 = disabled)
quarantine_suspend_user="0"

# Minimum userid value that can be suspended
quarantine_suspend_user_minuid="500"

# Enable Email Alerting for all scan users (1 = enabled, 0 = disabled)
email_subj="[MALWARE] ${HOSTNAME}: Linux Malware Detection on \${domain_count} domains"

# Use path names relative to a domain for cleaner reports
email_ignore_clean="1"

# Allow clean/delete operation to use signatures with HEX string matches below this value
quar_hex_min_suspect="70"

# The default find command to use, use of 'xargs' is required
# for 'find -exec' to queue and optimize processing of find matches
find_cmd="find \\\${scan_location} -type f -not -path '/proc/*' -not -path '/sys/*' -print0 | xargs -0 -P 10 -n 100"

# The default basis for determining file system ownership of a file
# should always be the username:group of the file/directory
file_owner_lookup="1"

# Size limit on files being scanned (in KB)
max_filesize="10240"

# When using the -r scan operation to scan root directory & user paths, the max directory depth
# that will be scanned, beyond that will be ignored.
maxdepth="15"

# The maximum amount of file download attempts that will be made before giving up
url_max_dl="3"

# The curl command line that handles all remote file transfers,
# adjust timeout and max-time to meet connectivity requirements.
curl_timeout="30"
curl_max_time="60"

# The maximum number of child processes that maldet should fork to handle scan operations,
# by default we fork one scan thread per available CPU.
scan_max_process="5"

# The maximum number of process operations that maldet should fork per signature in hex scan operations,
# limit this to 2 to reduce CPU load at expense of scan speed.
scan_max_process_hex="2"

# Additional paths for daily cron scan
scan_paths="/home /opt/polyserver /var/www"

# Do not scan mounts/paths defined here
scan_ignore_paths="/proc /sys /dev"

# Total CPU usage threshold (percentage) at which scanning will be suspended until usage drops
# Reduced from 75% to prevent resource conflicts with ClamAV and other services
scan_cpumax="60"

# Allow maldet to download and install updated signatures from rfxn.com
autoupdate="1"

# Daily automatic updates of malware signatures
autoupdate_signatures="1"

# Daily automatic updates of maldet
autoupdate_version="1"

# When defined, the update process will source this external file from
# rfxn.com following the update if it exists. This is used to deploy
# critical configuration settings to all installations.
autoupdate_version_hashed="1"

# Run weekly cronjob at specific day and time
cron_weekly_day="2"  # 0 = Sunday, 1 = Monday, 2 = Tuesday, etc.
cron_weekly_hour="3" # Hour in 24h format
cron_daily_hour="3"  # Hour in 24h format
EOF

# Create maldet daily scan script with resource-aware execution
cat > /etc/cron.daily/maldet-scan << 'EOF'
#!/bin/bash
# Daily maldet scan script with resource management

# Log file
LOGFILE="/var/log/maldet/daily_scan.log"

# Make sure log directory exists
mkdir -p /var/log/maldet

# Check system load before starting scan
LOAD_THRESHOLD=2.0
CURRENT_LOAD=$(uptime | awk -F'load average:' '{ print $2 }' | awk '{ print $1 }' | sed 's/,//')

if (( $(echo "$CURRENT_LOAD > $LOAD_THRESHOLD" | bc -l) )); then
    echo "$(date): System load too high ($CURRENT_LOAD), skipping maldet scan" >> $LOGFILE
    exit 0
fi

# Start the log
echo "Linux Malware Detect daily scan started at $(date)" > $LOGFILE
echo "System load: $CURRENT_LOAD" >> $LOGFILE

# Run scan with nice priority and resource limits
nice -n 19 ionice -c 3 timeout 3600 /usr/local/sbin/maldet --scan-all /home /opt/polyserver /var/www >> $LOGFILE 2>&1

# Check if scan completed or timed out
SCAN_EXIT_CODE=$?
if [ $SCAN_EXIT_CODE -eq 124 ]; then
    echo "$(date): Scan timed out after 1 hour" >> $LOGFILE
elif [ $SCAN_EXIT_CODE -ne 0 ]; then
    echo "$(date): Scan failed with exit code $SCAN_EXIT_CODE" >> $LOGFILE
fi

# Finish log
echo "Linux Malware Detect daily scan completed at $(date)" >> $LOGFILE

# Check for detections
if grep -q "malware hits" $LOGFILE; then
    HITS=$(grep "malware hits" $LOGFILE | grep -o '[0-9]\+')
    if [ "$HITS" -gt 0 ]; then
        # Send email alert if malware found
        cat $LOGFILE | mail -s "⚠️ MALWARE WARNING: $HITS malware hits found on $(hostname)" root
    fi
fi
EOF

# Make scan script executable
chmod 755 /etc/cron.daily/maldet-scan

# Apply systemd resource limits and reload daemon
systemctl daemon-reload
systemctl try-restart maldet 2>/dev/null || true

# Force initial maldet signature update with resource limits
nice -n 19 timeout 300 /usr/local/sbin/maldet --update-sigs

echo "Linux Malware Detect (maldet) configured with resource-aware settings."
echo "Resource limits: 30% CPU, 512MB memory, nice level 15"
echo "Daily scans will check /home, /opt/polyserver, and /var/www directories."
echo "Scans will be skipped if system load exceeds 2.0"
echo "Email alerts will be sent to root if malware is found."