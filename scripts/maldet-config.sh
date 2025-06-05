#!/bin/bash
# Configure Linux Malware Detect (maldet) with secure settings

# Stop script on any error
set -e

# Configure maldet for optimal security
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
scan_cpumax="75"

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

# Create maldet daily scan script with notifications
cat > /etc/cron.daily/maldet-scan << 'EOF'
#!/bin/bash
# Daily maldet scan script

# Log file
LOGFILE="/var/log/maldet/daily_scan.log"

# Make sure log directory exists
mkdir -p /var/log/maldet

# Start the log
echo "Linux Malware Detect daily scan started at $(date)" > $LOGFILE

# Run scan on important directories
/usr/local/sbin/maldet --scan-all /home /opt/polyserver /var/www >> $LOGFILE 2>&1

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

# Force initial maldet signature update
/usr/local/sbin/maldet --update-sigs

echo "Linux Malware Detect (maldet) configured with secure settings."
echo "Daily scans will check /home, /opt/polyserver, and /var/www directories."
echo "Email alerts will be sent to root if malware is found."