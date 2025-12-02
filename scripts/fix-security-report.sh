#!/bin/bash
# fix-security-report.sh - Fix daily security report to handle log rotation
# Fixes issues where logs are rotated at midnight, causing empty reports

set -Eeuo pipefail

if [ "$EUID" -ne 0 ]; then
    echo "❌ This script must be run as root"
    exit 1
fi

echo "=================================================="
echo "Fixing Daily Security Report Script"
echo "=================================================="
echo ""
echo "Issues being fixed:"
echo "  • SSH activity detection (now reads .log.1 for yesterday)"
echo "  • UFW blocked connections (now reads kern.log.1)"
echo "  • Fail2ban jail statistics (adds detailed stats per jail)"
echo "  • Audit summary date format (fixes time component requirement)"
echo "  • Critical events detection (uses correct date variables)"
echo ""

# Backup existing script
if [ -f /etc/cron.daily/bastion-security-report ]; then
    cp /etc/cron.daily/bastion-security-report /etc/cron.daily/bastion-security-report.backup
    echo "✅ Backed up existing script to bastion-security-report.backup"
fi

# Create fixed daily security report script
cat > /etc/cron.daily/bastion-security-report << 'EOF'
#!/bin/bash
# Daily Bastion Security Report - Fixed version

DATE=$(date +%Y-%m-%d)
HOSTNAME=$(hostname)
REPORT_FILE="/tmp/bastion-security-report-$DATE.txt"

echo "======================================================================" > $REPORT_FILE
echo "BASTION HOST SECURITY REPORT - $HOSTNAME - $DATE" >> $REPORT_FILE
echo "======================================================================" >> $REPORT_FILE
echo "" >> $REPORT_FILE

echo "SYSTEM OVERVIEW" >> $REPORT_FILE
echo "===============" >> $REPORT_FILE
echo "Hostname: $HOSTNAME" >> $REPORT_FILE
echo "Uptime: $(uptime)" >> $REPORT_FILE
echo "Load Average: $(cat /proc/loadavg)" >> $REPORT_FILE
echo "Disk Usage: $(df -h / | awk 'NR==2 {print $5}')" >> $REPORT_FILE
echo "Memory Usage: $(free -h | awk 'NR==2{printf "%.2f%%", $3*100/$2 }')" >> $REPORT_FILE
echo "" >> $REPORT_FILE

echo "SSH ACTIVITY SUMMARY" >> $REPORT_FILE
echo "====================" >> $REPORT_FILE
# Match both publickey and password authentication
# Note: Logs rotate at midnight, so yesterday's data is in .log.1
# Use %e for day with leading space instead of zero (Dec  2 not Dec 02)
YESTERDAY_DATE=$(date -d yesterday '+%b %e')
SUCCESSFUL_LOGINS=$(grep "$YESTERDAY_DATE" /var/log/auth.log.1 2>/dev/null | grep -E "Accepted (publickey|password)" | wc -l)
FAILED_LOGINS=$(grep "$YESTERDAY_DATE" /var/log/auth.log.1 2>/dev/null | grep -E "Failed (password|publickey)" | wc -l)
ACTIVE_SESSIONS=$(who | wc -l)
echo "Successful logins yesterday: $SUCCESSFUL_LOGINS" >> $REPORT_FILE
echo "Failed login attempts yesterday: $FAILED_LOGINS" >> $REPORT_FILE
echo "Currently active sessions: $ACTIVE_SESSIONS" >> $REPORT_FILE
echo "" >> $REPORT_FILE

echo "RECENT SUCCESSFUL LOGINS" >> $REPORT_FILE
echo "========================" >> $REPORT_FILE
LOGINS_FOUND=$(grep "$YESTERDAY_DATE" /var/log/auth.log.1 2>/dev/null | grep -E "Accepted (publickey|password)" | tail -10)
if [ -n "$LOGINS_FOUND" ]; then
    echo "$LOGINS_FOUND" >> $REPORT_FILE
else
    echo "No successful SSH logins found for yesterday" >> $REPORT_FILE
fi
echo "" >> $REPORT_FILE

echo "FIREWALL STATUS & STATISTICS" >> $REPORT_FILE
echo "============================" >> $REPORT_FILE
ufw status numbered >> $REPORT_FILE 2>/dev/null || echo "UFW status unavailable" >> $REPORT_FILE
echo "" >> $REPORT_FILE

echo "UFW BLOCKED CONNECTIONS (Yesterday)" >> $REPORT_FILE
echo "====================================" >> $REPORT_FILE
# Generate UFW block statistics from rotated kern.log
# Yesterday's kern.log is in .log.1 after midnight rotation
UFW_BLOCKS=$(grep "UFW BLOCK" /var/log/kern.log.1 2>/dev/null | wc -l)
echo "Total blocked connections: $UFW_BLOCKS" >> $REPORT_FILE
if [ $UFW_BLOCKS -gt 0 ]; then
    echo "" >> $REPORT_FILE
    echo "Top 10 blocked source IPs:" >> $REPORT_FILE
    grep "UFW BLOCK" /var/log/kern.log.1 2>/dev/null | \
        grep -o "SRC=[0-9.]*" | cut -d= -f2 | sort | uniq -c | sort -nr | head -10 | \
        awk '{printf "  %s attempts from %s\n", $1, $2}' >> $REPORT_FILE 2>/dev/null || true
    echo "" >> $REPORT_FILE
    echo "Top 10 blocked destination ports (with service identification):" >> $REPORT_FILE
    grep "UFW BLOCK" /var/log/kern.log.1 2>/dev/null | \
        grep -o "DPT=[0-9]*" | cut -d= -f2 | sort | uniq -c | sort -nr | head -10 | \
        while read count port; do
            case "$port" in
                22) service="SSH (default)";;
                23) service="Telnet";;
                80) service="HTTP";;
                443) service="HTTPS";;
                445) service="SMB";;
                3306) service="MySQL";;
                3389) service="RDP";;
                5060) service="SIP";;
                5432) service="PostgreSQL";;
                5555) service="Android Debug";;
                8000|8080|8081|8088|8443|8728|8888) service="HTTP-alt/Web";;
                9100) service="Printer/JetDirect";;
                *) service="Unknown";;
            esac
            printf "  %s attempts on port %s (%s)\n" "$count" "$port" "$service" >> $REPORT_FILE
        done
    echo "" >> $REPORT_FILE
    echo "ℹ️  Note: UFW blocks occur at firewall level, before reaching services." >> $REPORT_FILE
    echo "   Fail2ban only tracks attempts that reach SSH authentication." >> $REPORT_FILE
fi
echo "" >> $REPORT_FILE

echo "FAIL2BAN STATUS & STATISTICS" >> $REPORT_FILE
echo "=============================" >> $REPORT_FILE
if command -v fail2ban-client >/dev/null 2>&1; then
    fail2ban-client status >> $REPORT_FILE 2>/dev/null || echo "Fail2ban status unavailable" >> $REPORT_FILE
    echo "" >> $REPORT_FILE

    # Get detailed statistics for each jail
    JAILS=$(fail2ban-client status 2>/dev/null | grep "Jail list:" | cut -d: -f2 | tr ',' '\n' | xargs)
    if [ -n "$JAILS" ]; then
        echo "Jail Statistics:" >> $REPORT_FILE
        for jail in $JAILS; do
            echo "" >> $REPORT_FILE
            echo "[$jail]" >> $REPORT_FILE
            fail2ban-client status "$jail" 2>/dev/null | grep -E "Currently failed|Total failed|Currently banned|Total banned" >> $REPORT_FILE || true
        done
    fi
else
    echo "Fail2ban not installed" >> $REPORT_FILE
fi
echo "" >> $REPORT_FILE

echo "AUDIT SUMMARY" >> $REPORT_FILE
echo "=============" >> $REPORT_FILE
echo "" >> $REPORT_FILE
# Use proper date format for ausearch: MM/DD/YYYY HH:MM:SS (time required!)
# Get yesterday's date range (00:00:00 to 23:59:59)
YESTERDAY_START=$(date -d "yesterday" "+%m/%d/%Y 00:00:00")
YESTERDAY_END=$(date -d "yesterday" "+%m/%d/%Y 23:59:59")

# Check if auditd is running
if ! systemctl is-active --quiet auditd; then
    echo "⚠️  auditd service is not running - no audit data available" >> $REPORT_FILE
elif ! command -v ausearch >/dev/null 2>&1 || ! command -v aureport >/dev/null 2>&1; then
    echo "⚠️  Audit tools not installed" >> $REPORT_FILE
else
    # Try to get audit summary with better error handling
    AUDIT_TEMP=$(mktemp)
    if ausearch --start "$YESTERDAY_START" --end "$YESTERDAY_END" > "$AUDIT_TEMP" 2>/dev/null && [ -s "$AUDIT_TEMP" ]; then
        aureport --summary -i < "$AUDIT_TEMP" >> $REPORT_FILE 2>/dev/null || {
            echo "Audit events found but report generation failed" >> $REPORT_FILE
            echo "Event count: $(wc -l < "$AUDIT_TEMP")" >> $REPORT_FILE
        }
    else
        echo "No audit events found for yesterday ($YESTERDAY_START to $YESTERDAY_END)" >> $REPORT_FILE
        echo "Note: Auditd may have been recently installed or logs rotated" >> $REPORT_FILE
    fi
    rm -f "$AUDIT_TEMP"
fi
echo "" >> $REPORT_FILE

echo "CRITICAL SECURITY EVENTS" >> $REPORT_FILE
echo "========================" >> $REPORT_FILE
if systemctl is-active --quiet auditd && command -v ausearch >/dev/null 2>&1; then
    EVENTS_FOUND=0

    # Check for privilege escalation events
    if ausearch -k privilege_escalation --start "$YESTERDAY_START" --end "$YESTERDAY_END" >> $REPORT_FILE 2>/dev/null; then
        EVENTS_FOUND=1
    fi

    # Check for user command events (last 20)
    if ausearch -k user_commands --start "$YESTERDAY_START" --end "$YESTERDAY_END" 2>/dev/null | tail -20 >> $REPORT_FILE; then
        EVENTS_FOUND=1
    fi

    if [ $EVENTS_FOUND -eq 0 ]; then
        echo "No critical security events found for yesterday" >> $REPORT_FILE
    fi
else
    echo "⚠️  Audit system not available" >> $REPORT_FILE
fi
echo "" >> $REPORT_FILE

# Email the report
cat $REPORT_FILE | mail -s "📊 BASTION [$HOSTNAME]: Daily Security Report" root

# Cleanup
rm -f $REPORT_FILE
EOF

chmod 755 /etc/cron.daily/bastion-security-report

echo "✅ Security report script updated successfully"
echo ""
echo "To test the fixed script now:"
echo "  sudo /etc/cron.daily/bastion-security-report"
echo ""
echo "Or wait for tomorrow's automatic report"
echo ""
