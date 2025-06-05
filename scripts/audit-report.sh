#!/bin/bash
# audit-report.sh - Generate comprehensive audit reports
# This script generates daily summary reports from auditd logs

# Set variables
DATE=$(date +%Y-%m-%d)
REPORT_DIR="/var/log/audit/reports"
LOG_FILE="/var/log/audit/audit.log"
MAIL_RECIPIENT="root"
HOSTNAME=$(hostname)

# Create report directory if it doesn't exist
mkdir -p $REPORT_DIR

# Generate report filename
REPORT_FILE="${REPORT_DIR}/audit-report-${DATE}.txt"

# Start report
echo "===============================================================" > $REPORT_FILE
echo "Audit Report for $HOSTNAME on $DATE" >> $REPORT_FILE
echo "===============================================================" >> $REPORT_FILE
echo "" >> $REPORT_FILE

# System Summary
echo "SYSTEM SUMMARY" >> $REPORT_FILE
echo "===============" >> $REPORT_FILE
uname -a >> $REPORT_FILE
echo "" >> $REPORT_FILE
echo "Uptime: $(uptime)" >> $REPORT_FILE
echo "" >> $REPORT_FILE

# General Summary Report
echo "GENERAL SUMMARY" >> $REPORT_FILE
echo "===============" >> $REPORT_FILE
ausearch --start today --end now | aureport --summary -i >> $REPORT_FILE
echo "" >> $REPORT_FILE

# Authentication Report
echo "AUTHENTICATION EVENTS" >> $REPORT_FILE
echo "====================" >> $REPORT_FILE
ausearch --start today --end now | aureport --auth --summary -i >> $REPORT_FILE
echo "" >> $REPORT_FILE

# User Modification Events
echo "USER MODIFICATION EVENTS" >> $REPORT_FILE
echo "=======================" >> $REPORT_FILE
ausearch -k user_modify --start today --end now -i >> $REPORT_FILE
echo "" >> $REPORT_FILE

# Executable Summary
echo "EXECUTABLE SUMMARY" >> $REPORT_FILE
echo "=================" >> $REPORT_FILE
ausearch --start today --end now | aureport --executable --summary -i >> $REPORT_FILE
echo "" >> $REPORT_FILE

# Suspicious Command Executions
echo "SUSPICIOUS COMMAND EXECUTIONS" >> $REPORT_FILE
echo "============================" >> $REPORT_FILE
ausearch -k data_exfiltration --start today --end now -i >> $REPORT_FILE
echo "" >> $REPORT_FILE

# File Modification Events
echo "CONFIG FILE MODIFICATION EVENTS" >> $REPORT_FILE
echo "=============================" >> $REPORT_FILE
ausearch -k sshd_config_modifications --start today --end now -i >> $REPORT_FILE
ausearch -k nginx_config --start today --end now -i >> $REPORT_FILE
ausearch -k docker_config --start today --end now -i >> $REPORT_FILE
ausearch -k application_config_changes --start today --end now -i >> $REPORT_FILE
ausearch -k security_tool_config --start today --end now -i >> $REPORT_FILE
echo "" >> $REPORT_FILE

# Privilege Escalation
echo "PRIVILEGE ESCALATION EVENTS" >> $REPORT_FILE
echo "=========================" >> $REPORT_FILE
ausearch -k privilege_escalation --start today --end now -i >> $REPORT_FILE
echo "" >> $REPORT_FILE

# Unauthorized Access Attempts
echo "UNAUTHORIZED ACCESS ATTEMPTS" >> $REPORT_FILE
echo "==========================" >> $REPORT_FILE
ausearch -k unauthorized_access --start today --end now -i >> $REPORT_FILE
echo "" >> $REPORT_FILE

# Binary Modifications
echo "BINARY MODIFICATION EVENTS" >> $REPORT_FILE
echo "=========================" >> $REPORT_FILE
ausearch -k binary_modifications --start today --end now -i >> $REPORT_FILE
echo "" >> $REPORT_FILE

# Docker Socket Access
echo "DOCKER SOCKET ACCESS" >> $REPORT_FILE
echo "===================" >> $REPORT_FILE
ausearch -k docker_socket_access --start today --end now -i >> $REPORT_FILE
echo "" >> $REPORT_FILE

# DNS Lookups (if needed - can be very verbose)
echo "DNS LOOKUP EVENTS (Last 10)" >> $REPORT_FILE
echo "=========================" >> $REPORT_FILE
ausearch -k dns_lookup --start today --end now -i | tail -n 50 >> $REPORT_FILE
echo "" >> $REPORT_FILE

# Audit System Status
echo "AUDIT SYSTEM STATUS" >> $REPORT_FILE
echo "==================" >> $REPORT_FILE
auditctl -s >> $REPORT_FILE
echo "" >> $REPORT_FILE
auditctl -l >> $REPORT_FILE
echo "" >> $REPORT_FILE

# Check for empty report (only headings) and add note if so
if [ $(grep -v "^$\|^=\|^[A-Z]" $REPORT_FILE | wc -l) -eq 0 ]; then
    echo "No significant audit events recorded for this period." >> $REPORT_FILE
fi

# Email report if there are significant events
if grep -q "type=\|command=\|success=\|.*=yes\|modified\|executed" $REPORT_FILE; then
    cat $REPORT_FILE | mail -s "Audit Report for $HOSTNAME - $DATE" $MAIL_RECIPIENT
fi

# Cleanup old reports (keep 30 days)
find $REPORT_DIR -name "audit-report-*.txt" -mtime +30 -delete

exit 0