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
mkdir -p "$REPORT_DIR"

# Generate report filename
REPORT_FILE="${REPORT_DIR}/audit-report-${DATE}.txt"

# Start report
{
    echo "==============================================================="
    echo "Audit Report for $HOSTNAME on $DATE"
    echo "==============================================================="
    echo ""
} > "$REPORT_FILE"

# System Summary
{
    echo "SYSTEM SUMMARY"
    echo "==============="
    uname -a
    echo ""
    echo "Uptime: $(uptime)"
    echo ""
} >> "$REPORT_FILE"

# General Summary Report
{
    echo "GENERAL SUMMARY"
    echo "==============="
    ausearch --start today --end now | aureport --summary -i
    echo ""
} >> "$REPORT_FILE"

# Authentication Report
{
    echo "AUTHENTICATION EVENTS"
    echo "===================="
    ausearch --start today --end now | aureport --auth --summary -i
    echo ""
} >> "$REPORT_FILE"

# User Modification Events
{
    echo "USER MODIFICATION EVENTS"
    echo "======================="
    ausearch -k user_modify --start today --end now -i
    echo ""
} >> "$REPORT_FILE"

# Executable Summary
{
    echo "EXECUTABLE SUMMARY"
    echo "================="
    ausearch --start today --end now | aureport --executable --summary -i
    echo ""
} >> "$REPORT_FILE"

# Suspicious Command Executions
{
    echo "SUSPICIOUS COMMAND EXECUTIONS"
    echo "============================"
    ausearch -k data_exfiltration --start today --end now -i
    echo ""
} >> "$REPORT_FILE"

# File Modification Events
{
    echo "CONFIG FILE MODIFICATION EVENTS"
    echo "============================="
    ausearch -k sshd_config_modifications --start today --end now -i
    ausearch -k nginx_config --start today --end now -i
    ausearch -k docker_config --start today --end now -i
    ausearch -k application_config_changes --start today --end now -i
    ausearch -k security_tool_config --start today --end now -i
    echo ""
} >> "$REPORT_FILE"

# Privilege Escalation
{
    echo "PRIVILEGE ESCALATION EVENTS"
    echo "========================="
    ausearch -k privilege_escalation --start today --end now -i
    echo ""
} >> "$REPORT_FILE"

# Unauthorized Access Attempts
{
    echo "UNAUTHORIZED ACCESS ATTEMPTS"
    echo "=========================="
    ausearch -k unauthorized_access --start today --end now -i
    echo ""
} >> "$REPORT_FILE"

# Binary Modifications
{
    echo "BINARY MODIFICATION EVENTS"
    echo "========================="
    ausearch -k binary_modifications --start today --end now -i
    echo ""
} >> "$REPORT_FILE"

# Docker Socket Access
{
    echo "DOCKER SOCKET ACCESS"
    echo "==================="
    ausearch -k docker_socket_access --start today --end now -i
    echo ""
} >> "$REPORT_FILE"

# DNS Lookups (if needed - can be very verbose)
{
    echo "DNS LOOKUP EVENTS (Last 10)"
    echo "========================="
    ausearch -k dns_lookup --start today --end now -i | tail -n 50
    echo ""
} >> "$REPORT_FILE"

# Audit System Status
{
    echo "AUDIT SYSTEM STATUS"
    echo "=================="
    auditctl -s
    echo ""
    auditctl -l
    echo ""
} >> "$REPORT_FILE"

# Check for empty report (only headings) and add note if so
if [ "$(grep -vc "^$\|^=\|^[A-Z]" "$REPORT_FILE")" -eq 0 ]; then
    echo "No significant audit events recorded for this period." >> "$REPORT_FILE"
fi

# Email report if there are significant events
if grep -q "type=\|command=\|success=\|.*=yes\|modified\|executed" "$REPORT_FILE"; then
    mail -s "Audit Report for $HOSTNAME - $DATE" "$MAIL_RECIPIENT" < "$REPORT_FILE"
fi

# Cleanup old reports (keep 30 days)
find "$REPORT_DIR" -name "audit-report-*.txt" -mtime +30 -delete

exit 0