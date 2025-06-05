#!/bin/bash
# DSGVO/GDPR Compliance Check Script for PolyServer
# This script performs automated checks to verify GDPR compliance status.

# Set terminal colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NORMAL='\033[0m'

# Set variables
TIMESTAMP=$(date +"%Y-%m-%d")
LOG_DIR="/var/log/compliance"
REPORT_FILE="${LOG_DIR}/dsgvo_check_${TIMESTAMP}.txt"
CONFIG_DIR="/etc/dsgvo"
DATA_INVENTORY_FILE="${CONFIG_DIR}/data_inventory.json"
DPO_EMAIL=$(grep -Po 'DPO_EMAIL=\K.*' /etc/dsgvo/contacts.conf 2>/dev/null || echo "dpo@example.com")

# Create log directory if it doesn't exist
mkdir -p "${LOG_DIR}"

# Function to check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to check if a file exists and is not older than days
check_file_recent() {
    local file="$1"
    local days="$2"
    
    if [ -f "$file" ]; then
        local file_age=$(find "$file" -mtime -"$days" | wc -l)
        if [ "$file_age" -gt 0 ]; then
            return 0 # File exists and is recent
        else
            return 1 # File exists but is too old
        fi
    else
        return 2 # File doesn't exist
    fi
}

# Function to check a requirement and record the result
check_requirement() {
    local description="$1"
    local check_command="$2"
    local requirement_type="$3"
    
    echo -n "Checking $description... "
    
    # Run the check command
    if eval "$check_command"; then
        echo -e "[${GREEN}PASS${NORMAL}]"
        echo "✓ $description: PASSED" >> "${REPORT_FILE}"
        return 0
    else
        if [ "$requirement_type" == "critical" ]; then
            echo -e "[${RED}FAIL${NORMAL}]"
            echo "✗ $description: FAILED (CRITICAL)" >> "${REPORT_FILE}"
            CRITICAL_FAILURES=$((CRITICAL_FAILURES + 1))
        else
            echo -e "[${YELLOW}WARN${NORMAL}]"
            echo "! $description: WARNING" >> "${REPORT_FILE}"
            WARNINGS=$((WARNINGS + 1))
        fi
        return 1
    fi
}

# Initialize report
{
    echo "===================================================="
    echo "    DSGVO/GDPR COMPLIANCE CHECK - ${TIMESTAMP}"
    echo "===================================================="
    echo ""
    echo "SYSTEM INFORMATION"
    echo "------------------"
    echo "Hostname: $(hostname)"
    echo "IP Address: $(hostname -I | awk '{print $1}')"
    echo "Check Time: $(date)"
    echo ""
    echo "COMPLIANCE CHECK RESULTS"
    echo "------------------------"
    echo ""
} > "${REPORT_FILE}"

# Initialize counters
TOTAL_CHECKS=0
PASSED_CHECKS=0
WARNINGS=0
CRITICAL_FAILURES=0

# Header
clear
echo -e "${BOLD}============================================================${NORMAL}"
echo -e "${BOLD}       DSGVO/GDPR Compliance Check for PolyServer           ${NORMAL}"
echo -e "${BOLD}============================================================${NORMAL}"
echo -e "Date: ${BLUE}${TIMESTAMP}${NORMAL}"
echo -e "Report will be saved to: ${YELLOW}${REPORT_FILE}${NORMAL}\n"

echo -e "${BOLD}DOCUMENTATION CHECKS${NORMAL}"
echo "------------------------------------------------------------"

# Check if DSGVO directory exists first
if [ ! -d "/etc/dsgvo" ]; then
    echo -e "${RED}ERROR: DSGVO configuration directory /etc/dsgvo does not exist.${NORMAL}"
    echo -e "Please run the DSGVO setup script first:"
    echo -e "  ${YELLOW}sudo /opt/polyserver/scripts/setup-dsgvo.sh${NORMAL}"
    echo -e ""
    echo -e "This will create all necessary DSGVO compliance files and directories."
    exit 1
fi

# Check for required documentation
TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
check_requirement "Privacy policy exists" "[ -f '/etc/dsgvo/privacy_policy.md' ]" "critical" && PASSED_CHECKS=$((PASSED_CHECKS + 1))

TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
check_requirement "DSGVO procedures document exists" "[ -f '/etc/dsgvo/dsgvo_procedures.md' ]" "critical" && PASSED_CHECKS=$((PASSED_CHECKS + 1))

TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
check_requirement "Data processing records exist" "[ -f '/etc/dsgvo/processing_records.md' ]" "critical" && PASSED_CHECKS=$((PASSED_CHECKS + 1))

TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
check_requirement "Data processing records updated in last 12 months" "check_file_recent '/etc/dsgvo/processing_records.md' 365" "warning" && PASSED_CHECKS=$((PASSED_CHECKS + 1))

TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
check_requirement "Data inventory exists" "[ -f '$DATA_INVENTORY_FILE' ]" "critical" && PASSED_CHECKS=$((PASSED_CHECKS + 1))

TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
check_requirement "Data inventory updated in last 3 months" "check_file_recent '$DATA_INVENTORY_FILE' 90" "warning" && PASSED_CHECKS=$((PASSED_CHECKS + 1))

TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
check_requirement "DPO contact information is defined" "grep -q 'DPO_EMAIL' /etc/dsgvo/contacts.conf" "critical" && PASSED_CHECKS=$((PASSED_CHECKS + 1))

echo -e "\n${BOLD}SECURITY CHECKS${NORMAL}"
echo "------------------------------------------------------------"

# Check for security measures
TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
check_requirement "HTTPS is enabled" "grep -q 'ssl_certificate' /etc/nginx/sites-enabled/default 2>/dev/null || grep -rq 'ssl_certificate' /etc/nginx/conf.d/ 2>/dev/null" "critical" && PASSED_CHECKS=$((PASSED_CHECKS + 1))

TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
check_requirement "TLS version is 1.2 or higher" "grep -q 'ssl_protocols.*TLSv1.2' /etc/nginx/sites-enabled/default 2>/dev/null || grep -rq 'ssl_protocols.*TLSv1.2' /etc/nginx/conf.d/ 2>/dev/null" "critical" && PASSED_CHECKS=$((PASSED_CHECKS + 1))

TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
check_requirement "Strong cipher suites configured" "grep -q 'ssl_ciphers' /etc/nginx/sites-enabled/default 2>/dev/null || grep -rq 'ssl_ciphers' /etc/nginx/conf.d/ 2>/dev/null" "critical" && PASSED_CHECKS=$((PASSED_CHECKS + 1))

TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
check_requirement "HTTP headers for security are configured" "grep -q 'X-Content-Type-Options' /etc/nginx/sites-enabled/default 2>/dev/null || grep -rq 'X-Content-Type-Options' /etc/nginx/conf.d/ 2>/dev/null" "warning" && PASSED_CHECKS=$((PASSED_CHECKS + 1))

TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
check_requirement "Firewall is active" "command_exists 'ufw' && ufw status | grep -q 'active'" "critical" && PASSED_CHECKS=$((PASSED_CHECKS + 1))

TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
check_requirement "Backups are encrypted" "grep -q 'ENCRYPT_BACKUPS=true' /opt/polyserver/config/backup.conf 2>/dev/null" "critical" && PASSED_CHECKS=$((PASSED_CHECKS + 1))

# Check for audit logging
TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
check_requirement "Audit logging is enabled" "grep -q 'AUDIT_LOGGING=true' /opt/polyserver/config/app.conf 2>/dev/null" "critical" && PASSED_CHECKS=$((PASSED_CHECKS + 1))

TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
check_requirement "Log retention policy is defined" "grep -q 'LOG_RETENTION' /opt/polyserver/config/app.conf 2>/dev/null" "warning" && PASSED_CHECKS=$((PASSED_CHECKS + 1))

echo -e "\n${BOLD}ACCESS CONTROL CHECKS${NORMAL}"
echo "------------------------------------------------------------"

# Check for access controls
TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
check_requirement "Password policy is enabled" "grep -q 'PASSWORD_COMPLEXITY=strong' /opt/polyserver/config/app.conf 2>/dev/null" "critical" && PASSED_CHECKS=$((PASSED_CHECKS + 1))

TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
check_requirement "User access review conducted in last 90 days" "[ -f '/etc/dsgvo/access_review.log' ] && find '/etc/dsgvo/access_review.log' -mtime -90 | grep -q ." "warning" && PASSED_CHECKS=$((PASSED_CHECKS + 1))

TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
check_requirement "Session timeout is configured" "grep -q 'SESSION_TIMEOUT' /opt/polyserver/config/app.conf 2>/dev/null" "warning" && PASSED_CHECKS=$((PASSED_CHECKS + 1))

TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
check_requirement "Admin users are limited" "grep -Eq 'ADMIN_USERS_COUNT=[1-5]' /opt/polyserver/config/app.conf 2>/dev/null" "warning" && PASSED_CHECKS=$((PASSED_CHECKS + 1))

echo -e "\n${BOLD}DATA MANAGEMENT CHECKS${NORMAL}"
echo "------------------------------------------------------------"

# Check for data management
TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
check_requirement "Data retention policy is documented" "[ -f '/etc/dsgvo/retention_policy.md' ]" "critical" && PASSED_CHECKS=$((PASSED_CHECKS + 1))

TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
check_requirement "Data deletion procedures are documented" "[ -f '/etc/dsgvo/deletion_procedures.md' ]" "critical" && PASSED_CHECKS=$((PASSED_CHECKS + 1))

TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
check_requirement "Data subject request procedures exist" "[ -f '/etc/dsgvo/subject_request_procedures.md' ]" "critical" && PASSED_CHECKS=$((PASSED_CHECKS + 1))

TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
check_requirement "Data subject requests tracked" "[ -f '/etc/dsgvo/subject_requests.log' ]" "warning" && PASSED_CHECKS=$((PASSED_CHECKS + 1))

# Check for data processing agreements
TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
check_requirement "Data processing agreements documented" "[ -d '/etc/dsgvo/processing_agreements' ] && [ "$(ls -A /etc/dsgvo/processing_agreements 2>/dev/null)" ]" "critical" && PASSED_CHECKS=$((PASSED_CHECKS + 1))

echo -e "\n${BOLD}BREACH RESPONSE CHECKS${NORMAL}"
echo "------------------------------------------------------------"

# Check for breach response readiness
TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
check_requirement "Breach response procedure exists" "[ -f '/etc/dsgvo/breach_response.md' ]" "critical" && PASSED_CHECKS=$((PASSED_CHECKS + 1))

TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
check_requirement "Breach response script exists" "[ -f '/opt/polyserver/scripts/breach-response-checklist.sh' ] && [ -x '/opt/polyserver/scripts/breach-response-checklist.sh' ]" "critical" && PASSED_CHECKS=$((PASSED_CHECKS + 1))

TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
check_requirement "Authority contacts are up-to-date" "grep -q 'AUTHORITY_EMAIL' /etc/dsgvo/contacts.conf" "critical" && PASSED_CHECKS=$((PASSED_CHECKS + 1))

TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
check_requirement "Breach response tested in last 12 months" "[ -f '/etc/dsgvo/breach_drill.log' ] && find '/etc/dsgvo/breach_drill.log' -mtime -365 | grep -q ." "warning" && PASSED_CHECKS=$((PASSED_CHECKS + 1))

echo -e "\n${BOLD}TRAINING CHECKS${NORMAL}"
echo "------------------------------------------------------------"

# Check for team training
TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
check_requirement "DSGVO training records exist" "[ -f '/etc/dsgvo/training_records.csv' ]" "critical" && PASSED_CHECKS=$((PASSED_CHECKS + 1))

TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
check_requirement "DSGVO training conducted in last 12 months" "[ -f '/etc/dsgvo/training_records.csv' ] && find '/etc/dsgvo/training_records.csv' -mtime -365 | grep -q ." "critical" && PASSED_CHECKS=$((PASSED_CHECKS + 1))

# Calculate compliance score
COMPLIANCE_SCORE=$((PASSED_CHECKS * 100 / TOTAL_CHECKS))

# Append summary to report
{
    echo ""
    echo "COMPLIANCE SUMMARY"
    echo "------------------"
    echo "Total checks: ${TOTAL_CHECKS}"
    echo "Passed checks: ${PASSED_CHECKS}"
    echo "Warnings: ${WARNINGS}"
    echo "Critical failures: ${CRITICAL_FAILURES}"
    echo "Compliance score: ${COMPLIANCE_SCORE}%"
    echo ""
    echo "GENERATED ON: $(date)"
    echo "REPORT PATH: ${REPORT_FILE}"
    
    if [ $CRITICAL_FAILURES -gt 0 ]; then
        echo ""
        echo "CRITICAL ISSUES REQUIRE IMMEDIATE ATTENTION"
        echo "Please address all critical failures as soon as possible to ensure DSGVO compliance."
    fi
} >> "${REPORT_FILE}"

# Display summary
echo -e "\n${BOLD}COMPLIANCE SUMMARY${NORMAL}"
echo "------------------------------------------------------------"
echo -e "Total checks: ${BLUE}${TOTAL_CHECKS}${NORMAL}"
echo -e "Passed checks: ${GREEN}${PASSED_CHECKS}${NORMAL}"
echo -e "Warnings: ${YELLOW}${WARNINGS}${NORMAL}"
echo -e "Critical failures: ${RED}${CRITICAL_FAILURES}${NORMAL}"
echo -e "Compliance score: ${BLUE}${COMPLIANCE_SCORE}%${NORMAL}"
echo ""

# Display appropriate message based on compliance score
if [ $COMPLIANCE_SCORE -eq 100 ]; then
    echo -e "${GREEN}Full compliance achieved!${NORMAL}"
elif [ $COMPLIANCE_SCORE -ge 80 ]; then
    echo -e "${YELLOW}Good compliance level, but some issues need attention.${NORMAL}"
elif [ $COMPLIANCE_SCORE -ge 60 ]; then
    echo -e "${YELLOW}Moderate compliance level. Several issues need to be addressed.${NORMAL}"
else
    echo -e "${RED}Poor compliance level. Immediate action required!${NORMAL}"
fi

# Email report if mail command is available
if command_exists "mail" && [ -n "$DPO_EMAIL" ]; then
    echo ""
    echo -e "Emailing report to DPO (${BLUE}${DPO_EMAIL}${NORMAL})..."
    cat "${REPORT_FILE}" | mail -s "DSGVO Compliance Check Report - ${TIMESTAMP}" "$DPO_EMAIL"
fi

echo ""
echo -e "Full report saved to: ${YELLOW}${REPORT_FILE}${NORMAL}"
echo -e "${BOLD}============================================================${NORMAL}"

exit 0