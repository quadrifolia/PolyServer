#!/bin/bash
# DSGVO/GDPR Data Breach Response Checklist
# This script helps guide the initial response to a data breach incident
# by walking through essential steps and documenting actions taken.

# Set terminal colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NORMAL='\033[0m'

# Set variables
TIMESTAMP=$(date +"%Y-%m-%d_%H-%M-%S")
LOG_DIR="/var/log/security/incidents"
INCIDENT_DIR="${LOG_DIR}/incident_${TIMESTAMP}"
REPORT_FILE="${INCIDENT_DIR}/incident_report.txt"
EVIDENCE_DIR="${INCIDENT_DIR}/evidence"
TIMELINE_FILE="${INCIDENT_DIR}/timeline.txt"
CONTACT_FILE="/etc/dsgvo/contacts.conf"
EVIDENCE_SCRIPT="/opt/polyserver/scripts/collect-forensics.sh"

# Create directories
mkdir -p "${INCIDENT_DIR}"
mkdir -p "${EVIDENCE_DIR}"

# Initialize files
touch "${REPORT_FILE}"
touch "${TIMELINE_FILE}"

# Log action with timestamp
log_action() {
    echo "$(date +"%Y-%m-%d %H:%M:%S") - $1" >> "${TIMELINE_FILE}"
    echo -e "[${GREEN}✓${NORMAL}] $1"
}

# Log command output to evidence
capture_evidence() {
    local cmd="$1"
    local filename="$2"
    
    echo "Running: $cmd" >> "${EVIDENCE_DIR}/${filename}"
    echo "----------------------------------------" >> "${EVIDENCE_DIR}/${filename}"
    eval "$cmd" >> "${EVIDENCE_DIR}/${filename}" 2>&1
    echo -e "\n\n" >> "${EVIDENCE_DIR}/${filename}"
    
    log_action "Evidence captured: ${filename}"
}

# Header
clear
echo -e "${BOLD}============================================================${NORMAL}"
echo -e "${BOLD}       DSGVO/GDPR Data Breach Response Checklist            ${NORMAL}"
echo -e "${BOLD}============================================================${NORMAL}"
echo -e "Incident reference: ${YELLOW}incident_${TIMESTAMP}${NORMAL}"
echo -e "Documentation directory: ${BLUE}${INCIDENT_DIR}${NORMAL}\n"

# Step 1: Collect basic incident information
echo -e "${BOLD}STEP 1: BASIC INCIDENT INFORMATION${NORMAL}"
echo "------------------------------------------------------------"

read -p "Your name: " RESPONDER_NAME
read -p "Your role: " RESPONDER_ROLE
read -p "Brief description of the incident: " INCIDENT_DESCRIPTION
read -p "How was the incident discovered?: " DISCOVERY_METHOD
read -p "Estimated start time of incident (YYYY-MM-DD HH:MM or 'unknown'): " INCIDENT_START

# Save basic information
{
    echo "DSGVO/GDPR DATA BREACH INCIDENT REPORT"
    echo "======================================"
    echo ""
    echo "INCIDENT REFERENCE: incident_${TIMESTAMP}"
    echo "DATE OF REPORT: $(date +"%Y-%m-%d %H:%M:%S")"
    echo "RESPONDER: ${RESPONDER_NAME} (${RESPONDER_ROLE})"
    echo ""
    echo "INITIAL DESCRIPTION"
    echo "------------------"
    echo "${INCIDENT_DESCRIPTION}"
    echo ""
    echo "DISCOVERY INFORMATION"
    echo "--------------------"
    echo "Discovery method: ${DISCOVERY_METHOD}"
    echo "Estimated start: ${INCIDENT_START}"
    echo "Time discovered: $(date +"%Y-%m-%d %H:%M:%S")"
    echo ""
} > "${REPORT_FILE}"

log_action "Initial incident information documented"

# Step 2: Containment actions
echo -e "\n${BOLD}STEP 2: CONTAINMENT ACTIONS${NORMAL}"
echo "------------------------------------------------------------"
echo -e "${YELLOW}Consider these immediate containment actions:${NORMAL}"
echo "  - Isolate affected systems from the network"
echo "  - Block compromised accounts"
echo "  - Preserve logs and evidence"
echo "  - Do NOT power off systems (evidence may be lost)"
echo ""

read -p "Have you isolated affected systems? (y/n/na): " ISOLATED
read -p "Have you blocked compromised accounts? (y/n/na): " BLOCKED
read -p "Which systems are affected? (comma-separated): " AFFECTED_SYSTEMS

# Document containment actions
{
    echo "CONTAINMENT ACTIONS"
    echo "------------------"
    echo "Systems isolated: ${ISOLATED}"
    echo "Accounts blocked: ${BLOCKED}"
    echo "Affected systems: ${AFFECTED_SYSTEMS}"
    echo ""
} >> "${REPORT_FILE}"

log_action "Containment actions documented"

# Step 3: Evidence collection
echo -e "\n${BOLD}STEP 3: EVIDENCE COLLECTION${NORMAL}"
echo "------------------------------------------------------------"
echo -e "${YELLOW}Collecting system evidence. This may take a few minutes...${NORMAL}"

# Collect network connections
capture_evidence "netstat -tulanp" "network_connections.txt"

# Collect running processes
capture_evidence "ps auxf" "running_processes.txt"

# Collect logged in users
capture_evidence "who" "logged_in_users.txt"

# Collect last logins
capture_evidence "last -20" "recent_logins.txt"

# Collect auth logs
if [ -f "/var/log/auth.log" ]; then
    capture_evidence "tail -1000 /var/log/auth.log" "auth_logs.txt"
fi

# Collect nginx logs if available
if [ -d "/var/log/nginx" ]; then
    capture_evidence "tail -1000 /var/log/nginx/access.log" "nginx_access.log"
    capture_evidence "tail -1000 /var/log/nginx/error.log" "nginx_error.log"
fi

# Check for suspicious network traffic
capture_evidence "timeout 30 tcpdump -nn -c 100" "network_traffic.txt"

# Run more extensive evidence collection script if available
if [ -f "$EVIDENCE_SCRIPT" ]; then
    echo -e "${YELLOW}Running detailed forensic collection script...${NORMAL}"
    bash "$EVIDENCE_SCRIPT" "$EVIDENCE_DIR"
    log_action "Detailed forensic evidence collected"
fi

# Document evidence collected
{
    echo "EVIDENCE COLLECTED"
    echo "-----------------"
    echo "Location: ${EVIDENCE_DIR}"
    echo "Files collected:"
    ls -la "${EVIDENCE_DIR}" | awk '{print "  - " $9}' | grep -v '^  - \.$' | grep -v '^  - \.\.$' >> "${REPORT_FILE}"
    echo ""
} >> "${REPORT_FILE}"

log_action "Initial evidence collection completed"

# Step 4: Data impact assessment
echo -e "\n${BOLD}STEP 4: DATA IMPACT ASSESSMENT${NORMAL}"
echo "------------------------------------------------------------"
echo -e "${YELLOW}Determining impact on personal data:${NORMAL}"

read -p "Was personal data accessed or exfiltrated? (yes/no/unknown): " DATA_ACCESSED
read -p "What types of personal data were potentially affected? " DATA_TYPES
read -p "Approximate number of data subjects affected: " DATA_SUBJECTS
read -p "Could this result in a risk to individuals' rights and freedoms? (yes/no/unknown): " RISK_ASSESSMENT

# Document data impact
{
    echo "DATA IMPACT ASSESSMENT"
    echo "---------------------"
    echo "Personal data accessed: ${DATA_ACCESSED}"
    echo "Types of data affected: ${DATA_TYPES}"
    echo "Estimated data subjects: ${DATA_SUBJECTS}"
    echo "Risk assessment: ${RISK_ASSESSMENT}"
    echo ""
} >> "${REPORT_FILE}"

log_action "Data impact assessment documented"

# Step 5: Notification requirements
echo -e "\n${BOLD}STEP 5: NOTIFICATION REQUIREMENTS${NORMAL}"
echo "------------------------------------------------------------"

# Determine if authority notification is required
AUTHORITY_REQUIRED="unknown"
SUBJECTS_REQUIRED="unknown"

if [[ "$DATA_ACCESSED" == "yes" && "$RISK_ASSESSMENT" == "yes" ]]; then
    AUTHORITY_REQUIRED="yes"
    echo -e "${RED}AUTHORITY NOTIFICATION REQUIRED WITHIN 72 HOURS${NORMAL}"
    
    if [[ "$RISK_ASSESSMENT" == "yes" ]]; then
        SUBJECTS_REQUIRED="yes"
        echo -e "${RED}DATA SUBJECT NOTIFICATION REQUIRED${NORMAL}"
    fi
elif [[ "$DATA_ACCESSED" == "unknown" || "$RISK_ASSESSMENT" == "unknown" ]]; then
    AUTHORITY_REQUIRED="unknown"
    SUBJECTS_REQUIRED="unknown"
    echo -e "${YELLOW}FURTHER INVESTIGATION NEEDED TO DETERMINE NOTIFICATION REQUIREMENTS${NORMAL}"
else
    AUTHORITY_REQUIRED="no"
    SUBJECTS_REQUIRED="no"
    echo -e "${GREEN}No notifications appear to be required based on information provided${NORMAL}"
fi

# Document notification requirements
{
    echo "NOTIFICATION ASSESSMENT"
    echo "----------------------"
    echo "Authority notification required: ${AUTHORITY_REQUIRED}"
    echo "Data subject notification required: ${SUBJECTS_REQUIRED}"
    echo ""
} >> "${REPORT_FILE}"

# Look up contact information if available
if [ -f "$CONTACT_FILE" ]; then
    source "$CONTACT_FILE"
    {
        echo "CONTACT INFORMATION"
        echo "------------------"
        echo "Data Protection Officer: ${DPO_NAME}"
        echo "DPO Contact: ${DPO_EMAIL}, ${DPO_PHONE}"
        echo "Supervisory Authority: ${AUTHORITY_NAME}"
        echo "Authority Contact: ${AUTHORITY_EMAIL}, ${AUTHORITY_PHONE}"
        echo ""
    } >> "${REPORT_FILE}"
    
    echo -e "Contact Information:"
    echo -e "  - DPO: ${BLUE}${DPO_NAME}${NORMAL} (${DPO_EMAIL}, ${DPO_PHONE})"
    echo -e "  - Authority: ${BLUE}${AUTHORITY_NAME}${NORMAL} (${AUTHORITY_EMAIL})"
fi

log_action "Notification requirements assessed"

# Step 6: Additional notes
echo -e "\n${BOLD}STEP 6: ADDITIONAL NOTES${NORMAL}"
echo "------------------------------------------------------------"

read -p "Enter any additional notes or observations: " ADDITIONAL_NOTES

# Document additional notes
if [ ! -z "$ADDITIONAL_NOTES" ]; then
    {
        echo "ADDITIONAL NOTES"
        echo "---------------"
        echo "${ADDITIONAL_NOTES}"
        echo ""
    } >> "${REPORT_FILE}"
fi

# Step 7: Completion and next steps
echo -e "\n${BOLD}STEP 7: NEXT STEPS${NORMAL}"
echo "------------------------------------------------------------"

{
    echo "RECOMMENDED NEXT STEPS"
    echo "--------------------"
    echo "1. Notify the Data Protection Officer immediately"
    echo "2. Continue gathering evidence and monitoring the situation"
    echo "3. Prepare for authority notification if required (72-hour deadline)"
    echo "4. Document all ongoing actions in the timeline file"
    echo "5. Secure all evidence and ensure chain of custody"
    echo ""
} >> "${REPORT_FILE}"

# Summary
echo -e "\n${BOLD}INCIDENT RESPONSE SUMMARY${NORMAL}"
echo "------------------------------------------------------------"
echo -e "Incident report created: ${BLUE}${REPORT_FILE}${NORMAL}"
echo -e "Evidence directory: ${BLUE}${EVIDENCE_DIR}${NORMAL}"
echo -e "Timeline file: ${BLUE}${TIMELINE_FILE}${NORMAL}"
echo ""

if [[ "$AUTHORITY_REQUIRED" == "yes" ]]; then
    NOTIFICATION_DEADLINE=$(date -d "$(date +%Y-%m-%d) + 3 days" +"%Y-%m-%d %H:%M:%S")
    echo -e "${RED}IMPORTANT: Authority notification deadline: ${NOTIFICATION_DEADLINE}${NORMAL}"
fi

echo -e "\n${BOLD}REMINDER:${NORMAL}"
echo "1. Continue to document all actions in the timeline file"
echo "2. Contact the Data Protection Officer immediately"
echo "3. Follow the full DSGVO/GDPR breach procedure in the documentation"
echo ""

log_action "Incident response checklist completed"

# End of script
echo -e "${BOLD}============================================================${NORMAL}"
echo -e "Response checklist completed. Report saved to: ${REPORT_FILE}"
echo -e "${BOLD}============================================================${NORMAL}"
