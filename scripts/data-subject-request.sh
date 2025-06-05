#!/bin/bash
# DSGVO/GDPR Data Subject Request Handler
# This script manages data subject requests (access, rectification, deletion, etc.)

# Set terminal colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NORMAL='\033[0m'

# Set variables
TIMESTAMP=$(date +"%Y-%m-%d_%H-%M-%S")
LOG_DIR="/var/log/dsgvo"
REQUEST_DIR="${LOG_DIR}/subject_requests"
CURRENT_REQUEST="${REQUEST_DIR}/request_${TIMESTAMP}"
REQUEST_LOG="${LOG_DIR}/subject_requests.log"
CONFIG_DIR="/etc/dsgvo"
CONTACT_FILE="${CONFIG_DIR}/contacts.conf"
DB_QUERY_SCRIPT="/opt/polyserver/scripts/db-query.sh"

# Create directories
mkdir -p "${REQUEST_DIR}"
mkdir -p "${CURRENT_REQUEST}"
touch "${REQUEST_LOG}"

# Function to log actions
log_action() {
    echo "$(date +"%Y-%m-%d %H:%M:%S") - $1" >> "${REQUEST_LOG}"
    echo -e "[${GREEN}✓${NORMAL}] $1"
}

# Header
clear
echo -e "${BOLD}============================================================${NORMAL}"
echo -e "${BOLD}       DSGVO/GDPR Data Subject Request Handler              ${NORMAL}"
echo -e "${BOLD}============================================================${NORMAL}"
echo -e "Request reference: ${YELLOW}request_${TIMESTAMP}${NORMAL}"
echo -e "Documentation directory: ${BLUE}${CURRENT_REQUEST}${NORMAL}\n"

# Step 1: Collect request information
echo -e "${BOLD}STEP 1: REQUEST INFORMATION${NORMAL}"
echo "------------------------------------------------------------"

read -p "Handler name: " HANDLER_NAME
read -p "Handler role: " HANDLER_ROLE
read -p "Request type (access/rectification/deletion/restriction/objection/portability): " REQUEST_TYPE
read -p "Data subject name: " SUBJECT_NAME
read -p "Data subject contact (email/phone): " SUBJECT_CONTACT
read -p "Identity verification method: " ID_VERIFICATION
read -p "Date request received (YYYY-MM-DD): " REQUEST_DATE
read -p "Brief description of the request: " REQUEST_DESCRIPTION

# Calculate deadlines (1 month from receipt with possible 2 month extension)
RESPONSE_DEADLINE=$(date -d "$REQUEST_DATE + 1 month" +"%Y-%m-%d")
EXTENDED_DEADLINE=$(date -d "$REQUEST_DATE + 3 month" +"%Y-%m-%d")

# Save basic information
{
    echo "DSGVO/GDPR DATA SUBJECT REQUEST"
    echo "================================"
    echo ""
    echo "REQUEST REFERENCE: request_${TIMESTAMP}"
    echo "DATE OF REPORT: $(date +"%Y-%m-%d %H:%M:%S")"
    echo "HANDLER: ${HANDLER_NAME} (${HANDLER_ROLE})"
    echo ""
    echo "REQUEST DETAILS"
    echo "--------------"
    echo "Request type: ${REQUEST_TYPE}"
    echo "Data subject: ${SUBJECT_NAME}"
    echo "Contact: ${SUBJECT_CONTACT}"
    echo "Identity verification: ${ID_VERIFICATION}"
    echo "Date received: ${REQUEST_DATE}"
    echo "Response deadline: ${RESPONSE_DEADLINE}"
    echo "Extended deadline (if applicable): ${EXTENDED_DEADLINE}"
    echo ""
    echo "REQUEST DESCRIPTION"
    echo "------------------"
    echo "${REQUEST_DESCRIPTION}"
    echo ""
} > "${CURRENT_REQUEST}/request_info.txt"

log_action "Request information documented"

# Step 2: Determine data scope
echo -e "\n${BOLD}STEP 2: DATA SCOPE DETERMINATION${NORMAL}"
echo "------------------------------------------------------------"

echo -e "${YELLOW}What data systems need to be searched for this request?${NORMAL}"
echo "  - Application database"
echo "  - User account system"
echo "  - Activity logs"
echo "  - Application data/saved content"
echo "  - Email/communication records"
echo ""

read -p "Data identifiers (email, user ID, etc.): " DATA_IDENTIFIERS
read -p "Time range to search (e.g., 'last 2 years' or 'all'): " TIME_RANGE
read -p "Systems to search (comma-separated): " SYSTEMS_TO_SEARCH

# Document data scope
{
    echo "DATA SCOPE"
    echo "----------"
    echo "Data identifiers: ${DATA_IDENTIFIERS}"
    echo "Time range: ${TIME_RANGE}"
    echo "Systems to search: ${SYSTEMS_TO_SEARCH}"
    echo ""
} >> "${CURRENT_REQUEST}/request_info.txt"

log_action "Data scope defined"

# Step 3: Data processing plan
echo -e "\n${BOLD}STEP 3: REQUEST PROCESSING PLAN${NORMAL}"
echo "------------------------------------------------------------"

# Different handling based on request type
case "$REQUEST_TYPE" in
    "access")
        echo -e "${YELLOW}Data Access Request - Actions Required:${NORMAL}"
        echo "  1. Extract all personal data for the data subject"
        echo "  2. Document processing purposes, categories, recipients"
        echo "  3. Include retention periods and data source information"
        echo "  4. Prepare data in a structured, commonly used format"
        
        read -p "Will data export require specialized queries? (y/n): " SPECIALIZED_QUERIES
        read -p "Estimated completion date (YYYY-MM-DD): " COMPLETION_DATE
        
        {
            echo "ACCESS REQUEST PLAN"
            echo "------------------"
            echo "Requires specialized queries: ${SPECIALIZED_QUERIES}"
            echo "Estimated completion: ${COMPLETION_DATE}"
            echo ""
            echo "Data export checklist:"
            echo "☐ Application user account data"
            echo "☐ User-generated content and saved data"
            echo "☐ User activity logs"
            echo "☐ Email/communication records"
            echo "☐ Access permissions and groups"
            echo ""
        } >> "${CURRENT_REQUEST}/processing_plan.txt"
        ;;
        
    "rectification")
        echo -e "${YELLOW}Data Rectification Request - Actions Required:${NORMAL}"
        echo "  1. Identify all instances of incorrect data"
        echo "  2. Document current values and requested changes"
        echo "  3. Update information in all relevant systems"
        echo "  4. Notify any third parties who received the data"
        
        read -p "Current incorrect data: " INCORRECT_DATA
        read -p "Corrected data: " CORRECTED_DATA
        read -p "Verification document provided? (y/n): " VERIFICATION_PROVIDED
        
        {
            echo "RECTIFICATION REQUEST PLAN"
            echo "-------------------------"
            echo "Current data: ${INCORRECT_DATA}"
            echo "Corrected data: ${CORRECTED_DATA}"
            echo "Verification provided: ${VERIFICATION_PROVIDED}"
            echo ""
            echo "Rectification checklist:"
            echo "☐ Identify all data locations"
            echo "☐ Document current values before changes"
            echo "☐ Update application user records"
            echo "☐ Update database records"
            echo "☐ Notify third parties if applicable"
            echo ""
        } >> "${CURRENT_REQUEST}/processing_plan.txt"
        ;;
        
    "deletion")
        echo -e "${YELLOW}Data Deletion Request - Actions Required:${NORMAL}"
        echo "  1. Identify all personal data for the subject"
        echo "  2. Assess legal basis for retention if any"
        echo "  3. Document what will be deleted and what must be retained"
        echo "  4. Execute deletion in all systems and backups"
        
        read -p "Are there legal grounds to refuse deletion? (y/n): " DELETION_REFUSAL
        read -p "If yes, specify the grounds: " REFUSAL_GROUNDS
        read -p "Will partial deletion be performed? (y/n): " PARTIAL_DELETION
        
        {
            echo "DELETION REQUEST PLAN"
            echo "--------------------"
            echo "Deletion refusal: ${DELETION_REFUSAL}"
            if [ "$DELETION_REFUSAL" == "y" ]; then
                echo "Refusal grounds: ${REFUSAL_GROUNDS}"
            fi
            echo "Partial deletion: ${PARTIAL_DELETION}"
            echo ""
            echo "Deletion checklist:"
            echo "☐ Document all data to be deleted"
            echo "☐ Take pre-deletion backup for verification"
            echo "☐ Delete user account data"
            echo "☐ Delete user-generated content"
            echo "☐ Delete or anonymize activity logs"
            echo "☐ Delete or anonymize database records"
            echo "☐ Update backup retention policy"
            echo ""
        } >> "${CURRENT_REQUEST}/processing_plan.txt"
        ;;
        
    "restriction")
        echo -e "${YELLOW}Processing Restriction Request - Actions Required:${NORMAL}"
        echo "  1. Document basis for restriction request"
        echo "  2. Identify all processing activities to restrict"
        echo "  3. Implement technical measures to prevent processing"
        echo "  4. Document when/if processing can resume"
        
        read -p "Reason for restriction request: " RESTRICTION_REASON
        read -p "Processing to be restricted: " RESTRICTED_PROCESSING
        read -p "Temporary or permanent restriction? (temp/perm): " RESTRICTION_DURATION
        
        {
            echo "RESTRICTION REQUEST PLAN"
            echo "-----------------------"
            echo "Restriction reason: ${RESTRICTION_REASON}"
            echo "Restricted processing: ${RESTRICTED_PROCESSING}"
            echo "Restriction duration: ${RESTRICTION_DURATION}"
            echo ""
            echo "Restriction checklist:"
            echo "☐ Document current processing activities"
            echo "☐ Implement technical restriction measures"
            echo "☐ Notify relevant personnel"
            echo "☐ Set review date if temporary"
            echo ""
        } >> "${CURRENT_REQUEST}/processing_plan.txt"
        ;;
        
    "objection")
        echo -e "${YELLOW}Processing Objection Request - Actions Required:${NORMAL}"
        echo "  1. Document the specific processing being objected to"
        echo "  2. Assess legal grounds for processing vs. objection"
        echo "  3. Determine if compelling legitimate grounds exist"
        echo "  4. Document decision and implement as needed"
        
        read -p "Processing being objected to: " OBJECTION_PROCESSING
        read -p "Legal basis for original processing: " PROCESSING_BASIS
        read -p "Are there compelling legitimate grounds to continue? (y/n): " COMPELLING_GROUNDS
        
        {
            echo "OBJECTION REQUEST PLAN"
            echo "---------------------"
            echo "Objection to processing: ${OBJECTION_PROCESSING}"
            echo "Original legal basis: ${PROCESSING_BASIS}"
            echo "Compelling grounds exist: ${COMPELLING_GROUNDS}"
            echo ""
            echo "Objection checklist:"
            echo "☐ Document the objection details"
            echo "☐ Assess legal position"
            echo "☐ Consult with legal team if necessary"
            echo "☐ Implement processing changes if required"
            echo "☐ Notify data subject of decision with reasoning"
            echo ""
        } >> "${CURRENT_REQUEST}/processing_plan.txt"
        ;;
        
    "portability")
        echo -e "${YELLOW}Data Portability Request - Actions Required:${NORMAL}"
        echo "  1. Identify data provided by the subject or from their activity"
        echo "  2. Prepare data in a structured, machine-readable format"
        echo "  3. Include all relevant metadata and relationships"
        echo "  4. Securely transfer the data package to the subject"
        
        read -p "Requested data format (JSON/CSV/XML/other): " FORMAT_REQUESTED
        read -p "Direct transfer to another controller requested? (y/n): " DIRECT_TRANSFER
        if [ "$DIRECT_TRANSFER" == "y" ]; then
            read -p "Transfer recipient details: " TRANSFER_RECIPIENT
        fi
        
        {
            echo "PORTABILITY REQUEST PLAN"
            echo "-----------------------"
            echo "Requested format: ${FORMAT_REQUESTED}"
            echo "Direct transfer requested: ${DIRECT_TRANSFER}"
            if [ "$DIRECT_TRANSFER" == "y" ]; then
                echo "Transfer recipient: ${TRANSFER_RECIPIENT}"
            fi
            echo ""
            echo "Portability checklist:"
            echo "☐ Extract all user-provided data"
            echo "☐ Extract all activity-generated data"
            echo "☐ Format data according to request"
            echo "☐ Verify data structure and completeness"
            echo "☐ Arrange secure transfer method"
            echo ""
        } >> "${CURRENT_REQUEST}/processing_plan.txt"
        ;;
        
    *)
        echo -e "${RED}Unknown request type. Please check and try again.${NORMAL}"
        exit 1
        ;;
esac

log_action "Processing plan created for ${REQUEST_TYPE} request"

# Step 4: Verification of legitimacy
echo -e "\n${BOLD}STEP 4: REQUEST LEGITIMACY VERIFICATION${NORMAL}"
echo "------------------------------------------------------------"

read -p "Identity verification status (verified/pending/failed): " ID_STATUS
read -p "Verification method used: " VERIFY_METHOD
read -p "Is the request excessive or unfounded? (y/n): " EXCESSIVE
read -p "Is there a legal exemption to fulfilling this request? (y/n): " EXEMPTION
if [ "$EXEMPTION" == "y" ]; then
    read -p "Specify the exemption: " EXEMPTION_DETAILS
fi

# Document verification
{
    echo "REQUEST LEGITIMACY"
    echo "-----------------"
    echo "Identity verification: ${ID_STATUS}"
    echo "Verification method: ${VERIFY_METHOD}"
    echo "Excessive or unfounded: ${EXCESSIVE}"
    echo "Legal exemption applies: ${EXEMPTION}"
    if [ "$EXEMPTION" == "y" ]; then
        echo "Exemption details: ${EXEMPTION_DETAILS}"
    fi
    echo ""
} >> "${CURRENT_REQUEST}/request_info.txt"

# Determine if the request will be fulfilled
FULFILL="yes"
REFUSAL_REASON=""

if [ "$ID_STATUS" != "verified" ]; then
    FULFILL="no"
    REFUSAL_REASON="Identity not verified"
elif [ "$EXCESSIVE" == "y" ]; then
    FULFILL="no"
    REFUSAL_REASON="Request is excessive or unfounded"
elif [ "$EXEMPTION" == "y" ]; then
    FULFILL="no"
    REFUSAL_REASON="Legal exemption applies: ${EXEMPTION_DETAILS}"
fi

{
    echo "REQUEST DECISION"
    echo "---------------"
    echo "Request will be fulfilled: ${FULFILL}"
    if [ "$FULFILL" != "yes" ]; then
        echo "Reason for refusal: ${REFUSAL_REASON}"
    fi
    echo ""
} >> "${CURRENT_REQUEST}/request_info.txt"

log_action "Request legitimacy assessed: Will fulfill = ${FULFILL}"

# Step 5: Request processing
echo -e "\n${BOLD}STEP 5: PROCESSING ACTIONS${NORMAL}"
echo "------------------------------------------------------------"

if [ "$FULFILL" == "yes" ]; then
    echo -e "${GREEN}Request approved for processing.${NORMAL}"
    echo -e "${YELLOW}Follow the processing plan in:${NORMAL} ${BLUE}${CURRENT_REQUEST}/processing_plan.txt${NORMAL}"
    echo ""
    echo "Document all actions taken during processing, including:"
    echo "  - Database queries run"
    echo "  - Data extracted/modified/deleted"
    echo "  - Systems accessed"
    echo "  - Personnel involved"
    echo ""
    
    # Create action log file
    {
        echo "ACTION LOG"
        echo "----------"
        echo "$(date +"%Y-%m-%d %H:%M:%S") - Request processing initiated by ${HANDLER_NAME}"
        echo ""
    } > "${CURRENT_REQUEST}/action_log.txt"
    
    echo -e "Please record all actions in: ${BLUE}${CURRENT_REQUEST}/action_log.txt${NORMAL}"
else
    echo -e "${RED}Request will not be fulfilled. Reason: ${REFUSAL_REASON}${NORMAL}"
    echo "Prepare a formal response to the data subject explaining:"
    echo "  - The reason for refusal"
    echo "  - Their right to lodge a complaint with the supervisory authority"
    echo "  - Their right to seek judicial remedy"
    echo ""
    
    # Create refusal template
    {
        echo "SUBJECT: Response to Your Data Subject Request (Ref: request_${TIMESTAMP})"
        echo ""
        echo "Dear ${SUBJECT_NAME},"
        echo ""
        echo "We are writing regarding your ${REQUEST_TYPE} request received on ${REQUEST_DATE}."
        echo ""
        echo "After careful consideration, we regret to inform you that we are unable to fulfill your request for the following reason:"
        echo ""
        echo "${REFUSAL_REASON}"
        echo ""
        echo "In accordance with Article 12 of the GDPR, we would like to inform you of your right to:"
        echo ""
        echo "1. Lodge a complaint with a supervisory authority (contact information below)"
        echo "2. Seek a judicial remedy against our decision"
        echo ""
        echo "Supervisory Authority: [Authority Name]"
        echo "Contact: [Authority Contact Information]"
        echo ""
        echo "If you have any questions or would like to discuss this matter further, please contact our Data Protection Officer at [DPO Email]."
        echo ""
        echo "Sincerely,"
        echo "[Organization Name]"
        echo "[DPO or Data Protection Contact]"
    } > "${CURRENT_REQUEST}/refusal_response.txt"
    
    echo -e "Response template created at: ${BLUE}${CURRENT_REQUEST}/refusal_response.txt${NORMAL}"
fi

log_action "Processing guidance provided"

# Step 6: Communication record
echo -e "\n${BOLD}STEP 6: COMMUNICATION RECORD${NORMAL}"
echo "------------------------------------------------------------"

echo "Please document all communications with the data subject:"
echo "  - Acknowledgment of request receipt"
echo "  - Any requests for additional information or verification"
echo "  - Progress updates"
echo "  - Final response"
echo ""

# Create communication log
{
    echo "COMMUNICATION LOG"
    echo "----------------"
    echo "$(date +"%Y-%m-%d %H:%M:%S") - Request intake processed by ${HANDLER_NAME}"
    echo ""
} > "${CURRENT_REQUEST}/communication_log.txt"

echo -e "Please record all communications in: ${BLUE}${CURRENT_REQUEST}/communication_log.txt${NORMAL}"

log_action "Communication log initialized"

# Step 7: Summary and next steps
echo -e "\n${BOLD}STEP 7: SUMMARY AND NEXT STEPS${NORMAL}"
echo "------------------------------------------------------------"

# Summarize the request information
echo -e "Request Reference: ${YELLOW}request_${TIMESTAMP}${NORMAL}"
echo -e "Type: ${YELLOW}${REQUEST_TYPE}${NORMAL}"
echo -e "Data Subject: ${BLUE}${SUBJECT_NAME}${NORMAL}"
echo -e "Response Deadline: ${RED}${RESPONSE_DEADLINE}${NORMAL}"
echo -e "Status: ${FULFILL == "yes" ? "${GREEN}Approved for processing${NORMAL}" : "${RED}Denied${NORMAL}"}"
echo ""

echo "Next steps:"
if [ "$FULFILL" == "yes" ]; then
    echo "1. Follow the processing plan"
    echo "2. Document all actions taken"
    echo "3. Prepare the required data/response"
    echo "4. Send response to data subject before the deadline"
    echo "5. Update the request status when completed"
else
    echo "1. Review and finalize the refusal response"
    echo "2. Send response to data subject"
    echo "3. Record the communication"
    echo "4. Store all documentation for accountability"
fi

echo ""
echo -e "Request documentation is saved in: ${BLUE}${CURRENT_REQUEST}${NORMAL}"

# Final reminder
echo -e "\n${BOLD}REMINDER:${NORMAL}"
echo "All actions must be documented for accountability purposes."
echo "Ensure all responses meet the requirements of Article 12 (transparent information)."
echo "Store all request documentation for a minimum of [Organization's retention period] years."

log_action "Request handler completed initial processing"

# End of script
echo -e "\n${BOLD}============================================================${NORMAL}"
echo -e "Request handler completed. All documentation saved to: ${BLUE}${CURRENT_REQUEST}${NORMAL}"
echo -e "${BOLD}============================================================${NORMAL}"