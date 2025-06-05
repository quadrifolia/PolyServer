#!/bin/bash
# DSGVO/GDPR Setup Script for PolyServer Applications
# This script installs all DSGVO/GDPR compliance files in their correct locations

# Set terminal colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NORMAL='\033[0m'

# Set base directories
SOURCE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DSGVO_CONF_DIR="/etc/dsgvo"
POLYSERVER_OPT_DIR="/opt/polyserver"
POLYSERVER_SCRIPTS_DIR="/opt/polyserver/scripts"
LOG_DIR="/var/log/dsgvo"
SECURITY_LOG_DIR="/var/log/security"

# Function to create directories
create_directories() {
  echo -e "${BOLD}Creating required directories...${NORMAL}"
  
  # Create directories with proper permissions
  for dir in "$DSGVO_CONF_DIR" "$POLYSERVER_OPT_DIR" "$POLYSERVER_SCRIPTS_DIR" "$LOG_DIR" "$SECURITY_LOG_DIR" "$SECURITY_LOG_DIR/incidents"; do
    if [ ! -d "$dir" ]; then
      echo -e "Creating ${BLUE}$dir${NORMAL}..."
      sudo mkdir -p "$dir"
      sudo chmod 750 "$dir"
      echo -e "${GREEN}✓${NORMAL} Created $dir"
    else
      echo -e "${YELLOW}!${NORMAL} Directory $dir already exists"
    fi
  done
}

# Function to install configuration files
install_config_files() {
  echo -e "\n${BOLD}Installing configuration files...${NORMAL}"
  
  # Copy template files to /etc/dsgvo with proper naming
  config_files=(
    "contacts.conf.template:contacts.conf"
    "data_inventory.json.template:data_inventory.json"
    "processing_records.md.template:processing_records.md"
    "retention_policy.md.template:retention_policy.md"
    "deletion_procedures.md.template:deletion_procedures.md"
    "subject_request_procedures.md.template:subject_request_procedures.md"
  )
  
  for file_map in "${config_files[@]}"; do
    src="${file_map%%:*}"
    dst="${file_map##*:}"
    
    if [ -f "$SOURCE_DIR/templates/dsgvo/$src" ]; then
      echo -e "Installing ${BLUE}$dst${NORMAL}..."
      sudo cp "$SOURCE_DIR/templates/dsgvo/$src" "$DSGVO_CONF_DIR/$dst"
      sudo chmod 640 "$DSGVO_CONF_DIR/$dst"
      echo -e "${GREEN}✓${NORMAL} Installed $dst"
    else
      echo -e "${RED}✗${NORMAL} Source file $src not found"
    fi
  done
}

# Function to install scripts
install_scripts() {
  echo -e "\n${BOLD}Installing DSGVO scripts...${NORMAL}"
  
  # Scripts to install (source:destination:executable)
  scripts=(
    "breach-response-checklist.sh:$POLYSERVER_SCRIPTS_DIR/breach-response-checklist.sh:yes"
    "collect-forensics.sh:$POLYSERVER_SCRIPTS_DIR/collect-forensics.sh:yes"
    "dsgvo-compliance-check.sh:$POLYSERVER_SCRIPTS_DIR/dsgvo-compliance-check.sh:yes"
    "data-subject-request.sh:$POLYSERVER_SCRIPTS_DIR/data-subject-request.sh:yes"
  )
  
  for script_map in "${scripts[@]}"; do
    IFS=':' read -r src dst executable <<< "$script_map"
    script_name=$(basename "$src")
    source_path=""
    
    # Determine the source path
    if [ -f "$SOURCE_DIR/templates/dsgvo/$src" ]; then
      source_path="$SOURCE_DIR/templates/dsgvo/$src"
    elif [ -f "$SOURCE_DIR/scripts/$src" ]; then
      source_path="$SOURCE_DIR/scripts/$src"
    fi
    
    if [ -n "$source_path" ]; then
      echo -e "Installing ${BLUE}$script_name${NORMAL}..."
      sudo cp "$source_path" "$dst"
      
      if [ "$executable" = "yes" ]; then
        sudo chmod 750 "$dst"
        echo -e "${GREEN}✓${NORMAL} Installed $script_name (executable)"
      else
        sudo chmod 640 "$dst"
        echo -e "${GREEN}✓${NORMAL} Installed $script_name"
      fi
    else
      echo -e "${RED}✗${NORMAL} Source script $src not found"
    fi
  done
}

# Function to create log files
create_log_files() {
  echo -e "\n${BOLD}Creating initial log files...${NORMAL}"
  
  # Create necessary log files
  log_files=(
    "$LOG_DIR/subject_requests.log"
    "$LOG_DIR/dsgvo_compliance.log"
    "$DSGVO_CONF_DIR/access_review.log"
    "$DSGVO_CONF_DIR/breach_drill.log"
    "$DSGVO_CONF_DIR/training_records.csv"
    "$DSGVO_CONF_DIR/subject_requests.log"
  )
  
  for log_file in "${log_files[@]}"; do
    if [ ! -f "$log_file" ]; then
      echo -e "Creating ${BLUE}$log_file${NORMAL}..."
      sudo touch "$log_file"
      sudo chmod 640 "$log_file"
      
      # Add header to CSV file if needed
      if [[ "$log_file" == *".csv" ]]; then
        echo "Date,Employee,Training Type,Completion Status,Certificate ID" | sudo tee "$log_file" > /dev/null
      fi
      
      echo -e "${GREEN}✓${NORMAL} Created $log_file"
    else
      echo -e "${YELLOW}!${NORMAL} Log file $log_file already exists"
    fi
  done
}

# Function to create symbolic links
create_symlinks() {
  echo -e "\n${BOLD}Creating symbolic links...${NORMAL}"
  
  # Create symlinks for easy access
  symlinks=(
    "$POLYSERVER_SCRIPTS_DIR/breach-response-checklist.sh:/usr/local/bin/breach-response"
    "$POLYSERVER_SCRIPTS_DIR/dsgvo-compliance-check.sh:/usr/local/bin/dsgvo-check"
    "$POLYSERVER_SCRIPTS_DIR/data-subject-request.sh:/usr/local/bin/data-request"
  )
  
  for symlink_map in "${symlinks[@]}"; do
    IFS=':' read -r target link <<< "$symlink_map"
    
    if [ -f "$target" ]; then
      echo -e "Creating symlink ${BLUE}$link${NORMAL} -> $target..."
      sudo ln -sf "$target" "$link"
      echo -e "${GREEN}✓${NORMAL} Created symlink $link"
    else
      echo -e "${RED}✗${NORMAL} Target file $target not found"
    fi
  done
}

# Function to set up cron jobs
setup_cron_jobs() {
  echo -e "\n${BOLD}Setting up scheduled tasks...${NORMAL}"
  
  # Create temporary crontab file
  crontab_file=$(mktemp)
  
  # Get current crontab
  crontab -l > "$crontab_file" 2>/dev/null || echo "# DSGVO/GDPR scheduled tasks" > "$crontab_file"
  
  # Add DSGVO compliance check (monthly)
  if ! grep -q "dsgvo-compliance-check.sh" "$crontab_file"; then
    echo "# Run DSGVO compliance check on the 1st of every month at 2:00 AM" >> "$crontab_file"
    echo "0 2 1 * * $POLYSERVER_SCRIPTS_DIR/dsgvo-compliance-check.sh > $LOG_DIR/compliance_check_\$(date +\%Y\%m\%d).log 2>&1" >> "$crontab_file"
    echo -e "${GREEN}✓${NORMAL} Added monthly DSGVO compliance check"
  else
    echo -e "${YELLOW}!${NORMAL} DSGVO compliance check already in crontab"
  fi
  
  # Add breach response drill reminder (annually)
  if ! grep -q "breach_drill_reminder" "$crontab_file"; then
    echo "# Annual breach response drill reminder (first Monday of January)" >> "$crontab_file"
    echo "0 9 1-7 1 1 echo \"REMINDER: Annual breach response drill due this month\" | mail -s \"DSGVO Breach Response Drill Reminder\" \$(grep -oP 'DPO_EMAIL=\\K.*' $DSGVO_CONF_DIR/contacts.conf 2>/dev/null || echo root) && echo \"\$(date): Breach drill reminder sent\" >> $DSGVO_CONF_DIR/breach_drill.log 2>&1" >> "$crontab_file"
    echo -e "${GREEN}✓${NORMAL} Added annual breach drill reminder"
  else
    echo -e "${YELLOW}!${NORMAL} Breach drill reminder already in crontab"
  fi
  
  # Install new crontab
  crontab "$crontab_file"
  rm "$crontab_file"
  
  echo -e "${GREEN}✓${NORMAL} Crontab updated"
}

# Function to configure file permissions
set_permissions() {
  echo -e "\n${BOLD}Setting file permissions...${NORMAL}"
  
  # Ensure proper permissions on log directories
  sudo chmod 750 "$LOG_DIR" "$SECURITY_LOG_DIR" "$SECURITY_LOG_DIR/incidents" 2>/dev/null
  
  # Set permissions on configuration directory
  sudo chmod 750 "$DSGVO_CONF_DIR" 2>/dev/null
  
  echo -e "${GREEN}✓${NORMAL} Permissions set correctly"
}

# Main function
main() {
  echo -e "${BOLD}============================================================${NORMAL}"
  echo -e "${BOLD}       DSGVO/GDPR Setup for PolyServer                     ${NORMAL}"
  echo -e "${BOLD}============================================================${NORMAL}"
  
  echo -e "This script will install DSGVO/GDPR compliance files and configure"
  echo -e "your system for GDPR compliance with your application deployments."
  echo -e ""
  echo -e "${YELLOW}Note: This script requires sudo privileges.${NORMAL}"
  echo -e ""
  
  # Check for root permissions
  if [ "$EUID" -ne 0 ]; then
    echo -e "${YELLOW}This script requires elevated privileges to install files.${NORMAL}"
    echo -e "Please enter your password when prompted."
    echo -e ""
  fi
  
  # Confirm setup
  read -p "Do you want to continue with the DSGVO setup? (y/n): " confirm
  if [[ "$confirm" != [yY] && "$confirm" != [yY][eE][sS] ]]; then
    echo "Setup cancelled."
    exit 0
  fi
  
  # Perform setup tasks
  create_directories
  install_config_files
  install_scripts
  create_log_files
  create_symlinks
  setup_cron_jobs
  set_permissions
  
  echo -e "\n${BOLD}============================================================${NORMAL}"
  echo -e "${GREEN}DSGVO/GDPR setup completed successfully!${NORMAL}"
  echo -e "${BOLD}============================================================${NORMAL}"
  echo -e ""
  echo -e "Next steps:"
  echo -e "1. Edit ${BLUE}$DSGVO_CONF_DIR/contacts.conf${NORMAL} to add your DPO contact information"
  echo -e "2. Complete ${BLUE}$DSGVO_CONF_DIR/data_inventory.json${NORMAL} with your actual data"
  echo -e "3. Run a compliance check: ${YELLOW}sudo $POLYSERVER_SCRIPTS_DIR/dsgvo-compliance-check.sh${NORMAL}"
  echo -e "4. Review all template files and customize them for your organization"
  echo -e ""
  echo -e "Installed scripts:"
  echo -e "- Breach Response: ${YELLOW}breach-response${NORMAL}"
  echo -e "- Compliance Check: ${YELLOW}dsgvo-check${NORMAL}"
  echo -e "- Data Subject Request: ${YELLOW}data-request${NORMAL}"
  echo -e ""
}

# Execute main function
main