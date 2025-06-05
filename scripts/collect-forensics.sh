#!/bin/bash
# Forensic Evidence Collection Script for PolyServer Security Incidents
# This script collects comprehensive forensic evidence during a security incident.
#
# NOTE: Long-running commands are wrapped with timeout to prevent hanging:
# - tcpdump: 30 seconds (captures packets or times out)
# - DNS resolution: 10 seconds 
# - Filesystem searches: 1-2 minutes depending on scope
# - Malware scans: 5-10 minutes depending on tool
# Commands that timeout will be logged as warnings but won't stop collection.

# Set variables
TIMESTAMP=$(date +"%Y-%m-%d_%H-%M-%S")
OUTPUT_DIR="${1:-/var/log/security/evidence_${TIMESTAMP}}"
LOG_FILE="${OUTPUT_DIR}/collection_log.txt"
SYSTEM_INFO_DIR="${OUTPUT_DIR}/system_info"
NETWORK_INFO_DIR="${OUTPUT_DIR}/network_info"
USER_ACTIVITY_DIR="${OUTPUT_DIR}/user_activity"
FILE_SYSTEM_DIR="${OUTPUT_DIR}/file_system"
APPLICATION_DIR="${OUTPUT_DIR}/application"
DATABASE_DIR="${OUTPUT_DIR}/database"
DOCKER_DIR="${OUTPUT_DIR}/docker"
MALWARE_DIR="${OUTPUT_DIR}/malware_scan"

# Create directories
mkdir -p "${SYSTEM_INFO_DIR}" "${NETWORK_INFO_DIR}" "${USER_ACTIVITY_DIR}" 
mkdir -p "${FILE_SYSTEM_DIR}" "${APPLICATION_DIR}" "${DATABASE_DIR}" "${DOCKER_DIR}" "${MALWARE_DIR}"

# Log function
log() {
    echo "$(date +"%Y-%m-%d %H:%M:%S") - $1" | tee -a "${LOG_FILE}"
}

# Capture command output
capture() {
    local cmd="$1"
    local output_file="$2"
    local description="$3"
    
    log "Collecting: ${description}"
    echo "# Command: ${cmd}" > "${output_file}"
    echo "# Executed: $(date)" >> "${output_file}"
    echo "# Description: ${description}" >> "${output_file}"
    echo "# -------------------------------------------" >> "${output_file}"
    
    if ! eval "${cmd}" >> "${output_file}" 2>&1; then
        echo "# ERROR: Command failed with exit code $?" >> "${output_file}"
        log "WARNING: Failed to collect ${description}"
    else
        log "Successfully collected ${description}"
    fi
    
    echo "" >> "${output_file}"
}

# Start evidence collection
log "Starting forensic evidence collection"
log "Evidence will be stored in ${OUTPUT_DIR}"

# System information collection
log "Collecting system information..."

# Basic system info
capture "hostname" "${SYSTEM_INFO_DIR}/hostname.txt" "System hostname"
capture "date" "${SYSTEM_INFO_DIR}/date_time.txt" "System date and time"
capture "uptime" "${SYSTEM_INFO_DIR}/uptime.txt" "System uptime"
capture "uname -a" "${SYSTEM_INFO_DIR}/kernel_info.txt" "Kernel information"
capture "cat /etc/os-release" "${SYSTEM_INFO_DIR}/os_info.txt" "OS information"
capture "df -h" "${SYSTEM_INFO_DIR}/disk_usage.txt" "Disk usage"
capture "free -h" "${SYSTEM_INFO_DIR}/memory_usage.txt" "Memory usage"
capture "top -b -n 1" "${SYSTEM_INFO_DIR}/top_processes.txt" "Top processes"
capture "ps auxf" "${SYSTEM_INFO_DIR}/process_tree.txt" "Process tree"
capture "lsof" "${SYSTEM_INFO_DIR}/open_files.txt" "Open files"
capture "w" "${SYSTEM_INFO_DIR}/logged_in_users.txt" "Currently logged in users"
capture "last -20" "${SYSTEM_INFO_DIR}/recent_logins.txt" "Recent login history"
capture "lastb -20" "${SYSTEM_INFO_DIR}/failed_logins.txt" "Recent failed login attempts"
capture "cat /etc/passwd" "${SYSTEM_INFO_DIR}/passwd.txt" "User accounts"
capture "cat /etc/group" "${SYSTEM_INFO_DIR}/groups.txt" "Group definitions"
capture "find /etc/cron* -type f -exec ls -la {} \;" "${SYSTEM_INFO_DIR}/cron_jobs.txt" "Scheduled cron jobs"
capture "crontab -l" "${SYSTEM_INFO_DIR}/user_crontab.txt" "User crontab entries"
capture "systemctl list-units --type=service" "${SYSTEM_INFO_DIR}/systemd_services.txt" "Systemd services"
capture "find /etc/systemd/system -type f -name \"*.service\" -exec cat {} \;" "${SYSTEM_INFO_DIR}/systemd_service_files.txt" "Systemd service definitions"
capture "dmesg" "${SYSTEM_INFO_DIR}/dmesg.txt" "Kernel ring buffer"

# Network information
log "Collecting network information..."

capture "ifconfig -a" "${NETWORK_INFO_DIR}/ifconfig.txt" "Network interfaces"
capture "ip addr" "${NETWORK_INFO_DIR}/ip_addr.txt" "IP addresses"
capture "ip route" "${NETWORK_INFO_DIR}/ip_routes.txt" "Routing table"
capture "netstat -tulanp" "${NETWORK_INFO_DIR}/netstat.txt" "Active connections"
capture "ss -tulanp" "${NETWORK_INFO_DIR}/socket_stats.txt" "Socket statistics"
capture "lsof -i" "${NETWORK_INFO_DIR}/network_files.txt" "Open network files"
capture "iptables -L -n -v" "${NETWORK_INFO_DIR}/iptables.txt" "Firewall rules"
capture "cat /etc/hosts" "${NETWORK_INFO_DIR}/hosts_file.txt" "Hosts file"
capture "cat /etc/resolv.conf" "${NETWORK_INFO_DIR}/resolv_conf.txt" "DNS resolver configuration"
capture "timeout 10 dig ANY example.com" "${NETWORK_INFO_DIR}/dns_test.txt" "DNS resolution test (10 second timeout)"
capture "timeout 30 tcpdump -nn -c 100" "${NETWORK_INFO_DIR}/tcpdump.txt" "Network packet sample (30 second timeout)"
capture "arp -a" "${NETWORK_INFO_DIR}/arp_cache.txt" "ARP cache"

# User activity
log "Collecting user activity logs..."

capture "find /var/log -name \"auth.log*\" -exec ls -la {} \;" "${USER_ACTIVITY_DIR}/auth_log_files.txt" "Authentication log files"
capture "grep -a \"session opened\" /var/log/auth.log" "${USER_ACTIVITY_DIR}/session_opened.txt" "Session opened events"
capture "grep -a \"session closed\" /var/log/auth.log" "${USER_ACTIVITY_DIR}/session_closed.txt" "Session closed events"
capture "grep -a \"Failed password\" /var/log/auth.log" "${USER_ACTIVITY_DIR}/failed_passwords.txt" "Failed password attempts"
capture "grep -a \"Invalid user\" /var/log/auth.log" "${USER_ACTIVITY_DIR}/invalid_users.txt" "Invalid user attempts"
capture "find /home -name \".bash_history\" -exec ls -la {} \;" "${USER_ACTIVITY_DIR}/bash_history_files.txt" "Bash history files"
capture "find /root -name \".bash_history\" -exec ls -la {} \;" "${USER_ACTIVITY_DIR}/root_bash_history.txt" "Root bash history"
capture "find /home -name \".ssh\" -type d -exec ls -la {} \;" "${USER_ACTIVITY_DIR}/user_ssh_dirs.txt" "User SSH directories"
capture "find /var/log -name \"*.log\" -mtime -7 | xargs ls -la" "${USER_ACTIVITY_DIR}/recent_logs.txt" "Recently modified log files"

# Filesystem information
log "Collecting filesystem information..."

capture "timeout 120 find / -type f -mtime -1 -not -path \"/proc/*\" -not -path \"/sys/*\" -not -path \"/run/*\" -not -path \"/dev/*\" -exec ls -la {} \;" "${FILE_SYSTEM_DIR}/last_24h_files.txt" "Files modified in last 24 hours (2 minute timeout)"
capture "find / -type f -perm -4000 -ls" "${FILE_SYSTEM_DIR}/suid_files.txt" "SUID files"
capture "find / -type f -perm -2000 -ls" "${FILE_SYSTEM_DIR}/sgid_files.txt" "SGID files"
capture "find / -type f -perm -1000 -ls" "${FILE_SYSTEM_DIR}/sticky_bit_files.txt" "Sticky bit files"
capture "find / -nouser -o -nogroup -ls" "${FILE_SYSTEM_DIR}/noowner_files.txt" "Files without valid owner"
capture "find /tmp -type f -ls" "${FILE_SYSTEM_DIR}/tmp_files.txt" "Files in /tmp"
capture "find /var/tmp -type f -ls" "${FILE_SYSTEM_DIR}/var_tmp_files.txt" "Files in /var/tmp"
capture "find /dev/shm -type f -ls" "${FILE_SYSTEM_DIR}/dev_shm_files.txt" "Files in /dev/shm"
capture "ls -la /etc/init.d/" "${FILE_SYSTEM_DIR}/init_scripts.txt" "Init scripts"
capture "find /etc -mtime -7 -type f -exec ls -la {} \;" "${FILE_SYSTEM_DIR}/etc_recent_changes.txt" "Recent changes to /etc"

# Application-specific evidence
log "Collecting application information..."

# Application configuration and logs
if [ -d "/opt/polyserver" ]; then
    capture "find /opt/polyserver -type f -name \"*.jar\" -exec ls -la {} \;" "${APPLICATION_DIR}/application_jar_files.txt" "Application JAR files"
    capture "find /opt/polyserver -type f -name \"*.conf\" -exec ls -la {} \;" "${APPLICATION_DIR}/application_conf_files.txt" "Application configuration files"
    capture "find /opt/polyserver -type f -name \"*.log\" -exec ls -la {} \;" "${APPLICATION_DIR}/application_log_files.txt" "Application log files"
    
    # Collect the most recent logs
    for log_file in $(find /opt/polyserver -type f -name "*.log" -mtime -7); do
        log_filename=$(basename "$log_file")
        capture "tail -n 5000 ${log_file}" "${APPLICATION_DIR}/${log_filename}.evidence" "Recent entries from ${log_file}"
    done
fi

# Web server logs (if using Nginx)
if [ -d "/var/log/nginx" ]; then
    capture "find /var/log/nginx -type f -name \"*.log\" -exec ls -la {} \;" "${APPLICATION_DIR}/nginx_log_files.txt" "Nginx log files"
    capture "tail -n 5000 /var/log/nginx/access.log" "${APPLICATION_DIR}/nginx_access_recent.txt" "Recent Nginx access logs"
    capture "tail -n 5000 /var/log/nginx/error.log" "${APPLICATION_DIR}/nginx_error_recent.txt" "Recent Nginx error logs"
    capture "cat /etc/nginx/nginx.conf" "${APPLICATION_DIR}/nginx_main_config.txt" "Nginx main configuration"
    capture "find /etc/nginx/conf.d -type f -name \"*.conf\" -exec cat {} \;" "${APPLICATION_DIR}/nginx_site_configs.txt" "Nginx site configurations"
fi

# Database information (PostgreSQL, MySQL, or other databases)
log "Collecting database information..."

# PostgreSQL
if command -v psql &> /dev/null; then
    capture "ps aux | grep postgres" "${DATABASE_DIR}/postgres_processes.txt" "PostgreSQL processes"
    capture "find /var/lib/postgresql -type f -name \"*.log\" -mtime -7 -exec ls -la {} \;" "${DATABASE_DIR}/postgres_log_files.txt" "PostgreSQL log files"
    
    # Note: For actual database queries, you would need authentication
    # This would need to be customized with proper credentials
    log "NOTE: Database content examination requires authentication"
fi

# MySQL/MariaDB
if command -v mysql &> /dev/null; then
    capture "ps aux | grep mysql" "${DATABASE_DIR}/mysql_processes.txt" "MySQL processes"
    capture "find /var/log/mysql -type f -mtime -7 -exec ls -la {} \;" "${DATABASE_DIR}/mysql_log_files.txt" "MySQL log files"
    
    # Note: For actual database queries, you would need authentication
    log "NOTE: Database content examination requires authentication"
fi

# Docker information (if applications are running in Docker)
log "Collecting Docker information..."

if command -v docker &> /dev/null; then
    capture "docker version" "${DOCKER_DIR}/docker_version.txt" "Docker version"
    capture "docker info" "${DOCKER_DIR}/docker_info.txt" "Docker system info"
    capture "docker ps -a" "${DOCKER_DIR}/docker_containers.txt" "Docker containers"
    capture "docker images" "${DOCKER_DIR}/docker_images.txt" "Docker images"
    capture "docker network ls" "${DOCKER_DIR}/docker_networks.txt" "Docker networks"
    capture "docker volume ls" "${DOCKER_DIR}/docker_volumes.txt" "Docker volumes"
    
    # For each running container, collect logs
    for container_id in $(docker ps -q); do
        container_name=$(docker inspect --format='{{.Name}}' "$container_id" | sed 's/\///')
        capture "docker logs $container_id" "${DOCKER_DIR}/${container_name}_logs.txt" "Logs for container ${container_name}"
        capture "docker inspect $container_id" "${DOCKER_DIR}/${container_name}_inspect.txt" "Inspection for container ${container_name}"
    done
    
    # Check for application containers
    if docker ps | grep -q app; then
        app_container=$(docker ps | grep app | awk '{print $1}' | head -1)
        capture "docker exec $app_container env" "${DOCKER_DIR}/application_environment.txt" "Application container environment variables"
    fi
    
    # Check for docker-compose
    if [ -f "/opt/polyserver/config/docker-compose.yml" ]; then
        capture "cat /opt/polyserver/config/docker-compose.yml" "${DOCKER_DIR}/docker_compose_config.txt" "Docker Compose configuration"
    fi
fi

# Malware scanning
log "Performing basic malware scans..."

# Check for known malicious files
capture "timeout 60 find / -name \"*.php\" -not -path \"/usr/*\" -not -path \"/var/lib/*\" -type f -exec ls -la {} \;" "${MALWARE_DIR}/php_files.txt" "PHP files outside standard directories (1 minute timeout)"
capture "find /tmp -type f -name \"*.sh\" -exec ls -la {} \;" "${MALWARE_DIR}/tmp_shell_scripts.txt" "Shell scripts in /tmp"
capture "find / -type f -name \"nc\" -o -name \"netcat\" -exec ls -la {} \;" "${MALWARE_DIR}/netcat_binaries.txt" "Netcat binaries"

# Check for suspicious cron jobs
capture "grep -r \"wget\" /etc/cron*" "${MALWARE_DIR}/suspicious_cron_wget.txt" "Cron jobs with wget"
capture "grep -r \"curl\" /etc/cron*" "${MALWARE_DIR}/suspicious_cron_curl.txt" "Cron jobs with curl"
capture "grep -r \"\\.sh\" /etc/cron*" "${MALWARE_DIR}/suspicious_cron_shell.txt" "Cron jobs running shell scripts"

# Check for suspicious processes
capture "ps aux | grep -E \"nc|netcat|ncat\"" "${MALWARE_DIR}/suspicious_netcat_processes.txt" "Processes possibly using netcat"
capture "ps aux | grep -E \"wget|curl\"" "${MALWARE_DIR}/suspicious_download_processes.txt" "Processes possibly downloading content"

# Check for rootkits if rkhunter is available
if command -v rkhunter &> /dev/null; then
    capture "timeout 300 rkhunter --check --skip-keypress" "${MALWARE_DIR}/rkhunter_check.txt" "Rootkit Hunter scan (5 minute timeout)"
fi

# Check for malware if ClamAV is available
if command -v clamscan &> /dev/null; then
    capture "timeout 600 clamscan -r --max-filesize=100M --max-scansize=500M /tmp /var/tmp /home" "${MALWARE_DIR}/clamscan_results.txt" "ClamAV scan of key directories (10 minute timeout)"
fi

# Create evidence file hashes
log "Creating evidence file hashes for integrity verification..."

if command -v sha256sum &> /dev/null; then
    find "${OUTPUT_DIR}" -type f -not -name "file_hashes.txt" -exec sha256sum {} \; > "${OUTPUT_DIR}/file_hashes.txt"
    log "SHA256 hashes created for all evidence files"
else
    log "WARNING: sha256sum not available, skipping hash creation"
fi

# Create compressed archive of evidence
log "Creating compressed archive of all evidence..."

if command -v tar &> /dev/null; then
    ARCHIVE_NAME="polyserver_forensic_evidence_${TIMESTAMP}.tar.gz"
    tar -czf "${OUTPUT_DIR}/../${ARCHIVE_NAME}" -C "$(dirname "${OUTPUT_DIR}")" "$(basename "${OUTPUT_DIR}")"
    log "Evidence archived to ${OUTPUT_DIR}/../${ARCHIVE_NAME}"
else
    log "WARNING: tar not available, skipping archive creation"
fi

# Completion summary
log "Forensic evidence collection completed"
log "Total size of evidence: $(du -sh "${OUTPUT_DIR}" | cut -f1)"
log "Number of files collected: $(find "${OUTPUT_DIR}" -type f | wc -l)"

echo "Evidence collection complete. Results stored in: ${OUTPUT_DIR}"
echo "For chain of custody purposes, please document:"
echo "  - Who has accessed this evidence"
echo "  - When access occurred"
echo "  - What actions were taken with the evidence"

exit 0