#!/bin/bash
# trivy-scan.sh - Docker container vulnerability scanning script
# This script scans running containers for vulnerabilities using Trivy

# Set variables
DATE=$(date +%Y-%m-%d)
REPORT_DIR="/var/log/security/trivy"
MAIL_RECIPIENT="root"
HOSTNAME=$(hostname)
SEVERITY="HIGH,CRITICAL"
CONTAINERS=("app" "nginx" "db")
TRIVYLOG="${REPORT_DIR}/trivy-${DATE}.log"

# Resource management settings
LOAD_THRESHOLD=2.0
MAX_SCAN_TIME=1800  # 30 minutes max total scan time

# Create report directory if it doesn't exist
mkdir -p $REPORT_DIR

# Check system load before starting scan
CURRENT_LOAD=$(uptime | awk -F'load average:' '{ print $2 }' | awk '{ print $1 }' | sed 's/,//')

if (( $(echo "$CURRENT_LOAD > $LOAD_THRESHOLD" | bc -l) )); then
    echo "$(date): System load too high ($CURRENT_LOAD), skipping Trivy scan" > $TRIVYLOG
    exit 0
fi

# Set process priority for resource-aware scanning
renice -n 19 $$ >/dev/null 2>&1
ionice -c 3 -p $$ >/dev/null 2>&1

# Start log file
echo "===== Container Vulnerability Scan Report: $DATE =====" > $TRIVYLOG
echo "Hostname: $HOSTNAME" >> $TRIVYLOG
echo "Scanning for severity: $SEVERITY" >> $TRIVYLOG
echo "==========================================================" >> $TRIVYLOG
echo "" >> $TRIVYLOG

# Check for Trivy installation and install if not present
if ! command -v trivy &> /dev/null; then
    echo "Installing Trivy vulnerability scanner..." >> $TRIVYLOG
    
    # Add Trivy repository and install
    curl -sfL https://aquasecurity.github.io/trivy-repo/deb/public.key | gpg --dearmor | sudo tee /usr/share/keyrings/trivy.gpg > /dev/null
    echo "deb [signed-by=/usr/share/keyrings/trivy.gpg] https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main" | sudo tee /etc/apt/sources.list.d/trivy.list
    
    apt update
    apt install -y trivy
    
    if [ $? -ne 0 ]; then
        echo "Failed to install Trivy. Exiting." >> $TRIVYLOG
        exit 1
    fi
    
    echo "Trivy installation complete." >> $TRIVYLOG
    echo "" >> $TRIVYLOG
fi

# Update Trivy vulnerability database with timeout
echo "Updating Trivy vulnerability database..." >> $TRIVYLOG
timeout 300 nice -n 19 ionice -c 3 trivy image --download-db-only
if [ $? -eq 124 ]; then
    echo "Database update timed out after 5 minutes" >> $TRIVYLOG
elif [ $? -ne 0 ]; then
    echo "Database update failed" >> $TRIVYLOG
    exit 1
else
    echo "Vulnerability database updated." >> $TRIVYLOG
fi
echo "" >> $TRIVYLOG

# Scan all running containers with overall timeout
FOUND_VULNERABILITIES=0
TOTAL_HIGH=0
TOTAL_CRITICAL=0
SCAN_START_TIME=$(date +%s)

for CONTAINER in "${CONTAINERS[@]}"; do
    # Check if we've exceeded the maximum scan time
    CURRENT_TIME=$(date +%s)
    ELAPSED_TIME=$((CURRENT_TIME - SCAN_START_TIME))
    if [ $ELAPSED_TIME -gt $MAX_SCAN_TIME ]; then
        echo "Maximum scan time ($MAX_SCAN_TIME seconds) exceeded. Stopping scan." >> $TRIVYLOG
        break
    fi
    # Get the container image
    IMAGE_ID=$(docker inspect --format='{{.Config.Image}}' $CONTAINER 2>/dev/null)
    
    if [ $? -ne 0 ]; then
        echo "Container $CONTAINER not found or not running. Skipping." >> $TRIVYLOG
        continue
    fi
    
    echo "Scanning container: $CONTAINER (Image: $IMAGE_ID)" >> $TRIVYLOG
    
    # Scan the container image for vulnerabilities with resource controls
    SCAN_RESULT=$(timeout 600 nice -n 19 ionice -c 3 trivy image --no-progress --severity $SEVERITY --timeout 8m $IMAGE_ID 2>/dev/null)
    SCAN_EXIT_CODE=$?
    
    if [ $SCAN_EXIT_CODE -eq 124 ]; then
        echo "Scan for $CONTAINER timed out after 10 minutes" >> $TRIVYLOG
        continue
    elif [ $SCAN_EXIT_CODE -ne 0 ]; then
        echo "Scan for $CONTAINER failed with exit code $SCAN_EXIT_CODE" >> $TRIVYLOG
        continue
    fi
    
    # If vulnerabilities found
    if echo "$SCAN_RESULT" | grep -q -E "CRITICAL|HIGH"; then
        echo "$SCAN_RESULT" >> $TRIVYLOG
        FOUND_VULNERABILITIES=1
        
        # Count vulnerabilities by severity
        HIGH_COUNT=$(echo "$SCAN_RESULT" | grep -c "HIGH")
        CRITICAL_COUNT=$(echo "$SCAN_RESULT" | grep -c "CRITICAL")
        
        TOTAL_HIGH=$((TOTAL_HIGH + HIGH_COUNT))
        TOTAL_CRITICAL=$((TOTAL_CRITICAL + CRITICAL_COUNT))
        
        echo "Found $HIGH_COUNT HIGH and $CRITICAL_COUNT CRITICAL vulnerabilities." >> $TRIVYLOG
    else
        echo "No vulnerabilities found with severity $SEVERITY." >> $TRIVYLOG
    fi
    
    echo "" >> $TRIVYLOG
    echo "--------------------------------------------------------" >> $TRIVYLOG
    echo "" >> $TRIVYLOG
done

# Add summary
echo "SUMMARY" >> $TRIVYLOG
echo "=======" >> $TRIVYLOG
echo "Total containers scanned: ${#CONTAINERS[@]}" >> $TRIVYLOG
echo "Total HIGH vulnerabilities: $TOTAL_HIGH" >> $TRIVYLOG
echo "Total CRITICAL vulnerabilities: $TOTAL_CRITICAL" >> $TRIVYLOG
echo "" >> $TRIVYLOG

# Provide recommendations if vulnerabilities found
if [ $FOUND_VULNERABILITIES -eq 1 ]; then
    echo "RECOMMENDATIONS" >> $TRIVYLOG
    echo "===============" >> $TRIVYLOG
    echo "1. Update container images to newer versions if available" >> $TRIVYLOG
    echo "2. Check if there are security patches for the affected components" >> $TRIVYLOG
    echo "3. Consider implementing additional security controls for affected containers" >> $TRIVYLOG
    echo "4. For detailed vulnerability information, visit the CVE links provided above" >> $TRIVYLOG
    echo "" >> $TRIVYLOG
    
    # Send email notification if vulnerabilities found
    cat $TRIVYLOG | mail -s "⚠️ SECURITY: Container Vulnerabilities Found on $HOSTNAME" $MAIL_RECIPIENT
fi

# Keep only the last 30 days of logs
find $REPORT_DIR -name "trivy-*.log" -mtime +30 -delete

exit 0