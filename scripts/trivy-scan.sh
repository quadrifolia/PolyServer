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

# Create report directory if it doesn't exist
mkdir -p $REPORT_DIR

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

# Update Trivy vulnerability database
echo "Updating Trivy vulnerability database..." >> $TRIVYLOG
trivy image --download-db-only
echo "Vulnerability database updated." >> $TRIVYLOG
echo "" >> $TRIVYLOG

# Scan all running containers
FOUND_VULNERABILITIES=0
TOTAL_HIGH=0
TOTAL_CRITICAL=0

for CONTAINER in "${CONTAINERS[@]}"; do
    # Get the container image
    IMAGE_ID=$(docker inspect --format='{{.Config.Image}}' $CONTAINER 2>/dev/null)
    
    if [ $? -ne 0 ]; then
        echo "Container $CONTAINER not found or not running. Skipping." >> $TRIVYLOG
        continue
    fi
    
    echo "Scanning container: $CONTAINER (Image: $IMAGE_ID)" >> $TRIVYLOG
    
    # Scan the container image for vulnerabilities
    SCAN_RESULT=$(trivy image --no-progress --severity $SEVERITY --timeout 10m $IMAGE_ID)
    
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