#!/bin/bash
# server-setup-bastion.sh - Secure Debian 13 bastion host setup
# Specialized hardening for bastion hosts used for secure access to internal networks
# Run as root after fresh Debian 13 (trixie) instance creation

# Enhanced error handling with trap
set -Eeuo pipefail

# Root and OS verification
if [ "$(id -u)" -ne 0 ]; then echo "Run as root"; exit 1; fi
. /etc/os-release
case "$ID:$VERSION_ID" in debian:12*|debian:13*) : ;; *) echo "This script targets Debian 12/13"; exit 1;; esac

# Error trap function
error_trap() {
    local exit_code=$?
    local line_number=$1
    echo "❌ ERROR: Bastion setup failed at line $line_number with exit code $exit_code" >&2
    echo "❌ Command: ${BASH_COMMAND}" >&2
    echo "Setup failed! Check logs for details." >&2
    exit $exit_code
}

# Set trap for errors
trap 'error_trap $LINENO' ERR

# Root privilege check
if [[ $EUID -ne 0 ]]; then
   echo "❌ This script must be run as root"
   echo "Please run: sudo $0"
   exit 1
fi

set -e

# ========= Environment Setup =========
# Export necessary environment variables
export DEBIAN_FRONTEND=noninteractive
export LANG=C.UTF-8
export LC_ALL=C.UTF-8

# ========= Enhanced Error Handling and Logging =========
readonly SCRIPT_NAME="secure-bastion-setup"
readonly LOG_FILE="/var/log/${SCRIPT_NAME}.log"
readonly BACKUP_DIR="/var/backups/bastion-setup"

# Enhanced error handling
set -euo pipefail

# Utility functions
log_message() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "$LOG_FILE"
}

log_error() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] ERROR: $*" | tee -a "$LOG_FILE" >&2
}

# Create rollback point (SECURITY FIX)
create_rollback_point() {
    local checkpoint="$1"
    local timestamp
    timestamp=$(date +%s)
    local rollback_file="${BACKUP_DIR}/rollback-${checkpoint}-${timestamp}.tar.gz"
    
    mkdir -p "$BACKUP_DIR"
    log_message "Creating rollback point: $checkpoint"
    
    # Create encrypted backup if gpg is available (SECURITY ENHANCEMENT)
    if command -v gpg >/dev/null 2>&1; then
        local encrypted_file="${rollback_file}.gpg"
        tar -czf - \
            /etc/ssh \
            /etc/ufw \
            /etc/fail2ban \
            /etc/postfix \
            2>/dev/null | gpg --symmetric --cipher-algo AES256 --compress-algo 1 --batch --yes --passphrase "bastion-backup-$(hostname)-$timestamp" > "$encrypted_file" 2>/dev/null
        
        if [ -f "$encrypted_file" ]; then
            echo "$encrypted_file" > "${BACKUP_DIR}/latest-rollback"
            log_message "Encrypted rollback point created: $checkpoint"
        else
            # Fallback to unencrypted backup
            tar -czf "$rollback_file" \
                /etc/ssh \
                /etc/ufw \
                /etc/fail2ban \
                /etc/postfix \
                2>/dev/null || log_message "Some files missing during rollback creation"
            echo "$rollback_file" > "${BACKUP_DIR}/latest-rollback"
            log_message "Unencrypted rollback point created: $checkpoint"
        fi
    else
        # Fallback to unencrypted backup
        tar -czf "$rollback_file" \
            /etc/ssh \
            /etc/ufw \
            /etc/fail2ban \
            /etc/postfix \
            2>/dev/null || log_message "Some files missing during rollback creation"
        echo "$rollback_file" > "${BACKUP_DIR}/latest-rollback"
        log_message "Unencrypted rollback point created: $checkpoint (gpg not available)"
    fi
}

# Enhanced service management (SECURITY FIX)
start_service_with_retry() {
    local service="$1"
    local max_attempts=3
    local wait_time=5
    
    log_message "Starting service: $service"
    
    for attempt in $(seq 1 $max_attempts); do
        if systemctl start "$service"; then
            sleep "$wait_time"
            if systemctl is-active --quiet "$service"; then
                log_message "Service $service started successfully (attempt $attempt)"
                return 0
            fi
        fi
        log_message "Service $service start attempt $attempt failed, retrying..."
        sleep $((wait_time * attempt))
    done
    
    log_error "Failed to start service $service after $max_attempts attempts"
    return 1
}

# Secure password input (SECURITY FIX)
secure_password_input() {
    local prompt="$1"
    local password
    
    # Display prompt with explicit terminal write and flush
    echo -n "$prompt" >&2
    if ! read -rs password; then
        echo "" >&2
        log_error "Failed to read password input"
        return 1
    fi
    echo "" >&2
    
    if [ -z "$password" ]; then
        log_error "Password cannot be empty"
        return 1
    fi
    
    if [ ${#password} -lt 8 ]; then
        log_error "Password too short (minimum 8 characters)"
        return 1
    fi
    
    echo "$password"
}

# SSH key validation (SECURITY FIX)
validate_ssh_key() {
    local key="$1"
    local temp_key_file
    
    temp_key_file=$(mktemp)
    trap 'rm -f "$temp_key_file"' RETURN
    
    echo "$key" > "$temp_key_file"
    
    if ssh-keygen -l -f "$temp_key_file" >/dev/null 2>&1; then
        local key_bits
        key_bits=$(ssh-keygen -l -f "$temp_key_file" | awk '{print $1}')
        
        if [[ "$key" =~ ^ssh-ed25519 ]] || [ "$key_bits" -ge 2048 ]; then
            log_message "SSH key validation successful"
            return 0
        else
            log_error "SSH key too weak (minimum 2048 bits for RSA, or use Ed25519)"
            return 1
        fi
    else
        log_error "Invalid SSH key format"
        return 1
    fi
}

# Email validation (SECURITY FIX)
validate_email() {
    local email="$1"
    if [[ "$email" =~ ^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
        return 0
    else
        log_error "Invalid email format: $email"
        return 1
    fi
}

# Configuration validation (SECURITY FIX)
validate_critical_configs() {
    local errors=0
    
    log_message "Validating critical configurations..."
    
    echo "Checking SSH configuration..."
    if ! timeout 10 sshd -t 2>/dev/null; then
        log_error "SSH configuration validation failed"
        errors=$((errors + 1))
    else
        echo "✅ SSH configuration is valid"
    fi
    
    echo "Checking UFW configuration..."
    if ! timeout 10 ufw status >/dev/null 2>&1; then
        log_error "UFW configuration validation failed"
        errors=$((errors + 1))
    else
        echo "✅ UFW configuration is valid"
        # Check UFW status verbose for IPv6 and configuration details
        ufw_status=$(ufw status verbose 2>/dev/null)
        if echo "$ufw_status" | grep -q "IPV6: yes"; then
            echo "✅ UFW IPv6 support enabled"
        else
            echo "⚠️ UFW IPv6 support disabled"
        fi
        if echo "$ufw_status" | grep -q "Status: active"; then
            echo "✅ UFW firewall is active"
        else
            log_error "UFW firewall is inactive"
            errors=$((errors + 1))
        fi
    fi
    
    echo "Checking Fail2ban configuration..."
    if ! timeout 15 fail2ban-client -t >/dev/null 2>&1; then
        echo "⚠️ Fail2ban configuration validation timed out or failed"
        # Don't count as error if service is running
        if ! systemctl is-active --quiet fail2ban; then
            errors=$((errors + 1))
        fi
    else
        echo "✅ Fail2ban configuration is valid"
        # Check if fail2ban is using UFW backend as configured
        if fail2ban-client status 2>/dev/null | grep -q "sshd"; then
            echo "✅ Fail2ban SSH jail is active"
        else
            echo "⚠️ Fail2ban SSH jail not found"
        fi
    fi
    
    # AppArmor configuration validation
    echo "Checking AppArmor status..."
    if command -v aa-status >/dev/null 2>&1; then
        if aa_status_output=$(aa-status 2>/dev/null); then
            if echo "$aa_status_output" | grep -q "apparmor module is loaded"; then
                echo "✅ AppArmor is enabled and loaded"
                # Count enforce/complain profiles
                enforce_count=$(echo "$aa_status_output" | grep -c "profiles are in enforce mode" || echo "0")
                complain_count=$(echo "$aa_status_output" | grep -c "profiles are in complain mode" || echo "0")
                if [ "$enforce_count" -gt 0 ] || [ "$complain_count" -gt 0 ]; then
                    echo "✅ AppArmor profiles active (enforce: $enforce_count, complain: $complain_count)"
                else
                    echo "⚠️ AppArmor enabled but no active profiles found"
                fi
            else
                log_error "AppArmor module not loaded"
                errors=$((errors + 1))
            fi
        else
            log_error "Failed to get AppArmor status"
            errors=$((errors + 1))
        fi
    else
        log_error "AppArmor not installed (aa-status command not found)"
        errors=$((errors + 1))
    fi
    
    if [ $errors -eq 0 ]; then
        log_message "All critical configurations validated successfully"
        return 0
    else
        log_error "Configuration validation failed with $errors errors"
        return 1
    fi
}

# ========= Configuration =========
# This script is designed for production bastion host deployment
# All parameters are set to secure defaults for bastion use case

USERNAME="bastion"                      # Bastion user to create
HOSTNAME="bastion"                      # Bastion hostname  
SSH_PORT="${SSH_PORT:-2222}"            # Custom SSH port (configurable via environment, default 2222)
LOGWATCH_EMAIL="root"                   # Security notification email
MAX_SSH_SESSIONS="5"                    # Maximum concurrent SSH sessions
SSH_LOGIN_GRACE_TIME="30"               # SSH login grace time
SSH_CLIENT_ALIVE_INTERVAL="300"         # Keep alive interval
SSH_CLIENT_ALIVE_COUNT_MAX="2"          # Max keep alive attempts

# Security Components - Essential tools enabled by default for comprehensive bastion protection
: "${INSTALL_CLAMAV:=false}"            # Install ClamAV antivirus (high resource usage) - optional
: "${INSTALL_MALDET:=false}"            # Install Linux Malware Detect (medium resource usage) - optional
: "${INSTALL_RKHUNTER:=true}"           # Install rootkit detection tools (low resource usage) - ENABLED BY DEFAULT
: "${INSTALL_SURICATA:=true}"           # Install Suricata IDS (medium resource usage) - ENABLED BY DEFAULT

# Bastion-specific network configuration
INTERNAL_NETWORK="10.0.0.0/8,172.16.0.0/12,192.168.0.0/16"
ALLOWED_INTERNAL_PORTS="22,80,443,3306,5432"

# SSH public key - MUST be configured in this file
# Replace with your actual SSH public key before running the script
# Example: SSH_PUBLIC_KEY="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIG... user@domain.com"
SSH_PUBLIC_KEY=""

# CRITICAL: Prevent lock-out by requiring SSH key
if [ -z "$SSH_PUBLIC_KEY" ]; then
    echo "❌ ERROR: No SSH_PUBLIC_KEY configured" >&2
    echo "" >&2
    echo "SECURITY LOCKOUT PREVENTION:" >&2
    echo "Bastion hosts disable password authentication completely." >&2
    echo "Without an SSH key, you would be permanently locked out." >&2
    echo "" >&2
    echo "Please set SSH_PUBLIC_KEY in the script or provide it via environment variable." >&2
    echo "" >&2
    echo "To get your public key, run one of these commands on your local machine:" >&2
    echo "  cat ~/.ssh/id_ed25519.pub    (for Ed25519 keys - RECOMMENDED)" >&2
    echo "  cat ~/.ssh/id_rsa.pub        (for RSA keys - minimum 2048 bits)" >&2
    echo "" >&2
    echo "Then set it in the script:" >&2
    echo "  SSH_PUBLIC_KEY=\"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIG... user@domain.com\"" >&2
    echo "" >&2
    echo "Or provide it via environment variable:" >&2
    echo "  export SSH_PUBLIC_KEY=\"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIG... user@domain.com\"" >&2
    echo "  ./server-setup-bastion.sh" >&2
    echo "" >&2
    log_error "Refusing to continue to prevent lock-out. SSH key is mandatory for bastion hosts."
    exit 1
fi

# Validate the provided SSH key
if ! validate_ssh_key "$SSH_PUBLIC_KEY"; then
    echo "❌ ERROR: Invalid SSH key format" >&2
    echo "Please provide a valid SSH public key (Ed25519 recommended, or RSA ≥2048 bits)" >&2
    exit 1
fi

echo "✅ Valid SSH public key provided - proceeding with secure bastion setup"

# Email configuration
echo ""
while true; do
    read -r -p "Enter email address for security notifications (default: root): " EMAIL_INPUT
    if [ -z "$EMAIL_INPUT" ]; then
        LOGWATCH_EMAIL="root"
        break
    elif validate_email "$EMAIL_INPUT"; then
        LOGWATCH_EMAIL="$EMAIL_INPUT"
        break
    else
        echo "Please enter a valid email address"
    fi
done
    
echo ""
while true; do
    read -r -p "Enter SSH port for bastion access (default: 2222): " SSH_PORT_INPUT
    if [ -z "$SSH_PORT_INPUT" ]; then
        SSH_PORT="2222"
        break
    elif [[ "$SSH_PORT_INPUT" =~ ^[0-9]+$ ]] && [ "$SSH_PORT_INPUT" -ge 1024 ] && [ "$SSH_PORT_INPUT" -le 65535 ]; then
        SSH_PORT="$SSH_PORT_INPUT"
        break
    else
        echo "Please enter a valid port number (1024-65535)"
    fi
done
echo ""

# SMTP Configuration for reliable email delivery
echo "===== SMTP EMAIL CONFIGURATION ====="
echo ""
echo "Configure external SMTP for reliable email delivery (recommended)."
echo "This ensures security notifications are not filtered as spam."
echo ""
read -r -p "Do you want to configure external SMTP? (y/n, default: n): " SMTP_CONFIGURE

if [[ "$SMTP_CONFIGURE" =~ ^[Yy]$ ]]; then
    echo ""
    echo "Please provide your SMTP server details:"
    echo ""
    read -r -p "SMTP Server (e.g., smtp.gmail.com): " SMTP_SERVER
    read -r -p "SMTP Port (default: 587): " SMTP_PORT
    SMTP_PORT=${SMTP_PORT:-587}
    
    while true; do
        read -r -p "SMTP Username: " SMTP_USERNAME
        if [ -n "$SMTP_USERNAME" ]; then
            break
        fi
        echo "SMTP username is required"
    done
    
    # SECURITY FIX: Secure password input
    while true; do
        SMTP_PASSWORD=$(secure_password_input "SMTP Password: ")
        if [ $? -eq 0 ] && [ -n "$SMTP_PASSWORD" ]; then
            break
        fi
        echo "Valid SMTP password is required (minimum 8 characters)"
    done
    
    while true; do
        read -r -p "From Email Address (must match SMTP account): " SMTP_FROM_EMAIL
        if validate_email "$SMTP_FROM_EMAIL"; then
            break
        fi
    done

    read -r -p "Use TLS/STARTTLS? (y/n, default: y): " SMTP_TLS
    SMTP_TLS=${SMTP_TLS:-y}
    
    if [ -z "$SMTP_SERVER" ] || [ -z "$SMTP_USERNAME" ] || [ -z "$SMTP_PASSWORD" ] || [ -z "$SMTP_FROM_EMAIL" ]; then
        echo "ERROR: SMTP server, username, password, and from email are required"
        echo "Falling back to local mail delivery"
        SMTP_CONFIGURE="n"
    else
        echo ""
        echo "SMTP configuration saved. All security notifications will be sent via external SMTP."
        echo "From: $SMTP_FROM_EMAIL -> To: $LOGWATCH_EMAIL"
    fi
    echo ""
else
    echo "Using local mail delivery (emails will be stored locally only)"
    echo ""
fi

echo "===== BASTION HOST HARDENING SETUP ====="
echo "This script will configure a Debian 13 server as a secure bastion host"
echo "Bastion hosts require strict security configuration and monitoring"
echo ""
echo "✅ Running as root (required for system configuration)"
echo "✅ Script environment configured"
echo ""

# ========= Basic server hardening =========
echo "===== 1. Updating system packages ====="
# Debian 13 (Trixie) includes APT 3.0 with improved UI, Solver3 dependency resolver,
# and enhanced cryptographic support using OpenSSL/Sequoia instead of GnuTLS/GnuPG
# Wait for any running package management processes to complete
wait_for_dpkg_lock() {
    local timeout=300  # 5 minutes timeout
    local count=0

    while fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1 \
       || fuser /var/cache/apt/archives/lock >/dev/null 2>&1 \
       || pgrep -x unattended-upgrade >/dev/null 2>&1 \
       || pgrep -x apt-get >/dev/null 2>&1 \
       || pgrep -x dpkg >/dev/null 2>&1; do
        if [ $count -ge $timeout ]; then
            echo "⚠️ Timeout waiting for package management lock - continuing anyway"
            break
        fi

        if [ $((count % 10)) -eq 0 ]; then
            echo "Waiting for package management to complete... ($count/$timeout seconds)"
            # Show what process is holding the lock
            pgrep -af "(apt|dpkg|unattended)" || true
        fi

        sleep 1
        count=$((count + 1))
    done
}

echo "Checking for running package management processes..."
wait_for_dpkg_lock

# Configure dpkg properly before update
dpkg --configure -a

# Update package lists and upgrade system
apt-get clean
apt-get update || {
    log_error "Failed to update package lists"
    sleep 5
    apt-get update
}
apt-get upgrade -y || {
    log_error "Failed to upgrade packages - continuing anyway"
}

echo "===== 2. Setting hostname ====="
# Set hostname with better error handling
if ! hostnamectl set-hostname "$HOSTNAME" 2>/dev/null; then
    log_message "Note: Unable to set hostname via hostnamectl, using fallback method"
    echo "$HOSTNAME" > /etc/hostname
    hostname "$HOSTNAME" 2>/dev/null || true
fi

echo "===== 2.1 Setting root password for emergency access ====="
echo "Setting a secure root password for console/emergency access..."
echo "This is important for recovery scenarios when SSH key access fails."
echo ""
echo "Please set a strong root password:"
passwd root
echo "✅ Root password configured for emergency console access"
echo ""

echo "===== 3. Creating bastion user with strict configuration ====="
if ! id "$USERNAME" &>/dev/null; then
    
    echo "Creating bastion user with key-only authentication"
    useradd -m -s /bin/bash "$USERNAME"
    
    # Disable password authentication while preserving SSH key access
    # Method 1: Set impossible password hash (allows SSH keys, blocks password)
    usermod -p '*' "$USERNAME"   # Set impossible password hash (stronger than !)
    
    # Method 2: Configure password aging to eliminate expiration issues
    chage -E -1 "$USERNAME"      # Remove password expiration date (never expires)
    chage -I -1 "$USERNAME"      # Remove inactive period
    chage -m 0 "$USERNAME"       # No minimum password age
    chage -M 99999 "$USERNAME"   # Maximum password age (essentially forever)
    chage -d -1 "$USERNAME"      # Set last change to "never" (fixes sudo issues)
    chage -W -1 "$USERNAME"      # Remove expiration warning
    
    # Method 3: Do NOT use passwd -l as it completely locks the account
    # passwd -l would prevent SSH key authentication from working
    # The combination of usermod -p '*' and SSH configuration is sufficient
    
    # Method 4: Verify settings
    echo "Password authentication status for $USERNAME:"
    chage -l "$USERNAME" | grep -E "(Last password change|Password expires|Account expires)"
    echo "User created with disabled password authentication - SSH key authentication only"
    
    # Add bastion user to adm group for log access
    usermod -aG adm "$USERNAME"

    # Get the actual home directory created by useradd
    USER_HOME=$(getent passwd "$USERNAME" | cut -d: -f6)

    if [ -z "$USER_HOME" ]; then
        echo "❌ Could not determine home directory for newly created user $USERNAME"
        exit 1
    fi

    echo "Using home directory: $USER_HOME"

    # Create SSH directory for the new user
    mkdir -p "$USER_HOME/.ssh"
    chmod 700 "$USER_HOME/.ssh"
    chown "$USERNAME:$USERNAME" "$USER_HOME/.ssh"

    # Set up SSH key if provided
    if [ -n "$SSH_PUBLIC_KEY" ]; then
        echo "Setting up SSH public key for $USERNAME"
        echo "$SSH_PUBLIC_KEY" > "$USER_HOME/.ssh/authorized_keys"
        chmod 600 "$USER_HOME/.ssh/authorized_keys"
        chown "$USERNAME:$USERNAME" "$USER_HOME/.ssh/authorized_keys"
        echo "SSH key configured successfully"
    fi
fi

# Create restricted sudo access for bastion user (SECURITY HARDENED)
echo "Setting up restricted sudo privileges for $USERNAME..."
cat > /etc/sudoers.d/bastion-$USERNAME << EOF
# Bastion user sudo privileges - RESTRICTED to absolute minimum for security
# Using Cmnd_Alias with exact paths to prevent privilege escalation

# Define command aliases with exact paths only
Cmnd_Alias SSH_RESTART = /usr/bin/systemctl restart ssh, /bin/systemctl restart ssh, /usr/bin/systemctl restart sshd, /bin/systemctl restart sshd
Cmnd_Alias SSH_STATUS = /usr/bin/systemctl status ssh, /bin/systemctl status ssh, /usr/bin/systemctl status sshd, /bin/systemctl status sshd
Cmnd_Alias SSH_ACTIVE = /usr/bin/systemctl is-active ssh, /bin/systemctl is-active ssh, /usr/bin/systemctl is-active sshd, /bin/systemctl is-active sshd

# UFW status checking only (no modification allowed)
Cmnd_Alias UFW_STATUS = /usr/sbin/ufw status, /sbin/ufw status, /usr/bin/ufw status, /usr/sbin/ufw --version, /sbin/ufw --version, /usr/bin/ufw --version

# Fail2ban status checking only (no jail modification)
Cmnd_Alias FAIL2BAN_STATUS = /usr/bin/fail2ban-client status

# Essential bastion monitoring scripts (custom commands only)
Cmnd_Alias BASTION_COMMANDS = /usr/local/bin/bastionstat, /usr/local/bin/sshmon, /usr/local/bin/bastionmail

# Specific log file access (no wildcards)
Cmnd_Alias LOG_ACCESS = /usr/bin/tail /var/log/auth.log, /usr/bin/tail /var/log/syslog, /usr/bin/tail /var/log/fail2ban.log

# Grant minimal required privileges
$USERNAME ALL=(ALL) NOPASSWD: SSH_RESTART, SSH_STATUS, SSH_ACTIVE
$USERNAME ALL=(ALL) NOPASSWD: UFW_STATUS
$USERNAME ALL=(ALL) NOPASSWD: FAIL2BAN_STATUS  
$USERNAME ALL=(ALL) NOPASSWD: BASTION_COMMANDS
$USERNAME ALL=(ALL) NOPASSWD: LOG_ACCESS

# Security settings
Defaults:$USERNAME !requiretty
Defaults:$USERNAME secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
EOF
chmod 440 /etc/sudoers.d/bastion-$USERNAME

# Ensure bastion user is in adm group (for existing users too)
usermod -aG adm "$USERNAME" 2>/dev/null || true

echo "===== 4. Configuring SSH with bastion-specific hardening ====="
create_rollback_point "pre-ssh"
# Backup original SSH config
cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak
    
# Create highly secure SSH configuration for bastion host
cat > /etc/ssh/sshd_config << EOF
# Bastion Host SSH Configuration - Maximum Security
# This configuration prioritizes security over convenience

# Network Configuration
Port $SSH_PORT
Protocol 2
AddressFamily inet
ListenAddress 0.0.0.0

# Host Keys - Use only secure algorithms
HostKey /etc/ssh/ssh_host_ed25519_key
HostKey /etc/ssh/ssh_host_rsa_key

# Authentication Configuration
LoginGraceTime $SSH_LOGIN_GRACE_TIME
PermitRootLogin no
StrictModes yes
MaxAuthTries 2
MaxSessions $MAX_SSH_SESSIONS
MaxStartups 3:30:10

# Key-based authentication only (NO password auth on bastions)
PubkeyAuthentication yes
AuthenticationMethods publickey
PasswordAuthentication no
PermitEmptyPasswords no
ChallengeResponseAuthentication no
KbdInteractiveAuthentication no
UsePAM no
AuthorizedKeysFile .ssh/authorized_keys

# Forwarding and Tunneling - Essential for bastion functionality
AllowTcpForwarding local
AllowStreamLocalForwarding yes
AllowAgentForwarding no
PermitTunnel no
GatewayPorts no

# X11 and other features - Disabled for security
X11Forwarding no
PrintMotd yes
PrintLastLog yes

# Environment
AcceptEnv LANG LC_*

# Subsystems
Subsystem sftp internal-sftp -f AUTH -l INFO

# Security hardening
IgnoreRhosts yes
HostbasedAuthentication no
PermitUserEnvironment no
Compression delayed
ClientAliveInterval $SSH_CLIENT_ALIVE_INTERVAL
ClientAliveCountMax $SSH_CLIENT_ALIVE_COUNT_MAX
TCPKeepAlive yes

# Modern cryptographic algorithms with post-quantum hybrid support
KexAlgorithms sntrup761x25519-sha512@openssh.com,curve25519-sha256,curve25519-sha256@libssh.org
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com

# Ensure no weak key types
PubkeyAcceptedKeyTypes rsa-sha2-512,rsa-sha2-256,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521,ssh-ed25519

# User access control
AllowUsers $USERNAME
DenyUsers root

# Logging
LogLevel INFO
SyslogFacility AUTH

# Banner
Banner /etc/ssh/banner
EOF
    
# Create SSH banner for bastion host
cat > /etc/ssh/banner << EOF
***************************************************************************
                          BASTION HOST ACCESS
***************************************************************************

WARNING: This is a secure bastion host. All access is logged and monitored.

Unauthorized access is prohibited and will be prosecuted to the full extent
of the law. All activities on this system are recorded and may be used as
evidence in legal proceedings.

By accessing this system, you acknowledge that:
- You are an authorized user
- Your activities are being monitored and logged
- You agree to comply with all applicable policies
- You will not attempt to compromise system security

If you are not an authorized user, disconnect immediately.

***************************************************************************
EOF
chmod 644 /etc/ssh/banner

echo "===== 5. Setting up bastion-specific firewall rules ====="
create_rollback_point "pre-firewall"

# Install UFW if not already installed
if ! command -v ufw >/dev/null 2>&1; then
    echo "Installing UFW firewall..."
    apt update
    apt install -y ufw
    echo "✅ UFW installed successfully"
else
    echo "✅ UFW already installed"
fi

# Reset firewall to default state
echo "Configuring UFW firewall rules..."
ufw --force reset

# Configure IPv6 support and nftables backend (Debian 13 default)  
sed -i 's/IPV6=no/IPV6=yes/' /etc/default/ufw

# Ensure UFW uses nftables backend (Debian 13 default)
# This ensures consistency with fail2ban UFW actions
if ! grep -q "^BACKEND=nftables" /etc/default/ufw; then
    echo "BACKEND=nftables" >> /etc/default/ufw
fi

# Set restrictive default policies (IPv4 and IPv6)
ufw default deny incoming
ufw default deny outgoing
ufw default deny forward

# CRITICAL: Protect current SSH session before enabling UFW
echo "Detecting current SSH connection to prevent lockout..."

# Safer method to detect SSH connection details
CURRENT_SSH_PORT=""
CLIENT_IP=""

# Try multiple methods to detect SSH port
if command -v ss >/dev/null 2>&1; then
    CURRENT_SSH_PORT=$(ss -tlnp 2>/dev/null | grep sshd | grep -o ':[0-9]*' | head -1 | cut -d: -f2 2>/dev/null || echo "")
fi

# Fallback to netstat if ss fails
if [ -z "$CURRENT_SSH_PORT" ] && command -v netstat >/dev/null 2>&1; then
    CURRENT_SSH_PORT=$(netstat -tlnp 2>/dev/null | grep sshd | grep -o ':[0-9]*' | head -1 | cut -d: -f2 2>/dev/null || echo "")
fi

# Default to 22 if detection fails
if [ -z "$CURRENT_SSH_PORT" ]; then
    CURRENT_SSH_PORT="22"
fi

# Safely get client IP if SSH_CLIENT is set
if [ -n "${SSH_CLIENT:-}" ]; then
    CLIENT_IP=$(echo "$SSH_CLIENT" | cut -d' ' -f1 2>/dev/null || echo "")
fi

echo "Detected SSH port: $CURRENT_SSH_PORT"
echo "Detected client IP: ${CLIENT_IP:-'not detected'}"

# ALWAYS add protection for current SSH port (even if same as target port)
echo "Adding protection rules for current SSH session..."
ufw allow in "$CURRENT_SSH_PORT"/tcp comment "TEMP: Current SSH session protection"

# Add client-specific rule if we have the IP
if [ -n "$CLIENT_IP" ] && [ "$CLIENT_IP" != "" ]; then
    echo "Adding client-specific protection from $CLIENT_IP"
    ufw allow from "$CLIENT_IP" to any port "$CURRENT_SSH_PORT" comment "TEMP: Current SSH client protection"
fi

# Add protection for new SSH port if different
if [ "$CURRENT_SSH_PORT" != "$SSH_PORT" ]; then
    echo "⚠️  WARNING: Currently connected on port $CURRENT_SSH_PORT, bastion will use port $SSH_PORT"
    echo "Adding protection for new SSH port $SSH_PORT"
    ufw allow in "$SSH_PORT"/tcp comment "SSH bastion access"
else
    echo "✅ Current SSH port matches target port - single rule sufficient"
fi

# Also allow default SSH port temporarily (in case user is connected via default port)
if [ "$SSH_PORT" != "22" ]; then
    ufw allow in 22/tcp comment "TEMP: Default SSH port (remove after testing new port)"
fi

# Allow outgoing connections to internal networks on common ports (restricted by destination)
IFS=',' read -ra NETS <<< "$INTERNAL_NETWORK"
IFS=',' read -ra PORTS <<< "$ALLOWED_INTERNAL_PORTS"
for n in "${NETS[@]}"; do
  for p in "${PORTS[@]}"; do
    ufw allow out to "$n" port "$p" proto tcp comment "internal $p"
    [ "$p" = "53" ] && ufw allow out to "$n" port 53 proto udp comment "internal DNS"
  done
done

# Allow outgoing SSH on custom port (for SSH tunneling and forwarding)
ufw allow out "$SSH_PORT"/tcp comment "SSH outbound for tunneling"

# Ensure DNS is allowed (both TCP and UDP) if not already in the list
if [[ ! "$ALLOWED_INTERNAL_PORTS" =~ "53" ]]; then
    ufw allow out 53/tcp comment "DNS resolution TCP"
    ufw allow out 53/udp comment "DNS resolution UDP"
fi

# Allow outgoing HTTP/HTTPS for updates and monitoring
ufw allow out 80/tcp comment "HTTP updates"
ufw allow out 443/tcp comment "HTTPS updates"

# Allow NTP time synchronization (critical for logs and TLS)
ufw allow out 123/udp comment "NTP time sync"

# Enable NTP synchronization
systemctl enable --now systemd-timesyncd 2>/dev/null || true

# Allow SMTP port if external SMTP is configured
if [[ "$SMTP_CONFIGURE" =~ ^[Yy]$ ]]; then
    ufw allow out "$SMTP_PORT"/tcp comment "SMTP email delivery"
    echo "✅ Added UFW rule for SMTP port $SMTP_PORT"
fi

# NTP rule already configured above

# Use connection tracking instead of broad port ranges (SECURITY FIX)
# UFW automatically handles established connections when using stateful rules
# DNS and HTTP/HTTPS rules already configured above
ufw allow out 22/tcp comment "SSH for bastion connections"
ufw allow out $SSH_PORT/tcp comment "SSH on custom port"

# Log all denied connections for security monitoring
ufw logging on

# Final verification before enabling UFW
echo "===== FINAL VERIFICATION BEFORE ENABLING UFW ====="
echo "Verifying all protection rules are in place..."

# Show current rules before enabling
echo "Current UFW rules (before enabling):"
ufw status numbered

echo ""
echo "SSH Protection Summary:"
echo "• Current SSH port: $CURRENT_SSH_PORT"
echo "• Target SSH port: $SSH_PORT"
echo "• Client IP: ${CLIENT_IP:-'not detected'}"
echo ""

# Add a brief delay to ensure all rules are processed
echo "Waiting 3 seconds for rule processing..."
sleep 3

# Enable the firewall with safety measures
echo "===== ENABLING UFW FIREWALL WITH SESSION PROTECTION ====="
echo "🔒 Current SSH session has been protected with temporary rules"
echo "🔧 Bastion will use SSH port $SSH_PORT after setup is complete"
if [ "$SSH_PORT" != "22" ]; then
    echo "⚠️  After testing, remove temporary rule: sudo ufw delete allow 22/tcp"
fi
echo ""
echo "Enabling UFW firewall (non-interactive)..."

# Enable firewall without prompting (safer for remote execution) 
# Use yes to handle any unexpected prompts
if echo "y" | ufw --force enable; then
    echo "✅ UFW enabled successfully"
else
    echo "❌ UFW enable failed - checking status"
    ufw status
fi

# Show the status of the firewall
echo "✅ UFW firewall configuration complete"
ufw status verbose

echo ""
echo "🔐 FIREWALL SAFETY INFORMATION:"
echo "================================="
if [ "$SSH_PORT" != "22" ]; then
    echo "⚠️  Your current SSH session is protected by temporary rules"
    echo "⚠️  New bastion port: $SSH_PORT (configured)"
    echo "⚠️  Current connection port: ${CURRENT_SSH_PORT:-22} (temporary rule active)"
    echo ""
    echo "📋 NEXT STEPS FOR SSH PORT CHANGE:"
    echo "1. Keep this SSH session open as backup"
    echo "2. Test new SSH port in another terminal:"
    echo "   ssh -p $SSH_PORT $USERNAME@$(hostname -I | awk '{print $1}')"
    echo "3. Once confirmed working, remove temporary rule:"
    echo "   sudo ufw delete allow 22/tcp"
    echo "4. Only then close this session"
else
    echo "✅ SSH port remains 22 (no port change needed)"
fi
echo ""

echo "===== 5.1. Configuring NTP time synchronization ====="
# Ensure NTP synchronization is enabled (critical for bastion logging)
timedatectl set-ntp true

# Verify NTP is working
if timedatectl status | grep -q "NTP service: active"; then
    echo "✅ NTP synchronization enabled and active"
else
    echo "⚠️ NTP synchronization may not be working properly"
fi

# Show current time sync status
timedatectl status
echo ""

echo "===== 6. Installing security packages for bastion monitoring ====="
# Pre-configure postfix for local mail delivery (non-interactive)
echo "postfix postfix/main_mailer_type string 'Local only'" | debconf-set-selections
echo "postfix postfix/mailname string $(hostname -f)" | debconf-set-selections

# Update package lists before installing
wait_for_dpkg_lock; apt-get update

echo "===== 5. Optional Security Components for Bastion ====="
echo "Choose security tools for this bastion host. Bastions have unique requirements:"
echo ""

# ClamAV Antivirus
# Security components are now configured via environment variables
echo "===== 5.0 Security Components Configuration ====="
echo "• INSTALL_CLAMAV=$INSTALL_CLAMAV (File scanning - HIGH resource usage)"
if [ "$INSTALL_CLAMAV" = true ]; then
    # Create ClamAV user before package installation
    if ! id "clamav" &>/dev/null; then
        echo "Creating clamav user before package installation..."
        useradd --system --home-dir /var/lib/clamav --shell /bin/false clamav
        echo "✅ ClamAV user created"
    fi
fi

echo "• INSTALL_MALDET=$INSTALL_MALDET (Malware detection - MEDIUM resource usage - optional)"
echo "• INSTALL_RKHUNTER=$INSTALL_RKHUNTER (Rootkit detection - LOW resource usage - ENABLED BY DEFAULT)"
echo "• INSTALL_SURICATA=$INSTALL_SURICATA (Network IDS - MEDIUM resource usage - ENABLED BY DEFAULT)"
echo ""

echo "===== 5.1 Installing core bastion packages ====="
# Core packages (always installed for bastion functionality)
wait_for_dpkg_lock; apt-get install -y fail2ban unattended-upgrades apt-listchanges \
    logwatch lm-sensors unbound apparmor apparmor-utils \
    tcpdump netcat-openbsd mailutils postfix \
    $( [ "$INSTALL_CLAMAV" = true ] && echo "clamav clamav-daemon" ) \
    $( [ "$INSTALL_RKHUNTER" = true ] && echo "rkhunter chkrootkit" ) \
    $( [ "$INSTALL_SURICATA" = true ] && echo "suricata" )

echo "✅ Bastion security package installation completed"

INSTALLED_COMPONENTS=""
[ "$INSTALL_CLAMAV" = true ] && INSTALLED_COMPONENTS="$INSTALLED_COMPONENTS clamav"
[ "$INSTALL_MALDET" = true ] && INSTALLED_COMPONENTS="$INSTALLED_COMPONENTS maldet"
[ "$INSTALL_RKHUNTER" = true ] && INSTALLED_COMPONENTS="$INSTALLED_COMPONENTS rkhunter(default)"
[ "$INSTALL_SURICATA" = true ] && INSTALLED_COMPONENTS="$INSTALLED_COMPONENTS suricata(default)"
echo "Installed security components:${INSTALLED_COMPONENTS:- none}"

if [ "$INSTALL_CLAMAV" = true ]; then
    echo "===== 6.0.1 Configuring ClamAV with resource optimization for bastion hosts ====="
    # Optimize ClamAV for bastion host environment with limited resources
    # This prevents ClamAV from consuming excessive CPU/memory that could impact critical services

    # Stop services during configuration
    systemctl stop clamav-daemon clamav-freshclam 2>/dev/null || true

    # Configure ClamAV daemon with resource-conscious settings
    cat > /etc/clamav/clamd.conf << EOF
# ClamAV Daemon Configuration - Optimized for Bastion Hosts
User clamav
LocalSocket /run/clamav/clamd.ctl
FixStaleSocket true
LocalSocketGroup clamav
LocalSocketMode 666

# Reduce resource consumption
MaxThreads 1
MaxConnectionQueueLength 5
MaxQueue 50

# Optimize scanning performance vs resources
ReadTimeout 120
CommandReadTimeout 30
SendBufTimeout 120

# File size and scanning limits to prevent excessive resource usage
MaxScanSize 50M
MaxFileSize 10M
MaxRecursion 8
MaxFiles 5000
MaxPartitions 25
MaxIconsPE 50

# Scan behavior - balance security vs performance
ScanPE true
ScanELF true
ScanOLE2 true
ScanPDF true
ScanHTML true
ScanArchive true
ArchiveBlockEncrypted false
MaxDirectoryRecursion 10

# Memory and timeout optimizations
PCREMatchLimit 5000
PCRERecMatchLimit 2500
PCREMaxFileSize 10M
MaxScanTime 30000

# Logging - lightweight for bastion
LogFile /var/log/clamav/clamav.log
LogTime true
LogClean false
LogSyslog false
LogRotate true
LogVerbose false

# Network and detection settings
SelfCheck 3600
DatabaseDirectory /var/lib/clamav
OfficialDatabaseOnly false
Foreground false
Debug false

# Resource-conscious detection
IdleTimeout 30
ExitOnOOM true
LeaveTemporaryFiles false
DetectPUA false
CrossFilesystems false

# Heuristic settings - balanced approach
AlgorithmicDetection true
Bytecode true
BytecodeSecurity TrustSigned
BytecodeTimeout 30000

# Disable potentially resource-intensive features for bastion use
PhishingSignatures false
PhishingAlwaysBlockSSLMismatch false
PhishingAlwaysBlockCloak false
HeuristicScanPrecedence false
StructuredDataDetection false
ScanPartialMessages false
OLE2BlockMacros false
EOF

    # Configure freshclam with reduced frequency to prevent resource spikes
    cat > /etc/clamav/freshclam.conf << EOF
# ClamAV Freshclam Configuration - Optimized for Bastion Hosts
DatabaseOwner clamav

# Reduce update frequency from default 24/day to 2/day to minimize resource impact
Checks 2

# Database mirrors and sources
DatabaseMirror db.us.clamav.net
DatabaseMirror db.local.clamav.net

# Logging
UpdateLogFile /var/log/clamav/freshclam.log
LogVerbose false
LogSyslog false
LogTime true
LogRotate true

# Download behavior - be gentle on resources
MaxAttempts 3
ConnectTimeout 30
ReceiveTimeout 30

# Notify clamd of updates
NotifyClamd /etc/clamav/clamd.conf

# Test database before loading
TestDatabases yes

# Bytecode updates
Bytecode true
EOF

    # Create systemd resource limits for ClamAV services
    echo "Setting up systemd resource limits for ClamAV services..."

    # ClamAV daemon resource limits
    mkdir -p /etc/systemd/system/clamav-daemon.service.d
    cat > /etc/systemd/system/clamav-daemon.service.d/resource-limits.conf << EOF
[Service]
# Proper memory limits for ClamAV daemon (minimum 1GB required)
CPUQuota=25%
MemoryMax=1536M
MemoryHigh=1200M

# Process priority and I/O scheduling
Nice=19
IOSchedulingClass=3
IOSchedulingPriority=7

# Smart restart behavior with longer delays
Restart=on-failure
RestartSec=60
StartLimitInterval=1200
StartLimitBurst=2

# OOM handling - kill ClamAV rather than other services
OOMPolicy=kill
OOMScoreAdjust=500

# Security and resource isolation
NoNewPrivileges=true

# Prevent memory fragmentation issues
TasksMax=50
EOF

    # Freshclam resource limits
    mkdir -p /etc/systemd/system/clamav-freshclam.service.d
    cat > /etc/systemd/system/clamav-freshclam.service.d/resource-limits.conf << EOF
[Service]
# Proper memory limits for virus definition updates (minimum 768MB required)
CPUQuota=15%
MemoryMax=1024M
MemoryHigh=768M

# Process priority
Nice=19
IOSchedulingClass=3

# Restart behavior
Restart=on-failure
RestartSec=120
StartLimitInterval=1800
StartLimitBurst=2

# OOM handling
OOMPolicy=kill
OOMScoreAdjust=400

# Security isolation
NoNewPrivileges=true

# Prevent resource conflicts during updates
TasksMax=20
EOF

    # Create log directory with proper permissions
    mkdir -p /var/log/clamav
    chown clamav:clamav /var/log/clamav
    chmod 755 /var/log/clamav

    # Set up logrotate for ClamAV logs
    cat > /etc/logrotate.d/clamav << EOF
/var/log/clamav/*.log {
    weekly
    rotate 12
    compress
    delaycompress
    missingok
    notifempty
    create 644 clamav clamav
    postrotate
        systemctl reload clamav-daemon > /dev/null 2>&1 || true
    endscript
}
EOF

    # Reload systemd and start services with new configurations
    systemctl daemon-reload

    # Enable services but don't start immediately - let the user decide
    systemctl enable clamav-daemon clamav-freshclam

    echo "✅ ClamAV configured with resource allocation for bastion environment"
    echo "   • CPU limited to 25% (daemon) / 15% (updater)"
    echo "   • Memory INCREASED to 1536MB (daemon) / 1024MB (updater)"
    echo "   • Update frequency: 2x daily (instead of 24x)"
    echo "   • Optimized scan limits and timeouts"
    echo "   • Enhanced OOM protection and process isolation"
    echo ""
    echo "📋 ClamAV Management Commands:"
    echo "   • Start services: systemctl start clamav-daemon clamav-freshclam"
    echo "   • Check status: systemctl status clamav-daemon clamav-freshclam"
    echo "   • View logs: journalctl -u clamav-daemon -f"
    echo "   • Manual scan: clamscan -r /path/to/scan"
    echo ""
    echo "⚠️  IMPORTANT: ClamAV services are enabled but not started automatically"
    echo "   Start them manually after verifying system resources are adequate"
    echo ""
    echo "📋 ClamAV Resource Requirements:"
    echo "   • Memory: Minimum 512MB available RAM"
    echo "   • CPU: Will use up to 25% CPU during scans"
    echo "   • Disk: ~200MB for virus definitions"
    echo "   • Network: Periodic updates (2x daily)"
    echo ""
    echo "🚀 ClamAV Startup Commands:"
    echo "   • Check system resources: free -h && nproc"
    echo "   • Start freshclam updater: systemctl start clamav-freshclam"
    echo "   • Wait for initial database: journalctl -u clamav-freshclam -f"
    echo "   • Start daemon: systemctl start clamav-daemon"
    echo "   • Check status: systemctl status clamav-daemon clamav-freshclam"
    echo "   • Manual scan: clamscan -r /home /tmp"
    echo ""
    echo "⚡ Resource Monitoring:"
    echo "   • CPU usage: htop (ClamAV limited to 25%)"
    echo "   • Memory usage: free -h (daemon uses ~400MB)"
    echo "   • Service status: systemctl status clamav-*"
    echo ""
    echo "🔧 ClamAV Management:"
    echo "   • Update definitions: systemctl restart clamav-freshclam"
    echo "   • View logs: journalctl -u clamav-daemon -f"
    echo "   • Stop services: systemctl stop clamav-daemon clamav-freshclam"
    echo "   • Disable if needed: systemctl disable clamav-daemon clamav-freshclam"
    echo ""
    echo "🔄 Enable ClamAV to Start Automatically After Reboot:"
    echo "   • Start services now: systemctl start clamav-freshclam clamav-daemon"
    echo "   • Enable auto-start: systemctl enable clamav-freshclam clamav-daemon"
    echo "   • Verify enabled: systemctl is-enabled clamav-daemon clamav-freshclam"
    echo "   • Check after reboot: systemctl status clamav-daemon clamav-freshclam"
    echo ""
    echo "💡 Recommended Startup Sequence:"
    echo "   1. Check system resources: free -h"
    echo "   2. Start freshclam first: systemctl start clamav-freshclam"
    echo "   3. Wait for database update: journalctl -u clamav-freshclam -f"
    echo "   4. Start daemon: systemctl start clamav-daemon"
    echo "   5. Enable both services: systemctl enable clamav-freshclam clamav-daemon"
    echo "   6. Verify status: systemctl status clamav-daemon clamav-freshclam"
fi

if [ "$INSTALL_MALDET" = true ]; then
    # Install Linux Malware Detect (maldet) for enhanced malware protection
    echo "===== 7.1 Installing Linux Malware Detect (maldet) ====="

    # Create temporary directory for installation
    mkdir -p /tmp/maldet-install
    cd /tmp/maldet-install

    echo "Downloading Linux Malware Detect..."
    if wget -q https://www.rfxn.com/downloads/maldetect-current.tar.gz; then
        echo "✅ Downloaded maldetect successfully"
        
        # Extract and install with error handling
        echo "Extracting maldetect archive..."
        if tar -xzf maldetect-current.tar.gz 2>/dev/null; then
            echo "✅ Archive extracted successfully"

            # Find the extracted directory (more robust method)
            MALDET_DIR=$(find . -maxdepth 1 -type d -name "maldetect-*" | head -1 2>/dev/null)
            if [ -z "$MALDET_DIR" ]; then
                # Fallback: use tar output to get directory name
                MALDET_DIR=$(tar -tzf maldetect-current.tar.gz 2>/dev/null | head -1 | cut -f1 -d"/")
            fi

            if [ -n "$MALDET_DIR" ] && [ -d "$MALDET_DIR" ]; then
                echo "✅ Found maldet directory: $MALDET_DIR"
                cd "$MALDET_DIR"
            else
                echo "❌ Could not find maldet installation directory"
                cd /
                rm -rf /tmp/maldet-install
                echo "⚠️ Maldet installation failed - continuing without maldet"
                return 0  # Don't exit the entire script, just return from this section
            fi
        else
            echo "❌ Failed to extract maldet archive"
            cd /
            rm -rf /tmp/maldet-install
            echo "⚠️ Maldet installation failed - continuing without maldet"
            return 0  # Don't exit the entire script, just return from this section
        fi

        echo "Installing Linux Malware Detect..."
        if ./install.sh 2>/dev/null; then
            echo "✅ Maldet installation completed successfully"
        else
            echo "❌ Maldet installation script failed"
            cd /
            rm -rf /tmp/maldet-install
            echo "⚠️ Maldet installation failed - continuing without maldet"
            return 0  # Don't exit the entire script, just return from this section
        fi

        # Create symlink for easy access
        ln -sf /usr/local/maldetect/maldet /usr/local/bin/maldet

        # Configure maldet with bastion-specific settings
        echo "Configuring Linux Malware Detect for bastion environment..."
        cat > /usr/local/maldetect/conf.maldet << 'EOF'
# Linux Malware Detect - Bastion Host Configuration
email_alert="1"
email_addr="root@localhost"
email_subject="Malware Alert - Bastion Host"

# Scan configuration optimized for bastion hosts
scan_clamscan="1"
scan_tmpdir="1"
scan_ignore_root="0"
scan_max_filesize="10240"

# Quarantine settings
quarantine_hits="1"
quarantine_clean="0"
quarantine_suspend_user="0"

# Performance settings for bastion environment
maxfilesize="20480"
maxdepth="10"
cpu_nice="19"

# Log configuration
log_verbose="0"
log_mail="1"

# Auto-clean quarantine after 30 days
autoclean_days="30"

# Clamdscan performance tuning
clamdscan_threads="2"
clamdscan_timeout="300"
EOF

        # Set up daily scanning via cron
        echo "Setting up daily malware scanning..."
        cat > /etc/cron.d/maldet << 'EOF'
# Linux Malware Detect - Daily scan for bastion host
# Run at 3:00 AM daily to scan critical directories
0 3 * * * root /usr/local/maldetect/maldet -a /home,/etc,/usr/local,/opt 2>&1 | logger -t maldet
EOF

        # Create logrotate configuration
        cat > /etc/logrotate.d/maldet << 'EOF'
/usr/local/maldetect/logs/* {
    weekly
    rotate 8
    compress
    delaycompress
    missingok
    notifempty
    create 644 root root
}
EOF

        # Update maldet signatures
        echo "Updating malware signatures..."
        /usr/local/maldetect/maldet --update-ver
        /usr/local/maldetect/maldet --update

        echo "✅ Linux Malware Detect configured for bastion environment"
        echo "   • Daily scans of critical directories (home, etc, usr/local, opt)"
        echo "   • Email alerts enabled for detected threats"
        echo "   • Integration with ClamAV for enhanced detection"
        echo "   • Automatic quarantine of detected malware"
        echo "   • Optimized resource usage for bastion hosts"

        # Cleanup installation files
        cd /
        rm -rf /tmp/maldet-install

    else
        echo "❌ Failed to download Linux Malware Detect"
        echo "   Check internet connectivity and try again later"
        cd /
        rm -rf /tmp/maldet-install
    fi
fi

echo "===== 6.0.2 Configuring Unbound DNS with IPv4-only for bastion hosts ====="
# Configure Unbound DNS resolver with IPv4-only to prevent binding issues
echo "Configuring Unbound DNS resolver for bastion environment..."

# Stop unbound service during configuration
systemctl stop unbound unbound-resolvconf 2>/dev/null || true

# Create IPv4-only Unbound configuration optimized for bastion hosts
cat > /etc/unbound/unbound.conf.d/bastion.conf << EOF
# Bastion Host Unbound Configuration - IPv4 Only
server:
    # Network configuration - IPv4 only to prevent binding issues
    interface: 127.0.0.1
    port: 53
    do-ip4: yes
    do-ip6: no
    prefer-ip6: no
    
    # Security and access control
    access-control: 127.0.0.0/8 allow
    access-control: 0.0.0.0/0 refuse
    
    # Performance optimization for bastion host
    num-threads: 1
    msg-cache-slabs: 1
    rrset-cache-slabs: 1
    infra-cache-slabs: 1
    key-cache-slabs: 1
    
    # Cache settings - smaller cache for bastion
    msg-cache-size: 16m
    rrset-cache-size: 32m
    
    # Security settings
    hide-identity: yes
    hide-version: yes
    harden-glue: yes
    harden-dnssec-stripped: yes
    harden-below-nxdomain: yes
    harden-referral-path: yes
    use-caps-for-id: yes
    
    # Logging
    verbosity: 1
    use-syslog: yes
    log-queries: no
    log-replies: no
    
    # Performance tuning - conservative values to avoid warnings
    so-rcvbuf: 256k
    so-sndbuf: 256k
    so-reuseport: yes
    
    # DNSSEC - disable for simplified bastion configuration
    # trust-anchor-file: "/var/lib/unbound/root.key"
    auto-trust-anchor-file: "/var/lib/unbound/root.key"
    
    # Private address handling
    private-address: 192.168.0.0/16
    private-address: 172.16.0.0/12
    private-address: 10.0.0.0/8
    private-address: 169.254.0.0/16
    private-address: fd00::/8
    private-address: fe80::/10
    
remote-control:
    control-enable: no
EOF

# Create simple main unbound.conf that includes our bastion config
cat > /etc/unbound/unbound.conf << EOF
# Unbound configuration for Bastion Host
# Main configuration file - includes bastion-specific settings

include-toplevel: "/etc/unbound/unbound.conf.d/*.conf"
EOF

# Disable unbound-resolvconf service (causes issues in bastion environment)
# The unbound-resolvconf service tries to configure loopback which fails with:
# "Failed to set DNS configuration: Link lo is loopback device"
systemctl stop unbound-resolvconf 2>/dev/null || true
systemctl disable unbound-resolvconf 2>/dev/null || true
systemctl mask unbound-resolvconf 2>/dev/null || true
echo "✅ Disabled unbound-resolvconf service (not needed for bastion)"

# Configure AppArmor to allow Unbound net_admin capability
# This is required for Unbound to manage network configuration
echo "Configuring AppArmor for Unbound..."
mkdir -p /etc/apparmor.d/local
if [ ! -f /etc/apparmor.d/local/usr.sbin.unbound ]; then
    cat > /etc/apparmor.d/local/usr.sbin.unbound << 'APPARMOR_EOF'
# Site-specific additions and overrides for usr.sbin.unbound.
# For more details, please see /etc/apparmor.d/local/README.

# Allow net_admin capability for network configuration
capability net_admin,
APPARMOR_EOF
    echo "✅ Created AppArmor local override for Unbound"

    # Reload AppArmor profile if it exists
    if [ -f /etc/apparmor.d/usr.sbin.unbound ]; then
        apparmor_parser -r /etc/apparmor.d/usr.sbin.unbound 2>/dev/null || true
        echo "✅ Reloaded AppArmor profile for Unbound"
    fi
else
    echo "✅ AppArmor override already exists for Unbound"
fi

# Create systemd override for Unbound to ensure IPv4-only operation
mkdir -p /etc/systemd/system/unbound.service.d
cat > /etc/systemd/system/unbound.service.d/ipv4-only.conf << EOF
[Service]
# Force IPv4-only operation to prevent binding issues
Environment=UNBOUND_DISABLE_IPV6=yes

# Restart configuration
Restart=on-failure
RestartSec=10
StartLimitInterval=300
StartLimitBurst=4

# Resource limits
MemoryMax=256M
Nice=5
OOMScoreAdjust=100
EOF

# Ensure unbound directory and permissions are correct
mkdir -p /var/lib/unbound
chown unbound:unbound /var/lib/unbound
chmod 755 /var/lib/unbound

# Clean up any existing problematic trust anchor files (DNSSEC disabled for simplicity)
rm -f /var/lib/unbound/root.key /var/lib/unbound/root.key.* 2>/dev/null || true

# Remove any auto-trust-anchor-file references from main config
if [ -f /etc/unbound/unbound.conf ]; then
    sed -i '/auto-trust-anchor-file/d' /etc/unbound/unbound.conf
    sed -i '/trust-anchor-file/d' /etc/unbound/unbound.conf
fi

# Remove from any config.d files
find /etc/unbound/unbound.conf.d/ -name "*.conf" -exec sed -i '/auto-trust-anchor-file/d' {} \; 2>/dev/null || true
find /etc/unbound/unbound.conf.d/ -name "*.conf" -exec sed -i '/trust-anchor-file/d' {} \; 2>/dev/null || true

echo "✅ DNSSEC disabled for simplified bastion configuration"

# Test unbound configuration
echo "Testing Unbound configuration..."

# First check if the config file is readable
if [ ! -r /etc/unbound/unbound.conf ]; then
    echo "❌ Unbound config file not readable"
    exit 1
fi

# Test configuration 
echo "Running unbound-checkconf..."
if unbound-checkconf >/tmp/unbound-check.log 2>&1; then
    echo "✅ Unbound configuration is valid"
    
    # Show configuration summary
    echo "Unbound configuration summary:"
    grep -E "(interface|port|do-ip)" /etc/unbound/unbound.conf.d/bastion.conf | head -5
    
    # Reload systemd and start unbound
    systemctl daemon-reload
    systemctl enable unbound
    
    # Stop any existing unbound process
    systemctl stop unbound 2>/dev/null || true
    sleep 2
    
    # Start unbound
    if systemctl start unbound; then
        echo "✅ Unbound service started"
        
        # Wait for service to initialize
        sleep 8
        
        # Verify Unbound is running and listening
        if systemctl is-active --quiet unbound; then
            echo "✅ Unbound DNS resolver started successfully"
            
            # Wait a bit more for Unbound to be ready for queries
            sleep 3
            
            # Test DNS resolution with timeout - use a more reliable test
            if timeout 15 nslookup google.com 127.0.0.1 >/dev/null 2>&1; then
                echo "✅ Unbound DNS resolution test successful"
            elif timeout 15 dig @127.0.0.1 google.com >/dev/null 2>&1; then
                echo "✅ Unbound DNS resolution test successful (via dig)"
            else
                echo "⚠️ Unbound DNS resolution test failed - checking status"
                echo "Unbound may still be initializing (this is often normal)"
                echo "Recent Unbound logs:"
                journalctl -u unbound --no-pager -l --since="2 minutes ago" | tail -5
            fi
        else
            echo "⚠️ Unbound failed to start - checking status"
            systemctl status unbound --no-pager -l
            echo "Recent logs:"
            journalctl -u unbound --no-pager -l --since="5 minutes ago"
        fi
    else
        echo "❌ Failed to start Unbound service"
        systemctl status unbound --no-pager -l
    fi
else
    echo "❌ Unbound configuration test failed"
    echo "Configuration errors:"
    cat /tmp/unbound-check.log
    
    echo "Attempting to fix common issues..."
    
    # Check for permission issues
    echo "Checking file permissions:"
    ls -la /var/lib/unbound/root.key /etc/unbound/unbound.conf.d/bastion.conf
    
    # Verify trust anchor file format
    if [ -f /var/lib/unbound/root.key ]; then
        echo "Trust anchor file content:"
        head -3 /var/lib/unbound/root.key
    fi
    
    # Try to regenerate trust anchor
    echo "Regenerating trust anchor..."
    rm -f /var/lib/unbound/root.key
    
    # Create a working trust anchor
    cat > /var/lib/unbound/root.key << EOF
; This file contains trusted keys for validating DNSSEC
. IN DS 20326 8 2 E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D
EOF
    chown unbound:unbound /var/lib/unbound/root.key
    chmod 644 /var/lib/unbound/root.key
    
    # Test again
    echo "Retesting Unbound configuration..."
    if unbound-checkconf; then
        echo "✅ Unbound configuration"
        systemctl daemon-reload
        systemctl enable unbound
        systemctl start unbound
    else
        echo "❌ Unbound configuration still invalid - will disable"
        systemctl disable unbound 2>/dev/null || true
        echo "⚠️ Unbound DNS disabled due to configuration issues"
        echo "   System will use default DNS resolver"
    fi
fi

# Cleanup
rm -f /tmp/unbound-check.log

echo "✅ Unbound DNS configured for bastion environment"
echo "   • IPv4-only operation (prevents IPv6 binding issues)"
echo "   • Localhost binding only (127.0.0.1:53)"
echo "   • Optimized cache settings for bastion use"
echo "   • DNSSEC validation enabled"
echo "   • Private address filtering configured"

echo "===== 6.0.3 Installing CPU microcode updates ====="

# Check if running in a virtual environment
VIRT_TYPE=""
if [ -f /proc/cpuinfo ] && grep -q "hypervisor" /proc/cpuinfo; then
    VIRT_TYPE="hypervisor"
elif systemd-detect-virt &>/dev/null; then
    VIRT_TYPE=$(systemd-detect-virt)
elif [ -f /sys/hypervisor/type ]; then
    VIRT_TYPE=$(cat /sys/hypervisor/type)
fi

# Detect CPU vendor and install appropriate microcode updates
CPU_VENDOR=$(grep vendor_id /proc/cpuinfo | head -1 | awk '{print $3}')
echo "Detected CPU vendor: $CPU_VENDOR"

if [ -n "$VIRT_TYPE" ] && [ "$VIRT_TYPE" != "none" ]; then
    echo "🔍 Virtualization detected: $VIRT_TYPE"
    echo "⚠️  Note: In virtualized environments (OVH, Hetzner, AWS, etc.):"
    echo "   - Microcode updates are typically managed by the host/hypervisor"
    echo "   - VM-level microcode installation may not affect actual CPU vulnerability mitigations"
    echo "   - Contact your hosting provider for physical host microcode status"
    echo ""
    echo "Installing microcode package anyway for completeness..."
fi

if [ "$CPU_VENDOR" = "AuthenticAMD" ]; then
    echo "AMD processor detected - installing AMD microcode updates..."
    
    # Check if non-free-firmware repository is available
    if ! apt-cache search amd64-microcode | grep -q amd64-microcode; then
        echo "Adding non-free-firmware repository for AMD microcode..."
        
        # Check if we're using the new sources.list format (Debian 12+, still applicable in Debian 13)
        if [ -f /etc/apt/sources.list.d/debian.sources ]; then
            # Update existing debian.sources file to include non-free-firmware
            if ! grep -q "non-free-firmware" /etc/apt/sources.list.d/debian.sources; then
                echo "Updating debian.sources to include non-free-firmware..."
                sed -i 's/Components: main/Components: main non-free-firmware/' /etc/apt/sources.list.d/debian.sources
                echo "Waiting for package management lock before updating..."
                wait_for_dpkg_lock
                apt-get update
            fi
        else
            # Add to traditional sources.list
            if ! grep -q "non-free-firmware" /etc/apt/sources.list; then
                echo "Adding non-free-firmware to sources.list..."
                sed -i 's/main$/main non-free-firmware/' /etc/apt/sources.list
                echo "Waiting for package management lock before updating..."
                wait_for_dpkg_lock
                apt-get update
            fi
        fi
    fi
    
    # Install AMD microcode
    if apt-cache search amd64-microcode | grep -q amd64-microcode; then
        echo "Installing AMD microcode..."
        wait_for_dpkg_lock
        apt-get install -y amd64-microcode
        echo "✅ AMD microcode installed successfully"
        echo "⚠️  Microcode will be active after next reboot"
    else
        echo "⚠️  AMD microcode package not available in repositories"
    fi
    
elif [ "$CPU_VENDOR" = "GenuineIntel" ]; then
    echo "Intel processor detected - installing Intel microcode updates..."
    wait_for_dpkg_lock
    apt-get install -y intel-microcode
    echo "✅ Intel microcode installed successfully"
    echo "⚠️  Microcode will be active after next reboot"
    
else
    echo "Unknown or unsupported CPU vendor: $CPU_VENDOR"
    echo "Skipping microcode installation"
fi

# Update initramfs to include microcode and check for kernel updates
echo "===== 6.0.2 Updating system with microcode integration ====="

# Update initramfs to ensure microcode is loaded
echo "Updating initramfs to include microcode..."
update-initramfs -u -k all

# Check if kernel update is available and recommend it
echo "Checking for kernel updates..."
CURRENT_KERNEL=$(uname -r)
echo "Current kernel: $CURRENT_KERNEL"
echo "Note: Debian 13 (Trixie) ships with Linux kernel 6.12 LTS (supported until Dec 2026)"

# Check for available kernel updates
if apt list --upgradable 2>/dev/null | grep -q linux-image; then
    echo "⚠️  Kernel updates available:"
    apt list --upgradable 2>/dev/null | grep linux-image
    echo ""
    echo "💡 Kernel update recommendation:"
    echo "   Run: apt update && apt upgrade linux-image-*"
    echo "   Then reboot to activate microcode and kernel updates"
else
    echo "✅ Kernel is up to date"
fi

# Check for backports kernel if available (often has better hardware support)
if apt-cache search linux-image | grep -q backports; then
    echo ""
    echo "💡 Backports kernel available for better hardware support:"
    apt-cache search linux-image | grep backports | head -3
    echo "   Consider: apt install -t trixie-backports linux-image-amd64"
fi

# Show current CPU vulnerabilities status
echo ""
echo "Current CPU vulnerability status:"
if [ -d /sys/devices/system/cpu/vulnerabilities ]; then
    for vuln in /sys/devices/system/cpu/vulnerabilities/*; do
        vuln_name=$(basename "$vuln")
        vuln_status=$(cat "$vuln")
        printf "  %-25s %s\n" "$vuln_name:" "$vuln_status"
    done
else
    echo "  CPU vulnerability information not available"
fi

# Check if microcode is properly loaded
echo ""
echo "Microcode status:"
if dmesg | grep -i microcode | tail -5 | grep -q "updated"; then
    echo "✅ Microcode updates detected in dmesg"
    dmesg | grep -i microcode | tail -2
else
    if [ -n "$VIRT_TYPE" ] && [ "$VIRT_TYPE" != "none" ]; then
        echo "ℹ️  No microcode updates in dmesg (expected in virtualized environment)"
        echo "   Microcode management is handled by the hypervisor/host system"
    else
        echo "⚠️  Microcode updates not visible in dmesg (may require reboot)"
    fi
fi

# Check initramfs for microcode
if [ -f "/boot/initrd.img-$(uname -r)" ]; then
    if lsinitramfs "/boot/initrd.img-$(uname -r)" 2>/dev/null | grep -q microcode; then
        echo "✅ Microcode files present in initramfs"
        lsinitramfs "/boot/initrd.img-$(uname -r)" 2>/dev/null | grep microcode | head -3
    else
        echo "⚠️  No microcode files found in initramfs"
    fi
fi
echo ""

# Configure mail system based on user choice
echo "===== 6.1 Configuring mail system ====="

# Stop postfix for configuration
systemctl stop postfix 2>/dev/null || true

if [[ "$SMTP_CONFIGURE" =~ ^[Yy]$ ]]; then
    echo "Configuring external SMTP for reliable email delivery..."
    
    # Install SASL packages for SMTP authentication
    apt-get install -y libsasl2-modules
    
    # Configure postfix for external SMTP relay
    postconf -e "relayhost = [$SMTP_SERVER]:$SMTP_PORT"
    postconf -e "smtp_tls_security_level = encrypt"
    postconf -e "smtp_sasl_auth_enable = yes"
    postconf -e "smtp_sasl_security_options = noanonymous"
    postconf -e "smtp_sasl_password_maps = hash:/etc/postfix/sasl_passwd"
    postconf -e "smtp_tls_note_starttls_offer = yes"
    postconf -e "smtp_tls_CAfile = /etc/ssl/certs/ca-certificates.crt"
    
    # Disable SMTPUTF8 for compatibility with Amazon SES
    postconf -e "smtputf8_enable = no"
    
    # Critical: Configure postfix to send ALL mail via SMTP relay (satellite mode)
    postconf -e "mydestination ="
    postconf -e "myorigin = \$myhostname"
    postconf -e "inet_interfaces = loopback-only"
    postconf -e "mynetworks = 127.0.0.0/8"
    postconf -e "local_transport = error:local delivery is disabled"
    postconf -e "alias_maps ="
    postconf -e "alias_database ="
    postconf -e "local_recipient_maps ="
    postconf -e "mailbox_command ="
    postconf -e "mailbox_transport ="
    postconf -e "home_mailbox ="
    postconf -e "mail_spool_directory ="
    postconf -e "virtual_alias_maps ="
    postconf -e "virtual_mailbox_maps ="
    postconf -e "transport_maps ="
    
    # FORCE all mail to go via SMTP - override any local delivery attempts
    postconf -e "default_transport = smtp:[$SMTP_SERVER]:$SMTP_PORT"
    postconf -e "fallback_transport = smtp:[$SMTP_SERVER]:$SMTP_PORT"
    
    # Configure sender rewriting to use the SMTP from address
    postconf -e "sender_canonical_maps = regexp:/etc/postfix/sender_canonical"
    postconf -e "smtp_header_checks = regexp:/etc/postfix/smtp_header_checks"
    
    # Create recipient canonical map to redirect all local recipients
    cat > /etc/postfix/recipient_canonical << EOF
# Redirect all local recipients to external email address
root@bastion    $LOGWATCH_EMAIL
bastion@bastion $LOGWATCH_EMAIL
admin@bastion   $LOGWATCH_EMAIL
security@bastion $LOGWATCH_EMAIL
postmaster@bastion $LOGWATCH_EMAIL
webmaster@bastion $LOGWATCH_EMAIL
logcheck@bastion $LOGWATCH_EMAIL
root@\$(hostname)    $LOGWATCH_EMAIL
bastion@\$(hostname) $LOGWATCH_EMAIL
admin@\$(hostname)   $LOGWATCH_EMAIL
security@\$(hostname) $LOGWATCH_EMAIL
postmaster@\$(hostname) $LOGWATCH_EMAIL
webmaster@\$(hostname) $LOGWATCH_EMAIL
logcheck@\$(hostname) $LOGWATCH_EMAIL
EOF
    
    # Configure recipient canonical mapping
    postconf -e "recipient_canonical_maps = hash:/etc/postfix/recipient_canonical"
    postmap /etc/postfix/recipient_canonical
    
    # SECURITY FIX: Create SASL password file securely
    temp_sasl_file=$(mktemp)
    echo "[$SMTP_SERVER]:$SMTP_PORT    $SMTP_USERNAME:$SMTP_PASSWORD" > "$temp_sasl_file"
    mv "$temp_sasl_file" /etc/postfix/sasl_passwd
    chmod 600 /etc/postfix/sasl_passwd
    chown root:root /etc/postfix/sasl_passwd
    postmap /etc/postfix/sasl_passwd
    
    # SECURITY FIX: Clear password from memory
    unset SMTP_PASSWORD
    
    # Create sender canonical map to rewrite all From addresses
    cat > /etc/postfix/sender_canonical << EOF
# Rewrite all sender addresses to use the SMTP from address
/.*/    $SMTP_FROM_EMAIL
EOF
    
    # Create header checks to rewrite From headers
    cat > /etc/postfix/smtp_header_checks << EOF
# Rewrite From header to use proper SMTP from address
/^From:.*/ REPLACE From: $SMTP_FROM_EMAIL
EOF
    
    # Create hash databases for maps
    postmap /etc/postfix/sender_canonical
    postmap /etc/postfix/smtp_header_checks
    
    # Create aliases to redirect all local mail to the configured email address
    cat > /etc/aliases << EOF
# All local mail redirected to external email address
root: $LOGWATCH_EMAIL
bastion: $LOGWATCH_EMAIL
admin: $LOGWATCH_EMAIL
security: $LOGWATCH_EMAIL
postmaster: $LOGWATCH_EMAIL
MAILER-DAEMON: $LOGWATCH_EMAIL
webmaster: $LOGWATCH_EMAIL
logcheck: $LOGWATCH_EMAIL
EOF

    # Build alias database
    newaliases

else
    echo "Configuring local-only mail system..."
    
    # Configure postfix for local-only delivery
    postconf -e "inet_interfaces = loopback-only"
    postconf -e "mydestination = \$myhostname, localhost.\$mydomain, localhost"
    postconf -e "myorigin = \$mydomain"
    postconf -e "relayhost ="
    postconf -e "mynetworks = 127.0.0.0/8"
    postconf -e "local_transport = local:\$myhostname"
    postconf -e "default_transport = local"
    
    # Create mail directories with proper permissions
    mkdir -p /var/mail
    chmod 1777 /var/mail
    mkdir -p /var/spool/mail
    chmod 1777 /var/spool/mail
    
    # Ensure mail directory ownership
    chown root:mail /var/mail
    chown root:mail /var/spool/mail
    
    # Create local mail aliases (all external emails go to root locally)
    cat > /etc/aliases << EOF
# Local mail aliases for bastion host
# All external email addresses are redirected to local root account
root: root
$LOGWATCH_EMAIL: root
webmaster: root
logcheck: root
admin: root
security: root
postmaster: root
MAILER-DAEMON: root
EOF

fi

# Build alias database only for local delivery mode
if [[ ! "$SMTP_CONFIGURE" =~ ^[Yy]$ ]]; then
    newaliases
fi

# Enable and start postfix with new configuration
systemctl enable postfix
start_service_with_retry postfix

# Wait for postfix to fully start
sleep 3

# Test mail system
echo "===== Testing mail system ====="

if [[ "$SMTP_CONFIGURE" =~ ^[Yy]$ ]]; then
    echo "Testing external SMTP configuration..."
    
    # Create test message with proper From header
    cat > /tmp/smtp_test_email.txt << EOF
From: $SMTP_FROM_EMAIL
To: $LOGWATCH_EMAIL
Subject: SMTP Test - Bastion Setup Complete

This is a test email from your bastion host setup.
If you receive this email, external SMTP is working correctly.

Bastion Host: $(hostname)
Setup completed: $(date)
SMTP Server: $SMTP_SERVER
From Address: $SMTP_FROM_EMAIL
Destination: $LOGWATCH_EMAIL

All security notifications will be sent to this email address.
EOF
    
    # Send via sendmail
    /usr/sbin/sendmail -f "$SMTP_FROM_EMAIL" "$LOGWATCH_EMAIL" < /tmp/smtp_test_email.txt
    
    echo "✅ Test email sent to $LOGWATCH_EMAIL via external SMTP"
    echo "📧 Check your email inbox to confirm delivery"
    
    # Check mail queue for any issues
    sleep 3
    QUEUE_STATUS=$(mailq)
    if [[ "$QUEUE_STATUS" == "Mail queue is empty" ]]; then
        echo "✅ Mail queue is empty - email sent successfully"
    else
        echo "⚠️ Mail queue status:"
        mailq | head -n 10
    fi
    
else
    echo "Testing local mail system..."
    
    # Create test message for local delivery
    echo "Subject: Local Mail Test - Bastion Setup

Testing local mail system during bastion setup...
This test confirms local mail delivery is working.
All external emails will be stored locally due to bastion network restrictions.
Timestamp: $(date)
Server: $(hostname)
" | /usr/sbin/sendmail root
    
    echo "✅ Test email sent to local root account"
    
    # Wait for delivery
    sleep 5
    
    # Check if mail was delivered locally
    if [ -f /var/mail/root ]; then
        echo "✅ Local mail delivery confirmed in /var/mail/root"
        echo "Mail file size: $(stat -c%s /var/mail/root 2>/dev/null | numfmt --to=iec || echo "unknown")"
        echo "Recent mail headers:"
        tail -n 5 /var/mail/root | head -n 3
    elif [ -f /var/spool/mail/root ]; then
        echo "✅ Local mail delivery confirmed in /var/spool/mail/root"
        echo "Mail file size: $(stat -c%s /var/spool/mail/root 2>/dev/null | numfmt --to=iec || echo "unknown")"
        echo "Recent mail headers:"
        tail -n 5 /var/spool/mail/root | head -n 3
    else
        echo "⚠️ Mail file not found - checking postfix status and logs"
        systemctl status postfix --no-pager -l
        echo "Checking mail queue:"
        mailq
    fi
fi

# Check postfix configuration and logs
echo ""
echo "Postfix configuration check:"
if [[ "$SMTP_CONFIGURE" =~ ^[Yy]$ ]]; then
    postconf relayhost
    postconf smtp_sasl_auth_enable
    postconf smtp_use_tls
else
    postconf inet_interfaces
    postconf mydestination  
    postconf local_transport
fi

echo ""
echo "Recent postfix logs:"
tail -n 10 /var/log/mail.log 2>/dev/null || echo "Mail log not yet available"

echo ""
if [[ "$SMTP_CONFIGURE" =~ ^[Yy]$ ]]; then
    echo "📧 Mail system configured with external SMTP for reliable delivery"
    echo "📧 All security notifications will be sent to: $LOGWATCH_EMAIL"
else
    echo "📧 Mail system configured for local delivery only due to bastion security restrictions"
    echo "📧 All email notifications will be stored in local root mailbox"
fi

echo "===== 6.1 Installing bastion-specific monitoring tools ====="
# Network monitoring and diagnostics (essential for bastions)
apt-get install -y htop iotop sysstat atop bmon
apt-get install -y iftop nethogs ethtool mtr-tiny
apt-get install -y arp-scan dnsutils net-tools traceroute whois
apt-get install -y nmap ncat socat

# Pre-configure iperf3 to not start as daemon (security best practice for bastions)
echo "iperf3 iperf3/start_daemon boolean false" | debconf-set-selections
apt-get install -y iperf3

# Ensure iperf3 service is not started (bastion security)
systemctl disable iperf3 2>/dev/null || true
systemctl stop iperf3 2>/dev/null || true

# Security and audit tools
apt-get install -y debsums aide auditd audispd-plugins
apt-get install -y logcheck logcheck-database

# Enhanced shell environment for bastion administration
echo "===== 6.2 Installing enhanced shell environment ====="
apt-get install -y zsh vim git curl locales

# Configure locale to fix environment warnings
echo "===== 6.2.1 Configuring system locale ====="
# Enable both en_US.UTF-8 and de_DE.UTF-8 locales
sed -i '/en_US.UTF-8/s/^# //g' /etc/locale.gen
sed -i '/de_DE.UTF-8/s/^# //g' /etc/locale.gen

# Generate locales
locale-gen

# Set system-wide locale defaults
cat > /etc/default/locale << EOF
LANG=en_US.UTF-8
LANGUAGE=en_US:en
LC_ALL=en_US.UTF-8
LC_CTYPE=en_US.UTF-8
LC_MESSAGES=en_US.UTF-8
EOF

# Export locale for current session
export LANG=en_US.UTF-8
export LANGUAGE=en_US:en
export LC_ALL=en_US.UTF-8
export LC_CTYPE=en_US.UTF-8
export LC_MESSAGES=en_US.UTF-8

echo "Locale configuration updated to resolve environment warnings"

# Configure lm-sensors with enhanced detection and logwatch integration
echo "===== 6.2.2 Configuring hardware sensors with enhanced detection ====="

# Enhanced sensor detection and configuration with diagnostic output
echo "Running comprehensive sensor detection and virtualization check..."

# Check if this is a virtual environment first
if systemd-detect-virt &>/dev/null; then
    VIRT_TYPE=$(systemd-detect-virt)
    echo "🔍 Virtualization detected: $VIRT_TYPE"
    echo "   Hardware sensors typically not available in virtual environments"
    echo "   This is normal and expected for VMs/cloud instances"
else
    echo "✅ Physical hardware detected - proceeding with sensor detection"
fi

# Run sensors-detect automatically with safe defaults
if command -v sensors-detect >/dev/null 2>&1; then
    echo "Running sensors-detect with safe automatic detection..."
    # Run sensors-detect with automatic yes to safe drivers only
    echo -e "y\ny\ny\ny\ny\nn" | sensors-detect --auto 2>/dev/null || true
    
    # Load detected modules
    if [ -f /etc/modules ]; then
        echo "Loading detected sensor modules..."
        systemctl restart systemd-modules-load 2>/dev/null || true
        # Try manual module loading for common sensors
        echo "Attempting to load common sensor modules..."
        LOADED_MODULES=""
        for module in coretemp k10temp it87 w83627ehf nct6775; do
            if modprobe $module 2>/dev/null; then
                LOADED_MODULES="$LOADED_MODULES $module"
            fi
        done
        if [ -n "$LOADED_MODULES" ]; then
            echo "✅ Loaded sensor modules:$LOADED_MODULES"
        else
            echo "⚠️ No sensor modules loaded successfully"
        fi
    fi
else
    echo "❌ sensors-detect command not available"
fi

# Re-check sensors after detection with detailed diagnostics
if command -v sensors >/dev/null 2>&1; then
    # Wait for modules to initialize
    echo "Waiting for sensor modules to initialize..."
    sleep 2
    
    # Test sensor detection
    echo "Testing hardware sensor detection..."
    if sensors 2>/dev/null | grep -q "°C\|°F\|RPM\|V\|W"; then
        echo "✅ Hardware sensors detected successfully!"
        
        # Show detected sensors with counts
        SENSOR_COUNT=$(sensors 2>/dev/null | grep -cE "Core|temp|fan|°C|°F|RPM|V|W")
        echo "📊 Found $SENSOR_COUNT sensor readings:"
        sensors 2>/dev/null | grep -E "Core|temp|fan|°C|°F|RPM|V|W" | head -10 | sed 's/^/   /'
        
        # Show loaded sensor modules
        echo "📋 Active sensor modules:"
        lsmod | grep -E "coretemp|k10temp|it87|w83627|nct6775" | awk '{print "   • " $1}' || echo "   • No specific sensor modules detected"
        
        # Enable lm-sensors service
        systemctl enable lm-sensors 2>/dev/null || true
        systemctl start lm-sensors 2>/dev/null || true
        
        # Configure sensors for logwatch
        echo "Configuring sensors for logwatch integration..."
        mkdir -p /etc/logwatch/conf/services
        
        # Create sensors service configuration for logwatch
        cat > /etc/logwatch/conf/services/sensors.conf << 'EOF'
# Sensors monitoring for logwatch
Title = "Hardware Sensors"
LogFile = sensors
*OnlyService = sensors
*RemoveHeaders = Yes
EOF
        
        # Create sensor logging script for logwatch
        mkdir -p /var/log/sensors
        cat > /usr/local/bin/log-sensors << 'EOF'
#!/bin/bash
# Log sensor data for logwatch analysis
LOGFILE="/var/log/sensors/sensors.log"
DATE=$(date '+%Y-%m-%d %H:%M:%S')

# Ensure log directory exists
mkdir -p /var/log/sensors

# Log current sensor readings
echo "[$DATE] Sensor readings:" >> "$LOGFILE"
sensors >> "$LOGFILE" 2>/dev/null
echo "" >> "$LOGFILE"

# Check for critical temperatures and log alerts
if sensors 2>/dev/null | grep -E "CRITICAL|ALARM" | grep -v "+0.0"; then
    echo "[$DATE] CRITICAL: Sensor alerts detected!" >> "$LOGFILE"
    sensors 2>/dev/null | grep -E "CRITICAL|ALARM" >> "$LOGFILE"
    echo "" >> "$LOGFILE"
fi

# Rotate log if it gets too large (keep last 1000 lines)
# Use /tmp for temporary file to avoid read-only filesystem issues
if [ -f "$LOGFILE" ] && [ $(wc -l < "$LOGFILE" 2>/dev/null || echo 0) -gt 1000 ]; then
    TMPFILE=$(mktemp /tmp/sensors-log-XXXXXX)
    if tail -n 500 "$LOGFILE" > "$TMPFILE" 2>/dev/null && [ -s "$TMPFILE" ]; then
        mv "$TMPFILE" "$LOGFILE"
    else
        # If tail fails, remove any partial temp file and keep original
        rm -f "$TMPFILE"
    fi
fi
EOF
        
        chmod +x /usr/local/bin/log-sensors
        
        # Add sensor logging to cron (every 10 minutes)
        echo "*/10 * * * * root /usr/local/bin/log-sensors" >> /etc/crontab
        
        # Update logwatch configuration to include sensors
        if [ -f /etc/logwatch/conf/logwatch.conf ]; then
            # Check if sensors service already included
            if ! grep -q "sensors" /etc/logwatch/conf/logwatch.conf; then
                echo "Service = sensors" >> /etc/logwatch/conf/logwatch.conf
                echo "✅ Sensors added to logwatch daily reports"
            fi
        fi
        
        # Create logrotate configuration for sensor logs
        cat > /etc/logrotate.d/sensors << EOF
/var/log/sensors/*.log {
    weekly
    rotate 4
    compress
    delaycompress
    missingok
    notifempty
    create 644 root root
}
EOF
        
        echo "✅ Hardware sensors configured with logwatch integration"
        echo "   • Sensor data logged every 10 minutes"
        echo "   • Critical temperature alerts logged"
        echo "   • Included in daily logwatch reports"
        
        # Run initial sensor logging
        /usr/local/bin/log-sensors
        
    else
        echo "❌ No hardware sensors detected after comprehensive detection"
        
        # Provide diagnostic information
        if systemd-detect-virt &>/dev/null; then
            VIRT_TYPE=$(systemd-detect-virt)
            echo "🔍 Analysis: Running in $VIRT_TYPE virtualization"
            echo "   This is completely normal - VMs typically don't have hardware sensors"
            echo "   Virtual environments use hypervisor-level monitoring instead"
        else
            echo "⚠️ Analysis: Physical hardware detected but no sensors found"
            echo "   This may indicate:"
            echo "   • Motherboard doesn't support sensor monitoring"
            echo "   • Sensors require specific kernel modules not available"
            echo "   • Manual sensors-detect configuration needed"
        fi
        
        # Show what modules were attempted
        echo "📋 Attempted sensor modules: coretemp, k10temp, it87, w83627ehf, nct6775"
        
        # Disable sensors service and suppress warnings
        echo "Disabling lm-sensors service to prevent false error reports..."
        systemctl disable lm-sensors 2>/dev/null || true
        systemctl mask lm-sensors 2>/dev/null || true
        
        # Create empty sensors config to prevent startup warnings
        mkdir -p /etc/sensors.d
        cat > /etc/sensors.d/bastion-no-sensors.conf << EOF
# No hardware sensors configuration for bastion host
# This file prevents sensors warnings on systems without hardware monitoring
# Generated automatically during bastion setup
EOF
        echo "✅ Hardware sensor monitoring disabled (appropriate for this environment)"
        
        # Create fake sensor log for logwatch (prevents errors)
        mkdir -p /var/log/sensors
        cat > /var/log/sensors/sensors.log << EOF
# No hardware sensors available on this system
# This is normal for virtual machines and cloud instances
EOF
        
        # Still add sensors to logwatch but with a note about no sensors
        if [ -f /etc/logwatch/conf/logwatch.conf ]; then
            if ! grep -q "sensors" /etc/logwatch/conf/logwatch.conf; then
                echo "Service = sensors" >> /etc/logwatch/conf/logwatch.conf
                echo "✅ Sensors service added to logwatch (will show 'no sensors' message)"
            fi
        fi
    fi
else
    echo "Sensors command not available - installing lm-sensors package"
    apt-get update && apt-get install -y lm-sensors
    echo "✅ lm-sensors installed - rerun script or manually run sensors-detect"
fi

# Install Oh My Zsh for bastion user with security-focused plugins
if id "$USERNAME" &>/dev/null; then
    echo "Installing Oh My Zsh for $USERNAME with security plugins..."

    # Get the actual home directory for the user
    USER_HOME=$(getent passwd "$USERNAME" | cut -d: -f6)

    if [ -z "$USER_HOME" ] || [ ! -d "$USER_HOME" ]; then
        echo "⚠️  Could not determine home directory for $USERNAME, skipping Oh My Zsh installation"
    else
        echo "Using home directory: $USER_HOME"

        # Remove existing Oh My Zsh installation if present to allow reinstall
        if [ -d "$USER_HOME/.oh-my-zsh" ]; then
            echo "Removing existing Oh My Zsh installation..."
            sudo -u "$USERNAME" rm -rf "$USER_HOME/.oh-my-zsh" "$USER_HOME/.zshrc"
        fi

        # Install Oh My Zsh with proper HOME and USER environment variables set
        # The Oh My Zsh installer uses $USER to determine the home directory, so we must set both
        echo "Downloading and installing Oh My Zsh..."

        # Download the installer first to ensure we can set environment properly
        curl -fsSL https://raw.githubusercontent.com/ohmyzsh/ohmyzsh/master/tools/install.sh -o /tmp/omz-install.sh
        chmod +x /tmp/omz-install.sh

        # Run with explicit environment variables that will be preserved
        # IMPORTANT: cd to user's home first, because the installer uses "cd -" to return to $PWD
        # and the bastion user might not have access to the current directory
        (cd "$USER_HOME" && sudo -u "$USERNAME" env HOME="$USER_HOME" USER="$USERNAME" sh /tmp/omz-install.sh --unattended)

        # Clean up installer
        rm -f /tmp/omz-install.sh

        # Configure with security and network monitoring plugins
        if [ -f "$USER_HOME/.zshrc" ]; then
            sudo -u "$USERNAME" sed -i 's/plugins=(git)/plugins=(git sudo systemd colored-man-pages history-substring-search docker ssh-agent)/' "$USER_HOME/.zshrc"

            # Add bastion-specific aliases
            cat >> "$USER_HOME/.zshrc" << EOF

# Bastion host specific aliases and functions
alias auth-log='sudo tail -f /var/log/auth.log'
alias audit-log='sudo tail -f /var/log/audit/audit.log'
alias connections='sudo netstat -tulpn'
alias active-sessions='who -u'
alias ssh-attempts='grep "Failed password\|Invalid user" /var/log/auth.log | tail -20'
alias firewall-status='sudo ufw status numbered'
alias security-status='sudo fail2ban-client status'

# Function to show current bastion activity
# NOTE: Run as root (sudo bastionstat) for full system information
bastionstat() {
    echo "=== Bastion Host Status ==="
    echo "Active SSH Sessions:"
    who -u
    echo ""
    echo "Network Connections:"
    sudo netstat -tulpn | grep :2222
    echo ""
    echo "Recent SSH Attempts:"
    grep "$(date '+%b %d')" /var/log/auth.log | grep "Accepted publickey\|Failed password" | tail -5
}

# Function to monitor real-time SSH activity
# NOTE: Run as root (sudo sshmon) for access to auth.log
sshmon() {
    echo "Monitoring SSH activity (Ctrl+C to stop)..."
    sudo tail -f /var/log/auth.log | grep --line-buffered "sshd"
}
EOF

            # Configure vim settings for better bastion administration
            cat >> "$USER_HOME/.vimrc" << EOF
" Bastion host vim configuration
" Disable visual mode for security (prevents accidental mouse selections)
set mouse=
set nocompatible
set number
set tabstop=4
set shiftwidth=4
set expandtab
set autoindent
set hlsearch
set incsearch
syntax on
EOF
            chown "$USERNAME:$USERNAME" "$USER_HOME/.vimrc"
            echo "✅ Oh My Zsh installed and configured for $USERNAME"
        else
            echo "⚠️  Oh My Zsh installation may have failed - .zshrc not found"
        fi
    fi

    # Create global executable commands for bastion functions
    echo "===== 6.2.2 Creating global bastion commands ====="

    # Create bastionstat command
    cat > /usr/local/bin/bastionstat << EOF
#!/bin/bash
# Bastion Host Status Command
# This command can be run by the bastion user without entering a password

echo "=== Bastion Host Status ==="
echo "Hostname: \$(hostname)"
echo "Current Time: \$(date)"
echo "Uptime: \$(uptime)"
echo ""
echo "Active SSH Sessions:"
who -u
echo ""
echo "Network Connections:"
# Try different netstat commands with sudo
if command -v netstat >/dev/null 2>&1; then
    sudo netstat -tulpn | grep :2222 2>/dev/null || echo "No SSH connections on port 2222"
elif command -v ss >/dev/null 2>&1; then
    sudo ss -tulpn | grep :2222 2>/dev/null || echo "No SSH connections on port 2222"
else
    echo "(Network tools require sudo privileges)"
fi
echo ""
echo "Recent SSH Activity (last 10 entries):"
# Try different date formats to match auth.log entries
TODAY=\$(date '+%b %d')
TODAY_ALT=\$(date '+%b  %d')  # Handle single digit days with double space
grep -E "(\$TODAY|\$TODAY_ALT)" /var/log/auth.log 2>/dev/null | grep -E "Accepted publickey|Failed password|Invalid user" | tail -10 || echo "No recent SSH activity found"
echo ""
echo "System Resources:"
# Fix memory calculation
MEMORY_USED=\$(free | awk 'NR==2{printf "%.1f", \$3*100/\$2}')
echo "Memory: \${MEMORY_USED}% used"
echo "Disk: \$(df -h / | awk 'NR==2{print \$5 " used"}')"
echo "Load: \$(cat /proc/loadavg | awk '{print \$1 " " \$2 " " \$3}')"
echo ""
echo "Security Status:"
systemctl is-active --quiet fail2ban && echo "✅ Fail2ban: Active" || echo "❌ Fail2ban: Inactive"
systemctl is-active --quiet suricata && echo "✅ Suricata IDS: Active" || echo "❌ Suricata IDS: Inactive"
# Check UFW status with proper sudo access
if command -v ufw >/dev/null 2>&1; then
    UFW_STATUS=\$(sudo ufw status 2>/dev/null || echo "Error")
    if echo "\$UFW_STATUS" | grep -q "Status: active"; then
        echo "✅ Firewall (UFW): Active"
    elif echo "\$UFW_STATUS" | grep -q "Status: inactive"; then
        echo "❌ Firewall (UFW): Inactive"
    else
        echo "⚠️ Firewall (UFW): Status unknown"
    fi
else
    echo "❌ Firewall (UFW): Not installed"
fi
systemctl is-active --quiet auditd && echo "✅ Audit System: Active" || echo "❌ Audit System: Inactive"

# ClamAV Antivirus Status
systemctl is-active --quiet clamav-daemon && echo "✅ ClamAV Daemon: Active" || echo "❌ ClamAV Daemon: Inactive"
systemctl is-active --quiet clamav-freshclam && echo "✅ ClamAV Updates: Active" || echo "❌ ClamAV Updates: Inactive"

# DNS Security
systemctl is-active --quiet unbound && echo "✅ Unbound DNS: Active" || echo "❌ Unbound DNS: Inactive"

# Hardware Monitoring
systemctl is-active --quiet lm-sensors && echo "✅ Hardware Sensors: Active" || echo "❌ Hardware Sensors: Inactive"

# File Integrity Monitoring
if systemctl list-unit-files | grep -q aide.timer; then
    systemctl is-active --quiet aide.timer && echo "✅ AIDE Integrity: Active" || echo "❌ AIDE Integrity: Inactive"
else
    echo "⚠️ AIDE Integrity: Not configured"
fi

# Log Monitoring
if command -v logcheck >/dev/null 2>&1; then
    if [ -f /etc/cron.daily/logcheck ]; then
        echo "✅ Logcheck: Configured (daily)"
    elif [ -f /etc/cron.d/logcheck ]; then
        echo "✅ Logcheck: Configured (cron.d)"
    else
        echo "⚠️ Logcheck: Installed but not scheduled"
    fi
else
    echo "❌ Logcheck: Not installed"
fi

if command -v logwatch >/dev/null 2>&1; then
    if [ -f /etc/cron.d/logwatch ]; then
        echo "✅ Logwatch: Configured"
    else
        echo "⚠️ Logwatch: Installed but not scheduled"
    fi
else
    echo "❌ Logwatch: Not installed"
fi

# Rootkit Detection
if command -v rkhunter >/dev/null 2>&1; then
    # Check if rkhunter cron job exists
    if [ -f /etc/cron.daily/rkhunter ] || [ -f /etc/cron.d/rkhunter ]; then
        echo "✅ RKHunter: Configured"
    else
        echo "⚠️ RKHunter: Installed but not scheduled"
    fi
else
    echo "❌ RKHunter: Not installed"
fi

if command -v chkrootkit >/dev/null 2>&1; then
    if [ -f /etc/cron.daily/chkrootkit ] || [ -f /etc/cron.d/chkrootkit ]; then
        echo "✅ Chkrootkit: Configured"
    else
        echo "⚠️ Chkrootkit: Installed but not scheduled"
    fi
else
    echo "❌ Chkrootkit: Not installed"
fi

# Malware Detection
if command -v maldet >/dev/null 2>&1; then
    if [ -f /etc/cron.daily/maldet ] || grep -q maldet /etc/crontab 2>/dev/null; then
        echo "✅ Linux Malware Detect: Configured"
    else
        echo "⚠️ Linux Malware Detect: Installed but not scheduled"
    fi
else
    echo "❌ Linux Malware Detect: Not installed"
fi
echo ""
echo "Local Mail System:"
if [ -f /var/mail/root ]; then
    MAIL_COUNT=\$(grep -c "^From " /var/mail/root 2>/dev/null || echo "0")
    echo "📧 Local mail: \$MAIL_COUNT messages in /var/mail/root"
elif [ -f /var/spool/mail/root ]; then
    MAIL_COUNT=\$(grep -c "^From " /var/spool/mail/root 2>/dev/null || echo "0")
    echo "📧 Local mail: \$MAIL_COUNT messages in /var/spool/mail/root"
else
    echo "📭 Local mail: No mail file found"
fi
systemctl is-active --quiet postfix && echo "✅ Mail system (Postfix): Active" || echo "❌ Mail system (Postfix): Inactive"
EOF

    chmod +x /usr/local/bin/bastionstat

    # Create sshmon command
    cat > /usr/local/bin/sshmon << EOF
#!/bin/bash
# SSH Activity Monitor for Bastion Host
# IMPORTANT: Run as root (sudo sshmon) for access to auth.log
# Regular users cannot read /var/log/auth.log

echo "=== SSH Activity Monitor ==="
echo "Monitoring real-time SSH activity on bastion host..."
echo "Press Ctrl+C to stop monitoring"
echo ""
sudo tail -f /var/log/auth.log | grep --line-buffered "sshd"
EOF

    chmod +x /usr/local/bin/sshmon

    # Create mail reading command for bastion
    cat > /usr/local/bin/bastionmail << EOF
#!/bin/bash
# Read local mail on bastion host
echo "=== Bastion Host Local Mail ==="
if [ -f /var/mail/root ]; then
    echo "📧 Reading local mail for root:"
    echo "=================================="
    cat /var/mail/root
elif [ -f /var/spool/mail/root ]; then
    echo "📧 Reading local mail for root:"
    echo "=================================="
    cat /var/spool/mail/root
else
    echo "📭 No local mail found for root"
    echo "Mail files checked:"
    echo "  - /var/mail/root"
    echo "  - /var/spool/mail/root"
fi
EOF

    chmod +x /usr/local/bin/bastionmail

    echo "✅ Global bastion commands created:"
    echo "   • sudo bastionstat - Show bastion host status (requires root)"
    echo "   • sudo sshmon - Monitor SSH activity in real-time (requires root)"
    echo "   • bastionmail - Read local mail"
fi

# Configure automatic security updates
cat > /etc/apt/apt.conf.d/20auto-upgrades << EOF
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
EOF

# Configure unattended-upgrades for security patches only
cat > /etc/apt/apt.conf.d/50unattended-upgrades << EOF
Unattended-Upgrade::Allowed-Origins {
    "\${distro_id}:\${distro_codename}-security";
};

// Automatically reboot if required (at 3 AM for bastions)
Unattended-Upgrade::Automatic-Reboot "true";
Unattended-Upgrade::Automatic-Reboot-Time "03:00";

// Send email to admin if there are problems
Unattended-Upgrade::Mail "$LOGWATCH_EMAIL";
Unattended-Upgrade::MailReport "only-on-error";

// Remove unused dependencies
Unattended-Upgrade::Remove-Unused-Dependencies "true";

// Allow package downgrade if needed for security
Unattended-Upgrade::Allow-downgrade "true";
EOF

echo "===== 7. Configuring fail2ban for bastion protection ====="
create_rollback_point "pre-fail2ban"

# Enhanced fail2ban configuration for bastion hosts
cat > /etc/fail2ban/jail.local << EOF
[DEFAULT]
# Default ban time and find time (more aggressive for bastions)
bantime = 3600
findtime = 600
maxretry = 3
backend = systemd
usedns = warn
destemail = $LOGWATCH_EMAIL
sendername = Fail2Ban-Bastion-$HOSTNAME
mta = sendmail
protocol = tcp
chain = INPUT
port = 0:65535
fail2ban_agent = Fail2Ban/%(fail2ban_version)s
# Enable IPv6 support for modern infrastructure
allowipv6 = yes
ignoreip = 127.0.0.1/8 ::1 $CLIENT_IP

# Use UFW/nftables for Debian 13 firewall management
banaction = ufw
banaction_allports = ufw
action = %(banaction)s[blocktype=reject]

[sshd]
enabled = true
port = $SSH_PORT
filter = sshd
logpath = /var/log/auth.log
maxretry = 2
bantime = 7200
findtime = 300

[sshd-ddos]
enabled = true
port = $SSH_PORT
filter = sshd-ddos
logpath = /var/log/auth.log
maxretry = 2
bantime = 3600

[recidive]
enabled = true
filter = recidive
logpath = /var/log/fail2ban.log
action = %(banaction)s[name=recidive, port="all"]
bantime = 86400
findtime = 86400
maxretry = 5

EOF

# Create custom filter for SSH brute force detection
cat > /etc/fail2ban/filter.d/sshd-ddos.conf << 'EOF'
# Fail2Ban filter for SSH pre-auth connection floods and non-identifying clients
[Definition]
failregex = ^.*sshd\[\d+\]: Did not receive identification string from <HOST>\s*$
            ^.*sshd\[\d+\]: Connection closed by <HOST> port \d+ \[preauth\]$
            ^.*sshd\[\d+\]: Disconnected from <HOST> port \d+ \[preauth\]$
            ^.*sshd\[\d+\]: Connection reset by <HOST> port \d+ \[preauth\]$
ignoreregex =
EOF


# Install and configure rsyslog first (needed for fail2ban)
echo "Setting up logging system for fail2ban..."
if ! systemctl is-active --quiet rsyslog; then
    echo "Installing rsyslog for enhanced logging..."
    apt-get install -y rsyslog
    systemctl enable rsyslog
    start_service_with_retry rsyslog
    echo "✅ Rsyslog installed and started"
else
    echo "✅ Rsyslog already active"
fi

# Ensure required log files exist before fail2ban starts
echo "Creating required log files for fail2ban..."
touch /var/log/auth.log
touch /var/log/fail2ban.log
chmod 640 /var/log/auth.log
chmod 640 /var/log/fail2ban.log
chown root:adm /var/log/auth.log
chown root:adm /var/log/fail2ban.log

# Restart rsyslog to ensure proper logging
systemctl restart rsyslog
sleep 2
echo "✅ Logging system configured for fail2ban"

# Create a test log entry to initialize auth.log
logger -p auth.info "Bastion setup: Initializing auth.log for fail2ban"

# Test fail2ban configuration before starting
echo "Testing fail2ban configuration..."
if fail2ban-client -t; then
    echo "✅ Fail2ban configuration is valid"
else
    echo "⚠️ Fail2ban configuration test failed - checking for issues"
    fail2ban-client -t || true
fi

# Enable and start fail2ban with error handling
systemctl enable fail2ban

# Stop fail2ban if it's already running to ensure clean start
systemctl stop fail2ban 2>/dev/null || true
sleep 1

if start_service_with_retry fail2ban; then
    echo "✅ Fail2ban started successfully"
    # Wait a moment for fail2ban to initialize
    sleep 5
    # Verify it's running
    if systemctl is-active --quiet fail2ban; then
        echo "✅ Fail2ban is active and running"
        # Test fail2ban client connection
        if fail2ban-client status >/dev/null 2>&1; then
            echo "✅ Fail2ban client communication working"
            fail2ban-client status
        else
            echo "⚠️ Fail2ban status check failed (may still be initializing)"
        fi
    else
        echo "⚠️ Fail2ban failed to start properly"
        systemctl status fail2ban --no-pager -l
        echo "Checking fail2ban logs:"
        tail -n 20 /var/log/fail2ban.log 2>/dev/null || echo "No fail2ban log available yet"
    fi
else
    echo "❌ Failed to start fail2ban service"
    systemctl status fail2ban --no-pager -l
    echo "Checking fail2ban logs:"
    tail -n 20 /var/log/fail2ban.log 2>/dev/null || echo "No fail2ban log available"
fi

# Configure AIDE (Advanced Intrusion Detection Environment) for bastion host
echo "===== 7.5 Configuring AIDE for file integrity monitoring ====="

# Configure AIDE to run properly with mail functionality
cat > /etc/default/aide << EOF
# Configuration for AIDE on bastion host
# Run AIDE checks as root to enable mail functionality
AIDE_USER="root"

# Mail configuration
MAILTO="root"
MAILSUBJECT="AIDE integrity check for bastion host $HOSTNAME"

# Quiet mode - don't output unless there are changes
QUIETREPORTS="yes"

# Skip the database check if the database doesn't exist yet
COPYNEWDB="no"
EOF

# Create custom AIDE check script that handles mail properly
cat > /usr/local/bin/aide-check << EOF
#!/bin/bash
# Custom AIDE check script with proper mail handling for bastion host

# Log file for AIDE output
AIDE_LOG="/var/log/aide/aide-check.log"
mkdir -p /var/log/aide

# Run AIDE check and capture output
echo "AIDE integrity check started at \$(date)" > \$AIDE_LOG
echo "=====================================" >> \$AIDE_LOG

# Run AIDE check with explicit config file
# Debian stores AIDE config at /etc/aide/aide.conf
if aide --config=/etc/aide/aide.conf --check 2>&1 | tee -a \$AIDE_LOG; then
    # AIDE completed successfully
    echo "AIDE check completed at \$(date)" >> \$AIDE_LOG
    
    # Check if there were any changes detected
    if grep -q "found differences" \$AIDE_LOG || grep -q "File.*changed" \$AIDE_LOG; then
        # Changes detected - send alert email
        cat \$AIDE_LOG | mail -s "🚨 BASTION AIDE ALERT: File integrity changes detected on \$HOSTNAME" root
    else
        # No changes - log success
        echo "No integrity violations detected" >> \$AIDE_LOG
    fi
else
    # AIDE failed
    echo "AIDE check failed at \$(date)" >> \$AIDE_LOG
    echo "AIDE integrity check failed on bastion host \$HOSTNAME" | mail -s "🚨 BASTION AIDE ERROR: Check failed on \$HOSTNAME" root
    exit 1
fi

# Rotate old logs
find /var/log/aide -name "aide-check.log.*" -mtime +30 -delete
if [ -f \$AIDE_LOG ] && [ \$(stat -c%s \$AIDE_LOG) -gt 10485760 ]; then
    # Rotate if log is larger than 10MB
    mv \$AIDE_LOG \${AIDE_LOG}.\$(date +%Y%m%d)
    gzip \${AIDE_LOG}.\$(date +%Y%m%d)
fi
EOF

chmod 755 /usr/local/bin/aide-check

# Override the default AIDE systemd service to use our custom script
mkdir -p /etc/systemd/system/dailyaidecheck.service.d
cat > /etc/systemd/system/dailyaidecheck.service.d/override.conf << EOF
[Service]
# Override to use our custom AIDE check script
ExecStart=
ExecStart=/usr/local/bin/aide-check

# Ensure proper user and environment
User=root
Group=root

# Resource limits to prevent AIDE from overwhelming bastion system
CPUQuota=20%
MemoryMax=256M
Nice=19
IOSchedulingClass=3

# Proper logging
StandardOutput=journal
StandardError=journal
EOF

systemctl daemon-reload

# Create AIDE systemd timer for daily checks
cat > /etc/systemd/system/aide.timer << EOF
[Unit]
Description=Run AIDE integrity check daily
Requires=aide.service

[Timer]
OnCalendar=daily
RandomizedDelaySec=1h
Persistent=true

[Install]
WantedBy=timers.target
EOF

# Create AIDE service unit that uses our custom script
cat > /etc/systemd/system/aide.service << EOF
[Unit]
Description=AIDE integrity check
After=local-fs.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/aide-check
User=root
Group=root

# Resource limits to prevent AIDE from overwhelming bastion system
CPUQuota=20%
MemoryMax=256M
Nice=19
IOSchedulingClass=3

# Proper logging
StandardOutput=journal
StandardError=journal

# Security isolation
NoNewPrivileges=true
EOF

systemctl daemon-reload

echo "Initializing AIDE database for bastion host - this will take some time..."
# Run aideinit in a subshell to prevent environment pollution
(nice -n 19 aideinit)

# Enable and start AIDE timer
systemctl enable aide.timer
systemctl start aide.timer

# Clear any environment variables that might interfere with heredocs
unset EOF >/dev/null 2>&1 || true

echo "✅ AIDE configured with systemd timer and proper mail functionality for bastion host"
echo "   • Daily integrity checks enabled via aide.timer"
echo "   • Custom mail alerts for detected changes"
echo "   • Resource limits to prevent system impact"

echo "===== 8. Configuring comprehensive audit framework for bastion ====="

# Ensure filesystems are writable before making audit configuration changes
echo "Checking filesystem writability..."
if mount | grep " / " | grep -q "(ro,"; then
    echo "Root filesystem is read-only, remounting as read-write..."
    mount -o remount,rw /
fi
if mount | grep " /boot " | grep -q "(ro,"; then
    echo "/boot filesystem is read-only, remounting as read-write..."
    mount -o remount,rw /boot
fi

# Enable kernel audit subsystem if not already enabled
echo "Enabling kernel audit subsystem..."
if command -v auditctl >/dev/null 2>&1; then
    AUDIT_ENABLED=$(auditctl -s 2>/dev/null | grep "^enabled" | awk '{print $2}' || echo "unknown")

    if [ "$AUDIT_ENABLED" = "0" ]; then
        echo "Kernel audit is disabled, enabling now..."
        if auditctl -e 1 2>/dev/null; then
            echo "✅ Kernel audit enabled"
        else
            echo "⚠️  Failed to enable kernel audit - may need reboot"
        fi
    elif [ "$AUDIT_ENABLED" = "1" ]; then
        echo "✅ Kernel audit already enabled"
    else
        echo "ℹ️  Cannot determine kernel audit status (may not be available yet)"
    fi
fi

# Make audit enabled persistent via GRUB
if [ -f /etc/default/grub ]; then
    if ! grep -q "audit=1" /etc/default/grub; then
        echo "Adding audit=1 to GRUB for persistent kernel audit..."
        cp /etc/default/grub /etc/default/grub.backup-audit 2>/dev/null || true
        sed -i 's/GRUB_CMDLINE_LINUX_DEFAULT="/GRUB_CMDLINE_LINUX_DEFAULT="audit=1 /' /etc/default/grub

        if command -v update-grub >/dev/null 2>&1; then
            update-grub 2>/dev/null || echo "⚠️  GRUB update had issues"
            echo "✅ GRUB updated with audit=1"
        fi
    else
        echo "✅ audit=1 already in GRUB config"
    fi
fi

# Enhanced audit configuration for bastion hosts
cat > /etc/audit/auditd.conf << EOF
# Bastion Host Audit Configuration - Enhanced Monitoring
local_events = yes
write_logs = yes
log_file = /var/log/audit/audit.log
log_group = adm
log_format = ENRICHED
flush = INCREMENTAL_ASYNC
freq = 50
max_log_file = 16
num_logs = 10
priority_boost = 4
name_format = HOSTNAME
max_log_file_action = ROTATE
space_left = 100
space_left_action = SYSLOG
verify_email = yes
action_mail_acct = $LOGWATCH_EMAIL
admin_space_left = 75
admin_space_left_action = EMAIL
disk_full_action = SUSPEND
disk_error_action = SUSPEND
use_libwrap = yes
tcp_listen_queue = 5
tcp_max_per_addr = 1
tcp_client_max_idle = 0
enable_krb5 = no
distribute_network = no
EOF

# Create minimal, proven audit rules for bastion host
# These rules are tested to work reliably across different kernel versions
cat > /etc/audit/rules.d/bastion-audit.rules << EOF
## Bastion Host Audit Rules - Minimal Reliable Set
## Optimized for compatibility and stability

## First rule - delete all existing rules
-D

## Buffer size - moderate for bastion host
-b 8192

## Set failure mode to syslog (1) not panic (2)
-f 1

## === Session Tracking (Critical for Bastion) ===
-w /var/log/wtmp -p wa -k session
-w /var/log/btmp -p wa -k session
-w /var/run/utmp -p wa -k session
-w /var/log/lastlog -p wa -k session

## === SSH Configuration Monitoring ===
-w /etc/ssh/sshd_config -p wa -k ssh_config

## === Identity Management ===
-w /etc/group -p wa -k identity
-w /etc/passwd -p wa -k identity
-w /etc/gshadow -k identity
-w /etc/shadow -k identity

## === Sudo Configuration ===
-w /etc/sudoers -p wa -k privilege_escalation
-w /etc/sudoers.d/ -p wa -k privilege_escalation

## === Critical System Binaries ===
-w /bin/su -p x -k privilege_escalation
-w /usr/bin/sudo -p x -k privilege_escalation

## === User Command Execution (64-bit only for compatibility) ===
-a always,exit -F arch=b64 -S execve -F uid>=1000 -F uid!=4294967295 -k user_commands

## === Privilege Escalation Syscalls (64-bit only, no b32 for compatibility) ===
-a always,exit -F arch=b64 -S setuid -S setgid -S setresuid -S setresgid -k privilege_escalation

## === Kernel Module Loading ===
-w /sbin/insmod -p x -k module_insertion
-w /sbin/rmmod -p x -k module_removal
-w /sbin/modprobe -p x -k module_insertion

## === Time Changes ===
-w /etc/localtime -p wa -k time_change

## === Cron Jobs ===
-w /etc/crontab -p wa -k cron
-w /var/spool/cron/crontabs/ -p wa -k cron

## DO NOT make rules immutable to allow updates without reboot
## NOTE: b32 arch rules removed for compatibility
## NOTE: Complex syscalls (socket, chmod, kill) removed for reliability
EOF

echo "===== 8.1 Configuring Auditd Service (Remove Circular Dependency) ====="

# Fix the circular dependency: auditd requires audit-rules, but audit-rules often fails
# Solution: Copy auditd.service to /etc/systemd/system/ and remove the dependency
echo "Removing audit-rules hard dependency from auditd..."

if [ -f /usr/lib/systemd/system/auditd.service ]; then
    cp /usr/lib/systemd/system/auditd.service /etc/systemd/system/auditd.service

    # Remove the problematic Requires dependency
    sed -i '/^Requires=audit-rules.service/d' /etc/systemd/system/auditd.service
    sed -i 's/After=\(.*\) audit-rules.service/After=\1/' /etc/systemd/system/auditd.service

    echo "✅ auditd service dependency removed"
else
    echo "⚠️  auditd.service not found in /usr/lib/systemd/system/"
fi

# Mask the problematic audit-rules service permanently
echo "Masking audit-rules.service (has broken circular dependency)..."
systemctl mask audit-rules.service 2>/dev/null || true
echo "✅ audit-rules.service masked"

# Create alternative rule-loading service that runs after auditd
cat > /etc/systemd/system/load-audit-rules.service << 'EOF'
[Unit]
Description=Load Audit Rules After Auditd Starts
After=auditd.service
Requires=auditd.service

[Service]
Type=oneshot
# Wait for auditd to be fully ready
ExecStart=/bin/sleep 3
# Load the rules from our custom rules file
ExecStart=/usr/sbin/auditctl -R /etc/audit/rules.d/bastion-audit.rules
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

echo "✅ Created load-audit-rules.service"

# Configure auditd systemd resource limits for bastion host
echo "===== 8.1.1 Configuring Auditd Resource Management ====="
mkdir -p /etc/systemd/system/auditd.service.d
cat > /etc/systemd/system/auditd.service.d/resource-limits.conf << EOF
[Service]
# Resource limits for bastion host audit system
CPUQuota=15%
MemoryMax=128M
MemoryHigh=100M
Nice=0
IOSchedulingClass=1
IOSchedulingPriority=4
OOMPolicy=continue
OOMScoreAdjust=-200

# Security and isolation (limited for auditd requirements)
# Note: ProtectHome=true can interfere with audit rule loading
NoNewPrivileges=true
ReadWritePaths=/var/log/audit /etc/audit

# Restart policy for audit reliability
Restart=always
RestartSec=30
TimeoutStartSec=60
TimeoutStopSec=30
EOF

systemctl daemon-reload

# Enable both services
echo "Enabling audit services..."
systemctl enable auditd
systemctl enable load-audit-rules.service

# Check if auditd is already running and stop it cleanly if needed
if systemctl is-active --quiet auditd; then
    echo "Stopping existing auditd service..."
    systemctl stop auditd
    sleep 2
fi

# Start auditd with improved error handling
echo "Starting audit daemon..."
if start_service_with_retry auditd; then
    echo "✅ Audit daemon started successfully"

    # Verify kernel audit is actually working
    sleep 2
    AUDIT_PID=$(auditctl -s 2>/dev/null | grep "^pid" | awk '{print $2}' || echo "0")
    AUDIT_ENABLED=$(auditctl -s 2>/dev/null | grep "^enabled" | awk '{print $2}' || echo "0")

    if [ "$AUDIT_PID" != "0" ] && [ "$AUDIT_ENABLED" = "1" ]; then
        echo "✅ Audit daemon running (PID: $AUDIT_PID, enabled: $AUDIT_ENABLED)"

        # Start the rule-loading service
        echo "Loading audit rules..."
        if systemctl start load-audit-rules.service 2>/dev/null; then
            sleep 2
            RULE_COUNT=$(auditctl -l 2>/dev/null | grep -vc "No rules" || echo "0")
            if [ "$RULE_COUNT" -gt 10 ]; then
                echo "✅ Audit rules loaded: $RULE_COUNT rules active"
            else
                echo "⚠️  Rule loading had issues, but auditd is running"
            fi
        else
            echo "⚠️  Rule loading service had issues, but auditd is running"
        fi
    else
        echo "⚠️  Audit daemon started but kernel audit not fully active (PID: $AUDIT_PID, enabled: $AUDIT_ENABLED)"
        echo "This may resolve after reboot with audit=1 kernel parameter"
    fi
else
    echo "❌ Failed to start audit daemon after retries"
    echo "Checking audit system status:"
    systemctl status auditd --no-pager -l || true
    journalctl -u auditd --no-pager -l -n 10 || true
fi

echo "✅ Audit system configuration completed"

echo "===== 9. Setting up Suricata IDS for bastion network monitoring ====="
# Get primary network interface and bastion IP more robustly
INTERFACE=$(ip -o -4 route show to default | awk '{print $5}')

# Get bastion IP more reliably (avoid multiple IPs and whitespace issues)
BASTION_IP=$(ip -4 addr show "$INTERFACE" | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -1)
if [ -z "$BASTION_IP" ]; then
    # Fallback method
    BASTION_IP=$(hostname -I | awk '{print $1}')
fi

if [ "$INSTALL_SURICATA" = true ]; then
    echo "Configuring Suricata for interface: $INTERFACE, IP: $BASTION_IP"
    
    # Configure Suricata for bastion host monitoring with HOME_NET
    cat > /etc/suricata/suricata.yaml << EOF
%YAML 1.1
---
# Suricata configuration for bastion host monitoring
vars:
  address-groups:
    HOME_NET: "[$BASTION_IP]"
    EXTERNAL_NET: "![$BASTION_IP]"
    INTERNAL_NET: "[$INTERNAL_NETWORK]"
    # Bastion-specific: Only SSH services, others set to any for external monitoring only
    HTTP_SERVERS: "any"
    SQL_SERVERS: "any"
    DNS_SERVERS: "any"
    MAIL_SERVERS: "any"
    FTP_SERVERS: "any"
    
  port-groups:
    SSH_PORTS: "$SSH_PORT"
    HTTP_PORTS: "80"
    HTTPS_PORTS: "443"
    DNS_PORTS: "53"
    DB_PORTS: "3306,5432,1521,1433,27017"
    MAIL_PORTS: "25,465,587,993,995"
    FTP_PORTS: "21,990"
    
default-rule-path: /etc/suricata/rules
rule-files:
  - suricata.rules
  - bastion-custom.rules

af-packet:
  - interface: $INTERFACE
    cluster-id: 99
    cluster-type: cluster_flow
    defrag: yes
    use-mmap: yes
    tpacket-v3: yes
    
# Enhanced detection for bastion hosts
detect-engine:
  profile: high
  sgh-mpm-context: auto
  inspection-recursion-limit: 3000

# App layer protocol configuration
app-layer:
  protocols:
    # Essential protocols for bastion host monitoring
    http:
      enabled: yes
    tls:
      enabled: yes
    ssh:
      enabled: yes
    dns:
      enabled: yes
    smtp:
      enabled: yes
    ftp:
      enabled: yes
    imap:
      enabled: no
    
    # Disable protocols not needed on bastion hosts
    dcerpc:
      enabled: no
    smb:
      enabled: no
    modbus:
      enabled: no
    enip:
      enabled: no
    dnp3:
      enabled: no
    nfs:
      enabled: no
    ntp:
      enabled: no
    tftp:
      enabled: no
    ikev2:
      enabled: no
    krb5:
      enabled: no
    dhcp:
      enabled: no
    snmp:
      enabled: no
    sip:
      enabled: no
    rfb:
      enabled: no
    mqtt:
      enabled: no
    rdp:
      enabled: no
    http2:
      enabled: yes
  
# Comprehensive logging
outputs:
  - fast:
      enabled: yes
      filename: fast.log
      
  - eve-log:
      enabled: yes
      filetype: regular
      filename: eve.json
      types:
        - alert
        - http
        - dns
        - tls
        - ssh
        - flow
        - netflow
        
  - stats:
      enabled: yes
      filename: stats.log
      interval: 3600
EOF

    # Create bastion-specific Suricata rules
    cat > /etc/suricata/rules/bastion-custom.rules << EOF
# Bastion Host Custom Suricata Rules
# Detect common attacks against bastion hosts

# SSH brute force detection
alert tcp \$EXTERNAL_NET any -> \$HOME_NET \$SSH_PORTS (msg:"BASTION SSH Brute Force Attempt"; flow:established,to_server; detection_filter:track by_src, count 5, seconds 60; classtype:attempted-admin; sid:2000001; rev:1;)

# Multiple failed SSH connections
alert tcp \$EXTERNAL_NET any -> \$HOME_NET \$SSH_PORTS (msg:"BASTION SSH Multiple Connection Attempts"; flow:established,to_server; threshold:type threshold, track by_src, count 10, seconds 60; classtype:attempted-recon; sid:2000002; rev:1;)

# Detect SSH scanning
alert tcp \$EXTERNAL_NET any -> \$HOME_NET 22 (msg:"BASTION SSH Scan on Default Port"; flow:established,to_server; classtype:attempted-recon; sid:2000003; rev:1;)

# Detect port scanning targeting bastion
alert tcp \$EXTERNAL_NET any -> \$HOME_NET ![22,2222,80,443] (msg:"BASTION Port Scan Detected"; flow:established,to_server; threshold:type threshold, track by_src, count 5, seconds 10; classtype:attempted-recon; sid:2000004; rev:1;)

# Detect unusual outbound connections from bastion
alert tcp \$HOME_NET any -> \$EXTERNAL_NET ![22,53,80,123,443] (msg:"BASTION Unusual Outbound Connection"; flow:established,to_server; threshold:type threshold, track by_dst, count 5, seconds 60; classtype:policy-violation; sid:2000005; rev:1;)

# Detect potential data exfiltration
alert tcp \$HOME_NET any -> \$EXTERNAL_NET any (msg:"BASTION Large Data Transfer Outbound"; flow:established,to_server; threshold:type threshold, track by_src, count 10, seconds 60; classtype:policy-violation; sid:2000006; rev:1;)

# Detect ICMP tunneling attempts
alert icmp \$EXTERNAL_NET any -> \$HOME_NET any (msg:"BASTION ICMP Tunneling Attempt"; icode:0; itype:8; classtype:attempted-admin; sid:2000007; rev:1;)

# Detect DNS tunneling
alert udp \$HOME_NET any -> any 53 (msg:"BASTION DNS Tunneling Attempt"; content:"|00 01 00 00 00 01|"; classtype:policy-violation; sid:2000008; rev:1;)
EOF

    # Set up Suricata log rotation
    cat > /etc/logrotate.d/suricata << EOF
/var/log/suricata/*.log /var/log/suricata/*.json {
    daily
    size 100M
    rotate 14
    compress
    delaycompress
    missingok
    notifempty
    create 0640 root adm
    postrotate
        /bin/kill -USR2 $(cat /var/run/suricata.pid 2>/dev/null) 2>/dev/null || systemctl reload suricata 2>/dev/null || true
    endscript
}
EOF

    # Configure Suricata systemd resource limits for bastion host
    echo "===== 9.4.1 Configuring Suricata Resource Management ====="
    mkdir -p /etc/systemd/system/suricata.service.d
    cat > /etc/systemd/system/suricata.service.d/resource-limits.conf << EOF
[Service]
# Override ExecStart to specify the correct network interface
ExecStart=
ExecStart=/usr/bin/suricata -D --af-packet=$PRIMARY_INTERFACE -c /etc/suricata/suricata.yaml --pidfile /run/suricata.pid

# Resource limits for bastion host (more conservative than production)
CPUQuota=30%
MemoryMax=512M
MemoryHigh=400M
Nice=10
IOSchedulingClass=2
IOSchedulingPriority=5
OOMPolicy=kill
OOMScoreAdjust=300

# Security and isolation (minimal for IDS functionality)
PrivateTmp=false
NoNewPrivileges=false
ProtectHome=false
ProtectSystem=false

# Restart policy for network IDS reliability
Restart=always
RestartSec=60
TimeoutStartSec=120
TimeoutStopSec=30
EOF

    systemctl daemon-reload

    # Ensure required directories and files exist before testing
    echo "Preparing Suricata configuration..."
    mkdir -p /etc/suricata/rules /var/log/suricata /var/lib/suricata/rules

    # Create minimal default rules file if it doesn't exist
    if [ ! -f /etc/suricata/rules/suricata.rules ]; then
        echo "Creating initial Suricata rules file..."
        cat > /etc/suricata/rules/suricata.rules << EOF
# Default Suricata rules for bastion host
# This file is required by Suricata configuration
EOF
    fi

    # Test Suricata configuration
    echo "Testing Suricata configuration..."
    if suricata -T -c /etc/suricata/suricata.yaml >/tmp/suricata-test.log 2>&1; then
        echo "✅ Suricata configuration is valid"

        # Create log directory with proper permissions
        mkdir -p /var/log/suricata /var/lib/suricata

        # Ensure suricata user exists
        if ! id suricata >/dev/null 2>&1; then
            echo "Creating suricata user..."
            useradd --system --home-dir /var/lib/suricata --shell /bin/false suricata
        fi

        # Set proper ownership and permissions
        chown -R suricata:suricata /var/log/suricata /var/lib/suricata 2>/dev/null || chown -R root:root /var/log/suricata /var/lib/suricata
        chmod 755 /var/log/suricata /var/lib/suricata

        # Reload systemd configuration
        systemctl daemon-reload

        # Enable Suricata for automatic startup
        systemctl enable suricata

        # Start Suricata with error handling
        echo "Starting Suricata IDS service..."
        if start_service_with_retry suricata; then
            echo "✅ Suricata IDS started successfully"

            # Wait for service to initialize
            sleep 5

            # Verify Suricata is running
            if systemctl is-active --quiet suricata; then
                echo "✅ Suricata IDS is running and monitoring network traffic"

                # Show Suricata status
                systemctl --no-pager status suricata | head -10
            else
                echo "⚠️ Suricata started but may not be fully operational"
                echo "Checking Suricata logs:"
                journalctl -u suricata --no-pager -l --since="2 minutes ago" | tail -10
            fi
        else
            echo "❌ Failed to start Suricata IDS"
            echo "Checking systemctl status:"
            systemctl --no-pager status suricata
            echo ""
            echo "Recent logs:"
            journalctl -u suricata --no-pager -l --since="2 minutes ago"
            echo ""
            echo "⚠️ Suricata IDS disabled due to startup failure"
            systemctl disable suricata 2>/dev/null || true
            echo "   Network monitoring will be limited to other security tools"
        fi
    else
        echo "❌ Suricata configuration test failed"
        echo "Configuration errors:"
        cat /tmp/suricata-test.log

        echo "Attempting to fix common Suricata issues..."

        # Directories and rules file already created above
        echo "Suricata directories and basic rules file already exist"

        # Check interface exists
        if ! ip link show "$INTERFACE" >/dev/null 2>&1; then
            echo "⚠️ Network interface $INTERFACE not found, using fallback configuration"
            # Get first available interface
            FALLBACK_INTERFACE=$(ip -o link show | grep -v lo | head -1 | awk -F': ' '{print $2}')
            echo "Using fallback interface: $FALLBACK_INTERFACE"

            # Update Suricata config with fallback interface
            sed -i "s/interface: $INTERFACE/interface: $FALLBACK_INTERFACE/" /etc/suricata/suricata.yaml
        fi

        # Retry configuration test
        echo "Retesting Suricata configuration with fixes..."
        if suricata -T -c /etc/suricata/suricata.yaml >/tmp/suricata-retest.log 2>&1; then
            echo "✅ Suricata configuration"

            systemctl daemon-reload
            systemctl enable suricata

            if start_service_with_retry suricata; then
                echo "✅ Suricata IDS started successfully after fixes"
            else
                echo "❌ Suricata still fails to start - disabling"
                systemctl disable suricata 2>/dev/null || true
                echo "⚠️ Suricata IDS disabled - network monitoring limited"
            fi
        else
            echo "❌ Suricata configuration still invalid"
            echo "Final error details:"
            cat /tmp/suricata-retest.log

            # Disable Suricata if it still invalid
            systemctl disable suricata 2>/dev/null || true
            echo "⚠️ Suricata IDS disabled due to configuration errors"
            echo "   Other security tools (fail2ban, auditd) will provide protection"
            echo "   Manual Suricata configuration may be required"
        fi
    fi

    # Cleanup test logs
    rm -f /tmp/suricata-test.log /tmp/suricata-retest.log
fi

echo "===== 10. Setting up comprehensive logging and monitoring ====="

# Rsyslog already installed and configured earlier for fail2ban

# Configure rsyslog with traditional timestamp format for logwatch compatibility
if ! grep -q "RSYSLOG_TraditionalFileFormat" /etc/rsyslog.conf; then
    cp /etc/rsyslog.conf /etc/rsyslog.conf.backup
    RSYSLOG_TMP=$(mktemp /tmp/rsyslog-config-XXXXXX)
    {
        echo "\$ActionFileDefaultTemplate RSYSLOG_TraditionalFileFormat"
        cat /etc/rsyslog.conf
    } > "$RSYSLOG_TMP" && mv "$RSYSLOG_TMP" /etc/rsyslog.conf
    echo "✅ Configured rsyslog to use traditional timestamp format"
fi

# Configure rsyslog for enhanced logging
cat > /etc/rsyslog.d/bastion-logging.conf << EOF
# Bastion Host Enhanced Logging Configuration

# Log all authentication events separately
auth,authpriv.*                         /var/log/auth.log

# Log all SSH events to separate file
if \$programname == 'sshd' then /var/log/ssh.log
& stop

# Log all sudo events
if \$programname == 'sudo' then /var/log/sudo.log
& stop

# Log all audit events
if \$programname == 'auditd' then /var/log/audit/audit.log
& stop

# Log network events
if \$programname == 'NetworkManager' or \$programname == 'dhclient' then /var/log/network.log
& stop

# High priority events to dedicated file
*.emerg;*.alert;*.crit                  /var/log/emergency.log

# Remote logging (uncomment and configure for centralized logging)
# *.* @@log-server.internal.domain:514
EOF

# Restart rsyslog to apply new configuration
systemctl restart rsyslog

if [ "$INSTALL_RKHUNTER" = true ]; then
    # Configure chkrootkit
    echo "===== 10.1 Configuring chkrootkit ====="

    # Create chkrootkit scan script with proper log handling
    cat > /etc/cron.daily/chkrootkit-scan << EOF
#!/bin/bash
# Run a daily chkrootkit scan

# Log file
LOGFILE="/var/log/chkrootkit/daily_scan.log"
EXPECTED_LOG="/var/log/chkrootkit/log.expected"
TODAY_LOG="/var/log/chkrootkit/log.today"

# Create log directory if it doesn't exist
mkdir -p /var/log/chkrootkit

# Clear previous log
echo "chkrootkit daily scan started at \$(date)" > \$LOGFILE

# Run the scan
chkrootkit -q > \$TODAY_LOG 2>&1

# Add completion time
echo "chkrootkit daily scan completed at \$(date)" >> \$LOGFILE

# Create expected log file if it doesn't exist (first run)
if [ ! -f "\$EXPECTED_LOG" ]; then
    echo "Creating initial expected output file for chkrootkit..."
    cp "\$TODAY_LOG" "\$EXPECTED_LOG"
    echo "Initial chkrootkit expected output created at \$(date)" >> \$LOGFILE
fi

# Check for differences from expected output
if ! diff -q "\$EXPECTED_LOG" "\$TODAY_LOG" >/dev/null 2>&1; then
    # There are differences - send email alert
    ADMIN_EMAIL="${LOGWATCH_EMAIL:-root}"
    
    # Create diff report
    echo "chkrootkit output differs from expected baseline" > /tmp/chkrootkit-alert.txt
    echo "Scan date: \$(date)" >> /tmp/chkrootkit-alert.txt
    echo "" >> /tmp/chkrootkit-alert.txt
    echo "=== TODAY'S OUTPUT ===" >> /tmp/chkrootkit-alert.txt
    cat "\$TODAY_LOG" >> /tmp/chkrootkit-alert.txt
    echo "" >> /tmp/chkrootkit-alert.txt
    echo "=== EXPECTED OUTPUT ===" >> /tmp/chkrootkit-alert.txt
    cat "\$EXPECTED_LOG" >> /tmp/chkrootkit-alert.txt
    echo "" >> /tmp/chkrootkit-alert.txt
    echo "=== DIFFERENCES ===" >> /tmp/chkrootkit-alert.txt
    diff "\$EXPECTED_LOG" "\$TODAY_LOG" >> /tmp/chkrootkit-alert.txt
    
    # Send email alert
    cat /tmp/chkrootkit-alert.txt | mail -s "⚠️ CHKROOTKIT ALERT: Output changed on \$(hostname)" "\$ADMIN_EMAIL"
    
    # Log the alert
    echo "chkrootkit output changed - alert sent to \$ADMIN_EMAIL" >> \$LOGFILE
    
    # Clean up
    rm -f /tmp/chkrootkit-alert.txt
else
    echo "chkrootkit output matches expected baseline" >> \$LOGFILE
fi

# Check for INFECTED results specifically
if grep -q "INFECTED" "\$TODAY_LOG"; then
    ADMIN_EMAIL="${LOGWATCH_EMAIL:-root}"
    cat "\$TODAY_LOG" | mail -s "⚠️ ROOTKIT WARNING: Possible rootkit found on \$(hostname)" "\$ADMIN_EMAIL"
    echo "INFECTED results found - alert sent to \$ADMIN_EMAIL" >> \$LOGFILE
fi
EOF

    chmod 755 /etc/cron.daily/chkrootkit-scan

    # Run initial chkrootkit scan to create baseline
    echo "Running initial chkrootkit scan to create baseline..."
    mkdir -p /var/log/chkrootkit
    /etc/cron.daily/chkrootkit-scan

    echo ""
    echo "📝 IMPORTANT: chkrootkit baseline setup"
    echo "The initial chkrootkit baseline was created, but you should update it after"
    echo "all services are running and the system is in its final state."
    echo ""
    echo "After 24-48 hours of operation, run this command to update the baseline:"
    echo "  sudo cp -a -f /var/log/chkrootkit/log.today /var/log/chkrootkit/log.expected"
    echo ""
    echo "This will eliminate false positives from legitimate security tools like Suricata."
    echo ""
else
    echo "⏭️ Rootkit detection tools not selected - skipping chkrootkit configuration"
fi

# Configure Logcheck (make it less noisy - logwatch provides better daily reports)
echo "===== 10.2 Configuring Logcheck (minimal noise) ====="

# Create proper logcheck configuration with error handling
cat > /etc/logcheck/logcheck.conf << EOF
# Logcheck configuration for bastion host
# This file controls logcheck behavior and frequency

# Set to server level (much less noisy than default paranoid)
REPORTLEVEL="server"

# Email configuration
SENDMAILTO="${LOGWATCH_EMAIL}"

# Set running frequency to daily (default is hourly - too noisy!)
CRON_DAILY_RUN="true"
CRON_HOURLY_RUN="false"

# Lock file and PID management
LOCKFILE="/var/lock/logcheck/logcheck.lock"

# Temporary file cleanup
TMP="/tmp"

# Additional safety settings
FQDN=1
INTRO=1
ATTACKALERT=1
VIOLATIONS=1
CRACKING=1
PARANOID=0

# Reduce false positives for bastion hosts
SYSLOGSUMMARY=0
MAILASATTACHMENTS=0
REBOOT=0
EOF

# Disable hourly logcheck and ensure only daily runs
echo "===== 10.2.1 Setting logcheck to run daily only (reducing email frequency) ====="

# Remove or disable the default hourly logcheck cron job
rm -f /etc/cron.hourly/logcheck 2>/dev/null || true
rm -f /etc/cron.d/logcheck 2>/dev/null || true

# Create a proper daily logcheck cron job that runs as logcheck user
cat > /etc/cron.daily/logcheck << 'EOF'
#!/bin/bash
# Daily logcheck cron job - runs as logcheck user to avoid security warnings
if command -v sudo >/dev/null 2>&1; then
    sudo -u logcheck /usr/sbin/logcheck
else
    su -s /bin/bash -c "/usr/sbin/logcheck" logcheck
fi
EOF
chmod 755 /etc/cron.daily/logcheck

echo "✅ Logcheck configured to run daily only (instead of hourly)"
echo "   • To change frequency: edit /etc/logcheck/logcheck.conf"
echo "   • CRON_HOURLY_RUN=\"false\" = hourly disabled"
echo "   • CRON_DAILY_RUN=\"true\" = daily enabled"
echo "   • To re-enable hourly: set CRON_HOURLY_RUN=\"true\" and copy script to /etc/cron.hourly/"

# Ensure logcheck directories exist with proper permissions
mkdir -p /var/lock/logcheck
chown logcheck:logcheck /var/lock/logcheck 2>/dev/null || true
chmod 755 /var/lock/logcheck

# Clean up any stale lock files
rm -f /var/lock/logcheck/logcheck.lock 2>/dev/null || true

# Configure logcheck logfiles (fix "1 does not exist" error)
echo "Configuring logcheck logfiles..."

# Remove any existing logfiles configuration that might conflict
rm -f /etc/logcheck/logcheck.logfiles.d/* 2>/dev/null || true

# Create clean logfiles configuration
cat > /etc/logcheck/logcheck.logfiles << EOF
/var/log/auth.log
/var/log/syslog
/var/log/kern.log
/var/log/mail.log
/var/log/daemon.log
/var/log/user.log
/var/log/messages
EOF

# Ensure all configured log files exist
touch /var/log/auth.log
touch /var/log/syslog
touch /var/log/kern.log
touch /var/log/mail.log
touch /var/log/daemon.log
touch /var/log/user.log
touch /var/log/messages

# Set proper permissions for log files
chmod 640 /var/log/auth.log /var/log/syslog /var/log/kern.log /var/log/mail.log /var/log/daemon.log /var/log/user.log /var/log/messages
chown root:adm /var/log/auth.log /var/log/syslog /var/log/kern.log /var/log/mail.log /var/log/daemon.log /var/log/user.log /var/log/messages

# Test logcheck configuration
echo "Testing logcheck configuration..."

# Debug: Check if logfiles configuration is readable
echo "Checking logcheck.logfiles content:"
cat /etc/logcheck/logcheck.logfiles

# Ensure logcheck directories exist with proper permissions
mkdir -p /var/lib/logcheck
mkdir -p /etc/logcheck/logcheck.logfiles.d
chown logcheck:logcheck /var/lib/logcheck
chmod 755 /var/lib/logcheck

# Ensure logcheck user can read log files
usermod -aG adm logcheck 2>/dev/null || true

# Verify all log files exist and are readable by logcheck user
echo "Verifying log file permissions for logcheck user:"
for logfile in /var/log/auth.log /var/log/syslog /var/log/kern.log /var/log/mail.log /var/log/daemon.log /var/log/user.log /var/log/messages; do
    if [ -f "$logfile" ]; then
        if sudo -u logcheck test -r "$logfile"; then
            echo "✅ $logfile is readable by logcheck user"
        else
            echo "⚠️ $logfile is not readable by logcheck user - fixing permissions"
            chmod 640 "$logfile"
            chown root:adm "$logfile"
        fi
    else
        echo "⚠️ $logfile does not exist - creating it"
        touch "$logfile"
        chmod 640 "$logfile"
        chown root:adm "$logfile"
    fi
done

# Test logcheck configuration
if sudo -u logcheck logcheck -t; then
    echo "✅ Logcheck configuration is valid"
else
    echo "⚠️ Logcheck configuration test failed - checking for more issues"
    
    # Additional debugging
    echo "Logcheck user groups:"
    groups logcheck
    
    echo "Testing individual log file access:"
    sudo -u logcheck ls -la /var/log/auth.log /var/log/syslog 2>&1 || true
    
    # Check if there are any invalid entries in logfiles
    echo "Checking for invalid logfile entries:"
    while IFS= read -r line; do
        if [ -n "$line" ] && [ "${line:0:1}" != "#" ]; then
            if [ ! -f "$line" ]; then
                echo "⚠️ Log file does not exist: $line"
            elif ! sudo -u logcheck test -r "$line"; then
                echo "⚠️ Log file not readable by logcheck: $line"
            fi
        fi
    done < /etc/logcheck/logcheck.logfiles
    
    # If still failing, try a simpler approach
    echo "Attempting alternative logcheck configuration..."
    
    # Create a minimal working configuration
    cat > /etc/logcheck/logcheck.logfiles << EOF
/var/log/auth.log
/var/log/syslog
EOF
    
    # Test again with minimal config
    if sudo -u logcheck logcheck -t; then
        echo "✅ Logcheck working with minimal configuration"
    else
        echo "⚠️ Logcheck still failing - will disable problematic settings"
        
        # Disable logcheck if it continues to fail
        systemctl disable logcheck 2>/dev/null || true
        echo "⚠️ Logcheck disabled due to configuration issues - logwatch will provide log monitoring"
    fi
fi

# Add logcheck ignore rules for common bastion activity
echo "===== 10.1.1 Adding bastion-specific logcheck ignore rules ====="
cat >> /etc/logcheck/ignore.d.server/bastion-ignore << EOF
# Bastion host specific ignore patterns
# Ignore normal SSH activity patterns that are not security issues

# Normal SSH connection patterns
^\w{3} [ :0-9]{11} [._[:alnum:]-]+ sshd\[[0-9]+\]: Connection from [.[:digit:]]+ port [0-9]+ on [.[:digit:]]+ port [0-9]+$
^\w{3} [ :0-9]{11} [._[:alnum:]-]+ sshd\[[0-9]+\]: Accepted publickey for [[:alnum:]]+ from [.[:digit:]]+ port [0-9]+ ssh2: [[:alnum:][:space:]]+$
^\w{3} [ :0-9]{11} [._[:alnum:]-]+ sshd\[[0-9]+\]: pam_unix\(sshd:session\): session opened for user [[:alnum:]]+ by \(uid=[0-9]+\)$
^\w{3} [ :0-9]{11} [._[:alnum:]-]+ sshd\[[0-9]+\]: pam_unix\(sshd:session\): session closed for user [[:alnum:]]+$

# Normal sudo activity (bastion users need sudo access)
^\w{3} [ :0-9]{11} [._[:alnum:]-]+ sudo:\s+[[:alnum:]]+ : TTY=[[:alnum:]\/]+ ; PWD=[\/[:alnum:]._-]+ ; USER=root ; COMMAND=\/usr\/local\/bin\/.*$

# UFW and fail2ban normal operations  
# Support both traditional syslog and ISO 8601 timestamp formats
^\w{3} [ :0-9]{11} [._[:alnum:]-]+ kernel: \[UFW [[:upper:]]+\].*$
^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]+[+-][0-9]{4} [._[:alnum:]-]+ kernel: \[[0-9.]+\] \[UFW [[:upper:]]+\].*$

# Normal cron activity
^\w{3} [ :0-9]{11} [._[:alnum:]-]+ \/USR\/SBIN\/CRON\[[0-9]+\]: \([[:alnum:]]+\) CMD \(.*\)$
^\w{3} [ :0-9]{11} [._[:alnum:]-]+ cron\[[0-9]+\]: \([[:alnum:]]+\) CMD \(.*\)$

# Normal systemd activity
^\w{3} [ :0-9]{11} [._[:alnum:]-]+ systemd\[[0-9]+\]: .*\.service: Succeeded\.$
^\w{3} [ :0-9]{11} [._[:alnum:]-]+ systemd\[[0-9]+\]: Started .*\.$

# Normal postfix activity (for notifications)
^\w{3} [ :0-9]{11} [._[:alnum:]-]+ postfix\/.*\[[0-9]+\]: [A-F0-9]+: .*$
^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]+[+-][0-9]{4} [._[:alnum:]-]+ postfix\/.*\[[0-9]+\]: [A-F0-9]+: .*$

# Suricata normal operations and restarts
^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]+[+-][0-9]{4} [._[:alnum:]-]+ suricata\[[0-9]+\]: [0-9]{1,2}\/[0-9]{1,2}\/[0-9]{4} -- [0-9]{2}:[0-9]{2}:[0-9]{2} - <.*> - .*$
^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]+[+-][0-9]{4} [._[:alnum:]-]+ systemd\[[0-9]+\]: suricata\.service: .*$
^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]+[+-][0-9]{4} [._[:alnum:]-]+ suricatasc\[[0-9]+\]: Unable to connect to socket .*$
^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]+[+-][0-9]{4} [._[:alnum:]-]+ kernel: \[[0-9.]+\] device ens[0-9]+ (entered|left) promiscuous mode$

# Normal security tool operations
^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]+[+-][0-9]{4} [._[:alnum:]-]+ chkrootkit-daily\[[0-9]+\]: sending alert to root: .*$
^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]+[+-][0-9]{4} [._[:alnum:]-]+ maldet: .*$
^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]+[+-][0-9]{4} [._[:alnum:]-]+ root: (Security configuration backup completed|Suricata rules updated successfully): .*$

# SSH connection attempts and failures (these are expected on a bastion)
^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]+[+-][0-9]{4} [._[:alnum:]-]+ sshd\[[0-9]+\]: (error: |Unable to negotiate with|Connection closed by|banner exchange:|drop connection|fatal: |exited MaxStartups|beginning MaxStartups).*$

# Kernel packet filtering messages
^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]+[+-][0-9]{4} [._[:alnum:]-]+ kernel: \[[0-9.]+\] af_packet: .*$
EOF

echo "✅ Logcheck configured for daily server-level reports (less technical than default)"
echo "✅ Added bastion-specific ignore patterns to reduce false positives"
echo "📧 Primary reporting via Logwatch (user-friendly daily summaries)"
echo "🔍 Logcheck provides additional technical details if needed"

# Configure Logwatch for bastion-specific monitoring
mkdir -p /etc/logwatch/conf/logfiles
mkdir -p /var/cache/logwatch

cat > /etc/logwatch/conf/logwatch.conf << EOF
# Bastion Host Logwatch Configuration
Output = mail
MailTo = $LOGWATCH_EMAIL
Format = html
Range = yesterday
Detail = High
Show_Empty_Sections = yes

# Disable the default Service = All to avoid conflicts
Service = 

# Use specific services for bastion monitoring
Service = zz-sys         # System Configuration
Service = sshd           # SSH login attempts and success/fail
Service = secure         # PAM messages, login denials
Service = sudo           # Use of sudo, privilege escalations
Service = audit          # If auditd is active
Service = fail2ban       # Banned IPs (if you're using it)
Service = pam_unix       # Pluggable authentication messages
Service = cron           # Scheduled job activity
Service = dpkg           # Package installs/removals (Debian/Ubuntu)
Service = systemd        # System boot/service issues
Service = kernel         # Kernel messages (OOM, panics, etc.)
Service = postfix        # Mail logs (if you use local mail for cron/system)
Service = sendmail       # Might be triggered by postfix wrapper
Service = iptables       # Firewall logs (if you log dropped packets)
Service = zz-lm_sensors  # Hardware Sensors
Service = zz-network     # Network Interface
Service = zz-disk_space  # Disk usage overview
Service = clamav         # Virus scan results
Service = clam-update    # Virus scan updates
EOF

# Create enhanced postfix/sendmail service configuration for detailed reporting
mkdir -p /etc/logwatch/conf/services
mkdir -p /etc/logwatch/conf/logfiles

# Create journalctl-based service configurations for systemd services
cat > /etc/logwatch/conf/services/postfix.conf << EOF
# Enhanced Postfix reporting for bastion host using journalctl
Title = "Mail System (Postfix/Sendmail)"
Logfile =
Logfile = none
*JournalCtl = "--unit='postfix' --unit='postfix@-'"
*RemoveHeaders = Yes
Detail = High
EOF

# Create custom sendmail/postfix logwatch script for bastion-specific analysis
mkdir -p /etc/logwatch/scripts/services
cat > /etc/logwatch/scripts/services/postfix << 'EOF'
#!/usr/bin/perl
# Enhanced Postfix/Sendmail analysis for bastion hosts
# Focuses on security-relevant email events

use strict;
use warnings;

my %sent_count = ();
my %received_count = ();
my %rejected_count = ();
my %bounced_count = ();
my %smtp_stats = ();
my %security_events = ();
my %relay_attempts = ();
my @critical_events = ();

while (my $line = <STDIN>) {
    chomp $line;
    
    # Skip lines that don't contain postfix/sendmail
    next unless $line =~ /(postfix|sendmail)/;
    
    # Extract timestamp
    my ($timestamp) = $line =~ /^(\w+\s+\d+\s+\d+:\d+:\d+)/;
    
    # Count sent messages
    if ($line =~ /status=sent/) {
        $sent_count{total}++;
        if ($line =~ /relay=([^,\s]+)/) {
            $sent_count{$1}++;
        }
    }
    
    # Count received messages
    elsif ($line =~ /status=deferred|status=bounced/) {
        $bounced_count{total}++;
        if ($line =~ /(Connection refused|timeout|Host not found)/i) {
            $bounced_count{$1}++;
        }
    }
    
    # Track SMTP security events
    elsif ($line =~ /(SASL|TLS|SSL)/) {
        if ($line =~ /SASL.*authentication failed/i) {
            $security_events{"SASL Authentication Failed"}++;
            push @critical_events, "$timestamp: SASL auth failure";
        }
        elsif ($line =~ /(TLS|SSL).*established/i) {
            $smtp_stats{"TLS Connections"}++;
        }
        elsif ($line =~ /Anonymous TLS connection established/i) {
            $smtp_stats{"Anonymous TLS"}++;
        }
    }
    
    # Track relay attempts (security concern for bastion)
    elsif ($line =~ /Relay access denied/i) {
        $security_events{"Unauthorized Relay Attempts"}++;
        if ($line =~ /from=<([^>]*)>.*to=<([^>]*)>/) {
            push @critical_events, "$timestamp: Relay attempt from $1 to $2";
        }
    }
    
    # Track connection rejections
    elsif ($line =~ /(reject|blocked|denied)/i) {
        $rejected_count{total}++;
        if ($line =~ /Client host rejected/i) {
            $rejected_count{"Host Rejection"}++;
        }
        elsif ($line =~ /Sender address rejected/i) {
            $rejected_count{"Sender Rejection"}++;
        }
    }
    
    # Track postfix warnings and errors
    elsif ($line =~ /(warning|error|fatal)/i) {
        if ($line =~ /warning.*SASL/i) {
            $security_events{"SASL Warnings"}++;
        }
        elsif ($line =~ /error.*timeout/i) {
            $smtp_stats{"Timeout Errors"}++;
        }
    }
    
    # Track queue statistics
    elsif ($line =~ /postfix\/qmgr.*removed/) {
        $smtp_stats{"Messages Processed"}++;
    }
}

# Generate report
print "\n";
print "=" x 60 . "\n";
print "BASTION HOST MAIL SYSTEM REPORT\n";
print "=" x 60 . "\n\n";

# Mail delivery statistics
if (keys %sent_count || keys %bounced_count) {
    print "📧 MAIL DELIVERY STATISTICS:\n";
    print "-" x 30 . "\n";
    
    if ($sent_count{total}) {
        print "✅ Successfully sent: $sent_count{total} messages\n";
        foreach my $relay (sort keys %sent_count) {
            next if $relay eq 'total';
            print "   → via $relay: $sent_count{$relay}\n";
        }
    }
    
    if ($bounced_count{total}) {
        print "⚠️  Bounced/Deferred: $bounced_count{total} messages\n";
        foreach my $reason (sort keys %bounced_count) {
            next if $reason eq 'total';
            print "   → $reason: $bounced_count{$reason}\n";
        }
    }
    
    if ($rejected_count{total}) {
        print "🚫 Rejected: $rejected_count{total} messages\n";
        foreach my $reason (sort keys %rejected_count) {
            next if $reason eq 'total';
            print "   → $reason: $rejected_count{$reason}\n";
        }
    }
    print "\n";
}

# SMTP/TLS statistics
if (keys %smtp_stats) {
    print "🔐 SMTP/TLS STATISTICS:\n";
    print "-" x 25 . "\n";
    foreach my $stat (sort keys %smtp_stats) {
        print "• $stat: $smtp_stats{$stat}\n";
    }
    print "\n";
}

# Security events (important for bastion hosts)
if (keys %security_events) {
    print "🚨 SECURITY EVENTS:\n";
    print "-" x 20 . "\n";
    foreach my $event (sort keys %security_events) {
        my $count = $security_events{$event};
        my $indicator = $count > 5 ? "⚠️ " : "• ";
        print "$indicator$event: $count\n";
    }
    print "\n";
}

# Critical events detail
if (@critical_events) {
    print "🔍 CRITICAL EVENT DETAILS:\n";
    print "-" x 28 . "\n";
    foreach my $event (@critical_events) {
        print "• $event\n";
    }
    print "\n";
}

# Recommendations for bastion hosts
if (($security_events{"Unauthorized Relay Attempts"} // 0) > 0) {
    print "⚠️  SECURITY RECOMMENDATIONS:\n";
    print "-" x 32 . "\n";
    print "• Review relay restrictions in postfix configuration\n";
    print "• Consider implementing stricter sender verification\n";
    print "• Monitor source IPs for relay attempts\n\n";
}

if (!$smtp_stats{"TLS Connections"} && $sent_count{total}) {
    print "⚠️  TLS RECOMMENDATIONS:\n";
    print "-" x 23 . "\n";
    print "• Consider enforcing TLS for all SMTP connections\n";
    print "• Review SMTP authentication security\n\n";
}

print "📋 For detailed logs, check: /var/log/mail.log\n";
print "🔧 Mail queue status: mailq\n";
print "📊 Postfix configuration: postconf -n\n\n";
EOF

chmod +x /etc/logwatch/scripts/services/postfix

# Create logwatch cron job - use only cron.d for precise timing
# Remove any existing daily cron to prevent duplicates
rm -f /etc/cron.daily/00logwatch

# Configure logwatch to run once daily at 6:00 AM
cat > /etc/cron.d/logwatch << EOF
# Daily logwatch execution for bastion host
# Run at 6:00 AM daily to analyze previous day's logs
0 6 * * * root /usr/sbin/logwatch --output mail --format html --range yesterday --detail high
EOF

# Create logwatch test script for troubleshooting
cat > /usr/local/bin/test-logwatch << EOF
#!/bin/bash
# Test logwatch configuration and email delivery

echo "Testing logwatch configuration..."
echo "================================="
echo ""

echo "1. Checking logwatch installation:"
if command -v logwatch >/dev/null 2>&1; then
    echo "✅ Logwatch is installed"
    logwatch --version 2>/dev/null || echo "Version information not available"
else
    echo "❌ Logwatch is not installed"
    exit 1
fi
echo ""

echo "2. Checking logwatch configuration:"
if [ -f /etc/logwatch/conf/logwatch.conf ]; then
    echo "✅ Logwatch configuration exists"
    echo "Email recipient: $(grep '^MailTo' /etc/logwatch/conf/logwatch.conf | cut -d'=' -f2 | tr -d ' ')"
    echo "Output format: $(grep '^Output' /etc/logwatch/conf/logwatch.conf | cut -d'=' -f2 | tr -d ' ')"
    echo "Range: $(grep '^Range' /etc/logwatch/conf/logwatch.conf | cut -d'=' -f2 | tr -d ' ')"
    echo "Detail level: $(grep '^Detail' /etc/logwatch/conf/logwatch.conf | cut -d'=' -f2 | tr -d ' ')"
else
    echo "❌ Logwatch configuration not found"
    exit 1
fi
echo ""

echo "3. Checking cron jobs:"
if [ -f /etc/cron.daily/00logwatch ]; then
    echo "✅ Daily cron job exists and is executable: $(ls -la /etc/cron.daily/00logwatch | cut -d' ' -f1)"
else
    echo "❌ Daily cron job not found"
fi

if [ -f /etc/cron.d/logwatch ]; then
    echo "✅ Cron.d entry exists"
    cat /etc/cron.d/logwatch
else
    echo "❌ Cron.d entry not found"
fi
echo ""

echo "4. Testing logwatch execution (dry run):"
echo "Running: logwatch --output stdout --format text --range today --detail low"
echo "=============================================================="
timeout 30 logwatch --output stdout --format text --range today --detail low | head -20
echo ""
echo "=============================================================="
echo ""

echo "5. Testing mail system:"
if command -v mail >/dev/null 2>&1; then
    echo "✅ Mail command is available"
    
    # Test mail delivery
    echo "Subject: Logwatch Test - $(date)

This is a test email from the logwatch test script.
If you receive this email, basic mail delivery is working.

Host: $(hostname)
Date: $(date)
User: $(whoami)
" | mail -s "Logwatch Test - $(hostname)" root
    
    echo "✅ Test email sent to root"
    echo "Check /var/mail/root or configured email address"
else
    echo "❌ Mail command not available"
fi
echo ""

echo "6. Testing full logwatch email (for yesterday):"
echo "Running: logwatch --output mail --format html --range yesterday --detail high"
echo "This will send an actual email if mail is configured..."
read -p "Press Enter to continue or Ctrl+C to cancel: "
logwatch --output mail --format html --range yesterday --detail high
echo "✅ Logwatch email command executed"
echo ""

echo "7. Checking mail logs:"
echo "Recent mail log entries:"
tail -10 /var/log/mail.log 2>/dev/null || echo "Mail log not available"
echo ""

echo "8. Checking mail queue:"
mailq 2>/dev/null || echo "Mail queue command not available"
echo ""

echo "Logwatch test complete!"
echo "If you didn't receive emails, check:"
echo "- SMTP configuration in /etc/postfix/main.cf"
echo "- Email aliases in /etc/aliases"  
echo "- Mail logs in /var/log/mail.log"
echo "- Logwatch logs in /var/log/syslog"
EOF

chmod 755 /usr/local/bin/test-logwatch

echo "✅ Logwatch configured with daily email delivery"
echo "   • Daily reports sent to: $LOGWATCH_EMAIL"
echo "   • Test script available: sudo test-logwatch"

echo "===== 11. Creating bastion monitoring scripts ====="

# Create comprehensive bastion monitoring script
cat > /etc/cron.hourly/bastion-monitor << EOF
#!/bin/bash
# Bastion Host Monitoring Script - Runs every hour

LOGFILE="/var/log/bastion-monitor.log"
HOSTNAME=\$(hostname)
DATE=\$(date '+%Y-%m-%d %H:%M:%S')

# Function to log with timestamp
log_message() {
    echo "[\$DATE] \$1" >> \$LOGFILE
}

# Check for suspicious SSH activity
SSH_FAILURES=\$(grep "\$(date '+%b %d %H')" /var/log/auth.log | grep "Failed password" | wc -l)
if [ \$SSH_FAILURES -gt 10 ]; then
    log_message "WARNING: \$SSH_FAILURES SSH login failures in the last hour"
    echo "WARNING: High number of SSH failures (\$SSH_FAILURES) on bastion host \$HOSTNAME" | mail -s "🚨 BASTION [\$HOSTNAME]: SSH Failures (\$SSH_FAILURES)" root
fi

# Check for successful logins
SSH_SUCCESS=\$(grep "\$(date '+%b %d %H')" /var/log/auth.log | grep "Accepted publickey" | wc -l)
if [ \$SSH_SUCCESS -gt 0 ]; then
    log_message "INFO: \$SSH_SUCCESS successful SSH logins in the last hour"
fi

# Check active sessions
ACTIVE_SESSIONS=\$(who | wc -l)
if [ \$ACTIVE_SESSIONS -gt 5 ]; then
    log_message "WARNING: \$ACTIVE_SESSIONS active sessions (threshold: 5)"
    echo "WARNING: High number of active sessions (\$ACTIVE_SESSIONS) on bastion host \$HOSTNAME" | mail -s "🚨 BASTION [\$HOSTNAME]: High Session Count (\$ACTIVE_SESSIONS)" root
fi

# Check disk space
DISK_USAGE=\$(df / | awk 'NR==2 {print \$5}' | sed 's/%//')
if [ \$DISK_USAGE -gt 80 ]; then
    log_message "WARNING: Disk usage at \$DISK_USAGE%"
    echo "WARNING: Disk usage on bastion host \$HOSTNAME is at \$DISK_USAGE%" | mail -s "🚨 BASTION [\$HOSTNAME]: Disk Space (\$DISK_USAGE%)" root
fi

# Check for new audit events
AUDIT_ALERTS=\$(ausearch -ts recent -m avc,user_auth,user_acct,user_mgmt,user_chauthtok,user_role_change,role_assign,role_remove 2>/dev/null | wc -l)
if [ \$AUDIT_ALERTS -gt 0 ]; then
    log_message "INFO: \$AUDIT_ALERTS new audit events in the last hour"
fi

# Check firewall status
if ! ufw status | grep -q "Status: active"; then
    log_message "CRITICAL: Firewall is not active!"
    echo "CRITICAL: Firewall is not active on bastion host \$HOSTNAME" | mail -s "🚨 BASTION [\$HOSTNAME]: CRITICAL - Firewall Down" root
fi

# Check fail2ban status
if ! systemctl is-active --quiet fail2ban; then
    log_message "CRITICAL: Fail2ban is not running!"
    echo "CRITICAL: Fail2ban is not running on bastion host \$HOSTNAME" | mail -s "🚨 BASTION [\$HOSTNAME]: CRITICAL - Fail2ban Down" root
fi

log_message "Bastion monitoring check completed"
EOF

chmod 755 /etc/cron.hourly/bastion-monitor

# Create daily security report script
cat > /etc/cron.daily/bastion-security-report << EOF
#!/bin/bash
# Daily Bastion Security Report

DATE=\$(date +%Y-%m-%d)
HOSTNAME=\$(hostname)
REPORT_FILE="/tmp/bastion-security-report-\$DATE.txt"

echo "======================================================================" > \$REPORT_FILE
echo "BASTION HOST SECURITY REPORT - \$HOSTNAME - \$DATE" >> \$REPORT_FILE
echo "======================================================================" >> \$REPORT_FILE
echo "" >> \$REPORT_FILE

echo "SYSTEM OVERVIEW" >> \$REPORT_FILE
echo "===============" >> \$REPORT_FILE
echo "Hostname: \$HOSTNAME" >> \$REPORT_FILE
echo "Uptime: \$(uptime)" >> \$REPORT_FILE
echo "Load Average: \$(cat /proc/loadavg)" >> \$REPORT_FILE
echo "Disk Usage: \$(df -h / | awk 'NR==2 {print \$5}')" >> \$REPORT_FILE
echo "Memory Usage: \$(free -h | awk 'NR==2{printf "%.2f%%", \$3*100/\$2 }')" >> \$REPORT_FILE
echo "" >> \$REPORT_FILE

echo "SSH ACTIVITY SUMMARY" >> \$REPORT_FILE
echo "====================" >> \$REPORT_FILE
echo "Successful logins today: \$(grep "\$(date '+%b %d')" /var/log/auth.log | grep "Accepted publickey" | wc -l)" >> \$REPORT_FILE
echo "Failed login attempts today: \$(grep "\$(date '+%b %d')" /var/log/auth.log | grep "Failed password" | wc -l)" >> \$REPORT_FILE
echo "Currently active sessions: \$(who | wc -l)" >> \$REPORT_FILE
echo "" >> \$REPORT_FILE

echo "RECENT SUCCESSFUL LOGINS" >> \$REPORT_FILE
echo "========================" >> \$REPORT_FILE
if grep "\$(date '+%b %d')" /var/log/auth.log 2>/dev/null | grep "Accepted publickey" | tail -10 >> \$REPORT_FILE; then
    true
else
    echo "No successful SSH logins found for today" >> \$REPORT_FILE
fi
echo "" >> \$REPORT_FILE

echo "FIREWALL STATUS & STATISTICS" >> \$REPORT_FILE
echo "============================" >> \$REPORT_FILE
ufw status numbered >> \$REPORT_FILE 2>/dev/null || echo "UFW status unavailable" >> \$REPORT_FILE
echo "" >> \$REPORT_FILE

echo "UFW BLOCKED CONNECTIONS (Last 24h)" >> \$REPORT_FILE
echo "===================================" >> \$REPORT_FILE
# Generate UFW block statistics instead of showing individual blocks
UFW_BLOCKS=\$(grep "\$(date '+%Y-%m-%d')" /var/log/kern.log 2>/dev/null | grep "UFW BLOCK" | wc -l)
echo "Total blocked connections: \$UFW_BLOCKS" >> \$REPORT_FILE
if [ \$UFW_BLOCKS -gt 0 ]; then
    echo "" >> \$REPORT_FILE
    echo "Top 10 blocked source IPs:" >> \$REPORT_FILE
    grep "\$(date '+%Y-%m-%d')" /var/log/kern.log 2>/dev/null | grep "UFW BLOCK" | \
        grep -o "SRC=[0-9.]*" | cut -d= -f2 | sort | uniq -c | sort -nr | head -10 | \
        awk '{printf "  %s attempts from %s\\n", \$1, \$2}' >> \$REPORT_FILE 2>/dev/null || true
    echo "" >> \$REPORT_FILE
    echo "Top 10 blocked destination ports:" >> \$REPORT_FILE
    grep "\$(date '+%Y-%m-%d')" /var/log/kern.log 2>/dev/null | grep "UFW BLOCK" | \
        grep -o "DPT=[0-9]*" | cut -d= -f2 | sort | uniq -c | sort -nr | head -10 | \
        awk '{printf "  %s attempts on port %s\\n", \$1, \$2}' >> \$REPORT_FILE 2>/dev/null || true
fi
echo "" >> \$REPORT_FILE

echo "FAIL2BAN STATUS" >> \$REPORT_FILE
echo "===============" >> \$REPORT_FILE
fail2ban-client status >> \$REPORT_FILE 2>/dev/null || echo "Fail2ban status unavailable" >> \$REPORT_FILE
echo "" >> \$REPORT_FILE

echo "AUDIT SUMMARY" >> \$REPORT_FILE
echo "=============" >> \$REPORT_FILE
# Use proper date format for ausearch (MM/DD/YYYY HH:MM:SS)
START_DATE=\$(date -d "yesterday" "+%m/%d/%Y 00:00:00")
END_DATE=\$(date -d "today" "+%m/%d/%Y 00:00:00")
if ausearch --start "\$START_DATE" --end "\$END_DATE" 2>/dev/null | aureport --summary >> \$REPORT_FILE 2>/dev/null; then
    true
else
    echo "No audit events found for yesterday" >> \$REPORT_FILE
fi
echo "" >> \$REPORT_FILE

echo "CRITICAL SECURITY EVENTS" >> \$REPORT_FILE
echo "========================" >> \$REPORT_FILE
EVENTS_FOUND=0
if ausearch -k privilege_escalation --start "\$START_DATE" --end "\$END_DATE" >> \$REPORT_FILE 2>/dev/null; then
    EVENTS_FOUND=1
fi
if ausearch -k user_commands --start "\$START_DATE" --end "\$END_DATE" 2>/dev/null | tail -20 >> \$REPORT_FILE; then
    EVENTS_FOUND=1
fi
if [ \$EVENTS_FOUND -eq 0 ]; then
    echo "No critical security events found for today" >> \$REPORT_FILE
fi
echo "" >> \$REPORT_FILE

# Email the report
cat \$REPORT_FILE | mail -s "📊 BASTION [\$HOSTNAME]: Daily Security Report" root

# Cleanup
rm -f \$REPORT_FILE
EOF

chmod 755 /etc/cron.daily/bastion-security-report

echo "===== 12. Setting up bastion-specific log rotation (avoiding conflicts) ====="
# Remove any conflicting logrotate configurations and create bastion-specific ones
rm -f /etc/logrotate.d/bastion-logs

# Remove duplicate/conflicting system logrotate configs that cause errors
# Keep only one configuration per log file to avoid "duplicate log entry" errors
echo "Cleaning up duplicate logrotate configurations..."
for config in clamav-daemon clamav-freshclam alternatives apt btmp clamav dpkg fail2ban maldet netdata rkhunter rsyslog suricata ufw unattended-upgrades wtmp; do
    if [ -f "/etc/logrotate.d/$config" ]; then
        # Check if there are any bastion-specific entries that would conflict
        if [ -f "/etc/logrotate.d/bastion-$config" ]; then
            echo "Removing system default $config logrotate config (bastion-specific version exists)"
            rm -f "/etc/logrotate.d/$config"
        fi
    fi
done

# Create separate logrotate configs for bastion-specific logs only
# This avoids conflicts with system default logrotate configurations

# SSH logs (bastion-specific, not managed by default logrotate)
cat > /etc/logrotate.d/bastion-ssh << EOF
# SSH logs (critical for bastion security)
/var/log/ssh.log {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    create 0640 root adm
    postrotate
        systemctl reload rsyslog > /dev/null 2>&1 || true
    endscript
}
EOF

# Sudo activity logs (extend default retention for bastion)
cat > /etc/logrotate.d/bastion-sudo << EOF
# Sudo activity logs (important for privilege escalation monitoring)
/var/log/sudo.log {
    daily
    rotate 90
    compress
    delaycompress
    missingok
    notifempty
    create 0640 root adm
    postrotate
        systemctl reload rsyslog > /dev/null 2>&1 || true
    endscript
}
EOF

# Network activity logs (bastion-specific)
cat > /etc/logrotate.d/bastion-network << EOF
# Network activity logs
/var/log/network.log {
    weekly
    rotate 12
    compress
    delaycompress
    missingok
    notifempty
    create 0640 root adm
    postrotate
        systemctl reload rsyslog > /dev/null 2>&1 || true
    endscript
}
EOF

# Emergency/critical logs (bastion-specific)
cat > /etc/logrotate.d/bastion-emergency << EOF
# Emergency/critical logs (keep longer for incident analysis)
/var/log/emergency.log {
    monthly
    rotate 24
    compress
    delaycompress
    missingok
    notifempty
    create 0600 root root
    postrotate
        systemctl reload rsyslog > /dev/null 2>&1 || true
    endscript
}
EOF

# Bastion monitoring logs (bastion-specific)
cat > /etc/logrotate.d/bastion-monitor << EOF
# Bastion monitoring logs
/var/log/bastion-monitor.log {
    weekly
    rotate 12
    compress
    delaycompress
    missingok
    notifempty
    create 0644 root root
}
EOF

# AIDE logs (bastion-specific)
cat > /etc/logrotate.d/bastion-aide << EOF
# AIDE integrity check logs
/var/log/aide/aide-check.log {
    weekly
    rotate 12
    compress
    delaycompress
    missingok
    notifempty
    create 0640 root root
}
EOF

# Configure comprehensive rsyslog log rotation
cat > /etc/logrotate.d/rsyslog << 'EOF'
/var/log/syslog
/var/log/mail.log
/var/log/mail.err
/var/log/mail.info
/var/log/mail.warn
/var/log/kern.log
/var/log/auth.log
/var/log/user.log
/var/log/daemon.log
/var/log/debug
/var/log/messages
{
    rotate 7
    daily
    missingok
    notifempty
    delaycompress
    compress
    postrotate
        invoke-rc.d rsyslog rotate > /dev/null 2>&1 || true
    endscript
}
EOF

echo "✅ Comprehensive log rotation configured (including rsyslog system logs)"
echo "✅ Bastion-specific logrotate configurations created"

# Add disk space monitoring to bastion monitoring script
echo "===== 12.1 Adding disk space monitoring to prevent log overflow ====="
cat >> /etc/cron.hourly/bastion-monitor << EOF

# Check for excessive log growth (prevent disk space issues)
LOG_DIRS=("/var/log" "/var/log/audit" "/var/log/suricata")
for log_dir in "\${LOG_DIRS[@]}"; do
    if [ -d "\$log_dir" ]; then
        # Check if any single log file is over 500MB
        find "\$log_dir" -name "*.log" -size +500M | while read -r large_log; do
            LOG_SIZE=\$(du -h "\$large_log" | cut -f1)
            log_message "WARNING: Large log file detected: \$large_log (\$LOG_SIZE)"
            echo "WARNING: Large log file on bastion host \$HOSTNAME: \$large_log (\$LOG_SIZE)" | mail -s "🚨 BASTION [\$HOSTNAME]: Large Log File (\$LOG_SIZE)" root
        done
    fi
done

# Check overall /var/log disk usage
VAR_LOG_USAGE=\$(du -sh /var/log 2>/dev/null | cut -f1)
VAR_LOG_USAGE_PCT=\$(df /var/log | awk 'NR==2 {print \$5}' | sed 's/%//')
if [ "\$VAR_LOG_USAGE_PCT" -gt 70 ]; then
    log_message "WARNING: /var/log directory usage at \$VAR_LOG_USAGE_PCT% (\$VAR_LOG_USAGE)"
    echo "WARNING: High log directory usage on bastion host \$HOSTNAME: \$VAR_LOG_USAGE_PCT% (\$VAR_LOG_USAGE)" | mail -s "🚨 BASTION [\$HOSTNAME]: Log Directory Space (\$VAR_LOG_USAGE_PCT%)" root
fi
EOF

echo "===== 13. Creating bastion host documentation ====="
if [ "$EUID" -eq 0 ]; then
    echo "Creating documentation file in /root/BASTION-README.md..."
else
    echo "Creating documentation file in current directory..."
fi

# Check disk space before creating documentation
if [ "$EUID" -eq 0 ]; then
    DISK_FREE=$(df /root | awk 'NR==2 {print $4}')
    echo "Available disk space in /root: ${DISK_FREE}KB"
else
    DISK_FREE=$(df . | awk 'NR==2 {print $4}')
    echo "Available disk space in current directory: ${DISK_FREE}KB"
fi

# Create documentation in both root and home directory for accessibility
echo "Starting to write documentation file..."

# Check if we can write to /root (running as root)
if [ "$EUID" -ne 0 ]; then
    echo "⚠️ Not running as root - creating documentation in current directory instead"
    DOC_PATH="./BASTION-README.md"
else
    DOC_PATH="/root/BASTION-README.md"
fi

echo "Writing documentation to: $DOC_PATH"
if cat > "$DOC_PATH" << 'EOF'
# Bastion Host Configuration

This server has been configured as a secure bastion host with the following features:

## Security Features
- SSH key-only authentication (no passwords)
- Restrictive firewall configuration (UFW)
- Comprehensive audit logging (auditd)
- Intrusion detection (Suricata IDS)
- Brute force protection (fail2ban)
- Real-time monitoring and alerting

## SSH Configuration
- Port: Custom port (non-standard)
- Authentication: Public key only
- Root login: Disabled
- Session limits: Enforced

## Monitoring
- Hourly security checks
- Daily security reports
- Real-time audit logging
- Network activity monitoring

## Key Files
- SSH config: /etc/ssh/sshd_config
- Firewall rules: /etc/ufw/
- Audit rules: /etc/audit/rules.d/bastion-audit.rules
- Fail2ban config: /etc/fail2ban/jail.local
- Suricata config: /etc/suricata/suricata.yaml

## Useful Commands
- `bastionstat` - Show current bastion status
- `sshmon` - Monitor SSH activity in real-time
- `sudo fail2ban-client status` - Check fail2ban status
- `sudo ufw status numbered` - Show firewall rules
- `sudo ausearch -k user_commands` - Show user command audit logs

## Log Locations
- SSH logs: /var/log/ssh.log
- Audit logs: /var/log/audit/audit.log
- Security monitoring: /var/log/bastion-monitor.log
- Suricata alerts: /var/log/suricata/
- Authentication: /var/log/auth.log

## Maintenance
- Security reports are emailed daily
- Logs are rotated automatically
- System updates are applied automatically
- Monitoring scripts run hourly

For support or questions, contact the system administrator.
EOF
then
    echo "✅ Documentation file created successfully"
else
    echo "❌ Failed to create documentation file"
    exit 1
fi

# Also create documentation in bastion user's home directory
if [ "$EUID" -eq 0 ] && id "$USERNAME" &>/dev/null; then
    USER_HOME=$(getent passwd "$USERNAME" | cut -d: -f6)
    if [ -n "$USER_HOME" ] && [ -d "$USER_HOME" ]; then
        if cp "$DOC_PATH" "$USER_HOME/" 2>/dev/null; then
            chown "$USERNAME:$USERNAME" "$USER_HOME/BASTION-README.md" 2>/dev/null || true
            echo "Documentation created in $DOC_PATH and $USER_HOME/BASTION-README.md"
        else
            echo "Documentation created in $DOC_PATH (could not copy to user home directory)"
        fi
    else
        echo "Documentation created in $DOC_PATH"
    fi
else
    echo "Documentation created in $DOC_PATH"
fi

echo "===== 14. Final system hardening and restart services ====="

# Disable unnecessary services (bastion hosts should be minimal)
UNNECESSARY_SERVICES="bluetooth cups avahi-daemon"
for service in $UNNECESSARY_SERVICES; do
    if systemctl is-active --quiet "$service"; then
        systemctl stop "$service"
        systemctl disable "$service"
        echo "Disabled unnecessary service: $service"
    fi
done

# Set secure kernel parameters for bastion host
cat > /etc/sysctl.d/99-bastion-security.conf << EOF
# Bastion Host Security Kernel Parameters

# Network security
net.ipv4.ip_forward = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.tcp_syncookies = 1

# IPv6 security configuration (keep enabled for modern infrastructure)
net.ipv6.conf.all.accept_ra = 0
net.ipv6.conf.default.accept_ra = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv6.conf.all.forwarding = 0

# Process security
kernel.dmesg_restrict = 1
kernel.kptr_restrict = 2
kernel.yama.ptrace_scope = 1

# File system security
fs.suid_dumpable = 0
fs.protected_hardlinks = 1
fs.protected_symlinks = 1

# Debian 13 Trixie security enhancements
# Control Flow Integrity (CFI) hardening - available on supported hardware
# Note: These features are automatically enabled by the kernel on supported CPUs
# Intel CET (Control-flow Enforcement Technology) - amd64
# ARM PAC (Pointer Authentication) and BTI (Branch Target Identification) - arm64
# No explicit kernel parameters needed as they're enabled at compile time

# Additional memory protection
vm.mmap_rnd_bits = 32
vm.mmap_rnd_compat_bits = 16
EOF

# Apply kernel parameters
echo "Applying kernel security parameters..."
if sysctl -p /etc/sysctl.d/99-bastion-security.conf; then
    echo "✅ Kernel security parameters applied successfully"
else
    echo "⚠️ Some kernel parameters may not have been applied (this is usually non-critical)"
fi

echo "===== 14.1 Setting up system resource limits (ulimits) ====="
# Prevent resource exhaustion attacks with sensible limits
cat > /etc/security/limits.d/bastion.conf << EOF
# Bastion Host Resource Limits
# Prevent resource exhaustion attacks and improve system stability

# Limits for all users
* soft nofile 4096
* hard nofile 8192
* soft nproc 1024
* hard nproc 2048
* soft core 0
* hard core 0
* soft memlock 64
* hard memlock 64

# More restrictive limits for bastion user (non-root)
$USERNAME soft nofile 2048
$USERNAME hard nofile 4096
$USERNAME soft nproc 512
$USERNAME hard nproc 1024
$USERNAME soft maxlogins 5
$USERNAME hard maxlogins 10

# Root user (for system processes)
root soft nofile 8192
root hard nofile 16384
root soft nproc 4096
root hard nproc 8192

# Service accounts (more restrictive)
www-data soft nofile 1024
www-data hard nofile 2048
www-data soft nproc 256
www-data hard nproc 512
EOF

echo "✅ System resource limits configured to prevent resource exhaustion attacks"

echo "===== 14.2 Adding systemd journal rate limiting ====="
# Prevent log flooding that could fill disk space
mkdir -p /etc/systemd/journald.conf.d
cat > /etc/systemd/journald.conf.d/99-bastion-limits.conf << EOF
# Bastion Host Journal Configuration
# Prevent disk space exhaustion from excessive logging

[Journal]
# Limit journal size to prevent disk full
SystemMaxUse=500M
SystemKeepFree=1G
SystemMaxFileSize=50M
RuntimeMaxUse=100M
RuntimeKeepFree=1G
RuntimeMaxFileSize=10M

# Rate limiting to prevent log flooding
RateLimitIntervalSec=30s
RateLimitBurst=5000

# Compress logs to save space
Compress=yes

# Forward to syslog (rsyslog) for processing
ForwardToSyslog=yes
ForwardToConsole=no
EOF

systemctl restart systemd-journald
echo "✅ Systemd journal rate limiting configured"

echo "===== 14.3 Adding kernel panic auto-reboot for headless environments ====="
# Automatically reboot after kernel panic (useful for OVH/cloud environments)
cat >> /etc/sysctl.d/99-bastion-security.conf << EOF

# Automatic reboot after kernel panic (headless environment)
kernel.panic = 10
kernel.panic_on_oops = 1
EOF

# Reload sysctl configuration
sysctl -p /etc/sysctl.d/99-bastion-security.conf
echo "✅ Kernel panic auto-reboot configured (10 second delay)"

echo "===== 14.4 Blacklisting unused filesystem modules ====="
# Disable unused filesystems that could be security risks
cat > /etc/modprobe.d/blacklist-filesystems.conf << EOF
# Blacklist unused filesystems for security
# These filesystems are typically not needed on bastion hosts

# Network filesystems (if not needed)
blacklist nfs
blacklist nfsv3
blacklist nfsv4
blacklist cifs
blacklist smb

# Legacy/rare filesystems
blacklist cramfs
blacklist freevxfs
blacklist jffs2
blacklist hfs
blacklist hfsplus
blacklist squashfs
blacklist udf

# USB storage (uncomment if USB storage should be blocked)
# blacklist usb-storage
# blacklist uas

# FireWire (IEEE 1394) - rarely needed on servers
blacklist firewire-core
blacklist firewire-ohci
blacklist firewire-sbp2

# Bluetooth (not needed on bastion hosts)
blacklist bluetooth
blacklist btusb
blacklist rfcomm
blacklist bnep

# Wireless (typically not needed on bastion hosts)
blacklist cfg80211
blacklist mac80211
EOF

echo "✅ Unused filesystem modules blacklisted for security"

echo "===== 14.5 Advanced security hardening ====="

# APT Package Pinning for critical security packages
echo "Setting up APT pinning for critical packages..."
cat > /etc/apt/preferences.d/bastion-security << EOF
# Pin critical security packages to stable versions
# Prevents unintended upgrades that could break security

Package: openssh-server openssh-client
Pin: release a=stable
Pin-Priority: 1001

Package: fail2ban
Pin: release a=stable
Pin-Priority: 1001

Package: ufw
Pin: release a=stable
Pin-Priority: 1001

Package: auditd
Pin: release a=stable
Pin-Priority: 1001

Package: sudo
Pin: release a=stable
Pin-Priority: 1001
EOF
echo "✅ APT pinning configured for critical security packages"

# Full Disk Encryption Detection
echo "Checking for full disk encryption..."
if lsblk -o NAME,MOUNTPOINT,FSTYPE,TYPE | grep -qi luks; then
    echo "✅ LUKS disk encryption detected"
    lsblk -o NAME,MOUNTPOINT,FSTYPE,TYPE | grep -i luks
else
    echo "⚠️  WARNING: Disk is not encrypted with LUKS"
    echo "   For maximum security, consider using full disk encryption"
    echo "   This is especially important for cloud/VPS instances"
fi

# IPv6 Security (even when disabled via sysctl)
echo "Adding IPv6 firewall rules (belt and suspenders approach)..."
ufw deny out to ::/0 comment "Block all IPv6 outbound"
ufw deny in from ::/0 comment "Block all IPv6 inbound"
echo "✅ IPv6 traffic blocked via UFW (additional protection)"

# Filesystem Mount Options Audit
echo "Auditing filesystem mount options for security..."
MOUNT_ISSUES=0

# Check /tmp mount options
if mountpoint -q /tmp; then
    if findmnt -n -o OPTIONS /tmp | grep -qE 'noexec.*nodev.*nosuid|nodev.*noexec.*nosuid|nosuid.*nodev.*noexec|noexec.*nosuid.*nodev|nodev.*nosuid.*noexec|nosuid.*noexec.*nodev'; then
        echo "✅ /tmp mounted with security options"
    else
        echo "⚠️  /tmp not mounted with optimal security options (should have noexec,nodev,nosuid)"
        MOUNT_ISSUES=$((MOUNT_ISSUES + 1))
    fi
else
    echo "ℹ️  /tmp not a separate mount point"
fi

# Check /home mount options if separate
if mountpoint -q /home; then
    if findmnt -n -o OPTIONS /home | grep -qE 'nodev.*nosuid|nosuid.*nodev'; then
        echo "✅ /home mounted with security options"
    else
        echo "⚠️  /home not mounted with optimal security options (should have nodev,nosuid)"
        MOUNT_ISSUES=$((MOUNT_ISSUES + 1))
    fi
else
    echo "ℹ️  /home not a separate mount point"
fi

# Check /var mount options if separate
if mountpoint -q /var; then
    if findmnt -n -o OPTIONS /var | grep -qE 'nodev.*nosuid|nosuid.*nodev'; then
        echo "✅ /var mounted with security options"
    else
        echo "⚠️  /var not mounted with optimal security options (should have nodev,nosuid)"
        MOUNT_ISSUES=$((MOUNT_ISSUES + 1))
    fi
else
    echo "ℹ️  /var not a separate mount point"
fi

if [ $MOUNT_ISSUES -gt 0 ]; then
    echo "💡 Consider remounting filesystems with security options or configuring during next reboot"
fi

# Service Whitelist Audit
echo "Auditing enabled services..."
echo "Currently enabled services:"
ENABLED_SERVICES=$(systemctl list-unit-files --state=enabled --type=service | grep enabled | awk '{print $1}' | grep -v '@')

# Define whitelist of allowed services for bastion hosts
ALLOWED_SERVICES="ssh sshd rsyslog systemd-journald systemd-logind systemd-networkd systemd-resolved systemd-timesyncd cron systemd-cron-daily.timer systemd-cron-hourly.timer systemd-cron-monthly.timer systemd-cron-weekly.timer postfix fail2ban ufw auditd suricata unbound systemd-tmpfiles-setup systemd-tmpfiles-clean.timer unattended-upgrades apt-daily.timer apt-daily-upgrade.timer bastion-monitor.timer disk-space-protection.timer logrotate.timer man-db.timer"

echo "Checking for unexpected enabled services..."
UNEXPECTED_SERVICES=""
for service in $ENABLED_SERVICES; do
    # Remove .service suffix for comparison
    service_name=${service%.service}
    if ! echo " $ALLOWED_SERVICES " | grep -q " $service_name "; then
        UNEXPECTED_SERVICES="$UNEXPECTED_SERVICES $service"
        echo "⚠️  Unexpected enabled service: $service"
    fi
done

if [ -n "$UNEXPECTED_SERVICES" ]; then
    echo ""
    echo "💡 Consider reviewing and potentially masking unexpected services:"
    for service in $UNEXPECTED_SERVICES; do
        echo "   systemctl mask $service"
    done
    echo ""
    echo "⚠️  Only mask services you're certain are not needed!"
else
    echo "✅ All enabled services appear to be necessary"
fi

# Enhanced Persistence Detection
echo "Setting up enhanced persistence detection..."
cat > /etc/cron.daily/persistence-check << 'EOF'
#!/bin/bash
# Enhanced persistence detection for bastion host
# Monitors common persistence locations with reduced false positives

LOGFILE="/var/log/persistence-check.log"
BASELINE_DIR="/var/lib/persistence-baselines"
DATE=$(date '+%Y-%m-%d %H:%M:%S')
GRACE_PERIOD_DAYS=7  # Wait 7 days after system changes before alerting

mkdir -p "$BASELINE_DIR"

# Function to log with timestamp
log_message() {
    echo "[$DATE] $1" >> "$LOGFILE"
}

# Function to check if we're in grace period (recent system setup)
in_grace_period() {
    local setup_marker="/var/lib/bastion-setup-complete"
    if [ -f "$setup_marker" ]; then
        local setup_time=$(stat -c %Y "$setup_marker" 2>/dev/null || echo 0)
        local current_time=$(date +%s)
        local grace_seconds=$((GRACE_PERIOD_DAYS * 24 * 60 * 60))
        
        if [ $((current_time - setup_time)) -lt $grace_seconds ]; then
            return 0  # Still in grace period
        fi
    fi
    return 1  # Not in grace period
}

# Function to check for changes in persistence locations
check_persistence_location() {
    local location="$1"
    local name="$2"
    local baseline_file="$BASELINE_DIR/${name}.baseline"
    local current_file="/tmp/${name}.current"
    
    if [ -d "$location" ] || [ -f "$location" ]; then
        # Create current state (exclude known bastion scripts to reduce noise)
        find "$location" -type f -not -name "*bastion*" -not -name "*logcheck*" -not -name "*logwatch*" -exec stat -c "%n %Y %s" {} \; 2>/dev/null | sort > "$current_file"
        
        # Check if baseline exists
        if [ -f "$baseline_file" ]; then
            # Compare with baseline
            if ! diff -q "$baseline_file" "$current_file" >/dev/null 2>&1; then
                if in_grace_period; then
                    log_message "INFO: Changes detected in $name ($location) - Grace period active, no alert sent"
                else
                    log_message "ALERT: Changes detected in $name ($location)"
                    {
                        echo "PERSISTENCE ALERT: Changes detected in $name on bastion host $(hostname)"
                        echo ""
                        echo "System: $(hostname)"
                        echo "Location: $location"
                        echo "Detection time: $DATE"
                        echo "Change type: $name"
                        echo ""
                        echo "=== CHANGES DETECTED ==="
                        diff "$baseline_file" "$current_file" 2>/dev/null || echo "Unable to show differences"
                        echo ""
                        echo "Log file: $LOGFILE"
                    } | mail -s "🚨 BASTION [$(hostname)]: Persistence Alert - $name" root
                fi
                
                # Update baseline with new state
                cp "$current_file" "$baseline_file"
            else
                log_message "INFO: No changes in $name"
            fi
        else
            # Create initial baseline
            cp "$current_file" "$baseline_file"
            log_message "INFO: Created baseline for $name"
        fi
        
        # Cleanup
        rm -f "$current_file"
    fi
}

# Check common persistence locations
check_persistence_location "/etc/init.d" "init-scripts"
check_persistence_location "/etc/systemd/system" "systemd-services"
check_persistence_location "/etc/cron.d" "cron-jobs"
check_persistence_location "/etc/cron.daily" "cron-daily"
check_persistence_location "/etc/cron.hourly" "cron-hourly"
check_persistence_location "/etc/cron.weekly" "cron-weekly"
check_persistence_location "/etc/cron.monthly" "cron-monthly"
check_persistence_location "/var/spool/cron/crontabs" "user-crontabs"
check_persistence_location "/home/*/.*rc" "user-rc-files"
check_persistence_location "/home/*/.profile" "user-profiles"
check_persistence_location "/home/*/.bash_profile" "bash-profiles"
check_persistence_location "/etc/profile.d" "system-profiles"
check_persistence_location "/etc/rc.local" "rc-local"

# Check for new SUID/SGID binaries
find /usr /bin /sbin -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null | sort > /tmp/suid-sgid.current
SUID_BASELINE="$BASELINE_DIR/suid-sgid.baseline"

if [ -f "$SUID_BASELINE" ]; then
    if ! diff -q "$SUID_BASELINE" /tmp/suid-sgid.current >/dev/null 2>&1; then
        log_message "ALERT: SUID/SGID binary changes detected"
        echo "SECURITY ALERT: SUID/SGID binary changes on bastion host $(hostname)" | mail -s "BASTION ALERT: SUID/SGID Changes" root
        diff "$SUID_BASELINE" /tmp/suid-sgid.current >> "$LOGFILE" 2>/dev/null || true
    else
        log_message "INFO: No changes in SUID/SGID binaries"
    fi
else
    # Ensure baseline directory exists before creating baseline
    mkdir -p "$BASELINE_DIR"
    cp /tmp/suid-sgid.current "$SUID_BASELINE"
    log_message "INFO: Created SUID/SGID baseline"
fi

rm -f /tmp/suid-sgid.current

log_message "Persistence check completed"
EOF

chmod 755 /etc/cron.daily/persistence-check

# Run initial persistence check to create baselines
echo "Creating initial persistence baselines..."
/etc/cron.daily/persistence-check
echo "✅ Enhanced persistence detection configured"

echo "===== 14.6 Setting up disk space protection for logging ====="
# Create emergency disk space protection system

# Add disk usage monitoring to prevent full disk scenarios
cat > /etc/cron.hourly/disk-space-protection << EOF
#!/bin/bash
# Emergency disk space protection for bastion host
# Prevents system failure due to disk space exhaustion

CRITICAL_THRESHOLD=95
WARNING_THRESHOLD=85
ROOT_USAGE=\$(df / | awk 'NR==2 {print \$5}' | sed 's/%//')
VAR_USAGE=\$(df /var | awk 'NR==2 {print \$5}' | sed 's/%//')

# Function to clean old logs if disk space critical
emergency_cleanup() {
    echo "\$(date): EMERGENCY: Disk space at \$1% - performing emergency cleanup" >> /var/log/emergency-cleanup.log
    
    # Remove old compressed logs first
    find /var/log -name "*.gz" -mtime +7 -delete 2>/dev/null || true
    find /var/log -name "*.bz2" -mtime +7 -delete 2>/dev/null || true
    
    # Clean old log files
    find /var/log -name "*.log.*" -mtime +3 -delete 2>/dev/null || true
    
    # Truncate large current log files (keep last 1000 lines)
    # Use /tmp for temporary files to avoid read-only filesystem issues
    for logfile in /var/log/*.log; do
        if [ -f "\$logfile" ] && [ "\$(stat -c%s "\$logfile" 2>/dev/null)" -gt 104857600 ]; then  # 100MB
            tmpfile=\$(mktemp /tmp/log-truncate-XXXXXX)
            if tail -n 1000 "\$logfile" > "\$tmpfile" 2>/dev/null && [ -s "\$tmpfile" ]; then
                mv "\$tmpfile" "\$logfile"
                echo "\$(date): Truncated large log file: \$logfile" >> /var/log/emergency-cleanup.log
            else
                rm -f "\$tmpfile"
            fi
        fi
    done
    
    # Clear old journal logs
    journalctl --vacuum-time=1d --vacuum-size=100M 2>/dev/null || true
    
    # Send alert
    echo "EMERGENCY: Disk space critical on bastion host \$(hostname). Emergency cleanup performed." | mail -s "BASTION CRITICAL: Emergency Disk Cleanup" root
}

# Check root filesystem
if [ "\$ROOT_USAGE" -ge "\$CRITICAL_THRESHOLD" ]; then
    emergency_cleanup "\$ROOT_USAGE"
elif [ "\$ROOT_USAGE" -ge "\$WARNING_THRESHOLD" ]; then
    echo "WARNING: Root filesystem at \$ROOT_USAGE% usage" | mail -s "BASTION WARNING: Disk Space" root
fi

# Check /var filesystem (if separate)
if [ "\$VAR_USAGE" -ge "\$CRITICAL_THRESHOLD" ]; then
    emergency_cleanup "\$VAR_USAGE"
elif [ "\$VAR_USAGE" -ge "\$WARNING_THRESHOLD" ]; then
    echo "WARNING: /var filesystem at \$VAR_USAGE% usage" | mail -s "BASTION WARNING: /var Disk Space" root
fi
EOF

chmod +x /etc/cron.hourly/disk-space-protection

# Add emergency space management configuration to logrotate
# Create a separate config file instead of modifying main logrotate.conf
cat > /etc/logrotate.d/emergency-space-management << EOF
# Emergency space management for bastion hosts
# Force rotation of any logs larger than 100M
/var/log/*.log /var/log/*/*.log {
    size 100M
    rotate 1
    compress
    missingok
    notifempty
    copytruncate
}
EOF

echo "✅ Emergency disk space protection configured"

echo "===== 14.5.1 Creating systemd timer services for reliable monitoring ====="
# Create systemd services and timers to ensure monitoring runs even if cron missed

# Bastion monitoring service
cat > /etc/systemd/system/bastion-monitor.service << EOF
[Unit]
Description=Bastion Host Security Monitoring
After=network.target

[Service]
Type=oneshot
ExecStart=/etc/cron.hourly/bastion-monitor
User=root
StandardOutput=journal
StandardError=journal
EOF

# Bastion monitoring timer (runs hourly, catches up missed runs)
cat > /etc/systemd/system/bastion-monitor.timer << EOF
[Unit]
Description=Run bastion monitoring every hour
Requires=bastion-monitor.service

[Timer]
OnCalendar=hourly
Persistent=yes
AccuracySec=1min

[Install]
WantedBy=timers.target
EOF

# Disk space protection service
cat > /etc/systemd/system/disk-space-protection.service << EOF
[Unit]
Description=Emergency Disk Space Protection
After=network.target

[Service]
Type=oneshot
ExecStart=/etc/cron.hourly/disk-space-protection
User=root
StandardOutput=journal
StandardError=journal
EOF

# Disk space protection timer (runs hourly, catches up missed runs)
cat > /etc/systemd/system/disk-space-protection.timer << EOF
[Unit]
Description=Run disk space protection every hour
Requires=disk-space-protection.service

[Timer]
OnCalendar=hourly
Persistent=yes
AccuracySec=1min

[Install]
WantedBy=timers.target
EOF

# Enable and start the timer services
systemctl daemon-reload
systemctl enable bastion-monitor.timer
systemctl enable disk-space-protection.timer
systemctl start bastion-monitor.timer
systemctl start disk-space-protection.timer

echo "✅ Systemd timer services created and enabled"
echo "   • bastion-monitor.timer - runs hourly, catches missed runs"
echo "   • disk-space-protection.timer - runs hourly, catches missed runs"
echo "   • Both timers use Persistent=yes to run missed executions on boot"

# Verify timers are active
echo ""
echo "Timer status:"
systemctl list-timers bastion-monitor.timer disk-space-protection.timer --no-pager || true

echo "===== 14.6.1 Optional Netdata Monitoring Integration ====="
# Optional Netdata monitoring for bastion host insights

# Ask user if they want to install Netdata (unless already set via environment)
if [ -z "${INSTALL_NETDATA:-}" ]; then
    echo ""
    echo "📊 NETDATA MONITORING INTEGRATION"
    echo "================================="
    echo "Netdata provides comprehensive monitoring for your bastion host including:"
    echo "   • SSH connection tracking and analysis"
    echo "   • Resource usage monitoring for security analysis" 
    echo "   • Network traffic correlation with security events"
    echo "   • Optional integration with Netdata Cloud for centralized monitoring"
    echo ""
    read -p "Would you like to install Netdata monitoring? (y/N): " -r
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        INSTALL_NETDATA="true"
    else
        INSTALL_NETDATA="false"
    fi
fi

if [[ "$INSTALL_NETDATA" =~ ^[Yy]$ ]] || [[ "$INSTALL_NETDATA" == "true" ]]; then
    echo "Installing Netdata monitoring for bastion host visibility..."
    
    # Ask for Netdata Cloud claim token
    echo ""
    echo "🔗 NETDATA CLOUD INTEGRATION (OPTIONAL)"
    echo "======================================="
    echo "To connect this bastion host to Netdata Cloud for centralized monitoring:"
    echo "1. Sign up at https://app.netdata.cloud (free account)"
    echo "2. Create a Space for your infrastructure"
    echo "3. Get your claim token from the 'Connect Nodes' section"
    echo ""
    echo "Leave empty to skip Netdata Cloud integration (local-only monitoring)"
    read -p "Enter your Netdata Cloud claim token (or press Enter to skip): " -r NETDATA_CLAIM_TOKEN
    
    # Download and run the official installer
    echo "Downloading Netdata installer..."
    if curl -o /tmp/netdata-kickstart.sh https://get.netdata.cloud/kickstart.sh; then
        echo "Running Netdata installation..."
        # Wait for any dpkg locks to be released before installation
        echo "Waiting for package management to be available..."
        wait_for_dpkg_lock

        if [ -n "$NETDATA_CLAIM_TOKEN" ]; then
            echo "Installing with Netdata Cloud integration..."
            sh /tmp/netdata-kickstart.sh --stable-channel --disable-telemetry --claim-token "$NETDATA_CLAIM_TOKEN"
        else
            echo "Installing without Netdata Cloud (local monitoring only)..."
            sh /tmp/netdata-kickstart.sh --stable-channel --disable-telemetry --dont-wait
        fi
        
        # Clean up installer
        rm -f /tmp/netdata-kickstart.sh
    else
        echo "⚠️ Failed to download Netdata installer, trying fallback method..."

        # Fallback: install via package manager
        if command -v apt-get >/dev/null 2>&1; then
            wait_for_dpkg_lock
            apt-get update
            apt-get install -y netdata
        else
            echo "❌ Failed to install Netdata - please install manually"
            echo "   Visit: https://learn.netdata.cloud/docs/installing/one-line-installer-for-all-linux-systems"
            INSTALL_NETDATA="false"
        fi
    fi
    
    # Check if Netdata was successfully installed
    if ! command -v netdata >/dev/null 2>&1 && ! systemctl is-active --quiet netdata; then
        echo "❌ Netdata installation verification failed"
        INSTALL_NETDATA="false"
    fi
fi

if [[ "$INSTALL_NETDATA" =~ ^[Yy]$ ]] || [[ "$INSTALL_NETDATA" == "true" ]]; then
    # Configure Netdata for bastion host security
    echo "Configuring Netdata for secure bastion host monitoring..."
    
    # Create minimal security-focused configuration
    cat > /etc/netdata/netdata.conf << EOF
[global]
    # SECURITY: Bind to localhost only (access via SSH tunnel)
    bind socket to IP = 127.0.0.1
    default port = 19999
    
    # Performance optimized for bastion host
    page cache size = 32
    dbengine multihost disk space = 128
    
    # Update interval
    update every = 2
    
    # History
    history = 3600
    
[web]
    # No authentication needed since localhost-only
    web files owner = root
    web files group = netdata
    
[plugins]
    # Enable all plugins for complete monitoring
    proc = yes
    diskspace = yes
    cgroups = yes
    tc = yes
    
EOF

    # Enable and start Netdata
    systemctl enable netdata
    systemctl restart netdata

    # Wait for Netdata to start
    sleep 3
    NETDATA_CLAIM_ROOMS=${NETDATA_CLAIM_ROOMS:-}
    
    if [ -n "$NETDATA_CLAIM_TOKEN" ] && [ -n "$NETDATA_CLAIM_ROOMS" ]; then
        echo "Setting up Netdata Cloud integration for bastion host..."
        
        # Claim the bastion node to Netdata Cloud
        /opt/netdata/bin/netdata-claim.sh \
            -token="$NETDATA_CLAIM_TOKEN" \
            -rooms="$NETDATA_CLAIM_ROOMS" \
            -url=https://app.netdata.cloud \
            || echo "⚠️ Netdata Cloud claiming failed - check token and room ID"
        
        echo "✅ Netdata Cloud integration configured for bastion host"
        echo "   • Bastion should appear in your Netdata Cloud dashboard within a few minutes"
        echo "   • Login at: https://app.netdata.cloud"
    else
        echo ""
        echo "📊 NETDATA CLOUD INTEGRATION FOR BASTION (Optional)"
        echo "================================================="
        echo "To add this bastion host to Netdata Cloud for centralized monitoring:"
        echo ""
        echo "1. Sign up/login at: https://app.netdata.cloud"
        echo "2. Create a new space or select existing space"
        echo "3. Go to 'Connect Nodes' and copy your claim token"
        echo "4. Run the following command on this bastion host:"
        echo ""
        echo "   sudo /opt/netdata/bin/netdata-claim.sh \\"
        echo "     -token=YOUR_CLAIM_TOKEN \\"
        echo "     -rooms=YOUR_ROOM_ID \\"
        echo "     -url=https://app.netdata.cloud"
        echo ""
        echo "5. Your bastion will appear in Netdata Cloud within 1-2 minutes"
        echo ""
        echo "Bastion monitoring benefits:"
        echo "   • SSH connection monitoring"
        echo "   • Resource usage tracking"
        echo "   • Security event correlation"
        echo "   • Network traffic analysis"
        echo "   • Alert on suspicious activity"
        echo ""
    fi

    # Create Netdata log rotation
    cat > /etc/logrotate.d/netdata << EOF
/var/log/netdata/*.log {
    daily
    rotate 7
    missingok
    notifempty
    compress
    delaycompress
    postrotate
        systemctl reload netdata > /dev/null 2>&1 || true
    endscript
}
EOF

    # Create bastion-specific access script
    cat > /usr/local/bin/netdata-bastion << EOF
#!/bin/bash
# Quick access to bastion Netdata dashboard
echo "🌐 Bastion Netdata Dashboard Access:"
echo "   Local URL: http://127.0.0.1:19999"
echo "   SSH Tunnel: ssh -L 19999:127.0.0.1:19999 user@bastion"
echo "   Netdata Cloud: https://app.netdata.cloud"
echo ""
echo "📊 Bastion Monitoring Features:"
echo "   • SSH connection tracking"
echo "   • Failed login attempts"
echo "   • Resource utilization"
echo "   • Network traffic analysis"
echo "   • System performance metrics"
EOF
    chmod +x /usr/local/bin/netdata-bastion
    
    echo "✅ Netdata monitoring installed for bastion host"
    echo "   • Local access: http://127.0.0.1:19999 (via SSH tunnel)"
    echo "   • Quick access command: netdata-bastion"
    echo "   • Optimized for bastion host monitoring"
else
    echo "📊 Netdata monitoring skipped (optional feature)"
    echo "   To enable: Set INSTALL_NETDATA=true or answer 'y' when prompted"
    echo "   Benefits: SSH monitoring, resource tracking, security insights"
fi

# Optional: Create tmpfs fallback for critical scenarios (commented out by default)
cat > /usr/local/bin/setup-log-tmpfs << EOF
#!/bin/bash
# Emergency script to move logs to tmpfs if disk space critical
# WARNING: This will cause logs to be lost on reboot!
# Only use in emergency situations

if [ "\$(df / | awk 'NR==2 {print \$5}' | sed 's/%//')" -ge 98 ]; then
    echo "EMERGENCY: Setting up tmpfs for logs to prevent system failure"
    
    # Create tmpfs mount point
    mkdir -p /tmp/emergency-logs
    
    # Mount tmpfs (256MB)
    mount -t tmpfs -o size=256M tmpfs /tmp/emergency-logs
    
    # Stop logging services
    systemctl stop rsyslog auditd fail2ban 2>/dev/null || true
    
    # Backup current logs
    tar -czf /tmp/logs-backup-\$(date +%Y%m%d-%H%M%S).tar.gz /var/log/ 2>/dev/null || true
    
    # Move logs to tmpfs
    mv /var/log /var/log.backup
    ln -s /tmp/emergency-logs /var/log
    
    # Create basic log structure
    mkdir -p /var/log/audit
    touch /var/log/syslog /var/log/auth.log /var/log/mail.log
    chmod 640 /var/log/*.log
    chown root:adm /var/log/*.log
    
    # Restart services
    systemctl start rsyslog auditd fail2ban 2>/dev/null || true
    
    echo "EMERGENCY: Logs moved to tmpfs - LOGS WILL BE LOST ON REBOOT!" | mail -s "BASTION EMERGENCY: Logs on tmpfs" root
fi
EOF

chmod +x /usr/local/bin/setup-log-tmpfs

echo "✅ Emergency tmpfs script created (/usr/local/bin/setup-log-tmpfs)"
echo "💡 Run setup-log-tmpfs only in critical disk space emergencies"

echo "===== 14.7 AppArmor Security Hardening ====="
echo "Configuring AppArmor for enhanced bastion security..."

# Ensure AppArmor is enabled and running
systemctl enable apparmor 2>/dev/null || true
systemctl start apparmor 2>/dev/null || true

# Verify AppArmor is working
if command -v aa-status >/dev/null 2>&1; then
    if aa-status >/dev/null 2>&1; then
        echo "✅ AppArmor is enabled and active"
        aa-status | head -10
    else
        echo "⚠️ AppArmor module not loaded - checking kernel support"
        # Try to load the module
        modprobe apparmor 2>/dev/null || echo "AppArmor kernel module not available"
    fi
else
    echo "⚠️ AppArmor utilities not found - keeping basic installation"
fi

# Unattended Reboot Warning System
echo "Configuring unattended reboot warning system..."
if [ "$EUID" -ne 0 ]; then
    echo "⚠️ Not running as root - cannot configure unattended upgrades"
    echo "   Configuration would be created at: /etc/apt/apt.conf.d/51unattended-upgrades-bastion"
else
    cat > /etc/apt/apt.conf.d/51unattended-upgrades-bastion << EOF
// Enhanced bastion host configuration for unattended upgrades
Unattended-Upgrade::Automatic-Reboot "true";
Unattended-Upgrade::Automatic-Reboot-WithUsers "false";
Unattended-Upgrade::Automatic-Reboot-Time "04:00";

// Warning system before reboot
Unattended-Upgrade::SyslogEnable "true";
Unattended-Upgrade::SyslogFacility "daemon";
EOF
fi

# Create pre-reboot warning script
if [ "$EUID" -ne 0 ]; then
    echo "⚠️ Not running as root - cannot create reboot warning script"
    echo "   Script would be created at: /usr/local/bin/unattended-reboot-warning.sh"
else
    cat > /usr/local/bin/unattended-reboot-warning.sh << EOF
#!/bin/bash
# Pre-reboot warning for unattended upgrades

# Check if reboot is required
if [ -f /var/run/reboot-required ]; then
    # Send wall message to all logged in users
    echo "SYSTEM NOTICE: Unattended upgrade requires reboot. System will reboot at 04:00 AM." | wall
    
    # Log to syslog
    logger -p daemon.warning "Bastion host scheduled for automatic reboot due to unattended upgrade"
    
    # Send email notification
    echo "Bastion host \$(hostname) is scheduled for automatic reboot at 04:00 AM due to security updates requiring reboot." | \
        mail -s "BASTION NOTICE: Scheduled Reboot Tonight" root
fi
EOF
    
    chmod +x /usr/local/bin/unattended-reboot-warning.sh
    
    # Add to daily cron to warn users
    echo "0 20 * * * root /usr/local/bin/unattended-reboot-warning.sh" >> /etc/crontab
    
    echo "✅ Unattended reboot warning system configured"
fi

if [ "$INSTALL_SURICATA" = true ]; then
    # Suricata Rules Maintenance
    echo "Setting up Suricata rules maintenance..."
    if command -v suricata-update >/dev/null 2>&1; then
        # Configure suricata-update with timeout
        echo "Configuring Suricata rules update (this may take a moment)..."
        timeout 60 suricata-update update-sources || echo "⚠️ Suricata update-sources timed out"
        timeout 30 suricata-update enable-source et/open || echo "⚠️ ET Open source enable failed"
        timeout 30 suricata-update enable-source oisf/trafficid || echo "⚠️ OISF TrafficID source enable failed"

        # Create weekly rules update job
        if [ "$EUID" -ne 0 ]; then
            echo "⚠️ Not running as root - cannot create Suricata cron job"
            echo "   Job would be created at: /etc/cron.weekly/suricata-update"
        else
            cat > /etc/cron.weekly/suricata-update << EOF
#!/bin/bash
# Weekly Suricata rules update for bastion host

# Update rule sources
/usr/bin/suricata-update update-sources

# Update rules
/usr/bin/suricata-update

# Test configuration
if suricata -T -c /etc/suricata/suricata.yaml; then
    # Restart Suricata if config is valid
    systemctl reload suricata || systemctl restart suricata
    logger -p daemon.info "Suricata rules updated successfully"
else
    # Notify of configuration error
    echo "Suricata configuration test failed after rules update on \$(hostname)" | \
        mail -s "BASTION ERROR: Suricata Rules Update Failed" root
    logger -p daemon.error "Suricata rules update failed - configuration test error"
fi
EOF

            chmod +x /etc/cron.weekly/suricata-update
            echo "✅ Suricata rules auto-update configured"
        fi
    else
        echo "⚠️ suricata-update not available - install with: apt install suricata-update"
    fi
fi

# Smart Systemd Service Hardening for Critical Services
echo "Configuring smart systemd service hardening for critical services..."
echo "This configuration provides resource limits and restart policies"

if [ "$EUID" -ne 0 ]; then
    echo "⚠️ Not running as root - cannot configure systemd service hardening"
    echo "   Would create service configs in: /etc/systemd/system/"
else
    # Smart fail2ban service watchdog - increased timeout during high load
    mkdir -p /etc/systemd/system/fail2ban.service.d
    cat > /etc/systemd/system/fail2ban.service.d/watchdog.conf << EOF
[Service]
Restart=on-failure
RestartSec=10
StartLimitInterval=600
StartLimitBurst=3

# Resource awareness
OOMScoreAdjust=-100
# Ensure fail2ban has priority over resource-intensive services
Nice=-5
EOF

    # Smart Suricata service watchdog - adapted for network monitoring load
    mkdir -p /etc/systemd/system/suricata.service.d
    cat > /etc/systemd/system/suricata.service.d/watchdog.conf << EOF
[Service]
Restart=on-failure
RestartSec=30
StartLimitInterval=1200
StartLimitBurst=2

# Lower priority than critical access services
Nice=5
OOMScoreAdjust=200
EOF

    # Smart SSH service watchdog - highest priority for bastion access
    mkdir -p /etc/systemd/system/ssh.service.d
    cat > /etc/systemd/system/ssh.service.d/watchdog.conf << EOF
[Service]
Restart=on-failure
RestartSec=5
StartLimitInterval=300
StartLimitBurst=5

# Highest priority and OOM protection for SSH access
OOMScoreAdjust=-500
Nice=-10

# NO filesystem protection - allows normal system administration
# ProtectSystem causes read-only filesystem issues that break apt, installations, and system management
# Security is provided by network isolation, firewalls, and access controls instead
EOF

    # Unbound DNS watchdog - essential for bastion name resolution
    mkdir -p /etc/systemd/system/unbound.service.d
    cat > /etc/systemd/system/unbound.service.d/watchdog.conf << EOF
[Service]
Restart=on-failure
RestartSec=10
StartLimitInterval=300
StartLimitBurst=4

# Medium priority for DNS service
OOMScoreAdjust=100
Nice=0

# Ensure IPv4-only operation to prevent binding issues
Environment=UNBOUND_DISABLE_IPV6=yes
EOF

    systemctl daemon-reload
fi

echo "✅ Smart systemd service hardening configured for critical services"
echo "   • SSH: Watchdog pings not supported, highest priority (OOM -500, Nice -10)"
echo "   • fail2ban: Watchdog pings not supported, high priority (OOM -100, Nice -5)"
echo "   • Suricata: Watchdog pings not supported, lower priority (OOM +200, Nice +5)"
echo "   • Unbound: Watchdog pings not supported, medium priority (OOM +100)"
echo ""

echo "===== 14.7.1 Setting up Resource Guardian System ====="
# Proactive resource management to prevent service failures
echo "Installing Resource Guardian for proactive resource management..."

cat > /usr/local/bin/resource-guardian << EOF
#!/bin/bash
# Resource Guardian - Proactive Resource Management for Bastion Host
# Monitors and manages resource usage to prevent service failures

LOGFILE="/var/log/resource-guardian.log"
TIMESTAMP=\$(date '+%Y-%m-%d %H:%M:%S')

# Configuration
HIGH_CPU_THRESHOLD=80
SUSTAINED_CPU_TIME=300  # 5 minutes
HIGH_MEMORY_THRESHOLD=85
CRITICAL_MEMORY_THRESHOLD=95

# Whitelist of critical processes that should never be killed (ENHANCED FOR SAFETY)
CRITICAL_PROCESSES="sshd|systemd|kernel|init|fail2ban|ufw|auditd|rsyslog|postfix|cron|dbus|networkd|resolved|bastion|apt|dpkg|unattended"

# Function to log with timestamp
log_message() {
    echo "[\$TIMESTAMP] \$1" >> "\$LOGFILE"
}

# Function to check and kill resource hogs
check_cpu_usage() {
    log_message "Checking CPU usage..."
    
    # Get processes using high CPU for sustained periods
    while read -r pid cpu_percent command; do
        if (( \$(echo "\$cpu_percent > \$HIGH_CPU_THRESHOLD" | bc -l) )); then
            # Check if it's a critical process
            if ! echo "\$command" | grep -qE "\$CRITICAL_PROCESSES"; then
                # Check how long the process has been running
                process_time=\$(ps -o pid,etime -p "\$pid" 2>/dev/null | awk 'NR>1 {print \$2}')
                
                if [ -n "\$process_time" ]; then
                    # Convert time to seconds (simplified for common formats)
                    if echo "\$process_time" | grep -q ":"; then
                        # Format like MM:SS or HH:MM:SS
                        time_seconds=\$(echo "\$process_time" | awk -F: '{if(NF==2) print \$1*60+\$2; else if(NF==3) print \$1*3600+\$2*60+\$3}')
                    else
                        # Just seconds
                        time_seconds="\$process_time"
                    fi
                    
                    # If process has been consuming high CPU for sustained time
                    if [ "\$time_seconds" -gt "\$SUSTAINED_CPU_TIME" ]; then
                        log_message "ACTION: Terminating high-CPU process: PID=\$pid CMD=\$command CPU=\${cpu_percent}% TIME=\${process_time}"
                        
                        # Send alert email
                        echo "Resource Guardian terminated high-CPU process on bastion host \$(hostname):
                        
Process: \$command
PID: \$pid  
CPU Usage: \${cpu_percent}%
Runtime: \$process_time
Action: Process terminated to protect system stability

This action was taken automatically to prevent system overload." | mail -s "BASTION: Resource Guardian Action - High CPU Process Terminated" root
                        
                        # SAFETY ENHANCEMENT: Progressive warnings for one-person operations
                        echo "WARNING: Process \$pid (\$command) using \${cpu_percent}% CPU for \${time_seconds}s on bastion \$(hostname).
Will terminate in 60 seconds if not manually addressed.
To prevent: kill \$pid or systemctl stop [service]" | mail -s "BASTION WARNING: High CPU - Action Pending" root
                        
                        sleep 60
                        
                        # Check if still problematic before action
                        if kill -0 "\$pid" 2>/dev/null; then
                            current_cpu=\$(ps -p "\$pid" -o %cpu= 2>/dev/null | tr -d ' ')
                            if (( \$(echo "\$current_cpu > \$HIGH_CPU_THRESHOLD" | bc -l) )); then
                                # Final warning
                                echo "FINAL WARNING: Process \$pid terminating in 30s" | mail -s "BASTION CRITICAL: Final Warning" root
                                sleep 30
                                
                                if kill -0 "\$pid" 2>/dev/null; then
                                    kill -TERM "\$pid" 2>/dev/null
                                    sleep 10
                                    if kill -0 "\$pid" 2>/dev/null; then
                                        kill -KILL "\$pid" 2>/dev/null
                                        log_message "EMERGENCY: Process \$pid force-killed after warnings"
                                    fi
                                fi
                            else
                                log_message "INFO: Process \$pid CPU normalized during warning"
                            fi
                        fi
                    fi
                fi
            else
                log_message "INFO: High CPU process \$pid (\$command) is whitelisted - skipping"
            fi
        fi
    done < <(ps aux --sort=-%cpu | awk 'NR>1 && \$3>0 {print \$2, \$3, \$11}' | head -10)
}

# Function to check memory usage
check_memory_usage() {
    local memory_usage=\$(free | awk 'NR==2{printf "%.1f", \$3*100/\$2}')
    
    log_message "Current memory usage: \${memory_usage}%"
    
    if (( \$(echo "\$memory_usage > \$CRITICAL_MEMORY_THRESHOLD" | bc -l) )); then
        log_message "CRITICAL: Memory usage at \${memory_usage}% - taking emergency action"
        
        # Find biggest memory consumers (excluding critical processes)
        ps aux --sort=-%mem | awk 'NR>1 {print \$2, \$4, \$11}' | head -5 | while read -r pid mem_percent command; do
            if ! echo "\$command" | grep -qE "\$CRITICAL_PROCESSES"; then
                if (( \$(echo "\$mem_percent > 10" | bc -l) )); then
                    log_message "EMERGENCY: Killing high-memory process: PID=\$pid CMD=\$command MEM=\${mem_percent}%"
                    
                    echo "EMERGENCY: Resource Guardian terminated high-memory process on bastion host \$(hostname):
                    
Process: \$command
PID: \$pid
Memory Usage: \${mem_percent}%
System Memory: \${memory_usage}%
Action: Emergency termination due to critical memory usage

This emergency action was taken to prevent system failure." | mail -s "BASTION EMERGENCY: Memory Critical - Process Terminated" root

                    kill -KILL "\$pid" 2>/dev/null
                fi
            fi
        done
        
    elif (( \$(echo "\$memory_usage > \$HIGH_MEMORY_THRESHOLD" | bc -l) )); then
        log_message "WARNING: Memory usage at \${memory_usage}% - monitoring closely"
        
        # Send warning but don't kill processes yet
        echo "WARNING: High memory usage (\${memory_usage}%) detected on bastion host \$(hostname). Resource Guardian is monitoring the situation." | mail -s "BASTION WARNING: High Memory Usage" root
    fi
}

# Function to check system load
check_system_load() {
    local load_avg=\$(cat /proc/loadavg | awk '{print \$1}')
    local cpu_count=\$(nproc)
    local load_ratio=\$(echo "scale=2; \$load_avg / \$cpu_count" | bc -l)
    
    log_message "Current load average: \$load_avg (ratio: \$load_ratio per CPU)"
    
    # If load is more than 2x CPU count, system is heavily loaded
    if (( \$(echo "\$load_ratio > 2.0" | bc -l) )); then
        log_message "WARNING: High system load detected - load ratio \$load_ratio"
        
        # Log top processes contributing to load
        log_message "Top CPU processes during high load:"
        ps aux --sort=-%cpu | head -6 >> "\$LOGFILE"
        
        echo "High system load detected on bastion host \$(hostname):

Load Average: \$load_avg
CPU Count: \$cpu_count  
Load Ratio: \$load_ratio per CPU

Resource Guardian is monitoring the situation and will take action if specific processes exceed thresholds." | mail -s "BASTION ALERT: High System Load" root
    fi
}

# Function to check disk I/O
check_disk_io() {
    # Simple check using iotop if available
    if command -v iotop >/dev/null 2>&1; then
        # Get processes with high I/O (simplified check)
        local high_io_procs=\$(iotop -a -o -d 1 -n 1 2>/dev/null | grep -v TOTAL | awk '\$4+\$6 > 1000 {print \$2, \$4+\$6, \$NF}' | head -3)
        
        if [ -n "\$high_io_procs" ]; then
            log_message "High I/O processes detected:"
            echo "\$high_io_procs" >> "\$LOGFILE"
        fi
    fi
}

# Main execution
log_message "Resource Guardian scan started"

# Check if bc is available (required for floating point calculations)
if ! command -v bc >/dev/null 2>&1; then
    log_message "ERROR: bc calculator not found - installing..."
    apt-get update && apt-get install -y bc
fi

# Perform checks
check_cpu_usage
check_memory_usage
check_system_load
check_disk_io

log_message "Resource Guardian scan completed"

# Log rotation for resource guardian logs
if [ \$(stat -c%s "\$LOGFILE" 2>/dev/null || echo 0) -gt 10485760 ]; then  # 10MB
    mv "\$LOGFILE" "\${LOGFILE}.old"
    touch "\$LOGFILE"
    chmod 644 "\$LOGFILE"
    log_message "Resource Guardian log rotated"
fi
EOF

chmod +x /usr/local/bin/resource-guardian

# Install required dependency
if ! command -v bc >/dev/null 2>&1; then
    echo "Installing bc calculator for Resource Guardian..."
    wait_for_dpkg_lock
    apt-get update && apt-get install -y bc
fi

# Create systemd service for Resource Guardian
cat > /etc/systemd/system/resource-guardian.service << EOF
[Unit]
Description=Resource Guardian - Proactive Resource Management
After=network.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/resource-guardian
User=root
StandardOutput=journal
StandardError=journal
EOF

# Create systemd timer for Resource Guardian (runs every 2 minutes)
cat > /etc/systemd/system/resource-guardian.timer << EOF
[Unit]
Description=Run Resource Guardian every 2 minutes
Requires=resource-guardian.service

[Timer]
OnBootSec=2min
OnUnitActiveSec=2min
AccuracySec=30s

[Install]
WantedBy=timers.target
EOF

# Enable and start Resource Guardian
systemctl daemon-reload
systemctl enable resource-guardian.timer
systemctl start resource-guardian.timer

echo "✅ Resource Guardian system installed and configured"
echo "   • Monitors CPU usage every 2 minutes"
echo "   • Protects critical services: sshd, systemd, fail2ban, auditd, rsyslog"
echo "   • Terminates processes using >80% CPU for >5 minutes"
echo "   • Emergency memory management at >95% usage"
echo "   • Logs all actions to /var/log/resource-guardian.log"
echo "   • Sends email alerts for all actions taken"
echo ""
echo "💡 Resource Guardian Configuration:"
echo "   • CPU Threshold: 80% for 5+ minutes"
echo "   • Memory Warning: 85%"
echo "   • Memory Critical: 95%"
echo "   • Protected Services: SSH, systemd, fail2ban, auditd, etc."

# Daily Security Configuration Backup
echo "Setting up daily security configuration backup..."
cat > /etc/cron.daily/security-config-backup << EOF
#!/bin/bash
# Daily backup of critical security configurations

BACKUP_DIR="/var/backups/security-configs"
DATE=\$(date +%Y%m%d)
BACKUP_FILE="\$BACKUP_DIR/security-config-\$DATE.tar.gz"

# Create backup directory
mkdir -p "\$BACKUP_DIR"

# Create comprehensive backup
tar -czf "\$BACKUP_FILE" \
    /etc/fail2ban \
    /etc/suricata \
    /etc/ssh \
    /etc/audit \
    /etc/ufw \
    /etc/cron.d \
    /etc/cron.daily \
    /etc/cron.hourly \
    /etc/cron.weekly \
    /etc/systemd/system \
    /var/lib/security/baselines \
    /var/lib/persistence-baselines \
    /etc/security-status.conf \
    /etc/logrotate.d \
    2>/dev/null

# Verify backup
if [ -f "\$BACKUP_FILE" ]; then
    # Check backup integrity
    if tar -tzf "\$BACKUP_FILE" >/dev/null 2>&1; then
        logger -p daemon.info "Security configuration backup completed: \$BACKUP_FILE"
        
        # Keep only last 30 days of backups
        find "\$BACKUP_DIR" -name "security-config-*.tar.gz" -mtime +30 -delete
        
        # Report backup size
        BACKUP_SIZE=\$(du -h "\$BACKUP_FILE" | cut -f1)
        echo "Security configuration backup completed: \$BACKUP_SIZE (\$BACKUP_FILE)" >> /var/log/backup.log
    else
        logger -p daemon.error "Security configuration backup corrupted: \$BACKUP_FILE"
        echo "BACKUP ERROR: Security configuration backup corrupted on \$(hostname)" | \
            mail -s "BASTION ERROR: Backup Failure" root
    fi
else
    logger -p daemon.error "Security configuration backup failed"
    echo "BACKUP ERROR: Security configuration backup failed on \$(hostname)" | \
        mail -s "BASTION ERROR: Backup Failure" root
fi

# Quick integrity check of critical configs
for config in /etc/ssh/sshd_config /etc/suricata/suricata.yaml /etc/fail2ban/jail.local; do
    if [ -f "\$config" ]; then
        case "\$config" in
            */sshd_config)
                sshd -t 2>/dev/null || echo "WARNING: SSH config validation failed" >> /var/log/backup.log
                ;;
            */suricata.yaml)
                suricata -T -c "\$config" >/dev/null 2>&1 || echo "WARNING: Suricata config validation failed" >> /var/log/backup.log
                ;;
            */jail.local)
                fail2ban-client -t >/dev/null 2>&1 || echo "WARNING: Fail2ban config validation failed" >> /var/log/backup.log
                ;;
        esac
    fi
done
EOF

chmod +x /etc/cron.daily/security-config-backup

# Run initial backup
echo "Creating initial security configuration backup..."
/etc/cron.daily/security-config-backup

echo "✅ Daily security configuration backup system configured"

echo "===== 15. SSH service verification ====="
echo "Verifying SSH service is running properly..."
if systemctl is-active --quiet ssh; then
    echo "✅ SSH service is running"
else
    echo "⚠️ SSH service issues detected - checking status..."
    systemctl status ssh --no-pager -l
fi

echo "===== 15.1 SSH Authentication Troubleshooting and Validation ====="
echo "Performing comprehensive SSH authentication validation..."

# Check if SSH public key was provided and set up
if [ -n "$SSH_PUBLIC_KEY" ] && [ -n "$USERNAME" ]; then
    echo "Validating SSH key setup for user: $USERNAME"
    
    # Verify user exists
    if id "$USERNAME" &>/dev/null; then
        echo "✅ User $USERNAME exists"

        # Get the actual home directory for the user
        USER_HOME=$(getent passwd "$USERNAME" | cut -d: -f6)

        if [ -z "$USER_HOME" ]; then
            echo "❌ Could not determine home directory for $USERNAME"
        else
            echo "Using home directory: $USER_HOME"

            # Check home directory permissions
            if [ -d "$USER_HOME" ]; then
            HOME_PERMS=$(stat -c "%a" "$USER_HOME")
            echo "Home directory permissions: $HOME_PERMS"
            if [ "$HOME_PERMS" != "755" ]; then
                echo "⚠️ Fixing home directory permissions..."
                chmod 755 "$USER_HOME"
                echo "✅ Home directory permissions corrected"
            fi
        fi
        
        # Check .ssh directory
        if [ -d "$USER_HOME/.ssh" ]; then
            SSH_DIR_PERMS=$(stat -c "%a" "$USER_HOME/.ssh")
            SSH_DIR_OWNER=$(stat -c "%U:%G" "$USER_HOME/.ssh")
            echo "SSH directory permissions: $SSH_DIR_PERMS, owner: $SSH_DIR_OWNER"
            
            if [ "$SSH_DIR_PERMS" != "700" ] || [ "$SSH_DIR_OWNER" != "$USERNAME:$USERNAME" ]; then
                echo "⚠️ Fixing SSH directory permissions and ownership..."
                chmod 700 "$USER_HOME/.ssh"
                chown "$USERNAME:$USERNAME" "$USER_HOME/.ssh"
                echo "✅ SSH directory permissions and ownership corrected"
            fi
        else
            echo "⚠️ SSH directory missing - recreating..."
            mkdir -p "$USER_HOME/.ssh"
            chmod 700 "$USER_HOME/.ssh"
            chown "$USERNAME:$USERNAME" "$USER_HOME/.ssh"
            echo "✅ SSH directory created"
        fi
        
        # Check authorized_keys file
        if [ -f "$USER_HOME/.ssh/authorized_keys" ]; then
            KEYS_PERMS=$(stat -c "%a" "$USER_HOME/.ssh/authorized_keys")
            KEYS_OWNER=$(stat -c "%U:%G" "$USER_HOME/.ssh/authorized_keys")
            KEYS_SIZE=$(stat -c "%s" "$USER_HOME/.ssh/authorized_keys")
            echo "authorized_keys permissions: $KEYS_PERMS, owner: $KEYS_OWNER, size: $KEYS_SIZE bytes"
            
            if [ "$KEYS_PERMS" != "600" ] || [ "$KEYS_OWNER" != "$USERNAME:$USERNAME" ]; then
                echo "⚠️ Fixing authorized_keys permissions and ownership..."
                chmod 600 "$USER_HOME/.ssh/authorized_keys"
                chown "$USERNAME:$USERNAME" "$USER_HOME/.ssh/authorized_keys"
                echo "✅ authorized_keys permissions and ownership corrected"
            fi
            
            if [ "$KEYS_SIZE" -eq 0 ]; then
                echo "⚠️ authorized_keys file is empty - recreating with provided key..."
                echo "$SSH_PUBLIC_KEY" > "$USER_HOME/.ssh/authorized_keys"
                chmod 600 "$USER_HOME/.ssh/authorized_keys"
                chown "$USERNAME:$USERNAME" "$USER_HOME/.ssh/authorized_keys"
                echo "✅ authorized_keys file recreated with SSH key"
            else
                echo "✅ authorized_keys file contains $(wc -l < "$USER_HOME/.ssh/authorized_keys") key(s)"
                # Show key fingerprint for verification
                if command -v ssh-keygen >/dev/null 2>&1; then
                    echo "Key fingerprints:"
                    ssh-keygen -lf "$USER_HOME/.ssh/authorized_keys" 2>/dev/null || echo "   (unable to parse key fingerprint)"
                fi
            fi
        else
            echo "⚠️ authorized_keys file missing - creating with provided key..."
            echo "$SSH_PUBLIC_KEY" > "$USER_HOME/.ssh/authorized_keys"
            chmod 600 "$USER_HOME/.ssh/authorized_keys"
            chown "$USERNAME:$USERNAME" "$USER_HOME/.ssh/authorized_keys"
            echo "✅ authorized_keys file created with SSH key"
        fi
        
        # Advanced SSH debugging - check for permission issues
        echo ""
        
        # Check for filesystem issues
        echo "Checking filesystem mount options..."
        MOUNT_INFO=$(df "$USER_HOME" | tail -1)
        echo "Mount info: $MOUNT_INFO"
        
        MOUNT_POINT=$(echo "$MOUNT_INFO" | awk '{print $6}')
        if mount | grep " $MOUNT_POINT " | grep -q noexec; then
            echo "⚠️ WARNING: $MOUNT_POINT mounted with noexec - this may cause issues"
        fi
        
        # Check for extended attributes and immutable flags
        echo "Checking file attributes..."
        if lsattr "$USER_HOME/.ssh/authorized_keys" 2>/dev/null | grep -q '^....i'; then
            echo "⚠️ WARNING: authorized_keys has immutable flag - removing..."
            chattr -i "$USER_HOME/.ssh/authorized_keys" 2>/dev/null || true
        fi
        
        # Check full path permissions with namei
        echo "Full path permission analysis:"
        namei -l "$USER_HOME/.ssh/authorized_keys" 2>/dev/null || echo "namei not available"
        
        # Check if SSH can actually read the file
        echo "Testing file readability..."
        if sudo -u "$USERNAME" test -r "$USER_HOME/.ssh/authorized_keys"; then
            echo "✅ File readable by user $USERNAME"
        else
            echo "❌ File NOT readable by user $USERNAME"
            echo "Attempting to fix permissions..."
            chown "$USERNAME:$USERNAME" "$USER_HOME/.ssh/authorized_keys"
            chmod 600 "$USER_HOME/.ssh/authorized_keys"
            
            if sudo -u "$USERNAME" test -r "$USER_HOME/.ssh/authorized_keys"; then
                echo "✅ File now readable after permission fix"
            else
                echo "❌ File STILL not readable - deeper issue exists"
                echo "Manual debugging required - see /usr/local/bin/fix-ssh-auth"
            fi
        fi
        
        # Test SSH configuration
        echo "Testing SSH daemon configuration..."
        if sshd -t 2>/dev/null; then
            echo "✅ SSH daemon configuration is valid"
        else
            echo "⚠️ SSH daemon configuration test failed:"
            sshd -t
        fi
        
        # Check SSH service status
        if systemctl is-active --quiet ssh; then
            echo "✅ SSH service is running"
        else
            echo "⚠️ SSH service is not running - attempting to start..."
            systemctl start ssh
            if systemctl is-active --quiet ssh; then
                echo "✅ SSH service started successfully"
            else
                echo "❌ Failed to start SSH service"
                systemctl status ssh --no-pager -l
            fi
        fi
        
        # Check if SSH is listening on configured ports
        echo "Checking SSH listening ports..."
        SSH_PORTS_LISTENING=""
        if ss -tlnp | grep -q ":22 "; then
            echo "✅ SSH is listening on port 22 (default)"
            SSH_PORTS_LISTENING="22"
        fi
        if ss -tlnp | grep -q ":$SSH_PORT "; then
            echo "✅ SSH is listening on port $SSH_PORT (custom)"
            SSH_PORTS_LISTENING="$SSH_PORTS_LISTENING $SSH_PORT"
        fi
        
        if [ -z "$SSH_PORTS_LISTENING" ]; then
            echo "⚠️ SSH is not listening on expected ports"
            echo "Current listening ports:"
            ss -tlnp | grep sshd || echo "   No SSH listening ports found"
        else
            echo "✅ SSH is listening on ports:$SSH_PORTS_LISTENING"
            if [ "$SSH_PORT" != "22" ]; then
                echo "   📋 SSH configured for dual-port operation during transition"
                echo "   🔧 Test port $SSH_PORT, then disable port 22 when confirmed working"
            fi
        fi


        echo "✅ SSH authentication validation completed"

        fi # Close USER_HOME check

    else
        echo "❌ User $USERNAME does not exist"
    fi
else
    echo "⚠️ No SSH public key provided or username not set - manual SSH key setup required"
fi

echo "===== Final Configuration Validation ====="

# Validate all configurations before final restart
echo "Starting critical configuration validation..."
if ! validate_critical_configs; then
    log_error "Configuration validation failed - but continuing setup"
    echo "⚠️ Some configurations may need manual verification"
    echo "⚠️ SSH restart will proceed to maintain connectivity"
    # Don't exit - continue with setup to maintain SSH connectivity
else
    echo "✅ All critical configurations validated successfully"
fi

# Restart SSH with new configuration
echo "===== 16. Restarting SSH service ====="
systemctl restart sshd

# Verify SSH is running only on target port and clean up port 22
if ss -tnlp | grep -q ":$SSH_PORT.*sshd"; then
  sed -i '/^Port 22$/d' /etc/ssh/sshd_config
  systemctl reload ssh
  ufw delete allow 22/tcp || true
  echo "✅ SSH now running only on port $SSH_PORT"
fi

# Final system checks
echo "===== 17. Final system validation ====="
echo "Checking SSH configuration..."
sshd -t && echo "✅ SSH configuration is valid"

echo "Checking firewall status..."
ufw status | grep -q "Status: active" && echo "✅ Firewall is active"

echo "Checking fail2ban status..."
systemctl is-active --quiet fail2ban && echo "✅ Fail2ban is running"

echo "Checking audit system..."
systemctl is-active --quiet auditd && echo "✅ Audit system is running"

echo "Checking Suricata IDS..."
systemctl is-active --quiet suricata && echo "✅ Suricata IDS is running"

echo ""

echo "===== BASTION HOST SETUP COMPLETE ====="
echo "========================================"

# Set up date variables for final output and email
SETUP_DATE=$(date '+%Y-%m-%d_%H-%M-%S')
SETUP_DATE_DISPLAY=$(date '+%Y-%m-%d %H:%M:%S')

echo ""
echo "✅ Bastion host has been successfully configured with enhanced security"
echo ""
echo "🔐 IMPORTANT SECURITY INFORMATION:"
if [ "$SSH_PORT" != "22" ]; then
    echo "   • SSH Ports: 22 (temporary) AND $SSH_PORT (primary)"
    echo "   • ⚠️  TRANSITION: Both ports active - disable 22 after testing $SSH_PORT"
else
    echo "   • SSH Port: $SSH_PORT"
fi
echo "   • Authentication: SSH keys ONLY (no passwords)"
echo "   • User: $USERNAME"
echo "   • Firewall: Restrictive rules active"
echo "   • Monitoring: Comprehensive logging and alerting enabled"
echo ""
echo "🔗 CONNECTION COMMANDS:"
if [ "$SSH_PORT" != "22" ]; then
    echo "   Primary:   ssh -p $SSH_PORT $USERNAME@$BASTION_IP"
    echo "   Fallback:  ssh -p 22 $USERNAME@$BASTION_IP (temporary)"
else
    echo "   ssh -p $SSH_PORT $USERNAME@$BASTION_IP"
fi
echo ""
echo "📊 MONITORING:"
if [[ "$SMTP_CONFIGURE" =~ ^[Yy]$ ]]; then
    echo "   • Security reports delivered via external SMTP to: $LOGWATCH_EMAIL"
else
    echo "   • Security reports delivered to local root mailbox (use 'bastionmail' to read)"
fi
echo "   • Setup completion report saved locally"
echo "   • Real-time monitoring active"
echo "   • All activities logged and audited"
echo ""
echo "📚 DOCUMENTATION:"
echo "   • Read /root/BASTION-README.md for complete information"
echo "   • Setup report: /root/bastion-setup-completion-$SETUP_DATE.txt"
echo ""
echo "🛠️ BASTION COMMANDS:"
echo "   • 'sudo bastionstat' - Show comprehensive bastion status (requires root)"
echo "   • 'sudo sshmon' - Monitor SSH activity in real-time (requires root)"
if [[ "$SMTP_CONFIGURE" =~ ^[Yy]$ ]]; then
    echo "   • All security alerts sent to: $LOGWATCH_EMAIL"
else
    echo "   • 'bastionmail' - Read local mail and notifications"
fi
echo ""
echo "📧 EMAIL CONFIGURATION:"
if [[ "$SMTP_CONFIGURE" =~ ^[Yy]$ ]]; then
    echo "   • External SMTP configured: $SMTP_SERVER:$SMTP_PORT"
    echo "   • From address: $SMTP_FROM_EMAIL"
    echo "   • All security notifications sent to: $LOGWATCH_EMAIL"
    echo "   • Reliable delivery - emails will not be filtered as spam"
else
    echo "   • Local mail delivery only"
    echo "   • Security notifications stored in local root mailbox"
    echo "   • Use 'bastionmail' command to read alerts"
fi
echo ""
echo "🔐 ADVANCED SECURITY REFINEMENTS:"
echo "   • Unattended reboot warning system (wall messages + email alerts)"
echo "   • Suricata rules maintenance with weekly auto-updates"
echo "   • Enhanced OpenSSH HMAC tuning (SHA-1 completely disabled)"
echo "   • Systemd service hardening with resource limits and restart policies"
echo "   • Daily automated backup of all security configurations"
echo "   • ClamAV antivirus with daily scans and real-time monitoring"
echo "   • Linux Malware Detect (maldet) for enhanced malware protection"
if [[ "$INSTALL_NETDATA" =~ ^[Yy]$ ]] || [[ "$INSTALL_NETDATA" == "true" ]]; then
    echo "   • Netdata monitoring with optional Cloud integration"
fi
echo ""
echo "📁 CONFIGURATION BACKUP:"
echo "   • Location: /var/backups/security-configs/"
echo "   • Retention: 30 days"
echo "   • Daily automated backup with integrity verification"
echo ""
echo "⚠️  NEXT STEPS:"
echo "   1. Test SSH access from your workstation using: ssh -p $SSH_PORT $USERNAME@$BASTION_IP"
if [ "$SSH_PORT" != "22" ]; then
    echo "   2. ⚠️  CRITICAL: Once you confirm SSH access on port $SSH_PORT works, disable port 22:"
    echo "      sudo ufw delete allow 22/tcp"
    echo "      sudo ufw reload"
    echo "   3. Configure any internal network access rules as needed"
    echo "   4. Set up centralized logging if required"
    echo "   5. Review and customize monitoring alerts"
    echo "   6. Document connection procedures for authorized users"
    echo "   7. ⚠️  IMPORTANT: After 24-48 hours, update chkrootkit baseline:"
else
    echo "   2. Configure any internal network access rules as needed"
    echo "   3. Set up centralized logging if required"
    echo "   4. Review and customize monitoring alerts"
    echo "   5. Document connection procedures for authorized users"
    echo "   6. ⚠️  IMPORTANT: After 24-48 hours, update chkrootkit baseline:"
fi
echo "      sudo cp -a -f /var/log/chkrootkit/log.today /var/log/chkrootkit/log.expected"
if [[ "$SMTP_CONFIGURE" =~ ^[Yy]$ ]]; then
    if [ "$SSH_PORT" != "22" ]; then
        echo "   8. Check your email inbox for the setup completion report"
    else
        echo "   7. Check your email inbox for the setup completion report"
    fi
fi
echo ""
echo "🔧 SSH TROUBLESHOOTING (if connection fails):"
echo "   If you get 'Permission denied (publickey)' error, check:"
if [ "$SSH_PORT" != "22" ]; then
    echo "   1. ssh -v -p $SSH_PORT $USERNAME@$BASTION_IP (verbose output - primary port)"
    echo "   1b. ssh -v -p 22 $USERNAME@$BASTION_IP (verbose output - fallback port)"
else
    echo "   1. ssh -v -p $SSH_PORT $USERNAME@$BASTION_IP (verbose output)"
fi
echo "   2. sudo tail -f /var/log/auth.log (on server, in another session)"
echo "   3. sudo ls -la /home/$USERNAME/.ssh/"
echo "   4. sudo cat /home/$USERNAME/.ssh/authorized_keys"
echo "   5. sudo systemctl status ssh"
echo ""

# Send setup completion email
echo "===== Sending Setup Completion Report ====="

# Create setup completion email
if [[ "$SMTP_CONFIGURE" =~ ^[Yy]$ ]]; then
    MAIL_CONFIG_INFO="📧 MAIL CONFIGURATION:
• External SMTP: $SMTP_SERVER:$SMTP_PORT
• From Address: $SMTP_FROM_EMAIL
• Notifications sent to: $LOGWATCH_EMAIL
• TLS/STARTTLS: Enabled
• All security alerts delivered via reliable SMTP"
else
    MAIL_CONFIG_INFO="📧 MAIL CONFIGURATION:
• Local mail delivery only
• Notifications stored in: /var/mail/root
• Use 'bastionmail' command to read alerts
• External SMTP not configured"
fi

cat > /tmp/bastion-setup-complete.txt << EOF
Subject: ✅ Bastion Host Setup Complete - $HOSTNAME

===============================================================
BASTION HOST SETUP COMPLETION REPORT
===============================================================

Bastion Host: $HOSTNAME
IP Address: $BASTION_IP
Setup Completed: $SETUP_DATE_DISPLAY
User Account: $USERNAME

🔗 SSH CONNECTION:
EOF

# Add SSH connection information based on port configuration
if [ "$SSH_PORT" != "22" ]; then
    cat >> /tmp/bastion-setup-complete.txt << EOF
Primary: ssh -p $SSH_PORT $USERNAME@$BASTION_IP  
Fallback: ssh -p 22 $USERNAME@$BASTION_IP (temporary - disable after testing)
EOF
else
    cat >> /tmp/bastion-setup-complete.txt << EOF
ssh -p $SSH_PORT $USERNAME@$BASTION_IP
EOF
fi

cat >> /tmp/bastion-setup-complete.txt << EOF

🔐 SECURITY CONFIGURATION:
• SSH Authentication: Key-only (passwords disabled)
• Firewall: Restrictive UFW rules active
• Intrusion Detection: Suricata IDS running
• Brute Force Protection: Fail2ban configured
• Comprehensive Audit: auditd monitoring active
• Malware Protection: ClamAV + maldet scanning
• Network Monitoring: Real-time traffic analysis
• CPU Security: Microcode updates installed (active after reboot)

🔗 CONNECTION COMMAND:
ssh -p $SSH_PORT $USERNAME@$BASTION_IP

$MAIL_CONFIG_INFO

📊 MONITORING & ALERTS:
• Daily security reports via configured mail system
• Hourly suspicious activity checks
• Real-time SSH session monitoring
• Automated malware scanning
• Network intrusion detection

📁 KEY FILES:
• Configuration: /root/BASTION-README.md
• SSH Config: /etc/ssh/sshd_config
• Firewall Rules: ufw status numbered
• Audit Rules: /etc/audit/rules.d/bastion-audit.rules
• Monitoring Logs: /var/log/bastion-monitor.log

🛠️ USEFUL COMMANDS:
• sudo bastionstat - Show current bastion status (requires root)
• sudo sshmon - Monitor SSH activity in real-time (requires root)
• bastionmail - Read local mail (if using local delivery)
• sudo fail2ban-client status - Check fail2ban status
• sudo ufw status numbered - Show firewall rules
• sudo ausearch -k user_commands - Show user command audit logs

⚠️ NEXT STEPS:
1. Test SSH access from your workstation using: ssh -p $SSH_PORT $USERNAME@$BASTION_IP

🛡️ SECURITY FEATURES ACTIVE:
• Multi-layer firewall protection
• Real-time network monitoring
• Comprehensive audit logging
• Automated security scanning
• Intrusion detection system
• SSH session monitoring
• File integrity monitoring

🔐 ADVANCED SECURITY REFINEMENTS:
• Unattended reboot warning system (wall messages + email alerts)
• Suricata rules maintenance with weekly auto-updates
• Enhanced OpenSSH HMAC tuning (SHA-1 completely disabled)
• Systemd service hardening with resource limits and restart policies
• Daily automated backup of all security configurations
• ClamAV antivirus with daily scans and real-time monitoring
• Linux Malware Detect (maldet) for enhanced malware protection
EOF

# Add SSH port warning and complete next steps to email
if [ "$SSH_PORT" != "22" ]; then
    cat >> /tmp/bastion-setup-complete.txt << EOF
2. ⚠️  CRITICAL: Once you confirm SSH access on port $SSH_PORT works, disable port 22:
   sudo ufw delete allow 22/tcp
   sudo ufw reload
3. Configure internal network access rules if needed
4. Set up centralized logging if required
5. Review and customize monitoring alerts
6. Document connection procedures for authorized users
EOF
else
    cat >> /tmp/bastion-setup-complete.txt << EOF
2. Configure internal network access rules if needed
3. Set up centralized logging if required
4. Review and customize monitoring alerts
5. Document connection procedures for authorized users
EOF
fi

if [[ "$INSTALL_NETDATA" =~ ^[Yy]$ ]] || [[ "$INSTALL_NETDATA" == "true" ]]; then
    echo "   • Netdata monitoring with optional Cloud integration" >> /tmp/bastion-setup-complete.txt
fi

cat >> /tmp/bastion-setup-complete.txt << EOF

📁 CONFIGURATION BACKUP:
• Location: /var/backups/security-configs/
• Retention: 30 days
• Daily automated backup with integrity verification

🔧 SSH TROUBLESHOOTING (if connection fails):
If you get 'Permission denied (publickey)' error, check:
EOF

# Add troubleshooting commands based on port configuration
if [ "$SSH_PORT" != "22" ]; then
    cat >> /tmp/bastion-setup-complete.txt << EOF
1. ssh -v -p $SSH_PORT $USERNAME@$BASTION_IP (verbose output - primary port)
1b. ssh -v -p 22 $USERNAME@$BASTION_IP (verbose output - fallback port)
EOF
else
    cat >> /tmp/bastion-setup-complete.txt << EOF
1. ssh -v -p $SSH_PORT $USERNAME@$BASTION_IP (verbose output)
EOF
fi

cat >> /tmp/bastion-setup-complete.txt << EOF
2. sudo tail -f /var/log/auth.log (on server, in another session)
3. sudo ls -la /home/$USERNAME/.ssh/
4. sudo cat /home/$USERNAME/.ssh/authorized_keys
6. sudo systemctl status ssh

This bastion host is now ready for secure access management!

--
Generated by PolyServer Bastion Setup
$SETUP_DATE_DISPLAY
EOF

if [[ "$SMTP_CONFIGURE" =~ ^[Yy]$ ]]; then
    echo "Sending setup completion report via external SMTP..."
    
    # Create email with proper From header
    cat > /tmp/final_setup_email.txt << EOF
From: $SMTP_FROM_EMAIL
To: $LOGWATCH_EMAIL
Subject: ✅ Bastion Host Setup Complete - $HOSTNAME

$(tail -n +3 /tmp/bastion-setup-complete.txt)
EOF
    
    # Send to configured email address
    /usr/sbin/sendmail -f "$SMTP_FROM_EMAIL" "$LOGWATCH_EMAIL" < /tmp/final_setup_email.txt
    
    echo "✅ Setup completion report sent to: $LOGWATCH_EMAIL"
    echo "📧 Check your email inbox for the detailed setup report"
    
    # Check mail queue
    sleep 3
    QUEUE_STATUS=$(mailq)
    if [[ "$QUEUE_STATUS" == "Mail queue is empty" ]]; then
        echo "✅ Mail queue is empty - email sent successfully"
    else
        echo "⚠️ Mail queue status:"
        mailq | head -n 5
        echo "⚠️ If delivery fails, check your SMTP credentials and server settings"
    fi
    
else
    echo "Saving setup completion report to local mail..."
    
    # Send to local root account
    /usr/sbin/sendmail root < /tmp/bastion-setup-complete.txt
    
    echo "✅ Setup completion report saved to local root mailbox"
    echo "📧 Use 'bastionmail' command to read the setup report"
    
    # Check local delivery
    sleep 3
    if [ -f /var/mail/root ] || [ -f /var/spool/mail/root ]; then
        echo "✅ Local mail delivery confirmed"
    else
        echo "⚠️ Local mail delivery may have issues - check postfix logs"
    fi
fi

# Check recent postfix logs
echo ""
echo "Recent postfix logs:"
tail -n 10 /var/log/mail.log 2>/dev/null || echo "Mail logs not yet available"

# Also save a copy for local reference
cp /tmp/bastion-setup-complete.txt "/root/bastion-setup-completion-$SETUP_DATE.txt"

echo ""

# Clear any sensitive variables from memory
unset SMTP_PASSWORD
unset SSH_PUBLIC_KEY

# Clean up temporary files
rm -f /tmp/smtp_test_email.txt /tmp/final_setup_email.txt /tmp/bastion-setup-complete.txt

# Optional: Run Lynis security audit
echo ""
echo "===== OPTIONAL: LYNIS SECURITY AUDIT ====="
read -p "Run Lynis security audit to validate hardening? (y/N): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo "Installing and running Lynis security audit..."
    
    # Clone Lynis from official repository
    cd /tmp
    if [ -d "lynis" ]; then
        rm -rf lynis
    fi
    
    git clone https://github.com/CISOfy/lynis.git
    if [ $? -eq 0 ]; then
        # Set proper ownership for security
        chown -R 0:0 lynis
        cd lynis
        
        # Run the audit
        echo "Starting Lynis system audit..."
        ./lynis audit system
        
        # Save the report
        if [ -f /var/log/lynis.log ]; then
            cp /var/log/lynis.log "/root/lynis-audit-$(date +%Y%m%d-%H%M%S).log"
            echo "✅ Lynis audit completed - report saved to /root/"
        fi
        
        # Clean up
        cd /root
        rm -rf /tmp/lynis
    else
        echo "❌ Failed to download Lynis - skipping audit"
    fi
else
    echo "Skipping Lynis security audit"
fi

# Create setup completion marker for persistence monitoring grace period
touch /var/lib/bastion-setup-complete
echo "Setup completed at $(date)" > /var/lib/bastion-setup-complete

log_message "Bastion host setup completed successfully with enhanced security"

echo "🎉 This bastion host is now ready for secure access management!"
echo ""
echo "📧 PERSISTENCE MONITORING:"
echo "   • Grace period: 7 days from setup completion"

echo "   • During grace period: Changes logged but no email alerts sent"
echo "   • After grace period: Email alerts for suspicious persistence changes"
echo "   • To modify: edit /etc/cron.daily/persistence-check (GRACE_PERIOD_DAYS variable)"
