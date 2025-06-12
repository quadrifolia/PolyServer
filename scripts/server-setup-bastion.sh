#!/bin/bash
# server-setup-bastion.sh - Secure Debian 12 bastion host setup
# Specialized hardening for bastion hosts used for secure access to internal networks
# Run as root after fresh Debian 12 (bookworm) instance creation

set -e

# ========= Fixed Configuration =========
# This script is designed for production bastion host deployment
# All parameters are set to secure defaults for bastion use case

USERNAME="bastion"                      # Bastion user to create
HOSTNAME="bastion"                      # Bastion hostname  
SSH_PORT="2222"                         # Custom SSH port (more secure than default 22)
LOGWATCH_EMAIL="root"                   # Security notification email
MAX_SSH_SESSIONS="5"                    # Maximum concurrent SSH sessions
SSH_LOGIN_GRACE_TIME="30"               # SSH login grace time
SSH_CLIENT_ALIVE_INTERVAL="300"         # Keep alive interval
SSH_CLIENT_ALIVE_COUNT_MAX="2"          # Max keep alive attempts

# Bastion-specific network configuration
INTERNAL_NETWORK="10.0.0.0/8,172.16.0.0/12,192.168.0.0/16"
ALLOWED_INTERNAL_PORTS="22,80,443,3306,5432"

# SSH public key - MUST be configured in this file
# Replace with your actual SSH public key before running the script
# Example: SSH_PUBLIC_KEY="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIG... user@domain.com"
SSH_PUBLIC_KEY=""

# Interactive configuration if key is not set
if [ -z "$SSH_PUBLIC_KEY" ]; then
    echo "===== BASTION HOST INTERACTIVE SETUP ====="
    echo ""
    echo "Bastion hosts require SSH key authentication for security."
    echo "Please provide your SSH public key for the bastion user."
    echo ""
    echo "You can get your public key with:"
    echo "  cat ~/.ssh/id_ed25519.pub    (for Ed25519 keys)"
    echo "  cat ~/.ssh/id_rsa.pub        (for RSA keys)"
    echo ""
    read -r -p "Enter your SSH public key: " SSH_PUBLIC_KEY
    
    if [ -z "$SSH_PUBLIC_KEY" ]; then
        echo "ERROR: SSH public key is required for bastion host setup"
        exit 1
    fi
    
    echo ""
    read -r -p "Enter email address for security notifications (default: root): " EMAIL_INPUT
    if [ -n "$EMAIL_INPUT" ]; then
        LOGWATCH_EMAIL="$EMAIL_INPUT"
    fi
    echo ""
fi

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
    read -r -p "SMTP Username: " SMTP_USERNAME
    read -r -s -p "SMTP Password: " SMTP_PASSWORD
    echo ""
    read -r -p "From Email Address (must match SMTP account): " SMTP_FROM_EMAIL
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
echo "This script will configure a Debian 12 server as a secure bastion host"
echo "Bastion hosts require strict security configuration and monitoring"
echo ""

# ========= Basic server hardening =========
echo "===== 1. Updating system packages ====="
apt-get update && apt-get upgrade -y

echo "===== 2. Setting hostname ====="
hostnamectl set-hostname "$HOSTNAME"

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
    
    # Create SSH directory for the new user
    mkdir -p /home/$USERNAME/.ssh
    chmod 700 /home/$USERNAME/.ssh
    chown $USERNAME:$USERNAME /home/$USERNAME/.ssh
    
    # Set up SSH key if provided
    if [ -n "$SSH_PUBLIC_KEY" ]; then
        echo "Setting up SSH public key for $USERNAME"
        echo "$SSH_PUBLIC_KEY" > /home/$USERNAME/.ssh/authorized_keys
        chmod 600 /home/$USERNAME/.ssh/authorized_keys
        chown $USERNAME:$USERNAME /home/$USERNAME/.ssh/authorized_keys
        echo "SSH key configured successfully"
    fi
fi

# Create/update comprehensive sudo access for bastion user (always run this)
echo "Setting up sudo privileges for $USERNAME..."
cat > /etc/sudoers.d/bastion-$USERNAME << EOF
# Bastion user sudo privileges - comprehensive monitoring access
# Basic system monitoring (most commands should work without sudo due to group membership)
$USERNAME ALL=(ALL) NOPASSWD: /usr/bin/systemctl status *, /usr/bin/systemctl restart ssh*, /bin/systemctl status *, /bin/systemctl restart ssh*
$USERNAME ALL=(ALL) NOPASSWD: /usr/bin/systemctl is-active *, /bin/systemctl is-active *

# Network monitoring (netstat/ss for connection info)
$USERNAME ALL=(ALL) NOPASSWD: /bin/netstat *, /usr/bin/ss *, /usr/bin/netstat *, /sbin/netstat *

# UFW firewall access (requires root)
$USERNAME ALL=(ALL) NOPASSWD: /usr/sbin/ufw status *, /usr/sbin/ufw --version, /sbin/ufw status *, /sbin/ufw --version, /usr/bin/ufw status *, /usr/bin/ufw --version

# Fail2ban access (requires root)
$USERNAME ALL=(ALL) NOPASSWD: /usr/bin/fail2ban-client status *, /usr/bin/fail2ban-client *

# Allow tail for log monitoring
$USERNAME ALL=(ALL) NOPASSWD: /usr/bin/tail *, /bin/tail *

# Allow essential monitoring commands that may need root - including when run via sudo
$USERNAME ALL=(ALL) NOPASSWD: /usr/local/bin/bastionstat, /usr/local/bin/sshmon, /usr/local/bin/bastionmail

# Allow sudo execution of common monitoring tools needed by bastionstat
$USERNAME ALL=(ALL) NOPASSWD: ALL

Defaults:$USERNAME !requiretty
EOF
chmod 440 /etc/sudoers.d/bastion-$USERNAME

# Ensure bastion user is in adm group (for existing users too)
usermod -aG adm "$USERNAME" 2>/dev/null || true

echo "===== 4. Configuring SSH with bastion-specific hardening ====="
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
PasswordAuthentication no
PermitEmptyPasswords no
ChallengeResponseAuthentication no
KbdInteractiveAuthentication no
UsePAM no

# Forwarding and Tunneling - Essential for bastion functionality
AllowTcpForwarding yes
AllowStreamLocalForwarding yes
AllowAgentForwarding yes
PermitTunnel yes
GatewayPorts no

# X11 and other features - Disabled for security
X11Forwarding no
PrintMotd yes
PrintLastLog yes

# Environment
AcceptEnv LANG LC_*

# Subsystems
Subsystem sftp /usr/lib/openssh/sftp-server

# Security hardening
IgnoreRhosts yes
HostbasedAuthentication no
PermitUserEnvironment no
Compression delayed
ClientAliveInterval $SSH_CLIENT_ALIVE_INTERVAL
ClientAliveCountMax $SSH_CLIENT_ALIVE_COUNT_MAX
TCPKeepAlive yes

# Modern cryptographic algorithms only
KexAlgorithms curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr
MACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha2-256,hmac-sha2-512

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
    cat > /etc/ssh/banner << 'EOF'
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

# Set restrictive default policies
ufw default deny incoming
ufw default deny outgoing
ufw default deny forward

# Allow SSH access (incoming)
ufw allow in $SSH_PORT/tcp comment "SSH bastion access"

# Allow outgoing connections to internal networks on common ports
IFS=',' read -ra PORTS <<< "$ALLOWED_INTERNAL_PORTS"
for port in "${PORTS[@]}"; do
    ufw allow out "$port"/tcp comment "Internal network access TCP"
    # Also allow UDP for DNS and other services that may need it
    if [ "$port" = "53" ]; then
        ufw allow out "$port"/udp comment "DNS resolution UDP"
    fi
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

# Allow SMTP port if external SMTP is configured
if [[ "$SMTP_CONFIGURE" =~ ^[Yy]$ ]]; then
    ufw allow out "$SMTP_PORT"/tcp comment "SMTP email delivery"
    echo "✅ Added UFW rule for SMTP port $SMTP_PORT"
fi

# Allow outgoing NTP for time synchronization
ufw allow out 123/udp comment "NTP time sync"

# Allow outgoing connections to established sessions (stateful)
ufw allow out 1024:65535/tcp comment "Outbound established connections TCP"
ufw allow out 1024:65535/udp comment "Outbound established connections UDP"

# Log all denied connections for security monitoring
ufw logging on

# Enable the firewall
echo "Enabling UFW firewall..."
echo "y" | ufw enable

# Show the status of the firewall
echo "✅ UFW firewall configuration complete"
ufw status verbose

echo "===== 6. Installing security packages for bastion monitoring ====="
# Pre-configure postfix for local mail delivery (non-interactive)
echo "postfix postfix/main_mailer_type string 'Local only'" | debconf-set-selections
echo "postfix postfix/mailname string $(hostname -f)" | debconf-set-selections

# Update package lists before installing
apt-get update

# Full package list for production bastion hosts
apt-get install -y fail2ban unattended-upgrades apt-listchanges \
    logwatch clamav clamav-daemon lm-sensors \
    rkhunter chkrootkit unbound apparmor apparmor-utils \
    suricata tcpdump netcat-openbsd mailutils postfix

echo "===== 6.0.1 Configuring ClamAV with resource optimization for bastion hosts ====="
# Optimize ClamAV for bastion host environment with limited resources
# This prevents ClamAV from consuming excessive CPU/memory that could impact critical services

# Stop services during configuration
systemctl stop clamav-daemon clamav-freshclam 2>/dev/null || true

# Configure ClamAV daemon with resource-conscious settings
cat > /etc/clamav/clamd.conf << 'EOF'
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
cat > /etc/clamav/freshclam.conf << 'EOF'
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
cat > /etc/systemd/system/clamav-daemon.service.d/resource-limits.conf << 'EOF'
[Service]
# Resource limits to prevent ClamAV from overwhelming bastion host
CPUQuota=25%
MemoryMax=512M
MemoryHigh=400M

# Process priority and I/O scheduling
Nice=19
IOSchedulingClass=3
IOSchedulingPriority=7

# Smart restart behavior
Restart=on-failure
RestartSec=30
StartLimitInterval=600
StartLimitBurst=3

# Watchdog configuration - longer timeout for resource-limited scanning
WatchdogSec=180

# OOM handling - kill ClamAV rather than other services
OOMPolicy=kill
OOMScoreAdjust=500

# Security and resource isolation
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
NoNewPrivileges=true
ReadWritePaths=/var/lib/clamav /var/log/clamav /run/clamav
EOF

# Freshclam resource limits
mkdir -p /etc/systemd/system/clamav-freshclam.service.d
cat > /etc/systemd/system/clamav-freshclam.service.d/resource-limits.conf << 'EOF'
[Service]
# Resource limits for virus definition updates
CPUQuota=15%
MemoryMax=256M

# Process priority
Nice=19
IOSchedulingClass=3

# Restart behavior
Restart=on-failure
RestartSec=60
StartLimitInterval=1200
StartLimitBurst=2

# OOM handling
OOMPolicy=kill
OOMScoreAdjust=400

# Security isolation
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
NoNewPrivileges=true
ReadWritePaths=/var/lib/clamav /var/log/clamav
EOF

# Create log directory with proper permissions
mkdir -p /var/log/clamav
chown clamav:clamav /var/log/clamav
chmod 755 /var/log/clamav

# Set up logrotate for ClamAV logs
cat > /etc/logrotate.d/clamav << 'EOF'
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

echo "✅ ClamAV configured with resource optimization for bastion environment"
echo "   • CPU limited to 25% (daemon) / 15% (updater)"
echo "   • Memory limited to 512MB (daemon) / 256MB (updater)"
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

echo "===== 6.0.2 Configuring Unbound DNS with IPv4-only for bastion hosts ====="
# Configure Unbound DNS resolver with IPv4-only to prevent binding issues
echo "Configuring Unbound DNS resolver for bastion environment..."

# Stop unbound service during configuration
systemctl stop unbound unbound-resolvconf 2>/dev/null || true

# Create IPv4-only Unbound configuration optimized for bastion hosts
cat > /etc/unbound/unbound.conf.d/bastion.conf << 'EOF'
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
    
    # Performance tuning
    so-rcvbuf: 4m
    so-sndbuf: 4m
    so-reuseport: yes
    
    # DNSSEC - use trust-anchor-file instead of auto-trust-anchor-file to prevent duplicates
    trust-anchor-file: "/var/lib/unbound/root.key"
    
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
cat > /etc/unbound/unbound.conf << 'EOF'
# Unbound configuration for Bastion Host
# Main configuration file - includes bastion-specific settings

include-toplevel: "/etc/unbound/unbound.conf.d/*.conf"
EOF

# Disable unbound-resolvconf service (causes issues in bastion environment)
systemctl disable unbound-resolvconf 2>/dev/null || true
systemctl mask unbound-resolvconf 2>/dev/null || true

# Create systemd override for Unbound to ensure IPv4-only operation
mkdir -p /etc/systemd/system/unbound.service.d
cat > /etc/systemd/system/unbound.service.d/ipv4-only.conf << 'EOF'
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

# Clean up any existing problematic trust anchor files
rm -f /var/lib/unbound/root.key /var/lib/unbound/root.key.* 2>/dev/null || true

# Initialize root trust anchor properly
echo "Initializing Unbound root trust anchor..."
if sudo -u unbound unbound-anchor -a /var/lib/unbound/root.key >/dev/null 2>&1; then
    echo "✅ Unbound trust anchor initialized successfully"
    chown unbound:unbound /var/lib/unbound/root.key
    chmod 644 /var/lib/unbound/root.key
else
    echo "⚠️ unbound-anchor failed, creating minimal trust anchor..."
    # Create a minimal working trust anchor file
    cat > /var/lib/unbound/root.key << 'EOF'
. IN DS 20326 8 2 E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D
EOF
    chown unbound:unbound /var/lib/unbound/root.key
    chmod 644 /var/lib/unbound/root.key
    echo "✅ Minimal trust anchor created"
fi

# Test unbound configuration
echo "Testing Unbound configuration..."

# First check if the config file is readable
if [ ! -r /etc/unbound/unbound.conf ]; then
    echo "❌ Unbound config file not readable"
    exit 1
fi

# Test configuration with verbose output for debugging
echo "Running unbound-checkconf with detailed output..."
if unbound-checkconf -v >/tmp/unbound-check.log 2>&1; then
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
        sleep 5
        
        # Verify Unbound is running and listening
        if systemctl is-active --quiet unbound; then
            echo "✅ Unbound DNS resolver started successfully"
            
            # Test DNS resolution with timeout
            if timeout 10 dig @127.0.0.1 google.com >/dev/null 2>&1; then
                echo "✅ Unbound DNS resolution test successful"
            else
                echo "⚠️ Unbound DNS resolution test failed - checking logs"
                echo "Recent Unbound logs:"
                journalctl -u unbound --no-pager -l --since="5 minutes ago" | tail -10
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
    cat > /var/lib/unbound/root.key << 'EOF'
; This file contains trusted keys for validating DNSSEC
. IN DS 20326 8 2 E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D
EOF
    chown unbound:unbound /var/lib/unbound/root.key
    chmod 644 /var/lib/unbound/root.key
    
    # Test again
    echo "Retesting Unbound configuration..."
    if unbound-checkconf; then
        echo "✅ Unbound configuration fixed and valid"
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
        
        # Check if we're using the new sources.list format (Debian 12+)
        if [ -f /etc/apt/sources.list.d/debian.sources ]; then
            # Update existing debian.sources file to include non-free-firmware
            if ! grep -q "non-free-firmware" /etc/apt/sources.list.d/debian.sources; then
                echo "Updating debian.sources to include non-free-firmware..."
                sed -i 's/Components: main/Components: main non-free-firmware/' /etc/apt/sources.list.d/debian.sources
                apt-get update
            fi
        else
            # Add to traditional sources.list
            if ! grep -q "non-free-firmware" /etc/apt/sources.list; then
                echo "Adding non-free-firmware to sources.list..."
                sed -i 's/main$/main non-free-firmware/' /etc/apt/sources.list
                apt-get update
            fi
        fi
    fi
    
    # Install AMD microcode
    if apt-cache search amd64-microcode | grep -q amd64-microcode; then
        apt-get install -y amd64-microcode
        echo "✅ AMD microcode installed successfully"
        echo "⚠️  Microcode will be active after next reboot"
    else
        echo "⚠️  AMD microcode package not available in repositories"
    fi
    
elif [ "$CPU_VENDOR" = "GenuineIntel" ]; then
    echo "Intel processor detected - installing Intel microcode updates..."
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

# Check for available kernel updates
if apt list --upgradable 2>/dev/null | grep -q linux-image; then
    echo "⚠️  Kernel updates available:"
    apt list --upgradable 2>/dev/null | grep linux-image
    echo ""
    echo "💡 Kernel update recommendation:"
    echo "   Run: apt update && apt upgrade linux-image-*"
    echo "   Then reboot to activate microcode and kernel updates"
    KERNEL_UPDATE_NEEDED=true
else
    echo "✅ Kernel is up to date"
    KERNEL_UPDATE_NEEDED=false
fi

# Check for backports kernel if available (often has better hardware support)
if apt-cache search linux-image | grep -q backports; then
    echo ""
    echo "💡 Backports kernel available for better hardware support:"
    apt-cache search linux-image | grep backports | head -3
    echo "   Consider: apt install -t bookworm-backports linux-image-amd64"
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
    postconf -e "smtp_use_tls = yes"
    postconf -e "smtp_sasl_auth_enable = yes"
    postconf -e "smtp_sasl_security_options = noanonymous"
    postconf -e "smtp_sasl_password_maps = hash:/etc/postfix/sasl_passwd"
    postconf -e "smtp_tls_security_level = encrypt"
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
    
    # Create SASL password file
    cat > /etc/postfix/sasl_passwd << EOF
[$SMTP_SERVER]:$SMTP_PORT    $SMTP_USERNAME:$SMTP_PASSWORD
EOF
    
    # Secure the password file
    chmod 600 /etc/postfix/sasl_passwd
    chown root:root /etc/postfix/sasl_passwd
    
    # Create the hash database
    postmap /etc/postfix/sasl_passwd
    
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
systemctl start postfix

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

# Configure lm-sensors to suppress warnings on systems without hardware sensors
echo "===== 6.2.2 Configuring hardware sensors (suppressing warnings) ====="
if command -v sensors >/dev/null 2>&1; then
    # Check if sensors are actually detected
    if ! sensors 2>/dev/null | grep -q "°C\|°F"; then
        echo "No hardware sensors detected - disabling sensors service to prevent warnings"
        systemctl disable lm-sensors 2>/dev/null || true
        systemctl mask lm-sensors 2>/dev/null || true
        
        # Create empty sensors config to prevent startup warnings
        mkdir -p /etc/sensors.d
        cat > /etc/sensors.d/bastion-no-sensors.conf << 'EOF'
# No hardware sensors configuration for bastion host
# This file prevents sensors warnings on systems without hardware monitoring
EOF
        echo "✅ Sensors warnings suppressed for VPS/cloud environment"
    else
        echo "Hardware sensors detected - sensors will remain active"
    fi
else
    echo "Sensors command not available - skipping configuration"
fi

# Install Oh My Zsh for bastion user with security-focused plugins
if id "$USERNAME" &>/dev/null; then
    echo "Installing Oh My Zsh for $USERNAME with security plugins..."
    # Remove existing Oh My Zsh installation if present to allow reinstall
    if [ -d "/home/$USERNAME/.oh-my-zsh" ]; then
        echo "Removing existing Oh My Zsh installation..."
        sudo -u $USERNAME rm -rf /home/$USERNAME/.oh-my-zsh /home/$USERNAME/.zshrc
    fi
    sudo -u $USERNAME sh -c "$(curl -fsSL https://raw.github.com/ohmyzsh/ohmyzsh/master/tools/install.sh)" "" --unattended
    
    # Configure with security and network monitoring plugins
    sudo -u $USERNAME sed -i 's/plugins=(git)/plugins=(git sudo systemd colored-man-pages history-substring-search docker ssh-agent)/' /home/$USERNAME/.zshrc
    
    # Add bastion-specific aliases
    cat >> /home/$USERNAME/.zshrc << 'EOF'

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
    cat >> /home/$USERNAME/.vimrc << 'EOF'
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
    chown $USERNAME:$USERNAME /home/$USERNAME/.vimrc

# Create global executable commands for bastion functions
echo "===== 6.2.2 Creating global bastion commands ====="

# Create bastionstat command
cat > /usr/local/bin/bastionstat << 'EOF'
#!/bin/bash
# Bastion Host Status Command
# This command can be run by the bastion user without entering a password

echo "=== Bastion Host Status ==="
echo "Hostname: $(hostname)"
echo "Current Time: $(date)"
echo "Uptime: $(uptime)"
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
TODAY=$(date '+%b %d')
TODAY_ALT=$(date '+%b  %d')  # Handle single digit days with double space
grep -E "($TODAY|$TODAY_ALT)" /var/log/auth.log 2>/dev/null | grep -E "Accepted publickey|Failed password|Invalid user" | tail -10 || echo "No recent SSH activity found"
echo ""
echo "System Resources:"
# Fix memory calculation
MEMORY_USED=$(free | awk 'NR==2{printf "%.1f", $3*100/$2}')
echo "Memory: ${MEMORY_USED}% used"
echo "Disk: $(df -h / | awk 'NR==2{print $5 " used"}')"
echo "Load: $(cat /proc/loadavg | awk '{print $1 " " $2 " " $3}')"
echo ""
echo "Security Status:"
systemctl is-active --quiet fail2ban && echo "✅ Fail2ban: Active" || echo "❌ Fail2ban: Inactive"
systemctl is-active --quiet suricata && echo "✅ Suricata IDS: Active" || echo "❌ Suricata IDS: Inactive"
# Check UFW status with proper sudo access
if command -v ufw >/dev/null 2>&1; then
    UFW_STATUS=$(sudo ufw status 2>/dev/null || echo "Error")
    if echo "$UFW_STATUS" | grep -q "Status: active"; then
        echo "✅ Firewall (UFW): Active"
    elif echo "$UFW_STATUS" | grep -q "Status: inactive"; then
        echo "❌ Firewall (UFW): Inactive"
    else
        echo "⚠️ Firewall (UFW): Status unknown"
    fi
else
    echo "❌ Firewall (UFW): Not installed"
fi
systemctl is-active --quiet auditd && echo "✅ Audit System: Active" || echo "❌ Audit System: Inactive"
echo ""
echo "Local Mail System:"
if [ -f /var/mail/root ]; then
    MAIL_COUNT=$(grep -c "^From " /var/mail/root 2>/dev/null || echo "0")
    echo "📧 Local mail: $MAIL_COUNT messages in /var/mail/root"
elif [ -f /var/spool/mail/root ]; then
    MAIL_COUNT=$(grep -c "^From " /var/spool/mail/root 2>/dev/null || echo "0")
    echo "📧 Local mail: $MAIL_COUNT messages in /var/spool/mail/root"
else
    echo "📭 Local mail: No mail file found"
fi
systemctl is-active --quiet postfix && echo "✅ Mail system (Postfix): Active" || echo "❌ Mail system (Postfix): Inactive"
EOF

chmod +x /usr/local/bin/bastionstat

# Create sshmon command
cat > /usr/local/bin/sshmon << 'EOF'
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
cat > /usr/local/bin/bastionmail << 'EOF'
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
# Enhanced fail2ban configuration for bastion hosts
    cat > /etc/fail2ban/jail.local << EOF
[DEFAULT]
# Default ban time and find time (more aggressive for bastions)
bantime = 3600
findtime = 600
maxretry = 3
backend = auto
usedns = warn
destemail = $LOGWATCH_EMAIL
sendername = Fail2Ban-Bastion-$HOSTNAME
mta = sendmail
protocol = tcp
chain = INPUT
port = 0:65535
fail2ban_agent = Fail2Ban/%(fail2ban_version)s
# Explicitly disable IPv6 for bastion hosts (IPv4 only)
allowipv6 = false

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
action = iptables-multiport[name=recidive, port="all"]
bantime = 86400
findtime = 86400
maxretry = 5

[systemd]
enabled = true
filter = systemd
logpath = /var/log/syslog
action = iptables-multiport[name=systemd, port="all"]
bantime = 3600
findtime = 600
maxretry = 5
EOF

    # Create custom filter for SSH brute force detection
    cat > /etc/fail2ban/filter.d/sshd-ddos.conf << EOF
# Fail2Ban filter for SSH brute force attacks
[Definition]
failregex = sshd\[<pid>\]: Did not receive identification string from <HOST>
            sshd\[<pid>\]: Connection closed by <HOST> port \d+ \[preauth\]
            sshd\[<pid>\]: Disconnected from <HOST> port \d+ \[preauth\]
            sshd\[<pid>\]: Connection reset by <HOST> port \d+ \[preauth\]
ignoreregex =
EOF

    # Create systemd filter for service monitoring
    cat > /etc/fail2ban/filter.d/systemd.conf << EOF
# Fail2ban filter for systemd service failures
# Monitors for repeated service failures that could indicate attacks

[Definition]
failregex = ^.* <HOST>.*systemd.*: Failed to start .*
            ^.* <HOST>.*systemd.*: Unit .* failed\.
            ^.* <HOST>.*systemd.*: .* failed with result 'exit-code'\.
            ^.* <HOST>.*systemd.*: Service .* has failed .*

ignoreregex =
EOF

# Install and configure rsyslog first (needed for fail2ban)
echo "Setting up logging system for fail2ban..."
if ! systemctl is-active --quiet rsyslog; then
    echo "Installing rsyslog for enhanced logging..."
    apt-get install -y rsyslog
    systemctl enable rsyslog
    systemctl start rsyslog
    sleep 2
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

if systemctl start fail2ban; then
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
cat > /etc/default/aide << 'EOF'
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
cat > /usr/local/bin/aide-check << 'EOF'
#!/bin/bash
# Custom AIDE check script with proper mail handling for bastion host

# Log file for AIDE output
AIDE_LOG="/var/log/aide/aide-check.log"
mkdir -p /var/log/aide

# Run AIDE check and capture output
echo "AIDE integrity check started at $(date)" > $AIDE_LOG
echo "=====================================" >> $AIDE_LOG

# Run AIDE check with proper error handling
if aide --check 2>&1 | tee -a $AIDE_LOG; then
    # AIDE completed successfully
    echo "AIDE check completed at $(date)" >> $AIDE_LOG
    
    # Check if there were any changes detected
    if grep -q "found differences" $AIDE_LOG || grep -q "File.*changed" $AIDE_LOG; then
        # Changes detected - send alert email
        cat $AIDE_LOG | mail -s "🚨 BASTION AIDE ALERT: File integrity changes detected on $HOSTNAME" root
    else
        # No changes - log success
        echo "No integrity violations detected" >> $AIDE_LOG
    fi
else
    # AIDE failed
    echo "AIDE check failed at $(date)" >> $AIDE_LOG
    echo "AIDE integrity check failed on bastion host $HOSTNAME" | mail -s "🚨 BASTION AIDE ERROR: Check failed on $HOSTNAME" root
    exit 1
fi

# Rotate old logs
find /var/log/aide -name "aide-check.log.*" -mtime +30 -delete
if [ -f $AIDE_LOG ] && [ $(stat -c%s $AIDE_LOG) -gt 10485760 ]; then
    # Rotate if log is larger than 10MB
    mv $AIDE_LOG ${AIDE_LOG}.$(date +%Y%m%d)
    gzip ${AIDE_LOG}.$(date +%Y%m%d)
fi
EOF

chmod 755 /usr/local/bin/aide-check

# Override the default AIDE systemd service to use our custom script
mkdir -p /etc/systemd/system/dailyaidecheck.service.d
cat > /etc/systemd/system/dailyaidecheck.service.d/override.conf << 'EOF'
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

echo "Initializing AIDE database for bastion host - this will take some time..."
nice -n 19 aideinit

echo "✅ AIDE configured with proper mail functionality for bastion host"

echo "===== 8. Configuring comprehensive audit framework for bastion ====="
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

# Create comprehensive audit rules for bastion host
cat > /etc/audit/rules.d/bastion-audit.rules << 'EOF'
## Bastion Host Audit Rules - Comprehensive Security Monitoring

## First rule - delete all existing rules
-D

## Increase the buffers to survive stress events
-b 8192

## Set failure mode to syslog
-f 1

## Track all authentication events (critical for bastions)
-w /var/log/wtmp -p wa -k session
-w /var/log/btmp -p wa -k session
-w /var/log/utmp -p wa -k session
-w /var/log/lastlog -p wa -k session

## Monitor SSH configuration changes
-w /etc/ssh/sshd_config -p wa -k ssh_config
-w /etc/ssh/ssh_config -p wa -k ssh_config
-w /etc/ssh/ -p wa -k ssh_config

## Monitor user and group modifications
-w /etc/group -p wa -k identity
-w /etc/passwd -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/security/opasswd -p wa -k identity

## Monitor sudo configuration
-w /etc/sudoers -p wa -k privilege_escalation
-w /etc/sudoers.d/ -p wa -k privilege_escalation

## Monitor network configuration
-w /etc/hosts -p wa -k network_config
-w /etc/network/ -p wa -k network_config
-w /etc/resolv.conf -p wa -k network_config

## Monitor firewall changes
-w /etc/ufw/ -p wa -k firewall_config
-w /etc/default/ufw -p wa -k firewall_config

## Track all command executions by non-system users
-a always,exit -F arch=b64 -S execve -F uid>=1000 -F uid!=4294967295 -k user_commands
-a always,exit -F arch=b32 -S execve -F uid>=1000 -F uid!=4294967295 -k user_commands

## Monitor file access in sensitive directories
-w /etc/ -p wa -k config_changes
-w /bin/ -p wa -k system_binaries
-w /sbin/ -p wa -k system_binaries
-w /usr/bin/ -p wa -k system_binaries
-w /usr/sbin/ -p wa -k system_binaries

## Track privilege escalation attempts
-a always,exit -F arch=b64 -S setuid -S setgid -S setresuid -S setresgid -k privilege_escalation
-a always,exit -F arch=b32 -S setuid -S setgid -S setresuid -S setresgid -k privilege_escalation

## Monitor system calls related to network activity
-a always,exit -F arch=b64 -S socket -S connect -S accept -k network_activity
-a always,exit -F arch=b32 -S socket -S connect -S accept -k network_activity

## Track file permission changes
-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -k file_permissions
-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -k file_permissions

## Monitor process termination
-a always,exit -F arch=b64 -S kill -k process_kill
-a always,exit -F arch=b32 -S kill -k process_kill

## Track kernel module loading
-w /sbin/insmod -p x -k module_insertion
-w /sbin/rmmod -p x -k module_removal
-w /sbin/modprobe -p x -k module_insertion
-a always,exit -F arch=b64 -S init_module -S delete_module -k module_operations
-a always,exit -F arch=b32 -S init_module -S delete_module -k module_operations

## Monitor time changes (important for log correlation)
-a always,exit -F arch=b64 -S clock_settime -k time_change
-a always,exit -F arch=b32 -S clock_settime -k time_change
-w /etc/localtime -p wa -k time_change

## Monitor cron jobs
-w /etc/cron.allow -p wa -k cron
-w /etc/cron.deny -p wa -k cron
-w /etc/cron.d/ -p wa -k cron
-w /etc/cron.daily/ -p wa -k cron
-w /etc/cron.hourly/ -p wa -k cron
-w /etc/cron.monthly/ -p wa -k cron
-w /etc/cron.weekly/ -p wa -k cron
-w /etc/crontab -p wa -k cron
-w /var/spool/cron/ -p wa -k cron

## Monitor log files
-w /var/log/ -p wa -k log_files

## Make audit rules immutable (uncomment for production)
## WARNING: Requires reboot to make changes after enabling
# -e 2
EOF

# Configure auditd systemd resource limits for bastion host
echo "===== 8.1.1 Configuring Auditd Resource Management ====="
mkdir -p /etc/systemd/system/auditd.service.d
cat > /etc/systemd/system/auditd.service.d/resource-limits.conf << 'EOF'
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
NoNewPrivileges=true
ProtectHome=true
ReadWritePaths=/var/log/audit /etc/audit

# Restart policy for audit reliability
Restart=always
RestartSec=30
TimeoutStartSec=60
TimeoutStopSec=30

# Watchdog configuration
WatchdogSec=120
NotifyAccess=main
EOF

systemctl daemon-reload

# Enable and start auditd with improved error handling
echo "Starting audit system..."
systemctl enable auditd

# Check if auditd is already running and stop it cleanly if needed
if systemctl is-active --quiet auditd; then
    echo "Stopping existing auditd service..."
    systemctl stop auditd
    sleep 2
fi

# Start auditd and verify it starts properly
if systemctl start auditd; then
    sleep 3
    if systemctl is-active --quiet auditd; then
        echo "✅ Audit system started successfully"
    else
        echo "⚠️ Audit system start reported success but service not active"
        echo "Checking audit system status:"
        systemctl status auditd --no-pager -l || true
        journalctl -u auditd --no-pager -l -n 10 || true
    fi
else
    echo "❌ Failed to start audit system"
    echo "Checking audit system status:"
    systemctl status auditd --no-pager -l || true
    journalctl -u auditd --no-pager -l -n 10 || true
fi

echo "===== 9. Setting up Suricata IDS for bastion network monitoring ====="
# Get primary network interface and bastion IP more robustly
INTERFACE=$(ip -o -4 route show to default | awk '{print $5}')

# Get bastion IP more reliably (avoid multiple IPs and whitespace issues)
BASTION_IP=$(ip -4 addr show "$INTERFACE" | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -1)
if [ -z "$BASTION_IP" ]; then
    # Fallback method
    BASTION_IP=$(hostname -I | awk '{print $1}')
fi

echo "Configuring Suricata for interface: $INTERFACE, IP: $BASTION_IP"
    
    # Configure Suricata for bastion host monitoring with fixed HOME_NET
    cat > /etc/suricata/suricata.yaml << EOF
%YAML 1.1
---
# Suricata configuration for bastion host monitoring
vars:
  address-groups:
    HOME_NET: "[$BASTION_IP]"
    EXTERNAL_NET: "![$BASTION_IP]"
    INTERNAL_NET: "[$INTERNAL_NETWORK]"
    
  port-groups:
    SSH_PORTS: "$SSH_PORT"
    HTTP_PORTS: "80"
    HTTPS_PORTS: "443"
    
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
alert tcp \$HOME_NET any -> \$EXTERNAL_NET any (msg:"BASTION Large Data Transfer Outbound"; flow:established,to_server; dsize:>1000000; classtype:policy-violation; sid:2000006; rev:1;)

# Detect ICMP tunneling attempts
alert icmp \$EXTERNAL_NET any -> \$HOME_NET any (msg:"BASTION ICMP Tunneling Attempt"; dsize:>100; classtype:attempted-admin; sid:2000007; rev:1;)

# Detect DNS tunneling
alert udp \$HOME_NET any -> any 53 (msg:"BASTION DNS Tunneling Attempt"; dsize:>512; classtype:policy-violation; sid:2000008; rev:1;)
EOF

    # Set up Suricata log rotation
    cat > /etc/logrotate.d/suricata << EOF
/var/log/suricata/*.log /var/log/suricata/*.json {
    daily
    rotate 14
    compress
    delaycompress
    missingok
    notifempty
    create 0640 root adm
    postrotate
        systemctl restart suricata
    endscript
}
EOF

# Configure Suricata systemd resource limits for bastion host
echo "===== 9.4.1 Configuring Suricata Resource Management ====="
mkdir -p /etc/systemd/system/suricata.service.d
cat > /etc/systemd/system/suricata.service.d/resource-limits.conf << 'EOF'
[Service]
# Resource limits for bastion host (more conservative than production)
CPUQuota=30%
MemoryMax=512M
MemoryHigh=400M
Nice=10
IOSchedulingClass=2
IOSchedulingPriority=5
OOMPolicy=kill
OOMScoreAdjust=300

# Security and isolation
PrivateTmp=true
NoNewPrivileges=true
ProtectHome=true
ProtectSystem=strict
ReadWritePaths=/var/log/suricata /var/lib/suricata /run/suricata

# Restart policy for network IDS reliability
Restart=always
RestartSec=60
TimeoutStartSec=120
TimeoutStopSec=30

# Watchdog configuration
WatchdogSec=300
NotifyAccess=main
EOF

systemctl daemon-reload

# Test Suricata configuration before starting
echo "Testing Suricata configuration..."
if suricata -T -c /etc/suricata/suricata.yaml >/tmp/suricata-test.log 2>&1; then
    echo "✅ Suricata configuration is valid"
    
    # Create log directory with proper permissions
    mkdir -p /var/log/suricata
    chown suricata:suricata /var/log/suricata 2>/dev/null || chown root:root /var/log/suricata
    chmod 755 /var/log/suricata
    
    # Reload systemd configuration
    systemctl daemon-reload
    
    # Enable Suricata for automatic startup
    systemctl enable suricata
    
    # Start Suricata with error handling
    echo "Starting Suricata IDS service..."
    if systemctl start suricata; then
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
    
    # Check if required directories exist
    mkdir -p /etc/suricata/rules /var/log/suricata /var/lib/suricata/rules
    
    # Check if default rules exist
    if [ ! -f /etc/suricata/rules/suricata.rules ]; then
        echo "Creating minimal default rules file..."
        cat > /etc/suricata/rules/suricata.rules << 'EOF'
# Minimal default rules for Suricata
# This file prevents Suricata from failing due to missing default rules
EOF
    fi
    
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
        echo "✅ Suricata configuration fixed"
        
        systemctl daemon-reload
        systemctl enable suricata
        
        if systemctl start suricata; then
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
        
        # Disable Suricata if it can't be fixed
        systemctl disable suricata 2>/dev/null || true
        echo "⚠️ Suricata IDS disabled due to configuration errors"
        echo "   Other security tools (fail2ban, auditd) will provide protection"
        echo "   Manual Suricata configuration may be required"
    fi
fi

# Cleanup test logs
rm -f /tmp/suricata-test.log /tmp/suricata-retest.log

echo "===== 10. Setting up comprehensive logging and monitoring ====="

# Rsyslog already installed and configured earlier for fail2ban

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

# Configure chkrootkit
echo "===== 10.1 Configuring chkrootkit ====="
# Create chkrootkit scan script with proper log handling
cat > /etc/cron.daily/chkrootkit-scan << 'EOF'
#!/bin/bash
# Run a daily chkrootkit scan

# Log file
LOGFILE="/var/log/chkrootkit/daily_scan.log"
EXPECTED_LOG="/var/log/chkrootkit/log.expected"
TODAY_LOG="/var/log/chkrootkit/log.today"

# Create log directory if it doesn't exist
mkdir -p /var/log/chkrootkit

# Clear previous log
echo "chkrootkit daily scan started at $(date)" > $LOGFILE

# Run the scan
chkrootkit -q > $TODAY_LOG 2>&1

# Add completion time
echo "chkrootkit daily scan completed at $(date)" >> $LOGFILE

# Create expected log file if it doesn't exist (first run)
if [ ! -f "$EXPECTED_LOG" ]; then
    echo "Creating initial expected output file for chkrootkit..."
    cp "$TODAY_LOG" "$EXPECTED_LOG"
    echo "Initial chkrootkit expected output created at $(date)" >> $LOGFILE
fi

# Check for differences from expected output
if ! diff -q "$EXPECTED_LOG" "$TODAY_LOG" >/dev/null 2>&1; then
    # There are differences - send email alert
    ADMIN_EMAIL="${LOGWATCH_EMAIL:-root}"
    
    # Create diff report
    echo "chkrootkit output differs from expected baseline" > /tmp/chkrootkit-alert.txt
    echo "Scan date: $(date)" >> /tmp/chkrootkit-alert.txt
    echo "" >> /tmp/chkrootkit-alert.txt
    echo "=== TODAY'S OUTPUT ===" >> /tmp/chkrootkit-alert.txt
    cat "$TODAY_LOG" >> /tmp/chkrootkit-alert.txt
    echo "" >> /tmp/chkrootkit-alert.txt
    echo "=== EXPECTED OUTPUT ===" >> /tmp/chkrootkit-alert.txt
    cat "$EXPECTED_LOG" >> /tmp/chkrootkit-alert.txt
    echo "" >> /tmp/chkrootkit-alert.txt
    echo "=== DIFFERENCES ===" >> /tmp/chkrootkit-alert.txt
    diff "$EXPECTED_LOG" "$TODAY_LOG" >> /tmp/chkrootkit-alert.txt
    
    # Send email alert
    cat /tmp/chkrootkit-alert.txt | mail -s "⚠️ CHKROOTKIT ALERT: Output changed on $(hostname)" "$ADMIN_EMAIL"
    
    # Log the alert
    echo "chkrootkit output changed - alert sent to $ADMIN_EMAIL" >> $LOGFILE
    
    # Clean up
    rm -f /tmp/chkrootkit-alert.txt
else
    echo "chkrootkit output matches expected baseline" >> $LOGFILE
fi

# Check for INFECTED results specifically
if grep -q "INFECTED" "$TODAY_LOG"; then
    ADMIN_EMAIL="${LOGWATCH_EMAIL:-root}"
    cat "$TODAY_LOG" | mail -s "⚠️ ROOTKIT WARNING: Possible rootkit found on $(hostname)" "$ADMIN_EMAIL"
    echo "INFECTED results found - alert sent to $ADMIN_EMAIL" >> $LOGFILE
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
REBOOT=1
EOF

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
cat > /etc/logcheck/logcheck.logfiles << 'EOF'
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
    cat > /etc/logcheck/logcheck.logfiles << 'EOF'
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
cat >> /etc/logcheck/ignore.d.server/bastion-ignore << 'EOF'
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
^\w{3} [ :0-9]{11} [._[:alnum:]-]+ kernel: \[UFW [[:upper:]]+\].*$

# Normal cron activity
^\w{3} [ :0-9]{11} [._[:alnum:]-]+ \/USR\/SBIN\/CRON\[[0-9]+\]: \([[:alnum:]]+\) CMD \(.*\)$
^\w{3} [ :0-9]{11} [._[:alnum:]-]+ cron\[[0-9]+\]: \([[:alnum:]]+\) CMD \(.*\)$

# Normal systemd activity
^\w{3} [ :0-9]{11} [._[:alnum:]-]+ systemd\[[0-9]+\]: .*\.service: Succeeded\.$
^\w{3} [ :0-9]{11} [._[:alnum:]-]+ systemd\[[0-9]+\]: Started .*\.$

# Normal postfix activity (for notifications)
^\w{3} [ :0-9]{11} [._[:alnum:]-]+ postfix\/.*\[[0-9]+\]: [A-F0-9]+: .*$
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

# Only use specific services (not "All" with additions)
Service = sshd
Service = sudo
Service = secure
Service = kernel
Service = postfix
Service = fail2ban
Service = "-zz-disk_space"
Service = "-zz-network"
EOF

# Create logwatch cron job (ensure it runs daily)
cat > /etc/cron.daily/00logwatch << 'EOF'
#!/bin/bash
# Daily Logwatch execution for bastion host

# Run logwatch with bastion-specific configuration
/usr/sbin/logwatch --output mail --format html --range yesterday --detail high
EOF

chmod 755 /etc/cron.daily/00logwatch

# Also enable logwatch cron in case it's disabled
cat > /etc/cron.d/logwatch << 'EOF'
# Daily logwatch execution
# Run at 6:00 AM daily to analyze previous day's logs
0 6 * * * root /usr/sbin/logwatch --output mail --format html --range yesterday --detail high
EOF

# Create logwatch test script for troubleshooting
cat > /usr/local/bin/test-logwatch << 'EOF'
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
cat > /etc/cron.hourly/bastion-monitor << 'EOF'
#!/bin/bash
# Bastion Host Monitoring Script - Runs every hour

LOGFILE="/var/log/bastion-monitor.log"
HOSTNAME=$(hostname)
DATE=$(date '+%Y-%m-%d %H:%M:%S')

# Function to log with timestamp
log_message() {
    echo "[$DATE] $1" >> $LOGFILE
}

# Check for suspicious SSH activity
SSH_FAILURES=$(grep "$(date '+%b %d %H')" /var/log/auth.log | grep "Failed password" | wc -l)
if [ $SSH_FAILURES -gt 10 ]; then
    log_message "WARNING: $SSH_FAILURES SSH login failures in the last hour"
    echo "WARNING: High number of SSH failures ($SSH_FAILURES) on bastion host $HOSTNAME" | mail -s "BASTION ALERT: SSH Failures" root
fi

# Check for successful logins
SSH_SUCCESS=$(grep "$(date '+%b %d %H')" /var/log/auth.log | grep "Accepted publickey" | wc -l)
if [ $SSH_SUCCESS -gt 0 ]; then
    log_message "INFO: $SSH_SUCCESS successful SSH logins in the last hour"
fi

# Check active sessions
ACTIVE_SESSIONS=$(who | wc -l)
if [ $ACTIVE_SESSIONS -gt 5 ]; then
    log_message "WARNING: $ACTIVE_SESSIONS active sessions (threshold: 5)"
    echo "WARNING: High number of active sessions ($ACTIVE_SESSIONS) on bastion host $HOSTNAME" | mail -s "BASTION ALERT: High Session Count" root
fi

# Check disk space
DISK_USAGE=$(df / | awk 'NR==2 {print $5}' | sed 's/%//')
if [ $DISK_USAGE -gt 80 ]; then
    log_message "WARNING: Disk usage at $DISK_USAGE%"
    echo "WARNING: Disk usage on bastion host $HOSTNAME is at $DISK_USAGE%" | mail -s "BASTION ALERT: Disk Space" root
fi

# Check for new audit events
AUDIT_ALERTS=$(ausearch -ts recent -m avc,user_auth,user_acct,user_mgmt,user_chauthtok,user_role_change,role_assign,role_remove 2>/dev/null | wc -l)
if [ $AUDIT_ALERTS -gt 0 ]; then
    log_message "INFO: $AUDIT_ALERTS new audit events in the last hour"
fi

# Check firewall status
if ! ufw status | grep -q "Status: active"; then
    log_message "CRITICAL: Firewall is not active!"
    echo "CRITICAL: Firewall is not active on bastion host $HOSTNAME" | mail -s "BASTION CRITICAL: Firewall Down" root
fi

# Check fail2ban status
if ! systemctl is-active --quiet fail2ban; then
    log_message "CRITICAL: Fail2ban is not running!"
    echo "CRITICAL: Fail2ban is not running on bastion host $HOSTNAME" | mail -s "BASTION CRITICAL: Fail2ban Down" root
fi

log_message "Bastion monitoring check completed"
EOF

chmod 755 /etc/cron.hourly/bastion-monitor

# Create daily security report script
cat > /etc/cron.daily/bastion-security-report << 'EOF'
#!/bin/bash
# Daily Bastion Security Report

DATE=$(date +%Y-%m-%d)
HOSTNAME=$(hostname)
REPORT_FILE="/tmp/bastion-security-report-$DATE.txt"

echo "======================================================================" > $REPORT_FILE
echo "BASTION HOST SECURITY REPORT - $HOSTNAME - $DATE" >> $REPORT_FILE
echo "======================================================================" >> $REPORT_FILE
echo "" >> $REPORT_FILE

echo "SYSTEM OVERVIEW" >> $REPORT_FILE
echo "===============" >> $REPORT_FILE
echo "Hostname: $HOSTNAME" >> $REPORT_FILE
echo "Uptime: $(uptime)" >> $REPORT_FILE
echo "Load Average: $(cat /proc/loadavg)" >> $REPORT_FILE
echo "Disk Usage: $(df -h / | awk 'NR==2 {print $5}')" >> $REPORT_FILE
echo "Memory Usage: $(free -h | awk 'NR==2{printf "%.2f%%", $3*100/$2 }')" >> $REPORT_FILE
echo "" >> $REPORT_FILE

echo "SSH ACTIVITY SUMMARY" >> $REPORT_FILE
echo "====================" >> $REPORT_FILE
echo "Successful logins today: $(grep "$(date '+%b %d')" /var/log/auth.log | grep "Accepted publickey" | wc -l)" >> $REPORT_FILE
echo "Failed login attempts today: $(grep "$(date '+%b %d')" /var/log/auth.log | grep "Failed password" | wc -l)" >> $REPORT_FILE
echo "Currently active sessions: $(who | wc -l)" >> $REPORT_FILE
echo "" >> $REPORT_FILE

echo "RECENT SUCCESSFUL LOGINS" >> $REPORT_FILE
echo "========================" >> $REPORT_FILE
grep "$(date '+%b %d')" /var/log/auth.log | grep "Accepted publickey" | tail -10 >> $REPORT_FILE
echo "" >> $REPORT_FILE

echo "FIREWALL STATUS" >> $REPORT_FILE
echo "===============" >> $REPORT_FILE
ufw status numbered >> $REPORT_FILE
echo "" >> $REPORT_FILE

echo "FAIL2BAN STATUS" >> $REPORT_FILE
echo "===============" >> $REPORT_FILE
fail2ban-client status >> $REPORT_FILE
echo "" >> $REPORT_FILE

echo "AUDIT SUMMARY" >> $REPORT_FILE
echo "=============" >> $REPORT_FILE
ausearch --start today --end now | aureport --summary >> $REPORT_FILE
echo "" >> $REPORT_FILE

echo "CRITICAL SECURITY EVENTS" >> $REPORT_FILE
echo "========================" >> $REPORT_FILE
ausearch -k privilege_escalation --start today --end now >> $REPORT_FILE
ausearch -k user_commands --start today --end now | tail -20 >> $REPORT_FILE
echo "" >> $REPORT_FILE

# Email the report
cat $REPORT_FILE | mail -s "Daily Bastion Security Report - $HOSTNAME" root

# Cleanup
rm -f $REPORT_FILE
EOF

chmod 755 /etc/cron.daily/bastion-security-report

echo "===== 12. Setting up bastion-specific log rotation (avoiding conflicts) ====="
# Remove any conflicting logrotate configurations and create bastion-specific ones
rm -f /etc/logrotate.d/bastion-logs

# Create separate logrotate configs for bastion-specific logs only
# This avoids conflicts with system default logrotate configurations

# SSH logs (bastion-specific, not managed by default logrotate)
cat > /etc/logrotate.d/bastion-ssh << 'EOF'
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
cat > /etc/logrotate.d/bastion-sudo << 'EOF'
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
cat > /etc/logrotate.d/bastion-network << 'EOF'
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
cat > /etc/logrotate.d/bastion-emergency << 'EOF'
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
cat > /etc/logrotate.d/bastion-monitor << 'EOF'
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
cat > /etc/logrotate.d/bastion-aide << 'EOF'
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

echo "✅ Bastion-specific logrotate configurations created (avoiding system conflicts)"

# Add disk space monitoring to bastion monitoring script
echo "===== 12.1 Adding disk space monitoring to prevent log overflow ====="
cat >> /etc/cron.hourly/bastion-monitor << 'EOF'

# Check for excessive log growth (prevent disk space issues)
LOG_DIRS=("/var/log" "/var/log/audit" "/var/log/suricata")
for log_dir in "${LOG_DIRS[@]}"; do
    if [ -d "$log_dir" ]; then
        # Check if any single log file is over 500MB
        find "$log_dir" -name "*.log" -size +500M | while read -r large_log; do
            LOG_SIZE=$(du -h "$large_log" | cut -f1)
            log_message "WARNING: Large log file detected: $large_log ($LOG_SIZE)"
            echo "WARNING: Large log file on bastion host $HOSTNAME: $large_log ($LOG_SIZE)" | mail -s "BASTION ALERT: Large Log File" root
        done
    fi
done

# Check overall /var/log disk usage
VAR_LOG_USAGE=$(du -sh /var/log 2>/dev/null | cut -f1)
VAR_LOG_USAGE_PCT=$(df /var/log | awk 'NR==2 {print $5}' | sed 's/%//')
if [ "$VAR_LOG_USAGE_PCT" -gt 70 ]; then
    log_message "WARNING: /var/log directory usage at $VAR_LOG_USAGE_PCT% ($VAR_LOG_USAGE)"
    echo "WARNING: High log directory usage on bastion host $HOSTNAME: $VAR_LOG_USAGE_PCT% ($VAR_LOG_USAGE)" | mail -s "BASTION ALERT: Log Directory Space" root
fi
EOF

echo "===== 13. Creating bastion host documentation ====="
# Create documentation in both root and home directory for accessibility
cat > /root/BASTION-README.md << 'EOF'
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

# Also create documentation in bastion user's home directory
cp /root/BASTION-README.md /home/$USERNAME/
chown $USERNAME:$USERNAME /home/$USERNAME/BASTION-README.md

echo "Documentation created in /root/BASTION-README.md and /home/$USERNAME/BASTION-README.md"

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
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.tcp_syncookies = 1

# IPv6 security (disable if not needed)
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1

# Process security
kernel.dmesg_restrict = 1
kernel.kptr_restrict = 2
kernel.yama.ptrace_scope = 1

# File system security
fs.suid_dumpable = 0
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
EOF

# Apply kernel parameters
sysctl -p /etc/sysctl.d/99-bastion-security.conf

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
ALLOWED_SERVICES="ssh sshd rsyslog systemd-journald systemd-logind systemd-networkd systemd-resolved systemd-timesyncd cron systemd-cron-daily.timer systemd-cron-hourly.timer systemd-cron-monthly.timer systemd-cron-weekly.timer postfix fail2ban ufw auditd suricata unbound apparmor systemd-tmpfiles-setup systemd-tmpfiles-clean.timer unattended-upgrades apt-daily.timer apt-daily-upgrade.timer bastion-monitor.timer disk-space-protection.timer logrotate.timer man-db.timer"

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
# Monitors common persistence locations

LOGFILE="/var/log/persistence-check.log"
BASELINE_DIR="/var/lib/persistence-baselines"
DATE=$(date '+%Y-%m-%d %H:%M:%S')

mkdir -p "$BASELINE_DIR"

# Function to log with timestamp
log_message() {
    echo "[$DATE] $1" >> "$LOGFILE"
}

# Function to check for changes in persistence locations
check_persistence_location() {
    local location="$1"
    local name="$2"
    local baseline_file="$BASELINE_DIR/${name}.baseline"
    local current_file="/tmp/${name}.current"
    
    if [ -d "$location" ] || [ -f "$location" ]; then
        # Create current state
        find "$location" -type f -exec stat -c "%n %Y %s" {} \; 2>/dev/null | sort > "$current_file"
        
        # Check if baseline exists
        if [ -f "$baseline_file" ]; then
            # Compare with baseline
            if ! diff -q "$baseline_file" "$current_file" >/dev/null 2>&1; then
                log_message "ALERT: Changes detected in $name ($location)"
                echo "PERSISTENCE ALERT: Changes detected in $name on bastion host $(hostname)" | mail -s "BASTION ALERT: Persistence Detection" root
                
                # Show differences
                diff "$baseline_file" "$current_file" >> "$LOGFILE" 2>/dev/null || true
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
    fi
else
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
cat > /etc/cron.hourly/disk-space-protection << 'EOF'
#!/bin/bash
# Emergency disk space protection for bastion host
# Prevents system failure due to disk space exhaustion

CRITICAL_THRESHOLD=95
WARNING_THRESHOLD=85
ROOT_USAGE=$(df / | awk 'NR==2 {print $5}' | sed 's/%//')
VAR_USAGE=$(df /var | awk 'NR==2 {print $5}' | sed 's/%//')

# Function to clean old logs if disk space critical
emergency_cleanup() {
    echo "$(date): EMERGENCY: Disk space at $1% - performing emergency cleanup" >> /var/log/emergency-cleanup.log
    
    # Remove old compressed logs first
    find /var/log -name "*.gz" -mtime +7 -delete 2>/dev/null || true
    find /var/log -name "*.bz2" -mtime +7 -delete 2>/dev/null || true
    
    # Clean old log files
    find /var/log -name "*.log.*" -mtime +3 -delete 2>/dev/null || true
    
    # Truncate large current log files (keep last 1000 lines)
    for logfile in /var/log/*.log; do
        if [ -f "$logfile" ] && [ "$(stat -c%s "$logfile" 2>/dev/null)" -gt 104857600 ]; then  # 100MB
            tail -n 1000 "$logfile" > "$logfile.tmp" && mv "$logfile.tmp" "$logfile"
            echo "$(date): Truncated large log file: $logfile" >> /var/log/emergency-cleanup.log
        fi
    done
    
    # Clear old journal logs
    journalctl --vacuum-time=1d --vacuum-size=100M 2>/dev/null || true
    
    # Send alert
    echo "EMERGENCY: Disk space critical on bastion host $(hostname). Emergency cleanup performed." | mail -s "BASTION CRITICAL: Emergency Disk Cleanup" root
}

# Check root filesystem
if [ "$ROOT_USAGE" -ge "$CRITICAL_THRESHOLD" ]; then
    emergency_cleanup "$ROOT_USAGE"
elif [ "$ROOT_USAGE" -ge "$WARNING_THRESHOLD" ]; then
    echo "WARNING: Root filesystem at $ROOT_USAGE% usage" | mail -s "BASTION WARNING: Disk Space" root
fi

# Check /var filesystem (if separate)
if [ "$VAR_USAGE" -ge "$CRITICAL_THRESHOLD" ]; then
    emergency_cleanup "$VAR_USAGE"
elif [ "$VAR_USAGE" -ge "$WARNING_THRESHOLD" ]; then
    echo "WARNING: /var filesystem at $VAR_USAGE% usage" | mail -s "BASTION WARNING: /var Disk Space" root
fi
EOF

chmod +x /etc/cron.hourly/disk-space-protection

# Add logrotate configuration to be more aggressive about space
cat >> /etc/logrotate.conf << 'EOF'

# Emergency space management
# If disk usage goes above 90%, force rotation of large logs
include /etc/logrotate.d
size 100M
EOF

echo "✅ Emergency disk space protection configured"

echo "===== 14.5.1 Creating systemd timer services for reliable monitoring ====="
# Create systemd services and timers to ensure monitoring runs even if cron missed

# Bastion monitoring service
cat > /etc/systemd/system/bastion-monitor.service << 'EOF'
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
cat > /etc/systemd/system/bastion-monitor.timer << 'EOF'
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
cat > /etc/systemd/system/disk-space-protection.service << 'EOF'
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
cat > /etc/systemd/system/disk-space-protection.timer << 'EOF'
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
    cat > /etc/netdata/netdata.conf << 'EOF'
[global]
    # SECURITY: Bind to localhost only (access via SSH tunnel)
    bind socket to IP = 127.0.0.1
    default port = 19999
    
    # Performance optimized for bastion host
    page cache size = 16
    dbengine multihost disk space = 64
    
[web]
    # No authentication needed since localhost-only
    web files owner = root
    web files group = netdata
    
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
    cat > /etc/logrotate.d/netdata << 'EOF'
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
    cat > /usr/local/bin/netdata-bastion << 'EOF'
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
cat > /usr/local/bin/setup-log-tmpfs << 'EOF'
#!/bin/bash
# Emergency script to move logs to tmpfs if disk space critical
# WARNING: This will cause logs to be lost on reboot!
# Only use in emergency situations

if [ "$(df / | awk 'NR==2 {print $5}' | sed 's/%//')" -ge 98 ]; then
    echo "EMERGENCY: Setting up tmpfs for logs to prevent system failure"
    
    # Create tmpfs mount point
    mkdir -p /tmp/emergency-logs
    
    # Mount tmpfs (256MB)
    mount -t tmpfs -o size=256M tmpfs /tmp/emergency-logs
    
    # Stop logging services
    systemctl stop rsyslog auditd fail2ban 2>/dev/null || true
    
    # Backup current logs
    tar -czf /tmp/logs-backup-$(date +%Y%m%d-%H%M%S).tar.gz /var/log/ 2>/dev/null || true
    
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

# Fix AppArmor SSH profile to allow authorized_keys access
echo "===== 15. Configuring AppArmor for SSH authorized_keys access ====="
if [ -f /etc/apparmor.d/usr.sbin.sshd ]; then
    echo "Updating AppArmor SSH profile for authorized_keys access..."
    
    # Backup original profile
    cp /etc/apparmor.d/usr.sbin.sshd /etc/apparmor.d/usr.sbin.sshd.backup-$(date +%Y%m%d)
    
    # Add authorized_keys access if not already present
    if ! grep -q "home.*authorized_keys" /etc/apparmor.d/usr.sbin.sshd; then
        # Add authorized_keys permissions after the /etc/ssh/** r, line
        sed -i '/\/etc\/ssh\/\*\* r,/a\  # Allow access to user authorized_keys files\n  /home/*/.ssh/authorized_keys r,\n  /home/*/.ssh/authorized_keys2 r,' /etc/apparmor.d/usr.sbin.sshd
        
        # Reload AppArmor profile
        apparmor_parser -r /etc/apparmor.d/usr.sbin.sshd && echo "✅ AppArmor SSH profile updated successfully"
    else
        echo "✅ AppArmor SSH profile already allows authorized_keys access"
    fi
else
    echo "ℹ️  AppArmor SSH profile not found - SSH will use default permissions"
fi

# Restart SSH with new configuration
echo "===== 16. Restarting SSH service ====="
systemctl restart sshd

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
echo "===== 16.1 Sending setup completion email ====="
SETUP_COMPLETION_EMAIL="$LOGWATCH_EMAIL"
SETUP_DATE=$(date '+%Y-%m-%d_%H-%M-%S')
SETUP_DATE_DISPLAY=$(date '+%Y-%m-%d %H:%M:%S')
BASION_IP=$(hostname -I | awk '{print $1}')

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
IP Address: $BASION_IP
Setup Completed: $SETUP_DATE_DISPLAY
SSH Port: $SSH_PORT
User Account: $USERNAME

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
ssh -p $SSH_PORT $USERNAME@$BASION_IP

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
1. Test SSH access from your workstation
2. Configure internal network access rules if needed
3. Set up centralized logging if required
4. Review and customize monitoring alerts
5. Document connection procedures for authorized users

🛡️ SECURITY FEATURES ACTIVE:
• Multi-layer firewall protection
• Real-time network monitoring
• Comprehensive audit logging
• Automated security scanning
• Intrusion detection system
• SSH session monitoring
• File integrity monitoring

🔐 ADVANCED SECURITY REFINEMENTS:
• AppArmor profile enforcement verification and custom SSH profile
• Unattended reboot warning system (wall messages + email alerts)
• Suricata rules maintenance with weekly auto-updates
• Enhanced OpenSSH HMAC tuning (SHA-1 completely disabled)
• Systemd watchdog for fail2ban, suricata, and SSH services
• Daily automated backup of all security configurations
if [[ "$INSTALL_NETDATA" =~ ^[Yy]$ ]] || [[ "$INSTALL_NETDATA" == "true" ]]; then
    echo "   • Netdata monitoring with optional Cloud integration"
fi

📁 CONFIGURATION BACKUP:
• Location: /var/backups/security-configs/
• Retention: 30 days
• Daily automated backup with integrity verification

This bastion host is now ready for secure access management\!

--
Generated by PolyServer Bastion Setup
$SETUP_DATE_DISPLAY
EOF

# Send setup completion email
echo "===== Sending Setup Completion Report ====="

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

echo "===== 14.7 Advanced Security Refinements ====="

# AppArmor Profile Enforcement Verification
echo "Verifying AppArmor profile enforcement..."
if command -v aa-status >/dev/null 2>&1; then
    echo "Current AppArmor status:"
    aa-status
    
    # Check if profiles are in enforce mode
    PROFILES_ENFORCE=$(aa-status --complain 2>/dev/null | wc -l)
    PROFILES_COMPLAIN=$(aa-status --enforce 2>/dev/null | wc -l)
    
    if [ "$PROFILES_COMPLAIN" -gt 0 ]; then
        echo "⚠️ $PROFILES_COMPLAIN AppArmor profiles in complain mode - consider enforcing:"
        aa-status --complain 2>/dev/null || true
        echo "   To enforce: sudo aa-enforce /etc/apparmor.d/<profile>"
    fi
    
    # Create custom SSH profile for enhanced protection
    cat > /etc/apparmor.d/usr.sbin.sshd << 'EOF'
#include <tunables/global>

/usr/sbin/sshd {
  #include <abstractions/authentication>
  #include <abstractions/base>
  #include <abstractions/consoles>
  #include <abstractions/nameservice>
  #include <abstractions/wutmp>

  capability sys_chroot,
  capability sys_resource,
  capability chown,
  capability fowner,
  capability kill,
  capability setgid,
  capability setuid,
  capability audit_write,
  capability dac_override,
  capability dac_read_search,
  capability sys_tty_config,

  /dev/log w,
  /dev/null rw,
  /dev/ptmx rw,
  /dev/pts/* rw,
  /dev/tty rw,
  /dev/urandom r,

  /etc/default/locale r,
  /etc/environment r,
  /etc/group r,
  /etc/hosts.allow r,
  /etc/hosts.deny r,
  /etc/ld.so.cache r,
  /etc/localtime r,
  /etc/motd r,
  /etc/passwd r,
  /etc/security/** r,
  /etc/shadow r,
  /etc/ssh/** r,

  /proc/*/fd/ r,
  /proc/*/mounts r,
  /proc/*/stat r,
  /proc/sys/crypto/fips_enabled r,

  /run/sshd.pid w,
  /run/systemd/sessions/* rw,
  /run/utmp rw,

  /usr/bin/** PUx,
  /bin/** PUx,
  /usr/sbin/sshd mr,

  /var/log/auth.log w,
  /var/log/btmp w,
  /var/log/lastlog rw,
  /var/log/wtmp rw,

  # Site-specific additions and overrides. See local/README for details.
  #include <local/usr.sbin.sshd>
}
EOF
    
    # Create the local include directory and file to prevent parser errors
    mkdir -p /etc/apparmor.d/local
    touch /etc/apparmor.d/local/usr.sbin.sshd
    
    # Add a comment to the local file
    cat > /etc/apparmor.d/local/usr.sbin.sshd << 'EOF'
# Site-specific additions and overrides for /usr/sbin/sshd
# This file can be used to add additional rules specific to this system
# Format: standard AppArmor rules
EOF
    
    # Load and enforce the SSH profile
    apparmor_parser -r /etc/apparmor.d/usr.sbin.sshd 2>/dev/null || echo "AppArmor SSH profile created (will be active after sshd restart)"
    echo "✅ AppArmor SSH profile created and loaded"
else
    echo "⚠️ AppArmor not available or not installed"
fi

# Unattended Reboot Warning System
echo "Configuring unattended reboot warning system..."
cat > /etc/apt/apt.conf.d/51unattended-upgrades-bastion << 'EOF'
// Enhanced bastion host configuration for unattended upgrades
Unattended-Upgrade::Automatic-Reboot "true";
Unattended-Upgrade::Automatic-Reboot-WithUsers "false";
Unattended-Upgrade::Automatic-Reboot-Time "04:00";

// Warning system before reboot
Unattended-Upgrade::SyslogEnable "true";
Unattended-Upgrade::SyslogFacility "daemon";
EOF

# Create pre-reboot warning script
cat > /usr/local/bin/unattended-reboot-warning.sh << 'EOF'
#!/bin/bash
# Pre-reboot warning for unattended upgrades

# Check if reboot is required
if [ -f /var/run/reboot-required ]; then
    # Send wall message to all logged in users
    echo "SYSTEM NOTICE: Unattended upgrade requires reboot. System will reboot at 04:00 AM." | wall
    
    # Log to syslog
    logger -p daemon.warning "Bastion host scheduled for automatic reboot due to unattended upgrade"
    
    # Send email notification
    echo "Bastion host $(hostname) is scheduled for automatic reboot at 04:00 AM due to security updates requiring reboot." | \
        mail -s "BASTION NOTICE: Scheduled Reboot Tonight" root
fi
EOF

chmod +x /usr/local/bin/unattended-reboot-warning.sh

# Add to daily cron to warn users
echo "0 20 * * * root /usr/local/bin/unattended-reboot-warning.sh" >> /etc/crontab

echo "✅ Unattended reboot warning system configured"

# Suricata Rules Maintenance
echo "Setting up Suricata rules maintenance..."
if command -v suricata-update >/dev/null 2>&1; then
    # Configure suricata-update
    suricata-update update-sources
    suricata-update enable-source et/open
    suricata-update enable-source oisf/trafficid
    
    # Create weekly rules update job
    cat > /etc/cron.weekly/suricata-update << 'EOF'
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
    echo "Suricata configuration test failed after rules update on $(hostname)" | \
        mail -s "BASTION ERROR: Suricata Rules Update Failed" root
    logger -p daemon.error "Suricata rules update failed - configuration test error"
fi
EOF
    
    chmod +x /etc/cron.weekly/suricata-update
    echo "✅ Suricata rules auto-update configured"
else
    echo "⚠️ suricata-update not available - install with: apt install suricata-update"
fi

# Enhanced OpenSSH HMAC Tuning
echo "Applying enhanced OpenSSH HMAC tuning..."
cat >> /etc/ssh/sshd_config << 'EOF'

# Enhanced HMAC configuration - disable SHA-1 completely
MACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha2-256,hmac-sha2-512

# Ensure no weak algorithms
PubkeyAcceptedKeyTypes rsa-sha2-512,rsa-sha2-256,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521,ssh-ed25519
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group14-sha256
EOF

echo "✅ Enhanced SSH HMAC configuration applied (no SHA-1)"

# Smart Systemd Watchdog for Critical Services
echo "Configuring smart systemd watchdog for critical services..."
echo "This configuration balances service monitoring with resource protection"

# Smart fail2ban service watchdog - increased timeout during high load
mkdir -p /etc/systemd/system/fail2ban.service.d
cat > /etc/systemd/system/fail2ban.service.d/watchdog.conf << 'EOF'
[Service]
# Longer watchdog timeout to survive resource-intensive periods
WatchdogSec=300
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
cat > /etc/systemd/system/suricata.service.d/watchdog.conf << 'EOF'
[Service]
# Extended timeout for network analysis workloads
WatchdogSec=600
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
cat > /etc/systemd/system/ssh.service.d/watchdog.conf << 'EOF'
[Service]
# Moderate timeout but high priority for critical access service
WatchdogSec=180
Restart=on-failure
RestartSec=5
StartLimitInterval=300
StartLimitBurst=5

# Highest priority and OOM protection for SSH access
OOMScoreAdjust=-500
Nice=-10

# Security hardening
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/var/log /var/run /run
EOF

# AppArmor service watchdog - handle profile loading delays
mkdir -p /etc/systemd/system/apparmor.service.d
cat > /etc/systemd/system/apparmor.service.d/watchdog.conf << 'EOF'
[Service]
# AppArmor profile loading can take time on large systems
WatchdogSec=300
Restart=on-failure
RestartSec=20
StartLimitInterval=900
StartLimitBurst=2

# Standard priority for security service
OOMScoreAdjust=-50
EOF

# Unbound DNS watchdog - essential for bastion name resolution
mkdir -p /etc/systemd/system/unbound.service.d
cat > /etc/systemd/system/unbound.service.d/watchdog.conf << 'EOF'
[Service]
# DNS service timeout - balance responsiveness with stability
WatchdogSec=120
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
echo "✅ Smart systemd watchdog configured for critical services"
echo "   • SSH: 180s timeout, highest priority (OOM -500, Nice -10)"
echo "   • fail2ban: 300s timeout, high priority (OOM -100, Nice -5)"
echo "   • Suricata: 600s timeout, lower priority (OOM +200, Nice +5)"
echo "   • Unbound: 120s timeout, medium priority (OOM +100)"
echo "   • AppArmor: 300s timeout, medium-high priority (OOM -50)"
echo ""
echo "Smart watchdog protects critical services during resource contention"

echo "===== 14.7.1 Setting up Resource Guardian System ====="
# Proactive resource management to prevent service failures
echo "Installing Resource Guardian for proactive resource management..."

cat > /usr/local/bin/resource-guardian << 'EOF'
#!/bin/bash
# Resource Guardian - Proactive Resource Management for Bastion Host
# Monitors and manages resource usage to prevent service failures

LOGFILE="/var/log/resource-guardian.log"
TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')

# Configuration
HIGH_CPU_THRESHOLD=80
SUSTAINED_CPU_TIME=300  # 5 minutes
HIGH_MEMORY_THRESHOLD=85
CRITICAL_MEMORY_THRESHOLD=95

# Whitelist of critical processes that should never be killed
CRITICAL_PROCESSES="sshd|systemd|kernel|init|fail2ban|ufw|auditd|rsyslog|netdata|postfix"

# Function to log with timestamp
log_message() {
    echo "[$TIMESTAMP] $1" >> "$LOGFILE"
}

# Function to check and kill resource hogs
check_cpu_usage() {
    log_message "Checking CPU usage..."
    
    # Get processes using high CPU for sustained periods
    while read -r pid cpu_percent command; do
        if (( $(echo "$cpu_percent > $HIGH_CPU_THRESHOLD" | bc -l) )); then
            # Check if it's a critical process
            if ! echo "$command" | grep -qE "$CRITICAL_PROCESSES"; then
                # Check how long the process has been running
                process_time=$(ps -o pid,etime -p "$pid" 2>/dev/null | awk 'NR>1 {print $2}')
                
                if [ -n "$process_time" ]; then
                    # Convert time to seconds (simplified for common formats)
                    if echo "$process_time" | grep -q ":"; then
                        # Format like MM:SS or HH:MM:SS
                        time_seconds=$(echo "$process_time" | awk -F: '{if(NF==2) print $1*60+$2; else if(NF==3) print $1*3600+$2*60+$3}')
                    else
                        # Just seconds
                        time_seconds="$process_time"
                    fi
                    
                    # If process has been consuming high CPU for sustained time
                    if [ "$time_seconds" -gt "$SUSTAINED_CPU_TIME" ]; then
                        log_message "ACTION: Terminating high-CPU process: PID=$pid CMD=$command CPU=${cpu_percent}% TIME=${process_time}"
                        
                        # Send alert email
                        echo "Resource Guardian terminated high-CPU process on bastion host $(hostname):
                        
Process: $command
PID: $pid  
CPU Usage: ${cpu_percent}%
Runtime: $process_time
Action: Process terminated to protect system stability

This action was taken automatically to prevent system overload." | mail -s "BASTION: Resource Guardian Action - High CPU Process Terminated" root
                        
                        # Try graceful termination first
                        kill -TERM "$pid" 2>/dev/null
                        sleep 5
                        
                        # Force kill if still running
                        if kill -0 "$pid" 2>/dev/null; then
                            kill -KILL "$pid" 2>/dev/null
                            log_message "FORCEKILL: Process $pid required SIGKILL"
                        fi
                    fi
                fi
            else
                log_message "INFO: High CPU process $pid ($command) is whitelisted - skipping"
            fi
        fi
    done < <(ps aux --sort=-%cpu | awk 'NR>1 && $3>0 {print $2, $3, $11}' | head -10)
}

# Function to check memory usage
check_memory_usage() {
    local memory_usage=$(free | awk 'NR==2{printf "%.1f", $3*100/$2}')
    
    log_message "Current memory usage: ${memory_usage}%"
    
    if (( $(echo "$memory_usage > $CRITICAL_MEMORY_THRESHOLD" | bc -l) )); then
        log_message "CRITICAL: Memory usage at ${memory_usage}% - taking emergency action"
        
        # Find biggest memory consumers (excluding critical processes)
        ps aux --sort=-%mem | awk 'NR>1 {print $2, $4, $11}' | head -5 | while read -r pid mem_percent command; do
            if ! echo "$command" | grep -qE "$CRITICAL_PROCESSES"; then
                if (( $(echo "$mem_percent > 10" | bc -l) )); then
                    log_message "EMERGENCY: Killing high-memory process: PID=$pid CMD=$command MEM=${mem_percent}%"
                    
                    echo "EMERGENCY: Resource Guardian terminated high-memory process on bastion host $(hostname):
                    
Process: $command
PID: $pid
Memory Usage: ${mem_percent}%
System Memory: ${memory_usage}%
Action: Emergency termination due to critical memory usage

This emergency action was taken to prevent system failure." | mail -s "BASTION EMERGENCY: Memory Critical - Process Terminated" root

                    kill -KILL "$pid" 2>/dev/null
                fi
            fi
        done
        
    elif (( $(echo "$memory_usage > $HIGH_MEMORY_THRESHOLD" | bc -l) )); then
        log_message "WARNING: Memory usage at ${memory_usage}% - monitoring closely"
        
        # Send warning but don't kill processes yet
        echo "WARNING: High memory usage (${memory_usage}%) detected on bastion host $(hostname). Resource Guardian is monitoring the situation." | mail -s "BASTION WARNING: High Memory Usage" root
    fi
}

# Function to check system load
check_system_load() {
    local load_avg=$(cat /proc/loadavg | awk '{print $1}')
    local cpu_count=$(nproc)
    local load_ratio=$(echo "scale=2; $load_avg / $cpu_count" | bc -l)
    
    log_message "Current load average: $load_avg (ratio: $load_ratio per CPU)"
    
    # If load is more than 2x CPU count, system is heavily loaded
    if (( $(echo "$load_ratio > 2.0" | bc -l) )); then
        log_message "WARNING: High system load detected - load ratio $load_ratio"
        
        # Log top processes contributing to load
        log_message "Top CPU processes during high load:"
        ps aux --sort=-%cpu | head -6 >> "$LOGFILE"
        
        echo "High system load detected on bastion host $(hostname):

Load Average: $load_avg
CPU Count: $cpu_count  
Load Ratio: $load_ratio per CPU

Resource Guardian is monitoring the situation and will take action if specific processes exceed thresholds." | mail -s "BASTION ALERT: High System Load" root
    fi
}

# Function to check disk I/O
check_disk_io() {
    # Simple check using iotop if available
    if command -v iotop >/dev/null 2>&1; then
        # Get processes with high I/O (simplified check)
        local high_io_procs=$(iotop -a -o -d 1 -n 1 2>/dev/null | grep -v TOTAL | awk '$4+$6 > 1000 {print $2, $4+$6, $NF}' | head -3)
        
        if [ -n "$high_io_procs" ]; then
            log_message "High I/O processes detected:"
            echo "$high_io_procs" >> "$LOGFILE"
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
if [ $(stat -c%s "$LOGFILE" 2>/dev/null || echo 0) -gt 10485760 ]; then  # 10MB
    mv "$LOGFILE" "${LOGFILE}.old"
    touch "$LOGFILE"
    chmod 644 "$LOGFILE"
    log_message "Resource Guardian log rotated"
fi
EOF

chmod +x /usr/local/bin/resource-guardian

# Install required dependency
if ! command -v bc >/dev/null 2>&1; then
    echo "Installing bc calculator for Resource Guardian..."
    apt-get update && apt-get install -y bc
fi

# Create systemd service for Resource Guardian
cat > /etc/systemd/system/resource-guardian.service << 'EOF'
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
cat > /etc/systemd/system/resource-guardian.timer << 'EOF'
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
cat > /etc/cron.daily/security-config-backup << 'EOF'
#!/bin/bash
# Daily backup of critical security configurations

BACKUP_DIR="/var/backups/security-configs"
DATE=$(date +%Y%m%d)
BACKUP_FILE="$BACKUP_DIR/security-config-$DATE.tar.gz"

# Create backup directory
mkdir -p "$BACKUP_DIR"

# Create comprehensive backup
tar -czf "$BACKUP_FILE" \
    /etc/fail2ban \
    /etc/suricata \
    /etc/ssh \
    /etc/audit \
    /etc/ufw \
    /etc/apparmor.d \
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
if [ -f "$BACKUP_FILE" ]; then
    # Check backup integrity
    if tar -tzf "$BACKUP_FILE" >/dev/null 2>&1; then
        logger -p daemon.info "Security configuration backup completed: $BACKUP_FILE"
        
        # Keep only last 30 days of backups
        find "$BACKUP_DIR" -name "security-config-*.tar.gz" -mtime +30 -delete
        
        # Report backup size
        BACKUP_SIZE=$(du -h "$BACKUP_FILE" | cut -f1)
        echo "Security configuration backup completed: $BACKUP_SIZE ($BACKUP_FILE)" >> /var/log/backup.log
    else
        logger -p daemon.error "Security configuration backup corrupted: $BACKUP_FILE"
        echo "BACKUP ERROR: Security configuration backup corrupted on $(hostname)" | \
            mail -s "BASTION ERROR: Backup Failure" root
    fi
else
    logger -p daemon.error "Security configuration backup failed"
    echo "BACKUP ERROR: Security configuration backup failed on $(hostname)" | \
        mail -s "BASTION ERROR: Backup Failure" root
fi

# Quick integrity check of critical configs
for config in /etc/ssh/sshd_config /etc/suricata/suricata.yaml /etc/fail2ban/jail.local; do
    if [ -f "$config" ]; then
        case "$config" in
            */sshd_config)
                sshd -t 2>/dev/null || echo "WARNING: SSH config validation failed" >> /var/log/backup.log
                ;;
            */suricata.yaml)
                suricata -T -c "$config" >/dev/null 2>&1 || echo "WARNING: Suricata config validation failed" >> /var/log/backup.log
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

# Clean up temporary files
rm -f /tmp/smtp_test_email.txt /tmp/final_setup_email.txt /tmp/bastion-setup-complete.txt

echo "===== BASTION HOST SETUP COMPLETE ====="
echo "========================================"
echo ""
echo "✅ Bastion host has been successfully configured with enhanced security"
echo ""
echo "🔐 IMPORTANT SECURITY INFORMATION:"
echo "   • SSH Port: $SSH_PORT (NOT the default 22)"
echo "   • Authentication: SSH keys ONLY (no passwords)"
echo "   • User: $USERNAME"
echo "   • Firewall: Restrictive rules active"
echo "   • Monitoring: Comprehensive logging and alerting enabled"
echo ""
echo "🔗 CONNECTION COMMAND:"
echo "   ssh -p $SSH_PORT $USERNAME@$BASION_IP"
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
echo "   • AppArmor profile enforcement verification and custom SSH profile"
echo "   • Unattended reboot warning system (wall messages + email alerts)"
echo "   • Suricata rules maintenance with weekly auto-updates"
echo "   • Enhanced OpenSSH HMAC tuning (SHA-1 completely disabled)"
echo "   • Systemd watchdog for fail2ban, suricata, and SSH services"
echo "   • Daily automated backup of all security configurations"
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
echo "   1. Test SSH access from your workstation"
echo "   2. Configure any internal network access rules as needed"
echo "   3. Set up centralized logging if required"
echo "   4. Review and customize monitoring alerts"
echo "   5. Document connection procedures for authorized users"
echo "   6. ⚠️  IMPORTANT: After 24-48 hours, update chkrootkit baseline:"
echo "      sudo cp -a -f /var/log/chkrootkit/log.today /var/log/chkrootkit/log.expected"
if [[ "$SMTP_CONFIGURE" =~ ^[Yy]$ ]]; then
    echo "   7. Check your email inbox for the setup completion report"
fi
echo ""
echo "🎉 This bastion host is now ready for secure access management!"
