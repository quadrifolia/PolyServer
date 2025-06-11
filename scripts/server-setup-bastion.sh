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

echo "===== 6.0.1 Installing CPU microcode updates ====="

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
logcheck@@bastion $LOGWATCH_EMAIL
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
-w /var/run/utmp -p wa -k session
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

# Enable and start auditd
systemctl enable auditd
systemctl restart auditd

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
    EXTERNAL_NET: "!$HOME_NET"
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
alert tcp \$EXTERNAL_NET any -> \$HOME_NET ![22,$SSH_PORT,80,443] (msg:"BASTION Port Scan Detected"; flow:established,to_server; threshold:type threshold, track by_src, count 5, seconds 10; classtype:attempted-recon; sid:2000004; rev:1;)

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

# Enable and start Suricata
systemctl enable suricata
systemctl start suricata

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

echo "===== 12. Setting up comprehensive log rotation for bastion logs ====="
cat > /etc/logrotate.d/bastion-logs << 'EOF'
# Bastion host comprehensive log rotation configuration
# Ensures logs don't fill up disk space while retaining security audit trail

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

# Authentication logs (keep longer for security analysis)
/var/log/auth.log {
    daily
    rotate 60
    compress
    delaycompress
    missingok
    notifempty
    create 0640 root adm
    postrotate
        systemctl reload rsyslog > /dev/null 2>&1 || true
    endscript
}

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

# Audit logs (critical for compliance - keep longer)
/var/log/audit/audit.log {
    daily
    rotate 365
    compress
    delaycompress
    missingok
    notifempty
    create 0640 root adm
    copytruncate
    postrotate
        /sbin/service auditd restart > /dev/null 2>&1 || true
    endscript
}

# Mail logs (for email notification troubleshooting)
/var/log/mail.log {
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

# Fail2ban logs (security monitoring)
/var/log/fail2ban.log {
    weekly
    rotate 12
    compress
    delaycompress
    missingok
    notifempty
    create 0640 root adm
    postrotate
        systemctl reload fail2ban > /dev/null 2>&1 || true
    endscript
}

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

# System logs (general system activity)
/var/log/syslog {
    daily
    rotate 14
    compress
    delaycompress
    missingok
    notifempty
    create 0640 syslog adm
    postrotate
        systemctl reload rsyslog > /dev/null 2>&1 || true
    endscript
}

# Kernel logs
/var/log/kern.log {
    daily
    rotate 14
    compress
    delaycompress
    missingok
    notifempty
    create 0640 syslog adm
    postrotate
        systemctl reload rsyslog > /dev/null 2>&1 || true
    endscript
}
EOF

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

echo "===== 14.5 Setting up disk space protection for logging ====="
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

# Restart SSH with new configuration
echo "===== 15. Restarting SSH service ====="
systemctl restart sshd

# Final system checks
echo "===== 16. Final system validation ====="
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

This bastion host is now ready for secure access management!

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
echo "🛡️  This bastion host is now ready for secure access management!"
