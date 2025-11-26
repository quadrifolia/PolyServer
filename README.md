# PolyServer - Hardened Debian Server Foundation

This repository provides a comprehensive, security-hardened Debian server foundation that can be used as a base for deploying various applications including React/Next.js frontends, PHP backends, business intelligence platforms, analytics services, and other web applications.

> **SECURITY NOTICE**: This setup creates a production-ready, hardened server environment. Review our [security configurations](./SECURITY.md) and [compliance documentation](./DSGVO.md) before deployment.

## Table of Contents

- [Overview](#overview)
- [Repository Structure](#repository-structure)
- [Base Server Setup Process](#base-server-setup-process)
  - [SSH Key Setup (Recommended)](#ssh-key-setup-recommended)
  - [Step 1: Local Setup and Configuration](#step-1-local-setup-and-configuration)
  - [Step 2: Server Provisioning](#step-2-server-provisioning)
  - [Step 3: Deploy and Run Server Hardening](#step-3-deploy-and-run-server-hardening)
  - [Step 4: Deploy Base Configuration](#step-4-deploy-base-configuration)
  - [Bastion Host Setup](#bastion-host-setup)
- [Application Deployment](#application-deployment)
  - [Deployment Modes](#deployment-modes)
  - [Supported Applications](#supported-applications)
  - [Deployment Examples](#deployment-examples)
  - [Next Steps](#next-steps)
- [DSGVO/GDPR Compliance](#dsgvogdpr-compliance)
  - [Compliance Documentation](#compliance-documentation)
  - [Compliance Scripts](#compliance-scripts)
  - [Compliance Setup](#compliance-setup)
- [Base Server Features](#base-server-features)
- [Base Server Components](#base-server-components)
- [Optional Application Components](#optional-application-components)
- [Updating and Maintenance](#updating-and-maintenance)
  - [Update Schedule Recommendations](#update-schedule-recommendations)
  - [Updating Applications](#updating-applications)
  - [Updating Debian Server](#updating-debian-server)
  - [Updating Nginx](#updating-nginx)
  - [Updating Netdata Monitoring](#updating-netdata-monitoring)
  - [Update Verification](#update-verification)
- [SSL Certificate Management](#ssl-certificate-management)
- [Backup Strategy](#backup-strategy)
  - [Primary: OVH Object Storage for Backups](#primary-ovh-object-storage-for-backups)
  - [Optional: Block Storage for Local Backups](#optional-block-storage-for-local-backups)
- [Server Monitoring and Security](#server-monitoring-and-security)
  - [Firewall Configuration](#firewall-configuration)
  - [Web Application Firewall (ModSecurity)](#web-application-firewall-modsecurity)
  - [Container Security](#container-security)
  - [AppArmor Protection](#apparmor-protection)
  - [Network Intrusion Detection (Suricata)](#network-intrusion-detection-suricata)
  - [Audit Framework (auditd)](#audit-framework-auditd)
  - [Unbound DNS Cache](#unbound-dns-cache)
  - [Netdata Monitoring](#netdata-monitoring)
  - [Malware Protection](#malware-protection)
  - [Rootkit Detection](#rootkit-detection)
  - [File Integrity Monitoring](#file-integrity-monitoring)
  - [Logcheck System Monitoring](#logcheck-system-monitoring)
  - [Logwatch System Monitoring](#logwatch-system-monitoring)
  - [Automatic Security Updates](#automatic-security-updates)
  - [Advanced Firewall with Fail2ban](#advanced-firewall-with-fail2ban)
  - [Application-Specific Hardening](#application-specific-hardening)
- [Incident Response Tools](#incident-response-tools)
  - [System Monitoring Tools](#system-monitoring-tools)
  - [Network Monitoring Tools](#network-monitoring-tools)
  - [Network Diagnostics Tools](#network-diagnostics-tools)
  - [File Integrity Tools](#file-integrity-tools)
  - [Incident Response Reference](#incident-response-reference)
- [Maintenance and Monitoring](#maintenance-and-monitoring)
  - [Log Locations](#log-locations)
  - [Monitoring](#monitoring)
  - [Maintenance Tasks](#maintenance-tasks)
  - [Disaster Recovery Testing](#disaster-recovery-testing)
  - [Log Rotation and Management](#log-rotation-and-management)
  - [Advanced Network Traffic Monitoring](#advanced-network-traffic-monitoring)
- [Customizing the Deployment](#customizing-the-deployment)
- [Performance Comparison](#performance-comparison)
  - [Docker Mode Benefits](#docker-mode-benefits)
  - [Bare Metal Mode Benefits](#bare-metal-mode-benefits)
- [Local Testing](#local-testing)
  - [Testing Different Deployment Modes](#testing-different-deployment-modes)
  - [Docker-Based Testing](#docker-based-testing)
  - [What Gets Tested](#what-gets-tested)
  - [Testing PolyServer Scripts](#testing-polyserver-scripts)
  - [Testing Your Applications](#testing-your-applications)
- [CI/CD and Testing](#cicd-and-testing)
  - [Automated Testing Workflows](#automated-testing-workflows)
  - [Testing Strategy](#testing-strategy)
  - [Running Tests Locally](#running-tests-locally)
  - [Contributing Guidelines](#contributing-guidelines)
  - [Workflow Maintenance](#workflow-maintenance)

## Overview

PolyServer provides a **foundational layer** for secure Debian server deployments with:

### 🔒 **Security-First Design**
- **25+ integrated security tools and frameworks**
- **Post-quantum cryptography**: SSH with hybrid key exchange algorithms for future-proof security
- **Dual-stack security**: IPv4/IPv6 support with DNSSEC validation and integrity protection
- **Defense in depth**: ModSecurity WAF, Suricata IDS, fail2ban with UFW/nftables backend
- **Comprehensive audit framework**: auditd with file integrity monitoring and persistence detection
- **Enhanced access control**: AppArmor mandatory access control with restrictive sudoers configuration
- **DNS security**: Unbound with DNSSEC validation, dual-stack support, and fallback DNS
- **Malware protection**: ClamAV, Linux Malware Detect, and rootkit detection (RKHunter, chkrootkit)
- **Container security**: Trivy vulnerability scanning with severity-based filtering
- **Automated security updates**: Unattended upgrades with intelligent service restart management (needrestart automation)
- **Production hardening**: SSH host key generation, journald rate limiting (1000 burst), error handling with trap functions
- **Full DSGVO/GDPR compliance toolkit** with automated breach response and forensics collection

### ⚡ **Performance Optimized**
- Unbound DNS caching for improved response times
- Optimized system settings and resource management
- Real-time monitoring with Netdata and optional Cloud integration
- Systemd watchdog services for automatic failure recovery
- Enhanced systemd timers with persistent execution for missed runs

### 📋 **Application-Ready Foundation**
- Application-agnostic security configurations
- Template-based configuration system
- Standardized deployment patterns for various application types

## Repository Structure

```
polyserver/
├── scripts/                             # Deployment and administration scripts
│   ├── deploy-unified.sh                # Base configuration deployment script
│   ├── generate-configs.sh              # Configuration generation from templates
│   ├── server-setup-bastion.sh          # Specialized bastion host hardening script
│   ├── audit-report.sh                  # Security audit reporting
│   ├── breach-response-checklist.sh     # DSGVO breach response procedures
│   ├── collect-forensics.sh             # Forensic evidence collection
│   ├── data-subject-request.sh          # Data subject request handling
│   ├── dsgvo-compliance-check.sh        # GDPR compliance verification
│   ├── maldet-config.sh                 # Malware detection configuration
│   ├── setup-dsgvo.sh                   # DSGVO compliance setup
│   ├── trivy-scan.sh                    # Security vulnerability scanning
│   ├── remove-apparmor.sh               # AppArmor removal utility
│   └── ssh-disable-password-auth.sh     # SSH security hardening
├── templates/                           # Template files for configuration
│   ├── defaults.env                     # Base system configuration variables
│   ├── server-setup.sh.template         # Server hardening script template
│   ├── apparmor/                        # AppArmor security profiles
│   │   └── application-profile.template
│   ├── audit/                           # Audit system templates
│   │   ├── auditd.conf.template
│   │   ├── audit.rules.template
│   │   └── rules.d/
│   ├── dsgvo/                           # DSGVO/GDPR compliance templates
│   │   ├── contacts.conf.template
│   │   ├── data_inventory.json.template
│   │   ├── deletion_procedures.md.template
│   │   ├── processing-activities-record.md
│   │   ├── processing_records.md.template
│   │   ├── retention_policy.md.template
│   │   └── subject_request_procedures.md.template
│   ├── netdata/                         # Performance monitoring templates
│   │   ├── docker.conf.template
│   │   ├── health_alarm_notify.conf.template
│   │   └── health.d/
│   │       └── cgroups.conf.template
│   ├── mariadb/                         # Database server templates
│   │   └── 50-server.cnf.template           # Performance-optimized MariaDB configuration
│   ├── nginx/                           # Traditional web server templates (mode-specific)
│   │   ├── nginx-baremetal.conf.template    # Nginx config for bare metal mode
│   │   ├── nginx-docker.conf.template       # Nginx config for Docker mode (reverse proxy)
│   │   ├── default-baremetal.conf.template  # Default site for bare metal mode
│   │   ├── default-docker.conf.template     # Default site for Docker mode (reverse proxy)
│   │   ├── index.html.template
│   │   ├── proxy_params.template
│   │   └── security.conf.template
│   ├── php/                             # PHP-FPM configuration templates
│   │   ├── www.conf.template                 # PHP-FPM pool configuration
│   │   └── php.ini.template                  # Security-hardened PHP configuration
│   ├── redis/                           # Redis cache configuration
│   │   └── redis.conf.template               # Performance and security optimized Redis
│   ├── unit/                            # NGINX Unit application server templates
│   │   ├── config.json.template              # Unit config for bare metal mode
│   │   └── config-docker.json.template       # Unit config for Docker mode (reverse proxy)
│   ├── scripts/                         # Script templates
│   │   ├── backup.sh.template
│   │   └── s3backup.sh.template
│   ├── suricata/                        # Network intrusion detection templates
│   │   └── local.yaml.template
│   ├── systemd/                         # System service templates
│   │   └── application.service.template
│   └── unbound/                         # DNS resolver templates
│       ├── dhclient.conf.template
│       └── local.conf.template
├── config/                              # Generated configuration files (git-ignored)
│   └── [generated from templates/]     # Output directory for processed templates
├── CLAUDE.md                            # Claude Code AI assistant context and commands
├── DSGVO.md                             # DSGVO/GDPR compliance guide
├── DSGVO-TOOLS.md                       # DSGVO/GDPR tools documentation
├── GDPR-COMPLIANCE-ROADMAP.md           # GDPR implementation roadmap
├── README.md                            # This documentation
├── SECURITY.md                          # Comprehensive security documentation and guidelines
├── local-test-cleanup-docker.sh         # Local Docker testing cleanup script
└── local-test-docker.sh                 # Local Docker testing script
```

## Advanced Security Features

PolyServer implements enterprise-grade security with comprehensive monitoring, detection, and response capabilities:

### 🛡️ **Enhanced Security Hardening**

#### **APT Package Security**
- **Package Pinning**: Critical security packages (openssh, fail2ban, ufw, auditd, sudo) pinned to prevent accidental downgrades
- **Integrity Verification**: Automated verification of package signatures and checksums
- **Controlled Updates**: Staged updates with verification and rollback capabilities

#### **Persistence Detection System**
- **Comprehensive Monitoring**: Monitors all autostart locations (/etc/init.d, systemd, cron, user profiles)
- **SUID/SGID Binary Tracking**: Detects new privileged binaries and permission changes
- **Baseline Creation**: Automated baseline creation and change detection
- **Real-time Alerting**: Email notifications for unauthorized persistence attempts

#### **Full Disk Encryption Support**
- **LUKS Detection**: Automatic detection and status reporting of disk encryption
- **Security Status Tracking**: Comprehensive logging of encryption status
- **Compliance Reporting**: Integration with security audit reports

#### **Advanced Network Security**
- **IPv6 Hardening**: Belt-and-suspenders approach with sysctl + ip6tables + UFW
- **Suricata Rules Management**: Weekly automated rule updates with configuration validation
- **Enhanced Firewall Rules**: Application-aware filtering with rate limiting

### 📊 **Monitoring & Observability**

#### **Netdata Cloud Integration**
- **Optional Cloud Connectivity**: Centralized monitoring across multiple servers
- **Automatic Claiming**: Configurable auto-registration with Netdata Cloud
- **Mobile Access**: Real-time monitoring via mobile app
- **Team Collaboration**: Shared dashboards and alert management

#### **Systemd Reliability Enhancements**
- **Watchdog Services**: Automatic restart for critical services (fail2ban, suricata, SSH, nginx)
- **Persistent Timers**: Catch-up execution for missed security scans and monitoring
- **Failure Detection**: Enhanced failure detection with graduated restart limits
- **Service Monitoring**: Real-time health checks with automatic recovery

#### **Configuration Backup & Integrity**
- **Daily Automated Backups**: All security configurations backed up with integrity verification
- **Configuration Validation**: Syntax checking for SSH, nginx, Suricata, and fail2ban configs
- **30-day Retention**: Automated cleanup with configurable retention periods
- **Email Notifications**: Alerts for backup failures or configuration corruption

### 🔧 **Advanced System Hardening**

#### **AppArmor Mandatory Access Control**
- **Profile Enforcement**: Custom profiles for SSH, nginx, and critical services
- **Capability Restrictions**: Precise control over system capabilities
- **Automatic Profile Loading**: Enforcement verification and complain mode detection

#### **Unattended Upgrade Management**
- **Reboot Warning System**: Wall messages and email notifications before automatic reboots
- **Scheduled Maintenance**: Configurable maintenance windows (default: 4 AM)
- **User Notifications**: Clear communication of pending system maintenance

#### **Enhanced SSH Security**
- **HMAC Hardening**: Complete SHA-1 elimination, restricted to SHA-2 algorithms only
- **Algorithm Restrictions**: Enhanced key exchange algorithms (curve25519, ECDH-SHA256/512)
- **Key Type Enforcement**: Strengthened public key types (RSA-SHA2, ECDSA, Ed25519)

### 🎯 **Security Monitoring**

#### **Mount Option Security Audits**
- **Filesystem Security**: Automated auditing of mount options (noexec, nodev, nosuid)
- **Security Compliance**: Verification of security mount options on /tmp, /var/tmp, /home
- **Risk Assessment**: Detection of potentially dangerous mount configurations

#### **Service Whitelist Auditing**
- **Attack Surface Reduction**: Predefined whitelist of necessary services
- **Unauthorized Service Detection**: Alerts for unexpected running services
- **Security Baseline**: Continuous comparison against known-good service configurations

#### **Real-time Security Baselines**
- **Automated Baseline Creation**: Initial security state capture and monitoring
- **Change Detection**: Real-time monitoring of security-critical locations
- **Forensic Capabilities**: Detailed logging for incident response and compliance

## Base Server Setup Process

### SSH Key Setup (Recommended)

For secure access to your server, it's strongly recommended to use SSH keys instead of password authentication. PolyServer can automatically configure SSH key-based authentication during setup.

#### Creating SSH Keys

If you don't already have SSH keys, create them on your local machine:

**For Ed25519 keys (recommended):**
```bash
# Generate a new Ed25519 SSH key
ssh-keygen -t ed25519 -C "your-email@example.com"

# When prompted, save to default location: ~/.ssh/id_ed25519
# Enter a strong passphrase when prompted
```

**For RSA keys (alternative):**
```bash
# Generate a new RSA SSH key (4096 bits)
ssh-keygen -t rsa -b 4096 -C "your-email@example.com"

# When prompted, save to default location: ~/.ssh/id_rsa
# Enter a strong passphrase when prompted
```

#### Getting Your Public Key

Display your public key to copy into the PolyServer configuration:

```bash
# For Ed25519 keys
cat ~/.ssh/id_ed25519.pub

# For RSA keys
cat ~/.ssh/id_rsa.pub

# Example output:
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIG4rT3vTt99Ox5kndS4HmgTrKBT8SKzhK4rhGkEVGlCI your-email@example.com
```

Copy the entire output (starting with `ssh-ed25519` or `ssh-rsa`) for use in the next step.

#### SSH Authentication Options

PolyServer provides flexible SSH authentication configuration:

**Option 1: Key-Only Authentication (Recommended)**
- Set `SSH_PUBLIC_KEY="your-ssh-public-key"` in `defaults.env`
- Password authentication is automatically disabled
- Most secure option

**Option 2: Password Authentication (Initial Setup Only)**
- Leave `SSH_PUBLIC_KEY=""` empty in `defaults.env`
- Password authentication remains enabled for initial access
- You'll be prompted to set a password during server setup
- Add SSH keys later using `./scripts/ssh-disable-password-auth.sh`

**Option 3: Convert Later**
- Start with password authentication
- Add SSH keys to your server manually
- Run the conversion script to disable password auth:
  ```bash
  # On the server, after adding SSH keys
  sudo /opt/polyserver/scripts/ssh-disable-password-auth.sh
  ```

### Step 1: Local Setup and Configuration

**Run on your local machine:**

1. **Clone the repository:**
   ```bash
   git clone https://github.com/quadrifolia/PolyServer.git
   cd PolyServer
   ```

2. **Customize base configuration:**
   Edit `templates/defaults.env` to set your environment-specific values:
   ```bash
   nano templates/defaults.env
   ```
   
   **Required changes:**
   - `LOGWATCH_EMAIL=your-email@example.com` (for daily security reports)
   - `SSL_EMAIL=your-email@example.com` (for Let's Encrypt certificates)
   - `BASE_DOMAIN=your-domain.com` (your actual domain)
   - `TIMEZONE=Your/Timezone` (e.g., America/New_York)
   - `DEPLOYMENT_MODE=baremetal` or `docker` (choose your deployment strategy)

   **Netdata Cloud Integration (Optional):**
   For centralized monitoring across multiple servers:
   ```bash
   # Enable Netdata with Cloud integration
   NETDATA_ENABLED=true
   NETDATA_CLAIM_TOKEN=your_claim_token_from_netdata_cloud
   NETDATA_CLAIM_ROOMS=your_room_id_from_netdata_cloud
   ```

   **Email Configuration (Recommended):**
   For reliable security notification delivery, configure external SMTP:
   ```bash
   # Enable external SMTP for reliable email delivery
   SMTP_ENABLED=true
   SMTP_SERVER=smtp.gmail.com  # or your SMTP provider
   SMTP_PORT=587
   SMTP_USERNAME=your-email@gmail.com
   SMTP_PASSWORD=your-app-password  # Use App Password for Gmail
   SMTP_FROM_EMAIL=your-email@gmail.com
   SMTP_USE_TLS=true
   ```
   
   **Note**: If `SMTP_ENABLED=false`, all system emails will be stored locally in `/var/mail/root`

   **SSH Configuration:**
   ```bash
   # For key-based authentication (recommended):
   SSH_PUBLIC_KEY="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIG... your-email@example.com"
   
   # For password authentication (initial setup only):
   SSH_PUBLIC_KEY=""
   ```

   **Optional changes:**
   - `HOSTNAME=polyserver` (safe to change to your preferred hostname)
   - `SSH_PORT=2222` (custom SSH port for security)
   - `BACKEND_HOST=127.0.0.1` and `BACKEND_PORT=3000` (for Docker mode)
   - `NETDATA_ENABLED=true` (enable/disable Netdata monitoring)
   - Other security and monitoring settings

3. **Generate configuration files:**
   ```bash
   ./scripts/generate-configs.sh
   ```
   
   This will create a `config/` directory with all configuration files, including a customized `server-setup.sh` script that uses your settings from `defaults.env`.

### Step 2: Server Provisioning

**Set up your server:**

1. Provision a Debian 13 (trixie) server from your preferred provider
   - Recommended specs: 2+ vCores, 4GB+ RAM, 50GB+ SSD
   - Ensure SSH access with public key authentication
   - Record the server IP address and initial SSH port (usually 22)

### Step 3: Deploy and Run Server Hardening

**Run from your local machine:**

1. **Upload the generated hardening script to your server:**
   ```bash
   # Copy the customized script to your server
   scp config/server-setup.sh root@your-server-ip:/root/
   ```

2. **SSH to your server and run the hardening script:**
   ```bash
   # Connect to your server
   ssh root@your-server-ip
   
   # Run the hardening script (already executable)
   /root/server-setup.sh
   ```

   **The script will automatically:**
   - Update and secure the base Debian system
   - Install and configure all security tools
   - Set up monitoring and logging systems
   - Configure DSGVO/GDPR compliance framework
   - Harden network and system access
   - Change SSH port to 2222 (reconnect using this port afterward)

### Step 4: Deploy Base Configuration

**Run from your local machine after server hardening:**

Deploy the generated configuration to your hardened server:

```bash
# Deploy base configuration to server (note the new SSH port)
./scripts/deploy-unified.sh templates/defaults.env deploy your-server-ip 2222
```

**Note:** After step 3, SSH access will be on port 2222, and you'll connect as the `deploy` user, not root.

## Bastion Host Setup

For environments requiring secure access to internal networks, PolyServer includes a specialized bastion host hardening script. Bastion hosts provide a secure gateway for administrative access to internal infrastructure.

### What is a Bastion Host?

A bastion host is a specialized server that:
- Provides secure SSH access to internal networks
- Acts as a single point of entry for system administration
- Enforces strict security policies and logging
- Enables secure tunneling and port forwarding to internal services

### Setting Up a Bastion Host

**Prerequisites:**
- Fresh Debian 13 (trixie) server
- SSH public key for authentication (required - no password auth allowed)
- **Root access to the server** (or sudo privileges)

**Setup Process:**

1. **Configure SSH Public Key in Script:**
   ```bash
   # Edit the bastion setup script
   nano scripts/server-setup-bastion.sh
   
   # Find this line and replace with your actual SSH public key:
   SSH_PUBLIC_KEY=""
   
   # Replace with your key:
   SSH_PUBLIC_KEY="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIG... user@domain.com"
   ```

2. **Get Your SSH Public Key:**
   ```bash
   # Display your Ed25519 public key
   cat ~/.ssh/id_ed25519.pub
   
   # Or display your RSA public key
   cat ~/.ssh/id_rsa.pub
   
   # Copy the entire output to use in the script
   ```

3. **Deploy the Bastion Host:**
   ```bash
   # Copy the script to your server (as root)
   scp scripts/server-setup-bastion.sh root@your-bastion-ip:/root/
   
   # SSH to your server as root and run the hardening script
   ssh root@your-bastion-ip
   chmod +x /root/server-setup-bastion.sh
   /root/server-setup-bastion.sh
   ```
   
   **During setup, you'll be prompted for:**
   - Email address for security notifications
   - Optional external SMTP configuration for reliable email delivery
   - SMTP server details (recommended for production environments)
   
   **Alternative if you have sudo access:**
   ```bash
   # Copy the script to your server (as regular user)
   scp scripts/server-setup-bastion.sh debian@your-bastion-ip:/home/debian/
   
   # SSH to your server and run with sudo
   ssh debian@your-bastion-ip
   chmod +x /home/debian/server-setup-bastion.sh
   sudo /home/debian/server-setup-bastion.sh
   ```
   
   **⚠️ Important:** The script must run as root because it:
   - Installs and configures system packages
   - Modifies critical system configuration files
   - Sets up firewall rules and security services
   - Configures SSH, audit system, and kernel parameters

### Bastion Host Features

The bastion setup provides enhanced security beyond the standard server hardening:

#### Core Security Components (Always Installed)
- **Fail2ban**: Brute force protection with aggressive SSH monitoring
- **UFW Firewall**: Restrictive rules with only essential ports open
- **AIDE**: File integrity monitoring for detecting unauthorized changes
- **Unbound DNS**: Caching DNS resolver for improved performance and privacy
- **Postfix**: Local mail system for security notifications
- **AppArmor**: Mandatory access control for critical services

#### Optional Security Components (Disabled by Default)

**⚠️ Important:** The bastion script uses **conservative defaults** and does NOT install resource-intensive optional components unless explicitly requested. This ensures optimal performance on resource-constrained systems.

To enable optional components, set environment variables before running the script:

```bash
# Enable all optional security components
export INSTALL_CLAMAV=true      # Antivirus scanning (HIGH resource usage - 500MB+ RAM)
export INSTALL_MALDET=true      # Linux Malware Detect (MEDIUM resource - disk I/O intensive)
export INSTALL_RKHUNTER=true    # Rootkit detection (LOW resource usage)
export INSTALL_SURICATA=true    # Network IDS (MEDIUM resource - CPU intensive)
export INSTALL_NETDATA=true     # Real-time monitoring (optional - uses ~100MB RAM)

# Run the script with environment preserved
sudo -E ./scripts/server-setup-bastion.sh
```

**Default Behavior (No Environment Variables Set):**
- All optional components default to `false`
- Only core security tools are installed
- Minimal resource footprint (~200MB RAM for security services)
- Perfectly suitable for production bastion hosts

**What Each Optional Component Does:**
- **ClamAV** (`INSTALL_CLAMAV`): Antivirus scanning for uploaded files and malware detection. High resource usage.
- **Malware Detect** (`INSTALL_MALDET`): Linux-specific malware scanner. Periodic file system scanning.
- **RKHunter** (`INSTALL_RKHUNTER`): Rootkit detection and system integrity checking. Minimal overhead.
- **Suricata** (`INSTALL_SURICATA`): Network intrusion detection system with real-time traffic analysis.
- **Netdata** (`INSTALL_NETDATA`): Real-time performance monitoring with web dashboard.

**Viewing Current Configuration:**

After installation, check which components are active:
```bash
sudo bastionstat
```

This shows which security services are running and which are inactive (not installed).

#### Enhanced SSH Security
- **Key-only authentication**: No password authentication allowed
- **Custom SSH port**: Default port 2222 to reduce attack surface
- **SSH tunneling enabled**: Supports port forwarding for internal access
- **Connection limits**: Maximum 5 concurrent sessions
- **Client keep-alive**: Automatic session management

#### Authentication and Access Model

**IMPORTANT:** The bastion host uses a strict SSH key-only authentication model for maximum security.

**Bastion User Account:**
- **Password Authentication**: Intentionally DISABLED (no password login possible)
- **SSH Key Authentication**: REQUIRED (your public key must be configured)
- **Sudo Access**: **Restricted** to specific whitelisted commands only (security hardening)
- **Login Method**: SSH key authentication only

**Root Account:**
- **Password**: Set during installation for emergency console access
- **SSH Login**: DISABLED (root cannot SSH in)
- **Console Access**: Available for emergency recovery via hosting provider console
- **Use Case**: Emergency access when SSH keys are lost or bastion user is locked out

**Sudo Command Restrictions (Important!):**

The bastion host uses **restrictive sudoers** configuration that only allows passwordless sudo for specific whitelisted commands. This prevents unauthorized privilege escalation.

**Allowed Commands (No Password Required):**
```bash
# System monitoring commands
sudo bastionstat          # Show comprehensive bastion status
sudo sshmon               # Monitor SSH connections
sudo bastionmail          # Read system mail

# Service status checks (read-only)
sudo systemctl status sshd
sudo systemctl is-active ssh
sudo ufw status
sudo fail2ban-client status

# Log file access (read-only)
sudo tail /var/log/auth.log
sudo tail /var/log/syslog
sudo tail /var/log/fail2ban.log
```

**Restricted Commands (Require Root):**
```bash
# These will NOT work with sudo - use 'su -' to become root
sudo ./my-script.sh               # ❌ Scripts in home directory
sudo systemctl restart sshd       # ❌ Service control
sudo apt update                   # ❌ Package management
sudo nano /etc/ssh/sshd_config   # ❌ Configuration editing
```

**How to Run Administrative Commands:**

```bash
# Method 1: Use 'su -' to become root (recommended for admin tasks)
bastion@bastion:~$ su -
Password: [enter root password]
root@bastion:~# systemctl restart sshd
root@bastion:~# apt update
root@bastion:~# exit

# Method 2: Run allowed commands with sudo (monitoring only)
bastion@bastion:~$ sudo bastionstat
bastion@bastion:~$ sudo systemctl status sshd
```

**After Installation:**

```bash
# Correct login method (SSH with key)
ssh -p 2222 bastion@your-bastion-ip

# Allowed sudo commands work without password
bastion@bastion:~$ sudo bastionstat
bastion@bastion:~$ sudo systemctl status sshd
# Works immediately - no password prompt

# Administrative commands require root access
bastion@bastion:~$ sudo systemctl restart sshd
# ❌ This will ask for password (which doesn't exist)

# Solution: Use 'su -' for admin tasks
bastion@bastion:~$ su -
Password: [root password]
root@bastion:~# systemctl restart sshd
# ✅ Works

# Password login attempts will FAIL (by design)
ssh -p 2222 -o PubkeyAuthentication=no bastion@your-bastion-ip
# This will fail - password authentication is disabled

# If you need root access (emergency only)
# Use hosting provider console and login as root with the password you set
```

**Why This Design:**
- **Eliminates password brute-force attacks**: No password = no brute-forcing
- **Enforces strong authentication**: SSH keys are cryptographically stronger than passwords
- **Restricts privilege escalation**: Whitelisted sudo commands prevent unauthorized root access
- **Principle of least privilege**: Bastion user can monitor but not modify system
- **Audit trail**: All access tied to specific SSH keys, root access via su is logged
- **Compliance**: Meets security requirements for privileged access management (separation of duties)
- **Defense in depth**: Even if bastion account is compromised, attacker cannot run arbitrary root commands
- **Emergency recovery**: Root password via console provides last-resort access

**Common Issues:**

```bash
# Issue: "sudo password doesn't work"
# Solution: This is expected - bastion user has no password
# Only whitelisted commands work with sudo - use 'su -' for admin tasks

# Issue: "sudo ./script.sh asks for password"
# Solution: Scripts in home directory are not whitelisted for sudo
# Either: 1) Use 'su -' to run as root, OR
#         2) Install script to /usr/local/bin/ and add to sudoers

# Issue: "sudo systemctl restart fails"
# Solution: Only 'status' and 'is-active' are allowed, not 'restart'
# Use 'su -' for service management commands

# Issue: "I need to set a password for bastion user"
# Solution: Don't - this defeats the security model
# If you absolutely need it, see security implications below
```

**Security Implications of Enabling Passwords:**

If you absolutely must enable password authentication (NOT RECOMMENDED):

```bash
# As root (via console)
passwd bastion          # Set a password
nano /etc/ssh/sshd_config
# Change: PasswordAuthentication no → yes
systemctl restart sshd

# WARNING: This significantly reduces security by:
# - Allowing password brute-force attacks
# - Creating weaker authentication
# - Violating bastion host best practices
```

### SSH Filesystem Protection (ProtectSystem)

**ℹ️ DISABLED BY DEFAULT FOR USABILITY**

As of the latest version, **ProtectSystem is disabled by default** on the SSH service to ensure the system remains manageable and usable. System administration works normally without read-only filesystem issues.

#### Current Default Behavior (No ProtectSystem)

By default, the SSH service has **no filesystem restrictions**, providing a normal Linux experience:

```
Filesystem Status in SSH Sessions (Default):
✅ Fully writable: All directories including /, /etc, /var, /usr, /boot, /tmp, /home
✅ Normal system administration without restrictions
✅ apt install/update works without issues
✅ No read-only filesystem errors
```

**Why ProtectSystem was removed:**
- ❌ Caused read-only filesystem errors during package installations
- ❌ Made system administration unnecessarily complex
- ❌ Required console access for basic maintenance tasks
- ❌ Broke apt, dpkg, and other standard tools
- ✅ Security is better provided through network isolation, firewalls, and access controls

**Current Security Model:**
- ✅ Network-level protection (UFW firewall, fail2ban, port restrictions)
- ✅ Access control (key-based SSH authentication only, no password login)
- ✅ Monitoring and detection (Suricata IDS, auditd, comprehensive logging)
- ✅ Application-level sandboxing (individual services have their own protections)
- ✅ Usable system that can be properly maintained and updated

#### Running System Updates

**Default behavior (No restrictions):**
```bash
# SSH in as bastion user
ssh -p 2222 bastion@your-bastion

# Switch to root
su -
Password: [root password]

# Run updates normally - everything works!
apt update
apt upgrade -y
apt autoremove
exit
```

Everything works as expected on a normal Linux system.

#### Optional: Enabling ProtectSystem for Enhanced Security

**⚠️ WARNING: Only enable if you understand the implications!**

If you want to add filesystem protection despite the usability issues, you can manually enable it:

```bash
# 1. Edit SSH service configuration
nano /etc/systemd/system/ssh.service.d/watchdog.conf

# 2. Add ProtectSystem setting:
[Service]
Restart=on-failure
RestartSec=5
StartLimitInterval=300
StartLimitBurst=5
OOMScoreAdjust=-500
Nice=-10

# Add one of these protection levels:
ProtectSystem=full    # Protects /usr and /boot only (recommended if enabling)
# OR
ProtectSystem=strict  # Protects everything (requires console access for admin)
ReadWritePaths=/var/log /var/run /run /var/spool /var/tmp /var/lib /tmp /home /var/cache /var/backups /var/mail /etc

# 3. Save and reload
systemctl daemon-reload
systemctl restart ssh
```

**Consequences of enabling ProtectSystem:**
- ⚠️ May cause "Read-only file system" errors
- ⚠️ Can break apt, dpkg, and package installations
- ⚠️ Requires console access for many admin tasks
- ⚠️ Makes system harder to maintain and update
- ✅ Provides additional filesystem-level protection

#### Security Philosophy

The bastion host implements a **layered security approach** without relying on ProtectSystem:

**Defense in Depth:**
1. **Network Layer**: UFW firewall, fail2ban, Suricata IDS
2. **Access Layer**: Key-only SSH authentication, no password login, restricted sudo
3. **Monitoring Layer**: Comprehensive auditd rules, system logging, alerting
4. **Application Layer**: Individual services have their own sandboxing where appropriate

**Why this approach works better:**
- ✅ Security where it matters (network perimeter, access control)
- ✅ System remains usable and maintainable
- ✅ Can respond quickly to security incidents
- ✅ Proper monitoring and detection capabilities
- ✅ No unexpected "read-only filesystem" errors breaking operations

**If an attacker gets SSH access:**
- They still need to get root (auditd logs all attempts)
- All their actions are logged and monitored
- fail2ban will block repeated failed attempts
- Suricata IDS will detect suspicious patterns
- Network isolation limits lateral movement

This provides effective security while maintaining a usable, maintainable system.

---

#### Advanced Monitoring
- **Comprehensive audit logging**: All user activities tracked
- **Real-time SSH monitoring**: Live monitoring of SSH connections
- **Network intrusion detection**: Suricata IDS with bastion-specific rules
- **Hourly security checks**: Automated monitoring of suspicious activity
- **Daily security reports**: Detailed email reports of all activities

#### Email System Configuration
- **External SMTP support**: Reliable delivery via services like Amazon SES, Gmail, etc.
- **Local mail fallback**: Stores notifications locally if SMTP is not configured
- **Automatic aliasing**: All local system accounts redirect to your configured email
- **Security notifications**: Sudo usage, failed logins, and system alerts via email

#### Network Security
- **Restrictive firewall**: Only essential ports open (SSH, DNS, NTP, HTTP/HTTPS)
- **Internal network access**: Configurable access to internal networks
- **Enhanced fail2ban**: Aggressive protection against brute force attacks
- **Traffic monitoring**: Network activity logging and analysis

#### Diagnostic and Management Tools (Always Installed)
- **Network diagnostics**: nmap, ncat, socat, mtr, traceroute, tcpdump
- **System monitoring**: htop, iotop, atop, sysstat
- **Custom commands**: `bastionstat` (system status), `sshmon` (SSH monitoring), `bastionmail` (local mail reader)

Note: Security scanning tools (ClamAV, maldet, rkhunter, chkrootkit) are **optional** and only installed if explicitly enabled via environment variables (see Optional Security Components section above).

### Using the Bastion Host

After setup, connect to your bastion host:

```bash
# Connect to bastion host
ssh -p 2222 bastion@your-bastion-ip

# Use built-in status command (requires root privileges for UFW/system access)
sudo bastionstat

# Monitor SSH activity in real-time (requires root privileges for auth.log access)
sudo sshmon

# Access internal servers through the bastion
ssh -J bastion@your-bastion-ip:2222 user@internal-server

# Create SSH tunnel for web access
ssh -L 8080:internal-server:80 -p 2222 bastion@your-bastion-ip
# Then access http://localhost:8080 in your browser

# Read local mail (if using local delivery mode)
bastionmail

# Access Netdata monitoring (if installed)
netdata-bastion
```

#### Optional Netdata Integration for Bastion Hosts

Bastion hosts can optionally include Netdata monitoring for enhanced visibility:

```bash
# Enable Netdata during bastion setup by setting:
export INSTALL_NETDATA=true

# Or configure Netdata Cloud integration with environment variables:
export NETDATA_CLAIM_TOKEN=your_claim_token
export NETDATA_CLAIM_ROOMS=your_room_id
```

**Bastion Monitoring Benefits:**
- SSH connection tracking and analysis
- Resource usage monitoring for security analysis
- Network traffic correlation with security events
- Integration with centralized monitoring dashboard
- Mobile access for remote bastion monitoring

### Security Considerations

**Important Security Notes:**
- Bastion hosts should be dedicated servers (no other applications)
- Configure external SMTP for reliable security notification delivery
- Regularly review audit logs and security reports
- Keep the bastion host updated with security patches
- Monitor network traffic patterns for anomalies
- Implement proper access controls for bastion users

**Network Architecture:**
- Place bastion host in a DMZ or public subnet
- Restrict internal network access to necessary ports only
- Use security groups/firewalls to limit bastion access
- Monitor all traffic between bastion and internal networks

### Customizing Bastion Configuration

You can customize the bastion host by editing the script variables:

```bash
# Edit these variables in the script before deployment:
USERNAME="bastion"                                          # Bastion user account
HOSTNAME="bastion"                                          # Server hostname
SSH_PORT="2222"                                             # SSH port
INTERNAL_NETWORK="10.0.0.0/8,172.16.0.0/12,192.168.0.0/16"  # Allowed internal networks
ALLOWED_INTERNAL_PORTS="22,80,443,3306,5432"                # Ports accessible on internal networks
```

For more advanced configurations, review the comprehensive audit rules and monitoring settings in the script.

## Application Deployment

After setting up the hardened base server, you can deploy various applications using either deployment mode. Your choice of `DEPLOYMENT_MODE` in `defaults.env` determines how applications are deployed and managed.

### Deployment Modes

#### 🐳 **Docker Mode** (`DEPLOYMENT_MODE=docker`)
- Applications run in containers with Docker/Docker Compose
- Nginx configured as reverse proxy to containers
- Easy scaling, isolation, and management
- Perfect for modern microservices architectures

#### 🔧 **Bare Metal Mode** (`DEPLOYMENT_MODE=baremetal`)  
- Applications run directly on the server
- Nginx serves static files and proxies to local services
- Maximum performance with minimal overhead
- Ideal for single applications or legacy systems

### Supported Applications

The PolyServer foundation supports deployment of:

#### 🌐 **Frontend Applications**
- **Docker Mode**: React/Next.js in containers, nginx reverse proxy
- **Bare Metal Mode**: React/Next.js with PM2, nginx serves static files
- **Static Sites**: Optimized nginx serving in both modes

#### 🔧 **Backend Services** 
- **Docker Mode**: Containerized PHP, Node.js, Python applications
- **Bare Metal Mode**: PHP-FPM, Node.js with PM2, direct service management
- **API Services**: RESTful and GraphQL APIs in containers or direct deployment

#### 📊 **Analytics & Monitoring**
- **Docker Mode**: Metabase, Superset, Grafana as containers
- **Bare Metal Mode**: Direct installation with systemd services
- **Matomo**: Privacy-focused web analytics in either mode

#### 🗄️ **Database Systems**
- **Docker Mode**: PostgreSQL, MySQL, Redis containers with persistent volumes
- **Bare Metal Mode**: Native database installations with full performance
- **Backup Integration**: S3 backups work seamlessly in both modes

### Deployment Examples

#### Docker Mode Example: Containerized React App

```bash
# 1. Set Docker mode in configuration
echo "DEPLOYMENT_MODE=docker" >> templates/defaults.env

# 2. Generate Docker-optimized configs
./scripts/generate-configs.sh

# 3. Deploy hardened server with Docker support
./scripts/deploy-unified.sh templates/defaults.env deploy server.example.com 2222

# 4. Create application Docker Compose file
cat > docker-compose.yml << EOF
version: '3.8'
services:
  app:
    image: my-react-app:latest
    container_name: react-app
    restart: unless-stopped
    ports:
      - "3000:3000"
    networks:
      - polyserver-network
    environment:
      - NODE_ENV=production

networks:
  polyserver-network:
    external: true
EOF

# 5. Deploy application
docker compose up -d
```

#### Bare Metal Mode Example: PM2 React App

```bash
# 1. Set bare metal mode in configuration  
echo "DEPLOYMENT_MODE=baremetal" >> templates/defaults.env

# 2. Generate bare metal optimized configs
./scripts/generate-configs.sh

# 3. Deploy hardened server
./scripts/deploy-unified.sh templates/defaults.env deploy server.example.com 2222

# 4. Deploy React application directly
npm run build
pm2 start ecosystem.config.js
```

### Next Steps

1. **Choose Deployment Mode**: Decide between Docker or bare metal based on your needs
2. **Configure Application**: Set up application-specific configuration files
3. **Deploy Foundation**: Use the generated configs to deploy the hardened server
4. **Deploy Application**: Follow mode-specific deployment patterns
5. **Monitor and Maintain**: Use built-in monitoring tools regardless of deployment mode

## DSGVO/GDPR Compliance

This repository includes a comprehensive DSGVO/GDPR compliance toolkit for ensuring your server deployments meet data protection requirements, regardless of the application type.

### Compliance Documentation

- **DSGVO.md**: Main compliance guide covering breach procedures, notification requirements, and documentation templates
- **DSGVO-TOOLS.md**: Overview of all DSGVO/GDPR tools and usage instructions
- **Templates**:
  - **processing-activities-record.md**: Template for Article 30 records of processing activities
  - **processing_records.md.template**: Detailed documentation of data processing activities
  - **retention_policy.md.template**: Data retention policy template
  - **deletion_procedures.md.template**: Procedures for secure data deletion
  - **subject_request_procedures.md.template**: Procedures for handling data subject requests

### Compliance Scripts

- **breach-response-checklist.sh**: Interactive script for guiding through data breach response
- **collect-forensics.sh**: Comprehensive forensic evidence collection during security incidents
- **dsgvo-compliance-check.sh**: Automated verification of GDPR compliance status
- **data-subject-request.sh**: Interactive tool for handling data subject requests
- **setup-dsgvo.sh**: Automation script for setting up the DSGVO/GDPR compliance environment

### Compliance Setup

To set up the DSGVO/GDPR compliance toolkit:

```bash
# Make the setup script executable
chmod +x scripts/setup-dsgvo.sh

# Run the setup script
sudo ./scripts/setup-dsgvo.sh
```

The setup script will:
1. Create necessary directories in `/etc/dsgvo/` and `/opt/polyserver/`
2. Install all configuration templates and scripts
3. Configure log files and appropriate permissions
4. Set up scheduled compliance checks
5. Provide guidance for next steps

For more information, see the [DSGVO-TOOLS.md](./DSGVO-TOOLS.md) documentation.

## Base Server Features

The PolyServer foundation provides a comprehensive set of security, performance, and compliance features:

### Security Hardening

#### Multi-Layer Defense
- **UFW Firewall**: Restrictive firewall with minimal open ports
- **Fail2ban**: Dynamic IP blocking for brute force protection
- **ModSecurity WAF**: Web application firewall with OWASP Core Rule Set
- **Suricata IDS**: Network intrusion detection and prevention

#### System Security
- **AppArmor**: Mandatory access control for applications
- **Audit Framework**: Comprehensive system activity monitoring
- **File Integrity Monitoring**: AIDE for detecting unauthorized changes
- **Optional Malware Protection**: ClamAV and Linux Malware Detect (configurable)

#### Access Control
- **SSH Hardening**: Flexible authentication (key-based or password), custom ports
- **Strong Authentication**: Enforced strong passwords and access policies  
- **Privilege Escalation Protection**: Restricted sudo access and monitoring

#### Email & Notification System
- **External SMTP Support**: Reliable delivery via Gmail, Amazon SES, Outlook, etc.
- **Local Mail Fallback**: Stores notifications locally when SMTP is disabled
- **Email Aliasing**: All local system accounts redirect to configured email address
- **Security Notifications**: Automated alerts for malware, rootkits, failed logins, and system events
- **Amazon SES Compatibility**: Proper sender rewriting and UTF-8 handling

### Performance Optimization

#### Network Performance
- **Unbound DNS Caching**: Local DNS resolver for improved response times
- **Nginx Optimization**: High-performance web server configuration
- **Connection Pooling**: Optimized database and service connections

#### System Performance
- **Resource Monitoring**: Real-time system resource tracking
- **Process Management**: Optimized service configurations
- **Disk I/O Optimization**: Efficient storage access patterns

### Monitoring & Logging

#### Real-Time Monitoring
- **Netdata**: Comprehensive system performance monitoring
- **Resource Tracking**: CPU, memory, disk, and network monitoring
- **Health Checks**: Automated service health verification

#### Security Logging
- **Centralized Logging**: Structured log collection and analysis
- **Logwatch**: Daily system activity reports
- **Logcheck**: Automated log analysis for security events
- **Audit Trails**: Complete system activity auditing

## Base Server Components

### Security Framework

The PolyServer foundation includes:
1. **Hardened base system** with security-first configurations
2. **Comprehensive monitoring** with Netdata, audit logs, and intrusion detection
3. **Automated security updates** and optional malware scanning
4. **DSGVO/GDPR compliance** tools and procedures
5. **Template-based configuration** for easy customization
6. **Incident response tools** for security events

## Optional Application Components

During server setup, you can optionally install additional application components for your specific use case. These components are installed with secure configurations and production-ready defaults.

### 🐳 **Container Platform**
- **Docker with Security Optimizations**: Container runtime with hardened daemon configuration
  - Secure daemon configuration with logging restrictions
  - User namespace remapping for enhanced security
  - Storage driver optimization (overlay2)
  - Resource limits and security profiles

### 🌐 **Web Application Server Choice**

During server setup, you can choose between two high-performance web server architectures:

#### **Traditional nginx + PHP-FPM** (Default)
- **Industry Standard**: Battle-tested architecture used by millions of websites
- **Separate Processes**: nginx handles HTTP, PHP-FPM processes PHP requests
- **Extensive Documentation**: Large community, abundant resources and tutorials
- **Resource Usage**: Moderate memory usage, predictable performance
- **Best For**: Established workflows, large teams, complex nginx configurations

#### **NGINX Unit** (High-Performance Option)
- **Modern Architecture**: Single process handles both web serving and application execution
- **Superior Performance**: 8-10x faster response times than traditional PHP-FPM
- **Dynamic Configuration**: RESTful API for configuration changes without restarts
- **Better Resource Management**: More efficient under high load conditions
- **Multi-Language Support**: PHP, Python, Node.js, Go, Ruby, and more
- **Best For**: High-traffic sites, performance-critical applications, modern deployments

**Performance Comparison:**
- Response time: NGINX Unit ~7.6ms vs PHP-FPM ~60ms (99th percentile)
- Load handling: Unit handles 1000 requests without failures vs PHP-FPM with 200 failures
- Resource efficiency: Better memory and CPU utilization under stress

**Template Support:**
- Traditional setup uses `templates/nginx/` and `templates/php/` configurations
- NGINX Unit setup uses `templates/unit/` with optimized JSON configurations

### 🐘 **Database Systems**
- **MariaDB**: High-performance MySQL-compatible database
  - Secure installation with disabled remote root access
  - Performance optimization for server environments
  - Automatic security hardening configuration
  
- **PostgreSQL**: Advanced open-source relational database
  - Role-based access control
  - SSL/TLS encryption enabled by default
  - Performance tuning for production workloads

### 📦 **Caching and Storage**
- **Redis**: In-memory data structure store
  - Secure configuration with authentication
  - Memory optimization settings
  - Persistence configuration for data durability

### 🔧 **Development Platforms**

#### **PHP Development Stack**
- **PHP 8.4 with php-fpm**: Latest PHP with FastCGI Process Manager
  - Common extensions: mysqli, pdo, curl, gd, mbstring, xml, zip
  - OPcache enabled for performance
  - Security hardening (disabled dangerous functions)

- **PHP Development Tools** (optional):
  - **Composer**: Dependency management
  - **Xdebug**: Debugging and profiling extension

#### **Node.js Development Stack**
- **Node.js with PM2**: JavaScript runtime with process manager
  - Latest LTS version (v22.x) from NodeSource repository
  - PM2 process manager for production deployments
  - Cluster mode support for scalability

- **Node.js Development Tools** (optional):
  - **Yarn**: Fast, reliable package manager
  - **TypeScript**: Static type checking

### 🔧 **Development Tools**
- **Git**: Version control with optimized configuration
  - Security-focused default configurations
  - Performance optimizations for large repositories
  - Integration with system security monitoring

### 🖥️ **Advanced Monitoring Tools** (Optional)
- **serverstatus**: Comprehensive server health and status reporting
- **logmon**: Real-time log monitoring for different log types (auth, security, system, nginx)
- **servermail**: Local system mail and notification reader

### Installation Process

Optional components are presented during the interactive server setup process:

```bash
# During server setup, you'll be prompted:
Install/Configure Docker with security optimizations? (y/N): 
Install Nginx Unit (modern application server)? (y/N): 
Install PHP 8.4 with php-fpm and common extensions? (y/N): 
  Include PHP development tools (Composer, Xdebug)? (y/N): 
Install MariaDB with secure configuration? (y/N): 
Install PostgreSQL with secure configuration? (y/N): 
Install Node.js with PM2 process manager? (y/N): 
  Include development tools (Yarn, TypeScript)? (y/N): 
Install Redis with secure configuration? (y/N): 
Install Git with optimized configuration? (y/N): 
Install advanced server monitoring commands? (y/N): 
```

Each component is installed with:
- **Security-first configuration**: All services configured with security best practices
- **Performance optimization**: Tuned for production server environments
- **Integration with monitoring**: Automatic integration with system monitoring and logging
- **DSGVO compliance**: Data handling procedures documented where applicable

## Updating and Maintenance

Regular updates are crucial for security and functionality. This section provides comprehensive guidance on update procedures for all components of your deployment.

### Update Schedule Recommendations

| Component | Automatic Updates | Manual Update Frequency | Priority | Guidance |
|-----------|-------------------|------------------------|----------|----------|
| Applications | No | As needed | High | Follow application release notes, test in staging first |
| Docker Engine | No | Quarterly | High | `apt upgrade docker-ce` (Docker mode only) |
| Container Images | No | Weekly | High | `docker compose pull && docker compose up -d` (Docker mode only) |
| Debian OS (Security) | Yes | - | High | Auto-applied nightly, check logs weekly |
| Debian OS (Full) | No | Monthly | Medium | Apply during maintenance window |
| Nginx | No | Semi-annually | Medium | Only when security updates are available |
| Netdata | Yes | - | Low | Auto-updates via system package manager |
| ClamAV | Yes | - | Medium | Signatures updated daily, verify in logs |
| Linux Malware Detect | Yes | - | Medium | Signatures updated daily, check logs weekly |
| ModSecurity | No | Quarterly | High | Update OWASP CRS rules with `git pull` |
| Trivy | Yes | - | Medium | Database updates on scan, verify in logs |
| Suricata | No | Monthly | High | Update rule sets with ET Open rules |
| AppArmor | No | After major updates | Medium | Review after application version changes |
| Audit Framework | No | Quarterly | High | Review and update rules to match system changes |
| Unbound DNS | No | Quarterly | Low | Update root hints file from IANA |
| RKHunter | Yes | Monthly | High | Database updates automatically, property DB requires manual updates |
| chkrootkit | No | Monthly | High | Run `apt install --only-upgrade chkrootkit` |
| AIDE | No | Monthly | High | Update database with `sudo aideinit` |

### Updating Applications

The update process depends on your deployment mode:

#### Docker Mode Updates

For containerized applications:

```bash
# 1. Pull new container image
docker pull my-app:latest

# 2. Update using Docker Compose
docker compose pull
docker compose up -d

# 3. Verify deployment
docker compose ps
docker compose logs app
```

#### Bare Metal Mode Updates

For directly deployed applications:

```bash
# 1. Stop application gracefully
pm2 stop my-app  # For Node.js apps
systemctl stop my-app  # For systemd services

# 2. Update application code
git pull origin main
npm install --production  # For Node.js
composer install --no-dev  # For PHP

# 3. Restart application
pm2 restart my-app
systemctl start my-app

# 4. Verify application is running
pm2 status
systemctl status my-app
```

#### General Update Verification

Regardless of deployment mode:

1. Check application web interface accessibility
2. Verify application logs for errors
3. Test core functionality
4. Monitor system resources during and after updates

### Updating Debian Server

Automatic security updates are enabled by default, but manual full system updates should be performed regularly. Follow these steps monthly:

```bash
# Connect to your server
ssh -p 2222 deploy@your-server-ip

# Update package lists
sudo apt update

# Check available updates (review before applying)
apt list --upgradable

# Check automatic update logs
cat /var/log/unattended-upgrades/unattended-upgrades.log

# Apply all updates (during maintenance window)
sudo apt upgrade -y

# Reboot if kernel was updated
[ -f /var/run/reboot-required ] && sudo reboot
```

#### About Automatic Security Updates

The server is configured with automatic security updates enabled by default:

- Security patches are applied automatically
- Automatic reboots happen at 2 AM if required
- Cleanup of old packages is done weekly
- Error notifications are sent to the root user

To modify this configuration, edit the following files:

```bash
sudo nano /etc/apt/apt.conf.d/20auto-upgrades        # Update frequency
sudo nano /etc/apt/apt.conf.d/50unattended-upgrades  # Update behavior
```

To disable automatic updates (not recommended):

```bash
sudo dpkg-reconfigure -plow unattended-upgrades
# Select "No" when prompted
```

### Updating Nginx

Nginx updates are less frequent but important for security:

```bash
# Check for Nginx updates
sudo apt update
apt list --upgradable | grep nginx

# Update Nginx packages
sudo apt install --only-upgrade nginx

# Test configuration
sudo nginx -t

# Reload Nginx configuration
sudo systemctl reload nginx
```

### Updating Netdata Monitoring

Netdata is installed natively on the system and updates automatically via the system package manager:

```bash
# Check Netdata status
sudo systemctl status netdata

# Manual update (if needed)
sudo apt update && sudo apt upgrade netdata

# Restart Netdata after configuration changes
sudo systemctl restart netdata
```

### Update Verification

After any update, verify that all systems are functioning properly:

1. Check application web interface: `https://your-domain`
2. Verify monitoring: Netdata Cloud dashboards
3. Check application containers are running: `docker ps` (if using Docker)
4. Verify database backups are still working: `tail -f /opt/polyserver/backups/backup_*.log`
5. Check system logs for errors: `sudo journalctl -xef`

## SSL Certificate Management

SSL certificates are automatically managed by Certbot. The initial certificate is obtained during the first deployment, and renewal is handled automatically.

## Backup Strategy

This deployment includes a comprehensive backup strategy using OVH Object Storage (primary) and optional Block Storage (secondary).

### Primary: OVH Object Storage for Backups

OVH Object Storage is the recommended backup solution with many advantages:

- **Access from multiple servers**: Can be accessed from any server in any region
- **Higher durability**: Data is stored with erasure coding across multiple availability zones (with 3-AZ option)
- **Unlimited capacity**: No need to manage volume sizes or worry about running out of space
- **Versioning support**: Maintain multiple versions of your backups for better protection
- **Lifecycle policies**: Automate retention and deletion of old backups
- **Immutability options**: Prevent backups from being modified or deleted for compliance
- **Company-wide storage**: Can be organized across departments using buckets and prefixes

#### Setting Up OVH Object Storage

1. **Create an Object Storage container in the OVH Cloud Manager**:
   - Log in to your OVH Control Panel
   - Navigate to Public Cloud > Storage > Object Storage
   - Click "Create an Object Container"
   - Select a region close to your server for better performance (e.g., GRA, SBG, BHS)
   - Choose "Standard" storage class for backups

2. **Create an S3 user and generate access credentials**:
   - In the Object Storage section, click "Users and Roles"
   - Create a new user with a descriptive name (e.g., "app-backup")
   - Generate access keys and save them securely
   - **SECURITY**: Apply the principle of least privilege - limit permissions to only what's needed

3. **Configure your S3 credentials in the environment file**:

```bash
# Edit the environment file
nano /opt/polyserver/config/.env

# Add your S3 credentials
S3_BUCKET=polyserver-backups
S3_REGION=gra  # Your region (e.g., gra, sbg, bhs)
S3_PREFIX=production
AWS_ACCESS_KEY_ID=your_access_key
AWS_SECRET_ACCESS_KEY=your_secret_key

# Generate a strong encryption key for backups (highly recommended)
BACKUP_ENCRYPTION_KEY=$(openssl rand -base64 32)
echo "BACKUP_ENCRYPTION_KEY=$BACKUP_ENCRYPTION_KEY" >> /opt/polyserver/config/.env

# IMPORTANT: Store this encryption key safely outside the server too
echo "Save this encryption key in a secure location: $BACKUP_ENCRYPTION_KEY"
echo "Without this key, encrypted backups cannot be restored!"
```

4. **The S3 backup process will run automatically** via the scheduled backups.

**Note**: AWS CLI is already installed during the initial server setup.

#### Organization Strategy for Company-Wide Storage

For a company-wide Object Storage strategy, we recommend:

1. **Create one project per environment**:
   - Production
   - Development/Testing

2. **Within each project, create buckets by application**:
   - polyserver-backups
   - application-x-backups
   - database-backups

3. **Use prefixes within buckets for organization**:
   - production/
   - staging/
   - daily/weekly/monthly/

This organization allows for clear separation while maintaining the same pricing, as OVH charges based on total storage used regardless of how it's organized.

### Optional: Block Storage for Local Backups

Block Storage can be used as a secondary backup option, particularly when you need fast backup/restore performance. However, it has several limitations:

- **Single-instance mounting**: Can only be attached to one server at a time
- **Manual attachment**: Requires manual detachment/attachment to move between servers
- **No automatic failover**: If your primary server fails, you must manually recover backups
- **Fixed capacity**: Must provision a specific size in advance

#### Setting Up OVH Block Storage (Optional)

If you choose to use Block Storage as a secondary backup option, follow these steps:

1. **Enable Block Storage backups in your configuration**:

```bash
# Edit the environment file
nano /opt/polyserver/config/.env

# Enable Block Storage backups
BLOCK_STORAGE_ENABLED=true
```

2. **Provision a Block Storage volume**:
   - In your OVH Control Panel, navigate to your B2-7 server
   - Go to "Block Storage" and click "Create"
   - Select a size (recommended 50GB minimum for backups)
   - Choose the same region as your server
   - Click "Create" and wait for provisioning to complete

3. **Attach and mount the volume**:
   - Attach it to your server from the OVH control panel
   - SSH into your server and identify the block device:

```bash
lsblk
```

4. **Format the block device if it's new** (CAUTION: This erases all data):

```bash
sudo mkfs.ext4 /dev/sdb  # Replace sdb with your actual device
```

5. **Mount and configure the storage**:

```bash
# Create mount directory
sudo mkdir -p /mnt/backup

# Add to fstab for auto-mounting at boot
echo "/dev/sdb /mnt/backup ext4 defaults,noatime 0 2" | sudo tee -a /etc/fstab

# Mount the device
sudo mount /mnt/backup

# Create backup directory with proper permissions
sudo mkdir -p /mnt/backup/backups
sudo chown -R deploy:deploy /mnt/backup/backups
sudo chmod 750 /mnt/backup/backups
```

6. **Verify the mount**:

```bash
df -h | grep "/mnt/backup"
```

With both backup systems in place, you'll have a robust, multi-layered backup strategy with the speed of local storage and the durability of cloud storage.

## Server Monitoring and Security

The deployment includes multiple monitoring and security systems to ensure your applications are well-protected and properly monitored.

### Firewall Configuration

The server is protected by UFW (Uncomplicated Firewall), a user-friendly interface for iptables:

#### Default Firewall Rules

By default, the server is configured with these firewall rules:

```
Status: active

To                         Action      From
--                         ------      ----
2222/tcp                   ALLOW       Anywhere                   # SSH (custom port for security)
80/tcp                     ALLOW       Anywhere                   # HTTP (for redirects and Let's Encrypt)
443/tcp                    ALLOW       Anywhere                   # HTTPS (primary access)
```

All other incoming traffic is blocked by default, while all outgoing traffic is allowed.

#### Security Considerations

- **SSH Port**: Using non-standard port 2222 instead of 22 to reduce automated attacks
- **SSH Authentication**: Flexible configuration supporting both key-based and password authentication
- **No Direct Application Ports**: Application ports are not exposed directly; only accessible via Nginx proxy
- **No Public Monitoring**: Netdata monitoring port is not publicly accessible (access via SSH tunnel only)
- **Minimal Attack Surface**: Only essential services are exposed to the internet

#### Modifying Firewall Rules

To add or modify firewall rules on the server:

```bash
# Allow a new service (example: temporary access to port 8080)
sudo ufw allow 8080/tcp comment "Temporary development access"

# Delete a rule (by line number)
sudo ufw status numbered  # List rules with numbers
sudo ufw delete 3         # Delete rule number 3

# Temporarily disable firewall (not recommended in production)
sudo ufw disable

# Re-enable firewall
sudo ufw enable
```

#### Rate Limiting

The Nginx configuration includes rate limiting to protect against brute force attacks:

```
# Rate limiting to prevent brute-force attacks
limit_req_zone $binary_remote_addr zone=app_limit:10m rate=10r/s;

location / {
    # Rate limiting with burst
    limit_req zone=app_limit burst=20 nodelay;
    ...
}
```

This configuration:
- Limits each IP address to 10 requests per second
- Allows bursts of up to 20 requests
- Rejects excess requests immediately (nodelay)

### Audit Framework (auditd)

The server is configured with the Linux Audit Framework for comprehensive system activity monitoring:

- **Fine-grained audit rules**: Tracks critical system activities and changes
- **Security event monitoring**: Detects potential security breaches
- **Integrated reporting**: Daily audit reports with actionable insights
- **Comprehensive monitoring**: Over 30 key system areas monitored

#### Monitoring Areas

The audit system monitors:

1. **File System Changes**: Detects modifications to critical system files
2. **User Activity**: Monitors user management and authentication
3. **Privilege Escalation**: Identifies potential unauthorized escalation attempts
4. **Network Configuration**: Tracks changes to network settings
5. **Application Configuration**: Monitors changes to your deployment
6. **Docker Access**: Detects unauthorized access to Docker socket
7. **Critical Command Usage**: Monitors potentially dangerous commands
8. **DNS Lookups**: Provides visibility into DNS resolution activities
9. **Security Tool Configuration**: Ensures security tools remain properly configured
10. **Binary Modifications**: Detects changes to critical system binaries

#### Configuring Audit Framework

Audit settings can be configured by editing the defaults.env file:

```bash
# Audit settings
AUDIT_ENABLED=true
AUDIT_LOG_RETENTION=90
AUDIT_BUFFER_SIZE=8192
AUDIT_FAILURE_MODE=1
AUDIT_RULES_IMMUTABLE=false  # Set to true to make rules immutable (requires reboot to change)
```

#### Using the Audit System

```bash
# View current audit rules
sudo auditctl -l

# View audit status
sudo auditctl -s

# Search audit logs for events (example: user modification events)
sudo ausearch -k user_modify --start today -i

# Generate a comprehensive report
sudo ${DEPLOY_DIR}/scripts/audit-report.sh

# View specific failure types (example: authentication failures)
sudo ausearch --start today --end now | aureport --auth --summary -i

# View executable usage summary
sudo ausearch --start today --end now | aureport --executable --summary -i
```

#### Benefits of Audit Framework

- **Security compliance**: Helps meet regulatory requirements 
- **Breach detection**: Early warning of potential security incidents
- **Forensic analysis**: Detailed logs for post-incident investigation
- **Accountability**: Establishes clear audit trails for all system changes
- **Comprehensive reporting**: Daily summaries of security-relevant events

### Unbound DNS Cache

The server is configured with Unbound DNS cache to improve performance and security:

- **Local DNS caching**: Reduces latency for repeated DNS lookups
- **Performance improvements**: Faster application response times
- **Security benefits**: Protection against DNS-based attacks
- **DNSSEC validation**: Verifies DNS responses haven't been tampered with
- **Large cache size**: Optimized for minimal DNS lookup times

#### Configuring Unbound DNS Cache

Unbound settings can be configured by editing the defaults.env file:

```bash
# Unbound DNS cache settings
UNBOUND_ENABLED=true
UNBOUND_VERBOSITY=1
UNBOUND_CACHE_MIN_TTL=3600
UNBOUND_CACHE_MAX_TTL=86400
UNBOUND_MSG_CACHE_SIZE=128m
UNBOUND_RRSET_CACHE_SIZE=256m
UNBOUND_NEG_CACHE_SIZE=64m
UNBOUND_LOG_QUERIES=no
UNBOUND_LOG_REPLIES=no
UNBOUND_LOG_SERVFAIL=yes
UNBOUND_LOGFILE=/var/log/unbound.log
UNBOUND_DNS_PRIMARY=8.8.8.8
UNBOUND_DNS_SECONDARY=1.1.1.1
```

#### Checking Unbound Status

To check that Unbound is working correctly:

```bash
# Check service status
systemctl status unbound

# Query the local DNS resolver
dig @127.0.0.1 example.com

# Check cache statistics
unbound-control stats_noreset | grep cache
```

#### Benefits of Using Unbound

- **Improved performance**: Cached DNS responses reduce latency
- **Protection against DNS spoofing**: DNSSEC validation
- **Reduced load on upstream DNS**: Caching reduces queries to ISP DNS
- **Protection against DNS outages**: Cached responses remain available if upstream DNS fails
- **DNS privacy**: Queries are consolidated, reducing exposure to upstream DNS providers

### Netdata Monitoring

Netdata provides real-time performance monitoring installed natively on your Debian server with optional Cloud integration for centralized monitoring.

#### Accessing Netdata

Netdata is configured to bind only to localhost (127.0.0.1:19999) for security. Access it via:

**SSH Tunnel (Local Access)**:
```bash
ssh -L 19999:localhost:19999 -p 2222 deploy@your-server-ip
# Then visit http://localhost:19999 in your browser
```

**Netdata Cloud (Centralized Monitoring)**:
- **Automatic Setup**: Configure `NETDATA_CLAIM_TOKEN` and `NETDATA_CLAIM_ROOMS` in your environment for automatic registration
- **Manual Setup**: Use the detailed instructions provided during server setup
- **Mobile App**: Access your servers via Netdata Cloud mobile app
- **Team Collaboration**: Share dashboards, alerts, and insights across team members

#### Netdata Cloud Integration

To set up Netdata Cloud integration after deployment:

1. **Get Claim Token**:
   - Sign up/login at [https://app.netdata.cloud](https://app.netdata.cloud)
   - Create a new space or select existing space
   - Go to "Connect Nodes" and copy your claim token

2. **Register Server**:
   ```bash
   # Connect to your server
   ssh -p 2222 deploy@your-server-ip
   
   # Claim the node to Netdata Cloud
   sudo /opt/netdata/bin/netdata-claim.sh \
     -token=YOUR_CLAIM_TOKEN \
     -rooms=YOUR_ROOM_ID \
     -url=https://app.netdata.cloud
   ```

3. **Access Centralized Dashboard**:
   - Visit [https://app.netdata.cloud](https://app.netdata.cloud)
   - Your server will appear within 1-2 minutes

#### Netdata Cloud Benefits

- **Centralized Monitoring**: Single dashboard for all your servers
- **Mobile Access**: Monitor your infrastructure from anywhere
- **Alert Management**: Centralized alerting and notification management
- **Multi-server Correlation**: Compare performance across servers
- **Team Collaboration**: Share insights and collaborate on incidents
- **Infrastructure Overview**: High-level view of your entire infrastructure

#### Configuration

Netdata configuration is located at `/etc/netdata/netdata.conf` and is automatically configured during server setup for optimal security and performance. The configuration includes timezone settings from your template variables and security-optimized settings.

### Malware Protection

The server can be configured with complementary malware detection systems (optional components):

**Enable malware protection components:**

```bash
# Enable ClamAV antivirus (high resource usage)
export INSTALL_CLAMAV=true

# Enable Linux Malware Detect (medium resource usage)  
export INSTALL_MALDET=true

# Enable rootkit detection tools (low resource usage)
export INSTALL_RKHUNTER=true

# Enable Suricata network intrusion detection (medium resource usage)
export INSTALL_SURICATA=true
```

#### ClamAV Antivirus

ClamAV provides traditional antivirus protection:

- **Daily scans**: Automatic scans of key directories
- **Automatic updates**: Virus definitions are updated daily
- **Email alerts**: Notifications sent if viruses are detected

To manually run a ClamAV scan:

```bash
sudo clamscan -r -i /home /opt/polyserver /var/www
```

To update virus definitions:

```bash
sudo freshclam
```

#### Linux Malware Detect (maldet)

maldet provides specialized protection against web-based malware common in hosting environments:

- **Web-focused signatures**: Detects PHP/Perl/Python/Shell malware, backdoors, and web exploits
- **Optional ClamAV integration**: Can use both maldet and ClamAV signatures if both are enabled
- **File quarantine**: Isolates suspicious files for review
- **Daily scans**: Automatic scanning of critical directories
- **Email alerts**: Detailed reports of detected threats

To manually run a maldet scan:

```bash
# Scan specific directories
sudo maldet --scan-all /home /opt/polyserver /var/www

# View scan reports
sudo maldet --report list

# View specific report
sudo maldet --report REPORT_ID

# Update maldet signatures
sudo maldet --update-sigs
```

The combination of ClamAV and maldet provides comprehensive protection against both traditional and web-specific malware threats.

### Rootkit Detection

The server uses both RKHunter and chkrootkit for enhanced security:

- **Daily automated scans**: Both tools scan each night
- **Email alerts**: Notifications sent if suspicious activity is detected
- **Baseline updates**: Regular updates to maintain accuracy

To manually check for rootkits:

```bash
# Using RKHunter
sudo rkhunter --check --sk

# Using chkrootkit
sudo chkrootkit

# Update RKHunter database
sudo rkhunter --update

# Update RKHunter file properties database
sudo rkhunter --propupd
```

RKHunter is configured to do minimal whitelisting to provide high security with low false positives.

### File Integrity Monitoring

The server is configured with AIDE (Advanced Intrusion Detection Environment) to detect unauthorized file modifications:

- **Database initialization**: Initial file checksum database created during setup
- **Regular checking**: Compares current files against the known-good database
- **Notification**: Sends alerts when files change unexpectedly

To manually check file integrity:

```bash
# Run AIDE check
sudo aide.wrapper --check

# Update AIDE database after legitimate changes
sudo aide.wrapper --update
```

### Logcheck System Monitoring

Logcheck provides server-level log analysis with daily reports, carefully filtering out normal events to highlight potential issues:

- **Server log level**: Configured to show server-relevant security issues
- **Daily reports**: Summarizes suspicious log entries
- **Same recipient**: Uses the same email address as Logwatch

To customize logcheck settings:

```bash
sudo nano /etc/logcheck/logcheck.conf
```

### Logwatch System Monitoring

Logwatch provides daily system reports via email, summarizing server activities and potential issues.

#### Configuring Logwatch

Logwatch settings can be configured by editing the server-setup.sh script before installation, or by editing the configuration file afterward:

```bash
sudo nano /etc/logwatch/conf/logwatch.conf
```

Key settings you can modify:

```
# Email to receive reports
MailTo = your-email@example.com

# Detail level (Low, Med, High)
Detail = Med

# Time range for reports
Range = yesterday
```

Logwatch is configured to include hardware sensor information from lm_sensors, providing temperature and other hardware metrics in the daily reports.

### SSH Security Management

PolyServer provides comprehensive SSH security with flexible authentication options:

#### SSH Configuration Options

**Key-Based Authentication (Recommended)**
- Most secure option with automatic password auth disable
- Configured automatically during server setup if `SSH_PUBLIC_KEY` is provided
- No password authentication allowed

**Password Authentication (Initial Setup)**
- Enabled when `SSH_PUBLIC_KEY` is empty during setup
- Allows initial access with password
- Can be converted to key-only authentication later

#### Managing SSH Keys

**Adding SSH Keys to Existing Server:**
```bash
# Connect to your server
ssh -p 2222 deploy@your-server-ip

# Add your public key to authorized_keys
echo "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIG... your-email@example.com" >> ~/.ssh/authorized_keys

# Set proper permissions
chmod 600 ~/.ssh/authorized_keys
chmod 700 ~/.ssh
```

**Converting from Password to Key-Only Authentication:**
```bash
# After adding SSH keys, disable password authentication
sudo /opt/polyserver/scripts/ssh-disable-password-auth.sh

# This script will:
# 1. Create a backup of current SSH config
# 2. Ask for confirmation  
# 3. Test SSH configuration
# 4. Restart SSH service
# 5. Provide rollback instructions if needed
```

**Testing SSH Configuration:**
```bash
# Test SSH config before applying changes
sudo sshd -t

# Check current authentication methods
sudo sshd -T | grep -E "(PasswordAuthentication|PubkeyAuthentication)"

# View SSH authentication logs
sudo tail -f /var/log/auth.log
```

#### SSH Security Features

- **Custom Port**: SSH runs on port 2222 to reduce automated attacks
- **Strong Ciphers**: Modern encryption algorithms only
- **Failed Login Protection**: Fail2ban automatically blocks brute force attempts  
- **User Restrictions**: Only deploy user allowed for SSH access
- **No Root Access**: Root login disabled for security
- **Connection Limits**: Maximum 5 sessions, 3 authentication attempts

#### SSH Troubleshooting

**If Locked Out of Server:**
```bash
# If you have console access (VPS provider console)
# 1. Access via provider's web console
# 2. Edit SSH config to re-enable password auth temporarily:
sudo nano /etc/ssh/sshd_config
# Change: PasswordAuthentication yes
sudo systemctl restart sshd

# 3. Add SSH keys properly, then disable password auth again
```

**Backup and Recovery:**
```bash
# SSH config is automatically backed up during changes
ls -la /etc/ssh/sshd_config.*

# Restore from backup if needed
sudo cp /etc/ssh/sshd_config.backup /etc/ssh/sshd_config
sudo systemctl restart sshd
```

### Automatic Security Updates

For enhanced security, the server is configured with:

- **Automatic security patches**: Critical updates applied nightly
- **Fail2ban**: Protection against brute force attacks
- **UFW firewall**: Minimal open ports (SSH, HTTP, HTTPS)
- **SSH hardening**: Secure configuration with flexible authentication options

### Nginx Security Configuration

The server includes comprehensive nginx security rules that automatically block common attacks and reduce log noise:

#### Blocked Content
- **Sensitive Files**: `.git`, `.env`, `.htaccess`, backup files, config files
- **Documentation**: README, CHANGELOG, LICENSE files  
- **Common Admin Paths**: `/wp-admin`, `/phpmyadmin`, `/admin`, etc.
- **CMS Paths**: WordPress, Drupal, Joomla, Magento paths
- **Development Paths**: `/test`, `/dev`, `/staging`, `/backup`, etc.
- **Exploit Paths**: Common shell, backdoor, and attack tool paths
- **Script Files**: `.php`, `.asp`, `.jsp` files (varies by application)

#### Bot and Scanner Protection
- **Vulnerability Scanners**: Nikto, SQLMap, Nessus, Burp Suite, etc.
- **Bad User Agents**: Empty agents, known bot patterns
- **Suspicious Queries**: XSS attempts, SQL injection, path traversal
- **Malicious Referrers**: Spam and malicious referrer patterns

#### Rate Limiting
- **Authentication**: 1 request/second for login endpoints
- **API Endpoints**: 10 requests/second for general API calls  
- **Static Assets**: 50 requests/second with caching
- **General Traffic**: 10 requests/second baseline

#### Security Benefits
- **Reduced Attack Surface**: Blocks 90%+ of common automated attacks
- **Clean Logs**: Blocked requests don't generate log entries
- **Performance**: Faster response for blocked requests (return 444)
- **Early Defense**: Blocks attacks before they reach ModSecurity or applications

#### Testing Security Configuration

You can test the security configuration is working:

```bash
# Test blocking of sensitive files (should return connection closed)
curl -I https://your-domain/.env
curl -I https://your-domain/.git/config
curl -I https://your-domain/README.md

# Test blocking of admin paths (should return connection closed)
curl -I https://your-domain/wp-admin/
curl -I https://your-domain/phpmyadmin/

# Test rate limiting (make multiple rapid requests)
for i in {1..10}; do curl -I https://your-domain/api/session; done

# Check nginx configuration is valid
sudo nginx -t

# View security-related logs (should see blocked requests)
sudo tail -f /var/log/nginx/access.log | grep -E "(444|429)"
```

### Web Application Firewall (ModSecurity)

The Nginx server also includes ModSecurity, a powerful web application firewall that provides deeper content inspection:

- **OWASP Core Rule Set**: Baseline protection against OWASP Top 10 vulnerabilities
- **SQL Injection Prevention**: Blocks malicious SQL in requests
- **XSS Protection**: Prevents cross-site scripting attacks
- **Request Filtering**: Blocks malicious payloads and unusual request patterns
- **Custom Rules**: Application-specific exceptions to reduce false positives

#### ModSecurity Configuration

ModSecurity is automatically configured during server setup with application-specific rules in `/etc/nginx/modsec/modsecurity.conf`:

```bash
# Check ModSecurity status
sudo nginx -t

# View ModSecurity logs
sudo tail -f /var/log/nginx/modsec_audit.log
```

### Container Security

Docker containers are secured with multiple layers of protection:

- **Trivy Scanner**: Daily vulnerability scanning of all container images
- **Security Limits**: Strict resource limitations to prevent denial of service
- **No New Privileges**: Prevents privilege escalation within containers
- **Capability Restrictions**: Drops all Linux capabilities by default
- **Read-Only Filesystem**: Container runs with read-only root filesystem
- **Non-Root User**: Containers run as non-privileged users

#### Container Scanning

```bash
# Run a manual container scan
sudo /etc/cron.daily/trivy-scan

# View recent scan reports
ls -l /var/log/security/trivy/
```

### AppArmor Protection

AppArmor provides mandatory access control for Docker containers:

- **Restricted Filesystem Access**: Containers can only access necessary files
- **Process Isolation**: Limits system calls and capabilities
- **Deny Dangerous Operations**: Prevents mounting, kernel module loading
- **Application-Specific Profile**: Custom profile tailored to application needs

#### AppArmor Management

```bash
# Check AppArmor status
sudo aa-status

# See if profile is applied to container
docker inspect --format='{{.AppArmorProfile}}' app
```

### Network Intrusion Detection (Suricata)

Suricata monitors network traffic for malicious activity:

- **Real-time Traffic Analysis**: Inspects all incoming and outgoing packets
- **Application-Specific Rules**: Custom rules for application API endpoints
- **Attack Detection**: Identifies SQL injection, brute force, and scanning attempts
- **Alerting**: Logs potential security incidents for review

#### Suricata Logs

```bash
# View detected alerts
sudo cat /var/log/suricata/fast.log

# More detailed event information
sudo cat /var/log/suricata/eve.json
```

### Advanced Firewall with Fail2ban

In addition to the basic UFW firewall, the system uses Fail2ban to dynamically block malicious IP addresses:

#### Fail2ban Configuration

Fail2ban monitors log files and blocks IP addresses that show malicious behavior. The default configuration protects SSH:

```bash
# Configure fail2ban for SSH
cat > /etc/fail2ban/jail.local << EOF
[sshd]
enabled = true
port = $SSH_PORT
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
bantime = 3600
EOF
```

This configuration:
- Monitors SSH authentication logs
- Bans IP addresses after 3 failed attempts
- Ban duration is 3600 seconds (1 hour)

#### Managing Fail2ban

```bash
# View banned IPs
sudo fail2ban-client status sshd

# Manually ban an IP
sudo fail2ban-client set sshd banip 123.45.67.89

# Manually unban an IP
sudo fail2ban-client set sshd unbanip 123.45.67.89

# View fail2ban logs
sudo tail -f /var/log/fail2ban.log
```

### Application-Specific Hardening

Applications can be configured with security-hardened settings. For example, business intelligence platforms should include:

- **Strong Password Policy**: Requires complex passwords (12+ chars)
- **Session Timeout**: Sessions expire after 8 hours of inactivity
- **Login Protection**: Accounts lock after 5 failed attempts
- **Public Sharing Disabled**: No public dashboards or questions
- **Embedding Disabled**: No embedding in external applications
- **Download Restrictions**: Prevents data exfiltration via CSV/Excel
- **Advanced Permissions**: Granular access control enabled
- **TLS Validation**: Strict certificate validation for data sources
- **JWT Token Security**: Enhanced token rotation and validation

#### Database Encryption

For deployments using embedded databases, encryption can be enabled for at-rest data protection. **This encrypts your application database including user data and application content.**

**To enable database encryption:**

1. **Generate a strong encryption key**:
```bash
# Generate a 32-byte base64-encoded key
openssl rand -base64 32
```

2. **Add the key to your environment configuration**:
```bash
# Edit your environment file
nano /opt/polyserver/config/.env

# Add this line with your generated key
MB_ENCRYPTION_SECRET_KEY=your_generated_key_here
```

3. **Restart Application**:
```bash
# Docker mode
docker compose restart app

# Bare metal mode  
sudo systemctl restart application
```

**⚠️ IMPORTANT SECURITY NOTES:**
- **Store the encryption key securely** - without it, your database cannot be decrypted
- **Never lose this key** - there is no way to recover encrypted data without it
- **Back up the key separately** from your database backups
- **Use a password manager** or secure key management system to store it

#### Content Security Policy

A robust Content Security Policy has been implemented through Nginx:

```
Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; 
  connect-src 'self' https://trusted-domains.com; img-src 'self' data: blob:; 
  style-src 'self' 'unsafe-inline'; font-src 'self'; frame-src 'self'; base-uri 'self';
```

This policy:
- Restricts scripts to same origin (with exceptions needed for applications)
- Limits API connections to trusted sources
- Prevents loading of unauthorized resources
- Mitigates XSS and data injection attacks

## Incident Response Tools

The server comes with a comprehensive set of pre-installed tools for monitoring, diagnostics, and incident response:

### System Monitoring Tools

| Tool | Purpose | Basic Usage |
|------|---------|-------------|
| htop | Interactive process viewer with CPU/memory usage | `htop` |
| iotop | I/O monitoring, showing disk read/write by process | `sudo iotop` |
| sysstat | System performance tools (iostat, mpstat, etc.) | `iostat -x 2` |
| atop | Advanced system & process monitor | `atop` |
| bmon | Bandwidth monitoring and rate estimator | `bmon` |

### Network Monitoring Tools

| Tool | Purpose | Basic Usage |
|------|---------|-------------|
| iftop | Display bandwidth usage on an interface | `sudo iftop -i eth0` |
| nethogs | Group bandwidth by process | `sudo nethogs eth0` |
| tcpdump | Network packet analyzer | `sudo tcpdump -i eth0 host 1.2.3.4` |
| ethtool | Display or change Ethernet device settings | `sudo ethtool eth0` |
| iperf3 | Network bandwidth measurement | `iperf3 -s` (server) or `iperf3 -c server_ip` (client) |
| ncat | Networking utility for reading/writing across networks | `nc -l 9999` or `nc server_ip 9999` |

### Network Diagnostics Tools

| Tool | Purpose | Basic Usage |
|------|---------|-------------|
| mtr | Network diagnostic combining ping & traceroute | `mtr example.com` |
| arp-scan | ARP scanning and fingerprinting tool | `sudo arp-scan --interface=eth0 --localnet` |
| dnsutils | DNS utilities (dig, nslookup) | `dig example.com` or `nslookup example.com` |
| net-tools | Legacy networking tools | `netstat -tuln` |
| traceroute | Print the route packets trace to network host | `traceroute example.com` |
| whois | Query whois databases | `whois example.com` |
| unbound | Local DNS caching server | Check status with `systemctl status unbound` |

### File Integrity Tools

| Tool | Purpose | Basic Usage |
|------|---------|-------------|
| debsums | Verify installed package files against MD5 checksums | `sudo debsums -c` |
| aide | Advanced Intrusion Detection Environment | `sudo aide.wrapper --check` |

To check for modified files in Debian packages:

```bash
# Check all installed packages
sudo debsums -a

# Check for modified configuration files
sudo debsums -c
```

### Incident Response Reference

In case of a suspected security incident:

1. **Immediate Assessment**:
   ```bash
   # Check for unauthorized processes
   sudo htop
   
   # Check for unusual network connections
   sudo netstat -tulanp
   
   # Check for unauthorized users
   last
   ```

2. **Network Investigation**:
   ```bash
   # Identify unusual network traffic
   sudo iftop -i eth0
   
   # Capture suspicious traffic
   sudo tcpdump -i eth0 -w capture.pcap host suspicious_ip
   ```

3. **Verify System Integrity**:
   ```bash
   # Check for modified system files
   sudo aide.wrapper --check
   
   # Verify package integrity
   sudo debsums -c
   
   # Scan for rootkits
   sudo rkhunter --check --sk
   sudo chkrootkit
   ```

4. **Create Evidence If Needed**:
   ```bash
   # Create disk image for forensics
   sudo dd if=/dev/sda of=/path/to/external/disk.img bs=4M
   ```

## Maintenance and Monitoring

### Log Locations

#### Common Logs (Both Modes)
- Server logs: `/opt/polyserver/logs`
- Backup logs: `/opt/polyserver/backups/backup_*.log`
- Nginx access logs: `/var/log/nginx/access.log`
- Nginx error logs: `/var/log/nginx/error.log`

#### Docker Mode Specific
- Container logs: `docker compose logs` or `docker logs <container-name>`
- Application logs: Available through Docker logging drivers

#### Bare Metal Mode Specific  
- PM2 logs: `pm2 logs` or `/home/deploy/.pm2/logs/`
- Application logs: `/opt/polyserver/logs/` or application-specific locations
- System logs: Access with `sudo journalctl -xe`
- Virus scan logs: `/var/log/clamav/daily_scan.log`
- Malware detect logs: `/var/log/maldet/daily_scan.log`
- Rootkit scan logs: 
  - `/var/log/rkhunter/daily_scan.log` (RKHunter)
  - `/var/log/chkrootkit/daily_scan.log` (chkrootkit)
- File integrity logs: `/var/log/aide/aide.log`
- Audit logs: `/var/log/audit/audit.log`
- Audit reports: `/var/log/audit/reports/audit-report-*.txt`
- ModSecurity logs: `/var/log/nginx/modsec_audit.log`
- Container security: `/var/log/security/trivy/trivy-*.log`
- Suricata IDS logs: 
  - `/var/log/suricata/fast.log` (Alerts only)
  - `/var/log/suricata/eve.json` (Detailed events)
- Firewall logs: `/var/log/ufw.log`
- Fail2ban logs: `/var/log/fail2ban.log`
- AppArmor logs: `/var/log/syslog` (grep for 'apparmor')
- Logcheck reports: Sent via email
- Logwatch reports: Sent via email and in `/var/log/logwatch/logwatch.log`
- Unbound DNS logs: `/var/log/unbound.log`
- DSGVO/GDPR logs: 
  - `/var/log/dsgvo/subject_requests.log`
  - `/var/log/dsgvo/dsgvo_check_*.txt`
  - `/var/log/security/incidents/`

### Monitoring

#### System Monitoring (Both Modes)
- Netdata metrics: Available via Netdata Cloud or secure SSH tunnel at `http://localhost:19999`
- System resource usage: `htop`, `iotop`, `atop`
- Network monitoring: `iftop`, `nethogs`

#### Docker Mode Monitoring
- Container resource usage: `docker stats`
- Container health: `docker compose ps` and `docker compose top`
- Container logs: `docker compose logs -f`
- Docker system info: `docker system df` and `docker system events`

#### Bare Metal Mode Monitoring  
- Process monitoring: `pm2 monit` (for Node.js apps)
- Service status: `systemctl status <service-name>`
- Application-specific monitoring: Depends on application type

### Maintenance Tasks

| Task | Frequency | Command/Description |
|------|-----------|---------------------|
| Verify backups | Weekly | `ls -la /opt/polyserver/backups` and check S3 bucket |
| Test backup restore | Monthly | Follow backup restore procedure in disaster recovery plan |
| Clear old logs | Monthly | `find /opt/polyserver/logs -type f -mtime +30 -delete` |
| Check disk space | Weekly | `df -h` to ensure sufficient space |
| Verify auto-updates | Weekly | `cat /var/log/unattended-upgrades/unattended-upgrades.log` |
| Check virus scan logs | Weekly | `cat /var/log/clamav/daily_scan.log` |
| Review rootkit scans | Weekly | `cat /var/log/rkhunter/daily_scan.log /var/log/chkrootkit/daily_scan.log` |
| Check file integrity | Weekly | `sudo aide.wrapper --check` |
| Update virus signatures | Monthly | `sudo freshclam` |
| Update rootkit database | Monthly | `sudo rkhunter --update` |
| Update AIDE database | Monthly | `sudo aide.wrapper --update` |
| Clean unused Docker images | Monthly | `docker system prune -a` (Docker mode only) |
| Update container images | Weekly | `docker compose pull && docker compose up -d` (Docker mode only) |
| Check container health | Weekly | `docker compose ps` and `docker compose logs` (Docker mode only) |
| Manual security scan | Quarterly | `sudo rkhunter --check --sk` and review output |
| Check for failed updates | Weekly | `grep "ERROR" /var/log/unattended-upgrades/unattended-upgrades.log` |
| Review Logcheck reports | Weekly | Check email for logcheck reports |
| Review Logwatch reports | Weekly | Check email or `/var/log/logwatch/logwatch.log` |
| Check DNS cache status | Weekly | `unbound-control stats_noreset \| grep cache` |
| Update Unbound root hints | Monthly | `sudo wget -O /var/lib/unbound/root.hints https://www.internic.net/domain/named.root` |
| Check maldet reports | Weekly | `sudo maldet --report list` |
| Update maldet signatures | Weekly | `sudo maldet --update-sigs` |
| Review audit reports | Daily | Check email or `/var/log/audit/reports/audit-report-*.txt` |
| Check audit status | Weekly | `sudo auditctl -s` |
| Run manual audit report | Monthly | `sudo /opt/polyserver/scripts/audit-report.sh` |
| Check firewall status | Weekly | `sudo ufw status verbose` |
| Review fail2ban status | Weekly | `sudo fail2ban-client status` |
| Check banned IPs | Weekly | `sudo fail2ban-client status sshd` |
| Check AppArmor status | Weekly | `sudo aa-status` |
| Check ModSecurity logs | Weekly | `sudo cat /var/log/nginx/modsec_audit.log \| grep -i "attack"` |
| Review Suricata alerts | Weekly | `sudo cat /var/log/suricata/fast.log` |
| Scan container images | Monthly | `sudo /etc/cron.daily/trivy-scan` |
| Run DSGVO compliance check | Monthly | `sudo /opt/polyserver/scripts/dsgvo-compliance-check.sh` |
| Check SSH authentication logs | Weekly | `sudo grep "Failed password\|Accepted publickey" /var/log/auth.log` |
| Review SSH configuration | Quarterly | `sudo sshd -T \| grep -E "(PasswordAuthentication\|PubkeyAuthentication\|Port)"` |

### Disaster Recovery Testing
Regularly test your ability to recover from failures:

1. Schedule quarterly recovery drills
2. Practice restoring from backup in a test environment
3. Document recovery time and any issues encountered
4. Update recovery procedures based on findings

### Log Rotation and Management

PolyServer includes comprehensive log rotation to prevent disk space issues and maintain system performance. All logs are automatically rotated with compression and appropriate retention periods.

#### Configured Log Rotation

| Log Category | Rotation Frequency | Retention | Location |
|--------------|-------------------|-----------|----------|
| **Web Server Logs** | Daily | 30 days | `/var/log/nginx/*.log` |
| **ModSecurity WAF** | Daily | 14 days (100MB max) | `/var/log/nginx/modsec_*.log` |
| **Security Scans** | Weekly | 12 weeks | `/var/log/{clamav,maldet,rkhunter,chkrootkit}/` |
| **Container Security** | Weekly | 8 weeks | `/var/log/security/trivy/*.log` |
| **Docker Containers** | Daily | 7 days (100MB max) | `/var/lib/docker/containers/*/*.log` |
| **Application Logs** | Daily | 30 days | `/opt/polyserver/logs/*.log` |
| **Backup Logs** | Weekly | 12 weeks | `/opt/polyserver/backups/*.log` |
| **Audit Logs** | Weekly | 10 weeks (50MB max) | `/var/log/audit/audit.log` |
| **Suricata IDS** | Daily | 7 days | `/var/log/suricata/*.log` |
| **Netdata Monitoring** | Daily | 14 days | `/var/log/netdata/*.log` |
| **Unbound DNS** | Weekly | 12 weeks | `/var/log/unbound.log` |
| **Fail2ban** | Weekly | 12 weeks | `/var/log/fail2ban.log` |
| **UFW Firewall** | Daily | 30 days | `/var/log/ufw.log` |
| **DSGVO/GDPR** | Monthly | 24 months | `/var/log/dsgvo/*.log` |
| **Security Incidents** | Monthly | 36 months | `/var/log/security/incidents/*.log` |

#### Log Rotation Features

- **Compression**: All rotated logs are compressed to save disk space
- **Proper Permissions**: Rotated logs maintain appropriate ownership and permissions
- **Service Integration**: Services are properly reloaded/restarted after log rotation
- **Size Limits**: Large logs (ModSecurity, Docker) have size-based rotation
- **Compliance**: Security and GDPR logs have extended retention for compliance requirements

#### Manual Log Rotation

```bash
# Force rotation of all logs
sudo logrotate -f /etc/logrotate.conf

# Test log rotation configuration
sudo logrotate -d /etc/logrotate.conf

# Check log rotation status
sudo cat /var/lib/logrotate/status
```

#### Monitoring Disk Usage

```bash
# Check log directory sizes
sudo du -sh /var/log/* | sort -h

# Check PolyServer logs specifically
sudo du -sh /opt/polyserver/{logs,backups}

# Monitor disk space
df -h /var/log
```

### Advanced Network Traffic Monitoring

In addition to the built-in monitoring tools, the system provides capabilities for advanced network traffic analysis using `tcpdump`. This can be extremely valuable during security incidents or for traffic analysis.

#### Monitoring DNS Traffic

To monitor and log DNS queries for security analysis:

```bash
# Create log file with proper permissions
sudo touch /var/log/dns_queries.log
sudo chown root:root /var/log/dns_queries.log
sudo chmod 644 /var/log/dns_queries.log

# Start DNS monitoring in background (persists after logout)
nohup sudo bash -c 'tcpdump -i any port 53 -n -l -C 100 -W 5 >> /var/log/dns_queries.log 2>&1' &

# Check if monitoring is running
pgrep -a tcpdump
```

This configuration:
- Captures all DNS traffic (port 53)
- Creates a rotating log (5 files, 100MB each)
- Continues running even if you log out

#### Full Packet Capture for Forensics

During security incidents, capturing full packet data can provide crucial forensic evidence:

```bash
# Capture all traffic on primary interface to a pcap file
sudo tcpdump -i eth0 -w /var/log/security/incident-$(date +%Y%m%d).pcap

# For long-term monitoring with file rotation (new file every 5 minutes)
nohup sudo tcpdump -i eth0 -w '/var/log/security/net_%Y%m%d_%H%M.pcap' -G 300 -W 12 > /dev/null 2>&1 &
```

For continuous long-term monitoring, set up a rotating capture with cleanup:

```bash
# Set up directory
sudo mkdir -p /var/log/security/netcapture
sudo chmod 700 /var/log/security/netcapture

# Start continuous capture with 5-minute rotation
nohup sudo tcpdump -i eth0 -w '/var/log/security/netcapture/net_%Y%m%d_%H%M.pcap' -G 300 > /dev/null 2>&1 &

# Add cron job to delete files older than 2 hours
sudo crontab -e
# Add this line:
0 * * * * find /var/log/security/netcapture -name "net_*.pcap" -mmin +120 -delete
```

#### Managing Capture Processes

```bash
# Find running tcpdump processes
ps aux | grep tcpdump

# Stop all tcpdump processes
sudo pkill tcpdump

# Stop a specific process by PID
sudo kill 21678 

# Monitor capture file growth
ls -lh /var/log/security/netcapture/

# To leave shell while keeping capture running
jobs            # List jobs
disown %1       # Disown job #1
# or
disown -a       # Disown all jobs
```

#### Targeted Traffic Monitoring

For targeted monitoring of specific services or suspicious activity:

```bash
# Monitor web traffic (HTTP/HTTPS)
sudo tcpdump -i eth0 'tcp port 80 or tcp port 443' -w /var/log/security/web_traffic.pcap

# Monitor traffic to a specific IP address
sudo tcpdump -i eth0 host 192.168.1.100 -w /var/log/security/host_traffic.pcap

# Monitor SSH traffic for intrusion attempts
sudo tcpdump -i eth0 'tcp port 22' -w /var/log/security/ssh_traffic.pcap

# Monitor database traffic (e.g., PostgreSQL)
sudo tcpdump -i eth0 'tcp port 5432' -w /var/log/security/db_traffic.pcap
```

#### Analyzing Capture Files

Captured files can be analyzed with Wireshark or using command-line tools:

```bash
# Basic capture file statistics
tcpdump -r capture.pcap | wc -l        # Count packets
tcpdump -r capture.pcap -n | head -20  # View first 20 packets

# Extract HTTP request headers
tcpdump -r capture.pcap -A | grep -i "host:" | sort | uniq -c | sort -rn

# Find potential DNS exfiltration (unusually long DNS names)
tcpdump -r capture.pcap -n port 53 | grep -E '[A-Za-z0-9]{30,}'

# Extract IP conversations
tcpdump -r capture.pcap -nn -q | awk '{print $3 " " $5}' | tr -d : | sort | uniq -c | sort -nr | head
```

#### Security Best Practices for Packet Capture

1. **Storage Management**: Network captures grow quickly. Always set up proper rotation and cleanup.
2. **Access Control**: Restrict access to packet capture files as they may contain sensitive information.
3. **Targeted Capture**: In production, use filters to capture only relevant traffic and avoid performance impact.
4. **Memory Usage**: Monitor system resources when running long captures as they can consume significant memory.
5. **Data Protection**: Consider the privacy implications of packet captures and handle according to your organization's data policies.

## Customizing the Deployment

1. Edit the template files in the `templates/` directory
2. Modify `templates/defaults.env` to customize your server configuration:
   - Set `DEPLOYMENT_MODE=baremetal` for direct application deployment
   - Set `DEPLOYMENT_MODE=docker` for containerized application deployment
3. Run `./scripts/generate-configs.sh` to regenerate configuration files
4. Deploy using `./scripts/deploy-unified.sh`

## Performance Comparison

| Aspect | Docker Mode | Bare Metal Mode |
|--------|-------------|-----------------|
| **Setup Complexity** | ⭐⭐⭐⭐⭐ Easy | ⭐⭐⭐ Moderate |
| **Performance** | ⭐⭐⭐⭐ Good | ⭐⭐⭐⭐⭐ Excellent |
| **Resource Usage** | ⭐⭐⭐ Higher overhead | ⭐⭐⭐⭐⭐ Minimal overhead |
| **Security** | ⭐⭐⭐⭐⭐ Identical | ⭐⭐⭐⭐⭐ Identical |
| **Maintenance** | ⭐⭐⭐⭐ Simple | ⭐⭐⭐ More involved |
| **Scalability** | ⭐⭐⭐⭐⭐ Excellent | ⭐⭐⭐⭐ Good |
| **Isolation** | ⭐⭐⭐⭐⭐ Excellent | ⭐⭐⭐ Process-level |
| **Deployment** | ⭐⭐⭐⭐⭐ Container images | ⭐⭐⭐ Manual setup |

### Docker Mode Benefits:
- **Easy deployment**: Applications packaged as container images
- **Perfect isolation**: Each application in its own container
- **Horizontal scaling**: Easy to add/remove container instances
- **Rollback capability**: Quick rollback to previous container versions
- **Environment consistency**: Same container runs everywhere
- **Resource limits**: Built-in CPU/memory constraints per application

### Bare Metal Mode Benefits:
- **Maximum performance**: No containerization overhead
- **Minimal resource usage**: Direct hardware access
- **Lower complexity**: Fewer moving parts
- **Direct debugging**: Easier to troubleshoot issues
- **Custom optimizations**: Full control over system configuration

Both modes provide the same comprehensive security features and monitoring capabilities.

## Local Testing

Before deploying to production, you can test the PolyServer foundation locally using Docker. This allows you to validate configurations, test security features, and ensure everything works correctly for both deployment modes.

### Testing Different Deployment Modes

You can test both deployment modes locally by editing the test configuration:

```bash
# Test bare metal mode (default)
echo "DEPLOYMENT_MODE=baremetal" > test-config/.env

# Or test Docker mode
echo "DEPLOYMENT_MODE=docker" > test-config/.env
```

### Docker-Based Testing

1. **Start Local Test Environment**:
   ```bash
   ./local-test-docker.sh
   ```
   
   This script will:
   - Create a Docker-based PolyServer test environment
   - Generate configuration files from templates
   - Set up basic web server with security headers
   - Provide health check endpoints
   - Create persistent volumes for data, logs, and configuration

2. **Access Test Environment**:
   - Web interface: `http://localhost:8080`
   - Health check: `http://localhost:8080/health`
   - Container logs: `docker logs -f polyserver-test`
   - Zsh shell (root): `docker exec -it polyserver-test /bin/zsh`
   - Zsh shell (testuser): `docker exec -it -u testuser polyserver-test /bin/zsh`

3. **Cleanup Test Environment**:
   ```bash
   ./local-test-cleanup-docker.sh
   ```
   
   **SAFELY** removes only PolyServer-specific test containers, networks, and volumes. Your other Docker resources remain untouched.

### What Gets Tested

- **Base Configuration**: Template generation and configuration file creation
- **Web Server**: Nginx setup with security headers and professional landing page
- **Directory Structure**: PolyServer foundation directory layout
- **Security Features**: Basic security configurations
- **Health Monitoring**: Service health check endpoints
- **Development Environment**: Oh My Zsh with useful plugins and enhanced vim configuration

### Testing PolyServer Scripts

You can test the PolyServer scripts and functionality directly in the Docker container:

```bash
# Access the container shell
docker exec -it polyserver-test /bin/zsh

# Test DSGVO compliance scripts
cd /opt/polyserver/scripts
./dsgvo-compliance-check.sh

# Test breach response procedures
./breach-response-checklist.sh

# Test forensic collection
./collect-forensics.sh /tmp/test-evidence

# Test data subject request handling
./data-subject-request.sh
```

### Testing Your Applications

Once you've extended PolyServer for your specific application, you can modify the test scripts to:

- Test your application-specific configurations
- Validate custom templates and settings
- Test application deployment procedures
- Verify monitoring and security integrations

The local testing environment provides a safe sandbox to experiment with configurations before deploying to production servers.

## CI/CD and Testing

PolyServer includes comprehensive automated testing and validation through GitHub Actions workflows that ensure code quality, security, and proper functionality.

### Automated Testing Workflows

#### 🔧 **Server Hardening Tests** (`test-server-hardening.yml`)
Comprehensive testing of the PolyServer foundation:

- **Template Validation**: Validates shell script syntax and configuration generation
- **Matrix Testing**: Tests both Docker and Bare Metal deployment modes in parallel
- **Server Hardening**: Runs actual server-setup.sh script in containerized environments
- **Security Verification**: Validates log rotation, audit configuration, and DSGVO compliance
- **Local Testing**: Tests the local Docker testing workflow

**Triggers**: Pull requests to main, pushes to main, changes to templates/ or scripts/

#### 🛡️ **Security Scanning** (`security-scan.yml`)
Multi-layered security validation:

- **Secret Scanning**: Detects exposed credentials using TruffleHog
- **Vulnerability Scanning**: Scans container images with Trivy
- **Dependency Auditing**: Validates external dependencies and supply chain security
- **Code Quality**: ShellCheck analysis and configuration validation
- **Security Reporting**: Automated security reports with PR comments

**Triggers**: Pull requests, weekly schedule (Sundays 2 AM UTC), manual dispatch

#### 📚 **Documentation Validation** (`docs-validation.yml`)
Ensures documentation quality and consistency:

- **Markdown Validation**: Syntax checking and formatting
- **Link Verification**: Internal and external link validation  
- **Table of Contents**: Consistency with actual document structure
- **Content Completeness**: Required sections and DSGVO documentation
- **Reference Validation**: File and directory references in documentation

**Triggers**: Changes to *.md files, pull requests to main

### Testing Strategy

#### Quality Gates
All workflows must pass before PRs can be merged to main branch:

1. ✅ Template syntax and configuration generation
2. ✅ Server hardening in both deployment modes  
3. ✅ Security validation and compliance checks
4. ✅ Documentation consistency and completeness

#### Security-First Approach
- Continuous vulnerability scanning
- Secret detection and prevention
- Supply chain security monitoring
- Code quality enforcement

#### Automated Reporting
- Security scan results posted to PR comments
- Weekly security reports for ongoing monitoring
- Detailed test artifacts for troubleshooting
- Performance tracking and optimization

### Running Tests Locally

#### Prerequisites
```bash
# Docker for container testing
docker --version

# ShellCheck for script validation
shellcheck --version

# Basic tools
curl --version
```

#### Local Test Execution
```bash
# Run full local testing suite
./local-test-docker.sh

# Run specific template validation
./scripts/generate-configs.sh templates/defaults.env test-output/

# Validate shell scripts
find scripts/ -name "*.sh" -exec shellcheck {} \;

# Test both deployment modes
echo "DEPLOYMENT_MODE=docker" > test.env
cat templates/defaults.env >> test.env
./scripts/generate-configs.sh test.env test-docker/
```

#### Manual Security Checks
```bash
# Check for secrets (requires TruffleHog)
trufflehog git file://. --only-verified=false

# Scan containers for vulnerabilities (requires Trivy)
trivy image polyserver:test

# Validate configuration files
find templates/ -name "*.yml" -exec yamllint {} \;
```

### Contributing Guidelines

#### For Contributors
1. **Test Locally**: Run local tests before submitting PRs
2. **Review Security**: Address any security scan warnings
3. **Update Documentation**: Ensure documentation reflects changes
4. **Follow Conventions**: Use established coding and documentation standards

#### For Security-Sensitive Changes
1. **Extra Validation**: Test security configurations thoroughly
2. **Review Dependencies**: Audit any new external dependencies
3. **Document Changes**: Update security documentation as needed
4. **Monitor Results**: Review automated security scan results

### Workflow Maintenance

The CI/CD workflows are designed to be:
- **Self-Maintaining**: Automated updates for security tools
- **Extensible**: Easy to add new tests and validations
- **Efficient**: Parallel execution and smart caching
- **Informative**: Clear reporting and actionable feedback

For detailed workflow documentation, see [`.github/README-WORKFLOW.md`](.github/README-WORKFLOW.md).

