# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

PolyServer is a foundational security-hardened Debian server setup repository designed to create standardized, production-ready server environments. It provides a comprehensive base configuration that can be used for deploying various applications including React/Next.js frontends (PM2), PHP backends and other web applications.

## Architecture

### Template-Based Configuration System
- **Source**: `templates/defaults.env` (base system configuration parameters)
- **Processing**: `scripts/generate-configs.sh` converts templates to deployable configs
- **Syntax**: `{{VARIABLE}}` placeholders replaced with environment values
- **Output**: Generated files go to `config/` directory (git-ignored)

### Base Server Foundation
- **Security-First Design**: 15+ integrated security tools including ModSecurity WAF, Suricata IDS, AppArmor, fail2ban, comprehensive audit framework
- **Performance Optimized**: Unbound DNS caching, optimized system settings, resource monitoring
- **Compliance Ready**: Full DSGVO/GDPR compliance toolkit and documentation

## Essential Commands

### Configuration Management
```bash
# Generate all configs from templates (default: templates/defaults.env → config/)
./scripts/generate-configs.sh

# Generate with custom env file and output directory
./scripts/generate-configs.sh [env_file] [output_dir]
```

### Server Deployment & Hardening
```bash
# Initial server hardening and base setup
./scripts/server-setup.sh

# Deploy base configuration to server
./scripts/deploy-unified.sh templates/defaults.env username server.example.com 2222
```

### Security & Compliance
```bash
# Security audit and reporting
./scripts/audit-report.sh

# DSGVO compliance verification
./scripts/dsgvo-compliance-check.sh

# Malware detection configuration
./scripts/maldet-config.sh

# Container security scanning
./scripts/trivy-scan.sh
```

### DSGVO/GDPR Management
```bash
# Setup DSGVO compliance framework
./scripts/setup-dsgvo.sh

# Handle data subject requests
./scripts/data-subject-request.sh

# Breach response procedures
./scripts/breach-response-checklist.sh

# Collect forensic evidence
./scripts/collect-forensics.sh
```

## Key Files and Directories

### Configuration Templates (`templates/`)
- `defaults.env` - Master base system configuration
- `nginx/` - Complete web server configurations:
  - `nginx.conf.template` - Main nginx configuration
  - `default.conf.template` - Default site configuration
  - `security.conf.template` - Security rules (application-agnostic)
  - `proxy_params.template` - Proxy settings
  - `index.html.template` - Default landing page
- `dsgvo/` - GDPR compliance document templates
- `audit/` - System auditing configuration
- `netdata/` - Performance monitoring configuration
- `suricata/` - Network intrusion detection
- `systemd/` - System service templates

### Deployment Scripts (`scripts/`)
- `generate-configs.sh` - Template processing engine
- `server-setup.sh` - Primary server hardening script
- `deploy-unified.sh` - Base configuration deployment
- DSGVO compliance and security scripts

### Generated Output (`config/`)
- Git-ignored directory containing processed templates
- Created by `generate-configs.sh`
- Used by deployment scripts

## Development Workflow

1. **Modify Base Configuration**: Edit `templates/defaults.env` for system-wide settings
2. **Customize Templates**: Modify specific service templates as needed
3. **Generate Configs**: Run `./scripts/generate-configs.sh`
4. **Deploy Base Setup**: Use `./scripts/deploy-unified.sh` to deploy hardened base server

## Application-Specific Extensions

After deploying the base server, additional deployment scripts and workflows should be created for specific applications:

- **React/Next.js + PM2**: Frontend application deployment
- **PHP Backend**: PHP-FPM and backend service configuration
- **Other Applications**: Custom application-specific configurations

## Security & Compliance Features

### Security Tools Included
- **Firewall**: UFW with fail2ban integration
- **Web Application Firewall**: ModSecurity with OWASP Core Rule Set
- **Intrusion Detection**: Suricata IDS with custom rules
- **Malware Protection**: ClamAV and Linux Malware Detect
- **Rootkit Detection**: RKHunter and chkrootkit
- **File Integrity**: AIDE monitoring
- **Container Security**: Trivy vulnerability scanning
- **Access Control**: AppArmor mandatory access control
- **Audit Framework**: Comprehensive system auditing with auditd

### DSGVO/GDPR Compliance
- Complete compliance toolkit in `templates/dsgvo/`
- Automated compliance verification scripts
- Data subject request handling procedures
- Breach response documentation and automation
- Privacy-by-design system configuration

### Monitoring & Performance
- **Netdata**: Real-time performance monitoring
- **Unbound DNS**: Caching DNS resolver for improved performance
- **Log Management**: Logwatch and logcheck for system monitoring
- **Resource Monitoring**: Comprehensive system resource tracking

## Advanced Security Features (Optional)

The main server setup now includes optional advanced security features inspired by the bastion host configuration:

### Resource Guardian System
- **Purpose**: Proactive resource monitoring and management to prevent system overload
- **Configuration**: Conservative production-safe thresholds
  - CPU monitoring: 85% threshold for 10+ minutes (with 2-minute warning)
  - Memory monitoring: 90% warning, 95% critical with emergency cleanup
  - Load average alerts: 2x CPU count threshold
- **Safety Features**: 
  - Email alerts for all actions
  - Grace periods before termination
  - Protection of critical system processes
- **Usage**: Optional during setup, runs every 5 minutes via systemd timer

### Advanced Monitoring Commands
- **serverstatus**: Comprehensive server health and status report
  - System information, resource usage, service status
  - Recent security events and resource alerts
  - Can be run by any user without special privileges
  
- **logmon [type]**: Real-time log monitoring with filtering
  - Types: auth, security, system, nginx, all
  - Requires sudo for log file access
  - Intelligent filtering for relevant security events

- **servermail**: Local system mail reader
  - Reads system notifications and security alerts
  - Works with local mail delivery setup
  - Alternative to external email configuration

### Enhanced Systemd Resource Management
- **Priority-based service scheduling**:
  - SSH: Highest priority (OOM -300, Nice -8) with security hardening
  - fail2ban: High priority (OOM -100, Nice -5) for security protection
  - Suricata: Medium priority (OOM +100, Nice +5) for network monitoring  
  - Nginx: Standard priority (OOM +50, Nice 0) with security hardening
- **Security hardening**: PrivateTmp, ProtectSystem for critical services
- **Enhanced restart policies**: Intelligent failure handling and recovery

## Best Practices

- This repository provides the **foundation layer** only
- Application-specific deployment should extend this base
- All security configurations are application-agnostic
- DSGVO compliance tools work for any application type
- Templates can be customized while maintaining security standards
- **New**: Advanced features are optional and production-safe by design
