# MariaDB Dedicated Server Setup Plan

## Overview
Create a specialized setup script for dedicated MariaDB database servers running in OVH vRack private networks.

## Two-Phase Deployment Strategy

### Phase 1: Initial Setup (Public IP)
Server starts with public IP for installation and configuration:
1. SSH key-based access on public IP
2. Install and configure all software
3. Harden security
4. Configure MariaDB with optimizations
5. Set up monitoring

### Phase 2: Switch to vRack Private Network
Remove public access, switch to vRack-only:
1. Configure private network interface via netplan
2. Test private network connectivity
3. Remove public IP/interface
4. Database only accessible from vRack

## Architecture Decisions

### Base Approach
- **Start fresh** rather than modify bastion script (6700+ lines with 100+ bastion-specific references)
- **Borrow structure** from bastion for security hardening
- **Focus on database** - no web server components

### What to Include

#### Core Security (from bastion)
- ✅ SSH hardening (key-only, custom port)
- ✅ Firewall (UFW) - only MySQL port 3306 from private IPs
- ✅ fail2ban for MySQL brute force
- ✅ Unattended upgrades
- ✅ AIDE file integrity
- ✅ Audit framework (database-specific rules)
- ✅ AppArmor for MariaDB
- ✅ System hardening (sysctl, limits)

#### Monitoring
- ✅ Netdata with MySQL collector
- ✅ Logwatch for database logs
- ✅ Custom database monitoring scripts
- ✅ Resource guardian (database-optimized thresholds)

#### MariaDB Specific
- ✅ MariaDB 10.11 (Debian 13 default)
- ✅ RAM-based optimization (calculate InnoDB buffer pool)
- ✅ CPU-based optimization (thread pool, connections)
- ✅ Security hardening (mysql_secure_installation automated)
- ✅ Backup automation (mysqldump + optional S3)
- ✅ Slow query logging
- ✅ Binary logging for point-in-time recovery

### What to Exclude
- ❌ nginx, PHP, web server components
- ❌ Docker, Node.js, Redis (unless explicitly needed)
- ❌ SSH tunneling/forwarding (not a bastion)
- ❌ Extensive user management (single purpose server)

## Network Configuration

### vRack Network Interface Setup
Prompt for during Phase 1 setup:
- `VRACK_INTERFACE` - Network interface name (e.g., eno2, ens4)
- `VRACK_IP_ADDRESS` - Private IP address
- `VRACK_PREFIX` - CIDR prefix (e.g., 24 for /24)
- `VRACK_GATEWAY` (optional) - Gateway for private network

Configure via `/etc/netplan/50-cloud-init.yaml`:
```yaml
network:
    ethernets:
        NETWORK_INTERFACE:
            dhcp4: false
            addresses:
              - IP_ADDRESS/PREFIX
            # Optional gateway if needed
            # gateway4: GATEWAY_IP
```

### Firewall Rules
```bash
# Allow MySQL only from vRack subnet
ufw allow from 10.0.0.0/8 to any port 3306 proto tcp
ufw allow from 172.16.0.0/12 to any port 3306 proto tcp
ufw allow from 192.168.0.0/16 to any port 3306 proto tcp

# SSH from anywhere initially (Phase 1)
# SSH only from vRack after Phase 2
```

## MariaDB Optimization Formula

### RAM Allocation
```bash
TOTAL_RAM_MB=$(free -m | awk '/^Mem:/{print $2}')
CPU_CORES=$(nproc)

# InnoDB Buffer Pool: 70-80% of RAM for dedicated DB server
INNODB_BUFFER_POOL=$((TOTAL_RAM_MB * 75 / 100))

# InnoDB Log File Size: 25% of buffer pool
INNODB_LOG_FILE_SIZE=$((INNODB_BUFFER_POOL / 4))

# Thread Pool: Based on CPU cores
THREAD_POOL_SIZE=$((CPU_CORES * 2))

# Max Connections: Scale with RAM
if [ $TOTAL_RAM_MB -lt 2048 ]; then
    MAX_CONNECTIONS=100
elif [ $TOTAL_RAM_MB -lt 8192 ]; then
    MAX_CONNECTIONS=200
else
    MAX_CONNECTIONS=500
fi
```

### Key MariaDB Settings
```ini
[mysqld]
# Memory
innodb_buffer_pool_size = ${INNODB_BUFFER_POOL}M
innodb_log_file_size = ${INNODB_LOG_FILE_SIZE}M
innodb_log_buffer_size = 16M

# Performance
thread_cache_size = ${CPU_CORES}
table_open_cache = 4096
max_connections = ${MAX_CONNECTIONS}

# Thread Pool (MariaDB-specific)
thread_handling = pool-of-threads
thread_pool_size = ${THREAD_POOL_SIZE}
thread_pool_max_threads = 2000

# InnoDB
innodb_file_per_table = 1
innodb_flush_method = O_DIRECT
innodb_flush_log_at_trx_commit = 2
innodb_io_capacity = 2000

# Binary Logging
server_id = 1
log_bin = /var/log/mysql/mysql-bin.log
binlog_format = ROW
expire_logs_days = 7
max_binlog_size = 100M

# Slow Query Log
slow_query_log = 1
slow_query_log_file = /var/log/mysql/slow.log
long_query_time = 2

# Security
bind-address = 0.0.0.0  # Phase 1: any, Phase 2: vRack IP only
skip-name-resolve = 1
local-infile = 0
```

## Script Structure

### scripts/server-setup-mariadb.sh (Phase 1)
```bash
#!/bin/bash
# Phase 1: Initial setup with public IP

1. Environment Setup & Validation
2. System Updates & Base Packages
3. vRack Network Configuration (prompt & configure, don't apply yet)
4. User Creation & SSH Hardening
5. Firewall Setup (allow SSH + MySQL from vRack)
6. Security Tools (fail2ban, AIDE, auditd)
7. MariaDB Installation
8. MariaDB RAM/CPU Optimization
9. MariaDB Security Hardening
10. Backup Configuration
11. Monitoring Setup (Netdata, Logwatch)
12. Resource Guardian (DB-optimized)
13. System Hardening (sysctl, limits)
14. Create Phase 2 Script
15. Summary & Next Steps
```

### scripts/mariadb-phase2-private-network.sh (Phase 2)
```bash
#!/bin/bash
# Phase 2: Switch to vRack private network

1. Verify Private Network Configuration
2. Test Private Network Connectivity
3. Update MariaDB bind-address to vRack IP
4. Update Firewall (restrict SSH to vRack only)
5. Apply Netplan Configuration
6. Remove Public IP (optional, manual step)
7. Verify Connectivity
8. Update Documentation
```

## File Organization

```
scripts/
├── server-setup-mariadb.sh          # Phase 1: Main setup
├── mariadb-phase2-private.sh        # Phase 2: Switch to private
templates/
├── mariadb/
│   ├── my.cnf.template              # Optimized MariaDB config
│   ├── backup.sh.template           # Database backup script
│   └── monitoring.sh.template       # DB health monitoring
```

## Implementation Steps

1. Create `scripts/server-setup-mariadb.sh` - focused, database-specific script
2. Borrow security hardening sections from bastion (SSH, firewall, fail2ban, AIDE)
3. Add MariaDB-specific installation and optimization
4. Create Phase 2 script for network transition
5. Test on fresh Debian 13 instance

## Security Considerations

### Phase 1 (Public IP Active)
- SSH key-only on custom port
- fail2ban active
- MySQL port NOT exposed publicly
- Firewall only allows vRack IPs to MySQL

### Phase 2 (Private Network Only)
- No public IP
- Only accessible via vRack
- SSH restricted to vRack IPs
- MySQL bound to vRack IP only

## Implementation Status

✅ **COMPLETED** - MariaDB dedicated server setup scripts created

### Scripts Created

1. **scripts/convert-to-mariadb.sh** (633 lines)
   - Converts hardened bastion server to dedicated MariaDB server
   - Auto-calculates optimal settings based on RAM/CPU
   - Installs and secures MariaDB with strong passwords
   - Configures automated backups (daily at 2 AM)
   - Sets up monitoring and health checks
   - Updates firewall for MySQL access (private networks only)
   - Creates comprehensive documentation

2. **scripts/mariadb-enable-vrack.sh** (450+ lines)
   - Phase 2: Transitions server to vRack private network
   - Interactive network configuration with validation
   - Updates MariaDB to bind to vRack IP only
   - Safely handles SSH configuration with warnings
   - Creates network status monitoring script
   - Comprehensive verification and rollback instructions

### Key Features Implemented

#### Resource-Based Optimization
- **RAM Detection**: Auto-calculates InnoDB buffer pool (75% of RAM)
- **CPU Detection**: Configures thread pool based on CPU cores
- **Connection Scaling**: Adjusts max_connections based on available RAM
- **Table Cache**: Scales with connection count (4x connections)

#### Security Hardening
- **Strong Passwords**: Auto-generated 32-character root password
- **mysql_secure_installation**: Automated security setup
- **Firewall**: MySQL port restricted to private networks only (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
- **Systemd Hardening**: NoNewPrivileges, PrivateTmp, ProtectSystem
- **Bind Address**: Configurable per phase (0.0.0.0 → vRack IP)

#### Monitoring & Operations
- **Health Check**: `/usr/local/bin/mysql-health` - comprehensive status
- **Server Status**: `/usr/local/bin/dbstatus` - includes MySQL stats
- **vRack Status**: `/usr/local/bin/mariadb-vrack-status` - network verification
- **Netdata Integration**: MySQL collector with monitoring user
- **Logging**: Slow query log (2s threshold), error log with warnings

#### Backup System
- **Full Backups**: All databases with mysqldump
- **Individual Backups**: Per-database backups
- **Compression**: All backups gzipped
- **Retention**: 7 days automatic cleanup
- **Schedule**: Daily at 2 AM via cron
- **Location**: `/var/backups/mysql/`

### Usage

#### Step 1: Deploy Base Hardened Server
```bash
# Deploy bastion server first
./scripts/server-setup-bastion.sh
```

#### Step 2: Convert to MariaDB Server
```bash
# Run the conversion script
sudo ./scripts/convert-to-mariadb.sh

# What it does:
# - Installs MariaDB optimized for your hardware
# - Sets up automated backups
# - Configures monitoring
# - Updates firewall
# - Creates documentation in /root/MARIADB-SERVER-README.md
```

#### Step 3: Configure Application Access
```bash
# Connect to MySQL
mysql

# Create database and user
CREATE DATABASE myapp CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER 'myapp'@'10.0.%' IDENTIFIED BY 'secure_password';
GRANT ALL PRIVILEGES ON myapp.* TO 'myapp'@'10.0.%';
FLUSH PRIVILEGES;
```

#### Step 4: Transition to Private Network (Optional)
```bash
# IMPORTANT: Have console/KVM access before running!
sudo ./scripts/mariadb-enable-vrack.sh

# What it does:
# - Configures vRack network interface
# - Updates MariaDB to listen on private IP only
# - Optionally restricts SSH to vRack network
# - Creates network verification script
```

### Monitoring Commands

```bash
# Check MariaDB health
sudo /usr/local/bin/mysql-health

# Check server status (includes MySQL)
sudo /usr/local/bin/dbstatus

# Check vRack network status (after Phase 2)
sudo /usr/local/bin/mariadb-vrack-status

# Manual backup
sudo /usr/local/bin/mysql-backup

# View slow queries
tail -f /var/log/mysql/slow.log

# View error log
tail -f /var/log/mysql/error.log
```

### Configuration Files

- **Performance**: `/etc/mysql/mariadb.conf.d/60-performance.cnf` (auto-generated)
- **Security**: `/etc/mysql/mariadb.conf.d/99-security.cnf`
- **Root Credentials**: `/root/.my.cnf` (chmod 600)
- **vRack Network**: `/etc/netplan/60-vrack.yaml` (Phase 2)
- **Documentation**: `/root/MARIADB-SERVER-README.md`

### Testing Checklist

- [ ] Syntax validation (completed ✅)
- [ ] Test on fresh Debian 13 instance
- [ ] Verify MariaDB installation and optimization
- [ ] Test backup script execution
- [ ] Verify monitoring integration
- [ ] Test vRack network configuration
- [ ] Verify connectivity from application servers
- [ ] Test SSH safety mechanisms
- [ ] Performance testing with realistic workload

## Next Steps

1. ✅ Scripts created and syntax validated
2. Test on fresh Debian 13 server instance
3. Gather feedback and iterate
4. Add to main PolyServer documentation
5. Create quickstart guide for common use cases
