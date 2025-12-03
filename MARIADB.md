# MariaDB Dedicated Server Setup

Complete guide for deploying a security-hardened, performance-optimized MariaDB database server using PolyServer.

## Overview

This setup creates a dedicated MariaDB server with:
- **Security-first design**: Multiple layers of protection
- **Performance optimization**: Auto-tuned based on your hardware
- **Private network support**: vRack integration for OVH infrastructure
- **Enterprise features**: Automated backups, monitoring, health checks
- **Production-ready**: Based on battle-tested bastion hardening

## Quick Start

### Step 1: Deploy Base Server

```bash
# Clone the repository
git clone https://github.com/yourusername/PolyServer.git
cd PolyServer

# Run bastion setup script
sudo ./scripts/server-setup-bastion.sh
```

This creates a security-hardened base server with SSH hardening, firewall, AIDE, auditd, and system hardening.

### Step 2: Convert to MariaDB Server

```bash
# Run conversion script
sudo ./scripts/mariadb-1-convert.sh
```

**What happens:**
1. Detects system resources (RAM, CPU cores)
2. Installs MariaDB 10.11
3. Calculates optimal settings (InnoDB buffer pool, max connections, thread pool)
4. Generates strong root password → `/root/.my.cnf`
5. Runs automated security hardening
6. Sets up daily backups at 2 AM
7. Configures monitoring and health checks
8. Creates documentation in `/root/MARIADB-SERVER-README.md`

### Step 3: Configure Database Access

```bash
# Connect to MySQL (uses /root/.my.cnf automatically)
mysql

# Create database
CREATE DATABASE myapp CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

# Create user for your application servers (adjust IP range)
CREATE USER 'myapp'@'10.0.%' IDENTIFIED BY 'secure_password_here';

# Grant privileges
GRANT ALL PRIVILEGES ON myapp.* TO 'myapp'@'10.0.%';
FLUSH PRIVILEGES;
```

**IP Range Examples:**
- `'myapp'@'10.0.%'` - All 10.0.x.x network
- `'myapp'@'10.0.1.%'` - Only 10.0.1.x subnet
- `'myapp'@'10.0.1.10'` - Specific IP only

### Step 4: Test Connectivity

From your application server:

```bash
# Test connection
mysql -h DB_SERVER_IP -u myapp -p

# Or with connection string
mysql -h 10.0.1.10 -P 3306 -u myapp -pYourPassword -D myapp
```

### Step 5: Transition to Private Network (Optional)

**⚠️ IMPORTANT:** Have console/KVM access before proceeding!

```bash
# Run vRack transition script
sudo ./scripts/mariadb-2-enable-vrack.sh
```

The script will prompt for:
- vRack network interface (e.g., eno2, ens4)
- Private IP address (e.g., 10.0.1.10)
- Network prefix (e.g., 24 for /24)
- Gateway (optional)

**What happens:**
1. Configures network interface via netplan
2. Updates MariaDB to bind to vRack IP only
3. Optionally restricts SSH to vRack network
4. Creates network verification script
5. Updates documentation

### Step 6: Add PostgreSQL for Metabase (Optional)

If you need PostgreSQL for analytics tools like Metabase:

```bash
# Run PostgreSQL addition script
sudo ./scripts/mariadb-3-add-postgresql.sh
```

**What happens:**
1. Validates MariaDB installation
2. Installs PostgreSQL (latest stable)
3. Calculates optimal resource allocation (~20-30% of resources)
4. Creates optimized PostgreSQL configuration (SSD-optimized)
5. Sets up `metabase` database and user with secure password
6. Configures automated daily backups (7-day retention)
7. Enables Netdata PostgreSQL monitoring
8. Updates security monitoring (AIDE exclusions)
9. Creates documentation → `/root/POSTGRESQL-README.md`

**Use Case:** Internal analytics tools on the same server as MariaDB. PostgreSQL runs localhost-only with no external access.

**Resource Allocation:**
- MariaDB: Primary database (~70-75% of resources)
- PostgreSQL: Secondary for analytics (~20-30% of resources)
- Plenty of headroom on high-spec servers (256GB RAM / 32 cores)

See the [Phase 3 script documentation](#mariadb-3-add-postgresqlsh-phase-3---optional) below for detailed information.

## Architecture

### Three-Phase Deployment Strategy

#### Phase 1: Initial Setup (Public IP)
Server starts with public IP for installation and configuration:
1. SSH key-based access on public IP
2. Install and configure all software
3. Harden security
4. Configure MariaDB with optimizations
5. Set up monitoring

#### Phase 2: Switch to vRack Private Network (Optional)
Remove public access, switch to vRack-only:
1. Configure private network interface via netplan
2. Test private network connectivity
3. Update MariaDB to bind to private IP
4. Optionally remove public IP/interface
5. Database only accessible from vRack

#### Phase 3: Add PostgreSQL (Optional)
Add PostgreSQL for analytics tools on the same server:
1. Install and configure PostgreSQL with resource allocation
2. Create application database and user (e.g., Metabase)
3. Configure automated backups and monitoring
4. Localhost-only access (no external connections)
5. Both databases coexist efficiently

### What's Included

#### Core Security (from bastion)
- SSH hardening (key-only, custom port)
- Firewall (UFW) - only MySQL port 3306 from private IPs
- fail2ban for MySQL brute force protection
- Unattended security updates
- AIDE file integrity monitoring
- Audit framework (database-specific rules)
- AppArmor for MariaDB
- System hardening (sysctl, limits)

#### Monitoring
- Netdata with MySQL collector
- Logwatch for database logs
- Custom database monitoring scripts
- Resource guardian (database-optimized thresholds)

#### MariaDB Specific
- MariaDB 10.11 (Debian 13 default)
- RAM-based optimization (calculate InnoDB buffer pool)
- CPU-based optimization (thread pool, connections)
- Security hardening (mysql_secure_installation automated)
- Backup automation (mysqldump + optional S3)
- Slow query logging
- Binary logging for point-in-time recovery

### What's Excluded
- nginx, PHP, web server components
- Docker, Node.js, Redis (unless explicitly needed)
- SSH tunneling/forwarding (not a bastion)
- Extensive user management (single purpose server)

## Configuration Details

### Auto-Generated Performance Settings

Settings are calculated based on your hardware:

```ini
# Example for 8GB RAM, 4 CPU cores server:
innodb_buffer_pool_size = 6144M      # 75% of RAM
innodb_log_file_size = 1536M         # 25% of buffer pool
thread_pool_size = 8                 # 2x CPU cores
max_connections = 200                # Based on RAM tier
table_open_cache = 800               # 4x connections
thread_cache_size = 4                # = CPU cores
```

### RAM Allocation Formula

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

### Security Features

**MariaDB Security:**
- Strong random root password (32 characters)
- Anonymous users removed
- Remote root login disabled
- Test database removed
- `local-infile` disabled
- `skip-name-resolve` enabled

**Firewall Rules:**
```bash
# MySQL only from private networks
ufw allow from 10.0.0.0/8 to any port 3306
ufw allow from 172.16.0.0/12 to any port 3306
ufw allow from 192.168.0.0/16 to any port 3306

# Essential outgoing ports
ufw allow out 53      # DNS queries
ufw allow out 80      # HTTP for updates
ufw allow out 443     # HTTPS for updates
ufw allow out 123     # NTP time sync
ufw allow out 25      # SMTP for email delivery
ufw allow out 587     # SMTP submission
ufw allow out 465     # SMTPS secure email
```

**Systemd Hardening:**
- NoNewPrivileges=true
- PrivateTmp=true
- ProtectHome=true
- ProtectSystem=full
- OOMScoreAdjust=-200 (high priority)

### Backup System

**Automated Backups:**
- Schedule: Daily at 2 AM (cron)
- Full backup: All databases in one file
- Individual backups: One file per database
- Compression: gzip
- Retention: 7 days
- Location: `/var/backups/mysql/`

**Manual Backup:**
```bash
sudo /usr/local/bin/mysql-backup
```

**Restore Example:**
```bash
# Restore full backup
zcat /var/backups/mysql/full-backup-hostname-20250127-020000.sql.gz | mysql

# Restore single database
zcat /var/backups/mysql/myapp-20250127-020000.sql.gz | mysql myapp
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

## Common Operations

### Database Management

```sql
-- List databases
SHOW DATABASES;

-- Create database
CREATE DATABASE dbname CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- Drop database
DROP DATABASE dbname;

-- Database size
SELECT table_schema AS 'Database',
       ROUND(SUM(data_length + index_length) / 1024 / 1024, 2) AS 'Size (MB)'
FROM information_schema.tables
GROUP BY table_schema;
```

### User Management

```sql
-- Create user
CREATE USER 'username'@'host' IDENTIFIED BY 'password';

-- Grant privileges
GRANT ALL PRIVILEGES ON dbname.* TO 'username'@'host';
GRANT SELECT, INSERT, UPDATE, DELETE ON dbname.* TO 'username'@'host';

-- Show grants
SHOW GRANTS FOR 'username'@'host';

-- Change password
ALTER USER 'username'@'host' IDENTIFIED BY 'new_password';

-- Drop user
DROP USER 'username'@'host';

-- Reload privileges
FLUSH PRIVILEGES;
```

### Performance Analysis

```sql
-- Show current connections
SHOW PROCESSLIST;

-- Show status variables
SHOW GLOBAL STATUS LIKE 'Threads_connected';
SHOW GLOBAL STATUS LIKE 'Max_used_connections';
SHOW GLOBAL STATUS LIKE 'Slow_queries';

-- InnoDB status
SHOW ENGINE INNODB STATUS\G

-- Check buffer pool usage
SELECT (PagesData*PageSize)/POWER(1024,3) DataGB
FROM (SELECT variable_value PagesData
      FROM information_schema.global_status
      WHERE variable_name='Innodb_buffer_pool_pages_data') A,
     (SELECT variable_value PageSize
      FROM information_schema.global_status
      WHERE variable_name='Innodb_page_size') B;
```

### Table Optimization

```sql
-- Analyze tables
ANALYZE TABLE tablename;

-- Optimize tables
OPTIMIZE TABLE tablename;

-- Check table integrity
CHECK TABLE tablename;

-- Repair table
REPAIR TABLE tablename;
```

## Troubleshooting

### Cannot Connect

```bash
# 1. Check if MariaDB is running
systemctl status mariadb

# 2. Check listening ports
ss -tlnp | grep 3306

# 3. Check firewall
ufw status | grep 3306

# 4. Test local connection
mysql -e "SELECT 1;"

# 5. Check error log
tail -50 /var/log/mysql/error.log
```

### Connection Refused from Application Server

```bash
# 1. Verify bind-address
grep bind-address /etc/mysql/mariadb.conf.d/*.cnf

# 2. Check user host pattern
mysql -e "SELECT user, host FROM mysql.user WHERE user='myapp';"

# 3. Test network connectivity
ping DB_SERVER_IP

# 4. Check firewall on both sides
# DB server:
ufw status | grep 3306
# App server:
telnet DB_SERVER_IP 3306
```

### High Memory Usage

```bash
# Check InnoDB buffer pool setting
mysql -e "SHOW VARIABLES LIKE 'innodb_buffer_pool_size';"

# Current memory usage
free -h

# MySQL memory usage
ps aux | grep mysqld | awk '{print $6/1024 " MB"}'

# If needed, adjust in /etc/mysql/mariadb.conf.d/60-performance.cnf
# Then restart: systemctl restart mariadb
```

### Slow Queries

```bash
# View slow query log
tail -50 /var/log/mysql/slow.log

# Or use pt-query-digest (Percona Toolkit)
apt-get install percona-toolkit
pt-query-digest /var/log/mysql/slow.log
```

### Backup Failed

```bash
# Check backup log
tail -50 /var/log/mysql-backup.log

# Check disk space
df -h /var/backups/mysql

# Manual backup attempt
/usr/local/bin/mysql-backup
```

### Email Notifications Not Being Delivered

**Symptoms:** System emails (backup reports, security alerts, monitoring) not arriving.

**Common cause after vRack transition:** UFW interface-specific deny rules blocking outbound SMTP.

```bash
# 1. Check if emails are stuck in queue
mailq

# 2. Check mail log for connection timeouts
tail -50 /var/log/mail.log | grep -E "timeout|refused"

# 3. Test SMTP connectivity
timeout 5 bash -c 'cat < /dev/null > /dev/tcp/smtp.gmail.com/587' && echo "✅ Port 587: Connected" || echo "❌ Port 587: Blocked"

# 4. Check UFW rules - look for interface-specific deny rules
ufw status numbered | grep -E "DENY OUT|ALLOW OUT"
```

**Fix:** When using interface-specific deny rules (common after vRack setup), you must add interface-specific allow rules for SMTP ports **before** the deny rule:

```bash
# Identify your public interface
PUBLIC_INTERFACE=$(ip -o link show | awk -F': ' '{print $2}' | grep -E "enp.*f0$|ens.*0$" | head -1)

# Find the deny-out rule number
DENY_RULE=$(ufw status numbered | grep "DENY OUT.*$PUBLIC_INTERFACE" | head -1 | sed 's/\[//' | sed 's/\].*//' | xargs)

# Insert SMTP allow rules BEFORE the deny rule
ufw insert $DENY_RULE allow out on "$PUBLIC_INTERFACE" to any port 25 proto tcp comment "SMTP on public"
ufw insert $((DENY_RULE + 1)) allow out on "$PUBLIC_INTERFACE" to any port 587 proto tcp comment "SMTP submission on public"
ufw insert $((DENY_RULE + 2)) allow out on "$PUBLIC_INTERFACE" to any port 465 proto tcp comment "SMTPS on public"

# Reload and test
ufw reload
postqueue -f  # Flush mail queue
mailq         # Should be empty or reducing
```

**Why this happens:** UFW evaluates rules in order. Interface-specific deny rules (`deny out on enp97s0f0`) override generic port allows (`allow out 587/tcp`). You need interface-specific allows that match the deny rule's specificity.

**Prevention:** The `mariadb-2-enable-vrack.sh` script now includes these rules in the correct order during vRack setup.

## Security Best Practices

### 1. Password Management

```bash
# Generate strong password
openssl rand -base64 32

# Store securely (never in git!)
# Use environment variables or secrets management
```

### 2. Regular Updates

```bash
# Update MariaDB
apt-get update
apt-get upgrade mariadb-server mariadb-client

# Check version
mysql --version
```

### 3. Backup Verification

```bash
# Test restore monthly
zcat /var/backups/mysql/latest-backup.sql.gz | mysql test_restore

# Verify data integrity
mysql test_restore -e "SELECT COUNT(*) FROM test_table;"
```

### 4. Audit User Access

```sql
-- Review all users
SELECT user, host, password_expired, account_locked
FROM mysql.user;

-- Remove unused users
DROP USER 'olduser'@'oldhost';
```

### 5. Monitor Logs

```bash
# Check error log daily
tail -100 /var/log/mysql/error.log

# Review slow queries weekly
tail -500 /var/log/mysql/slow.log | grep "Query_time"
```

## Performance Tuning

### 1. Analyze Current Usage

```sql
-- Connection usage
SHOW STATUS LIKE 'Max_used_connections';
SHOW VARIABLES LIKE 'max_connections';
-- If Max_used_connections > 85% of max_connections, increase max_connections

-- Buffer pool efficiency
SHOW STATUS LIKE 'Innodb_buffer_pool_read%';
-- Calculate hit ratio:
-- (reads - read_requests) / reads * 100
-- Should be > 99%
```

### 2. Adjust Configuration

Edit `/etc/mysql/mariadb.conf.d/60-performance.cnf`:

```ini
# If you have more RAM available
innodb_buffer_pool_size = 8192M  # Increase

# If many connections needed
max_connections = 500  # Increase

# If high write load
innodb_io_capacity = 4000  # Increase
innodb_io_capacity_max = 8000  # Increase
```

Then restart: `systemctl restart mariadb`

### 3. Query Optimization

```sql
-- Enable profiling
SET profiling = 1;

-- Run query
SELECT * FROM large_table WHERE condition;

-- Show profile
SHOW PROFILES;
SHOW PROFILE FOR QUERY 1;

-- Analyze query plan
EXPLAIN SELECT * FROM large_table WHERE condition;
```

## Scaling Considerations

### Vertical Scaling (Single Server)

**When to scale:**
- CPU usage consistently > 80%
- Memory usage > 90%
- Disk I/O wait time high
- Connection limits reached

**How to scale:**
1. Upgrade server (more RAM/CPU)
2. Run script to recalculate settings:
   ```bash
   # Re-run conversion to update configs
   sudo ./scripts/mariadb-1-convert.sh
   ```

### Horizontal Scaling (Replication)

**Master-Slave Setup:**
1. Binary logging already enabled
2. Create replication user
3. Configure slave servers
4. Use read replicas for read-heavy loads

**Resources:**
- [MariaDB Replication Documentation](https://mariadb.com/kb/en/replication/)

## Migration Guide

### From Existing MySQL/MariaDB

```bash
# 1. Backup existing database
mysqldump --all-databases --single-transaction > full-backup.sql

# 2. Copy to new server
scp full-backup.sql new-server:/tmp/

# 3. On new server (after PolyServer setup)
mysql < /tmp/full-backup.sql

# 4. Verify
mysql -e "SHOW DATABASES;"
```

### From Other Database Systems

Use appropriate migration tools:
- PostgreSQL: pgloader
- MongoDB: mongodump → custom import script
- SQLite: sqlite3 .dump | mysql

## Network Configuration (vRack)

### vRack Network Interface Setup

Prompt for during Phase 1 setup:
- `VRACK_INTERFACE` - Network interface name (e.g., eno2, ens4)
- `VRACK_IP_ADDRESS` - Private IP address
- `VRACK_PREFIX` - CIDR prefix (e.g., 24 for /24)
- `VRACK_GATEWAY` (optional) - Gateway for private network

Configure via `/etc/netplan/60-vrack.yaml`:
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

### Security Considerations by Phase

#### Phase 1 (Public IP Active)
- SSH key-only on custom port
- fail2ban active
- MySQL port NOT exposed publicly
- Firewall only allows vRack IPs to MySQL

#### Phase 2 (Private Network Only)
- No public IP (optional)
- Only accessible via vRack
- SSH restricted to vRack IPs (optional)
- MySQL bound to vRack IP only

## Scripts

### mariadb-1-convert.sh (Phase 1)
Converts hardened bastion server to dedicated MariaDB server:
1. Environment Setup & Validation
2. System Updates & Base Packages
3. MariaDB Installation
4. MariaDB RAM/CPU Optimization
5. MariaDB Security Hardening
6. Backup Configuration
7. Monitoring Setup (Netdata, health checks)
8. Firewall Updates
9. Documentation Creation

### mariadb-2-enable-vrack.sh (Phase 2)
Transitions server to vRack private network:
1. Network Configuration Prompts
2. Netplan Configuration Creation
3. MariaDB bind-address Update
4. Firewall Rule Updates
5. SSH Configuration (optional restriction)
6. Network Verification Script
7. Rollback Instructions

### mariadb-3-add-postgresql.sh (Phase 3 - Optional)
Adds PostgreSQL to MariaDB server for Metabase analytics:
1. Validates MariaDB installation
2. Installs PostgreSQL (latest stable)
3. Calculates resource allocation (~20-30% of resources)
4. Creates optimized PostgreSQL configuration
5. Sets up metabase database and user
6. Configures automated backups (daily)
7. Enables Netdata PostgreSQL monitoring
8. Updates security monitoring (AIDE exclusions)
9. Creates documentation (/root/POSTGRESQL-README.md)

**Use Case**: Internal analytics tool (Metabase) on same server as MariaDB

**Resource Allocation**:
- MariaDB: Primary database (majority of resources)
- PostgreSQL: Secondary for Metabase (~20-30% resources)
- Example: 256GB RAM server → PostgreSQL gets ~50GB shared buffers

**Security**: Localhost-only access, no external connections

**Monitoring**: Integrated with Netdata, daily backups, security reports

## Additional Resources

- **MariaDB Documentation**: https://mariadb.com/kb/en/documentation/
- **Performance Tuning**: https://mariadb.com/kb/en/optimization-and-tuning/
- **Security Guide**: https://mariadb.com/kb/en/security/
- **Replication**: https://mariadb.com/kb/en/replication/

## Support

### Getting Help

1. Check logs: `/var/log/mysql/error.log`
2. Run health check: `sudo /usr/local/bin/mysql-health`
3. Review documentation: `/root/MARIADB-SERVER-README.md`
4. Check PolyServer issues: https://github.com/yourusername/PolyServer/issues

### Contributing

Found a bug or have improvements? Please contribute!

1. Fork the repository
2. Create feature branch
3. Test thoroughly
4. Submit pull request

---

**Created:** 2025-01-27
**Updated:** 2025-12-01
**Version:** 2.0
**Maintained by:** PolyServer Project
