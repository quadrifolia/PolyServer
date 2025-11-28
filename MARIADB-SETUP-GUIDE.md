# MariaDB Dedicated Server Setup Guide

Complete guide for setting up a security-hardened, performance-optimized MariaDB database server using PolyServer.

## Overview

This setup creates a dedicated MariaDB server with:
- **Security-first design**: Multiple layers of protection
- **Performance optimization**: Auto-tuned based on your hardware
- **Private network support**: vRack integration for OVH infrastructure
- **Enterprise features**: Automated backups, monitoring, health checks
- **Production-ready**: Based on battle-tested bastion hardening

## Architecture

### Two-Phase Deployment

#### Phase 1: Initial Setup (Public IP)
Server starts with public IP for installation:
1. Deploy hardened base server (bastion)
2. Convert to MariaDB server
3. Configure databases and users
4. Test from application servers

#### Phase 2: Private Network (Optional)
Switch to vRack private network:
1. Configure vRack network interface
2. Update MariaDB to bind to private IP
3. Restrict SSH access
4. Remove public IP

## Prerequisites

- Fresh Debian 13 server (bare metal or VM)
- Root access via SSH
- Minimum 2GB RAM (4GB+ recommended)
- For Phase 2: vRack network configured in OVH

## Quick Start

### Step 1: Deploy Base Server

```bash
# Clone the repository
git clone https://github.com/yourusername/PolyServer.git
cd PolyServer

# Run bastion setup script
sudo ./scripts/server-setup-bastion.sh
```

This creates a security-hardened base server with:
- SSH hardening (key-only, custom port)
- Firewall (UFW) with fail2ban
- AIDE file integrity monitoring
- Audit framework
- Unattended security updates
- System hardening (sysctl, limits)

### Step 2: Convert to MariaDB Server

```bash
# Run conversion script
sudo ./scripts/convert-to-mariadb.sh
```

**What happens:**
1. Detects system resources (RAM: 8192MB, CPU: 4 cores)
2. Installs MariaDB 10.11
3. Calculates optimal settings:
   - InnoDB Buffer Pool: 6144MB (75% of RAM)
   - Max Connections: 200
   - Thread Pool: 8 threads
4. Generates strong root password → `/root/.my.cnf`
5. Runs automated security hardening
6. Sets up daily backups at 2 AM
7. Configures monitoring
8. Creates documentation

**Output files:**
- Configuration: `/etc/mysql/mariadb.conf.d/60-performance.cnf`
- Root password: `/root/.my.cnf` (chmod 600)
- Documentation: `/root/MARIADB-SERVER-README.md`
- Backup script: `/usr/local/bin/mysql-backup`
- Health check: `/usr/local/bin/mysql-health`

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

# Verify
SHOW GRANTS FOR 'myapp'@'10.0.%';
```

**IP Range Examples:**
- `'myapp'@'10.0.%'` - All 10.0.x.x network
- `'myapp'@'10.0.1.%'` - Only 10.0.1.x subnet
- `'myapp'@'10.0.1.10'` - Specific IP only
- `'myapp'@'192.168.%'` - All 192.168.x.x network

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
sudo ./scripts/mariadb-enable-vrack.sh
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

**After transition:**
- MariaDB: Listens on vRack IP only
- SSH: Optionally restricted to vRack
- Firewall: Allows vRack network for MySQL
- Public IP: Can be removed manually

## Configuration Details

### Auto-Generated Performance Settings

Settings are calculated based on your hardware:

```ini
# For 8GB RAM, 4 CPU cores server:
innodb_buffer_pool_size = 6144M      # 75% of RAM
innodb_log_file_size = 1536M         # 25% of buffer pool
thread_pool_size = 8                 # 2x CPU cores
max_connections = 200                # Based on RAM tier
table_open_cache = 800               # 4x connections
thread_cache_size = 4                # = CPU cores
```

### RAM Tiers for max_connections

- < 2GB RAM: 100 connections
- 2GB - 8GB: 200 connections
- 8GB - 16GB: 500 connections
- 16GB+: 1000 connections

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
```

**Systemd Hardening:**
- NoNewPrivileges=true
- PrivateTmp=true
- ProtectHome=true
- ProtectSystem=strict
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

### Monitoring & Health Checks

**Health Check:**
```bash
sudo /usr/local/bin/mysql-health

# Output:
# ✅ MariaDB service: RUNNING
# ✅ MySQL connectivity: OK
# Active connections: 5
# Peak connections: 12
# Uptime (seconds): 86400
```

**Server Status:**
```bash
sudo /usr/local/bin/dbstatus

# Includes MySQL stats in output
```

**vRack Network Status:**
```bash
sudo /usr/local/bin/mariadb-vrack-status

# Shows network config and connectivity
```

**Netdata Integration:**
- MySQL collector enabled automatically
- Monitors: connections, queries, InnoDB, locks, etc.
- Access: http://server-ip:19999

**Log Files:**
- Slow queries: `/var/log/mysql/slow.log` (threshold: 2 seconds)
- Errors: `/var/log/mysql/error.log`
- Binary logs: `/var/log/mysql/mysql-bin.*` (7 day retention)

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

### Optimization

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
   sudo ./scripts/convert-to-mariadb.sh
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

## License

Same as PolyServer main project.

---

**Created:** 2025-01-27
**Version:** 1.0
**Maintained by:** PolyServer Project
