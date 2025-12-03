#!/bin/bash
# mariadb-1-convert.sh - Convert hardened bastion to dedicated MariaDB server
# Run AFTER server-setup-bastion.sh to convert the server for database use
#
# Prerequisites:
# - server-setup-bastion.sh must be completed successfully
# - Run as root
# - Connected via SSH (script will handle SSH changes carefully at the end)

set -Eeuo pipefail

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "❌ This script must be run as root"
    exit 1
fi

# Environment setup
export DEBIAN_FRONTEND=noninteractive
export LANG=C.UTF-8
export LC_ALL=C.UTF-8

readonly SCRIPT_NAME="mariadb-conversion"
readonly LOG_FILE="/var/log/${SCRIPT_NAME}.log"

# Logging function
log_message() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

log_message "===== Starting Bastion to MariaDB Conversion ====="
log_message ""

# Verify bastion setup was completed
if [ ! -f /var/lib/bastion-setup-complete ]; then
    echo "❌ ERROR: Bastion setup not detected"
    echo "   Please run server-setup-bastion.sh first"
    exit 1
fi

log_message "✅ Bastion setup detected - proceeding with MariaDB conversion"

# Detect system resources for optimization
TOTAL_RAM_MB=$(free -m | awk '/^Mem:/{print $2}')
CPU_CORES=$(nproc)

log_message "System resources detected:"
log_message "  • RAM: ${TOTAL_RAM_MB}MB"
log_message "  • CPU cores: ${CPU_CORES}"

echo ""
echo "===== MariaDB Server Conversion ====="
echo "This script will convert your hardened bastion server into a dedicated MariaDB database server."
echo ""
echo "Changes that will be made:"
echo "  1. Install MariaDB with optimized configuration"
echo "  2. Configure MariaDB based on your RAM (${TOTAL_RAM_MB}MB) and CPU (${CPU_CORES} cores)"
echo "  3. Set up automated database backups"
echo "  4. Configure database monitoring"
echo "  5. Update firewall for MySQL access"
echo "  6. Remove bastion-specific configurations"
echo "  7. Simplify SSH configuration (LAST STEP - will prompt)"
echo ""
read -p "Continue with conversion? (yes/no): " -r
if [[ ! "$REPLY" =~ ^[Yy]es$ ]]; then
    echo "Conversion cancelled"
    exit 0
fi

echo ""
log_message "===== 1. Installing MariaDB Server ====="

# Install MariaDB
apt-get update
apt-get install -y mariadb-server mariadb-client

log_message "✅ MariaDB installed"

# Stop MariaDB for configuration
systemctl stop mariadb

log_message "===== 2. Calculating Optimal MariaDB Configuration ====="

# Calculate optimal settings based on RAM and CPU
# InnoDB Buffer Pool: 75% of RAM for dedicated DB server
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
elif [ $TOTAL_RAM_MB -lt 16384 ]; then
    MAX_CONNECTIONS=500
else
    MAX_CONNECTIONS=1000
fi

# Table open cache: scale with connections
TABLE_OPEN_CACHE=$((MAX_CONNECTIONS * 4))

log_message "Calculated MariaDB settings:"
log_message "  • InnoDB Buffer Pool: ${INNODB_BUFFER_POOL}MB"
log_message "  • InnoDB Log File Size: ${INNODB_LOG_FILE_SIZE}MB"
log_message "  • Thread Pool Size: ${THREAD_POOL_SIZE}"
log_message "  • Max Connections: ${MAX_CONNECTIONS}"
log_message "  • Table Open Cache: ${TABLE_OPEN_CACHE}"

log_message "===== 3. Creating Optimized MariaDB Configuration ====="

# Backup original config
cp /etc/mysql/mariadb.conf.d/50-server.cnf /etc/mysql/mariadb.conf.d/50-server.cnf.backup-$(date +%Y%m%d)

# Create optimized configuration
cat > /etc/mysql/mariadb.conf.d/60-performance.cnf << EOF
# MariaDB Performance Optimization
# Auto-generated based on: ${TOTAL_RAM_MB}MB RAM, ${CPU_CORES} CPU cores
# Generated: $(date)

[mysqld]

# ===== Connection Settings =====
max_connections = ${MAX_CONNECTIONS}
max_allowed_packet = 256M
thread_cache_size = ${CPU_CORES}
table_open_cache = ${TABLE_OPEN_CACHE}

# ===== Thread Pool (MariaDB-specific) =====
thread_handling = pool-of-threads
thread_pool_size = ${THREAD_POOL_SIZE}
thread_pool_max_threads = 2000
thread_pool_idle_timeout = 60

# ===== InnoDB Settings =====
innodb_buffer_pool_size = ${INNODB_BUFFER_POOL}M
innodb_log_file_size = ${INNODB_LOG_FILE_SIZE}M
innodb_log_buffer_size = 16M
innodb_file_per_table = 1
innodb_flush_method = O_DIRECT
innodb_flush_log_at_trx_commit = 2
innodb_io_capacity = 2000
innodb_io_capacity_max = 4000
innodb_read_io_threads = 4
innodb_write_io_threads = 4

# ===== Query Cache (disabled in MariaDB 10.10+, using better alternatives) =====
query_cache_type = 0
query_cache_size = 0

# ===== Temporary Tables =====
tmp_table_size = 64M
max_heap_table_size = 64M

# ===== Binary Logging =====
server_id = 1
log_bin = /var/log/mysql/mysql-bin.log
binlog_format = ROW
expire_logs_days = 7
max_binlog_size = 100M
sync_binlog = 1

# ===== Slow Query Log =====
slow_query_log = 1
slow_query_log_file = /var/log/mysql/slow.log
long_query_time = 2
log_queries_not_using_indexes = 0

# ===== Error Log =====
log_error = /var/log/mysql/error.log
log_warnings = 2

# ===== Network Settings =====
# Bind to all interfaces initially (will be changed to vRack IP in phase 2)
bind-address = 0.0.0.0
port = 3306
skip-name-resolve = 1

# ===== Security Settings =====
local-infile = 0
symbolic-links = 0

# ===== Character Set =====
character-set-server = utf8mb4
collation-server = utf8mb4_unicode_ci

# ===== Other =====
back_log = 100
wait_timeout = 600
interactive_timeout = 600
EOF

log_message "✅ Created optimized MariaDB configuration"

# Create security configuration
cat > /etc/mysql/mariadb.conf.d/99-security.cnf << 'EOF'
# MariaDB Security Hardening

[mysqld]

# Disable dangerous functions
# local-infile already disabled in performance config

# SSL/TLS (to be configured with certificates)
# ssl-ca=/etc/mysql/ssl/ca-cert.pem
# ssl-cert=/etc/mysql/ssl/server-cert.pem
# ssl-key=/etc/mysql/ssl/server-key.pem
# require_secure_transport=ON

[client]
# Client-side security
# ssl-ca=/etc/mysql/ssl/ca-cert.pem
EOF

log_message "✅ Created security configuration"

# Ensure log directory exists with proper permissions
mkdir -p /var/log/mysql
chown mysql:mysql /var/log/mysql
chmod 750 /var/log/mysql

log_message "===== 4. Starting and Securing MariaDB ====="

# Start MariaDB
systemctl start mariadb
systemctl enable mariadb

# Wait for MariaDB to be ready
sleep 5

# Run mysql_secure_installation automatically
log_message "Running mysql_secure_installation..."

# Generate strong root password
MYSQL_ROOT_PASSWORD=$(openssl rand -base64 32)

# Secure installation commands
mysql <<MYSQL_SECURE
-- Set root password
ALTER USER 'root'@'localhost' IDENTIFIED BY '${MYSQL_ROOT_PASSWORD}';

-- Remove anonymous users
DELETE FROM mysql.user WHERE User='';

-- Disallow root login remotely
DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost', '127.0.0.1', '::1');

-- Remove test database
DROP DATABASE IF EXISTS test;
DELETE FROM mysql.db WHERE Db='test' OR Db='test\\_%';

-- Reload privilege tables
FLUSH PRIVILEGES;
MYSQL_SECURE

# Save root password securely
cat > /root/.my.cnf << EOF
[client]
user=root
password=${MYSQL_ROOT_PASSWORD}

[mysql]
user=root
password=${MYSQL_ROOT_PASSWORD}
EOF
chmod 600 /root/.my.cnf

log_message "✅ MariaDB secured with strong root password"
log_message "   Password saved to /root/.my.cnf (chmod 600)"

echo ""
echo "⚠️  IMPORTANT: MariaDB root password has been set and saved to /root/.my.cnf"
echo "   Keep this file secure and back it up!"
echo ""

log_message "===== 5. Configuring Database Backups ====="

# Create backup directory
mkdir -p /var/backups/mysql
chmod 700 /var/backups/mysql

# Create backup script
cat > /usr/local/bin/mysql-backup << 'EOF'
#!/bin/bash
# Automated MySQL/MariaDB backup script
# Created by mariadb-1-convert.sh

set -e

BACKUP_DIR="/var/backups/mysql"
DATE=$(date +%Y%m%d-%H%M%S)
HOSTNAME=$(hostname)
RETENTION_DAYS=7

# Ensure backup directory exists
mkdir -p "$BACKUP_DIR"

# Get list of databases (exclude system databases from individual backups)
DATABASES=$(mysql -e "SHOW DATABASES;" | grep -Ev "Database|information_schema|performance_schema|mysql|sys")

# Full backup (all databases)
echo "Starting full database backup..."
mysqldump --all-databases \
    --single-transaction \
    --quick \
    --lock-tables=false \
    --routines \
    --triggers \
    --events \
    | gzip > "$BACKUP_DIR/full-backup-${HOSTNAME}-${DATE}.sql.gz"

echo "✅ Full backup complete: full-backup-${HOSTNAME}-${DATE}.sql.gz"

# Individual database backups
for DB in $DATABASES; do
    echo "Backing up database: $DB"
    mysqldump "$DB" \
        --single-transaction \
        --quick \
        --lock-tables=false \
        --routines \
        --triggers \
        | gzip > "$BACKUP_DIR/${DB}-${DATE}.sql.gz"
done

# Remove old backups
echo "Removing backups older than ${RETENTION_DAYS} days..."
find "$BACKUP_DIR" -name "*.sql.gz" -mtime +${RETENTION_DAYS} -delete

# Calculate backup size
BACKUP_SIZE=$(du -sh "$BACKUP_DIR" | cut -f1)
echo "✅ Backup complete. Total backup size: $BACKUP_SIZE"

# Log to syslog
logger -t mysql-backup "Database backup completed. Size: $BACKUP_SIZE"
EOF

chmod +x /usr/local/bin/mysql-backup

# Add to cron (daily at 2 AM)
echo "0 2 * * * root /usr/local/bin/mysql-backup >> /var/log/mysql-backup.log 2>&1" > /etc/cron.d/mysql-backup

log_message "✅ Backup script created: /usr/local/bin/mysql-backup"
log_message "   Scheduled daily at 2 AM via cron"

# Run initial backup
log_message "Running initial backup..."
/usr/local/bin/mysql-backup >> /var/log/mysql-backup.log 2>&1 || log_message "⚠️  Initial backup failed - check /var/log/mysql-backup.log"

log_message "===== 6. Configuring Database Monitoring ====="

# Add MariaDB monitoring to Netdata (if installed)
if command -v netdata >/dev/null 2>&1 && [ -d /etc/netdata ]; then
    log_message "Configuring Netdata MySQL monitoring..."

    # Create MySQL user for monitoring
    mysql <<MYSQL_MONITOR
CREATE USER IF NOT EXISTS 'netdata'@'localhost';
GRANT USAGE, REPLICATION CLIENT, PROCESS ON *.* TO 'netdata'@'localhost';
FLUSH PRIVILEGES;
MYSQL_MONITOR

    # Configure Netdata MySQL plugin
    cat > /etc/netdata/python.d/mysql.conf << 'EOF'
mysql:
  name: 'local'
  update_every: 2
  user: 'netdata'
  # No password needed for localhost socket connection
EOF

    systemctl restart netdata
    log_message "✅ Netdata MySQL monitoring configured"
fi

# Create database health check script
cat > /usr/local/bin/mysql-health << 'EOF'
#!/bin/bash
# MySQL/MariaDB health check script

echo "===== MariaDB Health Check ====="
echo "Timestamp: $(date)"
echo ""

# Check if MySQL is running
if systemctl is-active --quiet mariadb; then
    echo "✅ MariaDB service: RUNNING"
else
    echo "❌ MariaDB service: STOPPED"
    exit 1
fi

# Check MySQL connectivity
if mysql -e "SELECT 1;" >/dev/null 2>&1; then
    echo "✅ MySQL connectivity: OK"
else
    echo "❌ MySQL connectivity: FAILED"
    exit 1
fi

echo ""
echo "===== Server Status ====="
mysql -e "SHOW GLOBAL STATUS LIKE 'Threads_connected';" -s -N | awk '{print "Active connections: " $2}'
mysql -e "SHOW GLOBAL STATUS LIKE 'Max_used_connections';" -s -N | awk '{print "Peak connections: " $2}'
mysql -e "SHOW GLOBAL STATUS LIKE 'Uptime';" -s -N | awk '{print "Uptime (seconds): " $2}'

echo ""
echo "===== Database List ====="
mysql -e "SHOW DATABASES;" | grep -v "Database\|information_schema\|performance_schema\|mysql\|sys"

echo ""
echo "===== InnoDB Status ====="
mysql -e "SHOW ENGINE INNODB STATUS\G" | grep -A 5 "BUFFER POOL AND MEMORY"

echo ""
echo "===== Slow Queries ====="
mysql -e "SHOW GLOBAL STATUS LIKE 'Slow_queries';" -s -N | awk '{print "Slow queries: " $2}'
EOF

chmod +x /usr/local/bin/mysql-health

log_message "✅ Health check script created: /usr/local/bin/mysql-health"

log_message "===== 7. Updating Firewall for Database Server ====="

# Add MySQL port (restricted to private networks)
ufw allow from 10.0.0.0/8 to any port 3306 proto tcp comment 'MySQL from private 10.0.0.0/8'
ufw allow from 172.16.0.0/12 to any port 3306 proto tcp comment 'MySQL from private 172.16.0.0/12'
ufw allow from 192.168.0.0/16 to any port 3306 proto tcp comment 'MySQL from private 192.168.0.0/16'

log_message "✅ Firewall rules added for MySQL (port 3306, private networks only)"

# Ensure essential outgoing ports are allowed for system updates and notifications
log_message "Configuring outgoing firewall rules for system maintenance..."

# DNS (required for hostname resolution)
ufw allow out 53 comment 'DNS queries' 2>/dev/null || true
ufw allow out 53/udp comment 'DNS queries UDP' 2>/dev/null || true

# HTTP/HTTPS (required for package updates and security updates)
ufw allow out 80/tcp comment 'HTTP for updates' 2>/dev/null || true
ufw allow out 443/tcp comment 'HTTPS for updates' 2>/dev/null || true

# NTP (required for time synchronization)
ufw allow out 123/udp comment 'NTP time sync' 2>/dev/null || true

# SMTP (required for email notifications - security alerts, backups, monitoring)
ufw allow out 25/tcp comment 'SMTP for email delivery' 2>/dev/null || true
ufw allow out 587/tcp comment 'SMTP submission' 2>/dev/null || true
ufw allow out 465/tcp comment 'SMTPS secure email' 2>/dev/null || true

log_message "✅ Essential outgoing ports configured (DNS, HTTP/S, NTP, SMTP)"

log_message "===== 8. Removing Bastion-Specific Configurations ====="

# Remove bastion-specific commands
rm -f /usr/local/bin/bastionstat 2>/dev/null || true
rm -f /usr/local/bin/bastionmail 2>/dev/null || true

# Update SSH banner for database server
if [ -f /etc/ssh/banner ]; then
    log_message "Updating SSH banner for database server..."
    cat > /etc/ssh/banner << 'EOF'
***************************************************************************
                       MARIADB DATABASE SERVER
***************************************************************************

WARNING: This is a secure database server. All access is logged and monitored.

Unauthorized access is prohibited and will be prosecuted to the full extent
of the law. All activities on this system are recorded and may be used as
evidence in legal proceedings.

By accessing this system, you acknowledge that:
- You are an authorized database administrator
- Your activities are being monitored and logged
- You agree to comply with all applicable policies
- You will not attempt to compromise system or data security

If you are not an authorized user, disconnect immediately.

***************************************************************************
EOF
    chmod 644 /etc/ssh/banner
    log_message "✅ SSH banner updated for database server"
fi

# Update monitoring scripts to be database-focused
if [ -f /usr/local/bin/serverstatus ]; then
    # Rename to dbstatus
    mv /usr/local/bin/serverstatus /usr/local/bin/dbstatus
    # Update the script to add MySQL status
    cat >> /usr/local/bin/dbstatus << 'EOF'

echo ""
echo "=== MariaDB Status ==="
if systemctl is-active --quiet mariadb; then
    mysql -e "SHOW GLOBAL STATUS LIKE 'Threads_connected';" -s -N | awk '{print "MySQL connections: " $2}'
    mysql -e "SHOW GLOBAL STATUS LIKE 'Uptime';" -s -N | awk '{print "MySQL uptime (sec): " $2}'
else
    echo "❌ MariaDB is not running"
fi
EOF
    log_message "✅ Updated server status command to dbstatus (includes MySQL)"
fi

log_message "✅ Bastion-specific configurations removed"

log_message "===== 9. Creating MariaDB System Service Hardening ====="

# Add systemd security hardening for MariaDB
mkdir -p /etc/systemd/system/mariadb.service.d
cat > /etc/systemd/system/mariadb.service.d/security.conf << 'EOF'
[Service]
# Security hardening (compatible with MariaDB requirements)
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
# Note: Using ProtectSystem=full instead of strict to allow /run/mysqld creation
# ProtectSystem=strict causes "Failed to set up mount namespacing" errors
ProtectSystem=full

# Resource management
Nice=-5
OOMScoreAdjust=-200
LimitNOFILE=65536

# Restart policy
Restart=on-failure
RestartSec=10
StartLimitBurst=3
StartLimitInterval=300
EOF

systemctl daemon-reload
log_message "✅ MariaDB systemd security hardening applied"

# Update resource guardian thresholds for database workload
if [ -f /usr/local/bin/resource-guardian ]; then
    log_message "Updating resource guardian for database workload..."
    # Database servers typically use more RAM, adjust thresholds
    sed -i 's/MEMORY_WARNING_THRESHOLD=90/MEMORY_WARNING_THRESHOLD=95/' /usr/local/bin/resource-guardian 2>/dev/null || true
    sed -i 's/MEMORY_CRITICAL_THRESHOLD=95/MEMORY_CRITICAL_THRESHOLD=98/' /usr/local/bin/resource-guardian 2>/dev/null || true
    log_message "✅ Resource guardian updated for database workload"
fi

log_message "===== 10. Creating Documentation ====="

cat > /root/MARIADB-SERVER-README.md << EOF
# MariaDB Server Configuration

## Server Information
- Converted from bastion: $(date)
- Total RAM: ${TOTAL_RAM_MB}MB
- CPU Cores: ${CPU_CORES}
- MariaDB Version: $(mysql --version)

## MariaDB Configuration
- InnoDB Buffer Pool: ${INNODB_BUFFER_POOL}MB (75% of RAM)
- Max Connections: ${MAX_CONNECTIONS}
- Thread Pool Size: ${THREAD_POOL_SIZE}
- Configuration: /etc/mysql/mariadb.conf.d/60-performance.cnf

## Root Access
- Password stored in: /root/.my.cnf (chmod 600)
- Connect: mysql (will use credentials from .my.cnf)

## Backups
- Script: /usr/local/bin/mysql-backup
- Location: /var/backups/mysql/
- Schedule: Daily at 2 AM
- Retention: 7 days
- Manual backup: sudo /usr/local/bin/mysql-backup

## Monitoring
- Health check: /usr/local/bin/mysql-health
- Server status: /usr/local/bin/dbstatus (includes MySQL stats)
- Slow query log: /var/log/mysql/slow.log
- Error log: /var/log/mysql/error.log
- Netdata: Includes MySQL collector

## Security
- Firewall: MySQL port 3306 open only to private networks (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
- Current bind-address: 0.0.0.0 (change to vRack IP in Phase 2)
- Root login: localhost only
- Anonymous users: removed
- Test database: removed

## Network Configuration
- Current: Public IP with SSH access
- Next step: Run mariadb-2-enable-vrack.sh to switch to private vRack network

## Useful Commands
\`\`\`bash
# MySQL root access
mysql

# Health check
sudo /usr/local/bin/mysql-health

# Manual backup
sudo /usr/local/bin/mysql-backup

# Check connections
mysql -e "SHOW PROCESSLIST;"

# Check status
systemctl status mariadb

# View slow queries
tail -f /var/log/mysql/slow.log

# View error log
tail -f /var/log/mysql/error.log
\`\`\`

## Next Steps
1. Create your application databases and users
2. Configure application connection strings
3. Test database connectivity from application servers
4. Run mariadb-2-enable-vrack.sh to switch to private network
5. Remove public IP access

## Creating Database and User Example
\`\`\`sql
-- Connect as root
mysql

-- Create database
CREATE DATABASE myapp CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- Create user (replace with your vRack IP range)
CREATE USER 'myapp'@'10.0.%' IDENTIFIED BY 'secure_password_here';

-- Grant privileges
GRANT ALL PRIVILEGES ON myapp.* TO 'myapp'@'10.0.%';

-- Flush privileges
FLUSH PRIVILEGES;
\`\`\`
EOF

log_message "✅ Documentation created: /root/MARIADB-SERVER-README.md"

echo ""
echo "===== MariaDB Conversion Complete ====="
echo ""
echo "✅ MariaDB installed and configured"
echo "   • InnoDB Buffer Pool: ${INNODB_BUFFER_POOL}MB"
echo "   • Max Connections: ${MAX_CONNECTIONS}"
echo "   • Root password: /root/.my.cnf"
echo ""
echo "✅ Backups configured"
echo "   • Daily at 2 AM"
echo "   • Location: /var/backups/mysql/"
echo "   • Manual: sudo /usr/local/bin/mysql-backup"
echo ""
echo "✅ Monitoring configured"
echo "   • Health check: sudo /usr/local/bin/mysql-health"
echo "   • Server status: sudo /usr/local/bin/dbstatus"
echo ""
echo "📖 Documentation: /root/MARIADB-SERVER-README.md"
echo ""
echo "🔐 Security Status:"
echo "   • MySQL port 3306: Open to private networks only"
echo "   • Current bind-address: 0.0.0.0 (all interfaces)"
echo "   • SSH: Still using bastion configuration"
echo ""
echo "⚠️  IMPORTANT NEXT STEPS:"
echo "   1. Read /root/MARIADB-SERVER-README.md"
echo "   2. Test MySQL connectivity: sudo /usr/local/bin/mysql-health"
echo "   3. Create your databases and users"
echo "   4. When ready, run mariadb-2-enable-vrack.sh to switch to private network"
echo ""
echo "Conversion complete at: $(date)"
echo ""

# Mark conversion complete
date > /var/lib/mariadb-conversion-complete

log_message "Conversion completed successfully"
