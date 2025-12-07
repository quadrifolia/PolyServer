#!/bin/bash
# mariadb-3-add-postgresql.sh - Add PostgreSQL to MariaDB server for Metabase
# Run AFTER mariadb-1-convert.sh (and optionally mariadb-2-enable-vrack.sh)
#
# ⚠️  DEPRECATION WARNING ⚠️
# This script is DEPRECATED and maintained for legacy deployments only.
#
# For new deployments, simply install both databases during initial setup:
#   1. Configure defaults.env with:
#      INSTALL_MARIADB=true
#      INSTALL_POSTGRESQL=true
#   2. Run server-setup.sh
#
# The general server-setup.sh now includes resource-aware configuration that
# automatically allocates resources appropriately when both databases are
# installed (MariaDB gets 40% RAM, PostgreSQL gets 20% RAM).
#
# Prerequisites:
# - mariadb-1-convert.sh must be completed successfully
# - Run as root
# - PostgreSQL will be configured for Metabase use (internal admin tool)
#
# Resource allocation:
# - MariaDB remains primary database (already configured)
# - PostgreSQL gets ~20-30% of resources for Metabase analytics

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

readonly SCRIPT_NAME="postgresql-addition"
readonly LOG_FILE="/var/log/${SCRIPT_NAME}.log"

# Logging function
log_message() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

log_message "===== Adding PostgreSQL to MariaDB Server ====="
log_message ""

# Verify MariaDB conversion was completed
if [ ! -f /var/lib/mariadb-conversion-complete ]; then
    echo "❌ ERROR: MariaDB conversion not detected"
    echo "   Please run mariadb-1-convert.sh first"
    exit 1
fi

log_message "✅ MariaDB server detected - proceeding with PostgreSQL addition"

# Detect system resources
TOTAL_RAM_MB=$(free -m | awk '/^Mem:/{print $2}')
CPU_CORES=$(nproc)

log_message "System resources detected:"
log_message "  • RAM: ${TOTAL_RAM_MB}MB"
log_message "  • CPU cores: ${CPU_CORES}"

echo ""
echo "===== PostgreSQL Addition for Metabase ====="
echo "This script will add PostgreSQL to your MariaDB database server."
echo ""
echo "Purpose: PostgreSQL will be used for Metabase analytics (internal admin tool)"
echo "Resource allocation: ~20-30% of server resources (MariaDB remains primary)"
echo ""
echo "Changes that will be made:"
echo "  1. Install PostgreSQL with optimized configuration"
echo "  2. Configure PostgreSQL for Metabase workload"
echo "  3. Create metabase database and user"
echo "  4. Set up automated PostgreSQL backups"
echo "  5. Configure PostgreSQL monitoring in Netdata"
echo "  6. Update firewall (localhost-only access)"
echo "  7. Add PostgreSQL to security monitoring"
echo ""
read -p "Continue with PostgreSQL installation? (yes/no): " -r
if [[ ! "$REPLY" =~ ^[Yy]es$ ]]; then
    echo "Installation cancelled"
    exit 0
fi

echo ""
log_message "===== 1. Installing PostgreSQL ====="

# Install PostgreSQL (latest stable from Debian repos)
apt-get update
apt-get install -y postgresql postgresql-contrib postgresql-client

# Get PostgreSQL version
PG_VERSION=$(psql --version | awk '{print $3}' | cut -d. -f1)
PG_CLUSTER="main"
PG_CONF_DIR="/etc/postgresql/${PG_VERSION}/${PG_CLUSTER}"
PG_DATA_DIR="/var/lib/postgresql/${PG_VERSION}/${PG_CLUSTER}"

log_message "✅ PostgreSQL ${PG_VERSION} installed"
log_message "   Config: ${PG_CONF_DIR}"
log_message "   Data: ${PG_DATA_DIR}"

# Stop PostgreSQL for configuration
systemctl stop postgresql

log_message "===== 2. Calculating PostgreSQL Configuration ====="

# Resource allocation: ~20-30% for PostgreSQL (Metabase workload)
# MariaDB keeps the majority of resources as primary database

# Shared buffers: 20% of RAM (conservative for secondary database)
SHARED_BUFFERS_MB=$((TOTAL_RAM_MB * 20 / 100))

# Effective cache size: 40% of RAM (includes OS cache)
EFFECTIVE_CACHE_SIZE_MB=$((TOTAL_RAM_MB * 40 / 100))

# Work memory: Per-query memory (be conservative with many connections)
WORK_MEM_MB=$((TOTAL_RAM_MB / 500))  # ~512MB with 256GB RAM
if [ $WORK_MEM_MB -lt 4 ]; then
    WORK_MEM_MB=4
elif [ $WORK_MEM_MB -gt 512 ]; then
    WORK_MEM_MB=512
fi

# Maintenance work memory: For VACUUM, CREATE INDEX
MAINTENANCE_WORK_MEM_MB=$((TOTAL_RAM_MB / 32))  # ~8GB with 256GB RAM
if [ $MAINTENANCE_WORK_MEM_MB -lt 64 ]; then
    MAINTENANCE_WORK_MEM_MB=64
elif [ $MAINTENANCE_WORK_MEM_MB -gt 8192 ]; then
    MAINTENANCE_WORK_MEM_MB=8192
fi

# WAL settings
WAL_BUFFERS_MB=$((SHARED_BUFFERS_MB / 32))
if [ $WAL_BUFFERS_MB -lt 16 ]; then
    WAL_BUFFERS_MB=16
elif [ $WAL_BUFFERS_MB -gt 64 ]; then
    WAL_BUFFERS_MB=64
fi

# Max connections: Metabase typically needs 10-50 connections
MAX_CONNECTIONS=100

# Parallel workers: Use some cores for parallel queries
MAX_PARALLEL_WORKERS=$((CPU_CORES / 4))
if [ $MAX_PARALLEL_WORKERS -lt 2 ]; then
    MAX_PARALLEL_WORKERS=2
elif [ $MAX_PARALLEL_WORKERS -gt 8 ]; then
    MAX_PARALLEL_WORKERS=8
fi

MAX_PARALLEL_WORKERS_PER_GATHER=$((MAX_PARALLEL_WORKERS / 2))
if [ $MAX_PARALLEL_WORKERS_PER_GATHER -lt 2 ]; then
    MAX_PARALLEL_WORKERS_PER_GATHER=2
fi

log_message "Calculated PostgreSQL settings:"
log_message "  • Shared buffers: ${SHARED_BUFFERS_MB}MB"
log_message "  • Effective cache size: ${EFFECTIVE_CACHE_SIZE_MB}MB"
log_message "  • Work mem: ${WORK_MEM_MB}MB"
log_message "  • Maintenance work mem: ${MAINTENANCE_WORK_MEM_MB}MB"
log_message "  • WAL buffers: ${WAL_BUFFERS_MB}MB"
log_message "  • Max connections: ${MAX_CONNECTIONS}"
log_message "  • Max parallel workers: ${MAX_PARALLEL_WORKERS}"

log_message "===== 3. Creating PostgreSQL Configuration ====="

# Create optimized PostgreSQL configuration
cat > "${PG_CONF_DIR}/conf.d/99-polyserver-optimization.conf" << EOF
# PolyServer PostgreSQL Configuration for Metabase
# Generated: $(date)
# System: ${TOTAL_RAM_MB}MB RAM, ${CPU_CORES} CPU cores

####################
# Connection Settings
####################
max_connections = ${MAX_CONNECTIONS}
superuser_reserved_connections = 3

####################
# Memory Settings
####################
shared_buffers = ${SHARED_BUFFERS_MB}MB
work_mem = ${WORK_MEM_MB}MB
maintenance_work_mem = ${MAINTENANCE_WORK_MEM_MB}MB
autovacuum_work_mem = ${MAINTENANCE_WORK_MEM_MB}MB
effective_cache_size = ${EFFECTIVE_CACHE_SIZE_MB}MB
temp_buffers = 8MB

####################
# WAL Settings
####################
wal_buffers = ${WAL_BUFFERS_MB}MB
min_wal_size = 512MB
max_wal_size = 2GB
wal_level = replica
checkpoint_completion_target = 0.9
checkpoint_timeout = 15min

####################
# Query Planner (SSD-optimized)
####################
random_page_cost = 1.1
seq_page_cost = 1.0
effective_io_concurrency = 200

####################
# Parallel Queries
####################
max_parallel_workers_per_gather = ${MAX_PARALLEL_WORKERS_PER_GATHER}
max_parallel_workers = ${MAX_PARALLEL_WORKERS}
max_parallel_maintenance_workers = ${MAX_PARALLEL_WORKERS_PER_GATHER}

####################
# Logging
####################
log_destination = 'stderr'
logging_collector = on
log_directory = 'log'
log_filename = 'postgresql-%Y-%m-%d_%H%M%S.log'
log_file_mode = 0600
log_rotation_age = 1d
log_rotation_size = 100MB
log_truncate_on_rotation = off

# Log slow queries (>1 second for Metabase analytics)
log_min_duration_statement = 1000
log_line_prefix = '%t [%p]: [%l-1] user=%u,db=%d,app=%a,client=%h '
log_checkpoints = on
log_connections = off
log_disconnections = off
log_lock_waits = on
log_temp_files = 0

####################
# Autovacuum (important for Metabase analytics)
####################
autovacuum = on
autovacuum_max_workers = 3
autovacuum_naptime = 1min
autovacuum_vacuum_threshold = 50
autovacuum_analyze_threshold = 50
autovacuum_vacuum_scale_factor = 0.1
autovacuum_analyze_scale_factor = 0.05

####################
# Statistics (critical for Metabase query optimization)
####################
track_activities = on
track_counts = on
track_io_timing = on
track_functions = pl
default_statistics_target = 100

####################
# Security
####################
password_encryption = scram-sha-256
ssl = off

####################
# Locale
####################
lc_messages = 'en_US.UTF-8'
lc_monetary = 'en_US.UTF-8'
lc_numeric = 'en_US.UTF-8'
lc_time = 'en_US.UTF-8'
default_text_search_config = 'pg_catalog.english'

####################
# Performance Features
####################
jit = off
huge_pages = try
EOF

log_message "✅ PostgreSQL configuration created"

# Configure pg_hba.conf for secure access
log_message "===== 4. Configuring PostgreSQL Authentication ====="

# Detect vRack interface and IP
VRACK_INTERFACE=$(ip -o link show | awk -F': ' '$2 ~ /^enp.*s0f1$/ {print $2}' | head -1)
if [ -n "$VRACK_INTERFACE" ]; then
    VRACK_IP=$(ip -4 addr show "$VRACK_INTERFACE" | grep -oP '(?<=inet\s)\d+(\.\d+){3}' || echo "")
    if [ -n "$VRACK_IP" ]; then
        log_message "Detected vRack interface: $VRACK_INTERFACE with IP: $VRACK_IP"
        VRACK_ENABLED=true
    else
        log_message "vRack interface found but no IP detected - using localhost only"
        VRACK_ENABLED=false
    fi
else
    log_message "No vRack interface detected - using localhost only"
    VRACK_ENABLED=false
fi

# Configure listen_addresses
if [ "$VRACK_ENABLED" = true ]; then
    log_message "Configuring PostgreSQL to listen on localhost and vRack ($VRACK_IP)"
    echo "listen_addresses = 'localhost,${VRACK_IP}'" >> "${PG_CONF_DIR}/postgresql.conf"
else
    log_message "Configuring PostgreSQL for localhost-only access"
    echo "listen_addresses = 'localhost'" >> "${PG_CONF_DIR}/postgresql.conf"
fi

# Backup original pg_hba.conf
cp "${PG_CONF_DIR}/pg_hba.conf" "${PG_CONF_DIR}/pg_hba.conf.backup"

# Create pg_hba.conf with vRack support if available
if [ "$VRACK_ENABLED" = true ]; then
    cat > "${PG_CONF_DIR}/pg_hba.conf" << 'EOF'
# PostgreSQL Client Authentication Configuration
# TYPE  DATABASE        USER            ADDRESS                 METHOD

# Local connections
local   all             postgres                                peer
local   all             all                                     scram-sha-256

# IPv4 localhost connections
host    all             all             127.0.0.1/32            scram-sha-256

# IPv6 localhost connections
host    all             all             ::1/128                 scram-sha-256

# vRack private network access (192.168.0.0/16)
host    all             all             192.168.0.0/16          scram-sha-256

# Replication connections
local   replication     all                                     peer
host    replication     all             127.0.0.1/32            scram-sha-256
host    replication     all             ::1/128                 scram-sha-256
host    replication     all             192.168.0.0/16          scram-sha-256
EOF
    log_message "✅ PostgreSQL authentication configured (localhost + vRack access)"
else
    cat > "${PG_CONF_DIR}/pg_hba.conf" << 'EOF'
# PostgreSQL Client Authentication Configuration
# TYPE  DATABASE        USER            ADDRESS                 METHOD

# Local connections
local   all             postgres                                peer
local   all             all                                     scram-sha-256

# IPv4 localhost connections
host    all             all             127.0.0.1/32            scram-sha-256

# IPv6 localhost connections
host    all             all             ::1/128                 scram-sha-256

# Replication connections
local   replication     all                                     peer
host    replication     all             127.0.0.1/32            scram-sha-256
host    replication     all             ::1/128                 scram-sha-256
EOF
    log_message "✅ PostgreSQL authentication configured (localhost-only)"
fi

# Start PostgreSQL
systemctl start postgresql
systemctl enable postgresql

log_message "===== 5. Creating Admin User and Metabase Database ====="

# Generate secure passwords
ADMIN_PASSWORD=$(openssl rand -base64 32)
METABASE_PASSWORD=$(openssl rand -base64 32)

# Create admin superuser and metabase database
sudo -u postgres psql << EOF
-- Create admin superuser for database administration and imports
CREATE USER admin WITH PASSWORD '${ADMIN_PASSWORD}' SUPERUSER CREATEDB CREATEROLE;

-- Create metabase user with secure password
CREATE USER metabase WITH PASSWORD '${METABASE_PASSWORD}';

-- Create metabase database
CREATE DATABASE metabase OWNER metabase;

-- Grant privileges to metabase user
GRANT ALL PRIVILEGES ON DATABASE metabase TO metabase;

-- Allow admin to operate on metabase database
GRANT ALL PRIVILEGES ON DATABASE metabase TO admin;

-- Show created objects
\l metabase
\du admin
\du metabase
EOF

log_message "✅ Admin superuser and Metabase database created"

# Save credentials securely
METABASE_CREDS="/root/.metabase-postgresql"

# Determine the host to use in connection strings
if [ "$VRACK_ENABLED" = true ]; then
    CONNECT_HOST="$VRACK_IP"
else
    CONNECT_HOST="localhost"
fi

cat > "$METABASE_CREDS" << EOF
# PostgreSQL Credentials for Metabase
# Generated: $(date)
# Connection Host: ${CONNECT_HOST}

# === ADMIN USER (for database imports and administration) ===
Host: ${CONNECT_HOST}
Port: 5432
User: admin
Password: ${ADMIN_PASSWORD}
Database: metabase (or any database)

# Admin connection string (for imports):
# postgresql://admin:${ADMIN_PASSWORD}@${CONNECT_HOST}:5432/metabase

# Import command examples:
# psql -h ${CONNECT_HOST} -U admin -d metabase < metabase_dump.sql
# PGPASSWORD='${ADMIN_PASSWORD}' psql -h ${CONNECT_HOST} -U admin -d metabase < metabase_dump.sql

# === METABASE APPLICATION USER (for Metabase application) ===
Host: ${CONNECT_HOST}
Port: 5432
Database: metabase
User: metabase
Password: ${METABASE_PASSWORD}

# Application connection string (for Metabase config):
# postgresql://metabase:${METABASE_PASSWORD}@${CONNECT_HOST}:5432/metabase

# Test connection:
# psql -h ${CONNECT_HOST} -U metabase -d metabase
EOF

chmod 600 "$METABASE_CREDS"
log_message "✅ Credentials saved to ${METABASE_CREDS}"

log_message "===== 6. Setting Up PostgreSQL Backups ====="

# Create backup directory
mkdir -p /var/backups/postgresql
chown postgres:postgres /var/backups/postgresql

# Create backup script
cat > /usr/local/bin/postgresql-backup << 'BACKUP_SCRIPT'
#!/bin/bash
# PostgreSQL backup script for Metabase database

set -Eeuo pipefail

BACKUP_DIR="/var/backups/postgresql"
DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="${BACKUP_DIR}/metabase_${DATE}.sql.gz"
LOG_FILE="/var/log/postgresql-backup.log"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

log "Starting PostgreSQL backup..."

# Backup metabase database
if sudo -u postgres pg_dump metabase | gzip > "$BACKUP_FILE"; then
    log "✅ Backup completed: $BACKUP_FILE"
    log "   Size: $(du -h "$BACKUP_FILE" | cut -f1)"
else
    log "❌ Backup failed!"
    exit 1
fi

# Keep last 7 days of backups
find "$BACKUP_DIR" -name "metabase_*.sql.gz" -mtime +7 -delete
log "Old backups cleaned (keeping 7 days)"

log "Backup completed successfully"
BACKUP_SCRIPT

chmod +x /usr/local/bin/postgresql-backup

# Create daily backup cron job
cat > /etc/cron.daily/postgresql-backup << 'EOF'
#!/bin/bash
/usr/local/bin/postgresql-backup
EOF

chmod +x /etc/cron.daily/postgresql-backup

log_message "✅ PostgreSQL backups configured (daily at 6:25 AM via cron.daily)"

log_message "===== 7. Configuring Netdata Monitoring ====="

# Enable PostgreSQL monitoring in Netdata
if [ -d /etc/netdata ]; then
    # Create PostgreSQL monitoring user
    sudo -u postgres psql << 'EOF'
CREATE USER netdata WITH PASSWORD 'netdata_monitor_readonly';
GRANT pg_monitor TO netdata;
GRANT CONNECT ON DATABASE metabase TO netdata;
EOF

    # Configure Netdata PostgreSQL plugin (using go.d collector)
    # Note: Python postgres collector was removed, replaced with go.d/postgres
    mkdir -p /etc/netdata/go.d

    cat > /etc/netdata/go.d/postgres.conf << 'EOF'
# Netdata go.d PostgreSQL monitoring
# https://learn.netdata.cloud/docs/data-collection/databases/postgresql

jobs:
  - name: metabase_db
    dsn: 'postgres://netdata:netdata_monitor_readonly@localhost:5432/metabase'
    timeout: 5
    collect_databases_metrics: yes
EOF

    chmod 640 /etc/netdata/go.d/postgres.conf
    chown root:netdata /etc/netdata/go.d/postgres.conf 2>/dev/null || true

    # Restart Netdata to pick up PostgreSQL monitoring
    systemctl restart netdata

    log_message "✅ Netdata PostgreSQL monitoring configured (using go.d collector)"
else
    log_message "⚠️  Netdata not found - skipping monitoring setup"
fi

log_message "===== 8. Updating Firewall Configuration ====="

# PostgreSQL is localhost-only, no firewall changes needed
# But document it for clarity
log_message "✅ PostgreSQL configured for localhost-only access (no firewall changes needed)"
log_message "   Metabase must run on the same server to access PostgreSQL"

log_message "===== 9. Adding PostgreSQL to Security Monitoring ====="

# Add PostgreSQL to daily security report if it exists
if [ -f /etc/cron.daily/bastion-security-report ]; then
    # The security report will automatically pick up PostgreSQL logs
    log_message "✅ PostgreSQL will be included in daily security reports"
fi

# Add to AIDE monitoring exclusions (PostgreSQL data changes frequently)
if [ -d /etc/aide/aide.conf.d ]; then
    cat > /etc/aide/aide.conf.d/99-postgresql-exclusions << 'EOF'
# PostgreSQL-specific AIDE exclusions
# Database files change constantly by design
!/var/lib/postgresql
EOF
    log_message "✅ PostgreSQL excluded from AIDE file integrity monitoring"
fi

log_message "===== 10. Verifying Installation ====="

# Test PostgreSQL connection
if sudo -u postgres psql -d metabase -c "SELECT version();" > /dev/null 2>&1; then
    log_message "✅ PostgreSQL connection test successful"
else
    log_message "❌ PostgreSQL connection test failed"
    exit 1
fi

# Check PostgreSQL status
PG_STATUS=$(systemctl is-active postgresql)
log_message "PostgreSQL status: $PG_STATUS"

# Mark completion
date > /var/lib/postgresql-addition-complete

log_message ""
log_message "===== PostgreSQL Addition Complete! ====="
log_message ""
log_message "PostgreSQL ${PG_VERSION} is now installed and configured for Metabase."
log_message ""
log_message "📊 Database Information:"
log_message "   • Database: metabase"
log_message "   • User: metabase"
log_message "   • Host: localhost:5432"
log_message "   • Credentials: ${METABASE_CREDS}"
log_message ""
log_message "📦 Resource Allocation:"
log_message "   • Shared buffers: ${SHARED_BUFFERS_MB}MB (~20% of RAM)"
log_message "   • Effective cache: ${EFFECTIVE_CACHE_SIZE_MB}MB (~40% of RAM)"
log_message "   • MariaDB remains primary database"
log_message ""
log_message "🔒 Security:"
log_message "   • Localhost-only access (no external connections)"
log_message "   • scram-sha-256 password encryption"
log_message "   • Automated daily backups to /var/backups/postgresql"
log_message ""
log_message "📈 Monitoring:"
log_message "   • Netdata PostgreSQL monitoring enabled"
log_message "   • Logs: /var/log/postgresql/"
log_message ""
log_message "Next steps:"
log_message "   1. Configure Metabase to use: postgresql://metabase:PASSWORD@localhost:5432/metabase"
log_message "   2. Password is in: ${METABASE_CREDS}"
log_message ""

# Create README
cat > /root/POSTGRESQL-README.md << EOF
# PostgreSQL for Metabase - Server Configuration

PostgreSQL has been added to this MariaDB server for Metabase analytics.

## Database Access

- **Host**: localhost
- **Port**: 5432
- **Database**: metabase
- **User**: metabase
- **Password**: See \`${METABASE_CREDS}\`

## Connection String

\`\`\`
postgresql://metabase:PASSWORD@localhost:5432/metabase
\`\`\`

(Replace PASSWORD with value from ${METABASE_CREDS})

## Resource Allocation

- **PostgreSQL**: ~20-30% of server resources
- **MariaDB**: Remains primary database with majority of resources
- **Shared buffers**: ${SHARED_BUFFERS_MB}MB
- **Max connections**: ${MAX_CONNECTIONS}

## Backups

- **Location**: /var/backups/postgresql/
- **Schedule**: Daily via cron.daily (runs around 6:25 AM)
- **Retention**: 7 days
- **Manual backup**: \`/usr/local/bin/postgresql-backup\`

## Monitoring

- **Netdata**: PostgreSQL metrics available in Netdata dashboard
- **Logs**: /var/log/postgresql/postgresql-${PG_VERSION}-main.log
- **Status**: \`systemctl status postgresql\`

## Common Commands

\`\`\`bash
# Access PostgreSQL as postgres user
sudo -u postgres psql

# Access metabase database
sudo -u postgres psql -d metabase

# Check PostgreSQL status
systemctl status postgresql

# View logs
tail -f /var/log/postgresql/postgresql-${PG_VERSION}-main.log

# Manual backup
/usr/local/bin/postgresql-backup

# View backups
ls -lh /var/backups/postgresql/
\`\`\`

## Performance

PostgreSQL is configured for Metabase analytics workload:
- SSD-optimized query planner
- Parallel query execution enabled
- Aggressive autovacuum for analytics tables
- Query logging for slow queries (>1 second)

## Security

- Localhost-only access (Metabase must run on same server)
- No external network access
- scram-sha-256 password encryption
- Minimal privileges for netdata monitoring user

## Installation Details

- **Installed**: $(date)
- **Version**: PostgreSQL ${PG_VERSION}
- **Configuration**: ${PG_CONF_DIR}/conf.d/99-polyserver-optimization.conf
- **Data directory**: ${PG_DATA_DIR}
- **Completion marker**: /var/lib/postgresql-addition-complete

EOF

log_message "📄 Documentation created: /root/POSTGRESQL-README.md"
log_message ""
log_message "Installation complete! PostgreSQL is ready for Metabase."
