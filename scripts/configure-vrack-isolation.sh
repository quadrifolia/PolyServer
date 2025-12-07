#!/bin/bash
# configure-vrack-isolation.sh - Configure OVH vRack private network isolation
# This script configures a server to use OVH vRack private networking
#
# Run AFTER server-setup.sh to transition services to private network
#
# Prerequisites:
# - server-setup.sh completed successfully
# - vRack network physically connected to this server
# - Run as root
# - IMPORTANT: Have console/KVM access before running in case of network issues

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

readonly SCRIPT_NAME="vrack-isolation"
readonly LOG_FILE="/var/log/${SCRIPT_NAME}.log"

# Logging function
log_message() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

log_message "===== Starting vRack Network Isolation Configuration ====="
log_message ""

echo ""
echo "===== vRack Network Isolation Setup ====="
echo ""
echo "⚠️  WARNING: This script will configure your server for private network only!"
echo ""
echo "Before proceeding, ensure you have:"
echo "  1. ✅ Console/KVM access to the server (in case of network issues)"
echo "  2. ✅ vRack network physically connected to this server"
echo "  3. ✅ Network details ready (interface, IP, prefix, gateway)"
echo "  4. ✅ Tested connectivity from other servers to the future private IP"
echo ""
echo "Changes that will be made:"
echo "  1. Configure network interface for vRack"
echo "  2. Update service configurations to bind to vRack IP (if applicable)"
echo "  3. Configure firewall for private network access"
echo "  4. Optionally restrict SSH to vRack network only"
echo "  5. Apply network configuration"
echo ""
read -p "⚠️  Do you have console access and are ready to proceed? (yes/no): " -r
if [[ ! "$REPLY" =~ ^[Yy]es$ ]]; then
    echo "Setup cancelled. Get console access before proceeding."
    exit 0
fi

echo ""
log_message "===== 1. Gathering vRack Network Configuration ====="

# Get network configuration from user
echo ""
echo "Please provide your vRack network configuration:"
echo ""

# Network interface
echo "Available network interfaces:"
ip -brief link show | grep -v "lo" | awk '{print "  • " $1 " (" $2 ")"}'
echo ""
read -p "vRack network interface name (e.g., eno2, ens4, eth1): " VRACK_INTERFACE
VRACK_INTERFACE=$(echo "$VRACK_INTERFACE" | xargs)  # Trim whitespace

# Validate interface exists
if ! ip link show "$VRACK_INTERFACE" >/dev/null 2>&1; then
    echo "❌ ERROR: Network interface '$VRACK_INTERFACE' not found"
    exit 1
fi

log_message "Selected interface: $VRACK_INTERFACE"

# IP address
echo ""
read -p "vRack IP address for this server (e.g., 10.0.1.10): " VRACK_IP_ADDRESS
VRACK_IP_ADDRESS=$(echo "$VRACK_IP_ADDRESS" | xargs)

# Validate IP format
if ! [[ "$VRACK_IP_ADDRESS" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "❌ ERROR: Invalid IP address format"
    exit 1
fi

log_message "IP address: $VRACK_IP_ADDRESS"

# Network prefix
echo ""
read -p "Network prefix/CIDR (e.g., 24 for /24): " VRACK_PREFIX
VRACK_PREFIX=$(echo "$VRACK_PREFIX" | xargs)

# Validate prefix
if ! [[ "$VRACK_PREFIX" =~ ^[0-9]+$ ]] || [ "$VRACK_PREFIX" -lt 8 ] || [ "$VRACK_PREFIX" -gt 32 ]; then
    echo "❌ ERROR: Invalid network prefix (must be 8-32)"
    exit 1
fi

log_message "Network prefix: /$VRACK_PREFIX"

# Gateway (optional)
echo ""
read -p "Gateway IP (optional, press Enter to skip): " VRACK_GATEWAY
VRACK_GATEWAY=$(echo "$VRACK_GATEWAY" | xargs)

if [ -n "$VRACK_GATEWAY" ]; then
    # Validate gateway format if provided
    if ! [[ "$VRACK_GATEWAY" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        echo "❌ ERROR: Invalid gateway IP address format"
        exit 1
    fi
    log_message "Gateway: $VRACK_GATEWAY"
else
    log_message "Gateway: none (layer 2 only)"
fi

# Calculate network address for firewall rules
IFS='.' read -r i1 i2 i3 i4 <<< "$VRACK_IP_ADDRESS"
NETWORK_BITS=$((32 - VRACK_PREFIX))
MASK=$((0xFFFFFFFF << NETWORK_BITS & 0xFFFFFFFF))
NETWORK_ADDRESS="$((i1 & (MASK >> 24))).$((i2 & (MASK >> 16 & 0xFF))).$((i3 & (MASK >> 8 & 0xFF))).$((i4 & (MASK & 0xFF)))"
VRACK_NETWORK="${NETWORK_ADDRESS}/${VRACK_PREFIX}"

log_message "Calculated network: $VRACK_NETWORK"

echo ""
echo "===== Configuration Summary ====="
echo "Interface: $VRACK_INTERFACE"
echo "IP Address: $VRACK_IP_ADDRESS/$VRACK_PREFIX"
echo "Gateway: ${VRACK_GATEWAY:-none}"
echo "Network: $VRACK_NETWORK"
echo ""
read -p "Is this configuration correct? (yes/no): " -r
if [[ ! "$REPLY" =~ ^[Yy]es$ ]]; then
    echo "Configuration cancelled. Please run the script again."
    exit 0
fi

log_message "===== 2. Creating Network Configuration ====="

# Backup existing netplan configuration
NETPLAN_FILE="/etc/netplan/50-cloud-init.yaml"
if [ -f "$NETPLAN_FILE" ]; then
    cp "$NETPLAN_FILE" "${NETPLAN_FILE}.backup-$(date +%Y%m%d-%H%M%S)"
    log_message "✅ Backed up existing netplan configuration"
fi

# Create netplan configuration for vRack
NETPLAN_VRACK="/etc/netplan/60-vrack.yaml"

cat > "$NETPLAN_VRACK" << EOF
# vRack Private Network Configuration
# Generated by configure-vrack-isolation.sh on $(date)
# Interface: $VRACK_INTERFACE
# Network: $VRACK_NETWORK

network:
  version: 2
  ethernets:
    $VRACK_INTERFACE:
      dhcp4: false
      addresses:
        - $VRACK_IP_ADDRESS/$VRACK_PREFIX
EOF

# Add gateway if provided
if [ -n "$VRACK_GATEWAY" ]; then
    cat >> "$NETPLAN_VRACK" << EOF
      gateway4: $VRACK_GATEWAY
EOF
fi

# Add DNS servers (use Google and Cloudflare for reliability)
cat >> "$NETPLAN_VRACK" << EOF
      nameservers:
        addresses:
          - 8.8.8.8
          - 1.1.1.1
EOF

log_message "✅ Created netplan configuration: $NETPLAN_VRACK"

log_message "===== 3. Updating Service Configurations (if applicable) ====="

# Detect and update MariaDB if installed
if systemctl is-active --quiet mariadb 2>/dev/null; then
    echo "MariaDB detected - updating bind-address to $VRACK_IP_ADDRESS"

    MARIADB_CONF="/etc/mysql/mariadb.conf.d/60-performance.cnf"
    if [ -f "$MARIADB_CONF" ]; then
        cp "$MARIADB_CONF" "${MARIADB_CONF}.backup-$(date +%Y%m%d-%H%M%S)"
        sed -i "s/^bind-address = .*/bind-address = $VRACK_IP_ADDRESS/" "$MARIADB_CONF"
        log_message "✅ Updated MariaDB bind-address to $VRACK_IP_ADDRESS"

        # Update Netdata MySQL monitoring to use Unix socket (since MariaDB bound to vRack IP)
        if [ -d /etc/netdata/go.d ]; then
            cat > /etc/netdata/go.d/mysql.conf << 'NETDATA_MYSQL_EOF'
jobs:
  - name: local
    dsn: 'netdata@unix(/var/run/mysqld/mysqld.sock)/'
    update_every: 1
NETDATA_MYSQL_EOF
            systemctl restart netdata 2>/dev/null || true
            log_message "✅ Updated Netdata MySQL monitoring to use Unix socket"
        fi

        systemctl restart mariadb
        log_message "✅ MariaDB restarted with vRack bind address"
    fi
fi

# Detect and update PostgreSQL if installed
if systemctl is-active --quiet postgresql 2>/dev/null; then
    echo "PostgreSQL detected - updating listen_addresses to localhost,$VRACK_IP_ADDRESS"

    PG_VERSION=$(psql --version | awk '{print $3}' | cut -d. -f1 2>/dev/null || echo "15")
    PG_CONF="/etc/postgresql/${PG_VERSION}/main/postgresql.conf"

    if [ -f "$PG_CONF" ]; then
        cp "$PG_CONF" "${PG_CONF}.backup-$(date +%Y%m%d-%H%M%S)"

        # Update or add listen_addresses
        if grep -q "^listen_addresses" "$PG_CONF"; then
            sed -i "s/^listen_addresses.*/listen_addresses = 'localhost,${VRACK_IP_ADDRESS}'/" "$PG_CONF"
        else
            echo "listen_addresses = 'localhost,${VRACK_IP_ADDRESS}'" >> "$PG_CONF"
        fi

        log_message "✅ Updated PostgreSQL listen_addresses to localhost,$VRACK_IP_ADDRESS"

        # Update pg_hba.conf to allow vRack network
        PG_HBA="/etc/postgresql/${PG_VERSION}/main/pg_hba.conf"
        if ! grep -q "$VRACK_NETWORK" "$PG_HBA"; then
            cp "$PG_HBA" "${PG_HBA}.backup-$(date +%Y%m%d-%H%M%S)"
            echo "# vRack private network access" >> "$PG_HBA"
            echo "host    all             all             ${VRACK_NETWORK}          scram-sha-256" >> "$PG_HBA"
            log_message "✅ Updated PostgreSQL pg_hba.conf for vRack network"
        fi

        systemctl restart postgresql
        log_message "✅ PostgreSQL restarted with vRack configuration"
    fi
fi

log_message "===== 4. Updating Firewall Configuration ====="

# Add SSH access from vRack network (before restricting)
SSH_PORT=$(grep -E "^Port " /etc/ssh/sshd_config | awk '{print $2}' || echo "2222")
ufw allow from "$VRACK_NETWORK" to any port "$SSH_PORT" proto tcp comment "SSH from vRack network"

log_message "✅ Added firewall rule for SSH from vRack network"

# Ensure essential outgoing ports are allowed
log_message "Verifying essential outgoing firewall rules..."

# DNS (required for hostname resolution)
ufw allow out 53 comment 'DNS queries' 2>/dev/null || true
ufw allow out 53/udp comment 'DNS queries UDP' 2>/dev/null || true

# HTTP/HTTPS (required for package updates)
ufw allow out 80/tcp comment 'HTTP for updates' 2>/dev/null || true
ufw allow out 443/tcp comment 'HTTPS for updates' 2>/dev/null || true

# NTP (required for time synchronization)
ufw allow out 123/udp comment 'NTP time sync' 2>/dev/null || true

# SMTP (required for email notifications)
ufw allow out 25/tcp comment 'SMTP for email delivery' 2>/dev/null || true
ufw allow out 587/tcp comment 'SMTP submission' 2>/dev/null || true
ufw allow out 465/tcp comment 'SMTPS secure email' 2>/dev/null || true

log_message "✅ Essential outgoing ports verified"

# Optional: Configure interface-specific rules for total isolation
echo ""
echo "════════════════════════════════════════════════════════════"
echo "Optional: Complete Public Interface Isolation"
echo "════════════════════════════════════════════════════════════"
echo ""
echo "Would you like to completely block the public interface?"
echo "This will:"
echo "  • Allow ALL traffic on vRack interface ($VRACK_INTERFACE)"
echo "  • DENY ALL traffic on public interface (if detected)"
echo "  • Only allow specific outgoing ports (DNS, HTTP/S, NTP, SMTP)"
echo ""
echo "⚠️  Only choose 'yes' if you have console access!"
echo ""
read -p "Block public interface completely? (yes/no): " -r

if [[ "$REPLY" =~ ^[Yy]es$ ]]; then
    # Detect public interface (not vRack, not loopback)
    PUBLIC_INTERFACE=$(ip -o link show | awk -F': ' '{print $2}' | grep -v "^lo$" | grep -v "^$VRACK_INTERFACE$" | head -1)

    if [ -n "$PUBLIC_INTERFACE" ]; then
        log_message "Detected public interface: $PUBLIC_INTERFACE"
        echo "Detected public interface: $PUBLIC_INTERFACE"

        # Allow all traffic on vRack interface
        ufw allow in on "$VRACK_INTERFACE" comment "Allow all on vRack" 2>/dev/null || true
        ufw allow out on "$VRACK_INTERFACE" comment "Allow all on vRack" 2>/dev/null || true

        # Block incoming on public interface
        ufw deny in on "$PUBLIC_INTERFACE" comment "Block public interface incoming" 2>/dev/null || true

        # CRITICAL: Allow specific outgoing ports on public interface BEFORE blocking
        log_message "Adding specific port allows on public interface..."
        ufw allow out on "$PUBLIC_INTERFACE" to any port 25 proto tcp comment "SMTP on public" 2>/dev/null || true
        ufw allow out on "$PUBLIC_INTERFACE" to any port 587 proto tcp comment "SMTP submission on public" 2>/dev/null || true
        ufw allow out on "$PUBLIC_INTERFACE" to any port 465 proto tcp comment "SMTPS on public" 2>/dev/null || true
        ufw allow out on "$PUBLIC_INTERFACE" to any port 53 comment "DNS on public" 2>/dev/null || true
        ufw allow out on "$PUBLIC_INTERFACE" to any port 80 proto tcp comment "HTTP on public" 2>/dev/null || true
        ufw allow out on "$PUBLIC_INTERFACE" to any port 443 proto tcp comment "HTTPS on public" 2>/dev/null || true
        ufw allow out on "$PUBLIC_INTERFACE" to any port 123 proto udp comment "NTP on public" 2>/dev/null || true

        # Now block all other outgoing traffic on public interface
        ufw deny out on "$PUBLIC_INTERFACE" comment "Block public interface outgoing" 2>/dev/null || true

        log_message "✅ Public interface $PUBLIC_INTERFACE: incoming blocked, outgoing limited to essential ports"
        echo "✅ Public interface $PUBLIC_INTERFACE configuration:"
        echo "   • Incoming: BLOCKED"
        echo "   • Outgoing: Only SMTP, DNS, HTTP/S, NTP allowed"
        echo "✅ vRack interface $VRACK_INTERFACE allows all traffic"
    else
        echo "⚠️  Could not detect public interface - skipping"
        log_message "⚠️  Could not auto-detect public interface"
    fi
else
    echo "Skipping public interface blocking"
    log_message "Public interface blocking skipped (user choice)"
fi

log_message "✅ Firewall configuration complete"

echo ""
echo "⚠️  CRITICAL: SSH Configuration"
echo ""
echo "Current SSH port: $SSH_PORT"
echo ""
echo "After applying network configuration, you should:"
echo "  1. Test SSH connectivity from vRack network: ssh -p $SSH_PORT user@$VRACK_IP_ADDRESS"
echo "  2. If successful, restrict SSH to vRack only: ufw delete allow $SSH_PORT"
echo "  3. Remove public IP access from OVH control panel"
echo ""
echo "⚠️  DO NOT restrict SSH now if you don't have console access!"
echo ""
read -p "Do you want to restrict SSH to vRack network only NOW? (yes/no): " -r
if [[ "$REPLY" =~ ^[Yy]es$ ]]; then
    # Remove public SSH access
    ufw --force delete allow "$SSH_PORT/tcp" 2>/dev/null || true
    log_message "✅ SSH restricted to vRack network only"
    echo "✅ SSH access restricted to vRack network"
else
    echo "⚠️  SSH still accessible from public network"
    echo "   Manually restrict after testing: ufw delete allow $SSH_PORT"
    log_message "⚠️  SSH still accessible from public (user choice)"
fi

log_message "===== 5. Applying Network Configuration ====="

echo ""
echo "⚠️  FINAL WARNING: Applying network configuration now!"
echo ""
echo "After applying, the server will:"
echo "  • Configure $VRACK_INTERFACE with $VRACK_IP_ADDRESS"
echo "  • Services will listen on $VRACK_IP_ADDRESS (if configured)"
echo "  • Network connectivity may be interrupted briefly"
echo ""
read -p "Apply network configuration? (yes/no): " -r
if [[ ! "$REPLY" =~ ^[Yy]es$ ]]; then
    echo "Configuration cancelled."
    echo "Network config prepared at: $NETPLAN_VRACK"
    echo "Service configurations updated but not applied"
    echo "Apply manually with: netplan apply"
    exit 0
fi

# Apply netplan configuration
log_message "Applying netplan configuration..."
netplan apply

# Wait for network to stabilize
sleep 5

log_message "✅ Network configuration applied"

log_message "===== 6. Verifying Connectivity ====="

# Check if interface has the IP
if ip addr show "$VRACK_INTERFACE" | grep -q "$VRACK_IP_ADDRESS"; then
    echo "✅ Network interface configured correctly"
    log_message "✅ Interface $VRACK_INTERFACE has IP $VRACK_IP_ADDRESS"
else
    echo "⚠️  WARNING: Interface may not have the expected IP"
    log_message "⚠️  Interface verification failed"
fi

# Test network connectivity
if ping -c 1 -W 2 "$VRACK_IP_ADDRESS" >/dev/null 2>&1; then
    echo "✅ vRack IP is reachable"
    log_message "✅ vRack IP reachability confirmed"
else
    echo "⚠️  vRack IP ping test inconclusive"
    log_message "⚠️  vRack IP ping test failed (may be normal if ICMP blocked)"
fi

echo ""
echo "===== vRack Network Isolation Complete ====="
echo ""
echo "✅ Network configured"
echo "   • Interface: $VRACK_INTERFACE"
echo "   • IP: $VRACK_IP_ADDRESS/$VRACK_PREFIX"
echo "   • Network: $VRACK_NETWORK"
echo ""
echo "✅ Services updated (if detected)"
if systemctl is-active --quiet mariadb 2>/dev/null; then
    echo "   • MariaDB: Listening on $VRACK_IP_ADDRESS:3306"
fi
if systemctl is-active --quiet postgresql 2>/dev/null; then
    echo "   • PostgreSQL: Listening on localhost,$VRACK_IP_ADDRESS:5432"
fi
echo ""
echo "🔍 Next Steps:"
echo "   1. Test connectivity from other vRack servers"
echo "   2. Update application connection strings to use $VRACK_IP_ADDRESS"
echo "   3. If SSH still public, test vRack SSH then: ufw delete allow $SSH_PORT"
echo "   4. Remove public IP from OVH control panel (optional)"
echo ""
echo "⚠️  Important: Test all connectivity before removing console access!"
echo ""
echo "Configuration completed at: $(date)"
echo ""

# Mark vRack isolation complete
cat > /var/lib/vrack-isolation-complete << EOF
vRack network isolation completed
Date: $(date)
Interface: $VRACK_INTERFACE
IP Address: $VRACK_IP_ADDRESS/$VRACK_PREFIX
Network: $VRACK_NETWORK
Gateway: ${VRACK_GATEWAY:-none}
EOF

log_message "vRack isolation completed successfully"
