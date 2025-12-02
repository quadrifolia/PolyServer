#!/bin/bash
# mariadb-2-enable-vrack.sh - Phase 2: Switch MariaDB to vRack private network
# Run AFTER mariadb-1-convert.sh to transition to private network-only access
#
# Prerequisites:
# - mariadb-1-convert.sh completed successfully
# - vRack network configured on the server
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

readonly SCRIPT_NAME="mariadb-vrack-enable"
readonly LOG_FILE="/var/log/${SCRIPT_NAME}.log"

# Logging function
log_message() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

log_message "===== Starting MariaDB vRack Network Transition ====="
log_message ""

# Verify MariaDB conversion was completed
if [ ! -f /var/lib/mariadb-conversion-complete ]; then
    echo "❌ ERROR: MariaDB conversion not detected"
    echo "   Please run mariadb-1-convert.sh first"
    exit 1
fi

log_message "✅ MariaDB conversion detected - proceeding with vRack transition"

echo ""
echo "===== MariaDB vRack Network Transition ====="
echo ""
echo "⚠️  WARNING: This script will switch your MariaDB server to private network only!"
echo ""
echo "Before proceeding, ensure you have:"
echo "  1. ✅ Console/KVM access to the server (in case of network issues)"
echo "  2. ✅ vRack network physically connected to this server"
echo "  3. ✅ Network details ready (interface, IP, prefix, gateway)"
echo "  4. ✅ Tested connectivity from application servers to the future private IP"
echo ""
echo "Changes that will be made:"
echo "  1. Configure network interface for vRack"
echo "  2. Update MariaDB bind-address to vRack IP"
echo "  3. Restrict SSH to vRack network only"
echo "  4. Apply network configuration"
echo "  5. Verify connectivity"
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
# Generated by mariadb-2-enable-vrack.sh on $(date)
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

log_message "===== 3. Updating MariaDB Configuration ====="

# Update MariaDB to bind to vRack IP only
MARIADB_CONF="/etc/mysql/mariadb.conf.d/60-performance.cnf"

if [ -f "$MARIADB_CONF" ]; then
    # Backup current config
    cp "$MARIADB_CONF" "${MARIADB_CONF}.backup-$(date +%Y%m%d-%H%M%S)"

    # Update bind-address
    sed -i "s/^bind-address = .*/bind-address = $VRACK_IP_ADDRESS/" "$MARIADB_CONF"

    log_message "✅ Updated MariaDB bind-address to $VRACK_IP_ADDRESS"

    # Restart MariaDB to apply changes
    systemctl restart mariadb
    log_message "✅ MariaDB restarted with new bind address"
else
    log_message "⚠️  MariaDB config not found at expected location"
fi

log_message "===== 4. Updating Firewall Rules ====="

# Add SSH access from vRack network (before restricting)
ufw allow from "$VRACK_NETWORK" to any port 2222 proto tcp comment "SSH from vRack network"

# Get current SSH port from sshd_config
SSH_PORT=$(grep -E "^Port " /etc/ssh/sshd_config | awk '{print $2}' || echo "2222")

log_message "✅ Added firewall rule for SSH from vRack network"

# Ensure essential outgoing ports are allowed (should already exist from convert script)
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
        # These must be added BEFORE the deny rule so they take precedence
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
echo "  • MySQL will only listen on $VRACK_IP_ADDRESS"
echo "  • Network connectivity may be interrupted briefly"
echo ""
read -p "Apply network configuration? (yes/no): " -r
if [[ ! "$REPLY" =~ ^[Yy]es$ ]]; then
    echo "Configuration cancelled."
    echo "Network config prepared at: $NETPLAN_VRACK"
    echo "MariaDB already configured for: $VRACK_IP_ADDRESS"
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

# Check if MariaDB is running and listening
if systemctl is-active --quiet mariadb; then
    echo "✅ MariaDB service is running"
    log_message "✅ MariaDB service active"

    # Check if MariaDB is listening on the vRack IP
    if ss -tlnp | grep -q ":3306.*$VRACK_IP_ADDRESS"; then
        echo "✅ MariaDB listening on $VRACK_IP_ADDRESS:3306"
        log_message "✅ MariaDB listening on vRack IP"
    else
        echo "⚠️  MariaDB may not be listening on vRack IP"
        log_message "⚠️  MariaDB listening verification inconclusive"
    fi
else
    echo "❌ ERROR: MariaDB service is not running"
    log_message "❌ MariaDB service not active"
fi

# Test MySQL connectivity
if mysql -e "SELECT 1;" >/dev/null 2>&1; then
    echo "✅ MySQL connectivity test passed"
    log_message "✅ MySQL connectivity verified"
else
    echo "⚠️  MySQL connectivity test failed"
    log_message "⚠️  MySQL connectivity test failed"
fi

log_message "===== 7. Updating Documentation ====="

# Update the README with vRack information
cat >> /root/MARIADB-SERVER-README.md << EOF

## vRack Network Configuration (Phase 2)
- **Enabled:** $(date)
- **Interface:** $VRACK_INTERFACE
- **IP Address:** $VRACK_IP_ADDRESS/$VRACK_PREFIX
- **Gateway:** ${VRACK_GATEWAY:-none}
- **Network:** $VRACK_NETWORK

### Network Status
- MariaDB bind-address: $VRACK_IP_ADDRESS
- MySQL port 3306: Listening on $VRACK_IP_ADDRESS only
- SSH access: ${REPLY}
- Firewall: Allows vRack network only

### Connecting from Application Servers
\`\`\`bash
# Test MySQL connectivity from application server
mysql -h $VRACK_IP_ADDRESS -u your_user -p

# Example connection string
mysql://user:password@$VRACK_IP_ADDRESS:3306/database_name
\`\`\`

### Troubleshooting
If you cannot connect:
1. Verify network connectivity: ping $VRACK_IP_ADDRESS
2. Check firewall rules: sudo ufw status
3. Verify MariaDB is listening: sudo ss -tlnp | grep 3306
4. Check MariaDB logs: tail -f /var/log/mysql/error.log
5. Test from MySQL client: mysql -h $VRACK_IP_ADDRESS -u root -p

### Reverting to Public Access (Emergency)
If you need to revert (requires console access):
\`\`\`bash
# Edit MariaDB config
sudo nano /etc/mysql/mariadb.conf.d/60-performance.cnf
# Change: bind-address = 0.0.0.0

# Restart MariaDB
sudo systemctl restart mariadb

# Allow public SSH temporarily
sudo ufw allow $SSH_PORT/tcp
\`\`\`
EOF

log_message "✅ Documentation updated with vRack configuration"

# Create verification script
cat > /usr/local/bin/mariadb-vrack-status << EOF
#!/bin/bash
# MariaDB vRack Network Status Check

echo "===== MariaDB vRack Network Status ====="
echo "Timestamp: \$(date)"
echo ""

echo "=== Network Configuration ==="
echo "Interface: $VRACK_INTERFACE"
echo -n "Status: "
if ip link show "$VRACK_INTERFACE" | grep -q "state UP"; then
    echo "✅ UP"
else
    echo "❌ DOWN"
fi

echo "IP Address: $VRACK_IP_ADDRESS/$VRACK_PREFIX"
echo -n "Configured: "
if ip addr show "$VRACK_INTERFACE" | grep -q "$VRACK_IP_ADDRESS"; then
    echo "✅ YES"
else
    echo "❌ NO"
fi

echo ""
echo "=== MariaDB Status ==="
echo -n "Service: "
if systemctl is-active --quiet mariadb; then
    echo "✅ RUNNING"
else
    echo "❌ STOPPED"
fi

echo -n "Listening on vRack IP: "
if ss -tlnp | grep -q ":3306.*$VRACK_IP_ADDRESS"; then
    echo "✅ YES"
else
    echo "❌ NO"
fi

echo ""
echo "=== Connectivity Test ==="
echo -n "MySQL local connection: "
if mysql -e "SELECT 1;" >/dev/null 2>&1; then
    echo "✅ OK"
else
    echo "❌ FAILED"
fi

echo ""
echo "=== Firewall Rules ==="
echo "MySQL (3306):"
ufw status | grep 3306 | head -5

echo ""
echo "SSH ($SSH_PORT):"
ufw status | grep "$SSH_PORT" | head -5

echo ""
echo "=== Network Statistics ==="
ip -s link show "$VRACK_INTERFACE" | head -10
EOF

chmod +x /usr/local/bin/mariadb-vrack-status

log_message "✅ Created status check script: /usr/local/bin/mariadb-vrack-status"

echo ""
echo "===== vRack Network Transition Complete ====="
echo ""
echo "✅ Network configured"
echo "   • Interface: $VRACK_INTERFACE"
echo "   • IP: $VRACK_IP_ADDRESS/$VRACK_PREFIX"
echo "   • Network: $VRACK_NETWORK"
echo ""
echo "✅ MariaDB configured"
echo "   • Listening on: $VRACK_IP_ADDRESS:3306"
echo "   • Accessible from: vRack network only"
echo ""
echo "✅ Monitoring"
echo "   • Status check: sudo /usr/local/bin/mariadb-vrack-status"
echo "   • Network stats: ip -s link show $VRACK_INTERFACE"
echo ""
echo "📖 Documentation: /root/MARIADB-SERVER-README.md"
echo ""
echo "🔍 Next Steps:"
echo "   1. Test connectivity from application servers"
echo "   2. Run: sudo /usr/local/bin/mariadb-vrack-status"
echo "   3. Create application databases and users"
echo "   4. Update application connection strings to use $VRACK_IP_ADDRESS"
echo "   5. If SSH still public, test vRack SSH then: ufw delete allow $SSH_PORT"
echo "   6. Remove public IP from OVH control panel (optional)"
echo ""
echo "⚠️  Important: Test all connectivity before removing console access!"
echo ""
echo "Transition completed at: $(date)"
echo ""

# Mark vRack transition complete
cat > /var/lib/mariadb-vrack-complete << EOF
vRack network transition completed
Date: $(date)
Interface: $VRACK_INTERFACE
IP Address: $VRACK_IP_ADDRESS/$VRACK_PREFIX
Network: $VRACK_NETWORK
Gateway: ${VRACK_GATEWAY:-none}
EOF

log_message "vRack transition completed successfully"
