#!/bin/bash
# Configure UFW for vRack isolation
# This script isolates the server to only accept connections via private vRack network
# All outbound traffic on public interface is restricted to essential services only

set -e

echo "🔒 UFW vRack Isolation Configuration Tool"
echo "═══════════════════════════════════════════════════════════════"
echo ""

# Show available interfaces
echo "Available network interfaces:"
echo ""
ip -br addr show | grep -v "^lo" | while read iface state addr rest; do
    printf "  %-15s %s\n" "$iface" "$addr"
done
echo ""

# Ask for public interface
while true; do
    read -p "Enter PUBLIC interface name (e.g., enp97s0f0, eth0): " PUBLIC_INTERFACE
    if [ -z "$PUBLIC_INTERFACE" ]; then
        echo "❌ Interface name cannot be empty"
        continue
    fi
    if ! ip link show "$PUBLIC_INTERFACE" &>/dev/null; then
        echo "❌ Interface '$PUBLIC_INTERFACE' not found!"
        continue
    fi
    echo "✅ Public interface: $PUBLIC_INTERFACE"
    break
done

echo ""

# Ask for private interface
while true; do
    read -p "Enter PRIVATE interface name (e.g., enp97s0f1, eth1): " PRIVATE_INTERFACE
    if [ -z "$PRIVATE_INTERFACE" ]; then
        echo "❌ Interface name cannot be empty"
        continue
    fi
    if ! ip link show "$PRIVATE_INTERFACE" &>/dev/null; then
        echo "❌ Interface '$PRIVATE_INTERFACE' not found!"
        continue
    fi
    if [ "$PRIVATE_INTERFACE" = "$PUBLIC_INTERFACE" ]; then
        echo "❌ Private interface must be different from public interface!"
        continue
    fi
    echo "✅ Private interface: $PRIVATE_INTERFACE"
    break
done

echo ""

# Ask for SSH port
while true; do
    read -p "Enter SSH port [default: 2222]: " SSH_PORT
    SSH_PORT=${SSH_PORT:-2222}
    if ! [[ "$SSH_PORT" =~ ^[0-9]+$ ]] || [ "$SSH_PORT" -lt 1 ] || [ "$SSH_PORT" -gt 65535 ]; then
        echo "❌ Invalid port number. Must be between 1 and 65535."
        continue
    fi
    echo "✅ SSH port: $SSH_PORT"
    break
done

echo ""
echo "═══════════════════════════════════════════════════════════════"
echo "Configuration summary:"
echo "  Public interface:  $PUBLIC_INTERFACE (will be restricted)"
echo "  Private interface: $PRIVATE_INTERFACE (full access)"
echo "  SSH port:          $SSH_PORT"
echo "═══════════════════════════════════════════════════════════════"
echo ""

# Ask user if they want to keep SSH on public interface
read -p "Keep SSH ($SSH_PORT/tcp) accessible on public interface? [y/N] " -n 1 -r
echo
KEEP_PUBLIC_SSH=false
if [[ $REPLY =~ ^[Yy]$ ]]; then
    KEEP_PUBLIC_SSH=true
    echo "⚠️  SSH will remain accessible on public interface"
else
    echo "🔒 SSH will be blocked on public interface (only accessible via vRack)"
fi
echo ""

read -p "This will BLOCK all incoming traffic on $PUBLIC_INTERFACE. Continue? [y/N] " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Aborted."
    exit 1
fi

echo ""
echo "Backing up current UFW rules..."
ufw status numbered > /root/ufw-backup-$(date +%Y%m%d-%H%M%S).txt
echo "✅ Backup saved to /root/ufw-backup-$(date +%Y%m%d-%H%M%S).txt"
echo ""

# Reset UFW to clean state
echo "Resetting UFW to clean state..."
ufw --force reset

# Set default policies
echo "Setting default policies..."
ufw default deny incoming
ufw default allow outgoing

# ==============================================================================
# PRIVATE INTERFACE (vRack) - Full access
# ==============================================================================
echo ""
echo "Configuring private interface ($PRIVATE_INTERFACE)..."

# Allow all incoming on private interface
ufw allow in on "$PRIVATE_INTERFACE"
echo "✅ Allowed all incoming traffic on $PRIVATE_INTERFACE"

# Allow all outgoing on private interface
ufw allow out on "$PRIVATE_INTERFACE"
echo "✅ Allowed all outgoing traffic on $PRIVATE_INTERFACE"

# ==============================================================================
# PUBLIC INTERFACE (enp97s0f0) - Restricted
# ==============================================================================
echo ""
echo "Configuring public interface ($PUBLIC_INTERFACE)..."

# DENY all incoming on public interface (no services exposed publicly)
ufw deny in on "$PUBLIC_INTERFACE"
echo "✅ Denied all incoming traffic on $PUBLIC_INTERFACE"

# Keep SSH accessible on public if requested (WARNING: Security risk)
if [ "$KEEP_PUBLIC_SSH" = true ]; then
    # Insert SSH rule BEFORE the deny rule
    ufw insert 1 allow in on "$PUBLIC_INTERFACE" to any port "$SSH_PORT" proto tcp comment "SSH on public (remove for full isolation)"
    echo "⚠️  Allowed SSH ($SSH_PORT/tcp) on $PUBLIC_INTERFACE (SECURITY RISK)"
fi

# Allow essential outbound services on public interface
echo ""
echo "Configuring allowed outbound services on public interface..."

# SMTP (for sending mail)
ufw allow out on "$PUBLIC_INTERFACE" to any port 25 proto tcp comment "SMTP on public"
ufw allow out on "$PUBLIC_INTERFACE" to any port 587 proto tcp comment "SMTP submission on public"
ufw allow out on "$PUBLIC_INTERFACE" to any port 465 proto tcp comment "SMTPS on public"
echo "✅ Allowed outbound SMTP (25, 587, 465)"

# DNS (for name resolution)
ufw allow out on "$PUBLIC_INTERFACE" to any port 53 comment "DNS on public"
echo "✅ Allowed outbound DNS (53)"

# HTTP/HTTPS (for updates, webhooks, external APIs)
ufw allow out on "$PUBLIC_INTERFACE" to any port 80 proto tcp comment "HTTP on public"
ufw allow out on "$PUBLIC_INTERFACE" to any port 443 proto tcp comment "HTTPS on public"
echo "✅ Allowed outbound HTTP/HTTPS (80, 443)"

# NTP (for time synchronization)
ufw allow out on "$PUBLIC_INTERFACE" to any port 123 proto udp comment "NTP on public"
echo "✅ Allowed outbound NTP (123/udp)"

# DENY all other outbound traffic on public interface
ufw deny out on "$PUBLIC_INTERFACE"
echo "✅ Denied all other outbound traffic on $PUBLIC_INTERFACE"

# ==============================================================================
# Enable UFW
# ==============================================================================
echo ""
echo "Enabling UFW..."
ufw --force enable

echo ""
echo "═══════════════════════════════════════════════════════════════"
echo "✅ UFW vRack isolation configured successfully!"
echo "═══════════════════════════════════════════════════════════════"
echo ""
echo "Current configuration:"
ufw status numbered
echo ""
echo "⚠️  IMPORTANT NOTES:"
echo ""
echo "1. All incoming connections MUST come via private interface ($PRIVATE_INTERFACE)"
echo "2. Public interface ($PUBLIC_INTERFACE) is fully isolated"
if [ "$KEEP_PUBLIC_SSH" = true ]; then
    echo "3. SSH is accessible on public (port $SSH_PORT) - REMOVE for full isolation:"
    echo "   sudo ufw delete 1"
else
    echo "3. SSH is only accessible via vRack/bastion - use bastion to connect"
fi
echo "4. Outbound: Only SMTP, DNS, HTTP/HTTPS, NTP allowed on public"
echo "5. All services (databases, apps, etc.) accessible via vRack only"
echo ""
echo "To restore previous configuration:"
echo "  sudo ufw --force reset"
echo "  # Then manually re-add your previous rules from backup"
echo ""
