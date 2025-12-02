#!/bin/bash
# fix-db-firewall-email.sh - Fix email delivery on isolated database servers
#
# Problem: When using interface-specific deny rules on public interface,
# the deny rule blocks email even though generic port allows exist.
#
# Solution: Add interface-specific allow rules BEFORE the deny rule.

set -Eeuo pipefail

if [ "$EUID" -ne 0 ]; then
    echo "❌ This script must be run as root"
    exit 1
fi

echo "=================================================="
echo "Fix Database Server Email Delivery"
echo "=================================================="
echo ""

# Detect interfaces
VRACK_INTERFACE=$(ip -o link show | awk -F': ' '{print $2}' | grep -E "enp.*f1$|ens.*1$" | head -1)
PUBLIC_INTERFACE=$(ip -o link show | awk -F': ' '{print $2}' | grep -E "enp.*f0$|ens.*0$" | head -1)

if [ -z "$VRACK_INTERFACE" ] || [ -z "$PUBLIC_INTERFACE" ]; then
    echo "❌ Could not auto-detect interfaces"
    echo "   vRack: $VRACK_INTERFACE"
    echo "   Public: $PUBLIC_INTERFACE"
    echo ""
    echo "Please specify manually:"
    read -p "vRack interface name (e.g., enp97s0f1): " VRACK_INTERFACE
    read -p "Public interface name (e.g., enp97s0f0): " PUBLIC_INTERFACE
fi

echo "Detected interfaces:"
echo "  • vRack: $VRACK_INTERFACE"
echo "  • Public: $PUBLIC_INTERFACE"
echo ""

# Check current UFW status
echo "Current UFW rules:"
ufw status numbered | grep -E "$PUBLIC_INTERFACE|SMTP|587|465|25/tcp"
echo ""

# Find the deny out rule number for public interface
DENY_RULE=$(ufw status numbered | grep "DENY OUT.*$PUBLIC_INTERFACE" | head -1 | sed 's/\[//' | sed 's/\].*//' | xargs)

if [ -z "$DENY_RULE" ]; then
    echo "✅ No deny-out rule found on public interface"
    echo "   Email should already be working"
    exit 0
fi

echo "Found deny-out rule at position: $DENY_RULE"
echo ""

# Delete old generic SMTP rules if they exist (they don't work with interface rules)
echo "Removing generic SMTP rules (if any)..."
ufw status numbered | grep -E "ALLOW OUT.*25/tcp.*# SMTP for email" | grep -v "on $PUBLIC_INTERFACE" | sed 's/\[//' | sed 's/\].*//' | sort -rn | while read rule_num rest; do
    [ -n "$rule_num" ] && ufw --force delete $rule_num 2>/dev/null || true
done
ufw status numbered | grep -E "ALLOW OUT.*587/tcp.*# SMTP" | grep -v "on $PUBLIC_INTERFACE" | sed 's/\[//' | sed 's/\].*//' | sort -rn | while read rule_num rest; do
    [ -n "$rule_num" ] && ufw --force delete $rule_num 2>/dev/null || true
done
ufw status numbered | grep -E "ALLOW OUT.*465/tcp.*# SMTP" | grep -v "on $PUBLIC_INTERFACE" | sed 's/\[//' | sed 's/\].*//' | sort -rn | while read rule_num rest; do
    [ -n "$rule_num" ] && ufw --force delete $rule_num 2>/dev/null || true
done

echo "✅ Old generic SMTP rules removed"
echo ""

# Add interface-specific rules BEFORE the deny rule
echo "Adding interface-specific allow rules on $PUBLIC_INTERFACE..."

# Insert rules before the deny rule
ufw insert $DENY_RULE allow out on "$PUBLIC_INTERFACE" to any port 25 proto tcp comment "SMTP on public"
ufw insert $((DENY_RULE + 1)) allow out on "$PUBLIC_INTERFACE" to any port 587 proto tcp comment "SMTP submission on public"
ufw insert $((DENY_RULE + 2)) allow out on "$PUBLIC_INTERFACE" to any port 465 proto tcp comment "SMTPS on public"
ufw insert $((DENY_RULE + 3)) allow out on "$PUBLIC_INTERFACE" to any port 53 comment "DNS on public"
ufw insert $((DENY_RULE + 4)) allow out on "$PUBLIC_INTERFACE" to any port 80 proto tcp comment "HTTP on public"
ufw insert $((DENY_RULE + 5)) allow out on "$PUBLIC_INTERFACE" to any port 443 proto tcp comment "HTTPS on public"
ufw insert $((DENY_RULE + 6)) allow out on "$PUBLIC_INTERFACE" to any port 123 proto udp comment "NTP on public"

echo "✅ Interface-specific rules added"
echo ""

# Reload UFW
echo "Reloading UFW..."
ufw reload

echo ""
echo "✅ Firewall configuration fixed!"
echo ""
echo "Testing SMTP connectivity..."
timeout 5 bash -c 'cat < /dev/null > /dev/tcp/smtp.gmail.com/587' && echo "✅ Port 587: Connected!" || echo "❌ Port 587: Still blocked"
echo ""

# Flush mail queue
echo "Flushing mail queue..."
postqueue -f

echo ""
echo "Mail queue status:"
mailq | head -20
echo ""
echo "Watch mail log for deliveries:"
echo "  sudo tail -f /var/log/mail.log"
echo ""
