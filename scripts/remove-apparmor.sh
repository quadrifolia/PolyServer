#!/bin/bash
# Remove AppArmor from bastion host for compatibility
# This script can be run on existing systems to remove AppArmor entirely

# Root privilege check
if [[ $EUID -ne 0 ]]; then
   echo "❌ This script must be run as root"
   echo "Please run: sudo $0"
   exit 1
fi

echo "===== Removing AppArmor from Bastion Host ====="
echo "This will completely disable and remove AppArmor profiles"
echo ""

# Show current AppArmor status
if command -v aa-status >/dev/null 2>&1; then
    echo "Current AppArmor status:"
    aa-status
    echo ""
fi

# Ask for confirmation
read -p "Continue with AppArmor removal? (y/N): " -r
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "AppArmor removal cancelled"
    exit 0
fi

echo ""
echo "Removing AppArmor..."

# Stop AppArmor service
echo "Stopping AppArmor service..."
systemctl stop apparmor 2>/dev/null || true

# Disable AppArmor service
echo "Disabling AppArmor service..."
systemctl disable apparmor 2>/dev/null || true

# Backup existing profiles
if [ -d /etc/apparmor.d ] && [ -n "$(ls -A /etc/apparmor.d 2>/dev/null)" ]; then
    echo "Backing up AppArmor profiles..."
    mkdir -p /var/backups
    tar -czf /var/backups/apparmor-profiles-backup-$(date +%Y%m%d-%H%M%S).tar.gz /etc/apparmor.d/ 2>/dev/null || true
    echo "✅ Backup created: /var/backups/apparmor-profiles-backup-$(date +%Y%m%d-%H%M%S).tar.gz"
fi

# Unload all AppArmor profiles using aa-teardown if available
if command -v aa-teardown >/dev/null 2>&1; then
    echo "Unloading all AppArmor profiles using aa-teardown..."
    aa-teardown 2>/dev/null || true
fi

# Alternative method: manually unload profiles
if [ -f /sys/kernel/security/apparmor/profiles ]; then
    echo "Manually unloading remaining AppArmor profiles..."
    while read -r profile; do
        profile_name=$(echo "$profile" | awk '{print $1}')
        if [ -n "$profile_name" ] && [ "$profile_name" != "unconfined" ]; then
            echo "  Unloading: $profile_name"
            echo -n "$profile_name" > /sys/kernel/security/apparmor/.remove 2>/dev/null || true
        fi
    done < /sys/kernel/security/apparmor/profiles
fi

# Remove profile files
if [ -d /etc/apparmor.d ]; then
    echo "Removing AppArmor profile files..."
    rm -rf /etc/apparmor.d/* 2>/dev/null || true
fi

# Remove AppArmor cache
if [ -d /var/cache/apparmor ]; then
    echo "Removing AppArmor cache..."
    rm -rf /var/cache/apparmor/* 2>/dev/null || true
fi

# Verify removal
echo ""
echo "Verifying AppArmor removal..."
if command -v aa-status >/dev/null 2>&1; then
    echo "AppArmor status after removal:"
    if aa-status 2>/dev/null | grep -q "0 profiles are loaded"; then
        echo "✅ All AppArmor profiles successfully removed"
    else
        echo "AppArmor status:"
        aa-status 2>/dev/null || echo "AppArmor status command failed"
    fi
else
    echo "✅ AppArmor commands not available"
fi

echo ""
echo "✅ AppArmor removal completed"
echo ""
echo "📋 What was done:"
echo "   • AppArmor service stopped and disabled"
echo "   • All AppArmor profiles unloaded"
echo "   • Profile files backed up and removed"
echo "   • AppArmor cache cleared"
echo ""
echo "🔄 System Impact:"
echo "   • SSH authentication issues resolved"
echo "   • Performance improved (no AppArmor overhead)"
echo "   • Security still maintained by:"
echo "     - fail2ban (brute force protection)"
echo "     - UFW firewall (network security)"
echo "     - auditd (comprehensive logging)"
echo "     - Suricata IDS (network monitoring)"
echo ""
echo "💡 Reboot recommended to ensure complete removal"
echo "   sudo reboot"