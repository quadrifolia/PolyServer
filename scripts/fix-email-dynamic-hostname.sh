#!/bin/bash
# fix-email-dynamic-hostname.sh - Update postfix email routing to use dynamic hostname/username
# Fixes servers deployed with old hardcoded 'bastion' references
#
# This script aligns existing deployments with the updated bastion-setup script
# that properly supports custom hostnames and usernames.

set -Eeuo pipefail

if [ "$EUID" -ne 0 ]; then
    echo "❌ This script must be run as root"
    exit 1
fi

echo "=================================================="
echo "Fix Email Routing for Dynamic Hostname/Username"
echo "=================================================="
echo ""
echo "This script will update your postfix configuration to properly"
echo "handle email routing with your actual hostname and username."
echo ""

# Detect current configuration
CURRENT_HOSTNAME=$(hostname)
CURRENT_USER=$(getent passwd 1000 | cut -d: -f1)

# Try to detect the bastion/admin user more intelligently
if [ -z "$CURRENT_USER" ]; then
    # Look for users with UID >= 1000 and < 60000 (normal users, not system)
    CURRENT_USER=$(getent passwd | awk -F: '$3 >= 1000 && $3 < 60000 {print $1}' | grep -v "nobody" | head -1)
fi

echo "Detected configuration:"
echo "  • Hostname: $CURRENT_HOSTNAME"
echo "  • Primary user: $CURRENT_USER"
echo ""

# Ask for email address
read -p "Enter the email address for system notifications (e.g., admin@example.com): " LOGWATCH_EMAIL

if [ -z "$LOGWATCH_EMAIL" ]; then
    echo "❌ Email address is required"
    exit 1
fi

echo ""
echo "Configuration to apply:"
echo "  • Hostname: $CURRENT_HOSTNAME"
echo "  • Username: $CURRENT_USER"
echo "  • Email: $LOGWATCH_EMAIL"
echo ""
read -p "Proceed with these settings? (yes/no): " -r

if [[ ! "$REPLY" =~ ^[Yy]es$ ]]; then
    echo "❌ Cancelled by user"
    exit 1
fi

echo ""
echo "Updating postfix configuration..."

# Backup existing configuration
BACKUP_DIR="/var/backups/postfix-fix-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$BACKUP_DIR"

echo "Backing up current configuration to $BACKUP_DIR..."
[ -f /etc/postfix/recipient_canonical ] && cp /etc/postfix/recipient_canonical "$BACKUP_DIR/"
[ -f /etc/postfix/virtual ] && cp /etc/postfix/virtual "$BACKUP_DIR/"
[ -f /etc/aliases ] && cp /etc/aliases "$BACKUP_DIR/"
postconf -n > "$BACKUP_DIR/main.cf.backup"

echo "✅ Configuration backed up"
echo ""

# Update recipient_canonical with dynamic values
echo "Updating recipient_canonical map..."
cat > /etc/postfix/recipient_canonical << EOF
# Redirect all local recipients to external email address
# Using hostname: $CURRENT_HOSTNAME and username: $CURRENT_USER
root@$CURRENT_HOSTNAME    $LOGWATCH_EMAIL
$CURRENT_USER@$CURRENT_HOSTNAME $LOGWATCH_EMAIL
admin@$CURRENT_HOSTNAME   $LOGWATCH_EMAIL
security@$CURRENT_HOSTNAME $LOGWATCH_EMAIL
postmaster@$CURRENT_HOSTNAME $LOGWATCH_EMAIL
webmaster@$CURRENT_HOSTNAME $LOGWATCH_EMAIL
logcheck@$CURRENT_HOSTNAME $LOGWATCH_EMAIL

# Catch-all for any local user without @hostname
root    $LOGWATCH_EMAIL
$CURRENT_USER $LOGWATCH_EMAIL
admin   $LOGWATCH_EMAIL
security $LOGWATCH_EMAIL
postmaster $LOGWATCH_EMAIL
webmaster $LOGWATCH_EMAIL
logcheck $LOGWATCH_EMAIL
EOF

postmap /etc/postfix/recipient_canonical
echo "✅ recipient_canonical updated"

# Remove virtual_alias_maps if it exists (was a workaround)
if postconf -h virtual_alias_maps | grep -q "/etc/postfix/virtual"; then
    echo ""
    echo "Removing virtual_alias_maps workaround..."
    postconf -e "virtual_alias_maps ="
    rm -f /etc/postfix/virtual /etc/postfix/virtual.db
    echo "✅ Removed virtual_alias_maps workaround"
fi

# Update /etc/aliases with dynamic username
echo ""
echo "Updating /etc/aliases..."
cat > /etc/aliases << EOF
# All local mail redirected to external email address
root: $LOGWATCH_EMAIL
$CURRENT_USER: $LOGWATCH_EMAIL
admin: $LOGWATCH_EMAIL
security: $LOGWATCH_EMAIL
postmaster: $LOGWATCH_EMAIL
MAILER-DAEMON: $LOGWATCH_EMAIL
webmaster: $LOGWATCH_EMAIL
logcheck: $LOGWATCH_EMAIL
EOF

newaliases
echo "✅ /etc/aliases updated"

# Reload postfix
echo ""
echo "Reloading postfix..."
systemctl reload postfix

echo ""
echo "✅ Email routing configuration updated successfully!"
echo ""
echo "Testing email routing..."
echo "Sending test email to root (should route to $LOGWATCH_EMAIL)..."

cat << TEST_EMAIL | mail -s "Email Routing Test - $(hostname)" root
This is a test email to verify that email routing is working correctly
after updating to dynamic hostname/username configuration.

Server: $CURRENT_HOSTNAME
User: $CURRENT_USER
Target: $LOGWATCH_EMAIL

If you receive this email at $LOGWATCH_EMAIL, the configuration is working correctly.
TEST_EMAIL

echo ""
echo "Test email sent. Check $LOGWATCH_EMAIL for delivery."
echo ""
echo "Mail queue status:"
mailq
echo ""
echo "Configuration summary:"
echo "  • Backup location: $BACKUP_DIR"
echo "  • recipient_canonical: Using $CURRENT_HOSTNAME and $CURRENT_USER"
echo "  • All local mail routes to: $LOGWATCH_EMAIL"
echo ""
