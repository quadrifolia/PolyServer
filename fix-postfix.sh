#!/bin/bash
# Fix Postfix issues on bastion host
# Run this with: sudo bash fix-postfix.sh

echo "===== Diagnosing Postfix Issues ====="

# Check Postfix status
echo "1. Postfix service status:"
systemctl status postfix --no-pager -l

# Check for deprecated parameters
echo ""
echo "2. Checking for deprecated parameters:"
if postconf smtp_use_tls 2>/dev/null | grep -q "yes"; then
    echo "   ⚠️  Found deprecated smtp_use_tls parameter"
fi

# Check resolv.conf ownership
echo ""
echo "3. Checking /var/spool/postfix/etc/resolv.conf ownership:"
if [ -f /var/spool/postfix/etc/resolv.conf ]; then
    ls -l /var/spool/postfix/etc/resolv.conf
    OWNER=$(stat -c "%U" /var/spool/postfix/etc/resolv.conf)
    if [ "$OWNER" != "root" ]; then
        echo "   ⚠️  Not owned by root (owned by: $OWNER)"
    fi
fi

# Check for read-only filesystem issues
echo ""
echo "4. Checking Postfix queue directories:"
for dir in /var/spool/postfix/maildrop /var/spool/postfix/incoming /var/spool/postfix/active; do
    if [ -d "$dir" ]; then
        echo "   Testing write access to $dir..."
        if touch "$dir/test-write-$$.tmp" 2>/dev/null; then
            rm -f "$dir/test-write-$$.tmp"
            echo "   ✅ $dir is writable"
        else
            echo "   ❌ $dir is READ-ONLY or not writable!"
        fi
    fi
done

# Check mount options
echo ""
echo "5. Checking /var mount options:"
findmnt /var 2>/dev/null || echo "   /var is not a separate mount"
mount | grep " /var " || echo "   /var mounted on root filesystem"

echo ""
echo "===== Applying Fixes ====="

# Fix 1: Remove deprecated smtp_use_tls parameter
echo "1. Removing deprecated smtp_use_tls parameter..."
if postconf smtp_use_tls 2>/dev/null | grep -q "yes"; then
    postconf -# smtp_use_tls
    echo "   ✅ Removed smtp_use_tls (using smtp_tls_security_level instead)"
else
    echo "   ✅ smtp_use_tls not set (good)"
fi

# Fix 2: Fix resolv.conf ownership
echo ""
echo "2. Fixing /var/spool/postfix/etc/resolv.conf ownership..."
if [ -f /var/spool/postfix/etc/resolv.conf ]; then
    chown root:root /var/spool/postfix/etc/resolv.conf
    chmod 644 /var/spool/postfix/etc/resolv.conf
    echo "   ✅ Ownership fixed"
else
    echo "   ℹ️  File doesn't exist yet"
fi

# Fix 3: Check and fix filesystem permissions
echo ""
echo "3. Checking Postfix spool directory permissions..."
chown -R postfix:postfix /var/spool/postfix 2>/dev/null || true
chmod 755 /var/spool/postfix
chmod 700 /var/spool/postfix/maildrop 2>/dev/null || true
chmod 700 /var/spool/postfix/incoming 2>/dev/null || true
chmod 700 /var/spool/postfix/active 2>/dev/null || true

# Ensure postfix user can write to spool
if [ -d /var/spool/postfix/maildrop ]; then
    chown postfix:postdrop /var/spool/postfix/maildrop
    chmod 730 /var/spool/postfix/maildrop
    echo "   ✅ Fixed maildrop permissions"
fi

# Fix 4: Check if /var or /var/spool is mounted read-only
echo ""
echo "4. Checking for read-only mount issues..."
if mount | grep " /var " | grep -q "ro,"; then
    echo "   ❌ WARNING: /var is mounted READ-ONLY!"
    echo "   This needs to be remounted read-write:"
    echo "   sudo mount -o remount,rw /var"
elif mount | grep " /var/spool " | grep -q "ro,"; then
    echo "   ❌ WARNING: /var/spool is mounted READ-ONLY!"
    echo "   This needs to be remounted read-write:"
    echo "   sudo mount -o remount,rw /var/spool"
else
    echo "   ✅ No read-only mount detected"
fi

# Fix 5: Restart Postfix
echo ""
echo "5. Restarting Postfix with new configuration..."
systemctl restart postfix
sleep 2

# Verify
echo ""
echo "6. Testing Postfix after fixes:"
systemctl status postfix --no-pager

echo ""
echo "7. Testing mail sending:"
echo "Test email from bastion host" | mail -s "Postfix test after fix" root
echo "   ✅ Test email queued (check /var/log/mail.log)"

echo ""
echo "8. Checking recent Postfix logs for errors:"
journalctl -u postfix --no-pager -n 20 --since "1 minute ago"

echo ""
echo "===== Fix Complete ====="
echo "If you still see read-only filesystem errors, check:"
echo "1. Mount options: mount | grep /var"
echo "2. Disk space: df -h"
echo "3. Filesystem errors: dmesg | grep -i error"
