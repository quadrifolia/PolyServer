#!/bin/bash
# Fix audit-rules service failure on bastion host
# Run this with: sudo bash fix-audit-rules.sh

echo "===== Diagnosing Audit Rules Issue ====="

# Check current status
echo "1. Current audit service status:"
systemctl status auditd --no-pager -l || true
systemctl status audit-rules --no-pager -l || true

# Check what's in the rules file
echo ""
echo "2. Current audit rules file:"
cat /etc/audit/rules.d/bastion-audit.rules | head -20

# Try to load rules manually to see exact error
echo ""
echo "3. Testing manual rule load:"
auditctl -R /etc/audit/rules.d/bastion-audit.rules 2>&1 | head -20

# Check for specific common issues
echo ""
echo "4. Checking for common issues:"

# Issue: Too many watches
WATCH_COUNT=$(grep -c "^-w " /etc/audit/rules.d/bastion-audit.rules || echo 0)
echo "   - Number of file watches: $WATCH_COUNT"
if [ "$WATCH_COUNT" -gt 100 ]; then
    echo "     ⚠️  WARNING: Too many watches may cause issues"
fi

# Issue: Arch mismatch
if uname -m | grep -q x86_64; then
    if ! grep -q "arch=b64" /etc/audit/rules.d/bastion-audit.rules; then
        echo "     ⚠️  WARNING: Missing b64 arch rules on 64-bit system"
    fi
fi

# Issue: Audit buffer size
BUFFER=$(grep "^-b" /etc/audit/rules.d/bastion-audit.rules | awk '{print $2}')
echo "   - Audit buffer size: $BUFFER"

echo ""
echo "5. Checking kernel audit status:"
auditctl -s 2>&1

echo ""
echo "===== Proposed Fix ====="
echo "Creating optimized audit rules (less aggressive)..."

# Backup original
cp /etc/audit/rules.d/bastion-audit.rules /etc/audit/rules.d/bastion-audit.rules.backup

# Create optimized rules
cat > /etc/audit/rules.d/bastion-audit.rules << 'EOF'
## Bastion Host Audit Rules - Optimized for Reliability

## First rule - delete all existing rules
-D

## Reasonable buffer size
-b 8192

## Set failure mode to syslog (1) not panic (2)
-f 1

## Track authentication events (critical for bastions)
-w /var/log/wtmp -p wa -k session
-w /var/log/btmp -p wa -k session
-w /var/run/utmp -p wa -k session
-w /var/log/lastlog -p wa -k session

## Monitor SSH configuration changes
-w /etc/ssh/sshd_config -p wa -k ssh_config

## Monitor user and group modifications
-w /etc/group -p wa -k identity
-w /etc/passwd -p wa -k identity
-w /etc/gshadow -k identity
-w /etc/shadow -k identity

## Monitor sudo configuration
-w /etc/sudoers -p wa -k privilege_escalation
-w /etc/sudoers.d/ -p wa -k privilege_escalation

## Monitor critical network configuration
-w /etc/hosts -p wa -k network_config
-w /etc/network/interfaces -p wa -k network_config

## Monitor firewall changes
-w /etc/ufw/ -p wa -k firewall_config

## Track command executions by non-system users (b64 only for x86_64)
-a always,exit -F arch=b64 -S execve -F uid>=1000 -F uid!=4294967295 -k user_commands

## Track privilege escalation attempts (b64 only)
-a always,exit -F arch=b64 -S setuid -S setgid -S setresuid -S setresgid -k privilege_escalation

## Monitor critical system binaries (not recursive)
-w /bin/su -p x -k privilege_escalation
-w /bin/sudo -p x -k privilege_escalation
-w /usr/bin/sudo -p x -k privilege_escalation

## Track kernel module loading
-w /sbin/insmod -p x -k module_insertion
-w /sbin/rmmod -p x -k module_removal
-w /sbin/modprobe -p x -k module_insertion
-a always,exit -F arch=b64 -S init_module -S delete_module -k module_operations

## Monitor time changes
-a always,exit -F arch=b64 -S clock_settime -k time_change
-w /etc/localtime -p wa -k time_change

## Monitor cron jobs
-w /etc/crontab -p wa -k cron
-w /var/spool/cron/crontabs/ -p wa -k cron

## Do NOT make rules immutable to allow updates
EOF

echo "✅ Optimized audit rules created"
echo ""
echo "6. Testing new rules:"
auditctl -R /etc/audit/rules.d/bastion-audit.rules 2>&1

echo ""
echo "7. Restarting audit services:"
systemctl stop auditd
sleep 2
systemctl start auditd
sleep 2
systemctl start audit-rules
sleep 2

echo ""
echo "8. Final status:"
systemctl status auditd --no-pager
systemctl status audit-rules --no-pager

echo ""
echo "9. Loaded rules count:"
auditctl -l | wc -l

echo ""
echo "===== Fix Complete ====="
echo "If audit-rules is still failing, check: journalctl -u audit-rules -n 50"
