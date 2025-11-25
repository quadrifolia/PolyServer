# Bastion Script Audit System Fixes Needed

## Summary of Issues Found During Deployment

During bastion host deployment on Debian 13 (Trixie), we discovered several critical issues with the audit system configuration:

### 1. Kernel Audit Not Enabled by Default
**Issue**: The kernel audit subsystem can be compiled in (`CONFIG_AUDIT=y`) but disabled at runtime (`enabled 0`).

**Current Script**: Does NOT check or enable kernel audit.

**Fix Needed**:
```bash
# Check if kernel audit is enabled
if command -v auditctl >/dev/null 2>&1; then
    AUDIT_ENABLED=$(auditctl -s 2>/dev/null | grep "^enabled" | awk '{print $2}')
    if [ "$AUDIT_ENABLED" = "0" ]; then
        echo "Enabling kernel audit subsystem..."
        auditctl -e 1
    fi
fi

# Make persistent via GRUB
if ! grep -q "audit=1" /etc/default/grub; then
    sed -i 's/GRUB_CMDLINE_LINUX_DEFAULT="/GRUB_CMDLINE_LINUX_DEFAULT="audit=1 /' /etc/default/grub
    update-grub
fi
```

### 2. Circular Dependency: auditd ↔ audit-rules
**Issue**: `/usr/lib/systemd/system/auditd.service` has `Requires=audit-rules.service`, but audit-rules can fail, preventing auditd from starting.

**Current Script**: Does NOT handle this dependency.

**Fix Needed**: Copy auditd.service to `/etc/systemd/system/` and remove the hard dependency:
```bash
# Copy service file to override system default
cp /usr/lib/systemd/system/auditd.service /etc/systemd/system/auditd.service

# Remove audit-rules dependency
sed -i '/^Requires=audit-rules.service/d' /etc/systemd/system/auditd.service
sed -i 's/After=\(.*\) audit-rules.service/After=\1/' /etc/systemd/system/auditd.service

# Reload systemd
systemctl daemon-reload
```

### 3. Problematic Audit Rules
**Issues with Current Rules**:
- ❌ `b32` arch rules cause "Invalid argument" errors on some systems
- ❌ Complex syscall rules (socket, connect, chmod, kill) can fail
- ❌ Too many rules (50+) can overwhelm the system

**Current Script**: Uses complex ruleset with b32 rules.

**Fix Needed**: Use minimal, battle-tested ruleset:
```bash
cat > /etc/audit/rules.d/bastion-audit.rules << 'EOF'
## Minimal Bastion Audit Rules (Guaranteed to Work)

## Delete all existing rules
-D

## Buffer Settings
-b 8192

## Failure Mode = 1 (log to syslog, don't panic)
-f 1

## === Session Tracking ===
-w /var/log/wtmp -p wa -k logins
-w /var/log/btmp -p wa -k logins
-w /var/run/utmp -p wa -k logins

## === Identity Management ===
-w /etc/passwd -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/gshadow -p wa -k identity

## === SSH Configuration ===
-w /etc/ssh/sshd_config -p wa -k sshd

## === Privilege Escalation Monitoring ===
-w /etc/sudoers -p wa -k sudo
-w /etc/sudoers.d/ -p wa -k sudo
-w /usr/bin/sudo -p x -k actions
-w /bin/su -p x -k actions

## === Critical Command Execution (64-bit only, simple) ===
-a always,exit -F arch=b64 -S execve -F uid>=1000 -k user_commands

## === Privilege Escalation Syscalls (64-bit only) ===
-a always,exit -F arch=b64 -S setuid -S setgid -k priv_change

## DO NOT make immutable to allow rule updates
EOF
```

### 4. Read-Only Filesystem Issues
**Issue**: Systems can boot with read-only `/` or `/boot`, preventing GRUB updates and configuration changes.

**Current Script**: Does NOT check or handle read-only filesystems.

**Fix Needed**:
```bash
# Ensure filesystems are writable before making changes
if mount | grep " / " | grep -q "(ro,"; then
    mount -o remount,rw /
fi

if mount | grep " /boot " | grep -q "(ro,"; then
    mount -o remount,rw /boot
fi
```

### 5. audit-rules.service Should Be Masked
**Issue**: The audit-rules.service tries to load rules but often fails, blocking auditd startup.

**Current Script**: Relies on audit-rules.service.

**Fix Needed**:
```bash
# Mask audit-rules permanently (we load rules differently)
systemctl mask audit-rules.service

# Load rules manually after auditd starts
cat > /etc/systemd/system/load-audit-rules.service << 'EOF'
[Unit]
Description=Load Audit Rules (Manual)
After=auditd.service
Requires=auditd.service

[Service]
Type=oneshot
ExecStart=/bin/sleep 3
ExecStart=/usr/sbin/auditctl -R /etc/audit/rules.d/bastion-audit.rules
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

systemctl enable load-audit-rules.service
```

## Implementation Plan

1. **Before Audit Configuration** (early in script):
   - Check and remount filesystems as rw
   - Enable kernel audit (`auditctl -e 1`)
   - Add `audit=1` to GRUB

2. **Audit Rules Section** (replace current complex rules):
   - Use minimal, proven ruleset
   - Only file watches and simple b64 syscalls
   - No b32 rules

3. **Audit Service Configuration**:
   - Copy auditd.service to /etc/systemd/system/
   - Remove audit-rules dependency
   - Mask audit-rules.service
   - Create load-audit-rules.service

4. **After Everything** (verification):
   - Check `auditctl -s` shows `enabled 1` and `pid != 0`
   - Verify rules are loaded
   - Test auditd service is active

## Files to Update

- `scripts/server-setup-bastion.sh` - Main script with all fixes
- Remove temporary fix scripts after integration

## Files to Remove After Integration

All diagnostic/fix scripts created during troubleshooting:
- `fix-unbound-apparmor.sh` - Fix integrated into main script
- `fix-postfix.sh` - Diagnostic only
- `fix-aide.sh` - Diagnostic only
- `fix-audit-rules.sh` - Diagnostic only
- `fix-sensor-log.sh` - Already fixed in main script
- `fix-verification-issues.sh` - Temporary
- `fix-audit-dependency.sh` - Solution integrated
- `fix-audit-circular-dependency.sh` - Solution integrated
- `diagnose-audit-kernel.sh` - Diagnostic only
- `enable-audit-kernel.sh` - Solution integrated
- `fix-auditd-remove-dependency.sh` - Solution integrated
- `fix-audit-invalid-rule.sh` - Solution integrated
- `fix-readonly-and-audit.sh` - Solution integrated
- `remount-all-rw.sh` - Diagnostic only
- `emergency-filesystem-check.sh` - Diagnostic only
- `disable-audit-no-kernel-support.sh` - Not needed with proper setup
- `start-auditd-standalone.sh` - Workaround not needed
- `fix-auditd-systemd-state.sh` - Workaround not needed
- `final-audit-fix.sh` - Solution integrated
- `copy-auditd-service.sh` - Solution integrated
- `verify-bastion-fixes.sh` - Keep for testing
- `install-verification-script.sh` - Keep for testing
- `re-run-bastion-safely.sh` - Useful for future

## Testing Plan

1. Fresh Debian 13 server
2. Run updated bastion script
3. Verify:
   - Kernel audit enabled (`auditctl -s | grep "enabled 1"`)
   - auditd service active
   - Rules loaded (10+ rules)
   - No systemd errors
   - GRUB has `audit=1`

## Success Criteria

- ✅ Audit works on fresh install without manual intervention
- ✅ No circular dependency errors
- ✅ Minimal, reliable ruleset
- ✅ Survives reboot
- ✅ Clean repository (no temporary fix scripts)
