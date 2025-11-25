#!/bin/bash
# Safe Re-Run Guide for Bastion Setup on Existing System
# This is a GUIDE - review and adapt before running

echo "===== Bastion Script Re-Run Safety Checklist ====="
echo ""
echo "⚠️  IMPORTANT: This guide helps you safely re-run the bastion setup"
echo "⚠️  on an existing bastion host to apply new fixes"
echo ""

# Backup critical files
echo "1. Creating backups of critical configurations..."

BACKUP_DIR="/root/bastion-backup-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$BACKUP_DIR"

# Backup configurations
echo "   Backing up to: $BACKUP_DIR"
cp -r /home/*/. "$BACKUP_DIR/home-backup/" 2>/dev/null || true
cp /etc/ssh/sshd_config "$BACKUP_DIR/sshd_config.backup" 2>/dev/null || true
cp /etc/ufw/user.rules "$BACKUP_DIR/ufw-rules.backup" 2>/dev/null || true
cp -r /etc/fail2ban "$BACKUP_DIR/fail2ban-backup/" 2>/dev/null || true
cp /var/lib/aide/aide.db "$BACKUP_DIR/aide.db.backup" 2>/dev/null || true
cp /etc/audit/rules.d/bastion-audit.rules "$BACKUP_DIR/audit-rules.backup" 2>/dev/null || true

# Backup authorized_keys for all users
find /home -name "authorized_keys" -exec cp --parents {} "$BACKUP_DIR/" \; 2>/dev/null || true
find /root -name "authorized_keys" -exec cp --parents {} "$BACKUP_DIR/" \; 2>/dev/null || true

echo "   ✅ Backups created in: $BACKUP_DIR"
echo ""

# Check current state
echo "2. Checking current system state..."
echo "   Current users with /bin/zsh:"
grep "/bin/zsh" /etc/passwd | cut -d: -f1

echo ""
echo "   Current SSH port:"
grep "^Port " /etc/ssh/sshd_config || echo "   Default (22)"

echo ""
echo "   Current UFW status:"
ufw status numbered | head -10

echo ""
echo "   Current bastion user:"
id bastion 2>/dev/null || echo "   No bastion user found"

echo ""
echo "===== Pre-Run Checklist ====="
echo ""
echo "Before running the bastion setup script, verify:"
echo ""
echo "☐ You have a backup SSH session open (don't close until verified)"
echo "☐ You know the current SSH port and it matches your .env configuration"
echo "☐ You have the root password or sudo access via another user"
echo "☐ You've backed up any custom configurations you want to keep"
echo "☐ You understand UFW rules will be reset to defaults from script"
echo ""

read -p "Have you completed the checklist above? (yes/no): " checklist_done

if [ "$checklist_done" != "yes" ]; then
    echo "Please complete the checklist before proceeding"
    exit 1
fi

echo ""
echo "===== Recommended: Run Fix Scripts Instead ====="
echo ""
echo "RECOMMENDATION: Instead of re-running the full bastion script,"
echo "consider running only the targeted fix scripts:"
echo ""
echo "  sudo bash fix-unbound-apparmor.sh"
echo "  sudo bash fix-aide.sh"
echo "  sudo bash fix-postfix.sh"
echo "  sudo bash fix-audit-rules.sh"
echo ""
echo "These scripts fix the specific issues without risking"
echo "SSH lockout or configuration overwrites."
echo ""
read -p "Do you want to run fix scripts instead? (yes/no): " use_fix_scripts

if [ "$use_fix_scripts" = "yes" ]; then
    echo ""
    echo "Running targeted fix scripts..."

    if [ -f ./fix-unbound-apparmor.sh ]; then
        echo ""
        echo "=== Running Unbound Fix ==="
        bash ./fix-unbound-apparmor.sh
    fi

    if [ -f ./fix-aide.sh ]; then
        echo ""
        echo "=== Running AIDE Fix ==="
        bash ./fix-aide.sh
    fi

    if [ -f ./fix-postfix.sh ]; then
        echo ""
        echo "=== Running Postfix Fix ==="
        bash ./fix-postfix.sh
    fi

    if [ -f ./fix-audit-rules.sh ]; then
        echo ""
        echo "=== Running Audit Rules Fix ==="
        bash ./fix-audit-rules.sh
    fi

    echo ""
    echo "✅ Fix scripts completed"
    exit 0
fi

echo ""
echo "===== Full Script Re-Run ====="
echo ""
echo "⚠️  WARNING: You are about to re-run the full bastion setup script"
echo "⚠️  This will reset many configurations to defaults"
echo ""
read -p "Are you ABSOLUTELY sure? Type 'RUN FULL SCRIPT' to continue: " final_confirm

if [ "$final_confirm" != "RUN FULL SCRIPT" ]; then
    echo "Cancelled - no changes made"
    exit 0
fi

echo ""
echo "Starting full bastion setup script..."
echo "Logs will be saved to: /var/log/bastion-rerun-$(date +%Y%m%d-%H%M%S).log"
echo ""

# Check if script exists
if [ ! -f ./scripts/server-setup-bastion.sh ]; then
    echo "❌ Error: server-setup-bastion.sh not found"
    echo "Please run this from the PolyServer directory"
    exit 1
fi

# Run the script with logging
sudo bash ./scripts/server-setup-bastion.sh 2>&1 | tee "/var/log/bastion-rerun-$(date +%Y%m%d-%H%M%S).log"

echo ""
echo "===== Post-Run Verification ====="
echo ""
echo "Verify the following:"
echo "1. SSH is still accessible: ssh -p <PORT> <USER>@<HOST>"
echo "2. All critical services are running: sudo systemctl status sshd ufw fail2ban"
echo "3. Check for any errors in: journalctl -xe"
echo ""
echo "If something went wrong, restore from backup:"
echo "  Backup location: $BACKUP_DIR"
echo ""
