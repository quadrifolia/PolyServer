#!/bin/bash
# ssh-disable-password-auth.sh - Disable SSH password authentication
# Run this script after adding SSH keys to switch from password to key-only auth

set -e

echo "===== SSH Password Authentication Disabler ====="
echo "This script will disable SSH password authentication and enable key-only auth."
echo "Make sure you have working SSH key access before running this!"
echo ""

# Check if we're running as root
if [ "$EUID" -ne 0 ]; then
    echo "Error: This script must be run as root"
    exit 1
fi

# Get the current SSH config
SSH_CONFIG="/etc/ssh/sshd_config"
SSH_BACKUP="/etc/ssh/sshd_config.$(date +%Y%m%d_%H%M%S).bak"

# Check if password auth is currently enabled
if grep -q "^PasswordAuthentication yes" "$SSH_CONFIG"; then
    echo "Current status: Password authentication is ENABLED"
else
    echo "Current status: Password authentication is already DISABLED"
    exit 0
fi

# Create backup
echo "Creating backup of SSH config: $SSH_BACKUP"
cp "$SSH_CONFIG" "$SSH_BACKUP"

# Ask for confirmation
echo ""
echo "WARNING: This will disable password authentication for SSH!"
echo "Make sure you can login with SSH keys before proceeding."
echo ""
read -p "Are you sure you want to disable password authentication? (yes/no): " CONFIRM

if [ "$CONFIRM" != "yes" ]; then
    echo "Operation cancelled."
    exit 0
fi

# Disable password authentication
echo "Disabling password authentication..."
sed -i 's/^PasswordAuthentication yes/PasswordAuthentication no/' "$SSH_CONFIG"

# Test SSH configuration
echo "Testing SSH configuration..."
if sshd -t; then
    echo "SSH configuration is valid."
    
    # Restart SSH service
    echo "Restarting SSH service..."
    systemctl restart sshd
    
    echo ""
    echo "✅ Password authentication has been disabled successfully!"
    echo "SSH is now configured for key-only authentication."
    echo ""
    echo "Backup created at: $SSH_BACKUP"
    echo "To re-enable password auth: sed -i 's/^PasswordAuthentication no/PasswordAuthentication yes/' $SSH_CONFIG && systemctl restart sshd"
else
    echo "❌ SSH configuration test failed!"
    echo "Restoring backup..."
    cp "$SSH_BACKUP" "$SSH_CONFIG"
    echo "Backup restored. No changes were made."
    exit 1
fi