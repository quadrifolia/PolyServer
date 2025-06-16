# SSH Bastion User Authentication Debugging Guide

## Issue Description
SSH authentication failing for bastion user with error:
"Could not open user 'bastion' authorized keys '/home/bastion/.ssh/authorized_keys': Permission denied"

## Step-by-Step Debugging Commands

### 1. Check AppArmor Status and SSH Profiles

```bash
# Check if AppArmor is enabled
sudo aa-status

# Check SSH daemon AppArmor profile status
sudo aa-status | grep -i ssh

# Check for SSH-related AppArmor denials in logs
sudo dmesg | grep -i apparmor | grep -i ssh
sudo journalctl -u ssh | grep -i apparmor
sudo grep -i apparmor /var/log/auth.log | grep -i ssh

# If AppArmor is blocking SSH, temporarily disable the SSH profile for testing
sudo aa-disable /usr/sbin/sshd

# Check SSH daemon AppArmor profile content
sudo cat /etc/apparmor.d/usr.sbin.sshd
```

### 2. Check Parent Directory Permissions Recursively

```bash
# Check full path permissions from root to authorized_keys
ls -la /
ls -la /home/
ls -la /home/bastion/
ls -la /home/bastion/.ssh/
ls -la /home/bastion/.ssh/authorized_keys

# Use namei to trace full path permissions
namei -l /home/bastion/.ssh/authorized_keys

# Check if /home is on a separate mount with restrictive options
mount | grep /home
cat /etc/fstab | grep /home
```

### 3. Test SSH Configuration and Daemon Status

```bash
# Test SSH configuration syntax
sudo sshd -t

# Check SSH daemon status and recent logs
sudo systemctl status ssh
sudo journalctl -u ssh -n 50

# Check SSH daemon configuration for relevant settings
sudo grep -E "AuthorizedKeysFile|PubkeyAuthentication|PasswordAuthentication|ChallengeResponseAuthentication" /etc/ssh/sshd_config

# Check if SSH is using a non-standard authorized_keys location
sudo grep -i authorizedkeysfile /etc/ssh/sshd_config

# Test SSH connection with verbose output (from client)
ssh -vvv bastion@your-server-ip
```

### 4. Check File System and Security Contexts

```bash
# Check if file system is mounted with noexec or other restrictive options
mount | grep "$(df /home/bastion | tail -1 | awk '{print $1}')"

# Check for extended attributes that might block access
getfattr -d /home/bastion/.ssh/authorized_keys 2>/dev/null || echo "No extended attributes"

# Check for SELinux (unlikely on Debian but worth checking)
which getenforce && getenforce 2>/dev/null || echo "SELinux not present"
ls -Z /home/bastion/.ssh/authorized_keys 2>/dev/null || echo "No SELinux contexts"

# Check for immutable file attributes
lsattr /home/bastion/.ssh/authorized_keys
```

### 5. Check System-Wide Security Policies

```bash
# Check for PAM restrictions
sudo grep -r "bastion" /etc/pam.d/

# Check /etc/security/ for user restrictions
sudo ls -la /etc/security/
sudo grep -r "bastion" /etc/security/ 2>/dev/null || echo "No bastion restrictions found"

# Check nsswitch configuration
cat /etc/nsswitch.conf

# Check if user is in required groups for SSH access
groups bastion
id bastion
```

### 6. Advanced SSH Debugging

```bash
# Run SSH daemon in debug mode (stop service first)
sudo systemctl stop ssh
sudo /usr/sbin/sshd -D -d -p 2222

# In another terminal, try connecting:
# ssh -p 2222 bastion@localhost

# Check SSH logs during connection attempt
sudo tail -f /var/log/auth.log

# After testing, restart SSH service
sudo systemctl start ssh
```

## Most Common Fixes

### Fix 1: AppArmor SSH Profile Issue
```bash
# If AppArmor is blocking access, add exception or disable profile
sudo aa-disable /usr/sbin/sshd
# Or edit the profile to allow access
sudo nano /etc/apparmor.d/usr.sbin.sshd
sudo systemctl reload apparmor
```

### Fix 2: Parent Directory Permissions
```bash
# Ensure all parent directories have correct permissions
sudo chmod 755 /home
sudo chmod 755 /home/bastion
sudo chown bastion:bastion /home/bastion
sudo chmod 700 /home/bastion/.ssh
sudo chmod 600 /home/bastion/.ssh/authorized_keys
sudo chown -R bastion:bastion /home/bastion/.ssh
```

### Fix 3: SSH Configuration Issues
```bash
# Ensure SSH daemon allows public key authentication
sudo sed -i 's/#PubkeyAuthentication yes/PubkeyAuthentication yes/' /etc/ssh/sshd_config
sudo sed -i 's/PubkeyAuthentication no/PubkeyAuthentication yes/' /etc/ssh/sshd_config

# Ensure AuthorizedKeysFile is set correctly
echo "AuthorizedKeysFile .ssh/authorized_keys" | sudo tee -a /etc/ssh/sshd_config

# Restart SSH daemon
sudo systemctl restart ssh
```

### Fix 4: File System Mount Options
```bash
# If /home is mounted with noexec, remount without it
sudo mount -o remount,exec /home

# Make permanent in /etc/fstab if needed
sudo nano /etc/fstab
```

### Fix 5: Remove File Immutable Attributes
```bash
# If file has immutable attributes, remove them
sudo chattr -i /home/bastion/.ssh/authorized_keys
```

## Quick Diagnostic Script

```bash
#!/bin/bash
echo "=== SSH Bastion User Diagnostic ==="
echo "1. AppArmor Status:"
sudo aa-status | grep -i ssh || echo "No SSH AppArmor profiles found"

echo -e "\n2. File Permissions:"
namei -l /home/bastion/.ssh/authorized_keys

echo -e "\n3. SSH Config Check:"
sudo sshd -t && echo "SSH config OK" || echo "SSH config ERROR"

echo -e "\n4. Mount Options:"
mount | grep "$(df /home | tail -1 | awk '{print $1}')"

echo -e "\n5. File Attributes:"
lsattr /home/bastion/.ssh/authorized_keys

echo -e "\n6. User Info:"
id bastion

echo -e "\n7. Recent SSH Logs:"
sudo tail -5 /var/log/auth.log | grep ssh
```

## Post-Fix Verification

```bash
# Test SSH key authentication
ssh -o PreferredAuthentications=publickey -o PasswordAuthentication=no bastion@your-server

# Check SSH logs for successful authentication
sudo grep "Accepted publickey" /var/log/auth.log | tail -5
```