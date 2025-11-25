#!/bin/bash
# Install the bastion verification script to /usr/local/bin/
# Run this with: sudo bash install-verification-script.sh

if [ "$EUID" -ne 0 ]; then
    echo "Please run as root: sudo bash $0"
    exit 1
fi

echo "Installing bastion verification script..."

# Copy to system location
cp verify-bastion-fixes.sh /usr/local/bin/bastionverify
chmod +x /usr/local/bin/bastionverify

# Add to allowed sudoers commands
if [ -f /etc/sudoers.d/bastion-bastion ]; then
    # Check if bastionverify is already in the list
    if ! grep -q "bastionverify" /etc/sudoers.d/bastion-bastion; then
        echo "Adding bastionverify to sudoers..."

        # Backup current sudoers file
        cp /etc/sudoers.d/bastion-bastion /etc/sudoers.d/bastion-bastion.backup

        # Add bastionverify to BASTION_COMMANDS alias
        sed -i 's#Cmnd_Alias BASTION_COMMANDS = \(.*\)#Cmnd_Alias BASTION_COMMANDS = \1, /usr/local/bin/bastionverify#' /etc/sudoers.d/bastion-bastion

        echo "✅ Added to sudoers"
    else
        echo "✅ Already in sudoers"
    fi
fi

echo ""
echo "✅ Installation complete!"
echo ""
echo "You can now run the verification script without sudo password:"
echo "  sudo bastionverify"
echo ""
