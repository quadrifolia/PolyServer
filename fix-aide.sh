#!/bin/bash
# Fix AIDE configuration error on bastion host
# Run this with: sudo bash fix-aide.sh

echo "===== Diagnosing AIDE Issue ====="

# Check if AIDE is installed
if ! command -v aide >/dev/null 2>&1; then
    echo "❌ AIDE is not installed"
    exit 1
fi

echo "✅ AIDE is installed"

# Check for config file
echo ""
echo "1. Checking for AIDE configuration file:"
if [ -f /etc/aide/aide.conf ]; then
    echo "   ✅ Found: /etc/aide/aide.conf"
elif [ -f /etc/aide.conf ]; then
    echo "   ✅ Found: /etc/aide.conf"
else
    echo "   ❌ No AIDE config file found!"
fi

# Check for database
echo ""
echo "2. Checking for AIDE database:"
if [ -f /var/lib/aide/aide.db ]; then
    echo "   ✅ Found: /var/lib/aide/aide.db"
    ls -lh /var/lib/aide/aide.db
elif [ -f /var/lib/aide/aide.db.new ]; then
    echo "   ⚠️  Found only: /var/lib/aide/aide.db.new (needs to be moved)"
    ls -lh /var/lib/aide/aide.db.new
else
    echo "   ❌ No AIDE database found - needs initialization"
fi

# Check current aide-check script
echo ""
echo "3. Current aide-check script:"
if [ -f /usr/local/bin/aide-check ]; then
    grep "aide --" /usr/local/bin/aide-check
else
    echo "   ❌ /usr/local/bin/aide-check not found"
fi

echo ""
echo "===== Applying Fix ====="

# Update the aide-check script to use explicit config path
echo "1. Updating aide-check script..."
cat > /usr/local/bin/aide-check << 'EOF'
#!/bin/bash
# Custom AIDE check script with proper mail handling for bastion host

# Log file for AIDE output
AIDE_LOG="/var/log/aide/aide-check.log"
mkdir -p /var/log/aide

# Run AIDE check and capture output
echo "AIDE integrity check started at $(date)" > $AIDE_LOG
echo "=====================================" >> $AIDE_LOG

# Run AIDE check with explicit config file
# Debian stores AIDE config at /etc/aide/aide.conf
if aide --config=/etc/aide/aide.conf --check 2>&1 | tee -a $AIDE_LOG; then
    # AIDE completed successfully
    echo "AIDE check completed at $(date)" >> $AIDE_LOG

    # Check if there were any changes detected
    if grep -q "found differences" $AIDE_LOG || grep -q "File.*changed" $AIDE_LOG; then
        # Changes detected - send alert email
        cat $AIDE_LOG | mail -s "🚨 BASTION AIDE ALERT: File integrity changes detected on $HOSTNAME" root
    else
        # No changes - log success
        echo "No integrity violations detected" >> $AIDE_LOG
    fi
else
    # AIDE failed
    echo "AIDE check failed at $(date)" >> $AIDE_LOG
    echo "AIDE integrity check failed on bastion host $HOSTNAME" | mail -s "🚨 BASTION AIDE ERROR: Check failed on $HOSTNAME" root
fi

# Rotate old logs (keep 30 days)
find /var/log/aide -name "aide-check.log.*" -mtime +30 -delete
if [ -f $AIDE_LOG ] && [ $(stat -c%s $AIDE_LOG) -gt 10485760 ]; then
    # If log is larger than 10MB, rotate it
    mv $AIDE_LOG ${AIDE_LOG}.$(date +%Y%m%d)
    gzip ${AIDE_LOG}.$(date +%Y%m%d)
fi
EOF

chmod 755 /usr/local/bin/aide-check
echo "   ✅ aide-check script updated"

# Check if database needs initialization
echo ""
echo "2. Checking AIDE database status..."
if [ ! -f /var/lib/aide/aide.db ]; then
    if [ -f /var/lib/aide/aide.db.new ]; then
        echo "   Moving aide.db.new to aide.db..."
        mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
        echo "   ✅ Database activated"
    else
        echo "   ⚠️  No database found - initializing AIDE (this may take a few minutes)..."
        aideinit
        if [ -f /var/lib/aide/aide.db.new ]; then
            mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
            echo "   ✅ AIDE database initialized and activated"
        else
            echo "   ❌ Failed to initialize AIDE database"
        fi
    fi
else
    echo "   ✅ AIDE database exists"
fi

# Test the aide-check script
echo ""
echo "3. Testing AIDE check..."
/usr/local/bin/aide-check

echo ""
echo "4. Checking AIDE timer status:"
systemctl status aide.timer --no-pager

echo ""
echo "===== Fix Complete ====="
echo "AIDE should now run properly."
echo "Check the log at: /var/log/aide/aide-check.log"
