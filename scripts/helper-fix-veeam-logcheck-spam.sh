#!/bin/bash
# Fix: Suppress Veeam backup agent sudo events from logcheck security emails
# Issue: veeam-usr-vspc-agent runs veeaminstaller via sudo every minute for health checks,
#        triggering hourly logcheck "Security Events for sudo" emails as false positives.
# These are legitimate Veeam VSPC agent operations and do not indicate a security incident.

set -e

IGNORE_FILE="/etc/logcheck/ignore.d.server/veeam-agent"

if ! command -v logcheck >/dev/null 2>&1; then
    echo "❌ logcheck is not installed. This fix is not needed."
    exit 1
fi

mkdir -p /etc/logcheck/ignore.d.server

# Back up existing file if present
if [ -f "$IGNORE_FILE" ]; then
    cp "$IGNORE_FILE" "${IGNORE_FILE}.bak-$(date +%Y%m%d-%H%M%S)"
    echo "✅ Backed up existing ignore file"
fi

# Write ignore rules for both traditional syslog and ISO 8601 timestamp formats.
# Matches: sudo[PID]: veeam-* : PWD=/ ; USER=root ; COMMAND=/var/lib/veeam*
# No TTY field because the Veeam agent runs non-interactively via systemd.
cat > "$IGNORE_FILE" << 'EOF'
# Veeam backup agent logcheck ignore rules
# Suppress legitimate sudo invocations by the Veeam VSPC agent service.
# The agent runs veeaminstaller every minute for health/version checks —
# these are not security events.

# Traditional syslog timestamp (e.g. "May 27 15:02:26")
^\w{3} [ :0-9]{11} [._[:alnum:]-]+ sudo\[[0-9]+\]: veeam-[[:alnum:]_-]+ : PWD=\/ ; USER=root ; COMMAND=\/var\/lib\/veeam[[:alnum:]\/._-]+ .*$

# ISO 8601 timestamp (e.g. "2025-05-27T15:02:26.123+0200")
^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]+[+-][0-9]{4} [._[:alnum:]-]+ sudo\[[0-9]+\]: veeam-[[:alnum:]_-]+ : PWD=\/ ; USER=root ; COMMAND=\/var\/lib\/veeam[[:alnum:]\/._-]+ .*$
EOF

chmod 640 "$IGNORE_FILE"
chown root:logcheck "$IGNORE_FILE" 2>/dev/null || chown root:root "$IGNORE_FILE"

echo "✅ Created $IGNORE_FILE"
echo ""
echo "Changes made:"
echo "  • Veeam VSPC agent sudo events suppressed in logcheck security emails"
echo "  • Covers both syslog and ISO 8601 log timestamp formats"
echo "  • Only /var/lib/veeam* commands by veeam-* users are suppressed"
echo "  • All other sudo activity continues to be reported"
echo ""
echo "To verify the rule works against a sample log line:"
echo "  echo 'May 27 15:02:26 polypublisher-1 sudo[2804225]: veeam-usr-vspc-agent : PWD=/ ; USER=root ; COMMAND=/var/lib/veeamma/utils/x64/veeaminstaller --agent-version' | grep -P \"\$(grep -v '^#' $IGNORE_FILE | grep -v '^$' | head -1)\""
echo ""
echo "To restore previous state: sudo rm $IGNORE_FILE"
