#!/bin/bash
# Fix: Suppress Veeam backup agent sudo events from logcheck security emails
# Issue: veeam-usr-vspc-agent runs veeaminstaller via sudo every minute for health checks,
#        triggering hourly logcheck "Security Events for sudo" emails as false positives.
# These are legitimate Veeam VSPC agent operations and do not indicate a security incident.
#
# IMPORTANT: "Security Events" in logcheck come from the violations.d ruleset and are
# ONLY suppressed by rules in /etc/logcheck/violations.ignore.d/. Rules placed in
# ignore.d.server/ filter the "System Events" section only and have NO effect on the
# "Security Events for sudo" report — which is why an earlier ignore.d.server rule did
# not work. We install into violations.ignore.d/ (primary) and ignore.d.server/ (fallback).

set -e

VIOLATIONS_FILE="/etc/logcheck/violations.ignore.d/veeam-agent"
SYSTEM_FILE="/etc/logcheck/ignore.d.server/veeam-agent"

# Backups MUST live outside the logcheck rule directories: logcheck reads every file
# in violations.ignore.d/ and ignore.d.server/ as a rule, so a stray ".bak" left there
# is parsed as a rule and (being unreadable to the logcheck user) aborts the whole run.
BACKUP_DIR="/var/backups/logcheck"

if ! command -v logcheck >/dev/null 2>&1; then
    echo "❌ logcheck is not installed. This fix is not needed."
    exit 1
fi

# Clean up backups that earlier versions of this script wrote INTO the rule directories.
# These break logcheck ("Could not read .../veeam-agent.bak-...") — move them to BACKUP_DIR.
mkdir -p "$BACKUP_DIR"
for stray in /etc/logcheck/violations.ignore.d/veeam-agent.bak-* \
             /etc/logcheck/ignore.d.server/veeam-agent.bak-*; do
    [ -e "$stray" ] || continue
    if mv -f "$stray" "$BACKUP_DIR/$(basename "$stray")" 2>/dev/null; then
        echo "🧹 Moved stray backup out of logcheck rule dir: $stray"
    else
        rm -f "$stray"
    fi
done

# Ignore-rule content. Two patterns cover traditional syslog and ISO 8601 timestamps.
# Matches: sudo[PID]: veeam-* : ... COMMAND=/var/lib/veeam*
# No TTY field, because the Veeam agent runs non-interactively via systemd.
# logcheck uses extended regex (egrep -i), so '/' needs no escaping.
read -r -d '' RULES <<'EOF' || true
# Veeam backup agent logcheck ignore rules
# Suppress legitimate sudo invocations by the Veeam VSPC agent service.
# The agent runs veeaminstaller every minute for health/version checks —
# these are not security events.

# Traditional syslog timestamp (e.g. "May 27 15:02:26")
^\w{3} [ :0-9]{11} [._[:alnum:]-]+ sudo\[[0-9]+\]:[[:space:]]+veeam-[[:alnum:]_-]+ : .*COMMAND=/var/lib/veeam[[:alnum:]/._-]+

# ISO 8601 timestamp (e.g. "2025-05-27T15:02:26.123+0200")
^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}[.,][0-9]+[+-][0-9]{4} [._[:alnum:]-]+ sudo\[[0-9]+\]:[[:space:]]+veeam-[[:alnum:]_-]+ : .*COMMAND=/var/lib/veeam[[:alnum:]/._-]+
EOF

install_rule() {
    local target="$1"
    local dir
    dir="$(dirname "$target")"
    mkdir -p "$dir"

    if [ -f "$target" ]; then
        mkdir -p "$BACKUP_DIR"
        cp "$target" "$BACKUP_DIR/$(basename "$target").bak-$(date +%Y%m%d-%H%M%S)"
        echo "✅ Backed up existing $target to $BACKUP_DIR"
    fi

    printf '%s\n' "$RULES" > "$target"
    chmod 644 "$target"
    # logcheck runs as the 'logcheck' user; make sure it can read the rule file.
    chown root:logcheck "$target" 2>/dev/null || chown root:root "$target"
    echo "✅ Installed $target"
}

# Primary: suppresses the "Security Events for sudo" violations report.
install_rule "$VIOLATIONS_FILE"
# Fallback: harmless coverage for the "System Events" section.
install_rule "$SYSTEM_FILE"

echo ""
echo "Changes made:"
echo "  • Veeam VSPC agent sudo events suppressed in logcheck SECURITY (violations) emails"
echo "  • Same rule installed as a System Events fallback"
echo "  • Covers both syslog and ISO 8601 log timestamp formats"
echo "  • Only /var/lib/veeam* commands by veeam-* users are suppressed"
echo "  • All other sudo activity continues to be reported"
echo ""
echo "Verify the rule matches a real log line (should print the line):"
echo "  echo 'May 27 15:02:26 polypublisher-1 sudo[2804225]: veeam-usr-vspc-agent : PWD=/ ; USER=root ; COMMAND=/var/lib/veeamma/utils/x64/veeaminstaller --agent-version' \\"
echo "    | grep -E -i -f $VIOLATIONS_FILE"
echo ""
echo "Confirm logcheck can read the rule files (must show readable by user 'logcheck'):"
echo "  sudo -u logcheck test -r $VIOLATIONS_FILE && echo readable || echo NOT-READABLE"
echo ""
echo "To restore previous state: sudo rm $VIOLATIONS_FILE $SYSTEM_FILE"