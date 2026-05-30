#!/bin/bash
# Fix: Suppress Veeam backup agent sudo events from logcheck security emails
#
# Issue: veeam-usr-vspc-agent runs /var/lib/veeamma/utils/x64/veeaminstaller via sudo every
#        minute for health/version checks. logcheck reports these under "Security Events for sudo",
#        generating hourly false-positive emails across every Veeam-backed host.
#
# Root cause: the stock ignore rule in /etc/logcheck/violations.ignore.d/logcheck-sudo only
#        whitelists sudo COMMANDs whose path is under /usr, /etc, /bin or /sbin
#        (COMMAND=((/(usr|etc|bin|sbin)/|sudoedit ).*|list)$). Veeam runs from /var/lib/veeamma,
#        so its sudo calls fall outside that whitelist and are flagged as security violations.
#
# Fix: extend the logcheck-sudo ignore ruleset with a veeam-scoped exception. We append to
#      logcheck-sudo (the ruleset logcheck actually applies to the "Security Events for sudo"
#      report) rather than a standalone violations.ignore.d file -- on these hosts a standalone
#      file was read by run-parts but never suppressed the sudo violations report.

set -e

SUDO_IGNORE="/etc/logcheck/violations.ignore.d/logcheck-sudo"
# Backups MUST live outside the logcheck rule directories: logcheck lists every file in those
# dirs as a rule, so a stray backup left there becomes noise (or an unreadable-file warning).
BACKUP_DIR="/var/backups/logcheck"

# Veeam exception, modeled on the stock logcheck-sudo rule so it slots into the same machinery.
# Covers both syslog ("May 27 15:02:26") and ISO 8601 timestamps, optional sudo[PID], and the
# standard "FIELD=value ; " preamble. Scoped to veeam-* users running /var/lib/veeam* commands.
VEEAM_SUDO_RULE='^(\w{3} [ :0-9]{11}|[0-9T:.+-]{32}) [._[:alnum:]-]+ sudo(\[[0-9]+\])?:[[:space:]]+veeam-[._[:alnum:]-]+ : ((HOST|TTY|CHROOT|PWD|USER|GROUP|ENV|TSID|EXIT|SIGNAL)=[^ ;]+ ; )*COMMAND=/var/lib/veeam[^ ]*( .*)?$'
MARKER='# PolyServer: Veeam VSPC backup agent (veeaminstaller from /var/lib/veeamma) - legitimate, not a security event'

if ! command -v logcheck >/dev/null 2>&1; then
    echo "❌ logcheck is not installed. This fix is not needed."
    exit 1
fi

if [ ! -f "$SUDO_IGNORE" ]; then
    echo "❌ $SUDO_IGNORE not found (logcheck-database not installed?). Aborting."
    exit 1
fi

mkdir -p "$BACKUP_DIR"

# Retire the earlier standalone rule files: they are not honored for the "Security Events for
# sudo" violations report and only cause confusion.
for stale in /etc/logcheck/violations.ignore.d/veeam-agent \
             /etc/logcheck/ignore.d.server/veeam-agent; do
    if [ -e "$stale" ]; then
        mv -f "$stale" "$BACKUP_DIR/$(basename "$stale").removed-$(date +%Y%m%d-%H%M%S)" 2>/dev/null || rm -f "$stale"
        echo "🧹 Removed non-functional standalone rule: $stale"
    fi
done

# Move any stray backups earlier versions wrote INTO the rule directories out to BACKUP_DIR.
for stray in /etc/logcheck/violations.ignore.d/veeam-agent.bak-* \
             /etc/logcheck/ignore.d.server/veeam-agent.bak-*; do
    [ -e "$stray" ] || continue
    mv -f "$stray" "$BACKUP_DIR/$(basename "$stray")" 2>/dev/null || rm -f "$stray"
done

# Idempotently add the Veeam exception to the stock sudo ignore ruleset.
if grep -qF "$VEEAM_SUDO_RULE" "$SUDO_IGNORE"; then
    echo "✅ Veeam sudo ignore rule already present in $SUDO_IGNORE - nothing to do."
else
    cp -a "$SUDO_IGNORE" "$BACKUP_DIR/logcheck-sudo.bak-$(date +%Y%m%d-%H%M%S)"
    echo "✅ Backed up $SUDO_IGNORE to $BACKUP_DIR"
    printf '\n%s\n%s\n' "$MARKER" "$VEEAM_SUDO_RULE" >> "$SUDO_IGNORE"
    echo "✅ Added Veeam sudo ignore rule to $SUDO_IGNORE"
fi

echo ""
echo "Changes made:"
echo "  • Veeam VSPC agent sudo events suppressed in logcheck's \"Security Events for sudo\" report"
echo "  • Covers both syslog and ISO 8601 log timestamp formats"
echo "  • Only /var/lib/veeam* commands by veeam-* users are suppressed; all other sudo is reported"
echo "  • Old standalone veeam-agent rule files retired to $BACKUP_DIR"
echo ""
echo "Verify logcheck now suppresses the Veeam sudo events (should print 0):"
echo "  sudo -u logcheck /usr/sbin/logcheck -o -t 2>/dev/null | grep -c veeaminstaller"
echo ""
echo "To undo: restore the latest $BACKUP_DIR/logcheck-sudo.bak-* over $SUDO_IGNORE"
