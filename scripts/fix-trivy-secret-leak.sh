#!/bin/bash
# fix-trivy-secret-leak.sh
#
# One-shot remediation for production servers running the OLD trivy-scan cron job
# that (a) emailed detected secrets (private keys, API keys, ...) in CLEARTEXT over
# unencrypted SMTP, and (b) emailed Trivy's wide ASCII table, which is unreadable in
# mail clients (especially mobile).
#
# This script replaces /usr/local/sbin/trivy-scan (run by trivy-scan.timer; older
# setups had it in /etc/cron.daily) with a version that:
#   - emits a compact, mobile-friendly report (one line per finding, no wide tables),
#   - reports vulnerabilities in full (no secret material), and
#   - reports secret findings as METADATA ONLY (type/file/line) — the credential
#     value is never emailed or written to /var/log.
#
# Safe to run repeatedly (idempotent). Backs up the existing cron job first.
#
# Usage (as root on each server):
#   sudo bash fix-trivy-secret-leak.sh          # install fix only
#   sudo bash fix-trivy-secret-leak.sh --run     # install fix and run one scan now

set -euo pipefail

CRON_FILE="/usr/local/sbin/trivy-scan"
OLD_CRON_FILE="/etc/cron.daily/trivy-scan"

if [ "$(id -u)" -ne 0 ]; then
    echo "ERROR: must be run as root (try: sudo bash $0)" >&2
    exit 1
fi

# Older setups kept the script in /etc/cron.daily, where run-parts ran it in addition
# to trivy-scan.timer (two scans and two mails a day). Move it out of cron.daily.
if [ -f "$OLD_CRON_FILE" ]; then
    if [ ! -f "$CRON_FILE" ]; then
        cp -a "$OLD_CRON_FILE" "$CRON_FILE"
    fi
    mv -f "$OLD_CRON_FILE" "/root/trivy-scan.cron-daily.bak-$(date +%Y%m%d-%H%M%S)"
    echo "Moved $OLD_CRON_FILE out of cron.daily (backup in /root)"
fi
# Point an existing timer service at the new location
if [ -f /etc/systemd/system/trivy-scan.service ] && grep -q "^ExecStart=$OLD_CRON_FILE$" /etc/systemd/system/trivy-scan.service; then
    sed -i "s|^ExecStart=$OLD_CRON_FILE$|ExecStart=$CRON_FILE|" /etc/systemd/system/trivy-scan.service
    systemctl daemon-reload
    echo "Updated trivy-scan.service ExecStart to $CRON_FILE"
fi

if [ ! -f "$CRON_FILE" ]; then
    echo "WARNING: $CRON_FILE not found — Trivy scanning may not be installed on this host." >&2
    echo "Installing the corrected job anyway."
else
    BACKUP="${CRON_FILE}.bak-$(date +%Y%m%d-%H%M%S)"
    cp -a "$CRON_FILE" "$BACKUP"
    echo "Backed up existing cron job to $BACKUP"
fi

# --- Purge old reports that may contain secret values in cleartext --------------
# The previous version stored full secret-scan output on disk. Remove those logs.
if [ -d /var/log/security/trivy ]; then
    find /var/log/security/trivy -name 'trivy-*.log' -delete 2>/dev/null || true
    chmod 750 /var/log/security/trivy
    echo "Purged old trivy logs (may have contained cleartext secrets) and tightened dir perms."
fi

# --- Install corrected cron job -------------------------------------------------
cat > "$CRON_FILE" << 'EOF'
#!/bin/bash
# Daily container vulnerability scanning
#
# SECURITY: Trivy's secret scanner detects credentials baked into images. We must
# NEVER email or log the secret VALUES (cleartext over unencrypted SMTP / in
# /var/log). Vulnerability findings are reported in full (no secret material);
# secret findings are reported as metadata only (type/file/line) so an admin
# knows what to rotate and where to look, without the credential leaving the image.

REPORT_DIR="/var/log/security/trivy"
DATE=$(date +%Y-%m-%d)
MAIL_RECIPIENT="${LOGWATCH_EMAIL:-root}"
HOSTNAME=$(hostname)
TRIVYLOG="${REPORT_DIR}/trivy-${DATE}.log"
REPORT_TMPL="${REPORT_DIR}/.report.tmpl"

# Create report directory if it doesn't exist (restrict — reports may name sensitive paths)
mkdir -p $REPORT_DIR
chmod 750 $REPORT_DIR

# Compact, mobile-friendly report template (one line per finding, no wide tables).
# Trivy's default table output uses box-drawing chars and wide columns that mail clients
# render in a proportional font, producing unreadable wrapped garbage. Secrets are emitted
# as metadata only (type/file/line) — the credential value is never written out.
cat > "$REPORT_TMPL" << 'TMPL'
{{- range . }}{{ if or .Vulnerabilities .Secrets }}
========================================
 {{ .Target }}
========================================
{{- range .Vulnerabilities }}
[{{ .Severity }}] {{ .VulnerabilityID }} — {{ .PkgName }} {{ .InstalledVersion }}{{ if .FixedVersion }} (fix: {{ .FixedVersion }}){{ else }} (no fix){{ end }}
{{- end }}
{{- if .Secrets }}

*** SECRETS DETECTED (values redacted — rotate the credential & rebuild the image): ***
{{- range .Secrets }}
[{{ .Severity }}] {{ .Title }} ({{ .RuleID }}) at line {{ .StartLine }}
{{- end }}
{{- end }}
{{ end }}{{- end }}
TMPL

# Update Trivy vulnerability database
/usr/local/bin/trivy image --download-db-only > /dev/null 2>&1

# Start log file
echo "===== Container Vulnerability Scan Report: $DATE =====" > $TRIVYLOG

# Scan running containers (single scan per image, compact template output)
CONTAINERS=$(docker ps --format "{{.Image}}")
for IMAGE in $CONTAINERS; do
    echo "" >> $TRIVYLOG
    /usr/local/bin/trivy image --no-progress --scanners vuln,secret --severity HIGH,CRITICAL --format template --template "@$REPORT_TMPL" "$IMAGE" >> $TRIVYLOG 2>/dev/null
done

# Remove the template and restrict the report (defense in depth)
rm -f "$REPORT_TMPL"
chmod 640 $TRIVYLOG

# Email report if findings present
if grep -q -E "\[(HIGH|CRITICAL)\]" $TRIVYLOG; then
    cat $TRIVYLOG | mail -s "⚠️ CONTAINER VULNERABILITIES: Found on $HOSTNAME" $MAIL_RECIPIENT
fi

# Cleanup old reports
find $REPORT_DIR -name "trivy-*.log" -mtime +30 -delete
EOF

chmod 755 "$CRON_FILE"
echo "Installed corrected cron job at $CRON_FILE"

if [ "${1:-}" = "--run" ]; then
    echo "Running one scan now (this can take several minutes)..."
    "$CRON_FILE"
    echo "Scan complete. Report: /var/log/security/trivy/trivy-$(date +%Y-%m-%d).log"
fi

echo "Done."
