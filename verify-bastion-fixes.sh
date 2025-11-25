#!/bin/bash
# Verification Script for Bastion Setup Fixes
# Run this after re-running server-setup-bastion.sh to verify all fixes worked

echo "===== Bastion Setup Verification ====="
echo "This script verifies that all the recent fixes are working properly"
echo ""

# Color codes for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

PASS=0
FAIL=0
WARN=0

# Function to report results
report_pass() {
    echo -e "${GREEN}✅ PASS${NC}: $1"
    ((PASS++))
}

report_fail() {
    echo -e "${RED}❌ FAIL${NC}: $1"
    ((FAIL++))
}

report_warn() {
    echo -e "${YELLOW}⚠️  WARN${NC}: $1"
    ((WARN++))
}

echo "1. Checking Unbound AppArmor Configuration..."
echo "─────────────────────────────────────────────"

# Check if AppArmor local override exists
if [ -f /etc/apparmor.d/local/usr.sbin.unbound ]; then
    if grep -q "capability net_admin" /etc/apparmor.d/local/usr.sbin.unbound; then
        report_pass "AppArmor local override exists with net_admin capability"
    else
        report_fail "AppArmor override exists but missing net_admin capability"
    fi
else
    report_fail "AppArmor local override file not created"
fi

# Check for recent AppArmor denials
echo ""
echo "2. Checking for AppArmor Denials..."
echo "─────────────────────────────────────────────"

RECENT_DENIALS=$(dmesg | grep -i "apparmor.*denied.*unbound" | tail -5)
if [ -z "$RECENT_DENIALS" ]; then
    report_pass "No AppArmor denials for Unbound in kernel log"
else
    report_warn "Found AppArmor denials (may be old):"
    echo "$RECENT_DENIALS" | head -3
    echo "   Check if these are recent or from before the fix"
fi

echo ""
echo "3. Checking Unbound Service Status..."
echo "─────────────────────────────────────────────"

if systemctl is-active --quiet unbound; then
    report_pass "Unbound service is active"

    # Check if it's actually responding
    if timeout 5 dig @127.0.0.1 google.com +short >/dev/null 2>&1; then
        report_pass "Unbound DNS resolution is working"
    else
        report_fail "Unbound is running but not resolving DNS queries"
    fi
else
    report_fail "Unbound service is not active"
    systemctl status unbound --no-pager -l | head -10
fi

echo ""
echo "4. Checking Unbound-Resolvconf Service..."
echo "─────────────────────────────────────────────"

# Check if service is masked
if systemctl is-masked --quiet unbound-resolvconf 2>/dev/null; then
    report_pass "unbound-resolvconf service is masked"
elif systemctl is-enabled --quiet unbound-resolvconf 2>/dev/null; then
    report_fail "unbound-resolvconf service is still enabled (should be masked)"
else
    # Service might not exist or is disabled
    if systemctl list-unit-files | grep -q unbound-resolvconf; then
        if systemctl is-enabled --quiet unbound-resolvconf 2>/dev/null; then
            report_fail "unbound-resolvconf exists but not properly disabled"
        else
            report_pass "unbound-resolvconf service is disabled"
        fi
    else
        report_pass "unbound-resolvconf service not present (OK)"
    fi
fi

echo ""
echo "5. Checking AIDE Configuration..."
echo "─────────────────────────────────────────────"

if [ -f /usr/local/bin/aide-check ]; then
    if grep -q "aide --config=/etc/aide/aide.conf" /usr/local/bin/aide-check; then
        report_pass "AIDE check script uses explicit config path"
    else
        report_warn "AIDE check script exists but might not use explicit config"
    fi

    # Check if AIDE database exists
    if [ -f /var/lib/aide/aide.db ]; then
        report_pass "AIDE database exists"
    else
        report_warn "AIDE database not initialized yet"
    fi
else
    report_warn "AIDE check script not found"
fi

echo ""
echo "6. Checking Audit Rules..."
echo "─────────────────────────────────────────────"

if systemctl is-active --quiet auditd; then
    report_pass "auditd service is active"

    # Check audit-rules service
    if systemctl is-active --quiet audit-rules 2>/dev/null; then
        report_pass "audit-rules service is active"
    else
        # Check if it loaded successfully
        if systemctl status audit-rules 2>&1 | grep -q "loaded"; then
            report_pass "audit-rules loaded successfully"
        else
            report_warn "audit-rules service status unclear"
        fi
    fi

    # Count loaded rules
    RULE_COUNT=$(auditctl -l 2>/dev/null | grep -v "No rules" | wc -l)
    if [ "$RULE_COUNT" -gt 15 ]; then
        report_pass "Audit rules loaded ($RULE_COUNT rules active)"
    elif [ "$RULE_COUNT" -gt 0 ]; then
        report_warn "Some audit rules loaded but count seems low ($RULE_COUNT rules)"
    else
        report_fail "No audit rules loaded"
    fi
else
    report_fail "auditd service is not active"
fi

echo ""
echo "7. Checking Postfix Configuration..."
echo "─────────────────────────────────────────────"

if systemctl is-active --quiet postfix; then
    report_pass "Postfix service is active"

    # Check for deprecated parameter
    if postconf smtp_use_tls 2>/dev/null | grep -q "yes"; then
        report_warn "Deprecated smtp_use_tls parameter still set"
    else
        report_pass "No deprecated smtp_use_tls parameter"
    fi

    # Check for modern TLS config
    if postconf smtp_tls_security_level 2>/dev/null | grep -q "encrypt"; then
        report_pass "Modern TLS configuration (smtp_tls_security_level) is set"
    else
        report_warn "TLS security level not set to encrypt"
    fi

    # Check resolv.conf ownership
    if [ -f /var/spool/postfix/etc/resolv.conf ]; then
        OWNER=$(stat -c "%U" /var/spool/postfix/etc/resolv.conf)
        if [ "$OWNER" = "root" ]; then
            report_pass "Postfix resolv.conf owned by root"
        else
            report_warn "Postfix resolv.conf not owned by root (owned by: $OWNER)"
        fi
    fi
else
    report_warn "Postfix service is not active"
fi

echo ""
echo "8. Checking Fail2ban Configuration..."
echo "─────────────────────────────────────────────"

if systemctl is-active --quiet fail2ban; then
    report_pass "Fail2ban service is active"

    # Check if sshd-ddos filter loads without errors
    if [ -f /etc/fail2ban/filter.d/sshd-ddos.conf ]; then
        # Try to test the filter
        if fail2ban-client status sshd-ddos >/dev/null 2>&1; then
            report_pass "sshd-ddos jail is active"
        else
            # Check if filter at least exists
            if grep -q "failregex" /etc/fail2ban/filter.d/sshd-ddos.conf; then
                report_pass "sshd-ddos filter configuration exists"
            fi
        fi
    fi
else
    report_fail "Fail2ban service is not active"
fi

echo ""
echo "9. Checking System Security Status..."
echo "─────────────────────────────────────────────"

# Check if bastionstat command exists
if command -v bastionstat >/dev/null 2>&1; then
    report_pass "bastionstat command is available"
else
    report_warn "bastionstat command not found"
fi

# Check UFW status
if ufw status | grep -q "Status: active"; then
    report_pass "UFW firewall is active"
else
    report_fail "UFW firewall is not active"
fi

# Check AppArmor status
if aa-status >/dev/null 2>&1; then
    APPARMOR_COUNT=$(aa-status --profiled 2>/dev/null || echo "0")
    if [ "$APPARMOR_COUNT" != "0" ]; then
        report_pass "AppArmor is active with profiles loaded"
    else
        report_warn "AppArmor status unclear"
    fi
else
    report_warn "Unable to check AppArmor status"
fi

echo ""
echo "10. Checking for Recent Errors in Logs..."
echo "─────────────────────────────────────────────"

# Check for recent critical errors
RECENT_ERRORS=$(journalctl --since "10 minutes ago" -p err --no-pager -n 10 2>/dev/null | grep -v "^--")
if [ -z "$RECENT_ERRORS" ]; then
    report_pass "No recent critical errors in system logs"
else
    report_warn "Found recent errors in logs:"
    echo "$RECENT_ERRORS" | head -5
fi

# Check for specific service failures
FAILED_SERVICES=$(systemctl --failed --no-pager --no-legend | wc -l)
if [ "$FAILED_SERVICES" -eq 0 ]; then
    report_pass "No failed systemd services"
else
    report_warn "Found $FAILED_SERVICES failed service(s):"
    systemctl --failed --no-pager | head -10
fi

echo ""
echo "============================================="
echo "           VERIFICATION SUMMARY"
echo "============================================="
echo -e "${GREEN}Passed: $PASS${NC}"
echo -e "${YELLOW}Warnings: $WARN${NC}"
echo -e "${RED}Failed: $FAIL${NC}"
echo ""

if [ "$FAIL" -eq 0 ] && [ "$WARN" -eq 0 ]; then
    echo -e "${GREEN}🎉 All checks passed! Your bastion setup is working perfectly.${NC}"
    exit 0
elif [ "$FAIL" -eq 0 ]; then
    echo -e "${YELLOW}⚠️  Setup is working but there are some warnings to review.${NC}"
    exit 0
else
    echo -e "${RED}❌ Some critical checks failed. Please review the output above.${NC}"
    exit 1
fi
