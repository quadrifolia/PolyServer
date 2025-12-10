#!/bin/bash
# Optional SMT (Simultaneous Multithreading / Hyper-Threading) Disable Script
# This script helps mitigate CPU vulnerabilities: MDS, TAA, MMIO, VMSCAPE
# Run this with: sudo bash disable-smt.sh

# IMPORTANT: Disabling SMT will reduce CPU performance by approximately 25-30%
# Only disable if security is more critical than performance for your use case

set -euo pipefail

echo "===== SMT (Hyper-Threading) Security Configuration ====="
echo ""
echo "⚠️  WARNING: This script will help you decide whether to disable SMT"
echo "⚠️  Disabling SMT reduces performance by ~25-30% but improves security"
echo ""

# Check current SMT status
echo "1. Current SMT Status:"
if [ -f /sys/devices/system/cpu/smt/control ]; then
    SMT_STATUS=$(cat /sys/devices/system/cpu/smt/control)
    echo "   SMT Control: $SMT_STATUS"

    if [ "$SMT_STATUS" = "on" ]; then
        echo "   ⚠️  SMT is currently ENABLED (Hyper-Threading active)"
    elif [ "$SMT_STATUS" = "off" ]; then
        echo "   ✅ SMT is currently DISABLED (maximum security)"
    elif [ "$SMT_STATUS" = "forceoff" ]; then
        echo "   ✅ SMT is FORCE DISABLED (maximum security, cannot be re-enabled)"
    elif [ "$SMT_STATUS" = "notsupported" ]; then
        echo "   ℹ️  SMT is not supported on this CPU"
        exit 0
    fi
else
    echo "   ℹ️  SMT control interface not available (older kernel or unsupported CPU)"
    exit 0
fi

# Check CPU information
echo ""
echo "2. CPU Information:"
CPU_MODEL=$(lscpu | grep "Model name" | sed 's/Model name: *//')
CPU_CORES=$(lscpu | grep "^CPU(s):" | awk '{print $2}')
THREADS_PER_CORE=$(lscpu | grep "Thread(s) per core" | awk '{print $4}')
echo "   Model: $CPU_MODEL"
echo "   Total CPUs: $CPU_CORES"
echo "   Threads per core: $THREADS_PER_CORE"

if [ "$THREADS_PER_CORE" = "2" ]; then
    PHYSICAL_CORES=$((CPU_CORES / 2))
    echo "   Physical cores: $PHYSICAL_CORES"
    echo "   ⚠️  Hyper-Threading is active (2 threads per core)"
elif [ "$THREADS_PER_CORE" = "1" ]; then
    echo "   Physical cores: $CPU_CORES"
    echo "   ✅ SMT already disabled (1 thread per core)"
else
    echo "   Unknown SMT configuration"
fi

# Check current vulnerability status
echo ""
echo "3. Current CPU Vulnerability Status:"
VULN_DIR="/sys/devices/system/cpu/vulnerabilities"
if [ -d "$VULN_DIR" ]; then
    echo "   Checking vulnerabilities that are affected by SMT:"

    # MDS (Microarchitectural Data Sampling)
    if [ -f "$VULN_DIR/mds" ]; then
        MDS_STATUS=$(cat "$VULN_DIR/mds")
        echo "   • MDS: $MDS_STATUS"
        if echo "$MDS_STATUS" | grep -q "SMT vulnerable"; then
            echo "     ⚠️  SMT makes this system vulnerable to MDS attacks"
        fi
    fi

    # TAA (TSX Asynchronous Abort)
    if [ -f "$VULN_DIR/tsx_async_abort" ]; then
        TAA_STATUS=$(cat "$VULN_DIR/tsx_async_abort")
        echo "   • TAA: $TAA_STATUS"
        if echo "$TAA_STATUS" | grep -q "SMT vulnerable"; then
            echo "     ⚠️  SMT makes this system vulnerable to TAA attacks"
        fi
    fi

    # MMIO Stale Data
    if [ -f "$VULN_DIR/mmio_stale_data" ]; then
        MMIO_STATUS=$(cat "$VULN_DIR/mmio_stale_data")
        echo "   • MMIO: $MMIO_STATUS"
        if echo "$MMIO_STATUS" | grep -q "SMT vulnerable"; then
            echo "     ⚠️  SMT makes this system vulnerable to MMIO attacks"
        fi
    fi

    # Retbleed
    if [ -f "$VULN_DIR/retbleed" ]; then
        RETBLEED_STATUS=$(cat "$VULN_DIR/retbleed")
        echo "   • Retbleed: $RETBLEED_STATUS"
        if echo "$RETBLEED_STATUS" | grep -q "SMT vulnerable"; then
            echo "     ⚠️  SMT makes this system vulnerable to Retbleed attacks"
        fi
    fi

    # GDS (Gather Data Sampling)
    if [ -f "$VULN_DIR/gather_data_sampling" ]; then
        GDS_STATUS=$(cat "$VULN_DIR/gather_data_sampling")
        echo "   • GDS: $GDS_STATUS"
        if echo "$GDS_STATUS" | grep -q "SMT vulnerable"; then
            echo "     ⚠️  SMT makes this system vulnerable to GDS attacks"
        fi
    fi
else
    echo "   ⚠️  Vulnerability information not available"
fi

# Check current kernel mitigations
echo ""
echo "4. Current Kernel Mitigations:"
if [ -f /proc/cmdline ]; then
    CMDLINE=$(cat /proc/cmdline)
    echo "   Checking boot parameters..."

    if echo "$CMDLINE" | grep -q "mitigations=off"; then
        echo "   ❌ WARNING: All mitigations are DISABLED (mitigations=off)"
    elif echo "$CMDLINE" | grep -q "mitigations=auto"; then
        echo "   ✅ Mitigations set to auto (recommended)"
    fi

    if echo "$CMDLINE" | grep -q "nosmt"; then
        echo "   ✅ SMT disabled via kernel parameter (nosmt)"
    fi

    if echo "$CMDLINE" | grep -q "mds=full"; then
        echo "   ✅ MDS mitigation: full"
    fi

    if echo "$CMDLINE" | grep -q "tsx=off"; then
        echo "   ✅ TSX disabled (prevents TAA)"
    fi
fi

echo ""
echo "===== Decision Guide ====="
echo ""
echo "When to DISABLE SMT (choose security over performance):"
echo "  • Bastion/jump hosts with sensitive access"
echo "  • Systems processing confidential data"
echo "  • Multi-tenant environments"
echo "  • High-security compliance requirements"
echo ""
echo "When to KEEP SMT enabled (choose performance):"
echo "  • Development/staging servers"
echo "  • Single-tenant dedicated servers"
echo "  • Systems where performance is critical"
echo "  • Workloads that benefit heavily from threading"
echo ""
echo "Performance Impact of Disabling SMT:"
echo "  • CPU-bound tasks: ~20-30% slower"
echo "  • Multi-threaded apps: ~25-40% slower"
echo "  • I/O-bound tasks: ~5-10% slower"
echo "  • Single-threaded apps: minimal impact"
echo ""

# Offer choices
echo "===== Available Actions ====="
echo ""
echo "1) Disable SMT temporarily (until next reboot)"
echo "2) Disable SMT permanently (via GRUB kernel parameters)"
echo "3) Enable SMT (if currently disabled)"
echo "4) Show detailed status and exit"
echo "5) Exit without changes"
echo ""
read -p "Enter your choice (1-5): " choice

case $choice in
    1)
        echo ""
        echo "Disabling SMT temporarily..."
        if [ -f /sys/devices/system/cpu/smt/control ]; then
            echo off > /sys/devices/system/cpu/smt/control
            echo "✅ SMT disabled temporarily (will re-enable on reboot)"
            echo ""
            echo "New status:"
            cat /sys/devices/system/cpu/smt/control
            echo ""
            echo "To make this permanent, run this script again and choose option 2"
        else
            echo "❌ Unable to disable SMT - control interface not available"
        fi
        ;;

    2)
        echo ""
        echo "⚠️  WARNING: This will permanently disable SMT until you manually re-enable it"
        echo "⚠️  Performance will be reduced by ~25-30%"
        echo ""
        read -p "Are you sure you want to proceed? (yes/no): " confirm

        if [ "$confirm" = "yes" ]; then
            echo ""
            echo "Disabling SMT permanently via GRUB..."

            # Backup GRUB config
            cp /etc/default/grub /etc/default/grub.backup.$(date +%Y%m%d-%H%M%S)

            # Check if nosmt is already present
            if grep -q "nosmt" /etc/default/grub; then
                echo "✅ nosmt parameter already present in GRUB config"
            else
                # Add nosmt to GRUB_CMDLINE_LINUX_DEFAULT
                sed -i 's/GRUB_CMDLINE_LINUX_DEFAULT="/GRUB_CMDLINE_LINUX_DEFAULT="nosmt /' /etc/default/grub
                echo "✅ Added nosmt to GRUB configuration"
            fi

            # Update GRUB
            echo ""
            echo "Updating GRUB..."
            update-grub

            # Also disable immediately
            if [ -f /sys/devices/system/cpu/smt/control ]; then
                echo off > /sys/devices/system/cpu/smt/control
                echo "✅ SMT disabled immediately"
            fi

            echo ""
            echo "✅ SMT will be disabled permanently on next reboot"
            echo ""
            echo "Current vulnerability status:"
            cat /sys/devices/system/cpu/vulnerabilities/mds 2>/dev/null || echo "MDS: N/A"
            cat /sys/devices/system/cpu/vulnerabilities/tsx_async_abort 2>/dev/null || echo "TAA: N/A"
            cat /sys/devices/system/cpu/vulnerabilities/mmio_stale_data 2>/dev/null || echo "MMIO: N/A"
            echo ""
            echo "IMPORTANT: You must reboot for GRUB changes to take effect"
            echo "After reboot, vulnerabilities should show 'Mitigation: SMT disabled'"
        else
            echo "Cancelled - no changes made"
        fi
        ;;

    3)
        echo ""
        echo "Enabling SMT..."

        # Check if nosmt is in GRUB
        if grep -q "nosmt" /etc/default/grub; then
            echo "⚠️  WARNING: nosmt is configured in GRUB"
            echo "SMT will be re-disabled on next reboot unless you remove it from GRUB"
            echo ""
            read -p "Remove nosmt from GRUB permanently? (yes/no): " remove_grub

            if [ "$remove_grub" = "yes" ]; then
                cp /etc/default/grub /etc/default/grub.backup.$(date +%Y%m%d-%H%M%S)
                sed -i 's/nosmt //g' /etc/default/grub
                update-grub
                echo "✅ Removed nosmt from GRUB configuration"
            fi
        fi

        # Enable SMT immediately
        if [ -f /sys/devices/system/cpu/smt/control ]; then
            CURRENT=$(cat /sys/devices/system/cpu/smt/control)
            if [ "$CURRENT" = "forceoff" ]; then
                echo "❌ SMT is force-disabled and cannot be re-enabled without reboot"
                echo "You must reboot after removing nosmt from GRUB"
            else
                echo on > /sys/devices/system/cpu/smt/control
                echo "✅ SMT enabled"
                echo ""
                echo "New CPU count: $(nproc)"
            fi
        fi
        ;;

    4)
        echo ""
        echo "===== Detailed SMT Status ====="
        echo ""
        echo "SMT Control:"
        cat /sys/devices/system/cpu/smt/control 2>/dev/null || echo "Not available"
        echo ""
        echo "Active CPUs:"
        cat /sys/devices/system/cpu/smt/active 2>/dev/null || echo "Not available"
        echo ""
        echo "All CPU Vulnerabilities:"
        ls -1 /sys/devices/system/cpu/vulnerabilities/ 2>/dev/null | while read vuln; do
            echo "  $vuln: $(cat /sys/devices/system/cpu/vulnerabilities/$vuln)"
        done
        echo ""
        echo "GRUB Configuration:"
        grep "GRUB_CMDLINE_LINUX" /etc/default/grub | grep -v "^#"
        ;;

    5)
        echo "Exiting without changes"
        exit 0
        ;;

    *)
        echo "Invalid choice"
        exit 1
        ;;
esac

echo ""
echo "===== Complete ====="
