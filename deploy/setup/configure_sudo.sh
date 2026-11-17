#!/bin/bash
# Copyright 2026 Intel Corporation
# SPDX-License-Identifier: Apache-2.0

#
# Configure passwordless sudo for BIOS security test commands
# This allows automated test execution without password prompts
#

echo "=========================================="
echo "Configuring Passwordless Sudo"
echo "=========================================="
echo ""

# Get current user
CURRENT_USER=$(whoami)

# Absolute path to the repo root (this script lives in deploy/setup/) -- used to scope the
# deploy_tools.py NOPASSWD rule to this exact checkout, not just any script.
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PYTHON3_PATH="$(command -v python3)"

echo "This script will configure passwordless sudo for:"
echo "  - rdmsr (MSR reading)"
echo "  - dmidecode (BIOS version)"
echo "  - reboot/shutdown (system control)"
echo "  - deploy/tools/deploy_tools.py --to-efi (copy staged tools onto the SUT EFI partition)"
echo ""

read -p "Continue? (y/n) " -n 1 -r
echo ""

if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Cancelled."
    exit 1
fi

# Create sudoers file for automation
SUDOERS_FILE="/etc/sudoers.d/bios_security_automation"

echo "Creating sudoers configuration..."

sudo tee "$SUDOERS_FILE" > /dev/null << EOF
# BIOS Security Automation - Passwordless Sudo Configuration
# Created: $(date)
# User: $CURRENT_USER

# Read-only commands only: no cp/mkdir/wrmsr/insmod/ipmitool -- with any arguments those equal root.
# MSR reading
$CURRENT_USER ALL=(ALL) NOPASSWD: /usr/sbin/rdmsr
$CURRENT_USER ALL=(ALL) NOPASSWD: /sbin/modprobe msr

# BIOS/DMI reading
$CURRENT_USER ALL=(ALL) NOPASSWD: /usr/sbin/dmidecode

# System control
$CURRENT_USER ALL=(ALL) NOPASSWD: /sbin/reboot
$CURRENT_USER ALL=(ALL) NOPASSWD: /sbin/shutdown

# deploy_tools.py -- stages tools into ./Tools/ and, when run with sudo,
# automatically also copies the EFI-bound ones onto the SUT EFI partition
# (/boot/efi/EFI/). Scoped to this exact script path only -- does NOT grant
# passwordless sudo for python3 in general.
$CURRENT_USER ALL=(ALL) NOPASSWD: $PYTHON3_PATH $REPO_ROOT/deploy/tools/deploy_tools.py
$CURRENT_USER ALL=(ALL) NOPASSWD: $PYTHON3_PATH $REPO_ROOT/deploy/tools/deploy_tools.py *
EOF

# Set proper permissions
sudo chmod 0440 "$SUDOERS_FILE"

# Validate sudoers file
if sudo visudo -c -f "$SUDOERS_FILE"; then
    echo ""
    echo "✓ Sudoers configuration created successfully"
    echo "  File: $SUDOERS_FILE"
    echo ""
    echo "Testing passwordless sudo..."
    
    # Test rdmsr
    if sudo -n rdmsr 0x0 2>/dev/null; then
        echo "✓ rdmsr: OK"
    else
        echo "⚠ rdmsr: May need MSR module loaded"
    fi
    
    # Test dmidecode
    if sudo -n dmidecode -s bios-version >/dev/null 2>&1; then
        echo "✓ dmidecode: OK"
    else
        echo "✓ dmidecode: Configured (needs hardware)"
    fi
    
    echo ""
    echo "=========================================="
    echo "Configuration Complete!"
    echo "=========================================="
    echo ""
    echo "You can now run tests without password prompts:"
    echo "  pytest tests/firmware/ -v"
    echo ""
else
    echo ""
    echo "✗ Error: Sudoers file validation failed"
    echo "  Removing invalid configuration..."
    sudo rm -f "$SUDOERS_FILE"
    exit 1
fi
