#!/usr/bin/env bash
# Copyright 2026 Intel Corporation
# SPDX-License-Identifier: Apache-2.0
# =============================================================================
# deploy/secure_boot/fetch_uefi_shell.sh — Stage an upstream EDK2 UEFI Shell for the
# "FW-Validation Shell" boot entry.
#
# WHY: Ubuntu's efi-shell-x64 (edk2 >= 2024.02-2ubuntu0.3, CVE-2025-2486) exits
# immediately when Secure Boot is enabled, so UEFI-shell test phases never run.
# This downloads the unmodified upstream build (pbatard/UEFI-Shell, built from
# edk2-stable tags) and verifies a pinned SHA-256.
#
# Idempotent: keeps an existing DEST unless it is the Ubuntu build.
# Called by deploy/setup/setup_sut.sh (step 7) and deploy/secure_boot/sign_efi_tools.sh.
#
# Usage:
#   ./deploy/secure_boot/fetch_uefi_shell.sh [DEST]     (default: <repo>/Tools/shellx64.efi)
#
# Overrides (update both together when moving to a new release):
#   UEFI_SHELL_URL     default: pbatard/UEFI-Shell 25H2 shellx64.efi
#   UEFI_SHELL_SHA256  default: published sha256 of that file
# Behind a proxy with sudo, keep the proxy env:  sudo -E ./deploy/...
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
DEST="${1:-${REPO_ROOT}/Tools/shellx64.efi}"
UEFI_SHELL_URL="${UEFI_SHELL_URL:-https://github.com/pbatard/UEFI-Shell/releases/download/25H2/shellx64.efi}"
UEFI_SHELL_SHA256="${UEFI_SHELL_SHA256:-954ffa52ee229cd638fccc623a56d5f35e2da239c99be4d3567b5f95de71a94d}"

shell_exits_under_secure_boot() {
    LC_ALL=C grep -qaP 'S\x00e\x00t\x00u\x00p\x00M\x00o\x00d\x00e\x00' "$1"
}

if [[ -f "${DEST}" ]] && ! shell_exits_under_secure_boot "${DEST}"; then
    echo "[OK]   Upstream UEFI shell already staged, keeping it: ${DEST}"
    exit 0
fi

echo "       Downloading upstream UEFI shell: ${UEFI_SHELL_URL}"
tmp="$(mktemp)"
trap 'rm -f "${tmp}"' EXIT

if ! curl -fsSL --retry 2 -m 120 -o "${tmp}" "${UEFI_SHELL_URL}"; then
    echo "[FAIL] Download failed: ${UEFI_SHELL_URL}"
    echo "       Check network/proxy (use 'sudo -E' to keep https_proxy), or download it"
    echo "       manually and copy it to: ${DEST}"
    exit 1
fi

if ! echo "${UEFI_SHELL_SHA256}  ${tmp}" | sha256sum -c --status; then
    echo "[FAIL] SHA-256 mismatch for ${UEFI_SHELL_URL}"
    echo "       expected: ${UEFI_SHELL_SHA256}"
    echo "       got     : $(sha256sum "${tmp}" | cut -d' ' -f1)"
    exit 1
fi

if shell_exits_under_secure_boot "${tmp}"; then
    echo "[FAIL] ${UEFI_SHELL_URL} also exits under Secure Boot -- pick another release (UEFI_SHELL_URL/UEFI_SHELL_SHA256)."
    exit 1
fi

mkdir -p "$(dirname "${DEST}")"
install -m 0644 "${tmp}" "${DEST}"
[[ -n "${SUDO_UID:-}" ]] && chown "${SUDO_UID}:${SUDO_GID:-${SUDO_UID}}" "${DEST}"
echo "[OK]   Upstream UEFI shell staged (sha256 verified): ${DEST}"
