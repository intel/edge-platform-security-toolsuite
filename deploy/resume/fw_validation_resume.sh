#!/bin/bash
# Copyright 2026 Intel Corporation
# SPDX-License-Identifier: Apache-2.0
#
# Resume runner for fw-validation-resume.service.
#
# WHY THIS IS A SCRIPT AND NOT AN INLINE ExecStart
# ------------------------------------------------
# systemd performs its own variable expansion on ExecStart command lines before
# handing them to the shell.  It only understands "$VAR" / "${VAR}", so a bash
# array expansion such as "${TESTS[@]}" is parsed by systemd as a variable named
# `TESTS[@]`, which is not a valid environment variable name.  systemd then
# replaces it with an EMPTY STRING and logs:
#
#   Invalid environment variable name evaluates to an empty string: TESTS[@]
#
# The shell therefore received `pytest "" -v -s ...` — no test node IDs — so
# pytest collected the ENTIRE repository instead of the queued resume batch and
# blocked on an unrelated manual-gate test.  The multi-phase (reboot-driven)
# test never resumed.
#
# Keeping the logic in a real script file means systemd never sees the `$`, so
# the array expansion is handled by bash as intended.
#
# Configuration comes from the environment (set via Environment= in the unit):
#   STATE_DIR   Test state folder                (default <repo>/logs/sut_state; set it to the
#               USB mount only if the suite config sets usb_mount)
#   EFI_MOUNT   EFI system partition mount point (default /boot/efi)
#   RESUME_LOG  Append-mode log file             (default <repo>/logs/resume_service.log)
#   PYTHON_BIN  Python interpreter to run pytest (default python3)
#   WAIT_SECS   Seconds to wait for a marker     (default 60)

set -u -o pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
STATE_DIR="${STATE_DIR:-${REPO_ROOT}/logs/sut_state}"
EFI_MOUNT="${EFI_MOUNT:-/boot/efi}"
PYTHON_BIN="${PYTHON_BIN:-python3}"
WAIT_SECS="${WAIT_SECS:-60}"
RESUME_LOG="${RESUME_LOG:-${REPO_ROOT}/logs/resume_service.log}"

mkdir -p "$(dirname "${RESUME_LOG}")"
exec >> "${RESUME_LOG}" 2>&1

echo "========== Resume service started: $(date) =========="

os_marker="${STATE_DIR}/state_done.txt"
efi_marker="${EFI_MOUNT}/state_done.txt"
next_test="${STATE_DIR}/next_test.txt"

# Wait for a completion marker to appear (the EFI partition can mount a little late).
for _ in $(seq 1 "${WAIT_SECS}"); do
    if [ -f "${os_marker}" ] || [ -f "${efi_marker}" ]; then
        break
    fi
    sleep 1
done

if [ ! -f "${os_marker}" ] && [ ! -f "${efi_marker}" ]; then
    echo "state_done.txt not found in ${STATE_DIR} or on EFI (${EFI_MOUNT}) — nothing to resume."
    exit 0
fi

if [ ! -f "${next_test}" ]; then
    echo "ERROR: ${next_test} not found — cannot determine which test(s) to resume."
    echo "Refusing to start pytest without explicit node IDs (that would run the whole suite)."
    exit 1
fi

# Read the queued node IDs, dropping blank lines and CR characters so a stray
# empty line can never turn into an empty pytest argument.
TESTS=()
while IFS= read -r line || [ -n "${line}" ]; do
    line="${line%$'\r'}"
    [ -z "${line}" ] && continue
    TESTS+=("${line}")
done < "${next_test}"

if [ "${#TESTS[@]}" -eq 0 ]; then
    echo "ERROR: ${next_test} contains no test node IDs."
    echo "Refusing to start pytest without explicit node IDs (that would run the whole suite)."
    exit 1
fi

echo "Resuming ${#TESTS[@]} queued test(s) from ${next_test}:"
printf '  %s\n' "${TESTS[@]}"
echo "Command: ${PYTHON_BIN} -m pytest ${TESTS[*]} -v -s --setup-confirmed --yes"

cd "${REPO_ROOT}" || exit 1
exec "${PYTHON_BIN}" -m pytest "${TESTS[@]}" -v -s --setup-confirmed --yes
