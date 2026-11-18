#!/usr/bin/env bash
# Copyright 2026 Intel Corporation
# SPDX-License-Identifier: Apache-2.0

# =============================================================================
# deploy/setup/setup_sut.sh — One-time SUT setup for firmware validation (SUT-only)
#
# Run this ONCE on the SUT before running any SUT-only test cases.
# It is safe to re-run — all steps are idempotent.
#
# Usage:
#   chmod +x deploy/setup/setup_sut.sh
#   sudo ./deploy/setup/setup_sut.sh --nopasswd-all         # test boards: setup + passwordless sudo for ALL commands
#   sudo ./deploy/setup/setup_sut.sh                        # exact passwordless sudo rules only (secure default)
#   sudo ./deploy/setup/setup_sut.sh --add-nopasswd-all     # only add the ALL rule to a board that is already set up
#   sudo ./deploy/setup/setup_sut.sh --no-nopasswd-all      # exact rules only, and remove the ALL rule if set before
#   sudo ./deploy/setup/setup_sut.sh --remove-nopasswd-all  # only remove the ALL rule, e.g. when testing is done
#   sudo ./deploy/setup/setup_sut.sh --uninstall [--dry-run] # undo this setup when testing is done
#   (a re-run without --nopasswd-all / --no-nopasswd-all keeps the earlier choice)
#
# No USB drive is needed: the tests keep their reboot state in <repo>/logs/sut_state.
#
# What this does:
#   1. Checks the EFI partition is mounted
#   2. Copies startup.nsh to /boot/efi/startup.nsh
#   3. Installs system packages (tpm2-tools, efibootmgr, msr-tools, dmidecode)
#      and loads the msr kernel module
#   4. Creates Python venv and installs requirements
#   5. Configures passwordless sudo for test commands (exact rules); with --nopasswd-all
#      also for ALL commands (/etc/sudoers.d/fw-validation-all, see SECURITY.md)
#   6. Generates + enables fw-validation-resume.service (auto-detect paths)
#   7. Creates FW-Validation Shell UEFI boot entry (upstream EDK2 shell via
#      deploy/secure_boot/fetch_uefi_shell.sh; Ubuntu's efi-shell-x64 only as fallback)
#   8. Stages external tools from Downloads/ via deploy_tools.py (skipped
#      with instructions if Downloads/ is empty -- those are licensed files
#      you fetch yourself; re-run this script once they're in place)
#   9. Swap for S4 hibernate (VT-d test): without a swap partition, grows the
#      swap file (/swap.img) to the RAM size (HIBERNATE_SWAP_GB=<n> overrides);
#      never creates or changes partitions
#
# After this script completes, the SUT is ready for SUT-only test execution.
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEPLOY_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
PROJECT_ROOT="$(cd "${DEPLOY_DIR}/.." && pwd)"

# Mirror every run's console output to a timestamped log file too, so there's
# a persistent record of each setup_sut.sh run, not just whatever scrolled by.
mkdir -p "${PROJECT_ROOT}/logs"
SETUP_LOG="${PROJECT_ROOT}/logs/setup_sut_$(date +%Y%m%d_%H%M%S).log"
exec > >(tee -a "${SETUP_LOG}") 2>&1
echo "Logging output to: ${SETUP_LOG}"

STATE_DIR="${PROJECT_ROOT}/logs/sut_state"
STARTUP_NSH_SRC="${DEPLOY_DIR}/resume/startup.nsh"
# NOTE: deploy/resume/fw-validation-resume.service is a reference template only and is
# deliberately NOT copied — the real unit is generated in Step 6 with paths
# auto-detected for this user/checkout.
SERVICE_DEST="/etc/systemd/system/fw-validation-resume.service"
EFI_STARTUP="/boot/efi/startup.nsh"
SHELL_BOOT_LABEL="FW-Validation Shell"
# UEFI result files the tests read back and delete when they end (EFI root + tool-folder copy).
EFI_RESULT_FILES=(vtinfo_baseline.txt vtinfo_s3.txt vtinfo_s4.txt vtinfo_s5.txt
                  eom_meinfo_result.txt txt_tpm_prov_result.txt txt_getsec_result.txt)

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

ok()   { echo -e "${GREEN}[OK]${NC}   $*"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
fail() { echo -e "${RED}[FAIL]${NC} $*"; exit 1; }
info() { echo -e "       $*"; }

echo "=============================================="
echo " Firmware Validation — SUT One-Time Setup"
echo "=============================================="
echo ""

# Must run as root
if [[ $EUID -ne 0 ]]; then
    fail "This script must be run with sudo. Use: sudo $0"
fi

# Passwordless sudo for ALL commands (accepted risk, SECURITY.md): off unless --nopasswd-all.
NOPASSWD_ALL=""
NOPASSWD_ALL_FILE="/etc/sudoers.d/fw-validation-all"

write_nopasswd_all() {
    local user="$1" tmp
    id "${user}" >/dev/null 2>&1 || fail "User '${user}' does not exist -- run with: sudo SUDO_USER=<your-login> $0 ..."
    tmp="$(mktemp)"
    printf '%s\n' "# Firmware Validation - passwordless sudo for ALL commands (accepted risk, see SECURITY.md)" \
        "# Remove when testing is done: sudo ./deploy/setup/setup_sut.sh --remove-nopasswd-all" \
        "${user} ALL=(ALL) NOPASSWD: ALL" > "${tmp}"
    visudo -cf "${tmp}" >/dev/null || { rm -f "${tmp}"; fail "Sudoers syntax error -- nothing installed to ${NOPASSWD_ALL_FILE}"; }
    install -o root -g root -m 0440 "${tmp}" "${NOPASSWD_ALL_FILE}"
    rm -f "${tmp}"
    warn "Passwordless sudo for ALL commands enabled for ${user} (dedicated test board only): ${NOPASSWD_ALL_FILE}"
    info "Remove it when testing is done: sudo ./deploy/setup/setup_sut.sh --remove-nopasswd-all"
}

UNINSTALL=0
DRY_RUN=0
for arg in "$@"; do
    case "${arg}" in
        --nopasswd-all)    NOPASSWD_ALL=yes ;;
        --no-nopasswd-all) NOPASSWD_ALL=no ;;
        --add-nopasswd-all)
            write_nopasswd_all "${SUDO_USER:-$(logname 2>/dev/null || echo user)}"
            exit 0 ;;
        --remove-nopasswd-all)
            rm -f "${NOPASSWD_ALL_FILE}"
            ok "Removed ${NOPASSWD_ALL_FILE} -- tests now use only the exact rules in /etc/sudoers.d/fw-validation"
            exit 0 ;;
        --uninstall) UNINSTALL=1 ;;
        --dry-run)   DRY_RUN=1 ;;
        *) fail "Unknown option: ${arg} (options: --nopasswd-all, --no-nopasswd-all, --add-nopasswd-all, --remove-nopasswd-all, --uninstall [--dry-run])" ;;
    esac
done
[[ "${DRY_RUN}" == 0 || "${UNINSTALL}" == 1 ]] || fail "--dry-run only works with --uninstall"
# --uninstall: undo what this script and the test runbooks leave on the SUT. Keeps packages, the venv and logs/.
uninstall() {
    act() { if [[ "${DRY_RUN}" == 1 ]]; then info "would run: $*"; else "$@"; fi; }
    echo "--- Uninstall$([[ "${DRY_RUN}" == 1 ]] && echo ' (dry run: nothing is changed)') ---"

    if [[ -n "$(ls -A /sys/firmware/efi/efivars 2>/dev/null)" ]] && command -v efibootmgr >/dev/null 2>&1; then
        local entries num
        entries="$(efibootmgr 2>/dev/null || true)"
        for num in $(grep "${SHELL_BOOT_LABEL}" <<< "${entries}" | grep -oP 'Boot\K[0-9A-Fa-f]{4}' || true); do
            if grep -q "^BootNext: ${num}" <<< "${entries}"; then
                act efibootmgr -q --delete-bootnext
            fi
            act efibootmgr -q --delete-bootnum --bootnum "${num}"
            ok "Boot entry Boot${num} '${SHELL_BOOT_LABEL}'"
        done
    fi
    if [[ -f /boot/efi/EFI/shell/shellx64.efi ]]; then
        act rm -f /boot/efi/EFI/shell/shellx64.efi
        act rmdir --ignore-fail-on-non-empty /boot/efi/EFI/shell
        ok "/boot/efi/EFI/shell/shellx64.efi"
    fi

    # A startup.nsh that does not run maintest.nsh is not ours: restore it from the backup, never delete it.
    if [[ -f "${EFI_STARTUP}.bak" ]] && ! grep -q maintest.nsh "${EFI_STARTUP}.bak"; then
        act cp "${EFI_STARTUP}.bak" "${EFI_STARTUP}"
        act rm -f "${EFI_STARTUP}.bak"
        ok "${EFI_STARTUP} restored from ${EFI_STARTUP}.bak"
    else
        if [[ -f "${EFI_STARTUP}" ]] && grep -q maintest.nsh "${EFI_STARTUP}"; then
            act rm -f "${EFI_STARTUP}"
            ok "${EFI_STARTUP}"
        fi
        if [[ -f "${EFI_STARTUP}.bak" ]]; then
            act rm -f "${EFI_STARTUP}.bak"
        fi
    fi
    local f
    for f in /boot/efi/maintest.nsh /boot/efi/state_done.txt \
             "${EFI_RESULT_FILES[@]/#//boot/efi/}" "${EFI_RESULT_FILES[@]/#//boot/efi/EFI/}"; do
        if [[ -f "${f}" ]]; then
            act rm -f "${f}"
            ok "${f}"
        fi
    done

    local unit reload=0
    for unit in fw-validation-resume fw-secure-boot-resume fw-bios-knob-resume fw-preflight-resume; do
        if [[ -f "/etc/systemd/system/${unit}.service" ]]; then
            act systemctl disable --quiet "${unit}.service"
            act rm -f "/etc/systemd/system/${unit}.service"
            ok "${unit}.service"
            reload=1
        fi
    done
    if [[ "${reload}" == 1 ]]; then
        act systemctl daemon-reload
    fi

    for f in /etc/sudoers.d/fw-validation "${NOPASSWD_ALL_FILE}" /etc/sudoers.d/bios_security_automation; do
        if [[ -f "${f}" ]]; then
            act rm -f "${f}"
            ok "${f}"
        fi
    done

    # Remove only what the VT-d test added (resume= / resume_offset=), keeping any later GRUB edits.
    if [[ -f /etc/default/grub.fwval.bak ]]; then
        if grep -qE '^GRUB_CMDLINE_LINUX=.*\<resume=' /etc/default/grub.fwval.bak; then
            warn "/etc/default/grub already had resume= before the VT-d test -- left as is (see /etc/default/grub.fwval.bak)"
        else
            if grep -qE '^GRUB_CMDLINE_LINUX=.*\<resume=' /etc/default/grub; then
                act cp /etc/default/grub /etc/default/grub.before-fwval-uninstall
                act sed -i -E '/^GRUB_CMDLINE_LINUX=/ s/ ?\<resume(_offset)?=[^" ]*//g' /etc/default/grub
                act update-grub
                ok "/etc/default/grub: resume= removed (old copy: /etc/default/grub.before-fwval-uninstall)"
            fi
            act rm -f /etc/default/grub.fwval.bak
        fi
    fi

    # Secrets: stored BIOS admin password, Secure Boot / MOK signing keys and the test certificate on the ESP.
    for f in /var/lib/fw-validation /etc/secureboot/key-material /root/secureboot /boot/efi/EFI/fw-validation \
             "${PROJECT_ROOT}/logs/mok_enrollment_pending"; do
        if [[ -e "${f}" ]]; then
            act rm -rf "${f}"
            ok "${f}"
        fi
    done

    echo "--- Not undone automatically ---"
    info "Secure Boot keys enrolled in the firmware: BIOS Setup -> Security -> Secure Boot -> Restore Factory Keys"
    info "MOK certificate (if enrolled): sudo mokutil --list-enrolled, then sudo mokutil --delete <cert>"
    info "Signed tool copies on the EFI partition (/boot/efi/EFI/*_signed.efi), swap file size, packages, venv, logs/"
    exit 0
}
[[ "${UNINSTALL}" == 0 ]] || uninstall

# Must be booted in UEFI mode. If Ubuntu was installed with Legacy/CSM BIOS
# boot (no ESP, no /sys/firmware/efi), there is no EFI System Partition to
# mount at /boot/efi and none of the *_sut_func.py UEFI-shell tests (EOM,
# TXT, virtualization, firmware capsule, etc.) will work.
if [[ ! -d /sys/firmware/efi ]]; then
    fail "System is not booted in UEFI mode (/sys/firmware/efi not found).\n" \
         "       Ubuntu must be installed/booted in UEFI mode, not Legacy/CSM BIOS mode.\n" \
         "       Fix: re-flash/reinstall Ubuntu with UEFI boot enabled in the BIOS setup\n" \
         "       (disable CSM/Legacy boot, enable UEFI boot only) before re-running this script."
fi
ok "System booted in UEFI mode"

# Print a short summary of the currently running boot configuration so the
# operator always knows what's active before setup proceeds (or fails).
BOOT_ENTRY_KIND="plain kernel entry (noefi not set)"
grep -qw noefi /proc/cmdline 2>/dev/null && BOOT_ENTRY_KIND="tboot/TXT entry (submenu 'tboot 1.12.1', noefi set)"
EFIVARS_STATE="NOT accessible"
[[ -n "$(ls -A /sys/firmware/efi/efivars 2>/dev/null)" ]] && EFIVARS_STATE="accessible"
echo "--- Current boot state -----------------------------------------------"
info "Running kernel : $(uname -r)"
info "Grub entry     : ${BOOT_ENTRY_KIND}"
info "EFI variables  : ${EFIVARS_STATE}"
echo "------------------------------------------------------------------------"

# The '/sys/firmware/efi' directory can exist even when the kernel was booted
# with 'noefi' (e.g. the tboot/TXT grub entry, submenu "tboot 1.12.1"), which
# disables EFI runtime variable access. efibootmgr (step 7) and Secure Boot
# tooling need live efivars, so fail fast with a clear message instead of
# hitting an opaque efibootmgr/mokutil error later.
if grep -qw noefi /proc/cmdline 2>/dev/null; then
    fail "Kernel booted with 'noefi' (/proc/cmdline) — EFI variables are disabled.\n" \
         "       This SUT looks like it booted the tboot/TXT grub entry (submenu\n" \
         "       'tboot 1.12.1') instead of the plain kernel entry.\n" \
         "       Fix: reboot, select the non-tboot 'Ubuntu, with Linux $(uname -r)' entry\n" \
         "       under 'Advanced options for Ubuntu', then re-run this script."
fi
if [[ -z "$(ls -A /sys/firmware/efi/efivars 2>/dev/null)" ]]; then
    fail "EFI variables are not accessible (/sys/firmware/efi/efivars is empty).\n" \
         "       efibootmgr and Secure Boot enrollment need live EFI variable access.\n" \
         "       Reboot into a non-tboot / non-'noefi' kernel entry and re-run this script."
fi
ok "EFI variables accessible (efivars populated)"

# ------------------------------------------------------------------
# Step 1 — Ensure EFI partition is mounted
# ------------------------------------------------------------------
echo "[1/9] Checking EFI partition..."

if ! mountpoint -q /boot/efi; then
    mount /boot/efi 2>/dev/null || fail "/boot/efi is not mounted and could not be mounted automatically"
fi
ok "/boot/efi is mounted"

# ------------------------------------------------------------------
# Step 2 — Install startup.nsh to EFI partition
# ------------------------------------------------------------------
echo "[2/9] Installing startup.nsh..."

if [[ ! -f "${STARTUP_NSH_SRC}" ]]; then
    fail "startup.nsh not found: ${STARTUP_NSH_SRC}\nRun this script from the project root."
fi

# Backup existing startup.nsh if present
if [[ -f "${EFI_STARTUP}" ]]; then
    cp "${EFI_STARTUP}" "${EFI_STARTUP}.bak"
    warn "Existing ${EFI_STARTUP} backed up to ${EFI_STARTUP}.bak"
fi

cp "${STARTUP_NSH_SRC}" "${EFI_STARTUP}"
ok "startup.nsh installed: ${EFI_STARTUP}"

# ------------------------------------------------------------------
# Step 3 — Install system packages
# ------------------------------------------------------------------
echo "[3/9] Installing system packages..."

PACKAGES=(tpm2-tools efibootmgr python3-venv msr-tools dmidecode p7zip-full)
NEED_INSTALL=()
for pkg in "${PACKAGES[@]}"; do
    if ! dpkg -s "${pkg}" &>/dev/null; then
        NEED_INSTALL+=("${pkg}")
    fi
done

if [[ ${#NEED_INSTALL[@]} -gt 0 ]]; then
    apt-get update -qq
    apt-get install -y "${NEED_INSTALL[@]}"
    ok "Installed: ${NEED_INSTALL[*]}"
else
    ok "All required packages already installed"
fi

# Load MSR kernel module (needed by rdmsr; msr-tools alone isn't enough)
modprobe msr 2>/dev/null && ok "MSR kernel module loaded" || warn "Could not load MSR module (may need reboot)"

# ------------------------------------------------------------------
# Step 4 — Create Python venv and install requirements
# ------------------------------------------------------------------
echo "[4/9] Setting up Python venv..."

REAL_USER="${SUDO_USER:-$(logname 2>/dev/null || echo user)}"
REAL_UID=$(id -u "${REAL_USER}")
REAL_GID=$(id -g "${REAL_USER}")

VENV_DIR="${PROJECT_ROOT}/../venv"
REQUIREMENTS="${PROJECT_ROOT}/requirements.txt"

if [[ ! -d "${VENV_DIR}" ]]; then
    python3 -m venv "${VENV_DIR}"
    chown -R "${REAL_UID}:${REAL_GID}" "${VENV_DIR}"
    ok "venv created: ${VENV_DIR}"
else
    ok "venv already exists: ${VENV_DIR}"
fi

VENV_DIR="$(realpath "${VENV_DIR}")"
PYTHON_BIN="${VENV_DIR}/bin/python3"

if [[ -f "${REQUIREMENTS}" ]]; then
    sudo -u "${REAL_USER}" "${PYTHON_BIN}" -m pip install -q -r "${REQUIREMENTS}"
    ok "Requirements installed from ${REQUIREMENTS}"
else
    warn "requirements.txt not found at ${REQUIREMENTS} — skipping pip install"
fi

# ------------------------------------------------------------------
# Step 5 — Configure passwordless sudo for test commands
# ------------------------------------------------------------------
# bios_scripts/*.sh are run straight from the checkout (no copy to ~/iec62443).
echo "[5/9] Configuring passwordless sudo for test commands..."

SUDOERS_FILE="/etc/sudoers.d/fw-validation"

command -v visudo >/dev/null 2>&1 || fail "visudo not found in PATH (\$PATH=${PATH}) — install the 'sudo' package."

# test_runner.py pre-flight: the Secure Boot / BIOS knob runbooks, the pre-flight chain and
# the reboots it runs with sudo. sudo matches the exact command line, so these use the same
# physical paths test_runner.py passes (repo, venv python). Re-run this script if the
# checkout or the venv moves.
REPO_REAL="$(cd "${PROJECT_ROOT}" && pwd -P)"
PREFLIGHT_RULES="# test_runner.py pre-flight (Secure Boot, BIOS knobs, BIOS Setup reboot) — runs the repo's runbooks as root.
${REAL_USER} ALL=(ALL) NOPASSWD: /usr/bin/bash ${REPO_REAL}/deploy/secure_boot/enable_secure_boot.sh *
${REAL_USER} ALL=(ALL) NOPASSWD: ${REPO_REAL}/deploy/secure_boot/enable_secure_boot.sh *
${REAL_USER} ALL=(ALL) NOPASSWD: /usr/bin/systemctl reboot
${REAL_USER} ALL=(ALL) NOPASSWD: /usr/bin/systemctl reboot --firmware-setup"
for PREFLIGHT_PY in "$(cd "${REPO_REAL}/.." && pwd -P)/venv/bin/python" "${REPO_REAL}/venv/bin/python" /usr/bin/python3; do
    PREFLIGHT_RULES+="
${REAL_USER} ALL=(ALL) NOPASSWD: ${PREFLIGHT_PY} ${REPO_REAL}/deploy/preflight/preflight_chain.py *
${REAL_USER} ALL=(ALL) NOPASSWD: ${PREFLIGHT_PY} ${REPO_REAL}/deploy/bios_knobs/configure_bios_knobs_linux.py *"
done
if [[ "${REPO_REAL}" =~ [[:space:]] ]]; then
    warn "Repo path contains spaces (${REPO_REAL}) — skipping the passwordless pre-flight rules; sudo will ask for a password."
    PREFLIGHT_RULES=""
fi

# ${REAL_USER} must be a real account: an empty or bogus name produces a
# sudoers file that visudo rejects.
id "${REAL_USER}" >/dev/null 2>&1 || \
    fail "Cannot configure sudoers: user '${REAL_USER}' does not exist.\n" \
         "       Re-run as: sudo ./deploy/setup/setup_sut.sh   (not 'su -' / direct root login)\n" \
         "       or force it: sudo SUDO_USER=<your-login> ./deploy/setup/setup_sut.sh"

# Validate on a temp file first so a bad fragment is never installed, and so an
# existing working /etc/sudoers.d/fw-validation is left intact on failure.
# sudo matches the resolved command path literally. Ubuntu 24.04 installs efibootmgr in
# /usr/bin (the package ships /bin/efibootmgr), older releases / other distros in /usr/sbin:
# a rule for the wrong one makes "sudo efibootmgr --bootnext" ask for a password, which
# fails when a test is resumed after a reboot (no terminal) -- the SUT then boots Ubuntu
# instead of the UEFI Shell and the batch stops. Cover both, plus wherever it is now.
EFIBOOTMGR_RULES=""
for EFIBOOTMGR_PATH in /usr/bin/efibootmgr /usr/sbin/efibootmgr "$(command -v efibootmgr || true)"; do
    [[ -n "${EFIBOOTMGR_PATH}" && "${EFIBOOTMGR_RULES}" != *"NOPASSWD: ${EFIBOOTMGR_PATH} *"* ]] || continue
    EFIBOOTMGR_RULES+="${REAL_USER} ALL=(ALL) NOPASSWD: ${EFIBOOTMGR_PATH}
${REAL_USER} ALL=(ALL) NOPASSWD: ${EFIBOOTMGR_PATH} *
"
done
EFIBOOTMGR_RULES="${EFIBOOTMGR_RULES%$'\n'}"
# UEFI result files the tests delete when they end: EFI root + tool-folder copy (exact names, see NOTE below).
EFI_RESULT_RULES=""
for RESULT_FILE in "${EFI_RESULT_FILES[@]}"; do
    for RESULT_DIR in /boot/efi /boot/efi/EFI; do
        EFI_RESULT_RULES+="${REAL_USER} ALL=(ALL) NOPASSWD: /usr/bin/rm -f ${RESULT_DIR}/${RESULT_FILE}
"
    done
done
EFI_RESULT_RULES+="${REAL_USER} ALL=(ALL) NOPASSWD: /usr/bin/rm -f /boot/efi/TPM2ProvfilesCBnT/txt_tpm_prov_result.txt"
SUDOERS_TMP="$(mktemp)"
cat > "${SUDOERS_TMP}" << SUDOEOF
# Firmware Validation - passwordless sudo for test automation
# Auto-generated by deploy/setup/setup_sut.sh - safe to re-run
#
# NOTE: sudo-rs (the Rust sudo now default on recent Ubuntu) rejects wildcards
# mixed with literal characters in a command argument (e.g. "/boot/efi/*") --
# it only allows a bare "*" as the whole final argument. The code only ever
# tee's/rm's these exact fixed filenames under /boot/efi, so list them
# explicitly instead of globbing (core/uefi_script_manager.py, tests/firmware).
${REAL_USER} ALL=(ALL) NOPASSWD: /usr/bin/tee /boot/efi/maintest.nsh
${REAL_USER} ALL=(ALL) NOPASSWD: /usr/bin/tee /boot/efi/startup.nsh
${REAL_USER} ALL=(ALL) NOPASSWD: /usr/bin/rm -f /boot/efi/maintest.nsh
${REAL_USER} ALL=(ALL) NOPASSWD: /usr/bin/rm -f /boot/efi/state_done.txt
${EFI_RESULT_RULES}
${EFIBOOTMGR_RULES}
${REAL_USER} ALL=(ALL) NOPASSWD: /usr/bin/tpm2_getcap *
${REAL_USER} ALL=(ALL) NOPASSWD: /usr/bin/tpm2_nvreadpublic *
${REAL_USER} ALL=(ALL) NOPASSWD: /usr/sbin/reboot
${REAL_USER} ALL=(ALL) NOPASSWD: /usr/sbin/rdmsr *
${REAL_USER} ALL=(ALL) NOPASSWD: /usr/sbin/dmidecode *
# BIOS Resiliency test: find the Obb.bin backup on the root-only ESP (exact arguments only).
${REAL_USER} ALL=(ALL) NOPASSWD: /usr/bin/find /boot/efi -iname obb.bin -type f -ls
${PREFLIGHT_RULES}
# VT-d (S3/S4/S5) and every OS-phase S5 reboot: rtcwake.
${REAL_USER} ALL=(ALL) NOPASSWD: /usr/sbin/rtcwake *
# VT-d S3/S4: disable non-RTC wake sources for the sleep cycle (device name on stdin).
${REAL_USER} ALL=(ALL) NOPASSWD: /usr/bin/tee /proc/acpi/wakeup
# VT-d Step 5.6: resume= / resume_offset= in GRUB for S4 (exact files from virtualization_config.yaml).
${REAL_USER} ALL=(ALL) NOPASSWD: /usr/bin/cp -p /etc/default/grub /etc/default/grub.fwval.bak
${REAL_USER} ALL=(ALL) NOPASSWD: /usr/bin/tee /etc/default/grub
${REAL_USER} ALL=(ALL) NOPASSWD: /usr/sbin/update-grub
${REAL_USER} ALL=(ALL) NOPASSWD: /usr/bin/cat /boot/grub/grub.cfg
# VT-d S4 to a swap file: physical offset of the root-only swap file (read-only).
${REAL_USER} ALL=(ALL) NOPASSWD: /usr/sbin/filefrag -v *
SUDOEOF
# Strip CR: if this script was checked out with Windows CRLF endings, every
# heredoc line would carry a trailing \r and visudo rejects the whole file.
sed -i 's/\r$//' "${SUDOERS_TMP}"
chmod 0440 "${SUDOERS_TMP}"

if ! VISUDO_OUT="$(visudo -cf "${SUDOERS_TMP}" 2>&1)"; then
    echo "--- visudo error ----------------------------------------------------"
    echo "${VISUDO_OUT}"
    echo "--- generated fragment ----------------------------------------------"
    cat -A "${SUDOERS_TMP}"
    echo "---------------------------------------------------------------------"
    rm -f "${SUDOERS_TMP}"
    fail "Sudoers syntax error — nothing installed to ${SUDOERS_FILE}"
fi

install -o root -g root -m 0440 "${SUDOERS_TMP}" "${SUDOERS_FILE}"
rm -f "${SUDOERS_TMP}"

grep -Eq '^\s*(@includedir|#includedir)\s+/etc/sudoers\.d' /etc/sudoers || \
    warn "/etc/sudoers has no includedir for /etc/sudoers.d — ${SUDOERS_FILE} will be ignored"

ok "Sudoers configured: ${SUDOERS_FILE}"

# Some tests still sudo commands the exact rules above do not cover (MEInfo, TXT /dev/mem reads,
# checkquote.sh, the AES-NI script): without this they ask for a password, or fail after a reboot.
if [[ -z "${NOPASSWD_ALL}" ]]; then
    [[ -f "${NOPASSWD_ALL_FILE}" ]] && NOPASSWD_ALL=yes || NOPASSWD_ALL=no   # a re-run keeps the earlier choice
fi
if [[ "${NOPASSWD_ALL}" == yes ]]; then
    write_nopasswd_all "${REAL_USER}"
else
    rm -f "${NOPASSWD_ALL_FILE}"
    OTHER_ALL="$(grep -lE '^[^#]*NOPASSWD: *ALL' /etc/sudoers.d/* 2>/dev/null || true)"
    if [[ -n "${OTHER_ALL}" ]]; then
        ok "Passwordless sudo for all commands is already granted by ${OTHER_ALL//$'\n'/, }"
        info "-- the tests will not ask for a password"
    else
        warn "Passwordless sudo covers only the exact test commands. These tests will ask for your"
        info "password during the test, and dTPM / fTPM / TXT fail after their reboot:"
        info "  CSME UPID, RPMC, Secure Debug, AES-NI, VT-d, dTPM, fTPM, TXT"
        info "On a dedicated test board, run once:  sudo ./deploy/setup/setup_sut.sh --add-nopasswd-all"
        info "(or start the tests from test_runner.py -- it offers to enable it)"
    fi
fi

# ------------------------------------------------------------------
# Step 6 — Install and enable systemd service
# ------------------------------------------------------------------
echo "[6/9] Installing systemd service..."

info "Project root : ${PROJECT_ROOT}"
info "User         : ${REAL_USER}"
info "Python       : ${PYTHON_BIN}"
info "State folder : ${STATE_DIR}"

RESUME_LOG="${PROJECT_ROOT}/logs/resume_service.log"
mkdir -p "${STATE_DIR}"
chown "${REAL_UID}:${REAL_GID}" "${PROJECT_ROOT}/logs" "${STATE_DIR}"
chmod 0700 "${STATE_DIR}"

RESUME_RUNNER="${DEPLOY_DIR}/resume/fw_validation_resume.sh"
[ -f "${RESUME_RUNNER}" ] || fail "Resume runner not found: ${RESUME_RUNNER}"
chmod +x "${RESUME_RUNNER}"

# NOTE: the resume logic MUST live in a standalone script, not an inline
# `bash -c` ExecStart.  systemd expands "$VAR"/"${VAR}" in ExecStart itself and
# treats "${TESTS[@]}" as an invalid variable name, substituting an EMPTY
# STRING.  pytest then runs with no node IDs and collects the whole repo
# instead of resuming the queued test, so multi-phase tests never continue
# after their reboot.
cat > "${SERVICE_DEST}" << SVCEOF
[Unit]
Description=Firmware Validation Test Resume
After=network.target local-fs.target

[Service]
Type=oneshot
User=${REAL_USER}
WorkingDirectory=${PROJECT_ROOT}
Environment=STATE_DIR=${STATE_DIR}
Environment=EFI_MOUNT=/boot/efi
Environment=PYTHON_BIN=${PYTHON_BIN}
Environment=RESUME_LOG=${RESUME_LOG}
ExecStart=${RESUME_RUNNER}
StandardOutput=journal+console
StandardError=journal+console
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
SVCEOF

systemctl daemon-reload
systemctl enable fw-validation-resume.service

ok "fw-validation-resume.service generated and enabled"
info "  User=${REAL_USER}  WorkingDirectory=${PROJECT_ROOT}"
info "  Python=${PYTHON_BIN}  State=${STATE_DIR}"

# The resumed run has no window of its own (it starts before login): open the status window at desktop login.
if sudo -H -u "${REAL_USER}" python3 "${DEPLOY_DIR}/resume/status_window.py" --install >/dev/null; then
    ok "Login status window installed: shows the batch, its reboots and the next BIOS step after every reboot"
else
    warn "Could not install the login window -- run as ${REAL_USER}: python3 deploy/resume/status_window.py --install"
fi

# ------------------------------------------------------------------
# Step 7 — Install FW-Validation Shell UEFI boot entry
# ------------------------------------------------------------------
echo "[7/9] Installing FW-Validation Shell UEFI boot entry..."

SHELL_EFI_SRC="${PROJECT_ROOT}/Tools/shellx64.efi"
# Ubuntu's efi-shell-x64 exits immediately under Secure Boot (CVE-2025-2486).
if ! "${DEPLOY_DIR}/secure_boot/fetch_uefi_shell.sh" "${SHELL_EFI_SRC}"; then
    warn "Falling back to Ubuntu's efi-shell-x64 -- UEFI-shell tests will NOT run with Secure Boot on."
    SHELL_EFI_SRC="/usr/share/efi-shell-x64/shellx64.efi"
fi
SHELL_EFI_DEST="/boot/efi/EFI/shell/shellx64.efi"

# Install efi-shell-x64 package if shellx64.efi not present
if [[ ! -f "${SHELL_EFI_SRC}" ]]; then
    info "Installing efi-shell-x64 package..."
    apt-get install -y efi-shell-x64 2>/dev/null || \
        fail "Could not install efi-shell-x64. Run: sudo apt-get install -y efi-shell-x64"
fi

shell_exits_under_secure_boot() {
    LC_ALL=C grep -qaP 'S\x00e\x00t\x00u\x00p\x00M\x00o\x00d\x00e\x00' "$1"
}

# Keep a shell that sign_efi_tools.sh already signed in place -- overwriting it
# with the unsigned package copy makes Secure Boot refuse the boot entry.
if [[ -f "${SHELL_EFI_DEST}" ]] && command -v sbverify >/dev/null 2>&1 \
    && sbverify --list "${SHELL_EFI_DEST}" 2>/dev/null | grep '^signature' >/dev/null \
    && ! shell_exits_under_secure_boot "${SHELL_EFI_DEST}"; then
    ok "shellx64.efi already present and signed, keeping it: ${SHELL_EFI_DEST}"
else
    mkdir -p "$(dirname "${SHELL_EFI_DEST}")"
    cp "${SHELL_EFI_SRC}" "${SHELL_EFI_DEST}"
    ok "shellx64.efi installed: ${SHELL_EFI_DEST} (from ${SHELL_EFI_SRC})"
    if shell_exits_under_secure_boot "${SHELL_EFI_DEST}"; then
        warn "${SHELL_EFI_SRC} is Ubuntu's efi-shell-x64 build: it exits immediately when Secure Boot\n" \
             "       is enabled, so UEFI-shell tests cannot run with Secure Boot on. Stage an upstream\n" \
             "       EDK2 shell at ${PROJECT_ROOT}/Tools/shellx64.efi and rerun this script."
    fi
    if command -v mokutil >/dev/null 2>&1 \
        && grep -qi "secureboot enabled" <<< "$(mokutil --sb-state 2>/dev/null || true)"; then
        warn "Secure Boot is enabled and ${SHELL_EFI_DEST} is unsigned -- the firmware will refuse to boot it.\n" \
             "       Sign it in place:  sudo ./deploy/secure_boot/sign_efi_tools.sh"
    fi
fi

# Detect EFI disk and partition number from /boot/efi mount
EFI_DEVICE=$(findmnt -n -o SOURCE /boot/efi)
EFI_DISK=$(echo "${EFI_DEVICE}" | sed 's/p\?[0-9]*$//')
EFI_PART=$(echo "${EFI_DEVICE}" | grep -oP '[0-9]+$')

if [[ -z "${EFI_DISK}" || -z "${EFI_PART}" ]]; then
    warn "Could not detect EFI disk/partition — skipping efibootmgr entry"
else
    # Remove existing FW-Validation Shell entry if present (idempotent)
    EXISTING=$(efibootmgr | grep "${SHELL_BOOT_LABEL}" | grep -oP 'Boot\K[0-9A-Fa-f]{4}' || true)
    if [[ -n "${EXISTING}" ]]; then
        efibootmgr --delete-bootnum --bootnum "${EXISTING}" > /dev/null 2>&1 || true
        info "Removed existing boot entry: Boot${EXISTING}"
    fi

    # Create new entry — NOT added to BootOrder (used only via --bootnext)
    efibootmgr --create-only \
        --disk "${EFI_DISK}" \
        --part "${EFI_PART}" \
        --label "${SHELL_BOOT_LABEL}" \
        --loader "\\EFI\\shell\\shellx64.efi" > /dev/null

    NEW_NUM=$(efibootmgr | grep "${SHELL_BOOT_LABEL}" | grep -oP 'Boot\K[0-9A-Fa-f]{4}' | head -1)
    ok "UEFI boot entry created: Boot${NEW_NUM} '${SHELL_BOOT_LABEL}'"
    ok "Entry is NOT in BootOrder — used only via efibootmgr --bootnext during tests"
fi

# ------------------------------------------------------------------
# Step 8 — Stage external tools (deploy/tools/deploy_tools.py)
# ------------------------------------------------------------------
echo "[8/9] Staging external tools (deploy/tools/deploy_tools.py)..."

DEPLOY_TOOLS_PY="${DEPLOY_DIR}/tools/deploy_tools.py"
DOWNLOADS_DIR="${PROJECT_ROOT}/Downloads"
TOOLS_STATUS="skipped"

# Whether Downloads/ was populated before this script ran or not, run
# deploy_tools.py interactively whenever there's an actual terminal attached
# (stdin is a tty) -- it then prompts for any missing/ambiguous tool right
# here (download it, press [C]/[R] to retry) instead of silently skipping it.
# Only fall back to unattended --yes when stdin isn't a tty (CI/scripted runs),
# where skipping early on an empty Downloads/ avoids hanging on a prompt no one
# can answer.
if [[ -t 0 ]]; then
    DEPLOY_ARGS=()
elif [[ ! -d "${DOWNLOADS_DIR}" || -z "$(ls -A "${DOWNLOADS_DIR}" 2>/dev/null)" ]]; then
    DEPLOY_ARGS=()
    warn "No files in Downloads/ yet — skipping tool staging for now (non-interactive run)."
    info "Get the tools listed in doc/DEPENDENCIES.md, drop them into Downloads/,"
    info "then re-run this script (safe to re-run), or stage them without redoing"
    info "the rest of setup: sudo ${PYTHON_BIN} deploy/tools/deploy_tools.py --yes"
    TOOLS_STATUS="skip_noninteractive"
else
    DEPLOY_ARGS=(--yes)
fi

if [[ "${TOOLS_STATUS}" != "skip_noninteractive" ]]; then
    # Already running as root (this script requires sudo), so this single pass
    # both stages Downloads/ -> ./Tools/ AND copies EFI-bound tools onto
    # /boot/efi — the same two things doc/TEST_GUIDE.md previously described
    # as a separate manual command. deploy_tools.py's exit code reflects
    # whether every applicable tool was actually staged, not just "it ran".
    if "${PYTHON_BIN}" "${DEPLOY_TOOLS_PY}" "${DEPLOY_ARGS[@]}"; then
        TOOLS_STATUS="staged"
        ok "External tools staged (see logs/deploy_tools_*.log for details)"
    else
        TOOLS_STATUS="partial"
        warn "External tools: some were missing/skipped — see logs/deploy_tools_*.log"
        info "Get any missing tools from doc/DEPENDENCIES.md into Downloads/, then re-run:"
        info "  sudo ${PYTHON_BIN} deploy/tools/deploy_tools.py"
    fi
    # It ran as root; hand ownership of what it wrote back to the real user,
    # same as the venv chown above.
    [[ -d "${PROJECT_ROOT}/Tools" ]] && chown -R "${REAL_UID}:${REAL_GID}" "${PROJECT_ROOT}/Tools"
    chown "${REAL_UID}:${REAL_GID}" "${PROJECT_ROOT}"/logs/deploy_tools_*.log 2>/dev/null || true
fi

# ------------------------------------------------------------------
# Step 9 — Swap for S4 hibernate (VT-d test)
# ------------------------------------------------------------------
# The VT-d test hibernates (S4). A swap partition is used as is. Without one,
# the kernel hibernates to the swap file (resume=UUID=<fs> resume_offset=<block>,
# set in GRUB by the test at Step 5.6), so the file must hold the hibernation
# image: it is grown to the RAM size (HIBERNATE_SWAP_GB=<n> overrides).
# Partitions are never created or changed here.
echo "[9/9] Checking swap for S4 hibernate (VT-d test)..."
SWAP_STATUS="unchanged"
# Captured first: with pipefail, "swapon | grep -q" can fail when grep exits early.
SWAP_LIST="$(swapon --show=NAME,TYPE --noheadings 2>/dev/null || true)"
SWAP_PART="$(awk '$2 == "partition" {print $1; exit}' <<< "${SWAP_LIST}")"
if [[ -n "${SWAP_PART}" ]]; then
    ok "Swap partition active: ${SWAP_PART}"
    SWAP_STATUS="partition"
else
    SWAP_FILE="$(awk '$2 == "file" {print $1; exit}' <<< "${SWAP_LIST}")"
    SWAP_FILE="${SWAP_FILE:-/swap.img}"
    MEM_BYTES=$(( $(awk '/^MemTotal:/ {print $2}' /proc/meminfo) * 1024 ))
    GIB=$(( 1024 * 1024 * 1024 ))
    if [[ -n "${HIBERNATE_SWAP_GB:-}" ]]; then
        [[ "${HIBERNATE_SWAP_GB}" =~ ^[1-9][0-9]*$ ]] || fail "HIBERNATE_SWAP_GB must be a whole number of GiB, got '${HIBERNATE_SWAP_GB}'"
        WANT_BYTES=$(( HIBERNATE_SWAP_GB * GIB ))
    else
        WANT_BYTES=$(( (MEM_BYTES + GIB - 1) / GIB * GIB ))
    fi
    CUR_BYTES=$(stat -c %s "${SWAP_FILE}" 2>/dev/null || echo 0)
    SWAP_DIR="$(dirname "${SWAP_FILE}")"
    SWAP_FS="$(findmnt -no FSTYPE -T "${SWAP_DIR}" 2>/dev/null || true)"
    AVAIL_BYTES=$(df --output=avail -B1 "${SWAP_DIR}" 2>/dev/null | tail -1 | tr -d ' ')
    SWAP_USED=$(swapon --show=NAME,USED --bytes --noheadings 2>/dev/null | awk -v f="${SWAP_FILE}" '$1 == f {print $2}')
    MEM_AVAIL=$(( $(awk '/^MemAvailable:/ {print $2}' /proc/meminfo) * 1024 ))
    info "Swap file ${SWAP_FILE}: $(( CUR_BYTES / GIB )) GiB, wanted $(( WANT_BYTES / GIB )) GiB (RAM $(( MEM_BYTES / GIB )) GiB), fs ${SWAP_FS:-?}"

    if (( CUR_BYTES >= WANT_BYTES )); then
        ok "Swap file large enough for hibernation: ${SWAP_FILE}"
        SWAP_STATUS="file_ok"
    elif [[ "${SWAP_FS}" != "ext4" && "${SWAP_FS}" != "xfs" ]]; then
        warn "Swap file ${SWAP_FILE} is on '${SWAP_FS:-unknown}' -- only ext4/xfs swap files are prepared here."
        info "Create a swap partition (lsblk) or a swap file of $(( WANT_BYTES / GIB )) GiB on ext4 for the VT-d S4 step."
        SWAP_STATUS="file_small"
    elif (( ${AVAIL_BYTES:-0} + CUR_BYTES < WANT_BYTES + GIB )); then
        warn "Not enough free space in ${SWAP_DIR} to grow ${SWAP_FILE} to $(( WANT_BYTES / GIB )) GiB."
        info "Free space, or re-run with a smaller target: sudo HIBERNATE_SWAP_GB=<n> ./deploy/setup/setup_sut.sh"
        SWAP_STATUS="file_small"
    elif (( ${SWAP_USED:-0} + GIB > MEM_AVAIL )); then
        warn "${SWAP_FILE} holds $(( ${SWAP_USED:-0} / GIB )) GiB that would not fit in free RAM -- not turning it off now."
        info "Close applications (or reboot) and re-run this script."
        SWAP_STATUS="file_small"
    else
        info "Growing ${SWAP_FILE} to $(( WANT_BYTES / GIB )) GiB (swapoff, recreate, mkswap, swapon)..."
        if awk -v f="${SWAP_FILE}" '$1 == f {found=1} END {exit !found}' <<< "${SWAP_LIST}"; then
            swapoff "${SWAP_FILE}"
        fi
        rm -f "${SWAP_FILE}"
        fallocate -l "${WANT_BYTES}" "${SWAP_FILE}"
        chmod 600 "${SWAP_FILE}"
        mkswap "${SWAP_FILE}" >/dev/null
        swapon "${SWAP_FILE}"
        if ! awk -v f="${SWAP_FILE}" '$1 == f && $3 == "swap" {found=1} END {exit !found}' /etc/fstab; then
            printf '%s\tnone\tswap\tsw\t0\t0\n' "${SWAP_FILE}" >> /etc/fstab
            info "Added ${SWAP_FILE} to /etc/fstab"
        fi
        ok "Swap file ready for hibernation: ${SWAP_FILE} ($(( WANT_BYTES / GIB )) GiB)"
        info "Its block offset changed: the VT-d test updates resume_offset in GRUB and reboots once."
        SWAP_STATUS="file_grown"
    fi
fi

# ------------------------------------------------------------------
# Summary
# ------------------------------------------------------------------
echo ""
echo "=============================================="
echo " Setup Complete"
echo "=============================================="
echo ""
ok "State folder  : ${STATE_DIR}"
ok "startup.nsh   : ${EFI_STARTUP}"
ok "Python venv   : ${VENV_DIR}"
ok "Sudoers       : ${SUDOERS_FILE}"
ok "systemd       : fw-validation-resume.service (auto-generated)"
ok "UEFI shell    : ${SHELL_EFI_DEST} + Boot${NEW_NUM:-????} '${SHELL_BOOT_LABEL}'"
case "${TOOLS_STATUS}" in
    staged)              ok   "External tools: staged from Downloads/ into ./Tools/ (+ EFI copy)" ;;
    partial)             warn "External tools: some missing/skipped — see logs/deploy_tools_*.log" ;;
    skip_noninteractive) warn "External tools: NOT staged yet — Downloads/ was empty" ;;
    *)                   warn "External tools: NOT staged yet — Downloads/ was empty" ;;
esac
case "${SWAP_STATUS}" in
    partition)  ok   "S4 swap       : swap partition" ;;
    file_ok)    ok   "S4 swap       : swap file large enough (${SWAP_FILE})" ;;
    file_grown) ok   "S4 swap       : swap file grown (${SWAP_FILE})" ;;
    *)          warn "S4 swap       : too small for hibernation -- the VT-d S4 step will fail (see step 9 above)" ;;
esac
echo ""
echo "Next steps:"
info "1. Copy test-specific files to EFI partition (if needed):"
info "   sudo cp <TPM prov files>  /boot/efi/EFI/<tpm_prov_dir>/"
info "   sudo cp getsec64.efi      /boot/efi/EFI/"
info "   sudo cp SINIT_ACM.bin     /boot/efi/EFI/"
info ""
info "2. Update config/suites/<test>_config.yaml for your platform."
info ""
info "3. Run the tests from the repo folder (no venv activation needed):"
info "   python3 test_runner.py"
info "   Pick the tests; the pre-flight then sets the BIOS knobs and Secure Boot they need"
info "   (AMI BIOS: AMISCE; other BIOS: list + reboot into BIOS Setup) and runs the tests."
info ""
info "   Direct pytest instead (no pre-flight):"
info "   source ${VENV_DIR}/bin/activate"
info "   python -m pytest tests/txt/test_ec62443_txt_sut_func.py \\"
info "       -v -s --setup-confirmed --yes"
info ""
info "View logs:"
info "   cat ${PROJECT_ROOT}/logs/resume_service.log"
info "   sudo journalctl -u fw-validation-resume.service --no-pager"
info "   ls  ${PROJECT_ROOT}/logs/test_run_*/"
echo ""
info "This run's full log: ${SETUP_LOG}"

# Script ran as root throughout; hand the log file back to the real user.
chown "${REAL_UID}:${REAL_GID}" "${SETUP_LOG}" 2>/dev/null || true
