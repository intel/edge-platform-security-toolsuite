#!/usr/bin/env bash
# Copyright 2026 Intel Corporation
# SPDX-License-Identifier: Apache-2.0

# NOTE: the 'sign' stage does NOT auto-reboot on purpose — you must reboot by
#       hand and watch for the blue 'MOK Manager' screen to enroll the key.
#       The 'modules' and 'provision' stages auto-reboot (AUTO_REBOOT=0 to opt out).
# =============================================================================
# deploy/secure_boot/enable_secure_boot.sh — Enable UEFI Secure Boot on the SUT (runbook)
#
# This is a PROVISIONING runbook, NOT a test.  It CHANGES firmware/key state:
# it generates a MOK, signs the kernel + modules, and enrolls PK/KEK/Microsoft
# DB certificates.  It mirrors doc/reference/secure_boot_linux.pdf step-by-step.
#
# It is stage-based and re-runnable: the operator runs one stage, performs the
# reboot / manual action it prints, then runs the next stage.  There is no
# hidden state file to maintain — each stage inspects the system and is safe to
# re-run.
#
#   Stage 1  sign      Install tools, generate MOK, sign the kernel,
#                      import the MOK (you set the password) → reboot + enroll
#                      at the blue "MOK Manager" screen.
#   Stage 2  modules   Sign every kernel module, rebuild initramfs + grub
#                      → AUTO-REBOOT.
#   Stage 3  provision Enroll OUR keys with deploy/secure_boot/sb_enroll.py in one
#                      run: db = Microsoft + ours, KEK = Microsoft + ours, PK =
#                      ours (written last), then read back → AUTO-REBOOT.
#                      In Setup Mode it first creates a fresh 10-year key when
#                      ours is missing or expiring (sb-setup's 30-day cert and
#                      sbvarsign's off-by-one month made AMI refuse the PK).
#                      Needs a BIOS WITHOUT factory keys (Setup Mode): if PK is
#                      someone else's (e.g. AMI "Platform Key"), 'auto' asks y/n and
#                      reboots into BIOS Setup to delete all keys (no software can),
#                      then continues by itself after Save & Exit.
#   (auto)   enable    Right after 'provision' (the 'Secure Boot' knob cannot be
#                      switched on while no PK is enrolled, so keys always come first):
#                      sign every .efi tool (adds our cert to db), then turn the
#                      'Secure Boot' knob on, first way that works on this BIOS:
#                      1. AMI: write its SecureBootSetup EFI variable from Linux
#                         (sb_enroll.py secure-boot-on; only with our keys in
#                         PK/KEK/db) → one reboot
#                      2. AMISCE ("Secure Boot" = Enabled, "Secure Boot Mode" =
#                         Custom, "Factory Key Provision" = Disabled; UEFI Shell reboots)
#                      3. BIOS Setup: y/n when someone is at the console; when the
#                         keys were enrolled unattended (after deleting factory keys),
#                         reboots straight into it — the operator is told up front
#                      A way that did not work is remembered per BIOS build and
#                      skipped there next time (some AMI builds ignore AMISCE for
#                      this knob: the import reports success, the value stays Disabled).
#                      Not needed at all when the knob is already Enabled: Secure
#                      Boot is then active after the next reboot.
#   Stage 4  verify    Check `mokutil --sb-state` == enabled AND that PK/KEK hold
#                      OUR certificate (deploy/secure_boot/sb_keys.py — factory keys are
#                      refused), then sign every staged .efi tool
#                      (deploy/secure_boot/sign_efi_tools.sh) with that db key so
#                      UEFI-shell/grouping test cases can run.
#
#   KEY OWNERSHIP: Secure Boot only counts as done when the firmware holds OUR
#   keys (PK/KEK = /etc/secureboot/key-material/test-cert.pem, compared byte for
#   byte) — with factory keys the firmware refuses every tool we sign, and db
#   cannot be changed from the OS. `python3 deploy/secure_boot/sb_keys.py status`
#   shows the owner.
#
#   auto     One command for all of the above (test_runner.py pre-flight runs
#            it): picks the next stage from the progress file, the key owner
#            and the live Secure Boot state. It runs sign -> modules -> provision ->
#            enable back to back (a reboot only for the blue MOK Manager screen, or
#            a BIOS Setup visit) and installs a temporary systemd unit
#            (fw-secure-boot-resume.service) that continues after each reboot and
#            removes itself at the end or on any failure. 'sign' (MOK password) and
#            the blue MOK Manager screen stay manual on purpose.
#            When test_runner.py's pre-flight started it (logs/preflight_plan.json),
#            'auto' reports to deploy/preflight/preflight_chain.py once Secure Boot
#            is verified, which runs the next pre-flight step or the tests.
#            'auto --no-reboot' (used by test_runner.py) leaves every reboot to the caller.
#
# Usage (run ON the SUT):
#   chmod +x deploy/secure_boot/enable_secure_boot.sh
#
#   # --- one command (recommended) ---
#   sudo ./deploy/secure_boot/enable_secure_boot.sh auto
#   # ... reboot, enroll MOK; the rest runs by itself ...
#
#   # --- PDF procedure (interactive MOK, for a custom kernel) ---
#   sudo ./deploy/secure_boot/enable_secure_boot.sh sign
#   # ... reboot, enroll MOK ...
#   sudo ./deploy/secure_boot/enable_secure_boot.sh modules
#   # ... reboot ... (AUTOMATIC — modules reboots itself when done)
#   sudo ./deploy/secure_boot/enable_secure_boot.sh provision
#   # ... reboot, verify Secure Boot in BIOS ... (AUTOMATIC reboot; BIOS check is manual)
#   sudo ./deploy/secure_boot/enable_secure_boot.sh verify
#
# Optional overrides (environment variables — defaults are sensible):
#   KEY_DIR          Where MOK keys live            (default: /root/secureboot)
#   KEY_CN           Certificate common name        (default: "Custom Ubuntu Kernel")
#   KEY_DAYS         Certificate validity in days   (default: 3650)
#   KERNEL_IMAGE     Kernel to sign                 (default: /boot/vmlinuz-$(uname -r))
#   QA_REPO_URL      Source of the Microsoft KEK/db certificates, only cloned when
#                    DB_KEY_DIR has no microsoft-*.siglist (default: launchpad qa-regression-testing)
#   QA_REPO_DIR      Local clone dir                (default: /root/qa-regression-testing)
#   AUTO_REBOOT      Auto-reboot after modules/provision (default: 1; set 0 to disable)
#   REBOOT_DELAY     Countdown in seconds before auto-reboot (default: 10; Ctrl+C to cancel)
#   DB_KEY_DIR       Our PK/KEK/db key + cert from 'provision' (default: /etc/secureboot/key-material)
#   SB_KEY_DAYS      Validity of a new PK/KEK/db cert in days (default: 3650; sb_enroll.py)
#   SB_USE_AMISCE    auto | yes | no — turn the Secure Boot knob on with AMISCE
#                    (default: auto = AMI BIOS with SceEfi64.efi on the EFI partition)
#   SB_USE_EFIVAR    auto | yes | no — turn it on by writing AMI's SecureBootSetup
#                    EFI variable from Linux, tried before AMISCE (default: auto = AMI BIOS)
#
# NOTE ON EFFICIENCY / ALTERNATIVES:
#   The MOK path below is interactive by design (physical-presence security) and
#   is only needed for a CUSTOM / self-built kernel.  For stock Ubuntu kernels,
#   Secure Boot works with the distro (Canonical) signature already trusted via
#   Microsoft's UEFI CA — you only turn Secure Boot ON in BIOS. That is enough
#   for the OS, but NOT for the UEFI-shell tools: they need our own keys, so
#   'auto' still provisions them.
# =============================================================================

set -euo pipefail

# ------------------------------------------------------------------
# Configuration (env-overridable defaults — nothing to maintain in YAML)
# ------------------------------------------------------------------
KEY_DIR="${KEY_DIR:-/root/secureboot}"
KEY_CN="${KEY_CN:-Custom Ubuntu Kernel}"
KEY_DAYS="${KEY_DAYS:-3650}"
KERNEL_IMAGE="${KERNEL_IMAGE:-/boot/vmlinuz-$(uname -r)}"
QA_REPO_URL="${QA_REPO_URL:-https://git.launchpad.net/qa-regression-testing}"
QA_REPO_DIR="${QA_REPO_DIR:-/root/qa-regression-testing}"
AUTO_REBOOT="${AUTO_REBOOT:-1}"
REBOOT_DELAY="${REBOOT_DELAY:-10}"

MOK_KEY="${KEY_DIR}/mok.key"
MOK_CRT="${KEY_DIR}/mok.crt"
MOK_CER="${KEY_DIR}/mok.cer"
PROGRESS_FILE="${KEY_DIR}/.progress"
SCRIPT_PATH="$(readlink -f "${BASH_SOURCE[0]}")"
MOTD_HOOK="/etc/update-motd.d/95-secure-boot-progress"
SIGN_EFI_TOOLS_SH="$(dirname "${SCRIPT_PATH}")/sign_efi_tools.sh"

# 'auto' stage: picks the next stage itself and resumes after each reboot
# through a temporary systemd unit (removed when done or on any failure).
REPO_ROOT="$(cd "$(dirname "${SCRIPT_PATH}")/../.." && pwd)"   # deploy/secure_boot/ -> repo
RESUME_UNIT_NAME="fw-secure-boot-resume.service"
RESUME_UNIT_PATH="/etc/systemd/system/${RESUME_UNIT_NAME}"
AUTO_LOG="${REPO_ROOT}/logs/enable_secure_boot_auto.log"
SB_AUTO_RESUMED="${SB_AUTO_RESUMED:-0}"       # 1 = started by the resume unit (no terminal)
BIOS_KNOB_STATE="/var/lib/fw-validation/bios_knob/state.json"
# test_runner.py pre-flight plan; when it exists, 'auto' reports to the chain script.
PREFLIGHT_PLAN="${REPO_ROOT}/logs/preflight_plan.json"
PREFLIGHT_CHAIN="${REPO_ROOT}/deploy/preflight/preflight_chain.py"
# 'auto --no-reboot' writes this when a MOK waits for the blue MOK Manager screen, so
# test_runner.py asks before rebooting instead of counting down.
MOK_PENDING_FLAG="${REPO_ROOT}/logs/mok_enrollment_pending"
# 'auto --no-reboot' writes this when factory keys must be deleted, so test_runner.py
# reboots straight into BIOS Setup instead of a normal reboot.
KEY_RESET_FLAG="${REPO_ROOT}/logs/secure_boot_key_reset_pending"
# Same, when the 'Secure Boot' knob has to be set to Enabled in BIOS Setup.
SB_ENABLE_FLAG="${REPO_ROOT}/logs/secure_boot_enable_pending"
SB_NO_REBOOT=0                                # 1 = 'auto --no-reboot': the caller reboots
AUTO_MODE=0

# Our own PK/KEK/db key from 'provision' (sb_enroll.py), and who owns the firmware keys.
DB_KEY_DIR="${DB_KEY_DIR:-/etc/secureboot/key-material}"
DB_CERT="${DB_KEY_DIR}/test-cert.pem"
SB_KEYS_PY="$(dirname "${SCRIPT_PATH}")/sb_keys.py"
SB_ENROLL_PY="$(dirname "${SCRIPT_PATH}")/sb_enroll.py"

# 'enable' step: AMISCE turns the Secure Boot knob on (AMI BIOS only).
SB_USE_AMISCE="${SB_USE_AMISCE:-auto}"
KNOB_RUNBOOK="${REPO_ROOT}/deploy/bios_knobs/configure_bios_knobs_linux.py"
KNOB_UNIT_NAME="fw-bios-knob-resume.service"
KNOB_RESULT="$(dirname "${BIOS_KNOB_STATE}")/last_result.json"
SCE_DIR="${EFI_MOUNT:-/boot/efi}/EFI/ubuntu"
# Custom mode + no factory key provisioning, or the firmware swaps our keys for its own.
SB_KNOBS=("Secure Boot=Enabled" "Secure Boot Mode=Custom" "Factory Key Provision=Disabled")
# BIOS build on which AMISCE could not set 'Secure Boot' (it is not tried again there).
AMISCE_SB_FAILED="${KEY_DIR}/.amisce_secure_boot_failed"
# Same for the direct write of AMI's SecureBootSetup EFI variable from Linux.
EFIVAR_SB_FAILED="${KEY_DIR}/.efivar_secure_boot_failed"
SB_USE_EFIVAR="${SB_USE_EFIVAR:-auto}"

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m'

ok()     { echo -e "${GREEN}[OK]${NC}   $*"; }
warn()   { echo -e "${YELLOW}[WARN]${NC} $*"; }
fail()   { echo -e "${RED}[FAIL]${NC} $*"; exit 1; }
info()   { echo -e "       $*"; }
action() { echo -e "${BLUE}[ACTION]${NC} $*"; }

require_root() {
    [[ $EUID -eq 0 ]] || fail "Run with sudo:  sudo $0 $*"
    install_motd_hook
}

# Record that a stage finished successfully so the operator can tell what was
# already done after a reboot (breadcrumb only — stages still self-inspect the
# system and remain safe to re-run without this file).
record_progress() {
    mkdir -p "${KEY_DIR}"; chmod 700 "${KEY_DIR}"
    echo "$1 $(date -Iseconds)" >> "${PROGRESS_FILE}"
}

# Has stage $1 EVER been recorded as completed on this SUT (at any point in
# history, not just the most recent line)?
stage_done() {
    [[ -f "${PROGRESS_FILE}" ]] && grep -q "^$1 " "${PROGRESS_FILE}"
}

# Intended run order. Used only to WARN when earlier stages were skipped or
# run out of order — never to block, since provision/verify don't strictly
# require sign/modules (those only matter for a CUSTOM kernel — see header
# "NOTE ON EFFICIENCY").
STAGE_SEQUENCE=(sign modules provision verify)

# Print a warning listing any stage(s) earlier than $1 (in STAGE_SEQUENCE)
# that were never recorded as completed on this SUT. Call this from every
# stage_* function AND from show_progress/status, so no output path can make
# it look like the full sequence ran when a step was skipped or run out of
# order.
warn_if_sequence_skipped() {
    local target="$1" s missing=()
    for s in "${STAGE_SEQUENCE[@]}"; do
        [[ "${s}" == "${target}" ]] && break
        stage_done "${s}" || missing+=("${s}")
    done
    if [[ ${#missing[@]} -gt 0 ]]; then
        warn "Stage(s) never recorded as completed on this SUT: ${missing[*]}"
        info "'${target}' does not strictly require them to run (see header 'NOTE ON"
        info "EFFICIENCY / ALTERNATIVES' for when sign/modules matter — e.g. a STOCK"
        info "kernel needs neither). But if you meant to run the full sequence in"
        info "order, stop and run the missing stage(s) first, e.g.:  sudo $0 ${missing[0]}"
    fi
}

# Show the last recorded stage and what to run next.
show_progress() {
    echo "--- Secure Boot progress ------------------------------------------------"
    if [[ ! -f "${PROGRESS_FILE}" ]]; then
        info "No stage recorded yet on this SUT — start with:  sudo $0 sign"
    else
        local last last_stage last_time
        last="$(tail -n1 "${PROGRESS_FILE}")"
        last_stage="${last%% *}"; last_time="${last#* }"
        info "Last completed stage : ${last_stage}  (${last_time})"
        case "${last_stage}" in
            sign)      info "NEXT: sudo $0 modules"
                       warn_if_sequence_skipped modules ;;
            modules)   info "NEXT: sudo $0 provision"
                       warn_if_sequence_skipped provision ;;
            provision-partial)
                       info   "An older run left the key enrollment unfinished."
                       info   "NEXT: sudo $0 provision   (or auto)"
                       warn_if_sequence_skipped provision ;;
            provision) action "Our keys are enrolled. NEXT: turn Secure Boot on:"
                       info   "  sudo $0 auto   (signs the tools, then AMISCE sets the knob on an AMI BIOS)"
                       info   "  or BIOS Setup -> Secure Boot = Enabled (keep Custom mode), then: sudo $0 verify"
                       warn_if_sequence_skipped provision ;;
            sb-knob)   info "AMISCE was asked to turn Secure Boot on (UEFI Shell reboots)."
                       info "NEXT: sudo $0 auto   (runs by itself after the last AMISCE reboot)" ;;
            keys-reset) info "Waiting for the factory keys to be deleted in BIOS Setup (Key Management -> Delete all keys)."
                       info "After Save & Exit, 'auto' continues by itself; or run:  sudo $0 auto" ;;
            sb-efivar) info "'Secure Boot' = Enabled was written from Linux; it is active after the next reboot."
                       info "NEXT: sudo $0 auto   (runs by itself after the reboot)" ;;
            sb-enable) info "Waiting for 'Secure Boot' = Enabled in BIOS Setup (Security -> Secure Boot)."
                       info "After Save & Exit, 'auto' continues by itself; or run:  sudo $0 auto" ;;
            verify)    info "All stages recorded complete — Secure Boot should be enabled."
                       warn_if_sequence_skipped verify ;;
            *)         info "Unrecognized stage in ${PROGRESS_FILE} — re-check manually." ;;
        esac
    fi
    if [[ -f "${RESUME_UNIT_PATH}" ]]; then
        info "Auto-resume is ON (${RESUME_UNIT_NAME}): the next stage runs by itself after reboot."
        info "Progress log: ${AUTO_LOG}"
    else
        info "Or let the script pick the next stage:  sudo $0 auto"
    fi
    echo "------------------------------------------------------------------------"
}

# Install a /etc/update-motd.d hook so the progress banner above is shown
# automatically at every SSH/console login — this is what actually solves
# "the operator forgot what they ran" after a reboot, without waiting for
# them to remember to run 'status' manually. Idempotent: safe to overwrite.
install_motd_hook() {
    [[ -d /etc/update-motd.d ]] || return 0
    cat > "${MOTD_HOOK}" <<EOF
#!/bin/sh
# Auto-installed by enable_secure_boot.sh — shows Secure Boot provisioning
# progress at login so the operator knows what's already done after a reboot.
[ -x "${SCRIPT_PATH}" ] && "${SCRIPT_PATH}" status 2>/dev/null
EOF
    chmod +x "${MOTD_HOOK}"
}

# Print a short summary of the currently running boot configuration so the
# operator always knows what's active before a stage runs (or fails).
describe_boot() {
    local kver boot_mode entry_kind efivars_state
    kver="$(uname -r)"
    boot_mode="Legacy/BIOS"; [[ -d /sys/firmware/efi ]] && boot_mode="UEFI"
    if grep -qw noefi /proc/cmdline 2>/dev/null; then
        entry_kind="tboot/TXT entry (submenu 'tboot 1.12.1', noefi set)"
    else
        entry_kind="plain kernel entry (noefi not set)"
    fi
    if [[ -n "$(ls -A /sys/firmware/efi/efivars 2>/dev/null)" ]]; then
        efivars_state="accessible"
    else
        efivars_state="NOT accessible"
    fi
    echo "--- Current boot state -----------------------------------------------"
    info "Running kernel : ${kver}"
    info "Boot mode      : ${boot_mode}"
    info "Grub entry     : ${entry_kind}"
    info "EFI variables  : ${efivars_state}"
    echo "------------------------------------------------------------------------"
}

# EFI runtime variables are required by mokutil/sbsign/efibootmgr. They are
# unavailable if the kernel booted with 'noefi' on the command line — which is
# what the tboot/TXT grub entry (submenu "tboot 1.12.1") passes on purpose so
# tboot can own the EFI handoff. Secure Boot enrollment must run from the plain
# (non-tboot) kernel entry instead.
require_efivars() {
    if grep -qw noefi /proc/cmdline 2>/dev/null; then
        fail "Kernel booted with 'noefi' (/proc/cmdline) — EFI variables are disabled.\n" \
             "       This SUT looks like it booted the tboot/TXT grub entry (submenu\n" \
             "       'tboot 1.12.1') instead of the plain kernel entry.\n" \
             "       Fix: reboot, select the non-tboot 'Ubuntu, with Linux $(uname -r)' entry\n" \
             "       under 'Advanced options for Ubuntu', then re-run:  sudo $0 $*"
    fi
    if [[ -z "$(ls -A /sys/firmware/efi/efivars 2>/dev/null)" ]]; then
        fail "EFI variables are not accessible (/sys/firmware/efi/efivars is empty).\n" \
             "       mokutil/sbsign/efibootmgr need live EFI variable access.\n" \
             "       Reboot into a non-tboot / non-'noefi' kernel entry and re-run:  sudo $0 $*"
    fi
}

# Reboot automatically with a cancellable countdown (Ctrl+C aborts before the
# reboot fires). Set AUTO_REBOOT=0 to always fall back to a manual reminder.
do_reboot() {
    local next_cmd="$1"
    if [[ "${SB_NO_REBOOT}" == "1" ]]; then
        info "Reboot left to test_runner.py; after it, '${next_cmd}' runs by itself (${RESUME_UNIT_NAME})."
        return
    fi
    if [[ "${AUTO_REBOOT}" != "1" ]]; then
        action "AUTO_REBOOT=0 — reboot manually, then run:  sudo $0 ${next_cmd}"
        return
    fi
    echo ""
    action "Rebooting in ${REBOOT_DELAY}s to continue (Ctrl+C to cancel)."
    if [[ "${AUTO_MODE}" == "1" ]]; then
        info   "After reboot this continues by itself (${RESUME_UNIT_NAME}); log: ${AUTO_LOG}"
    else
        info   "After reboot, run:  sudo $0 ${next_cmd}"
    fi
    local i
    for (( i=REBOOT_DELAY; i>0; i-- )); do
        printf '\r       rebooting in %2ds... ' "$i"
        sleep 1
    done
    echo ""
    # In 'auto', the shutdown may kill this script; that must not remove the resume unit.
    if [[ "${AUTO_MODE}" == "1" ]]; then
        trap - EXIT
    fi
    reboot
}

# mokutil exit codes differ between versions (on some SUTs `--test-key` prints
# "is already enrolled" and exits 1), and this script runs with pipefail, so a
# `mokutil ... | grep -q` check gives the wrong answer. Decide on the text only.
mokutil_text() { mokutil "$@" 2>/dev/null || true; }

sb_state() {
    local out; out="$(mokutil_text --sb-state)"
    if grep -qi "secureboot enabled" <<< "${out}"; then
        echo enabled
    elif grep -qi "secureboot disabled" <<< "${out}"; then
        echo disabled
    else
        echo unknown
    fi
}

# MOK state: enrolled | pending (imported, waiting for the MOK Manager screen) | no
mok_state() {
    [[ -f "${MOK_CER}" ]] || { echo no; return; }
    local out; out="$(mokutil_text --test-key "${MOK_CER}")"
    if grep -qiE "already enrolled|already in db" <<< "${out}"; then
        echo enrolled
    elif grep -qi "already in the enrollment request" <<< "${out}"; then
        echo pending
    else
        echo no
    fi
}

# setup | partial | ours | foreign | unknown — whose keys PK/KEK hold (sb_keys.py).
key_owner() {
    python3 "${SB_KEYS_PY}" --cert "${DB_CERT}" owner 2>/dev/null || echo unknown
}

cert_in_db() {
    python3 "${SB_KEYS_PY}" --cert "${DB_CERT}" has db 2>/dev/null
}

show_keys() {
    echo "--- Secure Boot keys (deploy/secure_boot/sb_keys.py) ---------------------"
    python3 "${SB_KEYS_PY}" --cert "${DB_CERT}" status 2>&1 | sed 's/^/       /' || true
    echo "------------------------------------------------------------------------"
}

# The firmware holds keys that are not ours: nothing we sign is trusted and
# neither PK/KEK nor db can be changed from the OS.
key_reset_steps() {
    action "In BIOS Setup -> Security -> Secure Boot:"
    info   "  Secure Boot Mode = Custom, Factory Key Provision = Disabled,"
    info   "  Key Management -> Delete all keys (Reset to Setup Mode) -> Yes, then Save & Exit."
    info   "  If 'Secure Boot' still shows Enabled, leave it. If it is Disabled you cannot enable it yet"
    info   "  (no keys): the SUT comes back to BIOS Setup by itself once our keys are enrolled."
    info   "  (Not 'Invoke OEM Key Revocation' — that is an ME setting, not Secure Boot keys.)"
}

fail_foreign_keys() {
    show_keys
    echo -e "${RED}[FAIL]${NC} $1"
    info "The firmware holds keys that are NOT ours (factory keys, e.g. AMI 'Platform Key'),"
    info "so it refuses every tool we sign and rejects our key enrollment. No software can"
    info "delete them (that needs the owner's private key) — it is one click in BIOS Setup:"
    key_reset_steps
    fail "Then run:  sudo $0 auto   (it offers to reboot straight into BIOS Setup)"
}

# Sign every staged .efi tool with OUR db key (DB_KEY_DIR/test-key.rsa, the key
# 'provision' put in PK/KEK) — not this run's MOK, which only lives in shim's
# MokList and can never sign a db update. sign_efi_tools.sh adds our cert to db
# first (accepted because our cert is in KEK) and refuses to run on factory keys.
# $1 = 1: Secure Boot must already be on ('verify'); 0: before the knob is turned on.
sign_efi_tools_now() {
    [[ -f "${SIGN_EFI_TOOLS_SH}" ]] || fail "sign_efi_tools.sh not found at ${SIGN_EFI_TOOLS_SH}"
    action "Signing staged .efi tools with our db key (${DB_KEY_DIR})..."
    REQUIRE_SB_ENABLED="${1:-1}" KEY_DIR="${DB_KEY_DIR}" bash "${SIGN_EFI_TOOLS_SH}" \
        || fail "sign_efi_tools.sh failed (see logs/sign_efi_tools_*.log) — the UEFI Shell would refuse the tools."
    cert_in_db || fail "Our cert (${DB_CERT}) is not in the firmware db after signing — the UEFI Shell would refuse the tools."
    ok "EFI tools signed and our cert is in db — see logs/sign_efi_tools_*.log"
}

# ------------------------------------------------------------------
# Stage 1 — sign: tools + MOK + kernel signing + MOK import
# ------------------------------------------------------------------
stage_sign() {
    require_root sign
    require_efivars sign
    echo "=== Stage 1: sign kernel with MOK ==================================="

    if [[ "$(sb_state)" == "enabled" ]]; then
        warn "Secure Boot is already ENABLED. This procedure expects it DISABLED to start."
        info "Disable Secure Boot in BIOS first, or skip to 'verify' if already provisioned."
    fi

    # Step 1 — prerequisite tools (idempotent)
    apt-get install -y openssl mokutil sbsigntool
    ok "Prerequisite tools installed"

    # Step 2 — generate MOK PEM PKCS#1 key + cert (idempotent: reuse if present)
    mkdir -p "${KEY_DIR}"; chmod 700 "${KEY_DIR}"
    if [[ -f "${MOK_KEY}" && -f "${MOK_CRT}" && -f "${MOK_CER}" ]]; then
        ok "Reusing existing MOK keys in ${KEY_DIR}"
    else
        openssl req -newkey rsa:4096 -nodes -keyout "${MOK_KEY}" -new -x509 \
            -sha512 -days "${KEY_DAYS}" -subj "/CN=${KEY_CN}" \
            -addext "nsComment=${KEY_CN} certificate" -out "${MOK_CRT}"
        openssl x509 -in "${MOK_CRT}" -inform PEM -out "${MOK_CER}" -outform DER
        ok "Generated MOK keys in ${KEY_DIR}"
    fi

    # Step 3 — sign the kernel image (idempotent: skip if already signed)
    [[ -f "${KERNEL_IMAGE}" ]] || fail "Kernel image not found: ${KERNEL_IMAGE} (set KERNEL_IMAGE=...)"
    if sbverify --cert "${MOK_CRT}" "${KERNEL_IMAGE}" >/dev/null 2>&1; then
        ok "Kernel already signed with this MOK: ${KERNEL_IMAGE}"
    else
        sbsign --key "${MOK_KEY}" --cert "${MOK_CRT}" \
            --output /tmp/vmlinuz.signed "${KERNEL_IMAGE}"
        mv /tmp/vmlinuz.signed "${KERNEL_IMAGE}"
        ok "Signed kernel image: ${KERNEL_IMAGE}"
    fi

    # Step 4 — import the MOK (interactive: operator sets the password)
    case "$(mok_state)" in
        enrolled)
            ok "MOK already enrolled — nothing to import"
            action "NEXT: run  sudo $0 modules" ;;
        pending)
            ok "MOK already imported — it is waiting for the blue 'MOK Manager' screen"
            action "NEXT: reboot now. At the blue 'MOK Manager' screen:"
            info   "  Enroll MOK -> Continue -> Yes -> enter the password you set before -> reboot."
            info   "Forgot that password? Run  sudo mokutil --revoke-import , then this stage again."
            info   "Then run:  sudo $0 modules" ;;
        *)
            action "Importing MOK — you will be prompted to SET A ONE-TIME PASSWORD."
            info   "Remember it: you must re-enter it at the blue 'MOK Manager' screen."
            # stdout/stderr go through 'exec > >(tee ...)' here (auto's log mirror), which
            # makes mokutil's own stdio fully-buffered instead of line-buffered like a real
            # tty -- its password prompts then sit in that buffer, unseen, until it exits.
            # Force unbuffered I/O so the prompt actually appears before mokutil waits on it.
            stdbuf -o0 -e0 mokutil --import "${MOK_CER}"
            echo ""
            action "NEXT: reboot now. At the blue 'MOK Manager' screen:"
            info   "  Enroll MOK -> Continue -> Yes -> enter the password -> reboot."
            info   "Then run:  sudo $0 modules" ;;
    esac
    record_progress sign
}

# ------------------------------------------------------------------
# Stage 2 — modules: kmodsign + initramfs + grub
# ------------------------------------------------------------------
stage_modules() {
    require_root modules
    echo "=== Stage 2: sign kernel modules ===================================="

    warn_if_sequence_skipped modules

    [[ -f "${MOK_KEY}" && -f "${MOK_CER}" ]] || \
        fail "MOK keys not found in ${KEY_DIR} — run 'sign' first."

    local kver mod_dir
    kver="$(uname -r)"
    mod_dir="/lib/modules/${kver}/"
    action "Signing every *.ko under ${mod_dir} (can take 5+ minutes)..."
    find "${mod_dir}" -name '*.ko' -exec kmodsign sha512 "${MOK_KEY}" "${MOK_CER}" {} \;
    ok "Kernel modules signed"

    update-initramfs -u -k all
    ok "initramfs rebuilt"
    update-grub
    ok "grub configuration regenerated"

    record_progress modules
    # 'auto' continues with 'provision' right away: nothing in it needs the rebuilt initramfs.
    [[ "${AUTO_MODE}" == "1" ]] && return
    do_reboot provision
}

# ------------------------------------------------------------------
# Stage 3 — provision: enroll OUR keys (db, KEK, PK) with sb_enroll.py
# ------------------------------------------------------------------
# sb_enroll.py writes db -> KEK -> PK itself in one run (Setup Mode). Ubuntu's
# sb-setup is no longer used for this: on AMI firmware it left PK empty — its
# 30-day certificate expires, sbvarsign stores the signing month off by one, and
# sbkeysync's second db/KEK append hits efivarfs' immutable flag.
# Microsoft certificates come from KEY_DIR's microsoft-*.siglist (older runs),
# else from the qa-regression-testing clone.
ms_cert_dirs() {
    local name have=1
    for name in microsoft-kekca-public microsoft-pca-public microsoft-uefica-public; do
        [[ -f "${DB_KEY_DIR}/${name}.der.siglist" ]] || have=0
    done
    [[ "${have}" == 1 ]] && return
    if [[ ! -d "${QA_REPO_DIR}" ]]; then
        timedatectl set-ntp true 2>/dev/null || true
        git clone --depth 1 "${QA_REPO_URL}" "${QA_REPO_DIR}" >&2 \
            || fail "Cannot clone ${QA_REPO_URL} (Microsoft certificates for KEK/db) — check the network."
    fi
    echo "--ms-dir"; echo "${QA_REPO_DIR}"
}

# Bring dbx (the revocation list) to its final state in the same run as the key enrollment.
# Ubuntu's secureboot-db.service applies the Microsoft-signed dbx update at every boot, and
# with Microsoft's KEK in our KEK the firmware accepts it -- if that first happens after
# Secure Boot is on, PCR 7 (which measures dbx) changes once between the first and second
# boot, and the measured-boot tests see unstable PCRs.
apply_dbx_updates() {
    local dir=/usr/share/secureboot/updates
    if [[ ! -d "${dir}/dbx" ]] || ! command -v sbkeysync >/dev/null 2>&1; then
        info "No dbx updates in ${dir} (package secureboot-db) — dbx left as it is."
        return
    fi
    chattr -i /sys/firmware/efi/efivars/dbx-* 2>/dev/null || true
    if sbkeysync --no-default-keystores --keystore "${dir}" --verbose >/dev/null 2>&1 \
        && ls /sys/firmware/efi/efivars/dbx-d719b2cb-3d3a-4596-a3bc-dad00e67656f >/dev/null 2>&1; then
        ok "dbx updated now (${dir}) — PCR 7 stays the same on every boot from here on."
    else
        warn "Could not apply the dbx update now — secureboot-db.service does it at the next boot,"
        info "and PCR 7 then changes once: give measured-boot tests one extra reboot before they start."
    fi
}

stage_provision() {
    require_root provision
    echo "=== Stage 3: Secure Boot key provisioning ==========================="

    warn_if_sequence_skipped provision

    case "$(key_owner)" in
        foreign)
            fail_foreign_keys "'provision' cannot enroll our keys on top of someone else's Platform Key." ;;
        unknown)
            fail "Cannot read the Secure Boot key variables (PK/KEK/db) in /sys/firmware/efi/efivars." ;;
    esac

    local ms_args=()
    mapfile -t ms_args < <(ms_cert_dirs)
    action "Enrolling our keys (db -> KEK -> PK) with ${SB_ENROLL_PY}..."
    python3 "${SB_ENROLL_PY}" enroll "${ms_args[@]}" \
        || fail "Key enrollment failed (see above). Fix it, then run:  sudo $0 auto"
    apply_dbx_updates

    record_progress provision
    # 'auto' continues with signing the tools and turning Secure Boot on (auto_after_provision).
    [[ "${AUTO_MODE}" == "1" ]] && return
    echo ""
    action "Our keys are enrolled. Secure Boot is turned on next:"
    info   "  after the reboot it is ON if the 'Secure Boot' knob is already Enabled in BIOS Setup;"
    info   "  otherwise 'auto' signs the tools and sets the knob (AMI: from Linux or AMISCE),"
    info   "  or by hand: BIOS Setup -> Secure Boot = Enabled (keep Custom mode, do NOT restore factory keys)."
    do_reboot auto
}

# ------------------------------------------------------------------
# Stage 4 — verify: read-only Secure Boot state check
# ------------------------------------------------------------------
stage_verify() {
    require_root verify
    require_efivars verify
    echo "=== Stage 4: verify Secure Boot state ==============================="

    warn_if_sequence_skipped verify

    local state; state="$(sb_state)"
    echo "Secure Boot state: ${state}"
    [[ "${state}" == "enabled" ]] || fail "Secure Boot is NOT enabled (state=${state})."
    ok "UEFI Secure Boot is ENABLED"

    local owner; owner="$(key_owner)"
    case "${owner}" in
        ours)    show_keys; ok "PK/KEK hold our cert (${DB_CERT}) — not factory keys" ;;
        foreign) fail_foreign_keys "Secure Boot is ENABLED, but with keys that are not ours." ;;
        *)       show_keys
                 fail "Secure Boot is ENABLED, but our key enrollment is incomplete (owner: ${owner}).\n" \
                      "       Run:  sudo $0 auto" ;;
    esac

    sign_efi_tools_now 1

    record_progress verify
}

# ------------------------------------------------------------------
# status: read-only summary of boot state + provisioning progress
# ------------------------------------------------------------------
stage_status() {
    echo "=== Secure Boot status ================================================"
    info "MOK dir        : ${KEY_DIR}"
    if [[ -f "${MOK_CER}" ]]; then
        case "$(mok_state)" in
            enrolled) info "MOK enrolled   : yes" ;;
            pending)  info "MOK enrolled   : not yet — imported, waiting for the blue 'MOK Manager' screen" ;;
            *)        info "MOK enrolled   : no" ;;
        esac
    else
        info "MOK enrolled   : no MOK generated yet"
    fi
    info "Secure Boot    : $(sb_state)"
    info "Key owner      : $(key_owner)   (details: python3 ${SB_KEYS_PY} status)"
}

# cancel: stop waiting for a reboot (resume unit + flag files); keys, tools and progress stay.
stage_cancel() {
    require_root cancel
    remove_resume_unit
    rm -f "${MOK_PENDING_FLAG}" "${KEY_RESET_FLAG}" "${SB_ENABLE_FLAG}"
    ok "Secure Boot auto stopped; nothing runs after the next reboot. Run 'auto' (or test_runner.py) again any time."
}

# ------------------------------------------------------------------
# auto: run whichever stage comes next; resume by itself after reboots
# ------------------------------------------------------------------
last_stage() {
    [[ -f "${PROGRESS_FILE}" ]] || return 0
    tail -n1 "${PROGRESS_FILE}" | cut -d' ' -f1
}

mok_enrolled() {
    [[ "$(mok_state)" == "enrolled" ]]
}

install_resume_unit() {
    mkdir -p "$(dirname "${AUTO_LOG}")"
    cat > "${RESUME_UNIT_PATH}" <<EOF
[Unit]
Description=Continue Secure Boot enablement after reboot (deploy/secure_boot/enable_secure_boot.sh auto)
Wants=network-online.target
# A BIOS knob run started by the 'enable' step resumes first; this unit continues after its last reboot.
After=local-fs.target network-online.target ${KNOB_UNIT_NAME}
ConditionPathExists=${SCRIPT_PATH}

[Service]
Type=oneshot
Environment=SB_AUTO_RESUMED=1
ExecStart=/bin/bash ${SCRIPT_PATH} auto
TimeoutStartSec=infinity
StandardOutput=journal+console
StandardError=journal+console

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable "${RESUME_UNIT_NAME}" >/dev/null 2>&1
    ok "Auto-resume unit installed: ${RESUME_UNIT_PATH}"
}

remove_resume_unit() {
    [[ -f "${RESUME_UNIT_PATH}" ]] || return 0
    systemctl disable "${RESUME_UNIT_NAME}" >/dev/null 2>&1 || true
    rm -f "${RESUME_UNIT_PATH}"
    systemctl daemon-reload || true
    ok "Auto-resume unit removed: ${RESUME_UNIT_NAME}"
}

# A failed stage started by the unit must not repeat on every boot.
auto_on_exit() {
    local rc=$?
    if [[ ${rc} -ne 0 ]]; then
        remove_resume_unit
        echo -e "${RED}[FAIL]${NC} Secure Boot auto stopped (exit ${rc}). Fix the error above, then run:  sudo $0 auto"
        report_preflight fail "Secure Boot auto stopped (exit ${rc}) -- see ${AUTO_LOG}"
    fi
}

# Tell deploy/preflight/preflight_chain.py how this step ended, when a
# test_runner.py pre-flight started it. On 'pass' the chain starts the next step
# or the tests. Does nothing for a run started by hand (no plan, or the plan's
# secure_boot step is not 'running').
report_preflight() {   # $1 = pass|fail, $2 = detail
    [[ -f "${PREFLIGHT_PLAN}" && -f "${PREFLIGHT_CHAIN}" ]] || return 0
    [[ "${PREFLIGHT_REPORTED:-0}" == "1" ]] && return 0
    PREFLIGHT_REPORTED=1
    python3 "${PREFLIGHT_CHAIN}" next --from secure_boot --result "$1" --detail "$2" || true
}

# The MOK import asks for a one-time password, so 'sign' never runs from the unit.
auto_needs_terminal() {
    remove_resume_unit
    action "$1"
    info   "Run this in a terminal on the SUT:  sudo $0 auto"
    info   "(or start python test_runner.py and pick the tests again; its pre-flight offers it)"
    report_preflight fail "$1 Pick the tests again in test_runner.py."
    exit 0
}

auto_sign() {
    # 'sign' only needs a person when the MOK still has to be imported (password + blue screen).
    if [[ "${SB_AUTO_RESUMED}" == "1" ]] && ! mok_enrolled; then
        if [[ "$(mok_state)" == "pending" ]]; then
            auto_needs_terminal "The MOK is not enrolled — the blue 'MOK Manager' screen was skipped; it waits only a few seconds."
        fi
        auto_needs_terminal "The next stage is 'sign', which asks you to set a MOK password."
    fi
    stage_sign
    install_resume_unit
    if mok_enrolled; then
        ok "MOK already enrolled — continuing with 'modules' and 'provision' now (no reboot needed in between)."
        auto_enroll_chain modules
        return
    fi
    # Modules are signed with the MOK, so they wait until it is enrolled (blue screen at the next boot).
    echo ""
    if [[ "${SB_NO_REBOOT}" == "1" ]]; then
        action "At the next reboot (test_runner.py starts it), the blue 'MOK Manager' screen appears:"
    else
        action "Reboot now. At the blue 'MOK Manager' screen:"
    fi
    info   "  Enroll MOK -> Continue -> Yes -> enter the password you just set -> Reboot."
    info   "After that, everything continues by itself: modules -> provision -> sign tools ->"
    info   "Secure Boot on -> verify. Progress is shown on the screen and in ${AUTO_LOG}."
    warn_later_bios_trip
    if [[ -f "${PREFLIGHT_PLAN}" ]]; then
        info "Then the rest of the test_runner.py pre-flight and the tests run by themselves."
    fi
    if [[ "${SB_NO_REBOOT}" == "1" ]]; then
        # test_runner.py asks y/n before it reboots, so nobody misses the MOK Manager screen.
        mkdir -p "$(dirname "${MOK_PENDING_FLAG}")"
        echo "$(date -Iseconds)" > "${MOK_PENDING_FLAG}"
        return
    fi
    if [[ -t 0 ]]; then
        warn "The blue 'MOK Manager' screen waits only a few seconds for a key press --"
        info "be at the SUT's monitor or serial console before you reboot."
        local answer=""
        until [[ "${answer}" =~ ^[YyNn]$ ]]; do
            read -r -p "       Reboot now to enroll the MOK? [y/n] " answer
        done
        if [[ "${answer}" =~ ^[Yy]$ ]]; then
            # The shutdown may kill this script; that must not remove the resume unit.
            trap - EXIT
            reboot
        fi
    fi
    info "Reboot when ready:  sudo reboot"
}

stage_auto() {
    require_root auto
    AUTO_MODE=1
    rm -f "${MOK_PENDING_FLAG}" "${KEY_RESET_FLAG}" "${SB_ENABLE_FLAG}"
    # Every run goes to AUTO_LOG (key creation/enrollment and tool signing included);
    # the console still shows everything.
    mkdir -p "$(dirname "${AUTO_LOG}")"
    exec > >(tee -a "${AUTO_LOG}") 2>&1
    if [[ "${SB_AUTO_RESUMED}" == "1" ]]; then
        echo "===== $(date -Iseconds)  auto (resumed after reboot)"
    else
        echo "===== $(date -Iseconds)  auto ($([[ "${SB_NO_REBOOT}" == "1" ]] && echo "test_runner.py pre-flight, --no-reboot" || echo "started by hand"))"
    fi
    trap auto_on_exit EXIT

    if [[ -f "${BIOS_KNOB_STATE}" ]]; then
        if [[ "$(last_stage)" == "sb-knob" ]]; then
            info "AMISCE is still turning Secure Boot on (${BIOS_KNOB_STATE});"
            info "this continues by itself after its last UEFI Shell reboot."
            return
        fi
        fail "A BIOS knob configuration run is in progress (${BIOS_KNOB_STATE}).\n" \
             "       Let it finish (it reboots by itself), then run:  sudo $0 auto"
    fi
    require_efivars auto
    echo "=== Secure Boot: auto ==============================================="

    local state owner last
    state="$(sb_state)"
    owner="$(key_owner)"
    last="$(last_stage)"

    if [[ "${state}" == "enabled" && "${owner}" == "ours" ]]; then
        remove_resume_unit
        stage_verify
        echo ""
        ok "Secure Boot is ENABLED with our own keys and the EFI tools are signed."
        if [[ -f "${PREFLIGHT_PLAN}" ]]; then
            report_preflight pass "Secure Boot enabled with our keys, EFI tools signed"
        else
            info "Run the tests:  python3 test_runner.py"
        fi
        return
    fi

    case "${owner}" in
        foreign) auto_factory_keys "${state}" "${last}"; return ;;
        unknown) fail "Cannot read the Secure Boot key variables (PK/KEK/db) in /sys/firmware/efi/efivars." ;;
    esac

    info "Secure Boot is ${state^^}; key owner: ${owner}; last completed stage: ${last:-none}"
    show_keys
    if [[ "${owner}" == "ours" ]]; then
        # Our keys are in; only the knob is left (also when it was turned off again later).
        auto_enable_secure_boot
        return
    fi

    # owner = setup (no PK) or partial (PK ours, KEK not yet). The 'Secure Boot' setting cannot be
    # switched on while there is no PK, so our keys always come first: sign -> modules -> provision
    # run back to back (no reboot needed in between), then the setting is turned on.
    case "${last}" in
        ""|verify|sb-efivar|sb-knob|sb-enable|keys-reset)
            if [[ "${last}" == "keys-reset" ]]; then
                ok "Back from BIOS Setup (Setup Mode) — enrolling our own keys now."
                mv "${PROGRESS_FILE}" "${PROGRESS_FILE}.$(date +%Y%m%d_%H%M%S)"
            elif [[ -n "${last}" ]]; then
                warn "Secure Boot was set up before, but our keys are gone (keys reset in BIOS or IFWI reflash)."
                info "Starting again from 'sign'; old progress kept in ${PROGRESS_FILE}.<time>."
                mv "${PROGRESS_FILE}" "${PROGRESS_FILE}.$(date +%Y%m%d_%H%M%S)"
            fi
            auto_sign ;;
        sign)
            if mok_enrolled; then
                install_resume_unit
                auto_enroll_chain modules
            elif [[ "${SB_AUTO_RESUMED}" == "1" ]]; then
                auto_needs_terminal "The MOK is not enrolled — the blue 'MOK Manager' screen was skipped."
            else
                warn "The MOK is not enrolled yet."
                auto_sign
            fi ;;
        modules|provision|provision-partial)
            # provision-partial: left by the old sb-setup enrollment; sb_enroll.py finishes it in one run.
            install_resume_unit
            auto_enroll_chain provision ;;
        *)
            fail "Unrecognized stage '${last}' in ${PROGRESS_FILE} — check it, or move it away to start over." ;;
    esac
}

# ------------------------------------------------------------------
# BIOS Setup trips: the two things no software can do on this kind of BIOS
#   keys    delete factory keys (deleting PK needs the owner's private key)
#   enable  set the 'Secure Boot' knob once our PK is enrolled (it cannot be switched on
#           without keys; some AMI builds lock it against AMISCE and Linux writes)
# Someone at the console: y/n, then a reboot straight into BIOS Setup. Started by
# test_runner.py (--no-reboot): leaves a flag file, test_runner.py asks y/n and reboots.
# 'enable' from the resume unit (keys enrolled unattended, e.g. after deleting factory
# keys): reboots straight into BIOS Setup without asking -- the operator was told at the
# start to stay for it. The resume unit continues after Save & Exit.
# ------------------------------------------------------------------
enable_steps() {
    action "In BIOS Setup -> Security -> Secure Boot:"
    info   "  Secure Boot = Enabled (keep Secure Boot Mode = Custom; do NOT restore factory/default keys),"
    info   "  then Save & Exit."
}

# MOK not enrolled yet: set its password now, while someone is at the terminal, so the blue
# MOK Manager screen comes right after Save & Exit in BIOS Setup (one trip for both) and the
# resume unit runs sign -> modules -> provision without asking anything afterwards.
prepare_mok_for_bios_trip() {
    if [[ "${SB_AUTO_RESUMED}" != "1" ]] && ! mok_enrolled; then
        info "The MOK is not enrolled yet — setting it up first, so the blue screen comes right after BIOS Setup."
        stage_sign
        if [[ "$(mok_state)" == "pending" && "${SB_NO_REBOOT}" == "1" ]]; then
            mkdir -p "$(dirname "${MOK_PENDING_FLAG}")"
            date -Iseconds > "${MOK_PENDING_FLAG}"
        fi
    fi
    if [[ "$(mok_state)" == "pending" ]]; then
        info "After Save & Exit in BIOS Setup the blue 'MOK Manager' screen appears (it waits only a few seconds):"
        info "  Enroll MOK -> Continue -> Yes -> the password you just set -> Reboot."
    fi
}

bios_setup_trip() {   # $1 = keys | enable
    local kind="$1" stage flag question what
    if [[ "${kind}" == "keys" ]]; then
        stage=keys-reset; flag="${KEY_RESET_FLAG}"; what="delete the factory Secure Boot keys"
        question="Reboot into BIOS Setup now to delete the keys?"
        key_reset_steps
    else
        stage=sb-enable; flag="${SB_ENABLE_FLAG}"; what="Secure Boot = Enabled"
        question="Reboot into BIOS Setup now to turn Secure Boot on?"
        enable_steps
    fi
    info "After Save & Exit, Ubuntu boots and this continues by itself, then the tests start."

    if [[ "${SB_AUTO_RESUMED}" == "1" && "${kind}" == "enable" ]]; then
        # Keys enrolled unattended: the operator was told to stay for this second BIOS visit.
        record_progress "${stage}"
        install_resume_unit
        action "Rebooting straight into BIOS Setup in ${REBOOT_DELAY}s: Secure Boot = Enabled, then Save & Exit."
        local i
        for (( i=REBOOT_DELAY; i>0; i-- )); do
            printf '\r       BIOS Setup in %2ds... ' "$i"
            sleep 1
        done
        echo ""
        trap - EXIT
        if ! systemctl reboot --firmware-setup; then
            trap auto_on_exit EXIT
            fail "This firmware cannot be asked to open BIOS Setup. Reboot and press F2/Del while it boots;\n" \
                 "       set Secure Boot = Enabled, Save & Exit — 'auto' continues by itself."
        fi
        return
    fi
    if [[ "${SB_AUTO_RESUMED}" == "1" ]]; then
        # Started by the resume unit after a reboot: nobody to ask y/n.
        remove_resume_unit
        report_preflight fail "BIOS Setup needed (${what}) -- pick the tests again in test_runner.py: it asks y/n and reboots into BIOS Setup."
        fail "This needs BIOS Setup. Pick the tests again in test_runner.py (it asks y/n and reboots into\n" \
             "       BIOS Setup), or run:  sudo $0 auto"
    fi
    if [[ "${SB_NO_REBOOT}" == "1" ]]; then
        record_progress "${stage}"
        install_resume_unit
        mkdir -p "$(dirname "${flag}")"
        date -Iseconds > "${flag}"
        return
    fi
    if [[ ! -t 0 ]]; then
        fail "No terminal to ask whether to reboot into BIOS Setup. Run in a terminal:  sudo $0 auto"
    fi
    warn "Be at the SUT's monitor or serial console: BIOS Setup opens right after the reboot."
    local answer=""
    until [[ "${answer}" =~ ^[YyNn]$ ]]; do
        read -r -p "       ${question} [y/n] " answer
    done
    if [[ ! "${answer}" =~ ^[Yy]$ ]]; then
        remove_resume_unit
        info "Not rebooted. Do it in BIOS Setup when ready, then run:  sudo $0 auto"
        report_preflight fail "BIOS Setup needed (${what}), then pick the tests again."
        return
    fi
    record_progress "${stage}"
    install_resume_unit
    # The shutdown may kill this script; that must not remove the resume unit.
    trap - EXIT
    if ! systemctl reboot --firmware-setup; then
        trap auto_on_exit EXIT
        fail "This firmware cannot be asked to open BIOS Setup. Reboot (sudo reboot) and press F2/Del while it boots;\n" \
             "       after Save & Exit, 'auto' continues by itself."
    fi
}

# Tell the operator up front when the unattended part ends in a second BIOS Setup visit.
warn_later_bios_trip() {
    local knob; knob="$(python3 "${SB_KEYS_PY}" knob 2>/dev/null)"
    [[ "${knob}" == "enabled" ]] && return
    [[ "${knob}" == "disabled" ]] && ! knob_needs_bios_setup && return
    warn "Stay at the SUT's console: once our keys are enrolled (a few minutes after Ubuntu boots) the SUT"
    info "may reboot straight into BIOS Setup by itself — then set Secure Boot = Enabled, Save & Exit."
    info "(The setting cannot be switched on before our keys are in, and this BIOS may not let software do it.)"
}

# 'auto': modules -> provision -> sign tools -> Secure Boot on, without reboots in between.
auto_enroll_chain() {   # $1 = modules | provision (first stage to run)
    [[ "$1" == "modules" ]] && stage_modules
    stage_provision
    auto_after_provision
}

# Our keys were just enrolled (still this boot): decide how Secure Boot gets switched on.
auto_after_provision() {
    local knob; knob="$(python3 "${SB_KEYS_PY}" knob 2>/dev/null)"
    if [[ "${knob}" == "disabled" ]]; then
        # AMI 'Secure Boot' setting is off: needs switching on (Linux, AMISCE or BIOS Setup).
        auto_enable_secure_boot
        return
    fi
    sign_efi_tools_now 0
    if [[ "${knob}" == "enabled" ]]; then
        ok "The BIOS 'Secure Boot' setting is Enabled — Secure Boot is active with our keys after the reboot."
    else
        info "Rebooting to see whether Secure Boot is active with our keys (non-AMI BIOS: usually as soon as PK is enrolled)."
        # The setting of this BIOS cannot be read: if it stays off, the next boot goes straight into BIOS Setup.
        [[ "${SB_AUTO_RESUMED}" != "1" ]] && warn_later_bios_trip
    fi
    do_reboot auto
}

# Factory keys: delete them in BIOS Setup, then sign -> modules -> provision -> verify run by themselves.
auto_factory_keys() {   # $1 = Secure Boot state, $2 = last completed stage
    show_keys
    if [[ "$2" == "keys-reset" ]]; then
        if [[ "${SB_AUTO_RESUMED}" == "1" ]]; then
            remove_resume_unit
            report_preflight fail "the factory keys are still there after the BIOS Setup reboot -- pick the tests again in test_runner.py: it asks y/n and reboots into BIOS Setup again."
            fail_foreign_keys "The keys are still not ours after the BIOS Setup reboot: 'Delete all keys' was not done, or the BIOS put its factory keys back."
        fi
        warn "The factory keys are still there after the last BIOS Setup trip — asking again."
    fi
    warn "Secure Boot is ${1^^}, but the firmware keys are NOT ours (factory keys) — tools we sign would be refused."
    info "No software can delete them (that needs the owner's private key); it is one click in BIOS Setup."
    prepare_mok_for_bios_trip
    warn_later_bios_trip
    bios_setup_trip keys
}

# AMI: 'Secure Boot' knob is Disabled and this BIOS build lets neither Linux nor AMISCE change
# it -- then a BIOS Setup visit is unavoidable once our keys are enrolled.
knob_needs_bios_setup() {
    [[ "$(python3 "${SB_KEYS_PY}" knob 2>/dev/null)" == "disabled" ]] || return 1
    case "${SB_USE_EFIVAR,,}" in
        no|false|0) ;;
        *) [[ -f "${EFIVAR_SB_FAILED}" && "$(cat "${EFIVAR_SB_FAILED}")" == "$(bios_build)" ]] || return 1 ;;
    esac
    case "${SB_USE_AMISCE,,}" in
        no|false|0) return 0 ;;
    esac
    [[ -f "${SCE_DIR}/SceEfi64.efi" || -f "${SCE_DIR}/SceEfi64_signed.efi" ]] || return 0
    amisce_known_to_fail
}

# AMISCE turning the knob on, remembered per BIOS build when it did not work.
bios_build() {
    echo "$(cat /sys/class/dmi/id/bios_version 2>/dev/null) $(cat /sys/class/dmi/id/bios_date 2>/dev/null)"
}

amisce_known_to_fail() {
    [[ -f "${AMISCE_SB_FAILED}" ]] && [[ "$(cat "${AMISCE_SB_FAILED}")" == "$(bios_build)" ]]
}

is_ami_bios() {
    python3 -c 'import sys; sys.path.insert(0, sys.argv[1]); from core.bios_knob_checks import detect_ami; sys.exit(0 if detect_ami()[0] else 1)' \
        "${REPO_ROOT}" 2>/dev/null
}

# Write AMI's SecureBootSetup variable from Linux: one reboot, no AMISCE, no BIOS Setup.
use_efivar() {
    case "${SB_USE_EFIVAR,,}" in
        no|false|0) return 1 ;;
    esac
    ls /sys/firmware/efi/efivars/SecureBootSetup-7b59104a-c00d-4158-87ff-f04d6396a915 >/dev/null 2>&1 || return 1
    if [[ -f "${EFIVAR_SB_FAILED}" ]] && [[ "$(cat "${EFIVAR_SB_FAILED}")" == "$(bios_build)" ]]; then
        info "Writing 'Secure Boot' from Linux did not work on this BIOS build before (${EFIVAR_SB_FAILED})."
        return 1
    fi
    case "${SB_USE_EFIVAR,,}" in
        yes|true|1) return 0 ;;
    esac
    is_ami_bios
}

use_amisce() {
    case "${SB_USE_AMISCE,,}" in
        no|false|0) return 1 ;;
    esac
    [[ -f "${KNOB_RUNBOOK}" ]] || return 1
    if [[ ! -f "${SCE_DIR}/SceEfi64.efi" && ! -f "${SCE_DIR}/SceEfi64_signed.efi" ]]; then
        info "AMISCE (SceEfi64.efi) is not in ${SCE_DIR} — Secure Boot has to be turned on in BIOS Setup."
        return 1
    fi
    case "${SB_USE_AMISCE,,}" in
        yes|true|1) return 0 ;;
    esac
    if amisce_known_to_fail; then
        info "AMISCE cannot set 'Secure Boot' on this BIOS build ($(bios_build); ${AMISCE_SB_FAILED}) — using BIOS Setup."
        return 1
    fi
    is_ami_bios
}

knob_result_detail() {
    python3 -c 'import json, sys; r = json.load(open(sys.argv[1])); print(r.get("result"), r.get("detail"), sep=": ")' \
        "${KNOB_RESULT}" 2>/dev/null || echo "see logs/configure_bios_knobs_linux_*.log"
}

# 'enable': our keys are in PK/KEK, Secure Boot is still off.
auto_enable_secure_boot() {
    echo "=== Enable Secure Boot (our keys are enrolled) ======================="
    # Before the knob: the AMISCE run below already boots the UEFI Shell with Secure Boot on,
    # so the boot shell and SceEfi64 must be signed and our cert must be in db first.
    sign_efi_tools_now 0

    case "$(last_stage)" in
        sb-efivar)
            mkdir -p "${KEY_DIR}"
            bios_build > "${EFIVAR_SB_FAILED}"
            warn "The BIOS took the 'Secure Boot' = Enabled write but Secure Boot is still off after the reboot."
            info "Remembered for this BIOS build (${EFIVAR_SB_FAILED}); trying the next way." ;;
        sb-knob)
            mkdir -p "${KEY_DIR}"
            bios_build > "${AMISCE_SB_FAILED}"
            warn "AMISCE could not turn Secure Boot on (last AMISCE run: $(knob_result_detail))."
            info "This BIOS keeps the 'Secure Boot' knob where AMISCE cannot change it (the import reports"
            info "success, the value stays Disabled). Remembered for this BIOS build; AMISCE is not used for it again." ;;
        sb-enable)
            if [[ "${SB_AUTO_RESUMED}" == "1" ]]; then
                remove_resume_unit
                report_preflight fail "Secure Boot is still off after the BIOS Setup reboot -- pick the tests again in test_runner.py: it asks y/n and reboots into BIOS Setup again (Secure Boot = Enabled, Save & Exit)."
                fail "Secure Boot is still DISABLED after the BIOS Setup reboot ('Secure Boot' was not set to Enabled,\n" \
                     "       or not saved). Pick the tests again in test_runner.py — it asks y/n and reboots into BIOS Setup\n" \
                     "       again — or run:  sudo $0 auto"
            fi
            warn "Secure Boot is still DISABLED after the last BIOS Setup trip — asking again." ;;
    esac

    if use_efivar; then
        action "Turning 'Secure Boot' on from Linux (AMI SecureBootSetup variable; our keys are checked first)..."
        if python3 "${SB_ENROLL_PY}" secure-boot-on; then
            record_progress sb-efivar
            install_resume_unit
            info "Secure Boot is active after the reboot; 'verify' then runs by itself."
            do_reboot auto
            return
        fi
        mkdir -p "${KEY_DIR}"
        bios_build > "${EFIVAR_SB_FAILED}"
        warn "The BIOS refused the write (see above). Remembered for this BIOS build; trying the next way."
    fi

    if ! use_amisce; then
        info "Our keys are enrolled and the EFI tools are signed; only the 'Secure Boot' knob is left."
        bios_setup_trip enable
        return
    fi

    local args=() knob
    for knob in "${SB_KNOBS[@]}"; do
        args+=(--knob "${knob}")
    done
    record_progress sb-knob
    install_resume_unit
    action "Turning Secure Boot on with AMISCE: ${SB_KNOBS[*]}"
    info   "AMISCE reboots into the UEFI Shell a few times; '${RESUME_UNIT_NAME}' runs 'verify' after its last reboot."
    # AMISCE reboots by itself; the shutdown must not remove the resume unit.
    trap - EXIT
    local rc=0
    python3 "${KNOB_RUNBOOK}" "${args[@]}" || rc=$?
    if [[ -f "${BIOS_KNOB_STATE}" ]]; then
        info "AMISCE run started (rc=${rc}); the SUT is rebooting into the UEFI Shell."
        return
    fi
    trap auto_on_exit EXIT
    fail "AMISCE could not start the Secure Boot knob run (rc=${rc}; $(knob_result_detail)).\n" \
         "       Turn Secure Boot on in BIOS Setup (keep Custom mode), then run:  sudo $0 auto"
}

usage() {
    cat <<EOF
Enable UEFI Secure Boot — provisioning runbook.

Usage: sudo $0 <stage>

Recommended (one command; test_runner.py pre-flight runs it for you):
  auto        Run whichever stage comes next. After 'sign' (MOK password +
              blue MOK Manager screen, both manual) it installs
              ${RESUME_UNIT_NAME}; modules -> provision -> enable run back to
              back (keys first: 'Secure Boot' cannot be switched on without a PK),
              then verify after the reboot; the unit removes itself at the end.
              'enable' signs the tools, then turns the Secure Boot knob on with
              AMISCE on an AMI BIOS (UEFI Shell reboots); on any other BIOS it
              asks you to turn it on in BIOS Setup.
              Factory keys (PK not ours): software cannot delete them, so it
              asks y/n and reboots into BIOS Setup (Key Management -> Delete
              all keys, Save & Exit); everything after that runs by itself.
              Started by test_runner.py's pre-flight, it then hands over to
              deploy/preflight/preflight_chain.py (next step, then the tests).
  auto --no-reboot
              The same, but never reboots (test_runner.py reboots instead) —
              except the AMISCE 'enable' run, which reboots by itself.
              Progress log: ${AUTO_LOG}

PDF procedure (interactive MOK — for a custom kernel; run in order):
  sign        Install tools, generate MOK, sign the kernel, import the MOK.
  modules     Sign kernel modules, rebuild initramfs + grub, then AUTO-REBOOT.
  provision   Enroll our keys with sb_enroll.py in one run (db, KEK, PK =
              Microsoft + our cert; a fresh 10-year key in Setup Mode when ours
              is missing or expiring), then AUTO-REBOOT. Needs a BIOS without
              factory keys (Setup Mode).
              Then turn Secure Boot on ('auto', or BIOS Setup, keep Custom mode).

Shared:
  verify      Check that Secure Boot is enabled with OUR keys in PK/KEK (not
              factory keys), then sign every staged .efi tool
              (deploy/secure_boot/sign_efi_tools.sh) with the db key installed by
              'provision' (${DB_KEY_DIR}).

After an IFWI reflash, run ALL stages again: sign, modules, provision, verify.
  status      Show current boot state + which stage was last completed and
              what to run next (read-only; also shown automatically at login
              via an installed /etc/update-motd.d hook).
              Key details: python3 ${SB_KEYS_PY} status
  cancel      Stop a waiting 'auto' (e.g. you answered 'n' to the BIOS Setup reboot):
              removes ${RESUME_UNIT_NAME}; keys, signed tools and progress stay.
              The next 'auto' / test_runner.py run asks again.

Auto-reboot (modules/provision stages only):
  AUTO_REBOOT=0     Disable auto-reboot; print a manual reminder instead.
  REBOOT_DELAY=N    Countdown in seconds before rebooting (default: 10).

Overrides via environment variables (see the header of this script).
EOF
}

[[ "${1:-}" == "auto" && "${2:-}" == "--no-reboot" ]] && SB_NO_REBOOT=1

case "${1:-}" in
    sign|modules|provision|verify|status|auto) describe_boot; show_progress ;;
esac

case "${1:-}" in
    auto)              stage_auto ;;
    sign)              stage_sign ;;
    modules)           stage_modules ;;
    provision)         stage_provision ;;
    verify)            stage_verify ;;
    status)            stage_status ;;
    cancel)            stage_cancel ;;
    -h|--help|help|"") usage ;;
    *)                 warn "Unknown stage: '$1'"; echo ""; usage; exit 1 ;;
esac
