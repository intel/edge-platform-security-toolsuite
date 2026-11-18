#!/usr/bin/env bash
# Copyright 2026 Intel Corporation
# SPDX-License-Identifier: Apache-2.0
# =============================================================================
# deploy/secure_boot/sign_efi_tools.sh — Enroll a db cert + sign every *.efi tool on the SUT
#
# WHY: once UEFI Secure Boot is ENABLED, the UEFI Shell refuses to start any
# .efi binary that isn't signed by a key in the firmware's own `db` variable
# (e.g. vendor tools deployed by deploy_tools.py such as MEInfo.efi,
# VTInfo.efi, Fpt.efi, CapsuleApp.efi, getsec64.efi — see deploy/tools/tools.xml
# efi_destination entries). A key enrolled only via `mokutil`/MOK is NOT
# enough: that only adds it to shim's MokList, which is not consulted by the
# firmware's raw LoadImage() path used when a tool is launched directly from
# the UEFI Shell.
#
# This script does both halves of that requirement:
#   1. ENROLL  — build an EFI_SIGNATURE_LIST from the cert, sign it as an
#                authenticated `db` variable update (sbsiglist + sbvarsign),
#                stage it in the sbkeysync keystore, then apply it with
#                `sbkeysync` so the cert actually lands in the live `db`
#                variable. Skipped automatically if already enrolled.
#                Only possible when the firmware trusts the update: our cert
#                is in KEK (the 'provision' stage of enable_secure_boot.sh put
#                it there) or the firmware is in Setup Mode. With factory keys
#                (e.g. AMI "Platform Key") it stops with the fix: clear the
#                keys in BIOS Setup, then run enable_secure_boot.sh auto. The
#                key owner is read by deploy/secure_boot/sb_keys.py.
#   2. SIGN    — sign every *.efi tool under EFI_MOUNT with the same key/cert,
#                producing a "<name>_signed.efi" file next to the original:
#                  /boot/efi/EFI/ubuntu/MEInfo.efi -> MEInfo_signed.efi
#                The original unsigned file is left in place; run the
#                *_signed.efi copy from the UEFI Shell instead.
#              EXCEPTION — the boot shell (EFI/shell/shellx64.efi) is signed
#                IN PLACE, keeping its name. The "FW-Validation Shell" boot
#                entry (setup_sut.sh step 7) loads that exact path, and the
#                firmware refuses an unsigned image at boot, so a separate
#                shellx64_signed.efi would never be used.
#              EXCEPTION — tools listed in IN_PLACE_TOOLS (TPM2ProvTool.efi) are
#                also signed IN PLACE: Intel's TPM provisioning .nsh scripts
#                (TXT test) call them by name, never a *_signed.efi copy.
#                A signed image still runs with Secure Boot off.
#
# WHEN TO (RE)RUN THIS (idempotent — safe to run anytime):
#   - enable_secure_boot.sh auto runs it right after 'provision' (Secure Boot
#     still off, REQUIRE_SB_ENABLED=0) so the boot shell and AMISCE are signed
#     before the Secure Boot knob is turned on, and again in 'verify'.
#   - After Secure Boot is enabled / re-enabled.
#   - After IFWI is reflashed: rerun ALL enable_secure_boot.sh stages
#     (sign, modules, provision, verify); 'verify' calls this script.
#   - After deploy_tools.py copies new/updated .efi tools onto the EFI
#     partition.
#
# Usage (run ON the SUT, as root):
#   sudo ./deploy/secure_boot/sign_efi_tools.sh [EFI_MOUNT]
#
# Optional overrides (environment variables):
#   EFI_MOUNT    SUT EFI System Partition mount point (default: /boot/efi;
#                matches <efi_mount> in deploy/tools/tools.xml)
#   KEY_DIR      Where the signing key/cert live
#                (default: /etc/secureboot/key-material)
#   KEY_FILE     Key file name inside KEY_DIR    (default: test-key.rsa)
#   CERT_FILE    PEM cert file name inside KEY_DIR (default: test-cert.pem)
#   CERT_DER     DER cert file inside KEY_DIR, used for db enrollment
#                (default: same basename as CERT_FILE with .der extension;
#                generated from CERT_FILE via openssl if missing)
#   KEYSTORE_DB_DIR  sbkeysync keystore dir for pending db updates
#                (default: /etc/secureboot/keys/db)
#   SKIP_ENROLL  1 = skip the db-enrollment step entirely, just sign
#                (default: 0)
#   FORCE_ENROLL 1 = re-run db enrollment even if the cert already appears
#                trusted in db (default: 0)
#   FORCE        1 = re-sign even if an up-to-date *_signed.efi already exists
#                (default: 0)
#   BOOT_SHELL_EFI  Boot shell signed in place
#                (default: EFI_MOUNT/EFI/shell/shellx64.efi)
#   BOOT_SHELL_SRC  Unsigned copy of the shell, used as the signing
#                input so a re-sign never stacks signatures
#                (default: <repo>/Tools/shellx64.efi, auto-downloaded by
#                deploy/secure_boot/fetch_uefi_shell.sh). Must be an upstream EDK2
#                shell: Ubuntu's efi-shell-x64 exits when Secure Boot is on.
#   REQUIRE_SB_ENABLED  1 = fail if Secure Boot is not enabled (default: 1).
#                Set to 0 to pre-sign tools before Secure Boot is turned on.
#   DRY_RUN      1 = show what would be enrolled/signed without doing it
#                (default: 0)
#   LOG_DIR      Where to save a copy of this run's output (default: <repo>/logs)
#   LOG_FILE     Full log file path (default: LOG_DIR/sign_efi_tools_<timestamp>.log)
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
LOG_DIR="${LOG_DIR:-${REPO_ROOT}/logs}"
LOG_FILE="${LOG_FILE:-${LOG_DIR}/sign_efi_tools_$(date +%Y%m%d_%H%M%S).log}"
mkdir -p "${LOG_DIR}"
# Tee all output to the log file, stripping ANSI color codes there (console keeps color).
exec > >(tee >(sed -r 's/\x1b\[[0-9;]*m//g' >> "${LOG_FILE}")) 2>&1
echo "Logging output to: ${LOG_FILE}"

EFI_MOUNT="${1:-${EFI_MOUNT:-/boot/efi}}"
KEY_DIR="${KEY_DIR:-/etc/secureboot/key-material}"
KEY_FILE="${KEY_FILE:-test-key.rsa}"
CERT_FILE="${CERT_FILE:-test-cert.pem}"
CERT_DER="${CERT_DER:-${CERT_FILE%.*}.der}"
KEYSTORE_DB_DIR="${KEYSTORE_DB_DIR:-/etc/secureboot/keys/db}"
SKIP_ENROLL="${SKIP_ENROLL:-0}"
FORCE_ENROLL="${FORCE_ENROLL:-0}"
FORCE="${FORCE:-0}"
REQUIRE_SB_ENABLED="${REQUIRE_SB_ENABLED:-1}"
DRY_RUN="${DRY_RUN:-0}"
BOOT_SHELL_EFI="${BOOT_SHELL_EFI:-${EFI_MOUNT%/}/EFI/shell/shellx64.efi}"
BOOT_SHELL_SRC="${BOOT_SHELL_SRC:-}"

MOK_KEY="${KEY_DIR}/${KEY_FILE}"
MOK_CRT="${KEY_DIR}/${CERT_FILE}"
MOK_CRT_DER="${KEY_DIR}/${CERT_DER}"
OWNER_GUID_FILE="${KEY_DIR}/.owner-guid"
SB_KEYS_PY="${SCRIPT_DIR}/sb_keys.py"

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

[[ $EUID -eq 0 ]] || fail "Run with sudo:  sudo $0 $*"
[[ -d "${EFI_MOUNT}" ]] || fail "EFI mount not found: ${EFI_MOUNT} (is the ESP mounted?)"
for tool in sbsign sbverify sbsiglist sbvarsign sbkeysync uuidgen openssl python3; do
    command -v "${tool}" >/dev/null 2>&1 || \
        fail "${tool} not found — install sbsigntool + efitools (uuidgen is in util-linux)."
done
[[ -f "${MOK_KEY}" && -f "${MOK_CRT}" ]] || \
    fail "Key/cert not found: ${MOK_KEY} / ${MOK_CRT}.\n" \
         "       This db key is installed by the 'provision' stage. Run the full sequence\n" \
         "       (sign, modules, provision, verify) of ./deploy/secure_boot/enable_secure_boot.sh,\n" \
         "       or set KEY_DIR/KEY_FILE/CERT_FILE to your db signing key."

if command -v mokutil >/dev/null 2>&1; then
    sb_state="$(mokutil --sb-state 2>/dev/null || echo unknown)"
    if echo "${sb_state}" | grep -qi enabled; then
        ok "Secure Boot is enabled (mokutil --sb-state: ${sb_state})"
    elif [[ "${REQUIRE_SB_ENABLED}" == "1" ]]; then
        fail "Secure Boot is NOT enabled (mokutil --sb-state: ${sb_state}).\n" \
             "       Signing is pointless until Secure Boot is on -- enable it first:\n" \
             "       sudo ./deploy/secure_boot/enable_secure_boot.sh sign   (then modules, provision, verify)\n" \
             "       Or bypass this check to pre-sign ahead of time: REQUIRE_SB_ENABLED=0 $0"
    else
        warn "Secure Boot not enabled (mokutil --sb-state: ${sb_state}) -- REQUIRE_SB_ENABLED=0, pre-signing anyway."
    fi
else
    warn "mokutil not found -- cannot verify Secure Boot state; proceeding anyway."
fi

# ------------------------------------------------------------------
# cert_trusted_in_db — true if MOK_CRT itself (byte for byte) is in the
# firmware's live `db` variable.
# ------------------------------------------------------------------
cert_trusted_in_db() {
    python3 "${SB_KEYS_PY}" --cert "${MOK_CRT}" has db
}

# setup | partial | ours | foreign | unknown — see sb_keys.py
key_owner() {
    python3 "${SB_KEYS_PY}" --cert "${MOK_CRT}" owner 2>/dev/null || echo unknown
}

# A db update signed with MOK_KEY is only accepted when MOK_CRT is in KEK
# ('ours') or the firmware is in Setup Mode; anything else is rejected.
require_db_writable() {
    local owner; owner="$(key_owner)"
    case "${owner}" in
        ours|setup) return 0 ;;
    esac
    python3 "${SB_KEYS_PY}" --cert "${MOK_CRT}" status || true
    case "${owner}" in
        foreign)
            fail "The firmware holds keys that are not ours (factory keys), so it would reject the\n" \
                 "       db update and every tool signed with ${MOK_CRT}.\n" \
                 "       In BIOS Setup -> Security -> Secure Boot: Secure Boot Mode = Custom,\n" \
                 "       Key Management -> Delete all keys (Setup Mode), Save & Exit, then run:\n" \
                 "         sudo ${SCRIPT_DIR}/enable_secure_boot.sh auto" ;;
        partial)
            fail "PK is ours but KEK does not hold ${MOK_CRT} yet -- the key enrollment did not finish.\n" \
                 "       Run:  sudo ${SCRIPT_DIR}/enable_secure_boot.sh auto" ;;
        *)
            fail "Cannot read the Secure Boot key variables (/sys/firmware/efi/efivars) -- boot a plain\n" \
                 "       (non-tboot, no 'noefi') kernel entry and run this again." ;;
    esac
}

# ------------------------------------------------------------------
# enroll_cert_in_db — build + sign an EFI_SIGNATURE_LIST for MOK_CRT and
# apply it to the firmware's `db` variable via sbkeysync. Idempotent: skips
# if already trusted, unless FORCE_ENROLL=1.
# ------------------------------------------------------------------
enroll_cert_in_db() {
    if [[ "${SKIP_ENROLL}" == "1" ]]; then
        info "SKIP_ENROLL=1 — not enrolling ${MOK_CRT} in db."
        cert_trusted_in_db || warn "${MOK_CRT} is NOT in the firmware db -- the UEFI Shell will refuse the signed tools."
        return
    fi

    if [[ "${FORCE_ENROLL}" != "1" ]] && cert_trusted_in_db; then
        ok "Cert already trusted in firmware db, skipping enrollment: ${MOK_CRT}"
        return
    fi

    require_db_writable

    echo "=== Enrolling cert into firmware db ==================================="
    info "Cert : ${MOK_CRT}"

    # sbsiglist needs the DER form; derive it from the PEM if not present.
    if [[ ! -f "${MOK_CRT_DER}" ]]; then
        action "Deriving DER cert: ${MOK_CRT_DER}"
        [[ "${DRY_RUN}" == "1" ]] || openssl x509 -in "${MOK_CRT}" -outform DER -out "${MOK_CRT_DER}"
    fi

    # Reuse the same owner GUID across runs so re-enrollment doesn't create a
    # duplicate db entry with a different owner each time.
    local guid
    if [[ -f "${OWNER_GUID_FILE}" ]]; then
        guid="$(cat "${OWNER_GUID_FILE}")"
    else
        guid="$(uuidgen)"
        [[ "${DRY_RUN}" == "1" ]] || echo "${guid}" > "${OWNER_GUID_FILE}"
    fi
    info "Owner GUID : ${guid}"

    local siglist="${MOK_CRT_DER}.siglist"
    local db_signed="${siglist}.db.signed"

    if [[ "${DRY_RUN}" == "1" ]]; then
        action "Would run: sbsiglist --owner ${guid} --type x509 --output ${siglist} ${MOK_CRT_DER}"
        action "Would run: sbvarsign --key ${MOK_KEY} --cert ${MOK_CRT} --output ${db_signed} db ${siglist}"
        action "Would copy ${db_signed} -> ${KEYSTORE_DB_DIR}/"
        action "Would run: sbkeysync --verbose"
        return
    fi

    sbsiglist --owner "${guid}" --type x509 --output "${siglist}" "${MOK_CRT_DER}"
    ok "Built signature list: ${siglist}"

    sbvarsign --key "${MOK_KEY}" --cert "${MOK_CRT}" --output "${db_signed}" db "${siglist}"
    ok "Signed db update: ${db_signed}"

    mkdir -p "${KEYSTORE_DB_DIR}"
    cp "${db_signed}" "${KEYSTORE_DB_DIR}/"
    ok "Staged in keystore: ${KEYSTORE_DB_DIR}/$(basename "${db_signed}")"

    # efivarfs marks db immutable on every boot; sbkeysync cannot append to it otherwise.
    chattr -i /sys/firmware/efi/efivars/db-* 2>/dev/null || true
    sbkeysync --verbose || fail "sbkeysync could not apply the db update (see its output above)."
    ok "sbkeysync applied pending key updates"

    if cert_trusted_in_db; then
        ok "Confirmed cert is now trusted in firmware db"
    else
        python3 "${SB_KEYS_PY}" --cert "${MOK_CRT}" status || true
        fail "${MOK_CRT} is still not in the firmware db after sbkeysync -- the firmware rejected the update."
    fi
}

enroll_cert_in_db

echo "=== Signing EFI tools under ${EFI_MOUNT} ============================="
info "Key   : ${MOK_KEY}"
info "Cert  : ${MOK_CRT}"
[[ "${DRY_RUN}" == "1" ]] && warn "DRY_RUN=1 — no files will be signed"

signed_count=0
skipped_count=0
failed_count=0

# ------------------------------------------------------------------
# shell_exits_under_secure_boot — true for Ubuntu's efi-shell-x64 build
# (edk2 >= 2024.02-2ubuntu0.3, CVE-2025-2486), which returns immediately when
# Secure Boot is enabled. Only that build references the SetupMode variable.
# ------------------------------------------------------------------
shell_exits_under_secure_boot() {
    LC_ALL=C grep -qaP 'S\x00e\x00t\x00u\x00p\x00M\x00o\x00d\x00e\x00' "$1"
}

# ------------------------------------------------------------------
# sign_boot_shell — sign BOOT_SHELL_EFI in place (same file name), because the
# "FW-Validation Shell" boot entry loads that exact path at boot.
# ------------------------------------------------------------------
sign_boot_shell() {
    if [[ ! -f "${BOOT_SHELL_EFI}" ]]; then
        warn "Boot shell not found: ${BOOT_SHELL_EFI} -- run sudo ./deploy/setup/setup_sut.sh (step 7), then rerun this script."
        return
    fi

    if [[ -z "${BOOT_SHELL_SRC}" ]]; then
        BOOT_SHELL_SRC="${REPO_ROOT}/Tools/shellx64.efi"
        if [[ "${DRY_RUN}" != "1" ]]; then
            "${SCRIPT_DIR}/fetch_uefi_shell.sh" "${BOOT_SHELL_SRC}" \
                || warn "Could not stage the upstream UEFI shell -- see message above."
        fi
    fi

    local src="${BOOT_SHELL_EFI}"
    [[ -f "${BOOT_SHELL_SRC}" ]] && src="${BOOT_SHELL_SRC}"

    if shell_exits_under_secure_boot "${src}"; then
        warn "Boot shell source ${src} is Ubuntu's efi-shell-x64 build -- it exits immediately"
        info "when Secure Boot is enabled (CVE-2025-2486), so maintest.nsh never runs."
        info "Fix the download error above (or put an upstream EDK2 shell at ${REPO_ROOT}/Tools/shellx64.efi),"
        info "then rerun:  sudo $0"
        failed_count=$((failed_count + 1))
        return
    fi

    if [[ "${FORCE}" != "1" ]] && sbverify --cert "${MOK_CRT}" "${BOOT_SHELL_EFI}" >/dev/null 2>&1 \
        && ! shell_exits_under_secure_boot "${BOOT_SHELL_EFI}"; then
        ok "Boot shell already signed, skipping: ${BOOT_SHELL_EFI}"
        skipped_count=$((skipped_count + 1))
        return
    fi

    info "Boot shell source: ${src}"

    if [[ "${DRY_RUN}" == "1" ]]; then
        action "Would sign boot shell in place: ${src} -> ${BOOT_SHELL_EFI}"
        return
    fi

    local tmp="${BOOT_SHELL_EFI}.tmp"
    if sbsign --key "${MOK_KEY}" --cert "${MOK_CRT}" --output "${tmp}" "${src}" >/dev/null 2>&1 \
        && sbverify --cert "${MOK_CRT}" "${tmp}" >/dev/null 2>&1; then
        mv -f "${tmp}" "${BOOT_SHELL_EFI}"
        ok "Signed boot shell in place: ${BOOT_SHELL_EFI}"
        signed_count=$((signed_count + 1))
    else
        rm -f "${tmp}"
        warn "Failed to sign boot shell: ${BOOT_SHELL_EFI}"
        failed_count=$((failed_count + 1))
    fi
}

sign_boot_shell

# Lower-case file names of tools other scripts call by name (see the header).
IN_PLACE_TOOLS="tpm2provtool.efi"

sign_in_place() {
    local src="$1"
    if [[ "${FORCE}" != "1" ]] && sbverify --cert "${MOK_CRT}" "${src}" >/dev/null 2>&1; then
        ok "Already signed in place, skipping: ${src}"
        skipped_count=$((skipped_count + 1))
        return
    fi
    if [[ "${DRY_RUN}" == "1" ]]; then
        action "Would sign in place: ${src}"
        return
    fi
    local tmp="${src}.tmp"
    if sbsign --key "${MOK_KEY}" --cert "${MOK_CRT}" --output "${tmp}" "${src}" >/dev/null 2>&1 \
        && sbverify --cert "${MOK_CRT}" "${tmp}" >/dev/null 2>&1; then
        mv -f "${tmp}" "${src}"
        ok "Signed in place: ${src}"
        signed_count=$((signed_count + 1))
    else
        rm -f "${tmp}"
        warn "Failed to sign in place: ${src}"
        failed_count=$((failed_count + 1))
    fi
}

# Exclude already-signed output files so a re-run never tries to sign its own
# previous output (e.g. MEInfo_signed.efi), and the boot shell (signed in place
# above).
while IFS= read -r -d '' src; do
    [[ "${src}" -ef "${BOOT_SHELL_EFI}" ]] && continue
    name="$(basename "${src}")"
    if [[ " ${IN_PLACE_TOOLS} " == *" ${name,,} "* ]]; then
        sign_in_place "${src}"
        continue
    fi
    out="${src%.efi}_signed.efi"

    if [[ "${FORCE}" != "1" && -f "${out}" && "${out}" -nt "${src}" ]] \
        && sbverify --cert "${MOK_CRT}" "${out}" >/dev/null 2>&1; then
        ok "Up to date, skipping: ${out}"
        skipped_count=$((skipped_count + 1))
        continue
    fi

    if [[ "${DRY_RUN}" == "1" ]]; then
        action "Would sign: ${src} -> ${out}"
        continue
    fi

    if sbsign --key "${MOK_KEY}" --cert "${MOK_CRT}" --output "${out}" "${src}" >/dev/null 2>&1 \
        && sbverify --cert "${MOK_CRT}" "${out}" >/dev/null 2>&1; then
        ok "Signed: ${out}"
        signed_count=$((signed_count + 1))
    else
        warn "Failed to sign: ${src}"
        failed_count=$((failed_count + 1))
    fi
done < <(find "${EFI_MOUNT}" -iname '*.efi' -not -iname '*_signed.efi' -print0)

echo "------------------------------------------------------------------------"
info "Signed: ${signed_count}   Skipped (up to date): ${skipped_count}   Failed: ${failed_count}"
info "Full log: ${LOG_FILE}"
[[ "${failed_count}" -eq 0 ]] || fail "${failed_count} tool(s) failed to sign — see warnings above."
ok "Done. The boot shell (${BOOT_SHELL_EFI}) and TPM2ProvTool.efi are signed in place; run the *_signed.efi copies of the other tools from the UEFI Shell when Secure Boot is enabled."
