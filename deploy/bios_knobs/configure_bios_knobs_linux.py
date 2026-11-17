#!/usr/bin/env python3
# Copyright 2026 Intel Corporation
# SPDX-License-Identifier: Apache-2.0
"""
deploy/bios_knobs/configure_bios_knobs_linux.py — Set BIOS knobs per test marker with AMI AMISCE (runbook)

This is a PRE-FLIGHT PROVISIONING runbook, NOT a test. It CHANGES BIOS setup
values through the AMI AMISCE UEFI tool (SceEfi64.efi), the same way
enable_secure_boot.sh changes Secure Boot state. Run it before the tests of a
marker; deploy/bios_knobs/bios_knobs.yaml lists the knobs each marker needs (or NA).
Only AMI Aptio V BIOS builds with AMISCE support can be used.

One command runs the whole flow. Each UEFI step reboots the SUT; a temporary
systemd unit (fw-bios-knob-resume.service) resumes the runbook after every
boot and removes itself at the end.

  Step 1  check    SceEfi64.efi (and startup.nsh, UEFI Shell boot entry) present
  Step 2  export   UEFI: SceEfi64.efi /o /s bios_value_extracted.txt  -> reset
  Step 3  modify   OS:   copy to bios_value_modified.txt in the operator's home,
                         move '*' to the wanted option, stage it in EFI/ubuntu
  Step 4  import   UEFI: SceEfi64.efi /i /s bios_value_modified.txt [/cpwd <admin_pwd>]  -> reset
                         (this reset applies the new BIOS settings)
  Step 5  verify   UEFI: SceEfi64.efi /o /s bios_value_verify.txt     -> reset
  Step 6  check    OS:   get_bios_value.py "<knob>" -f bios_value_verify.txt
                         must print the wanted option
  verify_only profiles stop after Step 2 and check bios_value_extracted.txt.
  verify_knobs (bios_knobs.yaml) are read-only: checked right after Step 2 and
  never imported; a mismatch fails fast with a "flash the right IFWI" hint
  instead of burning Steps 3-6 on a knob that was never going to take effect.

Linux SUT only; Windows SUTs use configure_bios_knobs_windows.py (SCEWIN_64.exe).
The OS-independent parts live in bios_knob_common.py.

Usage (run ON the SUT):
  sudo python3 deploy/bios_knobs/configure_bios_knobs_linux.py --marker ifwi_sep5
  sudo python3 deploy/bios_knobs/configure_bios_knobs_linux.py --marker measured_boot --variant dtpm
  sudo python3 deploy/bios_knobs/configure_bios_knobs_linux.py --marker tme --marker measured_boot:ftpm_ptt  # merged
  sudo python3 deploy/bios_knobs/configure_bios_knobs_linux.py list               # markers + knobs in the config
  sudo python3 deploy/bios_knobs/configure_bios_knobs_linux.py --knob "<Setup Question>=<option>"  # one-off
  sudo python3 deploy/bios_knobs/configure_bios_knobs_linux.py status             # progress / last result
  sudo python3 deploy/bios_knobs/configure_bios_knobs_linux.py resume             # continue by hand (--no-auto-resume)
  sudo python3 deploy/bios_knobs/configure_bios_knobs_linux.py abort              # stop and clean up

  <option> is the label after "[xx]" in the AMISCE script, e.g. "Enabled" for
      Options =[00]Disabled
               *[01]Enabled

Optional overrides (environment variables):
  EFI_MOUNT     EFI System Partition mount point   (default: /boot/efi)
  SCE_DIR       AMISCE folder relative to EFI_MOUNT (default: EFI/ubuntu)
  SCE_TOOL      AMISCE binary name (default: SceEfi64_signed.efi if present —
                see sign_efi_tools.sh — else SceEfi64.efi)
  STATE_DIR     Runbook state folder                (default: /var/lib/fw-validation/bios_knob)
  REBOOT_DELAY  Countdown before each reboot, s     (default: 10; Ctrl+C to cancel;
                --reboot-delay N overrides it for this run's first reboot)
  BIOS_ADMIN_PASSWORD  BIOS Administrator password for /cpwd (default: bios.admin_password
                in config/test_config.yaml; sudo drops it unless passed as sudo VAR=...)

Notes:
  - TME is grayed out (import is ignored) unless VT-d is Enabled.
  - Protected setup variables (e.g. CpuSetup: TME, VMX, TXT) are skipped by
    AMISCE without the BIOS Administrator password, yet it still exits 0. Set
    an Administrator password in BIOS Setup and bios.admin_password in
    config/test_config.yaml; the import step then adds /cpwd <admin_pwd>. The
    password is read at import time, masked in the log, never stored in the
    state file, and maintest.nsh (which holds it) is deleted when the import
    step comes back. It must be printable ASCII without " ^ % # (UEFI Shell).
  - Uses /boot/efi/maintest.nsh + startup.nsh like the UEFI-shell tests, so do
    not run it while a pytest UEFI test is in progress (it refuses to).
"""

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

SCRIPT_PATH = Path(__file__).resolve()
sys.path.insert(0, str(SCRIPT_PATH.parent))
from bios_knob_common import (  # noqa: E402
    EXTRACT_FILE, MODIFIED_FILE, PASSWORD_MASK, REPO_ROOT, VERIFY_FILE, RunbookError, _Tee, action,
    add_common_arguments, build_modified_script, check_fixed_knobs, check_knobs, cmd_list,
    explain_unchanged_knobs, info, knob_values_match, load_admin_password, ok, print_na, print_profile,
    report_to_preflight, sce_password_failure, select_profile, warn,
)
import bios_password  # noqa: E402

EFI_MOUNT = Path(os.environ.get("EFI_MOUNT", "/boot/efi"))
SCE_DIR_REL = os.environ.get("SCE_DIR", "EFI/ubuntu").strip("/\\")
SCE_DIR = EFI_MOUNT / SCE_DIR_REL
STATE_DIR = Path(os.environ.get("STATE_DIR", "/var/lib/fw-validation/bios_knob"))
STATE_FILE = STATE_DIR / "state.json"
RESULT_FILE = STATE_DIR / "last_result.json"
REBOOT_DELAY = int(os.environ.get("REBOOT_DELAY", "10"))

MAINTEST = EFI_MOUNT / "maintest.nsh"
DONE_MARKER = EFI_MOUNT / "bios_knob_done.txt"
# Ownership marker, not a path: keep unchanged so maintest.nsh files from older checkouts are still recognized.
MAINTEST_TAG = "# generated by deploy/configure_bios_knobs_linux.py"
UNIT_NAME = "fw-bios-knob-resume.service"
UNIT_PATH = Path("/etc/systemd/system") / UNIT_NAME

# step -> (AMISCE arguments, console log name on the EFI partition)
UEFI_STEPS = {
    "export": (f"/o /s {EXTRACT_FILE}", "sce_export.log"),
    "import": (f"/i /s {MODIFIED_FILE}", "sce_import.log"),
    "verify": (f"/o /s {VERIFY_FILE}", "sce_verify.log"),
}
STALE_FILES = [EXTRACT_FILE, MODIFIED_FILE, VERIFY_FILE] + [log for _, log in UEFI_STEPS.values()]
# UEFI Shell specials that do not survive quoting reliably (escape, variable, comment).
UEFI_SHELL_UNSAFE = set('"^%#')


# ------------------------------------------------------------------
# State
# ------------------------------------------------------------------

def load_state():
    if not STATE_FILE.is_file():
        return None
    return json.loads(STATE_FILE.read_text(encoding="utf-8"))


def save_state(state):
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    os.chmod(STATE_DIR, 0o700)
    STATE_FILE.write_text(json.dumps(state, indent=2), encoding="utf-8")


def operator_account():
    """(name, home, uid, gid) of the user who ran sudo, falling back to root."""
    import pwd

    name = os.environ.get("SUDO_USER") or "root"
    try:
        pw = pwd.getpwnam(name)
        return name, pw.pw_dir, pw.pw_uid, pw.pw_gid
    except KeyError:
        return "root", "/root", 0, 0


# ------------------------------------------------------------------
# Pre-checks
# ------------------------------------------------------------------

def require_root():
    if not sys.platform.startswith("linux"):
        raise RunbookError("Linux SUT only.")
    if os.geteuid() != 0:
        raise RunbookError(f"Run with sudo:  sudo python3 {SCRIPT_PATH} {' '.join(sys.argv[1:])}")


def find_uefi_shell_bootnum():
    """Boot number of 'FW-Validation Shell' (preferred) or any 'UEFI Shell' entry."""
    result = subprocess.run(["efibootmgr"], capture_output=True, text=True, timeout=30)
    if result.returncode != 0:
        raise RunbookError(f"efibootmgr failed (rc={result.returncode}): {result.stderr.strip()}")
    out = result.stdout
    fw_shell = int_shell = None
    for line in out.splitlines():
        m = re.match(r"Boot([0-9A-Fa-f]{4})\*?\s+(.*)", line)
        if not m:
            continue
        if re.search(r"FW-Validation\s+Shell", m.group(2), re.IGNORECASE):
            fw_shell = m.group(1)
        elif re.search(r"UEFI\s+Shell", m.group(2), re.IGNORECASE):
            int_shell = m.group(1)
    return fw_shell or int_shell


def pick_sce_tool():
    if os.environ.get("SCE_TOOL"):
        return os.environ["SCE_TOOL"]
    if (SCE_DIR / "SceEfi64_signed.efi").is_file():
        return "SceEfi64_signed.efi"
    return "SceEfi64.efi"


def preflight(sce_tool):
    """Step 1: everything the UEFI round trips depend on."""
    print("--- Step 1: pre-checks ---------------------------------------------------")
    if not EFI_MOUNT.is_dir() or not os.path.ismount(EFI_MOUNT):
        raise RunbookError(f"EFI partition not mounted at {EFI_MOUNT}")
    ok(f"EFI partition mounted: {EFI_MOUNT}")

    tool = SCE_DIR / sce_tool
    if not tool.is_file() or tool.stat().st_size == 0:
        raise RunbookError(
            f"{sce_tool} not found in {SCE_DIR}\n"
            "         (AMISCE is for AMI Aptio BIOS only -- on any other BIOS, set the knobs manually in BIOS Setup.)\n"
            "         Put the whole AMISCE package SceEfi.7z into Downloads/ and run:\n"
            "           sudo python3 deploy/tools/deploy_tools.py"
        )
    ok(f"AMISCE tool: {tool} ({tool.stat().st_size} bytes)")
    info("No dependency files needed (SCEEFI64.cif / .sbom.yaml are BIOS build metadata).")

    if not (EFI_MOUNT / "startup.nsh").is_file():
        raise RunbookError(f"{EFI_MOUNT}/startup.nsh missing — run: sudo ./deploy/setup/setup_sut.sh")
    ok(f"startup.nsh present: {EFI_MOUNT / 'startup.nsh'}")

    if MAINTEST.is_file() and MAINTEST_TAG not in MAINTEST.read_text(errors="replace"):
        raise RunbookError(
            f"{MAINTEST} belongs to a pytest UEFI test that is still in progress.\n"
            "         Let it finish (or clean it up, doc/TEST_GUIDE.md I-7) before running this."
        )

    bootnum = find_uefi_shell_bootnum()
    if not bootnum:
        raise RunbookError("No UEFI Shell boot entry found (efibootmgr) — run: sudo ./deploy/setup/setup_sut.sh")
    ok(f"UEFI Shell boot entry: Boot{bootnum}")

    sb = ""
    if shutil.which("mokutil"):
        result = subprocess.run(["mokutil", "--sb-state"], capture_output=True, text=True, timeout=30)
        sb = result.stdout if result.returncode == 0 else ""
        if result.returncode != 0:
            warn(f"mokutil --sb-state failed (rc={result.returncode}): Secure Boot state unknown.")
    if "enabled" in sb.lower() and not sce_tool.endswith("_signed.efi"):
        warn("Secure Boot is enabled but the tool is not signed — the UEFI Shell may refuse it.")
        info("Sign it first: sudo ./deploy/secure_boot/sign_efi_tools.sh")


# ------------------------------------------------------------------
# UEFI round trip
# ------------------------------------------------------------------

def show_sce_log(step):
    """Print the AMISCE console log of a UEFI step and return its exit code text."""
    log_path = SCE_DIR / UEFI_STEPS[step][1]
    if not log_path.is_file():
        warn(f"AMISCE console log missing: {log_path}")
        return "unknown"
    text = log_path.read_text(encoding="utf-8", errors="replace")
    info(f"AMISCE console log ({log_path}):")
    for line in text.splitlines():
        info(f"  {line}")
    m = re.search(r"SCE_EXIT=(\S+)", text)
    code = m.group(1) if m else "unknown"
    if code not in ("0", "0x0", "0x00") and not sce_password_failure(sce_exit_int(code)):
        warn(f"AMISCE exit code {code} — the final value check decides the result.")
    return code


def sce_exit_int(code_text):
    """%lasterror% text from the UEFI Shell (e.g. '0x86') as an int, or None."""
    try:
        return int(code_text, 16)
    except (TypeError, ValueError):
        return None


def uefi_shell_arg(value):
    """Quote one argument for maintest.nsh; refuse characters the UEFI Shell would mangle."""
    bad = sorted({c for c in value if c in UEFI_SHELL_UNSAFE or not (" " <= c <= "~")})
    if bad:
        raise RunbookError(
            "bios.admin_password has characters the UEFI Shell cannot pass to AMISCE "
            f"({' '.join(repr(c) for c in bad)}). Use printable ASCII without \" ^ % #, "
            "or set the knobs in BIOS Setup."
        )
    return f'"{value}"'


def maintest_lines(step, tool, password=None):
    """maintest.nsh lines for one AMISCE run; the import gets /cpwd when a password is given."""
    sce_args, log_name = UEFI_STEPS[step]
    if password:
        sce_args = " ".join([sce_args, "/cpwd", uefi_shell_arg(password)])
    return [
        "@echo -off",
        MAINTEST_TAG,
        f"cd {SCE_DIR_REL.replace('/', chr(92))}",
        f"ls {tool}",
        f"{tool} {sce_args} >a {log_name}",
        f"echo SCE_EXIT=%lasterror% >>a {log_name}",
        "cd \\",
        f"echo step={step} status=done >a {DONE_MARKER.name}",
        "reset",
    ]


def install_resume_unit():
    UNIT_PATH.write_text(
        "[Unit]\n"
        "Description=Resume BIOS knob configuration (deploy/bios_knobs/configure_bios_knobs_linux.py)\n"
        "After=local-fs.target\n"
        f"ConditionPathExists={STATE_FILE}\n"
        "\n[Service]\n"
        "Type=oneshot\n"
        f"ExecStart={sys.executable} {SCRIPT_PATH} resume\n"
        "StandardOutput=journal+console\n"
        "StandardError=journal+console\n"
        "\n[Install]\n"
        "WantedBy=multi-user.target\n",
        encoding="utf-8",
    )
    subprocess.run(["systemctl", "daemon-reload"], check=True, timeout=60)
    subprocess.run(["systemctl", "enable", UNIT_NAME], check=True, capture_output=True, timeout=60)
    ok(f"Auto-resume unit installed: {UNIT_PATH}")


def remove_resume_unit():
    if UNIT_PATH.exists():
        subprocess.run(["systemctl", "disable", UNIT_NAME], capture_output=True, timeout=60)
        UNIT_PATH.unlink()
        subprocess.run(["systemctl", "daemon-reload"], capture_output=True, timeout=60)
        ok(f"Auto-resume unit removed: {UNIT_NAME}")


def start_uefi_step(state, step):
    """Write maintest.nsh for one AMISCE run, set BootNext to the UEFI Shell and reboot."""
    sce_args = UEFI_STEPS[step][0]
    tool = state["sce_tool"]
    password = ""
    if step == "import":
        # Read now (not stored in state.json); maintest.nsh is deleted right after this step.
        password, source = load_admin_password()
        if password:
            ok(f"BIOS admin password from {source}: the import uses /cpwd (protected variables, e.g. CpuSetup)")
        else:
            info("No BIOS admin password stored: AMISCE skips protected variables, e.g. CpuSetup.")
        state["cpwd"] = bool(password)
        state["cpwd_from_store"] = source == bios_password.SOURCE_LABEL
    lines = maintest_lines(step, tool, password)
    if DONE_MARKER.exists():
        DONE_MARKER.unlink()
    MAINTEST.write_bytes("\r\n".join(lines).encode("ascii") + b"\r\n")
    shown = f"{tool} {sce_args}" + (f" /cpwd {PASSWORD_MASK}" if password else "")
    ok(f"{MAINTEST} written for step '{step}': {shown}")

    state.update(step=step, status="pending", updated=datetime.now().isoformat(timespec="seconds"))
    save_state(state)

    bootnum = find_uefi_shell_bootnum()
    if not bootnum:
        raise RunbookError("No UEFI Shell boot entry found (efibootmgr).")
    subprocess.run(["efibootmgr", "--bootnext", bootnum], check=True, capture_output=True, timeout=30)
    ok(f"BootNext = Boot{bootnum} (UEFI Shell)")

    if state["auto_resume"]:
        info("The runbook resumes automatically after the UEFI step resets the SUT.")
    else:
        info(f"After the SUT is back in Ubuntu, run:  sudo python3 {SCRIPT_PATH} resume")
    action(f"Rebooting into the UEFI Shell in {REBOOT_DELAY}s (Ctrl+C to cancel the whole run).")
    sys.stdout.flush()
    try:
        time.sleep(REBOOT_DELAY)
    except KeyboardInterrupt:
        subprocess.run(["efibootmgr", "--delete-bootnext"], capture_output=True, timeout=30)
        raise RunbookError("Cancelled by operator before reboot (BootNext cleared).")
    result = subprocess.run(["systemctl", "reboot"], capture_output=True, text=True, timeout=60)
    if result.returncode != 0:
        subprocess.run(["efibootmgr", "--delete-bootnext"], capture_output=True, timeout=30)
        # The caller's finish() removes maintest.nsh (it may hold the BIOS admin password).
        raise RunbookError(f"systemctl reboot failed (rc={result.returncode}): {result.stderr.strip()}")
    return 0


def finish(state, passed, detail):
    """Remove every temporary file/unit and record the result."""
    skipped = (state or {}).get("unsupported") or {}
    if skipped:
        detail += "; skipped (not supported by this CPU): " + ", ".join(skipped)
    for path in (MAINTEST, DONE_MARKER):
        if path.exists():
            path.unlink()
    remove_resume_unit()
    result = {
        "result": "PASS" if passed else "FAIL",
        "detail": detail,
        "profile": state.get("profile") if state else None,
        "knobs": state.get("knobs") if state else None,
        "verify_knobs": state.get("verify_knobs") if state else None,
        "log": state.get("log") if state else None,
        "finished": datetime.now().isoformat(timespec="seconds"),
    }
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    RESULT_FILE.write_text(json.dumps(result, indent=2), encoding="utf-8")
    if STATE_FILE.exists():
        STATE_FILE.unlink()
    print("=" * 74)
    print(f"BIOS knob configuration ({(state or {}).get('profile', '?')}): {result['result']} — {detail}")
    print("=" * 74)
    values = {**((state or {}).get("knobs") or {}), **((state or {}).get("verify_knobs") or {})}
    # This run's latest export: the verify export after an import, else the first export.
    script = SCE_DIR / (VERIFY_FILE if (state or {}).get("step") == "verify" else EXTRACT_FILE)
    report_to_preflight(passed, detail, values, script)
    return 0 if passed else 1


# ------------------------------------------------------------------
# Steps run in the OS
# ------------------------------------------------------------------

def step_modify(state):
    """Step 3: build bios_value_modified.txt from the extracted script and stage it."""
    print("--- Step 3: modify -------------------------------------------------------")
    work_dir = Path(state["work_dir"])
    work_copy = work_dir / MODIFIED_FILE
    build_modified_script(SCE_DIR / EXTRACT_FILE, state["knobs"], work_copy)
    os.chown(work_dir, state["owner_uid"], state["owner_gid"])
    os.chown(work_copy, state["owner_uid"], state["owner_gid"])

    staged = SCE_DIR / MODIFIED_FILE
    shutil.copyfile(work_copy, staged)
    if staged.read_bytes() != work_copy.read_bytes():
        raise RunbookError(f"Staged copy differs from working copy: {staged}")
    ok(f"Staged for import: {staged}")


# ------------------------------------------------------------------
# Commands
# ------------------------------------------------------------------

def cmd_run(args):
    profile, label = select_profile(args)
    if profile is None:
        print_na(label)
        return 0
    knobs = profile["knobs"]
    print_profile(profile, label)

    require_root()
    if load_state():
        raise RunbookError(
            "A BIOS knob run is already in progress — see 'status', continue with 'resume' "
            "or stop it with 'abort'."
        )
    sce_tool = pick_sce_tool()
    preflight(sce_tool)

    print("--- Step 2: export (original values) ---------------------------------------")
    for name in STALE_FILES:
        path = SCE_DIR / name
        if path.exists():
            path.unlink()
            info(f"Removed old file: {path}")

    owner, home, uid, gid = operator_account()
    state = {
        "knobs": knobs,
        "verify_knobs": profile["verify_knobs"],
        "unsupported": profile.get("unsupported") or {},
        "profile": label,
        "verify_only": profile["verify_only"],
        "sce_tool": sce_tool,
        "work_dir": str(Path(home) / "bios_knob"),
        "owner_uid": uid,
        "owner_gid": gid,
        "log": args.log,
        "auto_resume": not args.no_auto_resume,
        "started": datetime.now().isoformat(timespec="seconds"),
    }
    info(f"Operator: {owner} (working copy in {state['work_dir']})")
    try:
        if state["auto_resume"]:
            install_resume_unit()
        return start_uefi_step(state, "export")
    except (RunbookError, subprocess.SubprocessError, OSError) as exc:
        return finish(state, False, str(exc))


def cmd_resume(_args):
    require_root()
    state = load_state()
    if not state:
        print("No BIOS knob run in progress.")
        return 0
    step = state["step"]
    print(f"Resuming after UEFI step '{step}'")

    done = DONE_MARKER.read_text(errors="replace") if DONE_MARKER.is_file() else ""
    if f"step={step} status=done" not in done:
        return finish(state, False,
                      f"UEFI step '{step}' did not run (no {DONE_MARKER}). Check that the SUT booted "
                      "into the UEFI Shell and that startup.nsh ran maintest.nsh.")
    DONE_MARKER.unlink()
    if MAINTEST.exists():
        MAINTEST.unlink()  # the import's copy holds the BIOS admin password
    ok(f"UEFI step '{step}' completed")
    exit_code = sce_exit_int(show_sce_log(step))

    try:
        if step == "import" and sce_password_failure(exit_code):
            if state.get("cpwd_from_store"):
                # The BIOS does not take the stored password (any more): forget it, so the next pre-flight asks.
                bios_password.forget()
                warn("The stored BIOS admin password was rejected and has been deleted.")
            return finish(state, False, "Import: " + sce_password_failure(exit_code))
        if step == "import" and exit_code == 0 and state.get("cpwd_from_store"):
            bios_password.mark_verified()
            ok("AMISCE accepted the stored BIOS admin password")
        if step == "export" and state.get("verify_knobs"):
            passed, fixed_detail = check_fixed_knobs(state["verify_knobs"], SCE_DIR / EXTRACT_FILE)
            if not passed:
                return finish(state, False, fixed_detail)
            if not state["knobs"]:
                return finish(state, True, fixed_detail)
        if step == "export" and state.get("verify_only"):
            passed, detail = check_knobs(state["knobs"], SCE_DIR / EXTRACT_FILE)
            return finish(state, passed, ("verify only: " + detail))
        if step == "export" and knob_values_match(state["knobs"], SCE_DIR / EXTRACT_FILE):
            # Nothing to change: skip the import and the verify export (2 reboots).
            detail = "already set: " + ", ".join(f"{q} = {o}" for q, o in state["knobs"].items())
            return finish(state, True, detail)
        if step == "export":
            step_modify(state)
            print("--- Step 4: import ---------------------------------------------------------")
            return start_uefi_step(state, "import")
        if step == "import":
            print("--- Step 5: verify export ----------------------------------------------------")
            return start_uefi_step(state, "verify")
        if step == "verify":
            passed, detail = check_knobs(state["knobs"], SCE_DIR / VERIFY_FILE)
            if not passed:
                explain_unchanged_knobs(state.get("cpwd", False))
            return finish(state, passed, detail)
        return finish(state, False, f"Unknown step in {STATE_FILE}: {step!r}")
    except (RunbookError, subprocess.SubprocessError, OSError) as exc:
        return finish(state, False, str(exc))


def cmd_status(_args):
    state = load_state()
    print("--- BIOS knob configuration progress -----------------------------------------")
    if state:
        info(f"In progress: waiting for UEFI step '{state['step']}' ({state['status']}, {state['updated']})")
        info(f"Profile    : {state.get('profile', '?')}"
             f"{' (verify only)' if state.get('verify_only') else ''}")
        info(f"Knobs      : {state['knobs']}")
        if state.get("verify_knobs"):
            info(f"Verify only: {state['verify_knobs']}")
        info(f"Log        : {state['log']}")
        if not state["auto_resume"]:
            info(f"NEXT: sudo python3 {SCRIPT_PATH} resume")
    elif RESULT_FILE.is_file():
        result = json.loads(RESULT_FILE.read_text(encoding="utf-8"))
        info(f"Last run   : {result['result']} ({result['finished']}) — {result['detail']}")
        info(f"Profile    : {result.get('profile')}")
        info(f"Log        : {result['log']}")
    else:
        info(f"No run recorded yet — start with:  sudo python3 {SCRIPT_PATH} --marker <marker>")
    print("------------------------------------------------------------------------------")
    return 0


def cmd_abort(_args):
    require_root()
    subprocess.run(["efibootmgr", "--delete-bootnext"], capture_output=True, timeout=30)
    return finish(load_state() or {}, False, "aborted by operator")


def cmd_password(args):
    """
    password            show whether the BIOS has an admin password and whether it is stored (no root)
    password --set      ask for the existing BIOS admin password (not echoed) and store it encrypted
    password --set --new  choose a new one; test_runner.py then reboots into BIOS Setup to type it there
    password --forget   delete the stored password
    """
    if args.set or args.forget:
        require_root()
    if args.forget:
        bios_password.forget()
        ok("Stored BIOS admin password deleted.")
        return 0
    if args.set:
        st = bios_password.status()
        if not args.new and st["bios_has_password"] is False:
            raise RunbookError("The BIOS has no Administrator password yet -- use 'password --set --new' "
                               "(test_runner.py then reboots into BIOS Setup to set it).")
        if args.new and st["bios_has_password"]:
            raise RunbookError("The BIOS already has an Administrator password -- use 'password --set' to type it.")
        password = bios_password.prompt(new=args.new)
        if not password:
            print("Cancelled -- nothing stored.")
            return 1
        method = bios_password.save(password, pending_bios_setup=args.new)
        ok(f"BIOS admin password stored ({method}): {bios_password.SECRET_FILE}")
        if args.new:
            info("Next: in BIOS Setup -> Security -> Administrator Password, type the same password,")
            info("then Save & Exit (F4). test_runner.py reboots into BIOS Setup for you and checks it afterwards.")
        else:
            info("It is checked at the next AMISCE import (/cpwd); if the BIOS rejects it, it is deleted")
            info("and test_runner.py asks again.")
        return 0
    st = bios_password.status()
    has = {True: "yes", False: "no", None: "cannot be read here"}[st["bios_has_password"]]
    print("--- BIOS Administrator password (AMISCE /cpwd) -------------------------------")
    info(f"BIOS has one : {has}")
    info(f"Stored here  : {'yes' if st['stored'] else 'no'} -- {st['message']} [{st['state']}]")
    info(f"Status file  : {bios_password.STATUS_FILE}")
    print("------------------------------------------------------------------------------")
    return 0


def main():
    global REBOOT_DELAY
    ap = argparse.ArgumentParser(
        description="Pre-flight: set BIOS knobs per test marker with AMI AMISCE (SceEfi64.efi) and verify them.",
    )
    add_common_arguments(ap)
    ap.add_argument("--no-auto-resume", action="store_true",
                    help="Do not install the resume unit; run 'resume' by hand after each reboot.")
    args = ap.parse_args()
    if args.reboot_delay is not None:
        REBOOT_DELAY = max(0, args.reboot_delay)

    if args.command == "status":
        return cmd_status(args)
    if args.command == "password":
        try:
            return cmd_password(args)
        except (RunbookError, ValueError, OSError) as exc:
            print(f"[FAIL]   {exc}")
            return 1
    if args.command == "list":
        try:
            return cmd_list(args)
        except RunbookError as exc:
            print(f"[FAIL]   {exc}")
            return 1

    state = load_state()
    log_dir = REPO_ROOT / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    args.log = (state or {}).get("log") or str(
        log_dir / f"configure_bios_knobs_linux_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
    )
    console = sys.stdout
    with open(args.log, "a", encoding="utf-8") as log_fh:
        sys.stdout = _Tee(console, log_fh)
        try:
            print(f"===== {datetime.now().isoformat(timespec='seconds')}  {args.command}  (log: {args.log})")
            code = {"run": cmd_run, "resume": cmd_resume, "abort": cmd_abort}[args.command](args)
        except RunbookError as exc:
            print(f"[FAIL]   {exc}")
            code = 1
        finally:
            sys.stdout = console
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        uid, gid = ((state["owner_uid"], state["owner_gid"]) if state
                    else operator_account()[2:])
        os.chown(args.log, uid, gid)
    return code or 0


if __name__ == "__main__":
    sys.exit(main())
