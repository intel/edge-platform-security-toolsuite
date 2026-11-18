#!/usr/bin/env python3
# Copyright 2026 Intel Corporation
# SPDX-License-Identifier: Apache-2.0
"""
deploy/bios_knobs/configure_bios_knobs_windows.py — Set BIOS knobs per test marker with AMI AMISCE on Windows (runbook)

Windows counterpart of configure_bios_knobs_linux.py. This is a PRE-FLIGHT
PROVISIONING runbook, NOT a test. It CHANGES BIOS setup values through
SCEWIN_64.exe, which runs inside Windows (with its driver amigendrv64.sys), so
no UEFI Shell round trip is needed. deploy/bios_knobs/bios_knobs.yaml lists the knobs each
marker needs (or NA). Only AMI Aptio V BIOS builds with AMISCE support can be used.

AMISCE import writes NVRAM only; the BIOS applies the values at the next boot.
So the flow needs exactly one reboot, after the import. A Task Scheduler task
(at boot as SYSTEM, highest privileges) resumes the runbook after the reboot --
no sign-in needed -- and is removed at the end.

  Step 1  check    SCEWIN_64.exe + amigendrv64.sys present, Administrator
  Step 2  export   SCEWIN_64.exe /o /s bios_value_extracted.txt
  Step 3  modify   copy to bios_value_modified.txt, move '*' to the wanted option
  Step 4  import   SCEWIN_64.exe /i /s bios_value_modified.txt [/cpwd <admin_pwd>]  -> reboot
                   (this reboot applies the new BIOS settings)
  Step 5  verify   SCEWIN_64.exe /o /s bios_value_verify.txt     (after the reboot)
  Step 6  check    get_bios_value.py "<knob>" -f bios_value_verify.txt
                   must print the wanted option
  verify_only profiles and verify_knobs are checked right after Step 2, with
  no import and no reboot.

Usage (run ON the Windows SUT, from an Administrator PowerShell / Command Prompt):
  python deploy\\bios_knobs\\configure_bios_knobs_windows.py --marker ifwi_sep5
  python deploy\\bios_knobs\\configure_bios_knobs_windows.py --marker measured_boot --variant dtpm
  python deploy\\bios_knobs\\configure_bios_knobs_windows.py --marker tme --marker measured_boot:ftpm_ptt   # merged
  python deploy\\bios_knobs\\configure_bios_knobs_windows.py list
  python deploy\\bios_knobs\\configure_bios_knobs_windows.py --knob "<Setup Question>=<option>"
  python deploy\\bios_knobs\\configure_bios_knobs_windows.py status
  python deploy\\bios_knobs\\configure_bios_knobs_windows.py resume      # continue by hand (--no-auto-resume)
  python deploy\\bios_knobs\\configure_bios_knobs_windows.py abort

Optional overrides (environment variables):
  SCE_WIN_DIR   Folder with SCEWIN_64.exe + amigendrv64.sys (default: <repo>\\Tools)
  SCE_TOOL      AMISCE binary name                 (default: SCEWIN_64.exe)
  WORK_DIR      AMISCE script files                (default: %USERPROFILE%\\bios_knob)
  STATE_DIR     Runbook state folder               (default: %ProgramData%\\fw-validation\\bios_knob)
  REBOOT_DELAY  Countdown before the reboot, s     (default: 10; Ctrl+C to cancel;
                --reboot-delay N overrides it for this run)
  BIOS_ADMIN_PASSWORD  BIOS Administrator password for /cpwd (default: bios.admin_password
                in config\\test_config.yaml)

Notes:
  - TME is grayed out (import is ignored) unless VT-d is Enabled.
  - Protected setup variables (e.g. CpuSetup: TME, VMX, TXT) are skipped by
    AMISCE without the BIOS Administrator password, yet it still exits 0. Set
    an Administrator password in BIOS Setup and bios.admin_password in
    config\\test_config.yaml; the import then adds /cpwd <admin_pwd> (masked in
    the log, never stored in the state file).
  - If BitLocker protects the system drive, a BIOS change can trigger BitLocker
    recovery at the reboot; the runbook warns about it before the import.
"""

import argparse
import json
import os
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
    describe_sce_exit, explain_unchanged_knobs, info, knob_values_match, load_admin_password, ok,
    print_na, print_profile, report_to_preflight, sce_password_failure, select_profile, warn,
)

def _abs_path(env_name, default):
    """Absolute path from an environment override. run_sce() runs the tool with cwd=TOOL_DIR and the
    resume task starts in another folder, so a relative path would point somewhere else later."""
    return Path(os.environ.get(env_name, str(default))).expanduser().resolve()


# deploy_tools.py stages SCEWIN_64.exe + amigendrv64.sys from Downloads/ into <repo>\Tools
TOOL_DIR = _abs_path("SCE_WIN_DIR", REPO_ROOT / "Tools")
SCE_TOOL = os.environ.get("SCE_TOOL", "SCEWIN_64.exe")
SCE_DRIVER = "amigendrv64.sys"
WORK_DIR = _abs_path("WORK_DIR", Path.home() / "bios_knob")
STATE_DIR = _abs_path(
    "STATE_DIR", Path(os.environ.get("ProgramData", r"C:\ProgramData")) / "fw-validation" / "bios_knob"
)
STATE_FILE = STATE_DIR / "state.json"
RESULT_FILE = STATE_DIR / "last_result.json"
REBOOT_DELAY = int(os.environ.get("REBOOT_DELAY", "10"))
TASK_NAME = "FW_BIOS_Knob_Resume"
# A resume within this many seconds of the import's boot means the SUT has not rebooted yet.
BOOT_TIME_TOLERANCE = 120


# ------------------------------------------------------------------
# State
# ------------------------------------------------------------------

def load_state():
    if not STATE_FILE.is_file():
        return None
    return json.loads(STATE_FILE.read_text(encoding="utf-8"))


def save_state(state):
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    STATE_FILE.write_text(json.dumps(state, indent=2), encoding="utf-8")


def boot_time():
    """Epoch seconds of the last Windows boot."""
    import ctypes

    ctypes.windll.kernel32.GetTickCount64.restype = ctypes.c_ulonglong
    return time.time() - ctypes.windll.kernel32.GetTickCount64() / 1000.0


# ------------------------------------------------------------------
# Pre-checks
# ------------------------------------------------------------------

def require_admin():
    if sys.platform != "win32":
        raise RunbookError("Windows SUT only; on Linux use deploy/bios_knobs/configure_bios_knobs_linux.py.")
    import ctypes

    if not ctypes.windll.shell32.IsUserAnAdmin():
        raise RunbookError("Run from an Administrator PowerShell / Command Prompt (AMISCE needs it).")


def bitlocker_protected():
    drive = os.environ.get("SystemDrive", "C:")
    try:
        out = subprocess.run(["manage-bde", "-status", drive], capture_output=True, text=True, timeout=60).stdout
    except (OSError, subprocess.TimeoutExpired):
        return False
    return "protection on" in out.lower()


def preflight(will_import):
    """Step 1: tool, driver and BitLocker state."""
    print("--- Step 1: pre-checks ---------------------------------------------------")
    tool = TOOL_DIR / SCE_TOOL
    if not tool.is_file() or tool.stat().st_size == 0:
        raise RunbookError(
            f"{SCE_TOOL} not found in {TOOL_DIR}\n"
            "         (AMISCE is for AMI Aptio BIOS only -- on any other BIOS, set the knobs manually in BIOS Setup.)\n"
            "         Put the whole AMISCE package SceWin.7z into Downloads\\ and stage it into Tools\\:\n"
            "           .\\deploy\\setup\\setup_sut_windows.ps1\n"
            "         or:  ..\\venv\\Scripts\\python.exe deploy\\tools\\deploy_tools.py"
        )
    ok(f"AMISCE tool: {tool} ({tool.stat().st_size} bytes)")
    driver = TOOL_DIR / SCE_DRIVER
    if not driver.is_file():
        raise RunbookError(f"{SCE_DRIVER} not found next to {SCE_TOOL} in {TOOL_DIR} (AMISCE loads it at run time)")
    ok(f"AMISCE driver: {driver}")
    info("SCEWIN64.cif / SCEWIN64.sbom.yaml are BIOS build metadata, not needed at run time.")

    if will_import and bitlocker_protected():
        warn("BitLocker protects the system drive; a BIOS change can ask for the recovery key at reboot.")
        info("Suspend it for one reboot first:  manage-bde -protectors -disable %SystemDrive% -RebootCount 1")


# ------------------------------------------------------------------
# AMISCE
# ------------------------------------------------------------------

def run_sce(sce_args, title, cpwd=None):
    """Run SCEWIN_64.exe from its folder (so it finds its driver); raise on a non-zero exit code.
    cpwd: BIOS Administrator password, passed as /cpwd and masked in the log."""
    cmd = [str(TOOL_DIR / SCE_TOOL)] + sce_args
    shown = list(cmd)
    if cpwd:
        cmd += ["/cpwd", cpwd]
        shown += ["/cpwd", PASSWORD_MASK]
    info(f"$ {subprocess.list2cmdline(shown)}")
    try:
        result = subprocess.run(cmd, cwd=str(TOOL_DIR), capture_output=True, text=True, errors="replace",
                                timeout=900)
    except subprocess.TimeoutExpired as exc:
        raise RunbookError(f"{title}: AMISCE did not finish within {exc.timeout} s") from None
    output = result.stdout + result.stderr
    for line in output.splitlines():
        if line.strip():
            info(f"  {line}")
    code = result.returncode
    if code != 0:
        password_failure = sce_password_failure(code)
        if password_failure:
            raise RunbookError(f"{title}: {password_failure}")
        hint = ""
        if code == 0x10:
            hint = (f"\n         Check that {SCE_DRIVER} is next to {SCE_TOOL}; Windows Memory integrity "
                    "(Core isolation) or the vulnerable driver blocklist can also block it.")
        raise RunbookError(f"{title}: AMISCE exit code 0x{code:02X} — {describe_sce_exit(code)}{hint}")
    ok(f"{title}: AMISCE exit code 0x00")
    if "protected variable" in output.lower():
        warn(f"{title}: AMISCE skipped protected variables (see above) -- those knobs keep their old values.")


# ------------------------------------------------------------------
# Resume task / reboot
# ------------------------------------------------------------------

def install_resume_task():
    task_cmd = f'"{sys.executable}" "{SCRIPT_PATH}" resume'
    # At boot as SYSTEM, like the Linux resume unit: continues without anyone signing in. 90 s, after
    # FW_Preflight_Resume's 60 s, so the pre-flight still sees this run as busy and leaves it to us.
    result = subprocess.run(
        ["schtasks", "/create", "/tn", TASK_NAME, "/tr", task_cmd, "/sc", "ONSTART", "/delay", "0001:30",
         "/ru", "SYSTEM", "/rl", "HIGHEST", "/f"],
        capture_output=True, text=True, timeout=30,
    )
    if result.returncode != 0:
        warn(f"Task Scheduler task not created (rc={result.returncode}): {result.stderr.strip()}")
        return False
    ok(f"Auto-resume task installed: {TASK_NAME} (runs at the next boot, no sign-in needed)")
    return True


def remove_resume_task():
    result = subprocess.run(["schtasks", "/delete", "/tn", TASK_NAME, "/f"], capture_output=True, timeout=15)
    if result.returncode == 0:
        ok(f"Auto-resume task removed: {TASK_NAME}")


def reboot(state):
    if state["auto_resume"]:
        info("The runbook resumes automatically after the reboot -- no sign-in needed.")
    else:
        info(f"After the reboot, run (as Administrator):  python {SCRIPT_PATH} resume")
    action(f"Rebooting in {REBOOT_DELAY}s to apply the BIOS settings (Ctrl+C to reboot later yourself).")
    sys.stdout.flush()
    try:
        time.sleep(REBOOT_DELAY)
    except KeyboardInterrupt:
        warn("Reboot cancelled. The imported values are already in NVRAM and apply at the next reboot.")
        info(f"Reboot when ready; the run continues after the reboot (or: python {SCRIPT_PATH} abort).")
        return 0
    result = subprocess.run(["shutdown", "/r", "/t", "0"], capture_output=True, text=True, timeout=30)
    if result.returncode != 0:
        warn(f"shutdown /r failed (rc={result.returncode}): {(result.stderr or result.stdout).strip()}")
        info("The imported values are already in NVRAM -- reboot by hand; the run continues after the reboot.")
        return 1
    return 0


def finish(state, passed, detail):
    remove_resume_task()
    skipped = (state or {}).get("unsupported") or {}
    if skipped:
        detail += "; skipped (not supported by this CPU): " + ", ".join(skipped)
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
    # This run's latest export: the verify export after the import reboot, else the first export.
    script = WORK_DIR / (VERIFY_FILE if (state or {}).get("step") == "import" else EXTRACT_FILE)
    report_to_preflight(passed, detail, values, script)
    return 0 if passed else 1


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

    require_admin()
    if load_state():
        raise RunbookError(
            "A BIOS knob run is already in progress — see 'status', continue with 'resume' "
            "or stop it with 'abort'."
        )
    will_import = bool(knobs) and not profile["verify_only"]
    preflight(will_import)

    state = {
        "knobs": knobs,
        "verify_knobs": profile["verify_knobs"],
        "unsupported": profile.get("unsupported") or {},
        "profile": label,
        "verify_only": profile["verify_only"],
        "work_dir": str(WORK_DIR),
        "tool_dir": str(TOOL_DIR),
        "log": args.log,
        "auto_resume": not args.no_auto_resume,
        "started": datetime.now().isoformat(timespec="seconds"),
    }
    info(f"Operator: {os.environ.get('USERNAME', '?')} (AMISCE scripts in {WORK_DIR})")
    try:
        print("--- Step 2: export (original values) ---------------------------------------")
        WORK_DIR.mkdir(parents=True, exist_ok=True)
        for name in (EXTRACT_FILE, MODIFIED_FILE, VERIFY_FILE):
            path = WORK_DIR / name
            if path.exists():
                path.unlink()
                info(f"Removed old file: {path}")
        extracted = WORK_DIR / EXTRACT_FILE
        run_sce(["/o", "/s", str(extracted)], "Export")

        if state["verify_knobs"]:
            passed, fixed_detail = check_fixed_knobs(state["verify_knobs"], extracted)
            if not passed:
                return finish(state, False, fixed_detail)
            if not knobs:
                return finish(state, True, fixed_detail)
        if state["verify_only"]:
            passed, detail = check_knobs(knobs, extracted)
            return finish(state, passed, "verify only: " + detail)
        if knob_values_match(knobs, extracted):
            # Nothing to change: no import, so no reboot.
            return finish(state, True, "already set: " + ", ".join(f"{q} = {o}" for q, o in knobs.items()))

        print("--- Step 3: modify -------------------------------------------------------")
        modified = WORK_DIR / MODIFIED_FILE
        build_modified_script(extracted, knobs, modified)

        print("--- Step 4: import ---------------------------------------------------------")
        password, source = load_admin_password()
        if password:
            ok(f"BIOS admin password from {source}: the import uses /cpwd (protected variables, e.g. CpuSetup)")
        else:
            info("No BIOS admin password (bios.admin_password): AMISCE skips protected variables, e.g. CpuSetup.")
        run_sce(["/i", "/s", str(modified)], "Import", cpwd=password)
        state.update(step="import", status="pending reboot", boot_time=boot_time(), cpwd=bool(password),
                     updated=datetime.now().isoformat(timespec="seconds"))
        save_state(state)
        if state["auto_resume"] and not install_resume_task():
            state["auto_resume"] = False
            save_state(state)
        return reboot(state)
    except (RunbookError, subprocess.SubprocessError, OSError) as exc:
        return finish(state, False, str(exc))


def cmd_resume(_args):
    global TOOL_DIR, WORK_DIR
    require_admin()
    state = load_state()
    if not state:
        print("No BIOS knob run in progress.")
        remove_resume_task()
        return 0
    # The boot task does not inherit the SCE_WIN_DIR / WORK_DIR overrides of the first run
    TOOL_DIR = Path(state.get("tool_dir", TOOL_DIR))
    WORK_DIR = Path(state.get("work_dir", WORK_DIR))
    print(f"Resuming after step '{state['step']}'")
    if abs(boot_time() - state["boot_time"]) < BOOT_TIME_TOLERANCE:
        raise RunbookError("The SUT has not rebooted since the import — reboot first, then run 'resume'.")
    ok("SUT rebooted since the import")

    try:
        print("--- Step 5: verify export ----------------------------------------------------")
        verify = WORK_DIR / VERIFY_FILE
        if verify.exists():
            verify.unlink()
        run_sce(["/o", "/s", str(verify)], "Verify export")
        passed, detail = check_knobs(state["knobs"], verify)
        if not passed:
            explain_unchanged_knobs(state.get("cpwd", False))
        return finish(state, passed, detail)
    except (RunbookError, subprocess.SubprocessError, OSError) as exc:
        return finish(state, False, str(exc))


def cmd_status(_args):
    state = load_state()
    print("--- BIOS knob configuration progress -----------------------------------------")
    if state:
        info(f"In progress: after step '{state['step']}' ({state['status']}, {state['updated']})")
        info(f"Profile    : {state.get('profile', '?')}")
        info(f"Knobs      : {state['knobs']}")
        if state.get("verify_knobs"):
            info(f"Verify only: {state['verify_knobs']}")
        info(f"Log        : {state['log']}")
        if not state["auto_resume"]:
            info(f"NEXT: reboot, then  python {SCRIPT_PATH} resume")
    elif RESULT_FILE.is_file():
        result = json.loads(RESULT_FILE.read_text(encoding="utf-8"))
        info(f"Last run   : {result['result']} ({result['finished']}) — {result['detail']}")
        info(f"Profile    : {result.get('profile')}")
        info(f"Log        : {result['log']}")
    else:
        info(f"No run recorded yet — start with:  python {SCRIPT_PATH} --marker <marker>")
    print("------------------------------------------------------------------------------")
    return 0


def cmd_abort(_args):
    require_admin()
    state = load_state()
    if state and state.get("step") == "import":
        warn("The import already ran: the new values stay in NVRAM. Re-run with the old options to undo.")
    return finish(state or {}, False, "aborted by operator")


def main():
    global REBOOT_DELAY
    ap = argparse.ArgumentParser(
        description="Pre-flight (Windows): set BIOS knobs per test marker with AMI AMISCE (SCEWIN_64.exe) "
                    "and verify them.",
    )
    add_common_arguments(ap)
    ap.add_argument("--no-auto-resume", action="store_true",
                    help="Do not install the Task Scheduler task; run 'resume' by hand after the reboot.")
    ap.add_argument("--pause", action="store_true", help=argparse.SUPPRESS)
    args = ap.parse_args()
    if args.reboot_delay is not None:
        REBOOT_DELAY = max(0, args.reboot_delay)

    if args.command == "status":
        return cmd_status(args)
    if args.command == "password":
        print("[INFO]   Windows: the BIOS admin password is not stored by this runbook yet. Set the environment")
        print("         variable BIOS_ADMIN_PASSWORD (or bios.admin_password in config\\test_config.yaml).")
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
        log_dir / f"configure_bios_knobs_windows_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
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
    if args.pause:
        input("Press Enter to close this window...")
    return code or 0


if __name__ == "__main__":
    sys.exit(main())
