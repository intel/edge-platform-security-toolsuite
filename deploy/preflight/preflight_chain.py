#!/usr/bin/env python3
# Copyright 2026 Intel Corporation
# SPDX-License-Identifier: Apache-2.0
"""
deploy/preflight/preflight_chain.py — carry the test_runner.py pre-flight across reboots.

test_runner.py works out what the SUT needs before the selected tests can run
(Secure Boot on, BIOS knobs set) and writes the plan to logs/preflight_plan.json.
Steps that reboot the SUT are done by the existing runbooks, which keep their
own resume units/tasks. When a runbook finishes it reports here
(`next --from <step>`), and this script starts the next step: the next runbook
(as root / Administrator) or the tests (as the user who picked them). After a
reboot that no runbook continues (e.g. into BIOS Setup), the resume unit
fw-preflight-resume.service (Linux) / boot task FW_Preflight_Resume (Windows, as SYSTEM)
runs `next --boot`.

Standard library only: the runbooks call it with the system python3.

Plan steps, in order (each: pending -> running -> done, or failed):
  bios_setup   knobs set by hand in BIOS Setup (non-AMI BIOS); after the reboot every
               knob is read back (core/bios_knob_checks.py) -- a wrong one stops the plan
  secure_boot  deploy/secure_boot/enable_secure_boot*.{sh,ps1} auto -- on Linux "done" means
               Secure Boot on with OUR keys in PK/KEK/db (deploy/secure_boot/sb_keys.py), not factory keys
  bios_knobs   deploy/bios_knobs/configure_bios_knobs_*.py --marker ... (AMI BIOS)
  tests        pytest on the selected node ids

Usage:
  python3 deploy/preflight/preflight_chain.py status
  python3 deploy/preflight/preflight_chain.py cancel           # drop the plan (root/Admin to remove the unit)
  sudo python3 deploy/preflight/preflight_chain.py arm         # install the resume unit / logon task
  sudo python3 deploy/preflight/preflight_chain.py next --boot # what the resume unit runs
  ... next --from <step> --result pass|fail --detail "<text>"  # what the runbooks run
"""

import argparse
import json
import os
import platform
import shutil
import subprocess
import sys
from datetime import datetime
from pathlib import Path

PREFLIGHT_DIR = Path(__file__).resolve().parent
REPO_ROOT = PREFLIGHT_DIR.parents[1]
sys.path.insert(0, str(REPO_ROOT))
from core import bios_knob_checks as knob_checks  # noqa: E402

LOGS_DIR = REPO_ROOT / "logs"
PLAN_FILE = LOGS_DIR / "preflight_plan.json"
LAST_PLAN_FILE = LOGS_DIR / "preflight_last.json"
LOG_FILE = LOGS_DIR / "preflight.log"
KNOB_LAST_PASS_FILE = LOGS_DIR / "bios_knobs_last_pass.json"
TEST_RESUME_LOG = LOGS_DIR / "resume_service.log"

SB_SCRIPT_LINUX = REPO_ROOT / "deploy" / "secure_boot" / "enable_secure_boot.sh"
SB_SCRIPT_WINDOWS = REPO_ROOT / "deploy" / "secure_boot" / "enable_secure_boot_windows.ps1"
KNOB_SCRIPT_LINUX = REPO_ROOT / "deploy" / "bios_knobs" / "configure_bios_knobs_linux.py"
KNOB_SCRIPT_WINDOWS = REPO_ROOT / "deploy" / "bios_knobs" / "configure_bios_knobs_windows.py"

UNIT_NAME = "fw-preflight-resume.service"
UNIT_PATH = Path("/etc/systemd/system") / UNIT_NAME
WIN_TASK = "FW_Preflight_Resume"

# Runbooks that continue by themselves after a reboot (they report here when done).
LINUX_SB_UNIT = Path("/etc/systemd/system/fw-secure-boot-resume.service")
LINUX_KNOB_UNIT = Path("/etc/systemd/system/fw-bios-knob-resume.service")
LINUX_KNOB_STATE = Path("/var/lib/fw-validation/bios_knob/state.json")   # root-only folder
WIN_SB_TASK = "SecureBootAutoResume"
WIN_KNOB_STATE = Path(os.environ.get("ProgramData", r"C:\ProgramData")) / "fw-validation" / "bios_knob" / "state.json"

SECURE_BOOT_EFIVAR = Path("/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c")
SB_KEYS_DIR = REPO_ROOT / "deploy" / "secure_boot"   # sb_keys.py: whose keys PK/KEK/db hold

STEP_TITLES = {
    "bios_setup": "Set BIOS knobs by hand in BIOS Setup",
    "secure_boot": "Enable Secure Boot",
    "bios_admin_setup": "Set the BIOS admin password in BIOS Setup",
    "bios_knobs": "Set BIOS knobs with AMISCE",
    "tests": "Run the tests",
}


def is_windows():
    return platform.system() == "Windows"


def is_root():
    if is_windows():
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    return os.geteuid() == 0


# ------------------------------------------------------------------
# SUT facts (read-only)
# ------------------------------------------------------------------

# Shared with the tests (core/bios_knob_checks.py, standard library only).
boot_id = knob_checks.boot_id
bios_identity = knob_checks.bios_identity
detect_ami = knob_checks.detect_ami
tpm_manufacturer = knob_checks.tpm_manufacturer


def secure_boot_state():
    """True / False if UEFI Secure Boot is on / off, None if it cannot be read."""
    if is_windows():
        try:
            import winreg
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                                r"SYSTEM\CurrentControlSet\Control\SecureBoot\State") as key:
                return winreg.QueryValueEx(key, "UEFISecureBootEnabled")[0] == 1
        except OSError:
            return None
    try:
        data = SECURE_BOOT_EFIVAR.read_bytes()
        return len(data) >= 5 and data[4] == 1
    except OSError:
        pass
    try:
        out = subprocess.run(["mokutil", "--sb-state"], capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.SubprocessError):
        return None
    text = (out.stdout + out.stderr).lower()
    if "secureboot enabled" in text:
        return True
    return False if "secureboot disabled" in text else None


def _sb_keys():
    if str(SB_KEYS_DIR) not in sys.path:
        sys.path.insert(0, str(SB_KEYS_DIR))
    import sb_keys
    return sb_keys


def secure_boot_key_owner():
    """Linux: setup | partial | ours | foreign | unknown (deploy/secure_boot/sb_keys.py); Windows: None."""
    if is_windows():
        return None
    return _sb_keys().read_state().owner


def secure_boot_ready():
    """
    (ready, why). Linux: Secure Boot is on AND the firmware holds our own keys (PK/KEK) with our
    cert in db -- with factory keys the UEFI Shell refuses every tool we sign, so that is not ready.
    Windows: Secure Boot is on.
    """
    if is_windows():
        state = secure_boot_state()
        return state is True, "Secure Boot is " + {True: "ENABLED", False: "DISABLED", None: "unknown"}[state]
    return _sb_keys().ready()


def os_check_knob(question, option):
    """True = the OS reads the knob as wanted, False = it reads something else, None = cannot tell."""
    return knob_checks.check_knob(question, option).ok


def changed_setup_variables(recorded):
    """
    BIOS Setup variables (core/bios_knob_checks.py SETUP_VARIABLES) that differ from the
    recorded setup_fingerprint(): [] = unchanged, None = cannot compare (not readable here,
    or nothing recorded).
    """
    current = knob_checks.setup_fingerprint()
    if current is None or not recorded:
        return None
    return sorted({n.rsplit("-", 5)[0] for n in set(recorded) | set(current)
                   if recorded.get(n) != current.get(n)})


def knob_cache_status(values):
    """
    (cached, why). cached = the last AMISCE PASS on this exact BIOS build already covered every
    knob in values, the BIOS Setup variables are unchanged since (no knob changed in BIOS Setup,
    no IFWI reflash) and nothing the OS can read contradicts it.
    """
    try:
        last = json.loads(KNOB_LAST_PASS_FILE.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return False, "no AMISCE PASS recorded"
    if not knob_checks.same_bios_build(last.get("bios")):
        return False, "the last AMISCE PASS was on another BIOS build"
    known = {str(k).lower(): str(v).lower() for k, v in (last.get("values") or {}).items()}
    missing = [q for q, o in values.items() if known.get(q.lower()) != str(o).lower()]
    if missing:
        return False, "not covered by the last AMISCE PASS: " + ", ".join(missing)
    recorded = last.get("setup_fingerprint")
    if not recorded and knob_checks.setup_fingerprint() is not None:
        return False, "the last AMISCE PASS has no BIOS settings fingerprint (older record) -- checking again"
    changed = changed_setup_variables(recorded)
    if changed:
        return False, (f"BIOS settings changed since the last AMISCE PASS ({', '.join(changed)}) -- "
                       "a knob changed in BIOS Setup, or the IFWI was flashed")
    wrong = [r for r in knob_checks.check_knobs(values) if r.ok is False]
    if wrong:
        return False, "the OS reads " + ", ".join(f'"{r.question}" as {r.actual}' for r in wrong)
    return True, "the last AMISCE PASS on this BIOS build covered them, BIOS settings unchanged since"


def knobs_cached(values):
    """True if knob_cache_status() says the last AMISCE PASS still covers every knob in values."""
    return knob_cache_status(values)[0]


def record_knob_pass(values, still_set=None):
    """
    Called by the knob runbooks on PASS: remember the values and the BIOS Setup variables'
    fingerprint for this BIOS build. Knobs from an earlier PASS are kept only while still true:
    still_set(question, option) checks them in the runbook's fresh AMISCE export; without it
    they are kept only if the BIOS settings are unchanged since that PASS.
    """
    bios = bios_identity()
    merged = {}
    try:
        last = json.loads(KNOB_LAST_PASS_FILE.read_text(encoding="utf-8"))
        if knob_checks.same_bios_build(last.get("bios"), bios):
            unchanged = changed_setup_variables(last.get("setup_fingerprint")) == []
            for question, option in (last.get("values") or {}).items():
                if still_set(question, option) if still_set else unchanged:
                    merged[question] = option
    except (OSError, ValueError):
        pass
    merged.update(values)
    LOGS_DIR.mkdir(parents=True, exist_ok=True)
    KNOB_LAST_PASS_FILE.write_text(json.dumps({
        "bios": bios, "values": merged, "setup_fingerprint": knob_checks.setup_fingerprint(),
        "finished": datetime.now().isoformat(timespec="seconds"),
    }, indent=2), encoding="utf-8")
    if not is_windows():
        os.chmod(KNOB_LAST_PASS_FILE, 0o644)


# ------------------------------------------------------------------
# Plan file + log
# ------------------------------------------------------------------

def _plan_user():
    plan = load_plan()
    return (plan or {}).get("user") or ""


def give_to_user(path, user=None):
    """Files root writes in logs/ stay owned by the test user, so test_runner.py can update them."""
    if is_windows() or not is_root():
        return
    user = user or _plan_user()
    if user and user != "root":
        try:
            shutil.chown(path, user=user)
        except (OSError, LookupError):
            pass


def log(msg):
    print(msg, flush=True)
    try:
        LOGS_DIR.mkdir(parents=True, exist_ok=True)
        new = not LOG_FILE.exists()
        with open(LOG_FILE, "a", encoding="utf-8") as fh:
            fh.write(f"{datetime.now().isoformat(timespec='seconds')}  {msg}\n")
        if new:
            give_to_user(LOG_FILE)
    except OSError:
        pass


def load_plan(path=None):
    try:
        return json.loads(Path(path or PLAN_FILE).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def save_plan(plan):
    LOGS_DIR.mkdir(parents=True, exist_ok=True)
    PLAN_FILE.write_text(json.dumps(plan, indent=2), encoding="utf-8")
    give_to_user(PLAN_FILE, plan.get("user"))


def new_plan(tests, python, pytest_args, steps, user):
    return {
        "created": datetime.now().isoformat(timespec="seconds"),
        "runner_boot": boot_id(),
        "user": user,
        "python": python,
        "pytest_args": list(pytest_args),
        "tests": list(tests),
        "status": "running",
        "steps": [dict(step, status=step.get("status", "pending")) for step in steps],
    }


def find_step(plan, name):
    return next((s for s in plan.get("steps", []) if s["name"] == name), None)


def step_position(plan, step):
    steps = plan.get("steps", [])
    return steps.index(step) + 1, len(steps)


def runbook_in_progress():
    """Name of a runbook that continues by itself after the next reboot, or ''."""
    if is_windows():
        if WIN_KNOB_STATE.exists():
            return "BIOS knob configuration"
        try:
            out = subprocess.run(["schtasks", "/query", "/tn", WIN_SB_TASK], capture_output=True, timeout=15)
            if out.returncode == 0:
                return "Secure Boot enablement"
        except (OSError, subprocess.SubprocessError):
            pass
        return ""
    # os.path.exists: False (not an error) when a normal user cannot look into the root-only folder.
    if LINUX_KNOB_UNIT.exists() or os.path.exists(LINUX_KNOB_STATE):
        return "BIOS knob configuration"
    if LINUX_SB_UNIT.exists():
        return "Secure Boot enablement"
    return ""


def fail_plan(plan, reason):
    plan["status"] = "failed"
    plan["error"] = reason
    plan["finished"] = datetime.now().isoformat(timespec="seconds")
    save_plan(plan)
    disarm(quiet=True)
    log(f"[FAIL] Pre-flight stopped: {reason}")
    log("       The tests were not started. Fix the problem, then pick the tests again in test_runner.py.")
    return 1


def close_plan(plan, status):
    plan["status"] = status
    plan["finished"] = datetime.now().isoformat(timespec="seconds")
    LAST_PLAN_FILE.write_text(json.dumps(plan, indent=2), encoding="utf-8")
    give_to_user(LAST_PLAN_FILE, plan.get("user"))
    try:
        PLAN_FILE.unlink()
    except OSError:
        pass
    disarm(quiet=True)


# ------------------------------------------------------------------
# Resume unit (Linux) / logon task (Windows)
# ------------------------------------------------------------------

def _install_status_window():
    """Windows: logon task that opens the live status window -- the runs at boot have no window."""
    try:
        sys.path.insert(0, str(REPO_ROOT / "deploy" / "resume"))
        import status_window
        status_window.install(quiet=True)
    except Exception as exc:  # noqa: BLE001 -- the window is a convenience, never a reason to stop
        log(f"[WARN] Could not install the status window logon task: {exc}")

def arm():
    if not is_root():
        log("[FAIL] 'arm' needs root (Linux) / Administrator (Windows).")
        return 1
    if is_windows():
        # At boot as SYSTEM: continues whether or not anyone signs in. 60 s, after the Secure Boot task's
        # 30 s, so that task is already running (and seen as busy) when this one checks.
        task_cmd = f'"{sys.executable}" "{Path(__file__).resolve()}" next --boot'
        out = subprocess.run(["schtasks", "/create", "/tn", WIN_TASK, "/tr", task_cmd, "/sc", "ONSTART",
                              "/delay", "0001:00", "/ru", "SYSTEM", "/rl", "HIGHEST", "/f"],
                             capture_output=True, text=True, timeout=30)
        if out.returncode != 0:
            log(f"[FAIL] Could not create the boot task {WIN_TASK}: {out.stderr.strip()}")
            return 1
        _install_status_window()
        log(f"[OK] Pre-flight continues at the next boot, no sign-in needed (task {WIN_TASK}).")
        return 0
    UNIT_PATH.write_text(
        "[Unit]\n"
        "Description=Continue the test_runner.py pre-flight after reboot (deploy/preflight/preflight_chain.py)\n"
        "Wants=network-online.target\n"
        "After=local-fs.target network-online.target fw-secure-boot-resume.service fw-bios-knob-resume.service\n"
        f"ConditionPathExists={PLAN_FILE}\n"
        "\n[Service]\n"
        "Type=oneshot\n"
        f"ExecStart={sys.executable} {Path(__file__).resolve()} next --boot\n"
        "TimeoutStartSec=infinity\n"
        "StandardOutput=journal+console\n"
        "StandardError=journal+console\n"
        "\n[Install]\n"
        "WantedBy=multi-user.target\n",
        encoding="utf-8",
    )
    subprocess.run(["systemctl", "daemon-reload"], check=False, timeout=60)
    out = subprocess.run(["systemctl", "enable", UNIT_NAME], capture_output=True, text=True, check=False, timeout=60)
    if out.returncode != 0:
        log(f"[FAIL] Could not enable {UNIT_NAME}: {out.stderr.strip()}")
        return 1
    log(f"[OK] Pre-flight continues after the next boot ({UNIT_NAME}).")
    return 0


def disarm(quiet=False):
    if is_windows():
        out = subprocess.run(["schtasks", "/delete", "/tn", WIN_TASK, "/f"], capture_output=True, timeout=15)
        if out.returncode == 0 and not quiet:
            log(f"[OK] Boot task {WIN_TASK} removed.")
        return 0
    if UNIT_PATH.exists():
        if not is_root():
            if not quiet:
                log(f"[WARN] {UNIT_PATH} is left behind (needs root to remove); it does nothing without a plan.")
            return 0
        subprocess.run(["systemctl", "disable", UNIT_NAME], capture_output=True, check=False, timeout=60)
        UNIT_PATH.unlink()
        subprocess.run(["systemctl", "daemon-reload"], check=False, timeout=60)
        if not quiet:
            log(f"[OK] {UNIT_NAME} removed.")
    return 0


# ------------------------------------------------------------------
# Running the steps
# ------------------------------------------------------------------

def run_secure_boot_runbook():
    if is_windows():
        cmd = ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(SB_SCRIPT_WINDOWS), "auto"]
    else:
        cmd = ["bash", str(SB_SCRIPT_LINUX), "auto"]
    log(f"Running: {' '.join(cmd)}")
    return subprocess.run(cmd, cwd=REPO_ROOT).returncode


def run_knob_runbook(plan, step):
    script = KNOB_SCRIPT_WINDOWS if is_windows() else KNOB_SCRIPT_LINUX
    markers = [arg for spec in step.get("markers", []) for arg in ("--marker", spec)]
    cmd = [plan.get("python") or sys.executable, str(script), *markers]
    log(f"Running: {' '.join(cmd)}")
    return subprocess.run(cmd, cwd=REPO_ROOT).returncode


def start_tests(plan):
    """Start the selected tests: as the queuing user via systemd-run (Linux), in this window (Windows)."""
    tests = plan.get("tests") or []
    step = find_step(plan, "tests")
    if step:
        step["status"] = "done"
    close_plan(plan, "done")
    if not tests:
        log("[WARN] The plan listed no tests -- nothing to start.")
        return 0
    python = plan.get("python") or sys.executable
    if not Path(python).exists():
        python = shutil.which("python3") or sys.executable
    cmd = [python, "-m", "pytest", *tests, "-v", "-s", "--setup-confirmed", "--yes", *plan.get("pytest_args", [])]
    log(f"[OK] SUT ready. Starting {len(tests)} test(s):")
    for test in tests:
        log(f"       {test}")

    if is_windows():
        log("Results afterwards: python test_runner.py -> L (Last run results)")
        rc = subprocess.run(cmd, cwd=REPO_ROOT).returncode
        log(f"pytest finished (exit {rc}).")
        return 0

    user = plan.get("user") or "root"
    LOGS_DIR.mkdir(parents=True, exist_ok=True)
    if not TEST_RESUME_LOG.exists():
        TEST_RESUME_LOG.touch()
        give_to_user(TEST_RESUME_LOG, user)
    with open(TEST_RESUME_LOG, "a", encoding="utf-8") as fh:
        fh.write(f"========== Starting tests after the test_runner.py pre-flight: {datetime.now()} ==========\n")
    if not is_root():
        return subprocess.run(cmd, cwd=REPO_ROOT).returncode
    unit = f"fw-tests-after-preflight-{datetime.now().strftime('%Y%m%d%H%M%S')}"
    subprocess.run([
        "systemd-run", f"--unit={unit}", "--collect", "--no-block", f"--uid={user}",
        "--description=Tests selected in test_runner.py, started after the pre-flight",
        "-p", f"WorkingDirectory={REPO_ROOT}",
        "-p", f"StandardOutput=append:{TEST_RESUME_LOG}",
        "-p", f"StandardError=append:{TEST_RESUME_LOG}",
        *cmd,
    ], check=True)
    log(f"[OK] Tests started as {user} (systemd unit {unit}). Progress: {TEST_RESUME_LOG}")
    log("     Results afterwards: python3 test_runner.py -> L (Last run results)")
    return 0


def verify_bios_setup(plan, step):
    """
    After the BIOS Setup reboot: prove the reboot happened and read every knob back.
    A wrong knob stops the plan; a knob no check can read is recorded as confirmed by the operator.
    """
    if plan.get("runner_boot") == boot_id():
        fail_plan(plan, "the SUT has not rebooted since test_runner.py asked for BIOS Setup -- "
                        "the BIOS knobs cannot have been changed")
        return False
    log("[OK]   SUT rebooted since test_runner.py asked for BIOS Setup")
    results = knob_checks.check_knobs(step.get("knobs") or {})
    log("       BIOS knobs read back:")
    for line in knob_checks.format_results(results, indent="         "):
        log(line)

    wrong = [r for r in results if r.ok is False]
    if wrong:
        paths = _menu_paths()
        log("       Set these in BIOS Setup (F2), then Save & Exit (F4):")
        for r in wrong:
            log(f'         "{r.question}" = {r.expected}   F2 -> {paths.get(r.question.lower(), "search BIOS Setup for the name")}')
        fail_plan(plan, f"{len(wrong)} BIOS knob(s) still not set after BIOS Setup: "
                        + ", ".join(f'"{r.question}"' for r in wrong))
        return False

    unknown = {r.question: r.expected for r in results if r.ok is None}
    if unknown:
        knob_checks.record_attested(unknown, "set by hand in BIOS Setup during the test_runner.py pre-flight")
        log(f"[NOTE] {len(unknown)} knob(s) cannot be read back on this BIOS; the tests count them as confirmed by you.")
    return True


def _menu_paths():
    sys.path.insert(0, str(REPO_ROOT / "deploy" / "bios_knobs"))
    try:
        from bios_knob_common import load_menu_paths
    except ImportError:
        return {}
    return load_menu_paths()


def _bios_password():
    sys.path.insert(0, str(REPO_ROOT / "deploy" / "bios_knobs"))
    import bios_password
    return bios_password


BIOS_PASSWORD_STEPS = ("Security -> Administrator Password -> type the password you chose in test_runner.py "
                       "(twice), then Save & Exit (F4)")


def reboot_for_bios_password(plan, step):
    """Pending 'bios_admin_setup' step: reboot into BIOS Setup, where the operator types the stored password."""
    step["status"] = "running"
    save_plan(plan)
    log(f"       The SUT reboots into BIOS Setup now: {BIOS_PASSWORD_STEPS}.")
    log("       The pre-flight checks the BIOS has the password after the boot, then continues.")
    if subprocess.run(["systemctl", "reboot", "--firmware-setup"], timeout=60).returncode != 0:
        log("[WARN] This firmware cannot be asked to open BIOS Setup -- press F2 while the SUT boots.")
        result = subprocess.run(["systemctl", "reboot"], capture_output=True, text=True, timeout=60)
        if result.returncode != 0:
            return fail_plan(plan, f"systemctl reboot failed (rc={result.returncode}): {result.stderr.strip()}")
    return 0


def verify_bios_password(plan, step):
    """After the BIOS Setup reboot: the BIOS must now have an admin password (AMITSESetup)."""
    is_set, _fingerprint = knob_checks.ami_admin_password()
    if not is_set:
        fail_plan(plan, "the BIOS still has no Administrator password -- set it in BIOS Setup "
                        f"({BIOS_PASSWORD_STEPS}); pick the tests again to retry")
        return False
    _bios_password().mark_set_in_bios()
    step["status"] = "done"
    save_plan(plan)
    log("[OK] The BIOS now has an Administrator password; AMISCE uses the stored one (/cpwd).")
    return True


def advance(plan):
    """Start the next pending step. Returns after a runbook has been started (it reports back itself)."""
    while True:
        step = next((s for s in plan["steps"] if s["status"] == "pending"), None)
        if step is None:
            close_plan(plan, "done")
            return 0
        name = step["name"]
        pos, total = step_position(plan, step)
        log(f"--- Pre-flight step {pos}/{total}: {STEP_TITLES.get(name, name)}")

        if name == "bios_setup":
            if not verify_bios_setup(plan, step):
                return 1
            step["status"] = "done"
            save_plan(plan)
            continue

        if name == "bios_admin_setup":
            if knob_checks.ami_admin_password()[0]:
                # Already set (e.g. typed in BIOS Setup during an earlier reboot).
                if not verify_bios_password(plan, step):
                    return 1
                continue
            return reboot_for_bios_password(plan, step)

        if name == "secure_boot":
            ready, why = secure_boot_ready()
            if ready:
                log(f"[OK] {why}.")
                step["status"] = "done"
                save_plan(plan)
                continue
            log(f"       {why}")
            step["status"] = "running"
            save_plan(plan)
            rc = run_secure_boot_runbook()
        elif name == "bios_knobs":
            step["status"] = "running"
            save_plan(plan)
            rc = run_knob_runbook(plan, step)
        elif name == "tests":
            return start_tests(plan)
        else:
            return fail_plan(plan, f"unknown step '{name}' in {PLAN_FILE}")

        # The runbook reports PASS/FAIL itself (which may already have moved the plan on).
        latest = load_plan()
        if latest and rc != 0:
            current = find_step(latest, name)
            if current and current["status"] == "running":
                busy = runbook_in_progress() if is_windows() else ""
                if busy:
                    # The runbook's own reboot closed its window (e.g. exit 0x40010004); its task resumes it.
                    log(f"{busy}: the SUT is rebooting -- it continues by itself after the next boot.")
                    return 0
                return fail_plan(latest, f"{STEP_TITLES[name]}: runbook exited with code {rc} -- see its log")
        return 0


def cmd_next(args):
    plan = load_plan()
    if not plan or plan.get("status") != "running":
        if args.step or args.boot:
            log("No pre-flight plan in progress -- nothing to continue.")
        disarm(quiet=True)
        return 0

    if args.step:
        step = find_step(plan, args.step)
        if not step or step["status"] != "running":
            # Runbook started by hand, not by the plan.
            return 0
        if args.result == "fail":
            return fail_plan(plan, f"{STEP_TITLES.get(args.step, args.step)}: {args.detail or 'failed'}")
        step["status"] = "done"
        step["detail"] = args.detail or ""
        save_plan(plan)
        log(f"[OK] {STEP_TITLES.get(args.step, args.step)}: {args.detail or 'done'}")
        if plan.get("runner_boot") == boot_id():
            # test_runner.py is still running in this boot and continues the plan itself.
            return 0
    elif args.boot:
        busy = runbook_in_progress()
        if busy:
            log(f"{busy} is still in progress; it continues the pre-flight when it finishes.")
            return 0
        stuck = next((s for s in plan["steps"] if s["status"] == "running"), None)
        if stuck and stuck["name"] == "bios_admin_setup":
            # Back from the BIOS Setup reboot for the admin password.
            if not verify_bios_password(plan, stuck):
                return 1
            stuck = None
        if stuck:
            return fail_plan(plan, f"{STEP_TITLES.get(stuck['name'], stuck['name'])} stopped before it "
                                   "finished -- see logs/enable_secure_boot*_auto.log or logs/configure_bios_knobs_*.log")
    if not is_root():
        log("[FAIL] Continuing the pre-flight needs root (Linux) / Administrator (Windows).")
        return 1
    return advance(plan)


def cmd_status(_args):
    plan = load_plan()
    if not plan:
        last = load_plan(LAST_PLAN_FILE)
        print("No pre-flight in progress." + (f" Last: {last.get('status')} ({last.get('finished')})" if last else ""))
        return 0
    print(f"Pre-flight plan ({plan.get('status')}), created {plan.get('created')}:")
    for i, step in enumerate(plan["steps"], 1):
        print(f"  {i}. [{step['status']:<7}] {STEP_TITLES.get(step['name'], step['name'])}")
    if plan.get("error"):
        print(f"  Error: {plan['error']}")
    print(f"  Tests: {len(plan.get('tests', []))}   Log: {LOG_FILE}")
    return 0


def cmd_cancel(_args):
    plan = load_plan()
    if plan:
        close_plan(plan, "cancelled")
        log("Pre-flight plan cancelled; the tests will not start by themselves.")
    else:
        disarm(quiet=True)
    return 0


def report(step, passed, detail):
    """For Python runbooks: same as `next --from <step> --result pass|fail --detail <detail>`."""
    args = argparse.Namespace(step=step, result="pass" if passed else "fail", detail=detail, boot=False)
    try:
        return cmd_next(args)
    except Exception as exc:  # noqa: BLE001 -- a runbook must not fail because of this hook
        log(f"[WARN] Could not continue the pre-flight: {exc}")
        return 1


def main():
    ap = argparse.ArgumentParser(description="Continue the test_runner.py pre-flight across reboots.")
    sub = ap.add_subparsers(dest="command", required=True)
    nxt = sub.add_parser("next", help="continue with the next step")
    nxt.add_argument("--from", dest="step", choices=sorted(STEP_TITLES), help="step that just finished")
    nxt.add_argument("--result", choices=["pass", "fail"], default="pass")
    nxt.add_argument("--detail", default="")
    nxt.add_argument("--boot", action="store_true", help="run by the resume unit / logon task after a reboot")
    nxt.add_argument("--pause", action="store_true", help=argparse.SUPPRESS)
    sub.add_parser("arm", help="install the resume unit / logon task")
    sub.add_parser("disarm", help="remove the resume unit / logon task")
    sub.add_parser("status", help="show the plan")
    sub.add_parser("cancel", help="drop the plan")
    args = ap.parse_args()
    if args.command == "next":
        code = cmd_next(args)
        if args.pause and is_windows():
            input("Press Enter to close this window...")
        return code
    handlers = {"arm": lambda _a: arm(), "disarm": lambda _a: disarm(), "status": cmd_status, "cancel": cmd_cancel}
    return handlers[args.command](args)


if __name__ == "__main__":
    sys.exit(main())
