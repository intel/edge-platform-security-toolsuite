# Copyright 2026 Intel Corporation
# SPDX-License-Identifier: Apache-2.0

"""
TEST -- IEC 62443-4-2  CET (Control-flow Enforcement Technology)  Windows OS  (functional, SUT LOCAL)

Test ID:  IEC62443-4-2-TC_CET-FUNC-SUT
Suite:    cet

PURPOSE
-------
Verifies that CET (Control-flow Enforcement Technology / Shadow Stack) is
enabled and active on a Windows SUT: Kernel-mode Hardware-enforced Stack
Protection is running, and a sample process (msedge.exe) runs with user-mode
shadow stacks.

The operator turns the setting on (Windows Security -> Core isolation), and
the test then READS IT BACK -- the signal file alone never passes:
  - Kernel : Win32_DeviceGuard.SecurityServicesRunning contains 5
             (Kernel-mode Hardware-enforced Stack Protection running)
  - User   : Get-ProcessMitigation -Id <msedge pid> -> UserShadowStack = ON
             for at least one running msedge.exe process
If the check fails the gate re-arms (fix it, create the file again); after
3 failed checks the test FAILS with what was read.

Turning Kernel-mode HSP on needs a restart: restart when Windows asks -- the
test resumes by itself after the reboot (Task Scheduler, no sign-in needed) and keeps waiting.

STEPS
-----
  Step 3.0  -- Enable Kernel-mode Hardware-enforced Stack Protection
               (Windows Security -> Device security -> Core isolation; if the setting
               is not shown there: Task Manager -> Details -> 'Hardware-enforced Stack
               Protection' column -> set ONE msedge.exe from 'Compatible modules only'
               to 'Disabled'), create the signal file. If msedge.exe is not running the
               test starts it on the signed-in desktop itself (one-shot Interactive task)
  Step 3.1  -- Read back: kernel-mode HSP running + msedge.exe shadow stack ON

PRE-TEST (manual, performed before running this script)
-------------------------------------------------------
  1.0)  Flash IFWI and deploy Windows custom image to boot device and connect to SUT.
        - IFWI: Bootguard 5 (BtG5) EXTERNAL release — RPSF_SEP5 variant.
        - Any version from the current BOM release is acceptable.
        - Example (PTL board):
          ECG_PTL_PR04_B0A1-XXXODCA_RPSF_SEP5_11E50692_2026ww01.1.02_BE351556_CRB.bin
  2.0)  Power ON and boot the SUT to Windows OS.
  3.0)  Run this test script from an Administrator PowerShell session.

CONFIG (cet_config.yaml)
--------------------------
  usb_mount                : (optional) keep the state/signal files on this drive, e.g. "D:/"
  manual_gate_timeout_secs : 900            # 15 min per gate (0 = no gate timeout)
  hsp_target_process       : "msedge.exe"

RUN (on SUT, Administrator PowerShell)
---------------------------------------
  cd C:/path/to/asrock_repo
  python -m pytest tests/cet/test_ec62443_cet_sut_wins_func.py -v -s --setup-confirmed --yes
"""

import logging
import re
import subprocess

import pytest

from core.prereq import pre_test_check
from tests.sut_base_test import SUTBaseTest

logger = logging.getLogger(__name__)

# Signal filename -- operator creates this file in the state folder when the setting is on
_SIGNAL_STEP3 = "step3_cet_done.txt"

# Win32_DeviceGuard.SecurityServicesRunning value for Kernel-mode Hardware-enforced Stack Protection
_KERNEL_HSP_SERVICE = 5


@pytest.mark.cet
@pytest.mark.manual
class TestEC62443CETSUTWinsFunc(SUTBaseTest):
    """
    IEC 62443-4-2 CET functional test -- runs directly on the Windows SUT.

    The operator enables Kernel-mode Hardware-enforced Stack Protection; the
    test reads back that it is running and that msedge.exe uses shadow stacks.
    """

    SUITE = "cet"
    TEST_ID = "IEC62443-4-2-TC_CET-FUNC-SUT"

    REBOOTS = (
        ("manual", "Windows Security -> Core isolation: turn ON Kernel-mode Hardware-enforced "
                   "Stack Protection, then restart Windows", "it is not running yet"),
    )

    @classmethod
    def reboot_plan(cls, config: dict) -> list:
        kernel_running = cls._verify_cet("msedge")[1][0].startswith("[OK]")
        return [] if kernel_running else cls._reboots_confirmed(config)

    PRE_TEST_CHECKLIST = [
        "1.0)  Flash IFWI and deploy Windows custom image to boot device and connect to SUT.",
        "      - IFWI: Bootguard 5 (BtG5) EXTERNAL release — RPSF_SEP5 variant.",
        "      - Any version from the current BOM release is acceptable (no",
        "        specific IFWI version is pinned for this test).",
        "      - Example (PTL board):",
        "        ECG_PTL_PR04_B0A1-XXXODCA_RPSF_SEP5_11E50692_2026ww01.1.02_BE351556_CRB.bin",
        "2.0)  Power ON and boot the SUT to Windows OS.",
        "3.0)  Run this test script from an Administrator PowerShell session.",
    ]

    def test_ec62443_cet_sut_wins_func(
        self,
        request,
        config,
        log_dir,
    ):
        """
        IEC62443-4-2-TC_CET-FUNC-SUT

        Step 3.0 : operator enables Kernel-mode HSP and starts msedge.exe
        Step 3.1 : read back -- kernel-mode HSP running, msedge.exe shadow stack ON
        """
        self._begin()
        cfg = self._load_config(config)
        mgr = self._init_state_dir(cfg)

        pre_test_check(request, self.TEST_ID, self.PRE_TEST_CHECKLIST)

        timeout = int(cfg.get("manual_gate_timeout_secs", 900))
        target_process = str(cfg.get("hsp_target_process", "msedge.exe")).strip()
        process_name = re.sub(r"\.exe$", "", target_process, flags=re.IGNORECASE)
        assert re.fullmatch(r"[\w.-]+", process_name), (
            f"[Step 3.0] hsp_target_process in cet_config.yaml is not a plain process name: {target_process!r}"
        )

        # Step 3.0 -- already on? Then no operator action is needed at all.
        passed, evidence = self._verify_cet_started(process_name)
        for line in evidence:
            logger.info("[Step 3.0]   %s", line)
        if passed:
            logger.info("[Step 3.0] [OK] CET already active -- no manual step needed")
        else:
            self._wait_for_manual_signal(
                signal_file=_SIGNAL_STEP3,
                step_label="3.0",
                timeout_secs=timeout,
                verify=lambda: self._verify_cet_started(process_name),
                instructions=[
                    "─" * 64,
                    "STEP 3.0 -- Turn on Kernel-mode Hardware-enforced Stack Protection",
                    "─" * 64,
                    "Now on this SUT:",
                    *[f"  {line}" for line in evidence],
                    "",
                    "3.1) Open 'Windows Security' (Start menu -> search 'Windows Security').",
                    "3.2) Device security --> Core isolation.",
                    "3.3) Turn ON 'Kernel-mode Hardware-enforced Stack Protection'.",
                    "     Restart when Windows asks -- the test resumes by itself after the reboot",
                    "     (no sign-in needed; sign in to see its status and live log windows).",
                    "     Setting not shown under Core isolation? Use Task Manager instead:",
                    "       Task Manager -> Details -> right-click a column header -> Select columns ->",
                    "       tick 'Hardware-enforced Stack Protection'; then on ONE of the msedge.exe rows",
                    "       change it from 'Compatible modules only' to 'Disabled'.",
                    f"3.4) {target_process} must be running: the test starts it on the signed-in desktop",
                    "     by itself -- so sign in on the SUT screen (console/RDP) before creating the file.",
                    "     (To see it yourself: Task Manager -> Details -> column",
                    "      'Hardware-enforced Stack Protection' shows Compatible/Strict.)",
                    "─" * 64,
                ],
            )

        logger.info(
            "[Step 3.1] [OK] CET verified -- Kernel-mode Hardware-enforced Stack Protection running"
            " and user-mode shadow stacks ON for %s.",
            target_process,
        )

        mgr.cleanup()
        self._end()

    @classmethod
    def _verify_cet_started(cls, process_name: str):
        """_verify_cet(), first starting process_name on the signed-in desktop if it is not running."""
        passed, evidence = cls._verify_cet(process_name)
        if passed or not evidence[1].endswith("not running -- start it"):
            return passed, evidence
        started = cls._start_for_console_user(process_name)
        passed, evidence = cls._verify_cet(process_name)
        return passed, [*evidence, started]

    @staticmethod
    def _start_for_console_user(process_name: str) -> str:
        """
        Start process_name in the signed-in console user's session (this test may run as SYSTEM in
        session 0, which has no desktop): a one-shot Interactive task -- no password needed.
        Returns a log line saying what happened.
        """
        args = "--no-first-run about:blank" if process_name.lower() == "msedge" else ""
        task = f"FW_CET_Start_{process_name}"
        script = (
            "$exe = (Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\"
            f"{process_name}.exe' -ErrorAction SilentlyContinue).'(default)';"
            "if (-not $exe) { 'no-path'; return };"
            "$user = (Get-CimInstance Win32_ComputerSystem).UserName;"
            "if (-not $user) { 'no-user'; return };"
            f"$a = New-ScheduledTaskAction -Execute $exe.Trim('\"') {('-Argument ' + repr(args)) if args else ''};"
            "$p = New-ScheduledTaskPrincipal -UserId $user -LogonType Interactive;"
            f"Register-ScheduledTask -TaskName '{task}' -Action $a -Principal $p -Force | Out-Null;"
            f"Start-ScheduledTask -TaskName '{task}';"
            f"for ($i = 0; $i -lt 15 -and -not (Get-Process -Name '{process_name}' -ErrorAction SilentlyContinue); $i++)"
            " { Start-Sleep 1 };"
            "Start-Sleep 3;"
            f"Unregister-ScheduledTask -TaskName '{task}' -Confirm:$false;"
            "'started ' + $user"
        )
        try:
            out = subprocess.run(
                ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
                capture_output=True, text=True, errors="replace", timeout=120,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            return f"[NOT YET] Could not start {process_name}.exe: {exc}"
        result = out.stdout.strip().splitlines()[-1] if out.stdout.strip() else ""
        if result == "no-user":
            return (f"[NOT YET] Nobody is signed in on the SUT screen, so {process_name}.exe cannot be "
                    "started -- sign in (console/RDP), then create the signal file again")
        if result == "no-path":
            return f"[NOT YET] {process_name}.exe is not installed (no App Paths entry) -- start it by hand"
        if result.startswith("started "):
            return f"[INFO] Started {process_name}.exe on the desktop of {result[len('started '):]}"
        return f"[NOT YET] Could not start {process_name}.exe: {(out.stderr or out.stdout).strip()[:300]}"

    @staticmethod
    def _verify_cet(process_name: str):
        """(passed, evidence lines): kernel-mode HSP running + shadow stack ON in a running process_name."""
        script = (
            "$dg = Get-CimInstance -Namespace root\\Microsoft\\Windows\\DeviceGuard -ClassName Win32_DeviceGuard;"
            "'running=' + (@($dg.SecurityServicesRunning) -join ',');"
            f"$procs = @(Get-Process -Name '{process_name}' -ErrorAction SilentlyContinue);"
            "'processes=' + $procs.Count;"
            "'shadowstack_on=' + @($procs | Where-Object {"
            " (Get-ProcessMitigation -Id $_.Id -ErrorAction SilentlyContinue).UserShadowStack.UserShadowStack"
            " -eq 'ON' }).Count"
        )
        try:
            out = subprocess.run(
                ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
                capture_output=True, text=True, errors="replace", timeout=120,
            ).stdout
        except (OSError, subprocess.SubprocessError) as exc:
            return False, [f"Could not query CET state: {exc}"]
        fields = dict(line.split("=", 1) for line in out.splitlines() if "=" in line)
        running = [int(v) for v in fields.get("running", "").split(",") if v.strip().isdigit()]
        processes = int(fields.get("processes", "0") or 0)
        shadow_on = int(fields.get("shadowstack_on", "0") or 0)

        kernel_ok = _KERNEL_HSP_SERVICE in running
        user_ok = shadow_on > 0
        evidence = [
            f"[{'OK' if kernel_ok else 'NOT YET'}] Kernel-mode Hardware-enforced Stack Protection "
            f"{'running' if kernel_ok else 'not running'} "
            f"(Win32_DeviceGuard SecurityServicesRunning = {fields.get('running') or 'none'})",
            f"[{'OK' if user_ok else 'NOT YET'}] {process_name}.exe: "
            + (f"{shadow_on} of {processes} process(es) with user-mode shadow stack ON"
               if processes else "not running -- start it"),
        ]
        return kernel_ok and user_ok, evidence