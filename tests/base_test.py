# Copyright 2026 Intel Corporation
# SPDX-License-Identifier: Apache-2.0

"""
BaseTest — shared base class for all IEC 62443-4-2 test cases.

Every test class in this project MUST inherit from BaseTest:

    class TestEC62443MyTopic(BaseTest):
        SUITE    = "mytopic"      # matches config/suites/mytopic_config.yaml
        TEST_ID  = "IEC62443-4-2-TC_MY_TOPIC-FUNC"
        ...

BaseTest provides:
  - _cfg        : auto-loaded suite config dict (config/suites/<SUITE>_config.yaml)
  - _boot_key   : firmware.boot_menu_key from global config
  - log()       : prefixed logger helper
  - step()      : context manager that prints a header and captures failures
  - ssh()       : one-line SSH + assert helper (replaces repeated rc == 0 checks)
  - enter_shell(): thin wrapper around serial_manager.enter_uefi_shell

Nothing in BaseTest depends on a specific test; it is purely infrastructure.
"""

import importlib
import logging
import re
import subprocess
import sys
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple

import pytest

from conftest import load_suite_config, WIN_RESUME_ARGS_PATH, WIN_RESUME_TASK
from core import bios_knob_checks
from core.reboot_plan import entry as reboot_entry

logger = logging.getLogger(__name__)

_REPO_ROOT = Path(__file__).resolve().parents[1]


class BaseTest:
    """
    Shared base for all IEC 62443-4-2 pytest test classes.

    Subclass MUST define:
        SUITE   (str) — suite name matching config/suites/<SUITE>_config.yaml
        TEST_ID (str) — full test case identifier, e.g. "IEC62443-4-2-TC_TXT-FUNC"
    """

    SUITE: str = ""
    TEST_ID: str = ""

    # Local tool/script paths; relative values are repo-relative.
    _REPO_RELATIVE_PATH_KEYS = (
        "sut_meinfo_path_linux", "sut_meinfo_path_windows",
        "sut_checkquote_script", "sut_helper_script",
        "coreinfo_exe_path",
    )

    _request = None
    _strict_verification: bool = False
    _amisce_override: str = "auto"

    # Reboots this test causes, in order: (kind, what happens / what to set[, only if ...]).
    # kind "auto" = the SUT reboots by itself, "manual" = the operator reboots (BIOS Setup).
    # Shown in the batch status window after every reboot (core/reboot_plan.py).
    REBOOTS: tuple = ()

    @classmethod
    def reboot_plan(cls, config: dict) -> list:
        """Planned reboots for this run; override to drop ones this SUT does not need."""
        return [reboot_entry(*r) for r in cls.REBOOTS]

    @classmethod
    def _reboots_confirmed(cls, config: dict) -> list:
        """REBOOTS once an override has checked that its 'only if' condition holds on this SUT."""
        return [reboot_entry(r[0], f"{r[1]} -- {r[2]}" if len(r) > 2 else r[1]) for r in cls.REBOOTS]

    @classmethod
    def _bios_knobs_readable(cls, spec: str, config: dict) -> bool:
        """True if the test can read every knob of spec (AMI BIOS / OS check / pre-flight): no BIOS trip by hand."""
        if bios_knob_checks.detect_ami(str((config.get("bios") or {}).get("amisce", "auto")))[0]:
            return True
        knob_lib = cls._knob_lib()
        profile, _label = knob_lib.resolve_markers(knob_lib.DEFAULT_CONFIG, [spec])
        wanted = {**profile["knobs"], **profile["verify_knobs"]} if profile else {}
        return all(r.ok is not None for r in bios_knob_checks.check_knobs(wanted, attested=True))

    @pytest.fixture(autouse=True)
    def _base_request(self, request):
        """Keep `request` so helpers can note operator-confirmed steps and read the batch queue."""
        self._request = request
        yield

    # ------------------------------------------------------------------
    # Config helpers
    # ------------------------------------------------------------------

    def _load_config(self, global_config: dict) -> dict:
        """
        Load the suite-specific config.

        Stores it on self._cfg and self._boot_key for convenience.
        Call this once at the start of your test function.
        """
        self._cfg: dict = load_suite_config(self.SUITE)
        self._boot_key: str = global_config.get("firmware", {}).get("boot_menu_key", "F2")
        self._strict_verification = bool((global_config.get("verification") or {}).get("strict", False))
        self._amisce_override = str((global_config.get("bios") or {}).get("amisce", "auto"))
        for key in self._REPO_RELATIVE_PATH_KEYS:
            value = str(self._cfg.get(key) or "").strip()
            if value and not Path(value).is_absolute():
                self._cfg[key] = str(_REPO_ROOT / value)
        return self._cfg

    # ------------------------------------------------------------------
    # Logging helpers
    # ------------------------------------------------------------------

    def _log(self, step_label: str, msg: str, *args) -> None:
        """Log with a consistent [StepX.Y] prefix."""
        logger.info(f"[{step_label}] {msg}", *args)

    # ------------------------------------------------------------------
    # Step context manager
    # ------------------------------------------------------------------

    @contextmanager
    def step(self, label: str, description: str):
        """
        Context manager that prints a step header and re-raises with context.

        Usage:
            with self.step("5.0", "Reboot + enter UEFI shell"):
                result = serial_manager.enter_uefi_shell(...)
                assert result["status"], result["msg"]
        """
        logger.info("--- Step %-5s %s ---", label, description)
        try:
            yield
        except AssertionError as exc:
            raise AssertionError(f"[Step {label}] {exc}") from exc

    # ------------------------------------------------------------------
    # SSH command helper
    # ------------------------------------------------------------------

    def ssh(
        self,
        os_manager,
        command: str,
        step_label: str,
        timeout: int = 30,
        check_output: bool = False,
    ) -> str:
        """
        Run an SSH command and assert it succeeded.

        Args:
            os_manager:    OSManager instance.
            command:       Shell command to run on the SUT.
            step_label:    Used in assertion messages, e.g. "4.0".
            timeout:       Max seconds to wait.
            check_output:  If True, also assert that stdout is non-empty.

        Returns:
            stdout string (stripped).

        Raises:
            AssertionError on non-zero exit code or empty output when
            check_output=True.
        """
        rc, out, err = os_manager.execute_command(
            command, timeout=timeout, check_returncode=False
        )
        assert rc == 0, (
            f"[Step {step_label}] Command failed (rc={rc}): {command!r}\n"
            f"  stderr: {err.strip()}"
        )
        if check_output:
            assert out.strip(), (
                f"[Step {step_label}] Command produced no output: {command!r}"
            )
        return out.strip()

    # ------------------------------------------------------------------
    # UEFI shell helper
    # ------------------------------------------------------------------

    def enter_shell(
        self,
        serial_manager,
        reboot_manager,
        os_manager,
        step_label: str = "5.0",
        boot_timeout: int = 300,
        max_attempts: int = 2,
    ) -> None:
        """
        Enter the UEFI shell and assert success.

        Uses efibootmgr (primary) with POST key-intercept as fallback.
        Raises AssertionError with a clear message on failure.
        """
        result = serial_manager.enter_uefi_shell(
            reboot_manager=reboot_manager,
            os_manager=os_manager,
            max_attempts=max_attempts,
            boot_timeout=boot_timeout,
            boot_menu_key=self._boot_key,
        )
        assert result["status"], (
            f"[Step {step_label}] Failed to enter UEFI shell: {result['msg']}"
        )
        logger.info("[Step %s] UEFI shell ready: %s", step_label, result["msg"])

    # ------------------------------------------------------------------
    # Test header / footer
    # ------------------------------------------------------------------

    def _begin(self) -> None:
        logger.info("=" * 72)
        logger.info(self.TEST_ID)
        logger.info("=" * 72)

    def _end(self, passed: bool = True) -> None:
        status = "PASSED" if passed else "FAILED"
        logger.info("=" * 72)
        logger.info("%s: %s", self.TEST_ID, status)
        logger.info("=" * 72)

    # ------------------------------------------------------------------
    # Shared output-parsing helpers
    # (used by MEInfo, VTInfo, and UEFI tool tests)
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_meinfo_field(output: str, field: str, multiword: bool = False) -> str:
        """
        Extract a field value from MEInfo (or similar tool) output.

        Finds the first line containing ``field`` and returns its value.

        Args:
            output:    Raw tool output string.
            field:     Field name to search for (case-insensitive).
            multiword: If False (default), returns only the last
                       whitespace-separated token on the line — suitable
                       for single-word values like "RPMC", "OK", "0x00".
                       If True, strips the field name from the line and
                       returns everything after it — suitable for
                       multi-word values like
                       "Unprivileged Public Debug Enabled Security Locked".

        Returns:
            Matched value string, or "" if the field is not found.
        """
        field_lower = field.lower()
        for line in output.splitlines():
            if field_lower in line.lower():
                stripped = line.strip()
                if not multiword:
                    parts = stripped.split()
                    return parts[-1] if parts else ""
                idx = stripped.lower().find(field_lower)
                if idx != -1:
                    value = stripped[idx + len(field):].strip()
                    if value:
                        return value
        return ""

    # Keyword-based remediation hints, matched against the *text* of the
    # tool's own "Error NN: <message>" line rather than the numeric code.
    # Meinfo/MEInfo error codes are not exhaustively documented and new
    # ones can appear at any time, but the message text Intel prints for a
    # given failure class (elevation, unsupported feature, etc.) is stable
    # and self-describing — so matching on it stays useful for codes we
    # have never seen before instead of requiring every code to be
    # individually enumerated.
    _MEINFO_ERROR_KEYWORD_HINTS: tuple = (
        (
            ("communicate with cse", "communicate with csme", "access denied",
             "insufficient privilege", "permission denied"),
            "This looks like a privilege/elevation problem. On Linux, run "
            "MEInfo with sudo. On Windows, re-run from an elevated "
            "(Administrator) Command Prompt / PowerShell — being a member of "
            "the Administrators group is not the same as running elevated (UAC).",
        ),
        (
            ("feature not found", "not supported", "unsupported"),
            "This looks like the requested -FEAT is not supported/enabled on "
            "this platform. Verify the ME firmware version supports it, and "
            "that the relevant BIOS/MFIT flash settings were applied and the "
            "image was rebuilt/reflashed.",
        ),
    )

    @staticmethod
    def _extract_meinfo_error(output: str) -> str:
        """
        Extract the tool-reported "Error NN: <message>" line from Meinfo /
        MEInfo output, if present. This is the authoritative error
        description straight from the tool and should always be preferred
        over inferring the cause from the process return code.

        Returns:
            The matched "Error NN: <message>" text, or "" if not found.
        """
        match = re.search(r"Error\s+(\d+)\s*:\s*(.+)", output)
        if match:
            return f"Error {match.group(1)}: {match.group(2).strip()}"
        return ""

    @classmethod
    def _meinfo_failure_reason(cls, output: str) -> str:
        """
        Build a human-readable failure reason for a failed Meinfo/MEInfo
        invocation: the tool's own "Error NN" line (authoritative) plus a
        keyword-matched remediation hint, if the message text matches a
        known failure pattern. Any error code/message not recognized still
        gets the raw tool message plus a generic pointer to check the
        artifact — nothing is silently dropped just because the exact code
        hasn't been seen before.
        """
        err_line = cls._extract_meinfo_error(output)
        if not err_line:
            return "MEInfo did not report a specific 'Error NN' line — see raw output/artifact below."
        err_lower = err_line.lower()
        for keywords, hint in cls._MEINFO_ERROR_KEYWORD_HINTS:
            if any(keyword in err_lower for keyword in keywords):
                return f"{err_line}\n  Hint: {hint}"
        return (
            f"{err_line}\n"
            "  Hint: No known remediation pattern matched this message — "
            "check the artifact/output above for details, and confirm "
            "sudo/Administrator elevation and the -FEAT name/config are correct "
            "for this platform."
        )

    @staticmethod
    def _uefi_path_to_linux(uefi_path: str, efi_mount: str) -> str:
        """
        Convert a UEFI shell path to a Linux path under the EFI mount point.

        Examples:
            ("EFI", "/boot/efi")                          -> "/boot/efi/EFI"
            ("EFI\\\\Tpm2ProvFilesCBnT", "/boot/efi")    -> "/boot/efi/Tpm2ProvFilesCBnT"
        """
        parts = uefi_path.replace("\\", "/").split("/")
        if parts and parts[0].upper() == "EFI":
            parts = parts[1:]
        suffix = "/".join(parts)
        return efi_mount.rstrip("/") + ("/" + suffix if suffix else "")

    @staticmethod
    def _is_windows_admin() -> bool:
        """
        Check whether the current Windows process is running elevated
        (Administrator).  Used by SUT-local Windows tests (Meinfo.exe,
        driver-level tools) that require elevation for CSME/hardware access.

        Being a member of the local Administrators group is NOT the same
        as running elevated — UAC still requires "Run as Administrator".

        Returns:
            True if elevated, False if not elevated or the check itself
            fails (e.g. not running on Windows).
        """
        try:
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False

    def _queue_windows_resume(self, request, python_exe: Optional[str] = None, step_label: str = "") -> None:
        """
        Windows reboot point: queue this test + every test after it, register one
        shared resume task that re-runs that queue in order, and stop the session
        once this test reports -- so later tests never start before the reboot.
        """
        remaining = self._register_windows_resume(request, python_exe, step_label)
        request.session.shouldstop = (
            f"{self.TEST_ID} is waiting for a reboot -- the remaining {remaining} "
            "queued test(s) resume in order after the next boot (no sign-in needed)."
        )

    def _register_windows_resume(self, request, python_exe: Optional[str] = None, step_label: str = "") -> int:
        """
        Write the remaining queue + register the resume task, without stopping
        the session (a manual gate that may or may not see a reboot). Returns the queue length.
        """
        prefix = f"[Step {step_label}]" if step_label else "[Resume]"
        items = request.session.items
        remaining = items[items.index(request.node):]

        # Absolute paths: Task Scheduler starts pytest in System32, not the repo.
        args = [f"--rootdir={request.config.rootpath}", "-v", "-s", "--setup-confirmed", "--yes"]
        args += [f"{item.path}::{item.nodeid.split('::', 1)[1]}" for item in remaining]
        WIN_RESUME_ARGS_PATH.parent.mkdir(parents=True, exist_ok=True)
        WIN_RESUME_ARGS_PATH.write_text("\n".join(args) + "\n", encoding="utf-8")
        logger.info("%s Resume queue written (%d test(s)): %s", prefix, len(remaining), WIN_RESUME_ARGS_PATH)
        for i, item in enumerate(remaining, 1):
            logger.info("%s   %d. %s", prefix, i, item.nodeid)

        # Pre-batch per-test tasks would fire alongside the batch task and race on the same state files.
        for legacy in ("IEC62443_PAVP_Resume", "IEC62443_TME_Resume", "IEC62443_dTPM_Resume",
                       "IEC62443_fTPM_Resume", "IEC62443_MeasuredBoot_Resume"):
            subprocess.run(["schtasks", "/delete", "/tn", legacy, "/f"], capture_output=True, timeout=15)

        python_exe = python_exe or sys.executable
        # At boot as SYSTEM, for automatic and manual reboots alike: the batch continues without anyone
        # signing in (no stored password); the FW_Status_Window logon task shows it when someone does.
        # The 30 s delay lets TPM/WMI services come up.
        result = subprocess.run(
            [
                "schtasks", "/create",
                "/tn", WIN_RESUME_TASK,
                "/tr", f'"{python_exe}" -m pytest @"{WIN_RESUME_ARGS_PATH}"',
                "/sc", "ONSTART", "/delay", "0000:30", "/ru", "SYSTEM",
                "/rl", "HIGHEST",
                "/f",
            ],
            capture_output=True, text=True, timeout=30,
        )
        if result.returncode == 0:
            logger.info("%s Task Scheduler task created: %s (runs at the next boot, no sign-in needed)",
                        prefix, WIN_RESUME_TASK)
        else:
            logger.warning("%s Task creation failed (rc=%d): %s", prefix, result.returncode, result.stderr.strip())
        return len(remaining)

    @staticmethod
    def _cancel_windows_resume() -> None:
        """Drop the resume task + queue file again (the gate finished without a reboot)."""
        subprocess.run(["schtasks", "/delete", "/tn", WIN_RESUME_TASK, "/f"], capture_output=True, timeout=15)
        WIN_RESUME_ARGS_PATH.unlink(missing_ok=True)

    @staticmethod
    def _wait_for_windows_reboot(step_label: str = "") -> None:
        """
        Block until the operator reboots the SUT (the reboot kills this process).

        Keeps the test RUNNING -- same as SUTBaseTest's manual signal gate on
        Linux -- so it is never reported as SKIPPED/finished before the reboot.
        Call after _queue_windows_resume(); Task Scheduler resumes at the next boot.
        Never returns. Mark the test @pytest.mark.timeout(0) so pytest-timeout
        doesn't kill the whole run while the operator is in BIOS.
        """
        prefix = f"[Step {step_label}]" if step_label else "[Reboot]"
        lines = [
            f"{prefix} WAITING FOR REBOOT -- test is still RUNNING (not finished, not skipped).",
            f"{prefix}   Reboot into BIOS now and complete the steps above.",
            f"{prefix}   After Windows boots, the test resumes by itself (no sign-in needed).",
        ]
        for line in lines:
            logger.info(line)
            print(line, flush=True)
        elapsed = 0
        while True:
            time.sleep(60)
            elapsed += 60
            logger.info("%s Still waiting for reboot ... (%d min elapsed)", prefix, elapsed // 60)

    # ------------------------------------------------------------------
    # Verification helpers -- a manual step is never proof on its own
    # ------------------------------------------------------------------

    def _mark_attested(self, step_label: str, what: str) -> None:
        """
        Record a step only the operator can confirm. The test still passes (the step is
        listed as confirmed by the operator); verification.strict = true fails it instead.
        """
        prefix = f"[Step {step_label}]"
        assert not self._strict_verification, (
            f"{prefix} Only the operator can confirm this: {what}\n"
            "  verification.strict is true in config/test_config.yaml, so operator-confirmed steps fail the test."
        )
        logger.info("%s Confirmed by the operator (the test cannot check this itself): %s", prefix, what)
        if self._request is not None:
            entry = ("attested", f"{prefix} {what}")
            if entry not in self._request.node.user_properties:
                self._request.node.user_properties.append(entry)

    @staticmethod
    def _boot_id() -> str:
        """Changes on every boot (Linux boot_id / Windows BootId)."""
        return bios_knob_checks.boot_id()

    @staticmethod
    def _assert_distinct_boots(boots: Dict, step_label: str) -> None:
        """Each measurement must come from its own boot -- identical PCRs from one boot prove nothing."""
        prefix = f"[Step {step_label}]"
        for key in sorted(boots, key=str):
            logger.info("%s   iteration %s: boot id %s", prefix, key, boots[key] or "<not recorded>")
        ids = list(boots.values())
        assert ids and all(ids) and len(set(ids)) == len(ids), (
            f"{prefix} The measurements were not each taken after a new boot (boot ids: {boots}).\n"
            "  Matching PCRs only mean something across real reboots -- re-run the test from the start."
        )
        logger.info("%s [OK] %d measurements, each from a different boot", prefix, len(ids))

    @staticmethod
    def _assert_rebooted(since_boot: Optional[str], step_label: str, since_what: str) -> None:
        """Fail unless the SUT booted again after ``since_boot`` (bios_knob_checks.boot_id())."""
        prefix = f"[Step {step_label}]"
        now = bios_knob_checks.boot_id()
        logger.info("%s Boot id when %s: %s -- now: %s", prefix, since_what, since_boot or "<not recorded>", now)
        assert since_boot and now != since_boot, (
            f"{prefix} The SUT has not rebooted since {since_what} -- a BIOS change cannot be active yet.\n"
            "  Reboot into BIOS Setup, make the change, Save & Exit (F4), then let the test resume."
        )
        logger.info("%s [OK] SUT rebooted since %s", prefix, since_what)

    def _check_bios_knobs(self, spec: str, log_dir: Path, step_label: str,
                          known: Optional[Dict[str, Tuple[bool, str]]] = None) -> List:
        """
        Read back the BIOS knobs deploy/bios_knobs/bios_knobs.yaml lists for ``spec``
        ('marker' or 'marker:variant'): from the OS, AMISCE (AMI BIOS), the test's own
        evidence in ``known`` ({question: (ok, actual)}), then the pre-flight attestation.
        Fails on a wrong knob; returns the knobs nothing could read (KnobResult list).
        """
        prefix = f"[Step {step_label}]"
        knob_lib = self._knob_lib()
        profile, _label = knob_lib.resolve_markers(knob_lib.DEFAULT_CONFIG, [spec])
        wanted = {**profile["knobs"], **profile["verify_knobs"]} if profile else {}
        ami, ami_reason = bios_knob_checks.detect_ami(self._amisce_override)
        results = bios_knob_checks.check_knobs(wanted, amisce=ami, attested=True, known=known)

        lines = bios_knob_checks.format_results(results)
        logger.info("%s BIOS knobs for '%s' read back (%s):", prefix, spec, "AMI BIOS" if ami else ami_reason)
        for line in lines:
            logger.info("%s %s", prefix, line)
        artifact = Path(log_dir) / f"bios_knobs_{spec.replace(':', '_')}.log"
        artifact.write_text("\n".join(lines) + "\n", encoding="utf-8", errors="replace")

        wrong = [r for r in results if r.ok is False]
        if wrong:
            paths = knob_lib.load_menu_paths()
            raise AssertionError(
                f"{prefix} {len(wrong)} BIOS knob(s) not set as this test needs:\n"
                + "\n".join(
                    f'  - "{r.question}" must be {r.expected} (now: {r.actual})\n'
                    f"      BIOS Setup: {paths.get(r.question.lower(), 'search BIOS Setup for the name')}"
                    for r in wrong
                )
                + "\n  Run the test from test_runner.py (its pre-flight sets them on an AMI BIOS, or reboots"
                "\n  into BIOS Setup for you), or set them in BIOS Setup (F2), Save & Exit (F4), and run again."
                f"\n  Artifact: {artifact}"
            )
        for r in results:
            if r.status == "CONFIRMED":
                self._mark_attested(step_label, f'"{r.question}" = {r.expected} -- {r.actual}')
        unknown = [r for r in results if r.ok is None]
        if not unknown:
            logger.info("%s [OK] BIOS knobs for '%s' confirmed", prefix, spec)
        return unknown

    def _win_bios_setup_by_hand(self, unknown: List, request, python_exe: str, step_label: str,
                                save_state: Callable[[dict], None]) -> None:
        """
        Windows, last resort for knobs nothing can read back (not AMI / no AMISCE, no
        pre-flight attestation): the operator sets them in BIOS Setup. Records the boot
        id, queues the resume and waits for the reboot -- never returns. After the boot,
        call _win_bios_setup_resumed().
        """
        paths = self._knob_lib().load_menu_paths()
        lines = ["─" * 64, f"STEP {step_label} -- set these BIOS knobs by hand (this SUT cannot read them back)", "─" * 64]
        for r in unknown:
            lines.append(f'  "{r.question}" = {r.expected}')
            lines.append(f"      F2 -> {paths.get(r.question.lower(), 'search BIOS Setup for the name')}")
        lines += [
            "",
            f"  Why by hand: {unknown[0].actual}",
            "",
            "  1) Reboot straight into BIOS Setup (Administrator PowerShell):",
            "       shutdown /r /fw /t 0        (or reboot and press F2 at POST)",
            "  2) Set the knobs above, Save & Exit (F4), and let Windows boot.",
            "  3) Nothing else to do: the test resumes after the boot, checks that the SUT really",
            "     rebooted, and counts these knobs as confirmed by you.",
            "  Tip: on an AMI BIOS with AMISCE in Tools\\ this step is automatic and objective.",
            "─" * 64,
        ]
        for line in lines:
            logger.info(line)
            print(line)
        save_state({
            "bios_setup_boot": bios_knob_checks.boot_id(),
            "bios_setup_knobs": {r.question: r.expected for r in unknown},
        })
        self._queue_windows_resume(request, python_exe, step_label=step_label)
        self._wait_for_windows_reboot(step_label=step_label)

    def _win_bios_setup_resumed(self, state: dict, spec: str, log_dir: Path, step_label: str,
                                known: Optional[Dict[str, Tuple[bool, str]]] = None) -> None:
        """After the by-hand BIOS Setup reboot: prove the reboot, re-read every knob, attest the rest."""
        self._assert_rebooted(state.get("bios_setup_boot"), step_label, "the BIOS Setup steps were shown")
        for r in self._check_bios_knobs(spec, log_dir, step_label, known=known):
            self._mark_attested(step_label, f'"{r.question}" = {r.expected} -- set by hand in BIOS Setup (reboot confirmed)')

    @staticmethod
    def _knob_lib():
        """deploy/bios_knobs/bios_knob_common.py (bios_knobs.yaml rules + BIOS Setup menu paths)."""
        knob_dir = str(_REPO_ROOT / "deploy" / "bios_knobs")
        if knob_dir not in sys.path:
            sys.path.insert(0, knob_dir)
        return importlib.import_module("bios_knob_common")
