# Copyright 2026 Intel Corporation
# SPDX-License-Identifier: Apache-2.0

"""
Pre-test gate and automated prerequisite-check helpers.

Why this is NOT in conftest.py
-------------------------------
conftest.py is for pytest fixtures and hooks only.  Utility functions that
tests import directly belong in a regular Python module so they are:
  - importable without pytest
  - testable in isolation
  - clearly separated from pytest infrastructure

Usage in a test
---------------
    from core.prereq import (
        pre_test_check,
        prereq_ssh,
        prereq_os,
        prereq_secure_boot,
        prereq_tpm_location,
        prereq_pcr_bank,
    )

    class TestMyFeature:

        PRE_TEST_CHECKLIST = [
            "1.0)  Flash IFWI to the SUT board.",
            "2.0)  Deploy Ubuntu image.",
        ]

        def _prereqs(self, os_manager, security) -> list:
            return [
                ("SUT reachable via SSH",
                 lambda: preflight_ssh(os_manager)),
                ("SUT OS is Ubuntu",
                 lambda: prereq_os(os_manager, "ubuntu")),
                ("Secure Boot enabled",
                 lambda: prereq_secure_boot(os_manager)),
                ("TPM location == PTT",
                 lambda: prereq_tpm_location(security, "INTC")),
                ("Active PCR bank == SHA256",
                 lambda: prereq_pcr_bank(security, "SHA256")),
            ]

        def test_something(self, request, os_manager, security, ...):
            pre_test_check(
                request,
                "MY-TC-ID",
                self.PRE_TEST_CHECKLIST,
                prereq_checks=self._prereqs(os_manager, security),
            )
            # ... rest of test
"""

import os
import sys
import logging
import time
from pathlib import Path
import pytest

logger = logging.getLogger("BIOS_Security_Tests")


# ---------------------------------------------------------------------------
# TERMINAL I/O HELPER
# ---------------------------------------------------------------------------

def _read_from_terminal(prompt: str) -> str:
    """
    Write a prompt and read one line directly from the real terminal,
    bypassing pytest's stdin/stdout capture entirely.
    'CON' on Windows, '/dev/tty' on Linux/macOS.

    Uses raw os.open/os.read/os.write on the file descriptor instead of
    Python's buffered open(path, "r+"). Some virtual/pty terminals report as
    non-seekable, which makes open(..., "r+") raise io.UnsupportedOperation
    (a subclass of OSError) immediately — silently treated as "declined" by
    the caller even on a fully interactive terminal. Raw fd I/O has no
    seekability requirement, so it works on both real and virtual ttys.
    """
    tty_path = "CON" if os.name == "nt" else "/dev/tty"
    fd = None
    try:
        fd = os.open(tty_path, os.O_RDWR)
        os.write(fd, prompt.encode())
        chars = []
        while True:
            ch = os.read(fd, 1)
            if not ch or ch in (b"\n", b"\r"):
                break
            chars.append(ch)
        return b"".join(chars).decode(errors="replace").strip().lower()
    except OSError:
        # Truly non-interactive (piped CI run without --yes) — treat as 'N'
        return ""
    finally:
        if fd is not None:
            os.close(fd)


# ---------------------------------------------------------------------------
# MAIN PRE-TEST GATE
# ---------------------------------------------------------------------------

def pre_test_check(
    request: pytest.FixtureRequest,
    test_id: str,
    checklist: list,
    prereq_checks: list = None,
) -> None:
    """
    Pre-test gate called at the top of every test method.

    Parameters
    ----------
    request : pytest.FixtureRequest
        Built-in fixture — gives access to --setup-confirmed / --yes.
    test_id : str
        Short test identifier shown in log output.
    checklist : list[str]
        Manual / eyeball steps the operator must confirm (PRE_TEST_CHECKLIST).
        These are steps that CANNOT be automated (flash IFWI, MOK enrolment…).
    preflight_checks : list[tuple], optional
        Automated checks run BEFORE the manual checklist.
        Each entry: (description: str, fn: callable → (passed: bool, detail: str))
        SSH failure causes an early bail-out; all other failures are collected
        and reported together so the operator can fix everything in one go.

    Three behaviours depending on CLI flags
    ----------------------------------------
    1. No flags (default):
          Runs automated checks, prints manual checklist with [   ] boxes,
          then SKIPs. Tells operator what to do next.

    2. --setup-confirmed  (interactive):
          Runs automated checks, prints manual checklist, asks operator to
          type 'yes'. Prevents blindly skipping setup.

    3. --setup-confirmed --yes  (CI / re-runs):
          Runs automated checks, prints checklist with [ x ] boxes,
          proceeds immediately without a prompt.
    """
    flag_confirmed = request.config.getoption("--setup-confirmed")
    flag_yes       = request.config.getoption("--yes")
    sep = "=" * 80

    # ------------------------------------------------------------------
    # AUTOMATED PRE-FLIGHT CHECKS (always run, regardless of flags)
    # ------------------------------------------------------------------
    if prereq_checks:
        logger.info(sep)
        logger.info("AUTOMATED PRE-FLIGHT CHECKS  —  %s", test_id)
        logger.info(sep)
        failures = []
        for description, fn in prereq_checks:
            try:
                passed, detail = fn()
            except Exception as exc:
                passed, detail = False, f"Exception: {exc}"
            if passed:
                logger.info("  [PASS]  %s  —  %s", description, detail)
            else:
                logger.error("  [FAIL]  %s  —  %s", description, detail)
                failures.append(f"{description}: {detail}")
                # SSH failure = SUT unreachable; all downstream checks would
                # also fail with connection errors.  Bail out early so the
                # report shows only the real root cause.
                if "ssh" in description.lower():
                    logger.error("  (SSH failed — skipping remaining checks)")
                    break
        logger.info(sep)

        if failures:
            logger.error("PRE-FLIGHT FAILED — %d check(s) did not pass:", len(failures))
            for f in failures:
                logger.error("  ✗  %s", f)
            pytest.fail(
                f"Automated pre-flight failed for {test_id}.\n"
                + "\n".join(f"  ✗ {f}" for f in failures)
            )
        logger.info("[OK] All automated pre-flight checks passed")

    # ------------------------------------------------------------------
    # PATH 1 — no flag: print empty manual checklist and SKIP
    # ------------------------------------------------------------------
    if not flag_confirmed:
        logger.info(sep)
        logger.info("MANUAL PRE-TEST CHECKLIST  —  %s", test_id)
        logger.info(sep)
        for item in (checklist or ["(no manual checklist defined)"]):
            logger.info("  [   ]  %s", item)
        logger.info(sep)
        logger.warning("SKIPPED — manual pre-test setup not confirmed for: %s", test_id)
        logger.warning("")
        logger.warning("  Complete ALL items in the checklist above, then re-run with:")
        logger.warning("    pytest <test-path> --setup-confirmed")
        logger.warning("")
        logger.warning("  (You will be prompted to type 'yes' to confirm interactively.)")
        pytest.skip(
            f"Manual pre-test setup not confirmed for: {test_id}. "
            "Complete the checklist and re-run with --setup-confirmed."
        )

    # ------------------------------------------------------------------
    # PATH 2 — --setup-confirmed --yes: non-interactive / CI mode
    # ------------------------------------------------------------------
    if flag_yes:
        logger.info(sep)
        logger.info("MANUAL PRE-TEST CHECKLIST  —  %s  [--yes mode]", test_id)
        logger.info(sep)
        for item in (checklist or ["(no manual checklist defined)"]):
            logger.info("  [ x ]  %s", item)
        logger.info(sep)
        logger.info("[OK] Manual pre-test setup confirmed (--yes) — proceeding with %s", test_id)
        return

    # ------------------------------------------------------------------
    # PATH 3 — --setup-confirmed only: interactive confirmation
    # ------------------------------------------------------------------
    print(f"\n{sep}")
    print(f"MANUAL PRE-TEST CHECKLIST  —  {test_id}")
    print(sep)
    print("Please confirm you have completed each item below:\n")
    for item in (checklist or ["(no manual checklist defined)"]):
        print(f"  [   ]  {item}")
    print(f"\n{sep}")
    print("Type  yes  and press Enter to confirm ALL items above are done.")
    print("Anything else (or just Enter) will SKIP this test.")
    print(sep)

    answer = _read_from_terminal("\nConfirm all manual setup steps completed? [yes/N]: ")

    if answer not in ("yes", "y"):
        logger.warning(sep)
        logger.warning("SKIPPED — operator did not confirm manual pre-test setup for: %s", test_id)
        logger.warning(sep)
        pytest.skip(f"Manual pre-test setup not confirmed interactively for: {test_id}.")

    # Confirmed — log completed checklist as audit trail
    logger.info(sep)
    logger.info("MANUAL PRE-TEST CHECKLIST  —  %s", test_id)
    logger.info(sep)
    for item in (checklist or ["(no manual checklist defined)"]):
        logger.info("  [ x ]  %s", item)
    logger.info(sep)
    logger.info("[OK] Manual pre-test setup confirmed — proceeding with %s", test_id)


def wait_for_signal(
    checkpoint_id: str,
    instructions: list,
    gate_dir: str = "logs/manual_gates",
    timeout_seconds: int = 0,
    poll_interval_seconds: float = 2.0,
) -> None:
    """
    Block test execution until operator deletes a gate file.

    This helper is used for in-test manual BIOS checkpoints where automation must
    pause until an operator completes a hardware or BIOS action.

    Parameters
    ----------
    checkpoint_id : str
        Unique checkpoint identifier used as part of the gate filename.
    instructions : list[str]
        Human-readable manual steps shown in logs and written to the gate file.
    gate_dir : str
        Directory where the gate file is created.
    timeout_seconds : int
        Optional timeout. 0 means wait indefinitely.
    poll_interval_seconds : float
        Poll interval while waiting for gate-file deletion.
    """
    if not checkpoint_id:
        raise ValueError("checkpoint_id must be a non-empty string")

    gate_root = Path(gate_dir)
    gate_root.mkdir(parents=True, exist_ok=True)

    gate_file = gate_root / f"{checkpoint_id}.signal"
    sep = "=" * 80

    lines = [
        sep,
        f"MANUAL CHECKPOINT: {checkpoint_id}",
        sep,
        "Complete the steps below, then delete this file to continue:",
        "",
    ]
    lines.extend(str(item) for item in (instructions or []))
    lines.extend([
        "",
        "Delete this file after completing all steps:",
        str(gate_file.resolve()),
        sep,
        "",
    ])

    gate_file.write_text("\n".join(lines), encoding="utf-8")

    logger.info(sep)
    logger.info("MANUAL CHECKPOINT GATE  —  %s", checkpoint_id)
    logger.info(sep)
    for item in (instructions or ["(no instructions provided)"]):
        logger.info("  %s", item)
    logger.info("")
    logger.info("Gate file created: %s", gate_file)
    logger.info("Delete the gate file to continue this test.")
    if timeout_seconds > 0:
        logger.info("Timeout: %ds", timeout_seconds)
    logger.info(sep)

    start = time.time()
    while gate_file.exists():
        if timeout_seconds > 0 and (time.time() - start) >= timeout_seconds:
            pytest.fail(
                f"Manual checkpoint '{checkpoint_id}' timed out after {timeout_seconds}s. "
                f"Delete gate file to continue: {gate_file}"
            )
        time.sleep(max(0.1, poll_interval_seconds))

    logger.info("[OK] Manual checkpoint completed: %s", checkpoint_id)


# ---------------------------------------------------------------------------
# REUSABLE PRE-FLIGHT CHECK HELPERS
# Each returns (passed: bool, detail: str) for uniform reporting.
# ---------------------------------------------------------------------------

def prereq_ssh(os_manager) -> tuple:
    """Check the SUT is reachable and accepts SSH connections."""
    try:
        rc, stdout, _ = os_manager.execute_command("echo __ping__")
        if rc == 0 and "__ping__" in stdout:
            return True, f"SSH OK ({os_manager.sut_ip})"
        return False, f"SSH command returned rc={rc}"
    except Exception as exc:
        return False, f"SSH connection failed: {exc}"


def prereq_os(os_manager, expected_os: str) -> tuple:
    """
    Check the SUT OS matches expected_os (case-insensitive substring).
    Expected values: "ubuntu", "linux", "windows"
    """
    try:
        detected = os_manager.detect_sut_os()
        passed = expected_os.lower() in detected.lower()
        return passed, f"detected='{detected}', expected='{expected_os}'"
    except Exception as exc:
        return False, f"OS detection failed: {exc}"


def prereq_secure_boot(os_manager) -> tuple:
    """Check Secure Boot is enabled on the SUT (Linux, uses mokutil/efivar)."""
    try:
        rc, stdout, _ = os_manager.execute_command(
            "mokutil --sb-state 2>/dev/null"
        )
        output = stdout.strip().lower()
        if "secureboot enabled" in output:
            return True, "Secure Boot = enabled"
        if "secureboot disabled" in output:
            return False, "Secure Boot = disabled — enable it in BIOS"
        # mokutil not installed — try raw efivar read
        rc2, out2, _ = os_manager.execute_command(
            "python3 -c \""
            "import glob; "
            "f=glob.glob('/sys/firmware/efi/efivars/SecureBoot-*'); "
            "d=open(f[0],'rb').read() if f else b''; "
            "print(d[4] if len(d)>4 else 0)\""
        )
        val = out2.strip()
        if val == "1":
            return True, "Secure Boot = enabled (efivar)"
        if val == "0":
            return False, "Secure Boot = disabled (efivar) — enable it in BIOS"
        return False, f"Could not determine Secure Boot state: '{stdout.strip()}'"
    except Exception as exc:
        return False, f"Secure Boot check failed: {exc}"


def prereq_tpm_location(security, expected_manufacturer: str = "INTC") -> tuple:
    """
    Check TPM manufacturer by delegating to security.tpm.assert_ptt() /
    assert_dtpm() — the same method used in the test step.
    No logic duplication.
    """
    try:
        if expected_manufacturer.upper() == "INTC":
            security.tpm.assert_ptt()
        else:
            security.tpm.assert_dtpm()
        manu = security.tpm.manufacturer() or "unknown"
        return True, f"manufacturer='{manu}', expected='{expected_manufacturer}'"
    except AssertionError as exc:
        return False, str(exc)
    except Exception as exc:
        return False, f"TPM location check failed: {exc}"


def prereq_pcr_bank(security, expected_bank: str = "SHA256") -> tuple:
    """
    Check the active PCR bank by delegating to security.tpm.assert_pcr_bank()
    — the same method used in test Step 4.2.  No logic duplication.
    """
    try:
        security.tpm.assert_pcr_bank(expected_bank)
        active = security.tpm.active_pcr_banks()
        return True, f"active banks={active}, required='{expected_bank}'"
    except AssertionError as exc:
        return False, str(exc)
    except Exception as exc:
        return False, f"PCR bank check failed: {exc}"
