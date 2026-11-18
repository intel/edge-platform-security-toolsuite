# Copyright 2026 Intel Corporation
# SPDX-License-Identifier: Apache-2.0

"""
TEST — IEC 62443-4-2  CSME UPID (Unique Platform ID)  Windows OS  (functional — SUT LOCAL)

Test ID:  IEC62443-4-2_Windows-TC_CSME_UPID-FUNC-SUT
Suite:    csme

PURPOSE
-------
Verifies that the CSME (Converged Security and Manageability Engine) UPID
(Unique Platform ID) values programmed in the IFWI FPF (Field Programmable
Fuses) match the expected values retrieved from the MFIT tool during
pre-test setup.

Run this test when pytest is executed DIRECTLY on the Windows SUT machine.
Unlike the SSH-based variant, Meinfo.exe must already be present on the SUT
at the configured local path.  No file transfer is performed automatically.

The following FPF fields are verified:
  - UPID OEM ID [FPF]
  - UPID Refurbish Counter [FPF]

AUTOMATION / MANUAL split
--------------------------
  Pre-test steps 1.x–4.0  — manual (MFIT, flash IFWI, deploy Windows, place tool)
  Step 4.0                 — automated (verify Meinfo.exe is present locally)
  Step 5.0                 — automated (run Meinfo.exe, parse output + compare)

CONFIG
------
  config/suites/csme_config.yaml  — expected UPID values, sut_meinfo_path_windows
  config/test_config.yaml         — global settings

PRE-TEST (manual, performed before running this script)
-------------------------------------------------------
  1.0) Open MFIT tool on the host machine.
  1.1) Decompose image -> Select Bootguard 5 EXTERNAL release default IFWI.
  1.2) Go to Intel(R) Unique Platform ID -> note values of:
         UPID OEM ID [FPF]
         UPID Refurbish Counter [FPF]
       Write these values into config/suites/csme_config.yaml as
       expected_upid_oem_id and expected_upid_refurbish_counter.
  2.0) Flash IFWI and deploy Windows image to the SUT.
       - IFWI: Bootguard 5 (BtG5) EXTERNAL release — RPSF_SEP5 variant.
       - Any version from the current BOM release is acceptable.
       - Example (PTL board):
         ECG_PTL_PR04_B0A1-XXXODCA_RPSF_SEP5_11E50692_2026ww01.1.02_BE351556_CRB.bin
  3.0) Power ON the SUT and boot to Windows OS.
  4.0) Manually copy Meinfo.exe (Windows binary from CSME package) to the SUT.
       Update 'sut_meinfo_path_windows' in config/suites/csme_config.yaml to
       point to the exact location of Meinfo.exe on this Windows machine.

KEY WINDOWS DIFFERENCES vs Linux SUT variant
---------------------------------------------
  - Uses Meinfo.exe (Windows .exe binary) instead of Linux MEInfo binary
  - No chmod step required (Windows does not use Linux file permissions)
  - No sudo required — run Command Prompt or PowerShell as Administrator
  - Uses subprocess with a list of args (more secure than shell=True)
  - Path: Windows-style  (e.g. C:\\tools\\Meinfo.exe)

RUN (on the Windows SUT directly — NOT via SSH from a remote controller)
---
  cd C:\\path\\to\\asrock_repo
  python -m pytest tests/csme/test_ec62443_csme_upid_sut_wins_func.py -v -s --setup-confirmed --yes
  (Run Command Prompt or PowerShell as Administrator for driver-level access)
"""

import logging
import subprocess
from pathlib import Path

import pytest

from tests.base_test import BaseTest
from core.prereq import pre_test_check

logger = logging.getLogger(__name__)


@pytest.mark.csme
@pytest.mark.manual
class TestEC62443CSMEUPIDWinsSUTFunc(BaseTest):
    """IEC 62443-4-2 CSME UPID functional test — Windows OS LOCAL (on SUT, no SSH)."""

    SUITE   = "csme"
    TEST_ID = "IEC62443-4-2_Windows-TC_CSME_UPID-FUNC-SUT"

    PRE_TEST_CHECKLIST = [
        "1.0)  Open MFIT tool. Decompose image -> Bootguard 5 EXTERNAL release default IFWI.",
        "1.1)  Go to Intel(R) Unique Platform ID -> note UPID OEM ID [FPF] value.",
        "1.2)  Note UPID Refurbish Counter [FPF] value.",
        "      -> Set both in config/suites/csme_config.yaml before running.",
        "2.0)  Flash IFWI and deploy Windows image to the SUT.",
        "      - IFWI: Bootguard 5 (BtG5) EXTERNAL release — RPSF_SEP5 variant.",
        "3.0)  Power ON SUT and boot to Windows OS.",
        "4.0)  Manually copy Meinfo.exe (Windows binary from CSME package) to this machine.",
        "      Update 'sut_meinfo_path_windows' in config/suites/csme_config.yaml.",
        "      Run this script from an Administrator Command Prompt / PowerShell.",
    ]

    def _run_cmd_windows(self, args: list, timeout: int = 60) -> tuple:
        """
        Run a Windows executable via subprocess (no shell, no sudo).

        Uses a list of arguments rather than a shell string for safety.
        The process is executed with the current user context — ensure the
        caller has administrator privileges if MEInfo requires them.

        Args:
            args:    [executable_path, arg1, arg2, ...]
            timeout: Maximum seconds to wait.

        Returns:
            Tuple of (returncode, stdout, stderr).
        """
        try:
            result = subprocess.run(
                args,
                capture_output=True,
                text=True,
                timeout=timeout,
                errors="replace",
            )
            return result.returncode, result.stdout, result.stderr
        except subprocess.TimeoutExpired as exc:
            logger.error("Command timeout after %ds: %s", timeout, args)
            return 124, "", str(exc)
        except FileNotFoundError as exc:
            logger.error("Executable not found: %s", args[0] if args else "")
            return 1, "", str(exc)
        except Exception as exc:
            logger.error("Command execution error: %s", exc)
            return 1, "", str(exc)

    def test_ec62443_csme_upid_sut_wins_func(
        self,
        request,
        config,
        log_dir,
    ):
        """IEC62443-4-2_Windows-TC_CSME_UPID-FUNC-SUT — verify CSME UPID FPF values via local Meinfo.exe."""
        self._begin()
        cfg = self._load_config(config)

        pre_test_check(request, self.TEST_ID, self.PRE_TEST_CHECKLIST)

        # ------------------------------------------------------------------
        # Load config values
        # ------------------------------------------------------------------
        meinfo_path = Path(cfg.get("sut_meinfo_path_windows", "").strip())

        expected_oem_id    = str(cfg.get("expected_upid_oem_id",            "0x00")).lower()
        expected_refurbish = str(cfg.get("expected_upid_refurbish_counter",  "0x00")).lower()

        # ------------------------------------------------------------------
        # Step 4.0 — Verify Meinfo.exe exists on the Windows SUT
        # (Meinfo.exe must be manually placed before running this test)
        # No chmod needed — Windows .exe files are always executable.
        # ------------------------------------------------------------------
        logger.info("[Step 4.0] Verifying Meinfo.exe is present on this Windows machine")
        logger.info("[Step 4.0] Expected path: %s", meinfo_path)
        logger.info("[Step 4.0] NOTE: Meinfo.exe must be manually copied to this SUT before running.")
        logger.info("[Step 4.0]       This test does NOT transfer files automatically.")

        if str(meinfo_path) in ("", ".") or not meinfo_path.exists():
            logger.error("[Step 4.0] Meinfo.exe NOT FOUND at: %s", meinfo_path)
            logger.error("[Step 4.0] To fix: Copy Meinfo.exe (Windows binary) to this machine and")
            logger.error("[Step 4.0]   update 'sut_meinfo_path_windows' in config/suites/csme_config.yaml")

        assert str(meinfo_path) not in ("", ".") and meinfo_path.exists(), (
            f"[Step 4.0] Meinfo.exe not found: {meinfo_path}\n"
            "Meinfo.exe must be manually copied to this Windows machine before running this test.\n"
            "This test does NOT transfer files automatically.\n"
            "Steps to resolve:\n"
            "  1. Copy Meinfo.exe (Windows binary from CSME package) to this machine.\n"
            f"  2. Update 'sut_meinfo_path_windows' in config/suites/csme_config.yaml.\n"
            f"     Example: sut_meinfo_path_windows: \"C:/tools/CSME/Win64/Meinfo.exe\""
        )
        logger.info("[Step 4.0] [OK] Meinfo.exe found at: %s", meinfo_path)

        # ------------------------------------------------------------------
        # Step 4.1 — Verify this process is running elevated (Administrator).
        # Meinfo.exe needs elevation to talk to CSME even when the logged-in
        # user is a member of the Administrators group — UAC still requires
        # "Run as Administrator" on the Command Prompt / PowerShell session.
        # ------------------------------------------------------------------
        logger.info("[Step 4.1] Verifying this process is running elevated (Administrator)")
        is_admin = self._is_windows_admin()
        logger.info("[Step 4.1] Elevated (IsUserAnAdmin): %s", is_admin)

        assert is_admin, (
            "[Step 4.1] This process is NOT running elevated.\n"
            "  Meinfo.exe requires Administrator elevation to communicate with CSME.\n"
            "  Fix: close this terminal, then open Command Prompt / PowerShell via\n"
            "       'Run as administrator' and re-run:\n"
            "       python -m pytest tests/csme/test_ec62443_csme_upid_sut_wins_func.py -v -s "
            "--setup-confirmed --yes"
        )
        logger.info("[Step 4.1] [OK] Process is running elevated")

        # ------------------------------------------------------------------
        # Step 5.0 — Run Meinfo.exe -FEAT "FW Supported FPFs" locally
        # Note: No sudo or chmod required on Windows.
        #       Run as Administrator for hardware-level CSME access.
        # ------------------------------------------------------------------
        logger.info('[Step 5.0] Running: "%s" -FEAT "FW Supported FPFs"', meinfo_path)
        rc, out, err = self._run_cmd_windows(
            [str(meinfo_path), "-FEAT", "FW Supported FPFs"],
            timeout=60,
        )

        # Save full output as artifact
        log_file = log_dir / "meinfo_fpf_output.log"
        log_file.write_text(out + err, encoding="utf-8", errors="replace")
        logger.info("[Step 5.0] Artifact saved: %s", log_file)

        logger.info("[Step 5.0] Command output:")
        for line in (out + err).splitlines():
            logger.info("    %s", line)

        if rc != 0:
            logger.warning(
                "[Step 5.0] Meinfo.exe exited with rc=%d. %s",
                rc, self._meinfo_failure_reason(out + err),
            )

        combined = out + err
        assert combined.strip(), (
            f"[Step 5.0] Meinfo.exe returned empty output (rc={rc}).\n"
            f'  Try (as Administrator): "{meinfo_path}" -FEAT "FW Supported FPFs"\n'
            f"  Ensure you are running as Administrator.\n"
            f"  Check artifact: {log_file}"
        )

        assert rc == 0, (
            f"[Step 5.0] Meinfo.exe exited with rc={rc}.\n"
            f"  {self._meinfo_failure_reason(combined)}\n"
            f"  Check artifact: {log_file}"
        )

        # ------------------------------------------------------------------
        # Step 5.0 — Parse and compare UPID values
        # ------------------------------------------------------------------
        actual_oem_id    = self._parse_meinfo_field(out, "UPID OEM ID [FPF]")
        actual_refurbish = self._parse_meinfo_field(out, "UPID Refurbish Counter [FPF]")

        assert actual_oem_id, (
            "[Step 5.0] 'UPID OEM ID [FPF]' not found in Meinfo.exe output.\n"
            f"Check artifact: {log_file}"
        )
        assert actual_refurbish, (
            "[Step 5.0] 'UPID Refurbish Counter [FPF]' not found in Meinfo.exe output.\n"
            f"Check artifact: {log_file}"
        )

        logger.info(
            "[Step 5.0] UPID OEM ID [FPF]            : actual=%s  expected=%s",
            actual_oem_id, expected_oem_id,
        )
        logger.info(
            "[Step 5.0] UPID Refurbish Counter [FPF] : actual=%s  expected=%s",
            actual_refurbish, expected_refurbish,
        )

        assert actual_oem_id == expected_oem_id, (
            "[Step 5.0] UPID OEM ID [FPF] MISMATCH.\n"
            f"  Expected (MFIT)    : {expected_oem_id}\n"
            f"  Actual (Meinfo.exe): {actual_oem_id}\n"
            f"  Check artifact     : {log_file}"
        )
        assert actual_refurbish == expected_refurbish, (
            "[Step 5.0] UPID Refurbish Counter [FPF] MISMATCH.\n"
            f"  Expected (MFIT)    : {expected_refurbish}\n"
            f"  Actual (Meinfo.exe): {actual_refurbish}\n"
            f"  Check artifact     : {log_file}"
        )

        logger.info("[Step 5.0] [OK] UPID OEM ID and Refurbish Counter match MFIT values")
        self._end()
