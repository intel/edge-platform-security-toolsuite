# Copyright 2026 Intel Corporation
# SPDX-License-Identifier: Apache-2.0

"""
TEST — IEC 62443-4-2  RPMC (Replay Protected Monotonic Counter)  Windows OS  (SUT LOCAL)

Test ID:  IEC62443-4-2_Windows-TC_RPMC-FUNC-SUT
Suite:    csme

PURPOSE
-------
SUT-local variant: run pytest DIRECTLY ON the Windows SUT.
No external controller or SSH required.

Verifies RPMC CSME Anti-Replay (AR) services by running Meinfo.exe locally
on the Windows SUT.  Meinfo.exe must be manually transferred to the SUT
before running this test — this variant does NOT auto-transfer files.

The following fields are verified:
  CSME AR Services:
    - CSE AR Mode   == RPMC
    - CSE AR Status == OK
  BIOS AR Services:
    - BIOS AR Mode   == RPMC
    - BIOS AR Status == OK

AUTOMATION / MANUAL split
--------------------------
  Pre-test steps 1.x  — manual (MFIT RPMC enable + IFWI build + flash)
  Step 4.0            — automated (verify Meinfo.exe exists locally on SUT)
  Step 5.1            — automated (run Meinfo.exe -FEAT "CSME AR Services", parse)
  Step 5.2            — automated (run Meinfo.exe -FEAT "BIOS AR Services", parse)

KEY WINDOWS DIFFERENCES vs Linux RPMC SUT variant
-------------------------------------------------
  - Meinfo.exe (Windows .exe binary) instead of Linux MEInfo binary
  - No chmod +x (Windows .exe is always executable)
  - No sudo (Windows uses process-level privilege — run as Administrator)
  - subprocess uses list args [exe, arg1, arg2] (not shell=True)
  - Windows path conventions (backslashes in paths)

CONFIG
------
  config/suites/csme_config.yaml  — Meinfo.exe path (sut_meinfo_path_windows), expected AR values
  config/test_config.yaml         — global settings

PRE-TEST (manual, performed before running this script)
-------------------------------------------------------
  1.0) Open MFIT tool. Decompose image -> Bootguard 5 external release IFWI.
  1.1) Flash settings -> RPMC FW Supported      -> Yes.
  1.2) Flash settings -> RPMC Rebinding Enabled -> Yes.
  1.3) Build and flash IFWI; deploy Windows image to the SUT.
  2.0) Power ON the SUT and boot to Windows OS.
  3.0) **MANUALLY copy Meinfo.exe (Windows binary from CSME package) to the SUT.**
       Update 'sut_meinfo_path_windows' in config/suites/csme_config.yaml to
       point to the exact location of Meinfo.exe on this Windows machine.
       Example: sut_meinfo_path_windows: "C:/Users/user/tools/CSME/Win64/Meinfo.exe"

RUN (Administrator Command Prompt or PowerShell on Windows SUT)
---
  cd C:\\path\\to\\asrock_repo
  python -m pytest tests/rpmc/test_ec62443_rpmc_sut_wins_func.py \\
      -v -s --setup-confirmed --yes
"""

import logging
import subprocess
from pathlib import Path

import pytest

from tests.base_test import BaseTest
from core.prereq import pre_test_check

logger = logging.getLogger(__name__)


@pytest.mark.rpmc
@pytest.mark.manual
class TestEC62443RPMCWinsSUTFunc(BaseTest):
    """IEC 62443-4-2 RPMC functional test — Windows OS LOCAL (on SUT, no SSH)."""

    SUITE   = "csme"
    TEST_ID = "IEC62443-4-2_Windows-TC_RPMC-FUNC-SUT"

    PRE_TEST_CHECKLIST = [
        "1.0)  Open MFIT tool. Decompose image -> Bootguard 5 external release IFWI.",
        "1.1)  Flash settings -> RPMC FW Supported      -> Yes.",
        "1.2)  Flash settings -> RPMC Rebinding Enabled -> Yes.",
        "1.3)  Build and flash IFWI; deploy Windows image to the SUT.",
        "2.0)  Power ON SUT and boot to Windows OS.",
        "3.0)  Manually copy Meinfo.exe (Windows binary from CSME package) to this machine.",
        "      Update 'sut_meinfo_path_windows' in config/suites/csme_config.yaml.",
        "      Example: sut_meinfo_path_windows: \"C:/Users/user/tools/CSME/Win64/Meinfo.exe\"",
        "      Run this script from an Administrator Command Prompt / PowerShell.",
    ]

    def _run_meinfo(self, meinfo_path: Path, feat: str, timeout: int = 60) -> tuple:
        """
        Run Meinfo.exe with the specified -FEAT argument locally via subprocess.

        Uses a list of args (no shell=True) for safety.  The process is
        executed with the current user context — ensure Administrator rights
        are present if Meinfo.exe requires hardware-level CSME access.

        Args:
            meinfo_path: Path to Meinfo.exe on this Windows machine.
            feat:        Feature name string, e.g. "CSME AR Services".
            timeout:     Max seconds to wait.

        Returns:
            Tuple (returncode, stdout, stderr).
        """
        try:
            result = subprocess.run(
                [str(meinfo_path), "-FEAT", feat],
                capture_output=True,
                text=True,
                timeout=timeout,
                errors="replace",
            )
            return result.returncode, result.stdout, result.stderr
        except subprocess.TimeoutExpired as exc:
            logger.error("Meinfo.exe timeout after %ds (feat=%r)", timeout, feat)
            return 124, "", str(exc)
        except FileNotFoundError as exc:
            logger.error("Meinfo.exe not found: %s", meinfo_path)
            return 1, "", str(exc)
        except Exception as exc:
            logger.error("Meinfo.exe execution error: %s", exc)
            return 1, "", str(exc)

    def test_ec62443_rpmc_sut_wins_func(
        self,
        request,
        config,
        log_dir,
    ):
        """IEC62443-4-2_Windows-TC_RPMC-FUNC-SUT — verify RPMC AR services via local Meinfo.exe."""
        self._begin()
        cfg = self._load_config(config)

        pre_test_check(request, self.TEST_ID, self.PRE_TEST_CHECKLIST)

        # ------------------------------------------------------------------
        # Load config
        # ------------------------------------------------------------------
        meinfo_path = Path(cfg.get("sut_meinfo_path_windows", "").strip())

        exp_cse_mode    = str(cfg.get("expected_cse_ar_mode",    "RPMC")).upper()
        exp_cse_status  = str(cfg.get("expected_cse_ar_status",  "OK")).upper()
        exp_bios_mode   = str(cfg.get("expected_bios_ar_mode",   "RPMC")).upper()
        exp_bios_status = str(cfg.get("expected_bios_ar_status", "OK")).upper()

        # ------------------------------------------------------------------
        # Step 4.0 — Verify Meinfo.exe is present on this Windows machine
        # (must be manually transferred before running this test)
        # No chmod needed — Windows .exe files are always executable.
        # ------------------------------------------------------------------
        logger.info("[Step 4.0] Verifying Meinfo.exe is present on this Windows machine")
        logger.info("[Step 4.0] Expected path: %s", meinfo_path)
        logger.info("[Step 4.0] NOTE: Meinfo.exe must be manually copied to this machine.")
        logger.info("[Step 4.0]       This test does NOT transfer files automatically.")

        if str(meinfo_path) in ("", ".") or not meinfo_path.exists():
            logger.error("[Step 4.0] Meinfo.exe NOT FOUND at: %s", meinfo_path)
            logger.error("[Step 4.0] To fix: Copy Meinfo.exe (Windows binary) to this machine.")
            logger.error("[Step 4.0]   Update 'sut_meinfo_path_windows' in config/suites/csme_config.yaml")

        assert str(meinfo_path) not in ("", ".") and meinfo_path.exists(), (
            f"[Step 4.0] Meinfo.exe not found: {meinfo_path}\n"
            "Meinfo.exe must be manually copied to this Windows machine before running.\n"
            "This test does NOT transfer files automatically.\n"
            "Steps to resolve:\n"
            "  1. Copy Meinfo.exe (Windows binary from CSME package) to this machine.\n"
            "  2. Update 'sut_meinfo_path_windows' in config/suites/csme_config.yaml.\n"
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
            "       python -m pytest tests/rpmc/test_ec62443_rpmc_sut_wins_func.py -v -s "
            "--setup-confirmed --yes"
        )
        logger.info("[Step 4.1] [OK] Process is running elevated")

        # ------------------------------------------------------------------
        # Step 5.1 — Run Meinfo.exe -FEAT "CSME AR Services"
        # Note: No sudo / no chmod needed on Windows.
        #       Run as Administrator for CSME hardware-level access.
        # ------------------------------------------------------------------
        logger.info('[Step 5.2] Running: "%s" -FEAT "CSME AR Services"', meinfo_path)
        rc, csme_out, csme_err = self._run_meinfo(meinfo_path, "CSME AR Services", timeout=60)

        csme_log = log_dir / "meinfo_csme_ar_services.log"
        csme_log.write_text(csme_out + csme_err, encoding="utf-8", errors="replace")
        logger.info("[Step 5.2] Artifact: %s", csme_log)

        logger.info("[Step 5.2] Command output:")
        for line in (csme_out + csme_err).splitlines():
            logger.info("    %s", line)

        if rc != 0:
            logger.warning(
                "[Step 5.2] Meinfo.exe exited rc=%d. %s",
                rc, self._meinfo_failure_reason(csme_out + csme_err),
            )

        assert (csme_out + csme_err).strip(), (
            f"[Step 5.2] Meinfo.exe returned empty output (rc={rc}).\n"
            f'  Try (as Administrator): "{meinfo_path}" -FEAT "CSME AR Services"\n'
            f"  Ensure this script runs as Administrator.\n"
            f"  Check artifact: {csme_log}"
        )
        assert rc == 0, (
            f"[Step 5.2] Meinfo.exe CSME AR Services exited rc={rc}.\n"
            f"  {self._meinfo_failure_reason(csme_out + csme_err)}\n"
            f"  Check artifact: {csme_log}"
        )

        # ------------------------------------------------------------------
        # Step 5.2 — Run Meinfo.exe -FEAT "BIOS AR Services"
        # ------------------------------------------------------------------
        logger.info('[Step 5.3] Running: "%s" -FEAT "BIOS AR Services"', meinfo_path)
        rc, bios_out, bios_err = self._run_meinfo(meinfo_path, "BIOS AR Services", timeout=60)

        bios_log = log_dir / "meinfo_bios_ar_services.log"
        bios_log.write_text(bios_out + bios_err, encoding="utf-8", errors="replace")
        logger.info("[Step 5.3] Artifact: %s", bios_log)

        logger.info("[Step 5.3] Command output:")
        for line in (bios_out + bios_err).splitlines():
            logger.info("    %s", line)

        if rc != 0:
            logger.warning(
                "[Step 5.3] Meinfo.exe exited rc=%d. %s",
                rc, self._meinfo_failure_reason(bios_out + bios_err),
            )

        assert (bios_out + bios_err).strip(), (
            f"[Step 5.3] Meinfo.exe returned empty output (rc={rc}).\n"
            f'  Try (as Administrator): "{meinfo_path}" -FEAT "BIOS AR Services"\n'
            f"  Check artifact: {bios_log}"
        )
        assert rc == 0, (
            f"[Step 5.3] Meinfo.exe BIOS AR Services exited rc={rc}.\n"
            f"  {self._meinfo_failure_reason(bios_out + bios_err)}\n"
            f"  Check artifact: {bios_log}"
        )

        # ------------------------------------------------------------------
        # Step 5.2 — Parse and verify CSME AR fields
        # ------------------------------------------------------------------
        logger.info("[Step 5.2] Parsing CSME AR fields")
        actual_cse_mode   = self._parse_meinfo_field(csme_out, "CSE AR Mode")
        actual_cse_status = self._parse_meinfo_field(csme_out, "CSE AR Status")

        assert actual_cse_mode, (
            f"[Step 5.2] 'CSE AR Mode' not found in Meinfo.exe output.\n"
            f"  Meinfo.exe output:\n{csme_out}\n"
            f"  Check artifact: {csme_log}"
        )
        assert actual_cse_status, (
            f"[Step 5.2] 'CSE AR Status' not found in Meinfo.exe output.\n"
            f"  Meinfo.exe output:\n{csme_out}\n"
            f"  Check artifact: {csme_log}"
        )

        logger.info("[Step 5.2] CSE AR Mode   : actual=%-10s  expected=%s",
                    actual_cse_mode, exp_cse_mode)
        logger.info("[Step 5.2] CSE AR Status : actual=%-10s  expected=%s",
                    actual_cse_status, exp_cse_status)

        assert actual_cse_mode == exp_cse_mode, (
            "[Step 5.2] CSE AR Mode MISMATCH.\n"
            f"  Expected : {exp_cse_mode}\n"
            f"  Actual   : {actual_cse_mode}\n"
            f"  Check    : {csme_log}"
        )
        assert actual_cse_status == exp_cse_status, (
            "[Step 5.2] CSE AR Status MISMATCH.\n"
            f"  Expected : {exp_cse_status}\n"
            f"  Actual   : {actual_cse_status}\n"
            f"  Check    : {csme_log}"
        )
        logger.info("[Step 5.2] [OK] CSME AR Services — CSE AR Mode=RPMC, CSE AR Status=OK")

        # ------------------------------------------------------------------
        # Step 5.3 — Parse and verify BIOS AR fields
        # ------------------------------------------------------------------
        logger.info("[Step 5.3] Parsing BIOS AR fields")
        actual_bios_mode   = self._parse_meinfo_field(bios_out, "BIOS AR Mode")
        actual_bios_status = self._parse_meinfo_field(bios_out, "BIOS AR Status")

        assert actual_bios_mode, (
            f"[Step 5.3] 'BIOS AR Mode' not found in Meinfo.exe output.\n"
            f"  Meinfo.exe output:\n{bios_out}\n"
            f"  Check artifact: {bios_log}"
        )
        assert actual_bios_status, (
            f"[Step 5.3] 'BIOS AR Status' not found in Meinfo.exe output.\n"
            f"  Meinfo.exe output:\n{bios_out}\n"
            f"  Check artifact: {bios_log}"
        )

        logger.info("[Step 5.3] BIOS AR Mode   : actual=%-10s  expected=%s",
                    actual_bios_mode, exp_bios_mode)
        logger.info("[Step 5.3] BIOS AR Status : actual=%-10s  expected=%s",
                    actual_bios_status, exp_bios_status)

        assert actual_bios_mode == exp_bios_mode, (
            "[Step 5.3] BIOS AR Mode MISMATCH.\n"
            f"  Expected : {exp_bios_mode}\n"
            f"  Actual   : {actual_bios_mode}\n"
            f"  Check    : {bios_log}"
        )
        assert actual_bios_status == exp_bios_status, (
            "[Step 5.3] BIOS AR Status MISMATCH.\n"
            f"  Expected : {exp_bios_status}\n"
            f"  Actual   : {actual_bios_status}\n"
            f"  Check    : {bios_log}"
        )
        logger.info("[Step 5.3] [OK] BIOS AR Services — BIOS AR Mode=RPMC, BIOS AR Status=OK")

        logger.info(
            "[OK] IEC62443-4-2_Windows-TC_RPMC-FUNC-SUT PASSED — "
            "CSE AR Mode=RPMC, CSE AR Status=OK, BIOS AR Mode=RPMC, BIOS AR Status=OK"
        )
        self._end()
