# Copyright 2026 Intel Corporation
# SPDX-License-Identifier: Apache-2.0

"""
TEST — IEC 62443-4-2  RPMC (Replay Protected Monotonic Counter)  (functional — SUT LOCAL)

Test ID:  IEC62443-4-2-TC_RPMC-FUNC-SUT
Suite:    csme

PURPOSE
-------
Verifies that RPMC (Replay Protected Monotonic Counter) is correctly
provisioned in the IFWI and active at the OS level by querying the CSME
Anti-Replay (AR) services via the MEInfo tool.

RUN DIRECTLY ON SUT (no SSH) — Use this when pytest runs on the SUT itself,
not via SSH from a remote controller.

**NOTE**: MEInfo binary must be manually transferred to the SUT BEFORE running this test.
This test does NOT auto-transfer files from a remote host. The test verifies that MEInfo
exists at the configured path on the SUT filesystem and runs it directly.

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
  Step 4.0            — automated (locate MEInfo locally)
  Step 5.0            — automated (chmod, run MEInfo x2, parse + compare)

CONFIG
------
  config/suites/csme_config.yaml  — expected AR field values, sut_meinfo_path_linux

PRE-TEST (manual, performed before running this script)
-------------------------------------------------------
  1.0) Open MFIT tool on the host machine.
  1.1) Decompose image -> Select Bootguard 5 external release default IFWI.
  1.2) Flash settings -> RPMC FW Supported       -> Yes
  1.3) Flash settings -> RPMC Rebinding Enabled  -> Yes
  1.4) Build IFWI.
       - Base IFWI: Bootguard 5 (BtG5) EXTERNAL release — RPSF_SEP5 or RPSF_SED5 variant.
       - Any version from the current BOM release is acceptable.
       - Example (PTL board):
         ECG_PTL_PR04_B0A1-XXXODCA_RPSF_SEP5_11E50692_2026ww01.1.02_BE351556_CRB.bin
  2.0) Flash the IFWI build from step 1 and deploy Ubuntu custom image to SUT.
  3.0) Power ON the SUT and boot to Ubuntu OS (this will be the test runner machine).
  4.0) **MANUALLY transfer MEInfo binary to the SUT filesystem**.
       This test does NOT auto-transfer files. You must copy MEInfo to SUT before running.
       Example via SCP:
         scp /path/to/MEInfo user@<SUT_IP>:/home/user/
       Ensure MEInfo is placed at the path configured in
       sut_meinfo_path_linux (config/suites/csme_config.yaml).

RUN (on SUT directly, NOT via SSH from remote host)
---
  cd /path/to/asrock_repo
  python3 -m pytest tests/rpmc/test_ec62443_rpmc_sut_func.py -v -s --setup-confirmed --yes
"""

import logging
import subprocess
from pathlib import Path

import pytest

from tests.base_test import BaseTest
from core.prereq import pre_test_check

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Test class — runs directly on SUT with subprocess (no SSH)
# ---------------------------------------------------------------------------

@pytest.mark.rpmc
@pytest.mark.manual
class TestEC62443RPMCSUTFunc(BaseTest):
    """IEC 62443-4-2 RPMC functional test — LOCAL (on SUT, no SSH)."""

    SUITE   = "csme"
    TEST_ID = "IEC62443-4-2-TC_RPMC-FUNC-SUT"

    PRE_TEST_CHECKLIST = [
        "1.0)  Open MFIT tool. Decompose image -> Bootguard 5 external release default IFWI.",
        "1.1)  Flash settings -> RPMC FW Supported      -> Yes.",
        "1.2)  Flash settings -> RPMC Rebinding Enabled -> Yes.",
        "1.3)  Build IFWI.",
        "      - Base IFWI: Bootguard 5 (BtG5) EXTERNAL release — RPSF_SEP5 or RPSF_SED5 variant;",
        "        any version from the current BOM release is acceptable.",
        "      - Example (PTL board):",
        "        ECG_PTL_PR04_B0A1-XXXODCA_RPSF_SEP5_11E50692_2026ww01.1.02_BE351556_CRB.bin",
        "2.0)  Flash the IFWI build and deploy Ubuntu custom image to the SUT.",
        "3.0)  Power ON SUT and boot to Ubuntu OS (this is the test runner machine).",        "4.0)  **MANUAL**: Transfer MEInfo binary to the SUT.",
        "      Ensure it is placed at the path configured in sut_meinfo_path_linux",
        "      (config/suites/csme_config.yaml), e.g. /home/user/MEInfo.",    ]

    def _run_cmd(self, cmd: list, timeout: int = 60) -> tuple:
        """
        Run a command (argument list, no shell) locally via subprocess.
        
        Returns:
            (returncode, stdout, stderr)
        """
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                errors="replace",
            )
            return result.returncode, result.stdout, result.stderr
        except subprocess.TimeoutExpired as e:
            logger.error("Command timeout after %ds: %s", timeout, cmd)
            return 124, "", str(e)
        except Exception as e:
            logger.error("Command execution error: %s", e)
            return 1, "", str(e)

    def test_ec62443_rpmc_sut_func(
        self,
        request,
        config,
        log_dir,
    ):
        """IEC62443-4-2-TC_RPMC-FUNC-SUT — verify RPMC AR services via MEInfo (local)."""
        self._begin()
        cfg = self._load_config(config)

        pre_test_check(request, self.TEST_ID, self.PRE_TEST_CHECKLIST)

        # ------------------------------------------------------------------
        # Load config
        # ------------------------------------------------------------------
        meinfo_path   = Path((cfg.get("sut_meinfo_path_linux", "") or "").strip())
        tool_name     = meinfo_path.name if str(meinfo_path) not in ("", ".") else "MEInfo"

        exp_cse_mode    = str(cfg.get("expected_cse_ar_mode",    "RPMC")).upper()
        exp_cse_status  = str(cfg.get("expected_cse_ar_status",  "OK")).upper()
        exp_bios_mode   = str(cfg.get("expected_bios_ar_mode",   "RPMC")).upper()
        exp_bios_status = str(cfg.get("expected_bios_ar_status", "OK")).upper()

        # ------------------------------------------------------------------
        # Step 4.0 — Verify MEInfo exists locally (must be manually transferred)
        # ------------------------------------------------------------------
        logger.info("[Step 4.0] Verifying MEInfo binary is present on SUT")
        logger.info("[Step 4.0] Expected path: %s", meinfo_path)
        logger.info("[Step 4.0] NOTE: MEInfo must be manually transferred to SUT before running test.")
        logger.info("[Step 4.0]       This test does NOT auto-transfer files.")
        
        if str(meinfo_path) in ("", ".") or not meinfo_path.exists():
            logger.error("[Step 4.0] MEInfo NOT FOUND at: %s", meinfo_path)
            logger.error("[Step 4.0] To fix: Manually transfer MEInfo to SUT")
            logger.error("[Step 4.0]   Via SCP: scp /path/to/MEInfo user@<SUT_IP>:/home/user/")
            logger.error("[Step 4.0]   Via USB/Network share: Copy MEInfo to %s on SUT", meinfo_path)
            logger.error("[Step 4.0] Then update 'sut_meinfo_path_linux' in config/suites/csme_config.yaml if needed")
        
        assert str(meinfo_path) not in ("", ".") and meinfo_path.exists(), (
            f"[Step 4.0] MEInfo binary not found: {meinfo_path}\n"
            f"MEInfo must be manually transferred to the SUT before running this test.\n"
            f"This test does NOT auto-transfer files.\n"
            f"To transfer:\n"
            f"  Via SCP: scp /path/to/MEInfo user@<SUT_IP>:/home/user/\n"
            f"  Or copy via USB/network share to: {meinfo_path}\n"
            f"Then update 'sut_meinfo_path_linux' in config/suites/csme_config.yaml if the path differs."
        )
        logger.info("[Step 4.0] [OK] MEInfo found at: %s", meinfo_path)

        # ------------------------------------------------------------------
        # Step 4.1 — Make MEInfo executable
        # ------------------------------------------------------------------
        logger.info("[Step 4.1] Setting executable bit on MEInfo")
        rc, out, err = self._run_cmd(["sudo", "chmod", "+x", str(meinfo_path)], timeout=15)
        assert rc == 0, f"[Step 4.1] sudo chmod +x failed: {err.strip()}"
        logger.info("[Step 4.1] [OK] MEInfo executable")

        # ------------------------------------------------------------------
        # Step 5.1 — Run MEInfo -FEAT "CSME AR Services"
        # ------------------------------------------------------------------
        logger.info('[Step 5.1] Running: sudo %s -FEAT "CSME AR Services"', tool_name)
        rc, csme_out, csme_err = self._run_cmd(
            ["sudo", str(meinfo_path), "-FEAT", "CSME AR Services"],
            timeout=60,
        )
        csme_log = log_dir / "meinfo_csme_ar_services.log"
        csme_log.write_text(csme_out + csme_err, encoding="utf-8", errors="replace")
        logger.info("[Step 5.1] Artifact saved: %s", csme_log)
        
        # Log output for debugging
        logger.info("[Step 5.1] Command output:")
        for line in (csme_out + csme_err).splitlines():
            logger.info("    %s", line)
        
        if rc != 0:
            logger.warning(
                "[Step 5.1] MEInfo returned rc=%d. %s",
                rc, self._meinfo_failure_reason(csme_out + csme_err),
            )
        
        # Check if output is empty
        combined = csme_out + csme_err
        assert combined.strip(), (
            f"[Step 5.1] MEInfo returned empty output (rc={rc}).\n"
            f"  Try: sudo {meinfo_path} -FEAT \"CSME AR Services\"\n"
            f"  Check artifact: {csme_log}"
        )
        assert rc == 0, (
            f"[Step 5.1] MEInfo CSME AR Services exited rc={rc}.\n"
            f"  {self._meinfo_failure_reason(combined)}\n"
            f"  Check artifact: {csme_log}"
        )

        # ------------------------------------------------------------------
        # Step 5.2 — Run MEInfo -FEAT "BIOS AR Services"
        # ------------------------------------------------------------------
        logger.info('[Step 5.2] Running: sudo %s -FEAT "BIOS AR Services"', tool_name)
        rc, bios_out, bios_err = self._run_cmd(
            ["sudo", str(meinfo_path), "-FEAT", "BIOS AR Services"],
            timeout=60,
        )
        bios_log = log_dir / "meinfo_bios_ar_services.log"
        bios_log.write_text(bios_out + bios_err, encoding="utf-8", errors="replace")
        logger.info("[Step 5.2] Artifact saved: %s", bios_log)
        
        # Log output for debugging
        logger.info("[Step 5.2] Command output:")
        for line in (bios_out + bios_err).splitlines():
            logger.info("    %s", line)
        
        if rc != 0:
            logger.warning(
                "[Step 5.2] MEInfo returned rc=%d. %s",
                rc, self._meinfo_failure_reason(bios_out + bios_err),
            )
        
        # Check if output is empty
        combined = bios_out + bios_err
        assert combined.strip(), (
            f"[Step 5.2] MEInfo returned empty output (rc={rc}).\n"
            f"  Try: sudo {meinfo_path} -FEAT \"BIOS AR Services\"\n"
            f"  Check artifact: {bios_log}"
        )
        assert rc == 0, (
            f"[Step 5.2] MEInfo BIOS AR Services exited rc={rc}.\n"
            f"  {self._meinfo_failure_reason(combined)}\n"
            f"  Check artifact: {bios_log}"
        )

        # ------------------------------------------------------------------
        # Step 5.3 — Parse and verify CSME AR fields
        # ------------------------------------------------------------------
        actual_cse_mode   = self._parse_meinfo_field(csme_out, "CSE AR Mode")
        actual_cse_status = self._parse_meinfo_field(csme_out, "CSE AR Status")

        assert actual_cse_mode, (
            f"[Step 5.3] 'CSE AR Mode' not found in MEInfo output.\n"
            f"Expected format: 'CSE AR Mode : RPMC' or similar.\n"
            f"Check artifact: {csme_log}"
        )
        assert actual_cse_status, (
            f"[Step 5.3] 'CSE AR Status' not found in MEInfo output.\n"
            f"Expected format: 'CSE AR Status : OK' or similar.\n"
            f"Check artifact: {csme_log}"
        )

        logger.info("[Step 5.3] CSE AR Mode   : actual=%-10s  expected=%s",
                    actual_cse_mode, exp_cse_mode)
        logger.info("[Step 5.3] CSE AR Status : actual=%-10s  expected=%s",
                    actual_cse_status, exp_cse_status)

        assert actual_cse_mode == exp_cse_mode, (
            f"[Step 5.3] CSE AR Mode MISMATCH.\n"
            f"  Expected : {exp_cse_mode}\n"
            f"  Actual   : {actual_cse_mode}\n"
            f"  Check    : {csme_log}"
        )
        assert actual_cse_status == exp_cse_status, (
            f"[Step 5.3] CSE AR Status MISMATCH.\n"
            f"  Expected : {exp_cse_status}\n"
            f"  Actual   : {actual_cse_status}\n"
            f"  Check    : {csme_log}"
        )
        logger.info("[Step 5.3] [OK] CSME AR Services — CSE AR Mode=RPMC, CSE AR Status=OK")

        # ------------------------------------------------------------------
        # Step 5.4 — Parse and verify BIOS AR fields
        # ------------------------------------------------------------------
        actual_bios_mode   = self._parse_meinfo_field(bios_out, "BIOS AR Mode")
        actual_bios_status = self._parse_meinfo_field(bios_out, "BIOS AR Status")

        assert actual_bios_mode, (
            f"[Step 5.4] 'BIOS AR Mode' not found in MEInfo output.\n"
            f"Check artifact: {bios_log}"
        )
        assert actual_bios_status, (
            f"[Step 5.4] 'BIOS AR Status' not found in MEInfo output.\n"
            f"Check artifact: {bios_log}"
        )

        logger.info("[Step 5.4] BIOS AR Mode   : actual=%-10s  expected=%s",
                    actual_bios_mode, exp_bios_mode)
        logger.info("[Step 5.4] BIOS AR Status : actual=%-10s  expected=%s",
                    actual_bios_status, exp_bios_status)

        assert actual_bios_mode == exp_bios_mode, (
            f"[Step 5.4] BIOS AR Mode MISMATCH.\n"
            f"  Expected : {exp_bios_mode}\n"
            f"  Actual   : {actual_bios_mode}\n"
            f"  Check    : {bios_log}"
        )
        assert actual_bios_status == exp_bios_status, (
            f"[Step 5.4] BIOS AR Status MISMATCH.\n"
            f"  Expected : {exp_bios_status}\n"
            f"  Actual   : {actual_bios_status}\n"
            f"  Check    : {bios_log}"
        )
        logger.info("[Step 5.4] [OK] BIOS AR Services — BIOS AR Mode=RPMC, BIOS AR Status=OK")

        self._end()
