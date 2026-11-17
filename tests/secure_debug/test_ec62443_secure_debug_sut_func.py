# Copyright 2026 Intel Corporation
# SPDX-License-Identifier: Apache-2.0

"""
TEST — IEC 62443-4-2  Secure Debug  (functional — SUT LOCAL)

Test ID:  IEC62443-4-2-TC_Secure_debug-FUNC-SUT
Suite:    csme

PURPOSE
-------
Verifies that the platform's Debug policy is correctly locked down as
reported by the CSME firmware via the MEInfo tool.

Run this test when pytest is executed directly on the SUT Linux host.
Unlike the SSH-based secure debug test, this variant does not transfer the
MEInfo binary automatically. The binary must already exist on the SUT at the
configured local path.

The following field is verified:
  Debug Information:
    - DFx Policy == "Unprivileged Public Debug Enabled Security Locked"

AUTOMATION / MANUAL split
-------------------------
  Pre-test steps 1.x — manual (flash IFWI, deploy Ubuntu, place MEInfo on SUT)
  Step 3.0           — automated (locate MEInfo locally)
  Step 4.0           — automated (chmod, run MEInfo, parse DFx Policy, compare)

CONFIG
------
  config/suites/csme_config.yaml  — expected DFx policy value, sut_meinfo_path_linux

PRE-TEST (manual, performed before running this script)
-------------------------------------------------------
  1.0) Flash the IFWI image and deploy Ubuntu custom image to the SUT.
       - IFWI: Bootguard 5 (BtG5) EXTERNAL release — RPSF_SEP5 or RPSF_SED5 variant.
       - Any version from the current BOM release is acceptable.
       - Example (PTL board):
         ECG_PTL_PR04_B0A1-XXXODCA_RPSF_SEP5_11E50692_2026ww01.1.02_BE351556_CRB.bin
  2.0) Power ON the SUT and boot to Ubuntu OS.
  3.0) Manually place the MEInfo binary on the SUT and update
       sut_meinfo_path_linux in config/suites/csme_config.yaml to that path.

RUN (on SUT directly, NOT via SSH from remote host)
---
  cd /path/to/asrock_repo
  python3 -m pytest tests/secure_debug/test_ec62443_secure_debug_sut_func.py -v -s --setup-confirmed --yes
"""

import logging
import subprocess
from pathlib import Path

import pytest

from core.prereq import pre_test_check
from tests.base_test import BaseTest

logger = logging.getLogger(__name__)


@pytest.mark.secure_debug
@pytest.mark.manual
class TestEC62443SecureDebugSUTFunc(BaseTest):
    """IEC 62443-4-2 Secure Debug functional test — LOCAL (on SUT, no SSH)."""

    SUITE = "csme"
    TEST_ID = "IEC62443-4-2-TC_Secure_debug-FUNC-SUT"

    PRE_TEST_CHECKLIST = [
        "1.0)  Flash the IFWI image to the SUT board.",
        "      - IFWI: Bootguard 5 (BtG5) EXTERNAL release — RPSF_SEP5 or RPSF_SED5 variant.",
        "      - Any version from the current BOM release is acceptable (no",
        "        specific IFWI version is pinned for this test).",
        "      - Example (PTL board):",
        "        ECG_PTL_PR04_B0A1-XXXODCA_RPSF_SEP5_11E50692_2026ww01.1.02_BE351556_CRB.bin",
        "2.0)  Deploy Ubuntu custom image to the boot device.",
        "3.0)  Power ON SUT and boot to Ubuntu OS.",
        "4.0)  Manually place MEInfo on the SUT and set sut_meinfo_path_linux in config/suites/csme_config.yaml.",
    ]

    def _run_cmd(self, cmd: list, timeout: int = 60) -> tuple:
        """Run a command (argument list, no shell) locally and return rc/stdout/stderr."""
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                errors="replace",
            )
            return result.returncode, result.stdout, result.stderr
        except subprocess.TimeoutExpired as exc:
            logger.error("Command timeout after %ds: %s", timeout, cmd)
            return 124, "", str(exc)
        except Exception as exc:
            logger.error("Command execution error: %s", exc)
            return 1, "", str(exc)

    def test_ec62443_secure_debug_sut_func(
        self,
        request,
        config,
        log_dir,
    ):
        """IEC62443-4-2-TC_Secure_debug-FUNC-SUT — verify DFx Policy locally on the SUT."""
        self._begin()
        cfg = self._load_config(config)

        pre_test_check(request, self.TEST_ID, self.PRE_TEST_CHECKLIST)

        # ------------------------------------------------------------------
        # Load config
        # ------------------------------------------------------------------
        meinfo_path = Path(
            (cfg.get("sut_meinfo_path_linux", "") or "").strip()
        )
        tool_name = meinfo_path.name if str(meinfo_path) not in ("", ".") else "MEInfo"
        expected_dfx = cfg.get(
            "expected_dfx_policy",
            "Unprivileged Public Debug Enabled Security Locked",
        )

        # ------------------------------------------------------------------
        # Step 3.0 — Verify MEInfo exists locally on the SUT
        # ------------------------------------------------------------------
        logger.info("[Step 3.0] Verifying MEInfo binary is present on SUT")
        logger.info("[Step 3.0] Expected path: %s", meinfo_path)
        logger.info("[Step 3.0] NOTE: MEInfo must be manually transferred to SUT before running test.")
        logger.info("[Step 3.0]       This test does NOT auto-transfer files.")

        if str(meinfo_path) in ("", ".") or not meinfo_path.exists():
            logger.error("[Step 3.0] MEInfo NOT FOUND at: %s", meinfo_path)
            logger.error("[Step 3.0] To fix: Manually transfer MEInfo to the SUT")
            logger.error("[Step 3.0]   Via SCP: scp /path/to/MEInfo user@<SUT_IP>:/home/user/")
            logger.error("[Step 3.0]   Via USB/Network share: Copy MEInfo to %s on SUT", meinfo_path)
            logger.error("[Step 3.0] Then update 'sut_meinfo_path_linux' in config/suites/csme_config.yaml")

        assert str(meinfo_path) not in ("", ".") and meinfo_path.exists(), (
            f"[Step 3.0] MEInfo binary not found: {meinfo_path}\n"
            f"MEInfo must be manually transferred to the SUT before running this test.\n"
            f"This test does NOT auto-transfer files.\n"
            f"To transfer:\n"
            f"  Via SCP: scp /path/to/MEInfo user@<SUT_IP>:/home/user/\n"
            f"  Or copy via USB/network share to: {meinfo_path}\n"
            f"Then update 'sut_meinfo_path_linux' in config/suites/csme_config.yaml if the path differs."
        )
        logger.info("[Step 3.0] [OK] MEInfo found at: %s", meinfo_path)

        # ------------------------------------------------------------------
        # Step 3.1 — Make MEInfo executable
        # ------------------------------------------------------------------
        logger.info("[Step 3.1] Setting executable bit on MEInfo")
        rc, _, err = self._run_cmd(["sudo", "chmod", "+x", str(meinfo_path)], timeout=15)
        assert rc == 0, f"[Step 3.1] sudo chmod +x failed: {err.strip()}"
        logger.info("[Step 3.1] [OK] MEInfo executable")

        # ------------------------------------------------------------------
        # Step 4.0 — Run MEInfo -FEAT "Debug Information"
        # ------------------------------------------------------------------
        logger.info('[Step 4.0] Running: sudo %s -FEAT "Debug Information"', tool_name)
        rc, out, err = self._run_cmd(
            ["sudo", str(meinfo_path), "-FEAT", "Debug Information"],
            timeout=60,
        )

        log_file = log_dir / "meinfo_debug_information.log"
        log_file.write_text(out + err, encoding="utf-8", errors="replace")
        logger.info("[Step 4.0] Artifact saved: %s", log_file)

        logger.info("[Step 4.0] Command output:")
        for line in (out + err).splitlines():
            logger.info("    %s", line)

        if rc != 0:
            logger.warning("[Step 4.0] MEInfo returned rc=%d. Stderr: %s", rc, err.strip())

        combined = out + err
        assert combined.strip(), (
            f"[Step 4.0] MEInfo returned empty output (rc={rc}).\n"
            f"  Try: sudo {meinfo_path} -FEAT \"Debug Information\"\n"
            f"  Check artifact: {log_file}"
        )

        # ------------------------------------------------------------------
        # Step 4.1 — Parse and verify DFx Policy
        # ------------------------------------------------------------------
        actual_dfx = self._parse_meinfo_field(out, "DFx Policy", multiword=True)

        assert actual_dfx, (
            f"[Step 4.1] 'DFx Policy' field not found in MEInfo output.\n"
            f"Check artifact: {log_file}"
        )

        logger.info("[Step 4.1] DFx Policy : actual   = %s", actual_dfx)
        logger.info("[Step 4.1] DFx Policy : expected = %s", expected_dfx)

        assert actual_dfx.lower() == expected_dfx.lower(), (
            f"[Step 4.1] DFx Policy MISMATCH.\n"
            f"  Expected : {expected_dfx}\n"
            f"  Actual   : {actual_dfx}\n"
            f"  Check    : {log_file}"
        )
        logger.info("[Step 4.1] [OK] DFx Policy confirmed: %s", actual_dfx)

        self._end()