# Copyright 2026 Intel Corporation
# SPDX-License-Identifier: Apache-2.0

"""
TEST — IEC 62443-4-2  CSME UPID (Unique Platform ID)  (functional — SUT LOCAL)

Test ID:  IEC62443-4-2-TC_CSME_UPID-FUNC-SUT
Suite:    csme

PURPOSE
-------
Verifies that the CSME (Converged Security and Manageability Engine) UPID
(Unique Platform ID) values programmed in the IFWI FPF (Field Programmable
Fuses) match the expected values retrieved from the MFIT tool during
pre-test setup.

Run this test when pytest is executed directly on the SUT Linux host.
Unlike the SSH-based CSME UPID test, this variant does not transfer MEInfo
automatically. The MEInfo binary must already exist on the SUT at the
configured local path.

The following FPF fields are verified:
  - UPID OEM ID [FPF]
  - UPID Refurbish Counter [FPF]

AUTOMATION / MANUAL split
--------------------------
  Pre-test steps 1.x — manual (MFIT, flash, deploy, place MEInfo on SUT)
  Step 4.0           — automated (locate MEInfo locally)
  Step 5.0           — automated (chmod +x)
  Step 6.0           — automated (run MEInfo, parse + compare)

CONFIG
------
  config/suites/csme_config.yaml  — expected UPID values, sut_meinfo_path_linux
  config/test_config.yaml         — global settings

PRE-TEST (manual, performed before running this script)
-------------------------------------------------------
  1.0) Open MFIT tool on the host machine.
  1.1) Decompose image -> Select Bootguard 5 internal release default IFWI.
  1.2) Go to Intel(R) Unique Platform ID -> note values of:
         UPID OEM ID [FPF]
         UPID Refurbish Counter [FPF]
       Write these values into config/suites/csme_config.yaml as
       expected_upid_oem_id and expected_upid_refurbish_counter.
  2.0) Flash IFWI and deploy Ubuntu custom image to the SUT.
       - IFWI: Bootguard 5 (BtG5) EXTERNAL release — RPSF_SEP5 or RPSF_SED5 variant.
       - Any version from the current BOM release is acceptable.
       - Example (PTL board):
         ECG_PTL_PR04_B0A1-XXXODCA_RPSF_SEP5_11E50692_2026ww01.1.02_BE351556_CRB.bin
  3.0) Power ON the SUT and boot to Ubuntu OS.
  4.0) Manually place MEInfo on the SUT and set
       sut_meinfo_path_linux in config/suites/csme_config.yaml.

RUN (on SUT directly, NOT via SSH from remote host)
---
  cd /path/to/asrock_repo
  python3 -m pytest tests/csme/test_ec62443_csme_upid_sut_func.py -v -s --setup-confirmed --yes
"""

import logging
import subprocess
from pathlib import Path

import pytest

from core.prereq import pre_test_check
from tests.base_test import BaseTest

logger = logging.getLogger(__name__)


@pytest.mark.csme
@pytest.mark.manual
class TestEC62443CSMEUPIDSUTFunc(BaseTest):
    """IEC 62443-4-2 CSME UPID functional test — LOCAL (on SUT, no SSH)."""

    SUITE = "csme"
    TEST_ID = "IEC62443-4-2-TC_CSME_UPID-FUNC-SUT"

    PRE_TEST_CHECKLIST = [
        "1.0)  Open MFIT tool. Decompose image -> Bootguard 5 internal release default IFWI.",
        "1.1)  Go to Intel(R) Unique Platform ID -> note UPID OEM ID [FPF] value.",
        "1.2)  Note UPID Refurbish Counter [FPF] value.",
        "      -> Set both in config/suites/csme_config.yaml before running.",
        "2.0)  Flash IFWI and deploy Ubuntu custom image to the SUT.",
        "      - IFWI: Bootguard 5 (BtG5) EXTERNAL release — RPSF_SEP5 or RPSF_SED5 variant.",
        "      - Any version from the current BOM release is acceptable (no",
        "        specific IFWI version is pinned for this test).",
        "      - Example (PTL board):",
        "        ECG_PTL_PR04_B0A1-XXXODCA_RPSF_SEP5_11E50692_2026ww01.1.02_BE351556_CRB.bin",
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

    def test_ec62443_csme_upid_sut_func(
        self,
        request,
        config,
        log_dir,
    ):
        """IEC62443-4-2-TC_CSME_UPID-FUNC-SUT — verify CSME UPID FPF values via local MEInfo."""
        self._begin()
        cfg = self._load_config(config)

        pre_test_check(request, self.TEST_ID, self.PRE_TEST_CHECKLIST)

        # ------------------------------------------------------------------
        # Load config values
        # ------------------------------------------------------------------
        meinfo_path = Path((cfg.get("sut_meinfo_path_linux", "") or "").strip())
        tool_name = meinfo_path.name if str(meinfo_path) not in ("", ".") else "MEInfo"

        expected_oem_id = str(cfg.get("expected_upid_oem_id", "0x00")).lower()
        expected_refurbish = str(cfg.get("expected_upid_refurbish_counter", "0x00")).lower()

        # ------------------------------------------------------------------
        # Step 4.0 — Verify MEInfo exists locally (must be manually transferred)
        # ------------------------------------------------------------------
        logger.info("[Step 4.0] Verifying MEInfo binary is present on SUT")
        logger.info("[Step 4.0] Expected path: %s", meinfo_path)
        logger.info("[Step 4.0] NOTE: MEInfo must be manually transferred to SUT before running test.")
        logger.info("[Step 4.0]       This test does NOT auto-transfer files.")

        if str(meinfo_path) in ("", ".") or not meinfo_path.exists():
            logger.error("[Step 4.0] MEInfo NOT FOUND at: %s", meinfo_path)
            logger.error("[Step 4.0] To fix: Manually transfer MEInfo to the SUT")
            logger.error("[Step 4.0]   Via SCP: scp /path/to/MEInfo user@<SUT_IP>:/home/user/")
            logger.error("[Step 4.0]   Via USB/Network share: Copy MEInfo to %s on SUT", meinfo_path)
            logger.error("[Step 4.0] Then update 'sut_meinfo_path_linux' in config/suites/csme_config.yaml")

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
        # Step 5.0 — chmod +x MEInfo
        # ------------------------------------------------------------------
        logger.info("[Step 5.0] sudo chmod +x %s", meinfo_path)
        rc, _, err = self._run_cmd(["sudo", "chmod", "+x", str(meinfo_path)], timeout=15)
        assert rc == 0, f"[Step 5.0] sudo chmod +x failed: {err.strip()}"
        logger.info("[Step 5.0] [OK] File permission updated")

        # ------------------------------------------------------------------
        # Step 6.0 — Run MEInfo -FEAT "FW Supported FPFs"
        # ------------------------------------------------------------------
        logger.info('[Step 6.0] Running: sudo %s -FEAT "FW Supported FPFs"', tool_name)
        rc, out, err = self._run_cmd(
            ["sudo", str(meinfo_path), "-FEAT", "FW Supported FPFs"],
            timeout=60,
        )

        log_file = log_dir / "meinfo_fpf_output.log"
        log_file.write_text(out + err, encoding="utf-8", errors="replace")
        logger.info("[Step 6.0] Artifact saved: %s", log_file)

        logger.info("[Step 6.0] Command output:")
        for line in (out + err).splitlines():
            logger.info("    %s", line)

        if rc != 0:
            logger.warning(
                "[Step 6.0] MEInfo exited with rc=%d. %s",
                rc, self._meinfo_failure_reason(out + err),
            )

        combined = out + err
        assert combined.strip(), (
            f"[Step 6.0] MEInfo returned empty output (rc={rc}).\n"
            f"  Try: sudo {meinfo_path} -FEAT \"FW Supported FPFs\"\n"
            f"  Check artifact: {log_file}"
        )

        assert rc == 0, (
            f"[Step 6.0] MEInfo exited with rc={rc}.\n"
            f"  {self._meinfo_failure_reason(combined)}\n"
            f"  Check artifact: {log_file}"
        )

        # ------------------------------------------------------------------
        # Step 6.0 — Parse and compare UPID values
        # ------------------------------------------------------------------
        actual_oem_id = self._parse_meinfo_field(out, "UPID OEM ID [FPF]")
        actual_refurbish = self._parse_meinfo_field(out, "UPID Refurbish Counter [FPF]")

        assert actual_oem_id, (
            "[Step 6.0] 'UPID OEM ID [FPF]' not found in MEInfo output.\n"
            f"Check artifact: {log_file}"
        )
        assert actual_refurbish, (
            "[Step 6.0] 'UPID Refurbish Counter [FPF]' not found in MEInfo output.\n"
            f"Check artifact: {log_file}"
        )

        logger.info(
            "[Step 6.0] UPID OEM ID [FPF]            : actual=%s  expected=%s",
            actual_oem_id,
            expected_oem_id,
        )
        logger.info(
            "[Step 6.0] UPID Refurbish Counter [FPF] : actual=%s  expected=%s",
            actual_refurbish,
            expected_refurbish,
        )

        assert actual_oem_id == expected_oem_id, (
            "[Step 6.0] UPID OEM ID [FPF] MISMATCH.\n"
            f"  Expected (MFIT) : {expected_oem_id}\n"
            f"  Actual (MEInfo) : {actual_oem_id}\n"
            f"  Check artifact  : {log_file}"
        )
        assert actual_refurbish == expected_refurbish, (
            "[Step 6.0] UPID Refurbish Counter [FPF] MISMATCH.\n"
            f"  Expected (MFIT) : {expected_refurbish}\n"
            f"  Actual (MEInfo) : {actual_refurbish}\n"
            f"  Check artifact  : {log_file}"
        )

        logger.info("[Step 6.0] [OK] UPID OEM ID and Refurbish Counter match MFIT values")
        self._end()