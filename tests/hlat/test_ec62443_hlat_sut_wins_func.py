# Copyright 2026 Intel Corporation
# SPDX-License-Identifier: Apache-2.0

"""
TEST — IEC 62443-4-2  HLAT (Intel Virtualization Technology Redirection Protection (VT-rp)/HLAT)  (functional — SUT LOCAL)

Test ID:  IEC62443-4-2-TC_HLAT-FUNC-SUT
Suite:    hlat

PURPOSE
-------
Verifies that HLAT (Intel Virtualization Technology Redirection Protection (VT-rp)/HLAT) is correctly enabled and functional on the SUT.

RUN DIRECTLY ON SUT (no SSH) — Use this when pytest runs on the SUT itself,
not via SSH from a remote controller.

The following fields are verified:
Able to get "Hypervisor-Enforced Paging Translation" in vbs_report.txt

AUTOMATION / MANUAL split
--------------------------
  Pre-test steps 1.x  — manual (IFWI flash + Windows OS deployment)
  Step 5.0            — automated (run systeminfo, save vbs_report.txt)
  Step 5.1            — automated (verify expected string present in report)

CONFIG
------
  config/suites/hlat_config.yaml  — expected_vbs_feature string
  config/test_config.yaml         — global SUT connection settings

PRE-TEST (manual, performed before running this script)
-------------------------------------------------------
  1.0) Flash IFWI and Deploy windows custom image to boot device and connect to SUT.
       - IFWI: Bootguard 5 (BtG5) EXTERNAL release — RPSF_SEP5 variant.
       - Any version from the current BOM release is acceptable.
       - Example (PTL board):
         ECG_PTL_PR04_B0A1-XXXODCA_RPSF_SEP5_11E50692_2026ww01.1.02_BE351556_CRB.bin
  2.0) Power ON and boot the SUT to BIOS page.
  3.0) To enable Virtualization-based security  (VBS)
  3.1) Press F2 to enter BIOS menu --> Select "Intel Advanced Menu" --> Select "System Agent (SA) Configuration" --> Select "VT-d setup menu" --> Read "VT-d" --> "Enabled"
  3.2) Continue boot SUT to Windows OS
  4.0) Enable Hypervisor-enforced code integrity (HVCI). Start > Device security > Core isolation details > Enable Memory Integrity

TEST-STEPS (content of this script)
-------------------------------------------------------
  5.0) Run systeminfo command and capture output to vbs_report.txt artifact.
  5.1) Verify that "Hypervisor-Enforced Paging Translation" is present in the report.

RUN (on SUT directly, NOT via SSH from remote host)
---
  cd /path/to/asrock_repo
  python3 -m pytest tests/hlat/test_ec62443_hlat_sut_wins_func.py -v -s --setup-confirmed --yes
"""

import logging
import subprocess

import pytest

from core.prereq import pre_test_check
from tests.base_test import BaseTest

logger = logging.getLogger(__name__)


@pytest.mark.hlat
@pytest.mark.manual
class TestEC62443HLATSUTWinsFunc(BaseTest):
    """IEC 62443-4-2 HLAT functional test — LOCAL (on Windows SUT, no SSH)."""

    SUITE = "hlat"
    TEST_ID = "IEC62443-4-2-TC_HLAT-FUNC-SUT"

    PRE_TEST_CHECKLIST = [
        "1.0)  Flash IFWI and deploy Windows custom image to boot device and connect to SUT.",
        "      - IFWI: Bootguard 5 (BtG5) EXTERNAL release — RPSF_SEP5 variant.",
        "      - Any version from the current BOM release is acceptable (no",
        "        specific IFWI version is pinned for this test).",
        "      - Example (PTL board):",
        "        ECG_PTL_PR04_B0A1-XXXODCA_RPSF_SEP5_11E50692_2026ww01.1.02_BE351556_CRB.bin",
        "2.0)  Power ON and boot the SUT to BIOS page.",
        "3.0)  To enable Virtualization-based security (VBS):",
        "3.1)  Press F2 to enter BIOS menu --> Intel Advanced Menu --> System Agent (SA) Configuration",
        "      --> VT-d setup menu --> Verify VT-d is 'Enabled'.",
        "3.2)  Save and continue boot to Windows OS.",
        "4.0)  Enable Hypervisor-enforced code integrity (HVCI):",
        "      Start > Device security > Core isolation details > Enable Memory Integrity.",
    ]

    def _run_cmd(self, cmd: str, timeout: int = 60) -> tuple:
        """Run a shell command locally via subprocess and return (rc, stdout, stderr)."""
        try:
            result = subprocess.run(
                cmd,
                shell=True,
                capture_output=True,
                timeout=timeout,
            )
            stdout = result.stdout.decode(errors="replace")
            stderr = result.stderr.decode(errors="replace")
            return result.returncode, stdout, stderr
        except subprocess.TimeoutExpired as exc:
            logger.error("Command timeout after %ds: %s", timeout, cmd)
            return 124, "", str(exc)
        except Exception as exc:
            logger.error("Command execution error: %s", exc)
            return 1, "", str(exc)

    def test_ec62443_hlat_sut_wins_func(
        self,
        request,
        config,
        log_dir,
    ):
        """IEC62443-4-2-TC_HLAT-FUNC-SUT — verify HLAT via systeminfo VBS report on Windows SUT."""
        self._begin()
        cfg = self._load_config(config)

        pre_test_check(request, self.TEST_ID, self.PRE_TEST_CHECKLIST)

        import platform

        sut_hostname = str(config.get("sut", {}).get("hostname", "")).strip()
        if sut_hostname and platform.node().lower() != sut_hostname.lower():
            pytest.skip(
                f"SUT-local test must run on SUT host '{sut_hostname}', current host is '{platform.node()}'."
            )

        # ------------------------------------------------------------------
        # Load config values
        # ------------------------------------------------------------------
        expected_feature = str(
            cfg.get("expected_vbs_feature", "Hypervisor-Enforced Paging Translation")
        ).strip()

        # ------------------------------------------------------------------
        # Step 5.0 — Run systeminfo and capture output as vbs_report.txt
        # ------------------------------------------------------------------
        logger.info("[Step 5.0] Running 'systeminfo' to generate VBS report")
        rc, out, err = self._run_cmd("systeminfo", timeout=120)

        artifact = log_dir / "vbs_report.txt"
        artifact.write_text(out + err, encoding="utf-8", errors="replace")
        logger.info("[Step 5.0] Artifact saved: %s", artifact)

        logger.info("[Step 5.0] systeminfo output:")
        for line in (out + err).splitlines():
            logger.info("    %s", line)

        if rc != 0:
            logger.warning("[Step 5.0] systeminfo exited with rc=%d. stderr: %s", rc, err.strip())

        assert (out + err).strip(), (
            f"[Step 5.0] systeminfo returned empty output (rc={rc}).\n"
            f"Check artifact: {artifact}"
        )
        assert rc == 0, (
            f"[Step 5.0] systeminfo failed (rc={rc}).\n"
            f"  stderr: {err.strip()}\n"
            f"  Check artifact: {artifact}"
        )
        logger.info("[Step 5.0] [OK] systeminfo completed successfully")

        # ------------------------------------------------------------------
        # Step 5.1 — Verify "Hypervisor-Enforced Paging Translation" is present
        # ------------------------------------------------------------------
        logger.info(
            "[Step 5.1] Verifying expected VBS feature string is present in report: '%s'",
            expected_feature,
        )

        report_text = out + err
        feature_found = expected_feature.lower() in report_text.lower()

        logger.info("[Step 5.1] Expected feature   : '%s'", expected_feature)
        logger.info("[Step 5.1] Feature found       : %s", feature_found)

        assert feature_found, (
            f"[Step 5.1] Expected VBS feature NOT found in systeminfo output.\n"
            f"  Expected : '{expected_feature}'\n"
            f"  HLAT / VT-rp may not be enabled or HVCI (Memory Integrity) may be disabled.\n"
            f"  Verify:\n"
            f"    - VT-d is Enabled in BIOS\n"
            f"    - Memory Integrity (HVCI) is ON in Windows Security settings\n"
            f"  Check full report: {artifact}"
        )
        logger.info("[Step 5.1] [OK] Feature '%s' confirmed in VBS report", expected_feature)

        self._end()
