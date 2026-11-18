# Copyright 2026 Intel Corporation
# SPDX-License-Identifier: Apache-2.0

"""
TEST — IEC 62443-4-2  Virtualization / VT-d 002  (functional, SUT-only)

Test ID:  IEC62443-4-2-TC_Virtualization_Vtd_002-FUNC-SUT
Suite:    virtualization

PURPOSE
-------
Verifies the VT-d BIOS policy by confirming two conditions in the BIOS setup
menu under Intel Advanced Menu → System Agent (SA) Configuration → VT-d setup menu:

  1. VT-d is set to: Enabled
  2. The following sub-options are NOT present on the VT-d setup page:
       - IGD VTD
       - IPU VTD
       - IOP VTD
       - ITBT VTD

The presence of those sub-options would indicate per-device VT-d override
capability is exposed, which should not be the case under a locked VT-d policy.

What is checked objectively vs. on the operator's word:
  - The operator must really have been in BIOS Setup: a signal file created
    without a reboot since the step was shown is ignored.
  - VT-d = Enabled is read back from the OS (ACPI DMAR table present).
  - "Sub-options not present" is a visual check of a BIOS menu -- nothing in
    the OS can see it, so that part is confirmed by the operator.

Unlike the NUC variant (test_ec62443_virtualization_vtd_002_func.py):
  - Runs pytest directly on the SUT
  - No external NUC controller, no SSH, no os_manager
  - Uses systemd (fw-validation-resume.service) to resume after the reboot
  - Uses _wait_for_manual_signal (reboot-safe gate)

BIOS path
---------
  F2 → Intel Advanced Menu
     → System Agent (SA) Configuration
       → VT-d setup menu
         → VT-d          [Expected: Enabled]
         → IGD VTD       [Expected: NOT present]
         → IPU VTD       [Expected: NOT present]
         → IOP VTD       [Expected: NOT present]
         → ITBT VTD      [Expected: NOT present]

ONE-TIME SETUP (SUT)
--------------------
  See deploy/setup/setup_sut.sh — run once before any SUT-only test.
  fw-validation-resume.service must be installed and enabled.

PRE-TEST (manual, performed before running this script)
-------------------------------------------------------
  1.0)  Flash IFWI and deploy Windows custom image to boot device.
        - IFWI: Bootguard 5 (BtG5) EXTERNAL release — RPSF_SEP5 or RPSF_SED5 variant.
        - Any version from the current BOM release is acceptable.
        - Example (PTL board):
          ECG_PTL_PR04_B0A1-XXXODCA_RPSF_SEP5_11E50692_2026ww01.1.02_BE351556_CRB.bin
  2.0)  Power ON and boot the SUT.
  SETUP) fw-validation-resume.service installed + enabled (see deploy/).

CONFIG (virtualization_config.yaml)
-------------------------------------
  manual_gate_timeout_secs : 900

RUN (on SUT)
------------
  /home/user/Desktop/venv/bin/python3 -m pytest \\
      tests/virtualization/test_ec62443_virtualization_vtd_002_sut_func.py \\
      -v -s --setup-confirmed --yes
"""

import logging

import pytest

from tests.sut_base_test import SUTBaseTest
from core.prereq import pre_test_check

logger = logging.getLogger(__name__)

_SIGNAL_STEP3 = "step3_vtd002_verified.txt"


@pytest.mark.virtualization
@pytest.mark.manual
class TestEC62443VirtualizationVtd002SUTFunc(SUTBaseTest):
    """
    IEC 62443-4-2 Virtualization VT-d 002 — SUT-only, fully manual variant.

    Guides the operator through the BIOS VT-d setup menu check.
    Confirmed via signal file.
    """

    SUITE   = "virtualization"
    TEST_ID = "IEC62443-4-2-TC_Virtualization_Vtd_002-FUNC-SUT"

    REBOOTS = (
        ("manual", "BIOS Setup: look at Intel Advanced Menu -> SA Configuration -> VT-d setup menu "
                   "(VT-d Enabled; IGD/IPU/IOP/ITBT VTD absent), boot, create the signal file"),
    )

    PRE_TEST_CHECKLIST = [
        "1.0)  Flash IFWI and deploy Windows custom image to boot device.",
        "      - IFWI: Bootguard 5 (BtG5) EXTERNAL release — RPSF_SEP5 or RPSF_SED5 variant.",
        "      - Any version from the current BOM release is acceptable (no",
        "        specific IFWI version is pinned for this test).",
        "      - Example (PTL board):",
        "        ECG_PTL_PR04_B0A1-XXXODCA_RPSF_SEP5_11E50692_2026ww01.1.02_BE351556_CRB.bin",
        "2.0)  Power ON and boot the SUT.",
        "SETUP) fw-validation-resume.service installed + enabled (see deploy/).",
    ]

    def test_ec62443_virtualization_vtd_002_sut_func(
        self,
        request,
        config,
        log_dir,
    ):
        """
        IEC62443-4-2-TC_Virtualization_Vtd_002-FUNC-SUT

        Single-phase, fully manual execution:
          Step 3.0 : Verify VT-d = Enabled in BIOS VT-d setup menu
          Step 3.2 : Confirm IGD/IPU/IOP/ITBT VTD options are NOT present
        """
        self._begin()
        cfg = self._load_config(config)
        mgr = self._init_state_dir(cfg)

        pre_test_check(request, self.TEST_ID, self.PRE_TEST_CHECKLIST)

        expected_vtd   = cfg.get("expected_vtd_state", "Enabled")
        absent_options = cfg.get("absent_vtd_options", [
            "IGD VTD", "IPU VTD", "IOP VTD", "ITBT VTD",
        ])
        timeout = int(cfg.get("manual_gate_timeout_secs", 900))

        absent_lines = [f"       - {opt}  [Expected: NOT present]" for opt in absent_options]

        # ==================================================================
        # Step 3.0 — Manual BIOS check: VT-d Enabled + absent sub-options
        # ==================================================================
        self._wait_for_manual_signal(
            signal_file=_SIGNAL_STEP3,
            step_label="3.0",
            timeout_secs=timeout,
            requires_reboot=True,
            verify=self._knob_verifier({"VT-d": expected_vtd}),
            instructions=[
                "─" * 64,
                "STEP 3.0 — Verify VT-d in BIOS VT-d setup menu",
                "─" * 64,
                "",
                "  3.1) Reboot and press F2 during POST to enter BIOS Setup",
                "       (or: sudo systemctl reboot --firmware-setup).",
                "",
                "       Navigate to:",
                "         Intel Advanced Menu",
                "           → System Agent (SA) Configuration",
                "             → VT-d setup menu",
                "",
                f"       Confirm 'VT-d' reads: [ {expected_vtd} ]",
                "",
                "  3.2) On the same VT-d setup menu page, confirm the following",
                "       options are NOT present:",
                *absent_lines,
                "",
                "       If any of those options ARE present, the test FAILS:",
                "       write FAIL and the option name into the signal file (see below).",
                "",
                "  3.3) Exit BIOS Setup and boot back to Ubuntu, then create the signal file.",
                "─" * 64,
            ],
        )

        logger.info("[Step 3.1] [OK] VT-d = %s (read back from the OS)", expected_vtd)
        self._mark_attested(
            "3.2", "not present in the BIOS VT-d setup menu (visual check): " + ", ".join(absent_options),
        )

        # ==================================================================
        # PASS
        # ==================================================================
        mgr.cleanup()
        logger.info(
            "[OK] VT-d policy: VT-d = %s (read back); IGD/IPU/IOP/ITBT VTD absent (operator-confirmed).",
            expected_vtd,
        )
        self._end()
