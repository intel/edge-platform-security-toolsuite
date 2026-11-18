# Copyright 2026 Intel Corporation
# SPDX-License-Identifier: Apache-2.0

"""
TEST — IEC 62443-4-2  PAVP (Protected Audio Video Path)  Windows OS  (functional, SUT LOCAL)

Test ID:  IEC62443-4-2-TC_PAVP-FUNC-SUT
Suite:    pavp

PURPOSE
-------
Verifies that PAVP (Protected Audio Video Path) is enabled in the BIOS
Graphics Configuration on a Windows SUT, ensuring hardware-enforced content
protection is active on the platform.

The knob is read back instead of trusting that someone went into BIOS Setup
(BaseTest._check_bios_knobs, knob list in deploy/bios_knobs/bios_knobs.yaml -> pavp):
  - Windows: PlayReady hardware DRM available -> PAVP is on (Intel graphics need
    PAVP for hardware DRM) -> PASS now, no reboot. Not available while a working
    Intel graphics driver is loaded -> PAVP is off -> FAIL now (an operator "already
    set" answer cannot override this).
  - AMI BIOS + AMISCE (Tools\\SCEWIN_64.exe): read-only AMISCE export, no reboot.
  - Set by hand in the test_runner.py pre-flight: confirmed by the operator.
  - None of these: the test asks for BIOS Setup itself (below), confirmed by the operator.

PHASES
------
  Phase 0:
    - Read 'PAVP Enable' back. Readable -> PASS/FAIL now, no reboot.
    - Not readable -> print the BIOS Setup steps, save the boot id, register
      the Task Scheduler resume task and wait for the reboot.

  Phase 1 (only after the by-hand BIOS Setup; auto-resumed at the next boot):
    - Fail unless the SUT really rebooted, re-read the knobs, PASS.

Both phases are in the combined batch log (logs/batch_<time>_combined.log).

BIOS path
---------
  F2 → Intel Advanced Menu
     → System Agent (SA) Configuration
       → Graphics Configuration
         → PAVP  [Expected: Enabled]

ONE-TIME SETUP (SUT)
--------------------
  No service installation required. Task Scheduler auto-resume is managed
  automatically by the test (schtasks /create ... /sc ONSTART, as SYSTEM). Ensure the
  logged-in Windows user has Administrator rights. For an objective result on
  an AMI BIOS, stage AMISCE into Tools\\ (deploy/setup/setup_sut_windows.ps1).

PRE-TEST (manual, performed before running this script)
-------------------------------------------------------
  1.0) Flash IFWI and deploy Windows custom image to the boot device, then
       connect it to the SUT.
       - IFWI: Bootguard 5 (BtG5) EXTERNAL release — RPSF_SEP5 variant.
       - Any version from the current BOM release is acceptable.
       - Example (PTL board):
         ECG_PTL_PR04_B0A1-XXXODCA_RPSF_SEP5_11E50692_2026ww01.1.02_BE351556_CRB.bin
  2.0) Power ON and boot the SUT to Windows OS.
  3.0) Run this script from an Administrator Command Prompt / PowerShell.

RUN (on the Windows SUT — Administrator Command Prompt or PowerShell)
---
  cd C:\\path\\to\\asrock_repo
  python -m pytest tests/pavp/test_ec62443_pavp_sut_wins_func.py \\
      -v -s --setup-confirmed --yes
"""

import json
import logging
import sys
from pathlib import Path

import pytest

from tests.base_test import BaseTest
from core.prereq import pre_test_check
from core.state_dir import DEFAULT_STATE_DIR

logger = logging.getLogger(__name__)

_PHASE_KEY = "phase"


@pytest.mark.pavp
@pytest.mark.manual
@pytest.mark.timeout(0)
class TestEC62443PAVPSUTWinsFunc(BaseTest):
    """IEC 62443-4-2 PAVP functional test — Windows OS SUT-local, phase-based."""

    SUITE   = "pavp"
    TEST_ID = "IEC62443-4-2-TC_PAVP-FUNC-SUT"

    REBOOTS = (
        ("manual", "BIOS Setup: Intel Advanced Menu -> SA Configuration -> Graphics Configuration "
                   "-> PAVP = Enabled", "PAVP cannot be read back on this SUT"),
    )

    @classmethod
    def reboot_plan(cls, config: dict) -> list:
        return [] if cls._bios_knobs_readable("pavp", config) else cls._reboots_confirmed(config)

    PRE_TEST_CHECKLIST = [
        "1.0)  Flash IFWI and deploy Windows custom image to the boot device,",
        "      then connect it to the SUT.",
        "      - IFWI: Bootguard 5 (BtG5) EXTERNAL release — RPSF_SEP5 variant.",
        "      - Any version from the current BOM release is acceptable (no",
        "        specific IFWI version is pinned for this test).",
        "      - Example (PTL board):",
        "        ECG_PTL_PR04_B0A1-XXXODCA_RPSF_SEP5_11E50692_2026ww01.1.02_BE351556_CRB.bin",
        "2.0)  Power ON and boot the SUT to Windows OS.",
        "3.0)  Run this script from an Administrator Command Prompt / PowerShell.",
    ]

    # ------------------------------------------------------------------
    # State management (JSON file on local disk — survives the reboot)
    # ------------------------------------------------------------------

    def _init_state(self, state_dir: Path) -> None:
        state_dir.mkdir(parents=True, exist_ok=True)
        self._state_file = state_dir / "pavp_state.json"

    def _load_state(self) -> dict:
        if self._state_file.exists():
            try:
                return json.loads(self._state_file.read_text(encoding="utf-8"))
            except Exception as exc:
                logger.warning("State file load failed: %s — starting fresh", exc)
        return {_PHASE_KEY: 0}

    def _save_state(self, state: dict) -> None:
        self._state_file.write_text(json.dumps(state, indent=2), encoding="utf-8")

    def _cleanup_state(self) -> None:
        if self._state_file.exists():
            self._state_file.unlink(missing_ok=True)
            logger.info("[Cleanup] State file removed: %s", self._state_file)

    # ------------------------------------------------------------------
    # Test entry point
    # ------------------------------------------------------------------

    def test_ec62443_pavp_sut_wins_func(
        self,
        request,
        config,
        log_dir,
    ):
        """
        IEC62443-4-2-TC_PAVP-FUNC-SUT

        Reads 'PAVP Enable' back; only when that is impossible does it ask for
        BIOS Setup (one reboot, auto-resumed by Task Scheduler, confirmed by the operator).
        """
        self._begin()
        cfg = self._load_config(config)

        state_dir     = Path(cfg.get("win_state_dir") or DEFAULT_STATE_DIR)
        # Default to sys.executable (this process's own interpreter), not the bare
        # "python" -- Task Scheduler's ONLOGON/elevated context can resolve PATH
        # differently and find a python without pytest installed.
        python_exe    = cfg.get("win_python_path", sys.executable)

        self._init_state(state_dir)
        state = self._load_state()
        phase = state.get(_PHASE_KEY, 0)

        pre_test_check(request, self.TEST_ID, self.PRE_TEST_CHECKLIST)

        logger.info("[State] phase=%d  state_dir=%s", phase, state_dir)

        if phase == 0:
            # Step 3.0 — read PAVP back (PlayReady hardware DRM / AMISCE / pre-flight)
            unknown = self._check_bios_knobs("pavp", log_dir, step_label="3.0")
            if unknown:
                def save(extra: dict) -> None:
                    state.update(extra)
                    state[_PHASE_KEY] = 1
                    self._save_state(state)
                self._win_bios_setup_by_hand(unknown, request, python_exe, "3.0", save)
        else:
            logger.info("=" * 64)
            logger.info("Phase 1 — resumed after the BIOS Setup reboot")
            logger.info("=" * 64)
            try:
                self._win_bios_setup_resumed(state, "pavp", log_dir, step_label="3.0")
            finally:
                self._cleanup_state()

        logger.info("[Step 3.0] [OK] PAVP = Enabled (Intel Advanced Menu -> SA Configuration"
                    " -> Graphics Configuration -> PAVP)")
        self._cleanup_state()
        self._end()
