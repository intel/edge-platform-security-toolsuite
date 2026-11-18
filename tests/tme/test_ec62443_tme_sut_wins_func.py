# Copyright 2026 Intel Corporation
# SPDX-License-Identifier: Apache-2.0

"""
TEST — IEC 62443-4-2  TME (Total Memory Encryption)  Windows OS  (functional, SUT LOCAL)

Test ID:  IEC62443-4-2_Windows-TC_TME-FUNC-SUT
Suite:    tme

PURPOSE
-------
Verifies that Intel Total Memory Encryption (TME) is enabled in BIOS and
that VT-d is enabled, on a Windows SUT.

The knobs are read back instead of trusting that someone went into BIOS Setup
(BaseTest._check_bios_knobs, knob list in deploy/bios_knobs/bios_knobs.yaml -> tme):
  - VT-d : ACPI DMAR table present (always readable on Windows).
  - TME  : MSR 0x982 bit 1 via bios_scripts/tme_check.py when its MSR tool is
           available, else a read-only AMISCE export (AMI BIOS), else the
           test_runner.py pre-flight (confirmed by the operator).
  Only when none of these can read TME does the test ask for BIOS Setup itself
  (one reboot, auto-resumed, reboot proven, confirmed by the operator).

PHASES
------
  Phase 0:
    - bios_scripts/tme_check.py: TME Baseline Support (CPUID ECX[13]) must be
      SUPPORTED -- otherwise this is non-vPro silicon and the test fails.
    - Read VT-d + TME back. All readable -> PASS/FAIL now, no reboot.
    - Not readable -> print the BIOS Setup steps, save the boot id, register
      the Task Scheduler resume task and wait for the reboot.

  Phase 1 (only after the by-hand BIOS Setup; auto-resumed at the next boot):
    - Fail unless the SUT really rebooted, re-read the knobs, PASS.

Both phases are in the combined batch log (logs/batch_<time>_combined.log).

BIOS path
---------
  TME:
    F2 → Intel Advanced Menu
       → CPU Configuration
         → Total Memory Encryption  [Expected: Enabled]

  VT-d (read-only, do not change):
    F2 → Intel Advanced Menu
       → System Agent (SA) Configuration
         → VT-d Setup Menu
           → VT-d  [Expected: Enabled]

ONE-TIME SETUP (SUT)
--------------------
  No service installation required. Task Scheduler auto-resume is managed
  automatically by the test (schtasks /create ... /sc ONSTART, as SYSTEM). Ensure the
  logged-in Windows user has Administrator rights.

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
  python -m pytest tests/tme/test_ec62443_tme_sut_wins_func.py \\
      -v -s --setup-confirmed --yes
"""

import json
import logging
import re
import subprocess
import sys
from pathlib import Path

import pytest

from tests.base_test import BaseTest
from core.prereq import pre_test_check
from core.state_dir import DEFAULT_STATE_DIR

logger = logging.getLogger(__name__)

_PHASE_KEY = "phase"


@pytest.mark.tme
@pytest.mark.manual
@pytest.mark.timeout(0)
class TestEC62443TMESUTWinsFunc(BaseTest):
    """IEC 62443-4-2 TME functional test — Windows OS SUT-local, phase-based."""

    SUITE   = "tme"
    TEST_ID = "IEC62443-4-2_Windows-TC_TME-FUNC-SUT"

    REBOOTS = (
        ("manual", "BIOS Setup: Intel Advanced Menu -> CPU Configuration -> Total Memory Encryption "
                   "= Enabled (VT-d must be Enabled)", "TME cannot be read back on this SUT"),
    )

    @classmethod
    def reboot_plan(cls, config: dict) -> list:
        return [] if cls._bios_knobs_readable("tme", config) else cls._reboots_confirmed(config)

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
        self._state_file = state_dir / "tme_state.json"

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

    def test_ec62443_tme_sut_wins_func(
        self,
        request,
        config,
        log_dir,
    ):
        """
        IEC62443-4-2_Windows-TC_TME-FUNC-SUT

        TME capability check, then VT-d + TME read back; only when TME cannot be
        read does it ask for BIOS Setup (one reboot, auto-resumed, confirmed by the operator).
        """
        self._begin()
        cfg = self._load_config(config)

        state_dir    = Path(cfg.get("win_state_dir") or DEFAULT_STATE_DIR)
        # Default to sys.executable (this process's own interpreter), not the bare
        # "python" -- Task Scheduler's ONLOGON/elevated context can resolve PATH
        # differently and find a python without pytest installed.
        python_exe   = cfg.get("win_python_path", sys.executable)

        self._init_state(state_dir)
        state = self._load_state()
        phase = state.get(_PHASE_KEY, 0)

        pre_test_check(request, self.TEST_ID, self.PRE_TEST_CHECKLIST)

        logger.info("[State] phase=%d  state_dir=%s", phase, state_dir)
        # ------------------------------------------------------------------
        # Phase 0 — run bios_scripts/tme_check.py
        # ------------------------------------------------------------------
        if phase == 0:
            tme_check_script = Path(__file__).resolve().parents[2] / "bios_scripts" / "tme_check.py"
            if not tme_check_script.exists():
                pytest.fail(f"[Phase 0] Missing script: {tme_check_script}")

            logger.info("=" * 64)
            logger.info("Phase 0 — running TME capability check")
            logger.info("=" * 64)

            try:
                result = subprocess.run(
                    [python_exe, str(tme_check_script)],
                    capture_output=True,
                    text=True,
                    errors="replace",
                    timeout=180,
                    # tme_check.py looks for msr-cmd.exe / pcm-msr.exe in the current folder
                    cwd=str(tme_check_script.parent),
                )
            except subprocess.TimeoutExpired:
                pytest.fail("[Phase 0] tme_check.py timed out after 180 s.")

            if result.stdout:
                logger.info("[Phase 0][stdout]\n%s", result.stdout)
            if result.stderr:
                logger.warning("[Phase 0][stderr]\n%s", result.stderr)

            if result.returncode != 0:
                pytest.fail(f"[Phase 0] tme_check.py failed (rc={result.returncode}).")

            stdout = result.stdout or ""
            if "TME Baseline Support (ECX[13]): [-] NOT SUPPORTED" in stdout:
                pytest.fail(
                    "[Phase 0] TME Baseline Support (ECX[13]): [-] NOT SUPPORTED — "
                    "TME is not supported on this silicon. Use vPRO silicon to proceed."
                )
            if "TME Baseline Support (ECX[13]): [+] SUPPORTED" not in stdout:
                pytest.fail(
                    "[Phase 0] tme_check.py did not report 'TME Baseline Support (ECX[13])' "
                    "(non-Intel CPU, CPUID leaf 7 unavailable, or unexpected output)."
                )

            logger.info("[Phase 0] [OK] TME support check passed.")

            # Step 3.0 — read VT-d + TME back; tme_check.py's MSR 0x982 dump counts as TME evidence
            known = {}
            msr = re.search(r"Bit 1\s+\(Hardware Encryption\)\s*:\s*([01])", stdout)
            if msr:
                on = msr.group(1) == "1"
                known["Total Memory Encryption"] = (
                    on, f"tme_check.py: MSR 0x982 bit 1 = {msr.group(1)} ({'ENABLED' if on else 'DISABLED'})")
            unknown = self._check_bios_knobs("tme", log_dir, step_label="3.0", known=known)
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
                self._win_bios_setup_resumed(state, "tme", log_dir, step_label="3.0")
            finally:
                self._cleanup_state()

        logger.info("[Step 3.0] [OK] TME = Enabled and VT-d = Enabled")
        self._cleanup_state()
        self._end()
