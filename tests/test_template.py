# Copyright 2026 Intel Corporation
# SPDX-License-Identifier: Apache-2.0

"""
TEMPLATE — Copy this file to create a new IEC 62443-4-2 test case under tests/.

This is the customer-facing, SUT-local pattern: pytest runs directly on the
board under test via subprocess -- no NUC, no SSH, no serial. For the internal
NUC-driven pattern instead (BaseTest + os_manager/serial_manager), see an
existing file under internal_nuc/tests/<suite>/ and ask before adding more
there -- new tests should default to this SUT-local pattern.

HOW TO USE
----------
1. Copy into the correct suite folder and rename:
       cp tests/test_template.py tests/<suite>/test_ec62443_<topic>_sut_func.py

2. Replace every <PLACEHOLDER> with real values (search for "<").

3. Create config/suites/<suite>_config.yaml with test-specific parameters.

4. Run --collect-only to confirm pytest discovers your test:
       python -m pytest tests/<suite>/test_ec62443_<topic>_sut_func.py --collect-only

STANDARD STRUCTURE (enforced by SUTBaseTest inheritance)
----------------------------------------------------------
Every test class:
  - Inherits SUTBaseTest (tests/sut_base_test.py), which itself inherits
    BaseTest (tests/base_test.py) for the OS-agnostic helpers
  - Defines SUITE  (loads config/suites/<SUITE>_config.yaml automatically)
  - Defines TEST_ID (ends in "-SUT")
  - Defines PRE_TEST_CHECKLIST
  - One public test_* method (thin orchestrator)
  - No hardcoded IPs, paths, or credentials (always from config)
  - Logs computed values BEFORE asserting them
  - One assert per logical check with a descriptive failure message

RULES
-----
- No os_manager/serial_manager/reboot_manager fixtures here -- those are
  internal_nuc-only. Use subprocess directly for local commands.
- Use self._init_state_dir(cfg) + self._write_uefi_phase()/self._reboot_into_uefi()
  for any test that needs a UEFI shell tool and a reboot to survive.
- Use self._wait_for_manual_signal(...) for any in-test manual BIOS checkpoint.
- Use self._parse_meinfo_field() for MEInfo/UEFI tool output parsing.
- Use self.step() context manager for each phase.
- Test constants (expected values) -> class-level constants here.
- Environment values (paths, timeouts) -> config/suites/<suite>_config.yaml.
- See tests/CONTRIBUTING.md for the full rules.
"""

import logging
import subprocess

import pytest

from tests.sut_base_test import SUTBaseTest
from core.prereq import pre_test_check

logger = logging.getLogger(__name__)


@pytest.mark.<SUITE_MARKER>                     # e.g. @pytest.mark.txt
@pytest.mark.manual                             # keep if any pre-test step is manual
class Test<TC_NAME>SUTFunc(SUTBaseTest):        # e.g. class TestEC62443TXTSUTFunc(SUTBaseTest):
    """IEC 62443-4-2 <Topic> test -- SUT-local."""

    # ------------------------------------------------------------------
    # Mandatory class constants
    # ------------------------------------------------------------------
    SUITE   = "<suite>"                         # e.g. "txt" -> config/suites/txt_config.yaml
    TEST_ID = "IEC62443-4-2-TC_<TOPIC>-FUNC-SUT"

    #: Expected values -- tune here, never in code below
    EXPECTED_<VALUE> = "<expected>"             # e.g. EXPECTED_MSR_HEX = "f440000004"

    PRE_TEST_CHECKLIST = [
        "1.0)  Flash IFWI and deploy Ubuntu/Windows custom image to the SUT.",
        "2.0)  Power ON and boot the SUT.",
        "3.0)  <Any BIOS eyeball check needed before running>.",
    ]

    # ------------------------------------------------------------------
    # Entry point -- orchestrator only
    # ------------------------------------------------------------------
    def test_<tc_id>_sut_func(self, request, config, log_dir):
        """IEC62443-4-2-TC_<TOPIC>-FUNC-SUT -- <one-line description>."""
        self._begin()
        cfg = self._load_config(config)             # MUST be first — loads suite YAML

        pre_test_check(request, self.TEST_ID, self.PRE_TEST_CHECKLIST)

        # ==================================================================
        # Step 3.0 -- <what this step does>
        # ==================================================================
        with self.step("3.0", "<description>"):
            # Local command — pytest already runs on the SUT, no SSH needed
            result = subprocess.run(
                ["<command>"], capture_output=True, text=True, timeout=30
            )
            out = result.stdout.strip()
            logger.info("[Step 3.0] result = %s", out)
            assert out == self.EXPECTED_<VALUE>, (
                f"[Step 3.0] Expected '{self.EXPECTED_<VALUE>}', got '{out}'"
            )
            logger.info("[Step 3.0] [OK]")

        # Uncomment if this test needs an operator to make a manual BIOS change.
        # The signal file is never the proof: require the reboot and read the knob back.
        # self._wait_for_manual_signal(
        #     signal_file="step4_done.txt",
        #     step_label="4.0",
        #     timeout_secs=int(cfg.get("manual_gate_timeout_secs", 900)),
        #     instructions=["1) Enter BIOS Setup, set <X>.", "2) Save & Exit (F4), boot back to the OS."],
        #     requires_reboot=True,
        #     verify=self._knob_verifier({"<Setup Question>": "Enabled"}),
        # )

        # ==================================================================
        # PASS
        # ==================================================================
        logger.info("[PASS] %s completed successfully", self.TEST_ID)
        self._end()

