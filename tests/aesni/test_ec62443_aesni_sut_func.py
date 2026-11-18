# Copyright 2026 Intel Corporation
# SPDX-License-Identifier: Apache-2.0

"""
TEST — IEC 62443-4-2  AES-NI  (functional, SUT-only execution)

Test ID:  IEC62443-4-2-TC_AES-NI-FUNC-SUT
Suite:    aesni

PURPOSE
-------
Verifies that AES-NI (hardware AES acceleration) is enabled and locked down
on all CPU cores. Runs DIRECTLY ON THE SUT — no external controller or SSH
required.

Test plan mapping:
    4.0  Execute $ sudo python3 run_aesni_test.py — verify "TEST PASSED"
         (run_aesni_test.py is bundled in this repo's bios_scripts/ and run
         in place — no transfer needed since this test runs directly on
         the SUT.)

PRE-TEST (manual)
-----------------
  1.0)  SUT booted to Ubuntu OS.

RUN (on SUT)
------------
  python -m pytest tests/aesni/test_ec62443_aesni_sut_func.py -v -s --setup-confirmed --yes
"""

import logging
import subprocess
from pathlib import Path

import pytest

from tests.base_test import BaseTest
from core.prereq import pre_test_check

logger = logging.getLogger(__name__)

_PASS_KEYWORD = "TEST PASSED"

# Bundled AES-NI script shipped in this repo (bios_scripts/).
# Resolved relative to the project root so it works regardless of cwd.
_BUNDLED_SCRIPT = Path(__file__).resolve().parents[2] / "bios_scripts" / "run_aesni_test.py"


@pytest.mark.aesni
@pytest.mark.manual
class TestAESNISUT(BaseTest):
    """IEC 62443-4-2 AES-NI functional test — SUT-only execution variant."""

    SUITE   = "aesni"
    TEST_ID = "IEC62443-4-2-TC_AES-NI-FUNC-SUT"

    PRE_TEST_CHECKLIST = [
        "1.0)  SUT booted to Ubuntu OS.",
    ]

    def test_ec62443_aesni_sut_func(
        self,
        request,
        config,
        log_dir,
    ):
        """
        IEC62443-4-2-TC_AES-NI-FUNC-SUT

        Single-pass AES-NI check. No power state transitions (S3/S4/S5).
        """
        self._begin()
        self._load_config(config)

        pre_test_check(request, self.TEST_ID, self.PRE_TEST_CHECKLIST)

        # ==============================================================
        # Step 4.0 — Execute run_aesni_test.py and verify TEST PASSED
        # ==============================================================
        logger.info("\n[Step 4.0] Execute: sudo python3 %s", _BUNDLED_SCRIPT)
        assert _BUNDLED_SCRIPT.exists(), (
            f"[Step 4.0] Bundled script not found: {_BUNDLED_SCRIPT}\n"
            f"  Expected it in the repo at bios_scripts/run_aesni_test.py."
        )
        result = subprocess.run(
            ["sudo", "python3", str(_BUNDLED_SCRIPT)],
            capture_output=True, text=True, timeout=120,
        )
        combined = result.stdout + result.stderr

        artifact = Path(log_dir) / "aesni_Step_4.0.log"
        artifact.write_text(combined, encoding="utf-8", errors="replace")
        logger.info("[Artifact] %s", artifact)

        for line in combined.splitlines():
            logger.info("    %s", line)

        fail_lines = [l.strip() for l in combined.splitlines() if l.strip().startswith(("FAIL", "ERROR"))]
        assert _PASS_KEYWORD in combined, (
            f"[Step 4.0] AES-NI check failed — '{_PASS_KEYWORD}' not in output.\n"
            + "".join(f"  {line}\n" for line in fail_lines)
            + f"  Check artifact: {artifact}"
        )
        logger.info("[OK] Step 4.0 — %s", _PASS_KEYWORD)

        logger.info("AES-NI enabled and locked on all cores")
        self._end()
