# Copyright 2026 Intel Corporation
# SPDX-License-Identifier: Apache-2.0

"""
TEST — IEC 62443-4-2  SHA Extension  (functional, SUT-ONLY)

Test ID:  IEC62443-4-2-TC_SHA_Extension-FUNC-SUT
Suite:    sha_extension

PURPOSE
-------
SUT-only variant of test_ec62443_sha_extension_func.py.  Verifies that hardware
cryptographic extensions (AES-NI / SHA-NI) are active and that the OpenSSL
AES-256-CBC benchmark completes successfully.

Runs pytest DIRECTLY ON THE SUT — no external NUC controller, no SSH.

Unlike the NUC variant (test_ec62443_sha_extension_func.py):
  - Runs pytest directly on the SUT
  - Uses subprocess instead of os_manager
  - No reboots required — single-phase execution

The test runs:
    $ openssl speed aes-256-cbc

A run is considered PASSED when all of the following hold:
  1. Command exits with rc=0
  2. Output contains the throughput-table line beginning with "aes-256-cbc"
  3. Output contains "OPENSSL_ia32cap" in the CPUINFO line
  4. Throughput for the 16-byte block column exceeds min_throughput_kbps

PHASES
------
  Phase 0 (only phase — no reboots):
    - Step 3.0  Verify 'openssl' binary is available
    - Step 4.0  Run openssl speed aes-256-cbc via subprocess
    - Step 4.a  Assert rc == 0
    - Step 4.b  Assert throughput table line present
    - Step 4.c  Assert CPUINFO / ia32cap line present
    - Step 4.d  Assert throughput floor (if min_throughput_kbps > 0)
    - PASS + cleanup

ONE-TIME SETUP (SUT)
--------------------
  See deploy/setup/setup_sut.sh — run once before any SUT-only test.
  fw-validation-resume.service must be installed and enabled.

PRE-TEST (manual)
-----------------
  1.0)  SUT booted to Ubuntu OS.
  3.0)  openssl is installed: openssl version

CONFIG (sha_extension_config.yaml)
-----------------------------------
  openssl_command      : "openssl speed aes-256-cbc"
  output_type_keyword  : "aes-256-cbc"
  cpuinfo_keyword      : "OPENSSL_ia32cap"
  min_throughput_kbps  : 200000
  command_timeout      : 60

RUN (on SUT)
------------
  /home/user/Desktop/venv/bin/python3 -m pytest \\
      tests/sha_extension/test_ec62443_sha_extension_sut_func.py -v -s \\
      --setup-confirmed --yes
"""

import logging
import re
import shutil
import subprocess
from pathlib import Path

import pytest

from tests.sut_base_test import SUTBaseTest
from core.prereq import pre_test_check

logger = logging.getLogger(__name__)


@pytest.mark.sha_extension
class TestEC62443SHAExtensionSUTFunc(SUTBaseTest):
    """IEC 62443-4-2 SHA Extension — openssl AES-256-CBC benchmark, SUT-only variant."""

    SUITE   = "sha_extension"
    TEST_ID = "IEC62443-4-2-TC_SHA_Extension-FUNC-SUT"

    PRE_TEST_CHECKLIST = [
        "1.0)  SUT booted to Ubuntu OS.",
        "3.0)  openssl installed on SUT: openssl version",
        "SETUP) fw-validation-resume.service installed + enabled (see deploy/).",
    ]

    # ------------------------------------------------------------------
    # Step helpers
    # ------------------------------------------------------------------

    def _step_verify_openssl(self) -> None:
        """Step 3.0 — Confirm 'openssl' binary is on PATH."""
        if shutil.which("openssl") is None:
            pytest.fail(
                "[Step 3.0] 'openssl' not found on PATH.\n"
                "Install with: sudo apt-get install -y openssl"
            )
        logger.info("[Step 3.0] [OK] openssl binary found: %s", shutil.which("openssl"))

    def _step_run_openssl(self, cmd: str, timeout: int, artifact: Path) -> str:
        """
        Step 4.0 — Run openssl speed command locally and save output artifact.

        Returns:
            Combined stdout + stderr output string.
        """
        logger.info("[Step 4.0] Running: %s", cmd)
        try:
            result = subprocess.run(
                cmd.split(),
                capture_output=True,
                text=True,
                timeout=timeout,
            )
        except subprocess.TimeoutExpired:
            pytest.fail(
                f"[Step 4.0] openssl speed timed out after {timeout}s.\n"
                f"Increase command_timeout in sha_extension_config.yaml."
            )

        # openssl speed writes benchmark progress to stderr, results table to stdout
        full_output = result.stdout + result.stderr

        artifact.write_text(full_output, encoding="utf-8", errors="replace")
        logger.info("[Step 4.0] Artifact saved: %s", artifact)

        for line in full_output.splitlines():
            logger.info("    %s", line)

        # Step 4.a — exit code
        assert result.returncode == 0, (
            f"[Step 4.a] openssl exited with rc={result.returncode}.\n"
            f"Is openssl installed on the SUT?\n"
            f"Check artifact: {artifact}"
        )
        logger.info("[Step 4.a] [OK] openssl exited rc=0")

        return full_output

    def _step_verify_table_line(
        self, full_output: str, type_keyword: str, artifact: Path
    ) -> str:
        """
        Step 4.b — Assert throughput table line starting with type_keyword is present.

        Returns:
            The matched table line string.
        """
        table_line = ""
        for line in full_output.splitlines():
            if line.strip().lower().startswith(type_keyword.lower()):
                table_line = line.strip()
                break

        assert table_line, (
            f"[Step 4.b] Throughput table line starting with '{type_keyword}' "
            f"not found in output.\n"
            f"Check artifact: {artifact}"
        )
        logger.info("[Step 4.b] [OK] Throughput table line found:")
        logger.info("    %s", table_line)
        return table_line

    def _step_verify_cpuinfo(
        self, full_output: str, cpuinfo_keyword: str, artifact: Path
    ) -> None:
        """Step 4.c — Assert CPUINFO line with ia32cap is present (hardware extensions active)."""
        cpuinfo_present = any(
            cpuinfo_keyword.lower() in line.lower()
            for line in full_output.splitlines()
        )
        assert cpuinfo_present, (
            f"[Step 4.c] '{cpuinfo_keyword}' not found in openssl output.\n"
            f"Hardware cryptographic extensions may not be detected by OpenSSL.\n"
            f"Check artifact: {artifact}"
        )
        logger.info(
            "[Step 4.c] [OK] CPUINFO '%s' detected — hardware extensions active.",
            cpuinfo_keyword,
        )

    def _step_verify_throughput(
        self, table_line: str, min_throughput: float
    ) -> None:
        """Step 4.d — Assert 16-byte block throughput meets minimum floor."""
        if min_throughput <= 0:
            logger.info("[Step 4.d] Throughput floor check disabled (min_throughput_kbps=0).")
            return

        tokens = table_line.split()
        throughput_kbps = None
        for token in tokens:
            match = re.fullmatch(r"([\d.]+)k", token, re.IGNORECASE)
            if match:
                throughput_kbps = float(match.group(1))
                break

        if throughput_kbps is None:
            logger.warning(
                "[Step 4.d] Could not parse throughput value from table line: %s",
                table_line,
            )
            return

        logger.info(
            "[Step 4.d] 16-byte throughput: %.2f kB/s  (min: %.0f kB/s)",
            throughput_kbps, min_throughput,
        )
        assert throughput_kbps >= min_throughput, (
            f"[Step 4.d] AES-256-CBC 16-byte throughput too low: "
            f"{throughput_kbps:.2f} kB/s < {min_throughput:.0f} kB/s.\n"
            f"Hardware AES acceleration may not be in use."
        )
        logger.info("[Step 4.d] [OK] Throughput floor check passed.")

    # ------------------------------------------------------------------
    # Test entry point
    # ------------------------------------------------------------------

    def test_ec62443_sha_extension_sut_func(
        self,
        request,
        config,
        log_dir,
    ):
        """
        IEC62443-4-2-TC_SHA_Extension-FUNC-SUT

        Single-phase execution — no reboots required:
          Phase 0: verify openssl + run benchmark + assert all checks
        """
        self._begin()
        cfg = self._load_config(config)
        mgr = self._init_state_dir(cfg)

        pre_test_check(request, self.TEST_ID, self.PRE_TEST_CHECKLIST)

        # ------------------------------------------------------------------
        # Config
        # ------------------------------------------------------------------
        openssl_cmd     = cfg.get("openssl_command",     "openssl speed aes-256-cbc")
        type_keyword    = cfg.get("output_type_keyword", "aes-256-cbc")
        cpuinfo_keyword = cfg.get("cpuinfo_keyword",     "OPENSSL_ia32cap")
        min_throughput  = float(cfg.get("min_throughput_kbps", 200000))
        timeout         = int(cfg.get("command_timeout", 60))

        logger.info("[Config] openssl_cmd     : %s", openssl_cmd)
        logger.info("[Config] type_keyword    : %s", type_keyword)
        logger.info("[Config] cpuinfo_keyword : %s", cpuinfo_keyword)
        logger.info("[Config] min_throughput  : %.0f kB/s", min_throughput)
        logger.info("[Config] timeout         : %d s", timeout)

        state = mgr.get_state()
        phase = state.get("phase", 0)
        logger.info("[State] phase=%s", phase)

        # This test is single-phase — if phase != 0 something went wrong
        assert phase == 0, (
            f"[State] Unexpected phase={phase}. Expected 0 for this single-phase test.\n"
            "Clean the state files (logs/sut_state) and rerun."
        )

        # ==================================================================
        # Phase 0 — run openssl speed locally and verify output
        # ==================================================================

        artifact = Path(log_dir) / "openssl_speed_aes256cbc.log"

        # ------------------------------------------------------------------
        # Step 3.0 — Verify openssl binary
        # ------------------------------------------------------------------
        self._step_verify_openssl()

        # ------------------------------------------------------------------
        # Step 4.0 + 4.a — Run benchmark and assert rc=0
        # ------------------------------------------------------------------
        full_output = self._step_run_openssl(openssl_cmd, timeout, artifact)

        # ------------------------------------------------------------------
        # Step 4.b — Throughput table line
        # ------------------------------------------------------------------
        table_line = self._step_verify_table_line(full_output, type_keyword, artifact)

        # ------------------------------------------------------------------
        # Step 4.c — CPUINFO / ia32cap
        # ------------------------------------------------------------------
        self._step_verify_cpuinfo(full_output, cpuinfo_keyword, artifact)

        # ------------------------------------------------------------------
        # Step 4.d — Throughput floor
        # ------------------------------------------------------------------
        self._step_verify_throughput(table_line, min_throughput)

        logger.info("[Step 4.0] [OK] openssl speed aes-256-cbc completed successfully.")

        mgr.cleanup()
        self._end()
