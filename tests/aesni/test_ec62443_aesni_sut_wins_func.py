# Copyright 2026 Intel Corporation
# SPDX-License-Identifier: Apache-2.0

"""
TEST — IEC 62443-4-2  AES-NI  Windows OS  (functional — SUT LOCAL)

Test ID:  IEC62443-4-2_Windows-TC_AES-NI-FUNC-SUT
Suite:    aesni

PURPOSE
-------
SUT-local variant: run pytest DIRECTLY ON the Windows SUT.
No external controller or SSH required.

Verifies AES-NI functionality by running run_aesni_test.py locally.
The test completes as soon as the AES-NI check passes. No power management
state transitions (S3/S4/S5) are involved.

STEPS
-----
  Step 7.0  OpenSSL check (openssl.exe on PATH, or in openssl_bin_dir)
  Step 7.1  Coreinfo64.exe check (coreinfo_exe_path, default Tools/Coreinfo64.exe)
  Step 8.0  AES-NI check

PRE-TEST (manual — done BEFORE first run)
-----------------------------------------
  1.0)  Flash IFWI and deploy Windows image.
  2.0)  Power ON, boot Windows.
  3.0)  OpenSSL for Windows: run deploy\\setup\\setup_sut_windows.ps1 once from an
        Administrator PowerShell. Its step 4 downloads the pinned Win64 OpenSSL
        Light MSI (deploy/tools/download_links.xml, SHA-256 checked), installs it
        and adds its bin folder to the system PATH. Step 7.0 of this test checks it.
        Manual fallback: install from https://slproweb.com/products/Win32OpenSSL.html
        and add its bin folder (e.g. C:\\Program Files\\OpenSSL-Win64\\bin) to PATH.
  4.0)  Coreinfo64.exe (Sysinternals): staged into Tools\\Coreinfo64.exe by
        deploy\\tools\\deploy_tools.py (also run by setup_sut_windows.ps1), which
        downloads Coreinfo.zip from https://download.sysinternals.com/files/Coreinfo.zip
        when it is not in Downloads\\. Without internet access, put Coreinfo.zip
        into Downloads\\ first. Step 7.1 of this test checks it.
  5.0)  config/suites/aesni_config.yaml (forward slashes "/" in YAML values):
        5.1)  coreinfo_exe_path : Coreinfo64.exe, absolute or repo-relative;
                                  default "Tools/Coreinfo64.exe"
        5.2)  win_python_path   : full path to python.exe on this machine,
                                  or "python" if it is already on PATH
        5.3)  openssl_bin_dir   : (optional) OpenSSL bin folder, used when
                                  openssl is not on PATH; default
                                  "C:/Program Files/OpenSSL-Win64/bin"
  6.0)  Run from Administrator PowerShell.

NOTE: run_aesni_test.py is bundled in this repo (bios_scripts/) and run in
place — no separate copy or working directory needs to be configured.

RUN (Administrator PowerShell)
---
  cd C:\\path\\to\\asrock_repo
  python -m pytest tests/aesni/test_ec62443_aesni_sut_wins_func.py \\
      -v -s --setup-confirmed --yes
"""

import logging
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from tests.base_test import BaseTest
from core.prereq import pre_test_check

logger = logging.getLogger(__name__)

_PASS_KEYWORD = "TEST PASSED"
_DEFAULT_OPENSSL_BIN_DIR = "C:/Program Files/OpenSSL-Win64/bin"

_REPO_ROOT = Path(__file__).resolve().parents[2]
# Where deploy/tools/deploy_tools.py stages Coreinfo64.exe (tools.xml).
_DEFAULT_COREINFO_EXE = _REPO_ROOT / "Tools" / "Coreinfo64.exe"

# Bundled AES-NI script shipped in this repo (bios_scripts/), run in place.
# Resolved relative to the project root so it works regardless of cwd.
_BUNDLED_SCRIPT = _REPO_ROOT / "bios_scripts" / "run_aesni_test.py"


@pytest.mark.aesni
@pytest.mark.manual
class TestEC62443AESNIWinsSUTFunc(BaseTest):
    """IEC 62443-4-2 AES-NI functional test — Windows SUT-local."""

    SUITE   = "aesni"
    TEST_ID = "IEC62443-4-2_Windows-TC_AES-NI-FUNC-SUT"

    PRE_TEST_CHECKLIST = [
        "1.0)  Flash IFWI and deploy Windows image to the SUT.",
        "2.0)  Power ON and boot SUT to Windows OS.",
        "3.0)  OpenSSL for Windows: run .\\deploy\\setup\\setup_sut_windows.ps1 once",
        "      from an Administrator PowerShell (step 4 installs the pinned Win64",
        "      OpenSSL Light MSI and adds its bin folder to the system PATH).",
        "      Step 7.0 of this test checks it.",
        "4.0)  Coreinfo64.exe: staged into Tools\\Coreinfo64.exe by",
        "      deploy\\tools\\deploy_tools.py (run by setup_sut_windows.ps1), which",
        "      downloads Coreinfo.zip automatically. Offline: put Coreinfo.zip",
        "      into Downloads\\ first. Step 7.1 of this test checks it.",
        "5.0)  config/suites/aesni_config.yaml (forward slashes '/' in YAML values):",
        "      5.1)  coreinfo_exe_path : default \"Tools/Coreinfo64.exe\" (repo-relative);",
        "              change only if Coreinfo64.exe is elsewhere.",
        "      5.2)  win_python_path   : full path to python.exe on this machine,",
        "              or \"python\" if it is already on PATH.",
        "6.0)  Run from Administrator PowerShell.",
    ]

    # ------------------------------------------------------------------
    # OpenSSL check
    # ------------------------------------------------------------------

    def _check_openssl(self, openssl_bin_dir: str, log_dir: Path, label: str) -> dict:
        """Find openssl.exe and return the environment for the AES-NI script.

        run_aesni_test.py calls plain "openssl", so when it is not on PATH yet
        (e.g. this shell started before setup_sut_windows.ps1 changed the system
        PATH) openssl_bin_dir is put first on the child process PATH.
        """
        env = os.environ.copy()
        exe = shutil.which("openssl")
        if exe is None:
            candidate = Path(openssl_bin_dir) / "openssl.exe"
            if candidate.is_file():
                env["PATH"] = str(candidate.parent) + os.pathsep + env.get("PATH", "")
                exe = str(candidate)
        logger.info("[%s] openssl.exe : %s", label, exe)
        assert exe is not None, (
            f"[{label}] openssl.exe not found on PATH or in openssl_bin_dir "
            f"({openssl_bin_dir}).\n"
            "  Run .\\deploy\\setup\\setup_sut_windows.ps1 from an Administrator "
            "PowerShell (step 4 installs OpenSSL), or set openssl_bin_dir in "
            "config/suites/aesni_config.yaml."
        )

        try:
            result = subprocess.run(
                [exe, "version"], capture_output=True, text=True,
                timeout=30, errors="replace",
            )
            out, rc = (result.stdout + result.stderr).strip(), result.returncode
        except (OSError, subprocess.TimeoutExpired) as exc:
            out, rc = str(exc), -1
        log_file = log_dir / "openssl_version.log"
        log_file.write_text(out + "\n", encoding="utf-8", errors="replace")
        logger.info("[%s] openssl version: %s (rc=%s)", label, out, rc)
        logger.info("[Artifact] %s", log_file)
        assert rc == 0 and out.startswith("OpenSSL"), (
            f"[{label}] '{exe} version' failed (rc={rc}): {out}\n"
            f"  Check artifact: {log_file}"
        )
        logger.info("[%s] [OK] OpenSSL available", label)
        return env

    # ------------------------------------------------------------------
    # AES-NI run helper
    # ------------------------------------------------------------------

    def _run_aesni_local(self, python_path: str, log_dir: Path, label: str,
                         coreinfo_exe_path: str, env: dict) -> None:
        """Run the bundled run_aesni_test.py and assert TEST PASSED."""
        script = _BUNDLED_SCRIPT
        assert script.exists(), (
            f"[{label}] Bundled script not found: {script}\n"
            "  Expected it in the repo at bios_scripts/run_aesni_test.py."
        )

        cmd = [python_path, str(script), "--coreinfo-exe", coreinfo_exe_path]
        logger.info("[%s] Execute: %s", label, " ".join(cmd))
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=180,
                cwd=str(log_dir),
                env=env,
                errors="replace",
            )
            out = result.stdout
            err = result.stderr
            rc  = result.returncode
        except subprocess.TimeoutExpired as exc:
            out, err, rc = "", str(exc), 124

        log_file = log_dir / f"aesni_{label.replace(' ', '_').replace('.', '')}.log"
        log_file.write_text(out + err, encoding="utf-8", errors="replace")
        logger.info("[Artifact] %s", log_file)

        for line in (out + err).splitlines():
            logger.info("    %s", line)

        fail_lines = [l.strip() for l in (out + err).splitlines() if l.strip().startswith(("FAIL", "ERROR"))]
        assert _PASS_KEYWORD in out + err, (
            f"[{label}] AES-NI script did not print '{_PASS_KEYWORD}'.\n"
            + "".join(f"  {line}\n" for line in fail_lines)
            + f"  rc={rc}\n"
            f"  Check artifact: {log_file}"
        )
        logger.info("[%s] [OK] %s", label, _PASS_KEYWORD)

    # ------------------------------------------------------------------
    # Test entry point
    # ------------------------------------------------------------------

    def test_ec62443_aesni_sut_wins_func(
        self,
        request,
        config,
        log_dir,
    ):
        """
        IEC62443-4-2_Windows-TC_AES-NI-FUNC-SUT

        Single-pass AES-NI check. No power state transitions (S3/S4/S5).
        """
        self._begin()
        cfg        = self._load_config(config)
        # Default to sys.executable (this process's own interpreter), not the bare
        # "python" -- avoids depending on PATH resolution picking the same install.
        python_exe = cfg.get("win_python_path", sys.executable)
        coreinfo_exe_path = cfg.get("coreinfo_exe_path") or str(_DEFAULT_COREINFO_EXE)
        openssl_bin_dir = cfg.get("openssl_bin_dir", _DEFAULT_OPENSSL_BIN_DIR)

        pre_test_check(request, self.TEST_ID, self.PRE_TEST_CHECKLIST)

        logger.info("=" * 60)
        logger.info("Step 7.0 — OpenSSL check")
        logger.info("=" * 60)

        env = self._check_openssl(openssl_bin_dir, log_dir, "Step 7.0")

        logger.info("[Step 7.1] coreinfo_exe_path : %s", coreinfo_exe_path)
        assert Path(coreinfo_exe_path).is_file(), (
            f"[Step 7.1] Coreinfo64.exe not found: {coreinfo_exe_path}\n"
            "  Run: python deploy\\tools\\deploy_tools.py  (downloads Coreinfo.zip and "
            "stages Tools\\Coreinfo64.exe), or set coreinfo_exe_path in "
            "config/suites/aesni_config.yaml."
        )
        logger.info("[Step 7.1] [OK] Coreinfo64.exe found")

        logger.info("=" * 60)
        logger.info("Step 8.0 — AES-NI check")
        logger.info("=" * 60)

        self._run_aesni_local(python_exe, log_dir, "Step 8.0 AES-NI", coreinfo_exe_path, env)

        logger.info("=" * 72)
        logger.info("[OK] IEC62443-4-2_Windows-TC_AES-NI-FUNC-SUT PASSED — AES-NI verified")
        logger.info("=" * 72)

        self._end()
