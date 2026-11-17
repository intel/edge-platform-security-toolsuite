# Copyright 2026 Intel Corporation
# SPDX-License-Identifier: Apache-2.0

"""
TEST — IEC 62443-4-2  dTPM  Windows OS  (measured boot, SUT LOCAL)

Test ID:  IEC62443-4-2_Windows-TC_dTPM-FUNC-SUT
Suite:    measured_boot

PURPOSE
-------
SUT-local variant for discrete TPM: run pytest DIRECTLY ON the Windows SUT.
No external controller or SSH required.

Uses the same phase-based approach as the fTPM SUT variant:
  - JSON state file (logs/sut_state, or win_state_dir) persists PCR snapshots between reboots.
  - Windows Task Scheduler auto-resumes pytest after each cold boot.
  - Final phase compares all PCR snapshots.

Key dTPM difference vs fTPM:
  - VendorID is NOT Intel (expect IFX, STM, NTC, etc.)
  - Windows handles all TPM multiplexing automatically (no tpm2-abrmd needed)
  - The TBS API reads from the discrete TPM transparently

PHASES
------
  Phase 0              (first run):
    - Step 7.a  Confirm-SecureBootUEFI
    - Step 7.b  Get-Tpm (TPM status)
    - Step 7.d  tpmtool getdeviceinformation (verify non-Intel VendorID)
    - Step 7.c  Settle reboot: the boot the test starts on was not started by
                the test (after a disk/IFWI/BIOS change the firmware rebuilds
                BootOrder and tries stale boot options first, which changes
                PCR 1 and PCR 4), so it is never measured
    - Step 7.e  tpmtool gatherlogs + Read PCRs via TBS API (dTPM)
    - Reboot → Phase 1

  Phase 1 … ITER-2:
    - Step 7.b  Get-Tpm
    - Step 7.e  tpmtool gatherlogs + Read PCRs
    - Reboot → Phase N+1

  Phase ITER-1  (final):
    - Step 7.b  Get-Tpm
    - Step 7.e  tpmtool gatherlogs + Read PCRs
    - Step 8.0  Compare all PCR snapshots
    - Cleanup

PRE-TEST (manual)
-----------------
  1.0)  Build dTPM IFWI using MFIT:
        1.1)  Platform Protection → TPMs → TPM Technology = dTPM.
        1.2)  Intel PTT Configuration → Intel PTT Supported = No.
        1.3)  Build IFWI.
  2.0)  Flash dTPM IFWI and deploy Windows image to the SUT.
  3.0)  Power ON, boot SUT to Windows OS.
  4.0)  Enable UEFI Secure Boot — run ON the SUT in an elevated PowerShell
        (auto-verified at runtime):
          deploy/secure_boot/enable_secure_boot_windows.ps1 provision → verify
        PDF for reference/checking only, not required:
          doc/reference/secure_boot_windows.pdf
  4.1)  F2 → Platform Information → Current TPM Location = dTPM 2.0.
  4.2)  F2 → TPM EFI Device Manager → TCG2 Config → Active PCR Bank = SHA256.
  5.0)  Confirm discrete TPM chip is physically installed on the board.
  6.0)  Run from an Administrator Command Prompt / PowerShell.
        Run from an Administrator Command Prompt / PowerShell.

RUN (on the Windows SUT — Administrator Command Prompt or PowerShell)
---
  cd C:\\path\\to\\asrock_repo
  python -m pytest tests/measured_boot/test_ec62443_dtpm_sut_wins_func.py \\
      -v -s --setup-confirmed --yes
"""

import json
import logging
import subprocess
import sys
from pathlib import Path

import pytest

from tests.base_test import BaseTest
from conftest import load_suite_config
from core.prereq import pre_test_check
from core.reboot_plan import entry as reboot_entry
from core.state_dir import DEFAULT_STATE_DIR
from tests.measured_boot._win_mb_base import (
    _PS_CONFIRM_SECURE_BOOT,
    _PS_GET_TPM,
    _PS_TPM_DEVICE_INFO,
    _PS_GATHER_LOGS_TEMPLATE,
    run_ps_local,
    parse_pcrs_from_tpm_information,
    parse_get_tpm,
    parse_tpm_vendor,
)

logger = logging.getLogger(__name__)

_SNAPSHOT_KEY    = "dtpm_pcr_snapshots"
_BOOT_IDS_KEY    = "dtpm_boot_ids"
_PHASE_KEY       = "phase"
_SETTLED_KEY     = "settle_reboot_done"
_INTEL_VENDOR_IDS = {"INTC", "INTEL"}


@pytest.mark.measured_boot
@pytest.mark.manual
class TestEC62443dTPMWinsSUTFunc(BaseTest):
    """IEC 62443-4-2 dTPM measured-boot — Windows SUT-local, phase-based."""

    SUITE   = "measured_boot"
    TEST_ID = "IEC62443-4-2_Windows-TC_dTPM-FUNC-SUT"

    @classmethod
    def reboot_plan(cls, config: dict) -> list:
        n = int(load_suite_config(cls.SUITE).get("reboot_iterations", cls.ITERATIONS))
        return [reboot_entry("auto", "settle reboot before the first PCR read")] + [
            reboot_entry("auto", f"reboot {i} of {n - 1} for the PCR comparison") for i in range(1, n)]

    PCR_LIST   = [0, 1, 2, 3, 4, 5, 6, 7]
    ITERATIONS = 5

    PRE_TEST_CHECKLIST = [
        "1.0)  Build dTPM IFWI (MFIT: Platform Protection → TPMs → TPM Technology = dTPM).",
        "1.1)  Intel PTT Configuration → Intel PTT Supported = No.",
        "1.2)  Build IFWI and flash to the SUT.",
        "2.0)  Deploy Windows image and boot to Windows OS.",
        "3.0)  Enable UEFI Secure Boot — run ON the SUT (elevated PowerShell,",
        "      auto-verified at runtime):",
        "          .\\deploy\\secure_boot\\enable_secure_boot_windows.ps1 provision → verify",
        "      (PDF for reference/checking only, not required: doc/reference/secure_boot_windows.pdf)",
        "4.1)  F2 → Platform Information → Current TPM Location = dTPM 2.0.",
        "4.2)  F2 → TPM EFI Device Manager → TCG2 Config → Active PCR Bank = SHA256.",
        "5.0)  Confirm discrete TPM chip is physically installed on the board.",
        "6.0)  Run from an Administrator Command Prompt / PowerShell.",
    ]

    # ------------------------------------------------------------------
    # State management
    # ------------------------------------------------------------------

    def _init_state(self, state_dir: Path) -> None:
        state_dir.mkdir(parents=True, exist_ok=True)
        self._state_file = state_dir / "dtpm_state.json"

    def _load_state(self) -> dict:
        if self._state_file.exists():
            try:
                state = json.loads(self._state_file.read_text(encoding="utf-8"))
            except Exception as exc:
                logger.warning("State file load failed: %s — starting fresh", exc)
                return {_PHASE_KEY: 0, _SNAPSHOT_KEY: {}}
            # JSON object keys are always strings, so PCR-index keys (built as
            # int by parse_pcrs_from_tpm_information) come back as "0".. "7"
            # after this round-trip. Convert them back to int so lookups by
            # PCR_LIST (a list of ints) work the same for snapshots loaded
            # from disk as for the snapshot computed in the current process.
            snapshots = state.get(_SNAPSHOT_KEY, {})
            for phase_key, pcrs in snapshots.items():
                snapshots[phase_key] = {int(k): v for k, v in pcrs.items()}
            return state
        return {_PHASE_KEY: 0, _SNAPSHOT_KEY: {}}

    def _save_state(self, state: dict) -> None:
        self._state_file.write_text(json.dumps(state, indent=2), encoding="utf-8")

    def _cleanup_state(self) -> None:
        if self._state_file.exists():
            self._state_file.unlink(missing_ok=True)
            logger.info("[Cleanup] State file removed: %s", self._state_file)

    # ------------------------------------------------------------------
    # Reboot helper
    # ------------------------------------------------------------------

    def _reboot_sut(self) -> None:
        logger.info("[Reboot] shutdown /r /t 5 ...")
        result = subprocess.run(["shutdown", "/r", "/t", "5"], capture_output=True, text=True, timeout=30)
        if result.returncode != 0:
            self._cleanup_state()
            self._cancel_windows_resume()
            raise AssertionError(
                f"[Reboot] shutdown /r failed (rc={result.returncode}): "
                f"{(result.stderr or result.stdout).strip()}"
            )
        sys.exit(0)

    # ------------------------------------------------------------------
    # Per-phase step helpers
    # ------------------------------------------------------------------

    def _run_step_7a(self) -> None:
        """Step 7.a — Confirm-SecureBootUEFI"""
        logger.info("[Step 7.a] Confirm-SecureBootUEFI")
        rc, out, err = run_ps_local(_PS_CONFIRM_SECURE_BOOT, timeout=20)
        result = (out + err).strip()
        logger.info("[Step 7.a] Output: %r", result)
        assert "True" in result, (
            "[Step 7.a] Secure Boot NOT enabled.\n"
            f"  Output: {result!r}\n"
            "  Run the enable script ON the SUT (elevated PowerShell), then re-run:\n"
            "    .\\deploy\\secure_boot\\enable_secure_boot_windows.ps1 provision   # auto-reboots\n"
            "    .\\deploy\\secure_boot\\enable_secure_boot_windows.ps1 verify"
        )
        logger.info("[Step 7.a] [OK] Secure Boot enabled")

    def _run_step_7b(self) -> None:
        """Step 7.b — Get-Tpm status"""
        logger.info("[Step 7.b] Get-Tpm")
        rc, out, err = run_ps_local(_PS_GET_TPM, timeout=20)
        tpm = parse_get_tpm(out + err)
        logger.info("[Step 7.b] Get-Tpm: %s", tpm)
        for key in ("TpmPresent", "TpmReady", "TpmEnabled", "TpmActivated", "TpmOwned"):
            assert tpm.get(key, "").strip().lower() == "true", (
                f"[Step 7.b] TPM check failed: {key} is not True.\n"
                f"  Output: {out.strip()}"
            )
        logger.info("[Step 7.b] [OK] TPM operational")

    def _run_step_7d_dtpm(self) -> None:
        """Step 7.d — tpmtool getdeviceinformation → verify non-Intel (dTPM)"""
        logger.info("[Step 7.d] tpmtool getdeviceinformation")
        rc, out, err = run_ps_local(_PS_TPM_DEVICE_INFO, timeout=20)
        combined = out + err
        logger.info("[Step 7.d] Output:\n%s", combined.strip())
        vendor = parse_tpm_vendor(combined)
        logger.info("[Step 7.d] VendorID: %r", vendor)
        assert vendor, (
            f"[Step 7.d] Could not detect VendorID.\n  Full output:\n{combined.strip()}"
        )
        assert vendor.upper() not in _INTEL_VENDOR_IDS, (
            f"[Step 7.d] VendorID is {vendor!r} — this is Intel fTPM/PTT, NOT dTPM.\n"
            "  Use test_ec62443_ftpm_ptt_sut_wins_func.py for Intel PTT boards.\n"
            "  For dTPM: ensure discrete TPM chip is installed and IFWI built with dTPM mode."
        )
        logger.info("[Step 7.d] [OK] dTPM confirmed (VendorID=%s, non-Intel)", vendor)

    def _run_step_7e(
        self,
        log_dir: Path,
        state_dir: Path,
        iteration: int,
    ) -> dict:
        """Step 7.e — tpmtool gatherlogs artifact, parse PCRs from TpmInformation.txt"""
        # tpmtool gatherlogs already queries the TPM and writes the current
        # PCR digests (per active bank) into TpmInformation.txt -- read PCRs
        # from there instead of re-implementing raw TBS PCR reads.
        log_subdir = state_dir / f"dtpm_tpmlog_iter_{iteration}"
        gather_cmd = _PS_GATHER_LOGS_TEMPLATE.format(log_dir=str(log_subdir))
        rc, out, err = run_ps_local(gather_cmd, timeout=60)
        logger.info("[Step 7.e] tpmtool gatherlogs -> %s (rc=%d)", log_subdir, rc)

        info_file = log_subdir / "TpmInformation.txt"
        assert rc == 0 and info_file.exists(), (
            f"[Step 7.e] tpmtool gatherlogs failed (rc={rc}) or did not produce "
            f"{info_file}.\n"
            f"  stderr: {err.strip()}\n"
            "  Ensure this script runs as Administrator."
        )

        info_text = info_file.read_text(encoding="utf-16-le", errors="replace")

        log_file = log_dir / f"dTPM_pcr_read_iter{iteration}.log"
        log_file.write_text(info_text, encoding="utf-8", errors="replace")
        logger.info("[Step 7.e] Artifact: %s", log_file)

        pcrs = parse_pcrs_from_tpm_information(info_text, self.PCR_LIST)

        missing = [p for p in self.PCR_LIST if p not in pcrs]
        assert not missing, (
            f"[Step 7.e] Missing PCRs {missing} in {info_file}.\n"
            "  Confirm F2 → TPM EFI Device Manager → TCG2 Config → "
            "Active PCR Bank = SHA256."
        )

        for idx in self.PCR_LIST:
            logger.info("[Step 7.e]   dTPM PCR[%02d] = %s", idx, pcrs[idx])

        return pcrs

    # ------------------------------------------------------------------
    # Test entry point
    # ------------------------------------------------------------------

    def test_ec62443_dtpm_sut_wins_func(
        self,
        request,
        config,
        log_dir,
    ):
        """
        IEC62443-4-2_Windows-TC_dTPM-FUNC-SUT

        Phase-based execution; one cold boot per phase.
        Task Scheduler auto-resumes pytest after each reboot.
        """
        self._begin()
        cfg        = self._load_config(config)
        iterations = int(cfg.get("reboot_iterations", self.ITERATIONS))
        state_dir  = Path(cfg.get("win_state_dir") or DEFAULT_STATE_DIR)
        # Default to sys.executable (this process's own interpreter), not the bare
        # "python" -- Task Scheduler's ONLOGON/elevated context can resolve PATH
        # differently and find a python without pytest installed.
        python_exe = cfg.get("win_python_path", sys.executable)

        self._init_state(state_dir)

        state = self._load_state()

        pre_test_check(request, self.TEST_ID, self.PRE_TEST_CHECKLIST)

        # ------------------------------------------------------------------
        # Step 6.0 — Verify this process is running elevated (Administrator).
        # Confirm-SecureBootUEFI, tpmtool, and the /rl HIGHEST Task Scheduler
        # resume task all require elevation — being a member of the
        # Administrators group is not the same as running elevated (UAC).
        # ------------------------------------------------------------------
        logger.info("[Step 6.0] Verifying this process is running elevated (Administrator)")
        is_admin = self._is_windows_admin()
        logger.info("[Step 6.0] Elevated (IsUserAnAdmin): %s", is_admin)

        assert is_admin, (
            "[Step 6.0] This process is NOT running elevated.\n"
            "  Confirm-SecureBootUEFI, tpmtool, and the Task Scheduler resume task\n"
            "  all require Administrator elevation.\n"
            "  Fix: close this terminal, then open Command Prompt / PowerShell via\n"
            "       'Run as administrator' and re-run:\n"
            "       python -m pytest tests/measured_boot/test_ec62443_dtpm_sut_wins_func.py -v -s "
            "--setup-confirmed --yes"
        )
        logger.info("[Step 6.0] [OK] Process is running elevated")

        phase = state.get(_PHASE_KEY, 0)

        logger.info("[State] phase=%d  iterations=%d  state_dir=%s", phase, iterations, state_dir)

        # ------------------------------------------------------------------
        # Phase 0: initial checks + first PCR snapshot
        # ------------------------------------------------------------------
        if phase == 0:
            if not state.get(_SETTLED_KEY):
                logger.info("=" * 60)
                logger.info("Phase 0 — initial checks + settle reboot")
                logger.info("=" * 60)

                self._run_step_7a()
                self._run_step_7b()
                self._run_step_7d_dtpm()

                state[_SETTLED_KEY] = True
                self._save_state(state)
                logger.info("[Step 7.c] Settle reboot: this boot was not started by the test (after a disk, "
                            "IFWI or BIOS change the firmware rebuilds BootOrder and tries stale boot "
                            "options first, changing PCR 1/4) -- only boots the test starts are measured")
                self._queue_windows_resume(request, python_exe, step_label="7.c")
                self._reboot_sut()

            logger.info("=" * 60)
            logger.info("Phase 0 — first dTPM PCR read (iteration 1)")
            logger.info("=" * 60)

            self._run_step_7b()
            pcrs = self._run_step_7e(log_dir, state_dir, iteration=1)
            state[_SNAPSHOT_KEY] = {"1": pcrs}
            state[_BOOT_IDS_KEY] = {"1": self._boot_id()}
            state[_PHASE_KEY]    = 1
            self._save_state(state)

            if iterations > 1:
                self._queue_windows_resume(request, python_exe, step_label="7.e")
                self._reboot_sut()

        # ------------------------------------------------------------------
        # Middle phases
        # ------------------------------------------------------------------
        for mid_phase in range(1, iterations - 1):
            if phase == mid_phase:
                logger.info("=" * 60)
                logger.info("Phase %d — dTPM PCR read (iteration %d)", mid_phase, mid_phase + 1)
                logger.info("=" * 60)

                self._run_step_7b()
                pcrs = self._run_step_7e(log_dir, state_dir, iteration=mid_phase + 1)

                snapshots = state.get(_SNAPSHOT_KEY, {})
                snapshots[str(mid_phase + 1)] = pcrs
                state[_SNAPSHOT_KEY] = snapshots
                state.setdefault(_BOOT_IDS_KEY, {})[str(mid_phase + 1)] = self._boot_id()
                state[_PHASE_KEY]    = mid_phase + 1
                self._save_state(state)

                self._queue_windows_resume(request, python_exe, step_label="7.e")
                self._reboot_sut()

        # ------------------------------------------------------------------
        # Final phase: last PCR read + compare
        # ------------------------------------------------------------------
        final_phase = iterations - 1
        if phase >= final_phase:
            logger.info("=" * 60)
            logger.info("Phase %d (FINAL) — dTPM last PCR read + comparison", final_phase)
            logger.info("=" * 60)

            self._run_step_7b()
            pcrs = self._run_step_7e(log_dir, state_dir, iteration=iterations)

            snapshots = state.get(_SNAPSHOT_KEY, {})
            snapshots[str(iterations)] = pcrs
            state[_SNAPSHOT_KEY] = snapshots
            state.setdefault(_BOOT_IDS_KEY, {})[str(iterations)] = self._boot_id()
            self._save_state(state)

            # Matching PCRs only mean something if every snapshot came from its own boot.
            self._assert_distinct_boots(state[_BOOT_IDS_KEY], step_label="8.0")

            # ----------------------------------------------------------
            # Step 8.0 — Compare PCRs across all iterations
            # ----------------------------------------------------------
            logger.info("[Step 8.0] Comparing dTPM SHA256 PCR %s across %d boots",
                        self.PCR_LIST, iterations)

            mismatches = []
            for idx in self.PCR_LIST:
                values = {it: snapshots[it].get(idx, "MISSING") for it in snapshots}
                unique = set(values.values())
                consistent = (len(unique) == 1)
                logger.info(
                    "[Step 8.0]   PCR[%02d]: %s",
                    idx,
                    "MATCH" if consistent else f"MISMATCH {values}",
                )
                if not consistent:
                    mismatches.append((idx, values))

            snapshot_out = log_dir / "pcr_snapshots_dtpm_sut.json"
            snapshot_out.write_text(json.dumps(snapshots, indent=2), encoding="utf-8")
            logger.info("[Step 8.0] Snapshots artifact: %s", snapshot_out)

            self._cleanup_state()

            assert not mismatches, (
                "[Step 8.0] dTPM PCR values changed across reboots (expected identical):\n"
                + "\n".join(f"  PCR[{idx}] -> {vals}" for idx, vals in mismatches)
            )

            logger.info(
                "[Step 8.0] [OK] dTPM SHA256 PCR %s identical across %d cold boots",
                self.PCR_LIST, iterations,
            )

        self._end()
