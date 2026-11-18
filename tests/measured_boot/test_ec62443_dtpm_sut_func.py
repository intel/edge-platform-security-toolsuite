# Copyright 2026 Intel Corporation
# SPDX-License-Identifier: Apache-2.0

"""
TEST — IEC 62443-4-2  dTPM  (discrete TPM, measured boot, SUT-ONLY)

Test ID:  IEC62443-4-2-TC_dTPM-FUNC-SUT
Suite:    measured_boot

PURPOSE
-------
SUT-only variant of test_ec62443_dtpm_func.py.  Verifies a discrete TPM (dTPM)
measured-boot configuration by running pytest DIRECTLY ON THE SUT — no external
NUC controller, no SSH.

Unlike the NUC variant (test_ec62443_dtpm_func.py):
  - Runs pytest directly on the SUT
  - Uses systemd (fw-validation-resume.service) to survive cold reboots
  - Uses subprocess instead of os_manager / security fixtures
  - Runs bios_scripts/checkquote.sh straight from this repo checkout

The discrete TPM is identified by its TPM2_PT_MANUFACTURER value — any TPM
whose manufacturer is NOT Intel ("INTC") is treated as dTPM (IFX, STM, NTC …).
PCRs are collected via TPM attestation (checkquote.sh: RSA quote +
cryptographic verification) on PCRs 0-9 in the SHA256 bank.

PHASES
------
  Phase 0 (first run):
    - Step 2.0  Verify scripts exist on SUT filesystem
    - Step 3.0  Verify UEFI Secure Boot enabled
    - Step 4.1  Assert dTPM (manufacturer != INTC)
    - Step 4.2  Assert active PCR bank == SHA256
    - Step 8.0  Load TPM driver
    - Step 9.1  Verify /dev/tpm0 present
    - Step 9.0  Run checkquote.sh → TPM-attested PCR 0-9 quote → save snapshot (logs/sut_state)
    - Reboot → Phase 1

  Phase N  (1 to ITERATIONS-2, resumed by systemd):
    - Steps 8.0, 9.1  Load driver + verify device
    - Step 9.0  Run checkquote.sh → TPM-attested PCR 0-9 quote → save snapshot
    - Reboot → Phase N+1

  Phase ITERATIONS-1  (final, resumed by systemd):
    - Steps 8.0, 9.1  Load driver + verify device
    - Step 9.0  Run checkquote.sh → TPM-attested PCR 0-9 quote → save snapshot
    - Step 13.0 Load all snapshots + compare PCRs across all boots
    - PASS if identical; FAIL if any PCR changed
    - Cleanup

ONE-TIME SETUP (SUT)
--------------------
  See deploy/setup/setup_sut.sh — run once before any SUT-only test.
  fw-validation-resume.service must be installed and enabled.

PRE-TEST (manual)
-----------------
  1.0)  SUT booted to Ubuntu BSP Release OS.
        - IFWI: Bootguard 5 EXTERNAL release — RPSF_SED5 variant.
        - No specific IFWI version is required — any version from the
          current BOM release is acceptable.
        - Example (PTL board):
          ECG_PTL_PR04_B0A1-XXXODCA_RPSF_SED5_11E50692_2026ww01.1.02_BE351556_CRB
        - NOTE: this is the dTPM variant → RPSF_SED5 IFWI.
          The fTPM/PTT variant uses the RPSF_SEP5 IFWI variant instead — do not mix them up.
  2.0)  checkquote.sh + helpers.sh present in bios_scripts/ of this checkout
           (comes with git clone/pull -- no copy step).
  3.0)  Discrete TPM chip physically installed on the board.
  4.0)  Check dTPM configuration in BIOS menu.
  4.1)  Press F2 to enter BIOS menu --> Select "Platform Information" -->
        Read "Current TPM Location" --> "dTPM 2.0".
  4.2)  Press F2 to enter BIOS menu --> Select "TPM EFI Device Manager" -->
        Select "TCG2 Configuration" --> Make sure "Active PCR bank" is SHA256.
  5.0)  Enable UEFI Secure Boot — run ON the SUT (auto-verified at runtime):
          sudo ./deploy/secure_boot/enable_secure_boot.sh   (sign → modules → provision → verify)
        PDF for reference/checking only, not required:
          doc/reference/secure_boot_linux.pdf

CONFIG (measured_boot_config.yaml)
-----------------------------------
  sut_checkquote_script: "bios_scripts/checkquote.sh"   (repo-relative)
  sut_helper_script    : "bios_scripts/helpers.sh"      (repo-relative)
  sut_dtpm_device      : "/dev/tpm0"
  sut_dtpm_tcti        : "device:/dev/tpm0"
  sut_tpm_module_path  : "/usr/lib/modules"
  reboot_iterations    : 5

RUN (on SUT)
------------
  /home/user/Desktop/venv/bin/python3 -m pytest \\
      tests/measured_boot/test_ec62443_dtpm_sut_func.py -v -s \\
      --setup-confirmed --yes
"""

import json
import logging
import re
import subprocess
from pathlib import Path

import pytest

from tests.sut_base_test import SUTBaseTest
from conftest import load_suite_config
from core.prereq import pre_test_check
from core.reboot_plan import entry as reboot_entry

logger = logging.getLogger(__name__)

_BIOS_SCRIPTS = Path(__file__).resolve().parents[2] / "bios_scripts"

# Seconds to let tpm2-abrmd claim the device before reading PCRs
_ABRMD_SETTLE_SECS = 2

# Filename prefix (state folder) for per-iteration PCR snapshots
_SNAPSHOT_PREFIX = "dtpm_pcr_snapshot_"


@pytest.mark.measured_boot
@pytest.mark.manual
class TestEC62443dTPMSUT(SUTBaseTest):
    """
    IEC 62443-4-2 dTPM measured-boot test — SUT-only execution variant.

    Runs pytest directly on the SUT; uses systemd to survive reboots.
    PCR snapshots are stored as JSON in the state folder between phases so the comparison
    can span all ITERATIONS cold boots.
    """

    SUITE   = "measured_boot"
    TEST_ID = "IEC62443-4-2-TC_dTPM-FUNC-SUT"

    @classmethod
    def reboot_plan(cls, config: dict) -> list:
        n = int(load_suite_config(cls.SUITE).get("reboot_iterations", cls.ITERATIONS))
        return [reboot_entry("auto", f"reboot {i} of {n - 1} for the PCR comparison") for i in range(1, n)]

    # Test-definition constants (same on every SUT — override via config YAML)
    PCR_LIST   = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9]
    ITERATIONS = 5
    EXPECTED_BANK = "SHA256"

    PRE_TEST_CHECKLIST = [
        "1.0)  SUT booted to Ubuntu BSP Release OS.",
        "      - IFWI: Bootguard 5 EXTERNAL release — RPSF_SED5 variant.",
        "      - Any version from the current BOM release is acceptable (no",
        "        specific IFWI version is pinned for this test).",
        "      - Example (PTL board):",
        "        ECG_PTL_PR04_B0A1-XXXODCA_RPSF_SED5_11E50692_2026ww01.1.02_BE351556_CRB",
        "      - NOTE: this is the dTPM variant → RPSF_SED5 IFWI.",
        "        The fTPM/PTT variant uses the RPSF_SEP5 IFWI variant instead — do not mix them up.",
        "2.0)  checkquote.sh + helpers.sh present in bios_scripts/ of this checkout",
        "      (comes with git clone/pull -- no copy step). See measured_boot_config.yaml.",
        "3.0)  Discrete TPM chip physically installed on the board.",
        "4.0)  Check dTPM configuration in BIOS menu.",
        "4.1)  Press F2 to enter BIOS menu --> Select \"Platform Information\" -->",
        "      Read \"Current TPM Location\" --> \"dTPM 2.0\".",
        "4.2)  Press F2 to enter BIOS menu --> Select \"TPM EFI Device Manager\" -->",
        "      Select \"TCG2 Configuration\" --> Make sure \"Active PCR bank\" is SHA256.",
        "5.0)  Enable UEFI Secure Boot — run ON the SUT (auto-verified at runtime):",
        "          sudo ./deploy/secure_boot/enable_secure_boot.sh   (sign → modules → provision → verify)",
        "      (PDF for reference/checking only, not required: doc/reference/secure_boot_linux.pdf)",
        "SETUP) fw-validation-resume.service installed + enabled (see deploy/).",
    ]

    def test_ec62443_dtpm_sut_func(
        self,
        request,
        config,
        log_dir,
    ):
        """
        IEC62443-4-2-TC_dTPM-FUNC-SUT

        Multi-phase execution — one cold-boot iteration per phase:
          Phase 0                : pre-checks + measure iteration 1 + reboot
          Phase 1 … ITER-2       : measure iterations 2…N-1 + reboot
          Phase ITER-1 (final)   : measure last iteration + compare all + done
        """
        self._begin()
        cfg = self._load_config(config)
        self._init_state_dir(cfg)

        pre_test_check(request, self.TEST_ID, self.PRE_TEST_CHECKLIST)

        # ------------------------------------------------------------------
        # Config
        # ------------------------------------------------------------------
        dtpm_device   = cfg.get("sut_dtpm_device",     "/dev/tpmrm0")
        dtpm_tcti     = cfg.get("sut_dtpm_tcti",       f"device:{dtpm_device}")
        module_path   = cfg.get("sut_tpm_module_path", "/usr/lib/modules")
        iterations    = int(cfg.get("reboot_iterations", self.ITERATIONS))
        pcr_list      = self.PCR_LIST
        checkquote_sh = cfg.get("sut_checkquote_script", str(_BIOS_SCRIPTS / "checkquote.sh"))
        helper_sh     = cfg.get("sut_helper_script",     str(_BIOS_SCRIPTS / "helpers.sh"))

        logger.info("[Config] checkquote   : %s", checkquote_sh)
        logger.info("[Config] dtpm_device  : %s", dtpm_device)
        logger.info("[Config] dtpm_tcti    : %s", dtpm_tcti)
        logger.info("[Config] iterations   : %d", iterations)
        logger.info("[Config] pcr_list     : %s", pcr_list)

        mgr   = self._state_mgr
        state = mgr.get_state()
        phase = state.get("phase", 0)
        logger.info("[State] phase=%s  state=%s", phase, state)

        # ------------------------------------------------------------------
        # Inner helpers — closures over cfg locals
        # ------------------------------------------------------------------

        def _load_tpm_driver() -> None:
            """Load tpm_tis_spi kernel module (best-effort; already loaded is OK)."""
            try:
                kernel = subprocess.run(
                    ["uname", "-r"], capture_output=True, text=True, timeout=5,
                ).stdout.strip()
                ko_path = (
                    Path(module_path) / kernel
                    / "kernel/drivers/char/tpm/tpm_tis_spi.ko"
                )
                if ko_path.exists():
                    subprocess.run(
                        ["sudo", "insmod", str(ko_path)],
                        capture_output=True, timeout=15,
                    )
                else:
                    subprocess.run(
                        ["sudo", "modprobe", "tpm_tis_spi"],
                        capture_output=True, timeout=15,
                    )
            except Exception as exc:  # noqa: BLE001
                logger.warning("[Step 8.0] TPM driver load warning: %s", exc)

        def _assert_device_present() -> None:
            result = subprocess.run(
                ["ls", dtpm_device],
                capture_output=True, text=True, timeout=10,
            )
            assert result.returncode == 0, (
                f"[Step 9.1] Discrete TPM device {dtpm_device} not found after driver load.\n"
                "  Ensure the dTPM chip is installed and the BIOS has it enabled."
            )
            logger.info("[Step 9.1] [OK] Device present: %s", dtpm_device)

        def _assert_dtpm() -> None:
            """Assert TPM manufacturer is NOT Intel (i.e. not PTT/fTPM)."""
            result = subprocess.run(
                ["sudo", "tpm2_getcap", "properties-fixed", f"--tcti={dtpm_tcti}"],
                capture_output=True, text=True, timeout=30,
            )
            output = result.stdout + result.stderr
            m = re.search(r'TPM2_PT_MANUFACTURER[^"]*"([^"]+)"', output)
            manufacturer = m.group(1).strip() if m else "UNKNOWN"
            logger.info("[Step 4.1] TPM manufacturer reported: %r", manufacturer)
            assert "INTC" not in manufacturer.upper(), (
                f"[Step 4.1] TPM manufacturer is Intel ({manufacturer!r}) — "
                "this is an fTPM/PTT, NOT a discrete dTPM.\n"
                "  BIOS: Platform Information → Current TPM Location must be dTPM 2.0.\n"
                "  Run the fTPM/PTT variant (test_ec62443_ftpm_ptt_func.py) instead."
            )
            logger.info("[Step 4.1] [OK] dTPM confirmed (manufacturer: %s)", manufacturer)

        def _assert_pcr_bank() -> None:
            """Assert SHA256 PCR bank is active."""
            result = subprocess.run(
                ["sudo", "tpm2_getcap", "pcrs", f"--tcti={dtpm_tcti}"],
                capture_output=True, text=True, timeout=30,
            )
            output = result.stdout + result.stderr
            assert "sha256" in output.lower(), (
                f"[Step 4.2] SHA256 PCR bank is not active.\n"
                f"  tpm2_getcap pcrs output:\n{output.strip()}\n"
                "  BIOS: EFI Device Manager → TCG2 Configuration → Active PCR Bank = SHA256"
            )
            logger.info("[Step 4.2] [OK] SHA256 PCR bank active")

        def _save_snapshot(iteration: int, pcrs: dict) -> None:
            snapshot_path = Path(mgr.state_dir) / f"{_SNAPSHOT_PREFIX}{iteration}.json"
            snapshot_path.write_text(
                json.dumps(
                    {"iteration": iteration, "boot_id": self._boot_id(),
                     "pcrs": {str(k): v for k, v in pcrs.items()}},
                    indent=2,
                ),
                encoding="utf-8",
            )
            logger.info("[Snapshot] Saved iteration %d → %s", iteration, snapshot_path)

        def _clear_stale_snapshots() -> None:
            """Remove PCR snapshots left in the state folder by a previous/aborted run.

            Snapshots are only deleted at the end of a fully passing run, so an
            aborted run leaves them behind.  Phase 0 starts a brand-new
            measurement series, so any pre-existing snapshot is stale and must
            not be mixed into the final cross-boot comparison (it would cause a
            false PASS or a false FAIL).  Globbing covers iteration counts
            larger than the current `iterations` value too.
            """
            removed = []
            for p in sorted(Path(mgr.state_dir).glob(f"{_SNAPSHOT_PREFIX}*.json")):
                try:
                    p.unlink()
                    removed.append(p.name)
                except OSError as exc:  # noqa: PERF203
                    logger.warning("[Snapshot] Could not remove stale %s: %s", p, exc)
            if removed:
                logger.info(
                    "[Snapshot] Cleared %d stale snapshot(s) from a previous run: %s",
                    len(removed), ", ".join(removed),
                )

        snapshot_boots: dict = {}

        def _load_all_snapshots() -> dict:
            """Load all per-iteration PCR snapshots from the state folder into a dict."""
            snapshots: dict = {}
            for i in range(1, iterations + 1):
                p = Path(mgr.state_dir) / f"{_SNAPSHOT_PREFIX}{i}.json"
                assert p.exists(), (
                    f"[Step 13.0] PCR snapshot for iteration {i} not found: {p}\n"
                    "  A previous phase did not complete successfully."
                )
                data = json.loads(p.read_text(encoding="utf-8"))
                snapshots[i] = {int(k): v for k, v in data["pcrs"].items()}
                snapshot_boots[i] = data.get("boot_id", "")
            logger.info("[Snapshots] Loaded %d PCR snapshots", len(snapshots))
            return snapshots

        def _run_checkquote(iteration: int) -> dict:
            """
            Run checkquote.sh to collect SHA256 PCR 0-9 measurements via TPM
            attestation (RSA quote + cryptographic verification) against the
            discrete TPM device.

            checkquote.sh does not hardcode a TPM device path — it relies
            entirely on the TPM2TOOLS_TCTI environment variable, which is set
            here to the discrete TPM's TCTI (dtpm_tcti). The same script used
            by the fTPM/PTT SUT test is reused unmodified.

            PCR values are parsed from the RSA tpm2 quote YAML output, which is
            delimited by TPM2_QUOTE_RSA_OUTPUT_BEGIN/END markers emitted by
            checkquote.sh.  The full script output is saved to dTPM_PCR_ALL_{n}.log.

            Returns:
                dict mapping PCR index (int) → hex string (lower-case).
            Raises:
                AssertionError if checkquote.sh fails or PCRs cannot be parsed.
            """
            logger.info("[Step 9.0] Collecting SHA256 PCRs via checkquote.sh (iteration %d)",
                        iteration)
            result = subprocess.run(
                # Absolute bash path: sudoers NOPASSWD matches args literally
                # ("env TPM2TOOLS_TCTI=* /usr/bin/bash *"); bare "bash" falls
                # through to a password prompt and fails under the resume service.
                ["sudo", "env", f"TPM2TOOLS_TCTI={dtpm_tcti}", "/usr/bin/bash", checkquote_sh],
                capture_output=True, text=True, timeout=300,
            )
            combined = result.stdout + result.stderr
            local_log = log_dir / f"dTPM_PCR_ALL_{iteration}.log"
            local_log.write_text(combined, encoding="utf-8", errors="replace")
            assert result.returncode == 0, (
                f"[Step 9.0] checkquote.sh failed (rc={result.returncode}) — "
                f"PCR measurements could not be collected.\n"
                f"  Log: {local_log}"
            )
            logger.info("[Step 9.0] checkquote.sh OK → %s", local_log)

            # Parse PCR 0-9 SHA256 values from the RSA tpm2 quote YAML output.
            quote_block_m = re.search(
                r"=== TPM2_QUOTE_RSA_OUTPUT_BEGIN ===\n(.*?)=== TPM2_QUOTE_RSA_OUTPUT_END ===",
                combined,
                re.DOTALL,
            )
            assert quote_block_m, (
                f"[Step 9.0] TPM2_QUOTE_RSA_OUTPUT markers not found in checkquote.sh output.\n"
                f"  Log: {local_log}"
            )
            quote_block = quote_block_m.group(1)
            pcrs: dict = {}
            in_sha256 = False
            for line in quote_block.splitlines():
                if re.match(r"\s*sha256\s*:", line):
                    in_sha256 = True
                    continue
                if in_sha256:
                    m = re.match(r"\s+(\d+)\s*:\s*(0x[0-9A-Fa-f]+)", line)
                    if m:
                        idx = int(m.group(1))
                        if idx in pcr_list:
                            pcrs[idx] = m.group(2).lower()
                    elif line.strip() and not line[0].isspace():
                        in_sha256 = False
            missing = [p for p in pcr_list if p not in pcrs]
            assert not missing, (
                f"[Step 9.0] Missing PCRs {missing} in checkquote.sh RSA quote output.\n"
                f"  Log: {local_log}"
            )
            for idx in pcr_list:
                logger.info("[Step 9.0]   PCR[%02d] = %s", idx, pcrs[idx])
            return pcrs

        # ------------------------------------------------------------------
        # Main loop — one block per phase / per boot iteration
        # Each phase_target corresponds to iteration = phase_target + 1.
        # ------------------------------------------------------------------
        for phase_target in range(iterations):
            if phase != phase_target:
                continue

            iteration = phase_target + 1
            logger.info("=" * 60)
            logger.info("PHASE %d — PCR measurement iteration %d / %d",
                        phase_target, iteration, iterations)
            logger.info("=" * 60)

            # Acknowledge the OS-phase reboot that brought us here
            if phase_target > 0:
                mgr.mark_phase_done(phase_target)

            # -------------------------------------------------------
            # Phase 0 only: pre-checks + dTPM assertion + script setup
            # -------------------------------------------------------
            if phase_target == 0:
                # Discard snapshots from any previous/aborted run before
                # starting a fresh measurement series.
                _clear_stale_snapshots()

                # Step 3.0 — UEFI Secure Boot
                logger.info("[Step 3.0] Verifying UEFI Secure Boot enabled")
                sb_result = subprocess.run(
                    ["mokutil", "--sb-state"],
                    capture_output=True, text=True, timeout=15,
                )
                assert "SecureBoot enabled" in sb_result.stdout, (
                    "[Step 3.0] Secure Boot is NOT enabled on the SUT.\n"
                    f"  mokutil output: {sb_result.stdout.strip()!r}\n"
                    "  Run the enable script ON the SUT, then re-run this test:\n"
                    "    sudo ./deploy/secure_boot/enable_secure_boot.sh sign       # reboot + enroll MOK at blue screen\n"
                    "    sudo ./deploy/secure_boot/enable_secure_boot.sh modules    # auto-reboots\n"
                    "    sudo ./deploy/secure_boot/enable_secure_boot.sh provision  # auto-reboots\n"
                    "    sudo ./deploy/secure_boot/enable_secure_boot.sh verify"
                )
                logger.info("[Step 3.0] [OK] Secure Boot enabled")

                # Step 2.0 — Scripts present in the checkout
                logger.info("[Step 2.0] Verifying scripts in bios_scripts/")
                for script in (checkquote_sh, helper_sh):
                    assert Path(script).exists(), (
                        f"[Step 2.0] Script not found: {script}\n"
                        "  It ships in bios_scripts/ -- check the checkout (git status / git pull)."
                    )
                logger.info("[Step 2.0] [OK] Scripts ready: %s", Path(checkquote_sh).parent)

            # -------------------------------------------------------
            # Every phase: load driver → verify device → collect PCRs
            # -------------------------------------------------------
            logger.info("[Step 8.0] Loading TPM driver (tpm_tis_spi)")
            _load_tpm_driver()

            logger.info("[Step 9.1] Verifying discrete TPM device %s", dtpm_device)
            _assert_device_present()

            # Phase 0 only: assert dTPM manufacturer + PCR bank
            if phase_target == 0:
                logger.info("[Step 4.1] Verifying dTPM (non-Intel manufacturer)")
                _assert_dtpm()

                logger.info("[Step 4.2] Verifying active PCR bank == %s", self.EXPECTED_BANK)
                _assert_pcr_bank()

            # Step 9.0 — Collect PCR measurements via checkquote.sh
            pcrs = _run_checkquote(iteration)
            _save_snapshot(iteration, pcrs)

            # -------------------------------------------------------
            # Reboot to next phase, or fall through to comparison
            # -------------------------------------------------------
            if phase_target < iterations - 1:
                logger.info(
                    "[Phase %d] Iteration %d done — rebooting for iteration %d of %d",
                    phase_target, iteration, iteration + 1, iterations,
                )
                self._reboot_os_phase(
                    phase=phase_target + 1,
                    step_label=f"phase{phase_target}_to_phase{phase_target + 1}",
                )
                # ← does not return; systemd resumes at next phase

        # ------------------------------------------------------------------
        # FINAL — Step 13.0: Compare PCRs across all iterations
        # ------------------------------------------------------------------
        # Reached only when phase == iterations - 1 (all iterations complete).
        logger.info("=" * 60)
        logger.info("FINAL PHASE — Step 13.0: Compare PCRs across %d boots", iterations)
        logger.info("=" * 60)

        snapshots = _load_all_snapshots()
        assert len(snapshots) == iterations, (
            f"Expected {iterations} PCR snapshots in {mgr.state_dir}, found {len(snapshots)}.\n"
            "  One or more phases did not complete."
        )
        self._assert_distinct_boots(snapshot_boots, step_label="13.0")

        mismatches = []
        for idx in pcr_list:
            values = {i: snapshots[i][idx] for i in snapshots}
            consistent = len(set(values.values())) == 1
            logger.info(
                "  PCR[%02d]: %s", idx,
                "MATCH" if consistent else f"MISMATCH {values}",
            )
            if not consistent:
                mismatches.append((idx, values))

        assert not mismatches, (
            "[Step 13.0] PCR values changed across cold boots "
            "(measured-boot chain is NOT stable):\n"
            + "\n".join(f"  PCR[{idx}] → {vals}" for idx, vals in mismatches)
            + "\n\nNote: PCR 10 is intentionally excluded from PCR_LIST (IMA changes it)."
        )

        logger.info("=" * 60)
        logger.info(
            "%s: PASSED — PCRs %s identical across %d cold boots",
            self.TEST_ID, pcr_list, iterations,
        )
        logger.info("=" * 60)

        # Cleanup snapshot files
        for i in range(1, iterations + 1):
            p = Path(mgr.state_dir) / f"{_SNAPSHOT_PREFIX}{i}.json"
            if p.exists():
                p.unlink()
        mgr.cleanup()
