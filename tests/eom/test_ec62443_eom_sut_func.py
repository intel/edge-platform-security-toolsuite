# Copyright 2026 Intel Corporation
# SPDX-License-Identifier: Apache-2.0

"""
TEST — IEC 62443-4-2  EOM (End of Manufacturing)  (SUT-only execution)

Test ID:  IEC62443-4-2-TC_EOM-FUNC-SUT
Suite:    eom

PURPOSE
-------
Verifies that the End of Manufacturing (EOM) process completes correctly by
running entirely ON the SUT (no external NUC controller required):
  1. Running Fpt.efi -closemnfy in UEFI shell to trigger EOM close
  2. Running MEInfo.efi -FEAT "End Of Manufacturing" to confirm:
       NVAR Configuration State == Locked
       Flash Protection Mode    == Protected

!! WARNING !!
  Ensure HW Binding is DISABLED in the IFWI before running this test.
  Running EOM with HW Binding enabled permanently burns fuses and the
  action CANNOT be reversed.

  (Note: QS sample silicon should be used for this test)

Unlike the NUC variant (test_ec62443_eom_func.py) which controls the SUT
via SSH + serial from an external NUC, this test:
  - Runs pytest directly on the SUT
  - Uses startup.nsh + systemd to survive reboots into UEFI shell
  - Requires Fpt.efi and MEInfo.efi to be pre-staged on the SUT EFI partition

PHASES
------
  Phase 0 (OS):
    - Pre-checks (Fpt.efi + MEInfo.efi present on EFI partition)
    - Write Fpt.efi UEFI script → reboot into UEFI shell

  UEFI Phase 1 (automated via startup.nsh):
    - cd EFI
    - Fpt.efi -closemnfy -y  (auto-confirm; SUT auto-reboots after EOM close)
    NOTE: Because Fpt causes an immediate system reset, state_done.txt is NOT
          written. The test detects Phase 1 completion by the phase number
          in state.json (written before the reboot).

  Phase 1 (OS, resumed by systemd):
    - Write MEInfo.efi UEFI script → reboot into UEFI shell

  UEFI Phase 2 (automated via startup.nsh):
    - cd EFI
    - MEInfo.efi -FEAT "End Of Manufacturing" >a eom_meinfo_result.txt
    - Write state_done.txt → reset → boot OS

  Phase 2 (OS, resumed by systemd):
    - Verify MEInfo output:
        NVAR Configuration State == Locked
        Flash Protection Mode    == Protected
    - Cleanup + PASS

ONE-TIME SETUP (SUT)
--------------------
  1) startup.nsh on EFI partition:     /boot/efi/startup.nsh (see deploy/resume/startup.nsh)
  2) fw-validation-resume.service:     deploy/resume/fw-validation-resume.service
  3) Fpt.efi on EFI partition:         /boot/efi/EFI/Fpt.efi
  4) MEInfo.efi on EFI partition:      /boot/efi/EFI/MEInfo.efi

CONFIG
------
  config/suites/eom_config.yaml  — tool names, UEFI dir, expected EOM values
  config/test_config.yaml        — global settings

PRE-TEST (manual, performed once before running)
------------------------------------------------
  1.0) Flash IFWI (HW Binding DISABLED) and deploy Ubuntu custom image to SUT.
       - IFWI: Bootguard 5 (BtG5) EXTERNAL release — RPSF_SEP5 or RPSF_SED5 variant.
       - Any version from the current BOM release is acceptable.
       - Example (PTL board):
         ECG_PTL_PR04_B0A1-XXXODCA_RPSF_SEP5_11E50692_2026ww01.1.02_BE351556_CRB.bin
  2.0) Power ON the SUT and boot to Ubuntu OS.
  3.0) Copy Fpt.efi to SUT EFI partition:
         sudo cp Fpt.efi /boot/efi/EFI/
  4.0) Copy MEInfo.efi to SUT EFI partition:
         sudo cp MEInfo.efi /boot/efi/EFI/
  5.0) startup.nsh present at /boot/efi/startup.nsh (see deploy/resume/startup.nsh).
  6.0) fw-validation-resume.service installed + enabled (see deploy/).

RUN (on SUT)
------------
  python -m pytest tests/eom/test_ec62443_eom_sut_func.py -v -s --setup-confirmed --yes
"""

import logging
from pathlib import Path

import pytest

from tests.sut_base_test import SUTBaseTest
from core.prereq import pre_test_check

logger = logging.getLogger(__name__)

# Result file written by UEFI shell to EFI partition
EOM_RESULT_FILE = "eom_meinfo_result.txt"


@pytest.mark.eom
@pytest.mark.manual
class TestEC62443EOMFuncSUT(SUTBaseTest):
    """
    IEC 62443-4-2 End of Manufacturing functional test — SUT-only execution variant.

    Uses startup.nsh + systemd instead of NUC serial/SSH control.
    Fpt.efi and MEInfo.efi must be pre-staged on the SUT EFI partition.
    """

    SUITE   = "eom"
    TEST_ID = "IEC62443-4-2-TC_EOM-FUNC-SUT"

    REBOOTS = (
        ("auto", "UEFI Shell: Fpt.efi -closemnfy closes manufacturing mode, the SUT resets by itself"),
        ("auto", "UEFI Shell: MEInfo.efi reads the post-EOM state, then back to Ubuntu"),
    )

    PRE_TEST_CHECKLIST = [
        "!! WARNING: Ensure HW Binding is DISABLED in IFWI before running !!",
        "           Running EOM with HW Binding enabled permanently burns fuses.",
        "           (Note: QS sample silicon should be used for this test)",
        "",
        "1.0)  Flash IFWI (HW Binding disabled) and deploy Ubuntu custom image.",
        "      - IFWI: Bootguard 5 (BtG5) EXTERNAL release — RPSF_SEP5 or RPSF_SED5 variant.",
        "      - Any version from the current BOM release is acceptable (no",
        "        specific IFWI version is pinned for this test).",
        "      - Example (PTL board):",
        "        ECG_PTL_PR04_B0A1-XXXODCA_RPSF_SEP5_11E50692_2026ww01.1.02_BE351556_CRB.bin",
        "2.0)  Power ON SUT and boot to Ubuntu OS.",
        "3.0)  Fpt.efi present on SUT EFI partition (see eom_config.yaml: fpt_efi_name).",
        "4.0)  MEInfo.efi present on SUT EFI partition (see eom_config.yaml: meinfo_efi_name).",
        "SETUP) startup.nsh present at /boot/efi/startup.nsh (see deploy/resume/startup.nsh).",
        "SETUP) fw-validation-resume.service installed + enabled (see deploy/).",
    ]

    # ------------------------------------------------------------------
    # Entry point
    # ------------------------------------------------------------------

    def test_ec62443_eom_sut_func(
        self,
        request,
        config,
        log_dir,
    ):
        """
        IEC62443-4-2-TC_EOM-FUNC-SUT

        Multi-phase execution:
          Phase 0 : pre-checks + write Fpt.efi UEFI script + reboot into UEFI shell
          UEFI 1  : Fpt.efi -closemnfy (SUT auto-reboots; state_done.txt not written)
          Phase 1 : write MEInfo.efi UEFI script + reboot into UEFI shell
          UEFI 2  : MEInfo.efi EOM check + write result file
          Phase 2 : verify MEInfo output + cleanup
        """
        self._begin()
        cfg = self._load_config(config)
        self._init_state_dir(cfg)

        pre_test_check(request, self.TEST_ID, self.PRE_TEST_CHECKLIST)

        # ------------------------------------------------------------------
        # Config
        # ------------------------------------------------------------------
        uefi_tool_dir   = cfg.get("uefi_tool_dir",    "EFI")
        fpt_efi_name    = cfg.get("fpt_efi_name",     "Fpt.efi")
        meinfo_efi_name = cfg.get("meinfo_efi_name",  "MEInfo.efi")
        boot_timeout    = int(cfg.get("boot_timeout", 180))

        logger.info("[Config] uefi_tool_dir   : %s", uefi_tool_dir)
        logger.info("[Config] fpt_efi_name    : %s", fpt_efi_name)
        logger.info("[Config] meinfo_efi_name : %s", meinfo_efi_name)
        logger.info("[Config] boot_timeout_s  : %d", boot_timeout)

        efi_dir = Path(cfg.get("sut_efi_mount", "/boot/efi")) / uefi_tool_dir

        mgr   = self._state_mgr
        self._remove_at_test_end(mgr.efi_mount / EOM_RESULT_FILE, efi_dir / EOM_RESULT_FILE)
        state = mgr.get_state()
        phase = state.get("phase", 0)
        logger.info("[State] phase=%s  state=%s", phase, state)

        # ------------------------------------------------------------------
        # PHASE 0 — Pre-checks + write Fpt.efi UEFI script
        # ------------------------------------------------------------------
        if phase == 0:
            logger.info("=" * 60)
            logger.info("PHASE 0 — Pre-checks + Fpt.efi UEFI script")
            logger.info("=" * 60)

            # Step 3.0 — Verify Fpt.efi and MEInfo.efi are on EFI partition
            self._step_verify_efi_tools(cfg, step_label="3.0")

            # Step 3.1 — Pick signed/original tools per Secure Boot state.
            # MEInfo is resolved here too so a missing signed copy fails
            # before the irreversible EOM close.
            fpt_run = self._select_efi_tool(efi_dir, fpt_efi_name, step_label="3.1")
            self._select_efi_tool(efi_dir, meinfo_efi_name, step_label="3.1")

            # Step 5.0 — Write UEFI script for Fpt.efi -closemnfy
            logger.info("[Step 5.0] Writing Fpt.efi -closemnfy UEFI script")
            # NOTE: Fpt.efi -closemnfy causes an immediate system reset after
            # the user confirms Y (or via -y flag). state_done.txt will NOT be
            # written because the system resets before maintest.nsh can continue.
            # Phase 1 is identified from state.json (written here, before reboot).
            uefi_commands = [
                f"cd {uefi_tool_dir}",
                f"{fpt_run} -closemnf -y",
                # The two lines below run only if Fpt does NOT auto-reset
                # (some firmware versions require manual reboot after EOM close).
                # cd back to EFI root so state_done.txt is written at \ (EFI root),
                # which is where is_phase_done() looks for it.
                "cd \\",
                f"echo phase=1 status=fpt_done > state_done.txt",
            ]
            self._write_uefi_phase(
                phase=1,
                uefi_commands=uefi_commands,
                result_filename=None,
                step_label="5.0",
            )
            logger.info("[Step 5.0] Rebooting into UEFI shell for Fpt.efi -closemnfy ...")
            self._reboot_into_uefi(step_label="5.0")
            # ← does not return; systemd resumes at Phase 1

        # ------------------------------------------------------------------
        # PHASE 1 — Write MEInfo.efi UEFI script + reboot
        # ------------------------------------------------------------------
        if phase == 1:
            logger.info("=" * 60)
            logger.info("PHASE 1 — MEInfo.efi UEFI script")
            logger.info("=" * 60)

            # Fpt.efi causes an immediate system reset after EOM close,
            # so state_done.txt may not exist. We proceed regardless — if
            # state.json shows phase=1, UEFI Phase 1 was initiated.
            if mgr.is_phase_done():
                logger.info("[Step 5.1] state_done.txt found — Fpt completed without auto-reset")
                mgr.mark_phase_done(1)
            else:
                logger.info(
                    "[Step 5.1] state_done.txt not found — expected: "
                    "Fpt.efi -closemnfy triggered an immediate system reset "
                    "(this is normal behaviour). Proceeding to MEInfo phase."
                )
                # Clear any stale pending state, advance to phase 1 done
                mgr._write_state(1, "done")

            # Step 6.0 — Write UEFI script for MEInfo.efi EOM check
            # NOTE: MEInfo.efi runs inside the EFI subdirectory, so the result
            # file lands in EFI\eom_meinfo_result.txt. We copy it back to the
            # EFI root (\) so _read_uefi_result() can find it at /boot/efi/.
            logger.info("[Step 6.0] Writing MEInfo.efi EOM check UEFI script")
            meinfo_run = self._select_efi_tool(efi_dir, meinfo_efi_name, step_label="6.0")
            uefi_commands = [
                f"cd {uefi_tool_dir}",
                f'{meinfo_run} -FEAT "End Of Manufacturing" >a {EOM_RESULT_FILE}',
                "cd \\",
                f"copy {uefi_tool_dir}\\{EOM_RESULT_FILE} {EOM_RESULT_FILE}",
            ]
            self._write_uefi_phase(
                phase=2,
                uefi_commands=uefi_commands,
                result_filename=EOM_RESULT_FILE,
                step_label="6.0",
            )
            logger.info("[Step 6.0] Rebooting into UEFI shell for MEInfo.efi EOM check ...")
            self._reboot_into_uefi(step_label="6.0")
            # ← does not return; systemd resumes at Phase 2

        # ------------------------------------------------------------------
        # PHASE 2 — Verify MEInfo EOM output + done
        # ------------------------------------------------------------------
        logger.info("=" * 60)
        logger.info("PHASE 2 — Verify MEInfo EOM output")
        logger.info("=" * 60)

        # Step 6.1 — Verify UEFI MEInfo phase completed
        assert self._check_phase_done(phase=2, step_label="6.1"), (
            "[Step 6.1] UEFI MEInfo phase did not complete.\n"
            f"  Check EFI partition: /boot/efi/state_done.txt\n"
            f"  Check: {mgr.state_dir}/state_done.txt"
        )
        mgr.mark_phase_done(2)

        # Step 6.2 — Read MEInfo EOM result
        eom_raw = self._step_read_eom_result(step_label="6.2")

        # Step 6.3 — Verify EOM fields
        self._step_verify_eom(eom_raw, cfg, log_dir, step_label="6.3")

        mgr.cleanup()
        logger.info("[OK] EOM verified — NVAR Configuration State Locked, Flash Protection Protected")
        self._end()

    # ------------------------------------------------------------------
    # Step helpers
    # ------------------------------------------------------------------

    def _step_verify_efi_tools(self, cfg: dict, step_label: str = "") -> None:
        """Step 3.0: Verify Fpt.efi and MEInfo.efi are present on the SUT EFI partition."""
        prefix = f"[Step {step_label}]" if step_label else "[Pre-check]"
        efi_mount       = cfg.get("sut_efi_mount",    "/boot/efi")
        uefi_tool_dir   = cfg.get("uefi_tool_dir",    "EFI")
        fpt_efi_name    = cfg.get("fpt_efi_name",     "Fpt.efi")
        meinfo_efi_name = cfg.get("meinfo_efi_name",  "MEInfo.efi")

        # Build Linux path directly: /boot/efi/EFI — do NOT use _uefi_path_to_linux
        # here because that function strips the leading "EFI" segment (it maps UEFI
        # paths like "EFI\TPM2Prov\" to "/boot/efi/TPM2Prov/"). The EOM tools live
        # inside the EFI subdirectory (/boot/efi/EFI/), so we construct the path
        # as efi_mount / uefi_tool_dir.
        efi_dir = Path(efi_mount) / uefi_tool_dir

        logger.info("%s Verifying EOM tools on EFI partition: %s", prefix, efi_dir)

        fpt_path = efi_dir / fpt_efi_name
        assert fpt_path.exists(), (
            f"{prefix} {fpt_efi_name} not found: {fpt_path}\n"
            f"  Copy it: sudo cp {fpt_efi_name} {efi_dir}/"
        )
        logger.info("%s [OK] %s", prefix, fpt_path)

        meinfo_path = efi_dir / meinfo_efi_name
        assert meinfo_path.exists(), (
            f"{prefix} {meinfo_efi_name} not found: {meinfo_path}\n"
            f"  Copy it: sudo cp {meinfo_efi_name} {efi_dir}/"
        )
        logger.info("%s [OK] %s", prefix, meinfo_path)

        logger.info("%s [OK] All EOM tools present on EFI partition", prefix)

    def _step_read_eom_result(self, step_label: str = "") -> str:
        """Step 6.2: Read the MEInfo EOM result file written by the UEFI shell."""
        prefix = f"[Step {step_label}]" if step_label else "[EOM Result]"
        logger.info("%s Reading MEInfo EOM result: %s", prefix, EOM_RESULT_FILE)
        eom_raw = self._read_uefi_result(EOM_RESULT_FILE, step_label=step_label)
        assert eom_raw, (
            f"{prefix} MEInfo result file is empty or missing: {EOM_RESULT_FILE}\n"
            f"  Check EFI partition: /boot/efi/{EOM_RESULT_FILE}"
        )
        return eom_raw

    def _step_verify_eom(
        self,
        eom_raw: str,
        cfg: dict,
        log_dir: Path,
        step_label: str = "",
    ) -> None:
        """Step 6.3: Parse MEInfo EOM output and verify NVAR state + Flash protection."""
        prefix = f"[Step {step_label}]" if step_label else "[EOM Verify]"

        # Save artifact
        log_file = log_dir / "meinfo_end_of_manufacturing.log"
        log_file.write_text(eom_raw, encoding="utf-8", errors="replace")
        logger.info("%s Artifact saved: %s", prefix, log_file)

        for line in eom_raw.splitlines():
            logger.info("    %s", line)

        exp_nvar  = cfg.get("expected_nvar_config_state",     "Locked")
        exp_flash = cfg.get("expected_flash_protection_mode", "Protected")

        actual_nvar  = self._parse_meinfo_field(eom_raw, "NVAR Configuration State", multiword=True)
        actual_flash = self._parse_meinfo_field(eom_raw, "Flash Protection Mode",    multiword=True)

        assert actual_nvar, (
            f"{prefix} 'NVAR Configuration State' not found in MEInfo output.\n"
            f"  Check artifact: {log_file}"
        )
        assert actual_flash, (
            f"{prefix} 'Flash Protection Mode' not found in MEInfo output.\n"
            f"  Check artifact: {log_file}"
        )

        assert actual_nvar.lower() == exp_nvar.lower(), (
            f"{prefix} NVAR Configuration State mismatch.\n"
            f"  Expected : {exp_nvar}\n"
            f"  Actual   : {actual_nvar}\n"
            f"  Check artifact: {log_file}"
        )
        logger.info("%s [OK] NVAR Configuration State = %s", prefix, actual_nvar)

        assert actual_flash.lower() == exp_flash.lower(), (
            f"{prefix} Flash Protection Mode mismatch.\n"
            f"  Expected : {exp_flash}\n"
            f"  Actual   : {actual_flash}\n"
            f"  Check artifact: {log_file}"
        )
        logger.info("%s [OK] Flash Protection Mode = %s", prefix, actual_flash)

        logger.info("%s [OK] EOM verification passed", prefix)
