# Copyright 2026 Intel Corporation
# SPDX-License-Identifier: Apache-2.0

"""
TEST — IEC 62443-4-2  BIOS FW Capsule Update  (functional, SUT-only execution)

Test ID:  IEC62443-4-2-TC_BIOS_FW_Capsule_Update-FUNC-SUT
Suite:    firmware

PURPOSE
-------
Verifies the BIOS firmware capsule update flow end-to-end using CapsuleApp.efi
inside the UEFI Shell, executed DIRECTLY FROM THE SUT without a NUC controller.

Unlike the NUC-SUT variant (test_ec62443_bios_fw_capsule_update_func.py) which
uses serial to interact with the UEFI shell in real-time, this test uses:
  - startup.nsh (EFI partition) to auto-launch maintest.nsh (EFI partition)
  - state.json in the state folder (logs/sut_state) to track phase completion across reboots
  - systemd to auto-resume pytest after each reboot

PHASES
------
  Phase 0 (OS):
    - Read BIOS version BEFORE capsule update (store in state)
    - Verify capsule + CapsuleApp.efi present on SUT EFI partition
    - Write UEFI script (maintest.nsh) to EFI partition
    - Reboot into UEFI shell → pytest exits; systemd resumes

  UEFI Phase 1 (automated via startup.nsh):
    - cd EFI
    - CapsuleApp.efi <capsule_file> >a capsule_update_result.txt
    - Write state_done.txt → reset → boot OS

  Phase 1 (OS, resumed by systemd):
    - Verify UEFI phase completed (state_done.txt present)
    - Read capsule_update_result.txt from EFI partition, replay into log
    - Read BIOS version AFTER capsule update via dmidecode
    - Compare before/after versions: must be different for PASS
    - Cleanup + PASS

AUTOMATION / MANUAL split
--------------------------
  Pre-test steps 2.0–5.0  — manual (capsule creation, SUT flash, file transfer)
  Phase 1 + UEFI + Phase 2  — fully automated

ONE-TIME SETUP (SUT)
--------------------
  1) startup.nsh must exist on the EFI partition:
       /boot/efi/startup.nsh
     See: deploy/resume/startup.nsh

  2) The fw-validation-resume systemd service must be installed and enabled:
       sudo ./deploy/setup/setup_sut.sh   (generates + enables it; template:
       deploy/resume/fw-validation-resume.service)

CONFIG
------
  config/suites/firmware_config.yaml  — capsule paths, expected version
  config/test_config.yaml             — global settings

PRE-TEST (manual, performed before running this script)
-------------------------------------------------------
  2.0)  Generate BIOS capsule (.cap) on the Windows THM:
        2.1)  Client Capsule Toolkit downloaded to C:\\ on THM.
        2.2)  Debug BIOS ROM copied into the Toolkit folder.
        2.3)  python FmpCapsuleGen.py bioscap -bios <bios.rom>
        2.4)  Output: a .cap file in the Toolkit's CapsuleOutput\\ folder.
  3.0)  Flash SUT with latest release IFWI and boot to Ubuntu OS.
  4.0)  SUT powered on and booted to Ubuntu.
  5.0)  BIOS capsule (.cap) + CapsuleApp.efi copied to SUT EFI partition:
          sudo cp BIOS_Capsule_Debug.cap /boot/efi/EFI/
          sudo cp CapsuleApp.efi /boot/efi/EFI/

RUN (on SUT)
------------
  python -m pytest tests/firmware/test_ec62443_bios_fw_capsule_update_sut_func.py \\
      -v -s --setup-confirmed --yes
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




@pytest.mark.firmware
@pytest.mark.manual
class TestBIOSFWCapsuleUpdateSUT(SUTBaseTest):
    """
    IEC 62443-4-2 BIOS FW Capsule Update — SUT-only execution variant.

    Uses startup.nsh + systemd instead of NUC serial control.
    """

    SUITE   = "firmware"
    TEST_ID = "IEC62443-4-2-TC_BIOS_FW_Capsule_Update-FUNC-SUT"

    REBOOTS = (
        ("auto", "UEFI Shell: CapsuleApp.efi flashes the BIOS capsule, the SUT resets by itself"),
    )

    PRE_TEST_CHECKLIST = [
        "2.0)  BIOS capsule (.cap) generated on Windows THM via FmpCapsuleGen.py.",
        "3.0)  SUT flashed with latest release IFWI, booted to Ubuntu OS.",
        "4.0)  SUT powered on and running Ubuntu.",
        "5.0)  BIOS capsule (.cap) + CapsuleApp.efi available on SUT (auto-copy can be enabled via config).",
        "SETUP) startup.nsh present at /boot/efi/startup.nsh (see deploy/resume/startup.nsh).",
        "SETUP) fw-validation-resume.service installed + enabled (see deploy/).",
        "SETUP) dmidecode installed on SUT for BIOS version reading (sudo apt install dmidecode).",
    ]

    def test_ec62443_bios_fw_capsule_update_sut_func(
        self,
        request,
        config,
        log_dir,
    ):
        """
        IEC62443-4-2-TC_BIOS_FW_Capsule_Update-FUNC-SUT

        Two-phase execution:
          Phase 0: verify files, write UEFI script, reboot into UEFI shell
          Phase 1: verify UEFI output, confirm new BIOS version
        """
        self._begin()
        cfg = self._load_config(config)
        self._init_state_dir(cfg)

        pre_test_check(request, self.TEST_ID, self.PRE_TEST_CHECKLIST)

        # ------------------------------------------------------------------
        # Config
        # ------------------------------------------------------------------
        capsule_file    = cfg.get("capsule_file",     "BIOS_Capsule_Debug.cap")
        capsule_tool    = cfg.get("capsule_tool_efi", "CapsuleApp.efi")
        uefi_tool_dir   = cfg.get("uefi_tool_dir",    "EFI")

        logger.info("[Config] capsule_file    : %s", capsule_file)
        logger.info("[Config] capsule_tool    : %s", capsule_tool)
        logger.info("[Config] uefi_tool_dir   : %s", uefi_tool_dir)

        mgr   = self._state_mgr
        self._remove_at_test_end(mgr.state_dir / "bios_version_before.txt")
        state = mgr.get_state()
        phase = state.get("phase", 0)
        logger.info("[State] phase=%s  state=%s", phase, state)

        # ------------------------------------------------------------------
        # PHASE 0 — Pre-checks + write UEFI script + reboot
        # ------------------------------------------------------------------
        if phase == 0:
            logger.info("=" * 60)
            logger.info("PHASE 0 — Read BIOS version + verify files + reboot")
            logger.info("=" * 60)

            # Step 4.0 — Read BIOS version BEFORE capsule update
            bios_version_before = self._step_read_bios_version_before(step_label="4.0")
            self._write_bios_version_before(mgr, bios_version_before, step_label="4.0")

            # Step 5.0 — Verify capsule + CapsuleApp.efi on EFI partition
            efi_dir = self._step_verify_efi_tools(cfg, step_label="5.0")
            capsule_tool_run = self._select_efi_tool(efi_dir, capsule_tool, step_label="5.1")

            # Step 5.5 — Ensure startup.nsh and UEFI shell entry are ready
            self._step_prepare_startup(cfg, step_label="5.5")

            # Step 6.0 — Write UEFI shell script
            # NOTE: CapsuleApp.efi triggers an automatic system reset after
            # applying the capsule, so state_done.txt can never be written
            # by the script.  skip_completion_marker=True omits that block
            # and the trailing `reset`; the OS resume relies on state.json
            # (phase=1, status=pending) written before the reboot.
            logger.info("[Step 6.0] Writing CapsuleApp.efi UEFI script")
            self._write_uefi_phase(
                phase=1,
                uefi_commands=[
                    f"cd {uefi_tool_dir}",
                    f"{capsule_tool_run} {capsule_file}",
                ],
                step_label="6.0",
                skip_completion_marker=True,
            )
            logger.info("[Step 6.0] Rebooting into UEFI shell for capsule update ...")
            self._reboot_into_uefi(step_label="6.0")
            # ← does not return; systemd resumes at Phase 1

        # ------------------------------------------------------------------
        # PHASE 1 — Verify UEFI result + BIOS version
        # ------------------------------------------------------------------
        logger.info("=" * 60)
        logger.info("PHASE 1 — Verify capsule update result + BIOS version")
        logger.info("=" * 60)

        # Step 7.0 — CapsuleApp.efi auto-reboots after flashing, so
        # state_done.txt is never written.  Phase detection relies on
        # state.json (phase=1, status=pending) written before the UEFI reboot.
        logger.info(
            "[Step 7.0] CapsuleApp.efi triggers auto-reboot — "
            "state_done.txt not expected; resuming based on state.json phase=%d",
            phase,
        )
        logger.info("[Step 7.0] [OK] Capsule UEFI phase 1 resumed after auto-reboot")
        mgr.mark_phase_done(1)

        # Step 8.0 — Read new BIOS version after capsule update
        bios_version_after = self._step_read_bios_version_after(step_label="8.0")

        # Step 9.0 — Compare before/after versions; must be different
        bios_version_before = self._read_bios_version_before(mgr, step_label="9.0")
        self._step_verify_bios_version_changed(
            bios_version_before,
            bios_version_after,
            step_label="9.0",
        )

        self._remove_bios_version_before(mgr)
        mgr.cleanup()
        logger.info("[OK] BIOS capsule update verified — BIOS version changed")
        self._end()

    # ------------------------------------------------------------------
    # Step helpers
    # ------------------------------------------------------------------

    def _step_verify_efi_tools(self, cfg: dict, step_label: str = "") -> Path:
        """Step 5.0: Ensure capsule file and CapsuleApp.efi exist on the SUT EFI partition; return that directory."""
        prefix = f"[Step {step_label}]" if step_label else "[Pre-check]"
        efi_mount     = cfg.get("sut_efi_mount", "/boot/efi")
        uefi_tool_dir = cfg.get("uefi_tool_dir", "EFI")
        capsule_file  = cfg.get("capsule_file",     "BIOS_Capsule_Debug.cap")
        capsule_tool  = cfg.get("capsule_tool_efi", "CapsuleApp.efi")
        auto_copy     = self._cfg_bool(cfg.get("auto_copy_to_efi", False))
        force_copy    = self._cfg_bool(cfg.get("force_copy_to_efi", False))
        src_dir       = cfg.get("capsule_source_dir", "")
        tool_src      = cfg.get("capsule_tool_source_path", "")
        capsule_src   = cfg.get("capsule_file_source_path", "")
        efi_dir_cfg   = cfg.get("capsule_files_dir", "") or cfg.get("sut_efi_dir", "")

        cfg.setdefault("sut_efi_mount", efi_mount)
        if efi_dir_cfg:
            efi_dir = Path(efi_dir_cfg)
        else:
            efi_dir = Path(self._uefi_path_to_linux(uefi_tool_dir, efi_mount))

        logger.info("%s EFI destination directory: %s", prefix, efi_dir)

        if auto_copy:
            logger.info("%s Auto-copy to EFI is enabled", prefix)
            self._ensure_efi_dir(efi_dir, prefix)

            copy_map = [
                (capsule_tool, tool_src),
                (capsule_file, capsule_src),
            ]
            for fname, explicit_src in copy_map:
                dest = efi_dir / fname
                if explicit_src:
                    src = Path(explicit_src)
                elif src_dir:
                    src = Path(src_dir) / fname
                else:
                    src = None

                if src is None:
                    logger.info(
                        "%s No source path configured for %s; expecting it already on EFI",
                        prefix,
                        fname,
                    )
                    continue

                assert src.exists(), (
                    f"{prefix} Auto-copy source missing: {src}\n"
                    f"  Set capsule_source_dir / capsule_*_source_path correctly, "
                    f"or copy {fname} manually to {efi_dir}/"
                )

                if not dest.exists() or force_copy:
                    self._copy_to_efi(src, dest, prefix)
                else:
                    logger.info("%s Existing EFI file kept: %s", prefix, dest)

        logger.info("%s Verifying capsule tools on EFI partition: %s", prefix, efi_dir)
        for fname in (capsule_tool, capsule_file):
            path = efi_dir / fname
            assert path.exists(), (
                f"{prefix} Required file missing: {path}\n"
                f"  Copy it: sudo cp {fname} {efi_dir}/"
            )
            logger.info("%s [OK] %s", prefix, path)

        logger.info("%s [OK] All capsule files present on EFI partition", prefix)
        return efi_dir

    @staticmethod
    def _ensure_efi_dir(efi_dir: Path, prefix: str) -> None:
        """Create EFI directory, using sudo fallback when normal mkdir lacks permission."""
        try:
            efi_dir.mkdir(parents=True, exist_ok=True)
            return
        except PermissionError:
            pass

        result = subprocess.run(
            ["sudo", "-n", "mkdir", "-p", str(efi_dir)],
            capture_output=True,
            text=True,
            timeout=20,
        )
        assert result.returncode == 0, (
            f"{prefix} Cannot create EFI directory: {efi_dir}\n"
            "  Grant permissions or run 'sudo -v' before pytest.\n"
            f"  stderr: {result.stderr.strip()}"
        )
        logger.info("%s [OK] EFI directory ready: %s", prefix, efi_dir)

    @staticmethod
    def _copy_to_efi(src: Path, dest: Path, prefix: str) -> None:
        """Copy source file to EFI destination, with sudo fallback for protected mounts."""
        try:
            shutil.copy2(src, dest)
            logger.info("%s [OK] Copied %s -> %s", prefix, src, dest)
            return
        except PermissionError:
            pass

        result = subprocess.run(
            ["sudo", "-n", "cp", "-f", str(src), str(dest)],
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert result.returncode == 0, (
            f"{prefix} Failed to copy {src} -> {dest} with sudo cp.\n"
            "  Grant permissions or run 'sudo -v' before pytest.\n"
            f"  stderr: {result.stderr.strip()}"
        )
        logger.info("%s [OK] Copied %s -> %s (sudo)", prefix, src, dest)

    @staticmethod
    def _cfg_bool(value) -> bool:
        """Parse bool-like config values from YAML strings or booleans."""
        if isinstance(value, bool):
            return value
        if value is None:
            return False
        return str(value).strip().lower() in {"1", "true", "yes", "on"}

    @staticmethod
    def _write_bios_version_before(mgr, bios_version: str, step_label: str = "") -> None:
        """Persist the pre-update BIOS version in the state folder for the resumed phase."""
        prefix = f"[Step {step_label}]" if step_label else "[BIOS Before]"
        path = mgr.state_dir / "bios_version_before.txt"
        SUTBaseTest._write_read_only(path, bios_version + "\n")
        logger.info("%s Saved pre-update BIOS version: %s", prefix, path)

    @staticmethod
    def _read_bios_version_before(mgr, step_label: str = "") -> str:
        """Read the pre-update BIOS version saved before the reboot."""
        prefix = f"[Step {step_label}]" if step_label else "[BIOS Before]"
        path = mgr.state_dir / "bios_version_before.txt"
        assert path.exists(), (
            f"{prefix} Pre-update BIOS version artifact is missing: {path}\n"
            "  The test must start from Phase 0 so the before-update version is captured."
        )
        bios_version = path.read_text(encoding="utf-8").strip()
        logger.info("%s BIOS version (before): %s", prefix, bios_version)
        return bios_version

    @staticmethod
    def _remove_bios_version_before(mgr) -> None:
        """Remove the pre-update BIOS version artifact after successful comparison."""
        path = mgr.state_dir / "bios_version_before.txt"
        try:
            path.unlink()
            logger.info("[Cleanup] Removed pre-update BIOS version artifact: %s", path)
        except FileNotFoundError:
            pass

    def _step_read_bios_version_before(self, step_label: str = "") -> str:
        """Step 4.0: Read current BIOS version before capsule update."""
        prefix = f"[Step {step_label}]" if step_label else "[BIOS Before]"
        logger.info("%s Reading BIOS version BEFORE capsule update", prefix)

        result = subprocess.run(
            ["sudo", "dmidecode", "-s", "bios-version"],
            capture_output=True, text=True, timeout=30,
        )
        bios_ver = result.stdout.strip()
        logger.info("%s BIOS version (before): %s", prefix, bios_ver)

        assert bios_ver, (
            f"{prefix} dmidecode returned empty BIOS version.\n"
            "  Ensure dmidecode is installed: sudo apt install dmidecode"
        )
        return bios_ver

    def _step_read_bios_version_after(self, step_label: str = "") -> str:
        """Step 8.0: Read BIOS version after capsule update."""
        prefix = f"[Step {step_label}]" if step_label else "[BIOS After]"
        logger.info("%s Reading BIOS version AFTER capsule update", prefix)

        result = subprocess.run(
            ["sudo", "dmidecode", "-s", "bios-version"],
            capture_output=True, text=True, timeout=30,
        )
        bios_ver = result.stdout.strip()
        logger.info("%s BIOS version (after): %s", prefix, bios_ver)

        assert bios_ver, (
            f"{prefix} dmidecode returned empty BIOS version.\n"
            "  Ensure dmidecode is installed: sudo apt install dmidecode"
        )
        return bios_ver

    def _step_verify_bios_version_changed(
        self,
        version_before: str,
        version_after: str,
        step_label: str = "",
    ) -> None:
        """Step 9.0: Verify that BIOS version changed after capsule update."""
        prefix = f"[Step {step_label}]" if step_label else "[BIOS Compare]"
        logger.info("%s Comparing BIOS versions before/after capsule update", prefix)
        logger.info("%s BIOS version (before): %s", prefix, version_before)
        logger.info("%s BIOS version (after):  %s", prefix, version_after)

        assert version_before, (
            f"{prefix} BIOS version before capsule update is empty.\n"
            "  Check that UEFI script was executed and system rebooted."
        )

        assert version_after != version_before, (
            f"{prefix} BIOS version UNCHANGED after capsule update.\n"
            f"  Before: {version_before}\n"
            f"  After:  {version_after}\n"
            "  Capsule may have failed to apply; check UEFI log."
        )

        logger.info("%s [OK] BIOS version updated successfully", prefix)

    def _step_prepare_startup(self, cfg: dict, step_label: str = "") -> None:
        """Step 5.5: Verify/deploy startup.nsh and check UEFI shell boot entry."""
        prefix = f"[Step {step_label}]" if step_label else "[Startup]"
        auto_deploy = self._cfg_bool(cfg.get("auto_deploy_startup_nsh", True))
        require_fw_shell = self._cfg_bool(cfg.get("require_fw_validation_shell", False))

        startup_target = Path(cfg.get("startup_nsh_target", "/boot/efi/startup.nsh"))
        startup_source_cfg = cfg.get("startup_nsh_source", "").strip()
        if startup_source_cfg:
            startup_source = Path(startup_source_cfg)
        else:
            startup_source = Path(__file__).resolve().parents[2] / "deploy" / "startup.nsh"

        fw_shell, int_shell = self._detect_shell_boot_entries()
        logger.info("%s FW-Validation Shell boot entry: %s", prefix, fw_shell or "(not found)")
        logger.info("%s Internal UEFI Shell boot entry: %s", prefix, int_shell or "(not found)")
        if require_fw_shell:
            assert fw_shell, (
                f"{prefix} 'FW-Validation Shell' boot entry not found in efibootmgr output.\n"
                "  Create that boot option so startup.nsh auto-runs reliably,\n"
                "  or set require_fw_validation_shell=false to allow fallback."
            )

        has_valid_startup = False
        if startup_target.exists():
            try:
                existing = startup_target.read_text(encoding="utf-8", errors="replace")
                has_valid_startup = "maintest.nsh" in existing
            except OSError:
                has_valid_startup = False

        if has_valid_startup:
            logger.info("%s [OK] startup.nsh already present: %s", prefix, startup_target)
            return

        assert auto_deploy, (
            f"{prefix} startup.nsh missing/invalid at {startup_target}.\n"
            "  Enable auto_deploy_startup_nsh=true, or deploy manually:\n"
            "  sudo cp deploy/resume/startup.nsh /boot/efi/startup.nsh"
        )
        assert startup_source.exists(), (
            f"{prefix} startup.nsh source not found: {startup_source}\n"
            "  Set startup_nsh_source in firmware config to a valid file."
        )

        content = startup_source.read_text(encoding="utf-8", errors="replace")
        self._write_with_sudo(startup_target, content, prefix)
        logger.info("%s [OK] startup.nsh deployed: %s -> %s", prefix, startup_source, startup_target)

    @staticmethod
    def _detect_shell_boot_entries() -> tuple[str, str]:
        """Return (FW-Validation Shell bootnum, Internal UEFI Shell bootnum)."""
        result = subprocess.run(
            ["efibootmgr"],
            capture_output=True,
            text=True,
            timeout=20,
        )
        fw_shell = ""
        int_shell = ""
        for line in result.stdout.splitlines():
            m = re.match(r"Boot([0-9A-Fa-f]{4})\\*?\\s+(.*)", line)
            if not m:
                continue
            num, label = m.group(1), m.group(2)
            if re.search(r"FW-Validation\\s+Shell", label, re.IGNORECASE):
                fw_shell = num
            elif re.search(r"UEFI\\s+Shell", label, re.IGNORECASE):
                int_shell = num
        return fw_shell, int_shell

    @staticmethod
    def _write_with_sudo(target: Path, content: str, prefix: str) -> None:
        """Write file content with sudo tee for root-owned EFI partition paths."""
        normalized = content.replace("\r\n", "\n").replace("\n", "\r\n")
        result = subprocess.run(
            ["sudo", "-n", "tee", str(target)],
            input=normalized,
            capture_output=True,
            text=True,
            timeout=20,
        )
        assert result.returncode == 0, (
            f"{prefix} Failed to write {target} via sudo tee.\n"
            "  Run 'sudo -v' before pytest and ensure /boot/efi is mounted.\n"
            f"  stderr: {result.stderr.strip()}"
        )
