# Copyright 2026 Intel Corporation
# SPDX-License-Identifier: Apache-2.0

"""
TEST — IEC 62443-4-2  Virtualization / VT-d  (SUT-only execution)

Test ID:  IEC62443-4-2-TC_Virtualization_Vtd-FUNC-SUT
Suite:    virtualization

PURPOSE
-------
Verifies that Intel VT-x (VMX) and VT-d are correctly enabled and remain
functional across S3 (sleep), S4 (hibernate), and S5 (shutdown) power-state
transitions by running VTInfo.efi in the UEFI shell after each wake-up.

A run is considered PASSED when:
  - "PASS" keyword appears in the VTInfo.efi output
  - "FAIL" keyword does NOT appear
  - "WARNING" keyword does NOT appear
  - each power state is proven, not assumed (artifact power_state_<s3|s4|s5>.log):
      S3/S4: rtcwake rc=0, same boot_id, CPU stopped (wall - monotonic clock)
             >= wake_secs/2, kernel log shows entry -> "Preparing to enter system
             sleep state S3|S4" -> "Waking up ..." -> exit, in that order
      S5   : new boot_id, the old boot reached poweroff.target (not reboot.target),
             and this boot's kernel started >= 3/4 wake_secs after the power-off

Unlike the NUC variant (test_ec62443_virtualization_vtd_func.py) which controls
the SUT via SSH + serial from an external NUC, this test:
  - Runs pytest directly on the SUT
  - Uses startup.nsh + systemd to survive reboots into UEFI shell
  - Requires VTInfo.efi to be pre-staged on the SUT EFI partition
  - S3 and S4 power cycles are performed in-process (rtcwake returns after wake)
  - S5 requires a reboot phase because the process is killed on power-off

PHASES
------
  Phase 0 (OS):
    - Pre-checks (VTInfo.efi present on EFI partition)
    - BIOS knob check from the OS: VMX, VT-d, Low Power S0 Idle (no prompt)
    - S4 prerequisite: GRUB_CMDLINE_LINUX resume=<swap partition>, or
      resume=UUID=<fs> resume_offset=<n> for a swap file
      (if missing: set it + update-grub + automatic reboot; systemd
      resumes Phase 0 and confirms it in /proc/cmdline)
    - Write baseline UEFI script → reboot into UEFI shell

  UEFI Phase 1 (automated via startup.nsh):
    - cd EFI → VTInfo.efi >a vtinfo_baseline.txt
    - Write state_done.txt → reset → boot OS

  Phase 1 (OS, resumed by systemd):
    - Verify baseline VTInfo result
    - S3 sleep (rtcwake -m mem -s 60) — in-process, then proven (kernel log, boot_id, time off)
    - Write S3 UEFI script → reboot into UEFI shell

  UEFI Phase 2 (automated via startup.nsh):
    - cd EFI → VTInfo.efi >a vtinfo_s3.txt
    - Write state_done.txt → reset → boot OS

  Phase 2 (OS, resumed by systemd):
    - Verify S3 VTInfo result
    - Re-verify /proc/cmdline resume= (+ resume_offset=)
    - S4 hibernate (rtcwake -m disk -s 60) — in-process, then proven (kernel log, boot_id, time off)
    - Write S4 UEFI script → reboot into UEFI shell

  UEFI Phase 3 (automated via startup.nsh):
    - cd EFI → VTInfo.efi >a vtinfo_s4.txt
    - Write state_done.txt → reset → boot OS

  Phase 3 (OS, resumed by systemd):
    - Verify S4 VTInfo result
    - Record boot_id + power-off time (vtd_s5_poweroff.json in the state folder)
    - S5 shutdown (rtcwake -m off -s 90) → OS phase reboot — process exits

  Phase 4 (OS, resumed by systemd after S5 wake):
    - Prove S5: new boot_id, old boot reached poweroff.target, off >= 3/4 wake_secs
    - Write S5 UEFI script → reboot into UEFI shell

  UEFI Phase 4 (automated via startup.nsh):
    - cd EFI → VTInfo.efi >a vtinfo_s5.txt
    - Write state_done.txt → reset → boot OS

  Phase 5 (OS, resumed by systemd):
    - Verify S5 VTInfo result
    - Cleanup + PASS

MANUAL GATES
------------
  None. The BIOS knobs (VMX = Enabled, VT-d = Enabled, Low Power S0 Idle
  Capability = Disabled) come from deploy/bios_knobs/bios_knobs.yaml: the
  test_runner.py pre-flight sets them with AMISCE (AMI BIOS) or lists them for
  BIOS Setup (other BIOS) before the test starts.

  Step 5.0 checks them from the OS and fails at once, naming the knob, if one
  is wrong (for example when pytest is run directly, without the pre-flight):
    - VMX       : MSR 0x3A (IA32_FEATURE_CONTROL) bit 2 = 1
    - VT-d      : ACPI DMAR table present (/sys/firmware/acpi/tables/DMAR)
    - Low Power S0 Idle Disabled : /sys/power/mem_sleep selects [deep], so
                  "rtcwake -m mem" enters real S3, not s2idle

  Step 5.6 — GRUB resume= for S4 (automated, after the knob check):
    S4 resume needs the kernel to boot with resume= pointing at the swap.
    The target is the swap partition ('swap_partition' in config, else the
    first active one from swapon) or, without one, the active swap file
    (e.g. /swap.img): resume=UUID=<its filesystem> resume_offset=<first
    block, from sudo filefrag -v>. A swap file must be at least
    /sys/power/image_size (deploy/setup/setup_sut.sh step 9 grows it to the
    RAM size). No partition is ever created or changed.
    If /proc/cmdline lacks it, the test backs up
    /etc/default/grub to /etc/default/grub.fwval.bak, sets
      GRUB_CMDLINE_LINUX="... resume=/dev/nvme0n1p3"
      (swap file: "... resume=UUID=<uuid> resume_offset=<n>")
    and runs `sudo update-grub`, then reboots automatically (no user
    action). fw-validation-resume.service re-runs Phase 0, which confirms
    the arguments in /proc/cmdline and continues to Step 6.0. If they are
    still missing after that reboot, the test fails (no reboot loop).
    Before each S3/S4 rtcwake, every ACPI wake source except the RTC and
    power button is disabled via /proc/acpi/wakeup (restored after resume),
    so a USB-C/Thunderbolt/USB/LAN device cannot wake the SUT early.
    The sudo calls (cp/tee/update-grub/cat grub.cfg/filefrag/rtcwake) have
    passwordless rules from setup_sut.sh, so the test also works when it is
    resumed after a reboot with no terminal.

ONE-TIME SETUP (SUT)
--------------------
  1) startup.nsh on EFI partition:     /boot/efi/startup.nsh (see deploy/resume/startup.nsh)
  2) fw-validation-resume.service:     deploy/resume/fw-validation-resume.service
  3) VTInfo.efi on EFI partition:      /boot/efi/EFI/VTInfo.efi
  4) Swap for S4: an active swap partition, or (without one) a swap file of at
     least /sys/power/image_size -- sudo ./deploy/setup/setup_sut.sh (step 9)
     grows /swap.img to the RAM size. GRUB resume= is set by the test
     (Step 5.6); manual equivalent for a swap partition:
       lsblk                                   # find the [SWAP] partition
       sudo nano /etc/default/grub             # GRUB_CMDLINE_LINUX="resume=/dev/nvme0n1p3"
       sudo update-grub
       sudo reboot

CONFIG
------
  config/suites/virtualization_config.yaml  — tool name, expected keywords, timeouts
  config/test_config.yaml                   — global settings

PRE-TEST (manual, performed once before running)
------------------------------------------------
  1.0) Flash IFWI and deploy Ubuntu custom image to SUT boot device.
       - IFWI: Bootguard 5 (BtG5) EXTERNAL release — RPSF_SEP5 or RPSF_SED5 variant.
       - Any version from the current BOM release is acceptable.
       - Example (PTL board):
         ECG_PTL_PR04_B0A1-XXXODCA_RPSF_SEP5_11E50692_2026ww01.1.02_BE351556_CRB.bin
  2.0) Power ON SUT and boot to Ubuntu OS.
  3.0) Transfer the vtinfo package (zip/tar) to SUT and unzip it:
         scp VtInfo_v1.1.83.zip user@<SUT_IP>:/home/user/
         ssh user@<SUT_IP> 'cd /home/user && unzip VtInfo_v1.1.83.zip'
  3.1) Copy VTInfo.efi and all vt-tests into the SUT EFI partition:
         sudo cp /home/user/vtinfo/<VTInfo>.efi /boot/efi/EFI/
         sudo cp /home/user/vtinfo/vt-tests*      /boot/efi/EFI/
  3.2) Update 'vtinfo_efi_name' in config/suites/virtualization_config.yaml
       to match the exact .efi filename copied above.
  4.0) startup.nsh present at /boot/efi/startup.nsh (see deploy/resume/startup.nsh).
  5.0) fw-validation-resume.service installed + enabled (see deploy/).
  7.0) BIOS knobs: set by the test_runner.py pre-flight. For a direct pytest
       run, set them in BIOS Setup first:
         'Intel (VMX) Virtualization Technology' = Enabled
             (Intel Advanced Menu → CPU Configuration)
         'VT-d' = Enabled
             (Intel Advanced Menu → System Agent (SA) Configuration → VT-d Setup Menu)
         'Low Power S0 Idle Capability' = Disabled
             (Intel Advanced Menu → ACPI settings)

RUN (on SUT)
------------
  python3 test_runner.py     (recommended: the pre-flight sets the BIOS knobs)
  python -m pytest tests/virtualization/test_ec62443_virtualization_vtd_sut_func.py
      -v -s --setup-confirmed --yes
"""

import json
import logging
import os
import re
import subprocess
import time
from pathlib import Path
from typing import List, Optional, Tuple

import pytest

from tests.sut_base_test import SUTBaseTest
from core.prereq import pre_test_check

logger = logging.getLogger(__name__)

# Result files written by UEFI shell to EFI partition
VTINFO_BASELINE_FILE = "vtinfo_baseline.txt"
VTINFO_S3_FILE       = "vtinfo_s3.txt"
VTINFO_S4_FILE       = "vtinfo_s4.txt"
VTINFO_S5_FILE       = "vtinfo_s5.txt"

# Written to the state folder before the automatic GRUB reboot (Step 5.6)
GRUB_REBOOT_MARKER = "grub_resume_reboot.txt"

# Written to the state folder just before the S5 power-off (Step 9.0), checked at Step 9.1
S5_POWEROFF_RECORD = "vtd_s5_poweroff.json"

# How often to poll for signal files (seconds)
_POLL_INTERVAL = 10


@pytest.mark.virtualization
@pytest.mark.manual
class TestEC62443VirtualizationVtdFuncSUT(SUTBaseTest):
    """
    IEC 62443-4-2 Virtualization / VT-d functional test — SUT-only execution variant.

    Uses startup.nsh + systemd instead of NUC serial/SSH control.
    VTInfo.efi must be pre-staged on the SUT EFI partition.
    S3/S4 cycles are performed in-process; S5 uses an OS reboot phase.
    """

    SUITE   = "virtualization"
    TEST_ID = "IEC62443-4-2-TC_Virtualization_Vtd-FUNC-SUT"

    REBOOTS = (
        ("auto", "GRUB resume= for S4: update-grub, then reboot", "the kernel has no resume="),
        ("auto", "UEFI Shell: VTInfo.efi baseline"),
        ("auto", "UEFI Shell: VTInfo.efi after S3"),
        ("auto", "UEFI Shell: VTInfo.efi after S4"),
        ("auto", "S5 power-off, the RTC wakes the SUT after ~90 s"),
        ("auto", "UEFI Shell: VTInfo.efi after S5"),
    )

    @classmethod
    def reboot_plan(cls, config: dict) -> list:
        reboots = cls._reboots_confirmed(config)
        try:
            has_resume = "resume=" in Path("/proc/cmdline").read_text(encoding="utf-8")
        except OSError:
            has_resume = False
        return reboots[1:] if has_resume else reboots

    PRE_TEST_CHECKLIST = [
        "1.0)  Flash IFWI and deploy Ubuntu custom image to SUT.",
        "      - IFWI: Bootguard 5 (BtG5) EXTERNAL release — RPSF_SEP5 or RPSF_SED5 variant.",
        "      - Any version from the current BOM release is acceptable (no",
        "        specific IFWI version is pinned for this test).",
        "      - Example (PTL board):",
        "        ECG_PTL_PR04_B0A1-XXXODCA_RPSF_SEP5_11E50692_2026ww01.1.02_BE351556_CRB.bin",
        "2.0)  Power ON SUT and boot to Ubuntu OS.",
        "3.0)  Transfer vtinfo package to SUT and unzip:",
        "      scp VtInfo_v1.1.83.zip user@<SUT_IP>:/home/user/",
        "      ssh user@<SUT_IP> 'cd /home/user && unzip VtInfo_v1.1.83.zip'",
        "3.1)  Copy VTInfo.efi and vt-tests to the EFI partition:",
        "      sudo cp /home/user/vtinfo/<VTInfo>.efi /boot/efi/EFI/",
        "      sudo cp /home/user/vtinfo/vt-tests*      /boot/efi/EFI/",
        "3.2)  Update 'vtinfo_efi_name' in config/suites/virtualization_config.yaml",
        "      to match the exact .efi filename copied (e.g. VTInfo.efi).",
        "SETUP) startup.nsh present at /boot/efi/startup.nsh (see deploy/resume/startup.nsh).",
        "SETUP) fw-validation-resume.service installed + enabled (see deploy/).",
        "SETUP) BIOS knobs VMX + VT-d Enabled, Low Power S0 Idle Disabled -- set by the",
        "       test_runner.py pre-flight; checked from the OS at Step 5.0.",
        "SETUP) Swap for S4: a swap partition, or a swap file >= /sys/power/image_size",
        "       (sudo ./deploy/setup/setup_sut.sh grows /swap.img to the RAM size).",
        "       GRUB_CMDLINE_LINUX resume= (+ resume_offset= for a swap file) is set",
        "       automatically (Step 5.6: edit /etc/default/grub + sudo update-grub +",
        "       automatic reboot; the test resumes by itself). Manual equivalent:",
        "         GRUB_CMDLINE_LINUX=\"resume=/dev/nvme0n1p3\" ; sudo update-grub ; sudo reboot",
    ]

    # ------------------------------------------------------------------
    # Entry point
    # ------------------------------------------------------------------

    def test_ec62443_virtualization_vtd_sut_func(
        self,
        request,
        config,
        log_dir,
    ):
        """
        IEC62443-4-2-TC_Virtualization_Vtd-FUNC-SUT

        Multi-phase execution:
          Phase 0 : pre-checks + BIOS knob check + write baseline UEFI script + reboot
          UEFI 1  : VTInfo.efi baseline
          Phase 1 : verify baseline + S3 cycle + write S3 UEFI script + reboot
          UEFI 2  : VTInfo.efi after S3
          Phase 2 : verify S3 + S4 cycle + write S4 UEFI script + reboot
          UEFI 3  : VTInfo.efi after S4
          Phase 3 : verify S4 + S5 cycle (rtcwake off) → OS phase reboot
          Phase 4 : write S5 UEFI script + reboot into UEFI shell
          UEFI 4  : VTInfo.efi after S5
          Phase 5 : verify S5 + cleanup
        """
        self._begin()
        cfg = self._load_config(config)
        self._init_state_dir(cfg)

        pre_test_check(request, self.TEST_ID, self.PRE_TEST_CHECKLIST)

        # ------------------------------------------------------------------
        # Config
        # ------------------------------------------------------------------
        uefi_tool_dir   = cfg.get("uefi_tool_dir",    "EFI")
        vtinfo_efi_name = cfg.get("vtinfo_efi_name",  "VTInfo.efi")
        pass_kw         = cfg.get("pass_keyword",    "PASS")
        fail_kw         = cfg.get("fail_keyword",    "FAIL")
        warn_kw         = cfg.get("warning_keyword", "WARNING")
        s3_wake_secs    = int(cfg.get("s3_wake_secs", 60))
        s4_wake_secs    = int(cfg.get("s4_wake_secs", 60))
        s5_wake_secs    = int(cfg.get("s5_wake_secs", 90))

        logger.info("[Config] uefi_tool_dir   : %s", uefi_tool_dir)
        logger.info("[Config] vtinfo_efi_name : %s", vtinfo_efi_name)
        logger.info("[Config] pass_keyword    : %s", pass_kw)
        logger.info("[Config] fail_keyword    : %s", fail_kw)
        logger.info("[Config] warning_keyword : %s", warn_kw)
        logger.info("[Config] s3_wake_secs    : %d", s3_wake_secs)
        logger.info("[Config] s4_wake_secs    : %d", s4_wake_secs)
        logger.info("[Config] s5_wake_secs    : %d", s5_wake_secs)

        efi_dir = Path(cfg.get("sut_efi_mount", "/boot/efi")) / uefi_tool_dir

        mgr   = self._state_mgr
        # VTInfo writes into the tool folder; maintest.nsh copies each result to the EFI root.
        self._remove_at_test_end(*(
            folder / name
            for folder in (mgr.efi_mount, efi_dir)
            for name in (VTINFO_BASELINE_FILE, VTINFO_S3_FILE, VTINFO_S4_FILE, VTINFO_S5_FILE)
        ))
        state = mgr.get_state()
        phase = state.get("phase", 0)
        logger.info("[State] phase=%s  state=%s", phase, state)

        # ------------------------------------------------------------------
        # PHASE 0 — Pre-checks + BIOS manual gate + baseline UEFI script
        # ------------------------------------------------------------------
        if phase == 0:
            logger.info("=" * 60)
            logger.info("PHASE 0 — Pre-checks + BIOS knob check + baseline UEFI script")
            logger.info("=" * 60)

            # Step 3.0 — Verify VTInfo.efi is on EFI partition
            self._step_verify_efi_tool(cfg, step_label="3.0")
            self._select_efi_tool(efi_dir, vtinfo_efi_name, step_label="3.1")

            # Step 5.0 — BIOS knobs (set by the test_runner.py pre-flight), checked from the OS
            self._step_check_bios_knobs(log_dir, step_label="5.0")

            # Step 5.6 — S4 needs resume=<swap partition> on the kernel command line.
            # If missing: update GRUB + reboot (does not return); systemd re-runs Phase 0
            # and this step confirms the new command line.
            self._step_ensure_grub_resume(cfg, log_dir, step_label="5.6")

            # Step 6.0 — Write baseline VTInfo.efi UEFI script
            logger.info("[Step 6.0] Writing baseline VTInfo.efi UEFI script")
            vtinfo_run = self._select_efi_tool(efi_dir, vtinfo_efi_name, step_label="6.0")
            self._write_uefi_phase(
                phase=1,
                uefi_commands=[
                    f"cd {uefi_tool_dir}",
                    f"{vtinfo_run} >a {VTINFO_BASELINE_FILE}",
                    "cd \\",
                    f"copy {uefi_tool_dir}\\{VTINFO_BASELINE_FILE} {VTINFO_BASELINE_FILE}",
                ],
                result_filename=VTINFO_BASELINE_FILE,
                step_label="6.0",
            )
            logger.info("[Step 6.0] Rebooting into UEFI shell for baseline VTInfo check ...")
            self._reboot_into_uefi(step_label="6.0")
            # ← does not return; systemd resumes at Phase 1

        # ------------------------------------------------------------------
        # PHASE 1 — Verify baseline + S3 cycle + S3 UEFI script
        # ------------------------------------------------------------------
        if phase == 1:
            logger.info("=" * 60)
            logger.info("PHASE 1 — Verify baseline + S3 + S3 UEFI script")
            logger.info("=" * 60)

            assert self._check_phase_done(phase=1, step_label="6.1"), (
                "[Step 6.1] UEFI baseline phase did not complete.\n"
                f"  Check EFI partition: /boot/efi/state_done.txt"
            )
            mgr.mark_phase_done(1)

            raw = self._step_read_vtinfo(VTINFO_BASELINE_FILE, step_label="6.1")
            self._step_verify_vtinfo(raw, "Baseline", cfg, log_dir, step_label="6.1")

            # Step 7.0 — S3 sleep (in-process — rtcwake returns after wake)
            logger.info("[Step 7.0] Entering S3 (mem sleep, wake in %d s)", s3_wake_secs)
            self._step_power_cycle("S3", "mem", s3_wake_secs, log_dir, step_label="7.0")

            # Write S3 UEFI script
            logger.info("[Step 7.1] Writing S3 VTInfo.efi UEFI script")
            vtinfo_run = self._select_efi_tool(efi_dir, vtinfo_efi_name, step_label="7.1")
            self._write_uefi_phase(
                phase=2,
                uefi_commands=[
                    f"cd {uefi_tool_dir}",
                    f"{vtinfo_run} >a {VTINFO_S3_FILE}",
                    "cd \\",
                    f"copy {uefi_tool_dir}\\{VTINFO_S3_FILE} {VTINFO_S3_FILE}",
                ],
                result_filename=VTINFO_S3_FILE,
                step_label="7.1",
            )
            logger.info("[Step 7.1] Rebooting into UEFI shell for S3 VTInfo check ...")
            self._reboot_into_uefi(step_label="7.1")
            # ← does not return; systemd resumes at Phase 2

        # ------------------------------------------------------------------
        # PHASE 2 — Verify S3 + S4 cycle + S4 UEFI script
        # ------------------------------------------------------------------
        if phase == 2:
            logger.info("=" * 60)
            logger.info("PHASE 2 — Verify S3 + S4 + S4 UEFI script")
            logger.info("=" * 60)

            assert self._check_phase_done(phase=2, step_label="7.2"), (
                "[Step 7.2] UEFI S3 phase did not complete.\n"
                f"  Check EFI partition: /boot/efi/state_done.txt"
            )
            mgr.mark_phase_done(2)

            raw = self._step_read_vtinfo(VTINFO_S3_FILE, step_label="7.2")
            self._step_verify_vtinfo(raw, "After S3", cfg, log_dir, step_label="7.2")

            # Step 8.0 — S4 hibernate (in-process)
            self._step_verify_resume_cmdline(cfg, log_dir, step_label="8.0")
            logger.info("[Step 8.0] Entering S4 (disk hibernate, wake in %d s)", s4_wake_secs)
            self._step_power_cycle("S4", "disk", s4_wake_secs, log_dir, step_label="8.0")

            # Write S4 UEFI script
            logger.info("[Step 8.1] Writing S4 VTInfo.efi UEFI script")
            vtinfo_run = self._select_efi_tool(efi_dir, vtinfo_efi_name, step_label="8.1")
            self._write_uefi_phase(
                phase=3,
                uefi_commands=[
                    f"cd {uefi_tool_dir}",
                    f"{vtinfo_run} >a {VTINFO_S4_FILE}",
                    "cd \\",
                    f"copy {uefi_tool_dir}\\{VTINFO_S4_FILE} {VTINFO_S4_FILE}",
                ],
                result_filename=VTINFO_S4_FILE,
                step_label="8.1",
            )
            logger.info("[Step 8.1] Rebooting into UEFI shell for S4 VTInfo check ...")
            self._reboot_into_uefi(step_label="8.1")
            # ← does not return; systemd resumes at Phase 3

        # ------------------------------------------------------------------
        # PHASE 3 — Verify S4 + S5 power-off (process exits)
        # ------------------------------------------------------------------
        if phase == 3:
            logger.info("=" * 60)
            logger.info("PHASE 3 — Verify S4 + S5 shutdown")
            logger.info("=" * 60)

            assert self._check_phase_done(phase=3, step_label="8.2"), (
                "[Step 8.2] UEFI S4 phase did not complete.\n"
                f"  Check EFI partition: /boot/efi/state_done.txt"
            )
            mgr.mark_phase_done(3)

            raw = self._step_read_vtinfo(VTINFO_S4_FILE, step_label="8.2")
            self._step_verify_vtinfo(raw, "After S4", cfg, log_dir, step_label="8.2")

            # Step 9.0 — S5 shutdown via rtcwake -m off (process is killed; systemd
            # resumes at Phase 4 after the RTC alarm wakes the SUT).
            logger.info(
                "[Step 9.0] Entering S5 (shutdown, RTC wake in %d s) — "
                "systemd will resume at Phase 4 after wake",
                s5_wake_secs,
            )
            self._record_s5_poweroff(step_label="9.0")
            self._reboot_os_phase(phase=4, step_label="9.0", s5_wake_secs=s5_wake_secs)
            # ← does not return; systemd resumes at Phase 4

        # ------------------------------------------------------------------
        # PHASE 4 — Write S5 UEFI script + reboot into UEFI shell
        # ------------------------------------------------------------------
        if phase == 4:
            logger.info("=" * 60)
            logger.info("PHASE 4 — S5 VTInfo UEFI script")
            logger.info("=" * 60)

            assert self._check_phase_done(phase=4, step_label="9.1"), (
                "[Step 9.1] OS Phase 4 marker not found — S5 wake reboot did not complete.\n"
                f"  Check: {mgr.state_dir}/state_done.txt"
            )
            mgr.mark_phase_done(4)
            self._step_verify_s5(s5_wake_secs, log_dir, step_label="9.1")

            logger.info("[Step 9.2] Writing S5 VTInfo.efi UEFI script")
            vtinfo_run = self._select_efi_tool(efi_dir, vtinfo_efi_name, step_label="9.2")
            self._write_uefi_phase(
                phase=5,
                uefi_commands=[
                    f"cd {uefi_tool_dir}",
                    f"{vtinfo_run} >a {VTINFO_S5_FILE}",
                    "cd \\",
                    f"copy {uefi_tool_dir}\\{VTINFO_S5_FILE} {VTINFO_S5_FILE}",
                ],
                result_filename=VTINFO_S5_FILE,
                step_label="9.2",
            )
            logger.info("[Step 9.2] Rebooting into UEFI shell for S5 VTInfo check ...")
            self._reboot_into_uefi(step_label="9.2")
            # ← does not return; systemd resumes at Phase 5

        # ------------------------------------------------------------------
        # PHASE 5 — Verify S5 VTInfo result + done
        # ------------------------------------------------------------------
        logger.info("=" * 60)
        logger.info("PHASE 5 — Verify S5 VTInfo result")
        logger.info("=" * 60)

        assert self._check_phase_done(phase=5, step_label="9.3"), (
            "[Step 9.3] UEFI S5 phase did not complete.\n"
            f"  Check EFI partition: /boot/efi/state_done.txt"
        )
        mgr.mark_phase_done(5)

        raw = self._step_read_vtinfo(VTINFO_S5_FILE, step_label="9.3")
        self._step_verify_vtinfo(raw, "After S5", cfg, log_dir, step_label="9.3")

        mgr.cleanup()
        logger.info(
            "[OK] VT-d / VMX verified via VTInfo.efi — "
            "Baseline, After S3, After S4, After S5: all PASS"
        )
        self._end()

    # ------------------------------------------------------------------
    # Step helpers
    # ------------------------------------------------------------------

    def _step_verify_efi_tool(self, cfg: dict, step_label: str = "") -> None:
        """Verify VTInfo.efi is present on the SUT EFI partition."""
        prefix = f"[Step {step_label}]" if step_label else "[Pre-check]"
        efi_mount       = cfg.get("sut_efi_mount",   "/boot/efi")
        uefi_tool_dir   = cfg.get("uefi_tool_dir",   "EFI")
        vtinfo_efi_name = cfg.get("vtinfo_efi_name", "VTInfo.efi")

        # Build Linux path directly: /boot/efi/EFI — do NOT use _uefi_path_to_linux
        # here because that function strips the leading "EFI" segment.
        efi_dir = Path(efi_mount) / uefi_tool_dir
        vtinfo_path = efi_dir / vtinfo_efi_name

        logger.info("%s Verifying %s on EFI partition: %s", prefix, vtinfo_efi_name, efi_dir)
        assert vtinfo_path.exists(), (
            f"{prefix} {vtinfo_efi_name} not found: {vtinfo_path}\n"
            f"  Copy it: sudo cp {vtinfo_efi_name} {efi_dir}/"
        )
        logger.info("%s [OK] %s", prefix, vtinfo_path)

    def _step_check_bios_knobs(self, log_dir: Path, step_label: str = "") -> None:
        """Check from the OS that VMX, VT-d and Low Power S0 Idle are set as this test needs."""
        prefix = f"[Step {step_label}]" if step_label else "[BIOS knobs]"
        problems = []
        report = []

        # VMX: IA32_FEATURE_CONTROL (MSR 0x3A) bit 2 = VMX outside SMX enabled.
        subprocess.run(["sudo", "modprobe", "msr"], capture_output=True, text=True, timeout=30)
        msr = subprocess.run(["sudo", "rdmsr", "0x3a"], capture_output=True, text=True, timeout=30)
        msr_out = msr.stdout.strip()
        report.append(f"sudo rdmsr 0x3a -> rc={msr.returncode} stdout={msr_out!r} stderr={msr.stderr.strip()!r}")
        logger.info("%s MSR 0x3A (IA32_FEATURE_CONTROL) = %s (rc=%d)", prefix, msr_out or "<empty>", msr.returncode)
        try:
            vmx_on = msr.returncode == 0 and bool(int(msr_out, 16) & 0x4)
        except ValueError:
            vmx_on = False
        logger.info("%s VMX enabled (bit 2) : %s", prefix, vmx_on)
        if msr.returncode != 0 or not msr_out:
            problems.append(
                f"VMX: cannot read MSR 0x3A (rc={msr.returncode}, {msr.stderr.strip() or 'no output'}).\n"
                "      Install msr-tools and load the msr module (deploy/setup/setup_sut.sh does both)."
            )
        elif not vmx_on:
            problems.append(
                "'Intel (VMX) Virtualization Technology' must be Enabled (MSR 0x3A bit 2 is 0).\n"
                "      BIOS Setup: Intel Advanced Menu → CPU Configuration"
            )

        # VT-d: the BIOS publishes the ACPI DMAR table only when VT-d is enabled.
        dmar = Path("/sys/firmware/acpi/tables/DMAR")
        vtd_on = dmar.exists()
        report.append(f"{dmar} exists -> {vtd_on}")
        logger.info("%s VT-d (ACPI DMAR table present) : %s", prefix, vtd_on)
        if not vtd_on:
            problems.append(
                f"'VT-d' must be Enabled (no ACPI DMAR table at {dmar}).\n"
                "      BIOS Setup: Intel Advanced Menu → System Agent (SA) Configuration → VT-d Setup Menu"
            )

        # Low Power S0 Idle Capability = Disabled: the kernel then selects [deep] (real S3).
        mem_sleep_file = Path("/sys/power/mem_sleep")
        try:
            mem_sleep = mem_sleep_file.read_text(encoding="utf-8").strip()
        except OSError as exc:
            mem_sleep = f"<unreadable: {exc}>"
        report.append(f"{mem_sleep_file} -> {mem_sleep!r}")
        logger.info("%s %s : %s  (S3 needs [deep])", prefix, mem_sleep_file, mem_sleep)
        if "[deep]" not in mem_sleep:
            problems.append(
                f"'Low Power S0 Idle Capability' must be Disabled ({mem_sleep_file} = '{mem_sleep}';\n"
                "      S3 needs [deep], otherwise 'rtcwake -m mem' only enters s2idle).\n"
                "      BIOS Setup: Intel Advanced Menu → ACPI settings\n"
                "      If it is already Disabled, check the kernel command line for mem_sleep_default="
            )

        artifact = log_dir / "bios_knob_check.log"
        artifact.write_text("\n".join(report) + "\n", encoding="utf-8", errors="replace")
        logger.info("%s Artifact saved: %s", prefix, artifact)

        assert not problems, (
            f"{prefix} BIOS knobs are not set as this test needs:\n"
            + "\n".join(f"  - {p}" for p in problems)
            + "\n  Run the test from test_runner.py -- its pre-flight sets these knobs (AMI BIOS)"
            "\n  or lists them for BIOS Setup (other BIOS). Then Save & Exit (F4) and run again.\n"
            f"  Check artifact: {artifact}"
        )
        logger.info("%s [OK] VMX Enabled, VT-d Enabled, Low Power S0 Idle Disabled ([deep])", prefix)

    def _step_read_vtinfo(self, filename: str, step_label: str = "") -> str:
        """Read a VTInfo result file written by the UEFI shell."""
        prefix = f"[Step {step_label}]" if step_label else "[VTInfo Result]"
        logger.info("%s Reading VTInfo result: %s", prefix, filename)
        raw = self._read_uefi_result(filename, step_label=step_label)
        assert raw, (
            f"{prefix} VTInfo result file is empty or missing: {filename}\n"
            f"  Check EFI partition: /boot/efi/{filename}"
        )
        return raw

    # ------------------------------------------------------------------
    # S4 prerequisite — GRUB resume=<swap partition | swap file>
    # ------------------------------------------------------------------

    def _detect_swap_target(self, cfg: dict, prefix: str) -> Tuple[str, Optional[int]]:
        """
        Return (resume device, resume_offset) of the S4 hibernate target.

        - cfg['swap_partition'] when set                -> (that device, None)
        - else the first active swap partition (swapon) -> (partition, None)
        - else the first active swap file               -> (UUID=<its filesystem>, page
          offset of its first block from `sudo filefrag -v`)
        zram is skipped (it cannot hold a hibernation image). A swap file must be at
        least /sys/power/image_size; deploy/setup/setup_sut.sh (step 9) grows it.
        """
        lsblk = subprocess.run(["lsblk"], capture_output=True, text=True, timeout=30)
        logger.info("%s lsblk:\n%s", prefix, lsblk.stdout.rstrip())

        override = str(cfg.get("swap_partition", "") or "").strip()
        if override:
            logger.info("%s swap_partition from config: %s", prefix, override)
            assert Path(self._resolve_block_device(override)).exists(), (
                f"{prefix} swap_partition '{override}' (virtualization_config.yaml) "
                f"does not exist on this SUT.\n  lsblk:\n{lsblk.stdout}"
            )
            return override, None

        result = subprocess.run(
            ["swapon", "--show=NAME,TYPE,SIZE", "--bytes", "--noheadings", "--raw"],
            capture_output=True, text=True, timeout=30,
        )
        logger.info(
            "%s swapon --show rc=%d:\n%s", prefix, result.returncode, result.stdout.rstrip()
        )
        rows = [line.split() for line in result.stdout.splitlines()]
        partitions = [r[0] for r in rows if len(r) >= 2 and r[1] == "partition"]
        if partitions:
            if len(partitions) > 1:
                logger.warning(
                    "%s Multiple swap partitions %s — using %s "
                    "(set 'swap_partition' in config to override)",
                    prefix, partitions, partitions[0],
                )
            logger.info("%s Swap partition: %s", prefix, partitions[0])
            return partitions[0], None

        files = [r for r in rows if len(r) >= 3 and r[1] == "file"]
        assert files, (
            f"{prefix} No active swap partition or swap file — S4 (hibernate) needs one.\n"
            f"  swapon output: {result.stdout.strip() or '<none>'}\n"
            f"  Fix: sudo ./deploy/setup/setup_sut.sh (step 9 prepares /swap.img), or set\n"
            f"  'swap_partition' in config/suites/virtualization_config.yaml.\n"
            f"  lsblk:\n{lsblk.stdout}"
        )
        return self._swap_file_target(files[0][0], int(files[0][2]), prefix)

    def _swap_file_target(self, swap_file: str, swap_bytes: int, prefix: str) -> Tuple[str, int]:
        """(UUID=<filesystem>, resume_offset in pages) for hibernating to a swap file."""
        gib = 1024 ** 3
        try:
            image_size = int(Path("/sys/power/image_size").read_text(encoding="utf-8").strip())
        except (OSError, ValueError):
            image_size = 0
        logger.info("%s Swap file: %s (%.1f GiB), /sys/power/image_size: %.1f GiB",
                    prefix, swap_file, swap_bytes / gib, image_size / gib)
        assert swap_bytes >= image_size, (
            f"{prefix} Swap file {swap_file} is {swap_bytes / gib:.1f} GiB, smaller than the "
            f"kernel's hibernation image target /sys/power/image_size ({image_size / gib:.1f} GiB) "
            f"— S4 could fail.\n"
            f"  Fix: sudo ./deploy/setup/setup_sut.sh (step 9 grows it to the RAM size), "
            f"then re-run the test."
        )

        fs = subprocess.run(["findmnt", "-no", "UUID,FSTYPE", "-T", swap_file],
                            capture_output=True, text=True, timeout=30)
        fields = fs.stdout.split()
        assert fs.returncode == 0 and len(fields) == 2, (
            f"{prefix} Cannot find the filesystem UUID of {swap_file} "
            f"(findmnt rc={fs.returncode}: {fs.stdout.strip()} {fs.stderr.strip()})"
        )
        uuid, fstype = fields
        assert fstype in ("ext4", "xfs"), (
            f"{prefix} Swap file {swap_file} is on {fstype}; only ext4/xfs swap files are "
            f"supported for S4 here (btrfs needs a different resume_offset).\n"
            f"  Use a swap partition and set 'swap_partition' in virtualization_config.yaml."
        )

        # The swap file is root-only (0600), so its block map needs root (NOPASSWD rule: setup_sut.sh).
        frag = subprocess.run(["sudo", "/usr/sbin/filefrag", "-v", swap_file],
                              capture_output=True, text=True, timeout=60)
        block = re.search(r"blocks of (\d+) bytes", frag.stdout)
        first = re.search(r"^\s*0:\s*\d+\.\.\s*\d+:\s*(\d+)\.\.", frag.stdout, re.MULTILINE)
        assert frag.returncode == 0 and block and first, (
            f"{prefix} Cannot read the block map of {swap_file} "
            f"(sudo filefrag -v rc={frag.returncode}).\n"
            f"  {frag.stderr.strip() or frag.stdout.strip()[:300]}\n"
            f"  Fix: sudo ./deploy/setup/setup_sut.sh (adds the passwordless filefrag rule)."
        )
        offset = int(first.group(1)) * int(block.group(1)) // os.sysconf("SC_PAGE_SIZE")
        logger.info("%s Swap file on %s UUID=%s, resume_offset=%d", prefix, fstype, uuid, offset)
        return f"UUID={uuid}", offset

    @staticmethod
    def _resolve_block_device(spec: str) -> str:
        """Resolve /dev/..., UUID=, PARTUUID= or LABEL= to a canonical /dev path."""
        by_tag = {
            "UUID": "/dev/disk/by-uuid",
            "PARTUUID": "/dev/disk/by-partuuid",
            "LABEL": "/dev/disk/by-label",
        }
        tag, sep, value = spec.partition("=")
        if sep and tag.upper() in by_tag:
            spec = f"{by_tag[tag.upper()]}/{value}"
        try:
            return str(Path(spec).resolve())
        except OSError:
            return spec

    @staticmethod
    def _cmdline_resume() -> Tuple[str, Optional[int]]:
        """(resume=, resume_offset=) of /proc/cmdline; ('', None) if absent. The last one wins."""
        args = Path("/proc/cmdline").read_text(encoding="utf-8").split()
        devices = [a.split("=", 1)[1] for a in args if a.startswith("resume=")]
        offsets = [a.split("=", 1)[1] for a in args if a.startswith("resume_offset=")]
        try:
            offset = int(offsets[-1]) if offsets else None
        except ValueError:
            offset = None
        return (devices[-1] if devices else ""), offset

    def _resume_matches(self, dev: str, offset: Optional[int],
                        want_dev: str, want_offset: Optional[int]) -> bool:
        return bool(dev) and (
            self._resolve_block_device(dev) == self._resolve_block_device(want_dev)
            and (offset or 0) == (want_offset or 0)
        )

    @staticmethod
    def _resume_args(dev: str, offset: Optional[int]) -> List[str]:
        return [f"resume={dev}"] + ([f"resume_offset={offset}"] if offset is not None else [])

    @staticmethod
    def _grub_with_resume(content: str, resume_args: List[str]) -> str:
        """
        Return /etc/default/grub content with GRUB_CMDLINE_LINUX carrying
        resume_args (resume=... [resume_offset=...]). Existing resume= and
        resume_offset= tokens are replaced; all other kernel arguments are
        kept. Appends the line if it is missing.
        """
        pattern = re.compile(
            r"""^GRUB_CMDLINE_LINUX=(["']?)(.*?)\1[ \t]*$""", re.MULTILINE
        )
        matches = list(pattern.finditer(content))
        if not matches:
            return content.rstrip("\n") + '\nGRUB_CMDLINE_LINUX="' + " ".join(resume_args) + '"\n'
        m = matches[-1]   # shell semantics: the last assignment wins
        args = [a for a in m.group(2).split()
                if not a.startswith(("resume=", "resume_offset="))]
        args.extend(resume_args)
        new_line = 'GRUB_CMDLINE_LINUX="' + " ".join(args) + '"'
        return content[:m.start()] + new_line + content[m.end():]

    @staticmethod
    def _log_hibernation_state(prefix: str) -> None:
        """
        Log Secure Boot and the kernel lockdown state before S4 -- never fails the test.
        Ubuntu turns lockdown on when Secure Boot is enabled, and the kernel then refuses S4;
        the warning makes that visible in the log if the S4 step misbehaves.
        """
        try:
            sb = Path("/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c").read_bytes()
            sb_state = "ENABLED" if len(sb) >= 5 and sb[4] == 1 else "DISABLED"
        except OSError:
            sb_state = "unknown"
        try:
            text = Path("/sys/kernel/security/lockdown").read_text(encoding="utf-8").strip()
            mode = (re.search(r"\[(\w+)\]", text) or [None, "unknown"])[1]
        except OSError:
            text, mode = "not readable", "unknown"
        logger.info("%s Secure Boot: %s, kernel lockdown: %s", prefix, sb_state, text)
        if mode not in ("none", "unknown"):
            logger.warning(
                "%s Kernel lockdown '%s' (Secure Boot %s): the kernel may refuse S4 (hibernate). "
                "Continuing -- disable Secure Boot for this test if the S4 step fails.",
                prefix, mode, sb_state,
            )

    def _step_ensure_grub_resume(self, cfg: dict, log_dir: Path, step_label: str = "") -> None:
        """
        Make sure the kernel boots with resume= (+ resume_offset= for a swap
        file) pointing at the S4 hibernate target.

        Already active in /proc/cmdline → nothing to do (returns).
        Otherwise: back up /etc/default/grub (once), set the arguments in
        GRUB_CMDLINE_LINUX, run `sudo update-grub`, verify grub.cfg, then
        reboot via _reboot_os_phase(0) — does NOT return. systemd re-runs
        Phase 0 after boot, and this step confirms the new command line.

        GRUB_REBOOT_MARKER in the state folder guards against a reboot loop: if the kernel
        still lacks the arguments after the automatic reboot, the step fails.
        """
        prefix = f"[Step {step_label}]" if step_label else "[GRUB resume]"
        grub_default = Path(cfg.get("grub_default_file", "/etc/default/grub"))
        grub_cfg     = cfg.get("grub_cfg_file", "/boot/grub/grub.cfg")
        artifact     = log_dir / "grub_resume_check.log"
        marker       = Path(self._state_mgr.state_dir) / GRUB_REBOOT_MARKER

        swap_dev, swap_offset   = self._detect_swap_target(cfg, prefix)
        resume_args             = self._resume_args(swap_dev, swap_offset)
        wanted                  = " ".join(resume_args)
        cmdline_dev, cmdline_off = self._cmdline_resume()
        found = " ".join(self._resume_args(cmdline_dev, cmdline_off)) if cmdline_dev else "<absent>"
        logger.info("%s S4 target            : %s (%s)",
                    prefix, wanted, self._resolve_block_device(swap_dev))
        logger.info("%s /proc/cmdline        : %s", prefix, found)

        if self._resume_matches(cmdline_dev, cmdline_off, swap_dev, swap_offset):
            with artifact.open("a", encoding="utf-8") as fh:
                fh.write(f"target={wanted}\ncmdline={found}\nstatus=active\n")
            if marker.exists():
                # Resumed by systemd after our own GRUB reboot — consume the
                # OS-phase state_done.txt so later phase checks stay honest.
                marker.unlink()
                self._state_mgr.mark_phase_done(0)
                logger.info("%s [OK] Resumed after GRUB reboot", prefix)
            logger.info("%s [OK] Kernel booted with %s", prefix, found)
            return

        if marker.exists():
            marker.unlink()   # let a manual re-run try the GRUB update again
            raise AssertionError(
                f"{prefix} Kernel still lacks {wanted} after the automatic "
                f"GRUB reboot (found: {found}).\n"
                f"  Check /etc/default/grub.d/*.cfg overrides and the boot entry "
                f"actually used, then re-run the test.\n"
                f"  Check artifact: {artifact}"
            )

        assert grub_default.exists(), (
            f"{prefix} {grub_default} not found — cannot set resume= for S4.\n"
            f"  Set 'grub_default_file' in config/suites/virtualization_config.yaml."
        )
        old = grub_default.read_text(encoding="utf-8")
        new = self._grub_with_resume(old, resume_args)

        # Full command paths: sudo matches the NOPASSWD rules (setup_sut.sh) literally.
        if new != old:
            backup = grub_default.with_name(grub_default.name + ".fwval.bak")
            if not backup.exists():
                logger.info("%s Backing up %s -> %s", prefix, grub_default, backup)
                r = subprocess.run(
                    ["sudo", "/usr/bin/cp", "-p", str(grub_default), str(backup)],
                    capture_output=True, text=True, timeout=30,
                )
                assert r.returncode == 0, (
                    f"{prefix} Backup of {grub_default} failed rc={r.returncode}: "
                    f"{r.stderr.strip()}"
                )
            logger.info("%s Setting GRUB_CMDLINE_LINUX %s in %s", prefix, wanted, grub_default)
            r = subprocess.run(
                ["sudo", "/usr/bin/tee", str(grub_default)],
                input=new, capture_output=True, text=True, timeout=30,
            )
            assert r.returncode == 0, (
                f"{prefix} Writing {grub_default} failed rc={r.returncode}: "
                f"{r.stderr.strip()}"
            )
        else:
            logger.info("%s %s already has %s — kernel not rebooted yet",
                        prefix, grub_default, wanted)

        logger.info("%s sudo update-grub", prefix)
        upd = subprocess.run(["sudo", "/usr/sbin/update-grub"], capture_output=True, text=True, timeout=300)
        with artifact.open("a", encoding="utf-8", errors="replace") as fh:
            fh.write(
                f"target={wanted}\ncmdline={found}\n"
                f"--- {grub_default} (before) ---\n{old}\n"
                f"--- {grub_default} (after) ---\n{new}\n"
                f"--- update-grub rc={upd.returncode} ---\n{upd.stdout}{upd.stderr}\n"
            )
        logger.info("%s Artifact saved: %s", prefix, artifact)
        assert upd.returncode == 0, (
            f"{prefix} update-grub failed rc={upd.returncode}.\n"
            f"  Check artifact: {artifact}"
        )

        # grub.cfg is root-only (0600) on Ubuntu.
        chk = subprocess.run(["sudo", "/usr/bin/cat", grub_cfg], capture_output=True, text=True, timeout=30)
        missing = [a for a in resume_args if not re.search(rf"(?<!\S){re.escape(a)}(?!\S)", chk.stdout)]
        assert chk.returncode == 0 and not missing, (
            f"{prefix} {' '.join(missing) or wanted} not found in {grub_cfg} after update-grub "
            f"(rc={chk.returncode}; overridden in /etc/default/grub.d/?).\n"
            f"  Check artifact: {artifact}"
        )
        logger.info(
            "%s [OK] GRUB updated with %s — rebooting to apply; "
            "systemd resumes Phase 0 after boot",
            prefix, wanted,
        )
        marker.write_text(f"{wanted}\n", encoding="utf-8")
        self._reboot_os_phase(phase=0, step_label=step_label)
        # ← does not return; systemd re-runs Phase 0

    def _step_verify_resume_cmdline(self, cfg: dict, log_dir: Path, step_label: str = "") -> None:
        """Assert the running kernel has resume= (+ resume_offset=) pointing at the S4 target."""
        prefix = f"[Step {step_label}]" if step_label else "[GRUB resume]"
        self._log_hibernation_state(prefix)
        swap_dev, swap_offset    = self._detect_swap_target(cfg, prefix)
        cmdline_dev, cmdline_off = self._cmdline_resume()
        wanted = " ".join(self._resume_args(swap_dev, swap_offset))
        found = " ".join(self._resume_args(cmdline_dev, cmdline_off)) if cmdline_dev else "<absent>"
        logger.info("%s /proc/cmdline: %s, S4 target: %s", prefix, found, wanted)
        assert self._resume_matches(cmdline_dev, cmdline_off, swap_dev, swap_offset), (
            f"{prefix} Running kernel is not booted with {wanted} "
            f"(found: {found}) — S4 resume would fail.\n"
            f"  Step 5.6 sets it in GRUB and reboots; re-run the test so "
            f"Step 5.6 can apply it again.\n"
            f"  Check artifact: {log_dir / 'grub_resume_check.log'}"
        )
        logger.info("%s [OK] Kernel booted with %s", prefix, found)

    # def _step_verify_vtinfo(
    #     self,
    #     raw: str,
    #     label: str,
    #     cfg: dict,
    #     log_dir: Path,
    #     step_label: str = "",
    # ) -> None:
    #     """Verify VTInfo.efi output contains PASS and no FAIL/WARNING keywords."""
    #     prefix = f"[Step {step_label}]" if step_label else f"[VTInfo {label}]"

    #     pass_kw = cfg.get("pass_keyword",    "PASS")
    #     fail_kw = cfg.get("fail_keyword",    "FAIL")
    #     warn_kw = cfg.get("warning_keyword", "WARNING")

    #     # Save artifact
    #     safe_label = label.lower().replace(" ", "_")
    #     artifact = log_dir / f"vtinfo_{safe_label}.log"
    #     artifact.write_text(raw, encoding="utf-8", errors="replace")
    #     logger.info("%s Artifact saved: %s", prefix, artifact)

    #     for line in raw.splitlines():
    #         logger.info("    %s", line)

    #     assert pass_kw.upper() in raw.upper(), (
    #         f"{prefix} '{pass_kw}' keyword NOT found in VTInfo.efi output.\n"
    #         f"  Label: {label}\n"
    #         f"  Check artifact: {artifact}"
    #     )

    #     assert fail_kw.upper() not in raw.upper(), (
    #         f"{prefix} '{fail_kw}' keyword found in VTInfo.efi output — test FAILED.\n"
    #         f"  Label: {label}\n"
    #         f"  Check artifact: {artifact}"
    #     )

    #     assert warn_kw.upper() not in raw.upper(), (
    #         f"{prefix} '{warn_kw}' keyword found in VTInfo.efi output.\n"
    #         f"  Label: {label}\n"
    #         f"  Check artifact: {artifact}"
    #     )

    #     logger.info(
    #         "%s [OK] VTInfo verified (%s) — PASS present, no FAIL, no WARNING",
    #         prefix, label,
    #     )

    def _step_verify_vtinfo(
        self,
        raw: str,
        label: str,
        cfg: dict,
        log_dir: Path,
        step_label: str = "",
    ) -> None:
        """Verify VTInfo.efi output reports PASS with zero FAIL and WARN counts."""
        prefix = f"[Step {step_label}]" if step_label else f"[VTInfo {label}]"

        pass_kw = cfg.get("pass_keyword", "VT Test Status: PASS")

        # Save artifact
        safe_label = label.lower().replace(" ", "_")
        artifact = log_dir / f"vtinfo_{safe_label}.log"
        artifact.write_text(raw, encoding="utf-8", errors="replace")
        logger.info("%s Artifact saved: %s", prefix, artifact)

        for line in raw.splitlines():
            logger.info("    %s", line)

        # Verify overall PASS status
        assert pass_kw.upper() in raw.upper(), (
            f"{prefix} '{pass_kw}' not found in VTInfo output.\n"
            f"  Label: {label}\n"
            f"  Check artifact: {artifact}"
        )

        # Parse summary counts
        fail_match = re.search(r"Fail\s*\|\s*(\d+)", raw, re.IGNORECASE)
        warn_match = re.search(r"Warn\s*\|\s*(\d+)", raw, re.IGNORECASE)

        assert fail_match, (
            f"{prefix} Unable to locate FAIL count in VTInfo output.\n"
            f"  Check artifact: {artifact}"
        )

        assert warn_match, (
            f"{prefix} Unable to locate WARN count in VTInfo output.\n"
            f"  Check artifact: {artifact}"
        )

        fail_count = int(fail_match.group(1))
        warn_count = int(warn_match.group(1))

        assert fail_count == 0, (
            f"{prefix} VTInfo reported {fail_count} failed checks.\n"
            f"  Check artifact: {artifact}"
        )

        assert warn_count == 0, (
            f"{prefix} VTInfo reported {warn_count} warning(s).\n"
            f"  Check artifact: {artifact}"
        )

        logger.info(
            "%s [OK] VTInfo verified (%s) — PASS, Fail=%d, Warn=%d",
            prefix,
            label,
            fail_count,
            warn_count,
        )
    
    # Kernel messages that must appear, in this order, for a real S3 / S4 cycle.
    SLEEP_EVIDENCE = {
        "S3": (
            "PM: suspend entry (deep)",
            "ACPI: PM: Preparing to enter system sleep state S3",
            "ACPI: PM: Waking up from system sleep state S3",
            "PM: suspend exit",
        ),
        "S4": (
            "PM: hibernation: hibernation entry",
            "ACPI: PM: Preparing to enter system sleep state S4",
            "PM: hibernation: Creating image",
            "ACPI: PM: Waking up from system sleep state S4",
            "PM: hibernation: hibernation exit",
        ),
    }

    def _step_power_cycle(
        self,
        state: str,
        rtcwake_mode: str,
        wake_secs: int,
        log_dir: Path,
        step_label: str = "",
    ) -> None:
        """
        Perform an in-process power cycle (S3 or S4) using rtcwake, then prove it happened.

        rtcwake returns after the system wakes, so this method does not exit
        the pytest process. Only use for S3 (mem) and S4 (disk).
        For S5 (off), use _record_s5_poweroff() + _reboot_os_phase() + _step_verify_s5().
        """
        prefix = f"[Step {step_label}]" if step_label else f"[{state}]"
        boot_id_before = self._boot_id()
        disarmed = self._disarm_wake_sources(prefix)
        still_armed = self._enabled_wake_sources()
        try:
            wall_start, mono_start = time.time(), time.monotonic()
            logger.info(
                "%s sudo rtcwake -m %s -s %d — SUT will enter %s and wake after %d s",
                prefix, rtcwake_mode, wake_secs, state, wake_secs,
            )
            result = subprocess.run(
                ["sudo", "/usr/sbin/rtcwake", "-m", rtcwake_mode, "-s", str(wake_secs)],
                capture_output=True, text=True,
            )
            # CLOCK_MONOTONIC stops while the CPU is in S3/S4, the wall clock (RTC) does not.
            wall_secs = time.time() - wall_start
            off_secs = wall_secs - (time.monotonic() - mono_start)
        finally:
            self._rearm_wake_sources(disarmed, prefix)
        wakeup_irq = self._read_text("/sys/power/pm_wakeup_irq")
        logger.info(
            "%s rtcwake rc=%d, elapsed %.0f s, of which %.0f s with the CPU stopped",
            prefix, result.returncode, wall_secs, off_secs,
        )
        assert "password is required" not in result.stderr, (
            f"{prefix} sudo rtcwake needs a password (no terminal) — the SUT did NOT enter "
            f"{state}.\n  Fix: sudo ./deploy/setup/setup_sut.sh (adds the passwordless "
            f"rtcwake rule), then re-run the test."
        )

        time.sleep(5)  # let journald receive the resume messages
        boot_id_after = self._boot_id()
        kernel_log = self._kernel_log_since(wall_start - 1, prefix)
        missing = self._missing_in_order(kernel_log, self.SLEEP_EVIDENCE[state])
        min_off = wake_secs / 2

        artifact = log_dir / f"power_state_{state.lower()}.log"
        artifact.write_text(
            f"rtcwake -m {rtcwake_mode} -s {wake_secs}: rc={result.returncode}\n"
            f"stdout: {result.stdout.strip()}\nstderr: {result.stderr.strip()}\n"
            f"boot_id before: {boot_id_before}\nboot_id after : {boot_id_after}\n"
            f"elapsed: {wall_secs:.1f} s, CPU stopped: {off_secs:.1f} s (minimum {min_off:.0f} s)\n"
            f"wake sources disarmed: {disarmed or 'none'}\n"
            f"wake sources armed during {state}: {still_armed or 'none'}\n"
            f"wakeup IRQ (/sys/power/pm_wakeup_irq): {wakeup_irq or 'n/a'}\n"
            f"missing kernel messages: {missing or 'none'}\n"
            f"--- kernel log since rtcwake ---\n{kernel_log}",
            encoding="utf-8", errors="replace",
        )
        logger.info("%s Artifact saved: %s", prefix, artifact)

        assert result.returncode == 0, (
            f"{prefix} rtcwake -m {rtcwake_mode} failed rc={result.returncode} — the SUT did not "
            f"enter {state}: {result.stderr.strip()}\n  Check artifact: {artifact}"
        )
        assert boot_id_after == boot_id_before, (
            f"{prefix} boot_id changed ({boot_id_before} -> {boot_id_after}): the SUT rebooted "
            f"instead of resuming from {state}.\n  Check artifact: {artifact}"
        )
        assert off_secs >= min_off, (
            f"{prefix} The CPU was stopped for only {off_secs:.0f} s (expected >= {min_off:.0f} s "
            f"of the {wake_secs} s RTC alarm) — the SUT did not stay in {state}.\n"
            f"  Wake sources armed: {still_armed or 'none'}, wakeup IRQ: {wakeup_irq or 'n/a'} "
            f"(cat /proc/interrupts to map it to a device).\n"
            f"  Check artifact: {artifact}"
        )
        assert not missing, (
            f"{prefix} Kernel log since rtcwake lacks {missing} — no proof the SUT entered and "
            f"left {state}.\n  Check artifact: {artifact}"
        )
        logger.info(
            "%s [OK] %s entered and resumed: kernel log %s ... %s, CPU stopped %.0f s, same boot",
            prefix, state, self.SLEEP_EVIDENCE[state][1], self.SLEEP_EVIDENCE[state][-1], off_secs,
        )

    def _record_s5_poweroff(self, step_label: str = "") -> None:
        """Save this boot's id and the power-off time so Step 9.1 can prove S5 happened."""
        prefix = f"[Step {step_label}]" if step_label else "[S5]"
        record = {"boot_id": self._boot_id(), "poweroff_epoch": time.time()}
        path = Path(self._state_mgr.state_dir) / S5_POWEROFF_RECORD
        path.write_text(json.dumps(record), encoding="utf-8")
        logger.info("%s S5 record: %s -> %s", prefix, record, path)

    def _step_verify_s5(self, wake_secs: int, log_dir: Path, step_label: str = "") -> None:
        """
        Prove the SUT was powered off (S5) and woken by the RTC, not just rebooted:
          - new boot_id
          - the boot that ran rtcwake reached poweroff.target, not reboot.target
          - this boot's kernel started >= 3/4 of wake_secs after the power-off command
        """
        prefix = f"[Step {step_label}]" if step_label else "[S5]"
        path = Path(self._state_mgr.state_dir) / S5_POWEROFF_RECORD
        assert path.exists(), (
            f"{prefix} {path} not found — cannot prove the S5 power-off (Step 9.0 writes it).\n"
            f"  Re-run the test from the start."
        )
        record = json.loads(path.read_text(encoding="utf-8"))
        old_boot = record["boot_id"]
        new_boot = self._boot_id()
        boot_start = time.time() - time.clock_gettime(time.CLOCK_BOOTTIME)
        off_secs = boot_start - record["poweroff_epoch"]
        min_off = wake_secs * 3 / 4

        journal = subprocess.run(
            ["journalctl", "-b", old_boot.replace("-", ""), "-o", "cat", "--no-pager"],
            capture_output=True, text=True, timeout=120,
        )
        targets = [line for line in journal.stdout.splitlines()
                   if "Reached target poweroff.target" in line or "Reached target reboot.target" in line]
        powered_off = any("poweroff.target" in t for t in targets)
        rebooted = any("reboot.target" in t for t in targets)

        artifact = log_dir / "power_state_s5.log"
        artifact.write_text(
            f"record: {record}\nboot_id now: {new_boot}\n"
            f"kernel start: {time.ctime(boot_start)}, off for {off_secs:.1f} s (minimum {min_off:.0f} s)\n"
            f"journalctl -b {old_boot}: rc={journal.returncode} {journal.stderr.strip()}\n"
            f"shutdown targets: {targets or 'none'}\n"
            f"--- last 30 lines of the powered-off boot ---\n"
            + "\n".join(journal.stdout.splitlines()[-30:]) + "\n",
            encoding="utf-8", errors="replace",
        )
        logger.info(
            "%s boot_id %s -> %s, shutdown targets %s, off %.0f s (minimum %.0f s)",
            prefix, old_boot, new_boot, targets or "none", off_secs, min_off,
        )
        logger.info("%s Artifact saved: %s", prefix, artifact)

        assert new_boot != old_boot, (
            f"{prefix} Still the same boot ({new_boot}) — the SUT never powered off.\n"
            f"  Check artifact: {artifact}"
        )
        assert journal.returncode == 0 and journal.stdout.strip(), (
            f"{prefix} Cannot read the journal of boot {old_boot} (rc={journal.returncode}: "
            f"{journal.stderr.strip()}) — the user needs the 'adm' or 'systemd-journal' group "
            f"and a persistent journal.\n  Check artifact: {artifact}"
        )
        assert powered_off and not rebooted, (
            f"{prefix} Boot {old_boot} did not end with a power-off (targets: {targets or 'none'}) — "
            f"not an S5 cycle.\n  Check artifact: {artifact}"
        )
        assert off_secs >= min_off, (
            f"{prefix} This boot started {off_secs:.0f} s after the power-off command "
            f"(expected >= {min_off:.0f} s of the {wake_secs} s RTC alarm) — the SUT was not kept "
            f"off until the RTC woke it.\n  Check artifact: {artifact}"
        )
        path.unlink()
        logger.info(
            "%s [OK] S5: boot %s powered off (poweroff.target), RTC woke the SUT %.0f s later",
            prefix, old_boot, off_secs,
        )

    # ACPI wake sources (/proc/acpi/wakeup) left armed during S3/S4: RTC alarm and power button.
    KEEP_WAKE_SOURCES = ("AWAC", "RTC", "RTC_", "PWRB", "SLPB")

    @staticmethod
    def _read_text(path: str) -> str:
        try:
            return Path(path).read_text(encoding="utf-8").strip()
        except OSError:
            return ""

    def _enabled_wake_sources(self) -> List[str]:
        """Names of the ACPI wake devices currently *enabled in /proc/acpi/wakeup."""
        names = []
        for line in self._read_text("/proc/acpi/wakeup").splitlines()[1:]:
            fields = line.split()
            if len(fields) >= 3 and not fields[0].startswith("*") and fields[2] == "*enabled":
                names.append(fields[0])
        return names

    def _toggle_wake_source(self, name: str) -> bool:
        # Writing a device name to /proc/acpi/wakeup toggles that device's wake enable.
        result = subprocess.run(
            ["sudo", "-n", "/usr/bin/tee", "/proc/acpi/wakeup"],
            input=name, capture_output=True, text=True, timeout=30,
        )
        return result.returncode == 0

    def _disarm_wake_sources(self, prefix: str) -> List[str]:
        """
        Disable every ACPI wake source except the RTC / power button, so a USB-C,
        Thunderbolt, USB, LAN or PCIe device cannot wake the SUT before the RTC alarm.
        Returns the names that were disabled (re-enable with _rearm_wake_sources).
        """
        all_names = [line.split()[0] for line in
                     self._read_text("/proc/acpi/wakeup").splitlines()[1:]
                     if line.strip() and not line.split()[0].startswith("*")]
        disarmed = []
        for name in self._enabled_wake_sources():
            if name in self.KEEP_WAKE_SOURCES:
                continue
            if all_names.count(name) > 1:
                # /proc/acpi/wakeup toggles only the first entry with a given name.
                logger.warning("%s Wake source %s is not unique — left enabled", prefix, name)
                continue
            if self._toggle_wake_source(name) and name not in self._enabled_wake_sources():
                disarmed.append(name)
            else:
                logger.warning(
                    "%s Could not disable wake source %s (sudo tee /proc/acpi/wakeup) — re-run "
                    "sudo ./deploy/setup/setup_sut.sh to add the passwordless rule", prefix, name,
                )
        logger.info("%s Wake sources disabled for the sleep cycle: %s", prefix, disarmed or "none")
        logger.info("%s Wake sources still armed: %s", prefix, self._enabled_wake_sources())
        return disarmed

    def _rearm_wake_sources(self, names: List[str], prefix: str) -> None:
        for name in names:
            if name not in self._enabled_wake_sources() and not self._toggle_wake_source(name):
                logger.warning("%s Could not re-enable wake source %s", prefix, name)
        if names:
            logger.info("%s Wake sources re-enabled: %s", prefix, names)

    @staticmethod
    def _boot_id() -> str:
        return Path("/proc/sys/kernel/random/boot_id").read_text(encoding="utf-8").strip()

    @staticmethod
    def _kernel_log_since(epoch: float, prefix: str) -> str:
        """Kernel messages of the current boot since `epoch` (journald; needs the adm group)."""
        result = subprocess.run(
            ["journalctl", "-k", "-b", "0", "--since", f"@{int(epoch)}", "-o", "cat", "--no-pager"],
            capture_output=True, text=True, timeout=120,
        )
        assert result.returncode == 0 and "insufficient permissions" not in result.stderr, (
            f"{prefix} Cannot read the kernel log (journalctl rc={result.returncode}: "
            f"{result.stderr.strip()}) — add the test user to the 'adm' group."
        )
        return result.stdout

    @staticmethod
    def _missing_in_order(text: str, expected: Tuple[str, ...]) -> List[str]:
        """Expected messages not found in `text` in the given order."""
        pos, missing = 0, []
        for msg in expected:
            idx = text.find(msg, pos)
            if idx < 0:
                missing.append(msg)
            else:
                pos = idx + len(msg)
        return missing
