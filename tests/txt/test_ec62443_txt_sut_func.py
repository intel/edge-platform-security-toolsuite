# Copyright 2026 Intel Corporation
# SPDX-License-Identifier: Apache-2.0

"""
TEST — IEC 62443-4-2  TXT  (Trusted Execution Technology, SUT-only execution)

Test ID:  IEC62443-4-2-TC_TXT-FUNC-SUT
Suite:    txt

PURPOSE
-------
Verifies Intel TXT end-to-end, running DIRECTLY ON THE SUT without a NUC
controller. TXT/TME knobs are set BEFORE the run; In-Band ECC starts Disabled and the
operator enables it once during the test (Step 4.1):
  - TXT and TME (vPro) active at the start and again at the end
  - IBECC Disabled at the start, MemTotal BEFORE; the operator reboots into BIOS Setup, enables
    IBECC, boots Ubuntu and creates the signal file; MemTotal AFTER must drop and IBECC_ACTIVATE
    must be set
  - TPM provisioning via UEFI shell scripts (AUX + SGX NV indices in the TPM)
  - TXT enabled by the BIOS (MSR 0x3A SENTER global enable + lock)
  - GETSEC[SENTER] reports "System is now in TXT Environment" and no new TXT.ERRORCODE
  - TME active on vPro silicon (MSR 0x982); MSR 0x981 capability logged

Unlike the NUC-SUT variant (test_ec62443_txt_func.py) which controls the SUT
via SSH + serial from an external NUC, this test:
  - Runs pytest directly on the SUT
  - Uses startup.nsh + systemd to survive reboots into UEFI shell

PHASES
------
  Phase 0 (OS):
    - Pre-checks (script paths, files on EFI; with Secure Boot on: signed getsec
      copy and TPM2ProvTool.efi signed in place)
    - TXT (MSR 0x3A) and TME on vPro (MSR 0x982) already active; IBECC (IBECC_ACTIVATE) Disabled
    - Read MemTotal BEFORE IBECC
    - Manual gate (Step 4.1): operator reboots into BIOS Setup, enables In-Band ECC, F4, boots
      Ubuntu, then creates step4_ibecc_enabled.txt. After the reboot the test only waits for that
      file; it goes on once the file is there, the SUT has rebooted, IBECC is active and MemTotal dropped.
    - MemTotal AFTER lower than BEFORE; IBECC active, TXT/TME still active
    - Write TPM provisioning UEFI script → reboot into UEFI shell

  UEFI Phase 1 (automated via startup.nsh):
    - ResetPlatformAuth.nsh
    - TPM2_CBnT_Prov.nsh
    - Tpm2SgxiProv.nsh
    - Write result file → state_done.txt → reset → boot OS

  Phase 1 (OS, resumed by systemd):
    - Verify TPM provisioning result: AUX (0x1C10102) and SGX (0x1C10104) NV indices
    - Save TXT.ERRORCODE, write GETSEC UEFI script → reboot into UEFI shell

  UEFI Phase 2 (automated via startup.nsh):
    - cd EFI → run getsec64 -L SENTER -a <SINIT> -v -tpr >a EFI\txt_getsec_result.txt
    - state_done.txt → reset → boot OS

  Phase 2 (OS, resumed by systemd):
    - Verify GETSEC[SENTER] recorded no new TXT.ERRORCODE; save TXT register dump
    - Verify the getsec output says the system entered the TXT environment
    - Log MSR 0x981 (TME capability)
    - TXT, TME (vPro) and IBECC still active
    - Cleanup + PASS

BIOS KNOBS (set before the run)
-------------------------------
  deploy/bios_knobs/bios_knobs.yaml -> txt: VT-d, Total Memory Encryption (vPro only),
  Intel Trusted Execution Technology, Alias Check Request = Enabled; In-Band ECC Support = Disabled.
  test_runner.py sets them in its pre-flight (AMISCE on an AMI BIOS, else BIOS Setup).
  In-Band ECC Support is enabled by the operator at Step 4.1.
  TXT takes effect only after a full power cycle (BIOS help text).
  Alias Check Request has no OS readback -- the test does not check it.

ONE-TIME SETUP (SUT)
--------------------
  1) startup.nsh on EFI partition:     /boot/efi/startup.nsh
  2) fw-validation-resume.service:     deploy/resume/fw-validation-resume.service
  3) TPM provisioning files on EFI:    /boot/efi/EFI/Tpm2ProvFilesCBnT-20251217/
  4) getsec tool on EFI:               /boot/efi/EFI/getsec64_v2.0.71.efi
  5) SINIT binary on EFI:              /boot/efi/EFI/<SINIT>.bin

CONFIG
------
  config/suites/txt_config.yaml  — all TXT/SUT-specific parameters
  config/test_config.yaml        — global settings

PRE-TEST (manual, performed once before running)
------------------------------------------------
  1.0)  Flash SUT with latest release IFWI and boot to Ubuntu OS.
  1.1)  Set the BIOS knobs above (In-Band ECC Support = Disabled), Save & Exit, full power cycle, boot Ubuntu.
  2.0)  Copy TPM provisioning files to SUT EFI partition:
          sudo cp -r Tpm2ProvFilesCBnT-20251217/ /boot/efi/EFI/
  3.0)  Copy getsec tool + SINIT binary to SUT EFI partition:
          sudo cp getsec64_v2.0.71.efi /boot/efi/EFI/
          sudo cp PTL_SINIT_*.bin /boot/efi/EFI/
  4.0)  startup.nsh installed at /boot/efi/startup.nsh (see deploy/resume/startup.nsh).
  5.0)  fw-validation-resume.service installed + enabled (see deploy/).

RUN (on SUT)
------------
  python -m pytest tests/txt/test_ec62443_txt_sut_func.py -v -s --setup-confirmed --yes
"""

import logging
import re
import subprocess
import time
from pathlib import Path

import pytest

from tests.sut_base_test import SUTBaseTest
from core.prereq import pre_test_check
from core.bios_knob_checks import read_msr, tme_supported

logger = logging.getLogger(__name__)

# Result files written by UEFI shell to the EFI partition
TPM_PROV_RESULT_FILE  = "txt_tpm_prov_result.txt"
GETSEC_RESULT_FILE    = "txt_getsec_result.txt"
GETSEC_SUCCESS_LINE   = "GETSEC[SENTER] complete. System is now in TXT Environment."

# Intel's provisioning tool (called by name from its .nsh scripts) and the logs those scripts write
TPM_PROV_TOOL = "TPM2ProvTool.efi"
TPM_PROV_LOGS = ("SetPlatformAuth.log", "TPM2_CBnT_Prov.log", "Tpm2SgxProv.log")

# TXT public space (0xFED30000) register offsets, as in tboot include/txt/config_regs.h
TXT_STS       = 0x000
TXT_ERRORCODE = 0x030
TXT_ERRORCODE_BEFORE_FILE = "txt_errorcode_before.txt"   # state folder, Step 7.0 -> 8.0

# MemTotal with IBECC off (state folder, Step 4.0 -> 4.2); state.json is rewritten every phase
MEM_BEFORE_FILE = "mem_before_kb.txt"
# Created by the operator after enabling In-Band ECC in BIOS Setup and booting Ubuntu again
SIGNAL_IBECC_ENABLED = "step4_ibecc_enabled.txt"

# Prints IBECC_ACTIVATE of the first argv[1] memory controllers; layout as in Linux igen6_edac (ADL and later):
# MCHBAR = host bridge config 0x48 bits 41:17, one 64 KiB window per MC, IBECC_ACTIVATE at +0xD400
IBECC_ACTIVATE_READ = (
    "import mmap,os,struct,sys\n"
    "cfg=open('/sys/bus/pci/devices/0000:00:00.0/config','rb').read(0x50)\n"
    "mchbar=struct.unpack('<Q',cfg[0x48:0x50])[0]\n"
    "if not mchbar&1: sys.exit('MCHBAR disabled')\n"
    "base=mchbar&((1<<42)-(1<<17))\n"
    "fd=os.open('/dev/mem',os.O_RDONLY)\n"
    "for mc in range(int(sys.argv[1])):\n"
    "    m=mmap.mmap(fd,0x10000,mmap.MAP_SHARED,mmap.PROT_READ,offset=base+mc*0x10000)\n"
    "    print(struct.unpack('<I',m[0xD400:0xD404])[0]); m.close()\n"
)


@pytest.mark.txt
@pytest.mark.manual
class TestEC62443TXTFuncSUT(SUTBaseTest):
    """
    IEC 62443-4-2 TXT full-flow test — SUT-only execution variant.

    Uses startup.nsh + systemd instead of NUC serial/SSH control.
    TXT/TME knobs are set before the run; the operator enables In-Band ECC at Step 4.1.
    """

    SUITE   = "txt"
    TEST_ID = "IEC62443-4-2-TC_TXT-FUNC-SUT"

    REBOOTS = (
        ("manual", "BIOS Setup: In-Band ECC Support = Enabled (Step 4.1), F4, boot Ubuntu, create the signal file"),
        ("auto", "UEFI Shell: TPM provisioning, then back to Ubuntu"),
        ("auto", "UEFI Shell: GETSEC[SENTER], then back to Ubuntu"),
    )

    PRE_TEST_CHECKLIST = [
        "1.0)  SUT flashed with latest release IFWI and booted to Ubuntu OS.",
        "1.1)  BIOS knobs before the run (bios_knobs.yaml -> txt; test_runner.py pre-flight sets them): "
        "VT-d, Total Memory Encryption (vPro), Intel Trusted Execution Technology, Alias Check Request = Enabled; "
        "In-Band ECC Support = Disabled (Step 4.1 enables it) -- then a full power cycle.",
        "2.0)  TPM provisioning files present on SUT EFI partition (see txt_config.yaml: tpm_prov_uefi_dir).",
        "3.0)  getsec tool + SINIT binary present on SUT EFI partition (see txt_config.yaml).",
        "4.0)  startup.nsh present at /boot/efi/startup.nsh (see deploy/resume/startup.nsh).",
        "SETUP) fw-validation-resume.service installed + enabled (see deploy/).",
    ]

    # ------------------------------------------------------------------
    # Entry point
    # ------------------------------------------------------------------

    def test_ec62443_txt_sut_func(
        self,
        request,
        config,
        log_dir,
    ):
        """
        IEC62443-4-2-TC_TXT-FUNC-SUT

        Multi-phase execution:
          Phase 0 : pre-checks + TXT/TME active, IBECC off + MemTotal BEFORE + manual IBECC gate
                    + MemTotal AFTER dropped + write TPM prov UEFI script + reboot
          UEFI 1  : TPM provisioning scripts (automated)
          Phase 1 : verify TPM prov + write GETSEC script + reboot
          UEFI 2  : GETSEC[SENTER] (automated)
          Phase 2 : verify GETSEC + TXT/TME/IBECC still active + cleanup
        """
        self._begin()
        cfg = self._load_config(config)
        self._init_state_dir(cfg)

        pre_test_check(request, self.TEST_ID, self.PRE_TEST_CHECKLIST)

        # ------------------------------------------------------------------
        # Config
        # ------------------------------------------------------------------
        tpm_prov_uefi_dir  = cfg.get("tpm_prov_uefi_dir",  r"EFI\Tpm2ProvFilesCBnT-20251217")
        getsec_uefi_dir    = cfg.get("getsec_uefi_dir",    "EFI")
        getsec_tool        = cfg.get("getsec_tool",        "getsec64_v2.0.71.efi")
        sinit_binary       = cfg.get("sinit_binary",       "")
        # Auto-detected (CPUID.07H:ECX[13]) instead of a manual config flag -- TME support is a
        # property of the silicon, not something the operator should have to track per SUT.
        tme_capable, tme_how = tme_supported()
        is_vpro_silicon = bool(tme_capable)

        logger.info("[Config] tpm_prov_uefi_dir : %s", tpm_prov_uefi_dir)
        logger.info("[Config] getsec_uefi_dir   : %s", getsec_uefi_dir)
        logger.info("[Config] getsec_tool        : %s", getsec_tool)
        logger.info("[Config] sinit_binary       : %s", sinit_binary)
        logger.info("[Detect] TME capable (vPro) : %s (%s)", is_vpro_silicon, tme_how)

        mgr   = self._state_mgr
        efi_mount_cfg = cfg.get("sut_efi_mount", "/boot/efi")
        self._remove_at_test_end(
            Path(efi_mount_cfg) / TPM_PROV_RESULT_FILE,
            Path(self._uefi_path_to_linux(tpm_prov_uefi_dir, efi_mount_cfg)) / TPM_PROV_RESULT_FILE,
            Path(self._uefi_path_to_linux(getsec_uefi_dir, efi_mount_cfg)) / GETSEC_RESULT_FILE,
            Path(mgr.state_dir) / MEM_BEFORE_FILE,
            Path(mgr.state_dir) / TXT_ERRORCODE_BEFORE_FILE,
        )
        state = mgr.get_state()
        phase = state.get("phase", 0)
        logger.info("[State] phase=%s  state=%s", phase, state)

        # ------------------------------------------------------------------
        # PHASE 0 — Pre-checks + IBECC off + MemTotal BEFORE + manual IBECC gate + TPM prov script
        # ------------------------------------------------------------------
        if phase == 0:
            logger.info("=" * 60)
            logger.info("PHASE 0 — Pre-checks, IBECC Disabled -> Enabled (MemTotal), TPM provisioning")
            logger.info("=" * 60)

            # Step 2.0 — Verify TPM provisioning files on EFI
            self._step_verify_efi_files(cfg, step_label="2.0")

            # Step 2.1 — Fail early if Secure Boot needs a signed getsec copy that is missing
            getsec_linux_dir = self._uefi_path_to_linux(
                getsec_uefi_dir, cfg.get("sut_efi_mount", "/boot/efi"))
            self._select_efi_tool(getsec_linux_dir, getsec_tool, step_label="2.1")

            # Step 2.2 — Intel's .nsh scripts run TPM2ProvTool.efi by name: with Secure Boot on it must be signed in place
            prov_tool = Path(self._uefi_path_to_linux(
                tpm_prov_uefi_dir, cfg.get("sut_efi_mount", "/boot/efi"))) / TPM_PROV_TOOL
            if self._is_secure_boot_enabled(step_label="2.2"):
                assert prov_tool.is_file(), f"[Step 2.2] {prov_tool} not found in the TPM provisioning folder."
                assert self._pe_has_signature(prov_tool), (
                    f"[Step 2.2] Secure Boot is enabled but {prov_tool} is unsigned.\n"
                    "  Intel's provisioning scripts call it by this name, so the firmware would refuse it\n"
                    "  and no NV index would be created. Sign it in place on the SUT:\n"
                    "    sudo ./deploy/secure_boot/sign_efi_tools.sh"
                )
                logger.info("[Step 2.2] [OK] %s is signed", prov_tool)

            mem_before_path = Path(mgr.state_dir) / MEM_BEFORE_FILE
            # Resumed after the operator's BIOS Setup reboot: IBECC may be on now, keep the Step 4.0 baseline
            if state.get("sub") == f"gate_{SIGNAL_IBECC_ENABLED}" and mem_before_path.exists():
                mem_before_kb = int(mem_before_path.read_text(encoding="utf-8").strip())
                logger.info("[Step 4.0] Resumed at Step 4.1 -- MemTotal BEFORE from Step 4.0: %d kB (%.2f GB)",
                            mem_before_kb, mem_before_kb / 1024 / 1024)
            else:
                # Step 3.0 — TXT and TME (vPro) set before the run; IBECC must still be off for the BEFORE baseline
                self._step_verify_features_active(is_vpro_silicon, ibecc_expected=False, step_label="3.0")
                logger.info("[Step 3.0] Alias Check Request: no OS readback -- not checked (checklist 1.1)")

                # Step 4.0 — MemTotal BEFORE IBECC
                mem_before_kb = self._step_read_memtotal_local(label="BEFORE (IBECC disabled)", step_label="4.0")
                self._write_read_only(mem_before_path, str(mem_before_kb))
                logger.info("[Step 4.0] mem_before_kb saved: %s", mem_before_path)

            # Step 4.1 — Manual gate: operator enables IBECC in BIOS Setup, boots, then creates the signal file
            self._wait_for_manual_signal(
                signal_file=SIGNAL_IBECC_ENABLED,
                step_label="4.1",
                timeout_secs=int(cfg.get("manual_gate_timeout_secs", 900)),
                requires_reboot=True,
                verify=self._ibecc_enabled_verifier(mem_before_kb),
                instructions=[
                    "─" * 60,
                    "STEP 4.1 — MANUAL ACTION REQUIRED: enable In-Band ECC",
                    "─" * 60,
                    "",
                    "  1) Reboot and press F2 during POST to enter BIOS Setup",
                    "     (or: sudo systemctl reboot --firmware-setup).",
                    "  2) Intel Advanced Menu → Memory Configuration → In-Band ECC support → Enabled",
                    "  3) Leave every other setting as it is (TXT, TME, VT-d stay Enabled).",
                    "  4) Press F4 to save and exit, let the SUT boot Ubuntu.",
                    "  5) Create the signal file below -- the test waits for it after the reboot",
                    "     and only then checks IBECC and MemTotal.",
                    "─" * 60,
                ],
            )

            # Step 4.2 — IBECC reserves part of DRAM, so MemTotal must drop
            mem_after_kb = self._step_read_memtotal_local(label="AFTER (IBECC enabled)", step_label="4.2")
            self._step_verify_memory(mem_before_kb, mem_after_kb, step_label="4.2")
            mem_before_path.unlink(missing_ok=True)

            # Step 4.3 — The drop must come from IBECC; the BIOS visit must not have turned TXT/TME off
            self._step_verify_features_active(is_vpro_silicon, step_label="4.3")

            # Step 5.0 — Write UEFI script for TPM provisioning
            logger.info("[Step 5.0] Writing TPM provisioning UEFI script")
            uefi_commands = [
                f"cd {tpm_prov_uefi_dir}",
                # '>a' captures both stdout AND stderr (UEFI Shell 2.x syntax)
                f"ResetPlatformAuth.nsh SHA256 Example >a {TPM_PROV_RESULT_FILE}",
                f"TPM2_CBnT_Prov.nsh SHA256 Example >>a {TPM_PROV_RESULT_FILE}",
                f"Tpm2SgxiProv.nsh sha256 example >>a {TPM_PROV_RESULT_FILE}",
                # cd back to EFI root, copy result file so Linux can read it
                "cd \\",
                f"copy {tpm_prov_uefi_dir}\\{TPM_PROV_RESULT_FILE} {TPM_PROV_RESULT_FILE}",
            ]
            self._write_uefi_phase(
                phase=1,
                uefi_commands=uefi_commands,
                result_filename=TPM_PROV_RESULT_FILE,
                step_label="5.0",
            )
            logger.info("[Step 5.0] Rebooting into UEFI shell for TPM provisioning ...")
            self._reboot_into_uefi(step_label="5.0")
            # ← does not return; systemd resumes at Phase 1

        # ------------------------------------------------------------------
        # PHASE 1 — Verify TPM prov + write GETSEC script
        # ------------------------------------------------------------------
        if phase == 1:
            logger.info("=" * 60)
            logger.info("PHASE 1 — Verify TPM prov + GETSEC script")
            logger.info("=" * 60)

            # Step 6.0 — Verify UEFI TPM provisioning completed
            assert self._check_phase_done(phase=1, step_label="6.0"), (
                "[Step 6.0] UEFI TPM provisioning phase did not complete.\n"
                f"  Check: {mgr.efi_mount}/state_done.txt"
            )
            mgr.mark_phase_done(1)

            # Steps 6.1–6.5: verify TPM provisioning from the OS (tpm2-tools). The script
            # output is only a hint: not every firmware captures nested .nsh output.
            aux_nv_index = str(cfg.get("aux_nv_index", "0x1C10102"))
            sgx_nv_index = str(cfg.get("sgx_nv_index", "0x1C10104"))

            # Step 6.1 — Check NV indices exist (tpm2_getcap handles-nv-index)
            logger.info("[Step 6.1] Verifying TPM NV indices from OS (tpm2_getcap)")
            nv_result = subprocess.run(
                ["sudo", "tpm2_getcap", "handles-nv-index"],
                capture_output=True, text=True, timeout=30,
            )
            assert nv_result.returncode == 0, (
                f"[Step 6.1] tpm2_getcap failed (rc={nv_result.returncode}):\n"
                f"  {nv_result.stderr.strip()}"
            )
            nv_present = {int(h, 16) for h in re.findall(r"0x[0-9a-fA-F]+", nv_result.stdout)}
            logger.info("[Step 6.1] NV indices found:\n%s", nv_result.stdout.strip())

            # Step 6.2 — PlatformAuth reset by ResetPlatformAuth.nsh (from the provisioning output)
            prov_text = self._step_save_tpm_prov_output(cfg, tpm_prov_uefi_dir, log_dir, step_label="6.2")
            hint = self._tpm_prov_failure_hint(prov_text)
            assert "Did not satisfy PlatformPolicy" not in prov_text, (
                "[Step 6.2] ResetPlatformAuth.nsh could not set PlatformAuth to EMPTY.\n" + hint
            )
            if "Successfully set PlatformAuth to EMPTY" in prov_text:
                logger.info("[Step 6.2] [OK] PlatformAuth set to EMPTY")
            else:
                logger.info("[Step 6.2] PlatformAuth result not in the captured output -- "
                            "checked through the NV indices (Steps 6.3-6.4)")

            # Step 6.3 — AUX NV Index (Tpm2_CBnT_Prov.nsh, AuxSha256.iDef): the script only defines it
            # (no NvWrite); the ACM writes its data later, so 'written' is not expected yet.
            self._step_verify_nv_index("AUX", aux_nv_index, nv_present, hint,
                                       required_attr="platformcreate", step_label="6.3")

            # Step 6.4 — SGX NV Index (Tpm2SgxiProv.nsh, ExampleSgxSha256.iDef) is defined and written
            self._step_verify_nv_index("SGX", sgx_nv_index, nv_present, hint,
                                       required_attr="written", step_label="6.4")

            # Step 6.5 — No errors (both indices present with the expected attributes)
            logger.info("[Step 6.5] [OK] No errors — TPM provisioning verified from OS")
            logger.info("[Step 6.0] [OK] All TPM provisioning checks passed (6.1–6.5)")

            # Step 7.0 — Baseline TXT.ERRORCODE (it survives warm resets), then write the GETSEC[SENTER] UEFI script
            errorcode_before = self._read_txt_reg(TXT_ERRORCODE, step_label="7.0") & 0xFFFFFFFF
            self._write_read_only(Path(mgr.state_dir) / TXT_ERRORCODE_BEFORE_FILE, f"0x{errorcode_before:08X}")
            logger.info("[Step 7.0] TXT.ERRORCODE before GETSEC[SENTER] = 0x%08X", errorcode_before)
            logger.info("[Step 7.0] Writing GETSEC[SENTER] UEFI script")
            getsec_linux_dir = self._uefi_path_to_linux(
                getsec_uefi_dir, cfg.get("sut_efi_mount", "/boot/efi"))
            getsec_run = self._select_efi_tool(getsec_linux_dir, getsec_tool, step_label="7.0")
            getsec_cmd = f"{getsec_run} -L SENTER -a {sinit_binary} -v -tpr"
            # A result file left by an earlier run would make Step 8.1 pass without a launch
            getsec_result = Path(getsec_linux_dir) / GETSEC_RESULT_FILE
            if getsec_result.exists():
                logger.info("[Step 7.0] Removing stale %s", getsec_result)
                mgr._remove_efi_file(getsec_result)
            assert not getsec_result.exists(), f"[Step 7.0] Could not remove stale {getsec_result}"
            uefi_commands = [
                f"cd {getsec_uefi_dir}",
                f"{getsec_cmd} >a {GETSEC_RESULT_FILE}",
            ]
            self._write_uefi_phase(
                phase=2,
                uefi_commands=uefi_commands,
                step_label="7.0",
            )
            logger.info("[Step 7.0] Rebooting into UEFI shell for GETSEC[SENTER] ...")
            self._reboot_into_uefi(step_label="7.0")
            # ← does not return; systemd resumes at Phase 2

        # ------------------------------------------------------------------
        # PHASE 2 — Verify GETSEC + TXT/TME/IBECC still active + done
        # ------------------------------------------------------------------
        logger.info("=" * 60)
        logger.info("PHASE 2 — Verify GETSEC[SENTER] + TXT/TME/IBECC still active")
        logger.info("=" * 60)

        # Step 8.0 — GETSEC[SENTER] result: a failed launch makes the ACM write TXT.ERRORCODE and reset
        assert self._check_phase_done(phase=2, step_label="8.0"), (
            "[Step 8.0] UEFI GETSEC phase did not complete.\n"
            f"  Check: {mgr.efi_mount}/state_done.txt"
        )
        mgr.mark_phase_done(2)

        # Register dump first so a failure below still leaves it in the log folder
        self._step_save_txt_register_log(log_dir, mgr, step_label="8.0")
        txt_sts = self._read_txt_reg(TXT_STS, step_label="8.0")
        errorcode = self._read_txt_reg(TXT_ERRORCODE, step_label="8.0") & 0xFFFFFFFF
        before_path = Path(mgr.state_dir) / TXT_ERRORCODE_BEFORE_FILE
        errorcode_before = None
        if before_path.exists():
            errorcode_before = int(before_path.read_text(encoding="utf-8").strip(), 16)
            before_path.unlink()
        before_txt = "unknown" if errorcode_before is None else f"0x{errorcode_before:08X}"
        logger.info("[Step 8.0] TXT.STS = 0x%016X (SEXIT.DONE = %d is set after every reset -- not used as proof)",
                    txt_sts, (txt_sts >> 1) & 1)
        logger.info("[Step 8.0] TXT.ERRORCODE = 0x%08X (before GETSEC[SENTER]: %s)", errorcode, before_txt)
        assert not (errorcode >> 31 and errorcode != errorcode_before), (
            f"[Step 8.0] GETSEC[SENTER] failed: TXT.ERRORCODE = 0x{errorcode:08X} (before SENTER: {before_txt}).\n"
            "  Bit 31 = valid error, bit 30 = reported by the ACM; decode it with the SINIT ACM error tables.\n"
            "  Usual causes: TPM not provisioned, SINIT does not match the CPU, TXT/VT-d settings.\n"
            "  Register dump: txt_registers.txt in the log folder."
        )
        logger.info("[Step 8.0] [OK] No new TXT error recorded after GETSEC[SENTER]")

        # Step 8.1 — getsec64 output: the launch itself must report the TXT environment
        efi_mount       = cfg.get("sut_efi_mount", "/boot/efi")
        getsec_efi_path = Path(self._uefi_path_to_linux(getsec_uefi_dir, efi_mount)) / GETSEC_RESULT_FILE
        artifact_local  = log_dir / GETSEC_RESULT_FILE
        assert getsec_efi_path.is_file(), (
            f"[Step 8.1] {getsec_efi_path} not found -- getsec64 did not run, or its output was not captured.\n"
            "  Check the UEFI screen / serial console of the GETSEC boot."
        )
        getsec_text = self._read_uefi_text(getsec_efi_path)
        artifact_local.write_text(getsec_text, encoding="utf-8")
        logger.info("[Step 8.1] getsec output saved: %s", artifact_local)
        for line in getsec_text.strip().splitlines():
            logger.info("[Step 8.1]   | %s", line)
        assert GETSEC_SUCCESS_LINE in getsec_text, (
            f"[Step 8.1] GETSEC[SENTER] did not report the TXT environment: \"{GETSEC_SUCCESS_LINE}\" "
            f"is not in {getsec_efi_path}.\n"
            "  The measured launch did not complete; see the getsec output above and txt_registers.txt."
        )
        logger.info("[Step 8.1] [OK] %s", GETSEC_SUCCESS_LINE)

        # Step 9.0 — Read MSR 0x981: informational only (never fails the test) — it just
        # reports whether this silicon supports TME, it is not an IEC 62443 TXT pass/fail gate.
        self._step_verify_msr(cfg, step_label="9.0")

        # Step 9.1 — Provisioning, SENTER and the resets must not have turned any feature off
        ibecc_how = self._step_verify_features_active(is_vpro_silicon, step_label="9.1")

        mgr.cleanup()
        logger.info(
            "[OK] TXT checks passed — IBECC enabled with memory reduction, AUX/SGX NV indices provisioned, "
            "TXT enabled (MSR 0x3A), GETSEC[SENTER] entered the TXT environment with no new TXT.ERRORCODE, "
            "%s, IBECC: %s",
            "TME active (MSR 0x982)" if is_vpro_silicon else "no TME on this silicon",
            ibecc_how,
        )
        logger.info("getsec output: %s (copy in the log folder)", getsec_efi_path)
        self._end()

    # ------------------------------------------------------------------
    # Step helpers
    # ------------------------------------------------------------------

    def _step_verify_efi_files(self, cfg: dict, step_label: str = "") -> None:
        """Verify required files exist on the SUT EFI partition."""
        prefix = f"[Step {step_label}]" if step_label else "[Pre-check]"
        efi_mount     = cfg.get("sut_efi_mount",      "/boot/efi")
        getsec_dir    = cfg.get("getsec_uefi_dir",    "EFI")
        getsec_tool   = cfg.get("getsec_tool",        "getsec64_v2.0.71.efi")
        sinit_binary  = cfg.get("sinit_binary",       "")
        tpm_prov_dir  = cfg.get("tpm_prov_uefi_dir",  r"EFI\TPM2ProvfilesCBnT-202409165")

        # Convert UEFI-style paths to Linux paths
        getsec_linux_dir   = self._uefi_path_to_linux(getsec_dir,  efi_mount)
        tpm_prov_linux_dir = self._uefi_path_to_linux(tpm_prov_dir, efi_mount)

        logger.info("%s Verifying files on EFI partition", prefix)

        # getsec tool
        getsec_path = Path(getsec_linux_dir) / getsec_tool
        assert getsec_path.exists(), (
            f"{prefix} getsec tool not found: {getsec_path}\n"
            f"  Copy it: sudo cp {getsec_tool} {getsec_linux_dir}/"
        )
        logger.info("%s [OK] %s", prefix, getsec_path)

        # SINIT binary
        if sinit_binary:
            sinit_path = Path(getsec_linux_dir) / sinit_binary
            assert sinit_path.exists(), (
                f"{prefix} SINIT binary not found: {sinit_path}\n"
                f"  Copy it: sudo cp {sinit_binary} {getsec_linux_dir}/"
            )
            logger.info("%s [OK] %s", prefix, sinit_path)

        # TPM provisioning directory
        assert Path(tpm_prov_linux_dir).is_dir(), (
            f"{prefix} TPM provisioning directory not found: {tpm_prov_linux_dir}\n"
            f"  Copy it: sudo cp -r Tpm2ProvFilesCBnT-20251217/ {Path(efi_mount) / 'EFI'}/"
        )
        logger.info("%s [OK] TPM prov dir: %s", prefix, tpm_prov_linux_dir)

    def _step_verify_features_active(self, is_vpro_silicon: bool, step_label: str,
                                     ibecc_expected: bool = True) -> str:
        """Assert TXT and TME (vPro only) are active and IBECC is in the expected state; returns the IBECC evidence."""
        prefix = f"[Step {step_label}]"
        knobs_hint = ("  The txt BIOS knobs (deploy/bios_knobs/bios_knobs.yaml) must be set before the run --\n"
                      "  test_runner.py pre-flight sets them; then do a full power cycle.")

        # IA32_FEATURE_CONTROL: the BIOS sets bit 15 (SENTER global enable) and locks it (bit 0)
        feature_control, fc_how = read_msr(0x3A)
        assert feature_control is not None, f"{prefix} MSR 0x3A not readable: {fc_how}"
        senter_enabled = (feature_control >> 15) & 1
        fc_locked = feature_control & 1
        logger.info("%s MSR 0x3A IA32_FEATURE_CONTROL = 0x%X (SENTER global enable = %d, lock = %d)",
                    prefix, feature_control, senter_enabled, fc_locked)
        assert senter_enabled and fc_locked, (
            f"{prefix} TXT is not enabled: MSR 0x3A = 0x{feature_control:X} "
            f"(SENTER global enable = {senter_enabled}, lock = {fc_locked}; both must be 1).\n"
            "  BIOS Setup -> Intel Advanced Menu -> CPU Configuration -> Intel Trusted Execution Technology = Enabled.\n"
            "  If it is already Enabled: full power cycle, and check TPM and VT-d are enabled.\n" + knobs_hint
        )
        logger.info("%s [OK] TXT enabled by the BIOS", prefix)

        if is_vpro_silicon:
            tme_activate, tme_act_how = read_msr(0x982)
            assert tme_activate is not None, f"{prefix} MSR 0x982 not readable: {tme_act_how}"
            logger.info("%s MSR 0x982 IA32_TME_ACTIVATE = 0x%X (lock = %d, TME enable = %d)",
                        prefix, tme_activate, tme_activate & 1, (tme_activate >> 1) & 1)
            assert (tme_activate >> 1) & 1, (
                f"{prefix} TME is not active: MSR 0x982 = 0x{tme_activate:X} (bit 1 TME enable = 0).\n"
                "  BIOS Setup -> Intel Advanced Menu -> CPU Configuration -> Total Memory Encryption = Enabled.\n"
                + knobs_hint
            )
            logger.info("%s [OK] TME active", prefix)
        else:
            logger.info("%s Non-vPro silicon (no TME) -- TME activation not checked", prefix)

        ibecc_on, ibecc_how = self._ibecc_state_from_os()
        logger.info("%s In-Band ECC: %s", prefix, ibecc_how)
        if not ibecc_expected:
            assert ibecc_on is not True, (
                f"{prefix} In-Band ECC is already ENABLED -- the test needs it Disabled at the start\n"
                "  (Step 4.2 compares MemTotal before and after Step 4.1 enables it).\n"
                "  BIOS Setup -> Intel Advanced Menu -> Memory Configuration -> In-Band ECC support = Disabled,\n"
                "  Save & Exit (F4), boot Ubuntu, then run the test again."
            )
            if ibecc_on is None:
                logger.info("%s In-Band ECC state not readable from the OS -- relying on checklist 1.1", prefix)
            else:
                logger.info("%s [OK] In-Band ECC is Disabled", prefix)
            return ibecc_how
        assert ibecc_on is True, (
            f"{prefix} In-Band ECC is not confirmed active: {ibecc_how}.\n"
            "  BIOS Setup -> Intel Advanced Menu -> Memory Configuration -> In-Band ECC support = Enabled.\n"
            "  If it is Enabled but the state is unknown: sudo modprobe igen6_edac"
        )
        logger.info("%s [OK] In-Band ECC active", prefix)
        return ibecc_how

    def _ibecc_enabled_verifier(self, mem_before_kb: int):
        """verify= callable for the Step 4.1 gate: IBECC_ACTIVATE set and MemTotal below the Step 4.0 value."""
        def verify():
            ibecc_on, ibecc_how = self._ibecc_state_from_os()
            mem_now_kb = self._step_read_memtotal_local(label="now", step_label="4.1")
            evidence = [
                f"In-Band ECC: {ibecc_how}",
                f"MemTotal: {mem_before_kb} kB before (Step 4.0) -> {mem_now_kb} kB now (must be lower)",
            ]
            return ibecc_on is True and mem_now_kb < mem_before_kb, evidence
        return verify

    @staticmethod
    def _step_verify_memory(mem_before_kb: int, mem_after_kb: int, step_label: str = "") -> None:
        """Verify IBECC reduced visible memory after the BIOS change."""
        prefix = f"[Step {step_label}]" if step_label else "[Memory]"
        logger.info("%s MemTotal BEFORE = %d kB (%.2f GB)", prefix, mem_before_kb, mem_before_kb / 1024 / 1024)
        logger.info("%s MemTotal AFTER  = %d kB (%.2f GB)", prefix, mem_after_kb, mem_after_kb / 1024 / 1024)
        assert mem_before_kb > 0, (
            f"{prefix} MemTotal BEFORE (Step 4.0) is not available -- {MEM_BEFORE_FILE} was lost,\n"
            "  so the memory reduction cannot be verified. Run the test again from the start."
        )
        diff_kb = mem_before_kb - mem_after_kb
        logger.info("%s Memory reduction = %d kB (%.1f MB)", prefix, diff_kb, diff_kb / 1024)
        assert mem_after_kb < mem_before_kb, (
            f"{prefix} Expected MemTotal to DECREASE after enabling IBECC -- IBECC is not enabled.\n"
            f"  Before : {mem_before_kb} kB ({mem_before_kb / 1024 / 1024:.2f} GB)\n"
            f"  After  : {mem_after_kb} kB ({mem_after_kb / 1024 / 1024:.2f} GB)\n"
            "  BIOS Setup -> Intel Advanced Menu -> Memory Configuration -> In-Band ECC support = Enabled."
        )
        logger.info("%s [OK] MemTotal dropped by %.1f MB — IBECC enabled", prefix, diff_kb / 1024)

    @staticmethod
    def _ibecc_state_from_os() -> tuple:
        """
        (True/False/None, how) -- In-Band ECC state from IBECC_ACTIVATE of each memory controller.
        A registered igen6_edac "Intel_client_SoC MC#n" is not proof: with IBECC disabled the
        IBECC block reads all-ones, which the driver takes as active. No registered MC with the
        driver loaded means off; without the driver (kernel/SoC not supported) -> None.
        """
        mc_names = []
        for name_file in sorted(Path("/sys/devices/system/edac/mc").glob("mc*/mc_name")):
            try:
                mc_names.append(name_file.read_text(encoding="utf-8").strip())
            except OSError:
                continue
        ibecc_mcs = [n for n in mc_names if "Intel_client_SoC" in n]
        if not ibecc_mcs:
            if Path("/sys/module/igen6_edac").is_dir():
                return False, "Disabled (igen6_edac loaded, no IBECC memory controller registered)"
            return None, "unknown (igen6_edac driver not loaded on this kernel/SoC)"

        result = subprocess.run(
            ["sudo", "python3", "-c", IBECC_ACTIVATE_READ, str(len(ibecc_mcs))],
            capture_output=True, text=True, timeout=15,
        )
        values = [int(v) for v in result.stdout.split()] if result.returncode == 0 else []
        if len(values) != len(ibecc_mcs):
            return None, (f"unknown (igen6_edac registered {len(ibecc_mcs)} MC(s), IBECC_ACTIVATE not readable: "
                          f"{result.stderr.strip() or result.stdout.strip()})")
        regs = ", ".join(f"MC{i} IBECC_ACTIVATE=0x{v:08X}" for i, v in enumerate(values))
        active = [v != 0xFFFFFFFF and bool(v & 1) for v in values]
        if all(active):
            return True, f"ENABLED ({regs})"
        if not any(active):
            return False, f"Disabled ({regs}; 0xFFFFFFFF = IBECC block off, igen6_edac registration ignored)"
        return None, f"unknown (memory controllers disagree: {regs})"

    @staticmethod
    def _read_uefi_text(path: Path) -> str:
        """Text of a file written in the UEFI Shell (UTF-16 with or without BOM, or ASCII)."""
        data = path.read_bytes()
        if data[:2] == b"\xff\xfe" or data[1:2] == b"\x00":
            return data.decode("utf-16-le", errors="replace").lstrip("\ufeff").replace("\r", "")
        return data.decode("utf-8", errors="replace").replace("\r", "")

    def _step_save_tpm_prov_output(self, cfg: dict, tpm_prov_uefi_dir: str, log_dir: Path,
                                   step_label: str = "") -> str:
        """
        Save the provisioning script output and Intel's own provisioning logs as artifacts.
        Returns the script output of this run (the result file is deleted before each run).
        """
        prefix = f"[Step {step_label}]" if step_label else "[TPM prov]"
        efi_mount = cfg.get("sut_efi_mount", "/boot/efi")
        prov_dir = Path(self._uefi_path_to_linux(tpm_prov_uefi_dir, efi_mount))
        result_path = Path(efi_mount) / TPM_PROV_RESULT_FILE

        prov_text = ""
        for src in (result_path, *(prov_dir / name for name in TPM_PROV_LOGS)):
            if not src.is_file():
                logger.info("%s %s not found", prefix, src)
                continue
            text = self._read_uefi_text(src)
            artifact = Path(log_dir) / f"txt_prov_{src.name}"
            artifact.write_text(text, encoding="utf-8")
            logger.info("%s Saved %s (modified %s) -> %s", prefix, src,
                        time.strftime("%Y-%m-%d %H:%M", time.localtime(src.stat().st_mtime)), artifact)
            if src == result_path:
                prov_text = text
        for line in prov_text.strip().splitlines():
            logger.info("%s   | %s", prefix, line)
        return prov_text

    @staticmethod
    def _tpm_prov_failure_hint(prov_text: str) -> str:
        """Likely cause of a failed provisioning run, from the script output of this run."""
        if re.search(r"Security Violation|Access Denied", prov_text, re.IGNORECASE):
            return (f"  Cause: the firmware refused {TPM_PROV_TOOL} (Secure Boot). Sign it in place:\n"
                    "    sudo ./deploy/secure_boot/sign_efi_tools.sh\n")
        if "Did not satisfy PlatformPolicy" in prov_text or "PlatformAuth is not EMPTY" in prov_text:
            return ("  Cause: ResetPlatformAuth.nsh could not satisfy the platform authPolicy, so PlatformAuth\n"
                    "  stayed set and every provisioning script stopped ('PlatformAuth is not EMPTY').\n"
                    "  The BIOS has not installed the platform policy Intel TXT provisioning needs (seen on\n"
                    "  OEM/AMI BIOS). Check AMI Aptio Setup -> Security -> Platform Hierarchy = [Enabled]. If it\n"
                    "  already is, this BIOS cannot be TXT-provisioned from the UEFI Shell -- the BIOS vendor must\n"
                    "  provide a build that installs the Intel TXT platform authPolicy (as the Intel reference BIOS does).\n"
                    "  Details: txt_prov_SetPlatformAuth.log in the log folder.\n")
        if not prov_text.strip():
            return ("  Cause: no provisioning output was captured. If Secure Boot is on, an unsigned\n"
                    f"  {TPM_PROV_TOOL} is refused: sudo ./deploy/secure_boot/sign_efi_tools.sh\n")
        return "  See the provisioning output (txt_prov_*) in the log folder.\n"

    def _step_verify_nv_index(self, name: str, index: str, present: set, hint: str,
                              required_attr: str, step_label: str = "") -> None:
        """Assert a provisioning NV index exists and carries required_attr (e.g. 'written')."""
        prefix = f"[Step {step_label}]" if step_label else "[NV]"
        found = ", ".join(f"0x{h:X}" for h in sorted(present)) or "none"
        assert int(index, 16) in present, (
            f"{prefix} {name} NV Index ({index}) not found in the TPM -- provisioning did not create it.\n"
            f"{hint}"
            f"  NV indices present: {found}"
        )
        pub = subprocess.run(
            ["sudo", "tpm2_nvreadpublic", index],
            capture_output=True, text=True, timeout=30,
        )
        attrs = re.search(r"friendly:\s*(\S*\|\S*)", pub.stdout)
        attrs = attrs.group(1) if attrs else pub.stdout
        logger.info("%s %s NV Index (%s) attributes: %s", prefix, name, index, attrs)
        assert required_attr in attrs, (
            f"{prefix} {name} NV Index ({index}) exists but is not marked '{required_attr}'.\n"
            f"  Output: {pub.stdout}{pub.stderr}"
        )
        logger.info("%s [OK] %s NV Index (%s) provisioned -- %s", prefix, name, index, required_attr)

    def _step_read_memtotal_local(self, label: str, step_label: str = "") -> int:
        """Read MemTotal from /proc/meminfo on the local SUT."""
        prefix = f"[Step {step_label}]" if step_label else "[MemTotal]"
        logger.info("%s Reading MemTotal (%s)", prefix, label)
        result = subprocess.run(
            ["grep", "MemTotal", "/proc/meminfo"],
            capture_output=True, text=True, timeout=10,
        )
        output = result.stdout.strip()
        assert "MemTotal" in output, f"{prefix} MemTotal not found in /proc/meminfo"
        parts = output.split()
        assert len(parts) >= 2, f"{prefix} Could not parse MemTotal line: {output!r}"
        kb = int(parts[1])
        logger.info("%s MemTotal %s = %d kB (%.1f GB)", prefix, label, kb, kb / 1024 / 1024)
        return kb

    def _step_verify_msr(self, cfg: dict, step_label: str = "") -> None:
        """Report MSR 0x981 (IA32_TME_CAPABILITY): bits[35:32] non-zero => TME capability
        supported (per Intel SDM), and bit[2] == 1 => AES-XTS 256-bit algorithm supported.
        Informational only (never fails the test) — non-vPro silicon has no TME at all, and
        this check exists only to tell the operator which kind of silicon they are running."""
        prefix = f"[Step {step_label}]" if step_label else "[MSR]"
        msr_address = cfg.get("msr_address", "0x981")

        logger.info("%s Reading MSR %s", prefix, msr_address)
        result = subprocess.run(
            ["sudo", "rdmsr", msr_address],
            capture_output=True, text=True, timeout=15,
        )
        if result.returncode != 0:
            logger.info(
                "%s MSR %s not readable (rc=%d: %s) — TME capability NOT supported on this silicon.",
                prefix, msr_address, result.returncode, result.stderr.strip(),
            )
            return
        msr_hex = result.stdout.strip().lower().lstrip("0x")
        msr_int = int(msr_hex, 16)
        logger.info("%s MSR %s raw value = 0x%s", prefix, msr_address, msr_hex)

        # Bits[35:32] non-zero => TME capability supported (Intel SDM IA32_TME_CAPABILITY).
        tme_key_bits = (msr_int >> 32) & 0xF
        if tme_key_bits == 0:
            logger.info(
                "%s TME capability NOT supported on this silicon (MSR %s bits[35:32] == 0).",
                prefix, msr_address,
            )
            return
        logger.info("%s [OK] TME capability supported (bits[35:32]=0x%x)", prefix, tme_key_bits)

        # Bit[2] = 1 → AES-XTS 256-bit supported
        if not (msr_int >> 2) & 1:
            logger.info("%s MSR %s bit[2] is 0 — AES-XTS 256-bit NOT supported.", prefix, msr_address)
            return
        logger.info("%s [OK] AES-XTS 256-bit supported (bit[2]=1)", prefix)

    def _step_save_txt_register_log(
        self,
        log_dir: Path,
        mgr,
        step_label: str = "",
    ) -> None:
        """
        Read TXT Public Space registers from /dev/mem and save as a log artifact.

        Saved to log_dir/txt_registers.txt (per-run artifact, local logs/).
        """
        import mmap, struct, os as _os
        prefix = f"[Step {step_label}]" if step_label else "[TXT Registers]"
        TXT_PUBLIC_BASE = 0xFED30000

        # Key TXT Public Space registers (offset: name, description) -- tboot include/txt/config_regs.h
        REGISTERS = [
            (0x000, "TXT.STS",        "Status"),
            (0x008, "TXT.ESTS",       "Error Status"),
            (0x030, "TXT.ERRORCODE",  "Error Code"),
            (0x110, "TXT.DIDVID",     "Device ID / Vendor ID"),
            (0x270, "TXT.SINIT.BASE", "SINIT Base Address"),
            (0x278, "TXT.SINIT.SIZE", "SINIT Size"),
            (0x300, "TXT.HEAP.BASE",  "TXT Heap Base Address"),
            (0x308, "TXT.HEAP.SIZE",  "TXT Heap Size"),
            (0x330, "TXT.DPR",        "DMA Protected Range"),
            (0x8F0, "TXT.E2STS",      "Extended Error Status"),
        ]

        try:
            fd  = _os.open("/dev/mem", _os.O_RDONLY)
            m   = mmap.mmap(fd, 0x1000, mmap.MAP_SHARED, mmap.PROT_READ,
                            offset=TXT_PUBLIC_BASE)
            raw = {off: struct.unpack("<Q", m[off: off + 8])[0] for off, _, _ in REGISTERS}
            m.close()
            _os.close(fd)
        except (PermissionError, OSError):
            # Fall back to sudo python3
            py_code = (
                "import mmap,struct,os; "
                "fd=os.open('/dev/mem',os.O_RDONLY); "
                "m=mmap.mmap(fd,0x1000,mmap.MAP_SHARED,mmap.PROT_READ,offset=0xFED30000); "
                + "".join(
                    f"print({off},{repr(name)},struct.unpack('<Q',m[{off}:{off}+8])[0]); "
                    for off, name, _ in REGISTERS
                )
                + "m.close(); os.close(fd)"
            )
            result = subprocess.run(
                ["sudo", "python3", "-c", py_code],
                capture_output=True, text=True, timeout=15,
            )
            if result.returncode != 0:
                logger.warning("%s Could not read TXT registers: %s",
                               prefix, result.stderr.strip())
                return
            raw = {}
            for line in result.stdout.splitlines():
                parts = line.split(maxsplit=2)
                if len(parts) == 3:
                    raw[int(parts[0])] = int(parts[2])

        # Decode the status bits (tboot txt_sts_t / txt_ests_t / txt_e2sts_t)
        status_bits = [
            (0x000, 0,  "TXT.STS   SENTER.DONE"),
            (0x000, 1,  "TXT.STS   SEXIT.DONE (set after every reset)"),
            (0x000, 6,  "TXT.STS   MEM-CONFIG-LOCK"),
            (0x000, 7,  "TXT.STS   PRIVATE-OPEN"),
            (0x000, 15, "TXT.STS   LOCALITY1-OPEN"),
            (0x000, 16, "TXT.STS   LOCALITY2-OPEN"),
            (0x008, 0,  "TXT.ESTS  TXT_RESET"),
            (0x8F0, 1,  "TXT.E2STS SECRETS"),
            (0x030, 30, "TXT.ERRORCODE external (ACM/software)"),
            (0x030, 31, "TXT.ERRORCODE valid"),
        ]

        lines = [
            "TXT Public Space Register Dump",
            "Physical base: 0xFED30000",
            "=" * 60,
        ]
        for off, name, desc in REGISTERS:
            val = raw.get(off, 0)
            lines.append(f"  {name:<22} (+0x{off:03X})  =  0x{val:016X}  ({desc})")
        lines += [
            "",
            "Status bit decode:",
            "-" * 40,
        ]
        for off, bit, bname in status_bits:
            lines.append(f"  bit[{bit:2d}] {bname:<42} = {(raw.get(off, 0) >> bit) & 1}")
        lines += ["", "=" * 60]
        content = "\n".join(lines)

        artifact_local = log_dir / "txt_registers.txt"
        artifact_local.write_text(content, encoding="utf-8")

        logger.info("%s TXT register dump saved (for troubleshooting): %s", prefix, artifact_local)

    def _read_txt_reg(self, offset: int, step_label: str = "") -> int:
        """64-bit value of the TXT public space register at 0xFED30000 + offset (/dev/mem)."""
        import mmap, struct, os
        prefix = f"[Step {step_label}]" if step_label else ""
        TXT_PUBLIC_BASE = 0xFED30000
        try:
            fd = os.open("/dev/mem", os.O_RDONLY)
            m = mmap.mmap(fd, 0x1000, mmap.MAP_SHARED, mmap.PROT_READ, offset=TXT_PUBLIC_BASE)
            value = struct.unpack("<Q", m[offset:offset + 8])[0]
            m.close()
            os.close(fd)
        except (PermissionError, OSError) as exc:
            # Fall back to sudo python
            result = subprocess.run(
                ["sudo", "python3", "-c",
                 "import mmap,struct,os; fd=os.open('/dev/mem',os.O_RDONLY); "
                 "m=mmap.mmap(fd,0x1000,mmap.MAP_SHARED,mmap.PROT_READ,offset=0xFED30000); "
                 f"print(struct.unpack('<Q',m[{offset}:{offset + 8}])[0]); m.close(); os.close(fd)"],
                capture_output=True, text=True, timeout=10,
            )
            if result.returncode != 0:
                raise RuntimeError(
                    f"{prefix} Failed to read TXT register +0x{offset:03X} via /dev/mem: {result.stderr.strip()}"
                ) from exc
            value = int(result.stdout.strip())
        return value

    @staticmethod
    def _uefi_path_to_linux(uefi_path: str, efi_mount: str) -> str:
        """
        Convert a UEFI-shell-style path (e.g. 'EFI\\Tpm2Prov') to a Linux path
        (e.g. '/boot/efi/EFI/Tpm2Prov').
        """
        linux_rel = uefi_path.replace("\\", "/").lstrip("/")
        return str(Path(efi_mount) / linux_rel)
