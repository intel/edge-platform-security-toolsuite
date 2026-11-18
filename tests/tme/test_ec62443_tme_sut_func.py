# Copyright 2026 Intel Corporation
# SPDX-License-Identifier: Apache-2.0

"""
TEST — IEC 62443-4-2  TME (Total Memory Encryption)  (functional — SUT LOCAL)

Test ID:  IEC62443-4-2-TC_TME-FUNC-SUT
Suite:    tme

PURPOSE
-------
Verifies that Intel Total Memory Encryption (TME) is supported by the CPU,
ENABLED and LOCKED by the BIOS, and that the platform supports AES-XTS 256-bit
encryption as reported by the IA32_TME_CAPABILITY MSR (0x981).

Run this test when pytest is executed directly on the SUT Linux host.
Unlike the SSH-based TME test, this variant does not manage the BIOS reboot
gate or wait for SSH recovery. The system must already be booted back into
Ubuntu after the BIOS change (the test_runner.py pre-flight sets it with
AMISCE on an AMI BIOS) before this test is started.

Verification:
  - CPU supports TME: MSR 0x981 exists (rdmsr of MSR 0x3A works, 0x981 does
    not -> TME not supported by this CPU, e.g. non-vPro silicon -> FAIL)
  - MSR 0x981 bit[2] = 1  (AES-XTS 256-bit algorithm supported)
  - MSR 0x982 (IA32_TME_ACTIVATE) bit[0] = 1 (locked) and bit[1] = 1 (TME
    enabled) -- the BIOS really turned TME on, not just "the CPU can do it".
    Bit[31] (TME bypass) = 1 is logged as a warning: KeyID 0 memory is then
    not encrypted.
  - Kernel log: the kernel's own "x86/tme: ..." messages from this boot
    ("not enabled by BIOS" -> FAIL). Matched as whole words, so lines such
    as "initmem" are not mistaken for TME.
  - BIOS knobs of the 'tme' marker read back (VT-d: ACPI DMAR table, TME:
    the MSR 0x982 result above).

AUTOMATION / MANUAL split
--------------------------
  Pre-test steps 1.x — manual (flash IFWI, enable TME + VT-d in BIOS, boot Ubuntu)
  Step 3.0           — automated (TME supported by this CPU: MSR 0x3A vs 0x981)
  Step 3.1 / 3.2     — automated (MSR 0x981 value, mask + bit[2] capability check)
  Step 3.3           — automated (MSR 0x982: TME enabled + locked)
  Step 3.4           — automated (kernel log x86/tme messages, this boot)
  Step 3.5           — automated (BIOS knobs VT-d + TME read back)

  rdmsr runs as "sudo -n rdmsr <msr>" (passwordless rule from
  deploy/setup/setup_sut.sh); the kernel log is read with "journalctl -k -b"
  (adm group), falling back to "sudo -n dmesg".

CONFIG
------
  config/suites/tme_config.yaml  — MSR addresses and expected values
  config/test_config.yaml        — global SUT connection settings

PRE-TEST (manual, performed before running this script)
-------------------------------------------------------
  1.0) Flash the IFWI image and deploy Ubuntu custom image to the SUT.
       - IFWI: Bootguard 5 (BtG5) EXTERNAL release — RPSF_SEP5 or RPSF_SED5 variant.
       - Any version from the current BOM release is acceptable.
       - Example (PTL board):
         ECG_PTL_PR04_B0A1-XXXODCA_RPSF_SEP5_11E50692_2026ww01.1.02_BE351556_CRB.bin
  2.0) Enter BIOS, enable Total Memory Encryption (TME), verify VT-d is
       Enabled, save changes, reboot, and boot back into Ubuntu OS.
  3.0) Run this test directly on the SUT Linux host.

RUN (on SUT directly, NOT via SSH from remote host)
---
  cd /path/to/asrock_repo
  python3 -m pytest tests/tme/test_ec62443_tme_sut_func.py -v -s --setup-confirmed --yes
"""

import logging
import re
import subprocess

import pytest

from core.prereq import pre_test_check
from tests.base_test import BaseTest

logger = logging.getLogger(__name__)


# TME Capability check parameters
_TME_AES_XTS_256_BIT = 2
_TME_CAPABILITY_MASK = 0xF440000004  # Mask for TME capability check


def _apply_mask_and_check_bit(hex_value: str, mask: int, bit_pos: int) -> bool:
    """
    Apply a mask to the hex value, then check if the bit at bit_pos is set.

    Args:
        hex_value: MSR value as hex string (e.g., "f4c0000004")
        mask: Bitmask to apply
        bit_pos: Bit position to check (0-indexed)

    Returns:
        True if bit at bit_pos is set in the masked value, False otherwise
    """
    msr_int = int(hex_value, 16)
    masked_value = msr_int & mask
    logger.debug("MSR value (int): %d (0x%x)", msr_int, msr_int)
    logger.debug("Mask applied: 0x%x", mask)
    logger.debug("Masked result: %d (0x%x)", masked_value, masked_value)
    bit_set = bool((masked_value >> bit_pos) & 1)
    logger.debug("Bit[%d] from masked value: %s", bit_pos, bit_set)
    return bit_set


@pytest.mark.tme
@pytest.mark.manual
class TestEC62443TMESUTFunc(BaseTest):
    """IEC 62443-4-2 TME functional test — LOCAL (on SUT, no SSH)."""

    SUITE = "tme"
    TEST_ID = "IEC62443-4-2-TC_TME-FUNC-SUT"

    PRE_TEST_CHECKLIST = [
        "1.0)  Flash the IFWI image to the SUT board.",
        "      - IFWI: Bootguard 5 (BtG5) EXTERNAL release — RPSF_SEP5 or RPSF_SED5 variant.",
        "      - Any version from the current BOM release is acceptable (no",
        "        specific IFWI version is pinned for this test).",
        "      - Example (PTL board):",
        "        ECG_PTL_PR04_B0A1-XXXODCA_RPSF_SEP5_11E50692_2026ww01.1.02_BE351556_CRB.bin",
        "2.0)  Enable Total Memory Encryption (TME) in BIOS, verify VT-d is Enabled,",
        "      save changes, reboot, and boot back to Ubuntu OS.",
        "3.0)  Run this test directly on the SUT Linux host.",
    ]

    def _run_cmd(self, cmd: str, timeout: int = 60) -> tuple:
        """Run a shell command locally via subprocess and return rc/stdout/stderr."""
        try:
            result = subprocess.run(
                cmd,
                shell=True,
                capture_output=True,
                text=True,
                timeout=timeout,
                errors="replace",
            )
            return result.returncode, result.stdout, result.stderr
        except subprocess.TimeoutExpired as exc:
            logger.error("Command timeout after %ds: %s", timeout, cmd)
            return 124, "", str(exc)
        except Exception as exc:
            logger.error("Command execution error: %s", exc)
            return 1, "", str(exc)

    def _rdmsr(self, addr: str) -> tuple:
        """(rc, value or None, raw output) of 'sudo -n rdmsr <addr>' on CPU 0."""
        rc, out, err = self._run_cmd(f"sudo -n rdmsr {addr}", timeout=30)
        try:
            value = int(out.split()[0], 16) if rc == 0 else None
        except (IndexError, ValueError):
            value = None
        return rc, value, out + err

    def test_ec62443_tme_sut_func(
        self,
        request,
        config,
        log_dir,
    ):
        """IEC62443-4-2-TC_TME-FUNC-SUT — verify TME capability locally on the SUT."""
        self._begin()
        cfg = self._load_config(config)

        pre_test_check(request, self.TEST_ID, self.PRE_TEST_CHECKLIST)

        msr_addr = cfg.get("msr_tme_capability_address", "0x981")
        activate_addr = cfg.get("msr_tme_activate_address", "0x982")
        expected_hex = format(int(str(cfg.get("expected_tme_capability_hex", "f440000004")), 16), "x")

        # ------------------------------------------------------------------
        # Step 3.0 — TME supported by this CPU? (MSR 0x981 exists only on TME-capable CPUs)
        # ------------------------------------------------------------------
        logger.info("[Step 3.0] Checking that this CPU supports TME (MSR 0x3A vs %s)", msr_addr)
        rc, cap_value, cap_raw = self._rdmsr(msr_addr)
        log_file = log_dir / "msr_0x981_tme_capability.log"
        log_file.write_text(
            f"Command: sudo -n rdmsr {msr_addr}\nReturn code: {rc}\nOutput:\n{cap_raw}\n",
            encoding="utf-8", errors="replace",
        )
        logger.info("[Step 3.0] Artifact saved: %s", log_file)
        for line in cap_raw.splitlines():
            logger.info("    %s", line)
        if cap_value is None:
            fc_rc, fc_value, fc_raw = self._rdmsr("0x3a")
            logger.info("[Step 3.0] Control read: sudo -n rdmsr 0x3a -> rc=%d %s", fc_rc, fc_raw.strip())
            assert fc_value is not None, (
                f"[Step 3.0] MSRs cannot be read at all (rdmsr 0x3a rc={fc_rc}: {fc_raw.strip()}).\n"
                f"  Needs msr-tools, the msr module and the passwordless rdmsr rule:\n"
                f"  sudo ./deploy/setup/setup_sut.sh\n"
                f"  Check artifact: {log_file}"
            )
            raise AssertionError(
                f"[Step 3.0] TME is NOT supported by this CPU: MSR {msr_addr} (IA32_TME_CAPABILITY) does not\n"
                f"  exist (rdmsr: {cap_raw.strip()}), while MSR 0x3A reads fine (0x{fc_value:x}).\n"
                f"  The BIOS 'Total Memory Encryption' knob has no effect on this silicon -- use a vPro CPU.\n"
                f"  Check artifact: {log_file}"
            )
        logger.info("[Step 3.0] [OK] MSR %s exists — the CPU supports TME", msr_addr)

        # ------------------------------------------------------------------
        # Step 3.1 — MSR 0x981 (IA32_TME_CAPABILITY) value
        # ------------------------------------------------------------------
        msr_hex = format(cap_value, "x")
        logger.info("[Step 3.1] MSR %s raw value : 0x%s", msr_addr, msr_hex)
        logger.info("[Step 3.1] MSR %s expected reference value from config: 0x%s", msr_addr, expected_hex)
        logger.info(
            "[Step 3.1] [OK] MSR %s read succeeded; capability verification uses masked bit check",
            msr_addr,
        )

        # ------------------------------------------------------------------
        # Step 3.2 — Apply mask and check for AES-XTS 256-bit support (Bit 2)
        # ------------------------------------------------------------------
        msr_int = cap_value
        masked_value = msr_int & _TME_CAPABILITY_MASK
        bit2_set = _apply_mask_and_check_bit(msr_hex, _TME_CAPABILITY_MASK, _TME_AES_XTS_256_BIT)

        log_file.write_text(
            f"MSR {msr_addr} (IA32_TME_CAPABILITY)\n"
            f"Raw value : 0x{msr_hex}\n"
            f"Expected reference : 0x{expected_hex}\n"
            f"Mask applied : 0x{_TME_CAPABILITY_MASK:x}\n"
            f"Masked value : 0x{masked_value:x}\n"
            f"Bit[{_TME_AES_XTS_256_BIT}] after mask : {int(bit2_set)}\n",
            encoding="utf-8",
        )
        logger.info("[Step 3.2] Updated artifact with parsed MSR details: %s", log_file)

        logger.info("[Step 3.2] Applying mask 0x%x to check TME capability", _TME_CAPABILITY_MASK)
        logger.info("[Step 3.2] MSR value (int) : %d (0x%x)", msr_int, msr_int)
        logger.info("[Step 3.2] Masked result   : %d (0x%x)", masked_value, masked_value)
        logger.info(
            "[Step 3.2] MSR 0x%s bit[2] after masking = %d  (AES-XTS 256-bit support: %s)",
            msr_addr,
            int(bit2_set),
            "YES" if bit2_set else "NO",
        )

        assert bit2_set, (
            f"[Step 3.2] MSR {msr_addr} bit[2] is NOT set after applying mask 0x{_TME_CAPABILITY_MASK:x}.\n"
            f"  bit[2] = 1 is required to confirm AES-XTS 256-bit encryption support.\n"
            f"  Actual MSR value: 0x{msr_hex}\n"
            f"  Check artifact  : {log_file}"
        )
        logger.info("[Step 3.2] [OK] bit[2] = 1 after masking — AES-XTS 256-bit encryption capability confirmed")

        # ------------------------------------------------------------------
        # Step 3.3 — MSR 0x982 (IA32_TME_ACTIVATE): TME enabled AND locked by the BIOS
        # ------------------------------------------------------------------
        logger.info("[Step 3.3] Reading MSR %s (IA32_TME_ACTIVATE)", activate_addr)
        rc, act_value, act_raw = self._rdmsr(activate_addr)
        act_log = log_dir / "msr_0x982_tme_activate.log"
        lines = [f"Command: sudo -n rdmsr {activate_addr}", f"Return code: {rc}", f"Output: {act_raw.strip()}"]
        if act_value is not None:
            locked, enabled, bypass = act_value & 1, (act_value >> 1) & 1, (act_value >> 31) & 1
            lines += [
                f"Raw value          : 0x{act_value:x}",
                f"Bit[0]  Lock       : {locked}",
                f"Bit[1]  TME Enable : {enabled}",
                f"Bit[31] TME Bypass : {bypass}",
                f"Bits[7:4] Algorithm: 0x{(act_value >> 4) & 0xF:x}",
                f"Bits[35:32] MK-TME KeyID bits: {(act_value >> 32) & 0xF}",
            ]
        act_log.write_text("\n".join(lines) + "\n", encoding="utf-8", errors="replace")
        logger.info("[Step 3.3] Artifact saved: %s", act_log)
        for line in lines[3:]:
            logger.info("[Step 3.3] %s", line)
        assert act_value is not None, (
            f"[Step 3.3] MSR {activate_addr} could not be read (rc={rc}: {act_raw.strip()}).\n"
            f"  Check artifact: {act_log}"
        )
        assert enabled == 1, (
            f"[Step 3.3] TME is NOT enabled: MSR {activate_addr} bit[1] = 0 (value 0x{act_value:x}).\n"
            f"  The CPU supports TME but the BIOS did not turn it on. Set 'Total Memory Encryption' = Enabled\n"
            f"  (Intel Advanced Menu -> CPU Configuration; VT-d must be Enabled) -- the test_runner.py\n"
            f"  pre-flight does this with AMISCE on an AMI BIOS -- then reboot and run again.\n"
            f"  Check artifact: {act_log}"
        )
        assert locked == 1, (
            f"[Step 3.3] TME is enabled but NOT locked: MSR {activate_addr} bit[0] = 0 (value 0x{act_value:x}).\n"
            f"  The BIOS must lock IA32_TME_ACTIVATE; without the lock the kernel does not treat TME as active.\n"
            f"  Check artifact: {act_log}"
        )
        if bypass:
            logger.warning(
                "[Step 3.3] TME bypass is ON (MSR %s bit[31] = 1): memory with KeyID 0 is NOT encrypted. "
                "Check BIOS 'Total Memory Encryption (TME) Bypass'.", activate_addr,
            )
        logger.info("[Step 3.3] [OK] TME enabled and locked by the BIOS (MSR %s = 0x%x)", activate_addr, act_value)

        # ------------------------------------------------------------------
        # Step 3.4 — Kernel log: the kernel's own x86/tme messages from this boot
        # ------------------------------------------------------------------
        logger.info("[Step 3.4] Checking the kernel log of this boot for TME messages")
        kcmd = "journalctl -k -b --no-pager -q"
        rc, out, err = self._run_cmd(kcmd, timeout=60)
        if rc != 0 or not out.strip():
            kcmd = "sudo -n dmesg"
            rc, out, err = self._run_cmd(kcmd, timeout=30)
        tme_lines = [line for line in out.splitlines() if re.search(r"x86/tme|\bTME\b", line)]
        dmesg_log_file = log_dir / "dmesg_tme.log"
        dmesg_log_file.write_text(
            f"Command: {kcmd}\nReturn code: {rc}\nTME lines:\n" + "\n".join(tme_lines)
            + (f"\nstderr:\n{err}\n" if err.strip() else "\n"),
            encoding="utf-8", errors="replace",
        )
        logger.info("[Step 3.4] Artifact saved: %s", dmesg_log_file)
        for line in tme_lines:
            logger.info("    %s", line)
        not_enabled = [line for line in tme_lines if re.search(r"not enabled by BIOS", line, re.IGNORECASE)]
        assert not not_enabled, (
            f"[Step 3.4] The kernel reports TME as not enabled by the BIOS at boot:\n"
            + "".join(f"    {line.strip()}\n" for line in not_enabled)
            + f"  Check artifact: {dmesg_log_file}"
        )
        if rc != 0 and not out.strip():
            logger.warning("[Step 3.4] Kernel log not readable (%s rc=%d: %s) — MSR %s above is the evidence",
                           kcmd, rc, err.strip(), activate_addr)
        elif not tme_lines:
            logger.warning("[Step 3.4] No x86/tme kernel message in this boot — MSR %s above is the evidence",
                           activate_addr)
        else:
            logger.info("[Step 3.4] [OK] Kernel log agrees: no 'not enabled by BIOS' message")

        # ------------------------------------------------------------------
        # Step 3.5 — BIOS knobs of the 'tme' marker read back (VT-d + TME)
        # ------------------------------------------------------------------
        known = {"Total Memory Encryption": (
            True, f"MSR {activate_addr} = 0x{act_value:x} (TME enable = 1, lock = 1)")}
        self._check_bios_knobs("tme", log_dir, "3.5", known=known)

        self._end()