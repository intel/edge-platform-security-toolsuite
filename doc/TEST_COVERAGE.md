# Test Coverage

What the 24 test cases in `tests/` cover, how much operator work each needs, and which IEC
62443-4-2 requirement each maps to. Every test runs on the SUT itself. How to run them:
[TEST_GUIDE.md](TEST_GUIDE.md).

This page lists **what exists, not results**: it records no pass/fail status. Results of a run
are in `logs/` (TEST_GUIDE §8).

`internal_nuc/tests/` holds internal NUC-driven variants of the same test cases (same CR
mapping). They are not collected by a plain `pytest` run and are not counted here.

**Categories**

| Category | Meaning |
|---|---|
| **Automated** | No operator action once the test starts (the pre-test checklist and BIOS knobs are done before). |
| **Automated, operator fallback** | Automated when the BIOS setting can be read back or was set in the pre-flight; otherwise the operator sets it in BIOS Setup and confirms it. |
| **Operator-assisted, verified** | The operator does steps (BIOS Setup, Windows settings); the test then checks the result itself and fails if it is not in effect. |
| **Manual, operator-confirmed** | The main result cannot be read by the test; it passes on the operator's confirmation, with a `Confirmed by the operator` note (fails with `verification.strict: true`). |

**Planned / blocked:** none. The internal test-case tracker
lists 24 test IDs and all 24 are implemented below.

## 1. Test inventory

IFWI groups: see §4. Reboots use the default config (`reboot_iterations: 5`).
"Secure Boot" = UEFI Secure Boot must be on before the test starts.

| Suite (marker) | Test ID | OS | Category | Reboots | IFWI | File (`tests/<suite>/`) | Intel Official Security Feature Name |
|---|---|---|---|---|---|---|---|
| sha_extension | `IEC62443-4-2-TC_SHA_Extension-FUNC-SUT` | Linux | Automated | 0 | SEP5, SED5 |`test_ec62443_sha_extension_sut_func.py` | Intel SHA Extension |
| tme | `IEC62443-4-2-TC_TME-FUNC-SUT` | Linux | Automated | 0 | SEP5, SED5 | `test_ec62443_tme_sut_func.py` | Intel Total Memory Encryption (TME) |
| *aesni | `IEC62443-4-2-TC_AES-NI-FUNC-SUT` | Linux | Automated | 0 | SEP5, SED5 | `test_ec62443_aesni_sut_func.py` | Intel AES-NI, Intel Secure Key (DRNG) |
| aesni | `IEC62443-4-2_Windows-TC_AES-NI-FUNC-SUT` | Windows | Automated | 0 | SEP5 | `test_ec62443_aesni_sut_wins_func.py` | Intel AES-NI, Intel Secure Key (DRNG) |
| tme | `IEC62443-4-2_Windows-TC_TME-FUNC-SUT` | Windows | Automated, operator fallback | 0, or 1 manual | SEP5 |`test_ec62443_tme_sut_wins_func.py` |  Intel Total Memory Encryption (TME) |
| *csme | `IEC62443-4-2-TC_CSME_UPID-FUNC-SUT` | Linux | Automated | 0 | SEP5, SED5 | `test_ec62443_csme_upid_sut_func.py` | Intel CSME (UPID - vPro only) |
| *csme | `IEC62443-4-2_Windows-TC_CSME_UPID-FUNC-SUT` | Windows | Automated | 0 | SEP5 | `test_ec62443_csme_upid_sut_wins_func.py` | Intel CSME (UPID - vPro only) |
| *rpmc | `IEC62443-4-2-TC_RPMC-FUNC-SUT` | Linux | Automated | 0 | SEP5, SED5 | `test_ec62443_rpmc_sut_func.py` | Intel CSME (RPMC SPI Flash) |
| *rpmc | `IEC62443-4-2_Windows-TC_RPMC-FUNC-SUT` | Windows | Automated | 0 | SEP5 | `test_ec62443_rpmc_sut_wins_func.py` | Intel CSME (RPMC SPI Flash) |
| secure_debug | `IEC62443-4-2-TC_Secure_debug-FUNC-SUT` | Linux | Automated | 0 | SEP5, SED5 | `test_ec62443_secure_debug_sut_func.py` | Intel Secure Debug |
| measured_boot | `IEC62443-4-2-TC_fTPM-PTT-FUNC-SUT` | Linux | Automated; Secure Boot | 4 automatic | SEP5 only | `test_ec62443_ftpm_ptt_sut_func.py` | Intel Boot Guard, Intel Platform Trust Technology (PTT) |
| measured_boot | `IEC62443-4-2-TC_dTPM-FUNC-SUT` | Linux | Automated; Secure Boot | 4 automatic | SED5 only | `test_ec62443_dtpm_sut_func.py` | Intel Boot Guard, Discrete TPM |
| measured_boot | `IEC62443-4-2_Windows-TC_fTPM/PTT-FUNC-SUT` | Windows | Automated; Secure Boot | 4 automatic | SEP5 | `test_ec62443_ftpm_ptt_sut_wins_func.py` | Intel Boot Guard, Intel Platform Trust Technology (PTT) |
| measured_boot | `IEC62443-4-2_Windows-TC_dTPM-FUNC-SUT` | Windows | Automated; Secure Boot | 4 automatic | SED5 | `test_ec62443_dtpm_sut_wins_func.py` | Intel Boot Guard, Discrete TPM |
| virtualization | `IEC62443-4-2-TC_Virtualization_Vtd-FUNC-SUT` | Linux | Automated | 5 automatic (+1 if GRUB lacks `resume=`) | SEP5, SED5 | `test_ec62443_virtualization_vtd_sut_func.py` | Intel Virtualization Technology (VT) |
| virtualization | `IEC62443-4-2-TC_Virtualization_Vtd_002-FUNC-SUT` | Linux | Operator-assisted, verified | 1 manual | SEP5, SED5 | `test_ec62443_virtualization_vtd_002_sut_func.py` | Intel Virtualization Technology (VT) |
| txt | `IEC62443-4-2-TC_TXT-FUNC-SUT` | Linux | Operator-assisted, verified | 5 (3 automatic, 2 manual) | SEP5, SED5 | `test_ec62443_txt_sut_func.py` | Intel Trusted Execution Technology (TXT) |
| hlat | `IEC62443-4-2-TC_HLAT-FUNC-SUT` | Windows | Automated | 0 | SEP5 | `test_ec62443_hlat_sut_wins_func.py` | Intel Virtualization Technology Redirection Protection (VT-rp)/HLAT| 
| cet | `IEC62443-4-2-TC_CET-FUNC-SUT` | Windows | Operator-assisted, verified | 1 manual | SEP5 | `test_ec62443_cet_sut_wins_func.py` | Intel Control-flow Enforcement Technology (CET) |
| pavp | `IEC62443-4-2-TC_PAVP-FUNC-SUT` | Windows | Automated, operator fallback | 0, or 1 manual | SEP5 | `test_ec62443_pavp_sut_wins_func.py` | Intel Protected Audio Video Path (PAVP) |
| hdcp | `IEC62443-4-2-TC_HDCP-FUNC-SUT` | Windows | Manual, operator-confirmed | 0 | SEP5 | `test_ec62443_hdcp_sut_wins_func.py` | HDCP 1.4 / 2.2 / 2.3 |
| bios_resiliency | `IEC62443-4-2-TC_BIOS_Resiliency_Recovery-FUNC-SUT` | Linux (RVP only) | Manual, operator-confirmed | 1 manual | Resiliency | `test_ec62443_bios_resiliency_recovery_sut_func.py` | Intel Firmware Restart/Recovery | 
| * eom | `IEC62443-4-2-TC_EOM-FUNC-SUT` | Linux | Automated; **irreversible** | 2 automatic | SEP5, SED5 | `test_ec62443_eom_sut_func.py` | Intel CSME (End of Manufacturing (EOM)) |
| firmware | `IEC62443-4-2-TC_BIOS_FW_Capsule_Update-FUNC-SUT` | Linux | Automated; **irreversible** (reflashes BIOS) | 1 automatic | SEP5, SED5 | `test_ec62443_bios_fw_capsule_update_sut_func.py` | Intel Firmware Update / Restart | 

**Totals:** 24 test cases — 14 Linux, 10 Windows. 17 Automated, 2 Automated with operator
fallback, 3 Operator-assisted (verified), 2 Manual (operator-confirmed).

Notes:
- Almost every test carries `@pytest.mark.manual` because of its **pre-test** checklist (IFWI,
  BIOS); the category above is about what happens while the test runs.
- The tracker's own "Automation" column marks BIOS Resiliency, VT-d 002, Windows TME, CET, HDCP
  and PAVP as Manual and all others (including TXT) as Automated. TXT is listed here as
  operator-assisted because it waits for two BIOS changes made by hand.
- Automatic reboots: Linux UEFI Shell phases and S5 cycles are driven by the test; on Windows the
  measured boot tests reboot themselves. Manual reboots are the operator's BIOS Setup visits.

## 2. Operator steps

What the operator does during the run, and what the test checks itself afterwards. The operator
signals "done" with a file in `logs/sut_state/` (TEST_GUIDE §6.2).

| Test | Operator does | Test checks itself | Signal files |
|---|---|---|---|
| CET (Windows) | Turns on Kernel-mode Hardware-enforced Stack Protection, reboots, starts `msedge.exe` (skipped if already active) | `Win32_DeviceGuard` service 5 running + `msedge.exe` UserShadowStack on | `step3_cet_done.txt` |
| PAVP (Windows) | Nothing when PAVP reads back or was set in the pre-flight; otherwise PAVP Enable in BIOS Setup | PlayReady hardware DRM on Intel graphics / AMISCE; else reboot proof + operator confirmation | none (resumes after logon) |
| TME (Windows) | Nothing when TME can be read; otherwise TME in BIOS Setup | VT-d: ACPI DMAR; TME: `tme_check.py` MSR 0x982 / AMISCE; else reboot proof + operator confirmation | none (resumes after logon) |
| HDCP (Windows) | Checks HDCP = Compatible in Intel Graphics Command Center (+ optional DRM videos) | nothing can be read — operator confirmation | `step3_hdcp_done.txt` |
| TXT (Linux) | Reboots into BIOS Setup, enables In-Band ECC, F4, boots Ubuntu, creates the signal file | reboot proof; IBECC active (IBECC_ACTIVATE register) + MemTotal drop vs. Step 4.0 | `step4_ibecc_enabled.txt` |
| VT-d 002 (Linux) | Looks at the BIOS VT-d menu | reboot proof + VT-d via ACPI DMAR; "sub-options absent" is operator-confirmed | `step3_vtd002_verified.txt` |
| VT-d (Linux) | Nothing (S3/S4/S5 via `rtcwake`) | each state proven: S3/S4 kernel log entry → "sleep state S3/S4" → wake → exit, same boot_id, CPU stopped ≥ ½ RTC alarm; S5 new boot_id, old boot reached `poweroff.target`, off ≥ ¾ RTC alarm (`power_state_s3/s4/s5.log`) | none |
| BIOS Resiliency (Linux, RVP only) | Types `yes` to power off, flashes the corrupted IBB (from the POC), watches the purple rollback box | RVP (DMI), `Obb.bin` on the ESP before and after, reboot proof after the flash; the purple box is operator-confirmed | `step5_rollback_done.txt` |
## 3. IEC 62443-4-2 requirement mapping

Source: the internal test-case tracker (not published), sheet `Test Cases Configuration`.

| Suite (marker) | Tests | CR mapping (from the tracker) |
|---|---|---|
| `measured_boot` | 4 | CR1.5 Authentication Management; CR1.8 Hardware Security for Public Key Based Auth; CR1.9 Strength of Public Key Based Auth; CR3.14 Integrity of Boot Process (Boot Guard); CR3.13 Provisioning Asset Owner Root of Trust (TPM/PTT) |
| `tme` | 2 | CR3.11 Physical Tamper Resistance & Detection (Intel TME) |
| `aesni` | 2 | CR1.14 Hardware Security for Symmetric Key-based Authentication (AES-NI); CR4.3 Use of Cryptography (Secure Key RNG/DRNG) |
| `csme` (UPID) | 2 | CR1.2 Device Identification (Intel CSME, vPro only) |
| `rpmc` | 2 | CR3.14 Integrity of Boot Process (RPMC) |
| `virtualization` (VT-d, VT-d 002) | 2 | CR4.3 Use of Cryptography — Virtualization (VT-d IO Protection) |
| `sha_extension` | 1 | CR1.2 Device Identification (SHA Extension) |
| `secure_debug` | 1 | CR2.13 Use of Physical Diagnostic & Test Interfaces (Secure Debug) |
| `txt` | 1 | CR2.4 Mobile Code Execution Control, Authenticity Check (Intel TXT) |
| `eom` | 1 | CR3.12 Provisioning Product Supplier Root of Trust (EOM) |
| `firmware` | 1 | CR3.1 Support for Update (Intel Firmware Update) |
| `bios_resiliency` | 1 | CR6 Timely Response to Events (Firmware Restart/Recovery) |
| `cet` | 1 | CR3.2 Protection from Malicious Code (Intel CET) |
| `hlat` | 1 | CR4.3 Use of Cryptography — Virtualization (VT-rp / HLAT) |
| `hdcp` | 1 | CR4.3 Use of Cryptography — DRM (HDCP) |
| `pavp` | 1 | CR4.3 Use of Cryptography — DRM (PAVP) |

CR4.3 is reused by the tracker for several mechanisms (virtualization, HLAT, HDCP, PAVP).

## 4. IFWI groups

Each test is tagged with the IFWI(s) it runs on (`core/test_selection.py`); `test_runner.py` key `I`
runs one group at a time. On Linux every test except fTPM, dTPM and BIOS Resiliency runs on SEP5
or SED5, so it is in both groups.

| Group (marker) | IFWI build | Tests |
|---|---|---|
| SEP5 (`ifwi_sep5`, default) | Bootguard 5 EXTERNAL — RPSF_SEP5 (PTT) | 21: every Windows test except dTPM, every Linux test except dTPM and BIOS Resiliency |
| SED5 (`ifwi_sed5`) | Bootguard 5 EXTERNAL — RPSF_SED5 (dTPM) | 13: dTPM (Linux, Windows) + every Linux test except fTPM and BIOS Resiliency |
| Resiliency (`ifwi_resiliency`) | custom Resiliency-ROM build | 1: BIOS Resiliency |

The flashed IFWI is read from the TPM manufacturer (`INTC` = PTT = SEP5, any other = dTPM = SED5).
On a Linux SUT, `test_runner.py` shows it in the menu header and stops a run that picks fTPM on
SED5 or dTPM on SEP5; a direct `pytest` run skips those tests with the reason. The Resiliency ROM
cannot be told apart from SEP5 this way.

## 5. What the tests read back

BIOS knobs each suite needs are in `deploy/bios_knobs/bios_knobs.yaml`. The pre-flight in
`test_runner.py`, and the tests themselves, read them from the running OS
(`core/bios_knob_checks.py`). A knob that cannot be read is set by AMISCE (AMI BIOS) or confirmed
by the operator.

| BIOS knob | Linux | Windows |
|---|---|---|
| VT-d | ACPI DMAR table present | ACPI DMAR table present |
| Intel (VMX) Virtualization Technology | MSR 0x3A bit 2 (else `vmx` CPU flag) | firmware virtualization enabled, or Hyper-V running |
| Low Power S0 Idle Capability | ACPI FADT flag (else `/sys/power/mem_sleep`) | ACPI FADT flag |
| Total Memory Encryption | MSR 0x982 bit 1 | not in the pre-flight; the TME test reads MSR 0x982 with `tme_check.py` when `msr-cmd.exe` / `pcm-msr.exe` is present |
| Intel Trusted Execution Technology | MSR 0x3A bit 15 | not readable (TXT is Linux-only) |
| PAVP Enable | not readable (PAVP is Windows-only) | PlayReady hardware DRM available on Intel graphics |
| TPM Device Selection (fixed by the IFWI) | TPM manufacturer (`INTC` = PTT) | TPM manufacturer (`INTC` = PTT) |
| Alias Check Request, In-Band ECC Support | no OS check for Alias Check Request; In-Band ECC must be Disabled at the start and active after Step 4.1 and at the end of the TXT test (IBECC_ACTIVATE register of each memory controller; a registered `igen6_edac` controller alone is not trusted; unreadable = FAIL), plus the MemTotal reduction | — |

On an AMI BIOS with AMISCE installed, knobs are also read and set with AMISCE.

Knobs for a CPU feature are first checked against the CPU itself: `Total Memory Encryption` needs
CPUID.07H:ECX[13] (TME) = 1 (no root needed). On a CPU without TME (non-vPro) the knob reads as
WRONG ("not supported by this CPU"), and the pre-flight and the AMISCE runbooks skip it instead of
setting it -- the BIOS accepts the value and AMISCE reads it back as set, but the CPU ignores it.
The other knobs and tests are not affected; the TME test fails with that reason.
