# Test Guide — IEC 62443-4-2 SUT tests

How to install, configure, run and troubleshoot the tests in `tests/`. Every test runs
**directly on the board being validated (the SUT)**, on Ubuntu or Windows. No second machine,
serial cable or USB drive is needed.

| I want to… | Go to |
|---|---|
| Know what I need first | [1. Before you start](#1-before-you-start) |
| Set up a Linux SUT | [2. Install — Linux SUT](#2-install--linux-sut) |
| Set up a Windows SUT | [3. Install — Windows SUT](#3-install--windows-sut) |
| Change settings | [4. Configure](#4-configure) |
| Know which BIOS settings each test needs | [4.1 BIOS settings per test case](#41-bios-settings-per-test-case) |
| Run tests | [5. Run tests](#5-run-tests) |
| Understand reboots and manual steps | [6. Reboots and manual steps](#6-reboots-and-manual-steps) |
| Clean up after an interrupted run | [7. Clean up an interrupted run](#7-clean-up-an-interrupted-run) |
| Find results and logs | [8. Results and logs](#8-results-and-logs) |
| Fix a problem | [9. Troubleshooting](#9-troubleshooting) |

Related: external tools → [DEPENDENCIES.md](DEPENDENCIES.md); every test case, its category and
CR mapping → [TEST_COVERAGE.md](TEST_COVERAGE.md); setup scripts → [deploy/README.md](../deploy/README.md).

> `internal_nuc/tests/` holds internal NUC-driven variants (SSH + serial to a remote SUT). They are
> not collected by a plain `pytest` run and are not covered here.

---

## 1. Before you start

**Hardware**

| Item | Needed for |
|---|---|
| SUT board flashed with the right IFWI (see below) | all tests |
| HDCP-capable monitor | HDCP |
| Discrete TPM chip on the board | dTPM tests |
| Dediprog SPI programmer + an **Intel RVP** board (its EC performs the recovery); HXD, BpmGen2, MFIT only to build the images yourself ([6.3](#63-bios-resiliency-rvp-only)) | BIOS Resiliency |

**IFWI groups** — tests that need the same flashed image run together (runner key `I`):

| Group | IFWI | Tests |
|---|---|---|
| SEP5 | Bootguard 5 EXTERNAL, RPSF_SEP5 (PTT) | every test except dTPM and BIOS Resiliency |
| SED5 | Bootguard 5 EXTERNAL, RPSF_SED5 (dTPM) | dTPM (Linux + Windows) + every Linux test except fTPM and BIOS Resiliency |
| Resiliency | custom Resiliency-ROM build | BIOS Resiliency |

On Linux only fTPM (SEP5) and dTPM (SED5) are tied to one image; the other Linux tests run on
either. The flashed IFWI is read from the TPM manufacturer (`INTC` = PTT = SEP5, else SED5), and
fTPM/dTPM on the wrong one are stopped by the runner and skipped by pytest.

Some tests also need a specially built IFWI: RPMC (MFIT: RPMC supported + rebinding enabled),
EOM (**HW Binding disabled** — EOM permanently burns fuses otherwise; use QS silicon), CSME UPID
(UPID OEM ID / Refurbish Counter noted from MFIT). Each test prints its full checklist; it is
also the `PRE_TEST_CHECKLIST` in the test file.

**Software**
- Linux: Ubuntu booted in **UEFI mode** (not Legacy/CSM), `sudo` rights, internet for `apt`/`pip`.
- Windows: Windows 11 (HLAT needs VBS turned on — see its checklist), Python 3 on `PATH`, an **Administrator** PowerShell to run tests.
- Python 3.10 or newer, `git`.
- The licensed Intel tools for the tests you run — see [DEPENDENCIES.md](DEPENDENCIES.md).

**Folders** (all relative to the repo folder `edge-platform-security-toolsuite/`)

| Folder | Content |
|---|---|
| `../venv` | Python virtual environment, created by the setup scripts |
| `Downloads/` | where you drop the tool packages; `deploy_tools.py` picks them up |
| `Tools/` | staged tools (git-ignored) |
| `logs/` | all logs, reports and the reboot state (`logs/sut_state/`) |

---

## 2. Install — Linux SUT

Do this once per SUT.

1. **Check UEFI mode.** UEFI-shell tests (EOM, TXT, VT-d, capsule update) need an EFI System
   Partition at `/boot/efi`. Both commands must succeed:
   ```bash
   ls /sys/firmware/efi
   mount | grep /boot/efi
   ```
   If not, disable CSM/Legacy boot in BIOS Setup and reinstall Ubuntu in UEFI mode.
2. **Clone the repo onto the SUT** and go into it:
   ```bash
   git clone <repo_url> <folder>
   cd <folder>/edge-platform-security-toolsuite
   ```
3. **Drop the tool packages into `Downloads/`** (see [DEPENDENCIES.md](DEPENDENCIES.md)). You can
   also do this later.
4. **Run the setup script** (safe to re-run):
   ```bash
   sudo bash deploy/setup/setup_sut.sh --nopasswd-all
   ```
   `--nopasswd-all` lets the test user run every command with `sudo` without a password, so no test
   stops to ask for one and the tests that reboot (dTPM, fTPM, TXT) can continue unattended. Use it
   on a dedicated test board only ([SECURITY.md](../SECURITY.md)); without it, these tests ask for a
   password: CSME UPID, RPMC, Secure Debug, AES-NI, VT-d, dTPM, fTPM, TXT.
   | Step | What it does |
   |---|---|
   | 1 | Checks `/boot/efi` is mounted |
   | 2 | Copies `deploy/resume/startup.nsh` → `/boot/efi/startup.nsh` |
   | 3 | Installs `tpm2-tools efibootmgr python3-venv msr-tools dmidecode p7zip-full`, loads the `msr` module |
   | 4 | Creates `../venv` and installs `requirements.txt` |
   | 5 | Passwordless `sudo` for the commands the tests use, and for the `test_runner.py` pre-flight (Secure Boot / BIOS knob runbooks, pre-flight chain, reboot into BIOS Setup) — exact repo and venv paths. With `--nopasswd-all` also for all commands (test boards only, see [SECURITY.md](../SECURITY.md)) |
   | 6 | Creates `logs/sut_state/`, installs `fw-validation-resume.service` (resumes tests after a reboot) and the login status window |
   | 7 | Creates the **FW-Validation Shell** UEFI boot entry. Downloads the upstream EDK2 shell (SHA-256 checked) to `Tools/shellx64.efi`, because Ubuntu's `efi-shell-x64` exits under Secure Boot (CVE-2025-2486). Needs internet (`sudo -E` behind a proxy); offline, copy an upstream `shellx64.efi` to `Tools/` first. If the download fails it falls back to `efi-shell-x64` with a warning |
   | 8 | Stages tools from `Downloads/` (skipped with a message if it is empty) |
5. **Optional:** `./deploy/setup/configure_sudo.sh` — lets `deploy_tools.py` run with `sudo` without
   a password.
6. **Check:**
   ```bash
   ../venv/bin/python3 -m pytest --collect-only -q          # lists the tests
   systemctl status fw-validation-resume.service             # enabled
   ```
7. **When testing is done:** `sudo bash deploy/setup/setup_sut.sh --uninstall` removes the
   FW-Validation Shell boot entry, `startup.nsh`, the resume services, the sudoers files, the VT-d
   `resume=` GRUB change and the stored BIOS password / Secure Boot signing keys, and lists what to
   reset by hand (Secure Boot keys in BIOS Setup, MOK). `--dry-run` only prints what it would do.

Tools added to `Downloads/` later: `sudo python3 deploy/tools/deploy_tools.py` (or re-run the
setup script). Re-run `setup_sut.sh` after a `git pull` that changes `deploy/` — the resume
service and sudo rules contain repo paths.

### 2.1 UEFI Secure Boot (fTPM/PTT and dTPM tests only)

`test_runner.py` does this for you when you pick those tests. By hand, on the SUT:

```bash
sudo ./deploy/secure_boot/enable_secure_boot.sh auto     # runs the next stage, continues by itself after each reboot
sudo ./deploy/secure_boot/enable_secure_boot.sh status   # where am I
python3 deploy/secure_boot/sb_keys.py status             # whose keys are in PK/KEK/db (ours / factory)
```

Secure Boot only counts as done when the firmware holds **our own keys**: `provision` makes
`/etc/secureboot/key-material/test-cert.pem` the PK and a KEK, and the `.efi` tools are signed
with its key (`test-key.rsa`). With factory keys (e.g. AMI "Platform Key") the UEFI Shell refuses
every tool we sign and `db` cannot be changed from Linux — switching the Secure Boot knob on in BIOS
Setup is **not** enough.

The BIOS `Secure Boot` setting **cannot be switched on while no keys are enrolled** (Setup Mode) —
AMI only offers it once a Platform Key is in. So our keys always come first, and the setting last:

- **BIOS without keys (Setup Mode):** while you are at the SUT, the pre-flight runs
  `sign → modules → provision` back to back (no reboot in between), signs the EFI tools, and then
  switches `Secure Boot` on: nothing to do if the setting is already Enabled; otherwise from Linux or
  AMISCE when this BIOS build allows it; else it asks y/n **once** and reboots straight into BIOS
  Setup → Security → Secure Boot → **Secure Boot = Enabled**, Save & Exit. After that the check and
  the tests run by themselves. `python3 deploy/secure_boot/sb_keys.py knob` shows the setting.
- **BIOS with factory keys (most AMI / OEM BIOSes):** no software can delete them (deleting PK needs
  the owner's private key), so the pre-flight asks y/n and reboots straight into BIOS Setup →
  Security → Secure Boot: Secure Boot Mode = **Custom**, Factory Key Provision = **Disabled**,
  Key Management → **Delete all keys** (Reset to Setup Mode), Save & Exit. If `Secure Boot` still
  shows Enabled, leave it — then there is no second visit. Otherwise stay at the console: after
  Save & Exit, `sign → modules → provision` run by themselves and, once our keys are in, the SUT
  reboots **straight into BIOS Setup by itself** for **Secure Boot = Enabled**, Save & Exit.
  If the keys are still there after the first visit, it stops instead of looping.

If the MOK was never enrolled, the pre-flight asks for the MOK password before the first reboot, and
the blue MOK Manager screen comes right after it. Answering `n` to a BIOS Setup reboot cancels the
pre-flight cleanly (keys and signed tools stay); picking the tests again in `test_runner.py` asks
again. (`sudo ./deploy/secure_boot/enable_secure_boot.sh cancel` does the same by hand.)

`auto` runs these stages (you can also run them one by one):

| # | Command | What you do |
|---|---|---|
| 1 | `sudo ./deploy/secure_boot/enable_secure_boot.sh sign` | Set a one-time MOK password. Reboot; at the blue **MOK Manager** screen (it waits only a few seconds): Enroll MOK → Continue → Yes → password → Reboot. Skipped when the MOK is already enrolled (it survives a key reset) |
| 2 | `sudo ./deploy/secure_boot/enable_secure_boot.sh modules` | nothing (reboots by itself when run alone; `auto` goes straight on to `provision`) |
| 3 | `sudo ./deploy/secure_boot/enable_secure_boot.sh provision` | nothing — enrolls our keys in one run (`sb_enroll.py`: db and KEK = Microsoft + ours, PK = ours; a fresh 10-year key when ours is missing or expiring), then reboots when run alone (`auto` goes straight on) |
| – | enable (`auto` only, right after `provision`) | `auto` signs the tools, then turns `Secure Boot` on (only possible now that our PK is in), first way that works on this BIOS: **1.** AMI: writes its `SecureBootSetup` EFI variable from Linux (`sb_enroll.py secure-boot-on`, only with our keys in PK/KEK/db; one reboot); **2.** AMISCE (`Secure Boot` = Enabled, `Secure Boot Mode` = Custom, `Factory Key Provision` = Disabled; UEFI Shell reboots); **3.** BIOS Setup: Secure Boot = Enabled, Save & Exit — asks y/n when you are at the console, reboots straight into it when the keys were enrolled unattended (after deleting factory keys). A way that did not work is remembered per BIOS build (`/root/secureboot/.efivar_secure_boot_failed`, `.amisce_secure_boot_failed`) and skipped there |
| 4 | `sudo ./deploy/secure_boot/enable_secure_boot.sh verify` | nothing — checks Secure Boot is on **with our keys** and signs the `.efi` tools (`sign_efi_tools.sh`) |

- Stock Ubuntu kernel: stages 1–2 are only needed for a custom kernel.
- After an IFWI reflash the keys are gone: run `sudo ./deploy/secure_boot/enable_secure_boot.sh auto` again.
- After adding `.efi` tools: run `sudo ./deploy/secure_boot/enable_secure_boot.sh verify` again.
- With Secure Boot on, run the **signed** copy of each tool in the UEFI Shell (e.g. `MEInfo_signed.efi`).
  The shell `\EFI\shell\shellx64.efi` is signed in place and keeps its name; `verify` signs the
  upstream copy in `Tools/shellx64.efi` (downloaded if missing), never Ubuntu's `efi-shell-x64`.
  `TPM2ProvTool.efi` (TXT TPM provisioning) is signed in place too: Intel's `.nsh` scripts call it by name.

---

## 3. Install — Windows SUT

Do this once per SUT. Windows needs no resume service: tests that reboot register a Task
Scheduler logon task themselves.

1. **Clone the repo** and go into it:
   ```powershell
   git clone <repo_url> <folder>
   cd <folder>\edge-platform-security-toolsuite
   ```
2. **Drop the tool packages into `Downloads\`** (see [DEPENDENCIES.md](DEPENDENCIES.md)).
3. **Run the setup script** (safe to re-run). It creates `..\venv`, installs `requirements.txt`,
   stages the tools and installs OpenSSL for the AES-NI test. Steps 1–3 need no
   Administrator; the OpenSSL step does (it is skipped with a warning otherwise, or with
   `-SkipOpenSSL`):
   ```powershell
   .\deploy\setup\setup_sut_windows.ps1
   ```
4. **Per-test extras:**

   | Test | What to install |
   |---|---|
   | AES-NI | OpenSSL: done by the setup script (Administrator). `Coreinfo64.exe`: downloaded and staged into `Tools\` by the setup script (`deploy_tools.py`) |
   | CSME UPID, RPMC | `MEInfo.exe` — staged to `Tools\MEInfo.exe` from `Downloads\`; elsewhere: set `sut_meinfo_path_windows` in `config/suites/csme_config.yaml` |
   | TME (optional) | `msr-cmd.exe` or `pcm-msr.exe` in `bios_scripts\` lets the test read MSR 0x982 itself; without it TME is confirmed by the operator |
   | others | nothing |
5. **Check** (activate the venv in every new PowerShell):
   ```powershell
   ..\venv\Scripts\Activate.ps1
   python -m pytest --collect-only -q
   ```

### 3.1 UEFI Secure Boot (fTPM/PTT and dTPM tests only)

`test_runner.py` does this for you. By hand, in an **Administrator** PowerShell:
```powershell
.\deploy\secure_boot\enable_secure_boot_windows.ps1 auto     # provision -> reboot -> verify (continues after logon)
.\deploy\secure_boot\enable_secure_boot_windows.ps1 status
```

---

## 4. Configure

Most runs need no edits. All files must stay valid YAML.

**`config/test_config.yaml`** — the keys that matter for `tests/`:

| Key | Meaning |
|---|---|
| `bios.amisce` | `auto` (detect an AMI BIOS), `yes` or `no` — whether AMISCE reads/sets BIOS knobs |
| `verification.strict` | `false`: steps only the operator can confirm pass with a note; `true`: they fail (formal compliance runs) |
| `sut.hostname` | optional; if set, the HLAT test skips on any other host |
| `paths.artifacts_dir` | where logs go (default `logs`) |

The `sut.ip_address`, `serial_*`, `ipmi_*` and `reboot.*` keys are only used by `internal_nuc/`.

**`config/suites/<suite>_config.yaml`** — expected values and tool names per suite:

| File | Keys you may need to change |
|---|---|
| `csme_config.yaml` (also used by RPMC and Secure Debug) | `expected_upid_oem_id`, `expected_upid_refurbish_counter`, `expected_cse_ar_*`, `expected_bios_ar_*`, `expected_dfx_policy`, `sut_meinfo_path_linux` / `_windows` |
| `tme_config.yaml` | `expected_tme_capability_hex` |
| `aesni_config.yaml` | `coreinfo_exe_path`, `openssl_bin_dir` (Windows AES-NI) |
| `txt_config.yaml` | `getsec_tool`, `sinit_binary`, `tpm_prov_uefi_dir`, `aux_nv_index` / `sgx_nv_index` (default `0x1C10102` / `0x1C10104`, from the provisioning package) (TME/vPro support is auto-detected, no config needed) |
| `virtualization_config.yaml` | `vtinfo_efi_name` |
| `eom_config.yaml` | `fpt_efi_name`, `meinfo_efi_name` |
| `firmware_config.yaml` | `capsule_file`, `capsule_tool_efi` |
| `measured_boot_config.yaml` | `reboot_iterations` (default 5) |
| any suite with a manual step | `manual_gate_timeout_secs` (default 900; 0 = no limit) |

Optional overrides in a suite config: `usb_mount` keeps state and signal files on a mounted drive
instead of `logs/sut_state/`; the Windows PAVP, TME and measured boot tests use `win_state_dir`
(and `win_python_path`) instead.

### 4.1 BIOS settings per test case

The runner pre-flight sets and checks these from `deploy/bios_knobs/bios_knobs.yaml` (the source
of truth); for direct pytest runs set them yourself. **Set** = change it in BIOS Setup before the
run. **Verify** = fixed by the flashed IFWI, only read and checked. **—** = no BIOS knob needed.

| Suite | Test case | OS | IFWI | Secure Boot | BIOS knobs | Also needed |
|---|---|---|---|---|---|---|
| tme | IEC62443-4-2-TC_TME-FUNC-SUT | Linux | SEP5, SED5 | No | **Set:** VT-d = Enabled, Total Memory Encryption = Enabled | — |
| tme | IEC62443-4-2_Windows-TC_TME-FUNC-SUT | Windows | SEP5 | No | **Set:** VT-d = Enabled, Total Memory Encryption = Enabled | — |
| aesni | IEC62443-4-2-TC_AES-NI-FUNC-SUT | Linux | SEP5, SED5 | No | — | — |
| aesni | IEC62443-4-2_Windows-TC_AES-NI-FUNC-SUT | Windows | SEP5 | No | — | — |
| txt | IEC62443-4-2-TC_TXT-FUNC-SUT | Linux | SEP5, SED5 | No | **Set:** VT-d, Total Memory Encryption (vPro only), Intel Trusted Execution Technology, Alias Check Request = Enabled, In-Band ECC Support = Disabled, then a full power cycle. Step 4.1 (manual): reboot into BIOS Setup yourself, enable In-Band ECC, F4, boot Ubuntu, then create `step4_ibecc_enabled.txt`; the test then checks IBECC active and MemTotal dropped. TXT and TME are checked active at Steps 3.0, 4.3 and 9.1, IBECC at 4.3 and 9.1; Alias Check Request cannot be read back | — |
| measured_boot | IEC62443-4-2-TC_fTPM-PTT-FUNC-SUT | Linux | **SEP5 only** | **Yes** | **Verify:** TPM Device Selection = PTT | Active PCR bank = SHA256 |
| measured_boot | IEC62443-4-2_Windows-TC_fTPM/PTT-FUNC-SUT | Windows | SEP5 | **Yes** | **Verify:** TPM Device Selection = PTT | Active PCR bank = SHA256 |
| measured_boot | IEC62443-4-2-TC_dTPM-FUNC-SUT | Linux | **SED5 only** | **Yes** | **Verify:** TPM Device Selection = dTPM | Active PCR bank = SHA256 |
| measured_boot | IEC62443-4-2_Windows-TC_dTPM-FUNC-SUT | Windows | **SED5** | **Yes** | **Verify:** TPM Device Selection = dTPM | Active PCR bank = SHA256 |
| pavp | IEC62443-4-2-TC_PAVP-FUNC-SUT | Windows | SEP5 | No | **Set:** PAVP Enable = Enabled | — |
| virtualization | IEC62443-4-2-TC_Virtualization_Vtd-FUNC-SUT | Linux | SEP5, SED5 | No | **Set:** VT-d = Enabled, Intel (VMX) Virtualization Technology = Enabled, Low Power S0 Idle Capability = Disabled | Swap for S4: a swap partition, or a swap file >= `/sys/power/image_size` (`setup_sut.sh` step 9 grows `/swap.img` to the RAM size). The test adds `resume=` (+ `resume_offset=` for a file) to GRUB and reboots once if it is missing |
| virtualization | IEC62443-4-2-TC_Virtualization_Vtd_002-FUNC-SUT | Linux | SEP5, SED5 | No | **Set:** VT-d = Enabled, Intel (VMX) Virtualization Technology = Enabled, Low Power S0 Idle Capability = Disabled | IGD/IPU/IOP/ITBT VTD options absent |
| firmware | IEC62443-4-2-TC_BIOS_FW_Capsule_Update-FUNC-SUT | Linux | SEP5, SED5 | No | — | — |
| csme | IEC62443-4-2-TC_CSME_UPID-FUNC-SUT | Linux | SEP5, SED5 | No | — | UPID values from MFIT (see [§ 1](#1-before-you-start)) |
| csme | IEC62443-4-2_Windows-TC_CSME_UPID-FUNC-SUT | Windows | SEP5 | No | — | UPID values from MFIT (see [§ 1](#1-before-you-start)) |
| rpmc | IEC62443-4-2-TC_RPMC-FUNC-SUT | Linux | SEP5, SED5 | No | — | RPMC-enabled IFWI build (see [§ 1](#1-before-you-start)) |
| rpmc | IEC62443-4-2_Windows-TC_RPMC-FUNC-SUT | Windows | SEP5 | No | — | RPMC-enabled IFWI build (see [§ 1](#1-before-you-start)) |
| secure_debug | IEC62443-4-2-TC_Secure_debug-FUNC-SUT | Linux | SEP5, SED5 | No | — | — |
| sha_extension | IEC62443-4-2-TC_SHA_Extension-FUNC-SUT | Linux | SEP5, SED5 | No | — | — |
| eom | IEC62443-4-2-TC_EOM-FUNC-SUT | Linux | SEP5, SED5 | No | — | IFWI with HW Binding disabled (see [§ 1](#1-before-you-start)) |
| bios_resiliency | IEC62443-4-2-TC_BIOS_Resiliency_Recovery-FUNC-SUT | Linux | **Resiliency** | No | — | — |
| hlat | IEC62443-4-2-TC_HLAT-FUNC-SUT | Windows | SEP5 | No | — | — |
| cet | IEC62443-4-2-TC_CET-FUNC-SUT | Windows | SEP5 | No | — | — |
| hdcp | IEC62443-4-2-TC_HDCP-FUNC-SUT | Windows | SEP5 | No | — | — |

**Menu paths** (Intel reference BIOS; an OEM AMI BIOS may differ):

| Knob | Menu path |
|---|---|
| Total Memory Encryption, Intel (VMX) Virtualization Technology, Intel Trusted Execution Technology, Alias Check Request | Intel Advanced Menu → CPU Configuration |
| VT-d | Intel Advanced Menu → System Agent (SA) Configuration → VT-d Setup Menu |
| PAVP Enable | Intel Advanced Menu → System Agent (SA) Configuration → Graphics Configuration (PAVP) |
| Low Power S0 Idle Capability | Intel Advanced Menu → ACPI settings |
| In-Band ECC Support | Intel Advanced Menu → Memory Configuration |
| TPM Device Selection | Platform Information → Current TPM Location (fixed by the flashed IFWI) |

- Total Memory Encryption is greyed out unless VT-d is Enabled; VT-d is greyed out while X2APIC
  Enable is Enabled.
- On an AMI BIOS, AMISCE sets them for you — see [deploy/README.md](../deploy/README.md)
  (e.g. `configure_bios_knobs_linux.py --marker tme`, or `--marker ifwi_sep5` for a whole IFWI group).

---

## 5. Run tests

### 5.1 Test runner (recommended)

```bash
python3 test_runner.py     # Linux
python test_runner.py      # Windows (Administrator PowerShell)
```
It uses `../venv` by itself and lists only the suites for this OS (Linux: 12, Windows: 9).
Linux SUT example:

```
======================================================================
              🛡️  BIOS Security Automation - Test Runner
======================================================================
 🖥️  Host: Linux SUT (sut_linux)  |  14 tests available  |  O = change
 💾 Flashed IFWI: SEP5  (TPM manufacturer INTC = PTT)
======================================================================

📋 TEST SUITES
+----+-----------------+-------+----------------------+----------------------------------------------------+
| #  | Suite           | Tests | IFWI                 | Description                                        |
+----+-----------------+-------+----------------------+----------------------------------------------------+
| 1  | tme             | 1     | SEP5/SED5            | TME (Total Memory Encryption)                      |
| 2  | aesni           | 1     | SEP5/SED5            | AES-NI (AES New Instructions)                      |
| 3  | txt             | 1     | SEP5/SED5            | TXT (Trusted Execution Technology)                 |
| 4  | measured_boot   | 2     | SED5 only, SEP5 only | Measured Boot (fTPM/dTPM)                          |
| 5  | firmware        | 1     | SEP5/SED5            | Firmware update                                    |
| 6  | csme            | 1     | SEP5/SED5            | CSME (Converged Security and Manageability Engine) |
| 7  | rpmc            | 1     | SEP5/SED5            | RPMC (Replay Protected Monotonic Counter)          |
| 8  | secure_debug    | 1     | SEP5/SED5            | Secure Debug                                       |
| 9  | sha_extension   | 1     | SEP5/SED5            | SHA Extension (AES-NI/SHA-NI openssl benchmark)    |
| 10 | virtualization  | 2     | SEP5/SED5            | Virtualization (VT-d/VMX)                          |
| 11 | eom             | 1     | SEP5/SED5            | EOM (End of Manufacturing)                         |
| 12 | bios_resiliency | 1     | Resiliency only      | BIOS Resiliency / Recovery                         |
+----+-----------------+-------+----------------------+----------------------------------------------------+
 SEP5/SED5 = runs on either IFWI. 'only' = needs that IFWI flashed.
 Not available on sut_linux: pavp, hlat, cet, hdcp

🚀 RUN
   1-12     Run one suite (e.g. 1) or several (e.g. 1,3,5)
   I        Run a whole IFWI group (every test on one flashed image)
   M        Run by pytest marker expression
   F        Re-run FAILED tests from the last run
   R        Repeat the last run

📊 RESULTS
   L        Last run results
   H        Run history

⚙️  SETTINGS
   O        Change execution context
   P        SUT readiness -- BIOS knobs / Secure Boot status

👋 Q        Quit
======================================================================
```

| Key | What it does |
|---|---|
| `1`, `1,3,5` | Run one or several suites |
| `I` | Run a whole IFWI group (SEP5 / SED5 / Resiliency) |
| `M` | Run a pytest marker expression, e.g. `tme and not manual` |
| `F` / `R` | Re-run the failed tests / repeat the last run |
| `L` / `H` | Last run result (per-test reasons, log paths) / run history |
| `O` | Change the detected OS context |
| `P` | SUT readiness: BIOS, AMISCE, Secure Boot, TPM, pre-flight state |
| `X` | Shown only when a run left resume state behind: lists and deletes it (type `CLEAR`) |
| `Q` | Quit |

Every run goes through the same steps:

1. **Preview** — the tests in run order (`eom` and `firmware` always last). `Enter` runs all,
   `3,1,2` picks/reorders, `B` back, `N` cancel. `eom` and `firmware` cannot be undone and ask for
   a typed `yes`. On Linux the `On flashed <IFWI>` column marks fTPM/dTPM on the wrong IFWI as
   `WRONG IFWI`; picking them prints what to flash and offers **D** (drop them, run the rest) or
   **B** (back). If the TPM cannot be read, the runner asks which IFWI is flashed.
2. **Pre-flight** — reads what the tests need from the SUT and prints the plan:
   - **BIOS knobs** — each knob is read from the OS where possible (see
     [TEST_COVERAGE.md § 5](TEST_COVERAGE.md#5-what-the-tests-read-back)). Knobs already set need nothing.
     - A knob the CPU cannot support (TME on a non-vPro CPU: CPUID.07H:ECX[13] = 0) is skipped with a
       note in the plan -- it would be accepted by the BIOS but has no effect. The TME test then
       fails with "TME is NOT supported by this CPU"; the other tests run as usual.
     - AMI BIOS: AMISCE sets and checks the rest. Knobs in protected BIOS variables (VMX, TME, TXT ...)
       need the BIOS admin password: if none is stored, the pre-flight asks once -- **P** type the
       existing one, or **S** choose one and set it in BIOS Setup (one reboot, then it continues by
       itself). It is stored encrypted on the SUT, not in a config file
       ([deploy/README.md](../deploy/README.md#bios-knobs-that-will-not-change-protected-variables)). A knob set by an earlier AMISCE PASS on the same
       BIOS build is not set again while the BIOS Setup variables (`Setup`, `CpuSetup`, `SaSetup`,
       `PchSetup`) are unchanged since (Linux: SHA-256 per variable in `logs/bios_knobs_last_pass.json`).
       A knob changed in BIOS Setup or an IFWI reflash changes them, so AMISCE checks the knobs again.
     - Other BIOS: you choose **Y** (reboot into BIOS Setup, set them, Save & Exit — the pre-flight
       proves the reboot and reads them back), **S** (already set — refused if the OS reads a knob as
       wrong) or **B** (back).
   - **Secure Boot** for the fTPM/PTT and dTPM tests (see 2.1 / 3.1). On Linux the runner asks
     before the MOK reboot so you are at the screen.
   - When a step reboots the SUT, `deploy/preflight/preflight_chain.py` continues after each boot
     and then starts the tests by itself (log: `logs/preflight.log`).
3. **Stop at first failure?** — `y` adds `-x`; default runs everything.

### 5.2 pytest directly

No pre-flight: set BIOS knobs ([4.1](#41-bios-settings-per-test-case)) and Secure Boot yourself. Run from the repo folder with the venv
(Linux: `../venv/bin/python3 -m pytest …`; Windows: activate `..\venv` first).

```bash
python -m pytest tests/tme/test_ec62443_tme_sut_func.py -s --setup-confirmed --yes   # one file
python -m pytest tests/measured_boot/ -s --setup-confirmed --yes                     # one suite folder
python -m pytest tests/ -m "csme or rpmc" -s --setup-confirmed --yes                 # by marker
python -m pytest tests/ -s --setup-confirmed --yes                                   # everything for this OS
```

| Flag | Meaning |
|---|---|
| *(none)* | every test prints its checklist and **SKIPs** |
| `--setup-confirmed` | prints the checklist and asks you to type `yes` (needs `-s` to see the prompt) |
| `--setup-confirmed --yes` | checklist accepted without a prompt |
| `-s` | show live output and prompts |
| `-x` | stop at the first failure |

- Tests for the other OS are skipped automatically. `eom` and `firmware` always run last.
- Linux: fTPM on a SED5 board and dTPM on a SEP5 board are skipped automatically
  (`needs the SED5 IFWI; flashed IFWI is SEP5 (…)`).
- **`tests/` includes `eom` (permanently locks manufacturing mode) and `firmware` (reflashes the
  BIOS).** Exclude them when you don't mean to run them: `-m "not eom and not firmware"`.
- `-v` is already on (`pytest.ini`). Markers: `pytest.ini` / [README.md](../README.md#available-markers).
  `pytest.ini` also sets a 1800 s timeout per test.

---

## 6. Reboots and manual steps

### 6.1 Tests that reboot

- **Linux:** the test reboots the SUT itself (UEFI Shell phases, S5) and
  `fw-validation-resume.service` continues the batch after boot.
- **Windows:** the test registers the `IEC62443_Batch_Resume` logon task and asks you to reboot
  (or reboots itself for measured boot). **Log on** after the reboot — the batch continues.
- A **status window** opens by itself while a batch with reboots runs (Windows: new console at
  start and after each logon; Linux: terminal at start and at desktop login). It shows the reboots
  done and left, the test running, what the next reboot needs from you, and the latest log lines.
  Closing it never stops the tests. Open it by hand: `python deploy/resume/status_window.py`.

```
================================================================================
 🔄 RESUMED AFTER REBOOT 1 of 2 -- batch 20261025_110000   (started 07:14:59, 2m 00s ago)
================================================================================
   #  Test                                        Status        Reboots
   1  IEC62443-4-2_Windows-TC_CSME_UPID-FUNC-SUT  PASSED        -
   2  IEC62443-4-2-TC_PAVP-FUNC-SUT               RESUMING NOW  1 of 1 done (manual)
   3  IEC62443-4-2_Windows-TC_TME-FUNC-SUT        PENDING       1 manual

 Reboots: 1 done, 1 to go (0 automatic, 1 need you)
 Next   : REBOOT 2 of 2 -- test 3 (IEC62443-4-2_Windows-TC_TME-FUNC-SUT)
          NEEDS YOU: BIOS Setup: Intel Advanced Menu -> CPU Configuration -> Total Memory Encryption = Enabled
================================================================================
```

### 6.2 Manual steps (signal files)

When a test needs you (a BIOS change, a visual check), it prints the steps and waits for a
**signal file** in `logs/sut_state/`. It prints the exact command, e.g.:
```bash
touch "<repo>/logs/sut_state/step3_cet_done.txt"                                   # Linux: done
echo "FAIL HDCP shows Not Compatible" > "<repo>/logs/sut_state/step3_hdcp_done.txt"    # step failed -> test fails now
```
```powershell
New-Item -ItemType File -Force "<repo>\logs\sut_state\step3_cet_done.txt"           # Windows: done
Set-Content "<repo>\logs\sut_state\step3_hdcp_done.txt" "FAIL HDCP shows Not Compatible"
```

The file only means "I am done". The test then checks the result itself where it can:

| You see | Meaning |
|---|---|
| `PASSED` | passed |
| `PASSED` + `Confirmed by the operator: …` | passed; the listed steps could not be checked by the test (`verification.strict: true` fails them instead) |
| `[NOT YET] The check above failed …` | the setting is not in effect — fix it and create the file again (3 tries, then FAILED) |
| `Signal ignored: the SUT has not rebooted …` | the step needs BIOS Setup but the SUT did not reboot |

Rebooting while a test waits is safe: it resumes and keeps waiting at the same step. The
manual-step tests are listed in [TEST_COVERAGE.md](TEST_COVERAGE.md#1-test-inventory).

### 6.3 BIOS Resiliency (RVP only)

`IEC62443-4-2-TC_BIOS_Resiliency_Recovery-FUNC-SUT` runs only on an Intel RVP: its EC performs
the resiliency backup and rollback. Normally the POC provides both the Resiliency IFWI and the
corrupted IBB file. Manual input: the checklist, one `yes`, one signal file.

| Step | Who | What |
|---|---|---|
| Pre-test | you | Flash the Resiliency IFWI, boot Ubuntu, see the **blue** box "Resiliency backup begin … successful" |
| 1.0 | test | RVP check: DMI board vendor / name / product must match `rvp_board_patterns` |
| 2.0 / 3.0 | test | `Obb.bin` must be on the ESP (`/boot/efi`); missing → FAIL, reflash the correct Resiliency IFWI |
| 4.0 | you + test | Type `yes` → the SUT powers off after `poweroff_delay_secs` (`no` aborts; no terminal → power off by hand) |
| 5.0 | you | Flash the corrupted IBB with Dediprog, power on, see the **purple** box "Resiliency rollback" (Top Swap enabled), let it boot to Ubuntu, create `step5_rollback_done.txt` (or write `FAIL …` into it) |
| 6.x | test | The SUT rebooted (boot id), BIOS version logged, `Obb.bin` still present → PASS (purple box: operator-confirmed) |

Settings: `config/suites/bios_resiliency_config.yaml`. `/boot/efi` is root-only on Ubuntu; the
test uses the exact `sudo find` rule that `setup_sut.sh` installs — re-run
`sudo ./deploy/setup/setup_sut.sh` once on SUTs set up before this rule existed.

**Reference only — building the corrupted IBB yourself** (Windows host with BpmGen2 from the SBL
package and HXD):

1. Read the SPI flash with Dediprog: Detect → select the SPI ID → Edit → Read → *Chip buffer to
   File* → `<FileName>.bin`.
2. `BpmGen2.exe INFO <FileName>.bin` → section `# FIT Table: #` → address of the first
   `07- BIOS MODULE` entry (e.g. `00000000ffe80000`).
3. Image offset = `image_size - (0x100000000 - address)` (e.g. `0xffe80000` in a 32 MB image →
   `0x01e80000`).
4. In HXD: Ctrl+G to the offset, overwrite the 5 highlighted IBB bytes (e.g. `FF FF FF FF FF`),
   save as `<FileName>_resiliency_IBB.bin`.

Resiliency IFWI: MFIT → decompose the BootGuard 5 IFWI → replace the BIOS region with the
Resiliency ROM → build.

---

## 7. Clean up an interrupted run

Tests clean up after themselves when they end normally. If a run was killed (power loss,
force-kill), leftover files can make the next boot resume the old run.

**Easiest:** start `test_runner.py`; it shows a warning and the `X` key, which lists the files and
deletes them after you type `CLEAR` (logs are kept). In the runner, one Ctrl+C lets pytest clean up;
a second one kills it.

By hand:
```bash
# Linux
rm -f logs/sut_state/* logs/batch_status.json
sudo rm -f /boot/efi/maintest.nsh /boot/efi/state_done.txt
```
```powershell
# Windows
Remove-Item -Force .\logs\sut_state\*, .\logs\batch_status.json, .\logs\win_resume_args.txt -ErrorAction SilentlyContinue
schtasks /delete /tn IEC62443_Batch_Resume /f
```

---

## 8. Results and logs

| What | Where |
|---|---|
| Result of the last run / whole batch | `test_runner.py` → `L` (and `H` for history) |
| Combined log of a batch (all reboots), ends with `BATCH FINAL SUMMARY` | `logs/batch_<timestamp>_combined.log` |
| Log of one pytest process (one per boot) | `logs/test_run_<timestamp>/test_execution.log` + artifacts in the same folder |
| HTML report (runs started from the menu) | `logs/<selection>_<timestamp>.html` |
| Output of runs resumed after a reboot | Linux: `logs/resume_service.log`; Windows: the logon console + status window |
| Pre-flight progress | `logs/preflight.log` |
| pytest's own debug log | `logs/pytest.log` |

Each test (or test phase) ends with a `RESULT: <outcome>  >>  <test>` line: `PASSED`, `FAILED`
(with the reason), `SKIPPED`, or `REBOOT` / `PENDING REBOOT` when a phase ends at a reboot and
the test continues after boot. To scan many runs:
```bash
grep -h "RESULT:" logs/test_run_*/test_execution.log                          # Linux
Select-String "RESULT:" logs\test_run_*\test_execution.log                    # Windows
```

---

## 9. Troubleshooting

**All OSes**

| Symptom | Cause | Fix |
|---|---|---|
| Every test `SKIPPED … pre-test setup not confirmed` | `--setup-confirmed` missing | Complete the checklist, re-run with `--setup-confirmed --yes` |
| `SKIPPED … Windows-only test` / `Linux-only test` | test for the other OS | Run it on that OS |
| `SKIPPED … needs the SED5 IFWI; flashed IFWI is SEP5` (or the reverse) / runner `WRONG IFWI` | dTPM needs RPSF_SED5, fTPM needs RPSF_SEP5; the TPM manufacturer shows the other one is flashed | Flash the IFWI the test needs and run it in a separate session |
| Runner: `Could not detect the flashed IFWI` | `tpm2_getcap` cannot read the TPM (tpm2-tools missing, TPM disabled, `sudo -n` refused) | Pick the flashed IFWI at the prompt; fix with `sudo ./deploy/setup/setup_sut.sh` |
| Test waits for a signal file | the manual step is not confirmed yet | Do the printed steps, then run the printed `touch` / `New-Item` command |
| `[NOT YET] The check above failed` | the test read the setting and it is not in effect | Fix what the evidence lines show, create the file again |
| `Signal ignored: the SUT has not rebooted …` | BIOS step without a reboot | Reboot into BIOS Setup (Linux `sudo systemctl reboot --firmware-setup`, Windows `shutdown /r /fw /t 0`), change it, boot, then create the file |
| `[WRONG] "<knob>" …` / "BIOS knob(s) not set" | the OS reads the knob as off | Set it in BIOS Setup (path printed), Save & Exit |
| Pre-flight `Cannot skip -- these knobs are not set` | you answered **S** but a knob reads as wrong | Answer **Y** and set it |
| `Configuration file not found` / YAML error | `config/test_config.yaml` missing or broken | `git checkout config/test_config.yaml`, then redo your edits |
| `state.json belongs to a different test` (warning) | leftover state of another test | Nothing to do — it is cleared automatically |
| Tests resume an old run after boot | killed run left state behind | [7. Clean up](#7-clean-up-an-interrupted-run) |

**Linux**

| Symptom | Cause | Fix |
|---|---|---|
| Tests do not resume after a reboot | service missing or outdated (e.g. after `git pull` / the move to `logs/sut_state`) | `sudo bash deploy/setup/setup_sut.sh`; check `systemctl status fw-validation-resume.service` and `logs/resume_service.log` |
| `maintest.nsh` not run in the UEFI Shell | `startup.nsh` missing | `sudo cp deploy/resume/startup.nsh /boot/efi/startup.nsh` |
| SUT boots Ubuntu instead of the UEFI Shell and never resumes | Secure Boot on and the shell unsigned | `sudo ./deploy/secure_boot/sign_efi_tools.sh` |
| Same, but the shell **is** signed (`UEFI phase N did NOT complete`, or the test stops before the reboot naming CVE-2025-2486) | the shell is Ubuntu's `efi-shell-x64` build, which exits at once with Secure Boot on | `sudo ./deploy/secure_boot/sign_efi_tools.sh` — downloads the upstream EDK2 shell (`deploy/secure_boot/fetch_uefi_shell.sh`, SHA-256 checked) to `Tools/shellx64.efi` and re-signs it. Offline: copy an upstream `shellx64.efi` to `Tools/` first |
| UEFI Shell: `Access Denied` / `Security Violation` | unsigned tool with Secure Boot on | `sudo ./deploy/secure_boot/enable_secure_boot.sh verify`, then run the `*_signed.efi` copy |
| `.efi` tool not found | not on the EFI partition | `sudo python3 deploy/tools/deploy_tools.py` (see [DEPENDENCIES.md](DEPENDENCIES.md)) |
| `provision`: `Writing PK failed: ... EINVAL` / `EACCES` | the firmware refused our signed PK update | Enroll by hand: BIOS Setup → Security → Secure Boot → Key Management → Platform Key → Set New → from file `EFI\fw-validation\test-cert.der` (also append it to KEK and db), then `auto` again |
| `auto` / `provision` / `verify` / `sign_efi_tools.sh`: `keys that are NOT ours (factory keys)` | PK is the BIOS vendor's (e.g. AMI "Platform Key"), not our `test-cert` — tools we sign would be refused | Run `sudo ./deploy/secure_boot/enable_secure_boot.sh auto` in a terminal and answer `y`: it reboots into BIOS Setup → Security → Secure Boot: Mode = Custom, Factory Key Provision = Disabled, Key Management → Delete all keys, Save & Exit; the rest continues by itself. Check with `python3 deploy/secure_boot/sb_keys.py status` |
| Secure Boot on with our keys gets factory keys back | Secure Boot Mode = Standard or Factory Key Provision = Enabled (AMI restores its defaults) | Keep Custom mode + Factory Key Provision = Disabled, delete all keys, run `auto` again |
| `verify`: `Secure Boot is NOT enabled` | earlier stages unfinished or Secure Boot off in BIOS | Run `auto` (sets the knob with AMISCE on an AMI BIOS, else asks y/n and reboots into BIOS Setup); or BIOS: Secure Boot = Enabled |
| Measured boot Step 13.0: only `PCR[07]: MISMATCH`, boot 1 differs and boots 2–5 match | dbx (revocation list) was empty after the key enrollment; Ubuntu's `secureboot-db.service` added the Microsoft dbx update on the first boot, and PCR 7 measures dbx | Fixed in `provision` (applies the dbx update in the same run). On a SUT enrolled before the fix nothing to do — dbx is final after one boot (`python3 deploy/secure_boot/sb_keys.py status` shows the dbx entry count); rerun the test |
| AMISCE: `'Secure Boot': expected 'Enabled', got 'Disabled'` (import `SCE_EXIT=0x0`) | this BIOS build ignores AMISCE writes to the Secure Boot knob | Nothing to fix: it is remembered for this BIOS build; the next `auto` / pre-flight writes the knob from Linux instead (one reboot), and only if that does not stick either, asks y/n and reboots into BIOS Setup |
| MSR not readable | `msr` module / `msr-tools` missing | Re-run `setup_sut.sh` (installs `msr-tools`, loads `msr`) |
| Resiliency Step 1.0: `This test needs an Intel RVP board` | DMI board name does not match `rvp_board_patterns` | Run on an RVP; on a real RVP add its `board_name` to `config/suites/bios_resiliency_config.yaml` |
| Resiliency Step 2.0: `Searching /boot/efi for Obb.bin failed` | sudoers rule missing | `sudo ./deploy/setup/setup_sut.sh` |
| `test_runner.py` pre-flight asks `[sudo] password` (e.g. for `enable_secure_boot.sh auto --no-reboot`) | sudo rules from an older `setup_sut.sh`, or the repo / venv moved | `sudo ./deploy/setup/setup_sut.sh` once (last password); check with `sudo -n -l` |
| Resiliency Step 3.0: `Obb.bin was not found` | the resiliency backup did not run (wrong IFWI) | Reflash the correct Resiliency IFWI, check the blue backup box at boot, re-run |
| TXT Step 4.3 / 9.1: `In-Band ECC is not confirmed active` | IBECC_ACTIVATE reads `0xFFFFFFFF` or bit 0 = 0, or the state is unknown (`igen6_edac` not loaded). `igen6_edac` also registers controllers when IBECC is disabled, so the test does not trust it alone | BIOS Setup → Intel Advanced Menu → Memory Configuration → In-Band ECC support = Enabled; if it is, `sudo modprobe igen6_edac` |
| TXT Step 3.0: `In-Band ECC is already ENABLED` | The test needs IBECC Disabled at the start for the MemTotal BEFORE baseline | BIOS Setup → Intel Advanced Menu → Memory Configuration → In-Band ECC support = Disabled, F4, run again |
| TXT Step 4.2: `Expected MemTotal to DECREASE after enabling IBECC` | In-Band ECC was not enabled at Step 4.1 (or not saved) | Enable it in BIOS Setup at Step 4.1, press F4, boot, then create the signal file again (3 attempts) |
| TXT Step 2.2: `Secure Boot is enabled but … TPM2ProvTool.efi is unsigned` | Intel's provisioning scripts call `TPM2ProvTool.efi` by name; the firmware refuses it unsigned | `sudo ./deploy/secure_boot/sign_efi_tools.sh` (signs it in place); again after re-copying the provisioning folder |
| TXT Step 6.2: `ResetPlatformAuth.nsh could not set PlatformAuth to EMPTY` (`Did not satisfy PlatformPolicy`), then AUX/SGX index not found | The BIOS has not installed the platform authPolicy Intel TXT provisioning needs (seen on OEM/AMI BIOS), so every provisioning script stops | AMI Aptio Setup → Security → Platform Hierarchy = [Enabled] (under the TPM 2.0 device section). If it already is, the BIOS build itself lacks it: the BIOS vendor must provide a build that installs the Intel TXT platform authPolicy (as the Intel reference BIOS does). Details: `txt_prov_SetPlatformAuth.log` in the run's log folder |
| TXT Step 3.0 / 9.1: `TXT is not enabled: MSR 0x3A = ...` | IA32_FEATURE_CONTROL bit 15 (SENTER global enable) or bit 0 (lock) is 0: the TXT setting was not saved, no full power cycle yet, or the BIOS turned TXT off (no usable TPM, VT-d off) | BIOS Setup → Intel Advanced Menu → CPU Configuration → Intel Trusted Execution Technology = Enabled, full power cycle; check TPM and VT-d are enabled |
| TXT Step 8.0: `GETSEC[SENTER] failed: TXT.ERRORCODE = ...` | The ACM recorded a new error during SENTER (bit 31 = valid). The value before SENTER is in the log | Decode it with the SINIT ACM error tables; usual causes: TPM not provisioned, SINIT not matching the CPU, TXT/VT-d settings. Register dump: `txt_registers.txt` |
| TXT Step 8.1: `GETSEC[SENTER] did not report the TXT environment` / `txt_getsec_result.txt not found` | getsec64's output (`EFI\txt_getsec_result.txt`) lacks `GETSEC[SENTER] complete. System is now in TXT Environment.`, or getsec64 did not run | Read the saved output in the log folder and the UEFI screen / serial console; same causes as Step 8.0 |
| TXT Step 3.0 / 9.1: `TME is not active` (vPro only) | MSR 0x982 IA32_TME_ACTIVATE bit 1 is 0 | BIOS Setup → Intel Advanced Menu → CPU Configuration → Total Memory Encryption = Enabled |
| VT-d Step 5.6: `No active swap partition or swap file` | S4 needs swap to hibernate to (zram is not used) | Re-run `sudo ./deploy/setup/setup_sut.sh` (step 9 prepares `/swap.img`), or set `swap_partition` in `config/suites/virtualization_config.yaml` |
| VT-d Step 5.6: `Swap file ... smaller than ... /sys/power/image_size` | The swap file cannot hold the hibernation image (Ubuntu's installer makes an 8 GiB `/swap.img` at most) | Re-run `sudo ./deploy/setup/setup_sut.sh` (step 9 grows it to the RAM size; `HIBERNATE_SWAP_GB=<n>` overrides) |
| VT-d Step 8.0 WARNING `Kernel lockdown ... may refuse S4`, then the after-S4 VTInfo check fails | UEFI Secure Boot is on; Ubuntu's kernel then refuses hibernation (the test only warns, it does not stop) | Disable Secure Boot in BIOS Setup for the VT-d test, re-run |
| VT-d: `sudo ... needs a password (no terminal)` (rtcwake, update-grub, filefrag) | The test was resumed after a reboot and the passwordless sudo rule is missing | Re-run `sudo ./deploy/setup/setup_sut.sh` (step 5 adds the rules) |
| A test asks `[sudo] password`, or dTPM / fTPM / TXT fail after their reboot with `sudo: a password is required` | The SUT was set up without `--nopasswd-all` | `sudo ./deploy/setup/setup_sut.sh --add-nopasswd-all` (test boards only), or answer **Y** when `test_runner.py` offers it |
| VT-d Step 5.6: `Kernel still lacks resume=... after the automatic GRUB reboot` | another file overrides `GRUB_CMDLINE_LINUX` (e.g. `/etc/default/grub.d/*.cfg`) or a different boot entry was used | Check `logs/test_run_*/grub_resume_check.log`, fix the override, re-run the test (the backup is `/etc/default/grub.fwval.bak`) |

**Windows**

| Symptom | Cause | Fix |
|---|---|---|
| `No module named 'pytest'` | venv not created / not active | `.\deploy\setup\setup_sut_windows.ps1`, then `..\venv\Scripts\Activate.ps1` |
| `Access is denied` (schtasks, TPM, MEInfo) / test does not resume | not an Administrator PowerShell | Re-open PowerShell as Administrator and re-run |
| Test does not continue after reboot | the resume task runs at boot as SYSTEM (no sign-in needed, ~30-90 s after boot); the status window only appears once someone signs in | Check `schtasks /query /tn IEC62443_Batch_Resume` (tests) / `FW_BIOS_Knob_Resume` (BIOS knobs) and the newest `logs\test_run_*` folder |
| `openssl is not installed or not in PATH` / `openssl.exe not found` (AES-NI) | OpenSSL missing | Re-run `.\deploy\setup\setup_sut_windows.ps1` from an Administrator PowerShell, then open a new PowerShell |
| `coreinfo64.exe not found` / `Coreinfo64.exe not found` | not staged, or `coreinfo_exe_path` wrong | Run `python deploy\tools\deploy_tools.py` (downloads `Coreinfo.zip`, stages `Tools\Coreinfo64.exe`); otherwise fix the path in `config/suites/aesni_config.yaml` |
| `MEInfo` not found (CSME, RPMC) | `Tools\MEInfo.exe` missing | Put the CSME kit in `Downloads\` and re-run setup, or set `sut_meinfo_path_windows` |
