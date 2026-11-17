# Dependencies

Everything the tests in `tests/` need besides the repo itself: Python packages, OS packages,
scripts bundled in the repo, and the external (mostly licensed Intel) tools. Installation steps
are in [TEST_GUIDE.md](TEST_GUIDE.md) §2 (Linux) and §3 (Windows).

| Kind | Source of truth | Installed by |
|---|---|---|
| Python packages | `requirements.txt` | `deploy/setup/setup_sut.sh` / `setup_sut_windows.ps1` (into `../venv`) |
| Linux OS packages | `deploy/setup/setup_sut.sh` | `setup_sut.sh` (apt) |
| Bundled scripts | `bios_scripts/` | nothing — the tests run them from the repo |
| External tools | `deploy/tools/tools.xml` + `deploy/tools/download_links.xml` | you download them into `Downloads/`; `deploy/tools/deploy_tools.py` stages them |
| Windows extras | this page | `setup_sut_windows.ps1` (OpenSSL); you (the rest, manual install) |

---

## 1. Python packages (`requirements.txt`)

Python 3.10 or newer. `requirements.txt` pins each package to the tested major/minor version (`~=`).

| Package | Used for |
|---|---|
| `pytest`, `pyyaml` | running the tests, reading `config/` |
| `pytest-timeout` | `@pytest.mark.timeout(0)` on the Windows tests that wait for a reboot |
| `pytest-html` | the HTML report `test_runner.py` writes to `logs/` |
| `py7zr` | reading `.7z` packages (AMISCE) in `deploy_tools.py` |

`paramiko` and `pyserial` are only needed by the internal NUC-driven tests (`internal_nuc/`, not part
of the customer release): `pip install -r internal_nuc/requirements.txt`. Without them `conftest.py`
still loads; the NUC-only fixtures skip.

---

## 2. Linux OS packages (`setup_sut.sh`)

`tpm2-tools`, `efibootmgr`, `python3-venv`, `msr-tools`, `dmidecode`, `p7zip-full`; the script
also loads the `msr` kernel module. `openssl` (SHA Extension, AES-NI) is part of a standard Ubuntu
install.

UEFI Shell for the FW-Validation Shell boot entry: `setup_sut.sh` (and `sign_efi_tools.sh`) run
`deploy/secure_boot/fetch_uefi_shell.sh`, which downloads the upstream EDK2 shell
([pbatard/UEFI-Shell](https://github.com/pbatard/UEFI-Shell/releases), SHA-256 pinned) to
`Tools/shellx64.efi` with `curl`. Ubuntu's `efi-shell-x64` is only a fallback: it exits at once
when Secure Boot is on (CVE-2025-2486). Offline SUT: copy an upstream `shellx64.efi` to `Tools/`
before running `setup_sut.sh`.

---

## 3. Bundled scripts (`bios_scripts/`) — no download

The tests run these from the repo checkout; nothing copies them anywhere.

| File | Used by | Config key (default) |
|---|---|---|
| `checkquote.sh` | Linux fTPM/PTT + dTPM — TPM-attested quote of PCR 0–9 (adapted from `tpm2-tools`) | `sut_checkquote_script` (`bios_scripts/checkquote.sh`) |
| `helpers.sh` | sourced by `checkquote.sh` | `sut_helper_script` (`bios_scripts/helpers.sh`) |
| `run_aesni_test.py` | AES-NI (Linux + Windows) | — |
| `tme_check.py` | Windows TME — CPUID + MSR 0x982 | — |

---

## 4. Windows extras

| Item | Needed by | Where |
|---|---|---|
| OpenSSL for Windows ([installer](https://slproweb.com/products/Win32OpenSSL.html)) | AES-NI | installed by `deploy\setup\setup_sut_windows.ps1` (Administrator): pinned Win64 Light MSI from component `OpenSSL_Windows` in `deploy/tools/download_links.xml`, SHA-256 checked, `bin` added to the system `PATH`. Offline SUT: put that `.msi` in `Downloads\` first |
| Sysinternals `Coreinfo64.exe` (64-bit) | AES-NI | staged into `Tools\` by `deploy_tools.py`, which downloads `Coreinfo.zip` itself (section 5) |
| `msr-cmd.exe` or `pcm-msr.exe` (optional) | TME | in `bios_scripts\` (where `tme_check.py` looks); without one, TME is confirmed by the operator |

---

## 5. External tools (`deploy/tools/tools.xml`)

Not in git. Get them from the links in `deploy/tools/download_links.xml` (Intel downloads need
the matching access/NDA), drop the files, folders or archives (`.zip`, `.7z`) into `Downloads/`,
then stage them (section 6). Links marked `auto_download="true"` (public, direct links only:
`Coreinfo.zip`) are downloaded into `Downloads/` by `deploy_tools.py` itself when the tool is
missing, and only if the file matches the `sha256` pinned in `download_links.xml`; over a proxy,
set `HTTPS_PROXY` first. Offline, or when Microsoft has updated the file (SHA-256 mismatch): drop
the file in by hand.

| Staged as (in `Tools/`) | OS | Also copied to the EFI partition | Needed by | Package (component) |
|---|---|---|---|---|
| `VTInfo.efi` + `vt-tests` | both | `EFI/` | VT-d (`virtualization`) | [VtInfo_v1.1.83.zip](https://cdrdv2.intel.com/v1/dl/getContent/640214/640215?filename=VtInfo_v1.1.83.zip) (`VTInfo`) |
| `MEInfo` (Linux binary) | Linux | — | CSME UPID, RPMC, Secure Debug | [Intel_Silicon_FW_Kit_PTL-H_2026WW07.4.01_ECG_CSME_SSE_26WW18.zip](https://cdrdv2.intel.com/v1/dl/getContent/918226/918227?filename=Intel_Silicon_FW_Kit_PTL-H_2026WW07.4.01_ECG_CSME_SSE_26WW18.zip) (`CSMEKits`) |
| `MEInfo.exe` | Windows | — | CSME UPID, RPMC | [Intel_Silicon_FW_Kit_PTL-H_2026WW07.4.01_ECG_CSME_SSE_26WW18.zip](https://cdrdv2.intel.com/v1/dl/getContent/918226/918227?filename=Intel_Silicon_FW_Kit_PTL-H_2026WW07.4.01_ECG_CSME_SSE_26WW18.zip) (`CSMEKits`) |
| `MEInfo.efi` | both | `EFI/` | EOM | [Intel_Silicon_FW_Kit_PTL-H_2026WW07.4.01_ECG_CSME_SSE_26WW18.zip](https://cdrdv2.intel.com/v1/dl/getContent/918226/918227?filename=Intel_Silicon_FW_Kit_PTL-H_2026WW07.4.01_ECG_CSME_SSE_26WW18.zip) (`CSMEKits`) |
| `Fpt.efi` | both | `EFI/` | EOM | [Intel_Silicon_FW_Kit_PTL-H_2026WW07.4.01_ECG_CSME_SSE_26WW18.zip](https://cdrdv2.intel.com/v1/dl/getContent/918226/918227?filename=Intel_Silicon_FW_Kit_PTL-H_2026WW07.4.01_ECG_CSME_SSE_26WW18.zip) (`CSMEKits`) |
| `getsec64.efi` | both | `EFI/` | TXT | [Client_TXT_Debug_TPM_Prov_Kit_05282026.zip](https://cdrdv2.intel.com/v1/dl/getContent/914993/830393?filename=Client_TXT_Debug_TPM_Prov_Kit_05282026.zip) (`TXTProvKits`) |
| `Tpm2ProvFilesCBnT/` (folder) | both | `EFI/` | TXT | [Client_TXT_Debug_TPM_Prov_Kit_05282026.zip](https://cdrdv2.intel.com/v1/dl/getContent/914993/830393?filename=Client_TXT_Debug_TPM_Prov_Kit_05282026.zip) (`TXTProvKits`) |
| `PTL_SINIT.bin` | both | `EFI/` | TXT | [PTL_WCL_StartupACM_1.21.18_SINITACM_1.21.18.V3.zip](https://cdrdv2.intel.com/v1/dl/getContent/914993/892533?filename=PTL_WCL_StartupACM_1.21.18_SINITACM_1.21.18.V3.zip) (`PTL_ACM`) |
| `BIOS_release.cap` (any `.cap` name) | Linux | `EFI/` | BIOS capsule update (`firmware`) | not downloadable — request from your Intel representative (`BIOSCapsule`) |
| `CapsuleApp.efi` | Linux | `EFI/` | BIOS capsule update (`firmware`) | not downloadable — build from [edk2/MdeModulePkg/Application/CapsuleApp](https://github.com/tianocore/edk2/tree/master/MdeModulePkg/Application/CapsuleApp) (`CapsuleApp`) |
| `SceEfi64.efi` (optional) | Linux | `EFI/ubuntu/` | pre-flight BIOS knobs, **AMI BIOS only** | AMI NDA package `SceEfi.7z` (`AMISCE_Linux`) |
| `SCEWIN_64.exe` + `amigendrv64.sys` (optional) | Windows | — | pre-flight BIOS knobs, **AMI BIOS only** | AMI NDA package `SceWin.7z` (`AMISCE_Windows`) |
| `Coreinfo64.exe` | Windows | — | AES-NI (Windows) | [Coreinfo.zip](https://download.sysinternals.com/files/Coreinfo.zip), downloaded automatically (`Coreinfo`) |

- Versioned names are accepted and renamed back, e.g. `VtInfo_v1.1.83.efi` → `VTInfo.efi`,
  `PTL_SINIT_v1_21_17_….bin` → `PTL_SINIT.bin`; `MEInfo.exe` also matches `MEInfoWin64.exe`.
- AMISCE is optional: without it (non-AMI BIOS) it is reported `SKIPPED`, not missing, and BIOS
  knobs are set in BIOS Setup instead. Drop the whole `.7z` for your OS; only the needed files are
  taken.
- Tests that need nothing from this table: SHA Extension, AES-NI (Linux), TME, measured boot,
  PAVP, HLAT, CET, HDCP, BIOS Resiliency (on the SUT).

**Not staged — used on a separate build/flash host**

| Tool | Used for |
|---|---|
| IFWI release package ([870744_ptl-h-refbios4063_65releasepackage.zip](https://cdrdv2.intel.com/v1/dl/getContent/870744/920452?filename=870744_ptl-h-refbios4063_65releasepackage.zip)) | the IFWI flashed before testing (all tests; see TEST_GUIDE §1 IFWI groups) |
| MFIT ([Intel_Silicon_FW_Kit_PTL-H_2026WW07.4.01_ECG_CSME_SSE_26WW18.zip](https://cdrdv2.intel.com/v1/dl/getContent/918226/918227?filename=Intel_Silicon_FW_Kit_PTL-H_2026WW07.4.01_ECG_CSME_SSE_26WW18.zip)) | building the special IFWIs (RPMC, EOM, dTPM, Resiliency) |
| Dediprog SPI programmer (Intel RVP board); HXD, BpmGen2, Visual Studio only to build the corrupted IBB yourself | BIOS Resiliency (flash the corrupted IBB; optional FIT dump + IBB corruption) |

---

## 6. Stage the tools — `deploy/tools/deploy_tools.py`

The setup scripts run this for you. Run it again whenever you add files to `Downloads/`:

```bash
sudo python3 deploy/tools/deploy_tools.py                    # Linux: stage into Tools/ + copy to /boot/efi
..\venv\Scripts\python.exe deploy\tools\deploy_tools.py      # Windows: stage into Tools\
```

| Option | Meaning |
|---|---|
| `--yes`, `-y` | no prompts: skip missing or ambiguous tools |
| `--efi-mount <path>` | EFI partition mount point (default `/boot/efi`, from `tools.xml`) |
| `xml_file` (positional) | another tool list instead of `deploy/tools/tools.xml` |

Example output on Linux with `sudo` (recorded with an older, 7-entry `tools.xml`; the counts and
names differ with the current list):

```
Source folder: .../Downloads
Current OS: linux
Tools in config: 7
Skipped (wrong OS): 1        ← MEInfoWin64.exe auto-skipped (Windows-only)
Tools to deploy: 6
--------------------------------------------------
[OK]   VtInfo_v1.1.83.efi -> .../Tools/VtInfo.efi (renamed)
[OK]   MEInfo -> .../Tools
[OK]   FPT -> .../Tools
[OK]   getsec64.efi -> .../Tools
[OK]   Tpm2ProvFilesCBnT_v1.2.3/ -> .../Tools/Tpm2ProvFilesCBnT (renamed)
[OK]   PTL_SINIT_v1_21_17_20251016_REL.bin -> .../Tools/PTL_SINIT.bin (renamed)
--------------------------------------------------
Done. 6/6 tools deployed successfully.

--------------------------------------------------
EFI partition copy
--------------------------------------------------
EFI mount point: /boot/efi
Tools to copy to EFI partition: 4
--------------------------------------------------
[OK]   .../Tools/VtInfo.efi -> /boot/efi/EFI/VtInfo.efi
[OK]   .../Tools/getsec64.efi -> /boot/efi/EFI/getsec64.efi
[OK]   .../Tools/Tpm2ProvFilesCBnT -> /boot/efi/EFI/Tpm2ProvFilesCBnT
[OK]   .../Tools/PTL_SINIT.bin -> /boot/efi/EFI/PTL_SINIT.bin
--------------------------------------------------
Done. 4/4 tools copied to EFI partition.
```

- It only stages tools for the OS it runs on. A missing tool prints its download link; you can
  drop it in and retry, or skip it.
- Without `sudo` (Linux) the EFI copy is skipped with a message; staging into `Tools/` still works
  and the exit code is 0.
- `./deploy/setup/configure_sudo.sh` (optional) lets `deploy_tools.py` run with `sudo` without a
  password.
- `Downloads/` and `Tools/` are git-ignored.

**How the tests find the tools**

| Tool | Config key (file) | Looked up in |
|---|---|---|
| `MEInfo` / `MEInfo.exe` | `sut_meinfo_path_linux` / `sut_meinfo_path_windows` (`csme_config.yaml`) | `Tools/` (paths relative to the repo) |
| `VTInfo.efi` | `vtinfo_efi_name` (`virtualization_config.yaml`) | EFI partition |
| `Fpt.efi`, `MEInfo.efi` | `fpt_efi_name`, `meinfo_efi_name` (`eom_config.yaml`) | EFI partition |
| `getsec64.efi`, `PTL_SINIT.bin`, `Tpm2ProvFilesCBnT/` | `getsec_tool`, `sinit_binary`, `tpm_prov_uefi_dir` (`txt_config.yaml`) | EFI partition |
| `CapsuleApp.efi`, `BIOS_release.cap` | `capsule_tool_efi`, `capsule_file` (`firmware_config.yaml`) | EFI partition |
| `Coreinfo64.exe` | `coreinfo_exe_path` (`aesni_config.yaml`) | `Tools/` (paths relative to the repo) |

EFI file names must match exactly (case matters on Linux). With Secure Boot on, the tests run the
`*_signed.efi` copies made by `deploy/secure_boot/sign_efi_tools.sh`.
