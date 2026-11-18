# IEC 62443-4-2 Platform Security Test Framework

pytest-based tests for platform/BIOS security features (measured boot, TME, AES-NI, TXT, VT-d,
CSME, RPMC, Secure Debug, EOM, capsule update, BIOS resiliency, HLAT, CET, PAVP, HDCP), mapped to
IEC 62443-4-2 component requirements. All 24 test cases run directly on the board under test
(Ubuntu or Windows) — see [doc/TEST_COVERAGE.md](doc/TEST_COVERAGE.md).

## Project Structure

```
edge-platform-security-toolsuite/
│
├── tests/
│   ├── aesni/                    # AES-NI tests
│   ├── bios_resiliency/          # BIOS resiliency / recovery tests
│   ├── cet/                      # CET (Control-flow Enforcement) tests — Windows SUT
│   ├── csme/                     # CSME UPID tests
│   ├── eom/                      # End-of-Manufacturing tests
│   ├── firmware/                 # BIOS capsule update tests
│   ├── hdcp/                     # HDCP tests (Windows SUT)
│   ├── hlat/                     # HLAT tests — Windows SUT
│   ├── measured_boot/            # fTPM/PTT + dTPM measured boot tests
│   ├── pavp/                     # PAVP (Protected Audio Video Path) tests
│   ├── rpmc/                     # RPMC tests
│   ├── secure_debug/             # Secure Debug tests
│   ├── sha_extension/            # SHA/AES-NI openssl benchmark tests
│   ├── tme/                      # TME (Total Memory Encryption) tests
│   ├── txt/                      # TXT / GETSEC tests
│   ├── virtualization/           # VT-d / VMX tests
│   ├── base_test.py              # BaseTest: shared helpers (steps, config, knob checks); parent of SUTBaseTest
│   ├── sut_base_test.py          # SUTBaseTest: base class of every test in tests/ (state, reboots, manual steps)
│   ├── test_template.py          # Skeleton for new tests (not collected)
│   └── CONTRIBUTING.md           # Guide for new contributors
│
├── core/
│   ├── batch_log.py              # Combined batch log across reboots
│   ├── bios_knob_checks.py       # Reads BIOS knobs back from the OS (ACPI, MSR, TPM, PlayReady) + AMISCE
│   ├── prereq.py                 # Pre-test gate + automated prereq checks (shared by tests/ AND internal_nuc/tests/)
│   ├── reboot_plan.py            # Reboots planned for a batch (status window, runner)
│   ├── state_dir.py              # Where reboot state lives (logs/sut_state by default)
│   ├── test_selection.py         # Context/IFWI/Secure Boot/run-order rules + suite discovery (conftest.py, test_runner.py)
│   └── uefi_script_manager.py    # UEFI shell script execution (used by SUTBaseTest)
│
├── internal_nuc/                 # Internal engineering only -- NOT collected by default
│   │                             #   (outside pytest.ini's testpaths; run explicitly with
│   │                             #   `pytest internal_nuc/tests/`). NUC-driven tests that
│   │                             #   control a remote SUT over SSH/serial -- every one has
│   │                             #   a SUT-local equivalent under tests/ that customers use.
│   ├── core/
│   │   ├── bios_knobs_manager.py # BIOS knob read accessor
│   │   ├── msr_manager.py        # MSR reading and bit parsing
│   │   ├── os_manager.py         # SSH/paramiko command execution + OS detection
│   │   ├── reboot_manager.py     # System reboot management (incl. IPMI power control)
│   │   ├── serial_manager.py     # Serial console utilities + UEFI shell entry
│   │   ├── tpm_manager.py        # TPM operations and log comparison
│   │   └── features/             # Security feature check library (TXT NUC variant only)
│   └── tests/<suite>/test_ec62443_<name>_func.py   # NUC-driven variants
│
├── config/
│   ├── test_config.yaml          # SUT credentials, paths, test parameters
│   └── suites/                   # Per-suite expected values / thresholds (one YAML per suite)
│
├── bios_scripts/                 # Helper scripts the tests run from the repo
│   ├── checkquote.sh             # TPM-attested PCR quote (measured boot, Linux)
│   ├── helpers.sh                # Sourced by checkquote.sh
│   ├── run_aesni_test.py         # AES-NI check (Linux & Windows)
│   └── tme_check.py              # TME CPUID / MSR 0x982 check (Windows)
│
├── deploy/                       # SUT provisioning (see deploy/README.md for run order)
│   ├── setup/                    # One-time SUT setup
│   │   ├── setup_sut.sh          # Linux: startup.nsh, packages, venv, resume service, tools
│   │   ├── setup_sut_windows.ps1 # Windows: creates ../venv, installs requirements.txt, stages tools
│   │   └── configure_sudo.sh     # Linux: passwordless sudo for the test commands
│   ├── secure_boot/              # UEFI Secure Boot enablement
│   │   ├── enable_secure_boot.sh          # Linux runbook (stages: auto/sign/modules/provision/verify/status)
│   │   ├── enable_secure_boot_windows.ps1 # Windows runbook (stages: auto/provision/verify/status)
│   │   ├── sign_efi_tools.sh              # Signs every *.efi tool on the ESP; called by 'verify'
│   │   ├── sb_keys.py                     # Whose keys PK/KEK/db hold (ours vs factory), read-only
│   │   ├── sb_enroll.py                   # Enrolls our keys (db, KEK, PK); called by 'provision'
│   │   └── fetch_uefi_shell.sh            # Downloads the upstream EDK2 shell (Ubuntu's exits under Secure Boot)
│   ├── bios_knobs/               # Pre-flight BIOS knob configuration (AMI AMISCE)
│   │   ├── configure_bios_knobs_linux.py   # Set + verify knobs per test marker (SceEfi64.efi)
│   │   ├── configure_bios_knobs_windows.py # Windows counterpart (SCEWIN_64.exe)
│   │   ├── bios_knob_common.py   # Shared parts of both runbooks
│   │   ├── bios_knobs.yaml       # Knobs needed per marker / IFWI group
│   │   └── get_bios_value.py     # Read a knob's value from an AMISCE script file
│   ├── tools/                    # External tool staging
│   │   ├── deploy_tools.py       # Stages licensed tools (MEInfo, FPT, VtInfo, getsec64, ...) from
│   │   │                         #   Downloads/ into ./Tools, and (with sudo) onto the EFI partition
│   │   ├── tools.xml             # Tool filenames, destinations, OS, efi_destination
│   │   └── download_links.xml    # Download links referenced by tools.xml
│   ├── preflight/                # test_runner.py pre-flight across reboots
│   │   └── preflight_chain.py    # Runs the next pre-flight step after each reboot, then the tests
│   └── resume/                   # Reboot/resume plumbing
│       ├── fw-validation-resume.service  # Linux: systemd unit template (generated by setup_sut.sh)
│       ├── fw_validation_resume.sh       # Linux: resume runner the service calls after boot
│       ├── startup.nsh                   # Linux: UEFI shell autostart script (copied to /boot/efi)
│       └── status_window.py              # Linux + Windows: live batch status window across reboots
│
├── doc/                           # Guides (see doc/README.md for the index)
│   ├── TEST_GUIDE.md             # Install, configure, run, troubleshoot
│   ├── DEPENDENCIES.md           # Python/OS packages, bundled scripts, external tools
│   ├── TEST_COVERAGE.md          # Test inventory + categories, IFWI groups, CR mapping, knob read-back
│   └── reference/                # Secure Boot PDFs, test-case tracker (.xlsx), overview slides
│
├── logs/                          # Test logs, HTML reports, reboot state (logs/sut_state/)
│
├── conftest.py                    # Pytest options, fixtures, auto-applied markers, logging
├── pytest.ini                     # Pytest settings and markers
├── test_runner.py                 # Interactive menu-driven test runner (Linux + Windows)
└── requirements.txt                 # Python dependencies
```

## Getting Started

Full instructions: **[doc/TEST_GUIDE.md](doc/TEST_GUIDE.md)** — install on
[Linux](doc/TEST_GUIDE.md#2-install--linux-sut) or [Windows](doc/TEST_GUIDE.md#3-install--windows-sut),
[configure](doc/TEST_GUIDE.md#4-configure), [run](doc/TEST_GUIDE.md#5-run-tests) and
[troubleshoot](doc/TEST_GUIDE.md#9-troubleshooting). External tools: [doc/DEPENDENCIES.md](doc/DEPENDENCIES.md).
Writing a test: [tests/CONTRIBUTING.md](tests/CONTRIBUTING.md).

### First run on a new SUT

1. `git clone` this repo **onto the SUT** and drop the tool packages into `Downloads/`.
2. Run the setup script once (creates `../venv`, installs `requirements.txt`, stages the tools;
   Linux also installs the resume service and the UEFI Shell boot entry):
   ```bash
   sudo bash deploy/setup/setup_sut.sh --nopasswd-all   # Linux (dedicated test board: no password prompts, see SECURITY.md)
   ```
   ```powershell
   .\deploy\setup\setup_sut_windows.ps1         # Windows
   ```
3. Start the runner and pick tests (it uses `../venv` by itself):
   ```bash
   python3 test_runner.py      # Linux
   python test_runner.py       # Windows, Administrator PowerShell
   ```
   Its pre-flight reads the BIOS knobs and Secure Boot state the selected tests need, sets what
   it can (AMISCE on an AMI BIOS, the Secure Boot runbooks), asks you to set the rest in BIOS
   Setup, then starts the tests — also across reboots. See
   [TEST_GUIDE § 5.1](doc/TEST_GUIDE.md#51-test-runner-recommended).

### Direct pytest

No pre-flight — set BIOS knobs and Secure Boot yourself. Without `--setup-confirmed` every test
only prints its checklist and skips.
```bash
python -m pytest tests/measured_boot/ -s --setup-confirmed --yes
```
`tests/` includes `eom` and `firmware`, which cannot be undone; add
`-m "not eom and not firmware"` unless you mean to run them.

### Dev-only Python environment (no SUT)

```bash
python3 -m venv ../venv && ../venv/bin/python3 -m pip install -r requirements.txt   # Linux / macOS
../venv/bin/python3 -m pytest --collect-only -q
```
```powershell
python -m venv ..\venv; ..\venv\Scripts\python.exe -m pip install -r requirements.txt   # Windows
..\venv\Scripts\python.exe -m pytest --collect-only -q
```

## Support

If you have any questions, please submit them on the GitHub Issues page or contact your Intel representative for further support.

## Available Markers

Registered in `pytest.ini` (`markers =`) -- the only marker registry; the test runner's
menu descriptions are read from it too. Use with
`-m <marker>`, e.g. `python -m pytest tests/ -m tme -s --setup-confirmed --yes`.

| Marker | What it selects |
|---|---|
| `tme` | Total Memory Encryption tests |
| `aesni` | AES-NI (AES New Instructions) tests |
| `txt` | Trusted Execution Technology tests |
| `measured_boot` | Measured Boot fTPM / dTPM tests |
| `firmware` | Firmware capsule update tests |
| `csme` | CSME (Converged Security and Manageability Engine) tests |
| `pavp` | PAVP (Protected Audio Video Path) tests |
| `hdcp` | HDCP (High-bandwidth Digital Content Protection) tests |
| `rpmc` | RPMC (Replay Protected Monotonic Counter) tests |
| `secure_debug` | Secure Debug tests |
| `eom` | EOM (End of Manufacturing) tests |
| `virtualization` | Virtualization (VT-d / VMX) tests |
| `sha_extension` | SHA Extension (AES-NI/SHA-NI openssl benchmark) tests |
| `bios_resiliency` | BIOS Resiliency / Recovery tests |
| `hlat` | HLAT (VT-rp / Hypervisor Linear Address Translation) tests |
| `cet` | CET (Control-flow Enforcement Technology / ShadowStack) tests |
| `slow` | Tests that take > 5 min |
| `manual` | Tests with a manual pre-test checklist and/or operator steps (see [doc/TEST_COVERAGE.md](doc/TEST_COVERAGE.md) for which tests need an operator while running) |

Applied automatically (`core/test_selection.py`, via `conftest.py`), also usable with `-m`:

| Marker | What it selects |
|---|---|
| `sut_linux`, `sut_windows` | tests that run on a Linux / Windows SUT |
| `nuc_driven`, `wins_driven` | `internal_nuc/` variants only |
| `ifwi_sep5`, `ifwi_sed5`, `ifwi_resiliency` | tests that run on that IFWI; shared Linux tests carry both `ifwi_sep5` and `ifwi_sed5` ([groups](doc/TEST_COVERAGE.md#4-ifwi-groups)) |
| `secure_boot` | tests that need UEFI Secure Boot on (fTPM/PTT, dTPM) |

