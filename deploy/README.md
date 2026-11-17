# deploy/ — SUT provisioning scripts

Run every command from the **repo root** (`edge-platform-security-toolsuite/`).
Full walkthrough: [doc/TEST_GUIDE.md](../doc/TEST_GUIDE.md) (§2 Linux, §3 Windows).

After `setup/`, you normally only run `python3 test_runner.py` (Windows: `python test_runner.py`):
its pre-flight runs the `bios_knobs/` and `secure_boot/` runbooks below for the tests you pick,
carries on after each reboot through `preflight/preflight_chain.py`, and then starts the tests.
The commands below are for running them by hand.

## Layout

| Folder | Script | OS | What it does |
|---|---|---|---|
| `setup/` | `setup_sut.sh` | Linux | One-time SUT setup: `startup.nsh` → `/boot/efi`, packages, `../venv`, `fw-validation-resume.service`, FW-Validation Shell boot entry, tool staging (no USB drive needed) |
| `setup/` | `setup_sut_windows.ps1` | Windows | One-time SUT setup: `..\venv`, `requirements.txt`, tool staging, OpenSSL for AES-NI (Administrator) |
| `setup/` | `configure_sudo.sh` | Linux | Optional: passwordless sudo for test commands and `deploy_tools.py` |
| `tools/` | `deploy_tools.py` | Both | Stages licensed tools from `Downloads/` into `Tools/` (+ EFI partition with `sudo`) |
| `tools/` | `tools.xml`, `download_links.xml` | — | Tool list / destinations, and where to download each tool |
| `secure_boot/` | `enable_secure_boot.sh` | Linux | Secure Boot runbook: `auto` runs the next stage and resumes by itself after each reboot (`sign` → `modules` → `provision` → enable → `verify`; `status` any time), then hands over to `preflight/` when `test_runner.py` started it (`auto --no-reboot`: leaves the reboots to the runner, except the AMISCE enable run). Requires OUR keys in PK/KEK: on factory keys (e.g. AMI "Platform Key") it asks y/n and reboots into BIOS Setup to delete all keys (software cannot), then continues by itself. Enable = signs the tools, then sets `Secure Boot`/`Secure Boot Mode`/`Factory Key Provision` with AMISCE on an AMI BIOS (BIOS Setup by hand otherwise) |
| `secure_boot/` | `sign_efi_tools.sh` | Linux | Adds our cert to `db` and signs every `.efi` tool on the ESP with our db key (`/etc/secureboot/key-material/test-key.rsa`) — called by `auto`/`verify`, rarely run by hand; refuses factory keys |
| `secure_boot/` | `sb_keys.py` | Linux | Read-only: whose keys PK/KEK/db hold (`ours` / `foreign` = factory / `setup` / `partial`), compared byte for byte with our cert — `python3 deploy/secure_boot/sb_keys.py status` |
| `secure_boot/` | `sb_enroll.py` | Linux | Called by `provision`: enrolls our keys (db, KEK, PK) in one run from Linux — signs each update itself, creates a fresh 10-year key in Setup Mode when ours is missing or expiring. `secure-boot-on`: AMI BIOS, sets the `Secure Boot` knob from Linux (only with our keys enrolled) |
| `secure_boot/` | `fetch_uefi_shell.sh` | Linux | Downloads the upstream EDK2 UEFI Shell (SHA-256 checked) to `Tools/shellx64.efi`; Ubuntu's `efi-shell-x64` exits under Secure Boot (CVE-2025-2486). Called by `setup_sut.sh` and `sign_efi_tools.sh` |
| `secure_boot/` | `enable_secure_boot_windows.ps1` | Windows | Secure Boot runbook: `auto` (`provision` → `verify`, resumes at the next logon), then hands over to `preflight/` when `test_runner.py` started it |
| `bios_knobs/` | `configure_bios_knobs_linux.py` / `_windows.py` | Linux / Windows | Pre-flight: set + verify the BIOS knobs a marker needs (AMI AMISCE BIOS only); imports nothing when they are already set |
| `bios_knobs/` | `bios_knobs.yaml` | — | Knobs per marker / IFWI group (`... list` shows them); `--marker` can be repeated (`<marker>:<variant>`); `menu_paths:` = BIOS Setup path per knob, printed for a non-AMI BIOS |
| `bios_knobs/` | `bios_knob_common.py`, `get_bios_value.py` | — | Shared helpers used by both runbooks |
| `preflight/` | `preflight_chain.py` | Both | Carries the `test_runner.py` pre-flight across reboots (plan: `logs/preflight_plan.json`, log: `logs/preflight.log`); `status` / `cancel` by hand |
| `resume/` | `fw-validation-resume.service`, `fw_validation_resume.sh`, `startup.nsh` | Linux | Reboot/resume plumbing — installed by `setup_sut.sh`, never run by hand |
| `resume/` | `status_window.py` | Both | Batch status window (reboots done/left, next manual step, latest log lines); opens by itself, or `python deploy/resume/status_window.py` |

## Run order

**Linux SUT**
```bash
sudo bash deploy/setup/setup_sut.sh --nopasswd-all           # 1. once per SUT (re-run safe; test boards: no password prompts, SECURITY.md)
./deploy/setup/configure_sudo.sh                             # 2. optional: passwordless sudo
sudo python3 deploy/tools/deploy_tools.py                    # 3. only if you add files to Downloads/ later
sudo ./deploy/secure_boot/enable_secure_boot.sh auto         # 4. only if a test needs Secure Boot ON
sudo python3 deploy/bios_knobs/configure_bios_knobs_linux.py --marker <marker>   # 5. before each marker / IFWI group
sudo bash deploy/setup/setup_sut.sh --uninstall [--dry-run]  # when testing is done: undo the setup
```

**Windows SUT** (PowerShell, from the repo root)
```powershell
.\deploy\setup\setup_sut_windows.ps1                                       # 1. once per SUT (re-run safe)
..\venv\Scripts\python.exe deploy\tools\deploy_tools.py                    # 2. only if you add files to Downloads\ later
.\deploy\secure_boot\enable_secure_boot_windows.ps1 auto                   # 3. only if a test needs Secure Boot ON (Administrator)
python deploy\bios_knobs\configure_bios_knobs_windows.py --marker <marker> # 4. before each marker / IFWI group (Administrator)
```

## After moving to this folder layout (existing Linux SUTs)

A Linux SUT set up before this layout still has the old `deploy/...` paths baked into its
installed `fw-validation-resume.service` and sudoers rule, so tests stop auto-resuming after a
reboot. Re-run once on each such SUT (both are safe to re-run):
```bash
sudo bash deploy/setup/setup_sut.sh
./deploy/setup/configure_sudo.sh        # only if you used it before
```
Windows SUTs need nothing: the resume task is recreated on every run.

## BIOS knobs that will not change (protected variables)

Without the BIOS Administrator password, AMISCE skips protected setup variables such as
`CpuSetup` (TME, VMX, TXT ...) and only prints `Cannot update protected variable CpuSetup.
Please use /cpwd <admin_pwd>`, yet it still exits 0. The run then fails at the knob check with
`expected 'Enabled', got 'Disabled'`.

On a Linux SUT nothing has to be edited: when the pre-flight is about to run AMISCE and no
password is stored, `test_runner.py` asks once:

- **P** (the BIOS already has an admin password): type it; it is stored encrypted.
- **S** (the BIOS has none): choose one; the SUT reboots into BIOS Setup, you type it once
  more under Security -> Administrator Password, Save & Exit. After the boot the pre-flight
  checks the BIOS now has a password, then runs AMISCE with `/cpwd` by itself.

AMISCE cannot set the first admin password on a BIOS with `AmiSetupNvLock`, so that one
BIOS Setup visit is the only manual step. The password is stored with `systemd-creds` and the
machine's host key in `/var/lib/fw-validation/bios_admin_password.cred` (root-only), masked in
the logs and never in the runbook state. Whether the BIOS has an admin password, and whether it
changed since it was stored (e.g. after an IFWI flash), is read from the `AMITSESetup` EFI
variable, so the pre-flight asks again only when needed. A password AMISCE rejects is deleted.
By hand: `sudo python3 deploy/bios_knobs/configure_bios_knobs_linux.py password [--set [--new] | --forget]`.

Windows SUT (not automated yet), or CI: set `BIOS_ADMIN_PASSWORD`, or `bios.admin_password` in
`config/test_config.yaml`; both override the stored password. Never commit a real password.
