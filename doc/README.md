# Documentation

| Document | What it covers | Read it when |
|---|---|---|
| [TEST_GUIDE.md](TEST_GUIDE.md) | Install (Linux + Windows), configure, run (test runner + pytest), reboots and manual steps, cleanup, results, troubleshooting | Setting up a SUT or running tests |
| [DEPENDENCIES.md](DEPENDENCIES.md) | Python and OS packages, bundled scripts, external tools and how `deploy/tools/deploy_tools.py` stages them | Before the first run on a new SUT |
| [TEST_COVERAGE.md](TEST_COVERAGE.md) | Every test case: ID, OS, category (automated / operator-assisted / manual), reboots, IFWI group, CR mapping, what is read back | Checking what is covered / planning a run |
| [../deploy/README.md](../deploy/README.md) | Every setup / Secure Boot / BIOS knob / tool-staging script and the order to run them | Provisioning a SUT |
| [../tests/CONTRIBUTING.md](../tests/CONTRIBUTING.md) | How to write a new test | Adding or changing a test |

## Reference material (`reference/`)

| File | Content |
|---|---|
| [secure_boot_linux.pdf](reference/secure_boot_linux.pdf) | Step-by-step UEFI Secure Boot enablement on a Linux SUT (automated by `deploy/secure_boot/enable_secure_boot.sh`) |
| [secure_boot_windows.pdf](reference/secure_boot_windows.pdf) | Step-by-step UEFI Secure Boot enablement on a Windows SUT (automated by `deploy/secure_boot/enable_secure_boot_windows.ps1`) |

Test input files are not kept here: the HDCP DRM test videos live next to their test in
`tests/hdcp/assets/`.
