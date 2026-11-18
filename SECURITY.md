# Security Policy
Intel is committed to rapidly addressing security vulnerabilities affecting our customers and providing clear guidance on the solution, impact, severity and mitigation. 

## Reporting a Vulnerability
Please report any security vulnerabilities in this project utilizing the guidelines [here](https://www.intel.com/content/www/us/en/security-center/vulnerability-handling-guidelines.html).

## Accepted risks

### Passwordless sudo for all commands (Linux SUT, opt-in)
`deploy/setup/setup_sut.sh` always installs exact, per-command passwordless sudo rules
(`/etc/sudoers.d/fw-validation`). Some tests also run commands those rules do not cover (MEInfo,
TXT `/dev/mem` reads, `bios_scripts/checkquote.sh`, the AES-NI script); after a reboot the tests run
from a systemd service with no terminal, so sudo cannot ask for a password and those tests fail.
To run unattended, the documented setup command for test boards is
`sudo ./deploy/setup/setup_sut.sh --nopasswd-all`, which also allows passwordless sudo for **all**
commands. The script's default (no option) does not; `--add-nopasswd-all` adds it later, and
`test_runner.py` offers it before the selected tests start. It is written to its own file,
`/etc/sudoers.d/fw-validation-all`.

- Risk: any process running as the test user can become root without a password.
- Use only on a dedicated test board that is not used for anything else.
- Remove it when testing is done: `sudo ./deploy/setup/setup_sut.sh --remove-nopasswd-all`,
  or undo the whole setup: `sudo ./deploy/setup/setup_sut.sh --uninstall` (`--dry-run` to preview).
- Some Ubuntu images grant the same through cloud-init (`/etc/sudoers.d/90-cloud-init-users`);
  `setup_sut.sh` reports such files but does not change them.