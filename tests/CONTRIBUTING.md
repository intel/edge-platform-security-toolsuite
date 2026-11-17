# Writing New Test Cases — Contributor Guide

**This guide is for `tests/` — the customer-facing, SUT-local suite.** pytest
runs directly on the board under test here (no NUC, no SSH, no serial). For
the internal NUC-driven pattern instead, see an existing file under
`internal_nuc/tests/<suite>/` directly and ask before adding more there — new
tests should default to this SUT-local pattern.

## Quick Start

1. Copy the template:
   ```bash
   cp tests/test_template.py tests/<suite>/test_ec62443_<topic>_sut_func.py
   ```

2. Search for `<` in the file and replace every placeholder.

3. Create `config/suites/<suite>_config.yaml` with test-specific parameters.

4. Verify pytest can collect it:
   ```bash
   python -m pytest tests/<suite>/test_ec62443_<topic>_sut_func.py --collect-only
   ```

---

## Project Structure

```
tests/
  measured_boot/   — TPM / measured boot test cases
  firmware/        — BIOS capsule update / firmware test cases
  tme/             — TME test cases
  aesni/           — AES-NI test cases
  txt/             — TXT / GETSEC test cases
  base_test.py     — BaseTest: OS-agnostic helpers (inherited by SUTBaseTest)
  sut_base_test.py — SUTBaseTest: ALL tests/ classes inherit this
  test_template.py — START HERE when writing a new test

core/              — Shared managers used by tests/ (never modify without discussion)
  prereq.py        — pre_test_check() gate, wait_for_signal()
  uefi_script_manager.py — UEFI shell script execution (via SUTBaseTest)

internal_nuc/      — Internal engineering only, NOT part of this guide's scope.
                     NUC-driven tests + their os_manager/serial_manager/reboot_manager
                     managers live here instead — see that tree's own files directly.

config/
  test_config.yaml — All environment-specific settings (NOT in git)
  suites/<suite>_config.yaml — Per-suite expected values and tool paths

conftest.py        — pytest fixtures (config, log_dir, internal_nuc-only ones) + collection hooks
pytest.ini         — pytest config (markers, log format, addopts)
```

---

## Naming Conventions

| Thing | Convention | Example |
|---|---|---|
| File | `test_ec62443_<topic>_sut_func.py` | `test_ec62443_ftpm_ptt_sut_func.py` |
| Class | `Test<TCClassName>SUTFunc` | `TestEC62443fTPMPTTSUT` |
| Method | `test_ec62443_<topic>_sut_func` | `test_ec62443_ftpm_ptt_sut_func` |
| Test ID | `IEC62443-4-2-TC_<TOPIC>-FUNC-SUT` | `IEC62443-4-2-TC_fTPM-PTT-FUNC-SUT` |

---

## Mandatory Structure

Every test file must follow this structure (see `test_template.py`):

```python
# 1. Imports
import logging
import pytest
from tests.sut_base_test import SUTBaseTest
from core.prereq import pre_test_check

logger = logging.getLogger(__name__)

# 2. Markers + class
@pytest.mark.<suite_marker>
@pytest.mark.manual        # if any pre-test step is manual
class Test<Name>SUTFunc(SUTBaseTest):

    # 3. Mandatory class constants
    SUITE   = "<suite>"                      # matches config/suites/<suite>_config.yaml
    TEST_ID = "IEC62443-4-2-TC_<TOPIC>-FUNC-SUT"

    # 4. Test-definition constants (same on every SUT — lives HERE, not in YAML)
    EXPECTED_<X> = "..."

    # 5. PRE_TEST_CHECKLIST (manual / eyeball steps)
    PRE_TEST_CHECKLIST = [
        "1.0)  ...",
    ]

    # 6. Test method — no os_manager/serial_manager/reboot_manager here
    def test_<name>_sut_func(self, request, config, log_dir):
        self._begin()

        # 7. Load suite YAML — ALWAYS first
        cfg = self._load_config(config)

        # 8. Pre-test gate
        pre_test_check(request, self.TEST_ID, self.PRE_TEST_CHECKLIST)

        # 9. Test steps — subprocess for local commands, self._wait_for_manual_signal()
        #    for operator checkpoints, self._write_uefi_phase()/self._reboot_into_uefi()
        #    for UEFI-shell-and-reboot phases. Logging + asserts as usual.

        self._end()
```

---

## The Two-Config Rule

| Type of value | Where it lives |
|---|---|
| Expected values, thresholds, iteration count | Class constant in the test file |
| IP address, file paths, timeouts, credentials | `config/suites/<suite>_config.yaml` |

**Never hardcode IPs, passwords, or paths in a test file.**

---

## Available Fixtures (from `conftest.py`)

| Fixture | Type | What it gives you |
|---|---|---|
| `request` | pytest built-in | Access to `--setup-confirmed`, `--yes` CLI flags |
| `config` | `dict` | Full `config/test_config.yaml` loaded as a dict |
| `log_dir` | `Path` | `logs/test_run_<timestamp>/` — save artifacts here |

Everything else comes from `SUTBaseTest` methods, not fixtures:

| Helper | What it gives you |
|---|---|
| `self._load_config(config)` | Loads `config/suites/<SUITE>_config.yaml` |
| `self._init_state_dir(cfg)` | Phase-state manager (state folder `logs/sut_state`) for reboot-safe tests |
| `self._write_uefi_phase(...)` / `self._reboot_into_uefi(...)` | Run a `.efi` tool and reboot safely |
| `self._wait_for_manual_signal(...)` | Wait for the operator's signal file -- then prove the step with `verify=` / `requires_reboot=`, or it is listed as confirmed by the operator |
| `self._check_bios_knobs(...)` | Read a marker's BIOS knobs (`deploy/bios_knobs/bios_knobs.yaml`) back from the OS / AMISCE |
| `self._mark_attested(...)` | Record a step only the operator can confirm (result: PASSED, with a "Confirmed by the operator" note) |
| `self._parse_meinfo_field(...)` | Parse MEInfo/VTInfo/UEFI tool output |

`os_manager`/`serial_manager`/`reboot_manager`/`security` are **internal_nuc-only**
fixtures — don't request them in a `tests/` file.

---

## Logging Rules

```python
# Always log the value BEFORE asserting it
logger.info("PCR[00] = %s", pcr_value)
assert pcr_value == expected, f"Expected {expected}, got {pcr_value}"

# Step markers make the log easy to follow
logger.info("[Step 4.1] Verify TPM location == PTT")
logger.info("[OK] TPM location verified")
```

---

## Markers

Apply at least one suite marker to every test class:

```python
@pytest.mark.measured_boot
@pytest.mark.firmware
@pytest.mark.tme
@pytest.mark.txt
@pytest.mark.slow     # add if test takes > 5 minutes
@pytest.mark.manual   # add if any step requires human interaction
```

---

## Pre-Test Checklist Pattern

```python
PRE_TEST_CHECKLIST = [
    "1.0)  Flash IFWI to the SUT.",
    "4.1)  BIOS eyeball: TPM Location = PTT.",
]

def test_..._sut_func(self, request, ...):
    pre_test_check(request, self.TEST_ID, self.PRE_TEST_CHECKLIST)
```

Run without `--setup-confirmed` first → read the checklist → complete all items → re-run with `--setup-confirmed --yes`.
See [../doc/TEST_GUIDE.md](../doc/TEST_GUIDE.md) for the full workflow.

---

## Adding Config Keys

If your test needs new environment-specific values, add them to
`config/suites/<suite>_config.yaml`:

```yaml
my_new_key: "/path/on/sut"
manual_gate_timeout_secs: 900   # if using self._wait_for_manual_signal()
```

Then read in the test:
```python
cfg = self._load_config(config)
my_path = cfg["my_new_key"]
```

---

## Checklist Before Opening a PR

- [ ] File named `test_ec62443_<topic>_sut_func.py` in the correct suite folder
- [ ] Class inherits `SUTBaseTest`, method named `test_ec62443_<topic>_sut_func`
- [ ] `SUITE` and `TEST_ID` (ending `-SUT`) defined
- [ ] `PRE_TEST_CHECKLIST` defined with all manual steps
- [ ] `pre_test_check()` called right after `self._load_config(config)`
- [ ] No hardcoded IPs, passwords, or paths
- [ ] All values logged before being asserted
- [ ] `python -m pytest tests/<suite>/test_ec62443_<topic>_sut_func.py --collect-only` passes
- [ ] `doc/TEST_COVERAGE.md`'s inventory regenerated to include the new test

