# Copyright 2026 Intel Corporation
# SPDX-License-Identifier: Apache-2.0

"""
Pytest configuration and shared fixtures for BIOS security tests.
"""

import os
import re
import sys
import json
import importlib.util
import subprocess
import time
import pytest
import logging
import yaml
from pathlib import Path
from datetime import datetime

# Add project root to Python path
sys.path.insert(0, str(Path(__file__).parent))


def _use_utf8_console() -> None:
    """
    Windows: pytest's captured streams write raw UTF-8 bytes, which a code page 437
    console shows as 'ΓÇö' for '—'. Switch the console to UTF-8 for this run.
    """
    if sys.platform != "win32":
        return
    for stream in (sys.stdout, sys.stderr):
        if stream and (getattr(stream, "encoding", "") or "").lower() != "utf-8":
            try:
                stream.reconfigure(encoding="utf-8", errors="replace")
            except (AttributeError, ValueError):
                pass
    try:
        import atexit
        import ctypes
        kernel32 = ctypes.windll.kernel32
        previous = kernel32.GetConsoleOutputCP()
        if previous and previous != 65001 and kernel32.SetConsoleOutputCP(65001):
            atexit.register(kernel32.SetConsoleOutputCP, previous)
    except (AttributeError, OSError):
        pass


_use_utf8_console()


def _no_quick_edit_console() -> None:
    """
    Windows: with QuickEdit on, selecting text in the test console (e.g. to copy the signal-file
    command) pauses every write to it, so the test stops until the selection is cleared.
    Turn QuickEdit off for this run; copy from the status window or the log instead.
    """
    if sys.platform != "win32":
        return
    try:
        import atexit
        import ctypes
        kernel32 = ctypes.windll.kernel32
        handle = kernel32.GetStdHandle(-10)  # STD_INPUT_HANDLE
        mode = ctypes.c_uint32()
        if not kernel32.GetConsoleMode(handle, ctypes.byref(mode)) or not mode.value & 0x40:
            return
        # 0x40 ENABLE_QUICK_EDIT_MODE, 0x80 ENABLE_EXTENDED_FLAGS (needed for the change to stick)
        if kernel32.SetConsoleMode(handle, (mode.value & ~0x40) | 0x80):
            atexit.register(kernel32.SetConsoleMode, handle, mode.value | 0x80)
    except (AttributeError, OSError):
        pass


_no_quick_edit_console()

from core import bios_knob_checks, reboot_plan, test_selection  # noqa: E402
from core.batch_log import combined_log_path, format_duration, stitch_batch_log  # noqa: E402

# Captures log records emitted before the per-run file handler exists --
# i.e. during collection (BATCH QUEUE) and the first test's logstart, which
# both fire before the session-scoped `logger` fixture attaches its handler.
# Without this, those lines show up in logs/pytest.log (pytest's own ini-
# configured log_file, active from process start) but silently vanish from
# logs/test_run_<timestamp>/test_execution.log. Replayed + detached once the
# `logger` fixture runs (see below).
class _EarlyLogBuffer(logging.Handler):
    def __init__(self):
        super().__init__(level=logging.DEBUG)
        self.records = []

    def emit(self, record):
        self.records.append(record)


_early_log_buffer = _EarlyLogBuffer()
logging.getLogger().addHandler(_early_log_buffer)

# Set by the log_dir fixture; read by pytest_sessionfinish to record where
# this run's artifacts live in last_run_summary.json.
_current_log_dir = None
_LAST_RUN_SUMMARY_PATH = Path(__file__).parent / "logs" / "last_run_summary.json"
# Start time of THIS pytest process (one segment of a possibly reboot-spanning batch).
_session_started = time.time()

# Windows batch resume (the Windows counterpart of next_test.txt + fw-validation-resume.service):
# BaseTest._queue_windows_resume() writes the remaining queue here as a pytest @argsfile and
# registers ONE shared task (at boot as SYSTEM for automatic reboots, else at logon) that runs
# `python -m pytest @<this file>`.
WIN_RESUME_TASK = "IEC62443_Batch_Resume"
WIN_RESUME_ARGS_PATH = Path(__file__).parent / "logs" / "win_resume_args.txt"


def pytest_sessionstart(session):
    """A resumed Windows batch consumes its task + queue file so they never re-fire on a later logon."""
    global _session_started, _resumed_by_logon_task
    _session_started = time.time()
    queued = os.path.normcase("@" + str(WIN_RESUME_ARGS_PATH))
    if not any(os.path.normcase(arg) == queued for arg in session.config.invocation_params.args):
        return
    _resumed_by_logon_task = True
    subprocess.run(["schtasks", "/delete", "/tn", WIN_RESUME_TASK, "/f"], capture_output=True, timeout=15)
    WIN_RESUME_ARGS_PATH.unlink(missing_ok=True)


# True when Task Scheduler started this pytest at logon (its console window is the status window).
_resumed_by_logon_task = False


def _pause_before_closing() -> None:
    """Keep the logon-task window open on the final summary instead of closing it at once."""
    try:
        if not (sys.stdin and sys.stdin.isatty()):
            return
        if os.name == "nt":
            # Session 0 = started at boot as SYSTEM: no one can ever press Enter there
            import ctypes
            session = ctypes.c_ulong()
            if ctypes.windll.kernel32.ProcessIdToSessionId(os.getpid(), ctypes.byref(session)) and session.value == 0:
                return
        print("", flush=True)
        _print_safe(" 👉 Batch finished -- no more reboots. Press Enter to close this window...")
        input()
    except (EOFError, OSError, ValueError):
        pass

# NOTE: pytest only honors collect_ignore as a conftest.py module-level
# variable -- the "collect_ignore" key under [pytest] in pytest.ini is
# silently ignored. Keep this here, not in pytest.ini, or whole-tree runs
# (tests/, -m tme, etc.) fail collection on this doc-only template file.
collect_ignore = ["tests/test_template.py"]

# Import core managers
# NOTE: these live under internal_nuc/core/, not core/ -- they're only used by
# the internal NUC-driven tests under internal_nuc/tests/ (SSH/serial control
# of a remote SUT). The customer-facing SUT-local tests/ suite never requests
# the os_manager/serial_manager/reboot_manager/security fixtures below.
# The customer release ships without internal_nuc/ (and its paramiko/pyserial), so it is optional here.
try:
    from internal_nuc.core.msr_manager import MSRManager
    from internal_nuc.core.tpm_manager import TPMManager
    from internal_nuc.core.serial_manager import SerialManager
    from internal_nuc.core.os_manager import OSManager
    from internal_nuc.core.reboot_manager import RebootManager
    from internal_nuc.core.bios_knobs_manager import BiosKnobsManager
    # Import the central security-feature library
    from internal_nuc.core.features import FeatureContext, SecurityFeatures
    _INTERNAL_NUC_ERROR = None
except ImportError as _exc:
    _INTERNAL_NUC_ERROR = _exc


def _require_internal_nuc() -> None:
    """Skip a NUC-driven fixture when internal_nuc/ (or paramiko/pyserial) is not installed."""
    if _INTERNAL_NUC_ERROR is not None:
        pytest.skip(f"internal_nuc/ is not part of this installation ({_INTERNAL_NUC_ERROR}); "
                    "NUC-driven tests need it and internal_nuc/requirements.txt")


def pytest_addoption(parser):
    """Register custom CLI options."""
    parser.addoption(
        "--setup-confirmed",
        action="store_true",
        default=False,
        help=(
            "Signal that manual pre-test setup steps have been completed. "
            "The test will still show an interactive checklist and ask for "
            "confirmation before proceeding. Use --yes to skip the prompt "
            "(CI / automation only)."
        ),
    )
    parser.addoption(
        "--yes",
        action="store_true",
        default=False,
        help=(
            "Skip the interactive 'type yes to confirm' prompt. "
            "Only use in CI/automation where a human has already verified "
            "the setup. Must be combined with --setup-confirmed."
        ),
    )


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item, call):
    """
    Attach the call-phase report to the test node so fixtures can read the
    outcome (passed / failed / error) via ``request.node.rep_call``.

    Used by SUTBaseTest._sut_state_teardown to log the outcome and
    conditionally clean up the state files after every SUT test.
    """
    outcome = yield
    rep = outcome.get_result()
    # sys.exit(0) mid-test is a phase-based test's intentional reboot point, not a failure
    if (rep.when == "call" and call.excinfo is not None
            and call.excinfo.errisinstance(SystemExit) and call.excinfo.value.code in (0, None)):
        rep.outcome = "skipped"
        rep.longrepr = (str(item.path), (item.location[1] or 0) + 1, f"Skipped: {_PENDING_REBOOT_REASON}")
        rep.pending_reboot = True
    setattr(item, f"rep_{rep.when}", rep)


_PENDING_REBOOT_REASON = ("PENDING REBOOT -- the test rebooted the SUT on purpose; "
                          "it resumes automatically after the next boot.")


def pytest_report_teststatus(report, config):
    """Own outcome for reboot points, so pytest counts them as 'pending reboot', not failed/skipped."""
    if getattr(report, "pending_reboot", False):
        return "pending_reboot", "R", ("PENDING REBOOT", {"cyan": True})
    return None


# Markers are registered in pytest.ini only; context/IFWI/run-order rules live in core/test_selection.py.


@pytest.fixture(scope="session")
def config():
    """
    Load test configuration from YAML file.
    
    Returns:
        dict: Configuration dictionary
    """
    config_file = Path(__file__).parent / "config" / "test_config.yaml"
    
    if not config_file.exists():
        pytest.fail(f"Configuration file not found: {config_file}")
    
    with open(config_file, 'r') as f:
        config_data = yaml.safe_load(f)
    
    return config_data


def load_suite_config(suite_name: str) -> dict:
    """
    Load a per-suite config file from config/suites/<suite_name>_config.yaml.

    Each test suite owns its own YAML for test-specific parameters.
    This keeps test_config.yaml clean (global SUT settings only).

    Usage in a test:
        from conftest import load_suite_config
        cfg = load_suite_config("txt")   # loads config/suites/txt_config.yaml

    Raises:
        pytest.fail if the suite config file exists but cannot be parsed.
        Returns an empty dict if the file simply does not exist yet.
    """
    suite_file = Path(__file__).parent / "config" / "suites" / f"{suite_name}_config.yaml"
    if not suite_file.exists():
        logging.getLogger(__name__).warning(
            "Suite config not found: %s — using empty config", suite_file
        )
        return {}
    try:
        with open(suite_file, "r") as f:
            data = yaml.safe_load(f)
        return data or {}
    except Exception as exc:
        pytest.fail(f"Failed to parse suite config {suite_file}: {exc}")


@pytest.fixture(scope="session")
def log_dir(config):
    """
    Create and return log directory for test artifacts.

    artifacts_dir in test_config.yaml is always resolved relative to the
    repository root (this file's directory), never the current working
    directory. This keeps logs in a single top-level logs/ folder no
    matter which directory pytest is launched from (e.g. running a test
    directly from tests/csme/ instead of the repo root).

    NOTE: a previous version of this fixture tried to reuse the same
    folder/test_execution.log across reboots for a tracked batch (see
    batch_status.json's "log_dir"). Reverted: on Windows, each phase-based
    test (TME/PAVP/dTPM/fTPM) manages its OWN independent Task Scheduler
    ONLOGON task, so multiple tests from the same original batch can -- and
    do -- resume as SEPARATE CONCURRENT pytest processes at the same logon.
    Sharing one log file between them caused interleaved/corrupted writes
    (two processes' FileHandlers appending at once, no cross-process lock).
    Always create a fresh folder instead.

    The timestamp alone is NOT unique: a SUT with a bad/unsynced RTC boots
    with its clock restored to (roughly) the same saved time after every
    reboot, so consecutive resumes produced the same test_run_<ts> name and
    appended into one folder, which broke the stitched batch log. The folder
    is therefore created exclusively (atomic mkdir) with a _2, _3, ...
    suffix on collision -- also safe for concurrent processes.

    Returns:
        Path: Log directory path
    """
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_base = Path(config['paths']['artifacts_dir'])
    if not log_base.is_absolute():
        log_base = Path(__file__).parent / log_base
    log_base.mkdir(parents=True, exist_ok=True)

    suffix = 1
    while True:
        name = f"test_run_{timestamp}" if suffix == 1 else f"test_run_{timestamp}_{suffix}"
        log_dir = log_base / name
        try:
            log_dir.mkdir()
            break
        except FileExistsError:
            suffix += 1

    # Stash for pytest_sessionfinish to write into last_run_summary.json --
    # test_runner.py's L/H menu options read that file for a human summary.
    global _current_log_dir
    _current_log_dir = log_dir

    # Record this process's log folder in the batch manifest too -- a batch
    # spanning reboots is really several separate pytest processes, each with
    # its own log_dir, so this is what lets test_runner.py stitch them all
    # into one combined log once the whole batch finishes.
    batch = _load_batch_status()
    if batch.get("order"):
        batch.setdefault("log_dirs", [])
        if str(log_dir) not in batch["log_dirs"]:
            batch["log_dirs"].append(str(log_dir))
            _save_batch_status(batch)

    return log_dir


@pytest.fixture(scope="session", autouse=True)
def logger(config, log_dir, request):
    """
    Configure and return logger for test execution.
    
    Returns:
        logging.Logger: Configured logger
    """
    log_config = config['logging']
    
    # Configure root logger so all module/class loggers are captured
    root_logger = logging.getLogger()
    root_logger.setLevel(getattr(logging, log_config['level']))

    # Avoid duplicate handlers when running multiple sessions in same process
    for handler in list(root_logger.handlers):
        if getattr(handler, "_bios_session_handler", False):
            root_logger.removeHandler(handler)
    
    # File handler
    log_file = log_dir / "test_execution.log"
    file_handler = logging.FileHandler(log_file, encoding="utf-8")
    file_handler.setLevel(getattr(logging, log_config['level']))
    file_handler._bios_session_handler = True
    
    # Console handler
    if log_config.get('console_logging', True):
        console_handler = logging.StreamHandler()
        console_handler.setLevel(getattr(logging, log_config['level']))
        console_handler._bios_session_handler = True
    
    # Formatter
    formatter = logging.Formatter(
        fmt=log_config.get('format', '%(asctime)s - %(name)s - %(levelname)s - %(message)s'),
        datefmt=log_config.get('date_format', '%Y-%m-%d %H:%M:%S')
    )
    
    file_handler.setFormatter(formatter)
    if log_config.get('console_logging', True):
        console_handler.setFormatter(formatter)
    
    # Add handlers
    root_logger.addHandler(file_handler)
    if log_config.get('console_logging', True):
        root_logger.addHandler(console_handler)

    # Replay anything captured before these handlers existed (BATCH QUEUE,
    # first test's RUNNING TEST banner) so they land in test_execution.log
    # too, then stop buffering -- live records go straight to the real
    # handlers from here on.
    for record in _early_log_buffer.records:
        file_handler.emit(record)
        if log_config.get('console_logging', True):
            console_handler.emit(record)
    _early_log_buffer.records.clear()
    root_logger.removeHandler(_early_log_buffer)

    # Named logger used by tests/fixtures when explicitly requested
    logger = logging.getLogger("BIOS_Security_Tests")
    logger.setLevel(getattr(logging, log_config['level']))

    # ------------------------------------------------------------------
    # Session header — environment snapshot for reproducibility/debug
    # ------------------------------------------------------------------
    import platform
    import socket
    import sys as _sys

    sut = config.get("sut", {})
    sep = "=" * 80

    logger.info(sep)
    logger.info("BIOS SECURITY TEST SUITE — SESSION STARTED")
    logger.info(sep)

    # Controller (this machine)
    logger.info("[Controller]")
    logger.info("  Hostname     : %s", socket.gethostname())
    logger.info("  OS           : %s %s", platform.system(), platform.version())
    logger.info("  Python       : %s", _sys.version.split()[0])
    logger.info("  pytest       : %s", pytest.__version__)
    logger.info("  Working dir  : %s", Path.cwd())
    logger.info("  Log dir      : %s", log_dir)

    # SUT connection
    logger.info("[SUT Connection]")
    logger.info("  IP address   : %s", sut.get("ip_address", "(not set)"))
    logger.info("  Username     : %s", sut.get("username",   "(not set)"))
    logger.info("  Serial port  : %s", sut.get("serial_port", "(not set)"))
    logger.info("  Baud rate    : %s", sut.get("serial_baudrate", "(not set)"))

    # Config snapshot (non-sensitive keys only)
    reboot_cfg = config.get("reboot", {})
    fw_cfg     = config.get("firmware", {})
    logger.info("[Config]")
    logger.info("  Boot menu key       : %s", fw_cfg.get("boot_menu_key", "(not set)"))
    logger.info("  Power control method: %s", reboot_cfg.get("power_control_method", "(not set)"))
    logger.info("  Config file         : %s",
                Path(__file__).parent / "config" / "test_config.yaml")

    from core import platform_state
    for line in platform_state.snapshot_lines(item.nodeid for item in request.session.items):
        logger.info(line)

    logger.info(sep)

    return logger


@pytest.fixture(scope="session")
def msr_manager():
    """
    Create MSR Manager instance.
    
    Returns:
        MSRManager: MSR Manager instance
    """
    _require_internal_nuc()
    return MSRManager()


@pytest.fixture(scope="session")
def tpm_manager(config):
    """
    Create TPM Manager instance.
    
    Returns:
        TPMManager: TPM Manager instance
    """
    _require_internal_nuc()
    return TPMManager(config['tpm'])


@pytest.fixture(scope="session")
def serial_manager(config):
    """
    Create Serial Manager instance and establish connection.
    
    Returns:
        SerialManager: Serial Manager instance
    """
    _require_internal_nuc()
    sut_config = config['sut']
    serial_port = sut_config['serial_port']
    serial_baudrate = sut_config['serial_baudrate']
    
    manager = SerialManager(port=serial_port, baudrate=serial_baudrate)
    
    # Attempt to connect (may fail if serial not available)
    try:
        manager.connect()
    except Exception as e:
        logging.warning(f"Failed to connect to serial console: {e}")
    
    yield manager
    
    # Cleanup: disconnect
    manager.disconnect()


@pytest.fixture(scope="session")
def os_manager(config):
    """
    Create OS Manager instance.
    
    Returns:
        OSManager: OS Manager instance
    """
    _require_internal_nuc()
    return OSManager(config['sut'])


@pytest.fixture(scope="session")
def sut_os(config, os_manager):
    """
    Resolve and return the SUT operating system as a lowercase string.

    Reads  sut.os_type  from config:
      - ``"ubuntu"`` / ``"windows"``  — returned as-is (explicit)
      - ``"auto"``  or missing       — detected automatically via SSH

    Usage in a test::

        def test_something(self, sut_os, os_manager, ...):
            if sut_os == "ubuntu":
                os_manager.execute_command("some-linux-cmd")
            elif sut_os == "windows":
                os_manager.execute_command("Get-Something")
            else:
                pytest.skip(f"Unsupported SUT OS: {sut_os}")
    """
    _log = logging.getLogger("BIOS_Security_Tests")
    configured = config.get("sut", {}).get("os_type", "auto").strip().lower()

    if configured and configured != "auto":
        _log.info("SUT OS (from config): %s", configured)
        return configured

    detected = os_manager.detect_sut_os()
    _log.info("SUT OS (auto-detected): %s", detected)
    return detected


@pytest.fixture(scope="session")
def reboot_manager(config):
    """
    Create Reboot Manager instance.
    
    Returns:
        RebootManager: Reboot Manager instance
    """
    _require_internal_nuc()
    return RebootManager(config['reboot'], config['sut'])


@pytest.fixture(scope="session")
def bios_knobs(config, os_manager):
    """
    Board-independent, READ-ONLY BIOS knob accessor.

    A test declares WHAT knob it cares about by id (see ``bios_knobs`` in
    config/test_config.yaml); the manager works out HOW to read it on whatever
    board is connected (OS-side resolver first, then XmlCli when available).
    Use it as a test step, e.g.::

        def test_ftpm_ptt(bios_knobs):
            bios_knobs.detect_board()                 # logs which board
            assert bios_knobs.verify("ftpm_ptt", "Enabled")

    Returns:
        BiosKnobsManager: read-only knob accessor
    """
    allow_writes = bool(config.get("bios_knobs_allow_writes", False))
    return BiosKnobsManager(
        os_manager=os_manager, config=config, allow_writes=allow_writes
    )


@pytest.fixture(scope="session")
def security(config, os_manager, msr_manager, tpm_manager, logger):
    """
    Single access point to all reusable security-feature checks.

    Every check lives in internal_nuc/core/features/. Use it as a test step, e.g.::

        def test_tme(security):
            security.tme.assert_enabled()
            result = security.tme.verify_config(config['tme']['expected_bits'])
            assert result.passed, result.summary

    Returns:
        SecurityFeatures: facade exposing .tme, .txt, .tpm, .aes_ni, etc.
    """
    ctx = FeatureContext(
        config=config,
        os_manager=os_manager,
        msr_manager=msr_manager,
        tpm_manager=tpm_manager,
        logger=logger,
    )
    return SecurityFeatures(ctx)


@pytest.fixture(scope="function")
def test_logger(request, logger):
    """
    Per-test logger that logs test start/end.
    
    Returns:
        logging.Logger: Test-specific logger
    """
    test_name = request.node.name
    logger.info("")
    logger.info("=" * 80)
    logger.info(f"Starting test: {test_name}")
    logger.info("=" * 80)
    
    yield logger
    
    logger.info("=" * 80)
    logger.info(f"Completed test: {test_name}")
    logger.info("=" * 80)
    logger.info("")


@pytest.fixture(scope="function")
def tpm_log_dir(log_dir, request):
    """
    Create TPM-specific log directory for each test.
    
    Returns:
        Path: TPM log directory
    """
    test_name = request.node.name
    tpm_dir = log_dir / "tpm_logs" / test_name
    tpm_dir.mkdir(parents=True, exist_ok=True)
    
    return tpm_dir


def pytest_collection_modifyitems(config, items):
    """
    Modify test collection to add markers based on test path.
    """
    flashed = None
    for item in items:
        # Match the suite folder only -- the repo root name itself contains "firmware".
        suite_dir = Path(str(item.fspath)).parent.name
        if suite_dir == "tme":
            item.add_marker(pytest.mark.tme)
        elif suite_dir == "txt":
            item.add_marker(pytest.mark.txt)
        elif suite_dir == "measured_boot":
            item.add_marker(pytest.mark.measured_boot)
            item.add_marker(pytest.mark.slow)
        elif suite_dir == "firmware":
            item.add_marker(pytest.mark.firmware)
            item.add_marker(pytest.mark.manual)

        context = test_selection.os_context(item.nodeid)
        if context:
            item.add_marker(getattr(pytest.mark, context))
        for group in test_selection.ifwi_groups(item.nodeid):
            item.add_marker(getattr(pytest.mark, group))
        if test_selection.requires_secure_boot(item.nodeid):
            item.add_marker(pytest.mark.secure_boot)

        wrong_os = test_selection.wrong_os_reason(item.nodeid)
        if wrong_os:
            item.add_marker(pytest.mark.skip(reason=wrong_os))
        elif test_selection.ifwi_checked(item.nodeid):
            if flashed is None:
                flashed = bios_knob_checks.flashed_ifwi()
            wrong_ifwi = test_selection.wrong_ifwi_reason(item.nodeid, *flashed)
            if wrong_ifwi:
                item.add_marker(pytest.mark.skip(reason=wrong_ifwi))

    # Cross-suite run-order constraint (2026-10-12): every other suite is
    # order-independent, but eom and firmware are destructive/terminal --
    # eom permanently locks NVAR config + flash protection (irreversible),
    # and the firmware capsule update reflashes the BIOS. Both must sort to
    # the end of any multi-suite run, with eom second-to-last so a capsule
    # reflash can never run before (and invalidate) the EOM-locked state.
    # list.sort() is stable, so relative order is preserved within each rank.
    #
    # Skip the auto run-order rule when the operator passed explicit node ids
    # on the command line (test_runner.py's "pick individual tests" /
    # ifwi-group "choose & reorder" flows, or fw-validation-resume.service
    # resuming a queued batch) -- pytest normally preserves that exact order
    # and the operator's explicit intent should win over the automatic rule.
    # config.args (not invocation_params.args) so node ids from a Windows resume @argsfile count too.
    explicit_node_ids = any("::" in arg for arg in config.args)
    if not explicit_node_ids:
        items.sort(key=lambda item: test_selection.run_order_rank(item.nodeid))


def pytest_collection_finish(session):
    """
    Build the batch manifest from the FINAL selected item list.

    Must NOT be done inside pytest_collection_modifyitems: that hook can run
    before pytest's own `-m`/`-k` deselection hookimpl, so `items` there may
    still include tests that get deselected a moment later (e.g. `-m rpmc`
    would otherwise log "starting 24 test(s)" when only 2 actually run).
    pytest_collection_finish fires once collection AND all deselection is
    fully resolved, so session.items here is the true "what will actually run".

    Skipped for --collect-only: test_runner.py lists tests that way and must
    not overwrite the manifest of a batch that is mid-reboot.
    """
    if session.config.option.collectonly:
        return
    explicit_node_ids = any("::" in arg for arg in session.config.args)
    _update_batch_manifest(session.items, explicit_node_ids)


# ---------------------------------------------------------------------------
# Batch manifest — tracks the full queue + pass/fail status across an entire
# multi-test run, INCLUDING across reboots (each reboot restarts pytest as a
# brand-new process, so without this, each process only knows about its own
# tests and a consolidated "what passed/failed in the whole batch" summary is
# impossible). Stored at a fixed path (not the timestamped log_dir) so every
# process in a reboot chain reads/writes the same file.
# ---------------------------------------------------------------------------
_BATCH_STATUS_PATH = Path(__file__).parent / "logs" / "batch_status.json"
# Final verdict of the last completed batch, read by test_runner.py's banner and 'L' view.
_LAST_BATCH_SUMMARY_PATH = Path(__file__).parent / "logs" / "last_batch_summary.json"
# Same file test_runner.py appends to and reads for its 'H' history menu.
_HISTORY_PATH = Path(__file__).parent / ".pytest_cache" / "test_history.jsonl"

# Non-terminal statuses -- the batch is NOT finished while any test still has
# one of these.
_BATCH_PENDING_STATUSES = ("PENDING", "REBOOTING")

# A PASSED test whose batch reason starts with this had steps only the operator could
# confirm (BaseTest._mark_attested); test_runner.py shows it as a note, not a status.
_ATTESTED_PREFIX = "Confirmed by the operator: "


def _attested_steps(report) -> list:
    return [value for key, value in getattr(report, "user_properties", []) if key == "attested"]

# ANSI colors for status tags in the batch queue/summary listings -- this
# project already relies on raw ANSI in logs (pytest --color=yes, pytest-clarity
# diffs), so coloring these is consistent with existing log output.
_ANSI_RESET = "\033[0m"
_STATUS_COLORS = {
    "PASSED": "\033[32m",    # green
    "FAILED": "\033[31m",    # red
    "SKIPPED": "\033[33m",   # yellow
    "REBOOTING": "\033[36m", # cyan
}


def _colorize_status(status: str) -> str:
    color = _STATUS_COLORS.get(status)
    return f"{color}{status}{_ANSI_RESET}" if color else status


def _load_batch_status() -> dict:
    try:
        return json.loads(_BATCH_STATUS_PATH.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def _save_batch_status(batch: dict) -> None:
    _BATCH_STATUS_PATH.parent.mkdir(parents=True, exist_ok=True)
    _BATCH_STATUS_PATH.write_text(json.dumps(batch, indent=2), encoding="utf-8")


def _touch_segment(batch: dict) -> None:
    """Record this pytest process's start and latest-activity time in the batch manifest."""
    started = datetime.fromtimestamp(_session_started).isoformat()
    now = datetime.now().isoformat()
    segments = batch.setdefault("segments", [])
    if segments and segments[-1].get("started") == started:
        segments[-1]["last"] = now
    else:
        segments.append({"started": started, "last": now})


def _batch_times(batch: dict) -> tuple:
    """
    (started, total_seconds, test_seconds, reboots) for a batch manifest.

    test_seconds sums each pytest process from its start to its last recorded
    activity, so time the SUT spent rebooting / sitting in BIOS is excluded.
    """
    try:
        if batch.get("started"):
            started = datetime.fromisoformat(batch["started"])
        else:
            started = datetime.strptime(batch.get("batch_id", ""), "%Y%m%d_%H%M%S")
    except ValueError:
        started = datetime.now()
    total = (datetime.now() - started).total_seconds()
    segments = batch.get("segments") or []
    test_seconds = sum(
        (datetime.fromisoformat(s["last"]) - datetime.fromisoformat(s["started"])).total_seconds()
        for s in segments
    )
    # Wall clock can jump backwards across reboots (bad RTC / no NTP sync);
    # the total can never be less than the time actually spent running tests.
    total = max(total, test_seconds)
    reboots = max(len(segments) or len(batch.get("log_dirs") or []), 1) - 1
    return started, total, test_seconds, reboots


def _update_batch_manifest(items, explicit_node_ids: bool) -> None:
    """
    Create a fresh batch manifest, or -- if this process is resuming a queued
    batch after a reboot -- keep the existing one so already-completed results
    aren't lost.

    Also logs the full ordered queue for this run, so it's always clear from
    the log alone what's about to run / is still running / already ran.
    """
    node_ids = [item.nodeid for item in items]
    existing = _load_batch_status()
    order = existing.get("order", [])
    resuming = (
        explicit_node_ids
        and order[-len(node_ids):] == node_ids
        and any(existing.get("results", {}).get(nid) in _BATCH_PENDING_STATUSES for nid in node_ids)
    )

    if resuming:
        batch = existing
    else:
        batch = {
            "batch_id": datetime.now().strftime("%Y%m%d_%H%M%S"),
            "started": datetime.fromtimestamp(_session_started).isoformat(),
            "order": node_ids,
            "results": {nid: "PENDING" for nid in node_ids},
            "log_dirs": [],
            "test_ids": {item.nodeid: getattr(item.cls, "TEST_ID", None) or item.nodeid for item in items},
            "reboot_plan": _build_reboot_plan(items),
        }
    if node_ids:
        from core import bios_knob_checks
        reboot_plan.note_boot(batch, bios_knob_checks.boot_id(), node_ids[0])
    _touch_segment(batch)
    _save_batch_status(batch)
    if resuming or reboot_plan.counts(batch)["left"]:
        _open_status_window()

    # print() as well as logger.info(): this runs during collection, BEFORE the
    # session-scoped `logger` fixture has attached any handlers, so logger.info()
    # alone would be silently dropped for the very first test process in a batch.
    # This is the first thing the window that opens after a reboot shows.
    log = logging.getLogger("BIOS_Security_Tests")
    for line in reboot_plan.banner_lines(batch, resuming=node_ids[0] if resuming else None):
        log.info(line)
        _print_safe(line)


def _print_safe(line: str) -> None:
    """print() that degrades symbols instead of crashing on a non-UTF-8 console (cp1252 pipes)."""
    try:
        print(line, flush=True)
    except UnicodeEncodeError:
        encoding = getattr(sys.stdout, "encoding", None) or "ascii"
        print(line.encode(encoding, errors="replace").decode(encoding, errors="replace"), flush=True)


def _open_status_window() -> None:
    """
    Open the live batch status window (deploy/resume/status_window.py) unless one is open:
    Windows -- a new console, also after every reboot + logon; Linux -- a terminal when there is
    a desktop session, plus the login autostart entry for runs resumed before login.
    """
    try:
        spec = importlib.util.spec_from_file_location(
            "status_window", Path(__file__).parent / "deploy" / "resume" / "status_window.py")
        window = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(window)
        if sys.platform.startswith("linux") and os.geteuid() != 0 and not window.AUTOSTART.exists():
            window.install(quiet=True)
        elif os.name == "nt" and not window.windows_task_installed():
            window.install(quiet=True)
        window.launch()
    except Exception as exc:  # noqa: BLE001 -- the window is a convenience, never a reason to stop
        logging.getLogger("BIOS_Security_Tests").warning("Could not open the batch status window: %s", exc)


def _build_reboot_plan(items) -> dict:
    """{node id: planned reboots} from each test class's reboot_plan() (BaseTest.REBOOTS)."""
    try:
        global_cfg = yaml.safe_load((Path(__file__).parent / "config" / "test_config.yaml")
                                    .read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError):
        global_cfg = {}
    plan = {}
    for item in items:
        if item.get_closest_marker("skip") or not hasattr(item.cls, "reboot_plan"):
            plan[item.nodeid] = []
            continue
        try:
            plan[item.nodeid] = item.cls.reboot_plan(global_cfg)
        except Exception as exc:  # noqa: BLE001 -- a probe must never stop the batch
            logging.getLogger("BIOS_Security_Tests").warning(
                "Reboot plan for %s could not be worked out (%s) -- using its full list", item.nodeid, exc)
            plan[item.nodeid] = [reboot_plan.entry(*r) for r in getattr(item.cls, "REBOOTS", ())]
    return plan


# ---------------------------------------------------------------------------
# Pre-test gate + prereq helpers live in core/prereq.py (not here).
# conftest.py is for pytest fixtures and hooks only.
# Re-export them so existing  `from conftest import …`  calls still work.
# ---------------------------------------------------------------------------
from core.prereq import (          # noqa: E402  (import after code is fine in conftest)
    pre_test_check,
    prereq_ssh,
    prereq_os,
    prereq_secure_boot,
    prereq_tpm_location,
    prereq_pcr_bank,
)


def pytest_runtest_logstart(nodeid, location):
    """Log a clear 'now running X of Y' banner so the log always shows current progress."""
    batch = _load_batch_status()
    order = batch.get("order", [])
    if nodeid not in order:
        return
    batch["current"] = nodeid   # the status window shows it as RUNNING NOW
    _save_batch_status(batch)
    logger = logging.getLogger("BIOS_Security_Tests")
    sep = "=" * 80
    line = f"\u25b6 RUNNING TEST {order.index(nodeid) + 1} / {len(order)}  >>  {nodeid}"
    # print() too: for the very first test in a process, this fires before
    # the session-scoped `logger` fixture attaches handlers (same reason as
    # _update_batch_manifest), so logger.info() alone could be silently lost.
    # Leading blank line separates this banner from the previous test's tail
    # output, so it's easy to scan back and see where each test starts.
    logger.info("")
    logger.info(sep)
    logger.info(line)
    logger.info(sep)
    print()
    print(sep)
    _print_safe(line)
    print(sep)


def _set_batch_result(nodeid: str, status: str, reason: str = "") -> None:
    """Persist this test's outcome to the batch manifest (survives reboots)."""
    batch = _load_batch_status()
    if nodeid not in batch.get("results", {}):
        return  # not part of a tracked batch (manifest missing/stale) -- nothing to update
    batch["results"][nodeid] = status
    batch.setdefault("reasons", {})[nodeid] = reason
    _touch_segment(batch)
    _save_batch_status(batch)


def pytest_runtest_logreport(report):
    """Write PASSED / FAILED / ERROR to the log after each test phase."""
    # Setup-phase skips (e.g. wrong-OS) and errors must be recorded too, or the batch never completes.
    if report.when == "teardown" or (report.when == "setup" and report.passed):
        return
    logger = logging.getLogger("BIOS_Security_Tests")
    test_id = report.nodeid
    sep = "=" * 80
    if getattr(report, "pending_reboot", False):
        _set_batch_result(test_id, "REBOOTING")
        logger.info(sep)
        logger.info("RESULT: PENDING REBOOT (phase complete)  >>  %s", test_id)
        logger.info("REASON: the test rebooted the SUT on purpose -- it resumes automatically after the next boot.")
        logger.info(sep)
        return
    if report.passed:
        confirmed = _attested_steps(report)
        _set_batch_result(test_id, "PASSED", (_ATTESTED_PREFIX + "; ".join(confirmed)) if confirmed else "")
        logger.info(sep)
        logger.info("RESULT: PASSED  >>  %s", test_id)
        if confirmed:
            logger.info("Confirmed by the operator (the test cannot check these itself):")
            for step in confirmed:
                logger.info("  - %s", step)
        logger.info(sep)
    elif report.failed:
        # Extract the short failure reason (last line of the longrepr)
        reason = ""
        if hasattr(report.longrepr, "reprcrash"):
            reason = _clean_reason(report.longrepr.reprcrash.message)
        elif report.longrepr:
            reason = str(report.longrepr).splitlines()[-1]

        _set_batch_result(test_id, "FAILED", reason)
        logger.error(sep)
        logger.error("RESULT: FAILED  >>  %s", test_id)
        if reason:
            logger.error("REASON: %s", reason)
        logger.error(sep)
    elif report.skipped:
        reason = report.longrepr[-1] if isinstance(report.longrepr, tuple) else ""

        # Phase-based tests that pause for a MANUAL BIOS reboot (e.g.
        # tests/tme/test_ec62443_tme_sut_wins_func.py Phase 0) call
        # pytest.skip("PENDING REBOOT ...") instead of sys.exit(0) because
        # they haven't rebooted yet themselves -- the operator still has to.
        # A real "SKIPPED" is a terminal, nothing-more-will-happen result, so
        # reporting this the same way misleads readers (and _BATCH_PENDING_STATUSES
        # below would wrongly treat the test as finished). Recognize this exact
        # marker and report/track it the same non-terminal way as REBOOTING.
        # NOTE: pytest wraps the skip reason as "Skipped: <reason>" in longrepr,
        # so check for the marker as a substring, not a prefix.
        if "PENDING REBOOT" in reason:
            # Strip pytest's own "Skipped: " prefix -- it's redundant (and
            # confusing) next to a RESULT line that already says PENDING REBOOT.
            clean_reason = reason.split("Skipped: ", 1)[-1]
            _set_batch_result(test_id, "REBOOTING")
            logger.warning(sep)
            logger.warning("RESULT: PENDING REBOOT (manual action required)  >>  %s", test_id)
            logger.warning("REASON: %s", clean_reason)
            logger.warning(sep)
            return

        _set_batch_result(test_id, "SKIPPED", reason)
        logger.warning(sep)
        logger.warning("RESULT: SKIPPED  >>  %s", test_id)
        if reason:
            logger.warning("REASON: %s", reason)
        logger.warning(sep)


# ---------------------------------------------------------------------------
# Exit codes
# ---------------------------------------------------------------------------
# These are the framework's official numeric exit codes.
# pytest's own exit codes (ExitCode enum) are reused so shell scripts,
# CI systems, and other teams can rely on a single well-known table.
#
#   0  EXIT_OK          All collected tests passed (or xpassed).
#   1  EXIT_TESTSFAILED One or more tests FAILED.
#   2  EXIT_INTERRUPTED Execution was interrupted (Ctrl+C / SIGINT).
#   3  EXIT_INTERNALERROR Internal pytest error or unhandled exception.
#   4  EXIT_USAGEERROR  Bad CLI usage / missing config / collection error.
#   5  EXIT_NOTESTSCOLLECTED No tests were collected (all skipped or no match).
#
# The table is printed to the log at the end of every session so that
# anyone reading the log knows what the exit code means without grepping.

_EXIT_CODE_TABLE = {
    0: "EXIT_OK            — all tests PASSED",
    1: "EXIT_TESTSFAILED   — one or more tests FAILED",
    2: "EXIT_INTERRUPTED   — execution interrupted (Ctrl+C)",
    3: "EXIT_INTERNALERROR — internal pytest / framework error",
    4: "EXIT_USAGEERROR    — bad CLI / missing config / collection error",
    5: "EXIT_NOTESTSCOLLECTED — no tests collected (wrong path / all skipped)",
}


def _append_batch_history(summary: dict) -> None:
    """
    Add a finished reboot-spanning batch to test_runner.py's history (the 'H'
    menu). The runner only records runs whose pytest process returns to it,
    which never happens for a run that reboots the SUT.
    """
    results = summary.get("results", {})
    reasons = summary.get("reasons", {})

    def _with(status):
        return [nid for nid in summary.get("order", []) if results.get(nid) == status]

    entry = {
        "timestamp": summary["finished"],
        "exit_code": 1 if summary["failed"] else 0,
        "success": not summary["failed"],
        "label": f"batch {summary.get('batch_id')} (resumed after reboot)",
        "command_args": summary.get("order", []),
        "report_file": None,
        "passed": summary["passed"],
        "failed": summary["failed"],
        "skipped": summary["skipped"],
        "errors": 0,
        "passed_tests": _with("PASSED"),
        "failed_tests": _with("FAILED"),
        "skipped_tests": _with("SKIPPED"),
        "error_tests": [],
        "skip_reasons": {nid: reasons.get(nid, "") for nid in _with("SKIPPED")},
        "error_reasons": {},
        "failed_reasons": {nid: reasons.get(nid, "") for nid in _with("FAILED")},
        "log_dir": summary.get("log_dir"),
        "log_dirs": summary.get("log_dirs", []),
        "log_file": summary.get("log_file"),
        "batch_id": summary.get("batch_id"),
        "in_progress": False,
        "duration_seconds": summary.get("total_seconds"),
        "test_seconds": summary.get("test_seconds"),
        "reboots": summary.get("reboots"),
    }
    _HISTORY_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(_HISTORY_PATH, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")


def _print_batch_summary() -> None:
    """
    If this process's tests were part of a tracked batch (see
    _update_batch_manifest), print either:
      - a FINAL consolidated pass/fail summary for the whole batch (every
        queued test now has a terminal result -- nothing left to resume), or
      - an IN-PROGRESS note (some tests are still PENDING/REBOOTING -- more
        will run automatically after the next reboot/manual gate).

    This is what makes "what passed/failed across the WHOLE grouped run"
    answerable from the log alone, even though a batch spanning reboots is
    really multiple separate pytest processes under the hood.
    """
    batch = _load_batch_status()
    order = batch.get("order")
    if not order:
        return  # no tracked batch this run (e.g. ad-hoc single test outside test_runner.py)

    results = batch.get("results", {})
    pending = [nid for nid in order if results.get(nid) in _BATCH_PENDING_STATUSES]
    log = logging.getLogger("BIOS_Security_Tests")
    sep = "=" * 80
    summary = None
    # Every run gets one batch log -- 1 segment without a reboot, one per reboot otherwise.
    batch_log = combined_log_path(_BATCH_STATUS_PATH.parent, batch)
    started, total_seconds, test_seconds, reboots = _batch_times(batch)

    if pending:
        done = len(order) - len(pending)
        msg_lines = [
            sep,
            f"BATCH IN PROGRESS — {done}/{len(order)} test(s) complete so far.",
            f"  Elapsed so far: {format_duration(total_seconds)} (batch started {started:%Y-%m-%d %H:%M:%S})",
            "Remaining (will resume automatically after reboot/manual gate):",
        ]
        for nid in pending:
            msg_lines.append(f"  - {nid}")
            msg_lines.append("")
        msg_lines += reboot_plan.next_reboot_lines(batch)
        msg_lines.append(f"Full batch log (written when the batch finishes): {batch_log}")
        msg_lines.append(sep)
        color_lines = msg_lines  # no status tags here -- nothing to colorize
    else:
        n_pass = sum(1 for v in results.values() if v == "PASSED")
        n_fail = sum(1 for v in results.values() if v == "FAILED")
        n_skip = sum(1 for v in results.values() if v == "SKIPPED")
        header = [
            sep,
            f"BATCH FINAL SUMMARY — {len(order)} test(s) total "
            f"({n_pass} passed, {n_fail} failed, {n_skip} skipped)",
            f"  Started   : {started:%Y-%m-%d %H:%M:%S}",
            f"  Finished  : {datetime.now():%Y-%m-%d %H:%M:%S}",
        ]
        if reboots:
            header += [
                f"  Total time: {format_duration(total_seconds)}  (wall clock, includes {reboots} reboot(s))",
                f"  Test time : {format_duration(test_seconds)}  (pytest running time, excludes reboot downtime)",
            ]
        else:
            header.append(f"  Total time: {format_duration(total_seconds)}")
        from core import platform_state
        header.append(f"  Platform state at finish: {platform_state.summary_line()}")
        # ANSI color only renders in a real terminal -- a log file or editor
        # just shows the raw escape bytes as garbage text. So the logger
        # (files/editors) gets plain text, and only print() (live terminal)
        # gets the colored version.
        msg_lines = list(header)
        color_lines = list(header)
        for nid in order:
            status = results.get(nid, "?")
            msg_lines.append(f"  [{status}] {nid}")
            color_lines.append(f"  [{_colorize_status(status)}] {nid}")
            msg_lines.append("")    # blank line between entries for easier scanning
            color_lines.append("")
        total = (f"TOTAL: {n_pass} of {len(order)} test(s) passed"
                 f" ({n_fail} failed, {n_skip} skipped)")
        msg_lines.append(total)
        color_lines.append(total)
        msg_lines.append(f"Full batch log: {batch_log}")
        color_lines.append(f"Full batch log: {batch_log}")
        msg_lines.append(sep)
        color_lines.append(sep)
        summary = {
            "batch_id": batch.get("batch_id"),
            "started": started.isoformat(),
            "finished": datetime.now().isoformat(),
            "total_seconds": round(total_seconds, 1),
            "test_seconds": round(test_seconds, 1),
            "reboots": reboots,
            "passed": n_pass,
            "failed": n_fail,
            "skipped": n_skip,
            "order": order,
            "test_ids": batch.get("test_ids", {}),
            "results": results,
            "reasons": batch.get("reasons", {}),
            "log_dir": str(_current_log_dir) if _current_log_dir else None,
            "log_dirs": batch.get("log_dirs", []),
            "log_file": str(batch_log),
        }
        try:
            _LAST_BATCH_SUMMARY_PATH.write_text(json.dumps(summary, indent=2), encoding="utf-8")
            # Single-process batches are already recorded by test_runner.py itself.
            if len(summary["log_dirs"]) > 1:
                _append_batch_history(summary)
        except OSError:
            pass
        # Batch is done -- clear the manifest so the next run starts fresh.
        try:
            _BATCH_STATUS_PATH.unlink()
        except OSError:
            pass
        # The pre-flight's operator attestation was for this batch only.
        try:
            from core import bios_knob_checks
            bios_knob_checks.clear_attested()
        except ImportError:
            pass

    for line in msg_lines:
        log.info(line)
    print()
    for line in color_lines:
        _print_safe(line)

    # After the summary is logged, so the combined file ends with it.
    if summary:
        try:
            stitch_batch_log(_BATCH_STATUS_PATH.parent, summary)
        except OSError as exc:
            log.warning("Could not write combined batch log: %s", exc)


_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


def _clean_reason(text: str) -> str:
    """
    Strip terminal colour codes and the auto-generated assertion diff
    (pytest / pytest-clarity "assert ..." lines) that follow a custom
    assert message -- the message already says what failed and why.
    """
    lines = _ANSI_RE.sub("", str(text)).splitlines()
    for i, line in enumerate(lines[1:], 1):
        if line.startswith("assert "):
            lines = lines[:i]
            break
    return "\n".join(line.rstrip() for line in lines).strip()


def _report_reason(report) -> str:
    """
    Short human-readable reason from a skip/error/failure TestReport's longrepr.

    Skip/error longreprs are a (path, lineno, reason) tuple. Failures carry an
    ExceptionChainRepr instead -- str()'ing that dumps the full traceback, so
    use its .reprcrash.message (the same one-liner pytest's own "short test
    summary info" section shows) when present.
    """
    longrepr = getattr(report, "longrepr", None)
    if longrepr is None:
        return ""
    reprcrash = getattr(longrepr, "reprcrash", None)
    if reprcrash is not None:
        return _clean_reason(reprcrash.message)
    if isinstance(longrepr, tuple) and len(longrepr) == 3:
        return str(longrepr[2]).strip()
    return str(longrepr).strip()


def pytest_sessionfinish(session, exitstatus):
    """
    Print a structured exit-code summary at the end of the session.

    The summary is written to the log AND to stdout so it is always
    visible in CI output, test reports, and terminal captures.

    Exit code meaning:
        0  All tests passed
        1  One or more tests failed
        2  Interrupted
        3  Internal error
        4  Usage / config error
        5  No tests collected
    """
    # Listing tests must not overwrite last_run_summary.json or touch the batch manifest.
    if session.config.option.collectonly:
        return

    _log = logging.getLogger("BIOS_Security_Tests")
    sep = "=" * 80

    # Tally results from the terminal reporter if available
    passed = skipped = failed = error = pending = 0
    tr = session.config.pluginmanager.get_plugin("terminalreporter")
    if tr:
        passed  = len(tr.stats.get("passed",  []))
        failed  = len(tr.stats.get("failed",  []))
        skipped = len(tr.stats.get("skipped", []))
        error   = len(tr.stats.get("error",   []))
        pending = len(tr.stats.get("pending_reboot", []))
    attested_reasons = {
        r.nodeid: "; ".join(_attested_steps(r))
        for r in (tr.stats.get("passed", []) if tr else []) if _attested_steps(r)
    }

    # A reboot point stops the session (Windows: session.shouldstop -> exit 2); that is not a failure.
    if pending and not failed and not error and int(exitstatus) != 0:
        exitstatus = pytest.ExitCode.OK
        session.exitstatus = exitstatus

    code_desc = _EXIT_CODE_TABLE.get(int(exitstatus),
                                     f"EXIT_UNKNOWN ({exitstatus})")
    # Exit 0 only means "no failures" — pytest treats skipped tests as OK too.
    # Don't claim tests "PASSED" if none actually ran/passed.
    if int(exitstatus) == 0 and pending:
        code_desc = (f"EXIT_OK            — paused for reboot ({pending} test(s) PENDING REBOOT, "
                     "they resume automatically after the next boot)")
    elif int(exitstatus) == 0 and passed == 0 and skipped > 0:
        code_desc = f"EXIT_OK            — no failures ({skipped} test(s) SKIPPED, 0 passed)"
    elif int(exitstatus) == 0 and passed == 0 and failed == 0 and error == 0:
        # pytest.exit(returncode=0) from trigger_reboot() lands here mid-test.
        code_desc = "EXIT_OK            — no verdict yet (session paused for reboot/resume, 0 passed)"

    # A batch that reboots runs as one pytest session per boot; the counts above are this session only
    batch = _load_batch_status()
    results = batch.get("results") or {}
    multi_session = bool(batch.get("order")) and len(batch.get("log_dirs") or []) > 1
    batch_done = bool(batch.get("order")) and not any(s in _BATCH_PENDING_STATUSES for s in results.values())
    batch_ids = {s: [nid for nid in batch.get("order", []) if results.get(nid) == s]
                 for s in ("PASSED", "FAILED", "SKIPPED")}
    batch_line = ""
    shown = {"passed": passed, "failed": failed, "skipped": skipped, "error": error,
             "pending": pending, "attested": len(attested_reasons)}
    if multi_session:
        reasons = batch.get("reasons") or {}
        batch_line = f"{len(results)} test(s) in {len(batch['log_dirs'])} sessions (counts below are the whole batch)"
        shown = {
            "passed": len(batch_ids["PASSED"]),
            "failed": len(batch_ids["FAILED"]),
            "skipped": len(batch_ids["SKIPPED"]),
            "error": sum(1 for v in results.values() if v == "ERROR"),
            "pending": sum(1 for v in results.values() if v in _BATCH_PENDING_STATUSES),
            "attested": sum(1 for nid in batch_ids["PASSED"]
                            if reasons.get(nid, "").startswith(_ATTESTED_PREFIX)),
        }

    _log.info(sep)
    _log.info("SESSION FINISHED")
    if batch_line:
        _log.info("  Whole batch : %s", batch_line)
    _log.info("  Passed  : %d%s", shown["passed"],
              f"   ({shown['attested']} of them confirmed by the operator)" if shown["attested"] else "")
    _log.info("  Failed  : %d", shown["failed"])
    _log.info("  Skipped : %d", shown["skipped"])
    _log.info("  Errors  : %d", shown["error"])
    _log.info("  Pending reboot: %d", shown["pending"])
    _log.info("  Duration: %s%s", format_duration(time.time() - _session_started),
              "  (since the last reboot)" if batch_line else "")
    _log.info("  Exit code: %d  —  %s", int(exitstatus), code_desc)
    _log.info(sep)
    _log.info("EXIT CODE REFERENCE:")
    for code, desc in _EXIT_CODE_TABLE.items():
        _log.info("  %d  %s", code, desc)
    _log.info(sep)

    # Authoritative run summary for test_runner.py's L/H menu options --
    # richer than just "what command ran": pass/fail counts, failed test
    # ids, and where this run's log artifacts live.
    try:
        passed_tests = [r.nodeid for r in tr.stats.get("passed", [])] if tr else []
        failed_tests = [r.nodeid for r in tr.stats.get("failed", [])] if tr else []
        skipped_reports = tr.stats.get("skipped", []) if tr else []
        error_reports = tr.stats.get("error", []) if tr else []
        skipped_tests = [r.nodeid for r in skipped_reports]
        error_tests = [r.nodeid for r in error_reports]
        skip_reasons = {r.nodeid: _report_reason(r) for r in skipped_reports}
        error_reasons = {r.nodeid: _report_reason(r) for r in error_reports}
        failed_reasons = {r.nodeid: _report_reason(r) for r in (tr.stats.get("failed", []) if tr else [])}
        run_summary = {
            "timestamp": datetime.now().isoformat(),
            "exit_code": int(exitstatus),
            "duration_seconds": round(time.time() - _session_started, 1),
            "passed": passed,
            "failed": failed,
            "skipped": skipped,
            "errors": error,
            "pending_reboot": pending,
            "pending_reboot_tests": [r.nodeid for r in tr.stats.get("pending_reboot", [])] if tr else [],
            "passed_tests": passed_tests,
            "failed_tests": failed_tests,
            "skipped_tests": skipped_tests,
            "error_tests": error_tests,
            "skip_reasons": skip_reasons,
            "error_reasons": error_reasons,
            "failed_reasons": failed_reasons,
            "attested_reasons": attested_reasons,
            "log_dir": str(_current_log_dir) if _current_log_dir else None,
            "batch_log": str(combined_log_path(_BATCH_STATUS_PATH.parent, batch)) if batch_done else None,
        }
        if multi_session and batch_done:
            # test_runner.py 'L' shows this file: the finished batch, not just its last session
            reasons = batch.get("reasons") or {}
            run_summary.update({
                "exit_code": 1 if batch_ids["FAILED"] else int(exitstatus),
                "passed": len(batch_ids["PASSED"]),
                "failed": len(batch_ids["FAILED"]),
                "skipped": len(batch_ids["SKIPPED"]),
                "errors": 0,
                "pending_reboot": 0,
                "pending_reboot_tests": [],
                "passed_tests": batch_ids["PASSED"],
                "failed_tests": batch_ids["FAILED"],
                "skipped_tests": batch_ids["SKIPPED"],
                "error_tests": [],
                "skip_reasons": {nid: reasons.get(nid, "") for nid in batch_ids["SKIPPED"]},
                "error_reasons": {},
                "failed_reasons": {nid: reasons.get(nid, "") for nid in batch_ids["FAILED"]},
                "attested_reasons": {nid: reasons[nid][len(_ATTESTED_PREFIX):] for nid in batch_ids["PASSED"]
                                     if reasons.get(nid, "").startswith(_ATTESTED_PREFIX)},
            })
        _LAST_RUN_SUMMARY_PATH.parent.mkdir(parents=True, exist_ok=True)
        _LAST_RUN_SUMMARY_PATH.write_text(json.dumps(run_summary, indent=2), encoding="utf-8")
    except OSError:
        pass

    # Also print directly to stdout so it is always captured even when
    # log handlers are not yet flushed (e.g. in CI log parsers).
    print(f"\n{sep}")
    print(f"FRAMEWORK EXIT CODE: {int(exitstatus)}  —  {code_desc}")
    if batch_line:
        print(f"  Whole batch : {batch_line}")
    print(f"  Passed={shown['passed']}  Failed={shown['failed']}  Skipped={shown['skipped']}  "
          f"Errors={shown['error']}  PendingReboot={shown['pending']}")
    print(sep)

    batch = _load_batch_status()
    if batch.get("order"):
        _touch_segment(batch)
        _save_batch_status(batch)
    _print_batch_summary()

    if _resumed_by_logon_task and not _load_batch_status().get("order"):
        _pause_before_closing()
