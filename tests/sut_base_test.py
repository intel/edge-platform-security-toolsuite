# Copyright 2026 Intel Corporation
# SPDX-License-Identifier: Apache-2.0

"""
SUTBaseTest — base class for IEC 62443-4-2 tests that run DIRECTLY ON the SUT.

Difference from BaseTest
-------------------------
BaseTest assumes pytest runs on the NUC (external controller):
  NUC ──SSH──> SUT   (NUC survives SUT reboots)

SUTBaseTest assumes pytest runs ON the SUT itself:
  SUT runs pytest → needs UEFI shell → reboots → systemd resumes pytest

To survive reboots, SUTBaseTest keeps its files in the state folder
(core/state_dir.py: <repo>/logs/sut_state on the SUT's own disk; a USB drive only if
``usb_mount`` is set in the suite config) and the UEFI shell uses the EFI partition:
  - state.json        : current phase + status (state folder)
  - maintest.nsh      : UEFI commands to run (EFI partition)
  - result_phaseN.txt : UEFI tool output (EFI partition)
The log of every phase is in logs/test_run_<time>/ and the combined batch log.

Usage
-----
    class TestMyFeatureSUT(SUTBaseTest):
        SUITE   = "firmware"
        TEST_ID = "IEC62443-4-2-TC_MY_FEATURE-FUNC-SUT"

        def test_my_feature(self, config, log_dir):
            self._begin()
            cfg = self._load_config(config)
            mgr = self._init_state_dir(cfg)   # MUST call before any state/reboot ops

            state = mgr.get_state()

            if not mgr.is_phase_done() and state.get("phase") != 1:
                # Phase 1 — write UEFI script and reboot
                mgr.write_phase(1, [
                    "fs0:\\EFI\\VTInfo.efi > result_phase1.txt",
                ])
                mgr.trigger_reboot()     # <-- exits; systemd resumes

            # Phase 1 done — read and assert
            mgr.mark_phase_done(1)
            result = mgr.read_result("result_phase1.txt")
            assert "VT-d: Enabled" in result
            mgr.cleanup()
            self._end()

Systemd setup (one-time on SUT)
---------------------------------
See: deploy/resume/fw-validation-resume.service (template)
Installed and enabled by:
    sudo ./deploy/setup/setup_sut.sh
"""

import logging
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Callable, List, Optional, Tuple

import pytest

from tests.base_test import BaseTest
from core import bios_knob_checks
from core import state_dir as state_dir_resolver
from core.uefi_script_manager import UEFIScriptManager

logger = logging.getLogger(__name__)


class SUTBaseTest(BaseTest):
    """
    Shared base for IEC 62443-4-2 tests executed directly on the SUT.
    """

    # EFI_GLOBAL_VARIABLE SecureBoot: 4-byte attributes header + 1-byte value.
    SECURE_BOOT_EFIVAR = Path(
        "/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c"
    )

    # Loader of the 'FW-Validation Shell' boot entry (deploy/setup/setup_sut.sh step 7),
    # relative to the EFI System Partition mount.
    BOOT_SHELL_REL = "EFI/shell/shellx64.efi"

    _state_mgr: UEFIScriptManager = None

    # Set just before trigger_reboot() so _sut_state_teardown knows a reboot/
    # resume is in flight and must NOT wipe state.json/state_done.txt/
    # next_test.txt -- see _reboot_os_phase()/_reboot_into_uefi().
    _rebooting: bool = False

    # Temp files of this test (UEFI results, values saved across reboots); deleted when it ends.
    _end_cleanup_paths: tuple = ()

    # ------------------------------------------------------------------
    # Automatic cleanup fixture — runs after every SUT test (pass or fail)
    # ------------------------------------------------------------------

    @pytest.fixture(autouse=True)
    def _sut_state_teardown(self, request):
        """
        Auto-cleanup state files after every SUT test completes.

        Runs after the test regardless of pass/fail so the next run always
        starts from a clean state without requiring manual intervention.

        Files removed on exit:
          - state.json          (phase tracker)
          - state_done.txt      (UEFI/OS phase completion marker)
          - next_test.txt       (systemd resume pointer)
          - maintest.nsh        (EFI partition — written by _write_uefi_phase)

        Files intentionally preserved:
          - *_snapshot_*.json   (PCR snapshots — kept for post-analysis)

        Note: pytest.exit() (used by trigger_reboot()) does NOT reliably skip
        this teardown -- on pytest 9.x it still unwinds through fixture
        finalizers before the OS actually reboots/powers off, so relying on
        "the process exits first" is unsafe. _reboot_os_phase()/
        _reboot_into_uefi() instead set self._rebooting=True immediately
        before trigger_reboot(), and we check that flag below to skip
        cleanup -- otherwise this fixture would delete state.json/
        state_done.txt/next_test.txt moments after they were written for
        the resume, and fw-validation-resume.service would have nothing to
        resume into after the reboot/wake.
        """
        # Stash `request` so reboot/gate helpers can read the full batch
        # queue (request.session.items) without changing every test's
        # call signature -- see _write_next_test_queue().
        self._request = request

        yield  # run the test

        if self._state_mgr is None:
            return  # _init_state_dir was never called (e.g. failed in pre_test_check)

        if self._rebooting:
            logger.info(
                "[SUTBaseTest] Test ended mid-reboot — leaving state "
                "files in place for the resume."
            )
            return

        outcome = (
            request.node.rep_call.outcome
            if hasattr(request.node, "rep_call")
            else "unknown"
        )
        logger.info(
            "[SUTBaseTest] Test ended (%s) — auto-cleaning state files",
            outcome,
        )

        # mgr.cleanup() removes: state.json, state_done.txt, maintest.nsh
        # (state folder and EFI partition copies)
        try:
            self._state_mgr.cleanup()
        except Exception as exc:  # noqa: BLE001
            logger.warning("[SUTBaseTest] cleanup() raised: %s", exc)

        # next_test.txt is not removed by mgr.cleanup() — remove it here
        next_test = self._state_mgr.state_dir / "next_test.txt"
        if next_test.exists():
            try:
                next_test.unlink()
                logger.info("[SUTBaseTest] Removed: %s", next_test)
            except OSError as exc:
                logger.warning("[SUTBaseTest] Could not remove %s: %s", next_test, exc)

        for path in self._end_cleanup_paths:
            if not path.exists():
                continue
            try:
                if path.is_relative_to(self._state_mgr.efi_mount):
                    self._state_mgr._remove_efi_file(path)
                else:
                    path.unlink()
                logger.info("[SUTBaseTest] Removed: %s", path)
            except OSError as exc:
                logger.warning("[SUTBaseTest] Could not remove %s: %s", path, exc)

    def _remove_at_test_end(self, *paths) -> None:
        """Delete these temp files when the test ends, pass or fail (kept across its own reboots)."""
        self._end_cleanup_paths += tuple(Path(p) for p in paths)

    @staticmethod
    def _write_read_only(path: Path, text: str) -> None:
        """Write a value that must not change until it is read back, then remove write access."""
        path.unlink(missing_ok=True)
        path.write_text(text, encoding="utf-8")
        try:
            path.chmod(0o400)
        except OSError as exc:  # a FAT usb_mount state folder has no per-file modes
            logger.warning("Could not make %s read-only: %s", path, exc)

    def _init_state_dir(self, cfg: dict) -> UEFIScriptManager:
        """
        Initialise the UEFIScriptManager on the state folder (core/state_dir.py).

        Call this after _load_config() in every SUT test method.

        Args:
            cfg: Suite config dict (from self._load_config()).

        Returns:
            The UEFIScriptManager instance (also stored on self._state_mgr).
        """
        state_dir = state_dir_resolver.resolve(cfg.get("usb_mount"))
        self._state_mgr = UEFIScriptManager(state_dir, self.TEST_ID)

        # Guard: if state.json was left by a DIFFERENT test, wipe it so this
        # test always starts from Phase 0.  Without this, stale phase numbers
        # from the previous test cause the new test to skip Phase 0 entirely
        # (missing iteration 1 snapshot, missing pre-checks).
        existing_state = self._state_mgr.get_state()
        stale_test = existing_state.get("test", "")
        if stale_test and stale_test != self.TEST_ID:
            logger.warning(
                "[SUTBaseTest] state.json belongs to a different test (%r) — "
                "clearing stale state so %r starts from Phase 0.",
                stale_test, self.TEST_ID,
            )
            self._state_mgr.clear_state()

        logger.info("[SUTBaseTest] State folder: %s", state_dir)
        return self._state_mgr

    # ------------------------------------------------------------------
    # Secure Boot aware EFI tool selection
    # ------------------------------------------------------------------

    @classmethod
    def _is_secure_boot_enabled(cls, step_label: str = "") -> bool:
        """
        Return True if UEFI Secure Boot is enabled on this SUT.

        Reads the SecureBoot efivar directly; falls back to
        ``mokutil --sb-state``. Fails the test if neither source works,
        because guessing wrong makes the UEFI shell reject the tool.
        """
        prefix = f"[Step {step_label}]" if step_label else "[SecureBoot]"
        try:
            data = cls.SECURE_BOOT_EFIVAR.read_bytes()
            enabled = len(data) >= 5 and data[4] == 1
            logger.info(
                "%s Secure Boot %s (efivar %s = %s)",
                prefix, "ENABLED" if enabled else "DISABLED",
                cls.SECURE_BOOT_EFIVAR.name, data.hex(),
            )
            return enabled
        except OSError as exc:
            logger.warning(
                "%s Cannot read %s (%s) -- falling back to mokutil",
                prefix, cls.SECURE_BOOT_EFIVAR, exc,
            )

        try:
            result = subprocess.run(
                ["mokutil", "--sb-state"],
                capture_output=True, text=True, timeout=15,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise AssertionError(
                f"{prefix} Cannot determine Secure Boot state: efivar unreadable "
                f"and mokutil failed ({exc}).\n"
                "  Install mokutil:  sudo apt install mokutil"
            ) from exc

        output = (result.stdout + result.stderr).strip()
        logger.info("%s mokutil --sb-state: %s", prefix, output)
        assert "secureboot enabled" in output.lower() or "secureboot disabled" in output.lower(), (
            f"{prefix} Unexpected mokutil --sb-state output: {output!r}"
        )
        return "secureboot enabled" in output.lower()

    def _select_efi_tool(self, efi_dir, tool_name: str, step_label: str = "") -> str:
        """
        Return the EFI tool filename to run in the UEFI shell.

        Secure Boot enabled  -> ``<stem>_signed.efi`` (from deploy/secure_boot/sign_efi_tools.sh)
        Secure Boot disabled -> ``tool_name`` unchanged

        Args:
            efi_dir:    Linux directory holding the tool (e.g. /boot/efi/EFI).
            tool_name:  Original tool filename (e.g. "MEInfo.efi").
            step_label: For log prefix.
        """
        prefix = f"[Step {step_label}]" if step_label else "[EFI Tool]"
        if not self._is_secure_boot_enabled(step_label=step_label):
            logger.info("%s Using original tool: %s", prefix, tool_name)
            return tool_name

        signed_name = f"{Path(tool_name).stem}_signed.efi"
        signed_path = Path(efi_dir) / signed_name
        original_path = Path(efi_dir) / tool_name
        sign_hint = (
            "  Sign the EFI tools on the SUT:\n"
            "    sudo ./deploy/secure_boot/sign_efi_tools.sh"
        )
        assert signed_path.exists(), (
            f"{prefix} Secure Boot is enabled but signed tool not found: {signed_path}\n"
            f"  The UEFI shell will refuse the unsigned {tool_name} (Access Denied).\n"
            f"{sign_hint}"
        )
        assert not (
            original_path.exists()
            and original_path.stat().st_mtime > signed_path.stat().st_mtime
        ), (
            f"{prefix} {signed_path} is older than {original_path} -- stale signed copy.\n"
            f"{sign_hint}"
        )
        logger.info("%s [OK] Using signed tool: %s", prefix, signed_path)
        return signed_name

    @staticmethod
    def _pe_has_signature(path) -> bool:
        """
        Return True if the PE/COFF image at ``path`` has an Authenticode
        signature (non-empty IMAGE_DIRECTORY_ENTRY_SECURITY), else False.
        Raises OSError if the file cannot be read.
        """
        with open(path, "rb") as f:
            data = f.read(4096)
        if len(data) < 0x40 or data[:2] != b"MZ":
            return False
        pe_off = int.from_bytes(data[0x3C:0x40], "little")
        opt_off = pe_off + 24   # "PE\0\0" (4) + COFF file header (20)
        if data[pe_off:pe_off + 4] != b"PE\0\0" or len(data) < opt_off + 2:
            return False
        magic = int.from_bytes(data[opt_off:opt_off + 2], "little")
        if magic == 0x20B:      # PE32+
            count_off, dirs_off = opt_off + 108, opt_off + 112
        elif magic == 0x10B:    # PE32
            count_off, dirs_off = opt_off + 92, opt_off + 96
        else:
            return False
        sec_off = dirs_off + 4 * 8   # data directory 4 = certificate table
        if len(data) < sec_off + 8:
            return False
        if int.from_bytes(data[count_off:count_off + 4], "little") < 5:
            return False
        return int.from_bytes(data[sec_off + 4:sec_off + 8], "little") > 0

    @staticmethod
    def _shell_exits_under_secure_boot(path) -> bool:
        """
        True if ``path`` is Ubuntu's efi-shell-x64 build (edk2 >= 2024.02-2ubuntu0.3,
        CVE-2025-2486), which returns EFI_SECURITY_VIOLATION at startup when
        Secure Boot is enabled. Only that build references the SetupMode variable.
        """
        return "SetupMode".encode("utf-16-le") in Path(path).read_bytes()

    def _assert_boot_shell_signed(self, step_label: str = "") -> None:
        """
        Fail before rebooting if Secure Boot is enabled and the
        'FW-Validation Shell' image (EFI/shell/shellx64.efi) is unsigned.

        Without this check the firmware refuses the shell, falls back to the
        normal boot order and starts the OS, so maintest.nsh never runs and the
        test waits forever for a UEFI phase result.
        """
        prefix = f"[Step {step_label}]" if step_label else "[Reboot]"
        shell_path = Path(self._state_mgr.efi_mount) / self.BOOT_SHELL_REL
        if not self._is_secure_boot_enabled(step_label=step_label):
            return
        try:
            signed = self._pe_has_signature(shell_path)
        except FileNotFoundError:
            logger.info(
                "%s %s not found -- FW-Validation Shell not installed, skipping signature check",
                prefix, shell_path,
            )
            return
        except OSError as exc:
            logger.warning(
                "%s Cannot read %s (%s) -- skipping boot shell signature check",
                prefix, shell_path, exc,
            )
            return
        logger.info("%s Boot shell %s signed: %s", prefix, shell_path, signed)
        assert signed, (
            f"{prefix} Secure Boot is enabled but the boot shell is unsigned: {shell_path}\n"
            "  The firmware will refuse it and boot the OS instead, so the UEFI phase never runs.\n"
            "  Sign it in place on the SUT:\n"
            "    sudo ./deploy/secure_boot/sign_efi_tools.sh"
        )
        assert not self._shell_exits_under_secure_boot(shell_path), (
            f"{prefix} {shell_path} is Ubuntu's efi-shell-x64 build, which exits immediately\n"
            "  when Secure Boot is enabled (CVE-2025-2486). The firmware starts it, it returns,\n"
            "  and the SUT falls through to Ubuntu -- maintest.nsh never runs.\n"
            "  Replace it with the upstream EDK2 shell (auto-downloaded) and re-sign:\n"
            "    sudo ./deploy/secure_boot/sign_efi_tools.sh"
        )
        logger.info("%s [OK] Boot shell is signed", prefix)

    # ------------------------------------------------------------------
    # Phase helpers — thin wrappers that add logging
    # ------------------------------------------------------------------

    def _write_next_test_queue(self, step_label: str = "") -> list:
        """
        Write next_test.txt as the FULL remaining node-id queue -- this test
        plus everything still queued after it in the current pytest session
        -- not just this test alone. Without this, fw-validation-resume.service
        would only resume the one test that triggered the reboot and silently
        drop the rest of a multi-test batch run queued behind it.

        Falls back to just this test's own file path if `request` wasn't
        captured (e.g. this test ran outside the autouse fixture) or the
        current node can't be located in the session's item list.
        """
        import inspect, pathlib
        prefix = f"[Step {step_label}]" if step_label else "[Reboot]"

        if sys.platform.startswith("linux"):
            self._assert_resume_service_uses_state_dir(prefix)

        own_file = inspect.getfile(type(self))
        try:
            for parent in pathlib.Path(own_file).resolve().parents:
                if (parent / "pytest.ini").exists() or (parent / "pyproject.toml").exists():
                    own_rel = str(pathlib.Path(own_file).resolve().relative_to(parent))
                    break
            else:
                own_rel = pathlib.Path(own_file).name
        except ValueError:
            own_rel = pathlib.Path(own_file).name

        queue = [own_rel]
        request = getattr(self, "_request", None)
        if request is not None:
            try:
                items = request.session.items
                idx = items.index(request.node)
                queue = [item.nodeid for item in items[idx:]]
            except (ValueError, AttributeError) as exc:
                logger.warning(
                    "%s Could not resolve remaining batch queue (%s) -- "
                    "resuming only this test.", prefix, exc,
                )

        next_test_path = pathlib.Path(self._state_mgr.state_dir) / "next_test.txt"
        next_test_path.write_text("\n".join(queue) + "\n", encoding="utf-8")
        logger.info(
            "%s next_test.txt written -- %d test(s) queued to resume: %s",
            prefix, len(queue), queue,
        )
        return queue

    def _assert_resume_service_uses_state_dir(self, prefix: str) -> None:
        """Fail before rebooting if fw-validation-resume.service would read another state folder."""
        import shlex
        result = subprocess.run(
            ["systemctl", "show", "fw-validation-resume.service",
             "-p", "LoadState", "-p", "Environment", "-p", "WorkingDirectory"],
            capture_output=True, text=True, timeout=30,
        )
        props = dict(line.split("=", 1) for line in result.stdout.splitlines() if "=" in line)
        env = dict(kv.split("=", 1) for kv in shlex.split(props.get("Environment", "")) if "=" in kv)
        ours = Path(self._state_mgr.state_dir).resolve()
        theirs = env.get("STATE_DIR", "")
        logger.info(
            "%s fw-validation-resume.service: LoadState=%s WorkingDirectory=%s STATE_DIR=%s (this run: %s)",
            prefix, props.get("LoadState", "?"), props.get("WorkingDirectory", "?"), theirs or "?", ours,
        )
        assert props.get("LoadState") == "loaded" and theirs and Path(theirs).resolve() == ours, (
            f"{prefix} Not rebooting: fw-validation-resume.service would not resume this test.\n"
            f"  Service LoadState={props.get('LoadState', '?')}, "
            f"WorkingDirectory={props.get('WorkingDirectory', '?')}, STATE_DIR={theirs or '<unset>'}\n"
            f"  This run keeps its state in {ours}.\n"
            f"  The service was installed from another checkout. Fix (once, from this repo):\n"
            f"    sudo bash deploy/setup/setup_sut.sh\n"
            f"  then run the test again."
        )

    def _write_uefi_phase(
        self,
        phase: int,
        uefi_commands: list,
        result_filename: str = None,
        step_label: str = "",
        skip_completion_marker: bool = False,
    ) -> None:
        """
        Write maintest.nsh + state.json for the next UEFI phase.

        Args:
            phase:                   Phase number (1-based).
            uefi_commands:           UEFI shell command strings. `reset` appended
                                     automatically unless skip_completion_marker=True.
            result_filename:         Optional name of the result file the commands write.
            step_label:              For log prefix (e.g. "3.0").
            skip_completion_marker:  Pass True when the UEFI tool triggers an
                                     automatic reset (e.g. CapsuleApp.efi) so that
                                     state_done.txt and reset are omitted from the
                                     generated script.
        """
        prefix = f"[Step {step_label}]" if step_label else "[UEFI Phase]"
        logger.info("%s Writing UEFI phase %d script", prefix, phase)
        if skip_completion_marker:
            logger.info(
                "%s skip_completion_marker=True — state_done.txt + reset "
                "omitted (tool triggers auto-reboot)", prefix,
            )
        for cmd in uefi_commands:
            logger.info("%s   > %s", prefix, cmd)

        # A leftover marker (e.g. from a manual gate) or result file from an
        # earlier run would otherwise make a UEFI phase that never ran look PASSED.
        mgr = self._state_mgr
        names = ["state_done.txt"] + ([result_filename] if result_filename else [])
        for name in names:
            efi_path, state_path = mgr.efi_mount / name, mgr.state_dir / name
            if efi_path.exists():
                logger.info("%s Removing stale %s", prefix, efi_path)
                mgr._remove_efi_file(efi_path)
            if state_path.exists():
                logger.info("%s Removing stale %s", prefix, state_path)
                state_path.unlink()

        mgr.write_phase(phase, uefi_commands, result_filename, skip_completion_marker)
        logger.info("%s state.json: phase=%d status=pending", prefix, phase)

    def _check_phase_done(self, phase: int, step_label: str = "") -> bool:
        """
        Return True if the UEFI phase wrote its completion marker.
        Logs clearly whether phase succeeded or not.
        """
        prefix = f"[Step {step_label}]" if step_label else "[UEFI Phase]"
        done = self._state_mgr.is_phase_done()
        if done:
            logger.info("%s [OK] UEFI phase %d completed", prefix, phase)
        else:
            logger.error(
                "%s UEFI phase %d did NOT complete "
                "(state_done.txt not found on the EFI partition or in the state folder).",
                prefix, phase,
            )
            logger.error(
                "%s   state.json = %s", prefix, self._state_mgr.get_state()
            )
        return done

    def _read_uefi_result(self, filename: str, step_label: str = "") -> str:
        """
        Read a UEFI result file and replay its contents into the log.

        Args:
            filename:    Filename relative to the EFI partition root.
            step_label:  For log prefix.

        Returns:
            File contents as string.
        """
        prefix = f"[Step {step_label}]" if step_label else "[UEFI Result]"
        content = self._state_mgr.read_result(filename)
        if content:
            logger.info("%s UEFI output from %s:", prefix, filename)
            for line in content.splitlines():
                logger.info("%s   %s", prefix, line)
        else:
            logger.warning("%s Result file empty or missing: %s", prefix, filename)
        return content

    def _reboot_os_phase(
        self,
        phase: int,
        step_label: str = "",
        s5_wake_secs: int = None,
    ) -> None:
        """
        Complete the current OS phase and reboot back into OS (no UEFI involved).

        Use this for tests that require multiple OS reboots without any UEFI
        shell interaction — e.g. kernel module tests, OS-level firmware updates,
        secure boot enrollment, TPM provisioning across reboots, etc.

        Writes state_done.txt from the OS side so that fw-validation-resume.service
        fires on the next boot, same as after a UEFI phase.

        This is the LAST line that runs in the current pytest process.

        Args:
            phase:         Phase number being completed.
            step_label:    For log prefix (e.g. "11.0").
            s5_wake_secs:  If set, uses ``sudo rtcwake -m off -s N`` instead of
                           ``sudo reboot``. Use for S5 (full power-off) cycles
                           where the RTC alarm wakes the SUT after N seconds.
                           Typical value: 90.

        Example (S5 power cycle in AES-NI test):
            # S3, S4 are in-process (rtcwake returns after wake — no phase needed)
            # Only S5 kills the process:
            self._reboot_os_phase(phase=1, s5_wake_secs=90)   # does not return

        Example (3-reboot OS test):
            state = mgr.get_state()
            phase = state.get("phase", 0)

            if phase == 0:
                # ... do Phase 1 work ...
                self._reboot_os_phase(phase=1)   # reboots; does not return

            if phase == 1:
                mgr.mark_phase_done(1)
                # ... do Phase 2 work ...
                self._reboot_os_phase(phase=2)   # reboots; does not return

            # Phase 2 done — final assertions
            mgr.mark_phase_done(2)
            assert ...
            mgr.cleanup()
        """
        prefix = f"[Step {step_label}]" if step_label else "[Reboot]"

        # Write next_test.txt so systemd resumes the rest of the queued batch
        self._write_next_test_queue(step_label=step_label)

        # Write state_done.txt from OS side — triggers systemd on next boot
        self._state_mgr.mark_os_phase_done(phase)

        reboot_cmd = None
        if s5_wake_secs:
            reboot_cmd = ["sudo", "rtcwake", "-m", "off", "-s", str(s5_wake_secs)]
            logger.info(
                "%s OS phase %d complete — S5 power-off + RTC wake in %d s. "
                "systemd will resume this test after boot.",
                prefix, phase, s5_wake_secs,
            )
        else:
            logger.info(
                "%s OS phase %d complete — rebooting. "
                "systemd will resume this test after boot.",
                prefix, phase,
            )
        self._rebooting = True   # tell _sut_state_teardown to leave the state files alone
        try:
            self._state_mgr.trigger_reboot(reboot_cmd=reboot_cmd)   # pytest.exit() — session ends here
        except RuntimeError:
            self._rebooting = False   # no reboot: let teardown remove the resume state
            raise

    def _reboot_into_uefi(self, step_label: str = "") -> None:
        """
        Reboot the SUT into UEFI shell (via startup.nsh on EFI partition).
        pytest exits cleanly; systemd resumes after boot.

        Writes next_test.txt to the state folder so fw-validation-resume.service
        knows which test module to resume — making the service reusable across
        all SUT-only test cases without editing the service file.

        This is the LAST line that runs in the current pytest process.
        """
        prefix = f"[Step {step_label}]" if step_label else "[Reboot]"

        self._assert_boot_shell_signed(step_label=step_label)

        # Write next_test.txt — service reads this to resume the rest of the queued batch
        self._write_next_test_queue(step_label=step_label)

        # Set UEFI shell as the next one-time boot entry so the reboot
        # lands in the UEFI shell instead of going straight to Ubuntu.
        import subprocess as _sp
        uefi_shell_bootnum = self._find_uefi_shell_bootnum()
        if uefi_shell_bootnum:
            # Must never prompt: after a reboot the test runs from fw-validation-resume.service (no
            # terminal). Without BootNext the SUT boots Ubuntu, nothing runs in the UEFI Shell, and
            # the batch stops silently ("state_done.txt not found ... nothing to resume").
            result = _sp.run(
                ["sudo", "-n", "efibootmgr", "--bootnext", uefi_shell_bootnum],
                capture_output=True, text=True, timeout=30,
            )
            if result.returncode != 0:
                err = (result.stderr or result.stdout).strip()
                hint = ""
                if "password" in err.lower():
                    hint = ("\n  The passwordless sudo rule does not match this efibootmgr "
                            f"({shutil.which('efibootmgr') or '?'}).\n"
                            "  Fix: sudo ./deploy/setup/setup_sut.sh (it adds the rule for both /usr/bin and /usr/sbin),"
                            " then run the test again.")
                raise AssertionError(
                    f"{prefix} efibootmgr --bootnext {uefi_shell_bootnum} failed (rc={result.returncode}): {err}\n"
                    f"  Not rebooting: without BootNext the SUT would boot Ubuntu instead of the UEFI Shell "
                    f"and the test would stop there.{hint}"
                )
            logger.info(
                "%s efibootmgr --bootnext %s — next boot will enter UEFI shell",
                prefix, uefi_shell_bootnum,
            )
        else:
            logger.warning(
                "%s Could not find UEFI Shell boot entry — "
                "reboot may go to OS; add 'Internal UEFI Shell' to boot menu",
                prefix,
            )

        logger.info(
            "%s Rebooting SUT into UEFI shell — "
            "systemd will resume this test after boot.",
            prefix,
        )
        self._rebooting = True   # tell _sut_state_teardown to leave the state files alone
        try:
            self._state_mgr.trigger_reboot()   # pytest.exit() — session ends here
        except RuntimeError:
            self._rebooting = False   # no reboot: let teardown remove the resume state
            if uefi_shell_bootnum:
                _sp.run(["sudo", "-n", "efibootmgr", "--delete-bootnext"], capture_output=True, timeout=30)
            raise

    def _find_uefi_shell_bootnum(self) -> str:
        """
        Return the efibootmgr boot number (e.g. '0006') for the UEFI Shell
        entry. Prefers 'FW-Validation Shell' (EFI-partition shell that
        auto-runs startup.nsh) over 'Internal UEFI Shell' (firmware shell
        that does NOT auto-run startup.nsh).
        Returns None if no shell entry is found.
        """
        import subprocess as _sp, re
        result = _sp.run(
            ["efibootmgr"], capture_output=True, text=True, timeout=30
        )
        if result.returncode != 0:
            logger.warning("efibootmgr failed (rc=%d): %s", result.returncode, result.stderr.strip())
        fw_shell_num  = None
        int_shell_num = None
        for line in result.stdout.splitlines():
            m = re.match(r"Boot([0-9A-Fa-f]{4})\*?\s+(.*)", line)
            if not m:
                continue
            num, label = m.group(1), m.group(2)
            if re.search(r"FW-Validation\s+Shell", label, re.IGNORECASE):
                fw_shell_num = num
            elif re.search(r"UEFI\s+Shell", label, re.IGNORECASE):
                int_shell_num = num
        return fw_shell_num or int_shell_num

    # Words that, as the first word of a signal file, mean "this step failed".
    _OPERATOR_FAIL_WORDS = ("fail", "failed", "nok", "no")

    def _wait_for_manual_signal(
        self,
        signal_file: str,
        step_label: str,
        timeout_secs: int,
        instructions: list,
        verify: Optional[Callable[[], Tuple[bool, List[str]]]] = None,
        requires_reboot: bool = False,
        checked_later: str = "",
        confirms: str = "",
        attempts: int = 3,
    ) -> None:
        """
        Reboot-safe manual gate: the operator creates a signal file in the state folder when done.

        The signal file only means "I am done" -- it is never the proof that the step worked:
          requires_reboot  the SUT must have booted since the gate was shown (any BIOS
                           change). A signal from the same boot is rejected.
          verify           () -> (passed, evidence lines), run after every signal. A failed
                           check re-arms the gate (up to ``attempts``), then fails the test.
          checked_later    no check here, but a later step verifies the result objectively
                           (text for the log, e.g. "TXT.STS at Step 8.2").
          none of these    the step counts as confirmed by the operator -- ``confirms`` says what
                           operator vouched for (e.g. "HDCP = Compatible in Graphics Command Centre").
        Writing FAIL and a reason into the signal file fails the test at once.

        Reboot-safe on both OSes: Linux resumes via fw-validation-resume.service
        (state_done.txt + next_test.txt), Windows via the batch resume task (at boot, as SYSTEM).
        A gate already passed earlier in this run (before a later reboot) is not asked again.
        """
        prefix = f"[Step {step_label}]"
        mgr = self._state_mgr
        signal_path = Path(mgr.state_dir) / signal_file
        if sys.platform == "win32":
            done_cmd = f'New-Item -ItemType File -Force "{signal_path}"'
            fail_cmd = f'Set-Content "{signal_path}" "FAIL <what you saw>"'
        else:
            done_cmd = f'touch "{signal_path}"'
            fail_cmd = f'echo "FAIL <what you saw>" > "{signal_path}"'
        gate_key = f"gate_{signal_file}"
        state = mgr.get_state()
        batch_id = self._batch_id()

        # Gates passed before a reboot of THIS batch are kept; answers from an earlier run never count.
        same_batch = bool(batch_id) and state.get("gates_batch") == batch_id
        passed_gate = (state.get("gates_done") or {}).get(signal_file) if same_batch else None
        if passed_gate is not None and (verify is None or verify()[0]):
            logger.info("%s Already confirmed earlier in this run -- not asking again", prefix)
            if passed_gate.get("attested"):
                self._mark_attested(step_label, passed_gate["attested"])
            return

        if verify is not None:
            proof = "the test then checks the result itself -- the file alone does not pass this step"
        elif checked_later:
            proof = f"the result is checked later: {checked_later}"
        else:
            proof = "the test cannot check this step itself -- creating the file confirms it"
        how = [
            "",
            f"{prefix} When done, create the signal file (run on this SUT):",
            f"{prefix}     {done_cmd}",
            f"{prefix}   ({proof})",
            f"{prefix} If the step did not work, fail the test now instead:",
            f"{prefix}     {fail_cmd}",
            f"{prefix} This step needs a reboot (BIOS Setup): create the file only after the SUT has booted again."
            if requires_reboot else f"{prefix} Rebooting is safe: the test resumes by itself and keeps waiting.",
        ]

        resumed = state.get("sub") == gate_key and same_batch
        if resumed:
            logger.info("%s Resumed after reboot -- still waiting for %s", prefix, signal_file)
        elif signal_path.exists():
            signal_path.unlink()
            logger.warning("%s Removed a leftover %s from an earlier run -- it does not answer this step",
                           prefix, signal_file)
        for line in instructions:
            logger.info("%s %s", prefix, line)
            if not resumed:
                print(line)
        for line in how:
            logger.info(line)
            print(line)

        if not resumed:
            self._write_next_test_queue(step_label=step_label)
            saved = mgr.get_state()
            # mark_os_phase_done() rewrites state.json from scratch -- put the gate keys back after it.
            mgr.mark_os_phase_done(saved.get("phase", 0))
            self._update_state(**{**saved, "status": "done", "sub": gate_key, "gates_batch": batch_id,
                                  "gates_done": saved.get("gates_done") if same_batch else {},
                                  "gate_boot": bios_knob_checks.boot_id(), "gate_attempt": 1})
        if sys.platform == "win32" and self._request is not None:
            self._register_windows_resume(self._request, step_label=step_label)
        logger.info("%s Waiting for %s ...", prefix, signal_file)
        try:
            note = self._run_gate(prefix, signal_path, timeout_secs, done_cmd, verify, requires_reboot, attempts)
        finally:
            if sys.platform == "win32":
                self._cancel_windows_resume()

        attested = ""
        if verify is None and not checked_later:
            attested = (confirms or f"operator created {signal_file}") + (f" (operator note: {note})" if note else "")
            self._mark_attested(step_label, attested)
        elif checked_later:
            logger.info("%s Operator done -- checked objectively later: %s", prefix, checked_later)
        gates = dict(mgr.get_state().get("gates_done") or {})
        gates[signal_file] = {"attested": attested}
        self._update_state(sub="", gates_done=gates, gates_batch=batch_id)

    @staticmethod
    def _batch_id() -> str:
        """Id of the running batch (logs/batch_status.json, kept across its reboots), or ''."""
        import json
        try:
            path = Path(__file__).resolve().parents[1] / "logs" / "batch_status.json"
            return json.loads(path.read_text(encoding="utf-8")).get("batch_id", "")
        except (OSError, ValueError):
            return ""

    def _run_gate(self, prefix, signal_path, timeout_secs, done_cmd, verify, requires_reboot, attempts) -> str:
        """Poll until a signal is accepted (reboot proof + verify). Returns the operator's note."""
        attempt = int(self._state_mgr.get_state().get("gate_attempt", 1))
        while True:
            note = self._poll_for_signal(signal_path, prefix, timeout_secs, done_cmd)
            words = note.split()
            if words and words[0].lower().rstrip(":") in self._OPERATOR_FAIL_WORDS:
                raise AssertionError(f"{prefix} Operator reported FAIL: {note}")

            if requires_reboot and self._state_mgr.get_state().get("gate_boot") == bios_knob_checks.boot_id():
                msg = (f"{prefix} Signal ignored: the SUT has not rebooted since this step was shown, so a "
                       "BIOS change cannot be active yet. Reboot, make the change, then create the file again.")
                logger.warning(msg)
                print(msg)
                continue

            if verify is None:
                return note

            passed, evidence = verify()
            for line in evidence:
                logger.info("%s   %s", prefix, line)
            if passed:
                logger.info("%s [OK] Checked -- the step really took effect", prefix)
                return note
            if attempt >= attempts:
                raise AssertionError(
                    f"{prefix} The step did not take effect (checked {attempt} time(s)):\n"
                    + "\n".join(f"  {line}" for line in evidence)
                )
            attempt += 1
            self._update_state(gate_attempt=attempt, gate_boot=bios_knob_checks.boot_id())
            msg = (f"{prefix} [NOT YET] The check above failed -- fix it, then create the signal file again "
                   f"(attempt {attempt}/{attempts}).")
            logger.warning(msg)
            print(msg)

    def _update_state(self, **changes) -> None:
        """Merge changes into state.json (keeps every other key)."""
        state = self._state_mgr.get_state()
        state.update(changes)
        self._state_mgr._write_state(state.get("phase", 0), state.get("status", "done"), extra=state)

    @staticmethod
    def _poll_for_signal(signal_path, prefix: str, timeout_secs: int, create_cmd: str) -> str:
        """
        Poll every 10 s until signal_path exists, then delete it and return its text
        (the operator's note, '' for an empty file). timeout_secs <= 0 disables the gate
        timeout; pytest.ini's global `timeout` still caps the whole test.
        """
        import time
        _POLL_INTERVAL = 10
        limit = f"{timeout_secs} s" if timeout_secs > 0 else "no gate timeout"
        elapsed = 0
        while timeout_secs <= 0 or elapsed < timeout_secs:
            if signal_path.exists():
                time.sleep(1)   # let an editor finish writing a note into the file
                try:
                    note = signal_path.read_text(encoding="utf-8", errors="replace").strip()
                except OSError:
                    note = ""
                signal_path.unlink()
                logger.info("%s Signal file detected: %s%s", prefix, signal_path.name,
                            f" -- note: {note}" if note else "")
                return note
            time.sleep(_POLL_INTERVAL)
            elapsed += _POLL_INTERVAL
            if elapsed % 60 == 0:
                logger.info(
                    "%s Still waiting for %s ... (%d s elapsed, %s)",
                    prefix, signal_path.name, elapsed, limit,
                )

        raise AssertionError(
            f"{prefix} Timed out waiting for manual signal: {signal_path}\n"
            f"  Waited {timeout_secs}s. Create the file to continue:\n"
            f"    {create_cmd}"
        )

    def _knob_verifier(self, knobs: dict) -> Callable[[], Tuple[bool, List[str]]]:
        """verify= callable for a manual gate: read these BIOS knobs back from the OS (and AMISCE)."""
        def verify() -> Tuple[bool, List[str]]:
            ami, _reason = bios_knob_checks.detect_ami(self._amisce_override)
            results = bios_knob_checks.check_knobs(knobs, amisce=ami)
            lines = bios_knob_checks.format_results(results, indent="")
            return all(r.ok for r in results), lines
        return verify
