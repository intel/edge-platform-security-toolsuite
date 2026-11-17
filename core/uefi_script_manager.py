# Copyright 2026 Intel Corporation
# SPDX-License-Identifier: Apache-2.0

"""
UEFI Script Manager — file handshake between OS pytest phases and the UEFI shell (SUT-local tests).

How it works
------------
When pytest runs ON the SUT, it cannot survive a reboot. The OS side keeps its state in
the state folder (core/state_dir.py: <repo>/logs/sut_state by default, or a USB drive via
``usb_mount``); the UEFI shell can only read FAT32, so its script and results go to the
EFI partition.

Workflow
--------
Phase 1 (OS):
    1. pytest calls write_phase() — writes maintest.nsh (EFI partition) + state.json
    2. pytest calls trigger_reboot() — SUT reboots; pytest process exits

UEFI shell (no OS):
    3. startup.nsh (on EFI partition) auto-runs maintest.nsh
    4. maintest.nsh runs the .efi tool, redirects output to a result file on the EFI partition
    5. maintest.nsh writes state_done.txt (EFI partition)
    6. maintest.nsh executes `reset` to reboot back to OS

Phase 2 (OS, resumed by systemd):
    7. pytest reads state.json — confirms phase completed
    8. pytest reads the result file
    9. pytest asserts expected values
   10. If more phases needed: repeat from step 1 with phase+1
   11. Otherwise: write final PASS/FAIL record, clean up

Layout
------
    <state_dir>/                (logs/sut_state)
        state.json          ← current phase state
        state_done.txt      ← OS-only reboot marker (Linux resume service)
        next_test.txt       ← tests to resume (Linux resume service)
    <efi_mount>/                (/boot/efi)
        maintest.nsh        ← UEFI shell script for current phase
        state_done.txt      ← UEFI phase marker
        result_phase<N>.txt ← output from each UEFI phase
"""

import json
import logging
import subprocess
from pathlib import Path

logger = logging.getLogger(__name__)


class UEFIScriptManager:
    """
    Manages the file handshake between OS pytest phases and UEFI shell.

    Args:
        state_dir: folder that survives the reboot (core/state_dir.resolve()).
        test_id:   Test identifier string.
    """

    STATE_FILE  = "state.json"
    SCRIPT_FILE = "maintest.nsh"

    # EFI partition mount point — maintest.nsh and result files go here
    # because UEFI shell can only read FAT32.
    EFI_MOUNT_DEFAULT = "/boot/efi"

    # Written by SUTBaseTest._wait_for_manual_signal(); a gate waiting across a reboot needs them back.
    GATE_STATE_KEYS = ("sub", "gate_boot", "gate_attempt", "gates_batch", "gates_done")

    def __init__(self, state_dir, test_id: str, efi_mount: str = None):
        self.state_dir  = Path(state_dir)
        self.test_id    = test_id
        self.efi_mount  = Path(efi_mount or self.EFI_MOUNT_DEFAULT)
        self.state_path  = self.state_dir / self.STATE_FILE
        # maintest.nsh goes to EFI partition (FAT32) so UEFI shell can read it
        self.script_path = self.efi_mount / self.SCRIPT_FILE

    # ------------------------------------------------------------------
    # State
    # ------------------------------------------------------------------

    def get_state(self) -> dict:
        """
        Read and return state.json from the state folder.
        Returns empty dict if the file does not exist or is malformed.
        """
        if not self.state_path.exists():
            return {}
        try:
            return json.loads(self.state_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as exc:
            logger.warning("Could not read state.json: %s", exc)
            return {}

    def _write_state(self, phase: int, status: str, extra: dict = None) -> None:
        state = {"phase": phase, "test": self.test_id, "status": status}
        if extra:
            state.update(extra)
        self.state_path.write_text(json.dumps(state, indent=2), encoding="utf-8")
        logger.debug("state.json written: %s", state)

    def clear_state(self) -> None:
        """Remove state.json so the next test run starts fresh."""
        if self.state_path.exists():
            self.state_path.unlink()

    # ------------------------------------------------------------------
    # Phase script writing
    # ------------------------------------------------------------------

    def write_phase(
        self,
        phase: int,
        uefi_commands: list,
        result_filename: str = None,
        skip_completion_marker: bool = False,
    ) -> None:
        """
        Write maintest.nsh and state.json for the next UEFI phase.

        Args:
            phase:                   Integer phase number (1, 2, ...).
            uefi_commands:           List of UEFI shell command strings to execute.
                                     Do NOT include reset — it is appended automatically
                                     unless skip_completion_marker is True.
            result_filename:         Name of the result file the commands write
                                     (relative to the EFI partition root).
            skip_completion_marker:  When True, omit the state_done.txt write and
                                     the trailing `reset` from the script.  Use this
                                     when the UEFI tool (e.g. CapsuleApp.efi) triggers
                                     an automatic system reset before the script can
                                     continue — the OS resumes based on state.json
                                     alone (phase=N, status=pending → systemd fires).
        """
        # Write state BEFORE the reboot so UEFI can read it if needed
        self._write_state(phase, "pending")

        # Build UEFI shell script
        lines = ["@echo -off", ""]

        # Write state_done.txt at the VERY START of the script (before any tool
        # runs) so that fw-validation-resume.service can always resume the next
        # OS phase even if a UEFI tool hangs or causes an unscheduled reset
        # (e.g. Fpt.efi -closemnf auto-reset, MEInfo.efi waiting for ME after
        # EOM close).  The second write at the end overwrites this with
        # "status=done" when all commands complete successfully.
        lines.append(f'echo phase={phase} status=started > state_done.txt')
        lines.append("")

        for cmd in uefi_commands:
            lines.append(cmd)

        if not skip_completion_marker:
            # cd back to EFI root before writing state_done.txt so the path is
            # always correct regardless of any 'cd' done by earlier commands.
            lines.append("")
            lines.append("cd \\")
            lines.append(f'echo phase={phase} status=done > state_done.txt')

            # Reboot back to OS
            lines.append("")
            lines.append("reset")

        script_content = "\r\n".join(lines)
        self._write_efi_file(self.script_path, script_content)
        logger.info(
            "[UEFIScriptManager] Phase %d script written to %s",
            phase, self.script_path,
        )
        logger.debug("Script content:\n%s", script_content)

    # ------------------------------------------------------------------
    # EFI partition write helper (requires sudo)
    # ------------------------------------------------------------------

    def _write_efi_file(self, path: Path, content: str) -> None:
        """Write *content* to *path* on the EFI partition using sudo tee.

        The EFI partition is typically root-owned (mode 700) so a normal
        user process cannot write there directly.  Using ``sudo tee``
        avoids a permanent permission change to the EFI mount.
        """
        result = subprocess.run(
            ["sudo", "tee", str(path)],
            input=content.encode("utf-8"),
            capture_output=True,
        )
        if result.returncode != 0:
            raise PermissionError(
                f"[UEFIScriptManager] sudo tee failed for {path}: "
                f"{result.stderr.decode(errors='replace').strip()}"
            )

    def _remove_efi_file(self, path: Path) -> None:
        """Remove a file from the EFI partition using sudo rm (if it exists)."""
        if path.exists():
            result = subprocess.run(["sudo", "rm", "-f", str(path)], capture_output=True)
            if result.returncode != 0:
                raise PermissionError(
                    f"[UEFIScriptManager] sudo rm failed for {path}: "
                    f"{result.stderr.decode(errors='replace').strip()}"
                    " (passwordless rule missing? re-run: sudo ./deploy/setup/setup_sut.sh)"
                )

    # ------------------------------------------------------------------
    # Result reading
    # ------------------------------------------------------------------

    def read_result(self, filename: str) -> str:
        """
        Read a result file written by the UEFI shell.
        Checks EFI partition first (UEFI shell writes there), then the state folder.

        Args:
            filename: Filename relative to the mount root
                      (e.g. 'result_phase1.txt').

        Returns:
            File contents as a string, or empty string if not found.
        """
        path = self.efi_mount / filename
        if not path.exists():
            path = self.state_dir / filename
        if not path.exists():
            logger.warning(
                "[UEFIScriptManager] Result file not found: %s", filename
            )
            return ""
        content = path.read_text(encoding="utf-8", errors="replace")
        logger.info(
            "[UEFIScriptManager] Read result file %s (%d chars)",
            filename, len(content),
        )
        return content

    def is_phase_done(self) -> bool:
        """
        Check whether the UEFI phase completed by looking for state_done.txt.
        Checks EFI partition first (written by UEFI shell), then the state folder (written by OS).
        """
        return (self.efi_mount / "state_done.txt").exists() or \
               (self.state_dir / "state_done.txt").exists()

    def mark_phase_done(self, phase: int) -> None:
        """
        Update state.json to status=done after verifying UEFI completed.
        Removes state_done.txt from both EFI partition and the state folder.
        Manual-gate keys (GATE_STATE_KEYS) are kept.
        """
        old = self.get_state()
        self._write_state(phase, "done", extra={k: old[k] for k in self.GATE_STATE_KEYS if k in old})
        # EFI partition file was written by UEFI shell (root-owned) — needs sudo
        self._remove_efi_file(self.efi_mount / "state_done.txt")
        os_marker = self.state_dir / "state_done.txt"
        if os_marker.exists():
            os_marker.unlink()

    def mark_os_phase_done(self, phase: int) -> None:
        """
        Write state_done.txt FROM the OS side (no UEFI involved).

        Use this for tests that reboot between OS phases only — the UEFI shell
        is not involved, so pytest itself writes the completion marker before
        calling trigger_reboot(). The systemd service trigger condition
        (ConditionPathExists=state_done.txt) then fires on the next boot.

        Args:
            phase: Current phase number being completed.
        """
        self._write_state(phase, "done")
        done_marker = self.state_dir / "state_done.txt"
        done_marker.write_text(f"phase={phase} status=done\n", encoding="utf-8")
        logger.info(
            "[UEFIScriptManager] OS phase %d marked done — state_done.txt written.",
            phase,
        )

    # ------------------------------------------------------------------
    # Reboot trigger
    # ------------------------------------------------------------------

    def trigger_reboot(self, reboot_cmd: list = None) -> None:
        """
        Reboot the SUT. pytest exits cleanly; systemd resumes it after boot.

        This should be the LAST call in a test phase that needs a reboot.
        Uses pytest.exit(returncode=0) so pytest terminates cleanly (exit 0)
        and the systemd service restarts it on next boot.

        Args:
            reboot_cmd: Optional command list to use instead of 'sudo reboot'.
                        Use for S5 RTC wake:  ['sudo', 'rtcwake', '-m', 'off', '-s', '90']
        """
        cmd = reboot_cmd or ["sudo", "reboot"]
        logger.info(
            "[UEFIScriptManager] Triggering reboot: %s — "
            "systemd will resume this test after boot.",
            " ".join(cmd),
        )
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=False,
                timeout=10,
            )
        except subprocess.TimeoutExpired:
            result = None  # reboot command submitted; process will die shortly
        # A negative rc means the command was killed by the shutdown itself.
        if result is not None and result.returncode > 0:
            raise RuntimeError(
                f"[UEFIScriptManager] Reboot command failed (rc={result.returncode}): "
                f"{' '.join(cmd)}: {(result.stderr or result.stdout).strip()}"
            )
        import pytest as _pytest
        _pytest.exit("Rebooting SUT — systemd will resume after boot.", returncode=0)

    # ------------------------------------------------------------------
    # Cleanup
    # ------------------------------------------------------------------

    def cleanup(self) -> None:
        """
        Remove temporary files after the test completes.
        - Removes maintest.nsh and state_done.txt from the EFI partition
        - Removes state_done.txt and state.json from the state folder
        """
        # EFI partition files require sudo to remove
        errors = []
        for path in (
            self.efi_mount / self.SCRIPT_FILE,
            self.efi_mount / "state_done.txt",
        ):
            try:
                self._remove_efi_file(path)
            except PermissionError as exc:
                errors.append(str(exc))
                continue
            logger.debug("[UEFIScriptManager] Removed (EFI): %s", path)
        for path in (
            self.state_dir / "state_done.txt",
            self.state_dir / self.STATE_FILE,
        ):
            if path.exists():
                path.unlink()
                logger.debug("[UEFIScriptManager] Removed: %s", path)
        if errors:
            raise PermissionError("; ".join(errors))
