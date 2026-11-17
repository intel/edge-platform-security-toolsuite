# Copyright 2026 Intel Corporation
# SPDX-License-Identifier: Apache-2.0

"""
TEST — IEC 62443-4-2  BIOS Resiliency / Recovery  (functional, SUT-only)

Test ID:  IEC62443-4-2-TC_BIOS_Resiliency_Recovery-FUNC-SUT
Suite:    bios_resiliency

PURPOSE
-------
Verifies that the BIOS Resiliency mechanism backs up the OBB (Obb.bin on the
ESP) and rolls back to the backup (Top Swap) when the IBB in SPI flash is
corrupted.

RVP ONLY: the Embedded Controller (EC) of an Intel RVP performs the
resiliency / recovery flow. The test fails at Step 1.0 on any other board.

What is checked objectively vs. on the operator's word:
  - Step 1.0  RVP board         -- DMI board_vendor / board_name / product_name
  - Step 2.0  Obb.bin backup    -- found on the ESP (path, size, time logged)
  - Step 6.1  Rollback reboot   -- the SUT booted again after the gate was shown
  - Step 6.3  Obb.bin after     -- still present after the rollback
  - Step 6.0  PURPLE rollback box at boot -- visual, confirmed by the operator

FLOW (manual input: 1 checklist confirmation, 1 'yes', 1 signal file)
----
  Pre-test  Checklist (resiliency IFWI flashed, BLUE backup box seen,
            corrupted IBB received, Dediprog connected, RVP board).
  Step 1.0  [auto] RVP board check.
  Step 2.0  [auto] Obb.bin present on the ESP (/boot/efi)?
  Step 3.0  [auto] Missing -> FAIL: reflash the correct Resiliency IFWI.
  Step 3.1  [auto] Record boot id + BIOS version before the flash.
  Step 4.0  [prompt] Operator types 'yes' -> the test powers off the SUT
            (or 'no' to abort; no terminal -> power off manually).
  Step 5.0  [single gate, reboot-safe] Operator flashes the corrupted IBB with
            Dediprog, powers on, watches the PURPLE "Resiliency rollback
            (Top Swap enabled)" box, the SUT boots to Ubuntu, then creates the
            signal file (or writes FAIL <what you saw> into it).
  Step 6.x  [auto] Reboot proof, BIOS version logged, Obb.bin still present.
  PASS

REFERENCE ONLY -- generating a corrupted IBB image
--------------------------------------------------
Normally the POC provides the Resiliency IFWI and the corrupted IBB file. If
you must build the corrupted IBB yourself (Windows host with BpmGen2 from the
SBL package and HxD; Dediprog to read the SPI flash):
  R1) Read the SPI flash with Dediprog: Detect -> select SPI ID -> Edit ->
      Read -> 'Chip buffer to File' -> <FileName>.bin.
  R2) BpmGen2.exe INFO <FileName>.bin -> section '# FIT Table: #' -> note the
      address of the first '07- BIOS MODULE' entry (e.g. 00000000ffe80000).
  R3) Image offset = image_size - (0x100000000 - address)
      (e.g. 0xffe80000 in a 32 MB / 0x02000000 image -> 0x01e80000).
  R4) Open <FileName>.bin in HxD, Ctrl+G to the offset, overwrite the 5
      highlighted IBB bytes (e.g. FF FF FF FF FF), save as
      <FileName>_resiliency_IBB.bin.
  Building the Resiliency IFWI: MFIT -> decompose the BootGuard 5 IFWI ->
  replace the BIOS region with the Resiliency ROM -> build.

ONE-TIME SETUP (SUT)
--------------------
  sudo ./deploy/setup/setup_sut.sh -- installs fw-validation-resume.service and
  the sudoers rule this test uses to search /boot/efi (root-only on Ubuntu).

CONFIG (bios_resiliency_config.yaml)
------------------------------------
  manual_gate_timeout_secs, rvp_board_patterns, obb_search_root,
  poweroff_delay_secs

RUN (on SUT)
------------
  python3 -m pytest \\
      tests/bios_resiliency/test_ec62443_bios_resiliency_recovery_sut_func.py \\
      -v -s --setup-confirmed --yes
  The 'yes' prompt at Step 4.0 is separate from --yes (it reads the terminal).
"""

import logging
import os
import re
import subprocess
from datetime import datetime
from pathlib import Path

import pytest

from tests.sut_base_test import SUTBaseTest
from core import bios_knob_checks
from core.prereq import _read_from_terminal, pre_test_check

logger = logging.getLogger(__name__)

_SIGNAL_ROLLBACK = "step5_rollback_done.txt"
_OBB_NAME = "obb.bin"          # compared case-insensitively
_ESP_ROOT = "/boot/efi"        # the sudoers rule (setup_sut.sh) is tied to this path
_DMI_DIR = Path("/sys/class/dmi/id")


@pytest.mark.bios_resiliency
@pytest.mark.manual
class TestEC62443BIOSResiliencyRecoverySUTFunc(SUTBaseTest):
    """
    IEC 62443-4-2 BIOS Resiliency / Recovery — SUT-only, Intel RVP only.

    Automatic: RVP check, Obb.bin backup check, power-off, reboot proof,
    Obb.bin after rollback. One manual gate: flash the corrupted IBB and
    confirm the purple rollback box.
    """

    SUITE   = "bios_resiliency"
    TEST_ID = "IEC62443-4-2-TC_BIOS_Resiliency_Recovery-FUNC-SUT"

    REBOOTS = (
        ("manual", "flash the corrupted IBB with Dediprog, power on, watch the PURPLE rollback box, "
                   "boot to Ubuntu, create the signal file (Step 5.0)"),
    )

    PRE_TEST_CHECKLIST = [
        "1.0)  The SUT is an Intel RVP board (the EC performs the resiliency / recovery).",
        "2.0)  The BIOS Resiliency IFWI is flashed and the SUT boots to Ubuntu.",
        "      2.1) During boot a BLUE box showed 'Resiliency backup begin' and 'successful'.",
        "3.0)  The corrupted IBB file was received from the POC",
        "      (to build it yourself, see 'REFERENCE ONLY' in this test's docstring / TEST_GUIDE.md).",
        "4.0)  A Dediprog SPI programmer is connected to the SUT, with its host software ready.",
        "SETUP) sudo ./deploy/setup/setup_sut.sh run on this SUT (resume service + sudoers rule).",
    ]

    def test_ec62443_bios_resiliency_recovery_sut_func(self, request, config, log_dir):
        """
        IEC62443-4-2-TC_BIOS_Resiliency_Recovery-FUNC-SUT

          Step 1.0  : RVP board check (DMI)
          Step 2.0  : Obb.bin present on the ESP (FAIL -> reflash Resiliency IFWI)
          Step 3.1  : Record boot id + BIOS before the flash
          Step 4.0  : Operator 'yes' -> power off
          Step 5.0  : Gate -- flash corrupted IBB, purple rollback box, boot to OS
          Step 6.x  : Reboot proof, BIOS logged, Obb.bin still present
        """
        self._begin()
        cfg = self._load_config(config)
        mgr = self._init_state_dir(cfg)

        pre_test_check(request, self.TEST_ID, self.PRE_TEST_CHECKLIST)

        timeout = int(cfg.get("manual_gate_timeout_secs", 900))
        artifact = log_dir / "obb_check.log"

        state = mgr.get_state()
        phase = state.get("phase", 0)
        logger.info("[State] phase=%s sub=%s", phase, state.get("sub", ""))
        assert phase == 0, (
            f"[State] Unexpected phase={phase}. Expected 0 for this single-phase test.\n"
            "Clean the state files (logs/sut_state) and rerun."
        )

        # Resumed by systemd after the flash + reboot: Steps 1.0-4.0 are done.
        resumed = state.get("sub") == f"gate_{_SIGNAL_ROLLBACK}"

        if not resumed:
            # ==============================================================
            # Step 1.0 — RVP board check
            # ==============================================================
            self._step_check_rvp(cfg, step_label="1.0")

            # ==============================================================
            # Step 2.0 / 3.0 — Obb.bin backup present on the ESP
            # ==============================================================
            obb_before = self._find_obb(cfg, artifact, step_label="2.0")
            assert obb_before, (
                f"[Step 3.0] Obb.bin was not found under {cfg.get('obb_search_root', _ESP_ROOT)} -- "
                "the resiliency backup did not happen.\n"
                "  Reflash the CORRECT BIOS Resiliency IFWI, boot to Ubuntu and check that the BLUE box\n"
                "  'Resiliency backup begin ... successful' is shown during boot (it generates Obb.bin),\n"
                "  then re-run this test.\n"
                f"  Check artifact: {artifact}"
            )
            logger.info("[Step 3.0] [OK] Obb.bin backup present: %s", obb_before)

            # ==============================================================
            # Step 3.1 — Record the state before the flash
            # ==============================================================
            bios_before = bios_knob_checks.bios_identity()
            logger.info("[Step 3.1] Before the flash: BIOS %s (%s), boot id %s",
                        bios_before["version"], bios_before["date"], bios_knob_checks.boot_id())
            self._update_state(bios_before=bios_before, obb_before=obb_before)

            # ==============================================================
            # Step 4.0 — Operator confirms, the test powers off the SUT
            # ==============================================================
            self._step_prompt_poweroff(cfg, log_dir, step_label="4.0")

        # ==================================================================
        # Step 5.0 — Single gate: flash corrupted IBB, purple rollback box
        # ==================================================================
        self._wait_for_manual_signal(
            signal_file=_SIGNAL_ROLLBACK,
            step_label="5.0",
            timeout_secs=timeout,
            requires_reboot=True,
            confirms="PURPLE 'Resiliency rollback (Top Swap enabled)' box shown during boot after the "
                     "corrupted IBB flash; SUT booted back to Ubuntu",
            instructions=[
                "─" * 64,
                "STEP 5.0 — Flash the corrupted IBB, observe the rollback, boot to OS",
                "─" * 64,
                "",
                "  5.1) With the SUT powered OFF, flash the corrupted IBB file",
                "       (from the POC) with the Dediprog device and software.",
                "",
                "  5.2) Power on the SUT and watch the display during boot.",
                "",
                "  5.3) A PURPLE box must show 'Resiliency rollback' (Top Swap enabled).",
                "       The EC rolls back to the backup; the SUT may reboot by itself.",
                "",
                "  5.4) Let the SUT boot to Ubuntu. The test resumes automatically.",
                "",
                "  5.5) Saw the purple box -> create the signal file below.",
                "       No purple box -> write FAIL <what you saw> into it.",
                "─" * 64,
            ],
        )
        logger.info("[Step 6.1] [OK] The SUT booted again after the flash (boot id %s)",
                    bios_knob_checks.boot_id())

        # ==================================================================
        # Step 6.2 — BIOS identity after the rollback (evidence only)
        # ==================================================================
        state = mgr.get_state()
        bios_before = state.get("bios_before") or {}
        bios_after = bios_knob_checks.bios_identity()
        logger.info("[Step 6.2] BIOS before the flash: %s (%s)",
                    bios_before.get("version", "?"), bios_before.get("date", "?"))
        logger.info("[Step 6.2] BIOS after the rollback: %s (%s)",
                    bios_after["version"], bios_after["date"])

        # ==================================================================
        # Step 6.3 — Obb.bin still present after the rollback
        # ==================================================================
        obb_after = self._find_obb(cfg, artifact, step_label="6.3")
        logger.info("[Step 6.3] Obb.bin before: %s", state.get("obb_before", "<not recorded>"))
        logger.info("[Step 6.3] Obb.bin after : %s", obb_after or "<absent>")
        assert obb_after, (
            f"[Step 6.3] Obb.bin is missing from {cfg.get('obb_search_root', _ESP_ROOT)} after the "
            "rollback (it was present before the flash).\n"
            f"  Check artifact: {artifact}"
        )
        logger.info("[Step 6.3] [OK] Obb.bin still present after the rollback")

        # ==================================================================
        # PASS
        # ==================================================================
        mgr.cleanup()
        logger.info(
            "[OK] BIOS Resiliency / Recovery: RVP, Obb.bin backup present before and after, SUT rebooted "
            "after the corrupted IBB flash (boot id); the purple rollback box is operator-confirmed."
        )
        self._end()

    # ------------------------------------------------------------------
    # Step helpers
    # ------------------------------------------------------------------

    def _step_check_rvp(self, cfg: dict, step_label: str) -> None:
        """Fail unless a DMI board_vendor / board_name / product_name matches rvp_board_patterns."""
        prefix = f"[Step {step_label}]"
        dmi = {}
        for name in ("board_vendor", "board_name", "product_name"):
            try:
                dmi[name] = (_DMI_DIR / name).read_text(encoding="utf-8", errors="replace").strip()
            except OSError:
                dmi[name] = ""
            logger.info("%s DMI %-12s: %s", prefix, name, dmi[name] or "<unreadable>")

        patterns = [str(p) for p in (cfg.get("rvp_board_patterns") or []) if str(p).strip()]
        logger.info("%s rvp_board_patterns: %s", prefix, patterns)
        assert patterns, (
            f"{prefix} rvp_board_patterns is empty in config/suites/bios_resiliency_config.yaml -- "
            "set at least one pattern that matches your RVP's DMI board name."
        )
        hits = [(p, name) for p in patterns for name, value in dmi.items()
                if value and re.search(p, value, re.IGNORECASE)]
        assert hits, (
            f"{prefix} This test needs an Intel RVP board (the EC performs the resiliency / recovery).\n"
            f"  DMI: {dmi}\n"
            f"  None matches rvp_board_patterns {patterns}.\n"
            "  On a real RVP, add its board name to rvp_board_patterns in "
            "config/suites/bios_resiliency_config.yaml."
        )
        logger.info("%s [OK] RVP board: pattern %r matched %s", prefix, hits[0][0], hits[0][1])

    def _find_obb(self, cfg: dict, artifact: Path, step_label: str) -> str:
        """
        Return 'path size time' of the first Obb.bin under obb_search_root, or ''.

        Reads the tree directly when it is readable; otherwise (Ubuntu mounts the
        ESP root-only) runs the exact sudo command allowed by setup_sut.sh.
        """
        prefix = f"[Step {step_label}]"
        root = str(cfg.get("obb_search_root", _ESP_ROOT)).rstrip("/") or "/"
        found = []

        if os.access(root, os.R_OK | os.X_OK):
            how = f"os.walk({root})"
            for dirpath, _dirs, files in os.walk(root):
                for name in files:
                    if name.lower() == _OBB_NAME:
                        path = Path(dirpath) / name
                        st = path.stat()
                        mtime = datetime.fromtimestamp(st.st_mtime).strftime("%Y-%m-%d %H:%M")
                        found.append(f"{path} size={st.st_size} mtime={mtime}")
            output = "\n".join(found)
        else:
            assert root == _ESP_ROOT, (
                f"{prefix} {root} is not readable, and the sudo rule only covers {_ESP_ROOT}.\n"
                f"  Set obb_search_root to {_ESP_ROOT} or make {root} readable."
            )
            cmd = ["sudo", "-n", "/usr/bin/find", _ESP_ROOT, "-iname", _OBB_NAME, "-type", "f", "-ls"]
            how = " ".join(cmd)
            logger.info("%s %s is root-only -- running: %s", prefix, root, how)
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            output = (r.stdout + r.stderr).strip()
            assert r.returncode == 0, (
                f"{prefix} Searching {_ESP_ROOT} for Obb.bin failed rc={r.returncode}: {r.stderr.strip()}\n"
                "  The sudoers rule is missing -- run once:  sudo ./deploy/setup/setup_sut.sh"
            )
            for line in r.stdout.splitlines():
                # find -ls: inode blocks perms links owner group size mon day time|year path
                fields = line.split(None, 10)
                if len(fields) == 11:
                    found.append(f"{fields[10]} size={fields[6]} mtime={' '.join(fields[7:10])}")

        logger.info("%s Obb.bin search (%s):\n%s", prefix, how, output or "<no match>")
        with artifact.open("a", encoding="utf-8") as fh:
            fh.write(f"=== {prefix} {datetime.now().isoformat(timespec='seconds')} -- {how}\n"
                     f"{output or '<no match>'}\n")
        if len(found) > 1:
            logger.warning("%s %d Obb.bin files found -- using the first", prefix, len(found))
        return found[0] if found else ""

    def _step_prompt_poweroff(self, cfg: dict, log_dir: Path, step_label: str) -> None:
        """
        Ask the operator 'yes' to power off. On 'yes', start a delayed power-off
        in the background so the Step 5.0 gate saves its resume state first.
        'no' fails the test. No terminal -> the operator powers off by hand.
        """
        prefix = f"[Step {step_label}]"
        delay = int(cfg.get("poweroff_delay_secs", 20))
        for line in (
            "─" * 64,
            f"STEP {step_label} — Power off the SUT for the corrupted IBB flash",
            "─" * 64,
            "  Next: the SUT powers off, you flash the corrupted IBB with Dediprog,",
            "  power on and watch for the PURPLE 'Resiliency rollback' box (Step 5.0).",
            "─" * 64,
        ):
            logger.info("%s %s", prefix, line)
            print(line)

        if not self._terminal_available():
            msg = (f"{prefix} No terminal to ask -- power off the SUT MANUALLY when ready; "
                   "the test waits at Step 5.0 and resumes after the boot.")
            logger.warning(msg)
            print(msg)
            return

        while True:
            answer = _read_from_terminal(
                f"\n{prefix} Type 'yes' when ready to power off the SUT (or 'no' to abort): ")
            logger.info("%s Operator answered: %r", prefix, answer)
            if answer in ("yes", "y"):
                break
            if answer in ("no", "n"):
                pytest.fail(f"{prefix} Aborted by the operator before the power-off.", pytrace=False)

        poweroff_log = log_dir / "poweroff.log"
        script = (f"sleep {delay}; systemctl --no-ask-password poweroff "
                  "|| sudo -n shutdown -h now "
                  "|| echo 'POWER-OFF REFUSED -- power off the SUT manually'")
        logger.info("%s Powering off in %d s: %s (output: %s)", prefix, delay, script, poweroff_log)
        with poweroff_log.open("a", encoding="utf-8") as fh:
            proc = subprocess.Popen(["sh", "-c", script], stdout=fh, stderr=subprocess.STDOUT,
                                    start_new_session=True)
        for line in (
            f"{prefix} The SUT powers off in {delay} s (cancel: kill {proc.pid}).",
            f"{prefix} If it is still on after that, power it off manually (see {poweroff_log}).",
        ):
            logger.info(line)
            print(line)

    @staticmethod
    def _terminal_available() -> bool:
        """True if an interactive terminal can be opened for the prompt."""
        tty_path = "CON" if os.name == "nt" else "/dev/tty"
        try:
            fd = os.open(tty_path, os.O_RDWR)
        except OSError:
            return False
        os.close(fd)
        return True
