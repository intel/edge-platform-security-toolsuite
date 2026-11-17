#!/usr/bin/env python3
# Copyright 2026 Intel Corporation
# SPDX-License-Identifier: Apache-2.0

"""
Interactive Test Runner for BIOS Security Automation Framework

Features:
- Run all tests or select specific test suites
- Re-run only failed tests
- Filter by markers (tme, txt, csme, etc.)
- Generate detailed HTML reports
- Track test history and results
- Pre-flight before every run: the setup checklist, the BIOS knobs
  (deploy/bios_knobs/bios_knobs.yaml) and the Secure Boot state that the
  selected tests need, with the runbooks to set them
"""

import os
import sys

# Force UTF-8 output on Windows so emoji in print() don't crash
# with UnicodeEncodeError on cp1252 terminals.
if sys.stdout.encoding and sys.stdout.encoding.lower() != "utf-8":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if sys.stderr.encoding and sys.stderr.encoding.lower() != "utf-8":
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

import subprocess

# Relaunch under the project venv (../venv or ./venv) so its deps (PyYAML, pytest, ...) work without activation
if not os.environ.get("FW_RUNNER_VENV_RELAUNCHED"):
    _here = os.path.dirname(os.path.abspath(__file__))
    for _venv in (os.path.join(_here, os.pardir, "venv"), os.path.join(_here, "venv")):
        _venv = os.path.realpath(_venv)
        _venv_py = os.path.join(_venv, "Scripts", "python.exe") if os.name == "nt" else os.path.join(_venv, "bin", "python")
        if not os.path.isfile(_venv_py):
            continue
        if os.path.normcase(os.path.realpath(sys.prefix)) != os.path.normcase(_venv):
            os.environ["FW_RUNNER_VENV_RELAUNCHED"] = "1"
            try:
                sys.exit(subprocess.call([_venv_py, os.path.abspath(__file__), *sys.argv[1:]]))
            except KeyboardInterrupt:
                sys.exit(130)
        break

import getpass
import json
import platform
import re
import textwrap
import time
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Optional

import yaml

from core import bios_knob_checks, test_selection
from core.batch_log import format_duration, stitch_batch_log
from core.state_dir import DEFAULT_STATE_DIR


class TestRunner:
    """Main test runner class with interactive menu and test management."""

    # Same folders as SUTBaseTest (core/state_dir.py) and the Linux resume service.
    STATE_DIR = DEFAULT_STATE_DIR
    EFI_MOUNT = Path("/boot/efi")

    # Windows SUT resume state: the batch task (conftest.WIN_RESUME_TASK) plus older per-test tasks.
    WIN_RESUME_TASKS = ("IEC62443_Batch_Resume", "IEC62443_PAVP_Resume", "IEC62443_TME_Resume",
                        "IEC62443_dTPM_Resume", "IEC62443_fTPM_Resume", "IEC62443_MeasuredBoot_Resume")
    WIN_STATE_FILES = ("pavp_state.json", "tme_state.json", "dtpm_state.json", "ftpm_state.json")
    WIN_STATE_SUITES = ("pavp", "tme", "measured_boot")

    CONTEXT_LABELS = {
        "sut_linux": "Linux SUT (sut_linux)",
        "sut_windows": "Windows SUT (sut_windows)",
        "all": "All contexts -- no OS filtering",
    }
    # Same meanings as conftest._EXIT_CODE_TABLE (pytest's own exit codes).
    EXIT_CODE_MEANINGS = {
        0: "all tests PASSED",
        1: "one or more tests FAILED",
        2: "execution interrupted",
        3: "internal pytest / framework error",
        4: "bad CLI / missing config / collection error",
        5: "no tests collected",
    }
    STATUS_ICONS = {"PASSED": "✅", "FAILED": "❌", "INTERRUPTED": "⛔", "IN PROGRESS": "⏸️"}

    # Linux tests that sudo commands setup_sut.sh's exact rules do not cover (MEInfo, /dev/mem reads,
    # checkquote.sh, ...). True: it also does so after its own reboot, where nobody can type a password.
    NEEDS_SUDO_ALL = {
        "tests/csme/test_ec62443_csme_upid_sut_func.py": False,
        "tests/rpmc/test_ec62443_rpmc_sut_func.py": False,
        "tests/secure_debug/test_ec62443_secure_debug_sut_func.py": False,
        "tests/aesni/test_ec62443_aesni_sut_func.py": False,
        "tests/virtualization/test_ec62443_virtualization_vtd_sut_func.py": False,
        "tests/measured_boot/test_ec62443_dtpm_sut_func.py": True,
        "tests/measured_boot/test_ec62443_ftpm_ptt_sut_func.py": True,
        "tests/txt/test_ec62443_txt_sut_func.py": True,
    }

    def __init__(self):
        self.base_dir = Path(__file__).resolve().parent
        self.tests_dir = self.base_dir / "tests"
        self.logs_dir = self.base_dir / "logs"
        self.cache_dir = self.base_dir / ".pytest_cache"
        self.results_file = self.cache_dir / "last_run_results.json"
        # Written by conftest.py in every pytest process, including ones resumed after a reboot.
        self.batch_status_file = self.logs_dir / "batch_status.json"
        self.last_batch_file = self.logs_dir / "last_batch_summary.json"
        self.resume_log = self.logs_dir / "resume_service.log"
        # Pre-flight plan (deploy/preflight/preflight_chain.py): steps left after a reboot + the tests.
        self.plan_file = self.logs_dir / "preflight_plan.json"
        
        self.python = self._find_python()
        self.pytest_cmd = [self.python, "-m", "pytest"]
        self.has_pytest_html = subprocess.run(
            [self.python, "-c", "import pytest_html"], capture_output=True
        ).returncode == 0
        
        # Menu key -> suite. Adding a suite = new tests/<suite>/ folder + its marker line in pytest.ini.
        self.marker_descriptions = test_selection.marker_descriptions()
        self.test_suites = {
            str(i): {
                "name": suite,
                "path": f"tests/{suite}/",
                "description": self.marker_descriptions.get(suite, ""),
            }
            for i, suite in enumerate(test_selection.discover_suites(self.tests_dir), 1)
        }

        # Which machine is test_runner.py running on right now? Drives automatic
        # -m filtering so a suite folder that mixes SUT-Linux and SUT-Windows
        # test files only runs the flavour that matches THIS host.
        # One of: "sut_linux", "sut_windows", "all" (no filtering).
        self.host_context = self._detect_context()

        # file path -> TEST_ID, parsed on demand from source (no importing)
        self._test_id_cache: Dict[str, Optional[str]] = {}
        # Every node id under tests/, collected once on first use (all contexts).
        self._all_nodes: Optional[List[str]] = None
        # (IFWI group marker or None, how it was read) -- read once; only a reflash + reboot changes it.
        self._flashed: Optional[tuple] = None

        # Ensure directories exist
        self.logs_dir.mkdir(exist_ok=True)
        self.cache_dir.mkdir(exist_ok=True)
    
    def _find_python(self) -> str:
        """
        Python interpreter to run pytest with: the project venv (../venv or
        ./venv, POSIX or Windows layout) if present, else this interpreter.
        Plugin checks (pytest-html) must use the same interpreter as the run.
        """
        candidates = [
            self.base_dir.parent / "venv" / "bin" / "python",
            self.base_dir / "venv" / "bin" / "python",
            self.base_dir.parent / "venv" / "Scripts" / "python.exe",
            self.base_dir / "venv" / "Scripts" / "python.exe",
        ]
        for candidate in candidates:
            if candidate.exists():
                return str(candidate)
        return sys.executable

    def _detect_context(self) -> str:
        """
        Best-effort guess at which machine test_runner.py is running on.

        This runner only ever drives tests/ (SUT-local only -- see
        internal_nuc/ for the NUC-driven engineering tests, run directly with
        pytest, not through this menu). So the only real contexts are
        "sut_linux" and "sut_windows"; Linux maps directly, Windows defaults
        to sut_windows too since there's no NUC-driven option left to confuse
        it with. Use the 'O' menu option to override if detection is wrong.
        """
        return test_selection.host_context() or "all"

    def change_context(self):
        """Let the operator override the auto-detected execution context."""
        print("\n🖥️  EXECUTION CONTEXT -- where is test_runner.py running right now?")
        print("=" * 70)
        mapping = {"1": "sut_linux", "2": "sut_windows", "3": "all"}
        for key, context in mapping.items():
            current = "   <- current" if context == self.host_context else ""
            print(f"   {key}        {self.CONTEXT_LABELS[context]}{current}")
        choice = input("\nSelect [1-3], or Enter = no change: ").strip()
        if choice in mapping:
            self.host_context = mapping[choice]
            print(f"   → Context set to: {self.CONTEXT_LABELS[self.host_context]}")
        else:
            print("   → No change.")

    def clear_screen(self):
        """Clear terminal screen."""
        os.system('clear' if os.name != 'nt' else 'cls')
    
    def print_header(self):
        """Print main menu header."""
        self.clear_screen()
        print("=" * 70)
        print("🛡️  BIOS Security Automation - Test Runner".center(70))
        print("=" * 70)
        print(f" 🖥️  Host: {self.CONTEXT_LABELS.get(self.host_context, self.host_context)}  |  "
              f"{len(self._context_nodes())} tests available  |  O = change")
        if test_selection.host_context() in ("sut_linux", "sut_windows"):
            flashed, how = self._flashed_ifwi()
            print(f" 💾 Flashed IFWI: {test_selection.ifwi_short_label(flashed) if flashed else 'unknown'}  ({how})")
        print("=" * 70)
        progress = self._batch_progress()
        if progress:
            done, total = progress
            print(f" ⏸️  BATCH PAUSED FOR REBOOT -- {done}/{total} done. Remaining tests resume automatically.")
            if self.resume_log.exists():
                print(f"     Live progress: {self.resume_log}")
        resume_files = self._pending_resume_files()
        resume_tasks = self._win_resume_tasks()
        if resume_files or resume_tasks:
            pending = resume_tasks + [str(p) for p in resume_files]
            print(f" ⚠️  Next boot will auto-resume queued tests ({', '.join(pending)}).")
        if progress or resume_files or resume_tasks:
            print("     Not expected (run aborted/killed)? Press X to clear.")
            print("=" * 70)
        provisioning = self._provisioning_notes()
        for note in provisioning:
            print(f" {'❌' if note.startswith('Pre-flight stopped') else '⏳'} {note}")
        if provisioning:
            print("=" * 70)
        print()

    @staticmethod
    def _read_json(path: Path) -> Optional[Dict]:
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None

    def _batch_progress(self) -> Optional[tuple]:
        """(done, total) if conftest's batch manifest still has PENDING/REBOOTING tests, else None."""
        batch = self._read_json(self.batch_status_file) or {}
        results = batch.get("results") or {}
        pending = [s for s in results.values() if s in ("PENDING", "REBOOTING")]
        if not pending:
            return None
        return len(results) - len(pending), len(results)

    def _pending_resume_files(self) -> List[Path]:
        """Files that make an unfinished run resume/continue on the next boot (Linux state folder/EFI or Windows queue + phase state)."""
        if self.host_context == "sut_windows":
            files = [self.logs_dir / "win_resume_args.txt"]
            files += [d / name for d in self._win_state_dirs() for name in self.WIN_STATE_FILES]
            return [p for p in files if p.exists()]
        if self.host_context != "sut_linux":
            return []
        return [p for p in (self.STATE_DIR / "next_test.txt", self.STATE_DIR / "state_done.txt",
                            self.EFI_MOUNT / "state_done.txt") if p.exists()]

    def _win_state_dirs(self) -> List[Path]:
        """win_state_dir from each Windows phase-based suite config (default: the state folder)."""
        dirs = []
        for suite in self.WIN_STATE_SUITES:
            value = None
            try:
                cfg_path = self.base_dir / "config" / "suites" / f"{suite}_config.yaml"
                value = (yaml.safe_load(cfg_path.read_text(encoding="utf-8")) or {}).get("win_state_dir")
            except (OSError, yaml.YAMLError):
                pass
            path = Path(value) if value else self.STATE_DIR
            if path not in dirs:
                dirs.append(path)
        return dirs

    def _win_resume_tasks(self) -> List[str]:
        """IEC62443 resume tasks currently registered in Task Scheduler (Windows SUT only)."""
        if self.host_context != "sut_windows":
            return []
        registered = self._registered_win_tasks()
        return [t for t in self.WIN_RESUME_TASKS if t in registered]

    @staticmethod
    def _registered_win_tasks() -> set:
        """Names of the root Task Scheduler tasks, or an empty set if schtasks is unavailable."""
        try:
            out = subprocess.run(["schtasks", "/query", "/fo", "csv", "/nh"],
                                 capture_output=True, text=True, timeout=30).stdout
        except (OSError, subprocess.SubprocessError):
            return set()
        return {line.split(",", 1)[0].strip('"').lstrip("\\") for line in out.splitlines()}

    def clear_run_state(self):
        """Delete leftover batch/resume state from an aborted run, after confirmation."""
        state_files = [self.STATE_DIR / name for name in
                       ("next_test.txt", "state_done.txt", "state.json")]
        efi_files = [self.EFI_MOUNT / name for name in ("state_done.txt", "maintest.nsh")]
        win_files = self._pending_resume_files() if self.host_context == "sut_windows" else []
        targets = [p for p in [self.batch_status_file, self.plan_file, *state_files, *efi_files, *win_files]
                   if p.exists()]
        tasks = self._win_resume_tasks()
        print("\n🧹 CLEAR LEFTOVER RUN STATE")
        print("=" * 70)
        if not targets and not tasks:
            print("   → Nothing to clear.")
            return

        print("These files make an unfinished run continue (batch tracking / auto-resume on next boot):")
        for path in targets:
            print(f"  - {path}")
        for task in tasks:
            print(f"  - Task Scheduler task: {task}")
        print("Delete them ONLY if no test is running and you do not want that run to resume.")
        print("Test logs in logs/ are kept.")
        if input("Type CLEAR to delete them: ").strip() != "CLEAR":
            print("   → Nothing deleted.")
            return

        for path in targets:
            try:
                if path.parent == self.EFI_MOUNT:
                    # EFI partition is root-owned; same sudo rm as UEFIScriptManager uses.
                    subprocess.run(["sudo", "-n", "rm", "-f", str(path)], capture_output=True, timeout=10)
                else:
                    path.unlink()
            except (OSError, subprocess.SubprocessError):
                pass
            if path.exists():
                hint = f"Remove-Item -Force {path}" if os.name == "nt" else f"sudo rm -f {path}"
                print(f"  ⚠️  Could not delete {path} -- run: {hint}")
            else:
                print(f"  ✅ Deleted {path}")

        if self.plan_file in targets and platform.system() in ("Linux", "Windows"):
            # Without a plan the pre-flight resume unit/task does nothing, but remove it too.
            self._disarm_chain(self._chain())

        for task in tasks:
            result = subprocess.run(["schtasks", "/delete", "/tn", task, "/f"],
                                    capture_output=True, text=True, timeout=15)
            if result.returncode == 0:
                print(f"  ✅ Deleted Task Scheduler task {task}")
            else:
                print(f"  ⚠️  Could not delete task {task} -- run as Administrator: schtasks /delete /tn {task} /f")
    
    def print_menu(self):
        """Display main menu options."""
        self.print_header()

        available = self._available_suites()
        available_names = {suite["name"] for suite, _ in available}
        unavailable = [s["name"] for s in self.test_suites.values() if s["name"] not in available_names]

        print("📋 TEST SUITES")
        if available:
            rows = []
            for i, (suite, nodes) in enumerate(available, 1):
                ifwi = sorted({test_selection.ifwi_label(nid) for nid in nodes})
                description = re.sub(r"\s+tests\b", "", suite["description"])
                rows.append((str(i), suite["name"], str(len(nodes)), ", ".join(ifwi), description))
            self._print_simple_table(("#", "Suite", "Tests", "IFWI", "Description"), rows)
            if any("/" in row[3] for row in rows):
                print(" SEP5/SED5 = runs on either IFWI. 'only' = needs that IFWI flashed.")
        else:
            print(f"   (no suites have tests for {self.host_context})")
        if unavailable:
            print("\n".join(textwrap.wrap(
                ", ".join(unavailable), 70,
                initial_indent=f" Not available on {self.host_context}: ",
                subsequent_indent=" " * len(f" Not available on {self.host_context}: "),
            )))
        print()

        print("🚀 RUN")
        if available:
            print(f"   {'1-' + str(len(available)):<8} Run one suite (e.g. 1) or several (e.g. 1,3,5)")
        print(f"   {'I':<8} Run a whole IFWI group (every test on one flashed image)")
        print(f"   {'M':<8} Run by pytest marker expression")
        print(f"   {'F':<8} Re-run FAILED tests from the last run")
        print(f"   {'R':<8} Repeat the last run")
        print()

        print("📊 RESULTS")
        print(f"   {'L':<8} Last run results")
        print(f"   {'H':<8} Run history")
        print()

        print("⚙️  SETTINGS")
        print(f"   {'O':<8} Change execution context")
        print(f"   {'P':<8} SUT readiness -- BIOS knobs / Secure Boot status")
        if (self._batch_progress() or self._pending_resume_files() or self._win_resume_tasks()
                or self.plan_file.exists()):
            print(f"   {'X':<8} Clear leftover run state (unfinished batch / pending auto-resume)")
        print()

        print(f"👋 {'Q':<8} Quit")
        print("=" * 70)
        print()
    
    def _ask_failfast_flag(self) -> Optional[List[str]]:
        """
        Ask whether the run should stop at the first failure.

        By default (and today, unconditionally) pytest runs every collected
        test to completion regardless of earlier failures -- there is no
        -x / --maxfail in pytest.ini or here. This prompt makes that an
        explicit, per-run choice instead of a silent default.

        Returns None if the operator typed 'B' to go back a step.
        """
        answer = input(f" {'Stop at the first failure?':<62}[y/N, B=back]: ").strip().lower()
        if answer == "b":
            return None
        if answer in ("y", "yes"):
            print("   → Running with -x (stops at first failure).")
            return ["-x"]
        print("   → Running ALL selected tests to completion, even if some fail.")
        return []

    # ------------------------------------------------------------------
    # Pre-flight (before every run): BIOS knobs + Secure Boot
    # ------------------------------------------------------------------
    # The runner works out what the selected tests need, shows the plan, and
    # then does it:
    #   - Secure Boot: deploy/secure_boot/enable_secure_boot*.{sh,ps1} auto
    #   - BIOS knobs:  AMI BIOS -> AMISCE runbook (deploy/bios_knobs/);
    #                  other BIOS -> printed with their menu paths, then Y/S/B
    #                  (Y = reboot straight into BIOS Setup).
    # Steps that reboot the SUT hand over to deploy/preflight/preflight_chain.py
    # (plan in logs/preflight_plan.json), which runs the remaining steps after
    # each reboot and then starts the tests. A person is only needed for the
    # MOK password, the y/n before the MOK reboot and the blue MOK Manager
    # screen (Linux, first time), and for Y/S/B + BIOS Setup on a non-AMI BIOS.
    # Automatic plans start at once, with no countdown.
    # _preflight returns "ok" (run the tests now, in this process), "back" (to
    # the test list) or "stop" (handed over to the chain, or stopped).

    def _chain(self):
        """deploy/preflight/preflight_chain.py, imported on demand (standard library only)."""
        chain_dir = str(self.base_dir / "deploy" / "preflight")
        if chain_dir not in sys.path:
            sys.path.insert(0, chain_dir)
        import preflight_chain
        return preflight_chain

    def _rel(self, path: Path) -> str:
        """Path relative to the repo for messages; the full path if it is elsewhere."""
        try:
            return str(Path(path).relative_to(self.base_dir))
        except ValueError:
            return str(path)

    def _knob_lib(self):
        """deploy/bios_knobs/bios_knob_common.py, imported on demand (same knob rules as the runbooks)."""
        deploy_dir = str(self.base_dir / "deploy" / "bios_knobs")
        if deploy_dir not in sys.path:
            sys.path.insert(0, deploy_dir)
        import bios_knob_common
        return bios_knob_common

    def _amisce_override(self) -> str:
        """bios.amisce in config/test_config.yaml: auto (default), yes or no."""
        try:
            cfg = yaml.safe_load((self.base_dir / "config" / "test_config.yaml").read_text(encoding="utf-8")) or {}
        except (OSError, yaml.YAMLError):
            return "auto"
        bios = cfg.get("bios") if isinstance(cfg, dict) else None
        return str((bios or {}).get("amisce", "auto"))

    def _preflight(self, node_ids: List[str], report_name: str = "test_report") -> str:
        """Make the SUT ready for the selected tests (BIOS knobs, Secure Boot)."""
        print()
        print("=" * 70)
        print(f"🔧 PRE-FLIGHT -- what the {len(node_ids)} selected test(s) need")
        print("=" * 70)
        if platform.system() not in ("Linux", "Windows"):
            print("⚠️  Pre-flight runs on the Linux/Windows SUT only -- skipped on this host.")
            return "ok"
        chain = self._chain()
        busy = self._preflight_busy(chain)
        if busy:
            for note in busy:
                print(f" ⏳ {note}")
            print("   Wait until it has finished (the SUT reboots by itself), or press X in the menu to stop it.")
            return "stop"
        if platform.system() == "Linux" and self._ask_passwordless_sudo(node_ids) == "back":
            return "back"
        self._drop_old_plan(chain)

        needs = self._work_out_needs(chain, node_ids)
        if isinstance(needs, str):
            return needs
        self._print_plan(chain, needs, len(node_ids))
        if not needs["steps"]:
            print("   ✅ Nothing to change -- the SUT is ready.")
            return "ok"
        if self._ask_bios_password(needs) == "back":
            return "back"
        if "bios_setup" in needs["steps"]:
            # Knobs set by hand: the person decides, no countdown into a BIOS Setup reboot.
            choice = self._ask_bios_setup(needs["checks"])
            if choice == "back":
                return "back"
            if choice == "skip":
                needs["steps"].remove("bios_setup")
                unread = {r.question: r.expected for r in needs["checks"] if r.ok is None}
                bios_knob_checks.record_attested(unread, "operator answered Skip ('already set') in test_runner.py")
                print("   → BIOS knobs: skipped on your word. Knobs the tests cannot read back count as confirmed by you.")
                if not needs["steps"]:
                    print("   ✅ Nothing else to change -- running the tests now.")
                    return "ok"
        return self._carry_out(chain, needs, node_ids, report_name)

    def _ask_passwordless_sudo(self, node_ids: List[str]) -> str:
        """Selected tests that sudo uncovered commands: offer passwordless sudo for all commands. 'ok' or 'back'."""
        needing = sorted({nid.split("::", 1)[0] for nid in node_ids} & self.NEEDS_SUDO_ALL.keys())
        # -k: a password typed a few minutes ago must not count -- it is gone after the tests' reboot.
        if not needing or subprocess.run(["sudo", "-k", "-n", "true"], capture_output=True, timeout=15).returncode == 0:
            return "ok"
        print()
        print(f"   🔑 Passwordless sudo: {len(needing)} of the selected tests run commands with sudo that the setup's")
        print("      exact rules do not cover, so they would stop and ask for your password:")
        for path in needing:
            print(f"        {path}" + ("   (fails after its reboot)" if self.NEEDS_SUDO_ALL[path] else ""))
        print("     Y  Yes      -- allow passwordless sudo for all commands now (test boards only, see SECURITY.md);")
        print("                    you type your password once")
        print("     C  Continue -- run anyway and type the password when a test asks")
        print("     B  Back     -- back to the test list")
        while True:
            try:
                answer = input(" Your choice [Y/C/B]: ").strip().lower()
            except KeyboardInterrupt:
                print()
                return "back"
            if answer in ("b", "back"):
                return "back"
            if answer in ("c", "continue"):
                after_reboot = [Path(p).stem for p in needing if self.NEEDS_SUDO_ALL[p]]
                print("   → Continuing." + (f" These stop after their reboot: {', '.join(after_reboot)}" if after_reboot else ""))
                return "ok"
            if answer in ("y", "yes"):
                break
        setup = self.base_dir / "deploy" / "setup" / "setup_sut.sh"
        rc = subprocess.run(["sudo", "bash", str(setup), "--add-nopasswd-all"], cwd=self.base_dir).returncode
        if rc != 0:
            print(f"   → Not enabled (setup_sut.sh exit {rc}). Back to the test list.")
            return "back"
        print("   → Passwordless sudo enabled -- the tests will not ask for a password.")
        return "ok"

    def _ask_bios_password(self, needs: Dict) -> str:
        """
        AMI BIOS on Linux, AMISCE will import: make sure the BIOS admin password (/cpwd) is available.
        Asked once per SUT: the runbook stores it encrypted (bios_password.py). Returns 'ok' or 'back';
        may add a 'bios_admin_setup' step (reboot into BIOS Setup to set a new one).
        """
        status = needs.get("password")
        if not status or status["state"] in ("ok", "provided", "unknown"):
            return "ok"
        state = status["state"]
        can_type = state in ("missing", "changed")          # the BIOS has one: type it here
        print()
        print(f"   🔑 BIOS admin password: {status['message']}.")
        print("      AMISCE changes knobs in protected BIOS variables (CPU Configuration: VMX, TME, TXT, ...)")
        print("      only with it. You enter it once; it is stored encrypted on this SUT, not in a config file.")
        if can_type:
            print("     P  Provide -- type the BIOS admin password now (not shown)")
        else:
            print("     S  Set up  -- choose one now; the SUT then reboots into BIOS Setup, where you type it once more")
            print("                   (Security -> Administrator Password), Save & Exit -- the rest runs by itself")
        print("     C  Continue without -- only knobs outside protected variables can change")
        print("     B  Back -- back to the test list")
        key = "p" if can_type else "s"
        while True:
            try:
                answer = input(f" Your choice [{key.upper()}/C/B]: ").strip().lower()
            except KeyboardInterrupt:
                print()
                return "back"
            if answer in ("b", "back"):
                return "back"
            if answer in ("c", "continue"):
                print("   → Continuing without the BIOS admin password.")
                return "ok"
            if answer == key:
                break
        script = self.base_dir / "deploy" / "bios_knobs" / "configure_bios_knobs_linux.py"
        args = ["password", "--set"] + ([] if can_type else ["--new"])
        print()
        if subprocess.run(["sudo", self.python, str(script), *args], cwd=self.base_dir).returncode != 0:
            print("   → No password stored.")
            return "back"
        if not can_type:
            steps = needs["steps"]
            steps.insert(steps.index("bios_knobs"), "bios_admin_setup")
            when = "after Secure Boot is enabled" if "secure_boot" in steps else "next"
            print(f"   → Plan: the SUT reboots into BIOS Setup {when}; type the same password under")
            print("     Security -> Administrator Password, Save & Exit (F4). The pre-flight then checks it and")
            print("     sets the BIOS knobs with AMISCE by itself.")
        return "ok"

    @staticmethod
    def _ask_bios_setup(checks: List) -> str:
        """'yes' (reboot into BIOS Setup), 'skip' (knobs already set) or 'back'."""
        wrong = [r for r in checks if r.ok is False]
        print()
        print("   The BIOS knobs above must be set by hand in BIOS Setup:")
        print("     Y  Yes  -- reboot into BIOS Setup now; set them, Save & Exit (F4); the pre-flight")
        print("               reads them back after the boot, then the selected tests start by themselves")
        if wrong:
            print("     S  Skip -- not possible: the OS reads some of them as wrong (see 'now' above)")
        else:
            print("     S  Skip -- they are already set; continue without the BIOS Setup reboot")
        print("     B  Back -- back to the test list")
        choices = {"y": "yes", "yes": "yes", "s": "skip", "skip": "skip", "b": "back", "back": "back"}
        while True:
            try:
                answer = input(" Your choice [Y/S/B]: ").strip().lower()
            except KeyboardInterrupt:
                print()
                return "back"
            choice = choices.get(answer)
            if choice == "skip" and wrong:
                print("   ❌ Cannot skip -- these knobs are not set:")
                for line in bios_knob_checks.format_results(wrong, indent="      "):
                    print(line)
                continue
            if choice:
                return choice

    def _preflight_busy(self, chain) -> List[str]:
        """Runbooks / a plan that are still going, so a new pre-flight must not start."""
        notes = []
        plan = chain.load_plan()
        if plan and plan.get("status") == "running":
            notes.extend(self._plan_notes(chain, plan))
        busy = chain.runbook_in_progress()
        if busy and not notes:
            notes.append(f"{busy} is in progress -- it continues by itself after each reboot.")
        return notes

    def _drop_old_plan(self, chain) -> None:
        """A failed/finished plan from an earlier run is out of date once tests are picked again."""
        plan = chain.load_plan()
        if plan and plan.get("status") != "running":
            try:
                self.plan_file.unlink()
            except OSError:
                pass

    def _work_out_needs(self, chain, node_ids: List[str]):
        """What the selected tests need from the SUT, or "back"/"stop" when they cannot run as picked."""
        notes: List[str] = []
        specs = sorted({spec for spec in map(test_selection.bios_knob_spec, node_ids) if spec})
        mid_test = sorted({test_selection.suite_of(nid) for nid in node_ids
                           if test_selection.suite_of(nid) in test_selection.KNOBS_SET_MID_TEST})
        if mid_test:
            notes.append(f"{', '.join(mid_test)} sets its own BIOS knobs at manual steps during the test")

        knobs: Dict[str, str] = {}
        verify: Dict[str, str] = {}
        lib = None
        if specs:
            try:
                lib = self._knob_lib()
                profile, _label = lib.resolve_markers(lib.DEFAULT_CONFIG, specs)
            except Exception as exc:  # RunbookError (e.g. PTT + dTPM picked together), or PyYAML missing
                print(f"❌ {exc}")
                return "back"
            if profile:
                knobs = dict(profile["knobs"])
                verify = dict(profile["verify_knobs"])

        # A knob for a CPU feature this CPU lacks (e.g. TME on non-vPro) has no effect when set:
        # leave it out of AMISCE / BIOS Setup; the tests that need it fail with this reason.
        for question, why in bios_knob_checks.unsupported_knobs(knobs).items():
            notes.append(f'"{question}" = {knobs.pop(question)} skipped -- {why}. Setting it in the BIOS has '
                         "no effect; tests that need it fail with this reason, the others run as usual")

        # Knobs the OS already reads as set need neither AMISCE nor a BIOS Setup trip.
        checks = bios_knob_checks.check_knobs({**knobs, **verify})
        already = [r for r in checks if r.ok is True]
        if already:
            notes.append("already set (read from the OS):" + "".join(
                f'\n                   "{r.question}" = {r.expected}   ({r.actual})' for r in already))
            for r in already:
                knobs.pop(r.question, None)
                verify.pop(r.question, None)
        for r in checks:
            if r.ok is False and r.question in verify:
                ifwi = "RPSF_SEP5 (PTT)" if r.expected.lower() == "ptt" else "RPSF_SED5 (dTPM)"
                print(f'❌ "{r.question}" is not {r.expected} on this SUT ({r.actual}). It is fixed by the flashed IFWI:')
                print(f"   flash the {ifwi} IFWI first, or pick tests for the TPM this SUT has.")
                return "stop"
        checks = [r for r in checks if r.ok is not True]

        ami, ami_reason = chain.detect_ami(self._amisce_override())
        wanted = {**knobs, **verify}
        if wanted and ami:
            cached, why = chain.knob_cache_status(wanted)
            if cached:
                notes.append(f"BIOS knobs already set ({why})")
                knobs, verify, wanted = {}, {}, {}
            elif chain.KNOB_LAST_PASS_FILE.exists():
                notes.append(f"last AMISCE PASS not reused: {why}")

        sb_needed = [nid for nid in node_ids if test_selection.requires_secure_boot(nid)]
        sb_state = chain.secure_boot_state()
        sb_ready, sb_why = chain.secure_boot_ready()
        steps = []
        if wanted and not ami:
            steps.append("bios_setup")
        if sb_needed and not sb_ready:
            steps.append("secure_boot")
        if wanted and ami:
            steps.append("bios_knobs")
        password = None
        if "bios_knobs" in steps and platform.system() == "Linux":
            lib = lib or self._knob_lib()
            password = lib.admin_password_status()
        return {
            "steps": steps, "markers": specs, "knobs": knobs, "verify": verify, "notes": notes,
            "checks": checks if wanted else [],
            "ami": ami, "ami_reason": ami_reason, "sb_needed": sb_needed, "sb_state": sb_state,
            "sb_why": sb_why, "sb_owner": chain.secure_boot_key_owner(), "password": password,
            "menu_paths": lib.load_menu_paths() if (lib and "bios_setup" in steps) else {},
        }

    def _print_plan(self, chain, needs: Dict, test_count: int) -> None:
        sb_text = {True: "ENABLED", False: "DISABLED", None: "unknown"}[needs["sb_state"]]
        print(f"   BIOS        : {'AMI (AMISCE can set knobs)' if needs['ami'] else 'not AMI'} -- {needs['ami_reason']}")
        sb_use = f"needed by {len(needs['sb_needed'])} test(s)" if needs["sb_needed"] else "not needed"
        print(f"   Secure Boot : {sb_text} -- {sb_use}")
        if needs["sb_owner"]:
            print(f"   SB keys     : {needs['sb_owner']} -- {needs['sb_why']}")
        for note in needs["notes"]:
            print(f"   Note        : {note}")
        if not needs["steps"]:
            return
        print()
        print("   Plan:")
        n = 0
        for step in needs["steps"]:
            n += 1
            if step == "bios_setup":
                print(f"    {n}. Set these BIOS knobs by hand in BIOS Setup (Y below reboots into it),")
                print("       then Save & Exit (F4):")
                self._print_manual_knobs(needs)
            elif step == "secure_boot":
                print(f"    {n}. Enable Secure Boot with our own keys (deploy/secure_boot/, several reboots, runs by itself).")
                if platform.system() == "Linux":
                    if needs["sb_owner"] == "foreign":
                        print("       ⚠ The firmware holds factory keys. Software cannot delete them, so the SUT reboots")
                        print("         into BIOS Setup (after a y/n): Security -> Secure Boot -> Key Management ->")
                        print("         Delete all keys, Save & Exit. Everything after that runs by itself.")
                    print("       First time on this SUT: you type a one-time MOK password now, and at the next")
                    print("       reboot choose Enroll MOK -> Continue -> Yes -> password -> Reboot on the blue screen.")
            elif step == "bios_knobs":
                knobs = ", ".join(f'"{q}" = {o}' for q, o in {**needs["knobs"], **needs["verify"]}.items())
                reboots = "no reboot if nothing changes" if platform.system() == "Windows" else "UEFI Shell reboots"
                print(f"    {n}. Set BIOS knobs with AMISCE ({reboots}): {knobs}")
                password = needs.get("password")
                if password:
                    print(f"       BIOS admin password (/cpwd): {password['message']}")
        n += 1
        print(f"    {n}. Run the {test_count} test(s) -- they start by themselves when the steps above are done.")
        print(f"   Progress: {self._rel(chain.LOG_FILE)}  (menu P shows the state)")

    def _print_manual_knobs(self, needs: Dict) -> None:
        paths = needs.get("menu_paths") or {}
        now = {r.question.lower(): r for r in needs.get("checks") or []}

        def state(question: str) -> str:
            r = now.get(question.lower())
            if r is None:
                return ""
            if r.ok is False:
                return f"now: NOT set ({r.actual})"
            return "now: cannot be read on this BIOS -- counts as confirmed by you"

        for question, option in needs["knobs"].items():
            print(f'         - "{question}" = {option}    {state(question)}')
            print(f"             F2 → {paths.get(question.lower(), '(menu path not recorded -- search BIOS Setup for the name)')}")
        for question, option in needs["verify"].items():
            print(f'         - "{question}" must show {option} (fixed by the flashed IFWI; if not, flash the matching IFWI)')
            print(f"             F2 → {paths.get(question.lower(), '(menu path not recorded)')}")
        if any(q.lower() == "total memory encryption" for q in needs["knobs"]):
            print("         TME can only be set when VT-d is Enabled; VT-d is greyed out while X2APIC is Enabled.")

    def _carry_out(self, chain, needs: Dict, node_ids: List[str], report_name: str) -> str:
        """Do the planned steps that belong to this boot; hand the rest over to the chain."""
        system = platform.system()
        report_file = self.logs_dir / f"{report_name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        pytest_args = ["--tb=short"]
        if self.has_pytest_html:
            pytest_args += [f"--html={report_file}", "--self-contained-html"]
        steps = []
        for name in needs["steps"]:
            if name == "bios_knobs":
                steps.append({"name": name, "markers": needs["markers"]})
            elif name == "bios_setup":
                # Read back by preflight_chain.verify_bios_setup() after the BIOS Setup reboot.
                steps.append({"name": name, "knobs": {**needs["knobs"], **needs["verify"]}})
            else:
                steps.append({"name": name})
        plan = chain.new_plan(node_ids, self.python, pytest_args, steps + [{"name": "tests"}], getpass.getuser())
        chain.save_plan(plan)
        chain.log(f"Pre-flight started for {len(node_ids)} test(s): {', '.join(needs['steps'])}")

        reboot_kind = None
        mok_pending = False
        sb_bios = ""
        if "bios_setup" in needs["steps"]:
            reboot_kind = "firmware"
        password_first = "bios_admin_setup" in needs["steps"] and "secure_boot" not in needs["steps"]
        if password_first:
            # BIOS Setup now; after the boot the chain checks the password, then runs AMISCE.
            # (With Secure Boot in the plan, the chain does this BIOS Setup trip after Secure Boot.)
            self._set_step(chain, "bios_admin_setup", "running")
            reboot_kind = "firmware"

        if "secure_boot" in needs["steps"]:
            if system == "Linux":
                # Runs 'sign' (MOK password) or 'modules' now; every reboot is left to us.
                self._set_step(chain, "secure_boot", "running")
                script = self.base_dir / "deploy" / "secure_boot" / "enable_secure_boot.sh"
                print(f"\n   Running: sudo bash {script.relative_to(self.base_dir)} auto --no-reboot\n")
                rc = subprocess.run(["sudo", "bash", str(script), "auto", "--no-reboot"], cwd=self.base_dir).returncode
                if rc != 0 or self._plan_failed(chain):
                    return self._preflight_stopped(chain, f"Secure Boot runbook exited with code {rc}")
                mok_pending = self._take_mok_pending_flag()
                if self._take_flag("secure_boot_key_reset_pending"):
                    sb_bios = "keys"
                    reboot_kind = "firmware"
                elif self._take_flag("secure_boot_enable_pending"):
                    sb_bios = "enable"
                    reboot_kind = "firmware"
                reboot_kind = reboot_kind or "normal"
            elif reboot_kind is None:
                # Windows: 'provision' reboots by itself; its boot task reports to the chain.
                self._set_step(chain, "secure_boot", "running")
                if not self._arm_chain(chain):
                    return self._preflight_stopped(chain, "could not install the pre-flight boot task")
                script = self.base_dir / "deploy" / "secure_boot" / "enable_secure_boot_windows.ps1"
                print(f"\n   Running (as Administrator): {script.relative_to(self.base_dir)} auto -RebootDelay 0")
                command = (f"& '{script}' auto -RebootDelay 0; $rc = $LASTEXITCODE; "
                           "Read-Host 'Press Enter to close this window'; exit $rc")
                rc = self._run_as_admin("powershell.exe", ["-NoProfile", "-ExecutionPolicy", "Bypass",
                                                           "-Command", command])
                if rc != 0 and not self._plan_failed(chain) and chain.runbook_in_progress():
                    # The provision reboot closed the runbook's window; its boot task carries on.
                    return self._handed_over(chain)
                if rc != 0 or self._plan_failed(chain):
                    return self._preflight_stopped(chain, f"Secure Boot runbook exited with code {rc}")
                return self._handed_over(chain)
            # Windows + BIOS Setup reboot: the chain enables Secure Boot after that boot.

        if "bios_knobs" in needs["steps"] and "secure_boot" not in needs["steps"] and not password_first:
            # (With Secure Boot in the plan, the chain runs AMISCE after Secure Boot is verified.)
            self._set_step(chain, "bios_knobs", "running")
            if not self._arm_chain(chain):
                return self._preflight_stopped(chain, "could not install the pre-flight resume unit/task")
            runbook_args = [arg for spec in needs["markers"] for arg in ("--marker", spec)]
            # The plan was just shown: reboot at once instead of the runbook's own countdown.
            runbook_args += ["--reboot-delay", "0"]
            if system == "Linux":
                script = self.base_dir / "deploy" / "bios_knobs" / "configure_bios_knobs_linux.py"
                print(f"\n   Running: sudo {self.python} {script.relative_to(self.base_dir)} {' '.join(runbook_args)}\n")
                rc = subprocess.run(["sudo", self.python, str(script), *runbook_args], cwd=self.base_dir).returncode
            else:
                script = self.base_dir / "deploy" / "bios_knobs" / "configure_bios_knobs_windows.py"
                print(f"\n   Running (as Administrator): {self.python} {script.relative_to(self.base_dir)} {' '.join(runbook_args)}")
                rc = self._run_as_admin(self.python, [str(script), *runbook_args, "--pause"])
            step = self._plan_step(chain, "bios_knobs")
            if (system == "Windows" and rc != 0 and not self._plan_failed(chain)
                    and step and step["status"] == "running" and chain.runbook_in_progress()):
                # The runbook's reboot closed its window; its boot task carries on.
                return self._handed_over(chain)
            if self._plan_failed(chain) or (rc != 0 and step and step["status"] == "running"):
                return self._preflight_stopped(chain, f"BIOS knob runbook exited with code {rc}")
            if not step or step["status"] != "done":
                return self._handed_over(chain)
            # Done without a reboot (Windows: nothing to change): carry on here.
            self._disarm_chain(chain)

        if reboot_kind:
            if not self._arm_chain(chain):
                return self._preflight_stopped(chain, "could not install the pre-flight resume unit/task")
            if not self._reboot(reboot_kind, mok_pending, sb_bios) and sb_bios:
                # Answered 'n' to the BIOS Setup reboot: drop everything waiting for it, so picking
                # the tests again simply asks again (nothing is left 'in progress').
                return self._cancel_sb_bios_trip(chain)
            if password_first and self._plan_step(chain, "bios_admin_setup")["status"] == "cancelled":
                return self._cancel_password_trip(chain)
            return self._handed_over(chain)

        plan = chain.load_plan()
        if plan:
            chain.close_plan(plan, "done")
        print("   ✅ SUT ready.")
        return "ok"

    def _cancel_password_trip(self, chain) -> str:
        """The user declined the BIOS Setup reboot for the admin password: cancel the plan, back to the list."""
        plan = chain.load_plan()
        if plan:
            chain.close_plan(plan, "cancelled")
        self._disarm_chain(chain)
        print("   → Not rebooted; the pre-flight is cancelled. Pick the tests again when you are at the SUT")
        print("     and choose S again (you choose the password again, then the SUT reboots into BIOS Setup).")
        return "back"

    def _cancel_sb_bios_trip(self, chain) -> str:
        """Undo a pre-flight that waits for a BIOS Setup reboot the user declined; back to the test list."""
        script = self.base_dir / "deploy" / "secure_boot" / "enable_secure_boot.sh"
        subprocess.run(["sudo", "bash", str(script), "cancel"], cwd=self.base_dir, capture_output=True)
        plan = chain.load_plan()
        if plan:
            chain.close_plan(plan, "cancelled")
        self._disarm_chain(chain)
        print("   → Not rebooted; the pre-flight is cancelled (keys and signed tools stay as they are).")
        print("     Pick the tests again whenever you are at the SUT -- it asks y/n again.")
        return "back"

    def _plan_step(self, chain, name: str) -> Optional[Dict]:
        plan = chain.load_plan()
        return chain.find_step(plan, name) if plan else None

    def _set_step(self, chain, name: str, status: str) -> None:
        plan = chain.load_plan()
        step = chain.find_step(plan, name) if plan else None
        if step:
            step["status"] = status
            chain.save_plan(plan)

    def _plan_failed(self, chain) -> bool:
        plan = chain.load_plan()
        return bool(plan) and plan.get("status") == "failed"

    def _preflight_stopped(self, chain, reason: str) -> str:
        plan = chain.load_plan()
        if plan and plan.get("status") == "running":
            chain.fail_plan(plan, reason)
            plan = chain.load_plan()
        print(f"\n❌ Pre-flight stopped: {(plan or {}).get('error') or reason}")
        print(f"   Details: {self._rel(chain.LOG_FILE)}. Fix it, then pick the tests again.")
        return "stop"

    def _handed_over(self, chain) -> str:
        print()
        print("   ⏳ The SUT continues the pre-flight by itself after each reboot, then starts the tests.")
        print(f"      Progress: {self._rel(chain.LOG_FILE)}; test output: "
              f"{self.resume_log.relative_to(self.base_dir) if platform.system() == 'Linux' else 'the status window (opens when an administrator signs in; no sign-in is needed to continue)'}.")
        print("      Results afterwards: test_runner.py -> L.")
        return "stop"

    def _arm_chain(self, chain) -> bool:
        """Install the chain's resume unit (Linux) / logon task (Windows)."""
        chain_py = str(Path(chain.__file__).resolve())
        if platform.system() == "Linux":
            return subprocess.run(["sudo", self.python, chain_py, "arm"], cwd=self.base_dir).returncode == 0
        return self._run_as_admin(self.python, [chain_py, "arm"]) == 0

    def _disarm_chain(self, chain) -> None:
        chain_py = str(Path(chain.__file__).resolve())
        if platform.system() == "Linux":
            if chain.UNIT_PATH.exists():
                subprocess.run(["sudo", self.python, chain_py, "disarm"], cwd=self.base_dir)
        elif chain.WIN_TASK in self._registered_win_tasks():
            self._run_as_admin(self.python, [chain_py, "disarm"])

    def _take_mok_pending_flag(self) -> bool:
        """True if enable_secure_boot.sh left a MOK waiting for the MOK Manager screen (flag is removed)."""
        return self._take_flag("mok_enrollment_pending")

    def _take_flag(self, name: str) -> bool:
        """True if enable_secure_boot.sh left logs/<name> for the runner (the flag is removed)."""
        flag = self.logs_dir / name
        if not flag.exists():
            return False
        try:
            flag.unlink()
        except OSError:
            pass
        return True

    def _confirm_mok_reboot(self) -> bool:
        """Explicit y/n before the reboot that shows the MOK Manager screen; True = reboot now."""
        print()
        print("   ⚠️  MOK enrollment needs you at the SUT's monitor or serial console. After the reboot,")
        print("      the blue 'MOK Manager' screen waits only a few seconds for a key press. Press a key, then:")
        print("      Enroll MOK -> Continue -> Yes -> the password you just set -> Reboot.")
        print("      After that, the rest of the pre-flight and the tests run by themselves.")
        while True:
            answer = input(" Reboot now to enroll the MOK? [y/n]: ").strip().lower()
            if answer in ("y", "yes"):
                return True
            if answer in ("n", "no"):
                return False

    def _reboot(self, kind: str, mok_pending: bool = False, sb_bios: str = "") -> bool:
        """
        Reboot the SUT: kind 'firmware' = straight into BIOS Setup, 'normal' = the usual boot.
        mok_pending: a MOK waits for the MOK Manager screen, so ask y/n first; otherwise reboot at once.
        sb_bios: Secure Boot work only possible in BIOS Setup, so ask y/n first --
                 'keys' = delete the factory keys, 'enable' = set 'Secure Boot' = Enabled.
        Returns False if the user answered 'n' (nothing rebooted), True once the reboot was asked for.
        """
        print()
        if kind == "firmware" and sb_bios:
            print("   The SUT now reboots into BIOS Setup. In Security -> Secure Boot:")
            if sb_bios == "keys":
                print("     Secure Boot Mode = Custom, Factory Key Provision = Disabled,")
                print("     Key Management -> Delete all keys -> Yes.")
                print("     If 'Secure Boot' still shows Enabled, leave it. If it is Disabled you cannot enable it")
                print("     yet (no keys): once our keys are enrolled (a few minutes after Ubuntu boots) the SUT")
                print("     reboots straight into BIOS Setup by itself -- stay at the console and set it then.")
                print("     (Not 'Invoke OEM Key Revocation' -- that is an ME setting, not Secure Boot keys.)")
            else:
                print("     Secure Boot = Enabled (keep Secure Boot Mode = Custom; do NOT restore factory keys).")
                print("     Our keys were just enrolled and the EFI tools signed; only this setting is left")
                print("     (on this BIOS neither AMISCE nor Linux can change it -- it is locked against OS writes).")
            if self._plan_step(self._chain(), "bios_setup"):
                print("   Also set the BIOS knobs listed above.")
            print("   Then Save & Exit (F4); the rest continues by itself after Ubuntu boots.")
            if mok_pending:
                print("   Right after Save & Exit the blue 'MOK Manager' screen appears (it waits only a few seconds):")
                print("     Enroll MOK -> Continue -> Yes -> the password you just set -> Reboot.")
            if input("   Be at the SUT's monitor or serial console. Reboot into BIOS Setup now? [y/n] ").strip().lower() != "y":
                return False
        elif kind == "firmware" and self._plan_step(self._chain(), "bios_admin_setup"):
            print("   The SUT now reboots into BIOS Setup. Go to Security -> Administrator Password and type")
            print("   the password you just chose (twice), then Save & Exit (F4). Ubuntu boots, the pre-flight")
            print("   checks the BIOS has the password, then sets the BIOS knobs with AMISCE by itself.")
            if input("   Be at the SUT's monitor or serial console. Reboot into BIOS Setup now? [y/n] ").strip().lower() != "y":
                self._set_step(self._chain(), "bios_admin_setup", "cancelled")
                return False
        elif kind == "firmware":
            print("   The SUT now reboots into BIOS Setup. Set the knobs listed above, then Save & Exit (F4).")
        elif not mok_pending:
            print("   The SUT now reboots.")
        if mok_pending and not sb_bios:
            if not self._confirm_mok_reboot():
                print("   → Not rebooted. When you are at the SUT's console, reboot it (sudo reboot);")
                print("     the pre-flight continues after the MOK enrollment.")
                return False
        elif kind != "firmware" and platform.system() == "Linux" and self._plan_step(self._chain(), "secure_boot"):
            print("   If the blue 'MOK Manager' screen appears: Enroll MOK -> Continue -> Yes -> password -> Reboot.")
        if platform.system() == "Linux":
            cmd = ["sudo", "systemctl", "reboot"] + (["--firmware-setup"] if kind == "firmware" else [])
            if subprocess.run(cmd).returncode != 0 and kind == "firmware":
                print("⚠️  This firmware cannot be asked to open BIOS Setup -- press F2 while the SUT boots.")
                subprocess.run(["sudo", "systemctl", "reboot"])
        else:
            args = ["/r", "/fw", "/t", "0"] if kind == "firmware" else ["/r", "/t", "0"]
            if self._run_as_admin("shutdown", args) != 0 and kind == "firmware":
                print("⚠️  This firmware cannot be asked to open BIOS Setup -- press F2 while the SUT boots.")
                self._run_as_admin("shutdown", ["/r", "/t", "0"])
        return True

    def _run_as_admin(self, exe: str, args: List[str]) -> int:
        """Run a program elevated on Windows (UAC prompt if needed); waits and returns its exit code."""
        import ctypes
        if ctypes.windll.shell32.IsUserAnAdmin():
            return subprocess.run([exe, *args], cwd=self.base_dir).returncode
        arg_line = subprocess.list2cmdline(args).replace("'", "''")
        exe_ps = exe.replace("'", "''")
        cwd_ps = str(self.base_dir).replace("'", "''")
        ps = (f"$p = Start-Process -FilePath '{exe_ps}' -ArgumentList '{arg_line}' "
              f"-WorkingDirectory '{cwd_ps}' -Verb RunAs -Wait -PassThru; exit $p.ExitCode")
        print("   (Windows asks to allow Administrator rights -- choose Yes)")
        return subprocess.run(["powershell", "-NoProfile", "-Command", ps]).returncode

    def _plan_notes(self, chain, plan: Optional[Dict] = None) -> List[str]:
        """Header / 'P' lines about a pre-flight plan in progress or stopped."""
        plan = plan if plan is not None else chain.load_plan()
        if not plan:
            return []
        log = self._rel(chain.LOG_FILE)
        if plan.get("status") == "failed":
            return [f"Pre-flight stopped: {plan.get('error', '?')} -- pick the tests again to retry, "
                    f"or X to clear (log: {log})."]
        if plan.get("status") != "running":
            return []
        current = next((s for s in plan["steps"] if s["status"] in ("running", "pending")), None)
        if not current:
            return []
        pos, total = chain.step_position(plan, current)
        title = chain.STEP_TITLES.get(current["name"], current["name"])
        return [f"Pre-flight step {pos}/{total} ({title}) -- {len(plan.get('tests', []))} test(s) start "
                f"by themselves afterwards (log: {log})."]

    def _provisioning_notes(self) -> List[str]:
        """Header lines: a pre-flight plan, or a runbook started by hand that continues after reboot."""
        if platform.system() not in ("Linux", "Windows"):
            return []
        try:
            chain = self._chain()
        except ImportError:
            return []
        notes = self._plan_notes(chain)
        if not notes:
            busy = chain.runbook_in_progress()
            if busy:
                notes.append(f"{busy} is in progress -- it continues by itself after each reboot.")
        return notes

    def show_readiness(self):
        """Menu 'P': BIOS / Secure Boot / TPM facts, AMI detection, last AMISCE PASS, pre-flight plan."""
        print("\n🛠  SUT READINESS")
        print("=" * 70)
        if platform.system() not in ("Linux", "Windows"):
            print("   Only on a Linux/Windows SUT.")
            return
        chain = self._chain()
        bios = chain.bios_identity()
        ami, reason = chain.detect_ami(self._amisce_override())
        state = chain.secure_boot_state()
        print(f"   BIOS          : {bios['vendor'] or '?'}  {bios['version']}  {bios['date']}")
        print(f"   AMISCE        : {'yes (AMI)' if ami else 'no'} -- {reason}")
        print(f"   Secure Boot   : {({True: 'ENABLED', False: 'DISABLED', None: 'unknown'})[state]}")
        owner = chain.secure_boot_key_owner()
        if owner:
            _ready, why = chain.secure_boot_ready()
            print(f"   SB keys       : {owner} -- {why}")
            print("                   details: python3 deploy/secure_boot/sb_keys.py status")
        print(f"   TPM           : {chain.tpm_manufacturer() or 'unknown'} (INTC = PTT/fTPM)")
        last = self._read_json(chain.KNOB_LAST_PASS_FILE)
        if last:
            same = (last.get("bios") or {}).get("version") == bios["version"]
            changed = chain.changed_setup_variables(last.get("setup_fingerprint")) if same else None
            state_note = (" (other BIOS build)" if not same
                          else f" (BIOS settings changed since: {', '.join(changed)})" if changed else "")
            values = ", ".join(f"{q} = {o}" for q, o in (last.get("values") or {}).items())
            print(f"   Last AMISCE   : PASS {last.get('finished', '?')}{state_note}: {values}")
            print(f"                   delete {self._rel(chain.KNOB_LAST_PASS_FILE)} to make the"
                  " pre-flight run AMISCE again")
        for note in self._provisioning_notes():
            print(f" ⏳ {note}")
        print()
        print("   Before each run the pre-flight sets the BIOS knobs and Secure Boot the selected")
        print("   tests need (deploy/bios_knobs/bios_knobs.yaml). After an IFWI flash both are reset;")
        print("   the next pre-flight sets them again. Override AMI detection with bios.amisce:")
        print("   yes/no in config/test_config.yaml.")

    def run_pytest(self, command_args: List[str], report_name: str = "test_report") -> Optional[int]:
        """
        Execute pytest on the given paths / node ids and record the result.

        Only called after _preflight() returned "ok": the selected tests' setup
        is the operator's responsibility (each test still logs its checklist and
        runs its own automatic checks), so the run always gets
        --setup-confirmed --yes.

        Returns:
            Exit code from pytest, or None if the operator backed out ('B')
            of the fail-fast prompt.
        """
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_file = self.logs_dir / f"{report_name}_{timestamp}.html"

        failfast_flags = self._ask_failfast_flag()
        if failfast_flags is None:
            return None

        cmd = self.pytest_cmd + command_args + ["--setup-confirmed", "--yes"] + failfast_flags

        if self.has_pytest_html:
            cmd += [
                f"--html={report_file}",
                "--self-contained-html",
            ]
        else:
            print(f"⚠️  pytest-html not installed for {self.python}; running without HTML report")

        cmd += [
            "--tb=short",
            "-v",
            "--color=yes"
        ]
        
        print("\n" + "=" * 70)
        print(f"▶️  Executing: {' '.join(cmd)}")
        print("=" * 70 + "\n")
        
        started = time.time()
        returncode = self._run_until_done(cmd)
        if not report_file.exists():
            report_file = None

        results = self.save_test_results(returncode, command_args, report_file, report_name, started)
        self._print_run_complete(results, time.time() - started)
        
        return returncode

    def _print_run_complete(self, results: Dict, duration: float) -> None:
        """Post-run summary: verdict banner, per-test table, log/report paths, exit code meaning."""
        status = self._status_text(results)
        title = {
            "PASSED": "RUN COMPLETE -- PASSED",
            "FAILED": "RUN COMPLETE -- FAILED",
            "INTERRUPTED": "RUN INTERRUPTED",
            "IN PROGRESS": "PAUSED FOR REBOOT -- remaining tests resume after reboot",
        }[status]
        counts = ""
        if results.get("passed") is not None:
            counts = (f"   {results['passed']} passed, {results['failed']} failed, "
                      f"{results.get('skipped') or 0} skipped")

        print("\n" + "=" * 70)
        print(f" {self.STATUS_ICONS[status]} {title}{counts}   (total time: {format_duration(duration)})")
        print("=" * 70)
        self._print_result_rows(results)
        code = results["exit_code"]
        print(f"Exit code:   {code} ({self.EXIT_CODE_MEANINGS.get(code, 'unknown')})")

    def _run_until_done(self, cmd: List[str]) -> int:
        """
        Run pytest; on Ctrl+C keep waiting so pytest can finish its own teardown
        (state file cleanup, summary files) instead of being killed mid-cleanup.
        A second Ctrl+C force-kills it.
        """
        proc = subprocess.Popen(cmd, cwd=self.base_dir)
        try:
            return proc.wait()
        except KeyboardInterrupt:
            print("\n⚠️  Ctrl+C -- waiting for pytest to stop and clean up "
                  "(press Ctrl+C again to force-kill)...")
            try:
                return proc.wait()
            except KeyboardInterrupt:
                proc.kill()
                print("⚠️  pytest force-killed -- check the leftover-state warning in the menu.")
                return proc.wait()
    
    def save_test_results(
        self,
        exit_code: int,
        command_args: List[str],
        report_file: Optional[Path],
        label: str = "",
        started: float = 0.0,
    ) -> Dict:
        """
        Save test execution results for later reference.

        Pulls the richer pass/fail breakdown conftest.py writes to
        logs/last_run_summary.json -- but only if it was written by THIS run
        (mtime >= started); a pytest crash before sessionfinish leaves the
        previous run's file behind.
        """
        summary = {}
        summary_path = self.base_dir / "logs" / "last_run_summary.json"
        if summary_path.exists() and summary_path.stat().st_mtime >= started:
            try:
                summary = json.loads(summary_path.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                summary = {}

        results = {
            "timestamp": datetime.now().isoformat(),
            "exit_code": exit_code,
            "duration_seconds": round(time.time() - started, 1) if started else summary.get("duration_seconds"),
            "success": exit_code == 0,
            "label": label,
            "command_args": command_args,
            "report_file": str(report_file) if report_file else None,
            "passed": summary.get("passed"),
            "failed": summary.get("failed"),
            "skipped": summary.get("skipped"),
            "errors": summary.get("errors"),
            "pending_reboot_tests": summary.get("pending_reboot_tests", []),
            "passed_tests": summary.get("passed_tests", []),
            "failed_tests": summary.get("failed_tests", []),
            "skipped_tests": summary.get("skipped_tests", []),
            "error_tests": summary.get("error_tests", []),
            "skip_reasons": summary.get("skip_reasons", {}),
            "error_reasons": summary.get("error_reasons", {}),
            "failed_reasons": summary.get("failed_reasons", {}),
            "attested_reasons": summary.get("attested_reasons", {}),
            "log_dir": summary.get("log_dir"),
            "log_file": summary.get("batch_log"),
            "in_progress": self._batch_progress() is not None,
        }
        
        with open(self.results_file, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2)
        
        # Also append to history
        history_file = self.cache_dir / "test_history.jsonl"
        with open(history_file, 'a', encoding='utf-8') as f:
            f.write(json.dumps(results) + '\n')
        return results
    
    def load_last_results(self) -> Optional[Dict]:
        """Load results from last test run."""
        if not self.results_file.exists():
            return None
        
        try:
            with open(self.results_file, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            print(f"Error loading results: {e}")
            return None
    
    def run_failed_tests(self):
        """Re-run only tests that failed in the last run."""
        lastfailed_file = self.cache_dir / "v" / "cache" / "lastfailed"

        if not lastfailed_file.exists():
            print("\n⚠️  No failed tests found from previous run.")
            print("Please run tests first to generate cache.")
            input("\nPress Enter to continue...")
            return

        try:
            failed = json.loads(lastfailed_file.read_text(encoding="utf-8"))
        except (OSError, ValueError) as e:
            print(f"⚠️  Could not read lastfailed cache: {e}")
            return

        self._pick_and_run(list(failed.keys()), "previously FAILED tests", "failed_tests")

    def run_repeat_last(self):
        """
        Re-run the exact same test selection as the last run -- everything
        that was picked (passed, failed, AND skipped), not just the failures
        'F' re-runs. Source is our own .pytest_cache/last_run_results.json,
        or logs/last_batch_summary.json when a reboot-spanning batch finished
        after it -- not pytest's lastfailed cache.
        """
        last = self.load_last_results()
        last_batch = self._read_json(self.last_batch_file)
        if last_batch and last_batch.get("order") and (
            not last or last_batch.get("finished", "") > last["timestamp"]
        ):
            # A reboot-spanning run never returns to this runner, so its own record goes stale.
            last = {
                "command_args": last_batch["order"],
                "timestamp": last_batch["finished"],
                "label": f"batch {last_batch.get('batch_id')}",
            }
        node_ids = last.get("command_args") if last else None
        if not node_ids:
            print("\n⚠️  No previous run found to repeat.")
            print("Please run tests first.")
            input("\nPress Enter to continue...")
            return

        ts = last["timestamp"][:16].replace("T", " ")
        label = last.get("label") or "(unlabeled)"
        self._pick_and_run(node_ids, f"repeat of last run [{ts}] {label}", "repeat_last")

    @staticmethod
    def _parse_selection(text: str, count: int) -> List[int]:
        """'3,1,2' -> [2, 0, 1] (0-based, in the order typed); invalid tokens are reported and skipped."""
        indices = []
        for token in text.split(","):
            token = token.strip()
            if token.isdigit() and 1 <= int(token) <= count:
                indices.append(int(token) - 1)
            else:
                print(f"⚠️  Ignoring invalid selection: {token}")
        return indices

    def _pick_and_run(self, node_ids: List[str], group_label: str, report_name: str) -> str:
        """
        Shared preview/pick/run flow for every menu selection: filter to the
        current execution context, list the tests in run order grouped by
        suite, then run all, a reordered subset, or nothing.

        Returns "back" if the operator asked (at the order prompt, or with 'B'
        in the pre-flight or fail-fast prompts) to
        return to whatever selection step the caller used to build node_ids
        (IFWI group/suite, marker, etc). Returns "cancel" or "done" otherwise
        -- callers with no earlier selection step of their own can treat
        both the same as "finished, nothing more to do here".
        """
        if not node_ids:
            print("❌ No test cases found.")
            return "cancel"

        # Default to only the current execution context -- a sut_windows test
        # picked while running on sut_linux (or vice versa) just SKIPS itself
        # (see test_selection.wrong_os_reason), so there's no point offering it.
        if self.host_context != "all":
            filtered = [nid for nid in node_ids if self._node_context_label(nid) == self.host_context]
            if not filtered:
                print(f"\n⚠️  No '{self.host_context}' tests in this selection -- showing all contexts.")
            elif len(filtered) < len(node_ids):
                print(f"\n   → Showing {len(filtered)} of {len(node_ids)} test(s) -- context '{self.host_context}'.")
            node_ids = filtered or node_ids

        # Stable sort: eom/firmware last (same rule conftest applies), suites grouped, file order kept.
        node_ids = sorted(
            node_ids,
            key=lambda nid: (test_selection.run_order_rank(nid), test_selection.suite_of(nid)),
        )
        show_os = self.host_context == "all"
        linux_host = test_selection.host_context() == "sut_linux"

        def on_flashed(nid: str) -> str:
            if test_selection.wrong_ifwi_reason(nid, flashed, how):
                return "WRONG IFWI"
            return "OK" if flashed in test_selection.ifwi_groups(nid) else "cannot tell"

        while True:
            flashed, how = self._flashed_ifwi() if linux_host else (None, "")
            print(f"\n🧪 READY TO RUN {len(node_ids)} TEST(S) -- {group_label}")
            headers = ("#", "Suite", "Test ID", "IFWI") + (("OS",) if show_os else ())
            if flashed:
                headers += (f"On flashed {test_selection.ifwi_short_label(flashed)}",)
            rows = [
                (
                    str(i),
                    test_selection.suite_of(nid),
                    self._test_id_for_node(nid),
                    test_selection.ifwi_label(nid),
                ) + ((self._node_context_label(nid),) if show_os else ())
                + ((on_flashed(nid),) if flashed else ())
                for i, nid in enumerate(node_ids, 1)
            ]
            self._print_simple_table(headers, rows)
            suites = []
            for nid in node_ids:
                suite = test_selection.suite_of(nid)
                if suite not in suites:
                    suites.append(suite)
            for suite in suites:
                if suite in test_selection.SUITE_NOTES:
                    print(f" ⚠️  {suite}: {test_selection.SUITE_NOTES[suite]}")
                if suite in test_selection.IRREVERSIBLE_SUITES:
                    print(f" ⚠️  {suite}: cannot be undone -- {test_selection.IRREVERSIBLE_SUITES[suite]}")
            print(" Enter = run all  |  1,3,2 = pick/reorder  |  B = back  |  N = cancel")
            selection = input("> ").strip()

            if selection.upper() == "N":
                print("   → Cancelled.")
                return "cancel"
            if selection.upper() == "B":
                return "back"

            picked = node_ids
            if selection:
                picked = [node_ids[i] for i in self._parse_selection(selection, len(node_ids))]
            if not picked:
                print("❌ No valid test cases selected")
                continue
            picked = self._drop_wrong_ifwi(picked)
            if picked is None:
                print("   → Back to test selection.")
                continue
            if not self._confirm_irreversible(picked):
                print("   → Back to test selection.")
                continue

            preflight = self._preflight(picked, report_name)
            if preflight == "back":
                print("   → Back to test selection.")
                continue
            if preflight == "stop":
                return "cancel"
            print(f"\n🚀 Running {len(picked)} test case(s) -- {group_label}...")
            returncode = self.run_pytest(picked, report_name)
            if returncode is None:
                print("   → Back to test selection.")
                continue
            return "done"

    def _flashed_ifwi(self) -> tuple:
        """(IFWI group marker or None, how it was read), see bios_knob_checks.flashed_ifwi."""
        if self._flashed is None:
            self._flashed = bios_knob_checks.flashed_ifwi()
        return self._flashed

    def _ask_flashed_ifwi(self, why: str) -> tuple:
        """The operator names the flashed IFWI when the OS cannot tell; kept for this runner session."""
        print(f"\n⚠️  Could not detect the flashed IFWI ({why}).")
        print("   Which IFWI is flashed on this SUT?")
        for i, (_marker, desc) in enumerate(test_selection.IFWI_GROUPS, 1):
            label, image = (desc.split(" -- ") + ["", ""])[:2]
            print(f"     {i}) {label:<16} {image}")
        choice = input(f"   Select [1-{len(test_selection.IFWI_GROUPS)}], or B = back: ").strip()
        if choice.isdigit() and 1 <= int(choice) <= len(test_selection.IFWI_GROUPS):
            self._flashed = (test_selection.IFWI_GROUPS[int(choice) - 1][0], "entered by the operator")
            return self._flashed
        return None, why

    def _drop_wrong_ifwi(self, picked: List[str]) -> Optional[List[str]]:
        """picked minus the tests the flashed IFWI cannot run (if the operator agrees), or None = back."""
        checked = [nid for nid in picked if test_selection.ifwi_checked(nid)]
        if not checked:
            return picked
        flashed, how = self._flashed_ifwi()
        if flashed is None:
            flashed, how = self._ask_flashed_ifwi(how)
            if flashed is None:
                return None
        wrong = [nid for nid in checked if test_selection.wrong_ifwi_reason(nid, flashed, how)]
        if not wrong:
            return picked

        print()
        tied = sorted({test_selection.ifwi_groups(nid)[0] for nid in checked})
        if len(tied) > 1:
            mixed = " and ".join(f"{test_selection.ifwi_short_label(g)}-only" for g in tied)
            print(f"❌ The selection mixes {mixed} tests; one flashed IFWI cannot run both.")
        print(f"❌ {len(wrong)} test(s) cannot run on the flashed "
              f"{test_selection.ifwi_short_label(flashed)} IFWI ({how}):")
        for nid in wrong:
            needed = test_selection.ifwi_short_label(test_selection.ifwi_groups(nid)[0])
            print(f"     - {self._test_id_for_node(nid)}   needs the {needed} IFWI")
        print("   Flash the IFWI they need and run them in a separate session.")
        rest = [nid for nid in picked if nid not in wrong]
        if not rest:
            input(" Nothing else to run. Enter = back: ")
            return None
        answer = input(f" D = drop them and run the other {len(rest)}  |  B = back: ").strip().upper()
        return rest if answer == "D" else None

    def _confirm_irreversible(self, picked: List[str]) -> bool:
        """Typed 'yes' before suites whose run cannot be undone (eom, firmware)."""
        suites = sorted({test_selection.suite_of(nid) for nid in picked} & set(test_selection.IRREVERSIBLE_SUITES))
        if not suites:
            return True
        print()
        for suite in suites:
            print(f"⚠️  {suite}: {test_selection.IRREVERSIBLE_SUITES[suite]}. This cannot be undone.")
        return input(" Type yes to run it, anything else to go back: ").strip().lower() == "yes"

    def _context_nodes(self) -> List[str]:
        """Node ids under tests/ for the current execution context."""
        if self._all_nodes is None:
            self._all_nodes = self._collect("tests/")
        return [
            nid for nid in self._all_nodes
            if self.host_context == "all" or self._node_context_label(nid) == self.host_context
        ]

    def _available_suites(self) -> List[tuple]:
        """(suite, node_ids) for every suite with tests in the current context, in menu order."""
        nodes = self._context_nodes()
        available = []
        for suite in self.test_suites.values():
            members = [nid for nid in nodes if test_selection.suite_of(nid) == suite["name"]]
            if members:
                available.append((suite, members))
        return available

    def run_suites(self, selection: str):
        """Run one or more suites picked by their main-menu number (e.g. '3' or '1,3,5')."""
        available = self._available_suites()
        indices = list(dict.fromkeys(self._parse_selection(selection, len(available))))
        if not indices:
            print("\n❌ No valid suite number.")
            return

        picked = [available[i] for i in indices]
        node_ids = [nid for _, nodes in picked for nid in nodes]
        label = ", ".join(suite["name"] for suite, _ in picked)
        report_name = picked[0][0]["name"] if len(picked) == 1 else "custom_selection"
        self._pick_and_run(node_ids, label, report_name)

    def run_by_marker(self):
        """Run tests matching a pytest -m expression. Loops back here if the operator backs out ('B') downstream."""
        while True:
            print("\n🏷️  RUN BY MARKER")
            print("=" * 70)
            suites = {s["name"] for s in self.test_suites.values()}
            contexts = {marker for _, marker in test_selection.OS_CONTEXT_RULES}
            ifwi = {marker for marker, _ in test_selection.IFWI_GROUPS}
            type_order = {"suite": 0, "tag": 1, "OS context": 2, "IFWI": 3}
            rows = []
            for marker, desc in self.marker_descriptions.items():
                if marker.startswith("timeout"):
                    continue
                kind = ("suite" if marker in suites else "OS context" if marker in contexts
                        else "IFWI" if marker in ifwi else "tag")
                rows.append((marker, kind, re.sub(r"\s+tests\b", "", desc)))
            rows.sort(key=lambda row: type_order[row[1]])
            self._print_simple_table(("Marker", "Type", "Description"), rows)
            print(" Any -m expression works, e.g. 'tme and not manual'.")

            marker = input("\nMarker / expression, or B = back: ").strip()
            if not marker or marker.upper() == "B":
                return

            result = self._pick_and_run(self._collect("-m", marker, "tests/"), f"marker '{marker}'", f"marker_{marker}")
            if result == "back":
                continue
            return

    def _collect(self, *args: str) -> List[str]:
        """Node ids under tests/ that pytest would run for these args, without running them."""
        try:
            result = subprocess.run(
                [*self.pytest_cmd, "--collect-only", "-q", "-o", "addopts=", *args],
                cwd=self.base_dir,
                capture_output=True,
                text=True,
                timeout=60,
            )
        except (OSError, subprocess.SubprocessError) as e:
            print(f"⚠️  Could not collect tests ({' '.join(args)}): {e}")
            return []
        # 5 = nothing matched. Any other failure (e.g. a bad -m expression) still prints the
        # unfiltered node ids, so return nothing rather than offer to run the whole tree.
        if result.returncode not in (0, 5):
            print(f"⚠️  pytest collection failed (exit {result.returncode}) for: {' '.join(args)}")
            for line in (result.stdout + result.stderr).strip().splitlines()[-3:]:
                print(f"    {line}")
            return []
        return [
            line.strip() for line in result.stdout.splitlines()
            if line.strip().startswith("tests/") and "::" in line
        ]

    def _test_id_for_node(self, node_id: str) -> str:
        """
        Best-effort human label for a node id: the test's TEST_ID class
        attribute, parsed straight from source (no importing the module,
        which could pull in paramiko/pyserial and fail outside a full env).
        Falls back to the bare test function name if TEST_ID isn't found.
        """
        file_path = node_id.split("::", 1)[0]
        if file_path not in self._test_id_cache:
            label = None
            try:
                text = (self.base_dir / file_path).read_text(encoding="utf-8", errors="replace")
                match = re.search(r'TEST_ID\s*=\s*["\']([^"\']+)["\']', text)
                if match:
                    label = match.group(1)
            except OSError:
                pass
            self._test_id_cache[file_path] = label
        return self._test_id_cache[file_path] or node_id.rsplit("::", 1)[-1]

    @staticmethod
    def _node_context_label(node_id: str) -> str:
        """OS-context label (sut_linux/sut_windows/...) for a node id, from filename suffix."""
        return test_selection.os_context(node_id) or "?"

    def run_by_ifwi_group(self):
        """
        Run every test that shares one IFWI group (avoids reflashing between
        tests that already share the same flashed image). Picking specific
        suites is done straight from the main menu.

        Loops back to this same menu if the operator backs out ('B') of the
        preview/order, pre-flight or fail-fast prompts further down the chain.
        """
        while True:
            nodes = self._context_nodes()

            print("\n🔧 RUN BY IFWI GROUP -- every test that uses the same flashed image")
            print("=" * 70)
            flashed, _how = self._flashed_ifwi() if test_selection.host_context() else (None, "")
            rows = []
            for i, (marker, desc) in enumerate(test_selection.IFWI_GROUPS, 1):
                count = sum(1 for nid in nodes if marker in test_selection.ifwi_groups(nid))
                label, image = (desc.split(" -- ") + ["", ""])[:2]
                rows.append((str(i), label, image, str(count) if count else "-",
                             "<- flashed now" if marker == flashed else ""))
            self._print_simple_table(("#", "IFWI group", "Image to flash", "Tests", "Flashed"), rows)
            shared = sum(1 for nid in nodes if len(test_selection.ifwi_groups(nid)) > 1)
            if shared:
                print(f" {shared} test(s) run on SEP5 or SED5, so they are counted in both groups.")

            selection = input(f"\nSelect group [1-{len(rows)}], or B = back: ").strip()
            if not selection or selection.upper() == "B":
                return
            if not (selection.isdigit() and 1 <= int(selection) <= len(rows)):
                print(f"❌ Invalid group: {selection}")
                continue

            marker, desc = test_selection.IFWI_GROUPS[int(selection) - 1]
            members = [nid for nid in nodes if marker in test_selection.ifwi_groups(nid)]
            if not members:
                print(f"⚠️  No {self.host_context} tests use the {rows[int(selection) - 1][1]} image.")
                continue
            result = self._pick_and_run(members, f"IFWI group {rows[int(selection) - 1][1]}", f"ifwi_group_{marker}")
            if result == "back":
                continue
            return
    
    def view_last_results(self):
        """Display results from last test run."""
        self.print_header()
        print("📊 LAST RUN RESULTS")
        print("=" * 70)
        
        results = self.load_last_results()
        last_batch = self._read_json(self.last_batch_file)
        batch_is_newer = bool(last_batch) and (
            not results or last_batch.get("finished", "") > results["timestamp"]
        )

        if batch_is_newer:
            # A reboot-spanning run never returns to this runner, so its own record goes stale.
            self._print_final_batch(last_batch)
        elif results:
            self._print_result_detail(results)
        else:
            print("\n⚠️  No previous test results found.")
        
        print("\n" + "=" * 70)
        input("\nPress Enter to continue...")

    def _print_final_batch(self, batch: Dict) -> None:
        """Final verdict of the last completed batch -- covers tests resumed after reboots."""
        results = batch.get("results") or {}
        reasons = batch.get("reasons") or {}
        n_pass, n_fail, n_skip = batch.get("passed", 0), batch.get("failed", 0), batch.get("skipped", 0)
        status = "✅ PASSED" if n_fail == 0 and n_pass > 0 else ("❌ FAILED" if n_fail else "⚠️  NO TESTS PASSED")

        print(f"\nFinished:    {batch.get('finished', '')[:19].replace('T', ' ')}")
        print("Run:         batch (includes tests resumed after reboot)")
        duration = self._duration_text(batch.get("total_seconds"), batch.get("test_seconds"), batch.get("reboots"))
        if duration:
            print(f"Duration:    {duration}")
        rows = [(results.get(nid, "?"), nid, reasons.get(nid, "")) for nid in batch.get("order") or results]
        print(f"Result:      {status} -- {n_pass} passed, {n_fail} failed, {n_skip} skipped "
              f"({len(results)} total)")
        if rows:
            self._print_test_table(rows)
        self._print_log_location(batch)
        if self.resume_log.exists():
            print(f"Resume log:  {self.resume_log}")

    def _print_log_location(self, entry: Dict) -> None:
        """The batch log conftest.py writes for every finished run (one segment per reboot)."""
        log_file = entry.get("log_file")
        log_dirs = entry.get("log_dirs") or []
        # Records saved before conftest.py wrote the log itself have no log_file -- rebuild it.
        if not (log_file and Path(log_file).exists()) and log_dirs:
            log_file = stitch_batch_log(self.logs_dir, entry)
        if log_file and Path(log_file).exists():
            print(f"Full log:    {log_file}")
            if len(log_dirs) > 1:
                print(f"             ({len(log_dirs)} reboot segments, in order -- each segment's "
                      f"folder is listed inside)")
            elif entry.get("log_dir"):
                print(f"Artifacts:   {entry['log_dir']}")
        elif entry.get("log_dir"):
            print(f"Log folder:  {entry['log_dir']}")

    @staticmethod
    def _duration_text(total: Optional[float], test: Optional[float] = None, reboots: Optional[int] = None) -> str:
        """'2m 15s total (1 reboot), 1m 02s test time' -- or '' if the record has no timing."""
        if total is None:
            return ""
        if not reboots or test is None:
            return format_duration(total)
        return (f"{format_duration(total)} total ({reboots} reboot{'s' if reboots > 1 else ''}), "
                f"{format_duration(test)} test time")

    @staticmethod
    def _status_text(entry: Dict) -> str:
        if entry.get("in_progress"):
            return "IN PROGRESS"
        if entry.get("exit_code") == 2:
            return "INTERRUPTED"
        return "PASSED" if entry["success"] else "FAILED"

    def _status_label(self, entry: Dict) -> str:
        status = self._status_text(entry)
        suffix = " (resumes after reboot)" if status == "IN PROGRESS" else ""
        return f"{self.STATUS_ICONS[status]} {status}{suffix}"

    def _print_result_detail(self, entry: Dict) -> None:
        """Print one result entry's full detail: counts, failed tests, log folder, report."""
        ts = entry["timestamp"][:19].replace("T", " ")
        passed, failed = entry.get("passed"), entry.get("failed")
        skipped, errors = entry.get("skipped") or 0, entry.get("errors") or 0
        status = self._status_label(entry)

        print(f"\nTimestamp:   {ts}")
        print(f"Run:         {entry.get('label') or '(unlabeled)'}")
        duration = self._duration_text(entry.get("duration_seconds"), entry.get("test_seconds"), entry.get("reboots"))
        if duration:
            print(f"Duration:    {duration}")
        if passed is not None:
            total = passed + failed + skipped + errors
            print(f"Result:      {status} -- {passed} passed, {failed} failed, "
                  f"{skipped} skipped, {errors} errors ({total} total)")
        else:
            print(f"Result:      {status}  (exit code {entry['exit_code']})")
        self._print_result_rows(entry)

    def _print_result_rows(self, entry: Dict) -> None:
        """Per-test status/detail table plus log and HTML report locations for one result entry."""
        failed_tests = entry.get("failed_tests") or []
        failed_reasons = entry.get("failed_reasons") or {}
        rows = [("FAILED", nid, failed_reasons.get(nid, "")) for nid in failed_tests]
        error_reasons = entry.get("error_reasons") or {}
        rows += [("ERROR", nid, error_reasons.get(nid, "")) for nid in entry.get("error_tests") or []]
        skip_reasons = entry.get("skip_reasons") or {}
        rows += [("SKIPPED", nid, skip_reasons.get(nid, "")) for nid in entry.get("skipped_tests") or []]
        rows += [("PENDING REBOOT", nid, "resumes automatically after the next boot")
                 for nid in entry.get("pending_reboot_tests") or []]
        confirmed = entry.get("attested_reasons") or {}
        rows += [("PASSED", nid, f"Confirmed by the operator: {confirmed[nid]}" if nid in confirmed else "")
                 for nid in entry.get("passed_tests") or []]
        if rows:
            self._print_test_table(rows)

        self._print_log_location(entry)
        print(f"HTML report: {entry.get('report_file') or '(none)'}")

    @staticmethod
    def _table_border(widths) -> str:
        return "+" + "+".join("-" * (w + 2) for w in widths) + "+"

    @staticmethod
    def _table_row(cells, widths) -> str:
        return "|" + "|".join(f" {cell:<{w}} " for cell, w in zip(cells, widths)) + "|"

    def _print_simple_table(self, headers: tuple, rows: List[tuple]) -> None:
        """Bordered table for single-line cells (no wrapping) -- e.g. the test-case preview list."""
        widths = [
            max(len(headers[col]), max((len(r[col]) for r in rows), default=0))
            for col in range(len(headers))
        ]
        print(self._table_border(widths))
        print(self._table_row(headers, widths))
        print(self._table_border(widths))
        for row in rows:
            print(self._table_row(row, widths))
        print(self._table_border(widths))

    def _print_test_table(self, rows: List[tuple]) -> None:
        """
        Bordered 'Test ID / Status / Detail' table; rows are (status, node_id, detail).
        Long Detail text wraps onto extra lines instead of being cut off.
        """
        DETAIL_WIDTH = 60
        headers = ("Test ID", "Status", "Detail")
        table = [
            (
                self._test_id_for_node(nid),
                status,
                [w for para in detail.splitlines() for w in (textwrap.wrap(para, DETAIL_WIDTH) or [""])]
                if detail else [""],
            )
            for status, nid, detail in rows
        ]
        id_width = max(len(headers[0]), max((len(t) for t, _, _ in table), default=0))
        status_width = max(len(headers[1]), max((len(s) for _, s, _ in table), default=0))
        detail_width = max(len(headers[2]), max((len(line) for *_, lines in table for line in lines), default=0))
        widths = (id_width, status_width, detail_width)

        print()
        print(self._table_border(widths))
        print(self._table_row(headers, widths))
        print(self._table_border(widths))
        for row in table:
            print(self._table_row((row[0], row[1], row[2][0]), widths))
            for extra in row[2][1:]:
                print(self._table_row(("", "", extra), widths))
        print(self._table_border(widths))

    def view_test_history(self):
        """Display test execution history, with drill-down into any entry's log folder/report."""
        self.print_header()
        print("📜 RUN HISTORY")
        print("=" * 70)
        
        history_file = self.cache_dir / "test_history.jsonl"
        
        if not history_file.exists():
            print("\n⚠️  No test history found.")
            print("\n" + "=" * 70)
            input("\nPress Enter to continue...")
            return

        print("Recent test runs (last 20, newest first):")
        
        with open(history_file, 'r', encoding='utf-8') as f:
            lines = f.readlines()

        entries, rows = [], []
        for line in reversed(lines[-20:]):
            try:
                entry = json.loads(line)
            except Exception:
                continue
            entries.append(entry)
            passed, failed = entry.get("passed"), entry.get("failed")
            if passed is not None:
                total = passed + failed + (entry.get("skipped") or 0) + (entry.get("errors") or 0)
                counts = f"{passed}/{total}"
            else:
                counts = "?"
            rows.append((
                str(len(entries)),
                entry["timestamp"][:16].replace("T", " "),
                self._status_text(entry),
                counts,
                format_duration(entry["duration_seconds"]) if entry.get("duration_seconds") is not None else "-",
                entry.get("label") or "(unlabeled)",
            ))
        self._print_simple_table(("#", "When", "Result", "Passed", "Duration", "Run"), rows)

        print("\n" + "=" * 70)
        choice = input(
            "Enter a number to see its log folder/report/failed tests, "
            "or press Enter to go back: "
        ).strip()
        if choice.isdigit() and 1 <= int(choice) <= len(entries):
            print("=" * 70)
            self._print_result_detail(entries[int(choice) - 1])
            print("\n" + "=" * 70)

        input("\nPress Enter to continue...")
    
    def run(self):
        """Main interactive loop."""
        while True:
            self.print_menu()
            
            choice = input("Choice: ").strip().upper()
            
            if choice == 'Q':
                print("\n👋 Thank you for using BIOS Security Test Runner!")
                sys.exit(0)

            elif choice and all(token.strip().isdigit() for token in choice.split(",")):
                self.run_suites(choice)
                input("\nPress Enter to continue...")
            
            elif choice == 'F':
                self.run_failed_tests()
                input("\nPress Enter to continue...")

            elif choice == 'R':
                self.run_repeat_last()
                input("\nPress Enter to continue...")
            
            elif choice == 'M':
                self.run_by_marker()
                input("\nPress Enter to continue...")
            
            elif choice == 'I':
                self.run_by_ifwi_group()
                input("\nPress Enter to continue...")

            elif choice == 'X':
                self.clear_run_state()
                input("\nPress Enter to continue...")

            elif choice == 'O':
                self.change_context()
                input("\nPress Enter to continue...")

            elif choice == 'P':
                self.show_readiness()
                input("\nPress Enter to continue...")

            elif choice == 'L':
                self.view_last_results()
            
            elif choice == 'H':
                self.view_test_history()
            
            else:
                print(f"\n❌ Invalid choice: {choice}")
                input("\nPress Enter to continue...")


def main():
    """Main entry point."""
    runner = TestRunner()
    
    try:
        runner.run()
    except KeyboardInterrupt:
        print("\n\n⚠️  Interrupted by user")
        sys.exit(1)
    except Exception as e:
        import traceback
        error_log = runner.logs_dir / "test_runner_error.log"
        try:
            with error_log.open("a", encoding="utf-8") as fh:
                fh.write(f"===== {datetime.now().isoformat(timespec='seconds')} =====\n")
                traceback.print_exc(file=fh)
            print(f"\n❌ Error: {e}\n   Details: {error_log}")
        except OSError:
            print(f"\n❌ Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
