#!/usr/bin/env python3
# Copyright 2026 Intel Corporation
# SPDX-License-Identifier: Apache-2.0
"""
deploy/resume/status_window.py -- the batch status window (Windows and Linux).

A batch that reboots is several pytest runs; their output scrolls past in a console, or (Linux,
resumed before anyone logs in) only goes to a log file. This window keeps the batch status on
screen and opens by itself:
  - Windows: conftest.py opens it in a new console when a batch with reboots starts, and again
    when the batch resumes after every reboot + logon. Runs that continue at boot as SYSTEM (no
    sign-in needed) have no window: the logon task FW_Status_Window opens this one as soon as an
    administrator signs in.
  - Linux: a desktop login autostart entry opens it in a terminal while a batch is running
    (installed by setup_sut.sh or by the first batch with reboots); conftest.py also opens it
    when the batch starts from a desktop session.

Every few seconds it redraws: how many reboots the batch needs and has done, which test runs
now, what the next reboot needs from the operator (e.g. what to set in BIOS Setup), and the
latest lines of the test log (the BIOS steps / signal-file command of a waiting test). While a
reboot is pending it waits for the batch to continue; after the last test it shows the latest
final result and stays on it (switching to the next run if one starts) until Enter. Closing it
never stops the tests.

A second window opens next to it (--log) that follows the running batch's whole
test_execution.log live -- every step and manual instruction as it is logged -- and switches to
the new log after each reboot (the pre-flight log while the pre-flight runs).

Standard library only:
  python deploy/resume/status_window.py               show the status in this window
  python deploy/resume/status_window.py --launch      open it in a new window when a batch is
                                                      running (or just finished) and none is open,
                                                      plus the live test log window
  python deploy/resume/status_window.py --log         follow the running batch's test log here
  python3 deploy/resume/status_window.py --install    Linux: add the desktop login autostart entry;
                                                      Windows: add the FW_Status_Window logon task
  python3 deploy/resume/status_window.py --uninstall  remove it
"""

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import textwrap
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))
from core import reboot_plan  # noqa: E402
from core.state_dir import DEFAULT_STATE_DIR  # noqa: E402

LOGS_DIR = REPO_ROOT / "logs"
BATCH_FILE = LOGS_DIR / "batch_status.json"
LAST_BATCH_FILE = LOGS_DIR / "last_batch_summary.json"
PREFLIGHT_PLAN = LOGS_DIR / "preflight_plan.json"
PREFLIGHT_LOG = LOGS_DIR / "preflight.log"
SHOWN_FILE = LOGS_DIR / ".status_window_shown"
ALIVE_FILE = LOGS_DIR / ".status_window_alive"
LOG_ALIVE_FILE = LOGS_DIR / ".log_window_alive"
AUTOSTART = Path.home() / ".config" / "autostart" / "fw-status-window.desktop"
OLD_AUTOSTART = Path.home() / ".config" / "autostart" / "fw-resume-monitor.desktop"
WIN_LOGON_TASK = "FW_Status_Window"
TITLE = "FW validation -- batch status"
LOG_TITLE = "FW validation -- live test log"
LOG_BACKLOG_LINES = 200
REFRESH_SECS = 3
ALIVE_SECS = 15
LOG_LINES = 12
# "2026-10-25 07:27:12,345 - name - INFO - message" -> "07:27:12 message"
_LOG_PREFIX = re.compile(r"^\d{4}-\d\d-\d\d (\d\d:\d\d:\d\d)(?:,\d+)? - \S+ - (\w+) -(?: |$)")


def _load(path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def batch_running():
    batch = _load(BATCH_FILE)
    if any(s in ("PENDING", "REBOOTING") for s in (batch.get("results") or {}).values()):
        return True
    return _load(PREFLIGHT_PLAN).get("status") == "running"


def _boot_epoch():
    if os.name == "nt":
        import ctypes
        kernel32 = ctypes.windll.kernel32
        kernel32.GetTickCount64.restype = ctypes.c_ulonglong
        return time.time() - kernel32.GetTickCount64() / 1000.0
    try:
        return time.time() - float(Path("/proc/uptime").read_text().split()[0])
    except (OSError, ValueError, IndexError):
        return 0.0


def finished_unseen():
    """A batch finished during this boot whose final result no status window has shown yet."""
    if not LAST_BATCH_FILE.exists() or LAST_BATCH_FILE.stat().st_mtime < _boot_epoch():
        return False
    batch_id = _load(LAST_BATCH_FILE).get("batch_id", "")
    try:
        return SHOWN_FILE.read_text(encoding="utf-8").strip() != batch_id
    except OSError:
        return True


def window_open(alive_file=ALIVE_FILE):
    try:
        return time.time() - alive_file.stat().st_mtime < ALIVE_SECS
    except OSError:
        return False


def _in_boot_session():
    """Windows: True in session 0 (a task started at boot as SYSTEM) -- there is no desktop to show a window on."""
    if os.name != "nt":
        return False
    import ctypes
    session = ctypes.c_ulong()
    return bool(ctypes.windll.kernel32.ProcessIdToSessionId(os.getpid(), ctypes.byref(session))) and session.value == 0


def _touch_alive(alive_file=ALIVE_FILE):
    try:
        LOGS_DIR.mkdir(parents=True, exist_ok=True)
        alive_file.write_text(str(os.getpid()), encoding="utf-8")
    except OSError:
        pass


def _claim_window(alive_file):
    """True for exactly one of several launchers racing to open the same window (e.g. at sign-in)."""
    if window_open(alive_file):
        return False
    stale = alive_file.with_name(f"{alive_file.name}.{os.getpid()}.stale")
    try:
        os.replace(alive_file, stale)  # atomic: only one launcher moves the old file away
        stale.unlink()
    except OSError:
        pass
    try:
        os.close(os.open(alive_file, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600))
        return True
    except OSError:
        return False


def _minutes(seconds):
    seconds = int(seconds or 0)
    return f"{seconds // 60}m {seconds % 60:02d}s"


def _format_line(line):
    """(shortened line, level) for one log line, or None for blank lines and ===== separators."""
    line = line.rstrip()
    match = _LOG_PREFIX.match(line)
    message = line[match.end():] if match else line
    if not message.strip() or not set(message.strip()) - set("=-"):
        return None
    if not match:
        return line, ""
    level = match.group(2)
    shown = "" if level in ("INFO", "DEBUG") else level + " "
    return f"{match.group(1)} {shown}{message}", level


def _tail(path, count):
    """Last `count` non-empty lines of a log, timestamps shortened."""
    try:
        with open(path, "rb") as fh:
            fh.seek(max(0, fh.seek(0, os.SEEK_END) - 65536))
            text = fh.read().decode("utf-8", errors="replace")
    except OSError:
        return []
    lines = [f[0] for f in map(_format_line, text.splitlines()[-count * 3:]) if f]
    return lines[-count:]


def _short(path):
    try:
        return str(Path(path).resolve().relative_to(REPO_ROOT))
    except ValueError:
        return str(path)


def _running_frame(batch, rows):
    lines = reboot_plan.banner_lines(batch, running=batch.get("current"))
    log_dirs = batch.get("log_dirs") or []
    if log_dirs:
        log_file = Path(log_dirs[-1]) / "test_execution.log"
        room = max(3, min(LOG_LINES, rows - len(lines) - 4))
        lines.append(f" Latest from the test log ({_short(log_file)}):")
        lines += ["   " + line for line in _tail(log_file, room)]
    return lines


def _preflight_frame(plan, rows):
    sep = "=" * 80
    lines = [sep, " ⚙ PRE-FLIGHT -- getting the SUT ready; the tests start by themselves afterwards", sep]
    for i, step in enumerate(plan.get("steps") or [], 1):
        lines.append(f"  {i}. [{step.get('status', '?'):<7}] {step.get('name', '?').replace('_', ' ')}")
    lines += ["", f" Tests waiting: {len(plan.get('tests') or [])}", sep,
              f" Latest from {_short(PREFLIGHT_LOG)}:"]
    lines += ["   " + line for line in _tail(PREFLIGHT_LOG, max(3, min(LOG_LINES, rows - len(lines) - 2)))]
    return lines


def _final_frame(summary):
    sep = "=" * 80
    order = summary.get("order") or []
    results = summary.get("results") or {}
    reasons = summary.get("reasons") or {}
    test_ids = summary.get("test_ids") or {}
    failed = summary.get("failed", 0)
    verdict = "❌ BATCH FINISHED -- FAILED" if failed else "✅ BATCH FINISHED -- PASSED"
    lines = [sep,
             f" {verdict}   {summary.get('passed', 0)} passed, {failed} failed, {summary.get('skipped', 0)} skipped",
             f"   Total time {_minutes(summary.get('total_seconds'))}, {summary.get('reboots', 0)} reboot(s)",
             sep]
    width = max([len(test_ids.get(n, n)) for n in order] + [4])
    lines.append(f"  {'#':>2}  {'Test':<{width}}  Result")
    for i, nid in enumerate(order, 1):
        lines.append(f"  {i:>2}  {test_ids.get(nid, nid):<{width}}  {results.get(nid, '?')}")
        reason = (reasons.get(nid) or "").strip().splitlines()
        if reason:
            lines.append(f"  {'':>2}  {'':<{width}}  {reason[0][:100]}")
    lines += ["", f" Full batch log: {_short(summary.get('log_file', '-'))}",
              " Results any time: python test_runner.py -> L", sep]
    return lines


def _prepare_console(title=TITLE):
    if os.name == "nt":
        import ctypes
        os.system("")  # turns on ANSI escape handling in this console
        ctypes.windll.kernel32.SetConsoleTitleW(title)
    else:
        sys.stdout.write(f"\033]0;{title}\007")
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(errors="replace")


def _draw(lines):
    size = shutil.get_terminal_size((100, 40))
    width = size.columns - 3
    head = [f" {TITLE} -- updates every {REFRESH_SECS} s. Closing this window does not stop the tests.", ""]
    out = []
    for line in head + lines:
        if len(line) <= width:
            out.append(line)
            continue
        indent = " " * (len(line) - len(line.lstrip()) + 4)
        out += textwrap.wrap(line, width, subsequent_indent=indent, break_on_hyphens=False) or [line[:width]]
    body = "\n".join(line + "\033[K" for line in out[:size.lines - 2])
    sys.stdout.write("\033[H" + body + "\n\033[J")
    sys.stdout.flush()


def _resume_pending():
    """A batch continues at this/the next boot: its resume queue exists until the resumed pytest starts."""
    if os.name == "nt":
        return (LOGS_DIR / "win_resume_args.txt").exists()
    return (DEFAULT_STATE_DIR / "next_test.txt").exists()


def _wait_for_enter(seconds):
    """True if Enter is pressed within `seconds` (keeps the window updating meanwhile)."""
    if os.name != "nt":
        import select
        if not (sys.stdin and sys.stdin.isatty()):
            time.sleep(seconds)
            return False
        ready, _, _ = select.select([sys.stdin], [], [], seconds)
        if ready:
            sys.stdin.readline()
        return bool(ready)
    import msvcrt
    end = time.time() + seconds
    while time.time() < end:
        while msvcrt.kbhit():
            if msvcrt.getwch() in ("\r", "\n"):
                return True
        time.sleep(0.2)
    return False


def _show_final(prompt=""):
    summary = _load(LAST_BATCH_FILE)
    lines = _final_frame(summary) if summary.get("order") else ["No test batch is running."]
    _draw(lines + (["", prompt] if prompt else []))
    try:
        SHOWN_FILE.write_text(summary.get("batch_id", ""), encoding="utf-8")
    except OSError:
        pass


def show():
    _prepare_console()
    try:
        while True:
            _touch_alive()
            rows = shutil.get_terminal_size((100, 40)).lines - 2
            plan = _load(PREFLIGHT_PLAN)
            if BATCH_FILE.exists():
                batch = _load(BATCH_FILE)
                if batch.get("order"):  # else: read while being rewritten -- next round
                    _draw(_running_frame(batch, rows))
            elif plan.get("status") == "running":
                _draw(_preflight_frame(plan, rows))
            elif _resume_pending():
                _draw(["Waiting for the tests to continue after the reboot ..."])
            else:
                # Stay on the latest result until Enter; switch back by itself if the next run starts
                _show_final(" 👉 No test is running. Press Enter to close this window "
                            "(it switches to the next run by itself).")
                if _wait_for_enter(REFRESH_SECS):
                    return 0
                continue
            time.sleep(REFRESH_SECS)
    except KeyboardInterrupt:
        return 0
    finally:
        try:
            ALIVE_FILE.unlink()
        except OSError:
            pass


def _current_log():
    """The log to follow now: this boot's test log of the running batch, else the pre-flight log."""
    log_dirs = _load(BATCH_FILE).get("log_dirs") or []
    if log_dirs:
        return Path(log_dirs[-1]) / "test_execution.log"
    if _load(PREFLIGHT_PLAN).get("status") == "running":
        return PREFLIGHT_LOG
    return None


def _backlog_offset(path):
    """Byte offset of the last LOG_BACKLOG_LINES lines, so a window opened mid-run starts with context."""
    try:
        data = path.read_bytes()
    except OSError:
        return 0
    cut = len(data)
    for _ in range(LOG_BACKLOG_LINES + 1):
        cut = data.rfind(b"\n", 0, cut)
        if cut < 0:
            return 0
    return cut + 1


def _print_new_lines(path, offset):
    """Print the complete lines added to `path` since `offset`; returns the new offset."""
    try:
        with open(path, "rb") as fh:
            size = fh.seek(0, os.SEEK_END)
            if size < offset:
                offset = 0  # file was recreated
            fh.seek(offset)
            data = fh.read()
    except OSError:
        return offset
    end = data.rfind(b"\n") + 1
    colors = {"ERROR": "\033[31m", "CRITICAL": "\033[31m", "WARNING": "\033[33m"}
    for raw in data[:end].decode("utf-8", errors="replace").splitlines():
        formatted = _format_line(raw)
        if formatted:
            text, level = formatted
            print(f"{colors[level]}{text}\033[0m" if level in colors else text)
    sys.stdout.flush()
    return offset + end


def follow_log():
    """Show the running batch's test log as it grows, switching to the next log after a reboot."""
    _prepare_console(LOG_TITLE)
    print(f" {LOG_TITLE} -- what the tests are doing and what they need from you.")
    print(" Closing this window does not stop the tests.")
    current, offset, idle_noted, first = None, 0, False, True
    try:
        while True:
            _touch_alive(LOG_ALIVE_FILE)
            path = _current_log()
            if path is not None and path != current and path.exists():
                current = path
                print(f"\n\033[36m===== {_short(path)} =====\033[0m")
                offset = _backlog_offset(path) if first else 0
                first, idle_noted = False, False
            if current is not None:
                offset = _print_new_lines(current, offset)
            if path is None and not batch_running() and not _resume_pending():
                if not idle_noted:
                    print("\n 👉 No test is running (final result: status window / test_runner.py -> L).\n"
                          "    This window continues with the next run by itself. Press Enter to close it.")
                    idle_noted = True
                if _wait_for_enter(1):
                    return 0
                continue
            time.sleep(1)
    except KeyboardInterrupt:
        return 0
    finally:
        try:
            LOG_ALIVE_FILE.unlink()
        except OSError:
            pass


def launch():
    """Open the window in a new console / terminal when there is something to show and none is open."""
    # A window opened in the boot session would be invisible and block the one opened at sign-in.
    if _in_boot_session() or not (batch_running() or _resume_pending() or finished_unseen()):
        return 0
    python = Path(sys.executable)
    if python.name.lower() == "pythonw.exe":
        python = python.with_name("python.exe")  # the logon task starts us without a console
    cmd = [str(python), str(Path(__file__).resolve())]
    # Status window + live test log window; each claims its alive file first so two launches don't open two
    windows = [(ALIVE_FILE, [], TITLE)]
    if batch_running() or _resume_pending():
        windows.append((LOG_ALIVE_FILE, ["--log"], LOG_TITLE))
    if os.name == "nt":
        for alive_file, extra, _title in windows:
            if _claim_window(alive_file):
                subprocess.Popen(cmd + extra, cwd=REPO_ROOT, creationflags=subprocess.CREATE_NEW_CONSOLE)
        return 0
    if not (os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY")):
        return 0  # no desktop session (e.g. the systemd resume service): the login autostart opens it
    terminal = next((t for t in (("gnome-terminal", "--title={title}", "--"), ("x-terminal-emulator", "-e"),
                                 ("konsole", "-e"), ("xterm", "-e")) if shutil.which(t[0])), None)
    if terminal is None:
        print(f"No terminal emulator found -- show the status with: python3 {Path(__file__).resolve()}")
        return 1
    for alive_file, extra, title in windows:
        if _claim_window(alive_file):
            argv = [part.format(title=title) for part in terminal]
            subprocess.Popen(argv + cmd + extra, cwd=REPO_ROOT, start_new_session=True)
    return 0


def install(quiet=False):
    if os.name == "nt":
        return _install_windows(quiet)
    AUTOSTART.parent.mkdir(parents=True, exist_ok=True)
    AUTOSTART.write_text(
        "[Desktop Entry]\n"
        "Type=Application\n"
        f"Name={TITLE}\n"
        "Comment=Shows the test batch status (reboots, next BIOS step) after every reboot\n"
        f'Exec="{sys.executable}" "{Path(__file__).resolve()}" --launch\n'
        "X-GNOME-Autostart-enabled=true\n"
        "X-GNOME-Autostart-Delay=5\n"
        "NoDisplay=true\n",
        encoding="utf-8",
    )
    try:
        OLD_AUTOSTART.unlink()
    except OSError:
        pass
    if not quiet:
        print(f"[OK] Login window installed: {AUTOSTART}")
    return 0


def windows_task_installed():
    return subprocess.run(["schtasks", "/query", "/tn", WIN_LOGON_TASK], capture_output=True, timeout=15).returncode == 0


def _install_windows(quiet=False):
    """Logon task: opens this window when any administrator signs in while a batch / pre-flight runs at boot."""
    pythonw = Path(sys.executable).with_name("pythonw.exe")
    task_cmd = f'"{pythonw if pythonw.exists() else sys.executable}" "{Path(__file__).resolve()}" --launch'
    # HIGHEST: the logs may sit in another admin's profile, which a filtered (UAC) token cannot read
    create = ["schtasks", "/create", "/tn", WIN_LOGON_TASK, "/tr", task_cmd, "/sc", "ONLOGON", "/rl", "HIGHEST", "/f"]
    out = subprocess.run(create + ["/ru", r"BUILTIN\Administrators"], capture_output=True, text=True, timeout=30)
    if out.returncode != 0:
        # Localized Windows names the group differently -- fall back to the current account
        out = subprocess.run(create, capture_output=True, text=True, timeout=30)
    if out.returncode != 0:
        print(f"[WARN] Could not create the logon task {WIN_LOGON_TASK}: {out.stderr.strip()}")
        return 1
    if not quiet:
        print(f"[OK] Logon task installed: {WIN_LOGON_TASK}")
    return 0


def uninstall():
    if os.name == "nt":
        out = subprocess.run(["schtasks", "/delete", "/tn", WIN_LOGON_TASK, "/f"], capture_output=True, timeout=15)
        print(f"[OK] Removed {WIN_LOGON_TASK}" if out.returncode == 0 else "Nothing to remove.")
        return 0
    removed = False
    for path in (AUTOSTART, OLD_AUTOSTART):
        try:
            path.unlink()
            print(f"[OK] Removed {path}")
            removed = True
        except OSError:
            pass
    if not removed:
        print("Nothing to remove.")
    return 0


def main():
    ap = argparse.ArgumentParser(description="Show the test batch status (reboots, next BIOS step).")
    group = ap.add_mutually_exclusive_group()
    group.add_argument("--install", action="store_true",
                       help="Linux: add the desktop login autostart entry; Windows: add the logon task")
    group.add_argument("--uninstall", action="store_true", help="remove the autostart entry / logon task")
    group.add_argument("--launch", action="store_true", help="open a new window only if there is a batch to show")
    group.add_argument("--log", action="store_true", help="follow the running batch's test log in this window")
    args = ap.parse_args()
    if args.install:
        return install()
    if args.uninstall:
        return uninstall()
    if args.launch:
        return launch()
    if args.log:
        return follow_log()
    return show()


if __name__ == "__main__":
    sys.exit(main())
