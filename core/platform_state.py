# Copyright 2026 Intel Corporation
# SPDX-License-Identifier: Apache-2.0

"""
core/platform_state.py -- read-only snapshot of the SUT security state for the test log.

Logged in every session header (so the batch log shows it again after each reboot) and as
one line in the batch final summary: BIOS build, Secure Boot, TPM, VBS / memory integrity /
kernel CET (Windows) and the BIOS knobs the selected tests need (deploy/bios_knobs/bios_knobs.yaml),
read back the same way as the pre-flight (core/bios_knob_checks.py).

Never raises and never decides a verdict: anything it cannot read is logged as unknown.
"""

import platform
import subprocess
import sys
from pathlib import Path
from typing import Iterable, List, Optional, Tuple

from core import bios_knob_checks, test_selection

REPO_ROOT = Path(__file__).resolve().parents[1]
_SECURE_BOOT_EFIVAR = Path("/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c")
# Win32_DeviceGuard.SecurityServicesRunning: 2 = memory integrity (HVCI), 5 = kernel-mode HSP (CET)
_HVCI, _KERNEL_CET = 2, 5
_STATE = {True: "ENABLED", False: "DISABLED", None: "unknown"}


def _is_windows() -> bool:
    return platform.system() == "Windows"


def secure_boot() -> Tuple[Optional[bool], str]:
    """(on, how it was read); on is None when it cannot be read."""
    if _is_windows():
        try:
            import winreg
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\SecureBoot\State") as key:
                value = winreg.QueryValueEx(key, "UEFISecureBootEnabled")[0]
            return value == 1, f"UEFISecureBootEnabled = {value}"
        except OSError as exc:
            return None, f"SecureBoot\\State not readable ({exc.strerror or exc})"
    try:
        data = _SECURE_BOOT_EFIVAR.read_bytes()
        if len(data) >= 5:
            return data[4] == 1, f"efivars SecureBoot = {data[4]}"
    except OSError:
        pass
    try:
        out = subprocess.run(["mokutil", "--sb-state"], capture_output=True, text=True, timeout=10)
        text = (out.stdout + out.stderr).strip()
        if "enabled" in text.lower():
            return True, f"mokutil: {text}"
        if "disabled" in text.lower():
            return False, f"mokutil: {text}"
    except (OSError, subprocess.SubprocessError):
        pass
    return None, "no SecureBoot efivar and no mokutil"


def tpm() -> str:
    maker = bios_knob_checks.tpm_manufacturer()
    if not maker:
        return "unknown (TPM manufacturer not readable)"
    return f"{maker} ({'PTT' if maker == 'INTC' else 'dTPM'})"


def windows_isolation() -> List[Tuple[str, str]]:
    """[(label, value)] for VBS / memory integrity / kernel-mode CET; empty off Windows."""
    if not _is_windows():
        return []
    script = ("$dg = Get-CimInstance -Namespace root\\Microsoft\\Windows\\DeviceGuard -ClassName Win32_DeviceGuard;"
              "'vbs=' + $dg.VirtualizationBasedSecurityStatus; 'running=' + (@($dg.SecurityServicesRunning) -join ',')")
    try:
        out = subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
                             capture_output=True, text=True, errors="replace", timeout=60).stdout
    except (OSError, subprocess.SubprocessError) as exc:
        return [("VBS / HVCI", f"unknown ({exc})")]
    fields = dict(line.split("=", 1) for line in out.splitlines() if "=" in line)
    if "vbs" not in fields:
        return [("VBS / HVCI", "unknown (Win32_DeviceGuard not readable)")]
    running = [int(v) for v in fields.get("running", "").split(",") if v.strip().isdigit()]
    vbs = {"0": "off", "1": "enabled, not running", "2": "running"}.get(fields["vbs"].strip(), fields["vbs"])
    raw = f"(SecurityServicesRunning = {fields.get('running') or 'none'})"
    return [
        ("VBS / HVCI", f"VBS {vbs}, Memory integrity {'running' if _HVCI in running else 'not running'}"),
        ("Kernel CET", f"{'running' if _KERNEL_CET in running else 'not running'} {raw}"),
    ]


def knob_lines(node_ids: Iterable[str]) -> List[str]:
    """Read-back of the BIOS knobs (bios_knobs.yaml) the given tests need."""
    specs = sorted({spec for spec in map(test_selection.bios_knob_spec, node_ids) if spec})
    if not specs:
        return [f"  {'BIOS knobs':<13} : none needed by the selected tests"]
    knob_dir = str(REPO_ROOT / "deploy" / "bios_knobs")
    if knob_dir not in sys.path:
        sys.path.insert(0, knob_dir)
    import bios_knob_common
    try:
        profile, label = bios_knob_common.resolve_markers(bios_knob_common.DEFAULT_CONFIG, specs)
    except Exception as exc:  # noqa: BLE001 -- e.g. PTT and dTPM tests picked together
        return [f"  {'BIOS knobs':<13} : unknown ({exc})"]
    wanted = {**(profile or {}).get("knobs", {}), **(profile or {}).get("verify_knobs", {})}
    if not wanted:
        return [f"  {'BIOS knobs':<13} : none needed by the selected tests ({', '.join(specs)})"]
    results = bios_knob_checks.check_knobs(wanted, attested=True)
    return ([f"  BIOS knobs needed by the selected tests ({label}):"]
            + bios_knob_checks.format_results(results, indent="    "))


def snapshot_lines(node_ids: Iterable[str]) -> List[str]:
    """The [Platform Security State] block of the session header."""
    lines = ["[Platform Security State]"]

    def add(label: str, read) -> None:
        try:
            value = read()
        except Exception as exc:  # noqa: BLE001 -- a snapshot must never break the run
            value = f"unknown ({exc})"
        lines.append(f"  {label:<13} : {value}")

    def bios() -> str:
        ident = bios_knob_checks.bios_identity()
        return f"{ident['vendor']} {ident['version']} ({ident['date']})".strip() or "unknown"

    def sb() -> str:
        on, how = secure_boot()
        return f"{_STATE[on]:<9} ({how})"

    add("BIOS", bios)
    add("Boot", bios_knob_checks.boot_id)
    add("Secure Boot", sb)
    add("TPM", tpm)
    try:
        for label, value in windows_isolation():
            lines.append(f"  {label:<13} : {value}")
    except Exception as exc:  # noqa: BLE001
        lines.append(f"  {'VBS / HVCI':<13} : unknown ({exc})")
    try:
        lines += knob_lines(node_ids)
    except Exception as exc:  # noqa: BLE001
        lines.append(f"  {'BIOS knobs':<13} : unknown ({exc})")
    return lines


def summary_line() -> str:
    """One line for the batch final summary."""
    parts = []
    try:
        on, _how = secure_boot()
        parts.append(f"Secure Boot {_STATE[on]}")
    except Exception:  # noqa: BLE001
        parts.append("Secure Boot unknown")
    try:
        parts.append(f"TPM {tpm()}")
    except Exception:  # noqa: BLE001
        parts.append("TPM unknown")
    try:
        parts.append(f"BIOS {bios_knob_checks.bios_identity()['version'] or 'unknown'}")
    except Exception:  # noqa: BLE001
        parts.append("BIOS unknown")
    return " | ".join(parts)
