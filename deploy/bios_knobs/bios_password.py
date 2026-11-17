# Copyright 2026 Intel Corporation
# SPDX-License-Identifier: Apache-2.0
"""
deploy/bios_knobs/bios_password.py — the AMI BIOS Administrator password for AMISCE (/cpwd), Linux SUT.

With AmiSetupNvLock, AMISCE changes protected setup variables (e.g. CpuSetup: TME, VMX,
TXT) only with the BIOS Administrator password, and it cannot set the FIRST admin
password itself -- that is typed once in BIOS Setup. So that nobody keeps the password
in config/test_config.yaml:

  - test_runner.py asks for it once, through 'configure_bios_knobs_linux.py password --set'
    (getpass, run with sudo -- the password never passes through test_runner.py), and this
    module stores it ENCRYPTED with systemd-creds and the machine's host key
    (/var/lib/systemd/credential.secret, root-only; not the TPM, which the measured boot
    tests clear). Without systemd-creds it falls back to a root-only (0600) file.
  - No admin password in the BIOS yet: the pre-flight reboots into BIOS Setup once, you
    type the same password (Security -> Administrator Password), and after the boot the
    pre-flight checks that the BIOS now has one (preflight_chain.verify_bios_password).
  - Whether the BIOS has an admin password, and whether it changed since it was stored,
    is read from AMITSESetup (core/bios_knob_checks.ami_admin_password) -- no root, no reboot.
  - A password the BIOS rejects (AMISCE exit 0x82/0x86/0x8F/0x9A) is forgotten, so the next
    pre-flight asks again.

Files (the directory is root-owned; FW_VALIDATION_LIB overrides it for testing):
  /var/lib/fw-validation/bios_admin_password.cred   encrypted password (0600)
  /var/lib/fw-validation/bios_admin_password.json   status, no secret (0644, read by test_runner.py)

Standard library only (also imported by the pre-flight under the system python3).
"""

import getpass
import json
import os
import subprocess
import sys
from datetime import datetime
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
from core import bios_knob_checks  # noqa: E402

LIB_DIR = Path(os.environ.get("FW_VALIDATION_LIB", "/var/lib/fw-validation"))
SECRET_FILE = LIB_DIR / "bios_admin_password.cred"
STATUS_FILE = LIB_DIR / "bios_admin_password.json"
CRED_NAME = "fw-bios-admin-password"
SOURCE_LABEL = "the stored BIOS admin password (encrypted on this SUT)"

MIN_LEN, MAX_LEN = 3, 20                 # AMI TSE defaults; AdminPassword is CHAR16[20]
UEFI_SHELL_UNSAFE = set('"^%#')          # passed to AMISCE through maintest.nsh


def _now():
    return datetime.now().isoformat(timespec="seconds")


def read_status():
    try:
        return json.loads(STATUS_FILE.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def _write_status(info):
    LIB_DIR.mkdir(parents=True, exist_ok=True)
    STATUS_FILE.write_text(json.dumps(info, indent=2), encoding="utf-8")
    os.chmod(STATUS_FILE, 0o644)


def is_stored():
    return bool(read_status().get("stored")) and SECRET_FILE.exists()


def problem(password):
    """Why this password cannot be used, or '' if it can."""
    if not MIN_LEN <= len(password) <= MAX_LEN:
        return f"use {MIN_LEN} to {MAX_LEN} characters"
    bad = sorted({c for c in password if c in UEFI_SHELL_UNSAFE or not (" " <= c <= "~")})
    if bad:
        return "use printable ASCII without " + " ".join(repr(c) for c in bad) + " (the UEFI Shell cannot pass them)"
    if password != password.strip():
        return "no spaces at the start or end"
    return ""


# ------------------------------------------------------------------
# Encrypted storage (root)
# ------------------------------------------------------------------

def _systemd_creds(*args, data):
    try:
        out = subprocess.run(["systemd-creds", *args], input=data, capture_output=True, timeout=60)
    except (OSError, subprocess.SubprocessError):
        return None
    return out.stdout if out.returncode == 0 else None


def save(password, pending_bios_setup=False):
    """Store the password encrypted (root). pending_bios_setup: it still has to be typed in BIOS Setup."""
    why = problem(password)
    if why:
        raise ValueError(why)
    LIB_DIR.mkdir(parents=True, exist_ok=True)
    _systemd_creds("setup", data=b"")            # creates the host key once; harmless if it exists
    blob = _systemd_creds("encrypt", "--with-key=host", f"--name={CRED_NAME}", "-", "-",
                          data=password.encode("utf-8"))
    method = "systemd-creds (host key)" if blob else "root-only file (systemd-creds not available)"
    data = blob or password.encode("utf-8")
    fd = os.open(SECRET_FILE, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(data)
    os.chmod(SECRET_FILE, 0o600)
    _is_set, fingerprint = bios_knob_checks.ami_admin_password()
    _write_status({
        "stored": _now(), "method": method, "encrypted": bool(blob),
        "bios": bios_knob_checks.bios_identity(),
        # The BIOS password this one belongs to (None until the BIOS has one).
        "fingerprint": None if pending_bios_setup else fingerprint,
        "pending_bios_setup": bool(pending_bios_setup), "verified": None,
    })
    return method


def load():
    """The stored password (root), or '' if none is stored or it cannot be decrypted."""
    info = read_status()
    try:
        data = SECRET_FILE.read_bytes()
    except OSError:
        return ""
    if info.get("encrypted"):
        data = _systemd_creds("decrypt", f"--name={CRED_NAME}", "-", "-", data=data)
        if data is None:
            return ""
    return data.decode("utf-8", errors="replace").rstrip("\n")


def forget(reason=""):
    """Delete the stored password (root); the next pre-flight asks again."""
    for path in (SECRET_FILE, STATUS_FILE):
        try:
            path.unlink()
        except OSError:
            pass
    return reason


def _update(**changes):
    info = read_status()
    if not info:
        return
    info.update(changes)
    _write_status(info)


def mark_set_in_bios():
    """After the BIOS Setup reboot: the BIOS now has an admin password -- remember which one."""
    _is_set, fingerprint = bios_knob_checks.ami_admin_password()
    _update(fingerprint=fingerprint, pending_bios_setup=False)


def mark_verified():
    """AMISCE accepted the stored password (/cpwd, exit 0)."""
    _is_set, fingerprint = bios_knob_checks.ami_admin_password()
    _update(fingerprint=fingerprint, pending_bios_setup=False, verified=_now())


# ------------------------------------------------------------------
# Status (no root) and prompt
# ------------------------------------------------------------------

def status():
    """
    {'state', 'message', 'bios_has_password', 'stored'} -- no root needed. state:
      ok       stored, and the BIOS still has that admin password
      missing  the BIOS has an admin password, none is stored        -> type it once
      changed  stored, but the BIOS admin password changed since    -> type the new one
      none     the BIOS has no admin password, none stored           -> set one up in BIOS Setup
      cleared  stored, but the BIOS has no admin password any more (IFWI flashed?) -> set up again
      pending  stored, but not typed in BIOS Setup yet               -> set up (BIOS Setup reboot)
      unknown  the BIOS password state cannot be read here (not an AMI BIOS / Windows)
    """
    is_set, fingerprint = bios_knob_checks.ami_admin_password()
    info = read_status()
    stored = bool(info.get("stored"))
    result = {"bios_has_password": is_set, "stored": stored}
    if is_set is None:
        return dict(result, state="ok" if stored else "unknown",
                    message="stored" if stored else "the BIOS password state cannot be read here")
    if is_set:
        if not stored:
            return dict(result, state="missing", message="the BIOS has an admin password, but it is not stored here")
        if info.get("fingerprint") and info["fingerprint"] != fingerprint:
            return dict(result, state="changed",
                        message="the BIOS admin password changed since it was stored")
        return dict(result, state="ok", message=f"stored ({info.get('method', '?')}, {info.get('stored', '?')})")
    if stored and info.get("pending_bios_setup"):
        return dict(result, state="pending", message="stored, but not set in BIOS Setup yet")
    if stored:
        return dict(result, state="cleared",
                    message="the BIOS has no admin password any more (IFWI flashed or cleared in BIOS Setup)")
    return dict(result, state="none", message="the BIOS has no admin password yet")


def prompt(new):
    """Ask for the password twice (getpass, nothing echoed); '' if cancelled."""
    if new:
        print(f"Choose the BIOS Administrator password ({MIN_LEN}-{MAX_LEN} characters). You type it once more")
        print("in BIOS Setup after the reboot, so use something you can type on the SUT's keyboard.")
    else:
        print("Type the BIOS Administrator password that is set in BIOS Setup (Security -> Administrator Password).")
    for _ in range(3):
        try:
            first = getpass.getpass("  BIOS admin password : ")
            if not first:
                return ""
            why = problem(first)
            if why:
                print(f"  ✗ {why}. Try again (empty = cancel).")
                continue
            if getpass.getpass("  Type it again       : ") != first:
                print("  ✗ The two entries differ. Try again (empty = cancel).")
                continue
            return first
        except (KeyboardInterrupt, EOFError):
            print()
            return ""
    return ""
