#!/usr/bin/env python3
# Copyright 2026 Intel Corporation
# SPDX-License-Identifier: Apache-2.0
"""
deploy/secure_boot/sb_keys.py — whose Secure Boot keys are in the firmware (Linux SUT, read-only).

The 'provision' stage of enable_secure_boot.sh (sb-setup enroll) makes our own
test key the owner of the firmware:
    PK = test-cert     KEK = test-cert + Microsoft     db = Microsoft
and sign_efi_tools.sh then adds test-cert to db, so the UEFI Shell runs the
tools it signs. A BIOS that still holds its factory keys (e.g. AMI
"Platform Key") can have Secure Boot switched on in BIOS Setup, but then
nothing we sign is trusted and db cannot be changed from the OS -- so
"Secure Boot enabled" alone is not enough. The certificates are compared
byte for byte with our own certificate, not by name.

Owner (from PK and KEK):
  setup    no PK enrolled (Setup Mode) -- 'provision' can enroll ours
  partial  PK is ours, KEK does not hold ours yet -- run 'provision' again
  ours     PK and KEK hold our certificate -- we can sign tools and update db
  foreign  PK is not ours (factory keys) -- clear the keys in BIOS Setup first
  unknown  the EFI variables cannot be read

Usage:
  python3 deploy/secure_boot/sb_keys.py status       # summary of PK/KEK/db + owner
  python3 deploy/secure_boot/sb_keys.py owner        # prints setup|partial|ours|foreign|unknown
  python3 deploy/secure_boot/sb_keys.py has db       # exit 0 if our certificate is in db (or PK, KEK)
  python3 deploy/secure_boot/sb_keys.py ready        # exit 0 if Secure Boot is on with our keys + db
  python3 deploy/secure_boot/sb_keys.py knob         # AMI 'Secure Boot' setup knob: enabled|disabled|unknown

  --cert PATH   our certificate, PEM or DER (default: $DB_KEY_DIR/$DB_CERT_FILE,
                i.e. /etc/secureboot/key-material/test-cert.pem written by 'provision')

Standard library only; openssl, when present, is used only to print certificate names.
"""

import argparse
import base64
import hashlib
import os
import shutil
import struct
import subprocess
import sys
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Tuple

EFIVARS_DIR = Path("/sys/firmware/efi/efivars")
EFI_GLOBAL = "8be4df61-93ca-11d2-aa0d-00e098032b8c"
IMAGE_SECURITY_DB = "d719b2cb-3d3a-4596-a3bc-dad00e67656f"
VAR_GUIDS = {"PK": EFI_GLOBAL, "KEK": EFI_GLOBAL, "db": IMAGE_SECURITY_DB, "dbx": IMAGE_SECURITY_DB,
             "SecureBoot": EFI_GLOBAL, "SetupMode": EFI_GLOBAL}
EFI_CERT_X509 = uuid.UUID("a5c059a1-94e4-4aa7-87b5-ab155c2bf072")
# AMI Aptio: the 'Secure Boot' setup knob (byte 0; 1 = Enabled) of the BIOS Setup Secure Boot page.
AMI_SB_SETUP_VAR = "SecureBootSetup-7b59104a-c00d-4158-87ff-f04d6396a915"
DEFAULT_CERT = (Path(os.environ.get("DB_KEY_DIR", "/etc/secureboot/key-material"))
                / os.environ.get("DB_CERT_FILE", "test-cert.pem"))

OWNER_TEXT = {
    "setup": "no Platform Key enrolled (Setup Mode) -- 'provision' can enroll our keys",
    "partial": "PK is ours but KEK does not hold our certificate yet -- run 'provision' again",
    "ours": "PK and KEK hold our certificate -- tools can be signed and db updated from the OS",
    "foreign": "PK is NOT ours (factory / someone else's keys) -- nothing we sign is trusted",
    "unknown": "the Secure Boot EFI variables cannot be read",
}


def read_var(name: str) -> Optional[bytes]:
    """Variable data without its 4 attribute bytes; b'' if absent, None if efivars cannot be read."""
    if not EFIVARS_DIR.is_dir():
        return None
    try:
        data = (EFIVARS_DIR / f"{name}-{VAR_GUIDS[name]}").read_bytes()
    except FileNotFoundError:
        return b""
    except OSError:
        return None
    return data[4:]


def read_flag(name: str) -> Optional[bool]:
    data = read_var(name)
    return bool(data[0]) if data else None


def ami_knob() -> Optional[bool]:
    """AMI BIOS 'Secure Boot' setup knob: True = Enabled, False = Disabled, None = not an AMI layout."""
    try:
        data = (EFIVARS_DIR / AMI_SB_SETUP_VAR).read_bytes()
    except OSError:
        return None
    return data[4] == 1 if len(data) >= 5 and data[4] in (0, 1) else None


def sb_dbx_entries(data: bytes) -> int:
    """Number of signatures (hashes / certificates) in an EFI_SIGNATURE_LIST chain such as dbx."""
    count = 0
    off = 0
    while off + 28 <= len(data):
        list_size, header_size, sig_size = struct.unpack_from("<III", data, off + 16)
        if list_size < 28 or off + list_size > len(data):
            break
        if sig_size:
            count += (list_size - 28 - header_size) // sig_size
        off += list_size
    return count


def x509_certs(data: bytes) -> List[bytes]:
    """DER certificates in an EFI_SIGNATURE_LIST chain (other signature types are skipped)."""
    certs = []
    off = 0
    while off + 28 <= len(data):
        sig_type = uuid.UUID(bytes_le=data[off:off + 16])
        list_size, header_size, sig_size = struct.unpack_from("<III", data, off + 16)
        if list_size < 28 or off + list_size > len(data):
            break
        if sig_type == EFI_CERT_X509 and sig_size > 16:
            pos = off + 28 + header_size
            while pos + sig_size <= off + list_size:
                certs.append(data[pos + 16:pos + sig_size])   # skip the 16-byte SignatureOwner GUID
                pos += sig_size
        off += list_size
    return certs


def load_cert(path) -> Optional[bytes]:
    """DER bytes of a PEM or DER certificate file, or None if it cannot be read."""
    try:
        raw = Path(path).read_bytes()
    except OSError:
        return None
    begin, end = b"-----BEGIN CERTIFICATE-----", b"-----END CERTIFICATE-----"
    if begin in raw:
        body = raw.split(begin, 1)[1].split(end, 1)[0]
        try:
            return base64.b64decode(b"".join(body.split()), validate=True)
        except ValueError:
            return None
    return raw or None


def cert_name(der: bytes) -> str:
    if shutil.which("openssl"):
        try:
            out = subprocess.run(["openssl", "x509", "-inform", "DER", "-noout", "-subject"],
                                 input=der, capture_output=True, timeout=10)
            text = out.stdout.decode(errors="replace").strip()
            if out.returncode == 0 and text:
                return text.split("=", 1)[1].strip() if text.lower().startswith("subject") else text
        except (OSError, subprocess.SubprocessError):
            pass
    return "sha256:" + hashlib.sha256(der).hexdigest()[:16]


@dataclass
class KeyState:
    readable: bool
    secure_boot: Optional[bool]
    setup_mode: Optional[bool]
    cert_path: str
    cert: Optional[bytes]
    pk: List[bytes] = field(default_factory=list)
    kek: List[bytes] = field(default_factory=list)
    db: List[bytes] = field(default_factory=list)

    def has(self, var: str) -> bool:
        return self.cert is not None and self.cert in getattr(self, var.lower())

    @property
    def owner(self) -> str:
        if not self.readable:
            return "unknown"
        if not self.pk:
            return "setup"
        if not self.has("PK"):
            return "foreign"
        return "ours" if self.has("KEK") else "partial"


def read_state(cert_path=None) -> KeyState:
    cert_path = str(cert_path or DEFAULT_CERT)
    raw = {name: read_var(name) for name in ("PK", "KEK", "db")}
    return KeyState(
        readable=raw["PK"] is not None,
        secure_boot=read_flag("SecureBoot"),
        setup_mode=read_flag("SetupMode"),
        cert_path=cert_path,
        cert=load_cert(cert_path),
        pk=x509_certs(raw["PK"] or b""),
        kek=x509_certs(raw["KEK"] or b""),
        db=x509_certs(raw["db"] or b""),
    )


def ready(cert_path=None) -> Tuple[bool, str]:
    """(True, why) if Secure Boot is on, PK/KEK are ours and our certificate is in db."""
    state = read_state(cert_path)
    if state.secure_boot is not True:
        return False, "Secure Boot is " + ("DISABLED" if state.secure_boot is False else "unknown")
    owner = state.owner
    if owner != "ours":
        return False, f"Secure Boot is ENABLED, but keys are {owner}: {OWNER_TEXT[owner]}"
    if not state.has("db"):
        return False, "Secure Boot is ENABLED with our PK/KEK, but our certificate is not in db yet (tools not trusted)"
    return True, "Secure Boot is ENABLED with our own keys (PK/KEK/db)"


def print_status(state: KeyState) -> None:
    flag = {True: "ENABLED", False: "DISABLED", None: "unknown"}
    print(f"Secure Boot  : {flag[state.secure_boot]}   (SetupMode={ {True: 1, False: 0, None: '?'}[state.setup_mode] })")
    knob = ami_knob()
    if knob is not None:
        print(f"BIOS knob    : 'Secure Boot' = {'Enabled' if knob else 'Disabled'} (AMI SecureBootSetup)"
              + ("" if knob else " -- Secure Boot stays off even with our keys until this is Enabled"))
    if state.cert is None:
        print(f"Our cert     : {state.cert_path} -- not found (created by the 'provision' stage)")
    else:
        print(f"Our cert     : {state.cert_path} ({cert_name(state.cert)})")
    for var in ("PK", "KEK", "db"):
        certs = getattr(state, var.lower())
        if not state.readable:
            print(f"{var:<4}         : cannot be read")
            continue
        if not certs:
            print(f"{var:<4}         : (empty)")
            continue
        for i, der in enumerate(certs):
            mark = "  <- ours" if der == state.cert else ""
            print(f"{var if i == 0 else '':<4}         : {cert_name(der)}{mark}")
    print(f"Key owner    : {state.owner} -- {OWNER_TEXT[state.owner]}")
    print(f"Ours in db   : {'yes' if state.has('db') else 'no'}")
    dbx = read_var("dbx")
    if dbx is not None:
        print(f"dbx          : {sb_dbx_entries(dbx)} revocation entries"
              + (" (empty -- the Ubuntu dbx update is applied at the next boot and changes PCR 7 once)" if not dbx else ""))


def main() -> int:
    ap = argparse.ArgumentParser(description="Show whose Secure Boot keys (PK/KEK/db) are in the firmware.")
    ap.add_argument("--cert", default=str(DEFAULT_CERT), help=f"our certificate, PEM or DER (default: {DEFAULT_CERT})")
    sub = ap.add_subparsers(dest="command", required=True)
    sub.add_parser("status", help="summary of PK/KEK/db and the key owner")
    sub.add_parser("owner", help="print setup|partial|ours|foreign|unknown")
    has = sub.add_parser("has", help="exit 0 if our certificate is in the variable")
    has.add_argument("var", choices=["PK", "KEK", "db"])
    sub.add_parser("ready", help="exit 0 if Secure Boot is on with our PK/KEK and our certificate in db")
    sub.add_parser("knob", help="AMI BIOS 'Secure Boot' setup knob: prints enabled|disabled|unknown")
    args = ap.parse_args()

    if args.command == "knob":
        print({True: "enabled", False: "disabled", None: "unknown"}[ami_knob()])
        return 0

    if args.command == "ready":
        passed, why = ready(args.cert)
        print(why)
        return 0 if passed else 1
    state = read_state(args.cert)
    if args.command == "status":
        print_status(state)
    elif args.command == "owner":
        print(state.owner)
    elif args.command == "has":
        return 0 if state.has(args.var) else 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
