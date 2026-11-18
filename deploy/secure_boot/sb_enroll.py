#!/usr/bin/env python3
# Copyright 2026 Intel Corporation
# SPDX-License-Identifier: Apache-2.0
"""
deploy/secure_boot/sb_enroll.py — enroll OUR Secure Boot keys (db, KEK, PK) from Linux (root).

Called by the 'provision' stage of enable_secure_boot.sh. Replaces Ubuntu's
sb-setup/sbkeysync for the enrollment because, on AMI firmware, sb-setup left
the firmware without a PK:
  - its certificate is valid for 30 days only, and is reused after it expired;
  - sbvarsign stores the signing month off by one (May for a June signature;
    month 0 in January), so the PK update looked signed before the certificate
    was valid -- the firmware verifies the self-signed PK and refused it
    ("Error writing key update: Invalid argument" = EFI_INVALID_PARAMETER);
  - every efivarfs PK/KEK/db file is immutable as soon as it exists, so the
    second entry sbkeysync appended to db/KEK failed ("Operation not permitted").

What it does:
  1. Setup Mode (no PK): (re)creates our key when the certificate is missing or
     expires within a year -- RSA-2048, SHA-256, valid SB_KEY_DAYS days
     (default 3650), same files as before in DB_KEY_DIR:
       test-key.rsa (private), test-cert.pem, test-cert.der
     The previous key folder and the sbkeysync keystore are kept as *.bak-<time>.
  2. Signs each update itself (openssl cms, detached, no attributes, current UTC
     time with the right month) as an EFI_VARIABLE_AUTHENTICATION_2 payload.
  3. Writes, clearing the immutable flag before each write:
       Setup Mode   : db = Microsoft PCA + UEFI CA 2011 + ours,
                      KEK = Microsoft KEK CA 2011 + ours, PK = ours (last)
       PK ours only : KEK, then db (signed with our PK / KEK key)
  4. Reads the variables back (sb_keys.py): PK and KEK must hold our certificate
     and db must hold it too, so the tools sign_efi_tools.sh signs are trusted.
  It also copies test-cert.der to the EFI partition (EFI/fw-validation/) so the
  certificate can be enrolled by hand in BIOS Setup if the firmware still refuses.

Microsoft certificates: DB_KEY_DIR/microsoft-*-public.der.siglist (left there by
sb-setup), else microsoft-*-public.der found under the directories given with
--ms-dir (enable_secure_boot.sh passes the qa-regression-testing clone).

Usage (root, on the SUT):
  sudo python3 deploy/secure_boot/sb_enroll.py enroll [--ms-dir DIR ...]
  sudo python3 deploy/secure_boot/sb_enroll.py build --out DIR    # signed updates only, nothing written
  sudo python3 deploy/secure_boot/sb_enroll.py secure-boot-on     # AMI: 'Secure Boot' = Enabled (keys must be ours)

Standard library + the openssl and chattr commands.
"""

import argparse
import os
import shutil
import struct
import subprocess
import sys
import tempfile
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import List, Optional, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parent))
import sb_keys  # noqa: E402

KEY_DIR = Path(os.environ.get("DB_KEY_DIR", "/etc/secureboot/key-material"))
KEY_FILE = KEY_DIR / "test-key.rsa"
CERT_PEM = KEY_DIR / "test-cert.pem"
CERT_DER = KEY_DIR / "test-cert.der"
OWNER_GUID_FILE = KEY_DIR / ".owner-guid"          # shared with sign_efi_tools.sh
KEYSTORE_DIR = Path(os.environ.get("SB_KEYSTORE_DIR", "/etc/secureboot/keys"))
KEY_CN = os.environ.get("SB_KEY_CN", "test-key")
KEY_DAYS = int(os.environ.get("SB_KEY_DAYS", "3650"))
RENEW_SECONDS = 365 * 86400
ESP_CERT_DIR = Path(os.environ.get("EFI_MOUNT", "/boot/efi")) / "EFI" / "fw-validation"

MS_KEK = ["microsoft-kekca-public"]
MS_DB = ["microsoft-pca-public", "microsoft-uefica-public"]
MICROSOFT_OWNER = uuid.UUID("77fa9abd-0359-4d32-bd60-28f4e78f784b")

# NON_VOLATILE | BOOTSERVICE_ACCESS | RUNTIME_ACCESS | TIME_BASED_AUTHENTICATED_WRITE_ACCESS
SB_ATTRS = 0x27
EFI_CERT_TYPE_PKCS7_GUID = uuid.UUID("4aafd29d-68df-49ee-8aa9-347d375665a7")
WIN_CERT_TYPE_EFI_GUID = 0x0EF1
WIN_CERT_REVISION = 0x0200

ERRNO_HINT = {
    22: "EINVAL = the firmware returned EFI_INVALID_PARAMETER (it refused the update)",
    13: "EACCES = the firmware returned EFI_SECURITY_VIOLATION / EFI_ACCESS_DENIED (not trusted or not allowed)",
    30: "EROFS = the firmware returned EFI_WRITE_PROTECTED (the variable is locked against OS writes)",
    1: "EPERM = the efivarfs file is immutable or writes are not allowed",
    28: "ENOSPC = the firmware variable store is full",
}


class EnrollError(Exception):
    pass


def log(msg: str) -> None:
    print(msg, flush=True)


def run(cmd: List[str], **kwargs) -> subprocess.CompletedProcess:
    kwargs.setdefault("timeout", 120)
    try:
        out = subprocess.run(cmd, capture_output=True, **kwargs)
    except subprocess.TimeoutExpired as exc:
        raise EnrollError(f"{' '.join(map(str, cmd[:3]))} ... timed out after {exc.timeout} s") from None
    if out.returncode != 0:
        err = (out.stderr or b"").decode(errors="replace").strip()
        raise EnrollError(f"{' '.join(map(str, cmd[:3]))} ... failed (rc={out.returncode}): {err}")
    return out


# ------------------------------------------------------------------
# Our key
# ------------------------------------------------------------------

def cert_valid_for(path: Path, seconds: int) -> bool:
    if not path.is_file():
        return False
    return subprocess.run(["openssl", "x509", "-in", str(path), "-noout", "-checkend", str(seconds)],
                          capture_output=True, timeout=30).returncode == 0


def backup(path: Path, stamp: str) -> None:
    if path.exists():
        dest = path.with_name(f"{path.name}.bak-{stamp}")
        shutil.move(str(path), str(dest))
        log(f"[OK]   Kept the old {path} as {dest}")


def generate_key() -> None:
    """New self-signed RSA-2048/SHA-256 key + cert; valid from yesterday (firmware clock skew)."""
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    old_siglists = {p.name: p.read_bytes() for p in KEY_DIR.glob("microsoft-*.siglist")} if KEY_DIR.is_dir() else {}
    old_guid = OWNER_GUID_FILE.read_text().strip() if OWNER_GUID_FILE.is_file() else ""
    backup(KEY_DIR, stamp)
    # Signed updates in the sbkeysync keystore belong to the old key: sbkeysync would replay them.
    backup(KEYSTORE_DIR, stamp)

    start = datetime.now(timezone.utc) - timedelta(days=1)
    end = start + timedelta(days=KEY_DAYS + 1)
    with tempfile.TemporaryDirectory() as tmp:
        t = Path(tmp)
        (t / "index.txt").touch()
        # openssl ca needs an even number of hex digits: always 16.
        (t / "serial").write_text(f"{uuid.uuid4().int % (1 << 63):016X}\n")
        (t / "ca.cnf").write_text(
            "[ca]\ndefault_ca = c\n"
            f"[c]\ndatabase = {t}/index.txt\nnew_certs_dir = {t}\nserial = {t}/serial\n"
            "default_md = sha256\npolicy = p\nx509_extensions = ext\nunique_subject = no\n"
            "[p]\ncommonName = supplied\n"
            "[ext]\nsubjectKeyIdentifier = hash\nauthorityKeyIdentifier = keyid:always\n"
            "basicConstraints = critical,CA:TRUE\n"
        )
        run(["openssl", "req", "-new", "-newkey", "rsa:2048", "-nodes", "-sha256",
             "-subj", f"/CN={KEY_CN}", "-keyout", str(t / "key.pem"), "-out", str(t / "req.csr")])
        run(["openssl", "ca", "-batch", "-config", str(t / "ca.cnf"), "-selfsign", "-notext",
             "-keyfile", str(t / "key.pem"), "-in", str(t / "req.csr"),
             "-startdate", start.strftime("%Y%m%d%H%M%SZ"), "-enddate", end.strftime("%Y%m%d%H%M%SZ"),
             "-out", str(t / "cert.pem")])
        KEY_DIR.mkdir(parents=True, exist_ok=True)
        os.chmod(KEY_DIR, 0o755)
        fd = os.open(KEY_FILE, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as fh:
            fh.write((t / "key.pem").read_bytes())
        os.chmod(KEY_FILE, 0o600)  # an existing file keeps its old mode on open
        shutil.copyfile(t / "cert.pem", CERT_PEM)
    run(["openssl", "x509", "-in", str(CERT_PEM), "-outform", "DER", "-out", str(CERT_DER)])
    for name, data in old_siglists.items():
        (KEY_DIR / name).write_bytes(data)
    if old_guid:
        OWNER_GUID_FILE.write_text(old_guid + "\n")
    log(f"[OK]   New key: {KEY_FILE}, cert: {CERT_PEM} (CN={KEY_CN}, "
        f"valid {start:%Y-%m-%d} .. {end:%Y-%m-%d})")


def owner_guid() -> uuid.UUID:
    if OWNER_GUID_FILE.is_file():
        try:
            return uuid.UUID(OWNER_GUID_FILE.read_text().strip())
        except ValueError:
            pass
    guid = uuid.uuid4()
    OWNER_GUID_FILE.write_text(f"{guid}\n")
    return guid


# ------------------------------------------------------------------
# EFI_SIGNATURE_LIST + EFI_VARIABLE_AUTHENTICATION_2
# ------------------------------------------------------------------

def esl_x509(der: bytes, owner: uuid.UUID) -> bytes:
    sig_size = 16 + len(der)
    return (sb_keys.EFI_CERT_X509.bytes_le + struct.pack("<III", 28 + sig_size, 0, sig_size)
            + owner.bytes_le + der)


def microsoft_esls(names: List[str], ms_dirs: List[Path]) -> bytes:
    out = b""
    for name in names:
        siglist = KEY_DIR / f"{name}.der.siglist"
        if siglist.is_file():
            data = siglist.read_bytes()
            if not sb_keys.x509_certs(data):
                raise EnrollError(f"{siglist} holds no X.509 certificate")
            out += data
            continue
        found = next((p for d in ms_dirs if d.is_dir() for p in sorted(d.rglob(f"{name}.der"))), None)
        if not found:
            raise EnrollError(f"Microsoft certificate '{name}' not found ({siglist}, or {name}.der under "
                              f"{', '.join(map(str, ms_dirs)) or 'no --ms-dir'})")
        out += esl_x509(found.read_bytes(), MICROSOFT_OWNER)
    return out


def efi_time_now() -> bytes:
    now = datetime.now(timezone.utc)
    # EFI_TIME: Year, Month (1-12), Day, Hour, Minute, Second, Pad1, Nanosecond, TimeZone, Daylight, Pad2
    return struct.pack("<HBBBBBBIhBB", now.year, now.month, now.day, now.hour, now.minute, now.second,
                       0, 0, 0, 0, 0)


def _der_len(data: bytes, pos: int) -> Tuple[int, int]:
    first = data[pos]
    if first < 0x80:
        return first, pos + 1
    n = first & 0x7F
    return int.from_bytes(data[pos + 1:pos + 1 + n], "big"), pos + 1 + n


def signed_data(content_info: bytes) -> bytes:
    """The SignedData inside a PKCS#7 ContentInfo -- what EFI_VARIABLE_AUTHENTICATION_2 carries."""
    if content_info[0] != 0x30:
        raise EnrollError("openssl smime output is not a DER SEQUENCE")
    _, pos = _der_len(content_info, 1)
    if content_info[pos] != 0x06:
        raise EnrollError("openssl smime output has no content type")
    oid_len, oid_pos = _der_len(content_info, pos + 1)
    pos = oid_pos + oid_len
    if content_info[pos] != 0xA0:
        raise EnrollError("openssl smime output has no [0] content")
    inner_len, inner_pos = _der_len(content_info, pos + 1)
    return content_info[inner_pos:inner_pos + inner_len]


def authenticated_update(name: str, guid: str, payload: bytes, attrs: int = SB_ATTRS) -> bytes:
    """EFI_VARIABLE_AUTHENTICATION_2 + payload, signed with our key (sign = name|guid|attrs|time|data)."""
    timestamp = efi_time_now()
    to_sign = (name.encode("utf-16-le") + uuid.UUID(guid).bytes_le + struct.pack("<I", attrs)
               + timestamp + payload)
    with tempfile.TemporaryDirectory() as tmp:
        data_file, sig_file = Path(tmp) / "data", Path(tmp) / "sig"
        data_file.write_bytes(to_sign)
        # PKCS#7 (smime), not CMS: it encodes sha256 with NULL parameters like sbvarsign does.
        run(["openssl", "smime", "-sign", "-binary", "-noattr", "-md", "sha256", "-outform", "DER",
             "-signer", str(CERT_PEM), "-inkey", str(KEY_FILE), "-in", str(data_file), "-out", str(sig_file)])
        sd = signed_data(sig_file.read_bytes())
    win_cert = (struct.pack("<IHH", 24 + len(sd), WIN_CERT_REVISION, WIN_CERT_TYPE_EFI_GUID)
                + EFI_CERT_TYPE_PKCS7_GUID.bytes_le + sd)
    return timestamp + win_cert + payload


# ------------------------------------------------------------------
# Writing the variables
# ------------------------------------------------------------------

def write_var(name: str, payload: bytes) -> None:
    guid = sb_keys.VAR_GUIDS[name]
    path = sb_keys.EFIVARS_DIR / f"{name}-{guid}"
    update = authenticated_update(name, guid, payload)
    if path.exists():
        # efivarfs makes PK/KEK/db immutable as soon as they exist (again after every write).
        subprocess.run(["chattr", "-i", str(path)], capture_output=True, timeout=30)
    try:
        fd = os.open(str(path), os.O_WRONLY | os.O_CREAT, 0o644)
        try:
            written = os.write(fd, struct.pack("<I", SB_ATTRS) + update)
        finally:
            os.close(fd)
    except OSError as exc:
        hint = ERRNO_HINT.get(exc.errno, os.strerror(exc.errno or 0))
        raise EnrollError(f"Writing {name} failed: {exc.strerror} ({hint})") from exc
    if written != 4 + len(update):
        raise EnrollError(f"Writing {name}: only {written} of {4 + len(update)} bytes accepted")
    certs = len(sb_keys.x509_certs(payload))
    log(f"[OK]   {name} written ({certs} certificate{'s' if certs != 1 else ''})")


def copy_cert_to_esp() -> Optional[Path]:
    """test-cert.der on the EFI partition, for enrolling it by hand in BIOS Setup."""
    try:
        ESP_CERT_DIR.mkdir(parents=True, exist_ok=True)
        dest = ESP_CERT_DIR / "test-cert.der"
        shutil.copyfile(CERT_DER, dest)
        return dest
    except OSError:
        return None


def plan_updates(state: sb_keys.KeyState, ms_dirs: List[Path]) -> List[Tuple[str, bytes]]:
    ours = esl_x509(state.cert, owner_guid())
    db = microsoft_esls(MS_DB, ms_dirs) + ours
    kek = microsoft_esls(MS_KEK, ms_dirs) + ours
    if state.owner == "setup":
        return [("db", db), ("KEK", kek), ("PK", ours)]   # PK last: it ends Setup Mode
    return [("KEK", kek), ("db", db)]                   # PK is ours: KEK signed by PK, db by KEK


def ensure_key(state: sb_keys.KeyState) -> sb_keys.KeyState:
    if state.owner == "setup" and not cert_valid_for(CERT_PEM, RENEW_SECONDS):
        why = "missing" if not CERT_PEM.is_file() else "expired or expiring within a year"
        log(f"       Our certificate {CERT_PEM} is {why} -- creating a new key (Setup Mode, nothing to lose).")
        generate_key()
        return sb_keys.read_state(CERT_PEM)
    if not KEY_FILE.is_file() or state.cert is None:
        raise EnrollError(f"Our key {KEY_FILE} / cert {CERT_PEM} is missing, but PK already holds a key -- "
                          "delete all keys in BIOS Setup, then run this again.")
    return state


def cmd_enroll(args) -> int:
    state = sb_keys.read_state(CERT_PEM)
    if not state.readable:
        raise EnrollError(f"Cannot read the Secure Boot variables in {sb_keys.EFIVARS_DIR}")
    if state.owner == "foreign":
        raise EnrollError("PK holds a key that is not ours (factory keys) -- delete all keys in BIOS Setup first.")
    if state.owner == "ours" and state.has("db"):
        log("[OK]   PK, KEK and db already hold our certificate -- nothing to enroll.")
        return 0

    state = ensure_key(state)
    esp_cert = copy_cert_to_esp()
    updates = plan_updates(state, [Path(d) for d in args.ms_dir])
    log(f"       Enrolling {' -> '.join(n for n, _ in updates)} with {CERT_PEM} "
        f"({sb_keys.cert_name(state.cert)}), key owner now: {state.owner}")
    try:
        for name, payload in updates:
            write_var(name, payload)
    except EnrollError as exc:
        sb_keys.print_status(sb_keys.read_state(CERT_PEM))
        hand = f"EFI\\fw-validation\\{esp_cert.name}" if esp_cert else str(CERT_DER)
        raise EnrollError(
            f"{exc}\n"
            "       Enroll our certificate by hand instead: BIOS Setup -> Security -> Secure Boot ->\n"
            "       Key Management -> Platform Key (PK) -> Set New / Update -> from file:\n"
            f"       {hand} (Public Key Certificate); also append it to KEK and db the same way.\n"
            "       Then run:  sudo deploy/secure_boot/enable_secure_boot.sh auto"
        ) from exc

    after = sb_keys.read_state(CERT_PEM)
    sb_keys.print_status(after)
    if after.owner != "ours" or not after.has("db"):
        raise EnrollError(f"After the writes the keys are '{after.owner}' and our cert is "
                          f"{'' if after.has('db') else 'not '}in db -- the firmware did not keep them.")
    log("[OK]   Our keys are enrolled: PK, KEK and db hold our certificate.")
    return 0


def cmd_build(args) -> int:
    """Write the signed updates (efivarfs format: 4-byte attributes + update) to --out; nothing is enrolled."""
    state = sb_keys.read_state(CERT_PEM)
    if state.cert is None or not KEY_FILE.is_file():
        raise EnrollError(f"Our key {KEY_FILE} / cert {CERT_PEM} not found")
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    ours = esl_x509(state.cert, owner_guid())
    ms_dirs = [Path(d) for d in args.ms_dir]
    for name, payload in (("db", microsoft_esls(MS_DB, ms_dirs) + ours),
                          ("KEK", microsoft_esls(MS_KEK, ms_dirs) + ours), ("PK", ours)):
        path = out / f"{name}.auth"
        path.write_bytes(struct.pack("<I", SB_ATTRS) + authenticated_update(name, sb_keys.VAR_GUIDS[name], payload))
        log(f"[OK]   {path}")
    return 0


# ------------------------------------------------------------------
# AMI 'Secure Boot' setup knob (SecureBootSetup variable)
# ------------------------------------------------------------------
# AMI Aptio keeps the Secure Boot page of BIOS Setup in its own variable, not in
# 'Setup'; on some builds AMISCE cannot change it. Layout (AMISCE export, same
# order): byte 0 'Secure Boot' (1 = Enabled), byte 1 'Secure Boot Mode'
# (1 = Custom), byte 2 'Factory Key Provision' (0 = Disabled).
AMI_SB_SETUP_VAR = "SecureBootSetup-7b59104a-c00d-4158-87ff-f04d6396a915"
AMI_SB_WANTED = {0: 1, 1: 1, 2: 0}
AMI_SB_ATTRS = 0x07   # NON_VOLATILE | BOOTSERVICE_ACCESS | RUNTIME_ACCESS -- no authentication


def cmd_secure_boot_on(_args) -> int:
    """Set AMI 'Secure Boot' = Enabled (+ Custom mode, no factory keys) -- only with our keys enrolled."""
    state = sb_keys.read_state(CERT_PEM)
    if state.owner != "ours" or not state.has("db"):
        raise EnrollError(f"Refusing to turn Secure Boot on: the keys are '{state.owner}' and our cert is "
                          f"{'' if state.has('db') else 'not '}in db -- enroll our keys first ('provision').")
    path = sb_keys.EFIVARS_DIR / AMI_SB_SETUP_VAR
    try:
        raw = path.read_bytes()
    except FileNotFoundError:
        raise EnrollError(f"{path.name} not found -- not an AMI Secure Boot setup variable layout")
    attrs = struct.unpack_from("<I", raw)[0]
    data = bytearray(raw[4:])
    if attrs != AMI_SB_ATTRS or len(data) < 3 or any(data[i] not in (0, 1) for i in AMI_SB_WANTED):
        raise EnrollError(f"{path.name} has an unexpected layout (attributes {attrs:#x}, data {data.hex()}) "
                          "-- not changed")
    log(f"       {path.name}: {data.hex()}  (Secure Boot={data[0]}, Mode={'Custom' if data[1] else 'Standard'}, "
        f"Factory Key Provision={data[2]})")
    if all(data[i] == v for i, v in AMI_SB_WANTED.items()):
        log("[OK]   'Secure Boot' is already Enabled in the BIOS setting (Custom mode, no factory keys).")
        return 0
    new = bytearray(data)
    for i, value in AMI_SB_WANTED.items():
        new[i] = value
    subprocess.run(["chattr", "-i", str(path)], capture_output=True, timeout=30)
    try:
        fd = os.open(str(path), os.O_WRONLY)
        try:
            os.write(fd, struct.pack("<I", attrs) + bytes(new))
        finally:
            os.close(fd)
    except OSError as exc:
        hint = ERRNO_HINT.get(exc.errno, os.strerror(exc.errno or 0))
        raise EnrollError(f"The BIOS refused the change of {path.name}: {exc.strerror} ({hint})") from exc
    after = bytearray(path.read_bytes()[4:])
    if any(after[i] != v for i, v in AMI_SB_WANTED.items()):
        raise EnrollError(f"{path.name} reads {after.hex()} after the write -- the BIOS did not keep it")
    log(f"[OK]   {path.name}: {data.hex()} -> {after.hex()}  ('Secure Boot' = Enabled; active after the next reboot)")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="Enroll our own Secure Boot keys (db, KEK, PK) from Linux.")
    ap.add_argument("--efivars", help=argparse.SUPPRESS)
    sub = ap.add_subparsers(dest="command", required=True)
    for name, text in (("enroll", "enroll our keys (Setup Mode, or PK already ours)"),
                       ("build", "only write the signed updates to --out")):
        p = sub.add_parser(name, help=text)
        p.add_argument("--ms-dir", action="append", default=[],
                       help="directory searched for microsoft-*-public.der when the .siglist files are missing")
        if name == "build":
            p.add_argument("--out", required=True)
    sub.add_parser("secure-boot-on", help="AMI BIOS: set 'Secure Boot' = Enabled (our keys must be enrolled)")
    args = ap.parse_args()
    if args.efivars:
        sb_keys.EFIVARS_DIR = Path(args.efivars)
    if args.command != "build" and hasattr(os, "geteuid") and os.geteuid() != 0 and not args.efivars:
        print("[FAIL] Run as root: sudo python3 " + " ".join(sys.argv))
        return 1
    try:
        return {"enroll": cmd_enroll, "build": cmd_build, "secure-boot-on": cmd_secure_boot_on}[args.command](args)
    except EnrollError as exc:
        print(f"[FAIL] {exc}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
