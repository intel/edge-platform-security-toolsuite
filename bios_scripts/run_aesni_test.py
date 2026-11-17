#!/usr/bin/env python3
# Copyright 2026 Intel Corporation
# SPDX-License-Identifier: Apache-2.0

"""
Cross-platform AES-NI test script (Windows & Ubuntu/Linux)
Windows variant uses Coreinfo for AES capability check and does not use WSL.

Windows:
    - AES check: coreinfo64.exe -f, expect '*' on AES line
  - MSR check: skipped (no WSL path in this variant)

Linux:
  - AES check: /proc/cpuinfo
  - MSR check: sudo rdmsr 0x13c -a

Common:
  - OpenSSL encrypt/decrypt validation
  - OpenSSL benchmark
"""

from __future__ import annotations

import argparse
import binascii
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

IS_WINDOWS = sys.platform == "win32"
IS_LINUX = sys.platform in ("linux", "linux2")

# Fallback default when no --coreinfo-exe argument and no COREINFO_EXE env var
# are supplied. Prefer configuring the actual path via tme_config.yaml
# (coreinfo_exe_path) rather than relying on this default.
DEFAULT_COREINFO_EXE = "coreinfo64.exe"

KEY_IV_FILE = Path("./aes_drng_keyiv.env")
PLAIN_FILE = Path("plain.bin")
CIPHER_FILE = Path("cipher.bin")
PLAIN_OUT = Path("plain_out.bin")


def fail(msg: str, code: int = 1) -> None:
    print(f"FAIL: {msg}")
    sys.exit(code)


def run(cmd: list[str], capture: bool = False) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            cmd,
            check=True,
            text=True,
            capture_output=capture,
        )
    except FileNotFoundError:
        fail(f"command not found: {cmd[0]}")
    except subprocess.CalledProcessError as exc:
        stderr = exc.stderr.strip() if capture and exc.stderr else ""
        if stderr:
            print(stderr)
        fail(f"command failed: {' '.join(cmd)}")


def run_optional(cmd: list[str], capture: bool = False) -> subprocess.CompletedProcess[str] | None:
    try:
        return subprocess.run(
            cmd,
            check=True,
            text=True,
            capture_output=capture,
        )
    except (FileNotFoundError, subprocess.CalledProcessError):
        return None


def validate_hex32(value: str, label: str) -> None:
    if not re.fullmatch(r"[0-9A-Fa-f]{32}", value):
        fail(f"invalid {label}: {value}")


def rand_engine_args() -> list[str]:
    """Return the "-engine rdrand" option when the RDRAND engine is available.

    -engine is an option of the subcommand ("openssl rand -engine rdrand ..."),
    not of openssl itself; OpenSSL 4.x has no engines, so the probe finds none.
    """
    if shutil.which("openssl") is None:
        fail("openssl is not installed or not in PATH")

    probe = subprocess.run(
        ["openssl", "engine", "-t", "-c"],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        check=False,
    )
    if re.search(r"\brdrand\b", probe.stdout, re.IGNORECASE):
        return ["-engine", "rdrand"]
    return []


def generate_hex(engine_args: list[str], byte_count: int) -> str:
    result = run(["openssl", "rand", *engine_args, "-hex", str(byte_count)], capture=True)
    return result.stdout.strip()


def write_key_iv(path: Path, key: str, iv: str) -> None:
    old_mask = os.umask(0o177)
    try:
        path.write_text(f"KEY={key}\nIV={iv}\n", encoding="utf-8", newline="\n")
    finally:
        os.umask(old_mask)


def load_key_iv(path: Path) -> tuple[str, str]:
    data: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        data[k.strip()] = v.strip()

    if "KEY" not in data or "IV" not in data:
        fail(f"KEY or IV missing in {path}")
    return data["KEY"], data["IV"]


def resolve_coreinfo_command(exe_name: str) -> str | None:
    exe = shutil.which(exe_name)
    if exe:
        return exe

    local = Path(exe_name)
    if local.exists():
        return str(local)

    # Fall back to the directory containing this script, in case it is
    # invoked with a different current working directory (e.g. manually).
    script_dir_exe = Path(__file__).resolve().parent / exe_name
    if script_dir_exe.exists():
        return str(script_dir_exe)

    return None


def normalize_coreinfo_output(text: str) -> str:
    # Some environments return UTF-16-like output with NUL separators.
    text = text.replace("\x00", "")
    # Remove ANSI escape sequences and normalize newlines.
    text = re.sub(r"\x1B\[[0-9;]*[A-Za-z]", "", text)
    return text.replace("\r\n", "\n").replace("\r", "\n")


def check_aesni(coreinfo_exe_name: str) -> None:
    print("[1] Checking AES-NI support")

    if IS_LINUX:
        try:
            cpuinfo = Path("/proc/cpuinfo").read_text(encoding="utf-8", errors="ignore")
        except FileNotFoundError:
            fail("cannot read /proc/cpuinfo")

        if re.search(r"\baes\b", cpuinfo, re.IGNORECASE):
            print("PASS: AES flag found")
        else:
            fail("AES flag not found")
        return

    if IS_WINDOWS:
        coreinfo_exe = resolve_coreinfo_command(coreinfo_exe_name)
        if coreinfo_exe is None:
            fail(f"{coreinfo_exe_name} not found. Put it in PATH or next to this script")

        # -accepteula prevents first-run EULA output from breaking feature parsing.
        coreinfo_proc = run([coreinfo_exe, "-accepteula", "-f"], capture=True)
        # Some Coreinfo builds may emit parts of output to stderr.
        out = (coreinfo_proc.stdout or "") + "\n" + (coreinfo_proc.stderr or "")
        out = normalize_coreinfo_output(out)

        aes_marker = None
        for line in out.splitlines():
            parts = line.strip().split()
            if len(parts) >= 2 and parts[0].upper() == "AES" and parts[1] in ("*", "-"):
                aes_marker = parts[1]
                break

        if aes_marker is None:
            fail("Could not find AES feature line in coreinfo output")

        if aes_marker == "*":
            print("PASS: AES feature is supported (Coreinfo)")
        else:
            fail("AES feature is not supported (Coreinfo shows '-')")
        return

    print("WARN: Unsupported platform for AES-NI check; crypto validation will still run.")


def check_msr() -> None:
    print("[2] Checking MSR 0x13c on all CPUs")
    cpu_count = os.cpu_count() or 1
    print(f"Logical CPU count: {cpu_count}")

    if IS_LINUX:
        if shutil.which("rdmsr") is None:
            print("WARN: rdmsr not found; install msr-tools to check MSR 0x13c")
            return

        msr_proc = run_optional(["sudo", "rdmsr", "0x13c", "-a"], capture=True)
        if msr_proc is None:
            print("WARN: unable to read MSR 0x13c (requires sudo or msr-tools)")
            return

        bad_report = []
        for idx, raw_line in enumerate(msr_proc.stdout.splitlines()):
            raw = raw_line.strip()
            if not raw:
                continue
            # Newer msr-tools prefix each value with "CPU n: "; older ones print the bare value.
            value = raw.rsplit(":", 1)[-1].strip()
            if not re.fullmatch(r"(0x)?0*1", value, re.IGNORECASE):
                bad_report.append(f"CPU[{idx}]: {raw}")

        if not bad_report:
            print("PASS: rdmsr 0x13c is 1 on all CPUs")
        else:
            print("FAIL: rdmsr 0x13c has non-1 values")
            print("Per-core mismatches:")
            print("\n".join(bad_report))
            sys.exit(1)
        return

    if IS_WINDOWS:
        print("INFO: MSR check is skipped on Windows in this Coreinfo variant.")
        return


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Cross-platform AES-NI test script")
    parser.add_argument(
        "--coreinfo-exe",
        dest="coreinfo_exe",
        default=os.environ.get("COREINFO_EXE", DEFAULT_COREINFO_EXE),
        help=(
            "Name (or full path) of the Coreinfo executable to use for the "
            "Windows AES-NI check. Defaults to $COREINFO_EXE env var, then "
            f"'{DEFAULT_COREINFO_EXE}'. Prefer setting coreinfo_exe_path in "
            "tme_config.yaml, which the pytest wrapper passes through here."
        ),
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    # Resolve before leaving the caller's folder: a relative --coreinfo-exe is relative to it.
    coreinfo = resolve_coreinfo_command(args.coreinfo_exe)
    if coreinfo:
        args.coreinfo_exe = os.path.abspath(coreinfo)
    start_dir = os.getcwd()
    # Key/IV and plaintext/ciphertext files exist only for this run (folder is 0700, removed on exit).
    with tempfile.TemporaryDirectory(prefix="aesni_") as work_dir:
        os.chdir(work_dir)
        try:
            return run_test(args)
        finally:
            os.chdir(start_dir)


def run_test(args: argparse.Namespace) -> int:
    print(f"Platform: {'Windows' if IS_WINDOWS else 'Linux' if IS_LINUX else 'Unknown'}")
    print()

    engine_args = rand_engine_args()
    rng_source = " ".join(["openssl", "rand", *engine_args])

    if not KEY_IV_FILE.exists():
        key = generate_hex(engine_args, 16)
        iv = generate_hex(engine_args, 16)

        validate_hex32(key, "generated KEY")
        validate_hex32(iv, "generated IV")

        write_key_iv(KEY_IV_FILE, key, iv)
        print(f"INFO: Created key/IV file: {KEY_IV_FILE}")

    key, iv = load_key_iv(KEY_IV_FILE)
    validate_hex32(key, f"KEY in {KEY_IV_FILE}")
    validate_hex32(iv, f"IV in {KEY_IV_FILE}")
    print()

    check_aesni(args.coreinfo_exe)
    check_msr()
    print()

    print("[3] RNG source and generated values")
    print(f"RNG source: {rng_source}")
    print(f"Key/IV file: {KEY_IV_FILE}")
    print(f"KEY (hex): {key}")
    print(f"IV  (hex): {iv}")
    print()

    print("[4] Creating plaintext")
    plain_hex = (
        "6bc1bee22e409f96e93d7e117393172a"
        "ae2d8a571e03ac9c9eb76fac45af8e51"
        "30c81c46a35ce411e5fbc1191a0a52ef"
        "f69f2445df4f9b17ad2b417be66c3710"
    )
    PLAIN_FILE.write_bytes(binascii.unhexlify(plain_hex))

    print("[5] Encrypting")
    run([
        "openssl", "enc", "-aes-128-cbc",
        "-K", key, "-iv", iv, "-nopad",
        "-in", str(PLAIN_FILE),
        "-out", str(CIPHER_FILE),
    ])

    actual = CIPHER_FILE.read_bytes().hex()

    print("[6] Validating ciphertext length")
    print(f"Actual  : {actual}")
    if len(actual) == 128:
        print("PASS: ciphertext length is 64 bytes (128 hex chars)")
    else:
        fail(f"unexpected ciphertext length: {len(actual)} hex chars")
    print()

    print("[7] Decrypting")
    run([
        "openssl", "enc", "-d", "-aes-128-cbc",
        "-K", key, "-iv", iv, "-nopad",
        "-in", str(CIPHER_FILE),
        "-out", str(PLAIN_OUT),
    ])

    print("[8] Comparing plaintext")
    if PLAIN_FILE.read_bytes() == PLAIN_OUT.read_bytes():
        print("PASS: plaintext recovered")
    else:
        fail("plaintext mismatch after decryption")
    print()

    print("[9] Benchmark")
    speed = run(["openssl", "speed", "-evp", "aes-128-cbc"], capture=True)
    for line in speed.stdout.splitlines()[-5:]:
        print(line)

    print()
    print("TEST PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
