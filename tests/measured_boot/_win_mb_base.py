# Copyright 2026 Intel Corporation
# SPDX-License-Identifier: Apache-2.0

"""
_win_mb_base.py — shared helpers for Windows measured-boot tests.

Imported by:
  test_ec62443_dtpm_sut_wins_func.py
  test_ec62443_ftpm_ptt_sut_wins_func.py

Why a separate module?
    fTPM and dTPM Windows tests share ~90 % of their logic; the only
    material differences are:
      - Which TPM manufacturer is expected (Intel vs non-Intel).
      - The log-file label ("fTPM" vs "dTPM").
    Keeping shared code here avoids copy-paste drift.

KEY WINDOWS TOOL MAPPING  (Linux → Windows)
-------------------------------------------
  Linux               │  Windows
  ─────────────────── │ ────────────────────────────────────────────
  mokutil --sb-state  │  Confirm-SecureBootUEFI
  tpm2_getcap         │  Get-Tpm  /  tpmtool getdeviceinformation
  tpm2_pcrread        │  TBS API via embedded C# in PowerShell
  checkquote.sh       │  tpmtool gatherlogs <dir>
  /dev/tpmrm0         │  Windows TPM driver (auto-loaded)
  sudo insmod ...     │  (not needed — Windows loads driver automatically)
  chmod +x            │  (not needed — Windows .exe is always executable)
"""

import base64
import logging
import re
import subprocess
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# PowerShell script: Read SHA256 PCR values 0-7 via Windows TBS DLL
# ---------------------------------------------------------------------------
# Uses the TPM Base Services (Tbs.dll) which is built into every
# Windows 10/11 installation.  Requires Administrator rights.
#
# Response layout for a single TPM2_CC_PCR_Read:
#   header         : tag(2) + size(4) + responseCode(4) = 10 bytes
#   pcrUpdateCtr   : 4 bytes
#   TPML_PCR_SEL   : count(4) + hash(2) + sizeofSelect(1) + pcrSelect(3) = 10 bytes
#   TPML_DIGEST    : count(4) bytes
#   TPM2B_DIGEST[0]: size(2) + sha256_value(32) bytes
#   ──────────────────────────────────────────────────────────────────
#   Offset of PCR value = 10 + 4 + 10 + 4 + 2 = 30
_PS_READ_SHA256_PCRS = """\
$ErrorActionPreference = 'Stop'
Add-Type -TypeDefinition @'
using System; using System.Runtime.InteropServices;
public class WinTbs {
    [StructLayout(LayoutKind.Sequential)]
    public struct Params { public uint version; public uint flags; }
    [DllImport("Tbs.dll")] public static extern uint Tbsi_Context_Create(ref Params p, out IntPtr h);
    [DllImport("Tbs.dll")] public static extern uint Tbsip_Submit_Command(
        IntPtr h, uint loc, uint pri, byte[] cmd, uint cLen, byte[] resp, ref uint rLen);
    [DllImport("Tbs.dll")] public static extern uint Tbsip_Context_Close(IntPtr h);
}
'@
$p = New-Object WinTbs+Params
$p.version = 2
$p.flags   = 0x02
$h = [IntPtr]::Zero
if ([WinTbs]::Tbsi_Context_Create([ref]$p, [ref]$h) -ne 0) {
    throw 'TBS_CONTEXT_FAILED - ensure script runs as Administrator'
}
try {
    0..7 | ForEach-Object {
        $i   = $_
        $sel = [byte[]]@(0, 0, 0)
        $sel[[int]($i / 8)] = [byte](1 -shl ($i % 8))
        $cmd = [byte[]]@(
            0x80, 0x01,                  # tag: TPM2_ST_NO_SESSIONS
            0x00, 0x00, 0x00, 0x14,      # commandSize: 20
            0x00, 0x00, 0x01, 0x7E,      # commandCode: TPM2_CC_PCR_Read
            0x00, 0x00, 0x00, 0x01,      # TPML_PCR_SELECTION.count = 1
            0x00, 0x0B,                  # hash: TPM2_ALG_SHA256
            0x03,                        # sizeofSelect = 3
            $sel[0], $sel[1], $sel[2]    # pcrSelect bitmask
        )
        $resp = [byte[]]::new(4096)
        $rLen = [uint32]4096
        $ret  = [WinTbs]::Tbsip_Submit_Command($h, 0, 200, $cmd, [uint32]$cmd.Length, $resp, [ref]$rLen)
        if ($ret -ne 0) {
            Write-Output "PCR_${i}=ERROR_CMD_0x$($ret.ToString('X8'))"
            return
        }
        $rc = [uint32](($resp[6] -shl 24) -bor ($resp[7] -shl 16) -bor ($resp[8] -shl 8) -bor $resp[9])
        if ($rc -ne 0) {
            Write-Output "PCR_${i}=ERROR_TPM_RC_0x$($rc.ToString('X8'))"
            return
        }
        $hex = '0x' + (($resp[30..61] | ForEach-Object { $_.ToString('x2') }) -join '')
        Write-Output "PCR_${i}=${hex}"
    }
} finally {
    [WinTbs]::Tbsip_Context_Close($h) | Out-Null
}
"""

# ---------------------------------------------------------------------------
# PowerShell: Verify Secure Boot is enabled
# ---------------------------------------------------------------------------
_PS_CONFIRM_SECURE_BOOT = "Confirm-SecureBootUEFI"

# ---------------------------------------------------------------------------
# PowerShell: Get TPM status
# ---------------------------------------------------------------------------
_PS_GET_TPM = "Get-Tpm | Format-List"

# ---------------------------------------------------------------------------
# CMD: Get TPM device information (shows VendorID / manufacturer)
# ---------------------------------------------------------------------------
_PS_TPM_DEVICE_INFO = "tpmtool getdeviceinformation"

# ---------------------------------------------------------------------------
# CMD: Gather TPM logs to specified directory
# ---------------------------------------------------------------------------
_PS_GATHER_LOGS_TEMPLATE = "tpmtool gatherlogs {log_dir}"

# ---------------------------------------------------------------------------
# CMD: Optional BitLocker status artifact
# ---------------------------------------------------------------------------
_PS_BITLOCKER_STATUS = "manage-bde -status"


# ---------------------------------------------------------------------------
# Helper: Build base64-encoded PowerShell command
# ---------------------------------------------------------------------------

def ps_encoded_cmd(script: str) -> str:
    """
    Return a powershell.exe command that runs *script* via -EncodedCommand.

    Base64 UTF-16LE encoding avoids all quoting and newline issues when the
    script is passed over SSH or via subprocess on Windows.

    Args:
        script: Multi-line PowerShell script text.

    Returns:
        A single-line shell command string safe to pass to os_manager or
        subprocess.
    """
    enc = base64.b64encode(script.encode("utf-16-le")).decode("ascii")
    return f"powershell.exe -NonInteractive -NoProfile -EncodedCommand {enc}"


# ---------------------------------------------------------------------------
# Helper: Parse PCR output lines
# ---------------------------------------------------------------------------

def parse_pcrs(output: str, pcr_list: list) -> dict:
    """
    Parse PCR output produced by _PS_READ_SHA256_PCRS.

    Expected format (one line per PCR):
        PCR_0=0x<64-hex-chars>
        PCR_1=0x<64-hex-chars>
        ...

    Args:
        output:   Raw stdout from the PowerShell PCR-read script.
        pcr_list: List of expected PCR indices (int).

    Returns:
        Dict mapping PCR index (int) to lowercase hex string (e.g. "0xabcd…"),
        only for PCRs that were successfully parsed.
    """
    pcrs: dict = {}
    for line in output.splitlines():
        line = line.strip()
        m = re.match(r"PCR_(\d+)=(0x[0-9a-fA-F]+)", line)
        if m:
            idx = int(m.group(1))
            val = m.group(2).lower()
            pcrs[idx] = val
    return {p: pcrs[p] for p in pcr_list if p in pcrs}


# ---------------------------------------------------------------------------
# Helper: Parse PCR values out of tpmtool gatherlogs' TpmInformation.txt
# ---------------------------------------------------------------------------
#
# ``tpmtool gatherlogs <dir>`` already queries the TPM for the current PCR
# digests of the active bank and writes them into <dir>/TpmInformation.txt,
# e.g.:
#
#     -TPM_ALG_SHA256 PCRs:
#           -PCR[00] - ce1e222918a84a5461fee663aecf1a158d5640ab9233 51a297149c7218a3774
#           -PCR[01] - decdf9e1a8863 9c2a3c25f3b2e1b38e154e...
#
# Reading these values directly is simpler and more robust than
# re-implementing raw PCR reads via Tbsi_Context_Create /
# Tbsip_Submit_Command (which is easy to get wrong -- e.g. requesting a
# TPM 1.2 context on a TPM 2.0-only device -- and unnecessarily requires
# raw/administrative TBS access).
#
# NOTE: tpmtool writes this file as UTF-16LE without a byte-order mark.
def read_tpm_information(log_subdir: Path) -> str:
    """
    Read TpmInformation.txt produced by ``tpmtool gatherlogs <log_subdir>``.

    Args:
        log_subdir: Directory passed to ``tpmtool gatherlogs``.

    Returns:
        Decoded file contents.
    """
    info_file = log_subdir / "TpmInformation.txt"
    return info_file.read_text(encoding="utf-16-le", errors="replace")


def parse_pcrs_from_tpm_information(text: str, pcr_list: list, algorithm: str = "SHA256") -> dict:
    """
    Parse PCR values for one bank out of TpmInformation.txt contents.

    Args:
        text:      Decoded contents of TpmInformation.txt.
        pcr_list:  List of expected PCR indices (int).
        algorithm: PCR bank label as it appears in the file (default "SHA256").

    Returns:
        Dict mapping PCR index (int) to lowercase hex string (e.g. "0xabcd…"),
        only for PCRs found under the requested bank's section.
    """
    header_re = re.compile(rf"-TPM_ALG_{re.escape(algorithm)}\s+PCRs:", re.IGNORECASE)
    header_match = header_re.search(text)
    section = text[header_match.end():] if header_match else text

    pcrs: dict = {}
    for match in re.finditer(r"-PCR\[(\d+)\]\s*-\s*([0-9a-fA-F]+)", section):
        idx = int(match.group(1))
        val = "0x" + match.group(2).lower()
        pcrs[idx] = val
    return {p: pcrs[p] for p in pcr_list if p in pcrs}


# ---------------------------------------------------------------------------
# Helper: Run a local PowerShell command (SUT-local variant)
# ---------------------------------------------------------------------------

def run_ps_local(script: str, timeout: int = 60) -> tuple:
    """
    Execute a PowerShell script locally via subprocess.

    Encodes the script as base64 UTF-16LE and uses -EncodedCommand so
    newlines and special characters are handled correctly.

    Args:
        script:  PowerShell script text (may be multi-line).
        timeout: Seconds to wait before timeout.

    Returns:
        Tuple (returncode, stdout, stderr).
    """
    cmd_str = ps_encoded_cmd(script)
    # Split on the space between 'powershell.exe' and '-NonInteractive ...'
    # We rebuild as a list to avoid shell=True (more secure).
    parts = cmd_str.split(" ", 1)
    args  = [parts[0]] + parts[1].split()
    try:
        result = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=timeout,
            errors="replace",
        )
        return result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired as exc:
        logger.error("PS command timeout after %ds", timeout)
        return 124, "", str(exc)
    except Exception as exc:
        logger.error("PS command error: %s", exc)
        return 1, "", str(exc)


# ---------------------------------------------------------------------------
# Helper: Run a PowerShell command over SSH (SSH-based variant)
# ---------------------------------------------------------------------------

def run_ps_remote(os_manager, script: str, timeout: int = 60) -> tuple:
    """
    Execute a PowerShell script on the Windows SUT via SSH (os_manager).

    Uses -EncodedCommand so multi-line scripts are passed cleanly
    through the SSH channel without quoting issues.

    Args:
        os_manager: OSManager instance (connected to Windows SUT).
        script:     PowerShell script text (may be multi-line).
        timeout:    Command timeout in seconds.

    Returns:
        Tuple (returncode, stdout, stderr).
    """
    cmd = ps_encoded_cmd(script)
    return os_manager.execute_command(cmd, timeout=timeout, check_returncode=False)


# ---------------------------------------------------------------------------
# Helper: Parse Get-Tpm output into key-value dict
# ---------------------------------------------------------------------------

def parse_get_tpm(output: str) -> dict:
    """
    Parse ``Get-Tpm | Format-List`` output into a dict.

    Handles lines like:
        TpmPresent   : True
        TpmReady     : True

    Returns:
        Dict mapping stripped key → stripped value (both strings).
    """
    result: dict = {}
    for line in output.splitlines():
        if ":" in line:
            k, _, v = line.partition(":")
            k = k.strip()
            v = v.strip()
            if k:
                result[k] = v
    return result


# ---------------------------------------------------------------------------
# Helper: Parse tpmtool getdeviceinformation output → VendorID
# ---------------------------------------------------------------------------

def parse_tpm_vendor(output: str) -> str:
    """
    Extract the TPM VendorID from ``tpmtool getdeviceinformation`` output.

    Looks for lines like:
        VendorID: INTC
        VendorID: IFX
        Manufacturer: INTC
        -TPM Manufacturer ID: INTC
        SpecVersion: ...

    Returns:
        Uppercase 4-char vendor string (e.g. "INTC", "IFX"), or "" if not found.
    """
    for line in output.splitlines():
        m = re.search(r"(?:VendorID|Manufacturer(?:\s+ID)?)\s*:\s*([A-Za-z0-9]{2,8})", line, re.IGNORECASE)
        if m:
            return m.group(1).upper().strip()
    return ""
