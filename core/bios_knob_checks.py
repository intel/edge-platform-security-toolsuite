# Copyright 2026 Intel Corporation
# SPDX-License-Identifier: Apache-2.0

"""
core/bios_knob_checks.py — is a BIOS knob really set? Read it back, Linux and Windows.

Used by the test_runner.py pre-flight (deploy/preflight/preflight_chain.py) and by
the tests themselves, so "the operator says it is set" is never the only proof.
Standard library only: the pre-flight imports it under the system python3.

Each knob is checked in this order:
  0. CPU support (cpu_supports_knob): a knob for a CPU feature this CPU lacks (TME:
     CPUID.07H:ECX[13] = 0) is WRONG at once -- setting it in the BIOS has no effect.
     The pre-flight and the AMISCE runbooks skip such knobs (unsupported_knobs).
  1. From the running OS (same signal on both OSes where possible):
       VT-d                          ACPI DMAR table present
       Low Power S0 Idle Capability  ACPI FADT flag LOW_POWER_S0_IDLE_CAPABLE (bit 21)
       Intel (VMX) Virtualization    Linux: MSR 0x3A bit 2 (or 'vmx' cpu flag)
                                     Windows: firmware virtualization on, or Hyper-V running
       Total Memory Encryption       Linux: MSR 0x982 (IA32_TME_ACTIVATE) bit 1
       Intel TXT                     Linux: MSR 0x3A bit 15 (SENTER global enable)
       PAVP Enable                   Windows: PlayReady hardware DRM on Intel graphics
       TPM Device Selection          TPM manufacturer (INTC = PTT)
  2. AMI BIOS on Windows: AMISCE export (SCEWIN_64.exe /o) -- read-only, no reboot.
  3. Operator confirmation from the pre-flight (logs/bios_knobs_attested.json) --
     shown as CONFIRMED (by the operator), never as read back.
Anything left is UNKNOWN.
"""

import hashlib
import json
import os
import platform
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

REPO_ROOT = Path(__file__).resolve().parents[1]
ATTESTED_FILE = REPO_ROOT / "logs" / "bios_knobs_attested.json"
ATTESTED_MAX_AGE_HOURS = 24

DMI_DIR = Path("/sys/class/dmi/id")
ACPI_TABLES_DIR = Path("/sys/firmware/acpi/tables")
EFIVARS_DIR = Path("/sys/firmware/efi/efivars")

_ON = {"enabled", "enable", "on", "yes", "true", "1"}
_OFF = {"disabled", "disable", "off", "no", "false", "0"}


def is_windows() -> bool:
    return platform.system() == "Windows"


def is_admin() -> bool:
    if is_windows():
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    return os.geteuid() == 0


class KnobResult:
    """One knob: what we wanted, what we found, and how sure we are."""

    def __init__(self, question: str, expected: str, ok: Optional[bool], actual: str, source: str = "os"):
        self.question = question
        self.expected = expected
        self.ok = ok            # True = matches, False = does not, None = cannot tell
        self.actual = actual
        self.source = source    # "os" | "amisce" | "attested" | ""

    @property
    def status(self) -> str:
        if self.ok is None:
            return "UNKNOWN"
        if not self.ok:
            return "WRONG"
        return "CONFIRMED" if self.source == "attested" else "OK"

    def __repr__(self) -> str:
        return f"KnobResult({self.question!r}={self.expected!r}: {self.status}, {self.actual!r})"


# ------------------------------------------------------------------
# SUT identity
# ------------------------------------------------------------------

def boot_id() -> str:
    """Changes on every boot; equal values mean 'no reboot happened in between'."""
    if is_windows():
        try:
            import winreg
            key_path = r"SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters"
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path) as key:
                return f"win-boot-{winreg.QueryValueEx(key, 'BootId')[0]}"
        except OSError:
            import ctypes
            ctypes.windll.kernel32.GetTickCount64.restype = ctypes.c_ulonglong
            boot = time.time() - ctypes.windll.kernel32.GetTickCount64() / 1000.0
            return f"win-boottime-{int(boot // 60)}"
    try:
        return Path("/proc/sys/kernel/random/boot_id").read_text(encoding="utf-8").strip()
    except OSError:
        return ""


def bios_identity() -> Dict[str, str]:
    """SMBIOS BIOS vendor / version / date."""
    if is_windows():
        values = {}
        try:
            import winreg
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"HARDWARE\DESCRIPTION\System\BIOS") as key:
                for name, reg in (("vendor", "BIOSVendor"), ("version", "BIOSVersion"), ("date", "BIOSReleaseDate")):
                    try:
                        values[name] = str(winreg.QueryValueEx(key, reg)[0]).strip()
                    except OSError:
                        values[name] = ""
        except OSError:
            pass
        return {k: values.get(k, "") for k in ("vendor", "version", "date")}
    result = {}
    for name in ("vendor", "version", "date"):
        try:
            result[name] = (DMI_DIR / f"bios_{name}").read_text(encoding="utf-8", errors="replace").strip()
        except OSError:
            result[name] = ""
    return result


def same_bios_build(recorded: Optional[Dict[str, str]], current: Optional[Dict[str, str]] = None) -> bool:
    current = current or bios_identity()
    return bool(recorded) and recorded.get("version") == current["version"] and recorded.get("date") == current["date"]


# NVRAM variables that hold the knobs of deploy/bios_knobs/bios_knobs.yaml (Intel reference
# code / AMI): CPU Configuration -> CpuSetup, System Agent -> SaSetup, PCH -> PchSetup, ACPI -> Setup.
SETUP_VARIABLES = ("Setup", "CpuSetup", "SaSetup", "PchSetup")


def setup_fingerprint() -> Optional[Dict[str, str]]:
    """
    {efivar file name: SHA-256 of its data} for SETUP_VARIABLES, or None when they cannot be
    read (Windows, no efivarfs). A knob changed in BIOS Setup, an AMISCE import or an IFWI
    flash that resets the settings all change it -- including knobs no OS check can read.
    """
    if is_windows():
        return None
    try:
        files = sorted(p for p in EFIVARS_DIR.iterdir() if p.name.rsplit("-", 5)[0] in SETUP_VARIABLES)
        # The first 4 bytes are the variable attributes, not data.
        result = {p.name: hashlib.sha256(p.read_bytes()[4:]).hexdigest() for p in files}
    except OSError:
        return None
    return result or None


# AMI TSE stores the setup passwords in AMITSESetup: CHAR16 UserPassword[20] (bytes 0-39),
# CHAR16 AdminPassword[20] (bytes 40-79), both encrypted by the BIOS; all zero = no password.
AMITSESETUP_VAR = "AMITSESetup-c811fa38-42c8-4579-a9bb-60e94eddfb34"


def ami_admin_password() -> Tuple[Optional[bool], Optional[str]]:
    """
    (is_set, fingerprint) of the AMI BIOS Administrator password, read from AMITSESetup
    (world-readable on Linux, no root needed). fingerprint = SHA-256 of the encrypted bytes:
    it changes when the password is changed or cleared (e.g. by an IFWI flash), and never
    reveals the password. (None, None) when it cannot be read (Windows, not an AMI BIOS).
    """
    if is_windows():
        return None, None
    try:
        data = (EFIVARS_DIR / AMITSESETUP_VAR).read_bytes()[4:]
    except OSError:
        return None, None
    if len(data) < 80:
        return None, None
    admin = data[40:80]
    if not any(admin):
        return False, None
    return True, hashlib.sha256(admin).hexdigest()


def detect_ami(override: str = "auto") -> Tuple[bool, str]:
    """
    (is_ami, reason). AMI Aptio BIOS = AMISCE can read/write its setup knobs.
    override: 'yes' / 'no' from config/test_config.yaml (bios.amisce), else auto-detect.
    """
    override = str(override or "auto").strip().lower()
    if override in ("yes", "true", "ami"):
        return True, "config/test_config.yaml bios.amisce = yes"
    if override in ("no", "false"):
        return False, "config/test_config.yaml bios.amisce = no"
    if not is_windows():
        try:
            names = [p.name for p in EFIVARS_DIR.iterdir()]
        except OSError:
            names = []
        ami_vars = sorted({n.split("-", 1)[0] for n in names if n.lower().startswith("ami")})
        if ami_vars:
            return True, f"AMI EFI variables present ({', '.join(ami_vars[:3])})"
    vendor = bios_identity()["vendor"]
    if "american megatrends" in vendor.lower():
        return True, f"BIOS vendor '{vendor}'"
    return False, f"BIOS vendor '{vendor or 'unknown'}', no AMI EFI variables"


# ------------------------------------------------------------------
# Low-level readers
# ------------------------------------------------------------------

def _run(cmd: List[str], timeout: int = 30) -> Optional[subprocess.CompletedProcess]:
    try:
        return subprocess.run(cmd, capture_output=True, timeout=timeout)
    except (OSError, subprocess.SubprocessError):
        return None


def _sudo(cmd: List[str]) -> List[str]:
    return cmd if is_admin() or not shutil.which("sudo") else ["sudo", "-n"] + cmd


def _read_root_file(path: Path) -> Optional[bytes]:
    """Read a root-only file (e.g. an ACPI table) directly, else via 'sudo -n cat'."""
    try:
        return path.read_bytes()
    except PermissionError:
        out = _run(_sudo(["cat", str(path)]))
        return out.stdout if out and out.returncode == 0 else None
    except OSError:
        return None


def acpi_table(signature: str) -> Optional[bytes]:
    """Raw ACPI table by its 4-character signature (e.g. 'DMAR', 'FACP'), or None if absent/unreadable."""
    if is_windows():
        import ctypes
        kernel32 = ctypes.windll.kernel32
        provider = struct.unpack(">I", b"ACPI")[0]
        table_id = struct.unpack("<I", signature.encode("ascii"))[0]
        size = kernel32.GetSystemFirmwareTable(provider, table_id, None, 0)
        if not size:
            return None
        buf = ctypes.create_string_buffer(size)
        if kernel32.GetSystemFirmwareTable(provider, table_id, buf, size) != size:
            return None
        return buf.raw
    return _read_root_file(ACPI_TABLES_DIR / signature)


def read_msr(address: int) -> Tuple[Optional[int], str]:
    """(value, how) for CPU 0's MSR on Linux; (None, reason) when it cannot be read."""
    if is_windows():
        return None, "Windows has no built-in MSR access"
    dev = Path("/dev/cpu/0/msr")
    if not dev.exists():
        _run(_sudo(["modprobe", "msr"]))
    try:
        fd = os.open(str(dev), os.O_RDONLY)
        try:
            return struct.unpack("<Q", os.pread(fd, 8, address))[0], str(dev)
        finally:
            os.close(fd)
    except OSError:
        pass
    if shutil.which("rdmsr"):
        out = _run(_sudo(["rdmsr", hex(address)]))
        if out and out.returncode == 0:
            try:
                return int(out.stdout.decode(errors="replace").split()[0], 16), "rdmsr"
            except (ValueError, IndexError):
                pass
    return None, "MSR not readable (needs sudo, msr-tools and the msr module: deploy/setup/setup_sut.sh)"


def _powershell(command: str, timeout: int = 60) -> str:
    out = _run(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", command], timeout=timeout)
    return out.stdout.decode(errors="replace").strip() if out and out.returncode == 0 else ""


def tpm_manufacturer() -> str:
    """TPM manufacturer ID ('INTC' = Intel PTT/fTPM), or '' if it cannot be read."""
    if is_windows():
        out = _run(["tpmtool", "getdeviceinformation"])
        text = out.stdout.decode(errors="replace") if out else ""
        for line in text.splitlines():
            m = re.search(r"(?:VendorID|Manufacturer(?:\s+ID)?)\s*:\s*([A-Za-z0-9]{2,8})", line, re.IGNORECASE)
            if m:
                return m.group(1).upper().strip()
        return ""
    if not shutil.which("tpm2_getcap"):
        return ""
    out = _run(_sudo(["tpm2_getcap", "properties-fixed"]))
    text = (out.stdout + out.stderr).decode(errors="replace") if out else ""
    m = re.search(r'TPM2_PT_MANUFACTURER[^"]*"([^"]+)"', text)
    return m.group(1).strip().upper() if m else ""


def flashed_ifwi() -> Tuple[Optional[str], str]:
    """
    ('ifwi_sep5' | 'ifwi_sed5' | None, how it was read). The IFWI fixes the TPM mux:
    RPSF_SEP5 = PTT, RPSF_SED5 = dTPM. The Resiliency ROM cannot be told apart from SEP5.
    """
    manufacturer = tpm_manufacturer()
    if not manufacturer:
        if is_windows():
            return None, "TPM manufacturer not readable -- run as Administrator ('tpmtool getdeviceinformation') with a TPM enabled"
        return None, "TPM manufacturer not readable -- is tpm2-tools installed and a TPM enabled?"
    if "INTC" in manufacturer:
        return "ifwi_sep5", f"TPM manufacturer {manufacturer} = PTT"
    return "ifwi_sed5", f"TPM manufacturer {manufacturer} = dTPM"


# ------------------------------------------------------------------
# Knob checks from the OS
# ------------------------------------------------------------------

def _state_vtd() -> Tuple[Optional[bool], str]:
    if is_windows():
        present = acpi_table("DMAR") is not None
    else:
        present = (ACPI_TABLES_DIR / "DMAR").exists()
    return present, "ACPI DMAR table present" if present else "no ACPI DMAR table"


def _state_low_power_s0() -> Tuple[Optional[bool], str]:
    fadt = acpi_table("FACP")
    if fadt and len(fadt) >= 116:
        flags = struct.unpack_from("<I", fadt, 112)[0]
        on = bool(flags & (1 << 21))
        return on, f"ACPI FADT LOW_POWER_S0_IDLE_CAPABLE = {int(on)}"
    if not is_windows():
        try:
            mem_sleep = Path("/sys/power/mem_sleep").read_text(encoding="utf-8").strip()
        except OSError:
            return None, "ACPI FADT and /sys/power/mem_sleep not readable"
        # With Low Power S0 Idle Disabled the kernel selects real S3 ([deep]).
        return "[deep]" not in mem_sleep, f"/sys/power/mem_sleep = '{mem_sleep}'"
    return None, "ACPI FADT not readable"


def _state_vmx() -> Tuple[Optional[bool], str]:
    if is_windows():
        import ctypes
        if ctypes.windll.kernel32.IsProcessorFeaturePresent(21):   # PF_VIRT_FIRMWARE_ENABLED
            return True, "firmware virtualization enabled"
        if _powershell("(Get-CimInstance Win32_ComputerSystem).HypervisorPresent").lower() == "true":
            return True, "Hyper-V is running (it needs VT-x)"
        return False, "firmware virtualization disabled and no hypervisor running"
    value, how = read_msr(0x3A)
    if value is not None:
        on = bool(value & 0x4)
        return on, f"MSR 0x3A = 0x{value:X} (VMX outside SMX = {int(on)})"
    try:
        flags = Path("/proc/cpuinfo").read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None, how
    on = bool(re.search(r"^flags\s*:.*\bvmx\b", flags, re.MULTILINE))
    return on, f"cpu flag 'vmx' {'present' if on else 'absent'} ({how})"


def _state_tme() -> Tuple[Optional[bool], str]:
    value, how = read_msr(0x982)
    if value is None:
        return None, how
    on = bool(value & 0x2)
    return on, f"MSR 0x982 IA32_TME_ACTIVATE = 0x{value:X} (TME enable = {int(on)})"


# x86-64 machine code for cpuid(leaf, subleaf, uint32_t out[4]) -- SysV (Linux) and Microsoft (Windows) ABI.
_CPUID_TAIL = bytes([0x0F, 0xA2,                    # cpuid
                     0x41, 0x89, 0x00,              # mov [r8], eax
                     0x41, 0x89, 0x58, 0x04,        # mov [r8+4], ebx
                     0x41, 0x89, 0x48, 0x08,        # mov [r8+8], ecx
                     0x41, 0x89, 0x50, 0x0C,        # mov [r8+12], edx
                     0x5B, 0xC3])                   # pop rbx; ret
_CPUID_CODE_SYSV = bytes([0x53, 0x89, 0xF8, 0x89, 0xF1, 0x49, 0x89, 0xD0]) + _CPUID_TAIL  # push rbx; eax=edi; ecx=esi; r8=rdx
_CPUID_CODE_WIN = bytes([0x53, 0x89, 0xC8, 0x89, 0xD1]) + _CPUID_TAIL                     # push rbx; eax=ecx; ecx=edx
_cpuid_func = None


def cpuid(leaf: int, subleaf: int = 0) -> Optional[Tuple[int, int, int, int]]:
    """(eax, ebx, ecx, edx) of the CPUID instruction on x86-64 -- no root, no compiler -- or None."""
    global _cpuid_func
    import ctypes
    if platform.machine().lower() not in ("x86_64", "amd64") or ctypes.sizeof(ctypes.c_void_p) != 8:
        return None
    try:
        if _cpuid_func is None:
            code = _CPUID_CODE_WIN if is_windows() else _CPUID_CODE_SYSV
            if is_windows():
                k32 = ctypes.windll.kernel32
                k32.VirtualAlloc.restype = ctypes.c_void_p
                k32.VirtualAlloc.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_ulong, ctypes.c_ulong]
                k32.VirtualProtect.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_ulong,
                                               ctypes.POINTER(ctypes.c_ulong)]
                mem = k32.VirtualAlloc(None, len(code), 0x3000, 0x04)        # MEM_COMMIT|RESERVE, RW
                if not mem:
                    return None
                ctypes.memmove(mem, code, len(code))
                if not k32.VirtualProtect(mem, len(code), 0x20, ctypes.byref(ctypes.c_ulong())):  # RX
                    return None
            else:
                import mmap
                libc = ctypes.CDLL(None, use_errno=True)
                libc.mmap.restype = ctypes.c_void_p
                libc.mmap.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int, ctypes.c_int,
                                      ctypes.c_int, ctypes.c_long]
                libc.mprotect.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int]
                size = mmap.PAGESIZE
                mem = libc.mmap(None, size, mmap.PROT_READ | mmap.PROT_WRITE,
                                mmap.MAP_PRIVATE | mmap.MAP_ANONYMOUS, -1, 0)
                if mem in (None, ctypes.c_void_p(-1).value):
                    return None
                ctypes.memmove(mem, code, len(code))
                if libc.mprotect(mem, size, mmap.PROT_READ | mmap.PROT_EXEC) != 0:
                    return None
            proto = ctypes.CFUNCTYPE(None, ctypes.c_uint32, ctypes.c_uint32, ctypes.POINTER(ctypes.c_uint32 * 4))
            _cpuid_func = proto(mem)
        out = (ctypes.c_uint32 * 4)()
        _cpuid_func(leaf, subleaf, ctypes.byref(out))
        return out[0], out[1], out[2], out[3]
    except Exception:  # noqa: BLE001 -- a probe must never crash the caller
        return None


def tme_supported() -> Tuple[Optional[bool], str]:
    """
    (supported, how): does this CPU have TME at all, whatever the BIOS says?
    CPUID.07H:ECX[13] (TME_EN); fallback on Linux: MSR 0x981 (IA32_TME_CAPABILITY) exists
    only on TME-capable CPUs, checked against MSR 0x3A so "MSRs not readable" is not mistaken
    for "no TME". None = cannot tell.
    """
    leaf0 = cpuid(0)
    if leaf0:
        vendor = struct.pack("<III", leaf0[1], leaf0[3], leaf0[2]).decode("ascii", errors="replace")
        if vendor != "GenuineIntel":
            return False, f"not an Intel CPU (CPUID vendor {vendor})"
        if leaf0[0] < 7:
            return False, f"CPUID has no leaf 7 (max leaf 0x{leaf0[0]:X})"
        ecx = cpuid(7, 0)[2]
        on = bool(ecx & (1 << 13))
        return on, f"CPUID.07H:ECX[13] (TME) = {int(on)}" + ("" if on else " -- this CPU has no TME (non-vPro)")
    if is_windows():
        return None, "CPUID not available here"
    cap, _how = read_msr(0x981)
    if cap is not None:
        return True, f"MSR 0x981 IA32_TME_CAPABILITY = 0x{cap:X}"
    control, how = read_msr(0x3A)
    if control is not None:
        return False, "MSR 0x981 (IA32_TME_CAPABILITY) does not exist -- this CPU has no TME (non-vPro)"
    return None, how


# Knobs that only work on CPUs with the matching feature: question (lower case) -> support probe.
_CPU_SUPPORT = {
    "total memory encryption": tme_supported,
}


def cpu_supports_knob(question: str) -> Tuple[Optional[bool], str]:
    """(supported, how) for a knob tied to a CPU feature; (None, '') for any other knob."""
    probe = _CPU_SUPPORT.get(question.strip().lower())
    if probe is None:
        return None, ""
    try:
        return probe()
    except Exception as exc:  # noqa: BLE001
        return None, f"CPU support check failed: {exc}"


def unsupported_knobs(knobs: Dict[str, str]) -> Dict[str, str]:
    """{question: why} for knobs wanted ON that this CPU cannot support -- setting them has no effect."""
    result = {}
    for question, option in knobs.items():
        if str(option).strip().lower() not in _ON:
            continue
        supported, how = cpu_supports_knob(question)
        if supported is False:
            result[question] = how
    return result


def _state_txt() -> Tuple[Optional[bool], str]:
    value, how = read_msr(0x3A)
    if value is None:
        return None, how
    on = bool(value & (1 << 15))
    return on, f"MSR 0x3A = 0x{value:X} (SENTER global enable = {int(on)})"


_PLAYREADY_HW_DRM = (
    "$null = [Windows.Media.Protection.PlayReady.PlayReadyStatics, Windows.Media.Protection.PlayReady, "
    "ContentType = WindowsRuntime]; $hw = [Windows.Media.Protection.PlayReady.PlayReadyStatics]::CheckSupportedHardware("
    "[Windows.Media.Protection.PlayReady.PlayReadyHardwareDRMFeatures]::HardwareDRM); "
    "$gpu = Get-CimInstance Win32_VideoController | Where-Object { $_.PNPDeviceID -like 'PCI\\VEN_8086*' "
    "-and $_.Status -eq 'OK' } | Select-Object -First 1; [string]$hw + '|' + $gpu.Name + '|' + $gpu.DriverVersion"
)


def _state_pavp() -> Tuple[Optional[bool], str]:
    if not is_windows():
        return None, "no OS check for PAVP on Linux"
    hw, gpu, driver = (_powershell(_PLAYREADY_HW_DRM).split("|") + ["", "", ""])[:3]
    # Intel graphics offer PlayReady hardware DRM only while PAVP is on.
    if hw.lower() == "true":
        return True, f"PlayReady hardware DRM available on {gpu or 'the GPU'} (needs PAVP)"
    if hw.lower() == "false" and gpu:
        return False, f"PlayReady hardware DRM not available on {gpu} (driver {driver}) -- PAVP is off"
    return None, "PlayReady hardware DRM not available and no working Intel graphics driver to tell why"


_OS_CHECKS = {
    "vt-d": _state_vtd,
    "low power s0 idle capability": _state_low_power_s0,
    "intel (vmx) virtualization technology": _state_vmx,
    "total memory encryption": _state_tme,
    "intel trusted execution technology": _state_txt,
    "pavp enable": _state_pavp,
}


def check_knob(question: str, option: str) -> KnobResult:
    """Check one knob from the running OS only."""
    key = question.strip().lower()
    wanted = str(option).strip().lower()

    if key == "tpm device selection":
        manufacturer = tpm_manufacturer()
        if not manufacturer:
            return KnobResult(question, option, None, "TPM manufacturer not readable")
        is_ptt = "INTC" in manufacturer
        actual = f"TPM manufacturer {manufacturer} ({'PTT' if is_ptt else 'dTPM'})"
        if wanted in ("ptt", "dtpm"):
            return KnobResult(question, option, is_ptt == (wanted == "ptt"), actual)
        return KnobResult(question, option, None, actual)

    check = _OS_CHECKS.get(key)
    if check is None:
        return KnobResult(question, option, None, f"no OS check for this knob on {platform.system()}", "")
    want_on = True if wanted in _ON else False if wanted in _OFF else None
    if want_on:
        supported, how = cpu_supports_knob(question)
        if supported is False:
            return KnobResult(question, option, False, f"not supported by this CPU: {how}")
    try:
        state, actual = check()
    except Exception as exc:  # noqa: BLE001 -- a probe must never crash the caller
        return KnobResult(question, option, None, f"OS check failed: {exc}", "")
    if state is None or want_on is None:
        return KnobResult(question, option, None, actual, "")
    return KnobResult(question, option, state == want_on, actual)


# ------------------------------------------------------------------
# AMISCE read-back (Windows, AMI BIOS) -- read-only, no reboot
# ------------------------------------------------------------------

def amisce_read(questions: Iterable[str]) -> Tuple[Dict[str, Optional[str]], str]:
    """({question: current option or None}, note). Empty dict when AMISCE cannot run here."""
    questions = list(questions)
    if not is_windows():
        return {}, "AMISCE on Linux runs from the UEFI Shell (pre-flight only)"
    tool_dir = Path(os.environ.get("SCE_WIN_DIR", str(REPO_ROOT / "Tools"))).expanduser().resolve()
    tool = tool_dir / os.environ.get("SCE_TOOL", "SCEWIN_64.exe")
    if not tool.is_file():
        try:
            where = tool_dir.relative_to(REPO_ROOT)
        except ValueError:
            where = tool_dir
        return {}, f"AMISCE not installed ({tool.name} not in {where})"
    if not is_admin():
        return {}, "AMISCE needs Administrator"
    with tempfile.TemporaryDirectory() as tmp:
        export = Path(tmp) / "bios_setup_export.txt"
        try:
            out = subprocess.run([str(tool), "/o", "/s", str(export)], cwd=str(tool_dir),
                                 capture_output=True, text=True, errors="replace", timeout=300)
        except (OSError, subprocess.SubprocessError) as exc:
            return {}, f"AMISCE could not run: {exc}"
        if out.returncode != 0 or not export.is_file():
            return {}, f"AMISCE export failed (exit code 0x{out.returncode:02X})"
        sys.path.insert(0, str(REPO_ROOT / "deploy" / "bios_knobs"))
        from get_bios_value import find_setup_value
        return {q: find_setup_value(str(export), q) for q in questions}, "AMISCE export"


# ------------------------------------------------------------------
# Operator attestation (pre-flight BIOS Setup step / Skip answer)
# ------------------------------------------------------------------

def record_attested(values: Dict[str, str], how: str) -> None:
    """Remember knobs a person set/confirmed by hand that no check can read back."""
    if not values:
        return
    ATTESTED_FILE.parent.mkdir(parents=True, exist_ok=True)
    ATTESTED_FILE.write_text(json.dumps({
        "bios": bios_identity(), "values": values, "how": how,
        "recorded": datetime.now().isoformat(timespec="seconds"),
    }, indent=2), encoding="utf-8")


def load_attested() -> Dict[str, Tuple[str, str]]:
    """{question (lower case): (option, how)} if the record is for this BIOS build and recent."""
    try:
        data = json.loads(ATTESTED_FILE.read_text(encoding="utf-8"))
        recorded = datetime.fromisoformat(data["recorded"])
    except (OSError, ValueError, KeyError, TypeError):
        return {}
    if not same_bios_build(data.get("bios")):
        return {}
    if (datetime.now() - recorded).total_seconds() > ATTESTED_MAX_AGE_HOURS * 3600:
        return {}
    how = f"{data.get('how', 'confirmed by the operator')} ({recorded:%Y-%m-%d %H:%M})"
    return {str(q).lower(): (str(o), how) for q, o in (data.get("values") or {}).items()}


def clear_attested() -> None:
    try:
        ATTESTED_FILE.unlink()
    except OSError:
        pass


# ------------------------------------------------------------------
# All sources together
# ------------------------------------------------------------------

def check_knobs(knobs: Dict[str, str], amisce: bool = False, attested: bool = False,
                known: Optional[Dict[str, Tuple[bool, str]]] = None) -> List[KnobResult]:
    """
    Check every knob: OS first, then (optionally) the AMISCE export, then evidence the
    caller read itself (known = {question: (ok, actual)}, e.g. a test's own MSR tool),
    then (optionally) the operator attestation. amisce=True only runs AMISCE when an
    OS check is missing.
    """
    results = [check_knob(q, o) for q, o in knobs.items()]
    unknown = [r for r in results if r.ok is None]
    if unknown and amisce:
        values, note = amisce_read(r.question for r in unknown)
        for r in unknown:
            value = values.get(r.question)
            if value is not None:
                r.ok, r.actual, r.source = value.lower() == str(r.expected).lower(), f"AMISCE reads {value}", "amisce"
            else:
                r.actual = f"{r.actual}; {note}" if not values else f"{r.actual}; not in the AMISCE export"
    evidence = {q.lower(): v for q, v in (known or {}).items()}
    for r in results:
        if r.ok is None and r.question.lower() in evidence:
            r.ok, r.actual = evidence[r.question.lower()]
            r.source = "test"
    unknown = [r for r in results if r.ok is None]
    if unknown and attested:
        record = load_attested()
        for r in unknown:
            entry = record.get(r.question.lower())
            if entry and entry[0].lower() == str(r.expected).lower():
                r.ok, r.actual, r.source = True, entry[1], "attested"
    return results


def format_results(results: List[KnobResult], indent: str = "  ") -> List[str]:
    """Aligned, one line per knob:  [OK]       "VT-d" = Enabled     ACPI DMAR table present"""
    if not results:
        return []
    names = [f'"{r.question}" = {r.expected}' for r in results]
    width = max(len(n) for n in names)
    return [f"{indent}{'[' + r.status + ']':<11}{name:<{width}}   {r.actual}" for r, name in zip(results, names)]
