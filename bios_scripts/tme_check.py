# Copyright 2026 Intel Corporation
# SPDX-License-Identifier: Apache-2.0

"""
Intel TME Capability and Activation Status Auditor for Windows.

Features:
  1. Pure ctypes CPUID discovery (no compiler required). [Recommended]
  2. Multi-backend MSR 0x982 inspection: [External Tools below are not recommeded due to licensing]
     - msr-cmd.exe (with exact 3-column table decoding)
     - WinRing0x64.dll
  3. Elevated OEM BIOS WMI fallback querying (Dell, Lenovo, HP). [Recommended]
"""

import sys
import os
import re
import platform
import subprocess
import ctypes
from ctypes import wintypes

# Win32 Memory Management Constants
MEM_COMMIT = 0x00001000
MEM_RESERVE = 0x00002000
MEM_RELEASE = 0x00008000
PAGE_READWRITE = 0x04
PAGE_EXECUTE_READ = 0x20

kernel32 = ctypes.windll.kernel32

VirtualAlloc = kernel32.VirtualAlloc
VirtualAlloc.restype = ctypes.c_void_p
VirtualAlloc.argtypes = [ctypes.c_void_p, ctypes.c_size_t, wintypes.DWORD, wintypes.DWORD]

VirtualProtect = kernel32.VirtualProtect
VirtualProtect.restype = wintypes.BOOL
VirtualProtect.argtypes = [ctypes.c_void_p, ctypes.c_size_t, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]

VirtualFree = kernel32.VirtualFree
VirtualFree.restype = wintypes.BOOL
VirtualFree.argtypes = [ctypes.c_void_p, ctypes.c_size_t, wintypes.DWORD]


class NativeCpuidExecutor:
    """Executes CPUID via dynamically allocated machine code."""

    def __init__(self):
        self.is_64bit = (ctypes.sizeof(ctypes.c_void_p) == 8)
        self.code_bytes = self._assemble_machine_code()
        self.code_size = len(self.code_bytes)
        self.exec_mem = None
        self.cpuid_callable = None
        self._allocate_and_bind()

    def _assemble_machine_code(self):
        if self.is_64bit:
            return bytes([
                0x53,                         # push rbx
                0x89, 0xC8,                   # mov eax, ecx
                0x89, 0xD1,                   # mov ecx, edx
                0x0F, 0xA2,                   # cpuid
                0x41, 0x89, 0x00,             # mov [r8], eax
                0x41, 0x89, 0x58, 0x04,       # mov [r8 + 4], ebx
                0x41, 0x89, 0x48, 0x08,       # mov [r8 + 8], ecx
                0x41, 0x89, 0x50, 0x0C,       # mov [r8 + 12], edx
                0x5B,                         # pop rbx
                0xC3                          # ret
            ])
        else:
            return bytes([
                0x53,                         # push ebx
                0x57,                         # push edi
                0x8B, 0x44, 0x24, 0x0C,       # mov eax, [esp + 12]
                0x8B, 0x4C, 0x24, 0x10,       # mov ecx, [esp + 16]
                0x0F, 0xA2,                   # cpuid
                0x8B, 0x7C, 0x24, 0x14,       # mov edi, [esp + 20]
                0x89, 0x07,                   # mov [edi], eax
                0x89, 0x5F, 0x04,             # mov [edi + 4], ebx
                0x89, 0x4F, 0x08,             # mov [edi + 8], ecx
                0x89, 0x57, 0x0C,             # mov [edi + 12], edx
                0x5F,                         # pop edi
                0x5B,                         # pop ebx
                0xC3                          # ret
            ])

    def _allocate_and_bind(self):
        self.exec_mem = VirtualAlloc(None, self.code_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)
        if not self.exec_mem:
            raise ctypes.WinError()
        ctypes.memmove(self.exec_mem, self.code_bytes, self.code_size)
        old_protect = wintypes.DWORD()
        if not VirtualProtect(self.exec_mem, self.code_size, PAGE_EXECUTE_READ, ctypes.byref(old_protect)):
            raise ctypes.WinError()

        func_proto = ctypes.CFUNCTYPE(
            None,
            ctypes.c_uint32,
            ctypes.c_uint32,
            ctypes.POINTER(ctypes.c_uint32 * 4)
        )
        self.cpuid_callable = func_proto(self.exec_mem)

    def execute(self, leaf, subleaf=0):
        buffer = (ctypes.c_uint32 * 4)()
        self.cpuid_callable(leaf, subleaf, ctypes.byref(buffer))
        return buffer[0], buffer[1], buffer[2], buffer[3]

    def close(self):
        if self.exec_mem:
            VirtualFree(self.exec_mem, 0, MEM_RELEASE)
            self.exec_mem = None


def is_user_admin():
    """Verifies whether the current process token has Administrator privileges."""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


def decode_intel_vendor(ebx, ecx, edx):
    vendor_bytes = bytearray()
    for reg in (ebx, edx, ecx):
        vendor_bytes.extend(reg.to_bytes(4, byteorder='little'))
    return vendor_bytes.decode('ascii', errors='ignore')


# =========================================================================
# MSR Access Backends
# =========================================================================

def read_msr_via_msr_cmd(msr_addr=0x982):
    """Attempts MSR read using msr-cmd.exe."""
    exe_name = "msr-cmd.exe"
    target_path = exe_name if os.path.exists(exe_name) else None
    if not target_path:
        return None

    try:
        res = subprocess.run(
            [target_path, "read", hex(msr_addr)],
            capture_output=True,
            text=True,
            timeout=5
        )
        if res.returncode != 0:
            print(f"    [!] {exe_name} failed (rc={res.returncode}): {res.stderr.strip()}")
            return None
        output = res.stdout.strip()
        hex_tokens = re.findall(r"0x[0-9a-fA-F]+", output)

        if len(hex_tokens) >= 3:
            # Table output: [Register(0x982), EDX(bits 63:32), EAX(bits 31:0)]
            edx = int(hex_tokens[1], 16)
            eax = int(hex_tokens[2], 16)
            return (edx << 32) | eax
        elif len(hex_tokens) == 2:
            if int(hex_tokens[0], 16) == msr_addr:
                return int(hex_tokens[1], 16)
            return (int(hex_tokens[0], 16) << 32) | int(hex_tokens[1], 16)
        elif len(hex_tokens) == 1:
            return int(hex_tokens[0], 16)
    except (OSError, subprocess.SubprocessError) as exc:
        print(f"    [!] {exe_name} could not run: {exc}")
    return None


def read_msr_via_pcm(msr_addr=0x982):
    """Attempts MSR read via pcm-msr.exe."""
    exe_name = "pcm-msr.exe"
    target_path = exe_name if os.path.exists(exe_name) else None
    if not target_path:
        return None

    try:
        res = subprocess.run([target_path, hex(msr_addr)], capture_output=True, text=True, timeout=5)
        if res.returncode != 0:
            print(f"    [!] {exe_name} failed (rc={res.returncode}): {res.stderr.strip()}")
            return None
        match = re.search(r"Read value\s+(0x[0-9a-fA-F]+)", res.stdout, re.IGNORECASE)
        if match:
            return int(match.group(1), 16)
    except (OSError, subprocess.SubprocessError) as exc:
        print(f"    [!] {exe_name} could not run: {exc}")
    return None



def query_oem_bios_wmi():
    """Queries OEM WMI providers for firmware TME status."""
    print("    [*] Querying OEM UEFI/BIOS configurations via WMI...")

    ps_commands = (
            # Dell: matches 'TME Enable', 'IntelTME', or 'Total Memory Encryption'
            "try { "
            "  Get-CimInstance -Namespace root/dcim/sysman -ClassName DCIM_BIOSEnumeration -ErrorAction Stop | "
            "    Where-Object { $_.AttributeName -match 'TME|Memory Encryption' } | "
            "    ForEach-Object { Write-Output ('Dell_TME:' + $_.AttributeName + '=' + $_.CurrentValue) } "
            "} catch {}; "
            # Lenovo: matches 'Total Memory Encryption', 'Full encryption of main memory', or 'TME'
            "try { "
            "  Get-CimInstance -Namespace root/wmi -ClassName Lenovo_BiosSetting -ErrorAction Stop | "
            "    Where-Object { $_.CurrentSetting -match 'Full encryption of main memory|Total Memory Encryption|TME' } | "
            "    ForEach-Object { Write-Output ('Lenovo_TME:' + $_.CurrentSetting) } "
            "} catch {}; "
            # HP: matches 'Full encryption of main memory (DRAM)', 'Memory Encryption', etc., using CurrentValue
            "try { "
            "  Get-CimInstance -Namespace root/hp/instrumentedBIOS -ClassName HP_BIOSEnumeration -ErrorAction Stop | "
            "    Where-Object { $_.Name -match 'Full encryption of main memory|Memory Encryption|TME' } | "
            "    ForEach-Object { Write-Output ('HP_TME:' + $_.Name + '=' + $_.CurrentValue) } "
            "} catch {}; "
            # Fujitsu: matches FTS_BiosSetting under root/wmi
            "try { "
            "  Get-CimInstance -Namespace root/wmi -ClassName FTS_BiosSetting -ErrorAction Stop | "
            "    Where-Object { $_.CurrentSetting -match 'TME|Memory Encryption' } | "
            "    ForEach-Object { Write-Output ('Fujitsu_TME:' + $_.CurrentSetting) } "
            "} catch {}"
        )
    cmd = f'powershell.exe -NoProfile -Command "{ps_commands}"'
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=8)
        lines = [line.strip() for line in proc.stdout.splitlines() if line.strip()]
        if lines:
            for line in lines:
                print(f"        [+] BIOS Config Discovered: {line}")
            return True
        else:
            print("        [-] No standard OEM BIOS WMI entries enumerated.")
            return False
    except Exception as ex:
        print(f"        [-] WMI query failure: {ex}")
        return False


def decode_tme_activate_msr(msr_val, source_backend):
    """Decodes the 64-bit IA32_TME_ACTIVATE (0x982) register value."""
    lock = bool(msr_val & (1 << 0))
    hardware_enable = bool(msr_val & (1 << 1))
    algo_id = (msr_val >> 4) & 0x0F
    bypass_enable = bool(msr_val & (1 << 31))
    keyid_bits = (msr_val >> 32) & 0x0F

    algo_map = {0x0: "AES-XTS-128", 0x2: "AES-XTS-256"}
    algo_str = algo_map.get(algo_id, f"Unknown/Reserved ({algo_id})")

    print(f"\n    [+] Successfully read IA32_TME_ACTIVATE via {source_backend}:")
    print(f"        Raw MSR Value (0x982)         : 0x{msr_val:016X}")
    print(f"        Bit 0  (Lock Status)          : {'1 (LOCKED)' if lock else '0 (UNLOCKED)'}")
    print(f"        Bit 1  (Hardware Encryption)  : {'1 (ENABLED)' if hardware_enable else '0 (DISABLED)'}")
    print(f"        Bits 7:4 (Encryption Cipher)  : {algo_str}")
    print(f"        Bit 31 (Encryption Bypass)    : {'1 (BYPASSED - PLAINTEXT)' if bypass_enable else '0 (ACTIVE - ENCRYPTED)'}")
    print(f"        Bits 35:32 (MK-TME KeyID Bits): {keyid_bits} bit(s)")

    print("\n    [+] Cryptographic Verification Assessment:")
    if not lock:
        print("        [!] TME configuration register is not locked by BIOS.")
    elif hardware_enable and not bypass_enable:
        print("        [***] CONFIRMED: INTEL TME IS ACTIVELY ENCRYPTING MEMORY WITH KEYID 0 [***]")
    elif hardware_enable and bypass_enable:
        print("        [-] TME Engine is active, but KeyID 0 encryption is explicitly bypassed.")
    else:
        print("        [-] TME Hardware Encryption is DISABLED.")


def main():
    if platform.system() != "Windows":
        print("[ERROR] This script is designed for Windows.")
        sys.exit(1)

    print("=" * 75)
    print("      Intel Total Memory Encryption (TME) Capability and Status Audit")
    print("=" * 75)

    is_admin = is_user_admin()
    print(f"[*] Process Privilege Level     : {'Elevated (Administrator)' if is_admin else 'Standard User'}")
    if not is_admin:
        print("    [!] Note: Re-run with 'Run as administrator' for Ring 0 MSR inspection.")

    executor = NativeCpuidExecutor()
    try:
        # Step 1: Query CPUID
        eax_0, ebx_0, ecx_0, edx_0 = executor.execute(0x00000000, 0)
        vendor_id = decode_intel_vendor(ebx_0, ecx_0, edx_0)
        max_basic_leaf = eax_0

        print(f"[*] Processor Vendor ID         : {vendor_id}")
        print(f"[*] Maximum Basic CPUID Leaf    : 0x{max_basic_leaf:08X}")

        if vendor_id != "GenuineIntel" or max_basic_leaf < 0x07:
            print("[-] Processor does not meet prerequisites for Intel TME.")
            return

        eax_7, ebx_7, ecx_7, edx_7 = executor.execute(0x00000007, 0x00000000)
        tme_supported = bool(ecx_7 & (1 << 13))
        pconfig_supported = bool(edx_7 & (1 << 18))

        print("\n--- [1. Hardware Capability Detection (User-Mode Ring 3 CPUID)] ---")
        print(f"    Raw Registers [07H:00H]     : EAX=0x{eax_7:08X} EBX=0x{ebx_7:08X} ECX=0x{ecx_7:08X} EDX=0x{edx_7:08X}")
        print(f"    TME Baseline Support (ECX[13]): {'[+] SUPPORTED' if tme_supported else '[-] NOT SUPPORTED'}")
        print(f"    PCONFIG Support (EDX[18])   : {'[+] SUPPORTED' if pconfig_supported else '[-] NOT SUPPORTED'}")

        if not tme_supported:
            print("\n[-] Processor silicon lacks TME hardware encryption units.")
            return

        print("\n--- [2. Activation and Enablement Status Diagnostics (Ring 0 / BIOS)] ---")

        msr_val = None
        source_backend = None

        backends = [
            ("msr-cmd.exe", read_msr_via_msr_cmd),
            ("pcm-msr.exe", read_msr_via_pcm)
        ]

        for name, func in backends:
            val = func(0x982)
            if val is not None:
                msr_val = val
                source_backend = name
                break

        if msr_val is not None:
            decode_tme_activate_msr(msr_val, source_backend)
        else:
            print("    [-] Direct MSR tool not found in folder or driver access was blocked.")
            query_oem_bios_wmi()

    finally:
        executor.close()
    print("=" * 75)


if __name__ == "__main__":
    main()