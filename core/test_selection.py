# Copyright 2026 Intel Corporation
# SPDX-License-Identifier: Apache-2.0

"""
Test-selection rules shared by conftest.py (marker assignment, run order) and
test_runner.py (menu, context labels). Standard library only -- the runner
imports this without a pytest/paramiko environment.
"""

import configparser
import platform
import re
from pathlib import Path, PurePosixPath
from typing import Dict, List, Optional, Tuple

REPO_ROOT = Path(__file__).resolve().parent.parent

# Filename suffix -> execution-context marker. Most specific suffix first.
OS_CONTEXT_RULES = [
    (re.compile(r"_sut_wins_func\.py$"), "sut_windows"),
    (re.compile(r"_wins_func\.py$"), "wins_driven"),
    (re.compile(r"_sut_func\.py$"), "sut_linux"),
    (re.compile(r"_func\.py$"), "nuc_driven"),
]

# Filename substring -> the only IFWI group(s) the test runs on. First match wins.
IFWI_ONLY_RULES = [
    (re.compile(r"ftpm_ptt"), ("ifwi_sep5",)),
    (re.compile(r"dtpm"), ("ifwi_sed5",)),
    (re.compile(r"bios_resiliency"), ("ifwi_resiliency",)),
]
# Every other test: IFWI groups by execution context; contexts not listed run on DEFAULT_IFWI_GROUP only.
SHARED_IFWI_GROUPS = {"sut_linux": ("ifwi_sep5", "ifwi_sed5")}
DEFAULT_IFWI_GROUP = "ifwi_sep5"
# IFWI groups the running OS can tell apart (by TPM manufacturer: SEP5 = PTT, SED5 = dTPM).
DETECTABLE_IFWI_GROUPS = ("ifwi_sep5", "ifwi_sed5")

# Filename substring -> test needs UEFI Secure Boot ENABLED before it starts (PCR 7 checks).
# Tests that only need *signed* EFI tools when Secure Boot happens to be on are not listed.
SECURE_BOOT_RULES = [
    re.compile(r"ftpm_ptt"),
    re.compile(r"dtpm"),
]

# Suites whose BIOS knobs (deploy/bios_knobs/bios_knobs.yaml) are set by the test itself at a
# manual gate mid-test, so the runner pre-flight must not set them up front.
KNOBS_SET_MID_TEST: set = set()

# Suites whose bios_knobs.yaml entry is for their Linux test only; the Windows test needs no knob.
KNOBS_LINUX_ONLY = {"aesni"}

# Suites whose run cannot be undone: test_runner.py asks for a typed 'yes' before running them.
IRREVERSIBLE_SUITES = {
    "eom": "End of Manufacturing permanently locks the NVAR configuration and flash protection",
    "firmware": "the BIOS capsule update reflashes the BIOS",
}

# Setup the IFWI column of the test list cannot show (from each suite's PRE_TEST_CHECKLIST);
# test_runner.py prints it under the list.
SUITE_NOTES = {
    "rpmc": "needs an IFWI built in MFIT with RPMC FW Supported = Yes and RPMC Rebinding Enabled = Yes",
    "eom": "needs an IFWI built with HW Binding disabled",
    "csme": "needs the UPID OEM ID and Refurbish Counter noted from the IFWI in MFIT, and MEInfo on the SUT",
}

# (marker, menu label) in runner menu order.
IFWI_GROUPS = [
    ("ifwi_sep5", "SEP5 -- Bootguard5 EXTERNAL RPSF_SEP5 -- PTT; all tests but dTPM and Resiliency"),
    ("ifwi_sed5", "SED5 -- Bootguard5 EXTERNAL RPSF_SED5 -- dTPM; dTPM + Linux tests but fTPM and Resiliency"),
    ("ifwi_resiliency", "Resiliency -- custom Resiliency-ROM build -- bios_resiliency only"),
]

# Runner menu order; suite folders not listed here are appended alphabetically.
SUITE_MENU_ORDER = [
    "tme", "aesni", "txt", "measured_boot", "firmware", "csme", "pavp", "rpmc",
    "secure_debug", "sha_extension", "virtualization", "eom",
    "bios_resiliency", "hlat", "cet", "hdcp",
]


def _test_file(nodeid: str) -> PurePosixPath:
    return PurePosixPath(nodeid.split("::", 1)[0].replace("\\", "/"))


def suite_of(nodeid: str) -> str:
    """Suite folder name of a node id or test file path, e.g. 'tme'."""
    return _test_file(nodeid).parent.name


def os_context(nodeid: str) -> Optional[str]:
    """Execution-context marker for a node id or test file path, or None."""
    name = _test_file(nodeid).name
    for pattern, marker in OS_CONTEXT_RULES:
        if pattern.search(name):
            return marker
    return None


def host_context() -> Optional[str]:
    """SUT-local context this machine can run: 'sut_linux', 'sut_windows', or None."""
    return {"Linux": "sut_linux", "Windows": "sut_windows"}.get(platform.system())


def wrong_os_reason(nodeid: str) -> Optional[str]:
    """Skip reason if a SUT-local test targets the other OS than this host, else None."""
    context, host = os_context(nodeid), host_context()
    if host and context in ("sut_linux", "sut_windows") and context != host:
        target = "Windows" if context == "sut_windows" else "Linux"
        return f"{target}-only test; this host runs {platform.system()} -- run it on the {target} SUT"
    return None


def ifwi_groups(nodeid: str) -> Tuple[str, ...]:
    """IFWI-group markers a node id or test file path can run on."""
    name = _test_file(nodeid).name
    for pattern, groups in IFWI_ONLY_RULES:
        if pattern.search(name):
            return groups
    return SHARED_IFWI_GROUPS.get(os_context(nodeid), (DEFAULT_IFWI_GROUP,))


def ifwi_short_label(marker: str) -> str:
    """'ifwi_sep5' -> 'SEP5', from the menu label in IFWI_GROUPS."""
    for group_marker, desc in IFWI_GROUPS:
        if group_marker == marker:
            return desc.split(" -- ")[0].split(" (")[0].strip()
    return marker


def ifwi_label(nodeid: str) -> str:
    """'SEP5/SED5' for a test that runs on either image, 'SEP5 only' for one tied to one image."""
    groups = ifwi_groups(nodeid)
    labels = "/".join(ifwi_short_label(g) for g in groups)
    return labels if len(groups) > 1 else f"{labels} only"


def ifwi_checked(nodeid: str) -> bool:
    """True if the flashed IFWI, as read on this Linux SUT, decides whether this test can run."""
    groups = ifwi_groups(nodeid)
    return (os_context(nodeid) == "sut_linux" == host_context()
            and len(groups) == 1 and groups[0] in DETECTABLE_IFWI_GROUPS)


def wrong_ifwi_reason(nodeid: str, flashed: Optional[str], how: str) -> Optional[str]:
    """Skip reason if the flashed IFWI group cannot run this test, else None (also when flashed is unknown)."""
    if flashed is None or not ifwi_checked(nodeid) or flashed in ifwi_groups(nodeid):
        return None
    needed = ifwi_short_label(ifwi_groups(nodeid)[0])
    return f"needs the {needed} IFWI; flashed IFWI is {ifwi_short_label(flashed)} ({how})"


def requires_secure_boot(nodeid: str) -> bool:
    """True if the test needs UEFI Secure Boot enabled before it runs."""
    name = _test_file(nodeid).name
    return any(pattern.search(name) for pattern in SECURE_BOOT_RULES)


def bios_knob_spec(nodeid: str) -> Optional[str]:
    """
    deploy/bios_knobs/bios_knobs.yaml entry to apply before this test, as 'marker' or
    'marker:variant', or None if the runner must not set knobs up front.
    The YAML itself decides whether the entry is NA (~).
    """
    suite = suite_of(nodeid)
    if suite in KNOBS_SET_MID_TEST:
        return None
    if suite in KNOBS_LINUX_ONLY and os_context(nodeid) == "sut_windows":
        return None
    if suite == "measured_boot":
        return "measured_boot:dtpm" if "dtpm" in _test_file(nodeid).name else "measured_boot:ftpm_ptt"
    return suite


def run_order_rank(nodeid: str) -> int:
    """Sort key: eom (irreversible lock) and firmware (BIOS reflash) run last, eom first."""
    return {"eom": 1, "firmware": 2}.get(suite_of(nodeid), 0)


def marker_descriptions(ini_path: Path = REPO_ROOT / "pytest.ini") -> Dict[str, str]:
    """{marker: description} from the [pytest] markers entry of pytest.ini."""
    parser = configparser.ConfigParser(interpolation=None)
    parser.read(ini_path, encoding="utf-8")
    descriptions = {}
    for line in parser.get("pytest", "markers", fallback="").splitlines():
        name, sep, desc = line.partition(":")
        if sep:
            descriptions[name.strip()] = desc.strip()
    return descriptions


def discover_suites(tests_dir: Path = REPO_ROOT / "tests") -> List[str]:
    """Suite folder names under tests/ that contain test files, in menu order."""
    found = {p.name for p in tests_dir.iterdir() if p.is_dir() and any(p.glob("test_*.py"))}
    ordered = [s for s in SUITE_MENU_ORDER if s in found]
    return ordered + sorted(found - set(ordered))
