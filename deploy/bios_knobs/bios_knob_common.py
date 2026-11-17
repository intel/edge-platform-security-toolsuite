# Copyright 2026 Intel Corporation
# SPDX-License-Identifier: Apache-2.0
"""
deploy/bios_knobs/bios_knob_common.py — OS-independent parts of the BIOS knob runbooks.

Shared by configure_bios_knobs_linux.py (SceEfi64.efi from the UEFI Shell) and
configure_bios_knobs_windows.py (Windows, SCEWIN_64.exe in the OS): the
bios_knobs.yaml schema, AMISCE script editing and the value checks.
"""

import os
import re
import subprocess
import sys
from pathlib import Path

DEPLOY_DIR = Path(__file__).resolve().parent
REPO_ROOT = DEPLOY_DIR.parents[1]
GET_BIOS_VALUE = DEPLOY_DIR / "get_bios_value.py"
DEFAULT_CONFIG = DEPLOY_DIR / "bios_knobs.yaml"
TEST_CONFIG = REPO_ROOT / "config" / "test_config.yaml"
ADMIN_PASSWORD_ENV = "BIOS_ADMIN_PASSWORD"
PASSWORD_MASK = "********"
sys.path.insert(0, str(DEPLOY_DIR))
from get_bios_value import find_setup_value  # noqa: E402

EXTRACT_FILE = "bios_value_extracted.txt"
MODIFIED_FILE = "bios_value_modified.txt"
VERIFY_FILE = "bios_value_verify.txt"

# AMISCE User Guide, section "SCE Exit Codes"
SCE_EXIT_CODES = {
    0x00: "Operation completed successfully.",
    0x0D: "Invalid script file or command line parameter.",
    0x0E: "Kernel source files cannot be found.",
    0x0F: "Unable to make kernel driver.",
    0x10: "Unable to load driver.",
    0x11: "Unable to unload driver.",
    0x17: "Script file CRC check against current BIOS failed.",
    0x20: "Unable to initialize memory manager.",
    0x22: "Unable to allocate required memory.",
    0x26: "Unable to map physical memory.",
    0x57: "Incorrect command line usage.",
    0x61: "A program instance is already running.",
    0x71: "Unable to generate driver automatically when Secure Boot is enabled.",
    0x82: "Invalid password.",
    0x86: "Admin password does not exist.",
    0x8F: "Password retry count exceeded.",
    0x9A: "Password does not match admin password.",
}

# Exit codes of an import with /cpwd <admin_pwd> -> what the operator has to fix
_ASK_AGAIN = "pick the tests again in test_runner.py -- it asks for the password (Linux)"
SCE_PASSWORD_HINTS = {
    0x82: f"the BIOS rejected the admin password: {_ASK_AGAIN}",
    0x86: "the BIOS has no Administrator password: pick the tests again in test_runner.py -- "
          "it offers to set one up in BIOS Setup (Linux)",
    0x8F: f"too many wrong passwords: power-cycle the SUT, then {_ASK_AGAIN}",
    0x9A: f"wrong admin password: {_ASK_AGAIN}",
}


class _Tee:
    """Write to the console and the runbook log at once."""

    def __init__(self, *streams):
        self._streams = streams

    def write(self, data):
        for stream in self._streams:
            stream.write(data)

    def flush(self):
        for stream in self._streams:
            stream.flush()


class RunbookError(Exception):
    pass


def ok(msg):
    print(f"[OK]     {msg}")


def warn(msg):
    print(f"[WARN]   {msg}")


def info(msg):
    print(f"         {msg}")


def action(msg):
    print(f"[ACTION] {msg}")


def describe_sce_exit(code):
    return SCE_EXIT_CODES.get(code, "unknown exit code")


def sce_password_failure(code):
    """Failure text if an AMISCE exit code is a password error, else None."""
    if code not in SCE_PASSWORD_HINTS:
        return None
    return f"AMISCE exit code 0x{code:02X} — {describe_sce_exit(code)} ({SCE_PASSWORD_HINTS[code]})"


# ------------------------------------------------------------------
# BIOS Administrator password (AMISCE /cpwd)
# ------------------------------------------------------------------

def load_admin_password(config_path=TEST_CONFIG):
    """
    (password, source) for AMISCE '/cpwd <admin_pwd>', or ("", None) if none is available.

    AMISCE skips protected setup variables (e.g. CpuSetup: TME, VMX, TXT) unless the
    import passes the BIOS Administrator password ("Cannot update protected variable
    CpuSetup. Please use /cpwd <admin_pwd>"), yet still exits 0. Source order:
    environment variable BIOS_ADMIN_PASSWORD, bios.admin_password in config/test_config.yaml
    (both optional overrides, e.g. for CI), then the password test_runner.py asked for once
    and stored encrypted (bios_password.py, Linux, needs root). Never log the returned password.
    """
    value = os.environ.get(ADMIN_PASSWORD_ENV)
    if value:
        return value, f"environment variable {ADMIN_PASSWORD_ENV}"
    value, source = _config_admin_password(config_path)
    if value:
        return value, source
    if sys.platform.startswith("linux"):
        import bios_password
        value = bios_password.load()
        if value:
            return value, bios_password.SOURCE_LABEL
    return "", None


def _config_admin_password(config_path):
    path = Path(config_path)
    if not path.is_file():
        return "", None
    try:
        import yaml
    except ImportError:
        warn(f"PyYAML is not available: bios.admin_password in {path} cannot be read.")
        return "", None
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError) as exc:
        raise RunbookError(f"Cannot read {path}: {exc}") from exc
    bios = data.get("bios") if isinstance(data, dict) else None
    value = bios.get("admin_password") if isinstance(bios, dict) else None
    if value is None or value == "":
        return "", None
    if not isinstance(value, str):
        # YAML turns an unquoted 0123 into 83, 1e3 into 1000.0 ...
        raise RunbookError(f"bios.admin_password in {path} must be a quoted string "
                           "(YAML reads an unquoted 0123 as the number 83)")
    return value, f"bios.admin_password in {path}"


def admin_password_status(config_path=TEST_CONFIG):
    """
    No root needed -- for test_runner.py. bios_password.status() (Linux), or state 'provided'
    when BIOS_ADMIN_PASSWORD / bios.admin_password supplies it, 'unknown' elsewhere.
    """
    try:
        configured, source = _config_admin_password(config_path)
    except RunbookError:
        configured, source = "", None
    if os.environ.get(ADMIN_PASSWORD_ENV) or configured:
        return {"state": "provided", "message": source or f"environment variable {ADMIN_PASSWORD_ENV}"}
    if not sys.platform.startswith("linux"):
        return {"state": "unknown", "message": f"Windows: set {ADMIN_PASSWORD_ENV} or bios.admin_password"}
    import bios_password
    return bios_password.status()


def explain_unchanged_knobs(used_password):
    """After an import that exited 0: the likely reason a knob kept its old value."""
    if used_password:
        warn("The import ran with /cpwd but a knob kept its old value: it is probably grayed out by")
        info("a dependency (see its Help String in the exported script) or not supported by this CPU.")
        return
    warn("The import exited 0 but a knob kept its old value. Without the BIOS Administrator password,")
    info("AMISCE skips protected variables such as CpuSetup (TME, VMX, TXT ...) and only prints")
    info("'Cannot update protected variable CpuSetup. Please use /cpwd <admin_pwd>'.")
    info("Fix: pick the tests again in test_runner.py -- it asks for the BIOS admin password once")
    info("(or offers to set one up in BIOS Setup) and stores it encrypted; the import then uses /cpwd.")


# ------------------------------------------------------------------
# Knob selection (bios_knobs.yaml / --knob)
# ------------------------------------------------------------------

def parse_knobs(knob_args):
    knobs = {}
    for item in knob_args:
        question, sep, option = item.partition("=")
        if not sep or not question.strip() or not option.strip():
            raise RunbookError(f'--knob must be "<Setup Question>=<option>", got: {item!r}')
        knobs[question.strip()] = option.strip()
    return knobs


def load_marker_config(path):
    """The 'markers:' mapping of the YAML config."""
    try:
        import yaml
    except ImportError as exc:
        raise RunbookError(
            "PyYAML is not available to this Python. Run with the project venv (../venv),\n"
            "         or use --knob \"<Setup Question>=<option>\" instead of --marker."
        ) from exc
    path = Path(path)
    if not path.is_file():
        raise RunbookError(f"Config file not found: {path}")
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    markers = data.get("markers") if isinstance(data, dict) else None
    if not isinstance(markers, dict):
        raise RunbookError(f"{path}: expected a 'markers:' mapping (see the header of {DEFAULT_CONFIG.name})")
    return markers


def load_menu_paths(path=DEFAULT_CONFIG):
    """{setup question (lower case): BIOS Setup menu path} from the 'menu_paths:' mapping, or {}."""
    try:
        import yaml
        data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    except (ImportError, OSError, ValueError):
        return {}
    paths = data.get("menu_paths") if isinstance(data, dict) else None
    if not isinstance(paths, dict):
        return {}
    return {str(q).strip().lower(): str(p).strip() for q, p in paths.items() if p}


def knob_values_match(knobs, script):
    """True if the exported AMISCE script already has every wanted option selected (no output)."""
    script = Path(script)
    if not knobs or not script.is_file():
        return False
    for question, option in knobs.items():
        value = find_setup_value(str(script), question)
        if value is None or value.lower() != str(option).lower():
            return False
    return True


def report_to_preflight(passed, detail, values=None, script=None):
    """
    End of a runbook: remember the knob values that passed on this BIOS build,
    and let deploy/preflight/preflight_chain.py continue a test_runner.py
    pre-flight that started this runbook (no effect when run by hand).
    script: this run's latest AMISCE export -- knobs recorded by an earlier PASS
    are kept only if it still shows them.
    """
    sys.path.insert(0, str(DEPLOY_DIR.parent / "preflight"))
    try:
        import preflight_chain
    except ImportError:
        return
    if passed and values:
        still_set = None
        if script and Path(script).is_file():
            def still_set(question, option):
                value = find_setup_value(str(script), question)
                return value is not None and value.lower() == str(option).lower()
        try:
            preflight_chain.record_knob_pass(values, still_set)
        except OSError as exc:
            warn(f"Could not record the knob values in {preflight_chain.KNOB_LAST_PASS_FILE}: {exc}")
    preflight_chain.report("bios_knobs", passed, detail)


def knobs_from_mapping(entries, where, required=True):
    """Validate a "<Setup Question>": <option> mapping; entries set to ~ are left unchanged."""
    if entries is None and not required:
        return {}
    if not isinstance(entries, dict) or not entries:
        raise RunbookError(f"{where}: must be a non-empty mapping of \"<Setup Question>\": <option>")
    knobs = {}
    for question, option in entries.items():
        if option is None:
            continue
        if not isinstance(option, (str, int)) or isinstance(option, bool):
            raise RunbookError(
                f"{where}: '{question}' has value {option!r}; use the option label as text "
                "(quote yes/no/on/off/true/false)."
            )
        if not str(option).strip():
            raise RunbookError(f"{where}: '{question}' has an empty option")
        knobs[str(question).strip()] = str(option).strip()
    if not knobs:
        raise RunbookError(f"{where}: no knob selected (every entry is ~)")
    return knobs


def choose_variant(marker, variants):
    names = list(variants)
    if not sys.stdin.isatty():
        raise RunbookError(f"Marker '{marker}' needs --variant, one of: {', '.join(names)}")
    print(f"Marker '{marker}' has more than one knob set:")
    for i, name in enumerate(names, 1):
        print(f"  [{i}] {name:<10} {(variants[name] or {}).get('description', '')}")
    while True:
        choice = input(f"Select (1-{len(names)}, or 0 to cancel): ").strip()
        if choice == "0":
            raise RunbookError("Cancelled by operator.")
        if choice.isdigit() and 1 <= int(choice) <= len(names):
            return names[int(choice) - 1]


def resolve_profile(config_path, marker, variant=None):
    """
    Knob profile for a marker: dict(marker, variant, description, verify_only, knobs, verify_knobs),
    or None when the marker needs no BIOS knob configuration (NA).
    """
    markers = load_marker_config(config_path)
    if marker not in markers:
        raise RunbookError(
            f"Marker '{marker}' is not in {config_path}.\n"
            f"         Known markers: {', '.join(markers)}"
        )
    entry = markers[marker]
    if entry is None:
        if variant:
            raise RunbookError(f"Marker '{marker}' has no variants (NA).")
        return None
    if not isinstance(entry, dict):
        raise RunbookError(f"{config_path}: marker '{marker}' must be ~ or a mapping")

    where = f"{config_path}: {marker}"
    verify_only = bool(entry.get("verify_only", False))
    description = entry.get("description", "")
    variants = entry.get("variants")
    if variants:
        variant = variant or choose_variant(marker, variants)
        if variant not in variants:
            raise RunbookError(f"Marker '{marker}' has no variant '{variant}'; use one of: {', '.join(variants)}")
        sub = variants[variant] or {}
        verify_only = bool(sub.get("verify_only", verify_only))
        description = sub.get("description", description)
        knobs = knobs_from_mapping(sub.get("knobs"), f"{where}.{variant} knobs", required=False)
        verify_knobs = knobs_from_mapping(sub.get("verify_knobs"), f"{where}.{variant} verify_knobs", required=False)
    else:
        if variant:
            raise RunbookError(f"Marker '{marker}' has no variants.")
        knobs = knobs_from_mapping(entry.get("knobs"), f"{where} knobs", required=False)
        verify_knobs = knobs_from_mapping(entry.get("verify_knobs"), f"{where} verify_knobs", required=False)
    if not knobs and not verify_knobs:
        raise RunbookError(f"{where}: no knob selected (use ~ for NA, or add 'knobs'/'verify_knobs')")
    return {"marker": marker, "variant": variant, "description": description,
            "verify_only": verify_only, "knobs": knobs, "verify_knobs": verify_knobs}


def merge_profiles(profiles):
    """
    One profile from several resolved profiles (a test selection that spans suites).
    The same knob asked for with two different options is a RunbookError.
    """
    if len(profiles) == 1:
        return profiles[0]
    if len({bool(p["verify_only"]) for p in profiles}) > 1:
        raise RunbookError("Cannot combine a verify_only marker with markers that set knobs; run them separately.")
    merged = {"marker": None, "variant": None, "verify_only": profiles[0]["verify_only"],
              "description": "", "knobs": {}, "verify_knobs": {}}
    for kind in ("knobs", "verify_knobs"):
        owners = {}
        for profile in profiles:
            who = profile["marker"] + (f":{profile['variant']}" if profile["variant"] else "")
            for question, option in profile[kind].items():
                key = question.lower()
                if key in owners and owners[key][1].lower() != option.lower():
                    raise RunbookError(
                        f'Conflicting values for "{question}": {owners[key][1]} ({owners[key][0]}) '
                        f"vs {option} ({who}).\n"
                        "         These tests need different BIOS settings (often a different IFWI) "
                        "-- run them separately."
                    )
                if key not in owners:
                    owners[key] = (who, option)
                    merged[kind][question] = option
    return merged


def resolve_markers(config_path, specs, variant=None):
    """
    (profile, label) for one or more 'marker' / 'marker:variant' specs, merged;
    profile is None when every marker is NA. --variant only applies to a single spec.
    """
    if variant and len(specs) > 1:
        raise RunbookError("--variant works with one --marker; use --marker <marker>:<variant> for several.")
    profiles, labels = [], []
    for spec in specs:
        marker, _, spec_variant = spec.partition(":")
        profile = resolve_profile(config_path, marker.strip(), spec_variant.strip() or variant)
        if profile is None:
            continue
        profiles.append(profile)
        labels.append(marker.strip() + (f" --variant {profile['variant']}" if profile["variant"] else ""))
    if not profiles:
        return None, ", ".join(specs)
    return merge_profiles(profiles), " + ".join(labels)


def select_profile(args):
    """
    (profile, label) from --knob or --marker/--variant; profile is None for an NA marker.
    --marker may be repeated (or 'marker:variant'); the knob sets are merged.
    Knobs for a CPU feature this CPU lacks are moved to profile['unsupported'] (never set).
    """
    profile, label = _select_profile(args)
    if profile is not None:
        drop_unsupported_knobs(profile)
    return profile, label


def drop_unsupported_knobs(profile):
    """
    Move knobs this CPU cannot support (e.g. TME on a non-vPro CPU: CPUID.07H:ECX[13] = 0)
    from profile['knobs'] to profile['unsupported'] = {question: why}. The BIOS accepts such a
    knob and AMISCE reads it back as set, but the CPU ignores it -- so it is never imported.
    """
    if str(REPO_ROOT) not in sys.path:
        sys.path.insert(0, str(REPO_ROOT))
    try:
        from core import bios_knob_checks
    except ImportError:
        profile["unsupported"] = {}
        return profile
    unsupported = bios_knob_checks.unsupported_knobs(profile["knobs"])
    for question in unsupported:
        profile["knobs"].pop(question)
    profile["unsupported"] = unsupported
    if profile["knobs"] or profile["verify_knobs"] or not unsupported:
        return profile
    raise RunbookError("Nothing to set: " + "; ".join(f"'{q}' -- {why}" for q, why in unsupported.items()))


def _select_profile(args):
    markers = args.marker or []
    if args.knob and markers:
        raise RunbookError("Use either --marker or --knob, not both.")
    if args.knob:
        profile = {"marker": None, "variant": None, "description": "one-off --knob",
                   "verify_only": args.verify_only, "knobs": parse_knobs(args.knob), "verify_knobs": {}}
        return profile, "--knob"
    if not markers:
        raise RunbookError(
            "Choose the knobs with --marker <marker> (see 'list') or --knob \"<Setup Question>=<option>\"."
        )
    profile, label = resolve_markers(args.config, markers, args.variant)
    if profile is None:
        return None, label
    profile["verify_only"] = profile["verify_only"] or args.verify_only
    return profile, label


def print_profile(profile, label):
    knobs = profile["knobs"]
    print(f"Profile      : {label}{' - ' + profile['description'] if profile['description'] else ''}")
    print(f"Mode         : {'verify only (no import)' if (profile['verify_only'] or not knobs) else 'set + verify'}")
    for question, option in knobs.items():
        print(f'  "{question}" > {option}')
    for question, option in profile["verify_knobs"].items():
        print(f'  "{question}" > {option}  (read-only check; fixed by flashed IFWI, never imported)')
    for question, why in (profile.get("unsupported") or {}).items():
        warn(f'"{question}" skipped -- {why}. The BIOS accepts it, but this CPU ignores it;')
        info("tests that need it fail with this reason.")


def print_na(label):
    print("=" * 74)
    print(f"NOTE: No BIOS knob configuration is needed for marker '{label}'.")
    print("      Run the tests directly.")
    print("=" * 74)


def cmd_list(args):
    markers = load_marker_config(args.config)
    print(f"Markers in {Path(args.config).resolve()}:")
    for marker in markers:
        try:
            entry = markers[marker]
            if entry is None:
                print(f"  {marker:<34} NA - no BIOS knob configuration needed")
                continue
            for variant in (entry.get("variants") or {None: None}):
                profile = resolve_profile(args.config, marker, variant)
                label = f"{marker} --variant {variant}" if variant else marker
                mode = "verify only" if (profile["verify_only"] or not profile["knobs"]) else "set"
                knobs = ", ".join(f'"{q}">{o}' for q, o in profile["knobs"].items())
                verify_knobs = ", ".join(f'"{q}">{o} (read-only)' for q, o in profile["verify_knobs"].items())
                print(f"  {label:<34} {mode:<11} {', '.join(filter(None, [knobs, verify_knobs]))}")
        except RunbookError as exc:
            print(f"  {marker:<34} CONFIG ERROR: {exc}")
    return 0


def add_common_arguments(ap):
    ap.add_argument("command", nargs="?", default="run",
                    choices=["run", "list", "resume", "status", "abort", "password"])
    ap.add_argument("--set", action="store_true",
                    help="password: ask for the BIOS admin password (typed, not echoed) and store it encrypted")
    ap.add_argument("--new", action="store_true",
                    help="password --set: a NEW password, to be typed in BIOS Setup after the next reboot")
    ap.add_argument("--forget", action="store_true", help="password: delete the stored BIOS admin password")
    ap.add_argument("--marker", action="append",
                    help="Test marker whose knobs to apply (see 'list'), e.g. ifwi_sep5. Repeatable; "
                         "'<marker>:<variant>' picks a variant, e.g. --marker tme --marker measured_boot:ftpm_ptt")
    ap.add_argument("--variant", help="Knob set of a single marker with variants, e.g. measured_boot: ftpm_ptt / dtpm")
    ap.add_argument("--config", default=str(DEFAULT_CONFIG),
                    help=f"YAML file with the knobs per marker (default: {DEFAULT_CONFIG})")
    ap.add_argument("--knob", action="append",
                    help='One-off "<Setup Question>=<option>", repeatable; instead of --marker')
    ap.add_argument("--verify-only", action="store_true",
                    help="Only read and check the knob values; do not import anything.")
    ap.add_argument("--reboot-delay", type=int, metavar="SECONDS",
                    help="Countdown before the first reboot of this run (default: REBOOT_DELAY or 10; "
                         "test_runner.py passes 0)")


# ------------------------------------------------------------------
# AMISCE script editing and checks
# ------------------------------------------------------------------

def set_amisce_option(script_text, question, option_label):
    """
    Move '*' to option_label in every Options block of question.

    Returns (new_text, number_of_blocks_changed). Raises ValueError when the
    question or the option does not exist, or the question has no Options list.
    """
    question_re = re.compile(r"^\s*Setup Question\s*=\s*(.*?)\s*$")
    options_re = re.compile(r"^\s*Options\s*=")
    option_re = re.compile(
        r"^(?P<lead>\s*(?:Options\s*=\s*)?)(?P<star>\*?)(?P<code>\[[0-9A-Fa-f]+\])"
        r"(?P<label>[^\t\r\n]*?)(?P<tail>(?:\s*//[^\r\n]*)?\s*)$"
    )
    want_q = question.strip().lower()
    want_opt = option_label.strip().lower()
    lines = script_text.splitlines(keepends=True)
    changed = 0
    i = 0
    while i < len(lines):
        m = question_re.match(lines[i])
        i += 1
        if not m or m.group(1).strip().lower() != want_q:
            continue

        while (i < len(lines) and lines[i].strip()
               and not question_re.match(lines[i]) and not options_re.match(lines[i])):
            i += 1
        if i >= len(lines) or not options_re.match(lines[i]) or not option_re.match(lines[i]):
            raise ValueError(f"'{question}' has no Options list (not an option-type knob)")

        idx = [i]
        i += 1
        while i < len(lines) and option_re.match(lines[i]) and not options_re.match(lines[i]):
            idx.append(i)
            i += 1

        labels = [option_re.match(lines[k]).group("label").strip() for k in idx]
        if want_opt not in (label.lower() for label in labels):
            raise ValueError(f"option '{option_label}' not available; options are {labels}")

        for k in idx:
            om = option_re.match(lines[k])
            star = "*" if om.group("label").strip().lower() == want_opt else ""
            lines[k] = om.group("lead") + star + om.group("code") + om.group("label") + om.group("tail")
        changed += 1

    if not changed:
        raise ValueError(f"Setup Question '{question}' not found")
    return "".join(lines), changed


def build_modified_script(extracted, knobs, work_copy):
    """Step 3: write work_copy = extracted with '*' moved to every wanted option, then re-read it."""
    extracted = Path(extracted)
    if not extracted.is_file() or extracted.stat().st_size == 0:
        raise RunbookError(f"Export produced no script: {extracted}")
    ok(f"Extracted: {extracted} ({extracted.stat().st_size} bytes)")

    # surrogateescape keeps any non-UTF-8 bytes of the AMISCE file unchanged
    text = extracted.read_bytes().decode("utf-8", errors="surrogateescape")
    for question, option in knobs.items():
        current = find_setup_value(str(extracted), question)
        info(f"'{question}': current={current!r} wanted={option!r}")
        try:
            text, blocks = set_amisce_option(text, question, option)
        except ValueError as exc:
            raise RunbookError(f"Cannot set '{question}' = '{option}': {exc}") from exc
        ok(f"'*' moved to '{option}' in {blocks} block(s) of '{question}'")

    work_copy = Path(work_copy)
    work_copy.parent.mkdir(parents=True, exist_ok=True)
    work_copy.write_bytes(text.encode("utf-8", errors="surrogateescape"))
    ok(f"Working copy: {work_copy}")

    for question, option in knobs.items():
        value = find_setup_value(str(work_copy), question)
        if value is None or value.lower() != option.lower():
            raise RunbookError(f"Working copy check failed for '{question}': expected {option!r}, got {value!r}")
    ok("Working copy has every wanted option selected")


def check_fixed_knobs(verify_knobs, script):
    """
    verify_knobs: read-only checks for values AMISCE cannot import (e.g. a knob
    fixed by the flashed IFWI). Checked right after export, before any import,
    so a mismatch fails fast instead of burning reboots on a knob that was
    never going to take effect.
    """
    print("--- Fixed/read-only knob check ---------------------------------------------")
    script = Path(script)
    if not script.is_file() or script.stat().st_size == 0:
        return False, f"Export produced no script: {script}"

    failures = []
    for question, option in verify_knobs.items():
        value = find_setup_value(str(script), question)
        info(f"'{question}' (read-only): current={value!r} expected={option!r}")
        if value is None or value.lower() != option.lower():
            failures.append(f"'{question}': expected '{option}', got '{value}'")
        else:
            ok(f"'{question}' = {value}")
    if failures:
        warn("Fixed/read-only knob mismatch — this is not something a BIOS import can change here.")
        warn("Flash the IFWI variant that provides the wanted value and re-run.")
        return False, "; ".join(failures)
    return True, ", ".join(f"{q} = {o}" for q, o in verify_knobs.items())


def check_knobs(knobs, script):
    """Step 6: get_bios_value.py on the exported script must print each wanted option."""
    print("--- Step 6: check --------------------------------------------------------")
    script = Path(script)
    if not script.is_file() or script.stat().st_size == 0:
        return False, f"Export produced no script: {script}"

    failures = []
    for question, option in knobs.items():
        cmd = [sys.executable, str(GET_BIOS_VALUE), question, "-f", str(script)]
        info(f'$ {Path(sys.executable).name} {GET_BIOS_VALUE} "{question}" -f {script}')
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        value = result.stdout.strip() if result.returncode == 0 else None
        info(f"  -> {value if value is not None else result.stderr.strip()}")
        if value is None or value.lower() != option.lower():
            failures.append(f"'{question}': expected '{option}', got '{value}'")
        else:
            ok(f"'{question}' = {value}")
    if failures:
        return False, "; ".join(failures)
    return True, ", ".join(f"{q} = {o}" for q, o in knobs.items())
