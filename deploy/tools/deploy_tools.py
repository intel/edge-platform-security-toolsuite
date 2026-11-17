# Copyright 2026 Intel Corporation
# SPDX-License-Identifier: Apache-2.0

"""
deploy_tools.py - Cross-platform tool deployer.

Reads tools.xml for a list of tool filenames and their target destinations,
then copies each file from the configured source folder (e.g. Downloads) to
the specified destination folder.

Works on both Windows and Linux.
"""

import os
import re
import stat
import sys
import shutil
import subprocess
import tempfile
import zipfile
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

try:
    import py7zr
    HAS_PY7ZR = True
except ImportError:
    HAS_PY7ZR = False

# When True (set via --yes/-y), never prompt for input -- ambiguous matches and
# missing tools are automatically skipped instead of asking the user to choose
# or retry. Useful for unattended/CI runs.
NON_INTERACTIVE = False

# Anchor for relative paths in tools.xml (source_folder, destination, efi_mount) so they
# always resolve next to this script's parent (the repo root), regardless of cwd.
REPO_ROOT = Path(__file__).resolve().parents[2]


class _Tee:
    """Write to multiple streams at once (e.g. console + log file) so print() output
    doesn't need to change anywhere else in this script."""

    def __init__(self, *streams):
        self._streams = streams

    def write(self, data: str) -> None:
        for stream in self._streams:
            stream.write(data)

    def flush(self) -> None:
        for stream in self._streams:
            stream.flush()


def _find_7z_command() -> Optional[str]:
    """Find the 7z command-line tool. Returns the command name or None."""
    candidates = ['7z', '7za', '7zr']
    for cmd in candidates:
        try:
            result = subprocess.run(
                [cmd], capture_output=True, timeout=5
            )
            return cmd
        except (FileNotFoundError, subprocess.TimeoutExpired):
            continue
    return None


# Cache the 7z command name at module load
_7Z_CMD = _find_7z_command()
_WARNED_NO_7Z = False


def _skip_7z_archive(archive: Path) -> bool:
    """True (after warning once) when a .7z cannot be read because neither py7zr nor a
    7z command is available -- otherwise such archives would be silently ignored and
    their tools reported as 'file not found'."""
    global _WARNED_NO_7Z
    if HAS_PY7ZR or _7Z_CMD:
        return False
    if not _WARNED_NO_7Z:
        _WARNED_NO_7Z = True
        print(f"       [WARN] Cannot read {archive.name} (and other .7z files): neither the 'py7zr' Python "
              "module nor a 7z command is available.")
        print("              Fix: pip install py7zr   (in the venv running this script), "
              "or sudo apt-get install -y p7zip-full")
    return True


def _set_executable_if_needed(filepath: Path) -> None:
    """On Linux, set the executable bit if the file appears to be an executable
    (ELF binary or shell script) or has no extension (common for Linux CLI tools)."""
    if sys.platform.startswith('win'):
        return
    try:
        # Check if file has no extension (like MEInfo, FPT) or read magic bytes
        suffix = filepath.suffix.lower()
        if not suffix or suffix in ('.sh', '.py', '.pl', '.rb'):
            filepath.chmod(filepath.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
            return
        # Check ELF magic bytes
        with open(str(filepath), 'rb') as f:
            magic = f.read(4)
        if magic == b'\x7fELF':
            filepath.chmod(filepath.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    except OSError:
        pass


def _make_writable(filepath: Path) -> None:
    """Clear the read-only flag (some vendor archives, e.g. AMISCE .7z, store files read-only)."""
    try:
        if filepath.is_file():
            filepath.chmod(filepath.stat().st_mode | stat.S_IWRITE)
    except OSError:
        pass


def expand_path(path_str: str) -> Path:
    """Expand ~ and environment variables, return absolute Path.
    Relative paths are resolved against REPO_ROOT, not the current working directory."""
    expanded = Path(os.path.expandvars(os.path.expanduser(path_str)))
    if not expanded.is_absolute():
        expanded = REPO_ROOT / expanded
    return expanded.resolve()


def load_download_links(xml_path: str) -> Dict[str, List[Dict]]:
    """Parse download_links.xml (sibling of tools.xml) into a
    {component_name: [{"url": ..., "description": ...}, ...]} lookup dict.
    Kept in its own file so a link update never requires touching tools.xml.
    Returns {} if the file doesn't exist."""
    links_path = Path(xml_path).parent / "download_links.xml"
    download_components = {}  # type: Dict[str, List[Dict]]
    if not links_path.is_file():
        return download_components

    tree = ET.parse(str(links_path))
    root = tree.getroot()
    for comp_elem in root.findall("component"):
        comp_name = comp_elem.get("name", "").strip()
        if not comp_name:
            continue
        links = []
        for link_elem in comp_elem.findall("link"):
            url = link_elem.text.strip() if link_elem.text else ""
            desc = link_elem.get("description", "")
            if url:
                links.append({
                    "url": url,
                    "description": desc,
                    # auto_download="true": fetched into the source folder when the tool
                    # is missing (public direct links only; see _auto_download).
                    "auto_download": link_elem.get("auto_download", "").strip().lower() == "true",
                    "sha256": link_elem.get("sha256", "").strip().lower(),
                })
        download_components[comp_name] = links
    return download_components


def load_config(xml_path: str) -> Tuple[Path, List[Dict]]:
    """Parse tools.xml and return (source_folder, list of tool dicts)."""
    tree = ET.parse(xml_path)
    root = tree.getroot()

    # Read source folder from config section
    config = root.find("config")
    if config is None or config.find("source_folder") is None:
        print("Error: <config><source_folder> is required in tools.xml")
        sys.exit(1)

    source_folder = expand_path(config.find("source_folder").text.strip())

    # Download links live in a sibling file (download_links.xml), not here.
    download_components = load_download_links(xml_path)

    # Read tool entries
    tools = []
    for tool_elem in root.findall("tool"):
        filename_elem = tool_elem.find("filename")
        dest_elem = tool_elem.find("destination")
        if filename_elem is None or dest_elem is None:
            print("Warning: Skipping incomplete <tool> entry (missing filename or destination)")
            continue

        # Resolve download links from component reference
        downloads = []
        comp_elem = tool_elem.find("component")
        if comp_elem is not None:
            comp_name = comp_elem.text.strip()
            if comp_name in download_components:
                downloads = download_components[comp_name]
            else:
                print(f"Warning: Unknown download component '{comp_name}' for {filename_elem.text.strip()}")

        tools.append({
            "filename": filename_elem.text.strip(),
            "destination": expand_path(dest_elem.text.strip()),
            "type": (tool_elem.find("type").text.strip().lower()
                     if tool_elem.find("type") is not None else "file"),
            "os": (tool_elem.find("os").text.strip().lower()
                   if tool_elem.find("os") is not None else "both"),
            "match": (tool_elem.find("match").text.strip().lower()
                      if tool_elem.find("match") is not None else "version"),
            "downloads": downloads,
            # <optional_reason> marks a tool that not every SUT needs (e.g. AMISCE needs an
            # AMI BIOS): skipping it is reported as SKIPPED, never as missing or FAIL.
            "optional_reason": (tool_elem.find("optional_reason").text.strip()
                                if tool_elem.find("optional_reason") is not None
                                and tool_elem.find("optional_reason").text else None),
            "efi_destination": (tool_elem.find("efi_destination").text.strip()
                                 if tool_elem.find("efi_destination") is not None else None),
        })

    return source_folder, tools


def load_efi_mount(xml_path: str) -> Path:
    """Parse tools.xml and return the <config><efi_mount> path (default: /boot/efi)."""
    tree = ET.parse(xml_path)
    root = tree.getroot()
    config = root.find("config")
    efi_mount_elem = config.find("efi_mount") if config is not None else None
    efi_mount_str = efi_mount_elem.text.strip() if efi_mount_elem is not None and efi_mount_elem.text else "/boot/efi"
    return expand_path(efi_mount_str)


def get_current_os() -> str:
    """Return 'windows' or 'linux' based on the current platform."""
    if sys.platform.startswith('win'):
        return 'windows'
    return 'linux'


# Marks an Intel ACM build as Production Worthy, e.g.
# PTL_SINIT_REL_NT_O1.PW_v1_21_18_20260113_ACM2SRC_signed.bin
_PW_PATTERN = re.compile(r'(?:^|[_.\-])PW(?:[_.\-]|$)', re.IGNORECASE)
_DATE_PATTERN = re.compile(r'\d{8}')


def _select_production_worthy(candidates: List[str]) -> Optional[int]:
    """When multiple candidate filenames match, prefer the one uniquely marked as
    Production Worthy (PW). Returns the index of the chosen PW match, or None if
    zero candidates are marked, or the match stays ambiguous (fall back to prompting).

    A package can stage the identical PW build under more than one path (e.g. both
    a .../SINIT/ folder and a .../Driver/signed/... folder) -- those share the same
    basename and collapse to one representative (preferring the "SINIT" folder copy).

    A Downloads folder can also hold more than one ACM package version at once (e.g.
    both a 1.21.17 and a 1.21.18 zip), each contributing its own PW build with a
    different basename -- in that case prefer the one with the most recent embedded
    build date (the 8-digit YYYYMMDD in the filename), if it's uniquely the newest."""
    pw_indices = [i for i, name in enumerate(candidates) if _PW_PATTERN.search(Path(name).name)]
    if not pw_indices:
        return None

    by_basename: Dict[str, int] = {}
    for i in pw_indices:
        basename = Path(candidates[i]).name.lower()
        is_sinit_folder = "sinit" in (p.lower() for p in Path(candidates[i]).parts)
        if basename not in by_basename or is_sinit_folder:
            by_basename[basename] = i
    representatives = list(by_basename.values())

    if len(representatives) == 1:
        return representatives[0]

    dated = []
    for i in representatives:
        unique_dates = set(_DATE_PATTERN.findall(Path(candidates[i]).name))
        if len(unique_dates) == 1:
            dated.append((unique_dates.pop(), i))
    if len(dated) == len(representatives):
        dated.sort(reverse=True)
        if len(dated) == 1 or dated[0][0] != dated[1][0]:
            return dated[0][1]

    return None


def prompt_user_choice(tool_name: str, options: list, label: str = "file") -> Optional[int]:
    """Prompt user to choose from multiple matching items.
    Returns the index of the chosen option, or None to skip.
    In non-interactive mode (NON_INTERACTIVE=True), always skips without prompting."""
    print(f"       Multiple matching {label}s found for '{tool_name}':")
    for i, option in enumerate(options, 1):
        print(f"         [{i}] {option}")

    if NON_INTERACTIVE:
        print(f"       Non-interactive mode -- skipping '{tool_name}' (ambiguous match).")
        return None

    print(f"         [0] Skip this tool")

    while True:
        try:
            choice = input(f"       Select (1-{len(options)}, or 0 to skip): ").strip()
            if not choice:
                continue
            choice_num = int(choice)
            if choice_num == 0:
                return None
            if 1 <= choice_num <= len(options):
                return choice_num - 1
            print(f"       Invalid choice. Enter 0-{len(options)}.")
        except ValueError:
            print(f"       Invalid input. Enter a number 0-{len(options)}.")
        except (EOFError, KeyboardInterrupt):
            print()
            return None


def prompt_not_found(tool_name: str, downloads: List[Dict], tool_type: str = "file",
                     optional_reason: Optional[str] = None) -> bool:
    """Prompt user when a tool is not found, showing download links if available.
    Returns True if user wants to retry after downloading, False to skip.
    In non-interactive mode (NON_INTERACTIVE=True), always skips without prompting.
    optional_reason (tools.xml <optional_reason>) marks a tool not every SUT needs."""
    label = "folder" if tool_type == "folder" else "file"
    if optional_reason:
        print(f"[MISS] {tool_name} - optional tool, {label} not found ({optional_reason}).")
        if downloads:
            print("       If you need it, get it as follows; otherwise skip it:")
    elif downloads:
        print(f"[MISS] {tool_name} - {label} not found. Download links:")
    if downloads:
        for i, dl in enumerate(downloads, 1):
            desc = dl["description"]
            url = dl["url"]
            if desc:
                print(f"         [{i}] {desc}")
                print(f"             {url}")
            else:
                print(f"         [{i}] {url}")
        print()
    elif not optional_reason:
        print(f"[MISS] {tool_name} - {label} not found. No download links configured.")

    if NON_INTERACTIVE:
        print("       Non-interactive mode -- skipping.")
        return False

    if downloads:
        while True:
            try:
                prompt = ("       Press [R] to retry after downloading, or [S] to skip (not needed on this SUT): "
                          if optional_reason else
                          "       Download the tool and press [R] to retry, or [S] to skip: ")
                choice = input(prompt).strip().upper()
                if choice == 'R':
                    return True
                if choice == 'S':
                    return False
                print("       Invalid input. Enter R to retry or S to skip.")
            except (EOFError, KeyboardInterrupt):
                print()
                return False
    else:
        while True:
            try:
                choice = input("       Press [R] to retry, or [S] to skip: ").strip().upper()
                if choice == 'R':
                    return True
                if choice == 'S':
                    return False
                print("       Invalid input. Enter R to retry or S to skip.")
            except (EOFError, KeyboardInterrupt):
                print()
                return False


def _auto_download(downloads: List[Dict], source_folder: Path) -> bool:
    """Download every auto_download="true" link of a tool into source_folder.

    Only https links with a pinned sha256 are fetched. The file is written as <name>.part and
    renamed once complete and the hash matches. Proxies come from HTTPS_PROXY / the Windows proxy
    settings, as for pip. Returns True if at least one file was downloaded."""
    import hashlib
    import urllib.request
    from urllib.parse import urlparse

    downloaded = False
    for dl in downloads:
        if not dl.get("auto_download"):
            continue
        url = dl["url"]
        if urlparse(url).scheme != "https":
            print(f"       Auto-download refused (not https): {url}")
            continue
        if not dl.get("sha256"):
            print(f"       Auto-download refused (no sha256 pinned in download_links.xml): {url}")
            print("       Download it by hand into the source folder and check it before use.")
            continue
        name = Path(urlparse(url).path).name
        if not name:
            print(f"       Auto-download skipped (no file name in URL): {url}")
            continue
        dest = source_folder / name
        part = source_folder / (name + ".part")
        print(f"       Downloading {url} ...")
        try:
            source_folder.mkdir(parents=True, exist_ok=True)
            digest = hashlib.sha256()
            with urllib.request.urlopen(url, timeout=60) as resp, open(part, "wb") as fh:
                while True:
                    chunk = resp.read(1024 * 1024)
                    if not chunk:
                        break
                    fh.write(chunk)
                    digest.update(chunk)
            actual = digest.hexdigest()
            if actual != dl["sha256"]:
                part.unlink()
                print(f"[FAIL] {name} - SHA-256 mismatch (expected {dl['sha256']}, got {actual}); deleted")
                print("       The file at this URL changed. Download it by hand, check it, then update")
                print("       the sha256 in deploy/tools/download_links.xml.")
                continue
            os.replace(str(part), str(dest))
            print(f"[OK]   Downloaded {name} -> {source_folder} (SHA-256 {actual})")
            downloaded = True
        except (OSError, ValueError) as e:
            if part.exists():
                part.unlink()
            print(f"[FAIL] Auto-download of {url} failed: {e}")
            print("       Check the network/proxy (HTTPS_PROXY), or download it by hand into "
                  f"{source_folder}")
    return downloaded


def _version_pattern(filename: str) -> re.Pattern:
    """Build a regex pattern that matches filename with optional version/extra string.
    Matches: stem + optional (separator + anything) + same extension.
    Examples: VtInfo.efi matches VtInfo_v1.1.83.efi
              PTL_SINIT.bin matches PTL_SINIT_v1_21_17_20251016_REL_NT_O1.PW_v1_21_17_20251016_ACM2SRC.bin
              MEInfo (no extension) matches MEInfo only with version suffix appended
    """
    stem = Path(filename).stem
    suffix = Path(filename).suffix
    if suffix:
        return re.compile(
            r'^' + re.escape(stem) + r'(?:[\s_\-].+?)?' + re.escape(suffix) + r'$',
            re.IGNORECASE
        )
    else:
        # No extension: match stem + optional version, but must not have a dot extension
        # to avoid matching unrelated files like MEInfo.txt
        return re.compile(
            r'^' + re.escape(stem) + r'(?:[\s_\-][^.]+)?$',
            re.IGNORECASE
        )


def _folder_version_pattern(foldername: str) -> re.Pattern:
    """Build a regex pattern that matches a folder name with optional version/date string.
    Matches: name, name_v1.2.3, name-20251217, name_v2.0, etc."""
    return re.compile(
        r'^' + re.escape(foldername) + r'(?:[\s_\-]+v?[\d]+(?:\.[\d]+)*)?(?:[\s_\-]+\d{6,8})?$',
        re.IGNORECASE
    )


def _prefix_pattern(filename: str) -> re.Pattern:
    """Build a regex pattern that matches filename with ANY extra text appended after the
    stem -- no separator required, unlike 'version' mode. For tools whose packaged name can
    vary without a version-style separator (e.g. MEInfo.exe vs MEInfoWin64.exe).
    Examples: MEInfo.exe matches MEInfo.exe, MEInfoWin64.exe, MEInfo64.exe, etc.
    """
    stem = Path(filename).stem
    suffix = Path(filename).suffix
    if suffix:
        return re.compile(r'^' + re.escape(stem) + r'.*' + re.escape(suffix) + r'$', re.IGNORECASE)
    return re.compile(r'^' + re.escape(stem) + r'[^.]*$', re.IGNORECASE)


def _any_ext_pattern(filename: str) -> re.Pattern:
    """Build a regex pattern that matches ANY filename sharing the same extension,
    ignoring the stem entirely. For tools whose vendor-provided filename is unpredictable
    and shares no common stem with the standardized name (e.g. a BIOS capsule .cap file
    named arbitrarily by Intel, staged locally as a fixed name like BIOS_release.cap).
    """
    suffix = Path(filename).suffix
    if suffix:
        return re.compile(r'^.+' + re.escape(suffix) + r'$', re.IGNORECASE)
    return re.compile(r'^.+$', re.IGNORECASE)


def _file_pattern(filename: str, match_mode: str) -> re.Pattern:
    """Return the compiled regex for a non-exact file match_mode
    ('version', 'prefix', or 'any_ext')."""
    if match_mode == "prefix":
        return _prefix_pattern(filename)
    if match_mode == "any_ext":
        return _any_ext_pattern(filename)
    return _version_pattern(filename)


def find_matching_file(source_folder: Path, filename: str, match_mode: str = "version") -> Optional[Path]:
    """Find a file in source_folder matching the given filename.

    match_mode:
      "exact"   - only exact filename match
      "version" - also match filename with a version string appended after a separator
      "prefix"  - also match filename with ANY text appended after the stem (no separator
                  required) -- looser than "version", for inconsistently-named tools
      "any_ext" - match ANY filename sharing the same extension, ignoring the stem --
                  for tools with an unpredictable vendor-provided name
    """
    # Try exact match first
    exact = source_folder / filename
    if exact.is_file():
        return exact

    if match_mode == "exact":
        return None

    pattern = _file_pattern(filename, match_mode)
    matches = [f for f in source_folder.iterdir() if f.is_file() and pattern.match(f.name)]

    if not matches:
        return None

    if len(matches) == 1:
        return matches[0]

    # Multiple matches - prefer a uniquely-marked Production Worthy (PW) build,
    # otherwise prompt user to choose
    matches.sort(key=lambda f: f.name)
    options = [f.name for f in matches]
    pw_choice = _select_production_worthy(options)
    if pw_choice is not None:
        print(f"       Multiple matches for '{filename}' -- auto-selected Production Worthy (PW) build: {options[pw_choice]}")
        return matches[pw_choice]
    choice = prompt_user_choice(filename, options)
    if choice is None:
        return None  # User chose to skip
    return matches[choice]


def find_matching_folder(source_folder: Path, foldername: str, match_mode: str = "version") -> Optional[Path]:
    """Find a folder in source_folder matching the given folder name.

    match_mode:
      "exact"   - only exact folder name match
      "version" - also match folder name with version/date numbers appended
    """
    # Try exact match first
    exact = source_folder / foldername
    if exact.is_dir():
        return exact

    if match_mode == "exact":
        return None

    pattern = _folder_version_pattern(foldername)
    matches = [f for f in source_folder.iterdir() if f.is_dir() and pattern.match(f.name)]

    if not matches:
        return None

    if len(matches) == 1:
        return matches[0]

    # Multiple matches - prompt user to choose
    matches.sort(key=lambda f: f.name)
    options = [f.name + '/' for f in matches]
    choice = prompt_user_choice(foldername, options, label="folder")
    if choice is None:
        return None
    return matches[choice]


def _find_folder_in_zip(archive_path: Path, foldername: str, match_mode: str = "version") -> List[str]:
    """Search inside a .zip for folders matching foldername.
    Returns list of archive folder path prefixes."""
    pattern = _folder_version_pattern(foldername)
    results = []
    try:
        with zipfile.ZipFile(str(archive_path), 'r') as zf:
            # Collect unique directory names at all levels
            found_dirs = set()
            for member in zf.namelist():
                parts = Path(member).parts
                for part in parts:
                    found_dirs.add(part)

            for dirname in found_dirs:
                matches_name = False
                if match_mode == "exact":
                    matches_name = dirname.lower() == foldername.lower()
                else:
                    matches_name = bool(pattern.match(dirname))

                if matches_name:
                    for member in zf.namelist():
                        if '/' + dirname + '/' in '/' + member or member.startswith(dirname + '/'):
                            idx = member.find(dirname + '/')
                            if idx >= 0:
                                prefix = member[:idx + len(dirname)]
                                if prefix not in results:
                                    results.append(prefix)
                                break
    except (zipfile.BadZipFile, OSError):
        pass
    return results


def _extract_folder_from_zip(archive_path: Path, folder_prefix: str, dest_folder: Path) -> bool:
    """Extract all files under folder_prefix from a .zip archive to dest_folder."""
    try:
        with zipfile.ZipFile(str(archive_path), 'r') as zf:
            # Find all members under this folder prefix
            prefix_with_slash = folder_prefix + '/'
            members = [m for m in zf.namelist()
                       if m.startswith(prefix_with_slash) and not m.endswith('/')]

            if not members:
                return False

            for member in members:
                # Get relative path from the folder prefix
                rel_path = member[len(prefix_with_slash):]
                target = dest_folder / rel_path
                target.parent.mkdir(parents=True, exist_ok=True)
                with zf.open(member) as src, open(str(target), 'wb') as dst:
                    shutil.copyfileobj(src, dst)
                _set_executable_if_needed(target)
        return True
    except (zipfile.BadZipFile, OSError, KeyError) as e:
        print(f"       Error extracting folder from zip: {e}")
        return False


def _find_folder_in_7z(archive_path: Path, foldername: str, match_mode: str = "version") -> List[str]:
    """Search inside a .7z for folders matching foldername.
    Returns list of archive folder path prefixes."""
    pattern = _folder_version_pattern(foldername)
    results = []

    def _get_members():
        if HAS_PY7ZR:
            try:
                with py7zr.SevenZipFile(str(archive_path), 'r') as sz:
                    return sz.getnames()
            except Exception:
                return []
        try:
            result = subprocess.run(
                [_7Z_CMD, 'l', '-slt', str(archive_path)],
                capture_output=True, text=True, timeout=30
            )
            if result.returncode != 0:
                return []
            members = []
            for line in result.stdout.splitlines():
                if line.startswith('Path = '):
                    members.append(line[7:])
            return members
        except (FileNotFoundError, subprocess.TimeoutExpired, TypeError):
            return []

    members = _get_members() if (HAS_PY7ZR or _7Z_CMD) else []
    found_dirs = set()
    for member in members:
        parts = Path(member).parts
        for part in parts:
            found_dirs.add(part)

    for dirname in found_dirs:
        matches_name = False
        if match_mode == "exact":
            matches_name = dirname.lower() == foldername.lower()
        else:
            matches_name = bool(pattern.match(dirname))

        if matches_name:
            for member in members:
                norm = member.replace('\\', '/')
                if '/' + dirname + '/' in '/' + norm or norm.startswith(dirname + '/'):
                    idx = norm.find(dirname + '/')
                    if idx >= 0:
                        prefix = norm[:idx + len(dirname)]
                        if prefix not in results:
                            results.append(prefix)
                        break
    return results


def _extract_folder_from_7z(archive_path: Path, folder_prefix: str, dest_folder: Path) -> bool:
    """Extract all files under folder_prefix from a .7z archive to dest_folder."""
    prefix_with_slash = folder_prefix + '/'

    if HAS_PY7ZR:
        try:
            with tempfile.TemporaryDirectory() as tmpdir:
                with py7zr.SevenZipFile(str(archive_path), 'r') as sz:
                    all_names = sz.getnames()
                    targets = [m for m in all_names if m.startswith(prefix_with_slash)]
                    if not targets:
                        return False
                    sz.extract(path=tmpdir, targets=targets)
                # Copy extracted folder to destination
                extracted_folder = Path(tmpdir) / folder_prefix
                if extracted_folder.is_dir():
                    if dest_folder.exists():
                        shutil.rmtree(str(dest_folder))
                    shutil.copytree(str(extracted_folder), str(dest_folder))
                    return True
        except Exception as e:
            print(f"       Error extracting folder from 7z (py7zr): {e}")
        return False

    # Fallback: 7z command-line
    if not _7Z_CMD:
        print("       7z command not found. Install p7zip-full (Linux) or 7-Zip (Windows).")
        return False
    try:
        with tempfile.TemporaryDirectory() as tmpdir:
            result = subprocess.run(
                [_7Z_CMD, 'x', str(archive_path), f'-o{tmpdir}', f'{folder_prefix}/*', '-y'],
                capture_output=True, text=True, timeout=120
            )
            if result.returncode != 0:
                print(f"       7z extraction failed: {result.stderr.strip()}")
                return False
            extracted_folder = Path(tmpdir) / folder_prefix
            if extracted_folder.is_dir():
                if dest_folder.exists():
                    shutil.rmtree(str(dest_folder))
                shutil.copytree(str(extracted_folder), str(dest_folder))
                return True
    except (FileNotFoundError, subprocess.TimeoutExpired) as e:
        print(f"       7z command error: {e}")
    return False


def find_folder_in_archives(source_folder: Path, foldername: str, match_mode: str = "version") -> Optional[Tuple[Path, str]]:
    """Search all .zip and .7z archives in source_folder for a matching folder.
    Returns (archive_path, folder_prefix) if found, else None.
    Prompts user if multiple matches found."""
    all_matches = []  # list of (archive_path, folder_prefix)
    for archive in source_folder.iterdir():
        if not archive.is_file():
            continue
        suffix_lower = archive.suffix.lower()
        if suffix_lower == '.zip':
            prefixes = _find_folder_in_zip(archive, foldername, match_mode)
            for p in prefixes:
                all_matches.append((archive, p))
        elif suffix_lower == '.7z':
            if _skip_7z_archive(archive):
                continue
            prefixes = _find_folder_in_7z(archive, foldername, match_mode)
            for p in prefixes:
                all_matches.append((archive, p))

    if not all_matches:
        return None

    if len(all_matches) == 1:
        return all_matches[0]

    # Multiple matches - prompt user to choose
    options = [f"{arch.name} -> {prefix}/" for arch, prefix in all_matches]
    choice = prompt_user_choice(foldername, options, label="folder")
    if choice is None:
        return None
    return all_matches[choice]


def _find_in_zip(archive_path: Path, filename: str, match_mode: str = "version") -> List[str]:
    """Search inside a .zip for files matching filename.
    Returns list of matching archive member names."""
    pattern = _file_pattern(filename, match_mode)
    results = []
    try:
        with zipfile.ZipFile(str(archive_path), 'r') as zf:
            for member in zf.namelist():
                # Skip directory entries
                if member.endswith('/'):
                    continue
                member_basename = Path(member).name
                if not member_basename:
                    continue
                if match_mode == "exact":
                    if member_basename.lower() == filename.lower():
                        results.append(member)
                else:
                    if pattern.match(member_basename):
                        results.append(member)
    except (zipfile.BadZipFile, OSError):
        pass
    return results


def _extract_from_zip(archive_path: Path, member_name: str, dest_file: Path) -> bool:
    """Extract a single member from a .zip archive to dest_file."""
    try:
        with zipfile.ZipFile(str(archive_path), 'r') as zf:
            with zf.open(member_name) as src, open(str(dest_file), 'wb') as dst:
                shutil.copyfileobj(src, dst)
        _set_executable_if_needed(dest_file)
        return True
    except (zipfile.BadZipFile, OSError, KeyError) as e:
        print(f"       Error extracting from zip: {e}")
        return False


def _find_in_7z(archive_path: Path, filename: str, match_mode: str = "version") -> List[str]:
    """Search inside a .7z for files matching filename.
    Returns list of matching archive member names."""
    pattern = _file_pattern(filename, match_mode)
    results = []

    def _matches(member_basename: str) -> bool:
        if match_mode == "exact":
            return member_basename.lower() == filename.lower()
        return bool(pattern.match(member_basename))

    if HAS_PY7ZR:
        try:
            with py7zr.SevenZipFile(str(archive_path), 'r') as sz:
                for member in sz.getnames():
                    if member.endswith('/'):
                        continue
                    member_basename = Path(member).name
                    if member_basename and _matches(member_basename):
                        results.append(member)
        except Exception:
            pass
        return results

    # Fallback: use 7z command-line tool to list contents
    if not _7Z_CMD:
        return results
    try:
        result = subprocess.run(
            [_7Z_CMD, 'l', '-slt', str(archive_path)],
            capture_output=True, text=True, timeout=30
        )
        if result.returncode != 0:
            return results
        for line in result.stdout.splitlines():
            if line.startswith('Path = '):
                member = line[7:]
                member_basename = Path(member).name
                if member_basename and _matches(member_basename):
                    results.append(member)
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    return results


def _extract_from_7z(archive_path: Path, member_name: str, dest_file: Path) -> bool:
    """Extract a single member from a .7z archive to dest_file."""
    if HAS_PY7ZR:
        try:
            with tempfile.TemporaryDirectory() as tmpdir:
                with py7zr.SevenZipFile(str(archive_path), 'r') as sz:
                    sz.extract(path=tmpdir, targets=[member_name])
                extracted = Path(tmpdir) / member_name
                if extracted.is_file():
                    shutil.copy2(str(extracted), str(dest_file))
                    _set_executable_if_needed(dest_file)
                    return True
        except Exception as e:
            print(f"       Error extracting from 7z (py7zr): {e}")
        return False

    # Fallback: use 7z command-line tool
    if not _7Z_CMD:
        print("       7z command not found. Install p7zip-full (Linux) or 7-Zip (Windows).")
        return False
    try:
        with tempfile.TemporaryDirectory() as tmpdir:
            result = subprocess.run(
                [_7Z_CMD, 'e', str(archive_path), f'-o{tmpdir}', member_name, '-y'],
                capture_output=True, text=True, timeout=60
            )
            if result.returncode != 0:
                print(f"       7z extraction failed: {result.stderr.strip()}")
                return False
            extracted = Path(tmpdir) / Path(member_name).name
            if extracted.is_file():
                shutil.copy2(str(extracted), str(dest_file))
                _set_executable_if_needed(dest_file)
                return True
    except (FileNotFoundError, subprocess.TimeoutExpired) as e:
        print(f"       7z command error: {e}")
    return False


def find_in_archives(source_folder: Path, filename: str, match_mode: str = "version") -> Optional[Tuple[Path, str]]:
    """Search all .zip and .7z archives in source_folder for a matching file.
    Returns (archive_path, member_name) if found, else None.
    Prompts user if multiple matches found."""
    all_matches = []  # list of (archive_path, member_name)
    for archive in source_folder.iterdir():
        if not archive.is_file():
            continue
        suffix_lower = archive.suffix.lower()
        if suffix_lower == '.zip':
            members = _find_in_zip(archive, filename, match_mode)
            for m in members:
                all_matches.append((archive, m))
        elif suffix_lower == '.7z':
            if _skip_7z_archive(archive):
                continue
            members = _find_in_7z(archive, filename, match_mode)
            for m in members:
                all_matches.append((archive, m))

    if not all_matches:
        return None

    if len(all_matches) == 1:
        return all_matches[0]

    # Multiple matches - prefer a uniquely-marked Production Worthy (PW) build,
    # otherwise prompt user to choose
    options = [f"{arch.name} -> {member}" for arch, member in all_matches]
    pw_choice = _select_production_worthy([member for _, member in all_matches])
    if pw_choice is not None:
        print(f"       Multiple matches for '{filename}' -- auto-selected Production Worthy (PW) build: {options[pw_choice]}")
        return all_matches[pw_choice]
    choice = prompt_user_choice(filename, options)
    if choice is None:
        return None
    return all_matches[choice]


def _print_download_table(tools_list: List[Dict]) -> None:
    """Print a (tool, download link) table to guide a manual download into the source
    folder. Tools with multiple links get one row per link; tools with none configured
    are flagged as such."""
    rows = []  # (tool label or "" for a continuation row, link text)
    for tool in tools_list:
        label = f"{tool['filename']}/" if tool["type"] == "folder" else tool["filename"]
        downloads = tool.get("downloads", [])
        if not downloads:
            rows.append((label, "(no download link configured)"))
            continue
        for i, dl in enumerate(downloads):
            link_text = f"{dl['description']} -- {dl['url']}" if dl["description"] else dl["url"]
            rows.append((label if i == 0 else "", link_text))

    if not rows:
        return

    name_width = max(len("Tool"), max(len(name) for name, _ in rows))
    header = f"{'Tool':<{name_width}}  Download Link"
    print(header)
    print("-" * len(header))
    for name, link in rows:
        print(f"{name:<{name_width}}  {link}")
    print("-" * len(header))


def _print_summary_table(results: List[Tuple[str, str, str]]) -> None:
    """Print an aligned summary table of every tool's deployment outcome (status one of
    DEPLOYED/SKIPPED/FAILED, in the order tools were processed)."""
    if not results:
        return

    name_width = max(len("Tool"), max(len(name) for name, _, _ in results))
    status_width = max(len("Status"), max(len(status) for _, status, _ in results))

    print()
    print("=" * 50)
    print("Summary")
    print("=" * 50)
    header = f"{'Tool':<{name_width}}  {'Status':<{status_width}}  Details"
    print(header)
    print("-" * len(header))
    for name, status, detail in results:
        print(f"{name:<{name_width}}  {status:<{status_width}}  {detail}")
    print("-" * len(header))

    deployed = sum(1 for _, status, _ in results if status == "DEPLOYED")
    skipped = sum(1 for _, status, _ in results if status == "SKIPPED")
    failed = sum(1 for _, status, _ in results if status == "FAILED")
    print(f"Deployed: {deployed}   Skipped: {skipped}   Failed: {failed}")


def deploy_tools(xml_path: str) -> bool:
    """Main deployment logic. Returns True only if every applicable tool was
    deployed (or already staged) -- False if anything was skipped/missing/failed,
    so callers (e.g. setup_sut.sh) don't mistake a partial run for success."""
    source_folder, tools = load_config(xml_path)
    current_os = get_current_os()

    print(f"Source folder: {source_folder}")
    print(f"Current OS: {current_os}")
    print(f"Tools in config: {len(tools)}")

    # Filter tools by OS
    applicable_tools = [t for t in tools if t["os"] in (current_os, "both")]
    skipped_os = len(tools) - len(applicable_tools)
    if skipped_os > 0:
        print(f"Skipped (wrong OS): {skipped_os}")
    print(f"Tools to deploy: {len(applicable_tools)}")
    print("-" * 50)

    if not source_folder.is_dir():
        print(f"Source folder not found -- creating: {source_folder}")
        try:
            source_folder.mkdir(parents=True, exist_ok=True)
        except OSError as e:
            print(f"Error: Could not create source folder {source_folder}: {e}")
            sys.exit(1)

        print()
        print("=" * 50)
        print("The source folder was just created and is empty.")
        print("Please download the tools below and transfer the files/archives (.zip/.7z) into:")
        print(f"  {source_folder}")
        print("=" * 50)
        _print_download_table(applicable_tools)

        has_auto = any(dl.get("auto_download") for t in applicable_tools for dl in t.get("downloads", []))
        if NON_INTERACTIVE and not has_auto:
            print()
            print("Non-interactive mode -- re-run this script after placing the files.")
            return False

        if NON_INTERACTIVE:
            print()
            print("Non-interactive mode -- continuing so the auto-download tools are fetched and staged.")
        else:
            print()
            while True:
                try:
                    choice = input("Press [C] once the files are in place to continue, or [Q] to quit: ").strip().upper()
                except (EOFError, KeyboardInterrupt):
                    print()
                    return False
                if choice == 'C':
                    break
                if choice == 'Q':
                    return False
                print("Invalid input. Enter C to continue or Q to quit.")
        print("-" * 50)

    # Tracks (tool label, status, details) for the summary table printed at the end.

    results: List[Tuple[str, str, str]] = []
    for tool in tools:
        if tool["os"] not in (current_os, "both"):
            label = f"{tool['filename']}/" if tool["type"] == "folder" else tool["filename"]
            results.append((label, "SKIPPED", f"expected -- tool is only used on {tool['os']}"))

    success_count = 0
    optional_skipped = 0
    for tool in applicable_tools:
        filename = tool["filename"]
        destination = tool["destination"]
        match_mode = tool["match"]
        tool_type = tool["type"]
        label = f"{filename}/" if tool_type == "folder" else filename
        auto_tried = False

        if tool_type == "folder":
            # --- Folder deployment ---
            deployed = False
            while not deployed:
                source_dir = find_matching_folder(source_folder, filename, match_mode)

                if source_dir is not None:
                    dest_dir = destination / filename
                    try:
                        if dest_dir.exists():
                            shutil.rmtree(str(dest_dir))
                        shutil.copytree(str(source_dir), str(dest_dir))
                        if source_dir.name != filename:
                            print(f"[OK]   {source_dir.name}/ -> {dest_dir} (renamed)")
                            results.append((label, "DEPLOYED", f"{dest_dir} (renamed from {source_dir.name})"))
                        else:
                            print(f"[OK]   {filename}/ -> {destination}")
                            results.append((label, "DEPLOYED", str(dest_dir)))
                        success_count += 1
                        deployed = True
                    except PermissionError:
                        print(f"[FAIL] {filename}/ - permission denied writing to {destination}")
                        results.append((label, "FAILED", f"permission denied writing to {destination}"))
                    except OSError as e:
                        print(f"[FAIL] {filename}/ - {e}")
                        results.append((label, "FAILED", str(e)))
                    break

                # Search inside archives for the folder
                archive_result = find_folder_in_archives(source_folder, filename, match_mode)
                if archive_result is not None:
                    archive_path, folder_prefix = archive_result
                    dest_dir = destination / filename
                    destination.mkdir(parents=True, exist_ok=True)
                    print(f"       Found folder in archive: {archive_path.name} -> {folder_prefix}/")

                    success = False
                    if archive_path.suffix.lower() == '.zip':
                        success = _extract_folder_from_zip(archive_path, folder_prefix, dest_dir)
                    elif archive_path.suffix.lower() == '.7z':
                        success = _extract_folder_from_7z(archive_path, folder_prefix, dest_dir)

                    if success:
                        print(f"[OK]   {filename}/ <- {archive_path.name} (extracted)")
                        results.append((label, "DEPLOYED", f"{dest_dir} (extracted from {archive_path.name})"))
                        success_count += 1
                        deployed = True
                    else:
                        print(f"[FAIL] {filename}/ - extraction failed from {archive_path.name}")
                        results.append((label, "FAILED", f"extraction failed from {archive_path.name}"))
                    break

                # Not found in Downloads/archives - check if already staged in Tools from a prior run
                existing_dir = destination / filename
                if existing_dir.is_dir():
                    print(f"[OK]   {filename}/ already in {destination} (skipped -- not found in {source_folder})")
                    results.append((label, "DEPLOYED", f"{existing_dir} (already present, skipped re-copy)"))
                    success_count += 1
                    deployed = True
                    break

                # Not found - fetch auto_download links once, then search again
                if not auto_tried:
                    auto_tried = True
                    if _auto_download(tool.get("downloads", []), source_folder):
                        continue

                # Not found - prompt user with download links
                retry = prompt_not_found(filename, tool.get("downloads", []), tool_type="folder",
                                         optional_reason=tool.get("optional_reason"))
                if not retry:
                    if tool.get("optional_reason"):
                        print(f"[SKIP] {filename}/ - optional, not needed: {tool['optional_reason']}")
                        results.append((label, "SKIPPED", f"optional - {tool['optional_reason']}"))
                        optional_skipped += 1
                    else:
                        print(f"[SKIP] {filename}/ - skipped by user")
                        results.append((label, "SKIPPED", "not found - skipped by user"))
                    break

        else:
            # --- File deployment ---
            deployed = False
            while not deployed:
                source_file = find_matching_file(source_folder, filename, match_mode)

                if source_file is not None:
                    destination.mkdir(parents=True, exist_ok=True)
                    dest_file = destination / filename
                    try:
                        _make_writable(dest_file)
                        shutil.copy2(str(source_file), str(dest_file))
                        _make_writable(dest_file)
                        if source_file.name != filename:
                            print(f"[OK]   {source_file.name} -> {dest_file} (renamed)")
                            results.append((label, "DEPLOYED", f"{dest_file} (renamed from {source_file.name})"))
                        else:
                            print(f"[OK]   {filename} -> {destination}")
                            results.append((label, "DEPLOYED", str(dest_file)))
                        success_count += 1
                        deployed = True
                    except PermissionError:
                        print(f"[FAIL] {filename} - permission denied writing to {destination}")
                        results.append((label, "FAILED", f"permission denied writing to {destination}"))
                    except OSError as e:
                        print(f"[FAIL] {filename} - {e}")
                        results.append((label, "FAILED", str(e)))
                    break

                # Not found as loose file - search inside archives
                archive_result = find_in_archives(source_folder, filename, match_mode)
                if archive_result is not None:
                    archive_path, member_name = archive_result
                    destination.mkdir(parents=True, exist_ok=True)
                    dest_file = destination / filename
                    print(f"       Found in archive: {archive_path.name} -> {member_name}")

                    _make_writable(dest_file)
                    success = False
                    if archive_path.suffix.lower() == '.zip':
                        success = _extract_from_zip(archive_path, member_name, dest_file)
                    elif archive_path.suffix.lower() == '.7z':
                        success = _extract_from_7z(archive_path, member_name, dest_file)

                    if success:
                        _make_writable(dest_file)
                        print(f"[OK]   {filename} <- {archive_path.name} (extracted)")
                        results.append((label, "DEPLOYED", f"{dest_file} (extracted from {archive_path.name})"))
                        success_count += 1
                        deployed = True
                    else:
                        print(f"[FAIL] {filename} - extraction failed from {archive_path.name}")
                        results.append((label, "FAILED", f"extraction failed from {archive_path.name}"))
                    break

                # Not found in Downloads/archives - check if already staged in Tools from a prior run
                existing_file = destination / filename
                if existing_file.is_file():
                    print(f"[OK]   {filename} already in {destination} (skipped -- not found in {source_folder})")
                    results.append((label, "DEPLOYED", f"{existing_file} (already present, skipped re-copy)"))
                    success_count += 1
                    deployed = True
                    break

                # Not found - fetch auto_download links once, then search again
                if not auto_tried:
                    auto_tried = True
                    if _auto_download(tool.get("downloads", []), source_folder):
                        continue

                # Not found - prompt user with download links
                retry = prompt_not_found(filename, tool.get("downloads", []),
                                         optional_reason=tool.get("optional_reason"))
                if not retry:
                    if tool.get("optional_reason"):
                        print(f"[SKIP] {filename} - optional, not needed: {tool['optional_reason']}")
                        results.append((label, "SKIPPED", f"optional - {tool['optional_reason']}"))
                        optional_skipped += 1
                    else:
                        print(f"[SKIP] {filename} - skipped by user")
                        results.append((label, "SKIPPED", "not found - skipped by user"))
                    break

    print("-" * 50)
    optional_note = f" ({optional_skipped} optional skipped)" if optional_skipped else ""
    print(f"Done. {success_count}/{len(applicable_tools)} tools deployed successfully{optional_note}.")
    _print_summary_table(results)
    return success_count + optional_skipped == len(applicable_tools)


def deploy_to_efi(xml_path: str, efi_mount_override: Optional[str] = None) -> Optional[bool]:
    """Copy already-staged tools (from their <destination>, e.g. ./Tools/) onto the
    SUT EFI System Partition, for every tool that declares <efi_destination> in tools.xml.

    Always attempted after staging -- but skips gracefully (prints why, does not
    raise/exit) when not on Linux, not running as root, or the EFI partition isn't
    mounted, since staging into ./Tools/ does not itself require elevation.
    Tools without <efi_destination> (e.g. Windows-only or OS-level Linux binaries
    like plain 'MEInfo'/'FPT') are skipped -- they are not meant to run from the
    UEFI shell, so copying them to the EFI partition would not make sense.

    Returns True if every applicable tool was copied, False if any failed/weren't
    staged yet, or None if the whole phase was gracefully skipped (nothing to do,
    wrong OS, not root, or EFI partition not mounted) -- None is not a failure.
    """
    source_folder, tools = load_config(xml_path)
    efi_mount = Path(efi_mount_override) if efi_mount_override else load_efi_mount(xml_path)
    current_os = get_current_os()

    efi_tools = [t for t in tools if t.get("efi_destination") and t["os"] in (current_os, "both")]

    if not efi_tools:
        return None  # nothing in tools.xml is configured to go onto the EFI partition

    print()
    print("-" * 50)
    print("EFI partition copy")
    print("-" * 50)

    if current_os != "linux":
        print("Skipped: EFI partition copy is only supported on Linux.")
        return None

    if hasattr(os, "geteuid") and os.geteuid() != 0:
        print(f"Skipped: {len(efi_tools)} tool(s) need root to copy onto the EFI partition.")
        print(f"         Re-run with sudo to also copy them, e.g.:")
        print(f"           sudo python3 {Path(__file__).name}")
        return None

    if not efi_mount.is_dir():
        print(f"Skipped: EFI mount point does not exist: {efi_mount}")
        print("         Is the EFI System Partition mounted? (e.g. 'mount | grep /boot/efi')")
        return None

    print(f"EFI mount point: {efi_mount}")
    print(f"Tools to copy to EFI partition: {len(efi_tools)}")
    print("-" * 50)

    success_count = 0
    optional_skipped = 0
    for tool in efi_tools:
        filename = tool["filename"]
        staged_path = tool["destination"] / filename
        efi_dest_dir = efi_mount / tool["efi_destination"]

        if not staged_path.exists():
            if tool.get("optional_reason"):
                print(f"[SKIP] {filename} - optional, not staged: {tool['optional_reason']}")
                optional_skipped += 1
            else:
                print(f"[FAIL] {filename} - not staged yet: {staged_path}")
            continue

        try:
            efi_dest_dir.mkdir(parents=True, exist_ok=True)
            if tool["type"] == "folder":
                target = efi_dest_dir / filename
                if target.exists():
                    shutil.rmtree(str(target))
                shutil.copytree(str(staged_path), str(target))
            else:
                target = efi_dest_dir / filename
                shutil.copy2(str(staged_path), str(target))
                _set_executable_if_needed(target)
            print(f"[OK]   {staged_path} -> {target}")
            success_count += 1
        except PermissionError:
            print(f"[FAIL] {filename} - permission denied writing to {efi_dest_dir}")
        except OSError as e:
            print(f"[FAIL] {filename} - {e}")

    print("-" * 50)
    optional_note = f" ({optional_skipped} optional skipped)" if optional_skipped else ""
    print(f"Done. {success_count}/{len(efi_tools)} tools copied to EFI partition{optional_note}.")
    return success_count + optional_skipped == len(efi_tools)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="Deploy external tool binaries from a Downloads folder into ./Tools, "
                    "then automatically copy the ones needed on the SUT EFI partition there too "
                    "(EFI copy is skipped with a message if not run with sudo)."
    )
    parser.add_argument(
        "xml_file", nargs="?", default=None,
        help="Path to tools.xml (default: tools.xml next to this script)"
    )
    parser.add_argument(
        "--efi-mount", default=None,
        help="Override the EFI partition mount point (default: <config><efi_mount> in "
             "tools.xml, normally /boot/efi)"
    )
    parser.add_argument(
        "--yes", "-y", action="store_true",
        help="Non-interactive mode: never prompt. Ambiguous matches and missing tools "
             "are automatically skipped instead of asking to choose/retry. Use this for "
             "unattended runs, e.g.: sudo python3 deploy/tools/deploy_tools.py --yes"
    )
    args = parser.parse_args()

    if args.yes:
        NON_INTERACTIVE = True

    # Look for tools.xml in the same directory as this script, unless overridden
    script_dir = Path(__file__).parent
    xml_file = Path(args.xml_file) if args.xml_file else script_dir / "tools.xml"

    if not xml_file.is_file():
        print(f"Error: Cannot find {xml_file}")
        sys.exit(1)

    # Save a copy of everything printed below into logs/, matching the timestamped
    # log convention conftest.py uses for test runs.
    log_dir = REPO_ROOT / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    log_file = log_dir / f"deploy_tools_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
    console_stdout = sys.stdout
    with open(log_file, "w", encoding="utf-8") as log_fh:
        sys.stdout = _Tee(console_stdout, log_fh)
        try:
            print(f"Logging output to: {log_file}")

            # Step 1: always stage Downloads/ -> ./Tools/ (never needs elevation)
            staged_ok = deploy_tools(str(xml_file))
            # Step 2: always attempt to also copy the EFI-bound tools onto the SUT EFI
            # partition. tools.xml's <efi_destination> decides which tools qualify --
            # no separate flag needed. Gracefully skipped (not a hard failure) if this
            # process isn't running as root.
            efi_ok = deploy_to_efi(str(xml_file), efi_mount_override=args.efi_mount)
        finally:
            # Restore stdout before log_fh closes, so shutdown-time flushes don't hit it.
            sys.stdout = console_stdout

    # Exit non-zero whenever something was actually missing/skipped/failed, so
    # callers like setup_sut.sh can't mistake a partial run for full success --
    # efi_ok=None means that phase was gracefully skipped (not attempted), which
    # is not itself a failure.
    if not staged_ok or efi_ok is False:
        sys.exit(1)
