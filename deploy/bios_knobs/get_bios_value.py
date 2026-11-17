#!/usr/bin/env python3
# Copyright 2026 Intel Corporation
# SPDX-License-Identifier: Apache-2.0

"""Search a BIOS setup (AMISCE) file for a Setup Question and return its
current value.

For an option-based question the currently selected option is the one marked
with '*' (e.g. "Options =*[00]Disabled"). For a numeric question the "Value ="
line is returned.

Usage:
    python get_bios_value.py "Enable VTIO Support"
    python get_bios_value.py "Enable VTIO Support" -f C:\\git\\bios_setup\\bios_setup.txt
"""

import argparse
import re
import sys


def _label(opt):
    """Strip a leading "[xx]" code from an option, leaving the label."""
    return re.sub(r"^\[[0-9A-Fa-f]+\]\s*", "", opt).strip()


def find_setup_value(path, question):
    want = question.strip().lower()

    with open(path, "r", encoding="utf-8", errors="replace") as f:
        lines = f.readlines()

    i = 0
    n = len(lines)
    while i < n:
        line = lines[i]
        m = re.match(r"\s*Setup Question\s*=\s*(.*?)\s*$", line)
        if m and m.group(1).strip().lower() == want:
            # Scan forward until the next Setup Question / blank section end.
            j = i + 1
            while j < n:
                cur = lines[j]
                if re.match(r"\s*Setup Question\s*=", cur):
                    break

                # Simple single-line value fields: Value / Date / Time.
                vm = re.match(r"\s*(?:Value|Date|Time)\s*=\s*(.*?)\s*$", cur)
                if vm:
                    return re.split(r"//", vm.group(1))[0].strip()

                # ListOrder block: an ordered list spread over multiple lines.
                lm = re.match(r"\s*ListOrder\s*=\s*(.*?)\s*$", cur)
                if lm:
                    items = [_label(re.split(r"//", lm.group(1))[0].strip())]
                    k = j + 1
                    while k < n:
                        nxt = lines[k]
                        if re.match(r"\s*Setup Question\s*=", nxt) or \
                           nxt.strip() == "" or \
                           re.match(
                               r"\s*(Help String|Token|Offset|Width|"
                               r"BIOS Default|Value|Options|ListOrder|"
                               r"Date|Time)\s*=",
                               nxt,
                           ):
                            break
                        items.append(_label(re.split(r"//", nxt)[0].strip()))
                        k += 1
                    return ", ".join(i for i in items if i)

                # Options block: first line holds "Options =*[..]..." plus
                # possible following continuation lines. Return starred one.
                om = re.match(r"\s*Options\s*=\s*(.*?)\s*$", cur)
                if om:
                    # Gather the options line and its continuation lines.
                    opt_lines = [om.group(1)]
                    k = j + 1
                    while k < n:
                        nxt = lines[k]
                        if re.match(r"\s*Setup Question\s*=", nxt):
                            break
                        if re.match(
                            r"\s*(Help String|Token|Offset|Width|"
                            r"BIOS Default|Value|Options)\s*=",
                            nxt,
                        ):
                            break
                        if nxt.strip() == "":
                            break
                        opt_lines.append(nxt.strip())
                        k += 1

                    for opt in opt_lines:
                        # Strip trailing comments.
                        opt = re.split(r"//", opt)[0].strip()
                        if opt.startswith("*"):
                            return _label(opt.lstrip("*").strip())
                    # No starred option found; return first option.
                    first = re.split(r"//", opt_lines[0])[0].strip()
                    return _label(first.lstrip("*").strip())

                j += 1
            return None  # Section found but no value/options.
        i += 1
    return None


def main():
    ap = argparse.ArgumentParser(description="Get a BIOS setup value.")
    ap.add_argument("question", help="Setup Question text to search for.")
    ap.add_argument(
        "-f",
        "--file",
        default=r"C:\git\bios_setup\bios_setup.txt",
        help="Path to the BIOS setup file.",
    )
    args = ap.parse_args()

    result = find_setup_value(args.file, args.question)
    if result is None:
        print(f'Setup Question "{args.question}" not found.', file=sys.stderr)
        sys.exit(1)

    print(result)


if __name__ == "__main__":
    main()
