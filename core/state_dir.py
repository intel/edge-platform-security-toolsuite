# Copyright 2026 Intel Corporation
# SPDX-License-Identifier: Apache-2.0

"""
Where SUT-local tests keep what must survive a reboot.

Default: <repo>/logs/sut_state -- on the SUT's own disk, which survives every reboot, so no
USB drive is needed. It holds state.json, state_done.txt / next_test.txt (Linux resume
service), the operator's signal files and data saved before a reboot (PCR snapshots, ...).

``usb_mount`` in a suite YAML overrides it (e.g. "D:/" or "/media/usb" to keep using a USB drive).
"""

from pathlib import Path
import os
from typing import Optional

DEFAULT_STATE_DIR = Path(__file__).resolve().parents[1] / "logs" / "sut_state"


def resolve(configured: Optional[str] = None) -> Path:
    """The state folder to use: the ``usb_mount`` override if set, else DEFAULT_STATE_DIR (created)."""
    if configured:
        path = Path(configured)
        if not path.is_dir():
            raise FileNotFoundError(
                f"usb_mount '{configured}' (suite config) is not mounted. Plug in and mount the drive, "
                f"or remove 'usb_mount' to keep the state on this SUT's disk ({DEFAULT_STATE_DIR}).")
        return path
    DEFAULT_STATE_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    # mkdir's mode does not apply to an existing folder; only the owner may change it.
    if hasattr(os, "getuid") and DEFAULT_STATE_DIR.stat().st_uid == os.getuid():
        DEFAULT_STATE_DIR.chmod(0o700)
    return DEFAULT_STATE_DIR
