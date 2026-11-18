# Copyright 2026 Intel Corporation
# SPDX-License-Identifier: Apache-2.0

"""
Combined log for a batch that spans reboots, shared by conftest.py (written when
the batch finishes) and test_runner.py (rebuilt on view). Standard library only.
"""

from pathlib import Path
from typing import Dict, Optional


def combined_log_path(logs_dir: Path, batch: Dict) -> Path:
    return Path(logs_dir) / f"batch_{batch.get('batch_id', 'unknown')}_combined.log"


def format_duration(seconds: float) -> str:
    """45 -> '45s', 135 -> '2m 15s', 3735 -> '1h 02m 15s'."""
    seconds = max(int(round(seconds)), 0)
    hours, rem = divmod(seconds, 3600)
    minutes, secs = divmod(rem, 60)
    if hours:
        return f"{hours}h {minutes:02d}m {secs:02d}s"
    if minutes:
        return f"{minutes}m {secs:02d}s"
    return f"{secs}s"


def stitch_batch_log(logs_dir: Path, batch: Dict) -> Optional[Path]:
    """
    Concatenate every per-process test_execution.log the batch touched, in
    order, into one file -- each reboot starts a new pytest process with its
    own logs/test_run_*/ folder.
    """
    log_dirs = batch.get("log_dirs") or ([batch["log_dir"]] if batch.get("log_dir") else [])
    if not log_dirs:
        return None

    combined_path = combined_log_path(logs_dir, batch)
    with open(combined_path, "w", encoding="utf-8") as out:
        for i, log_dir in enumerate(log_dirs, 1):
            segment = Path(log_dir) / "test_execution.log"
            out.write(f"\n{'=' * 80}\nSEGMENT {i}/{len(log_dirs)}: {segment}\n{'=' * 80}\n\n")
            if segment.exists():
                out.write(segment.read_text(encoding="utf-8", errors="replace"))
            else:
                out.write("[missing -- log folder was removed or never wrote test_execution.log]\n")
    return combined_path
