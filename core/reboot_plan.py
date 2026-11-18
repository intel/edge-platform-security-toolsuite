# Copyright 2026 Intel Corporation
# SPDX-License-Identifier: Apache-2.0

"""
core/reboot_plan.py — how many reboots a batch needs, which test rebooted, and what comes next.

conftest.py prints this at the start of every pytest process of a batch, and the status window
(deploy/resume/status_window.py, opens by itself on Windows and Linux) keeps it on screen, so
the operator always sees where the batch is and whether the next reboot needs them in BIOS
Setup -- tests between reboots only take seconds.

Each test declares its reboots (BaseTest.REBOOTS / reboot_plan()); the batch manifest
(logs/batch_status.json) keeps that plan plus how many reboots each test has used so far,
counted from boot-id changes. Standard library only.
"""

from datetime import datetime
from typing import Dict, List, Optional

TERMINAL = ("PASSED", "FAILED", "SKIPPED")
_SEP = "=" * 80


def entry(kind: str, what: str, only_if: str = "") -> dict:
    """One planned reboot. kind: 'auto' (the SUT reboots by itself) or 'manual' (the operator does)."""
    return {"kind": kind, "what": what, "only_if": only_if}


def note_boot(batch: dict, boot: str, nodeid: str) -> bool:
    """Record the current boot; a new boot after the first one is charged to nodeid. True if it was a reboot."""
    boots = batch.setdefault("boots", [])
    if boots and boots[-1] == boot:
        return False
    boots.append(boot)
    if len(boots) == 1:
        return False
    done = batch.setdefault("reboots_done", {})
    done[nodeid] = done.get(nodeid, 0) + 1
    batch["last_reboot"] = nodeid
    return True


def _rows(batch: dict) -> List[dict]:
    plan = batch.get("reboot_plan") or {}
    done = batch.get("reboots_done") or {}
    results = batch.get("results") or {}
    rows = []
    for i, nid in enumerate(batch.get("order") or [], 1):
        planned = plan.get(nid) or []
        used = done.get(nid, 0)
        status = results.get(nid, "PENDING")
        rows.append({
            "index": i, "nid": nid, "status": status, "planned": planned, "done": used,
            "left": [] if status in TERMINAL else planned[used:],
        })
    return rows


def counts(batch: dict) -> Dict[str, int]:
    rows = _rows(batch)
    left = [e for r in rows for e in r["left"]]
    done = sum(r["done"] for r in rows)
    maybe = sum(1 for e in left if e["only_if"])
    return {
        "done": done,
        "left": len(left),
        "left_manual": sum(1 for e in left if e["kind"] == "manual"),
        "left_maybe": maybe,
        "total_min": done + len(left) - maybe,
        "total_max": done + len(left),
    }


def _total(c: Dict[str, int]) -> str:
    """'7', or '4-7' when some reboots only happen if needed."""
    return str(c["total_max"]) if c["total_min"] == c["total_max"] else f"{c['total_min']}-{c['total_max']}"


def _describe(e: dict) -> str:
    who = "AUTOMATIC -- nothing to do" if e["kind"] == "auto" else "NEEDS YOU"
    return f"{who}: {e['what']}" + (f" (only if {e['only_if']})" if e["only_if"] else "")


def _status_text(row: dict, reasons: dict, resuming: Optional[str], running: Optional[str] = None) -> str:
    if row["nid"] == resuming:
        return "RESUMING NOW"
    if row["nid"] == running and row["status"] == "PENDING":
        return "RUNNING NOW"
    return {"REBOOTING": "WAITING (reboot)"}.get(row["status"], row["status"])


def _reboot_text(row: dict) -> str:
    planned, used = row["planned"], row["done"]
    if not planned and not used:
        return "-"
    kinds = sorted({"manual" if e["kind"] == "manual" else "automatic" for e in planned})
    kind = "/".join(kinds) if kinds else "unplanned"
    maybe = " (only if needed)" if planned and all(e["only_if"] for e in planned) else ""
    if row["status"] in TERMINAL:
        return f"{used} done" if used else "-"
    if used:
        return f"{used} of {max(len(planned), used)} done ({kind})"
    return f"{len(planned)} {kind}{maybe}"


def _label(number: int, e: dict, total: str) -> str:
    return f"REBOOT {number} (only if needed)" if e["only_if"] else f"REBOOT {number} of {total}"


def _next_steps(batch: dict, test_ids: dict) -> List[str]:
    """'Next reboot' and 'next reboot that needs you' lines."""
    c = counts(batch)
    total = _total(c)
    pending = [(r, e, n) for r in _rows(batch) for n, e in enumerate(r["left"])]
    if not pending:
        return [" 👉 You  : nothing -- no more reboots in this batch."]
    lines = []
    number = c["done"] + 1
    row, e, _ = pending[0]
    tid = test_ids.get(row["nid"], row["nid"])
    lines.append(f" Next   : {_label(number, e, total)} -- test {row['index']} ({tid})")
    lines.append(f"          {_describe(e)}")
    manual = next(((i, r, x) for i, (r, x, _n) in enumerate(pending) if x["kind"] == "manual"), None)
    if manual is None:
        lines.append(" 👉 You  : nothing -- every reboot left in this batch is automatic.")
    elif manual[0] == 0:
        lines.append(" 👉 You  : stay at the SUT -- the test prints the exact BIOS steps when it gets there.")
    else:
        i, r, x = manual
        lines.append(f" 👉 You  : nothing now. First reboot that needs you: {_label(number + i, x, total)}"
                     f" -- test {r['index']} ({test_ids.get(r['nid'], r['nid'])})")
        lines.append(f"          {x['what']}" + (f" (only if {x['only_if']})" if x["only_if"] else ""))
    return lines


def banner_lines(batch: dict, resuming: Optional[str] = None, running: Optional[str] = None) -> List[str]:
    """
    The batch status window: title, one row per test with its reboots, and what happens next.
    resuming: node id this process resumes (shown as RESUMING NOW), or None at batch start.
    running: node id running right now (live status window), shown as RUNNING NOW.
    """
    test_ids = batch.get("test_ids") or {}
    reasons = batch.get("reasons") or {}
    rows = _rows(batch)
    c = counts(batch)
    total = _total(c)
    try:
        started = datetime.fromisoformat(batch.get("started", ""))
        age = int((datetime.now() - started).total_seconds())
        since = f"started {started:%H:%M:%S}, {age // 60}m {age % 60:02d}s ago"
    except ValueError:
        since = ""

    if running:
        done_tests = sum(1 for r in rows if r["status"] in TERMINAL)
        title = (f" ⏳ BATCH RUNNING -- {done_tests} of {len(rows)} test(s) done, "
                 f"{c['done']} of {total} reboot(s) done")
    elif resuming and c["done"]:
        title = f" 🔄 RESUMED AFTER REBOOT {c['done']} of {total} -- batch {batch.get('batch_id', '?')}"
    elif resuming:
        title = f" 🔄 RESUMED -- batch {batch.get('batch_id', '?')}"
    else:
        title = f" ▶ BATCH START -- {len(rows)} test(s), {total} reboot(s) in this batch"
    lines = [_SEP, title + (f"   ({since})" if since and (resuming or running) else ""), _SEP]

    tid_width = max([len(test_ids.get(r["nid"], r["nid"])) for r in rows] + [4])
    status_width = max([len(_status_text(r, reasons, resuming, running)) for r in rows] + [6])
    lines.append(f"  {'#':>2}  {'Test':<{tid_width}}  {'Status':<{status_width}}  Reboots")
    for r in rows:
        lines.append(f"  {r['index']:>2}  {test_ids.get(r['nid'], r['nid']):<{tid_width}}  "
                     f"{_status_text(r, reasons, resuming, running):<{status_width}}  {_reboot_text(r)}")
    lines.append("")

    sure_left = c["left"] - c["left_maybe"]
    to_go = str(c["left"]) if not c["left_maybe"] else f"{sure_left}-{c['left']}"
    lines.append(f" Reboots: {c['done']} done, {to_go} to go "
                 f"({c['left'] - c['left_manual']} automatic, {c['left_manual']} need you"
                 + (f"; {c['left_maybe']} only if needed" if c["left_maybe"] else "") + ")")
    last = batch.get("last_reboot")
    if (resuming or running) and last:
        row = next((r for r in rows if r["nid"] == last), None)
        if row:
            prev = row["planned"][row["done"] - 1] if 0 < row["done"] <= len(row["planned"]) else None
            lines.append(f" Now    : back from REBOOT {c['done']} -- test {row['index']} "
                         f"({test_ids.get(last, last)})" + (f": {prev['what']}" if prev else ""))
    lines += _next_steps(batch, test_ids)
    lines.append(_SEP)
    return lines


def next_reboot_lines(batch: dict) -> List[str]:
    """Short 'what comes after this reboot' block for the BATCH IN PROGRESS summary."""
    return _next_steps(batch, batch.get("test_ids") or {})
