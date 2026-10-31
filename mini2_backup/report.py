# AI-generated code. Review before use. See AI_DISCLOSURE.md.
"""Versioned JSON report helpers.

The report is explicit about what was *not* done.  In particular, a successful
run never flips hardware-validation, restore or OOB fields to true.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Iterable, List

from . import TOOL_NAME, __version__
from .util import utc_now, write_text_exclusive

SCHEMA_VERSION = "1.1"
LEGACY_SCHEMA_VERSIONS = ("1.0",)

FALSE_CLAIMS = (
    "physical_nand_oob_backup",
    "mtd0_complete",
    "reserved_areas_backed_up",
    "offline_consistent_snapshot",
    "independent_nand_reread",
    "restore_tested",
    "hardware_validation_of_this_tool",
)

CONSISTENCY_NOTES = [
    "Images are logical MTD streams obtained through the vendor NAND driver.",
    "nanddump is used with --bb=padbad --omitoob and default ECC handling; "
    "physical OOB/spare data is not captured.",
    "Bad blocks, if present, are replaced by 0xFF with the stream length preserved.",
    "mtd0 is not read by this tool.",
    "Reserved areas, BBT/ENV/KEY/DTB/DDR and the gap between mtd0 and mtd1 are "
    "not backed up by a verified safe method.",
    "UBI remains attached and Quasar/services are not stopped; no offline-consistent "
    "snapshot is claimed.",
    "The external/manual copy is not independent NAND re-reading.",
    "No restore has been tested.",
]


def new_report(status: str = "failed") -> dict:
    now = utc_now()
    return {
        "schema_version": SCHEMA_VERSION,
        "tool": {"name": TOOL_NAME, "version": __version__},
        "generated_by_ai": True,
        "ai_disclosure": "Code and documentation were produced with AI assistance; "
                         "see AI_DISCLOSURE.md. No independent security audit.",
        "synthetic_example": False,
        "started_at": now,
        "completed_at": None,
        "status": status,
        "host": {},
        "device": {},
        "layout": {},
        "preflight": {},
        "checks": [],
        "artifacts": [],
        "consistency": {key: False for key in FALSE_CLAIMS},
        "consistency_notes": list(CONSISTENCY_NOTES),
        "warnings": [],
        "errors": [],
    }


def finish_report(report: dict, status: str) -> dict:
    report["status"] = status
    report["completed_at"] = utc_now()
    return report


def report_json(report: dict) -> str:
    return json.dumps(report, indent=2, ensure_ascii=False, sort_keys=False) + "\n"


def write_report(path: Path, report: dict) -> None:
    write_text_exclusive(path, report_json(report))


def checksum_text(entries: Iterable[dict]) -> str:
    """Build a sha256sum-compatible file for completed artifacts only.

    Never includes the report or the checksum file itself.
    """
    lines: List[str] = []
    for entry in entries:
        if entry.get("status") != "completed":
            continue
        relative = entry.get("path")
        digest = entry.get("sha256")
        if not relative or not digest:
            continue
        if relative in ("checksums.sha256", "report.json"):
            continue
        lines.append("%s  %s" % (digest, relative))
    lines.sort(key=lambda line: line.split("  ", 1)[1])
    return "\n".join(lines) + ("\n" if lines else "")
