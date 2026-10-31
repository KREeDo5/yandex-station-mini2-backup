# AI-generated code. Review before use. See AI_DISCLOSURE.md.
"""Reference MTD profile and parsers for read-only device diagnostics.

The offsets below are a *reference* provided by the device owner.  Standard
Linux MTD interfaces used by this tool (``/proc/mtd`` and
``/sys/class/mtd``) expose sizes and geometry but not partition offsets, so
the tool never claims that offsets were verified.  The backup gate relies on
the fields that can be verified: device set, names, sizes, erasesize,
writesize and oobsize.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Tuple

WRITESIZE = 2048
ERASESIZE = 131072
OOBSIZE = 64
PHYSICAL_SPARE_DOCUMENTED = 128  # chip documentation; the 64/128 gap is unresolved


@dataclass(frozen=True)
class MtdPartition:
    id: str
    name: str
    offset: int
    size: int


# Reference layout supplied by the device owner for YNDX-00020.
# Offsets are documentation only and are not verified by the tool.
REFERENCE_LAYOUT: Tuple[MtdPartition, ...] = (
    MtdPartition("mtd0", "bootloader", 0, 2097152),
    MtdPartition("mtd1", "tpl", 8388608, 2097152),
    MtdPartition("mtd2", "boot", 10485760, 10485760),
    MtdPartition("mtd3", "system", 20971520, 83886080),
    MtdPartition("mtd4", "nv", 104857600, 1048576),
    MtdPartition("mtd5", "bkupgrade", 105906176, 110362624),
    MtdPartition("mtd6", "recovery", 216268800, 52166656),
)

REFERENCE_BY_ID: Dict[str, MtdPartition] = {p.id: p for p in REFERENCE_LAYOUT}

# mtd0 is intentionally excluded.  There is no experimental opt-in.
ALLOWED_BACKUP_IDS: Tuple[str, ...] = ("mtd1", "mtd2", "mtd3", "mtd4", "mtd5", "mtd6")

FORBIDDEN_IDS: Tuple[str, ...] = ("mtd0",)


@dataclass
class MtdInfo:
    id: str
    size: int
    erasesize: int
    name: str


@dataclass
class ProfileIssue:
    device: str
    field: str
    expected: object
    observed: object
    message: str


@dataclass
class ProfileResult:
    ok: bool
    devices: Dict[str, dict] = field(default_factory=dict)
    issues: List[ProfileIssue] = field(default_factory=list)
    offsets_verified: bool = False
    notes: List[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "profile_match": self.ok,
            "offsets_verified": self.offsets_verified,
            "expected_geometry": {
                "erasesize": ERASESIZE,
                "writesize": WRITESIZE,
                "oobsize": OOBSIZE,
            },
            "devices": self.devices,
            "issues": [
                {
                    "device": i.device,
                    "field": i.field,
                    "expected": i.expected,
                    "observed": i.observed,
                    "message": i.message,
                }
                for i in self.issues
            ],
            "notes": self.notes,
        }


_PROC_RE = re.compile(
    r'^mtd(?P<num>\d+):\s+(?P<size>[0-9a-fA-F]+)\s+'
    r'(?P<erase>[0-9a-fA-F]+)\s+"?(?P<name>[^"]*?)"?\s*$'
)


def parse_proc_mtd(text: str) -> Dict[str, MtdInfo]:
    """Parse ``/proc/mtd``.

    Raises ``ValueError`` on malformed or duplicate entries.
    """
    result: Dict[str, MtdInfo] = {}
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.lower().startswith("dev:"):
            continue
        match = _PROC_RE.match(line)
        if not match:
            raise ValueError("malformed /proc/mtd line: %r" % raw_line)
        dev_id = "mtd" + match.group("num")
        if dev_id in result:
            raise ValueError("duplicate %s in /proc/mtd" % dev_id)
        result[dev_id] = MtdInfo(
            id=dev_id,
            size=int(match.group("size"), 16),
            erasesize=int(match.group("erase"), 16),
            name=match.group("name"),
        )
    if not result:
        raise ValueError("/proc/mtd contained no MTD devices")
    return result


def parse_sysfs_probe(text: str) -> Dict[str, Dict[str, str]]:
    """Parse the fixed sysfs probe output produced by ``check``.

    Format::

        DEV mtd0
        ATTR size 2097152
        ATTR writesize 2048
        ...
    """
    devices: Dict[str, Dict[str, str]] = {}
    current: Optional[str] = None
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if line.startswith("DEV "):
            current = line[4:].strip()
            if not re.match(r"^mtd\d+$", current):
                raise ValueError("malformed sysfs device id: %r" % current)
            if current in devices:
                raise ValueError("duplicate sysfs device: %s" % current)
            devices[current] = {}
        elif line.startswith("ATTR "):
            if current is None:
                raise ValueError("sysfs attribute before device line")
            rest = line[5:].strip()
            if " " not in rest:
                raise ValueError("malformed sysfs attribute line: %r" % raw_line)
            key, value = rest.split(" ", 1)
            devices[current][key] = value.strip()
        else:
            raise ValueError("unexpected sysfs probe line: %r" % raw_line)
    if not devices:
        raise ValueError("sysfs probe contained no MTD devices")
    return devices


def _as_int(value: object) -> Optional[int]:
    try:
        return int(str(value).strip(), 10)
    except (TypeError, ValueError):
        return None


def evaluate_profile(
    proc: Dict[str, MtdInfo],
    sysfs: Dict[str, Dict[str, str]],
) -> ProfileResult:
    """Compare observed MTD information with the reference profile.

    A single mismatch makes ``ok`` false.  Missing data is a mismatch, never a
    reason to substitute expected values.
    """
    issues: List[ProfileIssue] = []
    devices: Dict[str, dict] = {}

    expected_ids = set(REFERENCE_BY_ID)
    observed_ids = set(proc) | set(sysfs)
    for missing in sorted(expected_ids - observed_ids):
        issues.append(
            ProfileIssue(missing, "presence", "present", "absent",
                         "%s is missing from the device" % missing)
        )
    for extra in sorted(observed_ids - expected_ids):
        issues.append(
            ProfileIssue(extra, "presence", "absent", "present",
                         "unexpected MTD device %s is present" % extra)
        )

    for part in REFERENCE_LAYOUT:
        proc_info = proc.get(part.id)
        sys_info = sysfs.get(part.id, {})
        record = {
            "name": part.name,
            "expected_size": part.size,
            "expected_offset": part.offset,
            "offset_verified": False,
            "proc_size": proc_info.size if proc_info else None,
            "proc_erasesize": proc_info.erasesize if proc_info else None,
            "proc_name": proc_info.name if proc_info else None,
            "sysfs": dict(sys_info),
        }
        devices[part.id] = record

        if proc_info is None:
            issues.append(ProfileIssue(part.id, "presence", "present", "absent",
                                       "%s is missing from /proc/mtd" % part.id))
            continue

        if proc_info.size != part.size:
            issues.append(ProfileIssue(part.id, "size", part.size, proc_info.size,
                                       "%s size does not match the reference profile" % part.id))
        if proc_info.erasesize != ERASESIZE:
            issues.append(ProfileIssue(part.id, "erasesize", ERASESIZE, proc_info.erasesize,
                                       "%s erasesize does not match" % part.id))
        if proc_info.name != part.name:
            issues.append(ProfileIssue(part.id, "name", part.name, proc_info.name,
                                       "%s name does not match" % part.id))

        sys_size = _as_int(sys_info.get("size"))
        sys_erase = _as_int(sys_info.get("erasesize"))
        sys_write = _as_int(sys_info.get("writesize"))
        sys_oob = _as_int(sys_info.get("oobsize"))
        sys_name = sys_info.get("name")

        if sys_size is None:
            issues.append(ProfileIssue(part.id, "sysfs.size", part.size, "unreadable",
                                       "%s sysfs size is not readable" % part.id))
        elif sys_size != part.size:
            issues.append(ProfileIssue(part.id, "sysfs.size", part.size, sys_size,
                                       "%s sysfs size does not match" % part.id))
        if sys_erase is None:
            issues.append(ProfileIssue(part.id, "sysfs.erasesize", ERASESIZE, "unreadable",
                                       "%s sysfs erasesize is not readable" % part.id))
        elif sys_erase != ERASESIZE:
            issues.append(ProfileIssue(part.id, "sysfs.erasesize", ERASESIZE, sys_erase,
                                       "%s sysfs erasesize does not match" % part.id))
        if sys_write is None:
            issues.append(ProfileIssue(part.id, "sysfs.writesize", WRITESIZE, "unreadable",
                                       "%s sysfs writesize is not readable" % part.id))
        elif sys_write != WRITESIZE:
            issues.append(ProfileIssue(part.id, "sysfs.writesize", WRITESIZE, sys_write,
                                       "%s sysfs writesize does not match" % part.id))
        if sys_oob is None:
            issues.append(ProfileIssue(part.id, "sysfs.oobsize", OOBSIZE, "unreadable",
                                       "%s sysfs oobsize is not readable" % part.id))
        elif sys_oob != OOBSIZE:
            issues.append(ProfileIssue(part.id, "sysfs.oobsize", OOBSIZE, sys_oob,
                                       "%s sysfs oobsize does not match" % part.id))
        if sys_name is None:
            issues.append(ProfileIssue(part.id, "sysfs.name", part.name, "unreadable",
                                       "%s sysfs name is not readable" % part.id))
        elif sys_name != part.name:
            issues.append(ProfileIssue(part.id, "sysfs.name", part.name, sys_name,
                                       "%s sysfs name does not match" % part.id))

    notes = [
        "/proc/mtd and /sys/class/mtd do not expose partition offsets; "
        "reference offsets are documentation only and are not verified.",
        "A matching layout does not prove the device is healthy or that the "
        "NAND content is readable end-to-end.",
        "mtd0 is intentionally excluded from every backup path.",
    ]
    return ProfileResult(ok=not issues, devices=devices, issues=issues,
                         offsets_verified=False, notes=notes)


def validate_backup_ids(ids: Iterable[str]) -> List[str]:
    """Validate a user-supplied partition selection.

    Only mtd1..mtd6 are allowed; mtd0 gets a dedicated error message.
    """
    result: List[str] = []
    for item in ids:
        dev_id = item.strip()
        if dev_id in FORBIDDEN_IDS:
            raise ValueError(
                "mtd0 is intentionally unsupported: the documented manual read "
                "stopped with an ECC error and the cause is unresolved"
            )
        if dev_id not in ALLOWED_BACKUP_IDS:
            raise ValueError(
                "unsupported partition %r; allowed values are %s"
                % (dev_id, ", ".join(ALLOWED_BACKUP_IDS))
            )
        if dev_id not in result:
            result.append(dev_id)
    if not result:
        raise ValueError("no partitions selected")
    return result
