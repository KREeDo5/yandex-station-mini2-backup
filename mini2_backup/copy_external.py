# AI-generated code. Review before use. See AI_DISCLOSURE.md.
"""Verified local copy of a backup tree to a user-supplied destination.

The copy is created in a new unique subdirectory.  Existing files are never
overwritten, symlinks are copied as symlinks (or the operation fails
explicitly), and regular files are compared byte-by-byte in blocks.
"""

from __future__ import annotations

import json
import os
import secrets
import stat
import sys
import tempfile
from pathlib import Path
from typing import Dict, List, Optional

from . import TOOL_NAME, __version__
from .errors import CopyError, UsageError
from .report import SCHEMA_VERSION
from .util import human_bytes, is_within, iter_file_blocks, utc_now, write_text_exclusive

CHUNK = 1024 * 1024


def scan_tree(root: Path) -> Dict[str, dict]:
    """Return a relative-path -> type/size/target inventory.

    Directory symlinks are not followed.  Special files are recorded so the
    caller can reject them explicitly.
    """
    root = Path(root)
    result: Dict[str, dict] = {}

    def walk(directory: Path, prefix: str) -> None:
        with os.scandir(str(directory)) as iterator:
            entries = sorted(iterator, key=lambda e: e.name)
        for entry in entries:
            relative = prefix + entry.name
            try:
                info = entry.stat(follow_symlinks=False)
            except OSError as exc:
                raise CopyError("cannot stat %s: %s" % (entry.path, exc))
            if stat.S_ISLNK(info.st_mode):
                target = os.readlink(entry.path)
                result[relative] = {"type": "symlink", "target": target,
                                    "size": len(target)}
            elif stat.S_ISDIR(info.st_mode):
                result[relative] = {"type": "dir"}
                walk(Path(entry.path), relative + "/")
            elif stat.S_ISREG(info.st_mode):
                result[relative] = {"type": "file", "size": info.st_size}
            else:
                result[relative] = {"type": "other", "mode": info.st_mode}
    walk(root, "")
    return result


def compare_trees(source: Path, destination: Path) -> List[str]:
    """Compare inventories and regular-file bytes.  Returns mismatches."""
    mismatches: List[str] = []
    left = scan_tree(source)
    right = scan_tree(destination)
    for relative in sorted(set(left) | set(right)):
        if relative not in left:
            mismatches.append("only in destination: %s" % relative)
            continue
        if relative not in right:
            mismatches.append("missing from destination: %s" % relative)
            continue
        a = left[relative]
        b = right[relative]
        if a["type"] != b["type"]:
            mismatches.append("type mismatch at %s: %s vs %s"
                              % (relative, a["type"], b["type"]))
            continue
        if a["type"] == "file":
            if a["size"] != b["size"]:
                mismatches.append("size mismatch at %s: %s vs %s"
                                  % (relative, a["size"], b["size"]))
                continue
            for detail in iter_file_blocks(source / relative, destination / relative, CHUNK):
                mismatches.append("%s: %s" % (relative, detail))
                break
        elif a["type"] == "symlink":
            if a["target"] != b["target"]:
                mismatches.append("symlink target mismatch at %s: %r vs %r"
                                  % (relative, a["target"], b["target"]))
        elif a["type"] == "other":
            mismatches.append("unsupported special file: %s" % relative)
    return mismatches


def _open_nofollow(path: Path) -> int:
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    return os.open(str(path), flags)


def _copy_file(source: Path, destination: Path) -> int:
    written = 0
    source_fd = _open_nofollow(source)
    try:
        with os.fdopen(source_fd, "rb") as reader:
            fd = os.open(str(destination), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            try:
                while True:
                    block = reader.read(CHUNK)
                    if not block:
                        break
                    offset = 0
                    while offset < len(block):
                        count = os.write(fd, block[offset:])
                        if count <= 0:
                            raise OSError("short write while copying %s" % source)
                        offset += count
                    written += len(block)
                os.fsync(fd)
            finally:
                os.close(fd)
    except OSError:
        # fdopen owns source_fd after a successful call; avoid a double close
        # only when fdopen itself failed.
        try:
            os.close(source_fd)
        except OSError:
            pass
        raise
    return written


def _copy_tree(source: Path, destination: Path,
               inventory: Optional[Dict[str, dict]] = None) -> dict:
    inventory = inventory if inventory is not None else scan_tree(source)
    files = directories = symlinks = 0
    bytes_copied = 0
    for relative in sorted(inventory):
        meta = inventory[relative]
        src = source / relative
        dst = destination / relative
        if meta["type"] == "dir":
            os.mkdir(str(dst), 0o700)
            directories += 1
        elif meta["type"] == "file":
            bytes_copied += _copy_file(src, dst)
            files += 1
        elif meta["type"] == "symlink":
            try:
                os.symlink(meta["target"], str(dst))
            except (OSError, NotImplementedError) as exc:
                raise CopyError(
                    "cannot create symlink %s on the destination filesystem: %s"
                    % (relative, exc)
                )
            symlinks += 1
        else:
            raise CopyError("unsupported special file in source: %s" % relative)
    return {
        "files": files,
        "directories": directories,
        "symlinks": symlinks,
        "bytes_copied": bytes_copied,
    }


def _new_report(source: Path, destination_root: Path, destination: Optional[Path]) -> dict:
    return {
        "schema_version": SCHEMA_VERSION,
        "tool": {"name": TOOL_NAME, "version": __version__},
        "generated_by_ai": True,
        "started_at": utc_now(),
        "completed_at": None,
        "status": "failed",
        "source": str(source),
        "destination_root": str(destination_root),
        "destination_copy": str(destination) if destination else None,
        "counts": {},
        "mismatches": [],
        "permissions_dates_xattrs_compared": False,
        "symlinks_preserved": False,
        "physical_independence": "not_verified",
        "source_modified_detected": False,
        "source_modification_check": "inventory_only",
        "errors": [],
        "warnings": [
            "Permissions, timestamps and extended attributes are not compared.",
            "A path under /Volumes does not by itself prove a separate physical device.",
            "This copy is not an independent NAND re-read.",
            "The source backup contents and checksum files are not rewritten; "
            "reading may still update access times depending on the filesystem.",
            "The tool never ejects the destination volume. Eject it safely with the "
            "operating system after the copy and verification complete.",
        ],
    }


def copy_external(
    source: Path,
    destination_root: Path,
    *,
    report_path: Optional[Path] = None,
    allow_non_volume: bool = False,
    platform: Optional[str] = None,
    printer=None,
) -> dict:
    """Copy ``source`` into a new unique subdirectory of ``destination_root``."""
    printer = printer or (lambda _message: None)
    platform = platform if platform is not None else sys.platform
    source = Path(source).expanduser()
    destination_root = Path(destination_root).expanduser()

    if not source.exists() or not source.is_dir():
        raise UsageError("source backup directory does not exist: %s" % source)
    if source.is_symlink():
        raise UsageError("source directory must not be a symlink")
    if not destination_root.exists() or not destination_root.is_dir():
        raise UsageError("destination root does not exist or is not a directory: %s"
                         % destination_root)

    source_resolved = source.resolve()
    destination_resolved = destination_root.resolve()
    if is_within(destination_resolved, source_resolved):
        raise UsageError("destination must not be inside the source backup tree")

    if platform == "darwin" and not allow_non_volume:
        volume_root = Path("/Volumes")
        if not is_within(destination_resolved, volume_root):
            raise UsageError(
                "on macOS the destination should be under /Volumes (for example an "
                "external disk). Re-run with --allow-non-volume if you understand "
                "that this does not prove physical independence."
            )

    if report_path is None:
        stamp = utc_now().replace(":", "").replace("-", "")
        report_path = destination_root / ("external-copy-report-%s-%s.json"
                                          % (stamp, secrets.token_hex(3)))
    report_path = Path(report_path).expanduser()
    if is_within(report_path, source_resolved):
        raise UsageError("the copy report must be written outside the source tree")
    if os.path.lexists(str(report_path)):
        raise UsageError("refusing to overwrite existing report: %s" % report_path)
    if not report_path.parent.is_dir():
        raise UsageError("report parent directory does not exist: %s" % report_path.parent)

    report = _new_report(source_resolved, destination_resolved, None)

    prefix = "external-copy-%s-" % utc_now().replace(":", "").replace("-", "")
    destination = Path(tempfile.mkdtemp(prefix=prefix, dir=str(destination_resolved)))
    if is_within(report_path, destination):
        try:
            destination.rmdir()
        except OSError:
            pass
        raise UsageError("the copy report must be written outside the copied tree")
    report["destination_copy"] = str(destination)
    printer("Copying to %s" % destination)

    try:
        before = scan_tree(source_resolved)
        counts = _copy_tree(source_resolved, destination, before)
        report["counts"] = counts
        after = scan_tree(source_resolved)
        report["source_modified_detected"] = before != after
        if before != after:
            report["errors"].append("source tree changed during the copy")
            report["status"] = "failed"
        else:
            mismatches = compare_trees(source_resolved, destination)
            report["mismatches"] = mismatches
            if mismatches:
                report["errors"].append("%d mismatch(es) after copy" % len(mismatches))
                report["status"] = "failed"
            else:
                report["status"] = "completed"
                report["symlinks_preserved"] = True
                printer("Copy verified byte-by-byte: %s in %d files"
                        % (human_bytes(counts["bytes_copied"]), counts["files"]))
    except (CopyError, OSError, ValueError) as exc:
        report["errors"].append(str(exc))
        report["status"] = "failed"
    finally:
        report["completed_at"] = utc_now()
        try:
            write_text_exclusive(
                report_path,
                json.dumps(report, indent=2, ensure_ascii=False) + "\n",
            )
        except OSError as exc:
            report["errors"].append("could not write report: %s" % exc)
            report["status"] = "failed"
        printer("Report: %s" % report_path)

    return report
