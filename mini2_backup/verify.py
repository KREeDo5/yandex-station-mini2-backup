# AI-generated code. Review before use. See AI_DISCLOSURE.md.
"""Offline verification of a local backup directory.

This module never contacts the device, never executes anything from the
archive, never extracts files and never claims that a restore was tested.
"""

from __future__ import annotations

import json
import os
import re
import tarfile
from pathlib import Path, PurePosixPath
from typing import Dict, List

from . import TOOL_NAME, __version__
from .profile import ALLOWED_BACKUP_IDS, REFERENCE_BY_ID
from .report import FALSE_CLAIMS, LEGACY_SCHEMA_VERSIONS, SCHEMA_VERSION
from .util import (
    ensure_regular_file,
    human_bytes,
    resolve_inside,
    safe_relative_path,
    stream_sha256,
    utc_now,
)

_SHA_RE = re.compile(r"^[0-9a-f]{64}$")
_CHECKSUM_RE = re.compile(r"^([0-9a-fA-F]{64}) [ *](.+)$")
_COMPRESSED_MAGIC = (
    b"\x1f\x8b",       # gzip
    b"\x42\x5a\x68",   # bzip2
    b"\xfd7zXZ",       # xz
    b"\x28\xb5\x2f\xfd",  # zstd
)


def new_verification_report(root: Path) -> dict:
    return {
        "schema_version": SCHEMA_VERSION,
        "tool": {"name": TOOL_NAME, "version": __version__},
        "generated_by_ai": True,
        "started_at": utc_now(),
        "completed_at": None,
        "status": "failed",
        "backup_dir": str(root),
        "backup_report_schema": None,
        "artifacts_checked": 0,
        "bytes_checked": 0,
        "partitions_in_report": [],
        "partitions_checked": [],
        "tar_checked": [],
        "checks": [],
        "errors": [],
        "warnings": [],
        "restore_tested": False,
        "hardware_validation_of_this_tool": False,
        "limitations": [
            "SHA-256 equality proves that local bytes did not change after the "
            "backup; it does not prove that the original NAND read was correct.",
            "Verification does not re-read the device and is not an independent "
            "NAND read.",
            "Verification does not test a restore.",
            "The /bkupgrade tar is inspected as a stream and never extracted or executed.",
        ],
    }


def _add_check(report: dict, check_id: str, ok: bool, detail: str) -> None:
    report["checks"].append({"id": check_id, "status": "ok" if ok else "failed",
                             "detail": detail})


def _validate_tar_name(name: str, *, allow_root: bool = False) -> None:
    if not isinstance(name, str) or not name:
        raise ValueError("empty member name in tar")
    if "\x00" in name:
        raise ValueError("NUL byte in tar member name")
    if "\\" in name:
        raise ValueError("backslash in tar member name: %r" % name)
    if name.startswith("/"):
        raise ValueError("absolute tar member name: %r" % name)
    if len(name) >= 2 and name[1] == ":":
        raise ValueError("drive-qualified tar member name: %r" % name)
    normalized = name
    while normalized.startswith("./"):
        normalized = normalized[2:]
    if normalized in ("", "."):
        if allow_root:
            return
        raise ValueError("unexpected empty tar member name")
    pure = PurePosixPath(normalized)
    if pure.is_absolute():
        raise ValueError("absolute tar member name: %r" % name)
    if any(part == ".." for part in pure.parts):
        raise ValueError("parent traversal in tar member name: %r" % name)


def inspect_tar(path: Path) -> dict:
    """Inspect tar structure without extraction.

    Returns counts.  Raises ``ValueError`` for unsafe or unsupported content.
    """
    ensure_regular_file(path, "tar archive")
    with path.open("rb") as handle:
        magic = handle.read(8)
        if any(magic.startswith(prefix) for prefix in _COMPRESSED_MAGIC):
            raise ValueError("compressed tar archives are not supported for inspection")
        handle.seek(0)
        members = 0
        regular_files = 0
        directories = 0
        symlinks = 0
        hardlinks = 0
        total_regular_bytes = 0
        try:
            with tarfile.open(fileobj=handle, mode="r|") as archive:
                for member in archive:
                    _validate_tar_name(member.name, allow_root=True)
                    if member.isreg():
                        regular_files += 1
                        total_regular_bytes += max(0, member.size)
                    elif member.isdir():
                        directories += 1
                    elif member.issym():
                        symlinks += 1
                        _validate_tar_name(member.linkname)
                    elif member.islnk():
                        hardlinks += 1
                        _validate_tar_name(member.linkname)
                    else:
                        raise ValueError(
                            "unsupported tar member type for %r" % member.name
                        )
                    members += 1
        except tarfile.TarError as exc:
            raise ValueError("cannot parse tar archive: %s" % exc)
    return {
        "members": members,
        "regular_files": regular_files,
        "directories": directories,
        "symlinks": symlinks,
        "hardlinks": hardlinks,
        "total_regular_bytes": total_regular_bytes,
    }


def _load_report(root: Path) -> dict:
    path = root / "report.json"
    ensure_regular_file(path, "report.json")
    try:
        with path.open("r", encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, ValueError) as exc:
        raise ValueError("cannot parse report.json: %s" % exc)
    if not isinstance(data, dict):
        raise ValueError("report.json must contain a JSON object")
    return data


def _stat_size(path: Path) -> int:
    return path.stat().st_size


def _check_file_state(root: Path, state, label: str, errors: List[str],
                      warnings: List[str]):
    if state is None:
        return None, None, None
    if not isinstance(state, dict):
        errors.append("%s file state is not an object" % label)
        return None, None, None
    exists = state.get("exists")
    if exists is True:
        relative = state.get("path")
        if not isinstance(relative, str):
            errors.append("%s file state has no path" % label)
            return None, None, None
        try:
            target = resolve_inside(root, relative)
            ensure_regular_file(target, label)
        except ValueError as exc:
            errors.append("%s: %s" % (label, exc))
            return None, None, None
        try:
            size = _stat_size(target)
        except OSError as exc:
            errors.append("%s: cannot stat file: %s" % (label, exc))
            return None, None, None
        reported_size = state.get("size")
        if reported_size is not None and reported_size != size:
            errors.append("%s size mismatch: state says %r, file is %d"
                          % (label, reported_size, size))
        if state.get("kind") not in (None, "file"):
            errors.append("%s has unexpected kind %r" % (label, state.get("kind")))
        return True, size, target
    if exists is False:
        return False, None, None
    if exists is None:
        warnings.append("%s file existence could not be determined" % label)
        return None, None, None
    errors.append("%s has invalid exists value %r" % (label, exists))
    return None, None, None


ALLOWED_ARTIFACT_KINDS = ("mtd_image", "tar")


def _validate_artifact_semantics(entry: dict, label: str, errors: List[str],
                                 seen_partitions: set):
    kind = entry.get("kind")
    if kind not in ALLOWED_ARTIFACT_KINDS:
        errors.append("%s: unsupported artifact kind %r" % (label, kind))
        return False, None
    if kind == "tar":
        if "partition" not in entry or entry.get("partition") is not None:
            errors.append("%s: tar artifact must have partition=null" % label)
            return False, None
        return True, None

    partition = entry.get("partition")
    if partition == "mtd0":
        errors.append("%s: mtd0 is forbidden" % label)
        return False, None
    if not isinstance(partition, str) or partition not in ALLOWED_BACKUP_IDS:
        errors.append("%s: unsupported mtd_image partition %r" % (label, partition))
        return False, None
    if partition in seen_partitions:
        errors.append("%s: duplicate partition %s" % (label, partition))
        return False, partition
    seen_partitions.add(partition)

    reference = REFERENCE_BY_ID[partition]
    if entry.get("name") != reference.name:
        errors.append("%s: name %r does not match reference %r for %s"
                      % (label, entry.get("name"), reference.name, partition))
        return False, partition
    if entry.get("expected_size") != reference.size:
        errors.append("%s: expected_size %r does not match reference %d for %s"
                      % (label, entry.get("expected_size"), reference.size, partition))
        return False, partition
    return True, partition


def _validate_v11_fields(entry: dict, label: str, errors: List[str]) -> bool:
    ok = True
    for key in ("bytes_received", "bytes_written"):
        value = entry.get(key)
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            errors.append("%s: schema 1.1 requires non-negative integer %s"
                          % (label, key))
            ok = False
    if not isinstance(entry.get("stderr_tail"), str):
        errors.append("%s: schema 1.1 requires string stderr_tail" % label)
        ok = False
    if not isinstance(entry.get("stderr_truncated"), bool):
        errors.append("%s: schema 1.1 requires boolean stderr_truncated" % label)
        ok = False
    if not isinstance(entry.get("counters_exact"), bool):
        errors.append("%s: schema 1.1 requires boolean counters_exact" % label)
        ok = False

    files = entry.get("files")
    if not isinstance(files, dict):
        errors.append("%s: schema 1.1 requires a files object" % label)
        return False
    for name in ("part", "final"):
        state = files.get(name)
        if not isinstance(state, dict):
            errors.append("%s: schema 1.1 requires files.%s object"
                          % (label, name))
            ok = False
            continue
        for key in ("exists", "size", "kind", "path"):
            if key not in state:
                errors.append("%s: schema 1.1 requires files.%s.%s"
                              % (label, name, key))
                ok = False
        if "exists" in state and not isinstance(state.get("exists"), bool):
            errors.append("%s: files.%s.exists must be boolean" % (label, name))
            ok = False
        if "size" in state:
            size = state.get("size")
            if size is not None and (not isinstance(size, int)
                                     or isinstance(size, bool) or size < 0):
                errors.append("%s: files.%s.size must be a non-negative "
                              "integer or null" % (label, name))
                ok = False
        if "kind" in state and state.get("kind") not in (
                None, "file", "dir", "symlink", "other"):
            errors.append("%s: files.%s.kind has unexpected value %r"
                          % (label, name, state.get("kind")))
            ok = False
        if "path" in state and not isinstance(state.get("path"), str):
            errors.append("%s: files.%s.path must be a string" % (label, name))
            ok = False

    final = files.get("final")
    if isinstance(final, dict):
        if not isinstance(final.get("sha256_verified"), bool):
            errors.append("%s: schema 1.1 requires boolean "
                          "files.final.sha256_verified" % label)
            ok = False
        created = final.get("created_by_this_attempt")
        if not (isinstance(created, bool) or created == "unknown"):
            errors.append(("%s: files.final.created_by_this_attempt must be "
                           'boolean or "unknown"') % label)
            ok = False
    if not isinstance(files.get("finalization_complete"), bool):
        errors.append("%s: schema 1.1 requires boolean "
                      "files.finalization_complete" % label)
        ok = False
    return ok


def verify_backup(root: Path) -> dict:
    """Verify a backup directory.  Local-only, read-only."""
    root = Path(root)
    if not root.exists():
        raise ValueError("backup directory does not exist: %s" % root)
    if not root.is_dir():
        raise ValueError("backup path is not a directory: %s" % root)

    report = new_verification_report(root)
    errors: List[str] = report["errors"]
    warnings: List[str] = report["warnings"]

    try:
        backup = _load_report(root)
    except ValueError as exc:
        errors.append(str(exc))
        _add_check(report, "report", False, str(exc))
        report["completed_at"] = utc_now()
        return report

    schema = backup.get("schema_version")
    report["backup_report_schema"] = schema
    legacy = schema in LEGACY_SCHEMA_VERSIONS
    if schema != SCHEMA_VERSION and not legacy:
        errors.append("unsupported backup report schema %r (expected %r or legacy %s)"
                      % (schema, SCHEMA_VERSION, ", ".join(LEGACY_SCHEMA_VERSIONS)))
        _add_check(report, "schema", False, "unsupported schema_version")
        report["completed_at"] = utc_now()
        return report
    if legacy:
        warnings.append(
            "legacy schema %s: limited verification; files/counter state is not "
            "required and final file state cannot be fully validated" % schema
        )
    _add_check(report, "schema", True,
               "schema_version %s%s" % (schema, " (legacy)" if legacy else ""))

    if backup.get("synthetic_example"):
        errors.append("this report is marked as a synthetic example and cannot be verified")
    if backup.get("status") != "completed":
        errors.append("backup report status is %r, not 'completed'"
                      % backup.get("status"))
    _add_check(report, "backup_status", backup.get("status") == "completed",
               "backup report status: %r" % backup.get("status"))

    consistency = backup.get("consistency") or {}
    if not isinstance(consistency, dict):
        errors.append("report consistency field must be an object")
        consistency = {}
    if consistency.get("hardware_validation_of_this_tool") is not False:
        errors.append(
            "report claims hardware validation of this tool; v0.1 never sets "
            "this field to true"
        )
    for key in FALSE_CLAIMS:
        if key == "hardware_validation_of_this_tool":
            continue
        if consistency.get(key) is True:
            warnings.append("report sets %s=true; review this claim manually" % key)

    artifacts = backup.get("artifacts")
    if not isinstance(artifacts, list) or not artifacts:
        errors.append("report contains no artifacts list")
        _add_check(report, "artifacts", False, "missing or empty artifacts list")
        report["completed_at"] = utc_now()
        return report
    _add_check(report, "artifacts", True, "%d artifact entries" % len(artifacts))

    completed: Dict[str, dict] = {}
    seen = set()
    seen_partitions = set()
    partitions_in_report = set()
    partitions_checked = set()
    for index, entry in enumerate(artifacts):
        if not isinstance(entry, dict):
            errors.append("artifact #%d is not an object" % index)
            continue
        label = "%s/%s" % (entry.get("partition") or "tar", entry.get("name") or "?")
        semantic_ok, partition = _validate_artifact_semantics(
            entry, label, errors, seen_partitions)
        if not semantic_ok:
            continue
        if partition is not None:
            partitions_in_report.add(partition)
        if not legacy and not _validate_v11_fields(entry, label, errors):
            continue
        status = entry.get("status")
        if status == "completed":
            relative = entry.get("path")
            if not isinstance(relative, str):
                errors.append("%s has no path" % label)
                continue
            if relative in seen:
                errors.append("duplicate artifact path: %s" % relative)
                continue
            seen.add(relative)
            try:
                target = resolve_inside(root, relative)
                ensure_regular_file(target, "artifact")
            except ValueError as exc:
                errors.append("%s: %s" % (label, exc))
                continue
            expected_size = entry.get("expected_size")
            try:
                actual_size = _stat_size(target)
            except OSError as exc:
                errors.append("%s: cannot stat file: %s" % (label, exc))
                continue
            if expected_size is not None and actual_size != expected_size:
                errors.append("%s size mismatch: expected %s, found %s"
                              % (label, expected_size, actual_size))
                continue
            if (partition is not None
                    and actual_size != REFERENCE_BY_ID[partition].size):
                errors.append("%s reference size mismatch: expected %d, found %d"
                              % (label, REFERENCE_BY_ID[partition].size, actual_size))
                continue
            reported_actual = entry.get("actual_size")
            reported_written = entry.get("bytes_written")
            if reported_actual is not None and reported_actual != actual_size:
                errors.append("%s actual_size mismatch: report says %r, file is %d"
                              % (label, reported_actual, actual_size))
                continue
            if reported_written is not None and reported_written != actual_size:
                errors.append("%s bytes_written mismatch: report says %r, file is %d"
                              % (label, reported_written, actual_size))
                continue
            received = entry.get("bytes_received")
            if received is not None and (not isinstance(received, int) or received < 0):
                errors.append("%s has an invalid bytes_received value" % label)
                continue
            if not legacy:
                if entry.get("counters_exact") is not True:
                    errors.append("%s is completed but counters_exact is not true"
                                  % label)
                    continue
                if received != actual_size:
                    errors.append("%s bytes_received mismatch: report says %r, "
                                  "file is %d" % (label, received, actual_size))
                    continue
                if reported_written != actual_size:
                    errors.append("%s bytes_written is not the actual file size"
                                  % label)
                    continue
            files = entry.get("files")
            if not legacy and files is not None:
                if not isinstance(files, dict):
                    errors.append("%s files field is not an object" % label)
                    continue
                part_state = files.get("part")
                final_state = files.get("final")
                part_exists, part_size, _ = _check_file_state(
                    root, part_state, "%s part" % label, errors, warnings)
                final_exists, final_size, _ = _check_file_state(
                    root, final_state, "%s final" % label, errors, warnings)
                if part_exists is not False:
                    errors.append("%s is completed but a .part file is reported"
                                  % label)
                    continue
                if final_exists is not True:
                    errors.append("%s is completed but its final file is missing"
                                  % label)
                    continue
                if not isinstance(final_state, dict):
                    errors.append("%s final state is not an object" % label)
                    continue
                if final_state.get("path") != relative:
                    errors.append("%s final path does not match artifact path" % label)
                    continue
                if final_state.get("created_by_this_attempt") is not True:
                    errors.append("%s final is not reported as created by this attempt"
                                  % label)
                    continue
                if final_state.get("sha256_verified") is not True:
                    errors.append("%s final is not reported as SHA-256 verified"
                                  % label)
                    continue
                if files.get("finalization_complete") is not True:
                    errors.append("%s finalization is not reported complete" % label)
                    continue
                if final_size != actual_size:
                    errors.append("%s final size mismatch: state says %r, file is %d"
                                  % (label, final_size, actual_size))
                    continue
            digest = entry.get("sha256")
            if not isinstance(digest, str) or not _SHA_RE.match(digest):
                errors.append("%s has an invalid sha256 value" % label)
                continue
            try:
                actual_digest = stream_sha256(target)
            except OSError as exc:
                errors.append("%s: cannot compute SHA-256: %s" % (label, exc))
                continue
            if actual_digest != digest:
                errors.append("%s SHA-256 mismatch" % label)
                continue
            report["artifacts_checked"] += 1
            report["bytes_checked"] += actual_size
            if partition is not None:
                partitions_checked.add(partition)
            completed[relative] = entry
            if entry.get("kind") == "tar":
                try:
                    info = inspect_tar(target)
                    _add_check(report, "tar:%s" % relative, True,
                               "%d members inspected, no extraction" % info["members"])
                    entry["tar_inspection"] = info
                    report.setdefault("tar_checked", []).append(relative)
                except (ValueError, OSError) as exc:
                    errors.append("%s: cannot inspect tar: %s" % (label, exc))
        elif status == "skipped":
            if backup.get("status") == "completed":
                errors.append("%s is skipped in a report marked completed" % label)
            else:
                warnings.append("%s was skipped: %s"
                                % (label, entry.get("error") or "no reason recorded"))
            if not legacy:
                files = entry.get("files")
                if isinstance(files, dict):
                    part_state = files.get("part") or {}
                    final_state = files.get("final") or {}
                    if part_state.get("exists") is not False or final_state.get("exists") is not False:
                        errors.append("%s is skipped but files state reports an "
                                      "existing file" % label)
                    if files.get("finalization_complete") is not False:
                        errors.append("%s is skipped but finalization is reported "
                                      "complete" % label)
        elif status == "failed":
            files = entry.get("files")
            if legacy or files is None:
                part = entry.get("part_path")
                if isinstance(part, str):
                    try:
                        part_path = resolve_inside(root, part)
                    except ValueError as exc:
                        errors.append("%s: invalid part path: %s" % (label, exc))
                    else:
                        if part_path.exists():
                            try:
                                part_size = _stat_size(part_path)
                            except OSError as exc:
                                errors.append("%s: cannot stat partial file: %s"
                                              % (label, exc))
                                part_size = None
                            if part_size is None:
                                errors.append("%s is marked as failed in the backup "
                                              "report" % label)
                                continue
                            reported_actual = entry.get("actual_size")
                            reported_written = entry.get("bytes_written")
                            if (reported_actual is not None
                                    and reported_actual != part_size):
                                errors.append(
                                    "%s actual_size mismatch for partial file: "
                                    "report says %r, file is %d"
                                    % (label, reported_actual, part_size))
                            if (reported_written is not None
                                    and reported_written != part_size):
                                errors.append(
                                    "%s bytes_written mismatch for partial file: "
                                    "report says %r, file is %d"
                                    % (label, reported_written, part_size))
                            warnings.append("%s has a kept partial file: %s"
                                            % (label, part))
                        else:
                            warnings.append("%s failed and its partial file is absent"
                                            % label)
            elif not isinstance(files, dict):
                errors.append("%s files field is not an object" % label)
            else:
                part_state = files.get("part")
                final_state = files.get("final")
                part_exists, part_size, _ = _check_file_state(
                    root, part_state, "%s part" % label, errors, warnings)
                final_exists, final_size, final_target = _check_file_state(
                    root, final_state, "%s final" % label, errors, warnings)
                if files.get("finalization_complete") is True:
                    errors.append("%s is failed but finalization is reported complete"
                                  % label)
                if part_exists is True:
                    reported_actual = entry.get("actual_size")
                    reported_written = entry.get("bytes_written")
                    if (reported_actual is not None
                            and reported_actual != part_size):
                        errors.append(
                            "%s actual_size mismatch for partial file: "
                            "report says %r, file is %d"
                            % (label, reported_actual, part_size))
                    if (reported_written is not None
                            and reported_written != part_size):
                        errors.append(
                            "%s bytes_written mismatch for partial file: "
                            "report says %r, file is %d"
                            % (label, reported_written, part_size))
                    if isinstance(part_state, dict) and part_state.get("path"):
                        warnings.append("%s has a kept partial file: %s"
                                        % (label, part_state["path"]))
                elif part_exists is False:
                    warnings.append("%s failed and its partial file is absent"
                                    % label)
                if final_exists is True:
                    if isinstance(final_state, dict) and final_state.get("sha256_verified") is True:
                        digest = entry.get("sha256")
                        if not isinstance(digest, str) or not _SHA_RE.match(digest):
                            errors.append("%s claims a verified final without sha256"
                                          % label)
                        elif final_target is not None:
                            try:
                                final_digest = stream_sha256(final_target)
                            except OSError as exc:
                                errors.append("%s: cannot compute final SHA-256: %s"
                                              % (label, exc))
                            else:
                                if final_digest != digest:
                                    errors.append("%s final SHA-256 mismatch" % label)
                    else:
                        warnings.append("%s final exists but is not reported as verified"
                                        % label)
                    if part_exists is not True and entry.get("actual_size") is not None:
                        if entry.get("actual_size") != final_size:
                            errors.append(
                                "%s actual_size mismatch for final-only artifact: "
                                "report says %r, file is %d"
                                % (label, entry.get("actual_size"), final_size))
                elif final_exists is False:
                    warnings.append("%s failed and no final file exists" % label)
                if part_exists is False and final_exists is False:
                    warnings.append("%s failure left no file on disk" % label)
                if entry.get("counters_exact") is False:
                    warnings.append("%s byte counters are not exact after the "
                                    "orchestration error" % label)
            errors.append("%s is marked as failed in the backup report" % label)
        else:
            errors.append("%s has unknown status %r" % (label, status))

    report["partitions_in_report"] = sorted(partitions_in_report)
    report["partitions_checked"] = sorted(partitions_checked)

    checksums_path = root / "checksums.sha256"
    checksum_entries: Dict[str, str] = {}
    if checksums_path.exists():
        try:
            ensure_regular_file(checksums_path, "checksums.sha256")
            with checksums_path.open("r", encoding="utf-8") as handle:
                for lineno, raw in enumerate(handle, 1):
                    line = raw.rstrip("\n")
                    if not line:
                        continue
                    match = _CHECKSUM_RE.match(line)
                    if not match:
                        raise ValueError("malformed checksum line %d" % lineno)
                    digest = match.group(1).lower()
                    relative = match.group(2)
                    if relative in ("checksums.sha256", "report.json"):
                        raise ValueError("checksum file references itself or the report")
                    safe_relative_path(relative)
                    if relative in checksum_entries:
                        raise ValueError("duplicate checksum entry: %s" % relative)
                    checksum_entries[relative] = digest
            _add_check(report, "checksums", True,
                       "%d checksum entries" % len(checksum_entries))
        except (OSError, ValueError) as exc:
            errors.append("checksums.sha256: %s" % exc)
            _add_check(report, "checksums", False, str(exc))
    else:
        if completed:
            errors.append("checksums.sha256 is missing while completed artifacts exist")
        _add_check(report, "checksums", False, "checksums.sha256 is missing")

    for relative, digest in checksum_entries.items():
        if relative not in completed:
            errors.append("checksum entry is not a completed artifact: %s" % relative)
            continue
        try:
            target = resolve_inside(root, relative)
            ensure_regular_file(target, "checksum target")
        except ValueError as exc:
            errors.append("checksum entry %s: %s" % (relative, exc))
            continue
        try:
            actual_digest = stream_sha256(target)
        except OSError as exc:
            errors.append("cannot compute SHA-256 for %s: %s" % (relative, exc))
            continue
        if actual_digest != digest:
            errors.append("checksum mismatch for %s" % relative)
    missing = sorted(set(completed) - set(checksum_entries))
    for relative in missing:
        errors.append("completed artifact is not listed in checksums.sha256: %s" % relative)

    partials: List[str] = []
    for dirpath, dirnames, filenames in os.walk(str(root), followlinks=False):
        dirnames[:] = [d for d in dirnames if not os.path.islink(os.path.join(dirpath, d))]
        for filename in filenames:
            if filename.endswith(".part"):
                partials.append(os.path.relpath(os.path.join(dirpath, filename), str(root)))
    if partials:
        errors.append("partial files are present: %s" % ", ".join(sorted(partials)))

    _add_check(report, "no_partial_files", not partials,
               "no .part files" if not partials else "%d .part files" % len(partials))
    _add_check(report, "restore_not_claimed", True,
               "verification does not test or claim a restore")

    report["status"] = "ok" if not errors else "failed"
    report["completed_at"] = utc_now()
    return report


def verification_json(report: dict) -> str:
    return json.dumps(report, indent=2, ensure_ascii=False) + "\n"


def summarize_verification(report: dict) -> str:
    lines = [
        "Backup verification: %s" % report["status"].upper(),
        "Artifacts checked: %d" % report["artifacts_checked"],
        "Bytes checked: %s" % human_bytes(report["bytes_checked"]),
        "Partitions checked: %s" % (", ".join(report.get("partitions_checked", []))
                                     or "none"),
        "Partitions present in report: %s"
        % (", ".join(report.get("partitions_in_report", [])) or "none"),
        "Tar archives checked: %s"
        % (", ".join(report.get("tar_checked", [])) or "none"),
    ]
    for entry in report.get("checks", []):
        lines.append("  [%s] %s: %s" % (entry["status"], entry["id"], entry["detail"]))
    for warning in report.get("warnings", []):
        lines.append("  WARNING: %s" % warning)
    for error in report.get("errors", []):
        lines.append("  ERROR: %s" % error)
    lines.append("Restore tested: no. Integrity of local bytes does not prove "
                 "a successful restore.")
    return "\n".join(lines)
