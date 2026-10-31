# AI-generated code. Review before use. See AI_DISCLOSURE.md.
"""Backup orchestration: read-only MTD streams and a /bkupgrade tar.

Nothing in this module writes to the device.  It does not stop Quasar, does
not detach UBI, does not run ``sync``, and does not retry failed reads.
"""

from __future__ import annotations

import os
import shutil
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, List, Optional, Tuple

from .check import CommandRunner, run_check
from .errors import GateError, UsageError
from .profile import (
    ALLOWED_BACKUP_IDS,
    REFERENCE_BY_ID,
    validate_backup_ids,
)
from .report import checksum_text, finish_report, new_report, write_report, write_text_exclusive
from .ssh import LocalPreflight, SshTarget, build_ssh_argv, require_preflight, validate_target
from .transfer import (
    TransferInterrupted,
    TransferResult,
    snapshot_files,
    stream_to_part_file,
)
from .util import fsync_dir, human_bytes, utc_now

MIB = 1024 * 1024
IMAGE_HEADROOM = 64 * MIB
TAR_HEADROOM = 64 * MIB


@dataclass
class BackupOptions:
    output_root: Path = Path("backups")
    partitions: List[str] = field(default_factory=lambda: list(ALLOWED_BACKUP_IDS))
    assume_yes: bool = False
    dry_run: bool = False
    firmware_version: Optional[str] = None


@dataclass
class BackupOutcome:
    report: dict
    exit_code: int
    output_dir: Optional[Path]


class _Logger:
    """Best-effort file logger.  Logging failures never escape this class."""

    def __init__(self, path: Optional[Path]):
        self._handle = None
        self.error: Optional[str] = None
        if path is None:
            return
        fd = None
        try:
            fd = os.open(str(path), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            self._handle = os.fdopen(fd, "w", encoding="utf-8")
            fd = None
        except OSError as exc:
            if fd is not None:
                try:
                    os.close(fd)
                except OSError:
                    pass
            self.error = "could not open backup.log: %s" % exc

    def _disable(self) -> None:
        handle = self._handle
        self._handle = None
        if handle is not None:
            try:
                handle.close()
            except OSError as exc:
                if self.error is None:
                    self.error = "could not close backup.log: %s" % exc

    def _mark_error(self, message: str) -> None:
        if self.error is None:
            self.error = message
        self._disable()

    def log(self, message: str) -> None:
        if self._handle is None:
            return
        line = "%s %s\n" % (utc_now(), message)
        try:
            self._handle.write(line)
            self._handle.flush()
            os.fsync(self._handle.fileno())
        except (OSError, ValueError) as exc:
            self._mark_error("log write/flush/fsync failed: %s" % exc)

    def close(self) -> None:
        self._disable()


class _SafeLog:
    """Defensive wrapper so even a buggy logger cannot block reporting."""

    def __init__(self, inner):
        self._inner = inner
        self._error: Optional[str] = getattr(inner, "error", None)

    @property
    def error(self) -> Optional[str]:
        return self._error or getattr(self._inner, "error", None)

    def log(self, message: str) -> None:
        try:
            self._inner.log(message)
        except Exception as exc:
            if self._error is None:
                self._error = "logging failed: %s" % exc

    def close(self) -> None:
        try:
            self._inner.close()
        except Exception as exc:
            if self._error is None:
                self._error = "log close failed: %s" % exc


def _default_confirm(prompt: str) -> bool:
    print(prompt, end="", file=sys.stderr, flush=True)
    try:
        answer = input()
    except EOFError:
        return False
    return answer.strip().lower() == "yes"


def _default_printer(message: str) -> None:
    print(message)


def _artifact_path(partition_id: str) -> str:
    part = REFERENCE_BY_ID[partition_id]
    return "images/%s.%s.bin" % (part.id, part.name)


def _planned_entries(partition_ids: List[str]) -> List[dict]:
    entries = []
    for partition_id in partition_ids:
        part = REFERENCE_BY_ID[partition_id]
        entries.append({
            "partition": part.id,
            "name": part.name,
            "kind": "mtd_image",
            "expected_size": part.size,
            "path": _artifact_path(part.id),
            "command": "nanddump --bb=padbad --omitoob /dev/%s" % part.id,
        })
    entries.append({
        "partition": None,
        "name": "bkupgrade",
        "kind": "tar",
        "expected_size": None,
        "path": "bkupgrade.tar",
        "command": "tar -cf - -C /bkupgrade .",
        "note": "size is not known in advance; the archive may contain secrets",
    })
    return entries


def _print_plan(outcome_printer: Callable[[str], None], options: BackupOptions) -> None:
    entries = _planned_entries(options.partitions)
    total = sum(e["expected_size"] or 0 for e in entries)
    outcome_printer("")
    outcome_printer("Planned read-only artifacts:")
    for entry in entries:
        size = human_bytes(entry["expected_size"]) if entry["expected_size"] else "unknown"
        outcome_printer("  %-8s %-10s %10s  %s"
                        % (entry["partition"] or "tar", entry["name"], size, entry["path"]))
    outcome_printer("  total image bytes: %s" % human_bytes(total))
    outcome_printer("Output root: %s" % options.output_root)
    outcome_printer("")
    outcome_printer("This does NOT produce a physical NAND dump, does not capture OOB,")
    outcome_printer("does not read mtd0, does not stop UBI/Quasar and is not recovery-ready.")
    outcome_printer("")


def run_backup(
    target: SshTarget,
    options: BackupOptions,
    *,
    check_runner: Optional[CommandRunner] = None,
    popen_factory=None,
    confirm: Optional[Callable[[str], bool]] = None,
    printer: Optional[Callable[[str], None]] = None,
    preflight: Optional[LocalPreflight] = None,
    started_at: Optional[str] = None,
    logger_factory: Optional[Callable[[Path], object]] = None,
) -> BackupOutcome:
    printer = printer or _default_printer
    confirm = confirm or _default_confirm

    validate_target(target)
    try:
        partition_ids = validate_backup_ids(options.partitions)
    except ValueError as exc:
        raise UsageError(str(exc))

    if options.dry_run:
        report = new_report("dry_run")
        if started_at:
            report["started_at"] = started_at
        report["dry_run"] = True
        report["preflight_executed"] = False
        report["host"] = {
            "hostname": target.host,
            "port": target.port,
            "user": target.user,
            "identity_file_basename": target.normalized_identity().name,
        }
        report["planned_artifacts"] = _planned_entries(partition_ids)
        report["planned_total_image_bytes"] = sum(
            e["expected_size"] or 0 for e in report["planned_artifacts"]
            if e["kind"] == "mtd_image"
        )
        report["warnings"].append(
            "Dry run performs no SSH connection and no device reads."
        )
        report["warnings"].append(
            "A real backup must pass the remote MTD profile gate before reading."
        )
        finish_report(report, "dry_run")
        _print_plan(printer, options)
        return BackupOutcome(report=report, exit_code=0, output_dir=None)

    if preflight is None:
        preflight = require_preflight(target)
    elif not preflight.ok:
        raise GateError("local preflight failed")

    _print_plan(printer, options)
    if not options.assume_yes:
        if not confirm("Type 'yes' to start the read-only backup: "):
            raise UsageError("backup cancelled by user")

    try:
        options.output_root.mkdir(parents=True, exist_ok=True)
        if not options.output_root.is_dir():
            raise UsageError("output root is not a directory: %s" % options.output_root)
        prefix = "backup-%s-" % time.strftime("%Y%m%d-%H%M%S")
        output_dir = Path(tempfile.mkdtemp(prefix=prefix, dir=str(options.output_root)))
        images_dir = output_dir / "images"
        os.mkdir(str(images_dir), 0o700)
    except OSError as exc:
        raise UsageError("could not create output directory: %s" % exc) from exc

    factory = logger_factory or _Logger
    try:
        inner_log = factory(output_dir / "backup.log")
    except Exception as exc:
        inner_log = _Logger(None)
        inner_log.error = "could not initialise backup.log: %s" % exc
    log = _SafeLog(inner_log)
    try:
        try:
            return _run_backup_with_output(
                target, options, partition_ids, output_dir, images_dir, log,
                check_runner, popen_factory, printer, preflight, started_at,
            )
        except OSError as exc:
            _emit(printer, "ERROR: orchestration failed while saving diagnostics: %s"
                  % exc)
            fallback = new_report("failed")
            fallback["output_dir"] = str(output_dir)
            fallback["errors"].append(
                "orchestration failed while saving diagnostics: %s" % exc)
            finish_report(fallback, "failed")
            return BackupOutcome(report=fallback, exit_code=1,
                                 output_dir=output_dir)
    finally:
        log.close()


def _run_backup_with_output(
    target: SshTarget,
    options: BackupOptions,
    partition_ids: List[str],
    output_dir: Path,
    images_dir: Path,
    log,
    check_runner,
    popen_factory,
    printer: Callable[[str], None],
    preflight,
    started_at,
) -> BackupOutcome:
    ctx = {"report": None}
    try:
        return _run_backup_body(
            target, options, partition_ids, output_dir, images_dir, log,
            check_runner, popen_factory, printer, preflight, started_at, ctx,
        )
    except OSError as exc:
        return _handle_orchestration_oserror(
            exc, ctx, partition_ids, output_dir, images_dir, printer, log,
        )


def _run_backup_body(
    target: SshTarget,
    options: BackupOptions,
    partition_ids: List[str],
    output_dir: Path,
    images_dir: Path,
    log,
    check_runner,
    popen_factory,
    printer: Callable[[str], None],
    preflight,
    started_at,
    ctx: dict,
) -> BackupOutcome:
    report = new_report("failed")
    ctx["report"] = report
    if started_at:
        report["started_at"] = started_at
    report["dry_run"] = False
    report["preflight_executed"] = True
    report["output_dir"] = str(output_dir)
    report["host"] = {
        "hostname": target.host,
        "port": target.port,
        "user": target.user,
        "identity_file_basename": target.normalized_identity().name,
        "host_key_verification": "strict",
    }
    report["capture"] = {
        "method": "logical_mtd_stream",
        "transport": "ssh without PTY, stdout binary stream, stderr separated",
        "nanddump_options": ["--bb=padbad", "--omitoob"],
        "ecc": "driver_default",
        "oob": "omitted",
        "bad_blocks": "replaced by 0xFF by nanddump with stream length preserved",
        "quasar_stopped": False,
        "ubi_detached": False,
        "sync_claimed_consistent": False,
        "automatic_retry": False,
    }
    report["warnings"].append(
        "The /bkupgrade tar may contain credentials, tokens, keys or personal data. "
        "Do not publish it."
    )
    report["warnings"].append(
        "Hardware validation of this tool has not been performed; successful "
        "tests are not hardware validation."
    )

    log.log("backup started for %s" % target.display_host())
    exit_code = 0

    selected_total = sum(REFERENCE_BY_ID[p].size for p in partition_ids)
    required_free = selected_total + REFERENCE_BY_ID["mtd5"].size + TAR_HEADROOM
    free_now = shutil.disk_usage(str(images_dir)).free
    if free_now < required_free:
        report["errors"].append(
            "not enough free space for the planned backup: need about %s, have %s"
            % (human_bytes(required_free), human_bytes(free_now))
        )
        _skip_all(report, partition_ids, "not attempted because of insufficient free space")
        finish_report(report, "failed")
        _write_report_and_checksums(output_dir, report, printer, log)
        return BackupOutcome(report=report, exit_code=1, output_dir=output_dir)

    try:
        try:
            check_report = run_check(
                target, options.firmware_version,
                runner=check_runner, preflight=preflight,
            )
        except GateError as exc:
            report["errors"].append("preflight: %s" % exc)
            _skip_all(report, partition_ids, "not attempted because the preflight failed")
            finish_report(report, "failed")
            _write_report_and_checksums(output_dir, report, printer, log)
            raise

        report["device"] = check_report.get("device", {})
        report["layout"] = check_report.get("layout", {})
        report["preflight"] = check_report.get("preflight", {})
        report["checks"] = check_report.get("checks", [])
        report["warnings"].extend(check_report.get("warnings", []))
        report["errors"].extend(check_report.get("errors", []))

        if check_report.get("status") != "ok":
            report["errors"].append(
                "remote MTD profile/utility gate failed; no partition was read"
            )
            _skip_all(report, partition_ids, "not attempted because the preflight gate failed")
            finish_report(report, "failed")
            _write_report_and_checksums(output_dir, report, printer, log)
            return BackupOutcome(report=report, exit_code=2, output_dir=output_dir)

        tar_attempted = False
        for position, partition_id in enumerate(partition_ids):
            part = REFERENCE_BY_ID[partition_id]
            expected = part.size
            free = shutil.disk_usage(str(images_dir)).free
            if free < expected + IMAGE_HEADROOM:
                report["errors"].append(
                    "not enough free space for %s: need %s + headroom, have %s"
                    % (partition_id, human_bytes(expected), human_bytes(free))
                )
                _append_failed(report, partition_id, part.name, "mtd_image",
                               _artifact_path(partition_id), expected, 0, None,
                               "insufficient free space")
                for remaining in partition_ids[position + 1:]:
                    _append_skipped(report, remaining, REFERENCE_BY_ID[remaining].name,
                                    "mtd_image", _artifact_path(remaining),
                                    "not attempted after an earlier failure")
                _append_skipped(report, None, "bkupgrade", "tar", "bkupgrade.tar",
                                "not attempted after an earlier failure")
                exit_code = 1
                break

            part_path = images_dir / ("%s.%s.bin.part" % (part.id, part.name))
            final_path = images_dir / ("%s.%s.bin" % (part.id, part.name))
            command = "nanddump --bb=padbad --omitoob /dev/%s" % part.id
            log.log("reading %s (%s) via %s" % (part.id, human_bytes(expected), command))
            printer("[%s] reading %s ..." % (part.id, human_bytes(expected)))
            started = utc_now()
            try:
                result = stream_to_part_file(
                    build_ssh_argv(target, command), part_path, final_path,
                    expected, popen_factory=popen_factory,
                )
            except TransferInterrupted as exc:
                _append_failed(report, partition_id, part.name, "mtd_image",
                               _artifact_path(partition_id), expected,
                               exc.bytes_written, None,
                               "interrupted by user; inspect files state",
                               bytes_received=exc.bytes_received,
                               files=exc.files)
                for remaining in partition_ids[position + 1:]:
                    _append_skipped(report, remaining, REFERENCE_BY_ID[remaining].name,
                                    "mtd_image", _artifact_path(remaining),
                                    "not attempted after interruption")
                _append_skipped(report, None, "bkupgrade", "tar", "bkupgrade.tar",
                                "not attempted after interruption")
                raise
            _record_result(report, partition_id, part.name, "mtd_image",
                           _artifact_path(partition_id),
                           _artifact_path(partition_id) + ".part",
                           expected, result, started, command)
            log.log("%s: %s, %d received, %d written, sha256=%s, error=%s"
                    % (partition_id, result.status, result.bytes_received,
                       result.bytes_written, result.sha256 or "none",
                       result.error or "none"))
            if result.ok:
                printer("[%s] completed %s sha256=%s"
                        % (partition_id, human_bytes(result.bytes_written), result.sha256))
            else:
                printer("[%s] FAILED: %s" % (partition_id, result.error))
                report["errors"].append("%s: %s" % (partition_id, result.error))
                for remaining in partition_ids[position + 1:]:
                    _append_skipped(report, remaining, REFERENCE_BY_ID[remaining].name,
                                    "mtd_image", _artifact_path(remaining),
                                    "not attempted after an earlier failure")
                _append_skipped(report, None, "bkupgrade", "tar", "bkupgrade.tar",
                                "not attempted after an earlier failure")
                exit_code = 1
                break

        if exit_code != 0 and not tar_attempted:
            already = any(a.get("kind") == "tar" for a in report["artifacts"])
            if not already:
                _append_skipped(report, None, "bkupgrade", "tar", "bkupgrade.tar",
                                "not attempted because an earlier artifact failed")

        if exit_code == 0:
            free = shutil.disk_usage(str(output_dir)).free
            estimate = REFERENCE_BY_ID["mtd5"].size + TAR_HEADROOM
            if free < estimate:
                report["errors"].append(
                    "not enough free space for the /bkupgrade tar estimate: "
                    "need about %s, have %s" % (human_bytes(estimate), human_bytes(free))
                )
                _append_failed(report, None, "bkupgrade", "tar", "bkupgrade.tar",
                               None, 0, None, "insufficient free space")
                exit_code = 1
            else:
                tar_attempted = True
                part_path = output_dir / "bkupgrade.tar.part"
                final_path = output_dir / "bkupgrade.tar"
                command = "tar -cf - -C /bkupgrade ."
                log.log("creating /bkupgrade tar via %s" % command)
                printer("[tar] streaming /bkupgrade ...")
                started = utc_now()
                try:
                    result = stream_to_part_file(
                        build_ssh_argv(target, command), part_path, final_path,
                        None, popen_factory=popen_factory, min_size=1,
                    )
                except TransferInterrupted as exc:
                    _append_failed(report, None, "bkupgrade", "tar",
                                   "bkupgrade.tar", None, exc.bytes_written, None,
                                   "interrupted by user; inspect files state",
                                   bytes_received=exc.bytes_received,
                                   files=exc.files)
                    raise
                _record_result(report, None, "bkupgrade", "tar", "bkupgrade.tar",
                               "bkupgrade.tar.part", None, result, started, command)
                log.log("tar: %s, %d received, %d written, sha256=%s, error=%s"
                        % (result.status, result.bytes_received,
                           result.bytes_written, result.sha256 or "none",
                           result.error or "none"))
                if result.ok:
                    printer("[tar] completed %s sha256=%s"
                            % (human_bytes(result.bytes_written), result.sha256))
                else:
                    printer("[tar] FAILED: %s" % result.error)
                    report["errors"].append("tar: %s" % result.error)
                    exit_code = 1

    except KeyboardInterrupt:
        report["errors"].append("interrupted by user; inspect files state")
        log.log("interrupted by user")
        exit_code = 130
        finish_report(report, "failed")
        _write_report_and_checksums(output_dir, report, printer, log)
        raise

    status = "completed" if exit_code == 0 and not report["errors"] else "failed"
    finish_report(report, status)
    report_written, checksums_ok = _write_report_and_checksums(
        output_dir, report, printer, log)
    if not report_written:
        report["status"] = "failed"
        exit_code = 1
        _emit(printer, "ERROR: the failed report could not be saved; "
                       "inspect the directory manually.")
    elif not checksums_ok:
        report["status"] = "failed"
        exit_code = 1
    return BackupOutcome(report=report, exit_code=exit_code, output_dir=output_dir)


def _default_files(part_relative: str, final_relative: str) -> dict:
    return {
        "part": {"exists": False, "size": None, "kind": None,
                 "path": part_relative},
        "final": {"exists": False, "size": None, "kind": None,
                  "path": final_relative, "sha256_verified": False,
                  "created_by_this_attempt": False},
        "finalization_complete": False,
    }


def _files_with_paths(files, part_relative: str, final_relative: str) -> dict:
    files = files if isinstance(files, dict) else {}
    part = dict(files.get("part") or {})
    final = dict(files.get("final") or {})
    part["path"] = part_relative
    final["path"] = final_relative
    return {
        "part": part,
        "final": final,
        "finalization_complete": bool(files.get("finalization_complete", False)),
    }


def _emit(printer: Callable[[str], None], message: str) -> None:
    try:
        printer(message)
    except OSError:
        pass


def _handle_orchestration_oserror(exc: OSError, ctx: dict, partition_ids: List[str],
                                  output_dir: Path, images_dir: Path,
                                  printer: Callable[[str], None], log) -> BackupOutcome:
    report = ctx.get("report")
    if not isinstance(report, dict):
        report = new_report("failed")
        report["output_dir"] = str(output_dir)
    report["errors"].append("orchestration OSError: %s" % exc)
    present = {a.get("partition") for a in report.get("artifacts", [])
               if isinstance(a, dict)}

    for partition_id in partition_ids:
        if partition_id in present:
            continue
        part = REFERENCE_BY_ID[partition_id]
        part_path = images_dir / ("%s.%s.bin.part" % (part.id, part.name))
        final_path = images_dir / ("%s.%s.bin" % (part.id, part.name))
        files = snapshot_files(part_path, final_path,
                               final_created_by_attempt="unknown")
        part_exists = files["part"].get("exists") is True
        final_exists = files["final"].get("exists") is True
        size = (files["part"].get("size") if part_exists
                else files["final"].get("size") if final_exists else 0) or 0
        if part_exists or final_exists:
            _append_failed(
                report, partition_id, part.name, "mtd_image",
                _artifact_path(partition_id), part.size, size, None,
                "orchestration error before completion: %s" % exc,
                bytes_received=size, files=files, counters_exact=False,
            )
        else:
            _append_skipped(report, partition_id, part.name, "mtd_image",
                            _artifact_path(partition_id),
                            "not started before the orchestration error")

    if not any(isinstance(a, dict) and a.get("kind") == "tar"
               for a in report.get("artifacts", [])):
        part_path = output_dir / "bkupgrade.tar.part"
        final_path = output_dir / "bkupgrade.tar"
        files = snapshot_files(part_path, final_path,
                               final_created_by_attempt="unknown")
        part_exists = files["part"].get("exists") is True
        final_exists = files["final"].get("exists") is True
        size = (files["part"].get("size") if part_exists
                else files["final"].get("size") if final_exists else 0) or 0
        if part_exists or final_exists:
            _append_failed(
                report, None, "bkupgrade", "tar", "bkupgrade.tar",
                None, size, None,
                "orchestration error before completion: %s" % exc,
                bytes_received=size, files=files, counters_exact=False,
            )
        else:
            _append_skipped(report, None, "bkupgrade", "tar", "bkupgrade.tar",
                            "not started before the orchestration error")

    finish_report(report, "failed")
    try:
        report_written, _checksum_ok = _write_report_and_checksums(
            output_dir, report, printer, log)
    except OSError as report_exc:
        report_written = False
        _emit(printer, "ERROR: could not save failed report: %s" % report_exc)
    if not report_written:
        _emit(printer, "ERROR: the failed report could not be saved; "
                       "inspect the directory manually.")
    return BackupOutcome(report=report, exit_code=1, output_dir=output_dir)


def _append_failed(report: dict, partition_id: Optional[str], name: str, kind: str,
                   relative: str, expected: Optional[int], actual: int,
                   exit_code: Optional[int], error: str,
                   *, bytes_received: int = 0,
                   stderr_truncated: bool = False,
                   files: Optional[dict] = None,
                   counters_exact: bool = True) -> None:
    part_relative = relative + ".part"
    files = _files_with_paths(
        files if files is not None else _default_files(part_relative, relative),
        part_relative, relative,
    )
    report["artifacts"].append({
        "partition": partition_id,
        "name": name,
        "kind": kind,
        "path": None,
        "part_path": part_relative if files["part"].get("exists") is True else None,
        "status": "failed",
        "expected_size": expected,
        "actual_size": actual,
        "bytes_received": bytes_received,
        "bytes_written": actual,
        "sha256": None,
        "exit_code": exit_code,
        "error": error,
        "stderr_tail": "",
        "stderr_truncated": stderr_truncated,
        "counters_exact": counters_exact,
        "files": files,
        "started_at": utc_now(),
        "completed_at": utc_now(),
    })


def _append_skipped(report: dict, partition_id: Optional[str], name: str,
                    kind: str, relative: str, reason: str) -> None:
    report["artifacts"].append({
        "partition": partition_id,
        "name": name,
        "kind": kind,
        "path": None,
        "part_path": None,
        "status": "skipped",
        "expected_size": REFERENCE_BY_ID[partition_id].size if partition_id else None,
        "actual_size": 0,
        "bytes_received": 0,
        "bytes_written": 0,
        "sha256": None,
        "exit_code": None,
        "error": reason,
        "stderr_tail": "",
        "stderr_truncated": False,
        "counters_exact": True,
        "files": _default_files(relative + ".part", relative),
        "started_at": None,
        "completed_at": None,
    })


def _skip_all(report: dict, partition_ids: List[str], reason: str) -> None:
    for partition_id in partition_ids:
        _append_skipped(report, partition_id, REFERENCE_BY_ID[partition_id].name,
                        "mtd_image", _artifact_path(partition_id), reason)
    _append_skipped(report, None, "bkupgrade", "tar", "bkupgrade.tar", reason)


def _record_result(report: dict, partition_id: Optional[str], name: str, kind: str,
                   relative: str, part_relative: str, expected: Optional[int],
                   result: TransferResult, started_at: str, command: str) -> None:
    files = _files_with_paths(result.files, part_relative, relative)
    report["artifacts"].append({
        "partition": partition_id,
        "name": name,
        "kind": kind,
        "command": command,
        "path": relative if result.ok else None,
        "part_path": part_relative if files["part"].get("exists") is True else None,
        "status": "completed" if result.ok else "failed",
        "expected_size": expected,
        "actual_size": result.bytes_written,
        "bytes_received": result.bytes_received,
        "bytes_written": result.bytes_written,
        "sha256": result.sha256,
        "exit_code": result.exit_code,
        "error": result.error,
        "stderr_tail": result.stderr_tail,
        "stderr_truncated": result.stderr_truncated,
        "counters_exact": True,
        "files": files,
        "started_at": started_at,
        "completed_at": utc_now(),
    })


def _write_report_and_checksums(output_dir: Path, report: dict,
                                printer: Callable[[str], None],
                                log) -> Tuple[bool, bool]:
    log_error = getattr(log, "error", None)
    if log_error:
        warning = "logging unavailable: %s" % log_error
        if warning not in report["warnings"]:
            report["warnings"].append(warning)

    report_path = output_dir / "report.json"
    text = checksum_text(report.get("artifacts", []))
    checksum_ok = True
    if text:
        try:
            write_text_exclusive(output_dir / "checksums.sha256", text)
        except OSError as exc:
            checksum_ok = False
            report["errors"].append("could not write checksums.sha256: %s" % exc)
            report["status"] = "failed"
            log.log("could not write checksums: %s" % exc)
            _emit(printer, "ERROR: could not write checksums: %s" % exc)
    try:
        write_report(report_path, report)
    except OSError as exc:
        log.log("could not write report: %s" % exc)
        _emit(printer, "ERROR: could not write report: %s" % exc)
        return False, checksum_ok
    fsync_dir(output_dir)
    log.log("report written: %s" % report_path)
    _emit(printer, "Report: %s" % report_path)
    return True, checksum_ok
