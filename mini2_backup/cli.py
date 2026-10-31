# AI-generated code. Review before use. See AI_DISCLOSURE.md.
"""Command-line interface.

Subcommands: check, backup, verify, copy-external.

Only ``check`` and ``backup`` can open an SSH connection.  ``verify`` and
``copy-external`` are strictly local.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import List, Optional

from . import AI_NOTICE, TOOL_NAME, __version__
from .backup import BackupOptions, run_backup
from .check import run_check
from .copy_external import copy_external
from .errors import ToolError, UsageError, VerifyError
from .ssh import DEFAULT_PORT, DEFAULT_USER, SshTarget
from .verify import summarize_verification, verification_json, verify_backup


def _add_ssh_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--host", required=True,
                        help="device hostname or IP address (no shell syntax)")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT,
                        help="SSH port (default: %d)" % DEFAULT_PORT)
    parser.add_argument("--user", default=DEFAULT_USER,
                        help="SSH user (default: %s)" % DEFAULT_USER)
    parser.add_argument("--identity", required=True,
                        help="path to the private key used for root SSH")
    parser.add_argument("--firmware-version", default=None,
                        help="optional user-provided firmware string; recorded as "
                             "user_provided, never treated as proof of compatibility")
    parser.add_argument("--json", action="store_true",
                        help="print the structured report as JSON")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python3 -m mini2_backup",
        description="Experimental, AI-generated read-only backup tooling for "
                    "Yandex Station Mini 2 with clock (YNDX-00020). "
                    "No flashing, no restore, no physical NAND dump.",
    )
    parser.add_argument("--version", action="version",
                        version="%s %s" % (TOOL_NAME, __version__))
    subparsers = parser.add_subparsers(dest="command", required=True)

    check_parser = subparsers.add_parser(
        "check", help="run local and remote read-only diagnostics")
    _add_ssh_options(check_parser)

    backup_parser = subparsers.add_parser(
        "backup", help="read mtd1..mtd6 and a /bkupgrade tar over SSH")
    _add_ssh_options(backup_parser)
    backup_parser.add_argument("--output-root", default="backups",
                               help="directory that will contain a new unique backup "
                                    "directory (default: backups)")
    backup_parser.add_argument("--partitions", default="mtd1,mtd2,mtd3,mtd4,mtd5,mtd6",
                               help="comma-separated subset of mtd1..mtd6; mtd0 is "
                                    "never allowed")
    backup_parser.add_argument("--yes", action="store_true",
                               help="skip the interactive confirmation")
    backup_parser.add_argument("--dry-run", action="store_true",
                               help="print the plan without any SSH connection or "
                                    "device read")

    verify_parser = subparsers.add_parser(
        "verify", help="verify a local backup directory without contacting the device")
    verify_parser.add_argument("backup_dir", help="backup directory containing report.json")
    verify_parser.add_argument("--json", action="store_true",
                               help="print the verification report as JSON")

    copy_parser = subparsers.add_parser(
        "copy-external", help="make and verify a byte-identical local copy")
    copy_parser.add_argument("--source", required=True,
                             help="existing backup directory to copy")
    copy_parser.add_argument("--destination", required=True,
                             help="existing destination root; a new unique subdirectory "
                                  "is created")
    copy_parser.add_argument("--report", default=None,
                             help="report path outside the source tree (default: next "
                                  "to the new copy directory)")
    copy_parser.add_argument("--allow-non-volume", action="store_true",
                             help="on macOS, allow a destination outside /Volumes; "
                                  "this does not prove physical independence")
    copy_parser.add_argument("--json", action="store_true",
                             help="print the copy report as JSON")

    return parser


def _banner() -> None:
    print("[!] " + AI_NOTICE, file=sys.stderr)


def _stderr_printer(message: str) -> None:
    print(message, file=sys.stderr)


def _target(args: argparse.Namespace) -> SshTarget:
    return SshTarget(host=args.host, port=args.port, user=args.user,
                     identity=args.identity)


def _print_check_summary(report: dict) -> None:
    device = report.get("device", {})
    layout = report.get("layout", {})
    print("Check status: %s" % report.get("status", "unknown").upper())
    host = report.get("host", {})
    print("Target: %s@%s:%s" % (host.get("user"), host.get("hostname"),
                                host.get("port")))
    print("Model: %s (source: %s)" % (device.get("model") or "unknown",
                                      device.get("model_source")))
    print("Kernel: %s" % (device.get("kernel") or "unknown"))
    print("Firmware: %s (source: %s)" % (device.get("firmware_version") or "not collected",
                                        device.get("firmware_source")))
    print("MTD profile: %s (offsets verified: %s)"
          % ("match" if layout.get("profile_match") else "MISMATCH",
             layout.get("offsets_verified")))
    nanddump = report.get("nanddump", {})
    print("nanddump: found=%s --bb=padbad=%s --omitoob=%s"
          % (nanddump.get("found"), nanddump.get("supports_bb_padbad"),
             nanddump.get("supports_omitoob")))
    print("tar: found=%s" % (report.get("tar", {}).get("found")))
    for check in report.get("checks", []):
        print("  [%s] %s: %s" % (check["status"], check["id"], check["detail"]))
    for warning in report.get("warnings", []):
        print("  WARNING: %s" % warning)
    for error in report.get("errors", []):
        print("  ERROR: %s" % error)


def _print_backup_summary(report: dict, output_dir: Optional[Path]) -> None:
    print("Backup status: %s" % report.get("status", "unknown").upper())
    if output_dir:
        print("Output: %s" % output_dir)
    for artifact in report.get("artifacts", []):
        print("  [%s] %s %s %s"
              % (artifact.get("status"), artifact.get("partition") or "tar",
                 artifact.get("name"),
                 artifact.get("sha256") or artifact.get("error") or ""))
    for warning in report.get("warnings", []):
        print("  WARNING: %s" % warning)
    for error in report.get("errors", []):
        print("  ERROR: %s" % error)
    print("Consistency: physical OOB=no, mtd0 complete=no, reserved areas=no, "
          "offline snapshot=no, independent re-read=no, restore tested=no, "
          "hardware validation=no.")


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        if args.command == "check":
            _banner()
            report = run_check(_target(args), args.firmware_version)
            if args.json:
                print(json.dumps(report, indent=2, ensure_ascii=False))
            else:
                _print_check_summary(report)
            return 0 if report.get("status") == "ok" else 2

        if args.command == "backup":
            _banner()
            partitions = [p.strip() for p in args.partitions.split(",") if p.strip()]
            if not partitions:
                raise UsageError("at least one partition must be selected")
            options = BackupOptions(
                output_root=Path(args.output_root),
                partitions=partitions,
                assume_yes=args.yes,
                dry_run=args.dry_run,
                firmware_version=args.firmware_version,
            )
            outcome = run_backup(
                _target(args), options,
                printer=_stderr_printer if args.json else None,
            )
            if args.json:
                print(json.dumps(outcome.report, indent=2, ensure_ascii=False))
            else:
                _print_backup_summary(outcome.report, outcome.output_dir)
            return outcome.exit_code

        if args.command == "verify":
            try:
                report = verify_backup(Path(args.backup_dir))
            except ValueError as exc:
                raise VerifyError(str(exc))
            except OSError as exc:
                raise VerifyError("filesystem error during verification: %s" % exc)
            if args.json:
                sys.stdout.write(verification_json(report))
            else:
                print(summarize_verification(report))
            return 0 if report.get("status") == "ok" else 1

        if args.command == "copy-external":
            try:
                report = copy_external(
                    Path(args.source), Path(args.destination),
                    report_path=Path(args.report) if args.report else None,
                    allow_non_volume=args.allow_non_volume,
                    printer=_stderr_printer if args.json else print,
                )
            except ValueError as exc:
                raise UsageError(str(exc))
            if args.json:
                print(json.dumps(report, indent=2, ensure_ascii=False))
            else:
                print("External copy: %s" % report.get("status", "unknown").upper())
                print("Destination: %s" % report.get("destination_copy"))
                print("Physical independence: %s" % report.get("physical_independence"))
                print("Permissions/dates/xattrs compared: no")
                for warning in report.get("warnings", []):
                    print("  WARNING: %s" % warning)
                for error in report.get("errors", []):
                    print("  ERROR: %s" % error)
            return 0 if report.get("status") == "completed" else 1

        parser.error("unknown command")
        return 2
    except ToolError as exc:
        if getattr(args, "json", False):
            print(json.dumps({
                "status": "failed",
                "error": str(exc),
                "tool": {"name": TOOL_NAME, "version": __version__},
            }, indent=2, ensure_ascii=False))
        else:
            print("ERROR: %s" % exc, file=sys.stderr)
        return exc.exit_code
    except KeyboardInterrupt:
        print("Interrupted. Partial files were kept; no success is claimed.",
              file=sys.stderr)
        return 130
    except BrokenPipeError:
        return 1
