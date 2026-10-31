# AI-generated tests. Review before use. See AI_DISCLOSURE.md.
"""Check/backup orchestration and CLI safety tests. No network access."""

from __future__ import annotations

import contextlib
import errno
import io
import json
import os
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock

from mini2_backup.backup import BackupOptions, _Logger, _default_confirm, run_backup
from mini2_backup.check import run_check
from mini2_backup.cli import main
from mini2_backup.errors import GateError, UsageError
from mini2_backup.profile import REFERENCE_BY_ID
from mini2_backup.ssh import LocalPreflight, SshTarget
from mini2_backup.verify import verify_backup

from .helpers import (
    FakePopenFactory,
    FakeProcess,
    PROC_MTD,
    check_runner,
    make_identity,
    make_tar,
    make_valid_backup,
    sysfs_probe,
)


class ExplodingLogger:
    def __init__(self):
        self.closed = False

    def log(self, _message):
        raise OSError(errno.ENOSPC, "simulated log full")

    def close(self):
        self.closed = True
        raise OSError(errno.EIO, "simulated log close failure")


class RecordingLogger:
    def __init__(self):
        self.closed = False
        self.messages = []

    def log(self, message):
        self.messages.append(message)

    def close(self):
        self.closed = True


def ok_preflight():
    return LocalPreflight(ok=True, checks=[], ssh_path="/usr/bin/ssh",
                          ssh_version="OpenSSH_9.0")


class LoggerTests(unittest.TestCase):
    def test_builtin_logger_swallows_fsync_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "backup.log"
            logger = _Logger(path)
            with mock.patch("mini2_backup.backup.os.fsync",
                            side_effect=OSError(errno.ENOSPC, "log full")):
                logger.log("hello")
            self.assertIsNotNone(logger.error)
            logger.close()
            self.assertTrue(path.exists())

    def test_builtin_logger_open_failure_does_not_raise(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "missing" / "backup.log"
            logger = _Logger(path)
            self.assertIsNotNone(logger.error)
            logger.log("ignored")
            logger.close()


class CheckTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.target = SshTarget(host="192.0.2.10", identity=str(make_identity(self.root)))

    def tearDown(self):
        self.tmp.cleanup()

    def test_successful_check(self):
        report = run_check(self.target, "user-said-0.1",
                           runner=check_runner(), preflight=ok_preflight())
        self.assertEqual(report["status"], "ok", report["errors"])
        self.assertEqual(report["device"]["uid"], 0)
        self.assertEqual(report["device"]["architecture"], "aarch64")
        self.assertEqual(report["device"]["firmware_source"], "user_provided")
        self.assertTrue(report["layout"]["profile_match"])
        self.assertFalse(report["layout"]["offsets_verified"])
        self.assertTrue(report["nanddump"]["supports_bb_padbad"])
        self.assertTrue(report["nanddump"]["supports_omitoob"])

    def test_profile_mismatch_fails_gate(self):
        bad = PROC_MTD.replace('mtd4: 00100000 00020000 "nv"',
                               'mtd4: 00200000 00020000 "nv"')
        report = run_check(self.target, runner=check_runner(proc_text=bad),
                           preflight=ok_preflight())
        self.assertEqual(report["status"], "failed")
        self.assertTrue(any("mismatch" in e for e in report["errors"])
                        or any(not c["status"] == "ok" and c["id"] == "mtd_profile"
                               for c in report["checks"]))

    def test_missing_nanddump_fails(self):
        report = run_check(
            self.target, runner=check_runner(nanddump_text="NANDDUMP_MISSING\n"),
            preflight=ok_preflight())
        self.assertEqual(report["status"], "failed")
        self.assertTrue(any(c["id"] == "nanddump" and c["status"] == "failed"
                            for c in report["checks"]))

    def test_missing_option_fails(self):
        report = run_check(
            self.target, runner=check_runner(nanddump_text="nanddump 1.0\n--omitoob\n"),
            preflight=ok_preflight())
        self.assertEqual(report["status"], "failed")
        self.assertFalse(report["nanddump"]["supports_bb_padbad"])

    def test_non_root_fails(self):
        report = run_check(self.target, runner=check_runner(uid="1000"),
                           preflight=ok_preflight())
        self.assertEqual(report["status"], "failed")
        self.assertTrue(any(c["id"] == "uid" and c["status"] == "failed"
                            for c in report["checks"]))

    def test_wrong_architecture_fails(self):
        report = run_check(
            self.target, runner=check_runner(uname="Linux 4.9.68 x86_64"),
            preflight=ok_preflight())
        self.assertEqual(report["status"], "failed")

    def test_unknown_model_is_a_hard_failure(self):
        report = run_check(self.target, runner=check_runner(model="UNKNOWN"),
                           preflight=ok_preflight())
        self.assertEqual(report["status"], "failed")
        self.assertEqual(report["device"]["model_source"], "unknown")
        self.assertIsNone(report["device"]["model_article_match"])
        self.assertTrue(any(c["id"] == "model" and c["status"] == "failed"
                            for c in report["checks"]))

    def test_family_model_does_not_prove_article(self):
        report = run_check(self.target,
                           runner=check_runner(model="Yandex Station Mini 2"),
                           preflight=ok_preflight())
        self.assertEqual(report["status"], "ok", report["errors"])
        self.assertFalse(report["device"]["model_article_match"])
        self.assertTrue(any("does not contain YNDX-00020" in w
                            for w in report["warnings"]))

    def test_tar_without_required_options_fails(self):
        report = run_check(
            self.target,
            runner=check_runner(tar_text="tar 1.0\n---TAR-HELP---\nno options here\n"),
            preflight=ok_preflight())
        self.assertEqual(report["status"], "failed")
        self.assertFalse(report["tar"]["supports_create"])

    def test_wrong_model_fails(self):
        report = run_check(self.target, runner=check_runner(model="Some Other Box"),
                           preflight=ok_preflight())
        self.assertEqual(report["status"], "failed")

    def test_ssh_failure_is_reported(self):
        report = run_check(
            self.target,
            runner=check_runner(failing_command="cat /proc/mtd"),
            preflight=ok_preflight())
        self.assertEqual(report["status"], "failed")
        self.assertTrue(any("host key" in e.lower() for e in report["errors"]))

    def test_no_credentials_are_collected(self):
        report = run_check(self.target, runner=check_runner(),
                           preflight=ok_preflight())
        text = json.dumps(report)
        self.assertNotIn("PRIVATE KEY", text)
        self.assertNotIn("password", text.lower())
        self.assertNotIn("wifi", text.lower())


class BackupTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.identity = make_identity(self.root)
        self.target = SshTarget(host="192.0.2.10", identity=str(self.identity))
        self.output_root = self.root / "backups"

    def tearDown(self):
        self.tmp.cleanup()

    def options(self, **kwargs):
        data = {"output_root": self.output_root, "partitions": ["mtd4"],
                "assume_yes": True}
        data.update(kwargs)
        return BackupOptions(**data)

    def image_factory(self, code=0):
        return lambda partition: b"X" * REFERENCE_BY_ID[partition].size, code

    def test_dry_run_does_not_connect_or_create_directories(self):
        with mock.patch("subprocess.Popen", side_effect=AssertionError("must not spawn")):
            outcome = run_backup(
                self.target, self.options(dry_run=True),
                preflight=ok_preflight(), confirm=lambda _p: True,
                printer=lambda _m: None)
        self.assertEqual(outcome.exit_code, 0)
        self.assertEqual(outcome.report["status"], "dry_run")
        self.assertFalse(outcome.report["preflight_executed"])
        self.assertIsNone(outcome.output_dir)
        self.assertFalse(self.output_root.exists())

    def test_dry_run_rejects_mtd0(self):
        with self.assertRaises(UsageError):
            run_backup(self.target, self.options(dry_run=True, partitions=["mtd0"]),
                       preflight=ok_preflight(), printer=lambda _m: None)

    def test_cancelled_confirmation_creates_nothing(self):
        with self.assertRaises(UsageError):
            run_backup(self.target, self.options(assume_yes=False),
                       preflight=ok_preflight(), confirm=lambda _p: False,
                       printer=lambda _m: None)
        self.assertFalse(self.output_root.exists())

    def test_successful_backup_with_one_image_and_tar(self):
        data = b"Y" * REFERENCE_BY_ID["mtd4"].size
        factory = FakePopenFactory(image_data=lambda _p: data,
                                   tar_data=b"fake-tar-bytes")
        outcome = run_backup(
            self.target, self.options(),
            check_runner=check_runner(), popen_factory=factory,
            preflight=ok_preflight(), printer=lambda _m: None)
        self.assertEqual(outcome.exit_code, 0, outcome.report["errors"])
        self.assertEqual(outcome.report["status"], "completed")
        image = outcome.output_dir / "images/mtd4.nv.bin"
        tar = outcome.output_dir / "bkupgrade.tar"
        self.assertTrue(image.exists())
        self.assertTrue(tar.exists())
        self.assertFalse((outcome.output_dir / "images/mtd4.nv.bin.part").exists())
        checksums = (outcome.output_dir / "checksums.sha256").read_text()
        self.assertIn("images/mtd4.nv.bin", checksums)
        self.assertIn("bkupgrade.tar", checksums)
        self.assertNotIn("report.json", checksums)
        self.assertNotIn("checksums.sha256", checksums)
        report = json.loads((outcome.output_dir / "report.json").read_text())
        self.assertTrue(all(v is False for v in report["consistency"].values()))
        self.assertFalse(report["consistency"]["hardware_validation_of_this_tool"])
        image_entry = [a for a in report["artifacts"] if a["partition"] == "mtd4"][0]
        self.assertFalse(image_entry["files"]["part"]["exists"])
        self.assertTrue(image_entry["files"]["final"]["exists"])
        self.assertTrue(image_entry["files"]["final"]["sha256_verified"])
        self.assertTrue(image_entry["files"]["finalization_complete"])

    def test_failed_stream_keeps_part_and_writes_failed_report(self):
        factory = FakePopenFactory(image_data=lambda _p: b"short",
                                   image_code=1)
        outcome = run_backup(
            self.target, self.options(),
            check_runner=check_runner(), popen_factory=factory,
            preflight=ok_preflight(), printer=lambda _m: None)
        self.assertEqual(outcome.exit_code, 1)
        self.assertEqual(outcome.report["status"], "failed")
        part = outcome.output_dir / "images/mtd4.nv.bin.part"
        self.assertTrue(part.exists())
        self.assertFalse((outcome.output_dir / "images/mtd4.nv.bin").exists())
        self.assertFalse((outcome.output_dir / "bkupgrade.tar").exists())
        self.assertTrue(any(a["status"] == "skipped" and a["kind"] == "tar"
                            for a in outcome.report["artifacts"]))
        failed = [a for a in outcome.report["artifacts"]
                  if a["partition"] == "mtd4"][0]
        self.assertTrue(failed["files"]["part"]["exists"])
        self.assertFalse(failed["files"]["final"]["exists"])
        self.assertFalse(failed["files"]["finalization_complete"])

    def test_profile_gate_failure_reads_no_partition(self):
        bad = PROC_MTD.replace("mtd4: 00100000", "mtd4: 00200000")
        factory = FakePopenFactory()
        outcome = run_backup(
            self.target, self.options(),
            check_runner=check_runner(proc_text=bad), popen_factory=factory,
            preflight=ok_preflight(), printer=lambda _m: None)
        self.assertEqual(outcome.exit_code, 2)
        self.assertEqual(outcome.report["status"], "failed")
        self.assertEqual(factory.calls, [])

    def test_unknown_model_blocks_backup_without_reading(self):
        factory = FakePopenFactory()
        outcome = run_backup(
            self.target, self.options(),
            check_runner=check_runner(model="UNKNOWN"), popen_factory=factory,
            preflight=ok_preflight(), printer=lambda _m: None)
        self.assertEqual(outcome.exit_code, 2)
        self.assertEqual(outcome.report["status"], "failed")
        self.assertEqual(factory.calls, [])
        self.assertTrue(all(a["status"] == "skipped"
                            for a in outcome.report["artifacts"]))

    def test_tar_failure_marks_run_failed(self):
        data = b"Z" * REFERENCE_BY_ID["mtd4"].size
        factory = FakePopenFactory(image_data=lambda _p: data, tar_code=1)
        outcome = run_backup(
            self.target, self.options(),
            check_runner=check_runner(), popen_factory=factory,
            preflight=ok_preflight(), printer=lambda _m: None)
        self.assertEqual(outcome.exit_code, 1)
        self.assertTrue((outcome.output_dir / "bkupgrade.tar.part").exists())
        self.assertFalse((outcome.output_dir / "bkupgrade.tar").exists())

    def test_finalization_interrupt_report_records_both_files(self):
        data = b"P" * REFERENCE_BY_ID["mtd4"].size
        factory = FakePopenFactory(image_data=lambda _p: data, tar_data=b"tar")
        real_link = os.link

        def link_then_interrupt(src, dst):
            real_link(src, dst)
            raise KeyboardInterrupt

        with mock.patch("mini2_backup.transfer.os.link",
                        side_effect=link_then_interrupt):
            with self.assertRaises(KeyboardInterrupt):
                run_backup(
                    self.target, self.options(),
                    check_runner=check_runner(), popen_factory=factory,
                    preflight=ok_preflight(), printer=lambda _m: None,
                    logger_factory=lambda _p: RecordingLogger())
        dirs = list(self.output_root.glob("backup-*"))
        self.assertEqual(len(dirs), 1)
        report = json.loads((dirs[0] / "report.json").read_text())
        artifact = [a for a in report["artifacts"] if a["partition"] == "mtd4"][0]
        self.assertEqual(artifact["status"], "failed")
        self.assertTrue(artifact["files"]["part"]["exists"])
        self.assertTrue(artifact["files"]["final"]["exists"])
        self.assertFalse(artifact["files"]["final"]["sha256_verified"])
        self.assertFalse(artifact["files"]["finalization_complete"])
        self.assertTrue((dirs[0] / "images/mtd4.nv.bin.part").exists())
        self.assertEqual((dirs[0] / "images/mtd4.nv.bin").read_bytes(), data)

    def test_part_removal_interrupt_report_records_final_only(self):
        data = b"Q" * REFERENCE_BY_ID["mtd4"].size
        factory = FakePopenFactory(image_data=lambda _p: data, tar_data=b"tar")
        real_unlink = os.unlink

        def unlink_then_interrupt(path):
            real_unlink(path)
            if os.path.basename(path) == "mtd4.nv.bin.part":
                raise KeyboardInterrupt

        with mock.patch("mini2_backup.transfer.os.unlink",
                        side_effect=unlink_then_interrupt):
            with self.assertRaises(KeyboardInterrupt):
                run_backup(
                    self.target, self.options(),
                    check_runner=check_runner(), popen_factory=factory,
                    preflight=ok_preflight(), printer=lambda _m: None,
                    logger_factory=lambda _p: RecordingLogger())
        dirs = list(self.output_root.glob("backup-*"))
        self.assertEqual(len(dirs), 1)
        report = json.loads((dirs[0] / "report.json").read_text())
        artifact = [a for a in report["artifacts"] if a["partition"] == "mtd4"][0]
        self.assertEqual(artifact["status"], "failed")
        self.assertFalse(artifact["files"]["part"]["exists"])
        self.assertTrue(artifact["files"]["final"]["exists"])
        self.assertFalse(artifact["files"]["final"]["sha256_verified"])
        self.assertFalse(artifact["files"]["finalization_complete"])
        self.assertIsNone(artifact["part_path"])
        self.assertEqual((dirs[0] / "images/mtd4.nv.bin").read_bytes(), data)
        verification = verify_backup(dirs[0])
        self.assertEqual(verification["status"], "failed")
        self.assertTrue(any("final exists but is not reported as verified" in w
                            for w in verification["warnings"]))
        self.assertFalse(any("final-only artifact" in e
                             for e in verification["errors"]))

    def test_log_failure_after_enospc_does_not_block_failed_report(self):
        logger = ExplodingLogger()
        with mock.patch("mini2_backup.transfer._write_block",
                        side_effect=OSError(errno.ENOSPC, "no space")):
            outcome = run_backup(
                self.target, self.options(),
                check_runner=check_runner(), popen_factory=FakePopenFactory(),
                preflight=ok_preflight(), printer=lambda _m: None,
                logger_factory=lambda _p: logger)
        self.assertEqual(outcome.exit_code, 1)
        report = json.loads((outcome.output_dir / "report.json").read_text())
        self.assertEqual(report["status"], "failed")
        self.assertTrue(any("logging unavailable" in w for w in report["warnings"]))
        self.assertTrue((outcome.output_dir / "images/mtd4.nv.bin.part").exists())
        self.assertTrue(logger.closed)

    def test_log_failure_after_successful_artifact_does_not_block_report(self):
        logger = ExplodingLogger()
        data = b"L" * REFERENCE_BY_ID["mtd4"].size
        tar_fixture = self.root / "log-fixture.tar"
        make_tar(tar_fixture)
        factory = FakePopenFactory(image_data=lambda _p: data,
                                   tar_data=tar_fixture.read_bytes())
        outcome = run_backup(
            self.target, self.options(),
            check_runner=check_runner(), popen_factory=factory,
            preflight=ok_preflight(), printer=lambda _m: None,
            logger_factory=lambda _p: logger)
        self.assertEqual(outcome.exit_code, 0, outcome.report["errors"])
        report = json.loads((outcome.output_dir / "report.json").read_text())
        self.assertEqual(report["status"], "completed")
        self.assertTrue(any("logging unavailable" in w for w in report["warnings"]))
        verification = verify_backup(outcome.output_dir)
        self.assertEqual(verification["status"], "ok", verification["errors"])
        self.assertTrue(logger.closed)

    def test_log_failure_during_keyboard_interrupt_does_not_block_report(self):
        logger = ExplodingLogger()

        def factory(_argv, **_kwargs):
            return FakeProcess(b"x" * 1024, interrupt_after=1024)

        with self.assertRaises(KeyboardInterrupt):
            run_backup(
                self.target, self.options(),
                check_runner=check_runner(), popen_factory=factory,
                preflight=ok_preflight(), printer=lambda _m: None,
                logger_factory=lambda _p: logger)
        dirs = list(self.output_root.glob("backup-*"))
        self.assertEqual(len(dirs), 1)
        report = json.loads((dirs[0] / "report.json").read_text())
        self.assertEqual(report["status"], "failed")
        self.assertTrue(any("logging unavailable" in w for w in report["warnings"]))
        self.assertTrue(logger.closed)

    def test_log_failure_inside_checksum_error_handler_does_not_block_report(self):
        logger = ExplodingLogger()
        data = b"M" * REFERENCE_BY_ID["mtd4"].size
        factory = FakePopenFactory(image_data=lambda _p: data, tar_data=b"tar")
        with mock.patch("mini2_backup.backup.write_text_exclusive",
                        side_effect=OSError(errno.ENOSPC, "checksums full")):
            outcome = run_backup(
                self.target, self.options(),
                check_runner=check_runner(), popen_factory=factory,
                preflight=ok_preflight(), printer=lambda _m: None,
                logger_factory=lambda _p: logger)
        self.assertEqual(outcome.exit_code, 1)
        report = json.loads((outcome.output_dir / "report.json").read_text())
        self.assertEqual(report["status"], "failed")
        self.assertTrue(any("could not write checksums.sha256" in e
                            for e in report["errors"]))
        self.assertTrue(logger.closed)

    def test_log_failure_when_report_cannot_be_saved_is_diagnostic(self):
        logger = ExplodingLogger()
        printed = []
        data = b"N" * REFERENCE_BY_ID["mtd4"].size
        factory = FakePopenFactory(image_data=lambda _p: data, tar_data=b"tar")
        with mock.patch("mini2_backup.backup.write_report",
                        side_effect=OSError(errno.ENOSPC, "report full")):
            outcome = run_backup(
                self.target, self.options(),
                check_runner=check_runner(), popen_factory=factory,
                preflight=ok_preflight(), printer=printed.append,
                logger_factory=lambda _p: logger)
        self.assertEqual(outcome.exit_code, 1)
        self.assertFalse((outcome.output_dir / "report.json").exists())
        self.assertTrue(any("could not write report" in line for line in printed))
        self.assertTrue(any("failed report could not be saved" in line
                            for line in printed))
        self.assertTrue(logger.closed)

    def test_orchestration_oserror_marks_all_skipped_and_saves_report(self):
        logger = RecordingLogger()
        with mock.patch("mini2_backup.backup.shutil.disk_usage",
                        side_effect=OSError(errno.EIO, "statvfs failed")):
            outcome = run_backup(
                self.target, self.options(),
                check_runner=check_runner(), popen_factory=FakePopenFactory(),
                preflight=ok_preflight(), printer=lambda _m: None,
                logger_factory=lambda _p: logger)
        self.assertEqual(outcome.exit_code, 1)
        report = json.loads((outcome.output_dir / "report.json").read_text())
        self.assertEqual(report["status"], "failed")
        self.assertTrue(any("orchestration OSError" in e for e in report["errors"]))
        self.assertTrue(all(a["status"] == "skipped" for a in report["artifacts"]))
        self.assertTrue(logger.closed)

    def test_orchestration_oserror_after_artifact_marks_remaining_skipped(self):
        logger = RecordingLogger()
        data = b"O" * REFERENCE_BY_ID["mtd1"].size
        factory = FakePopenFactory(image_data=lambda _p: data, tar_data=b"tar")
        real_usage = mock.Mock(free=10 ** 12)
        calls = {"n": 0}

        def disk_usage(_path):
            calls["n"] += 1
            if calls["n"] >= 3:
                raise OSError(errno.EIO, "statvfs failed after first artifact")
            return real_usage

        with mock.patch("mini2_backup.backup.shutil.disk_usage",
                        side_effect=disk_usage):
            outcome = run_backup(
                self.target, self.options(partitions=["mtd1", "mtd4"]),
                check_runner=check_runner(), popen_factory=factory,
                preflight=ok_preflight(), printer=lambda _m: None,
                logger_factory=lambda _p: logger)
        self.assertEqual(outcome.exit_code, 1)
        report = json.loads((outcome.output_dir / "report.json").read_text())
        self.assertEqual(report["status"], "failed")
        statuses = {a["partition"]: a["status"] for a in report["artifacts"]}
        self.assertEqual(statuses["mtd1"], "completed")
        self.assertEqual(statuses["mtd4"], "skipped")
        self.assertEqual(statuses[None], "skipped")
        self.assertTrue(logger.closed)

    def test_orchestration_oserror_report_failure_is_nonzero_and_diagnostic(self):
        logger = RecordingLogger()
        printed = []
        with mock.patch("mini2_backup.backup.shutil.disk_usage",
                        side_effect=OSError(errno.EIO, "statvfs failed")), \
                mock.patch("mini2_backup.backup.write_report",
                           side_effect=OSError(errno.ENOSPC, "report full")):
            outcome = run_backup(
                self.target, self.options(),
                check_runner=check_runner(), popen_factory=FakePopenFactory(),
                preflight=ok_preflight(), printer=printed.append,
                logger_factory=lambda _p: logger)
        self.assertEqual(outcome.exit_code, 1)
        self.assertFalse((outcome.output_dir / "report.json").exists())
        self.assertTrue(any("could not write report" in line for line in printed))
        self.assertTrue(any("failed report could not be saved" in line
                            for line in printed))
        self.assertTrue(logger.closed)

    def test_generated_backup_passes_offline_verify(self):
        data = b"V" * REFERENCE_BY_ID["mtd4"].size
        tar_fixture = self.root / "fixture.tar"
        make_tar(tar_fixture)
        factory = FakePopenFactory(image_data=lambda _p: data,
                                   tar_data=tar_fixture.read_bytes())
        outcome = run_backup(
            self.target, self.options(),
            check_runner=check_runner(), popen_factory=factory,
            preflight=ok_preflight(), printer=lambda _m: None)
        self.assertEqual(outcome.exit_code, 0, outcome.report["errors"])
        verification = verify_backup(outcome.output_dir)
        self.assertEqual(verification["status"], "ok", verification["errors"])
        self.assertFalse(verification["restore_tested"])

    def test_checksum_write_failure_marks_run_failed(self):
        data = b"C" * REFERENCE_BY_ID["mtd4"].size
        factory = FakePopenFactory(image_data=lambda _p: data, tar_data=b"tar")
        with mock.patch("mini2_backup.backup.write_text_exclusive",
                        side_effect=OSError("simulated checksum failure")):
            outcome = run_backup(
                self.target, self.options(),
                check_runner=check_runner(), popen_factory=factory,
                preflight=ok_preflight(), printer=lambda _m: None)
        self.assertEqual(outcome.exit_code, 1)
        report = json.loads((outcome.output_dir / "report.json").read_text())
        self.assertEqual(report["status"], "failed")
        self.assertTrue(any("checksums.sha256" in e for e in report["errors"]))

    def test_interruption_writes_failed_report_with_actual_partial_size(self):
        def factory(argv, **kwargs):
            if argv[-1].startswith("nanddump"):
                return FakeProcess(b"x" * 1024, interrupt_after=1024)
            return FakeProcess(b"", code=1)

        with self.assertRaises(KeyboardInterrupt):
            run_backup(
                self.target, self.options(),
                check_runner=check_runner(), popen_factory=factory,
                preflight=ok_preflight(), printer=lambda _m: None)

        dirs = list(self.output_root.glob("backup-*"))
        self.assertEqual(len(dirs), 1)
        report = json.loads((dirs[0] / "report.json").read_text())
        self.assertEqual(report["status"], "failed")
        artifact = [a for a in report["artifacts"] if a["partition"] == "mtd4"][0]
        self.assertEqual(artifact["status"], "failed")
        self.assertEqual(artifact["bytes_received"], 1024)
        self.assertEqual(artifact["bytes_written"], 1024)
        self.assertEqual(artifact["actual_size"], 1024)
        self.assertTrue((dirs[0] / "images/mtd4.nv.bin.part").exists())
        self.assertIn("interrupted", artifact["error"])
        self.assertTrue(any(a["status"] == "skipped" and a["kind"] == "tar"
                            for a in report["artifacts"]))

    def test_reports_do_not_contain_identity_contents(self):
        marker = "SECRET-KEY-MATERIAL"
        self.identity.write_text(marker, encoding="utf-8")
        factory = FakePopenFactory(image_data=lambda _p: b"Q" * 1024,
                                   tar_data=b"tar")
        outcome = run_backup(
            self.target, self.options(),
            check_runner=check_runner(), popen_factory=factory,
            preflight=ok_preflight(), printer=lambda _m: None)
        text = (outcome.output_dir / "report.json").read_text()
        self.assertNotIn(marker, text)


class CliTests(unittest.TestCase):
    def test_help_exits_zero(self):
        with self.assertRaises(SystemExit) as caught:
            main(["--help"])
        self.assertEqual(caught.exception.code, 0)

    def test_version_exits_zero(self):
        with self.assertRaises(SystemExit) as caught:
            main(["--version"])
        self.assertEqual(caught.exception.code, 0)

    def test_invalid_host_returns_usage_error_without_ssh(self):
        with tempfile.TemporaryDirectory() as tmp:
            identity = make_identity(Path(tmp))
            code = main(["check", "--host=-oProxyCommand=evil",
                         "--identity", str(identity)])
        self.assertEqual(code, 2)

    def test_check_inside_ssh_session_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            identity = make_identity(Path(tmp))
            with mock.patch.dict("os.environ", {"SSH_CONNECTION": "1 2 3 4"}):
                code = main(["check", "--host", "192.0.2.10",
                             "--identity", str(identity)])
        self.assertEqual(code, 2)

    def test_dry_run_cli_never_spawns_ssh(self):
        with tempfile.TemporaryDirectory() as tmp:
            identity = make_identity(Path(tmp))
            output = Path(tmp) / "out"
            with mock.patch("subprocess.Popen",
                            side_effect=AssertionError("must not spawn")):
                code = main([
                    "backup", "--dry-run", "--yes",
                    "--host", "192.0.2.10", "--identity", str(identity),
                    "--output-root", str(output), "--partitions", "mtd4",
                ])
            self.assertEqual(code, 0)
            self.assertFalse(output.exists())

    def test_verify_missing_directory_returns_nonzero(self):
        with tempfile.TemporaryDirectory() as tmp:
            code = main(["verify", str(Path(tmp) / "missing")])
        self.assertEqual(code, 1)

    def test_copy_external_requires_explicit_paths(self):
        with self.assertRaises(SystemExit) as caught:
            main(["copy-external", "--source", "/tmp/x"])
        self.assertNotEqual(caught.exception.code, 0)

    def test_backup_json_stdout_is_one_json_document(self):
        with tempfile.TemporaryDirectory() as tmp:
            identity = make_identity(Path(tmp))
            stdout = io.StringIO()
            stderr = io.StringIO()

            def fake_run_backup(_target, _options, printer=None):
                if printer:
                    printer("progress line")
                return types.SimpleNamespace(
                    report={"status": "failed", "artifacts": []},
                    exit_code=1, output_dir=None)

            with mock.patch("mini2_backup.cli.run_backup",
                            side_effect=fake_run_backup):
                with contextlib.redirect_stdout(stdout), \
                        contextlib.redirect_stderr(stderr):
                    code = main([
                        "backup", "--json", "--yes",
                        "--host", "192.0.2.10", "--identity", str(identity),
                        "--output-root", str(Path(tmp) / "out"),
                        "--partitions", "mtd4",
                    ])
        self.assertEqual(code, 1)
        parsed = json.loads(stdout.getvalue())
        self.assertEqual(parsed["status"], "failed")
        self.assertIn("progress line", stderr.getvalue())
        self.assertIn("EXPERIMENTAL", stderr.getvalue())
        self.assertNotIn("progress line", stdout.getvalue())

    def test_copy_external_json_stdout_is_one_json_document(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "source"
            destination = Path(tmp) / "destination"
            source.mkdir()
            destination.mkdir()
            stdout = io.StringIO()
            stderr = io.StringIO()

            def fake_copy_external(_source, _destination, *, printer=None,
                                   **_kwargs):
                if printer:
                    printer("copy progress")
                return {"status": "completed",
                        "destination_copy": str(_destination / "copy"),
                        "physical_independence": "not_verified"}

            with mock.patch("mini2_backup.cli.copy_external",
                            side_effect=fake_copy_external):
                with contextlib.redirect_stdout(stdout), \
                        contextlib.redirect_stderr(stderr):
                    code = main([
                        "copy-external", "--json",
                        "--source", str(source), "--destination", str(destination),
                        "--allow-non-volume",
                    ])
        self.assertEqual(code, 0)
        parsed = json.loads(stdout.getvalue())
        self.assertEqual(parsed["status"], "completed")
        self.assertIn("copy progress", stderr.getvalue())
        self.assertNotIn("copy progress", stdout.getvalue())

    def test_dry_run_json_stdout_is_one_json_document(self):
        with tempfile.TemporaryDirectory() as tmp:
            identity = make_identity(Path(tmp))
            stdout = io.StringIO()
            stderr = io.StringIO()
            with contextlib.redirect_stdout(stdout), \
                    contextlib.redirect_stderr(stderr):
                code = main([
                    "backup", "--dry-run", "--json", "--yes",
                    "--host", "192.0.2.10", "--identity", str(identity),
                    "--output-root", str(Path(tmp) / "out"),
                    "--partitions", "mtd4",
                ])
        self.assertEqual(code, 0)
        parsed = json.loads(stdout.getvalue())
        self.assertEqual(parsed["status"], "dry_run")
        self.assertIn("Planned read-only artifacts", stderr.getvalue())
        self.assertNotIn("Planned read-only artifacts", stdout.getvalue())

    def test_copy_external_json_stdout_contains_only_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "source"
            destination = Path(tmp) / "destination"
            source.mkdir()
            destination.mkdir()
            (source / "a.txt").write_text("hello\n", encoding="utf-8")
            stdout = io.StringIO()
            stderr = io.StringIO()
            with contextlib.redirect_stdout(stdout), \
                    contextlib.redirect_stderr(stderr):
                code = main([
                    "copy-external", "--json", "--allow-non-volume",
                    "--source", str(source), "--destination", str(destination),
                ])
        self.assertEqual(code, 0)
        parsed = json.loads(stdout.getvalue())
        self.assertEqual(parsed["status"], "completed")
        self.assertIn("Copying to", stderr.getvalue())
        self.assertNotIn("Copying to", stdout.getvalue())

    def test_backup_json_error_stdout_is_one_json_document(self):
        with tempfile.TemporaryDirectory() as tmp:
            identity = make_identity(Path(tmp))
            stdout = io.StringIO()
            stderr = io.StringIO()
            with contextlib.redirect_stdout(stdout), \
                    contextlib.redirect_stderr(stderr):
                code = main([
                    "backup", "--json", "--yes",
                    "--host=-oProxyCommand=evil", "--identity", str(identity),
                    "--output-root", str(Path(tmp) / "out"),
                ])
        self.assertEqual(code, 2)
        parsed = json.loads(stdout.getvalue())
        self.assertEqual(parsed["status"], "failed")
        self.assertIn("invalid host", parsed["error"])
        self.assertIn("EXPERIMENTAL", stderr.getvalue())

    def test_verify_json_filesystem_error_is_one_json_document(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "backup"
            make_valid_backup(root)
            stdout = io.StringIO()
            stderr = io.StringIO()
            with mock.patch("mini2_backup.verify.stream_sha256",
                            side_effect=OSError(5, "read boom")):
                with contextlib.redirect_stdout(stdout), \
                        contextlib.redirect_stderr(stderr):
                    code = main(["verify", str(root), "--json"])
        self.assertEqual(code, 1)
        parsed = json.loads(stdout.getvalue())
        self.assertEqual(parsed["status"], "failed")
        self.assertTrue(any("cannot compute SHA-256" in e
                            for e in parsed["errors"]))

    def test_confirm_prompt_goes_to_stderr(self):
        stdout = io.StringIO()
        stderr = io.StringIO()
        with mock.patch("builtins.input", return_value="yes"):
            with contextlib.redirect_stdout(stdout), \
                    contextlib.redirect_stderr(stderr):
                self.assertTrue(_default_confirm("Type yes: "))
        self.assertEqual(stdout.getvalue(), "")
        self.assertIn("Type yes:", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
