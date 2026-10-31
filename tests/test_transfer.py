# AI-generated tests. Review before use. See AI_DISCLOSURE.md.
"""Streaming transfer tests with injected fake processes (no SSH)."""

from __future__ import annotations

import errno
import hashlib
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from mini2_backup.transfer import (
    TransferInterrupted,
    _StderrTail,
    stream_to_part_file,
)

from .helpers import FakeProcess


class TransferTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.part = self.root / "image.bin.part"
        self.final = self.root / "image.bin"

    def tearDown(self):
        self.tmp.cleanup()

    def run_transfer(self, data, code=0, expected=None, stderr=b"", **kwargs):
        proc = FakeProcess(data, code=code, stderr=stderr, **kwargs)
        return stream_to_part_file(
            ["ssh", "fake"], self.part, self.final, expected,
            popen_factory=lambda *a, **k: proc,
        ), proc

    def test_success_writes_final_and_sha(self):
        data = b"hello-world" * 1000
        result, _ = self.run_transfer(data, expected=len(data))
        self.assertTrue(result.ok, result.error)
        self.assertEqual(result.bytes_received, len(data))
        self.assertEqual(result.bytes_written, len(data))
        self.assertEqual(result.sha256, hashlib.sha256(data).hexdigest())
        self.assertFalse(self.part.exists())
        self.assertEqual(self.final.read_bytes(), data)

    def test_nonzero_exit_keeps_part(self):
        data = b"abc"
        result, _ = self.run_transfer(data, code=1, expected=len(data))
        self.assertFalse(result.ok)
        self.assertIn("exited with code 1", result.error)
        self.assertTrue(self.part.exists())
        self.assertFalse(self.final.exists())
        self.assertEqual(self.part.read_bytes(), data)
        self.assertEqual(result.bytes_received, len(data))
        self.assertEqual(result.bytes_written, len(data))

    def test_short_stream_keeps_part_and_never_pads(self):
        data = b"abc"
        result, _ = self.run_transfer(data, expected=10)
        self.assertFalse(result.ok)
        self.assertIn("length mismatch", result.error)
        self.assertTrue(self.part.exists())
        self.assertEqual(self.part.read_bytes(), b"abc")
        self.assertEqual(result.bytes_received, 3)
        self.assertEqual(result.bytes_written, 3)

    def test_long_stream_is_stopped_and_keeps_part(self):
        data = b"abcdefghij"
        result, proc = self.run_transfer(data, expected=5)
        self.assertFalse(result.ok)
        self.assertIn("exceeded", result.error)
        self.assertTrue(proc.terminated)
        self.assertTrue(self.part.exists())
        self.assertEqual(result.bytes_received, 10)
        self.assertEqual(result.bytes_written, 0)
        self.assertEqual(self.part.stat().st_size, 0)

    def test_existing_final_is_never_overwritten(self):
        self.final.write_bytes(b"keep-me")
        result, _ = self.run_transfer(b"new", expected=3)
        self.assertFalse(result.ok)
        self.assertIn("refusing to overwrite", result.error)
        self.assertEqual(self.final.read_bytes(), b"keep-me")
        self.assertFalse(self.part.exists())

    def test_existing_part_is_not_overwritten(self):
        self.part.write_bytes(b"old-part")
        result, _ = self.run_transfer(b"new", expected=3)
        self.assertFalse(result.ok)
        self.assertEqual(self.part.read_bytes(), b"old-part")

    def test_disk_full_keeps_part(self):
        data = b"x" * 100
        proc = FakeProcess(data)
        with mock.patch("mini2_backup.transfer.os.write",
                        side_effect=OSError(errno.ENOSPC, "no space")):
            result = stream_to_part_file(
                ["ssh", "fake"], self.part, self.final, len(data),
                popen_factory=lambda *a, **k: proc,
            )
        self.assertFalse(result.ok)
        self.assertIn("disk is full", result.error)
        self.assertTrue(self.part.exists())
        self.assertFalse(self.final.exists())
        self.assertEqual(result.bytes_received, len(data))
        self.assertEqual(result.bytes_written, 0)
        self.assertEqual(self.part.stat().st_size, 0)

    def test_keyboard_interrupt_terminates_and_keeps_part(self):
        proc = FakeProcess(b"", interrupt=True)
        with self.assertRaises(KeyboardInterrupt):
            stream_to_part_file(
                ["ssh", "fake"], self.part, self.final, 10,
                popen_factory=lambda *a, **k: proc,
            )
        self.assertTrue(proc.terminated)
        self.assertTrue(self.part.exists())
        self.assertFalse(self.final.exists())

    def test_keyboard_interrupt_reports_actual_partial_size(self):
        proc = FakeProcess(b"abc", interrupt_after=3)
        with self.assertRaises(TransferInterrupted) as caught:
            stream_to_part_file(
                ["ssh", "fake"], self.part, self.final, 3,
                popen_factory=lambda *a, **k: proc,
            )
        self.assertEqual(caught.exception.bytes_received, 3)
        self.assertEqual(caught.exception.bytes_written, 3)
        self.assertEqual(self.part.stat().st_size, 3)
        self.assertFalse(self.final.exists())

    def test_stderr_is_separated_and_bounded(self):
        result, _ = self.run_transfer(b"abc", code=2, expected=3,
                                      stderr=b"nanddump: failure")
        self.assertFalse(result.ok)
        self.assertIn("nanddump: failure", result.stderr_tail)
        self.assertIn("exited with code 2", result.error)

    def test_unknown_size_tar_min_size(self):
        result, _ = self.run_transfer(b"tar-bytes", expected=None, )
        self.assertTrue(result.ok, result.error)
        self.assertEqual(result.bytes_written, 9)

    def test_empty_unknown_size_is_rejected_by_min_size(self):
        proc = FakeProcess(b"")
        result = stream_to_part_file(
            ["ssh", "fake"], self.part, self.final, None, min_size=1,
            popen_factory=lambda *a, **k: proc,
        )
        self.assertFalse(result.ok)
        self.assertIn("unexpectedly small", result.error)

    def test_interrupt_after_successful_link_preserves_both_files(self):
        data = b"abc"
        real_link = os.link

        def link_then_interrupt(src, dst):
            real_link(src, dst)
            raise KeyboardInterrupt

        with mock.patch("mini2_backup.transfer.os.link",
                        side_effect=link_then_interrupt):
            with self.assertRaises(TransferInterrupted) as caught:
                self.run_transfer(data, expected=len(data))
        files = caught.exception.files
        self.assertTrue(self.part.exists())
        self.assertTrue(self.final.exists())
        self.assertEqual(self.final.read_bytes(), data)
        self.assertTrue(files["part"]["exists"])
        self.assertTrue(files["final"]["exists"])
        self.assertFalse(files["final"]["sha256_verified"])
        self.assertFalse(files["finalization_complete"])
        self.assertTrue(files["final"]["created_by_this_attempt"])

    def test_interrupt_during_directory_fsync_preserves_both_files(self):
        data = b"abc"
        with mock.patch("mini2_backup.transfer._fsync_dir_strict",
                        side_effect=KeyboardInterrupt):
            with self.assertRaises(TransferInterrupted) as caught:
                self.run_transfer(data, expected=len(data))
        files = caught.exception.files
        self.assertTrue(self.part.exists())
        self.assertTrue(self.final.exists())
        self.assertEqual(self.final.read_bytes(), data)
        self.assertTrue(files["part"]["exists"])
        self.assertTrue(files["final"]["exists"])
        self.assertFalse(files["final"]["sha256_verified"])
        self.assertFalse(files["finalization_complete"])

    def test_interrupt_after_part_removal_preserves_final(self):
        data = b"abc"
        real_unlink = os.unlink
        part_abs = os.path.abspath(str(self.part))

        def unlink_then_interrupt(path):
            real_unlink(path)
            if os.path.abspath(path) == part_abs:
                raise KeyboardInterrupt

        with mock.patch("mini2_backup.transfer.os.unlink",
                        side_effect=unlink_then_interrupt):
            with self.assertRaises(TransferInterrupted) as caught:
                self.run_transfer(data, expected=len(data))
        files = caught.exception.files
        self.assertFalse(self.part.exists())
        self.assertTrue(self.final.exists())
        self.assertEqual(self.final.read_bytes(), data)
        self.assertFalse(files["part"]["exists"])
        self.assertTrue(files["final"]["exists"])
        self.assertFalse(files["final"]["sha256_verified"])
        self.assertFalse(files["finalization_complete"])
        self.assertTrue(files["final"]["created_by_this_attempt"])

    def test_interrupt_during_fallback_preserves_only_part(self):
        data = b"abc"
        real_write = os.write
        calls = {"n": 0}

        def write_then_interrupt(fd, block):
            calls["n"] += 1
            if calls["n"] == 1:
                return real_write(fd, block)
            raise KeyboardInterrupt

        with mock.patch("mini2_backup.transfer.os.link",
                        side_effect=OSError(errno.EPERM, "no hardlinks")), \
                mock.patch("mini2_backup.transfer.os.write",
                           side_effect=write_then_interrupt):
            with self.assertRaises(TransferInterrupted) as caught:
                self.run_transfer(data, expected=len(data))
        files = caught.exception.files
        self.assertTrue(self.part.exists())
        self.assertFalse(self.final.exists())
        self.assertEqual(self.part.read_bytes(), data)
        self.assertTrue(files["part"]["exists"])
        self.assertFalse(files["final"]["exists"])
        self.assertFalse(files["final"]["sha256_verified"])
        self.assertFalse(files["finalization_complete"])
        self.assertFalse(files["final"]["created_by_this_attempt"])

    def test_fsync_failure_prevents_completion(self):
        data = b"abc"
        with mock.patch("mini2_backup.transfer.os.fsync",
                        side_effect=OSError(errno.EIO, "fsync boom")):
            result, _ = self.run_transfer(data, expected=len(data))
        self.assertFalse(result.ok)
        self.assertIn("fsync failed", result.error)
        self.assertTrue(self.part.exists())
        self.assertEqual(self.part.read_bytes(), data)
        self.assertFalse(self.final.exists())

    def test_successful_fallback_leaves_no_part(self):
        data = b"fallback-data" * 100
        with mock.patch("mini2_backup.transfer.os.link",
                        side_effect=OSError(errno.EPERM, "no hardlinks")):
            result, _ = self.run_transfer(data, expected=len(data))
        self.assertTrue(result.ok, result.error)
        self.assertEqual(self.final.read_bytes(), data)
        self.assertFalse(self.part.exists())

    def test_fallback_write_failure_cleans_own_final(self):
        data = b"abc"
        real_write = os.write
        calls = {"n": 0}

        def flaky_write(fd, block):
            calls["n"] += 1
            if calls["n"] >= 2:
                raise OSError(errno.EIO, "fallback write boom")
            return real_write(fd, block)

        with mock.patch("mini2_backup.transfer.os.link",
                        side_effect=OSError(errno.EPERM, "no hardlinks")), \
                mock.patch("mini2_backup.transfer.os.write",
                           side_effect=flaky_write):
            result, _ = self.run_transfer(data, expected=len(data))
        self.assertFalse(result.ok)
        self.assertIn("fallback write failed", result.error)
        self.assertFalse(self.final.exists())
        self.assertTrue(self.part.exists())
        self.assertEqual(self.part.read_bytes(), data)

    def test_fallback_fsync_failure_cleans_own_final(self):
        data = b"abc"
        real_fsync = os.fsync
        calls = {"n": 0}

        def flaky_fsync(fd):
            calls["n"] += 1
            if calls["n"] == 2:
                raise OSError(errno.EIO, "fallback fsync boom")
            return real_fsync(fd)

        with mock.patch("mini2_backup.transfer.os.link",
                        side_effect=OSError(errno.EPERM, "no hardlinks")), \
                mock.patch("mini2_backup.transfer.os.fsync",
                           side_effect=flaky_fsync):
            result, _ = self.run_transfer(data, expected=len(data))
        self.assertFalse(result.ok)
        self.assertIn("fallback fsync boom", result.error)
        self.assertFalse(self.final.exists())
        self.assertTrue(self.part.exists())

    def test_fallback_close_failure_cleans_own_final(self):
        data = b"abc"
        real_close = os.close
        calls = {"n": 0}

        def flaky_close(fd):
            calls["n"] += 1
            if calls["n"] == 2:
                raise OSError(errno.EIO, "fallback close boom")
            return real_close(fd)

        with mock.patch("mini2_backup.transfer.os.link",
                        side_effect=OSError(errno.EPERM, "no hardlinks")), \
                mock.patch("mini2_backup.transfer.os.close",
                           side_effect=flaky_close):
            result, _ = self.run_transfer(data, expected=len(data))
        self.assertFalse(result.ok)
        self.assertIn("fallback close boom", result.error)
        self.assertFalse(self.final.exists())
        self.assertTrue(self.part.exists())

    def test_fallback_hash_failure_cleans_own_final(self):
        data = b"abc"
        real_sha = hashlib.sha256(data).hexdigest()
        with mock.patch("mini2_backup.transfer.os.link",
                        side_effect=OSError(errno.EPERM, "no hardlinks")), \
                mock.patch("mini2_backup.transfer.stream_sha256",
                           side_effect=[real_sha, "0" * 64]):
            result, _ = self.run_transfer(data, expected=len(data))
        self.assertFalse(result.ok)
        self.assertIn("verification of the final copy failed", result.error)
        self.assertFalse(self.final.exists())
        self.assertTrue(self.part.exists())

    def test_fallback_never_removes_pre_existing_final(self):
        data = b"new-data"
        self.final.write_bytes(b"keep-me")
        real_lexists = os.path.lexists

        def fake_lexists(path):
            if os.path.abspath(path) == os.path.abspath(str(self.final)):
                return False
            return real_lexists(path)

        with mock.patch("mini2_backup.transfer.os.path.lexists",
                        side_effect=fake_lexists), \
                mock.patch("mini2_backup.transfer.os.link",
                           side_effect=OSError(errno.EPERM, "no hardlinks")):
            result, _ = self.run_transfer(data, expected=len(data))
        self.assertFalse(result.ok)
        self.assertIn("refusing to overwrite", result.error)
        self.assertEqual(self.final.read_bytes(), b"keep-me")
        self.assertTrue(self.part.exists())

    def test_partial_write_counts_actual_bytes(self):
        data = b"abcdefghij"
        real_write = os.write
        calls = {"n": 0}

        def partial_write(fd, block):
            calls["n"] += 1
            if calls["n"] == 1:
                return real_write(fd, block[:3])
            raise OSError(errno.ENOSPC, "no space")

        with mock.patch("mini2_backup.transfer.os.write",
                        side_effect=partial_write):
            result, _ = self.run_transfer(data, expected=len(data))
        self.assertFalse(result.ok)
        self.assertEqual(result.bytes_received, len(data))
        self.assertEqual(result.bytes_written, 3)
        self.assertEqual(self.part.stat().st_size, 3)
        self.assertFalse(self.final.exists())

    def test_oversized_stream_reports_received_and_written(self):
        data = b"abcdefghij"
        proc = FakeProcess(data)
        result = stream_to_part_file(
            ["ssh", "fake"], self.part, self.final, 5,
            popen_factory=lambda *a, **k: proc, chunk_size=4,
        )
        self.assertFalse(result.ok)
        self.assertIn("exceeded", result.error)
        self.assertEqual(result.bytes_received, 8)
        self.assertEqual(result.bytes_written, 4)
        self.assertEqual(self.part.stat().st_size, 4)

    def test_directory_fsync_failure_prevents_completion(self):
        data = b"abc"
        with mock.patch("mini2_backup.transfer._fsync_dir_strict",
                        side_effect=OSError(errno.EIO, "dir fsync boom")):
            result, _ = self.run_transfer(data, expected=len(data))
        self.assertFalse(result.ok)
        self.assertIn("directory fsync failed", result.error)
        self.assertFalse(self.final.exists())
        self.assertTrue(self.part.exists())

    def test_stderr_truncation_flag_is_reported(self):
        from mini2_backup.transfer import STDERR_LIMIT
        data = b"abc"
        stderr = b"x" * (STDERR_LIMIT + 100)
        result, _ = self.run_transfer(data, expected=len(data), stderr=stderr)
        self.assertTrue(result.ok, result.error)
        self.assertTrue(result.stderr_truncated)
        self.assertTrue(result.stderr_tail.endswith("x"))

    def test_stderr_tail_keeps_last_bytes_and_marks_truncation(self):
        tail = _StderrTail(10)
        tail.append(b"abcdef")
        tail.append(b"ghijkl")
        self.assertEqual(bytes(tail.data), b"cdefghijkl")
        self.assertTrue(tail.truncated)

    def test_stdout_read_error_fails_and_cleans_process(self):
        proc = FakeProcess(b"", read_error=OSError(errno.EIO, "read boom"))
        result = stream_to_part_file(
            ["ssh", "fake"], self.part, self.final, 10,
            popen_factory=lambda *a, **k: proc,
        )
        self.assertFalse(result.ok)
        self.assertIn("stdout read failed", result.error)
        self.assertTrue(proc.terminated)
        self.assertTrue(proc.closed)
        self.assertTrue(self.part.exists())
        self.assertFalse(self.final.exists())

    def test_rehash_failure_prevents_completion(self):
        data = b"abc"
        with mock.patch("mini2_backup.transfer.stream_sha256",
                        side_effect=OSError(errno.EIO, "hash boom")):
            result, _ = self.run_transfer(data, expected=len(data))
        self.assertFalse(result.ok)
        self.assertIn("could not re-read", result.error)
        self.assertTrue(self.part.exists())
        self.assertFalse(self.final.exists())

    def test_close_failure_prevents_completion(self):
        data = b"abc"
        with mock.patch("mini2_backup.transfer.os.close",
                        side_effect=OSError(errno.EIO, "close boom")):
            result, _ = self.run_transfer(data, expected=len(data))
        self.assertFalse(result.ok)
        self.assertIn("close failed", result.error)
        self.assertTrue(self.part.exists())
        self.assertFalse(self.final.exists())

    def test_original_error_survives_close_failure(self):
        data = b"abc"
        with mock.patch("mini2_backup.transfer.os.write",
                        side_effect=OSError(errno.ENOSPC, "no space")), \
                mock.patch("mini2_backup.transfer.os.close",
                           side_effect=OSError(errno.EIO, "close boom")):
            result, _ = self.run_transfer(data, expected=len(data))
        self.assertFalse(result.ok)
        self.assertIn("disk is full", result.error)
        self.assertNotIn("close boom", result.error)
        self.assertTrue(self.part.exists())

    def test_popen_is_called_without_shell(self):
        calls = {}

        def factory(argv, **kwargs):
            calls.update(kwargs)
            calls["argv"] = argv
            return FakeProcess(b"abc")

        stream_to_part_file(["ssh", "fake"], self.part, self.final, 3,
                            popen_factory=factory)
        self.assertIs(calls["shell"], False)
        self.assertEqual(calls["argv"], ["ssh", "fake"])


if __name__ == "__main__":
    unittest.main()
