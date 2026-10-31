# AI-generated tests. Review before use. See AI_DISCLOSURE.md.
"""External copy tests: byte comparison, symlinks, empty dirs, no overwrite."""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

from mini2_backup.copy_external import (
    compare_trees,
    copy_external,
    scan_tree,
)
from mini2_backup.errors import UsageError


class CopyExternalTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.base = Path(self.tmp.name)
        self.source = self.base / "source"
        self.destination_root = self.base / "destination"
        self.source.mkdir()
        self.destination_root.mkdir()
        (self.source / "images").mkdir()
        (self.source / "images" / "mtd4.bin").write_bytes(b"abc" * 1000)
        (self.source / "empty").mkdir()
        (self.source / "nested").mkdir()
        (self.source / "nested" / "report.json").write_text('{"x":1}\n',
                                                           encoding="utf-8")
        (self.source / "link").symlink_to("images/mtd4.bin")

    def tearDown(self):
        self.tmp.cleanup()

    def test_copies_and_verifies_everything(self):
        report = copy_external(
            self.source, self.destination_root,
            allow_non_volume=True, platform="darwin",
        )
        self.assertEqual(report["status"], "completed", report["errors"])
        dest = Path(report["destination_copy"])
        self.assertTrue((dest / "empty").is_dir())
        self.assertEqual(os.readlink(str(dest / "link")), "images/mtd4.bin")
        self.assertEqual(compare_trees(self.source, dest), [])
        self.assertFalse(report["permissions_dates_xattrs_compared"])
        self.assertEqual(report["physical_independence"], "not_verified")

    def test_report_is_outside_copied_tree(self):
        report_path = self.base / "copy-report.json"
        report = copy_external(
            self.source, self.destination_root, report_path=report_path,
            allow_non_volume=True, platform="linux",
        )
        self.assertTrue(report_path.exists())
        self.assertNotEqual(Path(report["destination_copy"]), report_path.parent)
        self.assertNotIn(report_path, list(Path(report["destination_copy"]).rglob("*")))

    def test_source_is_not_modified(self):
        before = scan_tree(self.source)
        copy_external(self.source, self.destination_root,
                      allow_non_volume=True, platform="linux")
        self.assertEqual(scan_tree(self.source), before)

    def test_two_copies_use_unique_directories(self):
        first = copy_external(self.source, self.destination_root,
                              allow_non_volume=True, platform="linux")
        second = copy_external(self.source, self.destination_root,
                               allow_non_volume=True, platform="linux")
        self.assertNotEqual(first["destination_copy"], second["destination_copy"])

    def test_destination_inside_source_is_rejected(self):
        with self.assertRaises(UsageError):
            copy_external(self.source, self.source / "copy",
                          allow_non_volume=True, platform="linux")

    def test_report_inside_source_is_rejected(self):
        with self.assertRaises(UsageError):
            copy_external(self.source, self.destination_root,
                          report_path=self.source / "report.json",
                          allow_non_volume=True, platform="linux")

    def test_existing_report_is_not_overwritten(self):
        report_path = self.base / "report.json"
        report_path.write_text("keep", encoding="utf-8")
        with self.assertRaises(UsageError):
            copy_external(self.source, self.destination_root,
                          report_path=report_path,
                          allow_non_volume=True, platform="linux")
        self.assertEqual(report_path.read_text(encoding="utf-8"), "keep")

    def test_macos_non_volume_requires_flag(self):
        with self.assertRaises(UsageError) as caught:
            copy_external(self.source, self.destination_root, platform="darwin")
        self.assertIn("--allow-non-volume", str(caught.exception))

    def test_missing_destination_root_is_rejected(self):
        with self.assertRaises(UsageError):
            copy_external(self.source, self.base / "missing",
                          allow_non_volume=True, platform="linux")

    def test_special_file_causes_explicit_failure(self):
        fifo = self.source / "fifo"
        os.mkfifo(str(fifo))
        report = copy_external(self.source, self.destination_root,
                               allow_non_volume=True, platform="linux")
        self.assertEqual(report["status"], "failed")
        self.assertTrue(any("special file" in e for e in report["errors"]))

    def test_symlink_target_difference_is_detected(self):
        report = copy_external(self.source, self.destination_root,
                               allow_non_volume=True, platform="linux")
        dest = Path(report["destination_copy"])
        (dest / "link").unlink()
        (dest / "link").symlink_to("other-target")
        mismatches = compare_trees(self.source, dest)
        self.assertTrue(any("symlink target mismatch" in m for m in mismatches))

    def test_byte_difference_is_detected(self):
        report = copy_external(self.source, self.destination_root,
                               allow_non_volume=True, platform="linux")
        dest = Path(report["destination_copy"])
        target = dest / "images/mtd4.bin"
        data = bytearray(target.read_bytes())
        data[5] ^= 0xFF
        target.write_bytes(bytes(data))
        mismatches = compare_trees(self.source, dest)
        self.assertTrue(any("content differs" in m for m in mismatches))

    def test_empty_directory_presence_is_detected(self):
        report = copy_external(self.source, self.destination_root,
                               allow_non_volume=True, platform="linux")
        dest = Path(report["destination_copy"])
        (dest / "empty").rmdir()
        mismatches = compare_trees(self.source, dest)
        self.assertTrue(any("empty" in m for m in mismatches))


if __name__ == "__main__":
    unittest.main()
