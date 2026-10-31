# AI-generated tests. Review before use. See AI_DISCLOSURE.md.
"""Offline verification tests, including path traversal and tar safety."""

from __future__ import annotations

import copy
import json
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from mini2_backup.profile import REFERENCE_BY_ID
from mini2_backup.verify import inspect_tar, verify_backup

from .helpers import make_tar, make_valid_backup, sha256_file


class VerifyTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name) / "backup"
        self.report = make_valid_backup(self.root)

    def tearDown(self):
        self.tmp.cleanup()

    def rewrite_report(self):
        (self.root / "report.json").write_text(
            json.dumps(self.report, indent=2), encoding="utf-8")

    def refresh_checksums(self):
        lines = ["%s  %s" % (e["sha256"], e["path"])
                 for e in self.report["artifacts"]
                 if e.get("status") == "completed" and e.get("sha256") and e.get("path")]
        (self.root / "checksums.sha256").write_text("\n".join(lines) + "\n",
                                                    encoding="utf-8")

    def test_valid_backup_passes(self):
        result = verify_backup(self.root)
        self.assertEqual(result["status"], "ok", result["errors"])
        self.assertEqual(result["artifacts_checked"], 2)
        self.assertFalse(result["restore_tested"])
        self.assertFalse(result["hardware_validation_of_this_tool"])

    def test_corrupted_file_fails(self):
        target = self.root / "images/mtd4.nv.bin"
        data = bytearray(target.read_bytes())
        data[0] ^= 0xFF
        target.write_bytes(bytes(data))
        result = verify_backup(self.root)
        self.assertEqual(result["status"], "failed")
        self.assertTrue(any("SHA-256 mismatch" in e for e in result["errors"]))

    def test_path_traversal_in_report_is_rejected(self):
        self.report["artifacts"][0]["path"] = "../../etc/passwd"
        self.rewrite_report()
        result = verify_backup(self.root)
        self.assertEqual(result["status"], "failed")
        self.assertTrue(any("unsafe path" in e or "escapes" in e
                            for e in result["errors"]))

    def test_absolute_path_in_report_is_rejected(self):
        self.report["artifacts"][0]["path"] = "/etc/passwd"
        self.rewrite_report()
        result = verify_backup(self.root)
        self.assertEqual(result["status"], "failed")
        self.assertTrue(any("absolute path" in e for e in result["errors"]))

    def test_artifact_symlink_is_rejected(self):
        target = self.root / "images/mtd4.nv.bin"
        outside = Path(self.tmp.name) / "outside.bin"
        outside.write_bytes(target.read_bytes())
        target.unlink()
        target.symlink_to(outside)
        result = verify_backup(self.root)
        self.assertEqual(result["status"], "failed")
        self.assertTrue(any("symlink" in e for e in result["errors"]))

    def test_part_file_is_reported(self):
        (self.root / "images/leftover.bin.part").write_bytes(b"partial")
        result = verify_backup(self.root)
        self.assertEqual(result["status"], "failed")
        self.assertTrue(any(".part" in e for e in result["errors"]))

    def test_missing_checksums_fails(self):
        (self.root / "checksums.sha256").unlink()
        result = verify_backup(self.root)
        self.assertEqual(result["status"], "failed")
        self.assertTrue(any("checksums.sha256 is missing" in e
                            for e in result["errors"]))

    def test_checksum_mismatch_fails(self):
        lines = (self.root / "checksums.sha256").read_text().splitlines()
        lines[0] = "0" * 64 + "  " + lines[0].split("  ", 1)[1]
        (self.root / "checksums.sha256").write_text("\n".join(lines) + "\n")
        result = verify_backup(self.root)
        self.assertEqual(result["status"], "failed")
        self.assertTrue(any("checksum mismatch" in e.lower()
                            for e in result["errors"]))

    def test_checksum_self_reference_is_rejected(self):
        with (self.root / "checksums.sha256").open("a", encoding="utf-8") as handle:
            handle.write("%s  checksums.sha256\n" % ("a" * 64))
        result = verify_backup(self.root)
        self.assertEqual(result["status"], "failed")
        self.assertTrue(any("references itself" in e for e in result["errors"]))

    def test_unlisted_completed_artifact_fails(self):
        lines = (self.root / "checksums.sha256").read_text().splitlines()
        (self.root / "checksums.sha256").write_text(lines[0] + "\n")
        result = verify_backup(self.root)
        self.assertEqual(result["status"], "failed")
        self.assertTrue(any("not listed" in e for e in result["errors"]))

    def test_failed_partial_size_mismatch_is_reported(self):
        artifact = self.report["artifacts"][0]
        artifact["status"] = "failed"
        artifact["path"] = None
        artifact["part_path"] = "images/mtd4.nv.bin.part"
        artifact["actual_size"] = 1
        artifact["bytes_written"] = 1
        artifact["error"] = "simulated failure"
        artifact["files"] = {
            "part": {"exists": True, "size": 10, "kind": "file",
                     "path": "images/mtd4.nv.bin.part"},
            "final": {"exists": False, "size": None, "kind": None,
                      "path": "images/mtd4.nv.bin",
                      "sha256_verified": False,
                      "created_by_this_attempt": False},
            "finalization_complete": False,
        }
        self.report["status"] = "failed"
        (self.root / "images/mtd4.nv.bin.part").write_bytes(b"0123456789")
        self.rewrite_report()
        self.refresh_checksums()
        result = verify_backup(self.root)
        self.assertEqual(result["status"], "failed")
        self.assertTrue(any("actual_size mismatch for partial file" in e
                            for e in result["errors"]))

    def test_completed_artifact_with_unverified_final_fails(self):
        self.report["artifacts"][0]["files"]["final"]["sha256_verified"] = False
        self.rewrite_report()
        result = verify_backup(self.root)
        self.assertEqual(result["status"], "failed")
        self.assertTrue(any("not reported as SHA-256 verified" in e
                            for e in result["errors"]))

    def test_completed_artifact_with_part_present_fails(self):
        files = self.report["artifacts"][0]["files"]
        files["part"] = {"exists": True, "size": 1, "kind": "file",
                         "path": "images/mtd4.nv.bin.part"}
        (self.root / "images/mtd4.nv.bin.part").write_bytes(b"x")
        self.rewrite_report()
        result = verify_backup(self.root)
        self.assertEqual(result["status"], "failed")
        self.assertTrue(any("completed but a .part file is reported" in e
                            for e in result["errors"]))

    def test_failed_artifact_preserves_both_files_without_claiming_verified(self):
        artifact = self.report["artifacts"][0]
        size = artifact["actual_size"]
        artifact["status"] = "failed"
        artifact["path"] = None
        artifact["part_path"] = "images/mtd4.nv.bin.part"
        artifact["files"] = {
            "part": {"exists": True, "size": size, "kind": "file",
                     "path": "images/mtd4.nv.bin.part"},
            "final": {"exists": True, "size": size, "kind": "file",
                      "path": "images/mtd4.nv.bin",
                      "sha256_verified": False,
                      "created_by_this_attempt": True},
            "finalization_complete": False,
        }
        (self.root / "images/mtd4.nv.bin.part").write_bytes(
            (self.root / "images/mtd4.nv.bin").read_bytes())
        self.report["status"] = "failed"
        self.rewrite_report()
        self.refresh_checksums()
        result = verify_backup(self.root)
        self.assertEqual(result["status"], "failed")
        self.assertTrue(any("final exists but is not reported as verified" in w
                            for w in result["warnings"]))
        self.assertFalse(any("final SHA-256 mismatch" in e
                             for e in result["errors"]))

    def test_skipped_artifact_in_completed_report_fails(self):
        self.report["artifacts"][0]["status"] = "skipped"
        self.report["artifacts"][0]["path"] = None
        self.report["artifacts"][0]["part_path"] = None
        self.report["artifacts"][0]["error"] = "not attempted"
        self.rewrite_report()
        self.refresh_checksums()
        result = verify_backup(self.root)
        self.assertEqual(result["status"], "failed")
        self.assertTrue(any("skipped in a report marked completed" in e
                            for e in result["errors"]))

    def test_legacy_1_0_report_passes_with_limited_verification_warning(self):
        self.report["schema_version"] = "1.0"
        for artifact in self.report["artifacts"]:
            artifact.pop("bytes_received", None)
            artifact.pop("bytes_written", None)
            artifact.pop("stderr_truncated", None)
            artifact.pop("stderr_tail", None)
            artifact.pop("counters_exact", None)
            artifact.pop("files", None)
        self.rewrite_report()
        result = verify_backup(self.root)
        self.assertEqual(result["status"], "ok", result["errors"])
        self.assertTrue(any("legacy schema 1.0" in w for w in result["warnings"]))

    def test_v11_report_without_files_fails(self):
        for artifact in self.report["artifacts"]:
            artifact.pop("files", None)
        self.rewrite_report()
        result = verify_backup(self.root)
        self.assertEqual(result["status"], "failed")
        self.assertTrue(any("requires a files object" in e
                            for e in result["errors"]))

    def test_bytes_written_mismatch_fails(self):
        self.report["artifacts"][0]["bytes_written"] = 1
        self.rewrite_report()
        result = verify_backup(self.root)
        self.assertEqual(result["status"], "failed")
        self.assertTrue(any("bytes_written mismatch" in e for e in result["errors"]))

    def test_arbitrary_artifact_kind_fails(self):
        self.report["artifacts"][0]["kind"] = "raw_nand"
        self.rewrite_report()
        result = verify_backup(self.root)
        self.assertEqual(result["status"], "failed")
        self.assertTrue(any("unsupported artifact kind" in e
                            for e in result["errors"]))

    def test_mtd0_partition_is_forbidden(self):
        artifact = self.report["artifacts"][0]
        artifact["partition"] = "mtd0"
        artifact["name"] = REFERENCE_BY_ID["mtd0"].name
        artifact["expected_size"] = REFERENCE_BY_ID["mtd0"].size
        self.rewrite_report()
        result = verify_backup(self.root)
        self.assertEqual(result["status"], "failed")
        self.assertTrue(any("mtd0 is forbidden" in e for e in result["errors"]))

    def test_unknown_partition_is_rejected(self):
        artifact = self.report["artifacts"][0]
        artifact["partition"] = "mtd9"
        artifact["name"] = "unknown"
        artifact["expected_size"] = 1
        self.rewrite_report()
        result = verify_backup(self.root)
        self.assertEqual(result["status"], "failed")
        self.assertTrue(any("unsupported mtd_image partition" in e
                            for e in result["errors"]))

    def test_duplicate_partition_is_rejected(self):
        duplicate = copy.deepcopy(self.report["artifacts"][0])
        duplicate["path"] = "images/mtd4.nv.duplicate.bin"
        (self.root / "images/mtd4.nv.duplicate.bin").write_bytes(
            (self.root / "images/mtd4.nv.bin").read_bytes())
        self.report["artifacts"].append(duplicate)
        self.rewrite_report()
        result = verify_backup(self.root)
        self.assertEqual(result["status"], "failed")
        self.assertTrue(any("duplicate partition mtd4" in e
                            for e in result["errors"]))

    def test_tampered_expected_size_is_rejected(self):
        self.report["artifacts"][0]["expected_size"] += 1
        self.rewrite_report()
        result = verify_backup(self.root)
        self.assertEqual(result["status"], "failed")
        self.assertTrue(any("expected_size" in e and "reference" in e
                            for e in result["errors"]))

    def test_mtd_image_name_must_match_reference(self):
        self.report["artifacts"][0]["name"] = "wrong"
        self.rewrite_report()
        result = verify_backup(self.root)
        self.assertEqual(result["status"], "failed")
        self.assertTrue(any("does not match reference" in e
                            for e in result["errors"]))

    def test_tar_partition_must_be_null(self):
        self.report["artifacts"][1]["partition"] = "mtd4"
        self.rewrite_report()
        result = verify_backup(self.root)
        self.assertEqual(result["status"], "failed")
        self.assertTrue(any("tar artifact must have partition=null" in e
                            for e in result["errors"]))

    def test_actual_file_size_must_match_reference(self):
        target = self.root / "images/mtd4.nv.bin"
        target.write_bytes(target.read_bytes()[:-1])
        result = verify_backup(self.root)
        self.assertEqual(result["status"], "failed")
        self.assertTrue(any("size mismatch" in e for e in result["errors"]))

    def test_v11_missing_counter_field_fails(self):
        self.report["artifacts"][0].pop("bytes_received", None)
        self.rewrite_report()
        result = verify_backup(self.root)
        self.assertEqual(result["status"], "failed")
        self.assertTrue(any("requires non-negative integer bytes_received" in e
                            for e in result["errors"]))

    def test_partitions_checked_reports_actual_subset(self):
        result = verify_backup(self.root)
        self.assertEqual(result["status"], "ok", result["errors"])
        self.assertEqual(result["partitions_checked"], ["mtd4"])
        self.assertEqual(result["partitions_in_report"], ["mtd4"])
        self.assertEqual(result["tar_checked"], ["bkupgrade.tar"])

    def test_image_read_error_returns_failed_report(self):
        with mock.patch(
                "mini2_backup.verify.stream_sha256",
                side_effect=OSError(5, "read boom")):
            result = verify_backup(self.root)
        self.assertEqual(result["status"], "failed")
        self.assertTrue(any("cannot compute SHA-256" in e
                            for e in result["errors"]))

    def test_stat_error_returns_failed_report(self):
        with mock.patch(
                "mini2_backup.verify._stat_size",
                side_effect=OSError(5, "stat boom")):
            result = verify_backup(self.root)
        self.assertEqual(result["status"], "failed")
        self.assertTrue(any("cannot stat file" in e for e in result["errors"]))

    def test_tar_inspection_error_returns_failed_report(self):
        with mock.patch(
                "mini2_backup.verify.inspect_tar",
                side_effect=OSError(5, "tar boom")):
            result = verify_backup(self.root)
        self.assertEqual(result["status"], "failed")
        self.assertTrue(any("cannot inspect tar" in e for e in result["errors"]))

    def test_completed_counters_exact_false_fails(self):
        self.report["artifacts"][0]["counters_exact"] = False
        self.rewrite_report()
        result = verify_backup(self.root)
        self.assertEqual(result["status"], "failed")
        self.assertTrue(any("counters_exact is not true" in e
                            for e in result["errors"]))

    def test_completed_bytes_received_mismatch_fails(self):
        self.report["artifacts"][0]["bytes_received"] += 1
        self.rewrite_report()
        result = verify_backup(self.root)
        self.assertEqual(result["status"], "failed")
        self.assertTrue(any("bytes_received mismatch" in e
                            for e in result["errors"]))

    def test_failed_backup_status_fails(self):
        self.report["status"] = "failed"
        self.rewrite_report()
        result = verify_backup(self.root)
        self.assertEqual(result["status"], "failed")

    def test_hardware_validation_claim_is_rejected(self):
        self.report["consistency"]["hardware_validation_of_this_tool"] = True
        self.rewrite_report()
        result = verify_backup(self.root)
        self.assertEqual(result["status"], "failed")
        self.assertTrue(any("hardware validation" in e for e in result["errors"]))

    def test_synthetic_example_cannot_be_verified(self):
        self.report["synthetic_example"] = True
        self.rewrite_report()
        result = verify_backup(self.root)
        self.assertEqual(result["status"], "failed")

    def test_unsupported_schema_fails(self):
        self.report["schema_version"] = "9.9"
        self.rewrite_report()
        result = verify_backup(self.root)
        self.assertEqual(result["status"], "failed")

    def test_missing_report_fails(self):
        (self.root / "report.json").unlink()
        result = verify_backup(self.root)
        self.assertEqual(result["status"], "failed")

    def test_tar_traversal_is_rejected(self):
        members = [("../evil", b"x", "file")]
        make_tar(self.root / "bkupgrade.tar", members)
        self.report["artifacts"][1]["sha256"] = sha256_file(self.root / "bkupgrade.tar")
        self.report["artifacts"][1]["actual_size"] = (self.root / "bkupgrade.tar").stat().st_size
        self.rewrite_report()
        self.refresh_checksums()
        result = verify_backup(self.root)
        self.assertEqual(result["status"], "failed")
        self.assertTrue(any("parent traversal" in e for e in result["errors"]))

    def test_tar_inspection_never_extracts(self):
        marker = self.root / "images" / "marker"
        members = [("./marker", b"created-by-extraction", "file")]
        make_tar(self.root / "bkupgrade.tar", members)
        info = inspect_tar(self.root / "bkupgrade.tar")
        self.assertEqual(info["regular_files"], 1)
        self.assertFalse(marker.exists())

    def test_compressed_tar_is_rejected(self):
        path = self.root / "bkupgrade.tar"
        path.write_bytes(b"\x1f\x8b" + b"\x00" * 100)
        with self.assertRaises(ValueError):
            inspect_tar(path)

    def test_verify_works_on_copy_of_backup(self):
        copy_root = Path(self.tmp.name) / "copied"
        shutil.copytree(str(self.root), str(copy_root), symlinks=True)
        result = verify_backup(copy_root)
        self.assertEqual(result["status"], "ok", result["errors"])


if __name__ == "__main__":
    unittest.main()
