# AI-generated tests. Review before use. See AI_DISCLOSURE.md.
"""MTD parsing, profile gate, target validation and SSH argv tests."""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from mini2_backup.errors import GateError, UsageError
from mini2_backup.profile import (
    ALLOWED_BACKUP_IDS,
    ERASESIZE,
    WRITESIZE,
    evaluate_profile,
    parse_proc_mtd,
    parse_sysfs_probe,
    validate_backup_ids,
)
from mini2_backup.ssh import (
    LocalPreflight,
    SshTarget,
    build_ssh_argv,
    local_preflight,
    validate_target,
)

from .helpers import PROC_MTD, make_identity, sysfs_probe


class ProcMtdParserTests(unittest.TestCase):
    def test_parses_all_seven_partitions(self):
        parsed = parse_proc_mtd(PROC_MTD)
        self.assertEqual(set(parsed), {"mtd%d" % i for i in range(7)})
        self.assertEqual(parsed["mtd1"].size, 2 * 1024 * 1024)
        self.assertEqual(parsed["mtd5"].name, "bkupgrade")
        self.assertEqual(parsed["mtd6"].erasesize, 131072)

    def test_rejects_malformed_line(self):
        with self.assertRaises(ValueError):
            parse_proc_mtd("dev: size erasesize name\nnot an mtd line\n")

    def test_rejects_duplicate(self):
        with self.assertRaises(ValueError):
            parse_proc_mtd(PROC_MTD + '\nmtd1: 00200000 00020000 "tpl"')

    def test_rejects_empty(self):
        with self.assertRaises(ValueError):
            parse_proc_mtd("dev:    size   erasesize  name\n")


class SysfsParserTests(unittest.TestCase):
    def test_parses_probe(self):
        parsed = parse_sysfs_probe(sysfs_probe())
        self.assertEqual(parsed["mtd0"]["writesize"], "2048")
        self.assertEqual(parsed["mtd6"]["oobsize"], "64")

    def test_rejects_attribute_before_device(self):
        with self.assertRaises(ValueError):
            parse_sysfs_probe("ATTR size 1\n")

    def test_rejects_duplicate_device(self):
        text = "DEV mtd0\nATTR size 1\nDEV mtd0\nATTR size 1\n"
        with self.assertRaises(ValueError):
            parse_sysfs_probe(text)


class ProfileGateTests(unittest.TestCase):
    def setUp(self):
        self.proc = parse_proc_mtd(PROC_MTD)
        self.sysfs = parse_sysfs_probe(sysfs_probe())

    def test_matching_profile_passes(self):
        result = evaluate_profile(self.proc, self.sysfs)
        self.assertTrue(result.ok, result.issues)
        self.assertFalse(result.offsets_verified)
        self.assertEqual(result.devices["mtd0"]["expected_offset"], 0)

    def test_size_mismatch_blocks(self):
        self.proc["mtd5"] = self.proc["mtd5"].__class__(
            id="mtd5", size=123, erasesize=131072, name="bkupgrade")
        result = evaluate_profile(self.proc, self.sysfs)
        self.assertFalse(result.ok)
        self.assertTrue(any(i.field == "size" and i.device == "mtd5"
                            for i in result.issues))

    def test_missing_partition_blocks(self):
        del self.proc["mtd3"]
        result = evaluate_profile(self.proc, self.sysfs)
        self.assertFalse(result.ok)
        self.assertTrue(any(i.device == "mtd3" and i.field == "presence"
                            for i in result.issues))

    def test_extra_partition_blocks(self):
        self.proc["mtd7"] = self.proc["mtd6"].__class__(
            id="mtd7", size=1, erasesize=131072, name="extra")
        result = evaluate_profile(self.proc, self.sysfs)
        self.assertFalse(result.ok)
        self.assertTrue(any(i.device == "mtd7" for i in result.issues))

    def test_unreadable_writesize_is_not_substituted(self):
        del self.sysfs["mtd1"]["writesize"]
        result = evaluate_profile(self.proc, self.sysfs)
        self.assertFalse(result.ok)
        self.assertTrue(any(i.field == "sysfs.writesize" and i.device == "mtd1"
                            for i in result.issues))

    def test_wrong_geometry_blocks(self):
        self.sysfs["mtd2"]["oobsize"] = "128"
        result = evaluate_profile(self.proc, self.sysfs)
        self.assertFalse(result.ok)

    def test_geometry_constants(self):
        self.assertEqual(ERASESIZE, 131072)
        self.assertEqual(WRITESIZE, 2048)


class BackupSelectionTests(unittest.TestCase):
    def test_allowed_list_excludes_mtd0(self):
        self.assertNotIn("mtd0", ALLOWED_BACKUP_IDS)
        self.assertEqual(ALLOWED_BACKUP_IDS,
                         ("mtd1", "mtd2", "mtd3", "mtd4", "mtd5", "mtd6"))

    def test_mtd0_has_dedicated_error(self):
        with self.assertRaises(ValueError) as caught:
            validate_backup_ids(["mtd0"])
        self.assertIn("mtd0 is intentionally unsupported", str(caught.exception))

    def test_arbitrary_device_is_rejected(self):
        with self.assertRaises(ValueError):
            validate_backup_ids(["/dev/sda"])
        with self.assertRaises(ValueError):
            validate_backup_ids(["mtd9"])

    def test_deduplicates_preserving_order(self):
        self.assertEqual(validate_backup_ids(["mtd4", "mtd1", "mtd4"]),
                         ["mtd4", "mtd1"])

    def test_empty_is_rejected(self):
        with self.assertRaises(ValueError):
            validate_backup_ids([])


class SshTargetTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.identity = make_identity(self.root)

    def tearDown(self):
        self.tmp.cleanup()

    def target(self, **kwargs):
        data = {"host": "192.0.2.10", "port": 2222, "user": "root",
                "identity": str(self.identity)}
        data.update(kwargs)
        return SshTarget(**data)

    def test_builds_strict_key_only_argv(self):
        argv = build_ssh_argv(self.target(), "id -u")
        self.assertIn("-T", argv)
        self.assertNotIn("-t", argv)
        self.assertIn("BatchMode=yes", argv)
        self.assertIn("StrictHostKeyChecking=yes", argv)
        self.assertNotIn("StrictHostKeyChecking=no", argv)
        self.assertIn("PasswordAuthentication=no", argv)
        self.assertIn("IdentitiesOnly=yes", argv)
        self.assertEqual(argv[-1], "id -u")
        self.assertEqual(argv[argv.index("-p") + 1], "2222")
        self.assertEqual(argv[argv.index("-l") + 1], "root")
        self.assertEqual(argv[argv.index("-i") + 1], str(self.identity))

    def test_rejects_option_injection_host(self):
        for host in ("-oProxyCommand=evil", "host name", "host;rm", "user@host"):
            with self.assertRaises(UsageError):
                validate_target(self.target(host=host))

    def test_rejects_bad_ports(self):
        for port in (0, 65536, -1, True):
            with self.assertRaises(UsageError):
                validate_target(self.target(port=port))

    def test_rejects_bad_user(self):
        with self.assertRaises(UsageError):
            validate_target(self.target(user="root;id"))

    def test_rejects_missing_identity(self):
        with self.assertRaises(UsageError):
            validate_target(self.target(identity=str(self.root / "missing")))

    def test_rejects_directory_identity(self):
        with self.assertRaises(UsageError):
            validate_target(self.target(identity=str(self.root)))

    def test_does_not_read_identity_contents(self):
        marker = "SUPER-SECRET-KEY-MATERIAL"
        self.identity.write_text(marker, encoding="utf-8")
        argv = build_ssh_argv(self.target(), "true")
        self.assertNotIn(marker, " ".join(argv))


class LocalPreflightTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.identity = make_identity(self.root)
        self.known = self.root / "known_hosts"
        self.known.write_text("example.invalid ssh-ed25519 AAAA\n", encoding="utf-8")
        self.target = SshTarget(host="192.0.2.10", identity=str(self.identity))

    def tearDown(self):
        self.tmp.cleanup()

    def test_linux_platform_is_rejected(self):
        with mock.patch("mini2_backup.ssh.shutil.which", return_value="/usr/bin/ssh"):
            result = local_preflight(
                self.target, platform="linux", env={}, known_hosts=[self.known],
            )
        self.assertFalse(result.ok)
        self.assertTrue(any(c["id"] == "platform" and c["status"] == "failed"
                            for c in result.checks))

    def test_inside_ssh_is_rejected(self):
        with mock.patch("mini2_backup.ssh.shutil.which", return_value="/usr/bin/ssh"):
            result = local_preflight(
                self.target, platform="darwin",
                env={"SSH_CONNECTION": "1 2 3 4"}, known_hosts=[self.known],
            )
        self.assertFalse(result.ok)
        self.assertTrue(any(c["id"] == "not_inside_ssh" and c["status"] == "failed"
                            for c in result.checks))

    def test_missing_known_hosts_is_rejected(self):
        with mock.patch("mini2_backup.ssh.shutil.which", return_value="/usr/bin/ssh"):
            result = local_preflight(
                self.target, platform="darwin", env={},
                known_hosts=[self.root / "missing_known_hosts"],
            )
        self.assertFalse(result.ok)
        self.assertTrue(any(c["id"] == "known_hosts" and c["status"] == "failed"
                            for c in result.checks))

    def test_missing_ssh_is_rejected(self):
        with mock.patch("mini2_backup.ssh.shutil.which", return_value=None):
            result = local_preflight(
                self.target, platform="darwin", env={}, known_hosts=[self.known],
            )
        self.assertFalse(result.ok)
        self.assertTrue(any(c["id"] == "ssh_binary" and c["status"] == "failed"
                            for c in result.checks))

    def test_all_gates_pass_with_fake_environment(self):
        completed = mock.Mock(stdout=b"OpenSSH_9.0", stderr=b"", returncode=0)
        with mock.patch("mini2_backup.ssh.shutil.which", return_value="/usr/bin/ssh"), \
                mock.patch("mini2_backup.ssh.subprocess.run", return_value=completed):
            result = local_preflight(
                self.target, platform="darwin", env={}, known_hosts=[self.known],
            )
        self.assertTrue(result.ok, result.checks)
        self.assertEqual(result.ssh_version, "OpenSSH_9.0")


if __name__ == "__main__":
    unittest.main()
