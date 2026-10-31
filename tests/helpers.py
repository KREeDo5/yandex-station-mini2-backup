# AI-generated tests. Review before use. See AI_DISCLOSURE.md.
"""Test doubles and synthetic fixtures.

No test opens a network connection.  SSH argv construction and stream
handling are tested with injected fakes.
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import tarfile
from pathlib import Path

from mini2_backup.profile import (
    ERASESIZE,
    OOBSIZE,
    REFERENCE_BY_ID,
    REFERENCE_LAYOUT,
    WRITESIZE,
)

PROC_MTD = """dev:    size   erasesize  name
mtd0: 00200000 00020000 "bootloader"
mtd1: 00200000 00020000 "tpl"
mtd2: 00a00000 00020000 "boot"
mtd3: 05000000 00020000 "system"
mtd4: 00100000 00020000 "nv"
mtd5: 06940000 00020000 "bkupgrade"
mtd6: 031c0000 00020000 "recovery"
"""


def sysfs_probe() -> str:
    lines = []
    for part in REFERENCE_LAYOUT:
        lines.append("DEV %s" % part.id)
        lines.append("ATTR size %d" % part.size)
        lines.append("ATTR erasesize %d" % ERASESIZE)
        lines.append("ATTR writesize %d" % WRITESIZE)
        lines.append("ATTR oobsize %d" % OOBSIZE)
        lines.append("ATTR name %s" % part.name)
    return "\n".join(lines) + "\n"


def make_identity(root: Path) -> Path:
    path = root / "id_test"
    path.write_text("not-a-real-private-key\n", encoding="utf-8")
    os.chmod(path, 0o600)
    return path


class FakeProcess:
    def __init__(self, data: bytes = b"", code: int = 0, stderr: bytes = b"",
                 interrupt: bool = False, read_error=None,
                 interrupt_after: int = None):
        self._data = data
        self._interrupt = interrupt
        self._read_error = read_error
        self._interrupt_after = interrupt_after
        self.stdout = self
        self.stderr = io.BytesIO(stderr)
        self.returncode = None
        self._code = code
        self.terminated = False
        self.killed = False
        self.closed = False
        self._offset = 0

    def read(self, size: int = -1) -> bytes:
        if self._read_error is not None:
            raise self._read_error
        if self._interrupt_after is not None and self._offset >= self._interrupt_after:
            raise KeyboardInterrupt
        if self._interrupt:
            raise KeyboardInterrupt
        if size is None or size < 0:
            size = len(self._data) - self._offset
        chunk = self._data[self._offset:self._offset + size]
        self._offset += len(chunk)
        return chunk

    def wait(self, timeout=None):
        if self.returncode is None:
            self.returncode = -15 if self.terminated else self._code
        return self.returncode

    def poll(self):
        return self.returncode

    def terminate(self):
        self.terminated = True
        self.returncode = -15

    def kill(self):
        self.killed = True
        self.returncode = -9

    def close(self):
        self.closed = True


class FakePopenFactory:
    """Return a fake process based on the remote command in argv[-1]."""

    def __init__(self, image_data=None, tar_data=b"fake-tar-stream",
                 image_code: int = 0, tar_code: int = 0):
        self.image_data = image_data or (lambda _id: b"")
        self.tar_data = tar_data
        self.image_code = image_code
        self.tar_code = tar_code
        self.calls = []

    def __call__(self, argv, **kwargs):
        command = argv[-1]
        self.calls.append(command)
        if command.startswith("nanddump"):
            partition = command.rsplit("/dev/", 1)[-1]
            return FakeProcess(self.image_data(partition), code=self.image_code)
        if command.startswith("tar "):
            return FakeProcess(self.tar_data, code=self.tar_code)
        return FakeProcess(b"", code=1, stderr=b"unexpected command")


def check_runner(proc_text=PROC_MTD, sysfs_text=None, nanddump_text=None,
                 tar_text=("tar (GNU tar) 1.34\n---TAR-HELP---\n"
                           "  -c, --create\n  -f, --file=ARCHIVE\n"
                           "  -C, --directory=DIR\n"),
                 uname="Linux 4.9.68 aarch64",
                 model="Yandex Station Mini 2 YNDX-00020", uid="0",
                 failing_command=None):
    sysfs_text = sysfs_text if sysfs_text is not None else sysfs_probe()
    nanddump_text = nanddump_text if nanddump_text is not None else (
        "nanddump 2.1.2\n"
        "Usage: nanddump [OPTIONS] MTD_DEVICE\n"
        "  --bb=padbad\n"
        "  --omitoob\n"
    )

    def runner(_target, command):
        if failing_command and failing_command in command:
            return 255, b"", b"Host key verification failed."
        if command == "id -u":
            return 0, uid.encode(), b""
        if command == "cat /proc/mtd":
            return 0, proc_text.encode(), b""
        if command == "uname -srm":
            return 0, uname.encode(), b""
        if "device-tree/model" in command:
            return 0, model.encode(), b""
        if command.startswith("for d in /sys/class/mtd"):
            return 0, sysfs_text.encode(), b""
        if "nanddump --help" in command:
            return 0, nanddump_text.encode(), b""
        if "tar --version" in command:
            return 0, tar_text.encode(), b""
        return 1, b"", b"unexpected"

    return runner


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            block = handle.read(1024 * 1024)
            if not block:
                break
            digest.update(block)
    return digest.hexdigest()


def make_tar(path: Path, members=None) -> None:
    members = members or [
        ("./", b"", "dir"),
        ("./etc/", b"", "dir"),
        ("./etc/config", b"value=1\n", "file"),
    ]
    with tarfile.open(str(path), "w") as archive:
        for name, data, kind in members:
            info = tarfile.TarInfo(name)
            if kind == "dir":
                info.type = tarfile.DIRTYPE
                info.mode = 0o755
                archive.addfile(info)
            elif kind == "file":
                info.size = len(data)
                info.mode = 0o600
                archive.addfile(info, io.BytesIO(data))
            else:
                raise ValueError(kind)


def make_valid_backup(root: Path, tar_members=None) -> dict:
    root.mkdir(parents=True, exist_ok=True)
    images = root / "images"
    images.mkdir()
    image_data = b"I" * REFERENCE_BY_ID["mtd4"].size
    image_path = images / "mtd4.nv.bin"
    image_path.write_bytes(image_data)
    tar_path = root / "bkupgrade.tar"
    make_tar(tar_path, tar_members)

    report = {
        "schema_version": "1.1",
        "tool": {"name": "yandex-station-mini2-backup", "version": "0.1.0"},
        "generated_by_ai": True,
        "synthetic_example": False,
        "started_at": "2026-01-01T00:00:00Z",
        "completed_at": "2026-01-01T00:01:00Z",
        "status": "completed",
        "host": {"hostname": "example.invalid", "port": 2222, "user": "root"},
        "device": {"firmware_source": "user_provided"},
        "layout": {"profile_match": True, "offsets_verified": False},
        "preflight": {},
        "checks": [],
        "artifacts": [
            {
                "partition": "mtd4",
                "name": "nv",
                "kind": "mtd_image",
                "path": "images/mtd4.nv.bin",
                "part_path": None,
                "status": "completed",
                "expected_size": len(image_data),
                "actual_size": len(image_data),
                "bytes_received": len(image_data),
                "bytes_written": len(image_data),
                "sha256": sha256_bytes(image_data),
                "exit_code": 0,
                "error": None,
                "stderr_tail": "",
                "stderr_truncated": False,
                "counters_exact": True,
                "files": {
                    "part": {"exists": False, "size": None, "kind": None,
                             "path": "images/mtd4.nv.bin.part"},
                    "final": {"exists": True, "size": len(image_data), "kind": "file",
                              "path": "images/mtd4.nv.bin",
                              "sha256_verified": True,
                              "created_by_this_attempt": True},
                    "finalization_complete": True,
                },
            },
            {
                "partition": None,
                "name": "bkupgrade",
                "kind": "tar",
                "path": "bkupgrade.tar",
                "part_path": None,
                "status": "completed",
                "expected_size": None,
                "actual_size": tar_path.stat().st_size,
                "bytes_received": tar_path.stat().st_size,
                "bytes_written": tar_path.stat().st_size,
                "sha256": sha256_file(tar_path),
                "exit_code": 0,
                "error": None,
                "stderr_tail": "",
                "stderr_truncated": False,
                "counters_exact": True,
                "files": {
                    "part": {"exists": False, "size": None, "kind": None,
                             "path": "bkupgrade.tar.part"},
                    "final": {"exists": True,
                              "size": tar_path.stat().st_size, "kind": "file",
                              "path": "bkupgrade.tar",
                              "sha256_verified": True,
                              "created_by_this_attempt": True},
                    "finalization_complete": True,
                },
            },
        ],
        "consistency": {
            "physical_nand_oob_backup": False,
            "mtd0_complete": False,
            "reserved_areas_backed_up": False,
            "offline_consistent_snapshot": False,
            "independent_nand_reread": False,
            "restore_tested": False,
            "hardware_validation_of_this_tool": False,
        },
        "consistency_notes": [],
        "warnings": [],
        "errors": [],
    }
    (root / "report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    checksums = [
        "%s  %s" % (entry["sha256"], entry["path"])
        for entry in report["artifacts"]
    ]
    (root / "checksums.sha256").write_text("\n".join(checksums) + "\n", encoding="utf-8")
    return report
