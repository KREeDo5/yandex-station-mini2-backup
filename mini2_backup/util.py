# AI-generated code. Review before use. See AI_DISCLOSURE.md.
"""Small shared helpers: timestamps, hashing, path safety, formatting."""

from __future__ import annotations

import hashlib
import os
import stat
import time
from pathlib import Path, PurePosixPath
from typing import BinaryIO, Iterator, Optional

HASH_CHUNK = 1024 * 1024


def utc_now() -> str:
    """Return an ISO-8601 UTC timestamp with a trailing ``Z``."""
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def stream_sha256(path: Path, chunk_size: int = HASH_CHUNK) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            block = handle.read(chunk_size)
            if not block:
                break
            digest.update(block)
    return digest.hexdigest()


def hash_reader(reader: BinaryIO, chunk_size: int = HASH_CHUNK) -> str:
    digest = hashlib.sha256()
    while True:
        block = reader.read(chunk_size)
        if not block:
            break
        digest.update(block)
    return digest.hexdigest()


def human_bytes(value: Optional[int]) -> str:
    if value is None:
        return "unknown"
    units = ("B", "KiB", "MiB", "GiB", "TiB")
    size = float(value)
    for unit in units:
        if size < 1024 or unit == units[-1]:
            if unit == "B":
                return "%d %s" % (int(size), unit)
            return "%.2f %s" % (size, unit)
        size /= 1024.0
    return "%d B" % value


def is_within(child: Path, parent: Path) -> bool:
    """True if ``child`` is equal to or below ``parent`` after resolution."""
    try:
        child_r = child.resolve()
        parent_r = parent.resolve()
    except OSError:
        return False
    try:
        child_r.relative_to(parent_r)
        return True
    except ValueError:
        return False


def safe_relative_path(value: str) -> PurePosixPath:
    """Validate a report path and return it as a relative POSIX path.

    Rejects absolute paths, ``..`` components, NUL bytes and empty values.
    """
    if not isinstance(value, str) or not value.strip():
        raise ValueError("empty path in report")
    if "\x00" in value:
        raise ValueError("NUL byte in report path")
    if value.startswith("/") or value.startswith("\\"):
        raise ValueError("absolute path in report: %r" % value)
    # Windows drive letters and UNC-ish prefixes are rejected too.
    if len(value) >= 2 and value[1] == ":":
        raise ValueError("drive-qualified path in report: %r" % value)
    normalized = value.replace("\\", "/")
    pure = PurePosixPath(normalized)
    if pure.is_absolute():
        raise ValueError("absolute path in report: %r" % value)
    parts = pure.parts
    if not parts:
        raise ValueError("empty path in report")
    if any(part in ("", ".", "..") for part in parts):
        raise ValueError("unsafe path component in report: %r" % value)
    return pure


def resolve_inside(root: Path, relative: str) -> Path:
    """Resolve ``relative`` under ``root`` and refuse symlink escapes."""
    pure = safe_relative_path(relative)
    candidate = root.joinpath(*pure.parts)
    if candidate.is_symlink():
        raise ValueError("artifact path is a symlink: %r" % relative)
    resolved_root = root.resolve()
    try:
        resolved = candidate.resolve(strict=False)
    except OSError as exc:
        raise ValueError("cannot resolve %r: %s" % (relative, exc))
    try:
        resolved.relative_to(resolved_root)
    except ValueError:
        raise ValueError("path escapes the backup directory: %r" % relative)
    return candidate


def ensure_regular_file(path: Path, label: str = "file") -> None:
    try:
        info = path.lstat()
    except OSError as exc:
        raise ValueError("%s is missing: %s" % (label, exc))
    if not stat.S_ISREG(info.st_mode):
        raise ValueError("%s is not a regular file" % label)


def write_text_exclusive(path: Path, text: str) -> None:
    """Create ``path`` exclusively; never overwrite."""
    fd = os.open(str(path), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    try:
        data = text.encode("utf-8")
        offset = 0
        while offset < len(data):
            written = os.write(fd, data[offset:])
            if written <= 0:
                raise OSError("short write")
            offset += written
        os.fsync(fd)
    finally:
        os.close(fd)


def fsync_dir(path: Path) -> None:
    """Best-effort directory fsync on platforms that support it."""
    try:
        fd = os.open(str(path), os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(fd)
    except OSError:
        pass
    finally:
        os.close(fd)


def iter_file_blocks(a: Path, b: Path, chunk_size: int = HASH_CHUNK) -> Iterator[str]:
    """Compare two files byte-by-byte, yielding a mismatch description.

    Yields nothing when the files are identical.  This never loads a whole
    firmware image into memory.
    """
    with a.open("rb") as left, b.open("rb") as right:
        offset = 0
        while True:
            left_block = left.read(chunk_size)
            right_block = right.read(chunk_size)
            if left_block != right_block:
                yield "content differs near offset %d" % offset
                return
            if not left_block:
                return
            offset += len(left_block)
