# AI-generated code. Review before use. See AI_DISCLOSURE.md.
"""Bounded, streaming file transfer with strict finalisation rules.

A remote image is written to ``.part`` first.  It becomes a final file only
after: exit code 0, exact expected length, a successful local ``fsync`` and a
close, a streaming SHA-256, and a second SHA-256 computed from the local file.
A final path is created exclusively; existing files are never overwritten.  On
any failure the partial file is kept for inspection.

The hardlink path is the normal finalisation.  Filesystems without hardlinks
use a non-atomic copy fallback, which is explicitly *not* claimed to be atomic.
The fallback removes only a final file created by the current attempt.
"""

from __future__ import annotations

import errno
import hashlib
import os
import stat
import subprocess
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, List, Optional, Tuple

from .util import fsync_dir, human_bytes, stream_sha256

DEFAULT_CHUNK = 1024 * 1024
STDERR_LIMIT = 64 * 1024
STDERR_READ_CHUNK = 8192


class TransferInterrupted(KeyboardInterrupt):
    """Raised instead of a bare KeyboardInterrupt so the caller can report state."""

    def __init__(self, part_path: Path, bytes_received: int, bytes_written: int,
                 files: dict):
        super().__init__("transfer interrupted; partial file kept: %s" % part_path)
        self.part_path = str(part_path)
        self.bytes_received = bytes_received
        self.bytes_written = bytes_written
        self.files = files


@dataclass
class TransferResult:
    status: str  # "completed" or "failed"
    bytes_received: int
    bytes_written: int
    sha256: Optional[str]
    exit_code: Optional[int]
    error: Optional[str]
    stderr_tail: str
    stderr_truncated: bool = False
    files: dict = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return self.status == "completed"

    def as_dict(self) -> dict:
        return {
            "status": self.status,
            "bytes_received": self.bytes_received,
            "bytes_written": self.bytes_written,
            "sha256": self.sha256,
            "exit_code": self.exit_code,
            "error": self.error,
            "stderr_tail": self.stderr_tail,
            "stderr_truncated": self.stderr_truncated,
            "files": self.files,
        }


class _WriteFailure(Exception):
    def __init__(self, written: int, cause: OSError):
        super().__init__(str(cause))
        self.written = written
        self.cause = cause


class _WriteInterrupted(KeyboardInterrupt):
    def __init__(self, written: int):
        super().__init__("interrupted during local write")
        self.written = written


@dataclass
class _StderrTail:
    """Bounded buffer that keeps the *last* bytes, not the first ones."""

    limit: int
    data: bytearray = field(default_factory=bytearray)
    total: int = 0
    truncated: bool = False
    read_error: Optional[str] = None

    def append(self, chunk: bytes) -> None:
        if not chunk:
            return
        self.total += len(chunk)
        if self.limit <= 0:
            self.data.clear()
            self.truncated = True
            return
        if len(chunk) >= self.limit:
            self.data[:] = chunk[-self.limit:]
            self.truncated = True
            return
        overflow = len(self.data) + len(chunk) - self.limit
        if overflow > 0:
            del self.data[:overflow]
            self.truncated = True
        self.data.extend(chunk)

    def text(self) -> str:
        return self.data.decode("utf-8", "replace").strip()


def _failed(message: str, *, received: int = 0, written: int = 0,
            sha256: Optional[str] = None, exit_code: Optional[int] = None,
            stderr_tail: str = "", stderr_truncated: bool = False,
            files: Optional[dict] = None) -> TransferResult:
    return TransferResult("failed", received, written, sha256, exit_code,
                          message, stderr_tail, stderr_truncated, files or {})


def _snapshot_one(path: Path) -> dict:
    try:
        info = path.lstat()
    except FileNotFoundError:
        return {"exists": False, "size": None, "kind": None}
    except OSError as exc:
        return {"exists": None, "size": None, "kind": None, "error": str(exc)}
    if stat.S_ISREG(info.st_mode):
        kind = "file"
    elif stat.S_ISLNK(info.st_mode):
        kind = "symlink"
    elif stat.S_ISDIR(info.st_mode):
        kind = "dir"
    else:
        kind = "other"
    return {"exists": True, "size": info.st_size, "kind": kind}


def snapshot_files(part_path: Path, final_path: Path, *,
                   final_created_by_attempt: object = "unknown",
                   final_verified: bool = False,
                   finalization_complete: bool = False) -> dict:
    """Record the actual state of both paths without claiming unverified success."""
    final = _snapshot_one(final_path)
    if final_created_by_attempt is True and final.get("exists") is not True:
        final_created_by_attempt = False
    final["sha256_verified"] = bool(final_verified)
    final["created_by_this_attempt"] = final_created_by_attempt
    return {
        "part": _snapshot_one(part_path),
        "final": final,
        "finalization_complete": bool(finalization_complete),
    }


def _write_block(fd: int, data: bytes) -> int:
    """Write all bytes, reporting how many were written if a write fails."""
    offset = 0
    while offset < len(data):
        try:
            written = os.write(fd, data[offset:])
        except KeyboardInterrupt:
            raise _WriteInterrupted(offset)
        except OSError as exc:
            raise _WriteFailure(offset, exc)
        if written <= 0:
            raise _WriteFailure(offset, OSError(errno.EIO, "short write to local file"))
        offset += written
    return offset


def _drain(stream, tail: _StderrTail) -> None:
    try:
        while True:
            chunk = stream.read(STDERR_READ_CHUNK)
            if not chunk:
                return
            tail.append(chunk)
    except Exception as exc:
        tail.read_error = "%s: %s" % (type(exc).__name__, exc)
        tail.append(("\n[stderr read error: %s]" % exc).encode("utf-8", "replace"))


def _terminate(proc) -> None:
    try:
        proc.terminate()
    except (ProcessLookupError, OSError):
        pass
    try:
        proc.wait(timeout=5)
        return
    except subprocess.TimeoutExpired:
        pass
    except Exception:
        return
    try:
        proc.kill()
    except (ProcessLookupError, OSError):
        pass
    try:
        proc.wait(timeout=5)
    except Exception:
        pass


def _close_fd(fd: Optional[int]) -> Optional[OSError]:
    if fd is None:
        return None
    try:
        os.close(fd)
        return None
    except OSError as exc:
        return exc


def _stat_size(path: Path) -> Tuple[Optional[int], Optional[OSError]]:
    try:
        return path.stat().st_size, None
    except OSError as exc:
        return None, exc


def _remove_own_file(path: Path) -> Optional[OSError]:
    try:
        os.unlink(str(path))
        return None
    except FileNotFoundError:
        return None
    except OSError as exc:
        return exc


def _fsync_dir_strict(path: Path) -> None:
    fd = os.open(str(path), os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        close_error = _close_fd(fd)
    if close_error is not None:
        raise OSError(close_error.errno or errno.EIO,
                      "directory close failed after fsync: %s" % close_error)


def _exclusive_copy(part_path: Path, final_path: Path, expected_sha: str,
                    creation_state: dict) -> None:
    """Non-atomic fallback for filesystems without hard links.

    Creates ``final_path`` with ``O_EXCL`` so pre-existing files are never
    touched.  On failure, removes only the file created by this attempt.
    """
    fd: Optional[int] = None
    creation_state["final_created_by_attempt"] = True
    try:
        fd = os.open(str(final_path), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError:
        creation_state["final_created_by_attempt"] = False
        raise
    except OSError:
        creation_state["final_created_by_attempt"] = False
        raise

    try:
        with part_path.open("rb") as source:
            while True:
                block = source.read(DEFAULT_CHUNK)
                if not block:
                    break
                _write_block(fd, block)
        os.fsync(fd)
        close_error = _close_fd(fd)
        fd = None
        if close_error is not None:
            raise OSError(close_error.errno or errno.EIO,
                          "close failed after fallback copy: %s" % close_error)
        actual = stream_sha256(final_path)
        if actual != expected_sha:
            raise OSError(errno.EIO, "verification of the final copy failed")
    except BaseException as exc:
        _close_fd(fd)
        cleanup_error = _remove_own_file(final_path)
        if cleanup_error is not None and not isinstance(exc, KeyboardInterrupt):
            raise OSError(
                errno.EIO,
                "incomplete final copy could not be removed: %s (original error: %s)"
                % (cleanup_error, exc),
            ) from exc
        if isinstance(exc, _WriteFailure):
            raise OSError(
                exc.cause.errno or errno.EIO,
                "fallback write failed after %d bytes: %s" % (exc.written, exc.cause),
            ) from exc.cause
        raise


def _finalize(part_path: Path, final_path: Path, expected_sha: str,
              creation_state: dict) -> None:
    """Create the final file and remove ``.part`` only after full validation."""
    if os.path.lexists(str(final_path)):
        raise FileExistsError(errno.EEXIST, "refusing to overwrite an existing file",
                              str(final_path))
    creation_state["final_created_by_attempt"] = True
    try:
        os.link(str(part_path), str(final_path))
    except FileExistsError:
        creation_state["final_created_by_attempt"] = False
        raise
    except OSError:
        creation_state["final_created_by_attempt"] = False
        # Non-atomic fallback; it validates size/SHA-256 itself.
        _exclusive_copy(part_path, final_path, expected_sha, creation_state)

    try:
        _fsync_dir_strict(final_path.parent)
    except OSError as exc:
        # Do not report completion if the directory entry is not durable.
        # Remove only the final file created by this attempt; keep .part.
        cleanup_error = _remove_own_file(final_path)
        if cleanup_error is not None:
            raise OSError(
                errno.EIO,
                "destination directory fsync failed and the final file could not "
                "be removed (%s); partial file kept" % cleanup_error,
            ) from exc
        raise OSError(errno.EIO,
                      "destination directory fsync failed; final file removed, "
                      "partial file kept: %s" % exc) from exc

    unlink_error = _remove_own_file(part_path)
    if unlink_error is not None:
        raise OSError(errno.EIO,
                      "final file is valid but the partial file could not be "
                      "removed: %s" % unlink_error)
    fsync_dir(final_path.parent)


def stream_to_part_file(
    argv: List[str],
    part_path: Path,
    final_path: Path,
    expected_size: Optional[int],
    *,
    popen_factory: Optional[Callable[..., object]] = None,
    chunk_size: int = DEFAULT_CHUNK,
    min_size: int = 0,
) -> TransferResult:
    """Run ``argv`` and stream stdout into ``part_path``.

    ``expected_size`` is exact when not ``None``.  ``min_size`` is used for
    artifacts whose exact size is unknown (the ``/bkupgrade`` tar).
    """
    factory = popen_factory or subprocess.Popen

    if expected_size is not None and expected_size < 0:
        raise ValueError("expected_size must be non-negative")
    if os.path.lexists(str(final_path)):
        files = snapshot_files(part_path, final_path,
                               final_created_by_attempt=False)
        size = files["final"].get("size") or 0
        return _failed(
            "refusing to overwrite existing file: %s" % final_path,
            written=size, files=files,
        )
    if os.path.lexists(str(part_path)):
        files = snapshot_files(part_path, final_path,
                               final_created_by_attempt=False)
        size = files["part"].get("size") or 0
        return _failed(
            "partial file already exists: %s" % part_path,
            written=size, files=files,
        )

    try:
        fd: Optional[int] = os.open(
            str(part_path), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except OSError as exc:
        files = snapshot_files(part_path, final_path,
                               final_created_by_attempt=False)
        size = (files["part"].get("size") if files["part"].get("exists")
                else files["final"].get("size")) or 0
        return _failed(
            "cannot create partial file: %s" % exc,
            written=size, files=files,
        )
    creation_state = {"final_created_by_attempt": False}

    digest = hashlib.sha256()
    received = 0
    written = 0
    error: Optional[str] = None
    exit_code: Optional[int] = None
    stderr_tail = _StderrTail(STDERR_LIMIT)
    stderr_thread: Optional[threading.Thread] = None
    proc = None
    interrupted = False
    unexpected: Optional[BaseException] = None
    close_error: Optional[OSError] = None

    try:
        try:
            proc = factory(
                argv,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=False,
                bufsize=0,
            )
        except OSError as exc:
            error = "failed to start ssh: %s" % exc

        if proc is not None:
            stderr_thread = threading.Thread(
                target=_drain, args=(proc.stderr, stderr_tail), daemon=True,
            )
            stderr_thread.start()

            while error is None:
                try:
                    block = proc.stdout.read(chunk_size)
                except (OSError, ValueError) as exc:
                    error = "stdout read failed: %s" % exc
                    break
                if not block:
                    break
                received += len(block)
                if expected_size is not None and received > expected_size:
                    error = ("remote stream exceeded the expected size (%s > %s); "
                             "stopping without truncating or padding"
                             % (human_bytes(received), human_bytes(expected_size)))
                    break
                digest.update(block)
                try:
                    written += _write_block(fd, block)
                except _WriteInterrupted as exc:
                    written += exc.written
                    raise
                except _WriteFailure as exc:
                    written += exc.written
                    if exc.cause.errno == errno.ENOSPC:
                        error = "local disk is full while writing %s" % part_path.name
                    else:
                        error = "local write failed: %s" % exc.cause
                    break

            if error is not None and proc.poll() is None:
                _terminate(proc)

            try:
                exit_code = proc.wait()
            except KeyboardInterrupt:
                raise
            except Exception as exc:
                if error is None:
                    error = "wait for ssh/nanddump failed: %s" % exc
                _terminate(proc)

            if stderr_thread is not None:
                stderr_thread.join(timeout=3)

            if error is None and exit_code != 0:
                error = "ssh/nanddump exited with code %d" % exit_code
            if error is None and expected_size is not None and received != expected_size:
                error = ("stream length mismatch: expected %s, received %s; "
                         "the partial file was kept and will not be padded or "
                         "truncated" % (human_bytes(expected_size),
                                        human_bytes(received)))
            if error is None and received < min_size:
                error = "stream is unexpectedly small (%s bytes)" % received

            if error is None:
                try:
                    os.fsync(fd)
                except OSError as exc:
                    error = "local fsync failed; the partial file was kept: %s" % exc

    except KeyboardInterrupt:
        interrupted = True
        if proc is not None:
            _terminate(proc)
    except Exception as exc:
        unexpected = exc
        if error is None:
            error = "unexpected transfer error: %s" % exc
        if proc is not None:
            _terminate(proc)
    finally:
        if proc is not None and proc.poll() is None:
            _terminate(proc)
        close_error = _close_fd(fd)
        fd = None
        if stderr_thread is not None:
            try:
                stderr_thread.join(timeout=2)
            except Exception:
                pass
        if proc is not None:
            for stream in (getattr(proc, "stdout", None), getattr(proc, "stderr", None)):
                if stream is not None:
                    try:
                        stream.close()
                    except (OSError, ValueError):
                        pass

    stderr_text = stderr_tail.text()
    stderr_truncated = stderr_tail.truncated or stderr_tail.read_error is not None

    if interrupted:
        size, _ = _stat_size(part_path)
        files = snapshot_files(
            part_path, final_path,
            final_created_by_attempt=creation_state["final_created_by_attempt"],
        )
        raise TransferInterrupted(part_path, received,
                                  size if size is not None else written, files)

    if close_error is not None and error is None:
        error = "local close failed; the partial file was kept: %s" % close_error

    size, stat_error = _stat_size(part_path)
    if size is not None:
        written = size
    elif error is None:
        error = "cannot stat partial file: %s" % stat_error

    if unexpected is not None and error is None:
        error = "unexpected transfer error: %s" % unexpected

    files = snapshot_files(
        part_path, final_path,
        final_created_by_attempt=creation_state["final_created_by_attempt"],
    )

    if error is not None:
        return _failed(error, received=received, written=written,
                       exit_code=exit_code, stderr_tail=stderr_text,
                       stderr_truncated=stderr_truncated, files=files)

    try:
        local_sha = stream_sha256(part_path)
    except KeyboardInterrupt:
        raise TransferInterrupted(part_path, received, written, files)
    except OSError as exc:
        return _failed("could not re-read the partial file for SHA-256: %s" % exc,
                       received=received, written=written, exit_code=exit_code,
                       stderr_tail=stderr_text, stderr_truncated=stderr_truncated,
                       files=files)

    streaming_sha = digest.hexdigest()
    if local_sha != streaming_sha:
        return _failed(
            "local SHA-256 does not match the streaming hash; the partial file "
            "was kept", received=received, written=written, exit_code=exit_code,
            stderr_tail=stderr_text, stderr_truncated=stderr_truncated,
            files=files,
        )

    try:
        _finalize(part_path, final_path, local_sha, creation_state)
    except KeyboardInterrupt:
        size, _ = _stat_size(part_path)
        files = snapshot_files(
            part_path, final_path,
            final_created_by_attempt=creation_state["final_created_by_attempt"],
        )
        raise TransferInterrupted(part_path, received,
                                  size if size is not None else written, files)
    except FileExistsError:
        files = snapshot_files(
            part_path, final_path,
            final_created_by_attempt=creation_state["final_created_by_attempt"],
        )
        return _failed("refusing to overwrite existing file: %s" % final_path,
                       received=received, written=written, sha256=local_sha,
                       exit_code=exit_code, stderr_tail=stderr_text,
                       stderr_truncated=stderr_truncated, files=files)
    except OSError as exc:
        files = snapshot_files(
            part_path, final_path,
            final_created_by_attempt=creation_state["final_created_by_attempt"],
        )
        return _failed("could not finalise %s: %s" % (final_path.name, exc),
                       received=received, written=written, sha256=local_sha,
                       exit_code=exit_code, stderr_tail=stderr_text,
                       stderr_truncated=stderr_truncated, files=files)

    files = snapshot_files(
        part_path, final_path,
        final_created_by_attempt=creation_state["final_created_by_attempt"],
        final_verified=True, finalization_complete=True,
    )
    return TransferResult("completed", received, written, local_sha, exit_code,
                          None, stderr_text, stderr_truncated, files)
