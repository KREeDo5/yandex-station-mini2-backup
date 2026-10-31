# AI-generated code. Review before use. See AI_DISCLOSURE.md.
"""Strict, key-only SSH invocation helpers.

No ``shell=True``, no password prompts, no automatic host-key acceptance and
no pseudo-terminal allocation.  All remote commands used by the tool are
fixed strings; user-controlled values are validated and passed as separate
argv elements.
"""

from __future__ import annotations

import os
import re
import shutil
import stat
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import List, Mapping, Optional, Sequence, Tuple

from .errors import GateError, UsageError

DEFAULT_PORT = 2222
DEFAULT_USER = "root"
CONNECT_TIMEOUT_SECONDS = 15

_HOST_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9._:%-]{0,252})$")
_USER_RE = re.compile(r"^[a-z_][a-z0-9_-]{0,31}$")


@dataclass(frozen=True)
class SshTarget:
    host: str
    port: int = DEFAULT_PORT
    user: str = DEFAULT_USER
    identity: str = ""

    def normalized_identity(self) -> Path:
        return Path(os.path.expanduser(self.identity))

    def display_host(self) -> str:
        return "%s@%s:%d" % (self.user, self.host, self.port)


@dataclass
class LocalPreflight:
    ok: bool
    checks: List[dict]
    ssh_path: Optional[str] = None
    ssh_version: Optional[str] = None


def validate_target(target: SshTarget) -> None:
    """Validate user-controlled SSH parameters without touching the network."""
    if not isinstance(target.host, str) or not _HOST_RE.match(target.host):
        raise UsageError(
            "invalid host %r: use a plain hostname or IP address without "
            "spaces, shell characters or a leading dash" % (target.host,)
        )
    if target.host.startswith("-"):
        raise UsageError("invalid host: a leading dash is not allowed")
    if isinstance(target.port, bool) or not isinstance(target.port, int):
        raise UsageError("invalid port: an integer is required")
    if not (1 <= target.port <= 65535):
        raise UsageError("invalid port %r: expected 1..65535" % (target.port,))
    if not isinstance(target.user, str) or not _USER_RE.match(target.user):
        raise UsageError("invalid SSH user %r" % (target.user,))
    if not target.identity or not isinstance(target.identity, str):
        raise UsageError("an identity file is required (--identity)")
    if "\x00" in target.identity or "\n" in target.identity:
        raise UsageError("identity path contains a forbidden control character")
    identity = target.normalized_identity()
    if not identity.exists():
        raise UsageError("identity file does not exist: %s" % identity)
    if not identity.is_file():
        raise UsageError("identity path is not a regular file: %s" % identity)


def build_ssh_argv(target: SshTarget, remote_command: str) -> List[str]:
    """Build the local ``ssh`` argv.  The command is one fixed argv element."""
    validate_target(target)
    ssh_path = shutil.which("ssh") or "ssh"
    return [
        ssh_path,
        "-T",  # never allocate a PTY: stdout stays a clean binary stream
        "-p", str(target.port),
        "-l", target.user,
        "-i", str(target.normalized_identity()),
        "-o", "BatchMode=yes",
        "-o", "PasswordAuthentication=no",
        "-o", "KbdInteractiveAuthentication=no",
        "-o", "ChallengeResponseAuthentication=no",
        "-o", "PubkeyAuthentication=yes",
        "-o", "IdentitiesOnly=yes",
        "-o", "StrictHostKeyChecking=yes",
        "-o", "ConnectTimeout=%d" % CONNECT_TIMEOUT_SECONDS,
        "-o", "ConnectionAttempts=1",
        "-o", "ServerAliveInterval=30",
        "-o", "ServerAliveCountMax=4",
        "-o", "LogLevel=ERROR",
        target.host,
        remote_command,
    ]


def _known_hosts_candidates(env: Optional[Mapping[str, str]] = None,
                            home: Optional[Path] = None) -> List[Path]:
    env = env if env is not None else os.environ
    home = home if home is not None else Path.home()
    candidates = [home / ".ssh" / "known_hosts"]
    # OpenSSH also reads the system-wide file by default.
    candidates.append(Path("/etc/ssh/ssh_known_hosts"))
    return candidates


def local_preflight(
    target: SshTarget,
    *,
    platform: Optional[str] = None,
    env: Optional[Mapping[str, str]] = None,
    known_hosts: Optional[Sequence[Path]] = None,
) -> LocalPreflight:
    """Run all local gates required before opening any SSH connection."""
    checks: List[dict] = []
    platform = platform if platform is not None else sys.platform
    env = env if env is not None else os.environ

    def add(check_id: str, ok: bool, detail: str) -> None:
        checks.append({"id": check_id, "status": "ok" if ok else "failed",
                       "detail": detail})

    platform_ok = platform == "darwin"
    add("platform", platform_ok,
        "macOS detected" if platform_ok else
        "platform %r is not supported by v0.1; macOS is the only verified platform"
        % platform)

    inside_ssh = bool(env.get("SSH_CONNECTION") or env.get("SSH_CLIENT"))
    add("not_inside_ssh", not inside_ssh,
        "not running inside an SSH session" if not inside_ssh else
        "refusing to run inside an SSH session; run the tool from a local terminal")

    ssh_path = shutil.which("ssh")
    add("ssh_binary", ssh_path is not None,
        "ssh found at %s" % ssh_path if ssh_path else "ssh client not found on PATH")

    try:
        validate_target(target)
        target_ok = True
        target_detail = "host, port, user and identity look valid"
    except UsageError as exc:
        target_ok = False
        target_detail = str(exc)
    add("target_parameters", target_ok, target_detail)

    candidates = list(known_hosts) if known_hosts is not None else _known_hosts_candidates(env)
    usable = []
    for candidate in candidates:
        try:
            if candidate.is_file() and candidate.stat().st_size > 0:
                usable.append(candidate)
        except OSError:
            continue
    add("known_hosts", bool(usable),
        "known_hosts configured at %s" % ", ".join(str(p) for p in usable)
        if usable else
        "no non-empty known_hosts file found; verify the device host key "
        "out-of-band and add it yourself. This tool never accepts an unknown key")

    ssh_version = None
    if ssh_path:
        try:
            completed = subprocess.run(
                [ssh_path, "-V"], capture_output=True, timeout=10,
                check=False, shell=False,
            )
            raw = (completed.stdout or b"") + (completed.stderr or b"")
            ssh_version = raw.decode("utf-8", "replace").strip().splitlines()[0]
        except (OSError, subprocess.SubprocessError, IndexError):
            ssh_version = None

    return LocalPreflight(ok=all(c["status"] == "ok" for c in checks),
                           checks=checks, ssh_path=ssh_path,
                           ssh_version=ssh_version)


def require_preflight(target: SshTarget, **kwargs) -> LocalPreflight:
    result = local_preflight(target, **kwargs)
    if not result.ok:
        failures = [c["detail"] for c in result.checks if c["status"] != "ok"]
        raise GateError("local preflight failed: " + "; ".join(failures))
    return result


def run_capture(target: SshTarget, remote_command: str,
                timeout: int = 30) -> Tuple[int, bytes, bytes]:
    """Run a short diagnostic command.  Never used for bulk data streams."""
    argv = build_ssh_argv(target, remote_command)
    try:
        completed = subprocess.run(
            argv,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        raise GateError("SSH diagnostic command timed out after %d seconds" % timeout)
    except OSError as exc:
        raise GateError("failed to start ssh: %s" % exc)
    return completed.returncode, completed.stdout, completed.stderr


def explain_ssh_failure(code: int, stderr: bytes) -> str:
    text = stderr.decode("utf-8", "replace").strip()
    lowered = text.lower()
    if "host key verification failed" in lowered:
        return ("the device host key is not trusted. Verify its fingerprint "
                "out-of-band, add it to known_hosts yourself, and retry. "
                "The tool will not disable host-key checking.")
    if "permission denied" in lowered:
        return ("SSH authentication failed. Check that the root public key is "
                "installed on the device and that the identity file is correct.")
    if "connection refused" in lowered or "connection timed out" in lowered:
        return "could not connect to the device over SSH: %s" % text
    if "no such file" in lowered and "known_hosts" in lowered:
        return "known_hosts is missing; add the verified device host key first"
    if code == 255:
        return "SSH connection failed (exit 255): %s" % (text or "no diagnostic text")
    return "SSH command failed with exit %d: %s" % (code, text or "no diagnostic text")


def identity_mode_warning(target: SshTarget) -> Optional[str]:
    """Warn about an overly permissive private-key mode without reading it."""
    path = target.normalized_identity()
    try:
        mode = stat.S_IMODE(path.stat().st_mode)
    except OSError:
        return None
    if mode & 0o077:
        return ("identity file permissions are %04o; OpenSSH may reject keys "
                "readable by other users. Restrict them locally if needed." % mode)
    return None
