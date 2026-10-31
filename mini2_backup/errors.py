# AI-generated code. Review before use. See AI_DISCLOSURE.md.
"""Exception types with stable process exit codes."""

from __future__ import annotations


class ToolError(Exception):
    """Base class for expected, user-facing failures."""

    exit_code = 1


class UsageError(ToolError):
    """Invalid invocation or unsafe parameter."""

    exit_code = 2


class GateError(ToolError):
    """A mandatory safety or compatibility gate did not pass."""

    exit_code = 2


class TransferError(ToolError):
    """A remote stream could not be transferred and validated."""

    exit_code = 1


class VerifyError(ToolError):
    """A local backup failed verification."""

    exit_code = 1


class CopyError(ToolError):
    """An external copy failed or could not be verified."""

    exit_code = 1
