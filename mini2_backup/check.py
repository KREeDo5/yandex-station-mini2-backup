# AI-generated code. Review before use. See AI_DISCLOSURE.md.
"""Read-only local and remote diagnostics.

Only fixed commands are executed.  The tool does not read Quasar
configuration, credentials, Wi-Fi secrets, SSH keys or arbitrary files, and it
does not run ``strings`` on binaries.
"""

from __future__ import annotations

from typing import Callable, Optional, Tuple

from .errors import GateError
from .profile import evaluate_profile, parse_proc_mtd, parse_sysfs_probe
from .report import finish_report, new_report
from .ssh import (
    LocalPreflight,
    SshTarget,
    explain_ssh_failure,
    identity_mode_warning,
    require_preflight,
)
from .util import utc_now

CommandRunner = Callable[[SshTarget, str], Tuple[int, bytes, bytes]]

CMD_UID = "id -u"
CMD_PROC_MTD = "cat /proc/mtd"
CMD_UNAME = "uname -srm"
CMD_MODEL = (
    "if [ -r /proc/device-tree/model ]; then cat /proc/device-tree/model; "
    "elif [ -r /sys/firmware/devicetree/base/model ]; then "
    "cat /sys/firmware/devicetree/base/model; else echo UNKNOWN; fi"
)
CMD_SYSFS = (
    'for d in /sys/class/mtd/mtd[0-9]*; do '
    '[ -d "$d" ] || continue; '
    'printf "DEV %s\\n" "${d##*/}"; '
    'for f in name size erasesize writesize oobsize; do '
    'if [ -r "$d/$f" ]; then printf "ATTR %s " "$f"; cat "$d/$f"; '
    'else printf "ATTR %s UNREADABLE\\n" "$f"; fi; done; done'
)
CMD_NANDDUMP = (
    "if command -v nanddump >/dev/null 2>&1; then "
    "nanddump --help 2>&1 | head -n 200; else echo NANDDUMP_MISSING; fi"
)
CMD_TAR = (
    "if command -v tar >/dev/null 2>&1; then "
    "tar --version 2>&1 | head -n 3; "
    "echo '---TAR-HELP---'; tar --help 2>&1 | head -n 120; "
    "else echo TAR_MISSING; fi"
)

def _decode(raw: bytes) -> str:
    return raw.decode("utf-8", "replace").replace("\x00", "").strip()


def _first_line(text: str) -> Optional[str]:
    for line in text.splitlines():
        line = line.strip()
        if line:
            return line[:300]
    return None


def run_check(
    target: SshTarget,
    firmware_version: Optional[str] = None,
    *,
    runner: Optional[CommandRunner] = None,
    preflight: Optional[LocalPreflight] = None,
) -> dict:
    """Run all diagnostics and return a report dictionary.

    Raises ``GateError`` only when local preflight fails (before any network
    activity).  Remote failures are recorded in the report with ``status:
    failed``.
    """
    if preflight is None:
        preflight = require_preflight(target)
    if not preflight.ok:
        raise GateError("local preflight failed")

    run = runner
    if run is None:
        from .ssh import run_capture as run  # local import keeps tests injectable

    report = new_report("failed")
    report["host"] = {
        "hostname": target.host,
        "port": target.port,
        "user": target.user,
        "identity_file_basename": target.normalized_identity().name,
        "host_key_verification": "strict",
    }
    report["preflight"] = {
        "checks": preflight.checks,
        "ssh_path": preflight.ssh_path,
        "ssh_version": preflight.ssh_version,
    }
    report["device"] = {
        "uid": None,
        "model": None,
        "model_source": "unknown",
        "model_article_match": None,
        "firmware_version": firmware_version,
        "firmware_source": "user_provided" if firmware_version else "not_collected",
        "uname": None,
        "kernel": None,
        "architecture": None,
        "nanddump_version": None,
    }
    report["nanddump"] = {
        "found": False,
        "supports_bb_padbad": False,
        "supports_omitoob": False,
        "help_excerpt": None,
    }
    report["tar"] = {
        "found": False,
        "version": None,
        "supports_create": False,
        "supports_directory": False,
        "supports_file": False,
    }

    checks = report.setdefault("checks", [])
    errors = report["errors"]
    warnings = report["warnings"]

    def note(check_id: str, ok: bool, detail: str, gate: bool = True) -> None:
        checks.append({"id": check_id, "status": "ok" if ok else "failed",
                       "detail": detail, "gate": gate})

    def run_fixed(check_id: str, command: str) -> Optional[str]:
        try:
            code, stdout, stderr = run(target, command)
        except GateError as exc:
            errors.append("%s: %s" % (check_id, exc))
            note(check_id, False, str(exc))
            return None
        if code != 0:
            errors.append("%s: %s" % (check_id, explain_ssh_failure(code, stderr)))
            note(check_id, False, "command failed with exit %d" % code)
            return None
        return _decode(stdout)

    uid_text = run_fixed("uid", CMD_UID)
    if uid_text is not None:
        uid_ok = uid_text.strip() == "0"
        report["device"]["uid"] = int(uid_text) if uid_text.isdigit() else None
        note("uid", uid_ok,
             "remote uid is 0 (root)" if uid_ok else
             "remote uid is %r; root is required" % uid_text)

    uname_text = run_fixed("uname", CMD_UNAME)
    if uname_text is not None:
        parts = uname_text.split()
        report["device"]["uname"] = uname_text
        if len(parts) >= 2:
            report["device"]["kernel"] = parts[1]
        if len(parts) >= 3:
            report["device"]["architecture"] = parts[2]
        arch_ok = report["device"]["architecture"] == "aarch64"
        note("architecture", arch_ok,
             "aarch64 detected" if arch_ok else
             "unexpected architecture %r; only aarch64 was manually verified"
             % report["device"]["architecture"])
        kernel = report["device"]["kernel"]
        if kernel and kernel != "4.9.68":
            warnings.append(
                "kernel %s differs from the manually verified 4.9.68; the MTD "
                "profile gate still applies, but this combination is unverified" % kernel
            )

    model_text = run_fixed("model", CMD_MODEL)
    if model_text is not None:
        model = model_text.strip() or "UNKNOWN"
        report["device"]["model"] = model if model != "UNKNOWN" else None
        if model == "UNKNOWN":
            report["device"]["model_source"] = "unknown"
            report["device"]["model_article_match"] = None
            note("model", False,
                 "device model could not be read from the device tree; v0.1 "
                 "requires a readable model string")
        else:
            report["device"]["model_source"] = "device_tree"
            lowered = model.lower()
            article_match = "yndx-00020" in lowered
            family_match = any(token in lowered for token in
                               ("mini 2", "mini2", "station mini 2"))
            report["device"]["model_article_match"] = article_match
            if article_match:
                note("model", True,
                     "device tree model string contains YNDX-00020; this is a "
                     "string match, not hardware validation")
            elif family_match:
                note("model", True,
                     "device tree model identifies the Mini 2 family, but the "
                     "string does not prove YNDX-00020")
                warnings.append(
                    "device tree model %r does not contain YNDX-00020; a family "
                    "string is not proof of the exact article. Compatibility "
                    "relies on the MTD profile gate." % model
                )
            else:
                note("model", False,
                     "device tree model %r does not look like YNDX-00020" % model)

    proc_text = run_fixed("proc_mtd", CMD_PROC_MTD)
    sysfs_text = run_fixed("sysfs_mtd", CMD_SYSFS)
    if proc_text is not None and sysfs_text is not None:
        try:
            proc = parse_proc_mtd(proc_text)
            sysfs = parse_sysfs_probe(sysfs_text)
        except ValueError as exc:
            errors.append("MTD profile could not be parsed: %s" % exc)
            note("mtd_profile", False, str(exc))
        else:
            profile = evaluate_profile(proc, sysfs)
            report["layout"] = profile.as_dict()
            note("mtd_profile", profile.ok,
                 "MTD names, sizes and geometry match the reference profile"
                 if profile.ok else
                 "%d MTD profile mismatch(es); backup is blocked" % len(profile.issues))
            warnings.extend(profile.notes)

    nanddump_text = run_fixed("nanddump", CMD_NANDDUMP)
    if nanddump_text is not None:
        found = "NANDDUMP_MISSING" not in nanddump_text
        supports_padbad = "--bb=padbad" in nanddump_text
        supports_omitoob = "--omitoob" in nanddump_text
        report["nanddump"] = {
            "found": found,
            "supports_bb_padbad": supports_padbad,
            "supports_omitoob": supports_omitoob,
            "version_hint": _first_line(nanddump_text),
        }
        ok = found and supports_padbad and supports_omitoob
        note("nanddump", ok,
             "nanddump found with --bb=padbad and --omitoob"
             if ok else
             "nanddump is missing or does not advertise --bb=padbad/--omitoob")

    tar_text = run_fixed("tar", CMD_TAR)
    if tar_text is not None:
        found = "TAR_MISSING" not in tar_text
        version = _first_line(tar_text)
        help_text = ""
        if "---TAR-HELP---" in tar_text:
            help_text = tar_text.split("---TAR-HELP---", 1)[1]
        supports_create = ("--create" in help_text) or ("-c" in help_text)
        supports_directory = ("--directory" in help_text) or ("-C" in help_text)
        supports_file = ("--file" in help_text) or ("-f" in help_text)
        tar_ok = found and supports_create and supports_directory and supports_file
        report["tar"] = {
            "found": found,
            "version": version,
            "supports_create": supports_create,
            "supports_directory": supports_directory,
            "supports_file": supports_file,
        }
        note("tar", tar_ok,
             "tar found with create/file/directory options: %s" % version
             if tar_ok else
             "tar is missing or does not advertise -c/-f/-C in its help output")

    warning = identity_mode_warning(target)
    if warning:
        warnings.append(warning)

    warnings.append(
        "A successful diagnostic run is not hardware validation of this tool."
    )

    report["status"] = "ok" if all(c["status"] == "ok" for c in checks) and not errors else "failed"
    report["completed_at"] = utc_now()
    return report


def require_check_ok(report: dict) -> None:
    if report.get("status") != "ok":
        detail = "; ".join(report.get("errors") or ["one or more diagnostic gates failed"])
        raise GateError("preflight check failed: " + detail)
