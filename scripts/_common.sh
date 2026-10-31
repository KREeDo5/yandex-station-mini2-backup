# AI-generated shell helper. Review before use. See AI_DISCLOSURE.md.
# Sourced by the wrapper scripts. No sudo, no installs, no device access.

set -eu

SCRIPT_DIR=$(CDPATH= cd "$(dirname "$0")" && pwd)
REPO_ROOT=$(CDPATH= cd "$SCRIPT_DIR/.." && pwd)

find_python() {
    if [ -n "${MINI2_PYTHON:-}" ]; then
        if "$MINI2_PYTHON" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 11) else 1)' >/dev/null 2>&1; then
            printf '%s\n' "$MINI2_PYTHON"
            return 0
        fi
        return 1
    fi
    for candidate in python3.13 python3.12 python3.11 python3; do
        if command -v "$candidate" >/dev/null 2>&1; then
            if "$candidate" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 11) else 1)' >/dev/null 2>&1; then
                command -v "$candidate"
                return 0
            fi
        fi
    done
    return 1
}

if ! PYTHON=$(find_python); then
    printf '%s\n' "ERROR: Python 3.11+ not found. Set MINI2_PYTHON to a suitable interpreter." >&2
    exit 2
fi

export PYTHONPATH="$REPO_ROOT${PYTHONPATH:+:$PYTHONPATH}"
export MINI2_REPO_ROOT="$REPO_ROOT"
