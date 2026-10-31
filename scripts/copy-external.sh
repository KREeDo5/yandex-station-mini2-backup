#!/bin/sh
# AI-generated wrapper. Review before use. See AI_DISCLOSURE.md.
set -eu
. "$(CDPATH= cd "$(dirname "$0")" && pwd)/_common.sh"
exec "$PYTHON" -m mini2_backup copy-external "$@"
