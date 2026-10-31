# AI-generated code. Review before use. See AI_DISCLOSURE.md.
"""Module entry point: python3 -m mini2_backup."""

from __future__ import annotations

import sys


def _main() -> int:
    if sys.version_info < (3, 11):
        sys.stderr.write(
            "ERROR: Python 3.11 or newer is required (running %s).\n"
            "Set MINI2_PYTHON or use the scripts/*.sh wrappers.\n"
            % sys.version.split()[0]
        )
        return 2
    from .cli import main
    return main()


if __name__ == "__main__":
    sys.exit(_main())
