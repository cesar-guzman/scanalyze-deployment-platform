#!/usr/bin/env python3
"""Offline CLI for the GUG-395 private pre-plan seed contract."""

from __future__ import annotations

from pathlib import Path
import sys


REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tooling.platform_authority_gug395_preplan_seed import main  # noqa: E402


if __name__ == "__main__":
    raise SystemExit(main())
