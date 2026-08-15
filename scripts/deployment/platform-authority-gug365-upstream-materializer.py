#!/usr/bin/env python3
"""Zero-effect CLI for the GUG-377 repository materializer contract."""

from __future__ import annotations

from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tooling.platform_authority_gug365_upstream_materializer import main  # noqa: E402


if __name__ == "__main__":
    raise SystemExit(main())
