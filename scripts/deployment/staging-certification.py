#!/usr/bin/env python3
"""Verify one sanitized, signed GUG-127 staging certification package."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tooling.staging_certification import (  # noqa: E402
    StagingCertificationError,
    load_json,
    verify_certification,
)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--certification", type=Path, required=True)
    parser.add_argument("--trust-policy", type=Path, required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        result = verify_certification(
            load_json(args.certification),
            load_json(args.trust_policy),
        )
    except StagingCertificationError as exc:
        code = exc.code
        print(f"FAIL: {code}", file=sys.stderr)
        return 1
    print(
        "PASS: GUG-127 staging certification verified; "
        f"status={result.code}; production_authorized=false"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
