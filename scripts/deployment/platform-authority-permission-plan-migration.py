#!/usr/bin/env python3
"""Prepare an offline private permission migration draft, never apply it."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tooling import platform_authority_permission_plan_migration as subject  # noqa: E402


class Parser(argparse.ArgumentParser):
    def error(self, _message: str) -> None:
        raise subject.MigrationDraftError("CLI_ARGUMENTS_INVALID")


def main(argv: list[str] | None = None) -> int:
    parser = Parser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    try:
        args = parser.parse_args(argv)
        draft = subject.build_review_draft(subject.read_private_input(args.input))
        subject.write_private_draft(args.output, draft)
        print(json.dumps(subject.public_summary(draft), sort_keys=True))
        return 0
    except subject.MigrationDraftError as exc:
        print(json.dumps({"error": exc.code}), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
