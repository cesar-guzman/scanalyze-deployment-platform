#!/usr/bin/env python3
"""Capture the private read-only GUG-376 Plan seed snapshot."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import os
from pathlib import Path
import sys
from typing import Sequence


REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tooling import (  # noqa: E402
    platform_authority_plan_permission_repair_deployment_route as route,
)
from tooling import (  # noqa: E402
    platform_authority_plan_permission_repair_plan_seed_snapshot as subject,
)


class _Parser(argparse.ArgumentParser):
    def error(self, _message: str) -> None:
        raise subject.PlanSeedSnapshotError("CLI_ARGUMENTS_INVALID")


def _parser() -> argparse.ArgumentParser:
    parser = _Parser(
        description=(
            "Read the exact Plan permission set and generated role through "
            "two explicit SSO profiles using only read calls, then create one private "
            "NO-GO seed snapshot."
        )
    )
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--bootstrap-change-set-name", required=True)
    parser.add_argument("--private-root", type=Path, required=True)
    parser.add_argument(
        "--output-name", default=subject.DEFAULT_OUTPUT_NAME
    )
    parser.add_argument("--authority-profile", required=True)
    parser.add_argument("--management-profile", required=True)
    parser.add_argument("--region", required=True)
    return parser


def _absolute(path: Path) -> Path:
    return Path(os.path.abspath(os.path.expanduser(os.fspath(path))))


def main(argv: Sequence[str] | None = None) -> int:
    try:
        args = _parser().parse_args(argv)
        source_root = _absolute(args.source_root)
        private_root = _absolute(args.private_root)
        try:
            private_root.relative_to(source_root)
        except ValueError:
            pass
        else:
            raise subject.PlanSeedSnapshotError("PRIVATE_ROOT_INSIDE_SOURCE")
        snapshot = subject.capture_plan_seed_snapshot(
            source_root=source_root,
            source_commit=args.source_commit,
            bootstrap_change_set_name=args.bootstrap_change_set_name,
            authority_profile=args.authority_profile,
            management_profile=args.management_profile,
            region=args.region,
        )
        evaluated = datetime.now(timezone.utc).replace(microsecond=0)
        destination = subject.write_private_snapshot(
            private_root=private_root,
            output_name=args.output_name,
            snapshot=snapshot,
            source_commit=args.source_commit,
            now=evaluated,
        )
        # Principal, permission-set, instance, role, provider, and caller
        # coordinates intentionally never reach stdout.
        summary = {
            "record_type": snapshot["record_type"],
            "source_commit": snapshot["source_commit"],
            "output_name": destination.name,
            "snapshot_digest": snapshot["snapshot_digest"],
            "current_policy_digest": snapshot["current_policy_digest"],
            "desired_policy_digest": snapshot["desired_policy_digest"],
            "aws_calls": snapshot["aws_calls"],
            "aws_mutations": 0,
            "deployment_authorized": False,
            "production_status": "NO-GO",
        }
        sys.stdout.write(route.canonical_json(summary) + "\n")
        return 0
    except subject.PlanSeedSnapshotError as exc:
        sys.stderr.write(route.canonical_json({"error": exc.code}) + "\n")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
