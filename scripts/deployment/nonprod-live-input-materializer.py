#!/usr/bin/env python3
"""Materialize repository-attested private inputs for the protected live engine."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tooling.nonprod_live_input_materializer import (  # noqa: E402
    LiveInputMaterializationError,
    materialize_private_root,
    stage_sealed_request_from_environment,
    validate_private_root,
)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    stage = commands.add_parser("stage")
    stage.add_argument("--private-root", type=Path, required=True)
    for name in ("materialize", "validate"):
        command = commands.add_parser(name)
        command.add_argument("--private-root", type=Path, required=True)
        command.add_argument("--deployment-id", required=True)
        command.add_argument("--layer", required=True)
        command.add_argument("--operation", choices=("plan", "apply"), required=True)
        command.add_argument("--claim-digest", required=True)
        command.add_argument("--request-path", type=Path, required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.command == "stage":
        try:
            stage_sealed_request_from_environment(private_root=args.private_root)
        except LiveInputMaterializationError as exc:
            print(f"FAIL: {exc.code}", file=sys.stderr)
            return 1
        except Exception:
            print("FAIL: LIVE_INPUT_MATERIALIZATION_INTERNAL_ERROR", file=sys.stderr)
            return 1
        print("PASS: sealed live input transport staged")
        return 0
    operation = (
        materialize_private_root
        if args.command == "materialize"
        else validate_private_root
    )
    try:
        operation(
            private_root=args.private_root,
            deployment_id=args.deployment_id,
            layer=args.layer,
            operation=args.operation,
            claim_digest=args.claim_digest,
            deployment_request_path=args.request_path,
        )
    except LiveInputMaterializationError as exc:
        print(f"FAIL: {exc.code}", file=sys.stderr)
        return 1
    except Exception:
        print("FAIL: LIVE_INPUT_MATERIALIZATION_INTERNAL_ERROR", file=sys.stderr)
        return 1
    status = "materialized" if args.command == "materialize" else "validated"
    print(f"PASS: live inputs {status}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
