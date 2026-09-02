#!/usr/bin/env python3
"""Prepare or validate one private atomic GUG-376 collision context."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from typing import Any, Sequence


REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    materialize = commands.add_parser(
        "materialize-context",
        help="Create one zero-AWS, create-only atomic context.",
    )
    materialize.add_argument("--admission-private-root", type=Path, required=True)
    materialize.add_argument("--effect-private-root", type=Path, required=True)
    materialize.add_argument("--gug393-private-root", type=Path, required=True)
    materialize.add_argument("--gug395-private-root", type=Path, required=True)
    materialize.add_argument("--bootstrap-intent-digest", required=True)
    materialize.add_argument("--approval-reference-digest", required=True)
    materialize.add_argument("--approved-operation", required=True)
    materialize.add_argument("--authorized-at", required=True)
    materialize.add_argument("--expires-at", required=True)
    validate = commands.add_parser(
        "validate-context",
        help="Validate custody and emit digest-only context evidence.",
    )
    validate.add_argument("--admission-private-root", type=Path, required=True)
    validate.add_argument("--effect-private-root", type=Path, required=True)
    validate.add_argument("--gug393-private-root", type=Path, required=True)
    validate.add_argument("--gug395-private-root", type=Path, required=True)
    return parser


def _materialize(args: argparse.Namespace) -> dict[str, Any]:
    from tooling.platform_authority_gug376_collision_atomic_context import (
        materialize_atomic_collision_context,
    )

    context = materialize_atomic_collision_context(
        admission_private_root=args.admission_private_root,
        effect_private_root=args.effect_private_root,
        gug393_private_root=args.gug393_private_root,
        gug395_private_root=args.gug395_private_root,
        bootstrap_intent_digest=args.bootstrap_intent_digest,
        approval_reference_digest=args.approval_reference_digest,
        approved_operation=args.approved_operation,
        authorized_at=args.authorized_at,
        expires_at=args.expires_at,
    )
    return {
        "record_type": (
            "scanalyze.platform_authority."
            "gug376_atomic_collision_context_materialization.v1"
        ),
        "status": "ATOMIC_COLLISION_CONTEXT_MATERIALIZED",
        "context_digest": context["context_digest"],
        "catalog_digest": context["catalog_digest"],
        "private_bindings_digest": context["private_bindings_digest"],
        "approval_reference_digest": context["approval_reference_digest"],
        "approved_operation": context["approved_operation"],
        "aws_calls": 0,
        "aws_mutations": 0,
        "effect_executed": False,
        "production_authorized": False,
    }


def _validate(args: argparse.Namespace) -> dict[str, Any]:
    from tooling.platform_authority_gug376_collision_atomic_context import (
        read_atomic_collision_context,
    )

    context = read_atomic_collision_context(
        admission_private_root=args.admission_private_root,
        effect_private_root=args.effect_private_root,
        gug393_private_root=args.gug393_private_root,
        gug395_private_root=args.gug395_private_root,
    )
    return {
        "record_type": (
            "scanalyze.platform_authority."
            "gug376_atomic_collision_context_validation.v1"
        ),
        "status": "ATOMIC_COLLISION_CONTEXT_VALIDATED",
        "context_digest": context["context_digest"],
        "catalog_digest": context["catalog_digest"],
        "private_bindings_digest": context["private_bindings_digest"],
        "approval_reference_digest": context["approval_reference_digest"],
        "approved_operation": context["approved_operation"],
        "aws_calls": 0,
        "aws_mutations": 0,
        "effect_executed": False,
        "production_authorized": False,
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    try:
        result = {
            "materialize-context": _materialize,
            "validate-context": _validate,
        }[args.command](args)
    except Exception as exc:
        code = getattr(exc, "code", None)
        parser.error(
            code if isinstance(code, str) else "ATOMIC_COLLISION_CONTEXT_BLOCKED"
        )
    sys.stdout.write(
        json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
