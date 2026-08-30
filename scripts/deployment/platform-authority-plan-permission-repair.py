#!/usr/bin/env python3
"""Offline contracts CLI for the GUG-376 bootstrap Plan policy repair.

Materialization and validation perform zero AWS calls.  Operational mode names
exist only to make the human boundary explicit: this process can never obtain
the injected service-owned ports required by the exact versioned Lambdas.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import stat
import sys
from typing import Any, Mapping, Sequence


REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tooling.platform_authority_plan_permission_repair import (  # noqa: E402
    PlanPermissionRepairError,
    RepairBinding,
    build_private_intent,
    immutable_configuration_digest_from_parameters,
    sanitized_blocked_receipt,
    validate_private_intent,
    validate_private_ledger,
    validate_public_receipt,
)


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise PlanPermissionRepairError(
                "DUPLICATE_JSON_KEY", "operational JSON has duplicate keys"
            )
        value[key] = item
    return value


def _read_object(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise PlanPermissionRepairError(
            "INPUT_FILE_INVALID", "input must be one regular file"
        )
    try:
        value = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
        )
    except PlanPermissionRepairError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise PlanPermissionRepairError(
            "INPUT_JSON_INVALID", "input JSON is unavailable or malformed"
        ) from exc
    if type(value) is not dict:
        raise PlanPermissionRepairError(
            "INPUT_JSON_INVALID", "input JSON must be one object"
        )
    return value


def _write_private(path: Path, value: Mapping[str, Any]) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if path.parent.is_symlink():
        raise PlanPermissionRepairError(
            "OUTPUT_PATH_INVALID", "output parent cannot be a symlink"
        )
    payload = (json.dumps(value, sort_keys=True, indent=2) + "\n").encode()
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
    except OSError as exc:
        raise PlanPermissionRepairError(
            "OUTPUT_WRITE_BLOCKED", "private output could not be created"
        ) from exc
    if stat.S_IMODE(path.stat().st_mode) != 0o600:
        raise PlanPermissionRepairError(
            "OUTPUT_MODE_INVALID", "private output is not mode 0600"
        )


def _emit(value: Mapping[str, Any], *, stream: Any = sys.stdout) -> None:
    stream.write(json.dumps(value, sort_keys=True, separators=(",", ":")))
    stream.write("\n")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)

    materialize = commands.add_parser(
        "materialize-intent",
        help="Materialize one private intent from an offline binding.",
    )
    materialize.add_argument("--binding", type=Path, required=True)
    materialize.add_argument("--output", type=Path, required=True)

    configuration = commands.add_parser(
        "materialize-configuration-digest",
        help=(
            "Derive the replacement-bound Lambda configuration digest from "
            "one exact private CloudFormation parameter projection."
        ),
    )
    configuration.add_argument("--parameters", type=Path, required=True)

    for command in ("validate-intent", "validate-ledger", "validate-receipt"):
        validate = commands.add_parser(command)
        validate.add_argument("--input", type=Path, required=True)

    for command in ("plan", "repair", "reconcile"):
        commands.add_parser(
            command,
            help=(
                "Fail closed locally; this mode exists only inside its exact "
                "versioned Lambda contract."
            ),
        )
    return parser


def _materialize(args: argparse.Namespace) -> dict[str, Any]:
    binding = RepairBinding.from_mapping(_read_object(args.binding))
    intent = build_private_intent(binding, repo_root=REPO_ROOT)
    _write_private(args.output, intent)
    return {
        "record_type": (
            "scanalyze.platform_authority."
            "plan_permission_repair_materialization_receipt.v1"
        ),
        "status": "PRIVATE_INTENT_MATERIALIZED",
        "intent_digest": intent["intent_digest"],
        "predecessor_policy_digest": intent["predecessor_policy_digest"],
        "target_policy_digest": intent["target_policy_digest"],
        "policy_delta_digest": intent["policy_delta_digest"],
        "aws_calls": 0,
        "aws_mutations": 0,
        "direct_human_sso_mutation_authorized": False,
        "production_status": "NO-GO",
    }


def _materialize_configuration_digest(
    args: argparse.Namespace,
) -> dict[str, Any]:
    digest = immutable_configuration_digest_from_parameters(
        _read_object(args.parameters)
    )
    return {
        "record_type": (
            "scanalyze.platform_authority."
            "plan_permission_repair_configuration_digest.v1"
        ),
        "status": "IMMUTABLE_CONFIGURATION_DIGEST_MATERIALIZED",
        "cloudformation_parameter": {
            "ParameterKey": "ImmutableConfigurationDigest",
            "ParameterValue": digest,
        },
        "aws_calls": 0,
        "aws_mutations": 0,
        "direct_human_sso_mutation_authorized": False,
        "production_status": "NO-GO",
    }


def _validate(args: argparse.Namespace) -> dict[str, Any]:
    value = _read_object(args.input)
    validator = {
        "validate-intent": validate_private_intent,
        "validate-ledger": validate_private_ledger,
        "validate-receipt": validate_public_receipt,
    }[args.command]
    validator(value)
    digest_field = {
        "validate-intent": "intent_digest",
        "validate-ledger": "ledger_digest",
        "validate-receipt": "receipt_digest",
    }[args.command]
    return {
        "record_type": (
            "scanalyze.platform_authority."
            "plan_permission_repair_validation_receipt.v1"
        ),
        "status": "CONTRACT_VALIDATED",
        "contract_kind": args.command.removeprefix("validate-"),
        "contract_digest": value[digest_field],
        "aws_calls": 0,
        "aws_mutations": 0,
        "direct_human_sso_mutation_authorized": False,
        "production_status": "NO-GO",
    }


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.command in {"plan", "repair", "reconcile"}:
        _emit(
            sanitized_blocked_receipt(
                "EXACT_VERSIONED_LAMBDA_CONTRACT_REQUIRED"
            ),
            stream=sys.stderr,
        )
        return 2
    try:
        result = (
            _materialize(args)
            if args.command == "materialize-intent"
            else (
                _materialize_configuration_digest(args)
                if args.command == "materialize-configuration-digest"
                else _validate(args)
            )
        )
    except PlanPermissionRepairError as exc:
        _emit(sanitized_blocked_receipt(exc.code), stream=sys.stderr)
        return 2
    _emit(result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
