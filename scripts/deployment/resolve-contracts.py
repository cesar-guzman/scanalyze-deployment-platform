#!/usr/bin/env python3
"""Resolve verified layer contracts into a content-bound consumer input.

Fixture mode is test-only and requires an explicit acknowledgement.  The live
SSM reader intentionally remains blocked until the protected engine in GUG-125
can supply the same immutable inputs without adding a second trust path.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import stat
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parent.parent.parent
DEFAULT_SCHEMA = REPO_ROOT / "schemas" / "layer-contract.v2.schema.json"
DEFAULT_RESOLUTION_SCHEMA = (
    REPO_ROOT / "schemas" / "contract-resolution.v3.schema.json"
)
DEFAULT_CATALOG = REPO_ROOT / "deployment" / "contract-catalog.v1.json"
DEFAULT_CATALOG_SCHEMA = REPO_ROOT / "schemas" / "contract-catalog.v1.schema.json"
DEFAULT_DAG = REPO_ROOT / "deployment" / "layers.yaml"
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tooling.validate_digest import canonicalize, compute_digest  # noqa: E402
from contract_projection import (  # noqa: E402
    ContractProjectionError,
    load_json,
    project_contracts,
)


class ResolutionError(Exception):
    """An expected, sanitized contract-resolution failure."""


LAYER_PATTERN = re.compile(r"^[a-z][a-z0-9-]*$")
MAX_CONTRACT_AGE_SECONDS = 86400


def _is_within(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
    except ValueError:
        return False
    return True


def _load_yaml(path: Path, description: str) -> Any:
    try:
        import yaml
    except ImportError as exc:
        raise ResolutionError("BLOCKED_TOOLING: PyYAML is not installed") from exc
    try:
        return yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, yaml.YAMLError) as exc:
        raise ResolutionError(f"unable to read valid YAML from {description}") from exc


def _schema_error(instance: Any, schema: dict[str, Any]) -> str | None:
    try:
        import jsonschema
    except ImportError as exc:
        raise ResolutionError("BLOCKED_TOOLING: jsonschema is not installed") from exc
    validator = jsonschema.Draft202012Validator(
        schema,
        format_checker=jsonschema.FormatChecker(),
    )
    error = next(iter(validator.iter_errors(instance)), None)
    if error is None:
        return None
    path = ".".join(str(part) for part in error.absolute_path) or "(root)"
    return f"schema validation failed at {path} (validator={error.validator})"


def _validate_schema(instance: Any, schema: dict[str, Any], description: str) -> None:
    error = _schema_error(instance, schema)
    if error:
        raise ResolutionError(f"{description} {error}")


def _parse_timestamp(value: str, description: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (AttributeError, ValueError) as exc:
        raise ResolutionError(f"{description} is not a valid RFC 3339 timestamp") from exc
    if parsed.utcoffset() is None:
        raise ResolutionError(f"{description} must include a timezone")
    return parsed.astimezone(timezone.utc)


def _fixture_paths(args: argparse.Namespace) -> list[Path]:
    if args.contract:
        return [Path(value) for value in args.contract]
    if args.contracts_dir:
        directory = Path(args.contracts_dir)
        if not directory.is_dir():
            raise ResolutionError("contracts directory does not exist")
        paths = sorted(directory.glob("*.json"))
        if not paths:
            raise ResolutionError("contracts directory contains no JSON fixtures")
        return paths
    raise ResolutionError("no fixture source was selected")


def _select_output_path(layer: str, requested: Path | None) -> tuple[Path, int]:
    repo_root = REPO_ROOT.resolve()
    if requested is not None:
        output_path = requested.expanduser().resolve(strict=False)
        if _is_within(output_path, repo_root):
            raise ResolutionError("resolution output must be outside the repository")
        if output_path.suffix != ".json":
            raise ResolutionError("resolution output must use a .json suffix")
        if not output_path.parent.is_dir():
            raise ResolutionError("resolution output directory does not exist")
        try:
            descriptor = os.open(output_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except OSError as exc:
            raise ResolutionError("unable to create exclusive resolution output") from exc
        return output_path, descriptor

    temp_root = Path(os.environ.get("RUNNER_TEMP", tempfile.gettempdir())).resolve()
    if not temp_root.is_dir() or _is_within(temp_root, repo_root):
        raise ResolutionError("ephemeral output directory is not safe")
    descriptor, filename = tempfile.mkstemp(
        prefix=f"scanalyze-{layer}-",
        suffix=".resolution.json",
        dir=temp_root,
        text=True,
    )
    os.fchmod(descriptor, stat.S_IRUSR | stat.S_IWUSR)
    return Path(filename), descriptor


def _write_document(path: Path, descriptor: int, document: dict[str, Any]) -> None:
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(
                document,
                handle,
                sort_keys=True,
                indent=2,
                ensure_ascii=True,
                allow_nan=False,
            )
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
    except Exception:
        path.unlink(missing_ok=True)
        raise


def _parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--contract", action="append", help="contract fixture JSON; repeatable")
    source.add_argument("--contracts-dir", type=Path, help="directory containing contract fixtures")
    source.add_argument("--live", action="store_true", help="future read-only SSM resolution mode")
    parser.add_argument("--allow-fixtures", action="store_true", help="explicitly permit test fixtures")
    parser.add_argument("--layer", required=True, help="consumer layer")
    parser.add_argument("--customer-id")
    parser.add_argument("--deployment-id", required=True)
    parser.add_argument("--account-id", required=True)
    parser.add_argument("--region", required=True)
    parser.add_argument("--release-digest", required=True)
    parser.add_argument("--release-version", required=True)
    parser.add_argument(
        "--expected-account-ready-digest",
        help="independent digest from the authorized backend binding",
    )
    parser.add_argument("--resolved-at", help="explicit RFC 3339 orchestrator time")
    parser.add_argument("--max-contract-age-seconds", type=int, default=86400)
    parser.add_argument(
        "--required-contract",
        action="append",
        required=True,
        help="required '<producer>/vN' contract; repeatable",
    )
    parser.add_argument("--schema", type=Path, default=DEFAULT_SCHEMA)
    parser.add_argument(
        "--resolution-schema",
        type=Path,
        default=DEFAULT_RESOLUTION_SCHEMA,
    )
    parser.add_argument("--catalog", type=Path, default=DEFAULT_CATALOG)
    parser.add_argument("--catalog-schema", type=Path, default=DEFAULT_CATALOG_SCHEMA)
    parser.add_argument("--dag", type=Path, default=DEFAULT_DAG)
    parser.add_argument("--out", type=Path, help="exclusive output path outside the repository")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv or sys.argv[1:])

    if args.live:
        if os.environ.get("SCANALYZE_ALLOW_LIVE") != "1":
            print("BLOCKED_LIVE: set SCANALYZE_ALLOW_LIVE=1 to acknowledge live mode", file=sys.stderr)
            return 2
        print("BLOCKED_LIVE: SSM contract resolution is not implemented until GUG-125", file=sys.stderr)
        return 2

    if not args.allow_fixtures:
        print("BLOCKED_FIXTURES: fixture input requires explicit --allow-fixtures", file=sys.stderr)
        return 2

    try:
        if not LAYER_PATTERN.fullmatch(args.layer):
            raise ResolutionError("consumer layer identifier is invalid")
        if not args.customer_id:
            raise ResolutionError("--customer-id is required for fixture resolution")
        if not args.resolved_at:
            raise ResolutionError("--resolved-at is required for fixture resolution")
        if not 0 < args.max_contract_age_seconds <= MAX_CONTRACT_AGE_SECONDS:
            raise ResolutionError("max contract age is outside the approved range")
        resolved_at = _parse_timestamp(args.resolved_at, "resolved_at")

        envelope_schema = load_json(args.schema, "contract schema")
        resolution_schema = load_json(args.resolution_schema, "resolution schema")
        catalog = load_json(args.catalog, "contract catalog")
        catalog_schema = load_json(args.catalog_schema, "contract catalog schema")
        dag = _load_yaml(args.dag, "canonical DAG")
        if not all(
            isinstance(item, dict)
            for item in (
                envelope_schema,
                resolution_schema,
                catalog,
                catalog_schema,
            )
        ):
            raise ResolutionError("contract resolver configuration is invalid")
        _validate_schema(catalog, catalog_schema, "contract catalog")

        required_contracts = set(args.required_contract)
        if len(required_contracts) != len(args.required_contract):
            raise ResolutionError("--required-contract values must be unique")

        contracts = [
            load_json(path, "contract fixture")
            for path in _fixture_paths(args)
        ]
        resolved, _ = project_contracts(
            contracts,
            envelope_schema,
            catalog=catalog,
            dag=dag,
            layer=args.layer,
            customer_id=args.customer_id,
            deployment_id=args.deployment_id,
            account_id=args.account_id,
            region=args.region,
            release_digest=args.release_digest,
            release_version=args.release_version,
            resolved_at=resolved_at,
            max_contract_age_seconds=args.max_contract_age_seconds,
            required_contracts=required_contracts,
            expected_account_ready_digest=args.expected_account_ready_digest,
        )
        resolution: dict[str, Any] = {
            "schema_version": "3",
            "consumer_layer": args.layer,
            "customer_id": args.customer_id,
            "deployment_id": args.deployment_id,
            "aws_account_id": args.account_id,
            "region": args.region,
            "release_version": args.release_version,
            "release_digest": args.release_digest,
            "resolved_at": args.resolved_at,
            "max_contract_age_seconds": args.max_contract_age_seconds,
            "required_contracts": [
                resolved[contract_id] for contract_id in sorted(resolved)
            ],
        }
        resolution["resolution_digest"] = compute_digest(canonicalize(resolution))
        _validate_schema(resolution, resolution_schema, "resolution")
        output_path, descriptor = _select_output_path(args.layer, args.out)
        _write_document(output_path, descriptor, resolution)
    except (ResolutionError, ContractProjectionError) as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1
    except (OSError, TypeError, ValueError):
        print("FAIL: unable to resolve contracts safely", file=sys.stderr)
        return 1

    print(f"PASS: resolved {len(resolved)} contract(s) for {args.layer}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
