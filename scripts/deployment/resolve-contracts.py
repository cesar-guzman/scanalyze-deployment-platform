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
DEFAULT_CATALOG = REPO_ROOT / "deployment" / "contract-catalog.v1.json"
DEFAULT_CATALOG_SCHEMA = REPO_ROOT / "schemas" / "contract-catalog.v1.schema.json"
DEFAULT_DAG = REPO_ROOT / "deployment" / "layers.yaml"
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tooling.validate_digest import canonicalize, compute_digest  # noqa: E402


class ResolutionError(Exception):
    """An expected, sanitized contract-resolution failure."""


LAYER_PATTERN = re.compile(r"^[a-z][a-z0-9-]*$")
RESERVED_PROJECTION_FIELDS = {
    "contract_id",
    "schema_version",
    "customer_id",
    "deployment_id",
    "account_id",
    "region",
    "release_manifest_digest",
    "contract_digest",
}


def _is_within(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
    except ValueError:
        return False
    return True


def _load_json(path: Path, description: str) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ResolutionError(f"unable to read valid JSON from {description}") from exc


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


def _catalog_output_schema(record: dict[str, Any]) -> Path:
    relative = record.get("output_schema")
    if not isinstance(relative, str):
        raise ResolutionError("catalog output schema declaration is invalid")
    schema_root = (REPO_ROOT / "schemas").resolve()
    path = (REPO_ROOT / relative).resolve()
    if not _is_within(path, schema_root) or not path.is_file():
        raise ResolutionError("declared output schema is not available")
    return path


def _expected_terraform_contracts(dag: Any, catalog: dict[str, Any], layer: str) -> set[str]:
    if not isinstance(dag, dict) or not isinstance(dag.get("layers"), list):
        raise ResolutionError("canonical DAG document is invalid")
    stage = next(
        (item for item in dag["layers"] if isinstance(item, dict) and item.get("layer") == layer),
        None,
    )
    if stage is None:
        raise ResolutionError("consumer layer is not declared by the canonical DAG")
    required = stage.get("requires_contracts")
    if not isinstance(required, list):
        raise ResolutionError("canonical DAG contract declaration is invalid")
    records = catalog["contracts"]
    return {
        contract_id
        for contract_id in required
        if records.get(contract_id, {}).get("authority") == "terraform-root"
    }


def _metadata_value(contract: dict[str, Any], name: str) -> str:
    if name == "output_schema_major":
        return contract["output_schema_version"].rsplit("/v", 1)[1]
    value = contract.get(name)
    if not isinstance(value, str):
        raise ResolutionError("catalog metadata binding references an invalid field")
    return value


def _contract_projection(contract: dict[str, Any], outputs: dict[str, Any]) -> dict[str, Any]:
    projection: dict[str, Any] = {
        "contract_id": contract["output_schema_version"],
        "schema_version": contract["output_schema_version"].rsplit("/v", 1)[1],
        "customer_id": contract["customer_id"],
        "deployment_id": contract["deployment_id"],
        "account_id": contract["aws_account_id"],
        "region": contract["region"],
        "release_manifest_digest": contract["release_digest"],
        "contract_digest": contract["contract_digest"],
    }
    for key, value in outputs.items():
        if key in RESERVED_PROJECTION_FIELDS and projection[key] != value:
            raise ResolutionError("contract output conflicts with authoritative envelope metadata")
        projection[key] = value
    return projection


def _bind_variables(
    variables: dict[str, Any],
    contract: dict[str, Any],
    outputs: dict[str, Any],
    binding: dict[str, Any],
) -> None:
    additions: dict[str, Any] = {}
    contract_variable = binding.get("contract_variable")
    if contract_variable is not None:
        additions[contract_variable] = _contract_projection(contract, outputs)

    for source, destination in binding.get("output_variables", {}).items():
        if source not in outputs:
            raise ResolutionError("catalog binding references a missing contract output")
        additions[destination] = outputs[source]

    for source, destinations in binding.get("metadata_variables", {}).items():
        value = _metadata_value(contract, source)
        for destination in destinations:
            additions[destination] = value

    collision = set(variables) & set(additions)
    if collision:
        raise ResolutionError("consumer bindings contain an ambiguous destination variable")
    variables.update(additions)


def _validate_contract(
    contract: Any,
    envelope_schema: dict[str, Any],
    *,
    catalog: dict[str, Any],
    layer: str,
    customer_id: str,
    deployment_id: str,
    account_id: str,
    region: str,
    release_digest: str,
    release_version: str,
    resolved_at: datetime,
    max_contract_age_seconds: int,
    required_contracts: set[str],
) -> tuple[str, dict[str, Any], dict[str, Any], dict[str, Any]]:
    if not isinstance(contract, dict):
        raise ResolutionError("contract must be a JSON object")
    _validate_schema(contract, envelope_schema, "contract envelope")

    contract_id = contract.get("output_schema_version")
    if not isinstance(contract_id, str) or contract_id not in required_contracts:
        raise ResolutionError("contract does not match a declared contract identifier")

    record = catalog["contracts"].get(contract_id)
    if not isinstance(record, dict) or record.get("authority") != "terraform-root":
        raise ResolutionError("contract is not owned by a Terraform root")
    binding = record.get("consumer_bindings", {}).get(layer)
    if not isinstance(binding, dict):
        raise ResolutionError("contract is not authorized for consumer target")

    producer_layer = record.get("producer")
    if contract.get("layer") != producer_layer:
        raise ResolutionError("contract layer does not match the catalog producer")
    if contract.get("producer") != f"roots/{producer_layer}":
        raise ResolutionError("contract producer is not the canonical producer")
    if contract.get("scope") != record.get("scope"):
        raise ResolutionError("contract scope does not match the catalog declaration")

    if contract.get("customer_id") != customer_id:
        raise ResolutionError("contract customer binding mismatch")
    if contract.get("deployment_id") != deployment_id:
        raise ResolutionError("contract deployment binding mismatch")
    if contract.get("aws_account_id") != account_id:
        raise ResolutionError("contract account binding mismatch")
    if contract.get("release_digest") != release_digest:
        raise ResolutionError("contract release binding mismatch")
    if contract.get("release_version") != release_version:
        raise ResolutionError("contract release version binding mismatch")

    scope = contract.get("scope")
    contract_region = contract.get("region")
    if scope == "regional" and contract_region != region:
        raise ResolutionError("regional contract region binding mismatch")
    if scope == "global" and contract_region != "global":
        raise ResolutionError("global contract must use the global region marker")

    expected_state_key = (
        f"{deployment_id}/{producer_layer}/terraform.tfstate"
        if scope == "global"
        else f"{deployment_id}/{region}/{producer_layer}/terraform.tfstate"
    )
    if contract.get("state_key") != expected_state_key:
        raise ResolutionError("contract state ownership binding mismatch")

    produced_at = _parse_timestamp(contract["produced_at"], "contract produced_at")
    age_seconds = (resolved_at - produced_at).total_seconds()
    if age_seconds < -300:
        raise ResolutionError("contract production timestamp is in the future")
    if age_seconds > max_contract_age_seconds:
        raise ResolutionError("contract is stale for this resolution window")

    outputs = contract.get("outputs")
    if not isinstance(outputs, dict):
        raise ResolutionError("contract outputs must be an object")
    output_schema = _load_json(_catalog_output_schema(record), "output schema")
    if not isinstance(output_schema, dict):
        raise ResolutionError("output schema must be a JSON object")
    _validate_schema(outputs, output_schema, "contract outputs")
    if compute_digest(canonicalize(outputs)) != contract.get("contract_digest"):
        raise ResolutionError("contract digest verification failed")

    return contract_id, contract, outputs, binding


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
            json.dump(document, handle, sort_keys=True, indent=2, ensure_ascii=True)
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
    parser.add_argument("--resolved-at", help="explicit RFC 3339 orchestrator time")
    parser.add_argument("--max-contract-age-seconds", type=int, default=86400)
    parser.add_argument(
        "--required-contract",
        action="append",
        required=True,
        help="required '<producer>/vN' contract; repeatable",
    )
    parser.add_argument("--schema", type=Path, default=DEFAULT_SCHEMA)
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
        if args.max_contract_age_seconds <= 0:
            raise ResolutionError("max contract age must be positive")
        resolved_at = _parse_timestamp(args.resolved_at, "resolved_at")

        envelope_schema = _load_json(args.schema, "contract schema")
        catalog = _load_json(args.catalog, "contract catalog")
        catalog_schema = _load_json(args.catalog_schema, "contract catalog schema")
        dag = _load_yaml(args.dag, "canonical DAG")
        if not all(isinstance(item, dict) for item in (envelope_schema, catalog, catalog_schema)):
            raise ResolutionError("contract resolver configuration is invalid")
        _validate_schema(catalog, catalog_schema, "contract catalog")

        required_contracts = set(args.required_contract)
        if len(required_contracts) != len(args.required_contract):
            raise ResolutionError("--required-contract values must be unique")

        expected_contracts = _expected_terraform_contracts(dag, catalog, args.layer)
        resolved: dict[str, dict[str, Any]] = {}
        variables: dict[str, Any] = {}
        for path in _fixture_paths(args):
            contract = _load_json(path, "contract fixture")
            contract_id, envelope, outputs, binding = _validate_contract(
                contract,
                envelope_schema,
                catalog=catalog,
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
            )
            if contract_id in resolved:
                raise ResolutionError("duplicate contract fixture")
            _bind_variables(variables, envelope, outputs, binding)
            resolved[contract_id] = envelope

        missing = required_contracts - set(resolved)
        if missing:
            raise ResolutionError("one or more required contracts are missing")
        if required_contracts != expected_contracts:
            raise ResolutionError("required contract set does not match the canonical DAG target")

        contract_evidence = [
            {
                "contract_id": contract_id,
                "contract_digest": resolved[contract_id]["contract_digest"],
                "module_source_digest": resolved[contract_id]["module_source_digest"],
                "producer": resolved[contract_id]["producer"],
                "release_version": resolved[contract_id]["release_version"],
                "produced_at": resolved[contract_id]["produced_at"],
            }
            for contract_id in sorted(resolved)
        ]
        resolution: dict[str, Any] = {
            "schema_version": "1",
            "consumer_layer": args.layer,
            "customer_id": args.customer_id,
            "deployment_id": args.deployment_id,
            "aws_account_id": args.account_id,
            "region": args.region,
            "release_version": args.release_version,
            "release_digest": args.release_digest,
            "resolved_at": args.resolved_at,
            "required_contracts": contract_evidence,
            "variables": variables,
        }
        resolution["resolution_digest"] = compute_digest(canonicalize(resolution))
        output_path, descriptor = _select_output_path(args.layer, args.out)
        _write_document(output_path, descriptor, resolution)
    except ResolutionError as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1
    except (OSError, TypeError, ValueError):
        print("FAIL: unable to resolve contracts safely", file=sys.stderr)
        return 1

    print(f"PASS: resolved {len(resolved)} contract(s) for {args.layer}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
