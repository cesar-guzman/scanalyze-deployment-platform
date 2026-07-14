#!/usr/bin/env python3
"""Validate a contract-resolution artifact and materialize Terraform variables."""
from __future__ import annotations

import argparse
import json
import os
import stat
import sys
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parent.parent.parent
DEFAULT_SCHEMA = REPO_ROOT / "schemas" / "contract-resolution.v1.schema.json"
DEFAULT_CATALOG = REPO_ROOT / "deployment" / "contract-catalog.v1.json"
DEFAULT_CATALOG_SCHEMA = REPO_ROOT / "schemas" / "contract-catalog.v1.schema.json"
DEFAULT_DAG = REPO_ROOT / "deployment" / "layers.yaml"
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tooling.validate_digest import canonicalize, compute_digest  # noqa: E402


class ValidationError(Exception):
    """Expected sanitized validation failure."""


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
        raise ValidationError(f"unable to read valid JSON from {description}") from exc


def _load_yaml(path: Path, description: str) -> Any:
    try:
        import yaml
    except ImportError as exc:
        raise ValidationError("BLOCKED_TOOLING: PyYAML is not installed") from exc
    try:
        return yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, yaml.YAMLError) as exc:
        raise ValidationError(f"unable to read valid YAML from {description}") from exc


def _validate_schema(instance: Any, schema: dict[str, Any]) -> None:
    try:
        import jsonschema
    except ImportError as exc:
        raise ValidationError("BLOCKED_TOOLING: jsonschema is not installed") from exc
    validator = jsonschema.Draft202012Validator(
        schema,
        format_checker=jsonschema.FormatChecker(),
    )
    error = next(iter(validator.iter_errors(instance)), None)
    if error is not None:
        path = ".".join(str(part) for part in error.absolute_path) or "(root)"
        raise ValidationError(
            f"resolution schema validation failed at {path} (validator={error.validator})"
        )


def _write_exclusive(path: Path, document: dict[str, Any]) -> None:
    resolved = path.expanduser().resolve(strict=False)
    if _is_within(resolved, REPO_ROOT.resolve()):
        raise ValidationError("materialized variables must remain outside the repository")
    if not resolved.parent.is_dir():
        raise ValidationError("materialized variable directory does not exist")
    descriptor: int | None = None
    created = False
    try:
        descriptor = os.open(resolved, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        created = True
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            descriptor = None
            json.dump(document, handle, sort_keys=True, indent=2, ensure_ascii=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(resolved, stat.S_IRUSR | stat.S_IWUSR)
    except (OSError, TypeError, ValueError) as exc:
        if created:
            resolved.unlink(missing_ok=True)
        raise ValidationError("unable to materialize exclusive Terraform variables") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _canonical_requirements(
    catalog: dict[str, Any], dag: Any, layer: str
) -> tuple[dict[str, str], set[str]]:
    if not isinstance(dag, dict) or not isinstance(dag.get("layers"), list):
        raise ValidationError("canonical DAG document is invalid")
    stage = next(
        (item for item in dag["layers"] if isinstance(item, dict) and item.get("layer") == layer),
        None,
    )
    if stage is None or not isinstance(stage.get("requires_contracts"), list):
        raise ValidationError("consumer layer contract declaration is invalid")
    records = catalog.get("contracts")
    if not isinstance(records, dict):
        raise ValidationError("contract catalog is invalid")

    requirements: dict[str, str] = {}
    variable_names: set[str] = set()
    for contract_id in stage["requires_contracts"]:
        record = records.get(contract_id)
        if not isinstance(record, dict):
            raise ValidationError("canonical DAG references an unknown contract")
        if record.get("authority") != "terraform-root":
            continue
        producer = record.get("producer")
        binding = record.get("consumer_bindings", {}).get(layer)
        if not isinstance(producer, str) or not isinstance(binding, dict):
            raise ValidationError("canonical contract ownership binding is invalid")
        requirements[contract_id] = f"roots/{producer}"
        destinations: list[str] = []
        contract_variable = binding.get("contract_variable")
        if contract_variable is not None:
            destinations.append(contract_variable)
        destinations.extend(binding.get("output_variables", {}).values())
        for values in binding.get("metadata_variables", {}).values():
            destinations.extend(values)
        if any(not isinstance(name, str) for name in destinations):
            raise ValidationError("canonical consumer variable binding is invalid")
        if variable_names.intersection(destinations):
            raise ValidationError("canonical consumer variable binding is ambiguous")
        variable_names.update(destinations)
    return requirements, variable_names


def _parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--resolution", type=Path, required=True)
    parser.add_argument("--layer", required=True)
    parser.add_argument("--customer-id", required=True)
    parser.add_argument("--deployment-id", required=True)
    parser.add_argument("--account-id", required=True)
    parser.add_argument("--region", required=True)
    parser.add_argument("--release-version", required=True)
    parser.add_argument("--release-digest", required=True)
    parser.add_argument("--schema", type=Path, default=DEFAULT_SCHEMA)
    parser.add_argument("--catalog", type=Path, default=DEFAULT_CATALOG)
    parser.add_argument("--catalog-schema", type=Path, default=DEFAULT_CATALOG_SCHEMA)
    parser.add_argument("--dag", type=Path, default=DEFAULT_DAG)
    parser.add_argument("--materialize-out", type=Path, required=True)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv or sys.argv[1:])
    try:
        resolution_path = args.resolution.expanduser().resolve(strict=True)
        if _is_within(resolution_path, REPO_ROOT.resolve()):
            raise ValidationError("resolution artifact must remain outside the repository")
        if stat.S_IMODE(resolution_path.stat().st_mode) & 0o077:
            raise ValidationError("resolution artifact permissions must be owner-only")

        resolution = _load_json(resolution_path, "resolution artifact")
        schema = _load_json(args.schema, "resolution schema")
        catalog = _load_json(args.catalog, "contract catalog")
        catalog_schema = _load_json(args.catalog_schema, "contract catalog schema")
        dag = _load_yaml(args.dag, "canonical DAG")
        if not all(
            isinstance(item, dict)
            for item in (resolution, schema, catalog, catalog_schema)
        ):
            raise ValidationError("resolution validator configuration is invalid")
        _validate_schema(resolution, schema)
        _validate_schema(catalog, catalog_schema)

        supplied_digest = resolution.get("resolution_digest")
        digest_input = dict(resolution)
        digest_input.pop("resolution_digest", None)
        if supplied_digest != compute_digest(canonicalize(digest_input)):
            raise ValidationError("resolution digest verification failed")

        expected = {
            "consumer_layer": args.layer,
            "customer_id": args.customer_id,
            "deployment_id": args.deployment_id,
            "aws_account_id": args.account_id,
            "region": args.region,
            "release_version": args.release_version,
            "release_digest": args.release_digest,
        }
        if any(resolution.get(key) != value for key, value in expected.items()):
            raise ValidationError("resolution target binding mismatch")

        evidence = resolution["required_contracts"]
        evidence_ids = [item["contract_id"] for item in evidence]
        if len(evidence_ids) != len(set(evidence_ids)):
            raise ValidationError("resolution contains duplicate contract evidence")
        requirements, variable_names = _canonical_requirements(catalog, dag, args.layer)
        if set(evidence_ids) != set(requirements):
            raise ValidationError("resolution contract set does not match the canonical DAG target")
        if any(
            item["producer"] != requirements[item["contract_id"]]
            or item["release_version"] != args.release_version
            for item in evidence
        ):
            raise ValidationError("resolution contract ownership binding mismatch")
        if set(resolution["variables"]) != variable_names:
            raise ValidationError("resolution variables do not match canonical consumer bindings")
        _write_exclusive(args.materialize_out, resolution["variables"])
    except (ValidationError, FileNotFoundError) as exc:
        message = str(exc) if isinstance(exc, ValidationError) else "resolution artifact does not exist"
        print(f"FAIL: {message}", file=sys.stderr)
        return 1
    except (OSError, TypeError, ValueError):
        print("FAIL: unable to validate contract resolution safely", file=sys.stderr)
        return 1

    print("PASS: contract resolution verified and variables materialized")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
