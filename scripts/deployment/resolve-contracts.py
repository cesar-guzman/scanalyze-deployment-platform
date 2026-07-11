#!/usr/bin/env python3
"""Resolve validated layer-contract fixtures into an ephemeral Terraform var-file.

This PR deliberately implements no AWS access.  Fixture input requires the
explicit ``--allow-mocks`` acknowledgement, and the future live mode remains
blocked even when its environment guard is present.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import stat
import sys
import tempfile
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parent.parent.parent
DEFAULT_SCHEMA = REPO_ROOT / "schemas" / "layer-contract.schema.json"
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tooling.validate_digest import canonicalize, compute_digest  # noqa: E402


class ResolutionError(Exception):
    """An expected, sanitized contract-resolution failure."""


LAYER_PATTERN = re.compile(r"^[a-z][a-z0-9-]*$")


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


def _schema_error(contract: dict[str, Any], schema: dict[str, Any]) -> str | None:
    try:
        import jsonschema
    except ImportError as exc:
        raise ResolutionError("BLOCKED_TOOLING: jsonschema is not installed") from exc

    validator = jsonschema.Draft202012Validator(
        schema,
        format_checker=jsonschema.FormatChecker(),
    )
    error = next(iter(validator.iter_errors(contract)), None)
    if error is None:
        return None
    path = ".".join(str(part) for part in error.absolute_path) or "(root)"
    # Do not include jsonschema's message: it can contain the rejected value.
    return f"schema validation failed at {path} (validator={error.validator})"


def _layer_output_schema_path(contract_id: str) -> Path:
    if "/" not in contract_id:
        raise ResolutionError("contract output_schema_version is invalid")
    layer, version = contract_id.rsplit("/", 1)
    if not layer or not version.startswith("v") or not version[1:].isdigit() or "/" in layer:
        raise ResolutionError("contract output_schema_version is invalid")
    filename = (
        f"cicd-contract.{version}.schema.json"
        if layer == "cicd"
        else f"contract-{layer}.{version}.schema.json"
    )
    schema_root = (REPO_ROOT / "schemas").resolve()
    path = (schema_root / filename).resolve()
    if not _is_within(path, schema_root) or not path.is_file():
        raise ResolutionError("declared output schema is not available")
    return path


def _validate_contract(
    contract: Any,
    schema: dict[str, Any],
    *,
    deployment_id: str,
    account_id: str,
    region: str,
    release_digest: str,
    required_contracts: set[str],
) -> tuple[str, dict[str, Any]]:
    if not isinstance(contract, dict):
        raise ResolutionError("contract must be a JSON object")

    validation_error = _schema_error(contract, schema)
    if validation_error:
        raise ResolutionError(validation_error)

    contract_id = contract.get("output_schema_version")
    if contract_id not in required_contracts:
        raise ResolutionError("contract is not declared by --required-contract")
    if not isinstance(contract_id, str) or "/" not in contract_id:
        raise ResolutionError("contract output_schema_version is invalid")

    producer_layer = contract_id.rsplit("/", 1)[0]
    if contract.get("layer") != producer_layer:
        raise ResolutionError("contract layer does not own output_schema_version")
    if contract.get("producer") != f"roots/{producer_layer}":
        raise ResolutionError("contract producer is not the canonical root owner")

    if contract.get("deployment_id") != deployment_id:
        raise ResolutionError("contract deployment binding mismatch")
    if contract.get("aws_account_id") != account_id:
        raise ResolutionError("contract account binding mismatch")
    if contract.get("release_digest") != release_digest:
        raise ResolutionError("contract release binding mismatch")

    scope = contract.get("scope")
    contract_region = contract.get("region")
    if scope == "regional" and contract_region != region:
        raise ResolutionError("regional contract region binding mismatch")
    if scope == "global" and contract_region != "global":
        raise ResolutionError("global contract must use the global region marker")

    state_region = "global" if scope == "global" else region
    expected_state_key = (
        f"{deployment_id}/{producer_layer}/terraform.tfstate"
        if scope == "global"
        else f"{deployment_id}/{state_region}/{producer_layer}/terraform.tfstate"
    )
    if contract.get("state_key") != expected_state_key:
        raise ResolutionError("contract state ownership binding mismatch")

    outputs = contract.get("outputs")
    if not isinstance(outputs, dict):
        raise ResolutionError("contract outputs must be an object")
    output_schema = _load_json(_layer_output_schema_path(contract_id), "output schema")
    if not isinstance(output_schema, dict):
        raise ResolutionError("output schema must be a JSON object")
    output_validation_error = _schema_error(outputs, output_schema)
    if output_validation_error:
        raise ResolutionError(f"outputs {output_validation_error}")
    if compute_digest(canonicalize(outputs)) != contract.get("contract_digest"):
        raise ResolutionError("contract digest verification failed")

    return contract_id, outputs


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
            raise ResolutionError("var-file output must be outside the repository")
        if output_path.suffix != ".json":
            raise ResolutionError("var-file output must use a .json suffix")
        if not output_path.parent.is_dir():
            raise ResolutionError("var-file output directory does not exist")
        try:
            descriptor = os.open(
                output_path,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                0o600,
            )
        except OSError as exc:
            raise ResolutionError("unable to create exclusive var-file output") from exc
        return output_path, descriptor

    temp_root = Path(os.environ.get("RUNNER_TEMP", tempfile.gettempdir())).resolve()
    if not temp_root.is_dir():
        raise ResolutionError("ephemeral output directory does not exist")
    if _is_within(temp_root, repo_root):
        raise ResolutionError("ephemeral output directory must be outside the repository")
    try:
        descriptor, filename = tempfile.mkstemp(
            prefix=f"scanalyze-{layer}-",
            suffix=".auto.tfvars.json",
            dir=temp_root,
            text=True,
        )
    except OSError as exc:
        raise ResolutionError("unable to create ephemeral var-file") from exc
    os.fchmod(descriptor, stat.S_IRUSR | stat.S_IWUSR)
    return Path(filename), descriptor


def _write_var_file(path: Path, descriptor: int, variables: dict[str, Any]) -> None:
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(variables, handle, sort_keys=True, indent=2, ensure_ascii=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
    except Exception:
        try:
            path.unlink(missing_ok=True)
        finally:
            raise


def _parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--contract", action="append", help="contract fixture JSON; repeatable")
    source.add_argument("--contracts-dir", type=Path, help="directory containing contract fixtures")
    source.add_argument("--live", action="store_true", help="future read-only SSM resolution mode")
    parser.add_argument("--allow-mocks", action="store_true", help="explicitly permit fixture input")
    parser.add_argument("--layer", required=True, help="consumer layer")
    parser.add_argument("--deployment-id", required=True)
    parser.add_argument("--account-id", required=True)
    parser.add_argument("--region", required=True)
    parser.add_argument("--release-digest", required=True)
    parser.add_argument(
        "--required-contract",
        action="append",
        required=True,
        help="required '<producer>/vN' contract; repeatable",
    )
    parser.add_argument("--schema", type=Path, default=DEFAULT_SCHEMA)
    parser.add_argument("--out", type=Path, help="exclusive output path outside the repository")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv or sys.argv[1:])

    if args.live:
        if os.environ.get("SCANALYZE_ALLOW_LIVE") != "1":
            print("BLOCKED_LIVE: set SCANALYZE_ALLOW_LIVE=1 to acknowledge live mode", file=sys.stderr)
            return 2
        print("BLOCKED_LIVE: SSM contract resolution is not implemented in this PR", file=sys.stderr)
        return 2

    if not args.allow_mocks:
        print("BLOCKED_MOCKS: fixture input requires explicit --allow-mocks", file=sys.stderr)
        return 2

    try:
        if not LAYER_PATTERN.fullmatch(args.layer):
            raise ResolutionError("consumer layer identifier is invalid")
        schema = _load_json(args.schema, "contract schema")
        if not isinstance(schema, dict):
            raise ResolutionError("contract schema must be a JSON object")

        required_contracts = set(args.required_contract)
        if len(required_contracts) != len(args.required_contract):
            raise ResolutionError("--required-contract values must be unique")

        resolved: dict[str, dict[str, Any]] = {}
        variables: dict[str, Any] = {}
        for path in _fixture_paths(args):
            contract = _load_json(path, "contract fixture")
            contract_id, outputs = _validate_contract(
                contract,
                schema,
                deployment_id=args.deployment_id,
                account_id=args.account_id,
                region=args.region,
                release_digest=args.release_digest,
                required_contracts=required_contracts,
            )
            if contract_id in resolved:
                raise ResolutionError("duplicate contract fixture")
            for key, value in outputs.items():
                if key in variables:
                    raise ResolutionError("contract outputs contain an ambiguous duplicate variable")
                variables[key] = value
            resolved[contract_id] = outputs

        missing = required_contracts - set(resolved)
        if missing:
            raise ResolutionError("one or more required contracts are missing")

        output_path, descriptor = _select_output_path(args.layer, args.out)
        _write_var_file(output_path, descriptor, variables)
    except ResolutionError as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1
    except (OSError, TypeError, ValueError):
        print("FAIL: unable to resolve contracts safely", file=sys.stderr)
        return 1

    print(f"PASS: resolved {len(resolved)} contract(s) for {args.layer}")
    print(f"VAR_FILE_PATH={output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
