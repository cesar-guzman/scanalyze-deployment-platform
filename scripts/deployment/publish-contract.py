#!/usr/bin/env python3
"""Build and optionally publish a validated immutable layer-contract envelope.

Dry-run behavior remains a local mode-0600 envelope.  Explicit live mode uses
the catalog-owned content-addressed SSM path, create-only semantics, exact tags,
and double readback through an injectable AWS CLI adapter.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import stat
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parent.parent.parent
DEFAULT_SCHEMA_V1 = REPO_ROOT / "schemas" / "layer-contract.schema.json"
DEFAULT_SCHEMA_V2 = REPO_ROOT / "schemas" / "layer-contract.v2.schema.json"
DEFAULT_CATALOG = REPO_ROOT / "deployment" / "contract-catalog.v1.json"
DEFAULT_CATALOG_SCHEMA = REPO_ROOT / "schemas" / "contract-catalog.v1.schema.json"
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tooling.validate_digest import canonicalize, compute_digest  # noqa: E402
from tooling.ssm_contract_live_io import (  # noqa: E402
    LiveContractIoError,
    SubprocessAwsCliRunner,
    publish_immutable_ssm_contract,
    verify_caller_identity,
)


class PublicationError(Exception):
    """An expected, sanitized contract-publication failure."""


RFC3339_PATTERN = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"
    r"(?:\.[0-9]+)?(?:Z|[+-][0-9]{2}:[0-9]{2})$"
)
MAX_LIVE_CLOCK_SKEW_SECONDS = 300


def _validate_produced_at(value: str) -> None:
    """Validate an explicit RFC 3339 timestamp without optional dependencies."""
    if not RFC3339_PATTERN.fullmatch(value):
        raise PublicationError("produced_at must be an explicit RFC 3339 timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise PublicationError("produced_at must be an explicit RFC 3339 timestamp") from exc
    if parsed.utcoffset() is None:
        raise PublicationError("produced_at must include a timezone")


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
        raise PublicationError(f"unable to read valid JSON from {description}") from exc


def _validate_schema(instance: Any, schema: dict[str, Any], description: str) -> None:
    try:
        import jsonschema
    except ImportError as exc:
        raise PublicationError("BLOCKED_TOOLING: jsonschema is not installed") from exc

    validator = jsonschema.Draft202012Validator(
        schema,
        format_checker=jsonschema.FormatChecker(),
    )
    error = next(iter(validator.iter_errors(instance)), None)
    if error is None:
        return
    path = ".".join(str(part) for part in error.absolute_path) or "(root)"
    # The original jsonschema message can echo a sensitive rejected value.
    raise PublicationError(
        f"{description} schema validation failed at {path} (validator={error.validator})"
    )


def _layer_output_schema_path(contract_id: str) -> Path:
    if "/" not in contract_id:
        raise PublicationError("output schema version must use '<layer>/vN'")
    layer, version = contract_id.rsplit("/", 1)
    if not layer or not version.startswith("v") or not version[1:].isdigit():
        raise PublicationError("output schema version must use '<layer>/vN'")
    if any(part in {"", ".", ".."} for part in Path(layer).parts) or "/" in layer:
        raise PublicationError("output schema version contains an invalid layer")
    filename = (
        f"cicd-contract.{version}.schema.json"
        if layer == "cicd"
        else f"contract-{layer}.{version}.schema.json"
    )
    path = (REPO_ROOT / "schemas" / filename).resolve()
    if not _is_within(path, (REPO_ROOT / "schemas").resolve()) or not path.is_file():
        raise PublicationError("declared output schema is not available")
    return path


def _extract_outputs(terraform_document: Any, layer: str, contract_id: str) -> dict[str, Any]:
    if not isinstance(terraform_document, dict):
        raise PublicationError("Terraform output document must be a JSON object")

    values: dict[str, Any] = {}
    contract_payload: dict[str, Any] | None = None
    for name, metadata in terraform_document.items():
        if not isinstance(name, str) or not isinstance(metadata, dict):
            raise PublicationError("Terraform output document has an invalid entry")
        if "value" not in metadata or not isinstance(metadata.get("sensitive"), bool):
            raise PublicationError("Terraform output entry is missing value or sensitive metadata")
        if metadata["sensitive"]:
            raise PublicationError("Terraform output contains a sensitive value and cannot be published")
        if name == "contract_payload":
            if not isinstance(metadata["value"], dict):
                raise PublicationError("contract_payload must be an object")
            contract_payload = metadata["value"]
        else:
            values[name] = metadata["value"]

    if contract_payload is not None:
        declared_layer = contract_payload.get("layer")
        if declared_layer is not None and declared_layer != layer:
            raise PublicationError("contract_payload layer does not match --layer")
        declared_version = contract_payload.get("schema_version")
        expected_version = contract_id.rsplit("/", 1)[-1].removeprefix("v")
        if declared_version is not None and str(declared_version) != expected_version:
            raise PublicationError("contract_payload schema version does not match output schema")
        nested_outputs = contract_payload.get("outputs")
        if nested_outputs is not None:
            if not isinstance(nested_outputs, dict):
                raise PublicationError("contract_payload.outputs must be an object")
            # A nested payload is the sole publishable boundary. Sibling root
            # outputs may remain for Terraform operator compatibility, but can
            # neither add fields nor shadow the versioned contract schema.
            values = dict(nested_outputs)

    if not values:
        raise PublicationError("Terraform output document contains no publishable contract outputs")
    return values


def _build_envelope(args: argparse.Namespace, outputs: dict[str, Any]) -> dict[str, Any]:
    scope = args.scope or ("global" if args.region == "global" else "regional")
    contract_id = args.output_schema_version or f"{args.layer}/v1"
    producer = args.producer or f"roots/{args.layer}"
    expected_state_key = (
        f"{args.deployment_id}/{args.layer}/terraform.tfstate"
        if scope == "global"
        else f"{args.deployment_id}/{args.region}/{args.layer}/terraform.tfstate"
    )
    if args.state_key != expected_state_key:
        raise PublicationError("state_key is not owned by the declared producer layer")
    customer_id = getattr(args, "customer_id", None)
    envelope: dict[str, Any] = {
        "schema_version": "2" if customer_id is not None else "1",
        "deployment_id": args.deployment_id,
        "aws_account_id": args.account_id,
        "region": args.region,
        "scope": scope,
        "layer": args.layer,
        "producer": producer,
        "release_digest": args.release_digest,
        "output_schema_version": contract_id,
        "outputs": outputs,
        "contract_digest": compute_digest(canonicalize(outputs)),
        "produced_at": args.produced_at,
        "terraform_workspace": args.terraform_workspace,
        "state_key": args.state_key,
    }
    if customer_id is not None:
        if args.release_version is None:
            raise PublicationError("release_version is required for the v2 contract path")
        envelope["customer_id"] = customer_id
        envelope["release_version"] = args.release_version
    if args.module_source_digest is not None:
        envelope["module_source_digest"] = args.module_source_digest
    return envelope


def _reserve_exclusive(path: Path) -> tuple[Path, int]:
    output_path = path.expanduser().resolve(strict=False)
    if _is_within(output_path, REPO_ROOT.resolve()):
        raise PublicationError("envelope output must be outside the repository")
    if output_path.suffix != ".json":
        raise PublicationError("envelope output must use a .json suffix")
    if not output_path.parent.is_dir():
        raise PublicationError("envelope output directory does not exist")

    try:
        descriptor = os.open(
            output_path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o600,
        )
    except OSError as exc:
        raise PublicationError("unable to create exclusive envelope output") from exc
    return output_path, descriptor


def _write_reserved(
    output_path: Path,
    descriptor: int,
    document: dict[str, Any],
) -> None:
    open_descriptor: int | None = descriptor
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            open_descriptor = None
            json.dump(document, handle, sort_keys=True, indent=2, ensure_ascii=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(output_path, stat.S_IRUSR | stat.S_IWUSR)
    except (OSError, TypeError, ValueError) as exc:
        output_path.unlink(missing_ok=True)
        raise PublicationError("unable to create exclusive envelope output") from exc
    finally:
        if open_descriptor is not None:
            os.close(open_descriptor)


def _write_exclusive(path: Path, document: dict[str, Any]) -> None:
    output_path, descriptor = _reserve_exclusive(path)
    _write_reserved(output_path, descriptor, document)


def _parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--from-terraform-output-json", type=Path, required=True)
    parser.add_argument("--layer", required=True)
    parser.add_argument(
        "--customer-id",
        help="canonical cust_<ULID>; required by the v2 live contract path",
    )
    parser.add_argument("--deployment-id", required=True)
    parser.add_argument("--account-id", required=True)
    parser.add_argument("--region", required=True)
    parser.add_argument(
        "--aws-region",
        help="explicit AWS API region; required for live SSM I/O",
    )
    credentials = parser.add_mutually_exclusive_group()
    credentials.add_argument(
        "--aws-profile",
        help="explicit named AWS profile for live I/O",
    )
    credentials.add_argument(
        "--use-runtime-credentials",
        action="store_true",
        help="use an already established short-lived runtime credential chain",
    )
    parser.add_argument(
        "--aws-cli",
        default="aws",
        help="AWS CLI executable (injectable for hermetic validation)",
    )
    parser.add_argument("--scope", choices=("global", "regional"))
    parser.add_argument("--release-digest", required=True)
    parser.add_argument(
        "--release-version",
        help="immutable release version; required by the v2 contract path",
    )
    parser.add_argument(
        "--produced-at",
        required=True,
        help="explicit RFC 3339 production timestamp from the orchestrator",
    )
    parser.add_argument("--output-schema-version")
    parser.add_argument("--producer")
    parser.add_argument("--terraform-workspace", choices=("default",), default="default")
    parser.add_argument("--state-key", required=True)
    parser.add_argument("--module-source-digest")
    parser.add_argument(
        "--schema",
        type=Path,
        help="explicit envelope schema; defaults to v2 with --customer-id, otherwise v1",
    )
    parser.add_argument(
        "--catalog",
        type=Path,
        default=DEFAULT_CATALOG,
        help="canonical contract catalog",
    )
    parser.add_argument(
        "--catalog-schema",
        type=Path,
        default=DEFAULT_CATALOG_SCHEMA,
        help="canonical contract catalog schema",
    )
    parser.add_argument("--out", type=Path, required=True)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--dry-run", action="store_true", help="explicit dry-run (also the default)")
    mode.add_argument("--live", action="store_true", help="create the immutable SSM contract")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv or sys.argv[1:])
    reserved_output: Path | None = None
    reserved_descriptor: int | None = None

    if args.live:
        if os.environ.get("SCANALYZE_ALLOW_LIVE") != "1":
            print("BLOCKED_LIVE: set SCANALYZE_ALLOW_LIVE=1 to acknowledge live mode", file=sys.stderr)
            return 2

    try:
        _validate_produced_at(args.produced_at)
        if args.live:
            produced_at = datetime.fromisoformat(
                args.produced_at.replace("Z", "+00:00")
            ).astimezone(timezone.utc)
            if abs(
                (datetime.now(timezone.utc) - produced_at).total_seconds()
            ) > MAX_LIVE_CLOCK_SKEW_SECONDS:
                raise PublicationError(
                    "produced_at is outside the live action-time window"
                )
        schema_path = args.schema or (
            DEFAULT_SCHEMA_V2 if args.customer_id is not None else DEFAULT_SCHEMA_V1
        )
        if args.live and (
            args.customer_id is None
            or schema_path.resolve() != DEFAULT_SCHEMA_V2.resolve()
            or args.catalog.resolve() != DEFAULT_CATALOG.resolve()
            or args.catalog_schema.resolve() != DEFAULT_CATALOG_SCHEMA.resolve()
        ):
            raise PublicationError(
                "live publication requires canonical repository contracts"
            )
        schema = _load_json(schema_path, "contract schema")
        if not isinstance(schema, dict):
            raise PublicationError("contract schema must be a JSON object")

        contract_id = args.output_schema_version or f"{args.layer}/v1"
        terraform_document = _load_json(args.from_terraform_output_json, "Terraform output")
        outputs = _extract_outputs(terraform_document, args.layer, contract_id)

        output_schema = _load_json(_layer_output_schema_path(contract_id), "output schema")
        if not isinstance(output_schema, dict):
            raise PublicationError("output schema must be a JSON object")
        _validate_schema(outputs, output_schema, "contract outputs")

        envelope = _build_envelope(args, outputs)
        _validate_schema(envelope, schema, "contract envelope")
        if args.live:
            if not args.aws_region:
                raise PublicationError("--aws-region is required for live publication")
            catalog = _load_json(args.catalog, "contract catalog")
            catalog_schema = _load_json(args.catalog_schema, "contract catalog schema")
            if not isinstance(catalog, dict) or not isinstance(catalog_schema, dict):
                raise PublicationError("contract catalog must be a JSON object")
            _validate_schema(catalog, catalog_schema, "contract catalog")
            record = catalog.get("contracts", {}).get(contract_id)
            declared_output_schema = (
                record.get("output_schema") if isinstance(record, dict) else None
            )
            if (
                not isinstance(declared_output_schema, str)
                or (REPO_ROOT / declared_output_schema).resolve()
                != _layer_output_schema_path(contract_id).resolve()
            ):
                raise PublicationError("catalog output schema binding is invalid")
            reserved_output, reserved_descriptor = _reserve_exclusive(args.out)
            runner = SubprocessAwsCliRunner(
                executable=args.aws_cli,
                profile=args.aws_profile,
                use_runtime_credentials=args.use_runtime_credentials,
            )
            identity = verify_caller_identity(
                runner,
                expected_account_id=args.account_id,
                region=args.aws_region,
            )
            publish_immutable_ssm_contract(
                runner,
                identity=identity,
                catalog=catalog,
                envelope=envelope,
            )
            if reserved_output is None or reserved_descriptor is None:
                raise PublicationError("exclusive envelope output was not reserved")
            descriptor = reserved_descriptor
            reserved_descriptor = None
            _write_reserved(reserved_output, descriptor, envelope)
        else:
            _write_exclusive(args.out, envelope)
    except (PublicationError, LiveContractIoError) as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1
    except (OSError, TypeError, ValueError):
        print("FAIL: unable to build contract envelope safely", file=sys.stderr)
        return 1
    finally:
        if reserved_descriptor is not None:
            os.close(reserved_descriptor)
            if reserved_output is not None:
                reserved_output.unlink(missing_ok=True)

    if args.live:
        print(f"PASS: published immutable contract for {args.layer}")
        print("AWS_WRITE=ssm:PutParameter(create-only)")
    else:
        print(f"DRY_RUN: validated contract envelope for {args.layer}")
        print("AWS_WRITE=disabled")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
