"""Build catalog-bound layer-contract envelopes from Terraform outputs.

This module is the in-process equivalent of the local envelope construction in
``scripts/deployment/publish-contract.py``.  It deliberately owns no transport:
callers must pass the validated envelope to the existing immutable SSM adapter.
The canonical repository catalog is the sole source for contract identity,
producer, scope, and output-schema selection.
"""
from __future__ import annotations

import json
import math
import re
from pathlib import Path
from typing import Any

from tooling.validate_digest import canonicalize, compute_digest


class LiveContractEnvelopeError(ValueError):
    """A sanitized layer-contract envelope construction failure."""


REPO_ROOT = Path(__file__).resolve().parent.parent
CATALOG_PATH = REPO_ROOT / "deployment" / "contract-catalog.v1.json"
CATALOG_SCHEMA_PATH = REPO_ROOT / "schemas" / "contract-catalog.v1.schema.json"
ENVELOPE_SCHEMA_PATH = REPO_ROOT / "schemas" / "layer-contract.v2.schema.json"
SCHEMAS_ROOT = (REPO_ROOT / "schemas").resolve()

AWS_REGION_PATTERN = re.compile(r"^[a-z]{2}(?:-gov)?-[a-z]+-[0-9]+$")


def _load_repository_json(path: Path, description: str) -> dict[str, Any]:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise LiveContractEnvelopeError(
            f"canonical {description} is unavailable or invalid"
        ) from exc
    if not isinstance(document, dict):
        raise LiveContractEnvelopeError(
            f"canonical {description} must be a JSON object"
        )
    return document


def _validate_schema(
    instance: Any,
    schema: dict[str, Any],
    description: str,
) -> None:
    try:
        import jsonschema
    except ImportError as exc:
        raise LiveContractEnvelopeError(
            "BLOCKED_TOOLING: jsonschema is not installed"
        ) from exc

    validator = jsonschema.Draft202012Validator(
        schema,
        format_checker=jsonschema.FormatChecker(),
    )
    error = next(iter(validator.iter_errors(instance)), None)
    if error is not None:
        # jsonschema messages and instance paths may echo output names or values.
        raise LiveContractEnvelopeError(
            f"{description} schema validation failed "
            f"(validator={error.validator})"
        )


def _clone_json_value(value: Any) -> Any:
    """Copy a JSON value while rejecting coercion and non-finite numbers."""
    if value is None or type(value) in {str, bool, int}:
        return value
    if type(value) is float:
        if not math.isfinite(value):
            raise LiveContractEnvelopeError(
                "Terraform output document contains a non-finite number"
            )
        return value
    if isinstance(value, list):
        return [_clone_json_value(item) for item in value]
    if isinstance(value, dict):
        if any(not isinstance(key, str) for key in value):
            raise LiveContractEnvelopeError(
                "Terraform output document contains a non-string object key"
            )
        return {key: _clone_json_value(item) for key, item in value.items()}
    raise LiveContractEnvelopeError(
        "Terraform output document contains a non-JSON value"
    )


def sanitized_normalize_terraform_outputs(
    terraform_outputs: Any,
    *,
    layer: str,
    contract_id: str,
) -> dict[str, Any]:
    """Extract the sole publishable output boundary without echoing values.

    The behavior intentionally matches ``publish-contract.py``: every root
    entry must carry explicit Terraform ``sensitive`` metadata, any sensitive
    entry rejects the complete document, and ``contract_payload.outputs`` (when
    present) replaces all sibling root outputs as the exclusive contract body.
    """
    if not isinstance(terraform_outputs, dict):
        raise LiveContractEnvelopeError(
            "Terraform output document must be a JSON object"
        )

    values: dict[str, Any] = {}
    contract_payload: dict[str, Any] | None = None
    for name, metadata in terraform_outputs.items():
        if not isinstance(name, str) or not isinstance(metadata, dict):
            raise LiveContractEnvelopeError(
                "Terraform output document has an invalid entry"
            )
        if "value" not in metadata or not isinstance(metadata.get("sensitive"), bool):
            raise LiveContractEnvelopeError(
                "Terraform output entry is missing value or sensitive metadata"
            )
        if metadata["sensitive"]:
            raise LiveContractEnvelopeError(
                "Terraform output contains a sensitive value and cannot be published"
            )
        if name == "contract_payload":
            if not isinstance(metadata["value"], dict):
                raise LiveContractEnvelopeError("contract_payload must be an object")
            contract_payload = metadata["value"]
        else:
            values[name] = _clone_json_value(metadata["value"])

    if contract_payload is not None:
        declared_layer = contract_payload.get("layer")
        if declared_layer is not None and declared_layer != layer:
            raise LiveContractEnvelopeError(
                "contract_payload layer does not match the catalog producer"
            )
        declared_version = contract_payload.get("schema_version")
        expected_version = contract_id.rsplit("/", 1)[-1].removeprefix("v")
        if declared_version is not None and str(declared_version) != expected_version:
            raise LiveContractEnvelopeError(
                "contract_payload schema version does not match the catalog contract"
            )
        nested_outputs = contract_payload.get("outputs")
        if nested_outputs is not None:
            if not isinstance(nested_outputs, dict):
                raise LiveContractEnvelopeError(
                    "contract_payload.outputs must be an object"
                )
            values = _clone_json_value(nested_outputs)

    if not values:
        raise LiveContractEnvelopeError(
            "Terraform output document contains no publishable contract outputs"
        )
    return values


def _catalog_contract_for_layer(
    catalog: dict[str, Any],
    layer: str,
) -> tuple[str, dict[str, Any]]:
    contracts = catalog.get("contracts")
    if not isinstance(contracts, dict):
        raise LiveContractEnvelopeError("canonical contract catalog is invalid")
    matches = [
        (contract_id, record)
        for contract_id, record in contracts.items()
        if isinstance(contract_id, str)
        and isinstance(record, dict)
        and record.get("authority") == "terraform-root"
        and record.get("producer") == layer
    ]
    if len(matches) != 1:
        raise LiveContractEnvelopeError(
            "catalog must declare exactly one Terraform-root contract for the layer"
        )
    return matches[0]


def _catalog_output_schema(record: dict[str, Any]) -> dict[str, Any]:
    declared_path = record.get("output_schema")
    if not isinstance(declared_path, str):
        raise LiveContractEnvelopeError("catalog output schema binding is invalid")
    schema_path = (REPO_ROOT / declared_path).resolve()
    try:
        schema_path.relative_to(SCHEMAS_ROOT)
    except ValueError as exc:
        raise LiveContractEnvelopeError(
            "catalog output schema binding is invalid"
        ) from exc
    if not schema_path.is_file():
        raise LiveContractEnvelopeError("catalog output schema binding is unavailable")
    return _load_repository_json(schema_path, "catalog output schema")


def build_validated_layer_contract_envelope(
    *,
    terraform_outputs: Any,
    layer: str,
    customer_id: str,
    deployment_id: str,
    account_id: str,
    aws_region: str,
    release_version: str,
    release_digest: str,
    produced_at: str,
    state_key: str,
    module_source_digest: str,
) -> dict[str, Any]:
    """Return a canonical, schema-validated v2 layer-contract envelope.

    ``aws_region`` binds a regional contract and supplies the AWS API identity
    region for a global contract.  Catalog-global contracts always emit
    ``region=global`` and never serialize the operational AWS region.
    """
    if not isinstance(layer, str) or not layer:
        raise LiveContractEnvelopeError("layer is invalid")
    if not isinstance(aws_region, str) or not AWS_REGION_PATTERN.fullmatch(aws_region):
        raise LiveContractEnvelopeError("AWS region is invalid")

    catalog = _load_repository_json(CATALOG_PATH, "contract catalog")
    catalog_schema = _load_repository_json(
        CATALOG_SCHEMA_PATH,
        "contract catalog schema",
    )
    _validate_schema(catalog, catalog_schema, "contract catalog")
    contract_id, record = _catalog_contract_for_layer(catalog, layer)

    scope = record.get("scope")
    if scope not in {"global", "regional"}:
        raise LiveContractEnvelopeError(
            "catalog Terraform-root contract scope is invalid"
        )
    region = "global" if scope == "global" else aws_region
    expected_state_key = (
        f"{deployment_id}/{layer}/terraform.tfstate"
        if scope == "global"
        else f"{deployment_id}/{aws_region}/{layer}/terraform.tfstate"
    )
    if state_key != expected_state_key:
        raise LiveContractEnvelopeError(
            "state_key is not owned by the catalog producer layer"
        )

    outputs = sanitized_normalize_terraform_outputs(
        terraform_outputs,
        layer=layer,
        contract_id=contract_id,
    )
    output_schema = _catalog_output_schema(record)
    _validate_schema(outputs, output_schema, "contract outputs")

    try:
        contract_digest = compute_digest(canonicalize(outputs))
    except (TypeError, ValueError) as exc:
        raise LiveContractEnvelopeError(
            "contract outputs cannot be canonicalized"
        ) from exc

    envelope: dict[str, Any] = {
        "schema_version": "2",
        "customer_id": customer_id,
        "deployment_id": deployment_id,
        "aws_account_id": account_id,
        "region": region,
        "scope": scope,
        "layer": layer,
        "producer": f"roots/{layer}",
        "release_version": release_version,
        "release_digest": release_digest,
        "output_schema_version": contract_id,
        "outputs": outputs,
        "contract_digest": contract_digest,
        "produced_at": produced_at,
        "terraform_workspace": "default",
        "state_key": state_key,
        "module_source_digest": module_source_digest,
    }
    envelope_schema = _load_repository_json(
        ENVELOPE_SCHEMA_PATH,
        "layer contract envelope schema",
    )
    _validate_schema(envelope, envelope_schema, "contract envelope")
    return envelope


__all__ = [
    "LiveContractEnvelopeError",
    "build_validated_layer_contract_envelope",
    "sanitized_normalize_terraform_outputs",
]
