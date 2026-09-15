"""Conditional registry I/O with independently pinned operation inputs.

This module does not authenticate an operation pin, create an AWS client, or
install an authority. The embedding control plane must supply those boundaries.
No request-derived digest is accepted as a replacement for the external pin.
"""
from __future__ import annotations

import copy
import re
from datetime import datetime, timezone
from typing import Any, Callable, Mapping, Protocol

import jsonschema

from tooling.authorize_deployment_backend import (
    AuthorizationError,
    canonical_digest,
    load_json_strict,
)
from tooling.deployment_registry import (
    REPO_ROOT,
    _validate as validate_registry_record,
    prepare_registry_create,
    prepare_registry_update,
)
from tooling.verify_account_ready import verify_account_ready


Clock = Callable[[], datetime]
DIGEST = re.compile(r"sha256:[a-f0-9]{64}")
TABLE_ARN = re.compile(
    r"arn:(?P<partition>aws|aws-us-gov|aws-cn):dynamodb:"
    r"(?P<region>[a-z]{2}(?:-[a-z]+)+-[0-9]+):"
    r"(?P<account>(?!000000000000)[0-9]{12}):table/scanalyze-deployment-registry"
)
OPERATION_FIELDS = frozenset({
    "schema_version", "operation", "authority_account_id", "authority_region",
    "registry_table_arn", "valid_from", "expires_at", "expected_anchor",
    "previous_anchor", "account_ready_anchor",
})
TUPLE_FIELDS = ("customer_id", "deployment_id", "account_id", "region", "environment")


class RegistryClient(Protocol):
    """Authenticated, retry-disabled low-level DynamoDB client, supplied externally."""

    meta: Any

    def get_item(self, **kwargs: Any) -> dict[str, Any]: ...

    def put_item(self, **kwargs: Any) -> dict[str, Any]: ...


class RegistryConflict(AuthorizationError):
    """The conditional write was rejected; no successful receipt may be emitted."""


class RegistryOutcomeUncertain(AuthorizationError):
    """A write may have occurred. Reconcile independently; never retry blindly."""


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _snapshot(document: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(document, dict):
        raise AuthorizationError("registry input must be a JSON object")
    result = copy.deepcopy(document)
    # Constrain the supported JSON types before they reach the SDK. In particular
    # reject floats/bools for integer fields and arbitrary Python objects.
    _encode(result)
    return result


def _encode(value: Any) -> dict[str, Any]:
    if type(value) is str:
        return {"S": value}
    if type(value) is int:
        return {"N": str(value)}
    if type(value) is bool:
        return {"BOOL": value}
    if value is None:
        return {"NULL": True}
    if type(value) is dict and all(type(key) is str for key in value):
        return {"M": {key: _encode(item) for key, item in value.items()}}
    raise AuthorizationError("registry input contains unsupported value types")


def _decode(value: Any) -> Any:
    if type(value) is not dict or len(value) != 1:
        raise AuthorizationError("registry readback contains malformed attributes")
    kind, body = next(iter(value.items()))
    if kind == "S" and type(body) is str:
        return body
    if kind == "N" and type(body) is str and re.fullmatch(r"0|[1-9][0-9]{0,37}", body):
        return int(body)
    if kind == "M" and type(body) is dict and all(type(key) is str for key in body):
        return {key: _decode(item) for key, item in body.items()}
    # Registry target v1/v2 contain only strings, integers and maps.
    raise AuthorizationError("registry readback contains unsupported attributes")


def _validate_anchor(anchor: Any) -> None:
    schema = load_json_strict(REPO_ROOT / "schemas/deployment-target-anchor.v1.schema.json")
    if list(jsonschema.Draft202012Validator(schema).iter_errors(anchor)):
        raise AuthorizationError("registry operation anchor is invalid")


def _check_time(operation: dict[str, Any], clock: Clock) -> None:
    try:
        start = datetime.strptime(operation["valid_from"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
        end = datetime.strptime(operation["expires_at"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
        now = clock()
        if (
            start.strftime("%Y-%m-%dT%H:%M:%SZ") != operation["valid_from"]
            or end.strftime("%Y-%m-%dT%H:%M:%SZ") != operation["expires_at"]
            or not isinstance(now, datetime)
            or now.tzinfo is None
            or now.utcoffset() is None
            or not start <= now < end
        ):
            raise ValueError
    except (KeyError, TypeError, ValueError):
        raise AuthorizationError("registry operation is outside its approved validity interval") from None


def _admit(
    *, client: RegistryClient, authority: Mapping[str, Any],
    expected_authority_digest: str, account_ready: Mapping[str, Any],
    operation_name: str, clock: Clock,
) -> tuple[dict[str, Any], dict[str, Any]]:
    operation = _snapshot(authority)
    baseline = _snapshot(account_ready)
    if (
        set(operation) != OPERATION_FIELDS
        or operation["schema_version"] != "deployment-registry-operation.v1"
        or operation["operation"] != operation_name
        or not isinstance(expected_authority_digest, str)
        or DIGEST.fullmatch(expected_authority_digest) is None
        or canonical_digest(operation) != expected_authority_digest
    ):
        raise AuthorizationError("registry operation does not match independent authority pin")
    table = operation["registry_table_arn"]
    match = TABLE_ARN.fullmatch(table) if isinstance(table, str) else None
    if (
        match is None
        or match["account"] != operation["authority_account_id"]
        or match["region"] != operation["authority_region"]
    ):
        raise AuthorizationError("registry authority table binding is invalid")
    region = operation["authority_region"]
    partition = "aws-cn" if region.startswith("cn-") else "aws-us-gov" if region.startswith("us-gov-") else "aws"
    if match["partition"] != partition:
        raise AuthorizationError("registry authority partition does not match region")
    _validate_anchor(operation["expected_anchor"])
    if operation_name == "update":
        _validate_anchor(operation["previous_anchor"])
        if (
            operation["previous_anchor"]["deployment_id"] != operation["expected_anchor"]["deployment_id"]
            or operation["previous_anchor"]["registry_version"] + 1 != operation["expected_anchor"]["registry_version"]
        ):
            raise AuthorizationError("registry operation CAS anchors are inconsistent")
    elif operation["previous_anchor"] is not None:
        raise AuthorizationError("registry operation has unexpected previous anchor")
    result = verify_account_ready(
        baseline, operation["account_ready_anchor"],
        load_json_strict(REPO_ROOT / "schemas/account-ready.v2.schema.json"),
    )
    if not result.passed:
        raise AuthorizationError("registry ACCOUNT_READY verification failed")
    if (
        baseline["account_id"] == operation["authority_account_id"]
        or baseline["deployment_id"] != operation["expected_anchor"]["deployment_id"]
    ):
        raise AuthorizationError("registry authority and destination bindings are invalid")
    # No client creation or discovery occurs here. Reject SDK retry/default/custom
    # endpoint configurations that would violate this single-effect API.
    suffix = "amazonaws.com.cn" if partition == "aws-cn" else "amazonaws.com"
    try:
        valid_client = (
            client.meta.region_name == region
            and client.meta.endpoint_url == f"https://dynamodb.{region}.{suffix}"
            and client.meta.service_model.service_name == "dynamodb"
            and type(client.meta.config.retries.get("total_max_attempts")) is int
            and client.meta.config.retries["total_max_attempts"] == 1
        )
    except (AttributeError, KeyError, TypeError):
        valid_client = False
    if not valid_client:
        raise AuthorizationError("registry client must be exact-region and retry-disabled")
    _check_time(operation, clock)
    return operation, baseline


def _bind_record(record: dict[str, Any], anchor: dict[str, Any], baseline: dict[str, Any]) -> None:
    validate_registry_record(record)
    actual_anchor = {"schema_version": "1", **{key: record[key] for key in ("deployment_id", "registry_version", "record_digest")}}
    if actual_anchor != anchor:
        raise AuthorizationError("registry record does not match approved anchor")
    if any(record[field] != baseline[field] for field in TUPLE_FIELDS):
        raise AuthorizationError("registry record tuple does not match ACCOUNT_READY")
    if record["account_ready"] != {
        "schema_version": "2", "baseline_version": baseline["baseline_version"],
        "contract_digest": baseline["contract_digest"],
    } or record["state_binding"] != {
        key: baseline["state_infrastructure"][key] for key in ("state_bucket", "state_kms_key")
    }:
        raise AuthorizationError("registry record does not preserve ACCOUNT_READY state binding")


def _response(response: Any) -> dict[str, Any]:
    if (
        type(response) is not dict
        or type(response.get("ResponseMetadata")) is not dict
        or type(response["ResponseMetadata"].get("HTTPStatusCode")) is not int
        or type(response["ResponseMetadata"].get("RetryAttempts")) is not int
        or response["ResponseMetadata"].get("HTTPStatusCode") != 200
        or response["ResponseMetadata"].get("RetryAttempts") != 0
    ):
        raise AuthorizationError("registry I/O response is not an unambiguous single-attempt success")
    return response


def _read(client: RegistryClient, operation: dict[str, Any], anchor: dict[str, Any], baseline: dict[str, Any]) -> dict[str, Any]:
    try:
        response = _response(client.get_item(
            TableName=operation["registry_table_arn"],
            Key={"deployment_id": {"S": anchor["deployment_id"]}},
            ConsistentRead=True,
        ))
    except Exception:
        raise AuthorizationError("registry consistent read failed; no anchor issued") from None
    record = _decode({"M": response.get("Item")})
    _bind_record(record, anchor, baseline)
    return record


def retrieve_registry_anchor(
    *, client: RegistryClient, authority: Mapping[str, Any],
    expected_authority_digest: str, account_ready: Mapping[str, Any],
    clock: Clock = _utc_now,
) -> dict[str, Any]:
    """Read only the independently approved exact version/digest, never latest."""
    operation, baseline = _admit(
        client=client, authority=authority, expected_authority_digest=expected_authority_digest,
        account_ready=account_ready, operation_name="read", clock=clock,
    )
    record = _read(client, operation, operation["expected_anchor"], baseline)
    _check_time(operation, clock)
    return {"schema_version": "1", **{key: record[key] for key in ("deployment_id", "registry_version", "record_digest")}}


def _publish(
    *, client: RegistryClient, authority: Mapping[str, Any],
    expected_authority_digest: str, record: Mapping[str, Any],
    account_ready: Mapping[str, Any], operation_name: str, clock: Clock,
) -> dict[str, Any]:
    proposed = _snapshot(record)
    operation, baseline = _admit(
        client=client, authority=authority, expected_authority_digest=expected_authority_digest,
        account_ready=account_ready, operation_name=operation_name, clock=clock,
    )
    _bind_record(proposed, operation["expected_anchor"], baseline)
    current = None
    if operation_name == "create":
        condition = prepare_registry_create(proposed)
    else:
        current = _read(client, operation, operation["previous_anchor"], baseline)
        condition = prepare_registry_update(
            current=current, proposed=proposed,
            expected_version=operation["previous_anchor"]["registry_version"],
            expected_digest=operation["previous_anchor"]["record_digest"],
        )
    request = {
        "TableName": operation["registry_table_arn"], "Item": _encode(proposed)["M"],
        "ConditionExpression": condition["condition_expression"],
        "ReturnValues": "ALL_OLD", "ReturnValuesOnConditionCheckFailure": "NONE",
    }
    if condition["expression_attribute_names"]:
        request["ExpressionAttributeNames"] = condition["expression_attribute_names"]
    if condition["expression_attribute_values"]:
        request["ExpressionAttributeValues"] = {
            key: _encode(value) for key, value in condition["expression_attribute_values"].items()
        }
    _check_time(operation, clock)
    try:
        # Detached request: a client callback cannot mutate the private snapshots.
        response = client.put_item(**copy.deepcopy(request))
    except Exception as exc:
        error = getattr(exc, "response", {})
        metadata = error.get("ResponseMetadata", {}) if isinstance(error, dict) else {}
        if (
            isinstance(error, dict) and isinstance(error.get("Error"), dict)
            and error["Error"].get("Code") == "ConditionalCheckFailedException"
            and isinstance(metadata, dict)
            and type(metadata.get("HTTPStatusCode")) is int
            and metadata["HTTPStatusCode"] == 400
            and type(metadata.get("RetryAttempts")) is int
            and metadata["RetryAttempts"] == 0
        ):
            raise RegistryConflict("registry conditional write conflict; no anchor issued") from None
        raise RegistryOutcomeUncertain("registry write outcome uncertain; reconcile without retry") from None
    try:
        response = _response(response)
        old = _decode({"M": response["Attributes"]}) if "Attributes" in response else None
        if old != current:
            raise AuthorizationError("registry write returned a substituted previous record")
        readback = _read(client, operation, operation["expected_anchor"], baseline)
        if readback != proposed:
            raise AuthorizationError("registry write readback differs from approved record")
        _check_time(operation, clock)
    except Exception:
        raise RegistryOutcomeUncertain("registry write readback not confirmed; reconcile without retry") from None
    return {"schema_version": "1", **{key: readback[key] for key in ("deployment_id", "registry_version", "record_digest")}}


def publish_registry_create(
    *, client: RegistryClient, authority: Mapping[str, Any], expected_authority_digest: str,
    record: Mapping[str, Any], account_ready: Mapping[str, Any], clock: Clock = _utc_now,
) -> dict[str, Any]:
    """Execute exactly one approved create-only write and confirm its anchor."""
    return _publish(client=client, authority=authority, expected_authority_digest=expected_authority_digest,
                    record=record, account_ready=account_ready, operation_name="create", clock=clock)


def publish_registry_update(
    *, client: RegistryClient, authority: Mapping[str, Any], expected_authority_digest: str,
    record: Mapping[str, Any], account_ready: Mapping[str, Any], clock: Clock = _utc_now,
) -> dict[str, Any]:
    """Read the pinned predecessor, execute one CAS and confirm the exact result."""
    return _publish(client=client, authority=authority, expected_authority_digest=expected_authority_digest,
                    record=record, account_ready=account_ready, operation_name="update", clock=clock)
