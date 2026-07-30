"""Sanitized direct-provider readback for the 23 GUG-221 Phase B resources.

The CloudFormation execution receipt proves that one reviewed operation
reached terminal state.  It does not prove that the resources still expose the
same effective provider configuration.  This module closes that gap without
using CloudFormation or any mutating API:

* callers provide the private physical identifiers captured during Phase B;
* every identifier is bound to the receipt-safe SHA-256 value before use;
* IAM, Lambda, DynamoDB, KMS, and Logs are read directly;
* every list operation is bounded, duplicate rejecting, and token strict;
* two consecutive sanitized snapshots must be byte-for-byte identical; and
* the returned artifact contains logical identifiers and digests only.

``lambda:GetFunction`` is intentionally not used because it can return a
download location for the deployed artifact.  Expected-resource absence is
accepted only when the provider error code is exactly
``ResourceNotFoundException``; every other provider failure blocks evidence.
"""

from __future__ import annotations

from datetime import UTC, date, datetime
from hashlib import sha256
import json
import math
import re
from typing import Any, Callable, Mapping, Sequence
from urllib.parse import unquote

import yaml


ARTIFACT_TYPE = "scanalyze.platform_authority.lambda_audit_repair_effective_state.v1"
PHASE_B_EXECUTION_ARTIFACT_TYPE = (
    "scanalyze.platform_authority.lambda_audit_repair_pep_execution_receipt.v1"
)
WORK_PACKAGE = "GUG-221"
PHASE = "B_DIRECT_PROVIDER_EFFECTIVE_STATE"
AUTHORITY_ACCOUNT_ID = "042360977644"
MANAGEMENT_ACCOUNT_ID = "839393571433"
REGION = "us-east-1"
PRODUCTION_STATUS = "NO-GO"
MAX_PAGES = 100

PLAN_FUNCTION_NAME = "scanalyze-authority-lambda-audit-plan"
REPAIR_FUNCTION_NAME = "scanalyze-authority-lambda-audit-repair"
RECONCILE_FUNCTION_NAME = "scanalyze-authority-lambda-audit-reconcile"
PLAN_ALIAS_NAME = "plan-v1"
REPAIR_ALIAS_NAME = "repair-v1"
RECONCILE_ALIAS_NAME = "reconcile-v1"
PLAN_ROLE_NAME = "ScanalyzeLambdaAuditRepairPlan"
REPAIR_ROLE_NAME = "ScanalyzeLambdaAuditRepairExecution"
RECONCILE_ROLE_NAME = "ScanalyzeLambdaAuditRepairReconcile"
INSPECTOR_ROLE_NAME = "ScanalyzeLambdaAuditRepairAuthorityInspector"
TABLE_NAME = "scanalyze-platform-authority-gug221-repair-ledger"
KMS_ALIAS_NAME = "alias/scanalyze/platform-authority/gug221-repair-ledger"
PLAN_LOG_GROUP_NAME = f"/aws/lambda/{PLAN_FUNCTION_NAME}"
REPAIR_LOG_GROUP_NAME = f"/aws/lambda/{REPAIR_FUNCTION_NAME}"
RECONCILE_LOG_GROUP_NAME = f"/aws/lambda/{RECONCILE_FUNCTION_NAME}"

EXPECTED_RESOURCE_TYPES: dict[str, str] = {
    "InvocationAuthorityInspectorRole": "AWS::IAM::Role",
    "PlanAlias": "AWS::Lambda::Alias",
    "PlanEventInvokeConfig": "AWS::Lambda::EventInvokeConfig",
    "PlanExecutionRole": "AWS::IAM::Role",
    "PlanFunction": "AWS::Lambda::Function",
    "PlanFunctionVersion": "AWS::Lambda::Version",
    "PlanLogGroup": "AWS::Logs::LogGroup",
    "ReconcileAlias": "AWS::Lambda::Alias",
    "ReconcileEventInvokeConfig": "AWS::Lambda::EventInvokeConfig",
    "ReconcileExecutionRole": "AWS::IAM::Role",
    "ReconcileFunction": "AWS::Lambda::Function",
    "ReconcileFunctionVersion": "AWS::Lambda::Version",
    "ReconcileLogGroup": "AWS::Logs::LogGroup",
    "RepairAlias": "AWS::Lambda::Alias",
    "RepairCodeSigningConfig": "AWS::Lambda::CodeSigningConfig",
    "RepairEventInvokeConfig": "AWS::Lambda::EventInvokeConfig",
    "RepairExecutionRole": "AWS::IAM::Role",
    "RepairFunction": "AWS::Lambda::Function",
    "RepairFunctionVersion": "AWS::Lambda::Version",
    "RepairLedger": "AWS::DynamoDB::Table",
    "RepairLedgerKey": "AWS::KMS::Key",
    "RepairLedgerKeyAlias": "AWS::KMS::Alias",
    "RepairLogGroup": "AWS::Logs::LogGroup",
}
RESOURCE_LOGICAL_IDS = tuple(sorted(EXPECTED_RESOURCE_TYPES))

ROLE_NAMES = {
    "InvocationAuthorityInspectorRole": INSPECTOR_ROLE_NAME,
    "PlanExecutionRole": PLAN_ROLE_NAME,
    "ReconcileExecutionRole": RECONCILE_ROLE_NAME,
    "RepairExecutionRole": REPAIR_ROLE_NAME,
}
FUNCTION_NAMES = {
    "PlanFunction": PLAN_FUNCTION_NAME,
    "ReconcileFunction": RECONCILE_FUNCTION_NAME,
    "RepairFunction": REPAIR_FUNCTION_NAME,
}
VERSION_FUNCTIONS = {
    "PlanFunctionVersion": PLAN_FUNCTION_NAME,
    "ReconcileFunctionVersion": RECONCILE_FUNCTION_NAME,
    "RepairFunctionVersion": REPAIR_FUNCTION_NAME,
}
ALIAS_BINDINGS = {
    "PlanAlias": (PLAN_FUNCTION_NAME, PLAN_ALIAS_NAME),
    "ReconcileAlias": (RECONCILE_FUNCTION_NAME, RECONCILE_ALIAS_NAME),
    "RepairAlias": (REPAIR_FUNCTION_NAME, REPAIR_ALIAS_NAME),
}
EVENT_INVOKE_BINDINGS = {
    "PlanEventInvokeConfig": (PLAN_FUNCTION_NAME, PLAN_ALIAS_NAME),
    "ReconcileEventInvokeConfig": (
        RECONCILE_FUNCTION_NAME,
        RECONCILE_ALIAS_NAME,
    ),
    "RepairEventInvokeConfig": (REPAIR_FUNCTION_NAME, REPAIR_ALIAS_NAME),
}
LOG_GROUP_NAMES = {
    "PlanLogGroup": PLAN_LOG_GROUP_NAME,
    "ReconcileLogGroup": RECONCILE_LOG_GROUP_NAME,
    "RepairLogGroup": REPAIR_LOG_GROUP_NAME,
}
TEMPLATE_PARAMETER_KEYS = (
    "AuthorityAccountId",
    "ManagementAccountId",
    "SourceCommit",
    "RepairId",
    "PrincipalId",
    "IdentityStoreId",
    "IdentityCenterInstanceArn",
    "CollectorPermissionSetArn",
    "RepairInvokerPermissionSetArn",
    "CollectorPolicyDigest",
    "RepairInvokerPolicyDigest",
    "OriginalGug220LedgerDigest",
    "ExpectedPermissionSetTagsJson",
    "RepairNotBefore",
    "RepairNotAfter",
    "CollectorSamlProviderArn",
    "IdentityCenterKmsMode",
    "IdentityCenterKmsKeyArn",
    "ExpectedBoto3Version",
    "ExpectedBotocoreVersion",
    "RepairArtifactBucket",
    "RepairArtifactKey",
    "RepairArtifactVersion",
    "RepairArtifactCodeSha256",
    "ReconcileArtifactBucket",
    "ReconcileArtifactKey",
    "ReconcileArtifactVersion",
    "ReconcileArtifactCodeSha256",
    "SigningProfileVersionArn",
)
FUNCTION_RESOURCE_BINDINGS = {
    "PlanFunction": (
        "PlanExecutionRole",
        "ReconcileArtifactCodeSha256",
        "$LATEST",
    ),
    "RepairFunction": (
        "RepairExecutionRole",
        "RepairArtifactCodeSha256",
        "$LATEST",
    ),
    "ReconcileFunction": (
        "ReconcileExecutionRole",
        "ReconcileArtifactCodeSha256",
        "$LATEST",
    ),
}
VERSION_RESOURCE_BINDINGS = {
    "PlanFunctionVersion": (
        "PlanFunction",
        "ReconcileArtifactCodeSha256",
    ),
    "RepairFunctionVersion": (
        "RepairFunction",
        "RepairArtifactCodeSha256",
    ),
    "ReconcileFunctionVersion": (
        "ReconcileFunction",
        "ReconcileArtifactCodeSha256",
    ),
}

_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
_COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
_FUNCTION_VERSION_ARN_RE = re.compile(
    rf"^arn:aws:lambda:{REGION}:{AUTHORITY_ACCOUNT_ID}:function:"
    r"(?P<name>[A-Za-z0-9-_]{1,64}):(?P<version>[1-9][0-9]*)$"
)
_KMS_KEY_ID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
_CODE_SIGNING_ARN_RE = re.compile(
    rf"^arn:aws:lambda:{REGION}:{AUTHORITY_ACCOUNT_ID}:"
    r"code-signing-config:(?P<id>csc-[0-9a-zA-Z]{17})$"
)
_SIGNING_JOB_ARN_RE = re.compile(
    rf"^arn:aws:signer:{REGION}:{AUTHORITY_ACCOUNT_ID}:"
    r"/signing-jobs/[A-Za-z0-9-]{1,64}$"
)
_IAM_ROLE_ID_RE = re.compile(r"^AROA[A-Z0-9]{16,17}$")
_NOT_FOUND = object()


class EffectiveStateReadbackError(ValueError):
    """Stable fail-closed error that never includes provider payloads."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def _fail(code: str) -> None:
    raise EffectiveStateReadbackError(code)


def _private_json(value: Any) -> Any:
    """Return strict canonicalizable JSON without provider SDK metadata."""

    if isinstance(value, Mapping):
        result: dict[str, Any] = {}
        for key, item in value.items():
            if not isinstance(key, str) or key in result:
                _fail("PROVIDER_RESPONSE_MALFORMED")
            if key == "ResponseMetadata":
                continue
            result[key] = _private_json(item)
        return result
    if isinstance(value, (list, tuple)):
        return [_private_json(item) for item in value]
    if isinstance(value, datetime):
        if value.utcoffset() is None:
            _fail("PROVIDER_RESPONSE_MALFORMED")
        return value.astimezone(UTC).isoformat().replace("+00:00", "Z")
    if isinstance(value, date):
        return value.isoformat()
    if value is None or type(value) in {str, bool, int}:
        return value
    if type(value) is float:
        if not math.isfinite(value):
            _fail("PROVIDER_RESPONSE_MALFORMED")
        return value
    _fail("PROVIDER_RESPONSE_MALFORMED")


def canonical_json(value: Any) -> str:
    """Serialize strict JSON deterministically for evidence digests."""

    return json.dumps(
        _private_json(value),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


def canonical_digest(value: Any) -> str:
    """Return a lowercase unprefixed SHA-256 digest."""

    return sha256(canonical_json(value).encode("utf-8")).hexdigest()


class _CloudFormationLoader(yaml.SafeLoader):
    """Strict loader that preserves the small intrinsic set used by the PEP."""


def _construct_unique_mapping(
    loader: yaml.SafeLoader,
    node: yaml.MappingNode,
    deep: bool = False,
) -> dict[Any, Any]:
    result: dict[Any, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in result:
            _fail("REVIEWED_TEMPLATE_INVALID")
        result[key] = loader.construct_object(value_node, deep=deep)
    return result


def _construct_intrinsic(
    loader: yaml.SafeLoader,
    tag_suffix: str,
    node: yaml.Node,
) -> Mapping[str, Any]:
    names = {
        "Ref": "Ref",
        "Sub": "Fn::Sub",
        "GetAtt": "Fn::GetAtt",
        "Equals": "Fn::Equals",
        "Not": "Fn::Not",
    }
    name = names.get(tag_suffix)
    if name is None:
        _fail("REVIEWED_TEMPLATE_INVALID")
    if isinstance(node, yaml.ScalarNode):
        value: Any = loader.construct_scalar(node)
    elif isinstance(node, yaml.SequenceNode):
        value = loader.construct_sequence(node, deep=True)
    elif isinstance(node, yaml.MappingNode):
        value = loader.construct_mapping(node, deep=True)
    else:
        _fail("REVIEWED_TEMPLATE_INVALID")
    return {name: value}


_CloudFormationLoader.construct_mapping = _construct_unique_mapping  # type: ignore[method-assign]
_CloudFormationLoader.add_multi_constructor("!", _construct_intrinsic)


def _load_reviewed_template(reviewed_template_bytes: bytes) -> Mapping[str, Any]:
    try:
        text = reviewed_template_bytes.decode("utf-8")
        loaded = yaml.load(text, Loader=_CloudFormationLoader)
    except EffectiveStateReadbackError:
        raise
    except (UnicodeDecodeError, yaml.YAMLError, ValueError, TypeError):
        _fail("REVIEWED_TEMPLATE_INVALID")
    if not isinstance(loaded, Mapping):
        _fail("REVIEWED_TEMPLATE_INVALID")
    resources = loaded.get("Resources")
    parameters = loaded.get("Parameters")
    if (
        not isinstance(resources, Mapping)
        or not isinstance(parameters, Mapping)
        or tuple(parameters) != TEMPLATE_PARAMETER_KEYS
        or {
            logical_id: _mapping(resource).get("Type")
            for logical_id, resource in resources.items()
        }
        != EXPECTED_RESOURCE_TYPES
    ):
        _fail("REVIEWED_TEMPLATE_INVALID")
    return loaded


def _parameter_values(
    *,
    pep_parameter_handoff: Mapping[str, Any],
    reviewed_template_bytes: bytes,
) -> dict[str, str]:
    if (
        pep_parameter_handoff.get("artifact_type")
        != "scanalyze.platform_authority.lambda_audit_repair_pep_parameters.v1"
        or pep_parameter_handoff.get("schema_version") != 1
        or pep_parameter_handoff.get("work_package") != WORK_PACKAGE
        or pep_parameter_handoff.get("template_sha256")
        != sha256(reviewed_template_bytes).hexdigest()
    ):
        _fail("PEP_PARAMETER_HANDOFF_INVALID")
    raw_parameters = pep_parameter_handoff.get("parameters")
    if not isinstance(raw_parameters, list) or len(raw_parameters) != len(
        TEMPLATE_PARAMETER_KEYS
    ):
        _fail("PEP_PARAMETER_HANDOFF_INVALID")
    values: dict[str, str] = {}
    for expected_key, item in zip(TEMPLATE_PARAMETER_KEYS, raw_parameters):
        if (
            not isinstance(item, Mapping)
            or set(item) != {"ParameterKey", "ParameterValue"}
            or item.get("ParameterKey") != expected_key
            or not isinstance(item.get("ParameterValue"), str)
            or item.get("ParameterValue") == "****"
            or expected_key in values
        ):
            _fail("PEP_PARAMETER_HANDOFF_INVALID")
        values[expected_key] = str(item["ParameterValue"])
    if (
        values["AuthorityAccountId"] != AUTHORITY_ACCOUNT_ID
        or values["ManagementAccountId"] != MANAGEMENT_ACCOUNT_ID
        or values["SourceCommit"] != pep_parameter_handoff.get("source_commit")
    ):
        _fail("PEP_PARAMETER_HANDOFF_INVALID")
    return values


def _role_arn(role_name: str, *, path: str = "/") -> str:
    normalized_path = path.strip("/")
    prefix = f"{normalized_path}/" if normalized_path else ""
    return (
        f"arn:aws:iam::{AUTHORITY_ACCOUNT_ID}:role/"
        f"{prefix}{role_name}"
    )


def _resource_ref(
    logical_id: str,
    *,
    resources: Mapping[str, Any],
    physical_ids: Mapping[str, str],
) -> str:
    if logical_id not in resources or logical_id not in physical_ids:
        _fail("REVIEWED_TEMPLATE_INVALID")
    return physical_ids[logical_id]


def _resource_getatt(
    logical_id: str,
    attribute: str,
    *,
    resources: Mapping[str, Any],
    physical_ids: Mapping[str, str],
) -> str:
    resource = _mapping(resources.get(logical_id))
    resource_type = resource.get("Type")
    properties = _mapping(resource.get("Properties"))
    physical_id = physical_ids.get(logical_id)
    if not isinstance(physical_id, str):
        _fail("REVIEWED_TEMPLATE_INVALID")
    if resource_type == "AWS::IAM::Role" and attribute == "Arn":
        role_name = properties.get("RoleName")
        path = properties.get("Path", "/")
        if not isinstance(role_name, str) or not isinstance(path, str):
            _fail("REVIEWED_TEMPLATE_INVALID")
        return _role_arn(role_name, path=path)
    if resource_type == "AWS::KMS::Key" and attribute == "Arn":
        return f"arn:aws:kms:{REGION}:{AUTHORITY_ACCOUNT_ID}:key/{physical_id}"
    if resource_type == "AWS::DynamoDB::Table" and attribute == "Arn":
        return (
            f"arn:aws:dynamodb:{REGION}:{AUTHORITY_ACCOUNT_ID}:"
            f"table/{physical_id}"
        )
    if resource_type == "AWS::Lambda::Function" and attribute == "Arn":
        return (
            f"arn:aws:lambda:{REGION}:{AUTHORITY_ACCOUNT_ID}:"
            f"function:{physical_id}"
        )
    if resource_type == "AWS::Lambda::Version" and attribute == "Version":
        match = _FUNCTION_VERSION_ARN_RE.fullmatch(physical_id)
        if match is None:
            _fail("REVIEWED_TEMPLATE_INVALID")
        return match.group("version")
    _fail("REVIEWED_TEMPLATE_INVALID")


def _resolve_intrinsic(
    value: Any,
    *,
    parameters: Mapping[str, str],
    resources: Mapping[str, Any],
    physical_ids: Mapping[str, str],
) -> Any:
    if isinstance(value, list):
        return [
            _resolve_intrinsic(
                item,
                parameters=parameters,
                resources=resources,
                physical_ids=physical_ids,
            )
            for item in value
        ]
    if not isinstance(value, Mapping):
        return _private_json(value)
    if set(value) == {"Ref"}:
        target = value["Ref"]
        if not isinstance(target, str):
            _fail("REVIEWED_TEMPLATE_INVALID")
        pseudo = {
            "AWS::AccountId": AUTHORITY_ACCOUNT_ID,
            "AWS::Partition": "aws",
            "AWS::Region": REGION,
        }
        if target in pseudo:
            return pseudo[target]
        if target in parameters:
            return parameters[target]
        return _resource_ref(
            target,
            resources=resources,
            physical_ids=physical_ids,
        )
    if set(value) == {"Fn::GetAtt"}:
        target = value["Fn::GetAtt"]
        if isinstance(target, str):
            parts = target.split(".", 1)
        elif (
            isinstance(target, list)
            and len(target) == 2
            and all(isinstance(item, str) for item in target)
        ):
            parts = target
        else:
            _fail("REVIEWED_TEMPLATE_INVALID")
        if len(parts) != 2:
            _fail("REVIEWED_TEMPLATE_INVALID")
        return _resource_getatt(
            parts[0],
            parts[1],
            resources=resources,
            physical_ids=physical_ids,
        )
    if set(value) == {"Fn::Sub"}:
        raw_sub = value["Fn::Sub"]
        substitutions: Mapping[str, Any] = {}
        if isinstance(raw_sub, str):
            text = raw_sub
        elif (
            isinstance(raw_sub, list)
            and len(raw_sub) == 2
            and isinstance(raw_sub[0], str)
            and isinstance(raw_sub[1], Mapping)
        ):
            text = raw_sub[0]
            substitutions = raw_sub[1]
        else:
            _fail("REVIEWED_TEMPLATE_INVALID")

        def replace(match: re.Match[str]) -> str:
            token = match.group(1)
            if token in substitutions:
                resolved = _resolve_intrinsic(
                    substitutions[token],
                    parameters=parameters,
                    resources=resources,
                    physical_ids=physical_ids,
                )
                if not isinstance(resolved, str):
                    _fail("REVIEWED_TEMPLATE_INVALID")
                return resolved
            if "." in token:
                logical_id, attribute = token.split(".", 1)
                return _resource_getatt(
                    logical_id,
                    attribute,
                    resources=resources,
                    physical_ids=physical_ids,
                )
            return str(
                _resolve_intrinsic(
                    {"Ref": token},
                    parameters=parameters,
                    resources=resources,
                    physical_ids=physical_ids,
                )
            )

        return re.sub(r"\$\{([A-Za-z0-9:._-]+)\}", replace, text)
    if any(str(key).startswith("Fn::") for key in value):
        _fail("REVIEWED_TEMPLATE_INVALID")
    return {
        str(key): _resolve_intrinsic(
            item,
            parameters=parameters,
            resources=resources,
            physical_ids=physical_ids,
        )
        for key, item in value.items()
    }


def _normalized_policy(value: Any) -> Mapping[str, Any]:
    """Normalize IAM/KMS/DynamoDB policy set semantics before comparison."""

    parsed = _policy(value)

    def normalize(item: Any, *, key: str | None = None) -> Any:
        if isinstance(item, Mapping):
            return {
                name: normalize(child, key=name)
                for name, child in sorted(item.items())
            }
        if isinstance(item, list):
            normalized = [normalize(child, key=key) for child in item]
            return sorted(normalized, key=canonical_json)
        return item

    return _mapping(normalize(parsed))


def _template_tags(value: Any) -> list[dict[str, str]]:
    tags = _items(value)
    normalized: list[dict[str, str]] = []
    seen: set[str] = set()
    for item in tags:
        mapped = _mapping(item)
        key = mapped.get("Key")
        tag_value = mapped.get("Value")
        if (
            not isinstance(key, str)
            or not isinstance(tag_value, str)
            or key in seen
        ):
            _fail("REVIEWED_TEMPLATE_INVALID")
        seen.add(key)
        normalized.append({"Key": key, "Value": tag_value})
    return sorted(normalized, key=canonical_json)


def _text_digest(value: str) -> str:
    return sha256(value.encode("utf-8")).hexdigest()


def _mapping(value: Any) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        _fail("PROVIDER_RESPONSE_MALFORMED")
    return value


def _items(value: Any) -> list[Any]:
    if not isinstance(value, list):
        _fail("PROVIDER_RESPONSE_MALFORMED")
    return value


def _required_text(value: Any) -> str:
    if not isinstance(value, str) or not value:
        _fail("PROVIDER_RESPONSE_MALFORMED")
    return value


def _provider_error_code(exc: Exception) -> str | None:
    response = getattr(exc, "response", None)
    if not isinstance(response, Mapping):
        return None
    error = response.get("Error")
    if not isinstance(error, Mapping):
        return None
    code = error.get("Code")
    return code if isinstance(code, str) else None


def _provider_call(
    client: Any,
    method_name: str,
    *,
    allow_not_found: bool = False,
    **kwargs: Any,
) -> Mapping[str, Any] | object:
    method = getattr(client, method_name, None)
    if not callable(method):
        _fail("PROVIDER_CLIENT_INVALID")
    try:
        response = method(**kwargs)
    except Exception as exc:
        if _provider_error_code(exc) == "ResourceNotFoundException":
            if allow_not_found:
                return _NOT_FOUND
            _fail("EFFECTIVE_STATE_RESOURCE_ABSENT")
        _fail("PROVIDER_CALL_FAILED")
    return _mapping(response)


def _dedupe_item(
    item: Any,
    *,
    key: Callable[[Mapping[str, Any]], str],
    seen: set[str],
) -> Mapping[str, Any]:
    mapped = _mapping(item)
    identity = key(mapped)
    if not isinstance(identity, str) or not identity or identity in seen:
        _fail("PROVIDER_PAGINATION_MALFORMED")
    seen.add(identity)
    return mapped


def _paginate_next_marker(
    client: Any,
    method_name: str,
    result_key: str,
    *,
    dedupe_key: Callable[[Mapping[str, Any]], str],
    request: Mapping[str, Any],
) -> list[Mapping[str, Any]]:
    marker: str | None = None
    seen_tokens: set[str] = set()
    seen_items: set[str] = set()
    result: list[Mapping[str, Any]] = []
    for _ in range(MAX_PAGES):
        kwargs = dict(request)
        if marker is not None:
            kwargs["Marker"] = marker
        response = _provider_call(client, method_name, **kwargs)
        assert isinstance(response, Mapping)
        for raw in _items(response.get(result_key)):
            result.append(_dedupe_item(raw, key=dedupe_key, seen=seen_items))
        next_marker = response.get("NextMarker")
        if next_marker is None:
            return result
        if (
            not isinstance(next_marker, str)
            or not next_marker
            or next_marker in seen_tokens
        ):
            _fail("PROVIDER_PAGINATION_MALFORMED")
        seen_tokens.add(next_marker)
        marker = next_marker
    _fail("PROVIDER_PAGINATION_LIMIT_EXCEEDED")


def _paginate_next_token(
    client: Any,
    method_name: str,
    result_key: str,
    *,
    dedupe_key: Callable[[Mapping[str, Any]], str],
    request: Mapping[str, Any],
    token_request_key: str = "nextToken",
    token_response_key: str = "nextToken",
) -> list[Mapping[str, Any]]:
    token: str | None = None
    seen_tokens: set[str] = set()
    seen_items: set[str] = set()
    result: list[Mapping[str, Any]] = []
    for _ in range(MAX_PAGES):
        kwargs = dict(request)
        if token is not None:
            kwargs[token_request_key] = token
        response = _provider_call(client, method_name, **kwargs)
        assert isinstance(response, Mapping)
        for raw in _items(response.get(result_key)):
            result.append(_dedupe_item(raw, key=dedupe_key, seen=seen_items))
        next_token = response.get(token_response_key)
        if next_token is None:
            return result
        if (
            not isinstance(next_token, str)
            or not next_token
            or next_token in seen_tokens
        ):
            _fail("PROVIDER_PAGINATION_MALFORMED")
        seen_tokens.add(next_token)
        token = next_token
    _fail("PROVIDER_PAGINATION_LIMIT_EXCEEDED")


def _paginate_iam(
    client: Any,
    method_name: str,
    result_key: str,
    *,
    dedupe_key: Callable[[Mapping[str, Any]], str] | None,
    scalar_items: bool = False,
    request: Mapping[str, Any],
) -> list[Any]:
    marker: str | None = None
    seen_tokens: set[str] = set()
    seen_items: set[str] = set()
    result: list[Any] = []
    for _ in range(MAX_PAGES):
        kwargs = dict(request)
        kwargs["MaxItems"] = 100
        if marker is not None:
            kwargs["Marker"] = marker
        response = _provider_call(client, method_name, **kwargs)
        assert isinstance(response, Mapping)
        page = _items(response.get(result_key))
        for raw in page:
            if scalar_items:
                identity = _required_text(raw)
                item: Any = identity
            else:
                if dedupe_key is None:
                    _fail("PROVIDER_PAGINATION_MALFORMED")
                item = _dedupe_item(raw, key=dedupe_key, seen=seen_items)
                result.append(item)
                continue
            if identity in seen_items:
                _fail("PROVIDER_PAGINATION_MALFORMED")
            seen_items.add(identity)
            result.append(item)
        truncated = response.get("IsTruncated")
        next_marker = response.get("Marker")
        if type(truncated) is not bool:
            _fail("PROVIDER_PAGINATION_MALFORMED")
        if not truncated:
            if next_marker is not None:
                _fail("PROVIDER_PAGINATION_MALFORMED")
            return result
        if (
            not isinstance(next_marker, str)
            or not next_marker
            or next_marker in seen_tokens
        ):
            _fail("PROVIDER_PAGINATION_MALFORMED")
        seen_tokens.add(next_marker)
        marker = next_marker
    _fail("PROVIDER_PAGINATION_LIMIT_EXCEEDED")


def _paginate_kms(
    client: Any,
    method_name: str,
    result_key: str,
    *,
    dedupe_key: Callable[[Mapping[str, Any]], str],
    limit: int,
    request: Mapping[str, Any],
) -> list[Mapping[str, Any]]:
    if not 1 <= limit <= 100:
        _fail("PROVIDER_PAGINATION_MALFORMED")
    marker: str | None = None
    seen_tokens: set[str] = set()
    seen_items: set[str] = set()
    result: list[Mapping[str, Any]] = []
    for _ in range(MAX_PAGES):
        kwargs = dict(request)
        kwargs["Limit"] = limit
        if marker is not None:
            kwargs["Marker"] = marker
        response = _provider_call(client, method_name, **kwargs)
        assert isinstance(response, Mapping)
        for raw in _items(response.get(result_key)):
            result.append(_dedupe_item(raw, key=dedupe_key, seen=seen_items))
        truncated = response.get("Truncated")
        next_marker = response.get("NextMarker")
        if type(truncated) is not bool:
            _fail("PROVIDER_PAGINATION_MALFORMED")
        if not truncated:
            if next_marker is not None:
                _fail("PROVIDER_PAGINATION_MALFORMED")
            return result
        if (
            not isinstance(next_marker, str)
            or not next_marker
            or next_marker in seen_tokens
        ):
            _fail("PROVIDER_PAGINATION_MALFORMED")
        seen_tokens.add(next_marker)
        marker = next_marker
    _fail("PROVIDER_PAGINATION_LIMIT_EXCEEDED")


def _duplicate_rejecting_object(
    pairs: list[tuple[str, Any]],
) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            _fail("PROVIDER_RESPONSE_MALFORMED")
        result[key] = value
    return result


def _policy(value: Any) -> Mapping[str, Any]:
    if isinstance(value, Mapping):
        parsed: Any = dict(value)
    elif isinstance(value, str) and value:
        try:
            parsed = json.loads(
                unquote(value),
                object_pairs_hook=_duplicate_rejecting_object,
                parse_constant=lambda _: _fail("PROVIDER_RESPONSE_MALFORMED"),
            )
        except EffectiveStateReadbackError:
            raise
        except (json.JSONDecodeError, ValueError):
            _fail("PROVIDER_RESPONSE_MALFORMED")
    else:
        _fail("PROVIDER_RESPONSE_MALFORMED")
    if not isinstance(parsed, Mapping):
        _fail("PROVIDER_RESPONSE_MALFORMED")
    _private_json(parsed)
    return parsed


def _selected(
    value: Mapping[str, Any],
    keys: Sequence[str],
    *,
    required: Sequence[str] = (),
) -> dict[str, Any]:
    if any(key not in value for key in required):
        _fail("PROVIDER_RESPONSE_MALFORMED")
    result = {key: value[key] for key in keys if key in value}
    return _private_json(result)


def _optional_lambda_policy(
    lambda_client: Any,
    *,
    function_name: str,
    qualifier: str | None = None,
) -> Mapping[str, Any]:
    request: dict[str, str] = {"FunctionName": function_name}
    if qualifier is not None:
        request["Qualifier"] = qualifier
    response = _provider_call(
        lambda_client,
        "get_policy",
        allow_not_found=True,
        **request,
    )
    if response is _NOT_FOUND:
        return {"present": False}
    assert isinstance(response, Mapping)
    return {
        "present": True,
        "policy_sha256": canonical_digest(_policy(response.get("Policy"))),
        "revision_id": response.get("RevisionId"),
    }


def _lambda_tags(lambda_client: Any, *, resource_arn: str) -> Mapping[str, str]:
    response = _provider_call(
        lambda_client,
        "list_tags",
        Resource=resource_arn,
    )
    assert isinstance(response, Mapping)
    tags = response.get("Tags")
    if not isinstance(tags, Mapping) or any(
        not isinstance(key, str) or not isinstance(value, str)
        for key, value in tags.items()
    ):
        _fail("PROVIDER_RESPONSE_MALFORMED")
    return dict(sorted(tags.items()))


def _iam_role_state(
    iam_client: Any,
    *,
    role_name: str,
) -> Mapping[str, Any]:
    response = _provider_call(iam_client, "get_role", RoleName=role_name)
    assert isinstance(response, Mapping)
    role = _mapping(response.get("Role"))
    if role.get("RoleName") != role_name:
        _fail("PROVIDER_RESPONSE_MALFORMED")
    role_arn = _required_text(role.get("Arn"))
    if not role_arn.endswith("/" + role_name):
        _fail("PROVIDER_RESPONSE_MALFORMED")
    assume_role_policy = _policy(role.get("AssumeRolePolicyDocument"))

    policy_names = _paginate_iam(
        iam_client,
        "list_role_policies",
        "PolicyNames",
        dedupe_key=None,
        scalar_items=True,
        request={"RoleName": role_name},
    )
    inline_policies = []
    for policy_name in sorted(policy_names):
        policy_response = _provider_call(
            iam_client,
            "get_role_policy",
            RoleName=role_name,
            PolicyName=policy_name,
        )
        assert isinstance(policy_response, Mapping)
        if (
            policy_response.get("RoleName") != role_name
            or policy_response.get("PolicyName") != policy_name
        ):
            _fail("PROVIDER_RESPONSE_MALFORMED")
        inline_policies.append(
            {
                "policy_name": policy_name,
                "document": _policy(policy_response.get("PolicyDocument")),
            }
        )

    attached = _paginate_iam(
        iam_client,
        "list_attached_role_policies",
        "AttachedPolicies",
        dedupe_key=lambda item: _required_text(item.get("PolicyArn")),
        request={"RoleName": role_name},
    )
    tags = _paginate_iam(
        iam_client,
        "list_role_tags",
        "Tags",
        dedupe_key=lambda item: _required_text(item.get("Key")),
        request={"RoleName": role_name},
    )
    profiles = _paginate_iam(
        iam_client,
        "list_instance_profiles_for_role",
        "InstanceProfiles",
        dedupe_key=lambda item: _required_text(item.get("InstanceProfileId")),
        request={"RoleName": role_name},
    )
    return {
        "role": _selected(
            role,
            (
                "Path",
                "RoleName",
                "RoleId",
                "Arn",
                "Description",
                "MaxSessionDuration",
                "PermissionsBoundary",
            ),
            required=(
                "Path",
                "RoleName",
                "RoleId",
                "Arn",
                "MaxSessionDuration",
            ),
        ),
        "assume_role_policy": assume_role_policy,
        "inline_policies": sorted(
            (_private_json(item) for item in inline_policies),
            key=canonical_json,
        ),
        "attached_policies": sorted(
            (_private_json(item) for item in attached),
            key=canonical_json,
        ),
        "tags": sorted(
            (_private_json(item) for item in tags),
            key=canonical_json,
        ),
        "instance_profiles": sorted(
            (
                _selected(
                    item,
                    (
                        "Path",
                        "InstanceProfileName",
                        "InstanceProfileId",
                        "Arn",
                        "Roles",
                    ),
                    required=(
                        "InstanceProfileName",
                        "InstanceProfileId",
                        "Arn",
                    ),
                )
                for item in profiles
            ),
            key=canonical_json,
        ),
    }


_FUNCTION_CONFIGURATION_KEYS = (
    "FunctionName",
    "FunctionArn",
    "Runtime",
    "Role",
    "Handler",
    "CodeSize",
    "Description",
    "Timeout",
    "MemorySize",
    "CodeSha256",
    "Version",
    "VpcConfig",
    "DeadLetterConfig",
    "Environment",
    "KMSKeyArn",
    "TracingConfig",
    "MasterArn",
    "RevisionId",
    "Layers",
    "State",
    "StateReasonCode",
    "LastUpdateStatus",
    "LastUpdateStatusReasonCode",
    "FileSystemConfigs",
    "PackageType",
    "ImageConfigResponse",
    "SigningProfileVersionArn",
    "SigningJobArn",
    "Architectures",
    "EphemeralStorage",
    "SnapStart",
    "RuntimeVersionConfig",
    "LoggingConfig",
)


def _function_configuration(
    value: Mapping[str, Any],
    *,
    function_name: str,
    expected_arn: str,
    expected_version: str,
) -> Mapping[str, Any]:
    if (
        value.get("FunctionName") != function_name
        or value.get("FunctionArn") != expected_arn
        or value.get("Version") != expected_version
    ):
        _fail("PROVIDER_RESPONSE_MALFORMED")
    return _selected(
        value,
        _FUNCTION_CONFIGURATION_KEYS,
        required=(
            "FunctionName",
            "FunctionArn",
            "Runtime",
            "Role",
            "Handler",
            "Timeout",
            "MemorySize",
            "CodeSha256",
            "Version",
            "State",
            "PackageType",
            "Architectures",
        ),
    )


def _lambda_function_state(
    lambda_client: Any,
    *,
    function_name: str,
    code_signing_config_arn: str,
) -> Mapping[str, Any]:
    base_arn = (
        f"arn:aws:lambda:{REGION}:{AUTHORITY_ACCOUNT_ID}:function:{function_name}"
    )
    response = _provider_call(
        lambda_client,
        "get_function_configuration",
        FunctionName=function_name,
    )
    assert isinstance(response, Mapping)
    configuration = _function_configuration(
        response,
        function_name=function_name,
        expected_arn=base_arn,
        expected_version="$LATEST",
    )
    signing = _provider_call(
        lambda_client,
        "get_function_code_signing_config",
        FunctionName=function_name,
    )
    assert isinstance(signing, Mapping)
    if (
        signing.get("FunctionName") != function_name
        or signing.get("CodeSigningConfigArn") != code_signing_config_arn
    ):
        _fail("PROVIDER_RESPONSE_MALFORMED")
    concurrency = _provider_call(
        lambda_client,
        "get_function_concurrency",
        FunctionName=function_name,
    )
    assert isinstance(concurrency, Mapping)
    reserved = concurrency.get("ReservedConcurrentExecutions")
    if reserved is not None and (type(reserved) is not int or reserved < 0):
        _fail("PROVIDER_RESPONSE_MALFORMED")
    event_sources = _paginate_next_marker(
        lambda_client,
        "list_event_source_mappings",
        "EventSourceMappings",
        dedupe_key=lambda item: _required_text(item.get("UUID")),
        request={"FunctionName": function_name, "MaxItems": 100},
    )
    return {
        "configuration": configuration,
        "code_signing": _selected(
            signing,
            ("FunctionName", "CodeSigningConfigArn"),
            required=("FunctionName", "CodeSigningConfigArn"),
        ),
        "reserved_concurrent_executions": reserved,
        "resource_policy": _optional_lambda_policy(
            lambda_client, function_name=function_name
        ),
        "event_source_mappings": sorted(
            (_private_json(item) for item in event_sources),
            key=canonical_json,
        ),
        "tags": _lambda_tags(lambda_client, resource_arn=base_arn),
    }


def _lambda_version_state(
    lambda_client: Any,
    *,
    function_name: str,
    version_arn: str,
    version: str,
) -> Mapping[str, Any]:
    versions = _paginate_next_marker(
        lambda_client,
        "list_versions_by_function",
        "Versions",
        dedupe_key=lambda item: _required_text(item.get("Version")),
        request={"FunctionName": function_name, "MaxItems": 100},
    )
    expected_inventory = {
        (
            "$LATEST",
            f"arn:aws:lambda:{REGION}:{AUTHORITY_ACCOUNT_ID}:"
            f"function:{function_name}",
        ),
        (version, version_arn),
    }
    observed_inventory = {
        (
            _required_text(item.get("Version")),
            _required_text(item.get("FunctionArn")),
        )
        for item in versions
    }
    if (
        len(versions) != len(expected_inventory)
        or observed_inventory != expected_inventory
    ):
        _fail("EFFECTIVE_STATE_CONFORMANCE_DRIFT")
    matches = [
        item
        for item in versions
        if item.get("Version") == version and item.get("FunctionArn") == version_arn
    ]
    if len(matches) != 1:
        _fail("EFFECTIVE_STATE_RESOURCE_ABSENT")
    return {
        "configuration": _function_configuration(
            matches[0],
            function_name=function_name,
            expected_arn=version_arn,
            expected_version=version,
        ),
        "resource_policy": _optional_lambda_policy(
            lambda_client,
            function_name=function_name,
            qualifier=version,
        ),
    }


def _alias_projection(
    item: Mapping[str, Any],
    *,
    function_name: str,
    alias_name: str,
    alias_arn: str,
) -> Mapping[str, Any]:
    if (
        item.get("Name") != alias_name
        or item.get("AliasArn") != alias_arn
        or not isinstance(item.get("FunctionVersion"), str)
    ):
        _fail("PROVIDER_RESPONSE_MALFORMED")
    return _selected(
        item,
        (
            "AliasArn",
            "Name",
            "FunctionVersion",
            "Description",
            "RoutingConfig",
            "RevisionId",
        ),
        required=("AliasArn", "Name", "FunctionVersion"),
    )


def _lambda_alias_state(
    lambda_client: Any,
    *,
    function_name: str,
    alias_name: str,
    alias_arn: str,
) -> Mapping[str, Any]:
    direct = _provider_call(
        lambda_client,
        "get_alias",
        FunctionName=function_name,
        Name=alias_name,
    )
    assert isinstance(direct, Mapping)
    direct_projection = _alias_projection(
        direct,
        function_name=function_name,
        alias_name=alias_name,
        alias_arn=alias_arn,
    )
    aliases = _paginate_next_marker(
        lambda_client,
        "list_aliases",
        "Aliases",
        dedupe_key=lambda item: _required_text(item.get("Name")),
        request={"FunctionName": function_name, "MaxItems": 100},
    )
    if len(aliases) != 1:
        _fail("EFFECTIVE_STATE_CONFORMANCE_DRIFT")
    matches = [item for item in aliases if item.get("Name") == alias_name]
    if len(matches) != 1:
        _fail("EFFECTIVE_STATE_RESOURCE_ABSENT")
    inventory_projection = _alias_projection(
        matches[0],
        function_name=function_name,
        alias_name=alias_name,
        alias_arn=alias_arn,
    )
    if canonical_digest(direct_projection) != canonical_digest(inventory_projection):
        _fail("PROVIDER_RESPONSE_MALFORMED")
    return {
        "alias": direct_projection,
        "resource_policy": _optional_lambda_policy(
            lambda_client,
            function_name=function_name,
            qualifier=alias_name,
        ),
    }


def _event_invoke_projection(
    item: Mapping[str, Any],
    *,
    alias_arn: str,
) -> Mapping[str, Any]:
    if item.get("FunctionArn") not in (None, alias_arn):
        _fail("PROVIDER_RESPONSE_MALFORMED")
    return _selected(
        item,
        (
            "FunctionArn",
            "MaximumRetryAttempts",
            "MaximumEventAgeInSeconds",
            "DestinationConfig",
        ),
        required=("MaximumRetryAttempts", "MaximumEventAgeInSeconds"),
    )


def _event_invoke_state(
    lambda_client: Any,
    *,
    function_name: str,
    alias_name: str,
) -> Mapping[str, Any]:
    alias_arn = (
        f"arn:aws:lambda:{REGION}:{AUTHORITY_ACCOUNT_ID}:function:"
        f"{function_name}:{alias_name}"
    )
    direct = _provider_call(
        lambda_client,
        "get_function_event_invoke_config",
        FunctionName=function_name,
        Qualifier=alias_name,
    )
    assert isinstance(direct, Mapping)
    direct_projection = _event_invoke_projection(direct, alias_arn=alias_arn)
    inventory = _paginate_next_marker(
        lambda_client,
        "list_function_event_invoke_configs",
        "FunctionEventInvokeConfigs",
        dedupe_key=lambda item: _required_text(item.get("FunctionArn")),
        request={"FunctionName": function_name, "MaxItems": 100},
    )
    if len(inventory) != 1:
        _fail("EFFECTIVE_STATE_CONFORMANCE_DRIFT")
    matches = [item for item in inventory if item.get("FunctionArn") == alias_arn]
    if len(matches) != 1:
        _fail("EFFECTIVE_STATE_RESOURCE_ABSENT")
    inventory_projection = _event_invoke_projection(matches[0], alias_arn=alias_arn)
    if canonical_digest(direct_projection) != canonical_digest(inventory_projection):
        _fail("PROVIDER_RESPONSE_MALFORMED")
    return {"event_invoke_config": direct_projection}


def _code_signing_state(
    lambda_client: Any,
    *,
    config_arn: str,
) -> Mapping[str, Any]:
    match = _CODE_SIGNING_ARN_RE.fullmatch(config_arn)
    if match is None:
        _fail("PHYSICAL_RESOURCE_BINDING_INVALID")
    config_id = match.group("id")
    response = _provider_call(
        lambda_client,
        "get_code_signing_config",
        CodeSigningConfigArn=config_arn,
    )
    assert isinstance(response, Mapping)
    config = _mapping(response.get("CodeSigningConfig"))
    if (
        config.get("CodeSigningConfigId") != config_id
        or config.get("CodeSigningConfigArn") != config_arn
    ):
        _fail("PROVIDER_RESPONSE_MALFORMED")
    return {
        "code_signing_config": _selected(
            config,
            (
                "CodeSigningConfigId",
                "CodeSigningConfigArn",
                "Description",
                "AllowedPublishers",
                "CodeSigningPolicies",
            ),
            required=(
                "CodeSigningConfigId",
                "CodeSigningConfigArn",
                "AllowedPublishers",
                "CodeSigningPolicies",
            ),
        ),
        "tags": _lambda_tags(lambda_client, resource_arn=config_arn),
    }


def _dynamodb_state(
    dynamodb_client: Any,
    *,
    table_name: str,
) -> Mapping[str, Any]:
    table_response = _provider_call(
        dynamodb_client, "describe_table", TableName=table_name
    )
    assert isinstance(table_response, Mapping)
    table = _mapping(table_response.get("Table"))
    table_arn = f"arn:aws:dynamodb:{REGION}:{AUTHORITY_ACCOUNT_ID}:table/{table_name}"
    if table.get("TableName") != table_name or table.get("TableArn") != table_arn:
        _fail("PROVIDER_RESPONSE_MALFORMED")
    backups = _provider_call(
        dynamodb_client,
        "describe_continuous_backups",
        TableName=table_name,
    )
    ttl = _provider_call(
        dynamodb_client,
        "describe_time_to_live",
        TableName=table_name,
    )
    policy_response = _provider_call(
        dynamodb_client,
        "get_resource_policy",
        ResourceArn=table_arn,
        allow_not_found=True,
    )
    if policy_response is _NOT_FOUND:
        policy: Mapping[str, Any] = {"present": False}
    else:
        assert isinstance(policy_response, Mapping)
        raw_policy = policy_response.get("Policy")
        policy = (
            {"present": False}
            if raw_policy in (None, "")
            else {
                "present": True,
                "policy": _policy(raw_policy),
                "revision_id": policy_response.get("RevisionId"),
            }
        )
    tags = _paginate_next_token(
        dynamodb_client,
        "list_tags_of_resource",
        "Tags",
        dedupe_key=lambda item: _required_text(item.get("Key")),
        request={"ResourceArn": table_arn},
        token_request_key="NextToken",
        token_response_key="NextToken",
    )
    return {
        "table": _selected(
            table,
            (
                "TableName",
                "TableArn",
                "TableStatus",
                "AttributeDefinitions",
                "KeySchema",
                "BillingModeSummary",
                "LocalSecondaryIndexes",
                "GlobalSecondaryIndexes",
                "ProvisionedThroughput",
                "StreamSpecification",
                "LatestStreamLabel",
                "LatestStreamArn",
                "SSEDescription",
                "ArchivalSummary",
                "TableClassSummary",
                "DeletionProtectionEnabled",
                "OnDemandThroughput",
                "WarmThroughput",
                "MultiRegionConsistency",
                "GlobalTableWitnesses",
                "Replicas",
                "RestoreSummary",
            ),
            required=(
                "TableName",
                "TableArn",
                "TableStatus",
                "AttributeDefinitions",
                "KeySchema",
            ),
        ),
        "continuous_backups": _private_json(backups),
        "time_to_live": _private_json(ttl),
        "resource_policy": policy,
        "tags": sorted(
            (_private_json(item) for item in tags),
            key=canonical_json,
        ),
    }


def _kms_key_state(
    kms_client: Any,
    *,
    key_id: str,
) -> Mapping[str, Any]:
    response = _provider_call(kms_client, "describe_key", KeyId=key_id)
    assert isinstance(response, Mapping)
    metadata = _mapping(response.get("KeyMetadata"))
    expected_arn = f"arn:aws:kms:{REGION}:{AUTHORITY_ACCOUNT_ID}:key/{key_id}"
    if (
        metadata.get("KeyId") != key_id
        or metadata.get("Arn") != expected_arn
        or metadata.get("AWSAccountId") != AUTHORITY_ACCOUNT_ID
    ):
        _fail("PROVIDER_RESPONSE_MALFORMED")
    rotation = _provider_call(kms_client, "get_key_rotation_status", KeyId=key_id)
    policy_response = _provider_call(
        kms_client,
        "get_key_policy",
        KeyId=key_id,
        PolicyName="default",
    )
    assert isinstance(policy_response, Mapping)
    if policy_response.get("PolicyName") not in (None, "default"):
        _fail("PROVIDER_RESPONSE_MALFORMED")
    policy = _policy(policy_response.get("Policy"))
    tags = _paginate_kms(
        kms_client,
        "list_resource_tags",
        "Tags",
        dedupe_key=lambda item: _required_text(item.get("TagKey")),
        limit=50,
        request={"KeyId": key_id},
    )
    return {
        "key_metadata": _selected(
            metadata,
            (
                "AWSAccountId",
                "KeyId",
                "Arn",
                "Enabled",
                "Description",
                "KeyUsage",
                "KeyState",
                "Origin",
                "CustomKeyStoreId",
                "CloudHsmClusterId",
                "ExpirationModel",
                "KeyManager",
                "CustomerMasterKeySpec",
                "KeySpec",
                "EncryptionAlgorithms",
                "SigningAlgorithms",
                "MultiRegion",
                "MultiRegionConfiguration",
                "MacAlgorithms",
                "XksKeyConfiguration",
            ),
            required=(
                "AWSAccountId",
                "KeyId",
                "Arn",
                "Enabled",
                "KeyUsage",
                "KeyState",
                "Origin",
                "KeyManager",
                "KeySpec",
                "MultiRegion",
            ),
        ),
        "rotation": _selected(
            _mapping(rotation),
            (
                "KeyId",
                "KeyRotationEnabled",
                "RotationPeriodInDays",
                "OnDemandRotationStartDate",
            ),
            required=("KeyRotationEnabled",),
        ),
        "key_policy": policy,
        "tags": sorted(
            (_private_json(item) for item in tags),
            key=canonical_json,
        ),
    }


def _kms_alias_state(
    kms_client: Any,
    *,
    key_id: str,
    alias_name: str,
) -> Mapping[str, Any]:
    aliases = _paginate_kms(
        kms_client,
        "list_aliases",
        "Aliases",
        dedupe_key=lambda item: _required_text(item.get("AliasName")),
        limit=100,
        request={"KeyId": key_id},
    )
    if len(aliases) != 1:
        _fail("EFFECTIVE_STATE_CONFORMANCE_DRIFT")
    matches = [item for item in aliases if item.get("AliasName") == alias_name]
    if len(matches) != 1:
        _fail("EFFECTIVE_STATE_RESOURCE_ABSENT")
    alias = matches[0]
    if alias.get("TargetKeyId") != key_id:
        _fail("PROVIDER_RESPONSE_MALFORMED")
    return {
        "alias": _selected(
            alias,
            ("AliasName", "AliasArn", "TargetKeyId"),
            required=("AliasName", "AliasArn", "TargetKeyId"),
        )
    }


def _log_group_state(
    logs_client: Any,
    *,
    log_group_name: str,
) -> Mapping[str, Any]:
    groups = _paginate_next_token(
        logs_client,
        "describe_log_groups",
        "logGroups",
        dedupe_key=lambda item: _required_text(item.get("logGroupName")),
        request={
            "logGroupNamePrefix": log_group_name,
            "limit": 50,
        },
    )
    matches = [item for item in groups if item.get("logGroupName") == log_group_name]
    if len(matches) != 1:
        _fail("EFFECTIVE_STATE_RESOURCE_ABSENT")
    group = matches[0]
    arn = _required_text(group.get("arn"))
    if f":log-group:{log_group_name}" not in arn:
        _fail("PROVIDER_RESPONSE_MALFORMED")
    tags_response = _provider_call(
        logs_client,
        "list_tags_for_resource",
        resourceArn=_required_text(group.get("logGroupArn")),
    )
    assert isinstance(tags_response, Mapping)
    tags = tags_response.get("tags")
    if not isinstance(tags, Mapping) or any(
        not isinstance(key, str) or not isinstance(value, str)
        for key, value in tags.items()
    ):
        _fail("PROVIDER_RESPONSE_MALFORMED")
    return {
        "log_group": _selected(
            group,
            (
                "logGroupName",
                "arn",
                "retentionInDays",
                "kmsKeyId",
                "dataProtectionStatus",
                "inheritedProperties",
                "logGroupClass",
                "logGroupArn",
                "deletionProtectionEnabled",
            ),
            required=("logGroupName", "arn"),
        ),
        "tags": dict(sorted(tags.items())),
    }


def _resolved_resource_properties(
    logical_id: str,
    *,
    template: Mapping[str, Any],
    parameters: Mapping[str, str],
    physical_ids: Mapping[str, str],
) -> Mapping[str, Any]:
    resources = _mapping(template.get("Resources"))
    resource = _mapping(resources.get(logical_id))
    properties = _mapping(resource.get("Properties"))
    resolved = _resolve_intrinsic(
        properties,
        parameters=parameters,
        resources=resources,
        physical_ids=physical_ids,
    )
    return _mapping(resolved)


def _tag_map_from_template(value: Any) -> dict[str, str]:
    return {
        item["Key"]: item["Value"]
        for item in _template_tags(value)
    }


def _tag_map_from_provider(
    value: Any,
    *,
    key_name: str = "Key",
    value_name: str = "Value",
) -> dict[str, str]:
    result: dict[str, str] = {}
    for item in _items(value):
        mapped = _mapping(item)
        key = mapped.get(key_name)
        tag_value = mapped.get(value_name)
        if (
            not isinstance(key, str)
            or not isinstance(tag_value, str)
            or key in result
        ):
            _fail("PROVIDER_RESPONSE_MALFORMED")
        result[key] = tag_value
    return dict(sorted(result.items()))


def _normalized_list(value: Any) -> list[Any]:
    return sorted(
        (_private_json(item) for item in _items(value)),
        key=canonical_json,
    )


def _expected_role_contract(properties: Mapping[str, Any]) -> Mapping[str, Any]:
    role_name = _required_text(properties.get("RoleName"))
    path = properties.get("Path", "/")
    if not isinstance(path, str):
        _fail("REVIEWED_TEMPLATE_INVALID")
    policies = _items(properties.get("Policies", []))
    inline: list[dict[str, Any]] = []
    seen: set[str] = set()
    for item in policies:
        mapped = _mapping(item)
        policy_name = mapped.get("PolicyName")
        if (
            not isinstance(policy_name, str)
            or not policy_name
            or policy_name in seen
        ):
            _fail("REVIEWED_TEMPLATE_INVALID")
        seen.add(policy_name)
        inline.append(
            {
                "policy_name": policy_name,
                "document": _normalized_policy(mapped.get("PolicyDocument")),
            }
        )
    permissions_boundary = properties.get("PermissionsBoundary")
    result: dict[str, Any] = {
        "path": path,
        "role_name": role_name,
        "role_id_classification": {
            "authority": "AWS_ASSIGNED",
            "format": "IAM_ROLE_UNIQUE_ID",
            "conformance": "FORMAT_AND_TWO_SNAPSHOT_STABILITY",
        },
        "arn": _role_arn(role_name, path=path),
        "max_session_duration": properties.get("MaxSessionDuration", 3600),
        "permissions_boundary": (
            None
            if permissions_boundary is None
            else {
                "type": "Policy",
                "arn": permissions_boundary,
            }
        ),
        "assume_role_policy": _normalized_policy(
            properties.get("AssumeRolePolicyDocument")
        ),
        "inline_policies": sorted(inline, key=canonical_json),
        "attached_policy_arns": [],
        "tags": _tag_map_from_template(properties.get("Tags", [])),
        "instance_profile_arns": [],
    }
    if "Description" in properties:
        result["description"] = properties["Description"]
    return result


def _observed_role_contract(state: Mapping[str, Any]) -> Mapping[str, Any]:
    role = _mapping(state.get("role"))
    role_id = role.get("RoleId")
    if not isinstance(role_id, str) or _IAM_ROLE_ID_RE.fullmatch(role_id) is None:
        _fail("PROVIDER_RESPONSE_MALFORMED")
    raw_boundary = role.get("PermissionsBoundary")
    boundary = _mapping(raw_boundary) if raw_boundary is not None else {}
    result: dict[str, Any] = {
        "path": role.get("Path"),
        "role_name": role.get("RoleName"),
        "role_id_classification": {
            "authority": "AWS_ASSIGNED",
            "format": "IAM_ROLE_UNIQUE_ID",
            "conformance": "FORMAT_AND_TWO_SNAPSHOT_STABILITY",
        },
        "arn": role.get("Arn"),
        "max_session_duration": role.get("MaxSessionDuration"),
        "permissions_boundary": (
            None
            if raw_boundary is None
            else {
                "type": boundary.get("PermissionsBoundaryType"),
                "arn": boundary.get("PermissionsBoundaryArn"),
            }
        ),
        "assume_role_policy": _normalized_policy(
            state.get("assume_role_policy")
        ),
        "inline_policies": sorted(
            (
                {
                    "policy_name": _required_text(
                        _mapping(item).get("policy_name")
                    ),
                    "document": _normalized_policy(
                        _mapping(item).get("document")
                    ),
                }
                for item in _items(state.get("inline_policies"))
            ),
            key=canonical_json,
        ),
        "attached_policy_arns": sorted(
            _required_text(_mapping(item).get("PolicyArn"))
            for item in _items(state.get("attached_policies"))
        ),
        "tags": _tag_map_from_provider(state.get("tags")),
        "instance_profile_arns": sorted(
            _required_text(_mapping(item).get("Arn"))
            for item in _items(state.get("instance_profiles"))
        ),
    }
    if "Description" in role:
        result["description"] = role["Description"]
    return _private_json(result)


def _expected_function_configuration(
    *,
    function_logical_id: str,
    version_logical_id: str | None,
    template: Mapping[str, Any],
    parameters: Mapping[str, str],
    physical_ids: Mapping[str, str],
) -> Mapping[str, Any]:
    function = _resolved_resource_properties(
        function_logical_id,
        template=template,
        parameters=parameters,
        physical_ids=physical_ids,
    )
    function_name = _required_text(function.get("FunctionName"))
    if version_logical_id is None:
        function_arn = (
            f"arn:aws:lambda:{REGION}:{AUTHORITY_ACCOUNT_ID}:"
            f"function:{function_name}"
        )
        version = "$LATEST"
        description = function.get("Description", "")
        code_sha256 = parameters[
            FUNCTION_RESOURCE_BINDINGS[function_logical_id][1]
        ]
    else:
        version_arn = _required_text(physical_ids.get(version_logical_id))
        match = _FUNCTION_VERSION_ARN_RE.fullmatch(version_arn)
        if match is None or match.group("name") != function_name:
            _fail("PHYSICAL_RESOURCE_BINDING_INVALID")
        version_properties = _resolved_resource_properties(
            version_logical_id,
            template=template,
            parameters=parameters,
            physical_ids=physical_ids,
        )
        function_arn = version_arn
        version = match.group("version")
        description = version_properties.get("Description", "")
        code_sha256 = version_properties.get("CodeSha256")
    vpc = _mapping(function.get("VpcConfig", {}))
    dead_letter = _mapping(function.get("DeadLetterConfig", {}))
    tracing = _mapping(function.get("TracingConfig", {}))
    ephemeral = _mapping(function.get("EphemeralStorage", {}))
    snap_start = _mapping(function.get("SnapStart", {}))
    runtime_management = _mapping(
        function.get("RuntimeManagementConfig", {})
    )
    logging = _mapping(function.get("LoggingConfig", {}))
    file_systems = _normalized_list(
        function.get("FileSystemConfigs", [])
    )
    layer_arns = sorted(
        _required_text(item) for item in _items(function.get("Layers", []))
    )
    update_runtime_on = runtime_management.get(
        "UpdateRuntimeOn", "Auto"
    )
    runtime_version_arn = runtime_management.get("RuntimeVersionArn")
    if update_runtime_on == "Manual":
        runtime_version_contract: Mapping[str, Any] = {
            "mode": "Manual",
            "runtime_version_arn": runtime_version_arn,
            "error": None,
        }
    else:
        runtime_version_contract = {
            "mode": update_runtime_on,
            "runtime_version_arn": "PROVIDER_MANAGED",
            "error": None,
        }
    return {
        "function_name": function_name,
        "function_arn": function_arn,
        "runtime": function.get("Runtime"),
        "role": function.get("Role"),
        "handler": function.get("Handler"),
        "description": description,
        "timeout": function.get("Timeout", 3),
        "memory_size": function.get("MemorySize", 128),
        "code_sha256": code_sha256,
        "version": version,
        "package_type": function.get("PackageType", "Zip"),
        "architectures": function.get("Architectures", ["x86_64"]),
        "environment": function.get("Environment", {"Variables": {}}),
        "vpc_config": {
            "subnet_ids": sorted(vpc.get("SubnetIds", [])),
            "security_group_ids": sorted(
                vpc.get("SecurityGroupIds", [])
            ),
            "vpc_id": None,
            "ipv6_allowed_for_dual_stack": vpc.get(
                "Ipv6AllowedForDualStack", False
            ),
        },
        "dead_letter_target_arn": dead_letter.get("TargetArn"),
        "kms_key_arn": function.get("KmsKeyArn"),
        "tracing_mode": tracing.get("Mode", "PassThrough"),
        "layer_arns": layer_arns,
        "file_system_configs": file_systems,
        "image_config": (
            function.get("ImageConfig")
            if function.get("PackageType", "Zip") == "Image"
            else None
        ),
        "ephemeral_storage_size": ephemeral.get("Size", 512),
        "snap_start": {
            "apply_on": snap_start.get("ApplyOn", "None"),
            "optimization_status": (
                "Off"
                if snap_start.get("ApplyOn", "None") == "None"
                else "On"
            ),
        },
        "runtime_version": runtime_version_contract,
        "master_arn": None,
        "signing_profile_version_arn": parameters[
            "SigningProfileVersionArn"
        ],
        "signing_job_classification": {
            "authority": "AWS_SIGNER_ASSIGNED",
            "binding": "ACCOUNT_REGION_FORMAT_AND_TWO_SNAPSHOT_STABILITY",
            "exact_job_provenance": False,
        },
        "state_reason_code": None,
        "last_update_status_reason_code": None,
        "logging_config": {
            "log_format": logging.get("LogFormat", "Text"),
            "application_log_level": logging.get(
                "ApplicationLogLevel"
            ),
            "system_log_level": logging.get("SystemLogLevel"),
            "log_group": logging.get(
                "LogGroup", f"/aws/lambda/{function_name}"
            ),
        },
        "state": "Active",
        "last_update_status": "Successful",
    }


def _observed_runtime_version_contract(value: Any) -> Mapping[str, Any]:
    runtime = _mapping(value or {})
    error = runtime.get("Error")
    runtime_version_arn = runtime.get("RuntimeVersionArn")
    if error is not None:
        return {
            "mode": "Auto",
            "runtime_version_arn": runtime_version_arn,
            "error": _private_json(error),
        }
    if runtime_version_arn is None:
        normalized_arn: Any = "PROVIDER_MANAGED"
    elif (
        isinstance(runtime_version_arn, str)
        and runtime_version_arn.startswith(
            f"arn:aws:lambda:{REGION}::runtime:"
        )
    ):
        normalized_arn = "PROVIDER_MANAGED"
    else:
        normalized_arn = runtime_version_arn
    return {
        "mode": "Auto",
        "runtime_version_arn": normalized_arn,
        "error": None,
    }


def _observed_function_configuration(
    configuration: Mapping[str, Any],
) -> Mapping[str, Any]:
    vpc = _mapping(configuration.get("VpcConfig", {}))
    dead_letter = _mapping(configuration.get("DeadLetterConfig", {}))
    tracing = _mapping(configuration.get("TracingConfig", {}))
    ephemeral = _mapping(configuration.get("EphemeralStorage", {}))
    snap_start = _mapping(configuration.get("SnapStart", {}))
    logging = _mapping(configuration.get("LoggingConfig", {}))
    layers = _items(configuration.get("Layers", []))
    file_systems = _normalized_list(
        configuration.get("FileSystemConfigs", [])
    )
    image_response = configuration.get("ImageConfigResponse")
    signing_job_arn = configuration.get("SigningJobArn")
    if (
        not isinstance(signing_job_arn, str)
        or _SIGNING_JOB_ARN_RE.fullmatch(signing_job_arn) is None
    ):
        _fail("PROVIDER_RESPONSE_MALFORMED")
    return _private_json(
        {
            "function_name": configuration.get("FunctionName"),
            "function_arn": configuration.get("FunctionArn"),
            "runtime": configuration.get("Runtime"),
            "role": configuration.get("Role"),
            "handler": configuration.get("Handler"),
            "description": configuration.get("Description", ""),
            "timeout": configuration.get("Timeout"),
            "memory_size": configuration.get("MemorySize"),
            "code_sha256": configuration.get("CodeSha256"),
            "version": configuration.get("Version"),
            "package_type": configuration.get("PackageType"),
            "architectures": configuration.get("Architectures"),
            "environment": configuration.get(
                "Environment", {"Variables": {}}
            ),
            "vpc_config": {
                "subnet_ids": sorted(vpc.get("SubnetIds", [])),
                "security_group_ids": sorted(
                    vpc.get("SecurityGroupIds", [])
                ),
                "vpc_id": vpc.get("VpcId") or None,
                "ipv6_allowed_for_dual_stack": vpc.get(
                    "Ipv6AllowedForDualStack", False
                ),
            },
            "dead_letter_target_arn": dead_letter.get("TargetArn"),
            "kms_key_arn": configuration.get("KMSKeyArn"),
            "tracing_mode": tracing.get("Mode", "PassThrough"),
            "layer_arns": sorted(
                _required_text(_mapping(item).get("Arn"))
                for item in layers
            ),
            "file_system_configs": file_systems,
            "image_config": (
                None
                if image_response in (None, {})
                else _private_json(image_response)
            ),
            "ephemeral_storage_size": ephemeral.get("Size", 512),
            "snap_start": {
                "apply_on": snap_start.get("ApplyOn", "None"),
                "optimization_status": snap_start.get(
                    "OptimizationStatus", "Off"
                ),
            },
            "runtime_version": _observed_runtime_version_contract(
                configuration.get("RuntimeVersionConfig")
            ),
            "master_arn": configuration.get("MasterArn"),
            "signing_profile_version_arn": configuration.get(
                "SigningProfileVersionArn"
            ),
            "signing_job_classification": {
                "authority": "AWS_SIGNER_ASSIGNED",
                "binding": (
                    "ACCOUNT_REGION_FORMAT_AND_TWO_SNAPSHOT_STABILITY"
                ),
                "exact_job_provenance": False,
            },
            "state_reason_code": configuration.get("StateReasonCode"),
            "last_update_status_reason_code": configuration.get(
                "LastUpdateStatusReasonCode"
            ),
            "logging_config": {
                "log_format": logging.get("LogFormat", "Text"),
                "application_log_level": logging.get(
                    "ApplicationLogLevel"
                ),
                "system_log_level": logging.get("SystemLogLevel"),
                "log_group": logging.get(
                    "LogGroup",
                    f"/aws/lambda/{configuration.get('FunctionName')}",
                ),
            },
            "state": configuration.get("State"),
            "last_update_status": configuration.get("LastUpdateStatus"),
        }
    )


def _expected_lambda_function_contract(
    logical_id: str,
    *,
    template: Mapping[str, Any],
    parameters: Mapping[str, str],
    physical_ids: Mapping[str, str],
) -> Mapping[str, Any]:
    properties = _resolved_resource_properties(
        logical_id,
        template=template,
        parameters=parameters,
        physical_ids=physical_ids,
    )
    return {
        "configuration": _expected_function_configuration(
            function_logical_id=logical_id,
            version_logical_id=None,
            template=template,
            parameters=parameters,
            physical_ids=physical_ids,
        ),
        "code_signing_config_arn": properties.get("CodeSigningConfigArn"),
        "reserved_concurrent_executions": properties.get(
            "ReservedConcurrentExecutions"
        ),
        "resource_policy": {"present": False},
        "event_source_mappings": [],
        "tags": _tag_map_from_template(properties.get("Tags", [])),
    }


def _observed_lambda_function_contract(
    state: Mapping[str, Any],
) -> Mapping[str, Any]:
    signing = _mapping(state.get("code_signing"))
    return {
        "configuration": _observed_function_configuration(
            _mapping(state.get("configuration"))
        ),
        "code_signing_config_arn": signing.get("CodeSigningConfigArn"),
        "reserved_concurrent_executions": state.get(
            "reserved_concurrent_executions"
        ),
        "resource_policy": _mapping(state.get("resource_policy")),
        "event_source_mappings": _normalized_list(
            state.get("event_source_mappings")
        ),
        "tags": _mapping(state.get("tags")),
    }


def _expected_lambda_version_contract(
    logical_id: str,
    *,
    template: Mapping[str, Any],
    parameters: Mapping[str, str],
    physical_ids: Mapping[str, str],
) -> Mapping[str, Any]:
    function_logical_id = VERSION_RESOURCE_BINDINGS[logical_id][0]
    return {
        "configuration": _expected_function_configuration(
            function_logical_id=function_logical_id,
            version_logical_id=logical_id,
            template=template,
            parameters=parameters,
            physical_ids=physical_ids,
        ),
        "resource_policy": {"present": False},
    }


def _observed_lambda_version_contract(
    state: Mapping[str, Any],
) -> Mapping[str, Any]:
    return {
        "configuration": _observed_function_configuration(
            _mapping(state.get("configuration"))
        ),
        "resource_policy": _mapping(state.get("resource_policy")),
    }


def _expected_alias_contract(
    logical_id: str,
    *,
    template: Mapping[str, Any],
    parameters: Mapping[str, str],
    physical_ids: Mapping[str, str],
) -> Mapping[str, Any]:
    properties = _resolved_resource_properties(
        logical_id,
        template=template,
        parameters=parameters,
        physical_ids=physical_ids,
    )
    alias_name = _required_text(properties.get("Name"))
    function_name = _required_text(properties.get("FunctionName"))
    routing = _mapping(properties.get("RoutingConfig", {}))
    weights = _mapping(routing.get("AdditionalVersionWeights", {}))
    return {
        "alias": {
            "alias_arn": (
                f"arn:aws:lambda:{REGION}:{AUTHORITY_ACCOUNT_ID}:"
                f"function:{function_name}:{alias_name}"
            ),
            "name": alias_name,
            "function_version": properties.get("FunctionVersion"),
            "description": properties.get("Description", ""),
            "additional_version_weights": dict(sorted(weights.items())),
        },
        "resource_policy": {"present": False},
    }


def _observed_alias_contract(state: Mapping[str, Any]) -> Mapping[str, Any]:
    alias = _mapping(state.get("alias"))
    routing = _mapping(alias.get("RoutingConfig", {}))
    weights = _mapping(routing.get("AdditionalVersionWeights", {}))
    return {
        "alias": {
            "alias_arn": alias.get("AliasArn"),
            "name": alias.get("Name"),
            "function_version": alias.get("FunctionVersion"),
            "description": alias.get("Description", ""),
            "additional_version_weights": dict(sorted(weights.items())),
        },
        "resource_policy": _mapping(state.get("resource_policy")),
    }


def _expected_event_invoke_contract(
    logical_id: str,
    *,
    template: Mapping[str, Any],
    parameters: Mapping[str, str],
    physical_ids: Mapping[str, str],
) -> Mapping[str, Any]:
    properties = _resolved_resource_properties(
        logical_id,
        template=template,
        parameters=parameters,
        physical_ids=physical_ids,
    )
    function_name = _required_text(properties.get("FunctionName"))
    qualifier = _required_text(properties.get("Qualifier"))
    destinations = _mapping(properties.get("DestinationConfig", {}))
    return {
        "function_arn": (
            f"arn:aws:lambda:{REGION}:{AUTHORITY_ACCOUNT_ID}:"
            f"function:{function_name}:{qualifier}"
        ),
        "maximum_retry_attempts": properties.get("MaximumRetryAttempts"),
        "maximum_event_age_in_seconds": properties.get(
            "MaximumEventAgeInSeconds"
        ),
        "destination_config": {
            key: _mapping(value).get("Destination")
            for key, value in sorted(destinations.items())
            if _mapping(value).get("Destination") is not None
        },
    }


def _observed_event_invoke_contract(
    state: Mapping[str, Any],
) -> Mapping[str, Any]:
    config = _mapping(state.get("event_invoke_config"))
    destinations = _mapping(config.get("DestinationConfig", {}))
    return {
        "function_arn": config.get("FunctionArn"),
        "maximum_retry_attempts": config.get("MaximumRetryAttempts"),
        "maximum_event_age_in_seconds": config.get(
            "MaximumEventAgeInSeconds"
        ),
        "destination_config": {
            key: _mapping(value).get("Destination")
            for key, value in sorted(destinations.items())
            if _mapping(value).get("Destination") is not None
        },
    }


def _expected_code_signing_contract(
    properties: Mapping[str, Any],
    *,
    physical_ids: Mapping[str, str],
) -> Mapping[str, Any]:
    arn = _required_text(physical_ids.get("RepairCodeSigningConfig"))
    match = _CODE_SIGNING_ARN_RE.fullmatch(arn)
    if match is None:
        _fail("PHYSICAL_RESOURCE_BINDING_INVALID")
    return {
        "code_signing_config_id": match.group("id"),
        "code_signing_config_arn": arn,
        "description": properties.get("Description", ""),
        "allowed_publishers": _private_json(
            properties.get("AllowedPublishers")
        ),
        "code_signing_policies": _private_json(
            properties.get("CodeSigningPolicies")
        ),
        "tags": _tag_map_from_template(properties.get("Tags", [])),
    }


def _observed_code_signing_contract(
    state: Mapping[str, Any],
) -> Mapping[str, Any]:
    config = _mapping(state.get("code_signing_config"))
    return {
        "code_signing_config_id": config.get("CodeSigningConfigId"),
        "code_signing_config_arn": config.get("CodeSigningConfigArn"),
        "description": config.get("Description", ""),
        "allowed_publishers": config.get("AllowedPublishers"),
        "code_signing_policies": config.get("CodeSigningPolicies"),
        "tags": _mapping(state.get("tags")),
    }


def _optional_mapping_contract(value: Any) -> Mapping[str, Any] | None:
    if value in (None, {}):
        return None
    return _private_json(_mapping(value))


def _expected_provisioned_throughput(
    properties: Mapping[str, Any],
) -> Mapping[str, Any]:
    if properties.get("BillingMode") == "PAY_PER_REQUEST":
        return {
            "read_capacity_units": 0,
            "write_capacity_units": 0,
        }
    throughput = _mapping(properties.get("ProvisionedThroughput"))
    return {
        "read_capacity_units": throughput.get("ReadCapacityUnits"),
        "write_capacity_units": throughput.get("WriteCapacityUnits"),
    }


def _observed_provisioned_throughput(
    table: Mapping[str, Any],
) -> Mapping[str, Any]:
    throughput = _mapping(table.get("ProvisionedThroughput"))
    return {
        "read_capacity_units": throughput.get("ReadCapacityUnits"),
        "write_capacity_units": throughput.get("WriteCapacityUnits"),
    }


def _expected_warm_throughput(
    properties: Mapping[str, Any],
) -> Mapping[str, Any] | None:
    value = properties.get("WarmThroughput")
    if value in (None, {}):
        return None
    throughput = _mapping(value)
    return {
        "read_units_per_second": throughput.get("ReadUnitsPerSecond"),
        "write_units_per_second": throughput.get("WriteUnitsPerSecond"),
        "status": "ACTIVE",
    }


def _observed_warm_throughput(
    table: Mapping[str, Any],
) -> Mapping[str, Any] | None:
    value = table.get("WarmThroughput")
    if value in (None, {}):
        return None
    throughput = _mapping(value)
    return {
        "read_units_per_second": throughput.get("ReadUnitsPerSecond"),
        "write_units_per_second": throughput.get("WriteUnitsPerSecond"),
        "status": throughput.get("Status"),
    }


def _expected_dynamodb_contract(
    properties: Mapping[str, Any],
    *,
    physical_ids: Mapping[str, str],
) -> Mapping[str, Any]:
    table_name = _required_text(properties.get("TableName"))
    table_arn = (
        f"arn:aws:dynamodb:{REGION}:{AUTHORITY_ACCOUNT_ID}:"
        f"table/{table_name}"
    )
    pitr = _mapping(properties.get("PointInTimeRecoverySpecification"))
    sse = _mapping(properties.get("SSESpecification"))
    resource_policy = _mapping(properties.get("ResourcePolicy"))
    return {
        "table_name": table_name,
        "table_arn": table_arn,
        "table_status": "ACTIVE",
        "billing_mode": properties.get("BillingMode"),
        "provisioned_throughput": _expected_provisioned_throughput(
            properties
        ),
        "on_demand_throughput": _optional_mapping_contract(
            properties.get("OnDemandThroughput")
        ),
        "warm_throughput": _expected_warm_throughput(properties),
        "attribute_definitions": _normalized_list(
            properties.get("AttributeDefinitions")
        ),
        "key_schema": _normalized_list(properties.get("KeySchema")),
        "deletion_protection_enabled": properties.get(
            "DeletionProtectionEnabled", False
        ),
        "sse": {
            "status": "ENABLED" if sse.get("SSEEnabled") is True else "DISABLED",
            "sse_type": sse.get("SSEType"),
            "kms_master_key_arn": sse.get("KMSMasterKeyId"),
        },
        "point_in_time_recovery": {
            "continuous_backups_status": "ENABLED",
            "point_in_time_recovery_status": (
                "ENABLED"
                if pitr.get("PointInTimeRecoveryEnabled") is True
                else "DISABLED"
            ),
            "recovery_period_in_days": pitr.get("RecoveryPeriodInDays"),
        },
        "time_to_live_status": "DISABLED",
        "table_class": properties.get("TableClass", "STANDARD"),
        "resource_policy": {
            "present": True,
            "policy": _normalized_policy(
                resource_policy.get("PolicyDocument")
            ),
        },
        "tags": _tag_map_from_template(properties.get("Tags", [])),
        "secondary_indexes": {
            "local": _normalized_list(
                properties.get("LocalSecondaryIndexes", [])
            ),
            "global": _normalized_list(
                properties.get("GlobalSecondaryIndexes", [])
            ),
        },
        "stream_specification": properties.get("StreamSpecification"),
        "latest_stream_label": None,
        "latest_stream_arn": None,
        "multi_region_consistency": properties.get(
            "MultiRegionConsistency"
        ),
        "global_table_witnesses": _normalized_list(
            properties.get("GlobalTableWitnesses", [])
        ),
        "replicas": [],
        "restore_summary": None,
        "archival_summary": None,
    }


def _observed_dynamodb_contract(
    state: Mapping[str, Any],
) -> Mapping[str, Any]:
    table = _mapping(state.get("table"))
    billing = _mapping(table.get("BillingModeSummary"))
    sse = _mapping(table.get("SSEDescription"))
    backups = _mapping(state.get("continuous_backups"))
    backup_description = _mapping(
        backups.get("ContinuousBackupsDescription")
    )
    recovery = _mapping(
        backup_description.get("PointInTimeRecoveryDescription")
    )
    ttl = _mapping(state.get("time_to_live"))
    ttl_description = _mapping(ttl.get("TimeToLiveDescription"))
    table_class = _mapping(table.get("TableClassSummary"))
    policy = _mapping(state.get("resource_policy"))
    normalized_policy: dict[str, Any] = {"present": policy.get("present")}
    if policy.get("present") is True:
        normalized_policy["policy"] = _normalized_policy(policy.get("policy"))
    return {
        "table_name": table.get("TableName"),
        "table_arn": table.get("TableArn"),
        "table_status": table.get("TableStatus"),
        "billing_mode": billing.get("BillingMode"),
        "provisioned_throughput": _observed_provisioned_throughput(
            table
        ),
        "on_demand_throughput": _optional_mapping_contract(
            table.get("OnDemandThroughput")
        ),
        "warm_throughput": _observed_warm_throughput(table),
        "attribute_definitions": _normalized_list(
            table.get("AttributeDefinitions")
        ),
        "key_schema": _normalized_list(table.get("KeySchema")),
        "deletion_protection_enabled": table.get(
            "DeletionProtectionEnabled", False
        ),
        "sse": {
            "status": sse.get("Status"),
            "sse_type": sse.get("SSEType"),
            "kms_master_key_arn": sse.get("KMSMasterKeyArn"),
        },
        "point_in_time_recovery": {
            "continuous_backups_status": backup_description.get(
                "ContinuousBackupsStatus"
            ),
            "point_in_time_recovery_status": recovery.get(
                "PointInTimeRecoveryStatus"
            ),
            "recovery_period_in_days": recovery.get(
                "RecoveryPeriodInDays"
            ),
        },
        "time_to_live_status": ttl_description.get("TimeToLiveStatus"),
        "table_class": table_class.get("TableClass", "STANDARD"),
        "resource_policy": normalized_policy,
        "tags": _tag_map_from_provider(state.get("tags")),
        "secondary_indexes": {
            "local": _normalized_list(
                table.get("LocalSecondaryIndexes", [])
            ),
            "global": _normalized_list(
                table.get("GlobalSecondaryIndexes", [])
            ),
        },
        "stream_specification": table.get("StreamSpecification"),
        "latest_stream_label": table.get("LatestStreamLabel"),
        "latest_stream_arn": table.get("LatestStreamArn"),
        "multi_region_consistency": table.get(
            "MultiRegionConsistency"
        ),
        "global_table_witnesses": _normalized_list(
            table.get("GlobalTableWitnesses", [])
        ),
        "replicas": _normalized_list(table.get("Replicas", [])),
        "restore_summary": _optional_mapping_contract(
            table.get("RestoreSummary")
        ),
        "archival_summary": _optional_mapping_contract(
            table.get("ArchivalSummary")
        ),
    }


def _expected_kms_key_contract(
    properties: Mapping[str, Any],
    *,
    physical_ids: Mapping[str, str],
) -> Mapping[str, Any]:
    key_id = _required_text(physical_ids.get("RepairLedgerKey"))
    key_spec = properties.get("KeySpec", "SYMMETRIC_DEFAULT")
    key_usage = properties.get("KeyUsage", "ENCRYPT_DECRYPT")
    if key_spec != "SYMMETRIC_DEFAULT" or key_usage != "ENCRYPT_DECRYPT":
        _fail("REVIEWED_TEMPLATE_INVALID")
    return {
        "aws_account_id": AUTHORITY_ACCOUNT_ID,
        "key_id": key_id,
        "arn": f"arn:aws:kms:{REGION}:{AUTHORITY_ACCOUNT_ID}:key/{key_id}",
        "enabled": properties.get("Enabled", True),
        "description": properties.get("Description", ""),
        "key_usage": key_usage,
        "key_state": "Enabled",
        "origin": "AWS_KMS",
        "key_manager": "CUSTOMER",
        "customer_master_key_spec": key_spec,
        "key_spec": key_spec,
        "encryption_algorithms": ["SYMMETRIC_DEFAULT"],
        "signing_algorithms": [],
        "mac_algorithms": [],
        "custom_key_store_id": None,
        "cloud_hsm_cluster_id": None,
        "expiration_model": None,
        "multi_region": properties.get("MultiRegion", False),
        "multi_region_configuration": None,
        "xks_key_configuration": None,
        "rotation_enabled": properties.get("EnableKeyRotation", False),
        "rotation_period_in_days": properties.get(
            "RotationPeriodInDays", 365
        ),
        "on_demand_rotation_start_date": None,
        "key_policy": _normalized_policy(properties.get("KeyPolicy")),
        "tags": _tag_map_from_template(properties.get("Tags", [])),
    }


def _observed_kms_key_contract(
    state: Mapping[str, Any],
) -> Mapping[str, Any]:
    metadata = _mapping(state.get("key_metadata"))
    rotation = _mapping(state.get("rotation"))
    return {
        "aws_account_id": metadata.get("AWSAccountId"),
        "key_id": metadata.get("KeyId"),
        "arn": metadata.get("Arn"),
        "enabled": metadata.get("Enabled"),
        "description": metadata.get("Description", ""),
        "key_usage": metadata.get("KeyUsage"),
        "key_state": metadata.get("KeyState"),
        "origin": metadata.get("Origin"),
        "key_manager": metadata.get("KeyManager"),
        "customer_master_key_spec": metadata.get(
            "CustomerMasterKeySpec"
        ),
        "key_spec": metadata.get("KeySpec"),
        "encryption_algorithms": sorted(
            _required_text(item)
            for item in _items(metadata.get("EncryptionAlgorithms", []))
        ),
        "signing_algorithms": sorted(
            _required_text(item)
            for item in _items(metadata.get("SigningAlgorithms", []))
        ),
        "mac_algorithms": sorted(
            _required_text(item)
            for item in _items(metadata.get("MacAlgorithms", []))
        ),
        "custom_key_store_id": metadata.get("CustomKeyStoreId"),
        "cloud_hsm_cluster_id": metadata.get("CloudHsmClusterId"),
        "expiration_model": metadata.get("ExpirationModel"),
        "multi_region": metadata.get("MultiRegion"),
        "multi_region_configuration": _optional_mapping_contract(
            metadata.get("MultiRegionConfiguration")
        ),
        "xks_key_configuration": _optional_mapping_contract(
            metadata.get("XksKeyConfiguration")
        ),
        "rotation_enabled": rotation.get("KeyRotationEnabled"),
        "rotation_period_in_days": rotation.get(
            "RotationPeriodInDays", 365
        ),
        "on_demand_rotation_start_date": rotation.get(
            "OnDemandRotationStartDate"
        ),
        "key_policy": _normalized_policy(state.get("key_policy")),
        "tags": _tag_map_from_provider(
            state.get("tags"),
            key_name="TagKey",
            value_name="TagValue",
        ),
    }


def _expected_kms_alias_contract(
    properties: Mapping[str, Any],
    *,
    physical_ids: Mapping[str, str],
) -> Mapping[str, Any]:
    alias_name = _required_text(properties.get("AliasName"))
    return {
        "alias_name": alias_name,
        "alias_arn": (
            f"arn:aws:kms:{REGION}:{AUTHORITY_ACCOUNT_ID}:{alias_name}"
        ),
        "target_key_id": physical_ids.get("RepairLedgerKey"),
    }


def _observed_kms_alias_contract(
    state: Mapping[str, Any],
) -> Mapping[str, Any]:
    alias = _mapping(state.get("alias"))
    return {
        "alias_name": alias.get("AliasName"),
        "alias_arn": alias.get("AliasArn"),
        "target_key_id": alias.get("TargetKeyId"),
    }


def _expected_log_group_contract(
    properties: Mapping[str, Any],
) -> Mapping[str, Any]:
    name = _required_text(properties.get("LogGroupName"))
    return {
        "log_group_name": name,
        "arn": (
            f"arn:aws:logs:{REGION}:{AUTHORITY_ACCOUNT_ID}:"
            f"log-group:{name}:*"
        ),
        "log_group_arn": (
            f"arn:aws:logs:{REGION}:{AUTHORITY_ACCOUNT_ID}:"
            f"log-group:{name}"
        ),
        "retention_in_days": properties.get("RetentionInDays"),
        "kms_key_id": properties.get("KmsKeyId"),
        "log_group_class": properties.get("LogGroupClass", "STANDARD"),
        "deletion_protection_enabled": properties.get(
            "DeletionProtectionEnabled", False
        ),
        "data_protection_status": (
            "ACTIVATED"
            if properties.get("DataProtectionPolicy") is not None
            else "DISABLED"
        ),
        "inherited_properties": [],
        "tags": _tag_map_from_template(properties.get("Tags", [])),
    }


def _observed_log_group_contract(
    state: Mapping[str, Any],
) -> Mapping[str, Any]:
    group = _mapping(state.get("log_group"))
    data_protection_status = group.get("dataProtectionStatus")
    if data_protection_status is None:
        data_protection_status = "DISABLED"
    return {
        "log_group_name": group.get("logGroupName"),
        "arn": group.get("arn"),
        "log_group_arn": group.get("logGroupArn"),
        "retention_in_days": group.get("retentionInDays"),
        "kms_key_id": group.get("kmsKeyId"),
        "log_group_class": group.get("logGroupClass", "STANDARD"),
        "deletion_protection_enabled": group.get(
            "deletionProtectionEnabled", False
        ),
        "data_protection_status": data_protection_status,
        "inherited_properties": sorted(
            _required_text(item)
            for item in _items(group.get("inheritedProperties", []))
        ),
        "tags": _mapping(state.get("tags")),
    }


def _expected_resource_contracts(
    *,
    reviewed_template_bytes: bytes,
    pep_parameter_handoff: Mapping[str, Any],
    physical_ids: Mapping[str, str],
) -> dict[str, Mapping[str, Any]]:
    template = _load_reviewed_template(reviewed_template_bytes)
    parameters = _parameter_values(
        pep_parameter_handoff=pep_parameter_handoff,
        reviewed_template_bytes=reviewed_template_bytes,
    )
    contracts: dict[str, Mapping[str, Any]] = {}
    for logical_id in RESOURCE_LOGICAL_IDS:
        properties = _resolved_resource_properties(
            logical_id,
            template=template,
            parameters=parameters,
            physical_ids=physical_ids,
        )
        if logical_id in ROLE_NAMES:
            contract = _expected_role_contract(properties)
        elif logical_id in FUNCTION_NAMES:
            contract = _expected_lambda_function_contract(
                logical_id,
                template=template,
                parameters=parameters,
                physical_ids=physical_ids,
            )
        elif logical_id in VERSION_FUNCTIONS:
            contract = _expected_lambda_version_contract(
                logical_id,
                template=template,
                parameters=parameters,
                physical_ids=physical_ids,
            )
        elif logical_id in ALIAS_BINDINGS:
            contract = _expected_alias_contract(
                logical_id,
                template=template,
                parameters=parameters,
                physical_ids=physical_ids,
            )
        elif logical_id in EVENT_INVOKE_BINDINGS:
            contract = _expected_event_invoke_contract(
                logical_id,
                template=template,
                parameters=parameters,
                physical_ids=physical_ids,
            )
        elif logical_id == "RepairCodeSigningConfig":
            contract = _expected_code_signing_contract(
                properties, physical_ids=physical_ids
            )
        elif logical_id == "RepairLedger":
            contract = _expected_dynamodb_contract(
                properties, physical_ids=physical_ids
            )
        elif logical_id == "RepairLedgerKey":
            contract = _expected_kms_key_contract(
                properties, physical_ids=physical_ids
            )
        elif logical_id == "RepairLedgerKeyAlias":
            contract = _expected_kms_alias_contract(
                properties, physical_ids=physical_ids
            )
        elif logical_id in LOG_GROUP_NAMES:
            contract = _expected_log_group_contract(properties)
        else:
            _fail("REVIEWED_TEMPLATE_INVALID")
        contracts[logical_id] = _private_json(contract)
    return contracts


def _observed_resource_contract(
    logical_id: str,
    state: Mapping[str, Any],
) -> Mapping[str, Any]:
    if logical_id in ROLE_NAMES:
        return _observed_role_contract(state)
    if logical_id in FUNCTION_NAMES:
        return _observed_lambda_function_contract(state)
    if logical_id in VERSION_FUNCTIONS:
        return _observed_lambda_version_contract(state)
    if logical_id in ALIAS_BINDINGS:
        return _observed_alias_contract(state)
    if logical_id in EVENT_INVOKE_BINDINGS:
        return _observed_event_invoke_contract(state)
    if logical_id == "RepairCodeSigningConfig":
        return _observed_code_signing_contract(state)
    if logical_id == "RepairLedger":
        return _observed_dynamodb_contract(state)
    if logical_id == "RepairLedgerKey":
        return _observed_kms_key_contract(state)
    if logical_id == "RepairLedgerKeyAlias":
        return _observed_kms_alias_contract(state)
    if logical_id in LOG_GROUP_NAMES:
        return _observed_log_group_contract(state)
    _fail("PHYSICAL_RESOURCE_BINDING_INVALID")


def _phase_b_resource_hashes(
    phase_b_execution_receipt: Mapping[str, Any],
) -> tuple[str, dict[str, str]]:
    if (
        phase_b_execution_receipt.get("artifact_type")
        != PHASE_B_EXECUTION_ARTIFACT_TYPE
        or phase_b_execution_receipt.get("schema_version") != 1
        or phase_b_execution_receipt.get("work_package") != WORK_PACKAGE
    ):
        _fail("PHASE_B_EXECUTION_RECEIPT_INVALID")
    source_commit = phase_b_execution_receipt.get("source_commit")
    if (
        not isinstance(source_commit, str)
        or _COMMIT_RE.fullmatch(source_commit) is None
    ):
        _fail("PHASE_B_EXECUTION_RECEIPT_INVALID")
    resources = phase_b_execution_receipt.get("stack_resources")
    if not isinstance(resources, list) or len(resources) != 23:
        _fail("PHASE_B_EXECUTION_RECEIPT_INVALID")
    if phase_b_execution_receipt.get("stack_resources_sha256") != canonical_digest(
        resources
    ):
        _fail("PHASE_B_EXECUTION_RECEIPT_INVALID")
    observed: dict[str, str] = {}
    for item in resources:
        if not isinstance(item, Mapping) or set(item) != {
            "logical_resource_id",
            "resource_type",
            "physical_resource_id_sha256",
        }:
            _fail("PHASE_B_EXECUTION_RECEIPT_INVALID")
        logical_id = item.get("logical_resource_id")
        resource_type = item.get("resource_type")
        digest = item.get("physical_resource_id_sha256")
        if (
            not isinstance(logical_id, str)
            or logical_id in observed
            or resource_type != EXPECTED_RESOURCE_TYPES.get(logical_id)
            or not isinstance(digest, str)
            or _DIGEST_RE.fullmatch(digest) is None
        ):
            _fail("PHASE_B_EXECUTION_RECEIPT_INVALID")
        observed[logical_id] = digest
    if tuple(observed) != RESOURCE_LOGICAL_IDS:
        _fail("PHASE_B_EXECUTION_RECEIPT_INVALID")
    return source_commit, observed


def _validate_physical_ids(
    physical_resource_ids: Mapping[str, Any],
    expected_hashes: Mapping[str, str],
) -> dict[str, str]:
    if set(physical_resource_ids) != set(RESOURCE_LOGICAL_IDS):
        _fail("PHYSICAL_RESOURCE_BINDING_INVALID")
    result: dict[str, str] = {}
    seen_values: set[str] = set()
    for logical_id in RESOURCE_LOGICAL_IDS:
        value = physical_resource_ids.get(logical_id)
        if (
            not isinstance(value, str)
            or not value
            or len(value) > 2048
            or value in seen_values
            or _text_digest(value) != expected_hashes[logical_id]
        ):
            _fail("PHYSICAL_RESOURCE_BINDING_INVALID")
        seen_values.add(value)
        result[logical_id] = value

    for logical_id, role_name in ROLE_NAMES.items():
        if result[logical_id] != role_name:
            _fail("PHYSICAL_RESOURCE_BINDING_INVALID")
    for logical_id, function_name in FUNCTION_NAMES.items():
        if result[logical_id] != function_name:
            _fail("PHYSICAL_RESOURCE_BINDING_INVALID")
    for logical_id, function_name in VERSION_FUNCTIONS.items():
        match = _FUNCTION_VERSION_ARN_RE.fullmatch(result[logical_id])
        if match is None or match.group("name") != function_name:
            _fail("PHYSICAL_RESOURCE_BINDING_INVALID")
    for logical_id, (function_name, alias_name) in ALIAS_BINDINGS.items():
        expected_arn = (
            f"arn:aws:lambda:{REGION}:{AUTHORITY_ACCOUNT_ID}:"
            f"function:{function_name}:{alias_name}"
        )
        if result[logical_id] != expected_arn:
            _fail("PHYSICAL_RESOURCE_BINDING_INVALID")
    if (
        _CODE_SIGNING_ARN_RE.fullmatch(result["RepairCodeSigningConfig"]) is None
        or result["RepairLedger"] != TABLE_NAME
        or _KMS_KEY_ID_RE.fullmatch(result["RepairLedgerKey"]) is None
        or result["RepairLedgerKeyAlias"] != KMS_ALIAS_NAME
    ):
        _fail("PHYSICAL_RESOURCE_BINDING_INVALID")
    for logical_id, log_group_name in LOG_GROUP_NAMES.items():
        if result[logical_id] != log_group_name:
            _fail("PHYSICAL_RESOURCE_BINDING_INVALID")
    return result


def _resource_state(
    logical_id: str,
    physical_ids: Mapping[str, str],
    *,
    iam_client: Any,
    lambda_client: Any,
    dynamodb_client: Any,
    kms_client: Any,
    logs_client: Any,
) -> Mapping[str, Any]:
    if logical_id in ROLE_NAMES:
        return _iam_role_state(iam_client, role_name=ROLE_NAMES[logical_id])
    code_signing_arn = physical_ids["RepairCodeSigningConfig"]
    if logical_id in FUNCTION_NAMES:
        return _lambda_function_state(
            lambda_client,
            function_name=FUNCTION_NAMES[logical_id],
            code_signing_config_arn=code_signing_arn,
        )
    if logical_id in VERSION_FUNCTIONS:
        version_arn = physical_ids[logical_id]
        match = _FUNCTION_VERSION_ARN_RE.fullmatch(version_arn)
        assert match is not None
        return _lambda_version_state(
            lambda_client,
            function_name=VERSION_FUNCTIONS[logical_id],
            version_arn=version_arn,
            version=match.group("version"),
        )
    if logical_id in ALIAS_BINDINGS:
        function_name, alias_name = ALIAS_BINDINGS[logical_id]
        return _lambda_alias_state(
            lambda_client,
            function_name=function_name,
            alias_name=alias_name,
            alias_arn=physical_ids[logical_id],
        )
    if logical_id in EVENT_INVOKE_BINDINGS:
        function_name, alias_name = EVENT_INVOKE_BINDINGS[logical_id]
        return _event_invoke_state(
            lambda_client,
            function_name=function_name,
            alias_name=alias_name,
        )
    if logical_id == "RepairCodeSigningConfig":
        return _code_signing_state(lambda_client, config_arn=code_signing_arn)
    if logical_id == "RepairLedger":
        return _dynamodb_state(dynamodb_client, table_name=TABLE_NAME)
    if logical_id == "RepairLedgerKey":
        return _kms_key_state(kms_client, key_id=physical_ids[logical_id])
    if logical_id == "RepairLedgerKeyAlias":
        return _kms_alias_state(
            kms_client,
            key_id=physical_ids["RepairLedgerKey"],
            alias_name=KMS_ALIAS_NAME,
        )
    if logical_id in LOG_GROUP_NAMES:
        return _log_group_state(
            logs_client,
            log_group_name=LOG_GROUP_NAMES[logical_id],
        )
    _fail("PHYSICAL_RESOURCE_BINDING_INVALID")


def _collect_snapshot(
    *,
    physical_ids: Mapping[str, str],
    expected_hashes: Mapping[str, str],
    expected_contracts: Mapping[str, Mapping[str, Any]],
    iam_client: Any,
    lambda_client: Any,
    dynamodb_client: Any,
    kms_client: Any,
    logs_client: Any,
) -> list[dict[str, str]]:
    resources: list[dict[str, str]] = []
    for logical_id in RESOURCE_LOGICAL_IDS:
        state = _resource_state(
            logical_id,
            physical_ids,
            iam_client=iam_client,
            lambda_client=lambda_client,
            dynamodb_client=dynamodb_client,
            kms_client=kms_client,
            logs_client=logs_client,
        )
        expected_contract = expected_contracts.get(logical_id)
        if not isinstance(expected_contract, Mapping):
            _fail("REVIEWED_TEMPLATE_INVALID")
        observed_contract = _observed_resource_contract(logical_id, state)
        expected_digest = canonical_digest(expected_contract)
        observed_digest = canonical_digest(observed_contract)
        if expected_digest != observed_digest or expected_contract != observed_contract:
            _fail("EFFECTIVE_STATE_CONFORMANCE_DRIFT")
        resources.append(
            {
                "logical_resource_id": logical_id,
                "resource_type": EXPECTED_RESOURCE_TYPES[logical_id],
                "physical_resource_id_sha256": expected_hashes[logical_id],
                "expected_state_sha256": expected_digest,
                "observed_state_sha256": observed_digest,
                "provider_state_sha256": observed_digest,
                "conformance_status": "EXACT_TEMPLATE_MATCH",
            }
        )
    return resources


def _utc_text(value: datetime) -> str:
    if value.utcoffset() is None:
        _fail("EFFECTIVE_STATE_RECEIPT_INVALID")
    return (
        value.astimezone(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    )


def collect_effective_state_read_only(
    *,
    phase_b_execution_receipt: Mapping[str, Any],
    physical_resource_ids: Mapping[str, Any],
    reviewed_template_bytes: bytes,
    pep_parameter_handoff: Mapping[str, Any],
    iam_client: Any,
    lambda_client: Any,
    dynamodb_client: Any,
    kms_client: Any,
    logs_client: Any,
    evaluated_at: datetime | None = None,
) -> dict[str, Any]:
    """Collect and bind two identical direct-provider snapshots.

    ``physical_resource_ids`` is private input and is never copied into the
    result.  It must contain the exact 23 values whose hashes already appear in
    the Phase B execution receipt.
    """

    source_commit, expected_hashes = _phase_b_resource_hashes(phase_b_execution_receipt)
    physical_ids = _validate_physical_ids(physical_resource_ids, expected_hashes)
    expected_contracts = _expected_resource_contracts(
        reviewed_template_bytes=reviewed_template_bytes,
        pep_parameter_handoff=pep_parameter_handoff,
        physical_ids=physical_ids,
    )
    if pep_parameter_handoff.get("source_commit") != source_commit:
        _fail("PEP_PARAMETER_HANDOFF_INVALID")
    first = _collect_snapshot(
        physical_ids=physical_ids,
        expected_hashes=expected_hashes,
        expected_contracts=expected_contracts,
        iam_client=iam_client,
        lambda_client=lambda_client,
        dynamodb_client=dynamodb_client,
        kms_client=kms_client,
        logs_client=logs_client,
    )
    second = _collect_snapshot(
        physical_ids=physical_ids,
        expected_hashes=expected_hashes,
        expected_contracts=expected_contracts,
        iam_client=iam_client,
        lambda_client=lambda_client,
        dynamodb_client=dynamodb_client,
        kms_client=kms_client,
        logs_client=logs_client,
    )
    first_digest = canonical_digest(first)
    second_digest = canonical_digest(second)
    if first_digest != second_digest or first != second:
        _fail("EFFECTIVE_STATE_CHANGED_DURING_READBACK")
    expected_summary = [
        {
            "logical_resource_id": item["logical_resource_id"],
            "state_sha256": item["expected_state_sha256"],
        }
        for item in second
    ]
    observed_summary = [
        {
            "logical_resource_id": item["logical_resource_id"],
            "state_sha256": item["observed_state_sha256"],
        }
        for item in second
    ]
    expected_summary_digest = canonical_digest(expected_summary)
    observed_summary_digest = canonical_digest(observed_summary)
    if expected_summary_digest != observed_summary_digest:
        _fail("EFFECTIVE_STATE_CONFORMANCE_DRIFT")
    provider_state = {
        "resource_count": 23,
        "observed_resources_sha256": observed_summary_digest,
        "conformance_status": "EXACT_TEMPLATE_MATCH",
    }
    result: dict[str, Any] = {
        "artifact_type": ARTIFACT_TYPE,
        "schema_version": 1,
        "work_package": WORK_PACKAGE,
        "phase": PHASE,
        "source_commit": source_commit,
        "phase_b_execution_receipt_sha256": canonical_digest(phase_b_execution_receipt),
        "reviewed_template_sha256": sha256(reviewed_template_bytes).hexdigest(),
        "pep_parameter_handoff_sha256": canonical_digest(
            pep_parameter_handoff
        ),
        "resource_count": 23,
        "resources": second,
        "resources_sha256": second_digest,
        "first_snapshot_sha256": first_digest,
        "second_snapshot_sha256": second_digest,
        "expected_resources_sha256": expected_summary_digest,
        "observed_resources_sha256": observed_summary_digest,
        "conformance_status": "EXACT_TEMPLATE_MATCH",
        "provider_state_sha256": canonical_digest(provider_state),
        "evaluated_at": _utc_text(evaluated_at or datetime.now(UTC)),
        "evidence_status": "DIRECT_PROVIDER_EFFECTIVE_STATE_VERIFIED",
        "authority_status": ("READ_ONLY_SANITIZED_EVIDENCE_NOT_EXECUTION_AUTHORITY"),
        "production_status": PRODUCTION_STATUS,
    }
    validate_effective_state_receipt(result)
    return result


def validate_effective_state_receipt(receipt: Mapping[str, Any]) -> None:
    """Validate deterministic ordering and every digest in a receipt."""

    required = {
        "artifact_type",
        "schema_version",
        "work_package",
        "phase",
        "source_commit",
        "phase_b_execution_receipt_sha256",
        "reviewed_template_sha256",
        "pep_parameter_handoff_sha256",
        "resource_count",
        "resources",
        "resources_sha256",
        "first_snapshot_sha256",
        "second_snapshot_sha256",
        "expected_resources_sha256",
        "observed_resources_sha256",
        "conformance_status",
        "provider_state_sha256",
        "evaluated_at",
        "evidence_status",
        "authority_status",
        "production_status",
    }
    if set(receipt) != required:
        _fail("EFFECTIVE_STATE_RECEIPT_INVALID")
    source_commit = receipt.get("source_commit")
    phase_b_digest = receipt.get("phase_b_execution_receipt_sha256")
    template_digest = receipt.get("reviewed_template_sha256")
    handoff_digest = receipt.get("pep_parameter_handoff_sha256")
    resources = receipt.get("resources")
    if (
        receipt.get("artifact_type") != ARTIFACT_TYPE
        or receipt.get("schema_version") != 1
        or receipt.get("work_package") != WORK_PACKAGE
        or receipt.get("phase") != PHASE
        or not isinstance(source_commit, str)
        or _COMMIT_RE.fullmatch(source_commit) is None
        or not isinstance(phase_b_digest, str)
        or _DIGEST_RE.fullmatch(phase_b_digest) is None
        or not isinstance(template_digest, str)
        or _DIGEST_RE.fullmatch(template_digest) is None
        or not isinstance(handoff_digest, str)
        or _DIGEST_RE.fullmatch(handoff_digest) is None
        or receipt.get("resource_count") != 23
        or not isinstance(resources, list)
        or len(resources) != 23
        or receipt.get("evidence_status") != "DIRECT_PROVIDER_EFFECTIVE_STATE_VERIFIED"
        or receipt.get("authority_status")
        != "READ_ONLY_SANITIZED_EVIDENCE_NOT_EXECUTION_AUTHORITY"
        or receipt.get("production_status") != PRODUCTION_STATUS
    ):
        _fail("EFFECTIVE_STATE_RECEIPT_INVALID")
    for logical_id, item in zip(RESOURCE_LOGICAL_IDS, resources):
        if (
            not isinstance(item, Mapping)
            or set(item)
            != {
                "logical_resource_id",
                "resource_type",
                "physical_resource_id_sha256",
                "expected_state_sha256",
                "observed_state_sha256",
                "provider_state_sha256",
                "conformance_status",
            }
            or item.get("logical_resource_id") != logical_id
            or item.get("resource_type") != EXPECTED_RESOURCE_TYPES[logical_id]
            or _DIGEST_RE.fullmatch(str(item.get("physical_resource_id_sha256")))
            is None
            or _DIGEST_RE.fullmatch(str(item.get("provider_state_sha256"))) is None
            or _DIGEST_RE.fullmatch(str(item.get("expected_state_sha256"))) is None
            or _DIGEST_RE.fullmatch(str(item.get("observed_state_sha256"))) is None
            or item.get("expected_state_sha256")
            != item.get("observed_state_sha256")
            or item.get("provider_state_sha256")
            != item.get("observed_state_sha256")
            or item.get("conformance_status") != "EXACT_TEMPLATE_MATCH"
        ):
            _fail("EFFECTIVE_STATE_RECEIPT_INVALID")
    resources_digest = canonical_digest(resources)
    expected_summary = [
        {
            "logical_resource_id": item["logical_resource_id"],
            "state_sha256": item["expected_state_sha256"],
        }
        for item in resources
    ]
    observed_summary = [
        {
            "logical_resource_id": item["logical_resource_id"],
            "state_sha256": item["observed_state_sha256"],
        }
        for item in resources
    ]
    expected_summary_digest = canonical_digest(expected_summary)
    observed_summary_digest = canonical_digest(observed_summary)
    if (
        receipt.get("resources_sha256") != resources_digest
        or receipt.get("first_snapshot_sha256") != resources_digest
        or receipt.get("second_snapshot_sha256") != resources_digest
        or receipt.get("expected_resources_sha256")
        != expected_summary_digest
        or receipt.get("observed_resources_sha256")
        != observed_summary_digest
        or expected_summary_digest != observed_summary_digest
        or receipt.get("conformance_status") != "EXACT_TEMPLATE_MATCH"
        or receipt.get("provider_state_sha256")
        != canonical_digest(
            {
                "resource_count": 23,
                "observed_resources_sha256": observed_summary_digest,
                "conformance_status": "EXACT_TEMPLATE_MATCH",
            }
        )
    ):
        _fail("EFFECTIVE_STATE_RECEIPT_INVALID")
    evaluated_at = receipt.get("evaluated_at")
    if not isinstance(evaluated_at, str) or not evaluated_at.endswith("Z"):
        _fail("EFFECTIVE_STATE_RECEIPT_INVALID")
    try:
        parsed = datetime.fromisoformat(evaluated_at[:-1] + "+00:00")
    except ValueError:
        _fail("EFFECTIVE_STATE_RECEIPT_INVALID")
    if parsed.utcoffset() is None:
        _fail("EFFECTIVE_STATE_RECEIPT_INVALID")
