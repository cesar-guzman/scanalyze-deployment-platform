"""Guarded AWS provider boundary for the GUG-365 materialization plan.

The module is inert at import time: boto3 and botocore are loaded only by
``LiveProvider.open`` after the local profile, region, and ambient-environment
gates pass.  It does not authorize a phase or a plan.  Its narrow job is to
turn an already certified GUG-365 operation into one exact SDK call (or a
bounded sequence of read calls), retain a digest-only transcript, and never
retry a mutation whose result may be ambiguous.

An injected session factory exists only for deterministic contract tests.  An
instance opened that way can never report live-provider or AWS evidence.
"""

from __future__ import annotations

import base64
from collections.abc import Callable, Mapping, Sequence
from dataclasses import asdict, dataclass, field, replace
from datetime import date, datetime, timezone
from enum import Enum
from hashlib import sha256
import json
import math
import os
import re
import time
from typing import Any
from urllib.parse import unquote

from tooling import (
    platform_authority_retirement_entrypoint_service_role_materializer as gug365,
)


AUTHORITY_ACCOUNT_ID = gug365.AUTHORITY_ACCOUNT_ID
REGION = gug365.REGION
MAX_PAGES = 50
MAX_WAIT_ATTEMPTS = 20
MAX_RESPONSE_BYTES = 8 * 1024 * 1024

_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_PROFILE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_ACCOUNT_RE = re.compile(r"^[0-9]{12}$")
_ERROR_RE = re.compile(r"^[A-Za-z][A-Za-z0-9._-]{0,127}$")
_STAGE_RE = re.compile(r"^[A-Z][A-Z0-9_]{2,127}$")
_AMBIENT_NAMES = frozenset(
    {
        "BOTO_CONFIG",
        "REQUESTS_CA_BUNDLE",
        "SSL_CERT_FILE",
        "SSL_CERT_DIR",
    }
)
_PROFILE_FORBIDDEN = frozenset(
    {
        "aws_access_key_id",
        "aws_secret_access_key",
        "aws_session_token",
        "credential_process",
        "credential_source",
        "external_id",
        "mfa_serial",
        "role_arn",
        "source_profile",
        "web_identity_token_file",
        "endpoint_url",
        "ca_bundle",
        "services",
    }
)
_PROFILE_ALLOWED = frozenset(
    {
        "cli_pager",
        "output",
        "region",
        "sso_account_id",
        "sso_region",
        "sso_role_name",
        "sso_session",
        "sso_start_url",
    }
)
_PLACEHOLDER = "<OBSERVED_TABLE_SSE_DESCRIPTION_KMS_MASTER_KEY_ARN>"
_CONCLUSIVE_NO_EFFECT_ERRORS = frozenset(
    {
        "AccessDenied",
        "AccessDeniedException",
        "CodeSigningConfigNotFoundException",
        "CodeStorageExceededException",
        "CodeVerificationFailedException",
        "EntityAlreadyExists",
        "EntityAlreadyExistsException",
        "InvalidCodeSignatureException",
        "InvalidParameterException",
        "InvalidParameterValueException",
        "InvalidRequestContentException",
        "InvalidRequestException",
        "InvalidRuntimeException",
        "InvalidZipFileException",
        "KMSAccessDeniedException",
        "MalformedPolicyDocument",
        "NoSuchEntity",
        "NoSuchEntityException",
        "PolicyNotAttachable",
        "RequestTooLargeException",
        "ResourceConflictException",
        "ResourceNotFoundException",
        "UnmodifiableEntity",
        "UnsupportedMediaTypeException",
        "ValidationError",
        "ValidationException",
    }
)


class LiveProviderError(RuntimeError):
    """Stable public-safe failure at the provider boundary."""

    def __init__(self, code: str) -> None:
        if re.fullmatch(r"[A-Z][A-Z0-9_]{2,95}", code) is None:
            code = "GUG390_LIVE_PROVIDER_BLOCKED"
        self.code = code
        super().__init__(code)


def _fail(code: str) -> None:
    raise LiveProviderError(code)


def canonical_json(value: Any) -> str:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        )
    except (TypeError, ValueError, OverflowError, RecursionError) as exc:
        raise LiveProviderError("CANONICAL_VALUE_INVALID") from exc


def canonical_digest(value: Any) -> str:
    return "sha256:" + sha256(canonical_json(value).encode("utf-8")).hexdigest()


def _snapshot(value: Any) -> Any:
    try:
        return json.loads(canonical_json(value))
    except json.JSONDecodeError as exc:  # pragma: no cover - canonical JSON
        raise LiveProviderError("CANONICAL_VALUE_INVALID") from exc


class CallKind(str, Enum):
    IDENTITY = "IDENTITY"
    READ = "READ"
    MUTATION = "MUTATION"
    WAITER = "BOUNDED_WAITER"


class Outcome(str, Enum):
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"
    AMBIGUOUS = "AMBIGUOUS"


MUTATION_ACTIONS = frozenset(
    {
        "iam:AttachRolePolicy",
        "iam:CreatePolicy",
        "iam:CreateRole",
        "iam:DetachRolePolicy",
        "iam:PutRolePermissionsBoundary",
        "lambda:CreateFunction",
        "lambda:InvokeFunction",
        "lambda:PutFunctionConcurrency",
        "lambda:PutRuntimeManagementConfig",
        "logs:CreateLogGroup",
        "logs:PutRetentionPolicy",
    }
)

_READ_METHODS: dict[str, tuple[str, str]] = {
    "sts:GetCallerIdentity": ("sts", "get_caller_identity"),
    "iam:GetPolicy": ("iam", "get_policy"),
    "iam:GetPolicyVersion": ("iam", "get_policy_version"),
    "iam:GetRole": ("iam", "get_role"),
    "iam:ListAttachedRolePolicies": ("iam", "list_attached_role_policies"),
    "iam:ListEntitiesForPolicy": ("iam", "list_entities_for_policy"),
    "iam:ListPolicyTags": ("iam", "list_policy_tags"),
    "iam:ListPolicyVersions": ("iam", "list_policy_versions"),
    "iam:ListRolePolicies": ("iam", "list_role_policies"),
    "iam:ListRoleTags": ("iam", "list_role_tags"),
    "lambda:GetCodeSigningConfig": ("lambda", "get_code_signing_config"),
    "lambda:GetFunction": ("lambda", "get_function"),
    "lambda:GetFunctionCodeSigningConfig": (
        "lambda",
        "get_function_code_signing_config",
    ),
    "lambda:GetFunctionConcurrency": ("lambda", "get_function_concurrency"),
    "lambda:GetFunctionConfiguration": (
        "lambda",
        "get_function_configuration",
    ),
    "lambda:GetPolicy": ("lambda", "get_policy"),
    "lambda:GetRuntimeManagementConfig": (
        "lambda",
        "get_runtime_management_config",
    ),
    "lambda:ListAliases": ("lambda", "list_aliases"),
    "lambda:ListFunctionUrlConfigs": (
        "lambda",
        "list_function_url_configs",
    ),
    "lambda:ListTags": ("lambda", "list_tags"),
    "lambda:ListVersionsByFunction": (
        "lambda",
        "list_versions_by_function",
    ),
    "s3:GetObjectVersion": ("s3", "get_object"),
    "logs:DescribeLogGroups": ("logs", "describe_log_groups"),
    "logs:ListTagsForResource": ("logs", "list_tags_for_resource"),
    "dynamodb:DescribeContinuousBackups": (
        "dynamodb",
        "describe_continuous_backups",
    ),
    "dynamodb:DescribeTable": ("dynamodb", "describe_table"),
    "dynamodb:DescribeTimeToLive": ("dynamodb", "describe_time_to_live"),
    "dynamodb:GetResourcePolicy": ("dynamodb", "get_resource_policy"),
    "dynamodb:ListTagsOfResource": ("dynamodb", "list_tags_of_resource"),
    "dynamodb:Scan": ("dynamodb", "scan"),
    "kms:DescribeKey": ("kms", "describe_key"),
}

_MUTATION_METHODS: dict[str, tuple[str, str]] = {
    "iam:AttachRolePolicy": ("iam", "attach_role_policy"),
    "iam:CreatePolicy": ("iam", "create_policy"),
    "iam:CreateRole": ("iam", "create_role"),
    "iam:DetachRolePolicy": ("iam", "detach_role_policy"),
    "iam:PutRolePermissionsBoundary": (
        "iam",
        "put_role_permissions_boundary",
    ),
    "lambda:CreateFunction": ("lambda", "create_function"),
    "lambda:InvokeFunction": ("lambda", "invoke"),
    "lambda:PutFunctionConcurrency": (
        "lambda",
        "put_function_concurrency",
    ),
    "lambda:PutRuntimeManagementConfig": (
        "lambda",
        "put_runtime_management_config",
    ),
    "logs:CreateLogGroup": ("logs", "create_log_group"),
    "logs:PutRetentionPolicy": ("logs", "put_retention_policy"),
}

ALLOWED_ACTIONS = frozenset(_READ_METHODS) | MUTATION_ACTIONS

_POLICY_READS = frozenset(
    {
        "iam:GetPolicy",
        "iam:GetPolicyVersion",
        "iam:ListEntitiesForPolicy",
        "iam:ListPolicyTags",
        "iam:ListPolicyVersions",
    }
)
_ROLE_READS = frozenset(
    {
        "iam:GetRole",
        "iam:ListAttachedRolePolicies",
        "iam:ListRolePolicies",
        "iam:ListRoleTags",
    }
)
_FUNCTION_READS = frozenset(
    action for action in _READ_METHODS if action.startswith("lambda:")
)
_TABLE_READS = frozenset(
    action for action in _READ_METHODS if action.startswith("dynamodb:")
)
_LOG_READS = frozenset(
    action for action in _READ_METHODS if action.startswith("logs:")
)
_IDENTITY = frozenset({"sts:GetCallerIdentity"})

PHASE_ACTIONS: dict[str, frozenset[str]] = {
    "POLICY_FACTORY": _IDENTITY | _POLICY_READS | {"iam:CreatePolicy"},
    "FOUNDATION_FACTORY": _IDENTITY | _ROLE_READS | {"iam:CreateRole"},
    "FUNCTION_FACTORY": (
        _IDENTITY
        | _POLICY_READS
        | _ROLE_READS
        | _FUNCTION_READS
        | {"s3:GetObjectVersion"}
        | {
            "lambda:CreateFunction",
            "lambda:PutFunctionConcurrency",
            "lambda:PutRuntimeManagementConfig",
        }
    ),
    "LEDGER_FACTORY_FUNCTION_FACTORY": (
        _IDENTITY
        | _POLICY_READS
        | _ROLE_READS
        | _FUNCTION_READS
        | _LOG_READS
        | {"s3:GetObjectVersion"}
        | {
            "lambda:CreateFunction",
            "lambda:PutFunctionConcurrency",
            "lambda:PutRuntimeManagementConfig",
            "logs:CreateLogGroup",
            "logs:PutRetentionPolicy",
        }
    ),
    "LEDGER_FACTORY_ACTIVATOR": (
        _IDENTITY
        | _POLICY_READS
        | _ROLE_READS
        | {"iam:AttachRolePolicy", "iam:PutRolePermissionsBoundary"}
    ),
    "LEDGER_FACTORY_INVOKER": (
        _IDENTITY
        | _ROLE_READS
        | _FUNCTION_READS
        | _TABLE_READS
        | {"kms:DescribeKey", "lambda:InvokeFunction"}
    ),
    "LEDGER_FACTORY_REVOKER": (
        _IDENTITY
        | _POLICY_READS
        | _ROLE_READS
        | {"iam:DetachRolePolicy", "iam:PutRolePermissionsBoundary"}
    ),
    "ACTIVATOR": (
        _IDENTITY
        | _POLICY_READS
        | _ROLE_READS
        | {"iam:AttachRolePolicy", "iam:PutRolePermissionsBoundary"}
    ),
    "REVOCATOR": (
        _IDENTITY
        | _POLICY_READS
        | _ROLE_READS
        | {"iam:PutRolePermissionsBoundary"}
    ),
    "READBACK": frozenset(_READ_METHODS),
}

# request-token, response-token, truncation-flag (where one exists)
_PAGINATION: dict[str, tuple[str, str, str | None]] = {
    "iam:ListAttachedRolePolicies": ("Marker", "Marker", "IsTruncated"),
    "iam:ListEntitiesForPolicy": ("Marker", "Marker", "IsTruncated"),
    "iam:ListPolicyTags": ("Marker", "Marker", "IsTruncated"),
    "iam:ListPolicyVersions": ("Marker", "Marker", "IsTruncated"),
    "iam:ListRolePolicies": ("Marker", "Marker", "IsTruncated"),
    "iam:ListRoleTags": ("Marker", "Marker", "IsTruncated"),
    "lambda:ListAliases": ("Marker", "NextMarker", None),
    "lambda:ListFunctionUrlConfigs": ("Marker", "NextMarker", None),
    "lambda:ListVersionsByFunction": ("Marker", "NextMarker", None),
    "logs:DescribeLogGroups": ("nextToken", "nextToken", None),
    "dynamodb:ListTagsOfResource": ("NextToken", "NextToken", None),
    "dynamodb:Scan": ("ExclusiveStartKey", "LastEvaluatedKey", None),
}
_SINGLE_PAGE_COMPLETE = frozenset({"lambda:ListTags"})

_WAITER_ACTION: dict[str, tuple[str, str, str]] = {
    "lambda:WaitUntilFunctionActiveV2": (
        "lambda:GetFunctionConfiguration",
        "lambda",
        "get_function_configuration",
    ),
    "dynamodb:WaitUntilTableExists": (
        "dynamodb:DescribeTable",
        "dynamodb",
        "describe_table",
    ),
}


@dataclass(frozen=True, slots=True)
class ProviderConfig:
    profile_name: str
    expected_account_id: str = AUTHORITY_ACCOUNT_ID
    region: str = REGION
    expected_principal_digest: str | None = None
    expected_sso_role_name_digest: str | None = None
    max_pages: int = MAX_PAGES
    max_wait_attempts: int = MAX_WAIT_ATTEMPTS
    max_response_bytes: int = MAX_RESPONSE_BYTES
    validity_gate: Callable[[], None] | None = field(
        default=None, repr=False, compare=False
    )

    def __post_init__(self) -> None:
        if (
            not isinstance(self.profile_name, str)
            or _PROFILE_RE.fullmatch(self.profile_name) is None
            or self.profile_name.casefold() == "default"
        ):
            _fail("EXPLICIT_NON_DEFAULT_PROFILE_REQUIRED")
        if (
            not isinstance(self.expected_account_id, str)
            or _ACCOUNT_RE.fullmatch(self.expected_account_id) is None
            or self.expected_account_id != AUTHORITY_ACCOUNT_ID
        ):
            _fail("AUTHORITY_ACCOUNT_BINDING_INVALID")
        if self.region != REGION:
            _fail("REGION_BINDING_INVALID")
        for value in (
            self.expected_principal_digest,
            self.expected_sso_role_name_digest,
        ):
            if value is not None and _DIGEST_RE.fullmatch(value) is None:
                _fail("CALLER_BINDING_INVALID")
        if (
            type(self.max_pages) is not int
            or not 1 <= self.max_pages <= MAX_PAGES
            or type(self.max_wait_attempts) is not int
            or not 1 <= self.max_wait_attempts <= MAX_WAIT_ATTEMPTS
            or type(self.max_response_bytes) is not int
            or not 1 <= self.max_response_bytes <= MAX_RESPONSE_BYTES
        ):
            _fail("PROVIDER_BOUND_INVALID")
        if self.validity_gate is not None and not callable(self.validity_gate):
            _fail("AUTHORITY_WINDOW_GATE_INVALID")


@dataclass(frozen=True, slots=True)
class PlannedCall:
    phase: str
    sequence: int
    service: str
    api_action: str
    allowed_action: str
    target_arn: str = field(repr=False)
    request: Mapping[str, Any] = field(repr=False)
    request_digest: str
    operation_digest: str
    kind: CallKind
    complete_pagination_required: bool
    expected_code_sha256: str | None
    poll_interval_seconds: int = 0
    max_poll_attempts: int = 0
    timeout_seconds: int = 0


@dataclass(frozen=True, slots=True)
class IdentityReceipt:
    record_type: str
    region: str
    account_digest: str
    principal_digest: str
    sso_role_name_digest: str
    session_digest: str
    response_digest: str
    concrete_provider: bool
    receipt_digest: str


@dataclass(frozen=True, slots=True)
class ProviderResult:
    outcome: Outcome
    phase: str
    sequence: int
    operation_digest: str
    request_digest: str
    response_digest: str
    operation_calls: int
    provider_calls: int
    reconciliation_required: bool
    error_code: str | None = None
    response: Mapping[str, Any] = field(
        default_factory=dict, repr=False, compare=False
    )

    def private_record(self) -> dict[str, Any]:
        return {
            "outcome": self.outcome.value,
            "phase": self.phase,
            "sequence": self.sequence,
            "operation_digest": self.operation_digest,
            "request_digest": self.request_digest,
            "response_digest": self.response_digest,
            "operation_calls": self.operation_calls,
            "provider_calls": self.provider_calls,
            "reconciliation_required": self.reconciliation_required,
            "error_code": self.error_code,
            "response": _snapshot(self.response),
        }


@dataclass(frozen=True, slots=True)
class TranscriptReceipt:
    record_type: str
    region: str
    provider_mode: str
    profile_binding_digest: str
    identity_receipt_digest: str
    transcript_digest: str
    provider_calls: int
    provider_mutation_calls: int
    aws_calls: int
    aws_mutations: int
    live_provider_evidence: bool
    reconciliation_required: bool
    accepted_causal_receipt_binding_digest: str | None
    complete: bool
    summary_digest: str


def _load_boto3() -> tuple[Any, Any]:
    """Load the AWS SDK only after local gates pass."""

    try:
        import boto3  # type: ignore[import-not-found]
        from botocore.config import Config  # type: ignore[import-not-found]
    except ImportError as exc:
        raise LiveProviderError("AWS_SDK_UNAVAILABLE") from exc
    return boto3, Config


def _ambient_gate() -> None:
    if any(name.startswith("AWS_") or name in _AMBIENT_NAMES for name in os.environ):
        _fail("AMBIENT_AWS_OVERRIDE_FORBIDDEN")


def _resolve_projection(value: Any, projections: Mapping[str, str] | None) -> Any:
    if value == _PLACEHOLDER:
        if (
            not isinstance(projections, Mapping)
            or set(projections) != {_PLACEHOLDER}
            or not isinstance(projections[_PLACEHOLDER], str)
            or not projections[_PLACEHOLDER].startswith("arn:aws:kms:")
        ):
            _fail("READBACK_PROJECTION_REQUIRED")
        return projections[_PLACEHOLDER]
    if isinstance(value, Mapping):
        if any(not isinstance(key, str) for key in value):
            _fail("PLAN_OPERATION_FIELDS_INVALID")
        return {
            key: _resolve_projection(item, projections)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_resolve_projection(item, projections) for item in value]
    return value


def _validated_lambda_code_sha256(value: Any) -> str:
    if not isinstance(value, str) or not value:
        _fail("CREATE_FUNCTION_CODE_BINDING_INVALID")
    try:
        decoded = base64.b64decode(value, validate=True)
    except (TypeError, ValueError) as exc:
        raise LiveProviderError("CREATE_FUNCTION_CODE_BINDING_INVALID") from exc
    if len(decoded) != 32:
        _fail("CREATE_FUNCTION_CODE_BINDING_INVALID")
    return value


def _expected_create_function_code_sha256(
    plan: Mapping[str, Any],
    *,
    phase: str,
    target_arn: str,
    request: Mapping[str, Any],
) -> str:
    """Derive the exact Lambda package hash from the sealed GUG-365 plan."""

    if not isinstance(plan, Mapping):
        _fail("CREATE_FUNCTION_PLAN_BINDING_INVALID")
    plan_digest = plan.get("plan_digest")
    plan_body = {
        key: value
        for key, value in plan.items()
        if key not in {"_test_metadata", "plan_digest"}
    }
    if (
        not isinstance(plan_digest, str)
        or _DIGEST_RE.fullmatch(plan_digest) is None
        or canonical_digest(plan_body) != plan_digest
    ):
        _fail("CREATE_FUNCTION_PLAN_BINDING_INVALID")
    contract_key = {
        "FUNCTION_FACTORY": "broker_function",
        "LEDGER_FACTORY_FUNCTION_FACTORY": "ledger_factory_function",
    }.get(phase)
    contract = plan.get(contract_key) if contract_key is not None else None
    if not isinstance(contract, Mapping):
        _fail("CREATE_FUNCTION_PLAN_BINDING_INVALID")
    signed = contract.get("signed_code")
    normalized = contract.get("normalized_configuration")
    code = request.get("Code")
    if (
        contract.get("arn") != target_arn
        or contract.get("create_request") != request
        or not isinstance(signed, Mapping)
        or not isinstance(normalized, Mapping)
        or not isinstance(code, Mapping)
        or code.get("S3Bucket") != signed.get("s3_bucket")
        or code.get("S3Key") != signed.get("s3_key")
        or code.get("S3ObjectVersion") != signed.get("s3_object_version")
    ):
        _fail("CREATE_FUNCTION_PLAN_BINDING_INVALID")
    expected = _validated_lambda_code_sha256(signed.get("lambda_code_sha256"))
    if normalized.get("CodeSha256") != expected:
        _fail("CREATE_FUNCTION_PLAN_BINDING_INVALID")
    return expected


def planned_call_from_record(
    phase: str,
    record: Mapping[str, Any],
    *,
    slot_projections: Mapping[str, str] | None = None,
    plan: Mapping[str, Any] | None = None,
) -> PlannedCall:
    """Detach and validate one exact operation emitted by the GUG-365 plan."""

    if phase not in PHASE_ACTIONS or not isinstance(record, Mapping):
        _fail("PLAN_OPERATION_PHASE_INVALID")
    sequence = record.get("sequence")
    service = record.get("service")
    api_action = record.get("api_action")
    target = _resolve_projection(record.get("target_arn"), slot_projections)
    request = _resolve_projection(record.get("request"), slot_projections)
    if (
        type(sequence) is not int
        or not 1 <= sequence <= 4096
        or not isinstance(service, str)
        or not isinstance(api_action, str)
        or not isinstance(target, str)
        or not 1 <= len(target) <= 2048
        or not isinstance(request, Mapping)
    ):
        _fail("PLAN_OPERATION_FIELDS_INVALID")
    waiter_key = f"{service}:{api_action}"
    waiter = _WAITER_ACTION.get(waiter_key)
    derived_action = waiter[0] if waiter is not None else waiter_key
    allowed_action = record.get("allowed_action", derived_action)
    if (
        allowed_action != derived_action
        or derived_action not in PHASE_ACTIONS[phase]
        or derived_action not in ALLOWED_ACTIONS
    ):
        _fail("PLAN_OPERATION_NOT_ALLOWED")
    method = (_READ_METHODS | _MUTATION_METHODS).get(derived_action)
    if method is None or method[0] != service:
        _fail("PLAN_OPERATION_DISPATCH_INVALID")
    if record.get("retry_permitted", False) is not False:
        _fail("PLAN_OPERATION_RETRY_FORBIDDEN")
    if "attempt_limit" in record and (
        type(record["attempt_limit"]) is not int or record["attempt_limit"] != 1
    ):
        _fail("PLAN_OPERATION_ATTEMPT_INVALID")
    if record.get("write_retry_permitted", False) is not False:
        _fail("PLAN_OPERATION_RETRY_FORBIDDEN")
    if "mutation" in record and record["mutation"] is not (
        derived_action in MUTATION_ACTIONS
    ):
        _fail("PLAN_OPERATION_KIND_INVALID")
    request_copy = _snapshot(request)
    request_digest = canonical_digest(request_copy)
    supplied_request_digest = record.get("request_digest", request_digest)
    if supplied_request_digest != request_digest:
        _fail("PLAN_OPERATION_REQUEST_DIGEST_MISMATCH")
    complete = record.get("complete_pagination_required", False)
    if type(complete) is not bool:
        _fail("PLAN_OPERATION_PAGINATION_INVALID")
    if derived_action in _PAGINATION and api_action.startswith("List") and not complete:
        _fail("PLAN_OPERATION_PAGINATION_INVALID")
    if complete:
        spec = _PAGINATION.get(derived_action)
        if (
            derived_action not in _SINGLE_PAGE_COMPLETE
            and (spec is None or spec[0] in request_copy)
        ):
            _fail("PLAN_OPERATION_PAGINATION_INVALID")
    poll_interval = max_attempts = timeout = 0
    if waiter is not None:
        if record.get("bounded_read_polling") is not True:
            _fail("PLAN_WAITER_BOUND_INVALID")
        poll_interval = record.get("poll_interval_seconds")
        max_attempts = record.get("max_poll_attempts")
        timeout = record.get("timeout_seconds")
        if (
            type(poll_interval) is not int
            or not 0 <= poll_interval <= 3
            or type(max_attempts) is not int
            or not 1 <= max_attempts <= MAX_WAIT_ATTEMPTS
            or type(timeout) is not int
            or not 1 <= timeout <= 60
            or poll_interval * max_attempts > timeout
        ):
            _fail("PLAN_WAITER_BOUND_INVALID")
        kind = CallKind.WAITER
    elif derived_action == "sts:GetCallerIdentity":
        kind = CallKind.IDENTITY
    elif derived_action in MUTATION_ACTIONS:
        kind = CallKind.MUTATION
    else:
        kind = CallKind.READ
    expected_code_sha256 = None
    if derived_action == "lambda:CreateFunction" and plan is not None:
        expected_code_sha256 = _expected_create_function_code_sha256(
            plan,
            phase=phase,
            target_arn=target,
            request=request_copy,
        )
    operation_projection = {
        "phase": phase,
        "sequence": sequence,
        "service": service,
        "api_action": api_action,
        "allowed_action": derived_action,
        "target_arn": target,
        "request": request_copy,
        "request_digest": request_digest,
        "kind": kind.value,
        "complete_pagination_required": complete,
        "poll_interval_seconds": poll_interval,
        "max_poll_attempts": max_attempts,
        "timeout_seconds": timeout,
    }
    if derived_action == "lambda:CreateFunction":
        operation_projection["expected_code_sha256"] = expected_code_sha256
    return PlannedCall(
        phase=phase,
        sequence=sequence,
        service=service,
        api_action=api_action,
        allowed_action=derived_action,
        target_arn=target,
        request=request_copy,
        request_digest=request_digest,
        operation_digest=canonical_digest(operation_projection),
        kind=kind,
        complete_pagination_required=complete,
        expected_code_sha256=expected_code_sha256,
        poll_interval_seconds=poll_interval,
        max_poll_attempts=max_attempts,
        timeout_seconds=timeout,
    )


def _validate_call(call: PlannedCall) -> None:
    if type(call) is not PlannedCall:
        _fail("PLANNED_CALL_INVALID")
    record: dict[str, Any] = {
        "sequence": call.sequence,
        "service": call.service,
        "api_action": call.api_action,
        "allowed_action": call.allowed_action,
        "target_arn": call.target_arn,
        "request": call.request,
        "request_digest": call.request_digest,
        "complete_pagination_required": call.complete_pagination_required,
        "retry_permitted": False,
        "attempt_limit": 1,
    }
    if call.kind is CallKind.WAITER:
        record.update(
            {
                "mutation": False,
                "bounded_read_polling": True,
                "poll_interval_seconds": call.poll_interval_seconds,
                "max_poll_attempts": call.max_poll_attempts,
                "timeout_seconds": call.timeout_seconds,
                "write_retry_permitted": False,
            }
        )
    rebuilt = planned_call_from_record(call.phase, record)
    if call.allowed_action == "lambda:CreateFunction":
        expected_code_sha256 = (
            _validated_lambda_code_sha256(call.expected_code_sha256)
            if call.expected_code_sha256 is not None
            else None
        )
        projection = {
            "phase": rebuilt.phase,
            "sequence": rebuilt.sequence,
            "service": rebuilt.service,
            "api_action": rebuilt.api_action,
            "allowed_action": rebuilt.allowed_action,
            "target_arn": rebuilt.target_arn,
            "request": rebuilt.request,
            "request_digest": rebuilt.request_digest,
            "kind": rebuilt.kind.value,
            "complete_pagination_required": rebuilt.complete_pagination_required,
            "poll_interval_seconds": rebuilt.poll_interval_seconds,
            "max_poll_attempts": rebuilt.max_poll_attempts,
            "timeout_seconds": rebuilt.timeout_seconds,
            "expected_code_sha256": expected_code_sha256,
        }
        rebuilt = replace(
            rebuilt,
            expected_code_sha256=expected_code_sha256,
            operation_digest=canonical_digest(projection),
        )
    elif call.expected_code_sha256 is not None:
        _fail("CREATE_FUNCTION_CODE_BINDING_UNEXPECTED")
    if rebuilt != call:
        _fail("PLANNED_CALL_SUBSTITUTION_DETECTED")


def _safe_error_code(exc: BaseException) -> str:
    response = getattr(exc, "response", None)
    if isinstance(response, Mapping):
        error = response.get("Error")
        if isinstance(error, Mapping) and isinstance(error.get("Code"), str):
            candidate = error["Code"]
            if _ERROR_RE.fullmatch(candidate):
                return candidate
    name = type(exc).__name__
    return name if _ERROR_RE.fullmatch(name) else "ProviderCallError"


def _conclusive_error(exc: BaseException) -> bool:
    if _safe_error_code(exc) in _CONCLUSIVE_NO_EFFECT_ERRORS:
        return True
    return type(exc).__name__ in {
        "ParamValidationError",
        "UnknownClientMethodError",
        "UnknownParameterError",
        "UnsupportedSignatureVersionError",
    }


def _read_stream(stream: Any, limit: int) -> bytes:
    if not hasattr(stream, "read") or not callable(stream.read):
        _fail("PROVIDER_STREAM_INVALID")
    chunks: list[bytes] = []
    total = 0
    try:
        while True:
            chunk = stream.read(min(64 * 1024, limit + 1 - total))
            if chunk in (b"", "", None):
                break
            if isinstance(chunk, str):
                chunk = chunk.encode("utf-8")
            if not isinstance(chunk, bytes):
                _fail("PROVIDER_STREAM_INVALID")
            total += len(chunk)
            if total > limit:
                _fail("PROVIDER_RESPONSE_TOO_LARGE")
            chunks.append(chunk)
    finally:
        close = getattr(stream, "close", None)
        if callable(close):
            try:
                close()
            except Exception:
                _fail("PROVIDER_STREAM_CLOSE_FAILED")
    return b"".join(chunks)


def _normalize(
    value: Any,
    *,
    byte_limit: int,
    path: tuple[str, ...] = (),
) -> Any:
    if value is None or isinstance(value, (str, bool, int)):
        if isinstance(value, str) and len(value.encode("utf-8")) > byte_limit:
            _fail("PROVIDER_RESPONSE_TOO_LARGE")
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            _fail("PROVIDER_RESPONSE_UNSAFE")
        return value
    if isinstance(value, (datetime, date)):
        if isinstance(value, datetime):
            if value.tzinfo is None:
                value = value.replace(tzinfo=timezone.utc)
            return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
        return value.isoformat()
    if isinstance(value, bytes):
        if len(value) > byte_limit:
            _fail("PROVIDER_RESPONSE_TOO_LARGE")
        return {
            "byte_length": len(value),
            "byte_digest": "sha256:" + sha256(value).hexdigest(),
        }
    if isinstance(value, Mapping):
        result: dict[str, Any] = {}
        for raw_key in sorted(value, key=lambda item: str(item)):
            if not isinstance(raw_key, str):
                _fail("PROVIDER_RESPONSE_UNSAFE")
            if raw_key == "ResponseMetadata":
                continue
            item = value[raw_key]
            lowered = raw_key.casefold()
            current = (*path, raw_key)
            if lowered == "location":
                result[raw_key] = {
                    "redacted": True,
                    "reason": "EPHEMERAL_LOCATION_EXCLUDED",
                }
            elif lowered in {
                "accesskeyid",
                "secretaccesskey",
                "sessiontoken",
                "authorization",
                "cookie",
                "password",
            } or (len(current) >= 2 and current[-2:] == ("Environment", "Variables")):
                safe_item = _normalize(item, byte_limit=byte_limit, path=current)
                result[raw_key] = {
                    "redacted": True,
                    "value_digest": canonical_digest(safe_item),
                }
            elif raw_key in {"Body", "Payload"} and hasattr(item, "read"):
                content = _read_stream(item, byte_limit)
                projection: dict[str, Any] = {
                    "byte_length": len(content),
                    "byte_digest": "sha256:" + sha256(content).hexdigest(),
                }
                if raw_key == "Payload" and content:
                    try:
                        parsed = json.loads(content.decode("utf-8"))
                    except (UnicodeDecodeError, json.JSONDecodeError):
                        pass
                    else:
                        projection["json"] = _normalize(
                            parsed, byte_limit=byte_limit, path=current
                        )
                result[raw_key] = projection
            else:
                result[raw_key] = _normalize(
                    item, byte_limit=byte_limit, path=current
                )
        return result
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return [
            _normalize(item, byte_limit=byte_limit, path=path) for item in value
        ]
    _fail("PROVIDER_RESPONSE_UNSAFE")


def _normalize_response(value: Any, *, byte_limit: int) -> Mapping[str, Any]:
    try:
        normalized = _normalize(value, byte_limit=byte_limit)
    except LiveProviderError:
        raise
    except Exception as exc:
        raise LiveProviderError("PROVIDER_RESPONSE_UNSAFE") from exc
    if not isinstance(normalized, Mapping):
        _fail("PROVIDER_RESPONSE_UNSAFE")
    encoded = canonical_json(normalized).encode("utf-8")
    if len(encoded) > byte_limit:
        _fail("PROVIDER_RESPONSE_TOO_LARGE")
    return _snapshot(normalized)


def _merge_pagination_facts(
    pages: Sequence[Mapping[str, Any]],
    *,
    response_token_key: str,
    truncated_key: str | None,
    byte_limit: int | None = None,
) -> dict[str, Any]:
    """Remove transport controls and merge page facts independent of boundaries."""

    merged: dict[str, Any] = {}
    transport_keys = {response_token_key}
    if truncated_key is not None:
        transport_keys.add(truncated_key)
    for page in pages:
        for key, value in page.items():
            if key in transport_keys:
                continue
            detached = _snapshot(value)
            if isinstance(detached, list):
                current = merged.setdefault(key, [])
                if not isinstance(current, list):
                    _fail("PAGINATION_FACTS_INVALID")
                current.extend(detached)
            elif key in {"Count", "ScannedCount"} and type(detached) is int:
                current = merged.get(key, 0)
                if type(current) is not int:
                    _fail("PAGINATION_FACTS_INVALID")
                merged[key] = current + detached
            elif key not in merged:
                merged[key] = detached
            elif merged[key] != detached:
                _fail("PAGINATION_FACTS_INCONSISTENT")
    for key, value in merged.items():
        if isinstance(value, list):
            value.sort(key=canonical_json)
    detached = _snapshot(merged)
    if byte_limit is not None:
        if type(byte_limit) is not int or byte_limit < 1:
            _fail("PROVIDER_BOUND_INVALID")
        if len(canonical_json(detached).encode("utf-8")) > byte_limit:
            _fail("PROVIDER_RESPONSE_TOO_LARGE")
    return detached


def _validate_concrete_sso_profile(session: Any, config: ProviderConfig) -> str:
    """Prove that the selected SDK profile is direct SSO, not a role chain."""

    try:
        botocore_session = session._session  # noqa: SLF001 - SDK has no public profile document API
        full_config = botocore_session.full_config
        profiles = full_config["profiles"]
        profile = profiles[config.profile_name]
    except (AttributeError, KeyError, TypeError):
        _fail("SSO_PROFILE_METADATA_UNAVAILABLE")
    if not isinstance(full_config, Mapping) or not isinstance(profile, Mapping):
        _fail("SSO_PROFILE_METADATA_UNAVAILABLE")
    if set(profile) & _PROFILE_FORBIDDEN or not set(profile) <= _PROFILE_ALLOWED:
        _fail("DIRECT_SSO_PROFILE_REQUIRED")
    if (
        profile.get("sso_account_id") != config.expected_account_id
        or not isinstance(profile.get("sso_role_name"), str)
        or not profile["sso_role_name"]
        or canonical_digest(profile["sso_role_name"])
        != config.expected_sso_role_name_digest
        or profile.get("region", config.region) != config.region
    ):
        _fail("DIRECT_SSO_PROFILE_REQUIRED")
    modern = isinstance(profile.get("sso_session"), str) and bool(profile["sso_session"])
    legacy = all(
        isinstance(profile.get(key), str) and bool(profile[key])
        for key in ("sso_start_url", "sso_region")
    )
    if not modern and not legacy:
        _fail("DIRECT_SSO_PROFILE_REQUIRED")
    if modern:
        sessions = full_config.get("sso_sessions")
        selected = sessions.get(profile["sso_session"]) if isinstance(sessions, Mapping) else None
        if not isinstance(selected, Mapping) or not all(
            isinstance(selected.get(key), str) and bool(selected[key])
            for key in ("sso_start_url", "sso_region")
        ):
            _fail("DIRECT_SSO_PROFILE_REQUIRED")
    try:
        credentials = session.get_credentials()
        method = credentials.method
    except (AttributeError, TypeError):
        _fail("DIRECT_SSO_CREDENTIALS_REQUIRED")
    if method not in {"sso", "sso-session"}:
        _fail("DIRECT_SSO_CREDENTIALS_REQUIRED")
    if getattr(session, "region_name", config.region) != config.region:
        _fail("REGION_BINDING_INVALID")
    return str(profile["sso_role_name"])


SessionFactory = Callable[..., Any]


class LiveProvider:
    """Concrete, STS-bound SDK adapter with a digest-only call transcript."""

    def __init__(self) -> None:  # pragma: no cover - callers must use open()
        _fail("LIVE_PROVIDER_OPEN_REQUIRED")

    @classmethod
    def open(
        cls,
        config: ProviderConfig | str,
        expected_account_id: str | None = None,
        expected_region: str = REGION,
        *,
        session_factory: SessionFactory | None = None,
    ) -> "LiveProvider":
        if isinstance(config, str):
            selected = ProviderConfig(
                profile_name=config,
                expected_account_id=expected_account_id or AUTHORITY_ACCOUNT_ID,
                region=expected_region,
            )
        elif type(config) is ProviderConfig:
            if expected_account_id is not None or expected_region != REGION:
                _fail("PROVIDER_CONFIG_OVERRIDE_FORBIDDEN")
            selected = config
        else:
            _fail("PROVIDER_CONFIG_INVALID")
        _ambient_gate()
        concrete = session_factory is None
        if concrete and selected.validity_gate is None:
            _fail("AUTHORITY_WINDOW_GATE_REQUIRED")
        if concrete and (
            selected.expected_principal_digest is None
            or selected.expected_sso_role_name_digest is None
        ):
            _fail("CALLER_BINDING_REQUIRED")
        if selected.validity_gate is not None:
            selected.validity_gate()
        boto3, config_type = _load_boto3()
        try:
            sdk_config = config_type(
                region_name=selected.region,
                retries={"mode": "standard", "total_max_attempts": 1},
                connect_timeout=15,
                read_timeout=60,
                parameter_validation=True,
                tcp_keepalive=True,
                ignore_configured_endpoint_urls=True,
                user_agent_extra="scanalyze-gug390-live-provider/1",
            )
        except Exception:
            _fail("AWS_SDK_CONFIG_INVALID")
        factory = getattr(boto3, "Session", None) if concrete else session_factory
        if not callable(factory):
            _fail("AWS_SESSION_FACTORY_INVALID")
        try:
            session = factory(
                profile_name=selected.profile_name,
                region_name=selected.region,
            )
        except Exception:
            _fail("AWS_SESSION_OPEN_FAILED")
        sso_permission_set_name: str | None = None
        if concrete:
            sso_permission_set_name = _validate_concrete_sso_profile(
                session, selected
            )
        try:
            sts = session.client("sts", config=sdk_config)
        except Exception:
            _fail("STS_CLIENT_OPEN_FAILED")

        self = object.__new__(cls)
        self._config = selected
        self._session = session
        self._sdk_config = sdk_config
        self._concrete = concrete
        self._clients: dict[str, Any] = {"sts": sts}
        self._events: list[dict[str, Any]] = []
        self._validations: list[dict[str, Any]] = []
        self._provider_calls = 0
        self._provider_mutations = 0
        self._reconciliation_required = False
        self._accepted_causal_receipt: dict[str, Any] | None = None
        self._accepted_causal_receipt_binding: dict[str, Any] | None = None
        self._closed = False
        self._profile_binding_digest = canonical_digest(
            {
                "profile_name": selected.profile_name,
                "source": "DIRECT_SSO" if concrete else "INJECTED_NON_LIVE",
                "region": selected.region,
                "expected_account_id": selected.expected_account_id,
                "expected_principal_digest": selected.expected_principal_digest,
                "expected_sso_role_name_digest": (
                    selected.expected_sso_role_name_digest
                ),
            }
        )
        if selected.validity_gate is not None:
            selected.validity_gate()
        try:
            self._provider_calls += 1
            raw_identity = sts.get_caller_identity()
        except Exception:
            _fail("STS_IDENTITY_UNAVAILABLE")
        if not isinstance(raw_identity, Mapping):
            _fail("STS_IDENTITY_INVALID")
        account = raw_identity.get("Account")
        arn = raw_identity.get("Arn")
        user_id = raw_identity.get("UserId")
        if (
            account != selected.expected_account_id
            or not isinstance(arn, str)
            or not arn.startswith("arn:aws:sts::")
            or not isinstance(user_id, str)
            or not user_id
        ):
            _fail("STS_IDENTITY_MISMATCH")
        assumed_role_prefix = (
            f"arn:aws:sts::{selected.expected_account_id}:assumed-role/"
        )
        assumed_role_resource = (
            arn[len(assumed_role_prefix) :]
            if arn.startswith(assumed_role_prefix)
            else ""
        )
        role_path, separator, session_name = assumed_role_resource.rpartition("/")
        role_name = role_path.rsplit("/", 1)[-1] if role_path else ""
        if concrete:
            assert isinstance(sso_permission_set_name, str)
            generated_role_pattern = re.compile(
                rf"^AWSReservedSSO_{re.escape(sso_permission_set_name)}_"
                r"[0-9A-Fa-f]{16}$"
            )
            if (
                canonical_digest(arn) != selected.expected_principal_digest
                or not separator
                or not session_name
                or generated_role_pattern.fullmatch(role_name) is None
            ):
                _fail("STS_CALLER_BINDING_MISMATCH")
        receipt_sso_role_name = (
            sso_permission_set_name if concrete else role_name
        )
        if not isinstance(receipt_sso_role_name, str) or not receipt_sso_role_name:
            _fail("STS_CALLER_BINDING_MISMATCH")
        identity_projection = {"Account": account, "Arn": arn, "UserId": user_id}
        response_digest = canonical_digest(identity_projection)
        receipt_body = {
            "record_type": "scanalyze.platform_authority.gug390_identity_receipt.v1",
            "region": selected.region,
            "account_digest": canonical_digest(account),
            "principal_digest": canonical_digest(arn),
            # This digest binds the direct-SSO profile role/permission-set
            # name.  The exact generated AWSReservedSSO role remains bound by
            # principal_digest and by the relationship check above.
            "sso_role_name_digest": canonical_digest(receipt_sso_role_name),
            "session_digest": canonical_digest(identity_projection),
            "response_digest": response_digest,
            "concrete_provider": concrete,
        }
        self._identity_receipt = IdentityReceipt(
            **receipt_body,
            receipt_digest=canonical_digest(receipt_body),
        )
        self._events.append(
            {
                "ordinal": 1,
                "phase_digest": canonical_digest("IDENTITY"),
                "sequence": 1,
                "allowed_action": "sts:GetCallerIdentity",
                "target_digest": canonical_digest("*"),
                "request_digest": canonical_digest({}),
                "response_digest": response_digest,
                "outcome": Outcome.SUCCEEDED.value,
                "page_ordinal": 1,
                "error_code_digest": None,
            }
        )
        return self

    @property
    def identity_receipt(self) -> IdentityReceipt:
        return self._identity_receipt

    @property
    def provider_mode(self) -> str:
        return "CONCRETE_DIRECT_SSO" if self._concrete else "INJECTED_NON_LIVE"

    @property
    def identity_projection(self) -> dict[str, Any]:
        """Return phase-safe identity bindings without raw AWS identifiers."""

        return {
            "provider_mode": self.provider_mode,
            "region": self.identity_receipt.region,
            "account_digest": self.identity_receipt.account_digest,
            "principal_digest": self.identity_receipt.principal_digest,
            "sso_role_name_digest": (
                self.identity_receipt.sso_role_name_digest
            ),
            "session_digest": self.identity_receipt.session_digest,
            "identity_receipt_digest": self.identity_receipt.receipt_digest,
            "live_provider_evidence": self._concrete,
        }

    @property
    def accepted_causal_receipt_digest(self) -> str | None:
        binding = self._accepted_causal_receipt_binding
        return None if binding is None else str(binding["receipt_digest"])

    def revalidate_identity(self) -> IdentityReceipt:
        """Perform a fresh STS continuity check before a guarded read/CAS step."""

        if self._closed:
            _fail("PROVIDER_ALREADY_FINALIZED")
        request: dict[str, Any] = {}
        call = planned_call_from_record(
            "READBACK",
            {
                "sequence": 1,
                "service": "sts",
                "api_action": "GetCallerIdentity",
                "allowed_action": "sts:GetCallerIdentity",
                "target_arn": "*",
                "request": request,
                "request_digest": canonical_digest(request),
                "mutation": False,
                "complete_pagination_required": False,
                "attempt_limit": 1,
                "retry_permitted": False,
            },
        )
        result = self._invoke_phase_identity(call)
        if result.outcome is not Outcome.SUCCEEDED:
            _fail("STS_SESSION_CONTINUITY_FAILED")
        return self.identity_receipt

    def accepted_causal_receipt_binding(self) -> dict[str, Any]:
        """Return the digest-only link to the provider result stored by the ledger."""

        if self._accepted_causal_receipt_binding is None:
            _fail("CAUSAL_RECEIPT_NOT_ACCEPTED")
        return _snapshot(self._accepted_causal_receipt_binding)

    def private_accepted_causal_receipt(self) -> dict[str, Any]:
        """Return private receipt evidence for later offline recertification."""

        if (
            self._accepted_causal_receipt is None
            or self._accepted_causal_receipt_binding is None
        ):
            _fail("CAUSAL_RECEIPT_NOT_ACCEPTED")
        body = {
            **self._accepted_causal_receipt_binding,
            "receipt": _snapshot(self._accepted_causal_receipt),
        }
        return {**body, "private_evidence_digest": canonical_digest(body)}

    def _client(self, service: str) -> Any:
        if self._closed:
            _fail("PROVIDER_ALREADY_FINALIZED")
        if service not in {
            value[0] for value in (*_READ_METHODS.values(), *_MUTATION_METHODS.values())
        }:
            _fail("PROVIDER_SERVICE_NOT_ALLOWED")
        if service not in self._clients:
            try:
                self._clients[service] = self._session.client(
                    service, config=self._sdk_config
                )
            except Exception:
                _fail("PROVIDER_CLIENT_OPEN_FAILED")
        return self._clients[service]

    def _append_event(
        self,
        call: PlannedCall,
        *,
        request: Mapping[str, Any],
        response_digest: str,
        outcome: Outcome,
        page_ordinal: int,
        error_code: str | None,
    ) -> None:
        self._events.append(
            {
                "ordinal": self._provider_calls,
                "phase_digest": canonical_digest(call.phase),
                "sequence": call.sequence,
                "allowed_action": call.allowed_action,
                "target_digest": canonical_digest(call.target_arn),
                "request_digest": canonical_digest(request),
                "response_digest": response_digest,
                "outcome": outcome.value,
                "page_ordinal": page_ordinal,
                "error_code_digest": (
                    canonical_digest(error_code) if error_code is not None else None
                ),
            }
        )

    def _sdk_call(
        self,
        call: PlannedCall,
        *,
        service: str,
        method_name: str,
        request: Mapping[str, Any],
        page_ordinal: int,
    ) -> tuple[Mapping[str, Any] | None, str | None, bool]:
        client = self._client(service)
        if self._config.validity_gate is not None:
            self._config.validity_gate()
        try:
            method = getattr(client, method_name)
        except AttributeError:
            _fail("PROVIDER_METHOD_UNAVAILABLE")
        self._provider_calls += 1
        if call.kind is CallKind.MUTATION:
            self._provider_mutations += 1
        try:
            raw = method(**_snapshot(request))
        except Exception as exc:
            code = _safe_error_code(exc)
            ambiguous = call.kind is CallKind.MUTATION and not _conclusive_error(exc)
            outcome = Outcome.AMBIGUOUS if ambiguous else Outcome.FAILED
            if ambiguous:
                self._reconciliation_required = True
            response_digest = canonical_digest(
                {"error_code_digest": canonical_digest(code), "response_present": False}
            )
            self._append_event(
                call,
                request=request,
                response_digest=response_digest,
                outcome=outcome,
                page_ordinal=page_ordinal,
                error_code=code,
            )
            return None, code, ambiguous
        if not isinstance(raw, Mapping):
            code = "ProviderResponseInvalid"
            ambiguous = call.kind is CallKind.MUTATION
            if ambiguous:
                self._reconciliation_required = True
            self._append_event(
                call,
                request=request,
                response_digest=canonical_digest({"response_present": True}),
                outcome=Outcome.AMBIGUOUS if ambiguous else Outcome.FAILED,
                page_ordinal=page_ordinal,
                error_code=code,
            )
            return None, code, ambiguous
        return raw, None, False

    def _successful_result(
        self,
        call: PlannedCall,
        response: Mapping[str, Any],
        *,
        calls_before: int,
    ) -> ProviderResult:
        detached = _snapshot(response)
        return ProviderResult(
            outcome=Outcome.SUCCEEDED,
            phase=call.phase,
            sequence=call.sequence,
            operation_digest=call.operation_digest,
            request_digest=call.request_digest,
            response_digest=canonical_digest(detached),
            operation_calls=self._provider_calls - calls_before,
            provider_calls=self._provider_calls,
            reconciliation_required=False,
            response=detached,
        )

    def _failed_result(
        self,
        call: PlannedCall,
        *,
        code: str,
        ambiguous: bool,
        calls_before: int,
        response: Mapping[str, Any] | None = None,
    ) -> ProviderResult:
        detached = _snapshot(response or {})
        return ProviderResult(
            outcome=Outcome.AMBIGUOUS if ambiguous else Outcome.FAILED,
            phase=call.phase,
            sequence=call.sequence,
            operation_digest=call.operation_digest,
            request_digest=call.request_digest,
            response_digest=canonical_digest(detached),
            operation_calls=self._provider_calls - calls_before,
            provider_calls=self._provider_calls,
            reconciliation_required=ambiguous,
            error_code=code,
            response=detached,
        )

    def _mutation_readback_calls(self, call: PlannedCall) -> tuple[PlannedCall, ...]:
        """Derive the closed canonical readback sequence before dispatching a write."""

        action = call.allowed_action
        request = call.request

        def text_value(key: str) -> str:
            value = request.get(key)
            if not isinstance(value, str) or not value:
                _fail("MUTATION_READBACK_BINDING_INVALID")
            return value

        if action == "lambda:InvokeFunction":
            return ()
        specifications: list[tuple[str, dict[str, Any], bool]] = []
        if action == "iam:CreatePolicy":
            specifications = [
                ("iam:GetPolicy", {"PolicyArn": call.target_arn}, False),
                (
                    "iam:GetPolicyVersion",
                    {"PolicyArn": call.target_arn, "VersionId": "v1"},
                    False,
                ),
                ("iam:ListPolicyTags", {"PolicyArn": call.target_arn}, True),
            ]
        elif action == "iam:CreateRole":
            role_name = text_value("RoleName")
            specifications = [
                ("iam:GetRole", {"RoleName": role_name}, False),
                ("iam:ListRoleTags", {"RoleName": role_name}, True),
            ]
        elif action == "iam:PutRolePermissionsBoundary":
            specifications = [
                (
                    "iam:GetRole",
                    {"RoleName": text_value("RoleName")},
                    False,
                )
            ]
        elif action in {"iam:AttachRolePolicy", "iam:DetachRolePolicy"}:
            specifications = [
                (
                    "iam:ListAttachedRolePolicies",
                    {"RoleName": text_value("RoleName")},
                    True,
                )
            ]
        elif action == "lambda:CreateFunction":
            function_name = text_value("FunctionName")
            specifications = [
                ("lambda:GetFunction", {"FunctionName": function_name}, False),
                (
                    "lambda:GetFunctionCodeSigningConfig",
                    {"FunctionName": function_name},
                    False,
                ),
                ("lambda:ListTags", {"Resource": call.target_arn}, True),
                (
                    "lambda:ListVersionsByFunction",
                    {"FunctionName": function_name},
                    True,
                ),
            ]
        elif action == "lambda:PutRuntimeManagementConfig":
            read_request = {"FunctionName": text_value("FunctionName")}
            if "Qualifier" in request:
                read_request["Qualifier"] = text_value("Qualifier")
            specifications = [
                ("lambda:GetRuntimeManagementConfig", read_request, False)
            ]
        elif action == "lambda:PutFunctionConcurrency":
            specifications = [
                (
                    "lambda:GetFunctionConcurrency",
                    {"FunctionName": text_value("FunctionName")},
                    False,
                )
            ]
        elif action == "logs:CreateLogGroup":
            log_group_name = text_value("logGroupName")
            specifications = [
                (
                    "logs:DescribeLogGroups",
                    {"logGroupNamePrefix": log_group_name, "limit": 1},
                    True,
                ),
                (
                    "logs:ListTagsForResource",
                    {"resourceArn": call.target_arn},
                    False,
                ),
            ]
        elif action == "logs:PutRetentionPolicy":
            specifications = [
                (
                    "logs:DescribeLogGroups",
                    {
                        "logGroupNamePrefix": text_value("logGroupName"),
                        "limit": 1,
                    },
                    True,
                )
            ]
        else:
            _fail("MUTATION_READBACK_CONTRACT_MISSING")
        result: list[PlannedCall] = []
        for read_action, read_request, complete in specifications:
            service, api_action = read_action.split(":", 1)
            result.append(
                planned_call_from_record(
                    call.phase,
                    {
                        "sequence": call.sequence,
                        "service": service,
                        "api_action": api_action,
                        "allowed_action": read_action,
                        "target_arn": call.target_arn,
                        "request": read_request,
                        "request_digest": canonical_digest(read_request),
                        "mutation": False,
                        "complete_pagination_required": complete,
                        "attempt_limit": 1,
                        "retry_permitted": False,
                    },
                )
            )
        return tuple(result)

    def reconciliation_readback_calls(
        self, ambiguous_call: PlannedCall
    ) -> tuple[PlannedCall, ...]:
        """Return the write-free contract for the exact ambiguous operation."""

        _validate_call(ambiguous_call)
        if ambiguous_call.kind is CallKind.IDENTITY:
            _fail("RECONCILIATION_IDENTITY_OPERATION_FORBIDDEN")
        if ambiguous_call.kind in {CallKind.READ, CallKind.WAITER}:
            calls = (ambiguous_call,)
        elif ambiguous_call.allowed_action == "lambda:InvokeFunction":
            _fail("RECONCILIATION_CONTRACT_UNAVAILABLE")
        else:
            calls = self._mutation_readback_calls(ambiguous_call)
        if not calls or any(
            item.kind not in {CallKind.READ, CallKind.WAITER} for item in calls
        ):
            _fail("RECONCILIATION_READ_ONLY_CONTRACT_INVALID")
        return calls

    def _receipt_context_gate(
        self,
        call: PlannedCall,
        *,
        receipt_plan: Mapping[str, Any] | None,
        expected_receipt_digest: str | None,
    ) -> None:
        if call.allowed_action != "lambda:InvokeFunction":
            if receipt_plan is not None or expected_receipt_digest is not None:
                _fail("CAUSAL_RECEIPT_CONTEXT_UNEXPECTED")
            return
        if self._accepted_causal_receipt_binding is not None:
            _fail("CAUSAL_RECEIPT_ALREADY_ACCEPTED")
        if (
            not isinstance(receipt_plan, Mapping)
            or call.phase != "LEDGER_FACTORY_INVOKER"
            or call.request.get("InvocationType") != "RequestResponse"
            or call.request.get("Payload") != "{}"
        ):
            _fail("CAUSAL_RECEIPT_CONTEXT_REQUIRED")
        if expected_receipt_digest is not None and (
            not isinstance(expected_receipt_digest, str)
            or _DIGEST_RE.fullmatch(expected_receipt_digest) is None
        ):
            _fail("CAUSAL_RECEIPT_EXPECTATION_INVALID")
        plan_digest = receipt_plan.get("plan_digest")
        if (
            not isinstance(plan_digest, str)
            or _DIGEST_RE.fullmatch(plan_digest) is None
        ):
            _fail("CAUSAL_RECEIPT_PLAN_INVALID")
        phases = receipt_plan.get("authorization_phases")
        if not isinstance(phases, Sequence) or isinstance(phases, (str, bytes)):
            _fail("CAUSAL_RECEIPT_PLAN_INVALID")
        candidates: list[Mapping[str, Any]] = []
        for phase_record in phases:
            if not isinstance(phase_record, Mapping):
                _fail("CAUSAL_RECEIPT_PLAN_INVALID")
            if phase_record.get("phase") != "LEDGER_FACTORY_INVOKER":
                continue
            operations = phase_record.get("operations")
            if not isinstance(operations, Sequence) or isinstance(
                operations, (str, bytes)
            ):
                _fail("CAUSAL_RECEIPT_PLAN_INVALID")
            candidates.extend(
                item
                for item in operations
                if isinstance(item, Mapping)
                and item.get("allowed_action") == "lambda:InvokeFunction"
            )
        if len(candidates) != 1:
            _fail("CAUSAL_RECEIPT_PLAN_INVALID")
        try:
            bound_call = planned_call_from_record(
                "LEDGER_FACTORY_INVOKER", candidates[0]
            )
        except LiveProviderError as exc:
            raise LiveProviderError("CAUSAL_RECEIPT_PLAN_INVALID") from exc
        if bound_call != call:
            _fail("CAUSAL_RECEIPT_OPERATION_SUBSTITUTION")
        function = receipt_plan.get("ledger_factory_function")
        if (
            not isinstance(function, Mapping)
            or function.get("immutable_version_arn") != call.target_arn
            or call.request.get("FunctionName") != call.target_arn
        ):
            _fail("CAUSAL_RECEIPT_FUNCTION_BINDING_INVALID")

    def _validate_immediate_readback(
        self,
        mutation: PlannedCall,
        write_response: Mapping[str, Any],
        readbacks: Sequence[tuple[PlannedCall, ProviderResult]],
    ) -> dict[str, Any]:
        if not readbacks:
            _fail("MUTATION_READBACK_INCOMPLETE")
        responses: dict[str, Mapping[str, Any]] = {}
        for readback_call, readback in readbacks:
            if readback.outcome is not Outcome.SUCCEEDED:
                _fail("MUTATION_READBACK_INCOMPLETE")
            action = readback_call.allowed_action
            if readback.operation_digest != readback_call.operation_digest:
                _fail("MUTATION_READBACK_MALFORMED")
            if action in responses:
                _fail("MUTATION_READBACK_MALFORMED")
            responses[action] = readback.response
        request = mutation.request
        action = mutation.allowed_action

        def response(read_action: str) -> Mapping[str, Any]:
            selected = responses.get(read_action)
            if not isinstance(selected, Mapping):
                _fail("MUTATION_READBACK_INCOMPLETE")
            return selected

        def policy_document(value: Any) -> Mapping[str, Any]:
            if isinstance(value, Mapping):
                return _snapshot(value)
            if not isinstance(value, str) or not value:
                _fail("MUTATION_READBACK_MALFORMED")
            candidates = (value, unquote(value))
            for candidate in candidates:
                try:
                    parsed = json.loads(candidate)
                except (json.JSONDecodeError, TypeError):
                    continue
                if isinstance(parsed, Mapping):
                    return _snapshot(parsed)
            _fail("MUTATION_READBACK_MALFORMED")

        def canonical_tags(value: Any) -> list[dict[str, str]]:
            if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
                _fail("MUTATION_READBACK_MALFORMED")
            tags: list[dict[str, str]] = []
            for item in value:
                if (
                    not isinstance(item, Mapping)
                    or set(item) != {"Key", "Value"}
                    or not isinstance(item.get("Key"), str)
                    or not isinstance(item.get("Value"), str)
                ):
                    _fail("MUTATION_READBACK_MALFORMED")
                tags.append({"Key": item["Key"], "Value": item["Value"]})
            if len({item["Key"] for item in tags}) != len(tags):
                _fail("MUTATION_READBACK_MALFORMED")
            return sorted(tags, key=lambda item: (item["Key"], item["Value"]))

        def configuration_matches(configuration: Any) -> bool:
            if not isinstance(configuration, Mapping):
                return False
            exact_fields = (
                "FunctionName",
                "Runtime",
                "Role",
                "Handler",
                "Description",
                "Timeout",
                "MemorySize",
                "PackageType",
                "Architectures",
                "LoggingConfig",
            )
            if any(configuration.get(key) != request.get(key) for key in exact_fields):
                return False
            if configuration.get("FunctionArn") != mutation.target_arn:
                return False
            expected_variables = request.get("Environment", {}).get("Variables")
            observed_environment = configuration.get("Environment")
            observed_variables = (
                observed_environment.get("Variables")
                if isinstance(observed_environment, Mapping)
                else None
            )
            if observed_variables != {
                "redacted": True,
                "value_digest": canonical_digest(expected_variables),
            }:
                return False
            defaults = {
                "Layers": [],
                "FileSystemConfigs": [],
                "TracingConfig": {"Mode": "PassThrough"},
                "EphemeralStorage": {"Size": 512},
            }
            if any(configuration.get(key) != value for key, value in defaults.items()):
                return False
            vpc = configuration.get("VpcConfig")
            if (
                not isinstance(vpc, Mapping)
                or vpc.get("SubnetIds") != []
                or vpc.get("SecurityGroupIds") != []
                or vpc.get("VpcId") != ""
                or vpc.get("Ipv6AllowedForDualStack", False) is not False
            ):
                return False
            if configuration.get("KMSKeyArn") not in (None, ""):
                return False
            dead_letter = configuration.get("DeadLetterConfig")
            if dead_letter not in (None, {}):
                return False
            return True

        if action == "iam:CreatePolicy":
            policy = response("iam:GetPolicy").get("Policy")
            version = response("iam:GetPolicyVersion").get("PolicyVersion")
            tags = response("iam:ListPolicyTags").get("Tags")
            valid = (
                isinstance(policy, Mapping)
                and policy.get("Arn") == mutation.target_arn
                and policy.get("PolicyName") == request.get("PolicyName")
                and policy.get("Path") == request.get("Path")
                and policy.get("Description") == request.get("Description")
                and policy.get("DefaultVersionId") == "v1"
                and isinstance(version, Mapping)
                and version.get("VersionId") == "v1"
                and version.get("IsDefaultVersion") is True
                and policy_document(version.get("Document"))
                == policy_document(request.get("PolicyDocument"))
                and canonical_tags(tags) == canonical_tags(request.get("Tags"))
            )
        elif action in {"iam:CreateRole", "iam:PutRolePermissionsBoundary"}:
            role = response("iam:GetRole").get("Role")
            boundary = role.get("PermissionsBoundary") if isinstance(role, Mapping) else None
            expected_boundary = request.get("PermissionsBoundary")
            valid = (
                isinstance(role, Mapping)
                and role.get("Arn") == mutation.target_arn
                and role.get("RoleName") == request.get("RoleName")
                and isinstance(boundary, Mapping)
                and boundary.get("PermissionsBoundaryArn") == expected_boundary
            )
            if action == "iam:CreateRole":
                tags = response("iam:ListRoleTags").get("Tags")
                valid = (
                    valid
                    and role.get("Path") == request.get("Path")
                    and role.get("Description") == request.get("Description")
                    and role.get("MaxSessionDuration")
                    == request.get("MaxSessionDuration")
                    and policy_document(role.get("AssumeRolePolicyDocument"))
                    == policy_document(request.get("AssumeRolePolicyDocument"))
                    and canonical_tags(tags) == canonical_tags(request.get("Tags"))
                )
        elif action in {"iam:AttachRolePolicy", "iam:DetachRolePolicy"}:
            policies = response("iam:ListAttachedRolePolicies").get(
                "AttachedPolicies"
            )
            if not isinstance(policies, Sequence) or isinstance(
                policies, (str, bytes)
            ):
                _fail("MUTATION_READBACK_MALFORMED")
            observed = {
                item.get("PolicyArn")
                for item in policies
                if isinstance(item, Mapping) and isinstance(item.get("PolicyArn"), str)
            }
            present = request.get("PolicyArn") in observed
            valid = present if action == "iam:AttachRolePolicy" else not present
        elif action == "lambda:CreateFunction":
            function_response = response("lambda:GetFunction")
            configuration = function_response.get("Configuration")
            signing = response("lambda:GetFunctionCodeSigningConfig")
            tags = response("lambda:ListTags").get("Tags")
            versions = response("lambda:ListVersionsByFunction").get("Versions")
            write_version = write_response.get("Version")
            write_code_sha256 = write_response.get("CodeSha256")
            expected_code_sha256 = mutation.expected_code_sha256
            if expected_code_sha256 is None:
                _fail("CREATE_FUNCTION_CODE_BINDING_REQUIRED")
            expected_versions = {"$LATEST"}
            if request.get("Publish") is True:
                # CreateFunction is an absence-only operation in this closed
                # plan, so its first immutable publication must be version 1.
                if write_version != "1":
                    _fail("MUTATION_READBACK_MALFORMED")
                expected_versions.add("1")
            elif write_version != "$LATEST":
                _fail("MUTATION_READBACK_MALFORMED")
            if write_code_sha256 != expected_code_sha256:
                _fail("MUTATION_READBACK_MALFORMED")
            if not isinstance(versions, Sequence) or isinstance(
                versions, (str, bytes)
            ):
                _fail("MUTATION_READBACK_MALFORMED")
            observed_versions: dict[str, str] = {}
            for item in versions:
                if (
                    not isinstance(item, Mapping)
                    or not isinstance(item.get("Version"), str)
                    or item["Version"] in observed_versions
                    or item.get("CodeSha256") != expected_code_sha256
                ):
                    _fail("MUTATION_READBACK_MALFORMED")
                observed_versions[item["Version"]] = expected_code_sha256
            valid = (
                configuration_matches(configuration)
                and signing.get("CodeSigningConfigArn")
                == request.get("CodeSigningConfigArn")
                and isinstance(tags, Mapping)
                and dict(tags) == request.get("Tags")
                and set(observed_versions) == expected_versions
                and isinstance(configuration, Mapping)
                and configuration.get("Version") == "$LATEST"
                and configuration.get("CodeSha256") == expected_code_sha256
            )
        elif action == "lambda:PutRuntimeManagementConfig":
            runtime = response("lambda:GetRuntimeManagementConfig")
            qualifier = request.get("Qualifier")
            expected_arns = {mutation.target_arn}
            if isinstance(qualifier, str) and qualifier:
                expected_arns.add(f"{mutation.target_arn}:{qualifier}")
            valid = (
                runtime.get("FunctionArn") in expected_arns
                and runtime.get("UpdateRuntimeOn")
                == request.get("UpdateRuntimeOn")
            )
            if request.get("UpdateRuntimeOn") == "Manual":
                valid = valid and runtime.get("RuntimeVersionArn") == request.get(
                    "RuntimeVersionArn"
                )
        elif action == "lambda:PutFunctionConcurrency":
            valid = response("lambda:GetFunctionConcurrency").get(
                "ReservedConcurrentExecutions"
            ) == request.get("ReservedConcurrentExecutions")
        elif action in {"logs:CreateLogGroup", "logs:PutRetentionPolicy"}:
            groups = response("logs:DescribeLogGroups").get("logGroups")
            if not isinstance(groups, Sequence) or isinstance(groups, (str, bytes)):
                _fail("MUTATION_READBACK_MALFORMED")
            selected = [
                item
                for item in groups
                if isinstance(item, Mapping)
                and item.get("logGroupName") == request.get("logGroupName")
            ]
            valid = len(selected) == 1
            if action == "logs:CreateLogGroup" and valid:
                group = selected[0]
                observed_arn = group.get("logGroupArn", group.get("arn"))
                valid = (
                    isinstance(observed_arn, str)
                    and observed_arn.removesuffix(":*") == mutation.target_arn
                    and group.get("logGroupClass", "STANDARD")
                    == request.get("logGroupClass")
                    and group.get("deletionProtectionEnabled")
                    is request.get("deletionProtectionEnabled")
                    and group.get("kmsKeyId") in (None, "")
                    and response("logs:ListTagsForResource").get("tags")
                    == request.get("tags")
                )
            if action == "logs:PutRetentionPolicy" and valid:
                valid = selected[0].get("retentionInDays") == request.get(
                    "retentionInDays"
                )
        else:
            _fail("MUTATION_READBACK_CONTRACT_MISSING")
        if not valid:
            _fail("MUTATION_READBACK_MISMATCH")
        return {
            "readback_operation_digests": [
                readback.operation_digest for _call, readback in readbacks
            ],
            "readback_response_digests": [
                readback.response_digest for _call, readback in readbacks
            ],
            "state_match": True,
        }

    def _validate_causal_receipt(
        self,
        call: PlannedCall,
        response: Mapping[str, Any],
        *,
        receipt_plan: Mapping[str, Any],
        expected_receipt_digest: str | None,
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        payload = response.get("Payload")
        receipt = payload.get("json") if isinstance(payload, Mapping) else None
        executed = response.get("ExecutedVersion")
        if (
            type(response.get("StatusCode")) is not int
            or response.get("StatusCode") != 200
            or "FunctionError" in response
            or not isinstance(receipt, Mapping)
            or executed != call.target_arn.rsplit(":", 1)[-1]
        ):
            _fail("CAUSAL_RECEIPT_RESPONSE_INVALID")
        observed_receipt_digest = receipt.get("receipt_sha256")
        if (
            not isinstance(observed_receipt_digest, str)
            or _DIGEST_RE.fullmatch(observed_receipt_digest) is None
            or (
                expected_receipt_digest is not None
                and observed_receipt_digest != expected_receipt_digest
            )
        ):
            _fail("CAUSAL_RECEIPT_DIGEST_INVALID")
        try:
            gug365.validate_ledger_factory_causal_receipt(
                receipt_plan,
                receipt=receipt,
                expected_receipt_sha256=observed_receipt_digest,
            )
        except gug365.ServiceRoleMaterializationError as exc:
            raise LiveProviderError("CAUSAL_RECEIPT_NOT_ACCEPTED") from exc
        private_receipt = _snapshot(receipt)
        return (
            {
                "receipt_digest": observed_receipt_digest,
                "receipt_validation_digest": canonical_digest(private_receipt),
                "state_match": True,
                "certification_required": True,
                "activation_authorized": False,
            },
            private_receipt,
        )

    def _ambiguous_after_write(
        self,
        call: PlannedCall,
        *,
        calls_before: int,
        write_response: Mapping[str, Any],
        code: str,
        readbacks: Sequence[tuple[PlannedCall, ProviderResult]] = (),
    ) -> ProviderResult:
        self._reconciliation_required = True
        validation = {
            "operation_digest": call.operation_digest,
            "write_response_digest": canonical_digest(write_response),
            "readback_response_digests": [
                readback.response_digest for _call, readback in readbacks
            ],
            "outcome": Outcome.AMBIGUOUS.value,
            "error_code_digest": canonical_digest(code),
        }
        self._validations.append(validation)
        return self._failed_result(
            call,
            code=code,
            ambiguous=True,
            calls_before=calls_before,
            response={
                "mutation_response": _snapshot(write_response),
                "immediate_readbacks": [
                    readback.private_record() for _call, readback in readbacks
                ],
                "validation_digest": canonical_digest(validation),
            },
        )

    def _invoke_single(
        self,
        call: PlannedCall,
        *,
        receipt_plan: Mapping[str, Any] | None = None,
        expected_receipt_digest: str | None = None,
    ) -> ProviderResult:
        readback_calls: tuple[PlannedCall, ...] = ()
        if call.kind is CallKind.MUTATION:
            if (
                call.allowed_action == "lambda:CreateFunction"
                and call.expected_code_sha256 is None
            ):
                _fail("CREATE_FUNCTION_CODE_BINDING_REQUIRED")
            self._receipt_context_gate(
                call,
                receipt_plan=receipt_plan,
                expected_receipt_digest=expected_receipt_digest,
            )
            readback_calls = self._mutation_readback_calls(call)
        service, method_name = (_READ_METHODS | _MUTATION_METHODS)[call.allowed_action]
        before = self._provider_calls
        raw, code, ambiguous = self._sdk_call(
            call,
            service=service,
            method_name=method_name,
            request=call.request,
            page_ordinal=1,
        )
        if raw is None:
            return self._failed_result(
                call, code=code or "ProviderCallError", ambiguous=ambiguous, calls_before=before
            )
        try:
            normalized = _normalize_response(
                raw, byte_limit=self._config.max_response_bytes
            )
        except LiveProviderError:
            ambiguous = call.kind is CallKind.MUTATION
            if ambiguous:
                self._reconciliation_required = True
            code = "ProviderResponseUnsafe"
            digest = canonical_digest({"response_present": True, "normalized": False})
            self._append_event(
                call,
                request=call.request,
                response_digest=digest,
                outcome=Outcome.AMBIGUOUS if ambiguous else Outcome.FAILED,
                page_ordinal=1,
                error_code=code,
            )
            return self._failed_result(
                call, code=code, ambiguous=ambiguous, calls_before=before
            )
        response_digest = canonical_digest(normalized)
        self._append_event(
            call,
            request=call.request,
            response_digest=response_digest,
            outcome=Outcome.SUCCEEDED,
            page_ordinal=1,
            error_code=None,
        )
        if call.kind is not CallKind.MUTATION:
            return self._successful_result(call, normalized, calls_before=before)
        private_receipt: dict[str, Any] | None = None
        if call.allowed_action == "lambda:InvokeFunction":
            assert isinstance(receipt_plan, Mapping)
            try:
                validation, private_receipt = self._validate_causal_receipt(
                    call,
                    normalized,
                    receipt_plan=receipt_plan,
                    expected_receipt_digest=expected_receipt_digest,
                )
            except LiveProviderError as exc:
                return self._ambiguous_after_write(
                    call,
                    calls_before=before,
                    write_response=normalized,
                    code=exc.code,
                )
            combined = {
                "mutation_response": normalized,
                "causal_receipt_validation": validation,
            }
        else:
            if not readback_calls:
                _fail("MUTATION_READBACK_CONTRACT_MISSING")
            readbacks: list[tuple[PlannedCall, ProviderResult]] = []
            try:
                for readback_call in readback_calls:
                    readbacks.append(
                        (readback_call, self.read_operation(readback_call))
                    )
                validation = self._validate_immediate_readback(
                    call,
                    normalized,
                    readbacks,
                )
            except LiveProviderError as exc:
                return self._ambiguous_after_write(
                    call,
                    calls_before=before,
                    write_response=normalized,
                    code=exc.code,
                    readbacks=readbacks,
                )
            combined = {
                "mutation_response": normalized,
                "immediate_readbacks": [
                    readback.private_record() for _call, readback in readbacks
                ],
                "readback_validation": validation,
            }
        self._validations.append(
            {
                "operation_digest": call.operation_digest,
                "write_response_digest": response_digest,
                "validation_digest": canonical_digest(validation),
                "outcome": Outcome.SUCCEEDED.value,
                "error_code_digest": None,
            }
        )
        result = self._successful_result(call, combined, calls_before=before)
        if private_receipt is not None:
            assert isinstance(receipt_plan, Mapping)
            binding_body = {
                "record_type": (
                    "scanalyze.platform_authority."
                    "gug390_private_causal_receipt_binding.v1"
                ),
                "plan_digest": receipt_plan["plan_digest"],
                "operation_digest": call.operation_digest,
                "provider_result_digest": result.response_digest,
                "receipt_digest": validation["receipt_digest"],
                "identity_receipt_digest": self.identity_receipt.receipt_digest,
                "certification_required": True,
                "activation_authorized": False,
            }
            self._accepted_causal_receipt = private_receipt
            self._accepted_causal_receipt_binding = {
                **binding_body,
                "binding_digest": canonical_digest(binding_body),
            }
        return result

    def _invoke_paginated(self, call: PlannedCall) -> ProviderResult:
        spec = _PAGINATION.get(call.allowed_action)
        if spec is None:
            _fail("PAGINATION_CONTRACT_MISSING")
        request_key, response_key, truncated_key = spec
        service, method_name = _READ_METHODS[call.allowed_action]
        request = _snapshot(call.request)
        pages: list[Mapping[str, Any]] = []
        seen: set[str] = set()
        before = self._provider_calls
        for page_ordinal in range(1, self._config.max_pages + 1):
            raw, code, _ambiguous = self._sdk_call(
                call,
                service=service,
                method_name=method_name,
                request=request,
                page_ordinal=page_ordinal,
            )
            if raw is None:
                partial = _merge_pagination_facts(
                    pages,
                    response_token_key=response_key,
                    truncated_key=truncated_key,
                    byte_limit=self._config.max_response_bytes,
                )
                return self._failed_result(
                    call,
                    code=code or "ProviderReadError",
                    ambiguous=False,
                    calls_before=before,
                    response={"partial_facts": partial},
                )
            try:
                normalized = _normalize_response(
                    raw, byte_limit=self._config.max_response_bytes
                )
            except LiveProviderError as exc:
                self._append_event(
                    call,
                    request=request,
                    response_digest=canonical_digest(
                        {"response_present": True, "normalized": False}
                    ),
                    outcome=Outcome.FAILED,
                    page_ordinal=page_ordinal,
                    error_code=exc.code,
                )
                _fail("PROVIDER_RESPONSE_UNSAFE")
            response_digest = canonical_digest(normalized)
            self._append_event(
                call,
                request=request,
                response_digest=response_digest,
                outcome=Outcome.SUCCEEDED,
                page_ordinal=page_ordinal,
                error_code=None,
            )
            pages.append(normalized)
            token = raw.get(response_key)
            if truncated_key is not None:
                truncated = raw.get(truncated_key)
                if type(truncated) is not bool:
                    _fail("PAGINATION_RESPONSE_INVALID")
                if not truncated:
                    if token not in (None, "", {}):
                        _fail("PAGINATION_RESPONSE_INVALID")
                    facts = _merge_pagination_facts(
                        pages,
                        response_token_key=response_key,
                        truncated_key=truncated_key,
                        byte_limit=self._config.max_response_bytes,
                    )
                    return self._successful_result(
                        call, facts, calls_before=before
                    )
                if token in (None, "", {}):
                    _fail("PAGINATION_RESPONSE_INCOMPLETE")
            elif token in (None, "", {}):
                facts = _merge_pagination_facts(
                    pages,
                    response_token_key=response_key,
                    truncated_key=truncated_key,
                    byte_limit=self._config.max_response_bytes,
                )
                return self._successful_result(
                    call, facts, calls_before=before
                )
            token_digest = canonical_digest(token)
            if token_digest in seen:
                _fail("PAGINATION_TOKEN_REPEATED")
            seen.add(token_digest)
            request = {**request, request_key: _snapshot(token)}
        _fail("PAGINATION_LIMIT_EXCEEDED")

    def _invoke_waiter(self, call: PlannedCall) -> ProviderResult:
        waiter = _WAITER_ACTION[f"{call.service}:{call.api_action}"]
        _action, service, method_name = waiter
        before = self._provider_calls
        deadline = time.monotonic() + call.timeout_seconds
        last: Mapping[str, Any] = {}
        attempts = min(call.max_poll_attempts, self._config.max_wait_attempts)
        for page_ordinal in range(1, attempts + 1):
            raw, code, _ambiguous = self._sdk_call(
                call,
                service=service,
                method_name=method_name,
                request=call.request,
                page_ordinal=page_ordinal,
            )
            if raw is None:
                self._reconciliation_required = True
                return self._failed_result(
                    call,
                    code=code or "WaiterReadError",
                    ambiguous=True,
                    calls_before=before,
                )
            try:
                normalized = _normalize_response(
                    raw, byte_limit=self._config.max_response_bytes
                )
            except LiveProviderError as exc:
                self._append_event(
                    call,
                    request=call.request,
                    response_digest=canonical_digest(
                        {"response_present": True, "normalized": False}
                    ),
                    outcome=Outcome.AMBIGUOUS,
                    page_ordinal=page_ordinal,
                    error_code=exc.code,
                )
                self._reconciliation_required = True
                return self._failed_result(
                    call,
                    code="WaiterResponseUnsafe",
                    ambiguous=True,
                    calls_before=before,
                )
            last = normalized
            response_digest = canonical_digest(normalized)
            self._append_event(
                call,
                request=call.request,
                response_digest=response_digest,
                outcome=Outcome.SUCCEEDED,
                page_ordinal=page_ordinal,
                error_code=None,
            )
            if call.service == "lambda":
                ready = (
                    raw.get("State") == "Active"
                    and raw.get("LastUpdateStatus") == "Successful"
                )
                terminal_failure = raw.get("State") == "Failed" or raw.get(
                    "LastUpdateStatus"
                ) == "Failed"
            else:
                table = raw.get("Table")
                ready = isinstance(table, Mapping) and table.get("TableStatus") == "ACTIVE"
                terminal_failure = isinstance(table, Mapping) and table.get(
                    "TableStatus"
                ) in {"DELETING", "ARCHIVING"}
            if ready:
                return self._successful_result(call, last, calls_before=before)
            if terminal_failure:
                return self._failed_result(
                    call,
                    code="WaiterTerminalState",
                    ambiguous=False,
                    calls_before=before,
                    response=last,
                )
            if page_ordinal == attempts or time.monotonic() >= deadline:
                break
            time.sleep(min(call.poll_interval_seconds, max(0.0, deadline - time.monotonic())))
        self._reconciliation_required = True
        return self._failed_result(
            call,
            code="WaiterBoundExceeded",
            ambiguous=True,
            calls_before=before,
            response=last,
        )

    def _invoke_phase_identity(self, call: PlannedCall) -> ProviderResult:
        """Consume the phase's own STS operation and prove session continuity."""

        before = self._provider_calls
        raw, code, _ambiguous = self._sdk_call(
            call,
            service="sts",
            method_name="get_caller_identity",
            request=call.request,
            page_ordinal=1,
        )
        if raw is None:
            return self._failed_result(
                call,
                code=code or "PhaseIdentityUnavailable",
                ambiguous=False,
                calls_before=before,
            )
        account = raw.get("Account")
        principal = raw.get("Arn")
        user_id = raw.get("UserId")
        identity = {"Account": account, "Arn": principal, "UserId": user_id}
        same_session = (
            isinstance(account, str)
            and isinstance(principal, str)
            and isinstance(user_id, str)
            and canonical_digest(account) == self.identity_receipt.account_digest
            and canonical_digest(principal) == self.identity_receipt.principal_digest
            and canonical_digest(identity) == self.identity_receipt.session_digest
        )
        projection = {
            **self.identity_projection,
            "same_session": same_session,
            "phase_digest": canonical_digest(call.phase),
        }
        response_digest = canonical_digest(identity)
        outcome = Outcome.SUCCEEDED if same_session else Outcome.FAILED
        error = None if same_session else "PhaseIdentityMismatch"
        self._append_event(
            call,
            request=call.request,
            response_digest=response_digest,
            outcome=outcome,
            page_ordinal=1,
            error_code=error,
        )
        validation = {
            "operation_digest": call.operation_digest,
            "identity_receipt_digest": self.identity_receipt.receipt_digest,
            "phase_identity_response_digest": response_digest,
            "same_session": same_session,
            "outcome": outcome.value,
        }
        self._validations.append(validation)
        if not same_session:
            return self._failed_result(
                call,
                code=error or "PhaseIdentityMismatch",
                ambiguous=False,
                calls_before=before,
                response=projection,
            )
        return self._successful_result(call, projection, calls_before=before)

    def invoke_operation(
        self,
        operation: PlannedCall,
        *,
        receipt_plan: Mapping[str, Any] | None = None,
        expected_receipt_digest: str | None = None,
    ) -> ProviderResult:
        """Perform one closed operation; mutations are never retried."""

        _validate_call(operation)
        if self._closed:
            _fail("PROVIDER_ALREADY_FINALIZED")
        if operation.kind is CallKind.IDENTITY:
            if receipt_plan is not None or expected_receipt_digest is not None:
                _fail("CAUSAL_RECEIPT_CONTEXT_UNEXPECTED")
            return self._invoke_phase_identity(operation)
        if operation.kind is CallKind.WAITER:
            if receipt_plan is not None or expected_receipt_digest is not None:
                _fail("CAUSAL_RECEIPT_CONTEXT_UNEXPECTED")
            return self._invoke_waiter(operation)
        if operation.complete_pagination_required:
            if operation.kind is not CallKind.READ:
                _fail("PAGINATION_KIND_INVALID")
            if receipt_plan is not None or expected_receipt_digest is not None:
                _fail("CAUSAL_RECEIPT_CONTEXT_UNEXPECTED")
            if operation.allowed_action in _SINGLE_PAGE_COMPLETE:
                return self._invoke_single(operation)
            return self._invoke_paginated(operation)
        return self._invoke_single(
            operation,
            receipt_plan=receipt_plan,
            expected_receipt_digest=expected_receipt_digest,
        )

    execute = invoke_operation

    def read_operation(self, operation: PlannedCall) -> ProviderResult:
        _validate_call(operation)
        if operation.kind not in {CallKind.READ, CallKind.WAITER}:
            _fail("READ_OPERATION_REQUIRED")
        return self.invoke_operation(operation)

    def capture_readbacks(
        self,
        plan: Mapping[str, Any],
        *,
        stage: str | None = None,
        slot_projections: Mapping[str, str] | None = None,
    ) -> dict[str, Any]:
        """Capture one complete private readback projection from a sealed plan."""

        if not isinstance(plan, Mapping) or not isinstance(plan.get("plan_digest"), str):
            _fail("READBACK_PLAN_INVALID")
        plan_digest = plan["plan_digest"]
        if (
            _DIGEST_RE.fullmatch(plan_digest) is None
            or plan_digest
            != canonical_digest({key: value for key, value in plan.items() if key != "plan_digest"})
        ):
            _fail("READBACK_PLAN_DIGEST_INVALID")
        if stage is not None and (
            not isinstance(stage, str) or _STAGE_RE.fullmatch(stage) is None
        ):
            _fail("READBACK_STAGE_INVALID")
        records = plan.get("planned_readbacks")
        if not isinstance(records, Sequence) or isinstance(records, (str, bytes)):
            _fail("READBACK_PLAN_INVALID")
        selected: list[Mapping[str, Any]] = []
        for record in records:
            if not isinstance(record, Mapping):
                _fail("READBACK_PLAN_INVALID")
            record_stage = record.get("verification_stage")
            if record_stage is None or record_stage == stage:
                selected.append(record)
        if not selected:
            _fail("READBACK_STAGE_EMPTY")
        sequences = [record.get("sequence") for record in selected]
        if any(type(item) is not int for item in sequences) or len(sequences) != len(set(sequences)):
            _fail("READBACK_SEQUENCE_INVALID")
        results: list[dict[str, Any]] = []
        for record in sorted(selected, key=lambda item: int(item["sequence"])):
            call = planned_call_from_record(
                "READBACK", record, slot_projections=slot_projections
            )
            result = self.read_operation(call)
            expected_absence = record.get("absence_expected_before_create") is True
            accepted_absence = expected_absence and result.error_code in {
                "NoSuchEntity",
                "NoSuchEntityException",
                "ResourceNotFoundException",
            }
            if result.outcome is not Outcome.SUCCEEDED and not accepted_absence:
                _fail("READBACK_CAPTURE_INCOMPLETE")
            results.append(result.private_record())
        body = {
            "record_type": "scanalyze.platform_authority.gug390_private_readback_snapshot.v1",
            "plan_digest": plan_digest,
            "stage_digest": canonical_digest(stage),
            "identity_receipt_digest": self.identity_receipt.receipt_digest,
            "result_count": len(results),
            "results": results,
            "complete": True,
        }
        return {**body, "snapshot_digest": canonical_digest(body)}

    def transcript_summary(self) -> TranscriptReceipt:
        complete = (
            bool(self._events)
            and len(self._events) == self._provider_calls
            and self._events[0]["allowed_action"] == "sts:GetCallerIdentity"
            and [item["ordinal"] for item in self._events]
            == list(range(1, self._provider_calls + 1))
        )
        body = {
            "record_type": "scanalyze.platform_authority.gug390_provider_transcript.v1",
            "region": self._config.region,
            "provider_mode": self.provider_mode,
            "profile_binding_digest": self._profile_binding_digest,
            "identity_receipt_digest": self.identity_receipt.receipt_digest,
            "transcript_digest": canonical_digest(
                {"calls": self._events, "validations": self._validations}
            ),
            "provider_calls": self._provider_calls,
            "provider_mutation_calls": self._provider_mutations,
            "aws_calls": self._provider_calls if self._concrete else 0,
            "aws_mutations": self._provider_mutations if self._concrete else 0,
            "live_provider_evidence": self._concrete and self._provider_calls > 0,
            "reconciliation_required": self._reconciliation_required,
            "accepted_causal_receipt_binding_digest": (
                None
                if self._accepted_causal_receipt_binding is None
                else self._accepted_causal_receipt_binding["binding_digest"]
            ),
            "complete": complete,
        }
        return TranscriptReceipt(**body, summary_digest=canonical_digest(body))

    def finalize(self) -> TranscriptReceipt:
        if self._closed:
            _fail("PROVIDER_ALREADY_FINALIZED")
        receipt = self.transcript_summary()
        if not receipt.complete:
            _fail("PROVIDER_TRANSCRIPT_INCOMPLETE")
        self._closed = True
        return receipt


def build_live_provider(config: ProviderConfig) -> LiveProvider:
    """Production-only convenience factory; it accepts no injected SDK."""

    return LiveProvider.open(config)


__all__ = [
    "ALLOWED_ACTIONS",
    "AUTHORITY_ACCOUNT_ID",
    "CallKind",
    "IdentityReceipt",
    "LiveProvider",
    "LiveProviderError",
    "MUTATION_ACTIONS",
    "Outcome",
    "PHASE_ACTIONS",
    "PlannedCall",
    "ProviderConfig",
    "ProviderResult",
    "REGION",
    "TranscriptReceipt",
    "build_live_provider",
    "canonical_digest",
    "canonical_json",
    "planned_call_from_record",
]
