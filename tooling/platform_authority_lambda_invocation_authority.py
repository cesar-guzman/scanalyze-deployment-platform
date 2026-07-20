"""Fail-closed Lambda invocation-authority inventory for GUG-218.

The pure analyzer in this module accepts an immutable allowlist plus a raw,
read-only AWS discovery snapshot.  It over-approximates invocation and control
plane authority: an unsupported IAM construct is never treated as safe.  The
public inventory and receipt contain only counts and SHA-256 digests; principal
ARNs, account IDs, function names, and policy documents remain internal.

``AwsReadOnlyInventoryAdapter`` is deliberately separate.  It implements only
List/Get/Describe calls, uses strict pagination, never invokes Lambda, and
never calls an AWS mutation API.
"""
from __future__ import annotations

import fnmatch
import hashlib
import json
import re
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Callable, Iterable, Mapping, Sequence
from urllib.parse import unquote_to_bytes


EXPECTED_AUTHORITY_EDGE_COUNT = 14
INVENTORY_SCOPE = "ALL_ENABLED_REGIONS_AND_GLOBAL_IAM"

INVENTORY_REVIEW_SAFE = "REVIEW_SAFE_REPORT_ONLY"
INVENTORY_FOREIGN_AUTHORITY = "FOREIGN_AUTHORITY_PRESENT"
INVENTORY_INCOMPLETE = "INVENTORY_INCOMPLETE"
INVENTORY_UNSUPPORTED = "POLICY_SEMANTICS_UNSUPPORTED"
INVENTORY_DRIFT = "DRIFT_DETECTED"

RECEIPT_REVIEW_REQUIRED = "PREFLIGHT_PASSED_REVIEW_REQUIRED"
RECEIPT_UNSAFE = "BLOCKED_UNSAFE_AUTHORITY"
RECEIPT_ACCESS_DENIED = "BLOCKED_ACCESS_DENIED"
RECEIPT_INCOMPLETE = "BLOCKED_INCOMPLETE"
RECEIPT_AMBIGUOUS = "BLOCKED_AMBIGUOUS"
RECEIPT_UNVERIFIED_SOURCE = "BLOCKED_UNVERIFIED_SOURCE"
RECEIPT_DRIFT = "BLOCKED_DRIFT"

EVIDENCE_SOURCE_AWS_READ_ONLY = "AWS_READ_ONLY"
EVIDENCE_SOURCE_OFFLINE_UNVERIFIED = "OFFLINE_UNVERIFIED"
EVIDENCE_SOURCE_MODES = frozenset(
    {EVIDENCE_SOURCE_AWS_READ_ONLY, EVIDENCE_SOURCE_OFFLINE_UNVERIFIED}
)
INVENTORY_OFFLINE_UNVERIFIED = "OFFLINE_UNVERIFIED"
RAW_SNAPSHOT_FORMAT = "GUG218_AWS_DISCOVERY_V1"

COVERAGE_SURFACES = (
    "region_discovery",
    "lambda_functions",
    "lambda_aliases",
    "lambda_versions",
    "lambda_function_urls",
    "lambda_resource_policies",
    "lambda_event_source_mappings",
    "iam_account_authorization",
)
COVERAGE_STATUSES = frozenset({"COMPLETE", "ACCESS_DENIED", "INCOMPLETE", "AMBIGUOUS"})
EXPECTED_ALIASES = frozenset({"classify", "retire", "reconcile"})
PUBLISHED_CONFIGURATION_FIELDS = (
    "Architectures",
    "CapacityProviderConfig",
    "CodeSize",
    "ConfigSha256",
    "DeadLetterConfig",
    "Description",
    "DurableConfig",
    "Environment",
    "EphemeralStorage",
    "FileSystemConfigs",
    "Handler",
    "ImageConfigResponse",
    "KMSKeyArn",
    "Layers",
    "LoggingConfig",
    "MasterArn",
    "MemorySize",
    "PackageType",
    "Role",
    "Runtime",
    "RuntimeVersionConfig",
    "SigningJobArn",
    "SigningProfileVersionArn",
    "SnapStart",
    "TenancyConfig",
    "Timeout",
    "TracingConfig",
    "VpcConfig",
)
PUBLISHED_CONFIGURATION_METADATA_FIELDS = frozenset(
    {
        "CodeSha256",
        "FunctionArn",
        "FunctionName",
        "LastModified",
        "LastUpdateStatus",
        "LastUpdateStatusReason",
        "LastUpdateStatusReasonCode",
        "RevisionId",
        "State",
        "StateReason",
        "StateReasonCode",
        "Version",
    }
)
REVIEWED_FUNCTION_CONFIGURATION_RESPONSE_FIELDS = frozenset(
    PUBLISHED_CONFIGURATION_FIELDS
) | PUBLISHED_CONFIGURATION_METADATA_FIELDS
EXPECTED_FORBIDDEN_AUTHORITY_CLASSES = frozenset(
    {
        "PUBLIC_PRINCIPAL",
        "WILDCARD_ACTION",
        "WILDCARD_RESOURCE",
        "FUNCTION_URL_NONE",
        "UNQUALIFIED_FUNCTION",
        "LATEST_VERSION",
        "NUMERIC_VERSION",
        "ALTERNATE_ALIAS",
        "CROSS_ACCOUNT_PRINCIPAL",
        "SERVICE_PRINCIPAL",
        "FEDERATED_PRINCIPAL",
        "ALTERNATE_TRUST",
        "UNSUPPORTED_POLICY_SEMANTICS",
        "EVENT_SOURCE_MAPPING",
        "AUTHORITY_MUTATION",
    }
)
EXPECTED_ALLOWLIST_EDGE_SHAPES = frozenset(
    {
        (
            "INVOCATION",
            source_type,
            duty,
            target_scope,
            action,
            condition_class,
        )
        for source_type in ("LAMBDA_RESOURCE_POLICY", "IAM_ROLE_INLINE_POLICY")
        for duty, targets in (
            ("classifier", ("EXACT_CLASSIFY_ALIAS",)),
            (
                "independent_approver",
                ("EXACT_RETIRE_ALIAS", "EXACT_RECONCILE_ALIAS"),
            ),
        )
        for target_scope in targets
        for action, condition_class in (
            ("lambda:InvokeFunctionUrl", "FUNCTION_URL_AUTH_TYPE_AWS_IAM"),
            ("lambda:InvokeFunction", "INVOKED_VIA_FUNCTION_URL_TRUE"),
        )
    }
    | {
        (
            "TRUST",
            "IAM_ROLE_TRUST_POLICY",
            duty,
            target_scope,
            "sts:AssumeRole",
            "EXACT_PERMISSION_SET_TRUST",
        )
        for duty, target_scope in (
            ("classifier", "CLASSIFIER_INVOKER_ROLE"),
            ("independent_approver", "APPROVER_INVOKER_ROLE"),
        )
    }
)

INVOCATION_ACTIONS = (
    "lambda:InvokeFunctionUrl",
    "lambda:InvokeFunction",
    "lambda:InvokeAsync",
)
LAMBDA_MUTATION_ACTIONS = (
    "lambda:AddPermission",
    "lambda:RemovePermission",
    "lambda:CreateFunctionUrlConfig",
    "lambda:UpdateFunctionUrlConfig",
    "lambda:DeleteFunctionUrlConfig",
    "lambda:CreateAlias",
    "lambda:UpdateAlias",
    "lambda:DeleteAlias",
    "lambda:UpdateFunctionCode",
    "lambda:UpdateFunctionConfiguration",
    "lambda:PutFunctionConcurrency",
    "lambda:DeleteFunctionConcurrency",
    "lambda:PublishVersion",
    "lambda:PutFunctionEventInvokeConfig",
    "lambda:UpdateFunctionEventInvokeConfig",
    "lambda:DeleteFunctionEventInvokeConfig",
    "lambda:CreateEventSourceMapping",
    "lambda:UpdateEventSourceMapping",
    "lambda:DeleteEventSourceMapping",
    "lambda:PutFunctionCodeSigningConfig",
    "lambda:DeleteFunctionCodeSigningConfig",
    "lambda:DeleteFunction",
    "lambda:CreateFunction",
)
IAM_MUTATION_ACTIONS = (
    "iam:AddClientIDToOpenIDConnectProvider",
    "iam:AddRoleToInstanceProfile",
    "iam:AddUserToGroup",
    "iam:AttachGroupPolicy",
    "iam:PutRolePolicy",
    "iam:DeleteRolePolicy",
    "iam:AttachRolePolicy",
    "iam:DetachRolePolicy",
    "iam:AttachUserPolicy",
    "iam:ChangePassword",
    "iam:CreateAccessKey",
    "iam:CreateAccountAlias",
    "iam:CreateGroup",
    "iam:CreateInstanceProfile",
    "iam:CreateLoginProfile",
    "iam:CreateOpenIDConnectProvider",
    "iam:CreatePolicy",
    "iam:UpdateAssumeRolePolicy",
    "iam:CreateRole",
    "iam:CreateSAMLProvider",
    "iam:CreateServiceLinkedRole",
    "iam:CreateServiceSpecificCredential",
    "iam:CreateSigningCertificate",
    "iam:CreateUser",
    "iam:CreateVirtualMFADevice",
    "iam:DeactivateMFADevice",
    "iam:DeleteAccessKey",
    "iam:DeleteAccountAlias",
    "iam:DeleteAccountPasswordPolicy",
    "iam:DeleteGroup",
    "iam:DeleteGroupPolicy",
    "iam:DeleteInstanceProfile",
    "iam:DeleteLoginProfile",
    "iam:DeleteOpenIDConnectProvider",
    "iam:DeletePolicy",
    "iam:PutRolePermissionsBoundary",
    "iam:DeleteRolePermissionsBoundary",
    "iam:DeleteRole",
    "iam:DeleteSAMLProvider",
    "iam:DeleteServerCertificate",
    "iam:DeleteServiceLinkedRole",
    "iam:DeleteServiceSpecificCredential",
    "iam:DeleteSigningCertificate",
    "iam:DeleteSSHPublicKey",
    "iam:DeleteUser",
    "iam:DeleteUserPermissionsBoundary",
    "iam:DeleteUserPolicy",
    "iam:DeleteVirtualMFADevice",
    "iam:DetachGroupPolicy",
    "iam:DetachUserPolicy",
    "iam:EnableMFADevice",
    "iam:PassRole",
    "iam:PutGroupPolicy",
    "iam:PutUserPermissionsBoundary",
    "iam:PutUserPolicy",
    "iam:RemoveClientIDFromOpenIDConnectProvider",
    "iam:RemoveRoleFromInstanceProfile",
    "iam:RemoveUserFromGroup",
    "iam:ResetServiceSpecificCredential",
    "iam:SetSecurityTokenServicePreferences",
    "iam:TagOpenIDConnectProvider",
    "iam:TagPolicy",
    "iam:TagRole",
    "iam:TagSAMLProvider",
    "iam:TagServerCertificate",
    "iam:TagUser",
    "iam:UntagOpenIDConnectProvider",
    "iam:UntagPolicy",
    "iam:UntagRole",
    "iam:UntagSAMLProvider",
    "iam:UntagServerCertificate",
    "iam:UntagUser",
    "iam:UpdateAccessKey",
    "iam:UpdateAccountPasswordPolicy",
    "iam:UpdateGroup",
    "iam:UpdateLoginProfile",
    "iam:UpdateOpenIDConnectProviderThumbprint",
    "iam:UpdateRole",
    "iam:UpdateSAMLProvider",
    "iam:UpdateServerCertificate",
    "iam:UpdateServiceSpecificCredential",
    "iam:UpdateSigningCertificate",
    "iam:UpdateSSHPublicKey",
    "iam:UpdateUser",
    "iam:UploadServerCertificate",
    "iam:UploadSigningCertificate",
    "iam:UploadSSHPublicKey",
    "iam:CreatePolicyVersion",
    "iam:SetDefaultPolicyVersion",
    "iam:DeletePolicyVersion",
)
CLOUDFORMATION_MUTATION_ACTIONS = (
    "cloudformation:CreateStack",
    "cloudformation:UpdateStack",
    "cloudformation:DeleteStack",
    "cloudformation:CreateChangeSet",
    "cloudformation:ExecuteChangeSet",
    "cloudformation:DeleteChangeSet",
    "cloudformation:SetStackPolicy",
    "cloudformation:CreateStackSet",
    "cloudformation:UpdateStackSet",
    "cloudformation:CreateStackInstances",
    "cloudformation:UpdateStackInstances",
)
SENSITIVE_ACTIONS = (
    *INVOCATION_ACTIONS,
    *LAMBDA_MUTATION_ACTIONS,
    *IAM_MUTATION_ACTIONS,
    *CLOUDFORMATION_MUTATION_ACTIONS,
)
EXPLICIT_READ_ONLY_ACTIONS = frozenset(
    {
        "cloudformation:EstimateTemplateCost",
        "cloudformation:ValidateTemplate",
        "iam:GenerateCredentialReport",
        "iam:GenerateOrganizationsAccessReport",
        "iam:GenerateServiceLastAccessedDetails",
        "iam:SimulateCustomPolicy",
        "iam:SimulatePrincipalPolicy",
    }
)

ACCOUNT_ID = re.compile(r"^[0-9]{12}$")
REGION = re.compile(r"^[a-z]{2}(?:-gov)?-[a-z]+-[0-9]$")
FUNCTION_NAME = re.compile(r"^[A-Za-z0-9-_]{1,64}$")
DIGEST = re.compile(r"^sha256:[a-f0-9]{64}$")
BASE64_SHA256 = re.compile(r"^[A-Za-z0-9+/]{43}=$")
TIMESTAMP = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")
MAX_PAGES = 1000


class AuthorityInventoryError(RuntimeError):
    """Sanitized fail-closed inventory failure."""

    def __init__(self, code: str) -> None:
        self.code = code if re.fullmatch(r"[A-Z][A-Z0-9_]{2,79}", code) else "AUTHORITY_INVENTORY_DENIED"
        super().__init__(self.code)


def _json_safe(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(key): _json_safe(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_safe(item) for item in value]
    if isinstance(value, datetime):
        return value.astimezone(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    raise AuthorityInventoryError("AWS_RESPONSE_VALUE_UNSUPPORTED")


def canonical_digest(value: Any) -> str:
    encoded = json.dumps(
        _json_safe(value), sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def digest_text(value: str) -> str:
    if not isinstance(value, str) or not value:
        raise AuthorityInventoryError("DIGEST_SOURCE_INVALID")
    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()


def _parse_time(value: str, code: str) -> datetime:
    if not isinstance(value, str) or TIMESTAMP.fullmatch(value) is None:
        raise AuthorityInventoryError(code)
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise AuthorityInventoryError(code) from exc
    return parsed.astimezone(UTC)


def _utc_string(value: datetime) -> str:
    if value.tzinfo is None:
        raise AuthorityInventoryError("TIMESTAMP_MUST_BE_TIMEZONE_AWARE")
    return value.astimezone(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _now_utc() -> datetime:
    return datetime.now(tz=UTC).replace(microsecond=0)


def _seal_raw_snapshot(snapshot: Mapping[str, Any]) -> dict[str, Any]:
    sealed = dict(snapshot)
    sealed.pop("snapshot_digest", None)
    sealed["snapshot_digest"] = canonical_digest(sealed)
    return sealed


def _canonical_sts_principal_arn(
    value: object, *, partition: str, account_id: str
) -> str:
    """Validate and return the exact STS caller ARN used for collection.

    The ARN remains private to the raw snapshot.  Public records contain only
    its SHA-256 digest.  Exact account and partition binding prevents a caller
    from relabelling evidence collected under another authority account.
    """

    if not isinstance(value, str) or value != value.strip() or not value:
        raise AuthorityInventoryError("COLLECTOR_PRINCIPAL_ARN_INVALID")
    prefix = f"arn:{partition}:sts::{account_id}:assumed-role/"
    match = re.fullmatch(
        re.escape(prefix) + r"([^/\s]{1,64})(?:/[^/\s]{1,128})?",
        value,
    )
    if match is None:
        raise AuthorityInventoryError("COLLECTOR_PRINCIPAL_ARN_INVALID")
    return prefix + match.group(1)


def _strict_string_list(value: object, code: str) -> tuple[str, ...]:
    values = (value,) if isinstance(value, str) else value
    if (
        not isinstance(values, (list, tuple))
        or not values
        or not all(isinstance(item, str) and item for item in values)
    ):
        raise AuthorityInventoryError(code)
    return tuple(values)


def _strict_policy_document(value: object) -> Mapping[str, Any]:
    if isinstance(value, str):
        try:
            value = json.loads(value, object_pairs_hook=_reject_duplicate_keys)
        except json.JSONDecodeError as initial_error:
            if "%" not in value:
                raise AuthorityInventoryError("POLICY_DOCUMENT_MALFORMED") from initial_error
            if re.search(r"%(?![0-9A-Fa-f]{2})", value):
                raise AuthorityInventoryError("POLICY_DOCUMENT_PERCENT_ENCODING_INVALID")
            try:
                decoded = unquote_to_bytes(value).decode("utf-8", errors="strict")
            except UnicodeDecodeError as exc:
                raise AuthorityInventoryError("POLICY_DOCUMENT_PERCENT_ENCODING_INVALID") from exc
            if re.search(r"%[0-9A-Fa-f]{2}", decoded):
                raise AuthorityInventoryError("POLICY_DOCUMENT_DOUBLE_ENCODING_FORBIDDEN")
            try:
                value = json.loads(decoded, object_pairs_hook=_reject_duplicate_keys)
            except json.JSONDecodeError as exc:
                raise AuthorityInventoryError("POLICY_DOCUMENT_MALFORMED") from exc
    if not isinstance(value, Mapping):
        raise AuthorityInventoryError("POLICY_DOCUMENT_MALFORMED")
    if value.get("Version") != "2012-10-17":
        raise AuthorityInventoryError("POLICY_DOCUMENT_MALFORMED")
    statements = value.get("Statement")
    if not isinstance(statements, (list, Mapping)):
        raise AuthorityInventoryError("POLICY_DOCUMENT_MALFORMED")
    return value


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise AuthorityInventoryError("JSON_DUPLICATE_KEY")
        result[key] = value
    return result


@dataclass(frozen=True, slots=True)
class TargetBinding:
    """Trusted, non-secret identity of the exact Lambda authority target."""

    authority_account_id: str
    region: str
    function_name: str
    partition: str = "aws"

    def __post_init__(self) -> None:
        if ACCOUNT_ID.fullmatch(self.authority_account_id) is None:
            raise AuthorityInventoryError("AUTHORITY_ACCOUNT_INVALID")
        if REGION.fullmatch(self.region) is None:
            raise AuthorityInventoryError("TARGET_REGION_INVALID")
        if FUNCTION_NAME.fullmatch(self.function_name) is None:
            raise AuthorityInventoryError("FUNCTION_NAME_INVALID")
        if self.partition not in {"aws", "aws-us-gov", "aws-cn"}:
            raise AuthorityInventoryError("AWS_PARTITION_INVALID")

    @property
    def function_arn(self) -> str:
        return (
            f"arn:{self.partition}:lambda:{self.region}:{self.authority_account_id}:"
            f"function:{self.function_name}"
        )

    def alias_arn(self, alias: str) -> str:
        if alias not in EXPECTED_ALIASES:
            raise AuthorityInventoryError("ALIAS_INVALID")
        return f"{self.function_arn}:{alias}"


def _coverage(status: str, items: Sequence[Any], pages: int) -> dict[str, Any]:
    if status not in COVERAGE_STATUSES or pages < 0:
        raise AuthorityInventoryError("COVERAGE_INVALID")
    return {
        "status": status,
        "page_count": pages,
        "item_count": len(items),
        "evidence_digest": canonical_digest(items),
    }


def _condition_class(condition: object, action: str, *, trust: bool = False) -> str:
    if not condition:
        return "MISSING"
    if not isinstance(condition, Mapping):
        return "UNSUPPORTED"
    normalized = _json_safe(condition)
    if trust:
        arn_equals = normalized.get("ArnEquals")
        if (
            isinstance(arn_equals, Mapping)
            and set(normalized) == {"ArnEquals"}
            and set(arn_equals) == {"aws:PrincipalArn"}
            and isinstance(arn_equals.get("aws:PrincipalArn"), str)
        ):
            return "EXACT_PERMISSION_SET_TRUST"
        return "WILDCARD" if "*" in json.dumps(normalized, sort_keys=True) else "UNSUPPORTED"
    if action == "lambda:InvokeFunctionUrl" and normalized == {
        "StringEquals": {"lambda:FunctionUrlAuthType": "AWS_IAM"}
    }:
        return "FUNCTION_URL_AUTH_TYPE_AWS_IAM"
    if action == "lambda:InvokeFunction" and normalized in (
        {"Bool": {"lambda:InvokedViaFunctionUrl": "true"}},
        {"Bool": {"lambda:InvokedViaFunctionUrl": True}},
    ):
        return "INVOKED_VIA_FUNCTION_URL_TRUE"
    return "WILDCARD" if "*" in json.dumps(normalized, sort_keys=True) else "UNSUPPORTED"


def _action_matches(pattern: str, action: str) -> bool:
    return fnmatch.fnmatchcase(action.lower(), pattern.lower())


def _allowed_sensitive_actions(statement: Mapping[str, Any]) -> tuple[str, ...]:
    if statement.get("Effect") != "Allow":
        return ()
    has_action = "Action" in statement
    has_not_action = "NotAction" in statement
    if has_action == has_not_action:
        raise AuthorityInventoryError("POLICY_ACTION_SEMANTICS_UNSUPPORTED")
    patterns = _strict_string_list(
        statement["Action"] if has_action else statement["NotAction"],
        "POLICY_ACTION_SEMANTICS_UNSUPPORTED",
    )
    if has_action:
        return tuple(
            action
            for action in SENSITIVE_ACTIONS
            if any(_action_matches(pattern, action) for pattern in patterns)
        )
    return tuple(
        action
        for action in SENSITIVE_ACTIONS
        if not any(_action_matches(pattern, action) for pattern in patterns)
    )


def _has_unknown_authority_action(statement: Mapping[str, Any]) -> bool:
    """Reject future/unreviewed authority verbs instead of dropping them."""

    if statement.get("Effect") != "Allow":
        return False
    if "NotAction" in statement:
        return True
    if "Action" not in statement:
        return True
    patterns = _strict_string_list(
        statement["Action"], "POLICY_ACTION_SEMANTICS_UNSUPPORTED"
    )
    for pattern in patterns:
        parts = pattern.split(":", 1)
        if len(parts) != 2 or parts[0].lower() not in {
            "iam",
            "lambda",
            "cloudformation",
        }:
            continue
        verb = parts[1]
        if verb.lower().startswith(("get", "list", "describe")):
            continue
        if pattern in EXPLICIT_READ_ONLY_ACTIONS:
            continue
        if any(_action_matches(pattern, action) for action in SENSITIVE_ACTIONS):
            continue
        return True
    return False


def _resource_applies(statement: Mapping[str, Any], resource: str) -> bool:
    has_resource = "Resource" in statement
    has_not_resource = "NotResource" in statement
    if has_resource == has_not_resource:
        raise AuthorityInventoryError("POLICY_RESOURCE_SEMANTICS_UNSUPPORTED")
    patterns = _strict_string_list(
        statement["Resource"] if has_resource else statement["NotResource"],
        "POLICY_RESOURCE_SEMANTICS_UNSUPPORTED",
    )
    matched = any(fnmatch.fnmatchcase(resource, pattern) for pattern in patterns)
    return matched if has_resource else not matched


def _statements(document: Mapping[str, Any]) -> tuple[Mapping[str, Any], ...]:
    value = document.get("Statement")
    items = [value] if isinstance(value, Mapping) else value
    if not isinstance(items, list) or not items or not all(isinstance(item, Mapping) for item in items):
        raise AuthorityInventoryError("POLICY_DOCUMENT_MALFORMED")
    return tuple(items)


def _principal_values(principal: object) -> tuple[tuple[str, str], ...]:
    if principal == "*":
        return (("AWS", "*"),)
    if not isinstance(principal, Mapping) or not principal:
        raise AuthorityInventoryError("POLICY_PRINCIPAL_UNSUPPORTED")
    values: list[tuple[str, str]] = []
    for kind, raw in principal.items():
        if kind not in {"AWS", "Service", "Federated", "CanonicalUser"}:
            raise AuthorityInventoryError("POLICY_PRINCIPAL_UNSUPPORTED")
        for item in _strict_string_list(raw, "POLICY_PRINCIPAL_UNSUPPORTED"):
            values.append((str(kind), item))
    return tuple(values)


def _action_class(action: str) -> str:
    return {
        "lambda:InvokeFunctionUrl": "INVOKE_FUNCTION_URL",
        "lambda:InvokeFunction": "INVOKE_FUNCTION",
        "lambda:InvokeAsync": "INVOKE_ASYNC",
        "sts:AssumeRole": "ASSUME_ROLE",
    }.get(action, "UNKNOWN")


def _target_scope(binding: TargetBinding, resource: str) -> str:
    if any(character in resource for character in "*?["):
        return "WILDCARD"
    if resource == binding.alias_arn("classify"):
        return "EXACT_CLASSIFY_ALIAS"
    if resource == binding.alias_arn("retire"):
        return "EXACT_RETIRE_ALIAS"
    if resource == binding.alias_arn("reconcile"):
        return "EXACT_RECONCILE_ALIAS"
    if resource == binding.function_arn:
        return "UNQUALIFIED_FUNCTION"
    if resource == f"{binding.function_arn}:$LATEST":
        return "LATEST_VERSION"
    if re.fullmatch(re.escape(binding.function_arn) + r":[0-9]+", resource):
        return "NUMERIC_VERSION"
    if resource.startswith(binding.function_arn + ":"):
        return "ALTERNATE_ALIAS"
    if ":function:" in resource:
        return "OTHER_FUNCTION"
    return "UNKNOWN"


def _is_target_function_pattern(binding: TargetBinding, resource: str) -> bool:
    """Return True when a glob can preauthorize this function or qualifiers."""

    if not any(character in resource for character in "*?["):
        return False
    wildcard_offset = min(
        offset for character in "*?[" if (offset := resource.find(character)) >= 0
    )
    literal_prefix = resource[:wildcard_offset]
    return (
        resource.startswith(binding.function_arn)
        or binding.function_arn.startswith(literal_prefix)
    )


def _expected_digest_sets(allowlist: Mapping[str, Any]) -> dict[str, set[str]]:
    result: dict[str, set[str]] = {
        "classifier_roles": set(),
        "approver_roles": set(),
        "classifier_permission_sets": set(),
        "approver_permission_sets": set(),
        "classifier_resources": set(),
        "approver_resources": set(),
    }
    edges = allowlist.get("expected_authority_edges")
    if not isinstance(edges, list) or len(edges) != EXPECTED_AUTHORITY_EDGE_COUNT:
        raise AuthorityInventoryError("ALLOWLIST_EDGE_COUNT_INVALID")
    for edge in edges:
        if not isinstance(edge, Mapping):
            raise AuthorityInventoryError("ALLOWLIST_EDGE_INVALID")
        principal_digest = edge.get("principal_digest")
        resource_digest = edge.get("resource_digest")
        if not isinstance(principal_digest, str) or DIGEST.fullmatch(principal_digest) is None:
            raise AuthorityInventoryError("ALLOWLIST_EDGE_INVALID")
        if not isinstance(resource_digest, str) or DIGEST.fullmatch(resource_digest) is None:
            raise AuthorityInventoryError("ALLOWLIST_EDGE_INVALID")
        duty = edge.get("duty")
        source_type = edge.get("source_type")
        if duty == "classifier":
            result["classifier_resources"].add(resource_digest)
            bucket = "classifier_permission_sets" if source_type == "IAM_ROLE_TRUST_POLICY" else "classifier_roles"
            result[bucket].add(principal_digest)
        elif duty == "independent_approver":
            result["approver_resources"].add(resource_digest)
            bucket = "approver_permission_sets" if source_type == "IAM_ROLE_TRUST_POLICY" else "approver_roles"
            result[bucket].add(principal_digest)
        else:
            raise AuthorityInventoryError("ALLOWLIST_EDGE_INVALID")
    return result


def _principal_kind(
    principal: str,
    principal_type: str,
    expected: Mapping[str, set[str]],
    account_id: str,
) -> tuple[str, str, str]:
    principal_digest = digest_text(principal)
    if principal_digest in expected["classifier_roles"]:
        return "EXACT_CLASSIFIER_ROLE", principal_digest, "classifier"
    if principal_digest in expected["approver_roles"]:
        return "EXACT_APPROVER_ROLE", principal_digest, "independent_approver"
    if principal_digest in expected["classifier_permission_sets"]:
        return "EXACT_CLASSIFIER_PERMISSION_SET", principal_digest, "classifier"
    if principal_digest in expected["approver_permission_sets"]:
        return "EXACT_APPROVER_PERMISSION_SET", principal_digest, "independent_approver"
    if principal == "*":
        return "PUBLIC", principal_digest, "none"
    if principal_type == "Service":
        return "SERVICE", principal_digest, "none"
    if principal_type == "Federated":
        return "FEDERATED", principal_digest, "none"
    if ACCOUNT_ID.fullmatch(principal):
        return (
            "SAME_ACCOUNT_ROOT" if principal == account_id else "CROSS_ACCOUNT",
            principal_digest,
            "none",
        )
    if f"::{account_id}:root" in principal:
        return "SAME_ACCOUNT_ROOT", principal_digest, "none"
    arn_account = re.search(r"^arn:[^:]+:[^:]*:[^:]*:([0-9]{12}):", principal)
    if arn_account and arn_account.group(1) != account_id:
        return "CROSS_ACCOUNT", principal_digest, "none"
    if ":role/" in principal or ":assumed-role/" in principal:
        return "LOCAL_ROLE", principal_digest, "none"
    if ":user/" in principal:
        return "LOCAL_USER", principal_digest, "none"
    if ":group/" in principal:
        return "LOCAL_GROUP", principal_digest, "none"
    return "UNKNOWN", principal_digest, "none"


def _inventory_edge(
    *,
    authority_class: str,
    source_type: str,
    duty: str,
    target_scope: str,
    action_class: str,
    condition_class: str,
    principal_kind: str,
    principal_digest: str,
    resource_digest: str,
    source_document_digest: str,
    verdict: str,
    reason_code: str,
) -> dict[str, Any]:
    return {
        "authority_class": authority_class,
        "source_type": source_type,
        "duty": duty,
        "target_scope": target_scope,
        "action_class": action_class,
        "condition_class": condition_class,
        "principal_kind": principal_kind,
        "principal_digest": principal_digest,
        "resource_digest": resource_digest,
        "source_document_digest": source_document_digest,
        "verdict": verdict,
        "reason_code": reason_code,
    }


def _allowlist_match_key(edge: Mapping[str, Any]) -> tuple[Any, ...]:
    action = {
        "INVOKE_FUNCTION_URL": "lambda:InvokeFunctionUrl",
        "INVOKE_FUNCTION": "lambda:InvokeFunction",
        "ASSUME_ROLE": "sts:AssumeRole",
    }.get(edge.get("action_class"))
    return (
        edge.get("authority_class"),
        edge.get("source_type"),
        edge.get("duty"),
        edge.get("target_scope"),
        action,
        edge.get("condition_class"),
        edge.get("principal_digest"),
        edge.get("resource_digest"),
        edge.get("source_document_digest"),
    )


def _expected_edge_key(edge: Mapping[str, Any]) -> tuple[Any, ...]:
    return (
        edge.get("authority_class"),
        edge.get("source_type"),
        edge.get("duty"),
        edge.get("target_scope"),
        edge.get("action"),
        edge.get("condition_class"),
        edge.get("principal_digest"),
        edge.get("resource_digest"),
        edge.get("source_document_digest"),
    )


def _role_scope(expected: Mapping[str, set[str]], role_arn: str) -> str:
    digest = digest_text(role_arn)
    if digest in expected["classifier_resources"]:
        return "CLASSIFIER_INVOKER_ROLE"
    if digest in expected["approver_resources"]:
        return "APPROVER_INVOKER_ROLE"
    return "UNKNOWN"


def _policy_sources(iam: Mapping[str, Any]) -> Iterable[tuple[str, str, str, Mapping[str, Any]]]:
    managed = iam.get("managed_policy_documents", {})
    if not isinstance(managed, Mapping):
        raise AuthorityInventoryError("MANAGED_POLICY_INVENTORY_MALFORMED")
    definitions = (
        ("users", "Arn", "UserPolicyList", "IAM_USER_INLINE_POLICY"),
        ("groups", "Arn", "GroupPolicyList", "IAM_GROUP_INLINE_POLICY"),
        ("roles", "Arn", "RolePolicyList", "IAM_ROLE_INLINE_POLICY"),
    )
    for collection_name, arn_key, inline_key, source_type in definitions:
        collection = iam.get(collection_name, [])
        if not isinstance(collection, list):
            raise AuthorityInventoryError("IAM_AUTHORIZATION_DETAILS_MALFORMED")
        for entity in collection:
            if not isinstance(entity, Mapping) or not isinstance(entity.get(arn_key), str):
                raise AuthorityInventoryError("IAM_AUTHORIZATION_DETAILS_MALFORMED")
            actor = entity[arn_key]
            inline = entity.get(inline_key, [])
            if not isinstance(inline, list):
                raise AuthorityInventoryError("IAM_AUTHORIZATION_DETAILS_MALFORMED")
            for policy in inline:
                if not isinstance(policy, Mapping):
                    raise AuthorityInventoryError("IAM_AUTHORIZATION_DETAILS_MALFORMED")
                yield actor, source_type, "inline", _strict_policy_document(policy.get("PolicyDocument"))
            attached = entity.get("AttachedManagedPolicies", [])
            if not isinstance(attached, list):
                raise AuthorityInventoryError("IAM_AUTHORIZATION_DETAILS_MALFORMED")
            for reference in attached:
                if not isinstance(reference, Mapping) or not isinstance(reference.get("PolicyArn"), str):
                    raise AuthorityInventoryError("IAM_AUTHORIZATION_DETAILS_MALFORMED")
                arn = reference["PolicyArn"]
                document = managed.get(arn)
                if document is None:
                    raise AuthorityInventoryError("MANAGED_POLICY_DOCUMENT_MISSING")
                managed_type = (
                    "IAM_AWS_MANAGED_POLICY"
                    if arn.startswith("arn:aws:iam::aws:policy/")
                    else "IAM_CUSTOMER_MANAGED_POLICY"
                )
                yield actor, managed_type, arn, _strict_policy_document(document)


def _observed_invocation_resources(
    binding: TargetBinding, lambda_inventory: Mapping[str, Any]
) -> tuple[str, ...]:
    """Return every observed qualifier that can be an identity-policy target."""

    resources = {binding.function_arn}
    for alias in lambda_inventory.get("aliases", []):
        if not isinstance(alias, Mapping):
            raise AuthorityInventoryError("LAMBDA_ALIAS_INVENTORY_MALFORMED")
        arn = alias.get("FunctionArn")
        name = alias.get("Name")
        if isinstance(arn, str):
            resources.add(arn)
        if not isinstance(name, str) or not name:
            raise AuthorityInventoryError("LAMBDA_ALIAS_INVENTORY_MALFORMED")
        resources.add(f"{binding.function_arn}:{name}")
    for version in lambda_inventory.get("versions", []):
        if not isinstance(version, Mapping) or not isinstance(version.get("Version"), str):
            raise AuthorityInventoryError("LAMBDA_VERSION_INVENTORY_MALFORMED")
        version_id = version["Version"]
        arn = version.get("FunctionArn")
        if isinstance(arn, str):
            resources.add(arn)
        resources.add(f"{binding.function_arn}:{version_id}")
    return tuple(sorted(resources))


def _statement_resource_values(statement: Mapping[str, Any]) -> tuple[str, ...]:
    """Return concrete allow resources, conservatively collapsing NotResource."""

    if "Resource" in statement and "NotResource" not in statement:
        resources = _strict_string_list(
            statement["Resource"], "POLICY_RESOURCE_SEMANTICS_UNSUPPORTED"
        )
    elif "NotResource" in statement and "Resource" not in statement:
        resources = _strict_string_list(
            statement["NotResource"], "POLICY_RESOURCE_SEMANTICS_UNSUPPORTED"
        )
    else:
        raise AuthorityInventoryError("POLICY_RESOURCE_SEMANTICS_UNSUPPORTED")
    if any("${" in resource for resource in resources):
        # IAM policy variables are evaluated at request time.  Treating them
        # as literal fnmatch input can hide future or principal-controlled
        # Lambda/IAM authority.
        raise AuthorityInventoryError("POLICY_RESOURCE_VARIABLE_UNSUPPORTED")
    for resource in resources:
        if resource == "*":
            continue
        arn_parts = resource.split(":", 5)
        if (
            len(arn_parts) != 6
            or arn_parts[0] != "arn"
            or not arn_parts[1]
            or not arn_parts[2]
            or not arn_parts[5]
        ):
            # IAM expands incomplete ARNs with wildcard fields.  Literal
            # matching would therefore under-approximate effective authority.
            raise AuthorityInventoryError("POLICY_RESOURCE_ARN_INCOMPLETE")
        if arn_parts[2] == "lambda" and (
            not arn_parts[3]
            or not arn_parts[4]
            or not arn_parts[5].startswith("function:")
            or not arn_parts[5].removeprefix("function:")
        ):
            raise AuthorityInventoryError("POLICY_RESOURCE_ARN_INCOMPLETE")
    return resources if "Resource" in statement else ("*",)


def _identity_edges(
    binding: TargetBinding,
    allowlist: Mapping[str, Any],
    iam: Mapping[str, Any],
    lambda_inventory: Mapping[str, Any],
) -> tuple[list[dict[str, Any]], bool]:
    expected = _expected_digest_sets(allowlist)
    edges: list[dict[str, Any]] = []
    unsupported = False
    invocation_resources = _observed_invocation_resources(binding, lambda_inventory)
    for actor, source_type, _, document in _policy_sources(iam):
        source_digest = canonical_digest(document)
        actor_kind, actor_digest, duty = _principal_kind(actor, "AWS", expected, binding.authority_account_id)
        for statement in _statements(document):
            try:
                if _has_unknown_authority_action(statement):
                    unsupported = True
                actions = _allowed_sensitive_actions(statement)
            except AuthorityInventoryError:
                unsupported = True
                continue
            if not actions:
                continue
            try:
                statement_resources = _statement_resource_values(statement)
            except AuthorityInventoryError:
                unsupported = True
                continue
            condition = statement.get("Condition")
            for action in actions:
                if action in INVOCATION_ACTIONS:
                    candidate_invocation_resources = set(invocation_resources)
                    for stated_resource in statement_resources:
                        if _is_target_function_pattern(binding, stated_resource):
                            # A not-yet-created alias/version can already be
                            # authorized by a qualifier glob.  It must be
                            # represented even when no current Lambda surface
                            # happens to match the pattern.
                            edges.append(
                                _inventory_edge(
                                    authority_class="INVOCATION",
                                    source_type=source_type,
                                    duty=duty,
                                    target_scope="WILDCARD",
                                    action_class=_action_class(action),
                                    condition_class=_condition_class(condition, action),
                                    principal_kind=actor_kind,
                                    principal_digest=actor_digest,
                                    resource_digest=digest_text(stated_resource),
                                    source_document_digest=source_digest,
                                    verdict="PROHIBITED",
                                    reason_code="QUALIFIER_WILDCARD_PREAUTHORIZATION",
                                )
                            )
                        if (
                            not any(character in stated_resource for character in "*?[")
                            and stated_resource.startswith(binding.function_arn + ":")
                        ):
                            # Detect pre-authorized, deleted, alternate, numeric,
                            # or $LATEST qualifiers even when Lambda does not
                            # currently return them in its surface inventory.
                            candidate_invocation_resources.add(stated_resource)
                    for resource in sorted(candidate_invocation_resources):
                        try:
                            applies = _resource_applies(statement, resource)
                        except AuthorityInventoryError:
                            unsupported = True
                            break
                        if not applies:
                            continue
                        edge = _inventory_edge(
                            authority_class="INVOCATION",
                            source_type=source_type,
                            duty=duty,
                            target_scope=_target_scope(binding, resource),
                            action_class=_action_class(action),
                            condition_class=_condition_class(condition, action),
                            principal_kind=actor_kind,
                            principal_digest=actor_digest,
                            resource_digest=digest_text(resource),
                            source_document_digest=source_digest,
                            verdict="UNKNOWN",
                            reason_code="PENDING_ALLOWLIST_COMPARISON",
                        )
                        edges.append(edge)
                    continue
                if action in LAMBDA_MUTATION_ACTIONS:
                    action_class, mutation_source = "MUTATE_LAMBDA_AUTHORITY", "LAMBDA_AUTHORITY_MUTATION"
                    relevant_resources = tuple(
                        sorted(
                            set(invocation_resources)
                            | {
                                resource
                                for resource in statement_resources
                                if resource == "*"
                                or resource.startswith(binding.function_arn)
                                or _is_target_function_pattern(binding, resource)
                            }
                        )
                    )
                elif action in IAM_MUTATION_ACTIONS:
                    action_class, mutation_source = "MUTATE_IAM_AUTHORITY", "IAM_AUTHORITY_MUTATION"
                    relevant_resources = statement_resources
                else:
                    action_class, mutation_source = (
                        "MUTATE_CLOUDFORMATION_AUTHORITY",
                        "CLOUDFORMATION_AUTHORITY",
                    )
                    relevant_resources = statement_resources
                for resource in relevant_resources:
                    if action in (*IAM_MUTATION_ACTIONS, *CLOUDFORMATION_MUTATION_ACTIONS):
                        # Any IAM mutation can create, attach, or change an
                        # authority path; any CloudFormation mutation can
                        # replace Lambda/IAM until an exact owner-stack binding
                        # is separately proved. Resource specificity is not a
                        # safe reason to discard either class.
                        applies = True
                    elif action in LAMBDA_MUTATION_ACTIONS and (
                        resource in statement_resources
                        and (
                            resource == "*"
                            or resource.startswith(binding.function_arn)
                            or _is_target_function_pattern(binding, resource)
                        )
                    ):
                        # Represent latent exact qualifiers and wildcard
                        # preauthorization even when no current Lambda surface
                        # exists for them.
                        applies = True
                    else:
                        try:
                            applies = _resource_applies(statement, resource)
                        except AuthorityInventoryError:
                            unsupported = True
                            break
                    if not applies:
                        continue
                    target_scope = (
                        _target_scope(binding, resource)
                        if action in LAMBDA_MUTATION_ACTIONS
                        else _role_scope(expected, resource)
                        if action in IAM_MUTATION_ACTIONS and _role_scope(expected, resource) != "UNKNOWN"
                        else "WILDCARD"
                        if action in IAM_MUTATION_ACTIONS and "*" in resource
                        else "UNKNOWN"
                        if action in IAM_MUTATION_ACTIONS
                        else "WILDCARD"
                    )
                    edges.append(
                        _inventory_edge(
                            authority_class="AUTHORITY_MUTATION",
                            source_type=mutation_source,
                            duty="none",
                            target_scope=target_scope,
                            action_class=action_class,
                            condition_class=_condition_class(condition, action),
                            principal_kind=actor_kind,
                            principal_digest=actor_digest,
                            resource_digest=digest_text(resource),
                            source_document_digest=source_digest,
                            verdict="PROHIBITED",
                            reason_code="CONTROL_PLANE_MUTATION_AUTHORITY",
                        )
                    )
    return edges, unsupported


def _resource_policy_edges(
    binding: TargetBinding,
    allowlist: Mapping[str, Any],
    policies: Sequence[Any],
) -> tuple[list[dict[str, Any]], bool]:
    expected = _expected_digest_sets(allowlist)
    edges: list[dict[str, Any]] = []
    unsupported = False
    for item in policies:
        if not isinstance(item, Mapping) or not isinstance(item.get("resource_arn"), str):
            unsupported = True
            continue
        resource = item["resource_arn"]
        try:
            document = _strict_policy_document(item.get("policy_document"))
        except AuthorityInventoryError:
            unsupported = True
            continue
        source_digest = canonical_digest(document)
        for statement in _statements(document):
            try:
                if _has_unknown_authority_action(statement):
                    unsupported = True
                actions = _allowed_sensitive_actions(statement)
                principals = _principal_values(statement.get("Principal"))
            except AuthorityInventoryError:
                unsupported = True
                continue
            for action in actions:
                if action not in INVOCATION_ACTIONS:
                    unsupported = True
                    continue
                try:
                    if not _resource_applies(statement, resource):
                        continue
                except AuthorityInventoryError:
                    unsupported = True
                    continue
                for principal_type, principal in principals:
                    kind, principal_digest, duty = _principal_kind(
                        principal, principal_type, expected, binding.authority_account_id
                    )
                    edges.append(
                        _inventory_edge(
                            authority_class="INVOCATION",
                            source_type="LAMBDA_RESOURCE_POLICY",
                            duty=duty,
                            target_scope=_target_scope(binding, resource),
                            action_class=_action_class(action),
                            condition_class=_condition_class(statement.get("Condition"), action),
                            principal_kind=kind,
                            principal_digest=principal_digest,
                            resource_digest=digest_text(resource),
                            source_document_digest=source_digest,
                            verdict="UNKNOWN",
                            reason_code="PENDING_ALLOWLIST_COMPARISON",
                        )
                    )
    return edges, unsupported


def _trust_edges(
    binding: TargetBinding,
    allowlist: Mapping[str, Any],
    roles: Sequence[Any],
) -> tuple[list[dict[str, Any]], bool]:
    expected = _expected_digest_sets(allowlist)
    edges: list[dict[str, Any]] = []
    unsupported = False
    for role in roles:
        if not isinstance(role, Mapping) or not isinstance(role.get("Arn"), str):
            unsupported = True
            continue
        role_arn = role["Arn"]
        scope = _role_scope(expected, role_arn)
        if scope == "UNKNOWN":
            continue
        try:
            document = _strict_policy_document(role.get("AssumeRolePolicyDocument"))
        except AuthorityInventoryError:
            unsupported = True
            continue
        source_digest = canonical_digest(document)
        for statement in _statements(document):
            if statement.get("Effect") != "Allow":
                continue
            try:
                actions = _strict_string_list(statement.get("Action"), "TRUST_POLICY_UNSUPPORTED")
                principals = _principal_values(statement.get("Principal"))
            except AuthorityInventoryError:
                unsupported = True
                continue
            if actions != ("sts:AssumeRole",):
                # Expected invoker roles have exactly one assumptive action.
                # Web identity, SAML, wildcard, TagSession, future STS actions,
                # or mixed actions are alternate trust paths even when the
                # source-document digest was placed into an allowlist.
                unsupported = True
            if not any(_action_matches(pattern, "sts:AssumeRole") for pattern in actions):
                continue
            condition = statement.get("Condition")
            condition_class = _condition_class(condition, "sts:AssumeRole", trust=True)
            effective_principals = principals
            if condition_class == "EXACT_PERMISSION_SET_TRUST":
                value = condition["ArnEquals"]["aws:PrincipalArn"]  # type: ignore[index]
                effective_principals = (("AWS", value),)
            for principal_type, principal in effective_principals:
                kind, principal_digest, duty = _principal_kind(
                    principal, principal_type, expected, binding.authority_account_id
                )
                edges.append(
                    _inventory_edge(
                        authority_class="TRUST",
                        source_type="IAM_ROLE_TRUST_POLICY",
                        duty=duty,
                        target_scope=scope,
                        action_class="ASSUME_ROLE",
                        condition_class=condition_class,
                        principal_kind=kind,
                        principal_digest=principal_digest,
                        resource_digest=digest_text(role_arn),
                        source_document_digest=source_digest,
                        verdict="UNKNOWN",
                        reason_code="PENDING_ALLOWLIST_COMPARISON",
                    )
                )
    return edges, unsupported


def _surface_authority_edges(
    binding: TargetBinding,
    function_urls: Sequence[Any],
    event_sources: Sequence[Any],
) -> tuple[list[dict[str, Any]], bool]:
    edges: list[dict[str, Any]] = []
    drift = False
    expected_url_arns = {binding.alias_arn(alias) for alias in EXPECTED_ALIASES}
    for config in function_urls:
        if not isinstance(config, Mapping) or not isinstance(config.get("FunctionArn"), str):
            drift = True
            continue
        resource = config["FunctionArn"]
        if (
            resource not in expected_url_arns
            or config.get("AuthType") != "AWS_IAM"
            or config.get("InvokeMode", "BUFFERED") != "BUFFERED"
        ):
            edges.append(
                _inventory_edge(
                    authority_class="INVOCATION",
                    source_type="FUNCTION_URL_CONFIGURATION",
                    duty="none",
                    target_scope=_target_scope(binding, resource),
                    action_class="INVOKE_FUNCTION_URL",
                    condition_class="MISSING" if config.get("AuthType") == "NONE" else "ALTERNATE",
                    principal_kind="PUBLIC" if config.get("AuthType") == "NONE" else "UNKNOWN",
                    principal_digest=digest_text("public" if config.get("AuthType") == "NONE" else "unknown"),
                    resource_digest=digest_text(resource),
                    source_document_digest=canonical_digest(config),
                    verdict="PROHIBITED",
                    reason_code="UNEXPECTED_FUNCTION_URL_CONFIGURATION",
                )
            )
    if (
        len(function_urls) != len(expected_url_arns)
        or {
            item.get("FunctionArn")
            for item in function_urls
            if isinstance(item, Mapping)
        }
        != expected_url_arns
    ):
        drift = True
    for source in event_sources:
        if not isinstance(source, Mapping):
            drift = True
            continue
        resource = str(source.get("FunctionArn") or binding.function_arn)
        endpoint_digest = source.get("AuthorityEndpointDigest")
        endpoint_known = isinstance(endpoint_digest, str) and DIGEST.fullmatch(
            endpoint_digest
        ) is not None
        principal_digest = (
            endpoint_digest if endpoint_known else digest_text("unknown-event-source")
        )
        kind = "SERVICE" if endpoint_known else "UNKNOWN"
        edges.append(
            _inventory_edge(
                authority_class="INVOCATION",
                source_type="EVENT_SOURCE_MAPPING",
                duty="none",
                target_scope=_target_scope(binding, resource),
                action_class="EVENT_SOURCE_INVOKE",
                condition_class="MISSING",
                principal_kind=kind,
                principal_digest=principal_digest,
                resource_digest=digest_text(resource),
                source_document_digest=canonical_digest(source),
                verdict="PROHIBITED",
                reason_code="EVENT_SOURCE_AUTHORITY_PRESENT",
            )
        )
    return edges, drift


def _runtime_artifact_drift(
    binding: TargetBinding,
    allowlist: Mapping[str, Any],
    lambda_inventory: Mapping[str, Any],
) -> bool:
    """Bind every expected alias to one reviewed published artifact."""

    expected_code = allowlist.get("broker_artifact_code_sha256")
    if not isinstance(expected_code, str) or BASE64_SHA256.fullmatch(expected_code) is None:
        raise AuthorityInventoryError("BROKER_ARTIFACT_CODE_SHA256_INVALID")
    expected_configuration = allowlist.get("broker_published_configuration_sha256")
    if (
        not isinstance(expected_configuration, str)
        or DIGEST.fullmatch(expected_configuration) is None
    ):
        raise AuthorityInventoryError("BROKER_PUBLISHED_CONFIGURATION_SHA256_INVALID")
    aliases = lambda_inventory.get("aliases", [])
    versions = lambda_inventory.get("versions", [])
    functions = lambda_inventory.get("functions", [])
    if not isinstance(aliases, list) or not isinstance(versions, list) or not isinstance(functions, list):
        raise AuthorityInventoryError("LAMBDA_RUNTIME_INVENTORY_MALFORMED")
    if len(aliases) != len(EXPECTED_ALIASES):
        return True
    alias_versions: set[str] = set()
    for alias in aliases:
        if not isinstance(alias, Mapping):
            return True
        name = alias.get("Name")
        version = alias.get("FunctionVersion")
        routing = alias.get("RoutingConfig")
        if (
            name not in EXPECTED_ALIASES
            or not isinstance(version, str)
            or re.fullmatch(r"[1-9][0-9]*", version) is None
            or alias.get("FunctionArn") not in (
                None,
                binding.alias_arn(str(name)),
            )
            or routing not in (None, {}, {"AdditionalVersionWeights": {}})
        ):
            return True
        alias_versions.add(version)
    if len(alias_versions) != 1:
        return True
    published_version = next(iter(alias_versions))
    selected = [
        version
        for version in versions
        if isinstance(version, Mapping) and version.get("Version") == published_version
    ]
    latest = [
        version
        for version in versions
        if isinstance(version, Mapping) and version.get("Version") == "$LATEST"
    ]
    target_functions = [
        function
        for function in functions
        if isinstance(function, Mapping)
        and function.get("FunctionName") == binding.function_name
        and function.get("FunctionArn") == binding.function_arn
    ]
    return (
        len(selected) != 1
        or selected[0].get("CodeSha256") != expected_code
        or selected[0].get("PublishedConfigurationDigest") != expected_configuration
        or len(latest) != 1
        or latest[0].get("CodeSha256") != expected_code
        or latest[0].get("PublishedConfigurationDigest") != expected_configuration
        or len(target_functions) != 1
        or target_functions[0].get("CodeSha256") != expected_code
        or target_functions[0].get("PublishedConfigurationDigest")
        != expected_configuration
    )


def _mark_expected_edges(
    edges: list[dict[str, Any]], allowlist: Mapping[str, Any]
) -> tuple[list[dict[str, Any]], int]:
    expected_list = allowlist.get("expected_authority_edges")
    if not isinstance(expected_list, list):
        raise AuthorityInventoryError("ALLOWLIST_EDGE_INVALID")
    expected_keys = [_expected_edge_key(edge) for edge in expected_list]
    if len(set(expected_keys)) != EXPECTED_AUTHORITY_EDGE_COUNT:
        raise AuthorityInventoryError("ALLOWLIST_EDGE_DUPLICATE")
    remaining = list(expected_keys)
    matched = 0
    for edge in edges:
        if edge["verdict"] != "UNKNOWN" or edge["reason_code"] != "PENDING_ALLOWLIST_COMPARISON":
            continue
        key = _allowlist_match_key(edge)
        if key in remaining:
            remaining.remove(key)
            edge["verdict"] = "EXPECTED_EXACT"
            edge["reason_code"] = "EXPECTED_ALLOWLIST_EDGE"
            matched += 1
        else:
            edge["verdict"] = "PROHIBITED"
            edge["reason_code"] = "AUTHORITY_EDGE_NOT_ALLOWLISTED"
    return edges, len(remaining)


def _validate_allowlist(allowlist: Mapping[str, Any], binding: TargetBinding) -> None:
    required = {
        "schema_version",
        "record_type",
        "environment",
        "production",
        "inventory_scope",
        "authority_account_id_digest",
        "target_region",
        "source_template_sha256",
        "source_policy_bundle_sha256",
        "broker_artifact_code_sha256",
        "broker_published_configuration_sha256",
        "collector_role_principal_digest",
        "expected_authority_edges",
        "forbidden_authority_classes",
        "live_effect_authorized",
        "created_at",
        "allowlist_digest",
    }
    if not required.issubset(allowlist):
        raise AuthorityInventoryError("ALLOWLIST_MALFORMED")
    if (
        allowlist.get("record_type") != "platform_authority_lambda_invocation_allowlist"
        or allowlist.get("schema_version") != "1"
        or allowlist.get("environment") != "non-production"
        or allowlist.get("production") is not False
        or allowlist.get("inventory_scope") != INVENTORY_SCOPE
        or allowlist.get("target_region") != binding.region
        or allowlist.get("authority_account_id_digest") != digest_text(binding.authority_account_id)
        or allowlist.get("live_effect_authorized") is not False
    ):
        raise AuthorityInventoryError("ALLOWLIST_BINDING_INVALID")
    for key in (
        "source_template_sha256",
        "source_policy_bundle_sha256",
        "collector_role_principal_digest",
        "allowlist_digest",
    ):
        if not isinstance(allowlist.get(key), str) or DIGEST.fullmatch(allowlist[key]) is None:
            raise AuthorityInventoryError("ALLOWLIST_DIGEST_INVALID")
    if (
        not isinstance(allowlist.get("broker_artifact_code_sha256"), str)
        or BASE64_SHA256.fullmatch(allowlist["broker_artifact_code_sha256"]) is None
    ):
        raise AuthorityInventoryError("BROKER_ARTIFACT_CODE_SHA256_INVALID")
    if (
        not isinstance(allowlist.get("broker_published_configuration_sha256"), str)
        or DIGEST.fullmatch(allowlist["broker_published_configuration_sha256"])
        is None
    ):
        raise AuthorityInventoryError(
            "BROKER_PUBLISHED_CONFIGURATION_SHA256_INVALID"
        )
    _parse_time(allowlist["created_at"], "ALLOWLIST_TIMESTAMP_INVALID")
    edges = allowlist["expected_authority_edges"]
    if not isinstance(edges, list) or len(edges) != EXPECTED_AUTHORITY_EDGE_COUNT:
        raise AuthorityInventoryError("ALLOWLIST_EDGE_COUNT_INVALID")
    if len({_expected_edge_key(edge) for edge in edges if isinstance(edge, Mapping)}) != EXPECTED_AUTHORITY_EDGE_COUNT:
        raise AuthorityInventoryError("ALLOWLIST_EDGE_INVALID")
    shapes = {
        (
            edge.get("authority_class"),
            edge.get("source_type"),
            edge.get("duty"),
            edge.get("target_scope"),
            edge.get("action"),
            edge.get("condition_class"),
        )
        for edge in edges
        if isinstance(edge, Mapping)
    }
    if shapes != EXPECTED_ALLOWLIST_EDGE_SHAPES:
        raise AuthorityInventoryError("ALLOWLIST_EDGE_MATRIX_INVALID")
    forbidden = allowlist.get("forbidden_authority_classes")
    if (
        not isinstance(forbidden, list)
        or len(forbidden) != len(set(forbidden))
        or set(forbidden) != EXPECTED_FORBIDDEN_AUTHORITY_CLASSES
    ):
        raise AuthorityInventoryError("ALLOWLIST_FORBIDDEN_CLASSES_INVALID")
    digests = _expected_digest_sets(allowlist)
    if any(
        len(digests[key]) != 1
        for key in (
            "classifier_roles",
            "approver_roles",
            "classifier_permission_sets",
            "approver_permission_sets",
        )
    ):
        raise AuthorityInventoryError("ALLOWLIST_PRINCIPAL_BINDING_INVALID")
    if digests["classifier_roles"] == digests["approver_roles"] or digests[
        "classifier_permission_sets"
    ] == digests["approver_permission_sets"]:
        raise AuthorityInventoryError("ALLOWLIST_DUTY_SEPARATION_INVALID")
    collector_digest = allowlist["collector_role_principal_digest"]
    if collector_digest in set().union(*digests.values()):
        raise AuthorityInventoryError("ALLOWLIST_COLLECTOR_DUTY_SEPARATION_INVALID")
    classifier_role = next(iter(digests["classifier_roles"]))
    approver_role = next(iter(digests["approver_roles"]))
    trust_resources = {
        edge["duty"]: edge["resource_digest"]
        for edge in edges
        if isinstance(edge, Mapping) and edge.get("authority_class") == "TRUST"
    }
    if trust_resources != {
        "classifier": classifier_role,
        "independent_approver": approver_role,
    }:
        raise AuthorityInventoryError("ALLOWLIST_TRUST_BINDING_INVALID")
    calculated = canonical_digest({key: value for key, value in allowlist.items() if key != "allowlist_digest"})
    if calculated != allowlist["allowlist_digest"]:
        raise AuthorityInventoryError("ALLOWLIST_DIGEST_MISMATCH")


def validate_reviewed_allowlist(
    *,
    allowlist: Mapping[str, Any],
    binding: TargetBinding,
    expected_allowlist_digest: str,
) -> str:
    """Validate a reviewed allowlist before any evidence collection.

    ``expected_allowlist_digest`` must arrive through an independently
    reviewed release or deployment contract.  The function first validates
    the complete allowlist, including its canonical self-digest and target
    binding, then proves that the reviewed digest names that exact record.
    The returned collector digest is safe to pass to the AWS adapter for its
    post-STS, pre-inventory principal check.
    """

    _validate_allowlist(allowlist, binding)
    if (
        not isinstance(expected_allowlist_digest, str)
        or DIGEST.fullmatch(expected_allowlist_digest) is None
        or allowlist["allowlist_digest"] != expected_allowlist_digest
    ):
        raise AuthorityInventoryError("REVIEWED_ALLOWLIST_DIGEST_MISMATCH")
    return str(allowlist["collector_role_principal_digest"])


def analyze_authority_inventory(
    *,
    allowlist: Mapping[str, Any],
    snapshot: Mapping[str, Any],
    binding: TargetBinding,
    evidence_source_mode: str,
    decision_at: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Return a sanitized inventory and guard receipt.

    The function performs no I/O.  A safe result remains report-only and
    explicitly requires a separate human/live-enablement review.
    """

    _validate_allowlist(allowlist, binding)
    if evidence_source_mode not in EVIDENCE_SOURCE_MODES:
        raise AuthorityInventoryError("EVIDENCE_SOURCE_MODE_INVALID")
    if snapshot.get("snapshot_format") != RAW_SNAPSHOT_FORMAT:
        raise AuthorityInventoryError("SNAPSHOT_FORMAT_INVALID")
    snapshot_digest = snapshot.get("snapshot_digest")
    if not isinstance(snapshot_digest, str) or DIGEST.fullmatch(snapshot_digest) is None:
        raise AuthorityInventoryError("SNAPSHOT_DIGEST_INVALID")
    if _seal_raw_snapshot(snapshot)["snapshot_digest"] != snapshot_digest:
        raise AuthorityInventoryError("SNAPSHOT_DIGEST_MISMATCH")
    collector_nonce = snapshot.get("collector_nonce")
    if (
        not isinstance(collector_nonce, str)
        or not 1 <= len(collector_nonce) <= 256
        or any(character.isspace() for character in collector_nonce)
    ):
        raise AuthorityInventoryError("COLLECTOR_NONCE_INVALID")
    collector_principal_arn = _canonical_sts_principal_arn(
        snapshot.get("collector_principal_arn"),
        partition=binding.partition,
        account_id=binding.authority_account_id,
    )
    if snapshot.get("collector_principal_arn") != collector_principal_arn:
        raise AuthorityInventoryError("COLLECTOR_PRINCIPAL_NOT_CANONICAL")
    collector_principal_arn_digest = snapshot.get("collector_principal_arn_digest")
    if (
        not isinstance(collector_principal_arn_digest, str)
        or DIGEST.fullmatch(collector_principal_arn_digest) is None
        or collector_principal_arn_digest != digest_text(collector_principal_arn)
    ):
        raise AuthorityInventoryError("COLLECTOR_PRINCIPAL_DIGEST_MISMATCH")
    if allowlist.get("collector_role_principal_digest") != collector_principal_arn_digest:
        raise AuthorityInventoryError("COLLECTOR_PRINCIPAL_NOT_ALLOWLISTED")
    source_started_at = snapshot.get("capture_started_at")
    source_completed_at = snapshot.get("capture_completed_at")
    expires_at = snapshot.get("capture_expires_at")
    if not all(
        isinstance(value, str)
        for value in (source_started_at, source_completed_at, expires_at)
    ):
        raise AuthorityInventoryError("SNAPSHOT_CAPTURE_TIME_MISSING")
    source_started = _parse_time(source_started_at, "SCAN_STARTED_AT_INVALID")
    source_completed = _parse_time(source_completed_at, "SCAN_COMPLETED_AT_INVALID")
    expires = _parse_time(expires_at, "EXPIRES_AT_INVALID")
    decision = _parse_time(decision_at, "DECISION_AT_INVALID")
    if (
        not (source_started <= source_completed <= decision < expires)
        or source_completed - source_started > timedelta(minutes=5)
        or expires - source_completed > timedelta(minutes=5)
        or decision - source_completed > timedelta(minutes=5)
    ):
        raise AuthorityInventoryError("INVENTORY_TIME_WINDOW_INVALID")

    coverage = snapshot.get("coverage")
    if not isinstance(coverage, Mapping) or set(coverage) != set(COVERAGE_SURFACES):
        raise AuthorityInventoryError("COVERAGE_INCOMPLETE")
    normalized_coverage: dict[str, Any] = {}
    for surface in COVERAGE_SURFACES:
        entry = coverage[surface]
        if not isinstance(entry, Mapping) or entry.get("status") not in COVERAGE_STATUSES:
            raise AuthorityInventoryError("COVERAGE_MALFORMED")
        normalized_coverage[surface] = {
            "status": entry["status"],
            "page_count": entry.get("page_count"),
            "item_count": entry.get("item_count"),
            "evidence_digest": entry.get("evidence_digest"),
        }
        if (
            not isinstance(normalized_coverage[surface]["page_count"], int)
            or normalized_coverage[surface]["page_count"] < 0
            or not isinstance(normalized_coverage[surface]["item_count"], int)
            or normalized_coverage[surface]["item_count"] < 0
            or not isinstance(normalized_coverage[surface]["evidence_digest"], str)
            or DIGEST.fullmatch(normalized_coverage[surface]["evidence_digest"]) is None
        ):
            raise AuthorityInventoryError("COVERAGE_MALFORMED")

    lambda_inventory = snapshot.get("lambda")
    iam_inventory = snapshot.get("iam")
    if not isinstance(lambda_inventory, Mapping) or not isinstance(iam_inventory, Mapping):
        raise AuthorityInventoryError("INVENTORY_SNAPSHOT_MALFORMED")
    for key in (
        "functions",
        "aliases",
        "versions",
        "function_urls",
        "resource_policies",
        "event_source_mappings",
        "event_invoke_configs",
    ):
        if not isinstance(lambda_inventory.get(key), list):
            raise AuthorityInventoryError("INVENTORY_SNAPSHOT_MALFORMED")
    for key in ("users", "groups", "roles", "policies"):
        if not isinstance(iam_inventory.get(key), list):
            raise AuthorityInventoryError("INVENTORY_SNAPSHOT_MALFORMED")
    if not isinstance(iam_inventory.get("managed_policy_documents"), Mapping):
        raise AuthorityInventoryError("INVENTORY_SNAPSHOT_MALFORMED")

    evidence_items = {
        "region_discovery": snapshot.get("enabled_regions", []),
        "lambda_functions": lambda_inventory.get("functions", []),
        "lambda_aliases": lambda_inventory.get("aliases", []),
        "lambda_versions": lambda_inventory.get("versions", []),
        "lambda_function_urls": lambda_inventory.get("function_urls", []),
        "lambda_resource_policies": lambda_inventory.get("resource_policies", []),
        "lambda_event_source_mappings": [
            *lambda_inventory.get("event_source_mappings", []),
            *lambda_inventory.get("event_invoke_configs", []),
        ],
        "iam_account_authorization": [
            *iam_inventory.get("users", []),
            *iam_inventory.get("groups", []),
            *iam_inventory.get("roles", []),
            *iam_inventory.get("policies", []),
            iam_inventory.get("managed_policy_documents", {}),
        ],
    }
    for surface, items in evidence_items.items():
        if not isinstance(items, list):
            raise AuthorityInventoryError("INVENTORY_SNAPSHOT_MALFORMED")
        entry = normalized_coverage[surface]
        if (
            entry["status"] == "COMPLETE"
            and (
                entry["item_count"] != len(items)
                or entry["evidence_digest"] != canonical_digest(items)
            )
        ):
            # A collector cannot declare a surface complete while presenting
            # evidence with a different count or digest.
            entry["status"] = "AMBIGUOUS"

    resource_edges, resource_unsupported = _resource_policy_edges(
        binding, allowlist, lambda_inventory.get("resource_policies", [])
    )
    identity_edges, identity_unsupported = _identity_edges(
        binding, allowlist, iam_inventory, lambda_inventory
    )
    trust_edges, trust_unsupported = _trust_edges(
        binding, allowlist, iam_inventory.get("roles", [])
    )
    surface_edges, surface_drift = _surface_authority_edges(
        binding,
        lambda_inventory.get("function_urls", []),
        [
            *lambda_inventory.get("event_source_mappings", []),
            *lambda_inventory.get("event_invoke_configs", []),
        ],
    )
    edges, missing_expected = _mark_expected_edges(
        [*resource_edges, *identity_edges, *trust_edges, *surface_edges], allowlist
    )
    edges.sort(key=canonical_digest)

    aliases = lambda_inventory.get("aliases", [])
    alias_names = {
        item.get("Name")
        for item in aliases
        if isinstance(item, Mapping) and isinstance(item.get("Name"), str)
    }
    functions = lambda_inventory.get("functions", [])
    target_functions = [
        item
        for item in functions
        if isinstance(item, Mapping)
        and item.get("FunctionName") == binding.function_name
        and item.get("FunctionArn") == binding.function_arn
    ]
    structural_drift = (
        len(target_functions) != 1
        or alias_names != EXPECTED_ALIASES
        or surface_drift
        or _runtime_artifact_drift(binding, allowlist, lambda_inventory)
        or missing_expected != 0
    )
    unsupported = resource_unsupported or identity_unsupported or trust_unsupported
    prohibited = sum(edge["verdict"] == "PROHIBITED" for edge in edges)
    unknown = sum(edge["verdict"] == "UNKNOWN" for edge in edges)
    mutation_count = sum(edge["authority_class"] == "AUTHORITY_MUTATION" for edge in edges)

    coverage_statuses = {entry["status"] for entry in normalized_coverage.values()}
    if "ACCESS_DENIED" in coverage_statuses:
        status = INVENTORY_INCOMPLETE
    elif "INCOMPLETE" in coverage_statuses:
        status = INVENTORY_INCOMPLETE
    elif "AMBIGUOUS" in coverage_statuses or unsupported or unknown:
        status = INVENTORY_UNSUPPORTED
    elif prohibited or mutation_count:
        status = INVENTORY_FOREIGN_AUTHORITY
    elif structural_drift:
        status = INVENTORY_DRIFT
    elif len(edges) == EXPECTED_AUTHORITY_EDGE_COUNT:
        status = INVENTORY_REVIEW_SAFE
    else:
        status = INVENTORY_DRIFT

    enabled_regions = snapshot.get("enabled_regions", [])
    scanned_regions = snapshot.get("scanned_regions", [])
    if (
        not isinstance(enabled_regions, list)
        or not isinstance(scanned_regions, list)
        or binding.region not in enabled_regions
        or sorted(scanned_regions) != sorted(enabled_regions)
    ):
        status = INVENTORY_INCOMPLETE

    graph_status = status
    if evidence_source_mode == EVIDENCE_SOURCE_OFFLINE_UNVERIFIED:
        status = INVENTORY_OFFLINE_UNVERIFIED
    inventory: dict[str, Any] = {
        "schema_version": "1",
        "record_type": "platform_authority_lambda_invocation_inventory",
        "environment": "non-production",
        "production": False,
        "inventory_scope": INVENTORY_SCOPE,
        "evidence_source_mode": evidence_source_mode,
        "source_snapshot_digest": snapshot_digest,
        "collector_principal_digest": collector_principal_arn_digest,
        "source_snapshot_started_at": source_started_at,
        "source_snapshot_completed_at": source_completed_at,
        "authority_account_id_digest": digest_text(binding.authority_account_id),
        "target_region": binding.region,
        "scan_id_digest": digest_text(collector_nonce),
        "allowlist_digest": allowlist["allowlist_digest"],
        "source_template_sha256": allowlist["source_template_sha256"],
        "status": status,
        "coverage": normalized_coverage,
        "enabled_region_count": len(enabled_regions),
        "scanned_region_count": len(scanned_regions),
        "authority_edges": edges,
        "expected_edge_count": sum(edge["verdict"] == "EXPECTED_EXACT" for edge in edges),
        "prohibited_edge_count": prohibited,
        "unknown_edge_count": unknown,
        "observed_edge_count": len(edges),
        "mutating_authority_count": mutation_count,
        "unsupported_policy_semantics_detected": unsupported,
        "structural_drift_detected": structural_drift,
        "scan_started_at": decision_at,
        "scan_completed_at": decision_at,
        "expires_at": expires_at,
        "aws_mutation_performed": False,
        "lambda_invocation_performed": False,
        "live_effect_authorized": False,
    }
    inventory["inventory_digest"] = canonical_digest(inventory)

    denied_surfaces = sum(
        entry["status"] == "ACCESS_DENIED" for entry in normalized_coverage.values()
    )
    if evidence_source_mode == EVIDENCE_SOURCE_OFFLINE_UNVERIFIED:
        receipt_status = RECEIPT_UNVERIFIED_SOURCE
        next_control = "COLLECT_AUTHENTICATED_AWS_INVENTORY"
        reason_code = "UNVERIFIED_EVIDENCE_SOURCE"
    elif status == INVENTORY_REVIEW_SAFE:
        receipt_status = RECEIPT_REVIEW_REQUIRED
        next_control = "INDEPENDENT_REVIEW_AND_FRESH_DEPLOYMENT_AUTHORIZATION"
        reason_code = "EXACT_AUTHORITY_REPORT_ONLY"
    elif denied_surfaces:
        receipt_status = RECEIPT_ACCESS_DENIED
        next_control = "RESOLVE_ACCESS_DENIAL"
        reason_code = "READ_ACCESS_DENIED"
    elif status == INVENTORY_FOREIGN_AUTHORITY:
        receipt_status = RECEIPT_UNSAFE
        next_control = "REMOVE_UNSAFE_AUTHORITY"
        reason_code = "UNSAFE_AUTHORITY_PRESENT"
    elif status == INVENTORY_UNSUPPORTED:
        receipt_status = RECEIPT_AMBIGUOUS
        next_control = "RESOLVE_AMBIGUOUS_EVIDENCE"
        reason_code = "AMBIGUOUS_EVIDENCE"
    elif status == INVENTORY_DRIFT:
        receipt_status = RECEIPT_DRIFT
        next_control = "RESOLVE_AUTHORITY_DRIFT"
        reason_code = "AUTHORITY_DRIFT_DETECTED"
    else:
        receipt_status = RECEIPT_INCOMPLETE
        next_control = "COMPLETE_READ_ONLY_INVENTORY"
        reason_code = "INVENTORY_INCOMPLETE"

    receipt: dict[str, Any] = {
        "schema_version": "1",
        "record_type": "platform_authority_lambda_invocation_guard_receipt",
        "environment": "non-production",
        "production": False,
        "evidence_source_mode": evidence_source_mode,
        "source_snapshot_digest": snapshot_digest,
        "collector_principal_digest": collector_principal_arn_digest,
        "source_snapshot_started_at": source_started_at,
        "source_snapshot_completed_at": source_completed_at,
        "authority_account_id_digest": inventory["authority_account_id_digest"],
        "target_region": binding.region,
        "allowlist_digest": allowlist["allowlist_digest"],
        "inventory_digest": inventory["inventory_digest"],
        "status": receipt_status,
        "reason_code": reason_code,
        "coverage_complete": (
            evidence_source_mode == EVIDENCE_SOURCE_AWS_READ_ONLY
            and status != INVENTORY_INCOMPLETE
            and coverage_statuses == {"COMPLETE"}
        ),
        "expected_authority_exact": (
            evidence_source_mode == EVIDENCE_SOURCE_AWS_READ_ONLY
            and graph_status == INVENTORY_REVIEW_SAFE
            and inventory["expected_edge_count"] == EXPECTED_AUTHORITY_EDGE_COUNT
            and prohibited == 0
            and unknown == 0
            and not structural_drift
        ),
        "snapshot_fresh": (
            evidence_source_mode == EVIDENCE_SOURCE_AWS_READ_ONLY
            and source_completed <= decision < expires
        ),
        "prohibited_edge_count": prohibited,
        "unknown_edge_count": unknown,
        "denied_surface_count": denied_surfaces,
        "decision_at": decision_at,
        "expires_at": expires_at,
        "next_required_control": next_control,
        "aws_mutation_performed": False,
        "lambda_invocation_performed": False,
        "deployment_authorized": False,
        "live_retirement_authorized": False,
    }
    receipt["receipt_digest"] = canonical_digest(receipt)
    return inventory, receipt


def _error_code(exc: BaseException) -> str:
    response = getattr(exc, "response", None)
    if isinstance(response, Mapping):
        error = response.get("Error")
        if isinstance(error, Mapping) and isinstance(error.get("Code"), str):
            return error["Code"]
    return type(exc).__name__


def _strict_paginate(
    operation: Callable[..., Mapping[str, Any]],
    *,
    result_key: str,
    request_token: str,
    response_token: str,
    base_kwargs: Mapping[str, Any] | None = None,
    truncated_key: str | None = None,
) -> tuple[list[Any], int]:
    """Exhaust a token API and reject ambiguous or repeated pagination state."""

    items: list[Any] = []
    token: str | None = None
    seen: set[str] = set()
    pages = 0
    while True:
        if pages >= MAX_PAGES:
            raise AuthorityInventoryError("PAGINATION_LIMIT_EXCEEDED")
        kwargs = dict(base_kwargs or {})
        if token is not None:
            kwargs[request_token] = token
        response = operation(**kwargs)
        if not isinstance(response, Mapping) or not isinstance(response.get(result_key), list):
            raise AuthorityInventoryError("PAGINATION_RESPONSE_MALFORMED")
        pages += 1
        items.extend(response[result_key])
        next_token = response.get(response_token)
        if next_token in (None, ""):
            next_token = None
        elif not isinstance(next_token, str):
            raise AuthorityInventoryError("PAGINATION_TOKEN_MALFORMED")
        if truncated_key is not None:
            truncated = response.get(truncated_key)
            if not isinstance(truncated, bool):
                raise AuthorityInventoryError("PAGINATION_TRUNCATION_MISSING")
            if truncated != (next_token is not None):
                raise AuthorityInventoryError("PAGINATION_TRUNCATION_CONFLICT")
        if next_token is None:
            return items, pages
        if next_token in seen or next_token == token:
            raise AuthorityInventoryError("PAGINATION_TOKEN_REPEATED")
        seen.add(next_token)
        token = next_token


def _project_fields(item: object, fields: Sequence[str], code: str) -> dict[str, Any]:
    if not isinstance(item, Mapping):
        raise AuthorityInventoryError(code)
    return {field: _json_safe(item[field]) for field in fields if field in item}


def _published_configuration_digest(item: object, code: str) -> str:
    """Digest reviewed Lambda configuration without retaining raw values."""

    if not isinstance(item, Mapping):
        raise AuthorityInventoryError(code)
    if set(item) - REVIEWED_FUNCTION_CONFIGURATION_RESPONSE_FIELDS:
        raise AuthorityInventoryError("LAMBDA_CONFIGURATION_FIELD_UNREVIEWED")
    configuration = {
        field: _json_safe(item[field])
        for field in PUBLISHED_CONFIGURATION_FIELDS
        if field in item
    }
    required = {
        "Architectures",
        "ConfigSha256",
        "Handler",
        "PackageType",
        "Role",
        "Runtime",
    }
    if not required.issubset(configuration):
        raise AuthorityInventoryError(code)
    if BASE64_SHA256.fullmatch(str(configuration["ConfigSha256"])) is None:
        raise AuthorityInventoryError(code)
    return canonical_digest(configuration)


def _project_functions(items: Sequence[Any], region: str) -> list[dict[str, Any]]:
    projected: list[dict[str, Any]] = []
    for item in items:
        value = _project_fields(
            item,
            ("FunctionName", "FunctionArn", "Version", "CodeSha256"),
            "LAMBDA_FUNCTION_INVENTORY_MALFORMED",
        )
        if not isinstance(value.get("FunctionName"), str) or not isinstance(
            value.get("FunctionArn"), str
        ):
            raise AuthorityInventoryError("LAMBDA_FUNCTION_INVENTORY_MALFORMED")
        value["PublishedConfigurationDigest"] = _published_configuration_digest(
            item, "LAMBDA_FUNCTION_CONFIGURATION_MALFORMED"
        )
        value["InventoryRegion"] = region
        projected.append(value)
    return projected


def _project_aliases(items: Sequence[Any]) -> list[dict[str, Any]]:
    projected: list[dict[str, Any]] = []
    for item in items:
        value = _project_fields(
            item,
            ("Name", "FunctionVersion", "FunctionArn", "RoutingConfig"),
            "LAMBDA_ALIAS_INVENTORY_MALFORMED",
        )
        if not isinstance(value.get("Name"), str) or not isinstance(
            value.get("FunctionVersion"), str
        ):
            raise AuthorityInventoryError("LAMBDA_ALIAS_INVENTORY_MALFORMED")
        routing = value.get("RoutingConfig")
        if routing is not None:
            if not isinstance(routing, Mapping):
                raise AuthorityInventoryError("LAMBDA_ALIAS_INVENTORY_MALFORMED")
            if set(routing) - {"AdditionalVersionWeights"}:
                raise AuthorityInventoryError(
                    "LAMBDA_ALIAS_ROUTING_SEMANTICS_UNSUPPORTED"
                )
            weights = routing.get("AdditionalVersionWeights", {})
            if not isinstance(weights, Mapping):
                raise AuthorityInventoryError("LAMBDA_ALIAS_INVENTORY_MALFORMED")
            value["RoutingConfig"] = {
                "AdditionalVersionWeights": _json_safe(weights)
            }
        projected.append(value)
    return projected


def _project_versions(items: Sequence[Any]) -> list[dict[str, Any]]:
    projected: list[dict[str, Any]] = []
    for item in items:
        value = _project_fields(
            item,
            ("Version", "FunctionArn", "CodeSha256"),
            "LAMBDA_VERSION_INVENTORY_MALFORMED",
        )
        if not isinstance(value.get("Version"), str):
            raise AuthorityInventoryError("LAMBDA_VERSION_INVENTORY_MALFORMED")
        value["PublishedConfigurationDigest"] = _published_configuration_digest(
            item, "LAMBDA_VERSION_CONFIGURATION_MALFORMED"
        )
        projected.append(value)
    return projected


def _project_function_urls(items: Sequence[Any]) -> list[dict[str, Any]]:
    projected: list[dict[str, Any]] = []
    for item in items:
        value = _project_fields(
            item,
            ("FunctionArn", "AuthType", "InvokeMode"),
            "LAMBDA_FUNCTION_URL_INVENTORY_MALFORMED",
        )
        if not isinstance(value.get("FunctionArn"), str) or not isinstance(
            value.get("AuthType"), str
        ):
            raise AuthorityInventoryError("LAMBDA_FUNCTION_URL_INVENTORY_MALFORMED")
        projected.append(value)
    return projected


def _project_event_sources(
    items: Sequence[Any], *, invoke_config: bool
) -> list[dict[str, Any]]:
    projected: list[dict[str, Any]] = []
    for item in items:
        if not isinstance(item, Mapping):
            raise AuthorityInventoryError("LAMBDA_EVENT_SOURCE_INVENTORY_MALFORMED")
        function_arn = item.get("FunctionArn")
        if not isinstance(function_arn, str):
            raise AuthorityInventoryError("LAMBDA_EVENT_SOURCE_INVENTORY_MALFORMED")
        value: dict[str, Any] = {"FunctionArn": function_arn}
        if invoke_config:
            if isinstance(item.get("Qualifier"), str):
                value["Qualifier"] = item["Qualifier"]
            value["AuthorityEndpointDigest"] = canonical_digest(
                item.get("DestinationConfig", {})
            )
        else:
            source_arn = item.get("EventSourceArn")
            value["AuthorityEndpointDigest"] = (
                digest_text(source_arn)
                if isinstance(source_arn, str) and source_arn
                else digest_text("unknown-event-source")
            )
            if isinstance(item.get("State"), str):
                value["State"] = item["State"]
        projected.append(value)
    return projected


def _project_attached_policies(value: object) -> list[dict[str, str]]:
    if not isinstance(value, list):
        raise AuthorityInventoryError("IAM_AUTHORIZATION_DETAILS_MALFORMED")
    projected: list[dict[str, str]] = []
    for item in value:
        if not isinstance(item, Mapping) or not isinstance(item.get("PolicyArn"), str):
            raise AuthorityInventoryError("IAM_AUTHORIZATION_DETAILS_MALFORMED")
        projected.append({"PolicyArn": item["PolicyArn"]})
    return projected


def _project_inline_policies(value: object) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        raise AuthorityInventoryError("IAM_AUTHORIZATION_DETAILS_MALFORMED")
    projected: list[dict[str, Any]] = []
    for item in value:
        if not isinstance(item, Mapping):
            raise AuthorityInventoryError("IAM_AUTHORIZATION_DETAILS_MALFORMED")
        projected.append(
            {
                "PolicyDocument": _strict_policy_document(item.get("PolicyDocument"))
            }
        )
    return projected


def _project_iam_entity(item: object, entity_type: str) -> dict[str, Any]:
    if not isinstance(item, Mapping) or not isinstance(item.get("Arn"), str):
        raise AuthorityInventoryError("IAM_AUTHORIZATION_DETAILS_MALFORMED")
    inline_key = {
        "user": "UserPolicyList",
        "group": "GroupPolicyList",
        "role": "RolePolicyList",
    }[entity_type]
    projected: dict[str, Any] = {
        "Arn": item["Arn"],
        inline_key: _project_inline_policies(item.get(inline_key, [])),
        "AttachedManagedPolicies": _project_attached_policies(
            item.get("AttachedManagedPolicies", [])
        ),
    }
    if entity_type == "role":
        projected["AssumeRolePolicyDocument"] = _strict_policy_document(
            item.get("AssumeRolePolicyDocument")
        )
    boundary = item.get("PermissionsBoundary")
    if boundary is not None:
        if not isinstance(boundary, Mapping) or not isinstance(
            boundary.get("PermissionsBoundaryArn"), str
        ):
            raise AuthorityInventoryError("IAM_AUTHORIZATION_DETAILS_MALFORMED")
        projected["PermissionsBoundary"] = {
            "PermissionsBoundaryArn": boundary["PermissionsBoundaryArn"]
        }
    return projected


def _project_iam_page(response: Mapping[str, Any]) -> dict[str, list[Any]]:
    projections: dict[str, list[Any]] = {
        "UserDetailList": [],
        "GroupDetailList": [],
        "RoleDetailList": [],
        "Policies": [],
    }
    for key, entity_type in (
        ("UserDetailList", "user"),
        ("GroupDetailList", "group"),
        ("RoleDetailList", "role"),
    ):
        values = response.get(key, [])
        if not isinstance(values, list):
            raise AuthorityInventoryError("IAM_AUTHORIZATION_DETAILS_MALFORMED")
        projections[key] = [_project_iam_entity(item, entity_type) for item in values]
    policies = response.get("Policies", [])
    if not isinstance(policies, list):
        raise AuthorityInventoryError("IAM_AUTHORIZATION_DETAILS_MALFORMED")
    projections["Policies"] = [
        _project_fields(
            item,
            ("Arn", "DefaultVersionId", "AttachmentCount", "PermissionsBoundaryUsageCount"),
            "IAM_AUTHORIZATION_DETAILS_MALFORMED",
        )
        for item in policies
    ]
    return projections


def _canonical_aws_service_endpoint(
    *, partition: str, service: str, region: str
) -> str:
    """Return one reviewed public AWS endpoint; custom endpoints are forbidden."""

    if REGION.fullmatch(region) is None:
        raise AuthorityInventoryError("AWS_ENDPOINT_BINDING_INVALID")
    if service not in {"sts", "ec2", "lambda", "iam"}:
        raise AuthorityInventoryError("AWS_ENDPOINT_BINDING_INVALID")
    if partition == "aws":
        suffix = "amazonaws.com"
        iam_host = "iam.amazonaws.com"
    elif partition == "aws-us-gov":
        suffix = "amazonaws.com"
        iam_host = "iam.us-gov.amazonaws.com"
    elif partition == "aws-cn":
        suffix = "amazonaws.com.cn"
        iam_host = "iam.cn-north-1.amazonaws.com.cn"
    else:
        raise AuthorityInventoryError("AWS_ENDPOINT_BINDING_INVALID")
    host = iam_host if service == "iam" else f"{service}.{region}.{suffix}"
    return f"https://{host}"


def _validate_aws_client_endpoint(client: Any, expected: str) -> None:
    meta = getattr(client, "meta", None)
    endpoint = getattr(meta, "endpoint_url", None)
    if not isinstance(endpoint, str) or endpoint.rstrip("/") != expected:
        raise AuthorityInventoryError("AWS_ENDPOINT_OVERRIDE_FORBIDDEN")


@dataclass(slots=True)
class AwsReadOnlyInventoryAdapter:
    """Injected AWS clients for an exact read-only inventory."""

    sts: Any
    ec2: Any
    lambda_client: Any
    iam: Any
    lambda_client_factory: Callable[[str], Any] | None = None
    clock: Callable[[], datetime] = _now_utc

    @classmethod
    def from_boto3(
        cls,
        *,
        profile_name: str,
        region: str,
        partition: str = "aws",
    ) -> "AwsReadOnlyInventoryAdapter":
        if (
            not profile_name
            or REGION.fullmatch(region) is None
            or partition not in {"aws", "aws-us-gov", "aws-cn"}
        ):
            raise AuthorityInventoryError("AWS_SESSION_BINDING_INVALID")
        try:
            import boto3  # type: ignore[import-not-found]
            from botocore.config import Config  # type: ignore[import-not-found]
        except ImportError as exc:
            raise AuthorityInventoryError("BOTO3_UNAVAILABLE") from exc
        try:
            session = boto3.Session(profile_name=profile_name, region_name=region)
            config = Config(retries={"mode": "standard", "max_attempts": 3})

            def lambda_factory(target_region: str) -> Any:
                endpoint = _canonical_aws_service_endpoint(
                    partition=partition,
                    service="lambda",
                    region=target_region,
                )
                client = session.client(
                    "lambda",
                    region_name=target_region,
                    endpoint_url=endpoint,
                    verify=True,
                    config=config,
                )
                _validate_aws_client_endpoint(client, endpoint)
                return client

            sts_endpoint = _canonical_aws_service_endpoint(
                partition=partition, service="sts", region=region
            )
            ec2_endpoint = _canonical_aws_service_endpoint(
                partition=partition, service="ec2", region=region
            )
            iam_endpoint = _canonical_aws_service_endpoint(
                partition=partition, service="iam", region=region
            )
            sts = session.client(
                "sts",
                region_name=region,
                endpoint_url=sts_endpoint,
                verify=True,
                config=config,
            )
            ec2 = session.client(
                "ec2",
                region_name=region,
                endpoint_url=ec2_endpoint,
                verify=True,
                config=config,
            )
            iam = session.client(
                "iam",
                region_name=region,
                endpoint_url=iam_endpoint,
                verify=True,
                config=config,
            )
            _validate_aws_client_endpoint(sts, sts_endpoint)
            _validate_aws_client_endpoint(ec2, ec2_endpoint)
            _validate_aws_client_endpoint(iam, iam_endpoint)

            return cls(
                sts=sts,
                ec2=ec2,
                lambda_client=lambda_factory(region),
                iam=iam,
                lambda_client_factory=lambda_factory,
            )
        except AuthorityInventoryError:
            raise
        except Exception as exc:
            raise AuthorityInventoryError("AWS_SESSION_INITIALIZATION_FAILED") from exc

    def _surface(
        self, operation: Callable[[], tuple[list[Any], int]]
    ) -> tuple[list[Any], dict[str, Any]]:
        try:
            items, pages = operation()
        except Exception as exc:
            code = _error_code(exc)
            status = "ACCESS_DENIED" if code in {
                "AccessDenied",
                "AccessDeniedException",
                "UnauthorizedOperation",
            } else "AMBIGUOUS"
            return [], _coverage(status, [], 0)
        return items, _coverage("COMPLETE", items, pages)

    def _projected_surface(
        self,
        operation: Callable[[], tuple[list[Any], int]],
        projector: Callable[[Sequence[Any]], list[dict[str, Any]]],
    ) -> tuple[list[Any], dict[str, Any]]:
        items, coverage = self._surface(operation)
        if coverage["status"] != "COMPLETE":
            return [], coverage
        try:
            projected = projector(items)
        except AuthorityInventoryError:
            return [], _coverage("AMBIGUOUS", [], 0)
        return projected, _coverage("COMPLETE", projected, coverage["page_count"])

    def _get_resource_policies(self, binding: TargetBinding, qualifiers: Sequence[str]) -> tuple[list[Any], int]:
        policies: list[Any] = []
        for qualifier in (None, *qualifiers):
            kwargs: dict[str, Any] = {"FunctionName": binding.function_name}
            resource_arn = binding.function_arn
            if qualifier is not None:
                kwargs["Qualifier"] = qualifier
                resource_arn = f"{binding.function_arn}:{qualifier}"
            try:
                response = self.lambda_client.get_policy(**kwargs)
            except Exception as exc:
                if _error_code(exc) == "ResourceNotFoundException":
                    continue
                raise
            if not isinstance(response, Mapping) or "Policy" not in response:
                raise AuthorityInventoryError("LAMBDA_POLICY_RESPONSE_MALFORMED")
            document = _strict_policy_document(response["Policy"])
            policies.append({"resource_arn": resource_arn, "policy_document": document})
        return policies, 1

    def _managed_policy_documents(self, iam_details: Mapping[str, Any]) -> dict[str, Any]:
        arns: set[str] = set()
        for key in ("UserDetailList", "GroupDetailList", "RoleDetailList"):
            values = iam_details.get(key, [])
            if not isinstance(values, list):
                raise AuthorityInventoryError("IAM_AUTHORIZATION_DETAILS_MALFORMED")
            for entity in values:
                if not isinstance(entity, Mapping):
                    raise AuthorityInventoryError("IAM_AUTHORIZATION_DETAILS_MALFORMED")
                for reference in entity.get("AttachedManagedPolicies", []):
                    if not isinstance(reference, Mapping) or not isinstance(reference.get("PolicyArn"), str):
                        raise AuthorityInventoryError("IAM_AUTHORIZATION_DETAILS_MALFORMED")
                    arns.add(reference["PolicyArn"])
                boundary = entity.get("PermissionsBoundary")
                if isinstance(boundary, Mapping) and isinstance(boundary.get("PermissionsBoundaryArn"), str):
                    arns.add(boundary["PermissionsBoundaryArn"])
        documents: dict[str, Any] = {}
        for arn in sorted(arns):
            metadata = self.iam.get_policy(PolicyArn=arn).get("Policy")
            if not isinstance(metadata, Mapping) or not isinstance(metadata.get("DefaultVersionId"), str):
                raise AuthorityInventoryError("MANAGED_POLICY_METADATA_MALFORMED")
            version = self.iam.get_policy_version(
                PolicyArn=arn, VersionId=metadata["DefaultVersionId"]
            ).get("PolicyVersion")
            if not isinstance(version, Mapping):
                raise AuthorityInventoryError("MANAGED_POLICY_VERSION_MALFORMED")
            documents[arn] = _strict_policy_document(version.get("Document"))
        return documents

    def collect(
        self,
        *,
        binding: TargetBinding,
        scan_id: str,
        expected_collector_principal_digest: str,
        ttl_minutes: int = 5,
    ) -> dict[str, Any]:
        """Collect the raw snapshot using read-only AWS APIs only."""

        if not isinstance(scan_id, str) or not scan_id:
            raise AuthorityInventoryError("SCAN_ID_INVALID")
        if not isinstance(ttl_minutes, int) or not 1 <= ttl_minutes <= 5:
            raise AuthorityInventoryError("SNAPSHOT_TTL_INVALID")
        if (
            not isinstance(expected_collector_principal_digest, str)
            or DIGEST.fullmatch(expected_collector_principal_digest) is None
        ):
            raise AuthorityInventoryError("COLLECTOR_PRINCIPAL_DIGEST_INVALID")
        capture_started = self.clock()
        if capture_started.tzinfo is None:
            raise AuthorityInventoryError("SNAPSHOT_CLOCK_INVALID")
        try:
            identity = self.sts.get_caller_identity()
        except Exception as exc:
            raise AuthorityInventoryError("STS_IDENTITY_READ_FAILED") from exc
        if not isinstance(identity, Mapping) or identity.get("Account") != binding.authority_account_id:
            raise AuthorityInventoryError("AWS_ACCOUNT_MISMATCH")
        collector_principal_arn = _canonical_sts_principal_arn(
            identity.get("Arn"),
            partition=binding.partition,
            account_id=binding.authority_account_id,
        )
        collector_principal_arn_digest = digest_text(collector_principal_arn)
        if collector_principal_arn_digest != expected_collector_principal_digest:
            raise AuthorityInventoryError("COLLECTOR_PRINCIPAL_NOT_ALLOWLISTED")

        coverage: dict[str, Any] = {}
        try:
            regions_response = self.ec2.describe_regions(AllRegions=True)
            regions = (
                regions_response.get("Regions")
                if isinstance(regions_response, Mapping)
                else None
            )
            if not isinstance(regions, list):
                raise AuthorityInventoryError("REGION_DISCOVERY_MALFORMED")
            enabled_regions = sorted(
                item["RegionName"]
                for item in regions
                if isinstance(item, Mapping)
                and isinstance(item.get("RegionName"), str)
                and item.get("OptInStatus") in {"opt-in-not-required", "opted-in"}
            )
            if binding.region not in enabled_regions:
                raise AuthorityInventoryError("TARGET_REGION_NOT_ENABLED")
            coverage["region_discovery"] = _coverage("COMPLETE", enabled_regions, 1)
        except Exception as exc:
            code = _error_code(exc)
            region_status = "ACCESS_DENIED" if code in {
                "AccessDenied",
                "AccessDeniedException",
                "UnauthorizedOperation",
            } else "AMBIGUOUS"
            enabled_regions = [binding.region]
            coverage["region_discovery"] = _coverage(region_status, enabled_regions, 0)

        functions: list[Any] = []
        scanned_regions: list[str] = []
        function_pages = 0
        function_status = "COMPLETE"
        for region_name in enabled_regions:
            if region_name == binding.region:
                client = self.lambda_client
            elif self.lambda_client_factory is not None:
                try:
                    client = self.lambda_client_factory(region_name)
                except Exception:
                    function_status = "AMBIGUOUS"
                    continue
            else:
                function_status = "INCOMPLETE"
                continue
            try:
                regional_functions, pages = _strict_paginate(
                    client.list_functions,
                    result_key="Functions",
                    request_token="Marker",
                    response_token="NextMarker",
                )
            except Exception as exc:
                code = _error_code(exc)
                function_status = (
                    "ACCESS_DENIED"
                    if code in {
                        "AccessDenied",
                        "AccessDeniedException",
                        "UnauthorizedOperation",
                    }
                    else "AMBIGUOUS"
                )
                continue
            scanned_regions.append(region_name)
            function_pages += pages
            try:
                functions.extend(_project_functions(regional_functions, region_name))
            except AuthorityInventoryError:
                function_status = "AMBIGUOUS"
        coverage["lambda_functions"] = _coverage(
            function_status, functions, function_pages
        )
        target = [
            item
            for item in functions
            if isinstance(item, Mapping)
            and item.get("FunctionName") == binding.function_name
            and item.get("FunctionArn") == binding.function_arn
        ]
        if len(target) != 1:
            coverage["lambda_functions"]["status"] = "AMBIGUOUS"

        aliases, coverage["lambda_aliases"] = self._projected_surface(
            lambda: _strict_paginate(
                self.lambda_client.list_aliases,
                result_key="Aliases",
                request_token="Marker",
                response_token="NextMarker",
                base_kwargs={"FunctionName": binding.function_name},
            ),
            _project_aliases,
        )
        versions, coverage["lambda_versions"] = self._projected_surface(
            lambda: _strict_paginate(
                self.lambda_client.list_versions_by_function,
                result_key="Versions",
                request_token="Marker",
                response_token="NextMarker",
                base_kwargs={"FunctionName": binding.function_name},
            ),
            _project_versions,
        )
        urls, coverage["lambda_function_urls"] = self._projected_surface(
            lambda: _strict_paginate(
                self.lambda_client.list_function_url_configs,
                result_key="FunctionUrlConfigs",
                request_token="Marker",
                response_token="NextMarker",
                base_kwargs={"FunctionName": binding.function_name},
            ),
            _project_function_urls,
        )
        mappings, mappings_coverage = self._projected_surface(
            lambda: _strict_paginate(
                self.lambda_client.list_event_source_mappings,
                result_key="EventSourceMappings",
                request_token="Marker",
                response_token="NextMarker",
                base_kwargs={"FunctionName": binding.function_name},
            ),
            lambda items: _project_event_sources(items, invoke_config=False),
        )
        invokes, invokes_coverage = self._projected_surface(
            lambda: _strict_paginate(
                self.lambda_client.list_function_event_invoke_configs,
                result_key="FunctionEventInvokeConfigs",
                request_token="Marker",
                response_token="NextMarker",
                base_kwargs={"FunctionName": binding.function_name},
            ),
            lambda items: _project_event_sources(items, invoke_config=True),
        )
        event_items = [*mappings, *invokes]
        event_status = (
            "ACCESS_DENIED"
            if "ACCESS_DENIED" in {mappings_coverage["status"], invokes_coverage["status"]}
            else "AMBIGUOUS"
            if "AMBIGUOUS" in {mappings_coverage["status"], invokes_coverage["status"]}
            else "COMPLETE"
        )
        coverage["lambda_event_source_mappings"] = _coverage(
            event_status,
            event_items,
            mappings_coverage["page_count"] + invokes_coverage["page_count"],
        )

        qualifiers = sorted(
            {
                str(item.get("Name"))
                for item in aliases
                if isinstance(item, Mapping) and isinstance(item.get("Name"), str)
            }
            | {
                str(item.get("Version"))
                for item in versions
                if isinstance(item, Mapping)
                and isinstance(item.get("Version"), str)
                and item.get("Version") != "$LATEST"
            }
        )
        policies, coverage["lambda_resource_policies"] = self._surface(
            lambda: self._get_resource_policies(binding, qualifiers)
        )

        iam_aggregate = {
            "UserDetailList": [],
            "GroupDetailList": [],
            "RoleDetailList": [],
            "Policies": [],
        }
        token: str | None = None
        seen: set[str] = set()
        page_count = 0
        try:
            while True:
                if page_count >= MAX_PAGES:
                    raise AuthorityInventoryError("PAGINATION_LIMIT_EXCEEDED")
                kwargs: dict[str, Any] = {
                    "Filter": ["User", "Role", "Group", "LocalManagedPolicy", "AWSManagedPolicy"]
                }
                if token is not None:
                    kwargs["Marker"] = token
                response = self.iam.get_account_authorization_details(**kwargs)
                if not isinstance(response, Mapping) or not isinstance(response.get("IsTruncated"), bool):
                    raise AuthorityInventoryError("IAM_AUTHORIZATION_DETAILS_MALFORMED")
                page_count += 1
                projected_page = _project_iam_page(response)
                for key in iam_aggregate:
                    iam_aggregate[key].extend(projected_page[key])
                next_token = response.get("Marker")
                if next_token in (None, ""):
                    next_token = None
                elif not isinstance(next_token, str):
                    raise AuthorityInventoryError("PAGINATION_TOKEN_MALFORMED")
                if response["IsTruncated"] != (next_token is not None):
                    raise AuthorityInventoryError("PAGINATION_TRUNCATION_CONFLICT")
                if next_token is None:
                    break
                if next_token in seen or next_token == token:
                    raise AuthorityInventoryError("PAGINATION_TOKEN_REPEATED")
                seen.add(next_token)
                token = next_token
            managed_documents = self._managed_policy_documents(iam_aggregate)
            coverage["iam_account_authorization"] = _coverage(
                "COMPLETE",
                [
                    *iam_aggregate["UserDetailList"],
                    *iam_aggregate["GroupDetailList"],
                    *iam_aggregate["RoleDetailList"],
                    *iam_aggregate["Policies"],
                    managed_documents,
                ],
                page_count,
            )
        except Exception as exc:
            code = _error_code(exc)
            status = "ACCESS_DENIED" if code in {
                "AccessDenied",
                "AccessDeniedException",
                "UnauthorizedOperation",
            } else "AMBIGUOUS"
            managed_documents = {}
            iam_aggregate = {
                "UserDetailList": [],
                "GroupDetailList": [],
                "RoleDetailList": [],
                "Policies": [],
            }
            coverage["iam_account_authorization"] = _coverage(status, [], 0)

        capture_completed = self.clock()
        if capture_completed.tzinfo is None or capture_completed < capture_started:
            raise AuthorityInventoryError("SNAPSHOT_CLOCK_INVALID")
        snapshot = {
            "snapshot_format": RAW_SNAPSHOT_FORMAT,
            "capture_started_at": _utc_string(capture_started),
            "capture_completed_at": _utc_string(capture_completed),
            "capture_expires_at": _utc_string(
                capture_completed + timedelta(minutes=ttl_minutes)
            ),
            "collector_nonce": scan_id,
            "collector_principal_arn": collector_principal_arn,
            "collector_principal_arn_digest": collector_principal_arn_digest,
            "enabled_regions": enabled_regions,
            # Every enabled region must be present. An injected adapter without
            # a regional client factory remains deliberately INCOMPLETE.
            "scanned_regions": scanned_regions,
            "coverage": coverage,
            "lambda": {
                "functions": functions,
                "aliases": aliases,
                "versions": versions,
                "function_urls": urls,
                "resource_policies": policies,
                "event_source_mappings": mappings,
                "event_invoke_configs": invokes,
            },
            "iam": {
                "users": iam_aggregate["UserDetailList"],
                "groups": iam_aggregate["GroupDetailList"],
                "roles": iam_aggregate["RoleDetailList"],
                "policies": iam_aggregate["Policies"],
                "managed_policy_documents": managed_documents,
            },
        }
        return _seal_raw_snapshot(snapshot)
