"""Concrete zero-retry AWS adapters for the GUG-376 Plan repair PEP.

The pure state machine remains in ``platform_authority_plan_permission_repair``.
This module is the only deployment entrypoint that imports the AWS SDK.  It
derives live-only role suffixes, Lambda versions, and invocation authority from
provider state, then seals those facts into the same private intent in every
mode.  No request field can select an account, role, permission set, action, or
policy.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
import json
from pathlib import Path
import re
import time
from typing import Any, Callable, Mapping, Sequence
from urllib.parse import unquote

from tooling.platform_authority_bootstrap import canonical_digest
from tooling.platform_authority_lambda_audit_repair_invocation_authority import (
    RepairInvocationAuthorityBinding,
    collect_provider_invocation_snapshots,
    verify_provider_invocation_authority,
)
from tooling.platform_authority_lambda_invocation_authority import (
    AuthorityInventoryError,
    AwsReadOnlyInventoryAdapter,
    digest_text,
)
from tooling.platform_authority_plan_permission_repair import (
    AUTHORITY_ACCOUNT_ID,
    EXECUTION_ROLE_NAMES,
    FUNCTION_NAMES,
    FUNCTION_QUALIFIERS,
    MANAGEMENT_ACCOUNT_ID,
    PLAN_PERMISSION_SET_NAME,
    PLAN_ROLE_INLINE_POLICY_NAME,
    PLAN_ROLE_PREFIX,
    PLAN_SESSION_DURATION,
    REGION,
    Assignment,
    OperationResult,
    PlanPermissionRepair,
    PlanPermissionRepairError,
    PlanPermissionSnapshot,
    ProviderResponseAmbiguous,
    RepairBinding,
    RoleSnapshot,
    build_private_intent,
    canonical_json,
    install_runtime_factory,
    parse_timestamp,
    render_target_policy,
    validate_immutable_configuration_digest,
    validate_lambda_environment_budget,
    validate_private_intent,
    validate_private_ledger,
)
from tooling.platform_authority_plan_permission_repair_iam_effective_authority import (
    AwsPlanRepairIamEffectiveAuthorityVerifier,
    IamEffectiveAuthorityGuardedIdentityCenterPort,
    PlanRepairIamBindings,
)


READBACK_ROLE_ARN = (
    "arn:aws:iam::839393571433:role/scanalyze/platform-authority/"
    "ScanalyzeBootstrapPlanRepairReadback"
)
MUTATION_ROLE_ARN = (
    "arn:aws:iam::839393571433:role/scanalyze/platform-authority/"
    "ScanalyzeBootstrapPlanRepairMutation"
)
INSPECTOR_ROLE_ARN = (
    "arn:aws:iam::042360977644:role/scanalyze/platform-authority/"
    "ScanalyzeBootstrapPlanRepairInspector"
)
INSPECTOR_ROLE_NAME = "ScanalyzeBootstrapPlanRepairInspector"
INVOKER_PERMISSION_SET_NAME = "ScanalyzeBootstrapPlanRepair"
INVOKER_PERMISSION_SET_DESCRIPTION = (
    "GUG-376 invoke-only bootstrap Plan policy repair PEP"
)
INVOKER_PERMISSION_SET_TAGS = {
    "environment": "non-production",
    "managed_by": "cloudformation",
    "production": "false",
    "service": "scanalyze-platform-authority",
    "work_package": "GUG-376",
}
INVOKER_ROLE_PREFIX = "AWSReservedSSO_ScanalyzeBootstrapPlanRepair_"
RUNTIME_LOCK_NAME = "gug376_plan_permission_repair_runtime_lock.json"
RUNTIME_LOCK_TYPE = (
    "scanalyze.platform_authority.plan_permission_repair_runtime_lock.v1"
)
SDK_CONNECT_TIMEOUT_SECONDS = 3
SDK_READ_TIMEOUT_SECONDS = 8
MAX_PROVIDER_PAGES = 100
MAX_PROVIDER_ITEMS = 10_000
MAX_PROVIDER_PAGE_BYTES = 1_000_000
MIN_READ_CALL_REMAINING_MS = 60_000
MIN_MUTATION_CALL_REMAINING_MS = 75_000
ASSUME_ROLE_DURATION_SECONDS = 900
EXPECTED_HANDLERS = {
    "plan": (
        "tooling.platform_authority_plan_permission_repair_aws.plan_handler"
    ),
    "repair": (
        "tooling.platform_authority_plan_permission_repair_aws.repair_handler"
    ),
    "reconcile": (
        "tooling.platform_authority_plan_permission_repair_aws."
        "reconcile_handler"
    ),
}
EXPECTED_TIMEOUTS = {"plan": 300, "repair": 600, "reconcile": 300}
EXPECTED_VERSION_DESCRIPTION_PREFIXES = {
    "plan": "GUG-376 plan version ",
    "repair": "GUG-376 repair version ",
    "reconcile": "GUG-376 reconcile version ",
}
COMMON_FUNCTION_ENVIRONMENT_KEYS = frozenset(
    {
        "SOURCE_COMMIT",
        "SOURCE_BUNDLE_DIGEST",
        "REPAIR_ID",
        "PRINCIPAL_ID",
        "IDENTITY_STORE_ID",
        "IDENTITY_CENTER_INSTANCE_ARN",
        "PLAN_PERMISSION_SET_ARN",
        "EXPECTED_PERMISSION_SET_DESCRIPTION",
        "REPAIR_INVOKER_PERMISSION_SET_ARN",
        "CURRENT_POLICY_DIGEST",
        "DESIRED_POLICY_DIGEST",
        "EXPECTED_PLAN_PERMISSION_SET_TAGS_JSON",
        "BOOTSTRAP_CHANGE_SET_NAME",
        "REPAIR_LEDGER_TABLE_NAME",
        "REPAIR_LEDGER_KMS_KEY_ARN",
        "EXPECTED_ARTIFACT_CODE_SHA256",
        "EXPECTED_CODE_SIGNING_CONFIG_ARN",
        "EXPECTED_SIGNING_PROFILE_VERSION_ARN",
        "REPAIR_NOT_BEFORE",
        "REPAIR_NOT_AFTER",
        "PLAN_SAML_PROVIDER_ARN",
        "IDENTITY_CENTER_KMS_MODE",
        "IDENTITY_CENTER_KMS_KEY_ARN",
        "EXPECTED_BOTO3_VERSION",
        "EXPECTED_BOTOCORE_VERSION",
        "IMMU_CONFIG_DIGEST",
        "IMMU_CONFIG_DIGEST",
    }
)

_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_SOURCE_COMMIT = re.compile(r"^[0-9a-f]{40}$")
_DYNAMO_INTEGER = re.compile(r"^(?:0|-?[1-9][0-9]*)$")
_FUNCTION_VERSION = re.compile(r"^[1-9][0-9]*$")
_REQUEST_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9-]{0,127}$")
_PUBLIC_ERROR_CODE = re.compile(r"^[A-Z][A-Z0-9_]{0,79}$")
_RUNTIME_VERSION_ARN = re.compile(
    r"^arn:aws:lambda:us-east-1::runtime:[A-Za-z0-9._-]+$"
)


class PublicPlanRepairFailure(RuntimeError):
    """Stable Lambda error containing no provider exception or payload."""

    def __init__(self, code: str) -> None:
        super().__init__(f"GUG376_PLAN_REPAIR_BLOCKED:{code}")


def _reject_duplicate_json_keys(
    pairs: list[tuple[str, Any]],
) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _provider_code(exc: BaseException) -> str:
    response = getattr(exc, "response", None)
    if isinstance(response, Mapping):
        error = response.get("Error")
        if isinstance(error, Mapping) and isinstance(error.get("Code"), str):
            return str(error["Code"])
    return type(exc).__name__


def _normalize_policy(value: Any) -> dict[str, Any]:
    if isinstance(value, Mapping):
        normalized = dict(value)
    elif isinstance(value, str):
        candidates = (value, unquote(value))
        normalized = {}
        for candidate in candidates:
            try:
                decoded = json.loads(
                    candidate, object_pairs_hook=_reject_duplicate_json_keys
                )
            except (json.JSONDecodeError, TypeError, ValueError):
                continue
            if isinstance(decoded, Mapping):
                normalized = dict(decoded)
                break
    else:
        normalized = {}
    if not normalized or normalized.get("Version") != "2012-10-17":
        raise PlanPermissionRepairError(
            "POLICY_READBACK_MALFORMED",
            "provider policy document is malformed",
        )
    statements = normalized.get("Statement")
    if isinstance(statements, Mapping):
        normalized["Statement"] = [dict(statements)]
    elif not isinstance(statements, list) or not all(
        isinstance(item, Mapping) for item in statements
    ):
        raise PlanPermissionRepairError(
            "POLICY_READBACK_MALFORMED",
            "provider policy statements are malformed",
        )
    return normalized


def _checked_page(response: Any, operation: str) -> Mapping[str, Any]:
    if not isinstance(response, Mapping):
        raise PlanPermissionRepairError(
            "PROVIDER_RESPONSE_MALFORMED",
            f"{operation} response is malformed",
        )
    def project(value: Any) -> Any:
        if isinstance(value, datetime):
            if value.tzinfo is None or value.utcoffset() is None:
                raise TypeError("naive provider timestamp")
            return (
                value.astimezone(UTC)
                .isoformat(timespec="microseconds")
                .replace("+00:00", "Z")
            )
        raise TypeError(f"unsupported provider value {type(value).__name__}")

    try:
        size = len(
            json.dumps(
                response,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
                allow_nan=False,
                default=project,
            ).encode("utf-8")
        )
    except (TypeError, ValueError) as exc:
        raise PlanPermissionRepairError(
            "PROVIDER_RESPONSE_MALFORMED",
            f"{operation} response is not canonical JSON",
        ) from exc
    if size > MAX_PROVIDER_PAGE_BYTES:
        raise PlanPermissionRepairError(
            "PROVIDER_RESPONSE_OVERSIZED",
            f"{operation} response exceeds the closed byte budget",
        )
    return response


def _append_page(
    values: list[Any],
    response: Mapping[str, Any],
    operation: str,
    result_key: str,
) -> None:
    result = response.get(result_key)
    if not isinstance(result, list):
        raise PlanPermissionRepairError(
            "PROVIDER_RESPONSE_MALFORMED",
            f"{operation} result is malformed",
        )
    values.extend(result)
    if len(values) > MAX_PROVIDER_ITEMS:
        raise PlanPermissionRepairError(
            "PROVIDER_RESPONSE_OVERSIZED",
            f"{operation} inventory exceeds the closed item budget",
        )


def _paginate_token(
    client: Any,
    method_name: str,
    result_key: str,
    **kwargs: Any,
) -> list[Any]:
    values: list[Any] = []
    token: str | None = None
    seen: set[str] = set()
    for _ in range(MAX_PROVIDER_PAGES):
        request = dict(kwargs)
        if token is not None:
            request["NextToken"] = token
        response = _checked_page(
            getattr(client, method_name)(**request), method_name
        )
        _append_page(values, response, method_name, result_key)
        next_token = response.get("NextToken")
        if next_token is None:
            return values
        if (
            not isinstance(next_token, str)
            or not next_token
            or next_token in seen
        ):
            raise PlanPermissionRepairError(
                "PAGINATION_INVALID",
                f"{method_name} pagination token is malformed or repeated",
            )
        seen.add(next_token)
        token = next_token
    raise PlanPermissionRepairError(
        "PAGINATION_LIMIT",
        f"{method_name} exceeded the closed page budget",
    )


def _paginate_marker(
    client: Any,
    method_name: str,
    result_key: str,
    **kwargs: Any,
) -> list[Any]:
    values: list[Any] = []
    marker: str | None = None
    seen: set[str] = set()
    for _ in range(MAX_PROVIDER_PAGES):
        request = dict(kwargs)
        if marker is not None:
            request["Marker"] = marker
        response = _checked_page(
            getattr(client, method_name)(**request), method_name
        )
        _append_page(values, response, method_name, result_key)
        truncated = response.get("IsTruncated")
        if type(truncated) is not bool:
            raise PlanPermissionRepairError(
                "PAGINATION_INVALID",
                f"{method_name} pagination state is malformed",
            )
        next_marker = response.get("Marker")
        if not truncated:
            if next_marker is not None:
                raise PlanPermissionRepairError(
                    "PAGINATION_INVALID",
                    f"{method_name} terminal page carries a marker",
                )
            return values
        if (
            not isinstance(next_marker, str)
            or not next_marker
            or next_marker in seen
        ):
            raise PlanPermissionRepairError(
                "PAGINATION_INVALID",
                f"{method_name} pagination marker is malformed or repeated",
            )
        seen.add(next_marker)
        marker = next_marker
    raise PlanPermissionRepairError(
        "PAGINATION_LIMIT",
        f"{method_name} exceeded the closed page budget",
    )


def _require_budget(
    remaining_time_ms: Callable[[], int], minimum_ms: int
) -> None:
    value = remaining_time_ms()
    if type(value) is not int or value <= minimum_ms:
        raise PlanPermissionRepairError(
            "FUNCTION_BUDGET_INSUFFICIENT",
            "Lambda remaining-time budget is below the provider-call reserve",
        )


class _BudgetClient:
    def __init__(
        self,
        client: Any,
        remaining_time_ms: Callable[[], int],
        minimum_ms: int = MIN_READ_CALL_REMAINING_MS,
    ) -> None:
        self._client = client
        self._remaining_time_ms = remaining_time_ms
        self._minimum_ms = minimum_ms

    def __getattr__(self, name: str) -> Any:
        value = getattr(self._client, name)
        if not callable(value):
            return value

        def guarded(*args: Any, **kwargs: Any) -> Any:
            _require_budget(self._remaining_time_ms, self._minimum_ms)
            return value(*args, **kwargs)

        return guarded


@dataclass(frozen=True, slots=True)
class _PermissionSetState:
    permission_set: Mapping[str, Any]
    tags: tuple[tuple[str, str], ...]
    inline_policy: Mapping[str, Any]
    managed_policy_arns: tuple[str, ...]
    customer_policy_references: tuple[str, ...]
    boundary_present: bool
    assignments: tuple[Assignment, ...]
    accounts: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class _RoleState:
    snapshot: RoleSnapshot
    inline_policy: Mapping[str, Any]


def _parse_saml_trust(
    value: Any, expected_provider_arn: str
) -> tuple[str, str]:
    policy = _normalize_policy(value)
    statements = policy["Statement"]
    if len(statements) != 1:
        raise PlanPermissionRepairError(
            "SAML_TRUST_MISMATCH", "generated SSO role trust differs"
        )
    statement = dict(statements[0])
    actions = statement.pop("Action", None)
    if isinstance(actions, str):
        action_set = {actions}
    elif isinstance(actions, list) and all(
        isinstance(item, str) for item in actions
    ):
        action_set = set(actions)
    else:
        action_set = set()
    expected = {
        "Effect": "Allow",
        "Principal": {"Federated": expected_provider_arn},
        "Condition": {
            "StringEquals": {
                "SAML:aud": "https://signin.aws.amazon.com/saml"
            }
        },
    }
    if statement != expected or action_set != {
        "sts:AssumeRoleWithSAML",
        "sts:TagSession",
    }:
        raise PlanPermissionRepairError(
            "SAML_TRUST_MISMATCH", "generated SSO role trust differs"
        )
    return expected_provider_arn, "https://signin.aws.amazon.com/saml"


class AwsIdentityCenterAdapter:
    """Narrow management SSO adapter plus authority IAM readback."""

    def __init__(
        self,
        *,
        sso_admin: Any,
        identitystore: Any,
        authority_iam: Any,
        graph_supplier: Callable[[str, Mapping[str, Any]], str],
        expected_description: str,
        expected_plan_tags: Mapping[str, str],
        source_commit: str,
        remaining_time_ms: Callable[[], int],
    ) -> None:
        self._sso = sso_admin
        self._identitystore = identitystore
        self._iam = authority_iam
        self._graph_supplier = graph_supplier
        self._expected_description = expected_description
        self._expected_plan_tags = dict(expected_plan_tags)
        if (
            not self._expected_plan_tags
            or any(
                not isinstance(key, str)
                or not key
                or not isinstance(value, str)
                or not value
                for key, value in self._expected_plan_tags.items()
            )
        ):
            raise PlanPermissionRepairError(
                "PLAN_TAG_BINDING_MALFORMED",
                "expected Plan permission-set tags are malformed",
            )
        if _SOURCE_COMMIT.fullmatch(source_commit) is None:
            raise PlanPermissionRepairError(
                "INVOKER_TAG_BINDING_MALFORMED",
                "invoker permission-set source commit is malformed",
            )
        self._expected_invoker_tags = {
            **INVOKER_PERMISSION_SET_TAGS,
            "source_commit": source_commit,
        }
        self._remaining_time_ms = remaining_time_ms

    def _instance(self, intent_seed: Mapping[str, Any]) -> None:
        response = _checked_page(
            self._sso.describe_instance(
                InstanceArn=intent_seed["instance_arn"]
            ),
            "describe_instance",
        )
        if (
            response.get("InstanceArn") != intent_seed["instance_arn"]
            or response.get("IdentityStoreId")
            != intent_seed["identity_store_id"]
            or response.get("OwnerAccountId") != MANAGEMENT_ACCOUNT_ID
            or response.get("Status") != "ACTIVE"
        ):
            raise PlanPermissionRepairError(
                "INSTANCE_READBACK_MISMATCH",
                "Identity Center instance binding differs",
            )
        details = response.get("EncryptionConfigurationDetails")
        if not isinstance(details, Mapping):
            raise PlanPermissionRepairError(
                "KMS_READBACK_MALFORMED",
                "Identity Center encryption readback is malformed",
            )
        if (
            details.get("EncryptionStatus") != "ENABLED"
            or details.get("KeyType")
            != intent_seed["identity_center_kms_mode"]
            or details.get("KmsKeyArn")
            != intent_seed["identity_center_kms_key_arn"]
        ):
            raise PlanPermissionRepairError(
                "KMS_READBACK_MISMATCH",
                "Identity Center encryption binding differs",
            )

    def _pending_count(
        self, instance_arn: str, permission_set_arn: str
    ) -> int:
        operations = (
            (
                "list_account_assignment_creation_status",
                "AccountAssignmentsCreationStatus",
                "describe_account_assignment_creation_status",
                "AccountAssignmentCreationRequestId",
                "AccountAssignmentCreationStatus",
            ),
            (
                "list_account_assignment_deletion_status",
                "AccountAssignmentsDeletionStatus",
                "describe_account_assignment_deletion_status",
                "AccountAssignmentDeletionRequestId",
                "AccountAssignmentDeletionStatus",
            ),
            (
                "list_permission_set_provisioning_status",
                "PermissionSetsProvisioningStatus",
                "describe_permission_set_provisioning_status",
                "ProvisionPermissionSetRequestId",
                "PermissionSetProvisioningStatus",
            ),
        )
        count = 0
        for list_method, result_key, describe_method, request_key, detail_key in (
            operations
        ):
            items = _paginate_token(
                self._sso,
                list_method,
                result_key,
                InstanceArn=instance_arn,
                Filter={"Status": "IN_PROGRESS"},
            )
            for item in items:
                if (
                    not isinstance(item, Mapping)
                    or not isinstance(item.get("RequestId"), str)
                    or item.get("Status") != "IN_PROGRESS"
                ):
                    raise PlanPermissionRepairError(
                        "OPERATION_READBACK_MALFORMED",
                        "Identity Center operation inventory is malformed",
                    )
                response = _checked_page(
                    getattr(self._sso, describe_method)(
                        InstanceArn=instance_arn,
                        **{request_key: item["RequestId"]},
                    ),
                    describe_method,
                )
                detail = response.get(detail_key)
                if (
                    not isinstance(detail, Mapping)
                    or detail.get("RequestId") != item["RequestId"]
                    or detail.get("Status") != "IN_PROGRESS"
                    or not isinstance(detail.get("PermissionSetArn"), str)
                ):
                    raise PlanPermissionRepairError(
                        "OPERATION_READBACK_MALFORMED",
                        "Identity Center operation readback is malformed",
                    )
                if detail["PermissionSetArn"] == permission_set_arn:
                    count += 1
        return count

    def _permission_set(
        self,
        *,
        instance_arn: str,
        permission_set_arn: str,
    ) -> _PermissionSetState:
        described = _checked_page(
            self._sso.describe_permission_set(
                InstanceArn=instance_arn,
                PermissionSetArn=permission_set_arn,
            ),
            "describe_permission_set",
        ).get("PermissionSet")
        if (
            not isinstance(described, Mapping)
            or described.get("PermissionSetArn") != permission_set_arn
        ):
            raise PlanPermissionRepairError(
                "PERMISSION_SET_READBACK_MALFORMED",
                "permission-set readback is malformed",
            )
        tags_raw = _paginate_token(
            self._sso,
            "list_tags_for_resource",
            "Tags",
            InstanceArn=instance_arn,
            ResourceArn=permission_set_arn,
        )
        if any(
            not isinstance(item, Mapping)
            or set(item) != {"Key", "Value"}
            or not isinstance(item.get("Key"), str)
            or not isinstance(item.get("Value"), str)
            for item in tags_raw
        ):
            raise PlanPermissionRepairError(
                "TAG_READBACK_MALFORMED", "permission-set tags are malformed"
            )
        tags = tuple(sorted((item["Key"], item["Value"]) for item in tags_raw))
        if len(tags) != len({key for key, _ in tags}):
            raise PlanPermissionRepairError(
                "TAG_READBACK_MALFORMED", "permission-set tags are duplicated"
            )
        inline_raw = _checked_page(
            self._sso.get_inline_policy_for_permission_set(
                InstanceArn=instance_arn,
                PermissionSetArn=permission_set_arn,
            ),
            "get_inline_policy_for_permission_set",
        ).get("InlinePolicy")
        inline = _normalize_policy(inline_raw)
        managed_raw = _paginate_token(
            self._sso,
            "list_managed_policies_in_permission_set",
            "AttachedManagedPolicies",
            InstanceArn=instance_arn,
            PermissionSetArn=permission_set_arn,
        )
        if any(
            not isinstance(item, Mapping)
            or not isinstance(item.get("Arn"), str)
            or not item.get("Arn")
            for item in managed_raw
        ):
            raise PlanPermissionRepairError(
                "POLICY_READBACK_MALFORMED",
                "managed permission-set policies are malformed",
            )
        managed = tuple(sorted(str(item["Arn"]) for item in managed_raw))
        if len(managed) != len(set(managed)):
            raise PlanPermissionRepairError(
                "POLICY_READBACK_MALFORMED",
                "managed permission-set policies are duplicated",
            )
        customer_raw = _paginate_token(
            self._sso,
            "list_customer_managed_policy_references_in_permission_set",
            "CustomerManagedPolicyReferences",
            InstanceArn=instance_arn,
            PermissionSetArn=permission_set_arn,
        )
        if any(not isinstance(item, Mapping) for item in customer_raw):
            raise PlanPermissionRepairError(
                "POLICY_READBACK_MALFORMED",
                "customer-managed permission-set policies are malformed",
            )
        customer = tuple(sorted(canonical_json(item) for item in customer_raw))
        if len(customer) != len(set(customer)):
            raise PlanPermissionRepairError(
                "POLICY_READBACK_MALFORMED",
                "customer-managed permission-set policies are duplicated",
            )
        try:
            boundary = _checked_page(
                self._sso.get_permissions_boundary_for_permission_set(
                    InstanceArn=instance_arn,
                    PermissionSetArn=permission_set_arn,
                ),
                "get_permissions_boundary_for_permission_set",
            ).get("PermissionsBoundary")
        except Exception as exc:
            if _provider_code(exc) in {
                "ResourceNotFoundException",
                "ResourceNotFound",
            }:
                boundary = None
            else:
                raise
        accounts_raw = _paginate_token(
            self._sso,
            "list_accounts_for_provisioned_permission_set",
            "AccountIds",
            InstanceArn=instance_arn,
            PermissionSetArn=permission_set_arn,
        )
        if any(
            not isinstance(value, str)
            or re.fullmatch(r"[0-9]{12}", value) is None
            for value in accounts_raw
        ):
            raise PlanPermissionRepairError(
                "ACCOUNT_READBACK_MALFORMED",
                "provisioned-account inventory is malformed",
            )
        accounts = tuple(sorted(accounts_raw))
        if len(accounts) != len(set(accounts)):
            raise PlanPermissionRepairError(
                "ACCOUNT_READBACK_MALFORMED",
                "provisioned accounts are duplicated",
            )
        assignments_raw: list[Any] = []
        for account_id in sorted(set(accounts) | {AUTHORITY_ACCOUNT_ID}):
            assignments_raw.extend(
                _paginate_token(
                    self._sso,
                    "list_account_assignments",
                    "AccountAssignments",
                    InstanceArn=instance_arn,
                    AccountId=account_id,
                    PermissionSetArn=permission_set_arn,
                )
            )
        if any(
            not isinstance(item, Mapping)
            or item.get("PermissionSetArn") != permission_set_arn
            or not all(
                isinstance(item.get(field), str) and item.get(field)
                for field in (
                    "AccountId",
                    "PrincipalType",
                    "PrincipalId",
                )
            )
            for item in assignments_raw
        ):
            raise PlanPermissionRepairError(
                "ASSIGNMENT_READBACK_MALFORMED",
                "permission-set assignments are malformed",
            )
        assignments = tuple(
            sorted(
                (
                    Assignment(
                        str(item["PrincipalType"]),
                        str(item["PrincipalId"]),
                        str(item["AccountId"]),
                    )
                    for item in assignments_raw
                ),
                key=lambda item: (
                    item.target_account_id,
                    item.principal_type,
                    item.principal_id,
                ),
            )
        )
        if len(assignments) != len(set(assignments)):
            raise PlanPermissionRepairError(
                "ASSIGNMENT_READBACK_MALFORMED",
                "permission-set assignments are duplicated",
            )
        return _PermissionSetState(
            permission_set=dict(described),
            tags=tags,
            inline_policy=inline,
            managed_policy_arns=managed,
            customer_policy_references=customer,
            boundary_present=boundary is not None,
            assignments=assignments,
            accounts=accounts,
        )

    def _roles(self) -> tuple[Mapping[str, Any], ...]:
        roles = _paginate_marker(
            self._iam,
            "list_roles",
            "Roles",
            PathPrefix="/aws-reserved/sso.amazonaws.com/",
        )
        if any(
            not isinstance(item, Mapping)
            or not isinstance(item.get("RoleName"), str)
            or not isinstance(item.get("Arn"), str)
            or not isinstance(item.get("Path"), str)
            for item in roles
        ):
            raise PlanPermissionRepairError(
                "ROLE_READBACK_MALFORMED", "generated role list is malformed"
            )
        names = [str(item["RoleName"]) for item in roles]
        if len(names) != len(set(names)):
            raise PlanPermissionRepairError(
                "ROLE_READBACK_MALFORMED", "generated roles are duplicated"
            )
        return tuple(dict(item) for item in roles)

    def _role(
        self,
        roles: Sequence[Mapping[str, Any]],
        *,
        prefix: str,
        saml_provider_arn: str,
    ) -> _RoleState:
        candidates = [
            item
            for item in roles
            if str(item.get("RoleName", "")).startswith(prefix)
        ]
        if len(candidates) != 1:
            raise PlanPermissionRepairError(
                "ROLE_SET_MISMATCH",
                "generated permission-set role is not exactly one",
            )
        listed = candidates[0]
        role_name = str(listed["RoleName"])
        if re.fullmatch(re.escape(prefix) + r"[0-9a-fA-F]{16}", role_name) is None:
            raise PlanPermissionRepairError(
                "ROLE_BINDING_MISMATCH", "generated role suffix is malformed"
            )
        expected_path = "/aws-reserved/sso.amazonaws.com/"
        expected_arn = (
            f"arn:aws:iam::{AUTHORITY_ACCOUNT_ID}:role"
            f"{expected_path}{role_name}"
        )
        if listed.get("Path") != expected_path or listed.get("Arn") != expected_arn:
            raise PlanPermissionRepairError(
                "ROLE_BINDING_MISMATCH", "generated role ARN or path differs"
            )
        role = _checked_page(
            self._iam.get_role(RoleName=role_name), "get_role"
        ).get("Role")
        if (
            not isinstance(role, Mapping)
            or role.get("RoleName") != role_name
            or role.get("Arn") != expected_arn
            or role.get("Path") != expected_path
        ):
            raise PlanPermissionRepairError(
                "ROLE_READBACK_MALFORMED", "generated role readback differs"
            )
        provider_arn, audience = _parse_saml_trust(
            role.get("AssumeRolePolicyDocument"), saml_provider_arn
        )
        attached_raw = _paginate_marker(
            self._iam,
            "list_attached_role_policies",
            "AttachedPolicies",
            RoleName=role_name,
        )
        if any(
            not isinstance(item, Mapping)
            or not isinstance(item.get("PolicyArn"), str)
            for item in attached_raw
        ):
            raise PlanPermissionRepairError(
                "ROLE_POLICY_READBACK_MALFORMED",
                "generated role managed policies are malformed",
            )
        attached = tuple(sorted(str(item["PolicyArn"]) for item in attached_raw))
        if len(attached) != len(set(attached)):
            raise PlanPermissionRepairError(
                "ROLE_POLICY_READBACK_MALFORMED",
                "generated role managed policies are duplicated",
            )
        inline_raw = _paginate_marker(
            self._iam,
            "list_role_policies",
            "PolicyNames",
            RoleName=role_name,
        )
        if any(not isinstance(item, str) or not item for item in inline_raw):
            raise PlanPermissionRepairError(
                "ROLE_POLICY_READBACK_MALFORMED",
                "generated role inline policies are malformed",
            )
        inline_names = tuple(sorted(inline_raw))
        if len(inline_names) != len(set(inline_names)):
            raise PlanPermissionRepairError(
                "ROLE_POLICY_READBACK_MALFORMED",
                "generated role inline policies are duplicated",
            )
        if PLAN_ROLE_INLINE_POLICY_NAME not in inline_names:
            raise PlanPermissionRepairError(
                "ROLE_POLICY_MISSING", "generated role inline policy is absent"
            )
        policy_response = _checked_page(
            self._iam.get_role_policy(
                RoleName=role_name,
                PolicyName=PLAN_ROLE_INLINE_POLICY_NAME,
            ),
            "get_role_policy",
        )
        if (
            policy_response.get("RoleName") != role_name
            or policy_response.get("PolicyName")
            != PLAN_ROLE_INLINE_POLICY_NAME
        ):
            raise PlanPermissionRepairError(
                "ROLE_POLICY_READBACK_MALFORMED",
                "generated role inline policy binding differs",
            )
        inline_policy = _normalize_policy(policy_response.get("PolicyDocument"))
        boundary_raw = role.get("PermissionsBoundary")
        if boundary_raw is None:
            boundary_arn = None
        elif (
            isinstance(boundary_raw, Mapping)
            and boundary_raw.get("PermissionsBoundaryType") == "Policy"
            and isinstance(boundary_raw.get("PermissionsBoundaryArn"), str)
        ):
            boundary_arn = str(boundary_raw["PermissionsBoundaryArn"])
        else:
            raise PlanPermissionRepairError(
                "ROLE_BOUNDARY_MALFORMED",
                "generated role permissions boundary is malformed",
            )
        return _RoleState(
            snapshot=RoleSnapshot(
                role_arn=expected_arn,
                role_name=role_name,
                saml_provider_arn=provider_arn,
                saml_audience=audience,
                inline_policy_name=PLAN_ROLE_INLINE_POLICY_NAME,
                inline_policy=inline_policy,
                attached_managed_policy_arns=attached,
                extra_inline_policy_names=tuple(
                    item
                    for item in inline_names
                    if item != PLAN_ROLE_INLINE_POLICY_NAME
                ),
                permissions_boundary_arn=boundary_arn,
            ),
            inline_policy=inline_policy,
        )

    def _capture(self, seed: Mapping[str, Any]) -> PlanPermissionSnapshot:
        self._instance(seed)
        user = _checked_page(
            self._identitystore.describe_user(
                IdentityStoreId=seed["identity_store_id"],
                UserId=seed["principal_id"],
            ),
            "describe_user",
        )
        if user.get("UserId") != seed["principal_id"]:
            raise PlanPermissionRepairError(
                "PRINCIPAL_READBACK_MISMATCH",
                "Identity Center principal differs",
            )
        plan = self._permission_set(
            instance_arn=str(seed["instance_arn"]),
            permission_set_arn=str(seed["permission_set_arn"]),
        )
        invoker = self._permission_set(
            instance_arn=str(seed["instance_arn"]),
            permission_set_arn=str(seed["repair_invoker_permission_set_arn"]),
        )
        expected_invoker_policy = _json_object(
            (
                Path(__file__).resolve().parents[1]
                / "policies/iam/"
                "platform-authority-bootstrap-plan-repair-invoker-role.json"
            ).read_text(encoding="utf-8"),
            "BUNDLED_POLICY_INVALID",
        )
        expected_assignment = (
            Assignment("USER", str(seed["principal_id"])),
        )
        if (
            invoker.permission_set.get("Name") != INVOKER_PERMISSION_SET_NAME
            or invoker.permission_set.get("Description")
            != INVOKER_PERMISSION_SET_DESCRIPTION
            or invoker.permission_set.get("SessionDuration")
            != PLAN_SESSION_DURATION
            or invoker.permission_set.get("RelayState") not in (None, "")
            or dict(invoker.tags) != self._expected_invoker_tags
            or dict(invoker.inline_policy) != expected_invoker_policy
            or invoker.managed_policy_arns
            or invoker.customer_policy_references
            or invoker.boundary_present
            or invoker.assignments != expected_assignment
            or invoker.accounts != (AUTHORITY_ACCOUNT_ID,)
            or self._pending_count(
                str(seed["instance_arn"]),
                str(seed["repair_invoker_permission_set_arn"]),
            )
            != 0
        ):
            raise PlanPermissionRepairError(
                "INVOKER_BINDING_MISMATCH",
                "invoke-only permission-set binding differs",
            )
        roles = self._roles()
        plan_role = self._role(
            roles,
            prefix=PLAN_ROLE_PREFIX,
            saml_provider_arn=str(seed["saml_provider_arn"]),
        )
        invoker_role = self._role(
            roles,
            prefix=INVOKER_ROLE_PREFIX,
            saml_provider_arn=str(seed["saml_provider_arn"]),
        )
        if dict(invoker_role.inline_policy) != expected_invoker_policy:
            raise PlanPermissionRepairError(
                "INVOKER_ROLE_POLICY_MISMATCH",
                "invoke-only generated role policy differs",
            )
        if (
            plan.permission_set.get("Name") != PLAN_PERMISSION_SET_NAME
            or plan.permission_set.get("Description")
            != self._expected_description
            or plan.permission_set.get("SessionDuration")
            != PLAN_SESSION_DURATION
            or plan.permission_set.get("RelayState") not in (None, "")
            or dict(plan.tags) != self._expected_plan_tags
            or plan.managed_policy_arns
            or plan.customer_policy_references
            or plan.boundary_present
            or plan.assignments != expected_assignment
            or plan.accounts != (AUTHORITY_ACCOUNT_ID,)
            or plan_role.snapshot.attached_managed_policy_arns
            or plan_role.snapshot.extra_inline_policy_names
            or plan_role.snapshot.permissions_boundary_arn is not None
        ):
            raise PlanPermissionRepairError(
                "PLAN_BINDING_MISMATCH",
                "bootstrap Plan permission-set binding differs",
            )
        graph_digest = self._graph_supplier(
            invoker_role.snapshot.role_arn,
            invoker_role.inline_policy,
        )
        pending_count = self._pending_count(
            str(seed["instance_arn"]), str(seed["permission_set_arn"])
        )
        permission_set = plan.permission_set
        snapshot = PlanPermissionSnapshot(
            instance_arn=str(seed["instance_arn"]),
            identity_store_id=str(seed["identity_store_id"]),
            identity_center_kms_mode=str(seed["identity_center_kms_mode"]),
            identity_center_kms_key_arn=seed["identity_center_kms_key_arn"],
            permission_set_arn=str(seed["permission_set_arn"]),
            permission_set_name=str(permission_set.get("Name", "")),
            permission_set_description=str(
                permission_set.get("Description", "")
            ),
            session_duration=str(permission_set.get("SessionDuration", "")),
            relay_state=(
                None
                if permission_set.get("RelayState") in (None, "")
                else str(permission_set.get("RelayState"))
            ),
            permission_set_tags=plan.tags,
            inline_policy=dict(plan.inline_policy),
            managed_policy_arns=plan.managed_policy_arns,
            customer_managed_policy_references=(
                plan.customer_policy_references
            ),
            permissions_boundary_present=plan.boundary_present,
            assignments=plan.assignments,
            provisioned_account_ids=plan.accounts,
            pending_operation_count=pending_count,
            role=plan_role.snapshot,
            invocation_authority_graph_digest=graph_digest,
        )
        return snapshot

    def discover(self, seed: Mapping[str, Any]) -> PlanPermissionSnapshot:
        try:
            return self._capture(seed)
        except (PlanPermissionRepairError, AuthorityInventoryError):
            raise
        except Exception:
            raise PlanPermissionRepairError(
                "PROVIDER_READ_FAILED",
                "live Plan state could not be read completely",
            ) from None

    def snapshot(self, intent: Mapping[str, Any]) -> PlanPermissionSnapshot:
        return self.discover(intent)

    def put_inline_policy(
        self, intent: Mapping[str, Any], policy_json: str
    ) -> None:
        try:
            parsed = json.loads(policy_json)
        except json.JSONDecodeError as exc:
            raise PlanPermissionRepairError(
                "TARGET_POLICY_INVALID", "target inline policy is malformed"
            ) from exc
        expected = render_target_policy(str(intent["change_set_name"]))
        if parsed != expected or len(policy_json.encode("utf-8")) > 32_768:
            raise PlanPermissionRepairError(
                "TARGET_POLICY_INVALID", "target inline policy differs"
            )
        _require_budget(
            self._remaining_time_ms, MIN_MUTATION_CALL_REMAINING_MS
        )
        try:
            self._sso.put_inline_policy_to_permission_set(
                InstanceArn=intent["instance_arn"],
                PermissionSetArn=intent["permission_set_arn"],
                InlinePolicy=policy_json,
            )
        except Exception:
            raise ProviderResponseAmbiguous(
                "PutInlinePolicy outcome is ambiguous"
            ) from None

    def provision_permission_set(
        self, intent: Mapping[str, Any]
    ) -> OperationResult:
        _require_budget(
            self._remaining_time_ms, MIN_MUTATION_CALL_REMAINING_MS
        )
        try:
            response = _checked_page(
                self._sso.provision_permission_set(
                    InstanceArn=intent["instance_arn"],
                    PermissionSetArn=intent["permission_set_arn"],
                    TargetId=AUTHORITY_ACCOUNT_ID,
                    TargetType="AWS_ACCOUNT",
                ),
                "provision_permission_set",
            ).get("PermissionSetProvisioningStatus")
        except Exception:
            raise ProviderResponseAmbiguous(
                "ProvisionPermissionSet outcome is ambiguous"
            ) from None
        _validate_operation_coordinates(response, intent)
        return _parse_operation(response)

    def describe_provisioning(
        self, intent: Mapping[str, Any], request_id: str
    ) -> str:
        if _REQUEST_ID.fullmatch(request_id) is None:
            raise ProviderResponseAmbiguous("provisioning request ID is malformed")
        try:
            response = _checked_page(
                self._sso.describe_permission_set_provisioning_status(
                    InstanceArn=intent["instance_arn"],
                    ProvisionPermissionSetRequestId=request_id,
                ),
                "describe_permission_set_provisioning_status",
            ).get("PermissionSetProvisioningStatus")
        except Exception:
            raise ProviderResponseAmbiguous(
                "provisioning status readback is ambiguous"
            ) from None
        operation = _parse_operation(response)
        _validate_operation_coordinates(response, intent)
        if operation.request_id != request_id:
            raise ProviderResponseAmbiguous(
                "provisioning request identity differs"
            )
        return operation.status


def _validate_operation_coordinates(
    value: Any, intent: Mapping[str, Any]
) -> None:
    if not isinstance(value, Mapping):
        raise ProviderResponseAmbiguous("provisioning status is absent")
    expected = {
        "PermissionSetArn": intent["permission_set_arn"],
        "TargetId": AUTHORITY_ACCOUNT_ID,
        "TargetType": "AWS_ACCOUNT",
    }
    if any(
        key in value and value.get(key) != expected_value
        for key, expected_value in expected.items()
    ):
        raise ProviderResponseAmbiguous(
            "provisioning operation coordinates differ"
        )


def _parse_operation(value: Any) -> OperationResult:
    if not isinstance(value, Mapping):
        raise ProviderResponseAmbiguous("provisioning status is absent")
    request_id = value.get("RequestId")
    status = value.get("Status")
    if (
        not isinstance(request_id, str)
        or _REQUEST_ID.fullmatch(request_id) is None
        or status not in {"IN_PROGRESS", "SUCCEEDED", "FAILED"}
    ):
        raise ProviderResponseAmbiguous("provisioning status is malformed")
    return OperationResult(request_id=request_id, status=str(status))


class DynamoLedger:
    """Strongly consistent one-shot ledger using conditional SDK calls."""

    def __init__(self, client: Any, table_name: str) -> None:
        self._client = client
        self._table_name = table_name

    @staticmethod
    def _encode_value(value: Any) -> Mapping[str, Any]:
        if type(value) is bool:
            return {"BOOL": value}
        if type(value) is int:
            return {"N": str(value)}
        if value is None:
            return {"NULL": True}
        if isinstance(value, str):
            return {"S": value}
        raise PlanPermissionRepairError(
            "LEDGER_MALFORMED", "ledger contains an unsupported value"
        )

    @classmethod
    def _encode(cls, value: Mapping[str, Any]) -> dict[str, Mapping[str, Any]]:
        return {key: cls._encode_value(item) for key, item in value.items()}

    @staticmethod
    def _decode(value: Mapping[str, Mapping[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, item in value.items():
            if not isinstance(key, str) or not isinstance(item, Mapping):
                raise PlanPermissionRepairError(
                    "LEDGER_MALFORMED", "ledger value is malformed"
                )
            if set(item) == {"S"} and isinstance(item["S"], str):
                result[key] = item["S"]
            elif (
                set(item) == {"N"}
                and isinstance(item["N"], str)
                and _DYNAMO_INTEGER.fullmatch(item["N"]) is not None
            ):
                result[key] = int(item["N"])
            elif set(item) == {"BOOL"} and type(item["BOOL"]) is bool:
                result[key] = item["BOOL"]
            elif set(item) == {"NULL"} and item["NULL"] is True:
                result[key] = None
            else:
                raise PlanPermissionRepairError(
                    "LEDGER_MALFORMED", "ledger value is malformed"
                )
        return result

    def put_if_absent(self, ledger: Mapping[str, Any]) -> None:
        validate_private_ledger(ledger)
        try:
            self._client.put_item(
                TableName=self._table_name,
                Item=self._encode(ledger),
                ConditionExpression="attribute_not_exists(repair_id)",
                ReturnConsumedCapacity="NONE",
            )
        except Exception as exc:
            if _provider_code(exc) == "ConditionalCheckFailedException":
                raise PlanPermissionRepairError(
                    "REPLAY_BLOCKED", "repair ID is already present"
                ) from None
            raise ProviderResponseAmbiguous(
                "durable Plan write outcome is ambiguous"
            ) from None

    def read(self, repair_id: str) -> Mapping[str, Any] | None:
        try:
            response = _checked_page(
                self._client.get_item(
                    TableName=self._table_name,
                    Key={"repair_id": {"S": repair_id}},
                    ConsistentRead=True,
                    ReturnConsumedCapacity="NONE",
                ),
                "dynamodb_get_item",
            )
        except PlanPermissionRepairError:
            raise
        except Exception:
            raise PlanPermissionRepairError(
                "LEDGER_READ_FAILED", "durable ledger read failed"
            ) from None
        item = response.get("Item")
        if item is None:
            return None
        if not isinstance(item, Mapping) or not all(
            isinstance(value, Mapping) for value in item.values()
        ):
            raise PlanPermissionRepairError(
                "LEDGER_MALFORMED", "durable ledger item is malformed"
            )
        return self._decode(item)  # type: ignore[arg-type]

    def compare_and_swap(
        self,
        *,
        repair_id: str,
        expected_ledger_digest: str,
        expected_ledger: Mapping[str, Any],
        replacement: Mapping[str, Any],
    ) -> None:
        validate_private_ledger(expected_ledger)
        validate_private_ledger(replacement)
        if (
            expected_ledger.get("repair_id") != repair_id
            or expected_ledger.get("ledger_digest")
            != expected_ledger_digest
        ):
            raise PlanPermissionRepairError(
                "LEDGER_CAS_MISMATCH",
                "expected durable ledger coordinates differ",
            )
        names: dict[str, str] = {}
        values: dict[str, Mapping[str, Any]] = {}
        conditions: list[str] = []
        for index, key in enumerate(sorted(expected_ledger)):
            name = f"#e{index}"
            value = f":e{index}"
            names[name] = key
            values[value] = self._encode_value(expected_ledger[key])
            conditions.append(f"{name} = {value}")
        assignments: list[str] = []
        for index, key in enumerate(sorted(replacement)):
            if key == "repair_id":
                continue
            name = f"#n{index}"
            value = f":v{index}"
            names[name] = key
            values[value] = self._encode_value(replacement[key])
            assignments.append(f"{name} = {value}")
        try:
            raw_response = self._client.update_item(
                TableName=self._table_name,
                Key={"repair_id": {"S": repair_id}},
                ConditionExpression=" AND ".join(conditions),
                UpdateExpression="SET " + ", ".join(assignments),
                ExpressionAttributeNames=names,
                ExpressionAttributeValues=values,
                ReturnValues="ALL_NEW",
                ReturnConsumedCapacity="NONE",
            )
        except Exception as exc:
            if _provider_code(exc) == "ConditionalCheckFailedException":
                raise PlanPermissionRepairError(
                    "LEDGER_CAS_MISMATCH",
                    "durable ledger compare-and-swap condition failed",
                ) from None
            raise ProviderResponseAmbiguous(
                "durable ledger transition outcome is ambiguous"
            ) from None

        try:
            response = _checked_page(raw_response, "dynamodb_update_item")
            attributes = response.get("Attributes")
            if not isinstance(attributes, Mapping) or not all(
                isinstance(value, Mapping) for value in attributes.values()
            ):
                raise ValueError("malformed ALL_NEW")
            decoded = self._decode(attributes)  # type: ignore[arg-type]
        except Exception:
            raise ProviderResponseAmbiguous(
                "durable ledger transition readback is ambiguous"
            ) from None
        if (
            decoded != dict(replacement)
        ):
            raise ProviderResponseAmbiguous(
                "durable ledger transition readback differs"
            )


class BotoSessionFactory:
    """Build zero-retry clients and verify every assumed session."""

    def __init__(
        self,
        *,
        boto3_module: Any,
        config_type: Any,
        remaining_time_ms: Callable[[], int],
    ) -> None:
        self._boto3 = boto3_module
        self._remaining_time_ms = remaining_time_ms
        self.client_config = config_type(
            region_name=REGION,
            retries={"mode": "standard", "total_max_attempts": 1},
            connect_timeout=SDK_CONNECT_TIMEOUT_SECONDS,
            read_timeout=SDK_READ_TIMEOUT_SECONDS,
        )

    def local(self, service: str, *, region: str = REGION) -> Any:
        return _BudgetClient(
            self._boto3.client(
                service, region_name=region, config=self.client_config
            ),
            self._remaining_time_ms,
        )

    def _assume(
        self, role_arn: str, repair_id: str, purpose: str
    ) -> tuple[Mapping[str, Any], str]:
        suffix = canonical_digest({"repair_id": repair_id})[7:23]
        session_name = f"gug376-{purpose}-{suffix}"
        try:
            response = _checked_page(
                self.local("sts").assume_role(
                    RoleArn=role_arn,
                    RoleSessionName=session_name,
                    SourceIdentity=session_name,
                    DurationSeconds=ASSUME_ROLE_DURATION_SECONDS,
                ),
                "assume_role",
            )
        except Exception:
            raise PlanPermissionRepairError(
                "ASSUME_ROLE_FAILED", "exact service role could not be assumed"
            ) from None
        credentials = response.get("Credentials")
        assumed = response.get("AssumedRoleUser")
        role_name = role_arn.rsplit("/", 1)[-1]
        account = role_arn.split(":", 5)[4]
        expected_arn = (
            f"arn:aws:sts::{account}:assumed-role/{role_name}/{session_name}"
        )
        if (
            not isinstance(credentials, Mapping)
            or not isinstance(assumed, Mapping)
            or assumed.get("Arn") != expected_arn
            or response.get("SourceIdentity") != session_name
        ):
            raise PlanPermissionRepairError(
                "ASSUME_ROLE_IDENTITY_MISMATCH",
                "assumed service-role identity differs",
            )
        required = ("AccessKeyId", "SecretAccessKey", "SessionToken")
        if any(
            not isinstance(credentials.get(key), str) or not credentials.get(key)
            for key in required
        ):
            raise PlanPermissionRepairError(
                "ASSUME_ROLE_CREDENTIALS_MALFORMED",
                "assumed service-role credentials are malformed",
            )
        return credentials, expected_arn

    def assumed_clients(
        self,
        *,
        role_arn: str,
        repair_id: str,
        purpose: str,
        services: Sequence[str],
    ) -> tuple[dict[str, Any], str, Mapping[str, Any]]:
        credentials, expected_arn = self._assume(role_arn, repair_id, purpose)
        kwargs = {
            "aws_access_key_id": credentials["AccessKeyId"],
            "aws_secret_access_key": credentials["SecretAccessKey"],
            "aws_session_token": credentials["SessionToken"],
        }
        clients = {
            service: _BudgetClient(
                self._boto3.client(
                    service,
                    region_name=REGION,
                    config=self.client_config,
                    **kwargs,
                ),
                self._remaining_time_ms,
            )
            for service in services
        }
        assumed_sts = _BudgetClient(
            self._boto3.client(
                "sts",
                region_name=REGION,
                config=self.client_config,
                **kwargs,
            ),
            self._remaining_time_ms,
        )
        identity = _checked_page(
            assumed_sts.get_caller_identity(), "get_caller_identity"
        )
        if identity.get("Account") != role_arn.split(":", 5)[4] or (
            identity.get("Arn") != expected_arn
        ):
            raise PlanPermissionRepairError(
                "ASSUME_ROLE_IDENTITY_MISMATCH",
                "assumed session caller identity differs",
            )
        return clients, expected_arn, credentials

    def inspector_adapter(
        self, *, repair_id: str, clock: Callable[[], datetime]
    ) -> tuple[AwsReadOnlyInventoryAdapter, str]:
        clients, session_arn, credentials = self.assumed_clients(
            role_arn=INSPECTOR_ROLE_ARN,
            repair_id=repair_id,
            purpose="authority",
            services=("sts", "ec2", "lambda", "iam"),
        )
        canonical_principal = session_arn.rsplit("/", 1)[0]

        def regional(service: str, region: str) -> Any:
            return _BudgetClient(
                self._boto3.client(
                    service,
                    region_name=region,
                    config=self.client_config,
                    aws_access_key_id=credentials["AccessKeyId"],
                    aws_secret_access_key=credentials["SecretAccessKey"],
                    aws_session_token=credentials["SessionToken"],
                ),
                self._remaining_time_ms,
            )

        adapter = AwsReadOnlyInventoryAdapter(
            sts=clients["sts"],
            ec2=clients["ec2"],
            lambda_client=clients["lambda"],
            iam=clients["iam"],
            lambda_client_factory=lambda region: regional("lambda", region),
            clock=clock,
        )
        return adapter, digest_text(canonical_principal)


class InvocationGraphVerifier:
    def __init__(
        self,
        *,
        adapter: AwsReadOnlyInventoryAdapter,
        collector_principal_digest: str,
        saml_provider_arn: str,
        clock: Callable[[], datetime],
        repair_id: str,
    ) -> None:
        self._adapter = adapter
        self._collector_principal_digest = collector_principal_digest
        self._saml_provider_arn = saml_provider_arn
        self._clock = clock
        self._repair_id = repair_id
        self._index = 0

    def snapshot(
        self, invoker_role_arn: str, invoker_policy: Mapping[str, Any]
    ) -> str:
        binding = RepairInvocationAuthorityBinding(
            authority_account_id=AUTHORITY_ACCOUNT_ID,
            region=REGION,
            invoker_role_arn=invoker_role_arn,
            invoker_policy_digest=canonical_digest(dict(invoker_policy)),
            collector_principal_digest=self._collector_principal_digest,
            saml_provider_arn=self._saml_provider_arn,
            plan_function_name=FUNCTION_NAMES["plan"],
            repair_function_name=FUNCTION_NAMES["repair"],
            reconcile_function_name=FUNCTION_NAMES["reconcile"],
            invoker_role_name_prefix=INVOKER_ROLE_PREFIX,
        )
        self._index += 1
        snapshots = collect_provider_invocation_snapshots(
            adapter=self._adapter,
            binding=binding,
            scan_id=(
                f"gug376:{canonical_digest({'value': self._repair_id})[7:23]}:"
                f"{self._index:03d}"
            ),
        )
        result = verify_provider_invocation_authority(
            binding=binding,
            snapshots=snapshots,
            decision_at=(
                self._clock()
                .astimezone(UTC)
                .replace(microsecond=0)
                .isoformat()
                .replace("+00:00", "Z")
            ),
        )
        return result.authority_graph_digest


def _absent_lambda_surface(client: Any, method: str, **kwargs: Any) -> None:
    try:
        getattr(client, method)(**kwargs)
    except Exception as exc:
        if _provider_code(exc) in {
            "ResourceNotFoundException",
            "ResourceNotFound",
        }:
            return
        raise PlanPermissionRepairError(
            "LAMBDA_CONTROL_READ_FAILED",
            "Lambda private-surface readback failed",
        ) from None
    raise PlanPermissionRepairError(
        "LAMBDA_PUBLIC_SURFACE_PRESENT",
        "Lambda resource policy or function URL is present",
    )


def _verify_lambda_control_plane(
    *,
    client: Any,
    env: Mapping[str, str],
) -> dict[str, str]:
    missing_environment = COMMON_FUNCTION_ENVIRONMENT_KEYS - set(env)
    if missing_environment:
        raise PlanPermissionRepairError(
            "IMMUTABLE_ENVIRONMENT_MISSING",
            "immutable Lambda environment is incomplete",
        )
    common_environment = {
        key: env[key] for key in COMMON_FUNCTION_ENVIRONMENT_KEYS
    }
    versions: dict[str, str] = {}
    for mode, function_name in FUNCTION_NAMES.items():
        qualifier = FUNCTION_QUALIFIERS[mode]
        alias = _checked_page(
            client.get_alias(FunctionName=function_name, Name=qualifier),
            "get_alias",
        )
        version = alias.get("FunctionVersion")
        expected_alias_arn = (
            f"arn:aws:lambda:{REGION}:{AUTHORITY_ACCOUNT_ID}:"
            f"function:{function_name}:{qualifier}"
        )
        if (
            alias.get("AliasArn") != expected_alias_arn
            or alias.get("Name") != qualifier
            or not isinstance(version, str)
            or _FUNCTION_VERSION.fullmatch(version) is None
            or alias.get("Description") not in (None, "")
            or alias.get("RoutingConfig")
            not in (None, {}, {"AdditionalVersionWeights": {}})
        ):
            raise PlanPermissionRepairError(
                "LAMBDA_ALIAS_MISMATCH", "published Lambda alias differs"
            )
        versions[mode] = version
        configuration = _checked_page(
            client.get_function_configuration(
                FunctionName=function_name, Qualifier=version
            ),
            "get_function_configuration",
        )
        role_arn = (
            f"arn:aws:iam::{AUTHORITY_ACCOUNT_ID}:role/"
            f"{EXECUTION_ROLE_NAMES[mode]}"
        )
        expected_function_arn = (
            f"arn:aws:lambda:{REGION}:{AUTHORITY_ACCOUNT_ID}:"
            f"function:{function_name}:{version}"
        )
        exact = {
            "FunctionName": function_name,
            "FunctionArn": expected_function_arn,
            "Version": version,
            "Runtime": "python3.12",
            "Handler": EXPECTED_HANDLERS[mode],
            "Role": role_arn,
            "MemorySize": 1024,
            "Timeout": EXPECTED_TIMEOUTS[mode],
            "PackageType": "Zip",
            "CodeSha256": env.get("EXPECTED_ARTIFACT_CODE_SHA256"),
            "Description": (
                EXPECTED_VERSION_DESCRIPTION_PREFIXES[mode]
                + env["IMMU_CONFIG_DIGEST"]
            ),
            "State": "Active",
            "LastUpdateStatus": "Successful",
        }
        if any(configuration.get(key) != value for key, value in exact.items()):
            raise PlanPermissionRepairError(
                "LAMBDA_CONFIGURATION_MISMATCH",
                "published Lambda configuration differs",
            )
        runtime_configuration = _checked_page(
            client.get_runtime_management_config(
                FunctionName=function_name,
                Qualifier=version,
            ),
            "get_runtime_management_config",
        )
        runtime_version_arn = runtime_configuration.get(
            "RuntimeVersionArn"
        )
        if (
            set(runtime_configuration)
            - {
                "FunctionArn",
                "ResponseMetadata",
                "RuntimeVersionArn",
                "UpdateRuntimeOn",
            }
            or runtime_configuration.get("FunctionArn")
            != expected_function_arn
            or runtime_configuration.get("UpdateRuntimeOn")
            != "FunctionUpdate"
            or not isinstance(runtime_version_arn, str)
            or _RUNTIME_VERSION_ARN.fullmatch(runtime_version_arn) is None
            or configuration.get("RuntimeVersionConfig")
            != {"RuntimeVersionArn": runtime_version_arn}
        ):
            raise PlanPermissionRepairError(
                "LAMBDA_RUNTIME_MANAGEMENT_MISMATCH",
                "published Lambda runtime management differs",
            )
        expected_environment = dict(common_environment)
        if mode in {"repair", "reconcile"}:
            expected_environment["PLAN_FUNCTION_VERSION"] = versions["plan"]
        if mode == "reconcile":
            expected_environment["REPAIR_FUNCTION_VERSION"] = versions[
                "repair"
            ]
        environment = configuration.get("Environment")
        if (
            not isinstance(environment, Mapping)
            or not set(environment) <= {"Error", "Variables"}
            or environment.get("Error") not in (None, {})
            or environment.get("Variables") != expected_environment
        ):
            raise PlanPermissionRepairError(
                "LAMBDA_ENVIRONMENT_MISMATCH",
                "published Lambda environment differs",
            )
        if configuration.get("Architectures") != ["x86_64"]:
            raise PlanPermissionRepairError(
                "LAMBDA_CONFIGURATION_MISMATCH",
                "published Lambda architecture differs",
            )
        vpc = configuration.get("VpcConfig")
        if vpc not in (None, {}):
            if not isinstance(vpc, Mapping) or (
                not set(vpc)
                <= {
                    "Ipv6AllowedForDualStack",
                    "SecurityGroupIds",
                    "SubnetIds",
                    "VpcId",
                }
                or vpc.get("SubnetIds") not in (None, [])
                or vpc.get("SecurityGroupIds") not in (None, [])
                or vpc.get("VpcId") not in (None, "")
                or vpc.get("Ipv6AllowedForDualStack") not in (None, False)
            ):
                raise PlanPermissionRepairError(
                    "LAMBDA_CONFIGURATION_MISMATCH",
                    "published Lambda VPC binding differs",
                )
        logging = configuration.get("LoggingConfig")
        if logging not in (None, {}):
            if not isinstance(logging, Mapping) or (
                not set(logging)
                <= {
                    "ApplicationLogLevel",
                    "LogFormat",
                    "LogGroup",
                    "SystemLogLevel",
                }
                or logging.get("LogFormat") not in (None, "Text")
                or logging.get("LogGroup")
                not in (None, f"/aws/lambda/{function_name}")
                or logging.get("ApplicationLogLevel") not in (None, "")
                or logging.get("SystemLogLevel") not in (None, "", "INFO")
            ):
                raise PlanPermissionRepairError(
                    "LAMBDA_CONFIGURATION_MISMATCH",
                    "published Lambda logging controls differ",
                )
        snap_start = configuration.get("SnapStart")
        if snap_start not in (
            None,
            {},
            {"ApplyOn": "None", "OptimizationStatus": "Off"},
        ):
            raise PlanPermissionRepairError(
                "LAMBDA_CONFIGURATION_MISMATCH",
                "published Lambda SnapStart controls differ",
            )
        side_channels = (
            configuration.get("DeadLetterConfig") not in (None, {})
            or configuration.get("KMSKeyArn") not in (None, "")
            or configuration.get("Layers") not in (None, [])
            or configuration.get("FileSystemConfigs") not in (None, [])
            or configuration.get("MasterArn") not in (None, "")
            or configuration.get("ImageConfigResponse") not in (None, {})
            or configuration.get("TracingConfig")
            not in (None, {"Mode": "PassThrough"})
            or configuration.get("EphemeralStorage")
            not in (None, {"Size": 512})
        )
        if side_channels:
            raise PlanPermissionRepairError(
                "LAMBDA_CONFIGURATION_MISMATCH",
                "published Lambda side-channel configuration differs",
            )
        if configuration.get("SigningProfileVersionArn") != env.get(
            "EXPECTED_SIGNING_PROFILE_VERSION_ARN"
        ):
            raise PlanPermissionRepairError(
                "LAMBDA_SIGNING_MISMATCH",
                "published Lambda signer binding differs",
            )
        signing = _checked_page(
            client.get_function_code_signing_config(FunctionName=function_name),
            "get_function_code_signing_config",
        )
        if signing.get("CodeSigningConfigArn") != env.get(
            "EXPECTED_CODE_SIGNING_CONFIG_ARN"
        ):
            raise PlanPermissionRepairError(
                "LAMBDA_SIGNING_MISMATCH", "Lambda signing binding differs"
            )
        concurrency = _checked_page(
            client.get_function_concurrency(FunctionName=function_name),
            "get_function_concurrency",
        )
        if concurrency.get("ReservedConcurrentExecutions") != 1:
            raise PlanPermissionRepairError(
                "LAMBDA_CONCURRENCY_MISMATCH",
                "Lambda reserved concurrency differs",
            )
        invoke = _checked_page(
            client.get_function_event_invoke_config(
                FunctionName=function_name, Qualifier=qualifier
            ),
            "get_function_event_invoke_config",
        )
        if (
            invoke.get("MaximumRetryAttempts") != 0
            or invoke.get("MaximumEventAgeInSeconds") != 60
            or invoke.get("DestinationConfig")
            not in (None, {}, {"OnSuccess": {}, "OnFailure": {}})
        ):
            raise PlanPermissionRepairError(
                "LAMBDA_RETRY_CONFIGURATION_MISMATCH",
                "Lambda asynchronous retry controls differ",
            )
        _absent_lambda_surface(client, "get_policy", FunctionName=function_name)
        _absent_lambda_surface(
            client, "get_function_url_config", FunctionName=function_name
        )
    signing_config = _checked_page(
        client.get_code_signing_config(
            CodeSigningConfigArn=env["EXPECTED_CODE_SIGNING_CONFIG_ARN"]
        ),
        "get_code_signing_config",
    ).get("CodeSigningConfig")
    if not isinstance(signing_config, Mapping) or (
        signing_config.get("CodeSigningConfigArn")
        != env["EXPECTED_CODE_SIGNING_CONFIG_ARN"]
    ):
        raise PlanPermissionRepairError(
            "LAMBDA_SIGNING_MISMATCH", "code-signing configuration differs"
        )
    allowed = signing_config.get("AllowedPublishers")
    policies = signing_config.get("CodeSigningPolicies")
    if (
        not isinstance(allowed, Mapping)
        or set(allowed) != {"SigningProfileVersionArns"}
        or allowed.get("SigningProfileVersionArns")
        != [env["EXPECTED_SIGNING_PROFILE_VERSION_ARN"]]
        or not isinstance(policies, Mapping)
        or set(policies) != {"UntrustedArtifactOnDeployment"}
        or policies.get("UntrustedArtifactOnDeployment") != "Enforce"
    ):
        raise PlanPermissionRepairError(
            "LAMBDA_SIGNING_MISMATCH", "code-signing policy differs"
        )
    return versions


def _json_object(value: Any, code: str) -> dict[str, Any]:
    if isinstance(value, Mapping):
        return dict(value)
    if isinstance(value, str):
        try:
            parsed = json.loads(
                value, object_pairs_hook=_reject_duplicate_json_keys
            )
        except (json.JSONDecodeError, ValueError) as exc:
            raise PlanPermissionRepairError(
                code, "provider policy JSON is malformed"
            ) from exc
        if isinstance(parsed, Mapping):
            return dict(parsed)
    raise PlanPermissionRepairError(code, "provider policy is malformed")


def _expected_ledger_resource_policy(table_arn: str) -> dict[str, Any]:
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "DenyPlanCreationOutsidePlanExecution",
                "Effect": "Deny",
                "Principal": {"AWS": "*"},
                "Action": "dynamodb:PutItem",
                "Resource": table_arn,
                "Condition": {
                    "ArnNotEquals": {
                        "aws:PrincipalArn": (
                            "arn:aws:iam::042360977644:role/"
                            "ScanalyzeBootstrapPlanRepairPlan"
                        )
                    }
                },
            },
            {
                "Sid": "DenyPlanConsumptionOutsideRepairExecution",
                "Effect": "Deny",
                "Principal": {"AWS": "*"},
                "Action": "dynamodb:UpdateItem",
                "Resource": table_arn,
                "Condition": {
                    "ArnNotEquals": {
                        "aws:PrincipalArn": (
                            "arn:aws:iam::042360977644:role/"
                            "ScanalyzeBootstrapPlanRepairExecution"
                        )
                    }
                },
            },
            {
                "Sid": "DenyEveryUnsupportedLedgerMutation",
                "Effect": "Deny",
                "Principal": {"AWS": "*"},
                "Action": [
                    "dynamodb:BatchWriteItem",
                    "dynamodb:DeleteItem",
                    "dynamodb:PartiQLDelete",
                    "dynamodb:PartiQLInsert",
                    "dynamodb:PartiQLUpdate",
                    "dynamodb:TransactWriteItems",
                ],
                "Resource": table_arn,
            },
        ],
    }


def _expected_ledger_key_policy(key_arn: str) -> dict[str, Any]:
    del key_arn
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "DelegateAdministrationToExactAuthorityAccount",
                "Effect": "Allow",
                "Principal": {
                    "AWS": "arn:aws:iam::042360977644:root"
                },
                "Action": "kms:*",
                "Resource": "*",
            },
            {
                "Sid": (
                    "PermitDynamoDbCryptographicUseOnlyFromAuthorityAccount"
                ),
                "Effect": "Allow",
                "Principal": {
                    "AWS": "arn:aws:iam::042360977644:root"
                },
                "Action": [
                    "kms:Decrypt",
                    "kms:DescribeKey",
                    "kms:Encrypt",
                    "kms:GenerateDataKey*",
                    "kms:ReEncrypt*",
                ],
                "Resource": "*",
                "Condition": {
                    "StringEquals": {
                        "kms:CallerAccount": AUTHORITY_ACCOUNT_ID,
                        "kms:ViaService": "dynamodb.us-east-1.amazonaws.com",
                        "kms:EncryptionContext:aws:dynamodb:tableName": (
                            "scanalyze-platform-authority-plan-policy-"
                            "repair-ledger"
                        ),
                        "kms:EncryptionContext:aws:dynamodb:subscriberId": (
                            AUTHORITY_ACCOUNT_ID
                        ),
                    }
                },
            },
            {
                "Sid": "PermitDynamoDbGrantOnlyForAwsResource",
                "Effect": "Allow",
                "Principal": {
                    "AWS": "arn:aws:iam::042360977644:root"
                },
                "Action": "kms:CreateGrant",
                "Resource": "*",
                "Condition": {
                    "Bool": {"kms:GrantIsForAWSResource": "true"},
                    "StringEquals": {
                        "kms:CallerAccount": AUTHORITY_ACCOUNT_ID,
                        "kms:ViaService": "dynamodb.us-east-1.amazonaws.com",
                    },
                },
            },
        ],
    }


def _verify_ledger_control_plane(
    *, dynamodb: Any, kms: Any, table_name: str, key_arn: str
) -> None:
    table_arn = (
        f"arn:aws:dynamodb:{REGION}:{AUTHORITY_ACCOUNT_ID}:table/{table_name}"
    )
    table_response = _checked_page(
        dynamodb.describe_table(TableName=table_name), "describe_table"
    )
    table = table_response.get("Table")
    if not isinstance(table, Mapping):
        raise PlanPermissionRepairError(
            "LEDGER_CONTROL_MISMATCH", "ledger table readback is malformed"
        )
    billing = table.get("BillingModeSummary")
    sse = table.get("SSEDescription")
    table_class = table.get("TableClassSummary")
    if (
        table.get("TableName") != table_name
        or table.get("TableArn") != table_arn
        or table.get("TableStatus") != "ACTIVE"
        or not isinstance(billing, Mapping)
        or billing.get("BillingMode") != "PAY_PER_REQUEST"
        or table.get("KeySchema")
        != [{"AttributeName": "repair_id", "KeyType": "HASH"}]
        or table.get("AttributeDefinitions")
        != [{"AttributeName": "repair_id", "AttributeType": "S"}]
        or table.get("DeletionProtectionEnabled") is not True
        or not isinstance(table_class, Mapping)
        or table_class.get("TableClass") != "STANDARD"
        or not isinstance(sse, Mapping)
        or sse.get("Status") != "ENABLED"
        or sse.get("SSEType") != "KMS"
        or sse.get("KMSMasterKeyArn") != key_arn
        or table.get("LocalSecondaryIndexes") not in (None, [])
        or table.get("GlobalSecondaryIndexes") not in (None, [])
        or table.get("Replicas") not in (None, [])
        or table.get("LatestStreamArn") not in (None, "")
        or table.get("LatestStreamLabel") not in (None, "")
    ):
        raise PlanPermissionRepairError(
            "LEDGER_CONTROL_MISMATCH", "ledger table controls differ"
        )
    stream = table.get("StreamSpecification")
    if stream not in (None, {}) and (
        not isinstance(stream, Mapping)
        or stream.get("StreamEnabled") is not False
    ):
        raise PlanPermissionRepairError(
            "LEDGER_CONTROL_MISMATCH", "ledger stream controls differ"
        )
    backups_response = _checked_page(
        dynamodb.describe_continuous_backups(TableName=table_name),
        "describe_continuous_backups",
    )
    backups = backups_response.get("ContinuousBackupsDescription")
    pitr = (
        backups.get("PointInTimeRecoveryDescription")
        if isinstance(backups, Mapping)
        else None
    )
    if (
        not isinstance(backups, Mapping)
        or backups.get("ContinuousBackupsStatus") != "ENABLED"
        or not isinstance(pitr, Mapping)
        or pitr.get("PointInTimeRecoveryStatus") != "ENABLED"
        or pitr.get("RecoveryPeriodInDays") != 35
    ):
        raise PlanPermissionRepairError(
            "LEDGER_RECOVERY_MISMATCH", "ledger recovery controls differ"
        )
    ttl_response = _checked_page(
        dynamodb.describe_time_to_live(TableName=table_name),
        "describe_time_to_live",
    )
    ttl = ttl_response.get("TimeToLiveDescription")
    if (
        not isinstance(ttl, Mapping)
        or ttl.get("TimeToLiveStatus") != "DISABLED"
        or ttl.get("AttributeName") not in (None, "")
    ):
        raise PlanPermissionRepairError(
            "LEDGER_TTL_MISMATCH", "ledger TTL controls differ"
        )
    resource_policy_response = _checked_page(
        dynamodb.get_resource_policy(ResourceArn=table_arn),
        "get_resource_policy",
    )
    if _json_object(
        resource_policy_response.get("Policy"), "LEDGER_POLICY_MISMATCH"
    ) != _expected_ledger_resource_policy(table_arn):
        raise PlanPermissionRepairError(
            "LEDGER_POLICY_MISMATCH", "ledger resource policy differs"
        )

    key_id = key_arn.rsplit("/", 1)[-1]
    metadata_response = _checked_page(
        kms.describe_key(KeyId=key_arn), "describe_key"
    )
    metadata = metadata_response.get("KeyMetadata")
    if (
        not isinstance(metadata, Mapping)
        or metadata.get("AWSAccountId") != AUTHORITY_ACCOUNT_ID
        or metadata.get("KeyId") != key_id
        or metadata.get("Arn") != key_arn
        or metadata.get("Enabled") is not True
        or metadata.get("Description")
        != "GUG-376 retained bootstrap Plan policy repair ledger key"
        or metadata.get("KeyUsage") != "ENCRYPT_DECRYPT"
        or metadata.get("KeyState") != "Enabled"
        or metadata.get("Origin") != "AWS_KMS"
        or metadata.get("KeyManager") != "CUSTOMER"
        or metadata.get("KeySpec") != "SYMMETRIC_DEFAULT"
        or metadata.get("MultiRegion") is not False
        or metadata.get("DeletionDate") is not None
        or metadata.get("PendingDeletionWindowInDays") is not None
    ):
        raise PlanPermissionRepairError(
            "LEDGER_KMS_MISMATCH", "ledger KMS key controls differ"
        )
    rotation_response = _checked_page(
        kms.get_key_rotation_status(KeyId=key_arn),
        "get_key_rotation_status",
    )
    if (
        rotation_response.get("KeyId") != key_id
        or rotation_response.get("KeyRotationEnabled") is not True
        or rotation_response.get("RotationPeriodInDays") != 365
    ):
        raise PlanPermissionRepairError(
            "LEDGER_KMS_MISMATCH", "ledger KMS rotation controls differ"
        )
    key_policy_response = _checked_page(
        kms.get_key_policy(KeyId=key_arn, PolicyName="default"),
        "get_key_policy",
    )
    if (
        key_policy_response.get("PolicyName") not in (None, "default")
        or _json_object(
            key_policy_response.get("Policy"), "LEDGER_KMS_POLICY_MISMATCH"
        )
        != _expected_ledger_key_policy(key_arn)
    ):
        raise PlanPermissionRepairError(
            "LEDGER_KMS_POLICY_MISMATCH", "ledger KMS key policy differs"
        )
    aliases: list[Any] = []
    marker: str | None = None
    seen_alias_markers: set[str] = set()
    for _ in range(MAX_PROVIDER_PAGES):
        request: dict[str, Any] = {"KeyId": key_arn, "Limit": 100}
        if marker is not None:
            request["Marker"] = marker
        response = _checked_page(kms.list_aliases(**request), "list_aliases")
        page = response.get("Aliases")
        truncated = response.get("Truncated")
        if not isinstance(page, list) or type(truncated) is not bool:
            raise PlanPermissionRepairError(
                "LEDGER_KMS_ALIAS_MISMATCH",
                "ledger KMS alias inventory is malformed",
            )
        aliases.extend(page)
        next_marker = response.get("NextMarker")
        if not truncated:
            if next_marker is not None:
                raise PlanPermissionRepairError(
                    "LEDGER_KMS_ALIAS_MISMATCH",
                    "ledger KMS terminal alias page has a marker",
                )
            break
        if (
            not isinstance(next_marker, str)
            or not next_marker
            or next_marker in seen_alias_markers
        ):
            raise PlanPermissionRepairError(
                "LEDGER_KMS_ALIAS_MISMATCH",
                "ledger KMS alias pagination is malformed",
            )
        seen_alias_markers.add(next_marker)
        marker = next_marker
    else:
        raise PlanPermissionRepairError(
            "LEDGER_KMS_ALIAS_MISMATCH",
            "ledger KMS alias inventory exceeded the page budget",
        )
    expected_alias = (
        "alias/scanalyze/platform-authority/"
        "gug376-plan-policy-repair-ledger"
    )
    expected_alias_arn = (
        f"arn:aws:kms:{REGION}:{AUTHORITY_ACCOUNT_ID}:{expected_alias}"
    )
    if len(aliases) != 1 or not isinstance(aliases[0], Mapping) or (
        aliases[0].get("AliasName") != expected_alias
        or aliases[0].get("AliasArn") != expected_alias_arn
        or aliases[0].get("TargetKeyId") != key_id
    ):
        raise PlanPermissionRepairError(
            "LEDGER_KMS_ALIAS_MISMATCH", "ledger KMS alias differs"
        )
    tags: dict[str, str] = {}
    marker = None
    seen_tag_markers: set[str] = set()
    for _ in range(MAX_PROVIDER_PAGES):
        request = {"KeyId": key_arn, "Limit": 50}
        if marker is not None:
            request["Marker"] = marker
        response = _checked_page(
            kms.list_resource_tags(**request), "list_resource_tags"
        )
        page = response.get("Tags")
        truncated = response.get("Truncated")
        if not isinstance(page, list) or type(truncated) is not bool:
            raise PlanPermissionRepairError(
                "LEDGER_KMS_TAG_MISMATCH",
                "ledger KMS tag inventory is malformed",
            )
        for item in page:
            if (
                not isinstance(item, Mapping)
                or set(item) != {"TagKey", "TagValue"}
                or not isinstance(item.get("TagKey"), str)
                or not isinstance(item.get("TagValue"), str)
                or item["TagKey"] in tags
            ):
                raise PlanPermissionRepairError(
                    "LEDGER_KMS_TAG_MISMATCH",
                    "ledger KMS tags are malformed",
                )
            tags[str(item["TagKey"])] = str(item["TagValue"])
        next_marker = response.get("NextMarker")
        if not truncated:
            if next_marker is not None:
                raise PlanPermissionRepairError(
                    "LEDGER_KMS_TAG_MISMATCH",
                    "ledger KMS terminal tag page has a marker",
                )
            break
        if (
            not isinstance(next_marker, str)
            or not next_marker
            or next_marker in seen_tag_markers
        ):
            raise PlanPermissionRepairError(
                "LEDGER_KMS_TAG_MISMATCH",
                "ledger KMS tag pagination is malformed",
            )
        seen_tag_markers.add(next_marker)
        marker = next_marker
    else:
        raise PlanPermissionRepairError(
            "LEDGER_KMS_TAG_MISMATCH",
            "ledger KMS tag inventory exceeded the page budget",
        )
    if tags != {
        "managed_by": "cloudformation",
        "service": "scanalyze-platform-authority",
        "work_package": "GUG-376",
        "environment": "non-production",
        "production": "false",
    }:
        raise PlanPermissionRepairError(
            "LEDGER_KMS_TAG_MISMATCH", "ledger KMS tags differ"
        )


def _load_runtime_lock(
    *, repo_root: Path | None = None, supplied: Mapping[str, Any] | None = None
) -> Mapping[str, Any]:
    if supplied is not None:
        value = dict(supplied)
    else:
        root = repo_root or Path(__file__).resolve().parents[1]
        try:
            value = json.loads(
                (root / RUNTIME_LOCK_NAME).read_text(encoding="utf-8"),
                object_pairs_hook=_reject_duplicate_json_keys,
            )
        except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
            raise PlanPermissionRepairError(
                "RUNTIME_LOCK_UNAVAILABLE",
                "reviewed runtime lock is unavailable",
            ) from exc
    expected_fields = {
        "record_type",
        "schema_version",
        "source_commit",
        "source_bundle_digest",
        "expected_boto3_version",
        "expected_botocore_version",
    }
    if (
        set(value) != expected_fields
        or value.get("record_type") != RUNTIME_LOCK_TYPE
        or value.get("schema_version") != 1
        or _DIGEST.fullmatch(str(value.get("source_bundle_digest", "")))
        is None
    ):
        raise PlanPermissionRepairError(
            "RUNTIME_LOCK_INVALID", "reviewed runtime lock is malformed"
        )
    return value


def _static_seed(env: Mapping[str, str]) -> dict[str, Any]:
    required = (
        "SOURCE_COMMIT",
        "SOURCE_BUNDLE_DIGEST",
        "REPAIR_ID",
        "PRINCIPAL_ID",
        "IDENTITY_STORE_ID",
        "IDENTITY_CENTER_INSTANCE_ARN",
        "PLAN_PERMISSION_SET_ARN",
        "EXPECTED_PERMISSION_SET_DESCRIPTION",
        "REPAIR_INVOKER_PERMISSION_SET_ARN",
        "CURRENT_POLICY_DIGEST",
        "DESIRED_POLICY_DIGEST",
        "EXPECTED_PLAN_PERMISSION_SET_TAGS_JSON",
        "BOOTSTRAP_CHANGE_SET_NAME",
        "REPAIR_LEDGER_TABLE_NAME",
        "REPAIR_LEDGER_KMS_KEY_ARN",
        "EXPECTED_ARTIFACT_CODE_SHA256",
        "EXPECTED_CODE_SIGNING_CONFIG_ARN",
        "EXPECTED_SIGNING_PROFILE_VERSION_ARN",
        "REPAIR_NOT_BEFORE",
        "REPAIR_NOT_AFTER",
        "PLAN_SAML_PROVIDER_ARN",
        "IDENTITY_CENTER_KMS_MODE",
        "EXPECTED_BOTO3_VERSION",
        "EXPECTED_BOTOCORE_VERSION",
    )
    if any(not isinstance(env.get(key), str) or not env.get(key) for key in required):
        raise PlanPermissionRepairError(
            "IMMUTABLE_ENVIRONMENT_MISSING",
            "immutable runtime environment is incomplete",
        )
    try:
        tags = json.loads(
            env["EXPECTED_PLAN_PERMISSION_SET_TAGS_JSON"],
            object_pairs_hook=_reject_duplicate_json_keys,
        )
    except (json.JSONDecodeError, ValueError) as exc:
        raise PlanPermissionRepairError(
            "IMMUTABLE_ENVIRONMENT_MISMATCH",
            "immutable permission-set tags are malformed",
        ) from exc
    if not isinstance(tags, Mapping):
        raise PlanPermissionRepairError(
            "IMMUTABLE_ENVIRONMENT_MISMATCH",
            "immutable permission-set tags are malformed",
        )
    return {
        "source_commit": env["SOURCE_COMMIT"],
        "source_bundle_digest": env["SOURCE_BUNDLE_DIGEST"],
        "repair_id": env["REPAIR_ID"],
        "principal_id": env["PRINCIPAL_ID"],
        "identity_store_id": env["IDENTITY_STORE_ID"],
        "instance_arn": env["IDENTITY_CENTER_INSTANCE_ARN"],
        "permission_set_arn": env["PLAN_PERMISSION_SET_ARN"],
        "permission_set_description": env[
            "EXPECTED_PERMISSION_SET_DESCRIPTION"
        ],
        "permission_set_tags": dict(tags),
        "repair_invoker_permission_set_arn": env[
            "REPAIR_INVOKER_PERMISSION_SET_ARN"
        ],
        "current_policy_digest": env["CURRENT_POLICY_DIGEST"],
        "desired_policy_digest": env["DESIRED_POLICY_DIGEST"],
        "change_set_name": env["BOOTSTRAP_CHANGE_SET_NAME"],
        "ledger_table_name": env["REPAIR_LEDGER_TABLE_NAME"],
        "ledger_kms_key_arn": env["REPAIR_LEDGER_KMS_KEY_ARN"],
        "expected_artifact_code_sha256": env[
            "EXPECTED_ARTIFACT_CODE_SHA256"
        ],
        "expected_code_signing_config_arn": env[
            "EXPECTED_CODE_SIGNING_CONFIG_ARN"
        ],
        "expected_signing_profile_version_arn": env[
            "EXPECTED_SIGNING_PROFILE_VERSION_ARN"
        ],
        "not_before": env["REPAIR_NOT_BEFORE"],
        "not_after": env["REPAIR_NOT_AFTER"],
        "saml_provider_arn": env["PLAN_SAML_PROVIDER_ARN"],
        "identity_center_kms_mode": env["IDENTITY_CENTER_KMS_MODE"],
        "identity_center_kms_key_arn": (
            env.get("IDENTITY_CENTER_KMS_KEY_ARN") or None
        ),
        "expected_boto3_version": env["EXPECTED_BOTO3_VERSION"],
        "expected_botocore_version": env["EXPECTED_BOTOCORE_VERSION"],
    }


def _validate_static_seed(
    seed: Mapping[str, Any], *, repo_root: Path | None = None
) -> None:
    """Validate every operator-provided binding before any SDK client exists."""

    role_name = PLAN_ROLE_PREFIX + "0123456789abcdef"
    binding = RepairBinding(
        source_commit=str(seed["source_commit"]),
        repair_id=str(seed["repair_id"]),
        source_bundle_digest=str(seed["source_bundle_digest"]),
        instance_arn=str(seed["instance_arn"]),
        identity_store_id=str(seed["identity_store_id"]),
        permission_set_arn=str(seed["permission_set_arn"]),
        repair_invoker_permission_set_arn=str(
            seed["repair_invoker_permission_set_arn"]
        ),
        permission_set_description=str(seed["permission_set_description"]),
        permission_set_tags=tuple(
            sorted(dict(seed["permission_set_tags"]).items())
        ),
        principal_id=str(seed["principal_id"]),
        role_arn=(
            f"arn:aws:iam::{AUTHORITY_ACCOUNT_ID}:role/"
            f"aws-reserved/sso.amazonaws.com/{role_name}"
        ),
        role_name=role_name,
        saml_provider_arn=str(seed["saml_provider_arn"]),
        identity_center_kms_mode=str(seed["identity_center_kms_mode"]),
        identity_center_kms_key_arn=seed["identity_center_kms_key_arn"],
        invocation_authority_graph_digest="sha256:" + "0" * 64,
        change_set_name=str(seed["change_set_name"]),
        ledger_table_name=str(seed["ledger_table_name"]),
        ledger_kms_key_arn=str(seed["ledger_kms_key_arn"]),
        expected_artifact_code_sha256=str(
            seed["expected_artifact_code_sha256"]
        ),
        expected_code_signing_config_arn=str(
            seed["expected_code_signing_config_arn"]
        ),
        expected_signing_profile_version_arn=str(
            seed["expected_signing_profile_version_arn"]
        ),
        not_before=parse_timestamp(seed["not_before"], "not_before"),
        not_after=parse_timestamp(seed["not_after"], "not_after"),
        plan_function_version="1",
        repair_function_version="1",
        reconcile_function_version="1",
        expected_boto3_version=str(seed["expected_boto3_version"]),
        expected_botocore_version=str(seed["expected_botocore_version"]),
    )
    intent = build_private_intent(binding, repo_root=repo_root)
    validate_private_intent(intent, repo_root=repo_root)
    if (
        seed["current_policy_digest"]
        != intent["predecessor_policy_digest"]
        or seed["desired_policy_digest"] != intent["target_policy_digest"]
    ):
        raise PlanPermissionRepairError(
            "POLICY_BINDING_MISMATCH",
            "immutable policy digests differ from reviewed source",
        )


def _validate_local_execution_identity(
    identity: Mapping[str, Any], mode: str
) -> None:
    expected_prefix = (
        f"arn:aws:sts::{AUTHORITY_ACCOUNT_ID}:assumed-role/"
        f"{EXECUTION_ROLE_NAMES[mode]}/"
    )
    arn = identity.get("Arn")
    if (
        identity.get("Account") != AUTHORITY_ACCOUNT_ID
        or not isinstance(arn, str)
        or re.fullmatch(re.escape(expected_prefix) + r"[^/]+", arn) is None
    ):
        raise PlanPermissionRepairError(
            "LOCAL_IDENTITY_MISMATCH", "Lambda execution identity differs"
        )


def build_runtime(
    *,
    mode: str,
    env: Mapping[str, str],
    context: Any,
    boto3_module: Any,
    botocore_module: Any,
    config_type: Any,
    repo_root: Path | None = None,
    runtime_lock: Mapping[str, Any] | None = None,
    now: Callable[[], datetime] | None = None,
    sleep: Callable[[float], None] = time.sleep,
) -> PlanPermissionRepair:
    if mode not in FUNCTION_NAMES:
        raise PlanPermissionRepairError("INVALID_MODE", "mode is unsupported")
    validate_lambda_environment_budget(env, mode=mode)
    validate_immutable_configuration_digest(env)
    remaining = getattr(context, "get_remaining_time_in_millis", None)
    if not callable(remaining):
        raise PlanPermissionRepairError(
            "FUNCTION_CONTEXT_MISSING", "Lambda runtime context is incomplete"
        )
    seed = _static_seed(env)
    _validate_static_seed(seed, repo_root=repo_root)
    iam_bindings = PlanRepairIamBindings.from_seed(seed)
    lock = _load_runtime_lock(repo_root=repo_root, supplied=runtime_lock)
    exact_lock = {
        "source_commit": seed["source_commit"],
        "source_bundle_digest": seed["source_bundle_digest"],
        "expected_boto3_version": seed["expected_boto3_version"],
        "expected_botocore_version": seed["expected_botocore_version"],
    }
    if any(lock.get(key) != value for key, value in exact_lock.items()):
        raise PlanPermissionRepairError(
            "RUNTIME_LOCK_MISMATCH", "reviewed runtime lock differs"
        )
    if (
        getattr(boto3_module, "__version__", None)
        != seed["expected_boto3_version"]
        or getattr(botocore_module, "__version__", None)
        != seed["expected_botocore_version"]
    ):
        raise PlanPermissionRepairError(
            "SDK_VERSION_MISMATCH", "AWS SDK runtime version differs"
        )
    clock = now or (lambda: datetime.now(UTC))
    factory = BotoSessionFactory(
        boto3_module=boto3_module,
        config_type=config_type,
        remaining_time_ms=remaining,
    )
    local_sts = factory.local("sts")
    identity = _checked_page(
        local_sts.get_caller_identity(), "get_caller_identity"
    )
    _validate_local_execution_identity(identity, mode)
    lambda_client = factory.local("lambda")
    versions = _verify_lambda_control_plane(client=lambda_client, env=env)
    _verify_ledger_control_plane(
        dynamodb=factory.local("dynamodb"),
        kms=factory.local("kms"),
        table_name=str(seed["ledger_table_name"]),
        key_arn=str(seed["ledger_kms_key_arn"]),
    )
    role_arn = MUTATION_ROLE_ARN if mode == "repair" else READBACK_ROLE_ARN
    management, _, _ = factory.assumed_clients(
        role_arn=role_arn,
        repair_id=str(seed["repair_id"]),
        purpose=mode,
        services=("sso-admin", "identitystore", "iam"),
    )
    inventory, collector_digest = factory.inspector_adapter(
        repair_id=str(seed["repair_id"]), clock=clock
    )
    graph = InvocationGraphVerifier(
        adapter=inventory,
        collector_principal_digest=collector_digest,
        saml_provider_arn=str(seed["saml_provider_arn"]),
        clock=clock,
        repair_id=str(seed["repair_id"]),
    )
    authority_iam = factory.local("iam")
    provider_delegate = AwsIdentityCenterAdapter(
        sso_admin=management["sso-admin"],
        identitystore=management["identitystore"],
        authority_iam=authority_iam,
        graph_supplier=graph.snapshot,
        expected_description=str(seed["permission_set_description"]),
        expected_plan_tags=seed["permission_set_tags"],
        source_commit=str(seed["source_commit"]),
        remaining_time_ms=remaining,
    )
    provider = IamEffectiveAuthorityGuardedIdentityCenterPort(
        delegate=provider_delegate,
        verifier=AwsPlanRepairIamEffectiveAuthorityVerifier(
            authority_iam=authority_iam,
            management_iam=management["iam"],
            repo_root=repo_root,
        ),
        bindings=iam_bindings,
    )
    discovered = provider.discover(seed)
    binding = RepairBinding(
        source_commit=str(seed["source_commit"]),
        repair_id=str(seed["repair_id"]),
        source_bundle_digest=str(seed["source_bundle_digest"]),
        instance_arn=str(seed["instance_arn"]),
        identity_store_id=str(seed["identity_store_id"]),
        permission_set_arn=str(seed["permission_set_arn"]),
        repair_invoker_permission_set_arn=str(
            seed["repair_invoker_permission_set_arn"]
        ),
        permission_set_description=str(seed["permission_set_description"]),
        permission_set_tags=tuple(
            sorted(dict(seed["permission_set_tags"]).items())
        ),
        principal_id=str(seed["principal_id"]),
        role_arn=discovered.role.role_arn,
        role_name=discovered.role.role_name,
        saml_provider_arn=str(seed["saml_provider_arn"]),
        identity_center_kms_mode=str(seed["identity_center_kms_mode"]),
        identity_center_kms_key_arn=seed["identity_center_kms_key_arn"],
        invocation_authority_graph_digest=(
            discovered.invocation_authority_graph_digest
        ),
        change_set_name=str(seed["change_set_name"]),
        ledger_table_name=str(seed["ledger_table_name"]),
        ledger_kms_key_arn=str(seed["ledger_kms_key_arn"]),
        expected_artifact_code_sha256=str(
            seed["expected_artifact_code_sha256"]
        ),
        expected_code_signing_config_arn=str(
            seed["expected_code_signing_config_arn"]
        ),
        expected_signing_profile_version_arn=str(
            seed["expected_signing_profile_version_arn"]
        ),
        not_before=parse_timestamp(seed["not_before"], "not_before"),
        not_after=parse_timestamp(seed["not_after"], "not_after"),
        plan_function_version=versions["plan"],
        repair_function_version=versions["repair"],
        reconcile_function_version=versions["reconcile"],
        expected_boto3_version=str(seed["expected_boto3_version"]),
        expected_botocore_version=str(seed["expected_botocore_version"]),
    )
    intent = build_private_intent(binding, repo_root=repo_root)
    ledger = DynamoLedger(
        factory.local("dynamodb"), str(seed["ledger_table_name"])
    )
    return PlanPermissionRepair(
        intent=intent,
        provider=provider,
        ledger=ledger,
        now=clock,
        sleep=sleep,
    )


def _runtime_factory(
    mode: str, env: Mapping[str, str], context: Any
) -> PlanPermissionRepair:
    import boto3  # type: ignore[import-not-found]
    import botocore  # type: ignore[import-not-found]
    from botocore.config import Config  # type: ignore[import-not-found]

    return build_runtime(
        mode=mode,
        env=env,
        context=context,
        boto3_module=boto3,
        botocore_module=botocore,
        config_type=Config,
    )


install_runtime_factory(_runtime_factory)


def _capture_handler(
    mode: str, event: Any, context: Any
) -> tuple[dict[str, Any] | None, str | None]:
    try:
        from tooling import platform_authority_plan_permission_repair as core

        core.install_runtime_factory(_runtime_factory)
        handler = {
            "plan": core.plan_handler,
            "repair": core.repair_handler,
            "reconcile": core.reconcile_handler,
        }[mode]
        return handler(event, context), None
    except PlanPermissionRepairError as exc:
        code = (
            exc.code
            if _PUBLIC_ERROR_CODE.fullmatch(exc.code)
            else "CONTRACT_FAILURE"
        )
        return None, code
    except AuthorityInventoryError as exc:
        code = (
            exc.code
            if _PUBLIC_ERROR_CODE.fullmatch(exc.code)
            else "AUTHORITY_INVENTORY_DENIED"
        )
        return None, code
    except Exception:
        return None, "PROVIDER_FAILURE"


def _handler(mode: str, event: Any, context: Any) -> dict[str, Any]:
    result, error_code = _capture_handler(mode, event, context)
    if error_code is not None:
        raise PublicPlanRepairFailure(error_code)
    if result is None:
        raise PublicPlanRepairFailure("PROVIDER_FAILURE")
    return result


def plan_handler(event: Any, context: Any) -> dict[str, Any]:
    return _handler("plan", event, context)


def repair_handler(event: Any, context: Any) -> dict[str, Any]:
    return _handler("repair", event, context)


def reconcile_handler(event: Any, context: Any) -> dict[str, Any]:
    return _handler("reconcile", event, context)
