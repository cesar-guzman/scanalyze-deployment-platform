"""Read-only provider collector for GUG-221 Phase B broker topology.

The collector performs only AWS ``Get*``, ``List*`` and ``Describe*`` calls.
It validates the exact Identity Center application, immutable operator
assignment, IAM roles, qualified Lambda alias, DynamoDB one-shot ledger and
KMS signing key before emitting an *unsigned* canonical evidence payload.

Signing is intentionally a separate, explicitly authorized operation.  This
module never calls KMS ``Sign`` and never claims that an unsigned payload is
runtime evidence.  The broker accepts the final receipt only after
``kms:Verify`` over the exact canonical digest.
"""

from __future__ import annotations

import base64
import binascii
import json
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Mapping

from tooling.platform_authority_lambda_audit_repair_phase_b_pep import (
    AUTHORIZATION_CODE_GRANT,
    AUTHORITY_ACCOUNT_ID,
    BROKER_ROLE_NAME,
    BROKER_TOPOLOGY_EVIDENCE_KEYS,
    BROKER_TOPOLOGY_SIGNATURE_ALGORITHM,
    FUNCTION_ALIAS,
    FUNCTION_NAME,
    LEDGER_TABLE_NAME,
    MANAGEMENT_ACCOUNT_ID,
    PROOF_ROLE_NAME,
    REGION,
    REQUIRED_SCOPES,
    PhaseBIdentityBinding,
    PhaseBPepError,
    broker_topology_signature_digest,
    canonical_digest,
)


BROKER_POLICY_NAME = "Gug221PhaseBBrokerExecution"
PROOF_POLICY_NAME = "Gug221PhaseBZeroAuthorityProof"
MAX_PROVIDER_PAGES = 100
LEDGER_CONTROL_PLANE_MUTATION_ACTIONS = (
    "dynamodb:CreateBackup",
    "dynamodb:DeleteResourcePolicy",
    "dynamodb:DeleteTable",
    "dynamodb:DisableKinesisStreamingDestination",
    "dynamodb:EnableKinesisStreamingDestination",
    "dynamodb:ExportTableToPointInTime",
    "dynamodb:PutResourcePolicy",
    "dynamodb:RestoreTableToPointInTime",
    "dynamodb:TagResource",
    "dynamodb:UntagResource",
    "dynamodb:UpdateContinuousBackups",
    "dynamodb:UpdateContributorInsights",
    "dynamodb:UpdateKinesisStreamingDestination",
    "dynamodb:UpdateTable",
    "dynamodb:UpdateTableReplicaAutoScaling",
    "dynamodb:UpdateTimeToLive",
)

_BASE64_SIGNATURE = re.compile(r"^[A-Za-z0-9+/]+={0,2}$")


@dataclass(frozen=True, slots=True)
class PhaseBTopologyReadOnlyClients:
    """Exact read-only SDK clients required by the collector."""

    sso_admin: Any
    iam: Any
    lambda_client: Any
    dynamodb: Any
    kms: Any


def _fail(code: str) -> None:
    raise PhaseBPepError(code)


def _mapping(value: Any, code: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        _fail(code)
    return value


def _provider_call(
    client: Any,
    operation: str,
    *,
    code: str = "BROKER_TOPOLOGY_PROVIDER_READ_FAILED",
    **kwargs: Any,
) -> Mapping[str, Any]:
    method = getattr(client, operation, None)
    if not callable(method):
        _fail("BROKER_TOPOLOGY_PROVIDER_CLIENT_INVALID")
    try:
        response = method(**kwargs)
    except PhaseBPepError:
        raise
    except Exception:
        raise PhaseBPepError(code) from None
    return _mapping(response, "BROKER_TOPOLOGY_PROVIDER_RESPONSE_INVALID")


def _error_code(error: Exception) -> str | None:
    response = getattr(error, "response", None)
    if not isinstance(response, Mapping):
        return None
    detail = response.get("Error")
    if not isinstance(detail, Mapping):
        return None
    code = detail.get("Code")
    return code if isinstance(code, str) else None


def _require_absent(
    client: Any,
    operation: str,
    *,
    kwargs: Mapping[str, Any],
    absent_codes: frozenset[str] = frozenset({"ResourceNotFoundException"}),
) -> Mapping[str, Any]:
    method = getattr(client, operation, None)
    if not callable(method):
        _fail("BROKER_TOPOLOGY_PROVIDER_CLIENT_INVALID")
    try:
        method(**dict(kwargs))
    except Exception as exc:
        if _error_code(exc) not in absent_codes:
            raise PhaseBPepError(
                "BROKER_TOPOLOGY_PROVIDER_READ_FAILED"
            ) from None
    else:
        _fail("BROKER_TOPOLOGY_UNREVIEWED_SURFACE_PRESENT")
    return {"operation": operation, "request": dict(kwargs), "absent": True}


def _next_token_pages(
    client: Any,
    operation: str,
    result_key: str,
    *,
    request: Mapping[str, Any],
) -> list[Mapping[str, Any]]:
    method = getattr(client, operation, None)
    if not callable(method):
        _fail("BROKER_TOPOLOGY_PROVIDER_CLIENT_INVALID")
    token: str | None = None
    seen: set[str] = set()
    result: list[Mapping[str, Any]] = []
    for _ in range(MAX_PROVIDER_PAGES):
        kwargs = dict(request)
        if token is not None:
            kwargs["NextToken"] = token
        try:
            response = method(**kwargs)
        except Exception:
            raise PhaseBPepError(
                "BROKER_TOPOLOGY_PROVIDER_READ_FAILED"
            ) from None
        page = _mapping(
            response,
            "BROKER_TOPOLOGY_PROVIDER_RESPONSE_INVALID",
        )
        items = page.get(result_key)
        if not isinstance(items, list) or any(
            not isinstance(item, Mapping) for item in items
        ):
            _fail("BROKER_TOPOLOGY_PROVIDER_RESPONSE_INVALID")
        result.extend(items)
        next_token = page.get("NextToken")
        if next_token is None:
            return result
        if (
            not isinstance(next_token, str)
            or not next_token
            or next_token in seen
        ):
            _fail("BROKER_TOPOLOGY_PROVIDER_PAGINATION_INVALID")
        seen.add(next_token)
        token = next_token
    _fail("BROKER_TOPOLOGY_PROVIDER_PAGINATION_EXCEEDED")


def _marker_pages(
    client: Any,
    operation: str,
    result_key: str,
    *,
    request: Mapping[str, Any],
) -> list[Any]:
    method = getattr(client, operation, None)
    if not callable(method):
        _fail("BROKER_TOPOLOGY_PROVIDER_CLIENT_INVALID")
    marker: str | None = None
    seen: set[str] = set()
    result: list[Any] = []
    for _ in range(MAX_PROVIDER_PAGES):
        kwargs = dict(request)
        if marker is not None:
            kwargs["Marker"] = marker
        try:
            response = method(**kwargs)
        except Exception:
            raise PhaseBPepError(
                "BROKER_TOPOLOGY_PROVIDER_READ_FAILED"
            ) from None
        page = _mapping(
            response,
            "BROKER_TOPOLOGY_PROVIDER_RESPONSE_INVALID",
        )
        items = page.get(result_key)
        if not isinstance(items, list):
            _fail("BROKER_TOPOLOGY_PROVIDER_RESPONSE_INVALID")
        result.extend(items)
        truncated = page.get("IsTruncated", False)
        if truncated is False:
            if page.get("Marker") is not None:
                _fail("BROKER_TOPOLOGY_PROVIDER_PAGINATION_INVALID")
            return result
        next_marker = page.get("Marker")
        if (
            truncated is not True
            or not isinstance(next_marker, str)
            or not next_marker
            or next_marker in seen
        ):
            _fail("BROKER_TOPOLOGY_PROVIDER_PAGINATION_INVALID")
        seen.add(next_marker)
        marker = next_marker
    _fail("BROKER_TOPOLOGY_PROVIDER_PAGINATION_EXCEEDED")


def _kms_grant_pages(client: Any, *, key_arn: str) -> list[Mapping[str, Any]]:
    method = getattr(client, "list_grants", None)
    if not callable(method):
        _fail("BROKER_TOPOLOGY_PROVIDER_CLIENT_INVALID")
    marker: str | None = None
    seen: set[str] = set()
    result: list[Mapping[str, Any]] = []
    for _ in range(MAX_PROVIDER_PAGES):
        kwargs: dict[str, Any] = {"KeyId": key_arn, "Limit": 100}
        if marker is not None:
            kwargs["Marker"] = marker
        try:
            response = method(**kwargs)
        except Exception:
            raise PhaseBPepError(
                "BROKER_TOPOLOGY_PROVIDER_READ_FAILED"
            ) from None
        page = _mapping(
            response,
            "BROKER_TOPOLOGY_PROVIDER_RESPONSE_INVALID",
        )
        grants = page.get("Grants")
        if not isinstance(grants, list) or any(
            not isinstance(grant, Mapping) for grant in grants
        ):
            _fail("BROKER_TOPOLOGY_PROVIDER_RESPONSE_INVALID")
        result.extend(grants)
        truncated = page.get("Truncated", False)
        if truncated is False:
            if page.get("NextMarker") is not None:
                _fail("BROKER_TOPOLOGY_PROVIDER_PAGINATION_INVALID")
            return result
        next_marker = page.get("NextMarker")
        if (
            truncated is not True
            or not isinstance(next_marker, str)
            or not next_marker
            or next_marker in seen
        ):
            _fail("BROKER_TOPOLOGY_PROVIDER_PAGINATION_INVALID")
        seen.add(next_marker)
        marker = next_marker
    _fail("BROKER_TOPOLOGY_PROVIDER_PAGINATION_EXCEEDED")


def _strict_json_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if not isinstance(key, str) or key in result:
            _fail("BROKER_TOPOLOGY_POLICY_INVALID")
        result[key] = value
    return result


def _policy_document(value: Any) -> Mapping[str, Any]:
    if isinstance(value, Mapping):
        candidate: Any = dict(value)
    elif isinstance(value, str):
        try:
            candidate = json.loads(
                value,
                object_pairs_hook=_strict_json_pairs,
            )
        except PhaseBPepError:
            raise
        except (TypeError, ValueError, json.JSONDecodeError):
            raise PhaseBPepError("BROKER_TOPOLOGY_POLICY_INVALID") from None
    else:
        _fail("BROKER_TOPOLOGY_POLICY_INVALID")
    if not isinstance(candidate, Mapping):
        _fail("BROKER_TOPOLOGY_POLICY_INVALID")
    try:
        canonical = json.loads(
            json.dumps(
                candidate,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
            )
        )
    except (TypeError, ValueError):
        raise PhaseBPepError("BROKER_TOPOLOGY_POLICY_INVALID") from None
    return _mapping(canonical, "BROKER_TOPOLOGY_POLICY_INVALID")


def _raw_policy_digest(value: Any) -> str:
    return canonical_digest(_policy_document(value)).removeprefix("sha256:")


def _exact_set(value: Any, expected: set[str]) -> bool:
    if isinstance(value, str):
        observed = {value}
    elif isinstance(value, list) and all(
        isinstance(item, str) for item in value
    ):
        observed = set(value)
    else:
        return False
    return observed == expected and len(observed) == len(
        value if isinstance(value, list) else [value]
    )


def _collect_application(
    *,
    binding: PhaseBIdentityBinding,
    client: Any,
) -> Mapping[str, Any]:
    application = _provider_call(
        client,
        "describe_application",
        ApplicationArn=binding.identity_center_application_arn,
    )
    if (
        application.get("ApplicationArn")
        != binding.identity_center_application_arn
        or application.get("InstanceArn")
        != binding.identity_center_instance_arn
        or application.get("ApplicationAccount") != MANAGEMENT_ACCOUNT_ID
        or application.get("Status") != "ENABLED"
    ):
        _fail("BROKER_TOPOLOGY_APPLICATION_MISMATCH")

    assignment_config = _provider_call(
        client,
        "get_application_assignment_configuration",
        ApplicationArn=binding.identity_center_application_arn,
    )
    if assignment_config != {"AssignmentRequired": True}:
        _fail("BROKER_TOPOLOGY_APPLICATION_ASSIGNMENT_MISMATCH")
    assignments = _next_token_pages(
        client,
        "list_application_assignments",
        "ApplicationAssignments",
        request={
            "ApplicationArn": binding.identity_center_application_arn,
            "MaxResults": 100,
        },
    )
    if assignments != [
        {
            "ApplicationArn": binding.identity_center_application_arn,
            "PrincipalId": binding.operator_user_id,
            "PrincipalType": "USER",
        }
    ]:
        _fail("BROKER_TOPOLOGY_APPLICATION_ASSIGNMENT_MISMATCH")

    authentication_methods = _next_token_pages(
        client,
        "list_application_authentication_methods",
        "AuthenticationMethods",
        request={"ApplicationArn": binding.identity_center_application_arn},
    )
    if (
        len(authentication_methods) != 1
        or authentication_methods[0].get("AuthenticationMethodType")
        != "IAM"
    ):
        _fail("BROKER_TOPOLOGY_APPLICATION_AUTHENTICATION_MISMATCH")
    authentication = _provider_call(
        client,
        "get_application_authentication_method",
        ApplicationArn=binding.identity_center_application_arn,
        AuthenticationMethodType="IAM",
    )
    method = authentication.get("AuthenticationMethod")
    iam_method = method.get("Iam") if isinstance(method, Mapping) else None
    actor_policy = (
        iam_method.get("ActorPolicy")
        if isinstance(iam_method, Mapping)
        else None
    )
    if _raw_policy_digest(actor_policy) != (
        binding.application_actor_policy_sha256
    ):
        _fail("BROKER_TOPOLOGY_APPLICATION_POLICY_MISMATCH")

    grants = _next_token_pages(
        client,
        "list_application_grants",
        "Grants",
        request={"ApplicationArn": binding.identity_center_application_arn},
    )
    if (
        len(grants) != 1
        or grants[0].get("GrantType") != AUTHORIZATION_CODE_GRANT
    ):
        _fail("BROKER_TOPOLOGY_APPLICATION_GRANT_MISMATCH")
    grant = _provider_call(
        client,
        "get_application_grant",
        ApplicationArn=binding.identity_center_application_arn,
        GrantType=AUTHORIZATION_CODE_GRANT,
    )
    grant_value = grant.get("Grant")
    authorization_code = (
        grant_value.get("AuthorizationCode")
        if isinstance(grant_value, Mapping)
        else None
    )
    if (
        not isinstance(authorization_code, Mapping)
        or authorization_code.get("RedirectUris") != [binding.redirect_uri]
        or set(authorization_code) != {"RedirectUris"}
    ):
        _fail("BROKER_TOPOLOGY_APPLICATION_GRANT_MISMATCH")

    scopes = _next_token_pages(
        client,
        "list_application_access_scopes",
        "Scopes",
        request={
            "ApplicationArn": binding.identity_center_application_arn,
            "MaxResults": 100,
        },
    )
    scope_names = [scope.get("Scope") for scope in scopes]
    if sorted(scope_names) != sorted(REQUIRED_SCOPES):
        _fail("BROKER_TOPOLOGY_APPLICATION_SCOPE_MISMATCH")
    scope_projection: list[Mapping[str, Any]] = []
    for scope_name in sorted(REQUIRED_SCOPES):
        scope = _provider_call(
            client,
            "get_application_access_scope",
            ApplicationArn=binding.identity_center_application_arn,
            Scope=scope_name,
        )
        targets = scope.get("AuthorizedTargets")
        if (
            scope.get("Scope") != scope_name
            or not isinstance(targets, list)
            or any(not isinstance(target, str) for target in targets)
        ):
            _fail("BROKER_TOPOLOGY_APPLICATION_SCOPE_MISMATCH")
        expected_targets = (
            [binding.proof_role_arn]
            if scope_name == "sts:identity_context"
            else []
        )
        if targets != expected_targets:
            _fail("BROKER_TOPOLOGY_APPLICATION_SCOPE_MISMATCH")
        scope_projection.append(
            {"scope": scope_name, "authorized_targets": targets}
        )

    return {
        "application_arn": binding.identity_center_application_arn,
        "instance_arn": binding.identity_center_instance_arn,
        "status": "ENABLED",
        "assignment_required": True,
        "assignment": {
            "principal_type": "USER",
            "principal_id_digest": canonical_digest(
                {
                    "identity_store_user_id": (
                        binding.operator_user_id.lower()
                    )
                }
            ),
        },
        "actor_policy_sha256": binding.application_actor_policy_sha256,
        "grant": {
            "grant_type": AUTHORIZATION_CODE_GRANT,
            "redirect_uri": binding.redirect_uri,
        },
        "scopes": scope_projection,
    }


def _collect_role(
    *,
    client: Any,
    role_arn: str,
    expected_policy_sha256: str,
    expected_policy_name: str | None,
    expected_trust: Mapping[str, Any] | None,
    sso_role: bool = False,
) -> Mapping[str, Any]:
    role_name = role_arn.rsplit("/", 1)[-1]
    response = _provider_call(client, "get_role", RoleName=role_name)
    role = response.get("Role")
    if (
        not isinstance(role, Mapping)
        or role.get("Arn") != role_arn
        or role.get("RoleName") != role_name
        or role.get("MaxSessionDuration") != 3600
        or role.get("PermissionsBoundary") is not None
    ):
        _fail("BROKER_TOPOLOGY_ROLE_MISMATCH")
    trust = _policy_document(role.get("AssumeRolePolicyDocument"))
    if expected_trust is not None:
        if trust != _policy_document(expected_trust):
            _fail("BROKER_TOPOLOGY_ROLE_TRUST_MISMATCH")
    elif sso_role:
        if set(trust) != {"Version", "Statement"} or trust.get(
            "Version"
        ) != "2012-10-17":
            _fail("BROKER_TOPOLOGY_ROLE_TRUST_MISMATCH")
        statements = trust.get("Statement")
        if not isinstance(statements, list) or len(statements) != 1:
            _fail("BROKER_TOPOLOGY_ROLE_TRUST_MISMATCH")
        statement = statements[0]
        principal = (
            statement.get("Principal")
            if isinstance(statement, Mapping)
            else None
        )
        provider = (
            principal.get("Federated")
            if isinstance(principal, Mapping)
            else None
        )
        condition = (
            statement.get("Condition")
            if isinstance(statement, Mapping)
            else None
        )
        string_equals = (
            condition.get("StringEquals")
            if isinstance(condition, Mapping)
            else None
        )
        if (
            not isinstance(statement, Mapping)
            or set(statement)
            != {"Effect", "Principal", "Action", "Condition"}
            or statement.get("Effect") != "Allow"
            or not _exact_set(
                statement.get("Action"),
                {"sts:AssumeRoleWithSAML", "sts:TagSession"},
            )
            or not isinstance(provider, str)
            or set(principal) != {"Federated"}
            or re.fullmatch(
                rf"arn:aws:iam::{AUTHORITY_ACCOUNT_ID}:saml-provider/"
                r"AWSSSO_[A-Za-z0-9_+=,.@-]+_DO_NOT_DELETE",
                provider,
            )
            is None
            or not isinstance(condition, Mapping)
            or set(condition) != {"StringEquals"}
            or string_equals
            != {"SAML:aud": "https://signin.aws.amazon.com/saml"}
        ):
            _fail("BROKER_TOPOLOGY_ROLE_TRUST_MISMATCH")

    policy_names = _marker_pages(
        client,
        "list_role_policies",
        "PolicyNames",
        request={"RoleName": role_name, "MaxItems": 100},
    )
    if (
        len(policy_names) != 1
        or not isinstance(policy_names[0], str)
        or (
            expected_policy_name is not None
            and policy_names[0] != expected_policy_name
        )
    ):
        _fail("BROKER_TOPOLOGY_ROLE_POLICY_MISMATCH")
    inline = _provider_call(
        client,
        "get_role_policy",
        RoleName=role_name,
        PolicyName=policy_names[0],
    )
    if (
        inline.get("RoleName") not in (None, role_name)
        or inline.get("PolicyName") not in (None, policy_names[0])
        or _raw_policy_digest(inline.get("PolicyDocument"))
        != expected_policy_sha256
    ):
        _fail("BROKER_TOPOLOGY_ROLE_POLICY_MISMATCH")
    attached = _marker_pages(
        client,
        "list_attached_role_policies",
        "AttachedPolicies",
        request={"RoleName": role_name, "MaxItems": 100},
    )
    if attached:
        _fail("BROKER_TOPOLOGY_ROLE_POLICY_MISMATCH")
    tags = _marker_pages(
        client,
        "list_role_tags",
        "Tags",
        request={"RoleName": role_name, "MaxItems": 100},
    )
    if any(
        not isinstance(tag, Mapping)
        or not isinstance(tag.get("Key"), str)
        or not isinstance(tag.get("Value"), str)
        for tag in tags
    ):
        _fail("BROKER_TOPOLOGY_ROLE_MISMATCH")
    return {
        "arn": role_arn,
        "role_name": role_name,
        "trust_sha256": canonical_digest(trust),
        "inline_policy_name": policy_names[0],
        "inline_policy_sha256": expected_policy_sha256,
        "attached_policies": [],
        "permissions_boundary": None,
        "tags": sorted(
            (
                {"key": str(tag["Key"]), "value": str(tag["Value"])}
                for tag in tags
            ),
            key=lambda item: (item["key"], item["value"]),
        ),
    }


def _expected_broker_trust(binding: PhaseBIdentityBinding) -> Mapping[str, Any]:
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AssumeOnlyFromLambda",
                "Effect": "Allow",
                "Principal": {"Service": "lambda.amazonaws.com"},
                "Action": "sts:AssumeRole",
                "Condition": {
                    "StringEquals": {
                        "aws:SourceAccount": binding.authority_account_id
                    },
                    "ArnLike": {
                        "aws:SourceArn": (
                            f"arn:aws:lambda:{binding.region}:"
                            f"{binding.authority_account_id}:function:"
                            f"{FUNCTION_NAME}"
                        )
                    },
                },
            }
        ],
    }


def _expected_proof_trust(binding: PhaseBIdentityBinding) -> Mapping[str, Any]:
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AssumeOnlyFromExactBroker",
                "Effect": "Allow",
                "Principal": {
                    "AWS": binding.broker_execution_role_arn
                },
                "Action": "sts:AssumeRole",
            },
            {
                "Sid": "SetOnlyExactOperatorIdentityContext",
                "Effect": "Allow",
                "Principal": {
                    "AWS": binding.broker_execution_role_arn
                },
                "Action": "sts:SetContext",
                "Condition": {
                    "ForAllValues:ArnEquals": {
                        "sts:RequestContextProviders": [
                            (
                                "arn:aws:iam::aws:contextProvider/"
                                "IdentityCenter"
                            )
                        ]
                    },
                    "ForAnyValue:ArnEquals": {
                        "sts:RequestContextProviders": [
                            (
                                "arn:aws:iam::aws:contextProvider/"
                                "IdentityCenter"
                            )
                        ]
                    },
                    "StringEquals": {
                        "sts:RequestContext/identitystore:UserId": (
                            binding.operator_user_id
                        )
                    },
                    "ArnEquals": {
                        "aws:PrincipalArn": (
                            binding.broker_execution_role_arn
                        ),
                        (
                            "sts:RequestContext/identitystore:"
                            "IdentityStoreArn"
                        ): binding.identity_store_arn,
                        (
                            "sts:RequestContext/identitycenter:"
                            "InstanceArn"
                        ): binding.identity_center_instance_arn,
                        (
                            "sts:RequestContext/identitycenter:"
                            "ApplicationArn"
                        ): binding.identity_center_application_arn,
                    },
                    "Null": {
                        "sts:RequestContextProviders": "false",
                        (
                            "sts:RequestContext/identitystore:"
                            "UserId"
                        ): "false",
                        (
                            "sts:RequestContext/identitystore:"
                            "IdentityStoreArn"
                        ): "false",
                        (
                            "sts:RequestContext/identitycenter:"
                            "InstanceArn"
                        ): "false",
                        (
                            "sts:RequestContext/identitycenter:"
                            "ApplicationArn"
                        ): "false",
                    },
                },
            },
        ],
    }


def _expected_ledger_resource_policy(
    binding: PhaseBIdentityBinding,
) -> Mapping[str, Any]:
    resource = binding.ledger_table_arn
    key_condition = {"dynamodb:LeadingKeys": [binding.execution_id]}
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "DenyInsecureLedgerTransport",
                "Effect": "Deny",
                "Principal": "*",
                "Action": "dynamodb:*",
                "Resource": resource,
                "Condition": {
                    "Bool": {"aws:SecureTransport": "false"}
                },
            },
            {
                "Sid": "DenyLedgerMutationsOutsideExactBroker",
                "Effect": "Deny",
                "Principal": "*",
                "Action": [
                    "dynamodb:PutItem",
                    "dynamodb:UpdateItem",
                ],
                "Resource": resource,
                "Condition": {
                    "ArnNotEquals": {
                        "aws:PrincipalArn": (
                            binding.broker_execution_role_arn
                        )
                    }
                },
            },
            {
                "Sid": "DenyAnyForeignLedgerKey",
                "Effect": "Deny",
                "Principal": "*",
                "Action": [
                    "dynamodb:GetItem",
                    "dynamodb:PutItem",
                    "dynamodb:UpdateItem",
                ],
                "Resource": resource,
                "Condition": {
                    "ForAnyValue:StringNotEquals": key_condition
                },
            },
            {
                "Sid": "DenyUnsupportedLedgerOperations",
                "Effect": "Deny",
                "Principal": "*",
                "Action": [
                    "dynamodb:BatchGetItem",
                    "dynamodb:BatchWriteItem",
                    "dynamodb:ConditionCheckItem",
                    "dynamodb:DeleteItem",
                    "dynamodb:PartiQLDelete",
                    "dynamodb:PartiQLInsert",
                    "dynamodb:PartiQLSelect",
                    "dynamodb:PartiQLUpdate",
                    "dynamodb:Query",
                    "dynamodb:Scan",
                ],
                "Resource": resource,
            },
            {
                "Sid": "DenyTransactionalLedgerItemOperations",
                "Effect": "Deny",
                "Principal": "*",
                "Action": [
                    "dynamodb:ConditionCheckItem",
                    "dynamodb:DeleteItem",
                    "dynamodb:GetItem",
                    "dynamodb:PutItem",
                    "dynamodb:UpdateItem",
                ],
                "Resource": resource,
                "Condition": {
                    "ForAnyValue:StringEquals": {
                        "dynamodb:EnclosingOperation": [
                            "TransactGetItems",
                            "TransactWriteItems",
                        ]
                    }
                },
            },
            {
                "Sid": "DenyLedgerControlPlaneMutation",
                "Effect": "Deny",
                "Principal": "*",
                "Action": list(LEDGER_CONTROL_PLANE_MUTATION_ACTIONS),
                "Resource": resource,
            },
            {
                "Sid": "AllowOnlyExactBrokerLedgerItem",
                "Effect": "Allow",
                "Principal": {
                    "AWS": binding.broker_execution_role_arn
                },
                "Action": [
                    "dynamodb:GetItem",
                    "dynamodb:PutItem",
                    "dynamodb:UpdateItem",
                ],
                "Resource": resource,
                "Condition": {
                    "ForAllValues:StringEquals": key_condition,
                    "Null": {
                        "dynamodb:EnclosingOperation": "true",
                        "dynamodb:LeadingKeys": "false",
                    },
                },
            },
        ],
    }


def _collect_roles(
    *,
    binding: PhaseBIdentityBinding,
    client: Any,
) -> Mapping[str, Any]:
    return {
        "invoker": _collect_role(
            client=client,
            role_arn=binding.invoker_role_arn,
            expected_policy_sha256=binding.invoker_policy_sha256,
            expected_policy_name=None,
            expected_trust=None,
            sso_role=True,
        ),
        "broker": _collect_role(
            client=client,
            role_arn=binding.broker_execution_role_arn,
            expected_policy_sha256=binding.broker_policy_sha256,
            expected_policy_name=BROKER_POLICY_NAME,
            expected_trust=_expected_broker_trust(binding),
        ),
        "proof": _collect_role(
            client=client,
            role_arn=binding.proof_role_arn,
            expected_policy_sha256=binding.proof_policy_sha256,
            expected_policy_name=PROOF_POLICY_NAME,
            expected_trust=_expected_proof_trust(binding),
        ),
    }


def _collect_lambda(
    *,
    binding: PhaseBIdentityBinding,
    client: Any,
) -> Mapping[str, Any]:
    alias = _provider_call(
        client,
        "get_alias",
        FunctionName=FUNCTION_NAME,
        Name=FUNCTION_ALIAS,
    )
    version = alias.get("FunctionVersion")
    if (
        alias.get("AliasArn") != binding.broker_alias_arn
        or alias.get("Name") != FUNCTION_ALIAS
        or not isinstance(version, str)
        or re.fullmatch(r"[1-9][0-9]*", version) is None
        or alias.get("RoutingConfig") not in (None, {})
    ):
        _fail("BROKER_TOPOLOGY_LAMBDA_ALIAS_MISMATCH")
    version_arn = (
        f"arn:aws:lambda:{binding.region}:{binding.authority_account_id}:"
        f"function:{FUNCTION_NAME}:{version}"
    )
    function = _provider_call(
        client,
        "get_function_configuration",
        FunctionName=FUNCTION_NAME,
        Qualifier=version,
    )
    expected_configuration = {
        "FunctionName": FUNCTION_NAME,
        "FunctionArn": version_arn,
        "Runtime": "python3.12",
        "Role": binding.broker_execution_role_arn,
        "Handler": (
            "tooling.platform_authority_lambda_audit_repair_"
            "phase_b_runtime.handler"
        ),
        "CodeSha256": binding.broker_artifact_code_sha256,
        "Version": version,
        "State": "Active",
        "LastUpdateStatus": "Successful",
        "PackageType": "Zip",
        "Architectures": ["x86_64"],
        "MemorySize": 256,
        "Timeout": 60,
    }
    if any(
        function.get(key) != expected
        for key, expected in expected_configuration.items()
    ):
        _fail("BROKER_TOPOLOGY_LAMBDA_CONFIGURATION_MISMATCH")
    environment = function.get("Environment")
    expected_environment = dict(binding.broker_environment_variables)
    if (
        not isinstance(environment, Mapping)
        or set(environment) != {"Variables"}
        or not isinstance(environment.get("Variables"), Mapping)
    ):
        _fail("BROKER_TOPOLOGY_LAMBDA_ENVIRONMENT_MISMATCH")
    observed_environment = environment["Variables"]
    if (
        set(observed_environment) != set(expected_environment)
        or any(
            not isinstance(key, str) or not isinstance(value, str)
            for key, value in observed_environment.items()
        )
        or dict(observed_environment) != expected_environment
    ):
        _fail("BROKER_TOPOLOGY_LAMBDA_ENVIRONMENT_MISMATCH")
    signing = _provider_call(
        client,
        "get_function_code_signing_config",
        FunctionName=FUNCTION_NAME,
    )
    if (
        signing.get("FunctionName") != FUNCTION_NAME
        or signing.get("CodeSigningConfigArn")
        != binding.broker_code_signing_config_arn
    ):
        _fail("BROKER_TOPOLOGY_LAMBDA_CONFIGURATION_MISMATCH")
    concurrency = _provider_call(
        client,
        "get_function_concurrency",
        FunctionName=FUNCTION_NAME,
    )
    if concurrency != {"ReservedConcurrentExecutions": 1}:
        _fail("BROKER_TOPOLOGY_LAMBDA_CONFIGURATION_MISMATCH")
    event_invoke_config = _provider_call(
        client,
        "get_function_event_invoke_config",
        FunctionName=FUNCTION_NAME,
        Qualifier=FUNCTION_ALIAS,
    )
    expected_event_invoke_config = {
        "FunctionArn": binding.broker_alias_arn,
        "MaximumRetryAttempts": 0,
        "MaximumEventAgeInSeconds": 60,
        "DestinationConfig": {},
    }
    response_metadata = event_invoke_config.get("ResponseMetadata")
    if any(
        event_invoke_config.get(key) != expected
        for key, expected in expected_event_invoke_config.items()
    ) or not set(event_invoke_config).issubset(
        set(expected_event_invoke_config)
        | {"LastModified", "ResponseMetadata"}
    ) or (
        response_metadata is not None
        and (
            not isinstance(response_metadata, Mapping)
            or response_metadata.get("HTTPStatusCode") != 200
        )
    ):
        _fail("BROKER_TOPOLOGY_LAMBDA_CONFIGURATION_MISMATCH")

    policy_response = _provider_call(
        client,
        "get_policy",
        FunctionName=FUNCTION_NAME,
        Qualifier=FUNCTION_ALIAS,
    )
    policy = _policy_document(policy_response.get("Policy"))
    statements = policy.get("Statement")
    if (
        policy.get("Version") != "2012-10-17"
        or not set(policy).issubset({"Version", "Id", "Statement"})
        or not isinstance(statements, list)
        or len(statements) != 1
    ):
        _fail("BROKER_TOPOLOGY_LAMBDA_POLICY_MISMATCH")
    statement = statements[0]
    principal = (
        statement.get("Principal")
        if isinstance(statement, Mapping)
        else None
    )
    if (
        not isinstance(statement, Mapping)
        or not set(statement).issubset(
            {"Sid", "Effect", "Principal", "Action", "Resource"}
        )
        or statement.get("Effect") != "Allow"
        or not _exact_set(
            statement.get("Action"), {"lambda:InvokeFunction"}
        )
        or principal != {"AWS": binding.invoker_role_arn}
        or statement.get("Resource") != binding.broker_alias_arn
        or statement.get("Condition") not in (None, {})
    ):
        _fail("BROKER_TOPOLOGY_LAMBDA_POLICY_MISMATCH")

    absent_surfaces = [
        _require_absent(
            client,
            "get_policy",
            kwargs={"FunctionName": FUNCTION_NAME},
        ),
        _require_absent(
            client,
            "get_policy",
            kwargs={
                "FunctionName": FUNCTION_NAME,
                "Qualifier": version,
            },
        ),
        _require_absent(
            client,
            "get_function_url_config",
            kwargs={"FunctionName": FUNCTION_NAME},
        ),
        _require_absent(
            client,
            "get_function_url_config",
            kwargs={
                "FunctionName": FUNCTION_NAME,
                "Qualifier": FUNCTION_ALIAS,
            },
        ),
        _require_absent(
            client,
            "get_function_event_invoke_config",
            kwargs={"FunctionName": FUNCTION_NAME},
        ),
        _require_absent(
            client,
            "get_function_event_invoke_config",
            kwargs={
                "FunctionName": FUNCTION_NAME,
                "Qualifier": version,
            },
        ),
    ]
    event_source_requests = (
        {"FunctionName": FUNCTION_NAME, "MaxItems": 100},
        {
            "FunctionName": binding.broker_alias_arn,
            "MaxItems": 100,
        },
    )
    for request in event_source_requests:
        event_sources = _next_token_pages(
            client,
            "list_event_source_mappings",
            "EventSourceMappings",
            request=request,
        )
        if event_sources:
            _fail("BROKER_TOPOLOGY_UNREVIEWED_SURFACE_PRESENT")
    return {
        "alias_arn": binding.broker_alias_arn,
        "version_arn": version_arn,
        "version": version,
        "configuration": expected_configuration,
        "environment_variables_sha256": (
            binding.broker_environment_variables_sha256
        ),
        "code_signing_config_arn": binding.broker_code_signing_config_arn,
        "reserved_concurrent_executions": 1,
        "event_invoke_config": expected_event_invoke_config,
        "resource_policy_sha256": canonical_digest(policy),
        "absent_surfaces": absent_surfaces,
        "event_source_mappings": [
            {"function_target": request["FunctionName"], "mappings": []}
            for request in event_source_requests
        ],
    }


def _collect_ledger(
    *,
    binding: PhaseBIdentityBinding,
    client: Any,
) -> Mapping[str, Any]:
    response = _provider_call(
        client,
        "describe_table",
        TableName=LEDGER_TABLE_NAME,
    )
    table = response.get("Table")
    if not isinstance(table, Mapping):
        _fail("BROKER_TOPOLOGY_LEDGER_MISMATCH")
    expected_fields = {
        "TableName": LEDGER_TABLE_NAME,
        "TableArn": binding.ledger_table_arn,
        "TableStatus": "ACTIVE",
        "BillingModeSummary": {"BillingMode": "PAY_PER_REQUEST"},
        "DeletionProtectionEnabled": True,
        "KeySchema": [
            {"AttributeName": "execution_id", "KeyType": "HASH"}
        ],
        "AttributeDefinitions": [
            {"AttributeName": "execution_id", "AttributeType": "S"}
        ],
    }
    if any(table.get(key) != value for key, value in expected_fields.items()):
        _fail("BROKER_TOPOLOGY_LEDGER_MISMATCH")
    sse = table.get("SSEDescription")
    if (
        not isinstance(sse, Mapping)
        or sse.get("Status") != "ENABLED"
        or sse.get("SSEType") != "KMS"
    ):
        _fail("BROKER_TOPOLOGY_LEDGER_MISMATCH")
    backups = _provider_call(
        client,
        "describe_continuous_backups",
        TableName=LEDGER_TABLE_NAME,
    )
    description = backups.get("ContinuousBackupsDescription")
    pitr = (
        description.get("PointInTimeRecoveryDescription")
        if isinstance(description, Mapping)
        else None
    )
    if (
        not isinstance(description, Mapping)
        or description.get("ContinuousBackupsStatus") != "ENABLED"
        or not isinstance(pitr, Mapping)
        or pitr.get("PointInTimeRecoveryStatus") != "ENABLED"
    ):
        _fail("BROKER_TOPOLOGY_LEDGER_MISMATCH")
    time_to_live_response = _provider_call(
        client,
        "describe_time_to_live",
        TableName=LEDGER_TABLE_NAME,
    )
    time_to_live = time_to_live_response.get("TimeToLiveDescription")
    if (
        not isinstance(time_to_live, Mapping)
        or set(time_to_live) != {"TimeToLiveStatus"}
        or time_to_live.get("TimeToLiveStatus") != "DISABLED"
    ):
        _fail("BROKER_TOPOLOGY_LEDGER_MISMATCH")
    resource_policy_response = _provider_call(
        client,
        "get_resource_policy",
        ResourceArn=binding.ledger_table_arn,
    )
    policy = _policy_document(resource_policy_response.get("Policy"))
    expected_policy = _expected_ledger_resource_policy(binding)
    if policy != expected_policy:
        _fail("BROKER_TOPOLOGY_LEDGER_POLICY_MISMATCH")
    return {
        "table_arn": binding.ledger_table_arn,
        "billing_mode": "PAY_PER_REQUEST",
        "deletion_protection_enabled": True,
        "point_in_time_recovery": "ENABLED",
        "time_to_live": {
            "status": "DISABLED",
            "attribute_name": None,
        },
        "sse": {
            "status": "ENABLED",
            "type": "KMS",
            "key_arn": sse.get("KMSMasterKeyArn"),
        },
        "resource_policy_sha256": canonical_digest(policy),
    }


def _collect_signing_key(
    *,
    binding: PhaseBIdentityBinding,
    client: Any,
) -> Mapping[str, Any]:
    response = _provider_call(
        client,
        "describe_key",
        KeyId=binding.broker_topology_signing_key_arn,
    )
    metadata = response.get("KeyMetadata")
    if (
        not isinstance(metadata, Mapping)
        or metadata.get("Arn") != binding.broker_topology_signing_key_arn
        or metadata.get("AWSAccountId") != binding.authority_account_id
        or metadata.get("Enabled") is not True
        or metadata.get("KeyState") != "Enabled"
        or metadata.get("KeyUsage") != "SIGN_VERIFY"
        or metadata.get("KeyManager") != "CUSTOMER"
        or metadata.get("Origin") != "AWS_KMS"
        or metadata.get("MultiRegion") not in (None, False)
        or metadata.get("DeletionDate") is not None
        or metadata.get("KeySpec", metadata.get("CustomerMasterKeySpec"))
        != "ECC_NIST_P256"
        or metadata.get("SigningAlgorithms")
        != [BROKER_TOPOLOGY_SIGNATURE_ALGORITHM]
    ):
        _fail("BROKER_TOPOLOGY_SIGNING_KEY_MISMATCH")
    policy_response = _provider_call(
        client,
        "get_key_policy",
        KeyId=binding.broker_topology_signing_key_arn,
        PolicyName="default",
    )
    policy = _policy_document(policy_response.get("Policy"))
    statements = policy.get("Statement")
    if (
        policy.get("Version") != "2012-10-17"
        or not isinstance(statements, list)
        or not statements
    ):
        _fail("BROKER_TOPOLOGY_SIGNING_KEY_POLICY_MISMATCH")
    forbidden_signers = {
        "*",
        binding.invoker_role_arn,
        binding.broker_execution_role_arn,
        binding.proof_role_arn,
    }
    for statement in statements:
        if not isinstance(statement, Mapping) or statement.get(
            "Effect"
        ) != "Allow":
            continue
        actions = statement.get("Action")
        if isinstance(actions, str):
            action_set = {actions}
        elif isinstance(actions, list) and all(
            isinstance(action, str) for action in actions
        ):
            action_set = set(actions)
        else:
            _fail("BROKER_TOPOLOGY_SIGNING_KEY_POLICY_MISMATCH")
        if not action_set.intersection({"*", "kms:*", "kms:Sign"}):
            continue
        principal = statement.get("Principal")
        if principal == "*":
            principals = {"*"}
        elif isinstance(principal, Mapping):
            aws_principal = principal.get("AWS")
            if isinstance(aws_principal, str):
                principals = {aws_principal}
            elif isinstance(aws_principal, list) and all(
                isinstance(item, str) for item in aws_principal
            ):
                principals = set(aws_principal)
            else:
                _fail("BROKER_TOPOLOGY_SIGNING_KEY_POLICY_MISMATCH")
        else:
            _fail("BROKER_TOPOLOGY_SIGNING_KEY_POLICY_MISMATCH")
        if principals.intersection(forbidden_signers):
            _fail("BROKER_TOPOLOGY_SIGNER_SEPARATION_MISMATCH")
    grants = _kms_grant_pages(
        client,
        key_arn=binding.broker_topology_signing_key_arn,
    )
    if grants:
        _fail("BROKER_TOPOLOGY_SIGNING_KEY_GRANTS_PRESENT")
    return {
        "arn": binding.broker_topology_signing_key_arn,
        "account_id": binding.authority_account_id,
        "enabled": True,
        "key_state": "Enabled",
        "key_usage": "SIGN_VERIFY",
        "key_manager": "CUSTOMER",
        "key_spec": "ECC_NIST_P256",
        "origin": "AWS_KMS",
        "multi_region": False,
        "signature_algorithm": (
            binding.broker_topology_signature_algorithm
        ),
        "key_policy_sha256": canonical_digest(policy),
        "grants": [],
    }


def collect_unsigned_broker_topology_evidence(
    *,
    binding: PhaseBIdentityBinding,
    clients: PhaseBTopologyReadOnlyClients,
    now: datetime,
) -> Mapping[str, Any]:
    """Collect provider state and return the exact payload awaiting signature."""

    if now.tzinfo is None or now.utcoffset() is None:
        _fail("CLOCK_INVALID")
    if (
        binding.authority_account_id != AUTHORITY_ACCOUNT_ID
        or binding.management_account_id != MANAGEMENT_ACCOUNT_ID
        or binding.region != REGION
    ):
        _fail("FIXED_TOPOLOGY_MISMATCH")
    application = _collect_application(
        binding=binding,
        client=clients.sso_admin,
    )
    roles = _collect_roles(binding=binding, client=clients.iam)
    lambda_state = _collect_lambda(
        binding=binding,
        client=clients.lambda_client,
    )
    ledger = _collect_ledger(binding=binding, client=clients.dynamodb)
    signing_key = _collect_signing_key(binding=binding, client=clients.kms)
    state = {
        "application": application,
        "roles": roles,
        "lambda": lambda_state,
        "ledger": ledger,
        "signing_key": signing_key,
    }
    evidence: dict[str, Any] = {
        "schema_version": "1",
        "record_type": (
            "platform_authority_lambda_audit_repair_phase_b_"
            "broker_topology_evidence"
        ),
        "environment": "non-production",
        "production": False,
        "status": "PROVIDER_TOPOLOGY_READBACK_VERIFIED",
        "authority_account_id": binding.authority_account_id,
        "management_account_id": binding.management_account_id,
        "region": binding.region,
        "provider_readback": True,
        "identity_center_application_verified": True,
        "single_operator_assignment_verified": True,
        "broker_alias_verified": True,
        "broker_role_verified": True,
        "proof_role_verified": True,
        "ledger_resource_policy_verified": True,
        "direct_qualified_invoke_only": True,
        "function_url_absent": True,
        "synchronous_client_context_required": True,
        "asynchronous_effect_blocked": True,
        "pending_operations_absent": True,
        "invoker_policy_sha256": binding.invoker_policy_sha256,
        "broker_policy_sha256": binding.broker_policy_sha256,
        "proof_policy_sha256": binding.proof_policy_sha256,
        "application_actor_policy_sha256": (
            binding.application_actor_policy_sha256
        ),
        "broker_topology_sha256": binding.broker_topology_sha256,
        "topology_state_digest": canonical_digest(state),
        "collected_at": (
            now.astimezone(UTC)
            .replace(microsecond=0)
            .isoformat()
            .replace("+00:00", "Z")
        ),
        "signing_key_arn": binding.broker_topology_signing_key_arn,
        "signature_algorithm": (
            binding.broker_topology_signature_algorithm
        ),
    }
    evidence["receipt_digest"] = broker_topology_signature_digest(evidence)
    if set(evidence) != BROKER_TOPOLOGY_EVIDENCE_KEYS - {"signature"}:
        _fail("BROKER_TOPOLOGY_EVIDENCE_INVALID")
    return evidence


def attach_broker_topology_signature(
    *,
    unsigned_evidence: Mapping[str, Any],
    signature: str,
) -> Mapping[str, Any]:
    """Attach a separately authorized signature without calling AWS."""

    if set(unsigned_evidence) != BROKER_TOPOLOGY_EVIDENCE_KEYS - {
        "signature"
    }:
        _fail("BROKER_TOPOLOGY_EVIDENCE_INVALID")
    if unsigned_evidence.get("signature_algorithm") != (
        BROKER_TOPOLOGY_SIGNATURE_ALGORITHM
    ):
        _fail("BROKER_TOPOLOGY_EVIDENCE_INVALID")
    if (
        unsigned_evidence.get("receipt_digest")
        != broker_topology_signature_digest(unsigned_evidence)
    ):
        _fail("BROKER_TOPOLOGY_EVIDENCE_DIGEST_MISMATCH")
    if (
        not isinstance(signature, str)
        or not 80 <= len(signature) <= 1024
        or _BASE64_SIGNATURE.fullmatch(signature) is None
    ):
        _fail("BROKER_TOPOLOGY_EVIDENCE_INVALID")
    try:
        decoded = base64.b64decode(signature, validate=True)
    except (binascii.Error, ValueError):
        raise PhaseBPepError("BROKER_TOPOLOGY_EVIDENCE_INVALID") from None
    if not 64 <= len(decoded) <= 512:
        _fail("BROKER_TOPOLOGY_EVIDENCE_INVALID")
    evidence = dict(unsigned_evidence)
    evidence["signature"] = signature
    return evidence
