"""Closed materializer for the temporary GUG-376 artifact bootstrap.

This module is intentionally provider-free.  It binds two local TemplateBody
documents, one principal, one two-hour-or-shorter window and deterministic
authority resource names.  Live calls are implemented only by the companion
``platform_authority_plan_permission_repair_artifact_bootstrap_aws`` module.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from hashlib import sha256
import base64
import json
import re
from typing import Any, Mapping
from urllib.parse import urlencode


MANAGEMENT_ACCOUNT_ID = "839393571433"
AUTHORITY_ACCOUNT_ID = "042360977644"
REGION = "us-east-1"
MANAGEMENT_PROFILE = "839393571433_AWSAdministratorAccess"
AUTHORITY_PROFILE = "042360977644_ScanalyzeGug376ArtifactBootstrap"
BRIDGE_STACK_NAME = "scanalyze-platform-authority-gug376-artifact-bootstrap-bridge"
FOUNDATION_STACK_NAME = "scanalyze-platform-authority-gug376-artifact-foundation"
BRIDGE_CHANGE_SET_NAME = "gug376-artifact-bootstrap-bridge-create"
FOUNDATION_CHANGE_SET_NAME = "gug376-artifact-foundation-create"
REVOKE_CHANGE_SET_NAME = "gug376-artifact-bootstrap-bridge-revoke"
CLEANUP_RETIRE_CHANGE_SET_NAME = "gug376-artifact-bootstrap-cleanup-retire"
BRIDGE_TEMPLATE_PATH = (
    "bootstrap/cfn-platform-authority-gug376-artifact-bootstrap-bridge.yaml"
)
FOUNDATION_TEMPLATE_PATH = (
    "bootstrap/cfn-platform-authority-gug376-artifact-foundation.yaml"
)
INPUT_TYPE = "scanalyze.platform_authority.gug376_artifact_bootstrap_input.v1"
INTENT_TYPE = "scanalyze.platform_authority.gug376_artifact_bootstrap_intent.v1"
AUTHORIZATION_TYPE = (
    "scanalyze.platform_authority.gug376_artifact_bootstrap_authorization.v1"
)
MUTATION_AUTHORIZATION_TYPE = (
    "scanalyze.platform_authority.gug376_artifact_mutation_authorization.v1"
)
OBJECT_INTENT_TYPE = (
    "scanalyze.platform_authority.gug376_artifact_object_publish_intent.v1"
)
OBJECT_RECEIPT_TYPE = (
    "scanalyze.platform_authority.gug376_artifact_object_receipt.v1"
)
SIGNING_INTENT_TYPE = (
    "scanalyze.platform_authority.gug376_artifact_signing_intent.v1"
)
ACCESS_UPDATE_TYPE = (
    "scanalyze.platform_authority.gug376_artifact_foundation_access_update.v1"
)
BRIDGE_PIN_TYPE = (
    "scanalyze.platform_authority.gug376_artifact_bootstrap_bridge_pin.v1"
)
BRIDGE_CLEANUP_RETIRE_TYPE = (
    "scanalyze.platform_authority.gug376_artifact_bootstrap_cleanup_retire.v1"
)
BRIDGE_CLEANUP_RETIRE_AUTHORIZATION_TYPE = (
    "scanalyze.platform_authority.gug376_artifact_bootstrap_cleanup_retire_authorization.v1"
)
FOUNDATION_READBACK_TYPE = (
    "scanalyze.platform_authority.gug376_artifact_foundation_readback.v1"
)
FOUNDATION_ACCESS_READBACK_TYPE = (
    "scanalyze.platform_authority.gug376_artifact_foundation_access_readback.v1"
)
STACK_READBACK_TYPE = (
    "scanalyze.platform_authority.gug376_artifact_bootstrap_stack_readback.v1"
)
REVIEWED_SOURCES_TYPE = (
    "scanalyze.platform_authority.gug376_artifact_reviewed_sources.v1"
)
ROUTE_RELEASE_TYPE = (
    "scanalyze.platform_authority.gug376_artifact_bootstrap_route_release.v1"
)
FOUNDATION_STORAGE_BINDING_TYPE = (
    "scanalyze.platform_authority.gug376_artifact_foundation_publish_binding.v1"
)
PRODUCTION_STATUS = "NO-GO"
ARTIFACT_PREFIX = "scanalyze/platform-authority/gug-376/plan-policy-repair/"
ROUTE_TEMPLATE_SOURCE_PATH = (
    "bootstrap/cfn-platform-authority-gug376-temporary-change-set-route.yaml"
)
DELEGATION_TEMPLATE_SOURCE_PATH = (
    "bootstrap/cfn-platform-authority-bootstrap-plan-repair-delegation.yaml"
)
STACK_TAGS = [
    {"Key": "managed_by", "Value": "cloudformation"},
    {"Key": "service", "Value": "scanalyze-platform-authority"},
    {"Key": "work_package", "Value": "GUG-376"},
]
MIN_ACCESS_WINDOW_SECONDS = 3600
MUTATION_COMPLETION_RESERVE_SECONDS = 1800

_COMMIT = re.compile(r"^[a-f0-9]{40}$")
_DIGEST = re.compile(r"^sha256:[a-f0-9]{64}$")
_INSTANCE = re.compile(r"^arn:aws:sso:::instance/ssoins-[A-Za-z0-9]{16}$")
_PRINCIPAL = re.compile(
    r"^(?:[0-9a-f]{10}-)?[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$"
)
_VERSION = re.compile(r"^[A-Za-z0-9._~+/=-]{1,1024}$")
_KEY = re.compile(
    r"^scanalyze/platform-authority/gug-376/plan-policy-repair/"
    r"(?:templates|unsigned|signed|pep/unsigned|pep/signed|broker/unsigned|broker/signed|private)/"
    r"[A-Za-z0-9._~!$&'()*+,;=:@/-]{1,900}$"
)
_TIME = re.compile(
    r"^20[0-9]{2}-(?:0[1-9]|1[0-2])-(?:[0-2][0-9]|3[01])T"
    r"(?:[01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]Z$"
)


class ArtifactBootstrapError(ValueError):
    """Stable fail-closed materialization error."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def _fail(code: str) -> None:
    raise ArtifactBootstrapError(code)


def canonical_json(value: Any) -> str:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        )
    except (TypeError, ValueError) as exc:
        raise ArtifactBootstrapError("VALUE_NOT_CANONICAL") from exc


def digest_value(value: Any) -> str:
    return "sha256:" + sha256(canonical_json(value).encode("utf-8")).hexdigest()


def bytes_digest(value: bytes) -> str:
    return "sha256:" + sha256(value).hexdigest()


def _seal(value: Mapping[str, Any], field: str) -> dict[str, Any]:
    record = dict(value)
    record[field] = digest_value(record)
    return record


def _verify(value: Mapping[str, Any], field: str, code: str) -> None:
    claimed = value.get(field)
    if (
        not isinstance(claimed, str)
        or _DIGEST.fullmatch(claimed) is None
        or digest_value({key: item for key, item in value.items() if key != field})
        != claimed
    ):
        _fail(code)


def _parse_time(value: Any, code: str) -> datetime:
    if not isinstance(value, str) or _TIME.fullmatch(value) is None:
        _fail(code)
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise ArtifactBootstrapError(code) from exc
    if parsed.microsecond:
        _fail(code)
    return parsed


def _recovery_not_after(access_not_after: datetime) -> str:
    recovery_end = access_not_after + timedelta(hours=24)
    rendered = recovery_end.strftime("%Y-%m-%dT%H:%M:%SZ")
    if _TIME.fullmatch(rendered) is None:
        _fail("RECOVERY_WINDOW_INVALID")
    return rendered


def _cleanup_not_after(access_not_after: datetime) -> str:
    """Return the outer bridge-owned recovery/cleanup authority horizon.

    Normal artifact recovery remains limited to ``AccessNotAfter + 24h``.
    Route recovery can start after the artifact principal is revoked, so the
    two bridge-owned cleanup permission sets need one additional, exact 24h
    outer guard.  The downstream seed must still prove that its own narrower
    recovery horizon does not exceed this value.
    """

    cleanup_end = access_not_after + timedelta(hours=48)
    rendered = cleanup_end.strftime("%Y-%m-%dT%H:%M:%SZ")
    if _TIME.fullmatch(rendered) is None:
        _fail("CLEANUP_WINDOW_INVALID")
    return rendered


def _mutation_admission_not_after(access_not_after: datetime) -> datetime:
    """Return the exclusive cutoff for accepting a new mutation.

    The remaining access interval is reserved for the exact effect already
    admitted and its CloudFormation completion or rollback. Recovery cannot
    admit another effect.
    """

    return access_not_after - timedelta(
        seconds=MUTATION_COMPLETION_RESERVE_SECONDS
    )


def _validate_window_timestamp(
    value: Any,
    *,
    bootstrap: Mapping[str, Any],
    read_only: bool,
    code: str,
) -> datetime:
    """Validate one causal timestamp against a closed, half-open window.

    Mutations must happen while the temporary principal is authorized.  Reads
    and causal recovery may continue only through the separately bounded
    recovery horizon.  Equality with either upper boundary is intentionally
    rejected so the offline contracts match the IAM ``DateGreaterThanEquals``
    denies exactly.
    """

    observed = _parse_time(value, code)
    window_start = _parse_time(bootstrap.get("access_not_before"), code)
    boundary_field = "recovery_not_after" if read_only else "access_not_after"
    window_end = _parse_time(bootstrap.get(boundary_field), code)
    if not window_start <= observed < window_end:
        _fail(code)
    return observed


def deterministic_names(source_commit: str) -> dict[str, str]:
    if not isinstance(source_commit, str) or _COMMIT.fullmatch(source_commit) is None:
        _fail("SOURCE_COMMIT_INVALID")
    suffix = source_commit[:12]
    return {
        "artifact_bucket": f"scanalyze-platform-authority-gug376-artifacts-{suffix}",
        "artifact_kms_alias": (
            f"alias/scanalyze-platform-authority-gug376-artifacts-{suffix}"
        ),
        "signing_profile_name": f"ScanalyzeGug376ArtifactSigner_{suffix}",
    }


def _parameters(values: Mapping[str, str]) -> list[dict[str, str]]:
    return [
        {"ParameterKey": key, "ParameterValue": value}
        for key, value in values.items()
    ]


def _stack_request(
    *,
    stack_name: str,
    change_set_name: str,
    change_set_type: str,
    template_body: str,
    parameters: Mapping[str, str],
    token_seed: Mapping[str, Any],
) -> dict[str, Any]:
    if (
        change_set_type not in {"CREATE", "UPDATE"}
        or not template_body
        or len(template_body.encode("utf-8")) > 51_200
        or "TemplateURL" in template_body
    ):
        _fail("TEMPLATE_BODY_INVALID")
    return {
        "StackName": stack_name,
        "ChangeSetName": change_set_name,
        "ChangeSetType": change_set_type,
        "Description": "GUG-376 bounded artifact bootstrap; not production",
        "TemplateBody": template_body,
        "Parameters": _parameters(parameters),
        "Capabilities": [],
        "Tags": list(STACK_TAGS),
        "IncludeNestedStacks": False,
        "NotificationARNs": [],
        "RollbackConfiguration": {
            "MonitoringTimeInMinutes": 0,
            "RollbackTriggers": [],
        },
        "OnStackFailure": "DELETE" if change_set_type == "CREATE" else None,
        "ClientToken": "gug376-" + digest_value(token_seed)[7:55],
    }


def _normalize_request(value: dict[str, Any]) -> dict[str, Any]:
    return {key: item for key, item in value.items() if item is not None}


@dataclass(frozen=True, slots=True)
class MaterializedBootstrap:
    value: dict[str, Any]
    bridge_template: bytes
    foundation_template: bytes


def materialize_bootstrap_intent(
    value: Mapping[str, Any], *, bridge_template: bytes, foundation_template: bytes
) -> dict[str, Any]:
    """Bind both TemplateBody stacks and the only bootstrap principal."""

    expected = {
        "schema_version",
        "record_type",
        "source_commit",
        "management_account_id",
        "authority_account_id",
        "region",
        "identity_center_instance_arn",
        "bootstrap_principal_id",
        "access_not_before",
        "access_not_after",
        "production_authorized",
        "input_digest",
    }
    if not isinstance(value, Mapping) or set(value) != expected:
        _fail("INPUT_FIELDS_INVALID")
    _verify(value, "input_digest", "INPUT_DIGEST_INVALID")
    source_commit = value.get("source_commit")
    before = _parse_time(value.get("access_not_before"), "WINDOW_INVALID")
    after = _parse_time(value.get("access_not_after"), "WINDOW_INVALID")
    if (
        value.get("schema_version") != 1
        or value.get("record_type") != INPUT_TYPE
        or not isinstance(source_commit, str)
        or _COMMIT.fullmatch(source_commit) is None
        or value.get("management_account_id") != MANAGEMENT_ACCOUNT_ID
        or value.get("authority_account_id") != AUTHORITY_ACCOUNT_ID
        or value.get("region") != REGION
        or _INSTANCE.fullmatch(str(value.get("identity_center_instance_arn", "")))
        is None
        or _PRINCIPAL.fullmatch(str(value.get("bootstrap_principal_id", "")))
        is None
        or not before < after
        or (after - before).total_seconds() < MIN_ACCESS_WINDOW_SECONDS
        or (after - before).total_seconds() > 7200
        or value.get("production_authorized") is not False
    ):
        _fail("INPUT_INVALID")
    recovery_not_after = _recovery_not_after(after)
    cleanup_not_after = _cleanup_not_after(after)
    for body, marker in (
        (bridge_template, b"ArtifactBootstrapPermissionSet:"),
        (foundation_template, b"ArtifactKey:"),
    ):
        if (
            not isinstance(body, bytes)
            or not body
            or len(body) > 51_200
            or marker not in body
            or b"TemplateURL:" in body
            or (body is foundation_template and b"AWS::IAM::" in body)
        ):
            _fail("TEMPLATE_BODY_INVALID")
    if (
        bridge_template.count(b"Type: AWS::SSO::PermissionSet") != 3
        or bridge_template.count(b"Type: AWS::SSO::Assignment") != 3
        or bridge_template.count(b"Type: AWS::IAM::Role") != 1
        or b"Type: AWS::S3::Bucket" in bridge_template
        or b"Type: AWS::KMS::Key" in bridge_template
    ):
        _fail("BRIDGE_RESOURCE_SET_INVALID")

    names = deterministic_names(source_commit)
    common_bridge = {
        "ManagementAccountId": MANAGEMENT_ACCOUNT_ID,
        "AuthorityAccountId": AUTHORITY_ACCOUNT_ID,
        "SourceCommit": source_commit,
        "IdentityCenterInstanceArn": str(value["identity_center_instance_arn"]),
        "BootstrapPrincipalId": str(value["bootstrap_principal_id"]),
        "AccessNotBefore": str(value["access_not_before"]),
        "AccessNotAfter": str(value["access_not_after"]),
        "RecoveryNotAfter": recovery_not_after,
        "CleanupNotAfter": cleanup_not_after,
        "ArtifactBucketName": names["artifact_bucket"],
        "ArtifactKmsAlias": names["artifact_kms_alias"],
        "SigningProfileName": names["signing_profile_name"],
        "SigningProfileVersion": "NOT_CONFIGURED",
    }
    bridge_create_parameters = {
        **common_bridge,
        "AssignmentEnabled": "true",
        "CleanupAssignmentsEnabled": "true",
    }
    bridge_revoke_parameters = {
        **common_bridge,
        "AssignmentEnabled": "false",
        "CleanupAssignmentsEnabled": "true",
    }
    foundation_parameters = {
        "AuthorityAccountId": AUTHORITY_ACCOUNT_ID,
        "SourceCommit": source_commit,
        "ArtifactBucketName": names["artifact_bucket"],
        "ArtifactKmsAlias": names["artifact_kms_alias"],
        "SigningProfileName": names["signing_profile_name"],
        "CrossAccountAccessEnabled": "false",
        "RouteTemplateVersion": "NOT_CONFIGURED",
        "DelegationTemplateVersion": "NOT_CONFIGURED",
    }
    bridge_text = bridge_template.decode("utf-8")
    foundation_text = foundation_template.decode("utf-8")
    requests = {
        "bridge-create": _normalize_request(
            _stack_request(
                stack_name=BRIDGE_STACK_NAME,
                change_set_name=BRIDGE_CHANGE_SET_NAME,
                change_set_type="CREATE",
                template_body=bridge_text,
                parameters=bridge_create_parameters,
                token_seed={"source_commit": source_commit, "step": "bridge-create"},
            )
        ),
        "foundation-create": _normalize_request(
            _stack_request(
                stack_name=FOUNDATION_STACK_NAME,
                change_set_name=FOUNDATION_CHANGE_SET_NAME,
                change_set_type="CREATE",
                template_body=foundation_text,
                parameters=foundation_parameters,
                token_seed={"source_commit": source_commit, "step": "foundation-create"},
            )
        ),
        "bridge-revoke": _normalize_request(
            _stack_request(
                stack_name=BRIDGE_STACK_NAME,
                change_set_name=REVOKE_CHANGE_SET_NAME,
                change_set_type="UPDATE",
                template_body=bridge_text,
                parameters=bridge_revoke_parameters,
                token_seed={"source_commit": source_commit, "step": "bridge-revoke"},
            )
        ),
    }
    intent: dict[str, Any] = {
        "schema_version": 1,
        "record_type": INTENT_TYPE,
        "source_commit": source_commit,
        "management_account_id": MANAGEMENT_ACCOUNT_ID,
        "authority_account_id": AUTHORITY_ACCOUNT_ID,
        "region": REGION,
        "access_not_before": value["access_not_before"],
        "access_not_after": value["access_not_after"],
        "recovery_not_after": recovery_not_after,
        "cleanup_not_after": cleanup_not_after,
        "identity_center_instance_arn_digest": digest_value(
            value["identity_center_instance_arn"]
        ),
        "bootstrap_principal_id_digest": digest_value(
            value["bootstrap_principal_id"]
        ),
        "names": names,
        "template_digests": {
            "bridge": bytes_digest(bridge_template),
            "foundation": bytes_digest(foundation_template),
        },
        "requests": requests,
        "request_digests": {
            name: digest_value(request) for name, request in requests.items()
        },
        "required_order": [
            "bridge-create",
            "foundation-create",
            "bridge-pin-signing-profile-version",
            "publish-and-readback-route-and-delegation",
            "foundation-access-update",
            "publish-and-sign-artifacts",
            "bridge-revoke",
            "normal-route",
        ],
        "aws_calls": 0,
        "aws_mutations": 0,
        "deployment_authorized": False,
        "production_authorized": False,
        "production_status": PRODUCTION_STATUS,
    }
    return _seal(intent, "intent_digest")


def validate_bootstrap_intent(value: Mapping[str, Any]) -> dict[str, Any]:
    expected_fields = {
        "schema_version",
        "record_type",
        "source_commit",
        "management_account_id",
        "authority_account_id",
        "region",
        "access_not_before",
        "access_not_after",
        "recovery_not_after",
        "cleanup_not_after",
        "identity_center_instance_arn_digest",
        "bootstrap_principal_id_digest",
        "names",
        "template_digests",
        "requests",
        "request_digests",
        "required_order",
        "aws_calls",
        "aws_mutations",
        "deployment_authorized",
        "production_authorized",
        "production_status",
        "intent_digest",
    }
    if not isinstance(value, Mapping) or set(value) != expected_fields:
        _fail("INTENT_INVALID")
    _verify(value, "intent_digest", "INTENT_DIGEST_INVALID")
    if (
        value.get("schema_version") != 1
        or value.get("record_type") != INTENT_TYPE
        or value.get("management_account_id") != MANAGEMENT_ACCOUNT_ID
        or value.get("authority_account_id") != AUTHORITY_ACCOUNT_ID
        or value.get("region") != REGION
        or value.get("production_authorized") is not False
        or value.get("production_status") != PRODUCTION_STATUS
        or value.get("deployment_authorized") is not False
        or value.get("aws_calls") != 0
        or value.get("aws_mutations") != 0
    ):
        _fail("INTENT_INVALID")
    source_commit = value.get("source_commit")
    if value.get("names") != deterministic_names(str(source_commit)):
        _fail("INTENT_NAME_BINDING_INVALID")
    before = _parse_time(value.get("access_not_before"), "INTENT_WINDOW_INVALID")
    after = _parse_time(value.get("access_not_after"), "INTENT_WINDOW_INVALID")
    recovery_after = _parse_time(
        value.get("recovery_not_after"), "INTENT_WINDOW_INVALID"
    )
    cleanup_after = _parse_time(
        value.get("cleanup_not_after"), "INTENT_WINDOW_INVALID"
    )
    if (
        not before < after < recovery_after < cleanup_after
        or (after - before).total_seconds() < MIN_ACCESS_WINDOW_SECONDS
        or (after - before).total_seconds() > 7200
        or value.get("recovery_not_after") != _recovery_not_after(after)
        or value.get("cleanup_not_after") != _cleanup_not_after(after)
    ):
        _fail("INTENT_WINDOW_INVALID")
    requests = value.get("requests")
    digests = value.get("request_digests")
    if (
        not isinstance(requests, Mapping)
        or set(requests) != {"bridge-create", "foundation-create", "bridge-revoke"}
        or not isinstance(digests, Mapping)
        or digests
        != {name: digest_value(request) for name, request in requests.items()}
        or "TemplateURL" in canonical_json(requests)
        or requests["bridge-create"].get("ChangeSetType") != "CREATE"
        or requests["foundation-create"].get("ChangeSetType") != "CREATE"
        or requests["bridge-revoke"].get("ChangeSetType") != "UPDATE"
    ):
        _fail("INTENT_REQUEST_INVALID")
    create_keys = {
        "StackName",
        "ChangeSetName",
        "ChangeSetType",
        "Description",
        "TemplateBody",
        "Parameters",
        "Capabilities",
        "Tags",
        "IncludeNestedStacks",
        "NotificationARNs",
        "RollbackConfiguration",
        "OnStackFailure",
        "ClientToken",
    }
    update_keys = create_keys - {"OnStackFailure"}
    if (
        set(requests["bridge-create"]) != create_keys
        or set(requests["foundation-create"]) != create_keys
        or set(requests["bridge-revoke"]) != update_keys
        or value.get("required_order")
        != [
            "bridge-create",
            "foundation-create",
            "bridge-pin-signing-profile-version",
            "publish-and-readback-route-and-delegation",
            "foundation-access-update",
            "publish-and-sign-artifacts",
            "bridge-revoke",
            "normal-route",
        ]
    ):
        _fail("INTENT_REQUEST_SURFACE_INVALID")
    bridge_body = requests["bridge-create"].get("TemplateBody")
    foundation_body = requests["foundation-create"].get("TemplateBody")
    if (
        not isinstance(bridge_body, str)
        or not isinstance(foundation_body, str)
        or requests["bridge-revoke"].get("TemplateBody") != bridge_body
        or len(bridge_body.encode("utf-8")) > 51_200
        or len(foundation_body.encode("utf-8")) > 51_200
        or "TemplateURL" in bridge_body
        or "TemplateURL" in foundation_body
        or value.get("template_digests")
        != {
            "bridge": bytes_digest(bridge_body.encode("utf-8")),
            "foundation": bytes_digest(foundation_body.encode("utf-8")),
        }
    ):
        _fail("INTENT_TEMPLATE_BINDING_INVALID")
    bridge_parameters = {
        item.get("ParameterKey"): item.get("ParameterValue")
        for item in requests["bridge-create"].get("Parameters", [])
        if isinstance(item, Mapping)
    }
    if (
        len(bridge_parameters)
        != len(requests["bridge-create"].get("Parameters", []))
        or digest_value(bridge_parameters.get("IdentityCenterInstanceArn"))
        != value.get("identity_center_instance_arn_digest")
        or digest_value(bridge_parameters.get("BootstrapPrincipalId"))
        != value.get("bootstrap_principal_id_digest")
    ):
        _fail("INTENT_PRIVATE_PARAMETER_BINDING_INVALID")
    common_bridge = {
        "ManagementAccountId": MANAGEMENT_ACCOUNT_ID,
        "AuthorityAccountId": AUTHORITY_ACCOUNT_ID,
        "SourceCommit": str(source_commit),
        "IdentityCenterInstanceArn": str(
            bridge_parameters.get("IdentityCenterInstanceArn")
        ),
        "BootstrapPrincipalId": str(bridge_parameters.get("BootstrapPrincipalId")),
        "AccessNotBefore": str(value.get("access_not_before")),
        "AccessNotAfter": str(value.get("access_not_after")),
        "RecoveryNotAfter": str(value.get("recovery_not_after")),
        "CleanupNotAfter": str(value.get("cleanup_not_after")),
        "ArtifactBucketName": value["names"]["artifact_bucket"],
        "ArtifactKmsAlias": value["names"]["artifact_kms_alias"],
        "SigningProfileName": value["names"]["signing_profile_name"],
        "SigningProfileVersion": "NOT_CONFIGURED",
    }
    foundation_parameters = {
        "AuthorityAccountId": AUTHORITY_ACCOUNT_ID,
        "SourceCommit": str(source_commit),
        "ArtifactBucketName": value["names"]["artifact_bucket"],
        "ArtifactKmsAlias": value["names"]["artifact_kms_alias"],
        "SigningProfileName": value["names"]["signing_profile_name"],
        "CrossAccountAccessEnabled": "false",
        "RouteTemplateVersion": "NOT_CONFIGURED",
        "DelegationTemplateVersion": "NOT_CONFIGURED",
    }
    rebuilt = {
        "bridge-create": _normalize_request(
            _stack_request(
                stack_name=BRIDGE_STACK_NAME,
                change_set_name=BRIDGE_CHANGE_SET_NAME,
                change_set_type="CREATE",
                template_body=bridge_body,
                parameters={
                    **common_bridge,
                    "AssignmentEnabled": "true",
                    "CleanupAssignmentsEnabled": "true",
                },
                token_seed={"source_commit": source_commit, "step": "bridge-create"},
            )
        ),
        "foundation-create": _normalize_request(
            _stack_request(
                stack_name=FOUNDATION_STACK_NAME,
                change_set_name=FOUNDATION_CHANGE_SET_NAME,
                change_set_type="CREATE",
                template_body=foundation_body,
                parameters=foundation_parameters,
                token_seed={"source_commit": source_commit, "step": "foundation-create"},
            )
        ),
        "bridge-revoke": _normalize_request(
            _stack_request(
                stack_name=BRIDGE_STACK_NAME,
                change_set_name=REVOKE_CHANGE_SET_NAME,
                change_set_type="UPDATE",
                template_body=bridge_body,
                parameters={
                    **common_bridge,
                    "AssignmentEnabled": "false",
                    "CleanupAssignmentsEnabled": "true",
                },
                token_seed={"source_commit": source_commit, "step": "bridge-revoke"},
            )
        ),
    }
    if requests != rebuilt:
        _fail("INTENT_REQUEST_RECONSTRUCTION_MISMATCH")
    return json.loads(canonical_json(dict(value)))


def materialize_authorization(
    *,
    intent: Mapping[str, Any],
    operation: str,
    authorization: str,
    authorized_at: datetime,
    expires_at: datetime,
) -> dict[str, Any]:
    normalized = validate_bootstrap_intent(intent)
    match = re.fullmatch(
        r"(bridge-create|foundation-create|bridge-revoke):(dispatch|execute)",
        operation,
    )
    if match is None:
        _fail("AUTHORIZATION_OPERATION_INVALID")
    request_operation = match.group(1)
    if (
        authorized_at.tzinfo is None
        or authorized_at.utcoffset() is None
        or expires_at.tzinfo is None
        or expires_at.utcoffset() is None
    ):
        _fail("AUTHORIZATION_CLOCK_INVALID")
    start = authorized_at.astimezone(timezone.utc).replace(microsecond=0)
    end = expires_at.astimezone(timezone.utc).replace(microsecond=0)
    window_start = _parse_time(normalized["access_not_before"], "WINDOW_INVALID")
    window_end = _mutation_admission_not_after(
        _parse_time(normalized["access_not_after"], "WINDOW_INVALID")
    )
    expected = f"AUTHORIZE GUG-376 {operation} {normalized['source_commit']}"
    if (
        authorization != expected
        or not window_start <= start < end <= window_end
        or (end - start).total_seconds() > 900
    ):
        _fail("AUTHORIZATION_INVALID")
    record: dict[str, Any] = {
        "schema_version": 1,
        "record_type": AUTHORIZATION_TYPE,
        "source_commit": normalized["source_commit"],
        "operation": operation,
        "intent_digest": normalized["intent_digest"],
        "request_digest": normalized["request_digests"][request_operation],
        "authorization": authorization,
        "authorized_at": start.isoformat().replace("+00:00", "Z"),
        "expires_at": end.isoformat().replace("+00:00", "Z"),
        "production_authorized": False,
    }
    return _seal(record, "authorization_digest")


def validate_authorization(
    value: Mapping[str, Any], *, intent: Mapping[str, Any], operation: str, now: datetime
) -> dict[str, Any]:
    normalized = validate_bootstrap_intent(intent)
    match = re.fullmatch(
        r"(bridge-create|foundation-create|bridge-revoke):(dispatch|execute)",
        operation,
    )
    if match is None:
        _fail("AUTHORIZATION_OPERATION_INVALID")
    request_operation = match.group(1)
    expected_fields = {
        "schema_version", "record_type", "source_commit", "operation",
        "intent_digest", "request_digest", "authorization", "authorized_at",
        "expires_at", "production_authorized", "authorization_digest",
    }
    if not isinstance(value, Mapping) or set(value) != expected_fields:
        _fail("AUTHORIZATION_INVALID")
    _verify(value, "authorization_digest", "AUTHORIZATION_DIGEST_INVALID")
    if now.tzinfo is None or now.utcoffset() is None:
        _fail("AUTHORIZATION_CLOCK_INVALID")
    current = now.astimezone(timezone.utc).replace(microsecond=0)
    authorized = _parse_time(value.get("authorized_at"), "AUTHORIZATION_INVALID")
    expires = _parse_time(value.get("expires_at"), "AUTHORIZATION_INVALID")
    window_start = _parse_time(normalized["access_not_before"], "AUTHORIZATION_INVALID")
    window_end = _mutation_admission_not_after(
        _parse_time(normalized["access_not_after"], "AUTHORIZATION_INVALID")
    )
    if (
        value.get("schema_version") != 1
        or value.get("record_type") != AUTHORIZATION_TYPE
        or value.get("source_commit") != normalized["source_commit"]
        or value.get("operation") != operation
        or value.get("intent_digest") != normalized["intent_digest"]
        or value.get("request_digest")
        != normalized["request_digests"].get(request_operation)
        or value.get("authorization")
        != f"AUTHORIZE GUG-376 {operation} {normalized['source_commit']}"
        or value.get("production_authorized") is not False
        or not window_start <= authorized <= current < expires <= window_end
        or (expires - authorized).total_seconds() > 900
    ):
        _fail("AUTHORIZATION_INVALID")
    return json.loads(canonical_json(dict(value)))


def materialize_mutation_authorization(
    *,
    bootstrap_intent: Mapping[str, Any],
    operation: str,
    target_digest: str,
    authorization: str,
    authorized_at: datetime,
    expires_at: datetime,
) -> dict[str, Any]:
    """Authorize one already-materialized PutObject or StartSigningJob."""

    bootstrap = validate_bootstrap_intent(bootstrap_intent)
    source_commit = bootstrap["source_commit"]
    if (
        operation not in {
            "publish-object",
            "start-signing-job",
            "bridge-pin:dispatch",
            "bridge-pin:execute",
            "foundation-access-update:dispatch",
            "foundation-access-update:execute",
        }
        or _DIGEST.fullmatch(target_digest) is None
    ):
        _fail("MUTATION_AUTHORIZATION_INPUT_INVALID")
    if (
        authorized_at.tzinfo is None
        or authorized_at.utcoffset() is None
        or expires_at.tzinfo is None
        or expires_at.utcoffset() is None
    ):
        _fail("MUTATION_AUTHORIZATION_CLOCK_INVALID")
    start = authorized_at.astimezone(timezone.utc).replace(microsecond=0)
    end = expires_at.astimezone(timezone.utc).replace(microsecond=0)
    window_start = _parse_time(bootstrap["access_not_before"], "WINDOW_INVALID")
    window_end = _mutation_admission_not_after(
        _parse_time(bootstrap["access_not_after"], "WINDOW_INVALID")
    )
    expected = f"AUTHORIZE GUG-376 {operation} {target_digest}"
    if (
        authorization != expected
        or not window_start <= start < end <= window_end
        or (end - start).total_seconds() > 900
    ):
        _fail("MUTATION_AUTHORIZATION_INVALID")
    record: dict[str, Any] = {
        "schema_version": 1,
        "record_type": MUTATION_AUTHORIZATION_TYPE,
        "source_commit": source_commit,
        "bootstrap_intent_digest": bootstrap["intent_digest"],
        "operation": operation,
        "target_digest": target_digest,
        "authorization": authorization,
        "authorized_at": start.isoformat().replace("+00:00", "Z"),
        "expires_at": end.isoformat().replace("+00:00", "Z"),
        "production_authorized": False,
    }
    return _seal(record, "authorization_digest")


def validate_mutation_authorization(
    value: Mapping[str, Any],
    *,
    bootstrap_intent: Mapping[str, Any],
    operation: str,
    target_digest: str,
    now: datetime,
) -> dict[str, Any]:
    bootstrap = validate_bootstrap_intent(bootstrap_intent)
    source_commit = bootstrap["source_commit"]
    expected_fields = {
        "schema_version", "record_type", "source_commit",
        "bootstrap_intent_digest", "operation", "target_digest",
        "authorization", "authorized_at", "expires_at",
        "production_authorized", "authorization_digest",
    }
    if not isinstance(value, Mapping) or set(value) != expected_fields:
        _fail("MUTATION_AUTHORIZATION_INVALID")
    _verify(
        value,
        "authorization_digest",
        "MUTATION_AUTHORIZATION_DIGEST_INVALID",
    )
    if now.tzinfo is None or now.utcoffset() is None:
        _fail("MUTATION_AUTHORIZATION_CLOCK_INVALID")
    current = now.astimezone(timezone.utc).replace(microsecond=0)
    authorized = _parse_time(
        value.get("authorized_at"), "MUTATION_AUTHORIZATION_INVALID"
    )
    expires = _parse_time(
        value.get("expires_at"), "MUTATION_AUTHORIZATION_INVALID"
    )
    window_start = _parse_time(
        bootstrap["access_not_before"], "MUTATION_AUTHORIZATION_INVALID"
    )
    window_end = _mutation_admission_not_after(
        _parse_time(
            bootstrap["access_not_after"], "MUTATION_AUTHORIZATION_INVALID"
        )
    )
    if (
        value.get("schema_version") != 1
        or value.get("record_type") != MUTATION_AUTHORIZATION_TYPE
        or value.get("source_commit") != source_commit
        or value.get("bootstrap_intent_digest") != bootstrap["intent_digest"]
        or value.get("operation") != operation
        or value.get("target_digest") != target_digest
        or value.get("authorization")
        != f"AUTHORIZE GUG-376 {operation} {target_digest}"
        or value.get("production_authorized") is not False
        or not window_start <= authorized <= current < expires <= window_end
        or (expires - authorized).total_seconds() > 900
    ):
        _fail("MUTATION_AUTHORIZATION_INVALID")
    return json.loads(canonical_json(dict(value)))


def _validate_cleanup_terminal_readbacks(
    *,
    bootstrap: Mapping[str, Any],
    bootstrap_route_release: Mapping[str, Any],
    seed_intent: Mapping[str, Any],
    terminal_readbacks: Mapping[str, Any],
    evaluated_at: datetime,
) -> dict[str, Any]:
    """Validate the exact successful route/broker/protection terminal set.

    The connected seed terminal reader has already compared the complete live
    stack, resource, output, assignment and service-property projections to
    the sealed seed intent.  This cross-package join closes that receipt back
    to the same artifact release without copying private route inputs into the
    bridge-retirement receipt.
    """

    try:
        from tooling import platform_authority_plan_permission_repair_deployment_route as route

        seed = route.validate_seed_intent(seed_intent)
        release = validate_route_release(
            bootstrap_route_release,
            bootstrap_intent=bootstrap,
            now=evaluated_at,
        )
    except (ImportError, AttributeError, TypeError, ValueError, RuntimeError) as exc:
        raise ArtifactBootstrapError("CLEANUP_RETIRE_SUCCESS_EVIDENCE_INVALID") from exc
    if (
        seed.get("source_commit") != bootstrap["source_commit"]
        or seed.get("artifact_bootstrap_release_digest") != release["release_digest"]
        or seed.get("cleanup_not_after") != bootstrap["cleanup_not_after"]
        or seed.get("recovery_not_after") > seed.get("cleanup_not_after")
        or not isinstance(terminal_readbacks, Mapping)
        or set(terminal_readbacks) != {"route", "broker", "broker-protection"}
    ):
        _fail("CLEANUP_RETIRE_SUCCESS_EVIDENCE_INVALID")

    expected_fields = {
        "schema_version",
        "record_type",
        "source_commit",
        "target",
        "account_id",
        "execution_receipt_digest",
        "execute_cloudtrail_event_digest",
        "stack_arn",
        "stack_status",
        "template_digest",
        "resource_count",
        "resources_digest",
        "outputs_digest",
        "assignment_count",
        "assignments_digest",
        "live_property_read_count",
        "live_properties_digest",
        "read_at",
        "aws_calls",
        "aws_mutations",
        "retry_permitted",
        "production_authorized",
        "production_status",
        "readback_digest",
    }
    normalized: dict[str, Any] = {}
    read_times: dict[str, datetime] = {}
    broker_stack_arn: str | None = None
    for target in ("route", "broker", "broker-protection"):
        receipt = terminal_readbacks.get(target)
        spec = seed["targets"][target]
        account_id = (
            MANAGEMENT_ACCOUNT_ID if target == "route" else AUTHORITY_ACCOUNT_ID
        )
        status = "UPDATE_COMPLETE" if target == "broker-protection" else "CREATE_COMPLETE"
        stack_pattern = (
            rf"arn:aws:cloudformation:{REGION}:{account_id}:stack/"
            + re.escape(spec["stack_name"])
            + r"/[0-9a-f-]{36}"
        )
        if not isinstance(receipt, Mapping) or set(receipt) != expected_fields:
            _fail("CLEANUP_RETIRE_SUCCESS_EVIDENCE_INVALID")
        _verify(
            receipt,
            "readback_digest",
            "CLEANUP_RETIRE_SUCCESS_EVIDENCE_INVALID",
        )
        read_at = _parse_time(
            receipt.get("read_at"), "CLEANUP_RETIRE_SUCCESS_EVIDENCE_INVALID"
        )
        if (
            receipt.get("schema_version") != 1
            or receipt.get("record_type")
            != "scanalyze.platform_authority.plan_permission_repair_seed_terminal_readback.v1"
            or receipt.get("source_commit") != bootstrap["source_commit"]
            or receipt.get("target") != target
            or receipt.get("account_id") != account_id
            or _DIGEST.fullmatch(str(receipt.get("execution_receipt_digest", ""))) is None
            or _DIGEST.fullmatch(str(receipt.get("execute_cloudtrail_event_digest", ""))) is None
            or re.fullmatch(stack_pattern, str(receipt.get("stack_arn", ""))) is None
            or receipt.get("stack_status") != status
            or receipt.get("template_digest") != spec["template_digest"]
            or receipt.get("resource_count") != len(spec["expected_resources"])
            or receipt.get("resources_digest") != digest_value(spec["expected_resources"])
            or _DIGEST.fullmatch(str(receipt.get("outputs_digest", ""))) is None
            or receipt.get("assignment_count") != spec["expected_assignment_count"]
            or _DIGEST.fullmatch(str(receipt.get("assignments_digest", ""))) is None
            or type(receipt.get("live_property_read_count")) is not int
            or receipt["live_property_read_count"] < 0
            or _DIGEST.fullmatch(str(receipt.get("live_properties_digest", ""))) is None
            or not _parse_time(seed["route_not_before"], "CLEANUP_RETIRE_SUCCESS_EVIDENCE_INVALID")
            <= read_at
            <= evaluated_at
            or type(receipt.get("aws_calls")) is not int
            or receipt["aws_calls"] < 4
            or receipt.get("aws_mutations") != 0
            or receipt.get("retry_permitted") is not False
            or receipt.get("production_authorized") is not False
            or receipt.get("production_status") != PRODUCTION_STATUS
        ):
            _fail("CLEANUP_RETIRE_SUCCESS_EVIDENCE_INVALID")
        if target == "route" and receipt["live_property_read_count"] <= 0:
            _fail("CLEANUP_RETIRE_SUCCESS_EVIDENCE_INVALID")
        if target != "route" and receipt["assignment_count"] != 0:
            _fail("CLEANUP_RETIRE_SUCCESS_EVIDENCE_INVALID")
        if target == "broker":
            broker_stack_arn = str(receipt["stack_arn"])
        elif target == "broker-protection" and receipt["stack_arn"] != broker_stack_arn:
            _fail("CLEANUP_RETIRE_SUCCESS_EVIDENCE_INVALID")
        normalized[target] = json.loads(canonical_json(dict(receipt)))
        read_times[target] = read_at
    if not read_times["broker"] <= read_times["broker-protection"]:
        _fail("CLEANUP_RETIRE_SUCCESS_EVIDENCE_INVALID")
    return normalized


def materialize_bridge_cleanup_retire(
    *,
    bootstrap_intent: Mapping[str, Any],
    bridge_revoke_readback: Mapping[str, Any],
    bridge_template: bytes,
    mode: str,
    evaluated_at: datetime,
    bootstrap_route_release: Mapping[str, Any] | None = None,
    seed_intent: Mapping[str, Any] | None = None,
    terminal_readbacks: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Materialize the only UPDATE that retires bridge-owned cleanup access.

    ``SUCCESS`` is available only after all three initial route terminal
    readbacks prove the successful unprotected-create/protection sequence.
    ``EXPIRED`` is available only at or after the sealed CleanupNotAfter outer
    guard, when all recovery/cleanup permissions are already inert.
    """

    bootstrap = validate_bootstrap_intent(bootstrap_intent)
    revoke = validate_stack_readback(
        bridge_revoke_readback,
        bootstrap_intent=bootstrap,
        operation="bridge-revoke",
    )
    if evaluated_at.tzinfo is None or evaluated_at.utcoffset() is None:
        _fail("CLEANUP_RETIRE_CLOCK_INVALID")
    evaluated = evaluated_at.astimezone(timezone.utc).replace(microsecond=0)
    cleanup_not_after = _parse_time(
        bootstrap["cleanup_not_after"], "CLEANUP_RETIRE_WINDOW_INVALID"
    )
    if (
        not isinstance(bridge_template, bytes)
        or not bridge_template
        or len(bridge_template) > 51_200
        or bytes_digest(bridge_template) != bootstrap["template_digests"]["bridge"]
        or b"TemplateURL:" in bridge_template
        or mode not in {"SUCCESS", "EXPIRED"}
    ):
        _fail("CLEANUP_RETIRE_INPUT_INVALID")

    evidence_digests: dict[str, str] | None
    terminal_revalidation_aws_calls: int
    seed_digest: str | None
    if mode == "SUCCESS":
        if (
            evaluated >= cleanup_not_after
            or bootstrap_route_release is None
            or seed_intent is None
            or terminal_readbacks is None
        ):
            _fail("CLEANUP_RETIRE_SUCCESS_EVIDENCE_INVALID")
        terminals = _validate_cleanup_terminal_readbacks(
            bootstrap=bootstrap,
            bootstrap_route_release=bootstrap_route_release,
            seed_intent=seed_intent,
            terminal_readbacks=terminal_readbacks,
            evaluated_at=evaluated,
        )
        try:
            from tooling import platform_authority_plan_permission_repair_deployment_route as route

            seed = route.validate_seed_intent(seed_intent)
        except (ImportError, AttributeError, TypeError, ValueError, RuntimeError) as exc:
            raise ArtifactBootstrapError("CLEANUP_RETIRE_SUCCESS_EVIDENCE_INVALID") from exc
        seed_digest = str(seed["intent_digest"])
        release_digest: str | None = str(
            validate_route_release(
                bootstrap_route_release,
                bootstrap_intent=bootstrap,
                now=evaluated,
            )["release_digest"]
        )
        evidence_digests = {
            target: terminals[target]["readback_digest"]
            for target in ("route", "broker", "broker-protection")
        }
        terminal_revalidation_aws_calls = sum(
            terminals[target]["aws_calls"]
            for target in ("route", "broker", "broker-protection")
        )
    else:
        if (
            evaluated < cleanup_not_after
            or bootstrap_route_release is not None
            or seed_intent is not None
            or terminal_readbacks is not None
        ):
            _fail("CLEANUP_RETIRE_EXPIRED_EVIDENCE_INVALID")
        seed_digest = None
        release_digest = None
        evidence_digests = None
        terminal_revalidation_aws_calls = 0

    revoke_parameters = {
        item["ParameterKey"]: item["ParameterValue"]
        for item in bootstrap["requests"]["bridge-revoke"]["Parameters"]
    }
    request = _normalize_request(
        _stack_request(
            stack_name=BRIDGE_STACK_NAME,
            change_set_name=CLEANUP_RETIRE_CHANGE_SET_NAME,
            change_set_type="UPDATE",
            template_body=bridge_template.decode("utf-8"),
            parameters={
                **revoke_parameters,
                "AssignmentEnabled": "false",
                "CleanupAssignmentsEnabled": "false",
            },
            token_seed={
                "source_commit": bootstrap["source_commit"],
                "mode": mode,
                "bridge_revoke_readback_digest": revoke["readback_digest"],
                "bootstrap_route_release_digest": release_digest,
                "seed_intent_digest": seed_digest,
                "terminal_readback_digests": evidence_digests,
            },
        )
    )
    record: dict[str, Any] = {
        "schema_version": 1,
        "record_type": BRIDGE_CLEANUP_RETIRE_TYPE,
        "source_commit": bootstrap["source_commit"],
        "bootstrap_intent_digest": bootstrap["intent_digest"],
        "bridge_revoke_readback_digest": revoke["readback_digest"],
        "mode": mode,
        "bootstrap_route_release_digest": release_digest,
        "seed_intent_digest": seed_digest,
        "terminal_readback_digests": evidence_digests,
        "terminal_revalidation_aws_calls": terminal_revalidation_aws_calls,
        "cleanup_not_after": bootstrap["cleanup_not_after"],
        "evaluated_at": evaluated.isoformat().replace("+00:00", "Z"),
        "request": request,
        "request_digest": digest_value(request),
        "aws_calls": 0,
        "aws_mutations": 0,
        "production_authorized": False,
        "production_status": PRODUCTION_STATUS,
    }
    return _seal(record, "intent_digest")


def validate_bridge_cleanup_retire(
    value: Mapping[str, Any],
    *,
    bootstrap_intent: Mapping[str, Any],
    bridge_revoke_readback: Mapping[str, Any],
    bootstrap_route_release: Mapping[str, Any] | None = None,
    seed_intent: Mapping[str, Any] | None = None,
    terminal_readbacks: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    bootstrap = validate_bootstrap_intent(bootstrap_intent)
    expected = {
        "schema_version",
        "record_type",
        "source_commit",
        "bootstrap_intent_digest",
        "bridge_revoke_readback_digest",
        "mode",
        "bootstrap_route_release_digest",
        "seed_intent_digest",
        "terminal_readback_digests",
        "terminal_revalidation_aws_calls",
        "cleanup_not_after",
        "evaluated_at",
        "request",
        "request_digest",
        "aws_calls",
        "aws_mutations",
        "production_authorized",
        "production_status",
        "intent_digest",
    }
    if not isinstance(value, Mapping) or set(value) != expected:
        _fail("CLEANUP_RETIRE_INVALID")
    _verify(value, "intent_digest", "CLEANUP_RETIRE_DIGEST_INVALID")
    body = value.get("request", {}).get("TemplateBody") if isinstance(value.get("request"), Mapping) else None
    if not isinstance(body, str):
        _fail("CLEANUP_RETIRE_INVALID")
    evaluated = _parse_time(value.get("evaluated_at"), "CLEANUP_RETIRE_INVALID")
    expected_value = materialize_bridge_cleanup_retire(
        bootstrap_intent=bootstrap,
        bridge_revoke_readback=bridge_revoke_readback,
        bridge_template=body.encode("utf-8"),
        mode=str(value.get("mode", "")),
        evaluated_at=evaluated,
        bootstrap_route_release=bootstrap_route_release,
        seed_intent=seed_intent,
        terminal_readbacks=terminal_readbacks,
    )
    if dict(value) != expected_value:
        _fail("CLEANUP_RETIRE_REQUEST_RECONSTRUCTION_MISMATCH")
    return json.loads(canonical_json(dict(value)))


def materialize_bridge_cleanup_retire_authorization(
    *,
    cleanup_retire: Mapping[str, Any],
    operation: str,
    authorization: str,
    authorized_at: datetime,
    expires_at: datetime,
) -> dict[str, Any]:
    if operation not in {"dispatch", "execute"} or not isinstance(cleanup_retire, Mapping):
        _fail("CLEANUP_RETIRE_AUTHORIZATION_INVALID")
    intent_digest = cleanup_retire.get("intent_digest")
    request_digest = cleanup_retire.get("request_digest")
    if _DIGEST.fullmatch(str(intent_digest)) is None or _DIGEST.fullmatch(str(request_digest)) is None:
        _fail("CLEANUP_RETIRE_AUTHORIZATION_INVALID")
    if (
        authorized_at.tzinfo is None
        or authorized_at.utcoffset() is None
        or expires_at.tzinfo is None
        or expires_at.utcoffset() is None
    ):
        _fail("CLEANUP_RETIRE_AUTHORIZATION_CLOCK_INVALID")
    start = authorized_at.astimezone(timezone.utc).replace(microsecond=0)
    end = expires_at.astimezone(timezone.utc).replace(microsecond=0)
    expected_phrase = f"AUTHORIZE GUG-376 bridge-cleanup-retire:{operation} {intent_digest}"
    if authorization != expected_phrase or not start < end or (end - start).total_seconds() > 900:
        _fail("CLEANUP_RETIRE_AUTHORIZATION_INVALID")
    mode = cleanup_retire.get("mode")
    cleanup_end = _parse_time(cleanup_retire.get("cleanup_not_after"), "CLEANUP_RETIRE_AUTHORIZATION_INVALID")
    if (mode == "SUCCESS" and end > cleanup_end) or (mode == "EXPIRED" and start < cleanup_end):
        _fail("CLEANUP_RETIRE_AUTHORIZATION_INVALID")
    record: dict[str, Any] = {
        "schema_version": 1,
        "record_type": BRIDGE_CLEANUP_RETIRE_AUTHORIZATION_TYPE,
        "source_commit": cleanup_retire.get("source_commit"),
        "operation": operation,
        "cleanup_retire_intent_digest": intent_digest,
        "request_digest": request_digest,
        "mode": mode,
        "authorization": authorization,
        "authorized_at": start.isoformat().replace("+00:00", "Z"),
        "expires_at": end.isoformat().replace("+00:00", "Z"),
        "production_authorized": False,
    }
    return _seal(record, "authorization_digest")


def validate_bridge_cleanup_retire_authorization(
    value: Mapping[str, Any],
    *,
    cleanup_retire: Mapping[str, Any],
    operation: str,
    now: datetime,
) -> dict[str, Any]:
    expected = {
        "schema_version",
        "record_type",
        "source_commit",
        "operation",
        "cleanup_retire_intent_digest",
        "request_digest",
        "mode",
        "authorization",
        "authorized_at",
        "expires_at",
        "production_authorized",
        "authorization_digest",
    }
    if not isinstance(value, Mapping) or set(value) != expected:
        _fail("CLEANUP_RETIRE_AUTHORIZATION_INVALID")
    _verify(value, "authorization_digest", "CLEANUP_RETIRE_AUTHORIZATION_INVALID")
    if now.tzinfo is None or now.utcoffset() is None:
        _fail("CLEANUP_RETIRE_AUTHORIZATION_CLOCK_INVALID")
    current = now.astimezone(timezone.utc).replace(microsecond=0)
    authorized = _parse_time(value.get("authorized_at"), "CLEANUP_RETIRE_AUTHORIZATION_INVALID")
    expires = _parse_time(value.get("expires_at"), "CLEANUP_RETIRE_AUTHORIZATION_INVALID")
    expected_phrase = f"AUTHORIZE GUG-376 bridge-cleanup-retire:{operation} {cleanup_retire.get('intent_digest')}"
    cleanup_end = _parse_time(cleanup_retire.get("cleanup_not_after"), "CLEANUP_RETIRE_AUTHORIZATION_INVALID")
    if (
        operation not in {"dispatch", "execute"}
        or value.get("schema_version") != 1
        or value.get("record_type") != BRIDGE_CLEANUP_RETIRE_AUTHORIZATION_TYPE
        or value.get("source_commit") != cleanup_retire.get("source_commit")
        or value.get("operation") != operation
        or value.get("cleanup_retire_intent_digest") != cleanup_retire.get("intent_digest")
        or value.get("request_digest") != cleanup_retire.get("request_digest")
        or value.get("mode") != cleanup_retire.get("mode")
        or value.get("authorization") != expected_phrase
        or value.get("production_authorized") is not False
        or not authorized <= current < expires
        or not authorized < expires
        or (expires - authorized).total_seconds() > 900
        or (value.get("mode") == "SUCCESS" and expires > cleanup_end)
        or (value.get("mode") == "EXPIRED" and authorized < cleanup_end)
    ):
        _fail("CLEANUP_RETIRE_AUTHORIZATION_INVALID")
    return json.loads(canonical_json(dict(value)))


def validate_foundation_readback(
    value: Mapping[str, Any], *, bootstrap_intent: Mapping[str, Any]
) -> dict[str, Any]:
    """Validate the sealed provider receipt that binds the dynamic KMS ARN."""

    bootstrap = validate_bootstrap_intent(bootstrap_intent)
    expected = {
        "schema_version",
        "record_type",
        "source_commit",
        "bootstrap_intent_digest",
        "verifier",
        "artifact_bucket",
        "artifact_kms_key_arn",
        "artifact_kms_alias",
        "signing_profile_name",
        "signing_profile_version_arn",
        "code_signing_config_arn",
        "source_marker",
        "read_at",
        "aws_calls",
        "aws_mutations",
        "production_authorized",
        "production_status",
        "readback_digest",
    }
    if not isinstance(value, Mapping) or set(value) != expected:
        _fail("FOUNDATION_READBACK_INVALID")
    _verify(value, "readback_digest", "FOUNDATION_READBACK_DIGEST_INVALID")
    verifier = value.get("verifier")
    if (
        value.get("schema_version") != 1
        or value.get("record_type") != FOUNDATION_READBACK_TYPE
        or value.get("source_commit") != bootstrap["source_commit"]
        or value.get("bootstrap_intent_digest") != bootstrap["intent_digest"]
        or not isinstance(verifier, Mapping)
        or verifier.get("account_id") != AUTHORITY_ACCOUNT_ID
        or verifier.get("profile") != AUTHORITY_PROFILE
        or verifier.get("region") != REGION
        or re.fullmatch(
            r"arn:aws:sts::042360977644:assumed-role/"
            r"AWSReservedSSO_ScanalyzeGug376ArtifactBootstrap_[0-9A-Fa-f]{16}/"
            r"[A-Za-z0-9+=,.@_-]{1,64}",
            str(verifier.get("caller_arn", "")),
        )
        is None
        or value.get("artifact_bucket") != bootstrap["names"]["artifact_bucket"]
        or value.get("artifact_kms_alias")
        != bootstrap["names"]["artifact_kms_alias"]
        or value.get("signing_profile_name")
        != bootstrap["names"]["signing_profile_name"]
        or re.fullmatch(
            r"arn:aws:kms:us-east-1:042360977644:key/[A-Za-z0-9-]{1,128}",
            str(value.get("artifact_kms_key_arn", "")),
        )
        is None
        or re.fullmatch(
            r"arn:aws:signer:us-east-1:042360977644:/signing-profiles/"
            + re.escape(bootstrap["names"]["signing_profile_name"])
            + r"/[A-Za-z0-9]{10}",
            str(value.get("signing_profile_version_arn", "")),
        )
        is None
        or re.fullmatch(
            r"arn:aws:lambda:us-east-1:042360977644:code-signing-config:"
            r"csc-[A-Za-z0-9]{17}",
            str(value.get("code_signing_config_arn", "")),
        )
        is None
        or value.get("source_marker")
        != "AWS_STS_KMS_S3_SIGNER_LAMBDA_EXACT_READBACK"
        or type(value.get("aws_calls")) is not int
        or value["aws_calls"] < 13
        or value.get("aws_mutations") != 0
        or value.get("production_authorized") is not False
        or value.get("production_status") != PRODUCTION_STATUS
    ):
        _fail("FOUNDATION_READBACK_INVALID")
    _validate_window_timestamp(
        value.get("read_at"),
        bootstrap=bootstrap,
        read_only=True,
        code="FOUNDATION_READBACK_INVALID",
    )
    return json.loads(canonical_json(dict(value)))


def materialize_object_intent(
    *,
    bootstrap_intent: Mapping[str, Any],
    foundation_readback: Mapping[str, Any],
    key: str,
    body: bytes,
    content_type: str,
    mutation_nonce: str,
) -> dict[str, Any]:
    """Create a body-free, exact immutable S3 PutObject contract."""

    intent = validate_bootstrap_intent(bootstrap_intent)
    foundation = validate_foundation_readback(
        foundation_readback, bootstrap_intent=intent
    )
    kms_key_arn = foundation["artifact_kms_key_arn"]
    if (
        not isinstance(key, str)
        or _KEY.fullmatch(key) is None
        or intent["source_commit"] not in key
        or not isinstance(body, bytes)
        or not 0 < len(body) <= 16 * 1024 * 1024
        or content_type not in {"application/zip", "text/yaml"}
        or re.fullmatch(r"[a-f0-9]{64}", mutation_nonce) is None
        or re.fullmatch(
            r"arn:aws:kms:us-east-1:042360977644:key/[A-Za-z0-9-]{1,128}",
            kms_key_arn,
        )
        is None
    ):
        _fail("OBJECT_INPUT_INVALID")
    digest = sha256(body).digest()
    object_sha256 = "sha256:" + digest.hex()
    effect_digest = digest_value(
        {
            "bootstrap_intent_digest": intent["intent_digest"],
            "foundation_readback_digest": foundation["readback_digest"],
            "bucket": intent["names"]["artifact_bucket"],
            "key": key,
            "content_length": len(body),
            "content_type": content_type,
            "object_sha256": object_sha256,
            "sse_kms_key_arn": kms_key_arn,
            "mutation_nonce": mutation_nonce,
        }
    )
    causal_claim_digest = digest_value(
        {
            "operation": "publish-object",
            "effect_digest": effect_digest,
            "mutation_nonce": mutation_nonce,
        }
    )
    tags = {
        "managed_by": "gug376-artifact-bootstrap",
        "service": "scanalyze-platform-authority",
        "work_package": "GUG-376",
        "source_commit": intent["source_commit"],
        "mutation_nonce": mutation_nonce,
        "effect_digest": effect_digest,
        "causal_claim_digest": causal_claim_digest,
    }
    request = {
        "Bucket": intent["names"]["artifact_bucket"],
        "Key": key,
        "ContentLength": len(body),
        "ContentType": content_type,
        "ChecksumAlgorithm": "SHA256",
        "ChecksumSHA256": base64.b64encode(digest).decode("ascii"),
        "ServerSideEncryption": "aws:kms",
        "SSEKMSKeyId": kms_key_arn,
        "BucketKeyEnabled": True,
        "Metadata": {
            "source-commit": intent["source_commit"],
            "mutation-nonce": mutation_nonce,
            "effect-digest": effect_digest,
            "causal-claim-digest": causal_claim_digest,
            "object-sha256": object_sha256,
            "kms-key-arn": kms_key_arn,
            "artifact-key": key,
        },
        "Tagging": urlencode(tags),
        "IfNoneMatch": "*",
    }
    record: dict[str, Any] = {
        "schema_version": 1,
        "record_type": OBJECT_INTENT_TYPE,
        "source_commit": intent["source_commit"],
        "bootstrap_intent_digest": intent["intent_digest"],
        "foundation_readback_digest": foundation["readback_digest"],
        "object_sha256": object_sha256,
        "mutation_nonce": mutation_nonce,
        "effect_digest": effect_digest,
        "causal_claim_digest": causal_claim_digest,
        "request": request,
        "request_digest": digest_value(request),
        "aws_calls": 0,
        "aws_mutations": 0,
        "production_authorized": False,
        "production_status": PRODUCTION_STATUS,
    }
    return _seal(record, "intent_digest")


def validate_object_intent(
    value: Mapping[str, Any], *, bootstrap_intent: Mapping[str, Any],
    foundation_readback: Mapping[str, Any]
) -> dict[str, Any]:
    bootstrap = validate_bootstrap_intent(bootstrap_intent)
    foundation = validate_foundation_readback(
        foundation_readback, bootstrap_intent=bootstrap
    )
    expected_fields = {
        "schema_version",
        "record_type",
        "source_commit",
        "bootstrap_intent_digest",
        "foundation_readback_digest",
        "object_sha256",
        "mutation_nonce",
        "effect_digest",
        "causal_claim_digest",
        "request",
        "request_digest",
        "aws_calls",
        "aws_mutations",
        "production_authorized",
        "production_status",
        "intent_digest",
    }
    if not isinstance(value, Mapping) or set(value) != expected_fields:
        _fail("OBJECT_INTENT_INVALID")
    _verify(value, "intent_digest", "OBJECT_INTENT_DIGEST_INVALID")
    request = value.get("request")
    request_fields = {
        "Bucket",
        "Key",
        "ContentLength",
        "ContentType",
        "ChecksumAlgorithm",
        "ChecksumSHA256",
        "ServerSideEncryption",
        "SSEKMSKeyId",
        "BucketKeyEnabled",
        "Metadata",
        "Tagging",
        "IfNoneMatch",
    }
    expected_tags = {
        "managed_by": "gug376-artifact-bootstrap",
        "service": "scanalyze-platform-authority",
        "work_package": "GUG-376",
        "source_commit": bootstrap["source_commit"],
        "mutation_nonce": value.get("mutation_nonce"),
        "effect_digest": value.get("effect_digest"),
        "causal_claim_digest": value.get("causal_claim_digest"),
    }
    expected_tagging = urlencode(expected_tags)
    checksum = request.get("ChecksumSHA256") if isinstance(request, Mapping) else None
    try:
        checksum_hex = base64.b64decode(str(checksum), validate=True).hex()
    except (ValueError, TypeError):
        checksum_hex = ""
    if (
        value.get("schema_version") != 1
        or value.get("record_type") != OBJECT_INTENT_TYPE
        or value.get("source_commit") != bootstrap["source_commit"]
        or value.get("bootstrap_intent_digest") != bootstrap["intent_digest"]
        or value.get("foundation_readback_digest")
        != foundation["readback_digest"]
        or not isinstance(request, Mapping)
        or set(request) != request_fields
        or request.get("Bucket") != bootstrap["names"]["artifact_bucket"]
        or _KEY.fullmatch(str(request.get("Key", ""))) is None
        or bootstrap["source_commit"] not in str(request.get("Key"))
        or request.get("IfNoneMatch") != "*"
        or request.get("ServerSideEncryption") != "aws:kms"
        or request.get("ChecksumAlgorithm") != "SHA256"
        or request.get("BucketKeyEnabled") is not True
        or re.fullmatch(r"[a-f0-9]{64}", str(value.get("mutation_nonce", "")))
        is None
        or _DIGEST.fullmatch(str(value.get("effect_digest", ""))) is None
        or _DIGEST.fullmatch(str(value.get("causal_claim_digest", ""))) is None
        or request.get("Tagging") != expected_tagging
        or request.get("ContentType") not in {"application/zip", "text/yaml"}
        or type(request.get("ContentLength")) is not int
        or not 0 < request["ContentLength"] <= 16 * 1024 * 1024
        or re.fullmatch(
            r"arn:aws:kms:us-east-1:042360977644:key/[A-Za-z0-9-]{1,128}",
            str(request.get("SSEKMSKeyId", "")),
        )
        is None
        or request.get("SSEKMSKeyId") != foundation["artifact_kms_key_arn"]
        or checksum_hex != str(value.get("object_sha256", "")).removeprefix("sha256:")
        or value.get("request_digest") != digest_value(request)
        or _DIGEST.fullmatch(str(value.get("object_sha256", ""))) is None
        or value.get("aws_calls") != 0
        or value.get("aws_mutations") != 0
        or value.get("production_authorized") is not False
        or value.get("production_status") != PRODUCTION_STATUS
    ):
        _fail("OBJECT_INTENT_INVALID")
    expected_effect_digest = digest_value(
        {
            "bootstrap_intent_digest": bootstrap["intent_digest"],
            "foundation_readback_digest": foundation["readback_digest"],
            "bucket": bootstrap["names"]["artifact_bucket"],
            "key": request["Key"],
            "content_length": request["ContentLength"],
            "content_type": request["ContentType"],
            "object_sha256": value["object_sha256"],
            "sse_kms_key_arn": foundation["artifact_kms_key_arn"],
            "mutation_nonce": value["mutation_nonce"],
        }
    )
    expected_claim_digest = digest_value(
        {
            "operation": "publish-object",
            "effect_digest": expected_effect_digest,
            "mutation_nonce": value["mutation_nonce"],
        }
    )
    expected_metadata = {
        "source-commit": bootstrap["source_commit"],
        "mutation-nonce": value["mutation_nonce"],
        "effect-digest": expected_effect_digest,
        "causal-claim-digest": expected_claim_digest,
        "object-sha256": value["object_sha256"],
        "kms-key-arn": foundation["artifact_kms_key_arn"],
        "artifact-key": request["Key"],
    }
    if (
        value["effect_digest"] != expected_effect_digest
        or value["causal_claim_digest"] != expected_claim_digest
        or request.get("Metadata") != expected_metadata
    ):
        _fail("OBJECT_INTENT_CAUSAL_BINDING_INVALID")
    expected_request = {
        "Bucket": bootstrap["names"]["artifact_bucket"],
        "Key": request["Key"],
        "ContentLength": request["ContentLength"],
        "ContentType": request["ContentType"],
        "ChecksumAlgorithm": "SHA256",
        "ChecksumSHA256": base64.b64encode(
            bytes.fromhex(value["object_sha256"].removeprefix("sha256:"))
        ).decode("ascii"),
        "ServerSideEncryption": "aws:kms",
        "SSEKMSKeyId": foundation["artifact_kms_key_arn"],
        "BucketKeyEnabled": True,
        "Metadata": expected_metadata,
        "Tagging": expected_tagging,
        "IfNoneMatch": "*",
    }
    if request != expected_request:
        _fail("OBJECT_INTENT_REQUEST_RECONSTRUCTION_MISMATCH")
    return json.loads(canonical_json(dict(value)))


def validate_object_receipt(
    value: Mapping[str, Any], *, bootstrap_intent: Mapping[str, Any],
    foundation_readback: Mapping[str, Any]
) -> dict[str, Any]:
    bootstrap = validate_bootstrap_intent(bootstrap_intent)
    foundation = validate_foundation_readback(
        foundation_readback, bootstrap_intent=bootstrap
    )
    expected_fields = {
        "schema_version",
        "record_type",
        "source_commit",
        "bootstrap_intent_digest",
        "foundation_readback_digest",
        "object_intent_digest",
        "dispatch_receipt_digest",
        "effect_digest",
        "mutation_nonce",
        "causal_claim_digest",
        "verifier",
        "bucket",
        "key",
        "version",
        "object_sha256",
        "checksum_sha256",
        "content_length",
        "content_type",
        "sse_algorithm",
        "sse_kms_key_arn",
        "bucket_key_enabled",
        "metadata",
        "tags",
        "source_marker",
        "read_at",
        "aws_calls",
        "aws_mutations",
        "production_authorized",
        "production_status",
        "receipt_digest",
    }
    if not isinstance(value, Mapping) or set(value) != expected_fields:
        _fail("OBJECT_RECEIPT_INVALID")
    _verify(value, "receipt_digest", "OBJECT_RECEIPT_DIGEST_INVALID")
    verifier = value.get("verifier")
    if (
        value.get("schema_version") != 1
        or value.get("record_type") != OBJECT_RECEIPT_TYPE
        or value.get("source_commit") != bootstrap["source_commit"]
        or value.get("bootstrap_intent_digest") != bootstrap["intent_digest"]
        or value.get("foundation_readback_digest")
        != foundation["readback_digest"]
        or _DIGEST.fullmatch(str(value.get("object_intent_digest", ""))) is None
        or _DIGEST.fullmatch(str(value.get("dispatch_receipt_digest", ""))) is None
        or _DIGEST.fullmatch(str(value.get("effect_digest", ""))) is None
        or re.fullmatch(r"[a-f0-9]{64}", str(value.get("mutation_nonce", "")))
        is None
        or _DIGEST.fullmatch(str(value.get("causal_claim_digest", ""))) is None
        or not isinstance(verifier, Mapping)
        or set(verifier) != {"account_id", "caller_arn", "profile", "region"}
        or verifier.get("account_id") != AUTHORITY_ACCOUNT_ID
        or verifier.get("profile") != AUTHORITY_PROFILE
        or verifier.get("region") != REGION
        or re.fullmatch(
            r"arn:aws:sts::042360977644:assumed-role/"
            r"AWSReservedSSO_ScanalyzeGug376ArtifactBootstrap_[0-9A-Fa-f]{16}/"
            r"[A-Za-z0-9+=,.@_-]{1,64}",
            str(verifier.get("caller_arn", "")),
        )
        is None
        or value.get("sse_kms_key_arn") != foundation["artifact_kms_key_arn"]
        or value.get("bucket") != bootstrap["names"]["artifact_bucket"]
        or _KEY.fullmatch(str(value.get("key", ""))) is None
        or bootstrap["source_commit"] not in str(value.get("key"))
        or _VERSION.fullmatch(str(value.get("version", ""))) is None
        or str(value.get("version", "")).casefold() == "null"
        or _DIGEST.fullmatch(str(value.get("object_sha256", ""))) is None
        or value.get("checksum_sha256")
        != base64.b64encode(
            bytes.fromhex(str(value["object_sha256"]).removeprefix("sha256:"))
        ).decode("ascii")
        or type(value.get("content_length")) is not int
        or not 0 < value["content_length"] <= 16 * 1024 * 1024
        or value.get("content_type") not in {"application/zip", "text/yaml"}
        or value.get("sse_algorithm") != "aws:kms"
        or re.fullmatch(
            r"arn:aws:kms:us-east-1:042360977644:key/[A-Za-z0-9-]{1,128}",
            str(value.get("sse_kms_key_arn", "")),
        )
        is None
        or value.get("bucket_key_enabled") is not True
        or value.get("metadata")
        != {
            "source-commit": bootstrap["source_commit"],
            "mutation-nonce": value.get("mutation_nonce"),
            "effect-digest": value.get("effect_digest"),
            "causal-claim-digest": value.get("causal_claim_digest"),
            "object-sha256": value.get("object_sha256"),
            "kms-key-arn": value.get("sse_kms_key_arn"),
            "artifact-key": value.get("key"),
        }
        or value.get("tags")
        != {
            "managed_by": "gug376-artifact-bootstrap",
            "service": "scanalyze-platform-authority",
            "work_package": "GUG-376",
            "source_commit": bootstrap["source_commit"],
            "mutation_nonce": value.get("mutation_nonce"),
            "effect_digest": value.get("effect_digest"),
            "causal_claim_digest": value.get("causal_claim_digest"),
        }
        or value.get("source_marker")
        != "AWS_STS_S3_VERSIONED_SSE_KMS_OBJECT_READBACK"
        or type(value.get("aws_calls")) is not int
        or value["aws_calls"] < 6
        or value.get("aws_mutations") != 0
        or value.get("production_authorized") is not False
        or value.get("production_status") != PRODUCTION_STATUS
    ):
        _fail("OBJECT_RECEIPT_INVALID")
    expected_effect = digest_value(
        {
            "bootstrap_intent_digest": bootstrap["intent_digest"],
            "foundation_readback_digest": foundation["readback_digest"],
            "bucket": value["bucket"],
            "key": value["key"],
            "content_length": value["content_length"],
            "content_type": value["content_type"],
            "object_sha256": value["object_sha256"],
            "sse_kms_key_arn": value["sse_kms_key_arn"],
            "mutation_nonce": value["mutation_nonce"],
        }
    )
    expected_claim = digest_value(
        {
            "operation": "publish-object",
            "effect_digest": expected_effect,
            "mutation_nonce": value["mutation_nonce"],
        }
    )
    if (
        value["effect_digest"] != expected_effect
        or value["causal_claim_digest"] != expected_claim
    ):
        _fail("OBJECT_RECEIPT_CAUSAL_BINDING_INVALID")
    _validate_window_timestamp(
        value.get("read_at"),
        bootstrap=bootstrap,
        read_only=True,
        code="OBJECT_RECEIPT_INVALID",
    )
    return json.loads(canonical_json(dict(value)))


def seal_reviewed_sources(
    *,
    bootstrap_intent: Mapping[str, Any],
    bridge_template: bytes,
    foundation_template: bytes,
    route_template: bytes,
    delegation_template: bytes,
) -> dict[str, Any]:
    """Seal exact Git object bytes after the local runner proves clean HEAD.

    This is deliberately a byte-only primitive.  Connected callers must use
    ``attest_clean_reviewed_sources`` in the companion runner, which proves a
    clean exact Git checkout before calling this function.
    """

    bootstrap = validate_bootstrap_intent(bootstrap_intent)
    if any(
        not isinstance(body, bytes) or not 0 < len(body) <= 4 * 1024 * 1024
        for body in (
            bridge_template,
            foundation_template,
            route_template,
            delegation_template,
        )
    ):
        _fail("REVIEWED_SOURCE_BYTES_INVALID")
    record: dict[str, Any] = {
        "schema_version": 1,
        "record_type": REVIEWED_SOURCES_TYPE,
        "source_commit": bootstrap["source_commit"],
        "bootstrap_intent_digest": bootstrap["intent_digest"],
        "git_branch": "main",
        "git_head": bootstrap["source_commit"],
        "origin_main": bootstrap["source_commit"],
        "git_status_clean": True,
        "sources": {
            "bridge_template": {
                "path": BRIDGE_TEMPLATE_PATH,
                "sha256": bytes_digest(bridge_template),
                "bytes": len(bridge_template),
            },
            "foundation_template": {
                "path": FOUNDATION_TEMPLATE_PATH,
                "sha256": bytes_digest(foundation_template),
                "bytes": len(foundation_template),
            },
            "route_template": {
                "path": ROUTE_TEMPLATE_SOURCE_PATH,
                "sha256": bytes_digest(route_template),
                "bytes": len(route_template),
            },
            "delegation_template": {
                "path": DELEGATION_TEMPLATE_SOURCE_PATH,
                "sha256": bytes_digest(delegation_template),
                "bytes": len(delegation_template),
            },
        },
        "source_marker": "CLEAN_EXACT_MAIN_GIT_OBJECTS",
        "aws_calls": 0,
        "aws_mutations": 0,
        "production_authorized": False,
        "production_status": PRODUCTION_STATUS,
    }
    return _seal(record, "attestation_digest")


def validate_reviewed_sources(
    value: Mapping[str, Any], *, bootstrap_intent: Mapping[str, Any]
) -> dict[str, Any]:
    bootstrap = validate_bootstrap_intent(bootstrap_intent)
    expected = {
        "schema_version",
        "record_type",
        "source_commit",
        "bootstrap_intent_digest",
        "git_branch",
        "git_head",
        "origin_main",
        "git_status_clean",
        "sources",
        "source_marker",
        "aws_calls",
        "aws_mutations",
        "production_authorized",
        "production_status",
        "attestation_digest",
    }
    if not isinstance(value, Mapping) or set(value) != expected:
        _fail("REVIEWED_SOURCES_INVALID")
    _verify(value, "attestation_digest", "REVIEWED_SOURCES_DIGEST_INVALID")
    sources = value.get("sources")
    if not isinstance(sources, Mapping) or set(sources) != {
        "bridge_template",
        "foundation_template",
        "route_template",
        "delegation_template",
    }:
        _fail("REVIEWED_SOURCES_INVALID")
    for name, path in (
        ("bridge_template", BRIDGE_TEMPLATE_PATH),
        ("foundation_template", FOUNDATION_TEMPLATE_PATH),
        ("route_template", ROUTE_TEMPLATE_SOURCE_PATH),
        ("delegation_template", DELEGATION_TEMPLATE_SOURCE_PATH),
    ):
        item = sources.get(name)
        if (
            not isinstance(item, Mapping)
            or set(item) != {"path", "sha256", "bytes"}
            or item.get("path") != path
            or _DIGEST.fullmatch(str(item.get("sha256", ""))) is None
            or type(item.get("bytes")) is not int
            or not 0 < item["bytes"] <= 4 * 1024 * 1024
        ):
            _fail("REVIEWED_SOURCES_INVALID")
    if (
        value.get("schema_version") != 1
        or value.get("record_type") != REVIEWED_SOURCES_TYPE
        or value.get("source_commit") != bootstrap["source_commit"]
        or value.get("bootstrap_intent_digest") != bootstrap["intent_digest"]
        or value.get("git_branch") != "main"
        or value.get("git_head") != bootstrap["source_commit"]
        or value.get("origin_main") != bootstrap["source_commit"]
        or value.get("git_status_clean") is not True
        or sources["bridge_template"]["sha256"]
        != bootstrap["template_digests"]["bridge"]
        or sources["foundation_template"]["sha256"]
        != bootstrap["template_digests"]["foundation"]
        or value.get("source_marker") != "CLEAN_EXACT_MAIN_GIT_OBJECTS"
        or value.get("aws_calls") != 0
        or value.get("aws_mutations") != 0
        or value.get("production_authorized") is not False
        or value.get("production_status") != PRODUCTION_STATUS
    ):
        _fail("REVIEWED_SOURCES_INVALID")
    return json.loads(canonical_json(dict(value)))


def materialize_signing_intent(
    *,
    bootstrap_intent: Mapping[str, Any],
    foundation_readback: Mapping[str, Any],
    bridge_pin: Mapping[str, Any],
    bridge_pin_readback: Mapping[str, Any],
    unsigned_receipt: Mapping[str, Any],
    destination_prefix: str,
    profile_name: str,
) -> dict[str, Any]:
    bootstrap = validate_bootstrap_intent(bootstrap_intent)
    foundation = validate_foundation_readback(
        foundation_readback, bootstrap_intent=bootstrap
    )
    pin = validate_bridge_pin(
        bridge_pin,
        bootstrap_intent=bootstrap,
        foundation_readback=foundation,
    )
    pin_readback = validate_stack_readback(
        bridge_pin_readback,
        bootstrap_intent=bootstrap,
        operation="bridge-pin",
        bridge_pin=pin,
        foundation_readback=foundation,
    )
    try:
        unsigned = validate_object_receipt(
            unsigned_receipt,
            bootstrap_intent=bootstrap,
            foundation_readback=foundation_readback,
        )
    except ArtifactBootstrapError as exc:
        raise ArtifactBootstrapError("SIGNING_UNSIGNED_RECEIPT_INVALID") from exc
    if (
        profile_name != bootstrap["names"]["signing_profile_name"]
        or not destination_prefix.startswith(ARTIFACT_PREFIX)
        or not destination_prefix.endswith("/")
        or ".." in destination_prefix
    ):
        _fail("SIGNING_INPUT_INVALID")
    token_seed = {
        "source_commit": bootstrap["source_commit"],
        "unsigned_receipt_digest": unsigned["receipt_digest"],
        "sse_kms_key_arn": unsigned["sse_kms_key_arn"],
        "destination_prefix": destination_prefix,
        "profile_name": profile_name,
        "profile_version_arn": foundation["signing_profile_version_arn"],
    }
    request = {
        "source": {
            "s3": {
                "bucketName": unsigned["bucket"],
                "key": unsigned["key"],
                "version": unsigned["version"],
            }
        },
        "destination": {
            "s3": {
                "bucketName": unsigned["bucket"],
                "prefix": destination_prefix,
            }
        },
        "profileName": profile_name,
        "profileOwner": AUTHORITY_ACCOUNT_ID,
        "clientRequestToken": "gug376-" + digest_value(token_seed)[7:55],
    }
    record: dict[str, Any] = {
        "schema_version": 1,
        "record_type": SIGNING_INTENT_TYPE,
        "source_commit": bootstrap["source_commit"],
        "bootstrap_intent_digest": bootstrap["intent_digest"],
        "unsigned_receipt_digest": unsigned["receipt_digest"],
        "sse_kms_key_arn": unsigned["sse_kms_key_arn"],
        "foundation_readback_digest": foundation["readback_digest"],
        "bridge_pin_intent_digest": pin["intent_digest"],
        "bridge_pin_readback_digest": pin_readback["readback_digest"],
        "signing_profile_version_arn": foundation[
            "signing_profile_version_arn"
        ],
        "request": request,
        "request_digest": digest_value(request),
        "aws_calls": 0,
        "aws_mutations": 0,
        "production_authorized": False,
        "production_status": PRODUCTION_STATUS,
    }
    return _seal(record, "intent_digest")


def validate_signing_intent(
    value: Mapping[str, Any], *, bootstrap_intent: Mapping[str, Any],
    foundation_readback: Mapping[str, Any], bridge_pin: Mapping[str, Any],
    bridge_pin_readback: Mapping[str, Any], unsigned_receipt: Mapping[str, Any]
) -> dict[str, Any]:
    bootstrap = validate_bootstrap_intent(bootstrap_intent)
    foundation = validate_foundation_readback(
        foundation_readback, bootstrap_intent=bootstrap
    )
    pin = validate_bridge_pin(
        bridge_pin,
        bootstrap_intent=bootstrap,
        foundation_readback=foundation,
    )
    pin_readback = validate_stack_readback(
        bridge_pin_readback,
        bootstrap_intent=bootstrap,
        operation="bridge-pin",
        bridge_pin=pin,
        foundation_readback=foundation,
    )
    expected_fields = {
        "schema_version",
        "record_type",
        "source_commit",
        "bootstrap_intent_digest",
        "foundation_readback_digest",
        "bridge_pin_intent_digest",
        "bridge_pin_readback_digest",
        "unsigned_receipt_digest",
        "sse_kms_key_arn",
        "signing_profile_version_arn",
        "request",
        "request_digest",
        "aws_calls",
        "aws_mutations",
        "production_authorized",
        "production_status",
        "intent_digest",
    }
    if not isinstance(value, Mapping) or set(value) != expected_fields:
        _fail("SIGNING_INTENT_INVALID")
    _verify(value, "intent_digest", "SIGNING_INTENT_DIGEST_INVALID")
    request = value.get("request")
    try:
        source = request["source"]["s3"]
        destination = request["destination"]["s3"]
    except (KeyError, TypeError):
        _fail("SIGNING_INTENT_INVALID")
    if (
        value.get("schema_version") != 1
        or value.get("record_type") != SIGNING_INTENT_TYPE
        or value.get("source_commit") != bootstrap["source_commit"]
        or value.get("bootstrap_intent_digest") != bootstrap["intent_digest"]
        or value.get("foundation_readback_digest")
        != foundation["readback_digest"]
        or value.get("bridge_pin_intent_digest") != pin["intent_digest"]
        or value.get("bridge_pin_readback_digest") != pin_readback["readback_digest"]
        or value.get("signing_profile_version_arn")
        != foundation["signing_profile_version_arn"]
        or re.fullmatch(
            r"arn:aws:kms:us-east-1:042360977644:key/[A-Za-z0-9-]{1,128}",
            str(value.get("sse_kms_key_arn", "")),
        )
        is None
        or not isinstance(request, Mapping)
        or request.get("profileName")
        != bootstrap["names"]["signing_profile_name"]
        or request.get("profileOwner") != AUTHORITY_ACCOUNT_ID
        or source.get("bucketName") != bootstrap["names"]["artifact_bucket"]
        or destination.get("bucketName") != bootstrap["names"]["artifact_bucket"]
        or _KEY.fullmatch(str(source.get("key", ""))) is None
        or _VERSION.fullmatch(str(source.get("version", ""))) is None
        or not str(destination.get("prefix", "")).startswith(ARTIFACT_PREFIX)
        or not str(destination.get("prefix", "")).endswith("/")
        or value.get("request_digest") != digest_value(request)
        or value.get("production_authorized") is not False
        or value.get("production_status") != PRODUCTION_STATUS
        or value.get("aws_calls") != 0
        or value.get("aws_mutations") != 0
    ):
        _fail("SIGNING_INTENT_INVALID")
    expected = materialize_signing_intent(
        bootstrap_intent=bootstrap,
        foundation_readback=foundation,
        bridge_pin=pin,
        bridge_pin_readback=pin_readback,
        unsigned_receipt=unsigned_receipt,
        destination_prefix=str(destination.get("prefix", "")),
        profile_name=str(request.get("profileName", "")),
    )
    if dict(value) != expected:
        _fail("SIGNING_INTENT_REQUEST_RECONSTRUCTION_MISMATCH")
    return json.loads(canonical_json(dict(value)))


def materialize_bridge_pin(
    *,
    bootstrap_intent: Mapping[str, Any],
    foundation_readback: Mapping[str, Any],
    bridge_template: bytes,
) -> dict[str, Any]:
    """Pin Signer IAM authority to the exact foundation profile version."""

    bootstrap = validate_bootstrap_intent(bootstrap_intent)
    foundation = validate_foundation_readback(
        foundation_readback, bootstrap_intent=bootstrap
    )
    if (
        not isinstance(bridge_template, bytes)
        or not bridge_template
        or len(bridge_template) > 51_200
        or bytes_digest(bridge_template) != bootstrap["template_digests"]["bridge"]
        or b"TemplateURL:" in bridge_template
    ):
        _fail("BRIDGE_PIN_TEMPLATE_INVALID")
    profile_version = foundation["signing_profile_version_arn"].rsplit("/", 1)[-1]
    if re.fullmatch(r"[A-Za-z0-9]{10}", profile_version) is None:
        _fail("BRIDGE_PIN_PROFILE_VERSION_INVALID")
    create_parameters = {
        item["ParameterKey"]: item["ParameterValue"]
        for item in bootstrap["requests"]["bridge-create"]["Parameters"]
    }
    parameters = {
        **create_parameters,
        "AssignmentEnabled": "true",
        "SigningProfileVersion": profile_version,
    }
    request = _normalize_request(
        _stack_request(
            stack_name=BRIDGE_STACK_NAME,
            change_set_name="gug376-artifact-bootstrap-bridge-pin",
            change_set_type="UPDATE",
            template_body=bridge_template.decode("utf-8"),
            parameters=parameters,
            token_seed={
                "source_commit": bootstrap["source_commit"],
                "foundation_readback_digest": foundation["readback_digest"],
                "profile_version": profile_version,
            },
        )
    )
    record: dict[str, Any] = {
        "schema_version": 1,
        "record_type": BRIDGE_PIN_TYPE,
        "source_commit": bootstrap["source_commit"],
        "bootstrap_intent_digest": bootstrap["intent_digest"],
        "foundation_readback_digest": foundation["readback_digest"],
        "signing_profile_version_arn": foundation[
            "signing_profile_version_arn"
        ],
        "signing_profile_version": profile_version,
        "request": request,
        "request_digest": digest_value(request),
        "aws_calls": 0,
        "aws_mutations": 0,
        "production_authorized": False,
        "production_status": PRODUCTION_STATUS,
    }
    return _seal(record, "intent_digest")


def validate_bridge_pin(
    value: Mapping[str, Any], *, bootstrap_intent: Mapping[str, Any],
    foundation_readback: Mapping[str, Any]
) -> dict[str, Any]:
    bootstrap = validate_bootstrap_intent(bootstrap_intent)
    foundation = validate_foundation_readback(
        foundation_readback, bootstrap_intent=bootstrap
    )
    expected = {
        "schema_version",
        "record_type",
        "source_commit",
        "bootstrap_intent_digest",
        "foundation_readback_digest",
        "signing_profile_version_arn",
        "signing_profile_version",
        "request",
        "request_digest",
        "aws_calls",
        "aws_mutations",
        "production_authorized",
        "production_status",
        "intent_digest",
    }
    if not isinstance(value, Mapping) or set(value) != expected:
        _fail("BRIDGE_PIN_INVALID")
    _verify(value, "intent_digest", "BRIDGE_PIN_DIGEST_INVALID")
    request = value.get("request")
    parameters = (
        {
            item.get("ParameterKey"): item.get("ParameterValue")
            for item in request.get("Parameters", [])
            if isinstance(item, Mapping)
        }
        if isinstance(request, Mapping)
        else {}
    )
    profile_version = foundation["signing_profile_version_arn"].rsplit("/", 1)[-1]
    if (
        value.get("schema_version") != 1
        or value.get("record_type") != BRIDGE_PIN_TYPE
        or value.get("source_commit") != bootstrap["source_commit"]
        or value.get("bootstrap_intent_digest") != bootstrap["intent_digest"]
        or value.get("foundation_readback_digest") != foundation["readback_digest"]
        or value.get("signing_profile_version_arn")
        != foundation["signing_profile_version_arn"]
        or value.get("signing_profile_version") != profile_version
        or not isinstance(request, Mapping)
        or request.get("StackName") != BRIDGE_STACK_NAME
        or request.get("ChangeSetName") != "gug376-artifact-bootstrap-bridge-pin"
        or request.get("ChangeSetType") != "UPDATE"
        or "TemplateURL" in request
        or parameters.get("AssignmentEnabled") != "true"
        or parameters.get("CleanupAssignmentsEnabled") != "true"
        or parameters.get("CleanupNotAfter") != bootstrap["cleanup_not_after"]
        or parameters.get("SigningProfileVersion") != profile_version
        or value.get("request_digest") != digest_value(request)
        or value.get("aws_calls") != 0
        or value.get("aws_mutations") != 0
        or value.get("production_authorized") is not False
        or value.get("production_status") != PRODUCTION_STATUS
    ):
        _fail("BRIDGE_PIN_INVALID")
    body = request.get("TemplateBody") if isinstance(request, Mapping) else None
    if not isinstance(body, str):
        _fail("BRIDGE_PIN_INVALID")
    expected_value = materialize_bridge_pin(
        bootstrap_intent=bootstrap,
        foundation_readback=foundation,
        bridge_template=body.encode("utf-8"),
    )
    if dict(value) != expected_value:
        _fail("BRIDGE_PIN_REQUEST_RECONSTRUCTION_MISMATCH")
    return json.loads(canonical_json(dict(value)))


def materialize_foundation_access_update(
    *,
    bootstrap_intent: Mapping[str, Any],
    foundation_readback: Mapping[str, Any],
    route_template_receipt: Mapping[str, Any],
    delegation_template_receipt: Mapping[str, Any],
    reviewed_sources: Mapping[str, Any],
    foundation_template: bytes,
) -> dict[str, Any]:
    """Open only two exact cross-account version reads after publication."""

    bootstrap = validate_bootstrap_intent(bootstrap_intent)
    foundation = validate_foundation_readback(
        foundation_readback, bootstrap_intent=bootstrap
    )
    reviewed = validate_reviewed_sources(
        reviewed_sources, bootstrap_intent=bootstrap
    )
    try:
        route_receipt = validate_object_receipt(
            route_template_receipt,
            bootstrap_intent=bootstrap,
            foundation_readback=foundation,
        )
        delegation_receipt = validate_object_receipt(
            delegation_template_receipt,
            bootstrap_intent=bootstrap,
            foundation_readback=foundation,
        )
    except ArtifactBootstrapError as exc:
        raise ArtifactBootstrapError("ACCESS_UPDATE_RECEIPT_INVALID") from exc
    source_commit = bootstrap["source_commit"]
    expected_route_key = (
        f"{ARTIFACT_PREFIX}templates/{source_commit}/"
        "cfn-platform-authority-gug376-temporary-change-set-route.yaml"
    )
    expected_delegation_key = (
        f"{ARTIFACT_PREFIX}templates/{source_commit}/"
        "cfn-platform-authority-bootstrap-plan-repair-delegation.yaml"
    )
    if (
        route_receipt["key"] != expected_route_key
        or delegation_receipt["key"] != expected_delegation_key
        or route_receipt["sse_kms_key_arn"]
        != delegation_receipt["sse_kms_key_arn"]
        or route_receipt["content_type"] != "text/yaml"
        or delegation_receipt["content_type"] != "text/yaml"
        or route_receipt["object_sha256"]
        != reviewed["sources"]["route_template"]["sha256"]
        or route_receipt["content_length"]
        != reviewed["sources"]["route_template"]["bytes"]
        or delegation_receipt["object_sha256"]
        != reviewed["sources"]["delegation_template"]["sha256"]
        or delegation_receipt["content_length"]
        != reviewed["sources"]["delegation_template"]["bytes"]
    ):
        _fail("ACCESS_UPDATE_INPUT_INVALID")
    if (
        not isinstance(foundation_template, bytes)
        or not foundation_template
        or len(foundation_template) > 51_200
        or bytes_digest(foundation_template)
        != bootstrap["template_digests"]["foundation"]
        or b"TemplateURL:" in foundation_template
    ):
        _fail("ACCESS_UPDATE_TEMPLATE_INVALID")
    names = bootstrap["names"]
    parameters = {
        "AuthorityAccountId": AUTHORITY_ACCOUNT_ID,
        "SourceCommit": source_commit,
        "ArtifactBucketName": names["artifact_bucket"],
        "ArtifactKmsAlias": names["artifact_kms_alias"],
        "SigningProfileName": names["signing_profile_name"],
        "CrossAccountAccessEnabled": "true",
        "RouteTemplateVersion": route_receipt["version"],
        "DelegationTemplateVersion": delegation_receipt["version"],
    }
    request = _normalize_request(
        _stack_request(
            stack_name=FOUNDATION_STACK_NAME,
            change_set_name="gug376-artifact-foundation-access-update",
            change_set_type="UPDATE",
            template_body=foundation_template.decode("utf-8"),
            parameters=parameters,
            token_seed={
                "source_commit": source_commit,
                "route_receipt_digest": route_receipt["receipt_digest"],
                "delegation_receipt_digest": delegation_receipt["receipt_digest"],
                "reviewed_sources_digest": reviewed["attestation_digest"],
            },
        )
    )
    record: dict[str, Any] = {
        "schema_version": 1,
        "record_type": ACCESS_UPDATE_TYPE,
        "source_commit": source_commit,
        "bootstrap_intent_digest": bootstrap["intent_digest"],
        "route_template_receipt_digest": route_receipt["receipt_digest"],
        "delegation_template_receipt_digest": delegation_receipt["receipt_digest"],
        "reviewed_sources_digest": reviewed["attestation_digest"],
        "route_template_sha256": route_receipt["object_sha256"],
        "delegation_template_sha256": delegation_receipt["object_sha256"],
        "route_template_version_digest": digest_value(route_receipt["version"]),
        "delegation_template_version_digest": digest_value(
            delegation_receipt["version"]
        ),
        "artifact_kms_key_arn": route_receipt["sse_kms_key_arn"],
        "request": request,
        "request_digest": digest_value(request),
        "aws_calls": 0,
        "aws_mutations": 0,
        "production_authorized": False,
        "production_status": PRODUCTION_STATUS,
    }
    return _seal(record, "intent_digest")


def validate_foundation_access_update(
    value: Mapping[str, Any], *, bootstrap_intent: Mapping[str, Any],
    foundation_readback: Mapping[str, Any],
    route_template_receipt: Mapping[str, Any],
    delegation_template_receipt: Mapping[str, Any],
    reviewed_sources: Mapping[str, Any]
) -> dict[str, Any]:
    bootstrap = validate_bootstrap_intent(bootstrap_intent)
    reviewed = validate_reviewed_sources(
        reviewed_sources, bootstrap_intent=bootstrap
    )
    expected_fields = {
        "schema_version",
        "record_type",
        "source_commit",
        "bootstrap_intent_digest",
        "route_template_receipt_digest",
        "delegation_template_receipt_digest",
        "reviewed_sources_digest",
        "route_template_sha256",
        "delegation_template_sha256",
        "route_template_version_digest",
        "delegation_template_version_digest",
        "artifact_kms_key_arn",
        "request",
        "request_digest",
        "aws_calls",
        "aws_mutations",
        "production_authorized",
        "production_status",
        "intent_digest",
    }
    if not isinstance(value, Mapping) or set(value) != expected_fields:
        _fail("ACCESS_UPDATE_INVALID")
    _verify(value, "intent_digest", "ACCESS_UPDATE_DIGEST_INVALID")
    request = value.get("request")
    parameters = (
        {
            item.get("ParameterKey"): item.get("ParameterValue")
            for item in request.get("Parameters", [])
            if isinstance(item, Mapping)
        }
        if isinstance(request, Mapping)
        else {}
    )
    route_version = parameters.get("RouteTemplateVersion")
    delegation_version = parameters.get("DelegationTemplateVersion")
    if (
        value.get("schema_version") != 1
        or value.get("record_type") != ACCESS_UPDATE_TYPE
        or value.get("source_commit") != bootstrap["source_commit"]
        or value.get("bootstrap_intent_digest") != bootstrap["intent_digest"]
        or value.get("reviewed_sources_digest")
        != reviewed["attestation_digest"]
        or value.get("route_template_sha256")
        != reviewed["sources"]["route_template"]["sha256"]
        or value.get("delegation_template_sha256")
        != reviewed["sources"]["delegation_template"]["sha256"]
        or _DIGEST.fullmatch(str(value.get("reviewed_sources_digest", "")))
        is None
        or _DIGEST.fullmatch(str(value.get("route_template_sha256", ""))) is None
        or _DIGEST.fullmatch(
            str(value.get("delegation_template_sha256", ""))
        ) is None
        or not isinstance(request, Mapping)
        or request.get("StackName") != FOUNDATION_STACK_NAME
        or request.get("ChangeSetName")
        != "gug376-artifact-foundation-access-update"
        or request.get("ChangeSetType") != "UPDATE"
        or "TemplateURL" in request
        or parameters.get("CrossAccountAccessEnabled") != "true"
        or not isinstance(route_version, str)
        or _VERSION.fullmatch(route_version) is None
        or route_version == "NOT_CONFIGURED"
        or not isinstance(delegation_version, str)
        or _VERSION.fullmatch(delegation_version) is None
        or delegation_version == "NOT_CONFIGURED"
        or value.get("route_template_version_digest")
        != digest_value(route_version)
        or value.get("delegation_template_version_digest")
        != digest_value(delegation_version)
        or value.get("request_digest") != digest_value(request)
        or value.get("production_authorized") is not False
        or value.get("production_status") != PRODUCTION_STATUS
        or value.get("aws_calls") != 0
        or value.get("aws_mutations") != 0
    ):
        _fail("ACCESS_UPDATE_INVALID")
    body = request.get("TemplateBody") if isinstance(request, Mapping) else None
    if not isinstance(body, str):
        _fail("ACCESS_UPDATE_INVALID")
    expected_value = materialize_foundation_access_update(
        bootstrap_intent=bootstrap,
        foundation_readback=foundation_readback,
        route_template_receipt=route_template_receipt,
        delegation_template_receipt=delegation_template_receipt,
        reviewed_sources=reviewed,
        foundation_template=body.encode("utf-8"),
    )
    if dict(value) != expected_value:
        _fail("ACCESS_UPDATE_REQUEST_RECONSTRUCTION_MISMATCH")
    return json.loads(canonical_json(dict(value)))


def _validate_verifier(
    value: Any, *, profile: str, account_id: str, caller_pattern: str
) -> dict[str, str]:
    if (
        not isinstance(value, Mapping)
        or set(value) != {"account_id", "caller_arn", "profile", "region"}
        or value.get("account_id") != account_id
        or value.get("profile") != profile
        or value.get("region") != REGION
        or re.fullmatch(caller_pattern, str(value.get("caller_arn", ""))) is None
    ):
        _fail("VERIFIER_INVALID")
    return {key: str(item) for key, item in value.items()}


def validate_foundation_access_readback(
    value: Mapping[str, Any], *, bootstrap_intent: Mapping[str, Any],
    foundation_readback: Mapping[str, Any],
    access_update: Mapping[str, Any],
    route_template_receipt: Mapping[str, Any],
    delegation_template_receipt: Mapping[str, Any],
    reviewed_sources: Mapping[str, Any]
) -> dict[str, Any]:
    bootstrap = validate_bootstrap_intent(bootstrap_intent)
    update = validate_foundation_access_update(
        access_update,
        bootstrap_intent=bootstrap,
        foundation_readback=foundation_readback,
        route_template_receipt=route_template_receipt,
        delegation_template_receipt=delegation_template_receipt,
        reviewed_sources=reviewed_sources,
    )
    expected = {
        "schema_version",
        "record_type",
        "source_commit",
        "bootstrap_intent_digest",
        "access_update_intent_digest",
        "verifier",
        "route_template_receipt_digest",
        "delegation_template_receipt_digest",
        "route_template_sha256",
        "delegation_template_sha256",
        "route_template_version_digest",
        "delegation_template_version_digest",
        "template_digest",
        "parameters_digest",
        "bucket_policy_digest",
        "key_policy_digest",
        "direct_kms_grant_proven",
        "exact_resource_count",
        "source_marker",
        "read_at",
        "aws_calls",
        "aws_mutations",
        "production_authorized",
        "production_status",
        "readback_digest",
    }
    if not isinstance(value, Mapping) or set(value) != expected:
        _fail("FOUNDATION_ACCESS_READBACK_INVALID")
    _verify(
        value,
        "readback_digest",
        "FOUNDATION_ACCESS_READBACK_DIGEST_INVALID",
    )
    try:
        _validate_verifier(
            value.get("verifier"),
            profile=AUTHORITY_PROFILE,
            account_id=AUTHORITY_ACCOUNT_ID,
            caller_pattern=(
                r"arn:aws:sts::042360977644:assumed-role/"
                r"AWSReservedSSO_ScanalyzeGug376ArtifactBootstrap_"
                r"[0-9A-Fa-f]{16}/[A-Za-z0-9+=,.@_-]{1,64}"
            ),
        )
    except ArtifactBootstrapError as exc:
        raise ArtifactBootstrapError("FOUNDATION_ACCESS_READBACK_INVALID") from exc
    if (
        value.get("schema_version") != 1
        or value.get("record_type") != FOUNDATION_ACCESS_READBACK_TYPE
        or value.get("source_commit") != bootstrap["source_commit"]
        or value.get("bootstrap_intent_digest") != bootstrap["intent_digest"]
        or value.get("access_update_intent_digest") != update["intent_digest"]
        or value.get("route_template_receipt_digest")
        != update["route_template_receipt_digest"]
        or value.get("delegation_template_receipt_digest")
        != update["delegation_template_receipt_digest"]
        or value.get("route_template_sha256") != update["route_template_sha256"]
        or value.get("delegation_template_sha256")
        != update["delegation_template_sha256"]
        or value.get("route_template_version_digest")
        != update["route_template_version_digest"]
        or value.get("delegation_template_version_digest")
        != update["delegation_template_version_digest"]
        or value.get("template_digest")
        != bootstrap["template_digests"]["foundation"]
        or value.get("parameters_digest")
        != digest_value(
            {
                item["ParameterKey"]: item["ParameterValue"]
                for item in update["request"]["Parameters"]
            }
        )
        or _DIGEST.fullmatch(str(value.get("bucket_policy_digest", ""))) is None
        or _DIGEST.fullmatch(str(value.get("key_policy_digest", ""))) is None
        or value.get("direct_kms_grant_proven") is not True
        or value.get("exact_resource_count") != 6
        or value.get("source_marker")
        != "AWS_STS_CLOUDFORMATION_S3_KMS_EXACT_ACCESS_READBACK"
        or type(value.get("aws_calls")) is not int
        or value["aws_calls"] < 6
        or value.get("aws_mutations") != 0
        or value.get("production_authorized") is not False
        or value.get("production_status") != PRODUCTION_STATUS
    ):
        _fail("FOUNDATION_ACCESS_READBACK_INVALID")
    _validate_window_timestamp(
        value.get("read_at"),
        bootstrap=bootstrap,
        read_only=True,
        code="FOUNDATION_ACCESS_READBACK_INVALID",
    )
    return json.loads(canonical_json(dict(value)))


def materialize_foundation_publish_binding(
    *,
    bootstrap_intent: Mapping[str, Any],
    foundation_readback: Mapping[str, Any],
    reviewed_sources: Mapping[str, Any],
    access_update: Mapping[str, Any],
    access_readback: Mapping[str, Any],
    route_template_receipt: Mapping[str, Any],
    delegation_template_receipt: Mapping[str, Any],
) -> dict[str, Any]:
    """Seal the pre-revoke storage/signing authority used to build artifacts."""

    bootstrap = validate_bootstrap_intent(bootstrap_intent)
    foundation = validate_foundation_readback(
        foundation_readback, bootstrap_intent=bootstrap
    )
    reviewed = validate_reviewed_sources(
        reviewed_sources, bootstrap_intent=bootstrap
    )
    update = validate_foundation_access_update(
        access_update,
        bootstrap_intent=bootstrap,
        foundation_readback=foundation,
        route_template_receipt=route_template_receipt,
        delegation_template_receipt=delegation_template_receipt,
        reviewed_sources=reviewed,
    )
    access = validate_foundation_access_readback(
        access_readback,
        bootstrap_intent=bootstrap,
        foundation_readback=foundation,
        access_update=update,
        route_template_receipt=route_template_receipt,
        delegation_template_receipt=delegation_template_receipt,
        reviewed_sources=reviewed,
    )
    record: dict[str, Any] = {
        "schema_version": 1,
        "record_type": FOUNDATION_STORAGE_BINDING_TYPE,
        "source_commit": bootstrap["source_commit"],
        "bootstrap_intent_digest": bootstrap["intent_digest"],
        "foundation_readback_digest": foundation["readback_digest"],
        "reviewed_sources_digest": reviewed["attestation_digest"],
        "access_update_intent_digest": update["intent_digest"],
        "access_readback_digest": access["readback_digest"],
        "route_template_receipt_digest": update[
            "route_template_receipt_digest"
        ],
        "delegation_template_receipt_digest": update[
            "delegation_template_receipt_digest"
        ],
        "route_template_sha256": update["route_template_sha256"],
        "delegation_template_sha256": update["delegation_template_sha256"],
        "route_template_version_digest": update[
            "route_template_version_digest"
        ],
        "delegation_template_version_digest": update[
            "delegation_template_version_digest"
        ],
        "access_not_after": bootstrap["access_not_after"],
        "bucket": foundation["artifact_bucket"],
        "sse_algorithm": "aws:kms",
        "sse_kms_key_arn": foundation["artifact_kms_key_arn"],
        "signing_profile_version_arn": foundation[
            "signing_profile_version_arn"
        ],
        "code_signing_config_arn": foundation["code_signing_config_arn"],
        "foundation_readback": foundation,
        "reviewed_sources": reviewed,
        "access_update": update,
        "access_readback": access,
        "route_template_receipt": dict(route_template_receipt),
        "delegation_template_receipt": dict(delegation_template_receipt),
        "source_marker": "VALIDATED_GUG376_FOUNDATION_PUBLISH_AUTHORITY",
        "aws_calls": 0,
        "aws_mutations": 0,
        "production_authorized": False,
        "production_status": PRODUCTION_STATUS,
    }
    return _seal(record, "binding_digest")


def validate_foundation_publish_binding(
    value: Mapping[str, Any], *, bootstrap_intent: Mapping[str, Any]
) -> dict[str, Any]:
    bootstrap = validate_bootstrap_intent(bootstrap_intent)
    expected = {
        "schema_version",
        "record_type",
        "source_commit",
        "bootstrap_intent_digest",
        "foundation_readback_digest",
        "reviewed_sources_digest",
        "access_update_intent_digest",
        "access_readback_digest",
        "route_template_receipt_digest",
        "delegation_template_receipt_digest",
        "route_template_sha256",
        "delegation_template_sha256",
        "route_template_version_digest",
        "delegation_template_version_digest",
        "access_not_after",
        "bucket",
        "sse_algorithm",
        "sse_kms_key_arn",
        "signing_profile_version_arn",
        "code_signing_config_arn",
        "foundation_readback",
        "reviewed_sources",
        "access_update",
        "access_readback",
        "route_template_receipt",
        "delegation_template_receipt",
        "source_marker",
        "aws_calls",
        "aws_mutations",
        "production_authorized",
        "production_status",
        "binding_digest",
    }
    if not isinstance(value, Mapping) or set(value) != expected:
        _fail("FOUNDATION_PUBLISH_BINDING_INVALID")
    _verify(
        value,
        "binding_digest",
        "FOUNDATION_PUBLISH_BINDING_DIGEST_INVALID",
    )
    if (
        value.get("schema_version") != 1
        or value.get("record_type") != FOUNDATION_STORAGE_BINDING_TYPE
        or value.get("source_commit") != bootstrap["source_commit"]
        or value.get("bootstrap_intent_digest") != bootstrap["intent_digest"]
        or value.get("access_not_after") != bootstrap["access_not_after"]
        or value.get("bucket") != bootstrap["names"]["artifact_bucket"]
        or value.get("sse_algorithm") != "aws:kms"
        or re.fullmatch(
            r"arn:aws:kms:us-east-1:042360977644:key/[A-Za-z0-9-]{1,128}",
            str(value.get("sse_kms_key_arn", "")),
        )
        is None
        or re.fullmatch(
            r"arn:aws:signer:us-east-1:042360977644:/signing-profiles/"
            + re.escape(bootstrap["names"]["signing_profile_name"])
            + r"/[A-Za-z0-9]{10}",
            str(value.get("signing_profile_version_arn", "")),
        )
        is None
        or re.fullmatch(
            r"arn:aws:lambda:us-east-1:042360977644:code-signing-config:"
            r"csc-[A-Za-z0-9]{17}",
            str(value.get("code_signing_config_arn", "")),
        )
        is None
        or any(
            _DIGEST.fullmatch(str(value.get(field, ""))) is None
            for field in (
                "foundation_readback_digest",
                "reviewed_sources_digest",
                "access_update_intent_digest",
                "access_readback_digest",
                "route_template_receipt_digest",
                "delegation_template_receipt_digest",
                "route_template_sha256",
                "delegation_template_sha256",
                "route_template_version_digest",
                "delegation_template_version_digest",
            )
        )
        or value.get("source_marker")
        != "VALIDATED_GUG376_FOUNDATION_PUBLISH_AUTHORITY"
        or value.get("aws_calls") != 0
        or value.get("aws_mutations") != 0
        or value.get("production_authorized") is not False
        or value.get("production_status") != PRODUCTION_STATUS
    ):
        _fail("FOUNDATION_PUBLISH_BINDING_INVALID")
    _parse_time(value.get("access_not_after"), "FOUNDATION_PUBLISH_BINDING_INVALID")
    try:
        expected_value = materialize_foundation_publish_binding(
            bootstrap_intent=bootstrap,
            foundation_readback=value["foundation_readback"],
            reviewed_sources=value["reviewed_sources"],
            access_update=value["access_update"],
            access_readback=value["access_readback"],
            route_template_receipt=value["route_template_receipt"],
            delegation_template_receipt=value["delegation_template_receipt"],
        )
    except (ArtifactBootstrapError, KeyError, TypeError) as exc:
        raise ArtifactBootstrapError("FOUNDATION_PUBLISH_BINDING_INVALID") from exc
    if dict(value) != expected_value:
        _fail("FOUNDATION_PUBLISH_BINDING_RECONSTRUCTION_MISMATCH")
    return json.loads(canonical_json(dict(value)))


def validate_stack_readback(
    value: Mapping[str, Any], *, bootstrap_intent: Mapping[str, Any], operation: str,
    bridge_pin: Mapping[str, Any] | None = None,
    foundation_readback: Mapping[str, Any] | None = None,
    cleanup_retire: Mapping[str, Any] | None = None,
    bridge_revoke_readback: Mapping[str, Any] | None = None,
    bootstrap_route_release: Mapping[str, Any] | None = None,
    seed_intent: Mapping[str, Any] | None = None,
    terminal_readbacks: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    bootstrap = validate_bootstrap_intent(bootstrap_intent)
    if operation == "bridge-cleanup-retire":
        if cleanup_retire is None or bridge_revoke_readback is None:
            _fail("STACK_READBACK_INVALID")
        retire = validate_bridge_cleanup_retire(
            cleanup_retire,
            bootstrap_intent=bootstrap,
            bridge_revoke_readback=bridge_revoke_readback,
            bootstrap_route_release=bootstrap_route_release,
            seed_intent=seed_intent,
            terminal_readbacks=terminal_readbacks,
        )
        expected_intent_digest = retire["intent_digest"]
        expected_profile_version = "NOT_CONFIGURED"
    elif operation == "bridge-pin":
        if bridge_pin is None or foundation_readback is None:
            _fail("STACK_READBACK_INVALID")
        pin = validate_bridge_pin(
            bridge_pin,
            bootstrap_intent=bootstrap,
            foundation_readback=foundation_readback,
        )
        expected_intent_digest = pin["intent_digest"]
        expected_profile_version = pin["signing_profile_version"]
    else:
        if (
            bridge_pin is not None
            or foundation_readback is not None
            or cleanup_retire is not None
            or bridge_revoke_readback is not None
            or bootstrap_route_release is not None
            or seed_intent is not None
            or terminal_readbacks is not None
        ):
            _fail("STACK_READBACK_INVALID")
        expected_intent_digest = bootstrap["intent_digest"]
        expected_profile_version = "NOT_CONFIGURED"
    expected = {
        "schema_version",
        "record_type",
        "source_commit",
        "operation",
        "intent_digest",
        "verifier",
        "stack_status",
        "stack_completed_at",
        "template_digest",
        "resources",
        "outputs_digest",
        "sso_assignment_count",
        "permission_set_provisioned",
        "permission_set_arn_digest",
        "permission_set_policy_digest",
        "permission_set_tags_digest",
        "permission_set_metadata_exact",
        "managed_policy_count",
        "customer_managed_policy_count",
        "permissions_boundary_absent",
        "signing_profile_version_digest",
        "temporary_principal_authorized",
        "cleanup_assignment_count",
        "cleanup_permission_set_count",
        "cleanup_permission_sets_digest",
        "management_recovery_role_present",
        "management_recovery_role_digest",
        "cleanup_authority_active",
        "credential_window_expired",
        "read_at",
        "aws_calls",
        "aws_mutations",
        "production_authorized",
        "production_status",
        "readback_digest",
    }
    if (
        operation not in {
            "bridge-create",
            "bridge-pin",
            "foundation-create",
            "bridge-revoke",
            "bridge-cleanup-retire",
        }
        or not isinstance(value, Mapping)
        or set(value) != expected
    ):
        _fail("STACK_READBACK_INVALID")
    _verify(value, "readback_digest", "STACK_READBACK_DIGEST_INVALID")
    profile = AUTHORITY_PROFILE if operation == "foundation-create" else MANAGEMENT_PROFILE
    account_id = AUTHORITY_ACCOUNT_ID if operation == "foundation-create" else MANAGEMENT_ACCOUNT_ID
    caller_pattern = (
        r"arn:aws:sts::042360977644:assumed-role/"
        r"AWSReservedSSO_ScanalyzeGug376ArtifactBootstrap_[0-9A-Fa-f]{16}/"
        r"[A-Za-z0-9+=,.@_-]{1,64}"
        if operation == "foundation-create"
        else r"arn:aws:sts::839393571433:assumed-role/"
        r"AWSReservedSSO_AWSAdministratorAccess_[0-9A-Fa-f]{16}/"
        r"[A-Za-z0-9+=,.@_-]{1,64}"
    )
    try:
        _validate_verifier(
            value.get("verifier"),
            profile=profile,
            account_id=account_id,
            caller_pattern=caller_pattern,
        )
    except ArtifactBootstrapError as exc:
        raise ArtifactBootstrapError("STACK_READBACK_INVALID") from exc
    status = (
        "UPDATE_COMPLETE"
        if operation in {"bridge-pin", "bridge-revoke", "bridge-cleanup-retire"}
        else "CREATE_COMPLETE"
    )
    if operation == "bridge-cleanup-retire":
        completed = _parse_time(
            value.get("stack_completed_at"), "STACK_READBACK_INVALID"
        )
        read_at = _parse_time(value.get("read_at"), "STACK_READBACK_INVALID")
        evaluated = _parse_time(retire["evaluated_at"], "STACK_READBACK_INVALID")
        if completed < evaluated or read_at < evaluated:
            _fail("STACK_READBACK_INVALID")
    else:
        completed = _validate_window_timestamp(
            value.get("stack_completed_at"),
            bootstrap=bootstrap,
            read_only=True,
            code="STACK_READBACK_INVALID",
        )
        read_at = _validate_window_timestamp(
            value.get("read_at"),
            bootstrap=bootstrap,
            read_only=True,
            code="STACK_READBACK_INVALID",
        )
    if (
        value.get("schema_version") != 1
        or value.get("record_type") != STACK_READBACK_TYPE
        or value.get("source_commit") != bootstrap["source_commit"]
        or value.get("operation") != operation
        or value.get("intent_digest") != expected_intent_digest
        or value.get("stack_status") != status
        or completed > read_at
        or _DIGEST.fullmatch(str(value.get("template_digest", ""))) is None
        or not isinstance(value.get("resources"), list)
        or _DIGEST.fullmatch(str(value.get("outputs_digest", ""))) is None
        or type(value.get("aws_calls")) is not int
        or value["aws_calls"] < 4
        or value.get("aws_mutations") != 0
        or value.get("production_authorized") is not False
        or value.get("production_status") != PRODUCTION_STATUS
    ):
        _fail("STACK_READBACK_INVALID")
    if operation in {
        "bridge-create",
        "bridge-pin",
        "bridge-revoke",
        "bridge-cleanup-retire",
    }:
        expected_resources = (
            [
                {
                    "logical_resource_id": "ArtifactBootstrapPermissionSet",
                    "resource_type": "AWS::SSO::PermissionSet",
                }
            ]
            if operation == "bridge-cleanup-retire"
            else [
                {
                    "logical_resource_id": "ArtifactBootstrapAssignment",
                    "resource_type": "AWS::SSO::Assignment",
                },
                {
                    "logical_resource_id": "ArtifactBootstrapPermissionSet",
                    "resource_type": "AWS::SSO::PermissionSet",
                },
                {
                    "logical_resource_id": "BrokerSeedCleanupAssignment",
                    "resource_type": "AWS::SSO::Assignment",
                },
                {
                    "logical_resource_id": "BrokerSeedCleanupPermissionSet",
                    "resource_type": "AWS::SSO::PermissionSet",
                },
                {
                    "logical_resource_id": "ManagementRecoveryRole",
                    "resource_type": "AWS::IAM::Role",
                },
                {
                    "logical_resource_id": "RouteSeedCleanupAssignment",
                    "resource_type": "AWS::SSO::Assignment",
                },
                {
                    "logical_resource_id": "RouteSeedCleanupPermissionSet",
                    "resource_type": "AWS::SSO::PermissionSet",
                },
            ]
        )
        if operation == "bridge-revoke":
            expected_resources = [
                item
                for item in expected_resources
                if item["logical_resource_id"] != "ArtifactBootstrapAssignment"
            ]
        expected_resources = sorted(
            expected_resources, key=lambda item: item["logical_resource_id"]
        )
        cleanup_active = operation != "bridge-cleanup-retire"
        if (
            value.get("template_digest") != bootstrap["template_digests"]["bridge"]
            or value.get("resources") != expected_resources
            or value.get("sso_assignment_count")
            != (0 if operation in {"bridge-revoke", "bridge-cleanup-retire"} else 1)
            or type(value.get("permission_set_provisioned")) is not bool
            or _DIGEST.fullmatch(str(value.get("permission_set_arn_digest", "")))
            is None
            or _DIGEST.fullmatch(str(value.get("permission_set_policy_digest", "")))
            is None
            or _DIGEST.fullmatch(str(value.get("permission_set_tags_digest", "")))
            is None
            or value.get("permission_set_metadata_exact") is not True
            or value.get("managed_policy_count") != 0
            or value.get("customer_managed_policy_count") != 0
            or value.get("permissions_boundary_absent") is not True
            or value.get("signing_profile_version_digest")
            != digest_value(expected_profile_version)
            or value.get("temporary_principal_authorized")
            != (operation not in {"bridge-revoke", "bridge-cleanup-retire"})
            or value.get("cleanup_assignment_count") != (2 if cleanup_active else 0)
            or value.get("cleanup_permission_set_count") != (2 if cleanup_active else 0)
            or _DIGEST.fullmatch(str(value.get("cleanup_permission_sets_digest", "")))
            is None
            or value.get("management_recovery_role_present") is not cleanup_active
            or _DIGEST.fullmatch(str(value.get("management_recovery_role_digest", "")))
            is None
            or value.get("cleanup_authority_active") is not cleanup_active
        ):
            _fail("STACK_READBACK_INVALID")
    else:
        if (
            value.get("template_digest")
            != bootstrap["template_digests"]["foundation"]
            or value.get("resources")
            != [
                {
                    "logical_resource_id": "ArtifactBucket",
                    "resource_type": "AWS::S3::Bucket",
                },
                {
                    "logical_resource_id": "ArtifactBucketPolicy",
                    "resource_type": "AWS::S3::BucketPolicy",
                },
                {
                    "logical_resource_id": "ArtifactKey",
                    "resource_type": "AWS::KMS::Key",
                },
                {
                    "logical_resource_id": "ArtifactKeyAlias",
                    "resource_type": "AWS::KMS::Alias",
                },
                {
                    "logical_resource_id": "CodeSigningConfig",
                    "resource_type": "AWS::Lambda::CodeSigningConfig",
                },
                {
                    "logical_resource_id": "SigningProfile",
                    "resource_type": "AWS::Signer::SigningProfile",
                },
            ]
            or any(
                value.get(field) is not None
                for field in (
                    "sso_assignment_count",
                    "permission_set_provisioned",
                    "permission_set_arn_digest",
                    "permission_set_policy_digest",
                    "permission_set_tags_digest",
                    "permission_set_metadata_exact",
                    "managed_policy_count",
                    "customer_managed_policy_count",
                    "permissions_boundary_absent",
                    "signing_profile_version_digest",
                    "temporary_principal_authorized",
                    "cleanup_assignment_count",
                    "cleanup_permission_set_count",
                    "cleanup_permission_sets_digest",
                    "management_recovery_role_present",
                    "management_recovery_role_digest",
                    "cleanup_authority_active",
                )
            )
            or value.get("credential_window_expired") is not False
        ):
            _fail("STACK_READBACK_INVALID")
    if operation == "bridge-revoke":
        if (
            value.get("credential_window_expired") is not True
            or read_at
            < max(
                _parse_time(
                    bootstrap["access_not_after"], "STACK_READBACK_INVALID"
                ),
                completed + timedelta(hours=1),
            )
        ):
            _fail("STACK_READBACK_INVALID")
    elif operation == "bridge-cleanup-retire":
        if value.get("credential_window_expired") is not True:
            _fail("STACK_READBACK_INVALID")
    return json.loads(canonical_json(dict(value)))


def _validate_release_publication_evidence(
    *,
    bootstrap: Mapping[str, Any],
    publish: Mapping[str, Any],
    route_object_receipt: Mapping[str, Any],
    delegation_object_receipt: Mapping[str, Any],
    template_readbacks: Mapping[str, Any],
    pep_signed_artifact_receipt: Mapping[str, Any],
    broker_seed_input: Mapping[str, Any],
    broker_seed_receipts: Mapping[str, Any],
    revoke_completed_at: datetime,
) -> dict[str, Any]:
    """Validate the closed, pre-revoke publication/signing evidence set."""

    if not isinstance(template_readbacks, Mapping) or set(template_readbacks) != {
        "route_template",
        "delegation_template",
        "pep_template",
        "pep_protection_template",
        "broker_template",
        "broker_protection_template",
    }:
        _fail("ROUTE_RELEASE_PUBLICATION_EVIDENCE_INVALID")
    if not isinstance(broker_seed_receipts, Mapping) or set(
        broker_seed_receipts
    ) != {"broker_template", "broker_protection_template"}:
        _fail("ROUTE_RELEASE_PUBLICATION_EVIDENCE_INVALID")
    try:
        from tooling import (
            platform_authority_plan_permission_repair_broker_seed as broker_seed,
        )
        from tooling import (
            platform_authority_plan_permission_repair_signed_artifact as pep_artifact,
        )
        from tooling import (
            platform_authority_plan_permission_repair_template_readback as template_readback,
        )

        validated_templates: dict[str, dict[str, Any]] = {}
        for kind, raw in template_readbacks.items():
            observed = _parse_time(
                raw.get("observed_at") if isinstance(raw, Mapping) else None,
                "ROUTE_RELEASE_PUBLICATION_EVIDENCE_INVALID",
            )
            validated_templates[kind] = (
                template_readback.validate_template_readback_receipt(
                    raw,
                    artifact_kind=kind,
                    source_commit=bootstrap["source_commit"],
                    now=observed,
                    expected_storage_binding=publish,
                )
            )
        pep_evaluated = _parse_time(
            pep_signed_artifact_receipt.get("evaluated_at"),
            "ROUTE_RELEASE_PUBLICATION_EVIDENCE_INVALID",
        )
        pep_artifact.validate_signed_artifact_receipt(
            pep_signed_artifact_receipt,
            now=pep_evaluated,
            bootstrap_intent=bootstrap,
            foundation_publish_binding=publish,
        )
        seed_input = broker_seed.validate_input(broker_seed_input)
        broker_observed = _parse_time(
            seed_input["broker_code"].get("observed_at"),
            "ROUTE_RELEASE_PUBLICATION_EVIDENCE_INVALID",
        )
        broker_code = broker_seed.validate_archived_broker_signing_receipt(
            seed_input["broker_code"],
            source_commit=bootstrap["source_commit"],
            bootstrap_intent=bootstrap,
            foundation_publish_binding=publish,
            valid_through=_parse_time(
                seed_input.get("route_not_after"),
                "ROUTE_RELEASE_PUBLICATION_EVIDENCE_INVALID",
            ),
        )
        seed_receipts = {
            kind: broker_seed.validate_broker_seed_receipt(
                broker_seed_receipts[kind],
                expected_protection_enabled=(
                    kind == "broker_protection_template"
                ),
            )
            for kind in ("broker_template", "broker_protection_template")
        }
    except Exception as exc:
        raise ArtifactBootstrapError(
            "ROUTE_RELEASE_PUBLICATION_EVIDENCE_INVALID"
        ) from exc

    route_template = validated_templates["route_template"]
    delegation_template = validated_templates["delegation_template"]
    pep_template = validated_templates["pep_template"]
    pep_protection_template = validated_templates["pep_protection_template"]
    broker_template = validated_templates["broker_template"]
    broker_protection_template = validated_templates[
        "broker_protection_template"
    ]
    seed_receipt = seed_receipts["broker_template"]
    protection_seed_receipt = seed_receipts["broker_protection_template"]
    pep_template_receipt = pep_template.get("materialization_receipt")
    pep_protection_template_receipt = pep_protection_template.get(
        "materialization_receipt"
    )
    pep_signed = pep_signed_artifact_receipt["signed_artifact"]
    access_not_before = _parse_time(
        bootstrap["access_not_before"],
        "ROUTE_RELEASE_PUBLICATION_EVIDENCE_INVALID",
    )
    access_not_after = _parse_time(
        bootstrap["access_not_after"],
        "ROUTE_RELEASE_PUBLICATION_EVIDENCE_INVALID",
    )
    evidence_times = [
        _parse_time(
            item["observed_at"],
            "ROUTE_RELEASE_PUBLICATION_EVIDENCE_INVALID",
        )
        for item in validated_templates.values()
    ] + [pep_evaluated, broker_observed]
    if (
        any(not access_not_before <= item < access_not_after for item in evidence_times)
        or any(item >= revoke_completed_at for item in evidence_times)
        or route_template["bucket"] != route_object_receipt["bucket"]
        or route_template["key"] != route_object_receipt["key"]
        or route_template["version"] != route_object_receipt["version"]
        or route_template["artifact_sha256"]
        != route_object_receipt["object_sha256"]
        or delegation_template["bucket"] != delegation_object_receipt["bucket"]
        or delegation_template["key"] != delegation_object_receipt["key"]
        or delegation_template["version"] != delegation_object_receipt["version"]
        or delegation_template["artifact_sha256"]
        != delegation_object_receipt["object_sha256"]
        or seed_input["source_commit"] != bootstrap["source_commit"]
        or seed_input["foundation_publish_binding_digest"]
        != publish["binding_digest"]
        or seed_input["broker_config"]["foundation_publish_binding_digest"]
        != publish["binding_digest"]
        or seed_input["broker_code"]["upstream_storage_binding"] != publish
        or seed_input["pep_runtime_binding"]["upstream_storage_binding_digest"]
        != publish["binding_digest"]
        or seed_input["pep_runtime_binding"][
            "pep_signed_artifact_receipt_digest"
        ]
        != pep_signed_artifact_receipt.get("receipt_digest")
        or pep_signed_artifact_receipt.get("upstream_storage_binding") != publish
        or seed_input["pep_template"]
        != {
            "bucket": pep_template["bucket"],
            "key": pep_template["key"],
            "version": pep_template["version"],
            "url": pep_template["template_url"],
        }
        or seed_input["pep_protection_template"]
        != {
            "bucket": pep_protection_template["bucket"],
            "key": pep_protection_template["key"],
            "version": pep_protection_template["version"],
            "url": pep_protection_template["template_url"],
        }
        or not isinstance(pep_template_receipt, Mapping)
        or not isinstance(pep_protection_template_receipt, Mapping)
        or pep_template_receipt.get("template_variant") != "create"
        or pep_protection_template_receipt.get("template_variant")
        != "protection"
        or pep_template_receipt.get("source_commit")
        != bootstrap["source_commit"]
        or pep_protection_template_receipt.get("source_commit")
        != bootstrap["source_commit"]
        or pep_template_receipt.get("template_sha256")
        != pep_template["artifact_sha256"]
        or pep_protection_template_receipt.get("template_sha256")
        != pep_protection_template["artifact_sha256"]
        or pep_template_receipt.get("template_bytes")
        != pep_template["content_length"]
        or pep_protection_template_receipt.get("template_bytes")
        != pep_protection_template["content_length"]
        or pep_template_receipt.get("source_sha256")
        != pep_template["source_sha256"]
        or pep_protection_template_receipt.get("source_sha256")
        != pep_protection_template["source_sha256"]
        or pep_template["source_sha256"]
        != pep_protection_template["source_sha256"]
        or pep_template["artifact_sha256"]
        == pep_protection_template["artifact_sha256"]
        or pep_template["key"] == pep_protection_template["key"]
        or pep_template["template_url"]
        == pep_protection_template["template_url"]
        or seed_input["pep_artifact"]
        != {
            "bucket": pep_signed["bucket"],
            "key": pep_signed["key"],
            "version": pep_signed["version"],
        }
        or seed_receipt != broker_template.get("materialization_receipt")
        or seed_receipt["source_commit"] != bootstrap["source_commit"]
        or seed_receipt["template_sha256"] != broker_template["artifact_sha256"]
        or seed_receipt["template_bytes"] != broker_template["content_length"]
        or seed_receipt["signing_receipt_digest"]
        != broker_code["receipt_digest"]
        or seed_receipt["unsigned_package_sha256"]
        != broker_code["unsigned_artifact"]["sha256"]
        or seed_receipt["signed_package_sha256"]
        != broker_code["signed_artifact"]["sha256"]
        or seed_receipt["pep_runtime_binding_digest"]
        != seed_input["pep_runtime_binding"]["binding_digest"]
        or seed_receipt["foundation_publish_binding_digest"]
        != publish["binding_digest"]
        or protection_seed_receipt
        != broker_protection_template.get("materialization_receipt")
        or protection_seed_receipt["source_commit"]
        != bootstrap["source_commit"]
        or protection_seed_receipt["template_sha256"]
        != broker_protection_template["artifact_sha256"]
        or protection_seed_receipt["template_bytes"]
        != broker_protection_template["content_length"]
        or protection_seed_receipt["signing_receipt_digest"]
        != broker_code["receipt_digest"]
        or protection_seed_receipt["unsigned_package_sha256"]
        != broker_code["unsigned_artifact"]["sha256"]
        or protection_seed_receipt["signed_package_sha256"]
        != broker_code["signed_artifact"]["sha256"]
        or protection_seed_receipt["pep_runtime_binding_digest"]
        != seed_input["pep_runtime_binding"]["binding_digest"]
        or protection_seed_receipt["foundation_publish_binding_digest"]
        != publish["binding_digest"]
        or protection_seed_receipt["template_sha256"]
        == seed_receipt["template_sha256"]
        or broker_code["signing_job"]["profile_version_arn"]
        != publish["signing_profile_version_arn"]
        or pep_signed_artifact_receipt["signing_job"]["profile_version_arn"]
        != publish["signing_profile_version_arn"]
    ):
        _fail("ROUTE_RELEASE_PUBLICATION_EVIDENCE_INVALID")
    evidence = {
        "template_readbacks": validated_templates,
        "pep_signed_artifact_receipt": dict(pep_signed_artifact_receipt),
        "broker_seed_input": seed_input,
        "broker_seed_receipts": seed_receipts,
    }
    return json.loads(canonical_json(evidence))


def materialize_route_release(
    *,
    bootstrap_intent: Mapping[str, Any],
    foundation_readback: Mapping[str, Any],
    reviewed_sources: Mapping[str, Any],
    access_update: Mapping[str, Any],
    access_readback: Mapping[str, Any],
    foundation_publish_binding: Mapping[str, Any],
    bridge_pin: Mapping[str, Any],
    bridge_pin_readback: Mapping[str, Any],
    bridge_revoke_readback: Mapping[str, Any],
    route_template_receipt: Mapping[str, Any],
    delegation_template_receipt: Mapping[str, Any],
    template_readbacks: Mapping[str, Any],
    pep_signed_artifact_receipt: Mapping[str, Any],
    broker_seed_input: Mapping[str, Any],
    broker_seed_receipts: Mapping[str, Any],
    now: datetime,
) -> dict[str, Any]:
    """Seal the only foundation state that may feed the normal route."""

    bootstrap = validate_bootstrap_intent(bootstrap_intent)
    foundation = validate_foundation_readback(
        foundation_readback, bootstrap_intent=bootstrap
    )
    reviewed = validate_reviewed_sources(
        reviewed_sources, bootstrap_intent=bootstrap
    )
    update = validate_foundation_access_update(
        access_update,
        bootstrap_intent=bootstrap,
        foundation_readback=foundation,
        route_template_receipt=route_template_receipt,
        delegation_template_receipt=delegation_template_receipt,
        reviewed_sources=reviewed,
    )
    access = validate_foundation_access_readback(
        access_readback,
        bootstrap_intent=bootstrap,
        foundation_readback=foundation,
        access_update=update,
        route_template_receipt=route_template_receipt,
        delegation_template_receipt=delegation_template_receipt,
        reviewed_sources=reviewed,
    )
    publish = validate_foundation_publish_binding(
        foundation_publish_binding, bootstrap_intent=bootstrap
    )
    pin = validate_bridge_pin(
        bridge_pin,
        bootstrap_intent=bootstrap,
        foundation_readback=foundation,
    )
    pin_readback = validate_stack_readback(
        bridge_pin_readback,
        bootstrap_intent=bootstrap,
        operation="bridge-pin",
        bridge_pin=pin,
        foundation_readback=foundation,
    )
    revoke = validate_stack_readback(
        bridge_revoke_readback,
        bootstrap_intent=bootstrap,
        operation="bridge-revoke",
    )
    route_receipt = validate_object_receipt(
        route_template_receipt,
        bootstrap_intent=bootstrap,
        foundation_readback=foundation,
    )
    delegation_receipt = validate_object_receipt(
        delegation_template_receipt,
        bootstrap_intent=bootstrap,
        foundation_readback=foundation,
    )
    revoke_completed = _parse_time(
        revoke["stack_completed_at"], "ROUTE_RELEASE_INVALID"
    )
    publication = _validate_release_publication_evidence(
        bootstrap=bootstrap,
        publish=publish,
        route_object_receipt=route_receipt,
        delegation_object_receipt=delegation_receipt,
        template_readbacks=template_readbacks,
        pep_signed_artifact_receipt=pep_signed_artifact_receipt,
        broker_seed_input=broker_seed_input,
        broker_seed_receipts=broker_seed_receipts,
        revoke_completed_at=revoke_completed,
    )
    if now.tzinfo is None or now.utcoffset() is None:
        _fail("ROUTE_RELEASE_CLOCK_INVALID")
    evaluated = now.astimezone(timezone.utc).replace(microsecond=0)
    session_expiry = revoke_completed.timestamp() + 3600
    route_not_before = max(
        _parse_time(bootstrap["access_not_after"], "ROUTE_RELEASE_INVALID"),
        datetime.fromtimestamp(session_expiry, timezone.utc),
    )
    if (
        evaluated < route_not_before
        or route_receipt["receipt_digest"]
        != update["route_template_receipt_digest"]
        or delegation_receipt["receipt_digest"]
        != update["delegation_template_receipt_digest"]
        or route_receipt["object_sha256"] != update["route_template_sha256"]
        or delegation_receipt["object_sha256"]
        != update["delegation_template_sha256"]
        or digest_value(route_receipt["version"])
        != update["route_template_version_digest"]
        or digest_value(delegation_receipt["version"])
        != update["delegation_template_version_digest"]
        or publish["foundation_readback_digest"] != foundation["readback_digest"]
        or publish["reviewed_sources_digest"] != reviewed["attestation_digest"]
        or publish["access_update_intent_digest"] != update["intent_digest"]
        or publish["access_readback_digest"] != access["readback_digest"]
        or pin["foundation_readback_digest"] != foundation["readback_digest"]
        or pin_readback["stack_completed_at"] >= revoke["stack_completed_at"]
    ):
        _fail("ROUTE_RELEASE_INVALID")
    record: dict[str, Any] = {
        "schema_version": 1,
        "record_type": ROUTE_RELEASE_TYPE,
        "source_commit": bootstrap["source_commit"],
        "bootstrap_intent_digest": bootstrap["intent_digest"],
        "foundation_readback_digest": foundation["readback_digest"],
        "reviewed_sources_digest": reviewed["attestation_digest"],
        "access_update_intent_digest": update["intent_digest"],
        "access_readback_digest": access["readback_digest"],
        "foundation_publish_binding_digest": publish["binding_digest"],
        "bridge_pin_intent_digest": pin["intent_digest"],
        "bridge_pin_readback_digest": pin_readback["readback_digest"],
        "bridge_revoke_readback_digest": revoke["readback_digest"],
        "route_template_receipt_digest": route_receipt["receipt_digest"],
        "delegation_template_receipt_digest": delegation_receipt["receipt_digest"],
        "route_template_version": route_receipt["version"],
        "delegation_template_version": delegation_receipt["version"],
        "temporary_assignment_count": 0,
        "temporary_principal_authorized": False,
        "temporary_permission_set_provisioned_observed": revoke[
            "permission_set_provisioned"
        ],
        "temporary_credential_window_expired": True,
        "cleanup_not_after": bootstrap["cleanup_not_after"],
        "cleanup_not_after_digest": digest_value(
            bootstrap["cleanup_not_after"]
        ),
        "normal_route_not_before": route_not_before.isoformat().replace(
            "+00:00", "Z"
        ),
        "released_at": evaluated.isoformat().replace("+00:00", "Z"),
        "storage_binding": publish,
        "bridge_pin": pin,
        "bridge_pin_readback": pin_readback,
        "bridge_revoke_readback": revoke,
        "publication_evidence": publication,
        "publication_evidence_digest": digest_value(publication),
        "broker_config_digest": publication["broker_seed_input"][
            "broker_config"
        ]["config_digest"],
        "pep_signed_artifact_receipt_digest": publication[
            "pep_signed_artifact_receipt"
        ]["receipt_digest"],
        "pep_template_receipt_digests": {
            kind: publication["template_readbacks"][kind][
                "materialization_receipt"
            ]["receipt_digest"]
            for kind in ("pep_template", "pep_protection_template")
        },
        "broker_signing_receipt_digest": publication["broker_seed_input"][
            "broker_code"
        ]["receipt_digest"],
        "broker_seed_receipt_digests": {
            kind: publication["broker_seed_receipts"][kind]["receipt_digest"]
            for kind in ("broker_template", "broker_protection_template")
        },
        "aws_calls": 0,
        "aws_mutations": 0,
        "deployment_authorized": False,
        "production_authorized": False,
        "production_status": PRODUCTION_STATUS,
    }
    return _seal(record, "release_digest")


def validate_route_release(
    value: Mapping[str, Any], *, bootstrap_intent: Mapping[str, Any], now: datetime
) -> dict[str, Any]:
    bootstrap = validate_bootstrap_intent(bootstrap_intent)
    expected = {
        "schema_version",
        "record_type",
        "source_commit",
        "bootstrap_intent_digest",
        "foundation_readback_digest",
        "reviewed_sources_digest",
        "access_update_intent_digest",
        "access_readback_digest",
        "foundation_publish_binding_digest",
        "bridge_pin_intent_digest",
        "bridge_pin_readback_digest",
        "bridge_revoke_readback_digest",
        "route_template_receipt_digest",
        "delegation_template_receipt_digest",
        "route_template_version",
        "delegation_template_version",
        "temporary_assignment_count",
        "temporary_principal_authorized",
        "temporary_permission_set_provisioned_observed",
        "temporary_credential_window_expired",
        "cleanup_not_after",
        "cleanup_not_after_digest",
        "normal_route_not_before",
        "released_at",
        "storage_binding",
        "bridge_pin",
        "bridge_pin_readback",
        "bridge_revoke_readback",
        "publication_evidence",
        "publication_evidence_digest",
        "broker_config_digest",
        "pep_signed_artifact_receipt_digest",
        "pep_template_receipt_digests",
        "broker_signing_receipt_digest",
        "broker_seed_receipt_digests",
        "aws_calls",
        "aws_mutations",
        "deployment_authorized",
        "production_authorized",
        "production_status",
        "release_digest",
    }
    if not isinstance(value, Mapping) or set(value) != expected:
        _fail("ROUTE_RELEASE_INVALID")
    _verify(value, "release_digest", "ROUTE_RELEASE_DIGEST_INVALID")
    if now.tzinfo is None or now.utcoffset() is None:
        _fail("ROUTE_RELEASE_CLOCK_INVALID")
    current = now.astimezone(timezone.utc).replace(microsecond=0)
    threshold = _parse_time(
        value.get("normal_route_not_before"), "ROUTE_RELEASE_INVALID"
    )
    released = _parse_time(value.get("released_at"), "ROUTE_RELEASE_INVALID")
    try:
        storage = validate_foundation_publish_binding(
            value.get("storage_binding"), bootstrap_intent=bootstrap
        )
        foundation = validate_foundation_readback(
            storage["foundation_readback"], bootstrap_intent=bootstrap
        )
        pin = validate_bridge_pin(
            value.get("bridge_pin"),
            bootstrap_intent=bootstrap,
            foundation_readback=foundation,
        )
        pin_readback = validate_stack_readback(
            value.get("bridge_pin_readback"),
            bootstrap_intent=bootstrap,
            operation="bridge-pin",
            bridge_pin=pin,
            foundation_readback=foundation,
        )
        revoke = validate_stack_readback(
            value.get("bridge_revoke_readback"),
            bootstrap_intent=bootstrap,
            operation="bridge-revoke",
        )
        revoke_completed = _parse_time(
            revoke["stack_completed_at"], "ROUTE_RELEASE_INVALID"
        )
        publication = _validate_release_publication_evidence(
            bootstrap=bootstrap,
            publish=storage,
            route_object_receipt=storage["route_template_receipt"],
            delegation_object_receipt=storage["delegation_template_receipt"],
            template_readbacks=value.get("publication_evidence", {}).get(
                "template_readbacks"
            ),
            pep_signed_artifact_receipt=value.get(
                "publication_evidence", {}
            ).get("pep_signed_artifact_receipt"),
            broker_seed_input=value.get("publication_evidence", {}).get(
                "broker_seed_input"
            ),
            broker_seed_receipts=value.get("publication_evidence", {}).get(
                "broker_seed_receipts"
            ),
            revoke_completed_at=revoke_completed,
        )
    except ArtifactBootstrapError as exc:
        raise ArtifactBootstrapError("ROUTE_RELEASE_INVALID") from exc
    except (AttributeError, KeyError, TypeError) as exc:
        raise ArtifactBootstrapError("ROUTE_RELEASE_INVALID") from exc
    if (
        value.get("schema_version") != 1
        or value.get("record_type") != ROUTE_RELEASE_TYPE
        or value.get("source_commit") != bootstrap["source_commit"]
        or value.get("bootstrap_intent_digest") != bootstrap["intent_digest"]
        or value.get("temporary_assignment_count") != 0
        or value.get("temporary_principal_authorized") is not False
        or type(value.get("temporary_permission_set_provisioned_observed"))
        is not bool
        or value.get("temporary_credential_window_expired") is not True
        or value.get("cleanup_not_after") != bootstrap["cleanup_not_after"]
        or value.get("cleanup_not_after_digest")
        != digest_value(bootstrap["cleanup_not_after"])
        or not threshold <= released <= current
        or value.get("foundation_publish_binding_digest")
        != storage["binding_digest"]
        or value.get("bridge_pin_intent_digest") != pin["intent_digest"]
        or value.get("bridge_pin_readback_digest")
        != pin_readback["readback_digest"]
        or value.get("bridge_revoke_readback_digest")
        != revoke["readback_digest"]
        or value.get("publication_evidence") != publication
        or value.get("publication_evidence_digest") != digest_value(publication)
        or value.get("broker_config_digest")
        != publication["broker_seed_input"]["broker_config"]["config_digest"]
        or value.get("pep_signed_artifact_receipt_digest")
        != publication["pep_signed_artifact_receipt"]["receipt_digest"]
        or value.get("pep_template_receipt_digests")
        != {
            kind: publication["template_readbacks"][kind][
                "materialization_receipt"
            ]["receipt_digest"]
            for kind in ("pep_template", "pep_protection_template")
        }
        or value.get("broker_signing_receipt_digest")
        != publication["broker_seed_input"]["broker_code"]["receipt_digest"]
        or value.get("broker_seed_receipt_digests")
        != {
            kind: publication["broker_seed_receipts"][kind]["receipt_digest"]
            for kind in ("broker_template", "broker_protection_template")
        }
        or storage.get("foundation_readback_digest")
        != value.get("foundation_readback_digest")
        or storage.get("access_update_intent_digest")
        != value.get("access_update_intent_digest")
        or storage.get("access_readback_digest")
        != value.get("access_readback_digest")
        or storage.get("bucket")
        != bootstrap["names"]["artifact_bucket"]
        or storage.get("sse_algorithm") != "aws:kms"
        or re.fullmatch(
            r"arn:aws:kms:us-east-1:042360977644:key/[A-Za-z0-9-]{1,128}",
            str(storage.get("sse_kms_key_arn", "")),
        )
        is None
        or any(
            _DIGEST.fullmatch(str(value.get(field, ""))) is None
            for field in (
                "foundation_readback_digest",
                "reviewed_sources_digest",
                "access_update_intent_digest",
                "access_readback_digest",
                "bridge_revoke_readback_digest",
                "bridge_pin_intent_digest",
                "bridge_pin_readback_digest",
                "publication_evidence_digest",
                "broker_config_digest",
                "pep_signed_artifact_receipt_digest",
                "broker_signing_receipt_digest",
                "route_template_receipt_digest",
                "delegation_template_receipt_digest",
            )
        )
        or not isinstance(value.get("broker_seed_receipt_digests"), Mapping)
        or set(value["broker_seed_receipt_digests"])
        != {"broker_template", "broker_protection_template"}
        or any(
            _DIGEST.fullmatch(str(item)) is None
            for item in value["broker_seed_receipt_digests"].values()
        )
        or not isinstance(value.get("pep_template_receipt_digests"), Mapping)
        or set(value["pep_template_receipt_digests"])
        != {"pep_template", "pep_protection_template"}
        or any(
            _DIGEST.fullmatch(str(item)) is None
            for item in value["pep_template_receipt_digests"].values()
        )
        or _VERSION.fullmatch(str(value.get("route_template_version", ""))) is None
        or _VERSION.fullmatch(
            str(value.get("delegation_template_version", ""))
        ) is None
        or value.get("aws_calls") != 0
        or value.get("aws_mutations") != 0
        or value.get("deployment_authorized") is not False
        or value.get("production_authorized") is not False
        or value.get("production_status") != PRODUCTION_STATUS
    ):
        _fail("ROUTE_RELEASE_INVALID")
    try:
        expected_value = materialize_route_release(
            bootstrap_intent=bootstrap,
            foundation_readback=storage["foundation_readback"],
            reviewed_sources=storage["reviewed_sources"],
            access_update=storage["access_update"],
            access_readback=storage["access_readback"],
            foundation_publish_binding=storage,
            bridge_pin=pin,
            bridge_pin_readback=pin_readback,
            bridge_revoke_readback=revoke,
            route_template_receipt=storage["route_template_receipt"],
            delegation_template_receipt=storage[
                "delegation_template_receipt"
            ],
            template_readbacks=publication["template_readbacks"],
            pep_signed_artifact_receipt=publication[
                "pep_signed_artifact_receipt"
            ],
            broker_seed_input=publication["broker_seed_input"],
            broker_seed_receipts=publication["broker_seed_receipts"],
            now=released,
        )
    except ArtifactBootstrapError as exc:
        raise ArtifactBootstrapError("ROUTE_RELEASE_INVALID") from exc
    if dict(value) != expected_value:
        _fail("ROUTE_RELEASE_RECONSTRUCTION_MISMATCH")
    return json.loads(canonical_json(dict(value)))


__all__ = [
    "ARTIFACT_PREFIX",
    "AUTHORITY_ACCOUNT_ID",
    "AUTHORITY_PROFILE",
    "AUTHORIZATION_TYPE",
    "ACCESS_UPDATE_TYPE",
    "ArtifactBootstrapError",
    "BRIDGE_CHANGE_SET_NAME",
    "BRIDGE_CLEANUP_RETIRE_AUTHORIZATION_TYPE",
    "BRIDGE_CLEANUP_RETIRE_TYPE",
    "BRIDGE_PIN_TYPE",
    "BRIDGE_STACK_NAME",
    "BRIDGE_TEMPLATE_PATH",
    "CLEANUP_RETIRE_CHANGE_SET_NAME",
    "FOUNDATION_STACK_NAME",
    "FOUNDATION_CHANGE_SET_NAME",
    "FOUNDATION_ACCESS_READBACK_TYPE",
    "FOUNDATION_READBACK_TYPE",
    "FOUNDATION_STORAGE_BINDING_TYPE",
    "FOUNDATION_TEMPLATE_PATH",
    "INPUT_TYPE",
    "INTENT_TYPE",
    "MANAGEMENT_ACCOUNT_ID",
    "MANAGEMENT_PROFILE",
    "MIN_ACCESS_WINDOW_SECONDS",
    "MUTATION_COMPLETION_RESERVE_SECONDS",
    "OBJECT_INTENT_TYPE",
    "OBJECT_RECEIPT_TYPE",
    "PRODUCTION_STATUS",
    "REGION",
    "REVIEWED_SOURCES_TYPE",
    "REVOKE_CHANGE_SET_NAME",
    "ROUTE_RELEASE_TYPE",
    "ROUTE_TEMPLATE_SOURCE_PATH",
    "DELEGATION_TEMPLATE_SOURCE_PATH",
    "SIGNING_INTENT_TYPE",
    "STACK_READBACK_TYPE",
    "STACK_TAGS",
    "MUTATION_AUTHORIZATION_TYPE",
    "bytes_digest",
    "canonical_json",
    "deterministic_names",
    "digest_value",
    "materialize_authorization",
    "materialize_bootstrap_intent",
    "materialize_bridge_pin",
    "materialize_bridge_cleanup_retire",
    "materialize_bridge_cleanup_retire_authorization",
    "materialize_foundation_access_update",
    "materialize_foundation_publish_binding",
    "materialize_object_intent",
    "materialize_signing_intent",
    "materialize_mutation_authorization",
    "materialize_route_release",
    "seal_reviewed_sources",
    "validate_authorization",
    "validate_bootstrap_intent",
    "validate_bridge_pin",
    "validate_bridge_cleanup_retire",
    "validate_bridge_cleanup_retire_authorization",
    "validate_foundation_access_readback",
    "validate_foundation_access_update",
    "validate_foundation_publish_binding",
    "validate_foundation_readback",
    "validate_object_intent",
    "validate_object_receipt",
    "validate_mutation_authorization",
    "validate_reviewed_sources",
    "validate_route_release",
    "validate_signing_intent",
    "validate_stack_readback",
]
