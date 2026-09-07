"""Bounded, one-use recovery lanes for the GUG-376 bootstrap route.

This module is deliberately separate from the normal seed provider.  It can
only recover one attested failed initial change-set operation or clean one
attested failed CREATE stack.  It never turns an ambiguous provider result
into permission to retry and it never embeds a permanent broad DeleteStack
authority in the normal creator or executor roles.

The normal provider remains the source of truth for the primary requests and
terminal semantics.  Recovery records bind those immutable requests by digest
and replace only the exact change-set name and idempotency token.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
import os
import re
from typing import Any, Callable, Mapping, Sequence

from tooling import platform_authority_plan_permission_repair_deployment_route as route
from tooling import platform_authority_plan_permission_repair_deployment_route_aws as connected
from tooling.platform_authority_gug376_collision_admission import (
    RouteCollisionAdmissionCapability,
    RouteCollisionAdmissionEffectGrant,
    RouteCollisionAdmissionError,
    consume_route_collision_admission,
    revalidate_route_collision_admission_effect_grant,
)
from tooling.platform_authority_gug376_collision_atomic_admission import (
    invoke_route_collision_admission_loader,
)


PREEXECUTE_FAILURE_RECORD_TYPE = (
    "scanalyze.platform_authority.plan_permission_repair_seed_preexecute_failure.v1"
)
PROTECTION_ROLLBACK_RECORD_TYPE = (
    "scanalyze.platform_authority.plan_permission_repair_seed_protection_rollback.v1"
)
REENTRY_AUTHORIZATION_RECORD_TYPE = (
    "scanalyze.platform_authority.plan_permission_repair_seed_reentry_authorization.v1"
)
REENTRY_INTENT_RECORD_TYPE = (
    "scanalyze.platform_authority.plan_permission_repair_seed_reentry_intent.v1"
)
REENTRY_DISPATCH_RECORD_TYPE = (
    "scanalyze.platform_authority.plan_permission_repair_seed_reentry_dispatch.v1"
)
REENTRY_ATTESTATION_RECORD_TYPE = (
    "scanalyze.platform_authority.plan_permission_repair_seed_reentry_attestation.v1"
)
REENTRY_EXECUTION_AUTHORIZATION_RECORD_TYPE = (
    "scanalyze.platform_authority.plan_permission_repair_seed_reentry_execution_authorization.v1"
)
REENTRY_EXECUTION_INTENT_RECORD_TYPE = (
    "scanalyze.platform_authority.plan_permission_repair_seed_reentry_execution_intent.v1"
)
REENTRY_EXECUTION_RECEIPT_RECORD_TYPE = (
    "scanalyze.platform_authority.plan_permission_repair_seed_reentry_execution_receipt.v1"
)
FAILED_CREATE_STACK_RECORD_TYPE = (
    "scanalyze.platform_authority.plan_permission_repair_seed_failed_create_stack.v1"
)
CLEANUP_AUTHORIZATION_RECORD_TYPE = (
    "scanalyze.platform_authority.plan_permission_repair_seed_cleanup_authorization.v1"
)
CLEANUP_INTENT_RECORD_TYPE = (
    "scanalyze.platform_authority.plan_permission_repair_seed_cleanup_intent.v1"
)
CLEANUP_DISPATCH_RECORD_TYPE = (
    "scanalyze.platform_authority.plan_permission_repair_seed_cleanup_dispatch.v1"
)
CLEANUP_TERMINAL_RECORD_TYPE = (
    "scanalyze.platform_authority.plan_permission_repair_seed_cleanup_terminal.v1"
)
CLAIM_RECORD_TYPE = (
    "scanalyze.platform_authority.plan_permission_repair_seed_recovery_claim.v1"
)

REENTRY_CHANGE_SET_NAMES = {
    "route": "gug376-temporary-route-create-recovery-1",
    "broker": "gug376-route-broker-create-recovery-1",
    route.BROKER_PROTECTION_TARGET: (
        "gug376-route-broker-protection-enable-recovery-1"
    ),
}
REENTRY_CREATION_PHRASES = {
    "route": "I_AUTHORIZE_GUG376_ROUTE_SEED_CREATE_REENTRY_1",
    "broker": "I_AUTHORIZE_GUG376_BROKER_SEED_CREATE_REENTRY_1",
    route.BROKER_PROTECTION_TARGET: (
        "I_AUTHORIZE_GUG376_BROKER_PROTECTION_UPDATE_REENTRY_1"
    ),
}
REENTRY_EXECUTION_PHRASES = {
    "route": "I_AUTHORIZE_GUG376_ROUTE_SEED_EXECUTE_REENTRY_1",
    "broker": "I_AUTHORIZE_GUG376_BROKER_SEED_EXECUTE_REENTRY_1",
    route.BROKER_PROTECTION_TARGET: (
        "I_AUTHORIZE_GUG376_BROKER_PROTECTION_EXECUTE_REENTRY_1"
    ),
}
CLEANUP_AUTHORIZATION_PHRASES = {
    "route": "I_AUTHORIZE_GUG376_ROUTE_SEED_STACK_CLEANUP_1",
    "broker": "I_AUTHORIZE_GUG376_BROKER_SEED_STACK_CLEANUP_1",
}
CLEANUP_ROLE_NAMES = {
    "route": "ScanalyzeGug376RouteSeedCleanup",
    "broker": "ScanalyzeGug376BrokerSeedCleanup",
}
CLEANUP_PROFILE_NAMES = {
    "route": "839393571433_ScanalyzeGug376RouteSeedCleanup",
    "broker": "042360977644_ScanalyzeGug376BrokerSeedCleanup",
}
CLEANUP_IDENTITY_CONTRACTS = {
    "route": {
        "account_id": route.MANAGEMENT_ACCOUNT_ID,
        "permission_set_name": CLEANUP_ROLE_NAMES["route"],
        "role_name": CLEANUP_ROLE_NAMES["route"],
        "profile_name": CLEANUP_PROFILE_NAMES["route"],
        "owner": "artifact-bootstrap-bridge",
        "preexists_target_stack": True,
        "retirement_independent_of_artifact_assignment": True,
    },
    "broker": {
        "account_id": route.AUTHORITY_ACCOUNT_ID,
        "permission_set_name": CLEANUP_ROLE_NAMES["broker"],
        "role_name": CLEANUP_ROLE_NAMES["broker"],
        "profile_name": CLEANUP_PROFILE_NAMES["broker"],
        "owner": "artifact-bootstrap-bridge",
        "preexists_target_stack": True,
        "retirement_independent_of_artifact_assignment": True,
    },
}
BRIDGE_RECOVERY_ROLE_NAME = "ScanalyzeGug376RouteBrokerRecovery"
BRIDGE_RECOVERY_IDENTITY_CONTRACT = {
    "account_id": route.MANAGEMENT_ACCOUNT_ID,
    "role_name": BRIDGE_RECOVERY_ROLE_NAME,
    "owner": "artifact-bootstrap-bridge",
    "preexists_target_stack": True,
    "survives_target_cleanup": True,
    "retirement_operation": "bridge-cleanup-retire",
}
_CLEANUP_PROFILE_CONTRACTS = {
    contract["profile_name"]: (contract["account_id"], contract["role_name"])
    for contract in CLEANUP_IDENTITY_CONTRACTS.values()
}
ROUTE_FIXED_IAM_ROLE_NAMES = (
    "ScanalyzeGug376RouteBrokerCreator",
    "ScanalyzeGug376RouteBrokerExecutor",
)
ROUTE_FIXED_PERMISSION_SET_NAMES = (
    "ScanalyzeGug376BrokerInvoker",
    "ScanalyzeGug376BrokerSeedCreator",
    "ScanalyzeGug376BrokerSeedExec",
)
BROKER_FIXED_TABLE_NAME = (
    "scanalyze-platform-authority-gug376-route-broker-ledger"
)
BROKER_FIXED_KMS_ALIAS = (
    "alias/scanalyze/platform-authority/gug376-route-broker-ledger"
)
BROKER_FIXED_FUNCTION_NAMES = (
    "scanalyze-platform-authority-gug376-route-creator",
    "scanalyze-platform-authority-gug376-route-executor",
    "scanalyze-platform-authority-gug376-route-create-dispatch-recovery",
    "scanalyze-platform-authority-gug376-route-execute-dispatch-recovery",
)
BROKER_FIXED_LOG_GROUP_NAMES = tuple(
    f"/aws/lambda/{name}" for name in BROKER_FIXED_FUNCTION_NAMES
)
BROKER_FIXED_IAM_ROLE_NAMES = (
    "ScanalyzeGug376RouteBrokerCreator",
    "ScanalyzeGug376RouteBrokerExecutor",
    "ScanalyzeGug376RouteCreateDispatchRecovery",
    "ScanalyzeGug376RouteExecuteDispatchRecovery",
)

_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-"
    r"[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)
_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_TOKEN_RE = re.compile(r"^gug376-[0-9a-f]{48}$")
_KMS_KEY_ID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
)
CollisionAdmissionLoader = Callable[..., RouteCollisionAdmissionCapability]
_COLLISION_ADMISSION_FIELDS = frozenset(
    {
        "operation",
        "effect_request_digest",
        "bootstrap_intent_digest",
        "admission_digest",
    }
)
_PRIMARY_COLLISION_FIELDS = frozenset(
    {
        "collision_admission_digest",
        "collision_operation",
        "collision_effect_request_digest",
        "bootstrap_intent_digest",
    }
)
_REENTRY_COLLISION_OPERATIONS = {
    ("route", PREEXECUTE_FAILURE_RECORD_TYPE, "create"): (
        "route-reentry-preexecute:create-change-set"
    ),
    ("route", PREEXECUTE_FAILURE_RECORD_TYPE, "execute"): (
        "route-reentry-preexecute:execute-change-set"
    ),
    ("route", CLEANUP_TERMINAL_RECORD_TYPE, "create"): (
        "route-reentry-cleanup:create-change-set"
    ),
    ("route", CLEANUP_TERMINAL_RECORD_TYPE, "execute"): (
        "route-reentry-cleanup:execute-change-set"
    ),
    ("broker", PREEXECUTE_FAILURE_RECORD_TYPE, "create"): (
        "broker-reentry-preexecute:create-change-set"
    ),
    ("broker", PREEXECUTE_FAILURE_RECORD_TYPE, "execute"): (
        "broker-reentry-preexecute:execute-change-set"
    ),
    ("broker", CLEANUP_TERMINAL_RECORD_TYPE, "create"): (
        "broker-reentry-cleanup:create-change-set"
    ),
    ("broker", CLEANUP_TERMINAL_RECORD_TYPE, "execute"): (
        "broker-reentry-cleanup:execute-change-set"
    ),
    (route.BROKER_PROTECTION_TARGET, PROTECTION_ROLLBACK_RECORD_TYPE, "create"): (
        "broker-protection-reentry-rollback:create-change-set"
    ),
    (route.BROKER_PROTECTION_TARGET, PROTECTION_ROLLBACK_RECORD_TYPE, "execute"): (
        "broker-protection-reentry-rollback:execute-change-set"
    ),
}
_PREEXECUTE_FAILURE_FIELDS = frozenset(
    {
        "schema_version",
        "record_type",
        "source_commit",
        "target",
        "intent_digest",
        "primary_dispatch_digest",
        "primary_create_request_digest",
        "primary_claim_digest",
        "primary_cloudtrail_event_digest",
        "account_id",
        "stack_arn",
        "change_set_arn",
        "create_request_id",
        "status",
        "execution_status",
        "status_reason_digest",
        "stack_status",
        "resource_count",
        "resources_digest",
        "attested_at",
        "aws_calls",
        "aws_mutations",
        "retry_permitted",
        "production_authorized",
        "production_status",
        "attestation_digest",
    }
)
_PROTECTION_ROLLBACK_FIELDS = frozenset(
    {
        "schema_version",
        "record_type",
        "source_commit",
        "target",
        "intent_digest",
        "execution_intent_digest",
        "execution_receipt_digest",
        "execution_claim_digest",
        "execute_cloudtrail_event_digest",
        "account_id",
        "stack_arn",
        "change_set_arn",
        "execute_request_id",
        "stack_status",
        "resource_count",
        "resources_digest",
        "ledger_live_properties_digest",
        "ledger_deletion_protection_enabled",
        "attested_at",
        "aws_calls",
        "aws_mutations",
        "retry_permitted",
        "production_authorized",
        "production_status",
        "attestation_digest",
    }
)
_CLEANUP_TERMINAL_FIELDS = frozenset(
    {
        "schema_version",
        "record_type",
        "source_commit",
        "target",
        "account_id",
        "execution_lane",
        "cleanup_intent_digest",
        "cleanup_dispatch_digest",
        "parent_intent_digest",
        "failed_stack_attestation_digest",
        "failed_resources",
        "failed_resources_digest",
        "delete_cloudtrail_event_digest",
        "stack_arn",
        "stack_terminal_observation",
        "fixed_stack_name",
        "fixed_stack_name_absent",
        "survivor_check_count",
        "survivor_evidence_digest",
        "no_active_survivors",
        "scheduled_inert_survivor_count",
        "scheduled_inert_survivors",
        "scheduled_inert_survivors_digest",
        "attested_at",
        "aws_calls",
        "aws_mutations",
        "retry_permitted",
        "production_authorized",
        "production_status",
        "attestation_digest",
    }
)
_FAILED_STACK_FIELDS = frozenset(
    {
        "schema_version",
        "record_type",
        "source_commit",
        "target",
        "intent_digest",
        "execution_intent_digest",
        "reentry_source_failure_record_type",
        "execution_receipt_digest",
        "execution_claim_digest",
        "execute_cloudtrail_event_digest",
        "account_id",
        "stack_arn",
        "change_set_arn",
        "execute_request_id",
        "stack_status",
        "resource_count",
        "resources",
        "resources_digest",
        "attested_at",
        "aws_calls",
        "aws_mutations",
        "retry_permitted",
        "production_authorized",
        "production_status",
        "attestation_digest",
    }
)
_REENTRY_EXECUTION_RECEIPT_FIELDS = frozenset(
    {
        "schema_version",
        "record_type",
        "source_commit",
        "target",
        "account_id",
        "execution_intent_digest",
        "collision_admission",
        "stack_arn",
        "change_set_arn",
        "execute_request_id",
        "dispatched_at",
        "attempt",
        "aws_mutations",
        "retry_permitted",
        "production_authorized",
        "production_status",
        "receipt_digest",
    }
)
_CLEANUP_DISPATCH_FIELDS = frozenset(
    {
        "schema_version",
        "record_type",
        "source_commit",
        "target",
        "account_id",
        "execution_lane",
        "cleanup_intent_digest",
        "failed_stack_attestation_digest",
        "failed_resources_digest",
        "stack_arn",
        "delete_request_id",
        "dispatched_at",
        "attempt",
        "aws_mutations",
        "retry_permitted",
        "production_authorized",
        "production_status",
        "dispatch_digest",
    }
)
_REENTRY_DISPATCH_FIELDS = frozenset(
    {
        "schema_version",
        "record_type",
        "source_commit",
        "target",
        "account_id",
        "reentry_intent_digest",
        "create_request_digest",
        "collision_admission",
        "stack_arn",
        "change_set_arn",
        "create_request_id",
        "dispatched_at",
        "attempt",
        "aws_mutations",
        "retry_permitted",
        "production_authorized",
        "production_status",
        "dispatch_digest",
    }
)
_REENTRY_ATTESTATION_FIELDS = frozenset(
    {
        "schema_version",
        "record_type",
        "source_commit",
        "target",
        "account_id",
        "parent_intent_digest",
        "reentry_intent_digest",
        "create_request_digest",
        "collision_admission",
        "dispatch_digest",
        "stack_arn",
        "change_set_arn",
        "create_request_id",
        "cloudtrail_event_digest",
        "describe_change_set_digest",
        "template_digest",
        "changes_digest",
        "status",
        "execution_status",
        "attested_at",
        "attempt",
        "aws_calls",
        "aws_mutations",
        "retry_permitted",
        "production_authorized",
        "production_status",
        "attestation_digest",
    }
)


class DeploymentRecoveryError(RuntimeError):
    """Stable fail-closed recovery error."""

    def __init__(self, code: str, *, uncertain: bool = False) -> None:
        self.code = code
        self.uncertain = uncertain
        super().__init__(f"GUG376_DEPLOYMENT_RECOVERY_BLOCKED:{code}")


def _stamp(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise DeploymentRecoveryError("CLOCK_INVALID")
    return (
        value.astimezone(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def _time(value: Any, code: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise DeploymentRecoveryError(code)
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise DeploymentRecoveryError(code) from exc
    if parsed.microsecond:
        raise DeploymentRecoveryError(code)
    return parsed


def _verify_seal(value: Mapping[str, Any], field: str, code: str) -> str:
    observed = value.get(field)
    if not isinstance(observed, str) or _DIGEST_RE.fullmatch(observed) is None:
        raise DeploymentRecoveryError(code)
    body = dict(value)
    body.pop(field, None)
    if route.digest_value(body) != observed:
        raise DeploymentRecoveryError(code)
    return observed


def _reentry_collision_operation(
    *, target: str, failure_record_type: str, effect: str
) -> str:
    """Select one non-interchangeable admission operation."""

    operation = _REENTRY_COLLISION_OPERATIONS.get(
        (target, failure_record_type, effect)
    )
    if operation is None:
        raise DeploymentRecoveryError("COLLISION_ADMISSION_OPERATION_INVALID")
    return operation


def _validate_collision_admission_binding(
    value: object,
    *,
    operation: str,
    effect_request: Mapping[str, Any],
    bootstrap_intent_digest: str,
) -> dict[str, str]:
    effect_request_digest = route.digest_value(effect_request)
    if (
        not isinstance(value, Mapping)
        or set(value) != _COLLISION_ADMISSION_FIELDS
        or value.get("operation") != operation
        or value.get("effect_request_digest") != effect_request_digest
        or value.get("bootstrap_intent_digest") != bootstrap_intent_digest
        or _DIGEST_RE.fullmatch(str(value.get("admission_digest", ""))) is None
    ):
        raise DeploymentRecoveryError("COLLISION_ADMISSION_BINDING_INVALID")
    return {
        "operation": operation,
        "effect_request_digest": effect_request_digest,
        "bootstrap_intent_digest": bootstrap_intent_digest,
        "admission_digest": str(value["admission_digest"]),
    }


def _validate_reentry_collision_binding(
    value: object,
    *,
    target: str,
    effect: str,
    effect_request: Mapping[str, Any],
    bootstrap_intent_digest: str,
    failure_record_type: str | None = None,
) -> dict[str, str]:
    if failure_record_type is None:
        observed_operation = (
            value.get("operation") if isinstance(value, Mapping) else None
        )
        allowed = {
            operation
            for (
                candidate_target,
                _record_type,
                candidate_effect,
            ), operation in _REENTRY_COLLISION_OPERATIONS.items()
            if candidate_target == target and candidate_effect == effect
        }
        if observed_operation not in allowed:
            raise DeploymentRecoveryError(
                "COLLISION_ADMISSION_BINDING_INVALID"
            )
        operation = str(observed_operation)
    else:
        operation = _reentry_collision_operation(
            target=target,
            failure_record_type=failure_record_type,
            effect=effect,
        )
    return _validate_collision_admission_binding(
        value,
        operation=operation,
        effect_request=effect_request,
        bootstrap_intent_digest=bootstrap_intent_digest,
    )


def _validate_primary_collision_binding(
    value: Mapping[str, Any],
    *,
    action: str,
    target: str,
    effect_request_digest: str,
) -> dict[str, str]:
    try:
        return connected._validate_persisted_collision_binding(
            value,
            action=action,
            target=target,
            effect_request_digest=effect_request_digest,
        )
    except connected.ConnectedRouteError as exc:
        raise DeploymentRecoveryError(
            "COLLISION_ADMISSION_BINDING_INVALID"
        ) from exc


def _normalized_clock(clock: Callable[[], datetime]) -> datetime:
    value = clock()
    if value.tzinfo is None or value.utcoffset() is None:
        raise DeploymentRecoveryError("CLOCK_INVALID")
    return value.astimezone(timezone.utc).replace(microsecond=0)


def _recovery_window(
    intent: Mapping[str, Any], clock: Callable[[], datetime]
) -> datetime:
    now = _normalized_clock(clock)
    if not _time(intent["route_not_before"], "RECOVERY_WINDOW_INVALID") <= now < _time(
        intent["recovery_not_after"], "RECOVERY_WINDOW_INVALID"
    ):
        raise DeploymentRecoveryError("RECOVERY_WINDOW_CLOSED")
    return now


def _mutation_window(
    intent: Mapping[str, Any], clock: Callable[[], datetime]
) -> datetime:
    now = _normalized_clock(clock)
    cutoff = _time(intent["route_not_after"], "RECOVERY_WINDOW_INVALID") - timedelta(
        seconds=route.MUTATION_COMPLETION_RESERVE_SECONDS
    )
    if not _time(intent["route_not_before"], "RECOVERY_WINDOW_INVALID") <= now < cutoff:
        raise DeploymentRecoveryError("RECOVERY_MUTATION_WINDOW_CLOSED")
    return now


def _cleanup_window(
    intent: Mapping[str, Any], clock: Callable[[], datetime]
) -> datetime:
    """Admit exact failed-stack deletion through the recovery horizon.

    A CREATE can enter ROLLBACK_COMPLETE or DELETE_FAILED after normal
    mutation admission closes.  Cleanup therefore has its own bounded window;
    it is still one-use, exact-stack, separately authorized, and exclusive of
    RetainResources, RoleARN, or force deletion.
    """

    return _recovery_window(intent, clock)


def _require_active_authorization(
    intent: Mapping[str, Any],
    observed_at: datetime,
    *,
    invalid_code: str,
    inactive_code: str,
) -> None:
    if not _time(
        intent["authorization_not_before"], invalid_code
    ) <= observed_at < _time(intent["authorization_expires_at"], invalid_code):
        raise DeploymentRecoveryError(inactive_code)


def _resample_authorized_mutation_time(
    intent: Mapping[str, Any],
    clock: Callable[[], datetime],
    *,
    previous_at: datetime,
    invalid_code: str,
    inactive_code: str,
) -> datetime:
    """Recheck every temporal mutation gate against one fresh clock sample."""

    observed_at = _normalized_clock(clock)
    if observed_at < previous_at:
        raise DeploymentRecoveryError("CLOCK_REGRESSED")
    observed_at = _mutation_window(intent, lambda: observed_at)
    _require_active_authorization(
        intent,
        observed_at,
        invalid_code=invalid_code,
        inactive_code=inactive_code,
    )
    return observed_at


def _target_spec(intent: Mapping[str, Any], target: str) -> Mapping[str, Any]:
    if target not in route.TARGETS:
        raise DeploymentRecoveryError("TARGET_INVALID")
    spec = intent["targets"].get(target)
    if not isinstance(spec, Mapping):
        raise DeploymentRecoveryError("TARGET_INVALID")
    return spec


def _stack_name(target: str) -> str:
    if target == "route":
        return route.ROUTE_STACK_NAME
    if target in {"broker", route.BROKER_PROTECTION_TARGET}:
        return route.BROKER_STACK_NAME
    raise DeploymentRecoveryError("TARGET_INVALID")


def _account_id(target: str) -> str:
    if target == "route":
        return route.MANAGEMENT_ACCOUNT_ID
    if target in {"broker", route.BROKER_PROTECTION_TARGET}:
        return route.AUTHORITY_ACCOUNT_ID
    raise DeploymentRecoveryError("TARGET_INVALID")


def _execution_lane(
    *, target: str, change_set_arn: Any
) -> str:
    """Return the finite cleanup lane for one exact executed change set."""

    primary_name = (
        route.ROUTE_CHANGE_SET_NAME
        if target == "route"
        else route.BROKER_CHANGE_SET_NAME
    )
    try:
        _full_arn(
            change_set_arn,
            account_id=_account_id(target),
            kind="changeSet",
            name=primary_name,
        )
    except DeploymentRecoveryError:
        try:
            _full_arn(
                change_set_arn,
                account_id=_account_id(target),
                kind="changeSet",
                name=REENTRY_CHANGE_SET_NAMES[target],
            )
        except DeploymentRecoveryError as exc:
            raise DeploymentRecoveryError(
                "FAILED_EXECUTION_LANE_INVALID"
            ) from exc
        return "reentry"
    return "primary"


def _caller_arn_matches_phase(
    caller_arn: Any, *, target: str, phase: str
) -> bool:
    if not isinstance(caller_arn, str):
        return False
    account = _account_id(target)
    if phase == "cleanup":
        if target not in CLEANUP_ROLE_NAMES:
            return False
        role_name = CLEANUP_ROLE_NAMES[target]
    elif target == "route":
        role_name = "AWSAdministratorAccess"
    elif target in {"broker", route.BROKER_PROTECTION_TARGET}:
        if phase == "creator":
            role_name = "ScanalyzeGug376BrokerSeedCreator"
        elif phase == "executor":
            role_name = "ScanalyzeGug376BrokerSeedExec"
        else:
            return False
    else:
        return False
    return (
        re.fullmatch(
            rf"arn:aws:sts::{account}:assumed-role/"
            rf"AWSReservedSSO_{re.escape(role_name)}_[0-9A-Fa-f]{{16}}/"
            rf"[A-Za-z0-9+=,.@_-]{{1,64}}",
            caller_arn,
        )
        is not None
    )


def _full_arn(value: Any, *, account_id: str, kind: str, name: str) -> str:
    try:
        return route._full_arn(value, account_id=account_id, kind=kind, name=name)
    except route.RouteSeedError as exc:
        raise DeploymentRecoveryError("PROVIDER_ARN_INVALID") from exc


def _strict_json(raw: Any, code: str) -> Mapping[str, Any]:
    if not isinstance(raw, str):
        raise DeploymentRecoveryError(code)
    try:
        return connected._strict_json_mapping(raw)
    except ValueError as exc:
        raise DeploymentRecoveryError(code) from exc


def _cloudtrail_request(request: Mapping[str, Any]) -> dict[str, Any]:
    return connected._create_cloudtrail_params(request)


def _lookup(
    client: Any,
    *,
    event_name: str,
    start: datetime,
    end: datetime,
    code: str,
) -> tuple[list[Mapping[str, Any]], int]:
    try:
        return connected._lookup_cloudtrail_events(
            client,
            request={
                "LookupAttributes": [
                    {"AttributeKey": "EventName", "AttributeValue": event_name}
                ],
                "StartTime": start,
                "EndTime": end,
                "MaxResults": 50,
            },
            error_code=code,
        )
    except connected.ConnectedRouteError as exc:
        raise DeploymentRecoveryError(exc.code) from exc


def _primary_claim_key(intent: Mapping[str, Any], target: str) -> str:
    spec = _target_spec(intent, target)
    return (
        f"create:{target}:{intent['intent_digest']}:"
        f"{spec['create_request_digest']}"
    )


def _primary_claim(
    claims: connected.OExclClaimStore,
    *,
    intent: Mapping[str, Any],
    target: str,
) -> dict[str, Any]:
    spec = _target_spec(intent, target)
    request = spec["create_request"]
    try:
        claim = claims.read_claim(_primary_claim_key(intent, target))
    except connected.ConnectedRouteError as exc:
        raise DeploymentRecoveryError(exc.code) from exc
    fields = {
        "schema_version",
        "record_type",
        "operation",
        "target",
        "intent_digest",
        "request_digest",
        "creation_authorization",
        "creation_authorization_digest",
        "client_token",
        "stack_name",
        "change_set_name",
        "caller_arn_digest",
        "claimed_at",
        "retry_permitted",
        "production_authorized",
    } | set(_PRIMARY_COLLISION_FIELDS)
    claimed_at = _time(claim.get("claimed_at"), "PRIMARY_CLAIM_INVALID")
    try:
        authorization = route.validate_creation_authorization(
            claim.get("creation_authorization"),
            seed_intent=intent,
            target=target,
            now=claimed_at,
        )
    except route.RouteSeedError as exc:
        raise DeploymentRecoveryError("PRIMARY_CLAIM_INVALID") from exc
    _validate_primary_collision_binding(
        claim,
        action="create",
        target=target,
        effect_request_digest=spec["create_request_digest"],
    )
    if (
        set(claim) != fields
        or claim.get("schema_version") != 1
        or claim.get("record_type") != connected.CLAIM_RECORD_TYPE
        or claim.get("operation") != "CreateChangeSet"
        or claim.get("target") != target
        or claim.get("intent_digest") != intent["intent_digest"]
        or claim.get("request_digest") != spec["create_request_digest"]
        or claim.get("creation_authorization_digest")
        != authorization["authorization_digest"]
        or claim.get("client_token") != request["ClientToken"]
        or claim.get("stack_name") != request["StackName"]
        or claim.get("change_set_name") != request["ChangeSetName"]
        or _DIGEST_RE.fullmatch(str(claim.get("caller_arn_digest", ""))) is None
        or claim.get("retry_permitted") is not False
        or claim.get("production_authorized") is not False
    ):
        raise DeploymentRecoveryError("PRIMARY_CLAIM_INVALID")
    return claim


def _validate_primary_dispatch(
    value: Mapping[str, Any], *, intent: Mapping[str, Any], target: str
) -> dict[str, Any]:
    try:
        dispatch = connected.validate_dispatch(value, seed_intent=intent)
    except connected.ConnectedRouteError as exc:
        raise DeploymentRecoveryError("PRIMARY_DISPATCH_INVALID") from exc
    if dispatch["target"] != target:
        raise DeploymentRecoveryError("PRIMARY_DISPATCH_INVALID")
    return dispatch


def _create_event_digest(
    trail: Any,
    *,
    intent: Mapping[str, Any],
    target: str,
    claim: Mapping[str, Any],
    dispatch: Mapping[str, Any],
    request: Mapping[str, Any],
    now: datetime,
) -> tuple[str, int]:
    events, pages = _lookup(
        trail,
        event_name="CreateChangeSet",
        start=_time(claim["claimed_at"], "PRIMARY_CLAIM_INVALID"),
        end=now,
        code="PRIMARY_CREATE_CLOUDTRAIL_AMBIGUOUS",
    )
    expected = _cloudtrail_request(request)
    matches: list[dict[str, Any]] = []
    for envelope in events:
        event = _strict_json(
            envelope.get("CloudTrailEvent"), "PRIMARY_CREATE_CLOUDTRAIL_INVALID"
        )
        if event.get("requestID") != dispatch["create_request_id"]:
            continue
        event_time = _time(
            event.get("eventTime"), "PRIMARY_CREATE_CLOUDTRAIL_INVALID"
        )
        identity = event.get("userIdentity") or {}
        params = event.get("requestParameters") or {}
        result = event.get("responseElements") or {}
        caller = identity.get("arn") if isinstance(identity, Mapping) else None
        if (
            event.get("eventSource") != "cloudformation.amazonaws.com"
            or event.get("eventName") != "CreateChangeSet"
            or event.get("awsRegion") != route.REGION
            or event.get("recipientAccountId") != dispatch["account_id"]
            or event.get("readOnly") is not False
            or event.get("errorCode") is not None
            or event.get("errorMessage") is not None
            or not isinstance(caller, str)
            or not _caller_arn_matches_phase(
                caller, target=target, phase="creator"
            )
            or route.digest_value(caller) != claim["caller_arn_digest"]
            or params != expected
            or "roleARN" in params
            or result.get("id") != dispatch["change_set_arn"]
            or result.get("stackId") != dispatch["stack_arn"]
            or not _time(dispatch["dispatched_at"], "PRIMARY_DISPATCH_INVALID")
            <= event_time
            <= now
            or _UUID_RE.fullmatch(str(event.get("eventID", ""))) is None
        ):
            raise DeploymentRecoveryError("PRIMARY_CREATE_CLOUDTRAIL_INVALID")
        matches.append(
            {
                "event_id": event["eventID"],
                "event_time": _stamp(event_time),
                "request_id": event["requestID"],
                "request_digest": route.digest_value(expected),
                "stack_arn": dispatch["stack_arn"],
                "change_set_arn": dispatch["change_set_arn"],
            }
        )
    if len(matches) != 1:
        raise DeploymentRecoveryError("PRIMARY_CREATE_CLOUDTRAIL_MISSING")
    return route.digest_value(matches[0]), pages


def _validate_primary_failure_journal(
    claims: connected.OExclClaimStore,
    *,
    intent: Mapping[str, Any],
    failure_attestation: Mapping[str, Any],
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    """Reopen the immutable primary CREATE journal before recovery STS."""

    if failure_attestation.get("record_type") != PREEXECUTE_FAILURE_RECORD_TYPE:
        # Other failure classes need their own service-native proof graph; a
        # locally re-sealed terminal record is never enough to admit a write.
        raise DeploymentRecoveryError("FAILURE_REVALIDATION_UNSUPPORTED")
    target, _failure_digest = _failure_binding(failure_attestation)
    failure = json.loads(route.canonical_json(failure_attestation))
    if (
        failure.get("source_commit") != intent["source_commit"]
        or failure.get("intent_digest") != intent["intent_digest"]
        or failure.get("primary_create_request_digest")
        != _target_spec(intent, target)["create_request_digest"]
    ):
        raise DeploymentRecoveryError(
            "FAILURE_ATTESTATION_JOURNAL_BINDING_INVALID"
        )
    claim = _primary_claim(claims, intent=intent, target=target)
    try:
        persisted = claims.read_result(_primary_claim_key(intent, target))
    except connected.ConnectedRouteError as exc:
        raise DeploymentRecoveryError(exc.code) from exc
    dispatch = _validate_primary_dispatch(
        persisted, intent=intent, target=target
    )
    if (
        route.digest_value(claim) != failure["primary_claim_digest"]
        or any(
            claim[field] != dispatch[field]
            for field in _PRIMARY_COLLISION_FIELDS
        )
        or dispatch["dispatch_digest"]
        != failure["primary_dispatch_digest"]
        or dispatch["stack_arn"] != failure["stack_arn"]
        or dispatch["change_set_arn"] != failure["change_set_arn"]
        or dispatch["create_request_id"] != failure["create_request_id"]
        or dispatch["create_request_digest"]
        != failure["primary_create_request_digest"]
        or _time(
            dispatch["dispatched_at"],
            "FAILURE_ATTESTATION_JOURNAL_BINDING_INVALID",
        )
        > _time(
            failure["attested_at"],
            "FAILURE_ATTESTATION_JOURNAL_BINDING_INVALID",
        )
    ):
        raise DeploymentRecoveryError(
            "FAILURE_ATTESTATION_JOURNAL_BINDING_INVALID"
        )
    return failure, claim, dispatch


def _revalidate_primary_failure_live(
    *,
    cfn: Any,
    trail: Any,
    intent: Mapping[str, Any],
    failure: Mapping[str, Any],
    claim: Mapping[str, Any],
    dispatch: Mapping[str, Any],
    observed_at: datetime,
) -> None:
    """Reconstruct the failed CREATE evidence from AWS before reentry."""

    target = str(failure["target"])
    spec = _target_spec(intent, target)
    request = spec["create_request"]
    response = cfn.describe_change_set(
        StackName=dispatch["stack_arn"],
        ChangeSetName=dispatch["change_set_arn"],
    )
    reason = response.get("StatusReason") if isinstance(response, Mapping) else None
    if (
        not isinstance(response, Mapping)
        or response.get("NextToken") is not None
        or response.get("ChangeSetId") != dispatch["change_set_arn"]
        or response.get("StackId") != dispatch["stack_arn"]
        or response.get("StackName") != spec["stack_name"]
        or response.get("ChangeSetName") != spec["change_set_name"]
        or response.get("Status") != "FAILED"
        or response.get("ExecutionStatus") != "UNAVAILABLE"
        or not isinstance(reason, str)
        or not reason.strip()
        or response.get("Description") != request["Description"]
        or response.get("ChangeSetType") != "CREATE"
        or not connected._change_set_parameters_match(
            response.get("Parameters"),
            request.get("Parameters", []),
            target=target,
        )
        or response.get("Capabilities", []) != request["Capabilities"]
        or response.get("Tags", []) != request["Tags"]
        or response.get("IncludeNestedStacks", False) is not False
        or response.get("NotificationARNs", []) != []
        or response.get("RollbackConfiguration", {})
        != request["RollbackConfiguration"]
        or response.get("OnStackFailure") != "DELETE"
        or "RoleARN" in response
        or "ResourcesToImport" in response
    ):
        raise DeploymentRecoveryError("PRIMARY_FAILURE_READBACK_INVALID")
    stack, _stack_calls = _read_stack(
        cfn,
        stack_arn=dispatch["stack_arn"],
        code="PRIMARY_FAILURE_STACK_INVALID",
    )
    if (
        stack.get("StackId") != dispatch["stack_arn"]
        or stack.get("StackName") != spec["stack_name"]
        or stack.get("StackStatus") != "REVIEW_IN_PROGRESS"
    ):
        raise DeploymentRecoveryError("PRIMARY_FAILURE_STACK_INVALID")
    resources_response = cfn.list_stack_resources(
        StackName=dispatch["stack_arn"]
    )
    resources = _resource_projection(
        resources_response, "PRIMARY_FAILURE_RESOURCES_INVALID"
    )
    if resources:
        raise DeploymentRecoveryError("PRIMARY_FAILURE_RESOURCES_PRESENT")
    cloudtrail_digest, _pages = _create_event_digest(
        trail,
        intent=intent,
        target=target,
        claim=claim,
        dispatch=dispatch,
        request=request,
        now=observed_at,
    )
    if (
        failure.get("status") != "FAILED"
        or failure.get("execution_status") != "UNAVAILABLE"
        or failure.get("stack_status") != "REVIEW_IN_PROGRESS"
        or failure.get("resource_count") != 0
        or failure.get("resources_digest") != route.digest_value([])
        or failure.get("status_reason_digest") != route.digest_value(reason)
        or failure.get("primary_cloudtrail_event_digest")
        != cloudtrail_digest
        or _time(
            failure.get("attested_at"),
            "FAILURE_ATTESTATION_LIVE_BINDING_INVALID",
        )
        > observed_at
    ):
        raise DeploymentRecoveryError(
            "FAILURE_ATTESTATION_LIVE_BINDING_INVALID"
        )


def _validate_cleanup_terminal_journal(
    claims: connected.OExclClaimStore,
    *,
    intent: Mapping[str, Any],
    failure_attestation: Mapping[str, Any],
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], dict[str, Any]]:
    target, _failure_digest = _failure_binding(failure_attestation)
    terminal = json.loads(route.canonical_json(failure_attestation))
    lane = terminal.get("execution_lane")
    if (
        terminal.get("record_type") != CLEANUP_TERMINAL_RECORD_TYPE
        or terminal.get("source_commit") != intent["source_commit"]
        or terminal.get("parent_intent_digest") != intent["intent_digest"]
        or lane not in {"primary", "reentry"}
    ):
        raise DeploymentRecoveryError(
            "FAILURE_ATTESTATION_JOURNAL_BINDING_INVALID"
        )
    key = f"cleanup:{target}:{intent['intent_digest']}:{lane}"
    try:
        dispatch = claims.read_result(key)
        claim = claims.read_claim(key)
    except connected.ConnectedRouteError as exc:
        raise DeploymentRecoveryError(exc.code) from exc
    _verify_seal(
        dispatch, "dispatch_digest", "CLEANUP_DISPATCH_DIGEST_INVALID"
    )
    request_seed = {
        "record_type": CLEANUP_INTENT_RECORD_TYPE,
        "target": target,
        "execution_lane": lane,
        "failed_stack_attestation_digest": terminal[
            "failed_stack_attestation_digest"
        ],
        "attempt": 1,
    }
    request = {
        "StackName": terminal["stack_arn"],
        "ClientRequestToken": (
            "gug376-" + route.digest_value(request_seed)[7:55]
        ),
    }
    claim_fields = {
        "schema_version",
        "record_type",
        "operation",
        "target",
        "execution_lane",
        "attempt",
        "cleanup_intent_digest",
        "failed_stack_attestation_digest",
        "failed_resources_digest",
        "request_digest",
        "client_request_token",
        "stack_arn",
        "caller_arn_digest",
        "claimed_at",
        "retry_permitted",
        "production_authorized",
    }
    claimed_at = _time(
        claim.get("claimed_at"),
        "FAILURE_ATTESTATION_JOURNAL_BINDING_INVALID",
    )
    dispatched_at = _time(
        dispatch.get("dispatched_at"),
        "FAILURE_ATTESTATION_JOURNAL_BINDING_INVALID",
    )
    attested_at = _time(
        terminal.get("attested_at"),
        "FAILURE_ATTESTATION_JOURNAL_BINDING_INVALID",
    )
    if (
        set(dispatch) != _CLEANUP_DISPATCH_FIELDS
        or dispatch.get("schema_version") != 1
        or dispatch.get("record_type") != CLEANUP_DISPATCH_RECORD_TYPE
        or dispatch.get("source_commit") != intent["source_commit"]
        or dispatch.get("target") != target
        or dispatch.get("account_id") != _account_id(target)
        or dispatch.get("execution_lane") != lane
        or dispatch.get("cleanup_intent_digest")
        != terminal["cleanup_intent_digest"]
        or dispatch.get("failed_stack_attestation_digest")
        != terminal["failed_stack_attestation_digest"]
        or dispatch.get("failed_resources_digest")
        != terminal["failed_resources_digest"]
        or dispatch.get("dispatch_digest")
        != terminal["cleanup_dispatch_digest"]
        or dispatch.get("stack_arn") != terminal["stack_arn"]
        or _UUID_RE.fullmatch(
            str(dispatch.get("delete_request_id", ""))
        )
        is None
        or dispatch.get("attempt") != 1
        or dispatch.get("aws_mutations") != 1
        or dispatch.get("retry_permitted") is not False
        or dispatch.get("production_authorized") is not False
        or dispatch.get("production_status") != route.PRODUCTION_STATUS
        or set(claim) != claim_fields
        or claim.get("schema_version") != 1
        or claim.get("record_type") != CLAIM_RECORD_TYPE
        or claim.get("operation") != "DeleteStack"
        or claim.get("target") != target
        or claim.get("execution_lane") != lane
        or claim.get("attempt") != 1
        or claim.get("cleanup_intent_digest")
        != terminal["cleanup_intent_digest"]
        or claim.get("failed_stack_attestation_digest")
        != terminal["failed_stack_attestation_digest"]
        or claim.get("failed_resources_digest")
        != terminal["failed_resources_digest"]
        or claim.get("request_digest") != route.digest_value(request)
        or claim.get("client_request_token")
        != request["ClientRequestToken"]
        or claim.get("stack_arn") != terminal["stack_arn"]
        or _DIGEST_RE.fullmatch(
            str(claim.get("caller_arn_digest", ""))
        )
        is None
        or claim.get("retry_permitted") is not False
        or claim.get("production_authorized") is not False
        or not _time(
            intent["route_not_before"],
            "FAILURE_ATTESTATION_JOURNAL_BINDING_INVALID",
        )
        <= claimed_at
        <= dispatched_at
        <= attested_at
        < _time(
            intent["recovery_not_after"],
            "FAILURE_ATTESTATION_JOURNAL_BINDING_INVALID",
        )
    ):
        raise DeploymentRecoveryError(
            "FAILURE_ATTESTATION_JOURNAL_BINDING_INVALID"
        )
    return terminal, dict(claim), dict(dispatch), request


def _validate_protection_failure_journal(
    claims: connected.OExclClaimStore,
    *,
    intent: Mapping[str, Any],
    failure_attestation: Mapping[str, Any],
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], dict[str, Any]]:
    target, _failure_digest = _failure_binding(failure_attestation)
    failure = json.loads(route.canonical_json(failure_attestation))
    if (
        target != route.BROKER_PROTECTION_TARGET
        or failure.get("source_commit") != intent["source_commit"]
        or failure.get("intent_digest") != intent["intent_digest"]
    ):
        raise DeploymentRecoveryError(
            "FAILURE_ATTESTATION_JOURNAL_BINDING_INVALID"
        )
    operation_digest = route.digest_value(
        {
            "record_type": (
                "scanalyze.platform_authority."
                "plan_permission_repair_execute_operation.v1"
            ),
            "source_commit": failure["source_commit"],
            "target": target,
            "account_id": failure["account_id"],
            "stack_arn": failure["stack_arn"],
            "change_set_arn": failure["change_set_arn"],
        }
    )
    key = f"execute:{target}:{operation_digest}"
    try:
        receipt = claims.read_result(key)
        claim = claims.read_claim(key)
    except connected.ConnectedRouteError as exc:
        raise DeploymentRecoveryError(exc.code) from exc
    _verify_seal(
        receipt, "receipt_digest", "EXECUTION_RECEIPT_DIGEST_INVALID"
    )
    request = {
        "StackName": failure["stack_arn"],
        "ChangeSetName": failure["change_set_arn"],
        "ClientRequestToken": "gug376-" + operation_digest[7:55],
        "DisableRollback": False,
    }
    receipt_fields = (
        _REENTRY_EXECUTION_RECEIPT_FIELDS
        - {"attempt", "collision_admission"}
    ) | _PRIMARY_COLLISION_FIELDS
    claim_fields = {
        "schema_version",
        "record_type",
        "operation",
        "target",
        "execution_intent_digest",
        "request_digest",
        "client_request_token",
        "stack_arn",
        "change_set_arn",
        "caller_arn_digest",
        "claimed_at",
        "retry_permitted",
        "production_authorized",
    } | set(_PRIMARY_COLLISION_FIELDS)
    claim_collision_binding = _validate_primary_collision_binding(
        claim,
        action="execute",
        target=target,
        effect_request_digest=route.digest_value(request),
    )
    receipt_collision_binding = _validate_primary_collision_binding(
        receipt,
        action="execute",
        target=target,
        effect_request_digest=route.digest_value(request),
    )
    claimed_at = _time(
        claim.get("claimed_at"),
        "FAILURE_ATTESTATION_JOURNAL_BINDING_INVALID",
    )
    dispatched_at = _time(
        receipt.get("dispatched_at"),
        "FAILURE_ATTESTATION_JOURNAL_BINDING_INVALID",
    )
    if (
        set(receipt) != receipt_fields
        or receipt.get("schema_version") != 1
        or receipt.get("record_type")
        != connected.EXECUTION_RECEIPT_RECORD_TYPE
        or receipt.get("source_commit") != intent["source_commit"]
        or receipt.get("target") != target
        or receipt.get("account_id") != route.AUTHORITY_ACCOUNT_ID
        or receipt.get("execution_intent_digest")
        != failure["execution_intent_digest"]
        or receipt.get("receipt_digest")
        != failure["execution_receipt_digest"]
        or receipt.get("stack_arn") != failure["stack_arn"]
        or receipt.get("change_set_arn") != failure["change_set_arn"]
        or receipt.get("execute_request_id")
        != failure["execute_request_id"]
        or receipt.get("aws_mutations") != 1
        or receipt.get("retry_permitted") is not False
        or receipt.get("production_authorized") is not False
        or receipt.get("production_status") != route.PRODUCTION_STATUS
        or set(claim) != claim_fields
        or claim.get("schema_version") != 1
        or claim.get("record_type") != connected.CLAIM_RECORD_TYPE
        or claim.get("operation") != "ExecuteChangeSet"
        or claim.get("target") != target
        or claim.get("execution_intent_digest")
        != failure["execution_intent_digest"]
        or claim.get("request_digest") != route.digest_value(request)
        or claim.get("client_request_token")
        != request["ClientRequestToken"]
        or claim.get("stack_arn") != failure["stack_arn"]
        or claim.get("change_set_arn") != failure["change_set_arn"]
        or claim_collision_binding != receipt_collision_binding
        or route.digest_value(claim) != failure["execution_claim_digest"]
        or _DIGEST_RE.fullmatch(
            str(claim.get("caller_arn_digest", ""))
        )
        is None
        or claim.get("retry_permitted") is not False
        or claim.get("production_authorized") is not False
        or not _time(
            intent["route_not_before"],
            "FAILURE_ATTESTATION_JOURNAL_BINDING_INVALID",
        )
        <= claimed_at
        <= dispatched_at
        <= _time(
            failure["attested_at"],
            "FAILURE_ATTESTATION_JOURNAL_BINDING_INVALID",
        )
    ):
        raise DeploymentRecoveryError(
            "FAILURE_ATTESTATION_JOURNAL_BINDING_INVALID"
        )
    return failure, dict(claim), dict(receipt), request


def _read_stack(
    cfn: Any, *, stack_arn: str, code: str
) -> tuple[Mapping[str, Any], int]:
    try:
        response = cfn.describe_stacks(StackName=stack_arn)
    except Exception as exc:
        raise DeploymentRecoveryError(code) from exc
    stacks = response.get("Stacks") if isinstance(response, Mapping) else None
    if (
        response.get("NextToken") is not None
        or not isinstance(stacks, list)
        or len(stacks) != 1
        or not isinstance(stacks[0], Mapping)
    ):
        raise DeploymentRecoveryError(code)
    return stacks[0], 1


def _resource_projection(response: Mapping[str, Any], code: str) -> list[dict[str, str]]:
    raw = response.get("StackResourceSummaries")
    if not isinstance(raw, list) or response.get("NextToken") is not None:
        raise DeploymentRecoveryError(code)
    projected: list[dict[str, str]] = []
    seen: set[str] = set()
    for item in raw:
        if not isinstance(item, Mapping):
            raise DeploymentRecoveryError(code)
        logical = item.get("LogicalResourceId")
        resource_type = item.get("ResourceType")
        status = item.get("ResourceStatus")
        if (
            not isinstance(logical, str)
            or not logical
            or logical in seen
            or not isinstance(resource_type, str)
            or not resource_type
            or not isinstance(status, str)
            or not status
        ):
            raise DeploymentRecoveryError(code)
        seen.add(logical)
        projected.append(
            {
                "logical_resource_id": logical,
                "resource_type": resource_type,
                "resource_status": status,
            }
        )
    return sorted(projected, key=lambda item: item["logical_resource_id"])


def _cleanup_resource_projection(
    response: Mapping[str, Any], code: str
) -> list[dict[str, Any]]:
    """Preserve exact physical IDs needed to disprove retained survivors."""

    raw = response.get("StackResourceSummaries")
    if not isinstance(raw, list) or response.get("NextToken") is not None:
        raise DeploymentRecoveryError(code)
    result: list[dict[str, Any]] = []
    seen: set[str] = set()
    for item in raw:
        if not isinstance(item, Mapping):
            raise DeploymentRecoveryError(code)
        logical = item.get("LogicalResourceId")
        resource_type = item.get("ResourceType")
        status = item.get("ResourceStatus")
        physical = item.get("PhysicalResourceId")
        if (
            not isinstance(logical, str)
            or not logical
            or logical in seen
            or not isinstance(resource_type, str)
            or not resource_type
            or not isinstance(status, str)
            or not status
            or (physical is not None and (not isinstance(physical, str) or not physical))
        ):
            raise DeploymentRecoveryError(code)
        seen.add(logical)
        result.append(
            {
                "logical_resource_id": logical,
                "physical_resource_id": physical,
                "resource_type": resource_type,
                "resource_status": status,
            }
        )
    return sorted(result, key=lambda item: item["logical_resource_id"])


def _authoritative_reentry_change_set_readback(
    cfn: Any,
    *,
    seed_intent: Mapping[str, Any],
    reentry_intent: Mapping[str, Any],
    dispatch: Mapping[str, Any],
    observed_at: datetime,
) -> dict[str, Any]:
    """Re-read the exact immutable change-set state used by execution."""

    target = str(reentry_intent["target"])
    request = reentry_intent["create_request"]
    spec = _target_spec(seed_intent, target)
    response = cfn.describe_change_set(
        StackName=dispatch["stack_arn"],
        ChangeSetName=dispatch["change_set_arn"],
    )
    if not isinstance(response, Mapping):
        raise DeploymentRecoveryError("REENTRY_CHANGE_SET_READBACK_INVALID")
    try:
        changes = connected._change_projection(
            response,
            change_set_type=request["ChangeSetType"],
            expected_changes=spec["expected_changes"],
        )
    except connected.ConnectedRouteError as exc:
        raise DeploymentRecoveryError(exc.code) from exc
    creation_time = response.get("CreationTime")
    if (
        response.get("NextToken") is not None
        or response.get("ChangeSetId") != dispatch["change_set_arn"]
        or response.get("StackId") != dispatch["stack_arn"]
        or response.get("StackName") != _stack_name(target)
        or response.get("ChangeSetName") != REENTRY_CHANGE_SET_NAMES[target]
        or response.get("Status") != "CREATE_COMPLETE"
        or response.get("ExecutionStatus") != "AVAILABLE"
        or response.get("Description") != request["Description"]
        or response.get("ChangeSetType") != request["ChangeSetType"]
        or not connected._change_set_parameters_match(
            response.get("Parameters"),
            request.get("Parameters", []),
            target=target,
        )
        or response.get("Capabilities", []) != request["Capabilities"]
        or response.get("Tags", []) != request["Tags"]
        or response.get("IncludeNestedStacks", False) is not False
        or response.get("NotificationARNs", []) != []
        or response.get("RollbackConfiguration", {})
        != request["RollbackConfiguration"]
        or (
            response.get("OnStackFailure") != request.get("OnStackFailure")
            if request["ChangeSetType"] == "CREATE"
            else response.get("OnStackFailure") is not None
        )
        or "RoleARN" in response
        or changes != spec["expected_changes"]
        or not isinstance(creation_time, datetime)
        or creation_time.tzinfo is None
        or creation_time.utcoffset() is None
    ):
        raise DeploymentRecoveryError("REENTRY_CHANGE_SET_READBACK_INVALID")
    normalized_creation_time = creation_time.astimezone(timezone.utc).replace(
        microsecond=0
    )
    if not _time(
        dispatch["dispatched_at"], "REENTRY_CHANGE_SET_READBACK_INVALID"
    ) <= normalized_creation_time <= observed_at:
        raise DeploymentRecoveryError("REENTRY_CHANGE_SET_READBACK_INVALID")
    template = cfn.get_template(
        ChangeSetName=dispatch["change_set_arn"],
        TemplateStage="Original",
    )
    body = template.get("TemplateBody") if isinstance(template, Mapping) else None
    template_digest = (
        route.bytes_digest(body.encode()) if isinstance(body, str) else None
    )
    if template_digest != spec["template_digest"]:
        raise DeploymentRecoveryError("REENTRY_TEMPLATE_INVALID")
    return {
        "describe_change_set_digest": route.digest_value(
            {
                "id": response["ChangeSetId"],
                "stack_id": response["StackId"],
                "creation_time": _stamp(creation_time),
                "status": response["Status"],
                "execution_status": response["ExecutionStatus"],
                "request_digest": reentry_intent[
                    "create_request_digest"
                ],
            }
        ),
        "template_digest": template_digest,
        "changes_digest": route.digest_value(changes),
        "status": response["Status"],
        "execution_status": response["ExecutionStatus"],
    }


def _service_not_found(
    exc: Exception, *, codes: frozenset[str], statuses: frozenset[int]
) -> bool:
    """Accept only an exact service not-found response; AccessDenied is not absence."""

    response = getattr(exc, "response", None)
    error = response.get("Error") if isinstance(response, Mapping) else None
    metadata = response.get("ResponseMetadata") if isinstance(response, Mapping) else None
    return (
        isinstance(error, Mapping)
        and error.get("Code") in codes
        and isinstance(metadata, Mapping)
        and metadata.get("HTTPStatusCode") in statuses
    )


def _failure_binding(value: Mapping[str, Any]) -> tuple[str, str]:
    record_type = value.get("record_type")
    if record_type == PREEXECUTE_FAILURE_RECORD_TYPE:
        _verify_seal(value, "attestation_digest", "FAILURE_ATTESTATION_DIGEST_INVALID")
        target = str(value.get("target"))
        if (
            set(value) != _PREEXECUTE_FAILURE_FIELDS
            or value.get("schema_version") != 1
            or target not in {"route", "broker"}
            or value.get("account_id") != _account_id(target)
            or value.get("status") != "FAILED"
            or value.get("execution_status") != "UNAVAILABLE"
            or value.get("stack_status") != "REVIEW_IN_PROGRESS"
            or value.get("resource_count") != 0
            or value.get("resources_digest") != route.digest_value([])
            or any(
                _DIGEST_RE.fullmatch(str(value.get(field, ""))) is None
                for field in (
                    "intent_digest",
                    "primary_dispatch_digest",
                    "primary_create_request_digest",
                    "primary_claim_digest",
                    "primary_cloudtrail_event_digest",
                    "status_reason_digest",
                )
            )
            or _UUID_RE.fullmatch(str(value.get("create_request_id", ""))) is None
            or not isinstance(value.get("aws_calls"), int)
            or value.get("aws_calls", 0) < 5
            or value.get("aws_mutations") != 0
            or value.get("retry_permitted") is not False
            or value.get("production_authorized") is not False
            or value.get("production_status") != route.PRODUCTION_STATUS
        ):
            raise DeploymentRecoveryError("FAILURE_ATTESTATION_INVALID")
        _full_arn(
            value.get("stack_arn"),
            account_id=_account_id(target),
            kind="stack",
            name=_stack_name(target),
        )
        _full_arn(
            value.get("change_set_arn"),
            account_id=_account_id(target),
            kind="changeSet",
            name=(
                route.ROUTE_CHANGE_SET_NAME
                if target == "route"
                else route.BROKER_CHANGE_SET_NAME
            ),
        )
        _time(value.get("attested_at"), "FAILURE_ATTESTATION_INVALID")
        return target, str(value["attestation_digest"])
    if record_type == PROTECTION_ROLLBACK_RECORD_TYPE:
        _verify_seal(value, "attestation_digest", "FAILURE_ATTESTATION_DIGEST_INVALID")
        if (
            set(value) != _PROTECTION_ROLLBACK_FIELDS
            or value.get("schema_version") != 1
            or value.get("target") != route.BROKER_PROTECTION_TARGET
            or value.get("account_id") != route.AUTHORITY_ACCOUNT_ID
            or value.get("stack_status") != "UPDATE_ROLLBACK_COMPLETE"
            or value.get("ledger_deletion_protection_enabled") is not False
            or not isinstance(value.get("resource_count"), int)
            or value.get("resource_count", 0) <= 0
            or any(
                _DIGEST_RE.fullmatch(str(value.get(field, ""))) is None
                for field in (
                    "intent_digest",
                    "execution_intent_digest",
                    "execution_receipt_digest",
                    "execution_claim_digest",
                    "execute_cloudtrail_event_digest",
                    "resources_digest",
                    "ledger_live_properties_digest",
                )
            )
            or _UUID_RE.fullmatch(str(value.get("execute_request_id", ""))) is None
            or not isinstance(value.get("aws_calls"), int)
            or value.get("aws_calls", 0) < 5
            or value.get("aws_mutations") != 0
            or value.get("retry_permitted") is not False
            or value.get("production_authorized") is not False
            or value.get("production_status") != route.PRODUCTION_STATUS
        ):
            raise DeploymentRecoveryError("FAILURE_ATTESTATION_INVALID")
        _full_arn(
            value.get("stack_arn"),
            account_id=route.AUTHORITY_ACCOUNT_ID,
            kind="stack",
            name=route.BROKER_STACK_NAME,
        )
        _full_arn(
            value.get("change_set_arn"),
            account_id=route.AUTHORITY_ACCOUNT_ID,
            kind="changeSet",
            name=route.BROKER_PROTECTION_CHANGE_SET_NAME,
        )
        _time(value.get("attested_at"), "FAILURE_ATTESTATION_INVALID")
        return route.BROKER_PROTECTION_TARGET, str(value["attestation_digest"])
    if record_type == CLEANUP_TERMINAL_RECORD_TYPE:
        _verify_seal(value, "attestation_digest", "FAILURE_ATTESTATION_DIGEST_INVALID")
        target = str(value.get("target"))
        scheduled = value.get("scheduled_inert_survivors")
        failed_resources = value.get("failed_resources")
        if (
            set(value) != _CLEANUP_TERMINAL_FIELDS
            or value.get("schema_version") != 1
            or target not in {"route", "broker"}
            or value.get("account_id") != _account_id(target)
            or value.get("execution_lane") not in {"primary", "reentry"}
            or not isinstance(failed_resources, list)
            or value.get("failed_resources_digest")
            != route.digest_value(failed_resources)
            or value.get("fixed_stack_name") != _stack_name(target)
            or value.get("fixed_stack_name_absent") is not True
            or value.get("stack_terminal_observation")
            not in {"DELETE_COMPLETE", "NOT_FOUND"}
            or not isinstance(value.get("survivor_check_count"), int)
            or value.get("survivor_check_count", 0) <= 0
            or any(
                _DIGEST_RE.fullmatch(str(value.get(field, ""))) is None
                for field in (
                    "cleanup_intent_digest",
                    "cleanup_dispatch_digest",
                    "parent_intent_digest",
                    "failed_stack_attestation_digest",
                    "delete_cloudtrail_event_digest",
                    "survivor_evidence_digest",
                    "scheduled_inert_survivors_digest",
                )
            )
            or value.get("no_active_survivors") is not True
            or not isinstance(scheduled, list)
            or len(scheduled) > 1
            or value.get("scheduled_inert_survivor_count") != len(scheduled)
            or value.get("scheduled_inert_survivors_digest")
            != route.digest_value(scheduled)
            or not isinstance(value.get("aws_calls"), int)
            or value.get("aws_calls", 0)
            < 3 + value.get("survivor_check_count", 0)
            or value.get("aws_mutations") != 0
            or value.get("retry_permitted") is not False
            or value.get("production_authorized") is not False
            or value.get("production_status") != route.PRODUCTION_STATUS
        ):
            raise DeploymentRecoveryError("FAILURE_ATTESTATION_INVALID")
        if target == "route" and scheduled:
            raise DeploymentRecoveryError("FAILURE_ATTESTATION_INVALID")
        attested_at = _time(
            value.get("attested_at"), "FAILURE_ATTESTATION_INVALID"
        )
        for item in scheduled:
            resource = item.get("resource") if isinstance(item, Mapping) else None
            prefix = "arn:aws:kms:us-east-1:042360977644:key/"
            if (
                not isinstance(item, Mapping)
                or set(item)
                != {"service", "resource", "state", "enabled", "deletion_date"}
                or item.get("service") != "kms"
                or item.get("state") != "PendingDeletion"
                or item.get("enabled") is not False
                or not isinstance(resource, str)
                or not resource.startswith(prefix)
                or _KMS_KEY_ID_RE.fullmatch(resource[len(prefix) :]) is None
            ):
                raise DeploymentRecoveryError("FAILURE_ATTESTATION_INVALID")
            deletion_date = _time(
                item.get("deletion_date"), "FAILURE_ATTESTATION_INVALID"
            )
            if not attested_at < deletion_date <= attested_at + timedelta(days=30):
                raise DeploymentRecoveryError("FAILURE_ATTESTATION_INVALID")
        _full_arn(
            value.get("stack_arn"),
            account_id=_account_id(target),
            kind="stack",
            name=_stack_name(target),
        )
        return target, str(value["attestation_digest"])
    raise DeploymentRecoveryError("FAILURE_ATTESTATION_INVALID")


def _failure_parent_intent_digest(value: Mapping[str, Any]) -> Any:
    if value.get("record_type") == CLEANUP_TERMINAL_RECORD_TYPE:
        return value.get("parent_intent_digest")
    return value.get("intent_digest")


def _validate_failed_stack_attestation(value: Mapping[str, Any]) -> dict[str, Any]:
    _verify_seal(
        value, "attestation_digest", "FAILED_STACK_ATTESTATION_DIGEST_INVALID"
    )
    target = str(value.get("target"))
    resources = value.get("resources")
    reentry_source_failure_record_type = value.get(
        "reentry_source_failure_record_type"
    )
    if (
        set(value) != _FAILED_STACK_FIELDS
        or value.get("schema_version") != 1
        or value.get("record_type") != FAILED_CREATE_STACK_RECORD_TYPE
        or target not in {"route", "broker"}
        or value.get("account_id") != _account_id(target)
        or value.get("stack_status") not in {"ROLLBACK_COMPLETE", "DELETE_FAILED"}
        or not isinstance(resources, list)
        or value.get("resource_count") != len(resources)
        or value.get("resources_digest") != route.digest_value(resources)
        or any(
            _DIGEST_RE.fullmatch(str(value.get(field, ""))) is None
            for field in (
                "intent_digest",
                "execution_intent_digest",
                "execution_receipt_digest",
                "execution_claim_digest",
                "execute_cloudtrail_event_digest",
            )
        )
        or _UUID_RE.fullmatch(str(value.get("execute_request_id", ""))) is None
        or not isinstance(value.get("aws_calls"), int)
        or value.get("aws_calls", 0) < 4
        or value.get("aws_mutations") != 0
        or value.get("retry_permitted") is not False
        or value.get("production_authorized") is not False
        or value.get("production_status") != route.PRODUCTION_STATUS
    ):
        raise DeploymentRecoveryError("FAILED_STACK_ATTESTATION_INVALID")
    seen: set[str] = set()
    for item in resources:
        if not isinstance(item, Mapping):
            raise DeploymentRecoveryError("FAILED_STACK_ATTESTATION_INVALID")
        logical = item.get("logical_resource_id")
        physical = item.get("physical_resource_id")
        if (
            set(item)
            != {
                "logical_resource_id",
                "physical_resource_id",
                "resource_type",
                "resource_status",
            }
            or not isinstance(logical, str)
            or not logical
            or logical in seen
            or (
                physical is not None
                and (not isinstance(physical, str) or not physical)
            )
            or not isinstance(item.get("resource_type"), str)
            or not item["resource_type"]
            or not isinstance(item.get("resource_status"), str)
            or not item["resource_status"]
        ):
            raise DeploymentRecoveryError("FAILED_STACK_ATTESTATION_INVALID")
        seen.add(logical)
    _full_arn(
        value.get("stack_arn"),
        account_id=_account_id(target),
        kind="stack",
        name=_stack_name(target),
    )
    if reentry_source_failure_record_type is None:
        change_set_name = (
            route.ROUTE_CHANGE_SET_NAME
            if target == "route"
            else route.BROKER_CHANGE_SET_NAME
        )
    else:
        try:
            _reentry_collision_operation(
                target=target,
                failure_record_type=str(reentry_source_failure_record_type),
                effect="execute",
            )
        except DeploymentRecoveryError as exc:
            raise DeploymentRecoveryError(
                "FAILED_STACK_ATTESTATION_INVALID"
            ) from exc
        change_set_name = REENTRY_CHANGE_SET_NAMES[target]
    try:
        _full_arn(
            value.get("change_set_arn"),
            account_id=_account_id(target),
            kind="changeSet",
            name=change_set_name,
        )
    except DeploymentRecoveryError as exc:
        raise DeploymentRecoveryError(
            "FAILED_STACK_ATTESTATION_INVALID"
        ) from exc
    _time(value.get("attested_at"), "FAILED_STACK_ATTESTATION_INVALID")
    return json.loads(route.canonical_json(value))


def materialize_reentry_request(
    *, seed_intent: Mapping[str, Any], failure_attestation: Mapping[str, Any]
) -> dict[str, Any]:
    """Derive the only permitted recovery request from the sealed primary one."""

    try:
        intent = route.validate_seed_intent(seed_intent)
    except route.RouteSeedError as exc:
        raise DeploymentRecoveryError(exc.code) from exc
    target, failure_digest = _failure_binding(failure_attestation)
    if _failure_parent_intent_digest(failure_attestation) != intent["intent_digest"]:
        raise DeploymentRecoveryError("FAILURE_ATTESTATION_INVALID")
    spec = _target_spec(intent, target)
    request = json.loads(route.canonical_json(spec["create_request"]))
    request["ChangeSetName"] = REENTRY_CHANGE_SET_NAMES[target]
    token_seed = {
        "record_type": REENTRY_INTENT_RECORD_TYPE,
        "source_commit": intent["source_commit"],
        "target": target,
        "intent_digest": intent["intent_digest"],
        "failure_attestation_digest": failure_digest,
        "attempt": 1,
    }
    request["ClientToken"] = "gug376-" + route.digest_value(token_seed)[7:55]
    if target in {"route", "broker"} and request.get("ChangeSetType") != "CREATE":
        raise DeploymentRecoveryError("REENTRY_REQUEST_INVALID")
    if (
        target == route.BROKER_PROTECTION_TARGET
        and request.get("ChangeSetType") != "UPDATE"
    ):
        raise DeploymentRecoveryError("REENTRY_REQUEST_INVALID")
    if target in {"route", "broker"} and request.get("OnStackFailure") != "DELETE":
        raise DeploymentRecoveryError("REENTRY_REQUEST_INVALID")
    if target == route.BROKER_PROTECTION_TARGET and "OnStackFailure" in request:
        raise DeploymentRecoveryError("REENTRY_REQUEST_INVALID")
    if "RoleARN" in request or _TOKEN_RE.fullmatch(request["ClientToken"]) is None:
        raise DeploymentRecoveryError("REENTRY_REQUEST_INVALID")
    # Every field except the exact one-use name/token remains byte-for-byte equal.
    original = dict(spec["create_request"])
    for key in set(original) | set(request):
        if key not in {"ChangeSetName", "ClientToken"} and original.get(key) != request.get(key):
            raise DeploymentRecoveryError("REENTRY_REQUEST_INVALID")
    return request


def materialize_reentry_authorization(
    *,
    seed_intent: Mapping[str, Any],
    failure_attestation: Mapping[str, Any],
    authorization: str,
    authorized_at: str,
    expires_at: str,
) -> dict[str, Any]:
    try:
        intent = route.validate_seed_intent(seed_intent)
    except route.RouteSeedError as exc:
        raise DeploymentRecoveryError(exc.code) from exc
    target, failure_digest = _failure_binding(failure_attestation)
    request = materialize_reentry_request(
        seed_intent=intent, failure_attestation=failure_attestation
    )
    authorized = _time(authorized_at, "REENTRY_AUTHORIZATION_INVALID")
    expires = _time(expires_at, "REENTRY_AUTHORIZATION_INVALID")
    cutoff = _time(intent["route_not_after"], "REENTRY_AUTHORIZATION_INVALID") - timedelta(
        seconds=route.MUTATION_COMPLETION_RESERVE_SECONDS
    )
    duration = (expires - authorized).total_seconds()
    if (
        authorization != REENTRY_CREATION_PHRASES[target]
        or _failure_parent_intent_digest(failure_attestation)
        != intent["intent_digest"]
        or not _time(intent["route_not_before"], "REENTRY_AUTHORIZATION_INVALID")
        <= authorized
        < expires
        <= cutoff
        or not 60 <= duration <= 900
    ):
        raise DeploymentRecoveryError("REENTRY_AUTHORIZATION_INVALID")
    return route.seal(
        {
            "schema_version": 1,
            "record_type": REENTRY_AUTHORIZATION_RECORD_TYPE,
            "source_commit": intent["source_commit"],
            "target": target,
            "intent_digest": intent["intent_digest"],
            "failure_attestation_digest": failure_digest,
            "reentry_request_digest": route.digest_value(request),
            "attempt": 1,
            "authorization": authorization,
            "authorized_at": authorized_at,
            "expires_at": expires_at,
            "production_authorized": False,
        },
        "authorization_digest",
    )


def validate_reentry_authorization(
    value: Mapping[str, Any],
    *,
    seed_intent: Mapping[str, Any],
    failure_attestation: Mapping[str, Any],
) -> dict[str, Any]:
    fields = {
        "schema_version",
        "record_type",
        "source_commit",
        "target",
        "intent_digest",
        "failure_attestation_digest",
        "reentry_request_digest",
        "attempt",
        "authorization",
        "authorized_at",
        "expires_at",
        "production_authorized",
        "authorization_digest",
    }
    if not isinstance(value, Mapping) or set(value) != fields:
        raise DeploymentRecoveryError("REENTRY_AUTHORIZATION_INVALID")
    _verify_seal(
        value,
        "authorization_digest",
        "REENTRY_AUTHORIZATION_DIGEST_INVALID",
    )
    expected = materialize_reentry_authorization(
        seed_intent=seed_intent,
        failure_attestation=failure_attestation,
        authorization=str(value.get("authorization", "")),
        authorized_at=str(value.get("authorized_at", "")),
        expires_at=str(value.get("expires_at", "")),
    )
    if dict(value) != expected:
        raise DeploymentRecoveryError("REENTRY_AUTHORIZATION_INVALID")
    return json.loads(route.canonical_json(dict(value)))


def materialize_reentry_intent(
    *,
    seed_intent: Mapping[str, Any],
    failure_attestation: Mapping[str, Any],
    authorization: Mapping[str, Any],
) -> dict[str, Any]:
    try:
        intent = route.validate_seed_intent(seed_intent)
    except route.RouteSeedError as exc:
        raise DeploymentRecoveryError(exc.code) from exc
    target, failure_digest = _failure_binding(failure_attestation)
    request = materialize_reentry_request(
        seed_intent=intent, failure_attestation=failure_attestation
    )
    authorization = validate_reentry_authorization(
        authorization,
        seed_intent=intent,
        failure_attestation=failure_attestation,
    )
    if (
        authorization.get("record_type") != REENTRY_AUTHORIZATION_RECORD_TYPE
        or authorization.get("source_commit") != intent["source_commit"]
        or authorization.get("target") != target
        or authorization.get("intent_digest") != intent["intent_digest"]
        or authorization.get("failure_attestation_digest") != failure_digest
        or authorization.get("reentry_request_digest") != route.digest_value(request)
        or authorization.get("attempt") != 1
        or authorization.get("authorization") != REENTRY_CREATION_PHRASES[target]
        or authorization.get("production_authorized") is not False
    ):
        raise DeploymentRecoveryError("REENTRY_AUTHORIZATION_INVALID")
    return route.seal(
        {
            "schema_version": 1,
            "record_type": REENTRY_INTENT_RECORD_TYPE,
            "source_commit": intent["source_commit"],
            "target": target,
            "account_id": _account_id(target),
            "parent_intent_digest": intent["intent_digest"],
            "failure_attestation_digest": failure_digest,
            "authorization_digest": authorization["authorization_digest"],
            "authorization_not_before": authorization["authorized_at"],
            "authorization_expires_at": authorization["expires_at"],
            "route_not_before": intent["route_not_before"],
            "route_not_after": intent["route_not_after"],
            "recovery_not_after": intent["recovery_not_after"],
            "attempt": 1,
            "create_request": request,
            "create_request_digest": route.digest_value(request),
            "aws_calls": 0,
            "aws_mutations": 0,
            "retry_permitted": False,
            "production_authorized": False,
            "production_status": route.PRODUCTION_STATUS,
        },
        "reentry_intent_digest",
    )


def validate_reentry_intent_structure(value: Mapping[str, Any]) -> dict[str, Any]:
    """Validate shape and self-consistency only; never authorizes a mutation."""
    _verify_seal(value, "reentry_intent_digest", "REENTRY_INTENT_DIGEST_INVALID")
    fields = {
        "schema_version",
        "record_type",
        "source_commit",
        "target",
        "account_id",
        "parent_intent_digest",
        "failure_attestation_digest",
        "authorization_digest",
        "authorization_not_before",
        "authorization_expires_at",
        "route_not_before",
        "route_not_after",
        "recovery_not_after",
        "attempt",
        "create_request",
        "create_request_digest",
        "aws_calls",
        "aws_mutations",
        "retry_permitted",
        "production_authorized",
        "production_status",
        "reentry_intent_digest",
    }
    target = str(value.get("target"))
    request = value.get("create_request")
    token_seed = {
        "record_type": REENTRY_INTENT_RECORD_TYPE,
        "source_commit": value.get("source_commit"),
        "target": target,
        "intent_digest": value.get("parent_intent_digest"),
        "failure_attestation_digest": value.get("failure_attestation_digest"),
        "attempt": 1,
    }
    expected_token = "gug376-" + route.digest_value(token_seed)[7:55]
    if (
        set(value) != fields
        or value.get("schema_version") != 1
        or value.get("record_type") != REENTRY_INTENT_RECORD_TYPE
        or target not in route.TARGETS
        or value.get("account_id") != _account_id(target)
        or value.get("attempt") != 1
        or not isinstance(request, Mapping)
        or value.get("create_request_digest") != route.digest_value(request)
        or request.get("StackName") != _stack_name(target)
        or request.get("ChangeSetName") != REENTRY_CHANGE_SET_NAMES[target]
        or request.get("ClientToken") != expected_token
        or "RoleARN" in request
        or value.get("aws_calls") != 0
        or value.get("aws_mutations") != 0
        or value.get("retry_permitted") is not False
        or value.get("production_authorized") is not False
        or value.get("production_status") != route.PRODUCTION_STATUS
    ):
        raise DeploymentRecoveryError("REENTRY_INTENT_INVALID")
    authorized = _time(
        value.get("authorization_not_before"), "REENTRY_INTENT_INVALID"
    )
    expires = _time(
        value.get("authorization_expires_at"), "REENTRY_INTENT_INVALID"
    )
    route_not_after = _time(value.get("route_not_after"), "REENTRY_INTENT_INVALID")
    if (
        not _time(value.get("route_not_before"), "REENTRY_INTENT_INVALID")
        <= authorized
        < expires
        <= route_not_after
        - timedelta(seconds=route.MUTATION_COMPLETION_RESERVE_SECONDS)
        or _time(value.get("recovery_not_after"), "REENTRY_INTENT_INVALID")
        != route_not_after + timedelta(hours=24)
    ):
        raise DeploymentRecoveryError("REENTRY_INTENT_INVALID")
    return json.loads(route.canonical_json(value))


def validate_reentry_intent(
    value: Mapping[str, Any],
    *,
    seed_intent: Mapping[str, Any],
    failure_attestation: Mapping[str, Any],
    authorization: Mapping[str, Any],
) -> dict[str, Any]:
    """Reconstruct and bind a re-entry intent to its complete causal chain."""

    validated = validate_reentry_intent_structure(value)
    expected = materialize_reentry_intent(
        seed_intent=seed_intent,
        failure_attestation=failure_attestation,
        authorization=authorization,
    )
    if validated != expected:
        raise DeploymentRecoveryError("REENTRY_INTENT_CAUSAL_MISMATCH")
    return validated


def _validate_reentry_dispatch(
    value: Mapping[str, Any],
    *,
    reentry_intent: Mapping[str, Any],
    failure_record_type: str,
) -> dict[str, Any]:
    """Bind the provider dispatch receipt to one exact re-entry intent."""

    intent = validate_reentry_intent_structure(reentry_intent)
    if not isinstance(value, Mapping):
        raise DeploymentRecoveryError("REENTRY_DISPATCH_INVALID")
    _verify_seal(
        value, "dispatch_digest", "REENTRY_DISPATCH_DIGEST_INVALID"
    )
    target = intent["target"]
    request = intent["create_request"]
    collision_admission = _validate_reentry_collision_binding(
        value.get("collision_admission"),
        target=target,
        effect="create",
        effect_request=request,
        bootstrap_intent_digest=intent["parent_intent_digest"],
        failure_record_type=failure_record_type,
    )
    if (
        set(value) != _REENTRY_DISPATCH_FIELDS
        or value.get("schema_version") != 1
        or value.get("record_type") != REENTRY_DISPATCH_RECORD_TYPE
        or value.get("source_commit") != intent["source_commit"]
        or value.get("target") != target
        or value.get("account_id") != intent["account_id"]
        or value.get("reentry_intent_digest")
        != intent["reentry_intent_digest"]
        or value.get("create_request_digest")
        != intent["create_request_digest"]
        or value.get("collision_admission") != collision_admission
        or _UUID_RE.fullmatch(str(value.get("create_request_id", ""))) is None
        or value.get("attempt") != 1
        or value.get("aws_mutations") != 1
        or value.get("retry_permitted") is not False
        or value.get("production_authorized") is not False
        or value.get("production_status") != route.PRODUCTION_STATUS
    ):
        raise DeploymentRecoveryError("REENTRY_DISPATCH_INVALID")
    _full_arn(
        value.get("stack_arn"),
        account_id=intent["account_id"],
        kind="stack",
        name=_stack_name(target),
    )
    _full_arn(
        value.get("change_set_arn"),
        account_id=intent["account_id"],
        kind="changeSet",
        name=REENTRY_CHANGE_SET_NAMES[target],
    )
    dispatched_at = _time(
        value.get("dispatched_at"), "REENTRY_DISPATCH_INVALID"
    )
    if not _time(
        intent["authorization_not_before"], "REENTRY_DISPATCH_INVALID"
    ) <= dispatched_at < _time(
        intent["authorization_expires_at"], "REENTRY_DISPATCH_INVALID"
    ):
        raise DeploymentRecoveryError("REENTRY_DISPATCH_INVALID")
    if (
        request["StackName"] != _stack_name(target)
        or request["ChangeSetName"] != REENTRY_CHANGE_SET_NAMES[target]
    ):
        raise DeploymentRecoveryError("REENTRY_DISPATCH_INVALID")
    return json.loads(route.canonical_json(value))


def validate_reentry_attestation(
    value: Mapping[str, Any],
    *,
    seed_intent: Mapping[str, Any],
    failure_attestation: Mapping[str, Any],
    reentry_creation_authorization: Mapping[str, Any],
    reentry_intent: Mapping[str, Any],
    reentry_dispatch: Mapping[str, Any],
) -> dict[str, Any]:
    """Validate the full provider attestation and its exact causal dispatch."""

    if not isinstance(value, Mapping):
        raise DeploymentRecoveryError("REENTRY_ATTESTATION_INVALID")
    intent = validate_reentry_intent(
        reentry_intent,
        seed_intent=seed_intent,
        failure_attestation=failure_attestation,
        authorization=reentry_creation_authorization,
    )
    dispatch = _validate_reentry_dispatch(
        reentry_dispatch,
        reentry_intent=intent,
        failure_record_type=str(failure_attestation.get("record_type", "")),
    )
    _verify_seal(
        value,
        "attestation_digest",
        "REENTRY_ATTESTATION_DIGEST_INVALID",
    )
    target = intent["target"]
    spec = _target_spec(seed_intent, target)
    attested_at = _time(
        value.get("attested_at"), "REENTRY_ATTESTATION_INVALID"
    )
    if (
        set(value) != _REENTRY_ATTESTATION_FIELDS
        or value.get("schema_version") != 1
        or value.get("record_type") != REENTRY_ATTESTATION_RECORD_TYPE
        or value.get("source_commit") != intent["source_commit"]
        or value.get("target") != target
        or value.get("account_id") != intent["account_id"]
        or value.get("parent_intent_digest")
        != intent["parent_intent_digest"]
        or value.get("reentry_intent_digest")
        != intent["reentry_intent_digest"]
        or value.get("create_request_digest")
        != intent["create_request_digest"]
        or value.get("collision_admission")
        != dispatch["collision_admission"]
        or value.get("dispatch_digest") != dispatch["dispatch_digest"]
        or value.get("stack_arn") != dispatch["stack_arn"]
        or value.get("change_set_arn") != dispatch["change_set_arn"]
        or value.get("create_request_id") != dispatch["create_request_id"]
        or value.get("template_digest") != spec["template_digest"]
        or value.get("changes_digest")
        != route.digest_value(spec["expected_changes"])
        or any(
            _DIGEST_RE.fullmatch(str(value.get(field, ""))) is None
            for field in (
                "cloudtrail_event_digest",
                "describe_change_set_digest",
            )
        )
        or value.get("status") != "CREATE_COMPLETE"
        or value.get("execution_status") != "AVAILABLE"
        or value.get("attempt") != 1
        or type(value.get("aws_calls")) is not int
        or value.get("aws_calls", 0) < 4
        or value.get("aws_mutations") != 0
        or value.get("retry_permitted") is not False
        or value.get("production_authorized") is not False
        or value.get("production_status") != route.PRODUCTION_STATUS
        or not _time(
            dispatch["dispatched_at"], "REENTRY_ATTESTATION_INVALID"
        )
        <= attested_at
        < _time(intent["recovery_not_after"], "REENTRY_ATTESTATION_INVALID")
    ):
        raise DeploymentRecoveryError("REENTRY_ATTESTATION_INVALID")
    return json.loads(route.canonical_json(value))


def _validate_reentry_create_claim(
    value: Mapping[str, Any],
    *,
    intent: Mapping[str, Any],
    dispatch: Mapping[str, Any],
    failure_record_type: str,
) -> dict[str, Any]:
    fields = {
        "schema_version",
        "record_type",
        "operation",
        "target",
        "attempt",
        "reentry_intent_digest",
        "request_digest",
        "collision_admission",
        "client_token",
        "stack_name",
        "change_set_name",
        "caller_arn_digest",
        "claimed_at",
        "retry_permitted",
        "production_authorized",
    }
    request = intent["create_request"]
    collision_admission = _validate_reentry_collision_binding(
        value.get("collision_admission"),
        target=str(intent["target"]),
        effect="create",
        effect_request=request,
        bootstrap_intent_digest=str(intent["parent_intent_digest"]),
        failure_record_type=failure_record_type,
    )
    if (
        set(value) != fields
        or value.get("schema_version") != 1
        or value.get("record_type") != CLAIM_RECORD_TYPE
        or value.get("operation") != "CreateChangeSet"
        or value.get("target") != intent["target"]
        or value.get("attempt") != 1
        or value.get("reentry_intent_digest") != intent["reentry_intent_digest"]
        or value.get("request_digest") != intent["create_request_digest"]
        or collision_admission != dispatch.get("collision_admission")
        or value.get("client_token") != request["ClientToken"]
        or value.get("stack_name") != request["StackName"]
        or value.get("change_set_name") != request["ChangeSetName"]
        or _DIGEST_RE.fullmatch(str(value.get("caller_arn_digest", ""))) is None
        or value.get("retry_permitted") is not False
        or value.get("production_authorized") is not False
    ):
        raise DeploymentRecoveryError("REENTRY_CLAIM_INVALID")
    claimed_at = _time(value.get("claimed_at"), "REENTRY_CLAIM_INVALID")
    dispatched_at = _time(
        dispatch.get("dispatched_at"), "REENTRY_DISPATCH_INVALID"
    )
    if not _time(
        intent["authorization_not_before"], "REENTRY_CLAIM_INVALID"
    ) <= claimed_at <= dispatched_at < _time(
        intent["authorization_expires_at"], "REENTRY_CLAIM_INVALID"
    ):
        raise DeploymentRecoveryError("REENTRY_CLAIM_INVALID")
    return json.loads(route.canonical_json(value))


def materialize_reentry_execution_authorization(
    *,
    seed_intent: Mapping[str, Any],
    failure_attestation: Mapping[str, Any],
    reentry_creation_authorization: Mapping[str, Any],
    reentry_intent: Mapping[str, Any],
    reentry_dispatch: Mapping[str, Any],
    reentry_attestation: Mapping[str, Any],
    authorization: str,
    authorized_at: str,
    expires_at: str,
) -> dict[str, Any]:
    intent = validate_reentry_intent(
        reentry_intent,
        seed_intent=seed_intent,
        failure_attestation=failure_attestation,
        authorization=reentry_creation_authorization,
    )
    reentry_attestation = validate_reentry_attestation(
        reentry_attestation,
        seed_intent=seed_intent,
        failure_attestation=failure_attestation,
        reentry_creation_authorization=reentry_creation_authorization,
        reentry_intent=intent,
        reentry_dispatch=reentry_dispatch,
    )
    target = intent["target"]
    authorized = _time(authorized_at, "REENTRY_EXECUTION_AUTHORIZATION_INVALID")
    expires = _time(expires_at, "REENTRY_EXECUTION_AUTHORIZATION_INVALID")
    attested = _time(
        reentry_attestation.get("attested_at"),
        "REENTRY_EXECUTION_AUTHORIZATION_INVALID",
    )
    cutoff = _time(intent["route_not_after"], "REENTRY_EXECUTION_AUTHORIZATION_INVALID") - timedelta(
        seconds=route.MUTATION_COMPLETION_RESERVE_SECONDS
    )
    if (
        reentry_attestation.get("record_type") != REENTRY_ATTESTATION_RECORD_TYPE
        or reentry_attestation.get("reentry_intent_digest")
        != intent["reentry_intent_digest"]
        or reentry_attestation.get("target") != target
        or reentry_attestation.get("status") != "CREATE_COMPLETE"
        or reentry_attestation.get("execution_status") != "AVAILABLE"
        or authorization != REENTRY_EXECUTION_PHRASES[target]
        or not attested <= authorized < expires <= cutoff
        or not 60 <= (expires - authorized).total_seconds() <= 900
    ):
        raise DeploymentRecoveryError("REENTRY_EXECUTION_AUTHORIZATION_INVALID")
    return route.seal(
        {
            "schema_version": 1,
            "record_type": REENTRY_EXECUTION_AUTHORIZATION_RECORD_TYPE,
            "source_commit": intent["source_commit"],
            "target": target,
            "reentry_intent_digest": intent["reentry_intent_digest"],
            "reentry_attestation_digest": reentry_attestation["attestation_digest"],
            "authorization": authorization,
            "authorized_at": authorized_at,
            "expires_at": expires_at,
            "production_authorized": False,
        },
        "authorization_digest",
    )


def validate_reentry_execution_authorization(
    value: Mapping[str, Any],
    *,
    seed_intent: Mapping[str, Any],
    failure_attestation: Mapping[str, Any],
    reentry_creation_authorization: Mapping[str, Any],
    reentry_intent: Mapping[str, Any],
    reentry_dispatch: Mapping[str, Any],
    reentry_attestation: Mapping[str, Any],
) -> dict[str, Any]:
    fields = {
        "schema_version",
        "record_type",
        "source_commit",
        "target",
        "reentry_intent_digest",
        "reentry_attestation_digest",
        "authorization",
        "authorized_at",
        "expires_at",
        "production_authorized",
        "authorization_digest",
    }
    if not isinstance(value, Mapping) or set(value) != fields:
        raise DeploymentRecoveryError(
            "REENTRY_EXECUTION_AUTHORIZATION_INVALID"
        )
    _verify_seal(
        value,
        "authorization_digest",
        "REENTRY_EXECUTION_AUTHORIZATION_DIGEST_INVALID",
    )
    expected = materialize_reentry_execution_authorization(
        seed_intent=seed_intent,
        failure_attestation=failure_attestation,
        reentry_creation_authorization=reentry_creation_authorization,
        reentry_intent=reentry_intent,
        reentry_dispatch=reentry_dispatch,
        reentry_attestation=reentry_attestation,
        authorization=str(value.get("authorization", "")),
        authorized_at=str(value.get("authorized_at", "")),
        expires_at=str(value.get("expires_at", "")),
    )
    if dict(value) != expected:
        raise DeploymentRecoveryError(
            "REENTRY_EXECUTION_AUTHORIZATION_INVALID"
        )
    return json.loads(route.canonical_json(dict(value)))


def materialize_reentry_execution_intent(
    *,
    seed_intent: Mapping[str, Any],
    failure_attestation: Mapping[str, Any],
    reentry_creation_authorization: Mapping[str, Any],
    reentry_intent: Mapping[str, Any],
    reentry_dispatch: Mapping[str, Any],
    reentry_attestation: Mapping[str, Any],
    authorization: Mapping[str, Any],
) -> dict[str, Any]:
    intent = validate_reentry_intent(
        reentry_intent,
        seed_intent=seed_intent,
        failure_attestation=failure_attestation,
        authorization=reentry_creation_authorization,
    )
    reentry_attestation = validate_reentry_attestation(
        reentry_attestation,
        seed_intent=seed_intent,
        failure_attestation=failure_attestation,
        reentry_creation_authorization=reentry_creation_authorization,
        reentry_intent=intent,
        reentry_dispatch=reentry_dispatch,
    )
    authorization = validate_reentry_execution_authorization(
        authorization,
        seed_intent=seed_intent,
        failure_attestation=failure_attestation,
        reentry_creation_authorization=reentry_creation_authorization,
        reentry_intent=intent,
        reentry_dispatch=reentry_dispatch,
        reentry_attestation=reentry_attestation,
    )
    target = intent["target"]
    failure_record_type = str(failure_attestation.get("record_type", ""))
    if (
        authorization.get("record_type")
        != REENTRY_EXECUTION_AUTHORIZATION_RECORD_TYPE
        or authorization.get("target") != target
        or authorization.get("reentry_intent_digest")
        != intent["reentry_intent_digest"]
        or authorization.get("reentry_attestation_digest")
        != reentry_attestation["attestation_digest"]
        or authorization.get("authorization") != REENTRY_EXECUTION_PHRASES[target]
        or authorization.get("production_authorized") is not False
    ):
        raise DeploymentRecoveryError("REENTRY_EXECUTION_AUTHORIZATION_INVALID")
    operation_digest = route.digest_value(
        {
            "record_type": REENTRY_EXECUTION_INTENT_RECORD_TYPE,
            "source_commit": intent["source_commit"],
            "target": target,
            "failure_record_type": failure_record_type,
            "stack_arn": reentry_attestation["stack_arn"],
            "change_set_arn": reentry_attestation["change_set_arn"],
            "attempt": 1,
        }
    )
    request = {
        "StackName": reentry_attestation["stack_arn"],
        "ChangeSetName": reentry_attestation["change_set_arn"],
        "ClientRequestToken": "gug376-" + operation_digest[7:55],
    }
    if target == route.BROKER_PROTECTION_TARGET:
        request["DisableRollback"] = False
    return route.seal(
        {
            "schema_version": 1,
            "record_type": REENTRY_EXECUTION_INTENT_RECORD_TYPE,
            "source_commit": intent["source_commit"],
            "target": target,
            "account_id": intent["account_id"],
            "parent_intent_digest": intent["parent_intent_digest"],
            "failure_record_type": failure_record_type,
            "reentry_intent_digest": intent["reentry_intent_digest"],
            "reentry_attestation_digest": reentry_attestation["attestation_digest"],
            "authorization_digest": authorization["authorization_digest"],
            "authorization_not_before": authorization["authorized_at"],
            "authorization_expires_at": authorization["expires_at"],
            "route_not_before": intent["route_not_before"],
            "route_not_after": intent["route_not_after"],
            "recovery_not_after": intent["recovery_not_after"],
            "attempt": 1,
            "execute_operation_digest": operation_digest,
            "execute_request": request,
            "execute_request_digest": route.digest_value(request),
            "aws_calls": 0,
            "aws_mutations": 0,
            "retry_permitted": False,
            "production_authorized": False,
            "production_status": route.PRODUCTION_STATUS,
        },
        "execution_intent_digest",
    )


def validate_reentry_execution_intent_structure(
    value: Mapping[str, Any],
) -> dict[str, Any]:
    """Validate execution shape only; never authorizes ExecuteChangeSet."""
    _verify_seal(
        value, "execution_intent_digest", "REENTRY_EXECUTION_INTENT_DIGEST_INVALID"
    )
    target = str(value.get("target"))
    failure_record_type = str(value.get("failure_record_type", ""))
    request = value.get("execute_request")
    fields = {
        "schema_version",
        "record_type",
        "source_commit",
        "target",
        "account_id",
        "parent_intent_digest",
        "failure_record_type",
        "reentry_intent_digest",
        "reentry_attestation_digest",
        "authorization_digest",
        "authorization_not_before",
        "authorization_expires_at",
        "route_not_before",
        "route_not_after",
        "recovery_not_after",
        "attempt",
        "execute_operation_digest",
        "execute_request",
        "execute_request_digest",
        "aws_calls",
        "aws_mutations",
        "retry_permitted",
        "production_authorized",
        "production_status",
        "execution_intent_digest",
    }
    expected_request_fields = (
        {"StackName", "ChangeSetName", "ClientRequestToken", "DisableRollback"}
        if target == route.BROKER_PROTECTION_TARGET
        else {"StackName", "ChangeSetName", "ClientRequestToken"}
    )
    operation_seed = {
        "record_type": REENTRY_EXECUTION_INTENT_RECORD_TYPE,
        "source_commit": value.get("source_commit"),
        "target": target,
        "failure_record_type": failure_record_type,
        "stack_arn": request.get("StackName") if isinstance(request, Mapping) else None,
        "change_set_arn": (
            request.get("ChangeSetName") if isinstance(request, Mapping) else None
        ),
        "attempt": 1,
    }
    expected_operation_digest = route.digest_value(operation_seed)
    expected_token = "gug376-" + expected_operation_digest[7:55]
    try:
        _reentry_collision_operation(
            target=target,
            failure_record_type=failure_record_type,
            effect="execute",
        )
    except DeploymentRecoveryError as exc:
        raise DeploymentRecoveryError(
            "REENTRY_EXECUTION_INTENT_INVALID"
        ) from exc
    if (
        set(value) != fields
        or value.get("schema_version") != 1
        or value.get("record_type") != REENTRY_EXECUTION_INTENT_RECORD_TYPE
        or target not in route.TARGETS
        or value.get("account_id") != _account_id(target)
        or value.get("attempt") != 1
        or not isinstance(request, Mapping)
        or set(request) != expected_request_fields
        or value.get("execute_request_digest") != route.digest_value(request)
        or value.get("execute_operation_digest") != expected_operation_digest
        or request.get("ClientRequestToken") != expected_token
        or (
            target == route.BROKER_PROTECTION_TARGET
            and request.get("DisableRollback") is not False
        )
        or value.get("aws_calls") != 0
        or value.get("aws_mutations") != 0
        or value.get("retry_permitted") is not False
        or value.get("production_authorized") is not False
        or value.get("production_status") != route.PRODUCTION_STATUS
    ):
        raise DeploymentRecoveryError("REENTRY_EXECUTION_INTENT_INVALID")
    try:
        _full_arn(
            request["StackName"],
            account_id=_account_id(target),
            kind="stack",
            name=_stack_name(target),
        )
        _full_arn(
            request["ChangeSetName"],
            account_id=_account_id(target),
            kind="changeSet",
            name=REENTRY_CHANGE_SET_NAMES[target],
        )
    except DeploymentRecoveryError as exc:
        raise DeploymentRecoveryError("REENTRY_EXECUTION_INTENT_INVALID") from exc
    authorized = _time(value.get("authorization_not_before"), "REENTRY_EXECUTION_INTENT_INVALID")
    expires = _time(value.get("authorization_expires_at"), "REENTRY_EXECUTION_INTENT_INVALID")
    cutoff = _time(value.get("route_not_after"), "REENTRY_EXECUTION_INTENT_INVALID") - timedelta(
        seconds=route.MUTATION_COMPLETION_RESERVE_SECONDS
    )
    if (
        not _time(
            value.get("route_not_before"),
            "REENTRY_EXECUTION_INTENT_INVALID",
        )
        <= authorized
        < expires
        <= cutoff
        or not 60 <= (expires - authorized).total_seconds() <= 900
    ):
        raise DeploymentRecoveryError("REENTRY_EXECUTION_INTENT_INVALID")
    return json.loads(route.canonical_json(value))


def validate_reentry_execution_intent(
    value: Mapping[str, Any],
    *,
    seed_intent: Mapping[str, Any],
    failure_attestation: Mapping[str, Any],
    reentry_creation_authorization: Mapping[str, Any],
    reentry_intent: Mapping[str, Any],
    reentry_dispatch: Mapping[str, Any],
    reentry_attestation: Mapping[str, Any],
    execution_authorization: Mapping[str, Any],
) -> dict[str, Any]:
    """Reconstruct execution from the exact re-entry and review chain."""

    validated = validate_reentry_execution_intent_structure(value)
    expected = materialize_reentry_execution_intent(
        seed_intent=seed_intent,
        failure_attestation=failure_attestation,
        reentry_creation_authorization=reentry_creation_authorization,
        reentry_intent=reentry_intent,
        reentry_dispatch=reentry_dispatch,
        reentry_attestation=reentry_attestation,
        authorization=execution_authorization,
    )
    if validated != expected:
        raise DeploymentRecoveryError("REENTRY_EXECUTION_INTENT_CAUSAL_MISMATCH")
    return validated


def _validate_reentry_execution_receipt(
    value: Mapping[str, Any], *, execution: Mapping[str, Any]
) -> dict[str, Any]:
    _verify_seal(value, "receipt_digest", "EXECUTION_RECEIPT_DIGEST_INVALID")
    target = execution["target"]
    request = execution["execute_request"]
    collision_admission = _validate_reentry_collision_binding(
        value.get("collision_admission"),
        target=str(target),
        effect="execute",
        effect_request=request,
        bootstrap_intent_digest=str(execution["parent_intent_digest"]),
        failure_record_type=str(execution["failure_record_type"]),
    )
    if (
        set(value) != _REENTRY_EXECUTION_RECEIPT_FIELDS
        or value.get("schema_version") != 1
        or value.get("record_type") != REENTRY_EXECUTION_RECEIPT_RECORD_TYPE
        or value.get("source_commit") != execution["source_commit"]
        or value.get("target") != target
        or value.get("account_id") != _account_id(target)
        or value.get("execution_intent_digest")
        != execution["execution_intent_digest"]
        or value.get("collision_admission") != collision_admission
        or value.get("stack_arn") != request["StackName"]
        or value.get("change_set_arn") != request["ChangeSetName"]
        or _UUID_RE.fullmatch(str(value.get("execute_request_id", ""))) is None
        or value.get("attempt") != 1
        or value.get("aws_mutations") != 1
        or value.get("retry_permitted") is not False
        or value.get("production_authorized") is not False
        or value.get("production_status") != route.PRODUCTION_STATUS
    ):
        raise DeploymentRecoveryError("EXECUTION_RECEIPT_INVALID")
    dispatched = _time(
        value.get("dispatched_at"), "EXECUTION_RECEIPT_INVALID"
    )
    if not _time(
        execution["authorization_not_before"], "EXECUTION_RECEIPT_INVALID"
    ) <= dispatched < _time(
        execution["authorization_expires_at"], "EXECUTION_RECEIPT_INVALID"
    ):
        raise DeploymentRecoveryError("EXECUTION_RECEIPT_INVALID")
    return json.loads(route.canonical_json(value))


def materialize_cleanup_authorization(
    *,
    seed_intent: Mapping[str, Any],
    failed_stack_attestation: Mapping[str, Any],
    authorization: str,
    authorized_at: str,
    expires_at: str,
) -> dict[str, Any]:
    try:
        intent = route.validate_seed_intent(seed_intent)
    except route.RouteSeedError as exc:
        raise DeploymentRecoveryError(exc.code) from exc
    failed_stack_attestation = _validate_failed_stack_attestation(
        failed_stack_attestation
    )
    target = str(failed_stack_attestation["target"])
    execution_lane = _execution_lane(
        target=target,
        change_set_arn=failed_stack_attestation["change_set_arn"],
    )
    authorized = _time(authorized_at, "CLEANUP_AUTHORIZATION_INVALID")
    expires = _time(expires_at, "CLEANUP_AUTHORIZATION_INVALID")
    cutoff = _time(intent["recovery_not_after"], "CLEANUP_AUTHORIZATION_INVALID")
    if (
        failed_stack_attestation.get("record_type") != FAILED_CREATE_STACK_RECORD_TYPE
        or failed_stack_attestation.get("intent_digest") != intent["intent_digest"]
        or failed_stack_attestation.get("stack_status")
        not in {"ROLLBACK_COMPLETE", "DELETE_FAILED"}
        or authorization != CLEANUP_AUTHORIZATION_PHRASES[target]
        or not _time(intent["route_not_before"], "CLEANUP_AUTHORIZATION_INVALID")
        <= authorized
        < expires
        <= cutoff
        or not 60 <= (expires - authorized).total_seconds() <= 900
    ):
        raise DeploymentRecoveryError("CLEANUP_AUTHORIZATION_INVALID")
    request_seed = {
        "record_type": CLEANUP_INTENT_RECORD_TYPE,
        "target": target,
        "execution_lane": execution_lane,
        "failed_stack_attestation_digest": failed_stack_attestation[
            "attestation_digest"
        ],
        "attempt": 1,
    }
    request = {
        "StackName": failed_stack_attestation["stack_arn"],
        "ClientRequestToken": "gug376-" + route.digest_value(request_seed)[7:55],
    }
    return route.seal(
        {
            "schema_version": 1,
            "record_type": CLEANUP_AUTHORIZATION_RECORD_TYPE,
            "source_commit": intent["source_commit"],
            "target": target,
            "execution_lane": execution_lane,
            "intent_digest": intent["intent_digest"],
            "failed_stack_attestation_digest": failed_stack_attestation[
                "attestation_digest"
            ],
            "cleanup_request_digest": route.digest_value(request),
            "authorization": authorization,
            "authorized_at": authorized_at,
            "expires_at": expires_at,
            "production_authorized": False,
        },
        "authorization_digest",
    )


def validate_cleanup_authorization(
    value: Mapping[str, Any],
    *,
    seed_intent: Mapping[str, Any],
    failed_stack_attestation: Mapping[str, Any],
) -> dict[str, Any]:
    fields = {
        "schema_version",
        "record_type",
        "source_commit",
        "target",
        "execution_lane",
        "intent_digest",
        "failed_stack_attestation_digest",
        "cleanup_request_digest",
        "authorization",
        "authorized_at",
        "expires_at",
        "production_authorized",
        "authorization_digest",
    }
    if not isinstance(value, Mapping) or set(value) != fields:
        raise DeploymentRecoveryError("CLEANUP_AUTHORIZATION_INVALID")
    _verify_seal(
        value,
        "authorization_digest",
        "CLEANUP_AUTHORIZATION_DIGEST_INVALID",
    )
    expected = materialize_cleanup_authorization(
        seed_intent=seed_intent,
        failed_stack_attestation=failed_stack_attestation,
        authorization=str(value.get("authorization", "")),
        authorized_at=str(value.get("authorized_at", "")),
        expires_at=str(value.get("expires_at", "")),
    )
    if dict(value) != expected:
        raise DeploymentRecoveryError("CLEANUP_AUTHORIZATION_INVALID")
    return json.loads(route.canonical_json(dict(value)))


def materialize_cleanup_intent(
    *,
    seed_intent: Mapping[str, Any],
    failed_stack_attestation: Mapping[str, Any],
    authorization: Mapping[str, Any],
) -> dict[str, Any]:
    try:
        intent = route.validate_seed_intent(seed_intent)
    except route.RouteSeedError as exc:
        raise DeploymentRecoveryError(exc.code) from exc
    failed_stack_attestation = _validate_failed_stack_attestation(
        failed_stack_attestation
    )
    authorization = validate_cleanup_authorization(
        authorization,
        seed_intent=intent,
        failed_stack_attestation=failed_stack_attestation,
    )
    target = str(failed_stack_attestation.get("target"))
    execution_lane = _execution_lane(
        target=target,
        change_set_arn=failed_stack_attestation["change_set_arn"],
    )
    failed_resources = failed_stack_attestation.get("resources")
    request_seed = {
        "record_type": CLEANUP_INTENT_RECORD_TYPE,
        "target": target,
        "execution_lane": execution_lane,
        "failed_stack_attestation_digest": failed_stack_attestation["attestation_digest"],
        "attempt": 1,
    }
    request = {
        "StackName": failed_stack_attestation["stack_arn"],
        "ClientRequestToken": "gug376-" + route.digest_value(request_seed)[7:55],
    }
    if (
        target not in {"route", "broker"}
        or authorization.get("record_type") != CLEANUP_AUTHORIZATION_RECORD_TYPE
        or authorization.get("target") != target
        or authorization.get("execution_lane") != execution_lane
        or authorization.get("intent_digest") != intent["intent_digest"]
        or authorization.get("failed_stack_attestation_digest")
        != failed_stack_attestation["attestation_digest"]
        or authorization.get("cleanup_request_digest") != route.digest_value(request)
        or authorization.get("authorization") != CLEANUP_AUTHORIZATION_PHRASES[target]
        or authorization.get("production_authorized") is not False
        or not isinstance(failed_resources, list)
        or failed_stack_attestation.get("resources_digest")
        != route.digest_value(failed_resources)
        or set(request) != {"StackName", "ClientRequestToken"}
        or "RoleARN" in request
        or "RetainResources" in request
        or "DeletionMode" in request
    ):
        raise DeploymentRecoveryError("CLEANUP_AUTHORIZATION_INVALID")
    return route.seal(
        {
            "schema_version": 1,
            "record_type": CLEANUP_INTENT_RECORD_TYPE,
            "source_commit": intent["source_commit"],
            "target": target,
            "account_id": _account_id(target),
            "execution_lane": execution_lane,
            "parent_intent_digest": intent["intent_digest"],
            "identity_center_instance_arn": intent[
                "identity_center_instance_arn"
            ],
            "failed_stack_attestation_digest": failed_stack_attestation["attestation_digest"],
            "failed_resources": failed_resources,
            "failed_resources_digest": route.digest_value(failed_resources),
            "authorization_digest": authorization["authorization_digest"],
            "authorization_not_before": authorization["authorized_at"],
            "authorization_expires_at": authorization["expires_at"],
            "route_not_before": intent["route_not_before"],
            "route_not_after": intent["route_not_after"],
            "recovery_not_after": intent["recovery_not_after"],
            "attempt": 1,
            "cleanup_role_name": CLEANUP_ROLE_NAMES[target],
            "delete_request": request,
            "delete_request_digest": route.digest_value(request),
            "aws_calls": 0,
            "aws_mutations": 0,
            "retry_permitted": False,
            "production_authorized": False,
            "production_status": route.PRODUCTION_STATUS,
        },
        "cleanup_intent_digest",
    )


def validate_cleanup_intent_structure(value: Mapping[str, Any]) -> dict[str, Any]:
    """Validate cleanup shape only; never authorizes DeleteStack."""
    _verify_seal(value, "cleanup_intent_digest", "CLEANUP_INTENT_DIGEST_INVALID")
    fields = {
        "schema_version",
        "record_type",
        "source_commit",
        "target",
        "account_id",
        "execution_lane",
        "parent_intent_digest",
        "identity_center_instance_arn",
        "failed_stack_attestation_digest",
        "failed_resources",
        "failed_resources_digest",
        "authorization_digest",
        "authorization_not_before",
        "authorization_expires_at",
        "route_not_before",
        "route_not_after",
        "recovery_not_after",
        "attempt",
        "cleanup_role_name",
        "delete_request",
        "delete_request_digest",
        "aws_calls",
        "aws_mutations",
        "retry_permitted",
        "production_authorized",
        "production_status",
        "cleanup_intent_digest",
    }
    target = str(value.get("target"))
    request = value.get("delete_request")
    request_seed = {
        "record_type": CLEANUP_INTENT_RECORD_TYPE,
        "target": target,
        "execution_lane": value.get("execution_lane"),
        "failed_stack_attestation_digest": value.get(
            "failed_stack_attestation_digest"
        ),
        "attempt": 1,
    }
    expected_token = "gug376-" + route.digest_value(request_seed)[7:55]
    if (
        set(value) != fields
        or value.get("schema_version") != 1
        or value.get("record_type") != CLEANUP_INTENT_RECORD_TYPE
        or re.fullmatch(r"[a-f0-9]{40}", str(value.get("source_commit", "")))
        is None
        or any(
            _DIGEST_RE.fullmatch(str(value.get(field, ""))) is None
            for field in (
                "parent_intent_digest",
                "failed_stack_attestation_digest",
                "authorization_digest",
            )
        )
        or target not in {"route", "broker"}
        or value.get("execution_lane") not in {"primary", "reentry"}
        or value.get("account_id") != _account_id(target)
        or not isinstance(value.get("identity_center_instance_arn"), str)
        or re.fullmatch(
            r"arn:aws:sso:::instance/ssoins-[A-Za-z0-9]{16}",
            value["identity_center_instance_arn"],
        )
        is None
        or value.get("cleanup_role_name") != CLEANUP_ROLE_NAMES[target]
        or value.get("attempt") != 1
        or not isinstance(value.get("failed_resources"), list)
        or value.get("failed_resources_digest")
        != route.digest_value(value.get("failed_resources"))
        or not isinstance(request, Mapping)
        or set(request) != {"StackName", "ClientRequestToken"}
        or value.get("delete_request_digest") != route.digest_value(request)
        or request.get("ClientRequestToken") != expected_token
        or value.get("aws_calls") != 0
        or value.get("aws_mutations") != 0
        or value.get("retry_permitted") is not False
        or value.get("production_authorized") is not False
        or value.get("production_status") != route.PRODUCTION_STATUS
    ):
        raise DeploymentRecoveryError("CLEANUP_INTENT_INVALID")
    try:
        _full_arn(
            request["StackName"],
            account_id=_account_id(target),
            kind="stack",
            name=_stack_name(target),
        )
    except DeploymentRecoveryError as exc:
        raise DeploymentRecoveryError("CLEANUP_INTENT_INVALID") from exc
    authorized = _time(
        value.get("authorization_not_before"), "CLEANUP_INTENT_INVALID"
    )
    expires = _time(
        value.get("authorization_expires_at"), "CLEANUP_INTENT_INVALID"
    )
    route_not_after = _time(value.get("route_not_after"), "CLEANUP_INTENT_INVALID")
    recovery_not_after = _time(
        value.get("recovery_not_after"), "CLEANUP_INTENT_INVALID"
    )
    if (
        not _time(value.get("route_not_before"), "CLEANUP_INTENT_INVALID")
        <= authorized
        < expires
        <= recovery_not_after
        or recovery_not_after != route_not_after + timedelta(hours=24)
    ):
        raise DeploymentRecoveryError("CLEANUP_INTENT_INVALID")
    return json.loads(route.canonical_json(value))


def validate_cleanup_intent(
    value: Mapping[str, Any],
    *,
    seed_intent: Mapping[str, Any],
    failed_stack_attestation: Mapping[str, Any],
    authorization: Mapping[str, Any],
) -> dict[str, Any]:
    """Reconstruct cleanup from the exact seed, failure and authorization."""

    validated = validate_cleanup_intent_structure(value)
    expected = materialize_cleanup_intent(
        seed_intent=seed_intent,
        failed_stack_attestation=failed_stack_attestation,
        authorization=authorization,
    )
    if validated != expected:
        raise DeploymentRecoveryError("CLEANUP_INTENT_CAUSAL_MISMATCH")
    return validated


def _validate_cleanup_claim(
    value: Mapping[str, Any],
    *,
    intent: Mapping[str, Any],
    dispatch: Mapping[str, Any],
) -> dict[str, Any]:
    fields = {
        "schema_version",
        "record_type",
        "operation",
        "target",
        "execution_lane",
        "attempt",
        "cleanup_intent_digest",
        "failed_stack_attestation_digest",
        "failed_resources_digest",
        "request_digest",
        "client_request_token",
        "stack_arn",
        "caller_arn_digest",
        "claimed_at",
        "retry_permitted",
        "production_authorized",
    }
    request = intent["delete_request"]
    if (
        set(value) != fields
        or value.get("schema_version") != 1
        or value.get("record_type") != CLAIM_RECORD_TYPE
        or value.get("operation") != "DeleteStack"
        or value.get("target") != intent["target"]
        or value.get("execution_lane") != intent["execution_lane"]
        or value.get("attempt") != 1
        or value.get("cleanup_intent_digest") != intent["cleanup_intent_digest"]
        or value.get("failed_stack_attestation_digest")
        != intent["failed_stack_attestation_digest"]
        or value.get("failed_resources_digest")
        != intent["failed_resources_digest"]
        or value.get("request_digest") != intent["delete_request_digest"]
        or value.get("client_request_token") != request["ClientRequestToken"]
        or value.get("stack_arn") != request["StackName"]
        or _DIGEST_RE.fullmatch(str(value.get("caller_arn_digest", ""))) is None
        or value.get("retry_permitted") is not False
        or value.get("production_authorized") is not False
    ):
        raise DeploymentRecoveryError("CLEANUP_CLAIM_INVALID")
    claimed_at = _time(value.get("claimed_at"), "CLEANUP_CLAIM_INVALID")
    dispatched_at = _time(
        dispatch.get("dispatched_at"), "CLEANUP_DISPATCH_INVALID"
    )
    if not _time(
        intent["authorization_not_before"], "CLEANUP_CLAIM_INVALID"
    ) <= claimed_at <= dispatched_at < _time(
        intent["authorization_expires_at"], "CLEANUP_CLAIM_INVALID"
    ):
        raise DeploymentRecoveryError("CLEANUP_CLAIM_INVALID")
    return json.loads(route.canonical_json(value))


def clients_from_session(
    session: Any,
    config_type: Any,
    *,
    expected_profile: str,
    environment: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """Build pinned clients, including the two dedicated cleanup profiles."""

    if expected_profile not in _CLEANUP_PROFILE_CONTRACTS:
        try:
            return connected.clients_from_session(
                session,
                config_type,
                expected_profile=expected_profile,
                environment=environment,
            )
        except connected.ConnectedRouteError as exc:
            raise DeploymentRecoveryError(exc.code) from exc
    values = os.environ if environment is None else environment
    if any(values.get(key) for key in connected._AMBIENT_AWS_FORBIDDEN) or any(
        value
        and (key == "AWS_ENDPOINT_URL" or key.startswith("AWS_ENDPOINT_URL_"))
        for key, value in values.items()
    ):
        raise DeploymentRecoveryError("AMBIENT_AWS_CONFIGURATION_FORBIDDEN")
    if any(
        values.get(key) not in {None, "", expected_profile}
        for key in ("AWS_PROFILE", "AWS_DEFAULT_PROFILE")
    ):
        raise DeploymentRecoveryError("AMBIENT_PROFILE_INVALID")
    if any(
        values.get(key) not in {None, "", route.REGION}
        for key in ("AWS_REGION", "AWS_DEFAULT_REGION")
    ):
        raise DeploymentRecoveryError("AMBIENT_REGION_INVALID")
    expected_account, expected_role = _CLEANUP_PROFILE_CONTRACTS[expected_profile]
    if (
        getattr(session, "profile_name", None) != expected_profile
        or getattr(session, "region_name", None) != route.REGION
    ):
        raise DeploymentRecoveryError("AWS_SESSION_INVALID")
    internal = getattr(session, "_session", None)
    full_config = getattr(internal, "full_config", None)
    profiles = full_config.get("profiles") if isinstance(full_config, Mapping) else None
    document = profiles.get(expected_profile) if isinstance(profiles, Mapping) else None
    if (
        not isinstance(document, Mapping)
        or not set(document).issubset(connected._PROFILE_CONFIGURATION_KEYS)
        or document.get("region") != route.REGION
        or document.get("sso_account_id") != expected_account
        or document.get("sso_role_name") != expected_role
    ):
        raise DeploymentRecoveryError("AWS_SSO_CONFIGURATION_INVALID")
    sso_session_name = document.get("sso_session")
    try:
        if sso_session_name is None:
            if document.get("sso_region") != route.REGION:
                raise DeploymentRecoveryError("AWS_SSO_CONFIGURATION_INVALID")
            connected._validate_sso_start_url(document.get("sso_start_url"))
        else:
            sessions = (
                full_config.get("sso_sessions")
                if isinstance(full_config, Mapping)
                else None
            )
            selected = (
                sessions.get(sso_session_name)
                if isinstance(sso_session_name, str)
                and isinstance(sessions, Mapping)
                else None
            )
            if (
                not isinstance(selected, Mapping)
                or not set(selected).issubset(
                    connected._SSO_SESSION_CONFIGURATION_KEYS
                )
                or selected.get("sso_region") != route.REGION
                or document.get("sso_region") is not None
                or document.get("sso_start_url") is not None
            ):
                raise DeploymentRecoveryError("AWS_SSO_CONFIGURATION_INVALID")
            connected._validate_sso_start_url(selected.get("sso_start_url"))
    except connected.ConnectedRouteError as exc:
        raise DeploymentRecoveryError(exc.code) from exc
    try:
        credentials = session.get_credentials()
    except Exception as exc:
        raise DeploymentRecoveryError("AWS_SSO_CREDENTIALS_UNAVAILABLE") from exc
    if credentials is None or getattr(credentials, "method", None) != "sso":
        raise DeploymentRecoveryError("AWS_CREDENTIAL_SOURCE_INVALID")
    config = connected.sdk_client_config(config_type)
    clients: dict[str, Any] = {}
    for service in (
        "sts",
        "cloudformation",
        "cloudtrail",
        "sso-admin",
        "lambda",
        "iam",
        "dynamodb",
        "kms",
        "logs",
    ):
        try:
            clients[service] = connected._client(session, service, config)
        except connected.ConnectedRouteError as exc:
            raise DeploymentRecoveryError(exc.code) from exc
    return clients


class ConnectedDeploymentRecoveryProvider:
    """Connected provider with finite recovery and cleanup mutation surfaces."""

    def __init__(
        self,
        *,
        clients: Mapping[str, Any],
        claims: connected.OExclClaimStore,
        clock: Callable[[], datetime],
        collision_admission_loader: CollisionAdmissionLoader | None = None,
    ) -> None:
        required = {
            "sts",
            "cloudformation",
            "cloudtrail",
            "dynamodb",
            "kms",
            "lambda",
            "iam",
            "logs",
            "sso-admin",
        }
        if set(clients) != required:
            raise DeploymentRecoveryError("CLIENT_SET_INVALID")
        self._sts = clients["sts"]
        self._cfn = clients["cloudformation"]
        self._trail = clients["cloudtrail"]
        self._dynamodb = clients["dynamodb"]
        self._kms = clients["kms"]
        self._lambda = clients["lambda"]
        self._iam = clients["iam"]
        self._logs = clients["logs"]
        self._sso = clients["sso-admin"]
        self._claims = claims
        self._clock = clock
        self._collision_admission_loader = collision_admission_loader

    def _load_collision_admission(
        self,
        *,
        operation: str,
        effect_request: Mapping[str, Any],
        bootstrap_intent_digest: str,
        now: datetime,
    ) -> object:
        """Load the one-shot capability before its post-loader clock gate."""

        loader = self._collision_admission_loader
        if loader is None:
            raise DeploymentRecoveryError("COLLISION_ADMISSION_REQUIRED")
        effect_request_digest = route.digest_value(effect_request)
        try:
            return invoke_route_collision_admission_loader(
                loader,
                operation=operation,
                effect_request=effect_request,
                effect_request_digest=effect_request_digest,
                bootstrap_intent_digest=bootstrap_intent_digest,
                now=now,
            )
        except RouteCollisionAdmissionError as exc:
            raise DeploymentRecoveryError(exc.code) from exc

    def _assert_collision_admission(
        self,
        capability: object,
        *,
        operation: str,
        effect_request: Mapping[str, Any],
        bootstrap_intent_digest: str,
        now: datetime,
    ) -> tuple[dict[str, str], RouteCollisionAdmissionEffectGrant]:
        """Consume one exact admission and retain its verified time bounds."""

        effect_request_digest = route.digest_value(effect_request)
        try:
            grant = consume_route_collision_admission(
                capability,
                operation=operation,
                effect_request_digest=effect_request_digest,
                bootstrap_intent_digest=bootstrap_intent_digest,
                now=now,
            )
        except RouteCollisionAdmissionError as exc:
            raise DeploymentRecoveryError(exc.code) from exc
        binding = _validate_collision_admission_binding(
            {
                "operation": operation,
                "effect_request_digest": effect_request_digest,
                "bootstrap_intent_digest": bootstrap_intent_digest,
                "admission_digest": grant.admission_digest,
            },
            operation=operation,
            effect_request=effect_request,
            bootstrap_intent_digest=bootstrap_intent_digest,
        )
        return binding, grant

    @staticmethod
    def _require_collision_admission_active(
        grant: RouteCollisionAdmissionEffectGrant,
        *,
        observed_at: datetime,
        expected_admission_digest: str,
    ) -> None:
        """Prove the consumed short admission still covers the effect."""

        try:
            admission_digest = (
                revalidate_route_collision_admission_effect_grant(
                    grant,
                    now=observed_at,
                )
            )
        except RouteCollisionAdmissionError as exc:
            raise DeploymentRecoveryError(exc.code) from exc
        if admission_digest != expected_admission_digest:
            raise DeploymentRecoveryError(
                "COLLISION_ADMISSION_BINDING_INVALID"
            )

    @staticmethod
    def _normal_identity(sts: Any, *, target: str, phase: str) -> tuple[str, str]:
        try:
            return connected._verify_identity(sts, target=target, phase=phase)
        except connected.ConnectedRouteError as exc:
            raise DeploymentRecoveryError(exc.code) from exc

    def _cleanup_identity(self, *, target: str) -> tuple[str, str]:
        response = self._sts.get_caller_identity()
        account = _account_id(target)
        arn = response.get("Arn") if isinstance(response, Mapping) else None
        if (
            not isinstance(response, Mapping)
            or response.get("Account") != account
            or not isinstance(response.get("UserId"), str)
            or not response["UserId"]
            or not isinstance(arn, str)
            or not _caller_arn_matches_phase(
                arn, target=target, phase="cleanup"
            )
        ):
            raise DeploymentRecoveryError("CLEANUP_STS_IDENTITY_INVALID")
        return account, arn

    @staticmethod
    def _require_missing(
        call: Callable[..., Any],
        request: Mapping[str, Any],
        *,
        codes: frozenset[str],
        statuses: frozenset[int],
        code: str,
    ) -> None:
        try:
            call(**dict(request))
        except Exception as exc:
            if _service_not_found(exc, codes=codes, statuses=statuses):
                return
            raise DeploymentRecoveryError(code) from exc
        raise DeploymentRecoveryError(code)

    def _prove_no_active_survivors(
        self, *, intent: Mapping[str, Any]
    ) -> tuple[str, int, list[dict[str, Any]]]:
        """Prove no active survivor can block a bounded create reentry.

        Stack absence alone is insufficient when a failed DELETE can leave
        retained resources.  Every not-found below is service-native and exact;
        permission errors or malformed responses fail closed.  A captured KMS
        key is the sole allowed inert survivor because AWS keeps it in
        PendingDeletion for at least seven days; the fixed alias must still be
        absent and the exact key must be disabled with a future deletion date.
        """

        target = intent["target"]
        resources = intent.get("failed_resources")
        if not isinstance(resources, list):
            raise DeploymentRecoveryError("FIXED_RESOURCE_INVENTORY_INVALID")
        physical_by_logical = {
            item.get("logical_resource_id"): item.get("physical_resource_id")
            for item in resources
            if isinstance(item, Mapping)
        }
        if len(physical_by_logical) != len(resources):
            raise DeploymentRecoveryError("FIXED_RESOURCE_INVENTORY_INVALID")
        evidence: list[dict[str, Any]] = []
        scheduled_inert: list[dict[str, Any]] = []
        calls = 0

        def missing(
            service: str,
            resource: str,
            call: Callable[..., Any],
            request: Mapping[str, Any],
            *,
            codes: frozenset[str],
            statuses: frozenset[int],
        ) -> None:
            nonlocal calls
            calls += 1
            self._require_missing(
                call,
                request,
                codes=codes,
                statuses=statuses,
                code="FIXED_RESOURCE_ABSENCE_UNPROVEN",
            )
            evidence.append(
                {"service": service, "resource": resource, "absent": True}
            )

        if target == "route":
            captured_role_names = {
                item.get("physical_resource_id")
                for item in resources
                if isinstance(item, Mapping)
                and item.get("resource_type") == "AWS::IAM::Role"
                and item.get("physical_resource_id") is not None
            }
            if any(
                not isinstance(name, str)
                or re.fullmatch(r"[A-Za-z0-9+=,.@_-]{1,64}", name) is None
                for name in captured_role_names
            ):
                raise DeploymentRecoveryError("FIXED_RESOURCE_INVENTORY_INVALID")
            for role_name in sorted(
                set(ROUTE_FIXED_IAM_ROLE_NAMES) | captured_role_names
            ):
                missing(
                    "iam",
                    f"role/{role_name}",
                    self._iam.get_role,
                    {"RoleName": role_name},
                    codes=frozenset({"NoSuchEntity", "NoSuchEntityException"}),
                    statuses=frozenset({404}),
                )
            captured_permission_sets = {
                item.get("physical_resource_id")
                for item in resources
                if isinstance(item, Mapping)
                and item.get("resource_type") == "AWS::SSO::PermissionSet"
                and item.get("physical_resource_id") is not None
            }
            if any(
                not isinstance(arn, str)
                or re.fullmatch(
                    r"arn:aws:sso:::permissionSet/"
                    r"ssoins-[A-Za-z0-9]{16}/ps-[A-Za-z0-9]{16}",
                    arn,
                )
                is None
                for arn in captured_permission_sets
            ):
                raise DeploymentRecoveryError("FIXED_RESOURCE_INVENTORY_INVALID")
            for permission_arn in sorted(captured_permission_sets):
                missing(
                    "sso-admin",
                    permission_arn,
                    self._sso.describe_permission_set,
                    {
                        "InstanceArn": intent["identity_center_instance_arn"],
                        "PermissionSetArn": permission_arn,
                    },
                    codes=frozenset({"ResourceNotFoundException"}),
                    statuses=frozenset({400}),
                )
            try:
                permission_arns, page_count = connected._paginate_items(
                    self._sso.list_permission_sets,
                    request={
                        "InstanceArn": intent["identity_center_instance_arn"],
                        "MaxResults": 100,
                    },
                    item_key="PermissionSets",
                    error_code="FIXED_RESOURCE_ABSENCE_UNPROVEN",
                )
            except (connected.ConnectedRouteError, KeyError) as exc:
                raise DeploymentRecoveryError(
                    "FIXED_RESOURCE_ABSENCE_UNPROVEN"
                ) from exc
            calls += page_count
            exact_found: list[str] = []
            for permission_arn in permission_arns:
                if not isinstance(permission_arn, str) or not permission_arn:
                    raise DeploymentRecoveryError(
                        "FIXED_RESOURCE_ABSENCE_UNPROVEN"
                    )
                calls += 1
                try:
                    response = self._sso.describe_permission_set(
                        InstanceArn=intent["identity_center_instance_arn"],
                        PermissionSetArn=permission_arn,
                    )
                except Exception as exc:
                    if _service_not_found(
                        exc,
                        codes=frozenset({"ResourceNotFoundException"}),
                        statuses=frozenset({400}),
                    ):
                        continue
                    raise DeploymentRecoveryError(
                        "FIXED_RESOURCE_ABSENCE_UNPROVEN"
                    ) from exc
                permission = response.get("PermissionSet")
                if not isinstance(permission, Mapping):
                    raise DeploymentRecoveryError(
                        "FIXED_RESOURCE_ABSENCE_UNPROVEN"
                    )
                name = permission.get("Name")
                if name in ROUTE_FIXED_PERMISSION_SET_NAMES:
                    exact_found.append(str(name))
            if exact_found:
                raise DeploymentRecoveryError("FIXED_RESOURCE_SURVIVOR_PRESENT")
            for name in ROUTE_FIXED_PERMISSION_SET_NAMES:
                evidence.append(
                    {
                        "service": "sso-admin",
                        "resource": f"permission-set/{name}",
                        "absent": True,
                    }
                )
        elif target == "broker":
            missing(
                "dynamodb",
                f"table/{BROKER_FIXED_TABLE_NAME}",
                self._dynamodb.describe_table,
                {"TableName": BROKER_FIXED_TABLE_NAME},
                codes=frozenset({"ResourceNotFoundException"}),
                statuses=frozenset({400}),
            )
            missing(
                "kms",
                BROKER_FIXED_KMS_ALIAS,
                self._kms.describe_key,
                {"KeyId": BROKER_FIXED_KMS_ALIAS},
                codes=frozenset({"NotFoundException"}),
                statuses=frozenset({400}),
            )
            key_id = physical_by_logical.get("BrokerLedgerKey")
            if key_id is not None:
                if not isinstance(key_id, str) or _KMS_KEY_ID_RE.fullmatch(key_id) is None:
                    raise DeploymentRecoveryError(
                        "FIXED_RESOURCE_INVENTORY_INVALID"
                    )
                calls += 1
                try:
                    key_response = self._kms.describe_key(KeyId=key_id)
                except Exception as exc:
                    if not _service_not_found(
                        exc,
                        codes=frozenset({"NotFoundException"}),
                        statuses=frozenset({400}),
                    ):
                        raise DeploymentRecoveryError(
                            "FIXED_RESOURCE_ABSENCE_UNPROVEN"
                        ) from exc
                    evidence.append(
                        {
                            "service": "kms",
                            "resource": f"key/{key_id}",
                            "absent": True,
                        }
                    )
                else:
                    metadata = (
                        key_response.get("KeyMetadata")
                        if isinstance(key_response, Mapping)
                        else None
                    )
                    deletion_date = (
                        metadata.get("DeletionDate")
                        if isinstance(metadata, Mapping)
                        else None
                    )
                    observed_at = _normalized_clock(self._clock)
                    expected_arn = (
                        f"arn:aws:kms:{route.REGION}:"
                        f"{route.AUTHORITY_ACCOUNT_ID}:key/{key_id}"
                    )
                    if (
                        not isinstance(metadata, Mapping)
                        or metadata.get("KeyId") != key_id
                        or metadata.get("Arn") != expected_arn
                        or metadata.get("KeyState") != "PendingDeletion"
                        or metadata.get("Enabled") is not False
                        or not isinstance(deletion_date, datetime)
                        or deletion_date.tzinfo is None
                        or deletion_date.utcoffset() is None
                    ):
                        raise DeploymentRecoveryError(
                            "FIXED_RESOURCE_ACTIVE_SURVIVOR"
                        )
                    deletion_date = deletion_date.astimezone(timezone.utc)
                    if not (
                        observed_at
                        < deletion_date
                        <= observed_at + timedelta(days=30)
                    ):
                        raise DeploymentRecoveryError(
                            "FIXED_RESOURCE_ACTIVE_SURVIVOR"
                        )
                    scheduled = {
                        "service": "kms",
                        "resource": expected_arn,
                        "state": "PendingDeletion",
                        "enabled": False,
                        "deletion_date": _stamp(deletion_date),
                    }
                    evidence.append(dict(scheduled))
                    scheduled_inert.append(scheduled)
            captured_function_names = {
                item.get("physical_resource_id")
                for item in resources
                if isinstance(item, Mapping)
                and item.get("resource_type") == "AWS::Lambda::Function"
                and item.get("physical_resource_id") is not None
            }
            if any(
                not isinstance(name, str)
                or re.fullmatch(r"[A-Za-z0-9_-]{1,64}", name) is None
                for name in captured_function_names
            ):
                raise DeploymentRecoveryError("FIXED_RESOURCE_INVENTORY_INVALID")
            for function_name in sorted(
                set(BROKER_FIXED_FUNCTION_NAMES) | captured_function_names
            ):
                missing(
                    "lambda",
                    f"function/{function_name}",
                    self._lambda.get_function,
                    {"FunctionName": function_name},
                    codes=frozenset({"ResourceNotFoundException"}),
                    statuses=frozenset({404}),
                )
            signing_config = physical_by_logical.get("BrokerCodeSigningConfig")
            if signing_config is not None:
                if not isinstance(signing_config, str) or not signing_config.startswith(
                    "arn:aws:lambda:us-east-1:042360977644:code-signing-config:"
                ):
                    raise DeploymentRecoveryError(
                        "FIXED_RESOURCE_INVENTORY_INVALID"
                    )
                missing(
                    "lambda",
                    signing_config,
                    self._lambda.get_code_signing_config,
                    {"CodeSigningConfigArn": signing_config},
                    codes=frozenset({"ResourceNotFoundException"}),
                    statuses=frozenset({404}),
                )
            captured_role_names = {
                item.get("physical_resource_id")
                for item in resources
                if isinstance(item, Mapping)
                and item.get("resource_type") == "AWS::IAM::Role"
                and item.get("physical_resource_id") is not None
            }
            if any(
                not isinstance(name, str)
                or re.fullmatch(r"[A-Za-z0-9+=,.@_-]{1,64}", name) is None
                for name in captured_role_names
            ):
                raise DeploymentRecoveryError("FIXED_RESOURCE_INVENTORY_INVALID")
            for role_name in sorted(
                set(BROKER_FIXED_IAM_ROLE_NAMES) | captured_role_names
            ):
                missing(
                    "iam",
                    f"role/{role_name}",
                    self._iam.get_role,
                    {"RoleName": role_name},
                    codes=frozenset({"NoSuchEntity", "NoSuchEntityException"}),
                    statuses=frozenset({404}),
                )
            captured_log_names = {
                item.get("physical_resource_id")
                for item in resources
                if isinstance(item, Mapping)
                and item.get("resource_type") == "AWS::Logs::LogGroup"
                and item.get("physical_resource_id") is not None
            }
            if any(
                not isinstance(name, str)
                or not name.startswith("/aws/lambda/")
                or len(name) > 512
                for name in captured_log_names
            ):
                raise DeploymentRecoveryError("FIXED_RESOURCE_INVENTORY_INVALID")
            for log_name in sorted(
                set(BROKER_FIXED_LOG_GROUP_NAMES) | captured_log_names
            ):
                token: str | None = None
                seen: set[str] = set()
                while True:
                    request: dict[str, Any] = {
                        "logGroupNamePrefix": log_name,
                        "limit": 50,
                    }
                    if token is not None:
                        request["nextToken"] = token
                    calls += 1
                    try:
                        response = self._logs.describe_log_groups(**request)
                    except Exception as exc:
                        raise DeploymentRecoveryError(
                            "FIXED_RESOURCE_ABSENCE_UNPROVEN"
                        ) from exc
                    groups = response.get("logGroups")
                    if not isinstance(groups, list) or any(
                        not isinstance(item, Mapping) for item in groups
                    ):
                        raise DeploymentRecoveryError(
                            "FIXED_RESOURCE_ABSENCE_UNPROVEN"
                        )
                    if any(item.get("logGroupName") == log_name for item in groups):
                        raise DeploymentRecoveryError(
                            "FIXED_RESOURCE_SURVIVOR_PRESENT"
                        )
                    next_token = response.get("nextToken")
                    if next_token is None:
                        break
                    if (
                        not isinstance(next_token, str)
                        or not next_token
                        or next_token in seen
                        or len(seen) >= 99
                    ):
                        raise DeploymentRecoveryError(
                            "FIXED_RESOURCE_ABSENCE_UNPROVEN"
                        )
                    seen.add(next_token)
                    token = next_token
                evidence.append(
                    {"service": "logs", "resource": log_name, "absent": True}
                )
        else:
            raise DeploymentRecoveryError("TARGET_INVALID")
        ordered = sorted(
            evidence, key=lambda item: (item["service"], item["resource"])
        )
        return route.digest_value(ordered), calls, scheduled_inert

    def _revalidate_cleanup_terminal_live(
        self,
        *,
        seed: Mapping[str, Any],
        terminal: Mapping[str, Any],
        claim: Mapping[str, Any],
        dispatch: Mapping[str, Any],
        request: Mapping[str, Any],
        observed_at: datetime,
    ) -> None:
        target = str(terminal["target"])
        delete_digest, _pages = _delete_event_digest(
            self._trail,
            account=_account_id(target),
            claim=claim,
            dispatch=dispatch,
            request=request,
            now=observed_at,
        )
        if delete_digest != terminal["delete_cloudtrail_event_digest"]:
            raise DeploymentRecoveryError(
                "FAILURE_ATTESTATION_LIVE_BINDING_INVALID"
            )
        observed_terminal = "NOT_FOUND"
        try:
            response = self._cfn.describe_stacks(
                StackName=terminal["stack_arn"]
            )
        except Exception as exc:
            if not _is_stack_not_found(exc):
                raise DeploymentRecoveryError(
                    "CLEANUP_TERMINAL_READBACK_INVALID"
                ) from exc
        else:
            stacks = response.get("Stacks") if isinstance(response, Mapping) else None
            if (
                response.get("NextToken") is not None
                or not isinstance(stacks, list)
                or len(stacks) != 1
                or stacks[0].get("StackId") != terminal["stack_arn"]
                or stacks[0].get("StackStatus") != "DELETE_COMPLETE"
            ):
                raise DeploymentRecoveryError("CLEANUP_NOT_TERMINAL")
            observed_terminal = "DELETE_COMPLETE"
        try:
            self._cfn.describe_stacks(StackName=_stack_name(target))
        except Exception as exc:
            if not _is_stack_not_found(exc):
                raise DeploymentRecoveryError(
                    "CLEANUP_FIXED_NAME_READBACK_INVALID"
                ) from exc
        else:
            raise DeploymentRecoveryError("CLEANUP_FIXED_NAME_STILL_PRESENT")
        proof_intent = {
            "target": target,
            "failed_resources": terminal["failed_resources"],
            "identity_center_instance_arn": seed[
                "identity_center_instance_arn"
            ],
        }
        evidence_digest, calls, scheduled = self._prove_no_active_survivors(
            intent=proof_intent
        )
        if (
            terminal.get("stack_terminal_observation")
            != observed_terminal
            or terminal.get("fixed_stack_name_absent") is not True
            or terminal.get("survivor_check_count") != calls
            or terminal.get("survivor_evidence_digest") != evidence_digest
            or terminal.get("no_active_survivors") is not True
            or terminal.get("scheduled_inert_survivor_count")
            != len(scheduled)
            or terminal.get("scheduled_inert_survivors") != scheduled
            or terminal.get("scheduled_inert_survivors_digest")
            != route.digest_value(scheduled)
            or _time(
                terminal.get("attested_at"),
                "FAILURE_ATTESTATION_LIVE_BINDING_INVALID",
            )
            > observed_at
        ):
            raise DeploymentRecoveryError(
                "FAILURE_ATTESTATION_LIVE_BINDING_INVALID"
            )

    def _revalidate_protection_failure_live(
        self,
        *,
        seed: Mapping[str, Any],
        failure: Mapping[str, Any],
        claim: Mapping[str, Any],
        receipt: Mapping[str, Any],
        request: Mapping[str, Any],
        observed_at: datetime,
    ) -> None:
        execute_digest, _pages = _execute_event_digest(
            self._trail,
            account=route.AUTHORITY_ACCOUNT_ID,
            claim=claim,
            execution={
                "target": route.BROKER_PROTECTION_TARGET,
                "execute_request": request,
            },
            receipt=receipt,
            now=observed_at,
        )
        stack, _stack_calls = _read_stack(
            self._cfn,
            stack_arn=failure["stack_arn"],
            code="PROTECTION_ROLLBACK_STACK_INVALID",
        )
        if (
            stack.get("StackId") != failure["stack_arn"]
            or stack.get("StackName") != route.BROKER_STACK_NAME
            or stack.get("StackStatus") != "UPDATE_ROLLBACK_COMPLETE"
        ):
            raise DeploymentRecoveryError(
                "PROTECTION_ROLLBACK_STACK_INVALID"
            )
        resources_response = self._cfn.list_stack_resources(
            StackName=failure["stack_arn"]
        )
        resources = _resource_projection(
            resources_response, "PROTECTION_ROLLBACK_RESOURCES_INVALID"
        )
        expected_resources = seed["targets"]["broker"][
            "expected_resources"
        ]
        if [
            {
                "logical_resource_id": item["logical_resource_id"],
                "resource_type": item["resource_type"],
            }
            for item in resources
        ] != expected_resources:
            raise DeploymentRecoveryError(
                "PROTECTION_ROLLBACK_RESOURCES_INVALID"
            )
        table_item = next(
            (
                item
                for item in resources_response["StackResourceSummaries"]
                if item.get("LogicalResourceId") == "BrokerLedger"
            ),
            None,
        )
        key_item = next(
            (
                item
                for item in resources_response["StackResourceSummaries"]
                if item.get("LogicalResourceId") == "BrokerLedgerKey"
            ),
            None,
        )
        if not isinstance(table_item, Mapping) or not isinstance(
            key_item, Mapping
        ):
            raise DeploymentRecoveryError(
                "PROTECTION_ROLLBACK_LEDGER_INVALID"
            )
        key_id = key_item.get("PhysicalResourceId")
        if _KMS_KEY_ID_RE.fullmatch(str(key_id)) is None:
            raise DeploymentRecoveryError(
                "PROTECTION_ROLLBACK_LEDGER_INVALID"
            )
        expected_kms_arn = (
            f"arn:aws:kms:{route.REGION}:{route.AUTHORITY_ACCOUNT_ID}:"
            f"key/{key_id}"
        )
        table_response = self._dynamodb.describe_table(
            TableName=BROKER_FIXED_TABLE_NAME
        )
        table = table_response.get("Table")
        sse = table.get("SSEDescription") if isinstance(table, Mapping) else None
        if (
            not isinstance(table, Mapping)
            or table.get("TableName") != BROKER_FIXED_TABLE_NAME
            or table.get("TableArn")
            != (
                "arn:aws:dynamodb:us-east-1:042360977644:table/"
                f"{BROKER_FIXED_TABLE_NAME}"
            )
            or table.get("TableStatus") != "ACTIVE"
            or table.get("DeletionProtectionEnabled", False) is not False
            or not isinstance(sse, Mapping)
            or sse.get("Status") != "ENABLED"
            or sse.get("SSEType") != "KMS"
            or sse.get("KMSMasterKeyArn") != expected_kms_arn
        ):
            raise DeploymentRecoveryError(
                "PROTECTION_ROLLBACK_LEDGER_INVALID"
            )
        projection = {
            "table_name": table["TableName"],
            "table_arn": table["TableArn"],
            "table_status": table["TableStatus"],
            "deletion_protection_enabled": False,
            "sse_status": sse["Status"],
            "sse_type": sse["SSEType"],
            "kms_key_arn": expected_kms_arn,
        }
        if (
            execute_digest != failure["execute_cloudtrail_event_digest"]
            or failure.get("stack_status")
            != "UPDATE_ROLLBACK_COMPLETE"
            or failure.get("resource_count") != len(resources)
            or failure.get("resources_digest")
            != route.digest_value(resources)
            or failure.get("ledger_live_properties_digest")
            != route.digest_value(projection)
            or failure.get("ledger_deletion_protection_enabled") is not False
            or _time(
                failure.get("attested_at"),
                "FAILURE_ATTESTATION_LIVE_BINDING_INVALID",
            )
            > observed_at
        ):
            raise DeploymentRecoveryError(
                "FAILURE_ATTESTATION_LIVE_BINDING_INVALID"
            )

    def attest_preexecute_failure(
        self,
        *,
        seed_intent: Mapping[str, Any],
        target: str,
        primary_dispatch: Mapping[str, Any],
    ) -> dict[str, Any]:
        try:
            intent = route.validate_seed_intent(seed_intent)
        except route.RouteSeedError as exc:
            raise DeploymentRecoveryError(exc.code) from exc
        if target not in {"route", "broker"}:
            raise DeploymentRecoveryError("TARGET_INVALID")
        dispatch = _validate_primary_dispatch(
            primary_dispatch, intent=intent, target=target
        )
        spec = _target_spec(intent, target)
        claim = _primary_claim(self._claims, intent=intent, target=target)
        try:
            persisted_dispatch = _validate_primary_dispatch(
                self._claims.read_result(
                    _primary_claim_key(intent, target)
                ),
                intent=intent,
                target=target,
            )
        except connected.ConnectedRouteError as exc:
            raise DeploymentRecoveryError(exc.code) from exc
        if persisted_dispatch != dispatch:
            raise DeploymentRecoveryError(
                "PRIMARY_DISPATCH_JOURNAL_BINDING_INVALID"
            )
        before_sts = _recovery_window(intent, self._clock)
        # All causal/local checks precede the first AWS call.
        account, _caller = self._normal_identity(
            self._sts, target=target, phase="creator"
        )
        now = _recovery_window(intent, self._clock)
        if now < before_sts:
            raise DeploymentRecoveryError("CLOCK_REGRESSED")
        if account != spec["account_id"]:
            raise DeploymentRecoveryError("TARGET_ACCOUNT_INVALID")
        response = self._cfn.describe_change_set(
            StackName=dispatch["stack_arn"],
            ChangeSetName=dispatch["change_set_arn"],
        )
        request = spec["create_request"]
        reason = response.get("StatusReason")
        if (
            response.get("NextToken") is not None
            or response.get("ChangeSetId") != dispatch["change_set_arn"]
            or response.get("StackId") != dispatch["stack_arn"]
            or response.get("StackName") != spec["stack_name"]
            or response.get("ChangeSetName") != spec["change_set_name"]
            or response.get("Status") != "FAILED"
            or response.get("ExecutionStatus") != "UNAVAILABLE"
            or not isinstance(reason, str)
            or not reason.strip()
            or response.get("Description") != request["Description"]
            or response.get("ChangeSetType") != "CREATE"
            or not connected._change_set_parameters_match(
                response.get("Parameters"),
                request.get("Parameters", []),
                target=target,
            )
            or response.get("Capabilities", []) != request["Capabilities"]
            or response.get("Tags", []) != request["Tags"]
            or response.get("IncludeNestedStacks", False) is not False
            or response.get("NotificationARNs", []) != []
            or response.get("RollbackConfiguration", {})
            != request["RollbackConfiguration"]
            or response.get("OnStackFailure") != "DELETE"
            or "RoleARN" in response
            or "ResourcesToImport" in response
        ):
            raise DeploymentRecoveryError("PRIMARY_FAILURE_READBACK_INVALID")
        stack, stack_calls = _read_stack(
            self._cfn,
            stack_arn=dispatch["stack_arn"],
            code="PRIMARY_FAILURE_STACK_INVALID",
        )
        if (
            stack.get("StackId") != dispatch["stack_arn"]
            or stack.get("StackName") != spec["stack_name"]
            or stack.get("StackStatus") != "REVIEW_IN_PROGRESS"
        ):
            raise DeploymentRecoveryError("PRIMARY_FAILURE_STACK_INVALID")
        resources_response = self._cfn.list_stack_resources(
            StackName=dispatch["stack_arn"]
        )
        resources = _resource_projection(
            resources_response, "PRIMARY_FAILURE_RESOURCES_INVALID"
        )
        if resources:
            raise DeploymentRecoveryError("PRIMARY_FAILURE_RESOURCES_PRESENT")
        cloudtrail_digest, pages = _create_event_digest(
            self._trail,
            intent=intent,
            target=target,
            claim=claim,
            dispatch=dispatch,
            request=request,
            now=now,
        )
        return route.seal(
            {
                "schema_version": 1,
                "record_type": PREEXECUTE_FAILURE_RECORD_TYPE,
                "source_commit": intent["source_commit"],
                "target": target,
                "intent_digest": intent["intent_digest"],
                "primary_dispatch_digest": dispatch["dispatch_digest"],
                "primary_create_request_digest": spec["create_request_digest"],
                "primary_claim_digest": route.digest_value(claim),
                "primary_cloudtrail_event_digest": cloudtrail_digest,
                "account_id": account,
                "stack_arn": dispatch["stack_arn"],
                "change_set_arn": dispatch["change_set_arn"],
                "create_request_id": dispatch["create_request_id"],
                "status": "FAILED",
                "execution_status": "UNAVAILABLE",
                "status_reason_digest": route.digest_value(reason),
                "stack_status": "REVIEW_IN_PROGRESS",
                "resource_count": 0,
                "resources_digest": route.digest_value([]),
                "attested_at": _stamp(now),
                "aws_calls": 3 + pages + stack_calls,
                "aws_mutations": 0,
                "retry_permitted": False,
                "production_authorized": False,
                "production_status": route.PRODUCTION_STATUS,
            },
            "attestation_digest",
        )

    def create_reentry_change_set(
        self,
        *,
        seed_input: Mapping[str, Any],
        seed_intent: Mapping[str, Any],
        git: route.GitPort,
        failure_attestation: Mapping[str, Any],
        authorization: Mapping[str, Any],
        reentry_intent: Mapping[str, Any],
    ) -> dict[str, Any]:
        try:
            seed = route.validate_seed_intent_against_input(
                seed_intent,
                seed_input=seed_input,
                git=git,
                now=self._clock(),
            )
        except route.RouteSeedError as exc:
            raise DeploymentRecoveryError(exc.code) from exc
        intent = validate_reentry_intent(
            reentry_intent,
            seed_intent=seed,
            failure_attestation=failure_attestation,
            authorization=authorization,
        )
        target = intent["target"]
        failure_type = failure_attestation.get("record_type")
        if failure_type == PREEXECUTE_FAILURE_RECORD_TYPE:
            failure_context = _validate_primary_failure_journal(
                self._claims,
                intent=seed,
                failure_attestation=failure_attestation,
            )
        elif failure_type == CLEANUP_TERMINAL_RECORD_TYPE:
            failure_context = _validate_cleanup_terminal_journal(
                self._claims,
                intent=seed,
                failure_attestation=failure_attestation,
            )
        elif failure_type == PROTECTION_ROLLBACK_RECORD_TYPE:
            failure_context = _validate_protection_failure_journal(
                self._claims,
                intent=seed,
                failure_attestation=failure_attestation,
            )
        else:
            raise DeploymentRecoveryError("FAILURE_ATTESTATION_INVALID")
        now = _mutation_window(intent, self._clock)
        _require_active_authorization(
            intent,
            now,
            invalid_code="REENTRY_AUTHORIZATION_INVALID",
            inactive_code="REENTRY_AUTHORIZATION_NOT_ACTIVE",
        )
        account, caller = self._normal_identity(
            self._sts, target=target, phase="creator"
        )
        after_sts = _mutation_window(intent, self._clock)
        if after_sts < now:
            raise DeploymentRecoveryError("CLOCK_REGRESSED")
        _require_active_authorization(
            intent,
            after_sts,
            invalid_code="REENTRY_AUTHORIZATION_INVALID",
            inactive_code="REENTRY_AUTHORIZATION_NOT_ACTIVE",
        )
        if account != intent["account_id"]:
            raise DeploymentRecoveryError("TARGET_ACCOUNT_INVALID")
        if failure_type == PREEXECUTE_FAILURE_RECORD_TYPE:
            failure, primary_claim, primary_dispatch = failure_context
            _revalidate_primary_failure_live(
                cfn=self._cfn,
                trail=self._trail,
                intent=seed,
                failure=failure,
                claim=primary_claim,
                dispatch=primary_dispatch,
                observed_at=after_sts,
            )
        elif failure_type == CLEANUP_TERMINAL_RECORD_TYPE:
            terminal, cleanup_claim, cleanup_dispatch, cleanup_request = (
                failure_context
            )
            self._revalidate_cleanup_terminal_live(
                seed=seed,
                terminal=terminal,
                claim=cleanup_claim,
                dispatch=cleanup_dispatch,
                request=cleanup_request,
                observed_at=after_sts,
            )
        else:
            protection, execute_claim, execute_receipt, execute_request = (
                failure_context
            )
            self._revalidate_protection_failure_live(
                seed=seed,
                failure=protection,
                claim=execute_claim,
                receipt=execute_receipt,
                request=execute_request,
                observed_at=after_sts,
            )
        request = intent["create_request"]
        admission_operation = _reentry_collision_operation(
            target=target,
            failure_record_type=str(failure_type),
            effect="create",
        )
        key = (
            f"reentry-create:{target}:{intent['parent_intent_digest']}"
        )
        claim = {
            "schema_version": 1,
            "record_type": CLAIM_RECORD_TYPE,
            "operation": "CreateChangeSet",
            "target": target,
            "attempt": 1,
            "reentry_intent_digest": intent["reentry_intent_digest"],
            "request_digest": intent["create_request_digest"],
            "collision_admission": None,
            "client_token": request["ClientToken"],
            "stack_name": request["StackName"],
            "change_set_name": request["ChangeSetName"],
            "caller_arn_digest": route.digest_value(caller),
            "claimed_at": "",
            "retry_permitted": False,
            "production_authorized": False,
        }
        effect_at = _mutation_window(intent, self._clock)
        if effect_at < after_sts:
            raise DeploymentRecoveryError("CLOCK_REGRESSED")
        _require_active_authorization(
            intent,
            effect_at,
            invalid_code="REENTRY_AUTHORIZATION_INVALID",
            inactive_code="REENTRY_AUTHORIZATION_NOT_ACTIVE",
        )
        capability = self._load_collision_admission(
            operation=admission_operation,
            effect_request=request,
            bootstrap_intent_digest=intent["parent_intent_digest"],
            now=effect_at,
        )
        admission_at = _resample_authorized_mutation_time(
            intent,
            self._clock,
            previous_at=effect_at,
            invalid_code="REENTRY_AUTHORIZATION_INVALID",
            inactive_code="REENTRY_AUTHORIZATION_NOT_ACTIVE",
        )
        collision_admission, admission_grant = (
            self._assert_collision_admission(
                capability,
                operation=admission_operation,
                effect_request=request,
                bootstrap_intent_digest=intent["parent_intent_digest"],
                now=admission_at,
            )
        )
        claim["claimed_at"] = _stamp(admission_at)
        claim["collision_admission"] = collision_admission
        try:
            self._claims.claim(key, claim)
        except connected.ConnectedRouteError as exc:
            raise DeploymentRecoveryError(exc.code) from exc
        effect_at = _resample_authorized_mutation_time(
            intent,
            self._clock,
            previous_at=admission_at,
            invalid_code="REENTRY_AUTHORIZATION_INVALID",
            inactive_code="REENTRY_AUTHORIZATION_NOT_ACTIVE",
        )
        self._require_collision_admission_active(
            admission_grant,
            observed_at=effect_at,
            expected_admission_digest=collision_admission[
                "admission_digest"
            ],
        )
        try:
            response = self._cfn.create_change_set(**dict(request))
        except Exception as exc:
            raise DeploymentRecoveryError(
                "REENTRY_CREATE_CHANGE_SET_UNCERTAIN", uncertain=True
            ) from exc
        change_set_arn = response.get("Id")
        stack_arn = response.get("StackId")
        request_id = (response.get("ResponseMetadata") or {}).get("RequestId")
        _full_arn(
            change_set_arn,
            account_id=account,
            kind="changeSet",
            name=REENTRY_CHANGE_SET_NAMES[target],
        )
        _full_arn(
            stack_arn,
            account_id=account,
            kind="stack",
            name=_stack_name(target),
        )
        if _UUID_RE.fullmatch(str(request_id)) is None:
            raise DeploymentRecoveryError("REENTRY_CREATE_RESPONSE_UNCERTAIN", uncertain=True)
        receipt = route.seal(
            {
                "schema_version": 1,
                "record_type": REENTRY_DISPATCH_RECORD_TYPE,
                "source_commit": intent["source_commit"],
                "target": target,
                "account_id": account,
                "reentry_intent_digest": intent["reentry_intent_digest"],
                "create_request_digest": intent["create_request_digest"],
                "collision_admission": collision_admission,
                "stack_arn": stack_arn,
                "change_set_arn": change_set_arn,
                "create_request_id": request_id,
                "dispatched_at": _stamp(effect_at),
                "attempt": 1,
                "aws_mutations": 1,
                "retry_permitted": False,
                "production_authorized": False,
                "production_status": route.PRODUCTION_STATUS,
            },
            "dispatch_digest",
        )
        try:
            self._claims.complete(key, receipt)
        except connected.ConnectedRouteError as exc:
            raise DeploymentRecoveryError(
                "REENTRY_CREATE_RESULT_DURABILITY_UNCERTAIN", uncertain=True
            ) from exc
        return receipt

    def attest_reentry_change_set(
        self,
        *,
        seed_intent: Mapping[str, Any],
        failure_attestation: Mapping[str, Any],
        authorization: Mapping[str, Any],
        reentry_intent: Mapping[str, Any],
        dispatch: Mapping[str, Any],
    ) -> dict[str, Any]:
        try:
            seed = route.validate_seed_intent(seed_intent)
        except route.RouteSeedError as exc:
            raise DeploymentRecoveryError(exc.code) from exc
        intent = validate_reentry_intent(
            reentry_intent,
            seed_intent=seed,
            failure_attestation=failure_attestation,
            authorization=authorization,
        )
        failure_record_type = str(failure_attestation.get("record_type", ""))
        dispatch = _validate_reentry_dispatch(
            dispatch,
            reentry_intent=intent,
            failure_record_type=failure_record_type,
        )
        target = intent["target"]
        account, _caller = self._normal_identity(
            self._sts, target=target, phase="creator"
        )
        now = _recovery_window(intent, self._clock)
        _verify_seal(dispatch, "dispatch_digest", "REENTRY_DISPATCH_DIGEST_INVALID")
        request = intent["create_request"]
        if (
            intent.get("parent_intent_digest") != seed["intent_digest"]
            or intent.get("source_commit") != seed["source_commit"]
            or set(dispatch) != _REENTRY_DISPATCH_FIELDS
            or dispatch.get("schema_version") != 1
            or dispatch.get("record_type") != REENTRY_DISPATCH_RECORD_TYPE
            or dispatch.get("source_commit") != intent["source_commit"]
            or dispatch.get("reentry_intent_digest") != intent["reentry_intent_digest"]
            or dispatch.get("target") != target
            or dispatch.get("account_id") != account
            or dispatch.get("create_request_digest") != intent["create_request_digest"]
            or dispatch.get("attempt") != 1
            or dispatch.get("aws_mutations") != 1
            or dispatch.get("retry_permitted") is not False
            or dispatch.get("production_authorized") is not False
            or dispatch.get("production_status") != route.PRODUCTION_STATUS
        ):
            raise DeploymentRecoveryError("REENTRY_DISPATCH_INVALID")
        dispatched_at = _time(
            dispatch.get("dispatched_at"), "REENTRY_DISPATCH_INVALID"
        )
        if not _time(
            intent["authorization_not_before"], "REENTRY_DISPATCH_INVALID"
        ) <= dispatched_at < _time(
            intent["authorization_expires_at"], "REENTRY_DISPATCH_INVALID"
        ) or dispatched_at > now:
            raise DeploymentRecoveryError("REENTRY_DISPATCH_INVALID")
        readback = _authoritative_reentry_change_set_readback(
            self._cfn,
            seed_intent=seed,
            reentry_intent=intent,
            dispatch=dispatch,
            observed_at=now,
        )
        key = (
            f"reentry-create:{target}:{intent['parent_intent_digest']}"
        )
        try:
            claim = self._claims.read_claim(key)
        except connected.ConnectedRouteError as exc:
            raise DeploymentRecoveryError(exc.code) from exc
        claim = _validate_reentry_create_claim(
            claim,
            intent=intent,
            dispatch=dispatch,
            failure_record_type=failure_record_type,
        )
        cloudtrail_digest, pages = _reentry_create_event_digest(
            self._trail,
            account=account,
            claim=claim,
            dispatch=dispatch,
            request=request,
            now=now,
        )
        return route.seal(
            {
                "schema_version": 1,
                "record_type": REENTRY_ATTESTATION_RECORD_TYPE,
                "source_commit": intent["source_commit"],
                "target": target,
                "account_id": account,
                "parent_intent_digest": intent["parent_intent_digest"],
                "reentry_intent_digest": intent["reentry_intent_digest"],
                "create_request_digest": intent["create_request_digest"],
                "collision_admission": dispatch["collision_admission"],
                "dispatch_digest": dispatch["dispatch_digest"],
                "stack_arn": dispatch["stack_arn"],
                "change_set_arn": dispatch["change_set_arn"],
                "create_request_id": dispatch["create_request_id"],
                "cloudtrail_event_digest": cloudtrail_digest,
                "describe_change_set_digest": readback[
                    "describe_change_set_digest"
                ],
                "template_digest": readback["template_digest"],
                "changes_digest": readback["changes_digest"],
                "status": readback["status"],
                "execution_status": readback["execution_status"],
                "attested_at": _stamp(now),
                "attempt": 1,
                "aws_calls": 3 + pages,
                "aws_mutations": 0,
                "retry_permitted": False,
                "production_authorized": False,
                "production_status": route.PRODUCTION_STATUS,
            },
            "attestation_digest",
        )

    def execute_reentry_change_set(
        self,
        *,
        seed_input: Mapping[str, Any],
        seed_intent: Mapping[str, Any],
        git: route.GitPort,
        failure_attestation: Mapping[str, Any],
        reentry_creation_authorization: Mapping[str, Any],
        reentry_intent: Mapping[str, Any],
        reentry_dispatch: Mapping[str, Any],
        reentry_attestation: Mapping[str, Any],
        execution_authorization: Mapping[str, Any],
        execution_intent: Mapping[str, Any],
    ) -> dict[str, Any]:
        try:
            seed = route.validate_seed_intent_against_input(
                seed_intent,
                seed_input=seed_input,
                git=git,
                now=self._clock(),
            )
        except route.RouteSeedError as exc:
            raise DeploymentRecoveryError(exc.code) from exc
        intent = validate_reentry_execution_intent(
            execution_intent,
            seed_intent=seed,
            failure_attestation=failure_attestation,
            reentry_creation_authorization=reentry_creation_authorization,
            reentry_intent=reentry_intent,
            reentry_dispatch=reentry_dispatch,
            reentry_attestation=reentry_attestation,
            execution_authorization=execution_authorization,
        )
        target = intent["target"]
        failure_record_type = str(failure_attestation.get("record_type", ""))
        create_claim_key = (
            f"reentry-create:{target}:{intent['parent_intent_digest']}"
        )
        try:
            persisted_dispatch_value = self._claims.read_result(
                create_claim_key
            )
        except connected.ConnectedRouteError as exc:
            raise DeploymentRecoveryError(exc.code) from exc
        provided_dispatch = _validate_reentry_dispatch(
            reentry_dispatch,
            reentry_intent=reentry_intent,
            failure_record_type=failure_record_type,
        )
        persisted_dispatch = _validate_reentry_dispatch(
            persisted_dispatch_value,
            reentry_intent=reentry_intent,
            failure_record_type=failure_record_type,
        )
        if (
            persisted_dispatch != provided_dispatch
            or persisted_dispatch["stack_arn"]
            != reentry_attestation["stack_arn"]
            or persisted_dispatch["change_set_arn"]
            != reentry_attestation["change_set_arn"]
            or persisted_dispatch["create_request_id"]
            != reentry_attestation["create_request_id"]
        ):
            raise DeploymentRecoveryError(
                "REENTRY_ATTESTATION_DISPATCH_BINDING_INVALID"
            )
        try:
            create_claim = self._claims.read_claim(create_claim_key)
        except connected.ConnectedRouteError as exc:
            raise DeploymentRecoveryError(exc.code) from exc
        create_claim = _validate_reentry_create_claim(
            create_claim,
            intent=reentry_intent,
            dispatch=persisted_dispatch,
            failure_record_type=failure_record_type,
        )
        now = _mutation_window(intent, self._clock)
        _require_active_authorization(
            intent,
            now,
            invalid_code="REENTRY_EXECUTION_AUTHORIZATION_INVALID",
            inactive_code="REENTRY_EXECUTION_AUTHORIZATION_NOT_ACTIVE",
        )
        if _time(
            reentry_attestation["attested_at"],
            "REENTRY_ATTESTATION_INVALID",
        ) > now:
            raise DeploymentRecoveryError("REENTRY_ATTESTATION_INVALID")
        account, caller = self._normal_identity(
            self._sts, target=target, phase="executor"
        )
        after_sts = _mutation_window(intent, self._clock)
        if after_sts < now:
            raise DeploymentRecoveryError("CLOCK_REGRESSED")
        _require_active_authorization(
            intent,
            after_sts,
            invalid_code="REENTRY_EXECUTION_AUTHORIZATION_INVALID",
            inactive_code="REENTRY_EXECUTION_AUTHORIZATION_NOT_ACTIVE",
        )
        if account != intent["account_id"]:
            raise DeploymentRecoveryError("TARGET_ACCOUNT_INVALID")
        authoritative = _authoritative_reentry_change_set_readback(
            self._cfn,
            seed_intent=seed,
            reentry_intent=reentry_intent,
            dispatch=persisted_dispatch,
            observed_at=after_sts,
        )
        cloudtrail_digest, _pages = _reentry_create_event_digest(
            self._trail,
            account=account,
            claim=create_claim,
            dispatch=persisted_dispatch,
            request=reentry_intent["create_request"],
            now=after_sts,
        )
        if (
            authoritative["describe_change_set_digest"]
            != reentry_attestation["describe_change_set_digest"]
            or authoritative["template_digest"]
            != reentry_attestation["template_digest"]
            or authoritative["changes_digest"]
            != reentry_attestation["changes_digest"]
            or authoritative["status"] != reentry_attestation["status"]
            or authoritative["execution_status"]
            != reentry_attestation["execution_status"]
            or cloudtrail_digest
            != reentry_attestation["cloudtrail_event_digest"]
        ):
            raise DeploymentRecoveryError(
                "REENTRY_ATTESTATION_LIVE_BINDING_INVALID"
            )
        request = intent["execute_request"]
        admission_operation = _reentry_collision_operation(
            target=target,
            failure_record_type=failure_record_type,
            effect="execute",
        )
        key = (
            f"reentry-execute:{target}:{intent['parent_intent_digest']}"
        )
        claim = {
            "schema_version": 1,
            "record_type": CLAIM_RECORD_TYPE,
            "operation": "ExecuteChangeSet",
            "target": target,
            "attempt": 1,
            "execution_intent_digest": intent["execution_intent_digest"],
            "request_digest": intent["execute_request_digest"],
            "collision_admission": None,
            "client_request_token": request["ClientRequestToken"],
            "stack_arn": request["StackName"],
            "change_set_arn": request["ChangeSetName"],
            "caller_arn_digest": route.digest_value(caller),
            "claimed_at": "",
            "retry_permitted": False,
            "production_authorized": False,
        }
        effect_at = _mutation_window(intent, self._clock)
        if effect_at < after_sts:
            raise DeploymentRecoveryError("CLOCK_REGRESSED")
        _require_active_authorization(
            intent,
            effect_at,
            invalid_code="REENTRY_EXECUTION_AUTHORIZATION_INVALID",
            inactive_code="REENTRY_EXECUTION_AUTHORIZATION_NOT_ACTIVE",
        )
        capability = self._load_collision_admission(
            operation=admission_operation,
            effect_request=request,
            bootstrap_intent_digest=intent["parent_intent_digest"],
            now=effect_at,
        )
        admission_at = _resample_authorized_mutation_time(
            intent,
            self._clock,
            previous_at=effect_at,
            invalid_code="REENTRY_EXECUTION_AUTHORIZATION_INVALID",
            inactive_code="REENTRY_EXECUTION_AUTHORIZATION_NOT_ACTIVE",
        )
        collision_admission, admission_grant = (
            self._assert_collision_admission(
                capability,
                operation=admission_operation,
                effect_request=request,
                bootstrap_intent_digest=intent["parent_intent_digest"],
                now=admission_at,
            )
        )
        claim["claimed_at"] = _stamp(admission_at)
        claim["collision_admission"] = collision_admission
        try:
            self._claims.claim(key, claim)
        except connected.ConnectedRouteError as exc:
            raise DeploymentRecoveryError(exc.code) from exc
        effect_at = _resample_authorized_mutation_time(
            intent,
            self._clock,
            previous_at=admission_at,
            invalid_code="REENTRY_EXECUTION_AUTHORIZATION_INVALID",
            inactive_code="REENTRY_EXECUTION_AUTHORIZATION_NOT_ACTIVE",
        )
        self._require_collision_admission_active(
            admission_grant,
            observed_at=effect_at,
            expected_admission_digest=collision_admission[
                "admission_digest"
            ],
        )
        try:
            response = self._cfn.execute_change_set(**dict(request))
        except Exception as exc:
            raise DeploymentRecoveryError(
                "REENTRY_EXECUTE_CHANGE_SET_UNCERTAIN", uncertain=True
            ) from exc
        request_id = (response.get("ResponseMetadata") or {}).get("RequestId")
        if _UUID_RE.fullmatch(str(request_id)) is None:
            raise DeploymentRecoveryError("REENTRY_EXECUTE_RESPONSE_UNCERTAIN", uncertain=True)
        receipt = route.seal(
            {
                "schema_version": 1,
                "record_type": REENTRY_EXECUTION_RECEIPT_RECORD_TYPE,
                "source_commit": intent["source_commit"],
                "target": target,
                "account_id": account,
                "execution_intent_digest": intent["execution_intent_digest"],
                "collision_admission": collision_admission,
                "stack_arn": request["StackName"],
                "change_set_arn": request["ChangeSetName"],
                "execute_request_id": request_id,
                "dispatched_at": _stamp(effect_at),
                "attempt": 1,
                "aws_mutations": 1,
                "retry_permitted": False,
                "production_authorized": False,
                "production_status": route.PRODUCTION_STATUS,
            },
            "receipt_digest",
        )
        try:
            self._claims.complete(key, receipt)
        except connected.ConnectedRouteError as exc:
            raise DeploymentRecoveryError(
                "REENTRY_EXECUTE_RESULT_DURABILITY_UNCERTAIN", uncertain=True
            ) from exc
        return receipt

    def attest_protection_rollback(
        self,
        *,
        seed_intent: Mapping[str, Any],
        execution_intent: Mapping[str, Any],
        execution_receipt: Mapping[str, Any],
    ) -> dict[str, Any]:
        try:
            seed = route.validate_seed_intent(seed_intent)
        except route.RouteSeedError as exc:
            raise DeploymentRecoveryError(exc.code) from exc
        execution, receipt = _validate_create_execution_binding(
            execution_intent,
            execution_receipt,
            seed_intent=seed,
            allowed_targets=frozenset({route.BROKER_PROTECTION_TARGET}),
        )
        claim = _validate_durable_execution_result(
            self._claims, execution=execution, receipt=receipt
        )
        before_sts = _recovery_window(seed, self._clock)
        account, _caller = self._normal_identity(
            self._sts, target=route.BROKER_PROTECTION_TARGET, phase="executor"
        )
        now = _recovery_window(seed, self._clock)
        if now < before_sts:
            raise DeploymentRecoveryError("CLOCK_REGRESSED")
        if receipt["account_id"] != account:
            raise DeploymentRecoveryError("TARGET_ACCOUNT_INVALID")
        execute_digest, pages = _execute_event_digest(
            self._trail,
            account=account,
            claim=claim,
            execution=execution,
            receipt=receipt,
            now=now,
        )
        stack, stack_calls = _read_stack(
            self._cfn,
            stack_arn=receipt["stack_arn"],
            code="PROTECTION_ROLLBACK_STACK_INVALID",
        )
        if (
            stack.get("StackId") != receipt["stack_arn"]
            or stack.get("StackName") != route.BROKER_STACK_NAME
            or stack.get("StackStatus") != "UPDATE_ROLLBACK_COMPLETE"
        ):
            raise DeploymentRecoveryError("PROTECTION_ROLLBACK_STACK_INVALID")
        resources_response = self._cfn.list_stack_resources(
            StackName=receipt["stack_arn"]
        )
        resources = _resource_projection(
            resources_response, "PROTECTION_ROLLBACK_RESOURCES_INVALID"
        )
        expected_resources = seed["targets"]["broker"]["expected_resources"]
        if [
            {
                "logical_resource_id": item["logical_resource_id"],
                "resource_type": item["resource_type"],
            }
            for item in resources
        ] != expected_resources:
            raise DeploymentRecoveryError("PROTECTION_ROLLBACK_RESOURCES_INVALID")
        table_item = next(
            (item for item in resources_response["StackResourceSummaries"] if item.get("LogicalResourceId") == "BrokerLedger"),
            None,
        )
        key_item = next(
            (item for item in resources_response["StackResourceSummaries"] if item.get("LogicalResourceId") == "BrokerLedgerKey"),
            None,
        )
        if not isinstance(table_item, Mapping) or not isinstance(key_item, Mapping):
            raise DeploymentRecoveryError("PROTECTION_ROLLBACK_LEDGER_INVALID")
        key_id = key_item.get("PhysicalResourceId")
        expected_kms_arn = f"arn:aws:kms:{route.REGION}:{route.AUTHORITY_ACCOUNT_ID}:key/{key_id}"
        if _KMS_KEY_ID_RE.fullmatch(str(key_id)) is None:
            raise DeploymentRecoveryError("PROTECTION_ROLLBACK_LEDGER_INVALID")
        table_response = self._dynamodb.describe_table(
            TableName="scanalyze-platform-authority-gug376-route-broker-ledger"
        )
        table = table_response.get("Table")
        sse = table.get("SSEDescription") if isinstance(table, Mapping) else None
        if (
            not isinstance(table, Mapping)
            or table.get("TableName")
            != "scanalyze-platform-authority-gug376-route-broker-ledger"
            or table.get("TableArn")
            != "arn:aws:dynamodb:us-east-1:042360977644:table/scanalyze-platform-authority-gug376-route-broker-ledger"
            or table.get("TableStatus") != "ACTIVE"
            or table.get("DeletionProtectionEnabled", False) is not False
            or not isinstance(sse, Mapping)
            or sse.get("Status") != "ENABLED"
            or sse.get("SSEType") != "KMS"
            or sse.get("KMSMasterKeyArn") != expected_kms_arn
        ):
            raise DeploymentRecoveryError("PROTECTION_ROLLBACK_LEDGER_INVALID")
        projection = {
            "table_name": table["TableName"],
            "table_arn": table["TableArn"],
            "table_status": table["TableStatus"],
            "deletion_protection_enabled": False,
            "sse_status": sse["Status"],
            "sse_type": sse["SSEType"],
            "kms_key_arn": expected_kms_arn,
        }
        return route.seal(
            {
                "schema_version": 1,
                "record_type": PROTECTION_ROLLBACK_RECORD_TYPE,
                "source_commit": seed["source_commit"],
                "target": route.BROKER_PROTECTION_TARGET,
                "intent_digest": seed["intent_digest"],
                "execution_intent_digest": execution["execution_intent_digest"],
                "execution_receipt_digest": receipt["receipt_digest"],
                "execution_claim_digest": route.digest_value(claim),
                "execute_cloudtrail_event_digest": execute_digest,
                "account_id": account,
                "stack_arn": receipt["stack_arn"],
                "change_set_arn": receipt["change_set_arn"],
                "execute_request_id": receipt["execute_request_id"],
                "stack_status": "UPDATE_ROLLBACK_COMPLETE",
                "resource_count": len(resources),
                "resources_digest": route.digest_value(resources),
                "ledger_live_properties_digest": route.digest_value(projection),
                "ledger_deletion_protection_enabled": False,
                "attested_at": _stamp(now),
                "aws_calls": 3 + pages + stack_calls,
                "aws_mutations": 0,
                "retry_permitted": False,
                "production_authorized": False,
                "production_status": route.PRODUCTION_STATUS,
            },
            "attestation_digest",
        )

    def attest_failed_create_stack(
        self,
        *,
        seed_intent: Mapping[str, Any],
        execution_intent: Mapping[str, Any],
        execution_receipt: Mapping[str, Any],
    ) -> dict[str, Any]:
        try:
            seed = route.validate_seed_intent(seed_intent)
        except route.RouteSeedError as exc:
            raise DeploymentRecoveryError(exc.code) from exc
        execution, receipt = _validate_create_execution_binding(
            execution_intent,
            execution_receipt,
            seed_intent=seed,
            allowed_targets=frozenset({"route", "broker"}),
        )
        target = execution["target"]
        claim = _validate_durable_execution_result(
            self._claims, execution=execution, receipt=receipt
        )
        before_sts = _recovery_window(seed, self._clock)
        account, _caller = self._normal_identity(
            self._sts, target=target, phase="executor"
        )
        now = _recovery_window(seed, self._clock)
        if now < before_sts:
            raise DeploymentRecoveryError("CLOCK_REGRESSED")
        if receipt["account_id"] != account:
            raise DeploymentRecoveryError("TARGET_ACCOUNT_INVALID")
        execute_digest, pages = _execute_event_digest(
            self._trail,
            account=account,
            claim=claim,
            execution=execution,
            receipt=receipt,
            now=now,
        )
        stack, stack_calls = _read_stack(
            self._cfn,
            stack_arn=receipt["stack_arn"],
            code="FAILED_CREATE_STACK_INVALID",
        )
        status = stack.get("StackStatus")
        if (
            stack.get("StackId") != receipt["stack_arn"]
            or stack.get("StackName") != _stack_name(target)
            or status not in {"ROLLBACK_COMPLETE", "DELETE_FAILED"}
        ):
            raise DeploymentRecoveryError("FAILED_CREATE_STACK_INVALID")
        resources_response = self._cfn.list_stack_resources(
            StackName=receipt["stack_arn"]
        )
        resources = _cleanup_resource_projection(
            resources_response, "FAILED_CREATE_RESOURCES_INVALID"
        )
        return route.seal(
            {
                "schema_version": 1,
                "record_type": FAILED_CREATE_STACK_RECORD_TYPE,
                "source_commit": seed["source_commit"],
                "target": target,
                "intent_digest": seed["intent_digest"],
                "execution_intent_digest": execution["execution_intent_digest"],
                "reentry_source_failure_record_type": (
                    execution["failure_record_type"]
                    if execution["record_type"]
                    == REENTRY_EXECUTION_INTENT_RECORD_TYPE
                    else None
                ),
                "execution_receipt_digest": receipt["receipt_digest"],
                "execution_claim_digest": route.digest_value(claim),
                "execute_cloudtrail_event_digest": execute_digest,
                "account_id": account,
                "stack_arn": receipt["stack_arn"],
                "change_set_arn": receipt["change_set_arn"],
                "execute_request_id": receipt["execute_request_id"],
                "stack_status": status,
                "resource_count": len(resources),
                "resources": resources,
                "resources_digest": route.digest_value(resources),
                "attested_at": _stamp(now),
                "aws_calls": 2 + pages + stack_calls,
                "aws_mutations": 0,
                "retry_permitted": False,
                "production_authorized": False,
                "production_status": route.PRODUCTION_STATUS,
            },
            "attestation_digest",
        )

    def delete_failed_stack(
        self,
        *,
        seed_input: Mapping[str, Any],
        seed_intent: Mapping[str, Any],
        git: route.GitPort,
        failed_stack_attestation: Mapping[str, Any],
        authorization: Mapping[str, Any],
        cleanup_intent: Mapping[str, Any],
    ) -> dict[str, Any]:
        try:
            seed = route.validate_seed_intent_against_input(
                seed_intent,
                seed_input=seed_input,
                git=git,
                now=self._clock(),
            )
        except route.RouteSeedError as exc:
            raise DeploymentRecoveryError(exc.code) from exc
        failed = _validate_failed_stack_attestation(
            failed_stack_attestation
        )
        intent = validate_cleanup_intent(
            cleanup_intent,
            seed_intent=seed,
            failed_stack_attestation=failed,
            authorization=authorization,
        )
        target = intent["target"]
        (
            execution_claim,
            execution_receipt,
            execution_request,
        ) = _validate_failed_execution_journal(
            self._claims,
            seed_intent=seed,
            failed_stack_attestation=failed,
        )
        now = _cleanup_window(intent, self._clock)
        _require_active_authorization(
            intent,
            now,
            invalid_code="CLEANUP_AUTHORIZATION_INVALID",
            inactive_code="CLEANUP_AUTHORIZATION_NOT_ACTIVE",
        )
        account, caller = self._cleanup_identity(target=target)
        after_sts = _cleanup_window(intent, self._clock)
        if after_sts < now:
            raise DeploymentRecoveryError("CLOCK_REGRESSED")
        _require_active_authorization(
            intent,
            after_sts,
            invalid_code="CLEANUP_AUTHORIZATION_INVALID",
            inactive_code="CLEANUP_AUTHORIZATION_NOT_ACTIVE",
        )
        if account != intent["account_id"]:
            raise DeploymentRecoveryError("TARGET_ACCOUNT_INVALID")
        request = intent["delete_request"]
        execute_event_digest, _execute_pages = _execute_event_digest(
            self._trail,
            account=account,
            claim=execution_claim,
            execution={"execute_request": execution_request},
            receipt=execution_receipt,
            now=after_sts,
        )
        if (
            execute_event_digest
            != failed["execute_cloudtrail_event_digest"]
        ):
            raise DeploymentRecoveryError(
                "FAILED_EXECUTION_CLOUDTRAIL_BINDING_INVALID"
            )
        stack, _stack_calls = _read_stack(
            self._cfn,
            stack_arn=failed["stack_arn"],
            code="CLEANUP_STACK_PREDELETE_INVALID",
        )
        resources_response = self._cfn.list_stack_resources(
            StackName=failed["stack_arn"]
        )
        resources = _cleanup_resource_projection(
            resources_response,
            "CLEANUP_RESOURCES_PREDELETE_INVALID",
        )
        if (
            stack.get("StackId") != failed["stack_arn"]
            or stack.get("StackName") != _stack_name(target)
            or stack.get("StackStatus") != failed["stack_status"]
            or resources != failed["resources"]
            or route.digest_value(resources) != failed["resources_digest"]
        ):
            raise DeploymentRecoveryError("FAILED_STACK_STATE_CHANGED")
        key = (
            f"cleanup:{target}:{intent['parent_intent_digest']}:"
            f"{intent['execution_lane']}"
        )
        claim = {
            "schema_version": 1,
            "record_type": CLAIM_RECORD_TYPE,
            "operation": "DeleteStack",
            "target": target,
            "execution_lane": intent["execution_lane"],
            "attempt": 1,
            "cleanup_intent_digest": intent["cleanup_intent_digest"],
            "failed_stack_attestation_digest": intent[
                "failed_stack_attestation_digest"
            ],
            "failed_resources_digest": intent["failed_resources_digest"],
            "request_digest": intent["delete_request_digest"],
            "client_request_token": request["ClientRequestToken"],
            "stack_arn": request["StackName"],
            "caller_arn_digest": route.digest_value(caller),
            "claimed_at": "",
            "retry_permitted": False,
            "production_authorized": False,
        }
        effect_at = _cleanup_window(intent, self._clock)
        if effect_at < after_sts:
            raise DeploymentRecoveryError("CLOCK_REGRESSED")
        _require_active_authorization(
            intent,
            effect_at,
            invalid_code="CLEANUP_AUTHORIZATION_INVALID",
            inactive_code="CLEANUP_AUTHORIZATION_NOT_ACTIVE",
        )
        claim["claimed_at"] = _stamp(effect_at)
        try:
            self._claims.claim(key, claim)
        except connected.ConnectedRouteError as exc:
            raise DeploymentRecoveryError(exc.code) from exc
        try:
            response = self._cfn.delete_stack(**dict(request))
        except Exception as exc:
            raise DeploymentRecoveryError("CLEANUP_DELETE_STACK_UNCERTAIN", uncertain=True) from exc
        request_id = (response.get("ResponseMetadata") or {}).get("RequestId")
        if _UUID_RE.fullmatch(str(request_id)) is None:
            raise DeploymentRecoveryError("CLEANUP_DELETE_RESPONSE_UNCERTAIN", uncertain=True)
        receipt = route.seal(
            {
                "schema_version": 1,
                "record_type": CLEANUP_DISPATCH_RECORD_TYPE,
                "source_commit": intent["source_commit"],
                "target": target,
                "account_id": account,
                "execution_lane": intent["execution_lane"],
                "cleanup_intent_digest": intent["cleanup_intent_digest"],
                "failed_stack_attestation_digest": intent[
                    "failed_stack_attestation_digest"
                ],
                "failed_resources_digest": intent[
                    "failed_resources_digest"
                ],
                "stack_arn": request["StackName"],
                "delete_request_id": request_id,
                "dispatched_at": _stamp(effect_at),
                "attempt": 1,
                "aws_mutations": 1,
                "retry_permitted": False,
                "production_authorized": False,
                "production_status": route.PRODUCTION_STATUS,
            },
            "dispatch_digest",
        )
        try:
            self._claims.complete(key, receipt)
        except connected.ConnectedRouteError as exc:
            raise DeploymentRecoveryError("CLEANUP_RESULT_DURABILITY_UNCERTAIN", uncertain=True) from exc
        return receipt

    def attest_cleanup_complete(
        self,
        *,
        seed_intent: Mapping[str, Any],
        failed_stack_attestation: Mapping[str, Any],
        authorization: Mapping[str, Any],
        cleanup_intent: Mapping[str, Any],
        cleanup_dispatch: Mapping[str, Any],
    ) -> dict[str, Any]:
        intent = validate_cleanup_intent(
            cleanup_intent,
            seed_intent=seed_intent,
            failed_stack_attestation=failed_stack_attestation,
            authorization=authorization,
        )
        target = intent["target"]
        now = _recovery_window(intent, self._clock)
        expected_account = _account_id(target)
        _verify_seal(cleanup_dispatch, "dispatch_digest", "CLEANUP_DISPATCH_DIGEST_INVALID")
        if (
            set(cleanup_dispatch) != _CLEANUP_DISPATCH_FIELDS
            or cleanup_dispatch.get("schema_version") != 1
            or cleanup_dispatch.get("record_type") != CLEANUP_DISPATCH_RECORD_TYPE
            or cleanup_dispatch.get("source_commit") != intent["source_commit"]
            or cleanup_dispatch.get("cleanup_intent_digest") != intent["cleanup_intent_digest"]
            or cleanup_dispatch.get("failed_stack_attestation_digest")
            != intent["failed_stack_attestation_digest"]
            or cleanup_dispatch.get("failed_resources_digest")
            != intent["failed_resources_digest"]
            or cleanup_dispatch.get("target") != target
            or cleanup_dispatch.get("account_id") != expected_account
            or cleanup_dispatch.get("execution_lane")
            != intent["execution_lane"]
            or cleanup_dispatch.get("stack_arn") != intent["delete_request"]["StackName"]
            or _UUID_RE.fullmatch(str(cleanup_dispatch.get("delete_request_id", ""))) is None
            or cleanup_dispatch.get("attempt") != 1
            or cleanup_dispatch.get("aws_mutations") != 1
            or cleanup_dispatch.get("retry_permitted") is not False
            or cleanup_dispatch.get("production_authorized") is not False
            or cleanup_dispatch.get("production_status")
            != route.PRODUCTION_STATUS
        ):
            raise DeploymentRecoveryError("CLEANUP_DISPATCH_INVALID")
        dispatched_at = _time(
            cleanup_dispatch.get("dispatched_at"), "CLEANUP_DISPATCH_INVALID"
        )
        if not _time(
            intent["authorization_not_before"], "CLEANUP_DISPATCH_INVALID"
        ) <= dispatched_at < _time(
            intent["authorization_expires_at"], "CLEANUP_DISPATCH_INVALID"
        ) or dispatched_at > now:
            raise DeploymentRecoveryError("CLEANUP_DISPATCH_INVALID")
        key = (
            f"cleanup:{target}:{intent['parent_intent_digest']}:"
            f"{intent['execution_lane']}"
        )
        try:
            claim = self._claims.read_claim(key)
        except connected.ConnectedRouteError as exc:
            raise DeploymentRecoveryError(exc.code) from exc
        claim = _validate_cleanup_claim(
            claim, intent=intent, dispatch=cleanup_dispatch
        )
        account, _caller = self._cleanup_identity(target=target)
        after_sts = _recovery_window(intent, self._clock)
        if after_sts < now:
            raise DeploymentRecoveryError("CLOCK_REGRESSED")
        if account != expected_account:
            raise DeploymentRecoveryError("TARGET_ACCOUNT_INVALID")
        cloudtrail_digest, pages = _delete_event_digest(
            self._trail,
            account=account,
            claim=claim,
            dispatch=cleanup_dispatch,
            request=intent["delete_request"],
            now=after_sts,
        )
        terminal = "NOT_FOUND"
        try:
            response = self._cfn.describe_stacks(StackName=cleanup_dispatch["stack_arn"])
        except Exception as exc:
            if not _is_stack_not_found(exc):
                raise DeploymentRecoveryError("CLEANUP_TERMINAL_READBACK_INVALID") from exc
        else:
            stacks = response.get("Stacks") if isinstance(response, Mapping) else None
            if (
                response.get("NextToken") is not None
                or not isinstance(stacks, list)
                or len(stacks) != 1
                or stacks[0].get("StackId") != cleanup_dispatch["stack_arn"]
                or stacks[0].get("StackStatus") != "DELETE_COMPLETE"
            ):
                raise DeploymentRecoveryError("CLEANUP_NOT_TERMINAL")
            terminal = "DELETE_COMPLETE"
        try:
            self._cfn.describe_stacks(StackName=_stack_name(target))
        except Exception as exc:
            if not _is_stack_not_found(exc):
                raise DeploymentRecoveryError("CLEANUP_FIXED_NAME_READBACK_INVALID") from exc
        else:
            raise DeploymentRecoveryError("CLEANUP_FIXED_NAME_STILL_PRESENT")
        (
            survivor_evidence_digest,
            survivor_calls,
            scheduled_inert_survivors,
        ) = self._prove_no_active_survivors(intent=intent)
        attested_at = _recovery_window(intent, self._clock)
        if attested_at < after_sts:
            raise DeploymentRecoveryError("CLOCK_REGRESSED")
        return route.seal(
            {
                "schema_version": 1,
                "record_type": CLEANUP_TERMINAL_RECORD_TYPE,
                "source_commit": intent["source_commit"],
                "target": target,
                "account_id": account,
                "execution_lane": intent["execution_lane"],
                "cleanup_intent_digest": intent["cleanup_intent_digest"],
                "cleanup_dispatch_digest": cleanup_dispatch["dispatch_digest"],
                "parent_intent_digest": intent["parent_intent_digest"],
                "failed_stack_attestation_digest": intent[
                    "failed_stack_attestation_digest"
                ],
                "failed_resources": intent["failed_resources"],
                "failed_resources_digest": intent[
                    "failed_resources_digest"
                ],
                "delete_cloudtrail_event_digest": cloudtrail_digest,
                "stack_arn": cleanup_dispatch["stack_arn"],
                "stack_terminal_observation": terminal,
                "fixed_stack_name": _stack_name(target),
                "fixed_stack_name_absent": True,
                "survivor_check_count": survivor_calls,
                "survivor_evidence_digest": survivor_evidence_digest,
                "no_active_survivors": True,
                "scheduled_inert_survivor_count": len(
                    scheduled_inert_survivors
                ),
                "scheduled_inert_survivors": scheduled_inert_survivors,
                "scheduled_inert_survivors_digest": route.digest_value(
                    scheduled_inert_survivors
                ),
                "attested_at": _stamp(attested_at),
                "aws_calls": 3 + pages + survivor_calls,
                "aws_mutations": 0,
                "retry_permitted": False,
                "production_authorized": False,
                "production_status": route.PRODUCTION_STATUS,
            },
            "attestation_digest",
        )


def _reentry_create_event_digest(
    trail: Any,
    *,
    account: str,
    claim: Mapping[str, Any],
    dispatch: Mapping[str, Any],
    request: Mapping[str, Any],
    now: datetime,
) -> tuple[str, int]:
    events, pages = _lookup(
        trail,
        event_name="CreateChangeSet",
        start=_time(claim.get("claimed_at"), "REENTRY_CLAIM_INVALID"),
        end=now,
        code="REENTRY_CREATE_CLOUDTRAIL_AMBIGUOUS",
    )
    expected = _cloudtrail_request(request)
    matches: list[dict[str, Any]] = []
    for envelope in events:
        event = _strict_json(envelope.get("CloudTrailEvent"), "REENTRY_CREATE_CLOUDTRAIL_INVALID")
        if event.get("requestID") != dispatch["create_request_id"]:
            continue
        params = event.get("requestParameters") or {}
        result = event.get("responseElements") or {}
        identity = event.get("userIdentity") or {}
        event_time = _time(event.get("eventTime"), "REENTRY_CREATE_CLOUDTRAIL_INVALID")
        if (
            event.get("eventSource") != "cloudformation.amazonaws.com"
            or event.get("eventName") != "CreateChangeSet"
            or event.get("awsRegion") != route.REGION
            or event.get("recipientAccountId") != account
            or event.get("readOnly") is not False
            or event.get("errorCode") is not None
            or event.get("errorMessage") is not None
            or not isinstance(identity.get("arn"), str)
            or not _caller_arn_matches_phase(
                identity["arn"],
                target=str(claim.get("target")),
                phase="creator",
            )
            or route.digest_value(identity["arn"])
            != claim.get("caller_arn_digest")
            or params != expected
            or "roleARN" in params
            or result.get("id") != dispatch["change_set_arn"]
            or result.get("stackId") != dispatch["stack_arn"]
            or not _time(dispatch["dispatched_at"], "REENTRY_DISPATCH_INVALID") <= event_time <= now
            or _UUID_RE.fullmatch(str(event.get("eventID", ""))) is None
        ):
            raise DeploymentRecoveryError("REENTRY_CREATE_CLOUDTRAIL_INVALID")
        matches.append(
            {
                "event_id": event["eventID"],
                "event_time": _stamp(event_time),
                "request_id": event["requestID"],
                "request_digest": route.digest_value(expected),
            }
        )
    if len(matches) != 1:
        raise DeploymentRecoveryError("REENTRY_CREATE_CLOUDTRAIL_MISSING")
    return route.digest_value(matches[0]), pages


def _primary_execute_claim(
    claims: connected.OExclClaimStore,
    *,
    execution: Mapping[str, Any],
    receipt: Mapping[str, Any],
) -> dict[str, Any]:
    key = f"execute:{execution['target']}:{execution['execute_operation_digest']}"
    try:
        claim = claims.read_claim(key)
    except connected.ConnectedRouteError as exc:
        raise DeploymentRecoveryError(exc.code) from exc
    claim_collision_binding = _validate_primary_collision_binding(
        claim,
        action="execute",
        target=str(execution["target"]),
        effect_request_digest=str(execution["execute_request_digest"]),
    )
    receipt_collision_binding = _validate_primary_collision_binding(
        receipt,
        action="execute",
        target=str(execution["target"]),
        effect_request_digest=str(execution["execute_request_digest"]),
    )
    if (
        claim.get("record_type") != connected.CLAIM_RECORD_TYPE
        or claim.get("operation") != "ExecuteChangeSet"
        or claim.get("target") != execution["target"]
        or claim.get("execution_intent_digest") != execution["execution_intent_digest"]
        or claim.get("request_digest") != execution["execute_request_digest"]
        or claim.get("client_request_token") != execution["execute_request"]["ClientRequestToken"]
        or claim.get("stack_arn") != receipt["stack_arn"]
        or claim.get("change_set_arn") != receipt["change_set_arn"]
        or claim_collision_binding != receipt_collision_binding
        or _DIGEST_RE.fullmatch(str(claim.get("caller_arn_digest", ""))) is None
        or claim.get("retry_permitted") is not False
        or claim.get("production_authorized") is not False
    ):
        raise DeploymentRecoveryError("EXECUTION_CLAIM_INVALID")
    return claim


def _execution_claim(
    claims: connected.OExclClaimStore,
    *,
    execution: Mapping[str, Any],
    receipt: Mapping[str, Any],
) -> dict[str, Any]:
    if execution["record_type"] == route.RECORD_TYPE_EXECUTION_INTENT:
        return _primary_execute_claim(claims, execution=execution, receipt=receipt)
    key = (
        f"reentry-execute:{execution['target']}:"
        f"{execution['parent_intent_digest']}"
    )
    try:
        claim = claims.read_claim(key)
    except connected.ConnectedRouteError as exc:
        raise DeploymentRecoveryError(exc.code) from exc
    fields = {
        "schema_version",
        "record_type",
        "operation",
        "target",
        "attempt",
        "execution_intent_digest",
        "request_digest",
        "collision_admission",
        "client_request_token",
        "stack_arn",
        "change_set_arn",
        "caller_arn_digest",
        "claimed_at",
        "retry_permitted",
        "production_authorized",
    }
    collision_admission = _validate_reentry_collision_binding(
        claim.get("collision_admission"),
        target=str(execution["target"]),
        effect="execute",
        effect_request=execution["execute_request"],
        bootstrap_intent_digest=str(execution["parent_intent_digest"]),
        failure_record_type=str(execution["failure_record_type"]),
    )
    if (
        set(claim) != fields
        or claim.get("schema_version") != 1
        or claim.get("record_type") != CLAIM_RECORD_TYPE
        or claim.get("operation") != "ExecuteChangeSet"
        or claim.get("target") != execution["target"]
        or claim.get("attempt") != 1
        or claim.get("execution_intent_digest") != execution["execution_intent_digest"]
        or claim.get("request_digest") != execution["execute_request_digest"]
        or collision_admission != receipt.get("collision_admission")
        or claim.get("client_request_token")
        != execution["execute_request"]["ClientRequestToken"]
        or claim.get("stack_arn") != receipt["stack_arn"]
        or claim.get("change_set_arn") != receipt["change_set_arn"]
        or _DIGEST_RE.fullmatch(str(claim.get("caller_arn_digest", ""))) is None
        or claim.get("retry_permitted") is not False
        or claim.get("production_authorized") is not False
    ):
        raise DeploymentRecoveryError("EXECUTION_CLAIM_INVALID")
    _time(claim.get("claimed_at"), "EXECUTION_CLAIM_INVALID")
    return claim


def _validate_failed_execution_journal(
    claims: connected.OExclClaimStore,
    *,
    seed_intent: Mapping[str, Any],
    failed_stack_attestation: Mapping[str, Any],
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    """Bind cleanup to the durable execution claim/result that caused it."""

    failed = _validate_failed_stack_attestation(failed_stack_attestation)
    target = failed["target"]
    account = failed["account_id"]
    change_prefix = (
        f"arn:aws:cloudformation:{route.REGION}:{account}:changeSet/"
    )
    change_suffix = str(failed["change_set_arn"])[len(change_prefix) :]
    change_name = change_suffix.split("/", 1)[0]
    primary_change_name = (
        route.ROUTE_CHANGE_SET_NAME
        if target == "route"
        else route.BROKER_CHANGE_SET_NAME
    )
    reentry = change_name == REENTRY_CHANGE_SET_NAMES[target]
    if (
        failed.get("source_commit") != seed_intent["source_commit"]
        or failed.get("intent_digest") != seed_intent["intent_digest"]
        or _execution_lane(
            target=target, change_set_arn=failed["change_set_arn"]
        )
        != ("reentry" if reentry else "primary")
    ):
        raise DeploymentRecoveryError("FAILED_EXECUTION_JOURNAL_INVALID")
    if reentry:
        key = f"reentry-execute:{target}:{seed_intent['intent_digest']}"
        receipt_record_type = REENTRY_EXECUTION_RECEIPT_RECORD_TYPE
        claim_record_type = CLAIM_RECORD_TYPE
        receipt_fields = _REENTRY_EXECUTION_RECEIPT_FIELDS
        claim_fields = {
            "schema_version",
            "record_type",
            "operation",
            "target",
            "attempt",
            "execution_intent_digest",
            "request_digest",
            "collision_admission",
            "client_request_token",
            "stack_arn",
            "change_set_arn",
            "caller_arn_digest",
            "claimed_at",
            "retry_permitted",
            "production_authorized",
        }
    elif change_name == primary_change_name:
        operation_digest = route.digest_value(
            {
                "record_type": (
                    "scanalyze.platform_authority."
                    "plan_permission_repair_execute_operation.v1"
                ),
                "source_commit": failed["source_commit"],
                "target": target,
                "account_id": account,
                "stack_arn": failed["stack_arn"],
                "change_set_arn": failed["change_set_arn"],
            }
        )
        key = f"execute:{target}:{operation_digest}"
        receipt_record_type = connected.EXECUTION_RECEIPT_RECORD_TYPE
        claim_record_type = connected.CLAIM_RECORD_TYPE
        receipt_fields = (
            _REENTRY_EXECUTION_RECEIPT_FIELDS
            - {"attempt", "collision_admission"}
        ) | _PRIMARY_COLLISION_FIELDS
        claim_fields = {
            "schema_version",
            "record_type",
            "operation",
            "target",
            "execution_intent_digest",
            "request_digest",
            "client_request_token",
            "stack_arn",
            "change_set_arn",
            "caller_arn_digest",
            "claimed_at",
            "retry_permitted",
            "production_authorized",
        } | set(_PRIMARY_COLLISION_FIELDS)
    else:
        raise DeploymentRecoveryError("FAILED_EXECUTION_JOURNAL_INVALID")
    try:
        receipt = claims.read_result(key)
        claim = claims.read_claim(key)
    except connected.ConnectedRouteError as exc:
        raise DeploymentRecoveryError(exc.code) from exc
    _verify_seal(
        receipt, "receipt_digest", "FAILED_EXECUTION_JOURNAL_INVALID"
    )
    dispatched_at = _time(
        receipt.get("dispatched_at"), "FAILED_EXECUTION_JOURNAL_INVALID"
    )
    claimed_at = _time(
        claim.get("claimed_at"), "FAILED_EXECUTION_JOURNAL_INVALID"
    )
    route_not_before = _time(
        seed_intent["route_not_before"], "FAILED_EXECUTION_JOURNAL_INVALID"
    )
    mutation_cutoff = _time(
        seed_intent["route_not_after"], "FAILED_EXECUTION_JOURNAL_INVALID"
    ) - timedelta(seconds=route.MUTATION_COMPLETION_RESERVE_SECONDS)
    failed_attested_at = _time(
        failed["attested_at"], "FAILED_EXECUTION_JOURNAL_INVALID"
    )
    execute_request = {
        "StackName": failed["stack_arn"],
        "ChangeSetName": failed["change_set_arn"],
        "ClientRequestToken": claim.get("client_request_token"),
    }
    collision_admission = None
    if reentry:
        collision_admission = _validate_reentry_collision_binding(
            claim.get("collision_admission"),
            target=str(target),
            effect="execute",
            effect_request=execute_request,
            bootstrap_intent_digest=str(seed_intent["intent_digest"]),
            failure_record_type=str(failed["reentry_source_failure_record_type"]),
        )
    else:
        claim_primary_collision = _validate_primary_collision_binding(
            claim,
            action="execute",
            target=str(target),
            effect_request_digest=route.digest_value(execute_request),
        )
        receipt_primary_collision = _validate_primary_collision_binding(
            receipt,
            action="execute",
            target=str(target),
            effect_request_digest=route.digest_value(execute_request),
        )
    if (
        set(receipt) != receipt_fields
        or receipt.get("schema_version") != 1
        or receipt.get("record_type") != receipt_record_type
        or receipt.get("source_commit") != failed["source_commit"]
        or receipt.get("target") != target
        or receipt.get("account_id") != account
        or receipt.get("execution_intent_digest")
        != failed["execution_intent_digest"]
        or receipt.get("stack_arn") != failed["stack_arn"]
        or receipt.get("change_set_arn") != failed["change_set_arn"]
        or receipt.get("execute_request_id")
        != failed["execute_request_id"]
        or receipt.get("receipt_digest")
        != failed["execution_receipt_digest"]
        or (reentry and receipt.get("attempt") != 1)
        or receipt.get("aws_mutations") != 1
        or receipt.get("retry_permitted") is not False
        or receipt.get("production_authorized") is not False
        or receipt.get("production_status") != route.PRODUCTION_STATUS
        or set(claim) != claim_fields
        or claim.get("schema_version") != 1
        or claim.get("record_type") != claim_record_type
        or claim.get("operation") != "ExecuteChangeSet"
        or claim.get("target") != target
        or (reentry and claim.get("attempt") != 1)
        or claim.get("execution_intent_digest")
        != failed["execution_intent_digest"]
        or claim.get("request_digest") != route.digest_value(execute_request)
        or (
            reentry
            and (
                collision_admission != receipt.get("collision_admission")
            )
        )
        or (
            not reentry
            and claim_primary_collision != receipt_primary_collision
        )
        or _TOKEN_RE.fullmatch(str(claim.get("client_request_token", "")))
        is None
        or claim.get("stack_arn") != failed["stack_arn"]
        or claim.get("change_set_arn") != failed["change_set_arn"]
        or _DIGEST_RE.fullmatch(str(claim.get("caller_arn_digest", "")))
        is None
        or route.digest_value(claim) != failed["execution_claim_digest"]
        or claim.get("retry_permitted") is not False
        or claim.get("production_authorized") is not False
        or not route_not_before
        <= claimed_at
        <= dispatched_at
        < mutation_cutoff
        or dispatched_at > failed_attested_at
    ):
        raise DeploymentRecoveryError("FAILED_EXECUTION_JOURNAL_INVALID")
    return dict(claim), dict(receipt), execute_request


def _validate_create_execution_binding(
    execution_intent: Mapping[str, Any],
    execution_receipt: Mapping[str, Any],
    *,
    seed_intent: Mapping[str, Any],
    allowed_targets: frozenset[str],
) -> tuple[dict[str, Any], dict[str, Any]]:
    if execution_intent.get("record_type") != route.RECORD_TYPE_EXECUTION_INTENT:
        execution = validate_reentry_execution_intent_structure(execution_intent)
        receipt = _validate_reentry_execution_receipt(
            execution_receipt, execution=execution
        )
        if execution["target"] not in allowed_targets:
            raise DeploymentRecoveryError("TARGET_INVALID")
    else:
        try:
            execution = route.validate_execution_intent(execution_intent)
        except route.RouteSeedError as exc:
            raise DeploymentRecoveryError(exc.code) from exc
        _verify_seal(
            execution_receipt,
            "receipt_digest",
            "EXECUTION_RECEIPT_DIGEST_INVALID",
        )
        target = execution["target"]
        if (
            target not in allowed_targets
            or execution_receipt.get("record_type")
            != connected.EXECUTION_RECEIPT_RECORD_TYPE
            or execution_receipt.get("execution_intent_digest")
            != execution["execution_intent_digest"]
            or execution_receipt.get("target") != target
            or execution_receipt.get("account_id") != _account_id(target)
            or execution_receipt.get("stack_arn")
            != execution["execute_request"]["StackName"]
            or execution_receipt.get("change_set_arn")
            != execution["execute_request"]["ChangeSetName"]
            or _UUID_RE.fullmatch(
                str(execution_receipt.get("execute_request_id", ""))
            )
            is None
            or execution_receipt.get("aws_mutations") != 1
            or execution_receipt.get("retry_permitted") is not False
            or execution_receipt.get("production_authorized") is not False
            or execution_receipt.get("production_status")
            != route.PRODUCTION_STATUS
        ):
            raise DeploymentRecoveryError("EXECUTION_RECEIPT_INVALID")
        receipt = dict(execution_receipt)
    if (
        execution.get("source_commit") != seed_intent["source_commit"]
        or execution.get("parent_intent_digest")
        != seed_intent["intent_digest"]
        or execution.get("route_not_before")
        != seed_intent["route_not_before"]
        or execution.get("route_not_after") != seed_intent["route_not_after"]
        or execution.get("recovery_not_after")
        != seed_intent["recovery_not_after"]
        or execution.get("account_id") != _account_id(execution["target"])
    ):
        raise DeploymentRecoveryError("EXECUTION_SEED_BINDING_INVALID")
    return execution, receipt


def _validate_durable_execution_result(
    claims: connected.OExclClaimStore,
    *,
    execution: Mapping[str, Any],
    receipt: Mapping[str, Any],
) -> dict[str, Any]:
    if execution["record_type"] == route.RECORD_TYPE_EXECUTION_INTENT:
        key = (
            f"execute:{execution['target']}:"
            f"{execution['execute_operation_digest']}"
        )
    else:
        key = (
            f"reentry-execute:{execution['target']}:"
            f"{execution['parent_intent_digest']}"
        )
    try:
        durable_receipt = claims.read_result(key)
    except connected.ConnectedRouteError as exc:
        raise DeploymentRecoveryError(exc.code) from exc
    if durable_receipt != receipt:
        raise DeploymentRecoveryError("EXECUTION_RESULT_JOURNAL_INVALID")
    return _execution_claim(claims, execution=execution, receipt=receipt)


def _execute_event_digest(
    trail: Any,
    *,
    account: str,
    claim: Mapping[str, Any],
    execution: Mapping[str, Any],
    receipt: Mapping[str, Any],
    now: datetime,
) -> tuple[str, int]:
    events, pages = _lookup(
        trail,
        event_name="ExecuteChangeSet",
        start=_time(claim.get("claimed_at"), "EXECUTION_CLAIM_INVALID"),
        end=now,
        code="EXECUTE_CLOUDTRAIL_AMBIGUOUS",
    )
    request = execution["execute_request"]
    expected = {
        "stackName": request["StackName"],
        "changeSetName": request["ChangeSetName"],
        "clientRequestToken": request["ClientRequestToken"],
    }
    if "DisableRollback" in request:
        expected["disableRollback"] = request["DisableRollback"]
    matches: list[dict[str, Any]] = []
    for envelope in events:
        event = _strict_json(envelope.get("CloudTrailEvent"), "EXECUTE_CLOUDTRAIL_INVALID")
        if event.get("requestID") != receipt["execute_request_id"]:
            continue
        params = event.get("requestParameters") or {}
        identity = event.get("userIdentity") or {}
        caller = identity.get("arn")
        event_time = _time(event.get("eventTime"), "EXECUTE_CLOUDTRAIL_INVALID")
        if (
            event.get("eventSource") != "cloudformation.amazonaws.com"
            or event.get("eventName") != "ExecuteChangeSet"
            or event.get("awsRegion") != route.REGION
            or event.get("recipientAccountId") != account
            or event.get("readOnly") is not False
            or event.get("errorCode") is not None
            or event.get("errorMessage") is not None
            or event.get("responseElements") is not None
            or not isinstance(caller, str)
            or not _caller_arn_matches_phase(
                caller,
                target=str(claim.get("target")),
                phase="executor",
            )
            or route.digest_value(caller) != claim.get("caller_arn_digest")
            or params != expected
            or not _time(receipt["dispatched_at"], "EXECUTION_RECEIPT_INVALID") <= event_time <= now
            or _UUID_RE.fullmatch(str(event.get("eventID", ""))) is None
        ):
            raise DeploymentRecoveryError("EXECUTE_CLOUDTRAIL_INVALID")
        matches.append(
            {
                "event_id": event["eventID"],
                "event_time": _stamp(event_time),
                "request_id": event["requestID"],
                "request_digest": route.digest_value(expected),
            }
        )
    if len(matches) != 1:
        raise DeploymentRecoveryError("EXECUTE_CLOUDTRAIL_MISSING")
    return route.digest_value(matches[0]), pages


def reentry_execute_event_digest(
    *,
    cloudtrail: Any,
    claims: connected.OExclClaimStore,
    execution_intent: Mapping[str, Any],
    execution_receipt: Mapping[str, Any],
    observed_at: datetime,
) -> tuple[str, int]:
    """Validate one reentry execution and return its exact event evidence.

    This is the narrow read-only integration surface used by the existing
    terminal verifier.  The mutation provider already validated the complete
    causal chain before writing the claim; this step validates the immutable
    execution shape and receipt, reopens that claim, and requires exactly one
    matching ExecuteChangeSet event.
    """

    execution = validate_reentry_execution_intent_structure(execution_intent)
    receipt = _validate_reentry_execution_receipt(
        execution_receipt, execution=execution
    )
    if (
        not isinstance(observed_at, datetime)
        or observed_at.tzinfo is None
        or observed_at.utcoffset() is None
    ):
        raise DeploymentRecoveryError("CLOCK_INVALID")
    now = observed_at.astimezone(timezone.utc).replace(microsecond=0)
    if not _time(
        execution["route_not_before"], "RECOVERY_WINDOW_INVALID"
    ) <= now < _time(
        execution["recovery_not_after"], "RECOVERY_WINDOW_INVALID"
    ):
        raise DeploymentRecoveryError("RECOVERY_WINDOW_CLOSED")
    if _time(receipt["dispatched_at"], "EXECUTION_RECEIPT_INVALID") > now:
        raise DeploymentRecoveryError("EXECUTION_RECEIPT_INVALID")
    claim = _execution_claim(claims, execution=execution, receipt=receipt)
    return _execute_event_digest(
        cloudtrail,
        account=execution["account_id"],
        claim=claim,
        execution=execution,
        receipt=receipt,
        now=now,
    )


def _delete_event_digest(
    trail: Any,
    *,
    account: str,
    claim: Mapping[str, Any],
    dispatch: Mapping[str, Any],
    request: Mapping[str, Any],
    now: datetime,
) -> tuple[str, int]:
    events, pages = _lookup(
        trail,
        event_name="DeleteStack",
        start=_time(claim.get("claimed_at"), "CLEANUP_CLAIM_INVALID"),
        end=now,
        code="CLEANUP_CLOUDTRAIL_AMBIGUOUS",
    )
    expected = {
        "stackName": request["StackName"],
        "clientRequestToken": request["ClientRequestToken"],
    }
    matches: list[dict[str, Any]] = []
    for envelope in events:
        event = _strict_json(envelope.get("CloudTrailEvent"), "CLEANUP_CLOUDTRAIL_INVALID")
        if event.get("requestID") != dispatch["delete_request_id"]:
            continue
        params = event.get("requestParameters") or {}
        identity = event.get("userIdentity") or {}
        event_time = _time(event.get("eventTime"), "CLEANUP_CLOUDTRAIL_INVALID")
        if (
            event.get("eventSource") != "cloudformation.amazonaws.com"
            or event.get("eventName") != "DeleteStack"
            or event.get("awsRegion") != route.REGION
            or event.get("recipientAccountId") != account
            or event.get("readOnly") is not False
            or event.get("errorCode") is not None
            or event.get("errorMessage") is not None
            or event.get("responseElements") is not None
            or not isinstance(identity.get("arn"), str)
            or not _caller_arn_matches_phase(
                identity["arn"],
                target=str(claim.get("target")),
                phase="cleanup",
            )
            or route.digest_value(identity["arn"])
            != claim.get("caller_arn_digest")
            or params != expected
            or "roleARN" in params
            or "retainResources" in params
            or "deletionMode" in params
            or not _time(dispatch["dispatched_at"], "CLEANUP_DISPATCH_INVALID") <= event_time <= now
            or _UUID_RE.fullmatch(str(event.get("eventID", ""))) is None
        ):
            raise DeploymentRecoveryError("CLEANUP_CLOUDTRAIL_INVALID")
        matches.append(
            {
                "event_id": event["eventID"],
                "event_time": _stamp(event_time),
                "request_id": event["requestID"],
                "request_digest": route.digest_value(expected),
            }
        )
    if len(matches) != 1:
        raise DeploymentRecoveryError("CLEANUP_CLOUDTRAIL_MISSING")
    return route.digest_value(matches[0]), pages


def _is_stack_not_found(exc: Exception) -> bool:
    response = getattr(exc, "response", None)
    error = response.get("Error") if isinstance(response, Mapping) else None
    metadata = response.get("ResponseMetadata") if isinstance(response, Mapping) else None
    return (
        isinstance(error, Mapping)
        and error.get("Code") == "ValidationError"
        and isinstance(error.get("Message"), str)
        and "does not exist" in error["Message"]
        and isinstance(metadata, Mapping)
        and metadata.get("HTTPStatusCode") == 400
    )


__all__ = [
    "BRIDGE_RECOVERY_ROLE_NAME",
    "BRIDGE_RECOVERY_IDENTITY_CONTRACT",
    "BROKER_FIXED_FUNCTION_NAMES",
    "BROKER_FIXED_IAM_ROLE_NAMES",
    "BROKER_FIXED_KMS_ALIAS",
    "BROKER_FIXED_LOG_GROUP_NAMES",
    "BROKER_FIXED_TABLE_NAME",
    "CLAIM_RECORD_TYPE",
    "CLEANUP_IDENTITY_CONTRACTS",
    "CLEANUP_AUTHORIZATION_PHRASES",
    "CLEANUP_PROFILE_NAMES",
    "CLEANUP_ROLE_NAMES",
    "CLEANUP_TERMINAL_RECORD_TYPE",
    "ConnectedDeploymentRecoveryProvider",
    "DeploymentRecoveryError",
    "FAILED_CREATE_STACK_RECORD_TYPE",
    "PREEXECUTE_FAILURE_RECORD_TYPE",
    "PROTECTION_ROLLBACK_RECORD_TYPE",
    "REENTRY_CHANGE_SET_NAMES",
    "REENTRY_ATTESTATION_RECORD_TYPE",
    "REENTRY_CREATION_PHRASES",
    "REENTRY_EXECUTION_INTENT_RECORD_TYPE",
    "REENTRY_EXECUTION_PHRASES",
    "REENTRY_EXECUTION_RECEIPT_RECORD_TYPE",
    "ROUTE_FIXED_IAM_ROLE_NAMES",
    "clients_from_session",
    "materialize_cleanup_authorization",
    "materialize_cleanup_intent",
    "materialize_reentry_authorization",
    "materialize_reentry_execution_authorization",
    "materialize_reentry_execution_intent",
    "materialize_reentry_intent",
    "materialize_reentry_request",
    "reentry_execute_event_digest",
    "validate_cleanup_intent",
    "validate_cleanup_authorization",
    "validate_reentry_authorization",
    "validate_reentry_attestation",
    "validate_reentry_execution_authorization",
    "validate_reentry_execution_intent",
    "validate_reentry_execution_intent_structure",
    "validate_reentry_intent",
]
