from __future__ import annotations

import copy
from datetime import datetime, timedelta, timezone
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
from typing import Any, Mapping

import pytest

from tooling import platform_authority_plan_permission_repair_deployment_recovery as recovery
from tooling import platform_authority_plan_permission_repair_deployment_route as route
from tooling import platform_authority_plan_permission_repair_deployment_route_aws as connected


ROOT = Path(__file__).resolve().parents[2]
RECOVERY_CLI = ROOT / (
    "scripts/deployment/"
    "platform-authority-plan-permission-repair-deployment-recovery.py"
)
STACK_UUID = "22222222-2222-4222-8222-222222222222"
CHANGE_UUID = "11111111-1111-4111-8111-111111111111"
RECOVERY_CHANGE_UUID = "66666666-6666-4666-8666-666666666666"
REQUEST_UUID = "33333333-3333-4333-8333-333333333333"
RECOVERY_REQUEST_UUID = "77777777-7777-4777-8777-777777777777"
EVENT_UUID = "44444444-4444-4444-8444-444444444444"
TEST_TEMPLATE_BODY = "AWSTemplateFormatVersion: '2010-09-09'\nResources: {}\n"


def _request(
    *, target: str, stack_name: str, change_set_name: str, change_set_type: str
) -> dict[str, Any]:
    value: dict[str, Any] = {
        "StackName": stack_name,
        "ChangeSetName": change_set_name,
        "ChangeSetType": change_set_type,
        "Description": (
            "GUG-376 enable route broker ledger deletion protection"
            if target == route.BROKER_PROTECTION_TARGET
            else "GUG-376 reviewed initial administrative seed"
        ),
        "TemplateURL": (
            "https://scanalyze-gug376-artifacts.s3.us-east-1.amazonaws.com/"
            f"templates/{target}.yaml?versionId=version-1"
        ),
        "Capabilities": ["CAPABILITY_NAMED_IAM"],
        "Tags": copy.deepcopy(route.EXACT_TAGS),
        "IncludeNestedStacks": False,
        "NotificationARNs": [],
        "RollbackConfiguration": {
            "MonitoringTimeInMinutes": 0,
            "RollbackTriggers": [],
        },
        "ClientToken": "gug376-" + ("a" if target == "route" else "b") * 48,
    }
    if target == "route":
        value["Parameters"] = []
    if change_set_type == "CREATE":
        value["OnStackFailure"] = "DELETE"
    return value


def _seed_intent(now: datetime) -> dict[str, Any]:
    not_before = now - timedelta(minutes=5)
    not_after = now + timedelta(minutes=55)
    resources = [
        {
            "logical_resource_id": "OnlyResource",
            "resource_type": "AWS::IAM::Role",
        }
    ]
    targets: dict[str, Any] = {}
    for target, account, stack, change, change_type in (
        (
            "route",
            route.MANAGEMENT_ACCOUNT_ID,
            route.ROUTE_STACK_NAME,
            route.ROUTE_CHANGE_SET_NAME,
            "CREATE",
        ),
        (
            "broker",
            route.AUTHORITY_ACCOUNT_ID,
            route.BROKER_STACK_NAME,
            route.BROKER_CHANGE_SET_NAME,
            "CREATE",
        ),
        (
            route.BROKER_PROTECTION_TARGET,
            route.AUTHORITY_ACCOUNT_ID,
            route.BROKER_STACK_NAME,
            route.BROKER_PROTECTION_CHANGE_SET_NAME,
            "UPDATE",
        ),
    ):
        request = _request(
            target=target,
            stack_name=stack,
            change_set_name=change,
            change_set_type=change_type,
        )
        targets[target] = {
            "account_id": account,
            "stack_name": stack,
            "change_set_name": change,
            "creator_role_name": "creator",
            "executor_role_name": "executor",
            "template_digest": route.bytes_digest(
                TEST_TEMPLATE_BODY.encode("utf-8")
            ),
            "source_template_digest": "sha256:" + "2" * 64,
            "expected_resources": resources,
            "expected_changes": resources,
            "expected_outputs": [],
            "expected_assignment_count": 0,
            "broker_code_sha256": None,
            "broker_signing_profile_version_arn": None,
            "broker_signing_receipt_digest": None,
            "broker_config_digest": None,
            "broker_effective_policy_projection": None,
            "create_request": request,
            "create_request_digest": route.digest_value(request),
        }
    return route.seal(
        {
            "schema_version": 1,
            "record_type": route.RECORD_TYPE_INTENT,
            "source_commit": "a" * 40,
            "management_account_id": route.MANAGEMENT_ACCOUNT_ID,
            "authority_account_id": route.AUTHORITY_ACCOUNT_ID,
            "region": route.REGION,
            "route_not_before": _ts(not_before),
            "route_not_after": _ts(not_after),
            "recovery_not_after": _ts(not_after + timedelta(hours=24)),
            "identity_center_instance_arn": (
                "arn:aws:sso:::instance/ssoins-ABCDEFGHIJKLMNOP"
            ),
            "bootstrap_principal_id": (
                "12345678-1234-4123-8123-123456789012"
            ),
            "identity_center_instance_arn_digest": "sha256:" + "3" * 64,
            "bootstrap_principal_id_digest": "sha256:" + "4" * 64,
            "artifact_bootstrap_release_digest": "sha256:" + "5" * 64,
            "foundation_storage_binding_digest": "sha256:" + "6" * 64,
            "delegation_source_template_digest": "sha256:" + "7" * 64,
            "targets": targets,
            "aws_calls": 0,
            "aws_mutations": 0,
            "deployment_authorized": False,
            "production_authorized": False,
            "production_status": route.PRODUCTION_STATUS,
        },
        "intent_digest",
    )


@pytest.fixture
def case(
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[dict[str, Any], dict[str, Any], datetime]:
    now = datetime.now(timezone.utc).replace(microsecond=0)
    intent = _seed_intent(now)

    def validated(value: Mapping[str, Any]) -> dict[str, Any]:
        return json.loads(route.canonical_json(value))

    def validated_against_input(
        value: Mapping[str, Any], **_kwargs: Any
    ) -> dict[str, Any]:
        return validated(value)

    # Recovery unit tests isolate the recovery contracts from the independently
    # covered seed-intent materializer (which is edited in a separate lane).
    monkeypatch.setattr(route, "validate_seed_intent", validated)
    monkeypatch.setattr(
        route, "validate_seed_intent_against_input", validated_against_input
    )
    return {}, intent, now


def _ts(value: datetime) -> str:
    return value.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace(
        "+00:00", "Z"
    )


class Identity:
    def __init__(self, account: str, role: str, timeline: list[str]) -> None:
        self.account = account
        self.role = role
        self.timeline = timeline

    def get_caller_identity(self) -> dict[str, str]:
        self.timeline.append("sts")
        return {
            "Account": self.account,
            "Arn": _caller(self.account, self.role),
            "UserId": "AROATEST:cesar",
        }


class Claims:
    def __init__(self, timeline: list[str]) -> None:
        self.timeline = timeline
        self.seen: set[str] = set()
        self.records: dict[str, dict[str, Any]] = {}
        self.results: dict[str, dict[str, Any]] = {}

    def claim(self, key: str, record: Mapping[str, Any]) -> None:
        self.timeline.append("claim")
        if key in self.seen:
            raise connected.ConnectedRouteError("MUTATION_REPLAY_REJECTED")
        self.seen.add(key)
        self.records[key] = dict(record)

    def complete(self, key: str, record: Mapping[str, Any]) -> None:
        self.timeline.append("complete")
        if key not in self.seen:
            raise AssertionError("claim missing")
        self.results[key] = dict(record)

    def read_claim(self, key: str) -> dict[str, Any]:
        self.timeline.append("read-claim")
        return dict(self.records[key])

    def read_result(self, key: str) -> dict[str, Any]:
        self.timeline.append("read-result")
        if key not in self.results:
            raise connected.ConnectedRouteError("MUTATION_RESULT_MISSING")
        return dict(self.results[key])


def _observed_parameters(
    request: Mapping[str, Any], *, target: str
) -> list[dict[str, str]]:
    return [
        {
            "ParameterKey": item["ParameterKey"],
            "ParameterValue": (
                "*****"
                if target == "route"
                and item["ParameterKey"] in route.ROUTE_NO_ECHO_PARAMETER_KEYS
                else item["ParameterValue"]
            ),
        }
        for item in request.get("Parameters", [])
    ]


def _dispatch(
    intent: Mapping[str, Any], target: str, now: datetime
) -> dict[str, Any]:
    spec = intent["targets"][target]
    authorized_at = now - timedelta(minutes=1)
    authorization = route.materialize_creation_authorization(
        seed_intent=intent,
        target=target,
        authorization=(
            f"I_AUTHORIZE_GUG376_{target.upper().replace('-', '_')}_SEED_CREATION"
        ),
        authorized_at=_ts(authorized_at),
        expires_at=_ts(authorized_at + timedelta(minutes=10)),
    )
    value = {
        "schema_version": 1,
        "record_type": connected.DISPATCH_RECORD_TYPE,
        "source_commit": intent["source_commit"],
        "target": target,
        "account_id": spec["account_id"],
        "intent_digest": intent["intent_digest"],
        "create_request_digest": spec["create_request_digest"],
        "creation_authorization": authorization,
        "creation_authorization_digest": authorization["authorization_digest"],
        "stack_arn": (
            f"arn:aws:cloudformation:us-east-1:{spec['account_id']}:stack/"
            f"{spec['stack_name']}/{STACK_UUID}"
        ),
        "change_set_arn": (
            f"arn:aws:cloudformation:us-east-1:{spec['account_id']}:changeSet/"
            f"{spec['change_set_name']}/{CHANGE_UUID}"
        ),
        "create_request_id": REQUEST_UUID,
        "dispatched_at": _ts(authorized_at),
        "aws_mutations": 1,
        "retry_permitted": False,
        "production_authorized": False,
        "production_status": route.PRODUCTION_STATUS,
    }
    return route.seal(value, "dispatch_digest")


class ServiceError(RuntimeError):
    def __init__(self, code: str, status: int, message: str = "missing") -> None:
        self.response = {
            "Error": {"Code": code, "Message": message},
            "ResponseMetadata": {"HTTPStatusCode": status},
        }
        super().__init__(code)


class Trail:
    def __init__(self, event: Mapping[str, Any]) -> None:
        self.event = event
        self.requests: list[dict[str, Any]] = []

    def lookup_events(self, **request: Any) -> dict[str, Any]:
        self.requests.append(request)
        return {"Events": [{"CloudTrailEvent": json.dumps(self.event)}]}


class EmptyService:
    def __getattr__(self, _name: str) -> Any:
        def missing(**_request: Any) -> Any:
            raise AssertionError("unexpected AWS call")

        return missing


def _clients(
    *,
    sts: Any,
    cfn: Any,
    trail: Any,
    dynamodb: Any | None = None,
    kms: Any | None = None,
    lambda_client: Any | None = None,
    iam: Any | None = None,
    logs: Any | None = None,
    sso: Any | None = None,
) -> dict[str, Any]:
    empty = EmptyService()
    return {
        "sts": sts,
        "cloudformation": cfn,
        "cloudtrail": trail,
        "dynamodb": dynamodb or empty,
        "kms": kms or empty,
        "lambda": lambda_client or empty,
        "iam": iam or empty,
        "logs": logs or empty,
        "sso-admin": sso or empty,
    }


def _caller(account: str, role_name: str) -> str:
    return (
        f"arn:aws:sts::{account}:assumed-role/"
        f"AWSReservedSSO_{role_name}_0123456789abcdef/cesar"
    )


def _seed_primary_claim(
    claims: Claims,
    intent: Mapping[str, Any],
    target: str,
    dispatch: Mapping[str, Any],
) -> None:
    spec = intent["targets"][target]
    role = (
        "AWSAdministratorAccess"
        if target == "route"
        else "ScanalyzeGug376BrokerSeedCreator"
    )
    claim = {
        "schema_version": 1,
        "record_type": connected.CLAIM_RECORD_TYPE,
        "operation": "CreateChangeSet",
        "target": target,
        "intent_digest": intent["intent_digest"],
        "request_digest": spec["create_request_digest"],
        "creation_authorization": dispatch["creation_authorization"],
        "creation_authorization_digest": dispatch[
            "creation_authorization_digest"
        ],
        "client_token": spec["create_request"]["ClientToken"],
        "stack_name": spec["stack_name"],
        "change_set_name": spec["change_set_name"],
        "caller_arn_digest": route.digest_value(
            _caller(spec["account_id"], role)
        ),
        "claimed_at": dispatch["dispatched_at"],
        "retry_permitted": False,
        "production_authorized": False,
    }
    claims.seen.add(
        f"create:{target}:{intent['intent_digest']}:"
        f"{spec['create_request_digest']}"
    )
    claims.records[
        f"create:{target}:{intent['intent_digest']}:"
        f"{spec['create_request_digest']}"
    ] = claim
    claims.results[
        f"create:{target}:{intent['intent_digest']}:"
        f"{spec['create_request_digest']}"
    ] = dict(dispatch)


def _create_event(
    *,
    request: Mapping[str, Any],
    account: str,
    role_name: str,
    stack_arn: str,
    change_set_arn: str,
    request_id: str,
    event_id: str,
    when: datetime,
) -> dict[str, Any]:
    return {
        "eventSource": "cloudformation.amazonaws.com",
        "eventName": "CreateChangeSet",
        "awsRegion": route.REGION,
        "recipientAccountId": account,
        "readOnly": False,
        "errorCode": None,
        "errorMessage": None,
        "requestID": request_id,
        "eventID": event_id,
        "eventTime": _ts(when),
        "userIdentity": {"arn": _caller(account, role_name)},
        "requestParameters": connected._create_cloudtrail_params(request),
        "responseElements": {"id": change_set_arn, "stackId": stack_arn},
    }


class FailedChangeSetCloudFormation:
    def __init__(
        self,
        *,
        intent: Mapping[str, Any],
        target: str,
        dispatch: Mapping[str, Any],
        reason: str = "Template validation rejected the exact request",
    ) -> None:
        self.spec = intent["targets"][target]
        self.target = target
        self.dispatch = dispatch
        self.reason = reason

    def describe_change_set(self, **request: Any) -> dict[str, Any]:
        assert request == {
            "StackName": self.dispatch["stack_arn"],
            "ChangeSetName": self.dispatch["change_set_arn"],
        }
        source = self.spec["create_request"]
        return {
            "ChangeSetId": self.dispatch["change_set_arn"],
            "StackId": self.dispatch["stack_arn"],
            "StackName": self.spec["stack_name"],
            "ChangeSetName": self.spec["change_set_name"],
            "Status": "FAILED",
            "ExecutionStatus": "UNAVAILABLE",
            "StatusReason": self.reason,
            "Description": source["Description"],
            "ChangeSetType": "CREATE",
            "Parameters": _observed_parameters(
                source, target=self.target
            ),
            "Capabilities": source["Capabilities"],
            "Tags": source["Tags"],
            "IncludeNestedStacks": False,
            "NotificationARNs": [],
            "RollbackConfiguration": source["RollbackConfiguration"],
            "OnStackFailure": "DELETE",
        }

    def describe_stacks(self, **request: Any) -> dict[str, Any]:
        assert request == {"StackName": self.dispatch["stack_arn"]}
        return {
            "Stacks": [
                {
                    "StackId": self.dispatch["stack_arn"],
                    "StackName": self.spec["stack_name"],
                    "StackStatus": "REVIEW_IN_PROGRESS",
                }
            ]
        }

    def list_stack_resources(self, **request: Any) -> dict[str, Any]:
        assert request == {"StackName": self.dispatch["stack_arn"]}
        return {"StackResourceSummaries": []}


def _preexecute_failure(
    intent: Mapping[str, Any], now: datetime, target: str = "route"
) -> tuple[dict[str, Any], Claims, list[str]]:
    timeline: list[str] = []
    dispatch = _dispatch(intent, target, now)
    claims = Claims(timeline)
    _seed_primary_claim(claims, intent, target, dispatch)
    role = (
        "AWSAdministratorAccess"
        if target == "route"
        else "ScanalyzeGug376BrokerSeedCreator"
    )
    event = _create_event(
        request=intent["targets"][target]["create_request"],
        account=intent["targets"][target]["account_id"],
        role_name=role,
        stack_arn=dispatch["stack_arn"],
        change_set_arn=dispatch["change_set_arn"],
        request_id=dispatch["create_request_id"],
        event_id=EVENT_UUID,
        when=now,
    )
    provider = recovery.ConnectedDeploymentRecoveryProvider(
        clients=_clients(
            sts=Identity(
                intent["targets"][target]["account_id"], role, timeline
            ),
            cfn=FailedChangeSetCloudFormation(
                intent=intent, target=target, dispatch=dispatch
            ),
            trail=Trail(event),
        ),
        claims=claims,
        clock=lambda: now,
    )
    return (
        provider.attest_preexecute_failure(
            seed_intent=intent,
            target=target,
            primary_dispatch=dispatch,
        ),
        claims,
        timeline,
    )


def test_preexecute_failure_is_exact_sealed_read_only_and_redacts_reason(
    case: tuple[dict[str, Any], dict[str, Any], datetime]
) -> None:
    _source, intent, now = case
    attestation, _claims, timeline = _preexecute_failure(intent, now)
    assert attestation["status"] == "FAILED"
    assert attestation["execution_status"] == "UNAVAILABLE"
    assert attestation["stack_status"] == "REVIEW_IN_PROGRESS"
    assert attestation["resource_count"] == 0
    assert attestation["aws_mutations"] == 0
    assert "status_reason" not in attestation
    assert attestation["status_reason_digest"].startswith("sha256:")
    assert timeline == ["read-claim", "read-result", "sts"]


def test_preexecute_failure_rejects_resource_survivor(
    case: tuple[dict[str, Any], dict[str, Any], datetime]
) -> None:
    _source, intent, now = case
    target = "route"
    timeline: list[str] = []
    dispatch = _dispatch(intent, target, now)
    claims = Claims(timeline)
    _seed_primary_claim(claims, intent, target, dispatch)
    cfn = FailedChangeSetCloudFormation(
        intent=intent, target=target, dispatch=dispatch
    )

    def survivor(**_request: Any) -> dict[str, Any]:
        return {
            "StackResourceSummaries": [
                {
                    "LogicalResourceId": "Unexpected",
                    "ResourceType": "AWS::IAM::Role",
                    "ResourceStatus": "CREATE_COMPLETE",
                }
            ]
        }

    cfn.list_stack_resources = survivor  # type: ignore[method-assign]
    role_name = "AWSAdministratorAccess"
    event = _create_event(
        request=intent["targets"][target]["create_request"],
        account=route.MANAGEMENT_ACCOUNT_ID,
        role_name=role_name,
        stack_arn=dispatch["stack_arn"],
        change_set_arn=dispatch["change_set_arn"],
        request_id=REQUEST_UUID,
        event_id=EVENT_UUID,
        when=now,
    )
    provider = recovery.ConnectedDeploymentRecoveryProvider(
        clients=_clients(
            sts=Identity(route.MANAGEMENT_ACCOUNT_ID, role_name, timeline),
            cfn=cfn,
            trail=Trail(event),
        ),
        claims=claims,
        clock=lambda: now,
    )
    with pytest.raises(
        recovery.DeploymentRecoveryError,
        match="PRIMARY_FAILURE_RESOURCES_PRESENT",
    ):
        provider.attest_preexecute_failure(
            seed_intent=intent,
            target=target,
            primary_dispatch=dispatch,
        )


def test_reentry_request_changes_only_name_and_token_and_is_one_attempt(
    case: tuple[dict[str, Any], dict[str, Any], datetime]
) -> None:
    _source, intent, now = case
    failure, _claims, _timeline = _preexecute_failure(intent, now)
    request = recovery.materialize_reentry_request(
        seed_intent=intent, failure_attestation=failure
    )
    primary = intent["targets"]["route"]["create_request"]
    assert request["ChangeSetName"] == recovery.REENTRY_CHANGE_SET_NAMES["route"]
    assert request["ClientToken"] != primary["ClientToken"]
    assert request["OnStackFailure"] == "DELETE"
    assert "RoleARN" not in request
    assert "RetainResources" not in request
    assert {
        key: value
        for key, value in request.items()
        if key not in {"ChangeSetName", "ClientToken"}
    } == {
        key: value
        for key, value in primary.items()
        if key not in {"ChangeSetName", "ClientToken"}
    }


def test_reentry_authorization_exact_phrase_and_admission_reserve(
    case: tuple[dict[str, Any], dict[str, Any], datetime]
) -> None:
    _source, intent, now = case
    failure, _claims, _timeline = _preexecute_failure(intent, now)
    authorization = recovery.materialize_reentry_authorization(
        seed_intent=intent,
        failure_attestation=failure,
        authorization="I_AUTHORIZE_GUG376_ROUTE_SEED_CREATE_REENTRY_1",
        authorized_at=_ts(now),
        expires_at=_ts(now + timedelta(minutes=10)),
    )
    reentry = recovery.materialize_reentry_intent(
        seed_intent=intent,
        failure_attestation=failure,
        authorization=authorization,
    )
    assert recovery.validate_reentry_intent(
        reentry,
        seed_intent=intent,
        failure_attestation=failure,
        authorization=authorization,
    ) == reentry
    with pytest.raises(
        recovery.DeploymentRecoveryError, match="REENTRY_AUTHORIZATION_INVALID"
    ):
        recovery.materialize_reentry_authorization(
            seed_intent=intent,
            failure_attestation=failure,
            authorization="I_AUTHORIZE_GUG376_ROUTE_SEED_CREATION",
            authorized_at=_ts(now),
            expires_at=_ts(now + timedelta(minutes=10)),
        )
    cutoff = datetime.fromisoformat(
        intent["route_not_after"].replace("Z", "+00:00")
    ) - timedelta(seconds=route.MUTATION_COMPLETION_RESERVE_SECONDS)
    with pytest.raises(
        recovery.DeploymentRecoveryError, match="REENTRY_AUTHORIZATION_INVALID"
    ):
        recovery.materialize_reentry_authorization(
            seed_intent=intent,
            failure_attestation=failure,
            authorization="I_AUTHORIZE_GUG376_ROUTE_SEED_CREATE_REENTRY_1",
            authorized_at=_ts(cutoff - timedelta(seconds=60)),
            expires_at=_ts(cutoff + timedelta(seconds=1)),
        )


class ReentryCreateCloudFormation:
    def __init__(
        self,
        request: Mapping[str, Any],
        account: str,
        *,
        seed: Mapping[str, Any] | None = None,
        failure: Mapping[str, Any] | None = None,
    ) -> None:
        self.request = request
        self.account = account
        self.seed = seed
        self.failure = failure
        self.calls = 0

    def describe_change_set(self, **request: Any) -> dict[str, Any]:
        assert self.seed is not None and self.failure is not None
        assert request == {
            "StackName": self.failure["stack_arn"],
            "ChangeSetName": self.failure["change_set_arn"],
        }
        target = str(self.failure["target"])
        primary = self.seed["targets"][target]["create_request"]
        return {
            "ChangeSetId": self.failure["change_set_arn"],
            "StackId": self.failure["stack_arn"],
            "StackName": primary["StackName"],
            "ChangeSetName": primary["ChangeSetName"],
            "Status": "FAILED",
            "ExecutionStatus": "UNAVAILABLE",
            "StatusReason": (
                "Template validation rejected the exact request"
            ),
            "Description": primary["Description"],
            "ChangeSetType": "CREATE",
            "Parameters": _observed_parameters(primary, target=target),
            "Capabilities": primary["Capabilities"],
            "Tags": primary["Tags"],
            "IncludeNestedStacks": False,
            "NotificationARNs": [],
            "RollbackConfiguration": primary["RollbackConfiguration"],
            "OnStackFailure": "DELETE",
        }

    def describe_stacks(self, **request: Any) -> dict[str, Any]:
        assert self.failure is not None
        assert request == {"StackName": self.failure["stack_arn"]}
        return {
            "Stacks": [
                {
                    "StackId": self.failure["stack_arn"],
                    "StackName": (
                        route.ROUTE_STACK_NAME
                        if self.failure["target"] == "route"
                        else route.BROKER_STACK_NAME
                    ),
                    "StackStatus": "REVIEW_IN_PROGRESS",
                }
            ]
        }

    def list_stack_resources(self, **request: Any) -> dict[str, Any]:
        assert self.failure is not None
        assert request == {"StackName": self.failure["stack_arn"]}
        return {"StackResourceSummaries": []}

    def create_change_set(self, **request: Any) -> dict[str, Any]:
        self.calls += 1
        assert request == self.request
        return {
            "Id": (
                f"arn:aws:cloudformation:us-east-1:{self.account}:changeSet/"
                f"{request['ChangeSetName']}/{RECOVERY_CHANGE_UUID}"
            ),
            "StackId": (
                f"arn:aws:cloudformation:us-east-1:{self.account}:stack/"
                f"{request['StackName']}/{STACK_UUID}"
            ),
            "ResponseMetadata": {"RequestId": RECOVERY_REQUEST_UUID},
        }


def _reentry_intent(
    intent: Mapping[str, Any], now: datetime
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    failure, _claims, _timeline = _preexecute_failure(intent, now)
    authorization = recovery.materialize_reentry_authorization(
        seed_intent=intent,
        failure_attestation=failure,
        authorization=recovery.REENTRY_CREATION_PHRASES["route"],
        authorized_at=_ts(now),
        expires_at=_ts(now + timedelta(minutes=10)),
    )
    return (
        recovery.materialize_reentry_intent(
            seed_intent=intent,
            failure_attestation=failure,
            authorization=authorization,
        ),
        failure,
        authorization,
    )


def _seed_primary_failure_journal(
    claims: Claims,
    *,
    seed: Mapping[str, Any],
    failure: Mapping[str, Any],
    now: datetime,
) -> dict[str, Any]:
    target = str(failure["target"])
    dispatch = _dispatch(seed, target, now)
    assert dispatch["dispatch_digest"] == failure["primary_dispatch_digest"]
    _seed_primary_claim(claims, seed, target, dispatch)
    return _create_event(
        request=seed["targets"][target]["create_request"],
        account=seed["targets"][target]["account_id"],
        role_name=(
            "AWSAdministratorAccess"
            if target == "route"
            else "ScanalyzeGug376BrokerSeedCreator"
        ),
        stack_arn=dispatch["stack_arn"],
        change_set_arn=dispatch["change_set_arn"],
        request_id=dispatch["create_request_id"],
        event_id=EVENT_UUID,
        when=now,
    )


def _reentry_dispatch_and_attestation(
    seed: Mapping[str, Any],
    reentry_intent: Mapping[str, Any],
    now: datetime,
    *,
    change_uuid: str = RECOVERY_CHANGE_UUID,
    request_uuid: str = RECOVERY_REQUEST_UUID,
) -> tuple[dict[str, Any], dict[str, Any]]:
    target = str(reentry_intent["target"])
    account = str(reentry_intent["account_id"])
    stack_arn = (
        f"arn:aws:cloudformation:{route.REGION}:{account}:stack/"
        f"{reentry_intent['create_request']['StackName']}/{STACK_UUID}"
    )
    change_set_arn = (
        f"arn:aws:cloudformation:{route.REGION}:{account}:changeSet/"
        f"{recovery.REENTRY_CHANGE_SET_NAMES[target]}/"
        f"{change_uuid}"
    )
    dispatch = route.seal(
        {
            "schema_version": 1,
            "record_type": recovery.REENTRY_DISPATCH_RECORD_TYPE,
            "source_commit": seed["source_commit"],
            "target": target,
            "account_id": account,
            "reentry_intent_digest": reentry_intent[
                "reentry_intent_digest"
            ],
            "create_request_digest": reentry_intent[
                "create_request_digest"
            ],
            "stack_arn": stack_arn,
            "change_set_arn": change_set_arn,
            "create_request_id": request_uuid,
            "dispatched_at": _ts(now),
            "attempt": 1,
            "aws_mutations": 1,
            "retry_permitted": False,
            "production_authorized": False,
            "production_status": route.PRODUCTION_STATUS,
        },
        "dispatch_digest",
    )
    cloudtrail_digest = route.digest_value(
        {
            "event_id": EVENT_UUID,
            "event_time": _ts(now),
            "request_id": request_uuid,
            "request_digest": route.digest_value(
                connected._create_cloudtrail_params(
                    reentry_intent["create_request"]
                )
            ),
        }
    )
    describe_digest = route.digest_value(
        {
            "id": change_set_arn,
            "stack_id": stack_arn,
            "creation_time": _ts(now),
            "status": "CREATE_COMPLETE",
            "execution_status": "AVAILABLE",
            "request_digest": reentry_intent["create_request_digest"],
        }
    )
    attestation = route.seal(
        {
            "schema_version": 1,
            "record_type": recovery.REENTRY_ATTESTATION_RECORD_TYPE,
            "source_commit": seed["source_commit"],
            "target": target,
            "account_id": account,
            "parent_intent_digest": seed["intent_digest"],
            "reentry_intent_digest": reentry_intent[
                "reentry_intent_digest"
            ],
            "create_request_digest": reentry_intent[
                "create_request_digest"
            ],
            "dispatch_digest": dispatch["dispatch_digest"],
            "stack_arn": stack_arn,
            "change_set_arn": change_set_arn,
            "create_request_id": request_uuid,
            "cloudtrail_event_digest": cloudtrail_digest,
            "describe_change_set_digest": describe_digest,
            "template_digest": seed["targets"][target]["template_digest"],
            "changes_digest": route.digest_value(
                seed["targets"][target]["expected_changes"]
            ),
            "status": "CREATE_COMPLETE",
            "execution_status": "AVAILABLE",
            "attested_at": _ts(now),
            "attempt": 1,
            "aws_calls": 4,
            "aws_mutations": 0,
            "retry_permitted": False,
            "production_authorized": False,
            "production_status": route.PRODUCTION_STATUS,
        },
        "attestation_digest",
    )
    return dispatch, attestation


def _seed_reentry_create_journal(
    claims: Claims,
    *,
    seed: Mapping[str, Any],
    reentry_intent: Mapping[str, Any],
    dispatch: Mapping[str, Any],
) -> None:
    target = str(reentry_intent["target"])
    role_name = (
        "AWSAdministratorAccess"
        if target == "route"
        else "ScanalyzeGug376BrokerSeedCreator"
    )
    key = f"reentry-create:{target}:{seed['intent_digest']}"
    claims.records[key] = {
        "schema_version": 1,
        "record_type": recovery.CLAIM_RECORD_TYPE,
        "operation": "CreateChangeSet",
        "target": target,
        "attempt": 1,
        "reentry_intent_digest": reentry_intent[
            "reentry_intent_digest"
        ],
        "request_digest": reentry_intent["create_request_digest"],
        "client_token": reentry_intent["create_request"]["ClientToken"],
        "stack_name": reentry_intent["create_request"]["StackName"],
        "change_set_name": reentry_intent["create_request"][
            "ChangeSetName"
        ],
        "caller_arn_digest": route.digest_value(
            _caller(str(reentry_intent["account_id"]), role_name)
        ),
        "claimed_at": dispatch["dispatched_at"],
        "retry_permitted": False,
        "production_authorized": False,
    }
    claims.results[key] = dict(dispatch)


class AuthoritativeReentryCloudFormation:
    def __init__(
        self,
        *,
        seed: Mapping[str, Any],
        reentry_intent: Mapping[str, Any],
        live_dispatch: Mapping[str, Any],
    ) -> None:
        self.seed = seed
        self.intent = reentry_intent
        self.live_dispatch = live_dispatch
        self.describe_calls = 0
        self.template_calls = 0
        self.execute_calls = 0

    def describe_change_set(self, **_request: Any) -> dict[str, Any]:
        self.describe_calls += 1
        target = str(self.intent["target"])
        request = self.intent["create_request"]
        changes = [
            {
                "Type": "Resource",
                "ResourceChange": {
                    "Action": "Add",
                    "LogicalResourceId": change["logical_resource_id"],
                    "ResourceType": change["resource_type"],
                    "Replacement": "False",
                    "Scope": [],
                    "Details": [],
                },
            }
            for change in self.seed["targets"][target]["expected_changes"]
        ]
        return {
            "ChangeSetId": self.live_dispatch["change_set_arn"],
            "StackId": self.live_dispatch["stack_arn"],
            "StackName": request["StackName"],
            "ChangeSetName": request["ChangeSetName"],
            "Status": "CREATE_COMPLETE",
            "ExecutionStatus": "AVAILABLE",
            "Description": request["Description"],
            "ChangeSetType": request["ChangeSetType"],
            "Parameters": _observed_parameters(request, target=target),
            "Capabilities": request["Capabilities"],
            "Tags": request["Tags"],
            "IncludeNestedStacks": False,
            "NotificationARNs": [],
            "RollbackConfiguration": request["RollbackConfiguration"],
            "OnStackFailure": request.get("OnStackFailure"),
            "CreationTime": datetime.fromisoformat(
                self.live_dispatch["dispatched_at"].replace("Z", "+00:00")
            ),
            "Changes": changes,
        }

    def get_template(self, **_request: Any) -> dict[str, str]:
        self.template_calls += 1
        return {"TemplateBody": TEST_TEMPLATE_BODY}

    def execute_change_set(self, **_request: Any) -> dict[str, Any]:
        self.execute_calls += 1
        return {
            "ResponseMetadata": {"RequestId": RECOVERY_REQUEST_UUID}
        }


def _reentry_execution_chain(
    seed: Mapping[str, Any],
    now: datetime,
    *,
    execution_ttl_seconds: int = 600,
    change_uuid: str = RECOVERY_CHANGE_UUID,
    request_uuid: str = RECOVERY_REQUEST_UUID,
) -> tuple[
    dict[str, Any],
    dict[str, Any],
    dict[str, Any],
    dict[str, Any],
    dict[str, Any],
    dict[str, Any],
    dict[str, Any],
]:
    reentry, failure, creation_authorization = _reentry_intent(seed, now)
    dispatch, attestation = _reentry_dispatch_and_attestation(
        seed,
        reentry,
        now,
        change_uuid=change_uuid,
        request_uuid=request_uuid,
    )
    execution_authorization = (
        recovery.materialize_reentry_execution_authorization(
            seed_intent=seed,
            failure_attestation=failure,
            reentry_creation_authorization=creation_authorization,
            reentry_intent=reentry,
            reentry_dispatch=dispatch,
            reentry_attestation=attestation,
            authorization=recovery.REENTRY_EXECUTION_PHRASES["route"],
            authorized_at=_ts(now),
            expires_at=_ts(
                now + timedelta(seconds=execution_ttl_seconds)
            ),
        )
    )
    execution = recovery.materialize_reentry_execution_intent(
        seed_intent=seed,
        failure_attestation=failure,
        reentry_creation_authorization=creation_authorization,
        reentry_intent=reentry,
        reentry_dispatch=dispatch,
        reentry_attestation=attestation,
        authorization=execution_authorization,
    )
    return (
        reentry,
        failure,
        creation_authorization,
        dispatch,
        attestation,
        execution_authorization,
        execution,
    )


def test_connected_reentry_claims_before_single_mutation_and_rejects_replay(
    case: tuple[dict[str, Any], dict[str, Any], datetime]
) -> None:
    _source, seed, now = case
    intent, failure, authorization = _reentry_intent(seed, now)
    timeline: list[str] = []
    claims = Claims(timeline)
    event = _seed_primary_failure_journal(
        claims, seed=seed, failure=failure, now=now
    )
    current = [now]
    cfn = ReentryCreateCloudFormation(
        intent["create_request"],
        route.MANAGEMENT_ACCOUNT_ID,
        seed=seed,
        failure=failure,
    )
    provider = recovery.ConnectedDeploymentRecoveryProvider(
        clients=_clients(
            sts=Identity(
                route.MANAGEMENT_ACCOUNT_ID,
                "AWSAdministratorAccess",
                timeline,
            ),
            cfn=cfn,
            trail=Trail(event),
        ),
        claims=claims,
        clock=lambda: current[0],
    )
    receipt = provider.create_reentry_change_set(
        seed_input={},
        seed_intent=seed,
        git=object(),
        failure_attestation=failure,
        authorization=authorization,
        reentry_intent=intent,
    )
    assert receipt["attempt"] == 1
    assert receipt["aws_mutations"] == 1
    assert timeline == [
        "read-claim",
        "read-result",
        "sts",
        "claim",
        "complete",
    ]
    assert cfn.calls == 1
    claim_key = f"reentry-create:route:{seed['intent_digest']}"
    changed_claim = copy.deepcopy(claims.records[claim_key])
    changed_claim["client_token"] = "gug376-" + "0" * 48
    with pytest.raises(
        recovery.DeploymentRecoveryError, match="REENTRY_CLAIM_INVALID"
    ):
        recovery._validate_reentry_create_claim(
            changed_claim, intent=intent, dispatch=receipt
        )
    second_failure = copy.deepcopy(failure)
    second_failure["attested_at"] = _ts(now + timedelta(seconds=1))
    second_failure.pop("attestation_digest")
    second_failure = route.seal(second_failure, "attestation_digest")
    second_authorization = recovery.materialize_reentry_authorization(
        seed_intent=seed,
        failure_attestation=second_failure,
        authorization=recovery.REENTRY_CREATION_PHRASES["route"],
        authorized_at=_ts(now + timedelta(seconds=1)),
        expires_at=_ts(now + timedelta(minutes=10, seconds=1)),
    )
    second_intent = recovery.materialize_reentry_intent(
        seed_intent=seed,
        failure_attestation=second_failure,
        authorization=second_authorization,
    )
    assert second_intent["reentry_intent_digest"] != intent[
        "reentry_intent_digest"
    ]
    current[0] = now + timedelta(seconds=1)
    with pytest.raises(
        recovery.DeploymentRecoveryError, match="MUTATION_REPLAY_REJECTED"
    ):
        provider.create_reentry_change_set(
            seed_input={},
            seed_intent=seed,
            git=object(),
            failure_attestation=second_failure,
            authorization=second_authorization,
            reentry_intent=second_intent,
        )
    assert cfn.calls == 1


def test_connected_reentry_rejects_resealed_failure_not_matching_journal_before_sts(
    case: tuple[dict[str, Any], dict[str, Any], datetime]
) -> None:
    _source, seed, now = case
    failure, claims, timeline = _preexecute_failure(seed, now)
    forged = copy.deepcopy(failure)
    forged["primary_claim_digest"] = "sha256:" + "9" * 64
    forged.pop("attestation_digest")
    forged = route.seal(forged, "attestation_digest")
    authorization = recovery.materialize_reentry_authorization(
        seed_intent=seed,
        failure_attestation=forged,
        authorization=recovery.REENTRY_CREATION_PHRASES["route"],
        authorized_at=_ts(now),
        expires_at=_ts(now + timedelta(minutes=10)),
    )
    intent = recovery.materialize_reentry_intent(
        seed_intent=seed,
        failure_attestation=forged,
        authorization=authorization,
    )
    timeline.clear()
    cfn = ReentryCreateCloudFormation(
        intent["create_request"],
        route.MANAGEMENT_ACCOUNT_ID,
        seed=seed,
        failure=forged,
    )
    provider = recovery.ConnectedDeploymentRecoveryProvider(
        clients=_clients(
            sts=Identity(
                route.MANAGEMENT_ACCOUNT_ID,
                "AWSAdministratorAccess",
                timeline,
            ),
            cfn=cfn,
            trail=EmptyService(),
        ),
        claims=claims,
        clock=lambda: now,
    )
    with pytest.raises(
        recovery.DeploymentRecoveryError,
        match="FAILURE_ATTESTATION_JOURNAL_BINDING_INVALID",
    ):
        provider.create_reentry_change_set(
            seed_input={},
            seed_intent=seed,
            git=object(),
            failure_attestation=forged,
            authorization=authorization,
            reentry_intent=intent,
        )
    assert timeline == ["read-claim", "read-result"]
    assert cfn.calls == 0


def test_connected_reentry_rejects_cloudtrail_role_laundered_by_local_journal(
    case: tuple[dict[str, Any], dict[str, Any], datetime]
) -> None:
    _source, seed, now = case
    failure, claims, timeline = _preexecute_failure(seed, now)
    key = (
        f"create:route:{seed['intent_digest']}:"
        f"{seed['targets']['route']['create_request_digest']}"
    )
    wrong_role = "ScanalyzeGug376BrokerSeedCreator"
    wrong_caller = _caller(route.MANAGEMENT_ACCOUNT_ID, wrong_role)
    claims.records[key]["caller_arn_digest"] = route.digest_value(
        wrong_caller
    )
    forged = copy.deepcopy(failure)
    forged["primary_claim_digest"] = route.digest_value(
        claims.records[key]
    )
    forged.pop("attestation_digest")
    forged = route.seal(forged, "attestation_digest")
    authorization = recovery.materialize_reentry_authorization(
        seed_intent=seed,
        failure_attestation=forged,
        authorization=recovery.REENTRY_CREATION_PHRASES["route"],
        authorized_at=_ts(now),
        expires_at=_ts(now + timedelta(minutes=10)),
    )
    intent = recovery.materialize_reentry_intent(
        seed_intent=seed,
        failure_attestation=forged,
        authorization=authorization,
    )
    dispatch = claims.results[key]
    event = _create_event(
        request=seed["targets"]["route"]["create_request"],
        account=route.MANAGEMENT_ACCOUNT_ID,
        role_name=wrong_role,
        stack_arn=dispatch["stack_arn"],
        change_set_arn=dispatch["change_set_arn"],
        request_id=dispatch["create_request_id"],
        event_id=EVENT_UUID,
        when=now,
    )
    timeline.clear()
    cfn = ReentryCreateCloudFormation(
        intent["create_request"],
        route.MANAGEMENT_ACCOUNT_ID,
        seed=seed,
        failure=forged,
    )
    provider = recovery.ConnectedDeploymentRecoveryProvider(
        clients=_clients(
            sts=Identity(
                route.MANAGEMENT_ACCOUNT_ID,
                "AWSAdministratorAccess",
                timeline,
            ),
            cfn=cfn,
            trail=Trail(event),
        ),
        claims=claims,
        clock=lambda: now,
    )
    with pytest.raises(
        recovery.DeploymentRecoveryError,
        match="PRIMARY_CREATE_CLOUDTRAIL_INVALID",
    ):
        provider.create_reentry_change_set(
            seed_input={},
            seed_intent=seed,
            git=object(),
            failure_attestation=forged,
            authorization=authorization,
            reentry_intent=intent,
        )
    assert timeline == ["read-claim", "read-result", "sts"]
    assert cfn.calls == 0


def test_connected_reentry_rejects_resealed_foreign_template_url_before_aws(
    case: tuple[dict[str, Any], dict[str, Any], datetime]
) -> None:
    _source, seed, now = case
    intent, failure, authorization = _reentry_intent(seed, now)
    forged = copy.deepcopy(intent)
    forged["create_request"]["TemplateURL"] = (
        "https://attacker.example.invalid/forged-template.yaml"
    )
    forged["create_request_digest"] = route.digest_value(
        forged["create_request"]
    )
    forged.pop("reentry_intent_digest")
    forged = route.seal(forged, "reentry_intent_digest")
    timeline: list[str] = []
    cfn = ReentryCreateCloudFormation(
        intent["create_request"], route.MANAGEMENT_ACCOUNT_ID
    )
    provider = recovery.ConnectedDeploymentRecoveryProvider(
        clients=_clients(
            sts=Identity(
                route.MANAGEMENT_ACCOUNT_ID,
                "AWSAdministratorAccess",
                timeline,
            ),
            cfn=cfn,
            trail=EmptyService(),
        ),
        claims=Claims(timeline),
        clock=lambda: now,
    )
    with pytest.raises(
        recovery.DeploymentRecoveryError,
        match="REENTRY_INTENT_CAUSAL_MISMATCH",
    ):
        provider.create_reentry_change_set(
            seed_input={},
            seed_intent=seed,
            git=object(),
            failure_attestation=failure,
            authorization=authorization,
            reentry_intent=forged,
        )
    assert timeline == []
    assert cfn.calls == 0


def test_connected_reentry_create_resamples_expiry_before_effect(
    case: tuple[dict[str, Any], dict[str, Any], datetime]
) -> None:
    _source, seed, now = case
    failure, _primary_claims, _primary_timeline = _preexecute_failure(
        seed, now
    )
    authorization = recovery.materialize_reentry_authorization(
        seed_intent=seed,
        failure_attestation=failure,
        authorization=recovery.REENTRY_CREATION_PHRASES["route"],
        authorized_at=_ts(now),
        expires_at=_ts(now + timedelta(seconds=60)),
    )
    reentry = recovery.materialize_reentry_intent(
        seed_intent=seed,
        failure_attestation=failure,
        authorization=authorization,
    )
    timeline: list[str] = []
    claims = Claims(timeline)
    event = _seed_primary_failure_journal(
        claims, seed=seed, failure=failure, now=now
    )
    cfn = ReentryCreateCloudFormation(
        reentry["create_request"],
        route.MANAGEMENT_ACCOUNT_ID,
        seed=seed,
        failure=failure,
    )
    samples = iter(
        (now, now, now + timedelta(seconds=30), now + timedelta(seconds=60))
    )
    provider = recovery.ConnectedDeploymentRecoveryProvider(
        clients=_clients(
            sts=Identity(
                route.MANAGEMENT_ACCOUNT_ID,
                "AWSAdministratorAccess",
                timeline,
            ),
            cfn=cfn,
            trail=Trail(event),
        ),
        claims=claims,
        clock=lambda: next(samples),
    )
    with pytest.raises(
        recovery.DeploymentRecoveryError,
        match="REENTRY_AUTHORIZATION_NOT_ACTIVE",
    ):
        provider.create_reentry_change_set(
            seed_input={},
            seed_intent=seed,
            git=object(),
            failure_attestation=failure,
            authorization=authorization,
            reentry_intent=reentry,
        )
    assert timeline == ["read-claim", "read-result", "sts"]
    assert cfn.calls == 0


def test_recovery_mutation_requires_seed_input_binding_before_aws(
    case: tuple[dict[str, Any], dict[str, Any], datetime],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _source, seed, now = case
    intent, failure, authorization = _reentry_intent(seed, now)

    def reject_seed(*_args: Any, **_kwargs: Any) -> dict[str, Any]:
        raise route.RouteSeedError("INTENT_INPUT_BINDING_INVALID")

    monkeypatch.setattr(route, "validate_seed_intent_against_input", reject_seed)
    timeline: list[str] = []
    cfn = ReentryCreateCloudFormation(
        intent["create_request"], route.MANAGEMENT_ACCOUNT_ID
    )
    provider = recovery.ConnectedDeploymentRecoveryProvider(
        clients=_clients(
            sts=Identity(
                route.MANAGEMENT_ACCOUNT_ID,
                "AWSAdministratorAccess",
                timeline,
            ),
            cfn=cfn,
            trail=EmptyService(),
        ),
        claims=Claims(timeline),
        clock=lambda: now,
    )
    with pytest.raises(
        recovery.DeploymentRecoveryError,
        match="INTENT_INPUT_BINDING_INVALID",
    ):
        provider.create_reentry_change_set(
            seed_input={},
            seed_intent=seed,
            git=object(),
            failure_attestation=failure,
            authorization=authorization,
            reentry_intent=intent,
        )
    assert timeline == []
    assert cfn.calls == 0


def test_reentry_validator_rejects_resealed_token_replay_bypass(
    case: tuple[dict[str, Any], dict[str, Any], datetime]
) -> None:
    _source, seed, now = case
    intent, failure, authorization = _reentry_intent(seed, now)
    changed = copy.deepcopy(intent)
    changed["create_request"]["ClientToken"] = "gug376-" + "f" * 48
    changed["create_request_digest"] = route.digest_value(
        changed["create_request"]
    )
    changed.pop("reentry_intent_digest")
    changed = route.seal(changed, "reentry_intent_digest")
    with pytest.raises(
        recovery.DeploymentRecoveryError, match="REENTRY_INTENT_INVALID"
    ):
        recovery.validate_reentry_intent(
            changed,
            seed_intent=seed,
            failure_attestation=failure,
            authorization=authorization,
        )


def test_reentry_execution_validator_binds_operation_digest_and_exact_arns(
    case: tuple[dict[str, Any], dict[str, Any], datetime]
) -> None:
    _source, seed, now = case
    intent, failure, creation_authorization = _reentry_intent(seed, now)
    dispatch, attestation = _reentry_dispatch_and_attestation(
        seed, intent, now
    )
    authorization = recovery.materialize_reentry_execution_authorization(
        seed_intent=seed,
        failure_attestation=failure,
        reentry_creation_authorization=creation_authorization,
        reentry_intent=intent,
        reentry_dispatch=dispatch,
        reentry_attestation=attestation,
        authorization=recovery.REENTRY_EXECUTION_PHRASES["route"],
        authorized_at=_ts(now),
        expires_at=_ts(now + timedelta(minutes=10)),
    )
    execution = recovery.materialize_reentry_execution_intent(
        seed_intent=seed,
        failure_attestation=failure,
        reentry_creation_authorization=creation_authorization,
        reentry_intent=intent,
        reentry_dispatch=dispatch,
        reentry_attestation=attestation,
        authorization=authorization,
    )
    assert recovery.validate_reentry_execution_intent(
        execution,
        seed_intent=seed,
        failure_attestation=failure,
        reentry_creation_authorization=creation_authorization,
        reentry_intent=intent,
        reentry_dispatch=dispatch,
        reentry_attestation=attestation,
        execution_authorization=authorization,
    ) == execution

    changed = copy.deepcopy(execution)
    changed["execute_operation_digest"] = "sha256:" + "f" * 64
    changed["execute_request"]["ClientRequestToken"] = "gug376-" + "f" * 48
    changed["execute_request_digest"] = route.digest_value(
        changed["execute_request"]
    )
    changed.pop("execution_intent_digest")
    changed = route.seal(changed, "execution_intent_digest")
    with pytest.raises(
        recovery.DeploymentRecoveryError,
        match="REENTRY_EXECUTION_INTENT_INVALID",
    ):
        recovery.validate_reentry_execution_intent(
            changed,
            seed_intent=seed,
            failure_attestation=failure,
            reentry_creation_authorization=creation_authorization,
            reentry_intent=intent,
            reentry_dispatch=dispatch,
            reentry_attestation=attestation,
            execution_authorization=authorization,
        )


def test_connected_reentry_execution_rejects_unattested_arn_before_aws(
    case: tuple[dict[str, Any], dict[str, Any], datetime]
) -> None:
    _source, seed, now = case
    reentry, failure, creation_authorization = _reentry_intent(seed, now)
    dispatch, attestation = _reentry_dispatch_and_attestation(
        seed, reentry, now
    )
    execution_authorization = (
        recovery.materialize_reentry_execution_authorization(
            seed_intent=seed,
            failure_attestation=failure,
            reentry_creation_authorization=creation_authorization,
            reentry_intent=reentry,
            reentry_dispatch=dispatch,
            reentry_attestation=attestation,
            authorization=recovery.REENTRY_EXECUTION_PHRASES["route"],
            authorized_at=_ts(now),
            expires_at=_ts(now + timedelta(minutes=10)),
        )
    )
    execution = recovery.materialize_reentry_execution_intent(
        seed_intent=seed,
        failure_attestation=failure,
        reentry_creation_authorization=creation_authorization,
        reentry_intent=reentry,
        reentry_dispatch=dispatch,
        reentry_attestation=attestation,
        authorization=execution_authorization,
    )
    forged = copy.deepcopy(execution)
    forged_change_set_arn = forged["execute_request"]["ChangeSetName"].rsplit(
        "/", 1
    )[0] + "/aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
    forged["execute_request"]["ChangeSetName"] = forged_change_set_arn
    forged["execute_operation_digest"] = route.digest_value(
        {
            "record_type": recovery.REENTRY_EXECUTION_INTENT_RECORD_TYPE,
            "source_commit": forged["source_commit"],
            "target": forged["target"],
            "stack_arn": forged["execute_request"]["StackName"],
            "change_set_arn": forged_change_set_arn,
            "attempt": 1,
        }
    )
    forged["execute_request"]["ClientRequestToken"] = (
        "gug376-" + forged["execute_operation_digest"][7:55]
    )
    forged["execute_request_digest"] = route.digest_value(
        forged["execute_request"]
    )
    forged.pop("execution_intent_digest")
    forged = route.seal(forged, "execution_intent_digest")
    timeline: list[str] = []
    provider = recovery.ConnectedDeploymentRecoveryProvider(
        clients=_clients(
            sts=Identity(
                route.MANAGEMENT_ACCOUNT_ID,
                "AWSAdministratorAccess",
                timeline,
            ),
            cfn=EmptyService(),
            trail=EmptyService(),
        ),
        claims=Claims(timeline),
        clock=lambda: now,
    )
    with pytest.raises(
        recovery.DeploymentRecoveryError,
        match="REENTRY_EXECUTION_INTENT_CAUSAL_MISMATCH",
    ):
        provider.execute_reentry_change_set(
            seed_input={},
            seed_intent=seed,
            git=object(),
            failure_attestation=failure,
            reentry_creation_authorization=creation_authorization,
            reentry_intent=reentry,
            reentry_dispatch=dispatch,
            reentry_attestation=attestation,
            execution_authorization=execution_authorization,
            execution_intent=forged,
        )
    assert timeline == []


def test_reentry_execution_rejects_minimal_forged_attestation_before_aws(
    case: tuple[dict[str, Any], dict[str, Any], datetime]
) -> None:
    _source, seed, now = case
    reentry, failure, creation_authorization = _reentry_intent(seed, now)
    dispatch, attestation = _reentry_dispatch_and_attestation(
        seed, reentry, now
    )
    execution_authorization = (
        recovery.materialize_reentry_execution_authorization(
            seed_intent=seed,
            failure_attestation=failure,
            reentry_creation_authorization=creation_authorization,
            reentry_intent=reentry,
            reentry_dispatch=dispatch,
            reentry_attestation=attestation,
            authorization=recovery.REENTRY_EXECUTION_PHRASES["route"],
            authorized_at=_ts(now),
            expires_at=_ts(now + timedelta(minutes=10)),
        )
    )
    execution = recovery.materialize_reentry_execution_intent(
        seed_intent=seed,
        failure_attestation=failure,
        reentry_creation_authorization=creation_authorization,
        reentry_intent=reentry,
        reentry_dispatch=dispatch,
        reentry_attestation=attestation,
        authorization=execution_authorization,
    )
    forged = route.seal(
        {
            "schema_version": 1,
            "record_type": recovery.REENTRY_ATTESTATION_RECORD_TYPE,
            "source_commit": seed["source_commit"],
            "target": "route",
            "reentry_intent_digest": reentry["reentry_intent_digest"],
            "stack_arn": attestation["stack_arn"],
            "change_set_arn": (
                attestation["change_set_arn"].rsplit("/", 1)[0]
                + "/aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
            ),
            "status": "CREATE_COMPLETE",
            "execution_status": "AVAILABLE",
            "attested_at": _ts(now),
        },
        "attestation_digest",
    )
    with pytest.raises(
        recovery.DeploymentRecoveryError,
        match="REENTRY_ATTESTATION_INVALID",
    ):
        recovery.materialize_reentry_execution_authorization(
            seed_intent=seed,
            failure_attestation=failure,
            reentry_creation_authorization=creation_authorization,
            reentry_intent=reentry,
            reentry_dispatch=dispatch,
            reentry_attestation=forged,
            authorization=recovery.REENTRY_EXECUTION_PHRASES["route"],
            authorized_at=_ts(now),
            expires_at=_ts(now + timedelta(minutes=10)),
        )

    timeline: list[str] = []
    provider = recovery.ConnectedDeploymentRecoveryProvider(
        clients=_clients(
            sts=Identity(
                route.MANAGEMENT_ACCOUNT_ID,
                "AWSAdministratorAccess",
                timeline,
            ),
            cfn=EmptyService(),
            trail=EmptyService(),
        ),
        claims=Claims(timeline),
        clock=lambda: now,
    )
    with pytest.raises(
        recovery.DeploymentRecoveryError,
        match="REENTRY_ATTESTATION_INVALID",
    ):
        provider.execute_reentry_change_set(
            seed_input={},
            seed_intent=seed,
            git=object(),
            failure_attestation=failure,
            reentry_creation_authorization=creation_authorization,
            reentry_intent=reentry,
            reentry_dispatch=dispatch,
            reentry_attestation=forged,
            execution_authorization=execution_authorization,
            execution_intent=execution,
        )
    assert timeline == []


def test_connected_reentry_execution_allows_only_one_mutation_per_seed_lane(
    case: tuple[dict[str, Any], dict[str, Any], datetime]
) -> None:
    _source, seed, now = case
    reentry, failure, creation_authorization = _reentry_intent(seed, now)
    dispatch, attestation = _reentry_dispatch_and_attestation(
        seed, reentry, now
    )
    execution_authorization = (
        recovery.materialize_reentry_execution_authorization(
            seed_intent=seed,
            failure_attestation=failure,
            reentry_creation_authorization=creation_authorization,
            reentry_intent=reentry,
            reentry_dispatch=dispatch,
            reentry_attestation=attestation,
            authorization=recovery.REENTRY_EXECUTION_PHRASES["route"],
            authorized_at=_ts(now),
            expires_at=_ts(now + timedelta(minutes=10)),
        )
    )
    execution = recovery.materialize_reentry_execution_intent(
        seed_intent=seed,
        failure_attestation=failure,
        reentry_creation_authorization=creation_authorization,
        reentry_intent=reentry,
        reentry_dispatch=dispatch,
        reentry_attestation=attestation,
        authorization=execution_authorization,
    )

    timeline: list[str] = []
    claims = Claims(timeline)
    _seed_reentry_create_journal(
        claims,
        seed=seed,
        reentry_intent=reentry,
        dispatch=dispatch,
    )
    current = [now]
    cfn = AuthoritativeReentryCloudFormation(
        seed=seed,
        reentry_intent=reentry,
        live_dispatch=dispatch,
    )
    create_event = _create_event(
        request=reentry["create_request"],
        account=route.MANAGEMENT_ACCOUNT_ID,
        role_name="AWSAdministratorAccess",
        stack_arn=dispatch["stack_arn"],
        change_set_arn=dispatch["change_set_arn"],
        request_id=dispatch["create_request_id"],
        event_id=EVENT_UUID,
        when=now,
    )
    provider = recovery.ConnectedDeploymentRecoveryProvider(
        clients=_clients(
            sts=Identity(
                route.MANAGEMENT_ACCOUNT_ID,
                "AWSAdministratorAccess",
                timeline,
            ),
            cfn=cfn,
            trail=Trail(create_event),
        ),
        claims=claims,
        clock=lambda: current[0],
    )
    provider.execute_reentry_change_set(
        seed_input={},
        seed_intent=seed,
        git=object(),
        failure_attestation=failure,
        reentry_creation_authorization=creation_authorization,
        reentry_intent=reentry,
        reentry_dispatch=dispatch,
        reentry_attestation=attestation,
        execution_authorization=execution_authorization,
        execution_intent=execution,
    )
    assert cfn.execute_calls == 1

    second_execution_authorization = (
        recovery.materialize_reentry_execution_authorization(
            seed_intent=seed,
            failure_attestation=failure,
            reentry_creation_authorization=creation_authorization,
            reentry_intent=reentry,
            reentry_dispatch=dispatch,
            reentry_attestation=attestation,
            authorization=recovery.REENTRY_EXECUTION_PHRASES["route"],
            authorized_at=_ts(now + timedelta(seconds=1)),
            expires_at=_ts(now + timedelta(minutes=10, seconds=1)),
        )
    )
    second_execution = recovery.materialize_reentry_execution_intent(
        seed_intent=seed,
        failure_attestation=failure,
        reentry_creation_authorization=creation_authorization,
        reentry_intent=reentry,
        reentry_dispatch=dispatch,
        reentry_attestation=attestation,
        authorization=second_execution_authorization,
    )
    assert (
        second_execution["execution_intent_digest"]
        != execution["execution_intent_digest"]
    )
    assert (
        second_execution["execute_operation_digest"]
        == execution["execute_operation_digest"]
    )
    current[0] = now + timedelta(seconds=1)
    with pytest.raises(
        recovery.DeploymentRecoveryError,
        match="MUTATION_REPLAY_REJECTED",
    ):
        provider.execute_reentry_change_set(
            seed_input={},
            seed_intent=seed,
            git=object(),
            failure_attestation=failure,
            reentry_creation_authorization=creation_authorization,
            reentry_intent=reentry,
            reentry_dispatch=dispatch,
            reentry_attestation=attestation,
            execution_authorization=second_execution_authorization,
            execution_intent=second_execution,
        )
    assert cfn.execute_calls == 1
    assert timeline == [
        "read-result",
        "read-claim",
        "sts",
        "claim",
        "complete",
        "read-result",
        "read-claim",
        "sts",
        "claim",
    ]


def test_connected_reentry_execution_binds_durable_create_result_before_aws(
    case: tuple[dict[str, Any], dict[str, Any], datetime]
) -> None:
    _source, seed, now = case
    reentry, failure, creation_authorization = _reentry_intent(seed, now)
    persisted_dispatch, _persisted_attestation = (
        _reentry_dispatch_and_attestation(seed, reentry, now)
    )
    forged_dispatch, forged_attestation = (
        _reentry_dispatch_and_attestation(
            seed,
            reentry,
            now,
            change_uuid=CHANGE_UUID,
            request_uuid=REQUEST_UUID,
        )
    )
    execution_authorization = (
        recovery.materialize_reentry_execution_authorization(
            seed_intent=seed,
            failure_attestation=failure,
            reentry_creation_authorization=creation_authorization,
            reentry_intent=reentry,
            reentry_dispatch=forged_dispatch,
            reentry_attestation=forged_attestation,
            authorization=recovery.REENTRY_EXECUTION_PHRASES["route"],
            authorized_at=_ts(now),
            expires_at=_ts(now + timedelta(minutes=10)),
        )
    )
    execution = recovery.materialize_reentry_execution_intent(
        seed_intent=seed,
        failure_attestation=failure,
        reentry_creation_authorization=creation_authorization,
        reentry_intent=reentry,
        reentry_dispatch=forged_dispatch,
        reentry_attestation=forged_attestation,
        authorization=execution_authorization,
    )
    timeline: list[str] = []
    claims = Claims(timeline)
    claims.results[
        f"reentry-create:route:{seed['intent_digest']}"
    ] = persisted_dispatch
    provider = recovery.ConnectedDeploymentRecoveryProvider(
        clients=_clients(
            sts=Identity(
                route.MANAGEMENT_ACCOUNT_ID,
                "AWSAdministratorAccess",
                timeline,
            ),
            cfn=EmptyService(),
            trail=EmptyService(),
        ),
        claims=claims,
        clock=lambda: now,
    )
    with pytest.raises(
        recovery.DeploymentRecoveryError,
        match="REENTRY_ATTESTATION_DISPATCH_BINDING_INVALID",
    ):
        provider.execute_reentry_change_set(
            seed_input={},
            seed_intent=seed,
            git=object(),
            failure_attestation=failure,
            reentry_creation_authorization=creation_authorization,
            reentry_intent=reentry,
            reentry_dispatch=forged_dispatch,
            reentry_attestation=forged_attestation,
            execution_authorization=execution_authorization,
            execution_intent=execution,
        )
    assert timeline == ["read-result"]


def test_connected_reentry_execution_rejects_live_alternate_same_name_uuid(
    case: tuple[dict[str, Any], dict[str, Any], datetime]
) -> None:
    _source, seed, now = case
    (
        reentry,
        failure,
        creation_authorization,
        forged_dispatch,
        forged_attestation,
        execution_authorization,
        execution,
    ) = _reentry_execution_chain(
        seed,
        now,
        change_uuid=CHANGE_UUID,
        request_uuid=REQUEST_UUID,
    )
    live_dispatch, _live_attestation = _reentry_dispatch_and_attestation(
        seed,
        reentry,
        now,
    )
    timeline: list[str] = []
    claims = Claims(timeline)
    _seed_reentry_create_journal(
        claims,
        seed=seed,
        reentry_intent=reentry,
        dispatch=forged_dispatch,
    )
    cfn = AuthoritativeReentryCloudFormation(
        seed=seed,
        reentry_intent=reentry,
        live_dispatch=live_dispatch,
    )
    provider = recovery.ConnectedDeploymentRecoveryProvider(
        clients=_clients(
            sts=Identity(
                route.MANAGEMENT_ACCOUNT_ID,
                "AWSAdministratorAccess",
                timeline,
            ),
            cfn=cfn,
            trail=EmptyService(),
        ),
        claims=claims,
        clock=lambda: now,
    )
    with pytest.raises(
        recovery.DeploymentRecoveryError,
        match="REENTRY_CHANGE_SET_READBACK_INVALID",
    ):
        provider.execute_reentry_change_set(
            seed_input={},
            seed_intent=seed,
            git=object(),
            failure_attestation=failure,
            reentry_creation_authorization=creation_authorization,
            reentry_intent=reentry,
            reentry_dispatch=forged_dispatch,
            reentry_attestation=forged_attestation,
            execution_authorization=execution_authorization,
            execution_intent=execution,
        )
    assert timeline == ["read-result", "read-claim", "sts"]
    assert cfn.describe_calls == 1
    assert cfn.template_calls == 0
    assert cfn.execute_calls == 0


def test_connected_reentry_execution_expired_locally_never_calls_sts(
    case: tuple[dict[str, Any], dict[str, Any], datetime]
) -> None:
    _source, seed, now = case
    (
        reentry,
        failure,
        creation_authorization,
        dispatch,
        attestation,
        execution_authorization,
        execution,
    ) = _reentry_execution_chain(seed, now, execution_ttl_seconds=60)
    timeline: list[str] = []
    claims = Claims(timeline)
    _seed_reentry_create_journal(
        claims,
        seed=seed,
        reentry_intent=reentry,
        dispatch=dispatch,
    )
    provider = recovery.ConnectedDeploymentRecoveryProvider(
        clients=_clients(
            sts=Identity(
                route.MANAGEMENT_ACCOUNT_ID,
                "AWSAdministratorAccess",
                timeline,
            ),
            cfn=EmptyService(),
            trail=EmptyService(),
        ),
        claims=claims,
        clock=lambda: now + timedelta(seconds=60),
    )
    with pytest.raises(
        recovery.DeploymentRecoveryError,
        match="REENTRY_EXECUTION_AUTHORIZATION_NOT_ACTIVE",
    ):
        provider.execute_reentry_change_set(
            seed_input={},
            seed_intent=seed,
            git=object(),
            failure_attestation=failure,
            reentry_creation_authorization=creation_authorization,
            reentry_intent=reentry,
            reentry_dispatch=dispatch,
            reentry_attestation=attestation,
            execution_authorization=execution_authorization,
            execution_intent=execution,
        )
    assert timeline == ["read-result", "read-claim"]


def test_connected_reentry_execution_resamples_expiry_before_effect(
    case: tuple[dict[str, Any], dict[str, Any], datetime]
) -> None:
    _source, seed, now = case
    (
        reentry,
        failure,
        creation_authorization,
        dispatch,
        attestation,
        execution_authorization,
        execution,
    ) = _reentry_execution_chain(seed, now, execution_ttl_seconds=60)
    timeline: list[str] = []
    claims = Claims(timeline)
    _seed_reentry_create_journal(
        claims,
        seed=seed,
        reentry_intent=reentry,
        dispatch=dispatch,
    )
    cfn = AuthoritativeReentryCloudFormation(
        seed=seed,
        reentry_intent=reentry,
        live_dispatch=dispatch,
    )
    event = _create_event(
        request=reentry["create_request"],
        account=route.MANAGEMENT_ACCOUNT_ID,
        role_name="AWSAdministratorAccess",
        stack_arn=dispatch["stack_arn"],
        change_set_arn=dispatch["change_set_arn"],
        request_id=dispatch["create_request_id"],
        event_id=EVENT_UUID,
        when=now,
    )
    samples = iter(
        (now, now, now + timedelta(seconds=30), now + timedelta(seconds=60))
    )
    provider = recovery.ConnectedDeploymentRecoveryProvider(
        clients=_clients(
            sts=Identity(
                route.MANAGEMENT_ACCOUNT_ID,
                "AWSAdministratorAccess",
                timeline,
            ),
            cfn=cfn,
            trail=Trail(event),
        ),
        claims=claims,
        clock=lambda: next(samples),
    )
    with pytest.raises(
        recovery.DeploymentRecoveryError,
        match="REENTRY_EXECUTION_AUTHORIZATION_NOT_ACTIVE",
    ):
        provider.execute_reentry_change_set(
            seed_input={},
            seed_intent=seed,
            git=object(),
            failure_attestation=failure,
            reentry_creation_authorization=creation_authorization,
            reentry_intent=reentry,
            reentry_dispatch=dispatch,
            reentry_attestation=attestation,
            execution_authorization=execution_authorization,
            execution_intent=execution,
        )
    assert timeline == ["read-result", "read-claim", "sts"]
    assert cfn.describe_calls == 1
    assert cfn.template_calls == 1
    assert cfn.execute_calls == 0


def test_reentry_execution_authorization_rejects_one_second_grant(
    case: tuple[dict[str, Any], dict[str, Any], datetime]
) -> None:
    _source, seed, now = case
    reentry, failure, creation_authorization = _reentry_intent(seed, now)
    dispatch, attestation = _reentry_dispatch_and_attestation(
        seed, reentry, now
    )
    with pytest.raises(
        recovery.DeploymentRecoveryError,
        match="REENTRY_EXECUTION_AUTHORIZATION_INVALID",
    ):
        recovery.materialize_reentry_execution_authorization(
            seed_intent=seed,
            failure_attestation=failure,
            reentry_creation_authorization=creation_authorization,
            reentry_intent=reentry,
            reentry_dispatch=dispatch,
            reentry_attestation=attestation,
            authorization=recovery.REENTRY_EXECUTION_PHRASES["route"],
            authorized_at=_ts(now),
            expires_at=_ts(now + timedelta(seconds=1)),
        )


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("target", "broker"),
        ("client_request_token", "gug376-" + "0" * 48),
        ("retry_permitted", True),
        ("production_authorized", True),
    ),
)
def test_reentry_execution_claim_rejects_binding_overclaims(
    field: str, value: Any
) -> None:
    now = datetime.now(timezone.utc).replace(microsecond=0)
    token = "gug376-" + "a" * 48
    stack_arn = (
        "arn:aws:cloudformation:us-east-1:839393571433:stack/"
        f"{route.ROUTE_STACK_NAME}/{STACK_UUID}"
    )
    change_set_arn = (
        "arn:aws:cloudformation:us-east-1:839393571433:changeSet/"
        f"{recovery.REENTRY_CHANGE_SET_NAMES['route']}/{RECOVERY_CHANGE_UUID}"
    )
    execution = {
        "record_type": recovery.REENTRY_EXECUTION_INTENT_RECORD_TYPE,
        "target": "route",
        "parent_intent_digest": "sha256:" + "0" * 64,
        "execute_operation_digest": "sha256:" + "1" * 64,
        "execution_intent_digest": "sha256:" + "2" * 64,
        "execute_request_digest": "sha256:" + "3" * 64,
        "execute_request": {
            "StackName": stack_arn,
            "ChangeSetName": change_set_arn,
            "ClientRequestToken": token,
        },
    }
    receipt = {"stack_arn": stack_arn, "change_set_arn": change_set_arn}
    claim = {
        "schema_version": 1,
        "record_type": recovery.CLAIM_RECORD_TYPE,
        "operation": "ExecuteChangeSet",
        "target": "route",
        "attempt": 1,
        "execution_intent_digest": execution["execution_intent_digest"],
        "request_digest": execution["execute_request_digest"],
        "client_request_token": token,
        "stack_arn": stack_arn,
        "change_set_arn": change_set_arn,
        "caller_arn_digest": "sha256:" + "4" * 64,
        "claimed_at": _ts(now),
        "retry_permitted": False,
        "production_authorized": False,
    }
    claim[field] = value
    claims = Claims([])
    key = f"reentry-execute:route:{execution['parent_intent_digest']}"
    claims.records[key] = claim
    with pytest.raises(
        recovery.DeploymentRecoveryError, match="EXECUTION_CLAIM_INVALID"
    ):
        recovery._execution_claim(
            claims, execution=execution, receipt=receipt
        )


def test_public_reentry_execute_event_digest_validates_receipt_claim_and_event(
    case: tuple[dict[str, Any], dict[str, Any], datetime]
) -> None:
    _source, seed, now = case
    intent, failure, creation_authorization = _reentry_intent(seed, now)
    dispatch, attestation = _reentry_dispatch_and_attestation(
        seed, intent, now
    )
    stack_arn = attestation["stack_arn"]
    change_set_arn = attestation["change_set_arn"]
    authorization = recovery.materialize_reentry_execution_authorization(
        seed_intent=seed,
        failure_attestation=failure,
        reentry_creation_authorization=creation_authorization,
        reentry_intent=intent,
        reentry_dispatch=dispatch,
        reentry_attestation=attestation,
        authorization=recovery.REENTRY_EXECUTION_PHRASES["route"],
        authorized_at=_ts(now),
        expires_at=_ts(now + timedelta(minutes=10)),
    )
    execution = recovery.materialize_reentry_execution_intent(
        seed_intent=seed,
        failure_attestation=failure,
        reentry_creation_authorization=creation_authorization,
        reentry_intent=intent,
        reentry_dispatch=dispatch,
        reentry_attestation=attestation,
        authorization=authorization,
    )
    receipt = route.seal(
        {
            "schema_version": 1,
            "record_type": recovery.REENTRY_EXECUTION_RECEIPT_RECORD_TYPE,
            "source_commit": seed["source_commit"],
            "target": "route",
            "account_id": route.MANAGEMENT_ACCOUNT_ID,
            "execution_intent_digest": execution["execution_intent_digest"],
            "stack_arn": stack_arn,
            "change_set_arn": change_set_arn,
            "execute_request_id": RECOVERY_REQUEST_UUID,
            "dispatched_at": _ts(now),
            "attempt": 1,
            "aws_mutations": 1,
            "retry_permitted": False,
            "production_authorized": False,
            "production_status": route.PRODUCTION_STATUS,
        },
        "receipt_digest",
    )
    caller = _caller(route.MANAGEMENT_ACCOUNT_ID, "AWSAdministratorAccess")
    claim = {
        "schema_version": 1,
        "record_type": recovery.CLAIM_RECORD_TYPE,
        "operation": "ExecuteChangeSet",
        "target": "route",
        "attempt": 1,
        "execution_intent_digest": execution["execution_intent_digest"],
        "request_digest": execution["execute_request_digest"],
        "client_request_token": execution["execute_request"][
            "ClientRequestToken"
        ],
        "stack_arn": stack_arn,
        "change_set_arn": change_set_arn,
        "caller_arn_digest": route.digest_value(caller),
        "claimed_at": _ts(now),
        "retry_permitted": False,
        "production_authorized": False,
    }
    claims = Claims([])
    key = f"reentry-execute:route:{seed['intent_digest']}"
    claims.records[key] = claim
    request = execution["execute_request"]
    event = {
        "eventSource": "cloudformation.amazonaws.com",
        "eventName": "ExecuteChangeSet",
        "awsRegion": route.REGION,
        "recipientAccountId": route.MANAGEMENT_ACCOUNT_ID,
        "readOnly": False,
        "errorCode": None,
        "errorMessage": None,
        "requestID": RECOVERY_REQUEST_UUID,
        "eventID": EVENT_UUID,
        "eventTime": _ts(now),
        "userIdentity": {"arn": caller},
        "requestParameters": {
            "stackName": request["StackName"],
            "changeSetName": request["ChangeSetName"],
            "clientRequestToken": request["ClientRequestToken"],
        },
    }
    digest, pages = recovery.reentry_execute_event_digest(
        cloudtrail=Trail(event),
        claims=claims,
        execution_intent=execution,
        execution_receipt=receipt,
        observed_at=now,
    )
    assert digest.startswith("sha256:")
    assert pages == 1

    changed = copy.deepcopy(receipt)
    changed["attempt"] = 2
    changed.pop("receipt_digest")
    changed = route.seal(changed, "receipt_digest")
    with pytest.raises(
        recovery.DeploymentRecoveryError, match="EXECUTION_RECEIPT_INVALID"
    ):
        recovery.reentry_execute_event_digest(
            cloudtrail=Trail(event),
            claims=claims,
            execution_intent=execution,
            execution_receipt=changed,
            observed_at=now,
        )


def test_broker_protection_rollback_binds_execution_and_live_inert_table(
    case: tuple[dict[str, Any], dict[str, Any], datetime],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _source, original_seed, now = case
    seed = copy.deepcopy(original_seed)
    expected_resources = [
        {
            "logical_resource_id": "BrokerLedger",
            "resource_type": "AWS::DynamoDB::Table",
        },
        {
            "logical_resource_id": "BrokerLedgerKey",
            "resource_type": "AWS::KMS::Key",
        },
    ]
    seed["targets"]["broker"]["expected_resources"] = expected_resources
    seed.pop("intent_digest")
    seed = route.seal(seed, "intent_digest")
    stack_arn = (
        "arn:aws:cloudformation:us-east-1:042360977644:stack/"
        f"{route.BROKER_STACK_NAME}/{STACK_UUID}"
    )
    change_set_arn = (
        "arn:aws:cloudformation:us-east-1:042360977644:changeSet/"
        f"{route.BROKER_PROTECTION_CHANGE_SET_NAME}/{CHANGE_UUID}"
    )
    request = {
        "StackName": stack_arn,
        "ChangeSetName": change_set_arn,
        "ClientRequestToken": "gug376-" + "a" * 48,
        "DisableRollback": False,
    }
    execution = route.seal(
        {
            "schema_version": 1,
            "record_type": route.RECORD_TYPE_EXECUTION_INTENT,
            "source_commit": seed["source_commit"],
            "target": route.BROKER_PROTECTION_TARGET,
            "account_id": route.AUTHORITY_ACCOUNT_ID,
            "route_not_before": seed["route_not_before"],
            "route_not_after": seed["route_not_after"],
            "recovery_not_after": seed["recovery_not_after"],
            "parent_intent_digest": seed["intent_digest"],
            "execute_operation_digest": "sha256:" + "1" * 64,
            "execute_request": request,
            "execute_request_digest": route.digest_value(request),
        },
        "execution_intent_digest",
    )
    monkeypatch.setattr(
        route,
        "validate_execution_intent",
        lambda value: json.loads(route.canonical_json(value)),
    )
    receipt = route.seal(
        {
            "schema_version": 1,
            "record_type": connected.EXECUTION_RECEIPT_RECORD_TYPE,
            "source_commit": seed["source_commit"],
            "target": route.BROKER_PROTECTION_TARGET,
            "account_id": route.AUTHORITY_ACCOUNT_ID,
            "execution_intent_digest": execution["execution_intent_digest"],
            "stack_arn": stack_arn,
            "change_set_arn": change_set_arn,
            "execute_request_id": RECOVERY_REQUEST_UUID,
            "dispatched_at": _ts(now),
            "aws_mutations": 1,
            "retry_permitted": False,
            "production_authorized": False,
            "production_status": route.PRODUCTION_STATUS,
        },
        "receipt_digest",
    )
    caller = _caller(
        route.AUTHORITY_ACCOUNT_ID, "ScanalyzeGug376BrokerSeedExec"
    )
    claim = {
        "schema_version": 1,
        "record_type": connected.CLAIM_RECORD_TYPE,
        "operation": "ExecuteChangeSet",
        "target": route.BROKER_PROTECTION_TARGET,
        "execution_intent_digest": execution["execution_intent_digest"],
        "request_digest": execution["execute_request_digest"],
        "client_request_token": request["ClientRequestToken"],
        "stack_arn": stack_arn,
        "change_set_arn": change_set_arn,
        "caller_arn_digest": route.digest_value(caller),
        "claimed_at": _ts(now),
        "retry_permitted": False,
        "production_authorized": False,
    }
    claims = Claims([])
    claims.records[
        "execute:broker-protection:"
        f"{execution['execute_operation_digest']}"
    ] = claim
    claims.results[
        "execute:broker-protection:"
        f"{execution['execute_operation_digest']}"
    ] = receipt
    event = {
        "eventSource": "cloudformation.amazonaws.com",
        "eventName": "ExecuteChangeSet",
        "awsRegion": route.REGION,
        "recipientAccountId": route.AUTHORITY_ACCOUNT_ID,
        "readOnly": False,
        "errorCode": None,
        "errorMessage": None,
        "requestID": RECOVERY_REQUEST_UUID,
        "eventID": EVENT_UUID,
        "eventTime": _ts(now),
        "userIdentity": {"arn": caller},
        "requestParameters": {
            "stackName": stack_arn,
            "changeSetName": change_set_arn,
            "clientRequestToken": request["ClientRequestToken"],
            "disableRollback": False,
        },
    }
    key_id = "00000000-0000-4000-8000-000000000001"

    class RollbackCloudFormation:
        def describe_stacks(self, **request_value: Any) -> dict[str, Any]:
            assert request_value == {"StackName": stack_arn}
            return {
                "Stacks": [
                    {
                        "StackId": stack_arn,
                        "StackName": route.BROKER_STACK_NAME,
                        "StackStatus": "UPDATE_ROLLBACK_COMPLETE",
                    }
                ]
            }

        def list_stack_resources(
            self, **request_value: Any
        ) -> dict[str, Any]:
            assert request_value == {"StackName": stack_arn}
            return {
                "StackResourceSummaries": [
                    {
                        "LogicalResourceId": "BrokerLedger",
                        "PhysicalResourceId": recovery.BROKER_FIXED_TABLE_NAME,
                        "ResourceType": "AWS::DynamoDB::Table",
                        "ResourceStatus": "CREATE_COMPLETE",
                    },
                    {
                        "LogicalResourceId": "BrokerLedgerKey",
                        "PhysicalResourceId": key_id,
                        "ResourceType": "AWS::KMS::Key",
                        "ResourceStatus": "CREATE_COMPLETE",
                    },
                ]
            }

    class Ledger:
        def describe_table(self, **request_value: Any) -> dict[str, Any]:
            assert request_value == {"TableName": recovery.BROKER_FIXED_TABLE_NAME}
            return {
                "Table": {
                    "TableName": recovery.BROKER_FIXED_TABLE_NAME,
                    "TableArn": (
                        "arn:aws:dynamodb:us-east-1:042360977644:table/"
                        f"{recovery.BROKER_FIXED_TABLE_NAME}"
                    ),
                    "TableStatus": "ACTIVE",
                    "DeletionProtectionEnabled": False,
                    "SSEDescription": {
                        "Status": "ENABLED",
                        "SSEType": "KMS",
                        "KMSMasterKeyArn": (
                            "arn:aws:kms:us-east-1:042360977644:key/"
                            f"{key_id}"
                        ),
                    },
                }
            }

    provider = recovery.ConnectedDeploymentRecoveryProvider(
        clients=_clients(
            sts=Identity(
                route.AUTHORITY_ACCOUNT_ID,
                "ScanalyzeGug376BrokerSeedExec",
                [],
            ),
            cfn=RollbackCloudFormation(),
            trail=Trail(event),
            dynamodb=Ledger(),
        ),
        claims=claims,
        clock=lambda: now,
    )
    attestation = provider.attest_protection_rollback(
        seed_intent=seed,
        execution_intent=execution,
        execution_receipt=receipt,
    )
    assert attestation["stack_status"] == "UPDATE_ROLLBACK_COMPLETE"
    assert attestation["ledger_deletion_protection_enabled"] is False
    assert attestation["aws_calls"] == 5
    assert attestation["aws_mutations"] == 0


@pytest.mark.parametrize("attestor", ("failed-create", "protection"))
def test_failure_attestors_reject_execution_from_foreign_seed_before_aws(
    case: tuple[dict[str, Any], dict[str, Any], datetime],
    monkeypatch: pytest.MonkeyPatch,
    attestor: str,
) -> None:
    _source, seed_a, now = case
    target = (
        "route"
        if attestor == "failed-create"
        else route.BROKER_PROTECTION_TARGET
    )
    account = (
        route.MANAGEMENT_ACCOUNT_ID
        if target == "route"
        else route.AUTHORITY_ACCOUNT_ID
    )
    stack_name = (
        route.ROUTE_STACK_NAME
        if target == "route"
        else route.BROKER_STACK_NAME
    )
    change_name = (
        route.ROUTE_CHANGE_SET_NAME
        if target == "route"
        else route.BROKER_PROTECTION_CHANGE_SET_NAME
    )
    stack_arn = (
        f"arn:aws:cloudformation:{route.REGION}:{account}:stack/"
        f"{stack_name}/{STACK_UUID}"
    )
    change_set_arn = (
        f"arn:aws:cloudformation:{route.REGION}:{account}:changeSet/"
        f"{change_name}/{CHANGE_UUID}"
    )
    request: dict[str, Any] = {
        "StackName": stack_arn,
        "ChangeSetName": change_set_arn,
        "ClientRequestToken": "gug376-" + "a" * 48,
    }
    if target == route.BROKER_PROTECTION_TARGET:
        request["DisableRollback"] = False
    execution = route.seal(
        {
            "schema_version": 1,
            "record_type": route.RECORD_TYPE_EXECUTION_INTENT,
            "source_commit": seed_a["source_commit"],
            "target": target,
            "account_id": account,
            "route_not_before": seed_a["route_not_before"],
            "route_not_after": seed_a["route_not_after"],
            "recovery_not_after": seed_a["recovery_not_after"],
            "parent_intent_digest": seed_a["intent_digest"],
            "execute_operation_digest": "sha256:" + "1" * 64,
            "execute_request": request,
            "execute_request_digest": route.digest_value(request),
        },
        "execution_intent_digest",
    )
    monkeypatch.setattr(
        route,
        "validate_execution_intent",
        lambda value: json.loads(route.canonical_json(value)),
    )
    receipt = route.seal(
        {
            "schema_version": 1,
            "record_type": connected.EXECUTION_RECEIPT_RECORD_TYPE,
            "source_commit": seed_a["source_commit"],
            "target": target,
            "account_id": account,
            "execution_intent_digest": execution[
                "execution_intent_digest"
            ],
            "stack_arn": stack_arn,
            "change_set_arn": change_set_arn,
            "execute_request_id": REQUEST_UUID,
            "dispatched_at": _ts(now),
            "aws_mutations": 1,
            "retry_permitted": False,
            "production_authorized": False,
            "production_status": route.PRODUCTION_STATUS,
        },
        "receipt_digest",
    )
    seed_b = copy.deepcopy(seed_a)
    shifted_route_not_after = now + timedelta(hours=2)
    seed_b["route_not_after"] = _ts(shifted_route_not_after)
    seed_b["recovery_not_after"] = _ts(
        shifted_route_not_after + timedelta(hours=24)
    )
    seed_b.pop("intent_digest")
    seed_b = route.seal(seed_b, "intent_digest")
    timeline: list[str] = []
    provider = recovery.ConnectedDeploymentRecoveryProvider(
        clients=_clients(
            sts=Identity(account, "AWSAdministratorAccess", timeline),
            cfn=EmptyService(),
            trail=EmptyService(),
        ),
        claims=Claims(timeline),
        clock=lambda: now,
    )
    with pytest.raises(
        recovery.DeploymentRecoveryError,
        match="EXECUTION_SEED_BINDING_INVALID",
    ):
        if attestor == "failed-create":
            provider.attest_failed_create_stack(
                seed_intent=seed_b,
                execution_intent=execution,
                execution_receipt=receipt,
            )
        else:
            provider.attest_protection_rollback(
                seed_intent=seed_b,
                execution_intent=execution,
                execution_receipt=receipt,
            )
    assert timeline == []


def _failed_stack_attestation(
    intent: Mapping[str, Any], now: datetime, target: str = "route"
) -> dict[str, Any]:
    account = (
        route.MANAGEMENT_ACCOUNT_ID if target == "route" else route.AUTHORITY_ACCOUNT_ID
    )
    stack_name = route.ROUTE_STACK_NAME if target == "route" else route.BROKER_STACK_NAME
    change_name = (
        route.ROUTE_CHANGE_SET_NAME if target == "route" else route.BROKER_CHANGE_SET_NAME
    )
    resources = (
        [
            {
                "logical_resource_id": "ManagementBrokerCreatorRole",
                "physical_resource_id": "ScanalyzeGug376RouteBrokerCreator",
                "resource_type": "AWS::IAM::Role",
                "resource_status": "DELETE_FAILED",
            }
        ]
        if target == "route"
        else [
            {
                "logical_resource_id": "BrokerLedgerKey",
                "physical_resource_id": (
                    "00000000-0000-4000-8000-000000000001"
                ),
                "resource_type": "AWS::KMS::Key",
                "resource_status": "DELETE_FAILED",
            },
            {
                "logical_resource_id": "BrokerCodeSigningConfig",
                "physical_resource_id": (
                    "arn:aws:lambda:us-east-1:042360977644:"
                    "code-signing-config:csc-0123456789abcdef0"
                ),
                "resource_type": "AWS::Lambda::CodeSigningConfig",
                "resource_status": "DELETE_FAILED",
            },
        ]
    )
    return route.seal(
        {
            "schema_version": 1,
            "record_type": recovery.FAILED_CREATE_STACK_RECORD_TYPE,
            "source_commit": intent["source_commit"],
            "target": target,
            "intent_digest": intent["intent_digest"],
            "execution_intent_digest": "sha256:" + "1" * 64,
            "execution_receipt_digest": "sha256:" + "2" * 64,
            "execution_claim_digest": "sha256:" + "3" * 64,
            "execute_cloudtrail_event_digest": "sha256:" + "4" * 64,
            "account_id": account,
            "stack_arn": (
                f"arn:aws:cloudformation:us-east-1:{account}:stack/"
                f"{stack_name}/{STACK_UUID}"
            ),
            "change_set_arn": (
                f"arn:aws:cloudformation:us-east-1:{account}:changeSet/"
                f"{change_name}/{CHANGE_UUID}"
            ),
            "execute_request_id": REQUEST_UUID,
            "stack_status": "DELETE_FAILED",
            "resource_count": len(resources),
            "resources": resources,
            "resources_digest": route.digest_value(resources),
            "attested_at": _ts(now),
            "aws_calls": 4,
            "aws_mutations": 0,
            "retry_permitted": False,
            "production_authorized": False,
            "production_status": route.PRODUCTION_STATUS,
        },
        "attestation_digest",
    )


def _seed_failed_execution_journal(
    claims: Claims,
    *,
    seed: Mapping[str, Any],
    failed_stack_attestation: Mapping[str, Any],
    now: datetime,
) -> dict[str, Any]:
    failed = copy.deepcopy(failed_stack_attestation)
    target = str(failed["target"])
    account = str(failed["account_id"])
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
    client_token = "gug376-" + operation_digest[7:55]
    execute_request = {
        "stackName": failed["stack_arn"],
        "changeSetName": failed["change_set_arn"],
        "clientRequestToken": client_token,
    }
    claim = {
        "schema_version": 1,
        "record_type": connected.CLAIM_RECORD_TYPE,
        "operation": "ExecuteChangeSet",
        "target": target,
        "execution_intent_digest": failed["execution_intent_digest"],
        "request_digest": route.digest_value(
            {
                "StackName": failed["stack_arn"],
                "ChangeSetName": failed["change_set_arn"],
                "ClientRequestToken": client_token,
            }
        ),
        "client_request_token": client_token,
        "stack_arn": failed["stack_arn"],
        "change_set_arn": failed["change_set_arn"],
        "caller_arn_digest": route.digest_value(
            _caller(account, "AWSAdministratorAccess")
        ),
        "claimed_at": _ts(now),
        "retry_permitted": False,
        "production_authorized": False,
    }
    receipt = route.seal(
        {
            "schema_version": 1,
            "record_type": connected.EXECUTION_RECEIPT_RECORD_TYPE,
            "source_commit": seed["source_commit"],
            "target": target,
            "account_id": account,
            "execution_intent_digest": failed["execution_intent_digest"],
            "stack_arn": failed["stack_arn"],
            "change_set_arn": failed["change_set_arn"],
            "execute_request_id": failed["execute_request_id"],
            "dispatched_at": _ts(now),
            "aws_mutations": 1,
            "retry_permitted": False,
            "production_authorized": False,
            "production_status": route.PRODUCTION_STATUS,
        },
        "receipt_digest",
    )
    claims.records[key] = claim
    claims.results[key] = receipt
    failed["execution_receipt_digest"] = receipt["receipt_digest"]
    failed["execution_claim_digest"] = route.digest_value(claim)
    failed["execute_cloudtrail_event_digest"] = route.digest_value(
        {
            "event_id": EVENT_UUID,
            "event_time": _ts(now),
            "request_id": failed["execute_request_id"],
            "request_digest": route.digest_value(execute_request),
        }
    )
    failed.pop("attestation_digest")
    return route.seal(failed, "attestation_digest")


def _failed_execution_event(
    failed_stack_attestation: Mapping[str, Any],
    now: datetime,
) -> dict[str, Any]:
    failed = failed_stack_attestation
    target = str(failed["target"])
    account = str(failed["account_id"])
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
    return {
        "eventSource": "cloudformation.amazonaws.com",
        "eventName": "ExecuteChangeSet",
        "awsRegion": route.REGION,
        "recipientAccountId": account,
        "readOnly": False,
        "errorCode": None,
        "errorMessage": None,
        "requestID": failed["execute_request_id"],
        "eventID": EVENT_UUID,
        "eventTime": _ts(now),
        "userIdentity": {
            "arn": _caller(account, "AWSAdministratorAccess")
        },
        "requestParameters": {
            "stackName": failed["stack_arn"],
            "changeSetName": failed["change_set_arn"],
            "clientRequestToken": "gug376-" + operation_digest[7:55],
        },
    }


class NoEventsTrail:
    def __init__(self) -> None:
        self.requests: list[dict[str, Any]] = []

    def lookup_events(self, **request: Any) -> dict[str, Any]:
        self.requests.append(request)
        return {"Events": []}


class CleanupPredeleteCloudFormation:
    def __init__(
        self,
        failed_stack_attestation: Mapping[str, Any],
        *,
        stack_status: str | None = None,
        resources: list[dict[str, Any]] | None = None,
    ) -> None:
        self.failed = failed_stack_attestation
        self.stack_status = stack_status or str(
            failed_stack_attestation["stack_status"]
        )
        self.resources = copy.deepcopy(
            resources
            if resources is not None
            else failed_stack_attestation["resources"]
        )
        self.describe_calls = 0
        self.resource_calls = 0
        self.delete_calls = 0

    def describe_stacks(self, **request: Any) -> dict[str, Any]:
        self.describe_calls += 1
        assert request == {"StackName": self.failed["stack_arn"]}
        return {
            "Stacks": [
                {
                    "StackId": self.failed["stack_arn"],
                    "StackName": (
                        route.ROUTE_STACK_NAME
                        if self.failed["target"] == "route"
                        else route.BROKER_STACK_NAME
                    ),
                    "StackStatus": self.stack_status,
                }
            ]
        }

    def list_stack_resources(self, **request: Any) -> dict[str, Any]:
        self.resource_calls += 1
        assert request == {"StackName": self.failed["stack_arn"]}
        return {
            "StackResourceSummaries": [
                {
                    "LogicalResourceId": item["logical_resource_id"],
                    "PhysicalResourceId": item["physical_resource_id"],
                    "ResourceType": item["resource_type"],
                    "ResourceStatus": item["resource_status"],
                }
                for item in self.resources
            ]
        }

    def delete_stack(self, **_request: Any) -> dict[str, Any]:
        self.delete_calls += 1
        raise AssertionError("DeleteStack must not be called")


def _cleanup_chain(
    seed: Mapping[str, Any],
    now: datetime,
    *,
    authorization_ttl_seconds: int = 600,
) -> tuple[
    list[str],
    Claims,
    dict[str, Any],
    dict[str, Any],
    dict[str, Any],
]:
    timeline: list[str] = []
    claims = Claims(timeline)
    failed = _seed_failed_execution_journal(
        claims,
        seed=seed,
        failed_stack_attestation=_failed_stack_attestation(seed, now),
        now=now,
    )
    authorization = recovery.materialize_cleanup_authorization(
        seed_intent=seed,
        failed_stack_attestation=failed,
        authorization=recovery.CLEANUP_AUTHORIZATION_PHRASES["route"],
        authorized_at=_ts(now),
        expires_at=_ts(
            now + timedelta(seconds=authorization_ttl_seconds)
        ),
    )
    intent = recovery.materialize_cleanup_intent(
        seed_intent=seed,
        failed_stack_attestation=failed,
        authorization=authorization,
    )
    return timeline, claims, failed, authorization, intent


def test_cleanup_authorization_extends_to_recovery_horizon_but_not_beyond(
    case: tuple[dict[str, Any], dict[str, Any], datetime]
) -> None:
    _source, intent, now = case
    failed = _failed_stack_attestation(intent, now)
    normal_cutoff = datetime.fromisoformat(
        intent["route_not_after"].replace("Z", "+00:00")
    ) - timedelta(seconds=route.MUTATION_COMPLETION_RESERVE_SECONDS)
    authorized_at = normal_cutoff + timedelta(minutes=5)
    authorization = recovery.materialize_cleanup_authorization(
        seed_intent=intent,
        failed_stack_attestation=failed,
        authorization=recovery.CLEANUP_AUTHORIZATION_PHRASES["route"],
        authorized_at=_ts(authorized_at),
        expires_at=_ts(authorized_at + timedelta(minutes=10)),
    )
    cleanup = recovery.materialize_cleanup_intent(
        seed_intent=intent,
        failed_stack_attestation=failed,
        authorization=authorization,
    )
    assert recovery.validate_cleanup_intent(
        cleanup,
        seed_intent=intent,
        failed_stack_attestation=failed,
        authorization=authorization,
    ) == cleanup
    assert set(cleanup["delete_request"]) == {
        "StackName",
        "ClientRequestToken",
    }
    assert "RoleARN" not in cleanup["delete_request"]
    assert "RetainResources" not in cleanup["delete_request"]
    recovery_not_after = datetime.fromisoformat(
        intent["recovery_not_after"].replace("Z", "+00:00")
    )
    with pytest.raises(
        recovery.DeploymentRecoveryError, match="CLEANUP_AUTHORIZATION_INVALID"
    ):
        recovery.materialize_cleanup_authorization(
            seed_intent=intent,
            failed_stack_attestation=failed,
            authorization=recovery.CLEANUP_AUTHORIZATION_PHRASES["route"],
            authorized_at=_ts(recovery_not_after - timedelta(seconds=60)),
            expires_at=_ts(recovery_not_after + timedelta(seconds=1)),
        )


def test_cleanup_mutation_window_is_recovery_horizon_exclusive(
    case: tuple[dict[str, Any], dict[str, Any], datetime]
) -> None:
    _source, intent, _now = case
    recovery_not_after = datetime.fromisoformat(
        intent["recovery_not_after"].replace("Z", "+00:00")
    )
    assert recovery._cleanup_window(
        intent, lambda: recovery_not_after - timedelta(seconds=1)
    ) == recovery_not_after - timedelta(seconds=1)
    with pytest.raises(
        recovery.DeploymentRecoveryError, match="RECOVERY_WINDOW_CLOSED"
    ):
        recovery._cleanup_window(intent, lambda: recovery_not_after)


def test_cleanup_validator_rejects_resealed_token_replay_bypass(
    case: tuple[dict[str, Any], dict[str, Any], datetime]
) -> None:
    _source, seed, now = case
    failed = _failed_stack_attestation(seed, now)
    authorization = recovery.materialize_cleanup_authorization(
        seed_intent=seed,
        failed_stack_attestation=failed,
        authorization=recovery.CLEANUP_AUTHORIZATION_PHRASES["route"],
        authorized_at=_ts(now),
        expires_at=_ts(now + timedelta(minutes=10)),
    )
    intent = recovery.materialize_cleanup_intent(
        seed_intent=seed,
        failed_stack_attestation=failed,
        authorization=authorization,
    )
    changed = copy.deepcopy(intent)
    changed["delete_request"]["ClientRequestToken"] = "gug376-" + "e" * 48
    changed["delete_request_digest"] = route.digest_value(
        changed["delete_request"]
    )
    changed.pop("cleanup_intent_digest")
    changed = route.seal(changed, "cleanup_intent_digest")
    with pytest.raises(
        recovery.DeploymentRecoveryError, match="CLEANUP_INTENT_INVALID"
    ):
        recovery.validate_cleanup_intent(
            changed,
            seed_intent=seed,
            failed_stack_attestation=failed,
            authorization=authorization,
        )


def test_cleanup_claims_before_exact_delete_and_rejects_replay(
    case: tuple[dict[str, Any], dict[str, Any], datetime]
) -> None:
    _source, seed, now = case
    timeline: list[str] = []
    claims = Claims(timeline)
    failed = _failed_stack_attestation(seed, now)
    failed = _seed_failed_execution_journal(
        claims,
        seed=seed,
        failed_stack_attestation=failed,
        now=now,
    )
    authorization = recovery.materialize_cleanup_authorization(
        seed_intent=seed,
        failed_stack_attestation=failed,
        authorization=recovery.CLEANUP_AUTHORIZATION_PHRASES["route"],
        authorized_at=_ts(now),
        expires_at=_ts(now + timedelta(minutes=10)),
    )
    intent = recovery.materialize_cleanup_intent(
        seed_intent=seed,
        failed_stack_attestation=failed,
        authorization=authorization,
    )

    class DeleteCloudFormation:
        def __init__(self) -> None:
            self.calls = 0

        def describe_stacks(self, **request: Any) -> dict[str, Any]:
            assert request == {"StackName": failed["stack_arn"]}
            return {
                "Stacks": [
                    {
                        "StackId": failed["stack_arn"],
                        "StackName": route.ROUTE_STACK_NAME,
                        "StackStatus": failed["stack_status"],
                    }
                ]
            }

        def list_stack_resources(self, **request: Any) -> dict[str, Any]:
            assert request == {"StackName": failed["stack_arn"]}
            return {
                "StackResourceSummaries": [
                    {
                        "LogicalResourceId": item[
                            "logical_resource_id"
                        ],
                        "PhysicalResourceId": item[
                            "physical_resource_id"
                        ],
                        "ResourceType": item["resource_type"],
                        "ResourceStatus": item["resource_status"],
                    }
                    for item in failed["resources"]
                ]
            }

        def delete_stack(self, **request: Any) -> dict[str, Any]:
            self.calls += 1
            assert request == intent["delete_request"]
            assert set(request) == {"StackName", "ClientRequestToken"}
            return {"ResponseMetadata": {"RequestId": RECOVERY_REQUEST_UUID}}

    current = [now]
    cfn = DeleteCloudFormation()
    provider = recovery.ConnectedDeploymentRecoveryProvider(
        clients=_clients(
            sts=Identity(
                route.MANAGEMENT_ACCOUNT_ID,
                recovery.CLEANUP_ROLE_NAMES["route"],
                timeline,
            ),
            cfn=cfn,
            trail=Trail(_failed_execution_event(failed, now)),
        ),
        claims=claims,
        clock=lambda: current[0],
    )
    receipt = provider.delete_failed_stack(
        seed_input={},
        seed_intent=seed,
        git=object(),
        failed_stack_attestation=failed,
        authorization=authorization,
        cleanup_intent=intent,
    )
    assert receipt["attempt"] == 1
    assert receipt["aws_mutations"] == 1
    assert cfn.calls == 1
    claim_key = f"cleanup:route:{seed['intent_digest']}:primary"
    durable_claim = claims.records[claim_key]
    durable_dispatch = claims.results[claim_key]
    assert durable_claim["failed_stack_attestation_digest"] == failed[
        "attestation_digest"
    ]
    assert durable_claim["failed_resources_digest"] == failed[
        "resources_digest"
    ]
    assert durable_dispatch == receipt
    assert durable_dispatch["failed_stack_attestation_digest"] == failed[
        "attestation_digest"
    ]
    assert durable_dispatch["failed_resources_digest"] == failed[
        "resources_digest"
    ]
    assert timeline == [
        "read-result",
        "read-claim",
        "sts",
        "claim",
        "complete",
    ]
    changed_claim = copy.deepcopy(claims.records[claim_key])
    changed_claim["production_authorized"] = True
    with pytest.raises(
        recovery.DeploymentRecoveryError, match="CLEANUP_CLAIM_INVALID"
    ):
        recovery._validate_cleanup_claim(
            changed_claim, intent=intent, dispatch=receipt
        )
    second_failed = copy.deepcopy(failed)
    second_failed["attested_at"] = _ts(now + timedelta(seconds=1))
    second_failed.pop("attestation_digest")
    second_failed = route.seal(second_failed, "attestation_digest")
    second_authorization = recovery.materialize_cleanup_authorization(
        seed_intent=seed,
        failed_stack_attestation=second_failed,
        authorization=recovery.CLEANUP_AUTHORIZATION_PHRASES["route"],
        authorized_at=_ts(now + timedelta(seconds=1)),
        expires_at=_ts(now + timedelta(minutes=10, seconds=1)),
    )
    second_intent = recovery.materialize_cleanup_intent(
        seed_intent=seed,
        failed_stack_attestation=second_failed,
        authorization=second_authorization,
    )
    assert second_intent["cleanup_intent_digest"] != intent[
        "cleanup_intent_digest"
    ]
    current[0] = now + timedelta(seconds=1)
    with pytest.raises(
        recovery.DeploymentRecoveryError, match="MUTATION_REPLAY_REJECTED"
    ):
        provider.delete_failed_stack(
            seed_input={},
            seed_intent=seed,
            git=object(),
            failed_stack_attestation=second_failed,
            authorization=second_authorization,
            cleanup_intent=second_intent,
        )
    assert cfn.calls == 1


def test_reentry_cleanup_uses_distinct_lane_after_primary_cleanup(
    case: tuple[dict[str, Any], dict[str, Any], datetime]
) -> None:
    _source, seed, now = case
    timeline: list[str] = []
    claims = Claims(timeline)
    failed = copy.deepcopy(_failed_stack_attestation(seed, now))
    stack_uuid = "99999999-9999-4999-8999-999999999999"
    change_uuid = "88888888-8888-4888-8888-888888888888"
    failed["stack_arn"] = (
        f"arn:aws:cloudformation:{route.REGION}:"
        f"{route.MANAGEMENT_ACCOUNT_ID}:stack/"
        f"{route.ROUTE_STACK_NAME}/{stack_uuid}"
    )
    failed["change_set_arn"] = (
        f"arn:aws:cloudformation:{route.REGION}:"
        f"{route.MANAGEMENT_ACCOUNT_ID}:changeSet/"
        f"{recovery.REENTRY_CHANGE_SET_NAMES['route']}/{change_uuid}"
    )
    failed["execute_request_id"] = RECOVERY_REQUEST_UUID
    failed["execution_intent_digest"] = "sha256:" + "7" * 64
    client_token = "gug376-" + "d" * 48
    execute_request = {
        "StackName": failed["stack_arn"],
        "ChangeSetName": failed["change_set_arn"],
        "ClientRequestToken": client_token,
    }
    execution_key = f"reentry-execute:route:{seed['intent_digest']}"
    execution_claim = {
        "schema_version": 1,
        "record_type": recovery.CLAIM_RECORD_TYPE,
        "operation": "ExecuteChangeSet",
        "target": "route",
        "attempt": 1,
        "execution_intent_digest": failed[
            "execution_intent_digest"
        ],
        "request_digest": route.digest_value(execute_request),
        "client_request_token": client_token,
        "stack_arn": failed["stack_arn"],
        "change_set_arn": failed["change_set_arn"],
        "caller_arn_digest": route.digest_value(
            _caller(route.MANAGEMENT_ACCOUNT_ID, "AWSAdministratorAccess")
        ),
        "claimed_at": _ts(now),
        "retry_permitted": False,
        "production_authorized": False,
    }
    execution_receipt = route.seal(
        {
            "schema_version": 1,
            "record_type": recovery.REENTRY_EXECUTION_RECEIPT_RECORD_TYPE,
            "source_commit": seed["source_commit"],
            "target": "route",
            "account_id": route.MANAGEMENT_ACCOUNT_ID,
            "execution_intent_digest": failed[
                "execution_intent_digest"
            ],
            "stack_arn": failed["stack_arn"],
            "change_set_arn": failed["change_set_arn"],
            "execute_request_id": failed["execute_request_id"],
            "dispatched_at": _ts(now),
            "attempt": 1,
            "aws_mutations": 1,
            "retry_permitted": False,
            "production_authorized": False,
            "production_status": route.PRODUCTION_STATUS,
        },
        "receipt_digest",
    )
    claims.records[execution_key] = execution_claim
    claims.results[execution_key] = execution_receipt
    event_id = "55555555-5555-4555-8555-555555555555"
    failed["execution_receipt_digest"] = execution_receipt[
        "receipt_digest"
    ]
    failed["execution_claim_digest"] = route.digest_value(
        execution_claim
    )
    expected_event = {
        "event_id": event_id,
        "event_time": _ts(now),
        "request_id": failed["execute_request_id"],
        "request_digest": route.digest_value(
            {
                "stackName": execute_request["StackName"],
                "changeSetName": execute_request["ChangeSetName"],
                "clientRequestToken": execute_request[
                    "ClientRequestToken"
                ],
            }
        ),
    }
    failed["execute_cloudtrail_event_digest"] = route.digest_value(
        expected_event
    )
    failed.pop("attestation_digest")
    failed = route.seal(failed, "attestation_digest")
    authorization = recovery.materialize_cleanup_authorization(
        seed_intent=seed,
        failed_stack_attestation=failed,
        authorization=recovery.CLEANUP_AUTHORIZATION_PHRASES["route"],
        authorized_at=_ts(now),
        expires_at=_ts(now + timedelta(minutes=10)),
    )
    intent = recovery.materialize_cleanup_intent(
        seed_intent=seed,
        failed_stack_attestation=failed,
        authorization=authorization,
    )
    assert intent["execution_lane"] == "reentry"
    primary_cleanup_key = (
        f"cleanup:route:{seed['intent_digest']}:primary"
    )
    reentry_cleanup_key = (
        f"cleanup:route:{seed['intent_digest']}:reentry"
    )
    claims.seen.add(primary_cleanup_key)

    class DeleteReentryCloudFormation:
        def __init__(self) -> None:
            self.calls = 0

        def describe_stacks(self, **request: Any) -> dict[str, Any]:
            assert request == {"StackName": failed["stack_arn"]}
            return {
                "Stacks": [
                    {
                        "StackId": failed["stack_arn"],
                        "StackName": route.ROUTE_STACK_NAME,
                        "StackStatus": failed["stack_status"],
                    }
                ]
            }

        def list_stack_resources(self, **request: Any) -> dict[str, Any]:
            assert request == {"StackName": failed["stack_arn"]}
            return {
                "StackResourceSummaries": [
                    {
                        "LogicalResourceId": item[
                            "logical_resource_id"
                        ],
                        "PhysicalResourceId": item[
                            "physical_resource_id"
                        ],
                        "ResourceType": item["resource_type"],
                        "ResourceStatus": item["resource_status"],
                    }
                    for item in failed["resources"]
                ]
            }

        def delete_stack(self, **request: Any) -> dict[str, Any]:
            self.calls += 1
            assert request == intent["delete_request"]
            return {
                "ResponseMetadata": {
                    "RequestId": "66666666-6666-4666-8666-666666666666"
                }
            }

    event = {
        "eventSource": "cloudformation.amazonaws.com",
        "eventName": "ExecuteChangeSet",
        "awsRegion": route.REGION,
        "recipientAccountId": route.MANAGEMENT_ACCOUNT_ID,
        "readOnly": False,
        "errorCode": None,
        "errorMessage": None,
        "requestID": failed["execute_request_id"],
        "eventID": event_id,
        "eventTime": _ts(now),
        "userIdentity": {
            "arn": _caller(
                route.MANAGEMENT_ACCOUNT_ID,
                "AWSAdministratorAccess",
            )
        },
        "requestParameters": {
            "stackName": execute_request["StackName"],
            "changeSetName": execute_request["ChangeSetName"],
            "clientRequestToken": execute_request[
                "ClientRequestToken"
            ],
        },
    }
    cfn = DeleteReentryCloudFormation()
    provider = recovery.ConnectedDeploymentRecoveryProvider(
        clients=_clients(
            sts=Identity(
                route.MANAGEMENT_ACCOUNT_ID,
                recovery.CLEANUP_ROLE_NAMES["route"],
                timeline,
            ),
            cfn=cfn,
            trail=Trail(event),
        ),
        claims=claims,
        clock=lambda: now,
    )
    receipt = provider.delete_failed_stack(
        seed_input={},
        seed_intent=seed,
        git=object(),
        failed_stack_attestation=failed,
        authorization=authorization,
        cleanup_intent=intent,
    )
    assert receipt["execution_lane"] == "reentry"
    assert cfn.calls == 1
    assert primary_cleanup_key in claims.seen
    assert reentry_cleanup_key in claims.seen


@pytest.mark.parametrize(
    ("event_mode", "expected_error"),
    (
        ("absent", "EXECUTE_CLOUDTRAIL_MISSING"),
        (
            "different-event-id",
            "FAILED_EXECUTION_CLOUDTRAIL_BINDING_INVALID",
        ),
    ),
)
def test_cleanup_revalidates_execute_event_before_stack_or_delete(
    case: tuple[dict[str, Any], dict[str, Any], datetime],
    event_mode: str,
    expected_error: str,
) -> None:
    _source, seed, now = case
    timeline, claims, failed, authorization, intent = _cleanup_chain(
        seed, now
    )
    event = _failed_execution_event(failed, now)
    if event_mode == "different-event-id":
        event["eventID"] = "55555555-5555-4555-8555-555555555555"
    trail = NoEventsTrail() if event_mode == "absent" else Trail(event)
    cfn = CleanupPredeleteCloudFormation(failed)
    provider = recovery.ConnectedDeploymentRecoveryProvider(
        clients=_clients(
            sts=Identity(
                route.MANAGEMENT_ACCOUNT_ID,
                recovery.CLEANUP_ROLE_NAMES["route"],
                timeline,
            ),
            cfn=cfn,
            trail=trail,
        ),
        claims=claims,
        clock=lambda: now,
    )
    with pytest.raises(recovery.DeploymentRecoveryError, match=expected_error):
        provider.delete_failed_stack(
            seed_input={},
            seed_intent=seed,
            git=object(),
            failed_stack_attestation=failed,
            authorization=authorization,
            cleanup_intent=intent,
        )
    assert timeline == ["read-result", "read-claim", "sts"]
    assert cfn.describe_calls == 0
    assert cfn.resource_calls == 0
    assert cfn.delete_calls == 0


@pytest.mark.parametrize("drift", ("status", "resources"))
def test_cleanup_rejects_changed_failed_stack_before_delete(
    case: tuple[dict[str, Any], dict[str, Any], datetime],
    drift: str,
) -> None:
    _source, seed, now = case
    timeline, claims, failed, authorization, intent = _cleanup_chain(
        seed, now
    )
    resources = copy.deepcopy(failed["resources"])
    if drift == "resources":
        resources[0]["resource_status"] = "DELETE_COMPLETE"
    cfn = CleanupPredeleteCloudFormation(
        failed,
        stack_status=(
            "ROLLBACK_COMPLETE"
            if drift == "status"
            else failed["stack_status"]
        ),
        resources=resources,
    )
    provider = recovery.ConnectedDeploymentRecoveryProvider(
        clients=_clients(
            sts=Identity(
                route.MANAGEMENT_ACCOUNT_ID,
                recovery.CLEANUP_ROLE_NAMES["route"],
                timeline,
            ),
            cfn=cfn,
            trail=Trail(_failed_execution_event(failed, now)),
        ),
        claims=claims,
        clock=lambda: now,
    )
    with pytest.raises(
        recovery.DeploymentRecoveryError,
        match="FAILED_STACK_STATE_CHANGED",
    ):
        provider.delete_failed_stack(
            seed_input={},
            seed_intent=seed,
            git=object(),
            failed_stack_attestation=failed,
            authorization=authorization,
            cleanup_intent=intent,
        )
    assert timeline == ["read-result", "read-claim", "sts"]
    assert cfn.describe_calls == 1
    assert cfn.resource_calls == 1
    assert cfn.delete_calls == 0


def test_cleanup_expired_locally_never_calls_sts(
    case: tuple[dict[str, Any], dict[str, Any], datetime]
) -> None:
    _source, seed, now = case
    timeline, claims, failed, authorization, intent = _cleanup_chain(
        seed, now, authorization_ttl_seconds=60
    )
    provider = recovery.ConnectedDeploymentRecoveryProvider(
        clients=_clients(
            sts=Identity(
                route.MANAGEMENT_ACCOUNT_ID,
                recovery.CLEANUP_ROLE_NAMES["route"],
                timeline,
            ),
            cfn=EmptyService(),
            trail=EmptyService(),
        ),
        claims=claims,
        clock=lambda: now + timedelta(seconds=60),
    )
    with pytest.raises(
        recovery.DeploymentRecoveryError,
        match="CLEANUP_AUTHORIZATION_NOT_ACTIVE",
    ):
        provider.delete_failed_stack(
            seed_input={},
            seed_intent=seed,
            git=object(),
            failed_stack_attestation=failed,
            authorization=authorization,
            cleanup_intent=intent,
        )
    assert timeline == ["read-result", "read-claim"]


def test_cleanup_resamples_expiry_immediately_before_delete(
    case: tuple[dict[str, Any], dict[str, Any], datetime]
) -> None:
    _source, seed, now = case
    timeline, claims, failed, authorization, intent = _cleanup_chain(
        seed, now, authorization_ttl_seconds=60
    )
    cfn = CleanupPredeleteCloudFormation(failed)
    samples = iter(
        (now, now, now + timedelta(seconds=30), now + timedelta(seconds=60))
    )
    provider = recovery.ConnectedDeploymentRecoveryProvider(
        clients=_clients(
            sts=Identity(
                route.MANAGEMENT_ACCOUNT_ID,
                recovery.CLEANUP_ROLE_NAMES["route"],
                timeline,
            ),
            cfn=cfn,
            trail=Trail(_failed_execution_event(failed, now)),
        ),
        claims=claims,
        clock=lambda: next(samples),
    )
    with pytest.raises(
        recovery.DeploymentRecoveryError,
        match="CLEANUP_AUTHORIZATION_NOT_ACTIVE",
    ):
        provider.delete_failed_stack(
            seed_input={},
            seed_intent=seed,
            git=object(),
            failed_stack_attestation=failed,
            authorization=authorization,
            cleanup_intent=intent,
        )
    assert timeline == ["read-result", "read-claim", "sts"]
    assert cfn.describe_calls == 1
    assert cfn.resource_calls == 1
    assert cfn.delete_calls == 0


def test_cleanup_rejects_resealed_foreign_horizon_before_aws(
    case: tuple[dict[str, Any], dict[str, Any], datetime]
) -> None:
    _source, seed, now = case
    failed = _failed_stack_attestation(seed, now)
    authorization = recovery.materialize_cleanup_authorization(
        seed_intent=seed,
        failed_stack_attestation=failed,
        authorization=recovery.CLEANUP_AUTHORIZATION_PHRASES["route"],
        authorized_at=_ts(now),
        expires_at=_ts(now + timedelta(minutes=10)),
    )
    intent = recovery.materialize_cleanup_intent(
        seed_intent=seed,
        failed_stack_attestation=failed,
        authorization=authorization,
    )
    forged = copy.deepcopy(intent)
    forged["route_not_after"] = _ts(
        datetime.fromisoformat(seed["route_not_after"].replace("Z", "+00:00"))
        + timedelta(days=30)
    )
    forged["recovery_not_after"] = _ts(
        datetime.fromisoformat(forged["route_not_after"].replace("Z", "+00:00"))
        + timedelta(hours=24)
    )
    forged.pop("cleanup_intent_digest")
    forged = route.seal(forged, "cleanup_intent_digest")
    timeline: list[str] = []
    provider = recovery.ConnectedDeploymentRecoveryProvider(
        clients=_clients(
            sts=Identity(
                route.MANAGEMENT_ACCOUNT_ID,
                recovery.CLEANUP_ROLE_NAMES["route"],
                timeline,
            ),
            cfn=EmptyService(),
            trail=EmptyService(),
        ),
        claims=Claims(timeline),
        clock=lambda: now,
    )
    with pytest.raises(
        recovery.DeploymentRecoveryError,
        match="CLEANUP_INTENT_CAUSAL_MISMATCH",
    ):
        provider.delete_failed_stack(
            seed_input={},
            seed_intent=seed,
            git=object(),
            failed_stack_attestation=failed,
            authorization=authorization,
            cleanup_intent=forged,
        )
    assert timeline == []


@pytest.mark.parametrize(
    "command",
    (
        "authorize-reentry-execution",
        "materialize-reentry-execution",
        "execute-reentry",
    ),
)
def test_reentry_execution_cli_requires_causal_dispatch_argument(
    command: str,
) -> None:
    result = subprocess.run(
        [sys.executable, str(RECOVERY_CLI), command, "--help"],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    assert "--reentry-dispatch-name" in result.stdout


def test_connected_cli_rejects_forged_seed_before_provider_creation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    spec = importlib.util.spec_from_file_location(
        "gug376_recovery_cli_test",
        RECOVERY_CLI,
    )
    assert spec is not None and spec.loader is not None
    cli = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(cli)

    tmp_path.chmod(0o700)
    now = datetime.now(timezone.utc).replace(microsecond=0)
    forged_seed = _seed_intent(now)
    forged_seed["targets"]["route"]["create_request"]["TemplateURL"] = (
        "https://attacker.example.invalid/forged-template.yaml"
    )
    forged_seed["targets"]["route"]["create_request_digest"] = (
        route.digest_value(
            forged_seed["targets"]["route"]["create_request"]
        )
    )
    forged_seed.pop("intent_digest")
    forged_seed = route.seal(forged_seed, "intent_digest")

    def write_private(name: str, value: Mapping[str, Any]) -> None:
        path = tmp_path / name
        path.write_text(route.canonical_json(value) + "\n", encoding="utf-8")
        path.chmod(0o600)

    write_private("seed-input.json", {})
    write_private("seed-intent.json", forged_seed)

    validation_calls: list[str] = []

    def reject_forged_seed(
        value: Mapping[str, Any],
        *,
        seed_input: Mapping[str, Any],
        git: route.GitPort,
        now: datetime,
    ) -> dict[str, Any]:
        del seed_input, git, now
        validation_calls.append(
            value["targets"]["route"]["create_request"]["TemplateURL"]
        )
        raise route.RouteSeedError("INTENT_INPUT_BINDING_INVALID")

    provider_calls: list[str] = []

    def provider_must_not_be_created(
        _root: Path,
        _root_fd: int,
        *,
        profile: str,
    ) -> Any:
        provider_calls.append(profile)
        raise AssertionError("provider created before seed validation")

    monkeypatch.setattr(
        cli.route,
        "validate_seed_intent_against_input",
        reject_forged_seed,
    )
    monkeypatch.setattr(cli, "_provider", provider_must_not_be_created)
    result = cli.main(
        [
            "create-reentry",
            "--source-root",
            str(ROOT),
            "--private-root",
            str(tmp_path),
            "--seed-input-name",
            "seed-input.json",
            "--seed-intent-name",
            "seed-intent.json",
            "--target",
            "route",
            "--output-name",
            "output.json",
            "--profile",
            "839393571433_AWSAdministratorAccess",
            "--reentry-intent-name",
            "reentry-intent.json",
            "--failure-attestation-name",
            "failure.json",
            "--reentry-authorization-name",
            "reentry-authorization.json",
        ]
    )
    emitted = json.loads(capsys.readouterr().out)
    assert result == 2
    assert emitted["reason_code"] == "INTENT_INPUT_BINDING_INVALID"
    assert validation_calls == [
        "https://attacker.example.invalid/forged-template.yaml"
    ]
    assert provider_calls == []
    assert not (tmp_path / "output.json").exists()


def test_cleanup_identities_are_preexisting_bridge_owned_and_outside_targets() -> None:
    assert recovery.CLEANUP_IDENTITY_CONTRACTS == {
        "route": {
            "account_id": route.MANAGEMENT_ACCOUNT_ID,
            "permission_set_name": "ScanalyzeGug376RouteSeedCleanup",
            "role_name": "ScanalyzeGug376RouteSeedCleanup",
            "profile_name": "839393571433_ScanalyzeGug376RouteSeedCleanup",
            "owner": "artifact-bootstrap-bridge",
            "preexists_target_stack": True,
            "retirement_independent_of_artifact_assignment": True,
        },
        "broker": {
            "account_id": route.AUTHORITY_ACCOUNT_ID,
            "permission_set_name": "ScanalyzeGug376BrokerSeedCleanup",
            "role_name": "ScanalyzeGug376BrokerSeedCleanup",
            "profile_name": "042360977644_ScanalyzeGug376BrokerSeedCleanup",
            "owner": "artifact-bootstrap-bridge",
            "preexists_target_stack": True,
            "retirement_independent_of_artifact_assignment": True,
        },
    }
    assert recovery.CLEANUP_ROLE_NAMES["route"] not in set(
        recovery.ROUTE_FIXED_IAM_ROLE_NAMES
    )
    assert recovery.CLEANUP_ROLE_NAMES["broker"] not in set(
        recovery.BROKER_FIXED_IAM_ROLE_NAMES
    )
    assert recovery.BRIDGE_RECOVERY_IDENTITY_CONTRACT == {
        "account_id": route.MANAGEMENT_ACCOUNT_ID,
        "role_name": "ScanalyzeGug376RouteBrokerRecovery",
        "owner": "artifact-bootstrap-bridge",
        "preexists_target_stack": True,
        "survives_target_cleanup": True,
        "retirement_operation": "bridge-cleanup-retire",
    }
    assert recovery.BRIDGE_RECOVERY_ROLE_NAME not in set(
        recovery.ROUTE_FIXED_IAM_ROLE_NAMES
    )


class AbsentIAM:
    def __init__(self, *, denied: bool = False) -> None:
        self.denied = denied
        self.requests: list[dict[str, Any]] = []

    def get_role(self, **request: Any) -> Any:
        self.requests.append(request)
        if self.denied:
            raise ServiceError("AccessDenied", 403)
        raise ServiceError("NoSuchEntity", 404)


class EmptySSO:
    def list_permission_sets(self, **_request: Any) -> dict[str, Any]:
        return {"PermissionSets": []}


class AbsentBrokerResources:
    def __init__(self) -> None:
        self.requests: list[tuple[str, dict[str, Any]]] = []

    def describe_table(self, **request: Any) -> Any:
        self.requests.append(("describe_table", request))
        raise ServiceError("ResourceNotFoundException", 400)

    def describe_key(self, **request: Any) -> Any:
        self.requests.append(("describe_key", request))
        raise ServiceError("NotFoundException", 400)

    def get_function(self, **request: Any) -> Any:
        self.requests.append(("get_function", request))
        raise ServiceError("ResourceNotFoundException", 404)

    def get_code_signing_config(self, **request: Any) -> Any:
        self.requests.append(("get_code_signing_config", request))
        raise ServiceError("ResourceNotFoundException", 404)

    def get_role(self, **request: Any) -> Any:
        self.requests.append(("get_role", request))
        raise ServiceError("NoSuchEntity", 404)

    def describe_log_groups(self, **request: Any) -> dict[str, Any]:
        self.requests.append(("describe_log_groups", request))
        return {"logGroups": []}


class PendingDeletionBrokerResources(AbsentBrokerResources):
    def __init__(self, *, now: datetime, enabled: bool = False) -> None:
        super().__init__()
        self.now = now
        self.enabled = enabled

    def describe_key(self, **request: Any) -> Any:
        self.requests.append(("describe_key", request))
        key_id = request["KeyId"]
        if key_id == recovery.BROKER_FIXED_KMS_ALIAS:
            raise ServiceError("NotFoundException", 400)
        return {
            "KeyMetadata": {
                "KeyId": key_id,
                "Arn": (
                    "arn:aws:kms:us-east-1:042360977644:key/"
                    f"{key_id}"
                ),
                "Enabled": self.enabled,
                "KeyState": "PendingDeletion",
                "DeletionDate": self.now + timedelta(days=7),
            }
        }


def test_fixed_resource_absence_accepts_exact_not_found_and_rejects_access_denied(
    case: tuple[dict[str, Any], dict[str, Any], datetime]
) -> None:
    _source, seed, now = case
    failed = _failed_stack_attestation(seed, now)
    authorization = recovery.materialize_cleanup_authorization(
        seed_intent=seed,
        failed_stack_attestation=failed,
        authorization=recovery.CLEANUP_AUTHORIZATION_PHRASES["route"],
        authorized_at=_ts(now),
        expires_at=_ts(now + timedelta(minutes=10)),
    )
    intent = recovery.materialize_cleanup_intent(
        seed_intent=seed,
        failed_stack_attestation=failed,
        authorization=authorization,
    )
    timeline: list[str] = []
    iam = AbsentIAM()
    accepted = recovery.ConnectedDeploymentRecoveryProvider(
        clients=_clients(
            sts=Identity(
                route.MANAGEMENT_ACCOUNT_ID,
                recovery.CLEANUP_ROLE_NAMES["route"],
                timeline,
            ),
            cfn=EmptyService(),
            trail=EmptyService(),
            iam=iam,
            sso=EmptySSO(),
        ),
        claims=Claims(timeline),
        clock=lambda: now,
    )
    digest, calls, scheduled = accepted._prove_no_active_survivors(intent=intent)
    assert digest.startswith("sha256:")
    assert calls == 3
    assert scheduled == []
    assert {request["RoleName"] for request in iam.requests} == set(
        recovery.ROUTE_FIXED_IAM_ROLE_NAMES
    )
    denied = recovery.ConnectedDeploymentRecoveryProvider(
        clients=_clients(
            sts=Identity(
                route.MANAGEMENT_ACCOUNT_ID,
                recovery.CLEANUP_ROLE_NAMES["route"],
                timeline,
            ),
            cfn=EmptyService(),
            trail=EmptyService(),
            iam=AbsentIAM(denied=True),
            sso=EmptySSO(),
        ),
        claims=Claims(timeline),
        clock=lambda: now,
    )
    with pytest.raises(
        recovery.DeploymentRecoveryError,
        match="FIXED_RESOURCE_ABSENCE_UNPROVEN",
    ):
        denied._prove_no_active_survivors(intent=intent)


def test_broker_absence_covers_recovery_functions_roles_and_logs(
    case: tuple[dict[str, Any], dict[str, Any], datetime]
) -> None:
    _source, seed, now = case
    failed = _failed_stack_attestation(seed, now, target="broker")
    authorization = recovery.materialize_cleanup_authorization(
        seed_intent=seed,
        failed_stack_attestation=failed,
        authorization=recovery.CLEANUP_AUTHORIZATION_PHRASES["broker"],
        authorized_at=_ts(now),
        expires_at=_ts(now + timedelta(minutes=10)),
    )
    intent = recovery.materialize_cleanup_intent(
        seed_intent=seed,
        failed_stack_attestation=failed,
        authorization=authorization,
    )
    resources = AbsentBrokerResources()
    provider = recovery.ConnectedDeploymentRecoveryProvider(
        clients=_clients(
            sts=Identity(
                route.AUTHORITY_ACCOUNT_ID,
                recovery.CLEANUP_ROLE_NAMES["broker"],
                [],
            ),
            cfn=EmptyService(),
            trail=EmptyService(),
            dynamodb=resources,
            kms=resources,
            lambda_client=resources,
            iam=resources,
            logs=resources,
        ),
        claims=Claims([]),
        clock=lambda: now,
    )
    digest, calls, scheduled = provider._prove_no_active_survivors(intent=intent)
    assert digest.startswith("sha256:")
    assert calls == 16
    assert scheduled == []
    functions = {
        request["FunctionName"]
        for operation, request in resources.requests
        if operation == "get_function"
    }
    roles = {
        request["RoleName"]
        for operation, request in resources.requests
        if operation == "get_role"
    }
    logs = {
        request["logGroupNamePrefix"]
        for operation, request in resources.requests
        if operation == "describe_log_groups"
    }
    assert functions == set(recovery.BROKER_FIXED_FUNCTION_NAMES)
    assert roles == set(recovery.BROKER_FIXED_IAM_ROLE_NAMES)
    assert logs == set(recovery.BROKER_FIXED_LOG_GROUP_NAMES)


def test_broker_cleanup_accepts_only_exact_disabled_pending_deletion_key(
    case: tuple[dict[str, Any], dict[str, Any], datetime]
) -> None:
    _source, seed, now = case
    failed = _failed_stack_attestation(seed, now, target="broker")
    authorization = recovery.materialize_cleanup_authorization(
        seed_intent=seed,
        failed_stack_attestation=failed,
        authorization=recovery.CLEANUP_AUTHORIZATION_PHRASES["broker"],
        authorized_at=_ts(now),
        expires_at=_ts(now + timedelta(minutes=10)),
    )
    intent = recovery.materialize_cleanup_intent(
        seed_intent=seed,
        failed_stack_attestation=failed,
        authorization=authorization,
    )
    resources = PendingDeletionBrokerResources(now=now)
    provider = recovery.ConnectedDeploymentRecoveryProvider(
        clients=_clients(
            sts=Identity(
                route.AUTHORITY_ACCOUNT_ID,
                recovery.CLEANUP_ROLE_NAMES["broker"],
                [],
            ),
            cfn=EmptyService(),
            trail=EmptyService(),
            dynamodb=resources,
            kms=resources,
            lambda_client=resources,
            iam=resources,
            logs=resources,
        ),
        claims=Claims([]),
        clock=lambda: now,
    )
    digest, calls, scheduled = provider._prove_no_active_survivors(intent=intent)
    assert digest.startswith("sha256:")
    assert calls == 16
    assert scheduled == [
        {
            "service": "kms",
            "resource": (
                "arn:aws:kms:us-east-1:042360977644:key/"
                "00000000-0000-4000-8000-000000000001"
            ),
            "state": "PendingDeletion",
            "enabled": False,
            "deletion_date": _ts(now + timedelta(days=7)),
        }
    ]

    active = PendingDeletionBrokerResources(now=now, enabled=True)
    blocked = recovery.ConnectedDeploymentRecoveryProvider(
        clients=_clients(
            sts=Identity(
                route.AUTHORITY_ACCOUNT_ID,
                recovery.CLEANUP_ROLE_NAMES["broker"],
                [],
            ),
            cfn=EmptyService(),
            trail=EmptyService(),
            dynamodb=active,
            kms=active,
            lambda_client=active,
            iam=active,
            logs=active,
        ),
        claims=Claims([]),
        clock=lambda: now,
    )
    with pytest.raises(
        recovery.DeploymentRecoveryError,
        match="FIXED_RESOURCE_ACTIVE_SURVIVOR",
    ):
        blocked._prove_no_active_survivors(intent=intent)


def test_cleanup_terminal_seals_pending_deletion_as_inert_not_absent(
    case: tuple[dict[str, Any], dict[str, Any], datetime]
) -> None:
    _source, _seed, now = case
    scheduled = [
        {
            "service": "kms",
            "resource": (
                "arn:aws:kms:us-east-1:042360977644:key/"
                "00000000-0000-4000-8000-000000000001"
            ),
            "state": "PendingDeletion",
            "enabled": False,
            "deletion_date": _ts(now + timedelta(days=7)),
        }
    ]
    terminal = route.seal(
        {
            "schema_version": 1,
            "record_type": recovery.CLEANUP_TERMINAL_RECORD_TYPE,
            "source_commit": "a" * 40,
            "target": "broker",
            "account_id": route.AUTHORITY_ACCOUNT_ID,
            "execution_lane": "primary",
            "cleanup_intent_digest": "sha256:" + "1" * 64,
            "cleanup_dispatch_digest": "sha256:" + "2" * 64,
            "parent_intent_digest": "sha256:" + "3" * 64,
            "failed_stack_attestation_digest": "sha256:" + "4" * 64,
            "failed_resources": [],
            "failed_resources_digest": route.digest_value([]),
            "delete_cloudtrail_event_digest": "sha256:" + "5" * 64,
            "stack_arn": (
                "arn:aws:cloudformation:us-east-1:042360977644:stack/"
                f"{route.BROKER_STACK_NAME}/{STACK_UUID}"
            ),
            "stack_terminal_observation": "DELETE_COMPLETE",
            "fixed_stack_name": route.BROKER_STACK_NAME,
            "fixed_stack_name_absent": True,
            "survivor_check_count": 16,
            "survivor_evidence_digest": "sha256:" + "6" * 64,
            "no_active_survivors": True,
            "scheduled_inert_survivor_count": 1,
            "scheduled_inert_survivors": scheduled,
            "scheduled_inert_survivors_digest": route.digest_value(scheduled),
            "attested_at": _ts(now),
            "aws_calls": 19,
            "aws_mutations": 0,
            "retry_permitted": False,
            "production_authorized": False,
            "production_status": route.PRODUCTION_STATUS,
        },
        "attestation_digest",
    )
    assert recovery._failure_binding(terminal) == (
        "broker",
        terminal["attestation_digest"],
    )

    changed = copy.deepcopy(terminal)
    changed["scheduled_inert_survivors"][0]["enabled"] = True
    changed["scheduled_inert_survivors_digest"] = route.digest_value(
        changed["scheduled_inert_survivors"]
    )
    changed.pop("attestation_digest")
    changed = route.seal(changed, "attestation_digest")
    with pytest.raises(
        recovery.DeploymentRecoveryError,
        match="FAILURE_ATTESTATION_INVALID",
    ):
        recovery._failure_binding(changed)


def test_tampered_failure_cannot_authorize_reentry(
    case: tuple[dict[str, Any], dict[str, Any], datetime]
) -> None:
    _source, intent, now = case
    failure, _claims, _timeline = _preexecute_failure(intent, now)
    changed = copy.deepcopy(failure)
    changed["stack_status"] = "REVIEW_IN_PROGRESS"
    changed["resource_count"] = 1
    changed.pop("attestation_digest")
    changed = route.seal(changed, "attestation_digest")
    with pytest.raises(
        recovery.DeploymentRecoveryError, match="FAILURE_ATTESTATION_INVALID"
    ):
        recovery.materialize_reentry_request(
            seed_intent=intent, failure_attestation=changed
        )


class TerminalReentryCloudFormation:
    def __init__(self) -> None:
        self.expected_create_request: Mapping[str, Any] | None = None
        self.create_calls = 0
        self.describe_calls = 0

    def describe_stacks(self, **_request: Any) -> dict[str, Any]:
        self.describe_calls += 1
        raise ServiceError(
            "ValidationError", 400, "Stack with id does not exist"
        )

    def create_change_set(self, **request: Any) -> dict[str, Any]:
        self.create_calls += 1
        assert request == self.expected_create_request
        return {
            "Id": (
                "arn:aws:cloudformation:us-east-1:839393571433:changeSet/"
                f"{request['ChangeSetName']}/"
                "99999999-9999-4999-8999-999999999999"
            ),
            "StackId": (
                "arn:aws:cloudformation:us-east-1:839393571433:stack/"
                f"{route.ROUTE_STACK_NAME}/"
                "88888888-8888-4888-8888-888888888888"
            ),
            "ResponseMetadata": {"RequestId": RECOVERY_REQUEST_UUID},
        }


def _cleanup_terminal_reentry_chain(
    seed: Mapping[str, Any], now: datetime
) -> tuple[
    Claims,
    list[str],
    dict[str, Any],
    dict[str, Any],
    dict[str, Any],
    dict[str, Any],
    TerminalReentryCloudFormation,
]:
    timeline: list[str] = []
    claims = Claims(timeline)
    failed = _failed_stack_attestation(seed, now)
    cleanup_authorization = recovery.materialize_cleanup_authorization(
        seed_intent=seed,
        failed_stack_attestation=failed,
        authorization=recovery.CLEANUP_AUTHORIZATION_PHRASES["route"],
        authorized_at=_ts(now),
        expires_at=_ts(now + timedelta(minutes=10)),
    )
    cleanup_intent = recovery.materialize_cleanup_intent(
        seed_intent=seed,
        failed_stack_attestation=failed,
        authorization=cleanup_authorization,
    )
    cleanup_key = f"cleanup:route:{seed['intent_digest']}:primary"
    cleanup_claim = {
        "schema_version": 1,
        "record_type": recovery.CLAIM_RECORD_TYPE,
        "operation": "DeleteStack",
        "target": "route",
        "execution_lane": "primary",
        "attempt": 1,
        "cleanup_intent_digest": cleanup_intent["cleanup_intent_digest"],
        "failed_stack_attestation_digest": cleanup_intent[
            "failed_stack_attestation_digest"
        ],
        "failed_resources_digest": cleanup_intent[
            "failed_resources_digest"
        ],
        "request_digest": cleanup_intent["delete_request_digest"],
        "client_request_token": cleanup_intent["delete_request"][
            "ClientRequestToken"
        ],
        "stack_arn": failed["stack_arn"],
        "caller_arn_digest": route.digest_value(
            _caller(
                route.MANAGEMENT_ACCOUNT_ID,
                recovery.CLEANUP_ROLE_NAMES["route"],
            )
        ),
        "claimed_at": _ts(now),
        "retry_permitted": False,
        "production_authorized": False,
    }
    cleanup_dispatch = route.seal(
        {
            "schema_version": 1,
            "record_type": recovery.CLEANUP_DISPATCH_RECORD_TYPE,
            "source_commit": seed["source_commit"],
            "target": "route",
            "account_id": route.MANAGEMENT_ACCOUNT_ID,
            "execution_lane": "primary",
            "cleanup_intent_digest": cleanup_intent[
                "cleanup_intent_digest"
            ],
            "failed_stack_attestation_digest": cleanup_intent[
                "failed_stack_attestation_digest"
            ],
            "failed_resources_digest": cleanup_intent[
                "failed_resources_digest"
            ],
            "stack_arn": failed["stack_arn"],
            "delete_request_id": RECOVERY_REQUEST_UUID,
            "dispatched_at": _ts(now),
            "attempt": 1,
            "aws_mutations": 1,
            "retry_permitted": False,
            "production_authorized": False,
            "production_status": route.PRODUCTION_STATUS,
        },
        "dispatch_digest",
    )
    claims.seen.add(cleanup_key)
    claims.records[cleanup_key] = cleanup_claim
    claims.results[cleanup_key] = cleanup_dispatch
    delete_event = {
        "eventSource": "cloudformation.amazonaws.com",
        "eventName": "DeleteStack",
        "awsRegion": route.REGION,
        "recipientAccountId": route.MANAGEMENT_ACCOUNT_ID,
        "readOnly": False,
        "errorCode": None,
        "errorMessage": None,
        "requestID": RECOVERY_REQUEST_UUID,
        "eventID": EVENT_UUID,
        "eventTime": _ts(now),
        "userIdentity": {
            "arn": _caller(
                route.MANAGEMENT_ACCOUNT_ID,
                recovery.CLEANUP_ROLE_NAMES["route"],
            )
        },
        "requestParameters": {
            "stackName": failed["stack_arn"],
            "clientRequestToken": cleanup_intent["delete_request"][
                "ClientRequestToken"
            ],
        },
        "responseElements": None,
    }
    cfn = TerminalReentryCloudFormation()
    attestor = recovery.ConnectedDeploymentRecoveryProvider(
        clients=_clients(
            sts=Identity(
                route.MANAGEMENT_ACCOUNT_ID,
                recovery.CLEANUP_ROLE_NAMES["route"],
                timeline,
            ),
            cfn=cfn,
            trail=Trail(delete_event),
            iam=AbsentIAM(),
            sso=EmptySSO(),
        ),
        claims=claims,
        clock=lambda: now,
    )
    terminal = attestor.attest_cleanup_complete(
        seed_intent=seed,
        failed_stack_attestation=failed,
        authorization=cleanup_authorization,
        cleanup_intent=cleanup_intent,
        cleanup_dispatch=cleanup_dispatch,
    )
    return (
        claims,
        timeline,
        terminal,
        cleanup_authorization,
        cleanup_intent,
        delete_event,
        cfn,
    )


def test_cleanup_terminal_live_proof_allows_only_one_reentry_and_rejects_reseal(
    case: tuple[dict[str, Any], dict[str, Any], datetime]
) -> None:
    _source, seed, now = case
    claims, timeline, terminal, _cleanup_auth, _cleanup_intent, event, cfn = (
        _cleanup_terminal_reentry_chain(seed, now)
    )
    authorization = recovery.materialize_reentry_authorization(
        seed_intent=seed,
        failure_attestation=terminal,
        authorization=recovery.REENTRY_CREATION_PHRASES["route"],
        authorized_at=_ts(now),
        expires_at=_ts(now + timedelta(minutes=10)),
    )
    intent = recovery.materialize_reentry_intent(
        seed_intent=seed,
        failure_attestation=terminal,
        authorization=authorization,
    )
    cfn.expected_create_request = intent["create_request"]
    timeline.clear()
    provider = recovery.ConnectedDeploymentRecoveryProvider(
        clients=_clients(
            sts=Identity(
                route.MANAGEMENT_ACCOUNT_ID,
                "AWSAdministratorAccess",
                timeline,
            ),
            cfn=cfn,
            trail=Trail(event),
            iam=AbsentIAM(),
            sso=EmptySSO(),
        ),
        claims=claims,
        clock=lambda: now,
    )
    receipt = provider.create_reentry_change_set(
        seed_input={},
        seed_intent=seed,
        git=object(),
        failure_attestation=terminal,
        authorization=authorization,
        reentry_intent=intent,
    )
    assert receipt["attempt"] == 1
    assert cfn.create_calls == 1
    with pytest.raises(
        recovery.DeploymentRecoveryError, match="MUTATION_REPLAY_REJECTED"
    ):
        provider.create_reentry_change_set(
            seed_input={},
            seed_intent=seed,
            git=object(),
            failure_attestation=terminal,
            authorization=authorization,
            reentry_intent=intent,
        )
    assert cfn.create_calls == 1

    (
        forged_claims,
        forged_timeline,
        authentic,
        _forged_cleanup_auth,
        _forged_cleanup_intent,
        forged_event,
        forged_cfn,
    ) = _cleanup_terminal_reentry_chain(seed, now)
    forged = copy.deepcopy(authentic)
    forged["survivor_evidence_digest"] = "sha256:" + "9" * 64
    forged.pop("attestation_digest")
    forged = route.seal(forged, "attestation_digest")
    forged_authorization = recovery.materialize_reentry_authorization(
        seed_intent=seed,
        failure_attestation=forged,
        authorization=recovery.REENTRY_CREATION_PHRASES["route"],
        authorized_at=_ts(now),
        expires_at=_ts(now + timedelta(minutes=10)),
    )
    forged_intent = recovery.materialize_reentry_intent(
        seed_intent=seed,
        failure_attestation=forged,
        authorization=forged_authorization,
    )
    forged_cfn.expected_create_request = forged_intent["create_request"]
    forged_timeline.clear()
    forged_provider = recovery.ConnectedDeploymentRecoveryProvider(
        clients=_clients(
            sts=Identity(
                route.MANAGEMENT_ACCOUNT_ID,
                "AWSAdministratorAccess",
                forged_timeline,
            ),
            cfn=forged_cfn,
            trail=Trail(forged_event),
            iam=AbsentIAM(),
            sso=EmptySSO(),
        ),
        claims=forged_claims,
        clock=lambda: now,
    )
    with pytest.raises(
        recovery.DeploymentRecoveryError,
        match="FAILURE_ATTESTATION_LIVE_BINDING_INVALID",
    ):
        forged_provider.create_reentry_change_set(
            seed_input={},
            seed_intent=seed,
            git=object(),
            failure_attestation=forged,
            authorization=forged_authorization,
            reentry_intent=forged_intent,
        )
    assert forged_cfn.create_calls == 0


def test_cleanup_attestation_rejects_invalid_dispatch_before_sts(
    case: tuple[dict[str, Any], dict[str, Any], datetime]
) -> None:
    _source, seed, now = case
    claims, timeline, _terminal, authorization, intent, _event, _cfn = (
        _cleanup_terminal_reentry_chain(seed, now)
    )
    key = f"cleanup:route:{seed['intent_digest']}:primary"
    changed = copy.deepcopy(claims.results[key])
    changed.pop("failed_resources_digest")
    changed.pop("dispatch_digest")
    changed = route.seal(changed, "dispatch_digest")
    timeline.clear()
    provider = recovery.ConnectedDeploymentRecoveryProvider(
        clients=_clients(
            sts=Identity(
                route.MANAGEMENT_ACCOUNT_ID,
                recovery.CLEANUP_ROLE_NAMES["route"],
                timeline,
            ),
            cfn=EmptyService(),
            trail=EmptyService(),
        ),
        claims=claims,
        clock=lambda: now,
    )
    with pytest.raises(
        recovery.DeploymentRecoveryError,
        match="CLEANUP_DISPATCH_INVALID",
    ):
        provider.attest_cleanup_complete(
            seed_intent=seed,
            failed_stack_attestation=_failed_stack_attestation(seed, now),
            authorization=authorization,
            cleanup_intent=intent,
            cleanup_dispatch=changed,
        )
    assert timeline == []


def test_cleanup_terminal_cannot_drop_broker_resources_before_reentry_sts(
    case: tuple[dict[str, Any], dict[str, Any], datetime]
) -> None:
    _source, seed, now = case
    timeline: list[str] = []
    claims = Claims(timeline)
    failed = _failed_stack_attestation(seed, now, target="broker")
    cleanup_authorization = recovery.materialize_cleanup_authorization(
        seed_intent=seed,
        failed_stack_attestation=failed,
        authorization=recovery.CLEANUP_AUTHORIZATION_PHRASES["broker"],
        authorized_at=_ts(now),
        expires_at=_ts(now + timedelta(minutes=10)),
    )
    cleanup_intent = recovery.materialize_cleanup_intent(
        seed_intent=seed,
        failed_stack_attestation=failed,
        authorization=cleanup_authorization,
    )
    key = f"cleanup:broker:{seed['intent_digest']}:primary"
    claim = {
        "schema_version": 1,
        "record_type": recovery.CLAIM_RECORD_TYPE,
        "operation": "DeleteStack",
        "target": "broker",
        "execution_lane": "primary",
        "attempt": 1,
        "cleanup_intent_digest": cleanup_intent["cleanup_intent_digest"],
        "failed_stack_attestation_digest": cleanup_intent[
            "failed_stack_attestation_digest"
        ],
        "failed_resources_digest": cleanup_intent[
            "failed_resources_digest"
        ],
        "request_digest": cleanup_intent["delete_request_digest"],
        "client_request_token": cleanup_intent["delete_request"][
            "ClientRequestToken"
        ],
        "stack_arn": failed["stack_arn"],
        "caller_arn_digest": route.digest_value(
            _caller(
                route.AUTHORITY_ACCOUNT_ID,
                recovery.CLEANUP_ROLE_NAMES["broker"],
            )
        ),
        "claimed_at": _ts(now),
        "retry_permitted": False,
        "production_authorized": False,
    }
    dispatch = route.seal(
        {
            "schema_version": 1,
            "record_type": recovery.CLEANUP_DISPATCH_RECORD_TYPE,
            "source_commit": seed["source_commit"],
            "target": "broker",
            "account_id": route.AUTHORITY_ACCOUNT_ID,
            "execution_lane": "primary",
            "cleanup_intent_digest": cleanup_intent[
                "cleanup_intent_digest"
            ],
            "failed_stack_attestation_digest": cleanup_intent[
                "failed_stack_attestation_digest"
            ],
            "failed_resources_digest": cleanup_intent[
                "failed_resources_digest"
            ],
            "stack_arn": failed["stack_arn"],
            "delete_request_id": RECOVERY_REQUEST_UUID,
            "dispatched_at": _ts(now),
            "attempt": 1,
            "aws_mutations": 1,
            "retry_permitted": False,
            "production_authorized": False,
            "production_status": route.PRODUCTION_STATUS,
        },
        "dispatch_digest",
    )
    claims.seen.add(key)
    claims.records[key] = claim
    claims.results[key] = dispatch
    omitted_resources = copy.deepcopy(failed["resources"][1:])
    forged_terminal = route.seal(
        {
            "schema_version": 1,
            "record_type": recovery.CLEANUP_TERMINAL_RECORD_TYPE,
            "source_commit": seed["source_commit"],
            "target": "broker",
            "account_id": route.AUTHORITY_ACCOUNT_ID,
            "execution_lane": "primary",
            "cleanup_intent_digest": cleanup_intent[
                "cleanup_intent_digest"
            ],
            "cleanup_dispatch_digest": dispatch["dispatch_digest"],
            "parent_intent_digest": seed["intent_digest"],
            "failed_stack_attestation_digest": failed[
                "attestation_digest"
            ],
            "failed_resources": omitted_resources,
            "failed_resources_digest": route.digest_value(
                omitted_resources
            ),
            "delete_cloudtrail_event_digest": "sha256:" + "5" * 64,
            "stack_arn": failed["stack_arn"],
            "stack_terminal_observation": "NOT_FOUND",
            "fixed_stack_name": route.BROKER_STACK_NAME,
            "fixed_stack_name_absent": True,
            "survivor_check_count": 1,
            "survivor_evidence_digest": "sha256:" + "6" * 64,
            "no_active_survivors": True,
            "scheduled_inert_survivor_count": 0,
            "scheduled_inert_survivors": [],
            "scheduled_inert_survivors_digest": route.digest_value([]),
            "attested_at": _ts(now),
            "aws_calls": 4,
            "aws_mutations": 0,
            "retry_permitted": False,
            "production_authorized": False,
            "production_status": route.PRODUCTION_STATUS,
        },
        "attestation_digest",
    )
    authorization = recovery.materialize_reentry_authorization(
        seed_intent=seed,
        failure_attestation=forged_terminal,
        authorization=recovery.REENTRY_CREATION_PHRASES["broker"],
        authorized_at=_ts(now),
        expires_at=_ts(now + timedelta(minutes=10)),
    )
    intent = recovery.materialize_reentry_intent(
        seed_intent=seed,
        failure_attestation=forged_terminal,
        authorization=authorization,
    )
    provider = recovery.ConnectedDeploymentRecoveryProvider(
        clients=_clients(
            sts=Identity(
                route.AUTHORITY_ACCOUNT_ID,
                "ScanalyzeGug376BrokerSeedCreator",
                timeline,
            ),
            cfn=EmptyService(),
            trail=EmptyService(),
        ),
        claims=claims,
        clock=lambda: now,
    )
    with pytest.raises(
        recovery.DeploymentRecoveryError,
        match="FAILURE_ATTESTATION_JOURNAL_BINDING_INVALID",
    ):
        provider.create_reentry_change_set(
            seed_input={},
            seed_intent=seed,
            git=object(),
            failure_attestation=forged_terminal,
            authorization=authorization,
            reentry_intent=intent,
        )
    assert timeline == ["read-result", "read-claim"]


class ProtectionReentryCloudFormation:
    def __init__(
        self,
        *,
        stack_arn: str,
        expected_create_request: Mapping[str, Any],
        stack_status: str = "UPDATE_ROLLBACK_COMPLETE",
    ) -> None:
        self.stack_arn = stack_arn
        self.expected_create_request = expected_create_request
        self.stack_status = stack_status
        self.create_calls = 0
        self.key_id = "00000000-0000-4000-8000-000000000001"

    def describe_stacks(self, **request: Any) -> dict[str, Any]:
        assert request == {"StackName": self.stack_arn}
        return {
            "Stacks": [
                {
                    "StackId": self.stack_arn,
                    "StackName": route.BROKER_STACK_NAME,
                    "StackStatus": self.stack_status,
                }
            ]
        }

    def list_stack_resources(self, **request: Any) -> dict[str, Any]:
        assert request == {"StackName": self.stack_arn}
        return {
            "StackResourceSummaries": [
                {
                    "LogicalResourceId": "BrokerLedger",
                    "PhysicalResourceId": recovery.BROKER_FIXED_TABLE_NAME,
                    "ResourceType": "AWS::DynamoDB::Table",
                    "ResourceStatus": "CREATE_COMPLETE",
                },
                {
                    "LogicalResourceId": "BrokerLedgerKey",
                    "PhysicalResourceId": self.key_id,
                    "ResourceType": "AWS::KMS::Key",
                    "ResourceStatus": "CREATE_COMPLETE",
                },
            ]
        }

    def create_change_set(self, **request: Any) -> dict[str, Any]:
        self.create_calls += 1
        assert request == self.expected_create_request
        return {
            "Id": (
                "arn:aws:cloudformation:us-east-1:042360977644:changeSet/"
                f"{request['ChangeSetName']}/"
                "99999999-9999-4999-8999-999999999999"
            ),
            "StackId": self.stack_arn,
            "ResponseMetadata": {"RequestId": RECOVERY_REQUEST_UUID},
        }


class ProtectionLedger:
    def __init__(self, *, deletion_protection_enabled: bool = False) -> None:
        self.deletion_protection_enabled = deletion_protection_enabled
        self.key_id = "00000000-0000-4000-8000-000000000001"

    def describe_table(self, **request: Any) -> dict[str, Any]:
        assert request == {"TableName": recovery.BROKER_FIXED_TABLE_NAME}
        return {
            "Table": {
                "TableName": recovery.BROKER_FIXED_TABLE_NAME,
                "TableArn": (
                    "arn:aws:dynamodb:us-east-1:042360977644:table/"
                    f"{recovery.BROKER_FIXED_TABLE_NAME}"
                ),
                "TableStatus": "ACTIVE",
                "DeletionProtectionEnabled": (
                    self.deletion_protection_enabled
                ),
                "SSEDescription": {
                    "Status": "ENABLED",
                    "SSEType": "KMS",
                    "KMSMasterKeyArn": (
                        "arn:aws:kms:us-east-1:042360977644:key/"
                        f"{self.key_id}"
                    ),
                },
            }
        }


def _protection_rollback_reentry_chain(
    original_seed: Mapping[str, Any], now: datetime
) -> tuple[
    dict[str, Any],
    Claims,
    list[str],
    dict[str, Any],
    dict[str, Any],
    dict[str, Any],
    dict[str, Any],
]:
    seed = copy.deepcopy(original_seed)
    expected_resources = [
        {
            "logical_resource_id": "BrokerLedger",
            "resource_type": "AWS::DynamoDB::Table",
        },
        {
            "logical_resource_id": "BrokerLedgerKey",
            "resource_type": "AWS::KMS::Key",
        },
    ]
    seed["targets"]["broker"]["expected_resources"] = expected_resources
    seed.pop("intent_digest")
    seed = route.seal(seed, "intent_digest")
    stack_arn = (
        "arn:aws:cloudformation:us-east-1:042360977644:stack/"
        f"{route.BROKER_STACK_NAME}/{STACK_UUID}"
    )
    change_set_arn = (
        "arn:aws:cloudformation:us-east-1:042360977644:changeSet/"
        f"{route.BROKER_PROTECTION_CHANGE_SET_NAME}/{CHANGE_UUID}"
    )
    operation_digest = route.digest_value(
        {
            "record_type": (
                "scanalyze.platform_authority."
                "plan_permission_repair_execute_operation.v1"
            ),
            "source_commit": seed["source_commit"],
            "target": route.BROKER_PROTECTION_TARGET,
            "account_id": route.AUTHORITY_ACCOUNT_ID,
            "stack_arn": stack_arn,
            "change_set_arn": change_set_arn,
        }
    )
    execute_request = {
        "StackName": stack_arn,
        "ChangeSetName": change_set_arn,
        "ClientRequestToken": "gug376-" + operation_digest[7:55],
        "DisableRollback": False,
    }
    execution_intent_digest = "sha256:" + "7" * 64
    caller = _caller(
        route.AUTHORITY_ACCOUNT_ID, "ScanalyzeGug376BrokerSeedExec"
    )
    claim = {
        "schema_version": 1,
        "record_type": connected.CLAIM_RECORD_TYPE,
        "operation": "ExecuteChangeSet",
        "target": route.BROKER_PROTECTION_TARGET,
        "execution_intent_digest": execution_intent_digest,
        "request_digest": route.digest_value(execute_request),
        "client_request_token": execute_request["ClientRequestToken"],
        "stack_arn": stack_arn,
        "change_set_arn": change_set_arn,
        "caller_arn_digest": route.digest_value(caller),
        "claimed_at": _ts(now),
        "retry_permitted": False,
        "production_authorized": False,
    }
    receipt = route.seal(
        {
            "schema_version": 1,
            "record_type": connected.EXECUTION_RECEIPT_RECORD_TYPE,
            "source_commit": seed["source_commit"],
            "target": route.BROKER_PROTECTION_TARGET,
            "account_id": route.AUTHORITY_ACCOUNT_ID,
            "execution_intent_digest": execution_intent_digest,
            "stack_arn": stack_arn,
            "change_set_arn": change_set_arn,
            "execute_request_id": RECOVERY_REQUEST_UUID,
            "dispatched_at": _ts(now),
            "aws_mutations": 1,
            "retry_permitted": False,
            "production_authorized": False,
            "production_status": route.PRODUCTION_STATUS,
        },
        "receipt_digest",
    )
    timeline: list[str] = []
    claims = Claims(timeline)
    execution_key = (
        f"execute:{route.BROKER_PROTECTION_TARGET}:{operation_digest}"
    )
    claims.seen.add(execution_key)
    claims.records[execution_key] = claim
    claims.results[execution_key] = receipt
    event = {
        "eventSource": "cloudformation.amazonaws.com",
        "eventName": "ExecuteChangeSet",
        "awsRegion": route.REGION,
        "recipientAccountId": route.AUTHORITY_ACCOUNT_ID,
        "readOnly": False,
        "errorCode": None,
        "errorMessage": None,
        "requestID": RECOVERY_REQUEST_UUID,
        "eventID": EVENT_UUID,
        "eventTime": _ts(now),
        "userIdentity": {"arn": caller},
        "requestParameters": {
            "stackName": stack_arn,
            "changeSetName": change_set_arn,
            "clientRequestToken": execute_request["ClientRequestToken"],
            "disableRollback": False,
        },
    }
    resources = [
        {
            "logical_resource_id": "BrokerLedger",
            "resource_type": "AWS::DynamoDB::Table",
            "resource_status": "CREATE_COMPLETE",
        },
        {
            "logical_resource_id": "BrokerLedgerKey",
            "resource_type": "AWS::KMS::Key",
            "resource_status": "CREATE_COMPLETE",
        },
    ]
    ledger_projection = {
        "table_name": recovery.BROKER_FIXED_TABLE_NAME,
        "table_arn": (
            "arn:aws:dynamodb:us-east-1:042360977644:table/"
            f"{recovery.BROKER_FIXED_TABLE_NAME}"
        ),
        "table_status": "ACTIVE",
        "deletion_protection_enabled": False,
        "sse_status": "ENABLED",
        "sse_type": "KMS",
        "kms_key_arn": (
            "arn:aws:kms:us-east-1:042360977644:key/"
            "00000000-0000-4000-8000-000000000001"
        ),
    }
    failure = route.seal(
        {
            "schema_version": 1,
            "record_type": recovery.PROTECTION_ROLLBACK_RECORD_TYPE,
            "source_commit": seed["source_commit"],
            "target": route.BROKER_PROTECTION_TARGET,
            "intent_digest": seed["intent_digest"],
            "execution_intent_digest": execution_intent_digest,
            "execution_receipt_digest": receipt["receipt_digest"],
            "execution_claim_digest": route.digest_value(claim),
            "execute_cloudtrail_event_digest": route.digest_value(
                {
                    "event_id": EVENT_UUID,
                    "event_time": _ts(now),
                    "request_id": RECOVERY_REQUEST_UUID,
                    "request_digest": route.digest_value(
                        {
                            "stackName": stack_arn,
                            "changeSetName": change_set_arn,
                            "clientRequestToken": execute_request[
                                "ClientRequestToken"
                            ],
                            "disableRollback": False,
                        }
                    ),
                }
            ),
            "account_id": route.AUTHORITY_ACCOUNT_ID,
            "stack_arn": stack_arn,
            "change_set_arn": change_set_arn,
            "execute_request_id": RECOVERY_REQUEST_UUID,
            "stack_status": "UPDATE_ROLLBACK_COMPLETE",
            "resource_count": len(resources),
            "resources_digest": route.digest_value(resources),
            "ledger_live_properties_digest": route.digest_value(
                ledger_projection
            ),
            "ledger_deletion_protection_enabled": False,
            "attested_at": _ts(now),
            "aws_calls": 5,
            "aws_mutations": 0,
            "retry_permitted": False,
            "production_authorized": False,
            "production_status": route.PRODUCTION_STATUS,
        },
        "attestation_digest",
    )
    authorization = recovery.materialize_reentry_authorization(
        seed_intent=seed,
        failure_attestation=failure,
        authorization=recovery.REENTRY_CREATION_PHRASES[
            route.BROKER_PROTECTION_TARGET
        ],
        authorized_at=_ts(now),
        expires_at=_ts(now + timedelta(minutes=10)),
    )
    intent = recovery.materialize_reentry_intent(
        seed_intent=seed,
        failure_attestation=failure,
        authorization=authorization,
    )
    return seed, claims, timeline, failure, authorization, intent, event


def test_protection_rollback_live_proof_allows_only_one_reentry_and_blocks_drift(
    case: tuple[dict[str, Any], dict[str, Any], datetime]
) -> None:
    _source, original_seed, now = case
    seed, claims, timeline, failure, authorization, intent, event = (
        _protection_rollback_reentry_chain(original_seed, now)
    )
    cfn = ProtectionReentryCloudFormation(
        stack_arn=failure["stack_arn"],
        expected_create_request=intent["create_request"],
    )
    provider = recovery.ConnectedDeploymentRecoveryProvider(
        clients=_clients(
            sts=Identity(
                route.AUTHORITY_ACCOUNT_ID,
                "ScanalyzeGug376BrokerSeedCreator",
                timeline,
            ),
            cfn=cfn,
            trail=Trail(event),
            dynamodb=ProtectionLedger(),
        ),
        claims=claims,
        clock=lambda: now,
    )
    receipt = provider.create_reentry_change_set(
        seed_input={},
        seed_intent=seed,
        git=object(),
        failure_attestation=failure,
        authorization=authorization,
        reentry_intent=intent,
    )
    assert receipt["attempt"] == 1
    assert cfn.create_calls == 1
    with pytest.raises(
        recovery.DeploymentRecoveryError, match="MUTATION_REPLAY_REJECTED"
    ):
        provider.create_reentry_change_set(
            seed_input={},
            seed_intent=seed,
            git=object(),
            failure_attestation=failure,
            authorization=authorization,
            reentry_intent=intent,
        )
    assert cfn.create_calls == 1

    (
        drift_seed,
        drift_claims,
        drift_timeline,
        drift_failure,
        drift_authorization,
        drift_intent,
        drift_event,
    ) = _protection_rollback_reentry_chain(original_seed, now)
    drift_cfn = ProtectionReentryCloudFormation(
        stack_arn=drift_failure["stack_arn"],
        expected_create_request=drift_intent["create_request"],
        stack_status="UPDATE_COMPLETE",
    )
    drift_provider = recovery.ConnectedDeploymentRecoveryProvider(
        clients=_clients(
            sts=Identity(
                route.AUTHORITY_ACCOUNT_ID,
                "ScanalyzeGug376BrokerSeedCreator",
                drift_timeline,
            ),
            cfn=drift_cfn,
            trail=Trail(drift_event),
            dynamodb=ProtectionLedger(),
        ),
        claims=drift_claims,
        clock=lambda: now,
    )
    with pytest.raises(
        recovery.DeploymentRecoveryError,
        match="PROTECTION_ROLLBACK_STACK_INVALID",
    ):
        drift_provider.create_reentry_change_set(
            seed_input={},
            seed_intent=drift_seed,
            git=object(),
            failure_attestation=drift_failure,
            authorization=drift_authorization,
            reentry_intent=drift_intent,
        )
    assert drift_cfn.create_calls == 0


def _exact_reentry_attestation_case(
    seed: Mapping[str, Any], now: datetime
) -> tuple[
    dict[str, Any],
    dict[str, Any],
    dict[str, Any],
    Claims,
    dict[str, Any],
    AuthoritativeReentryCloudFormation,
]:
    intent, failure, authorization = _reentry_intent(seed, now)
    dispatch, _synthetic_attestation = _reentry_dispatch_and_attestation(
        seed, intent, now
    )
    timeline: list[str] = []
    claims = Claims(timeline)
    _seed_reentry_create_journal(
        claims,
        seed=seed,
        reentry_intent=intent,
        dispatch=dispatch,
    )
    event = _create_event(
        request=intent["create_request"],
        account=route.MANAGEMENT_ACCOUNT_ID,
        role_name="AWSAdministratorAccess",
        stack_arn=dispatch["stack_arn"],
        change_set_arn=dispatch["change_set_arn"],
        request_id=dispatch["create_request_id"],
        event_id=EVENT_UUID,
        when=now,
    )
    cfn = AuthoritativeReentryCloudFormation(
        seed=seed,
        reentry_intent=intent,
        live_dispatch=dispatch,
    )
    return intent, failure, authorization, claims, event, cfn


def test_reentry_attestor_and_create_event_digest_bind_exact_live_evidence(
    case: tuple[dict[str, Any], dict[str, Any], datetime]
) -> None:
    _source, seed, now = case
    intent, failure, authorization, claims, event, cfn = (
        _exact_reentry_attestation_case(seed, now)
    )
    key = f"reentry-create:route:{seed['intent_digest']}"
    dispatch = claims.results[key]
    provider = recovery.ConnectedDeploymentRecoveryProvider(
        clients=_clients(
            sts=Identity(
                route.MANAGEMENT_ACCOUNT_ID,
                "AWSAdministratorAccess",
                [],
            ),
            cfn=cfn,
            trail=Trail(event),
        ),
        claims=claims,
        clock=lambda: now,
    )
    attestation = provider.attest_reentry_change_set(
        seed_intent=seed,
        failure_attestation=failure,
        authorization=authorization,
        reentry_intent=intent,
        dispatch=dispatch,
    )
    digest, pages = recovery._reentry_create_event_digest(
        Trail(event),
        account=route.MANAGEMENT_ACCOUNT_ID,
        claim=claims.records[key],
        dispatch=dispatch,
        request=intent["create_request"],
        now=now,
    )
    assert attestation["cloudtrail_event_digest"] == digest
    assert attestation["dispatch_digest"] == dispatch["dispatch_digest"]
    assert attestation["changes_digest"] == route.digest_value(
        seed["targets"]["route"]["expected_changes"]
    )
    assert pages == 1
    assert cfn.describe_calls == 1
    assert cfn.template_calls == 1


@pytest.mark.parametrize("tamper", ("caller", "params", "claim"))
def test_reentry_create_event_digest_rejects_caller_params_and_claim_tamper(
    case: tuple[dict[str, Any], dict[str, Any], datetime],
    tamper: str,
) -> None:
    _source, seed, now = case
    intent, _failure, _authorization, claims, event, _cfn = (
        _exact_reentry_attestation_case(seed, now)
    )
    key = f"reentry-create:route:{seed['intent_digest']}"
    claim = copy.deepcopy(claims.records[key])
    changed_event = copy.deepcopy(event)
    if tamper == "caller":
        wrong_caller = _caller(
            route.MANAGEMENT_ACCOUNT_ID,
            "ScanalyzeGug376BrokerSeedCreator",
        )
        changed_event["userIdentity"]["arn"] = wrong_caller
        claim["caller_arn_digest"] = route.digest_value(wrong_caller)
    elif tamper == "params":
        changed_event["requestParameters"]["description"] = "forged"
    else:
        claim["caller_arn_digest"] = "sha256:" + "9" * 64
    with pytest.raises(
        recovery.DeploymentRecoveryError,
        match="REENTRY_CREATE_CLOUDTRAIL_INVALID",
    ):
        recovery._reentry_create_event_digest(
            Trail(changed_event),
            account=route.MANAGEMENT_ACCOUNT_ID,
            claim=claim,
            dispatch=claims.results[key],
            request=intent["create_request"],
            now=now,
        )


def test_cleanup_terminal_journal_rejects_tampered_claim_resource_binding(
    case: tuple[dict[str, Any], dict[str, Any], datetime]
) -> None:
    _source, seed, now = case
    claims, _timeline, terminal, *_rest = _cleanup_terminal_reentry_chain(
        seed, now
    )
    key = f"cleanup:route:{seed['intent_digest']}:primary"
    claims.records[key]["failed_resources_digest"] = "sha256:" + "9" * 64
    with pytest.raises(
        recovery.DeploymentRecoveryError,
        match="FAILURE_ATTESTATION_JOURNAL_BINDING_INVALID",
    ):
        recovery._validate_cleanup_terminal_journal(
            claims,
            intent=seed,
            failure_attestation=terminal,
        )


def test_reentry_execution_binding_rejects_foreign_seed_before_aws(
    case: tuple[dict[str, Any], dict[str, Any], datetime]
) -> None:
    _source, seed, now = case
    (
        _reentry,
        _failure,
        _creation_authorization,
        dispatch,
        _attestation,
        _execution_authorization,
        execution,
    ) = _reentry_execution_chain(seed, now)
    receipt = route.seal(
        {
            "schema_version": 1,
            "record_type": recovery.REENTRY_EXECUTION_RECEIPT_RECORD_TYPE,
            "source_commit": seed["source_commit"],
            "target": "route",
            "account_id": route.MANAGEMENT_ACCOUNT_ID,
            "execution_intent_digest": execution[
                "execution_intent_digest"
            ],
            "stack_arn": dispatch["stack_arn"],
            "change_set_arn": dispatch["change_set_arn"],
            "execute_request_id": RECOVERY_REQUEST_UUID,
            "dispatched_at": _ts(now),
            "attempt": 1,
            "aws_mutations": 1,
            "retry_permitted": False,
            "production_authorized": False,
            "production_status": route.PRODUCTION_STATUS,
        },
        "receipt_digest",
    )
    foreign_seed = copy.deepcopy(seed)
    foreign_seed["source_commit"] = "b" * 40
    foreign_seed.pop("intent_digest")
    foreign_seed = route.seal(foreign_seed, "intent_digest")
    timeline: list[str] = []
    provider = recovery.ConnectedDeploymentRecoveryProvider(
        clients=_clients(
            sts=Identity(
                route.MANAGEMENT_ACCOUNT_ID,
                "AWSAdministratorAccess",
                timeline,
            ),
            cfn=EmptyService(),
            trail=EmptyService(),
        ),
        claims=Claims(timeline),
        clock=lambda: now,
    )
    with pytest.raises(
        recovery.DeploymentRecoveryError,
        match="EXECUTION_SEED_BINDING_INVALID",
    ):
        provider.attest_failed_create_stack(
            seed_intent=foreign_seed,
            execution_intent=execution,
            execution_receipt=receipt,
        )
    assert timeline == []


def test_execute_event_digest_rejects_non_null_response_elements(
    case: tuple[dict[str, Any], dict[str, Any], datetime]
) -> None:
    _source, seed, now = case
    (
        _reentry,
        _failure,
        _creation_authorization,
        dispatch,
        _attestation,
        _execution_authorization,
        execution,
    ) = _reentry_execution_chain(seed, now)
    receipt = route.seal(
        {
            "schema_version": 1,
            "record_type": recovery.REENTRY_EXECUTION_RECEIPT_RECORD_TYPE,
            "source_commit": seed["source_commit"],
            "target": "route",
            "account_id": route.MANAGEMENT_ACCOUNT_ID,
            "execution_intent_digest": execution[
                "execution_intent_digest"
            ],
            "stack_arn": dispatch["stack_arn"],
            "change_set_arn": dispatch["change_set_arn"],
            "execute_request_id": RECOVERY_REQUEST_UUID,
            "dispatched_at": _ts(now),
            "attempt": 1,
            "aws_mutations": 1,
            "retry_permitted": False,
            "production_authorized": False,
            "production_status": route.PRODUCTION_STATUS,
        },
        "receipt_digest",
    )
    caller = _caller(route.MANAGEMENT_ACCOUNT_ID, "AWSAdministratorAccess")
    claim = {
        "schema_version": 1,
        "record_type": recovery.CLAIM_RECORD_TYPE,
        "operation": "ExecuteChangeSet",
        "target": "route",
        "attempt": 1,
        "execution_intent_digest": execution["execution_intent_digest"],
        "request_digest": execution["execute_request_digest"],
        "client_request_token": execution["execute_request"][
            "ClientRequestToken"
        ],
        "stack_arn": dispatch["stack_arn"],
        "change_set_arn": dispatch["change_set_arn"],
        "caller_arn_digest": route.digest_value(caller),
        "claimed_at": _ts(now),
        "retry_permitted": False,
        "production_authorized": False,
    }
    request = execution["execute_request"]
    event = {
        "eventSource": "cloudformation.amazonaws.com",
        "eventName": "ExecuteChangeSet",
        "awsRegion": route.REGION,
        "recipientAccountId": route.MANAGEMENT_ACCOUNT_ID,
        "readOnly": False,
        "errorCode": None,
        "errorMessage": None,
        "responseElements": {"unexpected": True},
        "requestID": RECOVERY_REQUEST_UUID,
        "eventID": EVENT_UUID,
        "eventTime": _ts(now),
        "userIdentity": {"arn": caller},
        "requestParameters": {
            "stackName": request["StackName"],
            "changeSetName": request["ChangeSetName"],
            "clientRequestToken": request["ClientRequestToken"],
        },
    }
    with pytest.raises(
        recovery.DeploymentRecoveryError,
        match="EXECUTE_CLOUDTRAIL_INVALID",
    ):
        recovery._execute_event_digest(
            Trail(event),
            account=route.MANAGEMENT_ACCOUNT_ID,
            claim=claim,
            execution=execution,
            receipt=receipt,
            now=now,
        )


@pytest.mark.parametrize(
    ("target", "phase", "caller"),
    (
        (
            "broker",
            "creator",
            "arn:aws:sts::042360977644:assumed-role/"
            "AWSReservedSSO_ScanalyzeGug376BrokerSeedCreator_"
            "0123456789abcde/cesar",
        ),
        (
            "route",
            "cleanup",
            "arn:aws:sts::839393571433:assumed-role/"
            "AWSReservedSSO_ScanalyzeGug376RouteSeedCleanup_"
            "0123456789abcdef/cesar/forged",
        ),
        (
            route.BROKER_PROTECTION_TARGET,
            "executor",
            "arn:aws:sts::839393571433:assumed-role/"
            "AWSReservedSSO_ScanalyzeGug376BrokerSeedExec_"
            "0123456789abcdef/cesar",
        ),
    ),
)
def test_phase_caller_contract_rejects_invalid_broker_cleanup_and_protection_arns(
    target: str, phase: str, caller: str
) -> None:
    assert recovery._caller_arn_matches_phase(
        caller, target=target, phase=phase
    ) is False


def test_cleanup_attestation_uses_post_live_clock_and_rejects_regression(
    case: tuple[dict[str, Any], dict[str, Any], datetime]
) -> None:
    _source, seed, now = case
    claims, _timeline, _terminal, authorization, intent, event, _old_cfn = (
        _cleanup_terminal_reentry_chain(seed, now)
    )
    key = f"cleanup:route:{seed['intent_digest']}:primary"
    dispatch = claims.results[key]
    cfn = TerminalReentryCloudFormation()
    iam = AbsentIAM()
    samples = iter(
        (now, now + timedelta(seconds=10), now + timedelta(seconds=20))
    )

    def advancing_clock() -> datetime:
        value = next(samples)
        if value == now + timedelta(seconds=20):
            assert cfn.describe_calls == 2
            assert len(iam.requests) == len(recovery.ROUTE_FIXED_IAM_ROLE_NAMES)
        return value

    provider = recovery.ConnectedDeploymentRecoveryProvider(
        clients=_clients(
            sts=Identity(
                route.MANAGEMENT_ACCOUNT_ID,
                recovery.CLEANUP_ROLE_NAMES["route"],
                [],
            ),
            cfn=cfn,
            trail=Trail(event),
            iam=iam,
            sso=EmptySSO(),
        ),
        claims=claims,
        clock=advancing_clock,
    )
    attestation = provider.attest_cleanup_complete(
        seed_intent=seed,
        failed_stack_attestation=_failed_stack_attestation(seed, now),
        authorization=authorization,
        cleanup_intent=intent,
        cleanup_dispatch=dispatch,
    )
    assert attestation["attested_at"] == _ts(now + timedelta(seconds=20))

    regressed_cfn = TerminalReentryCloudFormation()
    regressed_samples = iter((now, now - timedelta(seconds=1)))
    regressed_provider = recovery.ConnectedDeploymentRecoveryProvider(
        clients=_clients(
            sts=Identity(
                route.MANAGEMENT_ACCOUNT_ID,
                recovery.CLEANUP_ROLE_NAMES["route"],
                [],
            ),
            cfn=regressed_cfn,
            trail=Trail(event),
            iam=AbsentIAM(),
            sso=EmptySSO(),
        ),
        claims=claims,
        clock=lambda: next(regressed_samples),
    )
    with pytest.raises(
        recovery.DeploymentRecoveryError, match="CLOCK_REGRESSED"
    ):
        regressed_provider.attest_cleanup_complete(
            seed_intent=seed,
            failed_stack_attestation=_failed_stack_attestation(seed, now),
            authorization=authorization,
            cleanup_intent=intent,
            cleanup_dispatch=dispatch,
        )
    assert regressed_cfn.describe_calls == 0
