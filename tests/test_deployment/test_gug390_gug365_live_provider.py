"""Provider-boundary tests for the guarded GUG-390 live adapter."""

from __future__ import annotations

import base64
import copy
from dataclasses import asdict, dataclass, field
import io
import json
from pathlib import Path
from typing import Any, Mapping

import pytest

from tooling import platform_authority_gug365_live_provider as live


ROOT = Path(__file__).resolve().parents[2]
PLAN = (
    ROOT
    / "fixtures/valid/platform-authority-retirement-entrypoint-service-role-plan-v1-synthetic.json"
)
AWS_ENV = {
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
    "AWS_PROFILE",
    "AWS_DEFAULT_PROFILE",
    "AWS_CONFIG_FILE",
    "AWS_SHARED_CREDENTIALS_FILE",
    "AWS_WEB_IDENTITY_TOKEN_FILE",
    "AWS_ROLE_ARN",
    "AWS_ENDPOINT_URL",
    "AWS_ENDPOINT_URL_STS",
    "AWS_CONTAINER_CREDENTIALS_FULL_URI",
    "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI",
    "AWS_CONTAINER_AUTHORIZATION_TOKEN",
    "AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE",
    "BOTO_CONFIG",
}


@pytest.fixture(autouse=True)
def _clean_ambient(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in AWS_ENV:
        monkeypatch.delenv(name, raising=False)


def _operation(action: str) -> tuple[str, dict[str, Any]]:
    plan = json.loads(PLAN.read_text(encoding="utf-8"))
    for phase in plan["authorization_phases"]:
        for record in phase["operations"]:
            if f"{record['service']}:{record['api_action']}" == action:
                return str(phase["phase"]), copy.deepcopy(record)
    raise AssertionError(f"fixture has no {action}")


@dataclass
class FakeState:
    account_id: str = live.AUTHORITY_ACCOUNT_ID
    principal_arn: str = ""
    sessions: list[dict[str, Any]] = field(default_factory=list)
    clients: list[tuple[str, Any]] = field(default_factory=list)
    calls: list[tuple[str, str, dict[str, Any]]] = field(default_factory=list)
    pages: dict[str, list[Mapping[str, Any]]] = field(default_factory=dict)
    errors: dict[str, BaseException] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.principal_arn:
            self.principal_arn = (
                f"arn:aws:sts::{self.account_id}:assumed-role/GUG390Synthetic/operator"
            )


class FakeConfig:
    instances: list["FakeConfig"] = []

    def __init__(self, **kwargs: Any) -> None:
        self.kwargs = kwargs
        self.instances.append(self)


class StructuredClientError(Exception):
    def __init__(self, code: str) -> None:
        self.response = {"Error": {"Code": code}}
        super().__init__("synthetic-private-provider-error")


class FakeClient:
    def __init__(self, service: str, state: FakeState) -> None:
        self.service, self.state = service, state

    def _call(self, method: str, kwargs: dict[str, Any]) -> Mapping[str, Any]:
        self.state.calls.append((self.service, method, copy.deepcopy(kwargs)))
        error = self.state.errors.get(method)
        if error is not None:
            raise error
        pages = self.state.pages.get(method)
        if pages:
            return copy.deepcopy(dict(pages.pop(0)))
        return {"ResponseMetadata": {"RequestId": "synthetic-private-request"}}

    def get_caller_identity(self) -> Mapping[str, Any]:
        self.state.calls.append(("sts", "get_caller_identity", {}))
        return {
            "Account": self.state.account_id,
            "Arn": self.state.principal_arn,
            "UserId": "synthetic-private-user-id",
        }

    def get_role(self, **kwargs: Any) -> Mapping[str, Any]:
        return self._call("get_role", kwargs)

    def get_policy(self, **kwargs: Any) -> Mapping[str, Any]:
        return self._call("get_policy", kwargs)

    def list_role_policies(self, **kwargs: Any) -> Mapping[str, Any]:
        return self._call("list_role_policies", kwargs)

    def create_policy(self, **kwargs: Any) -> Mapping[str, Any]:
        return self._call("create_policy", kwargs)

    def put_runtime_management_config(self, **kwargs: Any) -> Mapping[str, Any]:
        return self._call("put_runtime_management_config", kwargs)

    def get_runtime_management_config(self, **kwargs: Any) -> Mapping[str, Any]:
        return self._call("get_runtime_management_config", kwargs)

    def __getattr__(self, method: str) -> Any:
        if method.startswith("_"):
            raise AttributeError(method)

        def dispatch(**kwargs: Any) -> Mapping[str, Any]:
            return self._call(method, kwargs)

        return dispatch


class FakeSession:
    def __init__(self, state: FakeState) -> None:
        self.state = state

    def client(self, service_name: str, *, config: Any = None, **_kwargs: Any) -> Any:
        self.state.clients.append((service_name, config))
        return FakeClient(service_name, self.state)


class FakeSessionFactory:
    def __init__(self, state: FakeState) -> None:
        self.state = state

    def __call__(self, *args: Any, **kwargs: Any) -> FakeSession:
        self.state.sessions.append({"args": args, "kwargs": copy.deepcopy(kwargs)})
        return FakeSession(self.state)


def _install_concrete_session(
    monkeypatch: pytest.MonkeyPatch,
    state: FakeState,
    *,
    permission_set_name: str = "GUG390Synthetic",
    source_profile: bool = False,
    credential_method: str = "sso",
    session_region: str = live.REGION,
) -> None:
    profile = {
        "sso_account_id": live.AUTHORITY_ACCOUNT_ID,
        "sso_role_name": permission_set_name,
        "sso_session": "synthetic-sso",
        "region": live.REGION,
    }
    if source_profile:
        profile["source_profile"] = "forbidden-chain"

    class Credentials:
        method = credential_method

    class ConcreteSession(FakeSession):
        region_name = session_region
        _session = type(
            "Core",
            (),
            {
                "full_config": {
                    "profiles": {"gug390-synthetic": profile},
                    "sso_sessions": {
                        "synthetic-sso": {
                            "sso_start_url": "https://synthetic.invalid/start",
                            "sso_region": live.REGION,
                        }
                    },
                }
            },
        )()

        def get_credentials(self) -> Credentials:
            return Credentials()

    class Boto3:
        @staticmethod
        def Session(**kwargs: Any) -> ConcreteSession:
            state.sessions.append({"args": (), "kwargs": copy.deepcopy(kwargs)})
            return ConcreteSession(state)

    monkeypatch.setattr(live, "_load_boto3", lambda: (Boto3, FakeConfig))


def _open(
    monkeypatch: pytest.MonkeyPatch,
    state: FakeState | None = None,
    **config_values: Any,
) -> tuple[live.LiveProvider, FakeState]:
    selected = state or FakeState()
    FakeConfig.instances.clear()
    monkeypatch.setattr(live, "_load_boto3", lambda: (object(), FakeConfig))
    config = live.ProviderConfig(profile_name="gug390-synthetic", **config_values)
    provider = live.LiveProvider.open(
        config, session_factory=FakeSessionFactory(selected)
    )
    return provider, selected


@pytest.mark.parametrize("profile", ["", "default", "DEFAULT"])
def test_profile_gate_rejects_missing_or_default_before_session(
    monkeypatch: pytest.MonkeyPatch, profile: str
) -> None:
    state = FakeState()
    monkeypatch.setattr(live, "_load_boto3", lambda: (object(), FakeConfig))
    with pytest.raises(live.LiveProviderError):
        config = live.ProviderConfig(profile_name=profile)
        live.LiveProvider.open(config, session_factory=FakeSessionFactory(state))
    assert state.sessions == [] and state.calls == []


@pytest.mark.parametrize("name", sorted(AWS_ENV))
def test_ambient_credentials_and_endpoint_overrides_stop_before_session(
    monkeypatch: pytest.MonkeyPatch, name: str
) -> None:
    state = FakeState()
    monkeypatch.setenv(name, "synthetic-forbidden")
    monkeypatch.setattr(live, "_load_boto3", lambda: (object(), FakeConfig))
    with pytest.raises(live.LiveProviderError):
        live.LiveProvider.open(
            live.ProviderConfig(profile_name="gug390-synthetic"),
            session_factory=FakeSessionFactory(state),
        )
    assert state.sessions == [] and state.calls == []


def test_region_gate_stops_before_session(monkeypatch: pytest.MonkeyPatch) -> None:
    state = FakeState()
    with pytest.raises(live.LiveProviderError):
        config = live.ProviderConfig(
            profile_name="gug390-synthetic", region="us-west-2"
        )
        live.LiveProvider.open(config, session_factory=FakeSessionFactory(state))
    assert state.sessions == [] and state.calls == []


def test_open_uses_explicit_profile_sts_first_and_disabled_sdk_retries(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    provider, state = _open(monkeypatch)
    assert state.sessions == [
        {
            "args": (),
            "kwargs": {
                "profile_name": "gug390-synthetic",
                "region_name": live.REGION,
            },
        }
    ]
    assert state.calls == [("sts", "get_caller_identity", {})]
    assert state.clients[0][0] == "sts"
    assert len(FakeConfig.instances) == 1
    config = FakeConfig.instances[0].kwargs
    assert config["region_name"] == live.REGION
    assert config["retries"]["mode"] == "standard"
    assert (
        config["retries"].get("max_attempts") == 0
        or config["retries"].get("total_max_attempts") == 1
    )
    assert provider.identity_receipt.account_digest
    assert provider.identity_receipt.principal_digest
    transcript = provider.transcript_summary()
    assert transcript.provider_calls == len(state.calls) == 1
    assert transcript.provider_mutation_calls == 0


def test_validity_gate_runs_before_sts_and_every_paginated_sdk_call(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = FakeState(
        pages={
            "list_role_policies": [
                {"PolicyNames": ["one"], "IsTruncated": True, "Marker": "next"},
                {"PolicyNames": ["two"], "IsTruncated": False},
            ]
        }
    )
    gate_observations: list[tuple[int, int]] = []

    def validity_gate() -> None:
        gate_observations.append((len(state.clients), len(state.calls)))
        if len(gate_observations) == 4:
            raise live.LiveProviderError("REQUEST_WINDOW_INVALID")

    provider, state = _open(
        monkeypatch,
        state,
        validity_gate=validity_gate,
    )
    phase, record = _operation("iam:ListRolePolicies")
    with pytest.raises(live.LiveProviderError, match="REQUEST_WINDOW_INVALID"):
        provider.read_operation(live.planned_call_from_record(phase, record))

    assert gate_observations == [
        (0, 0),  # Local authority window gate before session construction.
        (1, 0),  # Gate immediately before the opening STS call.
        (2, 1),  # IAM client exists, but gate precedes its first SDK call.
        (2, 2),  # Expired gate before the second IAM page.
    ]
    assert state.calls == [
        ("sts", "get_caller_identity", {}),
        ("iam", "list_role_policies", record["request"]),
    ]


def test_sts_account_mismatch_stops_before_resource_client(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = FakeState(account_id="000000000000")
    with pytest.raises(live.LiveProviderError):
        _open(monkeypatch, state)
    assert state.calls == [("sts", "get_caller_identity", {})]
    assert [service for service, _config in state.clients] == ["sts"]


def test_phase_identity_performs_second_sts_on_the_same_session(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    provider, state = _open(monkeypatch)
    phase, record = _operation("sts:GetCallerIdentity")
    result = provider.invoke_operation(live.planned_call_from_record(phase, record))
    assert state.calls == [
        ("sts", "get_caller_identity", {}),
        ("sts", "get_caller_identity", {}),
    ]
    assert [service for service, _config in state.clients] == ["sts"]
    assert result.outcome is live.Outcome.SUCCEEDED
    assert result.operation_calls == 1
    assert result.response["same_session"] is True
    assert provider.transcript_summary().provider_calls == 2


def test_phase_identity_rejects_changed_principal_on_second_sts(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    provider, state = _open(monkeypatch)
    state.principal_arn = (
        f"arn:aws:sts::{state.account_id}:assumed-role/GUG390Synthetic/substitute"
    )
    phase, record = _operation("sts:GetCallerIdentity")
    result = provider.invoke_operation(live.planned_call_from_record(phase, record))
    assert [item for item in state.calls if item[1] == "get_caller_identity"] == [
        ("sts", "get_caller_identity", {}),
        ("sts", "get_caller_identity", {}),
    ]
    assert result.outcome is live.Outcome.FAILED
    assert result.response["same_session"] is False
    assert result.reconciliation_required is False


def test_concrete_direct_sso_profile_and_generated_role_are_both_bound(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    permission_set = "GUG390Synthetic"
    state = FakeState(
        principal_arn=(
            f"arn:aws:sts::{live.AUTHORITY_ACCOUNT_ID}:assumed-role/"
            f"AWSReservedSSO_{permission_set}_0123456789abcdef/operator"
        )
    )
    _install_concrete_session(
        monkeypatch, state, permission_set_name=permission_set
    )
    gate_calls: list[int] = []

    provider = live.build_live_provider(
        live.ProviderConfig(
            profile_name="gug390-synthetic",
            expected_principal_digest=live.canonical_digest(state.principal_arn),
            expected_sso_role_name_digest=live.canonical_digest(permission_set),
            validity_gate=lambda: gate_calls.append(len(state.calls)),
        )
    )

    assert state.calls == [("sts", "get_caller_identity", {})]
    assert gate_calls == [0, 0]
    assert provider.provider_mode == "CONCRETE_DIRECT_SSO"
    assert provider.identity_receipt.concrete_provider is True
    assert provider.identity_receipt.principal_digest == live.canonical_digest(
        state.principal_arn
    )
    assert provider.identity_receipt.sso_role_name_digest == live.canonical_digest(
        permission_set
    )


@pytest.mark.parametrize(
    ("fault", "expected_code"),
    [
        ("source_profile", "DIRECT_SSO_PROFILE_REQUIRED"),
        ("credential_method", "DIRECT_SSO_CREDENTIALS_REQUIRED"),
        ("region", "REGION_BINDING_INVALID"),
    ],
)
def test_concrete_profile_must_be_direct_sso(
    monkeypatch: pytest.MonkeyPatch, fault: str, expected_code: str
) -> None:
    permission_set = "GUG390Synthetic"
    state = FakeState(
        principal_arn=(
            f"arn:aws:sts::{live.AUTHORITY_ACCOUNT_ID}:assumed-role/"
            f"AWSReservedSSO_{permission_set}_0123456789abcdef/operator"
        )
    )
    _install_concrete_session(
        monkeypatch,
        state,
        permission_set_name=permission_set,
        source_profile=fault == "source_profile",
        credential_method=(
            "assume-role" if fault == "credential_method" else "sso"
        ),
        session_region="us-west-2" if fault == "region" else live.REGION,
    )
    with pytest.raises(live.LiveProviderError) as error:
        live.build_live_provider(
            live.ProviderConfig(
                profile_name="gug390-synthetic",
                expected_principal_digest=live.canonical_digest(
                    state.principal_arn
                ),
                expected_sso_role_name_digest=live.canonical_digest(
                    permission_set
                ),
                validity_gate=lambda: None,
            )
        )
    assert error.value.code == expected_code
    assert state.calls == []


@pytest.mark.parametrize("fault", ["generated_role", "principal_digest"])
def test_concrete_sts_identity_requires_exact_principal_and_generated_sso_role(
    monkeypatch: pytest.MonkeyPatch, fault: str
) -> None:
    permission_set = "GUG390Synthetic"
    generated_role = f"AWSReservedSSO_{permission_set}_0123456789abcdef"
    if fault == "generated_role":
        generated_role = permission_set
    state = FakeState(
        principal_arn=(
            f"arn:aws:sts::{live.AUTHORITY_ACCOUNT_ID}:assumed-role/"
            f"{generated_role}/operator"
        )
    )
    _install_concrete_session(
        monkeypatch, state, permission_set_name=permission_set
    )
    expected_principal = (
        live.canonical_digest("substituted-principal")
        if fault == "principal_digest"
        else live.canonical_digest(state.principal_arn)
    )

    with pytest.raises(
        live.LiveProviderError, match="STS_CALLER_BINDING_MISMATCH"
    ):
        live.build_live_provider(
            live.ProviderConfig(
                profile_name="gug390-synthetic",
                expected_principal_digest=expected_principal,
                expected_sso_role_name_digest=live.canonical_digest(
                    permission_set
                ),
                validity_gate=lambda: None,
            )
        )
    assert state.calls == [("sts", "get_caller_identity", {})]


def test_every_phase_operation_maps_to_the_closed_catalog() -> None:
    plan = json.loads(PLAN.read_text(encoding="utf-8"))
    phases = [*plan["authorization_phases"], plan["revocation"]]
    calls = [
        live.planned_call_from_record(str(phase["phase"]), record, plan=plan)
        for phase in phases
        for record in phase["operations"]
    ]
    kms_projection = {
        "<OBSERVED_TABLE_SSE_DESCRIPTION_KMS_MASTER_KEY_ARN>": (
            f"arn:aws:kms:{live.REGION}:{live.AUTHORITY_ACCOUNT_ID}:key/"
            "00000000-0000-4000-8000-000000000390"
        )
    }
    calls.extend(
        live.planned_call_from_record(
            "READBACK", record, slot_projections=kms_projection
        )
        for record in plan["planned_readbacks"]
    )
    assert calls
    assert {call.allowed_action for call in calls} == set(live.ALLOWED_ACTIONS)
    assert all(call.request_digest == live.canonical_digest(call.request) for call in calls)


def _catalog_calls() -> tuple[dict[str, Any], dict[str, live.PlannedCall]]:
    plan = json.loads(PLAN.read_text(encoding="utf-8"))
    calls: list[live.PlannedCall] = []
    for phase in [*plan["authorization_phases"], plan["revocation"]]:
        calls.extend(
            live.planned_call_from_record(
                str(phase["phase"]), record, plan=plan
            )
            for record in phase["operations"]
        )
    kms_projection = {
        "<OBSERVED_TABLE_SSE_DESCRIPTION_KMS_MASTER_KEY_ARN>": (
            f"arn:aws:kms:{live.REGION}:{live.AUTHORITY_ACCOUNT_ID}:key/"
            "00000000-0000-4000-8000-000000000390"
        )
    }
    calls.extend(
        live.planned_call_from_record(
            "READBACK", record, slot_projections=kms_projection
        )
        for record in plan["planned_readbacks"]
    )
    selected: dict[str, live.PlannedCall] = {}
    for action in sorted(live.ALLOWED_ACTIONS):
        candidates = [call for call in calls if call.allowed_action == action]
        assert candidates, action
        direct = next(
            (
                call
                for call in candidates
                if call.api_action == action.split(":", 1)[1]
                and call.kind is not live.CallKind.WAITER
            ),
            candidates[0],
        )
        selected[action] = direct
    assert len(selected) == 42
    assert set(selected) == set(live.ALLOWED_ACTIONS)
    return plan, selected


def _waiter_call(api_action: str) -> live.PlannedCall:
    plan = json.loads(PLAN.read_text(encoding="utf-8"))
    matches: list[tuple[str, dict[str, Any]]] = []
    for phase in plan["authorization_phases"]:
        matches.extend(
            (str(phase["phase"]), copy.deepcopy(record))
            for record in phase["operations"]
            if record.get("api_action") == api_action
        )
    matches.extend(
        ("READBACK", copy.deepcopy(record))
        for record in plan["planned_readbacks"]
        if record.get("api_action") == api_action
    )
    assert matches
    phase, record = matches[0]
    record["poll_interval_seconds"] = 0
    record["max_poll_attempts"] = 2
    record["timeout_seconds"] = 1
    record.pop("request_digest", None)
    return live.planned_call_from_record(phase, record)


@pytest.mark.parametrize(
    "action", sorted(live.MUTATION_ACTIONS - {"lambda:InvokeFunction"})
)
def test_reconciliation_contract_is_derived_from_the_exact_ambiguous_mutation(
    monkeypatch: pytest.MonkeyPatch,
    action: str,
) -> None:
    _plan, calls = _catalog_calls()
    ambiguous = calls[action]
    provider, _state = _open(monkeypatch)

    readbacks = provider.reconciliation_readback_calls(ambiguous)

    assert readbacks == provider._mutation_readback_calls(  # noqa: SLF001
        ambiguous
    )
    assert readbacks
    assert all(
        type(item) is live.PlannedCall
        and item.kind in {live.CallKind.READ, live.CallKind.WAITER}
        and item.phase == ambiguous.phase
        and item.sequence == ambiguous.sequence
        for item in readbacks
    )
    assert all(item.allowed_action not in live.MUTATION_ACTIONS for item in readbacks)


def test_invoke_ambiguity_has_no_false_readback_contract(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _plan, calls = _catalog_calls()
    provider, _state = _open(monkeypatch)

    with pytest.raises(
        live.LiveProviderError, match="RECONCILIATION_CONTRACT_UNAVAILABLE"
    ):
        provider.reconciliation_readback_calls(calls["lambda:InvokeFunction"])


def _valid_causal_receipt(plan: Mapping[str, Any]) -> dict[str, Any]:
    from tooling import (
        platform_authority_retirement_entrypoint_service_role_materializer as materializer,
    )

    factory = plan["ledger_factory_function"]
    body: dict[str, Any] = {
        "artifact_type": materializer.ledger_factory.RECEIPT_ARTIFACT_TYPE,
        "schema_version": 1,
        "status": "CREATED",
        "reason_code": "LEDGER_EXACT_FULL_READBACK",
        "attempt": 1,
        "create_table_call_count": 1,
        "update_pitr_call_count": 1,
        "retry_permitted": False,
        "next_required_action": "REVOKE_FACTORY_AUTHORITY",
        "request_sha256": materializer.canonical_digest({}),
        "contract_sha256": materializer.ledger_factory.CONTRACT_SHA256,
        "qualified_function_sha256": materializer.canonical_digest(
            {"qualified_function_arn": factory["immutable_version_arn"]}
        ),
        "resource_policy_sha256": materializer.canonical_digest(
            materializer._ledger_resource_policy()  # noqa: SLF001
        ),
        "kms_key_arn_sha256": "sha256:" + "6" * 64,
        "kms_key_metadata_sha256": "sha256:" + "7" * 64,
        "revision_id_sha256": "sha256:" + "8" * 64,
        "active_readback_attempt_count": 2,
        "policy_readback_attempt_count": 2,
        "pitr_readback_attempt_count": 1,
    }
    return {**body, "receipt_sha256": materializer.canonical_digest(body)}


def _read_response(action: str) -> dict[str, Any]:
    paginated: dict[str, dict[str, Any]] = {
        "iam:ListAttachedRolePolicies": {
            "AttachedPolicies": [],
            "IsTruncated": False,
        },
        "iam:ListEntitiesForPolicy": {
            "PolicyGroups": [],
            "PolicyRoles": [],
            "PolicyUsers": [],
            "IsTruncated": False,
        },
        "iam:ListPolicyTags": {"Tags": [], "IsTruncated": False},
        "iam:ListPolicyVersions": {"Versions": [], "IsTruncated": False},
        "iam:ListRolePolicies": {"PolicyNames": [], "IsTruncated": False},
        "iam:ListRoleTags": {"Tags": [], "IsTruncated": False},
        "lambda:ListAliases": {"Aliases": []},
        "lambda:ListFunctionUrlConfigs": {"FunctionUrlConfigs": []},
        "lambda:ListTags": {"Tags": {}},
        "lambda:ListVersionsByFunction": {"Versions": []},
        "dynamodb:ListTagsOfResource": {"Tags": []},
    }
    return copy.deepcopy(paginated.get(action, {"synthetic": "present"}))


def _role_readback(call: live.PlannedCall) -> dict[str, Any]:
    request = call.request
    role: dict[str, Any] = {
        "Arn": call.target_arn,
        "RoleName": request["RoleName"],
        "Path": request.get("Path", "/"),
        "PermissionsBoundary": {
            "PermissionsBoundaryArn": request["PermissionsBoundary"]
        },
    }
    for field in (
        "AssumeRolePolicyDocument",
        "Description",
        "MaxSessionDuration",
        "Tags",
    ):
        if field in request:
            role[field] = copy.deepcopy(request[field])
    return {"Role": role}


def _function_readback(
    call: live.PlannedCall, *, code_sha256: str
) -> dict[str, Any]:
    request = call.request
    configuration: dict[str, Any] = {
        "FunctionArn": call.target_arn,
        "FunctionName": request["FunctionName"],
        "Version": "$LATEST",
        "CodeSha256": code_sha256,
    }
    for field in (
        "Description",
        "Runtime",
        "Role",
        "Handler",
        "Timeout",
        "MemorySize",
        "PackageType",
        "Architectures",
        "Environment",
        "CodeSigningConfigArn",
        "LoggingConfig",
    ):
        if field in request:
            configuration[field] = copy.deepcopy(request[field])
    return {"Configuration": configuration}


def _configure_positive_mutation(
    state: FakeState,
    call: live.PlannedCall,
    plan: Mapping[str, Any],
) -> None:
    action = call.allowed_action
    request = call.request
    if action == "iam:CreatePolicy":
        state.pages["get_policy"] = [
            {
                "Policy": {
                    "Arn": call.target_arn,
                    "PolicyName": request["PolicyName"],
                    "Path": request["Path"],
                    "Description": request.get("Description"),
                    "DefaultVersionId": "v1",
                }
            }
        ]
        state.pages["get_policy_version"] = [
            {
                "PolicyVersion": {
                    "VersionId": "v1",
                    "IsDefaultVersion": True,
                    "Document": request["PolicyDocument"],
                }
            }
        ]
        state.pages["list_policy_tags"] = [
            {"Tags": copy.deepcopy(request["Tags"]), "IsTruncated": False}
        ]
    elif action in {"iam:CreateRole", "iam:PutRolePermissionsBoundary"}:
        state.pages["get_role"] = [_role_readback(call)]
        if action == "iam:CreateRole":
            state.pages["list_role_tags"] = [
                {"Tags": copy.deepcopy(request["Tags"]), "IsTruncated": False}
            ]
    elif action in {"iam:AttachRolePolicy", "iam:DetachRolePolicy"}:
        policies = (
            [{"PolicyArn": request["PolicyArn"]}]
            if action == "iam:AttachRolePolicy"
            else []
        )
        state.pages["list_attached_role_policies"] = [
            {"AttachedPolicies": policies, "IsTruncated": False}
        ]
    elif action == "lambda:CreateFunction":
        contract_key = (
            "broker_function"
            if call.phase == "FUNCTION_FACTORY"
            else "ledger_factory_function"
        )
        code_sha256 = plan[contract_key]["signed_code"]["lambda_code_sha256"]
        write_version = "1" if request.get("Publish") is True else "$LATEST"
        state.pages["create_function"] = [
            {"Version": write_version, "CodeSha256": code_sha256}
        ]
        function = _function_readback(call, code_sha256=code_sha256)
        configuration = function["Configuration"]
        configuration.update(
            {
                "VpcConfig": {
                    "SubnetIds": [],
                    "SecurityGroupIds": [],
                    "VpcId": "",
                },
                "Layers": [],
                "FileSystemConfigs": [],
                "TracingConfig": {"Mode": "PassThrough"},
                "EphemeralStorage": {"Size": 512},
                "KMSKeyArn": "",
                "DeadLetterConfig": {},
            }
        )
        state.pages["get_function"] = [function]
        state.pages["get_function_code_signing_config"] = [
            {"CodeSigningConfigArn": request["CodeSigningConfigArn"]}
        ]
        state.pages["list_tags"] = [{"Tags": copy.deepcopy(request["Tags"])}]
        versions = [{"Version": "$LATEST", "CodeSha256": code_sha256}]
        if request.get("Publish") is True:
            versions.append({"Version": "1", "CodeSha256": code_sha256})
        state.pages["list_versions_by_function"] = [{"Versions": versions}]
    elif action == "lambda:PutFunctionConcurrency":
        state.pages["get_function_concurrency"] = [
            {
                "ReservedConcurrentExecutions": request[
                    "ReservedConcurrentExecutions"
                ]
            }
        ]
    elif action == "lambda:PutRuntimeManagementConfig":
        qualifier = request.get("Qualifier")
        function_arn = f"{call.target_arn}:{qualifier}" if qualifier else call.target_arn
        state.pages["get_runtime_management_config"] = [
            {
                "FunctionArn": function_arn,
                "UpdateRuntimeOn": request["UpdateRuntimeOn"],
                "RuntimeVersionArn": request.get("RuntimeVersionArn"),
            }
        ]
    elif action in {"logs:CreateLogGroup", "logs:PutRetentionPolicy"}:
        group: dict[str, Any] = {"logGroupName": request["logGroupName"]}
        if action == "logs:CreateLogGroup":
            group["logGroupArn"] = call.target_arn
            group["logGroupClass"] = request.get("logGroupClass")
            group["deletionProtectionEnabled"] = request.get(
                "deletionProtectionEnabled"
            )
            state.pages["list_tags_for_resource"] = [
                {"tags": copy.deepcopy(request["tags"])}
            ]
        else:
            group["retentionInDays"] = request["retentionInDays"]
        state.pages["describe_log_groups"] = [{"logGroups": [group]}]
    elif action == "lambda:InvokeFunction":
        receipt = _valid_causal_receipt(plan)
        state.pages["invoke"] = [
            {
                "StatusCode": 200,
                "ExecutedVersion": call.target_arn.rsplit(":", 1)[-1],
                "Payload": io.BytesIO(
                    json.dumps(receipt, sort_keys=True).encode("utf-8")
                ),
            }
        ]
    else:  # pragma: no cover - catalog assertion protects this branch
        raise AssertionError(action)


@pytest.mark.parametrize("action", sorted(live.ALLOWED_ACTIONS))
def test_closed_catalog_dispatch_and_readback_matrix(
    monkeypatch: pytest.MonkeyPatch,
    action: str,
) -> None:
    plan, calls = _catalog_calls()
    call = calls[action]
    state = FakeState()
    service, method = (live._READ_METHODS | live._MUTATION_METHODS)[  # noqa: SLF001
        action
    ]
    if call.kind is live.CallKind.READ:
        state.pages[method] = [_read_response(action)]
    elif call.kind is live.CallKind.MUTATION:
        _configure_positive_mutation(state, call, plan)
    provider, state = _open(monkeypatch, state)

    result = (
        provider.invoke_operation(call, receipt_plan=plan)
        if action == "lambda:InvokeFunction"
        else provider.invoke_operation(call)
    )

    assert result.outcome is live.Outcome.SUCCEEDED, action
    dispatched = [item for item in state.calls if item[0] != "sts"]
    if action == "sts:GetCallerIdentity":
        assert state.calls[-1] == ("sts", "get_caller_identity", {})
        assert result.operation_calls == 1
    else:
        assert dispatched[0] == (service, method, call.request)
        expected_calls = (
            1 + len(provider._mutation_readback_calls(call))  # noqa: SLF001
            if action in live.MUTATION_ACTIONS
            else 1
        )
        assert result.operation_calls == expected_calls


@pytest.mark.parametrize(
    ("publish", "expected_write_version", "expected_versions"),
    [
        (False, "$LATEST", {"$LATEST"}),
        (True, "1", {"$LATEST", "1"}),
    ],
)
def test_create_function_uses_real_version_and_code_hash_bindings(
    monkeypatch: pytest.MonkeyPatch,
    publish: bool,
    expected_write_version: str,
    expected_versions: set[str],
) -> None:
    plan = json.loads(PLAN.read_text(encoding="utf-8"))
    matches = [
        (str(phase["phase"]), copy.deepcopy(record))
        for phase in plan["authorization_phases"]
        for record in phase["operations"]
        if record.get("allowed_action") == "lambda:CreateFunction"
        and record["request"].get("Publish") is publish
    ]
    assert len(matches) == 1
    phase, record = matches[0]
    call = live.planned_call_from_record(phase, record, plan=plan)
    state = FakeState()
    _configure_positive_mutation(state, call, plan)
    provider, state = _open(monkeypatch, state)

    result = provider.invoke_operation(call)

    assert result.outcome is live.Outcome.SUCCEEDED
    assert result.operation_calls == 5
    mutation_response = result.response["mutation_response"]
    assert mutation_response["Version"] == expected_write_version
    assert isinstance(mutation_response["CodeSha256"], str)
    contract_key = (
        "broker_function"
        if phase == "FUNCTION_FACTORY"
        else "ledger_factory_function"
    )
    expected_code_sha256 = plan[contract_key]["signed_code"][
        "lambda_code_sha256"
    ]
    assert mutation_response["CodeSha256"] == expected_code_sha256
    assert call.expected_code_sha256 == expected_code_sha256
    version_readback = next(
        item
        for item in result.response["immediate_readbacks"]
        if item["operation_digest"]
        == provider._mutation_readback_calls(call)[3].operation_digest  # noqa: SLF001
    )
    assert {
        item["Version"] for item in version_readback["response"]["Versions"]
    } == expected_versions
    assert {
        item["CodeSha256"] for item in version_readback["response"]["Versions"]
    } == {expected_code_sha256}
    assert len([item for item in state.calls if item[1] == "create_function"]) == 1


@pytest.mark.parametrize("publish", [False, True])
def test_create_function_rejects_a_self_consistent_non_plan_code_hash(
    monkeypatch: pytest.MonkeyPatch,
    publish: bool,
) -> None:
    plan = json.loads(PLAN.read_text(encoding="utf-8"))
    phase, record = next(
        (str(phase["phase"]), copy.deepcopy(record))
        for phase in plan["authorization_phases"]
        for record in phase["operations"]
        if record.get("allowed_action") == "lambda:CreateFunction"
        and record["request"].get("Publish") is publish
    )
    call = live.planned_call_from_record(phase, record, plan=plan)
    state = FakeState()
    _configure_positive_mutation(state, call, plan)
    substituted = base64.b64encode(b"x" * 32).decode("ascii")
    assert substituted != call.expected_code_sha256
    state.pages["create_function"][0]["CodeSha256"] = substituted
    state.pages["get_function"][0]["Configuration"]["CodeSha256"] = substituted
    for version in state.pages["list_versions_by_function"][0]["Versions"]:
        version["CodeSha256"] = substituted
    provider, state = _open(monkeypatch, state)

    result = provider.invoke_operation(call)

    assert result.outcome is live.Outcome.AMBIGUOUS
    assert result.error_code == "MUTATION_READBACK_MALFORMED"
    assert result.reconciliation_required is True
    assert len([item for item in state.calls if item[1] == "create_function"]) == 1


def test_create_function_without_a_sealed_plan_hash_stops_before_write(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plan = json.loads(PLAN.read_text(encoding="utf-8"))
    phase, record = next(
        (str(phase["phase"]), copy.deepcopy(record))
        for phase in plan["authorization_phases"]
        for record in phase["operations"]
        if record.get("allowed_action") == "lambda:CreateFunction"
    )
    call = live.planned_call_from_record(phase, record)
    assert call.expected_code_sha256 is None
    provider, state = _open(monkeypatch)

    with pytest.raises(
        live.LiveProviderError, match="CREATE_FUNCTION_CODE_BINDING_REQUIRED"
    ):
        provider.invoke_operation(call)

    assert state.calls == [("sts", "get_caller_identity", {})]


def test_published_create_function_rejects_a_substituted_immutable_version(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plan = json.loads(PLAN.read_text(encoding="utf-8"))
    matches = [
        (str(phase["phase"]), copy.deepcopy(record))
        for phase in plan["authorization_phases"]
        for record in phase["operations"]
        if record.get("allowed_action") == "lambda:CreateFunction"
        and record["request"].get("Publish") is True
    ]
    assert len(matches) == 1
    phase, record = matches[0]
    call = live.planned_call_from_record(phase, record, plan=plan)
    state = FakeState()
    _configure_positive_mutation(state, call, plan)
    expected_code_sha256 = call.expected_code_sha256
    state.pages["create_function"][0]["Version"] = "2"
    state.pages["list_versions_by_function"][0]["Versions"] = [
        {"Version": "$LATEST", "CodeSha256": expected_code_sha256},
        {"Version": "2", "CodeSha256": expected_code_sha256},
    ]
    provider, state = _open(monkeypatch, state)

    result = provider.invoke_operation(call)

    assert result.outcome is live.Outcome.AMBIGUOUS
    assert result.error_code == "MUTATION_READBACK_MALFORMED"
    assert result.reconciliation_required is True
    assert len([item for item in state.calls if item[1] == "create_function"]) == 1


@pytest.mark.parametrize("action", sorted(live.MUTATION_ACTIONS))
def test_every_mutation_transport_uncertainty_is_ambiguous_without_retry(
    monkeypatch: pytest.MonkeyPatch,
    action: str,
) -> None:
    plan, calls = _catalog_calls()
    call = calls[action]
    _service, method = live._MUTATION_METHODS[action]  # noqa: SLF001
    state = FakeState(errors={method: TimeoutError("synthetic-private")})
    provider, state = _open(monkeypatch, state)

    result = (
        provider.invoke_operation(call, receipt_plan=plan)
        if action == "lambda:InvokeFunction"
        else provider.invoke_operation(call)
    )

    writes = [item for item in state.calls if item[1] == method]
    assert writes == [(call.service, method, call.request)]
    assert result.outcome is live.Outcome.AMBIGUOUS
    assert result.operation_calls == 1
    assert result.reconciliation_required is True


@pytest.mark.parametrize(
    ("action", "readback_method", "drift"),
    [
        (
            "iam:CreatePolicy",
            "get_policy_version",
            lambda value: value["PolicyVersion"].update(
                {"Document": '{"Version":"2012-10-17","Statement":[]}'}
            ),
        ),
        (
            "iam:CreateRole",
            "get_role",
            lambda value: value["Role"].update(
                {
                    "AssumeRolePolicyDocument": (
                        '{"Version":"2012-10-17","Statement":[]}'
                    )
                }
            ),
        ),
        (
            "iam:CreateRole",
            "list_role_tags",
            lambda value: value.update({"Tags": []}),
        ),
        (
            "iam:PutRolePermissionsBoundary",
            "get_role",
            lambda value: value["Role"]["PermissionsBoundary"].update(
                {"PermissionsBoundaryArn": "arn:aws:iam::042360977644:policy/drift"}
            ),
        ),
        (
            "lambda:CreateFunction",
            "get_function",
            lambda value: value["Configuration"].update(
                {"Handler": "substituted.handler"}
            ),
        ),
        (
            "lambda:CreateFunction",
            "get_function",
            lambda value: value["Configuration"].update(
                {"CodeSha256": "c3Vic3RpdHV0ZWQtY29kZS1zaGEyNTY="}
            ),
        ),
        (
            "lambda:CreateFunction",
            "list_tags",
            lambda value: value.update({"Tags": {}}),
        ),
        (
            "lambda:PutFunctionConcurrency",
            "get_function_concurrency",
            lambda value: value.update({"ReservedConcurrentExecutions": 99}),
        ),
        (
            "lambda:PutRuntimeManagementConfig",
            "get_runtime_management_config",
            lambda value: value.update(
                {
                    "RuntimeVersionArn": (
                        "arn:aws:lambda:us-east-1::runtime:" + "f" * 64
                    )
                }
            ),
        ),
        (
            "logs:PutRetentionPolicy",
            "describe_log_groups",
            lambda value: value["logGroups"][0].update({"retentionInDays": 1}),
        ),
    ],
)
def test_non_identity_readback_drift_is_ambiguous_without_write_retry(
    monkeypatch: pytest.MonkeyPatch,
    action: str,
    readback_method: str,
    drift: Any,
) -> None:
    plan, calls = _catalog_calls()
    call = calls[action]
    state = FakeState()
    _configure_positive_mutation(state, call, plan)
    drift(state.pages[readback_method][0])
    provider, state = _open(monkeypatch, state)

    result = provider.invoke_operation(call)

    _service, write_method = live._MUTATION_METHODS[action]  # noqa: SLF001
    assert len([item for item in state.calls if item[1] == write_method]) == 1
    assert result.outcome is live.Outcome.AMBIGUOUS
    assert result.operation_calls == 1 + len(  # noqa: SLF001
        provider._mutation_readback_calls(call)
    )
    assert result.reconciliation_required is True


@pytest.mark.parametrize("executed_version", [None, "2"])
def test_invoke_requires_exact_executed_version_for_causal_receipt(
    monkeypatch: pytest.MonkeyPatch,
    executed_version: str | None,
) -> None:
    plan, calls = _catalog_calls()
    call = calls["lambda:InvokeFunction"]
    state = FakeState()
    _configure_positive_mutation(state, call, plan)
    response = state.pages["invoke"][0]
    if executed_version is None:
        response.pop("ExecutedVersion")
    else:
        response["ExecutedVersion"] = executed_version
    provider, state = _open(monkeypatch, state)

    result = provider.invoke_operation(call, receipt_plan=plan)

    assert len([item for item in state.calls if item[1] == "invoke"]) == 1
    assert result.outcome is live.Outcome.AMBIGUOUS
    assert result.error_code == "CAUSAL_RECEIPT_RESPONSE_INVALID"
    assert result.reconciliation_required is True
    assert provider.accepted_causal_receipt_digest is None


@pytest.mark.parametrize("action", ["iam:GetRole", "iam:CreatePolicy"])
def test_exact_plan_dispatch_uses_only_the_bound_request(
    monkeypatch: pytest.MonkeyPatch, action: str
) -> None:
    phase, record = _operation(action)
    plan = json.loads(PLAN.read_text(encoding="utf-8"))
    call = live.planned_call_from_record(phase, record)
    state = FakeState()
    if action == "iam:CreatePolicy":
        _configure_positive_mutation(state, call, plan)
    provider, state = _open(monkeypatch, state)
    result = provider.invoke_operation(call)
    method = action.split(":", 1)[1]
    snake = "".join(("_" + char.lower()) if char.isupper() else char for char in method).lstrip("_")
    resource_calls = [item for item in state.calls if item[0] != "sts"]
    assert resource_calls[0] == (record["service"], snake, record["request"])
    if action == "iam:CreatePolicy":
        assert resource_calls == [
            ("iam", "create_policy", record["request"]),
            ("iam", "get_policy", {"PolicyArn": record["target_arn"]}),
            (
                "iam",
                "get_policy_version",
                {"PolicyArn": record["target_arn"], "VersionId": "v1"},
            ),
            (
                "iam",
                "list_policy_tags",
                {"PolicyArn": record["target_arn"]},
            ),
        ]
        assert result.operation_calls == 4
    else:
        assert resource_calls == [("iam", "get_role", record["request"])]
        assert result.operation_calls == 1
    assert result.outcome is live.Outcome.SUCCEEDED
    transcript = provider.transcript_summary()
    assert transcript.provider_calls == len(state.calls)
    assert transcript.provider_mutation_calls == (1 if action in live.MUTATION_ACTIONS else 0)


def test_plan_action_or_retry_substitution_is_rejected_before_dispatch() -> None:
    phase, record = _operation("iam:GetRole")
    for key, value in (("api_action", "DeleteRole"), ("retry_permitted", True)):
        forged = copy.deepcopy(record)
        forged[key] = value
        with pytest.raises(live.LiveProviderError):
            live.planned_call_from_record(phase, forged)


def test_list_pagination_is_complete_and_request_bound(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = FakeState(
        pages={
            "list_role_policies": [
                {"PolicyNames": ["one"], "IsTruncated": True, "Marker": "next"},
                {"PolicyNames": ["two"], "IsTruncated": False},
            ]
        }
    )
    provider, state = _open(monkeypatch, state)
    phase, record = _operation("iam:ListRolePolicies")
    result = provider.read_operation(live.planned_call_from_record(phase, record))
    calls = [item for item in state.calls if item[1] == "list_role_policies"]
    assert calls == [
        ("iam", "list_role_policies", record["request"]),
        ("iam", "list_role_policies", {**record["request"], "Marker": "next"}),
    ]
    assert result.outcome is live.Outcome.SUCCEEDED


@pytest.mark.parametrize(
    "pages",
    [
        [{"PolicyNames": [], "IsTruncated": True}],
        [
            {"PolicyNames": [], "IsTruncated": True, "Marker": "same"},
            {"PolicyNames": [], "IsTruncated": True, "Marker": "same"},
        ],
    ],
)
def test_incomplete_or_repeated_pagination_is_fail_closed(
    monkeypatch: pytest.MonkeyPatch, pages: list[Mapping[str, Any]]
) -> None:
    state = FakeState(pages={"list_role_policies": copy.deepcopy(pages)})
    provider, _ = _open(monkeypatch, state)
    phase, record = _operation("iam:ListRolePolicies")
    with pytest.raises(live.LiveProviderError):
        provider.read_operation(live.planned_call_from_record(phase, record))
    assert len([item for item in state.calls if item[1] == "list_role_policies"]) <= 2


def test_pagination_limit_is_enforced(monkeypatch: pytest.MonkeyPatch) -> None:
    state = FakeState(
        pages={
            "list_role_policies": [
                {"PolicyNames": [], "IsTruncated": True, "Marker": "next"},
                {"PolicyNames": [], "IsTruncated": False},
            ]
        }
    )
    provider, _ = _open(monkeypatch, state, max_pages=1)
    phase, record = _operation("iam:ListRolePolicies")
    with pytest.raises(live.LiveProviderError):
        provider.read_operation(live.planned_call_from_record(phase, record))
    assert len([item for item in state.calls if item[1] == "list_role_policies"]) == 1


def test_paginated_facts_enforce_one_global_response_bound(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first = {
        "PolicyNames": ["a" * 256],
        "IsTruncated": True,
        "Marker": "next",
    }
    second = {"PolicyNames": ["b" * 256], "IsTruncated": False}
    per_page_limit = max(
        len(live.canonical_json(first).encode("utf-8")),
        len(live.canonical_json(second).encode("utf-8")),
    )
    merged = {"PolicyNames": sorted(["a" * 256, "b" * 256])}
    assert len(live.canonical_json(merged).encode("utf-8")) > per_page_limit
    state = FakeState(
        pages={"list_role_policies": [first, second]}
    )
    provider, state = _open(
        monkeypatch, state, max_response_bytes=per_page_limit
    )
    phase, record = _operation("iam:ListRolePolicies")

    with pytest.raises(live.LiveProviderError, match="PROVIDER_RESPONSE_TOO_LARGE"):
        provider.read_operation(live.planned_call_from_record(phase, record))
    assert len([item for item in state.calls if item[1] == "list_role_policies"]) == 2


@pytest.mark.parametrize(
    ("api_action", "method", "pending", "ready"),
    [
        (
            "WaitUntilFunctionActiveV2",
            "get_function_configuration",
            {"State": "Pending", "LastUpdateStatus": "InProgress"},
            {"State": "Active", "LastUpdateStatus": "Successful"},
        ),
        (
            "WaitUntilTableExists",
            "describe_table",
            {"Table": {"TableStatus": "CREATING"}},
            {"Table": {"TableStatus": "ACTIVE"}},
        ),
    ],
)
def test_bounded_waiters_reach_ready_state(
    monkeypatch: pytest.MonkeyPatch,
    api_action: str,
    method: str,
    pending: Mapping[str, Any],
    ready: Mapping[str, Any],
) -> None:
    call = _waiter_call(api_action)
    state = FakeState(pages={method: [pending, ready]})
    provider, state = _open(monkeypatch, state)

    result = provider.read_operation(call)

    assert result.outcome is live.Outcome.SUCCEEDED
    assert result.operation_calls == 2
    assert [item for item in state.calls if item[1] == method] == [
        (call.service, method, call.request),
        (call.service, method, call.request),
    ]


@pytest.mark.parametrize(
    ("api_action", "method", "terminal"),
    [
        (
            "WaitUntilFunctionActiveV2",
            "get_function_configuration",
            {"State": "Failed", "LastUpdateStatus": "Successful"},
        ),
        (
            "WaitUntilTableExists",
            "describe_table",
            {"Table": {"TableStatus": "DELETING"}},
        ),
    ],
)
def test_bounded_waiters_fail_on_terminal_state(
    monkeypatch: pytest.MonkeyPatch,
    api_action: str,
    method: str,
    terminal: Mapping[str, Any],
) -> None:
    call = _waiter_call(api_action)
    state = FakeState(pages={method: [terminal]})
    provider, state = _open(monkeypatch, state)

    result = provider.read_operation(call)

    assert result.outcome is live.Outcome.FAILED
    assert result.error_code == "WaiterTerminalState"
    assert result.operation_calls == 1
    assert result.reconciliation_required is False
    assert len([item for item in state.calls if item[1] == method]) == 1


@pytest.mark.parametrize(
    ("api_action", "method", "pending"),
    [
        (
            "WaitUntilFunctionActiveV2",
            "get_function_configuration",
            {"State": "Pending", "LastUpdateStatus": "InProgress"},
        ),
        (
            "WaitUntilTableExists",
            "describe_table",
            {"Table": {"TableStatus": "CREATING"}},
        ),
    ],
)
def test_bounded_waiters_stop_at_attempt_bound(
    monkeypatch: pytest.MonkeyPatch,
    api_action: str,
    method: str,
    pending: Mapping[str, Any],
) -> None:
    call = _waiter_call(api_action)
    state = FakeState(pages={method: [pending, pending]})
    provider, state = _open(monkeypatch, state)

    result = provider.read_operation(call)

    assert result.outcome is live.Outcome.AMBIGUOUS
    assert result.error_code == "WaiterBoundExceeded"
    assert result.operation_calls == 2
    assert result.reconciliation_required is True
    assert len([item for item in state.calls if item[1] == method]) == 2


@pytest.mark.parametrize(
    ("api_action", "method", "pending"),
    [
        (
            "WaitUntilFunctionActiveV2",
            "get_function_configuration",
            {"State": "Pending", "LastUpdateStatus": "InProgress"},
        ),
        (
            "WaitUntilTableExists",
            "describe_table",
            {"Table": {"TableStatus": "CREATING"}},
        ),
    ],
)
def test_bounded_waiters_recheck_validity_before_every_poll(
    monkeypatch: pytest.MonkeyPatch,
    api_action: str,
    method: str,
    pending: Mapping[str, Any],
) -> None:
    call = _waiter_call(api_action)
    state = FakeState(pages={method: [pending, pending]})
    gate_calls = 0

    def validity_gate() -> None:
        nonlocal gate_calls
        gate_calls += 1
        if gate_calls == 4:
            raise live.LiveProviderError("REQUEST_WINDOW_INVALID")

    provider, state = _open(
        monkeypatch, state, validity_gate=validity_gate
    )

    with pytest.raises(live.LiveProviderError, match="REQUEST_WINDOW_INVALID"):
        provider.read_operation(call)
    assert gate_calls == 4
    assert len([item for item in state.calls if item[1] == method]) == 1


def test_mutation_transport_failure_is_ambiguous_and_never_sdk_retried(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = FakeState(errors={"create_policy": TimeoutError("synthetic-private")})
    provider, state = _open(monkeypatch, state)
    phase, record = _operation("iam:CreatePolicy")
    result = provider.invoke_operation(live.planned_call_from_record(phase, record))
    assert result.outcome is live.Outcome.AMBIGUOUS
    assert len([item for item in state.calls if item[1] == "create_policy"]) == 1
    assert not [item for item in state.calls if item[1] == "get_policy"]
    assert result.operation_calls == 1
    assert provider.transcript_summary().reconciliation_required is True


@pytest.mark.parametrize("code", ["InternalFailure", "ServiceUnavailable"])
def test_mutation_service_failure_is_ambiguous_and_never_retried(
    monkeypatch: pytest.MonkeyPatch, code: str
) -> None:
    state = FakeState(errors={"create_policy": StructuredClientError(code)})
    provider, state = _open(monkeypatch, state)
    phase, record = _operation("iam:CreatePolicy")
    result = provider.invoke_operation(live.planned_call_from_record(phase, record))
    writes = [item for item in state.calls if item[1] == "create_policy"]
    assert writes == [("iam", "create_policy", record["request"])]
    assert not [item for item in state.calls if item[1] == "get_policy"]
    assert result.outcome is live.Outcome.AMBIGUOUS
    assert result.outcome is not live.Outcome.FAILED
    assert result.error_code == code
    assert result.operation_calls == 1
    assert result.reconciliation_required is True
    assert provider.transcript_summary().reconciliation_required is True


def test_readback_mismatch_after_write_is_ambiguous_without_write_retry(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    phase, record = _operation("iam:CreatePolicy")
    plan = json.loads(PLAN.read_text(encoding="utf-8"))
    call = live.planned_call_from_record(phase, record)
    state = FakeState()
    _configure_positive_mutation(state, call, plan)
    state.pages["get_policy"][0]["Policy"]["Arn"] = "substitute"
    provider, state = _open(monkeypatch, state)
    result = provider.invoke_operation(call)
    resource_calls = [item for item in state.calls if item[0] != "sts"]
    assert resource_calls == [
        ("iam", "create_policy", record["request"]),
        ("iam", "get_policy", {"PolicyArn": record["target_arn"]}),
        (
            "iam",
            "get_policy_version",
            {"PolicyArn": record["target_arn"], "VersionId": "v1"},
        ),
        (
            "iam",
            "list_policy_tags",
            {"PolicyArn": record["target_arn"]},
        ),
    ]
    assert result.outcome is live.Outcome.AMBIGUOUS
    assert result.operation_calls == 4
    assert provider.transcript_summary().reconciliation_required is True


@pytest.mark.parametrize("with_qualifier", [False, True])
def test_runtime_management_config_accepts_flat_real_readback(
    monkeypatch: pytest.MonkeyPatch,
    with_qualifier: bool,
) -> None:
    plan = json.loads(PLAN.read_text(encoding="utf-8"))
    matches = [
        (str(phase["phase"]), copy.deepcopy(record))
        for phase in plan["authorization_phases"]
        for record in phase["operations"]
        if record["api_action"] == "PutRuntimeManagementConfig"
        and ("Qualifier" in record["request"]) is with_qualifier
    ]
    assert len(matches) == 1
    phase, record = matches[0]
    qualifier = record["request"].get("Qualifier")
    readback_arn = (
        f"{record['target_arn']}:{qualifier}" if qualifier else record["target_arn"]
    )
    readback = {
        "FunctionArn": readback_arn,
        "UpdateRuntimeOn": record["request"]["UpdateRuntimeOn"],
        "RuntimeVersionArn": record["request"]["RuntimeVersionArn"],
    }
    state = FakeState(pages={"get_runtime_management_config": [readback]})
    provider, state = _open(monkeypatch, state)

    result = provider.invoke_operation(live.planned_call_from_record(phase, record))

    expected_read_request = {"FunctionName": record["request"]["FunctionName"]}
    if qualifier:
        expected_read_request["Qualifier"] = qualifier
    resource_calls = [item for item in state.calls if item[0] != "sts"]
    assert resource_calls == [
        ("lambda", "put_runtime_management_config", record["request"]),
        ("lambda", "get_runtime_management_config", expected_read_request),
    ]
    assert result.outcome is live.Outcome.SUCCEEDED
    assert result.operation_calls == 2
    assert result.reconciliation_required is False


def test_transcript_and_errors_are_digest_only_and_fake_cannot_claim_live(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    provider, state = _open(monkeypatch)
    phase, record = _operation("iam:GetRole")
    provider.read_operation(live.planned_call_from_record(phase, record))
    receipt = provider.transcript_summary()
    public = json.dumps(asdict(receipt), sort_keys=True, default=str)
    assert receipt.live_provider_evidence is False
    for private in (
        state.account_id,
        state.principal_arn,
        "synthetic-private-user-id",
        "gug390-synthetic",
        "synthetic-private-request",
    ):
        assert private not in public
