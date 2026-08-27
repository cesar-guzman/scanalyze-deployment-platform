"""Focused offline tests for the budgeted GUG-393 provider boundary."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from tooling import platform_authority_gug376_live_provider as provider
from tooling import platform_authority_gug393_discovery_budget as budget
from tooling import platform_authority_gug393_private_input_discovery as discovery


AUTHORITY_ACCOUNT = "111111111111"
IDENTITY_ACCOUNT = "222222222222"
AUTHORITY_ROLE = "ScanalyzeAuthorityReader"
IDENTITY_ROLE = "ScanalyzeIdentityReader"
AUTHORITY_PRINCIPAL = (
    f"arn:aws:sts::{AUTHORITY_ACCOUNT}:assumed-role/{AUTHORITY_ROLE}/session"
)
IDENTITY_PRINCIPAL = (
    f"arn:aws:sts::{IDENTITY_ACCOUNT}:assumed-role/{IDENTITY_ROLE}/session"
)


def _budget_document(**overrides: Any) -> dict[str, Any]:
    value: dict[str, Any] = {
        "record_type": budget.RECORD_TYPE,
        "schema_version": budget.SCHEMA_VERSION,
        "max_network_calls": 4,
        "max_provider_calls": 3,
        "max_credential_vending_calls": 1,
        "max_page_calls": 2,
        "max_response_bytes": 4_096,
        "max_total_response_bytes": 8_192,
        "maximum_cost_usd": "1.000000000",
        "cost_model": {
            "fixed_run_cost_usd_upper": "0.000000000",
            "per_network_attempt_cost_usd_upper": "0.000000000",
            "per_projected_response_byte_cost_usd_upper": "0.000000000",
            "pricing_reference_digest": "sha256:" + "a" * 64,
            "valid_from": "2030-01-01T00:00:00Z",
            "valid_until": "2040-01-01T00:00:00Z",
        },
    }
    value.update(overrides)
    return value


def _global_budget(**overrides: Any) -> budget.GlobalDiscoveryBudget:
    return budget.GlobalDiscoveryBudget(
        budget.validate_discovery_budget(_budget_document(**overrides))
    )


def _builder_arguments(runtime_root: Path) -> dict[str, Any]:
    return {
        "sdk_runtime_root": str(runtime_root),
        "authority_profile": "scanalyze-authority-reader",
        "identity_center_profile": "scanalyze-identity-reader",
        "authority_expected_account_id": AUTHORITY_ACCOUNT,
        "authority_expected_principal_digest": provider.canonical_digest(
            AUTHORITY_PRINCIPAL
        ),
        "authority_expected_sso_role_name_digest": provider.canonical_digest(
            AUTHORITY_ROLE
        ),
        "identity_expected_account_id": IDENTITY_ACCOUNT,
        "identity_expected_principal_digest": provider.canonical_digest(
            IDENTITY_PRINCIPAL
        ),
        "identity_expected_sso_role_name_digest": provider.canonical_digest(
            IDENTITY_ROLE
        ),
        "authority_verification_digest": provider.canonical_digest(
            "authority-verification"
        ),
        "identity_authority_verification_digest": provider.canonical_digest(
            "identity-verification"
        ),
    }


def _build_discovery_factory(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    shared_budget: budget.GlobalDiscoveryBudget,
) -> tuple[provider.LiveProviderFactory, object, dict[str, Any]]:
    capability = object()
    captured: dict[str, Any] = {}

    class CapabilityGate:
        def __call__(self) -> None:
            return None

        def authorize_session(self, **_: Any) -> None:
            return None

    def assert_capability(value: object, **bindings: Any) -> Any:
        assert value is capability
        captured.update(bindings)
        return CapabilityGate()

    monkeypatch.setattr(
        discovery,
        "assert_preflight_provider_capability_bindings",
        assert_capability,
    )
    monkeypatch.setattr(provider, "_ambient_gate", lambda _: None)
    monkeypatch.setattr(
        provider,
        "_load_sdk",
        lambda _: provider._LoadedSdk(
            session_factory=lambda **_: None,
            config_factory=lambda **_: None,
            guard=lambda: None,
        ),
    )
    factory = provider.build_discovery_provider_factory(
        **_builder_arguments(tmp_path.resolve()),
        discovery_budget=shared_budget,
        execution_capability=capability,
    )
    return factory, capability, captured


class _Ledger:
    def __init__(self) -> None:
        self.authorized: list[dict[str, Any]] = []
        self.completed: list[dict[str, Any]] = []

    def authorize(self, **event: Any) -> str:
        ticket = f"ticket-{len(self.authorized) + 1}"
        self.authorized.append({"ticket": ticket, **event})
        return ticket

    def complete(self, ticket: str, response: Any = None, **event: Any) -> None:
        self.completed.append(
            {"ticket": ticket, "response": response, **event}
        )

    def finalize(self) -> tuple[int, str]:
        assert len(self.authorized) == len(self.completed)
        return len(self.completed), provider.canonical_digest(self.completed)


class _StsClient:
    def __init__(self) -> None:
        self.calls = 0

    def get_caller_identity(self) -> dict[str, str]:
        self.calls += 1
        return {
            "Account": IDENTITY_ACCOUNT,
            "Arn": IDENTITY_PRINCIPAL,
            "UserId": "TEST-ONLY-USER-ID",
        }


class _SsoClient:
    def __init__(self) -> None:
        self.calls = 0

    def list_instances(self, **_: Any) -> dict[str, list[Any]]:
        self.calls += 1
        return {"Instances": []}


def _identity_session(
    factory: provider.LiveProviderFactory,
) -> tuple[provider._StsSession, _Ledger, _StsClient]:
    now = datetime.now(UTC).replace(microsecond=0)
    ledger = _Ledger()
    sts_client = _StsClient()
    factory._ledger = ledger
    session = provider._StsSession(
        owner=factory,
        domain="identity_center",
        sdk_session=SimpleNamespace(),
        sdk_config=SimpleNamespace(),
        sts_client=sts_client,
        ledger=ledger,
        session_digest=provider.canonical_digest("test-session"),
        account_id=IDENTITY_ACCOUNT,
        principal_digest=provider.canonical_digest(IDENTITY_PRINCIPAL),
        authority_verification_digest=provider.canonical_digest(
            "identity-verification"
        ),
        policy={},
        policy_digest=provider.canonical_digest("test-policy"),
        start=now - timedelta(minutes=1),
        end=now + timedelta(minutes=10),
        opened_at=now,
        credential_expires_at=now + timedelta(minutes=30),
        policy_actions=frozenset(
            {"sts:GetCallerIdentity", "sso:ListInstances"}
        ),
        region=provider.REGION,
    )
    return session, ledger, sts_client


def test_discovery_builder_has_distinct_attestation_and_exact_budget_binding(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    shared_budget = _global_budget()
    factory, capability, captured = _build_discovery_factory(
        monkeypatch, tmp_path, shared_budget
    )

    assert provider.is_attested_discovery_provider(factory, capability) is True
    assert provider.is_attested_live_provider(factory, capability) is False
    assert factory.concrete_provider is True
    assert factory.discovery_provider is True
    assert factory.mode == "ATTESTED_DISCOVERY"
    assert captured["budget_digest"] == shared_budget.summary()["budget_digest"]
    assert set(captured) == {
        *_builder_arguments(tmp_path.resolve()),
        "budget_digest",
    }
    assert factory.discovery_budget_summary() == shared_budget.summary()


def test_existing_live_and_injected_modes_remain_non_discovery(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    capability = object()
    monkeypatch.setattr(provider, "_ambient_gate", lambda _: None)
    monkeypatch.setattr(
        provider,
        "_load_sdk",
        lambda _: provider._LoadedSdk(
            session_factory=lambda **_: None,
            config_factory=lambda **_: None,
            guard=lambda: None,
        ),
    )
    monkeypatch.setattr(
        provider,
        "assert_live_provider_capability_bindings",
        lambda *_args, **_kwargs: lambda: None,
    )
    live = provider.build_live_provider_factory(
        **_builder_arguments(tmp_path.resolve()),
        execution_capability=capability,
    )
    assert provider.is_attested_live_provider(live, capability) is True
    assert provider.is_attested_discovery_provider(live, capability) is False
    assert live.mode == "ATTESTED_LIVE"
    with pytest.raises(provider.LiveProviderError) as captured:
        live.discovery_budget_summary()
    assert captured.value.code == "DISCOVERY_PROVIDER_REQUIRED"

    arguments = _builder_arguments(tmp_path.resolve())
    arguments.pop("sdk_runtime_root")
    injected = provider.build_injected_provider_factory(
        **arguments,
        validity_gate=lambda: None,
        session_factory=lambda **_: None,
        config_factory=lambda **_: None,
        clock=lambda: datetime.now(UTC),
    )
    assert injected.mode == "INJECTED_NON_LIVE"
    assert injected.discovery_provider is False
    assert provider.is_attested_discovery_provider(injected, object()) is False


def test_provider_calls_pages_and_detached_bytes_share_one_budget_and_keep_transcript(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    shared_budget = _global_budget()
    factory, _, _ = _build_discovery_factory(
        monkeypatch, tmp_path, shared_budget
    )
    session, _, sts_client = _identity_session(factory)
    sso_client = _SsoClient()
    session._clients["sso-admin"] = sso_client

    identity = session.get_caller_identity()
    instances = session._paginate(
        operation="sso:ListInstances",
        service="sso-admin",
        method="list_instances",
        request={},
        item_key="Instances",
        request_token_key="NextToken",
        response_token_key="NextToken",
    )

    assert identity["account_id"] == IDENTITY_ACCOUNT
    assert instances == []
    assert sts_client.calls == 1
    assert sso_client.calls == 1
    budget_summary = factory.discovery_budget_summary()
    assert budget_summary["provider_calls"] == 2
    assert budget_summary["credential_vending_calls"] == 0
    assert budget_summary["network_calls"] == 2
    assert budget_summary["page_calls"] == 1
    assert budget_summary["projected_response_bytes"] > 0

    transcript = factory.transcript_summary()
    assert set(transcript) == {
        "provider_calls",
        "aws_calls",
        "aws_mutations",
        "live_provider_evidence",
        "transcript_digest",
    }
    assert transcript["provider_calls"] == 2
    assert transcript["aws_calls"] == 2
    assert transcript["aws_mutations"] == 0
    assert transcript["live_provider_evidence"] is True


def test_provider_budget_failure_happens_before_sdk_invocation(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    shared_budget = _global_budget(
        max_network_calls=1,
        max_provider_calls=0,
        max_credential_vending_calls=1,
        max_page_calls=0,
    )
    factory, _, _ = _build_discovery_factory(
        monkeypatch, tmp_path, shared_budget
    )
    session, _, sts_client = _identity_session(factory)

    with pytest.raises(provider.LiveProviderError) as captured:
        session.get_caller_identity()

    assert captured.value.code == "DISCOVERY_PROVIDER_CALL_BUDGET_EXCEEDED"
    assert sts_client.calls == 0
    assert factory.discovery_budget_summary()["provider_calls"] == 0
    transcript = factory.transcript_summary()
    assert transcript["provider_calls"] == 0
    assert transcript["aws_calls"] == 0
    assert transcript["live_provider_evidence"] is False


def test_response_budget_failure_is_safe_after_one_actual_provider_call(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    shared_budget = _global_budget(
        max_response_bytes=1,
        max_total_response_bytes=1,
    )
    factory, _, _ = _build_discovery_factory(
        monkeypatch, tmp_path, shared_budget
    )
    session, _, sts_client = _identity_session(factory)

    with pytest.raises(provider.LiveProviderError) as captured:
        session.get_caller_identity()

    assert captured.value.code == "DISCOVERY_RESPONSE_BYTE_BUDGET_EXCEEDED"
    assert sts_client.calls == 1
    summary = factory.discovery_budget_summary()
    assert summary["provider_calls"] == 1
    assert summary["network_calls"] == 1
    assert summary["projected_response_bytes"] == 0
    assert factory.transcript_summary()["provider_calls"] == 1


class _Emitter:
    def __init__(self) -> None:
        self.callback: Any = None

    def register(self, _: str, callback: Any, *, unique_id: str) -> None:
        assert unique_id
        self.callback = callback

    def unregister(self, _: str, *, unique_id: str) -> None:
        assert unique_id
        self.callback = None

    def emit_credential_vend(self) -> None:
        assert self.callback is not None
        self.callback(
            event_name="before-call.sso.GetRoleCredentials",
            context={
                "client_config": SimpleNamespace(
                    retries={"mode": "standard", "total_max_attempts": 1}
                )
            },
        )


class _CoreSession:
    def __init__(self, profile_name: str, emitter: _Emitter) -> None:
        self.full_config = {
            "profiles": {
                profile_name: {
                    "region": provider.REGION,
                    "sso_account_id": AUTHORITY_ACCOUNT,
                    "sso_role_name": AUTHORITY_ROLE,
                    "sso_start_url": "https://test-only.invalid/start",
                    "sso_region": provider.REGION,
                }
            }
        }
        self._emitter = emitter
        self._variables: dict[str, Any] = {}

    def set_config_variable(self, name: str, value: Any) -> None:
        self._variables[name] = value

    def get_config_variable(self, name: str) -> Any:
        return self._variables.get(name)

    def get_component(self, name: str) -> _Emitter:
        assert name == "event_emitter"
        return self._emitter


class _SsoCredentials:
    method = "sso"

    def __init__(
        self, emitter: _Emitter, *, vend: bool, expires_at: datetime
    ) -> None:
        self._emitter = emitter
        self._vend = vend
        self._expiry_time = expires_at

    def get_frozen_credentials(self) -> Any:
        if self._vend:
            self._emitter.emit_credential_vend()
        return SimpleNamespace(
            access_key="TEST-ONLY-NOT-A-CREDENTIAL",
            secret_key="TEST-ONLY-NOT-A-SECRET",
            token="TEST-ONLY-NOT-A-TOKEN",
        )


class _ProfileSession:
    region_name = provider.REGION

    def __init__(
        self, profile_name: str, *, vend: bool, expires_at: datetime
    ) -> None:
        emitter = _Emitter()
        self._session = _CoreSession(profile_name, emitter)
        self._credentials = _SsoCredentials(
            emitter, vend=vend, expires_at=expires_at
        )

    def get_credentials(self) -> _SsoCredentials:
        return self._credentials


class _ExplicitSession:
    def __init__(self, *, region_name: str, frozen: Any) -> None:
        self.region_name = region_name
        self._frozen = frozen

    def get_credentials(self) -> Any:
        return SimpleNamespace(
            method="explicit",
            get_frozen_credentials=lambda: self._frozen,
        )

    def client(self, service: str, *, config: Any, verify: bool) -> Any:
        assert service == "sts"
        assert config is not None
        assert verify is True
        return SimpleNamespace()


def _caller_policy(now: datetime) -> dict[str, Any]:
    def stamp(value: datetime) -> str:
        return value.isoformat().replace("+00:00", "Z")

    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "ConfirmOnlyTheCurrentCaller",
                "Effect": "Allow",
                "Action": "sts:GetCallerIdentity",
                "Resource": "*",
                "Condition": {
                    "DateGreaterThanEquals": {
                        "aws:CurrentTime": stamp(now - timedelta(minutes=1))
                    },
                    "DateLessThan": {
                        "aws:CurrentTime": stamp(now + timedelta(minutes=10))
                    },
                },
            }
        ],
    }


def test_only_observed_sso_before_call_events_count_as_vends(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    shared_budget = _global_budget()
    factory, _, _ = _build_discovery_factory(
        monkeypatch, tmp_path, shared_budget
    )
    profile_name = "scanalyze-authority-reader"
    opened_at = datetime.now(UTC).replace(microsecond=0)
    expires_at = opened_at + timedelta(minutes=30)
    vend_events = iter((False, True, True))

    def session_factory(**kwargs: Any) -> Any:
        selected_profile = kwargs.get("profile_name")
        if selected_profile is not None:
            assert selected_profile == profile_name
            return _ProfileSession(
                selected_profile,
                vend=next(vend_events),
                expires_at=expires_at,
            )
        frozen = SimpleNamespace(
            access_key=kwargs["aws_access_key_id"],
            secret_key=kwargs["aws_secret_access_key"],
            token=kwargs["aws_session_token"],
        )
        return _ExplicitSession(
            region_name=kwargs["region_name"], frozen=frozen
        )

    factory._session_factory = session_factory
    factory._config_factory = lambda **kwargs: SimpleNamespace(**kwargs)
    policy = _caller_policy(opened_at)
    policy_digest = provider.canonical_digest(policy)
    ledger = _Ledger()

    factory.build_authority(
        profile=profile_name, ledger=ledger, capture_index=1, retries=0
    ).open_sts(
        policy=policy,
        policy_digest=policy_digest,
        region=provider.REGION,
    )
    assert factory.discovery_budget_summary()["credential_vending_calls"] == 0

    factory.build_authority(
        profile=profile_name, ledger=ledger, capture_index=2, retries=0
    ).open_sts(
        policy=policy,
        policy_digest=policy_digest,
        region=provider.REGION,
    )
    summary = factory.discovery_budget_summary()
    assert summary["credential_vending_calls"] == 1
    assert summary["network_calls"] == 1

    with pytest.raises(provider.LiveProviderError) as captured:
        factory.build_authority(
            profile=profile_name,
            ledger=ledger,
            capture_index=2,
            retries=0,
        ).open_sts(
            policy=policy,
            policy_digest=policy_digest,
            region=provider.REGION,
        )
    assert captured.value.code == (
        "DISCOVERY_CREDENTIAL_VENDING_BUDGET_EXCEEDED"
    )
    assert factory.discovery_budget_summary()["credential_vending_calls"] == 1
