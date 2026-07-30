from __future__ import annotations

import copy
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

import pytest

from identity_control_plane.handlers import build_pre_token_handler
from identity_control_plane.m2m import M2MDenied, M2MProvisioner
from identity_control_plane.pre_token import PreTokenDenied


CUSTOMER_ID = "cust_01HZX3YQ8J4F6A2B7C9D0E1G5K"
DEPLOYMENT_ID = "dep_01HZX3YQ8J4F6A2B7C9D0E1G5K"
FOREIGN_CUSTOMER_ID = "cust_01HZX3YQ8J4F6A2B7C9D0E1G5M"
IDEMPOTENCY_KEY = "idem_01HZX3YQ8J4F6A2B7C9D0E1G5K"
NOW = datetime(2026, 7, 13, 12, 0, tzinfo=timezone.utc)
SENSITIVE_CLIENT_VALUE = "SENSITIVE_CANARY_M2M_CLIENT_VALUE"
POLICY_DIGEST = f"sha256:{'a' * 64}"


@dataclass
class AuditSink:
    events: list[dict[str, Any]] = field(default_factory=list)

    def emit(self, event: dict[str, Any]) -> None:
        self.events.append(copy.deepcopy(event))


@dataclass
class ClientProvider:
    error: Exception | None = None
    calls: list[dict[str, Any]] = field(default_factory=list)

    def ensure_client(self, **request: Any) -> dict[str, Any]:
        self.calls.append(request)
        if self.error:
            raise self.error
        return {
            "client_id": "syntheticclientid",
            "secret_reference": "secret_reference_synthetic",
        }


@dataclass
class BindingStore:
    existing: dict[str, Any] | None = None
    claim_result: str | None = "synthetic-claim"
    reacquire_result: str | None = "reacquired-synthetic-claim"
    complete_result: bool = True
    calls: list[tuple[str, dict[str, Any]]] = field(default_factory=list)

    def load_by_idempotency(self, idempotency_key: str) -> dict[str, Any] | None:
        self.calls.append(("load", {"idempotency_key": idempotency_key}))
        return copy.deepcopy(self.existing)

    def claim(self, **condition: Any) -> str | None:
        self.calls.append(("claim", condition))
        return self.claim_result

    def reacquire(self, **condition: Any) -> str | None:
        self.calls.append(("reacquire", condition))
        return self.reacquire_result

    def complete(self, **condition: Any) -> bool:
        self.calls.append(("complete", condition))
        return self.complete_result

    def release(self, **condition: Any) -> None:
        self.calls.append(("release", condition))


def _m2m_command(**overrides: Any) -> dict[str, Any]:
    command = {
        "schema_version": "identity-m2m-provisioning.v1",
        "principal_type": "m2m",
        "request_id": "request-synthetic",
        "workload_id": "ingest-api",
        "environment": "production",
        "customer_id": CUSTOMER_ID,
        "deployment_id": DEPLOYMENT_ID,
        "actions": ["read", "write"],
        "idempotency_key": IDEMPOTENCY_KEY,
    }
    command.update(overrides)
    return command


def _m2m_processor(
    *,
    provider: ClientProvider | None = None,
    bindings: BindingStore | None = None,
) -> tuple[M2MProvisioner, ClientProvider, BindingStore, AuditSink]:
    client_provider = provider or ClientProvider()
    binding_store = bindings or BindingStore()
    audit = AuditSink()
    processor = M2MProvisioner(
        config={
            "expected_customer_id": CUSTOMER_ID,
            "expected_deployment_id": DEPLOYMENT_ID,
            "action_scopes": {
                "read": "scanalyze.api.v1/read",
                "write": "scanalyze.api.v1/write",
                "admin": "scanalyze.api.v1/admin",
            },
            "policy_version": "1.0.0",
            "policy_digest": POLICY_DIGEST,
        },
        client_provider=client_provider,
        binding_store=binding_store,
        audit_sink=audit,
        clock=lambda: NOW,
        logger=logging.getLogger("scanalyze.identity.m2m.test"),
    )
    return processor, client_provider, binding_store, audit


def test_m2m_provisioning_escrows_value_and_returns_only_references(
    caplog: pytest.LogCaptureFixture,
) -> None:
    processor, provider, bindings, audit = _m2m_processor()
    caplog.set_level(logging.INFO, logger="scanalyze.identity.m2m.test")

    result = processor.provision(_m2m_command())

    assert result == {
        "status": "completed",
        "client_id": "syntheticclientid",
        "secret_reference": "secret_reference_synthetic",
    }
    assert provider.calls[0]["scopes"] == [
        "scanalyze.api.v1/read",
        "scanalyze.api.v1/write",
    ]
    assert next(details for name, details in bindings.calls if name == "complete")[
        "actions"
    ] == ["read", "write"]
    serialized = repr(result) + repr(audit.events) + caplog.text
    assert SENSITIVE_CLIENT_VALUE not in serialized
    assert CUSTOMER_ID not in serialized
    assert DEPLOYMENT_ID not in serialized


def test_m2m_idempotent_replay_returns_existing_references_without_new_effects() -> None:
    existing = {
        "status": "active",
        "workload_id": "ingest-api",
        "environment": "production",
        "customer_id": CUSTOMER_ID,
        "deployment_id": DEPLOYMENT_ID,
        "actions": ["read", "write"],
        "client_id": "existingclientid",
        "secret_reference": "existing_secret_reference",
    }
    bindings = BindingStore(existing=existing)
    processor, provider, _, _ = _m2m_processor(bindings=bindings)

    result = processor.provision(_m2m_command())

    assert result["client_id"] == "existingclientid"
    assert result["secret_reference"] == "existing_secret_reference"
    assert provider.calls == []


def test_m2m_provisioning_claim_is_reconciled_idempotently() -> None:
    existing = {
        "status": "provisioning",
        "claim_token": "retained-synthetic-claim",
        "claimed_at": "2026-07-13T11:54:59Z",
        "workload_id": "ingest-api",
        "environment": "production",
        "customer_id": CUSTOMER_ID,
        "deployment_id": DEPLOYMENT_ID,
        "actions": ["read", "write"],
    }
    bindings = BindingStore(existing=existing)
    processor, provider, _, audit = _m2m_processor(bindings=bindings)

    result = processor.provision(_m2m_command())

    assert result["status"] == "completed"
    assert len(provider.calls) == 1
    assert all(name != "claim" for name, _ in bindings.calls)
    reacquire = next(details for name, details in bindings.calls if name == "reacquire")
    assert reacquire["expected_claim_token"] == "retained-synthetic-claim"
    assert reacquire["expected_claimed_at"] == "2026-07-13T11:54:59Z"
    complete = next(details for name, details in bindings.calls if name == "complete")
    assert complete["claim_token"] == "reacquired-synthetic-claim"
    assert audit.events[-1]["reason_code"] == "m2m_reconciled"


def test_m2m_fresh_claim_cannot_be_reused_concurrently() -> None:
    existing = {
        "status": "provisioning",
        "claim_token": "retained-synthetic-claim",
        "claimed_at": "2026-07-13T11:59:59Z",
        "workload_id": "ingest-api",
        "environment": "production",
        "customer_id": CUSTOMER_ID,
        "deployment_id": DEPLOYMENT_ID,
        "actions": ["read", "write"],
    }
    bindings = BindingStore(existing=existing)
    processor, provider, _, _ = _m2m_processor(bindings=bindings)

    with pytest.raises(M2MDenied) as exc_info:
        processor.provision(_m2m_command())

    assert exc_info.value.reason_code == "m2m_claim_in_progress"
    assert provider.calls == []
    assert all(name not in {"reacquire", "complete"} for name, _ in bindings.calls)


def test_m2m_stale_claim_requires_successful_compare_and_swap() -> None:
    existing = {
        "status": "provisioning",
        "claim_token": "retained-synthetic-claim",
        "claimed_at": "2026-07-13T11:54:59Z",
        "workload_id": "ingest-api",
        "environment": "production",
        "customer_id": CUSTOMER_ID,
        "deployment_id": DEPLOYMENT_ID,
        "actions": ["read", "write"],
    }
    bindings = BindingStore(existing=existing, reacquire_result=None)
    processor, provider, _, _ = _m2m_processor(bindings=bindings)

    with pytest.raises(M2MDenied) as exc_info:
        processor.provision(_m2m_command())

    assert exc_info.value.reason_code == "m2m_claim_conflict"
    assert provider.calls == []


@pytest.mark.parametrize(
    ("override", "reason"),
    [
        ({"principal_type": "user"}, "human_runtime_provisioning_forbidden"),
        ({"customer_id": FOREIGN_CUSTOMER_ID}, "foreign_binding"),
        ({"actions": []}, "invalid_action_grant"),
        ({"actions": ["read", "read"]}, "invalid_action_grant"),
        ({"actions": ["superuser"]}, "invalid_action_grant"),
        ({"idempotency_key": ""}, "missing_binding"),
    ],
)
def test_m2m_unsafe_requests_fail_before_side_effects(
    override: dict[str, Any],
    reason: str,
) -> None:
    processor, provider, _, _ = _m2m_processor()

    with pytest.raises(M2MDenied) as exc_info:
        processor.provision(_m2m_command(**override))

    assert exc_info.value.reason_code == reason
    assert provider.calls == []


def test_m2m_dependency_failure_keeps_claim_for_reconciliation() -> None:
    bindings = BindingStore()
    processor, _, _, _ = _m2m_processor(
        provider=ClientProvider(error=TimeoutError("timeout")),
        bindings=bindings,
    )

    with pytest.raises(M2MDenied) as exc_info:
        processor.provision(_m2m_command())

    assert exc_info.value.reason_code == "m2m_provider_unavailable"
    assert exc_info.value.__suppress_context__ is True
    assert all(name != "release" for name, _ in bindings.calls)


def test_m2m_provider_cannot_return_a_raw_credential() -> None:
    class UnsafeProvider(ClientProvider):
        def ensure_client(self, **request: Any) -> dict[str, Any]:
            self.calls.append(request)
            return {
                "client_id": "syntheticclientid",
                "client_secret": SENSITIVE_CLIENT_VALUE,
                "secret_reference": "secret_reference_synthetic",
            }

    processor, _, _, _ = _m2m_processor(provider=UnsafeProvider())

    with pytest.raises(M2MDenied) as exc_info:
        processor.provision(_m2m_command())

    assert exc_info.value.reason_code == "m2m_provider_exposed_credential"


class ExplodingPreTokenProcessor:
    def handle(self, event: dict[str, Any]) -> dict[str, Any]:
        del event
        raise RuntimeError("SENSITIVE_CANARY_PRE_TOKEN_VALUE")


def test_pre_token_handler_converts_unknown_failure_to_sanitized_denial(
    caplog: pytest.LogCaptureFixture,
) -> None:
    logger = logging.getLogger("scanalyze.identity.handler.test")
    handler = build_pre_token_handler(  # type: ignore[arg-type]
        ExplodingPreTokenProcessor(),
        logger=logger,
    )
    caplog.set_level(logging.INFO, logger="scanalyze.identity.handler.test")

    with pytest.raises(PreTokenDenied) as exc_info:
        handler({}, None)

    assert exc_info.value.reason_code == "pre_token_runtime_failure"
    assert exc_info.value.__suppress_context__ is True
    assert "SENSITIVE_CANARY_PRE_TOKEN_VALUE" not in caplog.text
