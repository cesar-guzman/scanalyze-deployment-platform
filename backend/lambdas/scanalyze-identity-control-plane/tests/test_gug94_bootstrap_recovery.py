"""GUG-94 recovery tests for the one-use first-administrator bootstrap."""
from __future__ import annotations

import copy
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

import pytest

from identity_control_plane.bootstrap import BootstrapDenied, BootstrapProcessor


CUSTOMER_ID = "cust_01HZX3YQ8J4F6A2B7C9D0E1G5K"
DEPLOYMENT_ID = "dep_01HZX3YQ8J4F6A2B7C9D0E1G5K"
SUBJECT = "00000000-0000-4000-8000-000000000001"
REQUEST_ID = "boot_01HZX3YQ8J4F6A2B7C9D0E1G5K"
IDEMPOTENCY_KEY = "idem_01HZX3YQ8J4F6A2B7C9D0E1G5K"
NOW = datetime(2026, 7, 13, 12, 0, tzinfo=timezone.utc)
POLICY_DIGEST = "sha256:" + "a" * 64


def _config() -> dict[str, Any]:
    return {
        "human_runtime_enabled": True,
        "expected_customer_id": CUSTOMER_ID,
        "expected_deployment_id": DEPLOYMENT_ID,
        "allowed_role_ids": [
            "customer_admin",
            "document_operator",
            "document_reviewer",
            "auditor",
        ],
        "authz_schema_version": "enterprise-authorization.v1",
        "scope_catalog_version": "scanalyze.api.v1",
        "role_catalog_version": "enterprise-roles.v1",
        "policy_version": "1.0.0",
        "policy_digest": POLICY_DIGEST,
        "max_ttl_seconds": 900,
        "max_auth_age_seconds": 300,
        "max_recovery_seconds": 3600,
    }


def _request() -> dict[str, Any]:
    def approval(subject: str) -> dict[str, Any]:
        return {
            "approval_reference": "approval-" + subject[-2:],
            "request_id": REQUEST_ID,
            "approver_subject": subject,
            "customer_id": CUSTOMER_ID,
            "deployment_id": DEPLOYMENT_ID,
            "decision": "approved",
            "assurance": "phishing_resistant_mfa",
            "authenticated_at": NOW - timedelta(seconds=30),
        }

    return {
        "schema_version": "identity-bootstrap-request.v1",
        "request_id": REQUEST_ID,
        "state": "approved",
        "version": 7,
        "subject": SUBJECT,
        "customer_id": CUSTOMER_ID,
        "deployment_id": DEPLOYMENT_ID,
        "role_id": "customer_admin",
        "issued_at": NOW - timedelta(seconds=60),
        "expires_at": NOW + timedelta(seconds=600),
        "idempotency_key": IDEMPOTENCY_KEY,
        "approvals": [
            approval("00000000-0000-4000-8000-000000000010"),
            approval("00000000-0000-4000-8000-000000000011"),
        ],
        "authz_schema_version": "enterprise-authorization.v1",
        "scope_catalog_version": "scanalyze.api.v1",
        "role_catalog_version": "enterprise-roles.v1",
        "policy_version": "1.0.0",
        "policy_digest": POLICY_DIGEST,
    }


def _command() -> dict[str, Any]:
    return {
        "schema_version": "identity-bootstrap-command.v1",
        "request_id": REQUEST_ID,
        "expected_version": 7,
        "subject": SUBJECT,
        "customer_id": CUSTOMER_ID,
        "deployment_id": DEPLOYMENT_ID,
    }


@dataclass
class RecoverableRequestStore:
    request: dict[str, Any] = field(default_factory=_request)
    consume_result: bool = True
    mark_audit_result: bool = True
    calls: list[str] = field(default_factory=list)

    def load(self, request_id: str) -> dict[str, Any]:
        self.calls.append("load")
        return copy.deepcopy(self.request)

    def claim(self, **condition: Any) -> str | None:
        self.calls.append("claim")
        if self.request["state"] != "approved":
            return None
        self.request.update(
            {
                "state": "claimed",
                "claim_token": "synthetic-claim-token",
                "claimed_at": condition["claimed_at"],
            }
        )
        return "synthetic-claim-token"

    def mark_effects_applied(self, **condition: Any) -> bool:
        self.calls.append("mark_effects_applied")
        if self.request["state"] != "claimed":
            return False
        self.request.update(
            {
                "state": "effects_applied",
                "outcome_at": condition["outcome_at"],
                "user_reference": condition["user_reference"],
                "membership_reference": condition["membership_reference"],
            }
        )
        return True

    def mark_audit_committed(self, **condition: Any) -> bool:
        self.calls.append("mark_audit_committed")
        if not self.mark_audit_result or self.request["state"] != "effects_applied":
            return False
        self.request.update(
            {
                "state": "audit_committed",
                "audit_decision_id": condition["audit_decision_id"],
            }
        )
        return True

    def consume(self, **condition: Any) -> bool:
        self.calls.append("consume")
        if not self.consume_result or self.request["state"] != "audit_committed":
            return False
        self.request.update(
            {
                "state": "consumed",
                "consumed_at": condition["consumed_at"],
                "result_reference": condition["result_reference"],
            }
        )
        return True

    def release(self, **condition: Any) -> None:
        self.calls.append("release")
        if self.request["state"] == "claimed":
            self.request["state"] = "approved"
            self.request.pop("claim_token", None)
            self.request.pop("claimed_at", None)


@dataclass
class Provider:
    calls: int = 0

    def ensure_user(self, **record: Any) -> dict[str, str]:
        self.calls += 1
        return {
            "user_reference": "usr_synthetic_reference",
            "provider_principal_key": SUBJECT,
            "temporary_password": "SENSITIVE-MUST-NOT-ESCAPE",
        }


@dataclass
class Memberships:
    calls: int = 0

    def ensure_membership(self, **record: Any) -> dict[str, str]:
        self.calls += 1
        return {
            "membership_reference": "mem_synthetic_reference",
            "recovery_value": "SENSITIVE-MUST-NOT-ESCAPE",
        }


@dataclass
class IdempotentAudit:
    fail: bool = False
    events: dict[str, dict[str, Any]] = field(default_factory=dict)

    def emit(self, event: dict[str, Any]) -> None:
        if self.fail:
            raise RuntimeError("synthetic audit outage")
        existing = self.events.get(event["decision_id"])
        if existing is not None and existing != event:
            raise RuntimeError("conflicting audit replay")
        self.events[event["decision_id"]] = copy.deepcopy(event)


def _processor(
    *,
    store: RecoverableRequestStore | None = None,
    audit: IdempotentAudit | None = None,
) -> tuple[BootstrapProcessor, RecoverableRequestStore, Provider, Memberships, IdempotentAudit]:
    store = store or RecoverableRequestStore()
    provider = Provider()
    memberships = Memberships()
    audit = audit or IdempotentAudit()
    return (
        BootstrapProcessor(
            config=_config(),
            request_store=store,
            identity_provider=provider,
            membership_store=memberships,
            audit_sink=audit,
            clock=lambda: NOW,
        ),
        store,
        provider,
        memberships,
        audit,
    )


def _deny(processor: BootstrapProcessor) -> str:
    with pytest.raises(BootstrapDenied) as captured:
        processor.process(_command())
    return captured.value.reason_code


def test_audit_outage_recovers_without_repeating_provider_or_membership_effects() -> None:
    audit = IdempotentAudit(fail=True)
    processor, store, provider, memberships, _ = _processor(audit=audit)

    assert _deny(processor) == "audit_dependency_unavailable"
    assert store.request["state"] == "effects_applied"
    assert provider.calls == 1
    assert memberships.calls == 1
    assert "consume" not in store.calls

    audit.fail = False
    result = processor.process(_command())
    assert result["status"] == "completed"
    assert store.request["state"] == "consumed"
    assert provider.calls == 1
    assert memberships.calls == 1
    assert sum(event["decision"] == "allow" for event in audit.events.values()) == 1


def test_audit_checkpoint_failure_replays_one_exact_idempotent_event() -> None:
    store = RecoverableRequestStore(mark_audit_result=False)
    processor, store, provider, memberships, audit = _processor(store=store)

    assert _deny(processor) == "bootstrap_audit_checkpoint_conflict"
    assert store.request["state"] == "effects_applied"
    assert sum(event["decision"] == "allow" for event in audit.events.values()) == 1

    store.mark_audit_result = True
    result = processor.process(_command())
    assert result["status"] == "completed"
    assert provider.calls == 1
    assert memberships.calls == 1
    assert sum(event["decision"] == "allow" for event in audit.events.values()) == 1


def test_consume_failure_recovers_after_audit_without_repeating_prior_steps() -> None:
    store = RecoverableRequestStore(consume_result=False)
    processor, store, provider, memberships, audit = _processor(store=store)

    assert _deny(processor) == "bootstrap_consume_conflict"
    assert store.request["state"] == "audit_committed"
    assert sum(event["decision"] == "allow" for event in audit.events.values()) == 1

    store.consume_result = True
    result = processor.process(_command())
    assert result["status"] == "completed"
    assert provider.calls == 1
    assert memberships.calls == 1
    assert sum(event["decision"] == "allow" for event in audit.events.values()) == 1


def test_consumed_bootstrap_replay_remains_denied() -> None:
    processor, store, *_ = _processor()
    processor.process(_command())
    assert store.request["state"] == "consumed"
    assert _deny(processor) == "bootstrap_replay_denied"
