from __future__ import annotations

import copy
import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

import pytest

from identity_control_plane.bootstrap import BootstrapDenied, BootstrapProcessor


CUSTOMER_ID = "cust_01HZX3YQ8J4F6A2B7C9D0E1G5K"
DEPLOYMENT_ID = "dep_01HZX3YQ8J4F6A2B7C9D0E1G5K"
FOREIGN_CUSTOMER_ID = "cust_01HZX3YQ8J4F6A2B7C9D0E1G5M"
FOREIGN_DEPLOYMENT_ID = "dep_01HZX3YQ8J4F6A2B7C9D0E1G5M"
SUBJECT = "00000000-0000-4000-8000-000000000001"
APPROVER_A = "00000000-0000-4000-8000-000000000010"
APPROVER_B = "00000000-0000-4000-8000-000000000011"
REQUEST_ID = "boot_01HZX3YQ8J4F6A2B7C9D0E1G5K"
IDEMPOTENCY_KEY = "idem_01HZX3YQ8J4F6A2B7C9D0E1G5K"
POLICY_DIGEST = f"sha256:{'a' * 64}"
NOW = datetime(2026, 7, 13, 12, 0, tzinfo=timezone.utc)
SENSITIVE_TEMPORARY_VALUE = "SENSITIVE_CANARY_TEMPORARY_VALUE"
SENSITIVE_INVITATION_VALUE = "SENSITIVE_CANARY_INVITATION_VALUE"
SENSITIVE_RECOVERY_VALUE = "SENSITIVE_CANARY_RECOVERY_VALUE"


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
    }


def _approval(subject: str, **overrides: Any) -> dict[str, Any]:
    approval = {
        "approval_reference": f"approval-{subject[-2:]}",
        "request_id": REQUEST_ID,
        "approver_subject": subject,
        "customer_id": CUSTOMER_ID,
        "deployment_id": DEPLOYMENT_ID,
        "decision": "approved",
        "assurance": "phishing_resistant_mfa",
        "authenticated_at": NOW - timedelta(seconds=60),
    }
    approval.update(overrides)
    return approval


def _stored_request(**overrides: Any) -> dict[str, Any]:
    request = {
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
        "approvals": [_approval(APPROVER_A), _approval(APPROVER_B)],
        "authz_schema_version": "enterprise-authorization.v1",
        "scope_catalog_version": "scanalyze.api.v1",
        "role_catalog_version": "enterprise-roles.v1",
        "policy_version": "1.0.0",
        "policy_digest": POLICY_DIGEST,
    }
    request.update(overrides)
    return request


def _command(**overrides: Any) -> dict[str, Any]:
    command = {
        "schema_version": "identity-bootstrap-command.v1",
        "request_id": REQUEST_ID,
        "expected_version": 7,
        "subject": SUBJECT,
        "customer_id": CUSTOMER_ID,
        "deployment_id": DEPLOYMENT_ID,
    }
    command.update(overrides)
    return command


@dataclass
class RequestStore:
    request: dict[str, Any] | None
    load_error: Exception | None = None
    claim_result: str | None = "synthetic-claim-token"
    consume_result: bool = True
    calls: list[tuple[str, dict[str, Any]]] = field(default_factory=list)

    def load(self, request_id: str) -> dict[str, Any] | None:
        self.calls.append(("load", {"request_id": request_id}))
        if self.load_error is not None:
            raise self.load_error
        return copy.deepcopy(self.request)

    def claim(self, **condition: Any) -> str | None:
        self.calls.append(("claim", condition))
        if self.claim_result is not None and self.request is not None:
            self.request.update(
                {
                    "state": "claimed",
                    "claim_token": self.claim_result,
                    "claimed_at": condition["claimed_at"],
                }
            )
        return self.claim_result

    def mark_effects_applied(self, **condition: Any) -> bool:
        self.calls.append(("mark_effects_applied", condition))
        if self.request is None or self.request.get("state") != "claimed":
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
        self.calls.append(("mark_audit_committed", condition))
        if self.request is None or self.request.get("state") != "effects_applied":
            return False
        self.request.update(
            {
                "state": "audit_committed",
                "audit_decision_id": condition["audit_decision_id"],
            }
        )
        return True

    def consume(self, **condition: Any) -> bool:
        self.calls.append(("consume", condition))
        if self.consume_result and self.request is not None:
            self.request["state"] = "consumed"
        return self.consume_result

    def release(self, **condition: Any) -> None:
        self.calls.append(("release", condition))
        if self.request is not None and self.request.get("state") == "claimed":
            self.request["state"] = "approved"
            self.request.pop("claim_token", None)
            self.request.pop("claimed_at", None)


@dataclass
class IdentityProvider:
    error: Exception | None = None
    calls: list[dict[str, Any]] = field(default_factory=list)

    def ensure_user(self, **record: Any) -> dict[str, Any]:
        self.calls.append(record)
        if self.error is not None:
            raise self.error
        return {
            "user_reference": "usr_synthetic_reference",
            "provider_principal_key": SUBJECT,
            "temporary_password": SENSITIVE_TEMPORARY_VALUE,
            "invitation_secret": SENSITIVE_INVITATION_VALUE,
        }


@dataclass
class MembershipStore:
    error: Exception | None = None
    calls: list[dict[str, Any]] = field(default_factory=list)

    def ensure_membership(self, **record: Any) -> dict[str, Any]:
        self.calls.append(record)
        if self.error is not None:
            raise self.error
        return {
            "membership_reference": "mem_synthetic_reference",
            "recovery_value": SENSITIVE_RECOVERY_VALUE,
        }


@dataclass
class AuditSink:
    events: list[dict[str, Any]] = field(default_factory=list)

    def emit(self, event: dict[str, Any]) -> None:
        self.events.append(copy.deepcopy(event))


def _processor(
    request: dict[str, Any] | None = None,
    *,
    load_error: Exception | None = None,
    claim_result: str | None = "synthetic-claim-token",
    consume_result: bool = True,
    provider_error: Exception | None = None,
    membership_error: Exception | None = None,
) -> tuple[
    BootstrapProcessor,
    RequestStore,
    IdentityProvider,
    MembershipStore,
    AuditSink,
]:
    request_store = RequestStore(
        _stored_request() if request is None else request,
        load_error=load_error,
        claim_result=claim_result,
        consume_result=consume_result,
    )
    identity_provider = IdentityProvider(error=provider_error)
    membership_store = MembershipStore(error=membership_error)
    audit = AuditSink()
    processor = BootstrapProcessor(
        config=_config(),
        request_store=request_store,
        identity_provider=identity_provider,
        membership_store=membership_store,
        audit_sink=audit,
        clock=lambda: NOW,
        logger=logging.getLogger("scanalyze.identity.bootstrap.test"),
    )
    return processor, request_store, identity_provider, membership_store, audit


def _deny_reason(processor: BootstrapProcessor, command: dict[str, Any]) -> str:
    with pytest.raises(BootstrapDenied) as exc_info:
        processor.process(command)
    return exc_info.value.reason_code


def test_valid_bootstrap_uses_authoritative_binding_and_conditional_single_use() -> None:
    processor, request_store, provider, memberships, audit = _processor()

    result = processor.process(_command())

    assert result == {
        "status": "completed",
        "request_reference": "bootstrap_request_completed",
        "user_reference": "usr_synthetic_reference",
        "membership_reference": "mem_synthetic_reference",
    }
    assert provider.calls == [
        {
            "subject": SUBJECT,
            "immutable_attributes": {
                "custom:customerId": CUSTOMER_ID,
                "custom:deployment_id": DEPLOYMENT_ID,
            },
            "idempotency_key": IDEMPOTENCY_KEY,
        }
    ]
    assert memberships.calls == [
        {
            "subject": SUBJECT,
            "customer_id": CUSTOMER_ID,
            "deployment_id": DEPLOYMENT_ID,
            "role_id": "customer_admin",
            "state": "active",
            "membership_version": 1,
            "provider_user_reference": "usr_synthetic_reference",
            "provider_principal_key": SUBJECT,
            "created_at": NOW,
            "authz_schema_version": "enterprise-authorization.v1",
            "scope_catalog_version": "scanalyze.api.v1",
            "role_catalog_version": "enterprise-roles.v1",
            "policy_version": "1.0.0",
            "policy_digest": POLICY_DIGEST,
            "idempotency_key": IDEMPOTENCY_KEY,
        }
    ]
    claim = next(details for name, details in request_store.calls if name == "claim")
    assert claim == {
        "request_id": REQUEST_ID,
        "expected_state": "approved",
        "expected_version": 7,
        "idempotency_key": IDEMPOTENCY_KEY,
        "claimed_at": NOW,
    }
    consume = next(details for name, details in request_store.calls if name == "consume")
    assert consume == {
        "request_id": REQUEST_ID,
        "claim_token": "synthetic-claim-token",
        "expected_state": "audit_committed",
        "expected_version": 7,
        "consumed_at": NOW,
        "result_reference": "bootstrap_request_completed",
    }
    assert audit.events[-1]["decision"] == "allow"


def test_disabled_human_runtime_denies_before_read_or_side_effect() -> None:
    processor, request_store, provider, memberships, audit = _processor()
    processor.config["human_runtime_enabled"] = False

    assert (
        _deny_reason(processor, _command())
        == "human_runtime_provisioning_disabled"
    )
    assert request_store.calls == []
    assert provider.calls == []
    assert memberships.calls == []
    assert audit.events[-1]["decision"] == "deny"


@pytest.mark.parametrize(
    ("field", "value", "reason"),
    [
        ("subject", None, "missing_binding"),
        ("customer_id", None, "missing_binding"),
        ("deployment_id", None, "missing_binding"),
        ("subject", "", "malformed_binding"),
        ("customer_id", "customer-one", "malformed_binding"),
        ("deployment_id", "deployment-one", "malformed_binding"),
        ("customer_id", FOREIGN_CUSTOMER_ID, "foreign_binding"),
        ("deployment_id", FOREIGN_DEPLOYMENT_ID, "foreign_binding"),
    ],
)
def test_missing_malformed_or_foreign_stored_binding_denies_before_side_effects(
    field: str,
    value: str | None,
    reason: str,
) -> None:
    request = _stored_request()
    if value is None:
        del request[field]
    else:
        request[field] = value
    processor, _, provider, memberships, _ = _processor(request)

    assert _deny_reason(processor, _command()) == reason
    assert provider.calls == []
    assert memberships.calls == []


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("subject", "00000000-0000-4000-8000-000000000002"),
        ("customer_id", FOREIGN_CUSTOMER_ID),
        ("deployment_id", FOREIGN_DEPLOYMENT_ID),
        ("expected_version", 8),
    ],
)
def test_conflicting_command_binding_denies_without_using_payload_as_authority(
    field: str,
    value: Any,
) -> None:
    processor, _, provider, memberships, _ = _processor()

    assert _deny_reason(processor, _command(**{field: value})) == "conflicting_binding"
    assert provider.calls == []
    assert memberships.calls == []


@pytest.mark.parametrize(
    ("approvals", "reason"),
    [
        ([_approval(APPROVER_A)], "dual_approval_required"),
        (
            [_approval(APPROVER_A), _approval(APPROVER_A)],
            "independent_approvers_required",
        ),
        (
            [_approval(SUBJECT), _approval(APPROVER_B)],
            "self_approval_forbidden",
        ),
        (
            [_approval(APPROVER_A, decision="denied"), _approval(APPROVER_B)],
            "dual_approval_required",
        ),
        (
            [
                _approval(APPROVER_A, assurance="password"),
                _approval(APPROVER_B),
            ],
            "insufficient_assurance",
        ),
        (
            [
                _approval(APPROVER_A, authenticated_at=NOW - timedelta(seconds=301)),
                _approval(APPROVER_B),
            ],
            "stale_approval",
        ),
        (
            [
                _approval(APPROVER_A, customer_id=FOREIGN_CUSTOMER_ID),
                _approval(APPROVER_B),
            ],
            "conflicting_approval_binding",
        ),
        (
            [
                _approval(APPROVER_A, deployment_id=FOREIGN_DEPLOYMENT_ID),
                _approval(APPROVER_B),
            ],
            "conflicting_approval_binding",
        ),
        (
            [
                _approval(APPROVER_A, request_id="boot_foreign"),
                _approval(APPROVER_B),
            ],
            "conflicting_approval_binding",
        ),
        (
            [
                _approval(APPROVER_A),
                _approval(APPROVER_B),
                _approval("00000000-0000-4000-8000-000000000012"),
            ],
            "dual_approval_required",
        ),
        (
            [
                _approval(APPROVER_A, approval_reference="same-reference"),
                _approval(APPROVER_B, approval_reference="same-reference"),
            ],
            "independent_approvers_required",
        ),
        (
            [
                _approval(
                    APPROVER_A,
                    authenticated_at=NOW - timedelta(seconds=61),
                ),
                _approval(APPROVER_B),
            ],
            "stale_approval",
        ),
    ],
)
def test_dual_approval_is_independent_bound_fresh_and_not_self_approved(
    approvals: list[dict[str, Any]],
    reason: str,
) -> None:
    processor, _, provider, memberships, _ = _processor(
        _stored_request(approvals=approvals)
    )

    assert _deny_reason(processor, _command()) == reason
    assert provider.calls == []
    assert memberships.calls == []


@pytest.mark.parametrize(
    ("request_overrides", "reason"),
    [
        ({"state": "pending"}, "bootstrap_not_approved"),
        ({"state": "consumed"}, "bootstrap_replay_denied"),
        ({"state": "revoked"}, "bootstrap_not_approved"),
        ({"expires_at": NOW}, "bootstrap_expired"),
        ({"expires_at": NOW - timedelta(seconds=1)}, "bootstrap_expired"),
        (
            {
                "issued_at": NOW + timedelta(seconds=1),
                "expires_at": NOW + timedelta(seconds=600),
            },
            "bootstrap_not_yet_valid",
        ),
        (
            {
                "issued_at": NOW - timedelta(seconds=1),
                "expires_at": NOW + timedelta(seconds=900),
            },
            "bootstrap_ttl_exceeded",
        ),
    ],
)
def test_state_replay_expiry_and_ttl_are_fail_closed(
    request_overrides: dict[str, Any],
    reason: str,
) -> None:
    processor, _, provider, memberships, _ = _processor(
        _stored_request(**request_overrides)
    )

    assert _deny_reason(processor, _command()) == reason
    assert provider.calls == []
    assert memberships.calls == []


@pytest.mark.parametrize(
    ("field", "value", "reason"),
    [
        ("schema_version", "identity-bootstrap-request.v0", "unsupported_contract"),
        ("role_id", "unknown_superuser", "unknown_role"),
        ("authz_schema_version", "enterprise-authorization.v0", "stale_authorization_contract"),
        ("scope_catalog_version", "scanalyze.api.v0", "stale_authorization_contract"),
        ("role_catalog_version", "enterprise-roles.v0", "stale_authorization_contract"),
        ("policy_version", "0.9.0", "stale_authorization_contract"),
        ("policy_digest", f"sha256:{'b' * 64}", "stale_authorization_contract"),
        ("policy_digest", "malformed", "stale_authorization_contract"),
        ("idempotency_key", "", "missing_idempotency_key"),
    ],
)
def test_unknown_roles_and_stale_contracts_are_denied(
    field: str,
    value: Any,
    reason: str,
) -> None:
    processor, _, provider, memberships, _ = _processor(
        _stored_request(**{field: value})
    )

    assert _deny_reason(processor, _command()) == reason
    assert provider.calls == []
    assert memberships.calls == []


def test_conditional_claim_conflict_denies_replay_before_side_effects() -> None:
    processor, _, provider, memberships, _ = _processor(claim_result=None)

    assert _deny_reason(processor, _command()) == "bootstrap_claim_conflict"
    assert provider.calls == []
    assert memberships.calls == []


def test_conditional_consume_conflict_fails_closed_and_keeps_audit_checkpoint() -> None:
    processor, request_store, _, _, _ = _processor(consume_result=False)

    assert _deny_reason(processor, _command()) == "bootstrap_consume_conflict"
    assert request_store.request is not None
    assert request_store.request["state"] == "audit_committed"
    assert all(name != "release" for name, _ in request_store.calls)


def test_provider_and_membership_side_effects_share_trusted_idempotency_key() -> None:
    processor, _, provider, memberships, _ = _processor()
    command = _command(idempotency_key="attacker-controlled-key")

    processor.process(command)

    assert provider.calls[0]["idempotency_key"] == IDEMPOTENCY_KEY
    assert memberships.calls[0]["idempotency_key"] == IDEMPOTENCY_KEY


@pytest.mark.parametrize(
    ("dependency", "expected_reason"),
    [
        ("request", "bootstrap_dependency_unavailable"),
        ("provider", "identity_provider_unavailable"),
        ("membership", "membership_dependency_unavailable"),
    ],
)
def test_dependency_timeout_fails_closed_and_never_consumes(
    dependency: str,
    expected_reason: str,
) -> None:
    kwargs: dict[str, Any] = {}
    if dependency == "request":
        kwargs["load_error"] = TimeoutError("dependency timeout")
    elif dependency == "provider":
        kwargs["provider_error"] = TimeoutError("dependency timeout")
    else:
        kwargs["membership_error"] = TimeoutError("dependency timeout")
    processor, request_store, _, _, _ = _processor(**kwargs)

    assert _deny_reason(processor, _command()) == expected_reason
    assert all(name != "consume" for name, _ in request_store.calls)


def test_sensitive_provider_values_are_never_returned_logged_or_audited(
    caplog: pytest.LogCaptureFixture,
) -> None:
    processor, _, _, _, audit = _processor()
    caplog.set_level(logging.INFO, logger="scanalyze.identity.bootstrap.test")

    result = processor.process(_command())

    serialized_result = repr(result)
    serialized_logs = "\n".join(record.getMessage() for record in caplog.records)
    serialized_audit = repr(audit.events)
    for canary in (
        SENSITIVE_TEMPORARY_VALUE,
        SENSITIVE_INVITATION_VALUE,
        SENSITIVE_RECOVERY_VALUE,
        SUBJECT,
        CUSTOMER_ID,
        DEPLOYMENT_ID,
    ):
        assert canary not in serialized_result
        assert canary not in serialized_logs
        assert canary not in serialized_audit
    assert "temporary_password" not in serialized_logs
    assert "invitation_secret" not in serialized_logs
    assert "raw_claims" not in serialized_logs
