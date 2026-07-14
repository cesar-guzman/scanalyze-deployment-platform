"""GUG-94 portable, fail-closed enterprise user lifecycle tests."""
from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone
from typing import Any

import pytest

from app.auth import AuthContext
from app.enterprise_authorization import (
    AUTHORIZATION_CONTEXT_SCHEMA_VERSION,
    AUTHZ_SCHEMA_VERSION,
    MEMBERSHIP_SOURCE,
    POLICY_DIGEST,
    POLICY_VERSION,
    ROLE_CATALOG_VERSION,
    SCOPE_CATALOG_VERSION,
    Assurance,
    AssuranceSource,
    AssuranceVersion,
    AuthorizationPath,
    HumanAuthorizationSnapshot,
    HumanRole,
)
from app.errors import AppError
from app.user_lifecycle import (
    ApprovalEvidence,
    EnterpriseLifecycleRuntime,
    IdempotencyConflict,
    InvitationResendRequest,
    LifecycleAuditReceipt,
    LifecycleCommand,
    LifecycleOperation,
    LifecycleOperationRecord,
    LifecycleOperationStage,
    MembershipPage,
    MembershipRecord,
    MembershipState,
    ProviderUserReceipt,
    RoleChangeRequest,
    TransitionRequest,
    UserInvitationRequest,
    UserLifecycleService,
)


CUSTOMER_ID = "cust_01ARZ3NDEKTSV4RRFFQ69G5FAW"
DEPLOYMENT_ID = "dep_01ARZ3NDEKTSV4RRFFQ69G5FAV"
FOREIGN_CUSTOMER_ID = "cust_01ARZ3NDEKTSV4RRFFQ69G5FAX"
FOREIGN_DEPLOYMENT_ID = "dep_01ARZ3NDEKTSV4RRFFQ69G5FAY"
ACTOR_SUBJECT = "synthetic-admin-subject"
TARGET_SUBJECT = "synthetic-target-subject"
NOW = datetime(2026, 7, 13, 12, 0, tzinfo=timezone.utc)


def _snapshot(*, subject: str = ACTOR_SUBJECT) -> HumanAuthorizationSnapshot:
    return HumanAuthorizationSnapshot(
        schema_version=AUTHORIZATION_CONTEXT_SCHEMA_VERSION,
        authorization_path=AuthorizationPath.MEMBERSHIP,
        authorization_source=MEMBERSHIP_SOURCE,
        subject=subject,
        customer_id=CUSTOMER_ID,
        deployment_id=DEPLOYMENT_ID,
        membership_state="active",
        role_id=HumanRole.CUSTOMER_ADMIN,
        membership_version="membership-v7",
        temporary_grant_id=None,
        temporary_grant_type=None,
        temporary_grant_state=None,
        temporary_grant_version=None,
        allowed_operation_ids=frozenset(),
        allowed_data_classes=frozenset(),
        expires_at_epoch=None,
        authz_schema_version=AUTHZ_SCHEMA_VERSION,
        scope_catalog_version=SCOPE_CATALOG_VERSION,
        role_catalog_version=ROLE_CATALOG_VERSION,
        policy_version=POLICY_VERSION,
        policy_digest=POLICY_DIGEST,
        issued_at_epoch=int(NOW.timestamp()) - 30,
        assurance=Assurance.PHISHING_RESISTANT_MFA,
        authenticated_at_epoch=int(NOW.timestamp()) - 60,
        assurance_source=AssuranceSource.AUTHORITATIVE_AUTHENTICATION_EVENT,
        assurance_version=AssuranceVersion.PHISHING_RESISTANT_MFA_V1,
        authentication_event_reference="ref_" + "a" * 24,
    )


def _auth(*, subject: str = ACTOR_SUBJECT) -> AuthContext:
    return AuthContext(
        customer_id=CUSTOMER_ID,
        deployment_id=DEPLOYMENT_ID,
        principal_type="user",
        subject=subject,
        scopes={
            "scanalyze.api.v1/read",
            "scanalyze.api.v1/admin",
        },
        auth_source="cognito_jwt",
        human_authorization=_snapshot(subject=subject),
    )


def _membership(
    *,
    reference: str = "mbr_" + "1" * 32,
    subject: str = TARGET_SUBJECT,
    customer_id: str = CUSTOMER_ID,
    deployment_id: str = DEPLOYMENT_ID,
    state: MembershipState = MembershipState.ACTIVE,
    role: HumanRole = HumanRole.DOCUMENT_OPERATOR,
    version: int = 3,
) -> MembershipRecord:
    return MembershipRecord(
        schema_version="enterprise-membership.v1",
        membership_reference=reference,
        subject=subject,
        customer_id=customer_id,
        deployment_id=deployment_id,
        state=state,
        role_id=role,
        membership_version=version,
        provider_user_reference="ref_" + "b" * 24,
        provider_principal_key="synthetic-provider-principal",
        created_at=NOW - timedelta(days=1),
        updated_at=NOW - timedelta(minutes=1),
        invitation_expires_at=(
            NOW + timedelta(minutes=30)
            if state is MembershipState.INVITED
            else None
        ),
    )


class FakeOperationStore:
    def __init__(self) -> None:
        self.operations: dict[tuple[str, str, str], LifecycleOperationRecord] = {}
        self.memberships: dict[str, MembershipRecord] = {}
        self.list_calls: list[dict[str, Any]] = []
        self.fail_audit_checkpoint = False
        self.fail_provider_applied_checkpoint = False

    def reserve_operation(self, command: LifecycleCommand) -> LifecycleOperationRecord:
        key = (command.customer_id, command.deployment_id, command.idempotency_key)
        existing = self.operations.get(key)
        if existing is not None:
            if existing.request_digest != command.request_digest or existing.operation != command.operation:
                raise IdempotencyConflict()
            return existing
        record = LifecycleOperationRecord.new(command, now=NOW)
        self.operations[key] = record
        return record

    def checkpoint_operation(
        self,
        record: LifecycleOperationRecord,
        *,
        expected_stage: LifecycleOperationStage,
        next_stage: LifecycleOperationStage,
        evidence: dict[str, str] | None = None,
    ) -> LifecycleOperationRecord:
        if self.fail_audit_checkpoint and next_stage is LifecycleOperationStage.AUDIT_COMMITTED:
            raise RuntimeError("synthetic checkpoint failure")
        if (
            self.fail_provider_applied_checkpoint
            and next_stage is LifecycleOperationStage.PROVIDER_APPLIED
        ):
            raise RuntimeError("synthetic provider checkpoint failure")
        current = self.operations[(record.customer_id, record.deployment_id, record.idempotency_key)]
        if current.stage is not expected_stage:
            return current
        updated = replace(
            current,
            stage=next_stage,
            evidence={**current.evidence, **(evidence or {})},
            updated_at=NOW,
        )
        self.operations[(record.customer_id, record.deployment_id, record.idempotency_key)] = updated
        return updated

    def list_memberships(
        self,
        *,
        customer_id: str,
        deployment_id: str,
        state: MembershipState | None,
        cursor: str | None,
        limit: int,
    ) -> MembershipPage:
        self.list_calls.append(locals())
        owned = [
            value
            for value in self.memberships.values()
            if value.customer_id == customer_id
            and value.deployment_id == deployment_id
            and (state is None or value.state is state)
        ]
        return MembershipPage(tuple(owned[:limit]), None)

    def load_membership(
        self,
        *,
        customer_id: str,
        deployment_id: str,
        membership_reference: str,
    ) -> MembershipRecord | None:
        record = self.memberships.get(membership_reference)
        if record is None:
            return None
        if record.customer_id != customer_id or record.deployment_id != deployment_id:
            return None
        return record

    def create_invited_membership(
        self,
        *,
        customer_id: str,
        deployment_id: str,
        provider_receipt: ProviderUserReceipt,
        role_id: HumanRole,
        expires_at: datetime,
        operation_reference: str,
    ) -> MembershipRecord:
        reference = "mbr_" + "9" * 32
        current = self.memberships.get(reference)
        if current is not None:
            return current
        record = MembershipRecord(
            schema_version="enterprise-membership.v1",
            membership_reference=reference,
            subject=provider_receipt.subject,
            customer_id=customer_id,
            deployment_id=deployment_id,
            state=MembershipState.INVITED,
            role_id=role_id,
            membership_version=1,
            provider_user_reference=provider_receipt.provider_user_reference,
            provider_principal_key=provider_receipt.provider_principal_key,
            created_at=NOW,
            updated_at=NOW,
            invitation_expires_at=expires_at,
        )
        self.memberships[reference] = record
        return record

    def transition_membership(
        self,
        *,
        current: MembershipRecord,
        expected_state: MembershipState,
        expected_version: int,
        next_state: MembershipState,
        next_role: HumanRole,
        operation_reference: str,
        admin_replacement: MembershipRecord | None,
    ) -> MembershipRecord:
        stored = self.memberships[current.membership_reference]
        if stored.state is not expected_state or stored.membership_version != expected_version:
            raise RuntimeError("synthetic conditional conflict")
        updated = replace(
            stored,
            state=next_state,
            role_id=next_role,
            membership_version=stored.membership_version + 1,
            updated_at=NOW,
            invitation_expires_at=(
                stored.invitation_expires_at
                if next_state is MembershipState.INVITED
                else None
            ),
        )
        self.memberships[current.membership_reference] = updated
        return updated

    def refresh_invitation(
        self,
        *,
        current: MembershipRecord,
        expected_version: int,
        expires_at: datetime,
        operation_reference: str,
    ) -> MembershipRecord:
        stored = self.memberships[current.membership_reference]
        if (
            stored.state is not MembershipState.INVITED
            or stored.membership_version != expected_version
        ):
            raise RuntimeError("synthetic conditional conflict")
        updated = replace(
            stored,
            membership_version=stored.membership_version + 1,
            updated_at=NOW,
            invitation_expires_at=expires_at,
        )
        self.memberships[current.membership_reference] = updated
        return updated

class FakeProvider:
    def __init__(self) -> None:
        self.invites = 0
        self.resends = 0
        self.activations = 0
        self.enabled: list[tuple[str, bool]] = []
        self.session_revocations = 0

    def invite_user(self, **request: Any) -> ProviderUserReceipt:
        self.invites += 1
        return ProviderUserReceipt(
            subject=TARGET_SUBJECT,
            provider_user_reference="ref_" + "b" * 24,
            provider_principal_key="synthetic-provider-principal",
            principal_locator_digest=request["principal_locator_digest"],
            state="invited",
        )

    def resend_invitation(self, **request: Any) -> ProviderUserReceipt:
        self.resends += 1
        return ProviderUserReceipt(
            subject=request["subject"],
            provider_user_reference=request["provider_user_reference"],
            provider_principal_key=request["provider_principal_key"],
            principal_locator_digest="sha256:" + "c" * 64,
            state="invited",
        )

    def confirm_activation(self, **request: Any) -> ProviderUserReceipt:
        self.activations += 1
        return ProviderUserReceipt(
            subject=request["subject"],
            provider_user_reference=request["provider_user_reference"],
            provider_principal_key=request["provider_principal_key"],
            principal_locator_digest="sha256:" + "c" * 64,
            state="active",
        )

    def set_user_enabled(self, **request: Any) -> ProviderUserReceipt:
        self.enabled.append((request["subject"], request["enabled"]))
        return ProviderUserReceipt(
            subject=request["subject"],
            provider_user_reference=request["provider_user_reference"],
            provider_principal_key=request["provider_principal_key"],
            principal_locator_digest="sha256:" + "c" * 64,
            state="active" if request["enabled"] else "disabled",
        )

    def revoke_sessions(self, **request: Any) -> str:
        self.session_revocations += 1
        return "ref_" + "d" * 24


class FakeApprovals:
    def __init__(self) -> None:
        self.foreign = False
        self.self_approved = False
        self.request_digest_override: str | None = None

    def resolve(self, **request: Any) -> ApprovalEvidence:
        return ApprovalEvidence(
            schema_version="lifecycle-approval-evidence.v1",
            approval_reference=request["approval_reference"],
            approver_subject=(ACTOR_SUBJECT if self.self_approved else "independent-approver"),
            customer_id=(FOREIGN_CUSTOMER_ID if self.foreign else request["customer_id"]),
            deployment_id=request["deployment_id"],
            operation=request["operation"],
            target_reference=request["target_reference"],
            request_digest=(
                self.request_digest_override or request["request_digest"]
            ),
            state="approved",
            expires_at=NOW + timedelta(minutes=5),
        )


class FakeAudit:
    def __init__(self) -> None:
        self.events: list[dict[str, Any]] = []
        self.fail = False

    def emit(self, event: dict[str, Any]) -> LifecycleAuditReceipt:
        if self.fail:
            raise RuntimeError("synthetic audit failure")
        self.events.append(event)
        return LifecycleAuditReceipt(
            schema_version="lifecycle-audit-receipt.v1",
            decision_id=event["decision_id"],
            receipt_reference="ref_" + "e" * 24,
            acknowledged_at=NOW,
        )


def _service(
    *,
    store: FakeOperationStore | None = None,
    provider: FakeProvider | None = None,
    approvals: FakeApprovals | None = None,
    audit: FakeAudit | None = None,
) -> tuple[UserLifecycleService, FakeOperationStore, FakeProvider, FakeApprovals, FakeAudit]:
    store = store or FakeOperationStore()
    provider = provider or FakeProvider()
    approvals = approvals or FakeApprovals()
    audit = audit or FakeAudit()
    runtime = EnterpriseLifecycleRuntime(
        operation_store=store,
        membership_store=store,
        identity_provider=provider,
        approval_resolver=approvals,
        audit_sink=audit,
        clock=lambda: NOW,
    )
    return UserLifecycleService(runtime), store, provider, approvals, audit


def _invite_request(**overrides: Any) -> UserInvitationRequest:
    values: dict[str, Any] = {
        "principal_locator": "synthetic.user@example.invalid",
        "role_id": HumanRole.DOCUMENT_OPERATOR,
        "expires_in_seconds": 3600,
        "approval_reference": "apr_" + "1" * 32,
    }
    values.update(overrides)
    return UserInvitationRequest(**values)


def _assert_denied(call: Any, *, status: int = 403) -> AppError:
    with pytest.raises(AppError) as captured:
        call()
    assert captured.value.status_code == status
    assert captured.value.details == {}
    return captured.value


def test_membership_list_binds_owner_at_repository_boundary() -> None:
    service, store, *_ = _service()
    owned = _membership()
    store.memberships[owned.membership_reference] = owned
    foreign = _membership(
        reference="mbr_" + "2" * 32,
        customer_id=FOREIGN_CUSTOMER_ID,
    )
    store.memberships[foreign.membership_reference] = foreign

    result = service.list_memberships(_auth(), state=None, cursor=None, limit=25)

    assert [item.membership_reference for item in result.items] == [owned.membership_reference]
    assert store.list_calls[-1]["customer_id"] == CUSTOMER_ID
    assert store.list_calls[-1]["deployment_id"] == DEPLOYMENT_ID


@pytest.mark.parametrize(
    "payload",
    [
        {"customer_id": FOREIGN_CUSTOMER_ID},
        {"deploymentId": FOREIGN_DEPLOYMENT_ID},
        {"tenant-id": "foreign"},
        {"xTenantId": "foreign"},
    ],
)
def test_invitation_payload_rejects_identity_authority(payload: dict[str, Any]) -> None:
    with pytest.raises(Exception):
        UserInvitationRequest.model_validate({**_invite_request().model_dump(), **payload})


def test_invitation_uses_auth_owner_and_authoritative_approval() -> None:
    service, store, provider, _, audit = _service()

    result = service.invite_user(
        _auth(),
        _invite_request(),
        idempotency_key="idem_" + "1" * 32,
    )

    assert result.status == "completed"
    created = next(iter(store.memberships.values()))
    assert created.customer_id == CUSTOMER_ID
    assert created.deployment_id == DEPLOYMENT_ID
    assert created.state is MembershipState.INVITED
    assert provider.invites == 1
    assert audit.events[-1]["action"] == LifecycleOperation.INVITE.value
    serialized = str(audit.events[-1])
    assert "synthetic.user@example.invalid" not in serialized
    assert TARGET_SUBJECT not in serialized


def test_invitation_resend_is_owner_bound_idempotent_and_versioned() -> None:
    service, store, provider, _, audit = _service()
    invited = _membership(state=MembershipState.INVITED, version=3)
    store.memberships[invited.membership_reference] = invited
    request = InvitationResendRequest(
        expected_membership_version=3,
        expires_in_seconds=3600,
        approval_reference="apr_" + "2" * 32,
        reason_code="invitation_resend",
    )

    result = service.resend_invitation(
        _auth(),
        invited.membership_reference,
        request,
        idempotency_key="idem_" + "8" * 32,
    )

    assert result.status == "completed"
    assert provider.resends == 1
    refreshed = store.memberships[invited.membership_reference]
    assert refreshed.membership_version == 4
    assert refreshed.invitation_expires_at == NOW + timedelta(seconds=3600)
    assert audit.events[-1]["action"] == LifecycleOperation.RESEND_INVITATION.value

    retry = service.resend_invitation(
        _auth(),
        invited.membership_reference,
        request,
        idempotency_key="idem_" + "8" * 32,
    )
    assert retry.operation_reference == result.operation_reference
    assert provider.resends == 1


def test_ambiguous_invitation_resend_is_quarantined_without_duplicate_effect() -> None:
    service, store, provider, *_ = _service()
    invited = _membership(state=MembershipState.INVITED, version=3)
    store.memberships[invited.membership_reference] = invited
    store.fail_provider_applied_checkpoint = True
    request = InvitationResendRequest(
        expected_membership_version=3,
        expires_in_seconds=3600,
        approval_reference="apr_" + "3" * 32,
        reason_code="invitation_resend",
    )

    for _ in range(2):
        _assert_denied(
            lambda: service.resend_invitation(
                _auth(),
                invited.membership_reference,
                request,
                idempotency_key="idem_" + "9" * 32,
            ),
            status=503,
        )

    assert provider.resends == 1
    assert store.memberships[invited.membership_reference].membership_version == 3


def test_conflicting_idempotency_key_denies_without_second_provider_effect() -> None:
    service, _, provider, *_ = _service()
    key = "idem_" + "1" * 32
    service.invite_user(_auth(), _invite_request(), idempotency_key=key)

    _assert_denied(
        lambda: service.invite_user(
            _auth(),
            _invite_request(role_id=HumanRole.AUDITOR),
            idempotency_key=key,
        ),
        status=409,
    )
    assert provider.invites == 1


def test_exact_idempotent_replay_returns_completed_without_duplicate_effects() -> None:
    service, _, provider, *_ = _service()
    key = "idem_" + "1" * 32
    first = service.invite_user(_auth(), _invite_request(), idempotency_key=key)
    second = service.invite_user(_auth(), _invite_request(), idempotency_key=key)

    assert second == first
    assert provider.invites == 1


def test_foreign_or_self_approval_fails_before_provider_effect() -> None:
    approvals = FakeApprovals()
    service, _, provider, *_ = _service(approvals=approvals)
    approvals.foreign = True
    _assert_denied(
        lambda: service.invite_user(
            _auth(), _invite_request(), idempotency_key="idem_" + "2" * 32
        )
    )
    approvals.foreign = False
    approvals.self_approved = True
    _assert_denied(
        lambda: service.invite_user(
            _auth(), _invite_request(), idempotency_key="idem_" + "3" * 32
        )
    )
    assert provider.invites == 0


def test_approval_must_bind_the_exact_canonical_request_digest() -> None:
    approvals = FakeApprovals()
    approvals.request_digest_override = "sha256:" + "f" * 64
    service, _, provider, *_ = _service(approvals=approvals)

    _assert_denied(
        lambda: service.invite_user(
            _auth(),
            _invite_request(),
            idempotency_key="idem_" + "e" * 32,
        )
    )

    assert provider.invites == 0


def test_missing_or_malformed_auth_context_fails_closed() -> None:
    service, *_ = _service()
    for auth in (
        None,
        AuthContext(
            customer_id=CUSTOMER_ID,
            deployment_id=None,
            principal_type="user",
            subject=ACTOR_SUBJECT,
        ),
        AuthContext(
            customer_id=CUSTOMER_ID,
            deployment_id=DEPLOYMENT_ID,
            principal_type="m2m",
            client_id="synthetic-m2m",
            auth_source="m2m_identity_binding_v1",
        ),
    ):
        _assert_denied(
            lambda auth=auth: service.list_memberships(  # type: ignore[arg-type]
                auth, state=None, cursor=None, limit=25
            )
        )


def test_foreign_and_missing_membership_have_same_public_error() -> None:
    service, store, *_ = _service()
    foreign = _membership(customer_id=FOREIGN_CUSTOMER_ID)
    store.memberships[foreign.membership_reference] = foreign
    request = TransitionRequest(
        expected_membership_version=3,
        approval_reference="apr_" + "1" * 32,
        reason_code="security_review",
    )

    foreign_error = _assert_denied(
        lambda: service.suspend_membership(
            _auth(), foreign.membership_reference, request, idempotency_key="idem_" + "4" * 32
        ),
        status=404,
    )
    missing_error = _assert_denied(
        lambda: service.suspend_membership(
            _auth(), "mbr_" + "8" * 32, request, idempotency_key="idem_" + "5" * 32
        ),
        status=404,
    )
    assert (foreign_error.code, foreign_error.message) == (missing_error.code, missing_error.message)


def test_role_change_increments_version_revokes_sessions_and_audits() -> None:
    service, store, provider, _, audit = _service()
    member = _membership()
    store.memberships[member.membership_reference] = member
    request = RoleChangeRequest(
        expected_membership_version=3,
        role_id=HumanRole.DOCUMENT_REVIEWER,
        approval_reference="apr_" + "1" * 32,
        reason_code="approved_role_change",
    )

    result = service.change_role(
        _auth(), member.membership_reference, request, idempotency_key="idem_" + "6" * 32
    )

    updated = store.memberships[member.membership_reference]
    assert result.status == "completed"
    assert updated.role_id is HumanRole.DOCUMENT_REVIEWER
    assert updated.membership_version == 4
    assert provider.session_revocations == 1
    assert audit.events[-1]["before_membership_version"] == "3"
    assert audit.events[-1]["after_membership_version"] == "4"


@pytest.mark.parametrize(
    ("method", "initial", "expected"),
    [
        ("activate_membership", MembershipState.INVITED, MembershipState.ACTIVE),
        ("suspend_membership", MembershipState.ACTIVE, MembershipState.SUSPENDED),
        ("reactivate_membership", MembershipState.SUSPENDED, MembershipState.ACTIVE),
        ("revoke_membership", MembershipState.ACTIVE, MembershipState.REVOKED),
    ],
)
def test_only_cataloged_membership_transitions_are_applied(
    method: str,
    initial: MembershipState,
    expected: MembershipState,
) -> None:
    service, store, *_ = _service()
    member = _membership(state=initial)
    store.memberships[member.membership_reference] = member
    request = TransitionRequest(
        expected_membership_version=3,
        approval_reference="apr_" + "1" * 32,
        reason_code="approved_transition",
    )

    result = getattr(service, method)(
        _auth(), member.membership_reference, request, idempotency_key="idem_" + method[-8:].ljust(32, "1")
    )

    assert result.status == "completed"
    assert store.memberships[member.membership_reference].state is expected


def test_revoked_membership_cannot_be_reactivated() -> None:
    service, store, *_ = _service()
    member = _membership(state=MembershipState.REVOKED)
    store.memberships[member.membership_reference] = member
    request = TransitionRequest(
        expected_membership_version=3,
        approval_reference="apr_" + "1" * 32,
        reason_code="unsupported_reactivation",
    )
    _assert_denied(
        lambda: service.reactivate_membership(
            _auth(), member.membership_reference, request, idempotency_key="idem_" + "7" * 32
        ),
        status=409,
    )


def test_expired_invitation_cannot_be_activated() -> None:
    service, store, provider, *_ = _service()
    member = replace(
        _membership(state=MembershipState.INVITED),
        invitation_expires_at=NOW - timedelta(seconds=1),
    )
    store.memberships[member.membership_reference] = member
    request = TransitionRequest(
        expected_membership_version=3,
        approval_reference="apr_" + "1" * 32,
        reason_code="expired_invitation",
    )

    _assert_denied(
        lambda: service.activate_membership(
            _auth(),
            member.membership_reference,
            request,
            idempotency_key="idem_" + "7" * 32,
        ),
        status=409,
    )
    assert provider.activations == 0
    assert store.memberships[member.membership_reference].state is MembershipState.INVITED


def test_actor_cannot_mutate_own_role_or_membership_state() -> None:
    service, store, *_ = _service()
    member = _membership(subject=ACTOR_SUBJECT, role=HumanRole.CUSTOMER_ADMIN)
    store.memberships[member.membership_reference] = member
    transition = TransitionRequest(
        expected_membership_version=3,
        approval_reference="apr_" + "1" * 32,
        reason_code="self_change",
    )
    role_change = RoleChangeRequest(
        expected_membership_version=3,
        role_id=HumanRole.DOCUMENT_OPERATOR,
        approval_reference="apr_" + "1" * 32,
        reason_code="self_change",
    )
    for call in (
        lambda: service.change_role(_auth(), member.membership_reference, role_change, idempotency_key="idem_" + "8" * 32),
        lambda: service.suspend_membership(_auth(), member.membership_reference, transition, idempotency_key="idem_" + "9" * 32),
        lambda: service.revoke_membership(_auth(), member.membership_reference, transition, idempotency_key="idem_" + "a" * 32),
    ):
        _assert_denied(call)


def test_last_admin_cannot_be_removed_without_owned_active_replacement() -> None:
    service, store, *_ = _service()
    target = _membership(role=HumanRole.CUSTOMER_ADMIN)
    store.memberships[target.membership_reference] = target
    request = TransitionRequest(
        expected_membership_version=3,
        approval_reference="apr_" + "1" * 32,
        reason_code="offboarding",
    )
    _assert_denied(
        lambda: service.revoke_membership(
            _auth(subject="different-admin"),
            target.membership_reference,
            request,
            idempotency_key="idem_" + "b" * 32,
        ),
        status=409,
    )


def test_admin_can_be_removed_only_with_distinct_owned_active_admin_replacement() -> None:
    service, store, *_ = _service()
    target = _membership(role=HumanRole.CUSTOMER_ADMIN)
    replacement_admin = replace(
        _membership(role=HumanRole.CUSTOMER_ADMIN),
        membership_reference="mbr_" + "8" * 32,
        subject="replacement-admin",
    )
    store.memberships[target.membership_reference] = target
    store.memberships[replacement_admin.membership_reference] = replacement_admin
    request = TransitionRequest(
        expected_membership_version=3,
        approval_reference="apr_" + "1" * 32,
        reason_code="offboarding",
        replacement_membership_reference=replacement_admin.membership_reference,
    )

    result = service.revoke_membership(
        _auth(subject="different-admin"),
        target.membership_reference,
        request,
        idempotency_key="idem_" + "d" * 32,
    )

    assert result.status == "completed"
    assert store.memberships[target.membership_reference].state is MembershipState.REVOKED


def test_admin_removal_commits_membership_guard_before_provider_disable() -> None:
    service, store, provider, *_ = _service()
    target = _membership(role=HumanRole.CUSTOMER_ADMIN)
    replacement_admin = replace(
        _membership(role=HumanRole.CUSTOMER_ADMIN),
        membership_reference="mbr_" + "8" * 32,
        subject="replacement-admin",
    )
    store.memberships[target.membership_reference] = target
    store.memberships[replacement_admin.membership_reference] = replacement_admin
    events: list[str] = []
    transition = store.transition_membership
    provider_effect = provider.set_user_enabled

    def ordered_transition(**request: Any) -> MembershipRecord:
        events.append("membership")
        return transition(**request)

    def ordered_provider_effect(**request: Any) -> ProviderUserReceipt:
        events.append("provider")
        return provider_effect(**request)

    store.transition_membership = ordered_transition  # type: ignore[method-assign]
    provider.set_user_enabled = ordered_provider_effect  # type: ignore[method-assign]
    request = TransitionRequest(
        expected_membership_version=3,
        approval_reference="apr_" + "1" * 32,
        reason_code="offboarding",
        replacement_membership_reference=replacement_admin.membership_reference,
    )

    result = service.revoke_membership(
        _auth(subject="different-admin"),
        target.membership_reference,
        request,
        idempotency_key="idem_" + "f" * 32,
    )

    assert result.status == "completed"
    assert events[:2] == ["membership", "provider"]
    assert store.memberships[target.membership_reference].state is MembershipState.REVOKED


def test_audit_failure_never_reports_success_and_retry_recovers_without_duplicate_effect() -> None:
    audit = FakeAudit()
    service, store, provider, _, _ = _service(audit=audit)
    member = _membership()
    store.memberships[member.membership_reference] = member
    request = TransitionRequest(
        expected_membership_version=3,
        approval_reference="apr_" + "1" * 32,
        reason_code="security_review",
    )
    key = "idem_" + "c" * 32
    audit.fail = True
    _assert_denied(
        lambda: service.suspend_membership(_auth(), member.membership_reference, request, idempotency_key=key),
        status=503,
    )
    assert store.memberships[member.membership_reference].state is MembershipState.SUSPENDED
    assert provider.session_revocations == 1

    audit.fail = False
    result = service.suspend_membership(_auth(), member.membership_reference, request, idempotency_key=key)
    assert result.status == "completed"
    assert provider.session_revocations == 1
    assert len(audit.events) == 1


def test_list_response_never_contains_subject_provider_reference_or_locator() -> None:
    service, store, *_ = _service()
    member = _membership()
    store.memberships[member.membership_reference] = member
    page = service.list_memberships(_auth(), state=None, cursor=None, limit=25)

    public = page.to_public_dict()
    serialized = str(public)
    assert TARGET_SUBJECT not in serialized
    assert member.provider_user_reference not in serialized
    assert "principal_locator" not in serialized
