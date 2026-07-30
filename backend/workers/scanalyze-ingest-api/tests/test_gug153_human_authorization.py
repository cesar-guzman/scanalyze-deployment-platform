"""GUG-153 fail-closed human authorization contract tests.

These tests intentionally define the public, provider-neutral PDP contract before
the implementation exists.  All identifiers and timestamps are synthetic.
"""
from __future__ import annotations

from dataclasses import replace
import json
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator

from app.auth import AuthContext
from app.enterprise_authorization import (
    ASSURANCE_SOURCE,
    ASSURANCE_VERSION,
    AUDIT_REFERENCE_SCHEMA_VERSION,
    AUDIT_RECEIPT_SCHEMA_VERSION,
    AUDIT_SINK_SOURCE,
    AUDIT_SINK_VERSION,
    AUTHORIZATION_CONTEXT_SCHEMA_VERSION,
    AUTHORITATIVE_MEMBERSHIP_SOURCE,
    AUTHORITATIVE_STATE_SCHEMA_VERSION,
    Action,
    Assurance,
    AuthorizationAuditReferences,
    AuthoritativeMembershipEvidence,
    AuthoritativeTemporaryGrantEvidence,
    AuthorizationPath,
    DurableAuditReceipt,
    EnterpriseAuthorizationRuntime,
    HumanAuthorizationSnapshot,
    HumanRole,
    OperationId,
    authorize_operation,
)
from app.errors import AppError
from app.logging import bind_context, clear_context, opaque_log_reference


CUSTOMER_ID = "cust_01ARZ3NDEKTSV4RRFFQ69G5FAW"
DEPLOYMENT_ID = "dep_01ARZ3NDEKTSV4RRFFQ69G5FAV"
SUBJECT = "00000000-0000-4000-8000-000000000153"
NOW_EPOCH = 2_000_000_000

AUTHZ_SCHEMA_VERSION = "enterprise-authorization.v1"
SCOPE_CATALOG_VERSION = "scanalyze.api.v1"
ROLE_CATALOG_VERSION = "enterprise-roles.v1"
POLICY_VERSION = "1.0.0"
POLICY_DIGEST = "sha256:34a639992f6c2312176ac7dc12c361daa38201adea6af0c0b1765a17a14754f8"

MEMBERSHIP_SOURCE = "pre_token_membership_v1"
TEMPORARY_GRANT_SOURCE = "authoritative_temporary_grant_store_v1"

DOCUMENTS_READ = OperationId("documents.read_metadata")
DOCUMENTS_CREATE = OperationId("documents.create")
REVIEWS_WRITE = OperationId("reviews.write")
METRICS_READ = OperationId("metrics.read")
AUDIT_LOG_READ = OperationId("audit_log.read")
RESULTS_READ_FULL = OperationId("results.read_full")
EXPORTS_EXECUTE = OperationId("exports.execute")
ARTIFACTS_DOWNLOAD = OperationId("artifacts.download")

ACTION_SCOPES = {
    Action.READ: "scanalyze.api.v1/read",
    Action.WRITE: "scanalyze.api.v1/write",
    Action.ADMIN: "scanalyze.api.v1/admin",
}


def _scopes(*actions: Action) -> frozenset[str]:
    return frozenset(ACTION_SCOPES[action] for action in actions)


def _membership_snapshot(
    role: HumanRole = HumanRole.CUSTOMER_ADMIN,
    **changes: Any,
) -> HumanAuthorizationSnapshot:
    snapshot = HumanAuthorizationSnapshot(
        schema_version=AUTHORIZATION_CONTEXT_SCHEMA_VERSION,
        authorization_path=AuthorizationPath.MEMBERSHIP,
        authorization_source=MEMBERSHIP_SOURCE,
        subject=SUBJECT,
        customer_id=CUSTOMER_ID,
        deployment_id=DEPLOYMENT_ID,
        membership_state="active",
        role_id=role,
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
        issued_at_epoch=NOW_EPOCH - 30,
        assurance=Assurance.PHISHING_RESISTANT_MFA,
        authenticated_at_epoch=NOW_EPOCH - 30,
        grant_issued_at_epoch=None,
        assurance_source=ASSURANCE_SOURCE,
        assurance_version=ASSURANCE_VERSION,
        authentication_event_reference="ref_0123456789abcdef01234567",
    )
    return replace(snapshot, **changes) if changes else snapshot


def _temporary_grant_snapshot(**changes: Any) -> HumanAuthorizationSnapshot:
    snapshot = HumanAuthorizationSnapshot(
        schema_version=AUTHORIZATION_CONTEXT_SCHEMA_VERSION,
        authorization_path=AuthorizationPath.TEMPORARY_GRANT,
        authorization_source=TEMPORARY_GRANT_SOURCE,
        subject=SUBJECT,
        customer_id=CUSTOMER_ID,
        deployment_id=DEPLOYMENT_ID,
        membership_state=None,
        role_id=None,
        membership_version=None,
        temporary_grant_id="grant-synthetic-153",
        temporary_grant_type="support",
        temporary_grant_state="active",
        temporary_grant_version="temporary-grant-v3",
        allowed_operation_ids=frozenset({DOCUMENTS_READ.value}),
        allowed_data_classes=frozenset({"metadata"}),
        expires_at_epoch=NOW_EPOCH + 120,
        authz_schema_version=AUTHZ_SCHEMA_VERSION,
        scope_catalog_version=SCOPE_CATALOG_VERSION,
        role_catalog_version=ROLE_CATALOG_VERSION,
        policy_version=POLICY_VERSION,
        policy_digest=POLICY_DIGEST,
        issued_at_epoch=NOW_EPOCH - 30,
        assurance=Assurance.PHISHING_RESISTANT_MFA,
        authenticated_at_epoch=NOW_EPOCH - 30,
        grant_issued_at_epoch=NOW_EPOCH - 30,
        assurance_source=ASSURANCE_SOURCE,
        assurance_version=ASSURANCE_VERSION,
        authentication_event_reference="ref_0123456789abcdef01234567",
        case_reference="ref_111111111111111111111111",
        incident_reference=None,
        purpose_reference="ref_222222222222222222222222",
        approval_references=frozenset({"ref_333333333333333333333333"}),
    )
    if changes.get("temporary_grant_type") == "break_glass":
        changes.setdefault("case_reference", None)
        changes.setdefault("incident_reference", "ref_888888888888888888888888")
        changes.setdefault(
            "approval_references",
            frozenset(
                {
                    "ref_333333333333333333333333",
                    "ref_999999999999999999999999",
                }
            ),
        )
    return replace(snapshot, **changes) if changes else snapshot


def _human_context(
    *,
    role: HumanRole = HumanRole.CUSTOMER_ADMIN,
    scopes: frozenset[str] | None = None,
    snapshot: HumanAuthorizationSnapshot | None = None,
) -> AuthContext:
    return AuthContext(
        customer_id=CUSTOMER_ID,
        deployment_id=DEPLOYMENT_ID,
        principal_type="user",
        subject=SUBJECT,
        client_id="synthetic-human-client",
        scopes=scopes if scopes is not None else _scopes(Action.READ, Action.WRITE, Action.ADMIN),
        granted_actions=(),
        auth_source="cognito_jwt",
        human_authorization=snapshot or _membership_snapshot(role),
    )


def _m2m_context(
    *actions: Action,
    snapshot: HumanAuthorizationSnapshot | None = None,
) -> AuthContext:
    return AuthContext(
        customer_id=CUSTOMER_ID,
        deployment_id=DEPLOYMENT_ID,
        principal_type="m2m",
        subject="synthetic-workload",
        client_id="synthetic-m2m-client",
        scopes=_scopes(Action.READ, Action.WRITE, Action.ADMIN),
        granted_actions=(action.value for action in actions),
        auth_source="m2m_identity_binding_v1",
        human_authorization=snapshot,
    )


def _authoritative_evidence(
    snapshot: HumanAuthorizationSnapshot,
    _operation: OperationId,
    now_epoch: int,
) -> AuthoritativeMembershipEvidence | AuthoritativeTemporaryGrantEvidence:
    path = (
        snapshot.authorization_path.value
        if isinstance(snapshot.authorization_path, AuthorizationPath)
        else snapshot.authorization_path
    )
    if path == AuthorizationPath.MEMBERSHIP.value:
        return AuthoritativeMembershipEvidence(
            schema_version=AUTHORITATIVE_STATE_SCHEMA_VERSION,
            authorization_path=AuthorizationPath.MEMBERSHIP,
            authority_source=AUTHORITATIVE_MEMBERSHIP_SOURCE,
            checked_at_epoch=now_epoch,
            subject=str(snapshot.subject),
            customer_id=str(snapshot.customer_id),
            deployment_id=str(snapshot.deployment_id),
            membership_state=str(snapshot.membership_state),
            role_id=snapshot.role_id or "missing",
            membership_version=str(snapshot.membership_version),
        )
    return AuthoritativeTemporaryGrantEvidence(
        schema_version=AUTHORITATIVE_STATE_SCHEMA_VERSION,
        authorization_path=AuthorizationPath.TEMPORARY_GRANT,
        authority_source=TEMPORARY_GRANT_SOURCE,
        checked_at_epoch=now_epoch,
        subject=str(snapshot.subject),
        customer_id=str(snapshot.customer_id),
        deployment_id=str(snapshot.deployment_id),
        temporary_grant_id=str(snapshot.temporary_grant_id),
        temporary_grant_type=str(snapshot.temporary_grant_type),
        temporary_grant_state=str(snapshot.temporary_grant_state),
        temporary_grant_version=str(snapshot.temporary_grant_version),
        grant_issued_at_epoch=int(snapshot.grant_issued_at_epoch or 0),
        expires_at_epoch=int(snapshot.expires_at_epoch or 0),
        allowed_operation_ids=snapshot.allowed_operation_ids,
        allowed_data_classes=snapshot.allowed_data_classes,
        case_reference=snapshot.case_reference,
        incident_reference=snapshot.incident_reference,
        purpose_reference=snapshot.purpose_reference,
        approval_references=snapshot.approval_references,
    )


def _audit_references(
    _auth: AuthContext,
    _operation: OperationId,
    correlation_reference: str,
) -> AuthorizationAuditReferences:
    snapshot = _auth.human_authorization
    path = getattr(snapshot, "authorization_path", None)
    if isinstance(path, AuthorizationPath):
        path = path.value
    return AuthorizationAuditReferences(
        schema_version=AUDIT_REFERENCE_SCHEMA_VERSION,
        principal_reference="ref_444444444444444444444444",
        customer_reference="ref_555555555555555555555555",
        deployment_reference="ref_666666666666666666666666",
        correlation_reference=correlation_reference,
        grant_reference=(
            "ref_777777777777777777777777"
            if path == AuthorizationPath.TEMPORARY_GRANT.value
            else None
        ),
    )


def _runtime(
    events: list[dict[str, str]] | None = None,
    *,
    resolver=_authoritative_evidence,
    audit_reference_resolver=_audit_references,
    receipt_changes: dict[str, object] | None = None,
) -> EnterpriseAuthorizationRuntime:
    def audit_sink(event: dict[str, str]) -> DurableAuditReceipt:
        if events is not None:
            events.append(dict(event))
        receipt = DurableAuditReceipt(
            schema_version=AUDIT_RECEIPT_SCHEMA_VERSION,
            sink_source=AUDIT_SINK_SOURCE,
            sink_version=AUDIT_SINK_VERSION,
            decision_id=event["decision_id"],
            receipt_reference="ref_abcdef0123456789abcdef01",
            acknowledged_at_epoch=NOW_EPOCH,
        )
        return replace(receipt, **(receipt_changes or {}))

    return EnterpriseAuthorizationRuntime(
        authoritative_state_resolver=resolver,
        audit_sink=audit_sink,
        audit_reference_resolver=audit_reference_resolver,
    )


def _authorize(auth: AuthContext, operation: OperationId) -> tuple[AuthContext, list[dict[str, str]]]:
    events: list[dict[str, str]] = []
    result = authorize_operation(
        auth,
        operation,
        now_epoch=NOW_EPOCH,
        runtime=_runtime(events),
        audit_sink=events.append,
    )
    return result, events


def _assert_denied(auth: AuthContext, operation: OperationId | str) -> None:
    with pytest.raises(AppError):
        authorize_operation(
            auth,
            operation,
            now_epoch=NOW_EPOCH,
            runtime=_runtime(),
            audit_sink=lambda _event: None,
        )


@pytest.mark.parametrize(
    ("role", "operation", "scopes", "allowed"),
    [
        (HumanRole.CUSTOMER_ADMIN, DOCUMENTS_CREATE, _scopes(Action.WRITE), True),
        (
            HumanRole.CUSTOMER_ADMIN,
            RESULTS_READ_FULL,
            _scopes(Action.READ, Action.ADMIN),
            True,
        ),
        (HumanRole.DOCUMENT_OPERATOR, DOCUMENTS_READ, _scopes(Action.READ), True),
        (HumanRole.DOCUMENT_OPERATOR, DOCUMENTS_CREATE, _scopes(Action.WRITE), True),
        (
            HumanRole.DOCUMENT_OPERATOR,
            RESULTS_READ_FULL,
            _scopes(Action.READ, Action.ADMIN),
            False,
        ),
        (HumanRole.DOCUMENT_REVIEWER, DOCUMENTS_READ, _scopes(Action.READ), True),
        (HumanRole.DOCUMENT_REVIEWER, REVIEWS_WRITE, _scopes(Action.WRITE), True),
        (HumanRole.DOCUMENT_REVIEWER, DOCUMENTS_CREATE, _scopes(Action.WRITE), False),
        (HumanRole.AUDITOR, METRICS_READ, _scopes(Action.READ), True),
        (HumanRole.AUDITOR, AUDIT_LOG_READ, _scopes(Action.READ), True),
        (HumanRole.AUDITOR, DOCUMENTS_READ, _scopes(Action.READ), False),
    ],
)
def test_human_role_operation_matrix(
    role: HumanRole,
    operation: OperationId,
    scopes: frozenset[str],
    allowed: bool,
) -> None:
    auth = _human_context(role=role, scopes=scopes)

    if allowed:
        result, events = _authorize(auth, operation)
        assert result is auth
        assert len(events) == 1
    else:
        _assert_denied(auth, operation)


def test_required_scope_is_necessary_even_for_customer_admin() -> None:
    auth = _human_context(role=HumanRole.CUSTOMER_ADMIN, scopes=frozenset())

    _assert_denied(auth, DOCUMENTS_READ)


@pytest.mark.parametrize(
    ("role", "operation"),
    [
        (HumanRole.AUDITOR, DOCUMENTS_READ),
        (HumanRole.DOCUMENT_OPERATOR, EXPORTS_EXECUTE),
        (HumanRole.DOCUMENT_REVIEWER, METRICS_READ),
    ],
)
def test_scopes_are_not_sufficient_to_elevate_a_role(
    role: HumanRole,
    operation: OperationId,
) -> None:
    auth = _human_context(
        role=role,
        scopes=_scopes(Action.READ, Action.WRITE, Action.ADMIN),
    )

    _assert_denied(auth, operation)


def test_human_granted_actions_cannot_replace_role_authority() -> None:
    auth = AuthContext(
        customer_id=CUSTOMER_ID,
        deployment_id=DEPLOYMENT_ID,
        principal_type="user",
        subject=SUBJECT,
        client_id="synthetic-human-client",
        scopes=_scopes(Action.READ, Action.ADMIN),
        granted_actions=(Action.READ.value, Action.ADMIN.value),
        auth_source="cognito_jwt",
        human_authorization=_membership_snapshot(HumanRole.DOCUMENT_OPERATOR),
    )

    _assert_denied(auth, RESULTS_READ_FULL)


@pytest.mark.parametrize(
    "snapshot",
    [
        _membership_snapshot(authorization_path=None),
        _membership_snapshot(authorization_path="provider_group"),
        _membership_snapshot(role_id=None),
        _membership_snapshot(role_id="unknown_superuser"),
        _membership_snapshot(membership_state="suspended"),
        _membership_snapshot(membership_version=None),
        _membership_snapshot(membership_version="synthetic version with spaces"),
        _membership_snapshot(membership_version="v" * 129),
        _membership_snapshot(temporary_grant_id="conflicting-grant"),
        _membership_snapshot(authorization_source="jwt_claims_only"),
        _membership_snapshot(customer_id="foreign-customer"),
        _membership_snapshot(deployment_id="dep_01ARZ3NDEKTSV4RRFFQ69G5FAA"),
        _membership_snapshot(subject="00000000-0000-4000-8000-000000000999"),
        _membership_snapshot(subject="synthetic subject with spaces"),
        _membership_snapshot(subject="a" * 257),
    ],
)
def test_missing_unknown_or_conflicting_membership_context_denies(
    snapshot: HumanAuthorizationSnapshot,
) -> None:
    _assert_denied(_human_context(snapshot=snapshot), DOCUMENTS_READ)


def test_temporary_path_with_membership_role_is_conflicting() -> None:
    snapshot = _temporary_grant_snapshot(
        role_id=HumanRole.CUSTOMER_ADMIN,
        membership_version="conflicting-membership",
    )

    _assert_denied(_human_context(snapshot=snapshot), DOCUMENTS_READ)


def test_user_without_human_authorization_snapshot_denies() -> None:
    auth = AuthContext(
        customer_id=CUSTOMER_ID,
        deployment_id=DEPLOYMENT_ID,
        principal_type="user",
        subject=SUBJECT,
        client_id="synthetic-human-client",
        scopes=_scopes(Action.READ),
        granted_actions=(),
        auth_source="cognito_jwt",
        human_authorization=None,
    )

    _assert_denied(auth, DOCUMENTS_READ)


@pytest.mark.parametrize(
    ("field", "invalid_value"),
    [
        ("schema_version", None),
        ("schema_version", "human-authorization-context.v2"),
        ("authz_schema_version", None),
        ("authz_schema_version", "enterprise-authorization.v2"),
        ("scope_catalog_version", None),
        ("scope_catalog_version", "scanalyze.api.v2"),
        ("role_catalog_version", None),
        ("role_catalog_version", "enterprise-roles.v2"),
        ("policy_version", None),
        ("policy_version", "2.0.0"),
        ("policy_digest", None),
        ("policy_digest", "sha256:" + "0" * 64),
        ("policy_digest", "not-a-digest"),
    ],
)
def test_missing_unknown_or_conflicting_contract_version_denies(
    field: str,
    invalid_value: object,
) -> None:
    snapshot = replace(_membership_snapshot(), **{field: invalid_value})

    _assert_denied(_human_context(snapshot=snapshot), DOCUMENTS_READ)


def test_snapshot_schema_version_is_a_required_constructor_argument() -> None:
    values = dict(_membership_snapshot().__dict__)
    values.pop("schema_version")

    with pytest.raises(TypeError):
        HumanAuthorizationSnapshot(**values)


@pytest.mark.parametrize(
    ("issued_at_epoch", "allowed"),
    [
        (NOW_EPOCH - 300, True),
        (NOW_EPOCH - 301, False),
        (NOW_EPOCH + 1, False),
    ],
)
def test_authorization_snapshot_issued_at_is_bounded(
    issued_at_epoch: int,
    allowed: bool,
) -> None:
    auth = _human_context(
        snapshot=_membership_snapshot(
            issued_at_epoch=issued_at_epoch,
            authenticated_at_epoch=min(NOW_EPOCH - 30, issued_at_epoch),
        )
    )

    if allowed:
        result, _events = _authorize(auth, DOCUMENTS_READ)
        assert result is auth
    else:
        _assert_denied(auth, DOCUMENTS_READ)


@pytest.mark.parametrize(
    ("auth_age_seconds", "allowed"),
    [(299, True), (300, True), (301, False)],
)
def test_sensitive_operation_step_up_age_boundary(
    auth_age_seconds: int,
    allowed: bool,
) -> None:
    snapshot = _membership_snapshot(authenticated_at_epoch=NOW_EPOCH - auth_age_seconds)
    auth = _human_context(
        snapshot=snapshot,
        scopes=_scopes(Action.READ, Action.ADMIN),
    )

    if allowed:
        result, events = _authorize(auth, RESULTS_READ_FULL)
        assert result is auth
        assert len(events) == 1
    else:
        _assert_denied(auth, RESULTS_READ_FULL)


@pytest.mark.parametrize(
    "changes",
    [
        {"assurance": None},
        {"assurance": "password_only"},
        {"assurance_source": None},
        {"assurance_source": "raw_custom_claim"},
        {"assurance_version": None},
        {"assurance_version": "unreviewed.v1"},
        {"authentication_event_reference": None},
        {"authentication_event_reference": "raw-event-id"},
        {"authenticated_at_epoch": None},
        {"authenticated_at_epoch": NOW_EPOCH + 1},
    ],
)
def test_sensitive_operation_requires_verifiable_phishing_resistant_step_up(
    changes: dict[str, object],
) -> None:
    snapshot = replace(_membership_snapshot(), **changes)
    auth = _human_context(
        snapshot=snapshot,
        scopes=_scopes(Action.READ, Action.ADMIN),
    )

    _assert_denied(auth, ARTIFACTS_DOWNLOAD)


def test_partial_assurance_provenance_denies_even_non_sensitive_operation() -> None:
    snapshot = _membership_snapshot(assurance_source=None)

    _assert_denied(
        _human_context(snapshot=snapshot, scopes=_scopes(Action.READ)),
        DOCUMENTS_READ,
    )


def test_allowlisted_temporary_grant_can_read_only_its_metadata_operation() -> None:
    auth = _human_context(
        snapshot=_temporary_grant_snapshot(),
        scopes=_scopes(Action.READ),
    )

    result, events = _authorize(auth, DOCUMENTS_READ)

    assert result is auth
    assert len(events) == 1


def test_temporary_grant_cannot_use_unlisted_operation() -> None:
    auth = _human_context(
        snapshot=_temporary_grant_snapshot(),
        scopes=_scopes(Action.READ),
    )

    _assert_denied(auth, METRICS_READ)


@pytest.mark.parametrize(
    "operation",
    [RESULTS_READ_FULL, EXPORTS_EXECUTE, ARTIFACTS_DOWNLOAD],
)
def test_temporary_grant_always_denies_sensitive_operations(
    operation: OperationId,
) -> None:
    snapshot = _temporary_grant_snapshot(
        allowed_operation_ids=frozenset({operation.value}),
        allowed_data_classes=frozenset({"metadata", "masked", "content", "pii"}),
    )
    auth = _human_context(
        snapshot=snapshot,
        scopes=_scopes(Action.READ, Action.ADMIN),
    )

    _assert_denied(auth, operation)


@pytest.mark.parametrize(
    "snapshot",
    [
        _temporary_grant_snapshot(authorization_source="request_payload"),
        _temporary_grant_snapshot(temporary_grant_state="revoked"),
        _temporary_grant_snapshot(temporary_grant_version=None),
        _temporary_grant_snapshot(temporary_grant_version="version with spaces"),
        _temporary_grant_snapshot(temporary_grant_version="v" * 129),
        _temporary_grant_snapshot(temporary_grant_id="other-synthetic-153"),
        _temporary_grant_snapshot(temporary_grant_id="grant-short"),
        _temporary_grant_snapshot(temporary_grant_id="grant-invalid/value"),
        _temporary_grant_snapshot(case_reference=None),
        _temporary_grant_snapshot(purpose_reference=None),
        _temporary_grant_snapshot(approval_references=frozenset()),
        _temporary_grant_snapshot(
            approval_references=frozenset({opaque_log_reference(SUBJECT)})
        ),
        _temporary_grant_snapshot(
            temporary_grant_type="break_glass",
            approval_references=frozenset({"ref_333333333333333333333333"}),
        ),
        _temporary_grant_snapshot(
            temporary_grant_type="break_glass",
            incident_reference=None,
        ),
        _temporary_grant_snapshot(expires_at_epoch=NOW_EPOCH),
        _temporary_grant_snapshot(allowed_data_classes=frozenset()),
        _temporary_grant_snapshot(
            allowed_data_classes=frozenset({"metadata", "synthetic_private"})
        ),
    ],
)
def test_temporary_grant_invalid_source_state_version_expiry_or_data_class_denies(
    snapshot: HumanAuthorizationSnapshot,
) -> None:
    auth = _human_context(snapshot=snapshot, scopes=_scopes(Action.READ))

    _assert_denied(auth, DOCUMENTS_READ)


@pytest.mark.parametrize(
    ("grant_type", "lifetime_seconds", "allowed"),
    [
        ("support", 3600, True),
        ("support", 3601, False),
        ("break_glass", 900, True),
        ("break_glass", 901, False),
    ],
)
def test_temporary_grant_lifetime_boundaries(
    grant_type: str,
    lifetime_seconds: int,
    allowed: bool,
) -> None:
    grant_issued_at = NOW_EPOCH - 30
    snapshot = _temporary_grant_snapshot(
        temporary_grant_type=grant_type,
        grant_issued_at_epoch=grant_issued_at,
        expires_at_epoch=grant_issued_at + lifetime_seconds,
    )
    auth = _human_context(snapshot=snapshot, scopes=_scopes(Action.READ))

    if allowed:
        result, _events = _authorize(auth, DOCUMENTS_READ)
        assert result is auth
    else:
        _assert_denied(auth, DOCUMENTS_READ)


@pytest.mark.parametrize(
    "field_changes",
    [
        {"customer_id": "cust_01ARZ3NDEKTSV4RRFFQ69G5FAX"},
        {"deployment_id": "dep_01ARZ3NDEKTSV4RRFFQ69G5FAY"},
        {"membership_state": "suspended"},
        {"membership_version": "membership-v8"},
        {"role_id": HumanRole.AUDITOR},
        {"checked_at_epoch": NOW_EPOCH - 1},
        {"authorization_path": AuthorizationPath.TEMPORARY_GRANT},
        {"authority_source": "untrusted_membership_source"},
    ],
)
def test_foreign_stale_or_conflicting_authoritative_membership_denies(
    field_changes: dict[str, object],
) -> None:
    def resolver(
        snapshot: HumanAuthorizationSnapshot,
        operation: OperationId,
        now_epoch: int,
    ) -> AuthoritativeMembershipEvidence:
        evidence = _authoritative_evidence(snapshot, operation, now_epoch)
        assert isinstance(evidence, AuthoritativeMembershipEvidence)
        return replace(evidence, **field_changes)

    with pytest.raises(AppError):
        authorize_operation(
            _human_context(scopes=_scopes(Action.READ)),
            DOCUMENTS_READ,
            now_epoch=NOW_EPOCH,
            runtime=_runtime(resolver=resolver),
        )


@pytest.mark.parametrize("resolver", [None, "malformed", lambda *_args: None])
def test_missing_or_malformed_authoritative_resolver_denies(resolver: object) -> None:
    runtime = (
        None
        if resolver is None
        else EnterpriseAuthorizationRuntime(  # type: ignore[arg-type]
            authoritative_state_resolver=resolver,
            audit_sink=_runtime().audit_sink,
            audit_reference_resolver=_audit_references,
        )
    )

    with pytest.raises(AppError):
        authorize_operation(
            _human_context(scopes=_scopes(Action.READ)),
            DOCUMENTS_READ,
            now_epoch=NOW_EPOCH,
            runtime=runtime,
        )


def test_unavailable_authoritative_resolver_denies_without_leaking_error() -> None:
    def unavailable(*_args: object) -> AuthoritativeMembershipEvidence:
        raise RuntimeError("synthetic sensitive backend detail")

    with pytest.raises(AppError) as captured:
        authorize_operation(
            _human_context(scopes=_scopes(Action.READ)),
            DOCUMENTS_READ,
            now_epoch=NOW_EPOCH,
            runtime=_runtime(resolver=unavailable),
        )

    assert "sensitive backend detail" not in str(captured.value)


@pytest.mark.parametrize(
    "field_changes",
    [
        {"temporary_grant_id": "grant-foreign"},
        {"temporary_grant_version": "temporary-grant-v4"},
        {"grant_issued_at_epoch": NOW_EPOCH - 31},
        {"expires_at_epoch": NOW_EPOCH + 121},
        {"allowed_operation_ids": frozenset({METRICS_READ.value})},
        {"allowed_data_classes": frozenset({"pii"})},
        {"case_reference": "ref_aaaaaaaaaaaaaaaaaaaaaaaa"},
        {"purpose_reference": "ref_bbbbbbbbbbbbbbbbbbbbbbbb"},
        {"approval_references": frozenset({"ref_cccccccccccccccccccccccc"})},
    ],
)
def test_authoritative_temporary_grant_must_match_full_contract(
    field_changes: dict[str, object],
) -> None:
    snapshot = _temporary_grant_snapshot()

    def resolver(
        current: HumanAuthorizationSnapshot,
        operation: OperationId,
        now_epoch: int,
    ) -> AuthoritativeTemporaryGrantEvidence:
        evidence = _authoritative_evidence(current, operation, now_epoch)
        assert isinstance(evidence, AuthoritativeTemporaryGrantEvidence)
        return replace(evidence, **field_changes)

    with pytest.raises(AppError):
        authorize_operation(
            _human_context(snapshot=snapshot, scopes=_scopes(Action.READ)),
            DOCUMENTS_READ,
            now_epoch=NOW_EPOCH,
            runtime=_runtime(resolver=resolver),
        )


def test_audit_sink_failure_denies_an_otherwise_allowed_human_operation() -> None:
    calls = 0

    def failing_sink(_event: object) -> DurableAuditReceipt:
        nonlocal calls
        calls += 1
        raise RuntimeError("synthetic audit dependency failure")

    runtime = EnterpriseAuthorizationRuntime(
        authoritative_state_resolver=_authoritative_evidence,
        audit_sink=failing_sink,
        audit_reference_resolver=_audit_references,
    )
    with pytest.raises(AppError):
        authorize_operation(
            _human_context(scopes=_scopes(Action.READ)),
            DOCUMENTS_READ,
            now_epoch=NOW_EPOCH,
            runtime=runtime,
        )

    assert calls == 1


@pytest.mark.parametrize(
    "resolver",
    [
        None,
        lambda *_args: None,
        lambda _auth, _operation, correlation: AuthorizationAuditReferences(
            schema_version="authorization-audit-references.v2",
            principal_reference="ref_111111111111111111111111",
            customer_reference="ref_222222222222222222222222",
            deployment_reference="ref_333333333333333333333333",
            correlation_reference=correlation,
        ),
        lambda _auth, _operation, _correlation: AuthorizationAuditReferences(
            schema_version=AUDIT_REFERENCE_SCHEMA_VERSION,
            principal_reference="ref_111111111111111111111111",
            customer_reference="ref_222222222222222222222222",
            deployment_reference="ref_333333333333333333333333",
            correlation_reference="ref_ffffffffffffffffffffffff",
        ),
    ],
)
def test_missing_malformed_or_unbound_audit_references_deny(
    resolver: object,
) -> None:
    with pytest.raises(AppError):
        authorize_operation(
            _human_context(scopes=_scopes(Action.READ)),
            DOCUMENTS_READ,
            now_epoch=NOW_EPOCH,
            runtime=_runtime(audit_reference_resolver=resolver),  # type: ignore[arg-type]
        )


def test_allow_audit_references_are_stable_and_request_bound() -> None:
    events: list[dict[str, Any]] = []
    correlation_reference = "ref_aaaaaaaaaaaaaaaaaaaaaaaa"
    clear_context()
    try:
        bind_context(correlationId=correlation_reference)
        authorize_operation(
            _human_context(scopes=_scopes(Action.READ)),
            DOCUMENTS_READ,
            now_epoch=NOW_EPOCH,
            runtime=_runtime(events),  # type: ignore[arg-type]
        )
        authorize_operation(
            _human_context(scopes=_scopes(Action.READ)),
            DOCUMENTS_READ,
            now_epoch=NOW_EPOCH,
            runtime=_runtime(events),  # type: ignore[arg-type]
        )
    finally:
        clear_context()

    assert len(events) == 2
    for field in (
        "principal_reference",
        "customer_reference",
        "deployment_reference",
    ):
        assert events[0][field] == events[1][field]
    assert {event["correlation_reference"] for event in events} == {
        correlation_reference
    }


@pytest.mark.parametrize(
    "receipt_changes",
    [
        {"schema_version": "authorization-audit-receipt.v2"},
        {"sink_source": "logger_only"},
        {"sink_version": "2.0.0"},
        {"decision_id": "decision-mismatch"},
        {"receipt_reference": "raw-receipt"},
        {"acknowledged_at_epoch": NOW_EPOCH - 1},
    ],
)
def test_mismatched_or_non_durable_audit_receipt_denies_before_handler(
    receipt_changes: dict[str, object],
) -> None:
    with pytest.raises(AppError):
        authorize_operation(
            _human_context(scopes=_scopes(Action.READ)),
            DOCUMENTS_READ,
            now_epoch=NOW_EPOCH,
            runtime=_runtime(receipt_changes=receipt_changes),
        )


def test_logger_or_untyped_audit_sink_cannot_authorize_human_operation() -> None:
    runtime = EnterpriseAuthorizationRuntime(
        authoritative_state_resolver=_authoritative_evidence,
        audit_sink=lambda _event: None,  # type: ignore[arg-type]
        audit_reference_resolver=_audit_references,
    )

    with pytest.raises(AppError):
        authorize_operation(
            _human_context(scopes=_scopes(Action.READ)),
            DOCUMENTS_READ,
            now_epoch=NOW_EPOCH,
            runtime=runtime,
        )


def test_runtime_authorization_events_match_sanitized_contract() -> None:
    schema_path = (
        Path(__file__).resolve().parents[4]
        / "schemas"
        / "authorization-decision.v1.schema.json"
    )
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    validator = Draft202012Validator(schema)
    events: list[dict[str, str]] = []

    authorize_operation(
        _human_context(scopes=_scopes(Action.READ, Action.ADMIN)),
        EXPORTS_EXECUTE,
        now_epoch=NOW_EPOCH,
        runtime=_runtime(events),
    )
    with pytest.raises(AppError):
        authorize_operation(
            _human_context(
                role=HumanRole.AUDITOR,
                scopes=_scopes(Action.READ),
            ),
            DOCUMENTS_READ,
            now_epoch=NOW_EPOCH,
            runtime=_runtime(events),
        )
    authorize_operation(
        _m2m_context(Action.READ),
        DOCUMENTS_READ,
        now_epoch=NOW_EPOCH,
        audit_sink=events.append,
    )

    assert [event["decision"] for event in events] == ["allow", "deny", "allow"]
    assert events[0]["action"] == "read+admin"
    assert events[0]["assurance"] == Assurance.PHISHING_RESISTANT_MFA.value
    assert events[1]["reason_code"] == "role_permission_denied"
    assert events[2]["authorization_path"] == "m2m_binding"
    assert events[2]["assurance"] == "validated_client_credentials_binding"
    for event in events:
        validator.validate(event)
        serialized = json.dumps(event, sort_keys=True)
        assert CUSTOMER_ID not in serialized
        assert DEPLOYMENT_ID not in serialized
        assert SUBJECT not in serialized


def test_temporary_grant_allow_audit_carries_current_approval_bindings() -> None:
    schema_path = (
        Path(__file__).resolve().parents[4]
        / "schemas"
        / "authorization-decision.v1.schema.json"
    )
    validator = Draft202012Validator(
        json.loads(schema_path.read_text(encoding="utf-8"))
    )
    snapshot = _temporary_grant_snapshot()
    events: list[dict[str, Any]] = []

    authorize_operation(
        _human_context(snapshot=snapshot, scopes=_scopes(Action.READ)),
        DOCUMENTS_READ,
        now_epoch=NOW_EPOCH,
        runtime=_runtime(events),  # type: ignore[arg-type]
    )

    assert len(events) == 1
    event = events[0]
    validator.validate(event)
    assert event["case_reference"] == snapshot.case_reference
    assert event["purpose_reference"] == snapshot.purpose_reference
    assert event["approval_references"] == sorted(snapshot.approval_references)
    assert event["grant_reference"] == "ref_777777777777777777777777"


def test_malformed_authority_denies_before_resolver_and_emits_valid_audit() -> None:
    schema_path = (
        Path(__file__).resolve().parents[4]
        / "schemas"
        / "authorization-decision.v1.schema.json"
    )
    validator = Draft202012Validator(
        json.loads(schema_path.read_text(encoding="utf-8"))
    )
    marker = "synthetic version with spaces"
    events: list[dict[str, str]] = []
    resolver_calls = 0

    def resolver(*_args: object) -> AuthoritativeMembershipEvidence:
        nonlocal resolver_calls
        resolver_calls += 1
        return _authoritative_evidence(*_args)  # type: ignore[arg-type,return-value]

    with pytest.raises(AppError):
        authorize_operation(
            _human_context(
                snapshot=_membership_snapshot(membership_version=marker),
                scopes=_scopes(Action.READ),
            ),
            DOCUMENTS_READ,
            now_epoch=NOW_EPOCH,
            runtime=_runtime(events, resolver=resolver),
        )

    assert resolver_calls == 0
    assert len(events) == 1
    validator.validate(events[0])
    assert marker not in json.dumps(events[0], sort_keys=True)
    assert "membership_version" not in events[0]


def test_unknown_operation_denies_instead_of_defaulting_to_http_action() -> None:
    _assert_denied(
        _human_context(scopes=_scopes(Action.READ, Action.WRITE, Action.ADMIN)),
        "unknown.operation",
    )


def test_m2m_preserves_existing_explicit_action_authorization() -> None:
    read_auth = _m2m_context(Action.READ)
    export_auth = _m2m_context(Action.READ, Action.ADMIN)

    read_result, _read_events = _authorize(read_auth, DOCUMENTS_READ)
    export_result, _export_events = _authorize(export_auth, EXPORTS_EXECUTE)

    assert read_result is read_auth
    assert export_result is export_auth
    _assert_denied(read_auth, DOCUMENTS_CREATE)
    _assert_denied(read_auth, EXPORTS_EXECUTE)


def test_human_snapshot_cannot_elevate_an_m2m_principal() -> None:
    auth = _m2m_context(
        Action.READ,
        snapshot=_membership_snapshot(HumanRole.CUSTOMER_ADMIN),
    )

    _assert_denied(auth, DOCUMENTS_CREATE)


@pytest.mark.parametrize("with_snapshot", [False, True])
def test_local_mock_is_never_implicitly_authorized(with_snapshot: bool) -> None:
    auth = AuthContext(
        customer_id=CUSTOMER_ID,
        deployment_id=DEPLOYMENT_ID,
        principal_type="local_mock",
        subject="synthetic-local-user",
        client_id=None,
        scopes=_scopes(Action.READ, Action.WRITE, Action.ADMIN),
        granted_actions=(Action.READ.value, Action.WRITE.value, Action.ADMIN.value),
        auth_source="local_mock",
        human_authorization=(
            _membership_snapshot(HumanRole.CUSTOMER_ADMIN) if with_snapshot else None
        ),
    )

    _assert_denied(auth, DOCUMENTS_READ)
