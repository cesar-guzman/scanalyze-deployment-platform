from __future__ import annotations

import logging
from datetime import datetime
from typing import Any, Callable, Mapping, Protocol, Sequence

from .common import (
    CUSTOMER_ID_PATTERN,
    DEPLOYMENT_ID_PATTERN,
    POLICY_DIGEST_PATTERN,
    SUBJECT_PATTERN,
    AuditSink,
    constant_time_equal,
    emit_sanitized,
    is_non_empty_string,
    parse_timestamp,
    sanitized_audit_event,
)


class RequestStore(Protocol):
    def load(self, request_id: str) -> Mapping[str, Any] | None: ...

    def claim(self, **condition: Any) -> str | None: ...

    def consume(self, **condition: Any) -> bool: ...

    def release(self, **condition: Any) -> None: ...


class IdentityProvider(Protocol):
    def ensure_user(self, **record: Any) -> Mapping[str, Any]: ...


class MembershipStore(Protocol):
    def ensure_membership(self, **record: Any) -> Mapping[str, Any]: ...


class BootstrapDenied(RuntimeError):
    def __init__(self, reason_code: str) -> None:
        self.reason_code = reason_code
        super().__init__("identity bootstrap denied")


class BootstrapProcessor:
    """Consume one reviewed bootstrap request using conditional, idempotent effects."""

    def __init__(
        self,
        *,
        config: Mapping[str, Any],
        request_store: RequestStore,
        identity_provider: IdentityProvider,
        membership_store: MembershipStore,
        audit_sink: AuditSink,
        clock: Callable[[], datetime],
        logger: logging.Logger | None = None,
    ) -> None:
        self.config = dict(config)
        self.request_store = request_store
        self.identity_provider = identity_provider
        self.membership_store = membership_store
        self.audit_sink = audit_sink
        self.clock = clock
        self.logger = logger or logging.getLogger(__name__)

    def process(self, command: Mapping[str, Any]) -> dict[str, str]:
        now = self.clock()
        # GUG-93 composes the lifecycle machinery but deliberately does not
        # authorize human provisioning. The gate is evaluated before reading a
        # request or invoking any identity/membership side effect; GUG-153 must
        # explicitly promote a reviewed configuration before this path opens.
        if self.config.get("human_runtime_enabled") is not True:
            self._deny("human_runtime_provisioning_disabled", now)
        if not isinstance(command, Mapping):
            self._deny("unsupported_contract", now)
        if command.get("schema_version") != "identity-bootstrap-command.v1":
            self._deny("unsupported_contract", now)
        request_id = command.get("request_id")
        if not is_non_empty_string(request_id):
            self._deny("missing_binding", now)

        try:
            stored = self.request_store.load(str(request_id))
        except Exception:
            self._deny("bootstrap_dependency_unavailable", now, (request_id,))
        if not isinstance(stored, Mapping) or not stored:
            self._deny("bootstrap_not_authorized", now, (request_id,))

        binding = self._validate_request(command, stored, now)
        subject, customer_id, deployment_id = binding
        correlation = (request_id, subject, customer_id, deployment_id)
        idempotency_key = str(stored["idempotency_key"])
        version = int(stored["version"])

        claim_token: str | None
        try:
            claim_token = self.request_store.claim(
                request_id=request_id,
                expected_state="approved",
                expected_version=version,
                idempotency_key=idempotency_key,
                claimed_at=now,
            )
        except Exception:
            self._deny("bootstrap_dependency_unavailable", now, correlation)
        if not is_non_empty_string(claim_token):
            self._deny("bootstrap_claim_conflict", now, correlation)

        try:
            provider_result = self.identity_provider.ensure_user(
                subject=subject,
                immutable_attributes={
                    "custom:customerId": customer_id,
                    "custom:deployment_id": deployment_id,
                },
                idempotency_key=idempotency_key,
            )
        except Exception:
            self._release_claim(str(request_id), str(claim_token), version)
            self._deny("identity_provider_unavailable", now, correlation)
        if not isinstance(provider_result, Mapping) or not is_non_empty_string(
            provider_result.get("user_reference")
        ):
            self._release_claim(str(request_id), str(claim_token), version)
            self._deny("identity_provider_unavailable", now, correlation)

        try:
            membership_result = self.membership_store.ensure_membership(
                subject=subject,
                customer_id=customer_id,
                deployment_id=deployment_id,
                role_id=str(stored["role_id"]),
                membership_state="active",
                membership_version="1",
                authz_schema_version=str(stored["authz_schema_version"]),
                scope_catalog_version=str(stored["scope_catalog_version"]),
                role_catalog_version=str(stored["role_catalog_version"]),
                policy_version=str(stored["policy_version"]),
                policy_digest=str(stored["policy_digest"]),
                idempotency_key=idempotency_key,
            )
        except Exception:
            self._release_claim(str(request_id), str(claim_token), version)
            self._deny("membership_dependency_unavailable", now, correlation)
        if not isinstance(membership_result, Mapping) or not is_non_empty_string(
            membership_result.get("membership_reference")
        ):
            self._release_claim(str(request_id), str(claim_token), version)
            self._deny("membership_dependency_unavailable", now, correlation)

        try:
            consumed = self.request_store.consume(
                request_id=request_id,
                claim_token=claim_token,
                expected_version=version,
                consumed_at=now,
                result_reference="bootstrap_request_completed",
            )
        except Exception:
            consumed = False
        if consumed is not True:
            self._release_claim(str(request_id), str(claim_token), version)
            self._deny("bootstrap_consume_conflict", now, correlation)

        self._audit_allow(now, correlation)
        return {
            "status": "completed",
            "request_reference": "bootstrap_request_completed",
            "user_reference": str(provider_result["user_reference"]),
            "membership_reference": str(membership_result["membership_reference"]),
        }

    def _validate_request(
        self,
        command: Mapping[str, Any],
        stored: Mapping[str, Any],
        now: datetime,
    ) -> tuple[str, str, str]:
        if stored.get("schema_version") != "identity-bootstrap-request.v1":
            self._deny("unsupported_contract", now)

        binding_values = (
            stored.get("subject"),
            stored.get("customer_id"),
            stored.get("deployment_id"),
        )
        if any(value is None for value in binding_values):
            self._deny("missing_binding", now)
        subject, customer_id, deployment_id = binding_values
        if not (
            isinstance(subject, str)
            and SUBJECT_PATTERN.fullmatch(subject)
            and isinstance(customer_id, str)
            and CUSTOMER_ID_PATTERN.fullmatch(customer_id)
            and isinstance(deployment_id, str)
            and DEPLOYMENT_ID_PATTERN.fullmatch(deployment_id)
        ):
            self._deny("malformed_binding", now)
        correlation = (stored.get("request_id"), subject, customer_id, deployment_id)
        if customer_id != self.config.get("expected_customer_id"):
            self._deny("foreign_binding", now, correlation)
        if deployment_id != self.config.get("expected_deployment_id"):
            self._deny("foreign_binding", now, correlation)

        version = stored.get("version")
        command_binding = {
            "request_id": command.get("request_id"),
            "subject": command.get("subject"),
            "customer_id": command.get("customer_id"),
            "deployment_id": command.get("deployment_id"),
            "expected_version": command.get("expected_version"),
        }
        expected_binding = {
            "request_id": stored.get("request_id"),
            "subject": subject,
            "customer_id": customer_id,
            "deployment_id": deployment_id,
            "expected_version": version,
        }
        if command_binding != expected_binding:
            self._deny("conflicting_binding", now, correlation)
        if not isinstance(version, int) or isinstance(version, bool) or version < 1:
            self._deny("stale_authorization_contract", now, correlation)

        state = stored.get("state")
        if state == "consumed":
            self._deny("bootstrap_replay_denied", now, correlation)
        if state != "approved":
            self._deny("bootstrap_not_approved", now, correlation)

        issued_at = parse_timestamp(stored.get("issued_at"))
        expires_at = parse_timestamp(stored.get("expires_at"))
        if issued_at is None or expires_at is None or expires_at <= issued_at:
            self._deny("bootstrap_expired", now, correlation)
        if issued_at > now:
            self._deny("bootstrap_not_yet_valid", now, correlation)
        if now >= expires_at:
            self._deny("bootstrap_expired", now, correlation)
        max_ttl = self.config.get("max_ttl_seconds")
        if not isinstance(max_ttl, int) or max_ttl < 1:
            self._deny("stale_authorization_contract", now, correlation)
        if (expires_at - issued_at).total_seconds() > max_ttl:
            self._deny("bootstrap_ttl_exceeded", now, correlation)

        if not is_non_empty_string(stored.get("idempotency_key")):
            self._deny("missing_idempotency_key", now, correlation)
        allowed_roles = self._string_set(self.config.get("allowed_role_ids"))
        if stored.get("role_id") not in allowed_roles:
            self._deny("unknown_role", now, correlation)
        self._validate_versions(stored, now, correlation)
        self._validate_approvals(stored, now, correlation)
        return subject, customer_id, deployment_id

    def _validate_versions(
        self,
        stored: Mapping[str, Any],
        now: datetime,
        correlation: tuple[object, ...],
    ) -> None:
        for field in (
            "authz_schema_version",
            "scope_catalog_version",
            "role_catalog_version",
            "policy_version",
        ):
            if stored.get(field) != self.config.get(field):
                self._deny("stale_authorization_contract", now, correlation)
        actual_digest = stored.get("policy_digest")
        expected_digest = self.config.get("policy_digest")
        if not (
            isinstance(actual_digest, str)
            and POLICY_DIGEST_PATTERN.fullmatch(actual_digest)
            and constant_time_equal(actual_digest, expected_digest)
        ):
            self._deny("stale_authorization_contract", now, correlation)

    def _validate_approvals(
        self,
        stored: Mapping[str, Any],
        now: datetime,
        correlation: tuple[object, ...],
    ) -> None:
        approvals = stored.get("approvals")
        if not isinstance(approvals, Sequence) or isinstance(approvals, (str, bytes)):
            self._deny("dual_approval_required", now, correlation)
        if (
            len(approvals) != 2
            or any(not isinstance(item, Mapping) for item in approvals)
            or any(item.get("decision") != "approved" for item in approvals)
        ):
            self._deny("dual_approval_required", now, correlation)
        approved = list(approvals)
        approvers = [item.get("approver_subject") for item in approved]
        if any(
            not isinstance(approver, str) or not SUBJECT_PATTERN.fullmatch(approver)
            for approver in approvers
        ):
            self._deny("independent_approvers_required", now, correlation)
        if len(set(approvers)) != 2:
            self._deny("independent_approvers_required", now, correlation)
        if stored.get("subject") in approvers:
            self._deny("self_approval_forbidden", now, correlation)
        approval_references = [item.get("approval_reference") for item in approved]
        if (
            any(not is_non_empty_string(reference) for reference in approval_references)
            or len(set(approval_references)) != 2
        ):
            self._deny("independent_approvers_required", now, correlation)

        max_age = self.config.get("max_auth_age_seconds")
        if not isinstance(max_age, int) or max_age < 1:
            self._deny("stale_authorization_contract", now, correlation)
        issued_at = parse_timestamp(stored.get("issued_at"))
        expires_at = parse_timestamp(stored.get("expires_at"))
        if issued_at is None or expires_at is None:
            self._deny("bootstrap_expired", now, correlation)
        for approval in approved:
            if approval.get("assurance") != "phishing_resistant_mfa":
                self._deny("insufficient_assurance", now, correlation)
            approval_time = parse_timestamp(approval.get("authenticated_at"))
            if approval_time is None:
                self._deny("stale_approval", now, correlation)
            age = (now - approval_time).total_seconds()
            if (
                age < 0
                or age > max_age
                or approval_time < issued_at
                or approval_time >= expires_at
            ):
                self._deny("stale_approval", now, correlation)
            if (
                approval.get("request_id") != stored.get("request_id")
                or approval.get("customer_id") != stored.get("customer_id")
                or approval.get("deployment_id") != stored.get("deployment_id")
            ):
                self._deny("conflicting_approval_binding", now, correlation)

    @staticmethod
    def _string_set(value: object) -> frozenset[str]:
        if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
            return frozenset()
        return frozenset(item for item in value if isinstance(item, str))

    def _release_claim(self, request_id: str, claim_token: str, version: int) -> None:
        try:
            self.request_store.release(
                request_id=request_id,
                claim_token=claim_token,
                expected_version=version,
            )
        except Exception:
            self.logger.error("bootstrap_claim_release_failed")

    def _audit_allow(self, now: datetime, correlation: tuple[object, ...]) -> None:
        event = sanitized_audit_event(
            now=now,
            decision="allow",
            reason_code="bootstrap_completed",
            action="bootstrap",
            policy_version=str(self.config.get("policy_version", "unknown")),
            policy_digest=str(self.config.get("policy_digest", "unknown")),
            correlation_parts=correlation,
        )
        if not emit_sanitized(
            audit_sink=self.audit_sink,
            logger=self.logger,
            event=event,
            required=True,
        ):
            self.logger.warning(
                "identity_decision decision=deny reason_code=audit_dependency_unavailable"
            )
            raise BootstrapDenied("audit_dependency_unavailable")
        self.logger.info("identity_decision decision=allow reason_code=bootstrap_completed")

    def _deny(
        self,
        reason_code: str,
        now: datetime,
        correlation: tuple[object, ...] = (),
    ) -> None:
        event = sanitized_audit_event(
            now=now,
            decision="deny",
            reason_code=reason_code,
            action="bootstrap",
            policy_version=str(self.config.get("policy_version", "unknown")),
            policy_digest=str(self.config.get("policy_digest", "unknown")),
            correlation_parts=correlation,
        )
        emit_sanitized(
            audit_sink=self.audit_sink,
            logger=self.logger,
            event=event,
            required=False,
        )
        self.logger.warning(
            "identity_decision decision=deny reason_code=%s",
            reason_code,
        )
        raise BootstrapDenied(reason_code) from None
