from __future__ import annotations

import copy
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
    sanitized_audit_event,
)


class MembershipReader(Protocol):
    def get_membership(
        self,
        *,
        subject: str,
        customer_id: str,
        deployment_id: str,
    ) -> Mapping[str, Any] | None: ...


class PreTokenDenied(RuntimeError):
    def __init__(self, reason_code: str) -> None:
        self.reason_code = reason_code
        super().__init__("identity issuance denied")


class PreTokenProcessor:
    """Produce canonical access-token claims from an authoritative membership.

    Cognito groups, client metadata, and other request-controlled values are never
    authorization inputs. A denial uses a stable sanitized reason code and never
    includes the raw event in logs or audit records.
    """

    _SUPPORTED_TRIGGERS = frozenset(
        {
            "TokenGeneration_Authentication",
            "TokenGeneration_RefreshTokens",
        }
    )

    def __init__(
        self,
        *,
        config: Mapping[str, Any],
        membership_reader: MembershipReader,
        audit_sink: AuditSink,
        clock: Callable[[], datetime],
        logger: logging.Logger | None = None,
    ) -> None:
        self.config = dict(config)
        self.membership_reader = membership_reader
        self.audit_sink = audit_sink
        self.clock = clock
        self.logger = logger or logging.getLogger(__name__)

    def handle(self, event: Mapping[str, Any]) -> dict[str, Any]:
        now = self.clock()
        # This is an explicit rollout gate, not an implicit dependency check.
        # A disabled or missing gate must deny before inspecting provider input
        # or reading an authoritative membership.
        if self.config.get("human_runtime_enabled") is not True:
            self._deny("human_runtime_disabled", now)
        if not isinstance(event, Mapping):
            self._deny("unsupported_event", now)
        if event.get("version") != "2":
            self._deny("unsupported_event", now)
        if event.get("triggerSource") not in self._SUPPORTED_TRIGGERS:
            self._deny("unsupported_event", now)
        if event.get("userPoolId") != self.config.get("expected_user_pool_id"):
            self._deny("foreign_identity_provider", now)

        caller_context = event.get("callerContext")
        if not isinstance(caller_context, Mapping):
            self._deny("unsupported_event", now)
        allowed_clients = self._string_set(self.config.get("allowed_client_ids"))
        if caller_context.get("clientId") not in allowed_clients:
            self._deny("foreign_client", now)

        request = event.get("request")
        if not isinstance(request, Mapping):
            self._deny("unsupported_event", now)
        attributes = request.get("userAttributes")
        if not isinstance(attributes, Mapping):
            self._deny("missing_binding", now)

        subject = attributes.get("sub")
        customer_id = attributes.get("custom:customerId")
        deployment_id = attributes.get("custom:deployment_id")
        if any(value is None for value in (subject, customer_id, deployment_id)):
            self._deny("missing_binding", now)
        if not (
            isinstance(subject, str)
            and SUBJECT_PATTERN.fullmatch(subject)
            and isinstance(customer_id, str)
            and CUSTOMER_ID_PATTERN.fullmatch(customer_id)
            and isinstance(deployment_id, str)
            and DEPLOYMENT_ID_PATTERN.fullmatch(deployment_id)
        ):
            self._deny("malformed_binding", now)
        if customer_id != self.config.get("expected_customer_id"):
            self._deny("foreign_binding", now, (subject, customer_id, deployment_id))
        if deployment_id != self.config.get("expected_deployment_id"):
            self._deny("foreign_binding", now, (subject, customer_id, deployment_id))

        try:
            membership = self.membership_reader.get_membership(
                subject=subject,
                customer_id=customer_id,
                deployment_id=deployment_id,
            )
        except Exception:
            self._deny(
                "membership_dependency_unavailable",
                now,
                (subject, customer_id, deployment_id),
            )
        if not isinstance(membership, Mapping) or not membership:
            self._deny(
                "membership_not_authorized",
                now,
                (subject, customer_id, deployment_id),
            )

        self._validate_membership(
            membership,
            subject=subject,
            customer_id=customer_id,
            deployment_id=deployment_id,
            now=now,
        )

        result = copy.deepcopy(dict(event))
        result.setdefault("response", {})
        if not isinstance(result["response"], dict):
            self._deny("unsupported_event", now)
        result["response"]["claimsAndScopeOverrideDetails"] = {
            "accessTokenGeneration": {
                "claimsToAddOrOverride": {
                    "custom:customerId": customer_id,
                    "custom:deployment_id": deployment_id,
                    "principal_type": "user",
                    "membership_state": "active",
                    "role_id": str(membership["role_id"]),
                    "membership_version": str(membership["membership_version"]),
                    "authz_schema_version": str(membership["authz_schema_version"]),
                    "scope_catalog_version": str(membership["scope_catalog_version"]),
                    "role_catalog_version": str(membership["role_catalog_version"]),
                    "policy_version": str(membership["policy_version"]),
                    "policy_digest": str(membership["policy_digest"]),
                }
            },
            "groupOverrideDetails": {
                "groupsToOverride": [],
                "iamRolesToOverride": [],
            },
        }
        self._audit_allow(now, (subject, customer_id, deployment_id))
        return result

    def _validate_membership(
        self,
        membership: Mapping[str, Any],
        *,
        subject: str,
        customer_id: str,
        deployment_id: str,
        now: datetime,
    ) -> None:
        correlation = (subject, customer_id, deployment_id)
        if membership.get("subject") != subject:
            self._deny("conflicting_binding", now, correlation)
        if membership.get("customer_id") != customer_id:
            self._deny("foreign_binding", now, correlation)
        if membership.get("deployment_id") != deployment_id:
            self._deny("foreign_binding", now, correlation)
        if membership.get("principal_type") != "user":
            self._deny("conflicting_principal_type", now, correlation)
        if membership.get("membership_state") != "active":
            self._deny("inactive_membership", now, correlation)

        allowed_roles = self._string_set(self.config.get("allowed_role_ids"))
        if membership.get("role_id") not in allowed_roles:
            self._deny("unknown_role", now, correlation)

        expected_versions = {
            "authz_schema_version": self.config.get("authz_schema_version"),
            "scope_catalog_version": self.config.get("scope_catalog_version"),
            "role_catalog_version": self.config.get("role_catalog_version"),
            "policy_version": self.config.get("policy_version"),
        }
        if not is_non_empty_string(membership.get("membership_version")):
            self._deny("stale_authorization_contract", now, correlation)
        if any(membership.get(key) != expected for key, expected in expected_versions.items()):
            self._deny("stale_authorization_contract", now, correlation)

        actual_digest = membership.get("policy_digest")
        expected_digest = self.config.get("policy_digest")
        if not (
            isinstance(actual_digest, str)
            and POLICY_DIGEST_PATTERN.fullmatch(actual_digest)
            and constant_time_equal(actual_digest, expected_digest)
        ):
            self._deny("stale_authorization_contract", now, correlation)

    @staticmethod
    def _string_set(value: object) -> frozenset[str]:
        if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
            return frozenset()
        return frozenset(item for item in value if isinstance(item, str))

    def _audit_allow(self, now: datetime, correlation: tuple[object, ...]) -> None:
        event = sanitized_audit_event(
            now=now,
            decision="allow",
            reason_code="pre_token_issued",
            action="token.issue",
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
            raise PreTokenDenied("audit_dependency_unavailable")
        self.logger.info("identity_decision decision=allow reason_code=pre_token_issued")

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
            action="token.issue",
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
        raise PreTokenDenied(reason_code) from None
