from __future__ import annotations

import logging
import re
from datetime import datetime
from typing import Any, Callable, Mapping, Protocol, Sequence

from .common import (
    CUSTOMER_ID_PATTERN,
    DEPLOYMENT_ID_PATTERN,
    AuditSink,
    emit_sanitized,
    is_non_empty_string,
    parse_timestamp,
    sanitized_audit_event,
)


WORKLOAD_PATTERN = re.compile(r"^[a-z][a-z0-9_-]{2,63}$")
ENVIRONMENT_PATTERN = re.compile(r"^[a-z][a-z0-9-]{1,31}$")
IDEMPOTENCY_PATTERN = re.compile(r"^idem_[0-9A-HJKMNP-TV-Z]{26}$")
CLAIM_LEASE_SECONDS = 300


class M2MClientProvider(Protocol):
    def ensure_client(self, **request: Any) -> Mapping[str, Any]: ...


class M2MBindingStore(Protocol):
    def load_by_idempotency(self, idempotency_key: str) -> Mapping[str, Any] | None: ...

    def claim(self, **condition: Any) -> str | None: ...

    def reacquire(self, **condition: Any) -> str | None: ...

    def complete(self, **condition: Any) -> bool: ...

    def release(self, **condition: Any) -> None: ...


class M2MDenied(RuntimeError):
    def __init__(self, reason_code: str) -> None:
        self.reason_code = reason_code
        super().__init__("M2M provisioning denied")


class M2MProvisioner:
    """Provision one workload client and escrow its credential without exposure.

    Provider adapters must make ``ensure_client`` idempotent. This processor
    stores the credential immediately, records the exact binding conditionally,
    and returns only non-sensitive references.
    """

    def __init__(
        self,
        *,
        config: Mapping[str, Any],
        client_provider: M2MClientProvider,
        binding_store: M2MBindingStore,
        audit_sink: AuditSink,
        clock: Callable[[], datetime],
        logger: logging.Logger | None = None,
    ) -> None:
        self.config = dict(config)
        self.client_provider = client_provider
        self.binding_store = binding_store
        self.audit_sink = audit_sink
        self.clock = clock
        self.logger = logger or logging.getLogger(__name__)

    def provision(self, command: Mapping[str, Any]) -> dict[str, str]:
        now = self.clock()
        binding = self._validate_command(command, now)
        (
            request_id,
            workload_id,
            environment,
            customer_id,
            deployment_id,
            actions,
            scopes,
            idempotency_key,
        ) = binding
        correlation = (request_id, workload_id, customer_id, deployment_id)

        try:
            existing = self.binding_store.load_by_idempotency(idempotency_key)
        except Exception:
            self._deny("m2m_binding_dependency_unavailable", now, correlation)
        recovered_claim = False
        if existing is not None:
            if existing.get("status") == "active":
                return self._existing_result(
                    existing,
                    workload_id=workload_id,
                    environment=environment,
                    customer_id=customer_id,
                    deployment_id=deployment_id,
                    actions=actions,
                    now=now,
                    correlation=correlation,
                )
            claim_token = self._reacquire_stale_claim(
                existing,
                idempotency_key=idempotency_key,
                workload_id=workload_id,
                environment=environment,
                customer_id=customer_id,
                deployment_id=deployment_id,
                actions=actions,
                now=now,
                correlation=correlation,
            )
            recovered_claim = True
        else:
            try:
                claim_token = self.binding_store.claim(
                    idempotency_key=idempotency_key,
                    workload_id=workload_id,
                    environment=environment,
                    customer_id=customer_id,
                    deployment_id=deployment_id,
                    actions=list(actions),
                    claimed_at=now,
                )
            except Exception:
                self._deny("m2m_binding_dependency_unavailable", now, correlation)
            if not is_non_empty_string(claim_token):
                self._deny("m2m_claim_conflict", now, correlation)

        try:
            provider_result = self.client_provider.ensure_client(
                scopes=list(scopes),
                workload_id=workload_id,
                environment=environment,
                customer_id=customer_id,
                deployment_id=deployment_id,
                idempotency_key=idempotency_key,
            )
        except Exception:
            self._deny("m2m_provider_unavailable", now, correlation)
        if not isinstance(provider_result, Mapping):
            self._deny("m2m_provider_unavailable", now, correlation)
        client_id = provider_result.get("client_id")
        secret_reference = provider_result.get("secret_reference")
        if "client_secret" in provider_result or "secret_value" in provider_result:
            self._deny("m2m_provider_exposed_credential", now, correlation)
        if not is_non_empty_string(client_id) or not is_non_empty_string(
            secret_reference
        ):
            self._deny("m2m_provider_unavailable", now, correlation)
        secret_reference = str(secret_reference)

        try:
            completed = self.binding_store.complete(
                idempotency_key=idempotency_key,
                claim_token=claim_token,
                client_id=client_id,
                secret_reference=secret_reference,
                workload_id=workload_id,
                environment=environment,
                customer_id=customer_id,
                deployment_id=deployment_id,
                actions=list(actions),
                grant_version="1",
                completed_at=now,
            )
        except Exception:
            completed = False
        if completed is not True:
            self._deny("m2m_complete_conflict", now, correlation)

        self._audit_allow(
            now,
            correlation,
            reason_code=("m2m_reconciled" if recovered_claim else "m2m_provisioned"),
        )
        return {
            "status": "completed",
            "client_id": str(client_id),
            "secret_reference": secret_reference,
        }

    def _validate_command(
        self,
        command: Mapping[str, Any],
        now: datetime,
    ) -> tuple[str, str, str, str, str, tuple[str, ...], tuple[str, ...], str]:
        if not isinstance(command, Mapping):
            self._deny("unsupported_contract", now)
        if command.get("schema_version") != "identity-m2m-provisioning.v1":
            self._deny("unsupported_contract", now)
        if command.get("principal_type") != "m2m":
            self._deny("human_runtime_provisioning_forbidden", now)

        request_id = command.get("request_id")
        workload_id = command.get("workload_id")
        environment = command.get("environment")
        customer_id = command.get("customer_id")
        deployment_id = command.get("deployment_id")
        idempotency_key = command.get("idempotency_key")
        if not all(
            is_non_empty_string(value)
            for value in (
                request_id,
                workload_id,
                environment,
                customer_id,
                deployment_id,
                idempotency_key,
            )
        ):
            self._deny("missing_binding", now)
        if not (
            WORKLOAD_PATTERN.fullmatch(str(workload_id))
            and ENVIRONMENT_PATTERN.fullmatch(str(environment))
            and CUSTOMER_ID_PATTERN.fullmatch(str(customer_id))
            and DEPLOYMENT_ID_PATTERN.fullmatch(str(deployment_id))
            and IDEMPOTENCY_PATTERN.fullmatch(str(idempotency_key))
        ):
            self._deny("malformed_binding", now)
        correlation = (request_id, workload_id, customer_id, deployment_id)
        if customer_id != self.config.get("expected_customer_id"):
            self._deny("foreign_binding", now, correlation)
        if deployment_id != self.config.get("expected_deployment_id"):
            self._deny("foreign_binding", now, correlation)

        requested_actions = command.get("actions")
        if (
            not isinstance(requested_actions, Sequence)
            or isinstance(requested_actions, (str, bytes))
            or not requested_actions
            or any(not isinstance(action, str) for action in requested_actions)
        ):
            self._deny("invalid_action_grant", now, correlation)
        actions = tuple(sorted(set(requested_actions)))
        if len(actions) != len(requested_actions):
            self._deny("invalid_action_grant", now, correlation)
        action_scopes = self.config.get("action_scopes")
        if not isinstance(action_scopes, Mapping) or any(
            action not in action_scopes or not is_non_empty_string(action_scopes[action])
            for action in actions
        ):
            self._deny("invalid_action_grant", now, correlation)
        scopes = tuple(str(action_scopes[action]) for action in actions)
        return (
            str(request_id),
            str(workload_id),
            str(environment),
            str(customer_id),
            str(deployment_id),
            actions,
            scopes,
            str(idempotency_key),
        )

    def _existing_result(
        self,
        existing: Mapping[str, Any],
        *,
        workload_id: str,
        environment: str,
        customer_id: str,
        deployment_id: str,
        actions: tuple[str, ...],
        now: datetime,
        correlation: tuple[object, ...],
    ) -> dict[str, str]:
        expected = {
            "status": "active",
            "workload_id": workload_id,
            "environment": environment,
            "customer_id": customer_id,
            "deployment_id": deployment_id,
            "actions": list(actions),
        }
        if any(existing.get(key) != value for key, value in expected.items()):
            self._deny("m2m_idempotency_conflict", now, correlation)
        if not is_non_empty_string(existing.get("client_id")) or not is_non_empty_string(
            existing.get("secret_reference")
        ):
            self._deny("m2m_idempotency_conflict", now, correlation)
        self._audit_allow(now, correlation, reason_code="m2m_idempotent_replay")
        return {
            "status": "completed",
            "client_id": str(existing["client_id"]),
            "secret_reference": str(existing["secret_reference"]),
        }

    def _reacquire_stale_claim(
        self,
        existing: Mapping[str, Any],
        *,
        idempotency_key: str,
        workload_id: str,
        environment: str,
        customer_id: str,
        deployment_id: str,
        actions: tuple[str, ...],
        now: datetime,
        correlation: tuple[object, ...],
    ) -> str:
        expected = {
            "status": "provisioning",
            "workload_id": workload_id,
            "environment": environment,
            "customer_id": customer_id,
            "deployment_id": deployment_id,
            "actions": list(actions),
        }
        if any(existing.get(key) != value for key, value in expected.items()):
            self._deny("m2m_idempotency_conflict", now, correlation)
        claim_token = existing.get("claim_token")
        claimed_at_raw = existing.get("claimed_at")
        claimed_at = parse_timestamp(claimed_at_raw)
        if (
            not is_non_empty_string(claim_token)
            or not isinstance(claimed_at_raw, str)
            or claimed_at is None
            or claimed_at > now
        ):
            self._deny("m2m_idempotency_conflict", now, correlation)
        if (now - claimed_at).total_seconds() <= CLAIM_LEASE_SECONDS:
            self._deny("m2m_claim_in_progress", now, correlation)

        try:
            reacquired = self.binding_store.reacquire(
                idempotency_key=idempotency_key,
                expected_claim_token=str(claim_token),
                expected_claimed_at=claimed_at_raw,
                workload_id=workload_id,
                environment=environment,
                customer_id=customer_id,
                deployment_id=deployment_id,
                actions=list(actions),
                claimed_at=now,
            )
        except Exception:
            self._deny("m2m_binding_dependency_unavailable", now, correlation)
        if not is_non_empty_string(reacquired):
            self._deny("m2m_claim_conflict", now, correlation)
        return str(reacquired)

    def _release(self, idempotency_key: str, claim_token: str) -> None:
        try:
            self.binding_store.release(
                idempotency_key=idempotency_key,
                claim_token=claim_token,
            )
        except Exception:
            self.logger.error("m2m_claim_release_failed")

    def _audit_allow(
        self,
        now: datetime,
        correlation: tuple[object, ...],
        *,
        reason_code: str = "m2m_provisioned",
    ) -> None:
        event = sanitized_audit_event(
            now=now,
            decision="allow",
            reason_code=reason_code,
            action="m2m.provision",
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
            raise M2MDenied("audit_dependency_unavailable")
        self.logger.info(
            "identity_decision decision=allow reason_code=%s",
            reason_code,
        )

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
            action="m2m.provision",
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
        raise M2MDenied(reason_code) from None
