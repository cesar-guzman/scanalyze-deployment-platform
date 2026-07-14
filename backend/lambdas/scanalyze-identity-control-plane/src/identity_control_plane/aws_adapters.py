from __future__ import annotations

import hashlib
import json
import uuid
from collections.abc import Mapping, Sequence
from datetime import datetime
from typing import Any

from .common import (
    CUSTOMER_ID_PATTERN,
    DEPLOYMENT_ID_PATTERN,
    SUBJECT_PATTERN,
    is_non_empty_string,
    opaque_reference,
    utc_timestamp,
)
from .m2m import ENVIRONMENT_PATTERN, IDEMPOTENCY_PATTERN, WORKLOAD_PATTERN


_CONDITIONAL_FAILURE = "ConditionalCheckFailedException"
_NOT_FOUND = "ResourceNotFoundException"


class AdapterContractError(RuntimeError):
    """A sanitized AWS adapter or persistence contract failure."""

    def __init__(self) -> None:
        super().__init__("identity adapter contract rejected")


def _aws_error_code(error: BaseException) -> str | None:
    response = getattr(error, "response", None)
    if not isinstance(response, Mapping):
        return None
    details = response.get("Error")
    if not isinstance(details, Mapping):
        return None
    code = details.get("Code")
    return code if isinstance(code, str) else None


def _is_error(error: BaseException, code: str) -> bool:
    return _aws_error_code(error) == code


def _string_sequence(value: object) -> tuple[str, ...] | None:
    if (
        not isinstance(value, Sequence)
        or isinstance(value, (str, bytes))
        or any(not isinstance(item, str) or not item for item in value)
    ):
        return None
    result = tuple(value)
    if len(result) != len(set(result)):
        return None
    return result


def _membership_key(subject: str, customer_id: str, deployment_id: str) -> dict[str, str]:
    return {
        "pk": f"MEMBERSHIP#{deployment_id}#{customer_id}",
        "sk": f"SUBJECT#{subject}",
    }


def _bootstrap_key(request_id: str) -> dict[str, str]:
    if not is_non_empty_string(request_id):
        raise AdapterContractError()
    return {"pk": f"BOOTSTRAP_REQUEST#{request_id}", "sk": "REQUEST"}


class DynamoMembershipReader:
    def __init__(self, table: Any) -> None:
        self.table = table

    def get_membership(
        self,
        *,
        subject: str,
        customer_id: str,
        deployment_id: str,
    ) -> Mapping[str, Any] | None:
        if not (
            SUBJECT_PATTERN.fullmatch(subject)
            and CUSTOMER_ID_PATTERN.fullmatch(customer_id)
            and DEPLOYMENT_ID_PATTERN.fullmatch(deployment_id)
        ):
            raise AdapterContractError()
        response = self.table.get_item(
            Key=_membership_key(subject, customer_id, deployment_id),
            ConsistentRead=True,
        )
        item = response.get("Item") if isinstance(response, Mapping) else None
        if item is None:
            return None
        if not isinstance(item, Mapping):
            raise AdapterContractError()
        return dict(item)


class DynamoAuditSink:
    _FIELDS = frozenset(
        {
            "event_schema_version",
            "timestamp",
            "decision_id",
            "principal_type",
            "principal_reference",
            "customer_reference",
            "deployment_reference",
            "action",
            "resource_type",
            "decision",
            "reason_code",
            "policy_version",
            "policy_digest",
            "assurance",
            "correlation_reference",
        }
    )

    def __init__(self, table: Any) -> None:
        self.table = table

    def emit(self, event: dict[str, Any]) -> None:
        if set(event) != self._FIELDS:
            raise AdapterContractError()
        if (
            event.get("event_schema_version") != "identity-audit.v1"
            or event.get("principal_reference") != "redacted"
            or event.get("customer_reference") != "redacted"
            or event.get("deployment_reference") != "redacted"
            or not is_non_empty_string(event.get("timestamp"))
            or not is_non_empty_string(event.get("decision_id"))
        ):
            raise AdapterContractError()
        timestamp = str(event["timestamp"])
        item = {
            "pk": f"AUDIT#{timestamp[:10]}",
            "sk": f"{timestamp}#{event['decision_id']}",
            **event,
        }
        try:
            self.table.put_item(
                Item=item,
                ConditionExpression="attribute_not_exists(pk) AND attribute_not_exists(sk)",
            )
        except Exception as error:
            if not _is_error(error, _CONDITIONAL_FAILURE):
                raise
            response = self.table.get_item(
                Key={"pk": item["pk"], "sk": item["sk"]},
                ConsistentRead=True,
            )
            existing = response.get("Item") if isinstance(response, Mapping) else None
            if not isinstance(existing, Mapping) or dict(existing) != item:
                raise AdapterContractError() from error


class DynamoBootstrapRequestStore:
    def __init__(self, table: Any) -> None:
        self.table = table

    def load(self, request_id: str) -> Mapping[str, Any] | None:
        response = self.table.get_item(
            Key=_bootstrap_key(request_id),
            ConsistentRead=True,
        )
        item = response.get("Item") if isinstance(response, Mapping) else None
        if item is None:
            return None
        if not isinstance(item, Mapping):
            raise AdapterContractError()
        return dict(item)

    def claim(self, **condition: Any) -> str | None:
        request_id = condition.get("request_id")
        expected_state = condition.get("expected_state")
        expected_version = condition.get("expected_version")
        idempotency_key = condition.get("idempotency_key")
        claimed_at = condition.get("claimed_at")
        if not (
            isinstance(request_id, str)
            and expected_state == "approved"
            and isinstance(expected_version, int)
            and not isinstance(expected_version, bool)
            and expected_version >= 1
            and is_non_empty_string(idempotency_key)
            and isinstance(claimed_at, datetime)
        ):
            raise AdapterContractError()
        claim_token = uuid.uuid4().hex
        try:
            self.table.update_item(
                Key=_bootstrap_key(request_id),
                UpdateExpression=(
                    "SET #state = :claimed, claim_token = :claim_token, "
                    "claimed_at = :claimed_at"
                ),
                ConditionExpression=(
                    "#state = :approved AND #version = :version AND "
                    "idempotency_key = :idempotency_key AND "
                    "attribute_not_exists(claim_token)"
                ),
                ExpressionAttributeNames={"#state": "state", "#version": "version"},
                ExpressionAttributeValues={
                    ":approved": "approved",
                    ":claimed": "claimed",
                    ":version": expected_version,
                    ":idempotency_key": idempotency_key,
                    ":claim_token": claim_token,
                    ":claimed_at": utc_timestamp(claimed_at),
                },
            )
        except Exception as error:
            if _is_error(error, _CONDITIONAL_FAILURE):
                return None
            raise
        return claim_token

    def mark_effects_applied(self, **condition: Any) -> bool:
        request_id = condition.get("request_id")
        claim_token = condition.get("claim_token")
        expected_version = condition.get("expected_version")
        idempotency_key = condition.get("idempotency_key")
        outcome_at = condition.get("outcome_at")
        user_reference = condition.get("user_reference")
        membership_reference = condition.get("membership_reference")
        if not (
            isinstance(request_id, str)
            and is_non_empty_string(claim_token)
            and isinstance(expected_version, int)
            and not isinstance(expected_version, bool)
            and expected_version >= 1
            and is_non_empty_string(idempotency_key)
            and isinstance(outcome_at, datetime)
            and is_non_empty_string(user_reference)
            and is_non_empty_string(membership_reference)
        ):
            raise AdapterContractError()
        try:
            self.table.update_item(
                Key=_bootstrap_key(request_id),
                UpdateExpression=(
                    "SET #state = :effects_applied, outcome_at = :outcome_at, "
                    "user_reference = :user_reference, "
                    "membership_reference = :membership_reference"
                ),
                ConditionExpression=(
                    "#state = :claimed AND #version = :version AND "
                    "claim_token = :claim_token AND "
                    "idempotency_key = :idempotency_key"
                ),
                ExpressionAttributeNames={"#state": "state", "#version": "version"},
                ExpressionAttributeValues={
                    ":claimed": "claimed",
                    ":effects_applied": "effects_applied",
                    ":version": expected_version,
                    ":claim_token": claim_token,
                    ":idempotency_key": idempotency_key,
                    ":outcome_at": utc_timestamp(outcome_at),
                    ":user_reference": user_reference,
                    ":membership_reference": membership_reference,
                },
            )
        except Exception as error:
            if _is_error(error, _CONDITIONAL_FAILURE):
                return False
            raise
        return True

    def mark_audit_committed(self, **condition: Any) -> bool:
        request_id = condition.get("request_id")
        claim_token = condition.get("claim_token")
        expected_version = condition.get("expected_version")
        idempotency_key = condition.get("idempotency_key")
        audit_decision_id = condition.get("audit_decision_id")
        audit_committed_at = condition.get("audit_committed_at")
        if not (
            isinstance(request_id, str)
            and is_non_empty_string(claim_token)
            and isinstance(expected_version, int)
            and not isinstance(expected_version, bool)
            and expected_version >= 1
            and is_non_empty_string(idempotency_key)
            and is_non_empty_string(audit_decision_id)
            and isinstance(audit_committed_at, datetime)
        ):
            raise AdapterContractError()
        try:
            self.table.update_item(
                Key=_bootstrap_key(request_id),
                UpdateExpression=(
                    "SET #state = :audit_committed, "
                    "audit_decision_id = :audit_decision_id, "
                    "audit_committed_at = :audit_committed_at"
                ),
                ConditionExpression=(
                    "#state = :effects_applied AND #version = :version AND "
                    "claim_token = :claim_token AND "
                    "idempotency_key = :idempotency_key"
                ),
                ExpressionAttributeNames={"#state": "state", "#version": "version"},
                ExpressionAttributeValues={
                    ":effects_applied": "effects_applied",
                    ":audit_committed": "audit_committed",
                    ":version": expected_version,
                    ":claim_token": claim_token,
                    ":idempotency_key": idempotency_key,
                    ":audit_decision_id": audit_decision_id,
                    ":audit_committed_at": utc_timestamp(audit_committed_at),
                },
            )
        except Exception as error:
            if _is_error(error, _CONDITIONAL_FAILURE):
                return False
            raise
        return True

    def consume(self, **condition: Any) -> bool:
        request_id = condition.get("request_id")
        claim_token = condition.get("claim_token")
        expected_state = condition.get("expected_state")
        expected_version = condition.get("expected_version")
        consumed_at = condition.get("consumed_at")
        result_reference = condition.get("result_reference")
        if not (
            isinstance(request_id, str)
            and is_non_empty_string(claim_token)
            and expected_state == "audit_committed"
            and isinstance(expected_version, int)
            and not isinstance(expected_version, bool)
            and expected_version >= 1
            and isinstance(consumed_at, datetime)
            and result_reference == "bootstrap_request_completed"
        ):
            raise AdapterContractError()
        try:
            self.table.update_item(
                Key=_bootstrap_key(request_id),
                UpdateExpression=(
                    "SET #state = :consumed, consumed_at = :consumed_at, "
                    "result_reference = :result_reference REMOVE claim_token, claimed_at"
                ),
                ConditionExpression=(
                    "#state = :audit_committed AND #version = :version AND "
                    "claim_token = :claim_token"
                ),
                ExpressionAttributeNames={"#state": "state", "#version": "version"},
                ExpressionAttributeValues={
                    ":audit_committed": "audit_committed",
                    ":consumed": "consumed",
                    ":version": expected_version,
                    ":claim_token": claim_token,
                    ":consumed_at": utc_timestamp(consumed_at),
                    ":result_reference": result_reference,
                },
            )
        except Exception as error:
            if _is_error(error, _CONDITIONAL_FAILURE):
                return False
            raise
        return True

    def release(self, **condition: Any) -> None:
        request_id = condition.get("request_id")
        claim_token = condition.get("claim_token")
        expected_version = condition.get("expected_version")
        if not (
            isinstance(request_id, str)
            and is_non_empty_string(claim_token)
            and isinstance(expected_version, int)
            and not isinstance(expected_version, bool)
            and expected_version >= 1
        ):
            raise AdapterContractError()
        try:
            self.table.update_item(
                Key=_bootstrap_key(request_id),
                UpdateExpression="SET #state = :approved REMOVE claim_token, claimed_at",
                ConditionExpression=(
                    "#state = :claimed AND #version = :version AND "
                    "claim_token = :claim_token"
                ),
                ExpressionAttributeNames={"#state": "state", "#version": "version"},
                ExpressionAttributeValues={
                    ":claimed": "claimed",
                    ":approved": "approved",
                    ":version": expected_version,
                    ":claim_token": claim_token,
                },
            )
        except Exception as error:
            if _is_error(error, _CONDITIONAL_FAILURE):
                return
            raise


class CognitoExistingUserProvider:
    """Resolve and validate an existing human; never creates a runtime user."""

    def __init__(self, cognito_client: Any, *, user_pool_id: str) -> None:
        self.client = cognito_client
        self.user_pool_id = user_pool_id

    def ensure_user(self, **record: Any) -> Mapping[str, Any]:
        subject = record.get("subject")
        attributes = record.get("immutable_attributes")
        if not (
            isinstance(subject, str)
            and SUBJECT_PATTERN.fullmatch(subject)
            and isinstance(attributes, Mapping)
            and set(attributes) == {"custom:customerId", "custom:deployment_id"}
        ):
            raise AdapterContractError()
        response = self.client.admin_get_user(
            UserPoolId=self.user_pool_id,
            Username=subject,
        )
        if not isinstance(response, Mapping) or response.get("Username") != subject:
            raise AdapterContractError()
        raw_attributes = response.get("UserAttributes")
        if not isinstance(raw_attributes, Sequence) or isinstance(
            raw_attributes, (str, bytes)
        ):
            raise AdapterContractError()
        provider_attributes: dict[str, str] = {}
        for item in raw_attributes:
            if not isinstance(item, Mapping):
                raise AdapterContractError()
            name, value = item.get("Name"), item.get("Value")
            if isinstance(name, str) and isinstance(value, str):
                provider_attributes[name] = value
        if (
            provider_attributes.get("sub") != subject
            or provider_attributes.get("custom:customerId")
            != attributes.get("custom:customerId")
            or provider_attributes.get("custom:deployment_id")
            != attributes.get("custom:deployment_id")
        ):
            raise AdapterContractError()
        return {
            "user_reference": opaque_reference(
                self.user_pool_id,
                subject,
                attributes["custom:customerId"],
                attributes["custom:deployment_id"],
            ),
            "provider_principal_key": subject,
        }


class DynamoMembershipStore:
    _REQUIRED = frozenset(
        {
            "subject",
            "customer_id",
            "deployment_id",
            "role_id",
            "state",
            "membership_version",
            "authz_schema_version",
            "scope_catalog_version",
            "role_catalog_version",
            "policy_version",
            "policy_digest",
            "idempotency_key",
            "provider_user_reference",
            "provider_principal_key",
            "created_at",
        }
    )

    def __init__(self, table: Any) -> None:
        self.table = table

    def ensure_membership(self, **record: Any) -> Mapping[str, Any]:
        if set(record) != self._REQUIRED:
            raise AdapterContractError()
        subject = record.get("subject")
        customer_id = record.get("customer_id")
        deployment_id = record.get("deployment_id")
        if not (
            isinstance(subject, str)
            and SUBJECT_PATTERN.fullmatch(subject)
            and isinstance(customer_id, str)
            and CUSTOMER_ID_PATTERN.fullmatch(customer_id)
            and isinstance(deployment_id, str)
            and DEPLOYMENT_ID_PATTERN.fullmatch(deployment_id)
            and record.get("state") == "active"
            and isinstance(record.get("membership_version"), int)
            and not isinstance(record.get("membership_version"), bool)
            and record["membership_version"] == 1
            and is_non_empty_string(record.get("provider_user_reference"))
            and record.get("provider_principal_key") == subject
            and isinstance(record.get("created_at"), datetime)
        ):
            raise AdapterContractError()
        key = _membership_key(subject, customer_id, deployment_id)
        membership_reference = "mbr_" + hashlib.sha256(
            "\x1f".join((customer_id, deployment_id, subject)).encode("utf-8")
        ).hexdigest()[:32]
        item = {
            **key,
            **record,
            "schema_version": "enterprise-membership.v1",
            "membership_reference": membership_reference,
            "principal_type": "user",
            "updated_at": record["created_at"],
            "ownership_membership_key": (
                f"{deployment_id}#{customer_id}#MEMBERSHIP#{membership_reference}"
            ),
            "ownership_state_key": f"{deployment_id}#{customer_id}#STATE#active",
        }
        try:
            self.table.put_item(
                Item=item,
                ConditionExpression=(
                    "attribute_not_exists(pk) AND attribute_not_exists(sk)"
                ),
            )
        except Exception as error:
            if not _is_error(error, _CONDITIONAL_FAILURE):
                raise
            response = self.table.get_item(Key=key, ConsistentRead=True)
            existing = response.get("Item") if isinstance(response, Mapping) else None
            if not isinstance(existing, Mapping) or any(
                existing.get(field) != value for field, value in item.items()
            ):
                raise AdapterContractError() from None
        return {
            "membership_reference": membership_reference,
        }


class DynamoM2MBindingStore:
    def __init__(self, table: Any, *, customer_id: str, deployment_id: str) -> None:
        self.table = table
        self.customer_id = customer_id
        self.deployment_id = deployment_id

    def _key(self, idempotency_key: str) -> dict[str, str]:
        if IDEMPOTENCY_PATTERN.fullmatch(idempotency_key) is None:
            raise AdapterContractError()
        return {
            "pk": f"M2M#{self.deployment_id}#{self.customer_id}",
            "sk": f"IDEMPOTENCY#{idempotency_key}",
        }

    def load_by_idempotency(self, idempotency_key: str) -> Mapping[str, Any] | None:
        response = self.table.get_item(
            Key=self._key(idempotency_key),
            ConsistentRead=True,
        )
        item = response.get("Item") if isinstance(response, Mapping) else None
        if item is None:
            return None
        if not isinstance(item, Mapping):
            raise AdapterContractError()
        return dict(item)

    def claim(self, **condition: Any) -> str | None:
        idempotency_key = condition.get("idempotency_key")
        actions = _string_sequence(condition.get("actions"))
        claimed_at = condition.get("claimed_at")
        if not (
            isinstance(idempotency_key, str)
            and condition.get("customer_id") == self.customer_id
            and condition.get("deployment_id") == self.deployment_id
            and isinstance(condition.get("workload_id"), str)
            and WORKLOAD_PATTERN.fullmatch(condition["workload_id"])
            and isinstance(condition.get("environment"), str)
            and ENVIRONMENT_PATTERN.fullmatch(condition["environment"])
            and actions
            and isinstance(claimed_at, datetime)
        ):
            raise AdapterContractError()
        claim_token = uuid.uuid4().hex
        item = {
            **self._key(idempotency_key),
            "status": "provisioning",
            "idempotency_key": idempotency_key,
            "claim_token": claim_token,
            "workload_id": condition["workload_id"],
            "environment": condition["environment"],
            "customer_id": self.customer_id,
            "deployment_id": self.deployment_id,
            "actions": list(actions),
            "claimed_at": utc_timestamp(claimed_at),
        }
        try:
            self.table.put_item(
                Item=item,
                ConditionExpression=(
                    "attribute_not_exists(pk) AND attribute_not_exists(sk)"
                ),
            )
        except Exception as error:
            if _is_error(error, _CONDITIONAL_FAILURE):
                return None
            raise
        return claim_token

    def reacquire(self, **condition: Any) -> str | None:
        idempotency_key = condition.get("idempotency_key")
        expected_claim_token = condition.get("expected_claim_token")
        expected_claimed_at = condition.get("expected_claimed_at")
        actions = _string_sequence(condition.get("actions"))
        claimed_at = condition.get("claimed_at")
        if not (
            isinstance(idempotency_key, str)
            and is_non_empty_string(expected_claim_token)
            and is_non_empty_string(expected_claimed_at)
            and condition.get("customer_id") == self.customer_id
            and condition.get("deployment_id") == self.deployment_id
            and isinstance(condition.get("workload_id"), str)
            and WORKLOAD_PATTERN.fullmatch(condition["workload_id"])
            and isinstance(condition.get("environment"), str)
            and ENVIRONMENT_PATTERN.fullmatch(condition["environment"])
            and actions
            and isinstance(claimed_at, datetime)
        ):
            raise AdapterContractError()
        new_claim_token = uuid.uuid4().hex
        try:
            self.table.update_item(
                Key=self._key(idempotency_key),
                UpdateExpression=(
                    "SET claim_token = :new_claim_token, "
                    "claimed_at = :new_claimed_at"
                ),
                ConditionExpression=(
                    "#status = :provisioning AND "
                    "claim_token = :expected_claim_token AND "
                    "claimed_at = :expected_claimed_at AND "
                    "customer_id = :customer_id AND "
                    "deployment_id = :deployment_id AND "
                    "workload_id = :workload_id AND "
                    "environment = :environment AND actions = :actions"
                ),
                ExpressionAttributeNames={"#status": "status"},
                ExpressionAttributeValues={
                    ":provisioning": "provisioning",
                    ":expected_claim_token": expected_claim_token,
                    ":expected_claimed_at": expected_claimed_at,
                    ":new_claim_token": new_claim_token,
                    ":new_claimed_at": utc_timestamp(claimed_at),
                    ":customer_id": self.customer_id,
                    ":deployment_id": self.deployment_id,
                    ":workload_id": condition["workload_id"],
                    ":environment": condition["environment"],
                    ":actions": list(actions),
                },
            )
        except Exception as error:
            if _is_error(error, _CONDITIONAL_FAILURE):
                return None
            raise
        return new_claim_token

    def complete(self, **condition: Any) -> bool:
        idempotency_key = condition.get("idempotency_key")
        actions = _string_sequence(condition.get("actions"))
        completed_at = condition.get("completed_at")
        if not (
            isinstance(idempotency_key, str)
            and is_non_empty_string(condition.get("claim_token"))
            and is_non_empty_string(condition.get("client_id"))
            and is_non_empty_string(condition.get("secret_reference"))
            and condition.get("customer_id") == self.customer_id
            and condition.get("deployment_id") == self.deployment_id
            and actions
            and condition.get("grant_version") == "1"
            and isinstance(completed_at, datetime)
        ):
            raise AdapterContractError()
        try:
            self.table.update_item(
                Key=self._key(idempotency_key),
                UpdateExpression=(
                    "SET #status = :active, client_id = :client_id, "
                    "secret_reference = :secret_reference, grant_version = :grant_version, "
                    "completed_at = :completed_at REMOVE claim_token"
                ),
                ConditionExpression=(
                    "#status = :provisioning AND claim_token = :claim_token AND "
                    "customer_id = :customer_id AND deployment_id = :deployment_id AND "
                    "workload_id = :workload_id AND environment = :environment AND "
                    "actions = :actions"
                ),
                ExpressionAttributeNames={"#status": "status"},
                ExpressionAttributeValues={
                    ":active": "active",
                    ":provisioning": "provisioning",
                    ":claim_token": condition["claim_token"],
                    ":client_id": condition["client_id"],
                    ":secret_reference": condition["secret_reference"],
                    ":grant_version": "1",
                    ":completed_at": utc_timestamp(completed_at),
                    ":customer_id": self.customer_id,
                    ":deployment_id": self.deployment_id,
                    ":workload_id": condition.get("workload_id"),
                    ":environment": condition.get("environment"),
                    ":actions": list(actions),
                },
            )
        except Exception as error:
            if _is_error(error, _CONDITIONAL_FAILURE):
                return False
            raise
        return True

    def release(self, **condition: Any) -> None:
        idempotency_key = condition.get("idempotency_key")
        claim_token = condition.get("claim_token")
        if not isinstance(idempotency_key, str) or not is_non_empty_string(claim_token):
            raise AdapterContractError()
        try:
            self.table.update_item(
                Key=self._key(idempotency_key),
                UpdateExpression="SET #status = :reconciliation REMOVE claim_token",
                ConditionExpression=(
                    "#status = :provisioning AND claim_token = :claim_token"
                ),
                ExpressionAttributeNames={"#status": "status"},
                ExpressionAttributeValues={
                    ":provisioning": "provisioning",
                    ":reconciliation": "reconciliation_required",
                    ":claim_token": claim_token,
                },
            )
        except Exception as error:
            if _is_error(error, _CONDITIONAL_FAILURE):
                return
            raise


class CognitoSecretsM2MClientProvider:
    """Create/recover one exact Cognito client and escrow its secret directly.

    The generated value never crosses this adapter boundary. Recovery uses a
    deterministic client name plus List/Describe and a deterministic Secrets
    Manager version token; it never reads a secret value or updates a Cognito
    client in place.
    """

    def __init__(
        self,
        cognito_client: Any,
        secrets_client: Any,
        *,
        user_pool_id: str,
        customer_id: str,
        deployment_id: str,
        secret_name_prefix: str,
        kms_key_id: str,
        allowed_scopes: Sequence[str],
    ) -> None:
        self.cognito = cognito_client
        self.secrets = secrets_client
        self.user_pool_id = user_pool_id
        self.customer_id = customer_id
        self.deployment_id = deployment_id
        self.secret_name_prefix = secret_name_prefix
        self.kms_key_id = kms_key_id
        self.allowed_scopes = frozenset(allowed_scopes)

    def ensure_client(self, **request: Any) -> Mapping[str, Any]:
        workload_id = request.get("workload_id")
        environment = request.get("environment")
        customer_id = request.get("customer_id")
        deployment_id = request.get("deployment_id")
        idempotency_key = request.get("idempotency_key")
        scopes = _string_sequence(request.get("scopes"))
        if not (
            isinstance(workload_id, str)
            and WORKLOAD_PATTERN.fullmatch(workload_id)
            and isinstance(environment, str)
            and ENVIRONMENT_PATTERN.fullmatch(environment)
            and customer_id == self.customer_id
            and deployment_id == self.deployment_id
            and isinstance(idempotency_key, str)
            and IDEMPOTENCY_PATTERN.fullmatch(idempotency_key)
            and scopes
            and frozenset(scopes).issubset(self.allowed_scopes)
        ):
            raise AdapterContractError()

        token = hashlib.sha256(idempotency_key.encode("utf-8")).hexdigest()
        scope_digest = hashlib.sha256(
            json.dumps(sorted(scopes), separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        binding_digest = hashlib.sha256(
            "\x1f".join(
                (
                    self.customer_id,
                    self.deployment_id,
                    environment,
                    workload_id,
                    idempotency_key,
                    *sorted(scopes),
                )
            ).encode("utf-8")
        ).hexdigest()
        client_name = (
            f"scanalyze-{self.deployment_id[4:12].lower()}-"
            f"{workload_id[:24]}-{binding_digest[:24]}"
        )
        secret_name = f"{self.secret_name_prefix}{binding_digest[:32]}"
        base_tags = {
            "scanalyze:schema": "m2m-credential.v1",
            "scanalyze:customer-id": self.customer_id,
            "scanalyze:deployment-id": self.deployment_id,
            "scanalyze:environment": environment,
            "scanalyze:workload-id": workload_id,
            "scanalyze:idempotency-digest": token,
            "scanalyze:binding-digest": binding_digest,
            "scanalyze:scope-digest": scope_digest,
        }

        description = self._describe_secret(secret_name)
        if description is not None:
            client_id = self._validate_secret_metadata(
                description,
                base_tags,
                token,
                secret_name,
            )
            client = self._describe_exact_client(client_name, client_id, scopes)
            if self._has_current_version(description, token):
                return {
                    "client_id": client_id,
                    "secret_reference": self._secret_reference(description, secret_name),
                }
            raw_secret = client.get("ClientSecret")
            if not is_non_empty_string(raw_secret):
                raise AdapterContractError()
            try:
                reference = self._put_secret_version(
                    secret_name,
                    str(raw_secret),
                    token,
                    base_tags,
                    client_id,
                )
            finally:
                raw_secret = None
            return {"client_id": client_id, "secret_reference": reference}

        client, created_now = self._ensure_exact_client(client_name, scopes)
        client_id = client.get("ClientId")
        raw_secret = client.get("ClientSecret")
        if not is_non_empty_string(client_id) or not is_non_empty_string(raw_secret):
            raise AdapterContractError()
        try:
            reference = self._create_secret(
                secret_name,
                str(raw_secret),
                token,
                base_tags,
                str(client_id),
            )
        except Exception:
            if created_now:
                try:
                    self.cognito.delete_user_pool_client(
                        UserPoolId=self.user_pool_id,
                        ClientId=client_id,
                    )
                except Exception:
                    pass
            raise AdapterContractError() from None
        finally:
            raw_secret = None
        return {"client_id": str(client_id), "secret_reference": reference}

    def _describe_secret(self, secret_name: str) -> Mapping[str, Any] | None:
        try:
            response = self.secrets.describe_secret(SecretId=secret_name)
        except Exception as error:
            if _is_error(error, _NOT_FOUND):
                return None
            raise
        if not isinstance(response, Mapping):
            raise AdapterContractError()
        return response

    @staticmethod
    def _secret_reference(description: Mapping[str, Any], secret_name: str) -> str:
        arn = description.get("ARN")
        return str(arn) if is_non_empty_string(arn) else secret_name

    @staticmethod
    def _has_current_version(description: Mapping[str, Any], token: str) -> bool:
        versions = description.get("VersionIdsToStages")
        if not isinstance(versions, Mapping):
            return False
        stages = versions.get(token)
        return (
            isinstance(stages, Sequence)
            and not isinstance(stages, (str, bytes))
            and "AWSCURRENT" in stages
        )

    def _validate_secret_metadata(
        self,
        description: Mapping[str, Any],
        base_tags: Mapping[str, str],
        token: str,
        secret_name: str,
    ) -> str:
        kms_parts = self.kms_key_id.split(":", 5)
        if (
            len(kms_parts) != 6
            or kms_parts[0] != "arn"
            or kms_parts[2] != "kms"
            or description.get("Name") != secret_name
            or description.get("KmsKeyId") != self.kms_key_id
            or description.get("DeletedDate") is not None
        ):
            raise AdapterContractError()
        arn = description.get("ARN")
        expected_arn_prefix = (
            f"arn:{kms_parts[1]}:secretsmanager:{kms_parts[3]}:"
            f"{kms_parts[4]}:secret:{secret_name}-"
        )
        if not (
            isinstance(arn, str)
            and arn.startswith(expected_arn_prefix)
            and len(arn.removeprefix(expected_arn_prefix)) == 6
            and arn.removeprefix(expected_arn_prefix).isalnum()
        ):
            raise AdapterContractError()
        raw_tags = description.get("Tags")
        if not isinstance(raw_tags, Sequence) or isinstance(raw_tags, (str, bytes)):
            raise AdapterContractError()
        tags: dict[str, str] = {}
        for item in raw_tags:
            if not isinstance(item, Mapping):
                raise AdapterContractError()
            key, value = item.get("Key"), item.get("Value")
            if not isinstance(key, str) or not isinstance(value, str) or key in tags:
                raise AdapterContractError()
            tags[key] = value
        if any(tags.get(key) != value for key, value in base_tags.items()):
            raise AdapterContractError()
        if tags.get("scanalyze:idempotency-digest") != token:
            raise AdapterContractError()
        client_id = tags.get("scanalyze:cognito-client-id")
        if not is_non_empty_string(client_id):
            raise AdapterContractError()
        return str(client_id)

    def _list_matching_clients(self, client_name: str) -> list[Mapping[str, Any]]:
        matches: list[Mapping[str, Any]] = []
        next_token: str | None = None
        while True:
            request: dict[str, Any] = {
                "UserPoolId": self.user_pool_id,
                "MaxResults": 60,
            }
            if next_token is not None:
                request["NextToken"] = next_token
            response = self.cognito.list_user_pool_clients(**request)
            if not isinstance(response, Mapping):
                raise AdapterContractError()
            clients = response.get("UserPoolClients", [])
            if not isinstance(clients, Sequence) or isinstance(clients, (str, bytes)):
                raise AdapterContractError()
            for client in clients:
                if not isinstance(client, Mapping):
                    raise AdapterContractError()
                if client.get("ClientName") == client_name:
                    matches.append(client)
            raw_next = response.get("NextToken")
            if raw_next is None:
                break
            if not is_non_empty_string(raw_next):
                raise AdapterContractError()
            next_token = str(raw_next)
        return matches

    def _describe_exact_client(
        self,
        client_name: str,
        expected_client_id: str,
        scopes: Sequence[str],
    ) -> Mapping[str, Any]:
        matches = self._list_matching_clients(client_name)
        if len(matches) != 1 or matches[0].get("ClientId") != expected_client_id:
            raise AdapterContractError()
        response = self.cognito.describe_user_pool_client(
            UserPoolId=self.user_pool_id,
            ClientId=expected_client_id,
        )
        client = response.get("UserPoolClient") if isinstance(response, Mapping) else None
        if not isinstance(client, Mapping):
            raise AdapterContractError()
        self._validate_client(client, client_name, scopes)
        return client

    def _ensure_exact_client(
        self,
        client_name: str,
        scopes: Sequence[str],
    ) -> tuple[Mapping[str, Any], bool]:
        matches = self._list_matching_clients(client_name)
        if len(matches) > 1:
            raise AdapterContractError()
        if len(matches) == 1:
            client_id = matches[0].get("ClientId")
            if not is_non_empty_string(client_id):
                raise AdapterContractError()
            return self._describe_exact_client(client_name, str(client_id), scopes), False

        request = {
            "UserPoolId": self.user_pool_id,
            "ClientName": client_name,
            "GenerateSecret": True,
            "ExplicitAuthFlows": ["ALLOW_REFRESH_TOKEN_AUTH"],
            "SupportedIdentityProviders": ["COGNITO"],
            "AllowedOAuthFlows": ["client_credentials"],
            "AllowedOAuthScopes": list(scopes),
            "AllowedOAuthFlowsUserPoolClient": True,
            "AccessTokenValidity": 15,
            "IdTokenValidity": 5,
            "RefreshTokenValidity": 1,
            "TokenValidityUnits": {
                "AccessToken": "minutes",
                "IdToken": "minutes",
                "RefreshToken": "days",
            },
            "EnableTokenRevocation": True,
            "PreventUserExistenceErrors": "ENABLED",
        }
        try:
            response = self.cognito.create_user_pool_client(**request)
            client = response.get("UserPoolClient") if isinstance(response, Mapping) else None
            if not isinstance(client, Mapping):
                raise AdapterContractError()
            self._validate_client(client, client_name, scopes)
            return client, True
        except Exception:
            # CreateUserPoolClient has no idempotency token. Re-listing and
            # describing the deterministic exact name is the only safe local
            # recovery after an ambiguous response.
            recovered = self._list_matching_clients(client_name)
            if len(recovered) != 1 or not is_non_empty_string(
                recovered[0].get("ClientId")
            ):
                raise AdapterContractError() from None
            client = self._describe_exact_client(
                client_name,
                str(recovered[0]["ClientId"]),
                scopes,
            )
            return client, False

    @staticmethod
    def _validate_client(
        client: Mapping[str, Any],
        client_name: str,
        scopes: Sequence[str],
    ) -> None:
        actual_scopes = _string_sequence(client.get("AllowedOAuthScopes"))
        actual_flows = _string_sequence(client.get("AllowedOAuthFlows"))
        explicit_flows = _string_sequence(client.get("ExplicitAuthFlows"))
        providers = _string_sequence(client.get("SupportedIdentityProviders"))
        units = client.get("TokenValidityUnits")
        if not (
            client.get("ClientName") == client_name
            and is_non_empty_string(client.get("ClientId"))
            and actual_scopes is not None
            and frozenset(actual_scopes) == frozenset(scopes)
            and actual_flows == ("client_credentials",)
            and explicit_flows == ("ALLOW_REFRESH_TOKEN_AUTH",)
            and providers == ("COGNITO",)
            and client.get("AllowedOAuthFlowsUserPoolClient") is True
            and client.get("AccessTokenValidity") == 15
            and client.get("IdTokenValidity") == 5
            and client.get("RefreshTokenValidity") == 1
            and isinstance(units, Mapping)
            and units.get("AccessToken") == "minutes"
            and units.get("IdToken") == "minutes"
            and units.get("RefreshToken") == "days"
            and client.get("EnableTokenRevocation") is True
            and client.get("PreventUserExistenceErrors") == "ENABLED"
        ):
            raise AdapterContractError()

    @staticmethod
    def _tag_list(base_tags: Mapping[str, str], client_id: str) -> list[dict[str, str]]:
        tags = {**base_tags, "scanalyze:cognito-client-id": client_id}
        return [{"Key": key, "Value": tags[key]} for key in sorted(tags)]

    def _create_secret(
        self,
        secret_name: str,
        raw_secret: str,
        token: str,
        base_tags: Mapping[str, str],
        client_id: str,
    ) -> str:
        try:
            response = self.secrets.create_secret(
                Name=secret_name,
                Description="Scanalyze M2M credential escrow",
                KmsKeyId=self.kms_key_id,
                SecretString=raw_secret,
                ClientRequestToken=token,
                Tags=self._tag_list(base_tags, client_id),
            )
        except Exception:
            description = self._describe_secret(secret_name)
            if description is None:
                raise AdapterContractError() from None
            recovered_id = self._validate_secret_metadata(
                description,
                base_tags,
                token,
                secret_name,
            )
            if recovered_id != client_id or not self._has_current_version(
                description, token
            ):
                raise AdapterContractError() from None
            return self._secret_reference(description, secret_name)
        if not isinstance(response, Mapping) or response.get("VersionId") != token:
            raise AdapterContractError()
        description = self._describe_secret(secret_name)
        if description is None:
            raise AdapterContractError()
        recovered_id = self._validate_secret_metadata(
            description,
            base_tags,
            token,
            secret_name,
        )
        if recovered_id != client_id or not self._has_current_version(
            description,
            token,
        ):
            raise AdapterContractError()
        return self._secret_reference(description, secret_name)

    def _put_secret_version(
        self,
        secret_name: str,
        raw_secret: str,
        token: str,
        base_tags: Mapping[str, str],
        client_id: str,
    ) -> str:
        try:
            response = self.secrets.put_secret_value(
                SecretId=secret_name,
                SecretString=raw_secret,
                ClientRequestToken=token,
                VersionStages=["AWSCURRENT"],
            )
        except Exception:
            description = self._describe_secret(secret_name)
            if description is None:
                raise AdapterContractError() from None
            recovered_id = self._validate_secret_metadata(
                description,
                base_tags,
                token,
                secret_name,
            )
            if recovered_id != client_id or not self._has_current_version(
                description, token
            ):
                raise AdapterContractError() from None
            return self._secret_reference(description, secret_name)
        if not isinstance(response, Mapping) or response.get("VersionId") != token:
            raise AdapterContractError()
        description = self._describe_secret(secret_name)
        if description is None:
            raise AdapterContractError()
        recovered_id = self._validate_secret_metadata(
            description,
            base_tags,
            token,
            secret_name,
        )
        if recovered_id != client_id or not self._has_current_version(
            description,
            token,
        ):
            raise AdapterContractError()
        return self._secret_reference(description, secret_name)
