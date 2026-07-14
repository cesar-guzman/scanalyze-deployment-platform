"""Reviewed AWS adapters for the provider-neutral GUG-94 lifecycle ports.

These adapters are inert until explicitly composed and installed in
``app.state.enterprise_lifecycle_runtime`` by trusted deployment code.  They do
not read request identity, use table scans, infer ownership, or log provider
payloads.  Every key is derived from the configured customer/deployment tuple.
"""
from __future__ import annotations

import base64
import hashlib
import json
import re
from dataclasses import replace
from datetime import datetime, timezone
from typing import Any, Mapping, Sequence

from boto3.dynamodb.types import TypeSerializer

from .enterprise_authorization import HumanRole
from .user_lifecycle import (
    ApprovalEvidence,
    EnterpriseLifecycleRuntime,
    IdempotencyConflict,
    LIFECYCLE_APPROVAL_SCHEMA_VERSION,
    LIFECYCLE_AUDIT_EVENT_SCHEMA_VERSION,
    LIFECYCLE_AUDIT_RECEIPT_SCHEMA_VERSION,
    LIFECYCLE_OPERATION_SCHEMA_VERSION,
    LifecycleAuditEvent,
    LifecycleAuditPage,
    LifecycleAuditReceipt,
    LifecycleCommand,
    LifecycleOperation,
    LifecycleOperationRecord,
    LifecycleOperationStage,
    MembershipPage,
    MembershipRecord,
    MembershipState,
    ProviderUserReceipt,
)


MEMBERSHIP_REFERENCE_INDEX = "ownership-membership-reference-v1"
MEMBERSHIP_STATE_INDEX = "ownership-state-v1"
_CONDITIONAL_FAILURE = "ConditionalCheckFailedException"
_TRANSACTION_FAILURE = "TransactionCanceledException"
_USERNAME_EXISTS = "UsernameExistsException"
_SUBJECT_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@-]{0,255}$")
_REFERENCE_PATTERN = re.compile(r"^ref_[0-9a-f]{24,64}$")
_MEMBERSHIP_REFERENCE_PATTERN = re.compile(r"^mbr_[0-9a-f]{32,64}$")
_APPROVAL_REFERENCE_PATTERN = re.compile(r"^apr_[A-Za-z0-9][A-Za-z0-9_-]{15,63}$")
_IDEMPOTENCY_PATTERN = re.compile(r"^idem_[A-Za-z0-9][A-Za-z0-9_-]{15,63}$")
_OPERATION_EVIDENCE_FIELDS = frozenset(
    {
        "approval_reference",
        "target_reference",
        "role_id",
        "expires_at",
        "subject",
        "provider_user_reference",
        "provider_principal_key",
        "principal_locator_digest",
        "membership_reference",
        "before_membership_version",
        "after_membership_version",
        "reason_code",
        "expected_state",
        "desired_state",
        "before_role_id",
        "after_role_id",
        "effect_order",
        "admin_replacement_reference",
        "admin_replacement_version",
        "session_revocation_reference",
        "audit_receipt_reference",
    }
)
_AUDITED_OPERATION_STAGES = frozenset(
    {
        LifecycleOperationStage.AUDIT_COMMITTED,
        LifecycleOperationStage.COMPLETED,
    }
)


class LifecycleAdapterContractError(RuntimeError):
    def __init__(self) -> None:
        super().__init__("lifecycle adapter contract rejected")


def _error_code(error: BaseException) -> str | None:
    response = getattr(error, "response", None)
    details = response.get("Error") if isinstance(response, Mapping) else None
    code = details.get("Code") if isinstance(details, Mapping) else None
    return code if isinstance(code, str) else None


def _owner_prefix(customer_id: str, deployment_id: str) -> str:
    return f"{deployment_id}#{customer_id}"


def _membership_pk(customer_id: str, deployment_id: str) -> str:
    return f"MEMBERSHIP#{_owner_prefix(customer_id, deployment_id)}"


def _operation_pk(customer_id: str, deployment_id: str) -> str:
    return f"LIFECYCLE#{_owner_prefix(customer_id, deployment_id)}"


def _approval_pk(customer_id: str, deployment_id: str) -> str:
    return f"APPROVAL#{_owner_prefix(customer_id, deployment_id)}"


def _audit_pk(customer_id: str, deployment_id: str) -> str:
    return f"AUDIT#{_owner_prefix(customer_id, deployment_id)}"


def _membership_binding(
    customer_id: str,
    deployment_id: str,
    membership_reference: str,
) -> str:
    return (
        f"{_owner_prefix(customer_id, deployment_id)}"
        f"#MEMBERSHIP#{membership_reference}"
    )


def _state_binding(
    customer_id: str,
    deployment_id: str,
    state: MembershipState,
) -> str:
    return f"{_owner_prefix(customer_id, deployment_id)}#STATE#{state.value}"


def _timestamp(value: datetime) -> str:
    if value.tzinfo is None:
        raise LifecycleAdapterContractError()
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _parse_timestamp(value: object) -> datetime:
    if not isinstance(value, str):
        raise LifecycleAdapterContractError()
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise LifecycleAdapterContractError() from error
    if result.tzinfo is None:
        raise LifecycleAdapterContractError()
    return result.astimezone(timezone.utc)


def _reference(*parts: object) -> str:
    material = "\x1f".join(str(part) for part in parts)
    return "ref_" + hashlib.sha256(material.encode("utf-8")).hexdigest()[:32]


def _membership_reference(customer_id: str, deployment_id: str, subject: str) -> str:
    material = "\x1f".join((customer_id, deployment_id, subject))
    return "mbr_" + hashlib.sha256(material.encode("utf-8")).hexdigest()[:32]


def _integer(value: object) -> int:
    try:
        result = int(value)  # DynamoDB resource may return Decimal.
    except (TypeError, ValueError, OverflowError) as error:
        raise LifecycleAdapterContractError() from error
    if isinstance(value, bool) or result < 1 or str(result) != str(value):
        raise LifecycleAdapterContractError()
    return result


def _cursor_encode(key: Mapping[str, Any]) -> str:
    material = json.dumps(dict(key), sort_keys=True, separators=(",", ":"))
    encoded = base64.urlsafe_b64encode(material.encode("utf-8")).decode("ascii").rstrip("=")
    return "cur_" + encoded


def _cursor_decode(
    cursor: str,
    *,
    expected_pk: str,
    expected_sk_prefix: str,
) -> dict[str, str]:
    if not isinstance(cursor, str) or not cursor.startswith("cur_"):
        raise LifecycleAdapterContractError()
    value = cursor[4:]
    try:
        decoded = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
        key = json.loads(decoded.decode("utf-8"))
    except Exception as error:
        raise LifecycleAdapterContractError() from error
    if not (
        isinstance(key, Mapping)
        and set(key) == {"pk", "sk"}
        and key.get("pk") == expected_pk
        and isinstance(key.get("sk"), str)
        and str(key["sk"]).startswith(expected_sk_prefix)
    ):
        raise LifecycleAdapterContractError()
    return {"pk": expected_pk, "sk": str(key["sk"])}


def _state_cursor_decode(
    cursor: str,
    *,
    expected_pk: str,
    expected_state_binding: str,
) -> dict[str, str]:
    if not isinstance(cursor, str) or not cursor.startswith("cur_"):
        raise LifecycleAdapterContractError()
    value = cursor[4:]
    try:
        decoded = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
        key = json.loads(decoded.decode("utf-8"))
    except Exception as error:
        raise LifecycleAdapterContractError() from error
    if not (
        isinstance(key, Mapping)
        and set(key)
        == {"pk", "sk", "ownership_state_key", "membership_reference"}
        and key.get("pk") == expected_pk
        and isinstance(key.get("sk"), str)
        and str(key["sk"]).startswith("SUBJECT#")
        and key.get("ownership_state_key") == expected_state_binding
        and isinstance(key.get("membership_reference"), str)
        and _MEMBERSHIP_REFERENCE_PATTERN.fullmatch(
            str(key["membership_reference"])
        )
    ):
        raise LifecycleAdapterContractError()
    return {str(name): str(item) for name, item in key.items()}


def _serialize_map(values: Mapping[str, Any]) -> dict[str, Any]:
    serializer = TypeSerializer()
    return {name: serializer.serialize(value) for name, value in values.items()}


def _validated_operation_evidence(
    values: object,
    *,
    stage: LifecycleOperationStage,
) -> dict[str, str]:
    if not isinstance(values, Mapping):
        raise LifecycleAdapterContractError()
    evidence = dict(values)
    if (
        not set(evidence).issubset(_OPERATION_EVIDENCE_FIELDS)
        or any(
            not isinstance(value, str) or not value or len(value) > 512
            for value in evidence.values()
        )
        or (
            stage in _AUDITED_OPERATION_STAGES
            and "audit_receipt_reference" not in evidence
        )
    ):
        raise LifecycleAdapterContractError()
    return evidence


class DynamoLifecycleStore:
    """Conditional operation ledger plus ownership-bound membership repository."""

    def __init__(self, table: Any) -> None:
        self.table = table

    def reserve_operation(self, command: LifecycleCommand) -> LifecycleOperationRecord:
        now = datetime.now(timezone.utc)
        record = LifecycleOperationRecord.new(command, now=now)
        item = self._operation_item(record)
        try:
            self.table.put_item(
                Item=item,
                ConditionExpression="attribute_not_exists(pk) AND attribute_not_exists(sk)",
            )
            return record
        except Exception as error:
            if _error_code(error) != _CONDITIONAL_FAILURE:
                raise
        existing = self._load_operation(command)
        if not (
            existing.operation is command.operation
            and existing.actor_subject == command.actor_subject
            and existing.idempotency_key == command.idempotency_key
            and existing.request_digest == command.request_digest
        ):
            raise IdempotencyConflict()
        return existing

    def checkpoint_operation(
        self,
        record: LifecycleOperationRecord,
        *,
        expected_stage: LifecycleOperationStage,
        next_stage: LifecycleOperationStage,
        evidence: dict[str, str] | None = None,
    ) -> LifecycleOperationRecord:
        merged = {**record.evidence, **(evidence or {})}
        merged = _validated_operation_evidence(merged, stage=next_stage)
        now = datetime.now(timezone.utc)
        key = {
            "pk": _operation_pk(record.customer_id, record.deployment_id),
            "sk": f"IDEMPOTENCY#{record.idempotency_key}",
        }
        try:
            self.table.update_item(
                Key=key,
                UpdateExpression="SET #stage = :next_stage, evidence = :evidence, updated_at = :updated_at",
                ConditionExpression=(
                    "#stage = :expected_stage AND operation_reference = :operation_reference "
                    "AND request_digest = :request_digest AND actor_subject = :actor_subject"
                ),
                ExpressionAttributeNames={"#stage": "stage"},
                ExpressionAttributeValues={
                    ":expected_stage": expected_stage.value,
                    ":next_stage": next_stage.value,
                    ":operation_reference": record.operation_reference,
                    ":request_digest": record.request_digest,
                    ":actor_subject": record.actor_subject,
                    ":evidence": merged,
                    ":updated_at": _timestamp(now),
                },
            )
            return replace(record, stage=next_stage, evidence=merged, updated_at=now)
        except Exception as error:
            if _error_code(error) != _CONDITIONAL_FAILURE:
                raise
        current = self._load_operation(
            LifecycleCommand(
                operation=record.operation,
                customer_id=record.customer_id,
                deployment_id=record.deployment_id,
                actor_subject=record.actor_subject,
                idempotency_key=record.idempotency_key,
                request_digest=record.request_digest,
            )
        )
        if current.stage is next_stage and all(current.evidence.get(k) == v for k, v in merged.items()):
            return current
        raise IdempotencyConflict()

    def list_memberships(
        self,
        *,
        customer_id: str,
        deployment_id: str,
        state: MembershipState | None,
        cursor: str | None,
        limit: int,
    ) -> MembershipPage:
        pk = _membership_pk(customer_id, deployment_id)
        request: dict[str, Any] = {
            "KeyConditionExpression": "#pk = :pk AND begins_with(#sk, :subject_prefix)",
            "ExpressionAttributeNames": {"#pk": "pk", "#sk": "sk"},
            "ExpressionAttributeValues": {":pk": pk, ":subject_prefix": "SUBJECT#"},
            "Limit": limit,
            "ConsistentRead": True,
        }
        if state is not None:
            state_key = _state_binding(customer_id, deployment_id, state)
            request = {
                "IndexName": MEMBERSHIP_STATE_INDEX,
                "KeyConditionExpression": (
                    "#state_key = :state_key AND begins_with(#membership_reference, :reference_prefix)"
                ),
                "ExpressionAttributeNames": {"#state_key": "ownership_state_key"},
                "ExpressionAttributeValues": {
                    ":state_key": state_key,
                    ":reference_prefix": "mbr_",
                },
                "Limit": limit,
            }
        if cursor is not None:
            request["ExclusiveStartKey"] = (
                _state_cursor_decode(
                    cursor,
                    expected_pk=pk,
                    expected_state_binding=state_key,
                )
                if state is not None
                else _cursor_decode(
                    cursor,
                    expected_pk=pk,
                    expected_sk_prefix="SUBJECT#",
                )
            )
        response = self.table.query(**request)
        items = response.get("Items") if isinstance(response, Mapping) else None
        if not isinstance(items, Sequence) or isinstance(items, (str, bytes)):
            raise LifecycleAdapterContractError()
        records = tuple(self._membership_from_item(item) for item in items)
        for record in records:
            if (
                record.customer_id != customer_id
                or record.deployment_id != deployment_id
                or (state is not None and record.state is not state)
            ):
                raise LifecycleAdapterContractError()
        last_key = response.get("LastEvaluatedKey")
        next_cursor = None
        if last_key is not None:
            if not isinstance(last_key, Mapping):
                raise LifecycleAdapterContractError()
            encoded = _cursor_encode(last_key)
            validated = (
                _state_cursor_decode(
                    encoded,
                    expected_pk=pk,
                    expected_state_binding=state_key,
                )
                if state is not None
                else _cursor_decode(
                    encoded,
                    expected_pk=pk,
                    expected_sk_prefix="SUBJECT#",
                )
            )
            next_cursor = _cursor_encode(validated)
        return MembershipPage(records, next_cursor)

    def load_membership(
        self,
        *,
        customer_id: str,
        deployment_id: str,
        membership_reference: str,
    ) -> MembershipRecord | None:
        binding = _membership_binding(customer_id, deployment_id, membership_reference)
        response = self.table.query(
            IndexName=MEMBERSHIP_REFERENCE_INDEX,
            KeyConditionExpression="#binding = :binding",
            ExpressionAttributeNames={"#binding": "ownership_membership_key"},
            ExpressionAttributeValues={":binding": binding},
            Limit=2,
        )
        items = response.get("Items") if isinstance(response, Mapping) else None
        if not isinstance(items, Sequence) or isinstance(items, (str, bytes)):
            raise LifecycleAdapterContractError()
        if not items:
            return None
        if len(items) != 1 or response.get("LastEvaluatedKey") is not None:
            raise LifecycleAdapterContractError()
        candidate = self._membership_from_item(items[0])
        primary = self.table.get_item(
            Key={
                "pk": _membership_pk(customer_id, deployment_id),
                "sk": f"SUBJECT#{candidate.subject}",
            },
            ConsistentRead=True,
        )
        item = primary.get("Item") if isinstance(primary, Mapping) else None
        if item is None:
            return None
        result = self._membership_from_item(item)
        if (
            result.customer_id != customer_id
            or result.deployment_id != deployment_id
            or result.membership_reference != membership_reference
        ):
            raise LifecycleAdapterContractError()
        return result

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
        now = datetime.now(timezone.utc)
        reference = _membership_reference(customer_id, deployment_id, provider_receipt.subject)
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
            created_at=now,
            updated_at=now,
            invitation_expires_at=expires_at,
        )
        item = self._membership_item(record)
        item["last_operation_reference"] = operation_reference
        try:
            self.table.put_item(
                Item=item,
                ConditionExpression="attribute_not_exists(pk) AND attribute_not_exists(sk)",
            )
            return record
        except Exception as error:
            if _error_code(error) != _CONDITIONAL_FAILURE:
                raise
        response = self.table.get_item(
            Key={"pk": item["pk"], "sk": item["sk"]}, ConsistentRead=True
        )
        existing = response.get("Item") if isinstance(response, Mapping) else None
        if not isinstance(existing, Mapping) or existing.get("last_operation_reference") != operation_reference:
            raise IdempotencyConflict()
        current = self._membership_from_item(existing)
        if not (
            current.customer_id == record.customer_id
            and current.deployment_id == record.deployment_id
            and current.membership_reference == record.membership_reference
            and current.subject == record.subject
            and current.state is MembershipState.INVITED
            and current.role_id is record.role_id
            and current.membership_version == 1
            and current.provider_user_reference == record.provider_user_reference
            and current.provider_principal_key == record.provider_principal_key
            and current.invitation_expires_at == record.invitation_expires_at
        ):
            raise IdempotencyConflict()
        return current

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
        now = datetime.now(timezone.utc)
        next_version = expected_version + 1
        key = {
            "pk": _membership_pk(current.customer_id, current.deployment_id),
            "sk": f"SUBJECT#{current.subject}",
        }
        update_expression = (
                    "SET #state = :next_state, role_id = :next_role, "
                    "membership_version = :next_version, updated_at = :updated_at, "
                    "ownership_state_key = :state_key, "
                    "last_operation_reference = :operation_reference "
                    "REMOVE invitation_expires_at"
                )
        condition_expression = (
                    "customer_id = :customer_id AND deployment_id = :deployment_id "
                    "AND membership_reference = :membership_reference "
                    "AND #state = :expected_state AND membership_version = :expected_version"
                )
        expression_names = {"#state": "state"}
        expression_values = {
                    ":customer_id": current.customer_id,
                    ":deployment_id": current.deployment_id,
                    ":membership_reference": current.membership_reference,
                    ":expected_state": expected_state.value,
                    ":expected_version": expected_version,
                    ":next_state": next_state.value,
                    ":next_role": next_role.value,
                    ":next_version": next_version,
                    ":updated_at": _timestamp(now),
                    ":state_key": _state_binding(
                        current.customer_id,
                        current.deployment_id,
                        next_state,
                    ),
                    ":operation_reference": operation_reference,
                }
        removes_active_admin = (
            current.state is MembershipState.ACTIVE
            and current.role_id is HumanRole.CUSTOMER_ADMIN
            and (
                next_state is not MembershipState.ACTIVE
                or next_role is not HumanRole.CUSTOMER_ADMIN
            )
        )
        if removes_active_admin and admin_replacement is None:
            raise LifecycleAdapterContractError()
        try:
            if admin_replacement is not None:
                if not (
                    admin_replacement.customer_id == current.customer_id
                    and admin_replacement.deployment_id == current.deployment_id
                    and admin_replacement.membership_reference
                    != current.membership_reference
                    and admin_replacement.state is MembershipState.ACTIVE
                    and admin_replacement.role_id is HumanRole.CUSTOMER_ADMIN
                ):
                    raise LifecycleAdapterContractError()
                table_name = getattr(self.table, "name", None)
                client = getattr(getattr(self.table, "meta", None), "client", None)
                if not isinstance(table_name, str) or client is None:
                    raise LifecycleAdapterContractError()
                replacement_key = {
                    "pk": _membership_pk(
                        admin_replacement.customer_id,
                        admin_replacement.deployment_id,
                    ),
                    "sk": f"SUBJECT#{admin_replacement.subject}",
                }
                client.transact_write_items(
                    TransactItems=[
                        {
                            "ConditionCheck": {
                                "TableName": table_name,
                                "Key": _serialize_map(replacement_key),
                                "ConditionExpression": (
                                    "customer_id = :customer_id AND deployment_id = :deployment_id "
                                    "AND membership_reference = :replacement_reference "
                                    "AND #state = :active AND role_id = :admin_role "
                                    "AND membership_version = :replacement_version"
                                ),
                                "ExpressionAttributeNames": {"#state": "state"},
                                "ExpressionAttributeValues": _serialize_map(
                                    {
                                        ":customer_id": current.customer_id,
                                        ":deployment_id": current.deployment_id,
                                        ":replacement_reference": admin_replacement.membership_reference,
                                        ":active": MembershipState.ACTIVE.value,
                                        ":admin_role": HumanRole.CUSTOMER_ADMIN.value,
                                        ":replacement_version": admin_replacement.membership_version,
                                    }
                                ),
                            }
                        },
                        {
                            "Update": {
                                "TableName": table_name,
                                "Key": _serialize_map(key),
                                "UpdateExpression": update_expression,
                                "ConditionExpression": condition_expression,
                                "ExpressionAttributeNames": expression_names,
                                "ExpressionAttributeValues": _serialize_map(
                                    expression_values
                                ),
                            }
                        },
                    ],
                    ClientRequestToken=operation_reference,
                )
            else:
                self.table.update_item(
                    Key=key,
                    UpdateExpression=update_expression,
                    ConditionExpression=condition_expression,
                    ExpressionAttributeNames=expression_names,
                    ExpressionAttributeValues=expression_values,
                )
            return replace(
                current,
                state=next_state,
                role_id=next_role,
                membership_version=next_version,
                updated_at=now,
                invitation_expires_at=None,
            )
        except Exception as error:
            if _error_code(error) not in {
                _CONDITIONAL_FAILURE,
                _TRANSACTION_FAILURE,
            }:
                raise
        response = self.table.get_item(Key=key, ConsistentRead=True)
        item = response.get("Item") if isinstance(response, Mapping) else None
        if not isinstance(item, Mapping) or item.get("last_operation_reference") != operation_reference:
            raise IdempotencyConflict()
        result = self._membership_from_item(item)
        if not (
            result.state is next_state
            and result.role_id is next_role
            and result.membership_version == next_version
        ):
            raise IdempotencyConflict()
        return result

    def _load_operation(self, command: LifecycleCommand) -> LifecycleOperationRecord:
        response = self.table.get_item(
            Key={
                "pk": _operation_pk(command.customer_id, command.deployment_id),
                "sk": f"IDEMPOTENCY#{command.idempotency_key}",
            },
            ConsistentRead=True,
        )
        item = response.get("Item") if isinstance(response, Mapping) else None
        if not isinstance(item, Mapping):
            raise LifecycleAdapterContractError()
        return self._operation_from_item(item)

    @staticmethod
    def _operation_item(record: LifecycleOperationRecord) -> dict[str, Any]:
        evidence = _validated_operation_evidence(
            record.evidence,
            stage=record.stage,
        )
        return {
            "pk": _operation_pk(record.customer_id, record.deployment_id),
            "sk": f"IDEMPOTENCY#{record.idempotency_key}",
            "schema_version": record.schema_version,
            "operation_reference": record.operation_reference,
            "operation": record.operation.value,
            "customer_id": record.customer_id,
            "deployment_id": record.deployment_id,
            "actor_subject": record.actor_subject,
            "idempotency_key": record.idempotency_key,
            "request_digest": record.request_digest,
            "stage": record.stage.value,
            "evidence": evidence,
            "created_at": _timestamp(record.created_at),
            "updated_at": _timestamp(record.updated_at),
        }

    @staticmethod
    def _operation_from_item(item: Mapping[str, Any]) -> LifecycleOperationRecord:
        try:
            stage = LifecycleOperationStage(str(item["stage"]))
            return LifecycleOperationRecord(
                schema_version=str(item["schema_version"]),
                operation_reference=str(item["operation_reference"]),
                operation=LifecycleOperation(str(item["operation"])),
                customer_id=str(item["customer_id"]),
                deployment_id=str(item["deployment_id"]),
                actor_subject=str(item["actor_subject"]),
                idempotency_key=str(item["idempotency_key"]),
                request_digest=str(item["request_digest"]),
                stage=stage,
                evidence=_validated_operation_evidence(
                    item["evidence"],
                    stage=stage,
                ),
                created_at=_parse_timestamp(item["created_at"]),
                updated_at=_parse_timestamp(item["updated_at"]),
            )
        except Exception as error:
            raise LifecycleAdapterContractError() from error

    @staticmethod
    def _membership_item(record: MembershipRecord) -> dict[str, Any]:
        item = {
            "pk": _membership_pk(record.customer_id, record.deployment_id),
            "sk": f"SUBJECT#{record.subject}",
            "schema_version": record.schema_version,
            "membership_reference": record.membership_reference,
            "subject": record.subject,
            "customer_id": record.customer_id,
            "deployment_id": record.deployment_id,
            "state": record.state.value,
            "role_id": record.role_id.value,
            "membership_version": record.membership_version,
            "provider_user_reference": record.provider_user_reference,
            "provider_principal_key": record.provider_principal_key,
            "created_at": _timestamp(record.created_at),
            "updated_at": _timestamp(record.updated_at),
            "ownership_membership_key": _membership_binding(
                record.customer_id,
                record.deployment_id,
                record.membership_reference,
            ),
            "ownership_state_key": _state_binding(
                record.customer_id,
                record.deployment_id,
                record.state,
            ),
        }
        if record.invitation_expires_at is not None:
            item["invitation_expires_at"] = _timestamp(record.invitation_expires_at)
        return item

    @staticmethod
    def _membership_from_item(item: Mapping[str, Any]) -> MembershipRecord:
        try:
            return MembershipRecord(
                schema_version=str(item["schema_version"]),
                membership_reference=str(item["membership_reference"]),
                subject=str(item["subject"]),
                customer_id=str(item["customer_id"]),
                deployment_id=str(item["deployment_id"]),
                state=MembershipState(str(item["state"])),
                role_id=HumanRole(str(item["role_id"])),
                membership_version=_integer(item["membership_version"]),
                provider_user_reference=str(item["provider_user_reference"]),
                provider_principal_key=str(item["provider_principal_key"]),
                created_at=_parse_timestamp(item["created_at"]),
                updated_at=_parse_timestamp(item["updated_at"]),
                invitation_expires_at=(
                    _parse_timestamp(item["invitation_expires_at"])
                    if "invitation_expires_at" in item
                    else None
                ),
            )
        except Exception as error:
            raise LifecycleAdapterContractError() from error


class DynamoLifecycleApprovalResolver:
    def __init__(self, table: Any) -> None:
        self.table = table

    def resolve(self, **request: Any) -> ApprovalEvidence:
        approval_reference = request.get("approval_reference")
        customer_id = request.get("customer_id")
        deployment_id = request.get("deployment_id")
        if not (
            isinstance(approval_reference, str)
            and _APPROVAL_REFERENCE_PATTERN.fullmatch(approval_reference)
            and isinstance(customer_id, str)
            and isinstance(deployment_id, str)
        ):
            raise LifecycleAdapterContractError()
        response = self.table.get_item(
            Key={
                "pk": _approval_pk(customer_id, deployment_id),
                "sk": f"REFERENCE#{approval_reference}",
            },
            ConsistentRead=True,
        )
        item = response.get("Item") if isinstance(response, Mapping) else None
        if not isinstance(item, Mapping):
            raise LifecycleAdapterContractError()
        try:
            return ApprovalEvidence(
                schema_version=str(item["schema_version"]),
                approval_reference=str(item["approval_reference"]),
                approver_subject=str(item["approver_subject"]),
                customer_id=str(item["customer_id"]),
                deployment_id=str(item["deployment_id"]),
                operation=LifecycleOperation(str(item["operation"])),
                target_reference=str(item["target_reference"]),
                request_digest=str(item["request_digest"]),
                state=str(item["state"]),
                expires_at=_parse_timestamp(item["expires_at"]),
            )
        except Exception as error:
            raise LifecycleAdapterContractError() from error


class DynamoLifecycleAudit:
    _EVENT_FIELDS = frozenset(
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
            "approval_references",
            "before_membership_version",
            "after_membership_version",
        }
    )

    def __init__(self, table: Any, *, customer_id: str, deployment_id: str) -> None:
        self.table = table
        self.customer_id = customer_id
        self.deployment_id = deployment_id

    def emit(self, event: dict[str, Any]) -> LifecycleAuditReceipt:
        if (
            set(event) != self._EVENT_FIELDS
            or event.get("event_schema_version")
            != LIFECYCLE_AUDIT_EVENT_SCHEMA_VERSION
            or event.get("customer_reference") != _reference(self.customer_id)
            or event.get("deployment_reference") != _reference(self.deployment_id)
        ):
            raise LifecycleAdapterContractError()
        timestamp = _parse_timestamp(event.get("timestamp"))
        decision_id = event.get("decision_id")
        if not isinstance(decision_id, str) or not _REFERENCE_PATTERN.fullmatch(decision_id):
            raise LifecycleAdapterContractError()
        item = {
            "pk": _audit_pk(self.customer_id, self.deployment_id),
            "sk": f"{_timestamp(timestamp)}#{decision_id}",
            **event,
        }
        try:
            self.table.put_item(
                Item=item,
                ConditionExpression="attribute_not_exists(pk) AND attribute_not_exists(sk)",
            )
        except Exception as error:
            if _error_code(error) != _CONDITIONAL_FAILURE:
                raise
            response = self.table.get_item(
                Key={"pk": item["pk"], "sk": item["sk"]}, ConsistentRead=True
            )
            existing = response.get("Item") if isinstance(response, Mapping) else None
            if not isinstance(existing, Mapping) or dict(existing) != item:
                raise LifecycleAdapterContractError() from error
        acknowledged = datetime.now(timezone.utc)
        return LifecycleAuditReceipt(
            schema_version=LIFECYCLE_AUDIT_RECEIPT_SCHEMA_VERSION,
            decision_id=decision_id,
            receipt_reference=_reference(item["pk"], item["sk"]),
            acknowledged_at=acknowledged,
        )

    def list_events(
        self,
        *,
        customer_id: str,
        deployment_id: str,
        cursor: str | None,
        limit: int,
    ) -> LifecycleAuditPage:
        if customer_id != self.customer_id or deployment_id != self.deployment_id:
            raise LifecycleAdapterContractError()
        pk = _audit_pk(customer_id, deployment_id)
        request: dict[str, Any] = {
            "KeyConditionExpression": "#pk = :pk",
            "ExpressionAttributeNames": {"#pk": "pk"},
            "ExpressionAttributeValues": {":pk": pk},
            "ScanIndexForward": False,
            "Limit": limit,
            "ConsistentRead": True,
        }
        if cursor is not None:
            request["ExclusiveStartKey"] = _cursor_decode(
                cursor, expected_pk=pk, expected_sk_prefix="20"
            )
        response = self.table.query(**request)
        items = response.get("Items") if isinstance(response, Mapping) else None
        if not isinstance(items, Sequence) or isinstance(items, (str, bytes)):
            raise LifecycleAdapterContractError()
        events: list[LifecycleAuditEvent] = []
        for item in items:
            try:
                if (
                    item["pk"] != pk
                    or not isinstance(item["sk"], str)
                    or not item["sk"].startswith("20")
                ):
                    raise LifecycleAdapterContractError()
                events.append(
                    LifecycleAuditEvent(
                        event_reference=_reference(item["pk"], item["sk"]),
                        timestamp=_parse_timestamp(item["timestamp"]),
                        action=LifecycleOperation(str(item["action"])),
                        decision=str(item["decision"]),
                        reason_code=str(item["reason_code"]),
                        principal_reference=str(item["principal_reference"]),
                        correlation_reference=str(item["correlation_reference"]),
                        before_membership_version=str(item["before_membership_version"]),
                        after_membership_version=str(item["after_membership_version"]),
                    )
                )
            except Exception as error:
                raise LifecycleAdapterContractError() from error
        last_key = response.get("LastEvaluatedKey")
        next_cursor = None
        if last_key is not None:
            if not isinstance(last_key, Mapping):
                raise LifecycleAdapterContractError()
            validated = _cursor_decode(
                _cursor_encode(last_key),
                expected_pk=pk,
                expected_sk_prefix="20",
            )
            next_cursor = _cursor_encode(validated)
        return LifecycleAuditPage(tuple(events), next_cursor)


class CognitoIdentityLifecycleProvider:
    """Cognito adapter with exact immutable owner reconciliation and no secret output."""

    def __init__(self, client: Any, *, user_pool_id: str) -> None:
        self.client = client
        self.user_pool_id = user_pool_id

    def invite_user(self, **request: Any) -> ProviderUserReceipt:
        locator = request.get("principal_locator")
        locator_digest = request.get("principal_locator_digest")
        customer_id = request.get("customer_id")
        deployment_id = request.get("deployment_id")
        if not all(isinstance(value, str) and value for value in (locator, locator_digest, customer_id, deployment_id)):
            raise LifecycleAdapterContractError()
        provider_key = "usr-" + str(locator_digest).split(":", 1)[-1][:32]
        try:
            response = self.client.admin_create_user(
                UserPoolId=self.user_pool_id,
                Username=provider_key,
                UserAttributes=[
                    {"Name": "email", "Value": locator},
                    {"Name": "email_verified", "Value": "false"},
                    {"Name": "custom:customerId", "Value": customer_id},
                    {"Name": "custom:deployment_id", "Value": deployment_id},
                ],
                DesiredDeliveryMediums=["EMAIL"],
            )
        except Exception as error:
            if _error_code(error) != _USERNAME_EXISTS:
                raise
            response = {"User": self._get(provider_key)}
        user = response.get("User") if isinstance(response, Mapping) else None
        return self._receipt(
            user,
            provider_key=provider_key,
            locator_digest=str(locator_digest),
            customer_id=str(customer_id),
            deployment_id=str(deployment_id),
            expected_state="invited",
        )

    def confirm_activation(self, **request: Any) -> ProviderUserReceipt:
        return self._read_bound(request, expected_state="active")

    def set_user_enabled(self, **request: Any) -> ProviderUserReceipt:
        key = self._request_key(request)
        self._read_bound(request, expected_state=None)
        if request.get("enabled") is True:
            self.client.admin_enable_user(UserPoolId=self.user_pool_id, Username=key)
            state = "active"
        elif request.get("enabled") is False:
            self.client.admin_disable_user(UserPoolId=self.user_pool_id, Username=key)
            state = "disabled"
        else:
            raise LifecycleAdapterContractError()
        return self._read_bound(request, expected_state=state)

    def revoke_sessions(self, **request: Any) -> str:
        key = self._request_key(request)
        self._read_bound(request, expected_state=None)
        self.client.admin_user_global_sign_out(
            UserPoolId=self.user_pool_id,
            Username=key,
        )
        return _reference(self.user_pool_id, key, request.get("idempotency_key"))

    def _read_bound(
        self,
        request: Mapping[str, Any],
        *,
        expected_state: str | None,
    ) -> ProviderUserReceipt:
        key = self._request_key(request)
        user = self._get(key)
        receipt = self._receipt(
            user,
            provider_key=key,
            locator_digest="sha256:" + "0" * 64,
            customer_id=str(request.get("customer_id")),
            deployment_id=str(request.get("deployment_id")),
            expected_state=expected_state,
        )
        expected_reference = request.get("provider_user_reference")
        if not isinstance(expected_reference, str) or receipt.provider_user_reference != expected_reference:
            raise LifecycleAdapterContractError()
        expected_subject = request.get("subject")
        if not isinstance(expected_subject, str) or receipt.subject != expected_subject:
            raise LifecycleAdapterContractError()
        return receipt

    def _request_key(self, request: Mapping[str, Any]) -> str:
        key = request.get("provider_principal_key")
        if not isinstance(key, str) or not _SUBJECT_PATTERN.fullmatch(key):
            raise LifecycleAdapterContractError()
        return key

    def _get(self, key: str) -> Mapping[str, Any]:
        response = self.client.admin_get_user(UserPoolId=self.user_pool_id, Username=key)
        if not isinstance(response, Mapping):
            raise LifecycleAdapterContractError()
        return response

    def _receipt(
        self,
        user: object,
        *,
        provider_key: str,
        locator_digest: str,
        customer_id: str,
        deployment_id: str,
        expected_state: str | None,
    ) -> ProviderUserReceipt:
        if not isinstance(user, Mapping):
            raise LifecycleAdapterContractError()
        username = user.get("Username")
        attributes = user.get("Attributes", user.get("UserAttributes"))
        if username != provider_key or not isinstance(attributes, Sequence):
            raise LifecycleAdapterContractError()
        values = {
            str(item.get("Name")): str(item.get("Value"))
            for item in attributes
            if isinstance(item, Mapping)
        }
        subject = values.get("sub")
        if not (
            isinstance(subject, str)
            and _SUBJECT_PATTERN.fullmatch(subject)
            and values.get("custom:customerId") == customer_id
            and values.get("custom:deployment_id") == deployment_id
        ):
            raise LifecycleAdapterContractError()
        enabled = user.get("Enabled")
        status = user.get("UserStatus")
        state = "active" if enabled is True and status == "CONFIRMED" else "invited"
        if enabled is False:
            state = "disabled"
        if expected_state is not None and state != expected_state:
            raise LifecycleAdapterContractError()
        return ProviderUserReceipt(
            subject=subject,
            provider_user_reference=_reference(self.user_pool_id, provider_key, subject),
            provider_principal_key=provider_key,
            principal_locator_digest=locator_digest,
            state=state,
        )


def compose_enterprise_lifecycle_runtime(
    *,
    membership_table: Any,
    authorization_audit_table: Any,
    cognito_client: Any,
    user_pool_id: str,
    customer_id: str,
    deployment_id: str,
) -> EnterpriseLifecycleRuntime:
    """Compose exact deployment-bound adapters without making any SDK call."""
    store = DynamoLifecycleStore(membership_table)
    audit = DynamoLifecycleAudit(
        authorization_audit_table,
        customer_id=customer_id,
        deployment_id=deployment_id,
    )
    return EnterpriseLifecycleRuntime(
        operation_store=store,
        membership_store=store,
        identity_provider=CognitoIdentityLifecycleProvider(
            cognito_client,
            user_pool_id=user_pool_id,
        ),
        approval_resolver=DynamoLifecycleApprovalResolver(membership_table),
        audit_sink=audit,
        audit_reader=audit,
        clock=lambda: datetime.now(timezone.utc),
    )
