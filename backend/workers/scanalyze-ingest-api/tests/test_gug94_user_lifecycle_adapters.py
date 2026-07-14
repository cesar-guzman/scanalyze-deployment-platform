from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timezone
from types import SimpleNamespace
from typing import Any

import pytest

from app.enterprise_authorization import HumanRole
from app.user_lifecycle import (
    LifecycleCommand,
    LifecycleOperation,
    LifecycleOperationRecord,
    LifecycleOperationStage,
    MembershipRecord,
    MembershipState,
)
from app.user_lifecycle_adapters import (
    MEMBERSHIP_REFERENCE_INDEX,
    MEMBERSHIP_STATE_INDEX,
    CognitoIdentityLifecycleProvider,
    DynamoLifecycleAudit,
    DynamoLifecycleStore,
    IdempotencyConflict,
    LifecycleAdapterContractError,
    _audit_pk,
    _cursor_encode,
    _membership_binding,
    _membership_pk,
    _state_binding,
)


CUSTOMER_ID = "cust_01ARZ3NDEKTSV4RRFFQ69G5FAV"
DEPLOYMENT_ID = "dep_01ARZ3NDEKTSV4RRFFQ69G5FAV"
FOREIGN_CUSTOMER_ID = "cust_01ARZ3NDEKTSV4RRFFQ69G5FAW"
NOW = datetime(2026, 7, 13, 3, 0, tzinfo=timezone.utc)


class ConditionalFailure(RuntimeError):
    def __init__(self, code: str = "ConditionalCheckFailedException") -> None:
        super().__init__("synthetic conditional failure")
        self.response = {"Error": {"Code": code}}


class FakeClient:
    def __init__(self) -> None:
        self.transactions: list[dict[str, Any]] = []

    def transact_write_items(self, **request: Any) -> None:
        self.transactions.append(request)


class FakeTable:
    name = "synthetic-memberships"

    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, Any]]] = []
        self.query_responses: list[dict[str, Any]] = []
        self.get_responses: list[dict[str, Any]] = []
        self.put_error: Exception | None = None
        self.update_error: Exception | None = None
        self.meta = SimpleNamespace(client=FakeClient())

    def scan(self, **request: Any) -> None:  # pragma: no cover - guard rail
        raise AssertionError(f"protected scan attempted: {request}")

    def query(self, **request: Any) -> dict[str, Any]:
        self.calls.append(("query", request))
        return self.query_responses.pop(0)

    def get_item(self, **request: Any) -> dict[str, Any]:
        self.calls.append(("get_item", request))
        return self.get_responses.pop(0)

    def put_item(self, **request: Any) -> dict[str, Any]:
        self.calls.append(("put_item", request))
        if self.put_error is not None:
            raise self.put_error
        return {}

    def update_item(self, **request: Any) -> dict[str, Any]:
        self.calls.append(("update_item", request))
        if self.update_error is not None:
            raise self.update_error
        return {}


def _member(
    *,
    reference: str = "mbr_" + "1" * 32,
    subject: str = "synthetic-user",
    state: MembershipState = MembershipState.ACTIVE,
    role: HumanRole = HumanRole.DOCUMENT_OPERATOR,
    version: int = 3,
) -> MembershipRecord:
    return MembershipRecord(
        schema_version="enterprise-membership.v1",
        membership_reference=reference,
        subject=subject,
        customer_id=CUSTOMER_ID,
        deployment_id=DEPLOYMENT_ID,
        state=state,
        role_id=role,
        membership_version=version,
        provider_user_reference="ref_" + "a" * 24,
        provider_principal_key="synthetic-provider-principal",
        created_at=NOW,
        updated_at=NOW,
    )


def _item(record: MembershipRecord) -> dict[str, Any]:
    return DynamoLifecycleStore._membership_item(record)


def test_membership_list_queries_exact_owner_partition_without_scan() -> None:
    table = FakeTable()
    record = _member()
    last_key = {"pk": _membership_pk(CUSTOMER_ID, DEPLOYMENT_ID), "sk": "SUBJECT#synthetic-user"}
    table.query_responses.append({"Items": [_item(record)], "LastEvaluatedKey": last_key})

    page = DynamoLifecycleStore(table).list_memberships(
        customer_id=CUSTOMER_ID,
        deployment_id=DEPLOYMENT_ID,
        state=None,
        cursor=None,
        limit=25,
    )

    request = table.calls[0][1]
    assert request["ExpressionAttributeValues"][":pk"] == _membership_pk(
        CUSTOMER_ID, DEPLOYMENT_ID
    )
    assert request["ConsistentRead"] is True
    assert page.items == (record,)
    assert page.next_cursor is not None


def test_state_filter_and_cursor_remain_bound_to_exact_owner_and_state() -> None:
    table = FakeTable()
    record = _member(state=MembershipState.SUSPENDED)
    state_key = _state_binding(CUSTOMER_ID, DEPLOYMENT_ID, MembershipState.SUSPENDED)
    last_key = {
        "pk": _membership_pk(CUSTOMER_ID, DEPLOYMENT_ID),
        "sk": "SUBJECT#synthetic-user",
        "ownership_state_key": state_key,
        "membership_reference": record.membership_reference,
    }
    table.query_responses.extend(
        [
            {"Items": [_item(record)], "LastEvaluatedKey": last_key},
            {"Items": [], "LastEvaluatedKey": None},
        ]
    )
    store = DynamoLifecycleStore(table)

    first = store.list_memberships(
        customer_id=CUSTOMER_ID,
        deployment_id=DEPLOYMENT_ID,
        state=MembershipState.SUSPENDED,
        cursor=None,
        limit=1,
    )
    store.list_memberships(
        customer_id=CUSTOMER_ID,
        deployment_id=DEPLOYMENT_ID,
        state=MembershipState.SUSPENDED,
        cursor=first.next_cursor,
        limit=1,
    )

    first_request = table.calls[0][1]
    second_request = table.calls[1][1]
    assert first_request["IndexName"] == MEMBERSHIP_STATE_INDEX
    assert first_request["ExpressionAttributeValues"][":state_key"] == state_key
    assert second_request["ExclusiveStartKey"] == last_key


def test_foreign_or_malformed_state_cursor_is_rejected_before_query() -> None:
    table = FakeTable()
    cursor = _cursor_encode(
        {
            "pk": _membership_pk(FOREIGN_CUSTOMER_ID, DEPLOYMENT_ID),
            "sk": "SUBJECT#synthetic-user",
            "ownership_state_key": _state_binding(
                FOREIGN_CUSTOMER_ID,
                DEPLOYMENT_ID,
                MembershipState.ACTIVE,
            ),
            "membership_reference": "mbr_" + "1" * 32,
        }
    )

    with pytest.raises(LifecycleAdapterContractError):
        DynamoLifecycleStore(table).list_memberships(
            customer_id=CUSTOMER_ID,
            deployment_id=DEPLOYMENT_ID,
            state=MembershipState.ACTIVE,
            cursor=cursor,
            limit=25,
        )
    assert table.calls == []


def test_reference_lookup_uses_owner_bound_gsi_then_consistent_primary_read() -> None:
    table = FakeTable()
    record = _member()
    table.query_responses.append({"Items": [_item(record)]})
    table.get_responses.append({"Item": _item(record)})

    result = DynamoLifecycleStore(table).load_membership(
        customer_id=CUSTOMER_ID,
        deployment_id=DEPLOYMENT_ID,
        membership_reference=record.membership_reference,
    )

    query = table.calls[0][1]
    read = table.calls[1][1]
    assert query["IndexName"] == MEMBERSHIP_REFERENCE_INDEX
    assert query["Limit"] == 2
    assert query["ExpressionAttributeValues"][":binding"] == _membership_binding(
        CUSTOMER_ID, DEPLOYMENT_ID, record.membership_reference
    )
    assert read["ConsistentRead"] is True
    assert result == record


def test_duplicate_reference_binding_is_rejected_as_ambiguous() -> None:
    table = FakeTable()
    record = _member()
    table.query_responses.append({"Items": [_item(record), _item(replace(record, subject="other"))]})
    with pytest.raises(LifecycleAdapterContractError):
        DynamoLifecycleStore(table).load_membership(
            customer_id=CUSTOMER_ID,
            deployment_id=DEPLOYMENT_ID,
            membership_reference=record.membership_reference,
        )


def test_operation_idempotency_key_cannot_be_reused_for_different_command() -> None:
    table = FakeTable()
    table.put_error = ConditionalFailure()
    command = LifecycleCommand(
        operation=LifecycleOperation.SUSPEND,
        customer_id=CUSTOMER_ID,
        deployment_id=DEPLOYMENT_ID,
        actor_subject="synthetic-admin",
        idempotency_key="idem_" + "1" * 32,
        request_digest="sha256:" + "a" * 64,
    )
    conflicting = replace(command, request_digest="sha256:" + "b" * 64)
    existing = DynamoLifecycleStore._operation_item(
        LifecycleOperationRecord.new(conflicting, now=NOW)
    )
    table.get_responses.append({"Item": existing})

    with pytest.raises(IdempotencyConflict):
        DynamoLifecycleStore(table).reserve_operation(command)


def test_operation_adapter_rejects_unknown_evidence_field() -> None:
    command = LifecycleCommand(
        operation=LifecycleOperation.SUSPEND,
        customer_id=CUSTOMER_ID,
        deployment_id=DEPLOYMENT_ID,
        actor_subject="synthetic-admin",
        idempotency_key="idem_" + "2" * 32,
        request_digest="sha256:" + "c" * 64,
    )
    item = DynamoLifecycleStore._operation_item(
        LifecycleOperationRecord.new(command, now=NOW)
    )
    item["evidence"] = {"request_body": "synthetic-sensitive-payload"}

    with pytest.raises(LifecycleAdapterContractError):
        DynamoLifecycleStore._operation_from_item(item)


def test_operation_adapter_requires_audit_receipt_for_completed_stage() -> None:
    command = LifecycleCommand(
        operation=LifecycleOperation.SUSPEND,
        customer_id=CUSTOMER_ID,
        deployment_id=DEPLOYMENT_ID,
        actor_subject="synthetic-admin",
        idempotency_key="idem_" + "3" * 32,
        request_digest="sha256:" + "d" * 64,
    )
    record = replace(
        LifecycleOperationRecord.new(command, now=NOW),
        stage=LifecycleOperationStage.COMPLETED,
    )

    with pytest.raises(LifecycleAdapterContractError):
        DynamoLifecycleStore._operation_item(record)


def test_transition_conditions_bind_owner_state_version_and_reference() -> None:
    table = FakeTable()
    current = _member()

    updated = DynamoLifecycleStore(table).transition_membership(
        current=current,
        expected_state=MembershipState.ACTIVE,
        expected_version=3,
        next_state=MembershipState.SUSPENDED,
        next_role=HumanRole.DOCUMENT_OPERATOR,
        operation_reference="op_" + "1" * 32,
        admin_replacement=None,
    )

    request = table.calls[0][1]
    assert "customer_id = :customer_id" in request["ConditionExpression"]
    assert "deployment_id = :deployment_id" in request["ConditionExpression"]
    assert "membership_version = :expected_version" in request["ConditionExpression"]
    assert request["ExpressionAttributeValues"][":state_key"] == _state_binding(
        CUSTOMER_ID, DEPLOYMENT_ID, MembershipState.SUSPENDED
    )
    assert updated.membership_version == 4


def test_admin_removal_requires_transactionally_checked_active_replacement() -> None:
    table = FakeTable()
    current = _member(role=HumanRole.CUSTOMER_ADMIN)
    replacement_admin = _member(
        reference="mbr_" + "2" * 32,
        subject="replacement-admin",
        role=HumanRole.CUSTOMER_ADMIN,
        version=8,
    )
    store = DynamoLifecycleStore(table)

    with pytest.raises(LifecycleAdapterContractError):
        store.transition_membership(
            current=current,
            expected_state=MembershipState.ACTIVE,
            expected_version=3,
            next_state=MembershipState.REVOKED,
            next_role=HumanRole.CUSTOMER_ADMIN,
            operation_reference="op_" + "2" * 32,
            admin_replacement=None,
        )

    store.transition_membership(
        current=current,
        expected_state=MembershipState.ACTIVE,
        expected_version=3,
        next_state=MembershipState.REVOKED,
        next_role=HumanRole.CUSTOMER_ADMIN,
        operation_reference="op_" + "3" * 32,
        admin_replacement=replacement_admin,
    )
    transaction = table.meta.client.transactions[0]
    assert len(transaction["TransactItems"]) == 2
    assert "ConditionCheck" in transaction["TransactItems"][0]
    assert "Update" in transaction["TransactItems"][1]
    assert transaction["ClientRequestToken"] == "op_" + "3" * 32


def test_audit_query_cursor_is_exact_owner_bound() -> None:
    table = FakeTable()
    pk = _audit_pk(CUSTOMER_ID, DEPLOYMENT_ID)
    sk = "2026-07-13T03:00:00Z#ref_" + "a" * 24
    event = {
        "pk": pk,
        "sk": sk,
        "timestamp": "2026-07-13T03:00:00Z",
        "action": "membership.suspend",
        "decision": "allow",
        "reason_code": "security_review",
        "principal_reference": "ref_" + "b" * 24,
        "correlation_reference": "ref_" + "c" * 24,
        "before_membership_version": "3",
        "after_membership_version": "4",
    }
    table.query_responses.append({"Items": [event], "LastEvaluatedKey": {"pk": pk, "sk": sk}})
    audit = DynamoLifecycleAudit(table, customer_id=CUSTOMER_ID, deployment_id=DEPLOYMENT_ID)

    page = audit.list_events(
        customer_id=CUSTOMER_ID,
        deployment_id=DEPLOYMENT_ID,
        cursor=None,
        limit=25,
    )

    assert table.calls[0][1]["ExpressionAttributeValues"][":pk"] == pk
    assert page.next_cursor is not None


class FakeCognito:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, Any]]] = []
        self.users: dict[str, dict[str, Any]] = {}

    def admin_create_user(self, **request: Any) -> dict[str, Any]:
        self.calls.append(("admin_create_user", request))
        attributes = [*request["UserAttributes"], {"Name": "sub", "Value": "provider-subject"}]
        user = {
            "Username": request["Username"],
            "Attributes": attributes,
            "Enabled": True,
            "UserStatus": "FORCE_CHANGE_PASSWORD",
        }
        self.users[request["Username"]] = user
        return {"User": user}

    def admin_get_user(self, **request: Any) -> dict[str, Any]:
        self.calls.append(("admin_get_user", request))
        return self.users[request["Username"]]

    def admin_disable_user(self, **request: Any) -> None:
        self.calls.append(("admin_disable_user", request))
        self.users[request["Username"]]["Enabled"] = False

    def admin_enable_user(self, **request: Any) -> None:
        self.calls.append(("admin_enable_user", request))
        self.users[request["Username"]]["Enabled"] = True

    def admin_user_global_sign_out(self, **request: Any) -> None:
        self.calls.append(("admin_user_global_sign_out", request))


def test_cognito_invitation_uses_immutable_owner_attributes_and_returns_no_locator() -> None:
    client = FakeCognito()
    adapter = CognitoIdentityLifecycleProvider(client, user_pool_id="us-east-1_SYNTHETIC")
    locator_digest = "sha256:" + "d" * 64

    receipt = adapter.invite_user(
        principal_locator="synthetic@example.invalid",
        principal_locator_digest=locator_digest,
        customer_id=CUSTOMER_ID,
        deployment_id=DEPLOYMENT_ID,
    )

    request = client.calls[0][1]
    attributes = {item["Name"]: item["Value"] for item in request["UserAttributes"]}
    assert attributes["custom:customerId"] == CUSTOMER_ID
    assert attributes["custom:deployment_id"] == DEPLOYMENT_ID
    assert receipt.principal_locator_digest == locator_digest
    assert "synthetic@example.invalid" not in repr(receipt)


def test_cognito_reconciliation_rejects_foreign_provider_binding() -> None:
    client = FakeCognito()
    adapter = CognitoIdentityLifecycleProvider(client, user_pool_id="us-east-1_SYNTHETIC")
    receipt = adapter.invite_user(
        principal_locator="synthetic@example.invalid",
        principal_locator_digest="sha256:" + "e" * 64,
        customer_id=CUSTOMER_ID,
        deployment_id=DEPLOYMENT_ID,
    )
    client.users[receipt.provider_principal_key]["Attributes"] = [
        {"Name": "sub", "Value": receipt.subject},
        {"Name": "custom:customerId", "Value": FOREIGN_CUSTOMER_ID},
        {"Name": "custom:deployment_id", "Value": DEPLOYMENT_ID},
    ]

    with pytest.raises(LifecycleAdapterContractError):
        adapter.revoke_sessions(
            subject=receipt.subject,
            provider_user_reference=receipt.provider_user_reference,
            provider_principal_key=receipt.provider_principal_key,
            customer_id=CUSTOMER_ID,
            deployment_id=DEPLOYMENT_ID,
            idempotency_key="idem_" + "2" * 32,
        )
    assert not any(name == "admin_user_global_sign_out" for name, _ in client.calls)


def test_cognito_reconciles_binding_before_enable_or_disable_effect() -> None:
    client = FakeCognito()
    adapter = CognitoIdentityLifecycleProvider(client, user_pool_id="us-east-1_SYNTHETIC")
    receipt = adapter.invite_user(
        principal_locator="synthetic@example.invalid",
        principal_locator_digest="sha256:" + "f" * 64,
        customer_id=CUSTOMER_ID,
        deployment_id=DEPLOYMENT_ID,
    )
    client.users[receipt.provider_principal_key]["Attributes"] = [
        {"Name": "sub", "Value": receipt.subject},
        {"Name": "custom:customerId", "Value": FOREIGN_CUSTOMER_ID},
        {"Name": "custom:deployment_id", "Value": DEPLOYMENT_ID},
    ]
    request = {
        "subject": receipt.subject,
        "provider_user_reference": receipt.provider_user_reference,
        "provider_principal_key": receipt.provider_principal_key,
        "customer_id": CUSTOMER_ID,
        "deployment_id": DEPLOYMENT_ID,
        "idempotency_key": "idem_" + "3" * 32,
        "enabled": False,
    }

    with pytest.raises(LifecycleAdapterContractError):
        adapter.set_user_enabled(**request)

    assert not any(
        name in {"admin_disable_user", "admin_enable_user"}
        for name, _ in client.calls
    )
