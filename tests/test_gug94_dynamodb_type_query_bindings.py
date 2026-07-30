"""GUG-94 regression tests — DynamoDB membership type and query bindings.

Tests-first: each test proves the specific defect (A, B, C) and validates
the correction.  All tests are synthetic / offline; no AWS access occurs.

Defect A — datetime persistence in DynamoMembershipStore.ensure_membership()
Defect B — Decimal membership_version rejection in PreTokenProcessor
Defect C — missing #membership_reference GSI alias in state-filtered list
"""
from __future__ import annotations

import copy
import sys
import re
from collections.abc import Mapping
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from typing import Any
from unittest.mock import MagicMock

import pytest

# ---------------------------------------------------------------------------
# Path setup: identity-control-plane sources live in a non-installed package
# ---------------------------------------------------------------------------
_ICP_SRC = "backend/lambdas/scanalyze-identity-control-plane/src"
if _ICP_SRC not in sys.path:
    sys.path.insert(0, _ICP_SRC)

from identity_control_plane.aws_adapters import (  # noqa: E402
    AdapterContractError,
    DynamoMembershipStore,
)
from identity_control_plane.common import utc_timestamp  # noqa: E402
from identity_control_plane.pre_token import (  # noqa: E402
    PreTokenDenied,
    PreTokenProcessor,
)

# ---------------------------------------------------------------------------
# Synthetic constants
# ---------------------------------------------------------------------------
_SUBJECT = "a1b2c3d4-1234-4abc-9def-112233445566"
_CUSTOMER_ID = "cust_01JDEABC123XYZQRSTV4W56789"
_DEPLOYMENT_ID = "dep_01JDEABC123XYZQRSTV4W67890"
_ROLE_ID = "customer_admin"
_AUTHZ_SCHEMA = "authz-v2"
_SCOPE_CATALOG = "scope-catalog-v3"
_ROLE_CATALOG = "role-catalog-v2"
_POLICY_VERSION = "policy-v7"
_POLICY_DIGEST = "sha256:" + "a" * 64
_USER_POOL_ID = "us-east-1_TestPool"
_CLIENT_ID = "test-client-id"

_CREATED_AT = datetime(2026, 1, 15, 10, 30, 0, tzinfo=timezone.utc)
_CREATED_AT_STR = utc_timestamp(_CREATED_AT)


def _valid_membership_record() -> dict[str, Any]:
    """Return a valid membership record for ensure_membership()."""
    return {
        "subject": _SUBJECT,
        "customer_id": _CUSTOMER_ID,
        "deployment_id": _DEPLOYMENT_ID,
        "role_id": _ROLE_ID,
        "state": "active",
        "membership_version": 1,
        "authz_schema_version": _AUTHZ_SCHEMA,
        "scope_catalog_version": _SCOPE_CATALOG,
        "role_catalog_version": _ROLE_CATALOG,
        "policy_version": _POLICY_VERSION,
        "policy_digest": _POLICY_DIGEST,
        "idempotency_key": "test-idempotency-key",
        "provider_user_reference": "ref_abc123",
        "provider_principal_key": _SUBJECT,
        "created_at": _CREATED_AT,
    }


class _CaptureTable:
    """Fake DynamoDB table that captures put_item calls."""

    def __init__(self) -> None:
        self.items: list[dict[str, Any]] = []
        self._conditional_fail = False

    def put_item(self, *, Item: dict[str, Any], **kwargs: Any) -> dict[str, Any]:
        self.items.append(copy.deepcopy(Item))
        if self._conditional_fail:
            error = Exception("ConditionalCheckFailedException")
            error.response = {"Error": {"Code": "ConditionalCheckFailedException"}}
            raise error
        return {"ResponseMetadata": {"HTTPStatusCode": 200}}

    def get_item(self, **kwargs: Any) -> dict[str, Any]:
        if self.items:
            return {"Item": copy.deepcopy(self.items[-1])}
        return {}


# ═══════════════════════════════════════════════════════════════════════════
# DEFECT A — datetime persistence in ensure_membership()
# ═══════════════════════════════════════════════════════════════════════════

class TestDefectA_DatetimePersistence:
    """DynamoMembershipStore.ensure_membership() must store timestamps as
    canonical UTC strings, not Python datetime objects."""

    def test_created_at_is_string_after_fix(self) -> None:
        table = _CaptureTable()
        store = DynamoMembershipStore(table)
        record = _valid_membership_record()
        store.ensure_membership(**record)

        item = table.items[0]
        assert isinstance(item["created_at"], str), \
            "created_at must be a UTC string, not datetime"
        assert isinstance(item["updated_at"], str), \
            "updated_at must be a UTC string, not datetime"

    def test_timestamps_are_canonical_utc(self) -> None:
        table = _CaptureTable()
        store = DynamoMembershipStore(table)
        record = _valid_membership_record()
        store.ensure_membership(**record)

        item = table.items[0]
        expected = _CREATED_AT_STR
        assert item["created_at"] == expected
        assert item["updated_at"] == expected

    def test_no_datetime_anywhere_in_item(self) -> None:
        table = _CaptureTable()
        store = DynamoMembershipStore(table)
        record = _valid_membership_record()
        store.ensure_membership(**record)

        item = table.items[0]
        for key, value in item.items():
            assert not isinstance(value, datetime), \
                f"Item field '{key}' is a datetime — must be serializable"

    def test_item_is_type_serializable(self) -> None:
        """Every value in the item must pass boto3 TypeSerializer."""
        from boto3.dynamodb.types import TypeSerializer
        serializer = TypeSerializer()
        table = _CaptureTable()
        store = DynamoMembershipStore(table)
        store.ensure_membership(**_valid_membership_record())

        item = table.items[0]
        for key, value in item.items():
            try:
                serializer.serialize(value)
            except (TypeError, AttributeError) as exc:
                pytest.fail(
                    f"Field '{key}' ({type(value).__name__}) cannot be "
                    f"serialized: {exc}"
                )

    def test_input_record_not_mutated(self) -> None:
        table = _CaptureTable()
        store = DynamoMembershipStore(table)
        record = _valid_membership_record()
        original = copy.deepcopy(record)
        store.ensure_membership(**record)
        assert record == original, "ensure_membership must not mutate the input"

    def test_idempotent_replay_accepts_equivalent(self) -> None:
        """A conditional replay with the same canonical item must succeed."""
        table = _CaptureTable()
        table._conditional_fail = True
        store = DynamoMembershipStore(table)
        record = _valid_membership_record()
        # Should not raise — idempotent replay with matching item
        result = store.ensure_membership(**record)
        assert "membership_reference" in result

    def test_conflicting_replay_fails_closed(self) -> None:
        """A conditional replay with a different item must raise."""
        table = _CaptureTable()
        table._conditional_fail = True
        # Tamper with the stored item
        original_get = table.get_item

        def tampered_get(**kwargs: Any) -> dict[str, Any]:
            result = original_get(**kwargs)
            if "Item" in result:
                result["Item"]["role_id"] = "different_role"
            return result

        table.get_item = tampered_get
        store = DynamoMembershipStore(table)
        with pytest.raises(AdapterContractError):
            store.ensure_membership(**_valid_membership_record())


class _NoPutTable:
    """Fake table that records whether put_item was called."""

    def __init__(self) -> None:
        self.put_called = False

    def put_item(self, **kwargs: Any) -> dict[str, Any]:
        self.put_called = True
        return {"ResponseMetadata": {"HTTPStatusCode": 200}}


class TestDefectA_TimezoneAwareness:
    """Naive datetimes must be rejected before persistence.
    Non-UTC aware datetimes must be normalized to UTC."""

    def test_naive_datetime_rejected(self) -> None:
        """A naive datetime (no tzinfo) must be rejected before put_item."""
        table = _NoPutTable()
        store = DynamoMembershipStore(table)
        record = _valid_membership_record()
        record["created_at"] = datetime(2026, 1, 15, 10, 30, 0)  # naive
        with pytest.raises(AdapterContractError):
            store.ensure_membership(**record)
        assert not table.put_called, "put_item must not be called for naive datetime"

    def test_utc_aware_stored_with_z_suffix(self) -> None:
        """A UTC-aware datetime must be stored with canonical Z suffix."""
        table = _CaptureTable()
        store = DynamoMembershipStore(table)
        record = _valid_membership_record()
        record["created_at"] = datetime(2026, 6, 15, 8, 0, 0, tzinfo=timezone.utc)
        store.ensure_membership(**record)
        item = table.items[0]
        assert item["created_at"] == "2026-06-15T08:00:00Z"
        assert item["updated_at"] == "2026-06-15T08:00:00Z"
        assert item["created_at"].endswith("Z")

    def test_non_utc_aware_normalized_to_utc(self) -> None:
        """An aware datetime with a non-UTC offset must be normalized to UTC."""
        from datetime import timedelta
        cst = timezone(timedelta(hours=-6))
        table = _CaptureTable()
        store = DynamoMembershipStore(table)
        record = _valid_membership_record()
        # 2026-01-15T04:30:00-06:00 == 2026-01-15T10:30:00Z
        record["created_at"] = datetime(2026, 1, 15, 4, 30, 0, tzinfo=cst)
        store.ensure_membership(**record)
        item = table.items[0]
        assert item["created_at"] == "2026-01-15T10:30:00Z"
        assert item["updated_at"] == "2026-01-15T10:30:00Z"

    def test_no_datetime_nested_in_item_with_non_utc_input(self) -> None:
        """Even with a non-UTC input, no datetime must survive in the item."""
        from datetime import timedelta
        jst = timezone(timedelta(hours=9))
        table = _CaptureTable()
        store = DynamoMembershipStore(table)
        record = _valid_membership_record()
        record["created_at"] = datetime(2026, 1, 15, 19, 30, 0, tzinfo=jst)
        store.ensure_membership(**record)
        item = table.items[0]
        for key, value in item.items():
            assert not isinstance(value, datetime), \
                f"Item field '{key}' is a datetime — must be serializable"

    def test_put_item_not_called_on_invalid_timestamp(self) -> None:
        """put_item must not be called if the timestamp is invalid."""
        table = _NoPutTable()
        store = DynamoMembershipStore(table)
        for bad_ts in [
            None,
            42,
            datetime(2026, 1, 15, 10, 30, 0),  # naive
            "",  # empty string
        ]:
            table.put_called = False
            record = _valid_membership_record()
            record["created_at"] = bad_ts
            with pytest.raises(AdapterContractError):
                store.ensure_membership(**record)
            assert not table.put_called, \
                f"put_item must not be called for created_at={bad_ts!r}"

    def test_canonical_replay_compares_stored_representation(self) -> None:
        """Idempotent replay must compare against the canonical stored string,
        not the original datetime object."""
        table = _CaptureTable()
        table._conditional_fail = True
        store = DynamoMembershipStore(table)
        record = _valid_membership_record()
        # The stored item uses the string representation, and the replay
        # will build a fresh item with the same string — must match.
        result = store.ensure_membership(**record)
        assert "membership_reference" in result

    def test_host_timezone_does_not_affect_result(self) -> None:
        """Two different aware offsets representing the same instant must
        produce the same canonical string."""
        from datetime import timedelta
        utc_dt = datetime(2026, 3, 1, 12, 0, 0, tzinfo=timezone.utc)
        est_dt = datetime(2026, 3, 1, 7, 0, 0, tzinfo=timezone(timedelta(hours=-5)))

        table1 = _CaptureTable()
        store1 = DynamoMembershipStore(table1)
        r1 = _valid_membership_record()
        r1["created_at"] = utc_dt
        store1.ensure_membership(**r1)

        table2 = _CaptureTable()
        store2 = DynamoMembershipStore(table2)
        r2 = _valid_membership_record()
        r2["created_at"] = est_dt
        store2.ensure_membership(**r2)

        assert table1.items[0]["created_at"] == table2.items[0]["created_at"]
        assert table1.items[0]["updated_at"] == table2.items[0]["updated_at"]


# ═══════════════════════════════════════════════════════════════════════════
# DEFECT B — Decimal membership_version in PreTokenProcessor
# ═══════════════════════════════════════════════════════════════════════════

def _make_processor(
    *,
    membership_reader: Any = None,
    audit_sink: Any = None,
) -> PreTokenProcessor:
    config = {
        "human_runtime_enabled": True,
        "expected_user_pool_id": _USER_POOL_ID,
        "expected_customer_id": _CUSTOMER_ID,
        "expected_deployment_id": _DEPLOYMENT_ID,
        "allowed_client_ids": [_CLIENT_ID],
        "allowed_role_ids": [_ROLE_ID],
        "authz_schema_version": _AUTHZ_SCHEMA,
        "scope_catalog_version": _SCOPE_CATALOG,
        "role_catalog_version": _ROLE_CATALOG,
        "policy_version": _POLICY_VERSION,
        "policy_digest": _POLICY_DIGEST,
    }
    if audit_sink is None:
        audit_sink = MagicMock()
    return PreTokenProcessor(
        config=config,
        membership_reader=membership_reader or MagicMock(),
        audit_sink=audit_sink,
        clock=lambda: datetime(2026, 7, 26, 12, 0, 0, tzinfo=timezone.utc),
    )


def _make_event() -> dict[str, Any]:
    return {
        "version": "2",
        "triggerSource": "TokenGeneration_Authentication",
        "userPoolId": _USER_POOL_ID,
        "callerContext": {"clientId": _CLIENT_ID},
        "request": {
            "userAttributes": {
                "sub": _SUBJECT,
                "custom:customerId": _CUSTOMER_ID,
                "custom:deployment_id": _DEPLOYMENT_ID,
            },
        },
        "response": {},
    }


def _membership_with_version(version: Any) -> dict[str, Any]:
    return {
        "subject": _SUBJECT,
        "customer_id": _CUSTOMER_ID,
        "deployment_id": _DEPLOYMENT_ID,
        "principal_type": "user",
        "schema_version": "enterprise-membership.v1",
        "state": "active",
        "role_id": _ROLE_ID,
        "membership_version": version,
        "authz_schema_version": _AUTHZ_SCHEMA,
        "scope_catalog_version": _SCOPE_CATALOG,
        "role_catalog_version": _ROLE_CATALOG,
        "policy_version": _POLICY_VERSION,
        "policy_digest": _POLICY_DIGEST,
    }


class TestDefectB_DecimalVersion:
    """PreTokenProcessor must accept Decimal(1) from DynamoDB as a valid
    membership_version, normalize to int, and emit "1" in claims."""

    def test_decimal_1_is_accepted(self) -> None:
        """The canonical DynamoDB Decimal("1") must be accepted."""
        membership = _membership_with_version(Decimal("1"))
        reader = MagicMock()
        reader.get_membership.return_value = membership
        processor = _make_processor(membership_reader=reader)
        result = processor.handle(_make_event())
        claims = result["response"]["claimsAndScopeOverrideDetails"][
            "accessTokenGeneration"
        ]["claimsToAddOrOverride"]
        assert claims["membership_version"] == "1"

    def test_int_1_still_accepted(self) -> None:
        """Python int(1) must continue to work."""
        membership = _membership_with_version(1)
        reader = MagicMock()
        reader.get_membership.return_value = membership
        processor = _make_processor(membership_reader=reader)
        result = processor.handle(_make_event())
        claims = result["response"]["claimsAndScopeOverrideDetails"][
            "accessTokenGeneration"
        ]["claimsToAddOrOverride"]
        assert claims["membership_version"] == "1"

    @pytest.mark.parametrize(
        "bad_version",
        [
            pytest.param(True, id="bool_true"),
            pytest.param(False, id="bool_false"),
            pytest.param(0, id="zero"),
            pytest.param(-1, id="negative"),
            pytest.param(1.0, id="float"),
            pytest.param("1", id="string"),
            pytest.param(Decimal("0"), id="decimal_zero"),
            pytest.param(Decimal("-1"), id="decimal_negative"),
            pytest.param(Decimal("1.1"), id="decimal_fractional"),
            pytest.param(Decimal("NaN"), id="decimal_nan"),
            pytest.param(Decimal("Infinity"), id="decimal_infinity"),
            pytest.param(Decimal("-Infinity"), id="decimal_neg_infinity"),
        ],
    )
    def test_invalid_version_denied(self, bad_version: Any) -> None:
        membership = _membership_with_version(bad_version)
        reader = MagicMock()
        reader.get_membership.return_value = membership
        processor = _make_processor(membership_reader=reader)
        with pytest.raises(PreTokenDenied) as exc_info:
            processor.handle(_make_event())
        assert exc_info.value.reason_code == "stale_authorization_contract"

    @pytest.mark.parametrize(
        "good_version",
        [
            pytest.param(Decimal("1"), id="decimal_1"),
            pytest.param(Decimal("2"), id="decimal_2"),
            pytest.param(Decimal("100"), id="decimal_100"),
            pytest.param(1, id="int_1"),
            pytest.param(2, id="int_2"),
            pytest.param(100, id="int_100"),
        ],
    )
    def test_valid_version_accepted(self, good_version: Any) -> None:
        membership = _membership_with_version(good_version)
        reader = MagicMock()
        reader.get_membership.return_value = membership
        processor = _make_processor(membership_reader=reader)
        result = processor.handle(_make_event())
        claims = result["response"]["claimsAndScopeOverrideDetails"][
            "accessTokenGeneration"
        ]["claimsToAddOrOverride"]
        # The emitted claim must be a clean integer string
        assert claims["membership_version"] == str(int(good_version))

    def test_decimal_claim_not_decimal_string(self) -> None:
        """The emitted claim for Decimal("1") must be "1", not "1.0"."""
        membership = _membership_with_version(Decimal("1"))
        reader = MagicMock()
        reader.get_membership.return_value = membership
        processor = _make_processor(membership_reader=reader)
        result = processor.handle(_make_event())
        claims = result["response"]["claimsAndScopeOverrideDetails"][
            "accessTokenGeneration"
        ]["claimsToAddOrOverride"]
        assert claims["membership_version"] == "1"
        assert "." not in claims["membership_version"]


# ═══════════════════════════════════════════════════════════════════════════
# DEFECT C — GSI alias in state-filtered list_memberships()
# ═══════════════════════════════════════════════════════════════════════════

# Insert ingest-api path for the DynamoLifecycleStore import.
_INGEST_SRC = "backend/workers/scanalyze-ingest-api"
if _INGEST_SRC not in sys.path:
    sys.path.insert(0, _INGEST_SRC)

# The ingest-api adapter chain pulls in fastapi, starlette, structlog, and
# pydantic_settings transitively.  CI runners for tests/ do not install these
# worker-specific dependencies.  Rather than stubbing every transitive module
# (an unbounded whack-a-mole), we attempt the import and gracefully skip the
# Defect C tests when the dependencies are unavailable.
try:
    from app.user_lifecycle_adapters import (  # noqa: E402
        DynamoLifecycleStore,
        MEMBERSHIP_STATE_INDEX,
        LifecycleAdapterContractError,
    )
    from app.user_lifecycle import MembershipState  # noqa: E402
    _HAS_INGEST_DEPS = True
except ImportError:
    _HAS_INGEST_DEPS = False


class _QueryCaptureTable:
    """Captures query() calls for inspection."""

    def __init__(self) -> None:
        self.queries: list[dict[str, Any]] = []

    def query(self, **kwargs: Any) -> dict[str, Any]:
        self.queries.append(kwargs)
        return {"Items": [], "Count": 0}


@pytest.mark.skipif(
    not _HAS_INGEST_DEPS,
    reason="ingest-api worker dependencies (fastapi, structlog) not installed",
)
class TestDefectC_GSIAlias:
    """State-filtered list_memberships must include #membership_reference
    in ExpressionAttributeNames when querying the ownership-state-v1 GSI."""

    def test_alias_map_includes_membership_reference(self) -> None:
        table = _QueryCaptureTable()
        store = DynamoLifecycleStore(table)
        store.list_memberships(
            customer_id=_CUSTOMER_ID,
            deployment_id=_DEPLOYMENT_ID,
            state=MembershipState.ACTIVE,
            cursor=None,
            limit=10,
        )
        assert len(table.queries) == 1
        query = table.queries[0]
        aliases = query["ExpressionAttributeNames"]
        assert "#membership_reference" in aliases, \
            "#membership_reference alias is missing from the state GSI query"
        assert aliases["#membership_reference"] == "membership_reference"

    def test_state_key_alias_present(self) -> None:
        table = _QueryCaptureTable()
        store = DynamoLifecycleStore(table)
        store.list_memberships(
            customer_id=_CUSTOMER_ID,
            deployment_id=_DEPLOYMENT_ID,
            state=MembershipState.ACTIVE,
            cursor=None,
            limit=10,
        )
        query = table.queries[0]
        aliases = query["ExpressionAttributeNames"]
        assert "#state_key" in aliases
        assert aliases["#state_key"] == "ownership_state_key"

    def test_uses_correct_index(self) -> None:
        table = _QueryCaptureTable()
        store = DynamoLifecycleStore(table)
        store.list_memberships(
            customer_id=_CUSTOMER_ID,
            deployment_id=_DEPLOYMENT_ID,
            state=MembershipState.ACTIVE,
            cursor=None,
            limit=10,
        )
        query = table.queries[0]
        assert query.get("IndexName") == MEMBERSHIP_STATE_INDEX

    def test_no_consistent_read_on_gsi(self) -> None:
        table = _QueryCaptureTable()
        store = DynamoLifecycleStore(table)
        store.list_memberships(
            customer_id=_CUSTOMER_ID,
            deployment_id=_DEPLOYMENT_ID,
            state=MembershipState.ACTIVE,
            cursor=None,
            limit=10,
        )
        query = table.queries[0]
        assert query.get("ConsistentRead") is not True, \
            "GSI queries do not support ConsistentRead=True"

    def test_ownership_bound_values(self) -> None:
        table = _QueryCaptureTable()
        store = DynamoLifecycleStore(table)
        store.list_memberships(
            customer_id=_CUSTOMER_ID,
            deployment_id=_DEPLOYMENT_ID,
            state=MembershipState.ACTIVE,
            cursor=None,
            limit=10,
        )
        query = table.queries[0]
        values = query["ExpressionAttributeValues"]
        state_key = values[":state_key"]
        assert _DEPLOYMENT_ID in state_key
        assert _CUSTOMER_ID in state_key
        assert "active" in state_key

    def test_no_filter_expression(self) -> None:
        table = _QueryCaptureTable()
        store = DynamoLifecycleStore(table)
        store.list_memberships(
            customer_id=_CUSTOMER_ID,
            deployment_id=_DEPLOYMENT_ID,
            state=MembershipState.ACTIVE,
            cursor=None,
            limit=10,
        )
        query = table.queries[0]
        assert "FilterExpression" not in query

    def test_no_table_scan(self) -> None:
        table = _QueryCaptureTable()
        store = DynamoLifecycleStore(table)
        store.list_memberships(
            customer_id=_CUSTOMER_ID,
            deployment_id=_DEPLOYMENT_ID,
            state=MembershipState.ACTIVE,
            cursor=None,
            limit=10,
        )
        query = table.queries[0]
        assert "KeyConditionExpression" in query

    def test_key_condition_uses_both_aliases(self) -> None:
        """The KeyConditionExpression must reference both aliases."""
        table = _QueryCaptureTable()
        store = DynamoLifecycleStore(table)
        store.list_memberships(
            customer_id=_CUSTOMER_ID,
            deployment_id=_DEPLOYMENT_ID,
            state=MembershipState.ACTIVE,
            cursor=None,
            limit=10,
        )
        query = table.queries[0]
        kce = query["KeyConditionExpression"]
        assert "#state_key" in kce
        assert "#membership_reference" in kce

    def test_non_state_query_uses_consistent_read(self) -> None:
        """A non-state query (state=None) uses the table, not a GSI,
        and can use ConsistentRead."""
        table = _QueryCaptureTable()
        store = DynamoLifecycleStore(table)
        store.list_memberships(
            customer_id=_CUSTOMER_ID,
            deployment_id=_DEPLOYMENT_ID,
            state=None,
            cursor=None,
            limit=10,
        )
        query = table.queries[0]
        assert "IndexName" not in query
        assert query.get("ConsistentRead") is True


# ═══════════════════════════════════════════════════════════════════════════
# SECURITY / ABUSE-CASE TESTS
# ═══════════════════════════════════════════════════════════════════════════

class TestSecurityAbuseCases:
    """Adversarial scenarios that must fail closed."""

    def test_cross_customer_membership_denied(self) -> None:
        membership = _membership_with_version(Decimal("1"))
        membership["customer_id"] = "cust_99ZZZZZZZZZZZZZZZZZZZZZZZZ"
        reader = MagicMock()
        reader.get_membership.return_value = membership
        processor = _make_processor(membership_reader=reader)
        with pytest.raises(PreTokenDenied) as exc_info:
            processor.handle(_make_event())
        assert exc_info.value.reason_code == "foreign_binding"

    def test_cross_deployment_membership_denied(self) -> None:
        membership = _membership_with_version(Decimal("1"))
        membership["deployment_id"] = "dep_99ZZZZZZZZZZZZZZZZZZZZZZZZ"
        reader = MagicMock()
        reader.get_membership.return_value = membership
        processor = _make_processor(membership_reader=reader)
        with pytest.raises(PreTokenDenied) as exc_info:
            processor.handle(_make_event())
        assert exc_info.value.reason_code == "foreign_binding"

    def test_wrong_subject_denied(self) -> None:
        membership = _membership_with_version(Decimal("1"))
        membership["subject"] = "b2c3d4e5-5678-4abc-9def-aabbccddeeff"
        reader = MagicMock()
        reader.get_membership.return_value = membership
        processor = _make_processor(membership_reader=reader)
        with pytest.raises(PreTokenDenied) as exc_info:
            processor.handle(_make_event())
        assert exc_info.value.reason_code == "conflicting_binding"

    def test_inactive_membership_denied(self) -> None:
        membership = _membership_with_version(Decimal("1"))
        membership["state"] = "inactive"
        reader = MagicMock()
        reader.get_membership.return_value = membership
        processor = _make_processor(membership_reader=reader)
        with pytest.raises(PreTokenDenied) as exc_info:
            processor.handle(_make_event())
        assert exc_info.value.reason_code == "inactive_membership"

    def test_unknown_role_denied(self) -> None:
        membership = _membership_with_version(Decimal("1"))
        membership["role_id"] = "super_admin"
        reader = MagicMock()
        reader.get_membership.return_value = membership
        processor = _make_processor(membership_reader=reader)
        with pytest.raises(PreTokenDenied) as exc_info:
            processor.handle(_make_event())
        assert exc_info.value.reason_code == "unknown_role"

    def test_stale_policy_version_denied(self) -> None:
        membership = _membership_with_version(Decimal("1"))
        membership["policy_version"] = "policy-v999"
        reader = MagicMock()
        reader.get_membership.return_value = membership
        processor = _make_processor(membership_reader=reader)
        with pytest.raises(PreTokenDenied) as exc_info:
            processor.handle(_make_event())
        assert exc_info.value.reason_code == "stale_authorization_contract"

    def test_dependency_failure_denies(self) -> None:
        reader = MagicMock()
        reader.get_membership.side_effect = RuntimeError("db down")
        processor = _make_processor(membership_reader=reader)
        with pytest.raises(PreTokenDenied) as exc_info:
            processor.handle(_make_event())
        assert exc_info.value.reason_code == "membership_dependency_unavailable"
