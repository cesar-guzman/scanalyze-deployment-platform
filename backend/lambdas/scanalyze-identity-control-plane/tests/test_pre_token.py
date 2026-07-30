from __future__ import annotations

import copy
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

import pytest

from identity_control_plane.pre_token import PreTokenDenied, PreTokenProcessor


CUSTOMER_ID = "cust_01HZX3YQ8J4F6A2B7C9D0E1G5K"
DEPLOYMENT_ID = "dep_01HZX3YQ8J4F6A2B7C9D0E1G5K"
FOREIGN_CUSTOMER_ID = "cust_01HZX3YQ8J4F6A2B7C9D0E1G5M"
FOREIGN_DEPLOYMENT_ID = "dep_01HZX3YQ8J4F6A2B7C9D0E1G5M"
SUBJECT = "00000000-0000-4000-8000-000000000001"
USER_POOL_ID = "us-east-1_SYNTHETIC"
CLIENT_ID = "syntheticspaclient"
POLICY_DIGEST = f"sha256:{'a' * 64}"
NOW = datetime(2026, 7, 13, 12, 0, tzinfo=timezone.utc)
SENSITIVE_CANARIES = {
    "SENSITIVE_CANARY_ACCESS_VALUE",
    "SENSITIVE_CANARY_CLIENT_VALUE",
    "SENSITIVE_CANARY_PAYLOAD_VALUE",
    SUBJECT,
    CUSTOMER_ID,
    DEPLOYMENT_ID,
}


def _config() -> dict[str, Any]:
    return {
        "human_runtime_enabled": True,
        "expected_customer_id": CUSTOMER_ID,
        "expected_deployment_id": DEPLOYMENT_ID,
        "expected_user_pool_id": USER_POOL_ID,
        "allowed_client_ids": [CLIENT_ID],
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
    }


def _membership(**overrides: Any) -> dict[str, Any]:
    membership = {
        "schema_version": "enterprise-membership.v1",
        "subject": SUBJECT,
        "principal_type": "user",
        "customer_id": CUSTOMER_ID,
        "deployment_id": DEPLOYMENT_ID,
        "state": "active",
        "role_id": "document_operator",
        "membership_version": 7,
        "authz_schema_version": "enterprise-authorization.v1",
        "scope_catalog_version": "scanalyze.api.v1",
        "role_catalog_version": "enterprise-roles.v1",
        "policy_version": "1.0.0",
        "policy_digest": POLICY_DIGEST,
    }
    membership.update(overrides)
    return membership


def _event(**attribute_overrides: Any) -> dict[str, Any]:
    attributes = {
        "sub": SUBJECT,
        "custom:customerId": CUSTOMER_ID,
        "custom:deployment_id": DEPLOYMENT_ID,
        "email": "synthetic@example.invalid",
    }
    attributes.update(attribute_overrides)
    return {
        "version": "2",
        "triggerSource": "TokenGeneration_Authentication",
        "region": "us-east-1",
        "userPoolId": USER_POOL_ID,
        "userName": SUBJECT,
        "callerContext": {
            "awsSdkVersion": "synthetic",
            "clientId": CLIENT_ID,
        },
        "request": {
            "userAttributes": attributes,
            "groupConfiguration": {
                "groupsToOverride": ["customer_admin"],
                "iamRolesToOverride": ["SENSITIVE_CANARY_PAYLOAD_VALUE"],
                "preferredRole": "SENSITIVE_CANARY_PAYLOAD_VALUE",
            },
            "clientMetadata": {
                "customer_id": FOREIGN_CUSTOMER_ID,
                "deployment_id": FOREIGN_DEPLOYMENT_ID,
                "role_id": "customer_admin",
                "access_token": "SENSITIVE_CANARY_ACCESS_VALUE",
                "opaque": "SENSITIVE_CANARY_CLIENT_VALUE",
            },
        },
        "response": {},
    }


@dataclass
class MembershipReader:
    membership: dict[str, Any] | None
    error: Exception | None = None
    calls: list[dict[str, Any]] = field(default_factory=list)

    def get_membership(self, **binding: Any) -> dict[str, Any] | None:
        self.calls.append(binding)
        if self.error is not None:
            raise self.error
        return copy.deepcopy(self.membership)


@dataclass
class AuditSink:
    events: list[dict[str, Any]] = field(default_factory=list)

    def emit(self, event: dict[str, Any]) -> None:
        self.events.append(copy.deepcopy(event))


def _processor(
    membership: dict[str, Any] | None = None,
    *,
    reader_error: Exception | None = None,
    audit: AuditSink | None = None,
) -> tuple[PreTokenProcessor, MembershipReader, AuditSink]:
    reader = MembershipReader(
        _membership() if membership is None else membership,
        error=reader_error,
    )
    audit_sink = audit or AuditSink()
    processor = PreTokenProcessor(
        config=_config(),
        membership_reader=reader,
        audit_sink=audit_sink,
        clock=lambda: NOW,
        logger=logging.getLogger("scanalyze.identity.pre_token.test"),
    )
    return processor, reader, audit_sink


def _deny_reason(processor: PreTokenProcessor, event: dict[str, Any]) -> str:
    with pytest.raises(PreTokenDenied) as exc_info:
        processor.handle(event)
    return exc_info.value.reason_code


def test_valid_membership_emits_only_canonical_access_token_claims() -> None:
    processor, reader, audit = _processor()

    result = processor.handle(_event())

    assert reader.calls == [
        {
            "subject": SUBJECT,
            "customer_id": CUSTOMER_ID,
            "deployment_id": DEPLOYMENT_ID,
        }
    ]
    override = result["response"]["claimsAndScopeOverrideDetails"]
    assert "idTokenGeneration" not in override
    assert override["groupOverrideDetails"] == {
        "groupsToOverride": [],
        "iamRolesToOverride": [],
    }
    claims = override["accessTokenGeneration"]["claimsToAddOrOverride"]
    assert claims == {
        "custom:customerId": CUSTOMER_ID,
        "custom:deployment_id": DEPLOYMENT_ID,
        "principal_type": "user",
        "membership_state": "active",
        "role_id": "document_operator",
        "membership_version": "7",
        "authz_schema_version": "enterprise-authorization.v1",
        "scope_catalog_version": "scanalyze.api.v1",
        "role_catalog_version": "enterprise-roles.v1",
        "policy_version": "1.0.0",
        "policy_digest": POLICY_DIGEST,
    }
    assert audit.events[-1]["decision"] == "allow"


def test_disabled_human_runtime_explicitly_denies_before_membership_lookup() -> None:
    processor, reader, audit = _processor()
    processor.config["human_runtime_enabled"] = False

    assert _deny_reason(processor, _event()) == "human_runtime_disabled"
    assert reader.calls == []
    assert audit.events[-1]["reason_code"] == "human_runtime_disabled"


def test_provider_groups_and_client_metadata_never_establish_authority() -> None:
    event = _event()
    event["request"]["groupConfiguration"]["groupsToOverride"] = [
        "customer_admin",
        "arbitrary_superuser",
    ]
    event["request"]["clientMetadata"]["role_id"] = "customer_admin"
    processor, _, _ = _processor(_membership(role_id="auditor"))

    result = processor.handle(event)

    override = result["response"]["claimsAndScopeOverrideDetails"]
    assert override["groupOverrideDetails"]["groupsToOverride"] == []
    assert (
        override["accessTokenGeneration"]["claimsToAddOrOverride"]["role_id"]
        == "auditor"
    )


@pytest.mark.parametrize(
    ("attribute", "value", "reason"),
    [
        ("sub", None, "missing_binding"),
        ("custom:customerId", None, "missing_binding"),
        ("custom:deployment_id", None, "missing_binding"),
        ("sub", "", "malformed_binding"),
        ("custom:customerId", "customer-one", "malformed_binding"),
        ("custom:deployment_id", "deployment-one", "malformed_binding"),
        ("custom:customerId", FOREIGN_CUSTOMER_ID, "foreign_binding"),
        ("custom:deployment_id", FOREIGN_DEPLOYMENT_ID, "foreign_binding"),
    ],
)
def test_missing_malformed_or_foreign_event_binding_is_denied_before_lookup(
    attribute: str,
    value: str | None,
    reason: str,
) -> None:
    event = _event()
    if value is None:
        del event["request"]["userAttributes"][attribute]
    else:
        event["request"]["userAttributes"][attribute] = value
    processor, reader, _ = _processor()

    assert _deny_reason(processor, event) == reason
    assert reader.calls == []


@pytest.mark.parametrize(
    ("membership_overrides", "reason"),
    [
        ({"subject": "00000000-0000-4000-8000-000000000002"}, "conflicting_binding"),
        ({"customer_id": FOREIGN_CUSTOMER_ID}, "foreign_binding"),
        ({"deployment_id": FOREIGN_DEPLOYMENT_ID}, "foreign_binding"),
        ({"state": "invited"}, "inactive_membership"),
        ({"state": "suspended"}, "inactive_membership"),
        ({"state": "revoked"}, "inactive_membership"),
        ({"principal_type": "m2m"}, "conflicting_principal_type"),
        ({"role_id": "unknown_superuser"}, "unknown_role"),
    ],
)
def test_foreign_conflicting_or_inactive_membership_is_denied(
    membership_overrides: dict[str, Any],
    reason: str,
) -> None:
    processor, _, _ = _processor(_membership(**membership_overrides))

    assert _deny_reason(processor, _event()) == reason


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("membership_version", ""),
        ("authz_schema_version", "enterprise-authorization.v0"),
        ("scope_catalog_version", "scanalyze.api.v0"),
        ("role_catalog_version", "enterprise-roles.v0"),
        ("policy_version", "0.9.0"),
        ("policy_digest", f"sha256:{'b' * 64}"),
        ("policy_digest", "malformed"),
    ],
)
def test_stale_or_malformed_versions_and_digest_are_denied(
    field: str,
    value: str,
) -> None:
    processor, _, _ = _processor(_membership(**{field: value}))

    assert _deny_reason(processor, _event()) == "stale_authorization_contract"


def test_missing_membership_is_denied() -> None:
    processor, _, _ = _processor({})
    processor.membership_reader.membership = None

    assert _deny_reason(processor, _event()) == "membership_not_authorized"


@pytest.mark.parametrize(
    ("path", "value", "reason"),
    [
        (("version",), "1", "unsupported_event"),
        (("version",), "3", "unsupported_event"),
        (("triggerSource",), "TokenGeneration_ClientCredentials", "unsupported_event"),
        (("triggerSource",), "TokenGeneration_NewPasswordChallenge", "unsupported_event"),
        (("userPoolId",), "us-east-1_FOREIGN", "foreign_identity_provider"),
        (("callerContext", "clientId"), "foreignclient", "foreign_client"),
    ],
)
def test_unsupported_or_foreign_event_is_denied_before_lookup(
    path: tuple[str, ...],
    value: str,
    reason: str,
) -> None:
    event = _event()
    target = event
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = value
    processor, reader, _ = _processor()

    assert _deny_reason(processor, event) == reason
    assert reader.calls == []


def test_membership_dependency_timeout_fails_closed() -> None:
    processor, _, audit = _processor(reader_error=TimeoutError("dependency timeout"))

    assert _deny_reason(processor, _event()) == "membership_dependency_unavailable"
    assert audit.events[-1]["decision"] == "deny"


def test_denial_logs_and_audit_are_sanitized(caplog: pytest.LogCaptureFixture) -> None:
    processor, _, audit = _processor(reader_error=TimeoutError("dependency timeout"))
    caplog.set_level(logging.INFO, logger="scanalyze.identity.pre_token.test")

    assert _deny_reason(processor, _event()) == "membership_dependency_unavailable"

    serialized_logs = "\n".join(record.getMessage() for record in caplog.records)
    serialized_audit = repr(audit.events)
    for canary in SENSITIVE_CANARIES:
        assert canary not in serialized_logs
        assert canary not in serialized_audit
    assert "userAttributes" not in serialized_logs
    assert "clientMetadata" not in serialized_logs
    assert "groupConfiguration" not in serialized_logs
