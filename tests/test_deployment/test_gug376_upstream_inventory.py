"""Fail-closed tests for the private GUG-376 provider inventory."""

from __future__ import annotations

import copy
from datetime import UTC, datetime, timedelta

import pytest

from tooling.platform_authority_gug365_upstream_inventory import (
    READ_ONLY_ACTION_ALLOWLIST,
    SURFACES,
    UpstreamInventoryError,
    build_inventory_snapshot,
    build_raw_provider_snapshot,
    canonical_digest,
    certify_raw_provider_sessions,
    certify_stable_inventory,
    collect_paginated,
    surface_record,
    validate_inventory_snapshot,
    validate_raw_provider_snapshot,
)


COLLECTED = datetime(2026, 8, 13, 20, 0, tzinfo=UTC)
DIGEST = "sha256:" + "1" * 64
SECOND_DIGEST = "sha256:" + "2" * 64
MERGE = "a1999d0f9a885a98e443a5c8e9d4c9f7dba04d86"
TREE = "0a1171aae5c3fb8ccb8c7e62cbfbd780f91c700e"


def _surface(resource: dict[str, object] | None = None) -> dict[str, object]:
    return surface_record(
        classification=(
            "EXACT_PRESENT_NO_TOUCH" if resource else "ABSENT_READY"
        ),
        resources=[] if resource is None else [resource],
        page_digests=[DIGEST],
        required_read_actions=["s3:ListBucket"],
    )


def _snapshot(*, collected_at: datetime = COLLECTED) -> dict[str, object]:
    return build_inventory_snapshot(
        source_merge_sha=MERGE,
        source_tree_sha=TREE,
        account_binding_digest=DIGEST,
        management_binding_digest=DIGEST,
        caller_identity_digest=DIGEST,
        session_identifier_digest=DIGEST,
        session_expires_at=collected_at + timedelta(minutes=30),
        collected_at=collected_at,
        surfaces={name: _surface() for name in SURFACES},
    )


def _provider_pages() -> dict[str, dict[str, object]]:
    return {
        name: collect_paginated(
            lambda _token, surface=name: {
                "Items": [
                    {
                        "surface": surface,
                        "provider_fact_digest": canonical_digest(surface),
                    }
                ]
            },
            items_key="Items",
        )
        for name in SURFACES
    }


def _signed_calls(started_at: datetime) -> list[dict[str, object]]:
    surface_actions = {
        "s3": "s3:ListAllMyBuckets",
        "kms": "kms:ListKeys",
        "signer": "signer:ListSigningProfiles",
        "lambda_code_signing": "lambda:ListCodeSigningConfigs",
        "lambda_runtime": "lambda:ListFunctions",
        "identity_center": "sso:ListInstances",
        "identity_store": "identitystore:DescribeUser",
        "iam_roles": "iam:ListRoles",
        "artifact_objects": "s3:ListBucketVersions",
    }
    calls: list[dict[str, object]] = [
        {
            "action": "sts:GetCallerIdentity",
            "surface": None,
            "called_at": started_at + timedelta(seconds=1),
            "response_digest": canonical_digest("caller"),
            "pagination_complete": True,
        }
    ]
    for offset, (surface, action) in enumerate(surface_actions.items(), start=2):
        calls.append(
            {
                "action": action,
                "surface": surface,
                "called_at": started_at + timedelta(seconds=offset),
                "response_digest": canonical_digest({"action": action}),
                "pagination_complete": True,
            }
        )
    return calls


def _runtime_evidence(observed_at: datetime) -> dict[str, object]:
    runtime_arn = "arn:aws:lambda:us-east-1::runtime:" + "a" * 64
    record: dict[str, object] = {
        "runtime": "python3.12",
        "update_runtime_on": "Manual",
        "runtime_version_arn": runtime_arn,
        "runtime_version_arn_digest": canonical_digest(runtime_arn),
        "source_function_arn_digest": DIGEST,
        "source_function_version": "7",
        "function_configuration_digest": DIGEST,
        "runtime_management_config_digest": SECOND_DIGEST,
        "provider_backed": True,
        "readback_complete": True,
        "evidence_collected_at": observed_at.isoformat().replace("+00:00", "Z"),
    }
    record["runtime_evidence_digest"] = canonical_digest(record)
    return record


def _raw_snapshot(
    *,
    started_at: datetime = COLLECTED,
    session_identifier_digest: str = DIGEST,
    session_source: str = "DIRECT_SSO",
    session_chain_depth: int = 0,
    signed_calls: list[dict[str, object]] | None = None,
) -> dict[str, object]:
    return build_raw_provider_snapshot(
        session_source=session_source,
        session_chain_depth=session_chain_depth,
        credential_source_digest=DIGEST,
        account_binding_digest=DIGEST,
        caller_identity_digest=DIGEST,
        session_identifier_digest=session_identifier_digest,
        session_started_at=started_at,
        session_expires_at=started_at + timedelta(minutes=30),
        collected_at=started_at + timedelta(seconds=20),
        signed_calls=_signed_calls(started_at) if signed_calls is None else signed_calls,
        provider_pages=_provider_pages(),
        runtime_evidence=_runtime_evidence(started_at + timedelta(seconds=11)),
    )


def test_collect_paginated_requires_terminal_complete_page() -> None:
    pages = {
        None: {"Items": [{"id": "a"}], "NextToken": "page-2"},
        "page-2": {"Items": [{"id": "b"}]},
    }

    result = collect_paginated(lambda token: pages[token], items_key="Items")

    assert result["complete"] is True
    assert result["page_count"] == 2
    assert result["item_count"] == 2
    assert result["items"] == [{"id": "a"}, {"id": "b"}]
    assert result["pagination_digest"] == canonical_digest(result["page_digests"])


def test_access_denied_is_not_absence() -> None:
    def denied(_token: str | None) -> dict[str, object]:
        raise PermissionError("provider text must not escape")

    with pytest.raises(UpstreamInventoryError, match="INVENTORY_READ_UNAVAILABLE"):
        collect_paginated(denied, items_key="Items")


@pytest.mark.parametrize(
    "pages,code",
    [
        ({None: {"Items": [], "NextToken": "again"}, "again": {"Items": [], "NextToken": "again"}}, "INVENTORY_PAGINATION_CYCLE"),
        ({None: {"Items": [], "NextToken": "one"}, "one": {"Items": [], "NextToken": "two"}}, "INVENTORY_PAGE_LIMIT_EXCEEDED"),
    ],
)
def test_pagination_cycle_or_limit_fails_closed(
    pages: dict[object, dict[str, object]], code: str
) -> None:
    with pytest.raises(UpstreamInventoryError, match=code):
        collect_paginated(
            lambda token: pages[token],
            items_key="Items",
            maximum_pages=2,
        )


@pytest.mark.parametrize(
    "action",
    [
        "s3:PutObject",
        "kms:CreateKey",
        "signer:StartSigningJob",
        "sso:ProvisionPermissionSet",
        "kms:ScheduleKeyDeletion",
        "lambda:InvokeFunction",
        "sqs:PurgeQueue",
        "iam:PassRole",
        "kms:DisableKey",
        "service:ListResources",
    ],
)
def test_inventory_surface_rejects_write_actions(action: str) -> None:
    with pytest.raises(UpstreamInventoryError, match="INVENTORY_READ_ACTION_INVALID"):
        surface_record(
            classification="ABSENT_READY",
            resources=[],
            page_digests=[DIGEST],
            required_read_actions=[action],
        )


def test_inventory_surface_accepts_only_the_reviewed_exact_allowlist() -> None:
    assert "sts:GetCallerIdentity" in READ_ONLY_ACTION_ALLOWLIST
    assert "kms:Decrypt" in READ_ONLY_ACTION_ALLOWLIST
    assert "lambda:InvokeFunction" not in READ_ONLY_ACTION_ALLOWLIST
    surface_record(
        classification="ABSENT_READY",
        resources=[],
        page_digests=[DIGEST],
        required_read_actions=sorted(READ_ONLY_ACTION_ALLOWLIST),
    )


def test_snapshot_validator_cannot_bypass_the_exact_action_allowlist() -> None:
    snapshot = _snapshot()
    surface = snapshot["surfaces"]["lambda_runtime"]
    surface["required_read_actions"] = ["lambda:InvokeFunction"]
    surface["surface_digest"] = canonical_digest(
        {key: item for key, item in surface.items() if key != "surface_digest"}
    )
    snapshot["inventory_digest"] = canonical_digest(
        {
            key: item
            for key, item in snapshot.items()
            if key != "inventory_digest"
        }
    )

    with pytest.raises(UpstreamInventoryError, match="INVENTORY_READ_ACTION_INVALID"):
        validate_inventory_snapshot(snapshot)


def test_raw_provider_snapshot_proves_direct_sso_sts_first_and_zero_mutations() -> None:
    snapshot = _raw_snapshot()

    validate_raw_provider_snapshot(snapshot)
    assert snapshot["session_source"] == "DIRECT_SSO"
    assert snapshot["session_chained"] is False
    assert snapshot["session_chain_depth"] == 0
    assert snapshot["signed_calls"][0]["action"] == "sts:GetCallerIdentity"
    assert snapshot["signed_calls"][0]["surface"] is None
    assert snapshot["pagination_complete"] is True
    assert set(snapshot["resource_evidence"]) == set(SURFACES)
    assert snapshot["runtime_evidence"]["provider_backed"] is True
    assert snapshot["aws_mutations"] == 0
    assert snapshot["repository_persisted"] is False


def test_raw_provider_snapshot_rejects_any_non_sts_first_call() -> None:
    calls = _signed_calls(COLLECTED)
    calls[0]["action"] = "s3:ListAllMyBuckets"

    with pytest.raises(
        UpstreamInventoryError, match="RAW_PROVIDER_STS_FIRST_REQUIRED"
    ):
        build_raw_provider_snapshot(
            session_source="DIRECT_SSO",
            session_chain_depth=0,
            credential_source_digest=DIGEST,
            account_binding_digest=DIGEST,
            caller_identity_digest=DIGEST,
            session_identifier_digest=DIGEST,
            session_started_at=COLLECTED,
            session_expires_at=COLLECTED + timedelta(minutes=30),
            collected_at=COLLECTED + timedelta(seconds=20),
            signed_calls=calls,
            provider_pages=_provider_pages(),
            runtime_evidence=_runtime_evidence(
                COLLECTED + timedelta(seconds=11)
            ),
        )


@pytest.mark.parametrize(
    "action",
    [
        "kms:ScheduleKeyDeletion",
        "lambda:InvokeFunction",
        "sqs:PurgeQueue",
        "iam:PassRole",
        "kms:DisableKey",
    ],
)
def test_raw_provider_snapshot_rejects_non_allowlisted_actions(action: str) -> None:
    calls = _signed_calls(COLLECTED)
    calls[1]["action"] = action

    with pytest.raises(UpstreamInventoryError, match="RAW_PROVIDER_CALL_INVALID"):
        _raw_snapshot(signed_calls=calls)


def test_raw_provider_snapshot_rejects_incomplete_pagination() -> None:
    pages = _provider_pages()
    pages["s3"]["complete"] = False

    with pytest.raises(
        UpstreamInventoryError, match="RAW_PROVIDER_PAGINATION_INVALID"
    ):
        build_raw_provider_snapshot(
            session_source="DIRECT_SSO",
            session_chain_depth=0,
            credential_source_digest=DIGEST,
            account_binding_digest=DIGEST,
            caller_identity_digest=DIGEST,
            session_identifier_digest=DIGEST,
            session_started_at=COLLECTED,
            session_expires_at=COLLECTED + timedelta(minutes=30),
            collected_at=COLLECTED + timedelta(seconds=20),
            signed_calls=_signed_calls(COLLECTED),
            provider_pages=pages,
            runtime_evidence=_runtime_evidence(
                COLLECTED + timedelta(seconds=11)
            ),
        )


def test_raw_provider_snapshot_rejects_chaining_and_long_lived_sessions() -> None:
    with pytest.raises(
        UpstreamInventoryError, match="RAW_PROVIDER_SESSION_SOURCE_INVALID"
    ):
        _raw_snapshot(session_source="ASSUME_ROLE", session_chain_depth=1)

    chained = _raw_snapshot()
    chained["session_chained"] = True
    chained["raw_provider_digest"] = canonical_digest(
        {
            key: item
            for key, item in chained.items()
            if key != "raw_provider_digest"
        }
    )
    with pytest.raises(UpstreamInventoryError, match="RAW_PROVIDER_CONSTANT_INVALID"):
        validate_raw_provider_snapshot(chained)

    boolean_zero = _raw_snapshot()
    boolean_zero["aws_mutations"] = False
    boolean_zero["raw_provider_digest"] = canonical_digest(
        {
            key: item
            for key, item in boolean_zero.items()
            if key != "raw_provider_digest"
        }
    )
    with pytest.raises(UpstreamInventoryError, match="RAW_PROVIDER_CONSTANT_INVALID"):
        validate_raw_provider_snapshot(boolean_zero)

    with pytest.raises(
        UpstreamInventoryError, match="RAW_PROVIDER_SESSION_TIME_INVALID"
    ):
        build_raw_provider_snapshot(
            session_source="DIRECT_SSO",
            session_chain_depth=0,
            credential_source_digest=DIGEST,
            account_binding_digest=DIGEST,
            caller_identity_digest=DIGEST,
            session_identifier_digest=DIGEST,
            session_started_at=COLLECTED,
            session_expires_at=COLLECTED + timedelta(hours=2),
            collected_at=COLLECTED + timedelta(seconds=20),
            signed_calls=_signed_calls(COLLECTED),
            provider_pages=_provider_pages(),
            runtime_evidence=_runtime_evidence(
                COLLECTED + timedelta(seconds=11)
            ),
        )


def test_two_direct_sso_sessions_certify_stable_raw_provider_facts() -> None:
    first = _raw_snapshot()
    second = _raw_snapshot(
        started_at=COLLECTED + timedelta(minutes=1),
        session_identifier_digest=SECOND_DIGEST,
    )

    stable = certify_raw_provider_sessions(first, second)

    assert stable["stable"] is True
    assert stable["session_source"] == "DIRECT_SSO"
    assert stable["session_count"] == 2
    assert stable["sts_first_every_session"] is True
    assert stable["aws_mutations"] == 0


def test_raw_provider_certification_requires_distinct_sessions() -> None:
    first = _raw_snapshot()
    second = _raw_snapshot(started_at=COLLECTED + timedelta(minutes=1))

    with pytest.raises(
        UpstreamInventoryError, match="RAW_PROVIDER_SESSIONS_NOT_INDEPENDENT"
    ):
        certify_raw_provider_sessions(first, second)


def test_two_complete_snapshots_certify_stable_provider_facts() -> None:
    first = _snapshot()
    second = _snapshot(collected_at=COLLECTED + timedelta(minutes=1))

    stable = certify_stable_inventory(first, second)

    assert stable["stable"] is True
    assert stable["snapshot_count"] == 2
    assert stable["aws_mutations"] == 0


def test_stability_rejects_resource_drift() -> None:
    first = _snapshot()
    second = _snapshot(collected_at=COLLECTED + timedelta(minutes=1))
    surface = _surface({"configuration_digest": DIGEST})
    second["surfaces"]["s3"] = surface
    second["inventory_digest"] = canonical_digest(
        {key: item for key, item in second.items() if key != "inventory_digest"}
    )

    with pytest.raises(UpstreamInventoryError, match="INVENTORY_NOT_STABLE"):
        certify_stable_inventory(first, second)


def test_tampered_surface_or_envelope_digest_is_rejected() -> None:
    snapshot = _snapshot()
    tampered_surface = copy.deepcopy(snapshot)
    tampered_surface["surfaces"]["kms"]["classification"] = (
        "EXACT_PRESENT_NO_TOUCH"
    )
    tampered_surface["inventory_digest"] = canonical_digest(
        {
            key: item
            for key, item in tampered_surface.items()
            if key != "inventory_digest"
        }
    )
    with pytest.raises(UpstreamInventoryError, match="INVENTORY_SURFACE_INVALID"):
        validate_inventory_snapshot(tampered_surface)

    tampered_envelope = _snapshot()
    tampered_envelope["region"] = "us-west-2"
    with pytest.raises(UpstreamInventoryError, match="INVENTORY_CONSTANT_INVALID"):
        validate_inventory_snapshot(tampered_envelope)
