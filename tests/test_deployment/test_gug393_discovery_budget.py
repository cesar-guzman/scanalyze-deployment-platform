"""Focused offline tests for the GUG-393 global discovery budget."""

from __future__ import annotations

import copy
from datetime import UTC, datetime
from hashlib import sha256
import json
from typing import Any

import pytest

from tooling import platform_authority_gug393_discovery_budget as budget


NOW = datetime(2035, 1, 2, 3, 4, 5, tzinfo=UTC)


def _document(**overrides: Any) -> dict[str, Any]:
    value: dict[str, Any] = {
        "record_type": budget.RECORD_TYPE,
        "schema_version": budget.SCHEMA_VERSION,
        "max_network_calls": 4,
        "max_provider_calls": 3,
        "max_credential_vending_calls": 1,
        "max_page_calls": 3,
        "max_response_bytes": 10,
        "max_total_response_bytes": 20,
        "maximum_cost_usd": "0.000000160",
        "cost_model": {
            "fixed_run_cost_usd_upper": "0.000000100",
            "per_network_attempt_cost_usd_upper": "0.000000010",
            "per_projected_response_byte_cost_usd_upper": "0.000000001",
            "pricing_reference_digest": "sha256:" + "a" * 64,
            "valid_from": "2035-01-02T03:00:00Z",
            "valid_until": "2035-01-02T04:00:00Z",
        },
    }
    for key, item in overrides.items():
        if key.startswith("cost_model__"):
            value["cost_model"][key.removeprefix("cost_model__")] = item
        else:
            value[key] = item
    return value


def _summary_digest(value: dict[str, Any]) -> str:
    body = {key: item for key, item in value.items() if key != "summary_digest"}
    encoded = json.dumps(
        body,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")
    return "sha256:" + sha256(encoded).hexdigest()


def _error(value: dict[str, Any], code: str, **kwargs: Any) -> None:
    with pytest.raises(budget.DiscoveryBudgetError) as captured:
        budget.validate_discovery_budget(value, **kwargs)
    assert captured.value.code == code
    assert str(captured.value) == code


def test_validate_detaches_document_and_computes_fixed_point_worst_case() -> None:
    source = _document()
    validated = budget.validate_discovery_budget(source)

    assert validated.document == source
    assert validated.document is not source
    assert validated.document["cost_model"] is not source["cost_model"]
    assert validated.worst_case_cost_nano_usd == 160
    assert validated.digest.startswith("sha256:")
    assert len(validated.digest) == 71

    source["max_network_calls"] = 0
    source["cost_model"]["fixed_run_cost_usd_upper"] = "9.000000000"
    assert validated.document["max_network_calls"] == 4
    assert validated.document["cost_model"]["fixed_run_cost_usd_upper"] == (
        "0.000000100"
    )


@pytest.mark.parametrize(
    "value",
    [
        1,
        0.0,
        "0",
        "0.00000000",
        "0.0000000000",
        "00.000000000",
        "01.000000000",
        "+1.000000000",
        "-1.000000000",
        "1e-9",
        " 1.000000000",
    ],
)
def test_all_usd_values_require_one_canonical_nine_decimal_string(
    value: Any,
) -> None:
    _error(
        _document(maximum_cost_usd=value),
        "DISCOVERY_BUDGET_COST_INVALID",
    )
    _error(
        _document(cost_model__per_network_attempt_cost_usd_upper=value),
        "DISCOVERY_BUDGET_COST_INVALID",
    )


@pytest.mark.parametrize(
    ("field", "invalid"),
    [
        ("max_network_calls", budget.HARD_MAX_NETWORK_CALLS + 1),
        ("max_provider_calls", budget.HARD_MAX_PROVIDER_CALLS + 1),
        (
            "max_credential_vending_calls",
            budget.HARD_MAX_CREDENTIAL_VENDING_CALLS + 1,
        ),
        ("max_page_calls", budget.HARD_MAX_PAGE_CALLS + 1),
        ("max_response_bytes", budget.HARD_MAX_RESPONSE_BYTES + 1),
        (
            "max_total_response_bytes",
            budget.HARD_MAX_TOTAL_RESPONSE_BYTES + 1,
        ),
        ("max_network_calls", -1),
        ("max_provider_calls", True),
    ],
)
def test_hard_ceilings_and_strict_integer_types(field: str, invalid: Any) -> None:
    value = _document()
    value[field] = invalid
    _error(value, "DISCOVERY_BUDGET_HARD_CEILING_EXCEEDED")


def test_limit_relationships_are_closed_and_non_redundant() -> None:
    _error(
        _document(max_provider_calls=5),
        "DISCOVERY_BUDGET_INVALID",
    )
    _error(
        _document(max_page_calls=4),
        "DISCOVERY_BUDGET_INVALID",
    )
    _error(
        _document(max_response_bytes=21),
        "DISCOVERY_BUDGET_INVALID",
    )
    _error(
        _document(
            max_network_calls=4,
            max_provider_calls=1,
            max_credential_vending_calls=1,
        ),
        "DISCOVERY_BUDGET_INVALID",
    )


def test_missing_extra_and_wrong_record_shape_fail_closed() -> None:
    missing = _document()
    missing.pop("maximum_cost_usd")
    _error(missing, "DISCOVERY_BUDGET_INVALID")

    extra = _document()
    extra["inferred_default"] = True
    _error(extra, "DISCOVERY_BUDGET_INVALID")

    _error(
        _document(record_type="scanalyze.platform_authority.other.v1"),
        "DISCOVERY_BUDGET_INVALID",
    )
    _error(_document(schema_version=True), "DISCOVERY_BUDGET_INVALID")


def test_cost_model_is_exact_digest_bound_and_owner_budget_must_cover_it() -> None:
    malformed = _document()
    malformed["cost_model"]["unreviewed_rate"] = "0.000000000"
    _error(malformed, "DISCOVERY_COST_MODEL_INVALID")

    _error(
        _document(cost_model__pricing_reference_digest="not-a-digest"),
        "DISCOVERY_COST_MODEL_INVALID",
    )
    _error(
        _document(cost_model__pricing_reference_digest="sha256:" + "0" * 64),
        "DISCOVERY_COST_MODEL_INVALID",
    )
    _error(
        _document(maximum_cost_usd="0.000000159"),
        "DISCOVERY_COST_BUDGET_INSUFFICIENT",
    )


def test_action_time_validation_requires_an_explicit_active_aware_clock() -> None:
    _error(
        _document(),
        "DISCOVERY_BUDGET_CLOCK_REQUIRED",
        require_active=True,
    )
    _error(
        _document(),
        "DISCOVERY_BUDGET_CLOCK_INVALID",
        now=datetime(2035, 1, 2, 3, 4, 5),
        require_active=True,
    )
    _error(
        _document(),
        "DISCOVERY_COST_MODEL_INACTIVE",
        now=datetime(2035, 1, 2, 4, 0, 0, tzinfo=UTC),
        require_active=True,
    )

    validated = budget.validate_discovery_budget(
        _document(), now=NOW, require_active=True
    )
    assert validated.worst_case_cost_nano_usd == 160


def test_invalid_or_reversed_pricing_window_is_rejected_historically() -> None:
    _error(
        _document(cost_model__valid_from="2035-01-02T03:00:00.1Z"),
        "DISCOVERY_BUDGET_WINDOW_INVALID",
    )
    _error(
        _document(cost_model__valid_from="2035-01-02T04:00:00Z"),
        "DISCOVERY_BUDGET_WINDOW_INVALID",
    )


def test_global_ledger_counts_provider_pages_vending_bytes_and_cost() -> None:
    ledger = budget.GlobalDiscoveryBudget(
        budget.validate_discovery_budget(_document())
    )

    ledger.reserve_provider_call("sts:GetCallerIdentity", is_page=False)
    ledger.reserve_provider_call("sso:ListInstances", is_page=False)
    ledger.reserve_provider_call("sso:DescribeInstance", is_page=True)
    ledger.record_credential_vend("sso:GetRoleCredentials")
    ledger.record_response(5)
    ledger.record_response(10)

    summary = ledger.summary()
    assert summary == {
        "record_type": budget.SUMMARY_RECORD_TYPE,
        "budget_digest": summary["budget_digest"],
        "cost_model_digest": summary["cost_model_digest"],
        "provider_calls": 3,
        "credential_vending_calls": 1,
        "network_calls": 4,
        "page_calls": 2,
        "projected_response_bytes": 15,
        "modeled_cost_nano_usd": 155,
        "summary_digest": summary["summary_digest"],
    }
    assert summary["summary_digest"] == _summary_digest(summary)
    assert set(summary) == {
        "record_type",
        "budget_digest",
        "cost_model_digest",
        "provider_calls",
        "credential_vending_calls",
        "network_calls",
        "page_calls",
        "projected_response_bytes",
        "modeled_cost_nano_usd",
        "summary_digest",
    }
    assert "cost_model" not in summary
    assert "operations" not in summary


def test_provider_cap_failure_does_not_increment_any_counter() -> None:
    value = _document(
        max_network_calls=2,
        max_provider_calls=1,
        max_credential_vending_calls=1,
        max_page_calls=1,
        maximum_cost_usd="0.000000140",
    )
    ledger = budget.GlobalDiscoveryBudget(budget.validate_discovery_budget(value))
    ledger.reserve_provider_call("sts:GetCallerIdentity", is_page=False)
    before = ledger.summary()

    with pytest.raises(budget.DiscoveryBudgetError) as captured:
        ledger.reserve_provider_call("sso:DescribeInstance", is_page=False)
    assert captured.value.code == "DISCOVERY_PROVIDER_CALL_BUDGET_EXCEEDED"
    after = ledger.summary()
    assert {
        key: after[key]
        for key in (
            "provider_calls",
            "credential_vending_calls",
            "network_calls",
            "page_calls",
            "projected_response_bytes",
            "modeled_cost_nano_usd",
        )
    } == {
        key: before[key]
        for key in (
            "provider_calls",
            "credential_vending_calls",
            "network_calls",
            "page_calls",
            "projected_response_bytes",
            "modeled_cost_nano_usd",
        )
    }


def test_global_network_cap_applies_across_provider_and_vending() -> None:
    value = _document(
        max_network_calls=2,
        max_provider_calls=2,
        max_credential_vending_calls=1,
        max_page_calls=2,
        maximum_cost_usd="0.000000140",
    )
    ledger = budget.GlobalDiscoveryBudget(budget.validate_discovery_budget(value))
    ledger.reserve_provider_call("sts:GetCallerIdentity", is_page=False)
    ledger.record_credential_vend("sso:GetRoleCredentials")
    before = ledger.summary()

    with pytest.raises(budget.DiscoveryBudgetError) as captured:
        ledger.reserve_provider_call("sso:DescribeInstance", is_page=False)
    assert captured.value.code == "DISCOVERY_NETWORK_CALL_BUDGET_EXCEEDED"
    assert ledger.summary()["network_calls"] == before["network_calls"] == 2
    assert ledger.summary()["provider_calls"] == before["provider_calls"] == 1


def test_page_cap_applies_to_list_verb_or_explicit_page_before_increment() -> None:
    value = _document(
        max_network_calls=3,
        max_provider_calls=2,
        max_credential_vending_calls=1,
        max_page_calls=0,
        maximum_cost_usd="0.000000150",
    )
    ledger = budget.GlobalDiscoveryBudget(budget.validate_discovery_budget(value))

    with pytest.raises(budget.DiscoveryBudgetError) as listed:
        ledger.reserve_provider_call("sso:ListInstances", is_page=False)
    assert listed.value.code == "DISCOVERY_PAGE_CALL_BUDGET_EXCEEDED"
    assert ledger.summary()["provider_calls"] == 0
    assert ledger.summary()["network_calls"] == 0

    with pytest.raises(budget.DiscoveryBudgetError) as explicit:
        ledger.reserve_provider_call("sso:DescribeInstance", is_page=True)
    assert explicit.value.code == "DISCOVERY_PAGE_CALL_BUDGET_EXCEEDED"
    assert ledger.summary()["page_calls"] == 0


def test_only_exact_sso_role_credential_vending_is_accepted() -> None:
    ledger = budget.GlobalDiscoveryBudget(
        budget.validate_discovery_budget(_document())
    )
    for operation in (
        "sso-oidc:CreateToken",
        "sts:AssumeRole",
        "sso:GetRoleCredential",
        "",
    ):
        with pytest.raises(budget.DiscoveryBudgetError) as captured:
            ledger.record_credential_vend(operation)
        assert (
            captured.value.code
            == "DISCOVERY_CREDENTIAL_VENDING_OPERATION_NOT_ALLOWED"
        )
    assert ledger.summary()["credential_vending_calls"] == 0
    assert ledger.summary()["network_calls"] == 0

    ledger.record_credential_vend("sso:GetRoleCredentials")
    with pytest.raises(budget.DiscoveryBudgetError) as captured:
        ledger.record_credential_vend("sso:GetRoleCredentials")
    assert captured.value.code == "DISCOVERY_CREDENTIAL_VENDING_BUDGET_EXCEEDED"
    assert ledger.summary()["credential_vending_calls"] == 1
    assert ledger.summary()["network_calls"] == 1


def test_vending_cannot_be_misclassified_as_a_provider_call() -> None:
    ledger = budget.GlobalDiscoveryBudget(
        budget.validate_discovery_budget(_document())
    )
    with pytest.raises(budget.DiscoveryBudgetError) as captured:
        ledger.reserve_provider_call("sso:GetRoleCredentials", is_page=False)
    assert captured.value.code == "DISCOVERY_PROVIDER_OPERATION_INVALID"
    assert ledger.summary()["network_calls"] == 0


def test_response_limits_are_per_response_and_cumulative_fail_before_increment() -> None:
    value = _document(
        max_response_bytes=4,
        max_total_response_bytes=6,
        maximum_cost_usd="0.000000146",
    )
    ledger = budget.GlobalDiscoveryBudget(budget.validate_discovery_budget(value))

    with pytest.raises(budget.DiscoveryBudgetError) as per_response:
        ledger.record_response(5)
    assert per_response.value.code == "DISCOVERY_RESPONSE_BYTE_BUDGET_EXCEEDED"
    assert ledger.summary()["projected_response_bytes"] == 0

    ledger.record_response(4)
    before = ledger.summary()
    with pytest.raises(budget.DiscoveryBudgetError) as cumulative:
        ledger.record_response(3)
    assert (
        cumulative.value.code
        == "DISCOVERY_TOTAL_RESPONSE_BYTE_BUDGET_EXCEEDED"
    )
    after = ledger.summary()
    assert after["projected_response_bytes"] == before["projected_response_bytes"] == 4
    assert after["modeled_cost_nano_usd"] == before["modeled_cost_nano_usd"]


@pytest.mark.parametrize("value", [-1, True, 1.5, "1"])
def test_response_byte_count_is_a_nonnegative_exact_integer(value: Any) -> None:
    ledger = budget.GlobalDiscoveryBudget(
        budget.validate_discovery_budget(_document())
    )
    with pytest.raises(budget.DiscoveryBudgetError) as captured:
        ledger.record_response(value)  # type: ignore[arg-type]
    assert captured.value.code == "DISCOVERY_RESPONSE_BYTE_COUNT_INVALID"
    assert ledger.summary()["projected_response_bytes"] == 0


def test_zero_budget_is_an_explicit_valid_deny() -> None:
    value = _document(
        max_network_calls=0,
        max_provider_calls=0,
        max_credential_vending_calls=0,
        max_page_calls=0,
        max_response_bytes=0,
        max_total_response_bytes=0,
        maximum_cost_usd="0.000000000",
        cost_model__fixed_run_cost_usd_upper="0.000000000",
        cost_model__per_network_attempt_cost_usd_upper="0.000000000",
        cost_model__per_projected_response_byte_cost_usd_upper="0.000000000",
    )
    ledger = budget.GlobalDiscoveryBudget(budget.validate_discovery_budget(value))
    assert ledger.summary()["modeled_cost_nano_usd"] == 0
    with pytest.raises(budget.DiscoveryBudgetError) as captured:
        ledger.reserve_provider_call("sts:GetCallerIdentity", is_page=False)
    assert captured.value.code == "DISCOVERY_PROVIDER_CALL_BUDGET_EXCEEDED"
    assert ledger.summary()["network_calls"] == 0


def test_global_ledger_rejects_a_forged_validated_binding() -> None:
    validated = budget.validate_discovery_budget(_document())
    forged = budget.ValidatedDiscoveryBudget(
        document=copy.deepcopy(validated.document),
        digest="sha256:" + "0" * 64,
        worst_case_cost_nano_usd=validated.worst_case_cost_nano_usd,
    )
    with pytest.raises(budget.DiscoveryBudgetError) as captured:
        budget.GlobalDiscoveryBudget(forged)
    assert captured.value.code == "DISCOVERY_BUDGET_BINDING_INVALID"


def test_summary_is_a_fresh_digest_bound_copy() -> None:
    ledger = budget.GlobalDiscoveryBudget(
        budget.validate_discovery_budget(_document())
    )
    first = ledger.summary()
    first["provider_calls"] = 999
    first["budget_digest"] = "changed"

    second = ledger.summary()
    assert second["provider_calls"] == 0
    assert second["budget_digest"].startswith("sha256:")
    assert second["summary_digest"] == _summary_digest(second)


def test_budget_evidence_is_detached_and_replays_to_the_exact_summary() -> None:
    validated = budget.validate_discovery_budget(_document())
    ledger = budget.GlobalDiscoveryBudget(validated)
    ledger.record_credential_vend("sso:GetRoleCredentials")
    ledger.reserve_provider_call("sts:GetCallerIdentity", is_page=False)
    ledger.record_response(3)
    ledger.reserve_provider_call("sso:ListInstances", is_page=False)
    ledger.record_response(4)

    events = ledger.evidence_events()
    assert budget.replay_discovery_budget_evidence(
        validated, events
    ) == ledger.summary()
    assert [event["ordinal"] for event in events] == list(
        range(1, len(events) + 1)
    )
    assert [event["kind"] for event in events] == [
        "CREDENTIAL_VEND",
        "PROVIDER_CALL",
        "PROJECTED_RESPONSE",
        "PROVIDER_CALL",
        "PROJECTED_RESPONSE",
    ]

    events[1]["operation"] = "iam:DeleteRole"
    assert ledger.evidence_events()[1]["operation"] == "sts:GetCallerIdentity"


@pytest.mark.parametrize(
    ("mutation", "expected_code"),
    (
        ("ordinal", "DISCOVERY_BUDGET_EVIDENCE_INVALID"),
        ("extra_field", "DISCOVERY_BUDGET_EVIDENCE_INVALID"),
        ("response_before_call", "DISCOVERY_BUDGET_EVIDENCE_INVALID"),
        ("second_call_pending", "DISCOVERY_BUDGET_EVIDENCE_INVALID"),
        ("missing_response", "DISCOVERY_BUDGET_EVIDENCE_INVALID"),
    ),
)
def test_budget_evidence_replay_rejects_tampering(
    mutation: str, expected_code: str,
) -> None:
    validated = budget.validate_discovery_budget(_document())
    ledger = budget.GlobalDiscoveryBudget(validated)
    ledger.reserve_provider_call("sts:GetCallerIdentity", is_page=False)
    ledger.record_response(3)
    events = ledger.evidence_events()
    changed = copy.deepcopy(events)
    if mutation == "ordinal":
        changed[0]["ordinal"] = 2
    elif mutation == "extra_field":
        changed[0]["unreviewed"] = True
    elif mutation == "response_before_call":
        changed.reverse()
        for ordinal, event in enumerate(changed, 1):
            event["ordinal"] = ordinal
    elif mutation == "second_call_pending":
        changed.insert(
            1,
            {
                "ordinal": 2,
                "kind": "PROVIDER_CALL",
                "operation": "sso:ListInstances",
                "page_call": True,
            },
        )
        for ordinal, event in enumerate(changed, 1):
            event["ordinal"] = ordinal
    else:
        changed.pop()

    with pytest.raises(budget.DiscoveryBudgetError) as captured:
        budget.replay_discovery_budget_evidence(validated, changed)
    assert captured.value.code == expected_code


@pytest.mark.parametrize("invalid_sequence", ("second_call", "response_first"))
def test_budget_evidence_export_rejects_noncausal_runtime_sequence(
    invalid_sequence: str,
) -> None:
    ledger = budget.GlobalDiscoveryBudget(
        budget.validate_discovery_budget(_document())
    )
    if invalid_sequence == "second_call":
        ledger.reserve_provider_call("sts:GetCallerIdentity", is_page=False)
        ledger.reserve_provider_call("sso:ListInstances", is_page=False)
        ledger.record_response(3)
        ledger.record_response(4)
    else:
        ledger.record_response(3)
        ledger.reserve_provider_call("sts:GetCallerIdentity", is_page=False)

    with pytest.raises(budget.DiscoveryBudgetError) as captured:
        ledger.evidence_events()
    assert captured.value.code == "DISCOVERY_BUDGET_EVIDENCE_INCOMPLETE"
