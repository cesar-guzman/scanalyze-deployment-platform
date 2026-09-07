"""GUG-377 repository-only provider materializer security contracts."""

from __future__ import annotations

import copy
from dataclasses import replace
import inspect
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest
from jsonschema import Draft202012Validator

from tooling.platform_authority_gug365_upstream_materializer import (
    AttemptLedger,
    MaterializationError,
    build_repository_plan,
    main as materializer_main,
    materialize_repository_plan,
    reconcile_uncertain_operation,
    validate_public_evidence,
    validate_materialization_result,
    validate_repository_contract,
    validate_repository_plan,
)
from tooling.platform_authority_gug365_upstream_dry_run_runner import (
    run_repository_plan,
)
from tooling.platform_authority_gug365_upstream_provider_contracts import (
    STOP_LIVE_ORCHESTRATOR_NOT_IMPLEMENTED,
    InertProviderAdapter,
    ProviderAdapter,
    ProviderContractError,
    ProviderStatus,
    ReconciliationStatus,
    ScriptedProviderAdapter,
    bind_consumed_slot_projections,
    build_live_provider_adapter,
    operation_from_record,
    provider_result_projection_digest,
    provider_slot_projections,
)
from tooling.platform_authority_gug365_upstream_prerequisites import canonical_digest
from tooling.validate_schema import find_schema_for_fixture


ROOT = Path(__file__).resolve().parents[2]
SCHEMAS = ROOT / "schemas"
FIXTURES = ROOT / "fixtures"
CLI = ROOT / "scripts/deployment/platform-authority-gug365-upstream-materializer.py"
V2_FAMILIES = ("inventory", "plan", "final-handoff")
AWS_ENV_KEYS = (
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
    "AWS_PROFILE",
    "AWS_DEFAULT_PROFILE",
    "AWS_WEB_IDENTITY_TOKEN_FILE",
    "AWS_ROLE_ARN",
    "AWS_ENDPOINT_URL",
    "AWS_ENDPOINT_URL_STS",
    "AWS_ENDPOINT_URL_S3",
    "AWS_ENDPOINT_URL_KMS",
    "AWS_ENDPOINT_URL_SIGNER",
    "AWS_ENDPOINT_URL_LAMBDA",
    "AWS_ENDPOINT_URL_SSO",
    "AWS_ENDPOINT_URL_IDENTITYSTORE",
)


class FakeClock:
    def __init__(self) -> None:
        self.value = 0.0
        self.sleeps: list[float] = []

    def now(self) -> float:
        return self.value

    def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.value += seconds


def _plan() -> dict[str, object]:
    return build_repository_plan()


def _operation(plan: dict[str, object], index: int = 0) -> dict[str, object]:
    operations = plan["operations"]
    assert isinstance(operations, list)
    operation = operations[index]
    assert isinstance(operation, dict)
    return operation


def test_repository_plan_is_deterministic_closed_and_exactly_ordered() -> None:
    first = _plan()
    second = _plan()

    assert first == second
    validate_repository_plan(first)
    assert first["record_type"] == (
        "scanalyze.platform_authority.gug365_upstream_plan.v2"
    )
    assert first["schema_version"] == 2
    assert first["implementation_issue"] == "GUG-377"
    assert first["upstream_contract_issue"] == "GUG-376"
    assert first["consumer_issue"] == "GUG-365"
    assert first["live_promotion_status"] == STOP_LIVE_ORCHESTRATOR_NOT_IMPLEMENTED
    assert first["deployment_authorized"] is False
    assert first["production"] is False

    phases = first["phases"]
    operations = first["operations"]
    assert isinstance(phases, list) and len(phases) == 9
    assert isinstance(operations, list) and len(operations) == 30
    assert [item["global_sequence"] for item in operations] == list(range(1, 31))
    assert len({item["operation_id"] for item in operations}) == 30
    assert len({item["operation_kind"] for item in operations}) == 30
    for index, item in enumerate(operations):
        assert item["attempt_limit"] == 1
        assert item["sdk_retry_count"] == 0
        assert item["retry_permitted"] is False
        assert item["ambiguous_outcome"] == "UNCERTAIN_RECONCILE_ONLY"
        expected_dependencies = [] if index == 0 else [operations[index - 1]["operation_id"]]
        assert item["dependencies"] == expected_dependencies


def test_plan_rejects_stale_source_operation_substitution_and_mutable_runtime() -> None:
    plan = _plan()
    cases: list[dict[str, object]] = []

    stale = copy.deepcopy(plan)
    stale["source_manifest"]["source_head_sha"] = "0" * 40
    cases.append(stale)

    substituted = copy.deepcopy(plan)
    substituted["operations"][0]["action"] = "s3:PutObject"
    cases.append(substituted)

    spliced = copy.deepcopy(plan)
    spliced["operations"][28]["operation_kind"] = spliced["operations"][26][
        "operation_kind"
    ]
    cases.append(spliced)

    mutable_runtime = copy.deepcopy(plan)
    mutable_runtime["target_manifest"]["runtime"]["qualifier_policy"] = "$LATEST"
    cases.append(mutable_runtime)

    wrong_region = copy.deepcopy(plan)
    wrong_region["target_manifest"]["region"] = "us-west-2"
    cases.append(wrong_region)

    for candidate in cases:
        with pytest.raises(MaterializationError):
            validate_repository_plan(candidate)


def test_source_manifest_pins_imported_dependencies_and_snapshots_catalogs(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    baseline = _plan()
    sources = {
        item["repository_path"]: item["content_digest"]
        for item in baseline["source_manifest"]["implementation_sources"]
    }
    assert sources[
        "tooling/platform_authority_gug365_upstream_prerequisites.py"
    ] == "sha256:73c335c17515548145cbe950f54c765f9c886f9172b82ebf7de7483f3b7d7945"
    assert sources[
        "tooling/platform_authority_gug365_phase_execution_ledger.py"
    ] == "sha256:ade2d98d3ace73fc41b45e713e762520801c52d4a20703523e6e1db92a32edbc"

    import tooling.platform_authority_gug365_upstream_prerequisites as prerequisites

    changed_fields = set(prerequisites.REQUEST_KEYS["sso:CreateApplication"])
    changed_fields.add("unreviewed_runtime_field")
    monkeypatch.setitem(
        prerequisites.REQUEST_KEYS,
        "sso:CreateApplication",
        changed_fields,
    )
    assert _plan() == baseline


def test_direct_runner_rejects_a_tampered_plan_before_adapter_observation() -> None:
    plan = _plan()
    adapter = ScriptedProviderAdapter.succeeding(plan)
    tampered = copy.deepcopy(plan)
    tampered["target_manifest"]["runtime"]["runtime"] = "python3.11"
    ledger = AttemptLedger.from_plan(tampered)

    with pytest.raises(MaterializationError, match="PLAN_CONTRACT_MISMATCH"):
        run_repository_plan(plan=tampered, adapter=adapter, ledger=ledger)
    assert adapter.write_calls == []
    assert all(
        operation["attempt_count"] == 0
        for operation in ledger.snapshot()["operations"]
    )


def test_target_contract_closes_provider_slots_supply_chain_and_identity() -> None:
    plan = _plan()
    target = plan["target_manifest"]
    slots = target["provider_slots"]
    operations = plan["operations"]

    assert len(slots) == 22
    assert len({slot["slot"] for slot in slots}) == 22
    assert {
        slot
        for operation in operations
        for slot in operation["produced_slots"]
    } == {slot["slot"] for slot in slots}
    assert {
        "broker_signed_object",
        "ledger_factory_signed_object",
    }.issubset(target["resources"])
    assert target["runtime"] == {
        "runtime": "python3.12",
        "architecture": "x86_64",
        "qualifier_policy": "PUBLISHED_VERSION_ONLY",
        "runtime_management_mode": "Manual",
        "provider_provenance": "REQUIRED_LIVE_NOT_PRODUCED",
        "reference_storage": "DIGEST_ONLY",
        "required_provider_projections": [
            "PUBLISHED_QUALIFIER_DIGEST",
            "RUNTIME_CONFIGURATION_DIGEST",
            "RUNTIME_VERSION_REFERENCE_DIGEST",
        ],
    }
    assert target["identity_center"]["two_human_status"] == "NOT_PROVEN"
    assert target["identity_center"]["independent_approval_present"] is False
    assert all(
        item["mutable_reference_permitted"] is False
        for item in target["resources"].values()
    )
    assert all(
        item["live_value_status"] == "NOT_PRODUCED"
        and item["value_storage"] == "TRANSIENT_DIGEST_PROJECTION_ONLY"
        for item in slots
    )


def test_target_drift_spoofing_and_package_splicing_are_fail_closed() -> None:
    plan = _plan()
    candidates: list[dict[str, object]] = []
    for resource in (
        "artifact_bucket",
        "kms_key",
        "broker_signing_job",
        "broker_signed_object",
        "code_signing_config",
    ):
        changed = copy.deepcopy(plan)
        changed["target_manifest"]["resources"][resource]["constraints"].pop()
        candidates.append(changed)

    identity = copy.deepcopy(plan)
    identity["target_manifest"]["identity_center"][
        "independent_approval_present"
    ] = True
    candidates.append(identity)

    slot_spoof = copy.deepcopy(plan)
    slot_spoof["target_manifest"]["provider_slots"][0][
        "producer_operation_kind"
    ] = "BROKER_START_SIGNING_JOB"
    candidates.append(slot_spoof)

    package_splice = copy.deepcopy(plan)
    package_splice["target_manifest"]["package_inputs"][0]["content_digest"] = (
        "sha256:" + "9" * 64
    )
    candidates.append(package_splice)

    for candidate in candidates:
        with pytest.raises(MaterializationError, match="PLAN_CONTRACT_MISMATCH"):
            validate_repository_plan(candidate)


def test_adapter_protocol_is_closed_and_live_construction_always_stops() -> None:
    assert "execute" not in ProviderAdapter.__dict__
    assert "execute" not in inspect.getsource(ProviderAdapter)
    assert "payload" not in inspect.getsource(ProviderAdapter)
    assert InertProviderAdapter().mode == "INERT_DEFAULT"

    with pytest.raises(
        ProviderContractError, match=STOP_LIVE_ORCHESTRATOR_NOT_IMPLEMENTED
    ):
        build_live_provider_adapter()


def test_inert_and_protocol_compatible_custom_adapters_cannot_consume_a_claim() -> None:
    plan = _plan()
    ledger = AttemptLedger.from_plan(plan)
    before = ledger.snapshot()

    with pytest.raises(
        MaterializationError, match=STOP_LIVE_ORCHESTRATOR_NOT_IMPLEMENTED
    ):
        materialize_repository_plan(
            plan=plan, adapter=InertProviderAdapter(), ledger=ledger
        )
    assert ledger.snapshot() == before

    class UnreviewedAdapter:
        mode = "SCRIPTED_TEST"

    with pytest.raises(MaterializationError, match="ADAPTER_NOT_ALLOWLISTED"):
        materialize_repository_plan(
            plan=plan,
            adapter=UnreviewedAdapter(),  # type: ignore[arg-type]
            ledger=ledger,
        )
    assert ledger.snapshot() == before


def test_scripted_adapter_subclasses_are_rejected_by_every_execution_boundary() -> None:
    plan = _plan()
    exact_adapter = ScriptedProviderAdapter.succeeding(plan)

    class UnreviewedSubclass(ScriptedProviderAdapter):
        pass

    with pytest.raises(ProviderContractError, match="ADAPTER_SUBCLASS_FORBIDDEN"):
        UnreviewedSubclass.succeeding(plan)

    subclass_adapter = UnreviewedSubclass(_operations=exact_adapter._operations)
    wrapper_ledger = AttemptLedger.from_plan(plan)
    wrapper_before = wrapper_ledger.snapshot()
    with pytest.raises(MaterializationError, match="ADAPTER_NOT_ALLOWLISTED"):
        materialize_repository_plan(
            plan=plan,
            adapter=subclass_adapter,
            ledger=wrapper_ledger,
        )
    assert wrapper_ledger.snapshot() == wrapper_before

    runner_ledger = AttemptLedger.from_plan(plan)
    runner_before = runner_ledger.snapshot()
    with pytest.raises(ProviderContractError, match="ADAPTER_NOT_ALLOWLISTED"):
        run_repository_plan(
            plan=plan,
            adapter=subclass_adapter,
            ledger=runner_ledger,
        )
    assert runner_ledger.snapshot() == runner_before

def test_scripted_adapter_binds_every_result_to_exact_causal_operation() -> None:
    plan = _plan()
    adapter = ScriptedProviderAdapter.succeeding(plan)
    ledger = AttemptLedger.from_plan(plan)
    clock = FakeClock()

    result = materialize_repository_plan(
        plan=plan,
        adapter=adapter,
        ledger=ledger,
        now=clock.now,
        sleep=clock.sleep,
    )

    assert result.status == "SYNTHETIC_MATERIALIZATION_COMPLETE"
    assert adapter.write_calls == [item["operation_id"] for item in plan["operations"]]
    assert all(item["attempt_count"] == 1 for item in ledger.snapshot()["operations"])
    assert result.completion_package["provider_certification_complete"] is False
    assert result.handoff["status"] == STOP_LIVE_ORCHESTRATOR_NOT_IMPLEMENTED
    assert result.handoff["synthetic_materialization_complete"] is True
    assert result.handoff["aws_calls_performed"] == 0
    assert result.handoff["aws_mutations"] == 0
    assert result.handoff["gug365_effects"] == 0
    assert result.handoff["gug357_effects"] == 0
    assert result.handoff["gug215_effects"] == 0
    assert result.handoff["gug206_effects"] == 0


def test_provider_slots_are_single_assignment_value_bound_and_consumed_causally() -> None:
    plan = _plan()
    adapter = ScriptedProviderAdapter.succeeding(plan)
    result = materialize_repository_plan(
        plan=plan,
        adapter=adapter,
        ledger=AttemptLedger.from_plan(plan),
    )

    expected_slots = {
        slot["slot"] for slot in plan["target_manifest"]["provider_slots"]
    }
    assert set(result.provider_slot_projections) == expected_slots
    emitted = [
        slot
        for receipt in result.operation_results
        for slot in receipt["produced_slot_projection_digests"]
    ]
    assert {slot["slot"] for slot in emitted} == expected_slots
    assert len(emitted) == len(expected_slots)
    assert all(
        slot["value_projection_digest"].startswith("sha256:")
        and slot["projection_digest"].startswith("sha256:")
        and slot["value_projection_digest"] != slot["projection_digest"]
        for slot in emitted
    )
    consumers = [
        (receipt, ledger_operation)
        for receipt, ledger_operation in zip(
            result.operation_results, result.ledger["operations"], strict=True
        )
        if next(
            operation
            for operation in plan["operations"]
            if operation["operation_id"] == receipt["operation_id"]
        )["consumed_slots"]
    ]
    assert consumers
    assert all(
        receipt["consumed_slot_binding_digest"]
        == ledger_operation["consumed_slot_binding_digest"]
        for receipt, ledger_operation in consumers
    )

    substituted = ScriptedProviderAdapter.succeeding(plan)
    substituted.substitute_result(
        str(plan["operations"][0]["operation_id"]),
        produced_slot_projections=(),
    )
    with pytest.raises(MaterializationError, match="PROVIDER_RESULT_BINDING_MISMATCH"):
        materialize_repository_plan(
            plan=plan,
            adapter=substituted,
            ledger=AttemptLedger.from_plan(plan),
        )


def test_result_substitution_stops_before_the_next_operation() -> None:
    plan = _plan()
    first = _operation(plan)
    adapter = ScriptedProviderAdapter.succeeding(plan)
    adapter.substitute_result(
        str(first["operation_id"]), request_digest="sha256:" + "f" * 64
    )
    ledger = AttemptLedger.from_plan(plan)

    with pytest.raises(MaterializationError, match="PROVIDER_RESULT_BINDING_MISMATCH"):
        materialize_repository_plan(plan=plan, adapter=adapter, ledger=ledger)

    assert adapter.write_calls == [first["operation_id"]]
    snapshot = ledger.snapshot()["operations"]
    assert snapshot[0]["attempt_count"] == 1
    assert snapshot[1]["attempt_count"] == 0


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("operation_id", "GUG377_OP_02_PUT_APPLICATION_GRANT"),
        ("request_digest", "sha256:" + "a" * 64),
        ("before_state_digest", "sha256:" + "b" * 64),
        ("target_state_digest", "sha256:" + "c" * 64),
        ("result_projection_digest", "sha256:" + "e" * 64),
        ("readback_projection_digest", "sha256:" + "d" * 64),
    ],
)
def test_every_provider_result_binding_rejects_substitution(
    field: str, replacement: str
) -> None:
    plan = _plan()
    first = _operation(plan)
    adapter = ScriptedProviderAdapter.succeeding(plan)
    adapter.substitute_result(str(first["operation_id"]), **{field: replacement})
    ledger = AttemptLedger.from_plan(plan)

    with pytest.raises(MaterializationError, match="PROVIDER_RESULT_BINDING_MISMATCH"):
        materialize_repository_plan(plan=plan, adapter=adapter, ledger=ledger)
    assert adapter.write_calls == [first["operation_id"]]
    assert ledger.operation(str(first["operation_id"]))["attempt_count"] == 1


def test_async_write_cannot_substitute_success_and_skip_required_polling() -> None:
    plan = _plan()
    slot_projections: dict[str, str] = {}
    async_record: dict[str, object] | None = None
    resolved_async = None
    for record in plan["operations"]:
        operation = bind_consumed_slot_projections(
            operation_from_record(record), slot_projections
        )
        if operation.polling_kind != "NONE":
            async_record = record
            resolved_async = operation
            break
        result_digest = provider_result_projection_digest(
            operation, ProviderStatus.SUCCEEDED
        )
        for projection in provider_slot_projections(
            operation, ProviderStatus.SUCCEEDED, result_digest
        ):
            slot_projections[projection.slot] = projection.projection_digest
    assert async_record is not None and resolved_async is not None

    adapter = ScriptedProviderAdapter.succeeding(plan)
    adapter.substitute_result(
        str(async_record["operation_id"]),
        status=ProviderStatus.SUCCEEDED,
        result_projection_digest=provider_result_projection_digest(
            resolved_async, ProviderStatus.SUCCEEDED
        ),
    )
    ledger = AttemptLedger.from_plan(plan)
    with pytest.raises(MaterializationError, match="PROVIDER_RESULT_BINDING_MISMATCH"):
        materialize_repository_plan(plan=plan, adapter=adapter, ledger=ledger)
    assert adapter.poll_calls == []


def test_ambiguous_write_consumes_attempt_and_only_read_only_reconciliation_runs() -> None:
    plan = _plan()
    first = _operation(plan)
    operation_id = str(first["operation_id"])
    adapter = ScriptedProviderAdapter.succeeding(plan)
    adapter.make_ambiguous(operation_id)
    ledger = AttemptLedger.from_plan(plan)

    result = materialize_repository_plan(plan=plan, adapter=adapter, ledger=ledger)
    assert result.status == "UNCERTAIN_RECONCILE_ONLY"
    assert adapter.write_calls == [operation_id]
    assert ledger.operation(operation_id)["attempt_count"] == 1
    assert ledger.operation(operation_id)["status"] == "UNCERTAIN_RECONCILE_ONLY"

    with pytest.raises(MaterializationError, match="UNCERTAIN_RECONCILE_ONLY"):
        materialize_repository_plan(plan=plan, adapter=adapter, ledger=ledger)
    assert adapter.write_calls == [operation_id]

    adapter.set_reconciliation(operation_id, ReconciliationStatus.EFFECT_PROVEN)
    reconciled = reconcile_uncertain_operation(
        plan=plan,
        operation_id=operation_id,
        adapter=adapter,
        ledger=ledger,
    )
    assert reconciled["status"] == "RECONCILED_EFFECT_PROVEN"
    assert adapter.reconcile_calls == [operation_id]
    assert adapter.write_calls == [operation_id]


def test_later_consumer_reconciliation_retains_consumed_slot_binding() -> None:
    plan = _plan()
    consumer = plan["operations"][13]
    assert consumer["operation_kind"] == "PUT_APPLICATION_AUTH_METHOD"
    assert len(consumer["consumed_slots"]) == 3
    operation_id = str(consumer["operation_id"])
    adapter = ScriptedProviderAdapter.succeeding(plan)
    adapter.make_ambiguous(operation_id)
    ledger = AttemptLedger.from_plan(plan)

    result = materialize_repository_plan(plan=plan, adapter=adapter, ledger=ledger)
    assert result.status == "UNCERTAIN_RECONCILE_ONLY"
    claimed_binding = ledger.operation(operation_id)["consumed_slot_binding_digest"]
    assert isinstance(claimed_binding, str) and claimed_binding.startswith("sha256:")

    adapter.set_reconciliation(operation_id, ReconciliationStatus.EFFECT_PROVEN)
    receipt = reconcile_uncertain_operation(
        plan=plan,
        operation_id=operation_id,
        adapter=adapter,
        ledger=ledger,
    )
    assert receipt["consumed_slot_binding_digest"] == claimed_binding
    assert receipt["before_state_digest"].startswith("sha256:")
    assert receipt["readback_projection_digest"] == consumer["target_state_digest"]
    assert adapter.write_calls.count(operation_id) == 1


@pytest.mark.parametrize(
    ("poll_script", "expected"),
    [
        ((ProviderStatus.IN_PROGRESS, ProviderStatus.SUCCEEDED), "COMPLETE"),
        ((ProviderStatus.IN_PROGRESS, ProviderStatus.FAILED), "FAILED_TERMINAL"),
        ((ProviderStatus.IN_PROGRESS, ProviderStatus.UNKNOWN), "UNCERTAIN_RECONCILE_ONLY"),
        ((ProviderStatus.IN_PROGRESS,) * 20, "UNCERTAIN_RECONCILE_ONLY"),
    ],
)
def test_polling_has_closed_states_and_hard_bounds(
    poll_script: tuple[ProviderStatus, ...], expected: str
) -> None:
    plan = _plan()
    async_operation = next(
        item for item in plan["operations"] if item["polling_policy"]["kind"] != "NONE"
    )
    operation_id = str(async_operation["operation_id"])
    adapter = ScriptedProviderAdapter.succeeding(plan)
    adapter.set_poll_script(operation_id, poll_script)
    ledger = AttemptLedger.from_plan(plan)
    clock = FakeClock()

    result = materialize_repository_plan(
        plan=plan,
        adapter=adapter,
        ledger=ledger,
        now=clock.now,
        sleep=clock.sleep,
    )

    if expected == "COMPLETE":
        assert result.status == "SYNTHETIC_MATERIALIZATION_COMPLETE"
    else:
        assert ledger.operation(operation_id)["status"] == expected
    policy = async_operation["polling_policy"]
    assert len([call for call in adapter.poll_calls if call == operation_id]) <= policy[
        "max_attempts"
    ]
    assert clock.value <= policy["max_elapsed_seconds"]


def test_poll_success_after_elapsed_bound_is_reconcile_only() -> None:
    plan = _plan()
    async_operation = next(
        item for item in plan["operations"] if item["polling_policy"]["kind"] != "NONE"
    )
    adapter = ScriptedProviderAdapter.succeeding(plan)

    class PollAdvancingClock:
        def __init__(self) -> None:
            self.calls = 0

        def now(self) -> float:
            self.calls += 1
            return (
                0.0
                if self.calls == 1
                else float(async_operation["polling_policy"]["max_elapsed_seconds"] + 1)
            )

    clock = PollAdvancingClock()
    ledger = AttemptLedger.from_plan(plan)
    result = materialize_repository_plan(
        plan=plan,
        adapter=adapter,
        ledger=ledger,
        now=clock.now,
        sleep=lambda _seconds: None,
    )
    assert result.status == "UNCERTAIN_RECONCILE_ONLY"
    assert ledger.operation(str(async_operation["operation_id"]))["status"] == (
        "UNCERTAIN_RECONCILE_ONLY"
    )


def test_rollback_is_separate_non_executable_and_public_evidence_is_leak_free() -> None:
    plan = _plan()
    result = materialize_repository_plan(
        plan=plan,
        adapter=ScriptedProviderAdapter.succeeding(plan),
        ledger=AttemptLedger.from_plan(plan),
    )
    rollback = result.rollback_package
    assert rollback["automatic_rollback"] is False
    assert rollback["deployment_authorized"] is False
    assert rollback["provider_mutations"] == []
    assert rollback["package_digest"] != result.completion_package["package_digest"]
    validate_public_evidence(result.public_records())

    serialized = json.dumps(result.public_records(), sort_keys=True)
    for sentinel in (
        "arn:",
        "123456789012",
        "AIDACKCEVSQ6C2EXAMPLE",
        "X-Amz-Signature",
        "provider_payload",
        "/Users/",
    ):
        assert sentinel not in serialized

    for forbidden in (
        {"nested": {"raw_response": "sentinel"}},
        {"nested": "arn:aws:iam::123456789012:role/sentinel"},
        {"nested": "https://example.invalid/signed?X-Amz-Signature=sentinel"},
        {"nested_account_id": "123456789012"},
    ):
        with pytest.raises(MaterializationError, match="PUBLIC_EVIDENCE_"):
            validate_public_evidence(forbidden)


def test_bundle_validator_rejects_well_formed_cross_package_splicing() -> None:
    plan = _plan()
    result = materialize_repository_plan(
        plan=plan,
        adapter=ScriptedProviderAdapter.succeeding(plan),
        ledger=AttemptLedger.from_plan(plan),
    )
    completion = copy.deepcopy(result.completion_package)
    completion["rollback_package_digest"] = "sha256:" + "8" * 64
    completion["package_digest"] = canonical_digest(
        {key: value for key, value in completion.items() if key != "package_digest"}
    )
    spliced = replace(result, completion_package=completion)
    with pytest.raises(
        MaterializationError, match="MATERIALIZATION_COMPLETION_BINDING_MISMATCH"
    ):
        validate_materialization_result(spliced)


def test_v1_stops_remain_valid_and_v2_cross_version_substitution_is_rejected() -> None:
    for family in V2_FAMILIES:
        v1_fixture = FIXTURES / "valid" / (
            f"platform-authority-gug365-upstream-{family}-v1-synthetic.json"
        )
        v2_fixture = FIXTURES / "valid" / (
            f"platform-authority-gug365-upstream-{family}-v2-synthetic.json"
        )
        v1_schema = find_schema_for_fixture(v1_fixture.stem, SCHEMAS)
        v2_schema = find_schema_for_fixture(v2_fixture.stem, SCHEMAS)
        assert v1_schema is not None and v2_schema is not None
        assert v1_schema.name.endswith(".v1.schema.json")
        assert v2_schema.name.endswith(".v2.schema.json")

        v1 = json.loads(v1_fixture.read_text(encoding="utf-8"))
        v2 = json.loads(v2_fixture.read_text(encoding="utf-8"))
        v1_validator = Draft202012Validator(
            json.loads(v1_schema.read_text(encoding="utf-8"))
        )
        v2_validator = Draft202012Validator(
            json.loads(v2_schema.read_text(encoding="utf-8"))
        )
        assert not list(v1_validator.iter_errors(v1))
        assert not list(v2_validator.iter_errors(v2))
        assert list(v1_validator.iter_errors(v2))
        assert list(v2_validator.iter_errors(v1))

        invalid = FIXTURES / "invalid" / (
            f"platform-authority-gug365-upstream-{family}-v2-substitution.json"
        )
        invalid_value = json.loads(invalid.read_text(encoding="utf-8"))
        assert list(v2_validator.iter_errors(invalid_value))

    unsupported = copy.deepcopy(_plan())
    unsupported["schema_version"] = 3
    with pytest.raises(MaterializationError, match="UNSUPPORTED_CONTRACT_VERSION"):
        validate_repository_plan(unsupported)


def test_materializer_outputs_match_v2_schemas_and_closed_runtime_dispatch() -> None:
    plan = _plan()
    result = materialize_repository_plan(
        plan=plan,
        adapter=ScriptedProviderAdapter.succeeding(plan),
        ledger=AttemptLedger.from_plan(plan),
    )
    records = {
        "plan": plan,
        "inventory": result.inventory,
        "final-handoff": result.handoff,
    }
    for family, record in records.items():
        schema_path = SCHEMAS / (
            f"platform-authority-gug365-upstream-{family}.v2.schema.json"
        )
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(schema)
        Draft202012Validator(schema).validate(record)
        validate_repository_contract(record)

    for record in records.values():
        unsupported = copy.deepcopy(record)
        unsupported["schema_version"] = 3
        with pytest.raises(
            MaterializationError, match="UNSUPPORTED_CONTRACT_VERSION"
        ):
            validate_repository_contract(unsupported)


def test_import_plan_and_cli_attempt_no_sdk_network_or_subprocess() -> None:
    child = r'''
import builtins
import json
import sys

root = sys.argv[1]
sys.path.insert(0, root)
original_import = builtins.__import__
def guarded_import(name, *args, **kwargs):
    if name.split(".", 1)[0] in {"boto3", "botocore", "requests"}:
        raise AssertionError("SDK_OR_HTTP_IMPORT_ATTEMPT")
    return original_import(name, *args, **kwargs)
builtins.__import__ = guarded_import
def audit(event, args):
    if event.startswith("socket.") or event in {"subprocess.Popen", "os.system"}:
        raise AssertionError("NETWORK_OR_SUBPROCESS_ATTEMPT")
sys.addaudithook(audit)
from tooling.platform_authority_gug365_upstream_materializer import build_repository_plan
from tooling.platform_authority_gug365_upstream_provider_contracts import InertProviderAdapter
plan = build_repository_plan()
assert InertProviderAdapter().mode == "INERT_DEFAULT"
assert "boto3" not in sys.modules and "botocore" not in sys.modules
print(json.dumps({"digest": plan["plan_digest"], "aws_calls": 0, "provider_network_calls": 0}))
'''
    env = {key: value for key, value in os.environ.items() if key not in AWS_ENV_KEYS}
    env.pop("PYTHONPATH", None)
    env.pop("PYTHONHOME", None)
    env["AWS_EC2_METADATA_DISABLED"] = "true"
    process = subprocess.run(
        [sys.executable, "-I", "-S", "-B", "-c", child, str(ROOT)],
        cwd=ROOT,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )
    assert process.returncode == 0, process.stderr
    assert json.loads(process.stdout)["provider_network_calls"] == 0

    cli_child = r'''
import builtins
import runpy
import sys

root, cli = sys.argv[1:]
sys.path.insert(0, root)
original_import = builtins.__import__
def guarded_import(name, *args, **kwargs):
    if name.split(".", 1)[0] in {"boto3", "botocore", "requests"}:
        raise AssertionError("SDK_OR_HTTP_IMPORT_ATTEMPT")
    return original_import(name, *args, **kwargs)
builtins.__import__ = guarded_import
def audit(event, args):
    if event.startswith("socket.") or event in {"subprocess.Popen", "os.system"}:
        raise AssertionError("NETWORK_OR_SUBPROCESS_ATTEMPT")
sys.addaudithook(audit)
sys.argv = [cli, "--summary"]
try:
    runpy.run_path(cli, run_name="__main__")
except SystemExit as exc:
    if exc.code not in {0, None}:
        raise
assert "boto3" not in sys.modules and "botocore" not in sys.modules
'''
    cli = subprocess.run(
        [
            sys.executable,
            "-I",
            "-S",
            "-B",
            "-c",
            cli_child,
            str(ROOT),
            str(CLI),
        ],
        cwd=ROOT,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )
    assert cli.returncode == 0, cli.stderr
    summary = json.loads(cli.stdout)
    assert summary["aws_calls_performed"] == 0
    assert summary["aws_mutations"] == 0
    assert summary["provider_network_calls"] == 0
    assert summary["deployment_authorized"] is False


def test_cli_main_is_inert_under_socket_and_sdk_import_denial(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def denied_socket(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("NETWORK_ATTEMPT")

    import socket

    monkeypatch.setattr(socket, "socket", denied_socket)
    monkeypatch.setattr(socket, "create_connection", denied_socket)
    assert materializer_main(["--summary"]) == 0
    output = json.loads(capsys.readouterr().out)
    assert output["status"] == "REPOSITORY_SOURCE_CONTRACTS_CLOSED"
    assert output["live_promotion_status"] == STOP_LIVE_ORCHESTRATOR_NOT_IMPLEMENTED
