"""Semantic schema checks for the GUG-390 public and durable bindings."""

from __future__ import annotations

import copy
from hashlib import sha256
import json
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator, ValidationError

from tooling import platform_authority_gug365_phase_execution_ledger as ledger
from tooling import validate_schema


ROOT = Path(__file__).resolve().parents[2]
PUBLIC_SCHEMA = ROOT / "schemas/platform-authority-gug390-live-run.v1.schema.json"
LEDGER_SCHEMA = (
    ROOT / "schemas/platform-authority-gug365-phase-execution-ledger.v1.schema.json"
)
PUBLIC_FIXTURE = (
    ROOT / "fixtures/valid/platform-authority-gug390-live-run-v1-synthetic.json"
)
IMPOSSIBLE_COUNTS_FIXTURE = (
    ROOT
    / "fixtures/invalid/platform-authority-gug390-live-run-v1-impossible-counts.json"
)
STALE_DIGEST_FIXTURE = (
    ROOT
    / "fixtures/invalid/platform-authority-gug390-live-run-v1-stale-digest.json"
)
LEDGER_FIXTURE = (
    ROOT
    / "fixtures/valid/platform-authority-gug365-phase-execution-ledger-v1-synthetic.json"
)


def _load(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _digest(value: Any) -> str:
    payload = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")
    return "sha256:" + sha256(payload).hexdigest()


def _validator(path: Path) -> Draft202012Validator:
    schema = _load(path)
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema)


def _seal_public_run(manifest: dict[str, Any]) -> dict[str, Any]:
    manifest["run_digest"] = _digest(
        {key: value for key, value in manifest.items() if key != "run_digest"}
    )
    return manifest


def test_public_fixture_is_self_sealed_and_uses_unambiguous_live_bindings() -> None:
    manifest = _load(PUBLIC_FIXTURE)
    _validator(PUBLIC_SCHEMA).validate(manifest)

    assert "request_digest" not in manifest
    assert manifest["owner_checkpoint_digest"] != manifest["checkpoint_digest"]
    assert manifest["live_request_digest"] != manifest["checkpoint_digest"]
    assert manifest["run_digest"] == _digest(
        {key: value for key, value in manifest.items() if key != "run_digest"}
    )


def test_public_schema_rejects_private_alias_and_runtime_incompatible_shape() -> None:
    validator = _validator(PUBLIC_SCHEMA)
    manifest = _load(PUBLIC_FIXTURE)

    aliased = copy.deepcopy(manifest)
    aliased["request_digest"] = aliased.pop("live_request_digest")
    assert list(validator.iter_errors(aliased))

    wrong_phase = copy.deepcopy(manifest)
    wrong_phase.update({"command": "execute-phase", "phase": "NONE"})
    assert list(validator.iter_errors(wrong_phase))

    wrong_reconciliation_mode = copy.deepcopy(manifest)
    wrong_reconciliation_mode.update(
        {"command": "reconcile", "phase": "POLICY_FACTORY", "read_only": False}
    )
    assert list(validator.iter_errors(wrong_reconciliation_mode))


def test_public_schema_accepts_but_semantics_rejects_impossible_counts() -> None:
    manifest = _load(IMPOSSIBLE_COUNTS_FIXTURE)
    _validator(PUBLIC_SCHEMA).validate(manifest)

    assert validate_schema.validate_semantics(manifest, PUBLIC_SCHEMA) == [
        "GUG-390 aws_mutations must not exceed aws_calls"
    ]


def test_public_schema_accepts_but_semantics_rejects_stale_run_digest() -> None:
    manifest = _load(STALE_DIGEST_FIXTURE)
    _validator(PUBLIC_SCHEMA).validate(manifest)

    assert validate_schema.validate_semantics(manifest, PUBLIC_SCHEMA) == [
        "GUG-390 run_digest must seal the complete public record"
    ]


def test_public_semantics_rejects_stop_and_non_live_mutation_overclaims() -> None:
    manifest = _load(IMPOSSIBLE_COUNTS_FIXTURE)

    stop_with_mutation = copy.deepcopy(manifest)
    stop_with_mutation.update(
        {"status": "STOP_NO_MUTATION", "aws_calls": 1, "aws_mutations": 1}
    )
    _seal_public_run(stop_with_mutation)
    assert validate_schema.validate_semantics(stop_with_mutation, PUBLIC_SCHEMA) == [
        "GUG-390 STOP_NO_MUTATION requires aws_mutations = 0"
    ]

    synthetic_with_mutation = copy.deepcopy(manifest)
    synthetic_with_mutation.update(
        {
            "classification": "SYNTHETIC_VALIDATED",
            "status": "LIVE_PROVIDER_NOT_PROVEN",
            "aws_calls": 1,
            "aws_mutations": 1,
        }
    )
    _seal_public_run(synthetic_with_mutation)
    assert validate_schema.validate_semantics(
        synthetic_with_mutation, PUBLIC_SCHEMA
    ) == [
        "GUG-390 aws_mutations > 0 requires command=execute-phase "
        "and classification=LIVE_PROVIDER_EVIDENCE"
    ]


def _execution_context() -> dict[str, Any]:
    value = {
        "issue": "GUG-390",
        "owner_checkpoint_digest": _digest({"owner": "checkpoint"}),
        "live_request_digest": _digest({"live": "request"}),
        "activator_checkpoint_digest": None,
    }
    return {**value, "context_digest": _digest(value)}


def _durable_provider_evidence(
    *, context: dict[str, Any], outcome: dict[str, Any], ledger: dict[str, Any]
) -> dict[str, Any]:
    identity_receipt = {
        "caller_arn_digest": ledger["caller_arn_digest"],
        "session_identifier_digest": ledger[
            "authority_session_identifier_digest"
        ],
    }
    identity_receipt_digest = _digest(identity_receipt)
    transcript_before = {
        "provider_calls": 1,
        "provider_mutation_calls": 0,
        "provider_mode": "SYNTHETIC",
        "identity_receipt_digest": identity_receipt_digest,
    }
    transcript = {
        "provider_calls": 2,
        "provider_mutation_calls": 1,
        "provider_mode": "SYNTHETIC",
        "identity_receipt_digest": identity_receipt_digest,
    }
    value = {
        "record_type": (
            "scanalyze.platform_authority.gug390_durable_provider_evidence.v1"
        ),
        "schema_version": 1,
        "issue": "GUG-390",
        "phase": ledger["phase"],
        "operation_sequence": outcome["operation_sequence"],
        "operation_digest": _digest({"operation": outcome["operation_sequence"]}),
        "provider_request_digest": outcome["request_digest"],
        "outcome": outcome["result"],
        "provider_result_digest": outcome["provider_result_digest"],
        "provider_mode": "SYNTHETIC",
        "identity_receipt": identity_receipt,
        "identity_receipt_digest": identity_receipt_digest,
        "caller_arn_digest": ledger["caller_arn_digest"],
        "session_identifier_digest": ledger[
            "authority_session_identifier_digest"
        ],
        "transcript_before": transcript_before,
        "transcript_before_receipt_digest": _digest(transcript_before),
        "transcript": transcript,
        "transcript_receipt_digest": _digest(transcript),
        "owner_checkpoint_digest": context["owner_checkpoint_digest"],
        "live_request_digest": context["live_request_digest"],
        "execution_context_digest": context["context_digest"],
        "activator_checkpoint_digest": None,
        "causal_receipt_evidence": None,
        "causal_receipt_evidence_digest": None,
        "private_provider_evidence_file": (
            "gug390-provider-"
            + ledger["ledger_id"].split(":", 1)[1]
            + f"-{outcome['operation_sequence']:03d}.json"
        ),
        "private_provider_evidence_digest": _digest(
            {"private_provider_evidence": outcome["operation_sequence"]}
        ),
    }
    return {**value, "evidence_digest": _digest(value)}


def test_ledger_schema_accepts_legacy_and_closed_gug390_runtime_variants() -> None:
    validator = _validator(LEDGER_SCHEMA)
    legacy = _load(LEDGER_FIXTURE)
    legacy.pop("_test_metadata", None)
    validator.validate(legacy)

    extended = copy.deepcopy(legacy)
    context = _execution_context()
    extended["claim"]["execution_context"] = context
    outcome = extended["operation_outcomes"][0]
    evidence = _durable_provider_evidence(
        context=context,
        outcome=outcome,
        ledger=extended,
    )
    outcome["durable_provider_evidence"] = evidence
    evidence_receipt = next(
        item
        for item in extended["receipt_chain"]
        if item["event"] == "OPERATION_SUCCEEDED"
    )
    evidence_receipt["facts"]["durable_provider_evidence_digest"] = evidence[
        "evidence_digest"
    ]
    assert ledger.validate_execution_context(context) == context
    assert ledger.validate_durable_provider_evidence(
        evidence,
        record=extended,
        operation_sequence=outcome["operation_sequence"],
        outcome=outcome["result"],
        provider_result_digest=outcome["provider_result_digest"],
    ) == evidence
    validator.validate(extended)

    # An extended claim can retain a legacy-shaped outcome after a hard crash;
    # absence of evidence remains visible and cannot be mistaken for null evidence.
    hard_crash = copy.deepcopy(legacy)
    hard_crash["claim"]["execution_context"] = context
    validator.validate(hard_crash)

    partial_context = copy.deepcopy(extended)
    del partial_context["claim"]["execution_context"]["live_request_digest"]
    with pytest.raises(ValidationError):
        validator.validate(partial_context)

    partial_evidence = copy.deepcopy(extended)
    del partial_evidence["operation_outcomes"][0]["durable_provider_evidence"][
        "identity_receipt_digest"
    ]
    with pytest.raises(ValidationError):
        validator.validate(partial_evidence)

    null_evidence = copy.deepcopy(extended)
    null_evidence["operation_outcomes"][0]["durable_provider_evidence"] = None
    with pytest.raises(ValidationError):
        validator.validate(null_evidence)
