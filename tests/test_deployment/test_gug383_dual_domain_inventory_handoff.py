from __future__ import annotations

import copy, json, subprocess, sys
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from tooling.platform_authority_gug365_upstream_inventory import canonical_digest
from tooling.platform_authority_gug383_dual_domain_inventory_handoff import (
    HandoffError,
    compose,
    validate_authority_receipt,
    validate_public_handoff,
)

ROOT = Path(__file__).parents[2]
SCRIPT = ROOT / "scripts/deployment/platform-authority-gug383-dual-domain-inventory-handoff.py"; SCHEMA = ROOT / "schemas/platform-authority-gug383-dual-domain-inventory-handoff.v1.schema.json"
VALID = ROOT / "fixtures/valid/platform-authority-gug383-dual-domain-inventory-handoff-v1-synthetic.json"; INVALID = ROOT / "fixtures/invalid/platform-authority-gug383-dual-domain-inventory-handoff-v1-overclaim.json"


def _d(seed: str) -> str:
    return canonical_digest({"synthetic": seed})


def _authority() -> dict[str, object]:
    value: dict[str, object] = {
        "record_type": "scanalyze.platform_authority.gug376_authority_inventory_receipt.v1",
        "status": "AUTHORITY_INVENTORY_LIVE_NOT_PROVEN", "classification": "ABSENT_READY",
        "policy_digest": _d("authority-policy"), "facts_digest": _d("authority-facts"),
        "runtime_target_digest": _d("runtime-target"),
        "snapshot_digests": [_d("authority-snapshot-1"), _d("authority-snapshot-2")],
        "surface_counts_digest": _d("authority-counts"),
        "external_certification_digest": None, "external_verifier_identity_digest": None,
        "external_trust_anchor_digest": None, "session_count": 2, "stable": True,
        "read_only": True, "aws_mutations": 0, "two_human_status": "NOT_PROVEN",
        "independent_approval_present": False, "deployment_authorized": False,
        "production_status": "NO-GO",
    }
    value["receipt_digest"] = canonical_digest(value)
    return value


def _identity() -> dict[str, object]:
    value: dict[str, object] = {
        "record_type": "scanalyze.platform_authority.gug376_identity_center_inventory_receipt.v1",
        "status": "STOP_LIVE_ORCHESTRATOR_NOT_IMPLEMENTED",
        "live_status": "IDENTITY_CENTER_INVENTORY_LIVE_NOT_PROVEN", "classification": "ABSENT_READY",
        "policy_binding_digest": _d("identity-policy"), "target_digest": _d("identity-target"),
        "facts_digest": _d("identity-facts"),
        "snapshot_digests": [_d("identity-snapshot-1"), _d("identity-snapshot-2")],
        "surface_counts": {key: (0 if key in {"instances", "applications", "permission_sets"} else None) for key in (
            "instances", "applications", "permission_sets", "assignments",
            "provisioning", "target_accounts", "operators",
        )},
        "snapshot_count": 2, "stable": True, "read_only": True, "aws_calls": 0,
        "aws_mutations": 0, "two_human_status": "NOT_PROVEN",
        "independent_approval_present": False, "deployment_authorized": False,
        "production_status": "NO-GO",
    }
    value["receipt_digest"] = canonical_digest(value)
    return value


def _binding(receipt: dict[str, object], sessions: list[str], common: dict[str, str]) -> dict[str, object]:
    value: dict[str, object] = {
        "receipt_digest": receipt["receipt_digest"],
        "snapshot_digests": list(receipt["snapshot_digests"]), "session_digests": sessions, **common,
    }
    value["binding_digest"] = canonical_digest(value)
    return value


def _envelope(authority: dict[str, object], identity: dict[str, object]) -> dict[str, object]:
    common = {
        "run_id_digest": _d("run-id"), "source_commit_sha": "1" * 40,
        "source_tree_sha": "2" * 40, "window_digest": _d("window"),
        "authorization_digest": _d("authorization"),
    }
    value: dict[str, object] = {
        "record_type": "scanalyze.platform_authority.gug383_dual_domain_inventory_run_envelope.v1",
        "authority": _binding(authority, [_d("authority-session-1"), _d("authority-session-2")], common),
        "identity_center": _binding(identity, [_d("identity-session-1"), _d("identity-session-2")], common),
        **common, "evidence_complete": True, "evidence_stable": True,
    }
    value["private_run_digest"] = canonical_digest(value)
    return value


def _expected(envelope: dict[str, object]) -> dict[str, str]:
    return {
        "expected_source_commit_sha": str(envelope["source_commit_sha"]), "expected_source_tree_sha": str(envelope["source_tree_sha"]),
        "expected_window_digest": str(envelope["window_digest"]), "expected_authorization_digest": str(envelope["authorization_digest"]),
        "expected_run_id_digest": str(envelope["run_id_digest"]), "expected_private_run_digest": str(envelope["private_run_digest"]),
    }


def _inputs() -> tuple[dict[str, object], dict[str, object], dict[str, object]]:
    authority, identity = _authority(), _identity(); return authority, identity, _envelope(authority, identity)


def _compose(authority: dict[str, object], identity: dict[str, object], envelope: dict[str, object], **changes: str) -> dict[str, object]:
    expected = _expected(envelope); expected.update(changes)
    return compose(authority, identity, envelope, **expected)


def _reseal_envelope(envelope: dict[str, object]) -> None:
    for name in ("authority", "identity_center"):
        domain = envelope[name]
        assert isinstance(domain, dict)
        domain["binding_digest"] = canonical_digest({key: item for key, item in domain.items() if key != "binding_digest"})
    envelope["private_run_digest"] = canonical_digest({key: item for key, item in envelope.items() if key != "private_run_digest"})


def test_terminal_receipts_compose_to_exact_sanitized_fixture() -> None:
    authority, identity, envelope = _inputs()
    result = _compose(authority, identity, envelope)
    assert result == json.loads(VALID.read_text())
    serialized = json.dumps(result)
    for forbidden in ("account_id", "arn:aws:", "profile", "UserId", "email", "private_path", "filename", "request_id", "session_digests", "token", "payload"):
        assert forbidden not in serialized
    assert result["aws_calls"] == result["aws_mutations"] == 0
    assert result["live_provider_evidence"] is result["deployment_authorized"] is False


@pytest.mark.parametrize("domain", ["authority", "identity_center"])
@pytest.mark.parametrize("mode", ["altered", "substituted"])
def test_altered_or_substituted_receipt_is_rejected(domain: str, mode: str) -> None:
    authority, identity, envelope = _inputs()
    receipt = authority if domain == "authority" else identity
    receipt["facts_digest"] = _d(domain + mode)
    if mode == "substituted":
        receipt["receipt_digest"] = canonical_digest({key: item for key, item in receipt.items() if key != "receipt_digest"})
    with pytest.raises(HandoffError, match="GUG384_RECEIPT|GUG385_RECEIPT"):
        _compose(authority, identity, envelope)


@pytest.mark.parametrize("field,replacement", [
    ("expected_source_commit_sha", "3" * 40), ("expected_source_tree_sha", "4" * 40),
    ("expected_window_digest", _d("other-window")),
    ("expected_authorization_digest", _d("other-authorization")),
    ("expected_run_id_digest", _d("reused-run")),
])
def test_independently_expected_run_bindings_reject_wrong_or_reused_values(field: str, replacement: str) -> None:
    authority, identity, envelope = _inputs()
    with pytest.raises(HandoffError, match="EXPECTED_RUN_BINDING_MISMATCH"):
        _compose(authority, identity, envelope, **{field: replacement})


@pytest.mark.parametrize("field", ["source_commit_sha", "source_tree_sha", "window_digest", "authorization_digest", "run_id_digest"])
def test_cross_run_domain_bindings_are_rejected_even_when_resealed(field: str) -> None:
    authority, identity, envelope = _inputs()
    domain = envelope["identity_center"]
    assert isinstance(domain, dict)
    domain[field] = "5" * 40 if field.endswith("sha") else _d("cross-" + field)
    _reseal_envelope(envelope)
    with pytest.raises(HandoffError, match="CROSS_RUN_BINDING_MISMATCH"):
        _compose(authority, identity, envelope)


def test_altered_private_run_digest_is_rejected() -> None:
    authority, identity, envelope = _inputs(); envelope["private_run_digest"] = _d("altered-private-run")
    with pytest.raises(HandoffError, match="PRIVATE_RUN_DIGEST_MISMATCH"):
        _compose(authority, identity, envelope)


def test_identity_session_cardinality_cannot_omit_or_invent_sessions() -> None:
    authority, identity, envelope = _inputs(); domain = envelope["identity_center"]; assert isinstance(domain, dict)
    domain["session_digests"].append(_d("invented-session")); _reseal_envelope(envelope)
    with pytest.raises(HandoffError, match="SESSION_CARDINALITY_INVALID"): _compose(authority, identity, envelope)
    authority, identity, _ = _inputs(); identity["classification"] = "EXACT_PRESENT_NO_TOUCH"
    identity["surface_counts"] = {key: 0 for key in identity["surface_counts"]}; identity["receipt_digest"] = canonical_digest({key: item for key, item in identity.items() if key != "receipt_digest"})
    envelope = _envelope(authority, identity)
    with pytest.raises(HandoffError, match="SESSION_CARDINALITY_INVALID"): _compose(authority, identity, envelope)


def test_cross_domain_session_and_snapshot_reuse_are_rejected_after_reseal() -> None:
    authority, identity, envelope = _inputs()
    first = envelope["authority"]
    second = envelope["identity_center"]
    assert isinstance(first, dict) and isinstance(second, dict)
    second["session_digests"][0] = first["session_digests"][0]
    _reseal_envelope(envelope)
    with pytest.raises(HandoffError, match="CROSS_DOMAIN_SESSION_REUSE"):
        _compose(authority, identity, envelope)
    authority, identity, envelope = _inputs()
    first, second = envelope["authority"], envelope["identity_center"]
    assert isinstance(first, dict) and isinstance(second, dict)
    identity["snapshot_digests"][0] = authority["snapshot_digests"][0]
    identity["receipt_digest"] = canonical_digest({key: item for key, item in identity.items() if key != "receipt_digest"})
    second["snapshot_digests"] = list(identity["snapshot_digests"])
    second["receipt_digest"] = identity["receipt_digest"]
    _reseal_envelope(envelope)
    with pytest.raises(HandoffError, match="GUG385_RECEIPT_SUBSTITUTED|CROSS_DOMAIN_SNAPSHOT_REUSE"):
        _compose(authority, identity, envelope)


def test_unstable_incomplete_and_malformed_exact_evidence_fail_closed() -> None:
    authority, identity, envelope = _inputs()
    authority.update({"classification": "UNCERTAIN_RECONCILE_ONLY", "snapshot_digests": [_d("one")], "session_count": 1, "stable": False})
    authority["receipt_digest"] = canonical_digest({key: item for key, item in authority.items() if key != "receipt_digest"})
    with pytest.raises(HandoffError, match="EVIDENCE_INCOMPLETE_OR_UNSTABLE"):
        _compose(authority, identity, envelope)
    authority, identity, envelope = _inputs()
    envelope["evidence_complete"] = False
    _reseal_envelope(envelope)
    with pytest.raises(HandoffError, match="RUN_ENVELOPE_INVALID"):
        _compose(authority, identity, envelope)
    authority = _authority()
    authority.update({"classification": "EXACT_PRESENT_NO_TOUCH"})
    authority["receipt_digest"] = canonical_digest({key: item for key, item in authority.items() if key != "receipt_digest"})
    with pytest.raises(HandoffError, match="GUG384_RECEIPT_INVALID"):
        validate_authority_receipt(authority)


@pytest.mark.parametrize("field,value", [
    ("status", "LIVE_ORCHESTRATOR_READY"), ("classification", "LIVE_INVENTORY_COMPLETE"),
    ("live_provider_evidence", True), ("aws_calls", 1), ("aws_mutations", 1),
    ("deployment_authorized", True), ("two_human_status", "PROVEN"),
    ("independent_approval_present", True), ("production_status", "GO"),
])
def test_public_handoff_rejects_every_elevation_even_when_resealed(field: str, value: object) -> None:
    authority, identity, envelope = _inputs()
    handoff = _compose(authority, identity, envelope)
    handoff[field] = value
    handoff["handoff_digest"] = canonical_digest({key: item for key, item in handoff.items() if key != "handoff_digest"})
    with pytest.raises(HandoffError, match="PUBLIC_HANDOFF_INVALID"):
        validate_public_handoff(handoff)


@pytest.mark.parametrize("field", ["account", "arn", "profile", "UserId", "name", "email", "path", "filename", "request_id", "token", "payload"])
def test_public_handoff_rejects_sensitive_channels_even_when_resealed(field: str) -> None:
    authority, identity, envelope = _inputs()
    handoff = _compose(authority, identity, envelope)
    handoff[field] = "synthetic-private-value"
    handoff["handoff_digest"] = canonical_digest({key: item for key, item in handoff.items() if key != "handoff_digest"})
    with pytest.raises(HandoffError, match="PUBLIC_HANDOFF_INVALID"):
        validate_public_handoff(handoff)


def test_public_handoff_schema_accepts_valid_fixture_and_rejects_overclaim() -> None:
    schema = json.loads(SCHEMA.read_text())
    validator = Draft202012Validator(schema)
    assert not list(validator.iter_errors(json.loads(VALID.read_text())))
    assert list(validator.iter_errors(json.loads(INVALID.read_text())))


def test_cli_is_inert_and_compose_emits_only_public_json(tmp_path: Path) -> None:
    blocked = subprocess.run([sys.executable, "-I", "-S", str(SCRIPT), "capture"], text=True, capture_output=True, check=False)
    assert blocked.returncode == 2 and blocked.stdout == "" and json.loads(blocked.stderr)["code"] == "STOP_LIVE_ORCHESTRATOR_NOT_IMPLEMENTED"
    authority, identity, envelope = _inputs()
    paths = [tmp_path / name for name in ("authority-private.json", "identity-private.json", "run-private.json")]
    for path, value in zip(paths, (authority, identity, envelope), strict=True):
        path.write_text(json.dumps(value), encoding="utf-8")
    expected = _expected(envelope)
    command = [sys.executable, "-I", "-S", str(SCRIPT), "compose", "--authority-receipt", str(paths[0]), "--identity-center-receipt", str(paths[1]), "--run-envelope", str(paths[2])]
    for key, value in expected.items():
        command.extend(["--" + key.replace("_", "-"), value])
    result = subprocess.run(command, text=True, capture_output=True, check=False)
    assert result.returncode == 0 and result.stderr == "" and json.loads(result.stdout) == _compose(authority, identity, envelope)
    assert str(tmp_path) not in result.stdout and "Traceback" not in result.stderr


def test_composer_source_has_no_live_runtime_construction() -> None:
    source = (ROOT / "tooling/platform_authority_gug383_dual_domain_inventory_handoff.py").read_text()
    for forbidden in ("boto3", "botocore", "import socket", "import subprocess", "AWS_PROFILE", "execute(action", "ProviderFactory"):
        assert forbidden not in source
