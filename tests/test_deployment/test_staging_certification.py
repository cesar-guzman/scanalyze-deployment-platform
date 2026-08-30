from __future__ import annotations

import base64
import copy
import json
import subprocess
import sys
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)

from tooling import staging_certification as subject


ROOT = Path(__file__).resolve().parents[2]
NOW = datetime(2026, 8, 30, 5, 30, tzinfo=UTC)


@dataclass(frozen=True)
class _SigningKeys:
    certifier: ec.EllipticCurvePrivateKey
    approver: ec.EllipticCurvePrivateKey


def _digest(character: str) -> str:
    return "sha256:" + character * 64


def _indexed_digest(value: int) -> str:
    return "sha256:" + f"{value:064x}"


def _b64url(value: int) -> str:
    raw = value.to_bytes(32, "big")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _entry(environment: str, suffix: str, observed_at: str) -> dict[str, Any]:
    digest_start = {"V": 2, "W": 12}[suffix]
    digests = iter(
        _indexed_digest(value) for value in range(digest_start, digest_start + 10)
    )
    binding_digest = _indexed_digest({"V": 100, "W": 101}[suffix])
    entry = {
        "evidence_id": f"evi_01ARZ3NDEKTSV4RRFFQ69G5FA{suffix}",
        "logical_environment": environment,
        "deployment_binding_digest": binding_digest,
        "region": "us-east-1",
        "release_digest": _digest("1"),
        "isolated": True,
        "rerun_unchanged": True,
        "positive_tests_passed": True,
        "negative_tests_passed": True,
        "rollback_measured": True,
        "restore_measured": True,
        "observed_at": observed_at,
    }
    for field in (
        "workflow_run_digest",
        "saved_plan_digest",
        "apply_receipt_digest",
        "health_receipt_digest",
        "no_change_receipt_digest",
        "positive_test_report_digest",
        "negative_test_report_digest",
        "rollback_measurement_digest",
        "restore_measurement_digest",
        "game_day_record_digest",
    ):
        entry[field] = next(digests)
    return entry


def _signer(
    private_key: ec.EllipticCurvePrivateKey, *, key_id: str, identity: str
) -> dict[str, Any]:
    numbers = private_key.public_key().public_numbers()
    return {
        "key_id": key_id,
        "issuer": "https://issuer.example.test",
        "identity": identity,
        "algorithm": "ECDSA_SHA_256",
        "public_key_jwk": {
            "kty": "EC",
            "crv": "P-256",
            "x": _b64url(numbers.x),
            "y": _b64url(numbers.y),
        },
    }


def _package() -> tuple[dict[str, Any], dict[str, Any], _SigningKeys]:
    keys = _SigningKeys(
        certifier=ec.generate_private_key(ec.SECP256R1()),
        approver=ec.generate_private_key(ec.SECP256R1()),
    )
    certifier = _signer(
        keys.certifier,
        key_id="synthetic-gug127-certifier-key",
        identity="https://scanalyze.example.test/staging-certifier",
    )
    approver = _signer(
        keys.approver,
        key_id="synthetic-gug127-approval-key",
        identity="https://scanalyze.example.test/approval-authority",
    )
    policy = {
        "schema_version": "1",
        "record_type": "scanalyze.staging_certification_trust_policy.v1",
        "gate_id": "GUG-127",
        "trust_epoch": 1,
        "valid_from": "2026-08-29T00:00:00Z",
        "valid_until": "2026-09-05T00:00:00Z",
        "allowed_signers": [certifier],
        "allowed_approval_signers": [approver],
        "policy_digest": "",
    }
    policy["policy_digest"] = subject.trust_policy_digest(policy)
    certification = {
        "schema_version": "1",
        "record_type": "scanalyze.staging_certification.v1",
        "gate_id": "GUG-127",
        "certification_id": "stgcert_01ARZ3NDEKTSV4RRFFQ69G5FAV",
        "source_revision": "a" * 40,
        "release_digest": _digest("1"),
        "last_known_good_release_digest": _digest("0"),
        "phase_8_evidence_digest": _digest("f"),
        "observed_at": "2026-08-30T05:00:00Z",
        "expires_at": "2026-09-01T05:00:00Z",
        "evidence_index": {
            "schema_version": "1",
            "entries": [
                _entry("dev", "V", "2026-08-30T04:00:00Z"),
                _entry("staging", "W", "2026-08-30T05:00:00Z"),
            ],
            "index_digest": "",
        },
        "evidence_index_signature": {
            **{key: certifier[key] for key in ("key_id", "issuer", "identity", "algorithm")},
            "value": "",
        },
        "trust_policy_digest": policy["policy_digest"],
        "operations": {
            "no_open_critical": True,
            "no_open_high": True,
            "two_environment_isolation": True,
            "positive_tests_passed": True,
            "negative_tests_passed": True,
            "rollback_measured": True,
            "restore_measured": True,
            "on_call_confirmed": True,
            "change_window_confirmed": True,
            "alerts_confirmed": True,
            "backups_confirmed": True,
            "last_known_good_confirmed": True,
            "residual_risk_digest": _digest("a"),
            "on_call_digest": _digest("b"),
            "change_window_digest": _digest("c"),
            "alerts_digest": _digest("d"),
            "backups_digest": _digest("e"),
        },
        "independent_review": {
            "initiator_user_id": 1001,
            "reviewer_user_id": 1002,
            "human_identity_attested": True,
            "mfa_attested": True,
            "independence_attested": True,
            "least_privilege_attested": True,
            "reviewed_at": "2026-08-30T05:10:00Z",
            "approval_expires_at": "2026-08-30T08:00:00Z",
            "approval_evidence_digest": _digest("9"),
            "approval_authority_digest": _digest("8"),
            "environment_anchor_digest": _digest("7"),
            "reviewed_body_digest": "",
            "approval_binding_digest": "",
            "approval_signature": {
                **{
                    key: approver[key]
                    for key in ("key_id", "issuer", "identity", "algorithm")
                },
                "value": "",
            },
        },
        "decision": {
            "status": "STAGING_CERTIFIED",
            "staging_certified": True,
            "gug128_entry_evidence_ready": True,
            "gug128_manual_go_required": True,
            "production_pilot_authorized": False,
            "production_authorized": False,
        },
        "certification_digest": "",
    }
    _resign(certification, keys)
    return certification, policy, keys


def _resign(
    certification: dict[str, Any], keys: _SigningKeys
) -> None:
    index = certification["evidence_index"]
    index["index_digest"] = subject.evidence_index_digest(index)
    certification["independent_review"]["reviewed_body_digest"] = (
        subject.reviewed_certification_body_digest(certification)
    )
    certification["independent_review"]["approval_binding_digest"] = (
        subject.approval_binding_digest(certification)
    )
    approval_signature = _canonical_signature(
        keys.approver,
        subject.canonical_bytes(subject.approval_signature_statement(certification)),
    )
    certification["independent_review"]["approval_signature"]["value"] = (
        base64.b64encode(approval_signature).decode("ascii")
    )
    _certifier_resign_only(certification, keys)


def _canonical_signature(
    private_key: ec.EllipticCurvePrivateKey, statement: bytes
) -> bytes:
    signature = private_key.sign(statement, ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(signature)
    return encode_dss_signature(r, min(s, subject.P256_ORDER - s))


def _certifier_resign_only(
    certification: dict[str, Any], keys: _SigningKeys
) -> None:
    signature = _canonical_signature(
        keys.certifier,
        subject.canonical_bytes(subject.signature_statement(certification)),
    )
    certification["evidence_index_signature"]["value"] = base64.b64encode(
        signature
    ).decode("ascii")
    certification["certification_digest"] = subject.certification_digest(
        certification
    )


def _rebind_review_without_approval_signature(
    certification: dict[str, Any], keys: _SigningKeys
) -> None:
    certification["independent_review"]["reviewed_body_digest"] = (
        subject.reviewed_certification_body_digest(certification)
    )
    certification["independent_review"]["approval_binding_digest"] = (
        subject.approval_binding_digest(certification)
    )
    _certifier_resign_only(certification, keys)


def _verify(
    certification: dict[str, Any],
    policy: dict[str, Any],
    *,
    now: datetime = NOW,
) -> subject.CertificationDecision:
    return subject._verify_certification_at(
        certification,
        policy,
        now=now,
        expected_trust_policy_digest=policy["policy_digest"],
        expected_trust_epoch=policy["trust_epoch"],
    )


def test_signed_two_environment_certification_is_accepted() -> None:
    certification, policy, _ = _package()

    decision = _verify(certification, policy)

    assert decision.allowed is True
    assert decision.code == "STAGING_CERTIFIED"
    assert decision.production_authorized is False
    assert decision.evidence_index_digest == certification["evidence_index"][
        "index_digest"
    ]


@pytest.mark.parametrize(
    ("mutate", "code"),
    [
        (
            lambda value: value["evidence_index"]["entries"][1].update(
                logical_environment="dev"
            ),
            "TWO_ENVIRONMENT_EVIDENCE_REQUIRED",
        ),
        (
            lambda value: value["evidence_index"]["entries"][1].update(
                deployment_binding_digest=value["evidence_index"]["entries"][0][
                    "deployment_binding_digest"
                ]
            ),
            "ENVIRONMENT_ISOLATION_NOT_PROVEN",
        ),
        (
            lambda value: value["evidence_index"]["entries"][1].update(
                release_digest=_digest("8")
            ),
            "RELEASE_BINDING_MISMATCH",
        ),
        (
            lambda value: value["independent_review"].update(
                reviewer_user_id=value["independent_review"]["initiator_user_id"]
            ),
            "SELF_REVIEW_REJECTED",
        ),
        (
            lambda value: value.update(
                last_known_good_release_digest=value["release_digest"]
            ),
            "LAST_KNOWN_GOOD_NOT_DISTINCT",
        ),
    ],
)
def test_semantic_overclaims_fail_closed(mutate: Any, code: str) -> None:
    certification, policy, private_key = _package()
    mutate(certification)
    _resign(certification, private_key)

    with pytest.raises(subject.StagingCertificationError, match=code):
        _verify(certification, policy)


def test_expired_certification_is_rejected() -> None:
    certification, policy, private_key = _package()
    certification["expires_at"] = "2026-08-30T05:15:00Z"
    _resign(certification, private_key)

    with pytest.raises(subject.StagingCertificationError, match="CERTIFICATION_EXPIRED"):
        _verify(certification, policy)


def test_index_tamper_is_rejected_before_signature() -> None:
    certification, policy, _ = _package()
    certification["evidence_index"]["entries"][0]["health_receipt_digest"] = _digest(
        "0"
    )
    certification["certification_digest"] = subject.certification_digest(certification)

    with pytest.raises(
        subject.StagingCertificationError, match="EVIDENCE_INDEX_DIGEST_MISMATCH"
    ):
        _verify(certification, policy)


def test_invalid_signature_is_rejected() -> None:
    certification, policy, _ = _package()
    raw = base64.b64decode(certification["evidence_index_signature"]["value"])
    certification["evidence_index_signature"]["value"] = base64.b64encode(
        raw[:-1] + bytes([raw[-1] ^ 1])
    ).decode("ascii")
    certification["certification_digest"] = subject.certification_digest(certification)

    with pytest.raises(
        subject.StagingCertificationError, match="EVIDENCE_SIGNATURE_INVALID"
    ):
        _verify(certification, policy)


def test_schema_rejects_production_authorization_overclaim() -> None:
    certification, policy, private_key = _package()
    certification["decision"]["production_authorized"] = True
    _resign(certification, private_key)

    with pytest.raises(
        subject.StagingCertificationError, match="CERTIFICATION_SCHEMA_INVALID"
    ):
        _verify(certification, policy)


def test_cli_fails_closed_until_repository_anchor_is_configured(
    tmp_path: Path,
) -> None:
    certification, policy, _ = _package()
    certification_path = tmp_path / "certification.json"
    policy_path = tmp_path / "policy.json"
    certification_path.write_text(json.dumps(certification), encoding="utf-8")
    policy_path.write_text(json.dumps(policy), encoding="utf-8")

    result = subprocess.run(
        [
            sys.executable,
            "scripts/deployment/staging-certification.py",
            "--certification",
            str(certification_path),
            "--trust-policy",
            str(policy_path),
        ],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 1
    assert result.stdout == ""
    assert result.stderr == "FAIL: TRUST_ANCHOR_NOT_CONFIGURED\n"


def test_cli_failure_does_not_echo_input(tmp_path: Path) -> None:
    certification, policy, _ = _package()
    certification["certification_digest"] = _digest("0")
    certification_path = tmp_path / "certification.json"
    policy_path = tmp_path / "policy.json"
    certification_path.write_text(json.dumps(certification), encoding="utf-8")
    policy_path.write_text(json.dumps(policy), encoding="utf-8")

    result = subprocess.run(
        [
            sys.executable,
            "scripts/deployment/staging-certification.py",
            "--certification",
            str(certification_path),
            "--trust-policy",
            str(policy_path),
        ],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 1
    assert result.stdout == ""
    assert result.stderr == "FAIL: TRUST_ANCHOR_NOT_CONFIGURED\n"
    assert (
        certification["independent_review"]["approval_evidence_digest"]
        not in result.stderr
    )


def test_mutation_helpers_do_not_modify_original_policy() -> None:
    certification, policy, _ = _package()
    original = copy.deepcopy(policy)

    _verify(certification, policy)

    assert policy == original


def test_caller_selected_trust_policy_is_rejected() -> None:
    certification, policy, _ = _package()

    with pytest.raises(
        subject.StagingCertificationError, match="TRUST_ANCHOR_DIGEST_MISMATCH"
    ):
        subject._verify_certification_at(
            certification,
            policy,
            now=NOW,
            expected_trust_policy_digest=_digest("0"),
            expected_trust_epoch=policy["trust_epoch"],
        )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("valid_from", "2026-08-30T05:20:00Z"),
        ("valid_until", "2026-08-30T06:00:00Z"),
    ],
)
def test_policy_must_cover_review_and_full_certificate_window(
    field: str, value: str
) -> None:
    certification, policy, private_key = _package()
    policy[field] = value
    policy["policy_digest"] = subject.trust_policy_digest(policy)
    certification["trust_policy_digest"] = policy["policy_digest"]
    _resign(certification, private_key)

    with pytest.raises(
        subject.StagingCertificationError,
        match="TRUST_POLICY_CERTIFICATION_WINDOW_MISMATCH",
    ):
        _verify(certification, policy)


def test_decision_critical_tamper_is_covered_by_signature() -> None:
    certification, policy, _ = _package()
    certification["operations"]["alerts_digest"] = _digest("0")
    certification["certification_digest"] = subject.certification_digest(certification)

    with pytest.raises(
        subject.StagingCertificationError, match="REVIEWED_BODY_DIGEST_MISMATCH"
    ):
        _verify(certification, policy)


def test_authenticated_approval_tamper_breaks_exact_binding() -> None:
    certification, policy, _ = _package()
    certification["independent_review"]["approval_evidence_digest"] = _digest("0")
    certification["certification_digest"] = subject.certification_digest(certification)

    with pytest.raises(
        subject.StagingCertificationError, match="REVIEWED_BODY_DIGEST_MISMATCH"
    ):
        _verify(certification, policy)


def test_approval_binding_digest_tamper_is_rejected() -> None:
    certification, policy, _ = _package()
    certification["independent_review"]["approval_binding_digest"] = _digest("0")
    certification["certification_digest"] = subject.certification_digest(certification)

    with pytest.raises(
        subject.StagingCertificationError, match="APPROVAL_BINDING_MISMATCH"
    ):
        _verify(certification, policy)


@pytest.mark.parametrize(
    "mutate",
    [
        lambda value: value.update(phase_8_evidence_digest=_digest("0")),
        lambda value: value.update(last_known_good_release_digest=_digest("1")),
        lambda value: value["operations"].update(residual_risk_digest=_digest("0")),
        lambda value: value["operations"].update(alerts_digest=_digest("0")),
        lambda value: value.update(expires_at="2026-09-01T04:00:00Z"),
    ],
)
def test_certifier_cannot_reuse_independent_approval_for_changed_body(
    mutate: Any,
) -> None:
    certification, policy, private_key = _package()
    mutate(certification)
    _certifier_resign_only(certification, private_key)

    with pytest.raises(
        subject.StagingCertificationError, match="REVIEWED_BODY_DIGEST_MISMATCH"
    ):
        _verify(certification, policy)


def test_certifier_cannot_reauthorize_changed_body_without_approval_key() -> None:
    certification, policy, keys = _package()
    certification["phase_8_evidence_digest"] = _indexed_digest(500)
    _rebind_review_without_approval_signature(certification, keys)

    with pytest.raises(
        subject.StagingCertificationError, match="APPROVAL_SIGNATURE_INVALID"
    ):
        _verify(certification, policy)


def test_certifier_and_approval_authority_must_use_distinct_keys() -> None:
    certification, policy, keys = _package()
    certifier = copy.deepcopy(policy["allowed_signers"][0])
    policy["allowed_approval_signers"] = [certifier]
    policy["policy_digest"] = subject.trust_policy_digest(policy)
    certification["trust_policy_digest"] = policy["policy_digest"]
    approval_signature = certification["independent_review"]["approval_signature"]
    for field in ("key_id", "issuer", "identity", "algorithm"):
        approval_signature[field] = certifier[field]
    certification["independent_review"]["reviewed_body_digest"] = (
        subject.reviewed_certification_body_digest(certification)
    )
    certification["independent_review"]["approval_binding_digest"] = (
        subject.approval_binding_digest(certification)
    )
    approval_signature["value"] = base64.b64encode(
        _canonical_signature(
            keys.certifier,
            subject.canonical_bytes(
                subject.approval_signature_statement(certification)
            ),
        )
    ).decode("ascii")
    _certifier_resign_only(certification, keys)

    with pytest.raises(
        subject.StagingCertificationError,
        match="TRUST_POLICY_SEPARATION_OF_DUTIES_NOT_PROVEN",
    ):
        _verify(certification, policy)


def test_distinct_keys_do_not_make_the_same_identity_independent() -> None:
    certification, policy, keys = _package()
    certifier = policy["allowed_signers"][0]
    approver = policy["allowed_approval_signers"][0]
    approver["identity"] = certifier["identity"]
    policy["policy_digest"] = subject.trust_policy_digest(policy)
    certification["trust_policy_digest"] = policy["policy_digest"]
    certification["independent_review"]["approval_signature"]["identity"] = (
        certifier["identity"]
    )
    _resign(certification, keys)

    with pytest.raises(
        subject.StagingCertificationError,
        match="TRUST_POLICY_SEPARATION_OF_DUTIES_NOT_PROVEN",
    ):
        _verify(certification, policy)


def test_approval_signature_tamper_is_rejected() -> None:
    certification, policy, keys = _package()
    approval_signature = certification["independent_review"]["approval_signature"]
    raw = base64.b64decode(approval_signature["value"])
    approval_signature["value"] = base64.b64encode(
        raw[:-1] + bytes([raw[-1] ^ 1])
    ).decode("ascii")
    _certifier_resign_only(certification, keys)

    with pytest.raises(
        subject.StagingCertificationError, match="APPROVAL_SIGNATURE_INVALID"
    ):
        _verify(certification, policy)


@pytest.mark.parametrize("field", subject.ENVIRONMENT_SCOPED_EVIDENCE_FIELDS)
def test_cross_environment_evidence_replay_is_rejected(field: str) -> None:
    certification, policy, private_key = _package()
    entries = certification["evidence_index"]["entries"]
    entries[1][field] = entries[0][field]
    _resign(certification, private_key)

    with pytest.raises(
        subject.StagingCertificationError, match="ENVIRONMENT_EVIDENCE_DIGEST_REUSE"
    ):
        _verify(certification, policy)


def test_cross_type_evidence_digest_reuse_is_rejected() -> None:
    certification, policy, private_key = _package()
    entry = certification["evidence_index"]["entries"][0]
    entry["saved_plan_digest"] = entry["workflow_run_digest"]
    _resign(certification, private_key)

    with pytest.raises(
        subject.StagingCertificationError,
        match="ENVIRONMENT_EVIDENCE_DIGEST_REUSE",
    ):
        _verify(certification, policy)


@pytest.mark.parametrize(
    "mutate",
    [
        lambda value: value.update(
            phase_8_evidence_digest=value["evidence_index"]["entries"][0][
                "workflow_run_digest"
            ]
        ),
        lambda value: value["operations"].update(
            alerts_digest=value["operations"]["residual_risk_digest"]
        ),
        lambda value: value["independent_review"].update(
            approval_authority_digest=value["independent_review"][
                "approval_evidence_digest"
            ]
        ),
    ],
)
def test_evidence_digest_reuse_across_categories_is_rejected(mutate: Any) -> None:
    certification, policy, keys = _package()
    mutate(certification)
    _resign(certification, keys)

    with pytest.raises(
        subject.StagingCertificationError, match="EVIDENCE_DIGEST_REUSE"
    ):
        _verify(certification, policy)


def test_evidence_older_than_absolute_ceiling_is_rejected() -> None:
    certification, policy, private_key = _package()
    certification["evidence_index"]["entries"][0]["observed_at"] = (
        "2026-08-26T04:00:00Z"
    )
    certification["evidence_index"]["entries"][1]["observed_at"] = (
        "2026-08-26T05:00:00Z"
    )
    certification["observed_at"] = "2026-08-26T05:00:00Z"
    certification["independent_review"]["reviewed_at"] = "2026-08-26T05:10:00Z"
    policy["valid_from"] = "2026-08-20T00:00:00Z"
    policy["policy_digest"] = subject.trust_policy_digest(policy)
    certification["trust_policy_digest"] = policy["policy_digest"]
    _resign(certification, private_key)

    with pytest.raises(subject.StagingCertificationError, match="EVIDENCE_TOO_OLD"):
        _verify(certification, policy)


def test_noncanonical_high_s_signature_is_rejected() -> None:
    certification, policy, _ = _package()
    raw = base64.b64decode(certification["evidence_index_signature"]["value"])
    r, s = decode_dss_signature(raw)
    high_s = encode_dss_signature(r, subject.P256_ORDER - s)
    certification["evidence_index_signature"]["value"] = base64.b64encode(
        high_s
    ).decode("ascii")
    certification["certification_digest"] = subject.certification_digest(certification)

    with pytest.raises(
        subject.StagingCertificationError, match="EVIDENCE_SIGNATURE_INVALID"
    ):
        _verify(certification, policy)


def test_noncanonical_base64_padding_bits_are_rejected() -> None:
    for _ in range(20):
        certification, policy, _ = _package()
        encoded = certification["evidence_index_signature"]["value"]
        if encoded.endswith("="):
            break
    else:  # pragma: no cover - DER lengths normally include base64 padding
        pytest.fail("could not generate a padded ECDSA signature")

    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    padding = len(encoded) - len(encoded.rstrip("="))
    index = len(encoded) - padding - 1
    replacement = alphabet[alphabet.index(encoded[index]) ^ 1]
    alternate = encoded[:index] + replacement + encoded[index + 1 :]
    assert alternate != encoded
    assert base64.b64decode(alternate) == base64.b64decode(encoded)
    certification["evidence_index_signature"]["value"] = alternate
    certification["certification_digest"] = subject.certification_digest(certification)

    with pytest.raises(
        subject.StagingCertificationError, match="EVIDENCE_SIGNATURE_INVALID"
    ):
        _verify(certification, policy)


def test_duplicate_json_keys_are_rejected(tmp_path: Path) -> None:
    path = tmp_path / "duplicate.json"
    path.write_text(
        '{"gate_id":"GUG-127","gate_id":"GUG-128"}', encoding="utf-8"
    )

    with pytest.raises(subject.StagingCertificationError, match="DUPLICATE_JSON_KEY"):
        subject.load_json(path)


def test_repository_anchor_is_intentionally_fail_closed() -> None:
    with pytest.raises(
        subject.StagingCertificationError, match="TRUST_ANCHOR_NOT_CONFIGURED"
    ):
        subject.load_trust_anchor()


def test_public_verifier_has_no_caller_controlled_anchor_or_clock() -> None:
    certification, policy, _ = _package()

    with pytest.raises(
        subject.StagingCertificationError, match="TRUST_ANCHOR_NOT_CONFIGURED"
    ):
        subject.verify_certification(certification, policy)


def test_configured_anchor_pins_digest_epoch_and_window(tmp_path: Path) -> None:
    _, policy, _ = _package()
    path = tmp_path / "anchor.json"
    path.write_text(
        json.dumps(
            {
                "schema_version": "1",
                "record_type": "scanalyze.staging_certification_trust_anchor.v1",
                "gate_id": "GUG-127",
                "configuration_status": "CONFIGURED",
                "trust_epoch": policy["trust_epoch"],
                "trust_policy_digest": policy["policy_digest"],
                "valid_from": "2026-08-29T00:00:00Z",
                "valid_until": "2026-09-05T00:00:00Z",
            }
        ),
        encoding="utf-8",
    )

    anchor = subject._load_trust_anchor_at(path, now=NOW)

    assert anchor["trust_policy_digest"] == policy["policy_digest"]
    assert anchor["trust_epoch"] == 1
