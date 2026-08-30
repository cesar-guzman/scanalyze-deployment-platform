"""Fail-closed verifier for the GUG-127 staging certification package.

The package contains sanitized digests only.  Raw plans, state, cloud identifiers,
logs, customer data, and credentials stay in the approved external evidence store.
Successful verification proves the staging gate for one exact release; it never
authorizes a production pilot or a production mutation.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Mapping


ROOT = Path(__file__).resolve().parents[1]
SCHEMAS = ROOT / "schemas"
TRUST_ANCHOR_PATH = ROOT / "governance" / "staging-certification-trust-anchor.json"
MAX_EVIDENCE_SPAN = timedelta(hours=72)
MAX_EVIDENCE_AGE = timedelta(hours=72)
MAX_CERTIFICATION_VALIDITY = timedelta(days=7)
SIGNATURE_DOMAIN = "scanalyze.gug127.staging_certification.v1"
APPROVAL_BINDING_DOMAIN = "scanalyze.gug127.independent_approval.v1"
APPROVAL_SIGNATURE_DOMAIN = "scanalyze.gug127.independent_approval_signature.v1"
P256_ORDER = int(
    "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551", 16
)
ENVIRONMENT_SCOPED_EVIDENCE_FIELDS = (
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
)
OPERATION_EVIDENCE_FIELDS = (
    "residual_risk_digest",
    "on_call_digest",
    "change_window_digest",
    "alerts_digest",
    "backups_digest",
)
APPROVAL_EVIDENCE_FIELDS = (
    "approval_evidence_digest",
    "approval_authority_digest",
    "environment_anchor_digest",
)


class StagingCertificationError(ValueError):
    """Public-safe, stable staging certification failure."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class CertificationDecision:
    allowed: bool
    code: str
    certification_digest: str
    evidence_index_digest: str
    production_authorized: bool = False


def _assert_canonical(value: Any, path: str = "$") -> None:
    if value is None or isinstance(value, (str, bool, int)):
        return
    if isinstance(value, float):
        raise StagingCertificationError("NON_CANONICAL_NUMBER")
    if isinstance(value, list):
        for index, item in enumerate(value):
            _assert_canonical(item, f"{path}[{index}]")
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise StagingCertificationError("NON_CANONICAL_KEY")
            _assert_canonical(item, f"{path}.{key}")
        return
    raise StagingCertificationError("NON_CANONICAL_VALUE")


def canonical_bytes(value: Mapping[str, Any]) -> bytes:
    """Return the deterministic JSON profile used by this verifier."""

    _assert_canonical(value)
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def canonical_digest(
    value: Mapping[str, Any], *, omit_fields: frozenset[str] = frozenset()
) -> str:
    candidate = copy.deepcopy(dict(value))
    for field in omit_fields:
        candidate.pop(field, None)
    return "sha256:" + hashlib.sha256(canonical_bytes(candidate)).hexdigest()


def trust_policy_digest(policy: Mapping[str, Any]) -> str:
    return canonical_digest(policy, omit_fields=frozenset({"policy_digest"}))


def evidence_index_digest(index: Mapping[str, Any]) -> str:
    return canonical_digest(index, omit_fields=frozenset({"index_digest"}))


def certification_digest(certification: Mapping[str, Any]) -> str:
    return canonical_digest(
        certification, omit_fields=frozenset({"certification_digest"})
    )


def signed_certification_body_digest(certification: Mapping[str, Any]) -> str:
    """Digest every certification claim except derived/signature bytes."""

    candidate = copy.deepcopy(dict(certification))
    candidate.pop("certification_digest", None)
    signature = candidate.get("evidence_index_signature")
    if isinstance(signature, dict):
        signature.pop("value", None)
    return "sha256:" + hashlib.sha256(canonical_bytes(candidate)).hexdigest()


def reviewed_certification_body_digest(certification: Mapping[str, Any]) -> str:
    """Digest the exact claims independently reviewed, without circular fields."""

    candidate = copy.deepcopy(dict(certification))
    candidate.pop("certification_digest", None)
    signature = candidate.get("evidence_index_signature")
    if isinstance(signature, dict):
        signature.pop("value", None)
    review = candidate.get("independent_review")
    if isinstance(review, dict):
        review.pop("reviewed_body_digest", None)
        review.pop("approval_binding_digest", None)
        approval_signature = review.get("approval_signature")
        if isinstance(approval_signature, dict):
            approval_signature.pop("value", None)
    return "sha256:" + hashlib.sha256(canonical_bytes(candidate)).hexdigest()


def approval_binding_digest(certification: Mapping[str, Any]) -> str:
    """Bind authenticated approval evidence to the exact gate/release/index."""

    review = certification["independent_review"]
    statement = {
        "domain": APPROVAL_BINDING_DOMAIN,
        "gate_id": "GUG-127",
        "certification_id": str(certification["certification_id"]),
        "source_revision": str(certification["source_revision"]),
        "release_digest": str(certification["release_digest"]),
        "evidence_index_digest": str(
            certification["evidence_index"]["index_digest"]
        ),
        "trust_policy_digest": str(certification["trust_policy_digest"]),
        "reviewed_body_digest": str(review["reviewed_body_digest"]),
        "initiator_user_id": int(review["initiator_user_id"]),
        "reviewer_user_id": int(review["reviewer_user_id"]),
        "reviewed_at": str(review["reviewed_at"]),
        "approval_expires_at": str(review["approval_expires_at"]),
        "approval_evidence_digest": str(review["approval_evidence_digest"]),
        "approval_authority_digest": str(review["approval_authority_digest"]),
        "environment_anchor_digest": str(review["environment_anchor_digest"]),
    }
    return "sha256:" + hashlib.sha256(canonical_bytes(statement)).hexdigest()


def signature_statement(certification: Mapping[str, Any]) -> dict[str, str]:
    return {
        "domain": SIGNATURE_DOMAIN,
        "gate_id": "GUG-127",
        "certification_body_digest": signed_certification_body_digest(certification),
    }


def approval_signature_statement(
    certification: Mapping[str, Any],
) -> dict[str, str]:
    return {
        "domain": APPROVAL_SIGNATURE_DOMAIN,
        "gate_id": "GUG-127",
        "approval_binding_digest": str(
            certification["independent_review"]["approval_binding_digest"]
        ),
    }


def _schema_errors(value: Mapping[str, Any], schema_name: str) -> list[str]:
    try:
        from jsonschema import Draft202012Validator, FormatChecker
    except ImportError as exc:  # pragma: no cover - CLI dependency failure
        raise StagingCertificationError("VERIFIER_DEPENDENCY_UNAVAILABLE") from exc

    schema = json.loads((SCHEMAS / schema_name).read_text(encoding="utf-8"))
    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    return [
        error.message
        for error in sorted(
            validator.iter_errors(value), key=lambda item: list(item.absolute_path)
        )
    ]


def _timestamp(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise StagingCertificationError("TIMESTAMP_INVALID") from exc
    if parsed.tzinfo is None:
        raise StagingCertificationError("TIMESTAMP_INVALID")
    return parsed.astimezone(UTC)


def _decode_b64url(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _matching_signer(
    signature: Mapping[str, Any],
    policy: Mapping[str, Any],
    *,
    signer_set: str = "allowed_signers",
) -> Mapping[str, Any] | None:
    fields = ("key_id", "issuer", "identity", "algorithm")
    for signer in policy[signer_set]:
        if all(signature[field] == signer[field] for field in fields):
            return signer
    return None


def _same_signing_authority(
    first: Mapping[str, Any], second: Mapping[str, Any]
) -> bool:
    identity_fields = ("issuer", "identity")
    return all(first[field] == second[field] for field in identity_fields) or (
        first["public_key_jwk"] == second["public_key_jwk"]
    )


def _verify_signature(
    statement: Mapping[str, Any],
    signature: Mapping[str, Any],
    signer: Mapping[str, Any],
) -> bool:
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives.asymmetric.utils import (
            decode_dss_signature,
            encode_dss_signature,
        )
    except ImportError as exc:  # pragma: no cover - CLI dependency failure
        raise StagingCertificationError("VERIFIER_DEPENDENCY_UNAVAILABLE") from exc

    try:
        jwk = signer["public_key_jwk"]
        x = int.from_bytes(_decode_b64url(jwk["x"]), "big")
        y = int.from_bytes(_decode_b64url(jwk["y"]), "big")
        public_key = ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1()).public_key()
        encoded_signature = signature["value"]
        raw_signature = base64.b64decode(encoded_signature, validate=True)
        if base64.b64encode(raw_signature).decode("ascii") != encoded_signature:
            return False
        r, s = decode_dss_signature(raw_signature)
        if s > P256_ORDER // 2 or encode_dss_signature(r, s) != raw_signature:
            return False
        public_key.verify(
            raw_signature,
            canonical_bytes(statement),
            ec.ECDSA(hashes.SHA256()),
        )
    except (InvalidSignature, KeyError, TypeError, ValueError):
        return False
    return True


def _validate_semantics(
    certification: Mapping[str, Any], *, now: datetime
) -> None:
    if now.tzinfo is None:
        raise StagingCertificationError("NOW_MUST_BE_TIMEZONE_AWARE")
    now = now.astimezone(UTC)
    observed_at = _timestamp(str(certification["observed_at"]))
    expires_at = _timestamp(str(certification["expires_at"]))
    if observed_at > now:
        raise StagingCertificationError("CERTIFICATION_FROM_FUTURE")
    if expires_at <= now:
        raise StagingCertificationError("CERTIFICATION_EXPIRED")
    if expires_at <= observed_at:
        raise StagingCertificationError("CERTIFICATION_WINDOW_INVALID")
    if expires_at - observed_at > MAX_CERTIFICATION_VALIDITY:
        raise StagingCertificationError("CERTIFICATION_WINDOW_TOO_LONG")

    entries = certification["evidence_index"]["entries"]
    environments = [entry["logical_environment"] for entry in entries]
    if set(environments) != {"dev", "staging"} or len(set(environments)) != 2:
        raise StagingCertificationError("TWO_ENVIRONMENT_EVIDENCE_REQUIRED")
    if len({entry["evidence_id"] for entry in entries}) != 2:
        raise StagingCertificationError("EVIDENCE_ID_REUSED")
    if len({entry["deployment_binding_digest"] for entry in entries}) != 2:
        raise StagingCertificationError("ENVIRONMENT_ISOLATION_NOT_PROVEN")
    environment_evidence_digests = [
        entry[field]
        for entry in entries
        for field in ENVIRONMENT_SCOPED_EVIDENCE_FIELDS
    ]
    if len(set(environment_evidence_digests)) != len(environment_evidence_digests):
        raise StagingCertificationError("ENVIRONMENT_EVIDENCE_DIGEST_REUSE")
    if any(
        entry["release_digest"] != certification["release_digest"]
        for entry in entries
    ):
        raise StagingCertificationError("RELEASE_BINDING_MISMATCH")
    if (
        certification["release_digest"]
        == certification["last_known_good_release_digest"]
    ):
        raise StagingCertificationError("LAST_KNOWN_GOOD_NOT_DISTINCT")
    operations = certification["operations"]
    review = certification["independent_review"]
    all_evidence_digests = [
        certification["release_digest"],
        certification["last_known_good_release_digest"],
        certification["phase_8_evidence_digest"],
        *(entry["deployment_binding_digest"] for entry in entries),
        *environment_evidence_digests,
        *(operations[field] for field in OPERATION_EVIDENCE_FIELDS),
        *(review[field] for field in APPROVAL_EVIDENCE_FIELDS),
    ]
    if len(set(all_evidence_digests)) != len(all_evidence_digests):
        raise StagingCertificationError("EVIDENCE_DIGEST_REUSE")

    entry_times = [_timestamp(str(entry["observed_at"])) for entry in entries]
    if max(entry_times) != observed_at:
        raise StagingCertificationError("OBSERVATION_FRONTIER_MISMATCH")
    if any(item > now for item in entry_times):
        raise StagingCertificationError("EVIDENCE_FROM_FUTURE")
    if any(now - item > MAX_EVIDENCE_AGE for item in entry_times):
        raise StagingCertificationError("EVIDENCE_TOO_OLD")
    if max(entry_times) - min(entry_times) > MAX_EVIDENCE_SPAN:
        raise StagingCertificationError("MIXED_STALE_EVIDENCE")

    if review["initiator_user_id"] == review["reviewer_user_id"]:
        raise StagingCertificationError("SELF_REVIEW_REJECTED")
    reviewed_at = _timestamp(str(review["reviewed_at"]))
    if reviewed_at < observed_at or reviewed_at > now:
        raise StagingCertificationError("REVIEW_TIME_INVALID")
    approval_expires_at = _timestamp(str(review["approval_expires_at"]))
    if approval_expires_at <= now:
        raise StagingCertificationError("APPROVAL_EXPIRED")
    if approval_expires_at <= reviewed_at or approval_expires_at > expires_at:
        raise StagingCertificationError("APPROVAL_WINDOW_INVALID")


def _validate_trust_policy(
    policy: Mapping[str, Any],
    certification: Mapping[str, Any],
    *,
    now: datetime,
) -> None:
    valid_from = _timestamp(str(policy["valid_from"]))
    valid_until = _timestamp(str(policy["valid_until"]))
    if valid_until <= valid_from:
        raise StagingCertificationError("TRUST_POLICY_WINDOW_INVALID")
    if now < valid_from:
        raise StagingCertificationError("TRUST_POLICY_NOT_YET_VALID")
    if now >= valid_until:
        raise StagingCertificationError("TRUST_POLICY_EXPIRED")
    reviewed_at = _timestamp(str(certification["independent_review"]["reviewed_at"]))
    certification_expires_at = _timestamp(str(certification["expires_at"]))
    if reviewed_at < valid_from or certification_expires_at > valid_until:
        raise StagingCertificationError("TRUST_POLICY_CERTIFICATION_WINDOW_MISMATCH")
    if any(
        _same_signing_authority(certifier, approver)
        for certifier in policy["allowed_signers"]
        for approver in policy["allowed_approval_signers"]
    ):
        raise StagingCertificationError(
            "TRUST_POLICY_SEPARATION_OF_DUTIES_NOT_PROVEN"
        )


def _verify_certification_at(
    certification: Mapping[str, Any],
    trust_policy: Mapping[str, Any],
    *,
    expected_trust_policy_digest: str,
    expected_trust_epoch: int,
    now: datetime | None = None,
) -> CertificationDecision:
    """Internal deterministic verifier with explicit testable trust inputs."""

    _assert_canonical(certification)
    _assert_canonical(trust_policy)
    if _schema_errors(
        trust_policy, "staging-certification-trust-policy.v1.schema.json"
    ):
        raise StagingCertificationError("TRUST_POLICY_SCHEMA_INVALID")
    if _schema_errors(certification, "staging-certification.v1.schema.json"):
        raise StagingCertificationError("CERTIFICATION_SCHEMA_INVALID")

    verification_time = now or datetime.now(UTC)
    if verification_time.tzinfo is None:
        raise StagingCertificationError("NOW_MUST_BE_TIMEZONE_AWARE")
    verification_time = verification_time.astimezone(UTC)

    computed_policy_digest = trust_policy_digest(trust_policy)
    if trust_policy["policy_digest"] != computed_policy_digest:
        raise StagingCertificationError("TRUST_POLICY_DIGEST_MISMATCH")
    if computed_policy_digest != expected_trust_policy_digest:
        raise StagingCertificationError("TRUST_ANCHOR_DIGEST_MISMATCH")
    if trust_policy["trust_epoch"] != expected_trust_epoch:
        raise StagingCertificationError("TRUST_ANCHOR_EPOCH_MISMATCH")
    _validate_trust_policy(
        trust_policy, certification, now=verification_time
    )
    if certification["trust_policy_digest"] != computed_policy_digest:
        raise StagingCertificationError("TRUST_POLICY_BINDING_MISMATCH")

    index = certification["evidence_index"]
    expected_index_digest = evidence_index_digest(index)
    if index["index_digest"] != expected_index_digest:
        raise StagingCertificationError("EVIDENCE_INDEX_DIGEST_MISMATCH")
    expected_reviewed_body = reviewed_certification_body_digest(certification)
    if (
        certification["independent_review"]["reviewed_body_digest"]
        != expected_reviewed_body
    ):
        raise StagingCertificationError("REVIEWED_BODY_DIGEST_MISMATCH")
    expected_approval_binding = approval_binding_digest(certification)
    if (
        certification["independent_review"]["approval_binding_digest"]
        != expected_approval_binding
    ):
        raise StagingCertificationError("APPROVAL_BINDING_MISMATCH")
    expected_certification_digest = certification_digest(certification)
    if certification["certification_digest"] != expected_certification_digest:
        raise StagingCertificationError("CERTIFICATION_DIGEST_MISMATCH")

    _validate_semantics(certification, now=verification_time)
    signature = certification["evidence_index_signature"]
    signer = _matching_signer(signature, trust_policy)
    if signer is None:
        raise StagingCertificationError("UNTRUSTED_EVIDENCE_SIGNER")
    approval_signature = certification["independent_review"]["approval_signature"]
    approval_signer = _matching_signer(
        approval_signature,
        trust_policy,
        signer_set="allowed_approval_signers",
    )
    if approval_signer is None:
        raise StagingCertificationError("UNTRUSTED_APPROVAL_SIGNER")
    if _same_signing_authority(signer, approval_signer):
        raise StagingCertificationError("APPROVAL_SEPARATION_OF_DUTIES_NOT_PROVEN")
    if not _verify_signature(
        approval_signature_statement(certification),
        approval_signature,
        approval_signer,
    ):
        raise StagingCertificationError("APPROVAL_SIGNATURE_INVALID")
    if not _verify_signature(signature_statement(certification), signature, signer):
        raise StagingCertificationError("EVIDENCE_SIGNATURE_INVALID")

    return CertificationDecision(
        allowed=True,
        code="STAGING_CERTIFIED",
        certification_digest=expected_certification_digest,
        evidence_index_digest=expected_index_digest,
        production_authorized=False,
    )


def verify_certification(
    certification: Mapping[str, Any], trust_policy: Mapping[str, Any]
) -> CertificationDecision:
    """Verify using only the repository-pinned anchor and current UTC clock."""

    now = datetime.now(UTC)
    anchor = load_trust_anchor()
    return _verify_certification_at(
        certification,
        trust_policy,
        now=now,
        expected_trust_policy_digest=str(anchor["trust_policy_digest"]),
        expected_trust_epoch=int(anchor["trust_epoch"]),
    )


def _object_without_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise StagingCertificationError("DUPLICATE_JSON_KEY")
        value[key] = item
    return value


def load_json(path: Path) -> Mapping[str, Any]:
    try:
        value = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=_object_without_duplicate_keys,
        )
    except StagingCertificationError:
        raise
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise StagingCertificationError("INPUT_DOCUMENT_INVALID") from exc
    if not isinstance(value, dict):
        raise StagingCertificationError("INPUT_DOCUMENT_INVALID")
    return value


def _load_trust_anchor_at(path: Path, *, now: datetime) -> Mapping[str, Any]:
    """Internal deterministic anchor loader used by hermetic tests."""

    anchor = load_json(path)
    if _schema_errors(
        anchor, "staging-certification-trust-anchor.v1.schema.json"
    ):
        raise StagingCertificationError("TRUST_ANCHOR_SCHEMA_INVALID")
    if anchor["configuration_status"] != "CONFIGURED":
        raise StagingCertificationError("TRUST_ANCHOR_NOT_CONFIGURED")
    if now.tzinfo is None:
        raise StagingCertificationError("NOW_MUST_BE_TIMEZONE_AWARE")
    verification_time = now.astimezone(UTC)
    valid_from = _timestamp(str(anchor["valid_from"]))
    valid_until = _timestamp(str(anchor["valid_until"]))
    if valid_until <= valid_from:
        raise StagingCertificationError("TRUST_ANCHOR_WINDOW_INVALID")
    if verification_time < valid_from:
        raise StagingCertificationError("TRUST_ANCHOR_NOT_YET_VALID")
    if verification_time >= valid_until:
        raise StagingCertificationError("TRUST_ANCHOR_EXPIRED")
    return anchor


def load_trust_anchor() -> Mapping[str, Any]:
    """Load only the fixed repository anchor using the current UTC clock."""

    return _load_trust_anchor_at(TRUST_ANCHOR_PATH, now=datetime.now(UTC))
