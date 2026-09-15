"""Produce a release VSA from independently admitted evidence and an injected signer.

This module supplies no credentials, cloud adapter, evidence assembler, or CLI.
Pins and the evidence verification record must arrive through authenticated
release-authority custody; deriving pins from these same inputs is not approval.
"""
from __future__ import annotations

import copy
from dataclasses import dataclass
from datetime import UTC, datetime
import hashlib
from typing import Any, Callable, Mapping, Protocol

from tooling import release_policy_gate as gate


@dataclass(frozen=True)
class ReleaseVSAPins:
    manifest_digest: str
    policy_digest: str
    verification_digest: str
    signer_digest: str
    source_commit: str
    verifier_digest: str


@dataclass(frozen=True)
class SigningRequest:
    statement_bytes: bytes
    algorithm: str
    key_id: str
    issuer: str
    identity: str


class SigningClient(Protocol):
    def sign(self, request: SigningRequest) -> Mapping[str, str]:
        """Return the complete signature record for these exact statement bytes."""


@dataclass(frozen=True)
class ProducedVSA:
    attestation_bytes: bytes
    receipt_bytes: bytes


class VSAProductionRejected(ValueError):
    """A fixed error code, without input values or signer exception details."""


VERIFICATION_FIELDS = frozenset({
    "schema_version", "release_manifest_digest", "source_commit", "verifier",
    "time_verified", "verified_levels", "verification_result", "artifact_subjects",
    "evidence_digests",
})
SIGNATURE_FIELDS = frozenset({"algorithm", "key_id", "issuer", "identity", "value"})
EVIDENCE_FIELDS = (("sbom", "digest"), ("scan", "report_digest"),
                   ("provenance", "digest"), ("signature", "bundle_digest"))


def _require(condition: bool, code: str = "VSA_INPUT_REJECTED") -> None:
    if not condition:
        raise VSAProductionRejected(code)


def _now(clock: Callable[[], datetime]) -> datetime:
    value = clock()
    _require(isinstance(value, datetime) and value.tzinfo is not None, "VSA_CLOCK_INVALID")
    return value.astimezone(UTC)


def _snapshot(document: Mapping[str, Any]) -> dict[str, Any]:
    _require(isinstance(document, Mapping))
    result = copy.deepcopy(dict(document))
    gate.canonical_bytes(result)
    return result


def _prepare(manifest, policy, verification, evidence_payloads, signer, pins):
    _require(type(pins) is ReleaseVSAPins)
    _require(all(type(value) is str and value for value in vars(pins).values()))
    _require(not gate._schema_errors(manifest, "release.v2.schema.json"))
    _require(not gate._schema_errors(policy, "release-trust-policy.v1.schema.json"))
    _require(manifest["release_manifest_digest"] == pins.manifest_digest
             == gate.canonical_digest(manifest, omit_fields={"release_manifest_digest"}), "VSA_MANIFEST_PIN_MISMATCH")
    _require(gate.canonical_digest(policy) == pins.policy_digest, "VSA_POLICY_PIN_MISMATCH")
    _require(set(verification) == VERIFICATION_FIELDS
             and verification["schema_version"] == "release-verification-inputs.v1"
             and verification["verification_result"] == "PASSED", "VSA_VERIFICATION_INVALID")
    _require(gate.canonical_digest(verification) == pins.verification_digest, "VSA_VERIFICATION_PIN_MISMATCH")
    _require(gate.canonical_digest(signer) == pins.signer_digest, "VSA_SIGNER_PIN_MISMATCH")
    _require(sum(candidate == signer for candidate in policy["allowed_signers"]) == 1,
             "VSA_SIGNER_NOT_APPROVED")
    # Reject ambiguous tuple aliases even when one public-key record matches.
    _require(sum(all(candidate[field] == signer[field] for field in ("key_id", "issuer", "identity"))
                 for candidate in policy["allowed_signers"]) == 1, "VSA_SIGNER_NOT_APPROVED")
    _require(manifest["source"]["commit"] == verification["source_commit"] == pins.source_commit,
             "VSA_SOURCE_PIN_MISMATCH")
    _require(verification["release_manifest_digest"] == pins.manifest_digest,
             "VSA_VERIFICATION_SUBJECT_MISMATCH")
    vp = policy["verification_policy"]
    _require(verification["verifier"] == {"id": vp["verifier_id"], "version": vp["verifier_version"],
                                          "digest": vp["verifier_digest"]}
             and vp["verifier_digest"] == pins.verifier_digest, "VSA_VERIFIER_PIN_MISMATCH")
    subjects = {key: artifact["digest"] for key, artifact in manifest["artifacts"].items()}
    expected_evidence = [artifact[kind][field] for artifact in manifest["artifacts"].values()
                         for kind, field in EVIDENCE_FIELDS]
    _require(set(subjects) == gate.REQUIRED_ARTIFACT_IDS and len(expected_evidence) == 40
             and len(set(expected_evidence)) == 40, "VSA_EVIDENCE_INCOMPLETE")
    _require(verification["artifact_subjects"] == subjects
             and type(verification["evidence_digests"]) is list
             and len(verification["evidence_digests"]) == 40
             and set(verification["evidence_digests"]) == set(expected_evidence), "VSA_EVIDENCE_INCOMPLETE")
    _require(isinstance(evidence_payloads, Mapping) and set(evidence_payloads) == set(expected_evidence),
             "VSA_EVIDENCE_INCOMPLETE")
    for digest, payload in evidence_payloads.items():
        _require(type(payload) is bytes and bool(payload), "VSA_EVIDENCE_BYTES_INVALID")
        _require("sha256:" + hashlib.sha256(payload).hexdigest() == digest, "VSA_EVIDENCE_BYTES_INVALID")
    # Validate the approved public key before any signing effect.
    from cryptography.hazmat.primitives.asymmetric import ec
    jwk = signer["public_key_jwk"]
    ec.EllipticCurvePublicNumbers(
        int.from_bytes(gate._b64url_decode(jwk["x"]), "big"),
        int.from_bytes(gate._b64url_decode(jwk["y"]), "big"), ec.SECP256R1(),
    ).public_key()
    statement = {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [{"name": "scanalyze-release-manifest", "digest": {
            "sha256": pins.manifest_digest.removeprefix("sha256:")}}],
        "predicateType": "https://slsa.dev/verification_summary/v1",
        "predicate": {
            "verifier": verification["verifier"], "timeVerified": verification["time_verified"],
            "resourceUri": "pkg:generic/scanalyze/release-manifest",
            "policy": {"uri": policy["policy_id"], "digest": pins.policy_digest},
            "inputAttestations": sorted(expected_evidence), "verificationResult": "PASSED",
            "verifiedLevels": verification["verified_levels"], "artifactSubjects": subjects,
        },
    }
    metadata = {"algorithm": "ECDSA_P256_SHA256", **{
        field: signer[field] for field in ("key_id", "issuer", "identity")}}
    return statement, metadata


def produce_release_vsa(
    manifest: Mapping[str, Any],
    policy: Mapping[str, Any],
    verification: Mapping[str, Any],
    evidence_payloads: Mapping[str, bytes],
    signer: Mapping[str, Any],
    *,
    pins: ReleaseVSAPins,
    signing_client: SigningClient,
    clock: Callable[[], datetime] = lambda: datetime.now(UTC),
) -> ProducedVSA:
    """Sign once only after admission; emit immutable bytes only after the full gate.

    The verification record is upstream authority, not a report generated from
    the manifest here. This function hashes its exact evidence bytes but does
    not run scanners, verify Cosign/SLSA bundles, or claim artifact availability.
    """
    try:
        manifest, policy, verification, signer = map(_snapshot, (manifest, policy, verification, signer))
        payloads = dict(evidence_payloads)
        statement, metadata = _prepare(manifest, policy, verification, payloads, signer, pins)
        before = _now(clock)
        admission = gate.admit_release_signing_inputs(
            manifest, statement, metadata, policy,
            expected_policy_digest=pins.policy_digest, evaluated_at=before,
        )
        _require(admission.admitted, "VSA_SIGNING_ADMISSION_REJECTED")
        request = SigningRequest(gate.canonical_bytes(statement), **metadata)
    except VSAProductionRejected:
        raise
    except Exception:
        raise VSAProductionRejected("VSA_INPUT_REJECTED") from None

    # The sole external effect. There is no retry, fallback key, or default client.
    try:
        response = _snapshot(signing_client.sign(request))
    except Exception:
        raise VSAProductionRejected("VSA_SIGNING_FAILED") from None
    try:
        _require(set(response) == SIGNATURE_FIELDS
                 and all(response[key] == value for key, value in metadata.items()), "VSA_SIGNER_RESPONSE_INVALID")
        attestation = {"schema_version": "release-attestation.v2", "statement": statement, "signature": response}
        after = _now(clock)
        _require(after >= before, "VSA_CLOCK_INVALID")
        decision = gate.evaluate_release(manifest, attestation, policy,
                                         expected_policy_digest=pins.policy_digest, evaluated_at=after)
        _require(decision.allowed and decision.code == "RELEASE_POLICY_PASSED", "VSA_POST_SIGN_GATE_REJECTED")
        receipt = {
            "schema_version": "release-vsa-production-receipt.v1", "code": "VSA_PRODUCED_AND_VERIFIED",
            "release_manifest_digest": pins.manifest_digest, "policy_digest": pins.policy_digest,
            "verification_digest": pins.verification_digest, "signer_digest": pins.signer_digest,
            "source_commit": pins.source_commit, "verifier_digest": pins.verifier_digest,
            "statement_digest": gate.canonical_digest(statement),
            "attestation_digest": gate.canonical_digest(attestation),
            "checked_at": after.isoformat().replace("+00:00", "Z"),
        }
        return ProducedVSA(gate.canonical_bytes(attestation), gate.canonical_bytes(receipt))
    except VSAProductionRejected:
        raise
    except Exception:
        raise VSAProductionRejected("VSA_SIGNER_RESPONSE_INVALID") from None
