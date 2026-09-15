"""Synthetic, ephemeral-key signing with the real admission and release gate."""
import base64
from copy import deepcopy
from dataclasses import replace
from datetime import UTC, datetime, timedelta
import hashlib
import json
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
import pytest

from tooling import release_policy_gate as gate
from tooling import release_vsa_producer as producer

ROOT = Path(__file__).resolve().parents[2]
NOW = datetime(2026, 7, 14, 11, tzinfo=UTC)


class EphemeralSigner:
    def __init__(self):
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.requests = []

    def sign(self, request):
        self.requests.append(request)
        signature = self.key.sign(request.statement_bytes, ec.ECDSA(hashes.SHA256()))
        return {name: getattr(request, name) for name in ("algorithm", "key_id", "issuer", "identity")} | {
            "value": base64.b64encode(signature).decode()}

    def jwk(self):
        public = self.key.public_key().public_numbers()
        return {"kty": "EC", "crv": "P-256", **{
            name: base64.urlsafe_b64encode(getattr(public, name).to_bytes(32, "big")).decode().rstrip("=")
            for name in ("x", "y")}}


def reanchor(bundle):
    """Synthetic authority only: tests explicitly approve the changed inputs."""
    manifest, policy, verification = (bundle[name] for name in ("manifest", "policy", "verification"))
    manifest["policy_digest"] = gate.canonical_digest(policy)
    manifest["release_manifest_digest"] = gate.canonical_digest(manifest, omit_fields={"release_manifest_digest"})
    verification["release_manifest_digest"] = manifest["release_manifest_digest"]
    bundle["pins"] = producer.ReleaseVSAPins(
        manifest["release_manifest_digest"], gate.canonical_digest(policy), gate.canonical_digest(verification),
        gate.canonical_digest(bundle["signer"]), manifest["source"]["commit"],
        policy["verification_policy"]["verifier_digest"],
    )


@pytest.fixture
def bundle():
    manifest = json.loads((ROOT / "fixtures/valid/release-v2-complete.synthetic.json").read_text())
    policy = json.loads((ROOT / "fixtures/valid/release-trust-policy-v1-synthetic.json").read_text())
    client = EphemeralSigner()
    signer = deepcopy(policy["allowed_signers"][0])
    signer["public_key_jwk"] = client.jwk()
    policy["allowed_signers"] = [deepcopy(signer)]
    policy["verification_policy"]["verifier_digest"] = "sha256:" + hashlib.sha256(
        (ROOT / "tooling/release_policy_gate.py").read_bytes()).hexdigest()
    payloads = {}
    for artifact_id, artifact in manifest["artifacts"].items():
        for kind, field in producer.EVIDENCE_FIELDS:
            payload = json.dumps({"synthetic": True, "artifact": artifact_id, "kind": kind}).encode()
            digest = "sha256:" + hashlib.sha256(payload).hexdigest()
            artifact[kind][field] = digest
            payloads[digest] = payload
    vp = policy["verification_policy"]
    verification = {
        "schema_version": "release-verification-inputs.v1", "verification_result": "PASSED",
        "release_manifest_digest": manifest["release_manifest_digest"],
        "source_commit": manifest["source"]["commit"],
        "verifier": {"id": vp["verifier_id"], "version": vp["verifier_version"], "digest": vp["verifier_digest"]},
        "time_verified": "2026-07-14T10:50:00Z", "verified_levels": ["SLSA_BUILD_LEVEL_3"],
        "artifact_subjects": {key: value["digest"] for key, value in manifest["artifacts"].items()},
        "evidence_digests": sorted(payloads),
    }
    result = dict(manifest=manifest, policy=policy, verification=verification, evidence_payloads=payloads,
                  signer=signer, signing_client=client, clock=lambda: NOW)
    reanchor(result)
    return result


def test_real_signing_and_full_gate_cover_exact_ten_artifacts_and_forty_inputs(bundle):
    result = producer.produce_release_vsa(**bundle)
    attestation, receipt = json.loads(result.attestation_bytes), json.loads(result.receipt_bytes)
    request, = bundle["signing_client"].requests
    assert request.statement_bytes == gate.canonical_bytes(attestation["statement"])
    assert len(attestation["statement"]["predicate"]["inputAttestations"]) == 40
    assert set(attestation["statement"]["predicate"]["artifactSubjects"]) == gate.REQUIRED_ARTIFACT_IDS
    assert attestation["statement"]["predicate"]["verifiedLevels"] == ["SLSA_BUILD_LEVEL_3"]
    decision = gate.evaluate_release(bundle["manifest"], attestation, bundle["policy"],
                                    expected_policy_digest=bundle["pins"].policy_digest, evaluated_at=NOW)
    assert decision.allowed and decision.code == "RELEASE_POLICY_PASSED"
    assert receipt["attestation_digest"] == gate.canonical_digest(attestation)
    assert receipt["verification_digest"] == bundle["pins"].verification_digest
    assert result.attestation_bytes == gate.canonical_bytes(attestation)


@pytest.mark.parametrize("field", list(producer.ReleaseVSAPins.__dataclass_fields__))
def test_independent_pin_cannot_be_replaced_by_resealing_inputs(bundle, field):
    original = getattr(bundle["pins"], field)
    bundle["pins"] = replace(bundle["pins"], **{field: "b" * 40 if field == "source_commit" else "sha256:" + "f" * 64})
    assert original != getattr(bundle["pins"], field)
    with pytest.raises(producer.VSAProductionRejected):
        producer.produce_release_vsa(**bundle)
    assert bundle["signing_client"].requests == []


@pytest.mark.parametrize("mode", ["manifest", "policy", "verification"])
def test_resealed_substitution_still_requires_original_external_authority(bundle, mode):
    approved = bundle["pins"]
    if mode == "manifest": bundle["manifest"]["release_version"] = "9.9.9"
    elif mode == "policy": bundle["policy"]["allowed_source_refs"].append("refs/heads/unreviewed")
    else: bundle["verification"]["time_verified"] = "2026-07-14T10:51:00Z"
    reanchor(bundle)
    bundle["pins"] = approved
    with pytest.raises(producer.VSAProductionRejected): producer.produce_release_vsa(**bundle)
    assert bundle["signing_client"].requests == []


def finding_with_waiver(bundle, expires):
    artifact_id = "scanalyze-bank-worker"
    scan = bundle["manifest"]["artifacts"][artifact_id]["scan"]
    scan.update(high_findings=1, findings=[{"id": "CVE-SYNTHETIC-123", "severity": "high", "status": "waived"}])
    bundle["manifest"]["waivers"] = [{
        "waiver_id": "wav_synthetic", "artifact_id": artifact_id, "finding_id": "CVE-SYNTHETIC-123",
        "severity": "high", "approved_by_role": bundle["policy"]["waiver_policy"]["approver_roles"][0],
        "approved_at": "2026-07-14T10:00:00Z", "expires_at": expires,
        "reason": "Synthetic bounded test waiver only",
    }]


@pytest.mark.parametrize("mode", [
    "missing_artifact", "missing_payload", "extra_payload", "corrupt_payload", "reused_evidence",
    "wrong_subject", "wrong_source", "wrong_builder", "wrong_toolchain", "future_manifest",
    "future_verification", "insufficient_level", "failed_verification", "wrong_verifier",
    "wrong_signer_identity", "ambiguous_signer", "invalid_public_key", "rebuild", "high_finding",
    "expired_waiver", "duplicate_verification_digest", "unexpected_verification_field",
])
def test_invalid_inputs_never_reach_signing_effect_even_with_fresh_synthetic_pins(bundle, mode):
    m, p, v = (bundle[key] for key in ("manifest", "policy", "verification"))
    a = m["artifacts"]["scanalyze-bank-worker"]
    if mode == "missing_artifact": del m["artifacts"]["scanalyze-frontend-ui"]
    elif mode == "missing_payload": bundle["evidence_payloads"].pop(next(iter(bundle["evidence_payloads"])))
    elif mode == "extra_payload": bundle["evidence_payloads"]["sha256:" + "a" * 64] = b"synthetic"
    elif mode == "corrupt_payload": bundle["evidence_payloads"][next(iter(bundle["evidence_payloads"]))] = b"changed"
    elif mode == "reused_evidence": a["sbom"]["digest"] = a["provenance"]["digest"]
    elif mode == "wrong_subject": a["scan"]["subject_digest"] = "sha256:" + "a" * 64
    elif mode == "wrong_source": m["source"]["ref"] = "refs/heads/unreviewed"
    elif mode == "wrong_builder": m["builder"]["workflow_ref"] = m["builder"]["workflow_ref"].replace(".yml@", "-other.yml@")
    elif mode == "wrong_toolchain": a["scan"]["scanner"]["version"] = "v0.0.1"
    elif mode == "future_manifest": m["created_at"] = "2026-07-15T10:45:00Z"
    elif mode == "future_verification": v["time_verified"] = "2026-07-15T10:50:00Z"
    elif mode == "insufficient_level": v["verified_levels"] = ["SLSA_BUILD_LEVEL_1"]
    elif mode == "failed_verification": v["verification_result"] = "FAILED"
    elif mode == "wrong_verifier": v["verifier"]["version"] = "0.0.1"
    elif mode == "wrong_signer_identity":
        bundle["signer"]["identity"] = "https://issuer.invalid/foreign"
        p["allowed_signers"] = [deepcopy(bundle["signer"])]
    elif mode == "ambiguous_signer": p["allowed_signers"].append(deepcopy(bundle["signer"]))
    elif mode == "invalid_public_key":
        bundle["signer"]["public_key_jwk"].update(x="A" * 43, y="A" * 43)
        p["allowed_signers"] = [deepcopy(bundle["signer"])]
    elif mode == "rebuild": m["promotion"]["rebuild"] = True
    elif mode == "high_finding": a["scan"].update(high_findings=1, findings=[{"id": "CVE-SYNTHETIC-123", "severity": "high", "status": "active"}])
    elif mode == "expired_waiver": finding_with_waiver(bundle, "2026-07-14T10:59:00Z")
    elif mode == "duplicate_verification_digest": v["evidence_digests"][0] = v["evidence_digests"][1]
    else: v["extra"] = "unreviewed"
    reanchor(bundle)
    with pytest.raises(producer.VSAProductionRejected): producer.produce_release_vsa(**bundle)
    assert bundle["signing_client"].requests == []


@pytest.mark.parametrize("mode", ["wrong_key", "wrong_bytes", "corrupt_signature", "wrong_identity", "wrong_algorithm", "extra", "missing", "timeout"])
def test_bad_signer_response_never_produces_receipt(bundle, mode, capsys):
    original = bundle["signing_client"]
    class BadSigner:
        def sign(self, request):
            if mode == "timeout":
                original.requests.append(request)
                raise TimeoutError("synthetic-secret-sentinel")
            if mode == "wrong_bytes": request = replace(request, statement_bytes=request.statement_bytes + b"\n")
            response = original.sign(request)
            if mode == "wrong_key": response = EphemeralSigner().sign(request)
            elif mode == "corrupt_signature": response["value"] = "AAAA"
            elif mode == "wrong_identity": response["identity"] = "https://issuer.invalid/other"
            elif mode == "wrong_algorithm": response["algorithm"] = "other"
            elif mode == "extra": response["extra"] = "unreviewed"
            elif mode == "missing": del response["value"]
            return response
    bundle["signing_client"] = BadSigner()
    with pytest.raises(producer.VSAProductionRejected) as failure:
        producer.produce_release_vsa(**bundle)
    assert len(original.requests) == 1
    assert "synthetic-secret-sentinel" not in str(failure.value)
    assert capsys.readouterr() == ("", "")


def test_gate_rechecks_waiver_freshness_after_signing_and_emits_no_receipt(bundle):
    finding_with_waiver(bundle, "2026-07-14T11:00:01Z")
    reanchor(bundle)
    times = iter((NOW, NOW + timedelta(seconds=2)))
    bundle["clock"] = lambda: next(times)
    with pytest.raises(producer.VSAProductionRejected, match="VSA_POST_SIGN_GATE_REJECTED"):
        producer.produce_release_vsa(**bundle)
    assert len(bundle["signing_client"].requests) == 1


def test_inputs_cannot_be_mutated_by_signing_callback_after_admission(bundle):
    original = bundle["signing_client"]
    expected = bundle["pins"].manifest_digest
    class MutatingSigner:
        def sign(self, request):
            bundle["manifest"]["source"]["commit"] = "b" * 40
            bundle["policy"]["allowed_signers"] = []
            bundle["verification"]["verification_result"] = "FAILED"
            return original.sign(request)
    bundle["signing_client"] = MutatingSigner()
    output = producer.produce_release_vsa(**bundle)
    assert json.loads(output.receipt_bytes)["release_manifest_digest"] == expected


@pytest.mark.parametrize("mode", ["naive", "backwards"])
def test_invalid_clock_cannot_produce_receipt(bundle, mode):
    times = iter((NOW, NOW - timedelta(seconds=1)))
    bundle["clock"] = (lambda: NOW.replace(tzinfo=None)) if mode == "naive" else lambda: next(times)
    with pytest.raises(producer.VSAProductionRejected, match="VSA_CLOCK_INVALID"):
        producer.produce_release_vsa(**bundle)
    assert len(bundle["signing_client"].requests) == (0 if mode == "naive" else 1)


def test_unsigned_admission_is_not_a_promotion_decision_or_consumer_input(bundle):
    completed = producer.produce_release_vsa(**bundle)
    attestation = json.loads(completed.attestation_bytes)
    metadata = {key: value for key, value in attestation["signature"].items() if key != "value"}
    admission = gate.admit_release_signing_inputs(bundle["manifest"], attestation["statement"], metadata, bundle["policy"],
                                                 expected_policy_digest=bundle["pins"].policy_digest, evaluated_at=NOW)
    assert admission.admitted and admission.code == "SIGNING_INPUTS_ADMITTED"
    assert not hasattr(admission, "allowed")
    for unsigned in (admission, {"schema_version": "release-attestation.v2", "statement": attestation["statement"]}):
        decision = gate.evaluate_release(bundle["manifest"], unsigned, bundle["policy"],
                                        expected_policy_digest=bundle["pins"].policy_digest, evaluated_at=NOW)
        assert not decision.allowed and decision.code != "RELEASE_POLICY_PASSED"
        with pytest.raises(ValueError):
            gate.build_deployment_projection(bundle["manifest"], unsigned, bundle["policy"], target="production",
                                             expected_policy_digest=bundle["pins"].policy_digest, evaluated_at=NOW)
    with pytest.raises(TypeError):
        gate.evaluate_release(bundle["manifest"], attestation, bundle["policy"],
                              expected_policy_digest=bundle["pins"].policy_digest, skip_signature=True)


@pytest.mark.parametrize("mode", ["statement_missing", "statement_extra", "metadata_missing", "metadata_fake_signature"])
def test_unsigned_subschemas_are_closed_and_never_accept_a_fake_signature(bundle, mode):
    attestation = json.loads(producer.produce_release_vsa(**bundle).attestation_bytes)
    metadata = {key: value for key, value in attestation["signature"].items() if key != "value"}
    if mode == "statement_missing": del attestation["statement"]["subject"]
    elif mode == "statement_extra": attestation["statement"]["unknown"] = True
    elif mode == "metadata_missing": del metadata["issuer"]
    else: metadata["value"] = "AAAA"
    admission = gate.admit_release_signing_inputs(bundle["manifest"], attestation["statement"], metadata, bundle["policy"],
                                                 expected_policy_digest=bundle["pins"].policy_digest, evaluated_at=NOW)
    assert not admission.admitted and admission.code == "ATTESTATION_SCHEMA_INVALID"
