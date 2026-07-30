"""GUG-124 fail-closed release policy and promotion tests."""

from __future__ import annotations

import copy
import json
import pathlib
import subprocess
import sys
from datetime import UTC, datetime

import pytest


ROOT = pathlib.Path(__file__).resolve().parents[2]
FIXTURES = ROOT / "fixtures"
sys.path.insert(0, str(ROOT / "tooling"))

from release_policy_gate import (  # noqa: E402
    REQUIRED_ARTIFACT_IDS,
    build_deployment_projection,
    canonical_digest,
    evaluate_release,
)


NOW = datetime(2026, 7, 14, 12, 0, tzinfo=UTC)
EXPECTED_POLICY_DIGEST = (
    FIXTURES / "valid" / "release-trust-policy-v1-synthetic.sha256"
).read_text(encoding="utf-8").strip()


def _load(name: str, *, valid: bool = True) -> dict[str, object]:
    directory = "valid" if valid else "invalid"
    return json.loads((FIXTURES / directory / name).read_text(encoding="utf-8"))


@pytest.fixture
def bundle() -> tuple[dict[str, object], dict[str, object], dict[str, object]]:
    return (
        _load("release-v2-complete.synthetic.json"),
        _load("release-attestation-v2-complete.synthetic.json"),
        _load("release-trust-policy-v1-synthetic.json"),
    )


def _evaluate(
    bundle: tuple[dict[str, object], dict[str, object], dict[str, object]],
):
    manifest, attestation, policy = bundle
    return evaluate_release(
        manifest,
        attestation,
        policy,
        expected_policy_digest=EXPECTED_POLICY_DIGEST,
        evaluated_at=NOW,
    )


def _rebind_manifest(
    manifest: dict[str, object], attestation: dict[str, object]
) -> None:
    digest = canonical_digest(manifest, omit_fields={"release_manifest_digest"})
    manifest["release_manifest_digest"] = digest
    attestation["statement"]["subject"][0]["digest"]["sha256"] = digest.removeprefix(
        "sha256:"
    )


def _add_high_waiver(
    manifest: dict[str, object],
    *,
    waiver_id: str,
    approved_at: str,
    expires_at: str,
) -> None:
    scan = manifest["artifacts"]["scanalyze-ingest-api"]["scan"]
    scan["high_findings"] = 1
    scan["findings"] = [
        {"id": "CVE-SYNTHETIC-0099", "severity": "high", "status": "waived"}
    ]
    manifest["waivers"] = [
        {
            "waiver_id": waiver_id,
            "artifact_id": "scanalyze-ingest-api",
            "finding_id": "CVE-SYNTHETIC-0099",
            "severity": "high",
            "approved_by_role": "security_approver",
            "approved_at": approved_at,
            "expires_at": expires_at,
            "reason": "Synthetic temporal boundary fixture",
        }
    ]


def test_complete_signed_release_is_allowed(bundle) -> None:
    decision = _evaluate(bundle)

    assert decision.allowed is True
    assert decision.code == "RELEASE_POLICY_PASSED"
    assert decision.manifest_digest == bundle[0]["release_manifest_digest"]
    assert all(check.status == "PASSED" for check in decision.checks)


def test_release_requires_exact_artifact_inventory(bundle) -> None:
    manifest, attestation, policy = copy.deepcopy(bundle)
    del manifest["artifacts"]["scanalyze-gov-worker"]

    decision = _evaluate((manifest, attestation, policy))

    assert decision.allowed is False
    assert decision.code == "RELEASE_SCHEMA_INVALID"


@pytest.mark.parametrize("evidence_name", ["sbom", "scan", "provenance", "signature"])
def test_missing_evidence_fails_closed(bundle, evidence_name: str) -> None:
    manifest, attestation, policy = copy.deepcopy(bundle)
    del manifest["artifacts"]["scanalyze-ingest-api"][evidence_name]

    decision = _evaluate((manifest, attestation, policy))

    assert decision.allowed is False
    assert decision.code == "RELEASE_SCHEMA_INVALID"


def test_missing_toolchain_entry_fails_closed(bundle) -> None:
    manifest, attestation, policy = copy.deepcopy(bundle)
    del manifest["builder"]["toolchain"]["trivy"]

    decision = _evaluate((manifest, attestation, policy))

    assert decision.allowed is False
    assert decision.code == "RELEASE_SCHEMA_INVALID"


def test_unapproved_runner_image_is_denied(bundle) -> None:
    manifest, attestation, policy = copy.deepcopy(bundle)
    manifest["builder"]["runner_image"] = (
        "ghcr.io/actions/runner@sha256:" + "c" * 64
    )
    _rebind_manifest(manifest, attestation)

    decision = _evaluate((manifest, attestation, policy))

    assert decision.allowed is False
    assert decision.code == "BUILDER_NOT_TRUSTED"


def test_unapproved_workflow_path_is_denied(bundle) -> None:
    manifest, attestation, policy = copy.deepcopy(bundle)
    manifest["builder"]["workflow_ref"] = (
        "cesar-guzman/scanalyze-deployment-platform/"
        ".github/workflows/unreviewed.yml@"
        + manifest["source"]["commit"]
    )
    _rebind_manifest(manifest, attestation)

    decision = _evaluate((manifest, attestation, policy))

    assert decision.allowed is False
    assert decision.code == "BUILDER_NOT_TRUSTED"


def test_unapproved_base_image_is_denied(bundle) -> None:
    manifest, attestation, policy = copy.deepcopy(bundle)
    artifact = manifest["artifacts"]["scanalyze-ingest-api"]
    artifact["base_image_uri"] = (
        "registry.invalid/scanalyze/python-runtime@sha256:" + "c" * 64
    )
    artifact["base_image_digest"] = "sha256:" + "c" * 64
    _rebind_manifest(manifest, attestation)

    decision = _evaluate((manifest, attestation, policy))

    assert decision.allowed is False
    assert decision.code == "BASE_IMAGE_NOT_APPROVED"


@pytest.mark.parametrize(
    "uri",
    [
        "registry.invalid/scanalyze/ingest-api:latest",
        "registry.invalid/scanalyze/ingest-api:v2.4.0",
        "registry.invalid/scanalyze/ingest-api@sha256:aaaaaaaa",
    ],
)
def test_mutable_or_malformed_artifact_reference_is_denied(bundle, uri: str) -> None:
    manifest, attestation, policy = copy.deepcopy(bundle)
    manifest["artifacts"]["scanalyze-ingest-api"]["uri"] = uri

    decision = _evaluate((manifest, attestation, policy))

    assert decision.allowed is False
    assert decision.code in {"RELEASE_SCHEMA_INVALID", "ARTIFACT_DIGEST_MISMATCH"}


def test_artifact_subject_mismatch_is_denied(bundle) -> None:
    manifest, attestation, policy = copy.deepcopy(bundle)
    manifest["artifacts"]["scanalyze-ingest-api"]["sbom"]["subject_digest"] = (
        "sha256:" + "f" * 64
    )
    _rebind_manifest(manifest, attestation)

    decision = _evaluate((manifest, attestation, policy))

    assert decision.allowed is False
    assert decision.code == "EVIDENCE_SUBJECT_MISMATCH"


def test_critical_finding_cannot_be_waived(bundle) -> None:
    manifest, attestation, policy = copy.deepcopy(bundle)
    scan = manifest["artifacts"]["scanalyze-ingest-api"]["scan"]
    scan["critical_findings"] = 1
    scan["findings"] = [
        {"id": "CVE-SYNTHETIC-0001", "severity": "critical", "status": "waived"}
    ]
    manifest["waivers"] = [
        {
            "waiver_id": "wav_synthetic_critical",
            "artifact_id": "scanalyze-ingest-api",
            "finding_id": "CVE-SYNTHETIC-0001",
            "severity": "critical",
            "approved_by_role": "security_approver",
            "approved_at": "2026-07-14T10:00:00Z",
            "expires_at": "2026-07-15T10:00:00Z",
            "reason": "Synthetic negative fixture only",
        }
    ]
    _rebind_manifest(manifest, attestation)

    decision = _evaluate((manifest, attestation, policy))

    assert decision.allowed is False
    assert decision.code == "CRITICAL_FINDING"


def test_expired_waiver_is_denied(bundle) -> None:
    manifest, attestation, policy = copy.deepcopy(bundle)
    scan = manifest["artifacts"]["scanalyze-ingest-api"]["scan"]
    scan["high_findings"] = 1
    scan["findings"] = [
        {"id": "CVE-SYNTHETIC-0002", "severity": "high", "status": "waived"}
    ]
    manifest["waivers"] = [
        {
            "waiver_id": "wav_synthetic_expired",
            "artifact_id": "scanalyze-ingest-api",
            "finding_id": "CVE-SYNTHETIC-0002",
            "severity": "high",
            "approved_by_role": "security_approver",
            "approved_at": "2026-07-01T10:00:00Z",
            "expires_at": "2026-07-02T10:00:00Z",
            "reason": "Synthetic expired waiver",
        }
    ]
    _rebind_manifest(manifest, attestation)

    decision = _evaluate((manifest, attestation, policy))

    assert decision.allowed is False
    assert decision.code == "WAIVER_EXPIRED"


def test_future_waiver_approval_is_denied(bundle) -> None:
    manifest, attestation, policy = copy.deepcopy(bundle)
    _add_high_waiver(
        manifest,
        waiver_id="wav_synthetic_future",
        approved_at="2026-07-15T10:00:00Z",
        expires_at="2026-07-16T10:00:00Z",
    )
    _rebind_manifest(manifest, attestation)

    decision = _evaluate((manifest, attestation, policy))

    assert decision.allowed is False
    assert decision.code == "WAIVER_TIME_INVALID"


def test_waiver_longer_than_policy_maximum_is_denied(bundle) -> None:
    manifest, attestation, policy = copy.deepcopy(bundle)
    _add_high_waiver(
        manifest,
        waiver_id="wav_synthetic_overlong",
        approved_at="2026-06-13T10:00:00Z",
        expires_at="2026-07-15T10:00:00Z",
    )
    _rebind_manifest(manifest, attestation)

    decision = _evaluate((manifest, attestation, policy))

    assert decision.allowed is False
    assert decision.code == "WAIVER_WINDOW_INVALID"


def test_altered_manifest_is_denied_by_canonical_digest(bundle) -> None:
    manifest, attestation, policy = copy.deepcopy(bundle)
    manifest["release_version"] = "9.9.9"

    decision = _evaluate((manifest, attestation, policy))

    assert decision.allowed is False
    assert decision.code == "MANIFEST_DIGEST_MISMATCH"


def test_future_manifest_is_denied(bundle) -> None:
    manifest, attestation, policy = copy.deepcopy(bundle)
    manifest["created_at"] = "2026-07-15T10:45:00Z"
    _rebind_manifest(manifest, attestation)

    decision = _evaluate((manifest, attestation, policy))

    assert decision.allowed is False
    assert decision.code == "MANIFEST_TIME_INVALID"


def test_attestation_before_manifest_is_denied(bundle) -> None:
    manifest, attestation, policy = copy.deepcopy(bundle)
    attestation["statement"]["predicate"]["timeVerified"] = "2026-07-14T10:40:00Z"

    decision = _evaluate((manifest, attestation, policy))

    assert decision.allowed is False
    assert decision.code == "ATTESTATION_TIME_INVALID"


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("issuer", "https://issuer.invalid"),
        ("identity", "https://github.com/attacker/fork/.github/workflows/build.yml@refs/heads/main"),
        ("key_id", "untrusted-key"),
    ],
)
def test_untrusted_signer_is_denied(bundle, field: str, value: str) -> None:
    manifest, attestation, policy = copy.deepcopy(bundle)
    attestation["signature"][field] = value

    decision = _evaluate((manifest, attestation, policy))

    assert decision.allowed is False
    assert decision.code == "UNTRUSTED_SIGNER"


def test_invalid_cryptographic_signature_is_denied(bundle) -> None:
    manifest, attestation, policy = copy.deepcopy(bundle)
    attestation["signature"]["value"] = "MEUCIQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="

    decision = _evaluate((manifest, attestation, policy))

    assert decision.allowed is False
    assert decision.code == "SIGNATURE_INVALID"


def test_replaced_trust_policy_is_denied_by_external_root(bundle) -> None:
    manifest, attestation, policy = copy.deepcopy(bundle)
    policy["waiver_policy"]["max_validity_days"] = 31

    decision = _evaluate((manifest, attestation, policy))

    assert decision.allowed is False
    assert decision.code == "TRUST_POLICY_NOT_APPROVED"


def test_invalid_public_key_is_denied_without_verifier_crash(bundle) -> None:
    manifest, attestation, policy = copy.deepcopy(bundle)
    policy["allowed_signers"][0]["public_key_jwk"]["x"] = "_" * 43
    altered_policy_digest = canonical_digest(policy)
    manifest["policy_digest"] = altered_policy_digest
    attestation["statement"]["predicate"]["policy"]["digest"] = altered_policy_digest
    _rebind_manifest(manifest, attestation)

    decision = evaluate_release(
        manifest,
        attestation,
        policy,
        expected_policy_digest=altered_policy_digest,
        evaluated_at=NOW,
    )

    assert decision.allowed is False
    assert decision.code == "SIGNATURE_INVALID"


def test_legacy_release_manifest_is_migration_required() -> None:
    manifest = _load("release-manifest-complete.json")
    attestation = _load("release-attestation-v2-complete.synthetic.json")
    policy = _load("release-trust-policy-v1-synthetic.json")

    decision = _evaluate((manifest, attestation, policy))

    assert decision.allowed is False
    assert decision.code == "LEGACY_MANIFEST_DENIED"


def test_verified_projection_carries_same_digests_to_two_targets(bundle) -> None:
    manifest, attestation, policy = bundle
    decision = _evaluate(bundle)
    assert decision.allowed

    staging = build_deployment_projection(
        manifest,
        attestation,
        policy,
        target="staging",
        expected_policy_digest=EXPECTED_POLICY_DIGEST,
        evaluated_at=NOW,
    )
    production = build_deployment_projection(
        manifest,
        attestation,
        policy,
        target="production",
        expected_policy_digest=EXPECTED_POLICY_DIGEST,
        evaluated_at=NOW,
    )

    assert staging["release_manifest_digest"] == production["release_manifest_digest"]
    assert staging["service_images"] == production["service_images"]
    assert staging["runtime_artifacts"] == production["runtime_artifacts"]
    assert staging["promotion_mode"] == "copy-by-digest"
    assert staging["rebuild"] is False
    assert set(staging["service_images"]) == {
        artifact_id.removeprefix("scanalyze-")
        for artifact_id in REQUIRED_ARTIFACT_IDS
        if artifact_id.startswith("scanalyze-")
        and artifact_id not in {"scanalyze-frontend-ui"}
    }


def test_canonical_digest_ignores_only_manifest_digest_field(bundle) -> None:
    manifest = copy.deepcopy(bundle[0])
    expected = manifest["release_manifest_digest"]

    assert canonical_digest(manifest, omit_fields={"release_manifest_digest"}) == expected


def test_verify_image_script_propagates_cosign_failure(tmp_path: pathlib.Path) -> None:
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    fake_cosign = fake_bin / "cosign"
    fake_cosign.write_text("#!/bin/sh\nexit 7\n", encoding="utf-8")
    fake_cosign.chmod(0o755)

    completed = subprocess.run(
        [
            str(ROOT / "scripts" / "supply-chain" / "verify-image.sh"),
            "registry.invalid/scanalyze/ingest-api@sha256:" + "a" * 64,
            "--bundle",
            str(tmp_path / "bundle.json"),
            "--certificate-identity",
            "https://github.com/example/repo/.github/workflows/build.yml@refs/heads/main",
            "--certificate-oidc-issuer",
            "https://token.actions.githubusercontent.com",
        ],
        env={"PATH": f"{fake_bin}:/usr/bin:/bin"},
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 7


def test_generate_sbom_rejects_wrong_spdx_version(tmp_path: pathlib.Path) -> None:
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    fake_syft = fake_bin / "syft"
    fake_syft.write_text(
        """#!/usr/bin/env python3
import pathlib
import sys

for argument in sys.argv[1:]:
    if argument.startswith("spdx-json@2.3="):
        pathlib.Path(argument.split("=", 1)[1]).write_text(
            '{"spdxVersion":"SPDX-2.2"}', encoding="utf-8"
        )
        break
""",
        encoding="utf-8",
    )
    fake_syft.chmod(0o755)

    completed = subprocess.run(
        [
            str(ROOT / "scripts" / "supply-chain" / "generate-sbom.sh"),
            "registry.invalid/scanalyze/ingest-api@sha256:" + "a" * 64,
            str(tmp_path / "sbom.json"),
        ],
        env={
            "PATH": (
                f"{fake_bin}:{pathlib.Path(sys.executable).parent}:/usr/bin:/bin"
            )
        },
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 4
    assert "not SPDX 2.3 JSON" in completed.stderr


def test_supply_chain_scripts_do_not_contain_skipped_success_paths() -> None:
    for name in (
        "generate-sbom.sh",
        "scan-image.sh",
        "sign-image.sh",
        "verify-image.sh",
    ):
        script = ROOT / "scripts" / "supply-chain" / name
        contents = script.read_text(encoding="utf-8")
        assert "SKIPPED" not in contents
        assert "|| echo" not in contents
    assert "spdx-json@2.3=" in (
        ROOT / "scripts" / "supply-chain" / "generate-sbom.sh"
    ).read_text(encoding="utf-8")
