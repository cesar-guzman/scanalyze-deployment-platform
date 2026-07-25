"""Repository integration contracts for GUG-124 build-once delivery."""

from __future__ import annotations

import copy
import json
import pathlib
import subprocess
import sys
from datetime import UTC, datetime

import pytest
import yaml


ROOT = pathlib.Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "fixtures"

sys.path.insert(0, str(ROOT / "tooling"))

from release_policy_gate import (  # noqa: E402
    _digest_from_content_uri,
    build_deployment_projection,
    canonical_digest,
    evaluate_release,
)

NOW = datetime(2026, 7, 14, 12, 0, tzinfo=UTC)
EXPECTED_POLICY_DIGEST = (
    FIXTURES / "valid" / "release-trust-policy-v1-synthetic.sha256"
).read_text(encoding="utf-8").strip()

GOOD_DIGEST = "a" * 64
GOOD_S3_URI = f"s3://release-bucket/releases/sha256/{GOOD_DIGEST}/lambda.zip"
GOOD_HTTPS_URI = (
    f"https://artifacts.invalid/releases/sha256/{GOOD_DIGEST}/frontend.tar.gz"
)


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


# ── Existing repository integration tests ─────────────────────────────


def test_pr_validation_runs_supply_chain_gate_without_cloud_permissions() -> None:
    workflow = yaml.safe_load(
        (ROOT / ".github/workflows/pr-validation.yml").read_text(encoding="utf-8")
    )

    assert workflow["permissions"] == {"contents": "read"}
    assert "id-token" not in workflow["permissions"]
    commands = [
        step.get("run", "")
        for job in workflow["jobs"].values()
        for step in job.get("steps", [])
    ]
    assert "make supply-chain-check" in commands


def test_legacy_publish_job_remains_terminal_no_go() -> None:
    workflow = yaml.safe_load(
        (ROOT / ".github/workflows/microservices-build.yml").read_text(
            encoding="utf-8"
        )
    )
    publish = workflow["jobs"]["publish"]

    assert publish["permissions"] == {}
    rendered = json.dumps(publish)
    assert "Publication NO-GO" in rendered
    assert "aws-actions/configure-aws-credentials" not in rendered
    assert "exit 1" in rendered


def test_release_planning_inventory_cannot_authorize_promotion(tmp_path) -> None:
    script = ROOT / "scripts/supply-chain/release-graph.py"
    dry_run = subprocess.run(
        [str(script), "--dry-run"],
        check=False,
        capture_output=True,
        text=True,
    )
    live = subprocess.run(
        [str(script), "--no-dry-run"],
        check=False,
        capture_output=True,
        text=True,
    )

    assert dry_run.returncode == 0
    inventory = json.loads(dry_run.stdout)
    assert inventory["eligible_for_promotion"] is False
    assert inventory["production_status"] == "NO-GO"
    assert live.returncode != 0
    assert "cannot authorize" in live.stderr
    assert not list(tmp_path.iterdir())


def test_services_terraform_rejects_mutable_container_references() -> None:
    variables = (ROOT / "modules/services/variables.tf").read_text(encoding="utf-8")
    task_definitions = (ROOT / "modules/services/ecs_services.tf").read_text(
        encoding="utf-8"
    )

    assert "@sha256:[0-9a-f]{64}$" in variables
    assert "image     = each.value.image" in task_definitions
    active_lines = "\n".join(
        line for line in task_definitions.splitlines() if not line.lstrip().startswith("#")
    )
    assert 'image     = "' not in active_lines
    assert "ignore_changes" not in active_lines


def test_static_projection_matches_verified_generator() -> None:
    command = [
        sys.executable,
        str(ROOT / "tooling/release_policy_gate.py"),
        "--manifest",
        str(ROOT / "fixtures/valid/release-v2-complete.synthetic.json"),
        "--attestation",
        str(ROOT / "fixtures/valid/release-attestation-v2-complete.synthetic.json"),
        "--policy",
        str(ROOT / "fixtures/valid/release-trust-policy-v1-synthetic.json"),
        "--expected-policy-digest",
        (
            ROOT / "fixtures/valid/release-trust-policy-v1-synthetic.sha256"
        ).read_text(encoding="utf-8").strip(),
    ]
    completed = subprocess.run(command, check=False, capture_output=True, text=True)

    assert completed.returncode == 0, completed.stdout + completed.stderr
    decision = json.loads(completed.stdout)
    assert decision["allowed"] is True
    assert decision["code"] == "RELEASE_POLICY_PASSED"


def test_supply_chain_fixtures_are_explicitly_synthetic() -> None:
    names = {
        path.name
        for path in (ROOT / "fixtures/valid").glob("release-*-synthetic.json")
    }
    assert names == {
        "release-deployment-projection-v1-synthetic.json",
        "release-trust-policy-v1-synthetic.json",
    }
    assert (ROOT / "fixtures/valid/release-v2-complete.synthetic.json").exists()
    assert (
        ROOT / "fixtures/valid/release-attestation-v2-complete.synthetic.json"
    ).exists()


# ── GUG-124 Unit tests: _digest_from_content_uri ─────────────────────


class TestDigestFromContentUriPositive:
    """Valid content-addressed URIs that must return the canonical digest."""

    def test_s3_valid(self):
        result = _digest_from_content_uri(GOOD_S3_URI)
        assert result == f"sha256:{GOOD_DIGEST}"

    def test_https_valid(self):
        result = _digest_from_content_uri(GOOD_HTTPS_URI)
        assert result == f"sha256:{GOOD_DIGEST}"

    def test_deep_prefix_path(self):
        uri = f"https://cdn.invalid/org/releases/sha256/{GOOD_DIGEST}/app.zip"
        assert _digest_from_content_uri(uri) == f"sha256:{GOOD_DIGEST}"

    def test_multiple_artifact_path_segments(self):
        uri = f"s3://bucket/sha256/{GOOD_DIGEST}/path/to/file.zip"
        assert _digest_from_content_uri(uri) == f"sha256:{GOOD_DIGEST}"


class TestDigestFromContentUriNegative:
    """Malformed, ambiguous, or adversarial URIs that must return None."""

    def test_unsupported_scheme_ftp(self):
        assert _digest_from_content_uri(f"ftp://host/sha256/{GOOD_DIGEST}/f.zip") is None

    def test_unsupported_scheme_file(self):
        assert _digest_from_content_uri(f"file:///sha256/{GOOD_DIGEST}/f.zip") is None

    def test_no_sha256_marker(self):
        assert _digest_from_content_uri(f"https://host/releases/{GOOD_DIGEST}/f.zip") is None

    def test_missing_digest_after_marker(self):
        assert _digest_from_content_uri("https://host/sha256/") is None

    def test_digest_too_short(self):
        assert _digest_from_content_uri(f"https://host/sha256/{'a' * 63}/f.zip") is None

    def test_digest_too_long(self):
        assert _digest_from_content_uri(f"https://host/sha256/{'a' * 65}/f.zip") is None

    def test_uppercase_digest(self):
        assert _digest_from_content_uri(f"https://host/sha256/{'A' * 64}/f.zip") is None

    def test_non_hex_digest(self):
        assert _digest_from_content_uri(f"https://host/sha256/{'g' * 64}/f.zip") is None

    def test_empty_artifact_path_after_digest(self):
        assert _digest_from_content_uri(f"https://host/sha256/{GOOD_DIGEST}") is None

    def test_two_sha256_markers_ambiguous(self):
        uri = f"https://host/sha256/{GOOD_DIGEST}/sha256/{'b' * 64}/f.zip"
        assert _digest_from_content_uri(uri) is None

    def test_query_string_smuggling(self):
        uri = f"https://host/sha256/{GOOD_DIGEST}/f.zip?sha256={'b' * 64}"
        assert _digest_from_content_uri(uri) is None

    def test_fragment_smuggling(self):
        uri = f"https://host/sha256/{GOOD_DIGEST}/f.zip#sha256={'b' * 64}"
        assert _digest_from_content_uri(uri) is None

    def test_redundant_slashes_rejected(self):
        uri = f"https://host//sha256/{GOOD_DIGEST}/f.zip"
        assert _digest_from_content_uri(uri) is None

    def test_redundant_slashes_after_digest_rejected(self):
        uri = f"https://host/sha256/{GOOD_DIGEST}//f.zip"
        assert _digest_from_content_uri(uri) is None

    def test_empty_uri(self):
        assert _digest_from_content_uri("") is None

    def test_no_scheme(self):
        assert _digest_from_content_uri(f"/sha256/{GOOD_DIGEST}/f.zip") is None

    def test_no_host(self):
        assert _digest_from_content_uri(f"https:///sha256/{GOOD_DIGEST}/f.zip") is None


# ── GUG-124 Integration tests: evaluate_release archive branch ───────


class TestArchiveDigestBindingPositive:
    """Valid archive URIs pass the full signed release pipeline."""

    def test_complete_signed_release_with_archives_allowed(self, bundle):
        """Baseline: the existing fixture has valid archives and must pass."""
        decision = _evaluate(bundle)
        assert decision.allowed is True
        assert decision.code == "RELEASE_POLICY_PASSED"

    def test_s3_archive_uri_accepted(self):
        """An S3-based archive URI with matching canonical digest is extracted correctly."""
        hex_part = "0" * 64
        uri = f"s3://release-bucket/releases/sha256/{hex_part}/identity-pre-token-lambda.zip"
        assert _digest_from_content_uri(uri) == f"sha256:{hex_part}"

    def test_deployment_projection_unchanged(self, bundle):
        """Deployment projection is unaffected by the archive validation fix."""
        manifest, attestation, policy = bundle
        projection = build_deployment_projection(
            manifest,
            attestation,
            policy,
            target="staging",
            expected_policy_digest=EXPECTED_POLICY_DIGEST,
            evaluated_at=NOW,
        )
        assert projection["promotion_mode"] == "copy-by-digest"
        assert projection["rebuild"] is False
        for artifact_id in ("identity-pre-token-lambda", "identity-control-processor-lambda", "scanalyze-frontend-ui"):
            assert artifact_id in projection["runtime_artifacts"]


class TestArchiveDigestBindingAdversarial:
    """Smuggling, ambiguity, and format attacks on archive URIs."""

    def test_digest_in_filename_not_in_canonical_path(self, bundle):
        """Digest appears in filename but not in canonical /sha256/<hex>/ segment."""
        manifest, attestation, policy = copy.deepcopy(bundle)
        target_id = "identity-pre-token-lambda"
        digest = manifest["artifacts"][target_id]["digest"]
        hex_part = digest.removeprefix("sha256:")
        evil_hex = "b" * 64
        manifest["artifacts"][target_id]["uri"] = (
            f"https://artifacts.invalid/releases/sha256/{evil_hex}/{hex_part}-lambda.zip"
        )
        _rebind_manifest(manifest, attestation)

        decision = _evaluate((manifest, attestation, policy))
        assert decision.allowed is False
        assert decision.code == "ARTIFACT_DIGEST_MISMATCH"

    def test_digest_in_unrelated_parent_path(self, bundle):
        """Digest appears in a parent path segment but not in canonical position."""
        manifest, attestation, policy = copy.deepcopy(bundle)
        target_id = "identity-pre-token-lambda"
        digest = manifest["artifacts"][target_id]["digest"]
        hex_part = digest.removeprefix("sha256:")
        evil_hex = "c" * 64
        manifest["artifacts"][target_id]["uri"] = (
            f"https://artifacts.invalid/{hex_part}/sha256/{evil_hex}/lambda.zip"
        )
        _rebind_manifest(manifest, attestation)

        decision = _evaluate((manifest, attestation, policy))
        assert decision.allowed is False
        assert decision.code == "ARTIFACT_DIGEST_MISMATCH"

    def test_two_sha256_markers(self, bundle):
        """Two sha256 markers cause ambiguity and must be rejected."""
        manifest, attestation, policy = copy.deepcopy(bundle)
        target_id = "identity-pre-token-lambda"
        digest = manifest["artifacts"][target_id]["digest"]
        hex_part = digest.removeprefix("sha256:")
        manifest["artifacts"][target_id]["uri"] = (
            f"https://artifacts.invalid/sha256/{hex_part}/sha256/{'d' * 64}/lambda.zip"
        )
        _rebind_manifest(manifest, attestation)

        decision = _evaluate((manifest, attestation, policy))
        assert decision.allowed is False
        assert decision.code == "ARTIFACT_DIGEST_MISMATCH"

    def test_missing_sha256_marker(self, bundle):
        manifest, attestation, policy = copy.deepcopy(bundle)
        target_id = "identity-pre-token-lambda"
        digest = manifest["artifacts"][target_id]["digest"]
        hex_part = digest.removeprefix("sha256:")
        manifest["artifacts"][target_id]["uri"] = (
            f"https://artifacts.invalid/releases/{hex_part}/lambda.zip"
        )
        _rebind_manifest(manifest, attestation)

        decision = _evaluate((manifest, attestation, policy))
        assert decision.allowed is False
        assert decision.code in {"ARTIFACT_DIGEST_MISMATCH", "RELEASE_SCHEMA_INVALID"}

    def test_short_digest(self, bundle):
        manifest, attestation, policy = copy.deepcopy(bundle)
        target_id = "identity-pre-token-lambda"
        manifest["artifacts"][target_id]["uri"] = (
            f"https://artifacts.invalid/sha256/{'a' * 63}/lambda.zip"
        )
        _rebind_manifest(manifest, attestation)

        decision = _evaluate((manifest, attestation, policy))
        assert decision.allowed is False
        assert decision.code in {"ARTIFACT_DIGEST_MISMATCH", "RELEASE_SCHEMA_INVALID"}

    def test_long_digest(self, bundle):
        manifest, attestation, policy = copy.deepcopy(bundle)
        target_id = "identity-pre-token-lambda"
        manifest["artifacts"][target_id]["uri"] = (
            f"https://artifacts.invalid/sha256/{'a' * 65}/lambda.zip"
        )
        _rebind_manifest(manifest, attestation)

        decision = _evaluate((manifest, attestation, policy))
        assert decision.allowed is False
        assert decision.code in {"ARTIFACT_DIGEST_MISMATCH", "RELEASE_SCHEMA_INVALID"}

    def test_uppercase_hex(self, bundle):
        manifest, attestation, policy = copy.deepcopy(bundle)
        target_id = "identity-pre-token-lambda"
        manifest["artifacts"][target_id]["uri"] = (
            f"https://artifacts.invalid/sha256/{'A' * 64}/lambda.zip"
        )
        _rebind_manifest(manifest, attestation)

        decision = _evaluate((manifest, attestation, policy))
        assert decision.allowed is False
        assert decision.code in {"ARTIFACT_DIGEST_MISMATCH", "RELEASE_SCHEMA_INVALID"}

    def test_non_hex_digest(self, bundle):
        manifest, attestation, policy = copy.deepcopy(bundle)
        target_id = "identity-pre-token-lambda"
        manifest["artifacts"][target_id]["uri"] = (
            f"https://artifacts.invalid/sha256/{'g' * 64}/lambda.zip"
        )
        _rebind_manifest(manifest, attestation)

        decision = _evaluate((manifest, attestation, policy))
        assert decision.allowed is False
        assert decision.code in {"ARTIFACT_DIGEST_MISMATCH", "RELEASE_SCHEMA_INVALID"}

    def test_unsupported_scheme(self, bundle):
        manifest, attestation, policy = copy.deepcopy(bundle)
        target_id = "identity-pre-token-lambda"
        digest = manifest["artifacts"][target_id]["digest"]
        hex_part = digest.removeprefix("sha256:")
        manifest["artifacts"][target_id]["uri"] = (
            f"ftp://host/sha256/{hex_part}/lambda.zip"
        )
        _rebind_manifest(manifest, attestation)

        decision = _evaluate((manifest, attestation, policy))
        assert decision.allowed is False
        assert decision.code in {"ARTIFACT_DIGEST_MISMATCH", "RELEASE_SCHEMA_INVALID"}

    def test_empty_artifact_path_after_digest(self, bundle):
        manifest, attestation, policy = copy.deepcopy(bundle)
        target_id = "identity-pre-token-lambda"
        digest = manifest["artifacts"][target_id]["digest"]
        hex_part = digest.removeprefix("sha256:")
        manifest["artifacts"][target_id]["uri"] = (
            f"https://artifacts.invalid/sha256/{hex_part}"
        )
        _rebind_manifest(manifest, attestation)

        decision = _evaluate((manifest, attestation, policy))
        assert decision.allowed is False
        assert decision.code in {"ARTIFACT_DIGEST_MISMATCH", "RELEASE_SCHEMA_INVALID"}

    def test_substring_match_must_not_pass(self, bundle):
        """Exact regression test for the original substring vulnerability."""
        manifest, attestation, policy = copy.deepcopy(bundle)
        target_id = "identity-pre-token-lambda"
        digest = manifest["artifacts"][target_id]["digest"]
        hex_part = digest.removeprefix("sha256:")
        evil_hex = "e" * 64
        manifest["artifacts"][target_id]["uri"] = (
            f"https://artifacts.invalid/sha256/{evil_hex}/{hex_part}.zip"
        )
        _rebind_manifest(manifest, attestation)

        decision = _evaluate((manifest, attestation, policy))
        assert decision.allowed is False
        assert decision.code == "ARTIFACT_DIGEST_MISMATCH"


class TestArchiveDigestBindingRedundantSlash:
    """Redundant-slash behavior aligned with release.v2 schema."""

    def test_redundant_slash_in_prefix(self, bundle):
        """Double-slash before sha256/ → rejected (not normalized)."""
        manifest, attestation, policy = copy.deepcopy(bundle)
        target_id = "identity-pre-token-lambda"
        digest = manifest["artifacts"][target_id]["digest"]
        hex_part = digest.removeprefix("sha256:")
        manifest["artifacts"][target_id]["uri"] = (
            f"https://artifacts.invalid//sha256/{hex_part}/lambda.zip"
        )
        _rebind_manifest(manifest, attestation)

        decision = _evaluate((manifest, attestation, policy))
        assert decision.allowed is False
        assert decision.code in {"ARTIFACT_DIGEST_MISMATCH", "RELEASE_SCHEMA_INVALID"}


class TestBackwardCompatibility:
    """Verify that existing container validation and signed release remain unchanged."""

    def test_container_digest_validation_unchanged(self, bundle):
        manifest, attestation, policy = copy.deepcopy(bundle)
        manifest["artifacts"]["scanalyze-ingest-api"]["uri"] = (
            "registry.invalid/scanalyze/ingest-api:latest"
        )
        _rebind_manifest(manifest, attestation)

        decision = _evaluate((manifest, attestation, policy))
        assert decision.allowed is False
        assert decision.code in {"RELEASE_SCHEMA_INVALID", "ARTIFACT_DIGEST_MISMATCH"}

    def test_signed_manifest_still_allowed(self, bundle):
        decision = _evaluate(bundle)
        assert decision.allowed is True
        assert decision.code == "RELEASE_POLICY_PASSED"

    def test_projection_runtime_artifacts_include_archives(self, bundle):
        manifest, attestation, policy = bundle
        projection = build_deployment_projection(
            manifest,
            attestation,
            policy,
            target="production",
            expected_policy_digest=EXPECTED_POLICY_DIGEST,
            evaluated_at=NOW,
        )
        for aid in ("identity-pre-token-lambda", "identity-control-processor-lambda", "scanalyze-frontend-ui"):
            assert aid in projection["runtime_artifacts"]
            assert projection["runtime_artifacts"][aid]["digest"].startswith("sha256:")

