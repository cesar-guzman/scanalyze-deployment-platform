"""Tests for archive URI digest binding — GUG-124 build-once supply chain.

Tests the invariant:
    canonical_archive_digest(uri) == artifact.digest

where canonical_archive_digest extracts the digest from exactly one
unambiguous /sha256/<64-lowercase-hex>/ path segment.

Test categories:
  - Positive: valid S3, HTTPS, all archive artifact classes
  - Adversarial negative: substring smuggling, ambiguity, malformation
  - Backward compatibility: existing container and image policy behavior
"""
import sys
import pathlib
import pytest

# Add tooling to path
sys.path.insert(0, str(pathlib.Path(__file__).parent.parent / "tooling"))

from release_policy_gate import (
    ReleaseManifest,
    PolicyResult,
    _digest_from_content_uri,
    evaluate_release,
    check_release_policy,
)


# --- Deterministic synthetic digests (no real content) ---
DIGEST_A = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
DIGEST_B = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
DIGEST_C = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
HEX_A = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
HEX_B = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

# Three canonical archive artifact classes from the platform
ARCHIVE_IDS = [
    "identity-pre-token-lambda",
    "identity-control-processor-lambda",
    "scanalyze-frontend-ui",
]


def _make_valid_manifest(**overrides):
    """Create a fully valid release manifest with all required fields."""
    defaults = dict(
        version="v2.1.0",
        components={"ingest-api": DIGEST_C},
        signature_algorithm="ECDSA_SHA_256",
        signature_value="MEUCIQDxxx...fake_signature",
        sbom_ref="s3://evidence.invalid/sbom/v2.1.0.spdx.json",
        provenance_ref="s3://evidence.invalid/provenance/v2.1.0.intoto.json",
        waivers=[],
        archives=[],
    )
    defaults.update(overrides)
    return ReleaseManifest(**defaults)


# =========================================================================
# 1. Unit tests for _digest_from_content_uri (private helper)
# =========================================================================


class TestDigestFromContentUriPositive:
    """Valid content-addressed URIs must return the correct digest."""

    def test_s3_valid_archive_uri(self):
        uri = f"s3://bucket.invalid/releases/sha256/{HEX_A}/frontend.zip"
        assert _digest_from_content_uri(uri) == DIGEST_A

    def test_https_valid_archive_uri(self):
        uri = f"https://artifacts.invalid/releases/sha256/{HEX_A}/lambda.zip"
        assert _digest_from_content_uri(uri) == DIGEST_A

    def test_deep_prefix_path(self):
        uri = f"s3://bucket.invalid/org/project/releases/sha256/{HEX_B}/bundle.tar.gz"
        assert _digest_from_content_uri(uri) == DIGEST_B

    def test_multiple_artifact_path_segments(self):
        uri = f"s3://bucket.invalid/sha256/{HEX_A}/path/to/artifact.zip"
        assert _digest_from_content_uri(uri) == DIGEST_A


class TestDigestFromContentUriNegative:
    """Malformed, ambiguous, or adversarial URIs must return None."""

    def test_unsupported_scheme_ftp(self):
        assert _digest_from_content_uri(f"ftp://host.invalid/sha256/{HEX_A}/a.zip") is None

    def test_unsupported_scheme_file(self):
        assert _digest_from_content_uri(f"file:///sha256/{HEX_A}/a.zip") is None

    def test_no_sha256_marker(self):
        assert _digest_from_content_uri(f"s3://b.invalid/releases/{HEX_A}/a.zip") is None

    def test_missing_digest_after_marker(self):
        assert _digest_from_content_uri("s3://b.invalid/sha256/") is None

    def test_digest_too_short(self):
        assert _digest_from_content_uri("s3://b.invalid/sha256/aabbcc/a.zip") is None

    def test_digest_too_long(self):
        long_hex = HEX_A + "ff"
        assert _digest_from_content_uri(f"s3://b.invalid/sha256/{long_hex}/a.zip") is None

    def test_uppercase_digest(self):
        upper = HEX_A.upper()
        assert _digest_from_content_uri(f"s3://b.invalid/sha256/{upper}/a.zip") is None

    def test_non_hex_digest(self):
        bad = "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"
        assert _digest_from_content_uri(f"s3://b.invalid/sha256/{bad}/a.zip") is None

    def test_empty_artifact_path_after_digest(self):
        """Digest must be followed by at least one artifact path segment."""
        assert _digest_from_content_uri(f"s3://b.invalid/sha256/{HEX_A}/") is None
        assert _digest_from_content_uri(f"s3://b.invalid/sha256/{HEX_A}") is None

    def test_two_sha256_markers_ambiguous(self):
        """Two valid sha256/<digest> pairs must fail closed."""
        uri = f"s3://b.invalid/sha256/{HEX_A}/sha256/{HEX_B}/a.zip"
        assert _digest_from_content_uri(uri) is None

    def test_query_string_smuggling(self):
        uri = f"s3://b.invalid/sha256/{HEX_A}/a.zip?sha256={HEX_B}"
        assert _digest_from_content_uri(uri) is None

    def test_fragment_smuggling(self):
        uri = f"s3://b.invalid/sha256/{HEX_A}/a.zip#sha256={HEX_B}"
        assert _digest_from_content_uri(uri) is None

    def test_percent_encoded_slash(self):
        """Percent-encoded separator should not create a valid path segment."""
        uri = f"s3://b.invalid/sha256%2F{HEX_A}/a.zip"
        assert _digest_from_content_uri(uri) is None

    def test_empty_uri(self):
        assert _digest_from_content_uri("") is None

    def test_no_scheme(self):
        assert _digest_from_content_uri(f"/sha256/{HEX_A}/a.zip") is None


# =========================================================================
# 2. Policy-level tests via evaluate_release (public decision boundary)
# =========================================================================


class TestEvaluateReleaseArchivePositive:
    """Valid archive artifacts must pass the policy gate."""

    def test_valid_s3_archive_exact_digest(self):
        manifest = _make_valid_manifest(archives=[{
            "id": "identity-pre-token-lambda",
            "uri": f"s3://artifacts.invalid/releases/sha256/{HEX_A}/lambda.zip",
            "digest": DIGEST_A,
        }])
        result = evaluate_release(manifest)
        assert result.allowed, result.reason
        assert any("archive_digest_binding" in c for c in result.checks)

    def test_valid_https_archive_exact_digest(self):
        manifest = _make_valid_manifest(archives=[{
            "id": "scanalyze-frontend-ui",
            "uri": f"https://cdn.invalid/releases/sha256/{HEX_B}/frontend.zip",
            "digest": DIGEST_B,
        }])
        result = evaluate_release(manifest)
        assert result.allowed, result.reason

    def test_all_three_archive_classes(self):
        """All current archive artifact classes must pass when correctly bound."""
        archives = []
        for i, aid in enumerate(ARCHIVE_IDS):
            hex_d = f"{'0' * 62}{i:02x}"
            archives.append({
                "id": aid,
                "uri": f"s3://artifacts.invalid/sha256/{hex_d}/{aid}.zip",
                "digest": f"sha256:{hex_d}",
            })
        manifest = _make_valid_manifest(archives=archives)
        result = evaluate_release(manifest)
        assert result.allowed, result.reason
        assert len([c for c in result.checks if "archive_digest_binding" in c]) == 3

    def test_no_archives_passes(self):
        """A release with no archive artifacts should still pass."""
        manifest = _make_valid_manifest(archives=[])
        result = evaluate_release(manifest)
        assert result.allowed, result.reason

    def test_existing_container_behavior_unchanged(self):
        """Container image validation must remain unchanged."""
        manifest = _make_valid_manifest()
        result = check_release_policy(manifest, DIGEST_C)
        assert result.allowed, result.reason


class TestEvaluateReleaseArchiveAdversarial:
    """Adversarial archive artifacts must be rejected."""

    def test_digest_in_filename_not_in_canonical_path(self):
        """GUG-124 root cause: expected digest appears in filename only.

        URI uses digest B in the canonical /sha256/<B>/ segment but the
        filename contains digest A's hex. The declared digest is A.
        This is the exact defect that substring matching would accept.
        """
        manifest = _make_valid_manifest(archives=[{
            "id": "identity-pre-token-lambda",
            "uri": f"s3://synthetic.invalid/releases/sha256/{HEX_B}/frontend-{HEX_A}.zip",
            "digest": DIGEST_A,
        }])
        result = evaluate_release(manifest)
        assert not result.allowed
        assert result.result_code == "ARTIFACT_DIGEST_MISMATCH"

    def test_digest_in_parent_path_not_canonical(self):
        """Expected digest in an unrelated parent path segment."""
        manifest = _make_valid_manifest(archives=[{
            "id": "identity-control-processor-lambda",
            "uri": f"s3://synthetic.invalid/{HEX_A}/sha256/{HEX_B}/lambda.zip",
            "digest": DIGEST_A,
        }])
        result = evaluate_release(manifest)
        assert not result.allowed
        assert result.result_code == "ARTIFACT_DIGEST_MISMATCH"

    def test_two_sha256_digest_pairs_ambiguous(self):
        """Two valid sha256/<digest> pairs must fail closed."""
        manifest = _make_valid_manifest(archives=[{
            "id": "scanalyze-frontend-ui",
            "uri": f"s3://b.invalid/sha256/{HEX_A}/sha256/{HEX_B}/a.zip",
            "digest": DIGEST_A,
        }])
        result = evaluate_release(manifest)
        assert not result.allowed
        assert result.result_code == "ARCHIVE_URI_MALFORMED"

    def test_expected_digest_in_first_pair_different_in_second(self):
        """Expected digest in first pair, different digest in second canonical pair."""
        manifest = _make_valid_manifest(archives=[{
            "id": "identity-pre-token-lambda",
            "uri": f"s3://b.invalid/sha256/{HEX_A}/sha256/{HEX_B}/a.zip",
            "digest": DIGEST_A,
        }])
        result = evaluate_release(manifest)
        assert not result.allowed
        assert result.result_code == "ARCHIVE_URI_MALFORMED"

    def test_missing_sha256_marker(self):
        manifest = _make_valid_manifest(archives=[{
            "id": "identity-pre-token-lambda",
            "uri": f"s3://b.invalid/releases/{HEX_A}/lambda.zip",
            "digest": DIGEST_A,
        }])
        result = evaluate_release(manifest)
        assert not result.allowed
        assert result.result_code == "ARCHIVE_URI_MALFORMED"

    def test_missing_digest_segment(self):
        manifest = _make_valid_manifest(archives=[{
            "id": "identity-pre-token-lambda",
            "uri": "s3://b.invalid/sha256/",
            "digest": DIGEST_A,
        }])
        result = evaluate_release(manifest)
        assert not result.allowed

    def test_digest_shorter_than_64(self):
        manifest = _make_valid_manifest(archives=[{
            "id": "identity-pre-token-lambda",
            "uri": "s3://b.invalid/sha256/aabbccdd/lambda.zip",
            "digest": DIGEST_A,
        }])
        result = evaluate_release(manifest)
        assert not result.allowed

    def test_digest_longer_than_64(self):
        long_hex = HEX_A + "ff"
        manifest = _make_valid_manifest(archives=[{
            "id": "identity-pre-token-lambda",
            "uri": f"s3://b.invalid/sha256/{long_hex}/lambda.zip",
            "digest": DIGEST_A,
        }])
        result = evaluate_release(manifest)
        assert not result.allowed

    def test_uppercase_hex_digest(self):
        upper = HEX_A.upper()
        manifest = _make_valid_manifest(archives=[{
            "id": "identity-pre-token-lambda",
            "uri": f"s3://b.invalid/sha256/{upper}/lambda.zip",
            "digest": DIGEST_A,
        }])
        result = evaluate_release(manifest)
        assert not result.allowed

    def test_non_hex_digest(self):
        bad = "z" * 64
        manifest = _make_valid_manifest(archives=[{
            "id": "identity-pre-token-lambda",
            "uri": f"s3://b.invalid/sha256/{bad}/lambda.zip",
            "digest": DIGEST_A,
        }])
        result = evaluate_release(manifest)
        assert not result.allowed

    def test_empty_artifact_path_after_digest(self):
        manifest = _make_valid_manifest(archives=[{
            "id": "identity-pre-token-lambda",
            "uri": f"s3://b.invalid/sha256/{HEX_A}",
            "digest": DIGEST_A,
        }])
        result = evaluate_release(manifest)
        assert not result.allowed

    def test_unsupported_scheme_ftp(self):
        manifest = _make_valid_manifest(archives=[{
            "id": "identity-pre-token-lambda",
            "uri": f"ftp://b.invalid/sha256/{HEX_A}/lambda.zip",
            "digest": DIGEST_A,
        }])
        result = evaluate_release(manifest)
        assert not result.allowed
        assert result.result_code == "ARCHIVE_URI_MALFORMED"

    def test_query_digest_smuggling(self):
        """Query parameter containing digest must not establish authority."""
        manifest = _make_valid_manifest(archives=[{
            "id": "scanalyze-frontend-ui",
            "uri": f"s3://b.invalid/sha256/{HEX_A}/a.zip?digest={HEX_B}",
            "digest": DIGEST_A,
        }])
        result = evaluate_release(manifest)
        assert not result.allowed
        assert result.result_code == "ARCHIVE_URI_MALFORMED"

    def test_fragment_digest_smuggling(self):
        manifest = _make_valid_manifest(archives=[{
            "id": "scanalyze-frontend-ui",
            "uri": f"s3://b.invalid/sha256/{HEX_A}/a.zip#{HEX_B}",
            "digest": DIGEST_A,
        }])
        result = evaluate_release(manifest)
        assert not result.allowed
        assert result.result_code == "ARCHIVE_URI_MALFORMED"

    def test_substring_match_must_not_pass(self):
        """The exact GUG-124 defect: digest A appears as substring only.

        URI canonical path uses digest B, but filename embeds the full
        hex of digest A. A naive 'digest_hex in uri' check would pass.
        """
        manifest = _make_valid_manifest(archives=[{
            "id": "identity-pre-token-lambda",
            "uri": (
                f"s3://synthetic.invalid/releases/"
                f"sha256/{HEX_B}/"
                f"frontend-{HEX_A}.zip"
            ),
            "digest": DIGEST_A,
        }])
        result = evaluate_release(manifest)
        assert not result.allowed
        assert result.result_code == "ARTIFACT_DIGEST_MISMATCH"

    def test_invalid_archive_digest_format(self):
        """Declared digest must be valid sha256:<64hex>."""
        manifest = _make_valid_manifest(archives=[{
            "id": "identity-pre-token-lambda",
            "uri": f"s3://b.invalid/sha256/{HEX_A}/lambda.zip",
            "digest": "md5:abcdef",
        }])
        result = evaluate_release(manifest)
        assert not result.allowed
        assert result.result_code == "ARCHIVE_DIGEST_FORMAT_INVALID"


# =========================================================================
# 3. Backward compatibility — existing behavior must remain unchanged
# =========================================================================


class TestBackwardCompatibility:
    """Existing tests and behavior must not regress."""

    def test_container_digest_validation_unchanged(self):
        manifest = _make_valid_manifest()
        result = check_release_policy(manifest, DIGEST_C)
        assert result.allowed
        assert "ALLOWED" in result.reason

    def test_mutable_tag_still_blocked(self):
        manifest = _make_valid_manifest()
        result = check_release_policy(manifest, "latest")
        assert not result.allowed

    def test_missing_sbom_still_blocked(self):
        manifest = _make_valid_manifest(sbom_ref="")
        result = check_release_policy(manifest, DIGEST_C)
        assert not result.allowed

    def test_evaluate_release_passes_with_no_archives(self):
        manifest = _make_valid_manifest()
        result = evaluate_release(manifest)
        assert result.allowed
        assert result.result_code == "ALLOWED"

    def test_result_code_compatibility(self):
        """ARTIFACT_DIGEST_MISMATCH must be the code for digest binding failures."""
        manifest = _make_valid_manifest(archives=[{
            "id": "test-archive",
            "uri": f"s3://b.invalid/sha256/{HEX_B}/a.zip",
            "digest": DIGEST_A,
        }])
        result = evaluate_release(manifest)
        assert result.result_code == "ARTIFACT_DIGEST_MISMATCH"
