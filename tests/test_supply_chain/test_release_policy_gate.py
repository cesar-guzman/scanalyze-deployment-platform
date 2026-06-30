"""Tests for release_policy_gate — supply chain local evidence.

7 scenarios:
1. Unsigned digest → BLOCKED
2. Digest not in release manifest → BLOCKED
3. Mutable tag (:latest) → BLOCKED
4. Missing SBOM reference → BLOCKED
5. Missing provenance reference → BLOCKED
6. Waiver without waiver_id → BLOCKED
7. Approved digest with full attestation → PASS
"""
import sys
import pathlib
import pytest

# Add tooling to path
sys.path.insert(0, str(pathlib.Path(__file__).parent.parent.parent / "tooling"))

from release_policy_gate import ReleaseManifest, check_release_policy


VALID_DIGEST = "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
OTHER_DIGEST = "sha256:1111111111111111111111111111111111111111111111111111111111111111"


def _make_valid_manifest(digest=VALID_DIGEST):
    """Create a fully valid release manifest."""
    return ReleaseManifest(
        version="v2.1.0",
        components={"ingest-api": digest, "ocr-worker": OTHER_DIGEST},
        signature_algorithm="ECDSA_SHA_256",
        signature_value="MEUCIQDxxx...fake_signature",
        sbom_ref="s3://evidence/sbom/v2.1.0.spdx.json",
        provenance_ref="s3://evidence/provenance/v2.1.0.intoto.json",
        waivers=[],
    )


class TestUnsignedDigestBlocked:
    """1. Unsigned digest → BLOCKED"""

    def test_unsigned_no_algorithm(self):
        manifest = _make_valid_manifest()
        manifest.signature_algorithm = ""
        result = check_release_policy(manifest, VALID_DIGEST)
        assert not result.allowed
        assert "unsigned" in result.reason.lower() or "algorithm" in result.reason.lower()

    def test_unsigned_no_value(self):
        manifest = _make_valid_manifest()
        manifest.signature_value = ""
        result = check_release_policy(manifest, VALID_DIGEST)
        assert not result.allowed
        assert "unsigned" in result.reason.lower()

    def test_wrong_algorithm(self):
        manifest = _make_valid_manifest()
        manifest.signature_algorithm = "RSA_PSS_SHA_256"
        result = check_release_policy(manifest, VALID_DIGEST)
        assert not result.allowed


class TestDigestNotInManifest:
    """2. Digest not in release manifest → BLOCKED"""

    def test_unknown_digest(self):
        manifest = _make_valid_manifest()
        unknown = "sha256:9999999999999999999999999999999999999999999999999999999999999999"
        result = check_release_policy(manifest, unknown)
        assert not result.allowed
        assert "not in release" in result.reason.lower()


class TestMutableTagBlocked:
    """3. Mutable tag (:latest) → BLOCKED"""

    def test_latest_tag(self):
        manifest = _make_valid_manifest()
        result = check_release_policy(manifest, "latest")
        assert not result.allowed
        assert "mutable" in result.reason.lower() or "format" in result.reason.lower()

    def test_tag_without_sha256(self):
        manifest = _make_valid_manifest()
        result = check_release_policy(manifest, "v2.1.0")
        assert not result.allowed


class TestMissingSBOM:
    """4. Missing SBOM reference → BLOCKED"""

    def test_no_sbom(self):
        manifest = _make_valid_manifest()
        manifest.sbom_ref = ""
        result = check_release_policy(manifest, VALID_DIGEST)
        assert not result.allowed
        assert "sbom" in result.reason.lower()


class TestMissingProvenance:
    """5. Missing provenance reference → BLOCKED"""

    def test_no_provenance(self):
        manifest = _make_valid_manifest()
        manifest.provenance_ref = ""
        result = check_release_policy(manifest, VALID_DIGEST)
        assert not result.allowed
        assert "provenance" in result.reason.lower()


class TestWaiverWithoutId:
    """6. Waiver without waiver_id → BLOCKED"""

    def test_waiver_missing_id(self):
        manifest = _make_valid_manifest()
        manifest.waivers = [{"reason": "emergency fix", "waiver_id": ""}]
        result = check_release_policy(manifest, VALID_DIGEST)
        assert not result.allowed
        assert "waiver" in result.reason.lower()

    def test_waiver_no_id_field(self):
        manifest = _make_valid_manifest()
        manifest.waivers = [{"reason": "emergency fix"}]
        result = check_release_policy(manifest, VALID_DIGEST)
        assert not result.allowed


class TestApprovedDigest:
    """7. Approved digest with full attestation → PASS"""

    def test_fully_valid(self):
        manifest = _make_valid_manifest()
        result = check_release_policy(manifest, VALID_DIGEST)
        assert result.allowed
        assert "ALLOWED" in result.reason

    def test_with_valid_waiver(self):
        manifest = _make_valid_manifest()
        manifest.waivers = [
            {"waiver_id": "WAV-2025-001", "reason": "approved emergency"}
        ]
        result = check_release_policy(manifest, VALID_DIGEST)
        assert result.allowed

    def test_all_checks_present(self):
        manifest = _make_valid_manifest()
        result = check_release_policy(manifest, VALID_DIGEST)
        assert len(result.checks) >= 6
        assert all("PASS" in c for c in result.checks)
