"""Release Policy Gate — local supply chain verification.

Validates release manifests against supply chain policy rules:
1. All image digests must be sha256-pinned (no mutable tags)
2. Every image digest must appear in the release manifest's components
3. Signatures must use ECDSA_SHA_256
4. SBOM reference is required
5. Provenance reference is required
6. Waivers require a waiver_id
7. Approved digests with full attestation pass

This module provides fail-closed verification logic.
It does NOT perform actual cryptographic verification (pending_aws).
"""
import re
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class ReleaseManifest:
    """Simplified release manifest for policy gate testing."""
    version: str = ""
    components: dict = field(default_factory=dict)  # name -> digest
    signature_algorithm: str = ""
    signature_value: str = ""
    sbom_ref: str = ""
    provenance_ref: str = ""
    waivers: list = field(default_factory=list)


@dataclass
class PolicyResult:
    """Result of a policy gate check."""
    allowed: bool
    reason: str
    checks: list = field(default_factory=list)


def check_release_policy(manifest: ReleaseManifest, image_digest: str) -> PolicyResult:
    """Check if an image digest is allowed by the release manifest policy.

    Returns PolicyResult with allowed=True only if ALL checks pass.
    Fail-closed: any missing or invalid field results in BLOCKED.
    """
    checks = []

    # 1. Digest must be sha256-pinned
    if not re.match(r"^sha256:[a-f0-9]{64}$", image_digest):
        return PolicyResult(
            allowed=False,
            reason="BLOCKED: mutable tag or invalid digest format",
            checks=["digest_format: FAIL"]
        )
    checks.append("digest_format: PASS")

    # 2. Digest must be in release manifest components
    component_digests = set(manifest.components.values())
    if image_digest not in component_digests:
        return PolicyResult(
            allowed=False,
            reason="BLOCKED: digest not in release manifest components",
            checks=checks + ["digest_in_manifest: FAIL"]
        )
    checks.append("digest_in_manifest: PASS")

    # 3. Signature algorithm must be ECDSA_SHA_256
    if manifest.signature_algorithm != "ECDSA_SHA_256":
        return PolicyResult(
            allowed=False,
            reason=f"BLOCKED: unsigned or wrong algorithm ({manifest.signature_algorithm})",
            checks=checks + ["signature_algorithm: FAIL"]
        )
    checks.append("signature_algorithm: PASS")

    # 4. Signature value must be non-empty
    if not manifest.signature_value:
        return PolicyResult(
            allowed=False,
            reason="BLOCKED: unsigned digest — no signature value",
            checks=checks + ["signature_value: FAIL"]
        )
    checks.append("signature_value: PASS")

    # 5. SBOM reference required
    if not manifest.sbom_ref:
        return PolicyResult(
            allowed=False,
            reason="BLOCKED: missing SBOM reference",
            checks=checks + ["sbom_ref: FAIL"]
        )
    checks.append("sbom_ref: PASS")

    # 6. Provenance reference required
    if not manifest.provenance_ref:
        return PolicyResult(
            allowed=False,
            reason="BLOCKED: missing provenance reference",
            checks=checks + ["provenance_ref: FAIL"]
        )
    checks.append("provenance_ref: PASS")

    # 7. Check waivers — any waiver must have waiver_id
    for waiver in manifest.waivers:
        if not waiver.get("waiver_id"):
            return PolicyResult(
                allowed=False,
                reason="BLOCKED: waiver without waiver_id",
                checks=checks + ["waiver_id: FAIL"]
            )
    if manifest.waivers:
        checks.append("waiver_ids: PASS")

    return PolicyResult(
        allowed=True,
        reason="ALLOWED: all policy checks passed",
        checks=checks
    )
