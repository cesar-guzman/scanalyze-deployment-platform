"""Release Policy Gate — local supply chain verification.

Validates release manifests against supply chain policy rules:
1. All image digests must be sha256-pinned (no mutable tags)
2. Every image digest must appear in the release manifest's components
3. Signatures must use ECDSA_SHA_256
4. SBOM reference is required
5. Provenance reference is required
6. Waivers require a waiver_id
7. Approved digests with full attestation pass
8. Archive artifact URIs must be content-addressed with matching digest
9. Archive URI digest must match canonical /sha256/<digest>/ path segment

This module provides fail-closed verification logic.
It does NOT perform actual cryptographic verification (pending_aws).
"""
import re
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlsplit


# Accepted URI schemes for archive artifacts (consistent with release schema)
_ACCEPTED_ARCHIVE_SCHEMES = frozenset({"s3", "https"})

# Regex for a valid lowercase 64-character hexadecimal digest
_HEX64_RE = re.compile(r"^[a-f0-9]{64}$")


def _digest_from_content_uri(uri: str) -> str | None:
    """Extract the canonical content digest from a content-addressed archive URI.

    A valid content-addressed URI has exactly one path segment pair:
        /sha256/<64-lowercase-hex-digest>/
    followed by at least one artifact path segment.

    Returns:
        The digest as 'sha256:<hex>' if exactly one unambiguous canonical
        digest marker is found. None otherwise (malformed, ambiguous,
        unsupported scheme, or missing artifact path after digest).

    Properties:
        - Pure function: no network, filesystem, or environment access.
        - Deterministic: same input always produces the same output.
        - Fail-closed: returns None for any ambiguous or malformed input.
        - Does not log the full URI to avoid leaking sensitive paths.
    """
    try:
        parsed = urlsplit(uri)
    except Exception:
        return None

    # Reject unsupported schemes
    if parsed.scheme not in _ACCEPTED_ARCHIVE_SCHEMES:
        return None

    # Reject URIs with query or fragment (potential smuggling vectors)
    if parsed.query or parsed.fragment:
        return None

    # Split path into non-empty segments
    segments = [s for s in parsed.path.split("/") if s]

    # Find all 'sha256' markers and extract candidate digest pairs
    digest_indices = []
    for i, seg in enumerate(segments):
        if seg == "sha256":
            digest_indices.append(i)

    # Exactly one sha256 marker required — ambiguity fails closed
    if len(digest_indices) != 1:
        return None

    marker_idx = digest_indices[0]

    # Digest segment must follow the marker
    if marker_idx + 1 >= len(segments):
        return None

    candidate = segments[marker_idx + 1]

    # Validate exact 64-character lowercase hexadecimal
    if not _HEX64_RE.match(candidate):
        return None

    # At least one artifact path segment must follow the digest
    if marker_idx + 2 >= len(segments):
        return None

    return f"sha256:{candidate}"


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
    archives: list = field(default_factory=list)  # list of {"id", "uri", "digest"}


@dataclass
class PolicyResult:
    """Result of a policy gate check."""
    allowed: bool
    reason: str
    result_code: str = ""
    checks: list = field(default_factory=list)


def evaluate_release(manifest: ReleaseManifest) -> PolicyResult:
    """Evaluate a complete release manifest for supply chain policy compliance.

    This is the primary policy decision boundary. It validates:
    1. Container image digests (existing check_release_policy logic)
    2. Archive artifact URI digest binding (GUG-124)

    Returns PolicyResult with allowed=True only if ALL checks pass.
    Fail-closed: any missing, invalid, or ambiguous field results in BLOCKED.
    """
    checks = []

    # --- Container image checks (delegate to existing logic) ---
    for name, digest in manifest.components.items():
        img_result = check_release_policy(manifest, digest)
        if not img_result.allowed:
            return PolicyResult(
                allowed=False,
                reason=img_result.reason,
                result_code=img_result.result_code or "CONTAINER_POLICY_VIOLATION",
                checks=checks + img_result.checks,
            )
        checks.extend(img_result.checks)

    # --- Archive artifact URI digest binding (GUG-124) ---
    for archive in manifest.archives:
        archive_id = archive.get("id", "<unknown>")
        archive_uri = archive.get("uri", "")
        archive_digest = archive.get("digest", "")

        # Digest format check
        if not re.match(r"^sha256:[a-f0-9]{64}$", archive_digest):
            return PolicyResult(
                allowed=False,
                reason=f"BLOCKED: archive '{archive_id}' has invalid digest format",
                result_code="ARCHIVE_DIGEST_FORMAT_INVALID",
                checks=checks + [f"archive_digest_format({archive_id}): FAIL"],
            )

        # Extract canonical digest from URI
        uri_digest = _digest_from_content_uri(archive_uri)
        if uri_digest is None:
            return PolicyResult(
                allowed=False,
                reason=(
                    f"BLOCKED: archive '{archive_id}' URI is malformed, "
                    f"ambiguous, or uses an unsupported scheme"
                ),
                result_code="ARCHIVE_URI_MALFORMED",
                checks=checks + [f"archive_uri_parse({archive_id}): FAIL"],
            )

        # Cross-field equality: URI digest must equal declared digest
        if uri_digest != archive_digest:
            return PolicyResult(
                allowed=False,
                reason=(
                    f"BLOCKED: archive '{archive_id}' URI canonical digest "
                    f"does not match declared artifact digest"
                ),
                result_code="ARTIFACT_DIGEST_MISMATCH",
                checks=checks + [f"archive_digest_binding({archive_id}): FAIL"],
            )

        checks.append(f"archive_digest_binding({archive_id}): PASS")

    return PolicyResult(
        allowed=True,
        reason="ALLOWED: all policy checks passed",
        result_code="ALLOWED",
        checks=checks,
    )


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
