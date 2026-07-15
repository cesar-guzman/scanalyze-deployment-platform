#!/usr/bin/env python3
"""Fail-closed verification for Scanalyze build-once release manifests.

The verifier is deliberately cloud-independent. A live promotion engine may only
consume the deployment projection returned after schema, digest, evidence,
policy, signer identity, and ECDSA signature verification all pass.
"""

from __future__ import annotations

import argparse
import base64
import copy
import hashlib
import json
import sys
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Iterable, Mapping


ROOT = Path(__file__).resolve().parents[1]
SCHEMAS = ROOT / "schemas"

REQUIRED_ARTIFACT_IDS = frozenset(
    {
        "scanalyze-ingest-api",
        "scanalyze-ocr-worker",
        "scanalyze-postprocess-worker",
        "scanalyze-classifier-worker",
        "scanalyze-bank-worker",
        "scanalyze-personal-worker",
        "scanalyze-gov-worker",
        "identity-pre-token-lambda",
        "identity-control-processor-lambda",
        "scanalyze-frontend-ui",
    }
)
SERVICE_ARTIFACT_IDS = frozenset(
    artifact_id
    for artifact_id in REQUIRED_ARTIFACT_IDS
    if artifact_id.startswith("scanalyze-")
    and artifact_id != "scanalyze-frontend-ui"
)
RUNTIME_ARTIFACT_IDS = REQUIRED_ARTIFACT_IDS - SERVICE_ARTIFACT_IDS
SLSA_LEVELS = {
    "SLSA_BUILD_LEVEL_1": 1,
    "SLSA_BUILD_LEVEL_2": 2,
    "SLSA_BUILD_LEVEL_3": 3,
}


@dataclass(frozen=True)
class PolicyCheck:
    name: str
    status: str
    detail: str


@dataclass(frozen=True)
class PolicyDecision:
    allowed: bool
    code: str
    reason: str
    manifest_digest: str | None
    checks: tuple[PolicyCheck, ...]


def _failed(
    code: str,
    reason: str,
    checks: Iterable[PolicyCheck],
    manifest_digest: str | None = None,
) -> PolicyDecision:
    return PolicyDecision(False, code, reason, manifest_digest, tuple(checks))


def _passed(name: str, detail: str) -> PolicyCheck:
    return PolicyCheck(name=name, status="PASSED", detail=detail)


def _assert_canonical_value(value: Any, path: str = "$") -> None:
    if value is None or isinstance(value, (str, bool, int)):
        return
    if isinstance(value, float):
        raise ValueError(f"floating-point values are forbidden at {path}")
    if isinstance(value, list):
        for index, item in enumerate(value):
            _assert_canonical_value(item, f"{path}[{index}]")
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise ValueError(f"non-string object key at {path}")
            _assert_canonical_value(item, f"{path}.{key}")
        return
    raise ValueError(f"unsupported canonical JSON value at {path}")


def canonical_bytes(document: Mapping[str, Any]) -> bytes:
    """Return the deterministic Scanalyze JSON profile used for release signing."""

    _assert_canonical_value(document)
    return json.dumps(
        document,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def canonical_digest(
    document: Mapping[str, Any], *, omit_fields: set[str] | None = None
) -> str:
    candidate = copy.deepcopy(dict(document))
    for field in omit_fields or set():
        candidate.pop(field, None)
    return "sha256:" + hashlib.sha256(canonical_bytes(candidate)).hexdigest()


def _schema_errors(document: Mapping[str, Any], schema_name: str) -> list[str]:
    try:
        from jsonschema import Draft202012Validator, FormatChecker
    except ImportError as exc:  # pragma: no cover - exercised by CLI environments
        return [f"required verifier dependency unavailable: {exc.name}"]

    schema = json.loads((SCHEMAS / schema_name).read_text(encoding="utf-8"))
    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    errors = sorted(validator.iter_errors(document), key=lambda item: list(item.path))
    return [
        f"{'.'.join(str(part) for part in error.path) or '$'}: {error.message}"
        for error in errors
    ]


def _parse_time(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("timestamp must include an offset")
    return parsed.astimezone(UTC)


def _b64url_decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _verify_ecdsa_signature(
    statement: Mapping[str, Any], signature: Mapping[str, Any], signer: Mapping[str, Any]
) -> bool:
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec
    except ImportError as exc:  # pragma: no cover - exercised by CLI environments
        raise RuntimeError(f"required verifier dependency unavailable: {exc.name}") from exc

    try:
        jwk = signer["public_key_jwk"]
        x = int.from_bytes(_b64url_decode(jwk["x"]), "big")
        y = int.from_bytes(_b64url_decode(jwk["y"]), "big")
        public_key = ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1()).public_key()
        public_key.verify(
            base64.b64decode(signature["value"], validate=True),
            canonical_bytes(statement),
            ec.ECDSA(hashes.SHA256()),
        )
    except (InvalidSignature, TypeError, ValueError):
        return False
    return True


def _matching_signer(
    signature: Mapping[str, Any], policy: Mapping[str, Any]
) -> Mapping[str, Any] | None:
    for signer in policy["allowed_signers"]:
        if all(
            signature[field] == signer[field]
            for field in ("key_id", "issuer", "identity")
        ):
            return signer
    return None


def _digest_from_uri(uri: str) -> str | None:
    marker = "@sha256:"
    if marker not in uri:
        return None
    suffix = uri.rsplit(marker, 1)[1]
    return f"sha256:{suffix}" if len(suffix) == 64 else None


def evaluate_release(
    manifest: Mapping[str, Any],
    attestation: Mapping[str, Any],
    policy: Mapping[str, Any],
    *,
    expected_policy_digest: str,
    evaluated_at: datetime | None = None,
) -> PolicyDecision:
    """Evaluate a release without fallback, inference, or partial success."""

    checks: list[PolicyCheck] = []
    now = (evaluated_at or datetime.now(UTC)).astimezone(UTC)

    if manifest.get("schema_version") != "release.v2":
        return _failed(
            "LEGACY_MANIFEST_DENIED",
            "Only release.v2 is eligible; older or unversioned records require reviewed migration.",
            checks,
        )

    for document, schema_name, code in (
        (manifest, "release.v2.schema.json", "RELEASE_SCHEMA_INVALID"),
        (attestation, "release-attestation.v2.schema.json", "ATTESTATION_SCHEMA_INVALID"),
        (policy, "release-trust-policy.v1.schema.json", "POLICY_SCHEMA_INVALID"),
    ):
        errors = _schema_errors(document, schema_name)
        if errors:
            return _failed(code, "; ".join(errors[:5]), checks)
    checks.append(_passed("schemas", "manifest, attestation, and trust policy are structurally valid"))

    expected_manifest_digest = canonical_digest(
        manifest, omit_fields={"release_manifest_digest"}
    )
    claimed_manifest_digest = manifest["release_manifest_digest"]
    if claimed_manifest_digest != expected_manifest_digest:
        return _failed(
            "MANIFEST_DIGEST_MISMATCH",
            "The canonical manifest digest does not match the claimed digest.",
            checks,
            claimed_manifest_digest,
        )
    checks.append(_passed("manifest_digest", "canonical manifest digest matches"))

    manifest_created_at = _parse_time(manifest["created_at"])
    if manifest_created_at > now:
        return _failed(
            "MANIFEST_TIME_INVALID",
            "Release manifest creation time is in the future.",
            checks,
            claimed_manifest_digest,
        )

    computed_policy_digest = canonical_digest(policy)
    if expected_policy_digest != computed_policy_digest:
        return _failed(
            "TRUST_POLICY_NOT_APPROVED",
            "The supplied trust policy does not match the externally approved digest.",
            checks,
            claimed_manifest_digest,
        )
    if manifest["policy_digest"] != computed_policy_digest:
        return _failed(
            "POLICY_DIGEST_MISMATCH",
            "Manifest is not bound to the supplied trust policy.",
            checks,
            claimed_manifest_digest,
        )
    checks.append(_passed("policy_digest", "manifest is bound to the canonical trust policy"))

    source = manifest["source"]
    if (
        source["repository"] not in policy["allowed_source_repositories"]
        or source["ref"] not in policy["allowed_source_refs"]
    ):
        return _failed(
            "SOURCE_NOT_TRUSTED",
            "Source repository or ref is not trusted by release policy.",
            checks,
            claimed_manifest_digest,
        )

    builder = manifest["builder"]
    expected_workflow_ref = (
        builder["id"].removeprefix("https://github.com/") + "@" + source["commit"]
    )
    if (
        builder["id"] not in policy["allowed_builder_ids"]
        or builder["build_type"] not in policy["allowed_build_types"]
        or builder["runner_image"] not in policy["allowed_runner_images"]
        or builder["workflow_ref"] != expected_workflow_ref
    ):
        return _failed(
            "BUILDER_NOT_TRUSTED",
            "Builder identity, build type, or immutable workflow revision is not trusted.",
            checks,
            claimed_manifest_digest,
        )
    if builder["toolchain"] != policy["required_toolchain"]:
        return _failed(
            "TOOLCHAIN_MISMATCH",
            "Release toolchain is missing, mutable, or differs from the approved lock.",
            checks,
            claimed_manifest_digest,
        )
    checks.append(_passed("builder", "source, builder, workflow, runner, and toolchain are pinned"))

    artifact_ids = set(manifest["artifacts"])
    required_ids = set(policy["required_artifacts"])
    if artifact_ids != REQUIRED_ARTIFACT_IDS or required_ids != REQUIRED_ARTIFACT_IDS:
        return _failed(
            "ARTIFACT_INVENTORY_MISMATCH",
            "Manifest and policy must contain the exact reviewed runtime artifact inventory.",
            checks,
            claimed_manifest_digest,
        )

    evidence_digests: set[str] = set()
    latest_scan_time: datetime | None = None
    artifact_subjects: dict[str, str] = {}
    all_findings: dict[tuple[str, str], Mapping[str, Any]] = {}
    for artifact_id, artifact in manifest["artifacts"].items():
        digest = artifact["digest"]
        artifact_subjects[artifact_id] = digest
        if artifact["kind"] == "container":
            if _digest_from_uri(artifact["uri"]) != digest:
                return _failed(
                    "ARTIFACT_DIGEST_MISMATCH",
                    f"{artifact_id} URI is not bound to its exact digest.",
                    checks,
                    claimed_manifest_digest,
                )
            if _digest_from_uri(artifact["base_image_uri"]) != artifact["base_image_digest"]:
                return _failed(
                    "BASE_IMAGE_DIGEST_MISMATCH",
                    f"{artifact_id} base image is not digest-bound.",
                    checks,
                    claimed_manifest_digest,
                )
            if artifact["base_image_uri"] != policy["required_base_images"][artifact_id]:
                return _failed(
                    "BASE_IMAGE_NOT_APPROVED",
                    f"{artifact_id} base image differs from the approved trust policy.",
                    checks,
                    claimed_manifest_digest,
                )
        else:
            if digest.removeprefix("sha256:") not in artifact["uri"]:
                return _failed(
                    "ARTIFACT_DIGEST_MISMATCH",
                    f"{artifact_id} archive URI is not content-addressed.",
                    checks,
                    claimed_manifest_digest,
                )

        evidence = (
            ("sbom", artifact["sbom"], "digest", "syft"),
            ("scan", artifact["scan"], "report_digest", "trivy"),
            ("provenance", artifact["provenance"], "digest", None),
            ("signature", artifact["signature"], "bundle_digest", None),
        )
        for evidence_name, record, digest_field, tool_name in evidence:
            if record["subject_digest"] != digest:
                return _failed(
                    "EVIDENCE_SUBJECT_MISMATCH",
                    f"{artifact_id} {evidence_name} is bound to a different subject.",
                    checks,
                    claimed_manifest_digest,
                )
            evidence_digest = record[digest_field]
            if evidence_digest in evidence_digests:
                return _failed(
                    "EVIDENCE_REUSE_DENIED",
                    "Evidence digests must be unique to prevent cross-artifact substitution.",
                    checks,
                    claimed_manifest_digest,
                )
            evidence_digests.add(evidence_digest)
            if tool_name:
                tool_field = "generator" if evidence_name == "sbom" else "scanner"
                if record[tool_field] != builder["toolchain"][tool_name]:
                    return _failed(
                        "EVIDENCE_TOOLCHAIN_MISMATCH",
                        f"{artifact_id} {evidence_name} was produced by an unapproved tool.",
                        checks,
                        claimed_manifest_digest,
                    )

        provenance = artifact["provenance"]
        if any(
            (
                provenance["builder_id"] != builder["id"],
                provenance["build_type"] != builder["build_type"],
                provenance["source_repository"] != source["repository"],
                provenance["source_commit"] != source["commit"],
            )
        ):
            return _failed(
                "PROVENANCE_EXPECTATION_MISMATCH",
                f"{artifact_id} provenance does not match trusted build expectations.",
                checks,
                claimed_manifest_digest,
            )

        artifact_signature = artifact["signature"]
        trusted_artifact_signer = _matching_signer(artifact_signature, policy)
        expected_signer_identity = f"{builder['id']}@{source['ref']}"
        if (
            trusted_artifact_signer is None
            or artifact_signature["identity"] != expected_signer_identity
        ):
            return _failed(
                "ARTIFACT_SIGNER_UNTRUSTED",
                f"{artifact_id} signature identity is not trusted by release policy.",
                checks,
                claimed_manifest_digest,
            )

        scan = artifact["scan"]
        findings = scan["findings"]
        critical_count = sum(item["severity"] == "critical" for item in findings)
        high_count = sum(item["severity"] == "high" for item in findings)
        if critical_count != scan["critical_findings"] or high_count != scan["high_findings"]:
            return _failed(
                "SCAN_COUNT_MISMATCH",
                f"{artifact_id} scan counts do not match its finding inventory.",
                checks,
                claimed_manifest_digest,
            )
        if critical_count > policy["vulnerability_policy"]["max_critical"]:
            return _failed(
                "CRITICAL_FINDING",
                f"{artifact_id} contains a critical finding; critical findings are never waivable.",
                checks,
                claimed_manifest_digest,
            )
        scan_completed_at = _parse_time(scan["completed_at"])
        if scan_completed_at > manifest_created_at or scan_completed_at > now:
            return _failed(
                "SCAN_TIME_INVALID",
                f"{artifact_id} scan completion is after the manifest or current time.",
                checks,
                claimed_manifest_digest,
            )
        latest_scan_time = max(latest_scan_time or scan_completed_at, scan_completed_at)
        for finding in findings:
            key = (artifact_id, finding["id"])
            if key in all_findings:
                return _failed(
                    "DUPLICATE_FINDING",
                    "Finding identifiers must be unique within an artifact.",
                    checks,
                    claimed_manifest_digest,
                )
            all_findings[key] = finding

    checks.append(_passed("artifact_evidence", "every artifact has digest-bound evidence and provenance"))

    waiver_index: dict[tuple[str, str], Mapping[str, Any]] = {}
    waiver_ids: set[str] = set()
    waiver_policy = policy["waiver_policy"]
    for waiver in manifest["waivers"]:
        if waiver["waiver_id"] in waiver_ids:
            return _failed(
                "DUPLICATE_WAIVER",
                "Waiver identifiers must be unique within a release.",
                checks,
                claimed_manifest_digest,
            )
        waiver_ids.add(waiver["waiver_id"])
        key = (waiver["artifact_id"], waiver["finding_id"])
        finding = all_findings.get(key)
        if finding is None or finding["severity"] != waiver["severity"]:
            return _failed(
                "WAIVER_SCOPE_INVALID",
                "A waiver references a missing or mismatched artifact finding.",
                checks,
                claimed_manifest_digest,
            )
        if waiver["severity"] not in waiver_policy["allowed_severities"]:
            return _failed(
                "WAIVER_SEVERITY_DENIED",
                "The finding severity is not eligible for waiver.",
                checks,
                claimed_manifest_digest,
            )
        if waiver["approved_by_role"] not in waiver_policy["approver_roles"]:
            return _failed(
                "WAIVER_APPROVER_INVALID",
                "The waiver approver role is not authorized.",
                checks,
                claimed_manifest_digest,
            )
        approved_at = _parse_time(waiver["approved_at"])
        expires_at = _parse_time(waiver["expires_at"])
        if approved_at > now:
            return _failed(
                "WAIVER_TIME_INVALID",
                "A release waiver cannot be approved in the future.",
                checks,
                claimed_manifest_digest,
            )
        if expires_at <= now:
            return _failed(
                "WAIVER_EXPIRED",
                "A release waiver is expired.",
                checks,
                claimed_manifest_digest,
            )
        if expires_at <= approved_at or expires_at - approved_at > timedelta(
            days=waiver_policy["max_validity_days"]
        ):
            return _failed(
                "WAIVER_WINDOW_INVALID",
                "A waiver has an invalid or overlong approval window.",
                checks,
                claimed_manifest_digest,
            )
        if key in waiver_index:
            return _failed(
                "DUPLICATE_WAIVER",
                "Only one active waiver may apply to an artifact finding.",
                checks,
                claimed_manifest_digest,
            )
        waiver_index[key] = waiver

    for key, finding in all_findings.items():
        if finding["severity"] == "high":
            if finding["status"] != "waived" or key not in waiver_index:
                return _failed(
                    "UNWAIVED_HIGH_FINDING",
                    "All high findings require a current, scoped, approved waiver.",
                    checks,
                    claimed_manifest_digest,
                )
    checks.append(_passed("vulnerabilities", "no critical or unwaived high findings remain"))

    statement = attestation["statement"]
    predicate = statement["predicate"]
    subject_digest = "sha256:" + statement["subject"][0]["digest"]["sha256"]
    if subject_digest != claimed_manifest_digest:
        return _failed(
            "ATTESTATION_SUBJECT_MISMATCH",
            "Release attestation is bound to a different manifest.",
            checks,
            claimed_manifest_digest,
        )
    if predicate["policy"]["digest"] != computed_policy_digest:
        return _failed(
            "ATTESTATION_POLICY_MISMATCH",
            "Release attestation was evaluated against a different policy.",
            checks,
            claimed_manifest_digest,
        )
    verifier = policy["verification_policy"]
    if predicate["verifier"] != {
        "id": verifier["verifier_id"],
        "version": verifier["verifier_version"],
        "digest": verifier["verifier_digest"],
    }:
        return _failed(
            "VERIFIER_MISMATCH",
            "Attestation verifier is not the exact policy-approved verifier.",
            checks,
            claimed_manifest_digest,
        )
    verified_level = max(SLSA_LEVELS[level] for level in predicate["verifiedLevels"])
    if verified_level < SLSA_LEVELS[verifier["minimum_slsa_build_level"]]:
        return _failed(
            "SLSA_LEVEL_INSUFFICIENT",
            "Attestation does not meet the minimum approved SLSA build level.",
            checks,
            claimed_manifest_digest,
        )
    if predicate["artifactSubjects"] != artifact_subjects:
        return _failed(
            "ATTESTATION_ARTIFACT_MISMATCH",
            "Attestation artifact subjects differ from the manifest.",
            checks,
            claimed_manifest_digest,
        )
    if set(predicate["inputAttestations"]) != evidence_digests:
        return _failed(
            "ATTESTATION_EVIDENCE_MISMATCH",
            "Attestation does not cover the exact release evidence set.",
            checks,
            claimed_manifest_digest,
        )
    verified_at = _parse_time(predicate["timeVerified"])
    if (
        verified_at > now
        or verified_at < manifest_created_at
        or (latest_scan_time is not None and verified_at < latest_scan_time)
    ):
        return _failed(
            "ATTESTATION_TIME_INVALID",
            "Attestation time is outside the valid evidence and manifest chronology.",
            checks,
            claimed_manifest_digest,
        )

    signature = attestation["signature"]
    signer = _matching_signer(signature, policy)
    if signer is None or signature["identity"] != expected_signer_identity:
        return _failed(
            "UNTRUSTED_SIGNER",
            "Signature issuer, identity, and key ID are not an exact trusted tuple.",
            checks,
            claimed_manifest_digest,
        )
    try:
        signature_valid = _verify_ecdsa_signature(statement, signature, signer)
    except RuntimeError as exc:
        return _failed(
            "VERIFIER_TOOL_UNAVAILABLE",
            str(exc),
            checks,
            claimed_manifest_digest,
        )
    if not signature_valid:
        return _failed(
            "SIGNATURE_INVALID",
            "ECDSA signature verification failed.",
            checks,
            claimed_manifest_digest,
        )
    checks.append(_passed("attestation", "VSA subject, evidence, policy, identity, and signature verified"))

    if manifest["promotion"] != {"mode": "copy-by-digest", "rebuild": False}:
        return _failed(
            "PROMOTION_MODE_INVALID",
            "Release promotion must copy the approved digest set without rebuilding.",
            checks,
            claimed_manifest_digest,
        )
    checks.append(_passed("promotion", "promotion and rollback preserve the signed digest set without rebuild"))

    return PolicyDecision(
        True,
        "RELEASE_POLICY_PASSED",
        "The signed build-once release is eligible for reviewed promotion.",
        claimed_manifest_digest,
        tuple(checks),
    )


def build_deployment_projection(
    manifest: Mapping[str, Any],
    attestation: Mapping[str, Any],
    policy: Mapping[str, Any],
    *,
    target: str,
    expected_policy_digest: str,
    evaluated_at: datetime | None = None,
) -> dict[str, Any]:
    if target not in {"sandbox", "staging", "production"}:
        raise ValueError("target must be sandbox, staging, or production")
    decision = evaluate_release(
        manifest,
        attestation,
        policy,
        expected_policy_digest=expected_policy_digest,
        evaluated_at=evaluated_at,
    )
    if not decision.allowed:
        raise ValueError(f"{decision.code}: {decision.reason}")

    artifacts = manifest["artifacts"]
    projection = {
        "schema_version": "release-deployment-projection.v1",
        "target": target,
        "release_id": manifest["release_id"],
        "release_version": manifest["release_version"],
        "release_manifest_digest": manifest["release_manifest_digest"],
        "release_attestation_digest": canonical_digest(attestation),
        "service_images": {
            artifact_id.removeprefix("scanalyze-"): artifacts[artifact_id]["uri"]
            for artifact_id in sorted(SERVICE_ARTIFACT_IDS)
        },
        "runtime_artifacts": {
            artifact_id: {
                "uri": artifacts[artifact_id]["uri"],
                "digest": artifacts[artifact_id]["digest"],
            }
            for artifact_id in sorted(RUNTIME_ARTIFACT_IDS)
        },
        "promotion_mode": "copy-by-digest",
        "rebuild": False,
    }
    errors = _schema_errors(projection, "release-deployment-projection.v1.schema.json")
    if errors:  # pragma: no cover - defensive invariant
        raise ValueError("invalid generated projection: " + "; ".join(errors))
    return projection


def _load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _decision_json(decision: PolicyDecision) -> dict[str, Any]:
    return {
        "allowed": decision.allowed,
        "code": decision.code,
        "reason": decision.reason,
        "manifest_digest": decision.manifest_digest,
        "checks": [check.__dict__ for check in decision.checks],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--attestation", type=Path, required=True)
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--expected-policy-digest", required=True)
    parser.add_argument("--target", choices=("sandbox", "staging", "production"))
    parser.add_argument("--projection-out", type=Path)
    args = parser.parse_args(argv)

    if bool(args.target) != bool(args.projection_out):
        parser.error("--target and --projection-out must be supplied together")

    try:
        manifest = _load_json(args.manifest)
        attestation = _load_json(args.attestation)
        policy = _load_json(args.policy)
        decision = evaluate_release(
            manifest,
            attestation,
            policy,
            expected_policy_digest=args.expected_policy_digest,
        )
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        print(json.dumps({"allowed": False, "code": "INPUT_INVALID", "reason": str(exc)}))
        return 2

    print(json.dumps(_decision_json(decision), sort_keys=True))
    if not decision.allowed:
        return 1

    if args.projection_out:
        projection = build_deployment_projection(
            manifest,
            attestation,
            policy,
            target=args.target,
            expected_policy_digest=args.expected_policy_digest,
        )
        args.projection_out.write_text(
            json.dumps(projection, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
