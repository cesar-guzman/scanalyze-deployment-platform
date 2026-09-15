#!/usr/bin/env python3
"""Offline verifier adapters for the identity-control-plane production inputs.

These adapters project verified source authority (release/v2, identity-contract/v2,
enterprise-authorization policy) into the exact shapes required by the
identity-control-plane Terraform root.  No AWS call is made; each adapter
validates schemas, recomputes digests, and rejects mismatched inputs fail-closed.

Adapter inventory (7 root inputs covered):
  1. build_identity_runtime_artifact  → release_manifest_contract + expected digest
  2. verify_m2m_registry              → m2m_registry_contract + expected digest
  3. derive_policy_binding            → policy_version + policy_digest
  4. verify_control_processor         → control_processor_enabled
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

import jsonschema

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
SCHEMAS_DIR = REPO_ROOT / "schemas"
POLICIES_DIR = REPO_ROOT / "policies" / "authorization"

SHA256_RE = re.compile(r"^sha256:[a-f0-9]{64}$")
SEMVER_RE = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _require(condition: bool, message: str) -> None:
    """Fail-closed assertion."""
    if not condition:
        raise ValueError(message)


def _load_schema(name: str) -> dict:
    path = SCHEMAS_DIR / name
    _require(path.exists(), f"schema not found: {name}")
    return json.loads(path.read_text(encoding="utf-8"))


def _validate_schema(document: dict, schema_name: str) -> None:
    schema = _load_schema(schema_name)
    try:
        jsonschema.validate(document, schema)
    except jsonschema.ValidationError as exc:
        raise ValueError(f"schema validation failed ({schema_name}): {exc.message}") from exc


def _canonical_bytes(value: object) -> bytes:
    """Deterministic JSON for digest computation."""
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")


def _compute_digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _digest_of(document: dict, *, exclude_key: str = "record_digest") -> str:
    digestible = {k: v for k, v in document.items() if k != exclude_key}
    return _compute_digest(_canonical_bytes(digestible))


# ---------------------------------------------------------------------------
# 1. Identity Runtime Artifact adapter
#    Inputs : release/v2, S3 publication evidence, destination tuple
#    Outputs: identity-runtime-artifact.v1 projection
# ---------------------------------------------------------------------------

def build_identity_runtime_artifact(
    *,
    release: dict,
    attestation: dict,
    policy: dict,
    expected_policy_digest: str,
    expected_release_document_digest: str,
    expected_release_manifest_digest: str,
    cicd_contract: dict,
    expected_cicd_contract_digest: str,
    publication_receipt: dict,
    expected_publication_digest: str,
    customer_id: str,
    deployment_id: str,
    account_id: str,
    region: str,
    environment: str,
    resolved_at: datetime,
    max_contract_age_seconds: int,
) -> dict:
    """Build a verified identity-runtime-artifact/v1 projection.

    Validates the release/v2, recomputes its digest, verifies the two Lambda
    archive artifacts exist in the release, and binds S3 publication evidence
    to the destination tuple.  Returns the closed projection matching
    identity-runtime-artifact.v1.schema.json.
    """
    try:
        from tooling.release_policy_gate import evaluate_release
    except ModuleNotFoundError:
        from release_policy_gate import evaluate_release  # type: ignore[no-redef]

    decision = evaluate_release(
        release,
        attestation,
        policy,
        expected_policy_digest=expected_policy_digest,
    )
    _require(decision.allowed, f"release policy rejected: {decision.reason}")

    # The document pin and the signed manifest digest are distinct authorities.
    _require(SHA256_RE.fullmatch(expected_release_document_digest) is not None,
             "expected_release_document_digest is not a valid sha256 digest")
    _require(SHA256_RE.fullmatch(expected_release_manifest_digest) is not None,
             "expected_release_manifest_digest is not a valid sha256 digest")
    _validate_schema(release, "release.v2.schema.json")

    # 2. Recompute release digest
    release_digest = _compute_digest(_canonical_bytes(release))
    _require(release_digest == expected_release_document_digest,
             "release document digest mismatch")
    _require(decision.manifest_digest == expected_release_manifest_digest,
             "signed release manifest digest mismatch")

    # 3. Extract and verify the two identity artifacts exist in release
    artifacts = release.get("artifacts", {})
    _require("identity-pre-token-lambda" in artifacts,
             "release missing identity-pre-token-lambda artifact")
    _require("identity-control-processor-lambda" in artifacts,
             "release missing identity-control-processor-lambda artifact")

    pre_token_art = artifacts["identity-pre-token-lambda"]
    ctrl_proc_art = artifacts["identity-control-processor-lambda"]

    _require(pre_token_art.get("kind") == "archive",
             "identity-pre-token-lambda must be an archive artifact")
    _require(ctrl_proc_art.get("kind") == "archive",
             "identity-control-processor-lambda must be an archive artifact")

    # 3.5 Validate CICD Contract
    _require(SHA256_RE.fullmatch(expected_cicd_contract_digest) is not None, "expected_cicd_contract_digest invalid")
    cicd_digest = _compute_digest(_canonical_bytes(cicd_contract))
    _require(cicd_digest == expected_cicd_contract_digest, "cicd_contract digest mismatch")
    _require(isinstance(resolved_at, datetime) and resolved_at.tzinfo is not None,
             "resolved_at must include a timezone")
    _require(type(max_contract_age_seconds) is int and 1 <= max_contract_age_seconds <= 86400,
             "max_contract_age_seconds is invalid")
    from scripts.deployment.contract_projection import load_json, validate_contract
    # Artifact publication is the catalog-authorized consumer of CICD authority.
    _, _, cicd_outputs, _ = validate_contract(
        cicd_contract, _load_schema("layer-contract.v2.schema.json"),
        catalog=load_json(REPO_ROOT / "deployment/contract-catalog.v1.json", "contract catalog"),
        layer="artifact-publication", customer_id=customer_id,
        deployment_id=deployment_id, account_id=account_id, region=region,
        release_digest=expected_release_manifest_digest,
        release_version=release["release_version"], resolved_at=resolved_at,
        max_contract_age_seconds=max_contract_age_seconds,
        required_contracts={"cicd/v2"},
    )
    destination_bucket = cicd_outputs["artifact_bucket_name"]
    _require(isinstance(destination_bucket, str) and len(destination_bucket) >= 3, "CICD artifact_bucket_name invalid")

    # 3.6 Validate Publication Receipt
    _require(SHA256_RE.fullmatch(expected_publication_digest) is not None, "expected_publication_digest invalid")
    _validate_schema(publication_receipt, "identity-publication-receipt.v1.schema.json")

    receipt_digest = _digest_of(publication_receipt, exclude_key="receipt_digest")
    _require(receipt_digest == expected_publication_digest, "publication_receipt recomputed digest mismatch")
    _require(publication_receipt.get("receipt_digest") == expected_publication_digest, "publication_receipt self-digest mismatch")

    _require(publication_receipt["customer_id"] == customer_id, "receipt customer_id mismatch")
    _require(publication_receipt["deployment_id"] == deployment_id, "receipt deployment_id mismatch")
    _require(publication_receipt["account_id"] == account_id, "receipt account_id mismatch")
    _require(publication_receipt["region"] == region, "receipt region mismatch")
    _require(publication_receipt["environment"] == environment, "receipt environment mismatch")

    _require(publication_receipt["signed_release_manifest_digest"] == expected_release_manifest_digest, "receipt signed_release_manifest_digest mismatch")
    _require(publication_receipt["signed_release_manifest_version"] == release["release_version"], "receipt signed_release_manifest_version mismatch")
    _require(publication_receipt["cicd_contract_digest"] == expected_cicd_contract_digest, "receipt cicd_contract_digest mismatch")
    _require(publication_receipt["destination_bucket"] == destination_bucket, "receipt destination_bucket mismatch with CICD")

    pre_token_publication = publication_receipt["identity_pre_token_lambda_locator"]
    control_processor_publication = publication_receipt["identity_control_processor_lambda_locator"]

    # 4. Validate S3 publication locators (must be provided externally)
    import base64
    for label, pub, artifact in [
        ("pre_token", pre_token_publication, pre_token_art),
        ("control_processor", control_processor_publication, ctrl_proc_art)
    ]:
        _require(isinstance(pub, dict), f"{label} publication must be a dict")
        for field in ("bucket", "key", "object_version", "sha256_b64"):
            _require(field in pub, f"{label} publication missing '{field}'")
        _require(isinstance(pub["bucket"], str) and len(pub["bucket"]) >= 3,
                 f"{label} publication bucket invalid")
        _require(isinstance(pub["key"], str) and len(pub["key"]) >= 1,
                 f"{label} publication key invalid")
        _require(isinstance(pub["object_version"], str) and len(pub["object_version"]) >= 1,
                 f"{label} publication object_version invalid")
        _require(pub["object_version"].lower() != "null",
                 f"{label} publication object_version must be immutable (not null)")
        _require(len(pub["object_version"].encode("utf-8")) <= 1024,
                 f"{label} publication object_version exceeds the 1024-byte root limit")
        _require(re.fullmatch(r"[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]=", pub["sha256_b64"]) is not None,
                 f"{label} publication sha256_b64 invalid base64")

        _require(pub["bucket"] == destination_bucket,
                 f"{label} publication bucket not bound to CICD destination bucket")

        expected_key_prefix = f"deployments/{deployment_id}/artifacts/"
        _require(pub["key"].startswith(expected_key_prefix),
                 f"{label} publication key not bound to deployment_id")
        artifact_digest_hex = artifact["digest"].split(":", 1)[1]
        key_digests = re.findall(r"(?:^|/)sha256[-/:]([0-9a-f]{64})(?=[./_-]|$)", pub["key"])
        _require(key_digests == [artifact_digest_hex],
                 f"{label} publication key must contain exactly one content-addressed SHA-256 segment matching the signed artifact")
        # Encoding the signed bytes independently also rejects noncanonical
        # padding representations that permissive Base64 decoders accept.
        expected_b64 = base64.b64encode(bytes.fromhex(artifact_digest_hex)).decode("ascii")
        _require(pub["sha256_b64"] == expected_b64,
                 f"{label} publication sha256_b64 mismatch with signed release artifact digest")

    # 5. Build the projection
    projection = {
        "schema_version": "identity-runtime-artifact.v1",
        "contract_id": "release-manifest/v1",
        "customer_id": customer_id,
        "deployment_id": deployment_id,
        "account_id": account_id,
        "region": region,
        "release_version": release["release_version"],
        "manifest_digest": release["release_manifest_digest"],
        "contract_digest": "",  # placeholder, computed below
        "pre_token_artifact": {
            "bucket": pre_token_publication["bucket"],
            "key": pre_token_publication["key"],
            "object_version": pre_token_publication["object_version"],
            "sha256_b64": pre_token_publication["sha256_b64"],
        },
        "control_processor_artifact": {
            "bucket": control_processor_publication["bucket"],
            "key": control_processor_publication["key"],
            "object_version": control_processor_publication["object_version"],
            "sha256_b64": control_processor_publication["sha256_b64"],
        },
    }

    # Compute contract digest (excluding the contract_digest field itself)
    digestible = {k: v for k, v in projection.items() if k != "contract_digest"}
    projection["contract_digest"] = _compute_digest(_canonical_bytes(digestible))

    # 6. Validate the projection against its closed schema
    _validate_schema(projection, "identity-runtime-artifact.v1.schema.json")

    return projection


# ---------------------------------------------------------------------------
# 2. M2M Registry adapter
#    Inputs : identity-contract/v2, destination tuple
#    Outputs: m2m-registry-projection.v1
# ---------------------------------------------------------------------------

def verify_m2m_registry(
    *,
    identity_contract: dict,
    expected_identity_contract_digest: str,
    customer_id: str,
    deployment_id: str,
) -> dict:
    """Build a verified m2m-registry-projection/v1 from identity-contract/v2.

    Validates the full identity-contract/v2, verifies its digest, checks the
    deployment tuple, and projects the M2M-specific fields into a reduced
    closed shape.
    """
    # 1. Validate source
    _require(SHA256_RE.fullmatch(expected_identity_contract_digest) is not None,
             "expected digest is not a valid sha256")
    _validate_schema(identity_contract, "identity-contract.v2.schema.json")

    # 2. Verify digest
    contract_digest = _compute_digest(_canonical_bytes(identity_contract))
    _require(contract_digest == expected_identity_contract_digest,
             f"identity-contract digest mismatch: computed {contract_digest}")

    # 3. Verify deployment tuple
    _require(identity_contract["customer_id"] == customer_id,
             "identity-contract customer_id does not match destination")
    _require(identity_contract["deployment_id"] == deployment_id,
             "identity-contract deployment_id does not match destination")

    # 4. Verify M2M bindings are bound to the same deployment
    for binding in identity_contract["m2m_bindings"]:
        _require(binding["customer_id"] == customer_id,
                 f"M2M binding client {binding['client_id']} has wrong customer_id")
        _require(binding["deployment_id"] == deployment_id,
                 f"M2M binding client {binding['client_id']} has wrong deployment_id")

    # 5. Build projection
    projection = {
        "schema_version": "m2m-registry-projection.v1",
        "contract_id": "identity-contract/v2",
        "customer_id": customer_id,
        "deployment_id": deployment_id,
        "contract_digest": contract_digest,
        "action_scope_sets": identity_contract["action_scope_sets"],
        "m2m_bindings": identity_contract["m2m_bindings"],
    }

    # 6. Validate projection schema
    _validate_schema(projection, "m2m-registry-projection.v1.schema.json")

    return projection


# ---------------------------------------------------------------------------
# 3. Policy Binding adapter
#    Inputs : canonical policy path, policy version string
#    Outputs: (policy_version, policy_digest)
# ---------------------------------------------------------------------------

def derive_policy_binding(
    *,
    policy_path: Path | None = None,
    policy_version: str,
) -> tuple[str, str]:
    """Derive the policy version and RFC 8785 digest from the canonical policy.

    Uses tooling/policy_digest.py's canonicalization to recompute the digest
    and verifies the supplied version matches semver.  Returns the tuple
    (policy_version, policy_digest).
    """
    _require(SEMVER_RE.fullmatch(policy_version) is not None,
             "policy_version must be semantic x.y.z")

    if policy_path is None:
        policy_path = POLICIES_DIR / "enterprise-authorization.v1.json"

    _require(policy_path.exists(), f"policy file not found: {policy_path}")

    # Import the existing policy digest module
    try:
        from tooling.policy_digest import compute_policy_digest, canonicalize_rfc8785
        from tooling.validate_enterprise_authorization import load_json_without_duplicates
    except ModuleNotFoundError:
        from policy_digest import compute_policy_digest, canonicalize_rfc8785  # type: ignore[no-redef]
        from validate_enterprise_authorization import load_json_without_duplicates  # type: ignore[no-redef]

    policy = load_json_without_duplicates(policy_path)
    _require(policy.get("policy_version") == policy_version,
             "policy_version does not match the reviewed policy")
    computed_digest = compute_policy_digest(policy)

    _require(SHA256_RE.fullmatch(computed_digest) is not None,
             "computed policy digest is malformed")

    # Verify against tracked digest if it exists
    digest_path = policy_path.with_suffix(".sha256")
    if digest_path.exists():
        tracked = digest_path.read_text(encoding="utf-8").strip()
        _require(computed_digest == tracked,
                 f"policy digest does not match tracked digest: {computed_digest} vs {tracked}")

    return policy_version, computed_digest


# ---------------------------------------------------------------------------
# 4. Control Processor activation binding
#    Inputs : explicit boolean decision + binding evidence
#    Outputs: bool
# ---------------------------------------------------------------------------

def verify_control_processor(
    *,
    enabled: bool,
    policy_version: str,
    policy_digest: str,
    m2m_registry_digest: str,
    release_manifest_digest: str,
) -> bool:
    """Verify the explicit control-processor activation decision.

    The root requires `control_processor_enabled = true` as a precondition.
    This adapter verifies that the decision is bound to the correct set of
    identity/release/policy evidence, not merely set to true.
    """
    _require(isinstance(enabled, bool), "control_processor_enabled must be a boolean")
    _require(enabled is True,
             "identity-control-plane/v1 requires control_processor_enabled = true")

    # Verify the binding evidence exists and is valid
    _require(SEMVER_RE.fullmatch(policy_version) is not None,
             "policy_version binding is invalid")
    _require(SHA256_RE.fullmatch(policy_digest) is not None,
             "policy_digest binding is invalid")
    _require(SHA256_RE.fullmatch(m2m_registry_digest) is not None,
             "m2m_registry_digest binding is invalid")
    _require(SHA256_RE.fullmatch(release_manifest_digest) is not None,
             "release_manifest_digest binding is invalid")

    return True


def verify_identity_runtime_inputs(
    authority: dict, expected_digest: str, *, release: dict, attestation: dict,
    release_policy: dict, expected_release_policy_digest: str,
    expected_release_manifest_digest: str, customer_id: str, deployment_id: str,
    account_id: str, region: str, environment: str, resolved_at: datetime,
    max_contract_age_seconds: int,
) -> dict:
    """Verify one externally pinned authority and emit the seven root inputs.

    The outer pin comes from the reviewed sealed request, never this document.
    Each nested independent pin remains mandatory under that outer authority.
    """
    _validate_schema(authority, "identity-runtime-authority.v1.schema.json")
    _require(isinstance(expected_digest, str) and SHA256_RE.fullmatch(expected_digest) is not None,
             "identity authority independent digest is invalid")
    _require(_compute_digest(_canonical_bytes(authority)) == expected_digest,
             "identity authority document digest mismatch")
    artifact = build_identity_runtime_artifact(
        release=release, attestation=attestation, policy=release_policy,
        expected_policy_digest=expected_release_policy_digest,
        expected_release_document_digest=authority["expected_release_document_digest"],
        expected_release_manifest_digest=expected_release_manifest_digest,
        cicd_contract=authority["cicd_contract"],
        expected_cicd_contract_digest=authority["expected_cicd_contract_digest"],
        publication_receipt=authority["publication_receipt"],
        expected_publication_digest=authority["expected_publication_digest"],
        customer_id=customer_id, deployment_id=deployment_id, account_id=account_id,
        region=region, environment=environment, resolved_at=resolved_at,
        max_contract_age_seconds=max_contract_age_seconds,
    )
    registry = verify_m2m_registry(
        identity_contract=authority["identity_registry"],
        expected_identity_contract_digest=authority["expected_identity_registry_digest"],
        customer_id=customer_id, deployment_id=deployment_id,
    )
    from tooling.policy_digest import compute_policy_digest
    from tooling.validate_enterprise_authorization import validate_enterprise_authorization
    policy = authority["authorization_policy"]
    _validate_schema(policy, "enterprise-authorization.v1.schema.json")
    _require(not validate_enterprise_authorization(policy), "authorization policy semantics invalid")
    _require(policy["policy_version"] == authority["policy_version"], "authorization policy version mismatch")
    _require(compute_policy_digest(policy) == authority["expected_authorization_policy_digest"],
             "authorization policy digest mismatch")
    canonical_scopes = {action: [f"scanalyze.api.v1/{action}"] for action in ("read", "write", "admin")}
    _require(registry["action_scope_sets"] == canonical_scopes, "M2M action scopes are not canonical")
    bindings = registry["m2m_bindings"]
    _require(len({item["client_id"] for item in bindings}) == len(bindings), "M2M client bindings are duplicated")
    allowed_scopes = {scope for scopes in canonical_scopes.values() for scope in scopes}
    _require(all(item["required_scopes"] and len(set(item["required_scopes"])) == len(item["required_scopes"])
                 and set(item["required_scopes"]) <= allowed_scopes for item in bindings),
             "M2M binding scopes are not canonical")
    enabled = verify_control_processor(
        enabled=authority["control_processor_enabled"], policy_version=authority["policy_version"],
        policy_digest=authority["expected_authorization_policy_digest"],
        m2m_registry_digest=registry["contract_digest"],
        release_manifest_digest=expected_release_manifest_digest,
    )
    # Terraform consumes contract schema majors, not adapter transport versions.
    artifact["schema_version"] = "1"
    artifact["contract_digest"] = _digest_of(artifact, exclude_key="contract_digest")
    registry["schema_version"] = "2"
    variables = {
        "release_manifest_contract": artifact,
        "expected_release_manifest_contract_digest": artifact["contract_digest"],
        "m2m_registry_contract": registry,
        "expected_m2m_registry_contract_digest": authority["expected_identity_registry_digest"],
        "policy_version": authority["policy_version"],
        "policy_digest": authority["expected_authorization_policy_digest"],
        "control_processor_enabled": enabled,
    }
    # Opt-in ownership is meaningful only when present under the reviewed outer
    # pin. Absence preserves the root's existing native default.
    if "cognito_pool_ownership_mode" in authority:
        variables["cognito_pool_ownership_mode"] = authority["cognito_pool_ownership_mode"]
    return variables


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _write_projection(path: Path, projection: dict) -> None:
    """Create a private output exclusively, after every verification succeeds."""
    data = json.dumps(projection, indent=2, sort_keys=True) + "\n"
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                         stat.S_IRUSR | stat.S_IWUSR)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            stream.write(data)
    except BaseException:
        path.unlink(missing_ok=True)
        raise

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Identity adapter verifiers for identity-control-plane inputs"
    )
    sub = parser.add_subparsers(dest="command")

    # Sub: release-manifest
    rm_parser = sub.add_parser("release-manifest",
                               help="Build identity-runtime-artifact projection")
    rm_parser.add_argument("--release", type=Path, required=True)
    rm_parser.add_argument("--attestation", type=Path, required=True)
    rm_parser.add_argument("--policy", type=Path, required=True)
    rm_parser.add_argument("--expected-policy-digest", required=True)
    rm_parser.add_argument("--expected-release-document-digest", required=True)
    rm_parser.add_argument("--expected-release-manifest-digest", required=True)
    rm_parser.add_argument("--cicd-contract", type=Path, required=True)
    rm_parser.add_argument("--expected-cicd-contract-digest", required=True)
    rm_parser.add_argument("--publication-receipt", type=Path, required=True)
    rm_parser.add_argument("--expected-publication-digest", required=True)
    rm_parser.add_argument("--customer-id", required=True)
    rm_parser.add_argument("--deployment-id", required=True)
    rm_parser.add_argument("--account-id", required=True)
    rm_parser.add_argument("--region", required=True)
    rm_parser.add_argument("--environment", required=True)
    rm_parser.add_argument("--resolved-at", required=True)
    rm_parser.add_argument("--max-contract-age-seconds", type=int, required=True)
    rm_parser.add_argument("--output", type=Path, required=True)

    # Sub: m2m-registry
    mr_parser = sub.add_parser("m2m-registry",
                               help="Build M2M registry projection")
    mr_parser.add_argument("--identity-contract", type=Path, required=True)
    mr_parser.add_argument("--expected-digest", required=True)
    mr_parser.add_argument("--customer-id", required=True)
    mr_parser.add_argument("--deployment-id", required=True)
    mr_parser.add_argument("--output", type=Path, required=True)

    # Sub: policy
    pol_parser = sub.add_parser("policy",
                                help="Derive policy version and digest")
    pol_parser.add_argument("--policy-path", type=Path)
    pol_parser.add_argument("--policy-version", required=True)

    args = parser.parse_args(argv)

    if args.command is None:
        parser.print_help()
        return 1

    try:
        from scripts.deployment.contract_projection import load_json
        if args.command == "release-manifest":
            release = load_json(args.release, "release")
            attestation = load_json(args.attestation, "attestation")
            policy = load_json(args.policy, "release policy")
            cicd_contract = load_json(args.cicd_contract, "CICD contract")
            publication_receipt = load_json(args.publication_receipt, "publication receipt")

            projection = build_identity_runtime_artifact(
                release=release,
                attestation=attestation,
                policy=policy,
                expected_policy_digest=args.expected_policy_digest,
                expected_release_document_digest=args.expected_release_document_digest,
                expected_release_manifest_digest=args.expected_release_manifest_digest,
                cicd_contract=cicd_contract,
                expected_cicd_contract_digest=args.expected_cicd_contract_digest,
                publication_receipt=publication_receipt,
                expected_publication_digest=args.expected_publication_digest,
                customer_id=args.customer_id,
                deployment_id=args.deployment_id,
                account_id=args.account_id,
                region=args.region,
                environment=args.environment,
                resolved_at=datetime.fromisoformat(args.resolved_at.replace("Z", "+00:00")),
                max_contract_age_seconds=args.max_contract_age_seconds,
            )

            _write_projection(args.output, projection)
            print(f"VERIFIED: identity-runtime-artifact.v1 written to {args.output}")
            print(f"contract_digest: {projection['contract_digest']}")
            return 0

        if args.command == "m2m-registry":
            contract = load_json(args.identity_contract, "identity contract")
            projection = verify_m2m_registry(
                identity_contract=contract,
                expected_identity_contract_digest=args.expected_digest,
                customer_id=args.customer_id,
                deployment_id=args.deployment_id,
            )
            _write_projection(args.output, projection)
            print(f"VERIFIED: m2m-registry-projection.v1 written to {args.output}")
            print(f"contract_digest: {projection['contract_digest']}")
            return 0

        if args.command == "policy":
            version, digest = derive_policy_binding(
                policy_path=args.policy_path,
                policy_version=args.policy_version,
            )
            print(f"policy_version: {version}")
            print(f"policy_digest: {digest}")
            return 0

    except (ValueError, OSError, json.JSONDecodeError) as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1

    return 1


if __name__ == "__main__":
    raise SystemExit(main())
