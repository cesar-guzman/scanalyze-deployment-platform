# Build-Once Supply-Chain Contract

## Outcome

One reviewed source revision produces one immutable set of ten Scanalyze runtime artifacts. The set may be copied into multiple authorized customer accounts, but it may never be rebuilt during promotion or rollback.

## Authority chain

```text
release-trust-policy.v1
          |
          v
release.v2 --canonical digest--> signed VSA
          |                         |
          +------ strict gate ------+
                       |
                       v
         release-deployment-projection.v1
                       |
                       v
             Terraform digest inputs
```

The deployment projection exists only after `tooling/release_policy_gate.py` passes. A caller-provided image tag, archive path, evidence reference, account prefix, or legacy manifest cannot establish authority.

## Required artifact inventory

- `scanalyze-ingest-api`
- `scanalyze-ocr-worker`
- `scanalyze-postprocess-worker`
- `scanalyze-classifier-worker`
- `scanalyze-bank-worker`
- `scanalyze-personal-worker`
- `scanalyze-gov-worker`
- `identity-pre-token-lambda`
- `identity-control-processor-lambda`
- `scanalyze-frontend-ui`

Every artifact requires an exact digest, SPDX 2.3 JSON SBOM, vulnerability scan, SLSA provenance, and signature bundle. SPDX 2.3 is explicit because it is the newest SPDX JSON version supported by the pinned Syft generator; an upgrade requires a reviewed toolchain and schema change. Container artifacts also require a digest-pinned base image.

## Offline verification

```bash
python tooling/release_policy_gate.py \
  --manifest fixtures/valid/release-v2-complete.synthetic.json \
  --attestation fixtures/valid/release-attestation-v2-complete.synthetic.json \
  --policy fixtures/valid/release-trust-policy-v1-synthetic.json \
  --expected-policy-digest "$(cat fixtures/valid/release-trust-policy-v1-synthetic.sha256)" \
  --target staging \
  --projection-out /tmp/release-projection.json
```

The expected policy digest is a separate trust root, not a value read from the manifest or supplied policy. The committed command uses synthetic evidence only. A live execution must obtain the approved digest from a protected deployment-specific control plane, then obtain the trust policy, signed manifest, and evidence independently. Do not copy the synthetic digest or public key into a customer configuration.

## Fail-closed result codes

Examples include `LEGACY_MANIFEST_DENIED`, `MANIFEST_DIGEST_MISMATCH`, `TOOLCHAIN_MISMATCH`, `EVIDENCE_SUBJECT_MISMATCH`, `CRITICAL_FINDING`, `WAIVER_EXPIRED`, `UNTRUSTED_SIGNER`, and `SIGNATURE_INVALID`. Any non-zero command result is a release `NO-GO`; automation must not retry by disabling checks or substituting caller values.

## Build and tool constraints

- `scripts/microservices/build-push.sh` rejects every base image without `@sha256`, including local validation builds; the release gate additionally requires the runner and every service base image to match the externally approved trust policy.
- SBOM, scan, signing, and verification wrappers return non-zero when their tool or output is missing.
- `verify-image.sh` requires exact certificate identity and OIDC issuer and propagates the `cosign` failure status.
- The legacy release-graph command emits only a deterministic planning inventory with `eligible_for_promotion=false`.
- PR validation runs `make supply-chain-check` without OIDC or AWS credentials.
- The legacy cloud publication job remains an explicit terminal failure until GUG-125.

## Terraform boundary

`modules/services` rejects mutable service images. The GUG-125 orchestrator must construct tfvars from the verified deployment projection, compare destination registry digests with the source manifest, save the plan, and apply that exact reviewed plan. Terraform is not a cryptographic verifier and must never parse an unverified manifest directly.

## Evidence separation

| State | Meaning |
|---|---|
| Implemented | Code and contracts exist in the branch. |
| Locally validated | Offline tests passed against synthetic evidence. |
| CI validated | Required checks passed for the exact PR commit. |
| Live validated | Real protected builder, signer, registry, and destination readback passed. |
| Production | Separately approved production release. |

GUG-124 does not claim live validation. Production remains **NO-GO**.
