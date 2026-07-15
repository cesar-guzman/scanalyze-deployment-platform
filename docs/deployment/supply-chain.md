# Supply-Chain Reference

ADR-032 is authoritative for release eligibility. The complete operational model is in [build-once-supply-chain.md](build-once-supply-chain.md).

## Tools

| Tool | Purpose | Release behavior if unavailable |
|---|---|---|
| Syft | SPDX 2.3 JSON SBOM with `spdxVersion` readback | Fail |
| Trivy | Vulnerability and secret scan evidence | Fail |
| Cosign | Artifact signature and identity verification | Fail |
| Release policy gate | Schema, digest, policy, VSA, waiver, and ECDSA verification | Fail |

Tool name, exact version, and binary digest are part of the signed release and must match the deployment-specific trust policy. Installing a tool is not sufficient evidence.

## Commands

The shell wrappers accept immutable image digests only:

```bash
scripts/supply-chain/generate-sbom.sh IMAGE@sha256:DIGEST /safe/evidence/sbom.json
scripts/supply-chain/scan-image.sh IMAGE@sha256:DIGEST /safe/evidence/scan.json
scripts/supply-chain/sign-image.sh IMAGE@sha256:DIGEST --bundle /safe/evidence/signature.sigstore.json
scripts/supply-chain/verify-image.sh IMAGE@sha256:DIGEST \
  --bundle /safe/evidence/signature.sigstore.json \
  --certificate-identity EXPECTED_WORKFLOW_IDENTITY \
  --certificate-oidc-issuer EXPECTED_OIDC_ISSUER
```

Do not put evidence containing internal registry coordinates, account identifiers, findings, or timestamps into Git, chat, PR text, or Linear. Preserve it in the authorized evidence store and publish only sanitized digests/statuses.

## Planning inventory

`python scripts/supply-chain/release-graph.py --dry-run` is retained for repository reproducibility checks. It returns `eligible_for_promotion=false` and cannot create a release manifest. `--no-dry-run` always fails. Use the central release policy gate for authority.

## Current boundary

GUG-124 implements and locally validates the portable contract. It does not install tools in a privileged workflow, request GitHub OIDC, call AWS, push artifacts, create Terraform plans, or deploy. Those live steps remain GUG-125. Production is **NO-GO**.
