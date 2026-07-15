# ADR-032: Build Once and Supply Chain Fail-Closed

- **Status**: Accepted
- **Date**: 2026-07-14
- **Decision owners**: Platform Engineering, Security Engineering, Release Engineering
- **Linear**: GUG-124, GUG-117
- **Supersedes**: the fail-open behavior in ADR-016
- **Amends**: ADR-007 and ADR-019

## Context

Scanalyze had several release descriptions but no single enforceable release authority. The legacy supply-chain scripts returned success when `syft`, `trivy`, or `cosign` was missing; the signature wrapper could also return zero after a failed `cosign verify`. Release v1 accepted partial artifact inventories, mutable image URIs, opaque signature strings, weak waivers, and evidence references that were not cryptographically bound to the manifest. A deployment consumer could therefore receive a syntactically valid digest without proof that all runtime artifacts came from one reviewed build.

This is incompatible with build-once/promote-many. Promotion must copy one verified artifact set into any customer account without rebuilding or silently replacing evidence.

## Decision

The release authority is the following exact chain:

1. `release.v2` contains all ten runtime artifacts: seven OCI services, two identity Lambda archives, and the frontend archive.
2. Every artifact has one immutable digest and digest-bound SBOM, vulnerability scan, SLSA provenance, and signature bundle.
3. The manifest binds the immutable source revision, workflow revision, builder identity, runner digest, tool binary digests, base image digests, trust-policy digest, last-known-good release, and `copy-by-digest` promotion mode.
4. A signed in-toto Verification Summary Attestation binds the canonical manifest digest, exact evidence set, exact artifact subjects, policy, verifier, SLSA level, issuer, identity, and P-256 public key.
5. `tooling/release_policy_gate.py` is the only component allowed to convert the signed release into `release-deployment-projection.v1`.
6. Terraform and runtime consumers receive only the verified projection. OCI images remain `@sha256` references. Archive locators remain content-addressed. A tag, inferred digest, v1 manifest, partial record, or caller-supplied replacement is never authority.

The canonical Scanalyze JSON profile permits only JSON strings, booleans, integers, arrays, objects, and null; forbids floating-point values; encodes UTF-8 without ASCII substitution; sorts keys; and removes insignificant whitespace. The manifest digest omits only its own `release_manifest_digest` field. The policy digest includes the complete policy and must equal an externally approved, deployment-specific trust root that is never derived from the candidate manifest or policy. The attestation signature covers the complete statement.

## Policy invariants

- Missing schemas, verifier libraries, tools, artifacts, evidence, trust roots, or required fields fail closed.
- Builder, build type, source repository/ref, immutable workflow SHA, runner image, service base images, and tool binary digests must match the trust policy exactly.
- Artifact URIs and base images must bind the claimed SHA-256 digest.
- SBOM uses SPDX 2.3 JSON, the newest SPDX JSON version supported by the pinned Syft generator. Provenance uses the SLSA v1 predicate. Verification follows the SLSA 1.2 expectation model.
- Evidence subjects must equal their artifact digest and evidence digests cannot be reused across artifacts.
- Scan counts must equal the finding inventory. Critical findings always deny promotion. High findings require an unexpired, finding-specific, artifact-specific waiver from an approved role.
- Signature issuer, identity, key ID, public key, VSA subject, policy, verifier, evidence inputs, and artifact subjects must all match before ECDSA verification can pass.
- Promotion and rollback copy the signed digest set. Neither operation rebuilds.
- Verification output is sanitized and never contains artifact payloads, tokens, credentials, presigned URLs, Terraform state, or customer data.

## Portability and trust roots

The schemas and policy engine are account- and region-independent. Deployment-specific repository locations, accounts, regions, and trust roots are injected by the protected control plane, not hardcoded in product source. The committed fixture uses `.invalid` endpoints, zero-like synthetic digests, and a synthetic public key. It proves verifier behavior only and is never a live trust root.

GitHub Actions remains unprivileged in GUG-124. The existing publication job remains terminal `NO-GO`; GUG-125 is responsible for protected environments, OIDC, live evidence generation, destination digest readback, saved Terraform plans, and authorized promotion into two non-production accounts.

## Legacy decision

Release v1 records are migration-required and denied in normal paths. They are classified as:

- **Fully bound**: complete immutable artifact/evidence records that may be reviewed and re-attested.
- **Partially bound**: one or more evidence or ownership bindings missing; quarantine.
- **Ambiguous**: multiple artifacts or trust roots could satisfy a field; quarantine.
- **Orphaned**: the artifact or evidence cannot be resolved; deny.
- **Inconsistent**: digests, subjects, builders, or signer identities conflict; deny and investigate.

No field is inferred and no existing record is automatically migrated, deleted, resigned, or promoted. Reviewed migration must be report-only first, preserve original evidence, produce a new v2 manifest, and require a new approval.

## Rollback

Rollback selects the previous signed `release.v2` manifest recorded as last-known-good, re-runs the complete policy gate at the rollback decision time, produces a new target-specific projection and approval record, and copies the original digests. Missing or expired evidence blocks rollback; rebuilding the previous source is not rollback.

## Consequences

Release preparation is intentionally blocked when evidence tooling is unavailable or incomplete. This adds build latency and requires managed trust-policy rotation, but it removes silent partial success and makes the same artifact set portable across customer accounts.

## Evidence classification

- **Implemented**: schemas, central verifier, strict wrappers, digest-only builder input, CI gate, synthetic signed release, Terraform validation, documentation.
- **Locally validated**: schema, policy, signature, negative, projection, builder, and repository tests.
- **CI validated**: pending PR checks.
- **Live validated**: no.
- **Blocked**: live build, registry copy, AWS signature verification, two-account promotion, and saved-plan deployment belong to GUG-125.
- **Production**: **NO-GO**.

## References

- [SLSA 1.2](https://slsa.dev/spec/v1.2/)
- [SLSA artifact verification expectations](https://slsa.dev/spec/v1.2/verifying-artifacts)
- [Sigstore signature verification](https://docs.sigstore.dev/cosign/verifying/verify/)
- [Syft output formats and supported SPDX versions](https://oss.anchore.com/docs/guides/sbom/formats/)
