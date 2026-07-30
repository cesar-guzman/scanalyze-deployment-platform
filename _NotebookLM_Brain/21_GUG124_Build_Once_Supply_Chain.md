# GUG-124 — Build Once and Supply Chain Fail-Closed

## Executive source

GUG-124 replaces partial, status-only release descriptions with a cryptographically verifiable release authority. One release contains seven OCI services, two identity Lambda archives, and the frontend archive. Each artifact is immutable and carries an SBOM, vulnerability scan, SLSA provenance, and signature bundle bound to its digest.

The central policy gate verifies schemas, the canonical manifest digest, an externally approved deployment-specific policy digest, trusted source and builder expectations, pinned runner/base/toolchain identities, evidence subjects, vulnerability/waiver policy, VSA coverage, exact OIDC issuer and workflow identity, and an ECDSA P-256 signature. Only an allowed decision can produce the digest-only deployment projection consumed by Terraform.

Legacy v1 records are denied and classified for reviewed migration; missing tools or evidence are release failures. Promotion and rollback copy the same signed digest set without rebuilding. The synthetic repository fixture proves local verification only. It contains no live account, key, token, customer data, or production evidence.

## Handoff

GUG-125 must connect this contract to the protected GitHub/AWS execution chain, generate live evidence, copy by digest into two authorized non-production accounts, verify destination digests, create saved Terraform plans, apply only reviewed plans, test rollback, and clean up. Until that validation is complete, production status is **NO-GO**.
