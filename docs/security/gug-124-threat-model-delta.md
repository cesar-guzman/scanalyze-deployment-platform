# GUG-124 Threat-Model Delta: Build Once and Supply Chain

## Assets and trust boundaries

The protected assets are the immutable runtime artifact set, approved runner and base-image set, builder identity, source revision, SBOMs, scan reports, provenance, signature bundles, release trust policy, signed verification summary, last-known-good pointer, deployment projection, and Terraform digest inputs. The primary boundary is between a potentially attacker-influenced build/workflow and the protected release verifier. Secondary boundaries exist between the verifier and registry promotion, promotion and destination readback, and the verified projection and Terraform.

## Threats and controls

| Threat | Control | Failure behavior |
|---|---|---|
| Replace a manifest field after approval | Canonical manifest digest plus signed VSA subject | Deny digest or signature mismatch |
| Substitute the release trust policy together with the release | Out-of-band approved policy digest supplied to the verifier | Deny policy digest mismatch before evaluating release evidence |
| Substitute one artifact or evidence object | Exact ten-artifact inventory and per-artifact subject digests | Deny inventory, subject, or evidence mismatch |
| Use a tag or rebuild per account | Digest-only URI schema and `copy-by-digest`, `rebuild=false` | Deny schema/promotion mode |
| Run on an untrusted builder or tool | Exact source, builder, build type, workflow SHA, runner digest, and tool binary locks | Deny expectation/toolchain mismatch |
| Replace a reviewed base image while retaining an otherwise valid build | Exact service-to-base-image digest map in the trust policy | Deny missing or mismatched base-image binding |
| Claim an SBOM version the configured generator cannot emit | SPDX 2.3 output selection plus generated-document version readback | Deny SBOM generation or format mismatch |
| Accept a compromised or foreign signer | Exact issuer, identity, key ID, public key, and ECDSA P-256 verification | Deny signer/signature |
| Hide a critical vulnerability | Derived finding counts; critical waivers forbidden | Deny critical finding |
| Use a standing or broad waiver | Artifact/finding scope, approved role, bounded expiry, unique active waiver | Deny waiver |
| Treat missing scanner or verifier as success | Strict wrappers and required verifier dependencies | Non-zero, release `NO-GO` |
| Replay partial legacy metadata | v1 and unversioned manifests are migration-required | Deny legacy manifest |
| Alter Terraform image after verification | Projection-only handoff and Terraform `@sha256` validation | Deny Terraform input |
| Roll back by rebuilding old source | Last-known-good signed manifest and new approval | Deny rebuild |

## Residual risk

Local verification cannot prove that a hosted builder was isolated, that a live key remained protected, that registry copies preserved digest identity, or that a saved Terraform plan was applied unchanged. Those are GUG-125 live controls. Compromise of the approved build platform or policy root remains a high-impact trust-anchor risk and requires independent governance, rotation, audit, and two-person policy changes.

## Evidence classification

The committed signing key is a synthetic public verification root with `.invalid` artifact locations. It validates code behavior only. No private key, AWS identity, customer artifact, live scan, or production evidence is committed. CI and live evidence must remain distinct. Production remains **NO-GO**.
