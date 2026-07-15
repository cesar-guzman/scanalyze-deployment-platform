# Build-Once Promotion and Rollback Runbook

## Scope and exclusions

This runbook defines the evidence and decision procedure. GUG-124 does not authorize AWS calls, deployment, registry writes, Terraform plan/apply, production, or release promotion. GUG-125 implements the live executor.

## Promotion preconditions

1. Use a protected release environment and immutable source revision.
2. Resolve the deployment-specific approved policy digest from a protected control-plane root, then retrieve the policy independently and require an exact canonical digest match. Never derive the approved digest from the manifest or policy under evaluation.
3. Confirm all ten artifacts and all evidence objects are available by digest.
4. Run the release policy gate. Preserve the sanitized decision, manifest digest, attestation digest, policy digest, and exact verifier version.
5. Generate a target-specific deployment projection only from an allowed decision.
6. Copy artifacts by digest; never rebuild and never authorize by tag.
7. Read back every destination digest and compare it with the signed manifest.
8. Render Terraform inputs only from the verified projection, save the plan, review it, and apply the exact saved plan.
9. Record target, change ID, source identity, manifest digest, attestation digest, destination readback, and approval. Do not record credentials, URLs with signatures, artifact contents, or customer data.

Any missing step is `NO-GO`.

## Waivers

Critical findings are not waivable. A high-severity waiver must identify one finding and one artifact, use an approved role, include a bounded reason, and expire within the policy maximum. Expired, duplicate, broad, mismatched, or standing waivers fail closed. Changing a waiver changes the manifest digest and requires a new signed VSA.

## Rollback

1. Select the exact last-known-good signed v2 manifest; do not select a branch, tag, or source revision for rebuild.
2. Re-run verification against the current trust and waiver policy.
3. Obtain a new rollback change approval.
4. Produce a fresh deployment projection referencing the original artifact digests.
5. Copy/read back digests and apply a newly reviewed saved Terraform plan.
6. Confirm health and retain the failed and restored evidence chains separately.

If the old manifest cannot pass current verification, stop. An exception requires a separate security decision; rebuilding is a new release, not a rollback.

## Legacy inventory and quarantine

Run inventory in report-only mode. Classify each v1 or unversioned record as fully bound, partially bound, ambiguous, orphaned, or inconsistent. Store the original digest and classification in a restricted evidence location. Normal promotion denies all five classes until a reviewed process produces a new signed v2 manifest. Never infer a missing artifact, account, issuer, subject, base image, SBOM, scan, provenance, signature, or waiver.

## Rollback of this repository change

Revert the GUG-124 commit and restore the prior CI configuration only if no v2 release has been made authoritative. Do not restore the legacy fail-open wrappers for live release use. If a v2 consumer has been activated, first disable live publication and retain v2 manifests/evidence; schema downgrade requires an explicit compatibility review.
