# Root: cicd
# Layer: release-support side layer (after data-foundation, before services)
# Scope: regional
# State: {deployment_id}/{region}/cicd/terraform.tfstate
#
# Customer-local ECR/release metadata and optional legacy build-only pipelines.
# Terraform owns ECS. GitHub Actions may build/push images but never deploy ECS.

## Deployment Order

```
1. account-ready-gate
2. global
3. network
4. platform
5. data-foundation
6. cicd              ← this root provisions customer-local ECR/metadata
7. approved artifact publication and release manifest
8. services
9. edge-identity
10. edge
11. addons
12. synthetic validation and operational handoff
```

This is the dependency-correct target order. Production publication remains
NO-GO until the signed release manifest, SBOM/signature/provenance gates and
non-production validation documented in the enterprise deployment guide are
implemented. The current build script is a controlled non-production bootstrap,
not evidence of a complete production supply chain.

## GitHub monorepo transition

Use `environments/cicd.github-monorepo.tfvars.example` as the reviewed first
stage after the deployment's base tfvars: disable CodeBuild/CodePipeline while
preserving the existing CodeCommit, ECR, and SSM choices.

If CodeCommit is currently enabled, disable it only after explicit source
retention/export approval and in a separate plan. Never combine this transition
with state manipulation or an unreviewed production apply.

The AWS provider uses `allowed_account_ids = [var.account_id]`; a caller for a
different account is rejected before Terraform can manage this root.
