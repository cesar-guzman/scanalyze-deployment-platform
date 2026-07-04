# Scanalyze Platform v2 — Discrepancy Register

**Last Updated: 2026-07-03T18:12Z**

This register tracks known gaps between current sandbox state and target enterprise architecture.

---

## Active Discrepancies

| ID | Severity | Area | Description | Resolution Path | Owner |
|----|----------|------|-------------|-----------------|-------|
| D-CICD-STATE-001 | Medium | State Backend | DynamoDB lock table is deprecated in Terraform S3 backend. Current sandbox uses `dynamodb_table` for locking. | Evaluate `use_lockfile = true` (S3 lockfile) for Terraform >= 1.14. Enterprise accounts should use S3 lockfile unless compatibility requires DynamoDB. | Platform |
| D-CICD-BOOTSTRAP-001 | Medium | Bootstrap | Sandbox state backend was created via AWS CLI, not CloudFormation. Not repeatable via StackSets. | Replace with AccountVendingProvider / baseline CFN path before enterprise onboarding. | Platform + Org |
| D-CICD-CFN-001 | Low | Permissions | Neither `ScanalyzeSandboxDeploy` nor `ScanalyzeSandboxDestroy` has `cloudformation:CreateStack`. | Enterprise: use scoped baseline role; Sandbox: accepted as CLI fallback. Do NOT grant broad `cloudformation:*`. | Security |
| D-CICD-LOGS-001 | Closed | Cleanup | 7 orphan CW log groups outside Terraform state. | **RESOLVED** — R1 cleanup deleted all 7 on 2026-07-03. | N/A |
| D-CICD-PAR-001 | Closed | Governance | Post-apply reconciliation required honest accounting of all AWS writes. | **RESOLVED** — PAR report accepted 2026-07-03. | N/A |

---

## Acceptance Gates

### Gate: M3-CICD-P4 — Enable CodeCommit + Build Pipelines

**Status: NOT READY**

Before approving Phase 4, the following must be true:

| # | Gate | Status |
|---|------|--------|
| 1 | R1 orphan cleanup | ✅ Done |
| 2 | R2 state migration to S3 | ✅ Done |
| 3 | R3 governance closure | ✅ Done (this commit) |
| 4 | Permission Set least-privilege proposal | ❌ Not started |
| 5 | `enable_codecommit=true` plan reviewed | ❌ Not started |
| 6 | No ECS Deploy stage in plan | ❌ Not verified |
| 7 | No `iam:PassRole "*"` in plan | ❌ Not verified |
| 8 | No `ecs:*` in plan | ❌ Not verified |
| 9 | CodeBuild terminates at digest-to-SSM | ❌ Not verified |
| 10 | Rollback plan for P4 | ❌ Not prepared |

### Gate: Enterprise Readiness

**Status: NOT READY**

| # | Gate | Status |
|---|------|--------|
| 1 | D-CICD-BOOTSTRAP-001 resolved (CFN baseline) | ❌ |
| 2 | D-CICD-STATE-001 resolved (locking decision) | ❌ |
| 3 | D-CICD-CFN-001 resolved (permission scoping) | ❌ |
| 4 | All Terraform layers on remote state | ❌ (only cicd migrated) |
| 5 | Enterprise playbook tested on second account | ❌ |

---

## Resolution History

| Date | ID | Action |
|------|----|--------|
| 2026-07-03 | D-CICD-LOGS-001 | R1: Deleted 7 orphan CW log groups (storedBytes=0) |
| 2026-07-03 | D-CICD-PAR-001 | PAR report accepted by PM |
| 2026-07-03 | D-CICD-STATE-001 | Registered: DynamoDB lock deprecation |
| 2026-07-03 | D-CICD-BOOTSTRAP-001 | Registered: AWS CLI bootstrap as sandbox exception |
| 2026-07-03 | D-CICD-CFN-001 | Registered: CloudFormation permission gap |
