# Scanalyze Platform v2 — Discrepancy Register

**Last Updated: 2026-07-03T18:24Z**

This register tracks known gaps between current sandbox state and target enterprise architecture.

---

## Active Discrepancies

| ID | Severity | Area | Description | Resolution Path | Owner |
|----|----------|------|-------------|-----------------|-------|
| D-CICD-STATE-001 | Medium | State Backend | DynamoDB lock table is deprecated in Terraform S3 backend. Current sandbox uses `dynamodb_table` for locking. | Evaluate `use_lockfile = true` (S3 lockfile) for Terraform >= 1.14. Enterprise accounts should use S3 lockfile unless compatibility requires DynamoDB. | Platform |
| D-CICD-BOOTSTRAP-001 | Medium | Bootstrap | Sandbox state backend was created via AWS CLI, not CloudFormation. Not repeatable via StackSets. | Replace with AccountVendingProvider / baseline CFN path before enterprise onboarding. | Platform + Org |
| D-CICD-CFN-001 | Low | Permissions | Neither `ScanalyzeSandboxDeploy` nor `ScanalyzeSandboxDestroy` has `cloudformation:CreateStack`. | Enterprise: use scoped baseline role; Sandbox: accepted as CLI fallback. Do NOT grant broad `cloudformation:*`. | Security |
| D-CICD-BUILDSPEC-001 | Low | Build | No buildspec exists in repo. CodeBuild projects reference `buildspec.yml` but the file must be in CodeCommit source. | Template proposed in `reports/m3-cicd-p4-buildspec-review.md`. Must be pushed to CodeCommit after P4 apply. | Platform |
| D-CICD-PERMS-001 | Medium | Permissions | Permission Set lacks CodeCommit/CodeBuild/CodePipeline permissions. Cannot apply `enable_codecommit=true`. | Proposal in `reports/m3-cicd-p4-permission-set-proposal.md`. Must include explicit Deny for ECS/CodeDeploy. | Security |
| D-CICD-LOGS-001 | Closed | Cleanup | 7 orphan CW log groups outside Terraform state. | **RESOLVED** — R1 cleanup deleted all 7 on 2026-07-03. | N/A |
| D-CICD-PAR-001 | Closed | Governance | Post-apply reconciliation required honest accounting of all AWS writes. | **RESOLVED** — PAR report accepted 2026-07-03. | N/A |

---

## Acceptance Gates

### Gate: M3-CICD-P4 — Enable CodeCommit + Build Pipelines

**Status: 7/12 MET — pending operational gates**

| # | Gate | Status | Evidence |
|---|------|--------|----------|
| 1 | R1 orphan cleanup | ✅ Done | 7/7 deleted, 0 remaining |
| 2 | R2 state migration to S3 | ✅ Done | 41 resources, No changes |
| 3 | R3 governance closure | ✅ Done | Commit `d5b6b79` |
| 4 | Permission Set least-privilege proposal | ⏳ Proposed | `reports/m3-cicd-p4-permission-set-proposal.md` |
| 5 | `enable_codecommit=true` plan reviewed | ❌ Not executed | Diff expectation documented in readiness report |
| 6 | No ECS Deploy stage proof | ✅ Proven | Linter CICD-001 = 0 v2 findings |
| 7 | No `iam:PassRole "*"` proof | ✅ Proven | Linter CICD-005 = 0 v2 findings |
| 8 | No `ecs:*` proof | ✅ Proven | Linter CICD-004 = 0 v2 findings |
| 9 | No CodeDeploy resources proof | ✅ Proven | No codedeploy in v2 module |
| 10 | Buildspec review (build-only) | ✅ Proven | Template reviewed, no deploy patterns |
| 11 | Rollback plan for P4 | ⏳ Proposed | In `reports/m3-cicd-p4-readiness.md` §7 |
| 12 | PM approval for apply | ❌ Not requested | Pending gates 4, 5, 11 |

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
| 2026-07-03 18:24Z | D-CICD-PERMS-001 | Registered: Permission Set gap for CodeCommit/Build/Pipeline |
| 2026-07-03 18:24Z | D-CICD-BUILDSPEC-001 | Registered: No buildspec exists; template proposed |
| 2026-07-03 18:24Z | P4 gates 6-10 | Updated: proven by linter and code analysis |
| 2026-07-03 18:12Z | D-CICD-LOGS-001 | R1: Deleted 7 orphan CW log groups (storedBytes=0) |
| 2026-07-03 18:12Z | D-CICD-PAR-001 | PAR report accepted by PM |
| 2026-07-03 18:12Z | D-CICD-STATE-001 | Registered: DynamoDB lock deprecation |
| 2026-07-03 18:12Z | D-CICD-BOOTSTRAP-001 | Registered: AWS CLI bootstrap as sandbox exception |
| 2026-07-03 18:12Z | D-CICD-CFN-001 | Registered: CloudFormation permission gap |

