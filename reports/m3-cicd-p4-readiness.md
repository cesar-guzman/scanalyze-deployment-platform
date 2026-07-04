# M3-CICD-P4 Readiness Report

**Date: 2026-07-03T18:20Z**
**Status: READINESS ASSESSMENT — Phase 4 execution NOT approved**
**Scope: Local analysis only. No AWS writes, no terraform apply.**

---

## 1. Executive Summary

This report assesses readiness to enable `enable_codecommit = true` in `roots/cicd`. The current deployed infrastructure has 39 managed resources with CodeCommit, CodeBuild, and CodePipeline disabled. Enabling them would create approximately **28 additional resources** (7 CodeCommit repos, 7 CodeBuild projects, 7 CodePipeline pipelines, 7 CloudWatch log groups).

**Verdict: NOT READY for apply.** 7 of 10 gates are not met yet.

---

## 2. Expected Terraform Diff for `enable_codecommit=true`

### What WOULD change

If we set `enable_codecommit = true` in [cicd.tfvars](file:///Users/cesarguzmanguadarrama/Desktop/bcm-cloud/scanalyze-deployment-platform/environments/cicd.tfvars), the following resources **would be created**:

| Resource Type | Count | Naming Pattern |
|--------------|-------|----------------|
| `aws_codecommit_repository.service` | 7 | `dep_01KWM...-{service-name}` |
| `aws_codebuild_project.build` | 7 | `dep_01KWM...-{service-name}` |
| `aws_codepipeline.this` | 7 | `dep_01KWM...-{service-name}` |
| `aws_cloudwatch_log_group.codebuild` | 7 | `/aws/codebuild/dep_01KWM...-{service-name}` |
| `aws_iam_policy.codepipeline[0]` | 1 | `dep_01KWM...-codepipeline-policy` |
| `aws_iam_role_policy_attachment.codepipeline[0]` | 1 | Attachment to existing role |
| **Total new resources** | **30** | |

### What MUST NOT appear

| Pattern | Status in Code |
|---------|----------------|
| ECS Deploy stage (`Provider = "ECS"`) | ✅ NOT present — [main.tf:527](file:///Users/cesarguzmanguadarrama/Desktop/bcm-cloud/scanalyze-deployment-platform/modules/cicd/main.tf#L527) confirms `# NOTE: NO Deploy stage` |
| CodeDeployToECS (`Provider = "CodeDeployToECS"`) | ✅ NOT present |
| imagedefinitions.json as Deploy input | ✅ NOT present |
| `ecs:*` in IAM policies | ✅ NOT present — CodeBuild policy has NO ecs statement ([main.tf:375](file:///Users/cesarguzmanguadarrama/Desktop/bcm-cloud/scanalyze-deployment-platform/modules/cicd/main.tf#L375)) |
| `iam:PassRole "*"` | ✅ NOT present — no PassRole in any policy |
| CodeDeploy apps/deployment groups | ✅ NOT present |
| ECS service mutation | ✅ NOT present |
| Task definition mutation | ✅ NOT present |

### Existing resources (no change expected)

| Resource Type | Count | Note |
|--------------|-------|------|
| ECR repos | 7 | Already exist |
| ECR lifecycle | 7 | Already exist |
| S3 bucket + config | 5 | Already exist |
| KMS key + alias | 2 | Already exist |
| IAM roles | 2 | Already exist |
| IAM policy (codebuild) | 1 | Already exists |
| IAM attachment (codebuild) | 1 | Already exists |
| SSM parameters | 14 | Already exist, `UNSET` |

---

## 3. CI/CD Safety Proof

Linter: [lint_cicd_safety.py](file:///Users/cesarguzmanguadarrama/Desktop/bcm-cloud/scanalyze-deployment-platform/tooling/lint_cicd_safety.py)

```
Scanned: 3 root(s)
V2 Blockers:         0           ✅
Brownfield Blockers: 8           ℹ️ (ci-cd-micros, informational)
Warnings:            1           ⚠️ CICD-009 in services/variables.tf
```

### V2 Module Analysis

| Rule | Description | Status |
|------|-------------|--------|
| CICD-001 | No `Provider = "ECS"` deploy action | ✅ Clean |
| CICD-002 | No `Provider = "CodeDeployToECS"` | ✅ Clean |
| CICD-003 | No imagedefinitions.json in Deploy stage | ✅ Clean |
| CICD-004 | No `ecs:*` in IAM policies | ✅ Clean |
| CICD-005 | No `iam:PassRole` with Resource `"*"` | ✅ Clean |
| CICD-006 | No hardcoded cluster names | ✅ Clean |
| CICD-007 | No hardcoded CloudFront IDs | ✅ Clean |
| CICD-008 | No hardcoded Cognito IDs | ✅ Clean |
| CICD-009 | Image tag digest in services | ⚠️ Warning at [variables.tf:65](file:///Users/cesarguzmanguadarrama/Desktop/bcm-cloud/scanalyze-deployment-platform/modules/services/variables.tf#L65) — comment says "Must use @sha256 digest" |

### Brownfield Blockers (informational)

These exist in the **original** `ci-cd-micros` module and confirm why v2 was written:

| Rule | File | Issue |
|------|------|-------|
| CICD-004 | ci-cd-micros main.tf:667 | `ecs:*` wildcard in IAM |
| CICD-003 | ci-cd-micros main.tf:841 | imagedefinitions.json as Deploy input |
| CICD-001 | ci-cd-micros main.tf:851 | `Provider = "ECS"` deploy action |
| CICD-003 | ci-cd-micros main.tf:858 | imagedefinitions.json as Deploy input |

These are exactly the patterns Platform v2 eliminates.

---

## 4. CodeCommit Source Strategy

### Repo Naming Convention

From [main.tf:186](file:///Users/cesarguzmanguadarrama/Desktop/bcm-cloud/scanalyze-deployment-platform/modules/cicd/main.tf#L186):

```
{deployment_id}-{service_name}
```

Example repos:
```
dep_01KWM783E0S1FZVAM8FRDV1HR2-ingest-api
dep_01KWM783E0S1FZVAM8FRDV1HR2-ocr-worker
dep_01KWM783E0S1FZVAM8FRDV1HR2-postprocess-worker
dep_01KWM783E0S1FZVAM8FRDV1HR2-classifier-worker
dep_01KWM783E0S1FZVAM8FRDV1HR2-bank-worker
dep_01KWM783E0S1FZVAM8FRDV1HR2-personal-worker
dep_01KWM783E0S1FZVAM8FRDV1HR2-gov-worker
```

### Branch Strategy

Default: `main` (from [variables.tf:39](file:///Users/cesarguzmanguadarrama/Desktop/bcm-cloud/scanalyze-deployment-platform/modules/cicd/variables.tf#L39))

Pipeline trigger: `PollForSourceChanges = "false"` — EventBridge or manual trigger required.

### Push Process

1. Terraform creates empty CodeCommit repos
2. Developer pushes source code from local/GitHub mirror
3. EventBridge (or manual) triggers pipeline on branch change
4. Pipeline executes: Source → Build (no Deploy)

### Credential Helper / SSO Flow

```bash
# AWS SSO credential helper for CodeCommit
git config --global credential.helper '!aws codecommit credential-helper $@'
git config --global credential.UseHttpPath true

# Clone via HTTPS
git clone https://git-codecommit.us-east-1.amazonaws.com/v1/repos/dep_01KWM...-ingest-api
```

### Security Rules

- No credentials in repo
- No `.env`, secrets, or tokens committed
- No push until P4 apply is approved
- CodeCommit repos are initially empty after Terraform creates them

### CodeCommit Classification

```
Type: Sandbox source provider
Status: Transitional unless adopted as final enterprise source provider
Alternative: CodeStar connection (GitHub/Bitbucket) — already supported in module
             (see source.provider / source.connection_arn in variables.tf)
```

---

## 5. Release Metadata Contract

### Current SSM Parameters (deployed, all UNSET)

From [main.tf:537-558](file:///Users/cesarguzmanguadarrama/Desktop/bcm-cloud/scanalyze-deployment-platform/modules/cicd/main.tf#L537-L558):

| Parameter Path | Type | Current Value | Written By |
|----------------|------|---------------|------------|
| `/{dep_id}/cicd/images/{svc}/image_tag` | String | `UNSET` | CodeBuild (post-build) |
| `/{dep_id}/cicd/images/{svc}/image_digest` | String | `UNSET` | CodeBuild (post-build) |

### Proposed Full Release Metadata Contract

After a successful build, CodeBuild MUST write:

| Field | SSM Parameter | Source |
|-------|---------------|--------|
| `image_digest` | `/{dep_id}/cicd/images/{svc}/image_digest` | `sha256:...` from ECR push |
| `image_tag` | `/{dep_id}/cicd/images/{svc}/image_tag` | Git commit SHA or semantic version |
| `source_revision` | `/{dep_id}/cicd/images/{svc}/source_revision` | Git commit hash |
| `build_id` | `/{dep_id}/cicd/images/{svc}/build_id` | CodeBuild build ID |
| `build_timestamp` | `/{dep_id}/cicd/images/{svc}/build_timestamp` | ISO 8601 timestamp |
| `ecr_image_uri` | `/{dep_id}/cicd/images/{svc}/ecr_image_uri` | `{account}.dkr.ecr.{region}.amazonaws.com/{repo}@sha256:...` |
| `scanner_status` | `/{dep_id}/cicd/images/{svc}/scanner_status` | Placeholder: `NOT_IMPLEMENTED` |

> **Note:** Currently only `image_tag` and `image_digest` have Terraform SSM resources.
> The additional parameters (`source_revision`, `build_id`, `build_timestamp`, `ecr_image_uri`, `scanner_status`)
> should be added to the module before P4 apply if adopted, or can be written directly by
> the buildspec using the `ReleaseMetadataSSM` IAM permission (already scoped to `/{dep_id}/cicd/images/*`).

### How Services Layer Consumes

Terraform `roots/services` reads approved digests from SSM (not raw `latest` tag, not `imagedefinitions.json`):

```hcl
# services module expects digest-pinned image reference
service_definitions = [
  {
    name  = "ingest-api"
    image = "${ecr_url}@${data.aws_ssm_parameter.ingest_api_digest.value}"
    ...
  }
]
```

### What is NOT acceptable

| Pattern | Reason |
|---------|--------|
| `imagedefinitions.json` as ECS deploy artifact | Bypasses Terraform, triggers implicit `register-task-definition` |
| `:latest` tag in services layer | Mutable, non-reproducible |
| Raw tag without digest | Tag could be overwritten (though IMMUTABLE ECR prevents this) |
| CodeBuild directly calling `aws ecs update-service` | Violates Terraform ownership of ECS |

---

## 6. Proposed Plan Command

> **Do NOT execute.** This is the command that would be used when P4 readiness gates are met.

```bash
# Step 1: Update tfvars
# In environments/cicd.tfvars, change:
#   enable_codecommit = true

# Step 2: Run plan (read-only)
terraform -chdir=roots/cicd plan \
  -var-file=../../environments/cicd.tfvars \
  -no-color \
  -input=false
```

Expected output should show:
- ~30 resources to create (CodeCommit, CodeBuild, CodePipeline, CW log groups, pipeline policy+attachment)
- 0 resources to change
- 0 resources to destroy
- No ECS-related resources

---

## 7. Rollback Plan for Enabling CodeCommit

### Pre-conditions for rollback

- Pipeline has NOT been triggered (no builds executed)
- CodeCommit repos are empty (no pushes)
- No images built by pipeline

### Rollback procedure

```bash
# 1. Set enable_codecommit = false in cicd.tfvars

# 2. Plan
terraform -chdir=roots/cicd plan \
  -var-file=../../environments/cicd.tfvars \
  -no-color -input=false
# Expected: ~30 resources to destroy

# 3. Apply (requires PM approval)
terraform -chdir=roots/cicd apply \
  -var-file=../../environments/cicd.tfvars \
  -auto-approve
```

### Rollback with content

If CodeCommit repos have branches/commits:
- Must decide: preserve source in external mirror or accept data loss
- CodeCommit repos with content cannot be cleanly destroyed without acknowledgment

If artifact bucket has pipeline artifacts:
- Lifecycle policy expires after 30 days
- Manual cleanup: `aws s3 rm s3://{bucket}/ --recursive` (requires approval)

If log groups have logs:
- Retention is 14 days
- Can be deleted manually with Destroy role

If images exist in ECR:
- ECR repos are NOT gated by `enable_codecommit` (they always exist)
- Images persist regardless of pipeline state

### State considerations

- State is remote S3 — no state file manipulation needed
- `terraform destroy` for gated resources only (no `state rm` needed)
- Rollback is `enable_codecommit = false` + apply

---

## 8. Phase 4 Readiness Gates

| # | Gate | Status | Evidence |
|---|------|--------|----------|
| 1 | R1 orphan cleanup | ✅ Done | 7/7 deleted, 0 remaining |
| 2 | R2 state migration to S3 | ✅ Done | 41 resources, No changes |
| 3 | R3 governance closure | ✅ Done | Commit `d5b6b79` |
| 4 | Permission Set least-privilege proposal | ⏳ See [proposal](file:///Users/cesarguzmanguadarrama/Desktop/bcm-cloud/scanalyze-deployment-platform/reports/m3-cicd-p4-permission-set-proposal.md) | Ready for review |
| 5 | `enable_codecommit=true` plan reviewed | ❌ Plan not yet executed | Diff expectation documented above |
| 6 | No ECS Deploy stage proof | ✅ Proven | Linter CICD-001 = 0 v2 findings |
| 7 | No `iam:PassRole "*"` proof | ✅ Proven | Linter CICD-005 = 0 v2 findings |
| 8 | No `ecs:*` proof | ✅ Proven | Linter CICD-004 = 0 v2 findings |
| 9 | No CodeDeploy resources proof | ✅ Proven | No `codedeploy` in v2 module |
| 10 | Rollback plan approved | ⏳ Proposed | See section 7 above |
| 11 | State backend no changes | ✅ Verified | `terraform plan` = No changes |
| 12 | PM approval for apply | ❌ Not requested | Pending gates 4, 5, 10 |

**Current: 7/12 gates met.**

---

## 9. Outstanding Items Before P4 Apply

| Item | Blocker? | Action Required |
|------|----------|-----------------|
| Permission Set update for CodeCommit/Build/Pipeline | Yes | PM must approve IAM delta |
| `terraform plan` with `enable_codecommit=true` | Yes | Must be executed and reviewed |
| Buildspec creation | Yes | No buildspec exists yet; must be created and reviewed before build can succeed |
| Rollback plan approval | Yes | PM must accept rollback plan |
| PM explicit approval for apply | Yes | Final gate |
| Release metadata expansion (optional) | No | Additional SSM params can be added in buildspec |
| CICD-009 warning resolution (optional) | No | Services layer already expects digest; comment is correct |

---

## 10. Files Produced

| File | Purpose |
|------|---------|
| `reports/m3-cicd-p4-readiness.md` | This report |
| `reports/m3-cicd-p4-permission-set-proposal.md` | IAM least-privilege proposal |
| `reports/m3-cicd-p4-safety-gates.md` | Safety gates with linter results |
| `reports/m3-cicd-p4-buildspec-review.md` | Buildspec review and template |
| `reports/discrepancy-register.md` | Updated with P4 gates |
