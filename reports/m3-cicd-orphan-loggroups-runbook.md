# M3-CICD Orphan Log Groups Runbook

**Status: PREPARED — NOT EXECUTED**
**Date: 2026-07-03**
**Requires: PM approval before execution**

---

## Context

During the first `terraform apply` of `roots/cicd` (attempt 1), 7 CloudWatch Log Groups were created successfully. However, the apply failed partially (ECR names, CodeCommit permissions). After fixing the module to disable CodeCommit (`enable_codecommit = false`), these log groups became unmanaged because the `aws_cloudwatch_log_group.codebuild` resource is conditioned on `enable_codecommit`.

The log groups were removed from state with `terraform state rm` to allow convergence. They now exist in AWS but are not managed by Terraform.

## Orphan Inventory

| # | Log Group Name | Bytes | Retention |
|---|---------------|-------|-----------|
| 1 | `/aws/codebuild/dep_01KWM783E0S1FZVAM8FRDV1HR2-bank-worker` | 0 | 14d |
| 2 | `/aws/codebuild/dep_01KWM783E0S1FZVAM8FRDV1HR2-classifier-worker` | 0 | 14d |
| 3 | `/aws/codebuild/dep_01KWM783E0S1FZVAM8FRDV1HR2-gov-worker` | 0 | 14d |
| 4 | `/aws/codebuild/dep_01KWM783E0S1FZVAM8FRDV1HR2-ingest-api` | 0 | 14d |
| 5 | `/aws/codebuild/dep_01KWM783E0S1FZVAM8FRDV1HR2-ocr-worker` | 0 | 14d |
| 6 | `/aws/codebuild/dep_01KWM783E0S1FZVAM8FRDV1HR2-personal-worker` | 0 | 14d |
| 7 | `/aws/codebuild/dep_01KWM783E0S1FZVAM8FRDV1HR2-postprocess-worker` | 0 | 14d |

---

## Option A: Import and Manage (RECOMMENDED)

**When**: When `enable_codecommit` is set to `true` (requires permission set update).

**Rationale**: These log groups are the correct names for CodeBuild projects that will be created when pipelines are enabled. Importing them avoids recreating and lets Terraform manage them declaratively.

### Pre-conditions
- `enable_codecommit = true` in `environments/cicd.tfvars`
- Permission set includes `logs:*` and `codecommit:*`

### Steps

```bash
# 1. Update tfvars
# enable_codecommit = true

# 2. Import each log group
SERVICES="bank-worker classifier-worker gov-worker ingest-api ocr-worker personal-worker postprocess-worker"
DEP_ID="dep_01KWM783E0S1FZVAM8FRDV1HR2"

for svc in $SERVICES; do
  terraform import \
    -var-file=../../environments/cicd.tfvars \
    "module.cicd.aws_cloudwatch_log_group.codebuild[\"$svc\"]" \
    "/aws/codebuild/${DEP_ID}-${svc}"
done

# 3. Verify
terraform plan -var-file=../../environments/cicd.tfvars -no-color
# Expected: changes only for NEW resources (CodeBuild, CodeCommit, CodePipeline)
# Log groups should show as "no changes" (already imported)
```

### Post-verification
```bash
terraform state list | grep cloudwatch
# Should show 7 entries

terraform plan | grep "log_group"
# Should show no changes for log groups
```

---

## Option B: Exact Cleanup (DELETE)

**When**: If the decision is to keep `enable_codecommit = false` permanently and these log groups are pure residue.

**Rationale**: 0 bytes stored, no data loss. These are empty containers from a failed apply.

### Pre-conditions
- PM explicit approval for cleanup write
- Permission set includes `logs:DeleteLogGroup`
- Confirm no other system is writing to these log groups

### Steps

```bash
# 1. Verify still empty (pre-check)
SERVICES="bank-worker classifier-worker gov-worker ingest-api ocr-worker personal-worker postprocess-worker"
DEP_ID="dep_01KWM783E0S1FZVAM8FRDV1HR2"

for svc in $SERVICES; do
  echo "=== $svc ==="
  aws logs describe-log-groups \
    --log-group-name-prefix "/aws/codebuild/${DEP_ID}-${svc}" \
    --query "logGroups[0].{Name:logGroupName,Bytes:storedBytes}" \
    --output table
done

# 2. Delete each (only if storedBytes = 0)
for svc in $SERVICES; do
  aws logs delete-log-group \
    --log-group-name "/aws/codebuild/${DEP_ID}-${svc}" \
    --region us-east-1
  echo "Deleted: /aws/codebuild/${DEP_ID}-${svc}"
done

# 3. Post-verify
aws logs describe-log-groups \
  --log-group-name-prefix "/aws/codebuild/${DEP_ID}" \
  --query "logGroups[].logGroupName" \
  --output json
# Expected: []
```

### Post-verification
```bash
# Confirm terraform plan still clean
cd roots/cicd
terraform plan -var-file=../../environments/cicd.tfvars
# Expected: No changes (log groups not in config when enable_codecommit=false)
```

---

## Recommendation

**Option A (import)** is preferred because:
1. These log groups will be needed when CodeBuild projects are enabled
2. Importing is non-destructive
3. It avoids the naming collision risk if Terraform tries to create them later
4. The 14-day retention is already correct

**Option B (delete)** is acceptable only if:
1. The permission set will never get `codecommit:*`
2. CI/CD will use a completely different approach (e.g., GitHub Actions)
3. PM confirms these are pure waste
