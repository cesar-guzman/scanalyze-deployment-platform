# M3-CICD Destroy Runbook

**Status: PREPARED — NOT EXECUTED**
**Date: 2026-07-03 (updated 2026-07-03T18:12Z)**
**Requires: PM approval before execution**
**State: Remote S3 backend (post R2 migration)**

---

## Purpose

Complete rollback of the `roots/cicd` layer. Destroys all resources created by the cicd Terraform root and cleans up orphan resources.

## Pre-conditions

- [ ] PM explicit approval for destroy
- [ ] Permission set includes: `ecr:*`, `s3:*`, `kms:*`, `iam:*`, `ssm:*`, `logs:*`, `codebuild:*`, `codepipeline:*`
- [ ] No images exist in ECR repos (or force delete is acceptable)
- [ ] No objects exist in S3 artifact bucket (or force delete is acceptable)
- [ ] No other layer depends on SSM parameters from cicd
- [ ] Remote state in S3 is accessible (`terraform state list` works)
- [ ] `backend.tfvars` exists in `roots/cicd/` for S3 backend config

## Resources That Will Be Destroyed

### From Terraform State (39 managed)

| Resource Type | Count | Names |
|--------------|-------|-------|
| ECR repos | 7 | `dep-01kwm.../scanalyze/{service}` |
| ECR lifecycle | 7 | Same repos |
| S3 bucket | 1 | `dep-01kwm...-cicd-artifacts` |
| S3 config | 4 | versioning, encryption, lifecycle, PAB |
| KMS key | 1 | `alias/dep_01KWM...-cicd-artifacts` |
| KMS alias | 1 | Same |
| IAM roles | 2 | codepipeline-role, codebuild-role |
| IAM policies | 1 | codebuild-policy |
| IAM attachments | 1 | codebuild |
| SSM params | 14 | `/dep.../cicd/images/{service}/{type}` |

### Orphan Resources — CLEANED (R1 2026-07-03)

~~7 CloudWatch log groups~~ — **Deleted** in M3-CICD-R1.
No remaining orphan resources.

---

## Destroy Procedure

### Step 1: Handle ECR Repos with Images

```bash
# Check if any repo has images
SERVICES="bank-worker classifier-worker gov-worker ingest-api ocr-worker personal-worker postprocess-worker"
DEP_ID="dep-01kwm783e0s1fzvam8frdv1hr2"

for svc in $SERVICES; do
  COUNT=$(aws ecr list-images \
    --repository-name "${DEP_ID}/scanalyze/${svc}" \
    --query "length(imageIds)" \
    --output text 2>/dev/null)
  echo "${svc}: ${COUNT:-0} images"
done

# If any repo has images, you MUST delete them first (ECR IMMUTABLE prevents tag overwrite but allows image deletion)
# Or use --force flag on ecr delete-repository
```

### Step 2: Handle S3 Bucket with Objects

```bash
# Check if bucket has objects
aws s3 ls s3://dep-01kwm783e0s1fzvam8frdv1hr2-cicd-artifacts/ --recursive --summarize | tail -2

# If objects exist, empty the bucket first:
# aws s3 rm s3://dep-01kwm783e0s1fzvam8frdv1hr2-cicd-artifacts/ --recursive
# WARNING: This deletes all artifacts permanently
```

### Step 3: Handle KMS Key

```bash
# KMS keys cannot be deleted immediately.
# Terraform will schedule deletion with a waiting period (default 30 days).
# The key will be in "PendingDeletion" state.
# During this period, encrypted S3 objects become inaccessible.
#
# To cancel scheduled deletion:
# aws kms cancel-key-deletion --key-id <key-id>
# aws kms enable-key --key-id <key-id>
```

### Step 4: Terraform Destroy

```bash
cd roots/cicd

# Ensure remote backend is configured
terraform init -backend-config=backend.tfvars

# Dry run — review what will be destroyed
terraform plan -destroy \
  -var-file=../../environments/cicd.tfvars \
  -no-color

# Execute destroy (requires PM approval)
terraform destroy \
  -var-file=../../environments/cicd.tfvars \
  -auto-approve
```

### Step 5: Clean Orphan Log Groups

> **ALREADY DONE** — M3-CICD-R1 cleaned all 7 orphan log groups on 2026-07-03.
> This step is retained for reference in case orphans appear in future applies.

```bash
# Verify no orphans exist
aws logs describe-log-groups \
  --log-group-name-prefix "/aws/codebuild/dep_01KWM783E0S1FZVAM8FRDV1HR2" \
  --query "length(logGroups)" --output text
# Expected: 0
```

### Step 6: Verify Post-Destroy

```bash
# 1. No ECR repos
aws ecr describe-repositories --query "repositories[].repositoryName" --output json
# Expected: [] (or only repos from other layers)

# 2. No S3 bucket
aws s3api head-bucket --bucket dep-01kwm783e0s1fzvam8frdv1hr2-cicd-artifacts 2>&1
# Expected: 404

# 3. KMS key pending deletion
aws kms describe-key --key-id alias/dep_01KWM783E0S1FZVAM8FRDV1HR2-cicd-artifacts 2>&1
# Expected: PendingDeletion OR NotFoundException

# 4. No SSM params
aws ssm get-parameters-by-path \
  --path "/dep_01KWM783E0S1FZVAM8FRDV1HR2/cicd" \
  --recursive --query "length(Parameters)" --output text
# Expected: 0

# 5. No IAM roles
aws iam get-role --role-name dep_01KWM783E0S1FZVAM8FRDV1HR2-codepipeline-role 2>&1
aws iam get-role --role-name dep_01KWM783E0S1FZVAM8FRDV1HR2-codebuild-role 2>&1
# Expected: NoSuchEntity

# 6. No CW log groups
aws logs describe-log-groups \
  --log-group-name-prefix "/aws/codebuild/dep_01KWM783E0S1FZVAM8FRDV1HR2" \
  --query "length(logGroups)" --output text
# Expected: 0

# 7. Terraform state is empty (remote)
terraform state list
# Expected: empty or error (no state)

# 8. State in S3 is empty/gone
aws s3 ls s3://scanalyze-dep-01kwm783e0s1fzvam8frdv1hr2-tf-state/dep_01KWM783E0S1FZVAM8FRDV1HR2/us-east-1/cicd/
# Expected: empty or no output
```

### Step 7: Clean State Artifacts

```bash
# Local state is already empty (migrated to S3).
# Remote state will be empty after destroy.
# Optionally remove local backend config:
rm -f roots/cicd/backend.tfvars
# NOTE: Do NOT delete the S3 state bucket — it serves all layers.
```

---

## Rollback of Destroy

If destroy was premature and resources need to be recreated:

```bash
# Re-apply from the same commit
cd roots/cicd
terraform init -backend-config=backend.tfvars
terraform apply -var-file=../../environments/cicd.tfvars

# NOTE: KMS key scheduled for deletion cannot be reused.
# A new key will be created with a new KeyId.
# The old alias will be reassigned to the new key.
#
# NOTE: State is remote. If S3 backend still exists, state
# history (versioned) is available for forensics.
```

## Risk Assessment

| Risk | Impact | Mitigation |
|------|--------|-----------|
| KMS key deletion blocks decryption | Medium | 30-day grace period, `cancel-key-deletion` available |
| ECR images lost | Low | Currently 0 images in all repos |
| S3 artifacts lost | Low | Currently 0 objects |
| SSM params lost | Low | All values are "UNSET" |
| CW log data lost | N/A | Orphan log groups already cleaned (R1) |
| IAM roles in use by other services | None | Roles only referenced by cicd pipelines (which don't exist) |
| Remote state orphaned | Low | S3 versioning preserves history; bucket shared across layers |
