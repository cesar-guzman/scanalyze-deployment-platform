# M3-CICD-P4 Buildspec Review

**Date: 2026-07-03T18:23Z**
**Status: NO BUILDSPEC EXISTS YET — Template proposed for review**

---

## Current State

There are **no buildspec files** in the repository. The module references `buildspec.yml` as default path ([variables.tf:43-47](file:///Users/cesarguzmanguadarrama/Desktop/bcm-cloud/scanalyze-deployment-platform/modules/cicd/variables.tf#L43-L47)), but the file must be present in the CodeCommit repo source when the pipeline triggers.

**This means**: Even if `enable_codecommit=true` is applied and pipelines are created, no build can succeed until a valid buildspec is pushed to each CodeCommit repo.

---

## Proposed Buildspec Template

```yaml
# buildspec.yml — Scanalyze Platform v2 Build-Only Spec
# 
# PURPOSE: Build Docker image, push to ECR, write digest to SSM.
# DOES NOT: Deploy to ECS, register task definitions, invoke CodeDeploy.
#
# Environment variables injected by CodeBuild project:
#   AWS_REGION, ACCOUNT_ID, ECR_REPO_URI, ECR_REPO_NAME,
#   CONTAINER_NAME, IMAGE_TAG_SSM_PARAMETER, IMAGE_DIGEST_SSM_PARAMETER

version: 0.2

env:
  variables:
    # Fallback tag if CODEBUILD_RESOLVED_SOURCE_VERSION not available
    IMAGE_TAG_FALLBACK: "latest"

phases:
  pre_build:
    commands:
      - echo "=== Pre-Build ==="
      - echo "Region:    $AWS_REGION"
      - echo "Account:   $ACCOUNT_ID"
      - echo "Repo:      $ECR_REPO_URI"
      - echo "Container: $CONTAINER_NAME"
      - echo "Build ID:  $CODEBUILD_BUILD_ID"
      - echo "Source:    $CODEBUILD_RESOLVED_SOURCE_VERSION"

      # ECR login
      - aws ecr get-login-password --region $AWS_REGION | docker login --username AWS --password-stdin $ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com

      # Determine image tag (prefer git commit SHA)
      - |
        if [ -n "$CODEBUILD_RESOLVED_SOURCE_VERSION" ]; then
          export IMAGE_TAG=$(echo $CODEBUILD_RESOLVED_SOURCE_VERSION | cut -c1-12)
        else
          export IMAGE_TAG="$IMAGE_TAG_FALLBACK"
        fi
      - echo "Image tag: $IMAGE_TAG"

  build:
    commands:
      - echo "=== Build ==="
      - echo "Building $ECR_REPO_URI:$IMAGE_TAG"
      - docker build -t $ECR_REPO_URI:$IMAGE_TAG .
      - docker tag $ECR_REPO_URI:$IMAGE_TAG $ECR_REPO_URI:$IMAGE_TAG

  post_build:
    commands:
      - echo "=== Post-Build ==="

      # Push image to ECR
      - docker push $ECR_REPO_URI:$IMAGE_TAG

      # Capture image digest
      - |
        export IMAGE_DIGEST=$(aws ecr describe-images \
          --repository-name "$ECR_REPO_NAME" \
          --image-ids imageTag="$IMAGE_TAG" \
          --query "imageDetails[0].imageDigest" \
          --output text)
      - echo "Image digest: $IMAGE_DIGEST"

      # Write release metadata to SSM
      - |
        if [ -n "$IMAGE_TAG_SSM_PARAMETER" ] && [ "$IMAGE_TAG_SSM_PARAMETER" != "" ]; then
          aws ssm put-parameter \
            --name "$IMAGE_TAG_SSM_PARAMETER" \
            --value "$IMAGE_TAG" \
            --type String --overwrite
          echo "SSM: $IMAGE_TAG_SSM_PARAMETER = $IMAGE_TAG"
        fi

      - |
        if [ -n "$IMAGE_DIGEST_SSM_PARAMETER" ] && [ "$IMAGE_DIGEST_SSM_PARAMETER" != "" ]; then
          aws ssm put-parameter \
            --name "$IMAGE_DIGEST_SSM_PARAMETER" \
            --value "$IMAGE_DIGEST" \
            --type String --overwrite
          echo "SSM: $IMAGE_DIGEST_SSM_PARAMETER = $IMAGE_DIGEST"
        fi

      # Write sanitized build metadata (no secrets)
      - echo "Build complete."
      - echo "ECR URI:   $ECR_REPO_URI@$IMAGE_DIGEST"
      - echo "Tag:       $IMAGE_TAG"
      - echo "Source:    $CODEBUILD_RESOLVED_SOURCE_VERSION"
      - echo "Build ID:  $CODEBUILD_BUILD_ID"
      - echo "Timestamp: $(date -u +%Y-%m-%dT%H:%M:%SZ)"

      # NOTE: We do NOT generate imagedefinitions.json
      # NOTE: We do NOT call aws ecs update-service
      # NOTE: We do NOT call aws ecs register-task-definition
      # NOTE: We do NOT call aws deploy create-deployment
```

---

## Compliance Matrix

### ✅ Allowed Patterns (present in template)

| Pattern | Lines | Purpose |
|---------|-------|---------|
| `docker build` | build phase | Build container image |
| `docker push` to ECR | post_build | Push to customer-local ECR |
| `ecr describe-images` to capture digest | post_build | Get immutable digest |
| `ssm put-parameter` for image_tag | post_build | Write release tag to SSM |
| `ssm put-parameter` for image_digest | post_build | Write digest to SSM |
| Sanitized build metadata (echo) | post_build | Audit trail (no secrets) |

### ❌ Forbidden Patterns (NOT present — verified)

| Pattern | Check | Status |
|---------|-------|--------|
| `imagedefinitions.json` as ECS deploy artifact | grep | ✅ NOT present |
| `aws ecs update-service` | grep | ✅ NOT present |
| `aws ecs register-task-definition` | grep | ✅ NOT present |
| `aws deploy create-deployment` | grep | ✅ NOT present |
| `ecs:UpdateService` | IAM policy | ✅ NOT in CodeBuild policy |
| `ecs:RegisterTaskDefinition` | IAM policy | ✅ NOT in CodeBuild policy |
| Writing directly to ECS/CodeDeploy | grep | ✅ NOT present |
| Secrets/tokens in output | review | ✅ Only sanitized metadata |

---

## imagedefinitions.json Decision

### Current State

The buildspec template does **NOT** generate `imagedefinitions.json`.

### Policy

`imagedefinitions.json` was used by the brownfield pipeline to feed the ECS Deploy stage:

```json
[{"name":"container-name","imageUri":"..."}]
```

In Platform v2:
- No Deploy stage exists → no consumer of `imagedefinitions.json`
- Risk: If generated, a future developer might reintroduce a Deploy stage that consumes it
- Decision: **Do NOT generate `imagedefinitions.json`**

If legacy systems require build artifact metadata, use a different filename:
```
build-metadata.json  (NOT imagedefinitions.json)
```

This prevents accidental reintroduction of ECS deploy patterns.

---

## Build Output Flow

```
┌─────────────────┐     ┌────────────┐     ┌────────────┐
│   CodeCommit    │────▶│  CodeBuild │────▶│    ECR     │
│   (source)      │     │  (build)   │     │  (image)   │
└─────────────────┘     └─────┬──────┘     └────────────┘
                              │
                              │ post_build
                              ▼
                        ┌────────────┐
                        │    SSM     │
                        │ (metadata) │
                        └─────┬──────┘
                              │
                              │ (consumed later by)
                              ▼
                        ┌────────────┐
                        │ Terraform  │
                        │ services   │
                        │ (apply)    │
                        └────────────┘
```

The gap between "SSM written" and "services consuming" is intentional:
- **Build** is automated (pipeline)
- **Deploy** is controlled (Terraform apply with PM approval)
- **No automatic ECS mutation**

---

## Open Items

| Item | Status | Note |
|------|--------|------|
| Buildspec does not exist yet | Expected | Must be pushed to CodeCommit repos |
| Extended metadata (source_revision, build_id, etc.) | Proposed | Can be added to buildspec post_build; SSM IAM is already scoped to `/{dep}/cicd/images/*` |
| scanner_status placeholder | Proposed | Not yet implemented; placeholder `NOT_IMPLEMENTED` can be written to SSM |
| Per-service buildspec customization | Available | `buildspec_path` variable allows per-service override |
| Linter coverage for buildspec | Available | `lint_cicd_safety.py` scans `buildspec*.yml` for `update-service` and `register-task-definition` |
