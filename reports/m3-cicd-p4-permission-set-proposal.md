# M3-CICD-P4 Permission Set Least-Privilege Proposal

**Date: 2026-07-03T18:20Z**
**Status: PROPOSAL — Requires PM approval before implementation**
**Scope: `ScanalyzeSandboxDeploy` Permission Set delta for CodeCommit/CodeBuild/CodePipeline**

---

## Current Permissions (what exists)

The current `ScanalyzeSandboxDeploy` Permission Set has permissions for:
- `ecr:*` (scoped to account)
- `s3:*` (scoped to deployment buckets)
- `kms:*` (scoped)
- `ssm:*` (scoped)
- `iam:CreateRole`, `iam:PutRolePolicy`, etc. (scoped)
- `logs:*` (scoped)

**Missing** for CodeCommit/Pipeline/Build:
- `codecommit:*`
- `codebuild:*`
- `codepipeline:*`
- `events:*` (for EventBridge triggers)

---

## Proposed Permission Delta

### 1. CodeCommit Permissions

```json
{
  "Sid": "CodeCommitScopedRepos",
  "Effect": "Allow",
  "Action": [
    "codecommit:CreateRepository",
    "codecommit:DeleteRepository",
    "codecommit:GetRepository",
    "codecommit:ListRepositories",
    "codecommit:ListTagsForResource",
    "codecommit:TagResource",
    "codecommit:UntagResource",
    "codecommit:UpdateRepositoryDescription",
    "codecommit:UpdateRepositoryName"
  ],
  "Resource": "arn:aws:codecommit:us-east-1:905418363887:dep_01KWM783E0S1FZVAM8FRDV1HR2-*"
}
```

> **Note:** This does NOT include `codecommit:GitPush`, `codecommit:GitPull`, etc.
> Those are developer-facing actions needed for source push, handled via
> developer SSO or credential helper, NOT the Terraform deploy role.
> However, if Terraform needs to push initial content, add:
> ```
> "codecommit:GitPush"
> ```
> Only if explicitly approved.

### 2. CodeBuild Permissions

```json
{
  "Sid": "CodeBuildScopedProjects",
  "Effect": "Allow",
  "Action": [
    "codebuild:CreateProject",
    "codebuild:DeleteProject",
    "codebuild:UpdateProject",
    "codebuild:BatchGetProjects",
    "codebuild:ListProjects",
    "codebuild:ListTagsForResource",
    "codebuild:TagResource",
    "codebuild:UntagResource"
  ],
  "Resource": "arn:aws:codebuild:us-east-1:905418363887:project/dep_01KWM783E0S1FZVAM8FRDV1HR2-*"
}
```

> **Note:** Does NOT include `codebuild:StartBuild` or `codebuild:StopBuild`.
> Those are runtime actions used by CodePipeline (via the service role, not deploy role)
> or manual trigger (requires separate approval).

### 3. CodePipeline Permissions

```json
{
  "Sid": "CodePipelineScopedPipelines",
  "Effect": "Allow",
  "Action": [
    "codepipeline:CreatePipeline",
    "codepipeline:DeletePipeline",
    "codepipeline:GetPipeline",
    "codepipeline:GetPipelineState",
    "codepipeline:UpdatePipeline",
    "codepipeline:ListPipelines",
    "codepipeline:ListTagsForResource",
    "codepipeline:TagResource",
    "codepipeline:UntagResource"
  ],
  "Resource": "arn:aws:codepipeline:us-east-1:905418363887:dep_01KWM783E0S1FZVAM8FRDV1HR2-*"
}
```

> **Note:** Does NOT include `codepipeline:StartPipelineExecution`.

### 4. IAM PassRole (CICD roles only)

```json
{
  "Sid": "PassRoleToCICDServicesOnly",
  "Effect": "Allow",
  "Action": "iam:PassRole",
  "Resource": [
    "arn:aws:iam::905418363887:role/dep_01KWM783E0S1FZVAM8FRDV1HR2-codebuild-role",
    "arn:aws:iam::905418363887:role/dep_01KWM783E0S1FZVAM8FRDV1HR2-codepipeline-role"
  ],
  "Condition": {
    "StringEquals": {
      "iam:PassedToService": [
        "codebuild.amazonaws.com",
        "codepipeline.amazonaws.com"
      ]
    }
  }
}
```

### 5. EventBridge (for pipeline triggers)

```json
{
  "Sid": "EventBridgeCICDRules",
  "Effect": "Allow",
  "Action": [
    "events:PutRule",
    "events:DeleteRule",
    "events:DescribeRule",
    "events:PutTargets",
    "events:RemoveTargets",
    "events:ListTargetsByRule",
    "events:ListTagsForResource",
    "events:TagResource",
    "events:UntagResource"
  ],
  "Resource": "arn:aws:events:us-east-1:905418363887:rule/dep_01KWM783E0S1FZVAM8FRDV1HR2-*"
}
```

---

## Explicit Denies (Guardrails)

These MUST be present in the Permission Set to prevent accidental or future escalation:

```json
{
  "Sid": "DenyECSMutation",
  "Effect": "Deny",
  "Action": [
    "ecs:RegisterTaskDefinition",
    "ecs:UpdateService",
    "ecs:CreateService",
    "ecs:DeleteService",
    "ecs:DeregisterTaskDefinition"
  ],
  "Resource": "*",
  "Condition": {
    "StringNotLike": {
      "aws:PrincipalTag/layer": "services"
    }
  }
},
{
  "Sid": "DenyCodeDeploy",
  "Effect": "Deny",
  "Action": "codedeploy:*",
  "Resource": "*"
},
{
  "Sid": "DenyPassRoleWildcard",
  "Effect": "Deny",
  "Action": "iam:PassRole",
  "Resource": "*",
  "Condition": {
    "StringNotEquals": {
      "iam:PassedToService": [
        "codebuild.amazonaws.com",
        "codepipeline.amazonaws.com",
        "ecs-tasks.amazonaws.com"
      ]
    }
  }
}
```

---

## What is NOT Proposed

| Action | Reason |
|--------|--------|
| `codecommit:*` | Too broad. Only management actions needed for Terraform |
| `codepipeline:*` | Too broad. No `StartPipelineExecution` for deploy role |
| `codebuild:*` | Too broad. No `StartBuild` for deploy role |
| `codedeploy:*` | Explicitly rejected |
| `ecs:*` | Explicitly rejected — Terraform services layer owns ECS |
| `iam:PassRole "*"` | Explicitly rejected — scoped to 2 specific CICD roles |
| `cloudformation:*` | Explicitly rejected — separate baseline concern |

---

## Permission Matrix

| Service | Deploy Role (Terraform) | CodePipeline Service Role | CodeBuild Service Role | Developer (SSO) |
|---------|------------------------|---------------------------|------------------------|-----------------|
| CodeCommit CRUD | ✅ Scoped to `{dep}-*` | Read source only | No | Push/Pull |
| CodeBuild CRUD | ✅ Scoped to `{dep}-*` | StartBuild only | Self (exec) | No |
| CodePipeline CRUD | ✅ Scoped to `{dep}-*` | Self (exec) | No | No |
| ECR Push | No (deploy role) | No | ✅ Push to `{dep}/*` | No |
| SSM Write (digests) | No (deploy role) | No | ✅ `/{dep}/cicd/images/*` | No |
| ECS Mutation | ❌ DENIED | ❌ Not in policy | ❌ DENIED | ❌ |
| PassRole | ✅ 2 specific roles | N/A | N/A | No |
| CodeDeploy | ❌ DENIED | ❌ DENIED | ❌ DENIED | ❌ DENIED |

---

## Implementation Notes

1. **Scope**: All ARNs use deployment ID prefix — no wildcard across deployments
2. **Condition**: PassRole limited to specific AWS services
3. **Deny statements**: Override any future Allow that might be added
4. **No runtime actions**: Deploy role creates/updates/deletes infra, does not trigger pipelines
5. **CodeBuild StartBuild**: Only CodePipeline service role can start builds (via pipeline execution)

---

## Risk Assessment

| Risk | Mitigation |
|------|------------|
| Future team adds `codedeploy:*` | Explicit Deny blocks it |
| Future team adds ECS Deploy stage | Linter catches it; Deny blocks runtime |
| PassRole escalation | Scoped to 2 roles + condition on service |
| Cross-deployment access | ARN prefix isolates per deployment |
