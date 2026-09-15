# Read the bootstrap-owned ceiling before installing runtime grants or inputs.
# Its ARN is derived from the deployment; callers cannot substitute a policy.
data "aws_iam_policy" "runtime_boundary" {
  count = local.runtime_enabled ? 1 : 0
  arn   = "arn:${var.runtime_bindings.aws_partition}:iam::${var.account_id}:policy/${var.deployment_id}-workload-boundary"
}

locals {
  observed_runtime_boundary = try(jsondecode(data.aws_iam_policy.runtime_boundary[0].policy), null)
  runtime_boundary_visibility = try([
    for statement in local.observed_runtime_boundary.Statement : statement
    if try(statement.Sid, "") == "ExtendDeploymentStageVisibility"
  ], [])
  runtime_boundary_models = try([
    for statement in local.observed_runtime_boundary.Statement : statement
    if try(statement.Sid, "") == "InvokeSelectedRegionalModels"
  ], [])
  runtime_boundary_denies = try([
    for statement in local.observed_runtime_boundary.Statement : statement
    if try(statement.Effect, "") == "Deny"
  ], [])
  # Accept the fixed bootstrap control-plane deny, never attempt to partially
  # evaluate arbitrary IAM Deny/NotAction/Condition semantics in Terraform.
  runtime_boundary_control_plane_deny = {
    Sid    = "DenyControlPlaneEscalation"
    Effect = "Deny"
    Action = [
      "iam:CreateRole", "iam:DeleteRole", "iam:AttachRolePolicy", "iam:DetachRolePolicy",
      "iam:PutRolePolicy", "iam:DeleteRolePolicy", "iam:CreatePolicy", "iam:DeletePolicy",
      "iam:UpdateAssumeRolePolicy", "iam:PutRolePermissionsBoundary", "iam:DeleteRolePermissionsBoundary",
      "organizations:*", "account:*",
    ]
    Resource = "*"
  }
  runtime_boundary_stage_arns = local.runtime_enabled ? toset([
    for stage in keys(local.queue_topology) :
    "arn:${var.runtime_bindings.aws_partition}:sqs:${var.region}:${var.account_id}:${var.deployment_id}-${stage}-stage-queue"
  ]) : toset([])
}

resource "terraform_data" "runtime_boundary_gate" {
  count = local.runtime_enabled ? 1 : 0

  lifecycle {
    precondition {
      condition = try(
        data.aws_iam_policy.runtime_boundary[0].arn == "arn:${var.runtime_bindings.aws_partition}:iam::${var.account_id}:policy/${var.deployment_id}-workload-boundary" &&
        local.observed_runtime_boundary.Version == "2012-10-17" &&
        toset(keys(local.observed_runtime_boundary)) == toset(["Version", "Statement"]) &&
        alltrue([for statement in local.observed_runtime_boundary.Statement : contains(["Allow", "Deny"], statement.Effect)]) &&
        length(local.runtime_boundary_denies) == 1 &&
        jsonencode(one(local.runtime_boundary_denies)) == jsonencode(local.runtime_boundary_control_plane_deny), false
      )
      error_message = "Runtime requires the exact deployment boundary with only the fixed bootstrap control-plane deny; additional deny semantics require a reviewed contract."
    }
    precondition {
      condition = try(
        length(local.runtime_boundary_visibility) == 1 &&
        toset(keys(one(local.runtime_boundary_visibility))) == toset(["Sid", "Effect", "Action", "Resource"]) &&
        one(local.runtime_boundary_visibility).Effect == "Allow" &&
        jsonencode(one(local.runtime_boundary_visibility).Action) == jsonencode(["sqs:ChangeMessageVisibility"]) &&
        toset(one(local.runtime_boundary_visibility).Resource) == local.runtime_boundary_stage_arns,
        false
      )
      error_message = "The bootstrap boundary must allow visibility extension unconditionally on exactly the nine deployment stage queues before runtime publication."
    }
    precondition {
      condition = try(
        length(local.runtime_boundary_models) == 1 &&
        toset(keys(one(local.runtime_boundary_models))) == toset(["Sid", "Effect", "Action", "Resource"]) &&
        one(local.runtime_boundary_models).Effect == "Allow" &&
        jsonencode(one(local.runtime_boundary_models).Action) == jsonencode(["bedrock:InvokeModel"]) &&
        length(one(local.runtime_boundary_models).Resource) > 0 &&
        length(one(local.runtime_boundary_models).Resource) <= 4 &&
        length(distinct(one(local.runtime_boundary_models).Resource)) == length(one(local.runtime_boundary_models).Resource) &&
        alltrue([
          for arn in one(local.runtime_boundary_models).Resource :
          can(regex("^arn:${var.runtime_bindings.aws_partition}:bedrock:${var.region}::foundation-model/[A-Za-z0-9][A-Za-z0-9.:-]*$", arn))
        ]) &&
        length(setsubtract(toset(values(local.runtime_models)), toset(one(local.runtime_boundary_models).Resource))) == 0,
        false
      )
      error_message = "Every selected runtime model must be allowed unconditionally by the bootstrap boundary's finite regional model set; wildcard or different models cannot substitute."
    }
  }
}
