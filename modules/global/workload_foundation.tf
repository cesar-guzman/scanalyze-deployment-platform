# The deployment terminal consumes bootstrap-owned identities. Terraform-owned
# mode remains available for existing module consumers; changing an existing
# state to baseline mode requires an explicit, separately reviewed custody
# transfer because prevent_destroy protects its roles and boundaries.
moved {
  from = aws_iam_role.ecs_task_execution
  to   = aws_iam_role.ecs_task_execution[0]
}
moved {
  from = aws_iam_policy.workload_permissions_boundary
  to   = aws_iam_policy.workload_permissions_boundary[0]
}
moved {
  from = aws_iam_policy.identity_runtime_permissions_boundary
  to   = aws_iam_policy.identity_runtime_permissions_boundary[0]
}

locals {
  baseline_owned = var.ownership_mode == "baseline"
  baseline_workload_names = {
    for service in var.service_names : service => "${var.deployment_id}-workload-${service}"
  }
  expected_workload_boundary_arn = "arn:${var.aws_partition}:iam::${var.account_id}:policy/${var.deployment_id}-workload-boundary"
  expected_identity_boundary_arn = "arn:${var.aws_partition}:iam::${var.account_id}:policy/${var.deployment_id}-identity-runtime-boundary"
  expected_ecs_trust = {
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { Service = "ecs-tasks.amazonaws.com" }
      Condition = { StringEquals = { "aws:SourceAccount" = var.account_id } }
    }]
  }
  ecs_task_execution_role_arn   = local.baseline_owned ? data.aws_iam_role.ecs_task_execution[0].arn : aws_iam_role.ecs_task_execution[0].arn
  workload_role_arns            = local.baseline_owned ? { for key, role in data.aws_iam_role.workload : key => role.arn } : { for key, role in aws_iam_role.workload : key => role.arn }
  workload_boundary_arn         = local.baseline_owned ? data.aws_iam_policy.workload_boundary[0].arn : aws_iam_policy.workload_permissions_boundary[0].arn
  identity_runtime_boundary_arn = local.baseline_owned ? data.aws_iam_policy.identity_runtime_boundary[0].arn : aws_iam_policy.identity_runtime_permissions_boundary[0].arn
}

data "aws_iam_role" "ecs_task_execution" {
  count = local.baseline_owned ? 1 : 0
  name  = "${var.deployment_id}-ecs-task-execution"
}

data "aws_iam_role" "workload" {
  for_each = local.baseline_owned ? local.baseline_workload_names : {}
  name     = each.value
}

data "aws_iam_policy" "workload_boundary" {
  count = local.baseline_owned ? 1 : 0
  arn   = local.expected_workload_boundary_arn
}

data "aws_iam_policy" "identity_runtime_boundary" {
  count = local.baseline_owned ? 1 : 0
  arn   = local.expected_identity_boundary_arn
}

resource "terraform_data" "workload_foundation_gate" {
  lifecycle {
    precondition {
      condition = !local.baseline_owned || try(
        var.workload_foundation.schema_version == "1" &&
        var.workload_foundation.customer_id == var.customer_id &&
        var.workload_foundation.deployment_id == var.deployment_id &&
        var.workload_foundation.account_id == var.account_id &&
        var.workload_foundation.region == var.region &&
        var.workload_foundation.environment == var.environment &&
        var.workload_foundation.aws_partition == var.aws_partition &&
        var.workload_foundation.contract_digest == var.expected_workload_foundation_digest &&
        "sha256:${sha256(jsonencode({ for key, value in var.workload_foundation : key => value if key != "contract_digest" }))}" == var.expected_workload_foundation_digest &&
        can(regex("^sha256:[a-f0-9]{64}$", var.workload_foundation.template_sha256)), false
      )
      error_message = "Baseline ownership requires the independently anchored workload-foundation/v1 receipt for the exact authorized target."
    }
    precondition {
      condition = !local.baseline_owned || try(
        var.workload_foundation.ecs_task_execution_role_arn == local.ecs_task_execution_role_arn &&
        jsonencode(var.workload_foundation.workload_role_arns) == jsonencode({ for service, arn in local.workload_role_arns : "scanalyze-${service}" => arn }) &&
        var.workload_foundation.workload_boundary_arn == local.workload_boundary_arn &&
        var.workload_foundation.identity_runtime_boundary_arn == local.identity_runtime_boundary_arn &&
        var.workload_foundation.policy_digests.workload == "sha256:${sha256(jsonencode(jsondecode(data.aws_iam_policy.workload_boundary[0].policy)))}" &&
        var.workload_foundation.policy_digests.identity_runtime == "sha256:${sha256(jsonencode(jsondecode(data.aws_iam_policy.identity_runtime_boundary[0].policy)))}", false
      )
      error_message = "Observed IAM roles and boundary policy content must match the approved bootstrap receipt."
    }
    precondition {
      condition = !local.baseline_owned || try(alltrue([
        for role in concat([data.aws_iam_role.ecs_task_execution[0]], values(data.aws_iam_role.workload)) :
        role.permissions_boundary == local.expected_workload_boundary_arn &&
        jsonencode(jsondecode(role.assume_role_policy)) == jsonencode(local.expected_ecs_trust) &&
        role.tags["deployment_id"] == var.deployment_id && role.tags["layer"] == "global" &&
        role.tags["customer_id"] == var.customer_id &&
        role.tags["managed_by"] == "external-account-baseline"
      ]), false)
      error_message = "Bootstrap roles must retain exact ECS trust, customer/deployment tags, external-account-baseline custody, and the approved workload boundary."
    }
  }
}
