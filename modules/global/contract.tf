# Contract producer gate for global module.
# This module produces: global/v1
# Consumers: downstream layers that declare dependency on this contract.
#
# The contract is written by the root that calls this module,
# NOT by the module itself. The module only exposes outputs
# that the root's contracts.tf will publish to SSM.
#
# Single Contract Writer Rule (ADR-006 rev3):
# Each contract is written by EXACTLY ONE root.

# Contract output structure — root will publish this to SSM.
output "contract_payload" {
  description = "Structured contract payload for global/v1"
  value = {
    schema_version = "1"
    layer          = local.layer_name
    state_scope    = local.state_scope
    outputs = {
      ecs_execution_role_arn = aws_iam_role.ecs_task_execution.arn
      ecs_task_role_arns = {
        for service, role in aws_iam_role.workload : "scanalyze-${service}" => role.arn
      }
      permissions_boundary_arn                  = aws_iam_policy.workload_permissions_boundary.arn
      identity_runtime_permissions_boundary_arn = aws_iam_policy.identity_runtime_permissions_boundary.arn
    }
  }
}
