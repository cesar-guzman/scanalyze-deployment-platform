# Contract producer gate for services module.
# This module produces: services/v2
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
  description = "Structured contract payload for services/v2"
  value = {
    schema_version = "2"
    layer          = local.layer_name
    state_scope    = local.state_scope
    outputs = {
      service_arns         = { for key, service in aws_ecs_service.service : key => service.id }
      task_definition_arns = { for key, task in aws_ecs_task_definition.service : key => task.arn }
      target_group_arns    = { for key, target in aws_lb_target_group.service : key => target.arn }
    }
  }
}
