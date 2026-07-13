# Root outputs — contract payload published to SSM by orchestrator.
output "contract_payload" {
  description = "Contract payload from global module"
  value       = module.global.contract_payload
}

output "ecs_execution_role_arn" {
  description = "ECS task execution role published by global/v1."
  value       = module.global.ecs_task_execution_role_arn
}

output "ecs_task_role_arns" {
  description = "Canonical service-name to ECS task role mapping published by global/v1."
  value = {
    for service, arn in module.global.workload_role_arns : "scanalyze-${service}" => arn
  }
}

output "permissions_boundary_arn" {
  description = "General application workload permissions boundary."
  value       = module.global.permissions_boundary_arn
}

output "identity_runtime_permissions_boundary_arn" {
  description = "Dedicated identity runtime permissions boundary consumed by identity-control-plane."
  value       = module.global.identity_runtime_permissions_boundary_arn
}
