# Contract-aligned outputs for global layer.
# Root will publish these to SSM as contracts/global/v1.

output "ecs_task_execution_role_arn" {
  description = "ECS task execution role ARN"
  value       = "" # M1: interface skeleton — no real resource
}

output "workload_role_arns" {
  description = "Map of service name to workload IAM role ARN"
  value       = {} # M1: interface skeleton
}

output "permissions_boundary_arn" {
  description = "Permissions boundary policy ARN for all roles"
  value       = "" # M1: interface skeleton
}
