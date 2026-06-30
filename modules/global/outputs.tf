# Contract-aligned outputs for global layer.
# Root will publish these to SSM as contracts/global/v1.
# Status: authored_not_provider_validated

output "ecs_task_execution_role_arn" {
  description = "ECS task execution role ARN"
  value       = aws_iam_role.ecs_task_execution.arn
}

output "workload_role_arns" {
  description = "Map of service name to workload IAM role ARN"
  value       = { for k, v in aws_iam_role.workload : k => v.arn }
}

output "permissions_boundary_arn" {
  description = "Workload permissions boundary policy ARN"
  value       = aws_iam_policy.workload_permissions_boundary.arn
}
