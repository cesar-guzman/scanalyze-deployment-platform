# Contract-aligned outputs for services layer.
# Status: authored_not_provider_validated

output "service_arns" {
  description = "Map of service name to ECS service ARN"
  value       = { for k, v in aws_ecs_service.service : k => v.id }
}

output "task_definition_arns" {
  description = "Map of service name to task definition ARN"
  value       = { for k, v in aws_ecs_task_definition.service : k => v.arn }
}

output "target_group_arns" {
  description = "Map of service name to target group ARN"
  value       = { for k, v in aws_lb_target_group.service : k => v.arn }
}
