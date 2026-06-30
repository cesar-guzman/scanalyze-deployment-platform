output "service_arns" {
  description = "Map of service name to ECS service ARN"
  value       = {} # M1: interface skeleton
}

output "task_definition_arns" {
  description = "Map of service name to ECS task definition ARN"
  value       = {} # M1: interface skeleton
}

output "service_endpoints" {
  description = "Map of service name to internal endpoint URL"
  value       = {} # M1: interface skeleton
}
