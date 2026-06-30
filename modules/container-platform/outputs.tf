# Contract-aligned outputs for container-platform layer.
# Status: authored_not_provider_validated

output "ecs_cluster_arn" {
  description = "ECS cluster ARN"
  value       = aws_ecs_cluster.main.arn
}

output "ecs_cluster_name" {
  description = "ECS cluster name"
  value       = aws_ecs_cluster.main.name
}

output "alb_arn" {
  description = "Internal ALB ARN"
  value       = aws_lb.internal.arn
}

output "alb_dns_name" {
  description = "Internal ALB DNS name"
  value       = aws_lb.internal.dns_name
}

output "alb_listener_arn" {
  description = "HTTPS listener ARN"
  value       = aws_lb_listener.https.arn
}

output "alb_security_group_id" {
  description = "ALB security group ID"
  value       = aws_security_group.alb.id
}
