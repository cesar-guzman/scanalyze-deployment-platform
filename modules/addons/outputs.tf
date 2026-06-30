# Contract-aligned outputs for addons layer.
# Status: authored_not_provider_validated

output "dashboard_name" {
  description = "CloudWatch dashboard name"
  value       = aws_cloudwatch_dashboard.main.dashboard_name
}

output "alerts_topic_arn" {
  description = "SNS alerts topic ARN"
  value       = aws_sns_topic.alerts.arn
}

output "log_group_names" {
  description = "Map of service name to CloudWatch log group name"
  value       = { for k, v in aws_cloudwatch_log_group.service : k => v.name }
}
