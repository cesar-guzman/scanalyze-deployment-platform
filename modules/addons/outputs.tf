output "dashboard_urls" {
  description = "Map of dashboard name to CloudWatch dashboard URL"
  value       = {} # M1: interface skeleton
}

output "alarm_arns" {
  description = "Map of alarm name to CloudWatch alarm ARN"
  value       = {} # M1: interface skeleton
}

output "enabled_features" {
  description = "List of enabled addon feature names"
  value       = [] # M1: interface skeleton
}
