# Contract-aligned outputs for edge-identity layer.
# Status: authored_not_provider_validated
#
# NOTE: CloudFront and WAF outputs belong to modules/edge/, not here.

output "cognito_user_pool_id" {
  description = "Cognito User Pool ID"
  value       = aws_cognito_user_pool.main.id
}

output "cognito_user_pool_arn" {
  description = "Cognito User Pool ARN"
  value       = aws_cognito_user_pool.main.arn
}

output "cognito_user_pool_endpoint" {
  description = "Cognito User Pool endpoint"
  value       = aws_cognito_user_pool.main.endpoint
}

output "cognito_spa_client_id" {
  description = "Cognito SPA client ID (public, no secret)"
  value       = aws_cognito_user_pool_client.spa.id
}

output "api_gateway_endpoint" {
  description = "API Gateway HTTP API endpoint URL"
  value       = aws_apigatewayv2_api.main.api_endpoint
}

output "api_gateway_api_id" {
  description = "API Gateway HTTP API ID"
  value       = aws_apigatewayv2_api.main.id
}

output "vpc_link_id" {
  description = "API Gateway VPC Link ID"
  value       = aws_apigatewayv2_vpc_link.alb.id
}
