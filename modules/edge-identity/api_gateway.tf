# Edge Identity — API Gateway HTTP API
#
# Status: authored_not_provider_validated
#
# This module owns: HTTP API, JWT authorizer, VPC link, ALB integration, routes.
# CloudFront / WAF / ACM / Route53 belong to modules/edge/.

resource "aws_apigatewayv2_api" "main" {
  name          = "${var.deployment_id}-api"
  protocol_type = "HTTP"

  cors_configuration {
    allow_origins = var.cors_allowed_origins
    allow_methods = ["GET", "POST", "PUT", "DELETE", "OPTIONS"]
    allow_headers = ["Content-Type", "Authorization", "X-Amz-Date", "X-Api-Key", "x-tenant-id"]
    max_age       = 3600
  }

  tags = {
    deployment_id = var.deployment_id
    managed_by    = "terraform"
    layer         = "edge-identity"
  }
}

# VPC Link for private ALB integration
resource "aws_apigatewayv2_vpc_link" "alb" {
  name               = "${var.deployment_id}-vpc-link"
  subnet_ids         = values(var.private_subnet_ids)
  security_group_ids = [var.alb_security_group_id]

  tags = {
    deployment_id = var.deployment_id
    managed_by    = "terraform"
    layer         = "edge-identity"
  }
}

# JWT Authorizer — Cognito
resource "aws_apigatewayv2_authorizer" "jwt" {
  api_id           = aws_apigatewayv2_api.main.id
  authorizer_type  = "JWT"
  identity_sources = ["$request.header.Authorization"]
  name             = "${var.deployment_id}-jwt-authorizer"

  jwt_configuration {
    audience = [aws_cognito_user_pool_client.spa.id]
    issuer   = "https://cognito-idp.${var.region}.amazonaws.com/${aws_cognito_user_pool.main.id}"
  }
}

# ALB integration via VPC link
resource "aws_apigatewayv2_integration" "alb" {
  api_id             = aws_apigatewayv2_api.main.id
  integration_type   = "HTTP_PROXY"
  integration_uri    = var.alb_listener_arn
  integration_method = "ANY"
  connection_type    = "VPC_LINK"
  connection_id      = aws_apigatewayv2_vpc_link.alb.id
}

# Default route — all requests through JWT authorizer to ALB
resource "aws_apigatewayv2_route" "default" {
  api_id    = aws_apigatewayv2_api.main.id
  route_key = "$default"
  target    = "integrations/${aws_apigatewayv2_integration.alb.id}"

  authorization_type = "JWT"
  authorizer_id      = aws_apigatewayv2_authorizer.jwt.id
}

# Stage
resource "aws_apigatewayv2_stage" "live" {
  api_id      = aws_apigatewayv2_api.main.id
  name        = "$default"
  auto_deploy = true

  access_log_settings {
    destination_arn = var.api_access_log_group_arn
    format = jsonencode({
      requestId      = "$context.requestId"
      ip             = "$context.identity.sourceIp"
      caller         = "$context.identity.caller"
      user           = "$context.identity.user"
      requestTime    = "$context.requestTime"
      httpMethod     = "$context.httpMethod"
      resourcePath   = "$context.resourcePath"
      status         = "$context.status"
      protocol       = "$context.protocol"
      responseLength = "$context.responseLength"
    })
  }

  tags = {
    deployment_id = var.deployment_id
    managed_by    = "terraform"
    layer         = "edge-identity"
  }
}
