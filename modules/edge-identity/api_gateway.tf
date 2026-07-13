resource "aws_apigatewayv2_api" "main" {
  name          = "${var.deployment_id}-api"
  protocol_type = "HTTP"

  cors_configuration {
    allow_origins = var.cors_allowed_origins
    allow_methods = ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]
    allow_headers = ["Content-Type", "Authorization", "X-Amz-Date"]
    max_age       = 3600
  }

  tags = local.common_tags
}

resource "aws_apigatewayv2_vpc_link" "alb" {
  name               = "${var.deployment_id}-vpc-link"
  subnet_ids         = values(var.private_subnet_ids)
  security_group_ids = [var.alb_security_group_id]

  tags = local.common_tags
}

resource "aws_apigatewayv2_authorizer" "jwt" {
  api_id           = aws_apigatewayv2_api.main.id
  authorizer_type  = "JWT"
  identity_sources = ["$request.header.Authorization"]
  name             = "${var.deployment_id}-jwt-authorizer"

  jwt_configuration {
    audience = local.authorizer_audiences
    issuer   = var.cognito_issuer_url
  }

  depends_on = [terraform_data.identity_handoff_gate]
}

resource "aws_apigatewayv2_integration" "alb" {
  api_id             = aws_apigatewayv2_api.main.id
  integration_type   = "HTTP_PROXY"
  integration_uri    = var.alb_listener_arn
  integration_method = "ANY"
  connection_type    = "VPC_LINK"
  connection_id      = aws_apigatewayv2_vpc_link.alb.id
}

resource "aws_apigatewayv2_route" "protected" {
  for_each = var.api_authorization_routes

  api_id    = aws_apigatewayv2_api.main.id
  route_key = each.key
  target    = "integrations/${aws_apigatewayv2_integration.alb.id}"

  authorization_type   = "JWT"
  authorizer_id        = aws_apigatewayv2_authorizer.jwt.id
  authorization_scopes = each.value
}

resource "aws_apigatewayv2_deployment" "reviewed" {
  api_id = aws_apigatewayv2_api.main.id

  triggers = {
    reviewed_configuration = sha256(jsonencode({
      routes    = var.api_authorization_routes
      issuer    = var.cognito_issuer_url
      audiences = local.authorizer_audiences
      integration = {
        listener_arn = var.alb_listener_arn
        vpc_link_id  = aws_apigatewayv2_vpc_link.alb.id
      }
    }))
  }

  lifecycle {
    create_before_destroy = true
  }

  depends_on = [
    aws_apigatewayv2_authorizer.jwt,
    aws_apigatewayv2_integration.alb,
    aws_apigatewayv2_route.protected,
  ]
}

resource "aws_apigatewayv2_stage" "live" {
  api_id        = aws_apigatewayv2_api.main.id
  name          = "$default"
  auto_deploy   = false
  deployment_id = aws_apigatewayv2_deployment.reviewed.id

  access_log_settings {
    destination_arn = var.api_access_log_group_arn
    format = jsonencode({
      requestId      = "$context.requestId"
      requestTime    = "$context.requestTime"
      httpMethod     = "$context.httpMethod"
      routeKey       = "$context.routeKey"
      status         = "$context.status"
      protocol       = "$context.protocol"
      responseLength = "$context.responseLength"
    })
  }

  tags = local.common_tags
}
