# Edge Identity — Cognito
#
# Status: authored_not_provider_validated
#
# This module owns Cognito user pool, SPA client (Authorization Code + PKCE),
# M2M client (client_credentials), and resource server with scopes.

resource "aws_cognito_user_pool" "main" {
  name = "${var.deployment_id}-users"

  username_attributes      = ["email"]
  auto_verified_attributes = ["email"]

  password_policy {
    minimum_length                   = 12
    require_lowercase                = true
    require_uppercase                = true
    require_numbers                  = true
    require_symbols                  = true
    temporary_password_validity_days = 7
  }

  account_recovery_setting {
    recovery_mechanism {
      name     = "verified_email"
      priority = 1
    }
  }

  schema {
    name                     = "email"
    attribute_data_type      = "String"
    mutable                  = true
    required                 = true
    developer_only_attribute = false

    string_attribute_constraints {
      min_length = 1
      max_length = 256
    }
  }

  tags = {
    deployment_id = var.deployment_id
    managed_by    = "terraform"
    layer         = "edge-identity"
  }
}

resource "aws_cognito_user_pool_domain" "main" {
  domain       = var.deployment_id
  user_pool_id = aws_cognito_user_pool.main.id
}

resource "aws_cognito_resource_server" "api" {
  identifier   = "https://api.${var.domain_name}"
  name         = "${var.deployment_id}-api"
  user_pool_id = aws_cognito_user_pool.main.id

  dynamic "scope" {
    for_each = var.api_scopes
    content {
      scope_name        = scope.value.name
      scope_description = scope.value.description
    }
  }
}

# SPA client — Authorization Code + PKCE
resource "aws_cognito_user_pool_client" "spa" {
  name         = "${var.deployment_id}-spa"
  user_pool_id = aws_cognito_user_pool.main.id

  generate_secret = false # SPA clients must not have a secret

  allowed_oauth_flows                  = ["code"]
  allowed_oauth_flows_user_pool_client = true
  allowed_oauth_scopes = concat(
    ["openid", "email", "profile"],
    [for s in var.api_scopes : "${aws_cognito_resource_server.api.identifier}/${s.name}"]
  )

  callback_urls = var.spa_callback_urls
  logout_urls   = var.spa_logout_urls

  supported_identity_providers = ["COGNITO"]

  explicit_auth_flows = [
    "ALLOW_REFRESH_TOKEN_AUTH",
  ]

  token_validity_units {
    access_token  = "hours"
    id_token      = "hours"
    refresh_token = "days"
  }

  access_token_validity  = 1
  id_token_validity      = 1
  refresh_token_validity = 30
}

# M2M client — client_credentials
resource "aws_cognito_user_pool_client" "m2m" {
  name         = "${var.deployment_id}-m2m"
  user_pool_id = aws_cognito_user_pool.main.id

  generate_secret = true

  allowed_oauth_flows                  = ["client_credentials"]
  allowed_oauth_flows_user_pool_client = true
  allowed_oauth_scopes = [
    for s in var.api_scopes : "${aws_cognito_resource_server.api.identifier}/${s.name}"
  ]

  supported_identity_providers = ["COGNITO"]
}
