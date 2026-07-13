resource "aws_cognito_user_pool" "main" {
  name                = "${local.identity_prefix}-users"
  deletion_protection = "ACTIVE"
  user_pool_tier      = "PLUS"

  username_attributes      = ["email"]
  auto_verified_attributes = ["email"]
  mfa_configuration        = "ON"

  username_configuration {
    case_sensitive = false
  }

  admin_create_user_config {
    allow_admin_create_user_only = true
  }

  password_policy {
    minimum_length                   = 14
    require_lowercase                = true
    require_uppercase                = true
    require_numbers                  = true
    require_symbols                  = true
    temporary_password_validity_days = 1
  }

  software_token_mfa_configuration {
    enabled = true
  }

  account_recovery_setting {
    recovery_mechanism {
      name     = "verified_email"
      priority = 1
    }
  }

  user_pool_add_ons {
    advanced_security_mode = "ENFORCED"
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

  schema {
    name                     = "customerId"
    attribute_data_type      = "String"
    mutable                  = false
    required                 = false
    developer_only_attribute = false

    string_attribute_constraints {
      min_length = 31
      max_length = 31
    }
  }

  schema {
    name                     = "deployment_id"
    attribute_data_type      = "String"
    mutable                  = false
    required                 = false
    developer_only_attribute = false

    string_attribute_constraints {
      min_length = 30
      max_length = 30
    }
  }

  lambda_config {
    pre_token_generation_config {
      lambda_arn     = aws_lambda_alias.pre_token.arn
      lambda_version = "V2_0"
    }
  }

  lifecycle {
    prevent_destroy = true
  }

  tags = merge(local.common_tags, {
    purpose = "enterprise-human-identity"
  })
}

resource "aws_cognito_user_pool_domain" "main" {
  domain       = local.hosted_ui_prefix
  user_pool_id = aws_cognito_user_pool.main.id
}

resource "aws_cognito_user_group" "roles" {
  for_each = local.role_precedence

  name         = each.key
  description  = "Non-authoritative provider mapping for enterprise role ${each.key}"
  precedence   = each.value
  user_pool_id = aws_cognito_user_pool.main.id
}

resource "aws_cognito_resource_server" "api" {
  identifier   = "scanalyze.api.v1"
  name         = "${local.identity_prefix}-api-v1"
  user_pool_id = aws_cognito_user_pool.main.id

  dynamic "scope" {
    for_each = local.canonical_scopes
    content {
      scope_name        = scope.key
      scope_description = scope.value
    }
  }
}

resource "aws_cognito_user_pool_client" "spa" {
  name         = "${local.identity_prefix}-spa"
  user_pool_id = aws_cognito_user_pool.main.id

  generate_secret                      = false
  allowed_oauth_flows                  = ["code"]
  allowed_oauth_flows_user_pool_client = true
  allowed_oauth_scopes = concat(
    ["openid", "email", "profile"],
    [for scope_name in keys(local.canonical_scopes) : "${aws_cognito_resource_server.api.identifier}/${scope_name}"],
  )

  callback_urls                = var.spa_callback_urls
  logout_urls                  = var.spa_logout_urls
  supported_identity_providers = ["COGNITO"]

  explicit_auth_flows = [
    "ALLOW_REFRESH_TOKEN_AUTH",
  ]

  auth_session_validity         = 3
  enable_token_revocation       = true
  prevent_user_existence_errors = "ENABLED"

  token_validity_units {
    access_token  = "minutes"
    id_token      = "minutes"
    refresh_token = "days"
  }

  access_token_validity  = 15
  id_token_validity      = 15
  refresh_token_validity = 1
}
