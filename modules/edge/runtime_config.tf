# Public runtime configuration for the portable SPA.
#
# This document contains routing and display values only. It never establishes
# tenant authority and never accepts or emits a client secret or token value.
locals {
  aws_dns_suffix = {
    aws        = "amazonaws.com"
    aws-us-gov = "amazonaws.com"
    aws-cn     = "amazonaws.com.cn"
  }[var.aws_partition]

  cognito_domain_suffix = {
    aws        = "amazoncognito.com"
    aws-us-gov = "amazoncognito.com"
    aws-cn     = "amazoncognito.com.cn"
  }[var.aws_partition]

  frontend_config_schema = jsondecode(file("${path.module}/../../schemas/frontend-config.v3.schema.json"))

  frontend_origin          = "https://${var.domain_name}"
  frontend_bucket_name     = "scanalyze-${var.account_id}-frontend"
  frontend_bucket_endpoint = "${local.frontend_bucket_name}.s3.${var.region}.${local.aws_dns_suffix}"
  api_gateway_domain       = "${var.api_gateway_id}.execute-api.${var.region}.${local.aws_dns_suffix}"
  cognito_hosted_ui_prefix = lower(replace("${var.deployment_id}-identity", "_", "-"))

  frontend_runtime_config = {
    schema_version = "3"
    config_version = var.release_version
    customer_id    = var.customer_id
    deployment_id  = var.deployment_id
    account_id     = var.account_id
    region         = var.region
    environment    = var.environment
    api_endpoint   = "${local.frontend_origin}/api"
    cognito = {
      user_pool_id             = var.cognito_user_pool_id
      spa_client_id            = var.cognito_spa_client_id
      issuer_url               = var.cognito_issuer_url
      region                   = var.region
      hosted_ui_domain         = "https://${local.cognito_hosted_ui_prefix}.auth.${var.region}.${local.cognito_domain_suffix}"
      redirect_uri             = "${local.frontend_origin}/callback"
      post_logout_redirect_uri = "${local.frontend_origin}/"
      allowed_oauth_flows      = ["code"]
      pkce_required            = true
      client_secret_embedded   = false
    }
    authorization = {
      allowed_token_uses      = var.allowed_token_uses
      action_scopes           = var.identity_action_scopes
      policy_version          = var.identity_policy_version
      policy_digest           = var.identity_policy_digest
      policy_canonicalization = var.identity_policy_canonicalization
      customer_claim_name     = "custom:customerId"
      deployment_claim_name   = "custom:deployment_id"
      id_tokens_accepted      = var.id_tokens_accepted
    }
    identity_values_authoritative = false
    features                      = var.frontend_features
  }

  frontend_runtime_config_json   = jsonencode(local.frontend_runtime_config)
  frontend_runtime_config_sha256 = "sha256:${sha256(local.frontend_runtime_config_json)}"
}

resource "terraform_data" "frontend_runtime_config_gate" {
  input = local.frontend_runtime_config_sha256

  lifecycle {
    precondition {
      condition     = var.upstream_contract_digest == var.expected_upstream_digest
      error_message = "frontend runtime config requires the exact verified edge-identity contract digest."
    }

    precondition {
      condition     = startswith(var.cognito_user_pool_id, "${var.region}_")
      error_message = "Cognito user-pool identifier must match the deployment region."
    }

    precondition {
      condition     = var.cognito_issuer_url == "https://cognito-idp.${var.region}.${local.aws_dns_suffix}/${var.cognito_user_pool_id}"
      error_message = "Cognito issuer must exactly bind the projected partition, region, and user-pool identifier."
    }

    precondition {
      condition     = var.api_gateway_endpoint == "https://${local.api_gateway_domain}"
      error_message = "API Gateway endpoint must exactly bind the projected API identifier, partition, and region."
    }

    precondition {
      condition     = var.identity_policy_digest == "sha256:34a639992f6c2312176ac7dc12c361daa38201adea6af0c0b1765a17a14754f8"
      error_message = "frontend-config/v3 requires the reviewed authorization policy digest."
    }

    precondition {
      condition     = length(local.frontend_runtime_config_json) <= local.frontend_config_schema["x-maxDocumentBytes"]
      error_message = "frontend-config/v3 must not exceed the browser's canonical 65,536-byte limit."
    }

    precondition {
      condition     = var.frontend_bucket_domain_name == local.frontend_bucket_endpoint
      error_message = "frontend bucket origin must be the exact deployment-account regional bucket endpoint."
    }

    precondition {
      condition = (
        local.frontend_runtime_config.cognito.hosted_ui_domain == "https://${local.cognito_hosted_ui_prefix}.auth.${var.region}.${local.cognito_domain_suffix}" &&
        local.frontend_runtime_config.cognito.redirect_uri == "https://${var.domain_name}/callback" &&
        local.frontend_runtime_config.cognito.post_logout_redirect_uri == "https://${var.domain_name}/" &&
        local.frontend_runtime_config.api_endpoint == "https://${var.domain_name}/api"
      )
      error_message = "frontend runtime endpoints must remain bound to the exact deployment origin."
    }
  }
}

# Terraform owns the only mutable runtime-config object. Promotion publishes
# immutable build assets; it cannot hand-edit or independently replace config.
resource "aws_s3_object" "frontend_runtime_config" {
  bucket             = local.frontend_bucket_name
  key                = "${var.deployment_id}/config.json"
  content            = local.frontend_runtime_config_json
  content_type       = "application/json"
  cache_control      = "no-store, max-age=0, must-revalidate"
  checksum_algorithm = "SHA256"
  source_hash        = local.frontend_runtime_config_sha256

  lifecycle {
    prevent_destroy = true
  }

  depends_on = [terraform_data.frontend_runtime_config_gate]
}
