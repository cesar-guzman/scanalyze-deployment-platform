# Root: edge (layer 5a+)
# Scope: global
# State key: {dep_id}/edge/terraform.tfstate
# Module: modules/edge
#
# Rules:
# - No terraform_remote_state
# - No workspaces for customer isolation
# - No hardcoded account IDs
# - No external modules

module "edge" {
  source = "../../modules/edge"

  providers = {
    aws           = aws
    aws.us_east_1 = aws.us_east_1
  }

  customer_id             = var.customer_id
  deployment_id           = var.deployment_id
  account_id              = var.account_id
  region                  = var.region
  environment             = var.environment
  release_version         = var.release_version
  release_manifest_digest = var.release_manifest_digest

  domain_name                 = var.domain_name
  route53_zone_id             = var.route53_zone_id
  api_gateway_id              = var.api_gateway_id
  api_gateway_endpoint        = var.api_gateway_endpoint
  frontend_bucket_domain_name = var.frontend_bucket_domain_name

  aws_partition                    = var.aws_partition
  cognito_user_pool_id             = var.cognito_user_pool_id
  cognito_issuer_url               = var.cognito_issuer_url
  cognito_spa_client_id            = var.cognito_spa_client_id
  allowed_token_uses               = var.allowed_token_uses
  identity_action_scopes           = var.identity_action_scopes
  identity_policy_version          = var.identity_policy_version
  identity_policy_digest           = var.identity_policy_digest
  identity_policy_canonicalization = var.identity_policy_canonicalization
  id_tokens_accepted               = var.id_tokens_accepted
  frontend_features                = var.frontend_features

  upstream_contract_digest = var.upstream_contract_digest
  expected_upstream_digest = var.expected_upstream_digest

  # domain_aliases has a default
}
