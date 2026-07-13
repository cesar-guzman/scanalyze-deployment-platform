module "edge_identity" {
  source = "../../modules/edge-identity"

  customer_id             = var.customer_id
  deployment_id           = var.deployment_id
  account_id              = var.account_id
  region                  = var.region
  aws_partition           = var.identity_contract.aws_partition
  release_version         = var.release_version
  release_manifest_digest = var.release_manifest_digest

  domain_name              = var.domain_name
  vpc_id                   = var.services_contract.vpc_id
  private_subnet_ids       = var.services_contract.private_subnet_ids
  alb_listener_arn         = var.services_contract.alb_listener_arn
  alb_security_group_id    = var.services_contract.alb_security_group_id
  api_access_log_group_arn = var.services_contract.api_access_log_group_arn

  upstream_contract_digest = var.identity_contract.contract_digest
  expected_upstream_digest = var.expected_identity_contract_digest

  cognito_user_pool_id             = var.identity_contract.cognito_user_pool_id
  cognito_issuer_url               = var.identity_contract.cognito_issuer_url
  cognito_spa_client_id            = var.identity_contract.cognito_spa_client_id
  cognito_m2m_client_ids           = var.identity_contract.m2m_client_ids
  identity_action_scopes           = var.identity_contract.action_scopes
  identity_policy_version          = var.identity_contract.policy_version
  identity_policy_digest           = var.identity_contract.policy_digest
  identity_policy_canonicalization = var.identity_contract.policy_canonicalization

  cors_allowed_origins     = var.cors_allowed_origins
  api_authorization_routes = var.api_authorization_routes

  legacy_identity_handoff_complete = var.legacy_identity_handoff_complete

  depends_on = [terraform_data.contract_gate]
}
