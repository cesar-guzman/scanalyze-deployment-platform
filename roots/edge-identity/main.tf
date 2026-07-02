# Root: edge-identity (layer 5a)
# Scope: regional
# State key: {dep_id}/{region}/edge-identity/terraform.tfstate
# Module: modules/edge-identity
#
# Rules:
# - No terraform_remote_state
# - No workspaces for customer isolation
# - No hardcoded account IDs
# - No external modules

module "edge_identity" {
  source = "../../modules/edge-identity"

  deployment_id           = var.deployment_id
  account_id              = var.account_id
  region                  = var.region
  release_version         = var.release_version
  release_manifest_digest = var.release_manifest_digest

  domain_name              = var.domain_name
  vpc_id                   = var.vpc_id
  private_subnet_ids       = var.private_subnet_ids
  alb_listener_arn         = var.alb_listener_arn
  alb_security_group_id    = var.alb_security_group_id
  api_access_log_group_arn = var.api_access_log_group_arn

  upstream_contract_digest = var.upstream_contract_digest
  expected_upstream_digest = var.expected_upstream_digest

  # api_scopes, spa_callback_urls, spa_logout_urls, cors_allowed_origins have defaults
}
