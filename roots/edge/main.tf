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

  deployment_id           = var.deployment_id
  account_id              = var.account_id
  region                  = var.region
  release_version         = var.release_version
  release_manifest_digest = var.release_manifest_digest

  domain_name                 = var.domain_name
  route53_zone_id             = var.route53_zone_id
  api_gateway_endpoint        = var.api_gateway_endpoint
  frontend_bucket_domain_name = var.frontend_bucket_domain_name

  upstream_contract_digest = var.upstream_contract_digest
  expected_upstream_digest = var.expected_upstream_digest

  # domain_aliases has a default
}
