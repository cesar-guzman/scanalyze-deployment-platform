# Root: platform (layer 2)
# Scope: regional
# State key: {dep_id}/{region}/platform/terraform.tfstate
# Module: modules/container-platform
#
# Rules:
# - No terraform_remote_state
# - No workspaces for customer isolation
# - No hardcoded account IDs
# - No external modules

module "container_platform" {
  source = "../../modules/container-platform"

  deployment_id           = var.deployment_id
  account_id              = var.account_id
  region                  = var.region
  release_version         = var.release_version
  release_manifest_digest = var.release_manifest_digest

  vpc_id                   = var.vpc_id
  private_subnet_ids       = var.private_subnet_ids
  vpc_cidr_block           = var.vpc_cidr_block
  internal_certificate_arn = var.internal_certificate_arn

  upstream_contract_digest = var.upstream_contract_digest
  expected_upstream_digest = var.expected_upstream_digest
}
