# Root: network (layer 1)
# Scope: regional
# State key: {dep_id}/{region}/network/terraform.tfstate
# Module: modules/network
#
# Rules:
# - No terraform_remote_state
# - No workspaces for customer isolation
# - No hardcoded account IDs
# - No external modules

module "network" {
  source = "../../modules/network"

  deployment_id           = var.deployment_id
  account_id              = var.account_id
  region                  = var.region
  release_version         = var.release_version
  release_manifest_digest = var.release_manifest_digest

  upstream_contract_digest = var.upstream_contract_digest
  expected_upstream_digest = var.expected_upstream_digest

  # vpc_cidr, private/public_subnet_cidrs, vpc_endpoint_services have defaults
}
