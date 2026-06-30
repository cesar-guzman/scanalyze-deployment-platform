# Root: network (layer 1)
# Scope: regional
# State key: {dep_id}/{region}/network/terraform.tfstate
# Module: modules/network
#
# This root calls the network module and publishes its
# contract to SSM (when providers are configured in M2+).
#
# Rules:
# - No terraform_remote_state
# - No workspaces for customer isolation
# - No hardcoded account IDs
# - No external modules
# - No :latest in any image reference
# - No timestamp()

module "network" {
  source = "../../modules/network"

  deployment_id           = var.deployment_id
  account_id              = var.account_id
  region                  = var.region
  release_version         = var.release_version
  release_manifest_digest = var.release_manifest_digest
}
