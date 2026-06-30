# Root: services (layer 4)
# Scope: regional
# State key: {dep_id}/{region}/services/terraform.tfstate
# Module: modules/services
#
# This root calls the services module and publishes its
# contract to SSM (when providers are configured in M2+).
#
# Rules:
# - No terraform_remote_state
# - No workspaces for customer isolation
# - No hardcoded account IDs
# - No external modules
# - No :latest in any image reference
# - No timestamp()

module "services" {
  source = "../../modules/services"

  deployment_id           = var.deployment_id
  account_id              = var.account_id
  region                  = var.region
  release_version         = var.release_version
  release_manifest_digest = var.release_manifest_digest
}
