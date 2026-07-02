# Root: addons (layer 5b)
# Scope: regional
# State key: {dep_id}/{region}/addons/terraform.tfstate
# Module: modules/addons
#
# Rules:
# - No terraform_remote_state
# - No workspaces for customer isolation
# - No hardcoded account IDs
# - No external modules

module "addons" {
  source = "../../modules/addons"

  deployment_id           = var.deployment_id
  account_id              = var.account_id
  region                  = var.region
  release_version         = var.release_version
  release_manifest_digest = var.release_manifest_digest

  upstream_contract_digest = var.upstream_contract_digest
  expected_upstream_digest = var.expected_upstream_digest

  # service_names and dlq_queue_names have defaults
}
