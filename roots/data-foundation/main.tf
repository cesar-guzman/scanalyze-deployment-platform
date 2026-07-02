# Root: data-foundation (layer 3)
# Scope: regional
# State key: {dep_id}/{region}/data-foundation/terraform.tfstate
# Module: modules/data-foundation
#
# Rules:
# - No terraform_remote_state
# - No workspaces for customer isolation
# - No hardcoded account IDs
# - No external modules

module "data_foundation" {
  source = "../../modules/data-foundation"

  deployment_id           = var.deployment_id
  account_id              = var.account_id
  region                  = var.region
  release_version         = var.release_version
  release_manifest_digest = var.release_manifest_digest

  upstream_contract_digest = var.upstream_contract_digest
  expected_upstream_digest = var.expected_upstream_digest
}
