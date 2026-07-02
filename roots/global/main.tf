# Root: global (layer 0)
# Scope: global
# State key: {dep_id}/global/terraform.tfstate
# Module: modules/global
#
# Rules:
# - No terraform_remote_state
# - No workspaces for customer isolation
# - No hardcoded account IDs
# - No external modules

module "global" {
  source = "../../modules/global"

  deployment_id           = var.deployment_id
  account_id              = var.account_id
  region                  = var.region
  release_version         = var.release_version
  release_manifest_digest = var.release_manifest_digest

  # service_names and ecs_task_execution_managed_policies have defaults in module
}
