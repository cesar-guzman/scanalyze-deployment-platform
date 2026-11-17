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
  aws_partition           = var.aws_partition
  release_version         = var.release_version
  release_manifest_digest = var.release_manifest_digest

  # GUG-541: models and SSM prefix the workload identity policies allow.
  bedrock_classifier_model_ids  = var.bedrock_classifier_model_ids
  bedrock_extractor_model_ids   = var.bedrock_extractor_model_ids
  runtime_parameter_path_prefix = var.runtime_parameter_path_prefix

  # service_names and ecs_task_execution_managed_policies have defaults in module
}
