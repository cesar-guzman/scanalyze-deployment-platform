module "identity_control_plane" {
  source = "../../modules/identity-control-plane"

  customer_id                      = var.customer_id
  deployment_id                    = var.deployment_id
  account_id                       = var.account_id
  region                           = var.region
  aws_partition                    = var.aws_partition
  runtime_permissions_boundary_arn = var.global_contract.identity_runtime_permissions_boundary_arn
  release_version                  = var.release_version
  release_manifest_digest          = var.release_manifest_digest
  policy_version                   = var.policy_version
  policy_digest                    = var.policy_digest

  spa_callback_urls = var.spa_callback_urls
  spa_logout_urls   = var.spa_logout_urls

  pre_token_s3_bucket         = var.release_manifest_contract.pre_token_artifact.bucket
  pre_token_s3_key            = var.release_manifest_contract.pre_token_artifact.key
  pre_token_s3_object_version = var.release_manifest_contract.pre_token_artifact.object_version
  pre_token_source_code_hash  = var.release_manifest_contract.pre_token_artifact.sha256_b64

  control_processor_s3_bucket         = var.release_manifest_contract.control_processor_artifact.bucket
  control_processor_s3_key            = var.release_manifest_contract.control_processor_artifact.key
  control_processor_s3_object_version = var.release_manifest_contract.control_processor_artifact.object_version
  control_processor_source_code_hash  = var.release_manifest_contract.control_processor_artifact.sha256_b64
  control_processor_enabled           = var.control_processor_enabled
  m2m_bindings                        = var.m2m_registry_contract.m2m_bindings

  alarm_actions = var.alarm_actions

  depends_on = [terraform_data.contract_gate]
}
