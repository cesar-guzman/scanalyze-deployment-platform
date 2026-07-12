# Root: services (layer 4)
# Scope: regional
# State key: {dep_id}/{region}/services/terraform.tfstate
# Module: modules/services
#
# Rules:
# - No terraform_remote_state
# - No workspaces for customer isolation
# - No hardcoded account IDs
# - No external modules

module "services" {
  source = "../../modules/services"

  deployment_id           = var.deployment_id
  customer_id             = var.customer_id
  account_id              = var.account_id
  region                  = var.region
  release_version         = var.release_version
  release_manifest_digest = var.release_manifest_digest

  ecs_cluster_arn             = var.ecs_cluster_arn
  ecs_task_execution_role_arn = var.ecs_task_execution_role_arn
  workload_role_arns          = var.workload_role_arns
  vpc_id                      = var.vpc_id
  private_subnet_ids          = var.private_subnet_ids
  alb_listener_arn            = var.alb_listener_arn
  alb_security_group_id       = var.alb_security_group_id
  service_definitions         = var.service_definitions

  upstream_contract_digest = var.upstream_contract_digest
  expected_upstream_digest = var.expected_upstream_digest
}
