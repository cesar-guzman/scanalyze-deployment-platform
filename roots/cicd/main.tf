# Root: cicd (layer 6)
# Scope: regional
# State key: {dep_id}/{region}/cicd/terraform.tfstate
# Module: modules/cicd
#
# Owns:
# - CodePipeline pipelines (Source + Build only, NO ECS Deploy)
# - CodeBuild projects
# - CodeCommit repositories (sandbox source mirror)
# - ECR repositories (customer-local image store)
# - S3 artifact bucket + KMS key
# - Release metadata SSM parameters
#
# Does NOT own:
# - ECS task definitions (services layer)
# - ECS services (services layer)
# - ECS cluster (platform layer)
#
# Rules:
# - No terraform_remote_state
# - No workspaces for customer isolation
# - No hardcoded account IDs
# - No external modules
# - No ECS Deploy stage in pipelines
# - No imagedefinitions.json as deploy artifact
# - No ecs:* in IAM policies
# - No iam:PassRole with Resource "*"

module "cicd" {
  source = "../../modules/cicd"

  deployment_id = var.deployment_id
  account_id    = var.account_id
  region        = var.region

  # From platform contract
  ecs_cluster_name = var.ecs_cluster_name

  # Source configuration
  source_provider = var.source_provider
  default_branch  = var.default_branch

  # Microservice definitions
  microservices = var.microservices

  # Optional features
  enable_ecr_lifecycle_policy = var.enable_ecr_lifecycle_policy
  ecr_lifecycle_keep_last     = var.ecr_lifecycle_keep_last
  enable_release_metadata_ssm = var.enable_release_metadata_ssm
  enable_codecommit           = var.enable_codecommit

  # Upstream contract
  upstream_contract_digest = var.upstream_contract_digest
  expected_upstream_digest = var.expected_upstream_digest
}

