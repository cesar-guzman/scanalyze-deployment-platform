# CI/CD layer contract outputs
# Consumed by: services layer (ECR URIs, digests), deployment orchestrator

output "contract_payload" {
  description = "Contract payload for downstream layers"
  value = {
    layer          = "cicd"
    schema_version = "2"
    state_scope    = "regional"
    outputs = {
      artifact_bucket_name  = module.cicd.artifact_bucket_name
      artifact_kms_key_arn  = module.cicd.artifact_kms_key_arn
      ecr_repository_urls   = module.cicd.ecr_repository_urls
      ecr_repository_arns   = module.cicd.ecr_repository_arns
      pipeline_arns         = module.cicd.pipeline_arns
      pipeline_names        = module.cicd.pipeline_names
      codecommit_clone_urls = module.cicd.codecommit_clone_urls
      release_metadata      = module.cicd.release_metadata
      codebuild_role_arn    = module.cicd.codebuild_role_arn
      codepipeline_role_arn = module.cicd.codepipeline_role_arn
    }
  }
}

output "artifact_bucket_name" {
  description = "S3 bucket name for CI/CD artifacts"
  value       = module.cicd.artifact_bucket_name
}

output "artifact_kms_key_arn" {
  description = "KMS key ARN for artifact encryption"
  value       = module.cicd.artifact_kms_key_arn
}

output "ecr_repository_urls" {
  description = "Map of service name to ECR repository URL"
  value       = module.cicd.ecr_repository_urls
}

output "pipeline_arns" {
  description = "Map of service name to CodePipeline ARN"
  value       = module.cicd.pipeline_arns
}

output "release_metadata" {
  description = "Map of service name to SSM parameter paths for image metadata"
  value       = module.cicd.release_metadata
}
