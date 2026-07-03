# CI/CD layer contract outputs
# Consumed by: services layer (ECR URIs, digests), deployment orchestrator

output "contract_payload" {
  description = "Contract payload for downstream layers"
  value = {
    layer          = "cicd"
    schema_version = "1"
    state_scope    = "regional"
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
