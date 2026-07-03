# CI/CD module contract outputs

output "artifact_bucket_name" {
  value = aws_s3_bucket.artifacts.id
}

output "artifact_kms_key_arn" {
  value = aws_kms_key.artifacts.arn
}

output "ecr_repository_urls" {
  description = "Map of ECR repo name to repository URL"
  value       = { for name, repo in aws_ecr_repository.service : name => repo.repository_url }
}

output "ecr_repository_arns" {
  description = "Map of ECR repo name to repository ARN"
  value       = { for name, repo in aws_ecr_repository.service : name => repo.arn }
}

output "pipeline_arns" {
  description = "Map of service name to pipeline ARN"
  value       = { for name, pipeline in aws_codepipeline.this : name => pipeline.arn }
}

output "pipeline_names" {
  description = "Map of service name to pipeline name"
  value       = { for name, pipeline in aws_codepipeline.this : name => pipeline.name }
}

output "codecommit_clone_urls" {
  description = "Map of service name to CodeCommit clone URL"
  value       = { for name, repo in aws_codecommit_repository.service : name => repo.clone_url_http }
}

output "release_metadata" {
  description = "Map of service name to SSM parameter paths for release tracking"
  value = {
    for name, svc in local.microservices : name => {
      image_tag_parameter    = var.enable_release_metadata_ssm ? "${local.release_metadata_namespace}/${name}/image_tag" : null
      image_digest_parameter = var.enable_release_metadata_ssm ? "${local.release_metadata_namespace}/${name}/image_digest" : null
    }
  }
}

output "codebuild_role_arn" {
  value = aws_iam_role.codebuild.arn
}

output "codepipeline_role_arn" {
  value = aws_iam_role.codepipeline.arn
}
