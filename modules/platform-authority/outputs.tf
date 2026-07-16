output "kms_key_arn" {
  description = "KMS key protecting platform-authority control metadata."
  value       = aws_kms_key.control_plane.arn
}

output "release_bucket_arn" {
  description = "Authority-owned release bucket ARN."
  value       = aws_s3_bucket.releases.arn
}

output "registry_table_arn" {
  description = "Deployment registry table ARN."
  value       = aws_dynamodb_table.deployment_registry.arn
}

output "execution_ledger_table_arn" {
  description = "Live execution ledger table ARN."
  value       = aws_dynamodb_table.execution_ledger.arn
}

output "github_oidc_provider_arn" {
  description = "GitHub Actions OIDC provider ARN."
  value       = aws_iam_openid_connect_provider.github.arn
}

output "orchestrator_role_arns" {
  description = "Deployment ID to exact platform-authority orchestrator role ARN."
  value       = { for key, role in aws_iam_role.orchestrator : key => role.arn }
}
