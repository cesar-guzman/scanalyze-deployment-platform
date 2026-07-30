output "contract_payload" {
  description = "Portable platform-authority contract."
  value       = module.platform_authority.contract_payload
}

output "orchestrator_role_arns" {
  description = "Deployment ID to exact orchestrator role ARN."
  value       = module.platform_authority.orchestrator_role_arns
}

output "release_bucket_arn" {
  description = "Platform-authority release bucket ARN."
  value       = module.platform_authority.release_bucket_arn
}

output "kms_key_arn" {
  description = "Platform-authority KMS key ARN."
  value       = module.platform_authority.kms_key_arn
}
