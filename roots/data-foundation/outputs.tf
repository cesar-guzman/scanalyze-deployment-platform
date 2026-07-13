# Root outputs — contract payload published to SSM by orchestrator.
output "contract_payload" {
  description = "Contract payload from data-foundation module"
  value       = module.data_foundation.contract_payload
}

output "documents_table_name" {
  description = "DynamoDB documents table name contract"
  value       = module.data_foundation.documents_table_name
}

output "documents_table_arn" {
  description = "DynamoDB documents table ARN contract"
  value       = module.data_foundation.documents_table_arn
}

output "jobs_table_name" {
  description = "DynamoDB jobs table name contract"
  value       = module.data_foundation.jobs_table_name
}

output "documents_bucket_name" {
  description = "Document bucket name contract"
  value       = module.data_foundation.documents_bucket_name
}

output "documents_bucket_arn" {
  description = "Document bucket ARN contract"
  value       = module.data_foundation.documents_bucket_arn
}

output "data_kms_key_arn" {
  description = "Application data KMS key ARN contract"
  value       = module.data_foundation.data_kms_key_arn
}

output "sqs_queue_urls" {
  description = "Canonical stage to source SQS queue URL contract"
  value       = module.data_foundation.sqs_queue_urls
}

output "sqs_queue_arns" {
  description = "Canonical stage to source SQS queue ARN contract"
  value       = module.data_foundation.sqs_queue_arns
}

output "sqs_dlq_urls" {
  description = "Canonical stage to SQS DLQ URL contract"
  value       = module.data_foundation.sqs_dlq_urls
}

output "sqs_dlq_arns" {
  description = "Canonical stage to SQS DLQ ARN contract"
  value       = module.data_foundation.sqs_dlq_arns
}

output "queue_topology" {
  description = "Canonical GUG-89 queue producer and consumer contract"
  value       = module.data_foundation.queue_topology
}
