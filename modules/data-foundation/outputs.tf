# Contract-aligned outputs for data-foundation layer.
# Status: authored_not_provider_validated

output "documents_table_name" {
  description = "DynamoDB documents table name"
  value       = aws_dynamodb_table.documents.name
}

output "documents_table_arn" {
  description = "DynamoDB documents table ARN"
  value       = aws_dynamodb_table.documents.arn
}

output "jobs_table_name" {
  description = "DynamoDB jobs table name"
  value       = aws_dynamodb_table.jobs.name
}

output "sqs_queue_urls" {
  description = "Map of canonical stage name to source SQS queue URL"
  value       = { for k, v in aws_sqs_queue.stage : k => v.url }
}

output "sqs_queue_arns" {
  description = "Map of canonical stage name to source SQS queue ARN"
  value       = { for k, v in aws_sqs_queue.stage : k => v.arn }
}

output "sqs_dlq_urls" {
  description = "Map of canonical stage name to SQS DLQ URL"
  value       = { for k, v in aws_sqs_queue.stage_dlq : k => v.url }
}

output "sqs_dlq_arns" {
  description = "Map of canonical stage name to SQS DLQ ARN"
  value       = { for k, v in aws_sqs_queue.stage_dlq : k => v.arn }
}

output "queue_topology" {
  description = "Canonical GUG-89 stage producer, consumer, mode, and retry contract"
  value       = local.queue_topology
}

# Deprecated compatibility aliases. New consumers must use the canonical
# stage-oriented outputs above. Removal requires an explicit contract version.
output "worker_queue_urls" {
  description = "DEPRECATED data-foundation/v1 output: use sqs_queue_urls"
  value       = { for k, v in aws_sqs_queue.worker : k => v.url }
}

output "worker_queue_arns" {
  description = "DEPRECATED data-foundation/v1 output: use sqs_queue_arns"
  value       = { for k, v in aws_sqs_queue.worker : k => v.arn }
}

output "dlq_arns" {
  description = "DEPRECATED data-foundation/v1 output: use sqs_dlq_arns"
  value       = { for k, v in aws_sqs_queue.dlq : k => v.arn }
}

output "documents_bucket_name" {
  description = "S3 document storage bucket name"
  value       = aws_s3_bucket.documents.id
}

output "documents_bucket_arn" {
  description = "S3 document storage bucket ARN"
  value       = aws_s3_bucket.documents.arn
}

output "data_kms_key_arn" {
  description = "Application data KMS key ARN"
  value       = aws_kms_key.data.arn
}
