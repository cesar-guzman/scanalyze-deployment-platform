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

output "worker_queue_urls" {
  description = "Map of worker name to SQS queue URL"
  value       = { for k, v in aws_sqs_queue.worker : k => v.url }
}

output "worker_queue_arns" {
  description = "Map of worker name to SQS queue ARN"
  value       = { for k, v in aws_sqs_queue.worker : k => v.arn }
}

output "dlq_arns" {
  description = "Map of worker name to DLQ ARN"
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
