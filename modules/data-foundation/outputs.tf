output "dynamodb_table_arns" {
  description = "Map of table name to DynamoDB table ARN"
  value       = {} # M1: interface skeleton
}

output "s3_document_bucket_arns" {
  description = "Map of bucket purpose to S3 bucket ARN"
  value       = {} # M1: interface skeleton
}

output "sqs_queue_urls" {
  description = "Map of queue name to SQS queue URL"
  value       = {} # M1: interface skeleton
}

output "sqs_dlq_urls" {
  description = "Map of queue name to SQS DLQ URL"
  value       = {} # M1: interface skeleton
}

output "kms_key_arns" {
  description = "Map of purpose to KMS key ARN"
  value       = {} # M1: interface skeleton
}
