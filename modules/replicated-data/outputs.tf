# replicated-data is a sub-module of data-foundation.
# No independent outputs — data-foundation aggregates these.

output "replica_table_arns" {
  description = "Map of table name to replica DynamoDB table ARN"
  value       = {} # M1: no-op skeleton
}

output "replica_kms_key_arns" {
  description = "Map of region to replica KMS key ARN"
  value       = {} # M1: no-op skeleton
}
