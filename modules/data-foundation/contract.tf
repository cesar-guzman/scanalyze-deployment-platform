# Contract producer gate for data-foundation module.
# This module produces: data-foundation/v2
# Consumers: downstream layers that declare dependency on this contract.
#
# The contract is written by the root that calls this module,
# NOT by the module itself. The module only exposes outputs
# that the root's contracts.tf will publish to SSM.
#
# Single Contract Writer Rule (ADR-006 rev3):
# Each contract is written by EXACTLY ONE root.

# Contract output structure — root will publish this to SSM.
output "contract_payload" {
  description = "Structured contract payload for data-foundation/v2"
  value = {
    schema_version = "2"
    layer          = local.layer_name
    state_scope    = local.state_scope
    outputs = {
      documents_table_name  = aws_dynamodb_table.documents.name
      documents_table_arn   = aws_dynamodb_table.documents.arn
      jobs_table_name       = aws_dynamodb_table.jobs.name
      documents_bucket_name = aws_s3_bucket.documents.id
      documents_bucket_arn  = aws_s3_bucket.documents.arn
      data_kms_key_arn      = aws_kms_key.data.arn
      sqs_queue_urls        = { for key, queue in aws_sqs_queue.stage : key => queue.url }
      sqs_queue_arns        = { for key, queue in aws_sqs_queue.stage : key => queue.arn }
      sqs_dlq_urls          = { for key, queue in aws_sqs_queue.stage_dlq : key => queue.url }
      sqs_dlq_arns          = { for key, queue in aws_sqs_queue.stage_dlq : key => queue.arn }
      queue_topology        = local.queue_topology
    }
  }
}
