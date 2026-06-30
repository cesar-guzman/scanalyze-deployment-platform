# Data Foundation — SQS Queues
#
# Status: authored_not_provider_validated
#
# One queue per worker + DLQ per queue.

locals {
  worker_queues = toset([
    "ocr",
    "postprocess",
    "classifier",
    "bank",
    "personal",
    "gov",
  ])
}

resource "aws_sqs_queue" "worker" {
  for_each = local.worker_queues

  name                       = "${var.deployment_id}-${each.key}-queue"
  visibility_timeout_seconds = 300
  message_retention_seconds  = 1209600 # 14 days
  kms_master_key_id          = aws_kms_key.data.id

  redrive_policy = jsonencode({
    deadLetterTargetArn = aws_sqs_queue.dlq[each.key].arn
    maxReceiveCount     = 3
  })

  tags = {
    deployment_id = var.deployment_id
    managed_by    = "terraform"
    layer         = "data-foundation"
    worker        = each.key
  }
}

resource "aws_sqs_queue" "dlq" {
  for_each = local.worker_queues

  name                      = "${var.deployment_id}-${each.key}-dlq"
  message_retention_seconds = 1209600 # 14 days
  kms_master_key_id         = aws_kms_key.data.id

  tags = {
    deployment_id = var.deployment_id
    managed_by    = "terraform"
    layer         = "data-foundation"
    worker        = each.key
    purpose       = "dead-letter-queue"
  }
}
