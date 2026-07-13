# Data Foundation — SQS Queues
#
# Status: authored_not_provider_validated
#
# The six v1 worker-addressed source/DLQ pairs remain unchanged and protected
# from Terraform deletion. GUG-89 adds a separate Standard source/DLQ pair for
# every canonical v2 stage. No resource address or physical queue name is
# repurposed across the contract boundary.

resource "terraform_data" "queue_topology_gate" {
  input = local.queue_topology

  lifecycle {
    precondition {
      condition = toset(keys(local.queue_topology)) == toset([
        "ingest",
        "ocr",
        "classify",
        "bank-extract",
        "personal-extract",
        "gov-extract",
        "validate",
        "persist",
        "notify",
      ])
      error_message = "queue topology must define exactly the canonical GUG-89 stages"
    }

    precondition {
      condition = alltrue([
        for binding in values(local.queue_topology) :
        length(binding.producers) > 0 &&
        binding.consumer != "" &&
        binding.consumer_mode != "" &&
        binding.queue_type == "standard" &&
        binding.visibility_timeout_seconds > 0 &&
        binding.visibility_timeout_seconds <= 43200 &&
        binding.max_receive_count > 0 &&
        binding.max_receive_count <= 1000
      ])
      error_message = "every stage requires producers, one consumer mode, Standard queue type, visibility timeout, and retry limit"
    }

    precondition {
      condition = length(distinct([
        for binding in values(local.queue_topology) :
        "${binding.consumer}:${binding.consumer_mode}"
      ])) == length(local.queue_topology)
      error_message = "queue topology contains an ambiguous consumer/mode alias"
    }
  }
}

# data-foundation/v1 resources. Keep the exact resource names, instance keys,
# physical names, and settings. The only additive safeguard is prevent_destroy.
resource "aws_sqs_queue" "worker" {
  for_each = local.legacy_worker_queues

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

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_sqs_queue" "dlq" {
  for_each = local.legacy_worker_queues

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

  lifecycle {
    prevent_destroy = true
  }
}

# data-foundation/v2 canonical stage resources. The `-stage-` component keeps
# every physical name distinct from all v1 worker-addressed queues.
resource "aws_sqs_queue" "stage" {
  for_each = local.queue_topology

  name                       = "${var.deployment_id}-${each.key}-stage-queue"
  fifo_queue                 = false
  visibility_timeout_seconds = each.value.visibility_timeout_seconds
  message_retention_seconds  = 1209600 # 14 days
  receive_wait_time_seconds  = 20
  kms_master_key_id          = aws_kms_key.data.id

  redrive_policy = jsonencode({
    deadLetterTargetArn = aws_sqs_queue.stage_dlq[each.key].arn
    maxReceiveCount     = each.value.max_receive_count
  })

  tags = {
    deployment_id = var.deployment_id
    managed_by    = "terraform"
    layer         = "data-foundation"
    stage         = each.key
    consumer      = each.value.consumer
    consumer_mode = each.value.consumer_mode
  }
}

resource "aws_sqs_queue" "stage_dlq" {
  for_each = local.queue_topology

  name                      = "${var.deployment_id}-${each.key}-stage-dlq"
  fifo_queue                = false
  message_retention_seconds = 1209600 # 14 days
  kms_master_key_id         = aws_kms_key.data.id

  tags = {
    deployment_id = var.deployment_id
    managed_by    = "terraform"
    layer         = "data-foundation"
    stage         = each.key
    consumer      = each.value.consumer
    consumer_mode = each.value.consumer_mode
    purpose       = "dead-letter-queue"
  }
}

resource "aws_sqs_queue_redrive_allow_policy" "stage_dlq" {
  for_each = local.queue_topology

  queue_url = aws_sqs_queue.stage_dlq[each.key].id
  redrive_allow_policy = jsonencode({
    redrivePermission = "byQueue"
    sourceQueueArns   = [aws_sqs_queue.stage[each.key].arn]
  })
}
