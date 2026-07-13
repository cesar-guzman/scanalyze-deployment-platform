mock_provider "aws" {}

variables {
  deployment_id            = "dep_01ARZ3NDEKTSV4RRFFQ69G5FAV"
  account_id               = "000000000000"
  region                   = "us-east-1"
  release_version          = "v0.0.0-synthetic"
  release_manifest_digest  = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
  upstream_contract_digest = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
  expected_upstream_digest = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
}

run "declares_complete_standard_queue_topology" {
  command = plan

  assert {
    condition = toset(keys(output.queue_topology)) == toset([
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
    error_message = "queue topology must contain every canonical GUG-89 stage"
  }

  assert {
    condition = alltrue([
      for binding in values(output.queue_topology) :
      binding.queue_type == "standard" &&
      length(binding.producers) > 0 &&
      binding.consumer != "" &&
      binding.consumer_mode != "" &&
      binding.visibility_timeout_seconds > 0 &&
      binding.max_receive_count > 0
    ])
    error_message = "each stage must be Standard and have a complete producer/consumer/retry binding"
  }

  assert {
    condition     = length(output.sqs_queue_urls) == 9 && length(output.sqs_dlq_urls) == 9
    error_message = "every canonical stage must expose one source queue and one DLQ URL"
  }

  assert {
    condition     = length(output.sqs_queue_arns) == 9 && length(output.sqs_dlq_arns) == 9
    error_message = "every canonical stage must expose one source queue and one DLQ ARN"
  }

  assert {
    condition = (
      length(aws_sqs_queue.worker) == 6 &&
      length(aws_sqs_queue.dlq) == 6 &&
      length(aws_sqs_queue.stage) == 9 &&
      length(aws_sqs_queue.stage_dlq) == 9 &&
      length(aws_sqs_queue_redrive_allow_policy.stage_dlq) == 9
    )
    error_message = "legacy resources must remain while every canonical stage receives an additive source, DLQ, and redrive policy"
  }

  assert {
    condition = alltrue([
      for stage, policy in aws_sqs_queue_redrive_allow_policy.stage_dlq :
      jsondecode(policy.redrive_allow_policy).redrivePermission == "byQueue" &&
      jsondecode(policy.redrive_allow_policy).sourceQueueArns == [aws_sqs_queue.stage[stage].arn]
    ])
    error_message = "each DLQ must accept redrive only from its exact source queue"
  }

  assert {
    condition = alltrue([
      for key, queue in aws_sqs_queue.worker :
      queue.name == "${var.deployment_id}-${key}-queue"
      ]) && alltrue([
      for key, queue in aws_sqs_queue.dlq :
      queue.name == "${var.deployment_id}-${key}-dlq"
    ])
    error_message = "legacy queue addresses must retain their original physical names"
  }

  assert {
    condition = alltrue([
      for key, queue in aws_sqs_queue.stage :
      queue.name == "${var.deployment_id}-${key}-stage-queue"
      ]) && alltrue([
      for key, queue in aws_sqs_queue.stage_dlq :
      queue.name == "${var.deployment_id}-${key}-stage-dlq"
    ])
    error_message = "canonical stage queues must use collision-free v2 physical names"
  }

  assert {
    condition = (
      length(output.worker_queue_urls) == 6 &&
      length(output.worker_queue_arns) == 6 &&
      length(output.dlq_arns) == 6
    )
    error_message = "deprecated outputs must continue exposing exactly the legacy worker resources"
  }
}
