resource "aws_sqs_queue" "bootstrap_dlq" {
  name                        = "${local.identity_prefix}-bootstrap-dlq.fifo"
  fifo_queue                  = true
  content_based_deduplication = false
  message_retention_seconds   = 1209600
  sqs_managed_sse_enabled     = true

  lifecycle {
    prevent_destroy = true
  }

  tags = merge(local.common_tags, {
    purpose = "bootstrap-dead-letter"
  })
}

resource "aws_sqs_queue" "bootstrap" {
  name                        = "${local.identity_prefix}-bootstrap.fifo"
  fifo_queue                  = true
  content_based_deduplication = false
  message_retention_seconds   = 86400
  visibility_timeout_seconds  = 90
  sqs_managed_sse_enabled     = true

  redrive_policy = jsonencode({
    deadLetterTargetArn = aws_sqs_queue.bootstrap_dlq.arn
    maxReceiveCount     = 3
  })

  lifecycle {
    prevent_destroy = true
  }

  tags = merge(local.common_tags, {
    purpose = "one-use-bootstrap-requests"
  })
}

resource "aws_sqs_queue_redrive_allow_policy" "bootstrap_dlq" {
  queue_url = aws_sqs_queue.bootstrap_dlq.id

  redrive_allow_policy = jsonencode({
    redrivePermission = "byQueue"
    sourceQueueArns   = [aws_sqs_queue.bootstrap.arn]
  })
}

resource "aws_cloudwatch_metric_alarm" "identity_control_plane" {
  for_each = local.alarm_definitions

  alarm_name          = "${local.identity_prefix}-${each.key}"
  alarm_description   = "Identity control plane alarm: ${each.key}"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = each.value.metric_name
  namespace           = each.value.namespace
  period              = 60
  statistic           = "Sum"
  threshold           = each.value.threshold
  treat_missing_data  = "notBreaching"
  dimensions          = each.value.dimensions
  alarm_actions       = var.alarm_actions

  tags = local.common_tags
}
