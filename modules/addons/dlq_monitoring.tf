# Addons — DLQ Monitoring
#
# Status: authored_not_provider_validated

resource "aws_sns_topic" "alerts" {
  name = "${var.deployment_id}-alerts"

  tags = {
    deployment_id = var.deployment_id
    managed_by    = "terraform"
    layer         = "addons"
  }
}

resource "aws_cloudwatch_metric_alarm" "dlq_depth" {
  for_each = toset(var.dlq_queue_names)

  alarm_name          = "${var.deployment_id}-${each.key}-dlq-depth"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "ApproximateNumberOfMessagesVisible"
  namespace           = "AWS/SQS"
  period              = 300
  statistic           = "Sum"
  threshold           = 0
  alarm_description   = "Messages in DLQ for ${each.key}"
  alarm_actions       = [aws_sns_topic.alerts.arn]

  dimensions = {
    QueueName = "${var.deployment_id}-${each.key}-dlq"
  }

  tags = {
    deployment_id = var.deployment_id
    managed_by    = "terraform"
    layer         = "addons"
    worker        = each.key
  }
}
