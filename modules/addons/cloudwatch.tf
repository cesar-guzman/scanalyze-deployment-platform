# Addons — CloudWatch Dashboard and Service Alarms
#
# Status: authored_not_provider_validated

resource "aws_cloudwatch_dashboard" "main" {
  dashboard_name = "${var.deployment_id}-overview"

  dashboard_body = jsonencode({
    widgets = [
      {
        type   = "metric"
        x      = 0
        y      = 0
        width  = 12
        height = 6
        properties = {
          metrics = [
            for svc in var.service_names : [
              "AWS/ECS", "CPUUtilization",
              "ClusterName", "${var.deployment_id}-cluster",
              "ServiceName", "${var.deployment_id}-${svc}"
            ]
          ]
          period = 300
          stat   = "Average"
          region = var.region
          title  = "ECS CPU Utilization"
        }
      },
      {
        type   = "metric"
        x      = 12
        y      = 0
        width  = 12
        height = 6
        properties = {
          metrics = [
            for svc in var.service_names : [
              "AWS/ECS", "MemoryUtilization",
              "ClusterName", "${var.deployment_id}-cluster",
              "ServiceName", "${var.deployment_id}-${svc}"
            ]
          ]
          period = 300
          stat   = "Average"
          region = var.region
          title  = "ECS Memory Utilization"
        }
      }
    ]
  })
}

resource "aws_cloudwatch_metric_alarm" "service_cpu" {
  for_each = toset(var.service_names)

  alarm_name          = "${var.deployment_id}-${each.key}-cpu-high"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 3
  metric_name         = "CPUUtilization"
  namespace           = "AWS/ECS"
  period              = 300
  statistic           = "Average"
  threshold           = 80
  alarm_description   = "CPU utilization above 80% for ${each.key}"
  alarm_actions       = [aws_sns_topic.alerts.arn]

  dimensions = {
    ClusterName = "${var.deployment_id}-cluster"
    ServiceName = "${var.deployment_id}-${each.key}"
  }

  tags = {
    deployment_id = var.deployment_id
    managed_by    = "terraform"
    layer         = "addons"
    service       = each.key
  }
}

resource "aws_cloudwatch_log_group" "service" {
  for_each = toset(var.service_names)

  name              = "/ecs/${var.deployment_id}/${each.key}"
  retention_in_days = 90

  tags = {
    deployment_id = var.deployment_id
    managed_by    = "terraform"
    layer         = "addons"
    service       = each.key
  }
}
