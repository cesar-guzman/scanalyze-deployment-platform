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

# Service log groups are owned and created by the services layer
# (modules/services/logs.tf, GUG-108), before the first task starts. This
# layer only publishes their deterministic names in its contract.
locals {
  service_log_group_names = { for service in var.service_names : service => "/ecs/${var.deployment_id}/${service}" }
}
