# Platform SSM Contract Outputs
#
# Status: authored_not_provider_validated
#
# Publishes platform layer outputs to SSM for downstream layers
# (cicd, services, addons) to consume without terraform_remote_state.

resource "aws_ssm_parameter" "ecs_cluster_name" {
  name      = "/${var.deployment_id}/layers/platform/outputs/ecs_cluster_name"
  type      = "String"
  value     = aws_ecs_cluster.main.name
  overwrite = true

  tags = {
    layer    = "platform"
    contract = "platform/v1"
  }
}

resource "aws_ssm_parameter" "ecs_cluster_arn" {
  name      = "/${var.deployment_id}/layers/platform/outputs/ecs_cluster_arn"
  type      = "String"
  value     = aws_ecs_cluster.main.arn
  overwrite = true

  tags = {
    layer    = "platform"
    contract = "platform/v1"
  }
}

resource "aws_ssm_parameter" "alb_dns_name" {
  name      = "/${var.deployment_id}/layers/platform/outputs/alb_dns_name"
  type      = "String"
  value     = aws_lb.internal.dns_name
  overwrite = true

  tags = {
    layer    = "platform"
    contract = "platform/v1"
  }
}

resource "aws_ssm_parameter" "alb_listener_arn" {
  name      = "/${var.deployment_id}/layers/platform/outputs/alb_listener_arn"
  type      = "String"
  value     = aws_lb_listener.https.arn
  overwrite = true

  tags = {
    layer    = "platform"
    contract = "platform/v1"
  }
}

resource "aws_ssm_parameter" "alb_security_group_id" {
  name      = "/${var.deployment_id}/layers/platform/outputs/alb_security_group_id"
  type      = "String"
  value     = aws_security_group.alb.id
  overwrite = true

  tags = {
    layer    = "platform"
    contract = "platform/v1"
  }
}
