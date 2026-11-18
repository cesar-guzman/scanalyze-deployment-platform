# Services layer — service log groups (GUG-108)
#
# The ownership matrix assigns service log groups to this layer
# (ADR/ARCHITECTURE_OWNERSHIP_MATRIX.md). They must exist before the first task
# starts, because the awslogs driver does not create them.

resource "aws_cloudwatch_log_group" "service" {
  for_each = { for svc in var.service_definitions : svc.name => svc }

  name              = "/ecs/${var.deployment_id}/${each.key}"
  retention_in_days = var.service_log_retention_days

  tags = {
    deployment_id = var.deployment_id
    managed_by    = "terraform"
    layer         = "services"
    service       = each.key
  }
}
