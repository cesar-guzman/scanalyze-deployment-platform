# Every HTTP service has one explicitly reviewed listener association.
# Paths select a target without rewriting the API's /api/v1 or /api/v2 prefix.
resource "aws_lb_listener_rule" "service" {
  for_each = {
    for name, route in var.alb_service_routes : name => route
    if contains([for svc in var.service_definitions : svc.name if svc.port != null], name)
  }

  listener_arn = var.alb_listener_arn
  priority     = each.value.priority

  action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.service[each.key].arn
  }

  condition {
    path_pattern {
      values = each.value.path_patterns
    }
  }

  tags = {
    deployment_id = var.deployment_id
    managed_by    = "terraform"
    layer         = "services"
    service       = each.key
  }
}
