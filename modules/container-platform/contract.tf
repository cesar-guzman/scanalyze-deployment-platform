# Contract producer gate for container-platform module.
# This module produces: platform/v2
# Consumers: downstream layers that declare dependency on this contract.
#
# The contract is written by the root that calls this module,
# NOT by the module itself. The module only exposes outputs
# that the root's contracts.tf will publish to SSM.
#
# Single Contract Writer Rule (ADR-006 rev3):
# Each contract is written by EXACTLY ONE root.

# Contract output structure — root will publish this to SSM.
output "contract_payload" {
  description = "Structured contract payload for platform/v2"
  value = {
    schema_version = "2"
    layer          = local.layer_name
    state_scope    = local.state_scope
    outputs = {
      ecs_cluster_arn       = aws_ecs_cluster.main.arn
      ecs_cluster_name      = aws_ecs_cluster.main.name
      alb_arn               = aws_lb.internal.arn
      alb_dns_name          = aws_lb.internal.dns_name
      alb_listener_arn      = aws_lb_listener.https.arn
      alb_security_group_id = aws_security_group.alb.id
    }
  }
}
