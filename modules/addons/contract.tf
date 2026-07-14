# Contract producer gate for addons module.
# This module produces: addons/v2
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
  description = "Structured contract payload for addons/v2"
  value = {
    schema_version = "2"
    layer          = local.layer_name
    state_scope    = local.state_scope
    outputs = {
      dashboard_name   = aws_cloudwatch_dashboard.main.dashboard_name
      alerts_topic_arn = aws_sns_topic.alerts.arn
      log_group_names  = { for key, group in aws_cloudwatch_log_group.service : key => group.name }
    }
  }
}
