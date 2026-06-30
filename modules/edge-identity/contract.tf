# Contract producer gate for edge-identity module.
# This module produces: edge-identity/v1
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
  description = "Structured contract payload for edge-identity/v1"
  value = {
    schema_version = "1"
    layer          = local.layer_name
    state_scope    = local.state_scope
  }
}
