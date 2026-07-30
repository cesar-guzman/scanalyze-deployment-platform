# Contract producer gate for network module.
# This module produces: network/v2
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
  description = "Structured contract payload for network/v2"
  value = {
    schema_version = "2"
    layer          = local.layer_name
    state_scope    = local.state_scope
    outputs = {
      vpc_id             = aws_vpc.main.id
      private_subnet_ids = { for key, subnet in aws_subnet.private : key => subnet.id }
      public_subnet_ids  = { for key, subnet in aws_subnet.public : key => subnet.id }
      vpc_cidr_block     = aws_vpc.main.cidr_block
      vpc_endpoint_sg_id = aws_security_group.vpc_endpoints.id
    }
  }
}
