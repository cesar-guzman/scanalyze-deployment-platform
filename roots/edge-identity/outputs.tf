# Root outputs — contract payload published to SSM by orchestrator.
output "contract_payload" {
  description = "Contract payload from edge-identity module"
  value       = module.edge_identity.contract_payload
}
