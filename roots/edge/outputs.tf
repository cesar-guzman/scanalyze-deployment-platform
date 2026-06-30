# Root outputs — contract payload published to SSM by orchestrator.
output "contract_payload" {
  description = "Contract payload from edge module"
  value       = module.edge.contract_payload
}
