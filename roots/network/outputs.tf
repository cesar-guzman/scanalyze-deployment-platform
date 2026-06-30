# Root outputs — contract payload published to SSM by orchestrator.
output "contract_payload" {
  description = "Contract payload from network module"
  value       = module.network.contract_payload
}
