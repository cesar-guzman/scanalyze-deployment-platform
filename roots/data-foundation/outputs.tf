# Root outputs — contract payload published to SSM by orchestrator.
output "contract_payload" {
  description = "Contract payload from data-foundation module"
  value       = module.data_foundation.contract_payload
}
