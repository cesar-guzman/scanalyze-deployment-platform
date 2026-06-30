# Root outputs — contract payload published to SSM by orchestrator.
output "contract_payload" {
  description = "Contract payload from services module"
  value       = module.services.contract_payload
}
