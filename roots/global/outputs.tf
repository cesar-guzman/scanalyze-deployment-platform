# Root outputs — contract payload published to SSM by orchestrator.
output "contract_payload" {
  description = "Contract payload from global module"
  value       = module.global.contract_payload
}
