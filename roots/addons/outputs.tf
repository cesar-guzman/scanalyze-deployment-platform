# Root outputs — contract payload published to SSM by orchestrator.
output "contract_payload" {
  description = "Contract payload from addons module"
  value       = module.addons.contract_payload
}
