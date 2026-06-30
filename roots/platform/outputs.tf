# Root outputs — contract payload published to SSM by orchestrator.
output "contract_payload" {
  description = "Contract payload from container-platform module"
  value       = module.container_platform.contract_payload
}
