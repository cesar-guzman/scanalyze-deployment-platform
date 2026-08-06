# Root outputs — contract payload published to SSM by orchestrator.
output "contract_payload" {
  description = "Contract payload from edge module"
  value       = module.edge.contract_payload
}

output "frontend_runtime_config" {
  description = "Closed public frontend-config/v3 object"
  value       = module.edge.frontend_runtime_config
  sensitive   = false
}

output "frontend_runtime_config_json" {
  description = "Deterministic JSON encoding of frontend-config/v3"
  value       = module.edge.frontend_runtime_config_json
  sensitive   = false
}

output "frontend_runtime_config_sha256" {
  description = "SHA-256 digest of the exact frontend-config/v3 JSON bytes"
  value       = module.edge.frontend_runtime_config_sha256
  sensitive   = false
}
