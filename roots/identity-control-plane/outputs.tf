output "contract_payload" {
  description = "Publisher-compatible identity-control-plane/v1 contract for sanitized publication."
  value       = module.identity_control_plane.contract_payload
}
