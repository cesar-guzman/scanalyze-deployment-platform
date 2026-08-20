# Account-Ready Gate produces no outputs.
# It is a validation-only root.
output "validation_passed" {
  description = "True only when the external ACCOUNT_READY v2 binding matches the registry"
  value       = true
}
