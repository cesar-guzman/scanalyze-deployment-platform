# Account-Ready Gate — validation-only root.
# type: validation_root
# deployable: false
# produces_contract: false
# owns_state_backend: false
# creates_resources: false
#
# Consumes: verified ACCOUNT_READY v2 binding + independent registry values.
# Full roles, state infrastructure, controls, schema, and digest validation is
# performed by tooling/verify_account_ready.py before this projection reaches
# Terraform. This root binds that projection to the registry tuple fail-closed.

resource "terraform_data" "account_ready_gate" {
  lifecycle {
    precondition {
      condition     = var.account_ready_binding.schema_version == "2"
      error_message = "ACCOUNT_READY v2 is required"
    }
    precondition {
      condition     = var.account_ready_binding.customer_id == var.customer_id
      error_message = "ACCOUNT_READY customer binding does not match the registry"
    }
    precondition {
      condition     = var.account_ready_binding.deployment_id == var.deployment_id
      error_message = "ACCOUNT_READY deployment binding does not match the registry"
    }
    precondition {
      condition     = var.account_ready_binding.account_id == var.account_id
      error_message = "ACCOUNT_READY account binding does not match the registry"
    }
    precondition {
      condition     = var.account_ready_binding.region == var.region
      error_message = "ACCOUNT_READY region binding does not match the registry"
    }
    precondition {
      condition     = var.account_ready_binding.environment == var.environment
      error_message = "ACCOUNT_READY environment binding does not match the registry"
    }
    precondition {
      condition     = var.account_ready_binding.baseline_version == var.expected_baseline_version
      error_message = "ACCOUNT_READY baseline version does not match the registry"
    }
    precondition {
      condition     = var.account_ready_binding.contract_digest == var.expected_contract_digest
      error_message = "ACCOUNT_READY digest does not match the independent anchor"
    }
  }
}
