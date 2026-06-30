# Account-Ready Gate — validation-only root.
# type: validation_root
# deployable: false
# produces_contract: false
# owns_state_backend: false
# creates_resources: false
#
# Consumes: ACCOUNT_READY contract + deployment record expected values.
# Validates: fail-closed using preconditions.

resource "terraform_data" "account_ready_gate" {
  lifecycle {
    precondition {
      condition     = var.account_id != ""
      error_message = "account_id is required for ACCOUNT_READY validation"
    }
    precondition {
      condition     = var.deployment_id != ""
      error_message = "deployment_id is required for ACCOUNT_READY validation"
    }
    precondition {
      condition     = can(regex("^dep_[0-9A-HJKMNP-TV-Z]{26}$", var.deployment_id))
      error_message = "deployment_id format invalid"
    }
    precondition {
      condition     = var.account_ready_contract_digest != ""
      error_message = "ACCOUNT_READY contract digest is required"
    }
    precondition {
      condition     = var.account_ready_contract_digest == var.expected_contract_digest
      error_message = "ACCOUNT_READY contract digest does not match expected value — possible tampering"
    }
  }
}
