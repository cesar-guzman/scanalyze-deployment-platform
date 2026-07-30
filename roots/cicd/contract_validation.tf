# Contract Validation for cicd root
#
# Validates the exact data-foundation/v2 envelope before resource planning.
# terraform_data lifecycle preconditions fail the plan closed; check blocks are
# deliberately not used because they can degrade to warnings.

resource "terraform_data" "contract_gate" {
  lifecycle {
    precondition {
      condition     = var.upstream_contract_digest != ""
      error_message = "upstream contract digest is required"
    }
    precondition {
      condition     = var.expected_upstream_digest != ""
      error_message = "expected upstream contract digest is required"
    }
    precondition {
      condition     = var.upstream_contract_digest == var.expected_upstream_digest
      error_message = "upstream contract digest mismatch"
    }
    precondition {
      condition     = var.upstream_contract_id == "data-foundation/v2"
      error_message = "cicd requires the exact data-foundation/v2 contract"
    }
    precondition {
      condition     = var.upstream_schema_version == "2"
      error_message = "cicd requires data-foundation schema version 2"
    }
  }
}
