# Contract Validation for cicd root
#
# Validates upstream contract digest matches expected value.
# Uses terraform check block (TF 1.5+), no extra provider needed.

check "upstream_contract_digest" {
  assert {
    condition     = var.upstream_contract_digest == "" || var.expected_upstream_digest == "" || var.upstream_contract_digest == var.expected_upstream_digest
    error_message = "Upstream contract digest mismatch. Platform contract changed — review before applying cicd."
  }
}
