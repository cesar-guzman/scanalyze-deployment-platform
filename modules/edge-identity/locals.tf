locals {
  # Layer metadata
  layer_name     = "edge-identity"
  layer_number   = "5a"
  state_scope    = "regional"  # "global" or "regional"

  # Contract identity binding
  contract_key = "edge-identity/v1"
}
