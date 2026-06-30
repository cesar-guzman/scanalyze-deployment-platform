locals {
  # Layer metadata
  layer_name   = "container-platform"
  layer_number = "2"
  state_scope  = "regional" # "global" or "regional"

  # Contract identity binding
  contract_key = "platform/v1"
}
