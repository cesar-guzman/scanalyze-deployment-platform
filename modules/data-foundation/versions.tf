terraform {
  required_version = ">= 1.14.6, < 1.15.0"

  # NOTE: No provider block in module skeletons.
  # Provider configuration is injected by the calling root.
  # M1 does not use any AWS provider — interface-only skeleton.
}
