terraform {
  required_version = ">= 1.14.6, < 1.15.0"

  # This validation-only gate is initialized backendless, owns no state, and
  # uses only Terraform's built-in terraform_data resource.
}
