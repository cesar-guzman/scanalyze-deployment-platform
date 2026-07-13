# Backend configuration template for the identity-control-plane root.
# The orchestrator renders backend.tf from the authoritative deployment record;
# this template is never an operational backend configuration.
#
# State key pattern:
#   {deployment_id}/{region}/identity-control-plane/terraform.tfstate
#
# Do not hardcode bucket names, account IDs, ARNs, regions, or KMS identifiers.
# Do not use Terraform workspaces for customer/deployment isolation.

backend "s3" {
  bucket         = "RENDERED_BY_ORCHESTRATOR"
  key            = "{deployment_id}/{region}/identity-control-plane/terraform.tfstate"
  region         = "RENDERED_BY_ORCHESTRATOR"
  dynamodb_table = "RENDERED_BY_ORCHESTRATOR"
  encrypt        = true
  kms_key_id     = "RENDERED_BY_ORCHESTRATOR"
}
