# Backend configuration template for platform root.
# This file is NOT used directly — the orchestrator renders
# backend.tf from the deployment record at plan time.
#
# State key pattern:
#   {dep_id}/{region}/platform/terraform.tfstate
#
# IMPORTANT:
# - bucket, dynamodb_table, and kms_key_id come from the deployment record
# - Do NOT hardcode bucket names, account IDs, or ARNs
# - Do NOT use workspaces for customer isolation

backend "s3" {
  bucket         = "RENDERED_BY_ORCHESTRATOR"
  key            = "{dep_id}/{region}/platform/terraform.tfstate"
  region         = "RENDERED_BY_ORCHESTRATOR"
  dynamodb_table = "RENDERED_BY_ORCHESTRATOR"
  encrypt        = true
  kms_key_id     = "RENDERED_BY_ORCHESTRATOR"
}
