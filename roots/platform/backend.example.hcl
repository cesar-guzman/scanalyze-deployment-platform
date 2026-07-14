# Backend configuration template for platform root.
# This file is NOT used directly — the orchestrator renders
# backend.tf from the deployment record at plan time.
#
# State key pattern:
#   {dep_id}/{region}/platform/terraform.tfstate
#
# IMPORTANT:
# - bucket, key, region, and kms_key_id come from an authorized backend binding
# - Do NOT hardcode bucket names, account IDs, or ARNs
# - Do NOT use workspaces for customer isolation

bucket              = "RENDERED_BY_ORCHESTRATOR"
key                 = "{deployment_id}/{region}/platform/terraform.tfstate"
region              = "RENDERED_BY_ORCHESTRATOR"
encrypt             = true
kms_key_id          = "RENDERED_BY_ORCHESTRATOR"
use_lockfile        = true
allowed_account_ids = ["RENDERED_BY_ORCHESTRATOR"]
