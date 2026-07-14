# Non-operational example. The orchestrator renders all values from the
# authorized registry and ACCOUNT_READY binding into a private temporary file.
bucket              = "RENDERED_BY_ORCHESTRATOR"
key                 = "{deployment_id}/{region}/cicd/terraform.tfstate"
region              = "RENDERED_BY_ORCHESTRATOR"
encrypt             = true
kms_key_id          = "RENDERED_BY_ORCHESTRATOR"
use_lockfile        = true
allowed_account_ids = ["RENDERED_BY_ORCHESTRATOR"]
