# Backend configuration for cicd root.
# Copy to a local .tfvars file and pass via:
#   terraform init -backend-config=backend.tfvars
#
# Do NOT activate backend "s3" in providers.tf until PM approval.

bucket         = "scanalyze-<deployment_id>-tf-state"
key            = "<deployment_id>/<region>/cicd/terraform.tfstate"
region         = "us-east-1"
dynamodb_table = "scanalyze-<deployment_id>-tf-lock"
encrypt        = true
