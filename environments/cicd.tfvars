# =============================================================================
# Scanalyze CI/CD Layer — BCM Corp Sandbox
# =============================================================================
# Account:      905418363887
# Region:       us-east-1
# Layer:        cicd (build-only)
# =============================================================================

# --- Core identity ---
deployment_id = "dep_01KWM783E0S1FZVAM8FRDV1HR2"
account_id    = "905418363887"
region        = "us-east-1"

# --- From platform contract ---
ecs_cluster_name = "83E0S1FZVAM8FRDV1HR2-cluster"

# --- Source configuration ---
source_provider = "codecommit"
default_branch  = "main"

# --- Microservice definitions ---
microservices = {
  ingest-api = {
    service_name  = "ingest-api"
    ecr_repo_name = "scanalyze/ingest-api"
  }
  ocr-worker = {
    service_name  = "ocr-worker"
    ecr_repo_name = "scanalyze/ocr-worker"
  }
  postprocess-worker = {
    service_name  = "postprocess-worker"
    ecr_repo_name = "scanalyze/postprocess-worker"
  }
  classifier-worker = {
    service_name  = "classifier-worker"
    ecr_repo_name = "scanalyze/classifier-worker"
  }
  bank-worker = {
    service_name  = "bank-worker"
    ecr_repo_name = "scanalyze/bank-worker"
  }
  personal-worker = {
    service_name  = "personal-worker"
    ecr_repo_name = "scanalyze/personal-worker"
  }
  gov-worker = {
    service_name  = "gov-worker"
    ecr_repo_name = "scanalyze/gov-worker"
  }
}

# --- Optional features ---
enable_ecr_lifecycle_policy  = true
ecr_lifecycle_keep_last      = 20
enable_release_metadata_ssm  = true
enable_codecommit            = true   # P4: permission set updated with scoped CodeCommit/Build/Pipeline
