variable "deployment_id" {
  type        = string
  description = "Unique deployment identifier (ULID with dep_ prefix)"
  validation {
    condition     = can(regex("^dep_[0-9A-HJKMNP-TV-Z]{26}$", var.deployment_id))
    error_message = "deployment_id must match ^dep_[0-9A-HJKMNP-TV-Z]{26}$"
  }
}

variable "account_id" {
  type        = string
  description = "AWS account ID for the customer deployment"
  validation {
    condition     = can(regex("^[0-9]{12}$", var.account_id))
    error_message = "account_id must be a 12-digit AWS account ID"
  }
}

variable "region" {
  type        = string
  description = "AWS region for this deployment"
}

variable "upstream_contract_digest" {
  type        = string
  description = "SHA-256 digest of the upstream contract being consumed"
  default     = ""
}

variable "expected_upstream_digest" {
  type        = string
  description = "Expected upstream contract digest from deployment record"
  default     = ""
}


# --- From platform contract ---

variable "ecs_cluster_name" {
  type        = string
  description = "ECS cluster name from platform contract (NOT hardcoded)"
}

# --- Source configuration ---

variable "source_provider" {
  type        = string
  description = "Source provider for pipelines"
  default     = "codecommit"
  validation {
    condition     = contains(["codecommit", "codestar", "github", "artifact_bundle"], var.source_provider)
    error_message = "source_provider must be one of: codecommit, codestar, github, artifact_bundle"
  }
}

variable "default_branch" {
  type        = string
  description = "Default branch name for source stage"
  default     = "main"
}

# --- Microservices ---

variable "microservices" {
  type = map(object({
    service_name   = string
    ecr_repo_name  = string
    container_name = optional(string)
    source = optional(object({
      provider       = optional(string)
      repo_name      = optional(string)
      branch         = optional(string)
      connection_arn = optional(string)
      full_repo_id   = optional(string)
    }))
    buildspec_path = optional(string)
    build_env      = optional(map(string), {})
    # NO container_port — pipeline doesn't deploy to ECS
    # NO enable_ecs_deploy — pipeline NEVER deploys to ECS
    # NO codedeploy — REJECTED for Platform v2
  }))
  description = "Microservice definitions for build pipelines (build-only, no ECS deploy)"
}

# --- Optional features ---

variable "enable_ecr_lifecycle_policy" {
  type        = bool
  description = "Enable ECR lifecycle policies to manage image count"
  default     = true
}

variable "ecr_lifecycle_keep_last" {
  type        = number
  description = "Number of images to keep in ECR"
  default     = 20
}

variable "enable_release_metadata_ssm" {
  type        = bool
  description = "Write image tag/digest to SSM parameters for release tracking"
  default     = true
}

variable "enable_codecommit" {
  type        = bool
  description = "Create CodeCommit repos and pipelines. Disable when permission set lacks codecommit:*"
  default     = true
}
