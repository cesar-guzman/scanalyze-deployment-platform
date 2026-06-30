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

variable "release_version" {
  type        = string
  description = "Release version being deployed"
}

variable "release_manifest_digest" {
  type        = string
  description = "SHA-256 digest of the release manifest"
  validation {
    condition     = can(regex("^sha256:[a-f0-9]{64}$", var.release_manifest_digest))
    error_message = "release_manifest_digest must be sha256:<64 hex chars>"
  }
}

# global-specific: no upstream contract to consume

variable "service_names" {
  type        = list(string)
  description = "List of microservice names for per-service workload role creation"
  default = [
    "ingest-api",
    "ocr-worker",
    "postprocess-worker",
    "classifier-worker",
    "bank-worker",
    "personal-worker",
    "gov-worker",
  ]
}

variable "ecs_task_execution_managed_policies" {
  type        = list(string)
  description = "Managed policy ARNs to attach to the ECS task execution role"
  default = [
    "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy",
  ]
}
