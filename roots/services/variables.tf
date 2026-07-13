variable "deployment_id" {
  type        = string
  description = "Unique deployment identifier (ULID with dep_ prefix)"
  nullable    = false
  validation {
    condition     = can(regex("^dep_[0-9A-HJKMNP-TV-Z]{26}$", var.deployment_id))
    error_message = "deployment_id must match ^dep_[0-9A-HJKMNP-TV-Z]{26}$"
  }
}

variable "customer_id" {
  type        = string
  description = "Immutable customer identifier resolved from the deployment record"
  nullable    = false

  validation {
    condition     = can(regex("^cust_[0-9A-HJKMNP-TV-Z]{26}$", var.customer_id))
    error_message = "customer_id must match ^cust_[0-9A-HJKMNP-TV-Z]{26}$"
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

variable "upstream_contract_digest" {
  type        = string
  description = "SHA-256 digest of the upstream contract being consumed"
}

variable "expected_upstream_digest" {
  type        = string
  description = "Expected upstream contract digest from deployment record"
}

variable "upstream_schema_version" {
  type        = string
  description = "Schema version of the upstream contract"
}

variable "upstream_contract_id" {
  type        = string
  description = "Exact output schema identifier from the verified upstream envelope"
}

variable "accepted_schema_versions" {
  type        = list(string)
  default     = ["2"]
  description = "List of accepted upstream contract schema versions"
}

# --- Variables consumed by modules/services ---

variable "ecs_cluster_arn" {
  type        = string
  description = "ECS cluster ARN from platform contract"
}

variable "ecs_task_execution_role_arn" {
  type        = string
  description = "ECS task execution role ARN from global contract"
}

variable "workload_role_arns" {
  type        = map(string)
  description = "Map of service name to workload IAM role ARN from global contract"
}

variable "vpc_id" {
  type        = string
  description = "VPC ID from network contract"
}

variable "private_subnet_ids" {
  type        = map(string)
  description = "Map of AZ ID to private subnet ID from network contract"
}

variable "alb_listener_arn" {
  type        = string
  description = "Internal ALB listener ARN from platform contract"
}

variable "alb_security_group_id" {
  type        = string
  description = "ALB security group ID from platform contract"
}

variable "service_definitions" {
  type = list(object({
    name              = string
    image             = string
    cpu               = number
    memory            = number
    port              = optional(number)
    desired_count     = optional(number, 1)
    health_check_path = optional(string, "/health")
    extra_environment = optional(list(object({
      name  = string
      value = string
    })), [])
  }))
  description = "Service definitions for ECS tasks (Terraform sole owner)"

  validation {
    condition = alltrue([
      for svc in var.service_definitions :
      length(distinct([for item in svc.extra_environment : upper(item.name)])) == length(svc.extra_environment)
    ])
    error_message = "extra_environment variable names must be case-insensitively unique within each service definition"
  }

  validation {
    condition = alltrue(flatten([
      for svc in var.service_definitions : [
        for item in svc.extra_environment : !contains([
          "SCANALYZE_DEPLOYMENT_CUSTOMER_ID",
          "SCANALYZE_DEPLOYMENT_ID",
          "AWS_REGION",
          "RELEASE_VERSION",
        ], upper(item.name))
      ]
    ]))
    error_message = "extra_environment cannot override Terraform-owned identity or release variables"
  }
}
