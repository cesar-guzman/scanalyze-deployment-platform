variable "deployment_id" {
  type        = string
  description = "Unique deployment identifier"
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
  description = "AWS account ID"
}

variable "region" {
  type        = string
  description = "AWS region"
}

variable "release_version" {
  type        = string
  description = "Release version being deployed"
}

variable "release_manifest_digest" {
  type        = string
  description = "SHA-256 digest of the release manifest"
}

# From upstream contracts
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
  description = "ALB HTTPS listener ARN from platform contract"
}

variable "alb_security_group_id" {
  type        = string
  description = "ALB security group ID from platform contract"
}

variable "service_definitions" {
  type = list(object({
    name              = string
    image             = string # Must use @sha256 digest
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

# Upstream contract
variable "upstream_contract_digest" {
  type        = string
  description = "SHA-256 digest of upstream data-foundation contract"
}

variable "expected_upstream_digest" {
  type        = string
  description = "Expected upstream contract digest"
}
