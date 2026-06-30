variable "deployment_id" {
  type        = string
  description = "Unique deployment identifier"
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
