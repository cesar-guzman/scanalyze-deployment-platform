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

variable "accepted_schema_versions" {
  type        = list(string)
  default     = ["1"]
  description = "List of accepted upstream contract schema versions"
}

# --- Variables consumed by modules/edge-identity ---

variable "domain_name" {
  type        = string
  description = "Primary domain name for Cognito and API Gateway"
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

variable "api_access_log_group_arn" {
  type        = string
  description = "CloudWatch log group ARN for API Gateway access logs"
}
