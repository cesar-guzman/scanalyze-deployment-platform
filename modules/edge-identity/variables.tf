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

variable "domain_name" {
  type        = string
  description = "Primary domain name for the deployment"
}

# From upstream contracts
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

variable "api_scopes" {
  type = list(object({
    name        = string
    description = string
  }))
  description = "OAuth scopes for the API resource server"
  default = [
    { name = "read", description = "Read access to API" },
    { name = "write", description = "Write access to API" },
    { name = "admin", description = "Admin access to API" },
  ]
}

variable "spa_callback_urls" {
  type        = list(string)
  description = "Allowed callback URLs for the SPA client"
  default     = ["https://localhost:3000/callback"]
}

variable "spa_logout_urls" {
  type        = list(string)
  description = "Allowed logout URLs for the SPA client"
  default     = ["https://localhost:3000/logout"]
}

variable "cors_allowed_origins" {
  type        = list(string)
  description = "Allowed CORS origins for the API Gateway"
  default     = ["*"]
}

variable "api_access_log_group_arn" {
  type        = string
  description = "CloudWatch log group ARN for API Gateway access logs"
}

# Upstream contract
variable "upstream_contract_digest" {
  type        = string
  description = "SHA-256 digest of upstream services contract"
}

variable "expected_upstream_digest" {
  type        = string
  description = "Expected upstream contract digest"
}
