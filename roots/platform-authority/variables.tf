variable "authority_account_id" {
  type        = string
  description = "Dedicated platform-authority AWS account ID."
  nullable    = false

  validation {
    condition     = can(regex("^[0-9]{12}$", var.authority_account_id)) && try(tonumber(var.authority_account_id) > 0, false)
    error_message = "authority_account_id must be a non-zero 12-digit AWS account ID."
  }
}

variable "authority_region" {
  type        = string
  description = "Home region for the platform-authority control plane."
  nullable    = false

  validation {
    condition     = can(regex("^[a-z]{2}(?:-gov)?-[a-z]+-[0-9]+$", var.authority_region))
    error_message = "authority_region must be a valid AWS region identifier."
  }
}

variable "aws_partition" {
  type        = string
  description = "AWS partition for the authority."
  default     = "aws"
  nullable    = false
}

variable "release_bucket_name" {
  type        = string
  description = "Globally unique platform-authority release bucket."
  nullable    = false
}

variable "deployments" {
  type = map(object({
    customer_id            = string
    deployment_id          = string
    destination_account_id = string
    region                 = string
    environment            = string
    github_oidc_subject    = string
    repository_owner_id    = number
    repository_id          = number
  }))
  description = "Authoritative deployment bindings keyed by deployment_id."
  nullable    = false
}

variable "tags" {
  type        = map(string)
  description = "Additional non-sensitive platform-authority tags."
  default     = {}
  nullable    = false
}
