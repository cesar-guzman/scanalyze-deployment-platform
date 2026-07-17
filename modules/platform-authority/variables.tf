variable "authority_account_id" {
  type        = string
  description = "Dedicated Scanalyze platform-authority AWS account ID."
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
  description = "AWS partition for the authority and its registered destinations."
  default     = "aws"
  nullable    = false

  validation {
    condition     = contains(["aws", "aws-us-gov", "aws-cn"], var.aws_partition)
    error_message = "aws_partition must be aws, aws-us-gov, or aws-cn."
  }
}

variable "release_bucket_name" {
  type        = string
  description = "Globally unique, authority-owned bucket for immutable release manifests and evidence."
  nullable    = false

  validation {
    condition = (
      can(regex("^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$", var.release_bucket_name)) &&
      !strcontains(var.release_bucket_name, "..") &&
      !strcontains(var.release_bucket_name, ".-") &&
      !strcontains(var.release_bucket_name, "-.") &&
      !startswith(var.release_bucket_name, "xn--") &&
      !startswith(var.release_bucket_name, "sthree-") &&
      !startswith(var.release_bucket_name, "amzn_s3_demo_") &&
      !endswith(var.release_bucket_name, "-s3alias") &&
      !endswith(var.release_bucket_name, "--ol-s3") &&
      !endswith(var.release_bucket_name, ".mrap") &&
      !endswith(var.release_bucket_name, "--x-s3") &&
      !endswith(var.release_bucket_name, "--table-s3") &&
      !can(regex("^[0-9]+([.][0-9]+){3}$", var.release_bucket_name))
    )
    error_message = "release_bucket_name must be a valid general-purpose S3 bucket name."
  }
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
  description = "Authoritative deployment bindings keyed by canonical deployment_id."
  nullable    = false

  validation {
    condition = length(var.deployments) > 0 && alltrue([
      for deployment in values(var.deployments) :
      can(regex("^cust_[0-9A-HJKMNP-TV-Z]{26}$", deployment.customer_id)) &&
      can(regex("^dep_[0-9A-HJKMNP-TV-Z]{26}$", deployment.deployment_id)) &&
      can(regex("^[0-9]{12}$", deployment.destination_account_id)) &&
      try(tonumber(deployment.destination_account_id) > 0, false) &&
      can(regex("^[a-z]{2}(?:-gov)?-[a-z]+-[0-9]+$", deployment.region)) &&
      contains(["sandbox", "dev", "staging"], deployment.environment) &&
      can(regex("^repo:[A-Za-z0-9_.-]+(?:@[0-9]+)?/[A-Za-z0-9_.-]+(?:@[0-9]+)?:environment:[A-Za-z0-9_.-]+$", deployment.github_oidc_subject)) &&
      !strcontains(deployment.github_oidc_subject, "*") &&
      deployment.repository_owner_id > 0 &&
      deployment.repository_id > 0
    ])
    error_message = "every deployment must have canonical ownership, a non-production destination, and one exact GitHub environment subject."
  }
}

variable "tags" {
  type        = map(string)
  description = "Additional non-sensitive tags for platform-authority resources."
  default     = {}
  nullable    = false

  validation {
    condition = alltrue([
      for key in keys(var.tags) :
      !contains(["customer_id", "deployment_id", "account_id", "service", "managed_by", "data_classification"], key)
    ])
    error_message = "tags cannot override canonical security or ownership tags."
  }
}
