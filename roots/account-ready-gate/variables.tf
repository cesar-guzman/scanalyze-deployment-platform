variable "customer_id" {
  type        = string
  description = "Customer identifier independently retrieved from the deployment registry"
  sensitive   = true
  validation {
    condition     = can(regex("^cust_[0-9A-HJKMNP-TV-Z]{26}$", var.customer_id))
    error_message = "customer_id must be a canonical customer identifier"
  }
}

variable "deployment_id" {
  type        = string
  description = "Deployment identifier independently retrieved from the deployment registry"
  sensitive   = true
  validation {
    condition     = can(regex("^dep_[0-9A-HJKMNP-TV-Z]{26}$", var.deployment_id))
    error_message = "deployment_id must be a canonical deployment identifier"
  }
}

variable "account_id" {
  type        = string
  description = "Destination AWS account independently retrieved from the deployment registry"
  sensitive   = true
  validation {
    condition     = can(regex("^[0-9]{12}$", var.account_id)) && try(tonumber(var.account_id) != 0, false)
    error_message = "account_id must be a non-zero 12-digit AWS account ID"
  }
}

variable "region" {
  type        = string
  description = "Destination AWS region independently retrieved from the deployment registry"
  sensitive   = true
  validation {
    condition     = can(regex("^[a-z]{2}(?:-[a-z]+)+-[0-9]+$", var.region))
    error_message = "region must be a canonical AWS region identifier"
  }
}

variable "environment" {
  type        = string
  description = "Deployment environment independently retrieved from the deployment registry"
  sensitive   = true
  validation {
    condition = contains(
      ["sandbox", "dev", "staging", "production"],
      var.environment,
    )
    error_message = "environment must be an approved deployment environment"
  }
}

variable "expected_baseline_version" {
  type        = string
  description = "Expected ACCOUNT_READY baseline version from the deployment registry"
  sensitive   = true
  validation {
    condition     = can(regex("^v[0-9]+\\.[0-9]+\\.[0-9]+$", var.expected_baseline_version))
    error_message = "expected_baseline_version must be semantic version vN.N.N"
  }
}

variable "expected_contract_digest" {
  type        = string
  description = "Independently anchored canonical ACCOUNT_READY v2 digest"
  sensitive   = true
  validation {
    condition     = can(regex("^sha256:[a-f0-9]{64}$", var.expected_contract_digest))
    error_message = "expected_contract_digest must be a canonical SHA-256 digest"
  }
}

variable "account_ready_binding" {
  type = object({
    schema_version   = string
    customer_id      = string
    deployment_id    = string
    account_id       = string
    region           = string
    environment      = string
    baseline_version = string
    contract_digest  = string
  })
  description = "Verified identity and digest projection of the external ACCOUNT_READY v2 contract"
  sensitive   = true

  validation {
    condition = (
      var.account_ready_binding.schema_version == "2"
      && can(regex("^cust_[0-9A-HJKMNP-TV-Z]{26}$", var.account_ready_binding.customer_id))
      && can(regex("^dep_[0-9A-HJKMNP-TV-Z]{26}$", var.account_ready_binding.deployment_id))
      && can(regex("^[0-9]{12}$", var.account_ready_binding.account_id))
      && try(tonumber(var.account_ready_binding.account_id) != 0, false)
      && can(regex("^[a-z]{2}(?:-[a-z]+)+-[0-9]+$", var.account_ready_binding.region))
      && contains(
        ["sandbox", "dev", "staging", "production"],
        var.account_ready_binding.environment,
      )
      && can(regex("^v[0-9]+\\.[0-9]+\\.[0-9]+$", var.account_ready_binding.baseline_version))
      && can(regex("^sha256:[a-f0-9]{64}$", var.account_ready_binding.contract_digest))
    )
    error_message = "account_ready_binding must be a complete canonical ACCOUNT_READY v2 projection"
  }
}
