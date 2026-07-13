variable "customer_id" {
  type        = string
  description = "Immutable customer identifier from the deployment record."
  nullable    = false

  validation {
    condition     = can(regex("^cust_[0-9A-HJKMNP-TV-Z]{26}$", var.customer_id))
    error_message = "customer_id must be a canonical cust_ ULID."
  }
}

variable "deployment_id" {
  type        = string
  description = "Immutable deployment identifier from the deployment record."
  nullable    = false

  validation {
    condition     = can(regex("^dep_[0-9A-HJKMNP-TV-Z]{26}$", var.deployment_id))
    error_message = "deployment_id must be a canonical dep_ ULID."
  }
}

variable "account_id" {
  type        = string
  description = "Expected AWS account for this dedicated deployment."
  nullable    = false

  validation {
    condition     = can(regex("^[0-9]{12}$", var.account_id))
    error_message = "account_id must be a 12-digit AWS account ID."
  }
}

variable "region" {
  type        = string
  description = "AWS region for this deployment."
  nullable    = false

  validation {
    condition     = can(regex("^[a-z]{2}(?:-gov)?-[a-z]+-[0-9]+$", var.region))
    error_message = "region must be a valid AWS region identifier."
  }
}

variable "aws_partition" {
  type        = string
  description = "AWS partition from the authoritative deployment record."
  default     = "aws"
  nullable    = false

  validation {
    condition     = contains(["aws", "aws-us-gov", "aws-cn"], var.aws_partition)
    error_message = "aws_partition must be aws, aws-us-gov, or aws-cn."
  }
}

variable "release_version" {
  type        = string
  description = "Immutable reviewed release version."
  nullable    = false

  validation {
    condition     = trimspace(var.release_version) != ""
    error_message = "release_version must not be empty."
  }
}

variable "release_manifest_digest" {
  type        = string
  description = "Digest of the reviewed release manifest."
  nullable    = false

  validation {
    condition     = can(regex("^sha256:[0-9a-f]{64}$", var.release_manifest_digest))
    error_message = "release_manifest_digest must be sha256:<64 lowercase hex>."
  }
}

variable "global_contract" {
  type = object({
    contract_id                               = string
    schema_version                            = string
    customer_id                               = string
    deployment_id                             = string
    account_id                                = string
    contract_digest                           = string
    identity_runtime_permissions_boundary_arn = string
  })
  description = "Verified global/v1 envelope binding supplied by the orchestrator."
  nullable    = false
}

variable "expected_global_contract_digest" {
  type        = string
  description = "Expected global/v1 digest from the immutable deployment record."
  nullable    = false

  validation {
    condition     = can(regex("^sha256:[0-9a-f]{64}$", var.expected_global_contract_digest))
    error_message = "expected_global_contract_digest must be sha256:<64 lowercase hex>."
  }
}

variable "release_manifest_contract" {
  type = object({
    contract_id     = string
    schema_version  = string
    customer_id     = string
    deployment_id   = string
    account_id      = string
    region          = string
    release_version = string
    manifest_digest = string
    contract_digest = string
    pre_token_artifact = object({
      bucket         = string
      key            = string
      object_version = string
      sha256_b64     = string
    })
    control_processor_artifact = object({
      bucket         = string
      key            = string
      object_version = string
      sha256_b64     = string
    })
  })
  description = "Verified release-manifest/v1 binding and immutable identity runtime artifact locators."
  nullable    = false
}

variable "expected_release_manifest_contract_digest" {
  type        = string
  description = "Expected release-manifest/v1 contract digest from the deployment record."
  nullable    = false

  validation {
    condition     = can(regex("^sha256:[0-9a-f]{64}$", var.expected_release_manifest_contract_digest))
    error_message = "expected_release_manifest_contract_digest must be sha256:<64 lowercase hex>."
  }
}

variable "policy_version" {
  type        = string
  description = "Reviewed enterprise authorization policy version."
  nullable    = false

  validation {
    condition     = can(regex("^[0-9]+[.][0-9]+[.][0-9]+$", var.policy_version))
    error_message = "policy_version must use semantic x.y.z form."
  }
}

variable "policy_digest" {
  type        = string
  description = "RFC 8785 canonical enterprise authorization policy digest."
  nullable    = false

  validation {
    condition     = can(regex("^sha256:[0-9a-f]{64}$", var.policy_digest))
    error_message = "policy_digest must be sha256:<64 lowercase hex>."
  }
}

variable "spa_callback_urls" {
  type        = list(string)
  description = "Exact deployment SPA callback URLs."
  nullable    = false
}

variable "spa_logout_urls" {
  type        = list(string)
  description = "Exact deployment SPA logout URLs."
  nullable    = false
}

variable "alarm_actions" {
  type        = list(string)
  description = "Reviewed SNS alarm targets."
  default     = []
}

variable "control_processor_enabled" {
  type        = bool
  description = "Explicit reviewed M2M control-processor activation; human bootstrap remains runtime-denied."
  nullable    = false

  validation {
    condition     = var.control_processor_enabled
    error_message = "identity-control-plane/v1 requires the reviewed M2M control processor to be enabled."
  }
}

variable "m2m_registry_contract" {
  type = object({
    contract_id     = string
    schema_version  = string
    customer_id     = string
    deployment_id   = string
    contract_digest = string
    action_scope_sets = object({
      read  = list(string)
      write = list(string)
      admin = list(string)
    })
    m2m_bindings = list(object({
      client_id       = string
      customer_id     = string
      deployment_id   = string
      required_scopes = list(string)
    }))
  })
  description = "Verified identity-contract/v2 M2M registry projection from GUG-102."
  nullable    = false
}

variable "expected_m2m_registry_contract_digest" {
  type        = string
  description = "Expected identity-contract/v2 registry digest from the immutable deployment record."
  nullable    = false

  validation {
    condition     = can(regex("^sha256:[0-9a-f]{64}$", var.expected_m2m_registry_contract_digest))
    error_message = "expected_m2m_registry_contract_digest must be sha256:<64 lowercase hex>."
  }
}
