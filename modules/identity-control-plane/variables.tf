variable "deployment_id" {
  type        = string
  description = "Immutable deployment identifier from the authoritative deployment record."
  nullable    = false

  validation {
    condition     = can(regex("^dep_[0-9A-HJKMNP-TV-Z]{26}$", var.deployment_id))
    error_message = "deployment_id must be a canonical dep_ ULID."
  }
}

variable "customer_id" {
  type        = string
  description = "Immutable customer identifier from the authoritative deployment record."
  nullable    = false

  validation {
    condition     = can(regex("^cust_[0-9A-HJKMNP-TV-Z]{26}$", var.customer_id))
    error_message = "customer_id must be a canonical cust_ ULID."
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
  description = "AWS region for the regional identity control plane."
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

variable "runtime_permissions_boundary_arn" {
  type        = string
  description = "Customer-owned permissions boundary required on every identity runtime role."
  nullable    = false

  validation {
    condition = (
      startswith(var.runtime_permissions_boundary_arn, "arn:${var.aws_partition}:iam::${var.account_id}:policy/") &&
      !strcontains(var.runtime_permissions_boundary_arn, "*")
    )
    error_message = "runtime_permissions_boundary_arn must be an exact customer-account IAM policy ARN in the selected partition."
  }
}

variable "release_version" {
  type        = string
  description = "Immutable release identifier associated with this configuration."
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

variable "policy_version" {
  type        = string
  description = "Reviewed enterprise authorization policy version."
  nullable    = false

  validation {
    condition     = can(regex("^[0-9]+\\.[0-9]+\\.[0-9]+$", var.policy_version))
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
  description = "Exact HTTPS callback URLs for the deployment SPA."
  nullable    = false

  validation {
    condition = (
      length(var.spa_callback_urls) > 0 &&
      length(distinct(var.spa_callback_urls)) == length(var.spa_callback_urls) &&
      alltrue([
        for url in var.spa_callback_urls :
        startswith(url, "https://") && !strcontains(lower(url), "localhost") && !strcontains(url, "*")
      ])
    )
    error_message = "spa_callback_urls must be unique exact HTTPS URLs without localhost or wildcards."
  }
}

variable "spa_logout_urls" {
  type        = list(string)
  description = "Exact HTTPS logout URLs for the deployment SPA."
  nullable    = false

  validation {
    condition = (
      length(var.spa_logout_urls) > 0 &&
      length(distinct(var.spa_logout_urls)) == length(var.spa_logout_urls) &&
      alltrue([
        for url in var.spa_logout_urls :
        startswith(url, "https://") && !strcontains(lower(url), "localhost") && !strcontains(url, "*")
      ])
    )
    error_message = "spa_logout_urls must be unique exact HTTPS URLs without localhost or wildcards."
  }
}

variable "pre_token_s3_bucket" {
  type        = string
  description = "Bucket containing the immutable reviewed pre-token Lambda artifact."
  nullable    = false

  validation {
    condition = (
      can(regex("^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$", var.pre_token_s3_bucket)) &&
      !strcontains(var.pre_token_s3_bucket, "..") &&
      !strcontains(var.pre_token_s3_bucket, ".-") &&
      !strcontains(var.pre_token_s3_bucket, "-.") &&
      !startswith(var.pre_token_s3_bucket, "xn--") &&
      !startswith(var.pre_token_s3_bucket, "sthree-") &&
      !startswith(var.pre_token_s3_bucket, "amzn_s3_demo_") &&
      !endswith(var.pre_token_s3_bucket, "-s3alias") &&
      !endswith(var.pre_token_s3_bucket, "--ol-s3") &&
      !endswith(var.pre_token_s3_bucket, ".mrap") &&
      !endswith(var.pre_token_s3_bucket, "--x-s3") &&
      !endswith(var.pre_token_s3_bucket, "--table-s3") &&
      !can(regex("^[0-9]+([.][0-9]+){3}$", var.pre_token_s3_bucket))
    )
    error_message = "pre_token_s3_bucket must be a valid general-purpose S3 bucket name."
  }
}

variable "pre_token_s3_key" {
  type        = string
  description = "Content-addressed object key for the pre-token Lambda artifact."
  nullable    = false

  validation {
    condition     = can(regex("(^|/)sha256[-/:][0-9a-f]{64}([./_-]|$)", var.pre_token_s3_key))
    error_message = "pre_token_s3_key must contain an exact sha256[-/:]<64 lowercase hex> content-address segment."
  }
}

variable "pre_token_s3_object_version" {
  type        = string
  description = "Immutable S3 VersionId for the reviewed pre-token artifact."
  nullable    = false

  validation {
    condition = (
      can(regex("^[-A-Za-z0-9._~+/=]+$", var.pre_token_s3_object_version)) &&
      length(var.pre_token_s3_object_version) <= 1024 &&
      lower(var.pre_token_s3_object_version) != "null"
    )
    error_message = "pre_token_s3_object_version must be a non-null immutable S3 VersionId using safe opaque characters."
  }
}

variable "pre_token_source_code_hash" {
  type        = string
  description = "Base64-encoded SHA-256 digest of the reviewed Lambda ZIP."
  nullable    = false

  validation {
    condition     = can(base64decode(var.pre_token_source_code_hash)) && length(base64decode(var.pre_token_source_code_hash)) == 32
    error_message = "pre_token_source_code_hash must decode to exactly 32 bytes."
  }
}

variable "control_processor_s3_bucket" {
  type        = string
  description = "Bucket containing the immutable reviewed identity control-processor artifact."
  nullable    = false

  validation {
    condition = (
      can(regex("^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$", var.control_processor_s3_bucket)) &&
      !strcontains(var.control_processor_s3_bucket, "..") &&
      !strcontains(var.control_processor_s3_bucket, ".-") &&
      !strcontains(var.control_processor_s3_bucket, "-.") &&
      !startswith(var.control_processor_s3_bucket, "xn--") &&
      !startswith(var.control_processor_s3_bucket, "sthree-") &&
      !startswith(var.control_processor_s3_bucket, "amzn_s3_demo_") &&
      !endswith(var.control_processor_s3_bucket, "-s3alias") &&
      !endswith(var.control_processor_s3_bucket, "--ol-s3") &&
      !endswith(var.control_processor_s3_bucket, ".mrap") &&
      !endswith(var.control_processor_s3_bucket, "--x-s3") &&
      !endswith(var.control_processor_s3_bucket, "--table-s3") &&
      !can(regex("^[0-9]+([.][0-9]+){3}$", var.control_processor_s3_bucket))
    )
    error_message = "control_processor_s3_bucket must be a valid general-purpose S3 bucket name."
  }
}

variable "control_processor_s3_key" {
  type        = string
  description = "Content-addressed object key for the identity control-processor artifact."
  nullable    = false

  validation {
    condition     = can(regex("(^|/)sha256[-/:][0-9a-f]{64}([./_-]|$)", var.control_processor_s3_key))
    error_message = "control_processor_s3_key must contain an exact sha256[-/:]<64 lowercase hex> content-address segment."
  }
}

variable "control_processor_s3_object_version" {
  type        = string
  description = "Immutable S3 VersionId for the reviewed identity control-processor artifact."
  nullable    = false

  validation {
    condition = (
      can(regex("^[-A-Za-z0-9._~+/=]+$", var.control_processor_s3_object_version)) &&
      length(var.control_processor_s3_object_version) <= 1024 &&
      lower(var.control_processor_s3_object_version) != "null"
    )
    error_message = "control_processor_s3_object_version must be a non-null immutable S3 VersionId using safe opaque characters."
  }
}

variable "control_processor_source_code_hash" {
  type        = string
  description = "Base64-encoded SHA-256 digest of the reviewed identity control-processor ZIP."
  nullable    = false

  validation {
    condition     = can(base64decode(var.control_processor_source_code_hash)) && length(base64decode(var.control_processor_source_code_hash)) == 32
    error_message = "control_processor_source_code_hash must decode to exactly 32 bytes."
  }
}

variable "control_processor_enabled" {
  type        = bool
  description = "Explicit reviewed M2M control-processor activation; human bootstrap remains runtime-denied."
  nullable    = false

  validation {
    condition     = var.control_processor_enabled
    error_message = "identity-control-plane/v1 requires the reviewed M2M control processor to be enabled; human runtime remains independently disabled."
  }
}

variable "m2m_bindings" {
  type = list(object({
    client_id       = string
    customer_id     = string
    deployment_id   = string
    required_scopes = list(string)
  }))
  description = "Verified identity-contract/v2 M2M bindings promoted into the reviewed audience registry."
  nullable    = false

  validation {
    condition = (
      length(distinct([for binding in var.m2m_bindings : binding.client_id])) == length(var.m2m_bindings) &&
      alltrue([
        for binding in var.m2m_bindings :
        trimspace(binding.client_id) != "" &&
        binding.customer_id == var.customer_id &&
        binding.deployment_id == var.deployment_id &&
        length(binding.required_scopes) > 0 &&
        length(distinct(binding.required_scopes)) == length(binding.required_scopes) &&
        length(setsubtract(toset(binding.required_scopes), toset([
          "scanalyze.api.v1/read",
          "scanalyze.api.v1/write",
          "scanalyze.api.v1/admin",
        ]))) == 0
      ])
    )
    error_message = "m2m_bindings must contain unique clients exactly bound to this customer/deployment and non-empty canonical scopes."
  }
}

variable "alarm_actions" {
  type        = list(string)
  description = "Reviewed notification target ARNs for identity alarms. Empty is valid for offline composition only."
  default     = []

  validation {
    condition = alltrue([
      for arn in var.alarm_actions :
      startswith(arn, "arn:${var.aws_partition}:sns:${var.region}:${var.account_id}:") &&
      !strcontains(arn, "*")
    ])
    error_message = "alarm_actions may contain only exact same-account, same-region SNS topic ARNs."
  }
}
