variable "deployment_id" {
  type        = string
  description = "Unique deployment identifier (ULID with dep_ prefix)"
  validation {
    condition     = can(regex("^dep_[0-9A-HJKMNP-TV-Z]{26}$", var.deployment_id))
    error_message = "deployment_id must match ^dep_[0-9A-HJKMNP-TV-Z]{26}$"
  }
}

variable "customer_id" {
  type        = string
  description = "Immutable customer identifier from the authoritative deployment record"
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
  validation {
    condition     = can(regex("^[a-z]{2}(?:-gov)?-[a-z]+-[0-9]+$", var.region))
    error_message = "region must be a valid AWS region identifier"
  }
}

variable "environment" {
  type        = string
  description = "Deployment environment from the validated manifest"
  validation {
    condition     = contains(["sandbox", "dev", "staging", "production"], var.environment)
    error_message = "environment must be sandbox, dev, staging, or production"
  }
}

variable "release_version" {
  type        = string
  description = "Release version being deployed"
  validation {
    condition = (
      length(var.release_version) <= 128 &&
      can(regex("^v?[0-9]+\\.[0-9]+\\.[0-9]+(?:-[0-9A-Za-z-]+(?:\\.[0-9A-Za-z-]+)*)?(?:\\+[0-9A-Za-z-]+(?:\\.[0-9A-Za-z-]+)*)?$", var.release_version))
    )
    error_message = "release_version must be a reviewable semantic version of at most 128 characters"
  }
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
  description = "Exact output schema identifier from the verified edge-identity envelope"
}

variable "accepted_schema_versions" {
  type        = list(string)
  default     = ["2"]
  description = "List of accepted upstream contract schema versions"
}

# --- Variables consumed by modules/edge ---

variable "domain_name" {
  type        = string
  description = "Primary domain name for CloudFront and ACM"
  validation {
    condition     = length(var.domain_name) <= 253 && can(regex("^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$", var.domain_name))
    error_message = "domain_name must be an exact lowercase DNS hostname of at most 253 characters"
  }
}

variable "route53_zone_id" {
  type        = string
  description = "Route53 hosted zone ID for DNS records"
}

variable "api_gateway_endpoint" {
  type        = string
  description = "API Gateway endpoint URL from edge-identity contract"
}

variable "api_gateway_id" {
  type        = string
  description = "Exact API Gateway HTTP API identifier from edge-identity/v2"

  validation {
    condition     = can(regex("^[a-z0-9]{10}$", var.api_gateway_id))
    error_message = "api_gateway_id must be the exact 10-character lowercase HTTP API identifier"
  }
}

variable "frontend_bucket_domain_name" {
  type        = string
  description = "Exact regional endpoint for the account-scoped frontend bucket"
}

variable "aws_partition" {
  type        = string
  description = "AWS partition from edge-identity/v2"
  validation {
    condition     = contains(["aws", "aws-us-gov", "aws-cn"], var.aws_partition)
    error_message = "aws_partition must be aws, aws-us-gov, or aws-cn"
  }
}

variable "cognito_user_pool_id" {
  type        = string
  description = "Public Cognito user-pool identifier from edge-identity/v2"
}

variable "cognito_issuer_url" {
  type        = string
  description = "Exact public Cognito issuer from edge-identity/v2"
}

variable "cognito_spa_client_id" {
  type        = string
  description = "Public SPA client identifier from edge-identity/v2"
}

variable "allowed_token_uses" {
  type        = list(string)
  description = "Exact token-use policy from edge-identity/v2"
}

variable "identity_action_scopes" {
  type = object({
    read  = string
    write = string
    admin = string
  })
  description = "Exact action scopes from edge-identity/v2"
}

variable "identity_policy_version" {
  type        = string
  description = "Reviewed authorization policy version from edge-identity/v2"
}

variable "identity_policy_digest" {
  type        = string
  description = "Reviewed authorization policy digest from edge-identity/v2"
}

variable "identity_policy_canonicalization" {
  type        = string
  description = "Authorization policy canonicalization from edge-identity/v2"
}

variable "id_tokens_accepted" {
  type        = bool
  description = "Fail-closed ID-token marker from edge-identity/v2"
}

variable "frontend_features" {
  type        = map(bool)
  description = "Closed public SPA feature allowlist"
  default     = {}
  nullable    = false
  validation {
    condition = length(setsubtract(
      toset(keys(var.frontend_features)),
      toset([
        "document_upload",
        "batch_processing",
        "audit_view",
        "user_administration",
      ]),
    )) == 0
    error_message = "frontend_features contains an unsupported public feature flag"
  }
}
