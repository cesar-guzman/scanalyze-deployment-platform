variable "deployment_id" {
  type        = string
  description = "Unique deployment identifier"

  validation {
    condition     = can(regex("^dep_[0-9A-HJKMNP-TV-Z]{26}$", var.deployment_id))
    error_message = "deployment_id must be a canonical dep_ ULID."
  }
}

variable "customer_id" {
  type        = string
  description = "Immutable customer identifier from the authoritative deployment record"

  validation {
    condition     = can(regex("^cust_[0-9A-HJKMNP-TV-Z]{26}$", var.customer_id))
    error_message = "customer_id must be a canonical cust_ ULID."
  }
}

variable "account_id" {
  type        = string
  description = "AWS account ID"

  validation {
    condition     = can(regex("^[0-9]{12}$", var.account_id))
    error_message = "account_id must be a 12-digit AWS account ID."
  }
}

variable "region" {
  type        = string
  description = "AWS region"

  validation {
    condition     = can(regex("^[a-z]{2}(?:-gov)?-[a-z]+-[0-9]+$", var.region))
    error_message = "region must be a valid AWS region identifier."
  }
}

variable "environment" {
  type        = string
  description = "Deployment environment projected into the public runtime configuration"

  validation {
    condition     = contains(["sandbox", "dev", "staging", "production"], var.environment)
    error_message = "environment must be sandbox, dev, staging, or production."
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
    error_message = "release_version must be a reviewable semantic version of at most 128 characters."
  }
}

variable "release_manifest_digest" {
  type        = string
  description = "SHA-256 digest of the release manifest"
}

variable "domain_name" {
  type        = string
  description = "Primary domain name for the deployment"

  validation {
    condition     = length(var.domain_name) <= 253 && can(regex("^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$", var.domain_name))
    error_message = "domain_name must be an exact lowercase DNS hostname of at most 253 characters without scheme, path, wildcard, query, or fragment."
  }
}

variable "domain_aliases" {
  type        = list(string)
  description = "Alternative domain names for CloudFront"
  default     = []
}

variable "route53_zone_id" {
  type        = string
  description = "Route53 hosted zone ID for DNS records"
}

# From upstream edge-identity contract
variable "api_gateway_endpoint" {
  type        = string
  description = "API Gateway HTTP API endpoint URL from edge-identity contract"

  validation {
    condition = (
      startswith(var.api_gateway_endpoint, "https://") &&
      !strcontains(var.api_gateway_endpoint, "?") &&
      !strcontains(var.api_gateway_endpoint, "#") &&
      !endswith(var.api_gateway_endpoint, "/")
    )
    error_message = "api_gateway_endpoint must be an exact HTTPS origin without path suffix, query, fragment, or trailing slash."
  }
}

variable "api_gateway_id" {
  type        = string
  description = "Exact API Gateway HTTP API identifier from edge-identity/v2"

  validation {
    condition     = can(regex("^[a-z0-9]{10}$", var.api_gateway_id))
    error_message = "api_gateway_id must be the exact 10-character lowercase HTTP API identifier."
  }
}

variable "frontend_bucket_domain_name" {
  type        = string
  description = "Exact regional endpoint for the account-scoped frontend bucket"
}

# Upstream contract
variable "upstream_contract_digest" {
  type        = string
  description = "SHA-256 digest of upstream edge-identity contract"
}

variable "expected_upstream_digest" {
  type        = string
  description = "Expected upstream contract digest"
}

variable "aws_partition" {
  type        = string
  description = "AWS partition projected from the verified edge-identity contract"

  validation {
    condition     = contains(["aws", "aws-us-gov", "aws-cn"], var.aws_partition)
    error_message = "aws_partition must be aws, aws-us-gov, or aws-cn."
  }
}

variable "cognito_user_pool_id" {
  type        = string
  description = "Public Cognito user-pool identifier from edge-identity/v2"

  validation {
    condition     = can(regex("^[a-z]{2}(?:-gov)?-[a-z]+-[0-9]+_[A-Za-z0-9]+$", var.cognito_user_pool_id))
    error_message = "cognito_user_pool_id must be a valid regional Cognito user-pool identifier."
  }
}

variable "cognito_issuer_url" {
  type        = string
  description = "Exact public Cognito issuer from edge-identity/v2"

  validation {
    condition = (
      startswith(var.cognito_issuer_url, "https://cognito-idp.") &&
      !strcontains(var.cognito_issuer_url, "?") &&
      !strcontains(var.cognito_issuer_url, "#") &&
      !endswith(var.cognito_issuer_url, "/")
    )
    error_message = "cognito_issuer_url must be an exact HTTPS Cognito issuer."
  }
}

variable "cognito_spa_client_id" {
  type        = string
  description = "Public SPA client identifier from edge-identity/v2"

  validation {
    condition     = can(regex("^[A-Za-z0-9]{1,128}$", var.cognito_spa_client_id))
    error_message = "cognito_spa_client_id must contain 1 to 128 alphanumeric characters."
  }
}

variable "allowed_token_uses" {
  type        = list(string)
  description = "Exact public token-use policy from edge-identity/v2"

  validation {
    condition     = length(var.allowed_token_uses) == 1 && var.allowed_token_uses[0] == "access"
    error_message = "allowed_token_uses must be exactly [access]."
  }
}

variable "identity_action_scopes" {
  type = object({
    read  = string
    write = string
    admin = string
  })
  description = "Exact action scopes from edge-identity/v2"

  validation {
    condition = var.identity_action_scopes == {
      read  = "scanalyze.api.v1/read"
      write = "scanalyze.api.v1/write"
      admin = "scanalyze.api.v1/admin"
    }
    error_message = "identity_action_scopes must match the canonical Scanalyze API scopes."
  }
}

variable "identity_policy_version" {
  type        = string
  description = "Reviewed authorization policy version from edge-identity/v2"

  validation {
    condition     = var.identity_policy_version == "1.0.0"
    error_message = "identity_policy_version must be 1.0.0 for frontend-config/v3."
  }
}

variable "identity_policy_digest" {
  type        = string
  description = "Reviewed authorization policy digest from edge-identity/v2"

  validation {
    condition     = can(regex("^sha256:[0-9a-f]{64}$", var.identity_policy_digest))
    error_message = "identity_policy_digest must be sha256:<64 lowercase hex>."
  }
}

variable "identity_policy_canonicalization" {
  type        = string
  description = "Authorization policy canonicalization from edge-identity/v2"

  validation {
    condition     = var.identity_policy_canonicalization == "rfc8785_json_canonicalization"
    error_message = "identity_policy_canonicalization must be rfc8785_json_canonicalization."
  }
}

variable "id_tokens_accepted" {
  type        = bool
  description = "Fail-closed token-use marker from edge-identity/v2"

  validation {
    condition     = var.id_tokens_accepted == false
    error_message = "id_tokens_accepted must remain false."
  }
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
    error_message = "frontend_features contains an unsupported public feature flag."
  }
}
