variable "customer_id" {
  type        = string
  description = "Immutable customer identifier from the authoritative deployment record."
  nullable    = false

  validation {
    condition     = can(regex("^cust_[0-9A-HJKMNP-TV-Z]{26}$", var.customer_id))
    error_message = "customer_id must be a canonical cust_ ULID."
  }
}

variable "deployment_id" {
  type        = string
  description = "Immutable deployment identifier from the authoritative deployment record."
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
  description = "AWS region for the regional edge."
  nullable    = false

  validation {
    condition     = can(regex("^[a-z]{2}(?:-gov)?-[a-z]+-[0-9]+$", var.region))
    error_message = "region must be a valid AWS region identifier."
  }
}

variable "aws_partition" {
  type        = string
  description = "AWS partition from the verified identity-control-plane contract."
  default     = "aws"
  nullable    = false

  validation {
    condition     = contains(["aws", "aws-us-gov", "aws-cn"], var.aws_partition)
    error_message = "aws_partition must be aws, aws-us-gov, or aws-cn."
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

variable "domain_name" {
  type        = string
  description = "Deployment DNS name retained as non-authoritative routing metadata."
  nullable    = false

  validation {
    condition     = trimspace(var.domain_name) != "" && !strcontains(var.domain_name, "*")
    error_message = "domain_name must be a non-wildcard DNS name."
  }
}

variable "vpc_id" {
  type        = string
  description = "VPC identifier from the verified network contract."
  nullable    = false

  validation {
    condition     = can(regex("^vpc-[0-9a-f]+$", var.vpc_id))
    error_message = "vpc_id must be a valid VPC identifier."
  }
}

variable "private_subnet_ids" {
  type        = map(string)
  description = "AZ-ID keyed private subnets from the verified network contract."
  nullable    = false

  validation {
    condition = (
      length(var.private_subnet_ids) > 0 &&
      alltrue([for subnet_id in values(var.private_subnet_ids) : can(regex("^subnet-[0-9a-f]+$", subnet_id))])
    )
    error_message = "private_subnet_ids must contain at least one valid subnet identifier."
  }
}

variable "alb_listener_arn" {
  type        = string
  description = "Internal ALB HTTPS listener ARN from the verified services contract."
  nullable    = false

  validation {
    condition     = can(regex("^arn:aws[a-z-]*:elasticloadbalancing:[a-z0-9-]+:[0-9]{12}:listener/", var.alb_listener_arn))
    error_message = "alb_listener_arn must be a valid ELBv2 listener ARN."
  }
}

variable "alb_security_group_id" {
  type        = string
  description = "ALB integration security group from the verified services contract."
  nullable    = false

  validation {
    condition     = can(regex("^sg-[0-9a-f]+$", var.alb_security_group_id))
    error_message = "alb_security_group_id must be a valid security group identifier."
  }
}

variable "api_access_log_group_arn" {
  type        = string
  description = "Dedicated encrypted API Gateway access-log group ARN."
  nullable    = false

  validation {
    condition = (
      startswith(
        var.api_access_log_group_arn,
        "arn:${var.aws_partition}:logs:${var.region}:${var.account_id}:log-group:"
      ) &&
      !strcontains(var.api_access_log_group_arn, "*")
    )
    error_message = "api_access_log_group_arn must be an exact same-account, same-region CloudWatch Logs group ARN."
  }
}

variable "upstream_contract_digest" {
  type        = string
  description = "Verified identity-control-plane/v1 digest consumed by this module."
  nullable    = false

  validation {
    condition     = can(regex("^sha256:[0-9a-f]{64}$", var.upstream_contract_digest))
    error_message = "upstream_contract_digest must be sha256:<64 lowercase hex>."
  }
}

variable "expected_upstream_digest" {
  type        = string
  description = "Expected identity-control-plane/v1 digest from the deployment record."
  nullable    = false

  validation {
    condition     = can(regex("^sha256:[0-9a-f]{64}$", var.expected_upstream_digest))
    error_message = "expected_upstream_digest must be sha256:<64 lowercase hex>."
  }
}

variable "cognito_issuer_url" {
  type        = string
  description = "Exact Cognito issuer from the verified identity-control-plane contract."
  nullable    = false

  validation {
    condition = (
      startswith(var.cognito_issuer_url, "https://cognito-idp.") &&
      (strcontains(var.cognito_issuer_url, ".amazonaws.com/") || strcontains(var.cognito_issuer_url, ".amazonaws.com.cn/")) &&
      !endswith(var.cognito_issuer_url, "/") &&
      !strcontains(var.cognito_issuer_url, "?") &&
      !strcontains(var.cognito_issuer_url, "#")
    )
    error_message = "cognito_issuer_url must be an exact HTTPS Cognito issuer without query, fragment, or trailing slash."
  }
}

variable "cognito_user_pool_id" {
  type        = string
  description = "Public user-pool identifier from the verified identity-control-plane contract."
  nullable    = false

  validation {
    condition     = can(regex("^[a-z]{2}(?:-gov)?-[a-z]+-[0-9]+_[0-9A-Za-z]+$", var.cognito_user_pool_id))
    error_message = "cognito_user_pool_id must be a valid regional Cognito user-pool identifier."
  }
}

variable "cognito_spa_client_id" {
  type        = string
  description = "Public SPA audience from the verified identity-control-plane contract."
  nullable    = false

  validation {
    condition     = trimspace(var.cognito_spa_client_id) != ""
    error_message = "cognito_spa_client_id must not be empty."
  }
}

variable "cognito_m2m_client_ids" {
  type        = list(string)
  description = "Public workload audiences from the reviewed external M2M registry; no secret values."
  nullable    = false

  validation {
    condition = (
      length(distinct(var.cognito_m2m_client_ids)) == length(var.cognito_m2m_client_ids) &&
      alltrue([for client_id in var.cognito_m2m_client_ids : trimspace(client_id) != "" && client_id != var.cognito_spa_client_id])
    )
    error_message = "cognito_m2m_client_ids must be unique and distinct from the SPA client; an empty bootstrap registry is valid."
  }
}

variable "identity_action_scopes" {
  type = object({
    read  = string
    write = string
    admin = string
  })
  description = "Exact canonical action-to-scope catalog from identity-control-plane/v1."
  nullable    = false

  validation {
    condition = var.identity_action_scopes == {
      read  = "scanalyze.api.v1/read"
      write = "scanalyze.api.v1/write"
      admin = "scanalyze.api.v1/admin"
    }
    error_message = "identity_action_scopes must exactly match scanalyze.api.v1 read/write/admin."
  }
}

variable "identity_policy_version" {
  type        = string
  description = "Reviewed authorization policy version from identity-control-plane/v1."
  nullable    = false
}

variable "identity_policy_digest" {
  type        = string
  description = "Reviewed authorization policy digest from identity-control-plane/v1."
  nullable    = false

  validation {
    condition     = can(regex("^sha256:[0-9a-f]{64}$", var.identity_policy_digest))
    error_message = "identity_policy_digest must be sha256:<64 lowercase hex>."
  }
}

variable "identity_policy_canonicalization" {
  type        = string
  description = "Canonicalization algorithm from identity-control-plane/v1."
  nullable    = false

  validation {
    condition     = var.identity_policy_canonicalization == "rfc8785_json_canonicalization"
    error_message = "identity_policy_canonicalization must be rfc8785_json_canonicalization."
  }
}

variable "cors_allowed_origins" {
  type        = list(string)
  description = "Exact deployment HTTPS origins allowed by CORS."
  nullable    = false

  validation {
    condition = (
      length(var.cors_allowed_origins) > 0 &&
      length(distinct(var.cors_allowed_origins)) == length(var.cors_allowed_origins) &&
      alltrue([
        for origin in var.cors_allowed_origins :
        startswith(origin, "https://") && !strcontains(lower(origin), "localhost") && !strcontains(origin, "*") && !endswith(origin, "/")
      ])
    )
    error_message = "cors_allowed_origins must be unique exact HTTPS origins without localhost, wildcard, or trailing slash."
  }
}

variable "api_authorization_routes" {
  type        = map(list(string))
  description = "Closed route-key to canonical OAuth scope mapping."
  nullable    = false

  validation {
    condition = (
      length(var.api_authorization_routes) > 0 &&
      alltrue([
        for route_key, scopes in var.api_authorization_routes :
        route_key != "$default" &&
        can(regex("^(GET|POST|PUT|PATCH|DELETE|HEAD) /([A-Za-z0-9._~-]+|\\{[A-Za-z][A-Za-z0-9_]*\\})(/([A-Za-z0-9._~-]+|\\{[A-Za-z][A-Za-z0-9_]*\\}))*$", route_key)) &&
        length(scopes) == 1 &&
        length(distinct(scopes)) == length(scopes) &&
        length(setsubtract(toset(scopes), toset([
          "scanalyze.api.v1/read",
          "scanalyze.api.v1/write",
          "scanalyze.api.v1/admin",
        ]))) == 0
      ])
    )
    error_message = "every non-default route must declare exactly one canonical scanalyze.api.v1 prefilter scope; API Gateway scope arrays are OR, never AND."
  }
}

variable "legacy_identity_handoff_complete" {
  type        = bool
  description = "Reviewed assertion that legacy edge Cognito state was imported into identity-control-plane, or that no legacy state exists."
  nullable    = false
}
