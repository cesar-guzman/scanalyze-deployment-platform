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
  description = "AWS region for this regional edge."
  nullable    = false

  validation {
    condition     = can(regex("^[a-z]{2}(?:-gov)?-[a-z]+-[0-9]+$", var.region))
    error_message = "region must be a valid AWS region identifier."
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

variable "network_contract" {
  type = object({
    contract_id             = string
    schema_version          = string
    customer_id             = string
    deployment_id           = string
    account_id              = string
    region                  = string
    release_manifest_digest = string
    contract_digest         = string
    vpc_id                  = string
    private_subnet_ids      = map(string)
    public_subnet_ids       = map(string)
    vpc_cidr_block          = string
    vpc_endpoint_sg_id      = string
  })
  description = "Typed verified network/v2 contract projection required by the edge."
  nullable    = false
}

variable "expected_network_contract_digest" {
  type        = string
  description = "Expected network/v2 digest from the immutable deployment record."
  nullable    = false

  validation {
    condition     = can(regex("^sha256:[0-9a-f]{64}$", var.expected_network_contract_digest))
    error_message = "expected_network_contract_digest must be sha256:<64 lowercase hex>."
  }
}

variable "platform_contract" {
  type = object({
    contract_id             = string
    schema_version          = string
    customer_id             = string
    deployment_id           = string
    account_id              = string
    region                  = string
    release_manifest_digest = string
    contract_digest         = string
    ecs_cluster_arn         = string
    ecs_cluster_name        = string
    alb_arn                 = string
    alb_dns_name            = string
    alb_listener_arn        = string
    alb_security_group_id   = string
  })
  description = "Typed verified platform/v2 contract projection required by the edge."
  nullable    = false
}

variable "expected_platform_contract_digest" {
  type        = string
  description = "Expected platform/v2 digest from the immutable deployment record."
  nullable    = false

  validation {
    condition     = can(regex("^sha256:[0-9a-f]{64}$", var.expected_platform_contract_digest))
    error_message = "expected_platform_contract_digest must be sha256:<64 lowercase hex>."
  }
}

variable "services_contract" {
  type = object({
    contract_id             = string
    schema_version          = string
    customer_id             = string
    deployment_id           = string
    account_id              = string
    region                  = string
    release_manifest_digest = string
    contract_digest         = string
    service_arns            = map(string)
    task_definition_arns    = map(string)
    target_group_arns       = map(string)
  })
  description = "Typed verified services/v2 contract projection required by the edge."
  nullable    = false
}

variable "expected_services_contract_digest" {
  type        = string
  description = "Expected services/v2 digest from the immutable deployment record."
  nullable    = false

  validation {
    condition     = can(regex("^sha256:[0-9a-f]{64}$", var.expected_services_contract_digest))
    error_message = "expected_services_contract_digest must be sha256:<64 lowercase hex>."
  }
}

variable "api_access_log_group_arn" {
  type        = string
  description = "Exact edge-owned API access log group ARN from the deployment record."
  nullable    = false

  validation {
    condition = (
      startswith(var.api_access_log_group_arn, "arn:") &&
      strcontains(var.api_access_log_group_arn, ":logs:${var.region}:${var.account_id}:log-group:") &&
      !strcontains(var.api_access_log_group_arn, "*")
    )
    error_message = "api_access_log_group_arn must be exact and bound to the deployment account and region."
  }
}

variable "identity_contract" {
  type = object({
    contract_id                = string
    schema_version             = string
    contract_digest            = string
    customer_id                = string
    deployment_id              = string
    account_id                 = string
    region                     = string
    aws_partition              = string
    cognito_user_pool_id       = string
    cognito_issuer_url         = string
    cognito_spa_client_id      = string
    m2m_client_ids             = list(string)
    resource_server_identifier = string
    allowed_token_uses         = list(string)
    action_scopes = object({
      read  = string
      write = string
      admin = string
    })
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
    policy_version                     = string
    policy_digest                      = string
    policy_canonicalization            = string
    human_runtime_provisioning_enabled = bool
    m2m_runtime_provisioning_enabled   = bool
    m2m_client_secret_values_exposed   = bool
  })
  description = "Typed verified identity-control-plane/v1 contract projection required by the JWT edge."
  nullable    = false
}

variable "expected_identity_contract_digest" {
  type        = string
  description = "Expected identity-control-plane/v1 digest from the immutable deployment record."
  nullable    = false

  validation {
    condition     = can(regex("^sha256:[0-9a-f]{64}$", var.expected_identity_contract_digest))
    error_message = "expected_identity_contract_digest must be sha256:<64 lowercase hex>."
  }
}

variable "domain_name" {
  type        = string
  description = "Deployment DNS name retained as non-authoritative routing metadata."
  nullable    = false
}

variable "cors_allowed_origins" {
  type        = list(string)
  description = "Exact deployment HTTPS origins allowed by CORS."
  nullable    = false
}

variable "api_authorization_routes" {
  type        = map(list(string))
  description = "Closed API route-key to canonical OAuth scope mapping."
  nullable    = false
}

variable "legacy_identity_handoff_complete" {
  type        = bool
  description = "Reviewed state-transfer/no-legacy-state assertion required before edge changes."
  nullable    = false
}
