variable "deployment_id" {
  type        = string
  description = "Unique deployment identifier (ULID with dep_ prefix)"
  nullable    = false
  validation {
    condition     = can(regex("^dep_[0-9A-HJKMNP-TV-Z]{26}$", var.deployment_id))
    error_message = "deployment_id must match ^dep_[0-9A-HJKMNP-TV-Z]{26}$"
  }
}

variable "customer_id" {
  type        = string
  description = "Immutable customer identifier resolved from the deployment record"
  nullable    = false

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
}

variable "release_version" {
  type        = string
  description = "Release version being deployed"
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
  description = "Exact output schema identifier from the verified upstream envelope"
}

variable "accepted_schema_versions" {
  type        = list(string)
  default     = ["2"]
  description = "List of accepted upstream contract schema versions"
}

variable "identity_control_plane_contract" {
  type = object({
    contract_id                = string
    contract_digest            = string
    customer_id                = string
    deployment_id              = string
    account_id                 = string
    region                     = string
    aws_partition              = string
    cognito_user_pool_id       = string
    cognito_user_pool_arn      = string
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
    customer_claim_name                = string
    deployment_claim_name              = string
    policy_version                     = string
    policy_digest                      = string
    policy_canonicalization            = string
    authz_schema_version               = string
    scope_catalog_version              = string
    role_catalog_version               = string
    human_role_groups                  = list(string)
    provider_groups_authoritative      = bool
    pre_token_generation_version       = string
    human_runtime_provisioning_enabled = bool
    m2m_runtime_provisioning_enabled   = bool
    m2m_client_secret_values_exposed   = bool
  })
  description = "Verified identity-control-plane/v1 handoff without secret values"
  nullable    = false
}

variable "expected_identity_control_plane_contract_digest" {
  type        = string
  description = "Expected identity-control-plane/v1 digest from the deployment record"
  nullable    = false

  validation {
    condition = (
      can(regex("^sha256:[a-f0-9]{64}$", var.expected_identity_control_plane_contract_digest)) &&
      var.expected_identity_control_plane_contract_digest == var.identity_control_plane_contract.contract_digest
    )
    error_message = "expected_identity_control_plane_contract_digest must be the exact trusted sha256 digest carried by the identity contract envelope"
  }
}

# --- Variables consumed by modules/services ---

variable "ecs_cluster_arn" {
  type        = string
  description = "ECS cluster ARN from platform contract"
}

variable "ecs_task_execution_role_arn" {
  type        = string
  description = "ECS task execution role ARN from global contract"
}

variable "workload_role_arns" {
  type        = map(string)
  description = "Map of service name to workload IAM role ARN from global contract"
}

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
  description = "Internal ALB listener ARN from platform contract"
}

variable "alb_security_group_id" {
  type        = string
  description = "ALB security group ID from platform contract"
}

variable "service_definitions" {
  type = list(object({
    name              = string
    image             = string
    cpu               = number
    memory            = number
    port              = optional(number)
    desired_count     = optional(number, 1)
    health_check_path = optional(string, "/health")
    extra_environment = optional(list(object({
      name  = string
      value = string
    })), [])
  }))
  description = "Service definitions for ECS tasks (Terraform sole owner)"

  validation {
    condition = alltrue([
      for svc in var.service_definitions :
      length(distinct([for item in svc.extra_environment : upper(item.name)])) == length(svc.extra_environment)
    ])
    error_message = "extra_environment variable names must be case-insensitively unique within each service definition"
  }

  validation {
    condition = alltrue(flatten([
      for svc in var.service_definitions : [
        for item in svc.extra_environment : !contains([
          "AUTH_MODE",
          "COGNITO_ALLOWED_CLIENT_IDS",
          "COGNITO_ALLOWED_TOKEN_USES",
          "COGNITO_REGION",
          "COGNITO_USER_POOL_ID",
          "DEPLOYMENT_CLAIM_NAME",
          "ENTERPRISE_AUTHORIZATION_SCHEMA_VERSION",
          "ENTERPRISE_POLICY_DIGEST",
          "ENTERPRISE_POLICY_VERSION",
          "ENTERPRISE_ROLE_CATALOG_VERSION",
          "ENTERPRISE_SCOPE_CATALOG_VERSION",
          "HUMAN_ENTERPRISE_AUTHORIZATION_ENABLED",
          "M2M_ACTION_SCOPE_SETS_V1",
          "M2M_CLIENT_IDENTITY_BINDINGS_V1",
          "M2M_TENANT_RESOLUTION",
          "SCANALYZE_DEPLOYMENT_CUSTOMER_ID",
          "SCANALYZE_DEPLOYMENT_ID",
          "TENANT_CLAIM_NAME",
          "AWS_REGION",
          "RELEASE_VERSION",
        ], upper(item.name))
      ]
    ]))
    error_message = "extra_environment cannot override Terraform-owned identity or release variables"
  }
}
