variable "deployment_id" {
  type        = string
  description = "Unique deployment identifier"
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
  description = "AWS account ID"
}

variable "region" {
  type        = string
  description = "AWS region"
}

variable "release_version" {
  type        = string
  description = "Release version being deployed"
}

variable "release_manifest_digest" {
  type        = string
  description = "SHA-256 digest of the release manifest"
}

# From upstream contracts
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
  description = "ALB HTTPS listener ARN from platform contract"
}

variable "alb_security_group_id" {
  type        = string
  description = "ALB security group ID from platform contract"
}

variable "service_definitions" {
  type = list(object({
    name              = string
    image             = string # Must use @sha256 digest
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
      can(regex("^[^@[:space:]]+@sha256:[0-9a-f]{64}$", svc.image))
    ])
    error_message = "every service image must be an immutable digest reference ending in @sha256:<64 lowercase hex>"
  }

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

variable "identity_control_plane_contract" {
  type = object({
    # Publisher envelope metadata. Every other field maps one-for-one to
    # contract-identity-control-plane.v1.schema.json outputs.
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
  description = "Verified identity-control-plane/v1 handoff; contains identifiers and digests only, never secrets"
  nullable    = false

  validation {
    condition = (
      var.identity_control_plane_contract.contract_id == "identity-control-plane/v1" &&
      can(regex("^sha256:[a-f0-9]{64}$", var.identity_control_plane_contract.contract_digest)) &&
      can(regex("^cust_[0-9A-HJKMNP-TV-Z]{26}$", var.identity_control_plane_contract.customer_id)) &&
      can(regex("^dep_[0-9A-HJKMNP-TV-Z]{26}$", var.identity_control_plane_contract.deployment_id)) &&
      can(regex("^[0-9]{12}$", var.identity_control_plane_contract.account_id)) &&
      can(regex("^[a-z]{2}(-gov)?-[a-z]+-[0-9]+$", var.identity_control_plane_contract.region)) &&
      contains(["aws", "aws-us-gov", "aws-cn"], var.identity_control_plane_contract.aws_partition) &&
      can(regex("^[a-z]{2}(-gov)?-[a-z]+-[0-9]+_[A-Za-z0-9]+$", var.identity_control_plane_contract.cognito_user_pool_id)) &&
      can(regex("^[A-Za-z0-9]{1,128}$", var.identity_control_plane_contract.cognito_spa_client_id)) &&
      var.identity_control_plane_contract.cognito_user_pool_arn == "arn:${var.identity_control_plane_contract.aws_partition}:cognito-idp:${var.identity_control_plane_contract.region}:${var.identity_control_plane_contract.account_id}:userpool/${var.identity_control_plane_contract.cognito_user_pool_id}" &&
      var.identity_control_plane_contract.cognito_issuer_url == "https://cognito-idp.${var.identity_control_plane_contract.region}.${var.identity_control_plane_contract.aws_partition == "aws-cn" ? "amazonaws.com.cn" : "amazonaws.com"}/${var.identity_control_plane_contract.cognito_user_pool_id}"
    )
    error_message = "identity_control_plane_contract envelope and provider tuple must be canonical and internally consistent"
  }

  validation {
    condition = (
      var.identity_control_plane_contract.resource_server_identifier == "scanalyze.api.v1" &&
      var.identity_control_plane_contract.allowed_token_uses == tolist(["access"]) &&
      var.identity_control_plane_contract.action_scopes.read == "scanalyze.api.v1/read" &&
      var.identity_control_plane_contract.action_scopes.write == "scanalyze.api.v1/write" &&
      var.identity_control_plane_contract.action_scopes.admin == "scanalyze.api.v1/admin" &&
      var.identity_control_plane_contract.action_scope_sets.read == tolist(["scanalyze.api.v1/read"]) &&
      var.identity_control_plane_contract.action_scope_sets.write == tolist(["scanalyze.api.v1/write"]) &&
      var.identity_control_plane_contract.action_scope_sets.admin == tolist(["scanalyze.api.v1/admin"]) &&
      var.identity_control_plane_contract.customer_claim_name == "custom:customerId" &&
      var.identity_control_plane_contract.deployment_claim_name == "custom:deployment_id"
    )
    error_message = "identity_control_plane_contract must be access-only and use the canonical resource server, scopes, and claims"
  }

  validation {
    condition = (
      var.identity_control_plane_contract.policy_version == "1.0.0" &&
      var.identity_control_plane_contract.policy_digest == "sha256:34a639992f6c2312176ac7dc12c361daa38201adea6af0c0b1765a17a14754f8" &&
      var.identity_control_plane_contract.policy_canonicalization == "rfc8785_json_canonicalization" &&
      var.identity_control_plane_contract.authz_schema_version == "enterprise-authorization.v1" &&
      var.identity_control_plane_contract.scope_catalog_version == "scanalyze.api.v1" &&
      var.identity_control_plane_contract.role_catalog_version == "enterprise-roles.v1"
    )
    error_message = "identity_control_plane_contract must carry the exact reviewed policy digest and catalog versions"
  }

  validation {
    condition = (
      var.identity_control_plane_contract.human_role_groups == tolist(["customer_admin", "document_operator", "document_reviewer", "auditor"]) &&
      !var.identity_control_plane_contract.provider_groups_authoritative &&
      var.identity_control_plane_contract.pre_token_generation_version == "V2_0" &&
      !var.identity_control_plane_contract.human_runtime_provisioning_enabled &&
      var.identity_control_plane_contract.m2m_runtime_provisioning_enabled &&
      !var.identity_control_plane_contract.m2m_client_secret_values_exposed
    )
    error_message = "identity_control_plane_contract role ordering, trigger version, and lifecycle flags must be fail-closed"
  }

  validation {
    condition = (
      length(var.identity_control_plane_contract.m2m_client_ids) == length(distinct(var.identity_control_plane_contract.m2m_client_ids)) &&
      alltrue([
        for client_id in var.identity_control_plane_contract.m2m_client_ids : can(regex("^[A-Za-z0-9]{1,128}$", client_id))
      ]) &&
      length(var.identity_control_plane_contract.m2m_bindings) == length(distinct([
        for binding in var.identity_control_plane_contract.m2m_bindings : binding.client_id
      ])) &&
      length(setsubtract(
        toset(var.identity_control_plane_contract.m2m_client_ids),
        toset([for binding in var.identity_control_plane_contract.m2m_bindings : binding.client_id]),
      )) == 0 &&
      length(setsubtract(
        toset([for binding in var.identity_control_plane_contract.m2m_bindings : binding.client_id]),
        toset(var.identity_control_plane_contract.m2m_client_ids),
      )) == 0 &&
      alltrue([
        for binding in var.identity_control_plane_contract.m2m_bindings :
        binding.customer_id == var.identity_control_plane_contract.customer_id &&
        binding.deployment_id == var.identity_control_plane_contract.deployment_id &&
        length(binding.required_scopes) > 0 &&
        length(binding.required_scopes) == length(distinct(binding.required_scopes)) &&
        alltrue([
          for scope in binding.required_scopes : contains(values(var.identity_control_plane_contract.action_scopes), scope)
        ])
      ])
    )
    error_message = "identity_control_plane_contract M2M IDs must match unique, deployment-bound bindings with canonical scopes"
  }
}

variable "expected_identity_control_plane_contract_digest" {
  type        = string
  description = "Expected digest from the authoritative deployment record"
  nullable    = false

  validation {
    condition     = can(regex("^sha256:[a-f0-9]{64}$", var.expected_identity_control_plane_contract_digest))
    error_message = "expected_identity_control_plane_contract_digest must be sha256:<64 lowercase hex>"
  }
}

# Upstream contract
variable "upstream_contract_digest" {
  type        = string
  description = "SHA-256 digest of upstream data-foundation contract"
}

variable "expected_upstream_digest" {
  type        = string
  description = "Expected upstream contract digest"
}
