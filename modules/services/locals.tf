locals {
  # Layer metadata
  layer_name   = "services"
  layer_number = "4"
  state_scope  = "regional" # "global" or "regional"

  # Contract identity binding
  contract_key = "services/v1"

  identity_aware_services = toset(["ingest-api", "scanalyze-ingest-api"])
  m2m_bindings_enabled    = length(var.identity_control_plane_contract.m2m_bindings) > 0
  m2m_client_identity_bindings_v1 = {
    for binding in var.identity_control_plane_contract.m2m_bindings : binding.client_id => {
      customer_id     = binding.customer_id
      deployment_id   = binding.deployment_id
      required_scopes = binding.required_scopes
    }
  }
  m2m_environment = local.m2m_bindings_enabled ? [
    {
      name  = "M2M_TENANT_RESOLUTION"
      value = "client_identity_bindings_v1"
    },
    {
      name  = "M2M_CLIENT_IDENTITY_BINDINGS_V1"
      value = jsonencode(local.m2m_client_identity_bindings_v1)
    },
    {
      name  = "M2M_ACTION_SCOPE_SETS_V1"
      value = jsonencode(var.identity_control_plane_contract.action_scope_sets)
    },
    ] : [
    {
      name  = "M2M_TENANT_RESOLUTION"
      value = "disabled"
    },
  ]
  identity_environment = concat([
    {
      name  = "AUTH_MODE"
      value = "cognito_jwt"
    },
    {
      name  = "COGNITO_USER_POOL_ID"
      value = var.identity_control_plane_contract.cognito_user_pool_id
    },
    {
      name  = "COGNITO_REGION"
      value = var.identity_control_plane_contract.region
    },
    {
      name  = "COGNITO_ALLOWED_TOKEN_USES"
      value = "access"
    },
    {
      name = "COGNITO_ALLOWED_CLIENT_IDS"
      value = join(",", concat(
        [var.identity_control_plane_contract.cognito_spa_client_id],
        sort(var.identity_control_plane_contract.m2m_client_ids),
      ))
    },
    {
      name  = "TENANT_CLAIM_NAME"
      value = var.identity_control_plane_contract.customer_claim_name
    },
    {
      name  = "DEPLOYMENT_CLAIM_NAME"
      value = var.identity_control_plane_contract.deployment_claim_name
    },
    {
      name  = "ENTERPRISE_AUTHORIZATION_SCHEMA_VERSION"
      value = var.identity_control_plane_contract.authz_schema_version
    },
    {
      name  = "ENTERPRISE_ROLE_CATALOG_VERSION"
      value = var.identity_control_plane_contract.role_catalog_version
    },
    {
      name  = "ENTERPRISE_SCOPE_CATALOG_VERSION"
      value = var.identity_control_plane_contract.scope_catalog_version
    },
    {
      name  = "ENTERPRISE_POLICY_VERSION"
      value = var.identity_control_plane_contract.policy_version
    },
    {
      name  = "ENTERPRISE_POLICY_DIGEST"
      value = var.identity_control_plane_contract.policy_digest
    },
    {
      name  = "HUMAN_ENTERPRISE_AUTHORIZATION_ENABLED"
      value = "false"
    },
  ], local.m2m_environment)
}
