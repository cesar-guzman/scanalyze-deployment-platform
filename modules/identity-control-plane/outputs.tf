output "contract_payload" {
  description = "Publisher-compatible identity-control-plane/v1 contract; contains no secrets or artifact locators."
  value = {
    schema_version = "1"
    layer          = local.layer_name
    state_scope    = local.state_scope
    outputs = {
      customer_id   = var.customer_id
      deployment_id = var.deployment_id
      account_id    = var.account_id
      region        = var.region
      aws_partition = var.aws_partition

      cognito_user_pool_id  = aws_cognito_user_pool.main.id
      cognito_user_pool_arn = aws_cognito_user_pool.main.arn
      cognito_issuer_url    = "https://cognito-idp.${var.region}.${local.aws_dns_suffix}/${aws_cognito_user_pool.main.id}"
      cognito_spa_client_id = aws_cognito_user_pool_client.spa.id
      m2m_client_ids        = sort([for binding in var.m2m_bindings : binding.client_id])

      resource_server_identifier = aws_cognito_resource_server.api.identifier
      allowed_token_uses         = ["access"]
      action_scopes = {
        read  = "${aws_cognito_resource_server.api.identifier}/read"
        write = "${aws_cognito_resource_server.api.identifier}/write"
        admin = "${aws_cognito_resource_server.api.identifier}/admin"
      }
      action_scope_sets = {
        read  = ["${aws_cognito_resource_server.api.identifier}/read"]
        write = ["${aws_cognito_resource_server.api.identifier}/write"]
        admin = ["${aws_cognito_resource_server.api.identifier}/admin"]
      }
      m2m_bindings          = var.m2m_bindings
      customer_claim_name   = "custom:customerId"
      deployment_claim_name = "custom:deployment_id"

      policy_version          = var.policy_version
      policy_digest           = var.policy_digest
      policy_canonicalization = "rfc8785_json_canonicalization"
      authz_schema_version    = "enterprise-authorization.v1"
      scope_catalog_version   = "scanalyze.api.v1"
      role_catalog_version    = "enterprise-roles.v1"

      human_role_groups = [
        "customer_admin",
        "document_operator",
        "document_reviewer",
        "auditor",
      ]
      provider_groups_authoritative      = false
      pre_token_generation_version       = "V2_0"
      human_runtime_provisioning_enabled = false
      m2m_runtime_provisioning_enabled   = var.control_processor_enabled
      m2m_client_secret_values_exposed   = false
    }
  }
}
