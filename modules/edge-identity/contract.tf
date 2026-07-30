output "contract_payload" {
  description = "Publisher-compatible edge-identity/v2 contract; contains no secrets."
  value = {
    schema_version = "2"
    layer          = local.layer_name
    state_scope    = local.state_scope
    outputs = {
      customer_id   = var.customer_id
      deployment_id = var.deployment_id
      account_id    = var.account_id
      region        = var.region
      aws_partition = var.aws_partition

      identity_control_plane_contract_id     = "identity-control-plane/v1"
      identity_control_plane_contract_digest = var.upstream_contract_digest
      cognito_user_pool_id                   = var.cognito_user_pool_id
      cognito_issuer_url                     = var.cognito_issuer_url
      cognito_spa_client_id                  = var.cognito_spa_client_id
      m2m_client_ids                         = var.cognito_m2m_client_ids
      allowed_token_uses                     = ["access"]
      action_scopes                          = var.identity_action_scopes
      policy_version                         = var.identity_policy_version
      policy_digest                          = var.identity_policy_digest
      policy_canonicalization                = var.identity_policy_canonicalization

      api_gateway_id             = aws_apigatewayv2_api.main.id
      api_gateway_endpoint       = aws_apigatewayv2_api.main.api_endpoint
      api_gateway_stage          = aws_apigatewayv2_stage.live.name
      api_gateway_authorizer_id  = aws_apigatewayv2_authorizer.jwt.id
      authorizer_type            = "native_jwt"
      authorizer_audiences       = local.authorizer_audiences
      route_authorization_scopes = var.api_authorization_routes

      id_tokens_accepted                     = false
      request_identity_headers_authoritative = false
      x_tenant_id_fallback_enabled           = false
    }
  }
}
