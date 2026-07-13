mock_provider "aws" {}

variables {
  deployment_id           = "dep_01ARZ3NDEKTSV4RRFFQ69G5FAV"
  customer_id             = "cust_01ARZ3NDEKTSV4RRFFQ69G5FAV"
  account_id              = "000000000000"
  region                  = "us-east-1"
  release_version         = "v0.0.0-synthetic"
  release_manifest_digest = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
  domain_name             = "synthetic.example"

  vpc_id = "vpc-00000000000000000"
  private_subnet_ids = {
    use1-az1 = "subnet-00000000000000000"
  }
  alb_listener_arn                 = "arn:aws:elasticloadbalancing:us-east-1:000000000000:listener/app/synthetic/0000000000000000/0000000000000000"
  alb_security_group_id            = "sg-00000000000000000"
  api_access_log_group_arn         = "arn:aws:logs:us-east-1:000000000000:log-group:/scanalyze/synthetic/api"
  legacy_identity_handoff_complete = true

  upstream_contract_digest = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
  expected_upstream_digest = "sha256:1111111111111111111111111111111111111111111111111111111111111111"

  cognito_issuer_url    = "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_SYNTHETIC"
  cognito_user_pool_id  = "us-east-1_SYNTHETIC"
  cognito_spa_client_id = "syntheticspaclient"
  cognito_m2m_client_ids = [
    "syntheticworkloadclient",
  ]
  identity_action_scopes = {
    read  = "scanalyze.api.v1/read"
    write = "scanalyze.api.v1/write"
    admin = "scanalyze.api.v1/admin"
  }
  identity_policy_version          = "1.0.0"
  identity_policy_digest           = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
  identity_policy_canonicalization = "rfc8785_json_canonicalization"

  cors_allowed_origins = [
    "https://app.synthetic.example",
  ]

  api_authorization_routes = {
    "GET /documents" = [
      "scanalyze.api.v1/read",
    ]
    "POST /documents" = [
      "scanalyze.api.v1/write",
    ]
    "POST /batches/{batch_id}/export" = [
      "scanalyze.api.v1/admin",
    ]
  }
}

run "binds_the_authorizer_to_every_reviewed_client_audience" {
  command = apply

  assert {
    condition = toset(aws_apigatewayv2_authorizer.jwt.jwt_configuration[0].audience) == toset(concat(
      [var.cognito_spa_client_id],
      var.cognito_m2m_client_ids,
    ))
    error_message = "the JWT authorizer audience must be the exact reviewed SPA and workload client registry"
  }

  assert {
    condition     = aws_apigatewayv2_authorizer.jwt.jwt_configuration[0].issuer == var.cognito_issuer_url
    error_message = "the authorizer issuer must come from the exact identity-control-plane contract"
  }
}

run "accepts_an_empty_bootstrap_registry_without_authorizing_m2m" {
  command = apply

  variables {
    cognito_m2m_client_ids = []
  }

  assert {
    condition = (
      toset(aws_apigatewayv2_authorizer.jwt.jwt_configuration[0].audience) == toset([var.cognito_spa_client_id]) &&
      length(output.contract_payload.outputs.m2m_client_ids) == 0 &&
      toset(output.contract_payload.outputs.authorizer_audiences) == toset([var.cognito_spa_client_id])
    )
    error_message = "an empty reviewed registry must produce a SPA-only audience and never infer an M2M client"
  }
}

run "requires_canonical_authorization_scopes_on_every_protected_route" {
  command = apply

  assert {
    condition     = length(aws_apigatewayv2_route.protected) == length(var.api_authorization_routes)
    error_message = "every reviewed route mapping must produce one explicit API Gateway route"
  }

  assert {
    condition = alltrue([
      for route_key, route in aws_apigatewayv2_route.protected :
      route.route_key == route_key &&
      route.route_key != "$default" &&
      route.authorization_type == "JWT" &&
      route.authorizer_id == aws_apigatewayv2_authorizer.jwt.id &&
      toset(route.authorization_scopes) == toset(var.api_authorization_routes[route_key]) &&
      length(route.authorization_scopes) == 1 &&
      length(setsubtract(
        toset(route.authorization_scopes),
        toset([
          "scanalyze.api.v1/read",
          "scanalyze.api.v1/write",
          "scanalyze.api.v1/admin",
        ]),
      )) == 0
    ])
    error_message = "protected routes must be explicit, JWT-authorized, and require only the canonical reviewed scopes"
  }
}

run "rejects_a_malformed_route_key_even_with_a_canonical_scope" {
  command = plan

  variables {
    api_authorization_routes = {
      "GET /documents?admin=true" = ["scanalyze.api.v1/read"]
    }
  }

  expect_failures = [var.api_authorization_routes]
}

run "uses_an_exact_cors_allowlist_without_legacy_identity_headers" {
  command = apply

  assert {
    condition = (
      toset(aws_apigatewayv2_api.main.cors_configuration[0].allow_origins) == toset(var.cors_allowed_origins) &&
      alltrue([
        for origin in aws_apigatewayv2_api.main.cors_configuration[0].allow_origins :
        origin != "*" && startswith(origin, "https://") && !strcontains(lower(origin), "localhost")
      ])
    )
    error_message = "CORS origins must be exact deployment HTTPS origins; wildcard and localhost are forbidden"
  }

  assert {
    condition = (
      !contains([
        for header in aws_apigatewayv2_api.main.cors_configuration[0].allow_headers :
        lower(header)
      ], "x-tenant-id") &&
      toset([
        for header in aws_apigatewayv2_api.main.cors_configuration[0].allow_headers :
        lower(header)
        ]) == toset([
        "authorization",
        "content-type",
        "x-amz-date",
      ])
    )
    error_message = "CORS must not advertise X-Tenant-ID or unreviewed headers as identity inputs"
  }
}

run "requires_a_reviewed_stage_and_sanitized_access_logs" {
  command = apply

  assert {
    condition     = !aws_apigatewayv2_stage.live.auto_deploy
    error_message = "identity-facing route changes must use an explicit reviewed API deployment"
  }

  assert {
    condition = length(setintersection(
      toset(keys(jsondecode(aws_apigatewayv2_stage.live.access_log_settings[0].format))),
      toset([
        "authorization",
        "caller",
        "email",
        "ip",
        "token",
        "user",
      ]),
    )) == 0
    error_message = "API access logs must not contain tokens, identity claims, source IP, email, caller, or user fields"
  }
}

run "publishes_the_exact_edge_identity_v2_contract" {
  command = apply

  assert {
    condition = toset(keys(output.contract_payload)) == toset([
      "schema_version",
      "layer",
      "state_scope",
      "outputs",
    ])
    error_message = "edge-identity must publish one unambiguous publisher-compatible payload"
  }

  assert {
    condition = toset(keys(output.contract_payload.outputs)) == toset([
      "customer_id",
      "deployment_id",
      "account_id",
      "region",
      "aws_partition",
      "identity_control_plane_contract_id",
      "identity_control_plane_contract_digest",
      "cognito_user_pool_id",
      "cognito_issuer_url",
      "cognito_spa_client_id",
      "m2m_client_ids",
      "allowed_token_uses",
      "action_scopes",
      "policy_version",
      "policy_digest",
      "policy_canonicalization",
      "api_gateway_id",
      "api_gateway_endpoint",
      "api_gateway_stage",
      "api_gateway_authorizer_id",
      "authorizer_type",
      "authorizer_audiences",
      "route_authorization_scopes",
      "id_tokens_accepted",
      "request_identity_headers_authoritative",
      "x_tenant_id_fallback_enabled",
    ])
    error_message = "nested outputs must match contract-edge-identity.v2 exactly"
  }

  assert {
    condition = alltrue([
      output.contract_payload.schema_version == "2",
      output.contract_payload.layer == "edge-identity",
      output.contract_payload.outputs.identity_control_plane_contract_id == "identity-control-plane/v1",
      output.contract_payload.outputs.identity_control_plane_contract_digest == var.upstream_contract_digest,
      output.contract_payload.outputs.allowed_token_uses == ["access"],
      output.contract_payload.outputs.action_scopes == var.identity_action_scopes,
      output.contract_payload.outputs.authorizer_audiences == concat([var.cognito_spa_client_id], var.cognito_m2m_client_ids),
      output.contract_payload.outputs.route_authorization_scopes == var.api_authorization_routes,
      output.contract_payload.outputs.id_tokens_accepted == false,
      output.contract_payload.outputs.request_identity_headers_authoritative == false,
      output.contract_payload.outputs.x_tenant_id_fallback_enabled == false,
      !strcontains(lower(jsonencode(output.contract_payload.outputs)), "client_secret"),
    ])
    error_message = "edge-identity/v2 must preserve exact identity binding, access tokens, audiences, and no-secret constraints"
  }
}
