mock_provider "aws" {
  override_during = plan
}

mock_provider "aws" {
  alias           = "us_east_1"
  override_during = plan
}

variables {
  customer_id             = "cust_01ARZ3NDEKTSV4RRFFQ69G5FAV"
  deployment_id           = "dep_01ARZ3NDEKTSV4RRFFQ69G5FAV"
  account_id              = "123456789012"
  region                  = "us-east-1"
  environment             = "sandbox"
  release_version         = "v2.1.0"
  release_manifest_digest = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
  domain_name             = "app.synthetic.example"
  route53_zone_id         = "ZSYNTHETIC123"

  api_gateway_id              = "abc123def4"
  api_gateway_endpoint        = "https://abc123def4.execute-api.us-east-1.amazonaws.com"
  frontend_bucket_domain_name = "scanalyze-123456789012-frontend.s3.us-east-1.amazonaws.com"

  upstream_contract_digest = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
  expected_upstream_digest = "sha256:1111111111111111111111111111111111111111111111111111111111111111"

  aws_partition         = "aws"
  cognito_user_pool_id  = "us-east-1_SYNTHETIC01"
  cognito_issuer_url    = "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_SYNTHETIC01"
  cognito_spa_client_id = "syntheticspaclient000000000001"
  allowed_token_uses    = ["access"]
  identity_action_scopes = {
    read  = "scanalyze.api.v1/read"
    write = "scanalyze.api.v1/write"
    admin = "scanalyze.api.v1/admin"
  }
  identity_policy_version          = "1.0.0"
  identity_policy_digest           = "sha256:34a639992f6c2312176ac7dc12c361daa38201adea6af0c0b1765a17a14754f8"
  identity_policy_canonicalization = "rfc8785_json_canonicalization"
  id_tokens_accepted               = false
  frontend_features = {
    document_upload     = true
    batch_processing    = true
    audit_view          = false
    user_administration = false
  }
}

run "forwards_only_the_reviewed_document_journey_request_headers" {
  command = plan

  assert {
    condition = (
      toset([
        for behavior in aws_cloudfront_distribution.main.ordered_cache_behavior : behavior.path_pattern
        if behavior.target_origin_id == "api-gateway"
      ]) == toset(["/api", "/api/*"]) &&
      alltrue([
        for behavior in aws_cloudfront_distribution.main.ordered_cache_behavior :
        toset(behavior.forwarded_values[0].headers) == toset([
          "Authorization",
          "Content-Type",
          "Idempotency-Key",
          "Origin",
          "X-Correlation-ID",
          "X-Scanalyze-Contract-Version",
        ]) &&
        behavior.forwarded_values[0].query_string == true &&
        behavior.forwarded_values[0].cookies[0].forward == "none"
        if behavior.target_origin_id == "api-gateway"
      ])
    )
    error_message = "the API facade must forward exactly the reviewed auth, content, origin, idempotency, correlation, and contract-version headers"
  }

  assert {
    condition = alltrue([
      for behavior in aws_cloudfront_distribution.main.ordered_cache_behavior :
      !contains([for header in behavior.forwarded_values[0].headers : lower(header)], "x-tenant-id")
      if behavior.target_origin_id == "api-gateway"
    ])
    error_message = "CloudFront must not forward a browser-supplied tenant identity header"
  }
}

run "preserves_explicit_v2_and_bounds_the_historical_api_facade" {
  command = plan

  assert {
    condition = (
      output.frontend_runtime_config.api_endpoint == "https://${var.domain_name}/api" &&
      aws_cloudfront_function.api_path_rewrite.code == file("${path.module}/api_path_rewrite.js") &&
      strcontains(aws_cloudfront_function.api_path_rewrite.code, "request.uri === '/api/v2'") &&
      strcontains(aws_cloudfront_function.api_path_rewrite.code, "request.uri.indexOf('/api/v2/') === 0") &&
      strcontains(aws_cloudfront_function.api_path_rewrite.code, "request.uri === '/api'") &&
      strcontains(aws_cloudfront_function.api_path_rewrite.code, "request.uri.indexOf('/api/') === 0") &&
      strcontains(aws_cloudfront_function.api_path_rewrite.code, "request.uri = '/api/v1'") &&
      strcontains(aws_cloudfront_function.api_path_rewrite.code, "request.uri.substring(4)") &&
      !strcontains(aws_cloudfront_function.api_path_rewrite.code, "request.uri = '/';")
    )
    error_message = "the edge function must preserve explicit /api/v2 requests and bound only the historical /api facade to /api/v1"
  }
}
