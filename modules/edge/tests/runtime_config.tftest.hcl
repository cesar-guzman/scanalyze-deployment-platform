mock_provider "aws" {
  override_during = plan

  mock_resource "aws_acm_certificate" {
    defaults = {
      arn = "arn:aws:acm:us-east-1:123456789012:certificate/00000000-0000-0000-0000-000000000000"
      domain_validation_options = [{
        domain_name           = "app.synthetic.example"
        resource_record_name  = "_synthetic.app.synthetic.example"
        resource_record_type  = "CNAME"
        resource_record_value = "_synthetic.acm-validations.aws"
      }]
    }
  }

  mock_resource "aws_acm_certificate_validation" {
    defaults = {
      certificate_arn = "arn:aws:acm:us-east-1:123456789012:certificate/00000000-0000-0000-0000-000000000000"
    }
  }

  mock_resource "aws_cloudfront_distribution" {
    defaults = {
      arn            = "arn:aws:cloudfront::123456789012:distribution/ESYNTHETIC"
      domain_name    = "d111111abcdef8.cloudfront.net"
      hosted_zone_id = "Z2FDTNDATAQYW2"
      id             = "ESYNTHETIC"
    }
  }

  mock_resource "aws_cloudfront_cache_policy" {
    defaults = {
      id = "runtime-config-cache-policy"
    }
  }

  mock_resource "aws_cloudfront_response_headers_policy" {
    defaults = {
      id = "runtime-config-response-headers-policy"
    }
  }

  mock_resource "aws_wafv2_web_acl" {
    defaults = {
      arn = "arn:aws:wafv2:us-east-1:123456789012:global/webacl/synthetic/00000000-0000-0000-0000-000000000000"
    }
  }
}

mock_provider "aws" {
  alias = "us_east_1"

  override_during = plan

  mock_resource "aws_acm_certificate" {
    defaults = {
      arn = "arn:aws:acm:us-east-1:123456789012:certificate/00000000-0000-0000-0000-000000000000"
      domain_validation_options = [{
        domain_name           = "app.synthetic.example"
        resource_record_name  = "_synthetic.app.synthetic.example"
        resource_record_type  = "CNAME"
        resource_record_value = "_synthetic.acm-validations.aws"
      }]
    }
  }

  mock_resource "aws_acm_certificate_validation" {
    defaults = {
      certificate_arn = "arn:aws:acm:us-east-1:123456789012:certificate/00000000-0000-0000-0000-000000000000"
    }
  }

  mock_resource "aws_cloudfront_distribution" {
    defaults = {
      arn            = "arn:aws:cloudfront::123456789012:distribution/ESYNTHETIC"
      domain_name    = "d111111abcdef8.cloudfront.net"
      hosted_zone_id = "Z2FDTNDATAQYW2"
      id             = "ESYNTHETIC"
    }
  }

  mock_resource "aws_cloudfront_cache_policy" {
    defaults = {
      id = "runtime-config-cache-policy"
    }
  }

  mock_resource "aws_cloudfront_response_headers_policy" {
    defaults = {
      id = "runtime-config-response-headers-policy"
    }
  }

  mock_resource "aws_wafv2_web_acl" {
    defaults = {
      arn = "arn:aws:wafv2:us-east-1:123456789012:global/webacl/synthetic/00000000-0000-0000-0000-000000000000"
    }
  }
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

run "renders_the_exact_public_frontend_config_v3" {
  command = plan

  assert {
    condition = jsonencode(output.frontend_runtime_config) == jsonencode({
      schema_version = "3"
      config_version = "v2.1.0"
      customer_id    = "cust_01ARZ3NDEKTSV4RRFFQ69G5FAV"
      deployment_id  = "dep_01ARZ3NDEKTSV4RRFFQ69G5FAV"
      account_id     = "123456789012"
      region         = "us-east-1"
      environment    = "sandbox"
      api_endpoint   = "https://app.synthetic.example/api"
      cognito = {
        user_pool_id             = "us-east-1_SYNTHETIC01"
        spa_client_id            = "syntheticspaclient000000000001"
        issuer_url               = "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_SYNTHETIC01"
        region                   = "us-east-1"
        hosted_ui_domain         = "https://dep-01arz3ndektsv4rrffq69g5fav-identity.auth.us-east-1.amazoncognito.com"
        redirect_uri             = "https://app.synthetic.example/callback"
        post_logout_redirect_uri = "https://app.synthetic.example/"
        allowed_oauth_flows      = ["code"]
        pkce_required            = true
        client_secret_embedded   = false
      }
      authorization = {
        allowed_token_uses = ["access"]
        action_scopes = {
          read  = "scanalyze.api.v1/read"
          write = "scanalyze.api.v1/write"
          admin = "scanalyze.api.v1/admin"
        }
        policy_version          = "1.0.0"
        policy_digest           = "sha256:34a639992f6c2312176ac7dc12c361daa38201adea6af0c0b1765a17a14754f8"
        policy_canonicalization = "rfc8785_json_canonicalization"
        customer_claim_name     = "custom:customerId"
        deployment_claim_name   = "custom:deployment_id"
        id_tokens_accepted      = false
      }
      identity_values_authoritative = false
      features = {
        document_upload     = true
        batch_processing    = true
        audit_view          = false
        user_administration = false
      }
    })
    error_message = "edge must emit the exact closed frontend-config/v3 object"
  }

  assert {
    condition     = output.frontend_runtime_config_json == jsonencode(output.frontend_runtime_config)
    error_message = "the JSON output must encode exactly the typed runtime-config object"
  }

  assert {
    condition     = output.frontend_runtime_config_sha256 == "sha256:${sha256(output.frontend_runtime_config_json)}"
    error_message = "the runtime-config digest must bind the exact emitted JSON bytes"
  }

  assert {
    condition     = length(output.frontend_runtime_config_json) <= jsondecode(file("${path.module}/../../schemas/frontend-config.v3.schema.json"))["x-maxDocumentBytes"]
    error_message = "the emitted runtime config must fit the browser's canonical byte limit"
  }

  assert {
    condition = (
      output.frontend_runtime_config.cognito.client_secret_embedded == false &&
      output.frontend_runtime_config.identity_values_authoritative == false &&
      !strcontains(lower(output.frontend_runtime_config_json), "\"client_secret\":") &&
      !strcontains(lower(output.frontend_runtime_config_json), "\"access_token\":") &&
      !strcontains(lower(output.frontend_runtime_config_json), "\"refresh_token\":") &&
      !strcontains(lower(output.frontend_runtime_config_json), "\"aws_access_key_id\":") &&
      !strcontains(lower(output.frontend_runtime_config_json), "\"private_key\":")
    )
    error_message = "public runtime config must contain no secret, token, credential, or authoritative identity value"
  }
}

run "isolates_runtime_config_from_immutable_asset_caching" {
  command = plan

  assert {
    condition = (
      aws_cloudfront_cache_policy.runtime_config.min_ttl == 0 &&
      aws_cloudfront_cache_policy.runtime_config.default_ttl == 0 &&
      aws_cloudfront_cache_policy.runtime_config.max_ttl == 0
    )
    error_message = "the runtime-config cache policy must disable CloudFront caching with TTL 0/0/0"
  }

  assert {
    condition = (
      one([
        for behavior in aws_cloudfront_distribution.main.ordered_cache_behavior : behavior
        if behavior.path_pattern == "/config.json"
      ]).target_origin_id == "s3-runtime-config" &&
      one([
        for behavior in aws_cloudfront_distribution.main.ordered_cache_behavior : behavior
        if behavior.path_pattern == "/config.json"
      ]).cache_policy_id == aws_cloudfront_cache_policy.runtime_config.id &&
      one([
        for behavior in aws_cloudfront_distribution.main.ordered_cache_behavior : behavior
        if behavior.path_pattern == "/config.json"
      ]).response_headers_policy_id == aws_cloudfront_response_headers_policy.runtime_config.id
    )
    error_message = "/config.json must use only the isolated no-store behavior"
  }

  assert {
    condition = (
      one([
        for origin in aws_cloudfront_distribution.main.origin : origin
        if origin.origin_id == "s3-runtime-config"
      ]).origin_path == "/dep_01ARZ3NDEKTSV4RRFFQ69G5FAV" &&
      aws_cloudfront_distribution.main.default_cache_behavior[0].target_origin_id == "s3-frontend"
    )
    error_message = "runtime config must use the deployment prefix without changing the immutable asset origin"
  }

  assert {
    condition = (
      one(aws_cloudfront_response_headers_policy.runtime_config.custom_headers_config[0].items).header == "Cache-Control" &&
      one(aws_cloudfront_response_headers_policy.runtime_config.custom_headers_config[0].items).override == true &&
      one(aws_cloudfront_response_headers_policy.runtime_config.custom_headers_config[0].items).value == "no-store, max-age=0, must-revalidate"
    )
    error_message = "viewer responses for runtime config must carry the exact no-store header"
  }

  assert {
    condition = (
      length(aws_cloudfront_distribution.main.custom_error_response) == 0 &&
      strcontains(aws_cloudfront_function.spa_route_rewrite.code, "lastSegment.indexOf('.') === -1") &&
      !strcontains(aws_cloudfront_function.spa_route_rewrite.code, "config.json")
    )
    error_message = "SPA navigation fallback must not mask a missing config.json with index.html"
  }
}

run "rewrites_only_the_same_origin_api_prefix_before_api_gateway" {
  command = plan

  assert {
    condition = (
      toset([
        for behavior in aws_cloudfront_distribution.main.ordered_cache_behavior : behavior.path_pattern
        if behavior.target_origin_id == "api-gateway"
      ]) == toset(["/api", "/api/*"]) &&
      alltrue([
        for behavior in aws_cloudfront_distribution.main.ordered_cache_behavior :
        behavior.forwarded_values[0].query_string == true &&
        one(behavior.function_association).event_type == "viewer-request"
        if behavior.target_origin_id == "api-gateway"
      ])
    )
    error_message = "exact /api and /api/* behaviors must preserve query forwarding and use only the API prefix rewrite"
  }

  assert {
    condition = (
      aws_cloudfront_function.api_path_rewrite.code == file("${path.module}/api_path_rewrite.js") &&
      strcontains(aws_cloudfront_function.api_path_rewrite.code, "request.uri === '/api'") &&
      strcontains(aws_cloudfront_function.api_path_rewrite.code, "request.uri.indexOf('/api/') === 0") &&
      strcontains(aws_cloudfront_function.api_path_rewrite.code, "request.uri.substring(4)")
    )
    error_message = "the reviewed function must strip only the exact /api prefix before API Gateway route selection"
  }

  assert {
    condition = one([
      for origin in aws_cloudfront_distribution.main.origin : origin.domain_name
      if origin.origin_id == "api-gateway"
    ]) == "abc123def4.execute-api.us-east-1.amazonaws.com"
    error_message = "CloudFront must derive the API origin from the exact projected API identifier, partition, and region"
  }
}

run "keeps_promotion_write_scope_exact" {
  command = plan

  assert {
    condition = (
      !contains(
        one([
          for statement in jsondecode(file("${path.module}/../../policies/s3/frontend-bucket.json")).Statement : statement
          if statement.Sid == "AllowPromotionWriteFrontend"
        ]).Resource,
        "arn:$${aws_partition}:s3:::scanalyze-$${account_id}-frontend/$${deployment_id}/config.json",
      ) &&
      !contains(
        one([
          for statement in jsondecode(file("${path.module}/../../policies/s3/frontend-bucket.json")).Statement : statement
          if statement.Sid == "AllowPromotionWriteFrontend"
        ]).Resource,
        "arn:$${aws_partition}:s3:::scanalyze-$${account_id}-frontend/$${deployment_id}/*",
      )
    )
    error_message = "Promotion must remain limited to immutable release assets and cannot replace runtime config"
  }

  assert {
    condition = (
      one([
        for statement in jsondecode(file("${path.module}/../../policies/s3/frontend-bucket.json")).Statement : statement
        if statement.Sid == "AllowEdgeApplyRuntimeConfig"
      ]).Resource == "arn:$${aws_partition}:s3:::scanalyze-$${account_id}-frontend/$${deployment_id}/config.json" &&
      one([
        for statement in jsondecode(file("${path.module}/../../policies/s3/frontend-bucket.json")).Statement : statement
        if statement.Sid == "AllowEdgeApplyRuntimeConfig"
      ]).Action == ["s3:GetObject", "s3:PutObject"]
    )
    error_message = "Only the edge apply path may read or write the exact runtime config object"
  }
}

run "publishes_verified_runtime_config_with_no_store_headers" {
  command = plan

  assert {
    condition = (
      aws_s3_object.frontend_runtime_config.bucket == "scanalyze-123456789012-frontend" &&
      aws_s3_object.frontend_runtime_config.key == "dep_01ARZ3NDEKTSV4RRFFQ69G5FAV/config.json" &&
      aws_s3_object.frontend_runtime_config.content == output.frontend_runtime_config_json &&
      aws_s3_object.frontend_runtime_config.content_type == "application/json" &&
      aws_s3_object.frontend_runtime_config.cache_control == "no-store, max-age=0, must-revalidate" &&
      aws_s3_object.frontend_runtime_config.checksum_algorithm == "SHA256" &&
      aws_s3_object.frontend_runtime_config.source_hash == output.frontend_runtime_config_sha256
    )
    error_message = "Terraform must publish the exact validated bytes and cache headers to the exact deployment config object"
  }
}

run "projects_only_reviewed_public_identity_fields" {
  command = plan

  assert {
    condition = jsondecode(file("${path.module}/../../deployment/contract-catalog.v1.json")).contracts["edge-identity/v2"].consumer_bindings.edge.output_variables == {
      api_gateway_id          = "api_gateway_id"
      api_gateway_endpoint    = "api_gateway_endpoint"
      aws_partition           = "aws_partition"
      cognito_user_pool_id    = "cognito_user_pool_id"
      cognito_issuer_url      = "cognito_issuer_url"
      cognito_spa_client_id   = "cognito_spa_client_id"
      allowed_token_uses      = "allowed_token_uses"
      action_scopes           = "identity_action_scopes"
      policy_version          = "identity_policy_version"
      policy_digest           = "identity_policy_digest"
      policy_canonicalization = "identity_policy_canonicalization"
      id_tokens_accepted      = "id_tokens_accepted"
    }
    error_message = "edge projection must contain exactly the reviewed public identity fields needed by frontend-config/v3"
  }
}

run "rejects_unknown_frontend_features" {
  command = plan

  variables {
    frontend_features = {
      document_upload = true
      hidden_admin    = true
    }
  }

  expect_failures = [var.frontend_features]
}

run "rejects_unknown_environment" {
  command = plan

  variables {
    environment = "qa"
  }

  expect_failures = [var.environment]
}

run "rejects_domain_names_over_253_characters" {
  command = plan

  variables {
    domain_name = join(".", [for _ in range(4) : join("", [for _ in range(63) : "a"])])
  }

  expect_failures = [var.domain_name]
}

run "rejects_a_frontend_bucket_outside_the_deployment_account" {
  command = plan

  variables {
    frontend_bucket_domain_name = "attacker-controlled.s3.us-east-1.amazonaws.com"
  }

  expect_failures = [terraform_data.frontend_runtime_config_gate]
}

run "rejects_an_api_endpoint_outside_the_projected_api" {
  command = plan

  variables {
    api_gateway_endpoint = "https://attacker.example"
  }

  expect_failures = [terraform_data.frontend_runtime_config_gate]
}

run "rejects_an_invalid_api_gateway_identifier" {
  command = plan

  variables {
    api_gateway_id = "ABC/invalid"
  }

  expect_failures = [var.api_gateway_id]
}

run "rejects_non_semantic_config_version" {
  command = plan

  variables {
    release_version = "latest"
  }

  expect_failures = [var.release_version]
}

run "rejects_an_oversized_config_version" {
  command = plan

  variables {
    release_version = "1.0.0-${join("", [for _ in range(123) : "a"])}"
  }

  expect_failures = [var.release_version]
}

run "rejects_cognito_binding_mismatch" {
  command = plan

  variables {
    cognito_issuer_url = "https://cognito-idp.us-west-2.amazonaws.com/us-west-2_FOREIGN"
  }

  expect_failures = [terraform_data.frontend_runtime_config_gate]
}

run "rejects_id_tokens" {
  command = plan

  variables {
    id_tokens_accepted = true
  }

  expect_failures = [var.id_tokens_accepted]
}
