mock_provider "aws" {
  mock_resource "aws_kms_key" {
    defaults = {
      arn    = "arn:aws:kms:us-east-1:000000000000:key/00000000-0000-0000-0000-000000000000"
      key_id = "00000000-0000-0000-0000-000000000000"
    }
  }

  mock_resource "aws_iam_role" {
    defaults = {
      arn  = "arn:aws:iam::000000000000:role/synthetic-pre-token"
      id   = "synthetic-pre-token"
      name = "synthetic-pre-token"
    }
  }

  mock_resource "aws_lambda_alias" {
    defaults = {
      arn              = "arn:aws:lambda:us-east-1:000000000000:function:synthetic-pre-token:reviewed"
      function_name    = "synthetic-pre-token"
      function_version = "1"
    }
  }

  mock_resource "aws_cognito_user_pool" {
    defaults = {
      arn      = "arn:aws:cognito-idp:us-east-1:000000000000:userpool/us-east-1_SYNTHETIC"
      endpoint = "cognito-idp.us-east-1.amazonaws.com/us-east-1_SYNTHETIC"
      id       = "us-east-1_SYNTHETIC"
    }
  }

  mock_resource "aws_sqs_queue" {
    defaults = {
      arn = "arn:aws:sqs:us-east-1:000000000000:synthetic.fifo"
      id  = "https://sqs.us-east-1.amazonaws.com/000000000000/synthetic.fifo"
    }
  }
}

# Synthetic-only inputs. The module implementation must remain portable across
# customers, accounts, regions, and deployments; no value below is live.
variables {
  deployment_id                       = "dep_01ARZ3NDEKTSV4RRFFQ69G5FAV"
  customer_id                         = "cust_01ARZ3NDEKTSV4RRFFQ69G5FAV"
  account_id                          = "000000000000"
  runtime_permissions_boundary_arn    = "arn:aws:iam::000000000000:policy/scanalyze-identity-runtime-boundary"
  region                              = "us-east-1"
  release_version                     = "v0.0.0-synthetic"
  release_manifest_digest             = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
  policy_version                      = "1.0.0"
  policy_digest                       = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
  pre_token_s3_bucket                 = "synthetic-artifacts-bucket"
  pre_token_s3_key                    = "identity/pre-token/sha256-2222222222222222222222222222222222222222222222222222222222222222.zip"
  pre_token_s3_object_version         = "synthetic-version-1"
  pre_token_source_code_hash          = "IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiI="
  control_processor_s3_bucket         = "synthetic-artifacts-bucket"
  control_processor_s3_key            = "identity/control/sha256-3333333333333333333333333333333333333333333333333333333333333333.zip"
  control_processor_s3_object_version = "synthetic-version-2"
  control_processor_source_code_hash  = "MzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzM="
  control_processor_enabled           = true
  m2m_bindings                        = []

  spa_callback_urls = [
    "https://app.synthetic.example/callback",
  ]
  spa_logout_urls = [
    "https://app.synthetic.example/logout",
  ]
}

run "protects_the_user_pool_and_disables_self_signup" {
  command = apply

  assert {
    condition     = aws_cognito_user_pool.main.deletion_protection == "ACTIVE"
    error_message = "the user pool must enable provider deletion protection"
  }

  assert {
    condition     = aws_cognito_user_pool.main.user_pool_tier == "PLUS"
    error_message = "advanced threat protection requires an explicit Cognito Plus tier"
  }

  assert {
    condition     = aws_cognito_user_pool.main.admin_create_user_config[0].allow_admin_create_user_only
    error_message = "self-signup must be disabled; only the reviewed lifecycle workflow may create users"
  }

  assert {
    condition     = aws_cognito_user_pool.main.password_policy[0].minimum_length >= 14
    error_message = "password authentication, when enabled, must require at least 14 characters"
  }

  assert {
    condition     = aws_cognito_user_pool.main.password_policy[0].temporary_password_validity_days <= 1
    error_message = "provider temporary credentials must not outlive the 24-hour invitation boundary"
  }

  assert {
    condition     = aws_cognito_user_pool.main.mfa_configuration == "ON"
    error_message = "MFA must be mandatory; inability to prove stronger assurance must deny privileged operations"
  }

  assert {
    condition     = !aws_cognito_user_pool.main.username_configuration[0].case_sensitive
    error_message = "email-backed usernames must use a deterministic case-insensitive comparison"
  }
}

run "declares_only_immutable_tenant_binding_attributes" {
  command = apply

  assert {
    condition = toset([
      for attribute in aws_cognito_user_pool.main.schema : attribute.name
      if attribute.name != "email"
      ]) == toset([
      "customerId",
      "deployment_id",
    ])
    error_message = "the provider schema must contain only the immutable customerId and deployment_id custom bindings; roles and grants belong in the membership store"
  }

  assert {
    condition = alltrue([
      for attribute in aws_cognito_user_pool.main.schema :
      attribute.mutable == false && attribute.attribute_data_type == "String"
      if contains(["customerId", "deployment_id"], attribute.name)
    ])
    error_message = "authority-adjacent custom attributes must be immutable strings and remain non-authoritative hints"
  }
}

run "declares_the_closed_role_group_catalog" {
  command = apply

  assert {
    condition = toset(keys(aws_cognito_user_group.roles)) == toset([
      "customer_admin",
      "document_operator",
      "document_reviewer",
      "auditor",
    ])
    error_message = "Cognito groups must match the closed enterprise role catalog exactly"
  }

  assert {
    condition = {
      for role_id, group in aws_cognito_user_group.roles : role_id => group.precedence
      } == {
      customer_admin    = 10
      document_operator = 20
      document_reviewer = 30
      auditor           = 40
    }
    error_message = "role group precedence must be explicit, unique, and deterministic"
  }

  assert {
    condition = alltrue([
      for group in values(aws_cognito_user_group.roles) :
      group.role_arn == null
    ])
    error_message = "enterprise application groups must not attach IAM roles"
  }
}

run "publishes_only_the_canonical_resource_server_scopes" {
  command = apply

  assert {
    condition     = aws_cognito_resource_server.api.identifier == "scanalyze.api.v1"
    error_message = "the resource server identifier must be the portable scanalyze.api.v1 catalog, never a customer domain"
  }

  assert {
    condition = toset([
      for scope in aws_cognito_resource_server.api.scope :
      "${aws_cognito_resource_server.api.identifier}/${scope.scope_name}"
      ]) == toset([
      "scanalyze.api.v1/read",
      "scanalyze.api.v1/write",
      "scanalyze.api.v1/admin",
    ])
    error_message = "the resource server must expose exactly the reviewed read/write/admin scope catalog"
  }

  assert {
    condition = alltrue([
      for scope in aws_cognito_resource_server.api.scope :
      trimspace(scope.scope_description) != ""
    ])
    error_message = "every canonical scope must have a reviewable description"
  }
}

run "configures_a_public_authorization_code_spa_client" {
  command = apply

  assert {
    condition     = !aws_cognito_user_pool_client.spa.generate_secret
    error_message = "the SPA is a public client and must never receive a client secret"
  }

  assert {
    condition     = toset(aws_cognito_user_pool_client.spa.allowed_oauth_flows) == toset(["code"])
    error_message = "the SPA must use Authorization Code flow; implicit flow is forbidden"
  }

  assert {
    condition     = aws_cognito_user_pool_client.spa.allowed_oauth_flows_user_pool_client
    error_message = "the SPA OAuth flow must be explicitly enabled"
  }

  assert {
    condition = toset(aws_cognito_user_pool_client.spa.explicit_auth_flows) == toset([
      "ALLOW_REFRESH_TOKEN_AUTH",
    ])
    error_message = "the SPA client must not enable direct password or admin authentication flows"
  }

  assert {
    condition = toset(aws_cognito_user_pool_client.spa.allowed_oauth_scopes) == toset([
      "openid",
      "email",
      "profile",
      "scanalyze.api.v1/read",
      "scanalyze.api.v1/write",
      "scanalyze.api.v1/admin",
    ])
    error_message = "the SPA maximum scope set must be explicit; runtime role, lifecycle, step-up, and object checks remain mandatory"
  }

  assert {
    condition = alltrue([
      for url in concat(
        tolist(aws_cognito_user_pool_client.spa.callback_urls),
        tolist(aws_cognito_user_pool_client.spa.logout_urls),
      ) : startswith(url, "https://") && !strcontains(lower(url), "localhost")
    ])
    error_message = "customer-deployment callback and logout URLs must be exact HTTPS URLs; localhost is test-only"
  }

  assert {
    condition     = aws_cognito_user_pool_client.spa.prevent_user_existence_errors == "ENABLED"
    error_message = "the SPA client must return enumeration-safe authentication outcomes"
  }

  assert {
    condition     = aws_cognito_user_pool_client.spa.enable_token_revocation
    error_message = "the SPA client must support session revocation"
  }
}

run "binds_the_user_pool_to_a_versioned_v2_pre_token_trigger" {
  command = apply

  assert {
    condition     = aws_lambda_function.pre_token.publish
    error_message = "the pre-token function must publish immutable versions"
  }

  assert {
    condition     = aws_lambda_alias.pre_token.function_version != "$LATEST"
    error_message = "Cognito must never execute mutable $LATEST pre-token code"
  }

  assert {
    condition     = aws_cognito_user_pool.main.lambda_config[0].pre_token_generation_config[0].lambda_version == "V2_0"
    error_message = "access-token claim production requires the Cognito Pre Token Generation V2 event contract"
  }

  assert {
    condition     = aws_cognito_user_pool.main.lambda_config[0].pre_token_generation_config[0].lambda_arn == aws_lambda_alias.pre_token.arn
    error_message = "the pool must invoke the reviewed immutable pre-token alias"
  }
}
