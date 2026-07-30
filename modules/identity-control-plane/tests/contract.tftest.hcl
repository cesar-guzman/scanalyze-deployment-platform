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
  pre_token_s3_object_version         = "synthetic+provider/version=1"
  pre_token_source_code_hash          = "IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiI="
  control_processor_s3_bucket         = "synthetic-artifacts-bucket"
  control_processor_s3_key            = "identity/control/sha256-3333333333333333333333333333333333333333333333333333333333333333.zip"
  control_processor_s3_object_version = "synthetic+provider/version=2"
  control_processor_source_code_hash  = "MzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzM="
  control_processor_enabled           = true
  m2m_bindings = [{
    client_id       = "syntheticworkloadclient"
    customer_id     = "cust_01ARZ3NDEKTSV4RRFFQ69G5FAV"
    deployment_id   = "dep_01ARZ3NDEKTSV4RRFFQ69G5FAV"
    required_scopes = ["scanalyze.api.v1/read"]
  }]

  spa_callback_urls = [
    "https://app.synthetic.example/callback",
  ]
  spa_logout_urls = [
    "https://app.synthetic.example/logout",
  ]
}

run "publishes_a_complete_fail_closed_identity_contract" {
  command = apply

  assert {
    condition = toset(keys(output.contract_payload)) == toset([
      "schema_version",
      "layer",
      "state_scope",
      "outputs",
    ])
    error_message = "identity-control-plane/v1 must publish one unambiguous publisher-compatible payload"
  }

  assert {
    condition = alltrue([
      output.contract_payload.schema_version == "1",
      output.contract_payload.layer == "identity-control-plane",
      output.contract_payload.state_scope == "regional",
    ])
    error_message = "publisher metadata must identify the exact layer, schema, and state scope"
  }

  assert {
    condition = toset(keys(output.contract_payload.outputs)) == toset([
      "customer_id",
      "deployment_id",
      "account_id",
      "region",
      "aws_partition",
      "cognito_user_pool_id",
      "cognito_user_pool_arn",
      "cognito_issuer_url",
      "cognito_spa_client_id",
      "m2m_client_ids",
      "resource_server_identifier",
      "allowed_token_uses",
      "action_scopes",
      "action_scope_sets",
      "m2m_bindings",
      "customer_claim_name",
      "deployment_claim_name",
      "policy_version",
      "policy_digest",
      "policy_canonicalization",
      "authz_schema_version",
      "scope_catalog_version",
      "role_catalog_version",
      "human_role_groups",
      "provider_groups_authoritative",
      "pre_token_generation_version",
      "human_runtime_provisioning_enabled",
      "m2m_runtime_provisioning_enabled",
      "m2m_client_secret_values_exposed",
    ])
    error_message = "nested outputs must match contract-identity-control-plane.v1 exactly"
  }

  assert {
    condition = alltrue([
      output.contract_payload.outputs.customer_id == var.customer_id,
      output.contract_payload.outputs.deployment_id == var.deployment_id,
      output.contract_payload.outputs.account_id == var.account_id,
      output.contract_payload.outputs.region == var.region,
      output.contract_payload.outputs.aws_partition == var.aws_partition,
      output.contract_payload.outputs.resource_server_identifier == "scanalyze.api.v1",
      output.contract_payload.outputs.allowed_token_uses == ["access"],
      output.contract_payload.outputs.action_scopes == {
        read  = "scanalyze.api.v1/read"
        write = "scanalyze.api.v1/write"
        admin = "scanalyze.api.v1/admin"
      },
      output.contract_payload.outputs.action_scope_sets == {
        read  = ["scanalyze.api.v1/read"]
        write = ["scanalyze.api.v1/write"]
        admin = ["scanalyze.api.v1/admin"]
      },
    ])
    error_message = "the contract must bind the exact portability tuple and access-token-only action scope catalog"
  }

  assert {
    condition = alltrue([
      output.contract_payload.outputs.authz_schema_version == "enterprise-authorization.v1",
      output.contract_payload.outputs.scope_catalog_version == "scanalyze.api.v1",
      output.contract_payload.outputs.role_catalog_version == "enterprise-roles.v1",
      output.contract_payload.outputs.policy_version == var.policy_version,
      output.contract_payload.outputs.policy_digest == var.policy_digest,
      output.contract_payload.outputs.policy_canonicalization == "rfc8785_json_canonicalization",
      output.contract_payload.outputs.provider_groups_authoritative == false,
      output.contract_payload.outputs.human_runtime_provisioning_enabled == false,
      output.contract_payload.outputs.m2m_runtime_provisioning_enabled,
      output.contract_payload.outputs.m2m_client_secret_values_exposed == false,
    ])
    error_message = "authorization versions and digest must be exact; human provisioning and secret output remain disabled"
  }

  assert {
    condition = alltrue([
      output.contract_payload.outputs.customer_claim_name == "custom:customerId",
      output.contract_payload.outputs.deployment_claim_name == "custom:deployment_id",
      output.contract_payload.outputs.pre_token_generation_version == "V2_0",
      toset(output.contract_payload.outputs.human_role_groups) == toset([
        "customer_admin",
        "document_operator",
        "document_reviewer",
        "auditor",
      ]),
      toset(output.contract_payload.outputs.m2m_client_ids) == toset([for binding in var.m2m_bindings : binding.client_id]),
      jsonencode(output.contract_payload.outputs.m2m_bindings) == jsonencode(var.m2m_bindings),
      output.contract_payload.outputs.m2m_client_secret_values_exposed == false,
      !strcontains(lower(jsonencode(output.contract_payload.outputs)), "refresh_token"),
    ])
    error_message = "claim names, role order, audiences, and no-secret boundary must be exact"
  }
}
