mock_provider "aws" {
  mock_resource "aws_kms_key" {
    defaults = {
      arn    = "arn:aws:kms:us-east-1:000000000000:key/00000000-0000-0000-0000-000000000000"
      key_id = "00000000-0000-0000-0000-000000000000"
    }
  }

  mock_resource "aws_iam_role" {
    defaults = {
      arn  = "arn:aws:iam::000000000000:role/synthetic-identity-runtime"
      id   = "synthetic-identity-runtime"
      name = "synthetic-identity-runtime"
    }
  }

  mock_resource "aws_lambda_alias" {
    defaults = {
      arn              = "arn:aws:lambda:us-east-1:000000000000:function:synthetic-identity-runtime:reviewed"
      function_name    = "synthetic-identity-runtime"
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
  deployment_id                    = "dep_01ARZ3NDEKTSV4RRFFQ69G5FAV"
  customer_id                      = "cust_01ARZ3NDEKTSV4RRFFQ69G5FAV"
  account_id                       = "000000000000"
  runtime_permissions_boundary_arn = "arn:aws:iam::000000000000:policy/scanalyze-identity-runtime-boundary"
  region                           = "us-east-1"
  release_version                  = "v0.0.0-synthetic"
  release_manifest_digest          = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
  policy_version                   = "1.0.0"
  policy_digest                    = "sha256:1111111111111111111111111111111111111111111111111111111111111111"

  pre_token_s3_bucket         = "synthetic-artifacts-bucket"
  pre_token_s3_key            = "identity/pre-token/sha256-2222222222222222222222222222222222222222222222222222222222222222.zip"
  pre_token_s3_object_version = "synthetic-version-1"
  pre_token_source_code_hash  = "IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiI="

  control_processor_s3_bucket         = "synthetic-artifacts-bucket"
  control_processor_s3_key            = "identity/control/sha256-3333333333333333333333333333333333333333333333333333333333333333.zip"
  control_processor_s3_object_version = "synthetic-version-2"
  control_processor_source_code_hash  = "MzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzM="
  control_processor_enabled           = true
  m2m_bindings                        = []

  spa_callback_urls = ["https://app.synthetic.example/callback"]
  spa_logout_urls   = ["https://app.synthetic.example/logout"]
}

run "pins_real_handlers_and_immutable_artifacts" {
  command = apply

  assert {
    condition = alltrue([
      aws_lambda_function.pre_token.handler == "identity_control_plane.entrypoints.pre_token_handler",
      aws_lambda_function.control_processor.handler == "identity_control_plane.entrypoints.control_processor_handler",
      aws_lambda_function.pre_token.publish,
      aws_lambda_function.control_processor.publish,
      aws_lambda_alias.pre_token.function_version != "$LATEST",
      aws_lambda_alias.control_processor.function_version != "$LATEST",
    ])
    error_message = "both identity handlers must use the real entrypoints and immutable published aliases"
  }

  assert {
    condition = alltrue([
      aws_lambda_function.pre_token.s3_bucket == var.pre_token_s3_bucket,
      aws_lambda_function.pre_token.s3_key == var.pre_token_s3_key,
      aws_lambda_function.pre_token.s3_object_version == var.pre_token_s3_object_version,
      aws_lambda_function.pre_token.source_code_hash == var.pre_token_source_code_hash,
      aws_lambda_function.control_processor.s3_bucket == var.control_processor_s3_bucket,
      aws_lambda_function.control_processor.s3_key == var.control_processor_s3_key,
      aws_lambda_function.control_processor.s3_object_version == var.control_processor_s3_object_version,
      aws_lambda_function.control_processor.source_code_hash == var.control_processor_source_code_hash,
    ])
    error_message = "identity runtimes must consume exact bucket/key/version/hash artifact references"
  }

  assert {
    condition = alltrue([
      aws_lambda_function.pre_token.environment[0].variables.HUMAN_RUNTIME_ENABLED == "false",
      aws_lambda_function.pre_token.environment[0].variables.USER_POOL_ID == "UNBOUND",
      aws_lambda_function.control_processor.environment[0].variables.HUMAN_RUNTIME_ENABLED == "false",
      aws_lambda_function.control_processor.environment[0].variables.M2M_RUNTIME_ENABLED == "true",
      aws_lambda_function.control_processor.environment[0].variables.CONTROL_QUEUE_ARN == aws_sqs_queue.bootstrap.arn,
      jsondecode(aws_lambda_function.pre_token.environment[0].variables.ALLOWED_CLIENT_IDS) == [],
      jsondecode(aws_lambda_function.control_processor.environment[0].variables.ALLOWED_CLIENT_IDS) == [],
      toset(jsondecode(aws_lambda_function.pre_token.environment[0].variables.ALLOWED_ROLE_IDS)) == toset(keys(local.role_precedence)),
    ])
    error_message = "runtime gates, queue binding, SPA audience, and closed role catalog must be explicit"
  }
}

run "uses_partial_batch_response_without_breaking_fifo_order" {
  command = apply

  assert {
    condition = alltrue([
      aws_lambda_event_source_mapping.control_processor.enabled,
      aws_lambda_event_source_mapping.control_processor.event_source_arn == aws_sqs_queue.bootstrap.arn,
      aws_lambda_event_source_mapping.control_processor.function_name == aws_lambda_alias.control_processor.arn,
      aws_lambda_event_source_mapping.control_processor.batch_size == 1,
      toset(aws_lambda_event_source_mapping.control_processor.function_response_types) == toset(["ReportBatchItemFailures"]),
      aws_sqs_queue.bootstrap.visibility_timeout_seconds >= aws_lambda_function.control_processor.timeout * 6,
    ])
    error_message = "the M2M control processor must use exact FIFO source binding, partial failures, batch size one, and safe visibility"
  }
}

run "bounds_runtime_roles_and_control_processor_permissions" {
  command = apply

  assert {
    condition = alltrue([
      aws_iam_role.pre_token.path == "/scanalyze/${var.deployment_id}/",
      aws_iam_role.control_processor.path == "/scanalyze/${var.deployment_id}/",
      aws_iam_role.pre_token.permissions_boundary == var.runtime_permissions_boundary_arn,
      aws_iam_role.control_processor.permissions_boundary == var.runtime_permissions_boundary_arn,
      startswith(aws_iam_role.pre_token.name, "identity-"),
      startswith(aws_iam_role.control_processor.name, "identity-"),
    ])
    error_message = "identity runtime roles must use the exact deployment path and customer-owned permissions boundary"
  }

  assert {
    condition = alltrue([
      for resource in flatten([
        for statement in jsondecode(aws_iam_role_policy.control_processor.policy).Statement :
        statement.Resource
      ]) : resource != "*"
    ])
    error_message = "the control-processor role must never authorize wildcard resources"
  }

  assert {
    condition = alltrue([
      for action in flatten([
        for statement in jsondecode(aws_iam_role_policy.control_processor.policy).Statement :
        statement.Action
      ]) : action != "*" && !endswith(action, ":*")
    ])
    error_message = "the control-processor role must never authorize wildcard actions"
  }

  assert {
    condition = length(setsubtract(
      toset(flatten([
        for statement in jsondecode(aws_iam_role_policy.control_processor.policy).Statement :
        statement.Action
      ])),
      toset([
        "sqs:ChangeMessageVisibility",
        "sqs:DeleteMessage",
        "sqs:GetQueueAttributes",
        "sqs:ReceiveMessage",
        "dynamodb:GetItem",
        "dynamodb:PutItem",
        "dynamodb:UpdateItem",
        "cognito-idp:CreateUserPoolClient",
        "cognito-idp:DeleteUserPoolClient",
        "cognito-idp:DescribeUserPoolClient",
        "cognito-idp:ListUserPoolClients",
        "secretsmanager:CreateSecret",
        "secretsmanager:DescribeSecret",
        "secretsmanager:PutSecretValue",
        "secretsmanager:TagResource",
        "kms:Decrypt",
        "kms:Encrypt",
        "kms:GenerateDataKey",
        "logs:CreateLogStream",
        "logs:PutLogEvents",
      ]),
    )) == 0
    error_message = "the control-processor role contains an unreviewed permission"
  }
}

run "binds_the_kms_key_to_exact_services_and_log_context" {
  command = apply

  assert {
    condition = {
      for statement in jsondecode(aws_kms_key.identity.policy).Statement :
      statement.Sid => statement.Principal
    }["AllowExactRegionalLambdaLogGroups"].Service == "logs.${var.region}.amazonaws.com"
    error_message = "the identity key must trust only the exact regional CloudWatch Logs service principal"
  }

  assert {
    condition = {
      for statement in jsondecode(aws_kms_key.identity.policy).Statement :
      statement.Sid => try(statement.Condition, {})
      }["AllowExactRegionalLambdaLogGroups"].ArnEquals["kms:EncryptionContext:aws:logs:arn"] == [
      "arn:aws:logs:${var.region}:${var.account_id}:log-group:/aws/lambda/${var.deployment_id}-identity-pre-token",
      "arn:aws:logs:${var.region}:${var.account_id}:log-group:/aws/lambda/${var.deployment_id}-identity-control-processor",
    ]
    error_message = "CloudWatch Logs KMS use must bind the two exact identity runtime log groups"
  }

  assert {
    condition = {
      for statement in jsondecode(aws_kms_key.identity.policy).Statement :
      statement.Sid => try(statement.Condition, {})
      }["AllowExactRegionalDynamoDBService"].StringEquals == {
      "kms:CallerAccount" = var.account_id
      "kms:ViaService"    = "dynamodb.${var.region}.amazonaws.com"
    }
    error_message = "DynamoDB KMS use must bind the expected account and regional service"
  }

  assert {
    condition = {
      for statement in jsondecode(aws_kms_key.identity.policy).Statement :
      statement.Sid => try(statement.Condition, {})
    }["AllowExactRegionalDynamoDBService"].Bool["kms:GrantIsForAWSResource"] == "true"
    error_message = "DynamoDB may create KMS grants only for AWS-managed resource use"
  }

  assert {
    condition = alltrue([
      {
        for statement in jsondecode(aws_kms_key.identity.policy).Statement :
        statement.Sid => statement.Principal
      }["AllowSameAccountKeyAdministrationAndIAMDelegation"].AWS == "arn:aws:iam::${var.account_id}:root",
      {
        for statement in jsondecode(aws_kms_key.identity.policy).Statement :
        statement.Sid => statement.Principal
      }["AllowControlProcessorToEncryptExactSecrets"].AWS == aws_iam_role.control_processor.arn,
    ])
    error_message = "KMS must not trust another account and Secrets Manager encryption must bind the exact control-processor role"
  }
}

run "never_exposes_secret_or_artifact_material_in_contract_outputs" {
  command = apply

  assert {
    condition = alltrue([
      output.contract_payload.outputs.m2m_client_secret_values_exposed == false,
      !strcontains(jsonencode(output.contract_payload), var.pre_token_s3_bucket),
      !strcontains(jsonencode(output.contract_payload), var.pre_token_s3_key),
      !strcontains(jsonencode(output.contract_payload), var.pre_token_s3_object_version),
      !strcontains(jsonencode(output.contract_payload), var.control_processor_s3_key),
      !strcontains(jsonencode(output.contract_payload), var.runtime_permissions_boundary_arn),
      output.contract_payload.outputs.human_runtime_provisioning_enabled == false,
      output.contract_payload.outputs.m2m_runtime_provisioning_enabled == true,
    ])
    error_message = "contracts must expose no secret, artifact locator, boundary, or false runtime-activation claim"
  }
}

run "rejects_a_cross_account_runtime_boundary" {
  command = plan

  variables {
    runtime_permissions_boundary_arn = "arn:aws:iam::111111111111:policy/cross-account-boundary"
  }

  expect_failures = [var.runtime_permissions_boundary_arn]
}

run "rejects_disabling_the_v1_m2m_control_processor" {
  command = plan

  variables {
    control_processor_enabled = false
  }

  expect_failures = [var.control_processor_enabled]
}

run "rejects_a_non_content_addressed_pre_token_key" {
  command = plan

  variables {
    pre_token_s3_key = "identity/pre-token/sha256-not-a-digest.zip"
  }

  expect_failures = [var.pre_token_s3_key]
}

run "rejects_an_invalid_control_processor_bucket" {
  command = plan

  variables {
    control_processor_s3_bucket = "Synthetic_Invalid_Bucket"
  }

  expect_failures = [var.control_processor_s3_bucket]
}

run "rejects_the_unversioned_s3_sentinel" {
  command = plan

  variables {
    control_processor_s3_object_version = "null"
  }

  expect_failures = [var.control_processor_s3_object_version]
}

run "accepts_an_opaque_version_id_at_the_utf8_byte_boundary" {
  command = plan

  variables {
    control_processor_s3_object_version = join("", [for _ in range(512) : "é"])
  }
}

run "rejects_an_opaque_version_id_one_byte_over_the_utf8_boundary" {
  command = plan

  variables {
    control_processor_s3_object_version = join("", concat(
      [for _ in range(512) : "é"],
      ["a"],
    ))
  }

  expect_failures = [var.control_processor_s3_object_version]
}

run "rejects_an_opaque_version_id_over_the_utf8_byte_boundary" {
  command = plan

  variables {
    control_processor_s3_object_version = join("", [for _ in range(513) : "é"])
  }

  expect_failures = [var.control_processor_s3_object_version]
}
