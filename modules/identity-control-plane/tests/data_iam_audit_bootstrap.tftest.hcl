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

run "protects_membership_and_audit_stores" {
  command = apply

  assert {
    condition = alltrue([
      aws_dynamodb_table.memberships.billing_mode == "PAY_PER_REQUEST",
      aws_dynamodb_table.memberships.deletion_protection_enabled,
      aws_dynamodb_table.memberships.server_side_encryption[0].enabled,
      aws_dynamodb_table.memberships.point_in_time_recovery[0].enabled,
      aws_dynamodb_table.memberships.stream_enabled,
      aws_dynamodb_table.memberships.stream_view_type == "NEW_AND_OLD_IMAGES",
    ])
    error_message = "the authoritative membership store must be encrypted, protected, recoverable, and stream every before/after image"
  }

  assert {
    condition = alltrue([
      aws_dynamodb_table.authorization_audit.billing_mode == "PAY_PER_REQUEST",
      aws_dynamodb_table.authorization_audit.deletion_protection_enabled,
      aws_dynamodb_table.authorization_audit.server_side_encryption[0].enabled,
      aws_dynamodb_table.authorization_audit.point_in_time_recovery[0].enabled,
    ])
    error_message = "the deployment-scoped authorization audit store must be encrypted, protected, and recoverable"
  }

  assert {
    condition = (
      aws_dynamodb_table.memberships.hash_key == "pk" &&
      aws_dynamodb_table.memberships.range_key == "sk"
    )
    error_message = "membership lookups must use an exact composite key; protected table scans are not an authorization design"
  }
}

run "scopes_the_pre_token_execution_role" {
  command = apply

  assert {
    condition = alltrue([
      for resource in flatten([
        for statement in jsondecode(aws_iam_role_policy.pre_token.policy).Statement :
        [statement.Resource]
      ]) : resource != "*"
    ])
    error_message = "the pre-token role must not contain wildcard resources"
  }

  assert {
    condition = alltrue([
      for action in flatten([
        for statement in jsondecode(aws_iam_role_policy.pre_token.policy).Statement :
        [statement.Action]
      ]) : action != "*" && !endswith(action, ":*")
    ])
    error_message = "the pre-token role must not contain wildcard actions"
  }

  assert {
    condition = length(setsubtract(
      toset(flatten([
        for statement in jsondecode(aws_iam_role_policy.pre_token.policy).Statement :
        [statement.Action]
      ])),
      toset([
        "dynamodb:GetItem",
        "dynamodb:PutItem",
        "kms:Decrypt",
        "kms:GenerateDataKey",
        "logs:CreateLogStream",
        "logs:PutLogEvents",
      ]),
    )) == 0
    error_message = "the pre-token role may only read one membership, append one audit event, use exact KMS keys, and write its dedicated log stream"
  }

  assert {
    condition = alltrue([
      aws_lambda_permission.allow_cognito.principal == "cognito-idp.amazonaws.com",
      aws_lambda_permission.allow_cognito.source_arn == aws_cognito_user_pool.main.arn,
      aws_lambda_permission.allow_cognito.source_account == var.account_id,
    ])
    error_message = "only the exact deployment user pool in the expected account may invoke the pre-token function"
  }
}

run "encrypts_and_retains_identity_logs_without_using_them_as_audit" {
  command = apply

  assert {
    condition = (
      aws_cloudwatch_log_group.pre_token.kms_key_id != null &&
      aws_cloudwatch_log_group.pre_token.kms_key_id != "" &&
      aws_cloudwatch_log_group.pre_token.retention_in_days >= 365
    )
    error_message = "pre-token operational logs must be encrypted and retained under an explicit policy"
  }

  assert {
    condition = toset(keys(aws_cloudwatch_metric_alarm.identity_control_plane)) == toset([
      "bootstrap-dlq-depth",
      "control-processor-errors",
      "control-processor-throttles",
      "pre-token-errors",
      "pre-token-throttles",
    ])
    error_message = "identity issuance failures, throttling, and bootstrap poison messages require explicit alarms"
  }
}

run "creates_a_bounded_bootstrap_queue_and_dlq" {
  command = apply

  assert {
    condition = alltrue([
      aws_sqs_queue.bootstrap.fifo_queue,
      aws_sqs_queue.bootstrap_dlq.fifo_queue,
      endswith(aws_sqs_queue.bootstrap.name, ".fifo"),
      endswith(aws_sqs_queue.bootstrap_dlq.name, ".fifo"),
      aws_sqs_queue.bootstrap.sqs_managed_sse_enabled,
      aws_sqs_queue.bootstrap_dlq.sqs_managed_sse_enabled,
    ])
    error_message = "bootstrap requests and failures must use encrypted FIFO source and DLQ resources"
  }

  assert {
    condition = (
      jsondecode(aws_sqs_queue.bootstrap.redrive_policy).deadLetterTargetArn == aws_sqs_queue.bootstrap_dlq.arn &&
      jsondecode(aws_sqs_queue.bootstrap.redrive_policy).maxReceiveCount == 3
    )
    error_message = "bootstrap poison messages must move only to the exact paired DLQ after three attempts"
  }

  assert {
    condition = (
      jsondecode(aws_sqs_queue_redrive_allow_policy.bootstrap_dlq.redrive_allow_policy).redrivePermission == "byQueue" &&
      jsondecode(aws_sqs_queue_redrive_allow_policy.bootstrap_dlq.redrive_allow_policy).sourceQueueArns == [aws_sqs_queue.bootstrap.arn]
    )
    error_message = "the bootstrap DLQ must accept redrive only from its exact source queue"
  }
}
