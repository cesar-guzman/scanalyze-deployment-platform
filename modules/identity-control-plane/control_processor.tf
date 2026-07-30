resource "aws_cloudwatch_log_group" "control_processor" {
  name              = "/aws/lambda/${local.control_processor_function_name}"
  retention_in_days = 365
  kms_key_id        = aws_kms_key.identity.arn

  lifecycle {
    prevent_destroy = true
  }

  tags = merge(local.common_tags, {
    purpose = "identity-control-processor-operational-logs"
  })
}

resource "aws_iam_role" "control_processor" {
  name                 = "identity-${var.deployment_id}-control-processor"
  path                 = "/scanalyze/${var.deployment_id}/"
  permissions_boundary = var.runtime_permissions_boundary_arn

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AllowLambdaService"
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })

  tags = merge(local.common_tags, {
    purpose = "identity-control-processor-execution"
  })
}

resource "aws_iam_role_policy" "control_processor" {
  name = "identity-control-processor-exact-runtime"
  role = aws_iam_role.control_processor.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "ConsumeExactBootstrapQueue"
        Effect = "Allow"
        Action = [
          "sqs:ChangeMessageVisibility",
          "sqs:DeleteMessage",
          "sqs:GetQueueAttributes",
          "sqs:ReceiveMessage",
        ]
        Resource = [aws_sqs_queue.bootstrap.arn]
      },
      {
        Sid    = "ConditionallyUpdateBootstrapRequests"
        Effect = "Allow"
        Action = [
          "dynamodb:GetItem",
          "dynamodb:UpdateItem",
        ]
        Resource = [aws_dynamodb_table.bootstrap_requests.arn]
      },
      {
        Sid    = "ConditionallyWriteMembershipsAndBindings"
        Effect = "Allow"
        Action = [
          "dynamodb:GetItem",
          "dynamodb:PutItem",
          "dynamodb:UpdateItem",
        ]
        Resource = [
          aws_dynamodb_table.memberships.arn,
          aws_dynamodb_table.m2m_bindings.arn,
        ]
      },
      {
        Sid      = "AppendAuthorizationAudit"
        Effect   = "Allow"
        Action   = ["dynamodb:PutItem"]
        Resource = [aws_dynamodb_table.authorization_audit.arn]
      },
      {
        Sid    = "ManageWorkloadClientsInExactPool"
        Effect = "Allow"
        Action = [
          "cognito-idp:CreateUserPoolClient",
          "cognito-idp:DeleteUserPoolClient",
          "cognito-idp:DescribeUserPoolClient",
          "cognito-idp:ListUserPoolClients",
        ]
        Resource = [aws_cognito_user_pool.main.arn]
      },
      {
        Sid    = "WriteM2MSecretDirectlyToExactPrefix"
        Effect = "Allow"
        Action = [
          "secretsmanager:CreateSecret",
          "secretsmanager:DescribeSecret",
          "secretsmanager:PutSecretValue",
          "secretsmanager:TagResource",
        ]
        Resource = ["arn:${var.aws_partition}:secretsmanager:${var.region}:${var.account_id}:secret:${local.identity_prefix}-m2m-*"]
      },
      {
        Sid    = "EncryptM2MSecretWithExactKey"
        Effect = "Allow"
        Action = [
          "kms:Decrypt",
          "kms:Encrypt",
          "kms:GenerateDataKey",
        ]
        Resource = [aws_kms_key.identity.arn]
      },
      {
        Sid    = "WriteDedicatedLogStream"
        Effect = "Allow"
        Action = [
          "logs:CreateLogStream",
          "logs:PutLogEvents",
        ]
        Resource = ["${aws_cloudwatch_log_group.control_processor.arn}:*"]
      },
    ]
  })
}

resource "aws_lambda_function" "control_processor" {
  function_name = local.control_processor_function_name
  description   = "Fail-closed identity bootstrap and M2M control processor"
  role          = aws_iam_role.control_processor.arn
  handler       = "identity_control_plane.entrypoints.control_processor_handler"
  runtime       = "python3.12"
  architectures = ["arm64"]
  timeout       = 15
  memory_size   = 256
  publish       = true

  s3_bucket         = var.control_processor_s3_bucket
  s3_key            = var.control_processor_s3_key
  s3_object_version = var.control_processor_s3_object_version
  source_code_hash  = var.control_processor_source_code_hash

  environment {
    variables = {
      AUTHORIZATION_AUDIT_TABLE = aws_dynamodb_table.authorization_audit.name
      ALLOWED_ROLE_IDS          = jsonencode(sort(keys(local.role_precedence)))
      ALLOWED_CLIENT_IDS        = jsonencode(sort([for binding in var.m2m_bindings : binding.client_id]))
      AUTHZ_SCHEMA_VERSION      = "enterprise-authorization.v1"
      BOOTSTRAP_REQUEST_TABLE   = aws_dynamodb_table.bootstrap_requests.name
      CONTROL_QUEUE_ARN         = aws_sqs_queue.bootstrap.arn
      CUSTOMER_ID               = var.customer_id
      DEPLOYMENT_ID             = var.deployment_id
      HUMAN_RUNTIME_ENABLED     = "false"
      IDENTITY_KMS_KEY_ARN      = aws_kms_key.identity.arn
      M2M_BINDING_TABLE         = aws_dynamodb_table.m2m_bindings.name
      M2M_RUNTIME_ENABLED       = "true"
      MEMBERSHIP_TABLE          = aws_dynamodb_table.memberships.name
      POLICY_DIGEST             = var.policy_digest
      POLICY_VERSION            = var.policy_version
      RESOURCE_SERVER_ID        = aws_cognito_resource_server.api.identifier
      ROLE_CATALOG_VERSION      = "enterprise-roles.v1"
      SCOPE_CATALOG_VERSION     = "scanalyze.api.v1"
      SECRET_NAME_PREFIX        = "${local.identity_prefix}-m2m-"
      USER_POOL_ID              = aws_cognito_user_pool.main.id
    }
  }

  depends_on = [
    aws_cloudwatch_log_group.control_processor,
    aws_iam_role_policy.control_processor,
  ]

  tags = merge(local.common_tags, {
    purpose = "identity-control-processor"
  })
}

resource "aws_lambda_alias" "control_processor" {
  name             = "reviewed"
  description      = "Pinned reviewed identity control-processor implementation"
  function_name    = aws_lambda_function.control_processor.function_name
  function_version = aws_lambda_function.control_processor.version
}

resource "aws_lambda_event_source_mapping" "control_processor" {
  event_source_arn = aws_sqs_queue.bootstrap.arn
  function_name    = aws_lambda_alias.control_processor.arn

  # Batch size one preserves FIFO ordering because the runtime reports partial
  # failures but cannot safely continue within a failed message group.
  batch_size                         = 1
  enabled                            = var.control_processor_enabled
  function_response_types            = ["ReportBatchItemFailures"]
  maximum_batching_window_in_seconds = 0

  scaling_config {
    maximum_concurrency = 2
  }

  depends_on = [aws_iam_role_policy.control_processor]
}
