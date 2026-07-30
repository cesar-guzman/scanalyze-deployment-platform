resource "aws_cloudwatch_log_group" "pre_token" {
  name              = "/aws/lambda/${local.pre_token_function_name}"
  retention_in_days = 365
  kms_key_id        = aws_kms_key.identity.arn

  lifecycle {
    prevent_destroy = true
  }

  tags = merge(local.common_tags, {
    purpose = "pre-token-operational-logs"
  })
}

resource "aws_iam_role" "pre_token" {
  name                 = "identity-${var.deployment_id}-pre-token"
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
    purpose = "pre-token-execution"
  })
}

resource "aws_iam_role_policy" "pre_token" {
  name = "identity-pre-token-exact-runtime"
  role = aws_iam_role.pre_token.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "ReadExactMembership"
        Effect   = "Allow"
        Action   = ["dynamodb:GetItem"]
        Resource = [aws_dynamodb_table.memberships.arn]
      },
      {
        Sid      = "AppendAuthorizationAudit"
        Effect   = "Allow"
        Action   = ["dynamodb:PutItem"]
        Resource = [aws_dynamodb_table.authorization_audit.arn]
      },
      {
        Sid    = "WriteDedicatedLogStream"
        Effect = "Allow"
        Action = [
          "logs:CreateLogStream",
          "logs:PutLogEvents",
        ]
        Resource = ["${aws_cloudwatch_log_group.pre_token.arn}:*"]
      },
    ]
  })
}

resource "aws_lambda_function" "pre_token" {
  function_name = local.pre_token_function_name
  description   = "Fail-closed enterprise authorization claim producer"
  role          = aws_iam_role.pre_token.arn
  handler       = "identity_control_plane.entrypoints.pre_token_handler"
  runtime       = "python3.12"
  architectures = ["arm64"]
  timeout       = 5
  memory_size   = 256
  publish       = true

  s3_bucket         = var.pre_token_s3_bucket
  s3_key            = var.pre_token_s3_key
  s3_object_version = var.pre_token_s3_object_version
  source_code_hash  = var.pre_token_source_code_hash

  environment {
    variables = {
      AUTHORIZATION_AUDIT_TABLE = aws_dynamodb_table.authorization_audit.name
      # Fail-closed bootstrap allowlist. Enabling human runtime requires a
      # reviewed second-phase promotion because the SPA ID is generated only
      # after the user pool and trigger exist; referencing it here creates a
      # Terraform dependency cycle and would make first apply non-deterministic.
      ALLOWED_CLIENT_IDS    = jsonencode([])
      ALLOWED_ROLE_IDS      = jsonencode(sort(keys(local.role_precedence)))
      AUTHZ_SCHEMA_VERSION  = "enterprise-authorization.v1"
      CUSTOMER_ID           = var.customer_id
      DEPLOYMENT_ID         = var.deployment_id
      HUMAN_RUNTIME_ENABLED = "false"
      MEMBERSHIP_TABLE      = aws_dynamodb_table.memberships.name
      POLICY_DIGEST         = var.policy_digest
      POLICY_VERSION        = var.policy_version
      ROLE_CATALOG_VERSION  = "enterprise-roles.v1"
      SCOPE_CATALOG_VERSION = "scanalyze.api.v1"
      # A greenfield pool cannot place its generated ID in the Lambda that is
      # itself referenced by the pool without a Terraform dependency cycle.
      # GUG-93 therefore ships the human path explicitly unbound/disabled;
      # GUG-153 performs the reviewed second-phase pool-ID promotion.
      USER_POOL_ID = "UNBOUND"
    }
  }

  depends_on = [
    aws_cloudwatch_log_group.pre_token,
    aws_iam_role_policy.pre_token,
  ]

  tags = merge(local.common_tags, {
    purpose = "pre-token-claims-v2"
  })
}

resource "aws_lambda_alias" "pre_token" {
  name             = "reviewed"
  description      = "Pinned reviewed pre-token implementation"
  function_name    = aws_lambda_function.pre_token.function_name
  function_version = aws_lambda_function.pre_token.version
}

resource "aws_lambda_permission" "allow_cognito" {
  statement_id   = "AllowExactUserPool"
  action         = "lambda:InvokeFunction"
  function_name  = aws_lambda_alias.pre_token.arn
  principal      = "cognito-idp.amazonaws.com"
  source_arn     = aws_cognito_user_pool.main.arn
  source_account = var.account_id
}
