# Global layer — Application Workload IAM
#
# Status: authored_not_provider_validated
#
# This module creates ONLY workload/application IAM roles:
# - Shared ECS task execution role
# - Per-service workload IAM roles
# - Application-scoped permissions boundary

# ── ECS Task Execution Role ──
# Shared by all ECS services in this deployment.
# Allows pulling images from ECR and writing to CloudWatch Logs.

resource "aws_iam_role" "ecs_task_execution" {
  name = "${var.deployment_id}-ecs-task-execution"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "ecs-tasks.amazonaws.com"
        }
        Action = "sts:AssumeRole"
        Condition = {
          StringEquals = {
            "aws:SourceAccount" = var.account_id
          }
        }
      }
    ]
  })

  permissions_boundary = aws_iam_policy.workload_permissions_boundary.arn

  tags = {
    deployment_id = var.deployment_id
    managed_by    = "terraform"
    layer         = "global"
    purpose       = "ecs-task-execution"
  }
}

resource "aws_iam_role_policy_attachment" "ecs_task_execution_managed" {
  for_each = toset(length(var.ecs_task_execution_managed_policies) > 0 ? var.ecs_task_execution_managed_policies : [
    "arn:${var.aws_partition}:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy",
  ])

  role       = aws_iam_role.ecs_task_execution.name
  policy_arn = each.value
}

# ── Per-Service Workload Roles ──
# Each microservice gets its own workload role for task-level permissions.

resource "aws_iam_role" "workload" {
  for_each = toset(var.service_names)

  name = "${var.deployment_id}-workload-${each.key}"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "ecs-tasks.amazonaws.com"
        }
        Action = "sts:AssumeRole"
        Condition = {
          StringEquals = {
            "aws:SourceAccount" = var.account_id
          }
        }
      }
    ]
  })

  permissions_boundary = aws_iam_policy.workload_permissions_boundary.arn

  tags = {
    deployment_id = var.deployment_id
    managed_by    = "terraform"
    layer         = "global"
    service       = each.key
    purpose       = "workload-task-role"
  }
}

# ── Workload Permissions Boundary ──
# Scopes all workload roles to prevent privilege escalation.
# This is the APPLICATION boundary, not the account baseline boundary.

resource "aws_iam_policy" "workload_permissions_boundary" {
  name = "${var.deployment_id}-workload-boundary"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowComputeActions"
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:ListBucket",
          "sqs:SendMessage",
          "sqs:ReceiveMessage",
          "sqs:DeleteMessage",
          "sqs:GetQueueAttributes",
          "dynamodb:GetItem",
          "dynamodb:PutItem",
          "dynamodb:UpdateItem",
          "dynamodb:Query",
          "dynamodb:Scan",
          "logs:CreateLogStream",
          "logs:PutLogEvents",
          "kms:Decrypt",
          "kms:GenerateDataKey",
          "ssm:GetParameter",
          "ssm:GetParameters",
          "ssm:GetParametersByPath",
          "textract:*",
          "ecr:GetAuthorizationToken",
          "ecr:BatchGetImage",
          "ecr:GetDownloadUrlForLayer",
        ]
        Resource = "*"
      },
      {
        Sid    = "DenyControlPlaneEscalation"
        Effect = "Deny"
        Action = [
          "iam:CreateRole",
          "iam:DeleteRole",
          "iam:AttachRolePolicy",
          "iam:DetachRolePolicy",
          "iam:PutRolePolicy",
          "iam:DeleteRolePolicy",
          "iam:CreatePolicy",
          "iam:DeletePolicy",
          "iam:UpdateAssumeRolePolicy",
          "iam:PutRolePermissionsBoundary",
          "iam:DeleteRolePermissionsBoundary",
          "organizations:*",
          "account:*",
        ]
        Resource = "*"
      }
    ]
  })

  tags = {
    deployment_id = var.deployment_id
    managed_by    = "terraform"
    layer         = "global"
    purpose       = "workload-permissions-boundary"
  }
}

# Identity runtime roles are created by the dedicated identity layer.  Their
# boundary must be owned by an earlier, more trusted layer so the identity
# apply role cannot widen its own maximum permissions.
resource "aws_iam_policy" "identity_runtime_permissions_boundary" {
  name        = "${var.deployment_id}-identity-runtime-boundary"
  description = "Maximum permissions for deployment-scoped identity Lambda roles"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "IdentityTablesOnly"
        Effect = "Allow"
        Action = [
          "dynamodb:GetItem",
          "dynamodb:PutItem",
          "dynamodb:UpdateItem",
        ]
        Resource = "arn:${var.aws_partition}:dynamodb:${var.region}:${var.account_id}:table/${var.deployment_id}-identity-*"
      },
      {
        Sid    = "IdentityControlQueueOnly"
        Effect = "Allow"
        Action = [
          "sqs:ChangeMessageVisibility",
          "sqs:DeleteMessage",
          "sqs:GetQueueAttributes",
          "sqs:ReceiveMessage",
        ]
        Resource = "arn:${var.aws_partition}:sqs:${var.region}:${var.account_id}:${var.deployment_id}-identity-*"
      },
      {
        Sid    = "IdentityOperationalLogsOnly"
        Effect = "Allow"
        Action = [
          "logs:CreateLogStream",
          "logs:PutLogEvents",
        ]
        Resource = "arn:${var.aws_partition}:logs:${var.region}:${var.account_id}:log-group:/aws/lambda/${var.deployment_id}-identity-*:*"
      },
      {
        Sid    = "TaggedDeploymentUserPoolOnly"
        Effect = "Allow"
        Action = [
          "cognito-idp:AdminGetUser",
          "cognito-idp:CreateUserPoolClient",
          "cognito-idp:DeleteUserPoolClient",
          "cognito-idp:DescribeUserPoolClient",
          "cognito-idp:ListUserPoolClients",
        ]
        Resource = "arn:${var.aws_partition}:cognito-idp:${var.region}:${var.account_id}:userpool/*"
        Condition = {
          StringEquals = {
            "aws:ResourceTag/deployment_id" = var.deployment_id
          }
        }
      },
      {
        Sid    = "IdentityM2MSecretsOnly"
        Effect = "Allow"
        Action = [
          "secretsmanager:CreateSecret",
          "secretsmanager:DescribeSecret",
          "secretsmanager:PutSecretValue",
          "secretsmanager:TagResource",
        ]
        Resource = "arn:${var.aws_partition}:secretsmanager:${var.region}:${var.account_id}:secret:${var.deployment_id}-identity-m2m-*"
      },
      {
        Sid    = "TaggedIdentityEncryptionOnly"
        Effect = "Allow"
        Action = [
          "kms:Decrypt",
          "kms:Encrypt",
          "kms:GenerateDataKey",
        ]
        Resource = "arn:${var.aws_partition}:kms:${var.region}:${var.account_id}:key/*"
        Condition = {
          StringEquals = {
            "aws:ResourceTag/deployment_id" = var.deployment_id
            "aws:ResourceTag/layer"         = "identity-control-plane"
          }
        }
      },
      {
        Sid    = "DenyControlPlaneEscalation"
        Effect = "Deny"
        Action = [
          "account:*",
          "iam:*",
          "organizations:*",
          "sts:AssumeRole",
        ]
        Resource = "*"
      },
    ]
  })

  tags = {
    deployment_id = var.deployment_id
    managed_by    = "terraform"
    layer         = "global"
    purpose       = "identity-runtime-permissions-boundary"
  }
}
