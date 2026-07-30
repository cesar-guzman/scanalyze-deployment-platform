resource "aws_kms_key" "identity" {
  description             = "Identity control plane data and log encryption for ${var.deployment_id}"
  enable_key_rotation     = true
  deletion_window_in_days = 30
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowSameAccountKeyAdministrationAndIAMDelegation"
        Effect = "Allow"
        Principal = {
          AWS = "arn:${var.aws_partition}:iam::${var.account_id}:root"
        }
        Action = [
          "kms:CancelKeyDeletion",
          "kms:CreateAlias",
          "kms:CreateGrant",
          "kms:Decrypt",
          "kms:DeleteAlias",
          "kms:DescribeKey",
          "kms:DisableKey",
          "kms:EnableKey",
          "kms:Encrypt",
          "kms:GenerateDataKey*",
          "kms:GetKeyPolicy",
          "kms:GetKeyRotationStatus",
          "kms:ListGrants",
          "kms:ListKeyPolicies",
          "kms:ListResourceTags",
          "kms:PutKeyPolicy",
          "kms:ReEncrypt*",
          "kms:RetireGrant",
          "kms:RevokeGrant",
          "kms:ScheduleKeyDeletion",
          "kms:TagResource",
          "kms:UntagResource",
          "kms:UpdateAlias",
          "kms:UpdateKeyDescription",
          "kms:EnableKeyRotation",
          "kms:DisableKeyRotation",
        ]
        Resource = "*"
      },
      {
        Sid    = "AllowExactRegionalLambdaLogGroups"
        Effect = "Allow"
        Principal = {
          Service = "logs.${var.region}.${local.aws_dns_suffix}"
        }
        Action = [
          "kms:Decrypt",
          "kms:DescribeKey",
          "kms:Encrypt",
          "kms:GenerateDataKey*",
          "kms:ReEncrypt*",
        ]
        Resource = "*"
        Condition = {
          ArnEquals = {
            "kms:EncryptionContext:aws:logs:arn" = [
              "arn:${var.aws_partition}:logs:${var.region}:${var.account_id}:log-group:/aws/lambda/${local.pre_token_function_name}",
              "arn:${var.aws_partition}:logs:${var.region}:${var.account_id}:log-group:/aws/lambda/${local.control_processor_function_name}",
            ]
          }
        }
      },
      {
        Sid    = "AllowExactRegionalDynamoDBService"
        Effect = "Allow"
        Principal = {
          Service = "dynamodb.${local.aws_dns_suffix}"
        }
        Action = [
          "kms:CreateGrant",
          "kms:Decrypt",
          "kms:DescribeKey",
          "kms:Encrypt",
          "kms:GenerateDataKey*",
          "kms:ReEncrypt*",
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "kms:CallerAccount" = var.account_id
            "kms:ViaService"    = "dynamodb.${var.region}.${local.aws_dns_suffix}"
          }
          Bool = {
            "kms:GrantIsForAWSResource" = "true"
          }
        }
      },
      {
        Sid    = "AllowControlProcessorToEncryptExactSecrets"
        Effect = "Allow"
        Principal = {
          AWS = aws_iam_role.control_processor.arn
        }
        Action = [
          "kms:Decrypt",
          "kms:DescribeKey",
          "kms:Encrypt",
          "kms:GenerateDataKey*",
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "kms:CallerAccount" = var.account_id
            "kms:ViaService"    = "secretsmanager.${var.region}.${local.aws_dns_suffix}"
          }
        }
      },
    ]
  })

  lifecycle {
    prevent_destroy = true
  }

  tags = merge(local.common_tags, {
    purpose = "identity-control-plane-encryption"
  })
}

resource "aws_kms_alias" "identity" {
  name          = "alias/${local.identity_prefix}"
  target_key_id = aws_kms_key.identity.key_id
}

resource "aws_dynamodb_table" "memberships" {
  name         = "${local.identity_prefix}-memberships"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "pk"
  range_key    = "sk"

  deletion_protection_enabled = true
  stream_enabled              = true
  stream_view_type            = "NEW_AND_OLD_IMAGES"

  attribute {
    name = "pk"
    type = "S"
  }

  attribute {
    name = "sk"
    type = "S"
  }

  attribute {
    name = "ownership_membership_key"
    type = "S"
  }

  attribute {
    name = "ownership_state_key"
    type = "S"
  }

  attribute {
    name = "membership_reference"
    type = "S"
  }

  global_secondary_index {
    name            = "ownership-membership-reference-v1"
    hash_key        = "ownership_membership_key"
    projection_type = "ALL"
  }

  global_secondary_index {
    name            = "ownership-state-v1"
    hash_key        = "ownership_state_key"
    range_key       = "membership_reference"
    projection_type = "ALL"
  }

  point_in_time_recovery {
    enabled = true
  }

  server_side_encryption {
    enabled     = true
    kms_key_arn = aws_kms_key.identity.arn
  }

  lifecycle {
    prevent_destroy = true
  }

  tags = merge(local.common_tags, {
    purpose = "authoritative-membership-store"
  })
}

resource "aws_dynamodb_table" "authorization_audit" {
  name         = "${local.identity_prefix}-authorization-audit"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "pk"
  range_key    = "sk"

  deletion_protection_enabled = true

  attribute {
    name = "pk"
    type = "S"
  }

  attribute {
    name = "sk"
    type = "S"
  }

  point_in_time_recovery {
    enabled = true
  }

  server_side_encryption {
    enabled     = true
    kms_key_arn = aws_kms_key.identity.arn
  }

  lifecycle {
    prevent_destroy = true
  }

  tags = merge(local.common_tags, {
    purpose = "authorization-audit"
  })
}

resource "aws_dynamodb_table" "bootstrap_requests" {
  name         = "${local.identity_prefix}-bootstrap-requests"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "pk"
  range_key    = "sk"

  deletion_protection_enabled = true

  attribute {
    name = "pk"
    type = "S"
  }

  attribute {
    name = "sk"
    type = "S"
  }

  point_in_time_recovery {
    enabled = true
  }

  server_side_encryption {
    enabled     = true
    kms_key_arn = aws_kms_key.identity.arn
  }

  lifecycle {
    prevent_destroy = true
  }

  tags = merge(local.common_tags, {
    purpose = "reviewed-bootstrap-request-store"
  })
}

resource "aws_dynamodb_table" "m2m_bindings" {
  name         = "${local.identity_prefix}-m2m-bindings"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "pk"
  range_key    = "sk"

  deletion_protection_enabled = true

  attribute {
    name = "pk"
    type = "S"
  }

  attribute {
    name = "sk"
    type = "S"
  }

  point_in_time_recovery {
    enabled = true
  }

  server_side_encryption {
    enabled     = true
    kms_key_arn = aws_kms_key.identity.arn
  }

  lifecycle {
    prevent_destroy = true
  }

  tags = merge(local.common_tags, {
    purpose = "m2m-binding-store"
  })
}
