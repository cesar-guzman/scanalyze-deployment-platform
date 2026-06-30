# Data Foundation — Application Data KMS Key
#
# Status: authored_not_provider_validated
#
# This is the APPLICATION data encryption key.
# NOT the state/recovery/plan-execution KMS keys (owned by account baseline).

resource "aws_kms_key" "data" {
  description             = "Application data encryption for deployment ${var.deployment_id}"
  deletion_window_in_days = 30
  enable_key_rotation     = true

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "RootAccountAccess"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${var.account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid    = "WorkloadEncryptDecrypt"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${var.account_id}:root"
        }
        Action = [
          "kms:Decrypt",
          "kms:GenerateDataKey",
          "kms:GenerateDataKeyWithoutPlaintext",
          "kms:DescribeKey",
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "kms:ViaService" = [
              "s3.${var.region}.amazonaws.com",
              "dynamodb.${var.region}.amazonaws.com",
              "sqs.${var.region}.amazonaws.com",
            ]
          }
        }
      }
    ]
  })

  tags = {
    deployment_id = var.deployment_id
    managed_by    = "terraform"
    layer         = "data-foundation"
    purpose       = "application-data-encryption"
  }
}

resource "aws_kms_alias" "data" {
  name          = "alias/${var.deployment_id}-data"
  target_key_id = aws_kms_key.data.key_id
}
