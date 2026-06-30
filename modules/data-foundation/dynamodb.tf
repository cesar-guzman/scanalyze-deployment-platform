# Data Foundation — DynamoDB Tables
#
# Status: authored_not_provider_validated

resource "aws_dynamodb_table" "documents" {
  name         = "${var.deployment_id}-documents"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "pk"
  range_key    = "sk"

  attribute {
    name = "pk"
    type = "S"
  }

  attribute {
    name = "sk"
    type = "S"
  }

  server_side_encryption {
    enabled     = true
    kms_key_arn = aws_kms_key.data.arn
  }

  point_in_time_recovery {
    enabled = true
  }

  tags = {
    deployment_id = var.deployment_id
    managed_by    = "terraform"
    layer         = "data-foundation"
  }
}

resource "aws_dynamodb_table" "jobs" {
  name         = "${var.deployment_id}-jobs"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "job_id"

  attribute {
    name = "job_id"
    type = "S"
  }

  server_side_encryption {
    enabled     = true
    kms_key_arn = aws_kms_key.data.arn
  }

  point_in_time_recovery {
    enabled = true
  }

  tags = {
    deployment_id = var.deployment_id
    managed_by    = "terraform"
    layer         = "data-foundation"
  }
}
