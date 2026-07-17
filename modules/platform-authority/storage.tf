resource "aws_kms_key" "control_plane" {
  description             = "Scanalyze platform-authority control metadata and release encryption."
  deletion_window_in_days = 30
  enable_key_rotation     = true
  multi_region            = false
  tags                    = local.authority_tags

  depends_on = [terraform_data.contract]

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_kms_alias" "control_plane" {
  name          = "alias/scanalyze-platform-authority"
  target_key_id = aws_kms_key.control_plane.key_id
}

resource "aws_dynamodb_table" "deployment_registry" {
  name         = "scanalyze-deployment-registry"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "deployment_id"

  deletion_protection_enabled = true

  attribute {
    name = "deployment_id"
    type = "S"
  }

  point_in_time_recovery {
    enabled = true
  }

  server_side_encryption {
    enabled     = true
    kms_key_arn = aws_kms_key.control_plane.arn
  }

  tags       = local.authority_tags
  depends_on = [terraform_data.contract]

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_dynamodb_table" "execution_ledger" {
  name         = "scanalyze-deployment-executions"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "deployment_id"
  range_key    = "record_key"

  deletion_protection_enabled = true

  attribute {
    name = "deployment_id"
    type = "S"
  }

  attribute {
    name = "record_key"
    type = "S"
  }

  point_in_time_recovery {
    enabled = true
  }

  server_side_encryption {
    enabled     = true
    kms_key_arn = aws_kms_key.control_plane.arn
  }

  tags       = local.authority_tags
  depends_on = [terraform_data.contract]

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_s3_bucket" "releases" {
  bucket        = var.release_bucket_name
  force_destroy = false
  tags          = local.authority_tags

  depends_on = [terraform_data.contract]

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_s3_bucket_versioning" "releases" {
  bucket = aws_s3_bucket.releases.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "releases" {
  bucket = aws_s3_bucket.releases.id

  rule {
    bucket_key_enabled = true

    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.control_plane.arn
      sse_algorithm     = "aws:kms"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "releases" {
  bucket = aws_s3_bucket.releases.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "releases" {
  bucket = aws_s3_bucket.releases.id

  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_policy" "releases" {
  bucket = aws_s3_bucket.releases.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "DenyInsecureTransport"
      Effect    = "Deny"
      Action    = "s3:*"
      Principal = "*"
      Resource = [
        aws_s3_bucket.releases.arn,
        "${aws_s3_bucket.releases.arn}/*",
      ]
      Condition = {
        Bool = {
          "aws:SecureTransport" = "false"
        }
      }
    }]
  })

  depends_on = [aws_s3_bucket_public_access_block.releases]
}
