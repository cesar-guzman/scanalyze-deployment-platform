# Data Foundation — Document Storage S3 Bucket
#
# Status: authored_not_provider_validated
#
# This is the APPLICATION document bucket, NOT the state/evidence/contracts bucket.

resource "aws_s3_bucket" "documents" {
  # S3 requires lowercase DNS-compatible names; preserve the full canonical ULID.
  # This is a physical-name change and would replace an existing bucket.
  bucket = "${lower(replace(var.deployment_id, "_", "-"))}-documents"

  tags = {
    deployment_id = var.deployment_id
    managed_by    = "terraform"
    layer         = "data-foundation"
    purpose       = "document-storage"
  }
}

resource "aws_s3_bucket_versioning" "documents" {
  bucket = aws_s3_bucket.documents.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "documents" {
  bucket = aws_s3_bucket.documents.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.data.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "documents" {
  bucket = aws_s3_bucket.documents.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_lifecycle_configuration" "documents" {
  bucket = aws_s3_bucket.documents.id

  rule {
    id     = "transition-to-ia"
    status = "Enabled"

    transition {
      days          = 90
      storage_class = "STANDARD_IA"
    }
  }
}

# GUG-543: the frontend uploads with a presigned PUT (signed Content-Type
# header) and downloads with a presigned GET through fetch(). Browsers need a
# CORS rule for both. Requests are still authorized by their S3 signature.
resource "aws_s3_bucket_cors_configuration" "documents" {
  count = length(var.browser_origins) > 0 ? 1 : 0

  bucket = aws_s3_bucket.documents.id

  cors_rule {
    allowed_origins = var.browser_origins
    allowed_methods = ["GET", "PUT"]
    allowed_headers = ["content-type"]
    max_age_seconds = 3000
  }
}
