# Hermetic provider plans only: these tests never contact AWS.
mock_provider "aws" {}

variables {
  deployment_id            = "dep_01ARZ3NDEKTSV4RRFFQ69G5FAV"
  account_id               = "000000000000"
  region                   = "us-east-1"
  release_version          = "v0.0.0-synthetic"
  release_manifest_digest  = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
  upstream_contract_digest = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
  expected_upstream_digest = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
}

run "canonical_deployment_has_valid_document_bucket_name" {
  command = plan

  assert {
    condition = (
      length(aws_s3_bucket.documents.bucket) >= 3 &&
      length(aws_s3_bucket.documents.bucket) <= 63 &&
      can(regex("^[a-z0-9][a-z0-9-]*[a-z0-9]$", aws_s3_bucket.documents.bucket)) &&
      startswith(aws_s3_bucket.documents.bucket, "dep-") &&
      endswith(aws_s3_bucket.documents.bucket, "-documents")
    )
    error_message = "canonical identity must produce a valid, non-reserved S3 bucket name"
  }

  assert {
    condition     = aws_s3_bucket.documents.tags.deployment_id == var.deployment_id
    error_message = "the bucket must retain the exact canonical deployment identity in tags"
  }

  assert {
    condition     = aws_s3_bucket.documents.bucket == "dep-01arz3ndektsv4rrffq69g5fav-documents"
    error_message = "the full canonical ULID must survive in the document bucket name"
  }
}

run "deployments_differing_only_at_ulid_end_keep_distinct_buckets" {
  command = plan

  variables {
    deployment_id = "dep_01ARZ3NDEKTSV4RRFFQ69G5FAW"
  }

  assert {
    # Compare the configured name, not provider-generated IDs (unknown during plan).
    condition     = aws_s3_bucket.documents.bucket != "dep-01arz3ndektsv4rrffq69g5fav-documents"
    error_message = "truncating the deployment prefix must not collapse distinct document buckets"
  }

  assert {
    condition     = aws_s3_bucket.documents.tags.deployment_id == "dep_01ARZ3NDEKTSV4RRFFQ69G5FAW"
    error_message = "bucket name normalization must leave the second canonical deployment identity intact"
  }
}
