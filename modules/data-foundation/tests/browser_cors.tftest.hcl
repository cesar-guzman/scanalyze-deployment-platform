# GUG-543 — browser access to presigned document URLs.
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

run "no_origins_means_no_cors_rule" {
  command = plan

  assert {
    condition     = length(aws_s3_bucket_cors_configuration.documents) == 0
    error_message = "without frontend origins the bucket must not get a CORS rule"
  }
}

run "frontend_origin_can_put_and_get_with_content_type_only" {
  command = plan

  variables {
    browser_origins = ["https://pilot.scanalyze.cloud"]
  }

  assert {
    condition     = length(aws_s3_bucket_cors_configuration.documents) == 1
    error_message = "a frontend origin must produce exactly one CORS configuration"
  }

  assert {
    condition = (
      toset(one(aws_s3_bucket_cors_configuration.documents[0].cors_rule[*].allowed_origins)) == toset(["https://pilot.scanalyze.cloud"]) &&
      toset(one(aws_s3_bucket_cors_configuration.documents[0].cors_rule[*].allowed_methods)) == toset(["GET", "PUT"]) &&
      toset(one(aws_s3_bucket_cors_configuration.documents[0].cors_rule[*].allowed_headers)) == toset(["content-type"])
    )
    error_message = "CORS must allow only the frontend origin, GET and PUT, and the signed Content-Type header"
  }
}

run "wildcard_origin_is_rejected" {
  command = plan

  variables {
    browser_origins = ["https://*.scanalyze.cloud"]
  }

  expect_failures = [var.browser_origins]
}

run "plain_http_origin_is_rejected" {
  command = plan

  variables {
    browser_origins = ["http://pilot.scanalyze.cloud"]
  }

  expect_failures = [var.browser_origins]
}

run "origin_with_path_is_rejected" {
  command = plan

  variables {
    browser_origins = ["https://pilot.scanalyze.cloud/"]
  }

  expect_failures = [var.browser_origins]
}
