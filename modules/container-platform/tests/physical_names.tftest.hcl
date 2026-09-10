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
  vpc_id                   = "vpc-00000000000000000"
  vpc_cidr_block           = "10.0.0.0/16"
  private_subnet_ids = {
    use1-az1 = "subnet-00000000000000001"
    use1-az2 = "subnet-00000000000000002"
  }
  internal_certificate_arn = "arn:aws:acm:us-east-1:000000000000:certificate/00000000-0000-0000-0000-000000000000"
}

run "canonical_deployment_has_valid_alb_name" {
  command = plan

  assert {
    condition = (
      length(aws_lb.internal.name) <= 32 &&
      can(regex("^[a-z0-9]([a-z0-9-]*[a-z0-9])?$", aws_lb.internal.name)) &&
      !startswith(aws_lb.internal.name, "internal-")
    )
    error_message = "a canonical uppercase ULID must produce an AWS-valid ALB name"
  }

  assert {
    condition     = strcontains(aws_lb.internal.name, "01arz3ndektsv4rrffq69g5fav")
    error_message = "the full ULID, including its final entropy characters, must survive the ALB name limit"
  }

  assert {
    condition = (
      aws_lb.internal.tags.deployment_id == var.deployment_id &&
      aws_ecs_cluster.main.tags.deployment_id == var.deployment_id
    )
    error_message = "physical-name normalization must not rewrite canonical deployment identity"
  }
}

run "deployments_differing_only_at_ulid_end_keep_distinct_albs" {
  command = plan

  variables {
    deployment_id = "dep_01ARZ3NDEKTSV4RRFFQ69G5FAW"
  }

  assert {
    condition = (
      length(aws_lb.internal.name) <= 32 &&
      strcontains(aws_lb.internal.name, "01arz3ndektsv4rrffq69g5faw") &&
      !strcontains(aws_lb.internal.name, "01arz3ndektsv4rrffq69g5fav")
    )
    error_message = "the ALB name must distinguish deployments sharing all but the final ULID character"
  }
}
