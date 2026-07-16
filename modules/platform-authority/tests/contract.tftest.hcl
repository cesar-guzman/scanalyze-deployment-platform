mock_provider "aws" {
  mock_resource "aws_iam_openid_connect_provider" {
    defaults = {
      arn = "arn:aws:iam::999888777666:oidc-provider/token.actions.githubusercontent.com"
    }
  }

  mock_resource "aws_iam_policy" {
    defaults = {
      arn = "arn:aws:iam::999888777666:policy/ScanalyzePlatformAuthoritySynthetic"
    }
  }

  mock_resource "aws_kms_key" {
    defaults = {
      arn    = "arn:aws:kms:us-east-1:999888777666:key/00000000-0000-0000-0000-000000000000"
      key_id = "00000000-0000-0000-0000-000000000000"
    }
  }

  mock_resource "aws_s3_bucket" {
    defaults = {
      arn = "arn:aws:s3:::scanalyze-synthetic-platform-releases"
      id  = "scanalyze-synthetic-platform-releases"
    }
  }
}

variables {
  authority_account_id = "999888777666"
  authority_region     = "us-east-1"
  release_bucket_name  = "scanalyze-synthetic-platform-releases"

  deployments = {
    dep_01ARZ3NDEKTSV4RRFFQ69G5FAV = {
      customer_id            = "cust_01ARZ3NDEKTSV4RRFFQ69G5FAV"
      deployment_id          = "dep_01ARZ3NDEKTSV4RRFFQ69G5FAV"
      destination_account_id = "111222333444"
      region                 = "us-east-1"
      environment            = "staging"
      github_oidc_subject    = "repo:synthetic@101/scanalyze@201:environment:client-a-staging"
      repository_owner_id    = 101
      repository_id          = 201
    }
    dep_01BX5ZZKBKACTAV9WEVGEMMVRZ = {
      customer_id            = "cust_01BX5ZZKBKACTAV9WEVGEMMVRZ"
      deployment_id          = "dep_01BX5ZZKBKACTAV9WEVGEMMVRZ"
      destination_account_id = "555666777888"
      region                 = "us-east-1"
      environment            = "sandbox"
      github_oidc_subject    = "repo:synthetic/scanalyze:environment:client-b-sandbox"
      repository_owner_id    = 101
      repository_id          = 201
    }
  }
}

run "creates_two_isolated_customer_orchestrators" {
  command = apply

  assert {
    condition     = length(aws_iam_role.orchestrator) == 2
    error_message = "the factory must create one exact role per deployment"
  }

  assert {
    condition = alltrue([
      for deployment_id, role in aws_iam_role.orchestrator :
      role.name == "ScanalyzeOrchestrator-${deployment_id}" &&
      role.max_session_duration == 3600 &&
      role.permissions_boundary == aws_iam_policy.orchestrator_boundary.arn &&
      role.tags["deployment_id"] == deployment_id &&
      role.tags["customer_id"] == var.deployments[deployment_id].customer_id &&
      role.tags["account_id"] == var.deployments[deployment_id].destination_account_id
    ])
    error_message = "each orchestrator must retain exact immutable ownership and a short session"
  }

  assert {
    condition = alltrue([
      for binding in values(output.contract_payload.orchestrator_roles) :
      binding.requested_session_duration_seconds == 900
    ])
    error_message = "the OIDC caller contract must request the 15-minute STS minimum"
  }

  assert {
    condition = alltrue([
      for deployment_id, role in aws_iam_role.orchestrator :
      jsondecode(role.assume_role_policy).Statement[0].Condition.StringEquals["token.actions.githubusercontent.com:sub"] == var.deployments[deployment_id].github_oidc_subject &&
      jsondecode(role.assume_role_policy).Statement[0].Condition.StringEquals["token.actions.githubusercontent.com:repository_owner_id"] == tostring(var.deployments[deployment_id].repository_owner_id) &&
      jsondecode(role.assume_role_policy).Statement[0].Condition.StringEquals["token.actions.githubusercontent.com:repository_id"] == tostring(var.deployments[deployment_id].repository_id)
    ])
    error_message = "each trust must use its exact GitHub environment subject and immutable repository IDs"
  }

  assert {
    condition = (
      strcontains(aws_iam_policy.orchestrator_runtime.policy, var.release_bucket_name) &&
      strcontains(aws_iam_policy.orchestrator_runtime.policy, aws_kms_key.control_plane.arn) &&
      strcontains(aws_iam_policy.orchestrator_runtime.policy, "s3.${var.authority_region}.amazonaws.com")
    )
    error_message = "the runtime policy must receive the configured release bucket and exact KMS key"
  }

  assert {
    condition = (
      aws_dynamodb_table.deployment_registry.deletion_protection_enabled &&
      aws_dynamodb_table.execution_ledger.deletion_protection_enabled &&
      aws_s3_bucket.releases.force_destroy == false
    )
    error_message = "control data must be protected from routine deletion"
  }
}

run "rejects_authority_account_as_customer_destination" {
  command = plan

  variables {
    deployments = {
      dep_01ARZ3NDEKTSV4RRFFQ69G5FAV = {
        customer_id            = "cust_01ARZ3NDEKTSV4RRFFQ69G5FAV"
        deployment_id          = "dep_01ARZ3NDEKTSV4RRFFQ69G5FAV"
        destination_account_id = "999888777666"
        region                 = "us-east-1"
        environment            = "staging"
        github_oidc_subject    = "repo:synthetic/scanalyze:environment:client-a-staging"
        repository_owner_id    = 101
        repository_id          = 201
      }
    }
  }

  expect_failures = [terraform_data.contract]
}

run "rejects_map_key_and_deployment_confusion" {
  command = plan

  variables {
    deployments = {
      dep_01ARZ3NDEKTSV4RRFFQ69G5FAV = {
        customer_id            = "cust_01ARZ3NDEKTSV4RRFFQ69G5FAV"
        deployment_id          = "dep_01BX5ZZKBKACTAV9WEVGEMMVRZ"
        destination_account_id = "111222333444"
        region                 = "us-east-1"
        environment            = "staging"
        github_oidc_subject    = "repo:synthetic/scanalyze:environment:client-a-staging"
        repository_owner_id    = 101
        repository_id          = 201
      }
    }
  }

  expect_failures = [terraform_data.contract]
}

run "rejects_wildcard_github_subject" {
  command = plan

  variables {
    deployments = {
      dep_01ARZ3NDEKTSV4RRFFQ69G5FAV = {
        customer_id            = "cust_01ARZ3NDEKTSV4RRFFQ69G5FAV"
        deployment_id          = "dep_01ARZ3NDEKTSV4RRFFQ69G5FAV"
        destination_account_id = "111222333444"
        region                 = "us-east-1"
        environment            = "staging"
        github_oidc_subject    = "repo:synthetic/scanalyze:environment:*"
        repository_owner_id    = 101
        repository_id          = 201
      }
    }
  }

  expect_failures = [var.deployments]
}

run "rejects_production_environment" {
  command = plan

  variables {
    deployments = {
      dep_01ARZ3NDEKTSV4RRFFQ69G5FAV = {
        customer_id            = "cust_01ARZ3NDEKTSV4RRFFQ69G5FAV"
        deployment_id          = "dep_01ARZ3NDEKTSV4RRFFQ69G5FAV"
        destination_account_id = "111222333444"
        region                 = "us-east-1"
        environment            = "production"
        github_oidc_subject    = "repo:synthetic/scanalyze:environment:client-a-production"
        repository_owner_id    = 101
        repository_id          = 201
      }
    }
  }

  expect_failures = [var.deployments]
}
