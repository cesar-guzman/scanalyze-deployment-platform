mock_provider "aws" {}

variables {
  deployment_id           = "dep_01ARZ3NDEKTSV4RRFFQ69G5FAV"
  customer_id             = "cust_01ARZ3NDEKTSV4RRFFQ69G5FAV"
  account_id              = "000000000000"
  region                  = "us-east-1"
  release_version         = "v0.0.0-synthetic"
  release_manifest_digest = "sha256:0000000000000000000000000000000000000000000000000000000000000000"

  ecs_cluster_arn             = "arn:aws:ecs:us-east-1:000000000000:cluster/synthetic"
  ecs_task_execution_role_arn = "arn:aws:iam::000000000000:role/synthetic-execution"
  workload_role_arns = {
    ingest-api = "arn:aws:iam::000000000000:role/synthetic-ingest"
  }
  vpc_id = "vpc-00000000000000000"
  private_subnet_ids = {
    use1-az1 = "subnet-00000000000000000"
  }
  alb_listener_arn         = "arn:aws:elasticloadbalancing:us-east-1:000000000000:listener/app/synthetic/0000000000000000/0000000000000000"
  alb_security_group_id    = "sg-00000000000000000"
  upstream_contract_digest = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
  expected_upstream_digest = "sha256:1111111111111111111111111111111111111111111111111111111111111111"

  identity_control_plane_contract = {
    contract_id                = "identity-control-plane/v1"
    contract_digest            = "sha256:3333333333333333333333333333333333333333333333333333333333333333"
    customer_id                = "cust_01ARZ3NDEKTSV4RRFFQ69G5FAV"
    deployment_id              = "dep_01ARZ3NDEKTSV4RRFFQ69G5FAV"
    account_id                 = "000000000000"
    region                     = "us-east-1"
    aws_partition              = "aws"
    cognito_user_pool_id       = "us-east-1_SYNTHETIC"
    cognito_user_pool_arn      = "arn:aws:cognito-idp:us-east-1:000000000000:userpool/us-east-1_SYNTHETIC"
    cognito_issuer_url         = "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_SYNTHETIC"
    cognito_spa_client_id      = "syntheticspaclient"
    m2m_client_ids             = []
    resource_server_identifier = "scanalyze.api.v1"
    allowed_token_uses         = ["access"]
    action_scopes = {
      read  = "scanalyze.api.v1/read"
      write = "scanalyze.api.v1/write"
      admin = "scanalyze.api.v1/admin"
    }
    action_scope_sets = {
      read  = ["scanalyze.api.v1/read"]
      write = ["scanalyze.api.v1/write"]
      admin = ["scanalyze.api.v1/admin"]
    }
    m2m_bindings                       = []
    customer_claim_name                = "custom:customerId"
    deployment_claim_name              = "custom:deployment_id"
    policy_version                     = "1.0.0"
    policy_digest                      = "sha256:34a639992f6c2312176ac7dc12c361daa38201adea6af0c0b1765a17a14754f8"
    policy_canonicalization            = "rfc8785_json_canonicalization"
    authz_schema_version               = "enterprise-authorization.v1"
    scope_catalog_version              = "scanalyze.api.v1"
    role_catalog_version               = "enterprise-roles.v1"
    human_role_groups                  = ["customer_admin", "document_operator", "document_reviewer", "auditor"]
    provider_groups_authoritative      = false
    pre_token_generation_version       = "V2_0"
    human_runtime_provisioning_enabled = false
    m2m_runtime_provisioning_enabled   = true
    m2m_client_secret_values_exposed   = false
  }
  expected_identity_control_plane_contract_digest = "sha256:3333333333333333333333333333333333333333333333333333333333333333"

  service_definitions = [
    {
      name          = "ingest-api"
      image         = "000000000000.dkr.ecr.us-east-1.amazonaws.com/synthetic/ingest-api@sha256:2222222222222222222222222222222222222222222222222222222222222222"
      cpu           = 256
      memory        = 512
      desired_count = 1
      extra_environment = [
        {
          name  = "SCANALYZE_DEPLOYMENT_CUSTOMER_ID"
          value = "cust_01BX5ZZKBKACTAV9WEVGEMMVRZ"
        }
      ]
    }
  ]
}

run "rejects_reserved_identity_override" {
  command = plan

  expect_failures = [
    var.service_definitions,
  ]
}

run "rejects_duplicate_environment_names" {
  command = plan

  variables {
    service_definitions = [
      {
        name          = "ingest-api"
        image         = "000000000000.dkr.ecr.us-east-1.amazonaws.com/synthetic/ingest-api@sha256:2222222222222222222222222222222222222222222222222222222222222222"
        cpu           = 256
        memory        = 512
        desired_count = 1
        extra_environment = [
          {
            name  = "LOG_LEVEL"
            value = "INFO"
          },
          {
            name  = "LOG_LEVEL"
            value = "WARNING"
          }
        ]
      }
    ]
  }

  expect_failures = [
    var.service_definitions,
  ]
}

run "rejects_case_insensitive_reserved_identity_override" {
  command = plan

  variables {
    service_definitions = [
      {
        name          = "ingest-api"
        image         = "000000000000.dkr.ecr.us-east-1.amazonaws.com/synthetic/ingest-api@sha256:2222222222222222222222222222222222222222222222222222222222222222"
        cpu           = 256
        memory        = 512
        desired_count = 1
        extra_environment = [
          {
            name  = "scanalyze_deployment_customer_id"
            value = "cust_01BX5ZZKBKACTAV9WEVGEMMVRZ"
          }
        ]
      }
    ]
  }

  expect_failures = [
    var.service_definitions,
  ]
}

run "rejects_case_insensitive_duplicate_environment_names" {
  command = plan

  variables {
    service_definitions = [
      {
        name          = "ingest-api"
        image         = "000000000000.dkr.ecr.us-east-1.amazonaws.com/synthetic/ingest-api@sha256:2222222222222222222222222222222222222222222222222222222222222222"
        cpu           = 256
        memory        = 512
        desired_count = 1
        extra_environment = [
          {
            name  = "LOG_LEVEL"
            value = "INFO"
          },
          {
            name  = "log_level"
            value = "WARNING"
          }
        ]
      }
    ]
  }

  expect_failures = [
    var.service_definitions,
  ]
}

run "rejects_m2m_binding_override" {
  command = plan

  variables {
    service_definitions = [
      {
        name          = "ingest-api"
        image         = "000000000000.dkr.ecr.us-east-1.amazonaws.com/synthetic/ingest-api@sha256:2222222222222222222222222222222222222222222222222222222222222222"
        cpu           = 256
        memory        = 512
        desired_count = 1
        extra_environment = [
          {
            name  = "M2M_CLIENT_IDENTITY_BINDINGS_V1"
            value = "{}"
          }
        ]
      }
    ]
  }

  expect_failures = [
    var.service_definitions,
  ]
}

run "rejects_m2m_scope_set_override" {
  command = plan

  variables {
    service_definitions = [
      {
        name          = "ingest-api"
        image         = "000000000000.dkr.ecr.us-east-1.amazonaws.com/synthetic/ingest-api@sha256:2222222222222222222222222222222222222222222222222222222222222222"
        cpu           = 256
        memory        = 512
        desired_count = 1
        extra_environment = [
          {
            name  = "m2m_action_scope_sets_v1"
            value = "{}"
          }
        ]
      }
    ]
  }

  expect_failures = [
    var.service_definitions,
  ]
}

run "rejects_mutable_service_image" {
  command = plan

  variables {
    service_definitions = [
      {
        name              = "ingest-api"
        image             = "000000000000.dkr.ecr.us-east-1.amazonaws.com/synthetic/ingest-api:latest"
        cpu               = 256
        memory            = 512
        desired_count     = 1
        extra_environment = []
      }
    ]
  }

  expect_failures = [
    var.service_definitions,
  ]
}
