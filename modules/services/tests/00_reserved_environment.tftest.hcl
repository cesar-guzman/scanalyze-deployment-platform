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
