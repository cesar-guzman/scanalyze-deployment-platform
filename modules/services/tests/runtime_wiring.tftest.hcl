# GUG-108 — runtime wiring injected into the task definitions.
# Hermetic provider plans only: these tests never contact AWS.
mock_provider "aws" {}

variables {
  alb_service_routes      = {}
  deployment_id           = "dep_01ARZ3NDEKTSV4RRFFQ69G5FAV"
  customer_id             = "cust_01ARZ3NDEKTSV4RRFFQ69G5FAV"
  account_id              = "000000000000"
  region                  = "us-east-1"
  release_version         = "v0.0.0-synthetic"
  release_manifest_digest = "sha256:0000000000000000000000000000000000000000000000000000000000000000"

  ecs_cluster_arn             = "arn:aws:ecs:us-east-1:000000000000:cluster/synthetic"
  ecs_task_execution_role_arn = "arn:aws:iam::000000000000:role/synthetic-execution"
  workload_role_arns = {
    for name in ["ingest-api", "ocr-worker", "postprocess-worker", "classifier-worker", "bank-worker", "personal-worker", "gov-worker"] :
    name => "arn:aws:iam::000000000000:role/synthetic-${name}"
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
    for name in ["ingest-api", "ocr-worker", "ocr-poll-worker", "postprocess-worker", "classifier-worker", "bank-worker", "personal-worker", "gov-worker"] : {
      name          = name
      image         = "000000000000.dkr.ecr.us-east-1.amazonaws.com/synthetic/${name}@sha256:2222222222222222222222222222222222222222222222222222222222222222"
      cpu           = 256
      memory        = 512
      desired_count = 1
    }
  ]

  runtime_wiring = {
    runtime_environment   = "sandbox"
    documents_table_name  = "dep_01ARZ3NDEKTSV4RRFFQ69G5FAV-documents"
    documents_bucket_name = "dep-01arz3ndektsv4rrffq69g5fav-documents"
    stage_queue_urls = {
      for stage in ["ingest", "ocr", "classify", "bank-extract", "personal-extract", "gov-extract", "validate", "persist", "notify"] :
      stage => "https://sqs.us-east-1.amazonaws.com/000000000000/dep_01ARZ3NDEKTSV4RRFFQ69G5FAV-${stage}-stage-queue"
    }
  }
}

run "workers_read_their_configuration_from_the_environment" {
  command = plan

  assert {
    condition = alltrue([
      for service in ["ocr-worker", "ocr-poll-worker", "postprocess-worker", "classifier-worker", "bank-worker", "personal-worker", "gov-worker"] :
      contains([
        for item in jsondecode(aws_ecs_task_definition.service[service].container_definitions)[0].environment :
        "${item.name}=${item.value}"
      ], "SCANALYZE_RUNTIME_CONFIG_SOURCE=environment")
    ])
    error_message = "every worker must run in environment runtime-config mode"
  }

  assert {
    condition = alltrue(flatten([
      for service in ["ocr-worker", "ocr-poll-worker", "postprocess-worker", "classifier-worker", "bank-worker", "personal-worker", "gov-worker"] : [
        for name in [
          "SCANALYZE_ENV",
          "SCANALYZE_CONFIG_DATA_FOUNDATION_DOCUMENTS_TABLE_NAME",
          "SCANALYZE_CONFIG_DATA_FOUNDATION_RAW_BUCKET_NAME",
          "SCANALYZE_CONFIG_DATA_FOUNDATION_OCR_BUCKET_NAME",
          "SCANALYZE_CONFIG_DATA_FOUNDATION_STRUCTURED_BUCKET_NAME",
          "SCANALYZE_CONFIG_QUEUES_INGEST_URL",
          "SCANALYZE_CONFIG_QUEUES_OCR_URL",
          "SCANALYZE_CONFIG_QUEUES_CLASSIFY_URL",
          "SCANALYZE_CONFIG_QUEUES_BANK_EXTRACT_URL",
          "SCANALYZE_CONFIG_QUEUES_PERSONAL_EXTRACT_URL",
          "SCANALYZE_CONFIG_QUEUES_GOV_EXTRACT_URL",
          "SCANALYZE_CONFIG_QUEUES_VALIDATE_URL",
          "SCANALYZE_CONFIG_QUEUES_PERSIST_URL",
          "SCANALYZE_CONFIG_QUEUES_NOTIFY_URL",
          "DOCUMENTS_TABLE_PK_NAME",
          "DOCUMENTS_TABLE_SK_NAME",
        ] : contains([for item in jsondecode(aws_ecs_task_definition.service[service].container_definitions)[0].environment : item.name], name)
      ]
    ]))
    error_message = "every worker must receive the table, the bucket, all nine stage queues and the table key names"
  }

  assert {
    condition = one([
      for item in jsondecode(aws_ecs_task_definition.service["bank-worker"].container_definitions)[0].environment :
      item.value if item.name == "SCANALYZE_CONFIG_QUEUES_BANK_EXTRACT_URL"
    ]) == "https://sqs.us-east-1.amazonaws.com/000000000000/dep_01ARZ3NDEKTSV4RRFFQ69G5FAV-bank-extract-stage-queue"
    error_message = "stage names must map to SCANALYZE_CONFIG_QUEUES_<STAGE>_URL with the stage queue URL"
  }

  assert {
    condition = alltrue(flatten([
      for service, definition in aws_ecs_task_definition.service : [
        for item in jsondecode(definition.container_definitions)[0].environment :
        !contains(["SCANALYZE_TENANT", "SCANALYZE_TENANTS", "SCANALYZE_PARAM_ROOT"], item.name)
      ]
    ]))
    error_message = "no service may receive the legacy tenant settings (ADR-001)"
  }
}

run "domain_workers_and_ocr_modes_are_bound" {
  command = plan

  assert {
    condition = alltrue([
      for service, domain in { "bank-worker" = "bank", "personal-worker" = "personal", "gov-worker" = "gov" } :
      contains([
        for item in jsondecode(aws_ecs_task_definition.service[service].container_definitions)[0].environment :
        "${item.name}=${item.value}"
      ], "SCANALYZE_PROCESSING_DOMAIN=${domain}")
    ])
    error_message = "each extraction worker must be bound to its processing domain"
  }

  assert {
    condition = alltrue([
      for service, mode in { "ocr-worker" = "INGEST", "ocr-poll-worker" = "OCR_POLL" } :
      contains([
        for item in jsondecode(aws_ecs_task_definition.service[service].container_definitions)[0].environment :
        "${item.name}=${item.value}"
      ], "WORKER_MODE=${mode}")
    ])
    error_message = "the OCR worker and the OCR poller must run their own mode"
  }

  assert {
    condition     = aws_ecs_task_definition.service["ocr-poll-worker"].task_role_arn == "arn:aws:iam::000000000000:role/synthetic-ocr-worker"
    error_message = "the OCR poller must use the OCR worker's task role"
  }
}

run "ingest_api_receives_its_settings" {
  command = plan

  assert {
    condition = alltrue([
      for pair in [
        "APP_ENV=sandbox",
        "DOCUMENTS_TABLE_NAME=dep_01ARZ3NDEKTSV4RRFFQ69G5FAV-documents",
        "OPERATION_LEDGER_TABLE_NAME=dep_01ARZ3NDEKTSV4RRFFQ69G5FAV-documents",
        "RAW_BUCKET=dep-01arz3ndektsv4rrffq69g5fav-documents",
        "INGEST_QUEUE_URL=https://sqs.us-east-1.amazonaws.com/000000000000/dep_01ARZ3NDEKTSV4RRFFQ69G5FAV-ingest-stage-queue",
        "DOCUMENTS_TABLE_PK_NAME=pk",
        "DOCUMENTS_TABLE_SK_NAME=sk",
        ] : contains([
          for item in jsondecode(aws_ecs_task_definition.service["ingest-api"].container_definitions)[0].environment :
          "${item.name}=${item.value}"
      ], pair)
    ])
    error_message = "the ingest API must receive its table, buckets, ingest queue and table keys"
  }

  assert {
    condition = !contains([
      for item in jsondecode(aws_ecs_task_definition.service["ingest-api"].container_definitions)[0].environment : item.name
    ], "SCANALYZE_RUNTIME_CONFIG_SOURCE")
    error_message = "the ingest API reads its own settings, not the worker runtime-config mode"
  }
}

run "every_service_gets_its_own_log_group_first" {
  command = plan

  assert {
    condition     = toset(keys(aws_cloudwatch_log_group.service)) == toset([for svc in var.service_definitions : svc.name])
    error_message = "this layer must create one log group per service it defines"
  }

  assert {
    condition = alltrue([
      for service, definition in aws_ecs_task_definition.service :
      jsondecode(definition.container_definitions)[0].logConfiguration.options["awslogs-group"] == "/ecs/${var.deployment_id}/${service}"
    ])
    error_message = "every task must log to the group this layer creates"
  }
}

run "legacy_mode_injects_no_runtime_wiring" {
  command = plan

  variables {
    runtime_wiring = null
  }

  assert {
    condition = alltrue(flatten([
      for service, definition in aws_ecs_task_definition.service : [
        for item in jsondecode(definition.container_definitions)[0].environment :
        !startswith(item.name, "SCANALYZE_CONFIG_") && item.name != "SCANALYZE_RUNTIME_CONFIG_SOURCE"
      ]
    ]))
    error_message = "without runtime_wiring the task definitions must stay as before"
  }
}

run "extra_environment_cannot_override_runtime_wiring" {
  command = plan

  variables {
    service_definitions = [
      {
        name              = "bank-worker"
        image             = "000000000000.dkr.ecr.us-east-1.amazonaws.com/synthetic/bank-worker@sha256:2222222222222222222222222222222222222222222222222222222222222222"
        cpu               = 256
        memory            = 512
        extra_environment = [{ name = "SCANALYZE_ENV", value = "production" }]
      }
    ]
  }

  expect_failures = [terraform_data.runtime_wiring_gate]
}

run "legacy_tenant_settings_are_rejected_in_environment_mode" {
  command = plan

  variables {
    service_definitions = [
      {
        name              = "gov-worker"
        image             = "000000000000.dkr.ecr.us-east-1.amazonaws.com/synthetic/gov-worker@sha256:2222222222222222222222222222222222222222222222222222222222222222"
        cpu               = 256
        memory            = 512
        extra_environment = [{ name = "SCANALYZE_TENANT", value = "gov" }]
      }
    ]
  }

  expect_failures = [terraform_data.runtime_wiring_gate]
}

run "runtime_wiring_requires_all_nine_stages" {
  command = plan

  variables {
    runtime_wiring = {
      runtime_environment   = "sandbox"
      documents_table_name  = "dep_01ARZ3NDEKTSV4RRFFQ69G5FAV-documents"
      documents_bucket_name = "dep-01arz3ndektsv4rrffq69g5fav-documents"
      stage_queue_urls = {
        ingest = "https://sqs.us-east-1.amazonaws.com/000000000000/dep_01ARZ3NDEKTSV4RRFFQ69G5FAV-ingest-stage-queue"
      }
    }
  }

  expect_failures = [var.runtime_wiring]
}
