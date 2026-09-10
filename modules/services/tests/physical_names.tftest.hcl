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
    }
  ]
}

run "long_service_names_with_shared_prefix_remain_valid_and_distinct" {
  command = plan

  variables {
    alb_service_routes = {
      synthetic-shared-prefix-alpha = { priority = 100, path_patterns = ["/api/v1/*"] }
      synthetic-shared-prefix-beta  = { priority = 200, path_patterns = ["/api/v2/*"] }
    }
    service_definitions = [
      for name in ["synthetic-shared-prefix-alpha", "synthetic-shared-prefix-beta"] :
      merge(var.service_definitions[0], { name = name, port = 8080 })
    ]
    workload_role_arns = {
      for name in ["synthetic-shared-prefix-alpha", "synthetic-shared-prefix-beta"] :
      name => "arn:aws:iam::000000000000:role/synthetic-workload"
    }
  }

  assert {
    condition = alltrue([
      for group in aws_lb_target_group.service :
      length(group.name) <= 32 &&
      can(regex("^[a-z0-9]([a-z0-9-]*[a-z0-9])?$", group.name))
    ])
    error_message = "full canonical identities and long service names must produce AWS-valid target group names"
  }

  assert {
    condition = (
      length(aws_lb_target_group.service) == 2 &&
      length(distinct([for group in aws_lb_target_group.service : group.name])) == 2
    )
    error_message = "service names sharing their first 16 characters must not collide"
  }

  assert {
    condition     = aws_lb_target_group.service["synthetic-shared-prefix-alpha"].name == "tg-65560dae54da4ffcf39649332cd8"
    error_message = "a fixed synthetic identity pair must have a stable target group name across plans"
  }

  assert {
    condition = alltrue([
      for name, group in aws_lb_target_group.service :
      group.tags.deployment_id == var.deployment_id && group.tags.service == name
    ])
    error_message = "target groups must retain complete canonical deployment and service identities in tags"
  }

  assert {
    condition = alltrue([
      for service in aws_ecs_task_definition.service : {
        for item in jsondecode(service.container_definitions)[0].environment : item.name => item.value
      }["SCANALYZE_DEPLOYMENT_ID"] == var.deployment_id
    ])
    error_message = "physical target group names must not change runtime deployment identity"
  }
}

run "same_service_in_deployments_with_shared_prefix_gets_distinct_target_group" {
  command = plan

  variables {
    alb_service_routes = {
      synthetic-shared-prefix-alpha = { priority = 100, path_patterns = ["/api/v1/*"] }
    }
    deployment_id = "dep_01ARZ3NDEKTSV4RRFFQ69G5FAW"
    identity_control_plane_contract = merge(var.identity_control_plane_contract, {
      deployment_id = "dep_01ARZ3NDEKTSV4RRFFQ69G5FAW"
    })
    service_definitions = [
      merge(var.service_definitions[0], { name = "synthetic-shared-prefix-alpha", port = 8080 })
    ]
    workload_role_arns = {
      synthetic-shared-prefix-alpha = "arn:aws:iam::000000000000:role/synthetic-workload"
    }
  }

  assert {
    condition     = aws_lb_target_group.service["synthetic-shared-prefix-alpha"].name != "tg-65560dae54da4ffcf39649332cd8"
    error_message = "the same service in a deployment differing only at the ULID end must not reuse its target group name"
  }

  assert {
    condition     = aws_lb_target_group.service["synthetic-shared-prefix-alpha"].tags.deployment_id == "dep_01ARZ3NDEKTSV4RRFFQ69G5FAW"
    error_message = "target group tags must still carry the full second deployment identity"
  }
}
