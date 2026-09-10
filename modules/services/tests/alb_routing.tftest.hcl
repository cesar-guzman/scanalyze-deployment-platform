mock_provider "aws" {
  mock_resource "aws_lb_target_group" {
    defaults = {
      arn = "arn:aws:elasticloadbalancing:us-east-1:000000000000:targetgroup/synthetic/0000000000000000"
    }
  }
}

variables {
  alb_service_routes = {
    ingest-api = { priority = 100, path_patterns = ["/api/v1/*", "/api/v2/*"] }
  }
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
      name              = "ingest-api"
      image             = "000000000000.dkr.ecr.us-east-1.amazonaws.com/synthetic/ingest-api@sha256:2222222222222222222222222222222222222222222222222222222222222222"
      cpu               = 256
      memory            = 512
      desired_count     = 1
      port              = 80
      extra_environment = [{ name = "PORT", value = "80" }]
    }
  ]
}


run "routes_the_explicit_service_without_changing_prefix_or_port" {
  command = apply

  assert {
    condition = (
      toset(keys(aws_lb_listener_rule.service)) == toset(["ingest-api"]) &&
      aws_lb_listener_rule.service["ingest-api"].listener_arn == var.alb_listener_arn &&
      aws_lb_listener_rule.service["ingest-api"].priority == 100 &&
      aws_lb_listener_rule.service["ingest-api"].action[0].type == "forward" &&
      aws_lb_listener_rule.service["ingest-api"].action[0].target_group_arn == aws_lb_target_group.service["ingest-api"].arn
    )
    error_message = "the explicit ingest route must attach its own target group to the upstream HTTPS listener"
  }

  assert {
    condition = (
      toset(one(aws_lb_listener_rule.service["ingest-api"].condition).path_pattern[0].values) == toset(["/api/v1/*", "/api/v2/*"]) &&
      aws_lb_target_group.service["ingest-api"].protocol == "HTTP" &&
      aws_lb_target_group.service["ingest-api"].target_type == "ip" &&
      aws_lb_target_group.service["ingest-api"].port == 80 &&
      aws_lb_target_group.service["ingest-api"].health_check[0].path == "/health" &&
      one(aws_ecs_service.service["ingest-api"].load_balancer).container_port == 80 &&
      jsondecode(aws_ecs_task_definition.service["ingest-api"].container_definitions)[0].portMappings[0].containerPort == 80
    )
    error_message = "API paths and the explicit HTTP container/target port must remain aligned"
  }
}

run "workers_remain_unrouted" {
  command = apply
  variables {
    service_definitions = concat(var.service_definitions, [
      merge(var.service_definitions[0], { name = "synthetic-worker", port = null })
    ])
    workload_role_arns = merge(var.workload_role_arns, {
      synthetic-worker = "arn:aws:iam::000000000000:role/synthetic-worker"
    })
  }
  assert {
    condition = (
      !contains(keys(aws_lb_listener_rule.service), "synthetic-worker") &&
      !contains(keys(aws_lb_target_group.service), "synthetic-worker") &&
      length(aws_ecs_service.service["synthetic-worker"].load_balancer) == 0
    )
    error_message = "a worker without a port must not acquire an ALB rule, target group or attachment"
  }
}

run "rejects_a_missing_http_service_route" {
  command = plan
  variables { alb_service_routes = {} }
  expect_failures = [var.alb_service_routes]
}

run "rejects_an_unknown_service_route" {
  command = plan
  variables {
    alb_service_routes = merge(var.alb_service_routes, {
      unselected-service = { priority = 200, path_patterns = ["/api/v1/unselected/*"] }
    })
  }
  expect_failures = [var.alb_service_routes]
}

run "rejects_routing_a_worker_without_a_port" {
  command = plan
  variables {
    service_definitions = [merge(var.service_definitions[0], { port = null })]
  }
  expect_failures = [var.alb_service_routes]
}

run "rejects_duplicate_priorities" {
  command = plan
  variables {
    service_definitions = concat(var.service_definitions, [
      merge(var.service_definitions[0], { name = "second-api" })
    ])
    workload_role_arns = merge(var.workload_role_arns, {
      second-api = "arn:aws:iam::000000000000:role/synthetic-second-api"
    })
    alb_service_routes = merge(var.alb_service_routes, {
      second-api = { priority = 100, path_patterns = ["/api/v1/second/*"] }
    })
  }
  expect_failures = [var.alb_service_routes]
}

run "rejects_zero_priority" {
  command = plan
  variables {
    alb_service_routes = { ingest-api = { priority = 0, path_patterns = ["/api/v2/*"] } }
  }
  expect_failures = [var.alb_service_routes]
}

run "rejects_fractional_priority" {
  command = plan
  variables {
    alb_service_routes = { ingest-api = { priority = 1.5, path_patterns = ["/api/v2/*"] } }
  }
  expect_failures = [var.alb_service_routes]
}

run "rejects_out_of_range_priority" {
  command = plan
  variables {
    alb_service_routes = { ingest-api = { priority = 50001, path_patterns = ["/api/v2/*"] } }
  }
  expect_failures = [var.alb_service_routes]
}

run "rejects_catch_all_path" {
  command = plan
  variables {
    alb_service_routes = { ingest-api = { priority = 100, path_patterns = ["/*"] } }
  }
  expect_failures = [var.alb_service_routes]
}

run "rejects_missing_api_prefix_path" {
  command = plan
  variables {
    alb_service_routes = { ingest-api = { priority = 100, path_patterns = ["/v2/*"] } }
  }
  expect_failures = [var.alb_service_routes]
}

run "rejects_query_path" {
  command = plan
  variables {
    alb_service_routes = { ingest-api = { priority = 100, path_patterns = ["/api/v2/documents?admin=true"] } }
  }
  expect_failures = [var.alb_service_routes]
}

run "rejects_traversal_path" {
  command = plan
  variables {
    alb_service_routes = { ingest-api = { priority = 100, path_patterns = ["/api/v2/../admin"] } }
  }
  expect_failures = [var.alb_service_routes]
}

run "rejects_empty_path" {
  command = plan
  variables {
    alb_service_routes = { ingest-api = { priority = 100, path_patterns = [] } }
  }
  expect_failures = [var.alb_service_routes]
}

run "rejects_too_many_patterns_path" {
  command = plan
  variables {
    alb_service_routes = { ingest-api = { priority = 100, path_patterns = ["/api/v1/a", "/api/v1/b", "/api/v2/a", "/api/v2/b"] } }
  }
  expect_failures = [var.alb_service_routes]
}

run "rejects_duplicate_patterns_path" {
  command = plan
  variables {
    alb_service_routes = { ingest-api = { priority = 100, path_patterns = ["/api/v2/*", "/api/v2/*"] } }
  }
  expect_failures = [var.alb_service_routes]
}

run "rejects_too_many_wildcards_path" {
  command = plan
  variables {
    alb_service_routes = { ingest-api = { priority = 100, path_patterns = ["/api/v2/*/*/*/*/*/*"] } }
  }
  expect_failures = [var.alb_service_routes]
}

run "rejects_overlong_path" {
  command = plan
  variables {
    alb_service_routes = { ingest-api = { priority = 100, path_patterns = ["/api/v2/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"] } }
  }
  expect_failures = [var.alb_service_routes]
}
