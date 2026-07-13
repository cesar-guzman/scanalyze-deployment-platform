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
    }
  ]
}

run "injects_separate_customer_and_deployment_identities" {
  command = plan

  assert {
    condition = {
      for item in jsondecode(
        aws_ecs_task_definition.service["ingest-api"].container_definitions
      )[0].environment : item.name => item.value
    }["SCANALYZE_DEPLOYMENT_CUSTOMER_ID"] == var.customer_id
    error_message = "customer identity must come from customer_id"
  }

  assert {
    condition = {
      for item in jsondecode(
        aws_ecs_task_definition.service["ingest-api"].container_definitions
      )[0].environment : item.name => item.value
    }["SCANALYZE_DEPLOYMENT_ID"] == var.deployment_id
    error_message = "deployment identity must remain distinct from customer identity"
  }

  assert {
    condition = {
      for item in jsondecode(
        aws_ecs_task_definition.service["ingest-api"].container_definitions
      )[0].environment : item.name => item.value
    }["COGNITO_ALLOWED_TOKEN_USES"] == "access"
    error_message = "the services handoff must configure access tokens only"
  }

  assert {
    condition = {
      for item in jsondecode(
        aws_ecs_task_definition.service["ingest-api"].container_definitions
      )[0].environment : item.name => item.value
    }["HUMAN_ENTERPRISE_AUTHORIZATION_ENABLED"] == "false"
    error_message = "human runtime must remain fail-closed until downstream enforcement is proven"
  }

  assert {
    condition = {
      for item in jsondecode(
        aws_ecs_task_definition.service["ingest-api"].container_definitions
      )[0].environment : item.name => item.value
    }["ENTERPRISE_POLICY_DIGEST"] == var.identity_control_plane_contract.policy_digest
    error_message = "the reviewed enterprise policy digest must reach the ingest API exactly"
  }

  assert {
    condition = {
      for item in jsondecode(
        aws_ecs_task_definition.service["ingest-api"].container_definitions
      )[0].environment : item.name => item.value
    }["M2M_TENANT_RESOLUTION"] == "disabled"
    error_message = "an empty reviewed M2M registry must fail closed"
  }

  assert {
    condition = !contains([
      for item in jsondecode(
        aws_ecs_task_definition.service["ingest-api"].container_definitions
      )[0].environment : item.name
    ], "M2M_CLIENT_IDENTITY_BINDINGS_V1")
    error_message = "an empty M2M registry must not inject a binding variable"
  }

  assert {
    condition = !contains([
      for item in jsondecode(
        aws_ecs_task_definition.service["ingest-api"].container_definitions
      )[0].environment : item.name
    ], "M2M_ACTION_SCOPE_SETS_V1")
    error_message = "an empty M2M registry must not inject action scope sets"
  }

  assert {
    condition = {
      for item in jsondecode(
        aws_ecs_task_definition.service["ingest-api"].container_definitions
      )[0].environment : item.name => item.value
    }["COGNITO_ALLOWED_CLIENT_IDS"] == var.identity_control_plane_contract.cognito_spa_client_id
    error_message = "without reviewed M2M bindings the SPA must be the sole allowed audience"
  }
}

run "injects_exact_reviewed_m2m_binding" {
  command = plan

  variables {
    identity_control_plane_contract = merge(var.identity_control_plane_contract, {
      m2m_client_ids = ["syntheticm2mclient"]
      m2m_bindings = [{
        client_id       = "syntheticm2mclient"
        customer_id     = "cust_01ARZ3NDEKTSV4RRFFQ69G5FAV"
        deployment_id   = "dep_01ARZ3NDEKTSV4RRFFQ69G5FAV"
        required_scopes = ["scanalyze.api.v1/read", "scanalyze.api.v1/write"]
      }]
    })
  }

  assert {
    condition = {
      for item in jsondecode(
        aws_ecs_task_definition.service["ingest-api"].container_definitions
      )[0].environment : item.name => item.value
    }["M2M_TENANT_RESOLUTION"] == "client_identity_bindings_v1"
    error_message = "a reviewed M2M registry must enable only the versioned binding mode"
  }

  assert {
    condition = jsondecode({
      for item in jsondecode(
        aws_ecs_task_definition.service["ingest-api"].container_definitions
      )[0].environment : item.name => item.value
      }["M2M_CLIENT_IDENTITY_BINDINGS_V1"]) == {
      syntheticm2mclient = {
        customer_id     = var.customer_id
        deployment_id   = var.deployment_id
        required_scopes = ["scanalyze.api.v1/read", "scanalyze.api.v1/write"]
      }
    }
    error_message = "the runtime binding map must contain the exact reviewed identity tuple and scopes"
  }

  assert {
    condition = {
      for item in jsondecode(
        aws_ecs_task_definition.service["ingest-api"].container_definitions
      )[0].environment : item.name => item.value
    }["M2M_ACTION_SCOPE_SETS_V1"] == jsonencode(var.identity_control_plane_contract.action_scope_sets)
    error_message = "the canonical action scope sets must reach the runtime without drift"
  }

  assert {
    condition = split(",", {
      for item in jsondecode(
        aws_ecs_task_definition.service["ingest-api"].container_definitions
      )[0].environment : item.name => item.value
    }["COGNITO_ALLOWED_CLIENT_IDS"]) == tolist(["syntheticspaclient", "syntheticm2mclient"])
    error_message = "the allowlist must be exactly the SPA plus reviewed M2M clients"
  }
}

run "rejects_m2m_client_without_binding" {
  command = plan

  variables {
    identity_control_plane_contract = merge(var.identity_control_plane_contract, {
      m2m_client_ids = ["syntheticm2mclient"]
    })
  }

  expect_failures = [var.identity_control_plane_contract]
}

run "rejects_foreign_m2m_binding" {
  command = plan

  variables {
    identity_control_plane_contract = merge(var.identity_control_plane_contract, {
      m2m_client_ids = ["syntheticm2mclient"]
      m2m_bindings = [{
        client_id       = "syntheticm2mclient"
        customer_id     = "cust_01BX5ZZKBKACTAV9WEVGEMMVRZ"
        deployment_id   = "dep_01ARZ3NDEKTSV4RRFFQ69G5FAV"
        required_scopes = ["scanalyze.api.v1/read"]
      }]
    })
  }

  expect_failures = [var.identity_control_plane_contract]
}

run "rejects_noncanonical_m2m_scope" {
  command = plan

  variables {
    identity_control_plane_contract = merge(var.identity_control_plane_contract, {
      m2m_client_ids = ["syntheticm2mclient"]
      m2m_bindings = [{
        client_id       = "syntheticm2mclient"
        customer_id     = "cust_01ARZ3NDEKTSV4RRFFQ69G5FAV"
        deployment_id   = "dep_01ARZ3NDEKTSV4RRFFQ69G5FAV"
        required_scopes = ["scanalyze.api.v1/superuser"]
      }]
    })
  }

  expect_failures = [var.identity_control_plane_contract]
}

run "rejects_foreign_deployment_binding" {
  command = plan

  variables {
    identity_control_plane_contract = merge(var.identity_control_plane_contract, {
      m2m_client_ids = ["syntheticm2mclient"]
      m2m_bindings = [{
        client_id       = "syntheticm2mclient"
        customer_id     = "cust_01ARZ3NDEKTSV4RRFFQ69G5FAV"
        deployment_id   = "dep_01BX5ZZKBKACTAV9WEVGEMMVRZ"
        required_scopes = ["scanalyze.api.v1/read"]
      }]
    })
  }

  expect_failures = [var.identity_control_plane_contract]
}

run "rejects_id_token_handoff" {
  command = plan

  variables {
    identity_control_plane_contract = merge(var.identity_control_plane_contract, {
      allowed_token_uses = ["id"]
    })
  }

  expect_failures = [var.identity_control_plane_contract]
}

run "rejects_action_scope_set_drift" {
  command = plan

  variables {
    identity_control_plane_contract = merge(var.identity_control_plane_contract, {
      action_scope_sets = {
        read  = ["scanalyze.api.v1/read"]
        write = ["scanalyze.api.v1/write"]
        admin = ["scanalyze.api.v1/read", "scanalyze.api.v1/admin"]
      }
    })
  }

  expect_failures = [var.identity_control_plane_contract]
}

run "rejects_claim_name_drift" {
  command = plan

  variables {
    identity_control_plane_contract = merge(var.identity_control_plane_contract, {
      customer_claim_name = "custom:tenantId"
    })
  }

  expect_failures = [var.identity_control_plane_contract]
}

run "rejects_policy_digest_drift" {
  command = plan

  variables {
    identity_control_plane_contract = merge(var.identity_control_plane_contract, {
      policy_digest = "sha256:4444444444444444444444444444444444444444444444444444444444444444"
    })
  }

  expect_failures = [var.identity_control_plane_contract]
}

run "rejects_authorization_schema_drift" {
  command = plan

  variables {
    identity_control_plane_contract = merge(var.identity_control_plane_contract, {
      authz_schema_version = "enterprise-authorization.v2"
    })
  }

  expect_failures = [var.identity_control_plane_contract]
}

run "rejects_untrusted_contract_digest" {
  command = plan

  variables {
    expected_identity_control_plane_contract_digest = "sha256:9999999999999999999999999999999999999999999999999999999999999999"
  }

  expect_failures = [terraform_data.identity_contract_gate]
}
