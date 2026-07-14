resource "terraform_data" "contract_gate" {
  input = {
    customer_id              = var.customer_id
    deployment_id            = var.deployment_id
    account_id               = var.account_id
    region                   = var.region
    network_contract_digest  = var.network_contract.contract_digest
    platform_contract_digest = var.platform_contract.contract_digest
    services_contract_digest = var.services_contract.contract_digest
    identity_contract_digest = var.identity_contract.contract_digest
  }

  lifecycle {
    precondition {
      condition = (
        var.network_contract.contract_id == "network/v2" &&
        var.network_contract.schema_version == "2" &&
        var.network_contract.customer_id == var.customer_id &&
        var.network_contract.deployment_id == var.deployment_id &&
        var.network_contract.account_id == var.account_id &&
        var.network_contract.region == var.region &&
        var.network_contract.release_manifest_digest == var.release_manifest_digest &&
        var.network_contract.contract_digest == var.expected_network_contract_digest
      )
      error_message = "edge-identity requires the exact deployment-bound network/v2 contract."
    }

    precondition {
      condition = (
        var.platform_contract.contract_id == "platform/v2" &&
        var.platform_contract.schema_version == "2" &&
        var.platform_contract.customer_id == var.customer_id &&
        var.platform_contract.deployment_id == var.deployment_id &&
        var.platform_contract.account_id == var.account_id &&
        var.platform_contract.region == var.region &&
        var.platform_contract.release_manifest_digest == var.release_manifest_digest &&
        var.platform_contract.contract_digest == var.expected_platform_contract_digest
      )
      error_message = "edge-identity requires the exact deployment-bound platform/v2 contract."
    }

    precondition {
      condition = (
        var.services_contract.contract_id == "services/v2" &&
        var.services_contract.schema_version == "2" &&
        var.services_contract.customer_id == var.customer_id &&
        var.services_contract.deployment_id == var.deployment_id &&
        var.services_contract.account_id == var.account_id &&
        var.services_contract.region == var.region &&
        var.services_contract.release_manifest_digest == var.release_manifest_digest &&
        var.services_contract.contract_digest == var.expected_services_contract_digest
      )
      error_message = "edge-identity requires the exact deployment-bound services/v2 contract."
    }

    precondition {
      condition = (
        var.identity_contract.contract_id == "identity-control-plane/v1" &&
        var.identity_contract.schema_version == "1"
      )
      error_message = "edge-identity requires the exact identity-control-plane/v1 schema version 1 contract."
    }

    precondition {
      condition = (
        var.identity_contract.customer_id == var.customer_id &&
        var.identity_contract.deployment_id == var.deployment_id &&
        var.identity_contract.account_id == var.account_id &&
        var.identity_contract.region == var.region &&
        contains(["aws", "aws-us-gov", "aws-cn"], var.identity_contract.aws_partition)
      )
      error_message = "identity-control-plane/v1 customer, deployment, account, and region tuple must match exactly."
    }

    precondition {
      condition = (
        can(regex("^sha256:[0-9a-f]{64}$", var.identity_contract.contract_digest)) &&
        var.identity_contract.contract_digest == var.expected_identity_contract_digest
      )
      error_message = "identity-control-plane/v1 contract digest is missing, malformed, stale, or unexpected."
    }

    precondition {
      condition = (
        var.identity_contract.resource_server_identifier == "scanalyze.api.v1" &&
        var.identity_contract.allowed_token_uses == ["access"] &&
        var.identity_contract.action_scopes == {
          read  = "scanalyze.api.v1/read"
          write = "scanalyze.api.v1/write"
          admin = "scanalyze.api.v1/admin"
        } &&
        var.identity_contract.action_scope_sets == {
          read  = ["scanalyze.api.v1/read"]
          write = ["scanalyze.api.v1/write"]
          admin = ["scanalyze.api.v1/admin"]
        }
      )
      error_message = "identity-control-plane/v1 must publish the exact access-token-only canonical scope catalog."
    }

    precondition {
      condition = (
        trimspace(var.identity_contract.policy_version) != "" &&
        can(regex("^sha256:[0-9a-f]{64}$", var.identity_contract.policy_digest)) &&
        var.identity_contract.policy_canonicalization == "rfc8785_json_canonicalization"
      )
      error_message = "identity-control-plane/v1 must bind an explicit authorization policy version and digest."
    }

    precondition {
      condition = (
        !var.identity_contract.human_runtime_provisioning_enabled &&
        var.identity_contract.m2m_runtime_provisioning_enabled &&
        !var.identity_contract.m2m_client_secret_values_exposed
      )
      error_message = "human runtime authorization remains blocked until the downstream GUG-153/GUG-94 runtime enforcement package is validated."
    }

    precondition {
      condition = (
        length(distinct(var.identity_contract.m2m_client_ids)) == length(var.identity_contract.m2m_client_ids) &&
        toset(var.identity_contract.m2m_client_ids) == toset([
          for binding in var.identity_contract.m2m_bindings : binding.client_id
        ]) &&
        length(distinct([
          for binding in var.identity_contract.m2m_bindings : binding.client_id
        ])) == length(var.identity_contract.m2m_bindings) &&
        alltrue([
          for binding in var.identity_contract.m2m_bindings :
          trimspace(binding.client_id) != "" &&
          binding.customer_id == var.customer_id &&
          binding.deployment_id == var.deployment_id &&
          length(binding.required_scopes) > 0 &&
          length(distinct(binding.required_scopes)) == length(binding.required_scopes) &&
          length(setsubtract(
            toset(binding.required_scopes),
            toset(flatten(values(var.identity_contract.action_scope_sets))),
          )) == 0
        ])
      )
      error_message = "M2M audiences must have exact one-to-one verified bindings for this tuple and canonical required scopes."
    }
  }
}
