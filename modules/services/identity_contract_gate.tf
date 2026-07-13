resource "terraform_data" "identity_contract_gate" {
  input = {
    contract_id     = var.identity_control_plane_contract.contract_id
    contract_digest = var.identity_control_plane_contract.contract_digest
  }

  lifecycle {
    precondition {
      condition = (
        var.identity_control_plane_contract.customer_id == var.customer_id &&
        var.identity_control_plane_contract.deployment_id == var.deployment_id &&
        var.identity_control_plane_contract.account_id == var.account_id &&
        var.identity_control_plane_contract.region == var.region
      )
      error_message = "identity control-plane customer/deployment/account/region binding mismatch"
    }

    precondition {
      condition = (
        var.identity_control_plane_contract.contract_digest ==
        var.expected_identity_control_plane_contract_digest
      )
      error_message = "identity control-plane contract digest is stale or untrusted"
    }

    precondition {
      condition = (
        var.identity_control_plane_contract.authz_schema_version == "enterprise-authorization.v1" &&
        var.identity_control_plane_contract.role_catalog_version == "enterprise-roles.v1" &&
        var.identity_control_plane_contract.scope_catalog_version == "scanalyze.api.v1" &&
        var.identity_control_plane_contract.policy_version == "1.0.0" &&
        var.identity_control_plane_contract.policy_digest == "sha256:34a639992f6c2312176ac7dc12c361daa38201adea6af0c0b1765a17a14754f8" &&
        var.identity_control_plane_contract.policy_canonicalization == "rfc8785_json_canonicalization"
      )
      error_message = "identity control-plane authorization versions or policy digest are invalid"
    }

    precondition {
      condition = (
        can(regex("^[a-z]{2}(-gov)?-[a-z]+-[0-9]+_[A-Za-z0-9]+$", var.identity_control_plane_contract.cognito_user_pool_id)) &&
        can(regex("^[A-Za-z0-9]{1,128}$", var.identity_control_plane_contract.cognito_spa_client_id)) &&
        length(distinct(concat(
          [var.identity_control_plane_contract.cognito_spa_client_id],
          var.identity_control_plane_contract.m2m_client_ids,
        ))) == 1 + length(var.identity_control_plane_contract.m2m_client_ids)
      )
      error_message = "identity control-plane provider identifiers must be non-empty and unique"
    }

    precondition {
      condition = (
        length(var.identity_control_plane_contract.m2m_client_ids) == length(var.identity_control_plane_contract.m2m_bindings) &&
        length(setsubtract(
          toset(var.identity_control_plane_contract.m2m_client_ids),
          toset([for binding in var.identity_control_plane_contract.m2m_bindings : binding.client_id]),
        )) == 0 &&
        length(setsubtract(
          toset([for binding in var.identity_control_plane_contract.m2m_bindings : binding.client_id]),
          toset(var.identity_control_plane_contract.m2m_client_ids),
        )) == 0 &&
        alltrue([
          for binding in var.identity_control_plane_contract.m2m_bindings :
          binding.customer_id == var.customer_id &&
          binding.deployment_id == var.deployment_id
        ])
      )
      error_message = "identity control-plane M2M clients must map one-for-one to deployment-bound reviewed bindings"
    }
  }
}
