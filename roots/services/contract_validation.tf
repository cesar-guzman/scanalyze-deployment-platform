# Contract consumer validation for services root.
# Consumes: data-foundation/v2
# Scope: regional
# State key: {dep_id}/{region}/services/terraform.tfstate
#
# This gate runs BEFORE any resource creation.
# It validates upstream contract integrity using fail-closed preconditions.
# Uses terraform_data + precondition (ADR-006 rev3).
# NEVER uses check {} blocks (can be silently ignored).

resource "terraform_data" "contract_gate" {
  lifecycle {
    # ── Identity binding ──
    precondition {
      condition     = var.deployment_id != ""
      error_message = "deployment_id is required"
    }
    precondition {
      condition     = can(regex("^dep_[0-9A-HJKMNP-TV-Z]{26}$", var.deployment_id))
      error_message = "deployment_id format invalid"
    }
    precondition {
      condition     = can(regex("^cust_[0-9A-HJKMNP-TV-Z]{26}$", var.customer_id))
      error_message = "customer_id format invalid"
    }
    precondition {
      condition     = var.customer_id != var.deployment_id
      error_message = "customer_id and deployment_id must remain distinct"
    }
    precondition {
      condition     = can(regex("^[0-9]{12}$", var.account_id))
      error_message = "account_id must be a 12-digit AWS account ID"
    }

    # ── Release manifest binding ──
    precondition {
      condition     = can(regex("^sha256:[a-f0-9]{64}$", var.release_manifest_digest))
      error_message = "release_manifest_digest must be sha256:<64 hex chars>"
    }

    # ── Upstream contract digest ──
    precondition {
      condition     = var.upstream_contract_digest != ""
      error_message = "upstream contract digest is required — cannot proceed without verified upstream"
    }
    precondition {
      condition     = var.upstream_contract_digest == var.expected_upstream_digest
      error_message = "upstream contract digest does not match expected value — tampered or stale contract"
    }

    # ── Schema version ──
    precondition {
      condition     = var.upstream_contract_id == "data-foundation/v2"
      error_message = "services requires the exact data-foundation/v2 contract"
    }
    precondition {
      condition     = var.upstream_schema_version == "2"
      error_message = "services requires data-foundation schema version 2"
    }
    precondition {
      condition     = contains(var.accepted_schema_versions, var.upstream_schema_version)
      error_message = "upstream contract schema version is not accepted by this consumer"
    }

    # ── Identity control-plane contract ──
    precondition {
      condition = (
        var.identity_control_plane_contract.contract_id == "identity-control-plane/v1" &&
        var.identity_control_plane_contract.contract_digest ==
        var.expected_identity_control_plane_contract_digest
      )
      error_message = "services requires the exact trusted identity-control-plane/v1 contract"
    }
    precondition {
      condition = (
        var.identity_control_plane_contract.customer_id == var.customer_id &&
        var.identity_control_plane_contract.deployment_id == var.deployment_id &&
        var.identity_control_plane_contract.account_id == var.account_id &&
        var.identity_control_plane_contract.region == var.region
      )
      error_message = "identity control-plane binding must match customer, deployment, account, and region exactly"
    }
    precondition {
      condition = (
        var.identity_control_plane_contract.allowed_token_uses == tolist(["access"]) &&
        var.identity_control_plane_contract.resource_server_identifier == "scanalyze.api.v1" &&
        var.identity_control_plane_contract.action_scopes.read == "scanalyze.api.v1/read" &&
        var.identity_control_plane_contract.action_scopes.write == "scanalyze.api.v1/write" &&
        var.identity_control_plane_contract.action_scopes.admin == "scanalyze.api.v1/admin" &&
        var.identity_control_plane_contract.action_scope_sets.read == tolist(["scanalyze.api.v1/read"]) &&
        var.identity_control_plane_contract.action_scope_sets.write == tolist(["scanalyze.api.v1/write"]) &&
        var.identity_control_plane_contract.action_scope_sets.admin == tolist(["scanalyze.api.v1/admin"]) &&
        var.identity_control_plane_contract.customer_claim_name == "custom:customerId" &&
        var.identity_control_plane_contract.deployment_claim_name == "custom:deployment_id" &&
        !var.identity_control_plane_contract.human_runtime_provisioning_enabled &&
        !var.identity_control_plane_contract.provider_groups_authoritative &&
        !var.identity_control_plane_contract.m2m_client_secret_values_exposed
      )
      error_message = "identity control-plane authorization handoff must be access-only, canonical, and human-disabled"
    }

    precondition {
      condition = (
        var.identity_control_plane_contract.policy_version == "1.0.0" &&
        var.identity_control_plane_contract.policy_digest == "sha256:34a639992f6c2312176ac7dc12c361daa38201adea6af0c0b1765a17a14754f8" &&
        var.identity_control_plane_contract.policy_canonicalization == "rfc8785_json_canonicalization" &&
        var.identity_control_plane_contract.authz_schema_version == "enterprise-authorization.v1" &&
        var.identity_control_plane_contract.scope_catalog_version == "scanalyze.api.v1" &&
        var.identity_control_plane_contract.role_catalog_version == "enterprise-roles.v1" &&
        var.identity_control_plane_contract.human_role_groups == tolist(["customer_admin", "document_operator", "document_reviewer", "auditor"]) &&
        var.identity_control_plane_contract.pre_token_generation_version == "V2_0" &&
        var.identity_control_plane_contract.m2m_runtime_provisioning_enabled
      )
      error_message = "identity control-plane policy, role, scope, or trigger versions are not the reviewed v1 values"
    }

    precondition {
      condition = (
        var.identity_control_plane_contract.cognito_user_pool_arn == "arn:${var.identity_control_plane_contract.aws_partition}:cognito-idp:${var.region}:${var.account_id}:userpool/${var.identity_control_plane_contract.cognito_user_pool_id}" &&
        var.identity_control_plane_contract.cognito_issuer_url == "https://cognito-idp.${var.region}.${var.identity_control_plane_contract.aws_partition == "aws-cn" ? "amazonaws.com.cn" : "amazonaws.com"}/${var.identity_control_plane_contract.cognito_user_pool_id}" &&
        length(distinct(concat(
          [var.identity_control_plane_contract.cognito_spa_client_id],
          var.identity_control_plane_contract.m2m_client_ids,
        ))) == 1 + length(var.identity_control_plane_contract.m2m_client_ids)
      )
      error_message = "identity control-plane provider IDs, ARN, issuer, and audience set must remain exact and unique"
    }

    precondition {
      condition = (
        length(var.identity_control_plane_contract.m2m_client_ids) == length(distinct(var.identity_control_plane_contract.m2m_client_ids)) &&
        length(var.identity_control_plane_contract.m2m_bindings) == length(distinct([
          for binding in var.identity_control_plane_contract.m2m_bindings : binding.client_id
        ])) &&
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
          binding.deployment_id == var.deployment_id &&
          length(binding.required_scopes) > 0 &&
          length(binding.required_scopes) == length(distinct(binding.required_scopes)) &&
          alltrue([
            for scope in binding.required_scopes : contains(values(var.identity_control_plane_contract.action_scopes), scope)
          ])
        ])
      )
      error_message = "M2M client IDs and reviewed deployment-bound bindings must match one-for-one with canonical scopes"
    }
  }
}
