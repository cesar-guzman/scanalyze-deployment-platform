resource "terraform_data" "contract_gate" {
  input = {
    customer_id                      = var.customer_id
    deployment_id                    = var.deployment_id
    account_id                       = var.account_id
    region                           = var.region
    release_version                  = var.release_version
    release_manifest_digest          = var.release_manifest_digest
    global_contract_digest           = var.global_contract.contract_digest
    release_manifest_contract_digest = var.release_manifest_contract.contract_digest
    m2m_registry_contract_digest     = var.m2m_registry_contract.contract_digest
    policy_digest                    = var.policy_digest
  }

  lifecycle {
    precondition {
      condition = (
        var.global_contract.contract_id == "global/v1" &&
        var.global_contract.schema_version == "1"
      )
      error_message = "identity-control-plane requires the exact global/v1 schema version 1 contract."
    }

    precondition {
      condition = (
        var.global_contract.customer_id == var.customer_id &&
        var.global_contract.deployment_id == var.deployment_id &&
        var.global_contract.account_id == var.account_id
      )
      error_message = "global/v1 customer, deployment, and account tuple must exactly match the requested deployment."
    }

    precondition {
      condition = (
        startswith(
          var.global_contract.identity_runtime_permissions_boundary_arn,
          "arn:${var.aws_partition}:iam::${var.account_id}:policy/"
        ) &&
        !strcontains(var.global_contract.identity_runtime_permissions_boundary_arn, "*")
      )
      error_message = "global/v1 must supply an exact same-account identity runtime permissions boundary ARN."
    }

    precondition {
      condition = (
        can(regex("^sha256:[0-9a-f]{64}$", var.global_contract.contract_digest)) &&
        var.global_contract.contract_digest == var.expected_global_contract_digest
      )
      error_message = "global/v1 contract digest is missing, malformed, stale, or unexpected."
    }

    precondition {
      condition = (
        var.release_manifest_contract.contract_id == "release-manifest/v1" &&
        var.release_manifest_contract.schema_version == "1"
      )
      error_message = "identity-control-plane requires the exact release-manifest/v1 schema version 1 contract."
    }

    precondition {
      condition = (
        var.release_manifest_contract.customer_id == var.customer_id &&
        var.release_manifest_contract.deployment_id == var.deployment_id &&
        var.release_manifest_contract.account_id == var.account_id &&
        var.release_manifest_contract.region == var.region &&
        var.release_manifest_contract.release_version == var.release_version &&
        var.release_manifest_contract.manifest_digest == var.release_manifest_digest
      )
      error_message = "release-manifest/v1 identity, region, version, and manifest digest must exactly match the requested deployment."
    }

    precondition {
      condition = (
        can(regex("^sha256:[0-9a-f]{64}$", var.release_manifest_contract.contract_digest)) &&
        var.release_manifest_contract.contract_digest == var.expected_release_manifest_contract_digest
      )
      error_message = "release-manifest/v1 contract digest is missing, malformed, stale, or unexpected."
    }

    precondition {
      condition = (
        can(regex("^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$", var.release_manifest_contract.pre_token_artifact.bucket)) &&
        !strcontains(var.release_manifest_contract.pre_token_artifact.bucket, "..") &&
        !strcontains(var.release_manifest_contract.pre_token_artifact.bucket, ".-") &&
        !strcontains(var.release_manifest_contract.pre_token_artifact.bucket, "-.") &&
        !startswith(var.release_manifest_contract.pre_token_artifact.bucket, "xn--") &&
        !startswith(var.release_manifest_contract.pre_token_artifact.bucket, "sthree-") &&
        !startswith(var.release_manifest_contract.pre_token_artifact.bucket, "amzn_s3_demo_") &&
        !endswith(var.release_manifest_contract.pre_token_artifact.bucket, "-s3alias") &&
        !endswith(var.release_manifest_contract.pre_token_artifact.bucket, "--ol-s3") &&
        !endswith(var.release_manifest_contract.pre_token_artifact.bucket, ".mrap") &&
        !endswith(var.release_manifest_contract.pre_token_artifact.bucket, "--x-s3") &&
        !endswith(var.release_manifest_contract.pre_token_artifact.bucket, "--table-s3") &&
        !can(regex("^[0-9]+([.][0-9]+){3}$", var.release_manifest_contract.pre_token_artifact.bucket)) &&
        can(regex("(^|/)sha256[-/:][0-9a-f]{64}([./_-]|$)", var.release_manifest_contract.pre_token_artifact.key)) &&
        can(regex("^[-A-Za-z0-9._~+/=]+$", var.release_manifest_contract.pre_token_artifact.object_version)) &&
        length(var.release_manifest_contract.pre_token_artifact.object_version) <= 1024 &&
        lower(var.release_manifest_contract.pre_token_artifact.object_version) != "null" &&
        can(base64decode(var.release_manifest_contract.pre_token_artifact.sha256_b64)) &&
        length(base64decode(var.release_manifest_contract.pre_token_artifact.sha256_b64)) == 32
      )
      error_message = "the pre-token artifact must use an immutable bucket/key/version locator and an exact SHA-256 digest."
    }

    precondition {
      condition = (
        can(regex("^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$", var.release_manifest_contract.control_processor_artifact.bucket)) &&
        !strcontains(var.release_manifest_contract.control_processor_artifact.bucket, "..") &&
        !strcontains(var.release_manifest_contract.control_processor_artifact.bucket, ".-") &&
        !strcontains(var.release_manifest_contract.control_processor_artifact.bucket, "-.") &&
        !startswith(var.release_manifest_contract.control_processor_artifact.bucket, "xn--") &&
        !startswith(var.release_manifest_contract.control_processor_artifact.bucket, "sthree-") &&
        !startswith(var.release_manifest_contract.control_processor_artifact.bucket, "amzn_s3_demo_") &&
        !endswith(var.release_manifest_contract.control_processor_artifact.bucket, "-s3alias") &&
        !endswith(var.release_manifest_contract.control_processor_artifact.bucket, "--ol-s3") &&
        !endswith(var.release_manifest_contract.control_processor_artifact.bucket, ".mrap") &&
        !endswith(var.release_manifest_contract.control_processor_artifact.bucket, "--x-s3") &&
        !endswith(var.release_manifest_contract.control_processor_artifact.bucket, "--table-s3") &&
        !can(regex("^[0-9]+([.][0-9]+){3}$", var.release_manifest_contract.control_processor_artifact.bucket)) &&
        can(regex("(^|/)sha256[-/:][0-9a-f]{64}([./_-]|$)", var.release_manifest_contract.control_processor_artifact.key)) &&
        can(regex("^[-A-Za-z0-9._~+/=]+$", var.release_manifest_contract.control_processor_artifact.object_version)) &&
        length(var.release_manifest_contract.control_processor_artifact.object_version) <= 1024 &&
        lower(var.release_manifest_contract.control_processor_artifact.object_version) != "null" &&
        can(base64decode(var.release_manifest_contract.control_processor_artifact.sha256_b64)) &&
        length(base64decode(var.release_manifest_contract.control_processor_artifact.sha256_b64)) == 32
      )
      error_message = "the control-processor artifact must use an immutable bucket/key/version locator and an exact SHA-256 digest."
    }

    precondition {
      condition = (
        var.m2m_registry_contract.contract_id == "identity-contract/v2" &&
        var.m2m_registry_contract.schema_version == "2" &&
        var.m2m_registry_contract.customer_id == var.customer_id &&
        var.m2m_registry_contract.deployment_id == var.deployment_id
      )
      error_message = "M2M registry must be the exact identity-contract/v2 projection for this customer and deployment."
    }

    precondition {
      condition = (
        can(regex("^sha256:[0-9a-f]{64}$", var.m2m_registry_contract.contract_digest)) &&
        var.m2m_registry_contract.contract_digest == var.expected_m2m_registry_contract_digest
      )
      error_message = "identity-contract/v2 registry digest is missing, malformed, stale, or unexpected."
    }

    precondition {
      condition = var.m2m_registry_contract.action_scope_sets == {
        read  = ["scanalyze.api.v1/read"]
        write = ["scanalyze.api.v1/write"]
        admin = ["scanalyze.api.v1/admin"]
      }
      error_message = "identity-contract/v2 registry must use the exact canonical action scope sets."
    }

    precondition {
      condition = (
        length(distinct([for binding in var.m2m_registry_contract.m2m_bindings : binding.client_id])) == length(var.m2m_registry_contract.m2m_bindings) &&
        alltrue([
          for binding in var.m2m_registry_contract.m2m_bindings :
          trimspace(binding.client_id) != "" &&
          binding.customer_id == var.customer_id &&
          binding.deployment_id == var.deployment_id &&
          length(binding.required_scopes) > 0 &&
          length(distinct(binding.required_scopes)) == length(binding.required_scopes) &&
          length(setsubtract(toset(binding.required_scopes), toset([
            "scanalyze.api.v1/read",
            "scanalyze.api.v1/write",
            "scanalyze.api.v1/admin",
          ]))) == 0
        ])
      )
      error_message = "every promoted M2M client must be unique and exactly bound to this customer, deployment, and canonical scopes."
    }
  }
}
