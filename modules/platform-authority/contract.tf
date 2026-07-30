resource "terraform_data" "contract" {
  input = {
    authority_account_id = var.authority_account_id
    authority_region     = var.authority_region
    deployment_ids       = sort(keys(var.deployments))
  }

  lifecycle {
    precondition {
      condition = alltrue([
        for deployment_key, deployment in var.deployments :
        deployment_key == deployment.deployment_id
      ])
      error_message = "each deployments map key must equal its canonical deployment_id."
    }

    precondition {
      condition = alltrue([
        for deployment in values(var.deployments) :
        var.authority_account_id != deployment.destination_account_id
      ])
      error_message = "platform authority must be separate from every customer destination account."
    }

    precondition {
      condition = length(distinct([
        for deployment in values(var.deployments) :
        "${deployment.customer_id}|${deployment.deployment_id}|${deployment.destination_account_id}|${deployment.region}"
      ])) == length(var.deployments)
      error_message = "customer, deployment, account, and region bindings must be unique."
    }

    precondition {
      condition = length(distinct([
        for deployment in values(var.deployments) : deployment.github_oidc_subject
      ])) == length(var.deployments)
      error_message = "each deployment must use a dedicated GitHub environment subject."
    }
  }
}

output "contract_payload" {
  description = "Portable platform-authority contract without credentials or customer data."
  value = {
    contract_id              = "platform-authority/v1"
    schema_version           = "1"
    authority_account_id     = var.authority_account_id
    authority_region         = var.authority_region
    release_bucket_name      = var.release_bucket_name
    kms_key_arn              = aws_kms_key.control_plane.arn
    github_oidc_provider_arn = aws_iam_openid_connect_provider.github.arn
    registry_table_name      = aws_dynamodb_table.deployment_registry.name
    ledger_table_name        = aws_dynamodb_table.execution_ledger.name
    orchestrator_roles       = local.orchestrator_role_bindings
  }
}
