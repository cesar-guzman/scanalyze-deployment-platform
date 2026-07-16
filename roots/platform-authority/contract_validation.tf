resource "terraform_data" "root_contract" {
  input = {
    authority_account_id = var.authority_account_id
    authority_region     = var.authority_region
    deployments          = sort(keys(var.deployments))
  }

  lifecycle {
    precondition {
      condition = alltrue([
        for deployment_key, deployment in var.deployments :
        deployment_key == deployment.deployment_id &&
        var.authority_account_id != deployment.destination_account_id
      ])
      error_message = "authority and destination bindings are missing, mismatched, or not isolated."
    }
  }
}
