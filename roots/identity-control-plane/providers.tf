provider "aws" {
  region              = var.region
  allowed_account_ids = [var.account_id]

  skip_credentials_validation = true
  skip_metadata_api_check     = true
  skip_requesting_account_id  = false

  default_tags {
    tags = {
      customer_id   = var.customer_id
      deployment_id = var.deployment_id
      managed_by    = "terraform"
      platform      = "scanalyze"
      layer         = "identity-control-plane"
    }
  }
}
