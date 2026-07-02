# Provider configuration — no credentials, validate-only.
# M2 Level B: terraform validate does not require AWS credentials.
# Do NOT add assume_role, profile, access_key, secret_key, or token.

provider "aws" {
  region = var.region

  skip_credentials_validation = true
  skip_metadata_api_check     = true
  skip_requesting_account_id  = true

  default_tags {
    tags = {
      deployment_id = var.deployment_id
      managed_by    = "terraform"
      platform      = "scanalyze"
    }
  }
}

# Global edge resources (CloudFront, WAF CLOUDFRONT, ACM) require us-east-1.
provider "aws" {
  alias  = "us_east_1"
  region = "us-east-1"

  skip_credentials_validation = true
  skip_metadata_api_check     = true
  skip_requesting_account_id  = true

  default_tags {
    tags = {
      deployment_id = var.deployment_id
      managed_by    = "terraform"
      platform      = "scanalyze"
    }
  }
}
