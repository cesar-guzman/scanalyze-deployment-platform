terraform {
  required_version = ">= 1.14.6, < 1.15.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.80"
    }
  }

  # Configuration is rendered from the authorized registry binding.
  backend "s3" {}
}

provider "aws" {
  region              = var.region
  allowed_account_ids = [var.account_id]

  default_tags {
    tags = {
      deployment_id = var.deployment_id
      managed_by    = "terraform"
      layer         = "cicd"
    }
  }
}
