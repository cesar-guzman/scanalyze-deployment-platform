terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }

  # Remote state backend — activated after bootstrap.
  # Configure via: terraform init -backend-config=backend.tfvars
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
