terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }

  # Backend S3 is NOT active yet — see backend.example.hcl
  # Activate only after PM approval for remote state.
  # backend "s3" {}
}

provider "aws" {
  region = var.region

  default_tags {
    tags = {
      deployment_id = var.deployment_id
      managed_by    = "terraform"
      layer         = "cicd"
    }
  }
}
