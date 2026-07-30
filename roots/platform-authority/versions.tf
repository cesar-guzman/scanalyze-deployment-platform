terraform {
  required_version = ">= 1.14.6, < 1.15.0"

  backend "s3" {}

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.80"
    }
  }
}

provider "aws" {
  region              = var.authority_region
  allowed_account_ids = [var.authority_account_id]
}
