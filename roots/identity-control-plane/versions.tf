terraform {
  required_version = ">= 1.14.6, < 1.15.0"

  # Configuration is rendered from the authorized registry binding.
  backend "s3" {}
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.80"
    }
  }
}
