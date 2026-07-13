terraform {
  required_version = ">= 1.14.6, < 1.15.0"

  # The orchestrator renders the remote backend from the immutable deployment
  # record. Credentials and account selection are never accepted as inputs.
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.80"
    }
  }
}
