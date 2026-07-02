terraform {
  required_version = ">= 1.14.6, < 1.15.0"

  # Backend is rendered by orchestrator from deployment record.
  # See backend.example.hcl for the expected format.

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.80"
    }
  }
}
