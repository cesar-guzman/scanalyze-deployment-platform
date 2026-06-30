variable "deployment_id" {
  type        = string
  description = "Unique deployment identifier"
}

variable "account_id" {
  type        = string
  description = "AWS account ID"
}

variable "region" {
  type        = string
  description = "AWS region"
}

variable "release_version" {
  type        = string
  description = "Release version being deployed"
}

variable "release_manifest_digest" {
  type        = string
  description = "SHA-256 digest of the release manifest"
}

variable "vpc_cidr" {
  type        = string
  description = "CIDR block for the VPC"
  default     = "10.0.0.0/16"
}

variable "private_subnet_cidrs" {
  type        = map(string)
  description = "Map of AZ ID to CIDR for private subnets"
  default = {
    "use1-az1" = "10.0.1.0/24"
    "use1-az2" = "10.0.2.0/24"
  }
}

variable "public_subnet_cidrs" {
  type        = map(string)
  description = "Map of AZ ID to CIDR for public subnets"
  default = {
    "use1-az1" = "10.0.101.0/24"
    "use1-az2" = "10.0.102.0/24"
  }
}

variable "vpc_endpoint_services" {
  type        = list(string)
  description = "List of AWS services for VPC interface endpoints"
  default = [
    "ecr.api",
    "ecr.dkr",
    "logs",
    "sqs",
    "secretsmanager",
    "ssm",
  ]
}

# Upstream contract from global layer
variable "upstream_contract_digest" {
  type        = string
  description = "SHA-256 digest of upstream global contract"
}

variable "expected_upstream_digest" {
  type        = string
  description = "Expected upstream contract digest"
}
