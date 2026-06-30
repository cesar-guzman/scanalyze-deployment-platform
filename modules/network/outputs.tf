# Contract-aligned outputs for network layer.
# Status: authored_not_provider_validated

output "vpc_id" {
  description = "VPC ID"
  value       = aws_vpc.main.id
}

output "private_subnet_ids" {
  description = "Map of AZ ID to private subnet ID"
  value       = { for k, v in aws_subnet.private : k => v.id }
}

output "public_subnet_ids" {
  description = "Map of AZ ID to public subnet ID"
  value       = { for k, v in aws_subnet.public : k => v.id }
}

output "vpc_cidr_block" {
  description = "VPC CIDR block"
  value       = aws_vpc.main.cidr_block
}

output "vpc_endpoint_sg_id" {
  description = "Security group ID for VPC endpoints"
  value       = aws_security_group.vpc_endpoints.id
}
