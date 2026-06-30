# Base security groups
#
# Status: authored_not_provider_validated

resource "aws_security_group" "vpc_endpoints" {
  name_prefix = "${var.deployment_id}-vpce-"
  description = "Security group for VPC interface endpoints"
  vpc_id      = aws_vpc.main.id

  ingress {
    description = "HTTPS from VPC"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
  }

  tags = {
    Name          = "${var.deployment_id}-sg-vpce"
    deployment_id = var.deployment_id
    managed_by    = "terraform"
  }
}
