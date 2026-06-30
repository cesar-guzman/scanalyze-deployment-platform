# VPC Endpoints — private connectivity to AWS services
#
# Status: authored_not_provider_validated

# ── Gateway Endpoints (free) ──

resource "aws_vpc_endpoint" "s3" {
  vpc_id       = aws_vpc.main.id
  service_name = "com.amazonaws.${var.region}.s3"

  route_table_ids = concat(
    [aws_route_table.public.id],
    [for rt in aws_route_table.private : rt.id]
  )

  tags = {
    Name          = "${var.deployment_id}-vpce-s3"
    deployment_id = var.deployment_id
    managed_by    = "terraform"
  }
}

resource "aws_vpc_endpoint" "dynamodb" {
  vpc_id       = aws_vpc.main.id
  service_name = "com.amazonaws.${var.region}.dynamodb"

  route_table_ids = [for rt in aws_route_table.private : rt.id]

  tags = {
    Name          = "${var.deployment_id}-vpce-dynamodb"
    deployment_id = var.deployment_id
    managed_by    = "terraform"
  }
}

# ── Interface Endpoints ──

resource "aws_vpc_endpoint" "interface" {
  for_each = toset(var.vpc_endpoint_services)

  vpc_id              = aws_vpc.main.id
  service_name        = "com.amazonaws.${var.region}.${each.key}"
  vpc_endpoint_type   = "Interface"
  private_dns_enabled = true

  subnet_ids         = [for s in aws_subnet.private : s.id]
  security_group_ids = [aws_security_group.vpc_endpoints.id]

  tags = {
    Name          = "${var.deployment_id}-vpce-${each.key}"
    deployment_id = var.deployment_id
    managed_by    = "terraform"
  }
}
