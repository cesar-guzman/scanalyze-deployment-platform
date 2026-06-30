# Network layer — VPC, Subnets, NAT, VPC Endpoints
#
# Status: authored_not_provider_validated
#
# Uses availability_zone_id (not AZ name) for multi-account portability.

resource "aws_vpc" "main" {
  cidr_block           = var.vpc_cidr
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name          = "${var.deployment_id}-vpc"
    deployment_id = var.deployment_id
    managed_by    = "terraform"
    layer         = "network"
  }
}

resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id

  tags = {
    Name          = "${var.deployment_id}-igw"
    deployment_id = var.deployment_id
    managed_by    = "terraform"
  }
}

# ── Private Subnets (workload) ──

resource "aws_subnet" "private" {
  for_each = var.private_subnet_cidrs

  vpc_id               = aws_vpc.main.id
  cidr_block           = each.value
  availability_zone_id = each.key

  tags = {
    Name          = "${var.deployment_id}-private-${each.key}"
    deployment_id = var.deployment_id
    managed_by    = "terraform"
    tier          = "private"
  }
}

# ── Public Subnets (NAT gateways, ALB) ──

resource "aws_subnet" "public" {
  for_each = var.public_subnet_cidrs

  vpc_id                  = aws_vpc.main.id
  cidr_block              = each.value
  availability_zone_id    = each.key
  map_public_ip_on_launch = false

  tags = {
    Name          = "${var.deployment_id}-public-${each.key}"
    deployment_id = var.deployment_id
    managed_by    = "terraform"
    tier          = "public"
  }
}

# ── NAT Gateways ──

resource "aws_eip" "nat" {
  for_each = var.public_subnet_cidrs

  domain = "vpc"

  tags = {
    Name          = "${var.deployment_id}-nat-eip-${each.key}"
    deployment_id = var.deployment_id
    managed_by    = "terraform"
  }
}

resource "aws_nat_gateway" "main" {
  for_each = var.public_subnet_cidrs

  allocation_id = aws_eip.nat[each.key].id
  subnet_id     = aws_subnet.public[each.key].id

  tags = {
    Name          = "${var.deployment_id}-nat-${each.key}"
    deployment_id = var.deployment_id
    managed_by    = "terraform"
  }

  depends_on = [aws_internet_gateway.main]
}

# ── Route Tables ──

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.main.id
  }

  tags = {
    Name          = "${var.deployment_id}-rt-public"
    deployment_id = var.deployment_id
    managed_by    = "terraform"
  }
}

resource "aws_route_table_association" "public" {
  for_each = aws_subnet.public

  subnet_id      = each.value.id
  route_table_id = aws_route_table.public.id
}

resource "aws_route_table" "private" {
  for_each = var.private_subnet_cidrs

  vpc_id = aws_vpc.main.id

  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.main[each.key].id
  }

  tags = {
    Name          = "${var.deployment_id}-rt-private-${each.key}"
    deployment_id = var.deployment_id
    managed_by    = "terraform"
  }
}

resource "aws_route_table_association" "private" {
  for_each = aws_subnet.private

  subnet_id      = each.value.id
  route_table_id = aws_route_table.private[each.key].id
}
