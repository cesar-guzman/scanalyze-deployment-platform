# Container Platform — Internal ALB
#
# Status: authored_not_provider_validated

resource "aws_lb" "internal" {
  name               = "${var.deployment_id}-alb"
  internal           = true
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb.id]
  subnets            = values(var.private_subnet_ids)

  enable_deletion_protection = true

  tags = {
    deployment_id = var.deployment_id
    managed_by    = "terraform"
    layer         = "platform"
  }
}

resource "aws_lb_listener" "https" {
  load_balancer_arn = aws_lb.internal.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  certificate_arn   = var.internal_certificate_arn

  default_action {
    type = "fixed-response"
    fixed_response {
      content_type = "application/json"
      message_body = "{\"error\":\"no_route\"}"
      status_code  = "404"
    }
  }

  tags = {
    deployment_id = var.deployment_id
    managed_by    = "terraform"
  }
}

resource "aws_security_group" "alb" {
  name_prefix = "${var.deployment_id}-alb-"
  description = "Security group for internal ALB"
  vpc_id      = var.vpc_id

  ingress {
    description = "HTTPS from VPC"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr_block]
  }

  egress {
    description = "All outbound"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name          = "${var.deployment_id}-sg-alb"
    deployment_id = var.deployment_id
    managed_by    = "terraform"
  }
}
