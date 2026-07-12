# Services — ECS Service and Task Definitions
#
# Status: authored_not_provider_validated
#
# OWNERSHIP RULES (enforced by lint_services_ownership.py):
# - Terraform is the sole owner of task definitions
# - All images MUST use @sha256 digest references
# - SCANALYZE_DEPLOYMENT_CUSTOMER_ID is required as env var
# - No imagedefinitions.json pipeline mutation
# - No register-task-definition CLI calls
# - No ignore_changes on task_definition
# - No SCANALYZE_TENANT as canonical identity
# - No custom:tenantId as authoritative claim

resource "aws_ecs_task_definition" "service" {
  for_each = { for svc in var.service_definitions : svc.name => svc }

  family                   = "${var.deployment_id}-${each.key}"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = each.value.cpu
  memory                   = each.value.memory
  execution_role_arn       = var.ecs_task_execution_role_arn
  task_role_arn            = var.workload_role_arns[each.key]

  container_definitions = jsonencode([
    {
      name = each.key
      # Image MUST use @sha256 digest — enforced by schema + lint
      image     = each.value.image
      essential = true

      portMappings = each.value.port != null ? [
        {
          containerPort = each.value.port
          protocol      = "tcp"
        }
      ] : []

      environment = concat(
        [
          {
            name  = "SCANALYZE_DEPLOYMENT_CUSTOMER_ID"
            value = var.customer_id
          },
          {
            name  = "SCANALYZE_DEPLOYMENT_ID"
            value = var.deployment_id
          },
          {
            name  = "AWS_REGION"
            value = var.region
          },
          {
            name  = "RELEASE_VERSION"
            value = var.release_version
          },
        ],
        each.value.extra_environment
      )

      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = "/ecs/${var.deployment_id}/${each.key}"
          "awslogs-region"        = var.region
          "awslogs-stream-prefix" = "ecs"
        }
      }
    }
  ])

  tags = {
    deployment_id = var.deployment_id
    managed_by    = "terraform"
    layer         = "services"
    service       = each.key
  }
}

resource "aws_ecs_service" "service" {
  for_each = { for svc in var.service_definitions : svc.name => svc }

  name            = "${var.deployment_id}-${each.key}"
  cluster         = var.ecs_cluster_arn
  task_definition = aws_ecs_task_definition.service[each.key].arn
  desired_count   = each.value.desired_count
  launch_type     = "FARGATE"

  network_configuration {
    subnets          = values(var.private_subnet_ids)
    security_groups  = [aws_security_group.service[each.key].id]
    assign_public_ip = false
  }

  dynamic "load_balancer" {
    for_each = each.value.port != null ? [1] : []
    content {
      target_group_arn = aws_lb_target_group.service[each.key].arn
      container_name   = each.key
      container_port   = each.value.port
    }
  }

  deployment_circuit_breaker {
    enable   = true
    rollback = true
  }

  tags = {
    deployment_id = var.deployment_id
    managed_by    = "terraform"
    layer         = "services"
    service       = each.key
  }
}

resource "aws_lb_target_group" "service" {
  for_each = { for svc in var.service_definitions : svc.name => svc if svc.port != null }

  name        = "${substr(var.deployment_id, 0, 16)}-${substr(each.key, 0, 16)}"
  port        = each.value.port
  protocol    = "HTTP"
  vpc_id      = var.vpc_id
  target_type = "ip"

  health_check {
    path                = each.value.health_check_path
    healthy_threshold   = 2
    unhealthy_threshold = 3
    interval            = 30
    timeout             = 5
  }

  tags = {
    deployment_id = var.deployment_id
    managed_by    = "terraform"
    layer         = "services"
    service       = each.key
  }
}

resource "aws_security_group" "service" {
  for_each = { for svc in var.service_definitions : svc.name => svc }

  name_prefix = "${var.deployment_id}-${each.key}-"
  description = "Security group for ${each.key} ECS service"
  vpc_id      = var.vpc_id

  ingress {
    description     = "From ALB"
    from_port       = each.value.port != null ? each.value.port : 0
    to_port         = each.value.port != null ? each.value.port : 0
    protocol        = each.value.port != null ? "tcp" : "-1"
    security_groups = each.value.port != null ? [var.alb_security_group_id] : []
  }

  egress {
    description = "All outbound"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name          = "${var.deployment_id}-${each.key}-sg"
    deployment_id = var.deployment_id
    managed_by    = "terraform"
    service       = each.key
  }
}
