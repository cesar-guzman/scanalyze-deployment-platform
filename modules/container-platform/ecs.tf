# Container Platform — ECS Cluster
#
# Status: authored_not_provider_validated

resource "aws_ecs_cluster" "main" {
  name = "${var.deployment_id}-cluster"

  setting {
    name  = "containerInsights"
    value = "enabled"
  }

  tags = {
    deployment_id = var.deployment_id
    managed_by    = "terraform"
    layer         = "platform"
  }
}

resource "aws_ecs_cluster_capacity_providers" "main" {
  cluster_name = aws_ecs_cluster.main.name

  capacity_providers = ["FARGATE", "FARGATE_SPOT"]

  default_capacity_provider_strategy {
    base              = 1
    weight            = 1
    capacity_provider = "FARGATE"
  }
}
