# CI/CD Module — Build-Only Pipelines
#
# Status: authored_not_provider_validated
#
# OWNERSHIP RULES:
# - This module owns: CodePipeline, CodeBuild, CodeCommit, ECR, S3/KMS artifacts
# - This module does NOT own: ECS services, ECS task definitions, ECS cluster
#
# SAFETY RULES (enforced by lint_cicd_safety.py):
# - NO Provider = "ECS" deploy action in pipelines
# - NO Provider = "CodeDeployToECS" in pipelines
# - NO imagedefinitions.json consumed by Deploy stage
# - NO ecs:* in IAM policies
# - NO iam:PassRole with Resource "*"
# - NO hardcoded cluster names / CloudFront IDs / Cognito IDs
# - ALL ECR images MUST use tag immutability
# - Build output = digest in SSM, NOT imagedefinitions for ECS

data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id
  partition  = data.aws_partition.current.partition

  # Naming convention: {deployment_id}-{service_name}
  name_prefix = var.deployment_id

  artifact_bucket_name = "${var.deployment_id}-cicd-artifacts"

  microservices = {
    for name, svc in var.microservices : name => {
      service_name   = svc.service_name
      ecr_repo_name  = svc.ecr_repo_name
      container_name = coalesce(svc.container_name, svc.service_name)

      source = {
        provider       = coalesce(try(svc.source.provider, null), var.source_provider)
        repo_name      = coalesce(try(svc.source.repo_name, null), name)
        branch         = coalesce(try(svc.source.branch, null), var.default_branch)
        connection_arn = try(svc.source.connection_arn, null)
        full_repo_id   = try(svc.source.full_repo_id, null)
      }

      buildspec_path = coalesce(svc.buildspec_path, var.default_buildspec_path)
      build_env      = svc.build_env
    }
  }

  ecr_repo_names = distinct([
    for name, svc in local.microservices : svc.ecr_repo_name
  ])

  codecommit_repos = {
    for name, svc in local.microservices : name => svc.source.repo_name
    if svc.source.provider == "codecommit"
  }

  release_metadata_namespace = "/${var.deployment_id}/cicd/images"
}

# ---------------------------------------------------------------------------
# KMS — Artifact Encryption
# ---------------------------------------------------------------------------

resource "aws_kms_key" "artifacts" {
  description             = "${local.name_prefix} CI/CD artifact encryption"
  deletion_window_in_days = 7
  enable_key_rotation     = true

  tags = {
    Name  = "${local.name_prefix}-cicd-artifacts"
    layer = "cicd"
  }
}

resource "aws_kms_alias" "artifacts" {
  name          = "alias/${local.name_prefix}-cicd-artifacts"
  target_key_id = aws_kms_key.artifacts.key_id
}

# ---------------------------------------------------------------------------
# S3 — Artifact Bucket
# ---------------------------------------------------------------------------

resource "aws_s3_bucket" "artifacts" {
  bucket        = local.artifact_bucket_name
  force_destroy = false

  tags = {
    Name  = local.artifact_bucket_name
    layer = "cicd"
  }
}

resource "aws_s3_bucket_public_access_block" "artifacts" {
  bucket = aws_s3_bucket.artifacts.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "artifacts" {
  bucket = aws_s3_bucket.artifacts.id
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "artifacts" {
  bucket = aws_s3_bucket.artifacts.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.artifacts.arn
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "artifacts" {
  bucket = aws_s3_bucket.artifacts.id

  rule {
    id     = "expire-old-artifacts"
    status = "Enabled"
    expiration { days = 30 }
    noncurrent_version_expiration { noncurrent_days = 7 }
    abort_incomplete_multipart_upload { days_after_initiation = 1 }
  }
}

# ---------------------------------------------------------------------------
# ECR — Image Repositories (customer-local)
# ---------------------------------------------------------------------------

resource "aws_ecr_repository" "service" {
  for_each = toset(local.ecr_repo_names)

  name                 = "${var.deployment_id}/${each.value}"
  image_tag_mutability = "IMMUTABLE" # Enforced: no tag overwrites

  image_scanning_configuration {
    scan_on_push = true
  }

  encryption_configuration {
    encryption_type = "KMS"
    kms_key         = aws_kms_key.artifacts.arn
  }

  tags = {
    Name  = each.value
    layer = "cicd"
  }
}

resource "aws_ecr_lifecycle_policy" "service" {
  for_each   = var.enable_ecr_lifecycle_policy ? toset(local.ecr_repo_names) : toset([])
  repository = aws_ecr_repository.service[each.key].name

  policy = jsonencode({
    rules = [{
      rulePriority = 1
      description  = "Keep last ${var.ecr_lifecycle_keep_last} images"
      selection = {
        tagStatus   = "any"
        countType   = "imageCountMoreThan"
        countNumber = var.ecr_lifecycle_keep_last
      }
      action = { type = "expire" }
    }]
  })
}

# ---------------------------------------------------------------------------
# CodeCommit — Source Repositories (sandbox/transitional)
# ---------------------------------------------------------------------------

resource "aws_codecommit_repository" "service" {
  for_each = local.codecommit_repos

  repository_name = "${var.deployment_id}-${each.value}"
  description     = "Source mirror for ${each.value} (${var.deployment_id})"

  tags = {
    Name  = each.value
    layer = "cicd"
  }
}

# ---------------------------------------------------------------------------
# IAM — Build-Only Roles (NO ecs:*, NO iam:PassRole "*")
# ---------------------------------------------------------------------------

resource "aws_iam_role" "codepipeline" {
  name = "${local.name_prefix}-codepipeline-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "codepipeline.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })

  tags = { layer = "cicd" }
}

resource "aws_iam_role" "codebuild" {
  name = "${local.name_prefix}-codebuild-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "codebuild.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })

  tags = { layer = "cicd" }
}

# CodePipeline policy — Source + Build ONLY
resource "aws_iam_policy" "codepipeline" {
  name = "${local.name_prefix}-codepipeline-policy"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "ArtifactBucket"
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:GetObjectVersion",
          "s3:PutObject",
          "s3:GetBucketLocation",
          "s3:ListBucket"
        ]
        Resource = [
          aws_s3_bucket.artifacts.arn,
          "${aws_s3_bucket.artifacts.arn}/*"
        ]
      },
      {
        Sid    = "ArtifactKMS"
        Effect = "Allow"
        Action = [
          "kms:Decrypt",
          "kms:Encrypt",
          "kms:GenerateDataKey*",
          "kms:DescribeKey"
        ]
        Resource = [aws_kms_key.artifacts.arn]
      },
      {
        Sid    = "CodeBuildStart"
        Effect = "Allow"
        Action = [
          "codebuild:BatchGetBuilds",
          "codebuild:StartBuild"
        ]
        Resource = [for p in aws_codebuild_project.build : p.arn]
      },
      {
        Sid    = "CodeCommitSource"
        Effect = "Allow"
        Action = [
          "codecommit:GetBranch",
          "codecommit:GetCommit",
          "codecommit:UploadArchive",
          "codecommit:GetUploadArchiveStatus",
          "codecommit:CancelUploadArchive"
        ]
        Resource = [for r in aws_codecommit_repository.service : r.arn]
      }
      # NOTE: NO ecs:* statement
      # NOTE: NO iam:PassRole "*" statement
      # NOTE: NO codedeploy statement
    ]
  })
}

resource "aws_iam_role_policy_attachment" "codepipeline" {
  role       = aws_iam_role.codepipeline.name
  policy_arn = aws_iam_policy.codepipeline.arn
}

# CodeBuild policy — Build + Push to ECR + SSM metadata
resource "aws_iam_policy" "codebuild" {
  name = "${local.name_prefix}-codebuild-policy"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "BuildLogs"
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = [
          "arn:${local.partition}:logs:${var.region}:${local.account_id}:log-group:/aws/codebuild/${local.name_prefix}-*",
          "arn:${local.partition}:logs:${var.region}:${local.account_id}:log-group:/aws/codebuild/${local.name_prefix}-*:log-stream:*"
        ]
      },
      {
        Sid    = "ArtifactBucket"
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:GetObjectVersion",
          "s3:PutObject",
          "s3:GetBucketLocation",
          "s3:ListBucket"
        ]
        Resource = [
          aws_s3_bucket.artifacts.arn,
          "${aws_s3_bucket.artifacts.arn}/*"
        ]
      },
      {
        Sid      = "ECRAuth"
        Effect   = "Allow"
        Action   = ["ecr:GetAuthorizationToken"]
        Resource = ["*"]
      },
      {
        Sid    = "ECRPush"
        Effect = "Allow"
        Action = [
          "ecr:BatchCheckLayerAvailability",
          "ecr:BatchGetImage",
          "ecr:GetDownloadUrlForLayer",
          "ecr:InitiateLayerUpload",
          "ecr:UploadLayerPart",
          "ecr:CompleteLayerUpload",
          "ecr:PutImage",
          "ecr:DescribeImages"
        ]
        Resource = [for r in aws_ecr_repository.service : r.arn]
      },
      {
        Sid    = "ArtifactKMS"
        Effect = "Allow"
        Action = [
          "kms:Decrypt",
          "kms:Encrypt",
          "kms:GenerateDataKey*",
          "kms:DescribeKey"
        ]
        Resource = [aws_kms_key.artifacts.arn]
      },
      {
        Sid    = "ReleaseMetadataSSM"
        Effect = "Allow"
        Action = [
          "ssm:PutParameter",
          "ssm:AddTagsToResource"
        ]
        Resource = [
          "arn:${local.partition}:ssm:${var.region}:${local.account_id}:parameter${local.release_metadata_namespace}/*"
        ]
      }
      # NOTE: NO ecs:* — CodeBuild only builds, it does not deploy
      # NOTE: NO cloudfront:CreateInvalidation — frontend deploy is separate
    ]
  })
}

resource "aws_iam_role_policy_attachment" "codebuild" {
  role       = aws_iam_role.codebuild.name
  policy_arn = aws_iam_policy.codebuild.arn
}

# ---------------------------------------------------------------------------
# CodeBuild — Build Projects
# ---------------------------------------------------------------------------

resource "aws_cloudwatch_log_group" "codebuild" {
  for_each          = local.microservices
  name              = "/aws/codebuild/${local.name_prefix}-${each.key}"
  retention_in_days = 14
  tags              = { layer = "cicd" }
}

resource "aws_codebuild_project" "build" {
  for_each = local.microservices

  name          = "${local.name_prefix}-${each.key}"
  description   = "Build ${each.value.service_name} for ${var.deployment_id}"
  build_timeout = 30
  service_role  = aws_iam_role.codebuild.arn

  artifacts { type = "CODEPIPELINE" }

  environment {
    compute_type    = "BUILD_GENERAL1_SMALL"
    image           = "aws/codebuild/amazonlinux2-x86_64-standard:5.0"
    type            = "LINUX_CONTAINER"
    privileged_mode = true # Required for Docker builds

    environment_variable {
      name  = "AWS_REGION"
      value = var.region
    }
    environment_variable {
      name  = "ACCOUNT_ID"
      value = local.account_id
    }
    environment_variable {
      name  = "ECR_REPO_URI"
      value = aws_ecr_repository.service[each.value.ecr_repo_name].repository_url
    }
    environment_variable {
      name  = "ECR_REPO_NAME"
      value = "${var.deployment_id}/${each.value.ecr_repo_name}"
    }
    environment_variable {
      name  = "CONTAINER_NAME"
      value = each.value.container_name
    }
    # Release metadata SSM paths
    environment_variable {
      name  = "IMAGE_TAG_SSM_PARAMETER"
      value = var.enable_release_metadata_ssm ? "${local.release_metadata_namespace}/${each.key}/image_tag" : ""
    }
    environment_variable {
      name  = "IMAGE_DIGEST_SSM_PARAMETER"
      value = var.enable_release_metadata_ssm ? "${local.release_metadata_namespace}/${each.key}/image_digest" : ""
    }

    # Custom build env vars
    dynamic "environment_variable" {
      for_each = each.value.build_env
      content {
        name  = environment_variable.key
        value = environment_variable.value
      }
    }
  }

  source {
    type      = "CODEPIPELINE"
    buildspec = each.value.buildspec_path
  }

  logs_config {
    cloudwatch_logs {
      group_name = aws_cloudwatch_log_group.codebuild[each.key].name
    }
  }

  tags = { layer = "cicd" }
}

# ---------------------------------------------------------------------------
# CodePipeline — Source + Build ONLY (NO Deploy Stage)
# ---------------------------------------------------------------------------

resource "aws_codepipeline" "this" {
  for_each = local.microservices

  name     = "${local.name_prefix}-${each.key}"
  role_arn = aws_iam_role.codepipeline.arn

  artifact_store {
    location = aws_s3_bucket.artifacts.id
    type     = "S3"
    encryption_key {
      id   = aws_kms_key.artifacts.arn
      type = "KMS"
    }
  }

  # Stage 1: Source
  stage {
    name = "Source"
    action {
      name             = "Source"
      category         = "Source"
      owner            = "AWS"
      provider         = each.value.source.provider == "codecommit" ? "CodeCommit" : "CodeStarSourceConnection"
      version          = "1"
      output_artifacts = ["source_output"]

      configuration = each.value.source.provider == "codecommit" ? {
        RepositoryName       = aws_codecommit_repository.service[each.key].repository_name
        BranchName           = each.value.source.branch
        PollForSourceChanges = "false"
      } : {
        ConnectionArn    = each.value.source.connection_arn
        FullRepositoryId = each.value.source.full_repo_id
        BranchName       = each.value.source.branch
      }
    }
  }

  # Stage 2: Build (docker build + push ECR + write digest to SSM)
  stage {
    name = "Build"
    action {
      name             = "Build"
      category         = "Build"
      owner            = "AWS"
      provider         = "CodeBuild"
      version          = "1"
      input_artifacts  = ["source_output"]
      output_artifacts = ["build_output"]

      configuration = {
        ProjectName = aws_codebuild_project.build[each.key].name
      }
    }
  }

  # NOTE: NO Deploy stage
  # Terraform services layer owns ECS task definitions and services.
  # Build output (digest) goes to SSM. Services layer consumes it.

  tags = { layer = "cicd" }
}

# ---------------------------------------------------------------------------
# Release Metadata — SSM Parameters (consumed by services layer)
# ---------------------------------------------------------------------------

resource "aws_ssm_parameter" "image_tag" {
  for_each  = var.enable_release_metadata_ssm ? local.microservices : {}
  name      = "${local.release_metadata_namespace}/${each.key}/image_tag"
  type      = "String"
  value     = "UNSET"
  overwrite = true
  tags      = { layer = "cicd" }

  lifecycle { ignore_changes = [value] }
}

resource "aws_ssm_parameter" "image_digest" {
  for_each  = var.enable_release_metadata_ssm ? local.microservices : {}
  name      = "${local.release_metadata_namespace}/${each.key}/image_digest"
  type      = "String"
  value     = "UNSET"
  overwrite = true
  tags      = { layer = "cicd" }

  lifecycle { ignore_changes = [value] }
}
