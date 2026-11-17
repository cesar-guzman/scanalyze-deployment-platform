# GUG-541 — workload identity policies.
# Hermetic provider plans only: these tests never contact AWS.
mock_provider "aws" {}

variables {
  deployment_id           = "dep_01ARZ3NDEKTSV4RRFFQ69G5FAV"
  account_id              = "000000000000"
  region                  = "us-east-1"
  release_version         = "v0.0.0-synthetic"
  release_manifest_digest = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
}

run "every_workload_role_has_one_identity_policy" {
  command = plan

  assert {
    condition     = toset(keys(aws_iam_role_policy.workload)) == toset(var.service_names)
    error_message = "each workload role must have exactly one identity policy"
  }

  assert {
    condition = alltrue([
      for service, policy in aws_iam_role_policy.workload : length(jsondecode(policy.policy).Statement) >= 4
    ])
    error_message = "every workload policy must at least read runtime parameters, use the data key, and reach its objects and table"
  }
}

run "policies_have_no_wildcard_actions_and_scoped_resources" {
  command = plan

  assert {
    condition = alltrue(flatten([
      for service, policy in aws_iam_role_policy.workload : [
        for statement in jsondecode(policy.policy).Statement : [
          for action in flatten([statement.Action]) : !strcontains(action, "*")
        ]
      ]
    ]))
    error_message = "workload policies must not use wildcard actions"
  }

  assert {
    condition = alltrue(flatten([
      for service, policy in aws_iam_role_policy.workload : [
        for statement in jsondecode(policy.policy).Statement :
        statement.Sid == "TextractTextDetection" || !contains(flatten([statement.Resource]), "*")
      ]
    ]))
    error_message = "only Textract text detection, which has no resource-level permissions, may use Resource *"
  }

  assert {
    condition = alltrue(flatten([
      for service, policy in aws_iam_role_policy.workload : [
        for statement in jsondecode(policy.policy).Statement : statement.Effect == "Allow"
      ]
    ]))
    error_message = "workload identity policies only grant; denials belong to the boundary"
  }
}

run "bedrock_is_granted_only_to_model_workers_and_only_for_approved_models" {
  command = plan

  assert {
    condition = alltrue([
      for service in ["classifier-worker", "bank-worker", "personal-worker", "gov-worker"] :
      contains([for statement in jsondecode(aws_iam_role_policy.workload[service].policy).Statement : statement.Sid], "InvokeApprovedBedrockModels")
    ])
    error_message = "the classifier and the three extractors must be able to invoke their Bedrock model"
  }

  assert {
    condition = alltrue([
      for service in ["ingest-api", "ocr-worker", "postprocess-worker"] :
      !contains([for statement in jsondecode(aws_iam_role_policy.workload[service].policy).Statement : statement.Sid], "InvokeApprovedBedrockModels")
    ])
    error_message = "services that never call Bedrock must not be able to invoke models"
  }

  assert {
    condition = toset(one([
      for statement in jsondecode(aws_iam_role_policy.workload["classifier-worker"].policy).Statement :
      statement.Resource if statement.Sid == "InvokeApprovedBedrockModels"
    ])) == toset(["arn:aws:bedrock:us-east-1::foundation-model/amazon.nova-lite-v1:0"])
    error_message = "the classifier may invoke only the approved classifier model"
  }

  assert {
    condition = alltrue([
      for service in ["bank-worker", "personal-worker", "gov-worker"] :
      toset(one([
        for statement in jsondecode(aws_iam_role_policy.workload[service].policy).Statement :
        statement.Resource if statement.Sid == "InvokeApprovedBedrockModels"
      ])) == toset([
        "arn:aws:bedrock:us-east-1:000000000000:inference-profile/us.anthropic.claude-haiku-4-5-20251001-v1:0",
        "arn:aws:bedrock:*::foundation-model/anthropic.claude-haiku-4-5-20251001-v1:0",
      ])
    ])
    error_message = "the extractors may invoke only the approved extractor model"
  }
}

run "boundary_allows_bedrock_and_textract_only_as_needed" {
  command = plan

  assert {
    condition = alltrue(flatten([
      for statement in jsondecode(aws_iam_policy.workload_permissions_boundary.policy).Statement : [
        for action in flatten([statement.Action]) : !contains(["bedrock:*", "textract:*", "cognito-idp:*"], action)
      ]
    ]))
    error_message = "the workload boundary must not allow whole Bedrock, Textract or Cognito namespaces"
  }

  assert {
    condition = toset(one([
      for statement in jsondecode(aws_iam_policy.workload_permissions_boundary.policy).Statement :
      statement.Resource if statement.Sid == "AllowApprovedBedrockModels"
      ])) == toset([
      "arn:aws:bedrock:us-east-1::foundation-model/amazon.nova-lite-v1:0",
      "arn:aws:bedrock:us-east-1:000000000000:inference-profile/us.anthropic.claude-haiku-4-5-20251001-v1:0",
      "arn:aws:bedrock:*::foundation-model/anthropic.claude-haiku-4-5-20251001-v1:0",
    ])
    error_message = "the boundary must allow bedrock:InvokeModel only on the approved model ARNs"
  }

  assert {
    condition = alltrue([
      for action in ["sqs:ChangeMessageVisibility", "sqs:GetQueueUrl", "dynamodb:ConditionCheckItem", "textract:StartDocumentTextDetection", "textract:GetDocumentTextDetection"] :
      contains(flatten([
        for statement in jsondecode(aws_iam_policy.workload_permissions_boundary.policy).Statement :
        flatten([statement.Action]) if statement.Sid == "AllowComputeActions"
      ]), action)
    ])
    error_message = "the boundary must allow every action the identity policies grant"
  }
}

run "queue_access_follows_the_stage_topology" {
  command = plan

  assert {
    condition = toset(one([
      for statement in jsondecode(aws_iam_role_policy.workload["ingest-api"].policy).Statement :
      statement.Resource if statement.Sid == "SendToDownstreamStageQueues"
    ])) == toset(["arn:aws:sqs:us-east-1:000000000000:dep_01ARZ3NDEKTSV4RRFFQ69G5FAV-ingest-stage-queue"])
    error_message = "the ingest API may only send to the ingest stage queue"
  }

  assert {
    condition = !contains([
      for statement in jsondecode(aws_iam_role_policy.workload["ingest-api"].policy).Statement : statement.Sid
    ], "ConsumeOwnStageQueues")
    error_message = "the ingest API consumes no stage queue"
  }

  assert {
    condition = toset(one([
      for statement in jsondecode(aws_iam_role_policy.workload["ocr-worker"].policy).Statement :
      statement.Resource if statement.Sid == "ConsumeOwnStageQueues"
      ])) == toset([
      "arn:aws:sqs:us-east-1:000000000000:dep_01ARZ3NDEKTSV4RRFFQ69G5FAV-ingest-stage-queue",
      "arn:aws:sqs:us-east-1:000000000000:dep_01ARZ3NDEKTSV4RRFFQ69G5FAV-ocr-stage-queue",
    ])
    error_message = "the OCR worker consumes exactly the ingest and OCR polling stages"
  }

  assert {
    condition = toset(one([
      for statement in jsondecode(aws_iam_role_policy.workload["postprocess-worker"].policy).Statement :
      statement.Resource if statement.Sid == "ConsumeOwnStageQueues"
      ])) == toset([
      "arn:aws:sqs:us-east-1:000000000000:dep_01ARZ3NDEKTSV4RRFFQ69G5FAV-notify-stage-queue",
      "arn:aws:sqs:us-east-1:000000000000:dep_01ARZ3NDEKTSV4RRFFQ69G5FAV-persist-stage-queue",
      "arn:aws:sqs:us-east-1:000000000000:dep_01ARZ3NDEKTSV4RRFFQ69G5FAV-validate-stage-queue",
    ])
    error_message = "the postprocess worker consumes exactly the validate, persist and notify stages"
  }

  assert {
    condition = toset(one([
      for statement in jsondecode(aws_iam_role_policy.workload["bank-worker"].policy).Statement :
      statement.Resource if statement.Sid == "SendToDownstreamStageQueues"
    ])) == toset(["arn:aws:sqs:us-east-1:000000000000:dep_01ARZ3NDEKTSV4RRFFQ69G5FAV-validate-stage-queue"])
    error_message = "an extractor may only hand off to the validate stage"
  }
}

run "data_key_use_is_limited_to_the_tagged_key_through_data_services" {
  command = plan

  assert {
    condition = alltrue([
      for service, policy in aws_iam_role_policy.workload :
      toset(one([
        for statement in jsondecode(policy.policy).Statement :
        try(statement.Condition.StringEquals["kms:ViaService"], []) if statement.Sid == "UseDeploymentDataKeyThroughDataServices"
        ])) == toset([
        "dynamodb.us-east-1.amazonaws.com",
        "s3.us-east-1.amazonaws.com",
        "sqs.us-east-1.amazonaws.com",
      ])
    ])
    error_message = "the data key may only be used through DynamoDB, S3 and SQS"
  }

  assert {
    condition = alltrue([
      for service, policy in aws_iam_role_policy.workload :
      one([
        for statement in jsondecode(policy.policy).Statement :
        try(statement.Condition.StringEquals["aws:ResourceTag/deployment_id"], "") if statement.Sid == "UseDeploymentDataKeyThroughDataServices"
      ]) == var.deployment_id
    ])
    error_message = "the data key statement must be bound to this deployment's tagged key"
  }
}

run "only_the_ingest_api_administers_users" {
  command = plan

  assert {
    condition = alltrue([
      for service, policy in aws_iam_role_policy.workload :
      contains([for statement in jsondecode(policy.policy).Statement : statement.Sid], "AdministerDeploymentUsers") == (service == "ingest-api")
    ])
    error_message = "only the ingest API may call the Cognito admin user lifecycle APIs"
  }
}

run "inference_profile_ids_expand_to_profile_and_foundation_models" {
  command = plan

  variables {
    bedrock_extractor_model_ids = ["us.anthropic.claude-3-5-haiku-20241022-v1:0"]
  }

  assert {
    condition = toset(one([
      for statement in jsondecode(aws_iam_role_policy.workload["bank-worker"].policy).Statement :
      statement.Resource if statement.Sid == "InvokeApprovedBedrockModels"
      ])) == toset([
      "arn:aws:bedrock:us-east-1:000000000000:inference-profile/us.anthropic.claude-3-5-haiku-20241022-v1:0",
      "arn:aws:bedrock:*::foundation-model/anthropic.claude-3-5-haiku-20241022-v1:0",
    ])
    error_message = "a cross-region inference profile needs its profile ARN and the routed foundation model"
  }
}

run "wildcard_model_ids_are_rejected" {
  command = plan

  variables {
    bedrock_classifier_model_ids = ["anthropic.*"]
  }

  expect_failures = [var.bedrock_classifier_model_ids]
}

run "parameter_prefix_with_wildcard_is_rejected" {
  command = plan

  variables {
    runtime_parameter_path_prefix = "/scanalyze/*"
  }

  expect_failures = [var.runtime_parameter_path_prefix]
}
