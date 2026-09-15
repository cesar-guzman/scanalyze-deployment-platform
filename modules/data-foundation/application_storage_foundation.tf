# Explicit baseline opt-in; KMS data sources never administer the keys.
variable "kms_ownership_mode" {
  type        = string
  default     = "layer"
  description = "layer preserves existing ownership; baseline requires independently admitted greenfield storage."
  validation {
    condition     = contains(["layer", "baseline"], var.kms_ownership_mode)
    error_message = "kms_ownership_mode must be layer or baseline."
  }
}
variable "application_storage_foundation" {
  type        = any
  default     = null
  description = "Complete durable receipt; its historical observation does not expire."
}
variable "expected_application_storage_digest" {
  type    = string
  default = null
}
variable "application_storage_readback" {
  type        = any
  default     = null
  description = "Separate fresh CLOSED readback for this plan admission."
}
variable "expected_application_storage_readback_digest" {
  type    = string
  default = null
}
variable "environment" {
  type        = string
  default     = null
  description = "Independent target environment; required by baseline storage ownership."
}

locals {
  storage_baseline   = var.kms_ownership_mode == "baseline"
  storage_partition  = startswith(var.region, "cn-") ? "aws-cn" : startswith(var.region, "us-gov-") ? "aws-us-gov" : "aws"
  storage_dns_suffix = local.storage_partition == "aws-cn" ? "amazonaws.com.cn" : "amazonaws.com"
  storage_identity = {
    customer_id = var.customer_id, deployment_id = var.deployment_id, account_id = var.account_id,
    region      = var.region, environment = var.environment, aws_partition = local.storage_partition
  }
  storage_request = merge(local.storage_identity, {
    schema_version = "1", record_type = "application_storage_foundation_request",
    ownership_mode = "baseline", installation_mode = "greenfield"
  })
  storage_key_properties = {
    key_state = "Enabled", key_manager = "CUSTOMER", key_spec = "SYMMETRIC_DEFAULT",
    key_usage = "ENCRYPT_DECRYPT", origin = "AWS_KMS", multi_region = false, rotation_enabled = true
  }
  storage_tags = {
    for name, settings in {
      data           = { layer = "data-foundation", purpose = "application-data-encryption" }
      cicd_artifacts = { layer = "cicd", purpose = "cicd-artifact-encryption" }
      frontend       = { layer = "edge", purpose = "frontend-storage" }
      } : name => merge(settings, {
        customer_id = var.customer_id, deployment_id = var.deployment_id,
        environment = var.environment, managed_by = "external-account-baseline"
    })
  }
  storage_aliases = {
    data           = format("alias/%s-data", var.deployment_id)
    cicd_artifacts = format("alias/%s-cicd-artifacts", var.deployment_id)
  }
  storage_root_statement = {
    Sid       = "RootAccountAccess", Effect = "Allow",
    Principal = { AWS = format("arn:%s:iam::%s:root", local.storage_partition, var.account_id) },
    Action    = "kms:*", Resource = "*"
  }
  storage_data_statement = {
    Sid       = "WorkloadEncryptDecrypt", Effect = "Allow",
    Principal = { AWS = format("arn:%s:iam::%s:root", local.storage_partition, var.account_id) },
    Action    = ["kms:Decrypt", "kms:GenerateDataKey", "kms:GenerateDataKeyWithoutPlaintext", "kms:DescribeKey"],
    Resource  = "*",
    Condition = { StringEquals = { "kms:ViaService" = [
      for service in ["s3", "dynamodb", "sqs"] : format("%s.%s.%s", service, var.region, local.storage_dns_suffix)
    ] } }
  }
  storage_policy_digests = {
    data           = format("sha256:%s", sha256(jsonencode({ Version = "2012-10-17", Statement = [local.storage_root_statement, local.storage_data_statement] })))
    cicd_artifacts = format("sha256:%s", sha256(jsonencode({ Version = "2012-10-17", Statement = [local.storage_root_statement] })))
  }
  storage_bucket_name = format("scanalyze-%s-frontend", var.account_id)
  storage_bucket_arn  = format("arn:%s:s3:::%s", local.storage_partition, local.storage_bucket_name)
  storage_bucket_policy = {
    Version = "2012-10-17", Statement = [{
      Sid       = "DenyNonTLS", Effect = "Deny", Principal = "*", Action = "s3:*",
      Resource  = [local.storage_bucket_arn, format("%s/*", local.storage_bucket_arn)],
      Condition = { Bool = { "aws:SecureTransport" = "false" } }
    }]
  }
  storage_bucket_policy_digest = format("sha256:%s", sha256(jsonencode(local.storage_bucket_policy)))
  storage_bucket_controls = {
    encryption        = "AES256", versioning = "Enabled", ownership = "BucketOwnerEnforced",
    block_public_acls = true, block_public_policy = true, ignore_public_acls = true, restrict_public_buckets = true
  }
  storage_receipt_fields = toset(["schema_version", "record_type", "customer_id", "deployment_id", "account_id", "region", "environment", "aws_partition", "ownership_mode", "installation_mode", "request_digest", "template_sha256", "initial_readback_digest", "initial_observed_at", "keys", "frontend_bucket", "contract_digest"])
  storage_key_fields     = toset(["key_arn", "key_id", "alias_name", "alias_target_key_id", "key_state", "key_manager", "key_spec", "key_usage", "origin", "multi_region", "rotation_enabled", "tags", "policy_sha256"])
  storage_bucket_fields  = toset(["name", "arn", "region", "owner_account_id", "controls", "tags", "policy_sha256"])
  storage_receipt_admitted = try(
    toset(keys(var.application_storage_foundation)) == local.storage_receipt_fields &&
    var.application_storage_foundation.schema_version == "1" &&
    var.application_storage_foundation.record_type == "application_storage_foundation_receipt" &&
    var.application_storage_foundation.ownership_mode == "baseline" &&
    var.application_storage_foundation.installation_mode == "greenfield" &&
    can(regex("^cust_[0-9A-HJKMNP-TV-Z]{26}$", var.customer_id)) &&
    can(regex("^dep_[0-9A-HJKMNP-TV-Z]{26}$", var.deployment_id)) &&
    can(regex("^[0-9]{12}$", var.account_id)) && var.account_id != "000000000000" &&
    can(regex("^[a-z]{2}(-[a-z]+)+-[0-9]+$", var.region)) &&
    contains(["sandbox", "dev", "staging", "production"], var.environment) &&
    alltrue([for field, value in local.storage_identity : var.application_storage_foundation[field] == value]) &&
    var.application_storage_foundation.contract_digest == var.expected_application_storage_digest &&
    format("sha256:%s", sha256(jsonencode({ for key, value in var.application_storage_foundation : key => value if key != "contract_digest" }))) == var.expected_application_storage_digest &&
    var.application_storage_foundation.request_digest == format("sha256:%s", sha256(jsonencode(local.storage_request))) &&
    can(regex("^sha256:[a-f0-9]{64}$", var.application_storage_foundation.template_sha256)) &&
    can(regex("^sha256:[a-f0-9]{64}$", var.application_storage_foundation.initial_readback_digest)) &&
    can(regex("^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$", var.application_storage_foundation.initial_observed_at)) &&
    can(timeadd(var.application_storage_foundation.initial_observed_at, "0s")) &&
    toset(keys(var.application_storage_foundation.keys)) == toset(["data", "cicd_artifacts"]) &&
    alltrue([for name, key in var.application_storage_foundation.keys :
      toset(keys(key)) == local.storage_key_fields &&
      can(regex("^[a-f0-9]{8}-([a-f0-9]{4}-){3}[a-f0-9]{12}$", key.key_id)) &&
      key.key_arn == format("arn:%s:kms:%s:%s:key/%s", local.storage_partition, var.region, var.account_id, key.key_id) &&
      key.alias_name == local.storage_aliases[name] && key.alias_target_key_id == key.key_id &&
      jsonencode(key.tags) == jsonencode(local.storage_tags[name]) &&
      key.policy_sha256 == local.storage_policy_digests[name] &&
      alltrue([for field, value in local.storage_key_properties : key[field] == value])
    ]) &&
    var.application_storage_foundation.keys.data.key_arn != var.application_storage_foundation.keys.cicd_artifacts.key_arn &&
    toset(keys(var.application_storage_foundation.frontend_bucket)) == local.storage_bucket_fields &&
    var.application_storage_foundation.frontend_bucket.name == local.storage_bucket_name &&
    var.application_storage_foundation.frontend_bucket.arn == local.storage_bucket_arn &&
    var.application_storage_foundation.frontend_bucket.region == var.region &&
    var.application_storage_foundation.frontend_bucket.owner_account_id == var.account_id &&
    jsonencode(var.application_storage_foundation.frontend_bucket.controls) == jsonencode(local.storage_bucket_controls) &&
    jsonencode(var.application_storage_foundation.frontend_bucket.tags) == jsonencode(local.storage_tags.frontend) &&
    var.application_storage_foundation.frontend_bucket.policy_sha256 == local.storage_bucket_policy_digest,
    false
  )
  storage_observed_system_tags = {
    "aws:cloudformation:stack-id"   = try(var.application_storage_readback.stack_arn, "")
    "aws:cloudformation:stack-name" = try(split("/", split(":stack/", var.application_storage_readback.stack_arn)[1])[0], "")
  }
  storage_readback_admitted = try(
    toset(keys(var.application_storage_readback)) == toset(["schema_version", "record_type", "status", "customer_id", "deployment_id", "account_id", "region", "environment", "aws_partition", "request_digest", "observed_at", "stack_arn", "stack_status", "stack_resources", "actual_template", "keys", "frontend_bucket", "readback_digest"]) &&
    var.application_storage_readback.schema_version == "1" &&
    var.application_storage_readback.record_type == "application_storage_foundation_readback" &&
    var.application_storage_readback.status == "CLOSED" &&
    can(regex("^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$", var.application_storage_readback.observed_at)) &&
    contains(["CREATE_COMPLETE", "UPDATE_COMPLETE"], var.application_storage_readback.stack_status) &&
    can(regex(format("^arn:%s:cloudformation:%s:%s:stack/[A-Za-z][A-Za-z0-9-]{0,127}/[a-f0-9]{8}-([a-f0-9]{4}-){3}[a-f0-9]{12}$", local.storage_partition, var.region, var.account_id), var.application_storage_readback.stack_arn)) &&
    alltrue([for field, value in local.storage_identity : var.application_storage_readback[field] == value]) &&
    var.application_storage_readback.readback_digest == var.expected_application_storage_readback_digest &&
    format("sha256:%s", sha256(jsonencode({ for key, value in var.application_storage_readback : key => value if key != "readback_digest" }))) == var.expected_application_storage_readback_digest &&
    var.application_storage_readback.request_digest == var.application_storage_foundation.request_digest &&
    format("sha256:%s", sha256(jsonencode(var.application_storage_readback.actual_template))) == local.storage_active_template_digest &&
    toset(keys(var.application_storage_readback.keys)) == toset(["data", "cicd_artifacts"]) &&
    alltrue([for name, key in var.application_storage_readback.keys :
      toset(keys(key)) == setunion(setsubtract(local.storage_key_fields, ["policy_sha256"]), ["key_policy"]) &&
      jsonencode({ for field, value in key : field => value if !contains(["key_policy", "tags"], field) }) ==
      jsonencode({ for field, value in var.application_storage_foundation.keys[name] : field => value if !contains(["policy_sha256", "tags"], field) }) &&
      format("sha256:%s", sha256(jsonencode(key.key_policy))) == var.application_storage_foundation.keys[name].policy_sha256 &&
      jsonencode({ for tag, value in key.tags : tag => value if !startswith(tag, "aws:cloudformation:") }) == jsonencode(local.storage_tags[name]) &&
      alltrue([for tag, value in key.tags : value == merge(local.storage_tags[name], local.storage_observed_system_tags, { "aws:cloudformation:logical-id" = name == "data" ? "DataKey" : "ArtifactsKey" })[tag]])
    ]) &&
    toset(keys(var.application_storage_readback.frontend_bucket)) == setunion(setsubtract(local.storage_bucket_fields, ["policy_sha256"]), ["bucket_policy"]) &&
    jsonencode({ for field, value in var.application_storage_readback.frontend_bucket : field => value if !contains(["bucket_policy", "tags"], field) }) ==
    jsonencode({ for field, value in var.application_storage_foundation.frontend_bucket : field => value if !contains(["policy_sha256", "tags"], field) }) &&
    format("sha256:%s", sha256(jsonencode(var.application_storage_readback.frontend_bucket.bucket_policy))) == local.storage_active_policy_digest &&
    jsonencode({ for tag, value in var.application_storage_readback.frontend_bucket.tags : tag => value if !startswith(tag, "aws:cloudformation:") }) == jsonencode(local.storage_tags.frontend) &&
    alltrue([for tag, value in var.application_storage_readback.frontend_bucket.tags : value == merge(local.storage_tags.frontend, local.storage_observed_system_tags, { "aws:cloudformation:logical-id" = "FrontendBucket" })[tag]]) &&
    jsonencode(var.application_storage_readback.stack_resources) == jsonencode({
      DataKey        = var.application_storage_foundation.keys.data.key_id, DataAlias = local.storage_aliases.data,
      ArtifactsKey   = var.application_storage_foundation.keys.cicd_artifacts.key_id, ArtifactsAlias = local.storage_aliases.cicd_artifacts,
      FrontendBucket = local.storage_bucket_name, FrontendBucketPolicy = local.storage_bucket_name
    }),
    false
  )
  data_kms_key_arn = local.storage_baseline ? try(data.aws_kms_key.application_storage[0].arn, null) : aws_kms_key.data[0].arn
  data_kms_key_id  = local.storage_baseline ? try(data.aws_kms_key.application_storage[0].id, null) : aws_kms_key.data[0].id
}

data "aws_kms_key" "application_storage" {
  count  = local.storage_baseline && local.storage_receipt_admitted ? 1 : 0
  key_id = var.application_storage_foundation.keys.data.key_arn
}
data "aws_kms_alias" "application_storage" {
  count = local.storage_baseline && local.storage_receipt_admitted ? 1 : 0
  name  = local.storage_aliases.data
}

resource "terraform_data" "application_storage_gate" {
  # Custody/key changes require a separate reviewed procedure, not a mode toggle.
  triggers_replace = [var.kms_ownership_mode, local.data_kms_key_arn]
  lifecycle {
    prevent_destroy = true
    precondition {
      condition = local.storage_baseline ? local.storage_receipt_admitted && local.storage_readback_admitted && local.storage_access_admitted : (
        var.application_storage_foundation == null && var.expected_application_storage_digest == null &&
        var.application_storage_readback == null && var.expected_application_storage_readback_digest == null &&
        var.application_storage_access == null && var.expected_application_storage_access == null
      )
      error_message = "Baseline mode requires a complete independently anchored storage receipt and matching CLOSED readback plus protected access-phase pins; layer mode cannot ignore baseline inputs."
    }
    precondition {
      condition = !local.storage_baseline || try(
        timecmp(var.application_storage_readback.observed_at, plantimestamp()) <= 0 &&
        timecmp(plantimestamp(), timeadd(var.application_storage_readback.observed_at, "15m")) <= 0,
        false
      )
      error_message = "Plan admission requires separate storage readback observed within 15 minutes; the durable receipt itself does not expire."
    }
    precondition {
      condition = !local.storage_baseline || try(
        data.aws_kms_key.application_storage[0].arn == var.application_storage_foundation.keys.data.key_arn &&
        data.aws_kms_key.application_storage[0].id == var.application_storage_foundation.keys.data.key_id &&
        data.aws_kms_key.application_storage[0].aws_account_id == var.account_id &&
        data.aws_kms_key.application_storage[0].key_state == "Enabled" && data.aws_kms_key.application_storage[0].enabled &&
        data.aws_kms_key.application_storage[0].key_manager == "CUSTOMER" &&
        data.aws_kms_key.application_storage[0].key_spec == "SYMMETRIC_DEFAULT" &&
        data.aws_kms_key.application_storage[0].key_usage == "ENCRYPT_DECRYPT" &&
        data.aws_kms_key.application_storage[0].origin == "AWS_KMS" && !data.aws_kms_key.application_storage[0].multi_region &&
        data.aws_kms_alias.application_storage[0].target_key_id == var.application_storage_foundation.keys.data.key_id &&
        data.aws_kms_alias.application_storage[0].target_key_arn == var.application_storage_foundation.keys.data.key_arn,
        false
      )
      error_message = "DescribeKey and alias readback must match the selected enabled symmetric customer-managed regional key; Terraform cannot administer baseline keys."
    }
  }
}
moved {
  from = aws_kms_key.data
  to   = aws_kms_key.data[0]
}
moved {
  from = aws_kms_alias.data
  to   = aws_kms_alias.data[0]
}

