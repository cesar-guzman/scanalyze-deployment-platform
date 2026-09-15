# One independently pinned active policy; the original receipt remains durable.
variable "application_storage_access" {
  type        = any
  default     = null
  description = "Closed foundation/OAC phase bundle; baseline requires an explicit protected phase."
}
variable "expected_application_storage_access" {
  type        = any
  default     = null
  description = "Independent protected phase and OAC evidence/release pins; never derive from the submitted bundle."
}

locals {
  storage_oac                    = try(var.application_storage_access.phase == "oac" && var.expected_application_storage_access.phase == "oac", false)
  storage_active_template_digest = local.storage_oac ? try(var.application_storage_access.transition.template_sha256, null) : try(var.application_storage_foundation.template_sha256, null)
  storage_active_policy_digest   = local.storage_oac ? try(format("sha256:%s", sha256(jsonencode(local.storage_oac_policy))), null) : local.storage_bucket_policy_digest
  storage_oac_envelope           = try(var.application_storage_access.edge_envelope, null)
  storage_oac_edge               = try(var.application_storage_access.edge_readback, null)
  storage_oac_locator            = try(var.application_storage_access.edge_locator, null)
  storage_oac_transition         = try(var.application_storage_access.transition, null)
  storage_oac_pins               = var.expected_application_storage_access
  storage_oac_distribution       = try(local.storage_oac_edge.distribution, null)
  storage_oac_policy = try(merge(local.storage_bucket_policy, { Statement = concat(local.storage_bucket_policy.Statement, [{
    Sid       = "AllowDeploymentCloudFrontRead", Effect = "Allow", Principal = { Service = "cloudfront.amazonaws.com" }, Action = "s3:GetObject",
    Resource  = [format("%s/releases/%s/*", local.storage_bucket_arn, var.deployment_id), format("%s/%s/config.json", local.storage_bucket_arn, var.deployment_id)],
    Condition = { StringEquals = { "AWS:SourceArn" = local.storage_oac_distribution.arn } }
  }]) }), null)
  # Revert ONLY the policy in the observed active template, then require the
  # original independently anchored template digest. No resource/key mutation.
  storage_oac_original_template = try(merge(var.application_storage_readback.actual_template, {
    Resources = merge(var.application_storage_readback.actual_template.Resources, {
      FrontendBucketPolicy = merge(var.application_storage_readback.actual_template.Resources.FrontendBucketPolicy, {
        Properties = merge(var.application_storage_readback.actual_template.Resources.FrontendBucketPolicy.Properties, {
          PolicyDocument = local.storage_bucket_policy
        })
      })
    })
  }), null)
  storage_oac_expected_locator_name = try(format("/scanalyze/deployments/%s/contracts/edge/v2/releases/%s/digests/%s", var.deployment_id,
  replace(local.storage_oac_envelope.release_digest, ":", "-"), replace(local.storage_oac_envelope.contract_digest, ":", "-")), null)
  storage_oac_expected_origins = try({
    "s3-frontend" = {
      domain_name              = format("%s.s3.%s.amazonaws.com", local.storage_bucket_name, var.region), origin_path = format("/releases/%s", var.deployment_id),
      origin_access_control_id = local.storage_oac_edge.origin_access_control.id, origin_access_identity = ""
    },
    "s3-runtime-config" = {
      domain_name              = format("%s.s3.%s.amazonaws.com", local.storage_bucket_name, var.region), origin_path = format("/%s", var.deployment_id),
      origin_access_control_id = local.storage_oac_edge.origin_access_control.id, origin_access_identity = ""
    }
  }, null)
  storage_oac_expected_transition = try({
    schema_version               = "1", record_type = "application_storage_oac_transition",
    foundation_receipt_digest    = var.application_storage_foundation.contract_digest,
    edge_envelope_digest         = format("sha256:%s", sha256(jsonencode(local.storage_oac_envelope))),
    edge_locator_digest          = format("sha256:%s", sha256(jsonencode(local.storage_oac_locator))),
    initial_edge_readback_digest = local.storage_oac_transition.initial_edge_readback_digest,
    release_digest               = local.storage_oac_envelope.release_digest, release_version = local.storage_oac_envelope.release_version,
    distribution_id              = local.storage_oac_distribution.id, distribution_arn = local.storage_oac_distribution.arn,
    origin_access_control_id     = local.storage_oac_edge.origin_access_control.id,
    previous_template_sha256     = var.application_storage_foundation.template_sha256,
    template_sha256              = format("sha256:%s", sha256(jsonencode(var.application_storage_readback.actual_template))),
    previous_policy_sha256       = var.application_storage_foundation.frontend_bucket.policy_sha256,
    policy_sha256                = format("sha256:%s", sha256(jsonencode(local.storage_oac_policy)))
  }, null)
  storage_oac_transition_admitted = try(
    jsonencode({ for key, value in local.storage_oac_transition : key => value if key != "transition_digest" }) == jsonencode(local.storage_oac_expected_transition) &&
    toset(keys(local.storage_oac_transition)) == setunion(toset(keys(local.storage_oac_expected_transition)), ["transition_digest"]) &&
    local.storage_oac_transition.transition_digest == local.storage_oac_pins.transition_digest &&
    format("sha256:%s", sha256(jsonencode(local.storage_oac_expected_transition))) == local.storage_oac_pins.transition_digest &&
    can(regex("^sha256:[a-f0-9]{64}$", local.storage_oac_transition.initial_edge_readback_digest)) &&
    format("sha256:%s", sha256(jsonencode(local.storage_oac_original_template))) == var.application_storage_foundation.template_sha256 &&
    jsonencode(var.application_storage_readback.actual_template.Resources.FrontendBucketPolicy.Properties.PolicyDocument) == jsonencode(local.storage_oac_policy),
    false
  )
  storage_oac_envelope_admitted = try(
    local.storage_partition == "aws" &&
    toset(keys(local.storage_oac_envelope)) == toset(["schema_version", "customer_id", "deployment_id", "aws_account_id", "region", "scope", "layer", "producer", "release_version", "release_digest", "output_schema_version", "outputs", "contract_digest", "produced_at", "terraform_workspace", "state_key", "module_source_digest"]) &&
    local.storage_oac_envelope.schema_version == "2" && local.storage_oac_envelope.customer_id == var.customer_id &&
    local.storage_oac_envelope.deployment_id == var.deployment_id && local.storage_oac_envelope.aws_account_id == var.account_id &&
    local.storage_oac_envelope.region == "global" && local.storage_oac_envelope.scope == "global" &&
    local.storage_oac_envelope.layer == "edge" && local.storage_oac_envelope.producer == "roots/edge" &&
    local.storage_oac_envelope.output_schema_version == "edge/v2" && local.storage_oac_envelope.terraform_workspace == "default" &&
    local.storage_oac_envelope.state_key == format("%s/edge/terraform.tfstate", var.deployment_id) &&
    can(timeadd(local.storage_oac_envelope.produced_at, "0s")) &&
    can(regex("^sha256:[a-f0-9]{64}$", local.storage_oac_envelope.module_source_digest)) &&
    local.storage_oac_envelope.release_version == local.storage_oac_pins.release_version &&
    local.storage_oac_envelope.release_digest == local.storage_oac_pins.release_digest &&
    can(regex("^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$", local.storage_oac_envelope.release_version)) &&
    toset(keys(local.storage_oac_envelope.outputs)) == toset(["cloudfront_domain_name", "cloudfront_distribution_id", "cloudfront_distribution_arn", "waf_web_acl_arn", "acm_certificate_arn", "route53_zone_id"]) &&
    can(regex("^arn:[^:]+:wafv2:.+$", local.storage_oac_envelope.outputs.waf_web_acl_arn)) &&
    can(regex("^arn:[^:]+:acm:.+$", local.storage_oac_envelope.outputs.acm_certificate_arn)) &&
    can(regex("^Z[A-Z0-9]+$", local.storage_oac_envelope.outputs.route53_zone_id)) &&
    format("sha256:%s", sha256(jsonencode(local.storage_oac_envelope.outputs))) == local.storage_oac_envelope.contract_digest &&
    format("sha256:%s", sha256(jsonencode(local.storage_oac_envelope))) == local.storage_oac_pins.edge_envelope_digest &&
    jsonencode(local.storage_oac_locator) == jsonencode({ name = local.storage_oac_expected_locator_name,
    arn = format("arn:aws:ssm:%s:%s:parameter%s", var.region, var.account_id, local.storage_oac_expected_locator_name), version = 1 }) &&
    format("sha256:%s", sha256(jsonencode(local.storage_oac_locator))) == local.storage_oac_pins.edge_locator_digest,
    false
  )
  storage_oac_edge_admitted = try(
    toset(keys(local.storage_oac_edge)) == toset(["schema_version", "record_type", "status", "customer_id", "deployment_id", "account_id", "region", "environment", "aws_partition", "observed_at", "distribution", "origin_access_control", "readback_digest"]) &&
    local.storage_oac_edge.schema_version == "1" && local.storage_oac_edge.record_type == "application_storage_edge_readback" && local.storage_oac_edge.status == "CLOSED" &&
    alltrue([for field, value in local.storage_identity : local.storage_oac_edge[field] == value]) &&
    can(regex("^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$", local.storage_oac_edge.observed_at)) &&
    timecmp(local.storage_oac_edge.observed_at, plantimestamp()) <= 0 && timecmp(plantimestamp(), timeadd(local.storage_oac_edge.observed_at, "15m")) <= 0 &&
    local.storage_oac_edge.readback_digest == local.storage_oac_pins.edge_readback_digest &&
    format("sha256:%s", sha256(jsonencode({ for key, value in local.storage_oac_edge : key => value if key != "readback_digest" }))) == local.storage_oac_pins.edge_readback_digest &&
    toset(keys(local.storage_oac_distribution)) == toset(["id", "arn", "domain_name", "status", "enabled", "etag", "tags", "origins", "default_target_origin_id", "config_path_pattern", "config_target_origin_id"]) &&
    local.storage_oac_distribution.id == local.storage_oac_envelope.outputs.cloudfront_distribution_id &&
    local.storage_oac_distribution.arn == local.storage_oac_envelope.outputs.cloudfront_distribution_arn &&
    local.storage_oac_distribution.arn == format("arn:aws:cloudfront::%s:distribution/%s", var.account_id, local.storage_oac_distribution.id) &&
    local.storage_oac_distribution.domain_name == local.storage_oac_envelope.outputs.cloudfront_domain_name &&
    can(regex("^[A-Z0-9]{1,64}$", local.storage_oac_distribution.id)) &&
    can(regex("^[a-z0-9]+\\.cloudfront\\.net$", local.storage_oac_distribution.domain_name)) &&
    local.storage_oac_distribution.status == "Deployed" && local.storage_oac_distribution.enabled == true &&
    can(regex("^[A-Za-z0-9]{1,128}$", local.storage_oac_distribution.etag)) &&
    jsonencode(local.storage_oac_distribution.tags) == jsonencode({ deployment_id = var.deployment_id, managed_by = "terraform", layer = "edge" }) &&
    jsonencode(local.storage_oac_distribution.origins) == jsonencode(local.storage_oac_expected_origins) &&
    local.storage_oac_distribution.default_target_origin_id == "s3-frontend" && local.storage_oac_distribution.config_path_pattern == "/config.json" &&
    local.storage_oac_distribution.config_target_origin_id == "s3-runtime-config" &&
    can(regex("^[A-Z0-9]{1,64}$", local.storage_oac_edge.origin_access_control.id)) &&
    jsonencode(local.storage_oac_edge.origin_access_control) == jsonencode({
      id = local.storage_oac_edge.origin_access_control.id, origin_type = "s3", signing_behavior = "always", signing_protocol = "sigv4"
    }),
    false
  )
  storage_access_admitted = try(
    var.application_storage_access.phase == var.expected_application_storage_access.phase && (
      var.expected_application_storage_access.phase == "foundation" ? (
        jsonencode(var.application_storage_access) == jsonencode({ phase = "foundation" }) &&
        jsonencode(var.expected_application_storage_access) == jsonencode({ phase = "foundation" })
        ) : (
        local.storage_oac && toset(keys(var.application_storage_access)) == toset(["phase", "transition", "edge_envelope", "edge_locator", "edge_readback"]) &&
        toset(keys(var.expected_application_storage_access)) == toset(["phase", "transition_digest", "edge_envelope_digest", "edge_locator_digest", "edge_readback_digest", "release_digest", "release_version"]) &&
        alltrue([for name, value in var.expected_application_storage_access : can(regex("^sha256:[a-f0-9]{64}$", value)) if !contains(["phase", "release_version"], name)]) &&
        local.storage_oac_envelope_admitted && local.storage_oac_edge_admitted && local.storage_oac_transition_admitted
      )
    ), false
  )
}

resource "terraform_data" "application_storage_oac_custody" {
  count            = local.storage_baseline && try(var.application_storage_access.phase == "oac", false) ? 1 : 0
  depends_on       = [terraform_data.application_storage_gate]
  input            = try(local.storage_oac_transition.transition_digest, null)
  triggers_replace = [try(local.storage_oac_transition.foundation_receipt_digest, null), try(local.storage_oac_distribution.arn, null), try(local.storage_oac_edge.origin_access_control.id, null)]
  lifecycle {
    # Once applied, reverting to foundation would destroy this marker and fails.
    prevent_destroy = true
  }
}
