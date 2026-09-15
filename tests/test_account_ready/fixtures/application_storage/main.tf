# Test-only observations: no provider, resource, or cloud request.
locals {
  receipt  = jsondecode(file("${path.module}/receipt.synthetic.json"))
  original = jsondecode(file("${path.module}/readback.synthetic.json"))
  fresh_body = merge({ for key, value in local.original : key => value if key != "readback_digest" }, {
    observed_at = plantimestamp()
  })
  fresh      = merge(local.fresh_body, { readback_digest = "sha256:${sha256(jsonencode(local.fresh_body))}" })
  stale_body = merge(local.fresh_body, { observed_at = "2026-01-01T00:00:00Z" })
  stale      = merge(local.stale_body, { readback_digest = "sha256:${sha256(jsonencode(local.stale_body))}" })
}
output "receipt" {
  value = local.receipt
}
output "fresh" {
  value = local.fresh
}
output "stale" {
  value = local.stale
}

locals {
  oac_original_access   = jsondecode(file("${path.module}/oac-access.synthetic.json"))
  oac_original_pins     = jsondecode(file("${path.module}/oac-pins.synthetic.json"))
  oac_original_readback = jsondecode(file("${path.module}/oac-readback.synthetic.json"))
  oac_edge_body         = merge({ for key, value in local.oac_original_access.edge_readback : key => value if key != "readback_digest" }, { observed_at = plantimestamp() })
  oac_edge              = merge(local.oac_edge_body, { readback_digest = "sha256:${sha256(jsonencode(local.oac_edge_body))}" })
  oac_access            = merge(local.oac_original_access, { edge_readback = local.oac_edge })
  oac_pins              = merge(local.oac_original_pins, { edge_readback_digest = local.oac_edge.readback_digest })
  oac_storage_body      = merge({ for key, value in local.oac_original_readback : key => value if key != "readback_digest" }, { observed_at = plantimestamp() })
  oac_storage           = merge(local.oac_storage_body, { readback_digest = "sha256:${sha256(jsonencode(local.oac_storage_body))}" })

  stale_edge_body = merge(local.oac_edge_body, { observed_at = "2026-01-01T00:00:00Z" })
  stale_edge      = merge(local.stale_edge_body, { readback_digest = "sha256:${sha256(jsonencode(local.stale_edge_body))}" })
  wrong_origin_edge_body = merge(local.oac_edge_body, { distribution = merge(local.oac_edge_body.distribution, {
    origins = merge(local.oac_edge_body.distribution.origins, {
      "s3-frontend" = merge(local.oac_edge_body.distribution.origins["s3-frontend"], { origin_path = "/wrong" })
    })
  }) })
  wrong_origin_edge = merge(local.wrong_origin_edge_body, { readback_digest = "sha256:${sha256(jsonencode(local.wrong_origin_edge_body))}" })
}
output "oac_access" { value = local.oac_access }
output "oac_pins" { value = local.oac_pins }
output "oac_readback" { value = local.oac_storage }
output "stale_oac_access" { value = merge(local.oac_access, { edge_readback = local.stale_edge }) }
output "stale_oac_pins" { value = merge(local.oac_pins, { edge_readback_digest = local.stale_edge.readback_digest }) }
output "wrong_origin_access" { value = merge(local.oac_access, { edge_readback = local.wrong_origin_edge }) }
output "wrong_origin_pins" { value = merge(local.oac_pins, { edge_readback_digest = local.wrong_origin_edge.readback_digest }) }

locals {
  replaced_template = merge(local.oac_storage_body.actual_template, { Resources = merge(local.oac_storage_body.actual_template.Resources, {
    DataAlias = merge(local.oac_storage_body.actual_template.Resources.DataAlias, { DeletionPolicy = "Delete" })
  }) })
  replaced_storage_body = merge(local.oac_storage_body, { actual_template = local.replaced_template })
  replaced_storage      = merge(local.replaced_storage_body, { readback_digest = "sha256:${sha256(jsonencode(local.replaced_storage_body))}" })
  replaced_transition_body = merge({ for key, value in local.oac_access.transition : key => value if key != "transition_digest" }, {
    template_sha256 = "sha256:${sha256(jsonencode(local.replaced_template))}"
  })
  replaced_transition = merge(local.replaced_transition_body, { transition_digest = "sha256:${sha256(jsonencode(local.replaced_transition_body))}" })
}
output "replaced_storage" { value = local.replaced_storage }
output "replaced_access" { value = merge(local.oac_access, { transition = local.replaced_transition }) }
output "replaced_pins" { value = merge(local.oac_pins, { transition_digest = local.replaced_transition.transition_digest }) }
