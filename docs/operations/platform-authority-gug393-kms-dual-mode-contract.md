# GUG-393 Identity Center KMS dual-mode contract

This note defines the immutable v2 boundary used when the post-checkpoint
GUG-395 materializer creates the private GUG-393 source bundle. It does not
authorize an AWS call, mutation, deployment, staging acceptance or production.

## Closed mode/key matrix

The private source bundle has record type
`scanalyze.platform_authority.gug393_private_input_source_bundle.v2` and must
contain all three KMS binding fields:

| `identity_center_kms_mode` | `identity_center_kms_key_arn` | Result |
| --- | --- | --- |
| `AWS_OWNED_KMS_KEY` | `null` | Allowed |
| `CUSTOMER_MANAGED_KEY` | Exact `arn:aws:kms:us-east-1:839393571433:key/<uuid-or-mrk-id>` | Allowed |
| Any other pairing | Any value | Reject |

Empty strings, aliases, wrong accounts, wrong Regions, broad key identifiers
and the historical `AWS_OWNED_KEY` spelling are invalid. Do not coerce an empty
string to `null` or infer a mode from the key value.

## Full binding digest

`identity_center_kms_binding_digest` is the canonical SHA-256 digest of exactly
this private object:

```json
{
  "binding_name": "identity_center_kms_key_arn",
  "identity_center_instance_arn": "arn:aws:sso:::instance/ssoins-1234567890abcdef",
  "mode": "AWS_OWNED_KMS_KEY",
  "key_arn": null
}
```

For customer-managed mode, replace only `mode` and `key_arn` with the exact
attested values. The instance ARN comes from the same certified GUG-365 plan;
it is not a new operator input. Canonicalization uses sorted keys, compact JSON,
ASCII escaping, and includes JSON `null`. Hashing only the key ARN, only the
mode, or a display string is not equivalent.

The checked-in
[`platform-authority-gug393-source-bundle.example.json`](platform-authority-gug393-source-bundle.example.json)
uses that illustrative instance ARN for its binding digest. Its empty plans
remain deliberately non-runnable. The example's source-bundle self-digest is
complete for the checked-in body, but an operator must never edit it into a
live artifact. Only the capability-gated post-checkpoint materializer may emit
the private bundle after validating the exact plans and terminal handoff.

## Public leak boundary

The real source bundle, Identity Center instance ARN, KMS mode and customer
managed key ARN remain in private custody. Do not place them in Git, CI output,
GitHub comments, Linear, chat transcripts or public evidence.

The public v2 downstream receipt exposes only
`identity_center_kms_binding_digest`. Its schema rejects
`identity_center_instance_arn`, `identity_center_kms_mode` and
`identity_center_kms_key_arn` as additional properties. A digest proves only
which private tuple was bound; it does not disclose the tuple and does not
prove that AWS accepted it.

## Version and migration rules

- v1 schemas and fixtures remain immutable historical contracts.
- A v1 record is never relabeled, resealed or interpreted as v2.
- A v2 producer emits the v2 record type, `schema_version: 2`, the complete
  binding digest and a self-digest recomputed over the full v2 body.
- Every downstream consumer must require the matching v2 type and reject
  missing, additional or cross-run fields.
- Mode, key, instance and binding-digest disagreement is a fail-closed stop;
  it cannot be repaired by selecting a default.

Preserve the private source bundle, terminal handoff and public downstream
receipt together for reconciliation. If any binding differs, stop with the
existing human-decision or reconciliation gate. Do not rerun a provider effect
or claim production readiness from schema validity.
