# Root: identity-control-plane

> **Layer:** identity-control-plane
> **Scope:** regional
> **Module:** `modules/identity-control-plane`
> **Consumes:** `global/v1`, `release-manifest/v1`, and reviewed external
> `identity-contract/v2`
> **Produces:** `identity-control-plane/v1`
> **State key:** `{deployment_id}/{region}/identity-control-plane/terraform.tfstate`

## Purpose

This is the only Terraform composition root for the portable identity control
plane. It validates the exact customer, deployment, account, region, global
permissions boundary, immutable runtime artifacts, policy digest, and M2M
registry before calling the module. It exports one atomic non-sensitive contract
for the publisher and downstream services/edge consumers.

The reviewed `domain_name` input is shared with the edge root. The module
rejects Cognito app-client configuration unless callback and logout
registrations are exactly `https://<domain_name>/callback` and
`https://<domain_name>/`, respectively.

Historical manifests may omit `domain`, but this root cannot be planned through
the canonical wrapper without an approved deployment-target/v2 runtime origin.
The manifest domain is only an exact assertion. The wrapper accepts no
independent URI list and materializes the domain from the digest-bound backend
binding; the root derives both registrations from that authorized value.

## Safety constraints

- Dedicated `ScanalyzeCustomer-Identity-Plan` and
  `ScanalyzeCustomer-Identity-Apply` terminal roles own this state boundary.
- The root never reads another Terraform state or discovers provider resources
  by name.
- Release artifacts require exact bucket/key/version/digest bindings.
- A missing, stale, foreign, partial, ambiguous, or schema-incompatible upstream
  contract fails during plan.
- Saved-plan apply, contract publication, state adoption, migration, user or
  client lifecycle operations, and deployment require separate authorization.
- `prevent_destroy` and provider deletion protection are not rollback controls
  to disable for convenience.

Repository tests and offline provider validation do not authorize AWS or
production. Production remains NO-GO.
