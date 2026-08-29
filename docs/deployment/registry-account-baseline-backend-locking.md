# Registry, account baseline, backend, and locking

> Candidate implementation for GUG-122. It is offline-only until reviewed
> merge, main verification, GUG-123/GUG-124, and GUG-125 live enablement.

## Authorization chain

```text
manifest v2 target assertions
          |
          v exact equality
approved deployment target <---- independent registry version/digest anchor
          |
account-baseline exact readback
          |
          v deterministic repository-only producer
content-addressed ACCOUNT_READY v2
          |
          +---- target v2 runtime-origin v1 (domain-owning layers)
          |
          +---- exact ACCOUNT_READY v2 digest and state binding
          |
          +---- held deployment execution lock for exact registry digest
          |
          +---- canonical DAG state-key template
          v
private temporary S3 backend config -> terraform init -reconfigure
```

Every arrow is mandatory. A request field, environment variable, workflow
input, local path, legacy manifest, bucket name convention, AWS profile name,
or previous successful run cannot replace any proof.

## Contracts

| Contract | Purpose | Authority boundary |
|---|---|---|
| `deployment-manifest.v2` | operator intent and target assertions | never backend authority |
| `deployment-target.v1` | historical approved target and immutable state binding | controlled registry record; accepted only by layers without runtime-origin ownership |
| `deployment-target.v2` | v1 bindings plus immutable `runtime_origin/v1` | controlled registry record required by identity, API-edge and frontend-edge |
| `deployment-target-anchor.v1` | separately retrieved version/digest | prevents self-asserted registry records |
| `account-ready.v2` | account/baseline/security evidence | account vending owner |
| `deployment-execution-lock.v1` | one active execution per deployment | conditional registry write |
| `terraform-backend-binding.v1` | exact derived backend receipt for target v1 | generated only after all checks |
| `terraform-backend-binding.v2` | v1 receipt plus digest-bound `runtime_origin/v1` | generated only from target v2 after all checks |

The v1 deployment manifest and `ACCOUNT_READY` v1 remain explicit legacy
schemas. They are not accepted by `authorize_deployment_backend.py`.

## Greenfield ACCOUNT_READY producer

There is one repository producer: `python -m
tooling.account_ready_v2_materializer`. It accepts a closed readback from the
reviewed account-baseline template, the exact approved deployment target, and
the independently retrieved target anchor. It validates the complete
customer/deployment/account/region/environment tuple, all eight terminal role
ARNs and resource tags, the four bucket and three KMS bindings, and all six
state controls before calculating the canonical digest.

The producer has no AWS SDK import, subprocess path, environment/profile
fallback, resource-discovery path, v1 conversion, or overwrite behavior. It
requires readback bucket outputs to equal the template's four deterministic
name invariants; equality never proves live existence or ownership. Outputs are
new owner-only files outside the repository. Repeated identical input produces
identical contract and sanitized manifest bytes at fresh output paths; any
pre-existing output path is a stop condition.

The operator manifest never contains account IDs, ARNs, bucket names, state
keys, KMS identifiers, targets, anchors, or lock payloads. It labels repository
provenance `NOT_PROVEN_LIVE`. A future human account-vending operation and
readback require a separate issue-scoped, time-bounded authorization.

## Operational inputs

The plan wrapper requires owner-only files outside Git for the manifest,
registry record, registry anchor, ACCOUNT_READY contract, execution lock, and
GUG-121 contract resolution. It also requires caller assertions for customer,
deployment, account, region, release, and execution. Assertions are compared
to the authorized records and never override them. For domain-owning roots,
`environment` and `domain_name` are then materialized from the generated
binding rather than the manifest or command line.

The wrapper performs these steps before plan:

1. validate every schema and canonical digest;
2. compare the registry record with its independent anchor;
3. verify exact ownership, target lifecycle, baseline controls, and role tags;
4. verify the held execution lock, five-to-sixty-minute TTL, and non-future
   acquisition time;
5. compare the exact caller assertions and derive one state key from
   `deployment/layers.yaml`;
6. render a mode-0600 backend configuration and binding;
7. verify the actual AWS caller account;
8. validate/materialize the GUG-121 contract resolution;
9. run `terraform init -reconfigure` with the derived S3 backend; and
10. delete temporary backend, binding, and variable files on every exit path.

Identity-control-plane, edge-identity and edge require target/binding v2. A v1
target may be migrated once by exact version/digest CAS: preserve status and
every existing target field, add only closed `runtime_origin/v1`, increment
`registry_version`, and recompute `record_digest`. The registry anchor and any
execution lock for the old digest are stale after migration; both must be
retrieved/acquired again for the new digest. Ordinary lifecycle updates cannot
change the runtime origin.

The top-level `plan-layer` and `deploy-services` planning entrypoints do not
perform their own AWS lookup before step 1. Invalid registry/backend evidence
therefore creates zero AWS and zero Terraform subprocesses. Dry-run remains
zero-AWS and zero-mutation.

## Released-lock transitions

Deployment, account, and region remain immutable for every lock lifecycle. A
HELD lock also keeps its registry digest immutable and cannot be stolen when
expired. A RELEASED lock may be reacquired with the current registry digest
after an authorized registry transition when the request supplies the exact
prior `lock_version`. The result increments the version once, carries the new
digest, and recomputes `lock_digest`; stale replays and malformed evidence fail
closed. Same-digest RELEASED reacquisition remains supported.

## Negative behavior

The authorizer denies request-supplied backend coordinates, duplicate JSON/YAML
keys, missing v2 evidence, altered digests, anchor/version mismatch, wrong or
missing owner, suspended/offboarding/archived targets, foreign baseline roles,
bucket/KMS mismatch, region or runtime-origin mismatch, target v1 for a
domain-owning layer, unsafe state-key templates, key
collisions, expired/released/foreign execution evidence, and unknown fields.

Errors identify the failed invariant but do not print record contents, backend
coordinates, ARNs, state keys, tokens, plans, state, or customer data.

## Evidence boundary

Repository and CI evidence may include test counts, schema names, opaque
digests, commit SHA, and pass/fail status. Full registry records, backend files,
state keys, KMS identifiers, plans, state, lock payloads, AWS outputs, and live
account identifiers remain only in approved encrypted systems.

## Current gate

- Implemented: candidate code and contracts.
- Locally validated: offline synthetic tests only; no AWS or live Terraform.
- CI validated: pending PR.
- Live validated: no.
- Production: **NO-GO**.

GUG-379 requires exactly one independent code review from `@guguce-google` on
the exact final head. This repository review does not satisfy any future AWS,
stale-lock recovery, saved-plan, deployment, or production approval.
