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
| `deployment-target.v1` | approved target and immutable state binding | controlled registry record |
| `deployment-target-anchor.v1` | separately retrieved version/digest | prevents self-asserted registry records |
| `account-ready.v2` | account/baseline/security evidence | account vending owner |
| `deployment-execution-lock.v1` | one active execution per deployment | conditional registry write |
| `terraform-backend-binding.v1` | exact derived backend receipt | generated only after all checks |

The v1 deployment manifest and `ACCOUNT_READY` v1 remain explicit legacy
schemas. They are not accepted by `authorize_deployment_backend.py`.

## Operational inputs

The plan wrapper requires owner-only files outside Git for the manifest,
registry record, registry anchor, ACCOUNT_READY contract, execution lock, and
GUG-121 contract resolution. It also requires caller assertions for customer,
deployment, account, region, release, and execution. Assertions are compared
to the authorized records and never override them.

The wrapper performs these steps before plan:

1. verify the AWS caller account;
2. validate every schema and canonical digest;
3. compare the registry record with its independent anchor;
4. verify exact ownership, target lifecycle, baseline controls, and role tags;
5. verify the held execution lock, five-to-sixty-minute TTL, and non-future
   acquisition time;
6. derive one state key from `deployment/layers.yaml`;
7. render a mode-0600 backend configuration and binding;
8. validate/materialize the GUG-121 contract resolution;
9. run `terraform init -reconfigure` with the derived S3 backend; and
10. delete temporary backend, binding, and variable files on every exit path.

## Negative behavior

The authorizer denies request-supplied backend coordinates, duplicate JSON/YAML
keys, missing v2 evidence, altered digests, anchor/version mismatch, wrong or
missing owner, suspended/offboarding/archived targets, foreign baseline roles,
bucket/KMS mismatch, region mismatch, unsafe state-key templates, key
collisions, expired/released/foreign locks, and unknown fields.

Errors identify the failed invariant but do not print record contents, backend
coordinates, ARNs, state keys, tokens, plans, state, or customer data.

## Evidence boundary

Repository and CI evidence may include test counts, schema names, opaque
digests, commit SHA, and pass/fail status. Full registry records, backend files,
state keys, KMS identifiers, plans, state, lock payloads, AWS outputs, and live
account identifiers remain only in approved encrypted systems.

## Current gate

- Implemented: candidate code and contracts.
- Locally validated: offline synthetic tests only.
- CI validated: pending PR.
- Live validated: no.
- Production: **NO-GO**.
