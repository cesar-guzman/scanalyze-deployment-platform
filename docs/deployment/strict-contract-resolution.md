# Strict Contract Resolution Runbook (GUG-121)

## Purpose and status

This runbook describes the repository-only, fail-closed handoff from a
Terraform producer to a consumer. It performs no AWS write, SSM publication,
backend initialization, plan apply, deployment, migration, or production
operation. Production remains **NO-GO**.

## Authoritative files

- DAG: `deployment/layers.yaml`
- producer/consumer registry: `deployment/contract-catalog.v1.json`
- envelope: `schemas/layer-contract.v2.schema.json`
- resolution: `schemas/contract-resolution.v1.schema.json`
- publisher: `scripts/deployment/publish-contract.py`
- resolver: `scripts/deployment/resolve-contracts.py`
- pre-plan guard: `scripts/deployment/validate-contract-resolution.py`
- plan wrapper: `scripts/deployment/terraform-layer.sh`

## Offline test-vector flow

1. Run Terraform in a reviewed offline or synthetic provider harness.
2. Save `terraform output -json` outside the repository.
3. Compute the immutable module source digest from the reviewed source bundle.
4. Run `publish-contract.py` with exact customer, deployment, account, region,
   immutable release version and digest, state key, timestamp, output schema version, and module
   source digest.
5. Run `resolve-contracts.py --allow-fixtures` for the exact target layer and
   every Terraform contract required by the DAG.
6. Pass the resulting mode-0600 artifact to `terraform-layer.sh` using
   `--resolved-input`.

Fixture acknowledgement is deliberately named and test-only. `--live` stops
before I/O because GUG-125 owns the protected SSM resolver.

## Failure behavior

Stop before plan when any of the following occurs:

- missing, duplicate, undeclared, or extra required contract;
- producer, layer, schema, scope, state key, or consumer mismatch;
- customer, deployment, account, region, release version, or release digest mismatch;
- missing or wrong module source digest;
- output-schema failure or altered output digest;
- stale or future-dated contract;
- catalog binding to a missing source or duplicate destination variable;
- resolution stored in the repository, weak file permissions, wrong target
  tuple, altered resolution digest, non-canonical contract set, or wrong
  catalog producer.

Do not retry by changing expected digests, copying values from state, setting
environment variables, or adding defaults. Rebuild the producer contract from
the reviewed root or quarantine the generation.

## Migration and coexistence

| Layer | Active output contract |
|---|---|
| global | `global/v1` |
| network | `network/v2` |
| platform | `platform/v2` |
| data-foundation | `data-foundation/v2` |
| cicd | `cicd/v2` |
| identity-control-plane | `identity-control-plane/v1` |
| services | `services/v2` |
| edge-identity | `edge-identity/v2` |
| edge | `edge/v2` |
| addons | `addons/v2` |

Replaced v1 schemas remain available only for explicit rollback evidence. Do
not overwrite an old digest, repoint a mutable alias, infer fields, or silently
convert a v1 payload into v2. A version transition requires an updated DAG,
catalog, producer, consumer, schema, test vector, and reviewed PR.

## Evidence handling

Retain only sanitized command results and digests. Never publish contract
contents, Terraform variables, state, plans, credentials, JWTs, customer data,
documents, or provider responses to Linear, PR comments, or logs.

Classify evidence separately as Implemented, Locally validated, CI validated,
Live validated, Blocked, and Production NO-GO. Local fixtures and offline
Terraform tests are never live validation.

## Rollback

Revert the GUG-121 commit and remove any unpublished temporary resolution and
var files. Do not delete a published generation or state object. If a future
authorized engine has already published a contract, retain it as immutable
evidence and select a reviewed prior generation by exact version and digest.
