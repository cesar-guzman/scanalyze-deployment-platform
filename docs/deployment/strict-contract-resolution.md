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
- active resolution: `schemas/contract-resolution.v2.schema.json`
- retained historical resolution: `schemas/contract-resolution.v1.schema.json`
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

## Effective plan-input invariant

The only accepted contract-derived variables are:

```text
deterministic_projection(
  validated resolution-v2 contract envelopes,
  deployment/contract-catalog.v1.json
)
```

The wrapper adds only its explicit, target-validated deployment, account,
region, customer, release-version, and release-digest arguments. Variable names
alone are not evidence. Resolution v2 therefore carries canonical Terraform
contract envelopes and has no materialized `variables` field. The shared
projector revalidates each output schema/digest and reconstructs:

- `metadata_variables` from authoritative envelope metadata;
- `output_variables` from schema-validated canonical outputs, preserving JSON
  types;
- `contract_variable` from authoritative envelope metadata plus canonical
  outputs.

Resolution v1 cannot prove all three binding kinds and is rejected by the active
path even when a caller explicitly supplies its historical schema.

The canonical DAG may also declare external, non-Terraform contracts such as
`release-manifest/v1` and `identity-contract/v2`. The current projection filters
those records rather than validating them. That pre-existing P2 gap remains
explicitly out of scope for GUG-121 and must not be interpreted as verified
external-contract evidence.

## Terraform environment boundary

`terraform-layer.sh` enumerates exported variable names and rejects every
ambient `TF_*` before backend authorization, AWS identity lookup, Terraform
init, or Terraform plan. This includes all current/future `TF_VAR_*`,
`TF_CLI_ARGS*`, `TF_WORKSPACE`, `TF_REATTACH_PROVIDERS`,
`TF_CLI_CONFIG_FILE`, `TF_DATA_DIR`, plugin-cache, and logging inputs.
Rejections identify only the variable name.

Terraform receives an empty child environment with a wrapper-owned empty CLI
configuration, canonical automation/input settings, explicit region, and a
documented allowlist of AWS/OIDC process inputs. Unexpected
Terraform inputs are rejected, not silently removed.

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
  catalog producer;
- legacy resolution schema, duplicated materialized variable authority, or
  any ambient Terraform-specific environment variable.

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

Replaced layer-contract v1 schemas and `contract-resolution.v1` remain available
only for explicit historical rollback evidence. The active resolver emits only
resolution v2; the active validator never converts or accepts v1. Do not
overwrite an old digest, repoint a mutable alias, infer fields, or silently
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

Before an authorized engine consumes v2, revert the remediation commit and
remove only unpublished temporary resolution and var files. Do not reactivate
resolution v1 as an implicit fallback. If an authorized engine has consumed v2,
retain immutable evidence and use a reviewed forward fix or explicit version
rollback. Never delete a published generation or state object.
