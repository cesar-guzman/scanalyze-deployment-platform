# GUG-121 Threat Model Delta — Verified Terraform Plan Inputs

Production status: **NO-GO**. This delta covers repository behavior only.

## Classification

| Threat or regression vector | Classification | Control or evidence |
|---|---|---|
| Missing `TF_VAR_*` silently changes a plan | rejected by shell environment guard | Every ambient `TF_*` name is rejected before backend, AWS, or Terraform. |
| `TF_VAR_*` overrides a reconstructed contract value | rejected by shell environment guard | Ambient Terraform inputs never reach materialization or the Terraform child. |
| `TF_CLI_ARGS` adds `-var`, `-var-file`, or other flags | rejected by shell environment guard | The parent input is rejected by name and Terraform receives a controlled child environment. |
| `TF_CLI_ARGS_plan` adds `-target`, `-replace`, or `-destroy` | rejected by shell environment guard | The parent input is rejected before any subprocess. |
| `TF_WORKSPACE` changes state selection | rejected by shell environment guard | All ambient `TF_*` names fail closed. |
| `TF_REATTACH_PROVIDERS` injects provider endpoints | rejected by shell environment guard | All ambient `TF_*` names fail closed. |
| `TF_CLI_CONFIG_FILE`, `TF_DATA_DIR`, or plugin-cache settings redirect Terraform | rejected by shell environment guard | Parent values are rejected; the child receives a wrapper-owned empty CLI configuration and temporary home. |
| `TF_LOG` or `TF_LOG_PATH` exposes sensitive inputs | rejected by shell environment guard | Logging variables are rejected and only rejected names appear in diagnostics. |
| A future, unknown `TF_VAR_*` bypasses an enumerated denylist | rejected by shell environment guard | Prefix-based rejection covers the entire exported `TF_*` namespace. |
| Contract metadata is changed and the resolution digest is recomputed | rejected by deterministic semantic validation | Resolution v2 retains full contract evidence; tuple, ownership, state, freshness, schema, output, and digest invariants are revalidated before projection. |
| Contract output is changed and the resolution digest is recomputed | rejected by deterministic semantic validation | The embedded output schema and canonical output digest are revalidated before values are reconstructed. |
| A typed projection is changed independently of its source contract | rejected by schema | Resolution v2 contains no materialized variable map; typed objects are reconstructed from authoritative envelope evidence. |
| Attacker-controlled duplicate representations or JSON object keys disagree | rejected by schema | There is one accepted evidence representation, no second `variables` authority, and the shared JSON loader rejects duplicate keys. |
| A forged per-variable digest blesses an attacker value | not applicable | Per-variable digests are not an authority or part of the accepted v2 representation. |
| Two bindings write the same destination variable | rejected by deterministic semantic validation | Shared projection rejects duplicate destination variables before materialization. |
| Wrong contract, producer, schema, release, target, or state is supplied | rejected by deterministic semantic validation | Exact catalog/DAG set, producer, schema, release, customer/deployment/account/region, state key, and consumer checks fail closed. |
| Output type confusion changes Terraform semantics | rejected by schema | Outputs are validated against the declared output schema and JSON types are preserved through canonical projection. |
| A caller downgrades to resolution v1 | rejected by deterministic semantic validation | The active resolver emits only v2 and the active validator explicitly rejects every non-v2 resolution even when given a legacy schema path. |
| Extra or missing contract-derived variables alter a plan | rejected by deterministic semantic validation | The shared catalog projection is the complete set; missing sources and unexpected or duplicate bindings fail closed. |
| Symlink, in-repository path, or permissive artifact mode is used | rejected by deterministic semantic validation | Resolution evidence must be a non-symlink regular owner-only file outside the repository; materialization is exclusive and cannot overwrite an existing path. |
| Temporary artifacts survive success or failure | rejected by deterministic semantic validation | Wrapper cleanup removes only its exact resolution-derived tfvars, backend, CLI configuration, and temporary home paths on exit or signal. |
| Error text discloses rejected values | rejected by deterministic semantic validation | Errors identify invariant and variable name only; adversarial tests assert marker values are absent. |
| Authorization occurs after an untrusted subprocess | rejected by shell environment guard | Ambient validation precedes option processing that could reach backend authorization, AWS identity, or Terraform. |
| Different parsers interpret the same evidence differently | rejected by deterministic semantic validation | Resolver and pre-plan validator share the same duplicate-rejecting JSON loader, canonical projection, and digest implementation; JSON schema and semantic checks both run. |
| Valid single- and multi-upstream deployments regress | rejected by deterministic semantic validation | Positive tests cover one upstream, multiple upstreams, metadata, output, typed-object bindings, and JSON scalar/collection/null types. |

## Residual and deferred boundaries

| Boundary | Classification | Owner |
|---|---|---|
| Authenticate the terminal contract writer | deferred GUG-123/124/125 | GUG-123 owns terminal IAM; GUG-124 owns signed provenance and exact digest binding. |
| Read or publish immutable live contracts and run an authorized plan | deferred GUG-123/124/125 | GUG-125 owns the protected live engine and publication/read path. |
| Prove provider/backend behavior in a non-production AWS environment | deferred GUG-123/124/125 | Requires a separately authorized downstream validation package. |
| Validate external non-Terraform DAG contracts | not applicable | `release-manifest/v1` and `identity-contract/v2` remain a known out-of-scope P2; this package neither closes nor regresses that gap. |

The resolution digest detects alteration but is not a signature and does not
authenticate its writer. GUG-121 establishes deterministic repository
reconstruction, not provenance, live authorization, or deployment authority.

No AWS, SSM, Terraform provider, remote backend, plan/apply, data migration,
customer document, real token, or production validation is included here.
