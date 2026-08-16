# GUG-107 contract-reader reconciliation

## Disposition

`SOURCE_OBSERVED`: the historical employee-profile contract-reader failures do not reproduce on the current repository baseline. The historical cohort is classified `ALREADY_RESOLVED`; this does not recover the identities of the 18 original failures.

The missing checked-in regression for the four supported locator readers was `REPRODUCED` as a coverage gap and is addressed by `backend/workers/scanalyze-ingest-api/tests/test_gug107_contract_readers.py`. No production behavior changed.

## Evidence

| Evidence cut | Revision | Employee-profile suite | Four-reader smoke | Full ingest-api suite | Skips |
|---|---|---:|---:|---:|---:|
| Historical Linear comment | `main@f7790a7` | 52 passed | 4/4 passed | 214 passed | not recorded |
| Current pre-edit | `c82f22a38de56125dfd7eac52efae8b414a47b3c` (tree `2aeb2311208ccec4a51c0566d6d1665e65b2baa4`) | 52 passed | 4/4 passed | 1,069 passed | 0 |

The current full-suite run used the repository Python 3.11 virtual environment, disabled EC2 metadata, set `us-east-1`, and ran `pytest backend/workers/scanalyze-ingest-api/tests -q -p no:cacheprovider`. It completed with 1,069 passes, zero skips, and one Starlette `PendingDeprecationWarning`.

## Historical cohort matrix

The available source records only a cohort count; assigning identifiers or per-failure causes would invent evidence.

| cohort | count | individual_identity | current classification | basis |
|---|---:|---|---|---|
| Historical employee-profile contract-reader failures | 18 | `NOT_PROVEN` | `ALREADY_RESOLVED` | Current focal, inline four-reader, and full ingest-api runs did not reproduce a functional failure. |

## Four-reader matrix

| Reader path | Pre-edit inline smoke | Checked-in regression |
|---|---|---|
| `stages.persist.artifactRef` | PASS | `stages-persist-artifact-ref` |
| `artifacts.structured` | PASS | `artifacts-structured` |
| `artifacts.result` | PASS | `artifacts-result` |
| top-level `structured` | PASS | `top-level-structured` |

Each regression case verifies the owner-bound locator validation call and the exact S3 JSON read arguments using synthetic values only.

## Remaining gaps

- `VERSIONING_GAP` / `REQUIRES_SEPARATE_ISSUE`: `_load_structured_artifact` does not reject missing or incompatible `schemaVersion` or `contractVersion` values. Closing that gap requires a canonical producer/consumer version contract and production changes under `app/**`, which are forbidden in GUG-107.
- Fixtures and schemas versioned and exercised by exact-head CI: `NOT_PROVEN`. This change adds no fixture or schema and has no CI result yet.
- Image and runtime consuming the tested contract: `NOT_PROVEN`. The observed smoke was in-process and synthetic; no container build or runtime execution was performed.
- AWS, deployment, staging, and production behavior: `NOT_PROVEN` and out of scope.

## Acceptance mapping

| Linear acceptance criterion | Disposition | Evidence or next boundary |
|---|---|---|
| Classify the 18 historical failures | PARTIAL | Cohort classified `ALREADY_RESOLVED`; individual identities remain `NOT_PROVEN`. |
| Contract-reader suite green without general skips | `SOURCE_OBSERVED` | 52 focal passes, 4/4 reader smoke passes, and 1,069 ingest-api passes; zero skips. |
| Incompatible versions fail explicitly | `NOT_PROVEN` | `VERSIONING_GAP`; requires a separate issue because production edits are forbidden here. |
| Versioned fixtures and schemas covered by CI | `NOT_PROVEN` | No fixture/schema change and no exact-head CI evidence in this local cut. |
| Image and runtime consume the tested contract | `NOT_PROVEN` | No container/runtime execution. |
| Documentation and changelog reflect canonical state | PARTIAL | This reconciliation document records the current state; no changelog edit is authorized. |

## Scope and rollback

`SOURCE_OBSERVED`: this package adds only the focused regression test and this document. It does not modify production code, `backend/workers/scanalyze-ingest-api/README.md`, a changelog, AWS, cloud resources, deployment configuration, staging, or production.

Before commit, rollback is deletion of exactly these two added files:

- `backend/workers/scanalyze-ingest-api/tests/test_gug107_contract_readers.py`
- `docs/testing/gug-107-contract-reader-reconciliation.md`

After commit, rollback is a reviewed `git revert` of the GUG-107 commit; do not rewrite history.
