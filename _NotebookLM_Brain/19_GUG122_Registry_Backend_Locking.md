# GUG-122 — Registry, account baseline, backend, and locking

This sanitized source explains the candidate GUG-122 control boundary. It is
not an operational record, a backend configuration, or deployment authority.

Scanalyze now models a backend authorization chain in which manifest v2 carries
intent but cannot carry Terraform backend coordinates. An approved deployment
target, a separately retrieved registry anchor, ACCOUNT_READY v2, a held
deployment execution lock, and the canonical layer DAG must agree exactly.
Only then may a private temporary S3 backend configuration be derived.

The backend uses SSE-KMS, one allowed account, a deployment/region/layer state
key, and S3-native lockfiles. The full binding is removed after the plan path.
Registry updates are immutable and compare-and-swap. Concurrent or expired held
locks deny execution; locks are non-future and bounded to five-to-sixty minutes,
and expiry does not authorize automatic takeover. New registry contracts accept
multi-segment AWS partitions without inferring a commercial ARN.

Legacy v1 manifests, ACCOUNT_READY v1, DynamoDB lock configuration, unbound
buckets, inferred prefixes, and automatic force-unlock are migration-required
and denied on the candidate path. No live inventory or migration was run.

Evidence classification:

- Implemented: candidate contracts, authorizer, transition models, policies,
  wrapper integration, tests, ADR, runbook, and threat delta.
- Locally validated: synthetic offline tests only.
- CI validated: pending the exact PR commit.
- Live validated: no.
- Production: NO-GO.

Do not ingest registry records, backend files, state keys, ARNs, plans, state,
lock payloads, account inventories, screenshots, logs, or customer data into
NotebookLM.
