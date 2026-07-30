# GUG-122 threat-model delta

Production: **NO-GO**. Evidence below is code and synthetic offline validation,
not live control effectiveness.

| Threat | Control | Negative evidence |
|---|---|---|
| operator supplies foreign backend | manifest v2 forbids backend fields; backend derived from target + baseline + DAG | injected bucket/key rejected |
| forged registry record redirects execution | canonical digest plus independent version/digest anchor | altered or unanchored record denied |
| cross-customer/deployment/account/region plan | exact equality across manifest, target, ACCOUNT_READY, roles, lock, KMS | each conflicting binding denied |
| legacy or weak account baseline | ACCOUNT_READY v2 requires exact ownership and six state controls | missing/false/mismatched control denied |
| state-key collision/path traversal | one canonical DAG template per Terraform layer and deployment prefix validation | distinct deployments differ; traversal denied |
| concurrent execution | conditional deployment lock plus S3-native per-key lockfile | held lock denies second owner |
| registry transition strands released lock | RELEASED may adopt the current authorized registry digest only with exact prior-version CAS and unchanged deployment/account/region | READY→ACTIVE succeeds once; stale replay and foreign identity fail |
| held-lock digest substitution | registry digest remains immutable while HELD | changed digest denied for active and expired held locks |
| stale/future lock takeover | only a non-future five-to-sixty-minute lock is executable; expiry never authorizes automatic acquisition | future, out-of-range, and expired held locks are denied |
| registry enumeration or uncontrolled mutation | no DynamoDB Scan/Delete; leading-key IAM condition; create-only/CAS model | policy and transition tests |
| recovery inventory escapes deployment | exact bucket/prefix/session conditions plus `ListBucketVersions`; no bucket wildcard or version delete | structural allow/deny policy test |
| destructive recovery | recovery delete limited to exact `.tflock`; state restore is put-only and tagged | arbitrary/state/version deletion denied |
| STS or Terraform before authorization | child backend authorizer is canonical and precedes caller lookup; `plan-layer` and `deploy-services` perform no early STS | invalid target/anchor/baseline/lock evidence reaches zero fake subprocesses |
| sensitive evidence leakage | private temporary files, cleanup trap, sanitized errors/evidence boundary | rejected values and backend coordinates absent from entrypoint output |

## Residual risks and downstream ownership

- ADR-031/GUG-123 now define the candidate GitHub Environment/OIDC/IAM identity
  and separate human recovery trust; authorized live retrieval, tag issuance,
  and AWS evaluation remain unvalidated.
- GUG-124 must bind the exact saved plan and supply-chain evidence to these
  digests.
- GUG-125 must implement and exercise the live registry/lease adapter and
  non-production backend initialization/recovery path.
- Account vending must emit authentic ACCOUNT_READY v2. Hashes alone do not
  prove writer authority.
- No AWS control was inspected or changed in GUG-122.
- Repository tests use only synthetic identifiers and fake AWS/Terraform
  executables; no cloud identity or backend was contacted.

Any uncertainty in target ownership, backend binding, encryption, lock owner,
state version, or recovery authority is fail-closed and keeps production
**NO-GO**.
