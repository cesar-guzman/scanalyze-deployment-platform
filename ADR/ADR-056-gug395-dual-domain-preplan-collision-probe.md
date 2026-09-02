# ADR-056: Attested Dual-Domain Pre-Plan Collision Probe

- **Status:** Proposed repository implementation; connected run not executed
- **Date:** 2026-08-28
- **Implementation issue:** GUG-376
- **Seed contract:** GUG-395
- **AWS live validation:** None
- **AWS mutations:** None
- **Production:** **NO-GO**

## Context

ADR-055 removed the causal cycle between the GUG-376 foundation and the
post-run GUG-393/GUG-392 exact inventory. Its next causal step is a bounded
pre-plan collision probe that works only from source-bound names and tags. It
must not require provider-generated ARNs and must not relabel the post-run
collectors as pre-plan evidence.

An offline seed, a merged PR, a stable name or a matching tag cannot prove
absence. Conversely, a resource that appears compatible cannot be adopted:
ownership, creator identity and a complete mutation transcript are not
established by tags.

Traditional S3 bucket names use the global namespace. For those names,
`s3:ListAllMyBuckets` sees only the authenticated account and `HeadBucket`
`400`, `403`, and `404` responses cannot distinguish a missing bucket from an
inaccessible bucket. Therefore this probe does not use a traditional global
name and does not call `HeadBucket`.

The artifact bucket instead uses S3's account-regional namespace. Its exact
form is
`scanalyze-g376-art-<12 lowercase hex>-042360977644-us-east-1-an`, and the
future create request must set `BucketNamespace=account-regional`. AWS reserves
that account-and-region suffix to the named account. A complete regional
`ListBuckets` stream can therefore prove whether that account already owns the
exact reserved name without making a mutation or interpreting an ambiguous
negative response.

## Decision

### 1. Consume the private GUG-395 seed and pending plan without promotion

The probe consumes and validates the exact private seed and mutation plan. It
binds their digests, the predecessor source commit/tree, the current clean
fetched `origin/main` commit/tree, all owner decisions, the operational host,
the private custody root, the authenticated SDK runtime, two direct SSO
profiles, closed policies, a maximum fifteen-minute window and one reviewed
budget.

The seed and plan remain unchanged. They continue to state
`live_execution_ready=false`, `aws_mutations=0`,
`deployment_authorized=false` and `production_status=NO-GO`.

### 2. Probe seven source-bound targets

The exact target catalog is:

| Domain | Target | Selector |
|---|---|---|
| Authority | Artifact bucket | Account-regional bucket name, namespace and expected tag digest |
| Authority | KMS key | Exact alias or expected tag digest |
| Authority | Signing profile | Exact profile name or expected tag digest |
| Authority | Lambda code-signing config | Expected tag digest |
| Identity Center | Application | Exact instance plus name or expected tag digest |
| Identity Center | Classifier permission set | Exact instance plus name or expected tag digest |
| Identity Center | Approver permission set | Exact instance plus name or expected tag digest |

Authority resources use the additive future-mutation tag contract
`ScanalyzeIssue=GUG-376`. Identity Center uses the existing closed five-tag
contract: `managed_by=identity-center`,
`service=scanalyze-platform-authority`, `work_package=GUG-376`,
`environment=non-production` and `production=false`.

Any name, alias or tag match is `COLLISION_BLOCKED_NO_MUTATION`, including an
exact tag match. The probe never adopts, repairs, deletes, retags or reuses a
matching resource.

### 3. Use one exact read-only action surface

Authority permits only:

```text
sts:GetCallerIdentity
s3:ListAllMyBuckets
s3:GetBucketTagging
kms:ListAliases
kms:ListKeys
kms:DescribeKey
kms:ListResourceTags
signer:ListSigningProfiles
signer:GetSigningProfile
signer:ListTagsForResource
lambda:ListCodeSigningConfigs
lambda:GetCodeSigningConfig
lambda:ListTags
```

Identity Center permits only:

```text
sts:GetCallerIdentity
sso:ListInstances
sso:ListApplications
sso:DescribeApplication
sso:ListPermissionSets
sso:DescribePermissionSet
sso:ListTagsForResource
```

The deployable Identity Center IAM template also includes the service's
indirect `kms:Decrypt` dependency for CMK-backed metadata. It is restricted to
the exact `${identity_center_kms_key_arn}`, management account,
`sso.us-east-1.amazonaws.com`, the exact Identity Center instance encryption
context and the same window. The adapter never constructs a KMS client or
dispatches a KMS operation; this dependency is not part of the request's SDK
operation allowlist.

No wildcard operation is accepted. The request-bound documents are local SDK
operation contracts; they are not attached IAM policies and do not prove the
profiles' effective permissions. The two checked-in IAM templates are
separate deployable examples. A connected run still requires dedicated
profiles whose effective permissions have been independently shown to match
the reviewed read-only surface. `sts:GetCallerIdentity` is the first signed
call in each of four independent sessions. SDK retries and automatic S3
regional redirection are disabled. The two profiles must be distinct,
non-default, direct SSO, read-only and bound to different expected accounts
and exact expected role/principal digests.

### 4. Bound pages, resources, responses, network attempts and modeled cost

The global four-session budget stops before an over-limit call:

- 50 pages per stream;
- 2,048 provider calls and 1,024 page calls;
- exactly four session-bootstrap attempts, zero to four actual cached-or-live
  credential-vending calls, and at most 2,052 network calls;
- 256 KiB per projected response and 16 MiB total;
- 256 filtered bucket summaries before exact-match tag read, 256 KMS keys,
  256 signing profiles,
  256 code-signing configs, 256 applications and 512 permission sets; and
- a conservative modeled upper cost of USD 0.05.

The artifact query is always a complete paginated `ListBuckets` stream with
the exact `Prefix`, `BucketRegion=us-east-1`, and a bounded `MaxBuckets`.
Every returned candidate must carry `BucketRegion=us-east-1`. Only an exact
name match is tagged, and that `GetBucketTagging` request includes
`ExpectedBucketOwner=042360977644`. Complete zero exact matches is absence for
this reserved account-regional name; an exact match is a collision regardless
of its tags. No negative `HeadBucket` result participates in the decision.

Repeated tokens, incomplete pagination, malformed responses, access denial,
timeouts, an expired window or a resource cap are never absence.
Signer inventory explicitly requests `Active`, `Canceled` and `Revoked`
profiles; every retained exact-name or reviewed-tag match remains a collision.

### 5. Require two stable snapshots per domain

The probe opens two independent Authority sessions and two independent
Identity Center sessions. Snapshot identities and snapshot digests must be
distinct, while the semantic facts digest in each domain must match.

The public contract defines these classifications:

- `ABSENT_READY_FOR_PROVIDER_IMPLEMENTATION`: all seven targets are absent,
  the expected Identity Center instance is ready, both pairs are stable and
  all evidence/budgets are complete;
- `COLLISION_BLOCKED_NO_MUTATION`: at least one target is present in stable,
  complete evidence; or
- `UNCERTAIN_RECONCILE_ONLY`: any partial, unstable, ambiguous or prerequisite
  failure. Uncertainty dominates collision; collision dominates absence.

Even the absent result authorizes no mutation. It only permits review of the
next provider implementation iteration.

The concrete provider can emit the absent classification only because the
request binds the account-regional namespace, exact account and region, exact
name pattern, complete filtered pagination and expected-owner tag read. A
traditional global bucket selector, missing namespace binding, different
account or region, unbounded request, partial page stream, or any attempted
`HeadBucket` substitution fails closed.

### 6. Preserve private facts and publish only digests

The private root must be outside Git and synced/File Provider storage, mode
`0700`. Request and claim are single-link regular files, mode `0600`, written
create-only and read back. The authoritative result is one create-only atomic
bundle containing private evidence, its deterministic public projection and
bindings to the exact private-root, request and claim digests; reading or
copying the bundle without that same custody fails closed. Each snapshot also
binds the exact transcript segment for its direct-SSO session. Two separately
published evidence files are not treated as an atomic commit. A claim is
consumed before SDK construction; failed or ambiguous work is sealed as a
blocked reconciliation result when custody remains writable and is never
retried under the same request.

The public receipt contains only source bindings, canonical digests, scalar
counters and classification. It contains no profile, account ID, ARN, target
name, tag value, private path, credential or provider payload.
For a blocked attempt it deliberately sets AWS-call count, network-call count
and modeled-cost upper bound to `null`, because an SDK timeout or pre-send
failure cannot prove those values. The CLI emits that receipt but exits
non-zero so automation cannot mistake preserved failure evidence for success.

For every string binding, `canonical_digest(string)` means SHA-256 over the
canonical JSON serialization of that string, including JSON quoting and
escaping; it is not SHA-256 over the raw unquoted bytes. Each
`authority_verification_digest` must originate from the independently reviewed,
owner-private effective-authority evidence for that exact profile and window.
It is not the digest of either checked-in template and must not be invented as
an arbitrary label.

IAM Identity Center can require that dependent `kms:Decrypt` permission for
some List/Describe reads when the instance uses a customer managed key. The
checked-in template closes it with the exact key and context above, but the
template alone is not effective-authority evidence. A missing/mismatched key,
context or grant is `UNCERTAIN_RECONCILE_ONLY`; it cannot be repaired by
broadening the running request.

## Consequences

- The causal step between the offline seed and the future mutation provider is
  implemented as a separately reviewable read-only boundary.
- A connected run still requires a fresh exact authorization for both profile,
  account, role, region and action sets. This ADR grants none.
- The fourteen missing provider-slot routes, Identity Center actor-policy gap,
  thirty-operation mutation adapter, action-time phase authorization, durable
  nine-phase executor, terminal verifier/minter, staging and production pilot
  remain outside this change.
- Repository tests use injected fakes only and truthfully report
  `AWS_CALLS=0`, `AWS_MUTATIONS=0` and `LIVE_PROVIDER_NOT_PROVEN`.
- Production remains **NO-GO**.

## Rollback and recovery

Before any connected run, rollback is a reviewed Git revert. No cloud rollback
exists because the implementation is read-only.

After a request is claimed, preserve the private request, claim and any partial
evidence. Do not delete a claim to retry. A new run requires a new reviewed
window and a new create-only request. A detected collision is resolved only by
a separately reviewed decision; this probe never performs cleanup.

```text
PREPLAN_COLLISION_PROBE=REPOSITORY_IMPLEMENTED
CONNECTED_RUN=NOT_EXECUTED
AWS_CALLS=0
AWS_MUTATIONS=0
DEPLOYMENT_AUTHORIZED=false
PRODUCTION=NO-GO
```

## References

- [ADR-055](ADR-055-gug395-preplan-seed-and-downstream-materialization.md)
- [GUG-376 deployment contract](../docs/deployment/platform-authority-retirement-entrypoint-service-role.md)
- [GUG-376 operations runbook](../docs/operations/platform-authority-retirement-entrypoint-service-role.md)
