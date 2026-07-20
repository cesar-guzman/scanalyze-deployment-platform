# GUG-218 — Account-Wide Lambda Invocation Authority

## Executive statement

GUG-218 defines a portable, fail-closed inventory for every IAM and Lambda path
that could invoke or manufacture invocation authority over the GUG-217 broker.
The result is report-only. It cannot authorize a token exchange, STS context,
Lambda invocation, Change Set operation or production.

## Why the package exists

Validating only the expected invoker roles is insufficient. In the same AWS
account, another identity policy may authorize Lambda without using the
expected resource policy. Authority can also persist on another alias, version,
Function URL, event source or policy attachment.

The solution compares a complete account snapshot to a closed graph of exactly
fourteen allowed edges and zero mutation edges.

## Portable control model

1. An explicitly authorized read-only session captures every IAM and Lambda
   page into private typed evidence and seals source mode, capture times,
   exact reviewed collector-role digest, scan nonce and raw snapshot digest.
2. A pure offline analyzer validates completeness and conservative IAM
   semantics and recomputes the collector seal.
3. The graph must contain exactly six identity-policy edges, six resource-policy
   edges and two role-trust edges.
4. The allowlist binds the exact broker `CodeSha256` and a canonical digest of
   its complete published execution configuration, including AWS
   `ConfigSha256`; pinned-botocore field drift fails closed. All aliases share
   one numeric version and weighted routing is forbidden.
5. Any additional or missing edge, wildcard, foreign principal, old version,
   `$LATEST`, extra URL, async/event path or mutation capability blocks.
6. Only a sanitized receipt leaves the private evidence boundary.
7. Every receipt says live effect and production authorization are false.
8. Caller-authored JSON is always `OFFLINE_UNVERIFIED` /
   `BLOCKED_UNVERIFIED_SOURCE`; it cannot claim authenticated AWS provenance.
9. Allowlist, inventory and receipt are validated as one digest-bound evidence
   chain against a trusted UTC instant; standalone records cannot establish a
   pass result.
10. The expected allowlist digest comes from an independently reviewed
    immutable contract and is checked before any capture; same-channel
    self-consistency is insufficient provenance.
11. Canonical allowlist contents and target/artifact bindings are revalidated
    before the snapshot loader, while the AWS adapter permits only STS before
    it proves the current assumed role equals the reviewed collector role.

## Fail-closed rules

- Incomplete pagination is not absence.
- A denied read is not absence.
- An offline, stale, future-dated or unsealed snapshot is not trusted evidence.
- Root, IAM-user and unreviewed assumed-role collectors are rejected.
- Structural drift yields `BLOCKED_DRIFT`, not an ambiguous incomplete result.
- Custom endpoints/CA bundles and noncanonical AWS HTTPS endpoints are rejected.
- Capture duration and decision age are both capped at five minutes.
- Future-dated, expired, cross-boundary or detached evidence is rejected.
- Code equality without runtime-configuration equality is drift.
- Unsupported IAM semantics are not safe.
- A clean observation is not a preventive guardrail.
- A profile or role is not a second human.
- Repository implementation is not live validation.

## Evidence state

| Evidence | State |
|---|---|
| Contract/analyzer/tests/docs | Implemented only on the reviewed GUG-218 commit |
| Local validation | Named gates only |
| CI validation | Requires exact PR checks |
| AWS read-only capture | Not performed by this implementation |
| Preventive organization guardrail | Future separate package |
| Independent approver | Blocked while César is the only human |
| Production | **NO-GO** |

## Operational handoff

Use [ADR-044](../ADR/ADR-044-account-wide-lambda-invocation-authority.md), the
[deployment contract](../docs/deployment/platform-authority-lambda-invocation-authority.md),
[runbook](../docs/operations/platform-authority-lambda-invocation-authority.md)
and [threat-model delta](../docs/security/gug-218-lambda-invocation-authority-threat-model-delta.md)
as the authoritative package.
