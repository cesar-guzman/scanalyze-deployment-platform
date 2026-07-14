# User Lifecycle and Bootstrap Recovery Runbook

> **Scope:** GUG-94 recovery and reconciliation
> **Mode:** Report-only and fail-closed by default
> **Production:** NO-GO

This runbook does not authorize AWS access, provider mutation, data migration,
redrive, deployment, or deletion. Use only with an approved environment,
explicit profile/region, least privilege, and an incident/change record.

## Safety rules

- Never print or capture tokens, cookies, JWTs, temporary passwords, invitation
  secrets, raw provider responses, user locators, PII, table contents, or audit
  payloads.
- Work from opaque operation, membership, decision, bootstrap, and correlation
  references.
- Never infer customer or deployment from provider names, email domains,
  account defaults, queue names, or legacy tenant maps.
- Do not reset a membership version, reuse an idempotency key for new input,
  delete evidence, mark an operation complete manually, or consume a bootstrap
  request before its audit checkpoint.
- Exact retries are preferred to manual repair because every effect is
  checkpointed and reconciled.

## Lifecycle recovery classification

| Stored stage | Safe interpretation | Recovery action |
|---|---|---|
| `reserved` | no approved effect | Verify approval dependency, then exact retry |
| `approval_validated` | exact request-bound approval; no effect order assumed | Verify immutable `effect_order`, then exact retry |
| `provider_effect_reserved` | one resend attempt may be in flight and Cognito has no delivery receipt/idempotency token | Do not retry automatically; quarantine and reconcile sanitized provider/operation evidence under separate approval |
| `provider_applied` | provider-first effect proven for activation/reactivation | Exact retry; conditionally apply active membership |
| `membership_applied` | membership-first restriction/change proven | Exact retry; reconcile provider effect and/or revoke sessions as required |
| `sessions_revoked` | provider sessions invalidated | Exact retry; emit durable audit |
| `audit_committed` | audit receipt proven | Exact retry; complete ledger only |
| `completed` | final response eligible | Return existing operation reference; no new effect |

If any stored binding, owner tuple, version, request/approval digest, provider
reference, `effect_order`, stage, or audit receipt is missing or conflicting,
stop and classify the record for quarantine/review. Do not infer or overwrite
it. Never resume a legacy operation whose effect order cannot be proven.

## Bootstrap recovery classification

| Bootstrap state | Meaning | Permitted action |
|---|---|---|
| `approved` | dual approval valid; no claim | normal processor invocation |
| `claimed` | exact claim held; effects not checkpointed | exact retry within recovery window |
| `effects_applied` | stable user and membership references stored | exact retry to commit audit |
| `audit_committed` | audit decision stored | exact retry to consume |
| `consumed` | one-use request completed | deny replay |
| pending/revoked/expired/unknown | not executable | deny and review |

The recovery window is bounded. A claim outside the window, a missing claim
token, a different idempotency key, a changed request version, or missing stable
outcome references is not recoverable automatically.

## Report-only evidence procedure

1. Record issue/change reference, environment, owner, independent approver,
   exact deployment/customer opaque references, and time window.
2. Confirm the code release and policy/catalog digests expected for the
   deployment.
3. Retrieve only the exact operation or bootstrap key through an approved
   read-only mechanism; do not scan a protected table.
4. Classify the checkpoint using the tables above.
5. Compare only canonical hashes, versions, states, and opaque references.
6. Produce a sanitized report with `recoverable`, `quarantine_required`, or
   `manual_review_required`; include no payloads.
7. Obtain separate approval before any exact retry in a live non-production
   environment.

## Failure-specific guidance

### Provider succeeded, membership checkpoint absent

Do not create another provider user. Retry the same operation and idempotency
key. The adapter re-reads the deterministic provider principal and validates
subject plus immutable owner attributes before continuing. A mismatch requires
quarantine and provider-security review.

This state is valid only for activation/reactivation with the exact
`provider_then_membership` marker. For a restrictive mutation, it is ambiguous
and must be quarantined.

### Invitation resend is reserved but not checkpointed as applied

Do not resend automatically. Cognito does not accept an idempotency token for
`MessageAction=RESEND` and does not return a durable delivery receipt. The
pre-effect `provider_effect_reserved` checkpoint therefore makes an ambiguous
retry fail closed instead of sending a duplicate notification. Classify the
operation `manual_review_required`, reconcile only opaque operation/provider
references through an approved procedure, and issue a new operation and
approval only after the previous attempt is resolved. Never reset or advance
the stored stage manually.

### Membership changed, session revocation failed

Do not revert the membership version. Keep the membership fail-closed and
retry the exact operation to reconcile the provider user and revoke sessions.
This is the expected safe checkpoint for suspension/revocation with
`membership_then_provider`; escalate if the provider binding cannot be proven.

### Audit unavailable

Do not report success. Preserve the last effect checkpoint and retry after the
durable sink is healthy. An exact duplicate event is accepted only if all
stored content matches; a conflict is an incident.

### Final administrator guard conflict

Do not bypass the guard or use a count. Select a distinct owned active customer
admin as replacement, obtain a new target-bound approval and idempotency key,
and retry through the API. If no replacement exists, use the separately
governed bootstrap/recovery process with independent approval.

### Consumed bootstrap replay

Do not reset the request. A consumed request is final. A new bootstrap need
requires a new request, approvals, expiry, idempotency key, and review.

## Rollback

Disable human runtime and lifecycle route exposure in the service release.
Retain all membership, provider, operation, approval, audit, and bootstrap
evidence. Do not delete provider users or membership records automatically.
Reconcile partial effects using this runbook before any subsequent rollout.
