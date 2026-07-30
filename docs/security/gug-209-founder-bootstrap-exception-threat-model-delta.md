# GUG-209 Threat-Model Delta: Founder Bootstrap Exception

## Assets and trust boundaries

- the offline founder-exception risk-acceptance record format, which confers
  neither durability nor authorization;
- offline founder execution and revocation record formats, which are not a
  durable authorization ledger;
- a future controlled durable CAS ledger, trusted identity/event evidence, and
  immediate AWS readback PEP;
- offline Plan and Apply IAM Identity Center policy templates and any future
  temporary permission sets they may inform;
- AWS request-context `aws:CurrentTime` and `identitystore:UserId` conditions;
- one exact CloudFormation Change Set and reviewed state-backend template;
- private policy renderings, subject binding, and identity-system cleanup
  readbacks.

The exception boundary is exactly authority account `042360977644`,
`us-east-1`, and `non-production`. It is not a customer account, a production
path, a generic shared-services control, or a BreakGlass authority.

## Threats and controls

| Threat | Control | Failure behavior |
|---|---|---|
| Founder self-approval is mistaken for independent approval | Separate record type uses `SINGLE_OPERATOR_FOUNDER_EXCEPTION`, `independent_approval_present: false`, and `approver_id: null` | No normal approval is manufactured; exception remains explicit risk acceptance |
| Exception weakens normal GUG-206 approval | No normal-code self-approval option; normal equal-operator/principal checks stay required; separate temporary policies only | Normal flow still denies self-approval |
| Offline template is attached accidentally | `DenyOfflineOnlyFounderPlanMutations` and `DenyOfflineOnlyFounderApplyMutations` explicitly deny every founder mutation and override matching allows | Attachment remains mutation-blocked; no GUG-209 command can attach or remove the interlock |
| Wrong authority account, Region, or environment | Exact equality to `042360977644` / `us-east-1` / `non-production`; no wildcards or request-derived fallback | Record, rendering, or action is denied |
| Old normal Plan session overlaps founder Plan | Recorded normal Plan revocation plus minimum twelve-hour session quarantine before founder Plan begins | Founder Plan cannot be prepared or assigned |
| Plan and Apply authority overlap | Future PEP design requires disjoint windows, recorded gap, different policy actions, and explicit time denial | No GUG-209 live authority exists; a future PEP must deny requests outside the named window |
| Assignment removal leaves an active AWS session | Future temporary policies retain `aws:CurrentTime` Deny conditions for at least twelve hours after final expiry | A future PEP must keep existing-session requests denied after expiration |
| Wrong person uses a temporary policy | Private rendering binds the raw Identity Center `identitystore:UserId`; a future PEP verifies that binding against trusted identity evidence | No GUG-209 live policy exists; mismatched subject is a future-PEP deny condition and raw identity is not published |
| Arbitrary or reused Change Set is executed | Future PEP allows `ExecuteChangeSet` on the exact stack resource only with `cloudformation:ChangeSetName` equal to the reviewed name; if it reuses `create-change-set --tags`, it also confines `TagResource`, `CreateAction`, exact request-tag values, and exact tag keys; it immediately reads back Change Set, template, resources, account, Region, and state | Local JSON, wildcard ARN/tag authority, stale/foreign/cancelled Change Set, or incomplete readback blocks execution |
| Duplicate execution after retry or timeout | Future PEP atomically consumes a controlled durable CAS ledger using trusted identity/event evidence; local JSON never counts as a consumed attempt | Retry is denied; only read-only reconciliation is allowed |
| Direct S3/KMS or account public-access-block mutation | Founder policy design denies direct mutation; public-access block is a precondition; bounded alias creation is `CreateAlias` only, with an exact unconditioned alias statement plus companion tagged-key/`aws:CalledVia` check | Unauthorized direct API request, `DeleteAlias`, or `UpdateAlias` is denied |
| BreakGlass is used to promote a founder plan | BreakGlass remains outside the exception and retains its promotion deny | Attempt is denied/escalated |
| Cleanup is claimed without proof | Assignment and membership readbacks plus retained-deny schedule are required for `REVOKED` | State is `REVOCATION_REQUIRED` |
| Sensitive founder evidence leaks | Raw identity/ARN/Change Set/receipt/policy artifacts stay private and mode-restricted; only sanitized digests are published | Logging/publication is rejected by procedure |

## Residual risks

- This is deliberately a single-operator exception, so independent human
  approval is absent. The risk is explicit rather than hidden and cannot be
  reclassified as normal approval.
- AWS identity-policy propagation and identity-system readback remain live
  dependencies. The AWS-side time denial reduces the active-session risk, but
  does not turn unverified structural cleanup into evidence.
- GUG-209 has no live PEP or durable CAS store. Its local records and digests
  cannot provide exactly-once execution or authorize an AWS API request.
- The founder boundary can create no customer workloads and cannot establish
  two-deployment isolation. It must not be used as launch or production proof.
- A privileged organization administrator may be able to bypass repository
  controls outside this boundary; live governance and audit evidence remain
  separate prerequisites.

## Evidence boundary

GUG-209 code, schemas, templates, tests, policy review, and documentation are
**OFFLINE-ONLY** repository evidence until their named validation gates pass.
This change does not execute a CloudFormation Change Set, Terraform apply,
backend bootstrap, customer deployment, or production action. Live execution
is blocked until a separately reviewed PEP supplies controlled durable CAS,
trusted identity/event evidence, immediate exact AWS readback, explicit
authorization, exact tag-condition authority when applicable, read-only
reconciliation, and verified revocation. The explicit offline deny interlocks
remain in place until that separate work is reviewed. Production remains
**NO-GO**.
