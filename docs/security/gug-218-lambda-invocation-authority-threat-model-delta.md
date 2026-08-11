# GUG-218 threat-model delta: account-wide Lambda invocation authority

## Scope

This delta covers the read-only AWS IAM/Lambda capture contract, deterministic
authority graph, read-only collector boundary and sanitized report-only
receipt added by GUG-218. It does not cover a deployed preventive guardrail or
live GUG-217 execution.

Production is **NO-GO**.

## Authorization-mode boundary

Schema v1 preserves `TWO_HUMAN` and the normal
`classify -> retire -> reconcile` graph. Schema v2 is exclusive to
`SINGLE_OPERATOR_NONPROD_EXCEPTION` and requires the exact
`single-classify -> single-retire -> single-reconcile` graph, owner-reviewed
exception and release digests, `two_human_status = NOT_PROVEN`, and
`independent_approval_present = false`. Mixed alias/duty/scope families fail
closed; both graphs contain exactly fourteen authority edges.

GUG-218 does not certify Lambda runtime-management API state. The separate
GUG-215 gate must read back
`RuntimeManagementConfig.UpdateRuntimeOn = Manual` and the exact reviewed
`RuntimeVersionArn` before either report can support a retirement decision.

## Assets

- exact authority account, Region, function, alias and role bindings;
- complete IAM policy, boundary and trust graph;
- complete Lambda versions, aliases, policies, URLs and event sources;
- canonical fourteen-edge allowlist;
- private raw snapshot and sanitized receipt digest;
- GUG-215 one-shot ledger and GUG-217 proof path protected by the gate.

## Trust boundaries

### Read-only AWS collection boundary

The collector sees sensitive account-wide IAM and Lambda configuration. It may
read but never invoke or mutate. Wrong-account execution, partial pagination or
raw-response disclosure is a security failure.

### Pure analysis boundary

The analyzer has no AWS client and evaluates only a typed snapshot plus exact
allowlist. Unknown IAM semantics fail closed. Request fields do not establish
authority.

### Evidence boundary

Only bounded counts, status/reason codes and digests may enter public evidence.
Raw account IDs, ARNs, users, policy documents, URLs and provider responses
remain private.

The collector owns provenance. It seals source mode, capture times, principal
digest, nonce and raw snapshot digest. The allowlist binds the exact assumed
collector role; root, IAM users and other roles fail closed. Offline
caller-authored JSON remains explicitly unverified and cannot produce an
approval-candidate receipt.

### Governance boundary

A report is an observation, not a preventive control or live approval. Two
different humans remain required for normal `TWO_HUMAN`; ADR-050 instead uses
the exact owner-reviewed v2 exception and remains explicitly non-independent.

## Threats and controls

| Threat | Control | Failure behavior |
|---|---|---|
| Additive same-account identity policy invokes Lambda | Complete users/groups/roles/managed/inline policy graph | Foreign edge blocks |
| Resource policy grants public, service or cross-account access | Policies from function, version and alias are evaluated | Foreign principal blocks |
| Function URL needs two actions but only one is checked | Exact pair is required for every allowed URL edge | Missing/extra action is drift |
| Old version or `$LATEST` remains invocable | Every version and qualifier is inventoried | Any unexpected version path blocks |
| Exact alias routes to foreign code/version or altered runtime configuration | Allowlist binds `CodeSha256`, AWS `ConfigSha256` and the complete reviewed configuration digest; ADR-050 v2 additionally requires equality with the deterministic clean-commit package manifest; botocore-model drift blocks | Artifact/configuration/alias drift blocks |
| Extra alias or Function URL bypasses duty split | All aliases and URL configs are enumerated | Additional surface blocks |
| Event source or async configuration invokes function | Event mappings and event-invoke configs are inventoried | Any unexpected route blocks |
| Admin can manufacture a new path after capture | Mutation authority is a separate graph; report is report-only | Mutator blocks; TOCTOU remains residual |
| Wildcard action pattern (e.g. `lambda:*`, `*`, `?`, `[`) grants broad authority | Centralized classifier detects metacharacters **before** fnmatch expansion and emits PROHIBITED edges | `WILDCARD_ACTION` / `FOREIGN_AUTHORITY_PRESENT` |
| Wildcard action pattern understates mutation authority surface | Wildcard edges carry both INVOCATION and AUTHORITY_MUTATION authority classes per covered service | `mutating_authority_count > 0`, `PROHIBITED` |
| Out-of-scope service wildcard (e.g. `s3:*`, `ec2:*`) falsely triggers Lambda authority | `_wildcard_targets_authority_service()` checks service-segment relevance conservatively (including wildcard service prefixes like `*:InvokeFunction`, `lambd?:*`); exact unrelated services are silently skipped | No edges; baseline preserved |
| Wildcard action scoped to an unrelated Lambda function ARN blocks the target inventory | Resource/NotResource applicability is validated before emitting wildcard invocation edges. Applies exact complement semantics for `NotResource`, requiring universal proof of exclusion for the symbolic qualifier namespace (`<function-arn>:*`). Narrow globs and ambiguous glob containment fail closed. A preauthorized qualifier in `Resource` (e.g. `...:function:name:future`) covers the target space. Complete valid ARNs are required. | No invocation edge for unreachable targets; `unsupported` for malformed/variable/incomplete ARNs or missing exclusion |
| Lambda mutation wildcard authority on an unrelated function inflates `mutating_authority_count` | Lambda mutation edges follow target resource applicability; IAM and CloudFormation mutation edges remain account-wide by architectural decision | Lambda mutation edges only on target-applicable resources |
| Mixed exact-plus-wildcard statement only blocks invocation | Atomic classification: any wildcard in the statement blocks all exact actions from the same statement | No exact allowlist-eligible edge emitted |
| `NotAction` evades evaluator by inverting the action match | NotAction is classified as unsupported semantics; no edges are emitted | `POLICY_SEMANTICS_UNSUPPORTED` |
| Truncated page is treated as empty | Strict token state machine and page-completeness receipt | `INVENTORY_INCOMPLETE` |
| Denied AWS read is treated as absence | Adapter records failure and produces no safe snapshot | `INVENTORY_INCOMPLETE` |
| Caller fabricates or replays a clean offline snapshot | Collector-controlled source mode, origin timestamps, caller digest and canonical snapshot seal | `OFFLINE_UNVERIFIED` / `BLOCKED_UNVERIFIED_SOURCE` |
| Caller spoofs source mode or freshness fields | Wrapper overwrites trust metadata; analyzer verifies seal and bounded time order | Invalid or unverified evidence blocks |
| Root, IAM user or foreign assumed role collects evidence | Exact collector-role digest and STS assumed-role-only provenance | Collector identity blocks |
| Structural drift is mislabeled as missing evidence | Dedicated inventory and receipt states bind structural-drift semantics | `DRIFT_DETECTED` / `BLOCKED_DRIFT` |
| A receipt is resealed against another inventory or allowlist | One bundle validator binds every cross-record digest, edge, count, state and timestamp | Detached evidence blocks |
| Future-dated or expired evidence passes relative-only checks | Trusted timezone-aware evaluation instant is required for the complete bundle | Evidence blocks before review |
| Provider response captures Lambda secrets or raw URLs | Adapter projects a reviewed minimum field set before sealing | Sensitive fields never enter snapshot or receipt |
| Configured endpoint impersonates AWS or bypasses TLS provenance | Endpoint/CA overrides are rejected and constructed client endpoints are canonical HTTPS AWS endpoints | Capture blocks before evidence is accepted |
| Slow capture mixes observations across an unsafe interval | Capture duration and decision age are independently capped at five minutes | Stale/incoherent evidence blocks |
| Caller supplies a trusted account/function | Binding comes from reviewed configuration and is compared exactly | `DRIFT_DETECTED` |
| Caller alters an allowlist while preserving its embedded digest or CLI binding | CLI recomputes the canonical digest and validates the full target/artifact binding before invoking the loader | Collection blocks before snapshot/AWS access |
| Caller substitutes an internally consistent allowlist | CLI requires a mode-appropriate expected digest: independent release in `TWO_HUMAN`, exact owner-reviewed v2 release in ADR-050 | Collection blocks before snapshot/AWS access |
| Same-account but unreviewed role starts collection | Adapter compares the canonical STS principal digest immediately after STS | No EC2, Lambda or IAM inventory call occurs |
| Raw IAM graph leaks through receipt/log | Explicit field allowlist, canonical sanitizer and negative tests | Receipt rejected; incident handling |
| Clean report is presented as live authorization | Effect and production flags are constant false | Evidence overclaim rejected |
| One operator uses two profiles as two approvers | Governance records immutable human identities, not sessions | `TWO_HUMAN` rollout blocks; ADR-050 remains single-owner `NOT_PROVEN` rather than independent |

## Attack-path result

The intended gate is:

```text
complete private AWS snapshot
  -> exact closed-graph comparison
  -> sanitized report-only receipt
  -> mode-specific repeat review
  -> separately authorized preventive rollout
```

The package closes the repository's additive-authority blind spot at analysis
time. It does not remove administrator authority or prevent changes after the
snapshot. Therefore no Lambda, token, STS or retirement effect is authorized.

## Residual risks

- IAM evaluation includes policy types and conditions that may evolve; unknown
  semantics must continue to fail closed.
- External principals, service-linked roles and organization policies require
  separate preventive-account controls.
- An administrator can change authority after capture; fresh repeat inventory
  and a preventive package remain required.
- Raw account-wide authorization data is sensitive even without credentials.
- AWS list/read APIs can be eventually consistent.
- Evidence validation requires a trusted clock and the complete reviewed
  bundle; standalone records are never authorization evidence.
- A sole human cannot independently approve the result; ADR-050 records the
  owner's exact review as `NOT_PROVEN`, never as a second approver.

## Evidence classification

| Class | Status |
|---|---|
| Implemented | Repository-only on reviewed GUG-218 commit |
| Locally validated | Named local gates only |
| CI validated | Pending required PR checks |
| AWS inventory | Not performed by implementation |
| Preventive enforcement | Not implemented |
| ADR-050 v2 evidence | Repository-only; owner-reviewed exact digest required and two-human proof `NOT_PROVEN` |
| Live / production | **Blocked / NO-GO** |

## References

- [IAM policy evaluation logic](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic.html)
- [GetAccountAuthorizationDetails](https://docs.aws.amazon.com/IAM/latest/APIReference/API_GetAccountAuthorizationDetails.html)
- [Lambda Function URL authorization](https://docs.aws.amazon.com/lambda/latest/dg/urls-auth.html)
- [Lambda resource-based policies](https://docs.aws.amazon.com/lambda/latest/dg/access-control-resource-based.html)
