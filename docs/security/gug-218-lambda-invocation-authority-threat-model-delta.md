# GUG-218 threat-model delta: account-wide Lambda invocation authority

## Scope

This delta covers the read-only AWS IAM/Lambda capture contract, deterministic
authority graph, read-only collector boundary and sanitized report-only
receipt added by GUG-218. It does not cover a deployed preventive guardrail or
live GUG-217 execution.

Production is **NO-GO**.

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
different humans remain required for GUG-215/GUG-217.

## Threats and controls

| Threat | Control | Failure behavior |
|---|---|---|
| Additive same-account identity policy invokes Lambda | Complete users/groups/roles/managed/inline policy graph | Foreign edge blocks |
| Resource policy grants public, service or cross-account access | Policies from function, version and alias are evaluated | Foreign principal blocks |
| Function URL needs two actions but only one is checked | Exact pair is required for every allowed URL edge | Missing/extra action is drift |
| Old version or `$LATEST` remains invocable | Every version and qualifier is inventoried | Any unexpected version path blocks |
| Exact alias routes to foreign code/version or altered runtime configuration | Allowlist binds `CodeSha256`, AWS `ConfigSha256` and the complete reviewed configuration digest; botocore-model drift blocks | Artifact/configuration/alias drift blocks |
| Extra alias or Function URL bypasses duty split | All aliases and URL configs are enumerated | Additional surface blocks |
| Event source or async configuration invokes function | Event mappings and event-invoke configs are inventoried | Any unexpected route blocks |
| Admin can manufacture a new path after capture | Mutation authority is a separate graph; report is report-only | Mutator blocks; TOCTOU remains residual |
| Wildcard or `NotAction` evades evaluator | Conservative statement evaluator rejects broad/unknown semantics | `POLICY_SEMANTICS_UNSUPPORTED` |
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
| Caller substitutes an internally consistent allowlist | CLI requires an independently sourced expected allowlist digest before capture | Collection blocks before snapshot/AWS access |
| Same-account but unreviewed role starts collection | Adapter compares the canonical STS principal digest immediately after STS | No EC2, Lambda or IAM inventory call occurs |
| Raw IAM graph leaks through receipt/log | Explicit field allowlist, canonical sanitizer and negative tests | Receipt rejected; incident handling |
| Clean report is presented as live authorization | Effect and production flags are constant false | Evidence overclaim rejected |
| One operator uses two profiles as two approvers | Governance records immutable human identities, not sessions | Live rollout blocked |

## Attack-path result

The intended gate is:

```text
complete private AWS snapshot
  -> exact closed-graph comparison
  -> sanitized report-only receipt
  -> independent repeat review
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
- A sole human cannot independently approve the result.

## Evidence classification

| Class | Status |
|---|---|
| Implemented | Repository-only on reviewed GUG-218 commit |
| Locally validated | Named local gates only |
| CI validated | Pending required PR checks |
| AWS inventory | Not performed by implementation |
| Preventive enforcement | Not implemented |
| Live / production | **Blocked / NO-GO** |

## References

- [IAM policy evaluation logic](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic.html)
- [GetAccountAuthorizationDetails](https://docs.aws.amazon.com/IAM/latest/APIReference/API_GetAccountAuthorizationDetails.html)
- [Lambda Function URL authorization](https://docs.aws.amazon.com/lambda/latest/dg/urls-auth.html)
- [Lambda resource-based policies](https://docs.aws.amazon.com/lambda/latest/dg/access-control-resource-based.html)
