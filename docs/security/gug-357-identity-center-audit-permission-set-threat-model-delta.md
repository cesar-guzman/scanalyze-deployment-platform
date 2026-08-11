# GUG-357 Identity Center audit permission set threat-model delta

## Scope

This delta covers only the offline preparation of a temporary read-only IAM
Identity Center audit permission set. It does not cover or authorize live
creation, assignment, provisioning, audit execution, broker execution,
CloudFormation, Terraform, revocation, customer environments, or production.

## Assets and trust boundaries

- The management-account IAM Identity Center instance and Identity Store.
- The GUG-217 identity-context application.
- The authority-account runtime permission sets and their two direct users.
- The temporary auditor's immutable UserId and short-lived SSO session.
- The private evidence root containing raw identifiers, responses, and receipts.
- The public repository/Linear boundary, which accepts sanitized digests only.

The temporary auditor is an evidence collector. It is not a GUG-357
`APPROVER`, not a GUG-357 `EXECUTOR`, and not proof of two-human independence.

## Threats and controls

| Threat | Control | Residual / stop state |
| --- | --- | --- |
| Permission set silently becomes administrator authority | Exact action equality; explicit deny for every unreviewed action; no managed policies, boundary, relay, or role chaining | Any additional action or attachment is `POLICY_AUTHORITY_EXPANSION` |
| Read access escapes the intended instance or Region | Exact account/instance/store/application/permission-set/user bindings; `us-east-1` allow conditions and outside-region deny | `ListInstances` remains an unavoidable wildcard discovery call |
| Encrypted metadata would require decrypt authority | No KMS action is present in the allow list or closed boundary | Any KMS-related access denial stops the audit and requires a separately authorized package |
| Access starts early or persists after the audit | Exact not-before and not-after denies, `PT1H` session, at most four hours, expiry tag, mandatory revocation/readback | Tags alone do not revoke; issued sessions can persist until their own expiry |
| A group or shared identity is counted as an independent human | Exactly one direct `USER` auditor, distinct from both runtime users; runtime users must be distinct; group is prohibited; GUG-357 two-human status remains `NOT_PROVEN` | Technical UserIds do not prove real-person independence; attestations remain required |
| Auditor is treated as materialization approval | Intent fixes both approver/executor flags false and materialization authorization false | Separate GUG-357 duty contract and owner checkpoint still required |
| Identifiers or identity data leak through repository evidence | Public intent carries only digests, counts, fixed labels, and timestamps; raw rendered policy and AWS receipts stay under a private `0700` root | Local shell history and manually copied output remain operator risks |
| A recomputed checksum is mistaken for owner authorization | `intent_digest` proves only deterministic self-consistency; future execution must receive an expected digest from a separate owner checkpoint or signed envelope and verify the reviewed Git commit | This repository-only package contains no signature or trust root |
| Ambiguous create/delete result triggers duplicate mutation | No AWS client or executor in this package; future workflows must enter `RECONCILE_ONLY` and prohibit blind retry | Live recovery design requires separate review and authorization |
| Permission set is assigned to the authority, customer, or another account | Target account is fixed to management by digest; one direct assignment and one provisioned account only | Live readback is required; repository intent is not state proof |
| Broad discovery exposes unrelated identities | No `ListUsers`, `ListGroups`, group membership, Organizations, or arbitrary application discovery; two exact user resources only | Exact permission-set enumeration exposes instance metadata needed for uniqueness checks |
| Provisioning read reveals unrelated accounts | `ListAccountsForProvisionedPermissionSet` is limited to the two exact runtime permission sets and retained only for negative foreign-provisioning proof | It returns every account for those two permission sets; raw results remain private |
| Dual authorization on an old instance turns a new read into explicit deny | Fixed legacy aliases are exempted from the closed deny but never granted by an allow; exact policy exclusivity is required | Live instance age/mode is unknown until authorized readback |
| Identity-enhanced session policy conflicts with audit reads | Direct SSO permission-set session only; no `SetContext`, `ProvidedContexts`, relay, role chain, or additional identity policy | A mismatched session source is a hard stop before inventory |
| Policy exceeds IAM Identity Center inline-policy limits | Renderer enforces 32,768 total bytes and 10,240 non-whitespace bytes | Future AWS quota changes require revalidation against official documentation |

## Abuse cases rejected by construction

- `Create*`, `Update*`, `Delete*`, `Put*`, `Attach*`, `Detach*`,
  `Provision*`, tagging, token creation, role assumption, and broker invocation.
- `cloudformation:CreateStack`, `CreateChangeSet`, `ExecuteChangeSet`,
  `DeleteChangeSet`, and stack deletion.
- Administrator, deploy/destroy, services, sandbox, customer, Audit, Log Archive,
  static-key, and long-lived-credential substitution.
- Group assignment, multiple auditors, similarly named resource substitution,
  foreign-account provisioning, and publication of raw ARNs/UserIds/emails.

## Evidence claims

A passing repository test suite can claim only:

- `repository_package=PREPARED`;
- exact policy and intent contracts are deterministic and fail closed;
- `aws_mutations=NONE` for package preparation;
- live creation, live audit, two-human separation, revocation, and production are
  `NOT_PROVEN` / `NO-GO`.

No repository artifact may upgrade those live-state claims.

## Review gates

Before any live creation, require all of:

1. exact private identifier bindings and absolute expiry;
2. owner authorization naming the account, Region, permission set, auditor,
   allowed mutations, evidence root, and revocation phase;
3. independent security and design review of the final rendered digest;
4. CI on the exact reviewed head, reviewed merge, and exact-main readback;
5. a separate fail-closed materializer with one-attempt reconciliation;
6. a separate revocation authorization and terminal readback design.
