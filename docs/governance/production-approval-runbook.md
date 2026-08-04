# Repository Governance Approval Runbook

## Scope and standing decision

This runbook sequences GUG-119 repository governance only. It does not grant
production, AWS, Terraform, deployment, customer-data, or environment-creation
authority. Production remains **NO-GO** throughout this procedure.

The repository PR and any GitHub administrative write are two separate change
packages. Completing one never authorizes the other.

## Evidence classes

Label every artifact as one of:

- `HISTORICAL_SNAPSHOT`: dated evidence bound to its recorded revision;
- `CHECKED_IN_TARGET`: repository contract at an exact commit;
- `REMOTE_BEFORE`: fresh read-only state captured immediately before review;
- `REMOTE_AFTER`: direct response from an authorized write;
- `READBACK_VERIFIED`: fresh endpoint reads that match the approved target;
- `HUMAN_ATTESTED`: named human evidence for identity, MFA, independence, and
  least privilege; or
- `PRODUCTION_AUTHORIZED`: a separate approval for one exact production action.

Never relabel repository or CI evidence as remote, attested, or production
evidence.

## Phase 1: Publish and review the repository contract

1. Prepare one GUG-119 branch/worktree/PR from current `origin/main`.
2. Update policy, schema, CODEOWNERS, deterministic generator, tests, and these
   runbooks together.
3. Verify the policy retains exactly the six required checks listed in
   `independent-approval-standard.md`, with no missing, unexpected, duplicated,
   or silently unbound check.
4. Run focused governance tests, negative tests, documentation checks, and the
   applicable repository gates with AWS variables unset.
5. Publish a Draft PR. Record the final reviewable SHA and sanitized results.
6. Obtain repository review under the controls actually in force plus the
   manual policy in `CONTRIBUTING.md`.
7. Stop before merge at the human checkpoint below.

Published repository evidence does not prove that the target reached `main` or
that GitHub enforces it remotely.

## Human checkpoint before merge

Stop after Phase 1. The human decision record must bind all of the following:

- exact final PR SHA containing the generator and policy;
- `guguce-google` identity, MFA, independence, and least-privilege attestation;
- continued ownership authorization for `@Ferrusca08`;
- current PR reviews and checks for that SHA;
- negative-test results, residual risks, and rollback design;
- confirmation that any later administration package will inspect only existing
  Route B Environments and will not create one; and
- explicit separation between approval to merge and any later GitHub write.

Missing or contradictory evidence is a **BLOCKED** decision. Reviewer
unavailability is not an exception. Approval at this checkpoint can authorize
only the repository merge; it cannot authorize a GitHub administration write.

After an approved merge, independently verify the exact `main` SHA, reviewed
tree equivalence, and terminal post-merge CI. That proves only that the
checked-in target reached `main`.

## Phase 2: Generate the deterministic payload offline

Use only the generator committed at the reviewed SHA. Capture the authenticated
GitHub branch-protection GET response and derive a strict, timestamped readback
envelope from the same response. Store both mode-`0600` inputs outside Git in a
current-user-owned mode-`0700` directory; do not hand-edit either input. The
envelope contains `schema_version`, repository, branch, `captured_at`, effective
rulesets, `check_app_bindings`, and protection. Derive each `app_id`/`slug`
binding mechanically from completed check runs at the exact evidence SHA. The
collection step must mechanically retain only documented security fields and
actor `login`/`slug` values in the envelope, excluding raw URLs, node IDs, email
fields, and unrelated response metadata. With restrictive permissions in
effect, generate and hash the complete reviewed bundle:

```bash
umask 077
python scripts/governance/generate_protection_payload.py \
  --raw-input "$REMOTE_BEFORE_RAW" \
  --input "$REMOTE_BEFORE_ENVELOPE" \
  --policy governance/github-policy.json \
  --output "$BRANCH_PROTECTION_TARGET" \
  --recovery-output "$BRANCH_PROTECTION_RECOVERY" \
  --completion-output "$BRANCH_PROTECTION_COMPLETION" \
  --max-age-seconds 300
shasum -a 256 \
  "$BRANCH_PROTECTION_TARGET" \
  "$BRANCH_PROTECTION_RECOVERY" \
  "$BRANCH_PROTECTION_COMPLETION"
```

The generator is offline and creates two new mode-`0600` payloads plus a
mode-`0600` completion manifest outside the repository with exclusive-create,
atomic-file semantics. The manifest is written last and is the bundle commit
marker; payload files without that manifest are incomplete and must not be
used. A manifest without the generator's successful `PASS` and matching printed
digests is also invalid. It binds every mapped sanitized control to the
authenticated raw response.
Omitted or `null` actor groups normalize only when the raw evidence has the
same empty semantics, while present groups must match the raw identities
exactly. Any malformed, unknown, duplicated, lossy, incomplete, or mismatched
raw/envelope evidence fails closed.

The target output is the canonical policy projection. The recovery output is
classified as `EXACT_BEFORE` only when the mapped before-state already meets the
non-weaker security floor. If the before-state is weaker, recovery is classified
as `FORWARD_ONLY_TARGET`, its bytes and digest equal the target, and it must
never be described or authorized as rollback. An ambiguous or unmappable state
is `RECOVERY_NOT_PROVABLE` and produces no successful result. The complete
bundle needs independent review, a fresh pre-write readback, and separate owner
authorization.

The generator prints the raw-input, sanitized-input, policy, target, recovery,
and completion-manifest digests plus the recovery and separate-endpoint
classifications. The manifest binds all five source/payload digests and the
recovery mode. The generator validates the canonical policy, rejects stale or
ambiguous input and overlapping rulesets, preserves supported fields and
application-bound checks, and refuses unknown fields or unsafe paths.
Required-signature, Environment, private-reporting, and auto-merge state remain
separate endpoint work and are never added to branch protection.

Any input, policy, remote-before state, or final SHA change invalidates the
payload and its approval.

The remote-write package must bind:

- the independently verified merged `main` SHA;
- fresh branch-protection, ruleset, Environment, private-reporting, and
  auto-merge readbacks classified as `REMOTE_BEFORE`;
- confirmation that only existing Route B Environments are in scope;
- the authenticated raw input digest and the paired sanitized envelope;
- the deterministic target and recovery payloads, their printed SHA-256
  digests, and the explicit `EXACT_BEFORE` or `FORWARD_ONLY_TARGET` mode;
- the completion-manifest digest proving the target/recovery bundle completed;
- mode-`0600` before-state, target, recovery, and completion artifacts stored
  outside Git;
- negative-test results and residual risks; and
- exact actor, repository, endpoint set, execution window, and rollback owner.

## Phase 3: Separately authorize and apply GitHub administration

Only after the checkpoint owner explicitly approves the exact digest and
endpoint plan may a named human operator use a short-lived, least-privilege
credential. Immediately before each write:

1. re-read the target endpoint and conflicting rulesets;
2. verify it still matches the approved `REMOTE_BEFORE` state;
3. stop on drift, an unknown result, missing Environment, reviewer mismatch, or
   an unavailable control;
4. apply only the approved endpoint payload; and
5. retain the direct response as `REMOTE_AFTER`.

Branch protection, existing Environment protection, private vulnerability
reporting, and auto-merge are separate endpoint operations. Authorization for
one is not authorization for another. GUG-119 never creates an Environment.

## Phase 4: Readback and negative verification

Read every affected endpoint after the operation. Mark `READBACK_VERIFIED` only
when the fresh results match the reviewed target and there is no overlapping
ruleset or bypass path. Confirm that:

- the six exact application-bound checks remain required;
- one current CODEOWNER approval is the technical floor;
- stale approvals, self-approval, and unresolved conversations fail closed;
- administrators remain enforced and bypass actors remain empty;
- force-push and branch deletion remain disabled;
- only existing Route B Environments were inspected or changed, the candidate
  reviewer is required, and self-review is prevented;
- private vulnerability reporting is enabled through its separate endpoint and
  a named triage owner can receive a synthetic report; and
- auto-merge remains disabled.

Do not use a real vulnerability, customer data, or production action for the
test. Failed, partial, unavailable, or ambiguous evidence is not a pass.

## Rollback and unknown outcomes

Recovery requires its own human authorization and the reviewed recovery
artifact. Before recovery, read the endpoint again. Abort rather than overwrite
third-party drift, and do not retry an operation whose outcome cannot be read
reliably.

Use `EXACT_BEFORE` as rollback only when the generator proved that the mapped
before-state meets the security floor. When the mode is `FORWARD_ONLY_TARGET`,
`ROLLBACK_NOT_PROVABLE` is intentional: the recovery artifact is a separately
reviewed forward fix identical to the target, not restoration of the weaker
before-state. `RECOVERY_NOT_PROVABLE` is a hard stop.

Rollback must restore the captured safe state without:

- lowering the required approval count below one;
- allowing self-approval or admin bypass;
- removing CODEOWNER, stale-review, last-push, or conversation controls;
- disabling or unbinding a required check;
- enabling force-push, deletion, or auto-merge;
- creating or weakening an Environment; or
- disabling a verified private-reporting path without incident-owner approval.

If safe rollback would require any prohibited weakening, stop and use no
before-state restoration. A forward fix also requires independent review,
fresh readback, and explicit authorization.

## Closeout

Record the reviewed SHA, payload digest, actor, timestamps, direct responses,
fresh readbacks, negative-test results, rollback disposition, and remaining
gates in GUG-119. Keep sensitive/raw artifacts outside Git.

GUG-119 may close only for its repository-governance acceptance criteria. It
must not be used to claim deployment readiness or production authorization.
