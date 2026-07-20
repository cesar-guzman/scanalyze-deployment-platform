# Runbook: Identity-Context-Compatible Retirement PEP

## Purpose and hard boundary

This runbook describes how a future, separately authorized non-production
operator team would validate and use the GUG-217 proof-only transport for the
GUG-215 retained Change Set retirement PEP.

It is **not executable authorization**. The repository implementation has not
been deployed or invoked. No live token or STS proof was created. No Change Set
was deleted or executed. Production is **NO-GO**.

## Required people and current stop

The live procedure requires:

- one classifier human with one immutable Identity Store UserId;
- one different approver human with a different immutable UserId;
- one governed Identity Center/IAM administrator for reviewed provisioning;
- one read-only reviewer for independent evidence;
- the non-human broker execution role as the only mutation principal.

César is currently the only human. He may complete repository work, synthetic
tests and separately authorized read-only inventory. He must stop before live
provisioning or invocation because he cannot be both classifier and independent
approver. Multiple profiles, sessions, terminals or delayed self-approval do
not change this result.

## Phase 0 — Authorization and repository evidence

Before any AWS change or token exchange:

1. record the exact issue, branch, commit and reviewed PR;
2. prove all required CI checks passed for that commit;
3. verify the GUG-215, GUG-216 and GUG-217 ADRs and threat models are current;
4. obtain explicit authorization for the exact non-production account, Region,
   Identity Center mutations, broker/ledger deployment and one execution;
5. name two independent humans and verify their distinct immutable UserIds;
6. define revocation, uncertain-outcome and rollback owners.

Stop if any item is missing. Repository merge, admin access or an SSO login is
not execution authorization.

## Phase 1 — Read-only compatibility and target preflight

Using separately authorized read-only sessions:

1. verify STS identity, expected account and Region;
2. read the live default
   `AWSIAMIdentityCenterAllowListForIdentityContext` version and document;
3. compare its exact canonical digest to the reviewed snapshot;
4. prove `sts:SetContext` is compatible for proof-only use without claiming
   Lambda or CloudFormation compatibility;
5. prove the authority shell, complete Change Set inventory and exact retained
   target through the GUG-214/GUG-215 preflight;
6. prove no foreign invoker, ledger writer or Change Set deleter exists.

Any incomplete page, denied exact read, policy drift, foreign authority or
ambiguous target is `UNKNOWN` and blocks. Do not infer safety from a list-level
result.

## Phase 2 — Provisioning review, not execution

Prepare a reviewed change package that binds:

- exact Identity Center Application, authorization-code grant and loopback
  redirect;
- application actor policy naming only the broker execution role;
- exact classifier and approver permission sets and assignments;
- ordinary invoker roles for their exact aliases;
- deny-all classifier and approver proof roles;
- code-signed broker artifact, one published version and three aliases;
- three `AWS_IAM`, `BUFFERED` Function URLs on exact aliases;
- resource policies requiring the exact invoker and
  `lambda:InvokedViaFunctionUrl = true`;
- GUG-215 ledger policy, proof-policy digests and identity binding.

Do not execute this package under this runbook without a new explicit mutation
authorization. Review rendered effective policies; local source files are not
live authority.

## Phase 3 — Exact readback after separately authorized deployment

If deployment is authorized in a future change, read back and compare:

1. application/grant/actor policy and both assignments;
2. source roles, invoker trust/policies and absence of extra policies;
3. proof-role trust, deny-all inline policy, no attached policy and no boundary;
4. broker execution trust, sole inline policy and canonical digest;
5. function code digest, code signing, reserved concurrency and immutable
   alias version;
6. each Function URL qualifier, `AWS_IAM`, `BUFFERED` mode and exact resource
   policy;
7. ledger encryption, recovery, deletion protection and broker-only resource
   policy;
8. account-wide absence of foreign invocation and mutation authority.

Drift or incomplete evidence stops the procedure. Do not repair in place from
an execution session.

## Phase 4 — Classifier proof and classification

Only the classifier human may continue, under one separately authorized live
window.

1. start the exact authorization-code plus PKCE flow for the reviewed
   application and immutable callback;
2. send the one-time code and verifier only to the exact `classify` Function
   URL;
3. ensure no proxy, shell history, trace, access log or evidence collector
   captures the body;
4. require a sanitized `IDENTITY_CONTEXT_PROOF_VERIFIED` receipt;
5. require the broker to create or reconcile the exact `CLASSIFIED` item with
   the classifier proof digest;
6. stop at `INDEPENDENT_APPROVAL_REQUIRED`.

Never copy or persist the code, verifier, token, context assertion or temporary
credentials. A timeout or ambiguous response is reconciliation-only; do not
request a second code automatically and do not retry the operation blindly.

## Phase 5 — Independent approval and one attempt

Only the different approver human may continue after reviewing the exact
classification and target evidence.

1. independently validate the target and all immutable deployment digests;
2. run a separate authorization-code plus PKCE flow;
3. send the one-time material only to the exact `retire` Function URL;
4. require the approver proof digest to enter the `APPROVED` CAS transition;
5. require `ATTEMPTED`, `attempts = 1`, before any CloudFormation call;
6. observe only sanitized status.

The broker execution role, not the approver proof session, performs the AWS
effect. If the response is lost or uncertain after `ATTEMPTED`, do not invoke
`retire` again. Proceed only to read-only reconciliation.

## Phase 6 — Reconciliation and terminal state

The approver uses a new one-time proof against only the `reconcile` Function
URL. The broker must:

1. read the original durable item;
2. prove the exact full Stack ID binding and complete Change Set inventory;
3. prove the target is absent and the empty shell is preserved;
4. repeat the exact absence proof immediately before terminal CAS;
5. persist the reconciliation proof digest and
   `RETIRED_RECONCILED` without calling delete.

Target presence, foreign inventory, a denied read or inconsistent shell leaves
the item `ATTEMPTED`. There is no reset or second delete.

## Phase 7 — Revocation and recovery

After terminal reconciliation or any stop:

1. revoke the temporary classifier and approver assignments;
2. revoke active sessions and read back absence;
3. disable/remove Function URL invoke authority under a separately reviewed
   change if the PEP is no longer needed;
4. retain the ledger and private evidence according to policy;
5. run a fresh GUG-214 recovery preflight;
6. do not declare production readiness from retirement alone.

Cloud resource deletion requires a separate destructive review. Never delete
the ledger to hide or replay an attempt.

## Stop conditions

Stop immediately for:

- only one actual human or equal/unknown UserIds;
- ordinary-session proof presented as identity-enhanced proof;
- managed-policy version/digest drift;
- anything other than proof-only `sts:SetContext` compatibility;
- request fields that select identity, action, role, alias or target;
- non-`AWS_IAM`, unqualified, asynchronous or foreign Function URL authority;
- proof role with any effective allow;
- secret, request-body, token, assertion or credential logging;
- missing proof digest before ledger transition;
- effect before `APPROVED` and `ATTEMPTED` CAS;
- retry after uncertain OIDC, STS or delete outcome;
- attribution claiming native `onBehalfOf` for the broker effect;
- incomplete inventory, foreign object or data-loss risk;
- any production, customer or Terraform Apply scope.

## Evidence handling

Public evidence may contain commit/PR identifiers, named gate outcomes, public
managed-policy version/digest, sanitized status, receipt digests and counts.

Keep these only in the approved private evidence system:

- account, application, role and resource identifiers;
- emails and raw Identity Store UserIds;
- authorization codes, PKCE values, tokens and assertions;
- temporary credentials and request bodies;
- raw AWS responses, CloudTrail, ledger items and Change Set content.

Function URL bodies must not be captured by logs, traces, screenshots, shell
history, proxies or support bundles.

## Current evidence

| Class | Status |
|---|---|
| Repository implementation | In progress on the isolated GUG-217 package until reviewed commit/PR/merge |
| Local validation | Pending final named gates for the exact commit |
| CI validation | Not established |
| Live provisioning | **Not performed** |
| Live token / STS proof | **Not performed** |
| Two-person roster | **Blocked**; one current human |
| Live retirement | **Blocked** |
| Production | **NO-GO** |
