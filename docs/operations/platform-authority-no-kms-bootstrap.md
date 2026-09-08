# Identity Center bootstrap with unobserved encryption metadata

## Decision and scope

The 2026-09-08 contract change permits the bootstrap's existing protected path
when a successful, identity-verified `DescribeInstance` response omits
`EncryptionConfigurationDetails`. Its internal binding is `NOT_OBSERVED` with
a null key ARN. This is permission to select **no Identity Center KMS
authority**, not evidence of an encryption mode or permission to deploy.

The local implementation does not make AWS calls, change resources, publish a
package or certify production. The support inquiry is supplementary diagnosis;
an answer to it is not an additional prerequisite for this reviewed code path.

## Closed observation contract

| Verified response | Internal binding | Identity Center KMS authority |
| --- | --- | --- |
| Encryption block omitted | `NOT_OBSERVED`, null ARN | None |
| Explicit `AWS_OWNED_KMS_KEY`, `ENABLED`, no key ARN | Observed AWS-owned mode, null ARN | None |
| Explicit `CUSTOMER_MANAGED_KEY`, `ENABLED`, exact bound key ARN | Observed customer-managed mode and key | Existing exact-key, constrained dependency only |
| Present null, empty or malformed block; unknown key type; missing or unsuccessful status | Reject | No new grant |

`NOT_OBSERVED` is an internal observation state, never an AWS `KeyType`.
Omission is not translated into `AWS_OWNED_KMS_KEY` or `ENABLED`. A raw present
null is rejected; only the verified producer may normalize genuine omission to
`EncryptionConfigurationDetails: null` (or the collector's `encryption: null`).
Do not manufacture or edit private evidence to obtain that normalized value.

The entire instance response remains required. Caller, expected account,
instance ARN, Identity Store ID, ownership, active status, complete pagination
and independent observation checks are unchanged. An API denial, missing
instance or malformed response is not encryption-metadata omission.

The AWS references describe the response and encryption configuration, but do
not serve as proof of the target instance's live mode:
[DescribeInstance](https://docs.aws.amazon.com/singlesignon/latest/APIReference/API_DescribeInstance.html),
[EncryptionConfigurationDetails](https://docs.aws.amazon.com/singlesignon/latest/APIReference/API_EncryptionConfigurationDetails.html),
and [encryption at rest](https://docs.aws.amazon.com/singlesignon/latest/userguide/encryption-at-rest.html).

## Binding, packages and least privilege

The selector, mode/key digest, source digest, request materializer, plan seed,
broker configuration, atomic collision context and pre-effect observation must
agree on the exact state. Two stable omissions can establish an absence
observation; they cannot establish enabled encryption. A subsequent explicit
mode is a changed binding, even when it would also select zero KMS permissions.
Stop and reconcile/rematerialize through the existing reviewed path. Never
silently upgrade, downgrade, retry an effect or substitute a default selector.

The active v2 intent/source contracts accept the additional state. Historical
v1 intent schemas and fixtures retain their historical meaning; they are not
relabeled or accepted as v2. The shared observation helper is part of the exact
source closures, package manifest and signed runtime. Previously materialized
packages, source digests and private inputs are not reusable as new evidence.

For `NOT_OBSERVED`, both the management reader role and its intersecting session
policy contain zero Identity Center KMS authority, including `NotAction`
exceptions. The repair's effective-IAM checks preserve the same zero-KMS
surface. CloudFormation transports the absent key as an empty string only at
its parameter boundary; the internal JSON binding requires literal null.

This change does **not** remove or alter the separate encryption requirements
for authority artifacts, signed packages, durable ledgers or their storage.
The existing explicitly observed customer-managed-key path is unchanged.

## Failure and recovery

- Before an effect: a denied read, changed observation, invalid source or
  mismatched policy aborts admission. Do not add KMS permissions automatically.
- After a dispatch may have occurred: preserve the exact durable attempt and
  provider coordinates. Enter the existing reconciliation-only path; never
  issue a fresh repair or replay the uncertain call.
- If policy installation completed but provisioning failed, the ledger records
  partial progress. A failure is not a successful repair, clean rollback or
  permission to broaden the policy. Use readback and the existing recovery
  decision for that exact attempt.

## Verification and release boundary

The hermetic tests cover absent/malformed observations, exact binding drift,
no-KMS policies, source/package closure, broker/CloudFormation parameters and
partial-effect recovery. Run from the isolated implementation worktree with
the repository's pinned Python environment:

```bash
make platform-authority-bootstrap-plan-repair-check
make lint docs-check schema-check policy-check
python -m pytest -q tests --ignore=tests/sentinel
git diff --check
```

The last command group does not claim a security scan or connected AWS test.
Release still requires the exact reviewed/merged source, current protected
checks, fresh source-bound materialization, exact live-action authorization and
connected verification. DEV/STAGING certification and production acceptance
remain independent requirements. Local success is not deployment evidence.

Rollback for this unexecuted code change is removal of its reviewed local diff,
or a reviewed revert after publication. No AWS rollback is needed for this
implementation iteration. If a future run dispatches an effect, use its durable
recovery protocol before any code rollback or new execution.
