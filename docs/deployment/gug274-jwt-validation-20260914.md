# GUG-274 JWT candidate validation — 2026-09-14

Status: **LOCAL CANDIDATE VERIFIED; CONNECTED AUTHORITY AND PRODUCTION PENDING**.

Source: `fix/production-runtime-readiness` in the dedicated
`production-runtime-readiness/scanalyze-deployment-platform` worktree, with
uncommitted JWT changes over `997354d2891465268b8a58216bf99cf6203d8f36`.
This is not a clean source commit, protected-main receipt or signed release.

## Final local checks

The following disjoint suites total **559 passing cases**, run in separate
commands. All reported selections completed without skips. This total excludes
earlier overlapping checkpoints, the additional rejected command and frontend
checks from previous work.

| Selection | Cases | What the evidence establishes |
| --- | ---: | --- |
| `test_gug274_jwt_grant.py` | 188 | Closed bounded parser, one-shot consumption, issuer/topology and operation/freshness rejection |
| `test_gug274_jwt_runtime_template.py` | 42 | Explicit mode, complete/absent metadata Rules, shared Lambda environment and preserved template controls |
| `test_gug274_jwt_identity_integration.py` | 100 | Real runtime, verifier and broker with provider I/O fakes; proof/CAS/effect ordering and expiration after slow operations |
| `test_gug274_oidc_client.py`, `test_gug274_identity_grant.py`, `test_gug274_jwt_identity_grant.py` | 169 | 72 OIDC transport checks, 55 legacy launcher cases and 42 v2 CLI/pipe/socket cases; root run 3.94 s |
| `test_gug274_vendored_sdk.py`, `test_gug274_grant_source_snapshot.py`, `test_gug274_sdk_provision.py` | 60 | Package/source closure, snapshot imports and SDK provisioning; final run 15.97 s |

Provider responses are synthetic. Network mocking is confined to provider I/O;
the OIDC tests also exercise Python's real `HTTPResponse` parser with fixed-
length and chunked wire responses. A deadline test observes socket interruption
and refusal to return an assertion after expiration. These are not live TLS,
real issuer authentication, AWS signature acceptance or production evidence.

Six expiration/clock regressions detect the former behavior when transition
time is replaced in memory with operation-start time. They verify no ledger
create/CAS or effects after expiry during OIDC, STS or the storage read, and
reject a clock moving backwards. No source was altered for the mutation probe.

Python **3.12.12** passed AST/UTF-8 validation of the 18 Python files in the
runtime/operator source closure and 194 Python files in the reviewed SDK.
The SDK snapshot verified 2,133 entries. Host pytest runs used Python 3.14;
the package suite additionally imports the actual extracted runtime in Python
3.12. This does not claim a complete pytest run under Lambda's interpreter.

The earlier root legacy+launcher run initially failed three SDK tests because
it used the host's unapproved package tree. Re-running with the existing exact
external SDK closure passed all 161 selected cases. The validator was not
relaxed. That successful run preceded the later automatic-review rejection.

## Cloud check and unrun validations

AWS `cloudformation validate-template` accepted the exact rendered JSON through
`042360977644_ScanalyzePlatformAuthorityBootstrap`, `us-east-1`, after successful
STS account confirmation. It reported `CAPABILITY_NAMED_IAM` and recognized the
new parameters. The command did not create a change set, role, stack or grant.

- Template source SHA256:
  `c82bcd439424fe2c07c022e708429a0ca18334148a66d4f6c3b2eadaf4267187`.
- Rendered JSON SHA256:
  `aa5bc0fe051ecf8bce2ba721b7ca309d81b82bfc1e042ae95ba96e31b490e9b2`.
- Builder SHA256:
  `f5ca5ebc3323fb750e0e45e41dc2d361359cf15760e5e49bd648b6efee2d2e77`.
- Final OIDC client SHA256:
  `ddff8f78a4448a9a2888ea258c7b50f62d6533ec1d240a49a727bd668af523ea`.

`cfn-lint` and `ruff` were unavailable in the checked local runtimes; they were
not installed or claimed as passing. Terraform was not changed. No application
frontend build or connected document journey was rerun for the JWT delta.

An additional combined pytest command containing three legacy proof cases was
blocked by the automatic approval hook: `Blocked attempt to read or print
sensitive files or environment data..` It did not execute and was not retried
through another tool, profile or agent. Its legacy node names were:

- `test_identity_proof_uses_one_exact_context_and_clears_secret_responses`
- `test_authorization_code_grant_is_closed_duplicate_safe_and_one_shot`
- `test_apply_order_is_proof_then_cas_then_client_factory_then_effect`

The successful suites above do not override that denial. Earlier blocked GitHub
publication/collector and file operations remain separate unresolved limits.

## Delivery boundary and rollback

The live inventory returned no trusted issuers and no grants for the existing
custom application. The actual identity provider and two operator references
are still missing. The exchanged token's actual scope, absence of refresh,
maximum 900-second lifetime and provider-issued context remain unverified.
The operator guide makes these explicit activation prerequisites.

No new authority package was published or signed, and no authority/application
runtime was installed. No production URL or real document processing is claimed
as operational. The existing unsigned `997354d` artifact cannot represent these
source changes. A reviewed clean commit, fresh package/signature, protected
publication evidence, connected identity proofs and application acceptance are
still required.

Rollback currently means reverting only this reviewed local JWT delta. Keep
the earlier user-owned candidate and verified cloud foundations. There is no
deployed v2 to roll back; the known rejected v1 flow is not an operational
fallback. See the [operator guide](gug274-jwt-bearer-operator.md) and
[production playbook](../operations/production-recreation-playbook.md).
