# GUG-123 threat-model delta

Production: **NO-GO**. Evidence is repository implementation and synthetic
offline validation, not GitHub or AWS control effectiveness.

| Threat | Candidate control | Negative evidence |
|---|---|---|
| fork or pull request obtains cloud identity | exact repository numeric IDs, workflow ref, main ref, event, Environment and subject | fork/PR/wrong repo/workflow/ref/event denied |
| generic or spoofed Environment authorizes another deployment | deployment-specific name plus exact registry tuple | generic/cross-deployment/account/environment denied |
| workflow self-attests weak protection | separate, fresh GitHub API digest anchor | missing, forged, altered, future, stale or >10-minute anchor denied |
| initiator approves own release through a team | named user reviewer only; initiator inequality | self-review and team reviewer denied |
| variable scope overrides deployment | exact six-variable map and proof that reserved names are absent elsewhere | wrong/missing/extra variables and repository/org override state denied |
| OIDC trust accepts unintended token | customized five-claim subject and exact `aud`/`sub` equality | default, wildcard, wrong claim set/audience denied |
| approved Environment points to a foreign shared account | independently anchored platform authority binds repository IDs, provider, role and resource tags | foreign account/provider/role/tag/anchor denied |
| Plan escalates to Apply or another layer | terminal role per operation; generic roles exclude the GUG-93 identity boundary; dedicated identity roles accept only `identity-control-plane`; exact operation/layer resource and session tags | wrong role/operation/layer/tag/session denied |
| orchestrator becomes recovery authority | diagnostic/recovery trust only human break-glass with MFA, ownership, incident/operator and explicit recovery approval | orchestrator principal denied; machine policy excludes recovery roles |
| session cannot be attributed | exact tag allowlist, non-null multivalued tag-key context, and immutable `exec_<ULID>` source identity | missing/extra tag, absent tag-key context, and weak source pattern denied |
| workflow bypasses the central authorizer | every repository workflow is denied OIDC/credential primitives until GUG-125 wires the exact chain; the legacy microservices publisher is an explicit NO-GO | repository control test fails on either primitive in any workflow |
| evidence leaks identity or credentials | synthetic fixtures, sanitized decisions/errors, no token/ARN/API payload logging | safety/security gates and manual diff review |

## Residual risks and downstream ownership

- The repository cannot prove GitHub plan capabilities, remote Environment
  configuration, OIDC customization, or reviewer independence until a
  separately authorized live read occurs.
- The repository cannot prove AWS trust evaluation, Access Analyzer findings,
  CloudTrail attribution, or cross-account denial without authorized GUG-125
  live evidence.
- Repository-wide OIDC subject customization can interrupt existing consumers;
  the rollout must inventory and stage exact trusts first.
- GUG-124 must bind the saved Terraform plan, provenance, signing, scan results,
  and promoted artifact to this identity and target chain.
- GUG-125 must provide the trusted GitHub evidence collector, live registry/lock
  adapters, identity exchange, terminal session, and two-deployment isolation
  proof.
- No GitHub setting, AWS role, OIDC provider, Environment, or workload was read
  or changed by GUG-123.

Any uncertainty remains fail-closed and keeps production **NO-GO**.
