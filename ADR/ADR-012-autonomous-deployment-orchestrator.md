# ADR-012: Autonomous Deployment Orchestrator

- **Status**: Accepted
- **Date**: 2026-07-10
- **Deciders**: César Guzmán, Platform Engineering

## Context

Scanalyze has grown from a locally-validated monorepo to a platform that needs to be deployed autonomously for multiple customers. The existing tooling (Makefile gates, build-push.sh, m3_plan_only.sh) works but is fragmented — there is no single entrypoint that orchestrates the full lifecycle from manifest validation through deployment to handoff.

## Decision

Introduce `scripts/deployment/scanalyze-deploy.sh` as the single autonomous orchestrator with these properties:

1. **Dry-run by default**: All operations are read-only unless explicitly unlocked.
2. **Fail-closed**: Live mutations require `SCANALYZE_ALLOW_LIVE=1`, valid manifest, account binding, and explicit `--approve`.
3. **Production requires additional gate**: `SCANALYZE_ALLOW_PROD=1` plus non-production evidence.
4. **17 subcommands**: doctor, validate-manifest, bootstrap-local, repro-check, account-preflight, plan-layer, apply-layer, plan-all, apply-all, publish-images, deploy-services, validate-live, smoke-e2e, rollback, go-no-go, handoff-package.
5. **Reuses existing tools**: Calls build-push.sh, Makefile targets, terraform-layer.sh — does not duplicate logic.

## Consequences

- Single CLI for all deployment operations.
- No accidental production mutations.
- Clean separation between offline validation and live operations.
- Existing Makefile targets and scripts remain functional independently.

## Alternatives Considered

1. **Make-only orchestration**: Rejected because Make targets don't compose well for stateful operations like plan/apply with saved plans.
2. **Python orchestrator**: Rejected because the existing tooling is Bash and the team is proficient in Bash. Adding Python would create a mixed scripting surface.
3. **CI-only orchestration**: Rejected because the platform must be usable without CI (operator laptop, airgapped).
