"""Attested, budgeted executor for GUG-393 private input discovery.

The executor performs no work at import time.  Its only connected path accepts
the one-shot capability minted from an owner-approved private request, uses the
existing closed GUG-392 collectors, and persists only create-only owner data.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from tooling.platform_authority_gug376_authority_inventory_collector import (
    CollectorError,
    capture_live as capture_authority_live,
    private_target_absent,
    read_private_json,
)
from tooling.platform_authority_gug376_identity_center_inventory_collector import (
    capture_live_discovery as capture_identity_live_discovery,
)
from tooling.platform_authority_gug376_live_provider import (
    LiveProviderError,
    LiveProviderFactory,
    is_attested_discovery_provider,
)
from tooling.platform_authority_gug376_live_readonly_orchestrator import (
    CallLedger,
    OrchestratorError,
)
from tooling.platform_authority_gug393_private_input_discovery import (
    AUTHORITY_SNAPSHOT_FILES,
    DEFAULT_CLAIM_FILE,
    DEFAULT_PROPOSAL_FILE,
    IDENTITY_SNAPSHOT_FILES,
    RESERVED_LIFECYCLE_OUTPUT_FILES,
    DiscoveryExecutionCapability,
    DiscoveryProposal,
    PrivateInputDiscoveryError,
    approved_discovery_request,
    authorize_exact_identity_plan,
    build_discovery_proposal,
    claim_discovery_execution,
    persist_discovery_proposal,
    provisional_discovery_plans,
)


def _fail(code: str) -> None:
    raise PrivateInputDiscoveryError(code)


def _checked_now(value: datetime) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None:
        _fail("DISCOVERY_CLOCK_INVALID")
    return value.astimezone(UTC).replace(microsecond=0)


def execute_private_input_discovery(
    *,
    provider_factory: LiveProviderFactory,
    execution_capability: DiscoveryExecutionCapability,
    private_root: Path,
    now: datetime,
    proposal_file: str = DEFAULT_PROPOSAL_FILE,
) -> DiscoveryProposal:
    """Capture two stable snapshots per domain and seal one private proposal."""

    checked_now = _checked_now(now)
    if not is_attested_discovery_provider(
        provider_factory, execution_capability
    ):
        _fail("ATTESTED_DISCOVERY_PROVIDER_REQUIRED")
    request = approved_discovery_request(execution_capability)
    if proposal_file != DEFAULT_PROPOSAL_FILE:
        _fail("PROPOSAL_FILE_INVALID")
    reserved = {
        *(RESERVED_LIFECYCLE_OUTPUT_FILES - {DEFAULT_CLAIM_FILE}),
    }
    request_names = {
        str(request.get("request_file")),
        str(request.get("owner_checkpoint_file")),
        DEFAULT_CLAIM_FILE,
    }
    snapshots = {*AUTHORITY_SNAPSHOT_FILES, *IDENTITY_SNAPSHOT_FILES}
    expected_reserved_count = len(RESERVED_LIFECYCLE_OUTPUT_FILES) - 1
    if (
        len(reserved) != expected_reserved_count
        or not snapshots <= reserved
        or reserved & request_names
    ):
        _fail("PRIVATE_OUTPUT_COLLISION")
    try:
        for name in reserved:
            private_target_absent(private_root, name)
        claim_discovery_execution(execution_capability)
        authority_plan, identity_plan = provisional_discovery_plans(request)
        ledger = CallLedger("ATTESTED_LIVE")

        authority_snapshots: list[dict[str, Any]] = []
        for capture_index, artifact_name in enumerate(
            AUTHORITY_SNAPSHOT_FILES, 1
        ):
            factory = provider_factory.build_authority(
                profile=request["profiles"]["authority"]["name"],
                ledger=ledger,
                capture_index=capture_index,
                retries=0,
            )
            capture_authority_live(
                authority_plan,
                factory,
                private_root=private_root,
                artifact_name=artifact_name,
                now=checked_now,
                validation_clock=provider_factory.evaluation_time,
            )
            ledger.raise_if_failed()
            snapshot = read_private_json(private_root, artifact_name)
            if any(
                surface.get("complete") is not True
                for surface in snapshot.get("surfaces", {}).values()
            ):
                _fail("DISCOVERY_UNCERTAIN_RECONCILE_ONLY")
            authority_snapshots.append(snapshot)

        identity_snapshots: list[dict[str, Any]] = []
        for capture_index, artifact_name in enumerate(
            IDENTITY_SNAPSHOT_FILES, 1
        ):
            factory = provider_factory.build_identity(
                profile=request["profiles"]["identity_center"]["name"],
                ledger=ledger,
                capture_index=capture_index,
                retries=0,
            )
            capture_identity_live_discovery(
                identity_plan,
                factory,
                private_root=private_root,
                artifact_name=artifact_name,
                now=checked_now,
                validation_clock=provider_factory.evaluation_time,
                exact_plan_materializer=(
                    lambda provisional, targets, attestation, index=capture_index: (
                        authorize_exact_identity_plan(
                            execution_capability,
                            capture_index=index,
                            provisional_plan=provisional,
                            targets=targets,
                            transition_attestation=attestation,
                        )
                    )
                ),
            )
            ledger.raise_if_failed()
            snapshot = read_private_json(private_root, artifact_name)
            if snapshot.get("classification") in {
                "NOT_AUTHORIZED",
                "UNCERTAIN_RECONCILE_ONLY",
            }:
                _fail("DISCOVERY_UNCERTAIN_RECONCILE_ONLY")
            identity_snapshots.append(snapshot)

        proposal = build_discovery_proposal(
            private_root=private_root,
            request=request,
            execution_capability=execution_capability,
            authority_snapshots=authority_snapshots,
            identity_snapshots=identity_snapshots,
            provider_factory=provider_factory,
        )
        persist_discovery_proposal(
            private_root,
            proposal,
            proposal_file=proposal_file,
        )
        return proposal
    except PrivateInputDiscoveryError:
        raise
    except (CollectorError, OrchestratorError, LiveProviderError) as exc:
        raise PrivateInputDiscoveryError(
            str(getattr(exc, "code", "DISCOVERY_EXECUTION_FAILED"))
        ) from exc
    except Exception as exc:
        raise PrivateInputDiscoveryError("DISCOVERY_EXECUTION_FAILED") from exc


__all__ = [
    "AUTHORITY_SNAPSHOT_FILES",
    "IDENTITY_SNAPSHOT_FILES",
    "execute_private_input_discovery",
]
