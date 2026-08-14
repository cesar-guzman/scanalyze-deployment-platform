"""Fail-closed execution boundary for GUG-376.

Current main does not contain the provider-output polling, generated-role,
artifact-policy, signing-result, or private-orchestrator contracts required to
perform even a non-production upstream mutation safely.  This module therefore
contains no provider client, callback adapter, CAS adapter, or write-capable
simulation.  Every execution/ledger/evidence entry point stops before looking
at caller-supplied objects.

Repository-only request, inventory, plan, and STOP-checkpoint validation lives
in ``platform_authority_gug365_upstream_prerequisites``.  A future live runner
requires a separate reviewed source change; it must not grow behind one of the
stubs below.
"""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
import re
from typing import Any, Mapping


_TOKEN = re.compile(r"^[A-Z][A-Z0-9_]{2,95}$")
STOP_CODE = "STOP_UPSTREAM_SOURCE_CONTRACT_GAP"


class UpstreamRunnerError(ValueError):
    """Stable failure that never includes provider- or caller-controlled data."""

    def __init__(self, code: str) -> None:
        self.code = code if _TOKEN.fullmatch(code) else "UPSTREAM_PHASE_BLOCKED"
        super().__init__(self.code)


def _fail() -> None:
    raise UpstreamRunnerError(STOP_CODE)


def canonical_json(value: Any) -> str:
    """Canonical JSON helper retained for offline digest-only records."""

    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        )
    except (TypeError, ValueError) as exc:
        raise UpstreamRunnerError("RUNNER_VALUE_NOT_CANONICAL") from exc


def canonical_digest(value: Any) -> str:
    return "sha256:" + sha256(canonical_json(value).encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class ProviderOutcome:
    """Reserved digest-only result shape; it is never consumed in this branch."""

    classification: str
    provider_result_digest: str | None


def execute_next_once(*_args: Any, **_kwargs: Any) -> None:
    """Stop before validation, ledger claim, CAS, provider call, or readback."""

    _fail()


def initial_phase_ledger(*_args: Any, **_kwargs: Any) -> None:
    """No executable ledger may be opened from the incomplete source contract."""

    _fail()


def validate_phase_ledger(_ledger: Mapping[str, Any]) -> None:
    """Serialized ledgers cannot establish executable authority in this branch."""

    _fail()


def validate_phase_ledger_history(_history: Any) -> None:
    """Serialized histories cannot establish executable authority in this branch."""

    _fail()


def reconcile_ambiguous(*_args: Any, **_kwargs: Any) -> None:
    """There can be no GUG-376 live attempt to reconcile from this branch."""

    _fail()


def phase_receipt(_ledger: Mapping[str, Any]) -> None:
    """No phase receipt can be issued before the source contract is complete."""

    _fail()


def build_phase_execution_evidence(*_args: Any, **_kwargs: Any) -> None:
    """No execution evidence can be built from repository simulation."""

    _fail()


def validate_phase_execution_evidence(_record: Mapping[str, Any]) -> None:
    """No serialized execution record is accepted as provider evidence."""

    _fail()


def validate_owner_authorization_verification(*_args: Any, **_kwargs: Any) -> None:
    """Owner write authorization is unavailable while the source gap remains."""

    _fail()
