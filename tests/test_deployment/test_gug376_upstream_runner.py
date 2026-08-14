"""Fail-closed regression tests for the GUG-376 execution boundary."""

from __future__ import annotations

import inspect
from pathlib import Path

import pytest

from tooling.platform_authority_gug365_upstream_prerequisites import PHASE_NAMES
from tooling.platform_authority_gug365_upstream_runner import (
    STOP_CODE,
    ProviderOutcome,
    UpstreamRunnerError,
    build_phase_execution_evidence,
    canonical_digest,
    execute_next_once,
    initial_phase_ledger,
    phase_receipt,
    reconcile_ambiguous,
    validate_owner_authorization_verification,
    validate_phase_execution_evidence,
    validate_phase_ledger,
    validate_phase_ledger_history,
)


@pytest.mark.parametrize("phase", PHASE_NAMES)
def test_public_runner_stops_before_every_callback_and_cas(phase: str) -> None:
    calls = {"write": 0, "readback": 0, "transcript": 0, "cas": 0}

    def write_spy(*_args: object, **_kwargs: object) -> None:
        calls["write"] += 1

    def readback_spy(*_args: object, **_kwargs: object) -> None:
        calls["readback"] += 1

    def transcript_spy(*_args: object, **_kwargs: object) -> None:
        calls["transcript"] += 1

    class StoreSpy:
        def compare_and_swap(self, *_args: object, **_kwargs: object) -> None:
            calls["cas"] += 1

    with pytest.raises(UpstreamRunnerError, match=STOP_CODE):
        execute_next_once(
            phase=phase,
            store=StoreSpy(),
            write_once=write_spy,
            readback=readback_spy,
            provider_operation_transcript_receipt=transcript_spy,
        )
    assert calls == {"write": 0, "readback": 0, "transcript": 0, "cas": 0}


@pytest.mark.parametrize(
    "entrypoint",
    [
        initial_phase_ledger,
        validate_phase_ledger,
        validate_phase_ledger_history,
        reconcile_ambiguous,
        phase_receipt,
        build_phase_execution_evidence,
        validate_phase_execution_evidence,
        validate_owner_authorization_verification,
    ],
)
def test_all_execution_and_ledger_entrypoints_share_the_exact_stop(
    entrypoint: object,
) -> None:
    with pytest.raises(UpstreamRunnerError, match=STOP_CODE):
        entrypoint({})


def test_runner_has_no_provider_or_callback_execution_adapter() -> None:
    source = Path(inspect.getsourcefile(execute_next_once) or "").read_text(
        encoding="utf-8"
    )
    lowered = source.casefold()
    assert "import boto" not in lowered
    assert "aws_access_key" not in lowered
    assert "write_once" not in source
    assert "compare_and_swap(" not in source
    assert "Callable[" not in source
    assert list(inspect.signature(execute_next_once).parameters) == [
        "_args",
        "_kwargs",
    ]


def test_digest_helper_and_reserved_outcome_are_inert() -> None:
    assert canonical_digest({"b": 2, "a": 1}) == canonical_digest(
        {"a": 1, "b": 2}
    )
    outcome = ProviderOutcome("AMBIGUOUS", None)
    assert outcome.classification == "AMBIGUOUS"
    assert outcome.provider_result_digest is None
