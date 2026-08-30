"""CLI regression tests for the protected non-production live controller."""
from __future__ import annotations

import importlib.util
from pathlib import Path
from typing import Any

import pytest

from tooling.authorize_deployment_backend import AuthorizationError


REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "scripts/deployment/nonprod-live-controller.py"


def _load_cli():
    spec = importlib.util.spec_from_file_location("nonprod_live_cli", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _arguments(command: str, *extra: str) -> list[str]:
    return [
        command,
        "--private-root",
        "/private/live",
        "--claim-digest",
        "sha256:" + "a" * 64,
        "--receipt-digest",
        "sha256:" + "b" * 64,
        "--deployment-id",
        "dep_" + "A" * 26,
        "--execution-id",
        "exec_" + "A" * 26,
        "--change-id",
        "chg_" + "A" * 26,
        "--layer",
        "network",
        "--main-sha",
        "c" * 40,
        "--region",
        "us-east-1",
        *extra,
    ]


def test_public_apply_wires_every_real_post_apply_adapter(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    cli = _load_cli()
    package = object()
    terminal = object()
    ledger = object()
    health = object()
    publisher = object()
    reconciliation = object()
    observed: dict[str, Any] = {}
    monkeypatch.setattr(cli, "load_live_input_package", lambda **_kwargs: package)

    def dependencies(candidate: object, *, receipt_digest: str):
        observed["dependency_call"] = (candidate, receipt_digest)
        return terminal, ledger, health, publisher, reconciliation

    def apply(candidate: object, **kwargs: Any) -> dict[str, str]:
        observed["apply_call"] = (candidate, kwargs)
        return {"status": "HEALTHY"}

    monkeypatch.setattr(cli, "real_dependencies", dependencies)
    monkeypatch.setattr(cli, "run_apply_controller", apply)
    result = cli.main(
        _arguments(
            "apply",
            "--plan-record-digest",
            "sha256:" + "d" * 64,
            "--reviewer-packet-digest",
            "sha256:" + "e" * 64,
            "--expected-approver-user-id",
            "55",
        )
    )

    assert result == 0
    assert observed["dependency_call"] == (package, "sha256:" + "b" * 64)
    candidate, kwargs = observed["apply_call"]
    assert candidate is package
    assert kwargs["terminal_session"] is terminal
    assert kwargs["ledger_store"] is ledger
    assert kwargs["health_probe"] is health
    assert kwargs["contract_publisher"] is publisher
    assert kwargs["reconciliation_probe"] is reconciliation
    assert kwargs["plan_record_digest"] == "sha256:" + "d" * 64
    assert kwargs["reviewer_packet_digest"] == "sha256:" + "e" * 64
    assert kwargs["expected_approver_user_id"] == 55
    assert "status=HEALTHY" in capsys.readouterr().out


@pytest.mark.parametrize(
    "status",
    [
        "APPLIED",
        "UNCERTAIN",
        "RECONCILIATION_REQUIRED",
        "RECONCILED_APPLIED",
    ],
)
def test_public_apply_fails_until_health_is_terminal(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    status: str,
) -> None:
    cli = _load_cli()
    monkeypatch.setattr(cli, "load_live_input_package", lambda **_kwargs: object())
    monkeypatch.setattr(
        cli,
        "real_dependencies",
        lambda *_args, **_kwargs: (object(), object(), object(), object(), object()),
    )
    monkeypatch.setattr(
        cli,
        "run_apply_controller",
        lambda *_args, **_kwargs: {"status": status},
    )

    result = cli.main(
        _arguments(
            "apply",
            "--plan-record-digest",
            "sha256:" + "d" * 64,
            "--reviewer-packet-digest",
            "sha256:" + "e" * 64,
            "--expected-approver-user-id",
            "55",
        )
    )

    assert result == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert (
        captured.err
        == "FAIL: protected DEV apply controller did not reach HEALTHY\n"
    )


@pytest.mark.parametrize(
    ("command", "target", "expected_kwargs"),
    [
        ("_terminal-fetch", "run_terminal_fetch", {}),
        ("_terminal-apply", "run_terminal_apply", {"clock": True, "now": True}),
        (
            "_terminal-observe-health",
            "run_terminal_post_apply_observation",
            {"mode": "health"},
        ),
        (
            "_terminal-observe-reconciliation",
            "run_terminal_post_apply_observation",
            {"mode": "reconciliation"},
        ),
        ("_terminal-publish-contract", "run_terminal_contract_publication", {}),
    ],
)
def test_internal_terminal_commands_never_construct_outer_dependencies(
    monkeypatch: pytest.MonkeyPatch,
    command: str,
    target: str,
    expected_kwargs: dict[str, Any],
) -> None:
    cli = _load_cli()
    package = object()
    calls: list[tuple[tuple[Any, ...], dict[str, Any]]] = []
    monkeypatch.setattr(cli, "load_live_input_package", lambda **_kwargs: package)
    monkeypatch.setattr(
        cli,
        "real_dependencies",
        lambda *_args, **_kwargs: pytest.fail("outer dependencies were constructed"),
    )
    monkeypatch.setattr(
        cli,
        target,
        lambda *args, **kwargs: calls.append((args, kwargs)),
    )

    assert cli.main(_arguments(command)) == 0
    assert len(calls) == 1
    args, kwargs = calls[0]
    assert args == (package,)
    for key, value in expected_kwargs.items():
        if value is True:
            assert key in kwargs
        else:
            assert kwargs[key] == value


def test_dependency_failure_is_sanitized_before_apply(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    cli = _load_cli()
    monkeypatch.setattr(cli, "load_live_input_package", lambda **_kwargs: object())
    monkeypatch.setattr(
        cli,
        "real_dependencies",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AuthorizationError("adapter unavailable")
        ),
    )

    result = cli.main(
        _arguments(
            "apply",
            "--plan-record-digest",
            "sha256:" + "d" * 64,
            "--reviewer-packet-digest",
            "sha256:" + "e" * 64,
            "--expected-approver-user-id",
            "55",
        )
    )

    assert result == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == "FAIL: protected live phase stopped: adapter unavailable\n"
