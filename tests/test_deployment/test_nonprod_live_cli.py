"""CLI regression tests for the protected non-production live controller."""
from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "scripts/deployment/nonprod-live-controller.py"


def _load_cli():
    spec = importlib.util.spec_from_file_location("nonprod_live_cli", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize(
    ("command", "extra_arguments"),
    [
        (
            "apply",
            [
                "--plan-record-digest",
                "sha256:" + "d" * 64,
                "--reviewer-packet-digest",
                "sha256:" + "e" * 64,
                "--expected-approver-user-id",
                "55",
            ],
        ),
        ("_terminal-fetch", []),
        ("_terminal-apply", []),
    ],
)
def test_apply_entrypoints_stop_before_constructing_destination_dependencies(
    monkeypatch, capsys, command: str, extra_arguments: list[str]
) -> None:
    cli = _load_cli()
    dependency_calls: list[object] = []
    monkeypatch.setattr(cli, "load_live_input_package", lambda **_kwargs: object())
    monkeypatch.setattr(
        cli,
        "real_dependencies",
        lambda package: dependency_calls.append(package),
    )

    arguments = [
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
        ]
    result = cli.main([*arguments, *extra_arguments])

    assert result == 2
    assert dependency_calls == []
    captured = capsys.readouterr()
    assert "terminal operations are disabled before destination access" in captured.err
    assert "post-apply health" in captured.err
