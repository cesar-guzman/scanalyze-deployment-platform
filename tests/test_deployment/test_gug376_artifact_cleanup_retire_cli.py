"""Focused CLI tests for the bridge-owned cleanup retirement route."""

from __future__ import annotations

import copy
from datetime import datetime, timezone
import importlib.util
from pathlib import Path
import sys
from types import SimpleNamespace
from typing import Any, Mapping

import pytest

from tooling import platform_authority_plan_permission_repair_artifact_bootstrap as pure


ROOT = Path(__file__).resolve().parents[2]
CLI = (
    ROOT
    / "scripts/deployment/"
    "platform-authority-plan-permission-repair-artifact-bootstrap.py"
)


def _load_cli() -> Any:
    spec = importlib.util.spec_from_file_location(
        "gug376_artifact_cleanup_retire_cli", CLI
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _cleanup_bundle(*, mode: str) -> dict[str, Any]:
    success = mode == "SUCCESS"
    terminals = (
        {
            target: {"target": target, "proof": target}
            for target in ("route", "broker", "broker-protection")
        }
        if success
        else None
    )
    revalidation = (
        {
            target: {
                "execution_intent": {"target": target},
                "execution_receipt": {"target": target},
            }
            for target in ("route", "broker", "broker-protection")
        }
        if success
        else None
    )
    return {
        "bootstrap_intent": {"source_commit": "a" * 40},
        "cleanup_retire": {"mode": mode},
        "bridge_revoke_readback": {"revoked": True},
        "bootstrap_route_release": ({"release": True} if success else None),
        "seed_input": ({"input_digest": "input"} if success else None),
        "seed_intent": ({"intent_digest": "seed"} if success else None),
        "terminal_readbacks": terminals,
        "terminal_revalidation": revalidation,
    }


def _install_fake_sdk(
    monkeypatch: pytest.MonkeyPatch,
    *,
    session_profiles: list[str],
) -> None:
    class Config:
        pass

    class Boto3:
        @staticmethod
        def Session(*, profile_name: str, region_name: str) -> object:
            assert region_name == pure.REGION
            session_profiles.append(profile_name)
            return SimpleNamespace(profile_name=profile_name, region_name=region_name)

    monkeypatch.setitem(sys.modules, "boto3", Boto3)
    monkeypatch.setitem(sys.modules, "botocore", SimpleNamespace(config=None))
    monkeypatch.setitem(sys.modules, "botocore.config", SimpleNamespace(Config=Config))


def test_parser_exposes_closed_cleanup_actions_and_management_only_profile() -> None:
    cli = _load_cli()
    parser = cli._parser()
    action = next(item for item in parser._actions if item.dest == "action")
    assert {
        "materialize-cleanup-retire",
        "authorize-cleanup-retire",
        "dispatch-cleanup-retire",
        "attest-cleanup-retire",
        "execute-cleanup-retire",
        "recover-cleanup-retire",
        "recover-cleanup-retire-execution",
        "readback-cleanup-retire",
    } <= set(action.choices)

    parsed = parser.parse_args(
        [
            "--private-root",
            "/private",
            "--source-root",
            str(ROOT),
            "dispatch-cleanup-retire",
            "--bundle-name",
            "bundle.json",
            "--output-name",
            "receipt.json",
            "--profile",
            pure.MANAGEMENT_PROFILE,
            "--claim-root",
            "/claims",
        ]
    )
    assert parsed.profile == pure.MANAGEMENT_PROFILE
    with pytest.raises(SystemExit):
        parser.parse_args(
            [
                "--private-root",
                "/private",
                "--source-root",
                str(ROOT),
                "dispatch-cleanup-retire",
                "--bundle-name",
                "bundle.json",
                "--output-name",
                "receipt.json",
                "--profile",
                pure.AUTHORITY_PROFILE,
                "--claim-root",
                "/claims",
            ]
        )


def test_cleanup_connected_actions_have_exact_bundles_and_provider_routes() -> None:
    cli = _load_cli()
    common = {
        "bootstrap_intent",
        "cleanup_retire",
        "bridge_revoke_readback",
        "bootstrap_route_release",
        "seed_input",
        "seed_intent",
        "terminal_readbacks",
        "terminal_revalidation",
    }
    assert {
        action: cli._CONNECTED_FIELDS[action]
        for action in cli._CLEANUP_CONNECTED_ACTIONS
    } == {
        "dispatch-cleanup-retire": common | {"authorization"},
        "attest-cleanup-retire": common | {"dispatch_receipt"},
        "execute-cleanup-retire": common
        | {"dispatch_receipt", "change_set_attestation", "authorization"},
        "recover-cleanup-retire": common,
        "recover-cleanup-retire-execution": common
        | {"dispatch_receipt", "change_set_attestation"},
        "readback-cleanup-retire": common,
    }
    assert {
        action: cli._CONNECTED_METHODS[action]
        for action in cli._CLEANUP_CONNECTED_ACTIONS
    } == {
        "dispatch-cleanup-retire": "dispatch_change_set_once",
        "attest-cleanup-retire": "attest_change_set",
        "execute-cleanup-retire": "execute_change_set_once",
        "recover-cleanup-retire": "recover_change_set",
        "recover-cleanup-retire-execution": "recover_change_set_execution",
        "readback-cleanup-retire": "readback_stack",
    }


def test_offline_cleanup_materialize_and_authorize_use_exact_bundles(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cli = _load_cli()
    calls: list[tuple[str, dict[str, Any]]] = []
    monkeypatch.setattr(
        cli,
        "_aws_module",
        lambda: SimpleNamespace(
            read_clean_reviewed_source_bytes=lambda **_kwargs: {
                "bridge": b"reviewed-bridge"
            }
        ),
    )

    def materialize(**kwargs: Any) -> dict[str, Any]:
        calls.append(("materialize", kwargs))
        return {"kind": "cleanup"}

    def authorize(**kwargs: Any) -> dict[str, Any]:
        calls.append(("authorize", kwargs))
        return {"kind": "authorization"}

    monkeypatch.setattr(
        cli.contract, "materialize_bridge_cleanup_retire", materialize
    )
    monkeypatch.setattr(
        cli.contract,
        "materialize_bridge_cleanup_retire_authorization",
        authorize,
    )
    materialize_bundle = {
        "bootstrap_intent": {"source_commit": "a" * 40},
        "bridge_revoke_readback": {"revoked": True},
        "mode": "EXPIRED",
        "evaluated_at": "2026-09-01T12:00:00Z",
        "bootstrap_route_release": None,
        "seed_input": None,
        "seed_intent": None,
        "terminal_readbacks": None,
    }
    assert cli._offline(
        "materialize-cleanup-retire",
        materialize_bundle,
        source_root=ROOT,
    ) == {"kind": "cleanup"}
    assert calls[0][1]["bridge_template"] == b"reviewed-bridge"
    assert calls[0][1]["evaluated_at"] == datetime(
        2026, 9, 1, 12, 0, tzinfo=timezone.utc
    )

    authorization_bundle = {
        "cleanup_retire": {"intent_digest": "cleanup"},
        "operation": "dispatch",
        "authorization": "phrase",
        "authorized_at": "2026-09-01T12:00:00Z",
        "expires_at": "2026-09-01T12:05:00Z",
    }
    assert cli._offline(
        "authorize-cleanup-retire",
        authorization_bundle,
        source_root=ROOT,
    ) == {"kind": "authorization"}
    assert calls[1][1]["authorized_at"] == datetime(
        2026, 9, 1, 12, 0, tzinfo=timezone.utc
    )

    with pytest.raises(cli.CliError, match="BUNDLE_FIELDS_INVALID"):
        cli._offline(
            "materialize-cleanup-retire",
            {**materialize_bundle, "callback": "forbidden"},
            source_root=ROOT,
        )


def test_success_revalidator_validates_clean_git_then_rereads_exact_profiles(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    cli = _load_cli()
    events: list[str] = []
    closed: list[str] = []
    expected = {
        target: {"target": target, "proof": target}
        for target in cli._CLEANUP_TARGETS
    }
    revalidation = {
        target: {
            "execution_intent": {"target": target},
            "execution_receipt": {"target": target},
        }
        for target in cli._CLEANUP_TARGETS
    }
    seed = {"intent_digest": "seed"}

    class Route:
        class SubprocessGit:
            def __init__(self, source_root: Path) -> None:
                assert source_root == ROOT

        @staticmethod
        def validate_seed_intent_against_input(
            value: Mapping[str, Any],
            *,
            seed_input: Mapping[str, Any],
            git: Any,
            now: datetime,
        ) -> dict[str, Any]:
            assert value == seed
            assert seed_input == {"input_digest": "input"}
            assert isinstance(git, Route.SubprocessGit)
            assert now.tzinfo is not None
            events.append("git")
            return dict(value)

    monkeypatch.setattr(cli, "_seed_modules", lambda: (Route, object()))

    class Claims:
        def __init__(self, profile: str) -> None:
            self.profile = profile

        def close(self) -> None:
            closed.append(self.profile)

    class Provider:
        def __init__(self, profile: str) -> None:
            self.profile = profile

        def terminal_readback(self, **kwargs: Any) -> dict[str, Any]:
            target = kwargs["execution_intent"]["target"]
            assert kwargs["seed_intent"] == seed
            assert kwargs["execution_receipt"]["target"] == target
            events.append(f"read:{target}:{self.profile}")
            return dict(expected[target])

    def seed_provider(**kwargs: Any) -> tuple[Provider, Claims]:
        profile = kwargs["profile"]
        assert kwargs["claim_root"] == tmp_path
        events.append(f"profile:{profile}")
        return Provider(profile), Claims(profile)

    monkeypatch.setattr(cli, "_seed_provider", seed_provider)
    callback = cli._cleanup_success_revalidator(
        source_root=ROOT,
        claim_root=tmp_path,
        seed_intent=seed,
        seed_input={"input_digest": "input"},
        terminal_readbacks=expected,
        terminal_revalidation=revalidation,
        session_factory=object(),
        config_type=object(),
    )
    assert events == ["git"]
    assert callback(seed_intent=seed, terminal_readbacks=expected) == expected
    assert events == [
        "git",
        f"profile:{cli._ROUTE_TERMINAL_PROFILE}",
        f"read:route:{cli._ROUTE_TERMINAL_PROFILE}",
        f"profile:{cli._BROKER_TERMINAL_PROFILE}",
        f"read:broker:{cli._BROKER_TERMINAL_PROFILE}",
        f"read:broker-protection:{cli._BROKER_TERMINAL_PROFILE}",
    ]
    assert closed == [cli._BROKER_TERMINAL_PROFILE, cli._ROUTE_TERMINAL_PROFILE]


def test_success_revalidator_rejects_non_exact_target_map_before_profiles(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    cli = _load_cli()
    monkeypatch.setattr(
        cli,
        "_seed_provider",
        lambda **_kwargs: pytest.fail("profile must not be opened"),
    )
    terminals = {
        target: {"target": target} for target in cli._CLEANUP_TARGETS
    }
    revalidation = {
        target: {
            "execution_intent": {"target": target},
            "execution_receipt": {"target": target},
        }
        for target in cli._CLEANUP_TARGETS
    }
    revalidation["extra"] = {
        "execution_intent": {"target": "extra"},
        "execution_receipt": {"target": "extra"},
    }
    with pytest.raises(
        cli.CliError, match="CLEANUP_RETIRE_TERMINAL_REVALIDATION_INVALID"
    ):
        cli._cleanup_success_revalidator(
            source_root=ROOT,
            claim_root=tmp_path,
            seed_intent={"intent_digest": "seed"},
            seed_input={"input_digest": "input"},
            terminal_readbacks=terminals,
            terminal_revalidation=revalidation,
            session_factory=object(),
            config_type=object(),
        )


def test_expired_connected_cleanup_opens_only_main_management_session(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    cli = _load_cli()
    profiles: list[str] = []
    _install_fake_sdk(monkeypatch, session_profiles=profiles)
    claims_closed: list[bool] = []
    provider_kwargs: dict[str, Any] = {}

    class Claims:
        def __init__(self, root: Path) -> None:
            assert root == tmp_path

        def close(self) -> None:
            claims_closed.append(True)

    class Provider:
        def __init__(self, **kwargs: Any) -> None:
            provider_kwargs.update(kwargs)

        def readback_stack(self, **kwargs: Any) -> dict[str, Any]:
            assert kwargs["operation"] == "bridge-cleanup-retire"
            assert "terminal_revalidation" not in kwargs
            return {"status": "READ_BACK"}

    boundary = SimpleNamespace(
        sdk_client_config=lambda _config: object(),
        clients_from_session=lambda _session, _config: object(),
        OExclClaimStore=Claims,
        ConnectedArtifactBootstrapProvider=Provider,
    )
    monkeypatch.setattr(cli, "_aws_module", lambda: boundary)
    monkeypatch.setattr(
        cli.contract,
        "validate_bridge_cleanup_retire",
        lambda *_args, **_kwargs: {"mode": "EXPIRED"},
    )
    monkeypatch.setattr(
        cli,
        "_seed_provider",
        lambda **_kwargs: pytest.fail("downstream profile must not be opened"),
    )
    result = cli._connected(
        "readback-cleanup-retire",
        _cleanup_bundle(mode="EXPIRED"),
        source_root=ROOT,
        profile=pure.MANAGEMENT_PROFILE,
        claim_root=tmp_path,
    )
    assert result == {"status": "READ_BACK"}
    assert profiles == [pure.MANAGEMENT_PROFILE]
    assert provider_kwargs["profile"] == pure.MANAGEMENT_PROFILE
    assert provider_kwargs["cleanup_success_revalidator"] is None
    assert claims_closed == [True]

    profiles.clear()
    invalid = _cleanup_bundle(mode="EXPIRED")
    invalid["seed_input"] = {"forbidden": True}
    with pytest.raises(
        cli.CliError, match="CLEANUP_RETIRE_EXPIRED_REVALIDATION_FORBIDDEN"
    ):
        cli._connected(
            "readback-cleanup-retire",
            invalid,
            source_root=ROOT,
            profile=pure.MANAGEMENT_PROFILE,
            claim_root=tmp_path,
        )
    assert profiles == []


def test_success_readback_runs_cli_owned_jit_callback_before_provider(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    cli = _load_cli()
    profiles: list[str] = []
    _install_fake_sdk(monkeypatch, session_profiles=profiles)
    events: list[str] = []
    bundle = _cleanup_bundle(mode="SUCCESS")

    class Claims:
        def __init__(self, _root: Path) -> None:
            pass

        def close(self) -> None:
            events.append("main-claims-closed")

    class Provider:
        def __init__(self, **kwargs: Any) -> None:
            assert callable(kwargs["cleanup_success_revalidator"])

        def readback_stack(self, **kwargs: Any) -> dict[str, Any]:
            events.append("provider-enter")
            assert kwargs["operation"] == "bridge-cleanup-retire"
            callback = provider_callback[0]
            callback(
                seed_intent=kwargs["seed_intent"],
                terminal_readbacks=kwargs["terminal_readbacks"],
            )
            events.append("main-readback")
            return {"status": "READ_BACK"}

    provider_callback: list[Any] = []
    boundary = SimpleNamespace(
        sdk_client_config=lambda _config: object(),
        clients_from_session=lambda _session, _config: object(),
        OExclClaimStore=Claims,
        ConnectedArtifactBootstrapProvider=Provider,
    )
    monkeypatch.setattr(cli, "_aws_module", lambda: boundary)
    monkeypatch.setattr(
        cli.contract,
        "validate_bridge_cleanup_retire",
        lambda *_args, **_kwargs: {"mode": "SUCCESS"},
    )

    def build_revalidator(**kwargs: Any) -> Any:
        assert kwargs["terminal_revalidation"] == bundle["terminal_revalidation"]
        assert kwargs["seed_input"] == bundle["seed_input"]

        def callback(**callback_kwargs: Any) -> Mapping[str, Any]:
            assert callback_kwargs["seed_intent"] == bundle["seed_intent"]
            assert (
                callback_kwargs["terminal_readbacks"]
                == bundle["terminal_readbacks"]
            )
            events.append("jit")
            return callback_kwargs["terminal_readbacks"]

        provider_callback.append(callback)
        return callback

    monkeypatch.setattr(cli, "_cleanup_success_revalidator", build_revalidator)
    result = cli._connected(
        "readback-cleanup-retire",
        bundle,
        source_root=ROOT,
        profile=pure.MANAGEMENT_PROFILE,
        claim_root=tmp_path,
    )
    assert result == {"status": "READ_BACK"}
    assert profiles == [pure.MANAGEMENT_PROFILE]
    assert events == [
        "provider-enter",
        "jit",
        "main-readback",
        "main-claims-closed",
    ]


def test_offline_success_rejects_resealed_forged_template_url_with_zero_calls(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cli = _load_cli()
    from tests.test_deployment import (
        test_gug376_plan_permission_repair_deployment_route as route_tests,
    )

    source, intent, now = route_tests.case.__wrapped__()
    forged = copy.deepcopy(intent)
    forged_request = forged["targets"]["route"]["create_request"]
    forged_request["TemplateURL"] = (
        "https://attacker.example.invalid/forged-route-template.yaml"
    )
    forged["targets"]["route"]["create_request_digest"] = (
        route_tests.route.digest_value(forged_request)
    )
    forged.pop("intent_digest")
    forged = route_tests.route.seal(forged, "intent_digest")
    assert forged["aws_calls"] == 0
    assert (
        route_tests.route.validate_seed_intent_against_git(
            forged, git=route_tests.FakeGit()
        )
        == forged
    )

    class RouteFacade:
        SubprocessGit = staticmethod(lambda _root: route_tests.FakeGit())
        validate_seed_intent_against_input = staticmethod(
            route_tests.route.validate_seed_intent_against_input
        )

    monkeypatch.setattr(cli, "_seed_modules", lambda: (RouteFacade, object()))
    monkeypatch.setattr(
        cli,
        "_aws_module",
        lambda: pytest.fail("source read must follow causal seed validation"),
    )
    with pytest.raises(
        route_tests.route.RouteSeedError, match="INTENT_INPUT_BINDING_INVALID"
    ):
        cli._offline(
            "materialize-cleanup-retire",
            {
                "bootstrap_intent": {"source_commit": "a" * 40},
                "bridge_revoke_readback": {"revoked": True},
                "mode": "SUCCESS",
                "evaluated_at": now.isoformat().replace("+00:00", "Z"),
                "bootstrap_route_release": {"release": True},
                "seed_input": source,
                "seed_intent": forged,
                "terminal_readbacks": {
                    target: {"target": target}
                    for target in ("route", "broker", "broker-protection")
                },
            },
            source_root=ROOT,
        )


def test_connected_cleanup_bundle_cannot_inject_callback(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    cli = _load_cli()
    bundle = {
        **_cleanup_bundle(mode="EXPIRED"),
        "cleanup_success_revalidator": "forbidden",
    }
    with pytest.raises(cli.CliError, match="BUNDLE_FIELDS_INVALID"):
        cli._connected(
            "readback-cleanup-retire",
            bundle,
            source_root=ROOT,
            profile=pure.MANAGEMENT_PROFILE,
            claim_root=tmp_path,
        )
