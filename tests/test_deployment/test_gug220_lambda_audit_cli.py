"""GUG-220 CLI effect-boundary tests."""
from __future__ import annotations

import copy
import importlib.util
import inspect
import json
import os
import subprocess
from argparse import Namespace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest


REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "scripts/deployment/platform-authority-lambda-audit-permission-set.py"
SYNTHETIC_SAML_PROVIDER_ARN = (
    "arn:aws:iam::042360977644:saml-provider/"
    "AWSSSO_0123456789abcdef_DO_NOT_DELETE"
)
SYNTHETIC_SOURCE_COMMIT = "a" * 40


def _module(name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _allow_synthetic_source(
    module: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        module,
        "validate_provisioning_source_commit_binding",
        lambda **_: None,
    )
    monkeypatch.setattr(
        module,
        "sealed_collector_policy_for_intent",
        lambda *_args, **_kwargs: module.render_exact_collector_policy(REPO_ROOT),
    )
    monkeypatch.setattr(
        module,
        "_bound_execution_ledger_directory",
        lambda path: module._private_directory(path),
    )


def test_cli_exposes_separate_plan_apply_reconcile_and_bind_commands() -> None:
    module = _module("gug220_cli_parser")
    parser = module._parser()
    subparsers = next(
        action for action in parser._actions if hasattr(action, "choices") and action.choices
    )

    assert set(subparsers.choices) == {"plan", "apply", "reconcile", "bind-session"}
    assert "--allow-identity-center-mutation" in (
        subparsers.choices["apply"]._option_string_actions
    )
    assert "--allow-identity-center-mutation" not in (
        subparsers.choices["reconcile"]._option_string_actions
    )


@pytest.mark.parametrize(
    "name",
    (
        "AWS_ENDPOINT_URL",
        "AWS_ENDPOINT_URL_STS",
        "AWS_ENDPOINT_URL_IAM",
        "AWS_ENDPOINT_URL_SSO",
        "AWS_ENDPOINT_URL_SSO_ADMIN",
        "AWS_ENDPOINT_URL_IDENTITYSTORE",
        "AWS_ENDPOINT_URL_IDENTITY_STORE",
        "AWS_CA_BUNDLE",
        "REQUESTS_CA_BUNDLE",
        "SSL_CERT_FILE",
    ),
)
def test_environment_rejects_aws_transport_overrides(
    monkeypatch: pytest.MonkeyPatch,
    name: str,
) -> None:
    module = _module(f"gug220_cli_transport_{name.lower()}")
    for forbidden in module.FORBIDDEN_CREDENTIAL_ENV | module.FORBIDDEN_TRANSPORT_ENV:
        monkeypatch.delenv(forbidden, raising=False)
    monkeypatch.setenv(name, "https://untrusted.invalid")

    with pytest.raises(
        module.AuditPermissionSetError,
        match="AWS_TRANSPORT_OVERRIDE_FORBIDDEN",
    ):
        module._require_environment()


def test_aws_adapter_has_no_delete_or_lambda_effect_methods() -> None:
    module = _module("gug220_cli_adapter_surface")
    methods = {
        name
        for name, value in inspect.getmembers(module.IdentityCenterAdapter)
        if inspect.isfunction(value)
    }

    assert methods >= {
        "inventory",
        "create_permission_set",
        "put_inline_policy",
        "create_assignment",
        "provision",
        "readback",
    }
    assert not any(
        token in name
        for name in methods
        for token in ("delete", "detach", "invoke", "execute", "terraform")
    )


def test_effect_and_readback_methods_never_rerender_the_worktree_policy() -> None:
    module = _module("gug220_cli_no_policy_rerender")

    for method_name in (
        "put_inline_policy",
        "partial_state",
        "readback",
        "collector_role",
    ):
        source = inspect.getsource(getattr(module.IdentityCenterAdapter, method_name))
        assert "render_exact_collector_policy" not in source
        assert "expected_policy" in source


def test_private_artifact_rejects_repo_paths_and_public_modes(tmp_path: Path) -> None:
    module = _module("gug220_cli_private_artifacts")
    inside = REPO_ROOT / "gug220-private-must-not-exist.json"
    with pytest.raises(module.AuditPermissionSetError):
        module._output_path(inside)

    public = tmp_path / "operator.txt"
    public.write_text("synthetic@example.invalid\n", encoding="utf-8")
    os.chmod(public, 0o644)
    with pytest.raises(module.AuditPermissionSetError):
        module._read_private_line(public)


def test_private_output_rejects_symlink_without_creating_target(
    tmp_path: Path,
) -> None:
    module = _module("gug220_cli_private_output_symlink")
    target = tmp_path / "not-created.json"
    link = tmp_path / "receipt.json"
    link.symlink_to(target.name)

    with pytest.raises(module.AuditPermissionSetError):
        module._write_private(link, {"status": "synthetic"})
    assert not target.exists()


def test_execution_ledger_rejects_an_alternate_private_directory(
    tmp_path: Path,
) -> None:
    module = _module("gug220_cli_noncanonical_ledger_directory")

    with pytest.raises(
        module.AuditPermissionSetError,
        match="EXECUTION_LEDGER_DIRECTORY_NOT_CANONICAL",
    ):
        module._bound_execution_ledger_directory(tmp_path)


def test_execution_ledger_is_stable_and_create_only_across_intents(tmp_path: Path) -> None:
    module = _module("gug220_cli_execution_ledger")
    ledger_path = module._execution_ledger_path(tmp_path)
    ledger = {
        "intent_digest": "sha256:" + "a" * 64,
        "status": "MUTATION_WINDOW_CONSUMED",
    }

    module._write_private(
        ledger_path,
        ledger,
        already_exists_code="EXECUTION_LEDGER_ALREADY_CONSUMED",
    )
    with pytest.raises(
        module.AuditPermissionSetError,
        match="EXECUTION_LEDGER_ALREADY_CONSUMED",
    ):
        module._write_private(
            module._execution_ledger_path(tmp_path),
            {
                "intent_digest": "sha256:" + "b" * 64,
                "status": "MUTATION_WINDOW_CONSUMED",
            },
            already_exists_code="EXECUTION_LEDGER_ALREADY_CONSUMED",
        )


def test_consumed_ledger_blocks_a_second_intent_without_another_mutation(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    module = _module("gug220_cli_cross_intent_replay")
    now = datetime(2026, 7, 21, 12, 0, tzinfo=UTC)
    instance_arn = "arn:aws:sso:::instance/ssoins-0123456789abcdef"
    identity_store_id = "d-0123456789"
    principal_id = "synthetic-user-id"
    permission_set = {
        "PermissionSetArn": (
            "arn:aws:sso:::permissionSet/ssoins-0123456789abcdef/"
            "ps-fedcba9876543210"
        )
    }
    intents = iter(
        module.build_provisioning_intent(
            principal_id=principal_id,
            identity_center_instance_arn=instance_arn,
            identity_store_id=identity_store_id,
            saml_provider_arn=SYNTHETIC_SAML_PROVIDER_ARN,
            source_commit=SYNTHETIC_SOURCE_COMMIT,
            execution_ledger_directory_id=str(tmp_path),
            created_at=created_at,
            repo_root=REPO_ROOT,
        )
        for created_at in (now, now + timedelta(minutes=1))
    )

    class FakeAdapter:
        def __init__(self) -> None:
            self.put_calls = 0

        def inventory(self, *, operator_user_name: str | None) -> dict[str, Any]:
            assert operator_user_name is None
            return {
                "instance_arn": instance_arn,
                "identity_store_id": identity_store_id,
                "saml_provider_arn": SYNTHETIC_SAML_PROVIDER_ARN,
                "principal_id": principal_id,
                "permission_set": permission_set,
            }

        def partial_state(self, **_: Any) -> dict[str, Any]:
            return {
                "permission_set": permission_set,
                "inline_policy_present": False,
                "assignment_present": True,
                "provisioning_present": True,
            }

        def put_inline_policy(self, **_: Any) -> None:
            self.put_calls += 1
            raise module.AwsMutationUncertain("AWS_MUTATION_RESPONSE_UNCERTAIN")

    adapter = FakeAdapter()
    monkeypatch.setattr(module, "_load_intent", lambda _: next(intents))
    _allow_synthetic_source(module, monkeypatch)
    monkeypatch.setattr(module, "_adapter", lambda _: adapter)
    monkeypatch.setattr(module, "_operator_name", lambda _: None)
    monkeypatch.setattr(module, "_now", lambda: now + timedelta(minutes=2))

    first = Namespace(
        allow_identity_center_mutation=True,
        execution_ledger_directory=tmp_path,
        receipt_out=tmp_path / "first-receipt.json",
    )
    second = Namespace(
        allow_identity_center_mutation=True,
        execution_ledger_directory=tmp_path,
        receipt_out=tmp_path / "second-receipt.json",
    )

    assert module._cmd_apply(first) == 2
    with pytest.raises(
        module.AuditPermissionSetError,
        match="EXECUTION_LEDGER_ALREADY_CONSUMED",
    ):
        module._cmd_apply(second)
    assert adapter.put_calls == 1


def test_new_drift_after_a_noop_preflight_cannot_open_a_mutation_window(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    module = _module("gug220_cli_noop_preflight_drift")
    now = datetime(2026, 7, 21, 12, 0, tzinfo=UTC)
    instance_arn = "arn:aws:sso:::instance/ssoins-0123456789abcdef"
    principal_id = "synthetic-user-id"
    permission_set = {
        "PermissionSetArn": (
            "arn:aws:sso:::permissionSet/ssoins-0123456789abcdef/"
            "ps-fedcba9876543210"
        )
    }
    intent = module.build_provisioning_intent(
        principal_id=principal_id,
        identity_center_instance_arn=instance_arn,
        identity_store_id="d-0123456789",
        saml_provider_arn=SYNTHETIC_SAML_PROVIDER_ARN,
        source_commit=SYNTHETIC_SOURCE_COMMIT,
        execution_ledger_directory_id=str(tmp_path),
        created_at=now,
        repo_root=REPO_ROOT,
    )

    class FakeAdapter:
        def __init__(self) -> None:
            self.partial_calls = 0
            self.put_calls = 0

        def inventory(self, *, operator_user_name: str | None) -> dict[str, Any]:
            assert operator_user_name is None
            return {
                "instance_arn": instance_arn,
                "identity_store_id": "d-0123456789",
                "saml_provider_arn": SYNTHETIC_SAML_PROVIDER_ARN,
                "principal_id": principal_id,
                "permission_set": permission_set,
            }

        def partial_state(self, **_: Any) -> dict[str, Any]:
            self.partial_calls += 1
            return {
                "permission_set": permission_set,
                "inline_policy_present": self.partial_calls == 1,
                "assignment_present": True,
                "provisioning_present": True,
            }

        def put_inline_policy(self, **_: Any) -> None:
            self.put_calls += 1

    adapter = FakeAdapter()
    monkeypatch.setattr(module, "_load_intent", lambda _: intent)
    _allow_synthetic_source(module, monkeypatch)
    monkeypatch.setattr(module, "_adapter", lambda _: adapter)
    monkeypatch.setattr(module, "_operator_name", lambda _: None)
    monkeypatch.setattr(module, "_now", lambda: now)

    with pytest.raises(
        module.AuditPermissionSetError,
        match="PERMISSION_SET_STATE_CHANGED",
    ):
        module._cmd_apply(
            Namespace(
                allow_identity_center_mutation=True,
                execution_ledger_directory=tmp_path,
                receipt_out=tmp_path / "receipt.json",
            )
        )
    assert adapter.put_calls == 0


def test_policy_write_forces_provision_even_when_account_was_already_listed(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    module = _module("gug220_cli_policy_write_forces_provision")
    now = datetime(2026, 7, 21, 12, 0, tzinfo=UTC)
    instance_arn = "arn:aws:sso:::instance/ssoins-0123456789abcdef"
    principal_id = "synthetic-user-id"
    permission_set = {
        "PermissionSetArn": (
            "arn:aws:sso:::permissionSet/ssoins-0123456789abcdef/"
            "ps-fedcba9876543210"
        )
    }
    intent = module.build_provisioning_intent(
        principal_id=principal_id,
        identity_center_instance_arn=instance_arn,
        identity_store_id="d-0123456789",
        saml_provider_arn=SYNTHETIC_SAML_PROVIDER_ARN,
        source_commit=SYNTHETIC_SOURCE_COMMIT,
        execution_ledger_directory_id=str(tmp_path),
        created_at=now,
        repo_root=REPO_ROOT,
    )

    class FakeAdapter:
        def __init__(self) -> None:
            self.inline_policy_present = False
            self.effects: list[str] = []

        def inventory(self, *, operator_user_name: str | None) -> dict[str, Any]:
            assert operator_user_name is None
            return {
                "instance_arn": instance_arn,
                "identity_store_id": "d-0123456789",
                "saml_provider_arn": SYNTHETIC_SAML_PROVIDER_ARN,
                "principal_id": principal_id,
                "permission_set": permission_set,
            }

        def partial_state(self, **_: Any) -> dict[str, Any]:
            return {
                "permission_set": permission_set,
                "inline_policy_present": self.inline_policy_present,
                "assignment_present": True,
                "provisioning_present": True,
            }

        def put_inline_policy(self, **_: Any) -> None:
            self.effects.append("put")
            self.inline_policy_present = True

        def provision(self, **_: Any) -> None:
            self.effects.append("provision")

        def readback(self, **_: Any) -> None:
            return None

        def collector_role(self, **_: Any) -> dict[str, str]:
            return {
                "role_arn": (
                    "arn:aws:iam::042360977644:role/aws-reserved/"
                    "sso.amazonaws.com/"
                    "AWSReservedSSO_ScanalyzeAuthorityLambdaAudit_"
                    "0123456789abcdef"
                )
            }

    adapter = FakeAdapter()
    monkeypatch.setattr(module, "_load_intent", lambda _: intent)
    _allow_synthetic_source(module, monkeypatch)
    monkeypatch.setattr(module, "_adapter", lambda _: adapter)
    monkeypatch.setattr(module, "_operator_name", lambda _: None)
    monkeypatch.setattr(module, "_now", lambda: now)

    assert module._cmd_apply(
        Namespace(
            allow_identity_center_mutation=True,
            execution_ledger_directory=tmp_path,
            receipt_out=tmp_path / "receipt.json",
        )
    ) == 0
    assert adapter.effects == ["put", "provision"]


def test_private_writer_handles_short_writes(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    module = _module("gug220_cli_short_private_write")
    real_write = module.os.write

    def short_write(descriptor: int, payload: bytes) -> int:
        return real_write(descriptor, payload[: max(1, len(payload) // 2)])

    monkeypatch.setattr(module.os, "write", short_write)
    target = tmp_path / "short-write.json"
    expected = {"status": "synthetic", "value": "x" * 2048}
    module._write_private(target, expected)

    assert json.loads(target.read_text(encoding="utf-8")) == expected


@pytest.mark.parametrize("operation", ("write", "fsync"))
def test_private_writer_sanitizes_write_failures(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    operation: str,
) -> None:
    module = _module(f"gug220_cli_private_{operation}_failure")

    def fail(*_: Any, **__: Any) -> int:
        raise OSError("sensitive-local-path-must-not-leak")

    monkeypatch.setattr(module.os, operation, fail)
    with pytest.raises(
        module.AuditPermissionSetError,
        match="^PRIVATE_OUTPUT_WRITE_FAILED$",
    ) as error:
        module._write_private(tmp_path / f"{operation}.json", {"status": "synthetic"})
    assert "sensitive-local-path" not in str(error.value)


@pytest.mark.parametrize("operation", ("ftruncate", "lseek", "write", "fsync"))
def test_reserved_private_writer_sanitizes_write_failures(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    operation: str,
) -> None:
    module = _module(f"gug220_cli_reserved_{operation}_failure")
    _, descriptor = module._reserve_private_output(tmp_path / f"{operation}.json")

    def fail(*_: Any, **__: Any) -> int:
        raise OSError("sensitive-local-path-must-not-leak")

    monkeypatch.setattr(module.os, operation, fail)
    try:
        with pytest.raises(
            module.AuditPermissionSetError,
            match="^PRIVATE_OUTPUT_WRITE_FAILED$",
        ) as error:
            module._write_reserved_private(descriptor, {"status": "synthetic"})
        assert "sensitive-local-path" not in str(error.value)
    finally:
        module.os.close(descriptor)


def test_reserved_private_rewrite_restarts_at_the_beginning(tmp_path: Path) -> None:
    module = _module("gug220_cli_reserved_rewrite")
    target, descriptor = module._reserve_private_output(tmp_path / "receipt.json")
    try:
        module._write_reserved_private(
            descriptor,
            {"status": "READBACK_VERIFIED", "padding": "x" * 2048},
        )
        expected = {"status": "UNCERTAIN_RECONCILE_ONLY"}
        module._write_reserved_private(descriptor, expected)
    finally:
        module.os.close(descriptor)

    assert json.loads(target.read_text(encoding="utf-8")) == expected


def test_private_input_rejects_symlink_even_when_target_is_private(
    tmp_path: Path,
) -> None:
    module = _module("gug220_cli_private_symlink")
    target = tmp_path / "operator.txt"
    target.write_text("synthetic@example.invalid\n", encoding="utf-8")
    os.chmod(target, 0o600)
    link = tmp_path / "operator-link.txt"
    link.symlink_to(target)

    with pytest.raises(module.AuditPermissionSetError, match="PRIVATE_INPUT_INVALID"):
        module._read_private_line(link)


def test_reconcile_never_exposes_a_mutation_flag() -> None:
    module = _module("gug220_cli_reconcile")
    parser = module._parser()
    args = parser.parse_args(
        [
            "reconcile",
            "--intent",
            "/private/intent.json",
            "--expected-intent-digest",
            "sha256:" + "a" * 64,
            "--operator-user-name-file",
            "/private/operator.txt",
            "--management-profile",
            "synthetic-management",
            "--authority-readonly-profile",
            "synthetic-readonly",
            "--receipt-out",
            "/private/receipt.json",
        ]
    )

    assert args.command == "reconcile"
    assert not hasattr(args, "allow_identity_center_mutation")


def test_public_status_is_sanitized() -> None:
    module = _module("gug220_cli_public_status")
    payload = module._public_status(
        status="READBACK_VERIFIED",
        intent_digest="sha256:" + "a" * 64,
        receipt_digest="sha256:" + "b" * 64,
    )
    serialized = json.dumps(payload, sort_keys=True)

    assert set(payload) == {
        "status",
        "intent_digest",
        "receipt_digest",
        "production_status",
    }
    assert "042360977644" not in serialized
    assert "cesar" not in serialized.lower()
    assert payload["production_status"] == "NO-GO"


def test_manual_pagination_collects_every_page_and_rejects_token_replay() -> None:
    module = _module("gug220_cli_pagination")

    class FakeClient:
        def __init__(self, *, replay: bool = False) -> None:
            self.replay = replay
            self.calls: list[tuple[str, ...]] = []

        def run(self, service: str, operation: str, *args: str) -> dict[str, Any]:
            del service, operation
            self.calls.append(args)
            if "--starting-token" not in args:
                return {"Values": ["first"], "NextToken": "token-1"}
            if self.replay:
                return {"Values": ["second"], "NextToken": "token-1"}
            return {"Values": ["second"]}

    client = FakeClient()
    assert module._page(client, "sso-admin", "list-values", "Values") == [
        "first",
        "second",
    ]
    expected_limit = str(module.CLI_PAGE_ITEMS)
    assert client.calls == [
        ("--max-items", expected_limit, "--page-size", expected_limit),
        (
            "--max-items",
            expected_limit,
            "--page-size",
            expected_limit,
            "--starting-token",
            "token-1",
        ),
    ]
    assert all(
        forbidden not in call
        for call in client.calls
        for forbidden in ("--no-paginate", "--next-token", "--marker")
    )

    with pytest.raises(module.AwsReadError, match="AWS_PAGE_TOKEN_AMBIGUOUS"):
        module._page(
            FakeClient(replay=True), "sso-admin", "list-values", "Values"
        )


def test_list_tags_pagination_omits_unsupported_page_size() -> None:
    module = _module("gug220_cli_list_tags_pagination")

    class FakeClient:
        def __init__(self) -> None:
            self.calls: list[tuple[str, ...]] = []

        def run(self, service: str, operation: str, *args: str) -> dict[str, Any]:
            assert service == "sso-admin"
            assert operation == "list-tags-for-resource"
            self.calls.append(args)
            if "--starting-token" not in args:
                return {"Tags": [{"Key": "first"}], "NextToken": "tag-page-2"}
            return {"Tags": [{"Key": "second"}]}

    client = FakeClient()
    base = (
        "--instance-arn",
        "arn:aws:sso:::instance/ssoins-0123456789abcdef",
        "--resource-arn",
        "arn:aws:sso:::permissionSet/ssoins-0123456789abcdef/ps-0123456789abcdef",
    )
    assert module._page(
        client,
        "sso-admin",
        "list-tags-for-resource",
        "Tags",
        *base,
        page_size_supported=False,
    ) == [{"Key": "first"}, {"Key": "second"}]
    expected_limit = str(module.CLI_PAGE_ITEMS)
    assert client.calls == [
        (*base, "--max-items", expected_limit),
        (*base, "--max-items", expected_limit, "--starting-token", "tag-page-2"),
    ]
    assert all("--page-size" not in call for call in client.calls)
    assert "page_size_supported=False" in inspect.getsource(
        module.IdentityCenterAdapter.readback
    )
    assert "page_size_supported=False" in inspect.getsource(
        module.IdentityCenterAdapter.partial_state
    )


@pytest.mark.parametrize("next_token", ("", 7))
def test_manual_pagination_rejects_malformed_next_token(next_token: object) -> None:
    module = _module("gug220_cli_malformed_pagination_token")

    class FakeClient:
        def run(self, *_: str) -> dict[str, Any]:
            return {"Values": [], "NextToken": next_token}

    with pytest.raises(module.AwsReadError, match="AWS_PAGE_TOKEN_AMBIGUOUS"):
        module._page(FakeClient(), "sso-admin", "list-values", "Values")


def test_iam_pagination_cannot_hide_a_later_policy() -> None:
    module = _module("gug220_cli_iam_pagination")

    class FakeClient:
        def __init__(self) -> None:
            self.calls: list[tuple[str, ...]] = []

        def run(self, service: str, operation: str, *args: str) -> dict[str, Any]:
            assert service == "iam"
            assert operation == "list-attached-role-policies"
            assert "--max-items" in args
            assert "--page-size" in args
            assert "--no-paginate" not in args
            assert "--marker" not in args
            self.calls.append(args)
            if "--starting-token" not in args:
                return {
                    "AttachedPolicies": [],
                    "NextToken": "next-page",
                }
            return {
                "AttachedPolicies": [{"PolicyName": "ForeignPolicy"}],
            }

    client = FakeClient()
    assert module._iam_page(
        client,
        "list-attached-role-policies",
        "AttachedPolicies",
        "--role-name",
        "synthetic-role",
    ) == [{"PolicyName": "ForeignPolicy"}]
    expected_limit = str(module.CLI_PAGE_ITEMS)
    assert client.calls == [
        (
            "--role-name",
            "synthetic-role",
            "--max-items",
            expected_limit,
            "--page-size",
            expected_limit,
        ),
        (
            "--role-name",
            "synthetic-role",
            "--max-items",
            expected_limit,
            "--page-size",
            expected_limit,
            "--starting-token",
            "next-page",
        ),
    ]


@pytest.mark.parametrize("helper", ("role", "policy"))
def test_iam_pagination_rejects_truncation_without_cli_token(helper: str) -> None:
    module = _module(f"gug220_cli_iam_truncation_{helper}")

    class FakeClient:
        def run(self, *_: str) -> dict[str, Any]:
            key = "Roles" if helper == "role" else "AttachedPolicies"
            return {key: [], "IsTruncated": True}

    error = "IAM_ROLE_PAGE_AMBIGUOUS" if helper == "role" else "IAM_PAGE_AMBIGUOUS"
    with pytest.raises(module.AwsReadError, match=error):
        if helper == "role":
            module._iam_roles(FakeClient())
        else:
            module._iam_page(
                FakeClient(),
                "list-attached-role-policies",
                "AttachedPolicies",
                "--role-name",
                "synthetic-role",
            )


def test_iam_role_pagination_cannot_hide_a_later_reserved_role() -> None:
    module = _module("gug220_cli_iam_role_pagination")

    class FakeClient:
        def run(self, service: str, operation: str, *args: str) -> dict[str, Any]:
            assert service == "iam"
            assert operation == "list-roles"
            assert "--path-prefix" in args
            assert "--max-items" in args
            assert "--page-size" in args
            assert "--no-paginate" not in args
            assert "--marker" not in args
            if "--starting-token" not in args:
                return {"Roles": [], "NextToken": "next-page"}
            return {"Roles": [{"RoleName": "AWSReservedSSO_Synthetic"}]}

    assert module._iam_roles(FakeClient()) == [
        {"RoleName": "AWSReservedSSO_Synthetic"}
    ]


@pytest.mark.parametrize("inventory", ("inactive", "multiple-pages"))
def test_identity_center_instance_inventory_is_active_unique(
    inventory: str,
) -> None:
    module = _module(f"gug220_cli_instance_{inventory}")
    item = {
        "InstanceArn": "arn:aws:sso:::instance/ssoins-0123456789abcdef",
        "IdentityStoreId": "d-0123456789",
        "OwnerAccountId": module.MANAGEMENT_ACCOUNT_ID,
        "Status": "INACTIVE" if inventory == "inactive" else "ACTIVE",
    }

    class FakeManagement:
        def run(self, service: str, operation: str, *args: str, **__: Any) -> dict[str, Any]:
            if service == "sts" and operation == "get-caller-identity":
                return {
                    "Account": module.MANAGEMENT_ACCOUNT_ID,
                    "Arn": (
                        "arn:aws:sts::839393571433:assumed-role/"
                        "AWSReservedSSO_Synthetic_0123456789abcdef/synthetic.user"
                    ),
                }
            assert service == "sso-admin" and operation == "list-instances"
            if inventory == "multiple-pages" and "--starting-token" not in args:
                return {"Instances": [item], "NextToken": "next-page"}
            if inventory == "multiple-pages":
                return {"Instances": [copy.deepcopy(item)]}
            return {"Instances": [item]}

    adapter = object.__new__(module.IdentityCenterAdapter)
    adapter.management = FakeManagement()
    with pytest.raises(module.AuditPermissionSetError):
        adapter._instance()


@pytest.mark.parametrize("inventory", ("none", "multiple", "malformed"))
def test_saml_provider_inventory_requires_one_exact_authority_provider(
    inventory: str,
) -> None:
    module = _module(f"gug220_cli_saml_provider_{inventory}")
    exact = {"Arn": SYNTHETIC_SAML_PROVIDER_ARN}
    providers: object
    if inventory == "none":
        providers = []
    elif inventory == "multiple":
        providers = [
            exact,
            {
                "Arn": (
                    "arn:aws:iam::042360977644:saml-provider/"
                    "AWSSSO_fedcba9876543210_DO_NOT_DELETE"
                )
            },
        ]
    else:
        providers = [{"Arn": {"unexpected": "shape"}}]

    class FakeAuthority:
        def run(
            self, service: str, operation: str, *_: str, **__: Any
        ) -> dict[str, Any]:
            if service == "sts" and operation == "get-caller-identity":
                return {
                    "Account": module.AUTHORITY_ACCOUNT_ID,
                    "Arn": (
                        "arn:aws:sts::042360977644:assumed-role/"
                        "AWSReservedSSO_AWSReadOnlyAccess_0123456789abcdef/"
                        "synthetic.user"
                    ),
                }
            assert service == "iam" and operation == "list-saml-providers"
            return {"SAMLProviderList": providers}

    adapter = object.__new__(module.IdentityCenterAdapter)
    adapter.authority = FakeAuthority()
    with pytest.raises(module.AuditPermissionSetError):
        adapter._saml_provider()


def test_saml_provider_inventory_returns_exact_authority_provider() -> None:
    module = _module("gug220_cli_saml_provider_exact")

    class FakeAuthority:
        def run(
            self, service: str, operation: str, *_: str, **__: Any
        ) -> dict[str, Any]:
            if service == "sts" and operation == "get-caller-identity":
                return {
                    "Account": module.AUTHORITY_ACCOUNT_ID,
                    "Arn": (
                        "arn:aws:sts::042360977644:assumed-role/"
                        "AWSReservedSSO_AWSReadOnlyAccess_0123456789abcdef/"
                        "synthetic.user"
                    ),
                }
            assert service == "iam" and operation == "list-saml-providers"
            return {"SAMLProviderList": [{"Arn": SYNTHETIC_SAML_PROVIDER_ARN}]}

    adapter = object.__new__(module.IdentityCenterAdapter)
    adapter.authority = FakeAuthority()
    assert adapter._saml_provider() == SYNTHETIC_SAML_PROVIDER_ARN


def test_mutating_cli_call_disables_sdk_retries(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _module("gug220_cli_retry_control")
    observed: dict[str, str] = {}

    def fake_run(*_: Any, **kwargs: Any) -> subprocess.CompletedProcess[str]:
        observed.update(kwargs["env"])
        return subprocess.CompletedProcess(args=[], returncode=0, stdout="{}", stderr="")

    monkeypatch.setattr(module.subprocess, "run", fake_run)
    client = module.AwsCli("synthetic-profile")

    assert client.run("sso-admin", "create-permission-set", mutation=True) == {}
    assert observed["AWS_MAX_ATTEMPTS"] == "1"
    assert observed["AWS_RETRY_MODE"] == "standard"
    assert observed["AWS_IGNORE_CONFIGURED_ENDPOINT_URLS"] == "true"


def test_put_inline_policy_uses_the_sealed_object_without_rerender(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _module("gug220_cli_sealed_put_policy")
    expected_policy = module.render_exact_collector_policy(REPO_ROOT)
    observed: dict[str, Any] = {}

    class FakeManagement:
        def run(
            self, service: str, operation: str, *args: str, **kwargs: Any
        ) -> dict[str, Any]:
            assert service == "sso-admin"
            assert operation == "put-inline-policy-to-permission-set"
            observed["policy"] = json.loads(args[args.index("--inline-policy") + 1])
            observed["mutation"] = kwargs.get("mutation")
            return {}

    monkeypatch.setattr(
        module,
        "render_exact_collector_policy",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("effect path must not reopen the worktree")
        ),
    )
    adapter = object.__new__(module.IdentityCenterAdapter)
    adapter.management = FakeManagement()
    adapter.put_inline_policy(
        instance_arn="arn:aws:sso:::instance/ssoins-0123456789abcdef",
        permission_set_arn=(
            "arn:aws:sso:::permissionSet/ssoins-0123456789abcdef/"
            "ps-fedcba9876543210"
        ),
        expected_policy=expected_policy,
    )

    assert observed == {"policy": expected_policy, "mutation": True}


def test_mutation_failure_is_uncertain_and_response_is_not_disclosed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _module("gug220_cli_mutation_failure")

    def fake_run(*_: Any, **__: Any) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(
            args=[],
            returncode=1,
            stdout="",
            stderr="AccessDenied sensitive-response-must-not-leak",
        )

    monkeypatch.setattr(module.subprocess, "run", fake_run)
    with pytest.raises(
        module.AwsMutationUncertain, match="AWS_MUTATION_RESPONSE_UNCERTAIN"
    ) as error:
        module.AwsCli("synthetic-profile").run(
            "sso-admin", "create-permission-set", mutation=True
        )
    assert "sensitive-response" not in str(error.value)


def test_mutation_timeout_is_uncertain_and_command_is_not_disclosed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _module("gug220_cli_mutation_timeout")

    def fake_run(*_: Any, **__: Any) -> subprocess.CompletedProcess[str]:
        raise subprocess.TimeoutExpired(
            cmd=["aws", "--profile", "private-profile", "sso-admin"],
            timeout=90,
        )

    monkeypatch.setattr(module.subprocess, "run", fake_run)
    with pytest.raises(
        module.AwsMutationUncertain, match="AWS_MUTATION_RESPONSE_UNCERTAIN"
    ) as error:
        module.AwsCli("synthetic-profile").run(
            "sso-admin", "create-permission-set", mutation=True
        )
    assert "private-profile" not in str(error.value)


def test_post_mutation_read_failure_writes_reconcile_only_receipt(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    module = _module("gug220_cli_post_mutation_read_failure")
    instance_arn = "arn:aws:sso:::instance/ssoins-0123456789abcdef"
    identity_store_id = "d-0123456789"
    principal_id = "synthetic-user-id"
    now = datetime(2026, 7, 21, 12, 0, tzinfo=UTC)
    intent = module.build_provisioning_intent(
        principal_id=principal_id,
        identity_center_instance_arn=instance_arn,
        identity_store_id=identity_store_id,
        saml_provider_arn=SYNTHETIC_SAML_PROVIDER_ARN,
        source_commit=SYNTHETIC_SOURCE_COMMIT,
        execution_ledger_directory_id=str(tmp_path),
        created_at=now,
        repo_root=REPO_ROOT,
    )
    permission_set = {"PermissionSetArn": {"unexpected": "shape"}}

    class FakeAdapter:
        def __init__(self) -> None:
            self.inventory_calls = 0
            self.created = False

        def inventory(self, *, operator_user_name: str | None) -> dict[str, Any]:
            assert operator_user_name is None
            self.inventory_calls += 1
            if not self.created:
                return {
                    "instance_arn": instance_arn,
                    "identity_store_id": identity_store_id,
                    "saml_provider_arn": SYNTHETIC_SAML_PROVIDER_ARN,
                    "principal_id": principal_id,
                    "permission_set": None,
                }
            raise module.AwsReadError("AWS_READ_FAILED")

        def create_permission_set(self, *, instance_arn: str) -> dict[str, Any]:
            assert instance_arn == "arn:aws:sso:::instance/ssoins-0123456789abcdef"
            self.created = True
            return permission_set

    monkeypatch.setattr(module, "_load_intent", lambda _: intent)
    _allow_synthetic_source(module, monkeypatch)
    monkeypatch.setattr(module, "_adapter", lambda _: FakeAdapter())
    monkeypatch.setattr(module, "_operator_name", lambda _: None)
    monkeypatch.setattr(module, "_now", lambda: now)
    receipt_path = tmp_path / "receipt.json"
    args = Namespace(
        allow_identity_center_mutation=True,
        execution_ledger_directory=tmp_path,
        receipt_out=receipt_path,
    )

    assert module._cmd_apply(args) == 2
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    assert receipt["status"] == "UNCERTAIN_RECONCILE_ONLY"
    assert receipt["aws_mutation_attempted"] is True
    assert receipt["ambiguous_response"] is True
    assert receipt["permission_set_arn_digest"] is None
    ledgers = list(tmp_path.glob("gug220-*.execution-ledger.v1.json"))
    assert len(ledgers) == 1


@pytest.mark.parametrize("rotation_at", ("after-create", "final-refresh"))
def test_apply_revalidates_principal_after_every_inventory_refresh(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    rotation_at: str,
) -> None:
    module = _module(f"gug220_cli_principal_rotation_{rotation_at}")
    instance_arn = "arn:aws:sso:::instance/ssoins-0123456789abcdef"
    identity_store_id = "d-0123456789"
    principal_id = "synthetic-user-id"
    now = datetime(2026, 7, 21, 12, 0, tzinfo=UTC)
    intent = module.build_provisioning_intent(
        principal_id=principal_id,
        identity_center_instance_arn=instance_arn,
        identity_store_id=identity_store_id,
        saml_provider_arn=SYNTHETIC_SAML_PROVIDER_ARN,
        source_commit=SYNTHETIC_SOURCE_COMMIT,
        execution_ledger_directory_id=str(tmp_path),
        created_at=now,
        repo_root=REPO_ROOT,
    )
    permission_set = {
        "PermissionSetArn": (
            "arn:aws:sso:::permissionSet/ssoins-0123456789abcdef/"
            "ps-fedcba9876543210"
        )
    }

    class FakeAdapter:
        def __init__(self) -> None:
            self.inventory_calls = 0
            self.readback_calls = 0
            self.effect_occurred = False

        def inventory(self, *, operator_user_name: str | None) -> dict[str, Any]:
            assert operator_user_name is None
            self.inventory_calls += 1
            initial_permission_set = (
                None if rotation_at == "after-create" else permission_set
            )
            return {
                "instance_arn": instance_arn,
                "identity_store_id": identity_store_id,
                "saml_provider_arn": SYNTHETIC_SAML_PROVIDER_ARN,
                "principal_id": (
                    "rotated-user-id" if self.effect_occurred else principal_id
                ),
                "permission_set": permission_set if self.effect_occurred else initial_permission_set,
            }

        def create_permission_set(self, *, instance_arn: str) -> dict[str, Any]:
            assert instance_arn == "arn:aws:sso:::instance/ssoins-0123456789abcdef"
            self.effect_occurred = True
            return permission_set

        def partial_state(self, **_: Any) -> dict[str, Any]:
            return {
                "permission_set": permission_set,
                "inline_policy_present": rotation_at == "after-create",
                "assignment_present": True,
                "provisioning_present": True,
            }

        def put_inline_policy(self, **_: Any) -> None:
            self.effect_occurred = True
            return None

        def provision(self, **_: Any) -> None:
            return None

        def readback(self, **_: Any) -> None:
            self.readback_calls += 1

        def collector_role(self, **_: Any) -> dict[str, str]:
            return {
                "role_arn": (
                    "arn:aws:iam::042360977644:role/aws-reserved/"
                    "sso.amazonaws.com/"
                    "AWSReservedSSO_ScanalyzeAuthorityLambdaAudit_"
                    "0123456789abcdef"
                )
            }

    adapter = FakeAdapter()
    monkeypatch.setattr(module, "_load_intent", lambda _: intent)
    _allow_synthetic_source(module, monkeypatch)
    monkeypatch.setattr(module, "_adapter", lambda _: adapter)
    monkeypatch.setattr(module, "_operator_name", lambda _: None)
    monkeypatch.setattr(module, "_now", lambda: now)
    receipt_path = tmp_path / f"{rotation_at}-receipt.json"
    args = Namespace(
        allow_identity_center_mutation=True,
        execution_ledger_directory=tmp_path,
        receipt_out=receipt_path,
    )

    assert module._cmd_apply(args) == 2
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    assert receipt["status"] == "UNCERTAIN_RECONCILE_ONLY"
    assert receipt["ambiguous_response"] is True
    assert adapter.readback_calls == 0


def test_reconcile_read_failure_is_incomplete_not_deterministic_drift(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    module = _module("gug220_cli_reconcile_read_failure")
    instance_arn = "arn:aws:sso:::instance/ssoins-0123456789abcdef"
    identity_store_id = "d-0123456789"
    principal_id = "synthetic-user-id"
    now = datetime(2026, 7, 21, 12, 0, tzinfo=UTC)
    intent = module.build_provisioning_intent(
        principal_id=principal_id,
        identity_center_instance_arn=instance_arn,
        identity_store_id=identity_store_id,
        saml_provider_arn=SYNTHETIC_SAML_PROVIDER_ARN,
        source_commit=SYNTHETIC_SOURCE_COMMIT,
        execution_ledger_directory_id=str(tmp_path),
        created_at=now,
        repo_root=REPO_ROOT,
    )
    permission_set = {
        "PermissionSetArn": (
            "arn:aws:sso:::permissionSet/ssoins-0123456789abcdef/"
            "ps-fedcba9876543210"
        )
    }

    class FakeAdapter:
        def inventory(self, *, operator_user_name: str | None) -> dict[str, Any]:
            assert operator_user_name is None
            return {
                "instance_arn": instance_arn,
                "identity_store_id": identity_store_id,
                "saml_provider_arn": SYNTHETIC_SAML_PROVIDER_ARN,
                "principal_id": principal_id,
                "permission_set": permission_set,
            }

        def readback(self, **_: Any) -> None:
            raise module.AwsReadError("AWS_READ_FAILED")

    monkeypatch.setattr(module, "_load_intent", lambda _: intent)
    _allow_synthetic_source(module, monkeypatch)
    monkeypatch.setattr(module, "_adapter", lambda _: FakeAdapter())
    monkeypatch.setattr(module, "_operator_name", lambda _: None)
    monkeypatch.setattr(module, "_now", lambda: now)
    receipt_path = tmp_path / "reconcile-receipt.json"
    args = Namespace(receipt_out=receipt_path)

    assert module._cmd_reconcile(args) == 2
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    assert receipt["status"] == "READBACK_INCOMPLETE"
    assert receipt["aws_mutation_attempted"] is False
    assert receipt["ambiguous_response"] is True


def test_reconcile_inventory_failure_is_incomplete_without_claiming_drift(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    module = _module("gug220_cli_reconcile_inventory_failure")
    now = datetime(2026, 7, 21, 12, 0, tzinfo=UTC)
    intent = module.build_provisioning_intent(
        principal_id="synthetic-user-id",
        identity_center_instance_arn=(
            "arn:aws:sso:::instance/ssoins-0123456789abcdef"
        ),
        identity_store_id="d-0123456789",
        saml_provider_arn=SYNTHETIC_SAML_PROVIDER_ARN,
        source_commit=SYNTHETIC_SOURCE_COMMIT,
        execution_ledger_directory_id=str(tmp_path),
        created_at=now,
        repo_root=REPO_ROOT,
    )

    class FakeAdapter:
        def inventory(self, *, operator_user_name: str | None) -> dict[str, Any]:
            assert operator_user_name is None
            raise module.AwsReadError("AWS_READ_FAILED")

    monkeypatch.setattr(module, "_load_intent", lambda _: intent)
    _allow_synthetic_source(module, monkeypatch)
    monkeypatch.setattr(module, "_adapter", lambda _: FakeAdapter())
    monkeypatch.setattr(module, "_operator_name", lambda _: None)
    monkeypatch.setattr(module, "_now", lambda: now)
    receipt_path = tmp_path / "inventory-failure-receipt.json"

    assert module._cmd_reconcile(Namespace(receipt_out=receipt_path)) == 2
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    assert receipt["status"] == "READBACK_INCOMPLETE"
    assert receipt["permission_set_arn_digest"] is None
    assert receipt["aws_mutation_attempted"] is False
    assert receipt["ambiguous_response"] is True


def test_reconcile_malformed_permission_set_arn_records_blocked_drift_safely(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    module = _module("gug220_cli_reconcile_malformed_arn")
    now = datetime(2026, 7, 21, 12, 0, tzinfo=UTC)
    intent = module.build_provisioning_intent(
        principal_id="synthetic-user-id",
        identity_center_instance_arn=(
            "arn:aws:sso:::instance/ssoins-0123456789abcdef"
        ),
        identity_store_id="d-0123456789",
        saml_provider_arn=SYNTHETIC_SAML_PROVIDER_ARN,
        source_commit=SYNTHETIC_SOURCE_COMMIT,
        execution_ledger_directory_id=str(tmp_path),
        created_at=now,
        repo_root=REPO_ROOT,
    )
    malformed = {"PermissionSetArn": {"unexpected": "shape"}}

    class FakeAdapter:
        def inventory(self, *, operator_user_name: str | None) -> dict[str, Any]:
            assert operator_user_name is None
            return {
                "instance_arn": "arn:aws:sso:::instance/ssoins-0123456789abcdef",
                "identity_store_id": "d-0123456789",
                "saml_provider_arn": SYNTHETIC_SAML_PROVIDER_ARN,
                "principal_id": "synthetic-user-id",
                "permission_set": malformed,
            }

        def readback(self, **_: Any) -> None:
            raise module.AuditPermissionSetError("PERMISSION_SET_ARN_INVALID")

    monkeypatch.setattr(module, "_load_intent", lambda _: intent)
    _allow_synthetic_source(module, monkeypatch)
    monkeypatch.setattr(module, "_adapter", lambda _: FakeAdapter())
    monkeypatch.setattr(module, "_operator_name", lambda _: None)
    monkeypatch.setattr(module, "_now", lambda: now)
    receipt_path = tmp_path / "malformed-reconcile-receipt.json"

    assert module._cmd_reconcile(Namespace(receipt_out=receipt_path)) == 2
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    assert receipt["status"] == "BLOCKED_DRIFT"
    assert receipt["permission_set_arn_digest"] is None


def test_uncertain_receipt_sink_failure_emits_sanitized_public_status(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    module = _module("gug220_cli_uncertain_receipt_sink")

    def fail(*_: Any, **__: Any) -> None:
        raise module.AuditPermissionSetError("PRIVATE_OUTPUT_WRITE_FAILED")

    monkeypatch.setattr(module, "_write_reserved_private", fail)
    with pytest.raises(
        module.AuditPermissionSetError,
        match="^PRIVATE_OUTPUT_WRITE_FAILED$",
    ):
        module._persist_uncertain_receipt_or_report(
            descriptor=1,
            receipt={"receipt_digest": "sha256:" + "b" * 64},
            intent_digest="sha256:" + "a" * 64,
        )

    public = json.loads(capsys.readouterr().out)
    assert public == {
        "intent_digest": "sha256:" + "a" * 64,
        "production_status": "NO-GO",
        "receipt_digest": None,
        "status": "UNCERTAIN_RECONCILE_ONLY",
    }


def test_intent_is_revalidated_immediately_before_first_effect(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    module = _module("gug220_cli_expiry_before_effect")
    instance_arn = "arn:aws:sso:::instance/ssoins-0123456789abcdef"
    identity_store_id = "d-0123456789"
    principal_id = "synthetic-user-id"
    now = datetime(2026, 7, 21, 12, 0, tzinfo=UTC)
    intent = module.build_provisioning_intent(
        principal_id=principal_id,
        identity_center_instance_arn=instance_arn,
        identity_store_id=identity_store_id,
        saml_provider_arn=SYNTHETIC_SAML_PROVIDER_ARN,
        source_commit=SYNTHETIC_SOURCE_COMMIT,
        execution_ledger_directory_id=str(tmp_path),
        created_at=now,
        repo_root=REPO_ROOT,
    )
    permission_set = {
        "PermissionSetArn": (
            "arn:aws:sso:::permissionSet/ssoins-0123456789abcdef/"
            "ps-fedcba9876543210"
        )
    }

    class FakeAdapter:
        def inventory(self, *, operator_user_name: str | None) -> dict[str, Any]:
            assert operator_user_name is None
            return {
                "instance_arn": instance_arn,
                "identity_store_id": identity_store_id,
                "saml_provider_arn": SYNTHETIC_SAML_PROVIDER_ARN,
                "principal_id": principal_id,
                "permission_set": permission_set,
            }

        def partial_state(self, **_: Any) -> dict[str, Any]:
            return {
                "permission_set": permission_set,
                "inline_policy_present": False,
                "assignment_present": True,
                "provisioning_present": True,
            }

        def put_inline_policy(self, **_: Any) -> None:
            raise AssertionError("effect must not run after intent expiry")

    observed_times = iter(
        (
            now,
            now + timedelta(minutes=1),
            now + timedelta(minutes=15),
            now + timedelta(minutes=15),
        )
    )
    monkeypatch.setattr(module, "_load_intent", lambda _: intent)
    _allow_synthetic_source(module, monkeypatch)
    monkeypatch.setattr(module, "_adapter", lambda _: FakeAdapter())
    monkeypatch.setattr(module, "_operator_name", lambda _: None)
    monkeypatch.setattr(module, "_now", lambda: next(observed_times))
    args = Namespace(
        allow_identity_center_mutation=True,
        execution_ledger_directory=tmp_path,
        receipt_out=tmp_path / "receipt.json",
    )

    assert module._cmd_apply(args) == 2
    receipt = json.loads(args.receipt_out.read_text(encoding="utf-8"))
    assert receipt["status"] == "BLOCKED_DRIFT"
    assert receipt["aws_mutation_attempted"] is False
    assert list(tmp_path.glob("gug220-*.execution-ledger.v1.json"))


def test_async_receipt_mismatch_is_reconcile_only() -> None:
    module = _module("gug220_cli_async_receipt")

    class FakeClient:
        def run(self, *_: str) -> dict[str, Any]:
            return {
                "AccountAssignmentCreationStatus": {
                    "Status": "SUCCEEDED",
                    "RequestId": "request",
                    "PermissionSetArn": "foreign",
                    "PrincipalId": "synthetic-user",
                    "TargetId": module.AUTHORITY_ACCOUNT_ID,
                }
            }

    adapter = object.__new__(module.IdentityCenterAdapter)
    adapter.management = FakeClient()
    with pytest.raises(
        module.AwsMutationUncertain, match="AWS_MUTATION_RECEIPT_MISMATCH"
    ):
        adapter._wait(
            operation="assignment",
            instance_arn="instance",
            request_id="request",
            permission_set_arn="expected",
            principal_id="synthetic-user",
        )


@pytest.mark.parametrize(
    "missing_field",
    ("RequestId", "PermissionSetArn", "TargetId", "TargetType", "PrincipalType", "PrincipalId"),
)
def test_async_success_requires_complete_exact_assignment_binding(
    missing_field: str,
) -> None:
    module = _module(f"gug220_cli_async_missing_{missing_field}")
    status = {
        "Status": "SUCCEEDED",
        "RequestId": "request",
        "PermissionSetArn": "expected",
        "TargetId": module.AUTHORITY_ACCOUNT_ID,
        "TargetType": "AWS_ACCOUNT",
        "PrincipalType": "USER",
        "PrincipalId": "synthetic-user",
    }
    status.pop(missing_field)

    class FakeClient:
        def run(self, *_: str) -> dict[str, Any]:
            return {"AccountAssignmentCreationStatus": status}

    adapter = object.__new__(module.IdentityCenterAdapter)
    adapter.management = FakeClient()
    with pytest.raises(
        module.AwsMutationUncertain, match="AWS_MUTATION_RECEIPT_MISMATCH"
    ):
        adapter._wait(
            operation="assignment",
            instance_arn="instance",
            request_id="request",
            permission_set_arn="expected",
            principal_id="synthetic-user",
        )


@pytest.mark.parametrize(
    "mutation", ("extra-principal", "extra-action", "other-provider")
)
def test_collector_role_rejects_non_exact_saml_trust(
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
) -> None:
    module = _module(f"gug220_cli_exact_trust_{mutation}")
    role_name = (
        "AWSReservedSSO_ScanalyzeAuthorityLambdaAudit_0123456789abcdef"
    )
    role_arn = (
        "arn:aws:iam::042360977644:role/aws-reserved/sso.amazonaws.com/"
        + role_name
    )
    trust: dict[str, Any] = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {
                    "Federated": (
                        "arn:aws:iam::042360977644:saml-provider/"
                        "AWSSSO_0123456789abcdef_DO_NOT_DELETE"
                    )
                },
                "Action": ["sts:AssumeRoleWithSAML", "sts:TagSession"],
                "Condition": {
                    "StringEquals": {
                        "SAML:aud": "https://signin.aws.amazon.com/saml"
                    }
                },
            }
        ],
    }
    if mutation == "extra-principal":
        trust["Statement"][0]["Principal"]["AWS"] = (
            "arn:aws:iam::042360977644:root"
        )
    elif mutation == "extra-action":
        trust["Statement"][0]["Action"].append("sts:AssumeRole")
    else:
        trust["Statement"][0]["Principal"]["Federated"] = (
            "arn:aws:iam::042360977644:saml-provider/"
            "AWSSSO_fedcba9876543210_DO_NOT_DELETE"
        )

    class FakeAuthorityClient:
        def run(self, service: str, operation: str, *_: str, **__: Any) -> dict[str, Any]:
            assert service in {"sts", "iam"}
            if operation == "get-caller-identity":
                return {
                    "Account": module.AUTHORITY_ACCOUNT_ID,
                    "Arn": (
                        "arn:aws:sts::042360977644:assumed-role/"
                        "AWSReservedSSO_AWSReadOnlyAccess_0123456789abcdef/"
                        "synthetic.user"
                    ),
                }
            if operation == "get-role":
                return {
                    "Role": {
                        "RoleName": role_name,
                        "Arn": role_arn,
                        "AssumeRolePolicyDocument": copy.deepcopy(trust),
                    }
                }
            if operation == "list-attached-role-policies":
                return {"AttachedPolicies": []}
            if operation == "list-role-policies":
                return {"PolicyNames": ["ScanalyzeAuthorityLambdaAudit"]}
            if operation == "get-role-policy":
                return {
                    "PolicyDocument": module.render_exact_collector_policy(
                        REPO_ROOT
                    )
                }
            raise AssertionError(f"unexpected operation: {operation}")

    monkeypatch.setattr(
        module,
        "_iam_roles",
        lambda _: [{"RoleName": role_name, "Arn": role_arn}],
    )
    adapter = object.__new__(module.IdentityCenterAdapter)
    adapter.authority = FakeAuthorityClient()
    adapter.repo_root = REPO_ROOT

    with pytest.raises(
        module.AuditPermissionSetError, match="COLLECTOR_ROLE_TRUST_INVALID"
    ):
        adapter.collector_role(
            expected_saml_provider_arn=SYNTHETIC_SAML_PROVIDER_ARN,
            expected_policy=module.render_exact_collector_policy(REPO_ROOT),
        )
