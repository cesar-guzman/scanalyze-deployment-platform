"""GUG-219 CLI integration and pre-AWS fail-closed tests."""
from __future__ import annotations

import importlib.util
import json
import os
from datetime import UTC, datetime
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest


REPO_ROOT = Path(__file__).resolve().parents[2]
AUTHORITY_SCRIPT = (
    REPO_ROOT
    / "scripts/deployment/platform-authority-lambda-invocation-authority.py"
)
MATERIALIZER_SCRIPT = (
    REPO_ROOT
    / "scripts/deployment/platform-authority-lambda-invocation-materializer.py"
)


def _module(path: Path, name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _support() -> ModuleType:
    return _module(
        Path(__file__).with_name(
            "test_gug219_lambda_authority_materializer.py"
        ),
        "gug219_cli_support",
    )


def _write(path: Path, value: dict[str, Any], *, private: bool = False) -> Path:
    path.write_text(json.dumps(value), encoding="utf-8")
    if private:
        os.chmod(path, 0o600)
    return path


def _aws_args(
    module: ModuleType,
    tmp_path: Path,
    *,
    expected_release_digest: str,
) -> Any:
    support = _support()
    contract, allowlist, release = support.materialized_bundle()
    return module._parser().parse_args(
        [
            "aws-readonly",
            "--allowlist",
            str(_write(tmp_path / "allowlist.json", allowlist, private=True)),
            "--collector-contract",
            str(_write(tmp_path / "collector.json", contract, private=True)),
            "--release-manifest",
            str(_write(tmp_path / "release.json", release, private=True)),
            "--candidate-snapshot",
            str(
                _write(
                    tmp_path / "candidate.json",
                    support.candidate_snapshot(),
                    private=True,
                )
            ),
            "--expected-release-manifest-digest",
            expected_release_digest,
            "--profile",
            "synthetic-profile-name",
            "--authority-account-id",
            support.ACCOUNT,
            "--region",
            support.REGION,
            "--function-name",
            support.FUNCTION,
        ]
    )


def test_aws_cli_requires_release_anchor_instead_of_direct_allowlist_digest() -> None:
    module = _module(AUTHORITY_SCRIPT, "gug219_authority_cli_parser")
    parser = module._parser()
    subparsers = next(
        action for action in parser._actions if hasattr(action, "choices") and action.choices
    )
    aws_options = subparsers.choices["aws-readonly"]._option_string_actions
    offline_options = subparsers.choices["snapshot-check"]._option_string_actions

    assert "--expected-release-manifest-digest" in aws_options
    assert "--collector-contract" in aws_options
    assert "--candidate-snapshot" in aws_options
    assert "--expected-allowlist-digest" not in aws_options
    assert "--expected-allowlist-digest" in offline_options


def test_reviewed_release_digest_is_checked_before_snapshot_loader(
    tmp_path: Path,
) -> None:
    module = _module(AUTHORITY_SCRIPT, "gug219_authority_cli_preflight")
    args = _aws_args(
        module,
        tmp_path,
        expected_release_digest="sha256:" + "0" * 64,
    )
    called = False

    def forbidden_loader(_: Any) -> dict[str, Any]:
        nonlocal called
        called = True
        raise AssertionError("AWS snapshot loader must not run")

    args.snapshot_loader = forbidden_loader
    with pytest.raises(
        module.LambdaAuthorityMaterializationError,
        match="REVIEWED_RELEASE_DIGEST_MISMATCH",
    ):
        module._run(args)
    assert called is False


def test_materializer_cli_refuses_private_input_inside_repository() -> None:
    module = _module(MATERIALIZER_SCRIPT, "gug219_materializer_cli_private")
    with pytest.raises(
        module.LambdaAuthorityMaterializationError,
        match="PRIVATE_INPUT_INSIDE_REPOSITORY",
    ):
        module._private_input(
            REPO_ROOT
            / "fixtures/valid/platform-authority-lambda-invocation-allowlist-v1-synthetic.json"
        )


def _collector_binding(support: ModuleType) -> dict[str, str]:
    return {
        "identity_center_region": support.IDENTITY_CENTER_REGION,
        "collector_iam_role_arn": support.COLLECTOR_IAM_ROLE_ARN,
        "collector_sts_session_arn": support.COLLECTOR_SESSION_ARN,
    }


def _candidate_args(module: ModuleType, support: ModuleType, tmp_path: Path) -> Any:
    binding_path = _write(
        tmp_path / "collector-binding.json",
        _collector_binding(support),
        private=True,
    )
    return module._parser().parse_args(
        [
            "candidate-aws-readonly",
            "--collector-binding",
            str(binding_path),
            "--created-at",
            "2029-12-31T23:59:59Z",
            "--profile",
            "synthetic-dedicated-collector",
            "--output-dir",
            str(tmp_path / "candidate-output"),
            "--authority-account-id",
            support.ACCOUNT,
            "--region",
            support.REGION,
            "--function-name",
            support.FUNCTION,
        ]
    )


def _clear_aws_overrides(monkeypatch: pytest.MonkeyPatch, module: ModuleType) -> None:
    for name in (*module.FORBIDDEN_CREDENTIAL_ENV, *module.FORBIDDEN_TRANSPORT_ENV):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("AWS_REGION", "us-east-1")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")


def test_candidate_cli_mocked_readonly_success_writes_private_bundle(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    module = _module(MATERIALIZER_SCRIPT, "gug219_materializer_candidate_success")
    support = _support()
    args = _candidate_args(module, support, tmp_path)
    args.scan_id = "gug219-synthetic-candidate"
    _clear_aws_overrides(monkeypatch, module)

    class FakeAdapter:
        @classmethod
        def from_boto3(cls, **_: Any) -> "FakeAdapter":
            return cls()

        def collect(self, **_: Any) -> dict[str, Any]:
            return support.candidate_snapshot()

    monkeypatch.setattr(module, "AwsReadOnlyInventoryAdapter", FakeAdapter)

    assert module._candidate_aws_readonly(args) == 0
    output = tmp_path / "candidate-output"
    assert sorted(path.name for path in output.iterdir()) == [
        "candidate-snapshot.json",
        "collector-contract.json",
        "collector-inline-policy.json",
    ]
    assert all(path.stat().st_mode & 0o777 == 0o600 for path in output.iterdir())
    assert json.loads(capsys.readouterr().out)["status"] == (
        "CANDIDATE_CAPTURED_MATERIALIZATION_ONLY"
    )


def test_candidate_cli_rejects_existing_output_before_aws_client(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _module(MATERIALIZER_SCRIPT, "gug219_candidate_output_preflight")
    support = _support()
    args = _candidate_args(module, support, tmp_path)
    args.output_dir.mkdir()
    _clear_aws_overrides(monkeypatch, module)
    called = False

    class ForbiddenAdapter:
        @classmethod
        def from_boto3(cls, **_: Any) -> "ForbiddenAdapter":
            nonlocal called
            called = True
            raise AssertionError("AWS client creation must not run")

    monkeypatch.setattr(module, "AwsReadOnlyInventoryAdapter", ForbiddenAdapter)

    with pytest.raises(
        module.LambdaAuthorityMaterializationError, match="OUTPUT_PATH_EXISTS"
    ):
        module._candidate_aws_readonly(args)
    assert called is False


@pytest.mark.parametrize("name", ("AWS_ACCESS_KEY_ID", "AWS_ENDPOINT_URL"))
def test_candidate_cli_rejects_credential_or_transport_override_before_aws(
    name: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _module(MATERIALIZER_SCRIPT, f"gug219_candidate_env_{name}")
    support = _support()
    args = _candidate_args(module, support, tmp_path)
    _clear_aws_overrides(monkeypatch, module)
    monkeypatch.setenv(name, "synthetic-forbidden-value")
    called = False

    class ForbiddenAdapter:
        @classmethod
        def from_boto3(cls, **_: Any) -> "ForbiddenAdapter":
            nonlocal called
            called = True
            raise AssertionError("AWS client creation must not run")

    monkeypatch.setattr(module, "AwsReadOnlyInventoryAdapter", ForbiddenAdapter)

    with pytest.raises(module.LambdaAuthorityMaterializationError):
        module._candidate_aws_readonly(args)
    assert called is False


def test_materialize_cli_offline_success(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    module = _module(MATERIALIZER_SCRIPT, "gug219_materializer_offline_success")
    support = _support()
    contract = support.collector_contract()
    candidate = support.candidate_snapshot()
    candidate_path = _write(tmp_path / "candidate.json", candidate, private=True)
    contract_path = _write(tmp_path / "contract.json", contract, private=True)
    args = module._parser().parse_args(
        [
            "materialize",
            "--candidate-snapshot",
            str(candidate_path),
            "--collector-contract",
            str(contract_path),
            "--source-commit",
            support.SOURCE_COMMIT,
            "--created-at",
            support.RELEASE_CREATED,
            "--expires-at",
            support.RELEASE_EXPIRES,
            "--output-dir",
            str(tmp_path / "release-output"),
            "--authority-account-id",
            support.ACCOUNT,
            "--region",
            support.REGION,
            "--function-name",
            support.FUNCTION,
        ]
    )
    monkeypatch.setattr(module, "validate_source_commit_binding", lambda **_: None)

    assert module._materialize(args) == 0
    output = tmp_path / "release-output"
    assert sorted(path.name for path in output.iterdir()) == [
        "allowlist.json",
        "collector-contract.json",
        "collector-inline-policy.json",
        "release-manifest.json",
    ]
    assert json.loads(capsys.readouterr().out)["status"] == (
        "MATERIALIZED_REVIEW_REQUIRED"
    )


def test_private_input_rejects_symlink_and_nonregular_file(tmp_path: Path) -> None:
    module = _module(MATERIALIZER_SCRIPT, "gug219_private_input_types")
    target = _write(tmp_path / "target.json", {"synthetic": True}, private=True)
    symlink = tmp_path / "link.json"
    symlink.symlink_to(target)
    directory = tmp_path / "directory.json"
    directory.mkdir(mode=0o700)

    with pytest.raises(
        module.LambdaAuthorityMaterializationError,
        match="PRIVATE_INPUT_SYMLINK_FORBIDDEN",
    ):
        module._private_input(symlink)
    with pytest.raises(
        module.LambdaAuthorityMaterializationError,
        match="PRIVATE_INPUT_MODE_INVALID",
    ):
        module._private_input(directory)


def test_gug218_cli_mocked_fresh_b_success(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    module = _module(AUTHORITY_SCRIPT, "gug219_authority_fresh_success")
    support = _support()
    _, _, release = support.materialized_bundle()
    args = _aws_args(
        module,
        tmp_path,
        expected_release_digest=release["release_digest"],
    )
    args.snapshot_loader = lambda _: support.fresh_snapshot()

    class FixedDateTime(datetime):
        @classmethod
        def now(cls, tz: Any = None) -> datetime:
            return datetime(2030, 1, 1, 0, 3, 1, tzinfo=tz or UTC)

    monkeypatch.setattr(module, "datetime", FixedDateTime)

    assert module._run(args) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["inventory"]["status"] == "REVIEW_SAFE_REPORT_ONLY"
    assert result["receipt"]["status"] == "PREFLIGHT_PASSED_REVIEW_REQUIRED"
