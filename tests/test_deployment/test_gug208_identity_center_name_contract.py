"""GUG-208 AWS-valid IAM Identity Center permission-set name contracts."""
from __future__ import annotations

import importlib.util
import re
from pathlib import Path

import pytest

from tooling.platform_authority_bootstrap import BootstrapAuthorizationError


REPO_ROOT = Path(__file__).resolve().parents[2]
CLI_PATH = REPO_ROOT / "scripts/deployment/platform-authority-bootstrap.py"
EXPECTED_PLAN_PERMISSION_SET = "ScanalyzeAuthorityBootstrapPlan"
EXPECTED_APPLY_PERMISSION_SET = "ScanalyzeAuthorityBootstrapApply"
LEGACY_OVERLENGTH_NAMES = (
    "ScanalyzePlatformAuthorityBootstrapPlan",
    "ScanalyzePlatformAuthorityBootstrapApply",
)
AWS_PERMISSION_SET_NAME = re.compile(r"^[A-Za-z0-9_+=,.@-]{1,32}$")


def _load_cli():
    spec = importlib.util.spec_from_file_location("gug208_platform_authority_bootstrap_cli", CLI_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _caller(permission_set: str) -> str:
    return (
        "arn:aws:sts::111122223333:assumed-role/"
        f"AWSReservedSSO_{permission_set}_0123456789abcdef/synthetic.user"
    )


def test_canonical_permission_set_names_satisfy_aws_contract() -> None:
    module = _load_cli()

    assert module.PLAN_PERMISSION_SET == EXPECTED_PLAN_PERMISSION_SET
    assert module.APPLY_PERMISSION_SET == EXPECTED_APPLY_PERMISSION_SET
    assert module.PLAN_PERMISSION_SET != module.APPLY_PERMISSION_SET
    assert len(module.PLAN_PERMISSION_SET.encode("utf-8")) <= 32
    assert len(module.APPLY_PERMISSION_SET.encode("utf-8")) <= 32
    assert AWS_PERMISSION_SET_NAME.fullmatch(module.PLAN_PERMISSION_SET)
    assert AWS_PERMISSION_SET_NAME.fullmatch(module.APPLY_PERMISSION_SET)


@pytest.mark.parametrize(
    "permission_set",
    [
        "",
        "a" * 33,
        "Scanalyze Authority Bootstrap Plan",
        "ScanalyzeAuthorityBootstrapPlan/foreign",
        "ScanalyzeAuthorityBootstrapPlané",
    ],
)
def test_permission_set_name_validator_rejects_nonportable_names(permission_set: str) -> None:
    module = _load_cli()

    with pytest.raises(BootstrapAuthorizationError, match="permission-set name"):
        module._validate_permission_set_name(permission_set)


def test_permission_set_authorization_requires_exact_canonical_role() -> None:
    module = _load_cli()

    module._require_permission_set(
        _caller(EXPECTED_PLAN_PERMISSION_SET),
        module.PLAN_PERMISSION_SET,
    )
    module._require_permission_set(
        _caller(EXPECTED_APPLY_PERMISSION_SET),
        module.APPLY_PERMISSION_SET,
    )

    rejected = (
        _caller(EXPECTED_APPLY_PERMISSION_SET),
        _caller(LEGACY_OVERLENGTH_NAMES[0]),
        _caller(f"{EXPECTED_PLAN_PERMISSION_SET}Elevated"),
        _caller(EXPECTED_PLAN_PERMISSION_SET.lower()),
    )
    for caller_arn in rejected:
        with pytest.raises(BootstrapAuthorizationError, match="canonical"):
            module._require_permission_set(caller_arn, module.PLAN_PERMISSION_SET)


def test_operational_sources_do_not_reintroduce_overlength_names() -> None:
    paths = (
        CLI_PATH,
        REPO_ROOT / "docs/deployment/platform-authority-account-bootstrap.md",
        REPO_ROOT / "tests/test_deployment/test_gug206_platform_authority_bootstrap.py",
    )

    for path in paths:
        contents = path.read_text(encoding="utf-8")
        for legacy_name in LEGACY_OVERLENGTH_NAMES:
            assert legacy_name not in contents, f"legacy permission-set name remains in {path}"


def test_gug208_documentation_and_offline_gate_are_registered() -> None:
    documents = (
        REPO_ROOT / "ADR/ADR-036-identity-center-permission-set-name-contract.md",
        REPO_ROOT / "docs/security/gug-208-identity-center-name-contract-threat-model-delta.md",
        REPO_ROOT / "_NotebookLM_Brain/25_GUG208_Identity_Center_Name_Contract.md",
    )
    for document in documents:
        contents = document.read_text(encoding="utf-8")
        assert EXPECTED_PLAN_PERMISSION_SET in contents
        assert EXPECTED_APPLY_PERMISSION_SET in contents
        assert "Production" in contents and "NO-GO" in contents

    makefile = (REPO_ROOT / "Makefile").read_text(encoding="utf-8")
    notebook_index = (
        REPO_ROOT / "_NotebookLM_Brain/00_INDEX_AND_SOURCE_MAP.md"
    ).read_text(encoding="utf-8")
    assert "test_gug208_identity_center_name_contract.py" in makefile
    assert "25 — GUG-208 Identity Center Name Contract" in notebook_index
