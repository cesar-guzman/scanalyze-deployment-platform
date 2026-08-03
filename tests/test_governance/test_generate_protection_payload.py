"""Synthetic-only tests for deterministic branch-protection projection."""

from __future__ import annotations

import copy
from datetime import UTC, datetime
import hashlib
import importlib.util
import json
from pathlib import Path
import stat
import sys
from unittest.mock import patch

import pytest


REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT_PATH = REPO_ROOT / "scripts" / "governance" / "generate_protection_payload.py"
POLICY_PATH = REPO_ROOT / "governance" / "github-policy.json"
SPEC = importlib.util.spec_from_file_location("generate_protection_payload", SCRIPT_PATH)
assert SPEC is not None and SPEC.loader is not None
generator = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = generator
SPEC.loader.exec_module(generator)

FIXED_NOW = datetime(2026, 8, 3, 12, 0, 0, tzinfo=UTC)
CAPTURED_AT = "2026-08-03T11:59:00Z"
APP_ID = 15368


def _target_contexts() -> list[str]:
    policy = json.loads(POLICY_PATH.read_text(encoding="utf-8"))
    return [item["context"] for item in policy["required_status_checks"]["checks"]]


def _protection() -> dict[str, object]:
    contexts = _target_contexts()
    return {
        "url": "https://api.github.com/repos/cesar-guzman/scanalyze-deployment-platform/branches/main/protection",
        "required_status_checks": {
            "url": "https://api.github.com/repos/example/example/branches/main/protection/required_status_checks",
            "strict": False,
            "contexts": contexts,
            "contexts_url": "https://api.github.com/repos/example/example/branches/main/protection/required_status_checks/contexts",
            "checks": [
                {"context": context, "app_id": APP_ID} for context in contexts
            ],
        },
        "enforce_admins": {"url": "https://api.github.com/example", "enabled": False},
        "required_pull_request_reviews": {
            "url": "https://api.github.com/example",
            "dismissal_restrictions": {
                "users": [{"login": "release-manager"}],
                "teams": [{"slug": "security-reviewers"}],
            },
            "bypass_pull_request_allowances": {
                "users": [{"login": "legacy-bypass"}],
                "teams": [],
                "apps": [],
            },
            "dismiss_stale_reviews": False,
            "require_code_owner_reviews": False,
            "require_last_push_approval": False,
            "required_approving_review_count": 0,
        },
        "required_signatures": {
            "url": "https://api.github.com/example",
            "enabled": True,
        },
        "required_linear_history": {"enabled": True},
        "allow_force_pushes": {"enabled": True},
        "allow_deletions": {"enabled": True},
        "block_creations": {"enabled": True},
        "required_conversation_resolution": {"enabled": False},
        "lock_branch": {"enabled": False},
        "allow_fork_syncing": {"enabled": False},
        "restrictions": {
            "users": [{"login": "release-manager"}],
            "teams": [{"slug": "platform"}],
            "apps": [{"slug": "deployment-app"}],
        },
    }


def _envelope() -> dict[str, object]:
    return {
        "schema_version": "1",
        "repository": "cesar-guzman/scanalyze-deployment-platform",
        "branch": "main",
        "captured_at": CAPTURED_AT,
        "rulesets": [],
        "check_app_bindings": [
            {"app_id": APP_ID, "slug": "github-actions"},
        ],
        "protection": _protection(),
    }


def _write_input(tmp_path: Path, document: object | str) -> Path:
    tmp_path.chmod(0o700)
    path = tmp_path / "before.json"
    text = document if isinstance(document, str) else json.dumps(document)
    path.write_text(text, encoding="utf-8")
    path.chmod(0o600)
    return path


def _generate(
    tmp_path: Path,
    document: dict[str, object] | None = None,
    *,
    output_name: str = "payload.json",
):
    input_path = _write_input(tmp_path, document or _envelope())
    output_path = tmp_path / output_name
    result = generator.generate_payload(
        input_path=input_path,
        policy_path=POLICY_PATH,
        output_path=output_path,
        now=FIXED_NOW,
        max_age_seconds=300,
    )
    return result, output_path


def test_generator_preserves_exact_checks_bindings_and_supported_controls(
    tmp_path: Path,
) -> None:
    result, output_path = _generate(tmp_path)
    payload = json.loads(output_path.read_text(encoding="utf-8"))

    assert payload["required_status_checks"] == {
        "strict": True,
        "contexts": [],
        "checks": [
            {"context": context, "app_id": APP_ID}
            for context in _target_contexts()
        ],
    }
    assert payload["enforce_admins"] is True
    assert payload["required_pull_request_reviews"] == {
        "dismissal_restrictions": {
            "users": ["release-manager"],
            "teams": ["security-reviewers"],
        },
        "bypass_pull_request_allowances": {
            "users": [],
            "teams": [],
            "apps": [],
        },
        "dismiss_stale_reviews": True,
        "require_code_owner_reviews": True,
        "require_last_push_approval": True,
        "required_approving_review_count": 1,
    }
    assert payload["restrictions"] == {
        "users": ["release-manager"],
        "teams": ["platform"],
        "apps": ["deployment-app"],
    }
    assert payload["required_linear_history"] is True
    assert payload["block_creations"] is True
    assert payload["lock_branch"] is False
    assert payload["allow_fork_syncing"] is False
    assert payload["allow_force_pushes"] is False
    assert payload["allow_deletions"] is False
    assert payload["required_conversation_resolution"] is True
    assert "required_signatures" not in payload
    assert result.classifications["required_signatures"] == {
        "action": "separate_endpoint_unchanged",
        "observed_enabled": True,
    }
    assert result.classifications["environments"] == {
        "action": "separate_endpoint_not_mutated",
        "existing_environments_only": True,
        "create_missing_environments": False,
        "required_reviewer": "guguce-google",
        "prevent_self_review": True,
    }


def test_output_is_private_canonical_and_digest_is_deterministic(tmp_path: Path) -> None:
    input_path = _write_input(tmp_path, _envelope())
    outputs = [tmp_path / "payload-a.json", tmp_path / "payload-b.json"]
    results = [
        generator.generate_payload(
            input_path=input_path,
            policy_path=POLICY_PATH,
            output_path=output,
            now=FIXED_NOW,
            max_age_seconds=300,
        )
        for output in outputs
    ]

    assert results[0].digest == results[1].digest
    for result, output in zip(results, outputs, strict=True):
        payload_bytes = output.read_bytes()
        assert stat.S_IMODE(output.stat().st_mode) == 0o600
        assert payload_bytes.endswith(b"\n")
        assert result.digest == hashlib.sha256(payload_bytes).hexdigest()


@pytest.mark.parametrize(
    ("mutation", "error"),
    [
        ("missing", "missing required status check"),
        ("unexpected", "unexpected status check"),
        ("unbound", "positive app_id"),
        ("changed-app", "single GitHub App"),
        ("duplicate", "duplicate status check"),
    ],
)
def test_check_set_or_app_binding_drift_is_rejected(
    tmp_path: Path,
    mutation: str,
    error: str,
) -> None:
    document = _envelope()
    checks = document["protection"]["required_status_checks"]["checks"]
    contexts = document["protection"]["required_status_checks"]["contexts"]
    if mutation == "missing":
        checks.pop()
        contexts.pop()
    elif mutation == "unexpected":
        checks.append({"context": "Unexpected gate", "app_id": APP_ID})
        contexts.append("Unexpected gate")
    elif mutation == "unbound":
        checks[0]["app_id"] = None
    elif mutation == "changed-app":
        checks[0]["app_id"] = APP_ID + 1
    else:
        checks.append(copy.deepcopy(checks[0]))
        contexts.append(contexts[0])

    with pytest.raises(generator.GitHubProtectionError, match=error):
        _generate(tmp_path, document)


def test_app_id_must_match_observed_expected_slug_binding(tmp_path: Path) -> None:
    document = _envelope()
    document["check_app_bindings"][0]["slug"] = "untrusted-app"

    with pytest.raises(generator.GitHubProtectionError, match="policy target"):
        _generate(tmp_path, document)


def test_uniform_but_wrong_app_id_is_rejected(tmp_path: Path) -> None:
    document = _envelope()
    for check in document["protection"]["required_status_checks"]["checks"]:
        check["app_id"] = APP_ID + 1

    with pytest.raises(generator.GitHubProtectionError, match="expected app slug"):
        _generate(tmp_path, document)


@pytest.mark.parametrize(
    ("document", "error"),
    [
        (
            lambda: json.dumps(_envelope()).replace(
                '"schema_version": "1"',
                '"schema_version": "1", "schema_version": "1"',
                1,
            ),
            "duplicate JSON key",
        ),
        (
            lambda: json.dumps({**_envelope(), "rulesets": [float("nan")]}),
            "non-finite JSON value",
        ),
    ],
    ids=["duplicate-key", "non-finite"],
)
def test_strict_json_rejects_ambiguous_values(tmp_path: Path, document, error: str) -> None:
    input_path = _write_input(tmp_path, document())

    with pytest.raises(generator.GitHubProtectionError, match=error):
        generator.generate_payload(
            input_path=input_path,
            policy_path=POLICY_PATH,
            output_path=tmp_path / "payload.json",
            now=FIXED_NOW,
            max_age_seconds=300,
        )


def test_stale_readback_is_rejected(tmp_path: Path) -> None:
    document = _envelope()
    document["captured_at"] = "2026-08-03T11:00:00Z"

    with pytest.raises(generator.GitHubProtectionError, match="stale"):
        _generate(tmp_path, document)


def test_ruleset_and_classic_protection_overlap_is_rejected(tmp_path: Path) -> None:
    document = _envelope()
    document["rulesets"] = [{"id": 42, "enforcement": "active"}]

    with pytest.raises(generator.GitHubProtectionError, match="ruleset/classic"):
        _generate(tmp_path, document)


def test_noncanonical_policy_check_contract_is_rejected(tmp_path: Path) -> None:
    input_path = _write_input(tmp_path, _envelope())
    policy = json.loads(POLICY_PATH.read_text(encoding="utf-8"))
    policy["required_status_checks"]["checks"][0]["context"] = "Renamed gate"
    policy_path = tmp_path / "alternate-policy.json"
    policy_path.write_text(json.dumps(policy), encoding="utf-8")

    with pytest.raises(generator.GitHubProtectionError, match="canonical governance"):
        generator.generate_payload(
            input_path=input_path,
            policy_path=policy_path,
            output_path=tmp_path / "payload.json",
            now=FIXED_NOW,
            max_age_seconds=300,
        )

    with pytest.raises(generator.GitHubProtectionError, match="canonical six"):
        generator._validate_policy(policy)


def test_unknown_branch_protection_field_is_rejected(tmp_path: Path) -> None:
    document = _envelope()
    document["protection"]["unknown_field"] = True

    with pytest.raises(generator.GitHubProtectionError, match="unknown.*field"):
        _generate(tmp_path, document)


@pytest.mark.parametrize(
    "field",
    [
        "enforce_admins",
        "required_conversation_resolution",
        "allow_force_pushes",
        "allow_deletions",
    ],
)
def test_overwritten_get_wrappers_reject_unknown_nested_fields(
    tmp_path: Path,
    field: str,
) -> None:
    document = _envelope()
    document["protection"][field]["unexpected_bypass"] = True

    with pytest.raises(generator.GitHubProtectionError, match=f"unknown.*{field}"):
        _generate(tmp_path, document)


def test_unsanitized_actor_metadata_is_rejected(tmp_path: Path) -> None:
    document = _envelope()
    actor = document["protection"]["restrictions"]["users"][0]
    actor["node_id"] = "synthetic-node-id"

    with pytest.raises(generator.GitHubProtectionError, match="sanitized objects"):
        _generate(tmp_path, document)


def test_weak_permission_input_is_rejected(tmp_path: Path) -> None:
    input_path = _write_input(tmp_path, _envelope())
    input_path.chmod(0o644)

    with pytest.raises(generator.GitHubProtectionError, match="mode 0600"):
        generator.generate_payload(
            input_path=input_path,
            policy_path=POLICY_PATH,
            output_path=tmp_path / "payload.json",
            now=FIXED_NOW,
            max_age_seconds=300,
        )


def test_symlinked_input_is_rejected(tmp_path: Path) -> None:
    source = _write_input(tmp_path, _envelope())
    link = tmp_path / "linked-before.json"
    link.symlink_to(source)

    with pytest.raises(generator.GitHubProtectionError, match="symlink"):
        generator.generate_payload(
            input_path=link,
            policy_path=POLICY_PATH,
            output_path=tmp_path / "payload.json",
            now=FIXED_NOW,
            max_age_seconds=300,
        )


def test_symlinked_output_is_rejected(tmp_path: Path) -> None:
    input_path = _write_input(tmp_path, _envelope())
    target = tmp_path / "unrelated.json"
    target.write_text("{}", encoding="utf-8")
    target.chmod(0o600)
    link = tmp_path / "payload.json"
    link.symlink_to(target)

    with pytest.raises(generator.GitHubProtectionError, match="symlink"):
        generator.generate_payload(
            input_path=input_path,
            policy_path=POLICY_PATH,
            output_path=link,
            now=FIXED_NOW,
            max_age_seconds=300,
        )
    assert target.read_text(encoding="utf-8") == "{}"


def test_operational_output_inside_repository_is_rejected(tmp_path: Path) -> None:
    input_path = _write_input(tmp_path, _envelope())
    forbidden_output = REPO_ROOT / "tests" / ".gug119-operational-payload.json"

    with pytest.raises(generator.GitHubProtectionError, match="outside the repository"):
        generator.generate_payload(
            input_path=input_path,
            policy_path=POLICY_PATH,
            output_path=forbidden_output,
            now=FIXED_NOW,
            max_age_seconds=300,
        )
    assert not forbidden_output.exists()


def test_case_alias_cannot_bypass_repository_containment() -> None:
    canonical = str(REPO_ROOT)
    alias_root = Path(canonical.replace("/Users/", "/users/", 1))
    alias_output = alias_root / "tests" / ".gug119-case-alias.json"
    try:
        real_case_alias = alias_root.samefile(REPO_ROOT)
    except OSError:
        real_case_alias = False

    if real_case_alias:
        with pytest.raises(generator.GitHubProtectionError, match="outside the repository"):
            generator._ensure_outside_repository(alias_output)
        return

    original_samefile = Path.samefile

    def simulated_case_insensitive_samefile(self: Path, other: Path) -> bool:
        if str(self) == str(alias_root) and Path(other) == REPO_ROOT.resolve():
            return True
        return original_samefile(self, other)

    with patch.object(Path, "samefile", simulated_case_insensitive_samefile):
        with pytest.raises(generator.GitHubProtectionError, match="outside the repository"):
            generator._ensure_outside_repository(alias_output)
