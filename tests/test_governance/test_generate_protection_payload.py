"""Synthetic-only tests for deterministic branch-protection projection."""

from __future__ import annotations

import copy
from datetime import UTC, datetime
import hashlib
import importlib.util
from itertools import product
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


def _expected_put_status_checks() -> dict[str, object]:
    return {
        "strict": True,
        "checks": [
            {"context": context, "app_id": APP_ID}
            for context in _target_contexts()
        ],
    }


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


def _raw_protection() -> dict[str, object]:
    return copy.deepcopy(_protection())


def _safe_protection() -> dict[str, object]:
    protection = _protection()
    protection["required_status_checks"]["strict"] = True
    protection["enforce_admins"]["enabled"] = True
    reviews = protection["required_pull_request_reviews"]
    reviews["dismiss_stale_reviews"] = True
    reviews["require_code_owner_reviews"] = True
    reviews["require_last_push_approval"] = True
    reviews["required_approving_review_count"] = 2
    reviews["bypass_pull_request_allowances"] = {
        "users": [],
        "teams": [],
        "apps": [],
    }
    protection["required_conversation_resolution"]["enabled"] = True
    protection["allow_force_pushes"]["enabled"] = False
    protection["allow_deletions"]["enabled"] = False
    return protection


def _write_input(tmp_path: Path, document: object | str) -> Path:
    tmp_path.chmod(0o700)
    path = tmp_path / "before.json"
    text = document if isinstance(document, str) else json.dumps(document)
    path.write_text(text, encoding="utf-8")
    path.chmod(0o600)
    return path


def _write_raw_input(tmp_path: Path, document: object | str | None = None) -> Path:
    tmp_path.chmod(0o700)
    path = tmp_path / "raw-before.json"
    raw_document = _raw_protection() if document is None else document
    text = raw_document if isinstance(raw_document, str) else json.dumps(raw_document)
    path.write_text(text, encoding="utf-8")
    path.chmod(0o600)
    return path


def _generate(
    tmp_path: Path,
    document: dict[str, object] | None = None,
    *,
    raw_document: dict[str, object] | None = None,
    output_name: str = "payload.json",
    recovery_output_name: str = "recovery.json",
    completion_output_name: str = "completion.json",
):
    input_path = _write_input(tmp_path, document or _envelope())
    raw_input_path = _write_raw_input(tmp_path, raw_document)
    output_path = tmp_path / output_name
    recovery_output_path = tmp_path / recovery_output_name
    completion_output_path = tmp_path / completion_output_name
    result = generator.generate_payload(
        input_path=input_path,
        raw_input_path=raw_input_path,
        policy_path=POLICY_PATH,
        output_path=output_path,
        recovery_output_path=recovery_output_path,
        completion_output_path=completion_output_path,
        now=FIXED_NOW,
        max_age_seconds=300,
    )
    return result, output_path, recovery_output_path


def test_generator_emits_single_app_bound_checks_put_representation(
    tmp_path: Path,
) -> None:
    result, output_path, recovery_output_path = _generate(tmp_path)
    payload = json.loads(output_path.read_text(encoding="utf-8"))

    assert payload["required_status_checks"] == _expected_put_status_checks()
    assert payload["enforce_admins"] is True
    assert payload["required_pull_request_reviews"] == {
        "dismissal_restrictions": {
            "users": ["release-manager"],
            "teams": ["security-reviewers"],
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
    assert recovery_output_path.exists()


@pytest.mark.parametrize("representation", ["null", "omitted"])
def test_real_get_shape_normalizes_absent_actor_groups(
    tmp_path: Path,
    representation: str,
) -> None:
    document = _envelope()
    raw_document = _raw_protection()
    reviews = document["protection"]["required_pull_request_reviews"]
    raw_reviews = raw_document["required_pull_request_reviews"]
    for field in ("dismissal_restrictions", "bypass_pull_request_allowances"):
        if representation == "null":
            reviews[field] = None
            raw_reviews[field] = None
        else:
            reviews.pop(field)
            raw_reviews.pop(field)
    if representation == "null":
        document["protection"]["restrictions"] = None
        raw_document["restrictions"] = None
    else:
        document["protection"].pop("restrictions")
        raw_document.pop("restrictions")

    result, output_path, recovery_output_path = _generate(
        tmp_path,
        document,
        raw_document=raw_document,
    )
    payload = json.loads(output_path.read_text(encoding="utf-8"))

    assert (
        "bypass_pull_request_allowances"
        not in payload["required_pull_request_reviews"]
    )
    assert "dismissal_restrictions" not in payload["required_pull_request_reviews"]
    assert payload["restrictions"] is None
    assert result.digest == hashlib.sha256(output_path.read_bytes()).hexdigest()
    assert result.recovery_digest == hashlib.sha256(
        recovery_output_path.read_bytes()
    ).hexdigest()


def test_weak_before_state_requires_forward_fix_recovery(tmp_path: Path) -> None:
    result, output_path, recovery_output_path = _generate(tmp_path)
    target = json.loads(output_path.read_text(encoding="utf-8"))
    recovery = json.loads(recovery_output_path.read_text(encoding="utf-8"))

    assert result.classifications["recovery"]["rollback_disposition"] == (
        "ROLLBACK_NOT_PROVABLE"
    )
    assert result.classifications["recovery"]["strategy"] == "FORWARD_ONLY_TARGET"
    assert result.recovery_mode == "FORWARD_ONLY_TARGET"
    assert recovery_output_path.read_bytes() == output_path.read_bytes()
    assert result.recovery_digest == result.digest
    assert target["required_status_checks"] == _expected_put_status_checks()
    assert recovery["required_status_checks"] == _expected_put_status_checks()


def test_mixed_status_check_recovery_candidate_fails_closed_to_target(
    tmp_path: Path,
) -> None:
    protection = _safe_protection()
    document = _envelope()
    document["protection"] = copy.deepcopy(protection)
    original_exact_before = generator._exact_before_payload

    def mixed_exact_before(parsed):
        recovery_candidate = original_exact_before(parsed)
        recovery_candidate["required_status_checks"]["contexts"] = []
        return recovery_candidate

    with patch.object(generator, "_exact_before_payload", mixed_exact_before):
        result, output_path, recovery_output_path = _generate(
            tmp_path,
            document,
            raw_document=copy.deepcopy(protection),
        )

    target = json.loads(output_path.read_text(encoding="utf-8"))
    recovery = json.loads(recovery_output_path.read_text(encoding="utf-8"))
    assert result.recovery_mode == "FORWARD_ONLY_TARGET"
    assert "bare_required_check_contexts_present" in result.classifications[
        "recovery"
    ]["before_floor_violations"]
    assert recovery == target
    assert recovery["required_status_checks"] == _expected_put_status_checks()


@pytest.mark.parametrize(
    ("bypass_shape", "dismissal_shape", "restrictions_shape"),
    list(product(("null", "object"), repeat=3)),
)
def test_actor_group_null_object_matrix_is_deterministic(
    tmp_path: Path,
    bypass_shape: str,
    dismissal_shape: str,
    restrictions_shape: str,
) -> None:
    document = _envelope()
    raw_document = _raw_protection()
    reviews = document["protection"]["required_pull_request_reviews"]
    raw_reviews = raw_document["required_pull_request_reviews"]
    if bypass_shape == "null":
        reviews["bypass_pull_request_allowances"] = None
        raw_reviews["bypass_pull_request_allowances"] = None
    if dismissal_shape == "null":
        reviews["dismissal_restrictions"] = None
        raw_reviews["dismissal_restrictions"] = None
    if restrictions_shape == "null":
        document["protection"]["restrictions"] = None
        raw_document["restrictions"] = None

    result, output_path, recovery_output_path = _generate(
        tmp_path,
        document,
        raw_document=raw_document,
    )

    assert result.digest == hashlib.sha256(output_path.read_bytes()).hexdigest()
    assert result.recovery_digest == hashlib.sha256(
        recovery_output_path.read_bytes()
    ).hexdigest()
    assert result.classifications["raw_actor_provenance"][
        "bypass_pull_request_allowances"
    ]["raw_presence"] == bypass_shape


def test_omitted_null_and_explicit_empty_bypass_generate_identical_target(
    tmp_path: Path,
) -> None:
    results = []
    for name, bypass, omitted in (
        ("omitted", None, True),
        ("null", None, False),
        ("empty", {"users": [], "teams": [], "apps": []}, False),
    ):
        case_path = tmp_path / name
        case_path.mkdir()
        document = _envelope()
        raw_document = _raw_protection()
        reviews = document["protection"]["required_pull_request_reviews"]
        raw_reviews = raw_document["required_pull_request_reviews"]
        if omitted:
            reviews.pop("bypass_pull_request_allowances")
            raw_reviews.pop("bypass_pull_request_allowances")
        else:
            reviews["bypass_pull_request_allowances"] = bypass
            raw_reviews["bypass_pull_request_allowances"] = copy.deepcopy(bypass)
        results.append(
            _generate(case_path, document, raw_document=raw_document)
        )

    assert len({result.digest for result, _, _ in results}) == 1
    assert len({output_path.read_bytes() for _, output_path, _ in results}) == 1
    for _, output_path, _ in results:
        reviews = json.loads(output_path.read_text(encoding="utf-8"))[
            "required_pull_request_reviews"
        ]
        assert "bypass_pull_request_allowances" not in reviews


@pytest.mark.parametrize("invalid", [{}, [], False, "", 0])
@pytest.mark.parametrize(
    ("container_name", "field"),
    [
        ("reviews", "bypass_pull_request_allowances"),
        ("reviews", "dismissal_restrictions"),
        ("protection", "restrictions"),
    ],
)
def test_optional_actor_groups_reject_falsey_malformed_values(
    tmp_path: Path,
    container_name: str,
    field: str,
    invalid: object,
) -> None:
    document = _envelope()
    raw_document = _raw_protection()
    document_container = (
        document["protection"]["required_pull_request_reviews"]
        if container_name == "reviews"
        else document["protection"]
    )
    raw_container = (
        raw_document["required_pull_request_reviews"]
        if container_name == "reviews"
        else raw_document
    )
    document_container[field] = copy.deepcopy(invalid)
    raw_container[field] = copy.deepcopy(invalid)

    with pytest.raises(generator.GitHubProtectionError, match="object|required"):
        _generate(tmp_path, document, raw_document=raw_document)


@pytest.mark.parametrize(
    ("actors", "error"),
    [
        ([{"login": "Release"}, {"login": "release"}], "duplicate actor"),
        ([{"login": " release-manager "}], "whitespace"),
        ([{"login": f"actor-{index}"} for index in range(101)], "100-actor"),
    ],
)
def test_bypass_actor_identity_edge_cases_fail_closed(
    tmp_path: Path,
    actors: list[dict[str, str]],
    error: str,
) -> None:
    document = _envelope()
    raw_document = _raw_protection()
    bypass = {"users": actors, "teams": [], "apps": []}
    document["protection"]["required_pull_request_reviews"][
        "bypass_pull_request_allowances"
    ] = copy.deepcopy(bypass)
    raw_document["required_pull_request_reviews"][
        "bypass_pull_request_allowances"
    ] = copy.deepcopy(bypass)

    with pytest.raises(generator.GitHubProtectionError, match=error):
        _generate(tmp_path, document, raw_document=raw_document)


def test_authenticated_raw_actor_mismatch_creates_no_outputs(tmp_path: Path) -> None:
    document = _envelope()
    raw_document = _raw_protection()
    document["protection"]["required_pull_request_reviews"][
        "bypass_pull_request_allowances"
    ] = {"users": [], "teams": [], "apps": []}

    with pytest.raises(generator.GitHubProtectionError, match="authenticated raw"):
        _generate(tmp_path, document, raw_document=raw_document)

    assert not (tmp_path / "payload.json").exists()
    assert not (tmp_path / "recovery.json").exists()
    assert not (tmp_path / "completion.json").exists()


@pytest.mark.parametrize(
    ("mutation", "expected_field"),
    [
        ("status-checks", "required_status_checks"),
        ("admins", "enforce_admins"),
        ("reviews", "required_pull_request_reviews"),
        ("signatures", "required_signatures"),
        ("linear-history", "required_linear_history"),
    ],
)
def test_authenticated_raw_non_actor_mismatch_creates_no_outputs(
    tmp_path: Path,
    mutation: str,
    expected_field: str,
) -> None:
    raw_document = _raw_protection()
    if mutation == "status-checks":
        raw_document["required_status_checks"]["strict"] = True
    elif mutation == "admins":
        raw_document["enforce_admins"]["enabled"] = True
    elif mutation == "reviews":
        raw_document["required_pull_request_reviews"]["dismiss_stale_reviews"] = True
    elif mutation == "signatures":
        raw_document["required_signatures"]["enabled"] = False
    else:
        raw_document["required_linear_history"]["enabled"] = False

    with pytest.raises(generator.GitHubProtectionError, match=expected_field):
        _generate(tmp_path, raw_document=raw_document)

    assert not (tmp_path / "payload.json").exists()
    assert not (tmp_path / "recovery.json").exists()
    assert not (tmp_path / "completion.json").exists()


def test_authenticated_raw_requires_complete_mapped_state(tmp_path: Path) -> None:
    raw_document = _raw_protection()
    raw_document.pop("block_creations")

    with pytest.raises(generator.GitHubProtectionError, match="block_creations"):
        _generate(tmp_path, raw_document=raw_document)


def test_documented_raw_actor_metadata_is_projected_without_loss(
    tmp_path: Path,
) -> None:
    raw_document = _raw_protection()
    raw_reviews = raw_document["required_pull_request_reviews"]
    raw_reviews["dismissal_restrictions"].update(
        {
            "url": "https://api.github.com/example/dismissals",
            "users_url": "https://api.github.com/example/dismissals/users",
            "teams_url": "https://api.github.com/example/dismissals/teams",
        }
    )
    raw_document["restrictions"].update(
        {
            "url": "https://api.github.com/example/restrictions",
            "users_url": "https://api.github.com/example/restrictions/users",
            "teams_url": "https://api.github.com/example/restrictions/teams",
            "apps_url": "https://api.github.com/example/restrictions/apps",
        }
    )
    raw_reviews["dismissal_restrictions"]["users"][0].update(
        {"id": 7, "node_id": "synthetic-node"}
    )

    result, output_path, recovery_output_path = _generate(
        tmp_path,
        raw_document=raw_document,
    )

    assert result.classifications["raw_actor_provenance"][
        "dismissal_restrictions"
    ]["semantic_actor_count"] == 2
    assert output_path.exists()
    assert recovery_output_path.exists()


def test_unknown_raw_actor_group_metadata_fails_closed(tmp_path: Path) -> None:
    raw_document = _raw_protection()
    raw_document["restrictions"]["unexpected"] = "synthetic"

    with pytest.raises(generator.GitHubProtectionError, match="unknown.*raw"):
        _generate(tmp_path, raw_document=raw_document)


@pytest.mark.parametrize("count", [-1, 7])
def test_review_count_outside_github_put_range_is_rejected(
    tmp_path: Path,
    count: int,
) -> None:
    document = _envelope()
    raw_document = _raw_protection()
    document["protection"]["required_pull_request_reviews"][
        "required_approving_review_count"
    ] = count
    raw_document["required_pull_request_reviews"][
        "required_approving_review_count"
    ] = count

    with pytest.raises(generator.GitHubProtectionError, match=r"0\.\.6"):
        _generate(tmp_path, document, raw_document=raw_document)


def test_safe_before_state_generates_exact_before_recovery(tmp_path: Path) -> None:
    protection = _safe_protection()
    document = _envelope()
    document["protection"] = copy.deepcopy(protection)

    result, output_path, recovery_output_path = _generate(
        tmp_path,
        document,
        raw_document=copy.deepcopy(protection),
    )
    recovery = json.loads(recovery_output_path.read_text(encoding="utf-8"))
    target = json.loads(output_path.read_text(encoding="utf-8"))

    assert result.recovery_mode == "EXACT_BEFORE"
    assert result.classifications["recovery"]["rollback_disposition"] == "EXACT_BEFORE"
    assert recovery["required_pull_request_reviews"][
        "required_approving_review_count"
    ] == 2
    assert (
        "bypass_pull_request_allowances"
        not in recovery["required_pull_request_reviews"]
    )
    assert target["required_pull_request_reviews"]["required_approving_review_count"] == 1
    assert result.recovery_digest != result.digest


@pytest.mark.parametrize(
    ("weakness", "expected_violation"),
    [
        ("strict", "strict_required_checks_disabled"),
        ("approval", "required_approving_review_count_below_one"),
        ("codeowner", "code_owner_review_disabled"),
        ("stale", "stale_review_dismissal_disabled"),
        ("last-push", "last_push_approval_disabled"),
        ("conversation", "conversation_resolution_disabled"),
        ("admins", "admin_enforcement_disabled"),
        ("bypass", "bypass_actors_present"),
        ("force-push", "force_push_allowed"),
        ("deletion", "branch_deletion_allowed"),
    ],
)
def test_each_weak_before_control_forces_forward_only_recovery(
    tmp_path: Path,
    weakness: str,
    expected_violation: str,
) -> None:
    protection = _safe_protection()
    reviews = protection["required_pull_request_reviews"]
    if weakness == "strict":
        protection["required_status_checks"]["strict"] = False
    elif weakness == "approval":
        reviews["required_approving_review_count"] = 0
    elif weakness == "codeowner":
        reviews["require_code_owner_reviews"] = False
    elif weakness == "stale":
        reviews["dismiss_stale_reviews"] = False
    elif weakness == "last-push":
        reviews["require_last_push_approval"] = False
    elif weakness == "conversation":
        protection["required_conversation_resolution"]["enabled"] = False
    elif weakness == "admins":
        protection["enforce_admins"]["enabled"] = False
    elif weakness == "bypass":
        reviews["bypass_pull_request_allowances"] = {
            "users": [{"login": "legacy-bypass"}],
            "teams": [],
            "apps": [],
        }
    elif weakness == "force-push":
        protection["allow_force_pushes"]["enabled"] = True
    else:
        protection["allow_deletions"]["enabled"] = True
    document = _envelope()
    document["protection"] = copy.deepcopy(protection)

    result, output_path, recovery_output_path = _generate(
        tmp_path,
        document,
        raw_document=copy.deepcopy(protection),
    )

    assert result.recovery_mode == "FORWARD_ONLY_TARGET"
    assert expected_violation in result.classifications["recovery"][
        "before_floor_violations"
    ]
    assert recovery_output_path.read_bytes() == output_path.read_bytes()


def test_output_is_private_canonical_and_digest_is_deterministic(tmp_path: Path) -> None:
    input_path = _write_input(tmp_path, _envelope())
    raw_input_path = _write_raw_input(tmp_path)
    outputs = [tmp_path / "payload-a.json", tmp_path / "payload-b.json"]
    recovery_outputs = [tmp_path / "recovery-a.json", tmp_path / "recovery-b.json"]
    completion_outputs = [
        tmp_path / "completion-a.json",
        tmp_path / "completion-b.json",
    ]
    results = [
        generator.generate_payload(
            input_path=input_path,
            raw_input_path=raw_input_path,
            policy_path=POLICY_PATH,
            output_path=output,
            recovery_output_path=recovery_output,
            completion_output_path=completion_output,
            now=FIXED_NOW,
            max_age_seconds=300,
        )
        for output, recovery_output, completion_output in zip(
            outputs,
            recovery_outputs,
            completion_outputs,
            strict=True,
        )
    ]

    assert results[0].digest == results[1].digest
    assert results[0].recovery_digest == results[1].recovery_digest
    assert results[0].completion_digest == results[1].completion_digest
    for result, output, recovery_output, completion_output in zip(
        results,
        outputs,
        recovery_outputs,
        completion_outputs,
        strict=True,
    ):
        payload_bytes = output.read_bytes()
        assert stat.S_IMODE(output.stat().st_mode) == 0o600
        assert payload_bytes.endswith(b"\n")
        assert result.digest == hashlib.sha256(payload_bytes).hexdigest()
        recovery_bytes = recovery_output.read_bytes()
        assert stat.S_IMODE(recovery_output.stat().st_mode) == 0o600
        assert recovery_bytes.endswith(b"\n")
        assert result.recovery_digest == hashlib.sha256(recovery_bytes).hexdigest()
        completion_bytes = completion_output.read_bytes()
        assert stat.S_IMODE(completion_output.stat().st_mode) == 0o600
        assert completion_bytes.endswith(b"\n")
        assert result.completion_digest == hashlib.sha256(
            completion_bytes
        ).hexdigest()
        assert json.loads(completion_bytes) == result.completion_manifest


def test_target_and_recovery_output_paths_must_differ(tmp_path: Path) -> None:
    with pytest.raises(generator.GitHubProtectionError, match="must differ"):
        _generate(
            tmp_path,
            output_name="same.json",
            recovery_output_name="same.json",
        )

    assert not (tmp_path / "same.json").exists()

    with pytest.raises(generator.GitHubProtectionError, match="must differ"):
        _generate(
            tmp_path,
            output_name="same.json",
            completion_output_name="same.json",
        )


def test_preexisting_recovery_output_blocks_both_writes(tmp_path: Path) -> None:
    recovery_output = tmp_path / "recovery.json"
    recovery_output.write_text("synthetic-existing", encoding="utf-8")
    recovery_output.chmod(0o600)

    with pytest.raises(generator.GitHubProtectionError, match="overwrite"):
        _generate(tmp_path)

    assert recovery_output.read_text(encoding="utf-8") == "synthetic-existing"
    assert not (tmp_path / "payload.json").exists()
    assert not (tmp_path / "completion.json").exists()


def test_preexisting_completion_output_blocks_all_writes(tmp_path: Path) -> None:
    completion_output = tmp_path / "completion.json"
    completion_output.write_text("synthetic-existing", encoding="utf-8")
    completion_output.chmod(0o600)

    with pytest.raises(generator.GitHubProtectionError, match="overwrite"):
        _generate(tmp_path)

    assert completion_output.read_text(encoding="utf-8") == "synthetic-existing"
    assert not (tmp_path / "payload.json").exists()
    assert not (tmp_path / "recovery.json").exists()


@pytest.mark.parametrize("fail_on_write", [1, 2, 3])
def test_bundle_write_failure_never_publishes_completion_manifest(
    tmp_path: Path,
    fail_on_write: int,
) -> None:
    original_write = generator._write_private_output
    call_count = 0

    def injected_failure(path: Path, content: bytes):
        nonlocal call_count
        call_count += 1
        if call_count == fail_on_write:
            raise generator.GitHubProtectionError("synthetic bundle write failure")
        return original_write(path, content)

    with patch.object(generator, "_write_private_output", injected_failure):
        with pytest.raises(generator.GitHubProtectionError, match="synthetic"):
            _generate(tmp_path)

    assert (tmp_path / "recovery.json").exists() is (fail_on_write > 1)
    assert (tmp_path / "payload.json").exists() is (fail_on_write > 2)
    assert not (tmp_path / "completion.json").exists()


def test_bundle_failure_never_deletes_concurrent_replacement(tmp_path: Path) -> None:
    original_write = generator._write_private_output
    call_count = 0

    def replace_then_fail(path: Path, content: bytes):
        nonlocal call_count
        call_count += 1
        if call_count == 2:
            recovery_path = tmp_path / "recovery.json"
            recovery_path.unlink()
            recovery_path.write_text("synthetic-replacement", encoding="utf-8")
            recovery_path.chmod(0o600)
            raise generator.GitHubProtectionError("synthetic bundle write failure")
        return original_write(path, content)

    with patch.object(generator, "_write_private_output", replace_then_fail):
        with pytest.raises(generator.GitHubProtectionError, match="synthetic"):
            _generate(tmp_path)

    assert (tmp_path / "recovery.json").read_text(encoding="utf-8") == (
        "synthetic-replacement"
    )
    assert not (tmp_path / "payload.json").exists()
    assert not (tmp_path / "completion.json").exists()


def test_atomic_writer_does_not_publish_partial_file(tmp_path: Path) -> None:
    tmp_path.chmod(0o700)
    output_path = tmp_path / "atomic.json"

    with patch.object(generator.os, "fsync", side_effect=OSError("synthetic fsync")):
        with pytest.raises(generator.GitHubProtectionError, match="atomically"):
            generator._write_private_output(output_path, b"synthetic\n")

    assert not output_path.exists()
    assert not list(tmp_path.glob(".atomic.json.*.tmp"))


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
    raw_input_path = _write_raw_input(tmp_path)

    with pytest.raises(generator.GitHubProtectionError, match=error):
        generator.generate_payload(
            input_path=input_path,
            raw_input_path=raw_input_path,
            policy_path=POLICY_PATH,
            output_path=tmp_path / "payload.json",
            recovery_output_path=tmp_path / "recovery.json",
            completion_output_path=tmp_path / "completion.json",
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
    raw_input_path = _write_raw_input(tmp_path)
    policy = json.loads(POLICY_PATH.read_text(encoding="utf-8"))
    policy["required_status_checks"]["checks"][0]["context"] = "Renamed gate"
    policy_path = tmp_path / "alternate-policy.json"
    policy_path.write_text(json.dumps(policy), encoding="utf-8")

    with pytest.raises(generator.GitHubProtectionError, match="canonical governance"):
        generator.generate_payload(
            input_path=input_path,
            raw_input_path=raw_input_path,
            policy_path=policy_path,
            output_path=tmp_path / "payload.json",
            recovery_output_path=tmp_path / "recovery.json",
            completion_output_path=tmp_path / "completion.json",
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
    raw_input_path = _write_raw_input(tmp_path)
    input_path.chmod(0o644)

    with pytest.raises(generator.GitHubProtectionError, match="mode 0600"):
        generator.generate_payload(
            input_path=input_path,
            raw_input_path=raw_input_path,
            policy_path=POLICY_PATH,
            output_path=tmp_path / "payload.json",
            recovery_output_path=tmp_path / "recovery.json",
            completion_output_path=tmp_path / "completion.json",
            now=FIXED_NOW,
            max_age_seconds=300,
        )


def test_weak_permission_raw_input_is_rejected(tmp_path: Path) -> None:
    input_path = _write_input(tmp_path, _envelope())
    raw_input_path = _write_raw_input(tmp_path)
    raw_input_path.chmod(0o644)

    with pytest.raises(generator.GitHubProtectionError, match="mode 0600"):
        generator.generate_payload(
            input_path=input_path,
            raw_input_path=raw_input_path,
            policy_path=POLICY_PATH,
            output_path=tmp_path / "payload.json",
            recovery_output_path=tmp_path / "recovery.json",
            completion_output_path=tmp_path / "completion.json",
            now=FIXED_NOW,
            max_age_seconds=300,
        )


def test_symlinked_input_is_rejected(tmp_path: Path) -> None:
    source = _write_input(tmp_path, _envelope())
    raw_input_path = _write_raw_input(tmp_path)
    link = tmp_path / "linked-before.json"
    link.symlink_to(source)

    with pytest.raises(generator.GitHubProtectionError, match="symlink"):
        generator.generate_payload(
            input_path=link,
            raw_input_path=raw_input_path,
            policy_path=POLICY_PATH,
            output_path=tmp_path / "payload.json",
            recovery_output_path=tmp_path / "recovery.json",
            completion_output_path=tmp_path / "completion.json",
            now=FIXED_NOW,
            max_age_seconds=300,
        )


def test_symlinked_output_is_rejected(tmp_path: Path) -> None:
    input_path = _write_input(tmp_path, _envelope())
    raw_input_path = _write_raw_input(tmp_path)
    target = tmp_path / "unrelated.json"
    target.write_text("{}", encoding="utf-8")
    target.chmod(0o600)
    link = tmp_path / "payload.json"
    link.symlink_to(target)

    with pytest.raises(generator.GitHubProtectionError, match="symlink"):
        generator.generate_payload(
            input_path=input_path,
            raw_input_path=raw_input_path,
            policy_path=POLICY_PATH,
            output_path=link,
            recovery_output_path=tmp_path / "recovery.json",
            completion_output_path=tmp_path / "completion.json",
            now=FIXED_NOW,
            max_age_seconds=300,
        )
    assert target.read_text(encoding="utf-8") == "{}"


def test_operational_output_inside_repository_is_rejected(tmp_path: Path) -> None:
    input_path = _write_input(tmp_path, _envelope())
    raw_input_path = _write_raw_input(tmp_path)
    forbidden_output = REPO_ROOT / "tests" / ".gug119-operational-payload.json"

    with pytest.raises(generator.GitHubProtectionError, match="outside the repository"):
        generator.generate_payload(
            input_path=input_path,
            raw_input_path=raw_input_path,
            policy_path=POLICY_PATH,
            output_path=forbidden_output,
            recovery_output_path=tmp_path / "recovery.json",
            completion_output_path=tmp_path / "completion.json",
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
