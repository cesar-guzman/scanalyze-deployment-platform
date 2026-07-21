"""GUG-219 collector and release contract tests."""
from __future__ import annotations

import copy
import hashlib
import importlib.util
import inspect
import json
import re
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest
from jsonschema import Draft202012Validator, FormatChecker, ValidationError

from tooling.platform_authority_lambda_invocation_authority import canonical_digest
from tooling.validate_schema import validate_semantics


REPO_ROOT = Path(__file__).resolve().parents[2]
COLLECTOR_SCHEMA = (
    REPO_ROOT
    / "schemas/platform-authority-lambda-invocation-collector-contract.v1.schema.json"
)
RELEASE_SCHEMA = (
    REPO_ROOT
    / "schemas/platform-authority-lambda-invocation-allowlist-release.v1.schema.json"
)
ALLOWLIST_SCHEMA = (
    REPO_ROOT
    / "schemas/platform-authority-lambda-invocation-allowlist.v1.schema.json"
)
POLICY_TEMPLATE = (
    REPO_ROOT
    / "policies/iam/platform-authority-lambda-invocation-inventory-role.json"
)


@lru_cache(maxsize=1)
def helpers() -> ModuleType:
    path = Path(__file__).with_name(
        "test_gug219_lambda_authority_materializer.py"
    )
    spec = importlib.util.spec_from_file_location("gug219_materializer_helpers", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _load(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _validator(path: Path) -> Draft202012Validator:
    schema = _load(path)
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema, format_checker=FormatChecker())


def _bundle() -> tuple[Any, dict[str, Any], dict[str, Any], dict[str, Any]]:
    test_support = helpers()
    module = test_support.materializer()
    contract, allowlist, release = test_support.materialized_bundle()
    return module, contract, allowlist, release


def _reseal(record: dict[str, Any], digest_field: str) -> dict[str, Any]:
    record[digest_field] = canonical_digest(
        {key: value for key, value in record.items() if key != digest_field}
    )
    return record


def test_materializer_exports_the_reviewed_tests_first_api() -> None:
    module = helpers().materializer()
    expected = {
        "build_collector_contract": {
            "binding",
            "identity_center_region",
            "collector_iam_role_arn",
            "collector_sts_session_arn",
            "created_at",
            "repo_root",
        },
        "render_collector_inline_policy": {"binding", "repo_root"},
        "materialize_allowlist_release": {
            "snapshot",
            "binding",
            "collector_contract",
            "source_commit",
            "created_at",
            "expires_at",
            "repo_root",
        },
        "validate_release_bundle": {
            "allowlist",
            "release",
            "collector_contract",
            "binding",
            "expected_release_digest",
            "evaluation_at",
        },
        "validate_fresh_capture": {
            "candidate_snapshot",
            "fresh_snapshot",
            "allowlist",
            "release",
                "collector_contract",
                "binding",
                "expected_release_digest",
                "evaluation_at",
            },
        "write_private_bundle": {"output_dir", "repo_root", "artifacts"},
    }

    for function_name, parameters in expected.items():
        function = getattr(module, function_name)
        assert set(inspect.signature(function).parameters) == parameters


def test_materializer_constants_bind_exact_collector_and_broker_names() -> None:
    module = helpers().materializer()

    assert module.COLLECTOR_PERMISSION_SET_NAME == "ScanalyzeAuthorityLambdaAudit"
    assert (
        module.BROKER_FUNCTION_NAME
        == "scanalyze-platform-authority-gug215-retirement"
    )


@pytest.mark.parametrize(
    "schema_path",
    (COLLECTOR_SCHEMA, RELEASE_SCHEMA, ALLOWLIST_SCHEMA),
)
def test_gug219_and_reused_gug218_schemas_are_valid_draft_2020_12(
    schema_path: Path,
) -> None:
    _validator(schema_path)


def test_generated_collector_contract_has_exact_schema_shape() -> None:
    _, contract, _, _ = _bundle()
    schema = _load(COLLECTOR_SCHEMA)

    _validator(COLLECTOR_SCHEMA).validate(contract)
    assert set(contract) == set(schema["required"])


def test_generated_release_has_exact_schema_shape() -> None:
    _, _, _, release = _bundle()
    schema = _load(RELEASE_SCHEMA)

    _validator(RELEASE_SCHEMA).validate(release)
    assert set(release) == set(schema["required"])


def test_materialized_allowlist_reuses_the_complete_gug218_contract() -> None:
    _, _, allowlist, _ = _bundle()

    _validator(ALLOWLIST_SCHEMA).validate(allowlist)
    assert validate_semantics(allowlist, ALLOWLIST_SCHEMA) == []


def test_collector_and_release_records_publish_digests_not_raw_identity() -> None:
    support = helpers()
    _, contract, _, release = _bundle()
    serialized = json.dumps(
        {"collector_contract": contract, "release": release}, sort_keys=True
    )

    for raw_value in (
        support.ACCOUNT,
        support.FUNCTION,
        support.COLLECTOR_IAM_ROLE_ARN,
        support.COLLECTOR_SESSION_ARN,
        "synthetic.operator@example.invalid",
    ):
        assert raw_value not in serialized


def test_release_binds_every_materialized_digest() -> None:
    _, contract, allowlist, release = _bundle()

    assert release["collector_contract_digest"] == contract[
        "collector_contract_digest"
    ]
    assert release["collector_role_principal_digest"] == contract[
        "collector_role_sts_arn_digest"
    ]
    assert release["allowlist_digest"] == allowlist["allowlist_digest"]
    assert release["expected_authority_edges_digest"] == canonical_digest(
        allowlist["expected_authority_edges"]
    )
    assert release["source_template_sha256"] == allowlist[
        "source_template_sha256"
    ]
    assert release["source_policy_bundle_sha256"] == allowlist[
        "source_policy_bundle_sha256"
    ]
    assert release["broker_artifact_code_sha256"] == allowlist[
        "broker_artifact_code_sha256"
    ]
    assert release["broker_published_configuration_sha256"] == allowlist[
        "broker_published_configuration_sha256"
    ]
    assert release["release_digest"] == canonical_digest(
        {key: value for key, value in release.items() if key != "release_digest"}
    )


def test_allowlist_document_digests_come_from_the_candidate_snapshot() -> None:
    support = helpers()
    _, _, allowlist, _ = _bundle()
    snapshot = support.candidate_snapshot()
    raw_documents = [
        item["policy_document"]
        for item in snapshot["lambda"]["resource_policies"]
    ]
    for role in snapshot["iam"]["roles"][:2]:
        raw_documents.append(role["AssumeRolePolicyDocument"])
        raw_documents.extend(
            policy["PolicyDocument"] for policy in role["RolePolicyList"]
        )
    observed_document_digests = {canonical_digest(item) for item in raw_documents}

    assert {
        edge["source_document_digest"]
        for edge in allowlist["expected_authority_edges"]
    } == observed_document_digests


def test_policy_template_has_exactly_the_four_reviewed_placeholders() -> None:
    placeholders = set(
        re.findall(r"\$\{[a-z_]+\}", POLICY_TEMPLATE.read_text(encoding="utf-8"))
    )

    assert placeholders == {
        "${aws_partition}",
        "${region}",
        "${authority_account_id}",
        "${broker_function_name}",
    }


def test_collector_contract_binds_template_and_rendered_policy_digests() -> None:
    support = helpers()
    module, contract, _, _ = _bundle()
    template_digest = "sha256:" + hashlib.sha256(POLICY_TEMPLATE.read_bytes()).hexdigest()
    rendered = module.render_collector_inline_policy(
        binding=support.binding(), repo_root=REPO_ROOT
    )

    assert contract["inline_policy_template_sha256"] == template_digest
    assert contract["collector_inline_policy_digest"] == canonical_digest(rendered)
    assert contract["managed_policy_arns"] == []
    assert contract["customer_managed_policy_references"] == []
    assert contract["permissions_boundary_present"] is False


def test_release_rejects_unknown_fields_even_when_resealed() -> None:
    support = helpers()
    module, contract, allowlist, release = _bundle()
    release["legacy_fallback"] = True
    _reseal(release, "release_digest")

    with pytest.raises(
        module.LambdaAuthorityMaterializationError,
        match="RELEASE_FIELDS_INVALID",
    ):
        module.validate_release_bundle(
            allowlist=allowlist,
            release=release,
            collector_contract=contract,
            binding=support.binding(),
            expected_release_digest=release["release_digest"],
            evaluation_at=support.EVALUATION_AT,
        )


def test_release_rejects_copied_foreign_allowlist_digest_even_when_resealed() -> None:
    support = helpers()
    module, contract, allowlist, release = _bundle()
    release["allowlist_digest"] = "sha256:" + "f" * 64
    _reseal(release, "release_digest")

    with pytest.raises(
        module.LambdaAuthorityMaterializationError,
        match="RELEASE_ALLOWLIST_DIGEST_MISMATCH",
    ):
        module.validate_release_bundle(
            allowlist=allowlist,
            release=release,
            collector_contract=contract,
            binding=support.binding(),
            expected_release_digest=release["release_digest"],
            evaluation_at=support.EVALUATION_AT,
        )


@pytest.mark.parametrize(
    "source_commit",
    (
        "",
        "a" * 39,
        "A" * 40,
        "a" * 41,
        "not-a-git-commit",
    ),
)
def test_materializer_requires_a_full_lowercase_commit_digest(
    source_commit: str,
) -> None:
    support = helpers()
    module = support.materializer()

    with pytest.raises(
        module.LambdaAuthorityMaterializationError,
        match="SOURCE_COMMIT_INVALID",
    ):
        module.materialize_allowlist_release(
            snapshot=support.candidate_snapshot(),
            binding=support.binding(),
            collector_contract=support.collector_contract(),
            source_commit=source_commit,
            created_at=support.RELEASE_CREATED,
            expires_at=support.RELEASE_EXPIRES,
            repo_root=REPO_ROOT,
        )


def test_release_window_cannot_exceed_five_minutes() -> None:
    support = helpers()
    module = support.materializer()

    with pytest.raises(
        module.LambdaAuthorityMaterializationError,
        match="RELEASE_WINDOW_INVALID",
    ):
        module.materialize_allowlist_release(
            snapshot=support.candidate_snapshot(),
            binding=support.binding(),
            collector_contract=support.collector_contract(),
            source_commit=support.SOURCE_COMMIT,
            created_at="2030-01-01T00:01:30Z",
            expires_at="2030-01-01T00:06:31Z",
            repo_root=REPO_ROOT,
        )


def test_release_expiry_is_exclusive_at_the_trusted_evaluation_time() -> None:
    support = helpers()
    module, contract, allowlist, release = _bundle()

    with pytest.raises(
        module.LambdaAuthorityMaterializationError,
        match="RELEASE_EXPIRED",
    ):
        module.validate_release_bundle(
            allowlist=allowlist,
            release=release,
            collector_contract=contract,
            binding=support.binding(),
            expected_release_digest=release["release_digest"],
            evaluation_at=release["expires_at"],
        )


def test_release_schema_denies_live_or_deployment_authorization() -> None:
    _, _, _, release = _bundle()

    for field in ("live_effect_authorized", "deployment_authorized"):
        changed = copy.deepcopy(release)
        changed[field] = True
        _reseal(changed, "release_digest")
        with pytest.raises(ValidationError):
            _validator(RELEASE_SCHEMA).validate(changed)


def test_private_bundle_rejects_artifact_path_traversal(tmp_path: Path) -> None:
    module = helpers().materializer()

    with pytest.raises(
        module.LambdaAuthorityMaterializationError,
        match="ARTIFACT_NAME_INVALID",
    ):
        module.write_private_bundle(
            output_dir=tmp_path / "private",
            repo_root=REPO_ROOT,
            artifacts={"../escaped.json": {"synthetic": True}},
        )


def test_contract_timestamps_are_utc_and_release_is_temporally_ordered() -> None:
    _, contract, _, release = _bundle()

    for value in (
        contract["created_at"],
        release["created_at"],
        release["expires_at"],
    ):
        assert value.endswith("Z")
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        assert parsed.tzinfo == timezone.utc
    assert release["created_at"] < release["expires_at"]
