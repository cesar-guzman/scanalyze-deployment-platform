"""Offline integrity and negative-fixture tests for GUG-93 contracts."""

from __future__ import annotations

import copy
import json
import subprocess
import sys
from pathlib import Path

import jsonschema
import pytest

from tooling.policy_digest import (
    CanonicalizationError,
    canonicalize_rfc8785,
    compute_policy_digest,
    load_digest,
    verify_policy_digest,
)
from tooling.validate_enterprise_authorization import DuplicateKeyError
from tooling.validate_schema import (
    find_schema_for_fixture,
    load_json,
    validate_fixture,
    validate_semantics,
)


REPO_ROOT = Path(__file__).resolve().parent.parent
POLICY_PATH = (
    REPO_ROOT / "policies/authorization/enterprise-authorization.v1.json"
)
DIGEST_PATH = (
    REPO_ROOT / "policies/authorization/enterprise-authorization.v1.sha256"
)
IDENTITY_SCHEMA = REPO_ROOT / "schemas/contract-identity-control-plane.v1.schema.json"
IDENTITY_FIXTURE = (
    REPO_ROOT / "fixtures/valid/contract-identity-control-plane-v1.json"
)
EDGE_SCHEMA = REPO_ROOT / "schemas/contract-edge-identity.v2.schema.json"
EDGE_FIXTURE = REPO_ROOT / "fixtures/valid/contract-edge-identity-v2.json"
FRONTEND_V1_SCHEMA = REPO_ROOT / "schemas/frontend-config.schema.json"
FRONTEND_V2_SCHEMA = REPO_ROOT / "schemas/frontend-config.v2.schema.json"
FRONTEND_V2_FIXTURE = REPO_ROOT / "fixtures/valid/frontend-config-v2-synthetic.json"
INVALID_FIXTURES = (
    REPO_ROOT / "fixtures/invalid/contract-identity-control-plane-v1-id-token.json",
    REPO_ROOT
    / "fixtures/invalid/contract-identity-control-plane-v1-provider-mismatch.json",
    REPO_ROOT / "fixtures/invalid/contract-edge-identity-v2-id-token.json",
    REPO_ROOT / "fixtures/invalid/contract-edge-identity-v2-audience-mismatch.json",
    REPO_ROOT / "fixtures/invalid/frontend-config-v2-id-token.json",
    REPO_ROOT / "fixtures/invalid/frontend-config-v2-region-mismatch.json",
)


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _validator(path: Path) -> jsonschema.Draft202012Validator:
    schema = _load(path)
    jsonschema.Draft202012Validator.check_schema(schema)
    return jsonschema.Draft202012Validator(
        schema,
        format_checker=jsonschema.FormatChecker(),
    )


def test_tracked_digest_matches_rfc8785_policy_bytes() -> None:
    policy = _load(POLICY_PATH)
    expected = load_digest(DIGEST_PATH)

    assert canonicalize_rfc8785(policy) == json.dumps(
        policy,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    assert compute_policy_digest(policy) == expected
    assert verify_policy_digest(POLICY_PATH, DIGEST_PATH) == (True, expected)


def test_digest_canonicalization_is_order_independent_and_fail_closed() -> None:
    left = {"z": [3, 2, 1], "a": {"true": True, "none": None}}
    right = {"a": {"none": None, "true": True}, "z": [3, 2, 1]}

    assert canonicalize_rfc8785(left) == canonicalize_rfc8785(right)
    assert compute_policy_digest(left) == compute_policy_digest(right)
    with pytest.raises(CanonicalizationError):
        canonicalize_rfc8785({"unsafe": 1.5})
    with pytest.raises(CanonicalizationError):
        canonicalize_rfc8785({"unsafe": 2**53})


def test_digest_cli_checks_the_tracked_artifact() -> None:
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "tooling.policy_digest",
            str(POLICY_PATH),
            "--check",
            "--digest-file",
            str(DIGEST_PATH),
        ],
        cwd=REPO_ROOT,
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert result.stdout.strip() == "PASS: reviewed policy digest matches"


def test_digest_loader_rejects_duplicate_policy_keys(tmp_path: Path) -> None:
    duplicate = tmp_path / "duplicate-policy.json"
    duplicate.write_text('{"effect":"deny","effect":"allow"}', encoding="utf-8")

    with pytest.raises(DuplicateKeyError):
        verify_policy_digest(duplicate, DIGEST_PATH)


def test_digest_verifier_rejects_stale_or_ambiguous_digest_files(
    tmp_path: Path,
) -> None:
    stale = tmp_path / "stale.sha256"
    stale.write_text(f"sha256:{'0' * 64}\n", encoding="utf-8")
    malformed = tmp_path / "malformed.sha256"
    malformed.write_text(
        f"sha256:{'0' * 64}\nsha256:{'1' * 64}\n",
        encoding="utf-8",
    )

    matches, computed = verify_policy_digest(POLICY_PATH, stale)
    assert matches is False
    assert computed == load_digest(DIGEST_PATH)
    with pytest.raises(ValueError):
        load_digest(malformed)


@pytest.mark.parametrize(
    ("schema_path", "fixture_path"),
    (
        (IDENTITY_SCHEMA, IDENTITY_FIXTURE),
        (EDGE_SCHEMA, EDGE_FIXTURE),
        (FRONTEND_V2_SCHEMA, FRONTEND_V2_FIXTURE),
    ),
)
def test_gug93_valid_contracts_pass_shape_and_semantics(
    schema_path: Path,
    fixture_path: Path,
) -> None:
    validator = _validator(schema_path)
    fixture = _load(fixture_path)

    assert list(validator.iter_errors(fixture)) == []
    assert validate_semantics(fixture, schema_path) == []
    assert validate_fixture(fixture_path, schema_path) == (True, "PASS")


@pytest.mark.parametrize("fixture_path", INVALID_FIXTURES, ids=lambda path: path.stem)
def test_gug93_negative_fixtures_fail_closed(fixture_path: Path) -> None:
    schema_path = find_schema_for_fixture(fixture_path.stem, REPO_ROOT / "schemas")

    assert schema_path is not None
    valid, message = validate_fixture(fixture_path, schema_path)
    assert not valid
    assert message.startswith("FAIL:")


@pytest.mark.parametrize(
    ("fixture_path", "schema_path", "expected"),
    (
        (
            REPO_ROOT
            / "fixtures/invalid"
            / "contract-identity-control-plane-v1-provider-mismatch.json",
            IDENTITY_SCHEMA,
            "pool ARN",
        ),
        (
            REPO_ROOT
            / "fixtures/invalid/contract-edge-identity-v2-audience-mismatch.json",
            EDGE_SCHEMA,
            "audiences",
        ),
        (
            REPO_ROOT / "fixtures/invalid/frontend-config-v2-region-mismatch.json",
            FRONTEND_V2_SCHEMA,
            "Cognito region",
        ),
    ),
)
def test_semantic_negative_fixtures_are_well_shaped_but_denied(
    fixture_path: Path,
    schema_path: Path,
    expected: str,
) -> None:
    fixture = _load(fixture_path)

    assert list(_validator(schema_path).iter_errors(fixture)) == []
    errors = validate_semantics(fixture, schema_path)
    assert any(expected in error for error in errors)


def test_frontend_v2_is_additive_and_never_reinterprets_v1() -> None:
    legacy = _load(FRONTEND_V1_SCHEMA)
    schema = _load(FRONTEND_V2_SCHEMA)
    fixture = _load(FRONTEND_V2_FIXTURE)

    assert legacy["$id"].endswith("frontend-config.v1.schema.json")
    assert legacy["properties"]["schema_version"]["const"] == "1"
    assert schema["$id"].endswith("frontend-config.v2.schema.json")
    assert schema["properties"]["schema_version"]["const"] == "2"
    assert find_schema_for_fixture(
        FRONTEND_V2_FIXTURE.stem,
        FRONTEND_V2_SCHEMA.parent,
    ) == FRONTEND_V2_SCHEMA
    assert fixture["identity_values_authoritative"] is False
    assert fixture["authorization"]["allowed_token_uses"] == ["access"]
    assert "m2m_client_ids" not in fixture


def test_frontend_v2_rejects_identity_authority_and_m2m_material() -> None:
    fixture = _load(FRONTEND_V2_FIXTURE)
    validator = _validator(FRONTEND_V2_SCHEMA)

    authoritative = copy.deepcopy(fixture)
    authoritative["identity_values_authoritative"] = True
    assert list(validator.iter_errors(authoritative))

    m2m_material = copy.deepcopy(fixture)
    m2m_material["m2m_client_ids"] = ["syntheticm2mclient00000000001"]
    assert list(validator.iter_errors(m2m_material))


def test_policy_digest_is_bound_into_every_gug93_public_contract() -> None:
    expected = load_digest(DIGEST_PATH)

    for fixture_path, schema_path in (
        (IDENTITY_FIXTURE, IDENTITY_SCHEMA),
        (EDGE_FIXTURE, EDGE_SCHEMA),
        (FRONTEND_V2_FIXTURE, FRONTEND_V2_SCHEMA),
    ):
        fixture = load_json(fixture_path)
        serialized = json.dumps(fixture, sort_keys=True)
        assert expected in serialized

        stale = copy.deepcopy(fixture)
        if "policy_digest" in stale:
            stale["policy_digest"] = f"sha256:{'0' * 64}"
        else:
            stale["authorization"]["policy_digest"] = f"sha256:{'0' * 64}"
        assert list(_validator(schema_path).iter_errors(stale))
