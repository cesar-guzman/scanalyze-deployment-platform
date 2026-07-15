"""GUG-122 deployment target, backend, and locking security contracts."""
from __future__ import annotations

import copy
import json
from datetime import UTC, datetime
from pathlib import Path

import jsonschema
import pytest

from tooling.authorize_deployment_backend import (
    AuthorizationError,
    authorize_backend,
    canonical_digest,
    load_json_strict,
    render_backend_hcl,
    write_private_file,
)
from tooling.deployment_execution_lock import acquire_lock
from tooling.deployment_registry import (
    prepare_registry_create,
    prepare_registry_update,
)


REPO_ROOT = Path(__file__).resolve().parents[2]
SCHEMAS = REPO_ROOT / "schemas"
CUSTOMER_ID = "cust_01J5A1B2C3D4E5F6G7H8J9K0M1"
DEPLOYMENT_ID = "dep_01J5A1B2C3D4E5F6G7H8J9K0M1"
OTHER_DEPLOYMENT_ID = "dep_01J5A1B2C3D4E5F6G7H8J9K0M2"
ACCOUNT_ID = "111222333444"
REGION = "us-east-1"
ENVIRONMENT = "sandbox"
NOW = datetime(2026, 7, 14, 18, 0, tzinfo=UTC)


def _digest(document: dict, field: str) -> str:
    return canonical_digest({k: v for k, v in document.items() if k != field})


def _manifest() -> dict:
    return {
        "schema_version": "2",
        "customer_id": CUSTOMER_ID,
        "deployment_id": DEPLOYMENT_ID,
        "environment": ENVIRONMENT,
        "aws_account_id": ACCOUNT_ID,
        "aws_region": REGION,
        "github": {
            "environment": "synthetic-sandbox",
            "oidc_role_arn": (
                f"arn:aws:iam::{ACCOUNT_ID}:role/github-oidc-scanalyze-deploy"
            ),
        },
        "ecr": {"prefix": "dep-01j5a1b2c3d4e5f6g7h8j9k0m1/scanalyze"},
        "base_image_uri": (
            f"{ACCOUNT_ID}.dkr.ecr.{REGION}.amazonaws.com/base:3.11"
            "@sha256:" + ("a" * 64)
        ),
        "enabled_domains": ["bank", "personal", "gov"],
    }


def _account_ready() -> dict:
    roles = {}
    for role, role_name in (
        ("plan", "Plan"),
        ("apply", "Apply"),
        ("identity_plan", "Identity-Plan"),
        ("identity_apply", "Identity-Apply"),
        ("promotion", "Promotion"),
        ("validation", "Validation"),
        ("diagnostic", "Diagnostic"),
        ("state_recovery", "StateRecovery"),
    ):
        roles[role] = {
            "arn": f"arn:aws:iam::{ACCOUNT_ID}:role/ScanalyzeCustomer-{role_name}",
            "customer_id_tag": CUSTOMER_ID,
            "deployment_id_tag": DEPLOYMENT_ID,
            "account_id_tag": ACCOUNT_ID,
            "region_tag": REGION,
            "environment_tag": ENVIRONMENT,
        }
    document = {
        "schema_version": "2",
        "customer_id": CUSTOMER_ID,
        "deployment_id": DEPLOYMENT_ID,
        "account_id": ACCOUNT_ID,
        "region": REGION,
        "environment": ENVIRONMENT,
        "baseline_version": "v2.0.0",
        "provisioned_at": "2026-07-14T17:00:00Z",
        "roles": roles,
        "state_infrastructure": {
            "state_bucket": f"arn:aws:s3:::scanalyze-{ACCOUNT_ID}-tf-state",
            "evidence_bucket": f"arn:aws:s3:::scanalyze-{ACCOUNT_ID}-tf-evidence",
            "contracts_bucket": f"arn:aws:s3:::scanalyze-{ACCOUNT_ID}-contracts",
            "state_kms_key": (
                f"arn:aws:kms:{REGION}:{ACCOUNT_ID}:key/"
                "00000000-0000-0000-0000-000000000001"
            ),
            "evidence_kms_key": (
                f"arn:aws:kms:{REGION}:{ACCOUNT_ID}:key/"
                "00000000-0000-0000-0000-000000000002"
            ),
            "contracts_kms_key": (
                f"arn:aws:kms:{REGION}:{ACCOUNT_ID}:key/"
                "00000000-0000-0000-0000-000000000003"
            ),
        },
        "controls": {
            "state_versioning_enabled": True,
            "state_default_encryption": "aws:kms",
            "state_bucket_key_enabled": True,
            "state_public_access_blocked": True,
            "state_object_lock_enabled": False,
            "native_lockfile_enabled": True,
        },
    }
    document["contract_digest"] = _digest(document, "contract_digest")
    return document


def _target(account_ready: dict) -> dict:
    document = {
        "schema_version": "1",
        "record_type": "deployment_target",
        "customer_id": CUSTOMER_ID,
        "deployment_id": DEPLOYMENT_ID,
        "account_id": ACCOUNT_ID,
        "region": REGION,
        "environment": "sandbox",
        "status": "READY",
        "registry_version": 7,
        "account_ready": {
            "schema_version": "2",
            "baseline_version": "v2.0.0",
            "contract_digest": account_ready["contract_digest"],
        },
        "state_binding": {
            "state_bucket": account_ready["state_infrastructure"]["state_bucket"],
            "state_kms_key": account_ready["state_infrastructure"]["state_kms_key"],
        },
    }
    document["record_digest"] = _digest(document, "record_digest")
    return document


def _anchor(target: dict) -> dict:
    return {
        "schema_version": "1",
        "deployment_id": target["deployment_id"],
        "registry_version": target["registry_version"],
        "record_digest": target["record_digest"],
    }


def _lock(target: dict) -> dict:
    document = {
        "schema_version": "1",
        "deployment_id": DEPLOYMENT_ID,
        "account_id": ACCOUNT_ID,
        "region": REGION,
        "execution_id": "exec_01J5A1B2C3D4E5F6G7H8J9K0M1",
        "owner": "github:synthetic/repository:run:123",
        "status": "HELD",
        "acquired_at": "2026-07-14T17:55:00Z",
        "expires_at": "2026-07-14T18:30:00Z",
        "registry_record_digest": target["record_digest"],
        "lock_version": 3,
    }
    document["lock_digest"] = _digest(document, "lock_digest")
    return document


def _catalog() -> dict:
    import yaml

    return yaml.safe_load((REPO_ROOT / "deployment/layers.yaml").read_text())


def _authorized(layer: str = "network") -> tuple[dict, dict, dict, dict, dict]:
    account_ready = _account_ready()
    target = _target(account_ready)
    anchor = _anchor(target)
    lock = _lock(target)
    binding = authorize_backend(
        manifest=_manifest(),
        target=target,
        anchor=anchor,
        account_ready=account_ready,
        execution_lock=lock,
        layer_catalog=_catalog(),
        layer=layer,
        now=NOW,
        schema_dir=SCHEMAS,
    )
    return binding, target, anchor, account_ready, lock


def test_authorization_derives_backend_only_from_trusted_bindings() -> None:
    binding, target, _, account_ready, _ = _authorized()

    assert binding["customer_id"] == CUSTOMER_ID
    assert binding["deployment_id"] == DEPLOYMENT_ID
    assert binding["account_id"] == ACCOUNT_ID
    assert binding["region"] == REGION
    assert binding["layer"] == "network"
    assert binding["backend"] == {
        "bucket": f"scanalyze-{ACCOUNT_ID}-tf-state",
        "key": f"{DEPLOYMENT_ID}/{REGION}/network/terraform.tfstate",
        "region": REGION,
        "encrypt": True,
        "kms_key_id": account_ready["state_infrastructure"]["state_kms_key"],
        "use_lockfile": True,
        "allowed_account_ids": [ACCOUNT_ID],
    }
    assert binding["registry_record_digest"] == target["record_digest"]
    assert binding["binding_digest"] == _digest(binding, "binding_digest")


def test_manifest_v2_rejects_request_supplied_backend_coordinates() -> None:
    manifest = _manifest()
    manifest["terraform_backend"] = {
        "bucket": "attacker-controlled",
        "key": "foreign/terraform.tfstate",
    }
    schema = json.loads(
        (SCHEMAS / "deployment-manifest.v2.schema.json").read_text()
    )

    errors = list(jsonschema.Draft202012Validator(schema).iter_errors(manifest))

    assert errors
    assert any("terraform_backend" in error.message for error in errors)


def test_legacy_manifest_is_not_accepted_by_operational_authorizer() -> None:
    manifest = _manifest()
    manifest["schema_version"] = "1"
    manifest["terraform_backend"] = {
        "bucket": "legacy",
        "lock_table": "legacy",
        "key_prefix": "legacy",
    }
    account_ready = _account_ready()
    target = _target(account_ready)

    with pytest.raises(AuthorizationError, match="manifest v2"):
        authorize_backend(
            manifest=manifest,
            target=target,
            anchor=_anchor(target),
            account_ready=account_ready,
            execution_lock=_lock(target),
            layer_catalog=_catalog(),
            layer="network",
            now=NOW,
            schema_dir=SCHEMAS,
        )


def test_legacy_account_ready_is_not_accepted_by_operational_authorizer() -> None:
    account_ready = _account_ready()
    account_ready["schema_version"] = "1"
    account_ready["contract_digest"] = _digest(account_ready, "contract_digest")
    target = _target(account_ready)

    with pytest.raises(AuthorizationError, match="ACCOUNT_READY v2"):
        authorize_backend(
            manifest=_manifest(),
            target=target,
            anchor=_anchor(target),
            account_ready=account_ready,
            execution_lock=_lock(target),
            layer_catalog=_catalog(),
            layer="network",
            now=NOW,
            schema_dir=SCHEMAS,
        )


@pytest.mark.parametrize(
    ("document_name", "field", "value"),
    [
        ("manifest", "customer_id", "cust_01J5A1B2C3D4E5F6G7H8J9K0M2"),
        ("manifest", "deployment_id", OTHER_DEPLOYMENT_ID),
        ("manifest", "aws_account_id", "555666777888"),
        ("manifest", "aws_region", "us-west-2"),
        ("manifest", "environment", "staging"),
        ("account_ready", "customer_id", "cust_01J5A1B2C3D4E5F6G7H8J9K0M2"),
        ("account_ready", "deployment_id", OTHER_DEPLOYMENT_ID),
        ("account_ready", "account_id", "555666777888"),
        ("account_ready", "region", "us-west-2"),
    ],
)
def test_cross_boundary_or_conflicting_target_fails_closed(
    document_name: str,
    field: str,
    value: str,
) -> None:
    manifest = _manifest()
    account_ready = _account_ready()
    target = _target(account_ready)
    anchor = _anchor(target)
    lock = _lock(target)
    document = manifest if document_name == "manifest" else account_ready
    document[field] = value
    if document_name == "account_ready":
        document["contract_digest"] = _digest(document, "contract_digest")

    with pytest.raises(AuthorizationError):
        authorize_backend(
            manifest=manifest,
            target=target,
            anchor=anchor,
            account_ready=account_ready,
            execution_lock=lock,
            layer_catalog=_catalog(),
            layer="network",
            now=NOW,
            schema_dir=SCHEMAS,
        )


def test_tampered_or_unanchored_registry_record_fails_closed() -> None:
    account_ready = _account_ready()
    target = _target(account_ready)
    anchor = _anchor(target)
    lock = _lock(target)
    target["region"] = "us-west-2"

    with pytest.raises(AuthorizationError, match="record digest"):
        authorize_backend(
            manifest=_manifest(),
            target=target,
            anchor=anchor,
            account_ready=account_ready,
            execution_lock=lock,
            layer_catalog=_catalog(),
            layer="network",
            now=NOW,
            schema_dir=SCHEMAS,
        )


def test_registry_anchor_version_and_digest_are_exact() -> None:
    account_ready = _account_ready()
    target = _target(account_ready)
    anchor = _anchor(target)
    anchor["registry_version"] += 1

    with pytest.raises(AuthorizationError, match="anchor"):
        authorize_backend(
            manifest=_manifest(),
            target=target,
            anchor=anchor,
            account_ready=account_ready,
            execution_lock=_lock(target),
            layer_catalog=_catalog(),
            layer="network",
            now=NOW,
            schema_dir=SCHEMAS,
        )


@pytest.mark.parametrize(
    ("control", "value"),
    [
        ("state_versioning_enabled", False),
        ("state_default_encryption", "AES256"),
        ("state_bucket_key_enabled", False),
        ("state_public_access_blocked", False),
        ("state_object_lock_enabled", True),
        ("native_lockfile_enabled", False),
    ],
)
def test_account_baseline_security_mismatch_fails_closed(
    control: str,
    value: object,
) -> None:
    account_ready = _account_ready()
    account_ready["controls"][control] = value
    account_ready["contract_digest"] = _digest(account_ready, "contract_digest")
    target = _target(account_ready)

    with pytest.raises(AuthorizationError):
        authorize_backend(
            manifest=_manifest(),
            target=target,
            anchor=_anchor(target),
            account_ready=account_ready,
            execution_lock=_lock(target),
            layer_catalog=_catalog(),
            layer="network",
            now=NOW,
            schema_dir=SCHEMAS,
        )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("customer_id_tag", "cust_01J5A1B2C3D4E5F6G7H8J9K0M2"),
        ("deployment_id_tag", OTHER_DEPLOYMENT_ID),
        ("account_id_tag", "555666777888"),
        ("region_tag", "us-west-2"),
        ("environment_tag", "staging"),
    ],
)
def test_account_ready_role_resource_tags_are_authoritative(
    field: str, value: str
) -> None:
    account_ready = _account_ready()
    account_ready["roles"]["plan"][field] = value
    account_ready["contract_digest"] = _digest(account_ready, "contract_digest")
    target = _target(account_ready)

    with pytest.raises(AuthorizationError, match="role .*binding|role .*tag"):
        authorize_backend(
            manifest=_manifest(),
            target=target,
            anchor=_anchor(target),
            account_ready=account_ready,
            execution_lock=_lock(target),
            layer_catalog=_catalog(),
            layer="network",
            now=NOW,
            schema_dir=SCHEMAS,
        )


def test_foreign_bucket_or_kms_binding_fails_closed() -> None:
    account_ready = _account_ready()
    target = _target(account_ready)
    target["state_binding"]["state_bucket"] = (
        "arn:aws:s3:::scanalyze-555666777888-tf-state"
    )
    target["record_digest"] = _digest(target, "record_digest")

    with pytest.raises(AuthorizationError, match="state binding"):
        authorize_backend(
            manifest=_manifest(),
            target=target,
            anchor=_anchor(target),
            account_ready=account_ready,
            execution_lock=_lock(target),
            layer_catalog=_catalog(),
            layer="network",
            now=NOW,
            schema_dir=SCHEMAS,
        )


@pytest.mark.parametrize(
    "kms_key",
    [
        "arn:aws:kms:us-east-1:555666777888:key/00000000-0000-0000-0000-000000000001",
        f"arn:aws:kms:us-west-2:{ACCOUNT_ID}:key/00000000-0000-0000-0000-000000000001",
    ],
)
def test_state_kms_key_must_match_exact_account_and_region(kms_key: str) -> None:
    account_ready = _account_ready()
    account_ready["state_infrastructure"]["state_kms_key"] = kms_key
    account_ready["contract_digest"] = _digest(account_ready, "contract_digest")
    target = _target(account_ready)

    with pytest.raises(AuthorizationError, match="state KMS key"):
        authorize_backend(
            manifest=_manifest(),
            target=target,
            anchor=_anchor(target),
            account_ready=account_ready,
            execution_lock=_lock(target),
            layer_catalog=_catalog(),
            layer="network",
            now=NOW,
            schema_dir=SCHEMAS,
        )


@pytest.mark.parametrize("status", ["SUSPENDED", "OFFBOARDING", "ARCHIVED"])
def test_non_executable_registry_status_is_denied(status: str) -> None:
    account_ready = _account_ready()
    target = _target(account_ready)
    target["status"] = status
    target["record_digest"] = _digest(target, "record_digest")

    with pytest.raises(AuthorizationError, match="status"):
        authorize_backend(
            manifest=_manifest(),
            target=target,
            anchor=_anchor(target),
            account_ready=account_ready,
            execution_lock=_lock(target),
            layer_catalog=_catalog(),
            layer="network",
            now=NOW,
            schema_dir=SCHEMAS,
        )


@pytest.mark.parametrize(
    "mutation",
    [
        {"status": "RELEASED"},
        {"deployment_id": OTHER_DEPLOYMENT_ID},
        {"account_id": "555666777888"},
        {"region": "us-west-2"},
        {"expires_at": "2026-07-14T17:59:59Z"},
        {"registry_record_digest": "sha256:" + ("f" * 64)},
    ],
)
def test_missing_foreign_released_or_expired_lock_is_denied(
    mutation: dict[str, object],
) -> None:
    account_ready = _account_ready()
    target = _target(account_ready)
    lock = _lock(target)
    lock.update(mutation)
    lock["lock_digest"] = _digest(lock, "lock_digest")

    with pytest.raises(AuthorizationError, match="lock"):
        authorize_backend(
            manifest=_manifest(),
            target=target,
            anchor=_anchor(target),
            account_ready=account_ready,
            execution_lock=lock,
            layer_catalog=_catalog(),
            layer="network",
            now=NOW,
            schema_dir=SCHEMAS,
        )


@pytest.mark.parametrize(
    ("acquired_at", "expires_at", "message"),
    [
        ("2026-07-14T18:01:00Z", "2026-07-14T18:31:00Z", "future"),
        ("2026-07-14T17:59:00Z", "2026-07-14T18:03:00Z", "duration"),
        ("2026-07-14T16:59:00Z", "2026-07-14T18:00:01Z", "duration"),
    ],
)
def test_future_or_out_of_range_lock_interval_is_denied(
    acquired_at: str,
    expires_at: str,
    message: str,
) -> None:
    account_ready = _account_ready()
    target = _target(account_ready)
    lock = _lock(target)
    lock["acquired_at"] = acquired_at
    lock["expires_at"] = expires_at
    lock["lock_digest"] = _digest(lock, "lock_digest")

    with pytest.raises(AuthorizationError, match=message):
        authorize_backend(
            manifest=_manifest(),
            target=target,
            anchor=_anchor(target),
            account_ready=account_ready,
            execution_lock=lock,
            layer_catalog=_catalog(),
            layer="network",
            now=NOW,
            schema_dir=SCHEMAS,
        )


def test_new_contracts_accept_multi_segment_aws_partitions() -> None:
    _, target, _, account_ready, lock = _authorized()
    partition = "aws-us-gov"
    for role in account_ready["roles"].values():
        role["arn"] = role["arn"].replace("arn:aws:", f"arn:{partition}:")
    for field in ("state_bucket", "evidence_bucket", "contracts_bucket"):
        account_ready["state_infrastructure"][field] = account_ready[
            "state_infrastructure"
        ][field].replace("arn:aws:", f"arn:{partition}:")
    for field in ("state_kms_key", "evidence_kms_key", "contracts_kms_key"):
        account_ready["state_infrastructure"][field] = account_ready[
            "state_infrastructure"
        ][field].replace("arn:aws:", f"arn:{partition}:")
    account_ready["contract_digest"] = _digest(account_ready, "contract_digest")
    target["account_ready"]["contract_digest"] = account_ready["contract_digest"]
    target["state_binding"] = {
        "state_bucket": account_ready["state_infrastructure"]["state_bucket"],
        "state_kms_key": account_ready["state_infrastructure"]["state_kms_key"],
    }
    target["record_digest"] = _digest(target, "record_digest")
    lock["registry_record_digest"] = target["record_digest"]
    lock["lock_digest"] = _digest(lock, "lock_digest")

    result = authorize_backend(
        manifest=_manifest(),
        target=target,
        anchor=_anchor(target),
        account_ready=account_ready,
        execution_lock=lock,
        layer_catalog=_catalog(),
        layer="network",
        now=NOW,
        schema_dir=SCHEMAS,
    )

    assert result["backend"]["kms_key_id"].startswith(f"arn:{partition}:kms:")


def test_same_deployment_cannot_acquire_concurrent_or_stale_lock() -> None:
    account_ready = _account_ready()
    target = _target(account_ready)
    existing = _lock(target)
    request = {
        "deployment_id": DEPLOYMENT_ID,
        "account_id": ACCOUNT_ID,
        "region": REGION,
        "execution_id": "exec_01J5A1B2C3D4E5F6G7H8J9K0M2",
        "owner": "github:synthetic/repository:run:124",
        "registry_record_digest": target["record_digest"],
        "expected_lock_version": 3,
        "ttl_seconds": 1800,
    }

    with pytest.raises(AuthorizationError, match="already held"):
        acquire_lock(existing=existing, request=request, now=NOW)

    stale = copy.deepcopy(existing)
    stale["expires_at"] = "2026-07-14T17:59:59Z"
    stale["lock_digest"] = _digest(stale, "lock_digest")
    with pytest.raises(AuthorizationError, match="reviewed stale-lock recovery"):
        acquire_lock(existing=stale, request=request, now=NOW)


def test_released_lock_can_be_reacquired_with_exact_version() -> None:
    account_ready = _account_ready()
    target = _target(account_ready)
    existing = _lock(target)
    existing["status"] = "RELEASED"
    existing["lock_digest"] = _digest(existing, "lock_digest")
    request = {
        "deployment_id": DEPLOYMENT_ID,
        "account_id": ACCOUNT_ID,
        "region": REGION,
        "execution_id": "exec_01J5A1B2C3D4E5F6G7H8J9K0M2",
        "owner": "github:synthetic/repository:run:124",
        "registry_record_digest": target["record_digest"],
        "expected_lock_version": 3,
        "ttl_seconds": 1800,
    }

    acquired = acquire_lock(existing=existing, request=request, now=NOW)

    assert acquired["status"] == "HELD"
    assert acquired["lock_version"] == 4
    assert acquired["lock_digest"] == _digest(acquired, "lock_digest")


def test_state_key_is_collision_free_across_deployments() -> None:
    first, target, _, account_ready, lock = _authorized()
    manifest = _manifest()
    manifest["deployment_id"] = OTHER_DEPLOYMENT_ID
    account_ready["deployment_id"] = OTHER_DEPLOYMENT_ID
    for role in account_ready["roles"].values():
        role["deployment_id_tag"] = OTHER_DEPLOYMENT_ID
    account_ready["contract_digest"] = _digest(account_ready, "contract_digest")
    target["deployment_id"] = OTHER_DEPLOYMENT_ID
    target["account_ready"]["contract_digest"] = account_ready["contract_digest"]
    target["record_digest"] = _digest(target, "record_digest")
    lock["deployment_id"] = OTHER_DEPLOYMENT_ID
    lock["registry_record_digest"] = target["record_digest"]
    lock["lock_digest"] = _digest(lock, "lock_digest")

    second = authorize_backend(
        manifest=manifest,
        target=target,
        anchor=_anchor(target),
        account_ready=account_ready,
        execution_lock=lock,
        layer_catalog=_catalog(),
        layer="network",
        now=NOW,
        schema_dir=SCHEMAS,
    )

    assert first["backend"]["key"] != second["backend"]["key"]


def test_path_traversal_or_nonterraform_layer_is_rejected() -> None:
    catalog = _catalog()
    catalog["layers"][2]["state_key"] = "{deployment_id}/../foreign.tfstate"
    account_ready = _account_ready()
    target = _target(account_ready)

    with pytest.raises(AuthorizationError, match="state key"):
        authorize_backend(
            manifest=_manifest(),
            target=target,
            anchor=_anchor(target),
            account_ready=account_ready,
            execution_lock=_lock(target),
            layer_catalog=catalog,
            layer="network",
            now=NOW,
            schema_dir=SCHEMAS,
        )


def test_backend_hcl_uses_native_lockfile_and_no_legacy_table() -> None:
    binding, *_ = _authorized()

    rendered = render_backend_hcl(binding)

    assert "use_lockfile = true" in rendered
    assert "encrypt = true" in rendered
    assert f'key = "{DEPLOYMENT_ID}/{REGION}/network/terraform.tfstate"' in rendered
    assert "dynamodb_table" not in rendered
    assert "lock_table" not in rendered


def test_strict_json_loader_rejects_duplicate_keys(tmp_path: Path) -> None:
    document = tmp_path / "duplicate.json"
    document.write_text('{"deployment_id":"one","deployment_id":"two"}')

    with pytest.raises(AuthorizationError, match="duplicate"):
        load_json_strict(document)


def test_backend_artifacts_are_private_and_symlinks_are_denied(tmp_path: Path) -> None:
    destination = tmp_path / "backend.hcl"
    write_private_file(destination, "encrypt = true\n")
    assert destination.stat().st_mode & 0o777 == 0o600

    symlink = tmp_path / "backend-link.hcl"
    symlink.symlink_to(destination)
    with pytest.raises(AuthorizationError, match="symlink"):
        write_private_file(symlink, "replacement\n")


def test_all_operational_backend_templates_use_native_lockfile() -> None:
    templates = sorted((REPO_ROOT / "roots").glob("*/backend.example.hcl"))
    operational = [path for path in templates if "account-ready-gate" not in str(path)]
    assert operational
    for path in operational:
        text = path.read_text()
        assert "use_lockfile" in text, path
        assert "dynamodb_table" not in text, path


def test_each_terraform_layer_declares_s3_backend() -> None:
    catalog = _catalog()
    for stage in catalog["layers"]:
        if stage["kind"] != "terraform":
            continue
        root = REPO_ROOT / stage["root"]
        terraform_source = "\n".join(
            path.read_text() for path in sorted(root.glob("*.tf"))
        )
        assert 'backend "s3" {}' in terraform_source, stage["layer"]


def test_registry_policy_cannot_scan_or_unconditionally_delete() -> None:
    policy = json.loads((REPO_ROOT / "policies/iam/orchestrator-role.json").read_text())
    allowed_actions = {
        action
        for statement in policy["Statement"]
        if statement["Effect"] == "Allow"
        for action in (
            statement["Action"]
            if isinstance(statement["Action"], list)
            else [statement["Action"]]
        )
    }
    assert "dynamodb:Scan" not in allowed_actions
    assert "dynamodb:DeleteItem" not in allowed_actions
    registry_writes = [
        statement
        for statement in policy["Statement"]
        if statement.get("Sid") == "WriteDeploymentRegistry"
    ]
    assert len(registry_writes) == 1
    assert "dynamodb:LeadingKeys" in json.dumps(registry_writes[0]["Condition"])


def test_state_recovery_cannot_delete_state_or_arbitrary_prefixes() -> None:
    policy = json.loads((REPO_ROOT / "policies/iam/state-recovery-role.json").read_text())
    delete_statements = []
    for statement in policy["Statement"]:
        if statement["Effect"] != "Allow":
            continue
        actions = statement["Action"]
        actions = actions if isinstance(actions, list) else [actions]
        resources = statement["Resource"]
        resources = resources if isinstance(resources, list) else [resources]
        if "s3:DeleteObject" in actions:
            delete_statements.append(statement)
            assert all(resource.endswith("terraform.tfstate.tflock") for resource in resources)
    assert len(delete_statements) == 1
    assert delete_statements[0]["Condition"]["StringEquals"][
        "aws:PrincipalTag/recovery_approved"
    ] == "true"


def test_state_recovery_trust_requires_independent_review_and_exact_tags() -> None:
    trust = json.loads((REPO_ROOT / "policies/trust/state-recovery-trust.json").read_text())
    by_action = {statement["Action"]: statement for statement in trust["Statement"]}
    assert set(by_action) == {
        "sts:AssumeRole",
        "sts:TagSession",
        "sts:SetSourceIdentity",
    }
    assume = by_action["sts:AssumeRole"]["Condition"]
    assert assume["StringEquals"]["aws:PrincipalTag/mfa_authenticated"] == "true"
    assert assume["StringEquals"]["aws:PrincipalTag/break_glass_approved"] == "true"
    assert assume["StringEquals"]["aws:RequestTag/recovery_approved"] == "true"
    assert assume["StringLike"]["aws:RequestTag/incident_id"] == "inc_*"
    tags = by_action["sts:TagSession"]["Condition"]
    assert set(tags["ForAllValues:StringEquals"]["aws:TagKeys"]) == {
        "customer_id",
        "deployment_id",
        "account_id",
        "region",
        "environment",
        "operation",
        "incident_id",
        "operator_id",
        "recovery_approved",
    }
    assert all(value == "false" for value in tags["Null"].values())


def test_backend_authorization_precedes_aws_identity_lookup() -> None:
    wrapper = (REPO_ROOT / "scripts/deployment/terraform-layer.sh").read_text()

    assert wrapper.index("tooling/authorize_deployment_backend.py") < wrapper.index(
        "aws sts get-caller-identity"
    )


def test_registry_create_is_create_only() -> None:
    target = _target(_account_ready())
    target["registry_version"] = 1
    target["record_digest"] = _digest(target, "record_digest")

    write = prepare_registry_create(target)

    assert write["condition_expression"] == "attribute_not_exists(deployment_id)"


def test_registry_update_requires_exact_version_digest_and_binding() -> None:
    current = _target(_account_ready())
    proposed = copy.deepcopy(current)
    proposed["status"] = "ACTIVE"
    proposed["registry_version"] += 1
    proposed["record_digest"] = _digest(proposed, "record_digest")

    write = prepare_registry_update(
        current=current,
        proposed=proposed,
        expected_version=current["registry_version"],
        expected_digest=current["record_digest"],
    )

    assert "registry_version = :expected_version" in write["condition_expression"]
    assert "record_digest = :expected_digest" in write["condition_expression"]
    assert "customer_id = :customer_id" in write["condition_expression"]


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("customer_id", "cust_01J5A1B2C3D4E5F6G7H8J9K0M2"),
        ("deployment_id", OTHER_DEPLOYMENT_ID),
        ("account_id", "555666777888"),
        ("region", "us-west-2"),
    ],
)
def test_registry_update_cannot_reassign_ownership(
    field: str,
    value: str,
) -> None:
    current = _target(_account_ready())
    proposed = copy.deepcopy(current)
    proposed[field] = value
    proposed["status"] = "ACTIVE"
    proposed["registry_version"] += 1
    proposed["record_digest"] = _digest(proposed, "record_digest")

    with pytest.raises(AuthorizationError, match="immutable"):
        prepare_registry_update(
            current=current,
            proposed=proposed,
            expected_version=current["registry_version"],
            expected_digest=current["record_digest"],
        )


def test_registry_update_rejects_stale_compare_and_swap() -> None:
    current = _target(_account_ready())
    proposed = copy.deepcopy(current)
    proposed["status"] = "ACTIVE"
    proposed["registry_version"] += 1
    proposed["record_digest"] = _digest(proposed, "record_digest")

    with pytest.raises(AuthorizationError, match="version conflict"):
        prepare_registry_update(
            current=current,
            proposed=proposed,
            expected_version=current["registry_version"] - 1,
            expected_digest=current["record_digest"],
        )


def test_registry_update_rejects_unsafe_lifecycle_jump() -> None:
    current = _target(_account_ready())
    proposed = copy.deepcopy(current)
    proposed["status"] = "ARCHIVED"
    proposed["registry_version"] += 1
    proposed["record_digest"] = _digest(proposed, "record_digest")

    with pytest.raises(AuthorizationError, match="transition is forbidden"):
        prepare_registry_update(
            current=current,
            proposed=proposed,
            expected_version=current["registry_version"],
            expected_digest=current["record_digest"],
        )
