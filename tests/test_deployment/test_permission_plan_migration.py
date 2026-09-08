"""Hermetic tests: every coordinate below is synthetic; no AWS operation."""

from __future__ import annotations

import ast
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import socket
import stat
import subprocess
import sys

import pytest

from tooling import platform_authority_permission_plan_migration as subject
from tooling import platform_authority_plan_permission_repair as repair


ROOT = Path(__file__).resolve().parents[2]
CLI = ROOT / "scripts/deployment/platform-authority-permission-plan-migration.py"


def _request():
    # Not a snapshot, owner decision, active window, or live configuration.
    instance = "ssoins-0123456789ABCDEF"
    policy = {"Version": "2012-10-17", "Statement": [{
        "Sid": "SyntheticOriginal", "Effect": "Allow",
        "Action": ["cloudformation:CreateChangeSet", "cloudformation:DescribeStacks"],
        "Resource": ["arn:aws:cloudformation:us-east-1:042360977644:stack/synthetic/*"],
    }]}
    return {
        "schema_version": 1,
        "management_account_id": "839393571433",
        "authority_account_id": "042360977644",
        "region": "us-east-1",
        "identity_center_instance_arn": f"arn:aws:sso:::instance/{instance}",
        "identity_store_id": "d-0123456789",
        "reader_permission_set_arn": f"arn:aws:sso:::permissionSet/{instance}/ps-fedcba9876543210",
        "plan_permission_set_arn": f"arn:aws:sso:::permissionSet/{instance}/ps-0123456789abcdef",
        "target_user_id": "01234567-89ab-cdef-0123-456789abcdef",
        "change_set_name": "scanalyze-platform-authority-bootstrap-20300101000000",
        "not_before": "2030-01-01T00:00:00Z",
        "not_after": "2030-01-01T00:15:00Z",
        "target_plan_tags": {"purpose": "synthetic-local-review"},
        "baseline": {
            "reader_inline_policy": None,
            "reader_provisioned_accounts": ["839393571433", "042360977644", "111122223333"],
            "reader_assignments_coverage": "NOT_COMPLETE",
            "reader_boundary_observation": "NOT_OBSERVED",
            "plan_inline_policy": policy,
            "plan_role_inline_policy": None,
            "plan_tags": {},
            "plan_assignment": {"account_id": "042360977644", "principal_type": "GROUP",
                                "principal_id": "abcdef01-2345-6789-abcd-ef0123456789"},
            "plan_provisioned_accounts": ["042360977644"],
            "plan_boundary_observation": "NOT_OBSERVED",
        },
    }


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def forbidden(*_args, **_kwargs):
        pytest.fail("Network is not part of offline draft preparation")
    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)


def test_draft_preserves_input_and_matches_original_repair_contract():
    request = _request()
    before = deepcopy(request)
    draft = subject.build_review_draft(request)
    target = repair.render_target_policy(request["change_set_name"], repo_root=ROOT)
    assert draft["plan_proposed_predecessor_policy"] == repair.render_predecessor_policy(target)
    assert repair.policy_delta_digest(draft["plan_proposed_predecessor_policy"], target)
    assert request == before
    assert draft["supplied_input"] == request
    assert draft["status"] == "DRAFT_REVIEW_ONLY"
    assert draft["source_status"] == "LOCAL_WORKING_COPY_NOT_ATTESTED"
    assert draft["baseline_verified"] is False
    assert draft["admission_snapshot"] is False
    assert draft["execution_authorized"] is False
    assert draft["deployment_authorized"] is False
    assert draft["production_status"] == "NO-GO"
    assert draft["aws_calls"] == draft["aws_mutations"] == 0
    assert draft["plan_policy_delta"]["effective_authorization_evaluated"] is False
    assert draft["plan_policy_delta"]["removed_statement_digests"]
    assert draft["plan_policy_delta"]["added_statement_digests"]


def test_repeatable_content_digests_bind_input_and_source():
    request = _request()
    first = subject.build_review_draft(request)
    assert subject.build_review_draft(request) == first
    assert first["source_material_digests"][subject.PLAN_PATH] == (
        "sha256:" + hashlib.sha256((ROOT / subject.PLAN_PATH).read_bytes()).hexdigest())
    request["target_plan_tags"]["purpose"] = "another-reviewed-selection"
    second = subject.build_review_draft(request)
    assert first["input_digest"] != second["input_digest"]
    assert first["draft_digest"] != second["draft_digest"]


def test_additive_reader_preserves_unrelated_allow_deny_and_document_id():
    request = _request()
    original = {"Version": "2012-10-17", "Id": "SyntheticBaseline", "Statement": [
        {"Sid": "UnrelatedAllow", "Effect": "Allow", "Action": "lambda:ListFunctions", "Resource": "*"},
        {"Sid": "ExistingDeny", "Effect": "Deny", "Action": "sso:ListInstances", "Resource": "*"},
    ]}
    request["baseline"]["reader_inline_policy"] = original
    draft = subject.build_review_draft(request)
    merged = draft["reader_proposed_inline_policy"]
    assert merged["Id"] == original["Id"]
    assert merged["Statement"][:2] == original["Statement"]
    assert merged["Statement"][2:] == draft["reader_supplement_policy"]["Statement"]
    assert "EXISTING_READER_DENIES_PRESERVED_REQUIRE_EVALUATION" in draft["required_reviews"]
    for stmt in draft["reader_supplement_policy"]["Statement"]:
        assert stmt["Effect"] == "Allow"
        assert stmt["Condition"]["StringEquals"] == {
            "aws:PrincipalAccount": "839393571433", "aws:RequestedRegion": "us-east-1"}
        assert stmt["Condition"]["DateGreaterThanEquals"] == {"aws:CurrentTime": request["not_before"]}
        assert stmt["Condition"]["DateLessThan"] == {"aws:CurrentTime": request["not_after"]}
    assert "${" not in json.dumps(draft["reader_supplement_policy"])


def test_sid_collision_is_not_overwrite_or_automatic_retry():
    request = _request()
    prior = subject.build_review_draft(request)["reader_supplement_policy"]
    request["baseline"]["reader_inline_policy"] = prior
    with pytest.raises(subject.MigrationDraftError, match="READER_STATEMENT_SID_COLLISION"):
        subject.build_review_draft(request)


def test_partial_baseline_is_never_promoted_to_execution():
    request = _request()
    draft = subject.build_review_draft(request)
    assert set(draft["required_reviews"]) >= {
        "READER_ASSIGNMENT_IMPACT_UNKNOWN", "READER_BOUNDARY_REQUIRES_REVIEW",
        "PLAN_BOUNDARY_REQUIRES_REVIEW", "PLAN_SSO_IAM_EQUALITY_NOT_ESTABLISHED",
        "OLD_GROUP_SESSIONS_CLOSED_REQUIRED", "TAG_BASED_ADMIN_AUTHORITY_DELTA_REQUIRES_REVIEW"}
    request["baseline"]["reader_assignments_coverage"] = "COMPLETE"
    request["baseline"]["reader_boundary_observation"] = "ABSENT"
    request["baseline"]["plan_boundary_observation"] = "ABSENT"
    request["baseline"]["plan_role_inline_policy"] = deepcopy(request["baseline"]["plan_inline_policy"])
    supplied_complete = subject.build_review_draft(request)
    assert supplied_complete["execution_authorized"] is False
    assert supplied_complete["baseline_verified"] is False
    assert "FRESH_ATTESTED_BASELINE_REQUIRED" in supplied_complete["required_reviews"]
    assert "EXPLICIT_MUTATION_APPROVAL_REQUIRED" in supplied_complete["required_reviews"]


def test_session_safety_and_no_zero_assignment_stage_order():
    draft = subject.build_review_draft(_request())
    outline = draft["migration_outline"]
    stages = [row["stage"] for row in outline]
    assert stages.index("ADD_TARGET_USER") < stages.index("REMOVE_OLD_GROUP_ASSIGNMENT")
    assert stages.index("REMOVE_OLD_GROUP_ASSIGNMENT") < stages.index("CLOSE_OLD_GROUP_SESSIONS")
    assert stages.index("CLOSE_OLD_GROUP_SESSIONS") < stages.index("MIGRATE_PLAN")
    assert "creation also provisions policy" in outline[2]["gate"]
    assert "SSO/IAM equality" in outline[2]["gate"]
    assert "Never pass through zero assignments" in outline[3]["gate"]
    assert "do not revoke existing sessions" in outline[4]["gate"]
    assert draft["rollback"]["automatic"] is False


@pytest.mark.parametrize("field,value", [
    ("schema_version", True), ("schema_version", 2),
    ("management_account_id", "111122223333"), ("authority_account_id", "839393571433"),
    ("region", "us-west-2"), ("identity_center_instance_arn", "*"),
    ("identity_store_id", "d-*/injection"), ("target_user_id", "*"),
    ("target_user_id", "abcdef01-2345-6789-abcd-ef0123456789"),
    ("change_set_name", "invented"), ("change_set_name", "scanalyze-platform-authority-bootstrap-*"),
    ("not_before", "2030-01-01T00:00:00"), ("not_after", "2030-01-01T01:00:01Z"),
    ("not_after", "2030-01-01T00:00:00Z"), ("not_before", "2030-99-01T00:00:00Z"),
    ("target_plan_tags", {}), ("target_plan_tags", {"aws:managed": "no"}),
    ("target_plan_tags", {"purpose": ""}), ("target_plan_tags", {"purpose": "unsafe\nvalue"}),
])
def test_invalid_explicit_selections_fail_without_defaults(field, value):
    request = _request()
    request[field] = value
    with pytest.raises(subject.MigrationDraftError):
        subject.build_review_draft(request)


@pytest.mark.parametrize("field", sorted(subject._FIELDS))
def test_missing_required_input_fails(field):
    request = _request()
    request.pop(field)
    with pytest.raises(subject.MigrationDraftError, match="INPUT_FIELDS_INVALID"):
        subject.build_review_draft(request)


def test_permission_set_cannot_cross_instance_or_alias_reader():
    request = _request()
    request["plan_permission_set_arn"] = request["reader_permission_set_arn"]
    with pytest.raises(subject.MigrationDraftError, match="PERMISSION_SET_BINDING_INVALID"):
        subject.build_review_draft(request)
    request = _request()
    request["plan_permission_set_arn"] = request["plan_permission_set_arn"].replace("ssoins-012", "ssoins-987")
    with pytest.raises(subject.MigrationDraftError, match="PERMISSION_SET_BINDING_INVALID"):
        subject.build_review_draft(request)


@pytest.mark.parametrize("field,value", [
    ("plan_provisioned_accounts", ["042360977644", "111122223333"]),
    ("reader_provisioned_accounts", []), ("reader_provisioned_accounts", ["042360977644"]),
    ("reader_provisioned_accounts", ["839393571433", "839393571433"]),
    ("reader_assignments_coverage", "ASSUMED"), ("plan_boundary_observation", False),
    ("plan_inline_policy", None), ("plan_inline_policy", {"Version": "2012-10-17", "Statement": []}),
    ("plan_assignment", {"account_id": "042360977644", "principal_type": "USER", "principal_id": "x"}),
])
def test_baseline_scope_and_unknowns_are_explicit(field, value):
    request = _request()
    request["baseline"][field] = value
    with pytest.raises(subject.MigrationDraftError):
        subject.build_review_draft(request)


@pytest.mark.parametrize("field,value", [("Effect", []), ("Condition", "bad"), ("Action", []),
                                        ("Sid", "bad-sid"), ("Principal", "*")])
def test_malformed_policy_never_leaks_provider_style_error(field, value):
    request = _request()
    request["baseline"]["plan_inline_policy"]["Statement"][0][field] = value
    with pytest.raises(subject.MigrationDraftError, match="BASELINE_POLICY_INVALID"):
        subject.build_review_draft(request)


def test_public_summary_omits_private_coordinates_and_documents():
    request = _request()
    summary = json.dumps(subject.public_summary(subject.build_review_draft(request)))
    for field in ("identity_center_instance_arn", "target_user_id", "reader_permission_set_arn",
                  "plan_permission_set_arn", "change_set_name"):
        assert request[field] not in summary
    assert "Statement" not in summary
    assert "principal_id" not in summary


def _private_input(tmp_path):
    # pytest's directory is not an artifact source; create an owner-only child.
    private = tmp_path / "private"
    private.mkdir(mode=0o700)
    path = private / "input.json"
    path.write_text(json.dumps(_request()))
    path.chmod(0o600)
    return path, private / "draft.json"


def _cli(source, output, *extra):
    return subprocess.run([sys.executable, "-I", "-B", str(CLI), "--input", str(source),
                           "--output", str(output), *extra], capture_output=True, text=True,
                          timeout=20, cwd=source.parent)


def test_real_cli_is_private_create_only_and_sanitized(tmp_path):
    source, output = _private_input(tmp_path)
    result = _cli(source, output)
    assert result.returncode == 0, result.stderr
    summary = json.loads(result.stdout)
    assert summary["status"] == "DRAFT_REVIEW_ONLY"
    assert json.loads(output.read_text())["draft_digest"] == summary["draft_digest"]
    assert stat.S_IMODE(output.stat().st_mode) == 0o600
    prior = output.read_bytes()
    repeat = _cli(source, output)
    assert repeat.returncode == 2
    assert json.loads(repeat.stderr) == {"error": "PRIVATE_OUTPUT_CREATE_FAILED"}
    assert output.read_bytes() == prior
    assert str(source) not in result.stdout + result.stderr + repeat.stderr


def test_cli_has_no_live_apply_or_profile_switch(tmp_path):
    source, output = _private_input(tmp_path)
    for argument in ("--apply", "--live", "--profile", "--approve"):
        result = _cli(source, output, argument)
        assert result.returncode == 2
        assert json.loads(result.stderr) == {"error": "CLI_ARGUMENTS_INVALID"}
        assert not output.exists()


@pytest.mark.parametrize("payload", ['{"duplicate":1,"duplicate":2}', '{"x":NaN}', '{"x":Infinity}', 'not-json'])
def test_private_json_rejects_duplicates_nonfinite_and_invalid(tmp_path, payload):
    source, output = _private_input(tmp_path)
    source.write_text(payload)
    result = _cli(source, output)
    assert result.returncode == 2
    assert not output.exists()
    assert payload not in result.stderr


def test_private_input_permissions_links_and_destination_guards(tmp_path):
    source, output = _private_input(tmp_path)
    source.chmod(0o644)
    with pytest.raises(subject.MigrationDraftError, match="PRIVATE_INPUT_INVALID"):
        subject.read_private_input(source)
    source.chmod(0o600)
    linked = source.parent / "linked.json"
    linked.symlink_to(source)
    with pytest.raises(subject.MigrationDraftError, match="PRIVATE_PATH_INVALID"):
        subject.read_private_input(linked)
    with pytest.raises(subject.MigrationDraftError, match="PRIVATE_PATH_INVALID"):
        subject.write_private_draft(ROOT / "must-not-exist.json", {})
    synced = tmp_path / "OneDrive-Synthetic"
    synced.mkdir(mode=0o700)
    with pytest.raises(subject.MigrationDraftError, match="PRIVATE_PATH_INVALID"):
        subject.write_private_draft(synced / "must-not-exist.json", {})
    os.link(source, source.parent / "hard.json")
    with pytest.raises(subject.MigrationDraftError, match="PRIVATE_INPUT_INVALID"):
        subject.read_private_input(source)
    assert not output.exists()


def test_no_provider_process_or_network_import_in_new_runtime():
    for path in (ROOT / "tooling/platform_authority_permission_plan_migration.py", CLI):
        tree = ast.parse(path.read_text())
        imports = {node.names[0].name.split(".")[0] for node in ast.walk(tree) if isinstance(node, ast.Import)}
        imports |= {(node.module or "").split(".")[0] for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)}
        assert not imports & {"boto3", "botocore", "socket", "subprocess", "urllib", "requests", "httpx"}


@pytest.mark.parametrize("folder", ["cloudstorage", "CLOUDSTORAGE", "oNeDrIvE-Test",
                                    "dropbox", "GOOGLEDRIVE-Test", "mobile documents"])
def test_synced_paths_rejected_independent_of_case(tmp_path, folder):
    parent = tmp_path / folder
    parent.mkdir(mode=0o700)
    with pytest.raises(subject.MigrationDraftError, match="PRIVATE_PATH_INVALID"):
        subject.write_private_draft(parent / "draft.json", {})
    assert not (parent / "draft.json").exists()


@pytest.mark.parametrize("method", ["is_symlink", "exists"])
def test_directory_inspection_oserror_is_sanitized(tmp_path, monkeypatch, method):
    def denied(_self):
        raise PermissionError("synthetic-private-path-must-not-escape")
    monkeypatch.setattr(Path, method, denied)
    with pytest.raises(subject.MigrationDraftError, match="^PRIVATE_PATH_INVALID$") as result:
        subject.read_private_input(tmp_path / "private.json")
    assert "synthetic-private-path" not in str(result.value)


def test_statement_delta_preserves_duplicate_multiplicity():
    request = _request()
    statement = request["baseline"]["plan_inline_policy"]["Statement"][0]
    statement.pop("Sid")
    request["baseline"]["plan_inline_policy"]["Statement"].append(deepcopy(statement))
    result = subject.build_review_draft(request)["plan_policy_delta"]
    assert len(result["removed_statement_digests"]) == 2
    assert result["removed_statement_digests"][0] == result["removed_statement_digests"][1]


def test_draft_is_not_accepted_as_original_snapshot():
    from datetime import datetime, timezone
    from tooling import platform_authority_plan_permission_repair_broker_config as broker
    draft = subject.build_review_draft(_request())
    with pytest.raises(Exception) as rejected:
        broker.validate_plan_snapshot(draft, source_commit="a" * 40,
                                      now=datetime.now(timezone.utc))
    assert not isinstance(rejected.value, (TypeError, AttributeError))
