"""Focused, offline tests for the fail-closed GUG-365 plan compiler."""

from __future__ import annotations

import copy
import base64
from datetime import datetime, timedelta, timezone
from hashlib import sha256
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import sys
from typing import Any, Mapping

import pytest


REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tooling import (  # noqa: E402
    platform_authority_retirement_entrypoint_materializer as gug363,
)
from tooling import (  # noqa: E402
    platform_authority_retirement_entrypoint_service_role_materializer as materializer,
)
from tooling import (  # noqa: E402
    platform_authority_retirement_ledger_factory_package as factory_package,
)


def _load_gug363_helpers() -> Any:
    path = REPO_ROOT / "tests/test_deployment/test_gug363_retirement_entrypoint_materializer.py"
    spec = importlib.util.spec_from_file_location("_gug363_helpers", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _git(root: Path, *args: str) -> str:
    return subprocess.run(
        ["git", *args], cwd=root, check=True, capture_output=True, text=True, timeout=30
    ).stdout.strip()


def _repository_files() -> tuple[Path, ...]:
    return (
        gug363.TEMPLATE_PATH,
        gug363.FUNCTION_CONFIGURATOR_POLICY_PATH,
        *materializer.BOUNDARY_TEMPLATE_PATHS.values(),
        materializer.POLICY_FACTORY_POLICY_PATH,
        materializer.FOUNDATION_FACTORY_POLICY_PATH,
        materializer.FUNCTION_FACTORY_POLICY_PATH,
        materializer.LEDGER_FACTORY_FUNCTION_FACTORY_POLICY_PATH,
        materializer.ACTIVATOR_POLICY_PATH,
        materializer.REVOCATOR_POLICY_PATH,
        materializer.LEDGER_FACTORY_ACTIVATOR_POLICY_PATH,
        materializer.LEDGER_FACTORY_INVOKER_POLICY_PATH,
        materializer.LEDGER_FACTORY_REVOKER_POLICY_PATH,
        *factory_package.SOURCE_PATHS,
        *factory_package.PROVENANCE_PATHS,
    )


@pytest.fixture(scope="module")
def bundle(tmp_path_factory: pytest.TempPathFactory) -> Mapping[str, Any]:
    """Build GUG-363 and GUG-365 from one clean, immutable Git snapshot."""

    helpers = _load_gug363_helpers()
    source = tmp_path_factory.mktemp("gug365-source")
    for relative in _repository_files():
        target = source / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(REPO_ROOT / relative, target)
    _git(source, "init", "-q")
    _git(source, "config", "user.email", "synthetic@example.invalid")
    _git(source, "config", "user.name", "Synthetic Test")
    _git(source, "add", "--", *[path.as_posix() for path in _repository_files()])
    _git(source, "commit", "-q", "-m", "synthetic immutable GUG-365 source")
    commit = _git(source, "rev-parse", "HEAD")
    tree = _git(source, "rev-parse", "HEAD^{tree}")
    template_digest = "sha256:" + sha256(
        (source / gug363.TEMPLATE_PATH).read_bytes()
    ).hexdigest()

    package_source = source / "package-source"
    package_source.mkdir()
    committed_sources = {
        path: b"" if path.as_posix() == "tooling/__init__.py" else b"# synthetic\n"
        for path in helpers.SOURCE_PATHS
    }
    built = helpers.build_retirement_package(
        source_root=package_source,
        source_commit=commit,
        broker_runtime_version_arn=helpers.RUNTIME_ARN,
        broker_version_binding_sha256=helpers.VERSION_BINDING,
        committed_sources=committed_sources,
    )
    signed_archive = built.archive + b"scanalyze-gug365-signer-envelope-v1"
    intent = helpers._intent(
        commit=commit,
        tree=tree,
        template_digest=template_digest,
        package_manifest=built.manifest,
        signed_archive=signed_archive,
    )

    provisional = {
        "authorization_mode": gug363.AUTHORIZATION_MODE,
        "parameter_projection": [
            {"ParameterKey": key, "ParameterValue": intent["parameters"][key]}
            for key in gug363.PARAMETER_KEYS
        ],
            "artifact_signing_contract": intent["artifact_signing_contract"],
            "artifact_signing_contract_digest": intent[
                "artifact_signing_contract_digest"
            ],
        "source": intent["source"],
        "plan_digest": "sha256:" + "0" * 64,
    }
    boundaries = materializer._render_boundaries(  # noqa: SLF001
        gug363_plan=provisional, repo_root=source
    )
    digests = {item["key"]: item["document_digest"] for item in boundaries}
    parameters = intent["parameters"]
    parameters.update(
        {
            "ExpectedBrokerPolicySha256": digests["broker"],
            "ClassifierInvokerPolicySha256": digests["classifier_invoker"],
            "ApproverInvokerPolicySha256": digests["approver_invoker"],
            "ClassifierProofPolicySha256": digests["proof"],
            "ApproverProofPolicySha256": digests["proof"],
        }
    )
    parameters[gug363.PRIVATE_PARAMETER_PROJECTION_KEY] = (
        gug363.private_parameter_projection_digest(parameters)
    )
    intent["gug363_pre_function_binding_sha256"] = (
        gug363.gug363_pre_function_binding_sha256(
            source=intent["source"],
            artifact_signing_contract_digest_value=intent[
                "artifact_signing_contract_digest"
            ],
            parameters=parameters,
        )
    )
    intent["intent_digest"] = gug363.canonical_digest(
        {key: value for key, value in intent.items() if key != "intent_digest"}
    )
    helpers.ARTIFACT_PAYLOADS.clear()
    helpers.ARTIFACT_PAYLOADS.update(
        {
            intent["artifact_signing_contract"]["unsigned_source"]["version_id"]: built.archive,
            intent["artifact_signing_contract"]["signed_destination"]["version_id"]: signed_archive,
        }
    )
    plan = gug363.build_materialization_plan(
        intent=intent,
        package_manifest=built.manifest,
        package_archive=built.archive,
        repo_root=source,
    )
    factory_built = factory_package.build_ledger_factory_package(
        source_root=source,
        source_commit=commit,
        runtime_version_arn=helpers.RUNTIME_ARN,
        committed_sources=factory_package.verify_clean_source_commit(
            source_root=source, source_commit=commit
        ),
    )
    factory_signed_archive = (
        factory_built.archive + b"scanalyze-gug365-dedicated-signer-envelope-v1"
    )
    factory_signed_digest = sha256(factory_signed_archive).digest()
    factory_job_id = "abcdef0123456789abcdef0123456789"
    broker_signer = plan["artifact_signing_contract"]["signer"]
    broker_csc = plan["artifact_signing_contract"]["code_signing_config"]
    kms_arn = plan["artifact_signing_contract"]["signed_destination"][
        "sse_kms_key_arn"
    ]
    bucket = plan["artifact_signing_contract"]["signed_destination"]["bucket"]
    factory_contract = {
        "contract_version": 1,
        "package_manifest": factory_built.manifest,
        "runtime_version_arn": helpers.RUNTIME_ARN,
        "unsigned_source": {
            "artifact_type": factory_built.manifest["artifact_type"],
            "work_package": factory_built.manifest["work_package"],
            "manifest_digest": factory_built.manifest["manifest_digest"],
            "archive_sha256": factory_built.manifest["archive_sha256"],
            "lambda_code_sha256": factory_built.manifest["lambda_code_sha256"],
            "archive_size_bytes": factory_built.manifest["archive_size_bytes"],
            "bucket": bucket,
            "key": (
                "scanalyze/platform-authority/gug-365/ledger-factory/unsigned/"
                f"{commit}/{factory_package.ARCHIVE_NAME}"
            ),
            "version_id": "synthetic-factory-unsigned-version-0001",
            "sse_algorithm": "aws:kms",
            "sse_kms_key_arn": kms_arn,
        },
        "signer": {**broker_signer, "job_id": factory_job_id},
        "signed_destination": {
            "bucket": bucket,
            "key": (
                "scanalyze/platform-authority/gug-365/ledger-factory/signed/"
                f"{factory_job_id}.zip"
            ),
            "version_id": "synthetic-factory-signed-version-0001",
            "archive_sha256": factory_signed_digest.hex(),
            "lambda_code_sha256": base64.b64encode(factory_signed_digest).decode(
                "ascii"
            ),
            "archive_size_bytes": len(factory_signed_archive),
            "sse_algorithm": "aws:kms",
            "sse_kms_key_arn": kms_arn,
        },
        "code_signing_config": broker_csc,
    }
    return {
        "repo": source,
        "plan": plan,
        "factory_contract": factory_contract,
        "factory_contract_digest": (
            materializer.ledger_factory_artifact_signing_contract_digest(
                factory_contract
            )
        ),
    }


@pytest.fixture(scope="module")
def compiled(bundle: Mapping[str, Any]) -> Mapping[str, Any]:
    plan = bundle["plan"]
    return materializer.compile_service_role_materialization_plan(
        gug363_plan=plan,
        expected_gug363_plan_digest=plan["plan_digest"],
        ledger_factory_artifact_signing_contract=bundle["factory_contract"],
        expected_ledger_factory_artifact_signing_contract_digest=bundle[
            "factory_contract_digest"
        ],
        repo_root=bundle["repo"],
    )


def _actions(document: Mapping[str, Any], effect: str = "Allow") -> set[str]:
    result: set[str] = set()
    for statement in document["Statement"]:
        if statement["Effect"] != effect:
            continue
        action = statement["Action"]
        result.update([action] if isinstance(action, str) else action)
    return result


def _reseal(plan: dict[str, Any]) -> None:
    plan["plan_digest"] = materializer.canonical_digest(
        {key: value for key, value in plan.items() if key != "plan_digest"}
    )


def _factory_kwargs(bundle: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "ledger_factory_artifact_signing_contract": bundle[
            "factory_contract"
        ],
        "expected_ledger_factory_artifact_signing_contract_digest": bundle[
            "factory_contract_digest"
        ],
    }


AUTHORITY_EVALUATION = datetime(
    2035, 1, 2, 3, 4, 5, tzinfo=timezone.utc
)


def _authority_evidence(
    compiled: Mapping[str, Any],
    phase: str,
    *,
    caller_digest: str = "sha256:" + "1" * 64,
    evaluation_at: datetime = AUTHORITY_EVALUATION,
) -> dict[str, Any]:
    phase_item = next(
        item for item in compiled["authorization_phases"] if item["phase"] == phase
    )
    policy_digest = phase_item["executor_policy"]["document_digest"]
    issued = evaluation_at - timedelta(seconds=60)
    expires = evaluation_at + timedelta(seconds=840)
    collected = evaluation_at - timedelta(seconds=30)
    evidence: dict[str, Any] = {
        "record_type": (
            "scanalyze.platform_authority.gug365_executor_authority_evidence.v1"
        ),
        "phase": phase,
        "caller_account_id": materializer.AUTHORITY_ACCOUNT_ID,
        "region": materializer.REGION,
        "caller_arn_digest": caller_digest,
        "session_identifier_digest": materializer.canonical_digest(
            {
                "phase": phase,
                "caller_arn_digest": caller_digest,
                "session_issued_at": issued.isoformat().replace("+00:00", "Z"),
            }
        ),
        "session_issued_at": issued.isoformat().replace("+00:00", "Z"),
        "session_expires_at": expires.isoformat().replace("+00:00", "Z"),
        "evidence_collected_at": collected.isoformat().replace("+00:00", "Z"),
        "session_lifetime_seconds": 900,
        "session_remaining_seconds": 840,
        "session_chain_depth": 0,
        "evidence_collected_after_sts": True,
        "effective_policy_inventory_complete": True,
        "sole_identity_policy_document_digest": policy_digest,
        "additional_inline_policy_count": 0,
        "additional_attached_policy_count": 0,
        "group_policy_count": 0,
        "maximum_authority_source": "DEDICATED_ROLE_PERMISSIONS_BOUNDARY",
        "maximum_authority_document_digest": policy_digest,
        "raw_caller_arn_persisted": False,
        "evidence_digest": "",
    }
    evidence["evidence_digest"] = materializer.canonical_digest(
        {key: value for key, value in evidence.items() if key != "evidence_digest"}
    )
    return evidence


def test_compiles_deterministically_offline_with_exact_36_mutations(
    bundle: Mapping[str, Any], compiled: Mapping[str, Any]
) -> None:
    second = materializer.compile_service_role_materialization_plan(
        gug363_plan=copy.deepcopy(bundle["plan"]),
        expected_gug363_plan_digest=bundle["plan"]["plan_digest"],
        **_factory_kwargs(bundle),
        repo_root=bundle["repo"],
    )
    assert second == compiled
    assert compiled["deployment_authorized"] is False
    assert compiled["aws_calls_performed"] is False
    writes = compiled["planned_iam_writes"]
    assert len(writes) == 36
    assert [item["sequence"] for item in writes] == list(range(1, 37))
    assert [item["allowed_action"] for item in writes].count("iam:CreatePolicy") == 6
    assert [item["allowed_action"] for item in writes].count("iam:CreateRole") == 7
    assert [item["allowed_action"] for item in writes].count("iam:AttachRolePolicy") == 7
    assert [item["allowed_action"] for item in writes].count("iam:PutRolePermissionsBoundary") == 6
    assert [item["allowed_action"] for item in writes].count("iam:DetachRolePolicy") == 1
    assert [item["allowed_action"] for item in writes].count("lambda:CreateFunction") == 2
    assert [item["allowed_action"] for item in writes].count("lambda:PutRuntimeManagementConfig") == 2
    assert [item["allowed_action"] for item in writes].count("lambda:PutFunctionConcurrency") == 2
    assert [item["allowed_action"] for item in writes].count("lambda:InvokeFunction") == 1
    assert [item["allowed_action"] for item in writes].count("logs:CreateLogGroup") == 1
    assert [item["allowed_action"] for item in writes][-2:] == [
        "iam:AttachRolePolicy",
        "iam:PutRolePermissionsBoundary",
    ]
    assert writes[-1]["target_arn"] == materializer.SERVICE_ROLE_ARN
    assert all(item["attempt_limit"] == 1 and not item["retry_permitted"] for item in writes)
    assert not ({"iam:PutRolePolicy", "dynamodb:PutResourcePolicy", "dynamodb:CreateTable"} & {
        item["allowed_action"] for item in writes
    })


def test_phase_authorities_are_identity_gated_disjoint_and_checkpointed(
    compiled: Mapping[str, Any]
) -> None:
    phases = compiled["authorization_phases"]
    assert [phase["phase"] for phase in phases] == [
        "POLICY_FACTORY",
        "FOUNDATION_FACTORY",
        "FUNCTION_FACTORY",
        "LEDGER_FACTORY_FUNCTION_FACTORY",
        "LEDGER_FACTORY_ACTIVATOR",
        "LEDGER_FACTORY_INVOKER",
        "LEDGER_FACTORY_REVOKER",
        "ACTIVATOR",
    ]
    assert [len(phase["mutations"]) for phase in phases] == [6, 7, 3, 5, 2, 1, 2, 10]
    for phase in phases:
        assert phase["operations"][0]["allowed_action"] == "sts:GetCallerIdentity"
        assert phase["operations"][0]["expected_account_id"] == materializer.AUTHORITY_ACCOUNT_ID
        assert phase["operations"][0]["mismatch_or_timeout_mode"] == "STOP_NO_MUTATION"
        assert phase["same_session_reuse_permitted"] is False
        assert phase["authority_overlap_permitted"] is False
        assert phase["checkpoint_required_before_next_phase"] is True
        requirement = phase["executor_effective_authority_requirement"]
        assert requirement["sole_identity_grant_required"] is True
        assert requirement["identical_maximum_permissions_cap_required"] is True
        assert requirement["additional_inline_policy_count"] == 0
        assert requirement["additional_attached_policy_count"] == 0
        assert requirement["group_policy_count"] == 0
        assert requirement["missing_incomplete_or_drift_mode"] == "STOP_NO_MUTATION"
    allows = [_actions(phase["executor_policy"]["document"]) for phase in phases]
    assert "iam:CreatePolicy" in allows[0] and "iam:CreateRole" not in allows[0]
    assert "iam:CreateRole" in allows[1] and "iam:CreatePolicy" not in allows[1]
    assert "lambda:CreateFunction" in allows[2] and "iam:PassRole" in allows[2]
    assert "lambda:CreateFunction" in allows[3] and "logs:CreateLogGroup" in allows[3]
    assert "iam:AttachRolePolicy" in allows[4] and "lambda:InvokeFunction" not in allows[4]
    assert "lambda:InvokeFunction" in allows[5] and "iam:AttachRolePolicy" not in allows[5]
    assert "iam:DetachRolePolicy" in allows[6] and "lambda:InvokeFunction" not in allows[6]
    assert "iam:AttachRolePolicy" in allows[7] and "iam:CreateRole" not in allows[7]
    assert all("iam:PutRolePolicy" not in actions for actions in allows)
    revocation = compiled["revocation"]
    assert revocation["operations"][0]["allowed_action"] == "sts:GetCallerIdentity"
    assert revocation["forward_execution_permitted"] is False
    assert len(revocation["mutations"]) == 4
    assert revocation["executor_effective_authority_requirement"][
        "identical_maximum_permissions_cap_required"
    ] is True
    proof_digest = next(
        item["document_digest"]
        for item in compiled["boundaries"]
        if item["key"] == "proof"
    )
    operations = revocation["operations"]
    first_write = next(
        index
        for index, item in enumerate(operations)
        if item["api_action"] == "PutRolePermissionsBoundary"
    )
    last_write = max(
        index
        for index, item in enumerate(operations)
        if item["api_action"] == "PutRolePermissionsBoundary"
    )
    prechecks = operations[1:first_write]
    postchecks = operations[last_write + 1 :]
    assert [item["api_action"] for item in prechecks] == [
        "GetPolicy",
        "GetPolicyVersion",
        "ListPolicyVersions",
        "ListEntitiesForPolicy",
        "ListEntitiesForPolicy",
    ]
    assert [item["api_action"] for item in postchecks] == [
        item["api_action"] for item in prechecks
    ]
    for item in [*prechecks, *postchecks]:
        assert item["expected_default_version_id"] == "v1"
        assert item["expected_policy_versions"] == ["v1"]
        assert item["expected_document_digest"] == proof_digest
        assert item["mismatch_or_incomplete_mode"] == "STOP_NO_REVOCATION"


def test_executor_authority_evidence_rejects_additive_or_uncapped_profiles(
    compiled: Mapping[str, Any]
) -> None:
    evidence = _authority_evidence(compiled, "POLICY_FACTORY")
    materializer.validate_executor_authority_evidence(
        compiled,
        phase="POLICY_FACTORY",
        evidence=evidence,
        expected_caller_arn_digest=evidence["caller_arn_digest"],
        expected_evidence_digest=evidence["evidence_digest"],
        evaluation_at=AUTHORITY_EVALUATION,
    )

    for field, unsafe_value in (
        ("additional_attached_policy_count", 1),
        ("maximum_authority_document_digest", "sha256:" + "2" * 64),
        ("effective_policy_inventory_complete", False),
        ("session_chain_depth", 1),
    ):
        unsafe = copy.deepcopy(evidence)
        unsafe[field] = unsafe_value
        unsafe["evidence_digest"] = materializer.canonical_digest(
            {key: value for key, value in unsafe.items() if key != "evidence_digest"}
        )
        with pytest.raises(
            materializer.ServiceRoleMaterializationError,
            match="EXECUTOR_EFFECTIVE_AUTHORITY_NOT_CLOSED",
        ):
            materializer.validate_executor_authority_evidence(
                compiled,
                phase="POLICY_FACTORY",
                evidence=unsafe,
                expected_caller_arn_digest=evidence["caller_arn_digest"],
                expected_evidence_digest=unsafe["evidence_digest"],
                evaluation_at=AUTHORITY_EVALUATION,
            )

    forged = copy.deepcopy(evidence)
    forged["caller_arn_digest"] = "sha256:" + "9" * 64
    forged["evidence_digest"] = materializer.canonical_digest(
        {key: value for key, value in forged.items() if key != "evidence_digest"}
    )
    with pytest.raises(
        materializer.ServiceRoleMaterializationError,
        match="EXECUTOR_EFFECTIVE_AUTHORITY_NOT_CLOSED",
    ):
        materializer.validate_executor_authority_evidence(
            compiled,
            phase="POLICY_FACTORY",
            evidence=forged,
            expected_caller_arn_digest=evidence["caller_arn_digest"],
            expected_evidence_digest=forged["evidence_digest"],
            evaluation_at=AUTHORITY_EVALUATION,
        )

    with pytest.raises(
        materializer.ServiceRoleMaterializationError,
        match="EXECUTOR_EFFECTIVE_AUTHORITY_NOT_CLOSED",
    ):
        materializer.validate_executor_authority_evidence(
            compiled,
            phase="POLICY_FACTORY",
            evidence=evidence,
            expected_caller_arn_digest=evidence["caller_arn_digest"],
            expected_evidence_digest=evidence["evidence_digest"],
            evaluation_at=AUTHORITY_EVALUATION + timedelta(minutes=20),
        )


def test_foundation_proof_bounds_seven_roles_and_has_zero_dynamodb_authority(
    compiled: Mapping[str, Any]
) -> None:
    proof_arn = next(
        item["arn"] for item in compiled["boundaries"] if item["key"] == "proof"
    )
    foundation = compiled["authorization_phases"][1]
    operation_actions = [item["allowed_action"] for item in foundation["operations"]]
    assert not any(action.startswith("dynamodb:") for action in operation_actions)
    role_creates = [
        item for item in foundation["mutations"] if item["allowed_action"] == "iam:CreateRole"
    ]
    assert len(role_creates) == 7
    assert {item["request"]["PermissionsBoundary"] for item in role_creates} == {proof_arn}
    assert foundation["checkpoint"]["all_role_permissions_boundary_arn"] == proof_arn
    assert foundation["checkpoint"]["human_dynamodb_actions"] == []
    assert not any(
        action.startswith("dynamodb:")
        for action in _actions(foundation["executor_policy"]["document"])
    )


def test_roles_have_exact_trust_final_boundary_attachment_and_zero_inline(
    compiled: Mapping[str, Any]
) -> None:
    roles = [compiled["service_role"], *compiled["child_roles"]]
    assert len(roles) == 7
    for role in roles:
        expected = [] if role["role_name"] == materializer.LEDGER_FACTORY_ROLE_NAME else [role["permissions_boundary_arn"]]
        assert role["attached_policy_arns"] == expected
        assert role["inline_policy_names"] == []
    assert compiled["service_role"]["trust_policy"] == materializer.cloudformation_trust_policy()
    assert compiled["service_role"]["trust_policy"]["Statement"][0]["Principal"] == {
        "Service": "cloudformation.amazonaws.com"
    }
    activations = next(
        item["mutations"]
        for item in compiled["authorization_phases"]
        if item["phase"] == "ACTIVATOR"
    )
    assert not any(
        item["allowed_action"] == "iam:PutRolePermissionsBoundary"
        and item["target_arn"] in {
            materializer._role_arn(materializer.CLASSIFIER_PROOF_ROLE_NAME),  # noqa: SLF001
            materializer._role_arn(materializer.APPROVER_PROOF_ROLE_NAME),  # noqa: SLF001
        }
        for item in activations
    )


def test_service_managed_policy_has_no_child_iam_or_dynamodb_authority(
    bundle: Mapping[str, Any], compiled: Mapping[str, Any]
) -> None:
    policy = compiled["boundaries"][0]["document"]
    allow = _actions(policy)
    assert len(materializer.canonical_json(policy).encode()) <= 6144
    assert not any(action.startswith("dynamodb:") for action in allow)
    assert not ({
        "iam:CreateRole", "iam:PutRolePolicy", "iam:TagRole", "iam:GetRole",
        "iam:GetRolePolicy", "iam:ListRolePolicies", "iam:ListAttachedRolePolicies",
    } & allow)
    assert not any(action.startswith("iam:") for action in allow)
    contract = bundle["plan"]["artifact_signing_contract"]
    serialized = materializer.canonical_json(policy)
    assert contract["signed_destination"]["version_id"] not in serialized
    assert contract["signed_destination"]["sse_kms_key_arn"] not in serialized
    assert contract["code_signing_config"]["arn"] not in serialized
    assert contract["unsigned_source"]["key"] not in serialized
    assert "s3:GetObject\"" not in serialized
    assert "s3:GetObjectVersion" not in serialized
    assert "aws:CalledVia" not in serialized
    assert "aws:ViaAWSService" not in serialized


@pytest.mark.parametrize(
    "condition",
    [
        {
            "ForAnyValue:StringEquals": {
                "aws:CalledVia": ["cloudformation.amazonaws.com"]
            }
        },
        {"Bool": {"aws:ViaAWSService": "true"}},
    ],
)
def test_service_managed_policy_rejects_service_chain_conditions(
    bundle: Mapping[str, Any], compiled: Mapping[str, Any], condition: Mapping[str, Any]
) -> None:
    altered = copy.deepcopy(compiled)
    service_boundary = altered["boundaries"][0]
    statement = next(
        item
        for item in service_boundary["document"]["Statement"]
        if item["Sid"] == "ManageBrokerGraph"
    )
    statement["Condition"] = copy.deepcopy(condition)
    service_boundary["document_digest"] = materializer.canonical_digest(
        service_boundary["document"]
    )
    altered["boundary_set_digest"] = materializer.canonical_digest(
        altered["boundaries"]
    )
    _reseal(altered)

    with pytest.raises(
        materializer.ServiceRoleMaterializationError,
        match="BOUNDARY_SET_INVALID",
    ):
        materializer.validate_service_role_materialization_plan(
            altered,
            gug363_plan=bundle["plan"],
            expected_gug363_plan_digest=bundle["plan"]["plan_digest"],
            **_factory_kwargs(bundle),
            repo_root=bundle["repo"],
        )


def test_function_url_and_permission_conditions_are_closed(
    bundle: Mapping[str, Any], compiled: Mapping[str, Any]
) -> None:
    statements = compiled["boundaries"][0]["document"]["Statement"]
    assert "lambda:CreateFunction" not in _actions(compiled["boundaries"][0]["document"])
    url = next(item for item in statements if item["Action"] == "lambda:CreateFunctionUrlConfig")
    assert url["Condition"]["StringEquals"]["lambda:FunctionUrlAuthType"] == "AWS_IAM"
    permissions = [item for item in statements if item["Action"] == "lambda:AddPermission"]
    assert len(permissions) == 4
    for statement in permissions:
        condition = statement["Condition"]
        assert condition["StringEquals"]["lambda:Principal"] in {
            materializer._role_arn(materializer.CLASSIFIER_ROLE_NAME),  # noqa: SLF001
            materializer._role_arn(materializer.APPROVER_ROLE_NAME),  # noqa: SLF001
        }
        assert (
            condition["StringEquals"].get("lambda:FunctionUrlAuthType") == "AWS_IAM"
            or condition.get("Bool", {}).get("lambda:InvokedViaFunctionUrl") == "true"
        )


def test_function_factory_precreates_inert_exact_signed_broker(
    bundle: Mapping[str, Any], compiled: Mapping[str, Any]
) -> None:
    function = compiled["broker_function"]
    request = function["create_request"]
    assert request["FunctionName"] == materializer.BROKER_FUNCTION_NAME
    assert request["Environment"] == {"Variables": {}}
    assert request["Publish"] is False
    assert request["Role"] == materializer._role_arn(  # noqa: SLF001
        materializer.BROKER_ROLE_NAME
    )
    signed = bundle["plan"]["artifact_signing_contract"]["signed_destination"]
    assert request["Code"] == {
        "S3Bucket": signed["bucket"],
        "S3Key": signed["key"],
        "S3ObjectVersion": signed["version_id"],
    }
    assert function["normalized_configuration"]["CodeSha256"] == signed[
        "lambda_code_sha256"
    ]
    assert function["expected_versions"] == ["$LATEST"]
    assert function["expected_aliases"] == []
    assert function["expected_function_urls"] == []
    assert function["resource_policy_expected"] == "ABSENT_RESOURCE_NOT_FOUND"
    assert function["complete_environment_configuration_deferred_to_gug357"] is True
    assert function["fresh_gug357_configuration_is_not_part_of_gug365_bundle"] is True
    phases = {item["phase"]: item for item in compiled["authorization_phases"]}
    checkpoint = phases["FUNCTION_FACTORY"]["checkpoint"]
    assert checkpoint["checkpoint"] == (
        "EXACT_PRECREATED_BROKER_CERTIFIED_AUTHORITY_EXPIRED"
    )
    assert checkpoint["execution_role_permissions_boundary_arn"].endswith(
        materializer.PROOF_BOUNDARY_NAME
    )
    assert checkpoint["execution_role_attached_policy_arns"] == []
    assert checkpoint["versions"] == ["$LATEST"]
    assert checkpoint["aliases"] == []
    assert checkpoint["function_urls"] == []


def test_dedicated_factory_uses_separate_signed_zip_and_immutable_version(
    bundle: Mapping[str, Any], compiled: Mapping[str, Any]
) -> None:
    factory = compiled["ledger_factory_function"]
    broker = compiled["broker_function"]
    request = factory["create_request"]
    assert request["FunctionName"] == materializer.LEDGER_FACTORY_FUNCTION_NAME
    assert request["Handler"] == factory_package.HANDLER
    assert request["Role"] == materializer._role_arn(  # noqa: SLF001
        materializer.LEDGER_FACTORY_ROLE_NAME
    )
    assert request["Environment"] == {"Variables": {}}
    assert request["Publish"] is True
    assert factory["immutable_version"] == "1"
    assert factory["immutable_version_arn"].endswith(":1")
    assert factory["signed_code"] != broker["signed_code"]
    assert request["Code"]["S3Key"] == bundle["factory_contract"][
        "signed_destination"
    ]["key"]
    assert factory["package_manifest_digest"] == bundle["factory_contract"][
        "package_manifest"
    ]["manifest_digest"]
    assert factory["event_contract"] == {}
    assert factory["invocation_type"] == "RequestResponse"


@pytest.mark.parametrize(
    "mutation",
    [
        "profile_name",
        "profile_version_id",
        "profile_version_arn",
        "signature_expired",
        "reuse_broker_signed_destination",
        "manifest_digest",
        "foreign_bucket",
        "foreign_kms",
        "malformed_csc",
    ],
)
def test_dedicated_factory_signing_contract_rejects_cross_binding(
    bundle: Mapping[str, Any], mutation: str
) -> None:
    contract = copy.deepcopy(bundle["factory_contract"])
    if mutation == "profile_name":
        contract["signer"]["profile_name"] = "different_profile"
    elif mutation == "profile_version_id":
        contract["signer"]["profile_version_id"] = "f" * 10
    elif mutation == "profile_version_arn":
        contract["signer"]["profile_version_arn"] = (
            contract["signer"]["profile_version_arn"] + "-drift"
        )
    elif mutation == "signature_expired":
        contract["signer"]["signature_expires_at"] = "2029-12-31T23:59:59Z"
    elif mutation == "reuse_broker_signed_destination":
        contract["signed_destination"] = copy.deepcopy(
            bundle["plan"]["artifact_signing_contract"]["signed_destination"]
        )
    elif mutation == "manifest_digest":
        contract["unsigned_source"]["manifest_digest"] = "sha256:" + "f" * 64
    elif mutation == "foreign_bucket":
        contract["unsigned_source"]["bucket"] = "foreign-gug365-artifacts"
        contract["signed_destination"]["bucket"] = "foreign-gug365-artifacts"
    elif mutation == "foreign_kms":
        foreign_kms = (
            "arn:aws:kms:us-east-1:999999999999:key/"
            "11111111-2222-3333-4444-555555555555"
        )
        contract["unsigned_source"]["sse_kms_key_arn"] = foreign_kms
        contract["signed_destination"]["sse_kms_key_arn"] = foreign_kms
    elif mutation == "malformed_csc":
        contract["code_signing_config"]["arn"] = (
            "arn:aws:lambda:us-east-1:042360977644:"
            "code-signing-config:csc-malformed-extra"
        )
    digest = materializer.ledger_factory_artifact_signing_contract_digest(
        contract
    )
    with pytest.raises(materializer.ServiceRoleMaterializationError):
        materializer.compile_service_role_materialization_plan(
            gug363_plan=bundle["plan"],
            expected_gug363_plan_digest=bundle["plan"]["plan_digest"],
            ledger_factory_artifact_signing_contract=contract,
            expected_ledger_factory_artifact_signing_contract_digest=digest,
            repo_root=bundle["repo"],
        )


def _valid_factory_receipt(compiled: Mapping[str, Any]) -> dict[str, Any]:
    version_arn = compiled["ledger_factory_function"]["immutable_version_arn"]
    receipt: dict[str, Any] = {
        "artifact_type": materializer.ledger_factory.RECEIPT_ARTIFACT_TYPE,
        "schema_version": 1,
        "status": "CREATED",
        "reason_code": "LEDGER_EXACT_FULL_READBACK",
        "attempt": 1,
        "create_table_call_count": 1,
        "update_pitr_call_count": 1,
        "retry_permitted": False,
        "next_required_action": "REVOKE_FACTORY_AUTHORITY",
        "request_sha256": materializer.canonical_digest({}),
        "contract_sha256": materializer.ledger_factory.CONTRACT_SHA256,
        "qualified_function_sha256": materializer.canonical_digest(
            {"qualified_function_arn": version_arn}
        ),
        "resource_policy_sha256": materializer.canonical_digest(
            materializer._ledger_resource_policy()  # noqa: SLF001
        ),
        "kms_key_arn_sha256": "sha256:" + "6" * 64,
        "kms_key_metadata_sha256": "sha256:" + "7" * 64,
        "revision_id_sha256": "sha256:" + "8" * 64,
        "active_readback_attempt_count": 2,
        "policy_readback_attempt_count": 2,
        "pitr_readback_attempt_count": 1,
        "receipt_sha256": "",
    }
    receipt["receipt_sha256"] = materializer.canonical_digest(
        {key: value for key, value in receipt.items() if key != "receipt_sha256"}
    )
    return receipt


def _complete_causal_bundle(
    compiled: Mapping[str, Any],
) -> tuple[
    list[dict[str, Any]],
    list[dict[str, Any]],
    list[dict[str, Any]],
    str,
    str,
    dict[str, Any],
]:
    initial_absence = materializer.canonical_digest(
        {
            "classification": "ALL_TARGETS_ABSENT",
            "authorized_plan_digest": compiled["plan_digest"],
        }
    )
    factory_receipt = _valid_factory_receipt(compiled)
    records: list[dict[str, Any]] = []
    bindings: list[dict[str, Any]] = []
    evidence_records: list[dict[str, Any]] = []
    bundle_digest = ""
    previous: dict[str, Any] | None = None
    previous_phase: Mapping[str, Any] | None = None
    for index, phase_item in enumerate(compiled["authorization_phases"]):
        phase = phase_item["phase"]
        phase_start = AUTHORITY_EVALUATION + timedelta(minutes=20 * index)
        caller_digest = materializer.canonical_digest(
            {"phase": phase, "caller_session": index}
        )
        evidence = _authority_evidence(
            compiled,
            phase,
            caller_digest=caller_digest,
            evaluation_at=phase_start,
        )
        predecessor_security: dict[str, Any]
        if previous is None:
            predecessor_security = {
                "expected_initial_bundle_absence_digest": initial_absence,
                "predecessor_record": None,
                "expected_predecessor_binding": None,
            }
        else:
            assert previous_phase is not None
            predecessor_security = {
                "expected_initial_bundle_absence_digest": None,
                "predecessor_record": copy.deepcopy(previous),
                "expected_predecessor_binding": {
                    "phase": previous["phase"],
                    "ledger_id": previous["ledger_id"],
                    "initial_ledger_digest": previous["initial_ledger_digest"],
                    "claim_nonce_digest": previous["claim"][
                        "claim_nonce_digest"
                    ],
                    "terminal_receipt_digest": previous["receipt_chain"][-1][
                        "receipt_digest"
                    ],
                    "ledger_digest": previous["ledger_digest"],
                    "checkpoint_digest": previous_phase["checkpoint_digest"],
                },
            }
        required_checkpoint = (
            initial_absence
            if previous_phase is None
            else previous_phase["checkpoint_digest"]
        )
        prepared = materializer.phase_ledger.build_prepared_ledger(
            plan=compiled,
            expected_plan_digest=compiled["plan_digest"],
            phase=phase,
            profile_class="GUG365" + phase.replace("_", ""),
            caller_arn_digest=evidence["caller_arn_digest"],
            executor_authority_evidence_digest=evidence["evidence_digest"],
            executor_authority_evidence=evidence,
            authority_evaluation_at=phase_start,
            authority_session_identifier_digest=evidence[
                "session_identifier_digest"
            ],
            authority_session_issued_at=datetime.fromisoformat(
                evidence["session_issued_at"].replace("Z", "+00:00")
            ),
            authority_session_expires_at=datetime.fromisoformat(
                evidence["session_expires_at"].replace("Z", "+00:00")
            ),
            authority_evidence_collected_at=datetime.fromisoformat(
                evidence["evidence_collected_at"].replace("Z", "+00:00")
            ),
            host_digest="sha256:" + "3" * 64,
            predecessor_phase=(
                None if previous_phase is None else previous_phase["phase"]
            ),
            predecessor_terminal_receipt_digest=(
                None
                if previous is None
                else previous["receipt_chain"][-1]["receipt_digest"]
            ),
            predecessor_ledger_digest=(
                None if previous is None else previous["ledger_digest"]
            ),
            before_state_digest=required_checkpoint,
            required_predecessor_checkpoint_digest=required_checkpoint,
            **predecessor_security,
            not_before=phase_start,
            expires_at=phase_start + timedelta(minutes=10),
        )
        claim_nonce = materializer.canonical_digest(
            {"phase": phase, "claim": "OWNER_AUTHORIZED_ONCE"}
        )
        execution_authorization = {
            field: (
                claim_nonce
                if field == "claim_nonce_digest"
                else copy.deepcopy(prepared[field])
            )
            for field in materializer.phase_ledger._EXECUTION_AUTHORIZATION_FIELDS  # noqa: SLF001
        }
        current = materializer.phase_ledger.prepare_claim(
            prepared,
            expected_version=prepared["ledger_version"],
            expected_digest=prepared["ledger_digest"],
            at=phase_start + timedelta(seconds=1),
            claim_nonce_digest=claim_nonce,
            profile_class=prepared["profile_class"],
            caller_arn_digest=prepared["caller_arn_digest"],
            executor_authority_evidence_digest=prepared[
                "executor_authority_evidence_digest"
            ],
            host_digest=prepared["host_digest"],
            execution_authorization=execution_authorization,
            plan=compiled,
            expected_plan_digest=compiled["plan_digest"],
            executor_authority_evidence=evidence,
            authority_evaluation_at=phase_start,
            **predecessor_security,
        ).proposed_record
        for operation_sequence, operation in enumerate(
            phase_item["operations"], 1
        ):
            in_flight = materializer.phase_ledger.prepare_operation_in_flight(
                current,
                expected_version=current["ledger_version"],
                expected_digest=current["ledger_digest"],
                at=phase_start + timedelta(seconds=2 * operation_sequence),
                operation_sequence=operation_sequence,
            ).proposed_record
            provider_result = (
                factory_receipt["receipt_sha256"]
                if phase == "LEDGER_FACTORY_INVOKER"
                and operation.get("api_action") == "InvokeFunction"
                else materializer.canonical_digest(
                    {
                        "phase": phase,
                        "operation_sequence": operation_sequence,
                        "result": "SYNTHETIC_SUCCESS",
                    }
                )
            )
            current = materializer.phase_ledger.prepare_operation_record(
                in_flight,
                expected_version=in_flight["ledger_version"],
                expected_digest=in_flight["ledger_digest"],
                at=phase_start
                + timedelta(seconds=(2 * operation_sequence) + 1),
                operation_sequence=operation_sequence,
                outcome="SUCCEEDED",
                provider_result_digest=provider_result,
            ).proposed_record
        derived = materializer.phase_ledger.phase_binding_from_plan(
            compiled,
            phase=phase,
            expected_plan_digest=compiled["plan_digest"],
        )
        bundle_digest = derived["bundle_digest"]
        records.append(current)
        evidence_records.append(evidence)
        bindings.append(
            {
                "phase": phase,
                "ledger_id": prepared["ledger_id"],
                "initial_ledger_digest": prepared["initial_ledger_digest"],
                "claim_nonce_digest": claim_nonce,
                "terminal_receipt_digest": current["receipt_chain"][-1][
                    "receipt_digest"
                ],
                "caller_arn_digest": current["caller_arn_digest"],
                "executor_authority_evidence_digest": current[
                    "executor_authority_evidence_digest"
                ],
                "authority_session_identifier_digest": current[
                    "authority_session_identifier_digest"
                ],
                "authority_session_issued_at": current[
                    "authority_session_issued_at"
                ],
                "authority_session_expires_at": current[
                    "authority_session_expires_at"
                ],
                "authority_evidence_collected_at": current[
                    "authority_evidence_collected_at"
                ],
                "authority_evaluation_at": current["authority_evaluation_at"],
                "predecessor_phase": current["predecessor_phase"],
                "predecessor_terminal_receipt_digest": current[
                    "predecessor_terminal_receipt_digest"
                ],
                "predecessor_ledger_digest": current[
                    "predecessor_ledger_digest"
                ],
                "before_state_digest": current["before_state_digest"],
                "required_predecessor_checkpoint_digest": current[
                    "required_predecessor_checkpoint_digest"
                ],
            }
        )
        previous = current
        previous_phase = phase_item
    return (
        records,
        bindings,
        evidence_records,
        bundle_digest,
        initial_absence,
        factory_receipt,
    )


def test_factory_activation_invoke_receipt_and_revocation_are_causal(
    compiled: Mapping[str, Any]
) -> None:
    phases = {item["phase"]: item for item in compiled["authorization_phases"]}
    activator = phases["LEDGER_FACTORY_ACTIVATOR"]
    assert [item["allowed_action"] for item in activator["mutations"]] == [
        "iam:AttachRolePolicy",
        "iam:PutRolePermissionsBoundary",
    ]
    invoker = phases["LEDGER_FACTORY_INVOKER"]
    invoke = invoker["mutations"][0]
    assert invoke["target_arn"].endswith(":1")
    assert invoke["request"] == {
        "FunctionName": invoke["target_arn"],
        "InvocationType": "RequestResponse",
        "Payload": "{}",
    }
    gate = invoker["checkpoint"]
    assert gate["accepted_statuses"] == ["CREATED", "CREATED_RECONCILED"]
    assert gate["accepted_create_table_call_count"] == 1
    assert gate["accepted_update_pitr_call_count"] == 1
    assert gate["already_exact_mode"] == "BLOCK_OWNER_RECOVERY_NO_ACTIVATION"
    revoker = phases["LEDGER_FACTORY_REVOKER"]
    assert [item["allowed_action"] for item in revoker["mutations"]] == [
        "iam:PutRolePermissionsBoundary",
        "iam:DetachRolePolicy",
    ]
    assert revoker["checkpoint"]["proof_boundary_write_is_first_mutation"] is True
    assert revoker["checkpoint"]["detach_is_second_mutation"] is True
    assert list(phases).index("LEDGER_FACTORY_REVOKER") < list(phases).index(
        "ACTIVATOR"
    )


def test_factory_causal_receipt_accepts_only_created_one_one(
    compiled: Mapping[str, Any]
) -> None:
    receipt = _valid_factory_receipt(compiled)
    materializer.validate_ledger_factory_causal_receipt(
        compiled,
        receipt=receipt,
        expected_receipt_sha256=receipt["receipt_sha256"],
    )
    no_touch = copy.deepcopy(receipt)
    no_touch.update(
        {
            "status": "ALREADY_EXACT",
            "create_table_call_count": 0,
            "update_pitr_call_count": 0,
        }
    )
    no_touch["receipt_sha256"] = materializer.canonical_digest(
        {key: value for key, value in no_touch.items() if key != "receipt_sha256"}
    )
    with pytest.raises(
        materializer.ServiceRoleMaterializationError,
        match="LEDGER_FACTORY_CAUSAL_RECEIPT_NOT_ACCEPTED",
    ):
        materializer.validate_ledger_factory_causal_receipt(
            compiled,
            receipt=no_touch,
            expected_receipt_sha256=no_touch["receipt_sha256"],
        )


@pytest.mark.parametrize(
    ("field", "invalid_value"),
    (
        ("revision_id_sha256", "x"),
        ("attempt", True),
        ("create_table_call_count", True),
        ("update_pitr_call_count", True),
        ("active_readback_attempt_count", "x"),
        ("active_readback_attempt_count", 0),
        ("active_readback_attempt_count", True),
        ("active_readback_attempt_count", 61),
        ("policy_readback_attempt_count", "x"),
        ("policy_readback_attempt_count", 0),
        ("policy_readback_attempt_count", True),
        ("policy_readback_attempt_count", 13),
        ("pitr_readback_attempt_count", "x"),
        ("pitr_readback_attempt_count", 0),
        ("pitr_readback_attempt_count", True),
        ("pitr_readback_attempt_count", 13),
    ),
)
def test_factory_causal_receipt_rejects_non_digest_and_unbounded_counts(
    compiled: Mapping[str, Any], field: str, invalid_value: object
) -> None:
    receipt = _valid_factory_receipt(compiled)
    receipt[field] = invalid_value
    receipt["receipt_sha256"] = materializer.canonical_digest(
        {key: value for key, value in receipt.items() if key != "receipt_sha256"}
    )

    with pytest.raises(
        materializer.ServiceRoleMaterializationError,
        match="LEDGER_FACTORY_CAUSAL_RECEIPT_NOT_ACCEPTED",
    ):
        materializer.validate_ledger_factory_causal_receipt(
            compiled,
            receipt=receipt,
            expected_receipt_sha256=receipt["receipt_sha256"],
        )


def test_factory_causal_receipt_accepts_runtime_maximum_poll_counts(
    compiled: Mapping[str, Any]
) -> None:
    receipt = _valid_factory_receipt(compiled)
    receipt.update(
        {
            "status": "CREATED_RECONCILED",
            "active_readback_attempt_count": 60,
            "policy_readback_attempt_count": 12,
            "pitr_readback_attempt_count": 12,
        }
    )
    receipt["receipt_sha256"] = materializer.canonical_digest(
        {key: value for key, value in receipt.items() if key != "receipt_sha256"}
    )

    materializer.validate_ledger_factory_causal_receipt(
        compiled,
        receipt=receipt,
        expected_receipt_sha256=receipt["receipt_sha256"],
    )


def test_function_factory_policy_and_readback_close_alternate_payloads(
    compiled: Mapping[str, Any]
) -> None:
    phases = {item["phase"]: item for item in compiled["authorization_phases"]}
    document = phases["FUNCTION_FACTORY"]["executor_policy"]["document"]
    create = next(
        item for item in document["Statement"]
        if item["Action"] == "lambda:CreateFunction"
    )
    tags = compiled["broker_function"]["tags"]
    assert create["Condition"]["StringEquals"] == {
        f"aws:RequestTag/{key}": value for key, value in tags.items()
    }
    assert create["Condition"]["ForAllValues:StringEquals"] == {
        "aws:TagKeys": list(tags)
    }
    assert create["Condition"]["Null"] == {
        "lambda:Layer": "true",
        "lambda:VpcIds": "true",
        "lambda:SubnetIds": "true",
        "lambda:SecurityGroupIds": "true",
    }
    deny = _actions(document, effect="Deny")
    assert {
        "lambda:UpdateFunctionCode",
        "lambda:UpdateFunctionConfiguration",
        "lambda:PublishVersion",
        "lambda:CreateAlias",
        "lambda:CreateFunctionUrlConfig",
        "lambda:AddPermission",
        "lambda:InvokeFunction",
    }.issubset(deny)
    function_reads = [
        item for item in compiled["planned_readbacks"]
        if item["service"] == "lambda"
    ]
    assert {item["verification_stage"] for item in function_reads} == {
        "BEFORE_FUNCTION_CREATE_ABSENCE_OR_RECONCILIATION",
        "AFTER_FUNCTION_FACTORY_AUTHORITY_EXPIRED",
    }
    assert all(item["code_location_persistence_permitted"] is False for item in function_reads)
    assert all(item["environment_values_persistence_permitted"] is False for item in function_reads)
    before = [
        item
        for item in function_reads
        if item["verification_stage"]
        == "BEFORE_FUNCTION_CREATE_ABSENCE_OR_RECONCILIATION"
    ]
    csc = next(item for item in before if item["api_action"] == "GetCodeSigningConfig")
    assert csc["absence_expected_before_create"] is False
    assert csc["code_signing_config_exact_and_enforcing"] is True
    assert all(
        item["absence_expected_before_create"] is True
        for item in before
        if item["api_action"] != "GetCodeSigningConfig"
    )


def test_factory_lambda_readbacks_certify_exact_immutable_version(
    compiled: Mapping[str, Any]
) -> None:
    function = compiled["ledger_factory_function"]
    version_arn = function["immutable_version_arn"]
    phase = next(
        item
        for item in compiled["authorization_phases"]
        if item["phase"] == "LEDGER_FACTORY_FUNCTION_FACTORY"
    )
    policy_statement = next(
        statement
        for statement in phase["executor_policy"]["document"]["Statement"]
        if "lambda:PutRuntimeManagementConfig"
        in (
            [statement["Action"]]
            if isinstance(statement.get("Action"), str)
            else statement.get("Action", [])
        )
    )
    assert set(policy_statement["Resource"]) == {
        function["arn"],
        version_arn,
        function["code_signing_config_arn"],
    }
    readbacks = [
        item
        for item in compiled["planned_readbacks"]
        if item["service"] == "lambda"
        and item["target_arn"] == version_arn
    ]
    qualified_actions = {
        "GetFunction",
        "GetFunctionConfiguration",
        "GetRuntimeManagementConfig",
        "GetPolicy",
    }
    assert {item["api_action"] for item in readbacks} == qualified_actions
    assert len(readbacks) == len(qualified_actions) * 2
    assert all(item["request"]["FunctionName"] == function["function_name"] for item in readbacks)
    assert all(item["request"]["Qualifier"] == "1" for item in readbacks)
    assert all(item["immutable_version_certified"] is True for item in readbacks)
    factory_base_reads = [
        item
        for item in compiled["planned_readbacks"]
        if item["service"] == "lambda"
        and item["request"].get("FunctionName") == function["function_name"]
        and item["api_action"] not in qualified_actions
        and item["api_action"] != "GetCodeSigningConfig"
    ]
    assert factory_base_reads
    assert all("Qualifier" not in item["request"] for item in factory_base_reads)
    assert all(item["target_arn"] == function["arn"] for item in factory_base_reads)


@pytest.mark.parametrize(
    "api_action",
    (
        "GetFunction",
        "GetFunctionConfiguration",
        "GetRuntimeManagementConfig",
        "GetPolicy",
    ),
)
def test_factory_lambda_readback_rejects_missing_version_qualifier(
    bundle: Mapping[str, Any], compiled: Mapping[str, Any], api_action: str
) -> None:
    altered = copy.deepcopy(compiled)
    readback = next(
        item
        for item in altered["planned_readbacks"]
        if item["service"] == "lambda"
        and item["api_action"] == api_action
        and item["target_arn"]
        == altered["ledger_factory_function"]["immutable_version_arn"]
    )
    readback["request"].pop("Qualifier")
    readback["target_arn"] = altered["ledger_factory_function"]["arn"]
    readback["immutable_version_certified"] = False
    altered["planned_readback_digest"] = materializer.canonical_digest(
        altered["planned_readbacks"]
    )
    _reseal(altered)

    with pytest.raises(
        materializer.ServiceRoleMaterializationError,
        match="PLANNED_READBACKS_INVALID",
    ):
        materializer.validate_service_role_materialization_plan(
            altered,
            gug363_plan=bundle["plan"],
            expected_gug363_plan_digest=bundle["plan"]["plan_digest"],
            **_factory_kwargs(bundle),
            repo_root=bundle["repo"],
        )


def test_factory_tag_conditions_and_activator_pairs_are_exact(compiled: Mapping[str, Any]) -> None:
    phases = {phase["phase"]: phase for phase in compiled["authorization_phases"]}
    policy_doc = phases["POLICY_FACTORY"]["executor_policy"]["document"]
    foundation_doc = phases["FOUNDATION_FACTORY"]["executor_policy"]["document"]
    for document in (policy_doc, foundation_doc):
        serialized = materializer.canonical_json(document)
        assert "aws:RequestTag/source_commit" in serialized
        assert "aws:RequestTag/gug363_pre_function_binding_sha256" in serialized
    assert {"iam:CreatePolicy", "iam:TagPolicy"}.issubset(
        _actions(policy_doc)
    )
    assert {"iam:CreateRole", "iam:TagRole"}.issubset(
        _actions(foundation_doc)
    )
    policy_operations = phases["POLICY_FACTORY"]["operations"]
    role_operations = phases["FOUNDATION_FACTORY"]["operations"]
    policy_creates = [
        item
        for item in policy_operations
        if item.get("allowed_action") == "iam:CreatePolicy"
    ]
    role_creates = [
        item
        for item in role_operations
        if item.get("allowed_action") == "iam:CreateRole"
    ]
    assert len(policy_creates) == 6 and len(role_creates) == 7
    assert all(
        item["dependent_authorization_actions"] == ["iam:TagPolicy"]
        and item["dependent_action_permitted_standalone"] is False
        and item["dependent_action_bound_to_create_request_tags"] is True
        for item in policy_creates
    )
    assert all(
        item["dependent_authorization_actions"] == ["iam:TagRole"]
        and item["dependent_action_permitted_standalone"] is False
        and item["dependent_action_bound_to_create_request_tags"] is True
        for item in role_creates
    )
    assert not any(
        item.get("allowed_action") in {"iam:TagPolicy", "iam:TagRole"}
        for phase in ("POLICY_FACTORY", "FOUNDATION_FACTORY")
        for item in phases[phase]["mutations"]
    )
    assert not any(
        action.startswith("dynamodb:") for action in _actions(foundation_doc)
    )
    function_factory = phases["FUNCTION_FACTORY"]
    function_document = function_factory["executor_policy"]["document"]
    assert {"lambda:CreateFunction", "lambda:TagResource", "iam:PassRole"}.issubset(
        _actions(function_document)
    )
    actions = [item["api_action"] for item in function_factory["operations"]]
    create_index = actions.index("CreateFunction")
    assert actions[create_index : create_index + 4] == [
        "CreateFunction",
        "WaitUntilFunctionActiveV2",
        "PutRuntimeManagementConfig",
        "PutFunctionConcurrency",
    ]
    ledger_function_factory = phases["LEDGER_FACTORY_FUNCTION_FACTORY"]
    ledger_actions = [item["api_action"] for item in ledger_function_factory["operations"]]
    assert ledger_actions.index("CreateLogGroup") < ledger_actions.index("CreateFunction")
    assert {"logs:CreateLogGroup", "logs:PutRetentionPolicy"}.issubset(
        _actions(ledger_function_factory["executor_policy"]["document"])
    )
    log_create = next(
        item
        for item in ledger_function_factory["mutations"]
        if item["allowed_action"] == "logs:CreateLogGroup"
    )
    assert log_create["request"]["deletionProtectionEnabled"] is True
    assert "tags" in log_create["request"]
    assert not any(
        item["allowed_action"] == "logs:TagResource"
        for item in ledger_function_factory["mutations"]
    )
    weakened_log_group = copy.deepcopy(compiled["ledger_factory_log_group"])
    weakened_log_group["deletion_protection_enabled"] = False
    assert weakened_log_group != compiled["ledger_factory_log_group"]
    activator = phases["ACTIVATOR"]["executor_policy"]["document"]
    attaches = [item for item in activator["Statement"] if item["Action"] == "iam:AttachRolePolicy"]
    assert len(attaches) == 6
    assert all(set(item["Condition"]["ArnEquals"]) == {
        "iam:PermissionsBoundary", "iam:PolicyARN"
    } for item in attaches)
    puts = [item for item in activator["Statement"] if item["Action"] == "iam:PutRolePermissionsBoundary"]
    assert len(puts) == 4
    assert all(set(item["Condition"]["ArnEquals"]) == {"iam:PermissionsBoundary"} for item in puts)


def test_table_create_request_is_factory_embedded_with_canonical_policy_string(
    compiled: Mapping[str, Any]
) -> None:
    table = compiled["ledger_table"]
    writes = compiled["planned_iam_writes"]
    assert not any(item["allowed_action"].startswith("dynamodb:") for item in writes)
    create_request = materializer._create_table_request(table)  # noqa: SLF001
    assert create_request["ResourcePolicy"] == materializer.canonical_json(
        table["resource_policy"]
    )
    assert create_request["BillingMode"] == "PAY_PER_REQUEST"
    assert create_request["DeletionProtectionEnabled"] is True
    assert create_request["SSESpecification"] == {
        "Enabled": True,
        "SSEType": "KMS",
        "KMSMasterKeyId": "alias/aws/dynamodb",
    }
    assert table["kms_key_contract"]["metadata_projection"]["KeyManager"] == "AWS"
    assert table["kms_key_contract"]["metadata_projection"]["Origin"] == "AWS_KMS"
    assert table["time_to_live"] == {
        "TimeToLiveStatus": "DISABLED",
        "AttributeName": None,
    }
    assert create_request["Tags"] == [
        {"Key": "managed_by", "Value": "reviewed-direct-dynamodb"},
        {"Key": "service", "Value": "scanalyze-platform-authority"},
        {"Key": "data_class", "Value": "control-metadata"},
        {"Key": "work_package", "Value": "GUG-215"},
        {"Key": "environment", "Value": "non-production"},
        {"Key": "production", "Value": "false"},
        {"Key": "account_id", "Value": materializer.AUTHORITY_ACCOUNT_ID},
        {"Key": "region", "Value": materializer.REGION},
    ]
    assert materializer._update_pitr_request(table)[  # noqa: SLF001
        "PointInTimeRecoverySpecification"
    ] == {
        "PointInTimeRecoveryEnabled": True, "RecoveryPeriodInDays": 35
    }
    assert "PutResourcePolicy" not in [item["api_action"] for item in writes]


def test_broker_boundary_requires_exact_source_and_defaults_dangerous_actions_to_deny(
    compiled: Mapping[str, Any]
) -> None:
    broker = next(item for item in compiled["boundaries"] if item["key"] == "broker")["document"]
    assert not any(item["Effect"] == "Deny" for item in broker["Statement"])
    delete = next(item for item in broker["Statement"] if item["Action"] == "cloudformation:DeleteChangeSet")
    assert delete["Condition"]["ArnEquals"]["lambda:SourceFunctionArn"].endswith(
        ":function:scanalyze-platform-authority-gug215-retirement"
    )
    assert all(
        item.get("Condition", {}).get("ArnEquals", {}).get("lambda:SourceFunctionArn")
        for item in broker["Statement"] if item["Effect"] == "Allow"
    )
    assert "iam:CreateUser" not in _actions(broker)
    assert "cloudformation:CreateStack" not in _actions(broker)
    assert {"iam:GetPolicy", "iam:GetPolicyVersion"}.issubset(_actions(broker))


def test_deny_all_boundary_caps_malicious_identity_policy(compiled: Mapping[str, Any]) -> None:
    malicious = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}],
    }
    boundaries = {item["key"]: item["document"] for item in compiled["boundaries"]}
    assert materializer.effective_allow_actions(boundaries["proof"], malicious) == ()
    assert "iam:CreateUser" not in materializer.effective_allow_actions(
        boundaries["classifier_invoker"], malicious
    )


def test_exact_readbacks_and_final_inventory(compiled: Mapping[str, Any]) -> None:
    readbacks = compiled["planned_readbacks"]
    assert sum(item["api_action"] == "GetPolicyVersion" for item in readbacks) == 6
    assert sum(item["api_action"] == "ListEntitiesForPolicy" for item in readbacks) == 12
    assert sum(item["api_action"] == "GetRole" for item in readbacks) == 7
    assert not any(item["api_action"] == "GetRolePolicy" for item in readbacks)
    dynamodb_readbacks = [
        item for item in readbacks if item["service"] == "dynamodb"
    ]
    tag_readbacks = [
        item
        for item in dynamodb_readbacks
        if item["api_action"] == "ListTagsOfResource"
    ]
    assert len(tag_readbacks) == 2
    assert all(item["complete_pagination_required"] is True for item in tag_readbacks)
    assert all(
        item["complete_pagination_required"] is False
        for item in dynamodb_readbacks
        if item["api_action"] != "ListTagsOfResource"
    )
    kms_readbacks = [item for item in readbacks if item["service"] == "kms"]
    assert len(kms_readbacks) == 2
    assert {item["verification_stage"] for item in kms_readbacks} == {
        "AFTER_ACCEPTED_CAUSAL_RECEIPT_AND_FACTORY_REVOCATION",
        "AFTER_FINAL_ROLE_POLICY_SET_CERTIFIED",
    }
    kms_metadata = compiled["ledger_table"]["kms_key_contract"][
        "metadata_projection"
    ]
    for item in kms_readbacks:
        assert item["api_action"] == "DescribeKey"
        assert item["request"] == {
            "KeyId": "<OBSERVED_TABLE_SSE_DESCRIPTION_KMS_MASTER_KEY_ARN>"
        }
        assert item["iam_resource_scope_required"] == "*"
        assert item["expected_aws_managed_metadata"] == kms_metadata
        assert item["key_metadata_arn_must_equal_observed_table_kms_arn"] is True
        assert item["metadata_digest_projection_dynamic_fields"] == {
            "arn_sha256": "kms_key_arn_sha256"
        }
        assert item["receipt_digest_comparisons"] == {
            "kms_key_arn_sha256": "EXACT_CANONICAL_DIGEST_MATCH",
            "kms_key_metadata_sha256": "EXACT_CANONICAL_DIGEST_MATCH",
        }
        assert item["raw_key_identifiers_persistence_permitted"] is False
    inventory = materializer.expected_normalized_inventory(compiled)
    assert len(inventory["policies"]) == 6 and len(inventory["roles"]) == 7
    for role in inventory["roles"].values():
        expected = [] if role["role_name"] == materializer.LEDGER_FACTORY_ROLE_NAME else [role["permissions_boundary_arn"]]
        assert role["attached_policy_arns"] == expected
        assert role["inline_policy_names"] == []
    assert inventory["ledger_table"]["scan_count"] == 0
    assert inventory["broker_function"] == compiled["broker_function"]
    assert inventory["ledger_factory_function"] == compiled["ledger_factory_function"]
    assert inventory["ledger_factory_log_group"] == compiled["ledger_factory_log_group"]


def test_preexisting_state_classifications_require_authorization_and_causal_ledger(
    compiled: Mapping[str, Any]
) -> None:
    expected = materializer.expected_normalized_inventory(compiled)
    absent = {
        "policies": {arn: None for arn in expected["policies"]},
        "roles": {arn: None for arn in expected["roles"]},
        "ledger_table": None,
        "broker_function": None,
        "ledger_factory_function": None,
        "ledger_factory_log_group": None,
    }
    unauthorized_absent = materializer.classify_preexisting_inventory(compiled, absent)
    assert unauthorized_absent["classification"] == "NOT_AUTHORIZED"
    assert unauthorized_absent["observed_state"] == "ALL_TARGETS_ABSENT"
    assert unauthorized_absent["writes_authorized"] is False
    caller_digest = "sha256:" + "a" * 64
    evidence = _authority_evidence(
        compiled, "POLICY_FACTORY", caller_digest=caller_digest
    )
    ready = materializer.classify_preexisting_inventory(
        compiled,
        absent,
        expected_authorized_plan_digest=compiled["plan_digest"],
        executor_authority_evidence=evidence,
        expected_executor_authority_phase="POLICY_FACTORY",
        expected_caller_arn_digest=caller_digest,
        expected_executor_authority_evidence_digest=evidence["evidence_digest"],
        authority_evaluation_at=AUTHORITY_EVALUATION,
    )
    assert ready["classification"] == "ABSENT_READY"
    assert ready["writes_authorized"] is True
    resealed = copy.deepcopy(compiled)
    resealed["environment"] = "attacker-resealed"
    resealed["plan_digest"] = materializer.canonical_digest(
        {key: value for key, value in resealed.items() if key != "plan_digest"}
    )
    with pytest.raises(
        materializer.ServiceRoleMaterializationError,
        match="AUTHORIZED_PLAN_DIGEST_MISMATCH",
    ):
        materializer.classify_preexisting_inventory(
            resealed,
            absent,
            expected_authorized_plan_digest=compiled["plan_digest"],
            executor_authority_evidence=evidence,
            expected_executor_authority_phase="POLICY_FACTORY",
            expected_caller_arn_digest=caller_digest,
            expected_executor_authority_evidence_digest=evidence[
                "evidence_digest"
            ],
            authority_evaluation_at=AUTHORITY_EVALUATION,
        )
    stale_self_digest = copy.deepcopy(compiled)
    stale_self_digest["authorization_phases"][0]["operations"][0]["request"] = {
        "attacker": "mutated-with-old-self-digest"
    }
    with pytest.raises(
        materializer.ServiceRoleMaterializationError,
        match="AUTHORIZED_PLAN_DIGEST_MISMATCH",
    ):
        materializer.classify_preexisting_inventory(
            stale_self_digest,
            absent,
            expected_authorized_plan_digest=compiled["plan_digest"],
            executor_authority_evidence=evidence,
            expected_executor_authority_phase="POLICY_FACTORY",
            expected_caller_arn_digest=caller_digest,
            expected_executor_authority_evidence_digest=evidence[
                "evidence_digest"
            ],
            authority_evaluation_at=AUTHORITY_EVALUATION,
        )
    exact = materializer.classify_preexisting_inventory(compiled, expected)
    assert exact["classification"] == "PREEXISTING_NO_TOUCH"
    assert exact["writes_permitted_by_state"] is False
    # Equal naked digests are no longer an acceptable causal proof.  The
    # classifier requires a separately root-bound, fully consumed phase ledger.
    with pytest.raises(TypeError):
        materializer.classify_preexisting_inventory(
            compiled,
            expected,
            causal_ledger_digest="sha256:" + "b" * 64,
            expected_causal_ledger_digest="sha256:" + "b" * 64,
        )

    (
        causal_records,
        causal_bindings,
        causal_authority,
        bundle_digest,
        initial_absence_digest,
        factory_receipt,
    ) = _complete_causal_bundle(compiled)
    certified = materializer.classify_preexisting_inventory(
        compiled,
        expected,
        expected_authorized_plan_digest=compiled["plan_digest"],
        causal_phase_records=causal_records,
        expected_causal_phase_bindings=causal_bindings,
        expected_causal_ledger_bundle_digest=bundle_digest,
        causal_phase_authority_evidence=causal_authority,
        causal_phase_authority_evaluation_at=[
            datetime.fromisoformat(
                record["authority_evaluation_at"].replace("Z", "+00:00")
            )
            for record in causal_records
        ],
        expected_initial_bundle_absence_digest=initial_absence_digest,
        ledger_factory_causal_receipt=factory_receipt,
        expected_ledger_factory_causal_receipt_digest=factory_receipt[
            "receipt_sha256"
        ],
    )
    assert certified["classification"] == "EXACT_PRESENT_NO_TOUCH"
    assert certified["causal_ledger_bound"] is True
    causal_evaluation = [
        datetime.fromisoformat(
            record["authority_evaluation_at"].replace("Z", "+00:00")
        )
        for record in causal_records
    ]
    causal_kwargs: dict[str, Any] = {
        "expected_authorized_plan_digest": compiled["plan_digest"],
        "causal_phase_records": causal_records,
        "expected_causal_phase_bindings": causal_bindings,
        "expected_causal_ledger_bundle_digest": bundle_digest,
        "causal_phase_authority_evidence": causal_authority,
        "causal_phase_authority_evaluation_at": causal_evaluation,
        "expected_initial_bundle_absence_digest": initial_absence_digest,
        "ledger_factory_causal_receipt": factory_receipt,
        "expected_ledger_factory_causal_receipt_digest": factory_receipt[
            "receipt_sha256"
        ],
    }
    authority_negative: list[dict[str, Any]] = []
    missing_authority = dict(causal_kwargs)
    missing_authority["causal_phase_authority_evidence"] = causal_authority[:-1]
    authority_negative.append(missing_authority)
    swapped_authority = dict(causal_kwargs)
    swapped_authority["causal_phase_authority_evidence"] = [
        causal_authority[1],
        causal_authority[0],
        *causal_authority[2:],
    ]
    authority_negative.append(swapped_authority)
    additive = copy.deepcopy(causal_authority)
    additive[0]["additional_attached_policy_count"] = 1
    additive[0]["evidence_digest"] = materializer.canonical_digest(
        {
            key: value
            for key, value in additive[0].items()
            if key != "evidence_digest"
        }
    )
    additive_authority = dict(causal_kwargs)
    additive_authority["causal_phase_authority_evidence"] = additive
    authority_negative.append(additive_authority)
    stale_evaluation = dict(causal_kwargs)
    stale_evaluation["causal_phase_authority_evaluation_at"] = [
        *causal_evaluation[:-1],
        causal_evaluation[-1] + timedelta(minutes=20),
    ]
    authority_negative.append(stale_evaluation)
    wrong_absence = dict(causal_kwargs)
    wrong_absence["expected_initial_bundle_absence_digest"] = (
        "sha256:" + "0" * 64
    )
    authority_negative.append(wrong_absence)
    for candidate in authority_negative:
        with pytest.raises(materializer.ServiceRoleMaterializationError):
            materializer.classify_preexisting_inventory(
                compiled, expected, **candidate
            )

    for field, unsafe in (
        ("status", "ALREADY_EXACT"),
        ("create_table_call_count", 0),
        ("update_pitr_call_count", 0),
    ):
        bad_receipt = copy.deepcopy(factory_receipt)
        bad_receipt[field] = unsafe
        bad_receipt["receipt_sha256"] = materializer.canonical_digest(
            {
                key: value
                for key, value in bad_receipt.items()
                if key != "receipt_sha256"
            }
        )
        candidate = dict(causal_kwargs)
        candidate["ledger_factory_causal_receipt"] = bad_receipt
        candidate["expected_ledger_factory_causal_receipt_digest"] = bad_receipt[
            "receipt_sha256"
        ]
        with pytest.raises(materializer.ServiceRoleMaterializationError):
            materializer.classify_preexisting_inventory(
                compiled, expected, **candidate
            )

    for later_phase in compiled["authorization_phases"][1:]:
        later_evidence = _authority_evidence(
            compiled, later_phase["phase"], caller_digest=caller_digest
        )
        blocked = materializer.classify_preexisting_inventory(
            compiled,
            absent,
            expected_authorized_plan_digest=compiled["plan_digest"],
            executor_authority_evidence=later_evidence,
            expected_executor_authority_phase=later_phase["phase"],
            expected_caller_arn_digest=caller_digest,
            expected_executor_authority_evidence_digest=later_evidence[
                "evidence_digest"
            ],
            authority_evaluation_at=AUTHORITY_EVALUATION,
        )
        assert blocked["classification"] == "NOT_AUTHORIZED"
        assert blocked["writes_authorized"] is False
        assert blocked["reason_code"] == "PHASE_PRECONDITION_MISSING"
    with pytest.raises(materializer.ServiceRoleMaterializationError):
        materializer.classify_preexisting_inventory(
            compiled,
            expected,
            expected_authorized_plan_digest=compiled["plan_digest"],
            causal_phase_records=causal_records[-1:],
            expected_causal_phase_bindings=causal_bindings[-1:],
            expected_causal_ledger_bundle_digest=bundle_digest,
            causal_phase_authority_evidence=causal_authority[-1:],
            causal_phase_authority_evaluation_at=[
                datetime.fromisoformat(
                    causal_records[-1]["authority_evaluation_at"].replace(
                        "Z", "+00:00"
                    )
                )
            ],
            expected_initial_bundle_absence_digest=initial_absence_digest,
            ledger_factory_causal_receipt=factory_receipt,
            expected_ledger_factory_causal_receipt_digest=factory_receipt[
                "receipt_sha256"
            ],
        )
    partial = copy.deepcopy(absent)
    arn = next(iter(expected["policies"]))
    partial["policies"][arn] = expected["policies"][arn]
    assert materializer.classify_preexisting_inventory(compiled, partial)["classification"] == "DRIFT_BLOCKED_NO_REPAIR"
    drift = copy.deepcopy(expected)
    role_arn = next(iter(drift["roles"]))
    drift["roles"][role_arn]["trust_policy"] = {"Version": "2012-10-17", "Statement": []}
    assert materializer.classify_preexisting_inventory(compiled, drift)["classification"] == "DRIFT_BLOCKED_NO_REPAIR"
    forged = copy.deepcopy(evidence)
    forged["additional_attached_policy_count"] = 1
    forged["evidence_digest"] = materializer.canonical_digest(
        {key: value for key, value in forged.items() if key != "evidence_digest"}
    )
    with pytest.raises(materializer.ServiceRoleMaterializationError):
        materializer.classify_preexisting_inventory(
            compiled,
            absent,
            expected_authorized_plan_digest=compiled["plan_digest"],
            executor_authority_evidence=forged,
            expected_executor_authority_phase="POLICY_FACTORY",
            expected_caller_arn_digest=caller_digest,
            expected_executor_authority_evidence_digest=forged["evidence_digest"],
            authority_evaluation_at=AUTHORITY_EVALUATION,
        )


@pytest.mark.parametrize(
    "record_field",
    [
        "authority_session_issued_at",
        "authority_session_expires_at",
        "authority_evidence_collected_at",
    ],
)
def test_classifier_rejects_ledger_authority_times_not_in_validated_evidence(
    compiled: Mapping[str, Any], record_field: str
) -> None:
    expected = materializer.expected_normalized_inventory(compiled)
    (
        records,
        bindings,
        authority,
        bundle_digest,
        absence_digest,
        factory_receipt,
    ) = _complete_causal_bundle(compiled)
    forged_records = copy.deepcopy(records)
    forged_bindings = copy.deepcopy(bindings)
    original = datetime.fromisoformat(
        forged_records[0][record_field].replace("Z", "+00:00")
    )
    forged_value = (original + timedelta(seconds=1)).isoformat().replace(
        "+00:00", "Z"
    )
    forged_records[0][record_field] = forged_value
    forged_bindings[0][record_field] = forged_value

    with pytest.raises(
        materializer.ServiceRoleMaterializationError,
        match="CAUSAL_PHASE_AUTHORITY_BINDING_INVALID",
    ):
        materializer.classify_preexisting_inventory(
            compiled,
            expected,
            expected_authorized_plan_digest=compiled["plan_digest"],
            causal_phase_records=forged_records,
            expected_causal_phase_bindings=forged_bindings,
            expected_causal_ledger_bundle_digest=bundle_digest,
            causal_phase_authority_evidence=authority,
            causal_phase_authority_evaluation_at=[
                datetime.fromisoformat(
                    record["authority_evaluation_at"].replace("Z", "+00:00")
                )
                for record in records
            ],
            expected_initial_bundle_absence_digest=absence_digest,
            ledger_factory_causal_receipt=factory_receipt,
            expected_ledger_factory_causal_receipt_digest=factory_receipt[
                "receipt_sha256"
            ],
        )


def test_classifier_canonical_snapshot_prevents_authority_and_inventory_toctou(
    compiled: Mapping[str, Any],
) -> None:
    expected = materializer.expected_normalized_inventory(compiled)
    absent = {
        "policies": {arn: None for arn in expected["policies"]},
        "roles": {arn: None for arn in expected["roles"]},
        "ledger_table": None,
        "broker_function": None,
        "ledger_factory_function": None,
        "ledger_factory_log_group": None,
    }
    caller_digest = "sha256:" + "a" * 64
    evidence = _authority_evidence(
        compiled, "POLICY_FACTORY", caller_digest=caller_digest
    )

    class MutatingPlan(dict[str, Any]):
        def items(self) -> Any:
            snapshot = copy.deepcopy(list(super().items()))
            self["authorization_phases"][0]["operations"][0]["request"] = {
                "attacker": "post-snapshot"
            }
            return iter(snapshot)

    moving_plan = MutatingPlan(copy.deepcopy(compiled))
    ready = materializer.classify_preexisting_inventory(
        moving_plan,
        absent,
        expected_authorized_plan_digest=compiled["plan_digest"],
        executor_authority_evidence=evidence,
        expected_executor_authority_phase="POLICY_FACTORY",
        expected_caller_arn_digest=caller_digest,
        expected_executor_authority_evidence_digest=evidence["evidence_digest"],
        authority_evaluation_at=AUTHORITY_EVALUATION,
    )
    assert ready["classification"] == "ABSENT_READY"
    assert moving_plan["authorization_phases"][0]["operations"][0]["request"] == {
        "attacker": "post-snapshot"
    }

    class MutatingObserved(dict[str, Any]):
        def items(self) -> Any:
            snapshot = copy.deepcopy(list(super().items()))
            self["ledger_table"] = None
            self["broker_function"] = None
            return iter(snapshot)

    moving_observed = MutatingObserved(copy.deepcopy(expected))
    exact = materializer.classify_preexisting_inventory(compiled, moving_observed)
    assert exact["classification"] == "PREEXISTING_NO_TOUCH"
    assert moving_observed["ledger_table"] is None
    assert moving_observed["broker_function"] is None


def test_tampering_altered_source_or_scope_is_rejected(
    bundle: Mapping[str, Any], compiled: Mapping[str, Any]
) -> None:
    with pytest.raises(materializer.ServiceRoleMaterializationError, match="GUG363_PLAN_DIGEST_MISMATCH"):
        materializer.compile_service_role_materialization_plan(
            gug363_plan=bundle["plan"], expected_gug363_plan_digest="sha256:" + "f" * 64,
            **_factory_kwargs(bundle),
            repo_root=bundle["repo"],
        )
    altered = copy.deepcopy(compiled)
    altered["planned_iam_writes"][-1]["retry_permitted"] = True
    altered["planned_iam_write_digest"] = materializer.canonical_digest(altered["planned_iam_writes"])
    _reseal(altered)
    with pytest.raises(materializer.ServiceRoleMaterializationError, match="PLANNED_IAM_WRITES_INVALID"):
        materializer.validate_service_role_materialization_plan(
            altered, gug363_plan=bundle["plan"],
            expected_gug363_plan_digest=bundle["plan"]["plan_digest"],
            **_factory_kwargs(bundle), repo_root=bundle["repo"],
        )
    incomplete_tags = copy.deepcopy(compiled)
    tag_readback = next(
        item
        for item in incomplete_tags["planned_readbacks"]
        if item["service"] == "dynamodb"
        and item["api_action"] == "ListTagsOfResource"
    )
    tag_readback["complete_pagination_required"] = False
    incomplete_tags["planned_readback_digest"] = materializer.canonical_digest(
        incomplete_tags["planned_readbacks"]
    )
    _reseal(incomplete_tags)
    with pytest.raises(
        materializer.ServiceRoleMaterializationError,
        match="PLANNED_READBACKS_INVALID",
    ):
        materializer.validate_service_role_materialization_plan(
            incomplete_tags,
            gug363_plan=bundle["plan"],
            expected_gug363_plan_digest=bundle["plan"]["plan_digest"],
            **_factory_kwargs(bundle),
            repo_root=bundle["repo"],
        )
    scoped = copy.deepcopy(bundle["plan"])
    scoped["target"]["region"] = "us-west-2"
    _reseal(scoped)
    with pytest.raises(materializer.ServiceRoleMaterializationError, match="GUG363_PLAN_INVALID"):
        materializer.compile_service_role_materialization_plan(
            gug363_plan=scoped, expected_gug363_plan_digest=scoped["plan_digest"],
            **_factory_kwargs(bundle), repo_root=bundle["repo"]
        )


@pytest.mark.parametrize(
    ("action", "code"),
    [("lambda:*", "BOUNDARY_ALLOW_ACTION_WILDCARD"), ("iam:CreateUser", "BOUNDARY_ALLOW_ACTION_OUT_OF_SCOPE")],
)
def test_wildcard_or_dangerous_boundary_action_is_rejected(action: str, code: str) -> None:
    document = {
        "Version": "2012-10-17",
        "Statement": [{"Sid": "Bad", "Effect": "Allow", "Action": action, "Resource": materializer._role_arn(materializer.BROKER_ROLE_NAME)}],  # noqa: SLF001
    }
    with pytest.raises(materializer.ServiceRoleMaterializationError, match=code):
        materializer._validate_document_shape(  # noqa: SLF001
            "classifier_invoker", document,
            exact_arns=(f"arn:aws:iam::{materializer.AUTHORITY_ACCOUNT_ID}:",),
        )


def test_working_policy_bytes_must_equal_head(bundle: Mapping[str, Any]) -> None:
    path = bundle["repo"] / materializer.CLASSIFIER_BOUNDARY_PATH
    original = path.read_bytes()
    try:
        path.write_bytes(original + b"\n")
        with pytest.raises(materializer.ServiceRoleMaterializationError, match="POLICY_TEMPLATE_COMMIT_DRIFT"):
            materializer._read_template(  # noqa: SLF001
                repo_root=bundle["repo"], path=materializer.CLASSIFIER_BOUNDARY_PATH,
                replacements={"classifier_function_arn": "arn:aws:lambda:us-east-1:042360977644:function:fixed"},
            )
    finally:
        path.write_bytes(original)


@pytest.mark.parametrize(
    ("phase", "path", "variant", "code"),
    [
        (
            "POLICY_FACTORY",
            materializer.POLICY_FACTORY_POLICY_PATH,
            "remove_dependent_tag_policy",
            "PROVISIONING_EXECUTOR_AUTHORITY_INVALID",
        ),
        (
            "FOUNDATION_FACTORY",
            materializer.FOUNDATION_FACTORY_POLICY_PATH,
            "remove_dependent_tag_role",
            "PROVISIONING_EXECUTOR_AUTHORITY_INVALID",
        ),
        (
            "ACTIVATOR",
            materializer.ACTIVATOR_POLICY_PATH,
            "remove_attach_condition",
            "PROVISIONING_EXECUTOR_ACTIVATOR_CONDITION_INVALID",
        ),
        (
            "ACTIVATOR",
            materializer.ACTIVATOR_POLICY_PATH,
            "widen_attach_role_arn",
            "PROVISIONING_EXECUTOR_RESOURCE_OUT_OF_SCOPE",
        ),
        (
            "LEDGER_FACTORY_FUNCTION_FACTORY",
            materializer.LEDGER_FACTORY_FUNCTION_FACTORY_POLICY_PATH,
            "remove_factory_version_resource",
            "BOUNDARY_TEMPLATE_PLACEHOLDER_INVALID",
        ),
    ],
)
def test_committed_authority_weakening_is_rejected(
    tmp_path: Path,
    bundle: Mapping[str, Any],
    compiled: Mapping[str, Any],
    phase: str,
    path: Path,
    variant: str,
    code: str,
) -> None:
    root = tmp_path / "authority-repo"
    root.mkdir()
    for relative in _repository_files():
        target = root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(REPO_ROOT / relative, target)
    _git(root, "init", "-q")
    _git(root, "config", "user.email", "synthetic@example.invalid")
    _git(root, "config", "user.name", "Synthetic Test")
    _git(root, "add", "--", *[item.as_posix() for item in _repository_files()])
    _git(root, "commit", "-q", "-m", "baseline authorities")

    document = json.loads((root / path).read_text(encoding="utf-8"))
    statements = document["Statement"]
    if variant == "remove_dependent_tag_policy":
        statement = next(item for item in statements if item["Sid"] == "CreateExactBoundaryPolicies")
        statement["Action"] = "iam:CreatePolicy"
    elif variant == "remove_dependent_tag_role":
        statement = next(item for item in statements if item["Sid"] == "CreateExactRolesUnderProofBoundary")
        statement["Action"] = "iam:CreateRole"
    elif variant == "group_resource_policy_under_create_tags":
        create = next(item for item in statements if item["Sid"] == "CreateExactEmptyLedger")
        create["Action"] = ["dynamodb:CreateTable", "dynamodb:PutResourcePolicy"]
        statements[:] = [
            item for item in statements if item["Sid"] != "PermitOnlyCreateTableInlineResourcePolicy"
        ]
    elif variant == "remove_scan_condition":
        next(item for item in statements if item["Sid"] == "CountOnlyExactCreatedLedger").pop("Condition")
    elif variant == "remove_ledger_self_escalation_cap":
        statements[:] = [
            item
            for item in statements
            if item.get("Sid")
            != "DenyLedgerSelfEscalationOutsideFoundationContract"
        ]
    elif variant == "remove_attach_condition":
        next(item for item in statements if item["Sid"] == "AttachBroker").pop("Condition")
    elif variant == "widen_attach_role_arn":
        next(item for item in statements if item["Sid"] == "AttachBroker")["Resource"] = "*"
    elif variant == "remove_factory_version_resource":
        statement = next(
            item
            for item in statements
            if "lambda:PutRuntimeManagementConfig"
            in (
                [item["Action"]]
                if isinstance(item.get("Action"), str)
                else item.get("Action", [])
            )
        )
        statement["Resource"] = [
            resource
            for resource in statement["Resource"]
            if resource != "${ledger_factory_function_version_arn}"
        ]
    else:  # pragma: no cover - parameter table is exhaustive
        raise AssertionError(variant)
    (root / path).write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
    _git(root, "add", "--", path.as_posix())
    _git(root, "commit", "-q", "-m", f"malicious {variant}")

    with pytest.raises(materializer.ServiceRoleMaterializationError, match=code):
        materializer._render_executor_policy(  # noqa: SLF001
            phase=phase,
            gug363_plan=bundle["plan"],
            repo_root=root,
            boundaries=compiled["boundaries"],
            factory_function=compiled["ledger_factory_function"],
        )


def test_untracked_source_and_head_mismatch_block_compilation(
    tmp_path: Path, bundle: Mapping[str, Any]
) -> None:
    untracked = bundle["repo"] / "untracked-policy.json"
    try:
        untracked.write_text("{}\n", encoding="utf-8")
        with pytest.raises(materializer.ServiceRoleMaterializationError, match="GUG363_PLAN_INVALID"):
            materializer.compile_service_role_materialization_plan(
                gug363_plan=bundle["plan"],
                expected_gug363_plan_digest=bundle["plan"]["plan_digest"],
                **_factory_kwargs(bundle),
                repo_root=bundle["repo"],
            )
    finally:
        untracked.unlink(missing_ok=True)

    copied = tmp_path / "head-mismatch"
    shutil.copytree(bundle["repo"], copied)
    extra = copied / "tracked-extra.txt"
    extra.write_text("new HEAD\n", encoding="utf-8")
    _git(copied, "add", "--", extra.name)
    _git(copied, "commit", "-q", "-m", "advance HEAD")
    with pytest.raises(materializer.ServiceRoleMaterializationError, match="GUG363_PLAN_INVALID"):
        materializer.compile_service_role_materialization_plan(
            gug363_plan=bundle["plan"],
            expected_gug363_plan_digest=bundle["plan"]["plan_digest"],
            **_factory_kwargs(bundle),
            repo_root=copied,
        )
