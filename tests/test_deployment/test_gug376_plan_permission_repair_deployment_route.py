from __future__ import annotations

import base64
import copy
from datetime import datetime, timedelta, timezone
from hashlib import sha256
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace
from typing import Any, Mapping

import pytest

from tooling import platform_authority_plan_permission_repair_deployment_route as route
from tooling import platform_authority_plan_permission_repair_deployment_route_aws as aws
from tooling import platform_authority_plan_permission_repair_deployment_recovery as recovery
from tooling import platform_authority_plan_permission_repair_broker_seed as broker_seed
from tooling import platform_authority_plan_permission_repair_route_broker as broker
from tests.test_deployment.test_gug376_plan_permission_repair_broker_seed import (
    _input as _broker_seed_private_input,
)
from tests.test_deployment.test_gug376_plan_permission_repair_route_broker import (
    _config_value as _broker_config_value,
)
from tests.test_deployment.gug376_foundation_fixtures import (
    build_foundation_contract,
    build_pep_signed_receipt,
    build_route_release,
    build_template_readback,
)


ROOT = Path(__file__).resolve().parents[2]
OFFLINE_CLI = ROOT / "scripts/deployment/platform-authority-plan-permission-repair-deployment-route.py"
AWS_CLI = ROOT / "scripts/deployment/platform-authority-plan-permission-repair-deployment-route-aws.py"
SOURCE_COMMIT = "a" * 40
INSTANCE_ARN = "arn:aws:sso:::instance/ssoins-ABCDEFGHIJKLMNOP"
PRINCIPAL_ID = "12345678-1234-4123-8123-123456789012"
STACK_UUID = "22222222-2222-4222-8222-222222222222"
CHANGE_UUID = "11111111-1111-4111-8111-111111111111"
REQUEST_UUID = "33333333-3333-4333-8333-333333333333"
EVENT_UUID = "44444444-4444-4444-8444-444444444444"
BROKER_STACK_ARN = (
    "arn:aws:cloudformation:us-east-1:042360977644:stack/"
    f"{route.BROKER_STACK_NAME}/{STACK_UUID}"
)


def _digest(payload: bytes) -> str:
    return "sha256:" + sha256(payload).hexdigest()


def _ts(value: datetime) -> str:
    return (
        value.astimezone(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def _observed_change_set_parameters(
    request: Mapping[str, Any], *, target: str
) -> list[dict[str, Any]]:
    return [
        {
            "ParameterKey": item["ParameterKey"],
            "ParameterValue": (
                "*****"
                if target == "route"
                and item["ParameterKey"] in route.ROUTE_NO_ECHO_PARAMETER_KEYS
                else item["ParameterValue"]
            ),
        }
        for item in request.get("Parameters", [])
    ]


class FakeGit:
    def __init__(self, *, status: str = "", branch: str = "main") -> None:
        self._status = status
        self._branch = branch

    def root(self) -> Path:
        return ROOT.resolve()

    def branch(self) -> str:
        return self._branch

    def head(self) -> str:
        return SOURCE_COMMIT

    def origin_main(self) -> str:
        return SOURCE_COMMIT

    def status(self) -> str:
        return self._status

    def read_at(self, commit: str, path: str) -> bytes:
        assert commit == SOURCE_COMMIT
        return (ROOT / path).read_bytes()

    def render_broker_seed(
        self, private_input: Mapping[str, Any], *, protection_enabled: bool
    ) -> bytes:
        return broker_seed.render_template_from_source(
            source=(ROOT / broker_seed.SOURCE_TEMPLATE_PATH).read_bytes(),
            private_input=private_input,
            protection_enabled=protection_enabled,
        )


def _broker_receipt(now: datetime) -> dict[str, Any]:
    unsigned = b"unsigned-route-broker-package"
    signed = b"signed-route-broker-package"
    profile = (
        "arn:aws:signer:us-east-1:042360977644:/signing-profiles/"
        "ScanalyzeGug376/ABCDEFGHIJ"
    )
    job_id = "55555555-5555-4555-8555-555555555555"
    job_arn = (
        "arn:aws:signer:us-east-1:042360977644:/signing-jobs/" + job_id
    )
    kms_key_arn = (
        "arn:aws:kms:us-east-1:042360977644:key/"
        "00000000-0000-4000-8000-000000000001"
    )
    storage_binding = {
        "schema_version": 1,
        "record_type": (
            "scanalyze.platform_authority."
            "plan_permission_repair_gug365_template_storage_binding.v1"
        ),
        "gug363_plan_digest": "sha256:" + "1" * 64,
        "gug363_artifact_signing_contract_digest": "sha256:" + "2" * 64,
        "gug365_plan_digest": "sha256:" + "3" * 64,
        "gug365_ledger_factory_artifact_signing_contract_digest": (
            "sha256:" + "4" * 64
        ),
        "gug365_signed_artifact_binding_digest": "sha256:" + "5" * 64,
        "bucket": "scanalyze-gug376-artifacts",
        "sse_algorithm": "aws:kms",
        "sse_kms_key_arn": kms_key_arn,
        "source_marker": "VALIDATED_GUG363_AND_GUG365_CAUSAL_PLANS",
    }
    storage_binding["binding_digest"] = route.digest_value(storage_binding)
    value: dict[str, Any] = {
        "schema_version": 1,
        "record_type": (
            "scanalyze.platform_authority."
            "plan_permission_repair_broker_signed_artifact_receipt.v1"
        ),
        "source_commit": SOURCE_COMMIT,
        "verifier": {
            "account_id": route.AUTHORITY_ACCOUNT_ID,
            "caller_arn": (
                "arn:aws:sts::042360977644:assumed-role/"
                "AWSReservedSSO_AWSReadOnlyAccess_0123456789ABCDEF/cesar"
            ),
            "profile": "042360977644_AWSReadOnlyAccess",
            "region": route.REGION,
        },
        "unsigned_artifact": {
            "bucket": "scanalyze-gug376-artifacts",
            "key": (
                "scanalyze/platform-authority/gug-376/plan-policy-repair/"
                f"broker/unsigned/{SOURCE_COMMIT}/route-broker-unsigned.zip"
            ),
            "version": "unsigned-version-1",
            "sha256": _digest(unsigned),
            "code_sha256": base64.b64encode(sha256(unsigned).digest()).decode(),
            "bytes": len(unsigned),
            "sse_algorithm": "aws:kms",
            "sse_kms_key_arn": kms_key_arn,
        },
        "signing_job": {
            "job_id": job_id,
            "job_owner": broker_seed.AUTHORITY_ACCOUNT_ID,
            "job_invoker": broker_seed.AUTHORITY_ACCOUNT_ID,
            "status": "Succeeded",
            "platform_id": "AWSLambda-SHA384-ECDSA",
            "profile_version_arn": profile,
            "created_at": _ts(now - timedelta(minutes=5)),
            "completed_at": _ts(now - timedelta(minutes=2)),
            "signature_expires_at": _ts(now + timedelta(days=7)),
            "profile_status": "Active",
            "job_revocation_record_absent": True,
            "profile_revocation_record_absent": True,
        },
        "signed_artifact": {
            "bucket": "scanalyze-gug376-artifacts",
            "key": (
                "scanalyze/platform-authority/gug-376/plan-policy-repair/"
                f"broker/signed/{SOURCE_COMMIT}/{job_id}.zip"
            ),
            "version": "signed-version-1",
            "sha256": _digest(signed),
            "code_sha256": base64.b64encode(sha256(signed).digest()).decode(),
            "bytes": len(signed),
            "sse_algorithm": "aws:kms",
            "sse_kms_key_arn": kms_key_arn,
        },
        "upstream_storage_binding": storage_binding,
        "revocation_check": {
            "status": "JOB_AND_PROFILE_REVOCATION_RECORDS_ABSENT",
            "checked_at": _ts(now),
            "profile_version_arn_digest": route.digest_value(profile),
            "job_arn_digest": route.digest_value(job_arn),
            "source_marker": "DESCRIBE_SIGNING_JOB_AND_GET_SIGNING_PROFILE",
        },
        "observed_at": _ts(now),
        "source_marker": "AWS_STS_S3_SIGNER_PROFILE_AND_VERSIONED_OBJECT_READBACK",
        "aws_calls": 9,
        "aws_mutations": 0,
    }
    value["receipt_digest"] = route.digest_value(value)
    return value


def _materialization_receipt(
    *,
    now: datetime,
    rendered: bytes,
    signing: Mapping[str, Any],
    pep_runtime_binding_digest: str,
    protection_enabled: bool = False,
) -> dict[str, Any]:
    del now
    artifact_digest = _digest(rendered)
    projection = broker_seed.derive_effective_policy_projection(
        rendered_template=rendered,
        source_commit=SOURCE_COMMIT,
    )
    value = {
        "record_type": (
            "scanalyze.platform_authority.plan_permission_repair_"
            "broker_seed_receipt.v1"
        ),
        "schema_version": 1,
        "source_commit": SOURCE_COMMIT,
        "template_variant": (
            "protection" if protection_enabled else "create"
        ),
        "output_name": (
            "cfn-platform-authority-gug376-route-broker-protection.yaml"
            if protection_enabled
            else "cfn-platform-authority-gug376-route-broker.yaml"
        ),
        "template_sha256": artifact_digest,
        "template_bytes": len(rendered),
        "unsigned_package_sha256": signing["unsigned_artifact"]["sha256"],
        "signed_package_sha256": signing["signed_artifact"]["sha256"],
        "signed_package_code_sha256": signing["signed_artifact"]["code_sha256"],
        "signing_receipt_digest": signing["receipt_digest"],
        "pep_runtime_binding_digest": pep_runtime_binding_digest,
        "foundation_publish_binding_digest": signing[
            "upstream_storage_binding"
        ]["binding_digest"],
        "effective_policy_projection": projection,
        "effective_policy_projection_digest": projection["projection_digest"],
        "parameters_section_absent": True,
        "private_mode": "0600",
        "aws_calls": 0,
        "aws_mutations": 0,
        "deployment_authorized": False,
        "production_status": "NO-GO",
    }
    return route.seal(value, "receipt_digest")


def _template_receipt(
    name: str,
    *,
    now: datetime,
    source_path: str,
    artifact_payload: bytes,
    materialization: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    source_payload = (ROOT / source_path).read_bytes()
    filename = {
        "route_template": "cfn-platform-authority-gug376-temporary-change-set-route.yaml",
        "delegation_template": "cfn-platform-authority-bootstrap-plan-repair-delegation.yaml",
        "broker_template": "cfn-platform-authority-gug376-route-broker.yaml",
        "broker_protection_template": (
            "cfn-platform-authority-gug376-route-broker-protection.yaml"
        ),
    }[name]
    scope = (
        "private"
        if name in {"broker_template", "broker_protection_template"}
        else "templates"
    )
    bucket = "scanalyze-gug376-templates"
    key = (
        f"scanalyze/platform-authority/gug-376/plan-policy-repair/{scope}/"
        f"{SOURCE_COMMIT}/{filename}"
    )
    version = f"{name}-version-1"
    storage_binding = route.seal(
        {
            "schema_version": 1,
            "record_type": (
                "scanalyze.platform_authority."
                "plan_permission_repair_gug365_template_storage_binding.v1"
            ),
            "gug363_plan_digest": "sha256:" + "1" * 64,
            "gug363_artifact_signing_contract_digest": "sha256:" + "2" * 64,
            "gug365_plan_digest": "sha256:" + "3" * 64,
            "gug365_ledger_factory_artifact_signing_contract_digest": (
                "sha256:" + "4" * 64
            ),
            "gug365_signed_artifact_binding_digest": "sha256:" + "5" * 64,
            "bucket": bucket,
            "sse_algorithm": "aws:kms",
            "sse_kms_key_arn": (
                "arn:aws:kms:us-east-1:042360977644:key/"
                "00000000-0000-4000-8000-000000000001"
            ),
            "source_marker": "VALIDATED_GUG363_AND_GUG365_CAUSAL_PLANS",
        },
        "binding_digest",
    )
    value = {
        "schema_version": 1,
        "record_type": (
            "scanalyze.platform_authority."
            "plan_permission_repair_template_readback.v1"
        ),
        "source_commit": SOURCE_COMMIT,
        "source_path": source_path,
        "source_sha256": _digest(source_payload),
        "bucket": bucket,
        "key": key,
        "version": version,
        "template_url": (
            f"https://{bucket}.s3.us-east-1.amazonaws.com/{key}?versionId={version}"
        ),
        "artifact_sha256": _digest(artifact_payload),
        "content_length": len(artifact_payload),
        "sse_algorithm": "aws:kms",
        "sse_kms_key_arn": storage_binding["sse_kms_key_arn"],
        "upstream_storage_binding": storage_binding,
        "materialization_receipt": materialization,
        "verifier": {
            "account_id": route.AUTHORITY_ACCOUNT_ID,
            "caller_arn": (
                "arn:aws:sts::042360977644:assumed-role/"
                "AWSReservedSSO_AWSReadOnlyAccess_0123456789ABCDEF/cesar"
            ),
            "profile": "042360977644_AWSReadOnlyAccess",
            "region": route.REGION,
        },
        "observed_at": _ts(now),
        "source_marker": "AWS_STS_S3_VERSIONED_OBJECT_READBACK",
        "aws_calls": 4,
        "aws_mutations": 0,
    }
    return route.seal(value, "receipt_digest")


@pytest.fixture
def case() -> tuple[dict[str, Any], dict[str, Any], datetime]:
    publication_time = datetime.now(timezone.utc).replace(microsecond=0)
    now = publication_time + timedelta(minutes=75)
    route_not_before = publication_time + timedelta(minutes=70)
    route_not_after = publication_time + timedelta(minutes=130)
    broker_input = _broker_seed_private_input(ROOT, SOURCE_COMMIT)
    broker_input["route_not_before"] = _ts(route_not_before)
    broker_input["route_not_after"] = _ts(route_not_after)
    config = dict(broker_input["broker_config"])
    config["route_not_before"] = broker_input["route_not_before"]
    config["route_not_after"] = broker_input["route_not_after"]
    config["recovery_not_after"] = _ts(route_not_after + timedelta(hours=24))
    config.pop("config_digest")
    broker_input["broker_config"] = broker.seal(config, "config_digest")
    signing = broker_input["broker_code"]
    rendered = FakeGit().render_broker_seed(
        broker_input, protection_enabled=False
    )
    protection_rendered = FakeGit().render_broker_seed(
        broker_input, protection_enabled=True
    )
    materialization = _materialization_receipt(
        now=now,
        rendered=rendered,
        signing=signing,
        pep_runtime_binding_digest=broker_input["pep_runtime_binding"][
            "binding_digest"
        ],
    )
    protection_materialization = _materialization_receipt(
        now=now,
        rendered=protection_rendered,
        signing=signing,
        pep_runtime_binding_digest=broker_input["pep_runtime_binding"][
            "binding_digest"
        ],
        protection_enabled=True,
    )
    binding_observed = datetime.fromisoformat(
        signing["observed_at"][:-1] + "+00:00"
    )
    foundation_contract = build_foundation_contract(
        source_commit=SOURCE_COMMIT,
        observed_at=binding_observed,
    )
    assert (
        foundation_contract["foundation_publish_binding"]
        == broker_input["foundation_publish_binding"]
    )
    pep_receipt = build_pep_signed_receipt(
        source_commit=SOURCE_COMMIT,
        observed_at=binding_observed,
        bootstrap_intent=foundation_contract["bootstrap_intent"],
        foundation_publish_binding=foundation_contract[
            "foundation_publish_binding"
        ],
    )
    template_readbacks = {
        "route_template": build_template_readback(
            artifact_kind="route_template",
            source_commit=SOURCE_COMMIT,
            observed_at=binding_observed,
            artifact_payload=(ROOT / route.ROUTE_TEMPLATE_PATH).read_bytes(),
            foundation_publish_binding=foundation_contract[
                "foundation_publish_binding"
            ],
        ),
        "delegation_template": build_template_readback(
            artifact_kind="delegation_template",
            source_commit=SOURCE_COMMIT,
            observed_at=binding_observed,
            artifact_payload=(ROOT / route.DELEGATION_TEMPLATE_PATH).read_bytes(),
            foundation_publish_binding=foundation_contract[
                "foundation_publish_binding"
            ],
        ),
        "pep_template": build_template_readback(
            artifact_kind="pep_template",
            source_commit=SOURCE_COMMIT,
            observed_at=binding_observed,
            artifact_payload=(
                ROOT
                / "bootstrap/cfn-platform-authority-bootstrap-plan-repair-pep.yaml"
            ).read_bytes(),
            foundation_publish_binding=foundation_contract[
                "foundation_publish_binding"
            ],
        ),
        "broker_template": build_template_readback(
            artifact_kind="broker_template",
            source_commit=SOURCE_COMMIT,
            observed_at=binding_observed,
            artifact_payload=rendered,
            foundation_publish_binding=foundation_contract[
                "foundation_publish_binding"
            ],
            materialization_receipt=materialization,
        ),
        "broker_protection_template": build_template_readback(
            artifact_kind="broker_protection_template",
            source_commit=SOURCE_COMMIT,
            observed_at=binding_observed,
            artifact_payload=protection_rendered,
            foundation_publish_binding=foundation_contract[
                "foundation_publish_binding"
            ],
            materialization_receipt=protection_materialization,
        ),
    }
    route_release = build_route_release(
        foundation_contract=foundation_contract,
        publication_observed_at=binding_observed,
        template_readbacks=template_readbacks,
        pep_signed_artifact_receipt=pep_receipt,
        broker_seed_input=broker_input,
        broker_seed_receipts={
            "broker_template": materialization,
            "broker_protection_template": protection_materialization,
        },
    )
    value = {
        "schema_version": 1,
        "record_type": route.RECORD_TYPE_INPUT,
        "source_commit": SOURCE_COMMIT,
        "management_account_id": route.MANAGEMENT_ACCOUNT_ID,
        "authority_account_id": route.AUTHORITY_ACCOUNT_ID,
        "region": route.REGION,
        "route_not_before": _ts(route_not_before),
        "route_not_after": _ts(route_not_after),
        "identity_center_instance_arn": INSTANCE_ARN,
        "bootstrap_principal_id": PRINCIPAL_ID,
        "artifact_bootstrap_intent": foundation_contract["bootstrap_intent"],
        "bootstrap_route_release": route_release,
        "artifacts": {
            "route_template": template_readbacks["route_template"],
            "delegation_template": template_readbacks["delegation_template"],
            "broker_template": template_readbacks["broker_template"],
            "broker_protection_template": template_readbacks[
                "broker_protection_template"
            ],
            "broker_code": signing,
        },
        "broker_seed_input": broker_input,
        "production_authorized": False,
    }
    value = route.seal(value, "input_digest")
    return value, route.materialize_seed_intent(value, git=FakeGit(), now=now), now


def test_materializes_exact_route_broker_and_broker_protection_operations(
    case: tuple[dict[str, Any], dict[str, Any], datetime]
) -> None:
    source, intent, _now = case
    assert route.validate_seed_intent_against_git(intent, git=FakeGit()) == intent
    assert set(intent["targets"]) == set(route.TARGETS)
    route_request = intent["targets"]["route"]["create_request"]
    broker_request = intent["targets"]["broker"]["create_request"]
    protection_request = intent["targets"][
        route.BROKER_PROTECTION_TARGET
    ]["create_request"]
    assert route_request["ChangeSetName"] == "gug376-temporary-route-create"
    assert broker_request["ChangeSetName"] == "gug376-route-broker-create"
    assert "Parameters" not in broker_request
    assert protection_request["ChangeSetName"] == (
        route.BROKER_PROTECTION_CHANGE_SET_NAME
    )
    assert protection_request["ChangeSetType"] == "UPDATE"
    assert "Parameters" not in protection_request
    assert protection_request["TemplateURL"] != broker_request["TemplateURL"]
    assert intent["targets"]["broker"]["template_digest"] == source[
        "artifacts"
    ]["broker_template"]["artifact_sha256"]
    assert intent["targets"][route.BROKER_PROTECTION_TARGET][
        "template_digest"
    ] == source["artifacts"]["broker_protection_template"]["artifact_sha256"]
    assert "OnStackFailure" not in protection_request
    assert broker_request["TemplateURL"].startswith("https://")
    assert "versionId=" in broker_request["TemplateURL"]
    assert "TemplateBody" not in broker_request
    assert "RoleARN" not in route_request and "RoleARN" not in broker_request
    assert "ResourcesToImport" not in route_request
    assert route_request["OnStackFailure"] == "DELETE"
    assert broker_request["OnStackFailure"] == "DELETE"
    parameters = {
        item["ParameterKey"]: item["ParameterValue"]
        for item in route_request["Parameters"]
    }
    assert set(parameters) == set(route.ROUTE_PARAMETER_KEYS)
    assert parameters["SeedAssignmentsEnabled"] == "true"
    assert parameters["BrokerInvokerAssignmentEnabled"] == "true"
    expected_recovery = _ts(
        datetime.fromisoformat(
            source["route_not_after"].replace("Z", "+00:00")
        )
        + timedelta(hours=24)
    )
    assert intent["recovery_not_after"] == expected_recovery
    assert parameters["RecoveryNotAfter"] == expected_recovery
    assert intent["cleanup_not_after"] == source[
        "bootstrap_route_release"
    ]["cleanup_not_after"]
    assert intent["recovery_not_after"] <= intent["cleanup_not_after"]
    assert parameters["ArtifactKmsKeyArn"] == source["artifacts"][
        "route_template"
    ]["sse_kms_key_arn"]
    assert source["broker_seed_input"]["broker_config"][
        "recovery_not_after"
    ] == expected_recovery
    assert parameters["BrokerCodeVersion"] == "broker-signed-version-1"
    assert parameters["BrokerSigningProfileVersionArn"] == source["artifacts"][
        "broker_code"
    ]["signing_job"]["profile_version_arn"]
    assert parameters["BrokerProtectionTemplateVersion"] == source[
        "artifacts"
    ]["broker_protection_template"]["version"]
    assert parameters["BrokerProtectionTemplateUrl"] == protection_request[
        "TemplateURL"
    ]
    assert intent["targets"]["route"]["expected_assignment_count"] == 3
    assert len(intent["targets"]["route"]["expected_resources"]) == 8
    assert intent["targets"]["broker"]["broker_code_sha256"] == source[
        "artifacts"
    ]["broker_code"]["signed_artifact"]["code_sha256"]
    assert intent["targets"][route.BROKER_PROTECTION_TARGET][
        "expected_changes"
    ] == sorted(
        [
            {"logical_resource_id": "BrokerLedgerKey", "resource_type": "AWS::KMS::Key"},
            {"logical_resource_id": "BrokerLedger", "resource_type": "AWS::DynamoDB::Table"},
            {"logical_resource_id": "CreatorLogGroup", "resource_type": "AWS::Logs::LogGroup"},
            {"logical_resource_id": "ExecutorLogGroup", "resource_type": "AWS::Logs::LogGroup"},
            {"logical_resource_id": "CreateDispatchRecoveryLogGroup", "resource_type": "AWS::Logs::LogGroup"},
            {"logical_resource_id": "ExecuteDispatchRecoveryLogGroup", "resource_type": "AWS::Logs::LogGroup"},
            {"logical_resource_id": "CreatorVersion", "resource_type": "AWS::Lambda::Version"},
            {"logical_resource_id": "ExecutorVersion", "resource_type": "AWS::Lambda::Version"},
            {"logical_resource_id": "CreateDispatchRecoveryVersion", "resource_type": "AWS::Lambda::Version"},
            {"logical_resource_id": "ExecuteDispatchRecoveryVersion", "resource_type": "AWS::Lambda::Version"},
        ],
        key=lambda item: item["logical_resource_id"],
    )
    encoded = route.canonical_json(intent)
    for forbidden in (PRINCIPAL_ID, INSTANCE_ARN, "broker-signed-version-1"):
        assert forbidden in encoded  # private intent, never stdout


def test_seed_intent_rejects_recovery_beyond_bootstrap_cleanup_horizon(
    case: tuple[dict[str, Any], dict[str, Any], datetime]
) -> None:
    _source, intent, _now = case
    changed = copy.deepcopy(intent)
    changed["cleanup_not_after"] = changed["route_not_after"]
    changed.pop("intent_digest")
    changed = route.seal(changed, "intent_digest")
    with pytest.raises(route.RouteSeedError, match="INTENT_INVALID"):
        route.validate_seed_intent(changed)


def test_versioned_template_url_accepts_reserved_version_id_only_when_encoded() -> None:
    artifact = {
        "bucket": "scanalyze-gug376-templates",
        "key": "scanalyze/platform-authority/gug-376/template.yaml",
        "version": "A+B/C==",
        "template_url": (
            "https://scanalyze-gug376-templates.s3.us-east-1.amazonaws.com/"
            "scanalyze/platform-authority/gug-376/template.yaml"
            "?versionId=A%2BB%2FC%3D%3D"
        ),
    }
    route._versioned_url(artifact)

    raw = copy.deepcopy(artifact)
    raw["template_url"] = raw["template_url"].replace(
        "A%2BB%2FC%3D%3D", "A+B/C=="
    )
    with pytest.raises(route.RouteSeedError, match="ARTIFACT_URL_INVALID"):
        route._versioned_url(raw)

    oversized = copy.deepcopy(artifact)
    oversized["template_url"] = "x" * (
        route.MAX_CLOUDFORMATION_TEMPLATE_URL_LENGTH + 1
    )
    with pytest.raises(route.RouteSeedError, match="ARTIFACT_URL_INVALID"):
        route._versioned_url(oversized)


def test_post_revoke_route_reconstructs_pre_revoke_signing_evidence_without_wall_clock(
    case: tuple[dict[str, Any], dict[str, Any], datetime],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source, expected, route_time = case
    receipt_time = datetime.fromisoformat(
        source["artifacts"]["broker_code"]["observed_at"].replace("Z", "+00:00")
    )
    release_time = datetime.fromisoformat(
        source["bootstrap_route_release"]["normal_route_not_before"].replace(
            "Z", "+00:00"
        )
    )
    assert (release_time - receipt_time).total_seconds() >= 65 * 60
    assert (route_time - receipt_time).total_seconds() > (
        broker_seed.MAX_SIGNING_RECEIPT_AGE_SECONDS
    )

    class RouteClock(datetime):
        @classmethod
        def now(cls, tz: timezone | None = None) -> datetime:
            return route_time if tz is None else route_time.astimezone(tz)

    monkeypatch.setattr(broker_seed, "datetime", RouteClock)
    assert route.materialize_seed_intent(
        source,
        git=FakeGit(),
        now=route_time,
    ) == expected


def test_route_validation_rejects_naive_clock(
    case: tuple[dict[str, Any], dict[str, Any], datetime]
) -> None:
    with pytest.raises(route.RouteSeedError, match="CLOCK_INVALID"):
        route.validate_input(
            case[0],
            git=FakeGit(),
            now=datetime(2026, 8, 30, 21, 0),
        )


def test_cloudformation_resolver_supports_strict_list_form_sub() -> None:
    value = {
        "Fn::Sub": [
            "${Creator}:create-v1,${Creator}:execute-v1@${AWS::Region}",
            {
                "Creator": {
                    "Fn::Sub": (
                        "arn:${AWS::Partition}:lambda:${AWS::Region}:"
                        "${AuthorityAccountId}:function:creator"
                    )
                }
            },
        ]
    }
    resolved = aws._resolve_cloudformation_value(
        value,
        parameters={
            "AWS::Partition": "aws",
            "AWS::Region": "us-east-1",
            "AuthorityAccountId": route.AUTHORITY_ACCOUNT_ID,
        },
    )
    creator = (
        "arn:aws:lambda:us-east-1:042360977644:function:creator"
    )
    assert resolved == f"{creator}:create-v1,{creator}:execute-v1@us-east-1"


@pytest.mark.parametrize(
    "raw",
    [
        ["${Creator}", {}],
        ["literal", {"Unused": "value"}],
        ["${Creator}", {"Creator": 1}],
        ["${AWS::Region}", {"AWS::Region": "eu-west-1"}],
        ["${Unknown}", {}],
        ["${Creator", {"Creator": "value"}],
        ["${Creator}", []],
        ["${Creator}"],
    ],
)
def test_cloudformation_resolver_rejects_invalid_list_form_sub(raw: Any) -> None:
    with pytest.raises(
        aws.ConnectedRouteError,
        match="ROUTE_PERMISSION_SET_CONTRACT_INVALID",
    ):
        aws._resolve_cloudformation_value(
            {"Fn::Sub": raw},
            parameters={"AWS::Region": "us-east-1"},
        )


@pytest.mark.parametrize(
    ("mutate", "code"),
    [
        (
            lambda value: value.update(bootstrap_principal_id="not-a-uuid"),
            "PRIVATE_COORDINATE_INVALID",
        ),
        (
            lambda value: value["artifacts"]["route_template"].update(
                observed_at="2020-01-01T00:00:00Z"
            ),
            "TEMPLATE_RECEIPT_DIGEST_INVALID",
        ),
        (
            lambda value: value["artifacts"]["broker_code"]["signed_artifact"].update(
                code_sha256="sha256:" + "0" * 64
            ),
            "BROKER_SIGNING_RECEIPT_INVALID",
        ),
        (
            lambda value: value.update(production_authorized=True),
            "EXECUTION_BOUNDARY_INVALID",
        ),
    ],
)
def test_rejects_private_input_drift_even_when_outer_input_is_resealed(
    case: tuple[dict[str, Any], dict[str, Any], datetime],
    mutate: Any,
    code: str,
) -> None:
    changed = copy.deepcopy(case[0])
    mutate(changed)
    changed.pop("input_digest")
    changed = route.seal(changed, "input_digest")
    with pytest.raises(route.RouteSeedError, match=code):
        route.materialize_seed_intent(changed, git=FakeGit(), now=case[2])


def _attestation(intent: Mapping[str, Any], target: str, now: datetime) -> dict[str, Any]:
    spec = intent["targets"][target]
    value = {
        "schema_version": 1,
        "record_type": route.RECORD_TYPE_CREATE_ATTESTATION,
        "source_commit": SOURCE_COMMIT,
        "target": target,
        "intent_digest": intent["intent_digest"],
        "create_request_digest": spec["create_request_digest"],
        "account_id": spec["account_id"],
        "stack_arn": (
            f"arn:aws:cloudformation:us-east-1:{spec['account_id']}:"
            f"stack/{spec['stack_name']}/{STACK_UUID}"
        ),
        "change_set_arn": (
            f"arn:aws:cloudformation:us-east-1:{spec['account_id']}:"
            f"changeSet/{spec['change_set_name']}/{CHANGE_UUID}"
        ),
        "create_request_id": REQUEST_UUID,
        "cloudtrail_event_digest": "sha256:" + "1" * 64,
        "describe_change_set_digest": "sha256:" + "2" * 64,
        "template_digest": spec["template_digest"],
        "changes_digest": route.digest_value(spec["expected_changes"]),
        "status": "CREATE_COMPLETE",
        "execution_status": "AVAILABLE",
        "attested_at": _ts(now),
        "aws_mutations": 0,
        "retry_permitted": False,
        "production_authorized": False,
        "production_status": "NO-GO",
    }
    return route.seal(value, "attestation_digest")


def _execution_records(
    intent: Mapping[str, Any], target: str, now: datetime
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    attestation = _attestation(intent, target, now)
    authorization = route.materialize_execution_authorization(
        seed_intent=intent,
        create_attestation=attestation,
        authorization=(
            "I_AUTHORIZE_GUG376_"
            + target.upper().replace("-", "_")
            + "_SEED_EXECUTION"
        ),
        authorized_at=_ts(now),
        expires_at=_ts(now + timedelta(minutes=10)),
    )
    execution = route.materialize_execution_intent(
        seed_intent=intent,
        create_attestation=attestation,
        authorization=authorization,
    )
    return attestation, authorization, execution


def _creator_role(target: str) -> str:
    return (
        "AWSAdministratorAccess"
        if target == "route"
        else "ScanalyzeGug376BrokerSeedCreator"
    )


def _executor_role(target: str) -> str:
    return (
        "AWSAdministratorAccess"
        if target == "route"
        else "ScanalyzeGug376BrokerSeedExec"
    )


def _creator_arn(target: str) -> str:
    account_id = (
        route.MANAGEMENT_ACCOUNT_ID
        if target == "route"
        else route.AUTHORITY_ACCOUNT_ID
    )
    return (
        f"arn:aws:sts::{account_id}:assumed-role/"
        f"AWSReservedSSO_{_creator_role(target)}_0123456789abcdef/cesar"
    )


def _template_body(
    source: Mapping[str, Any], *, target: str
) -> str:
    if target == "route":
        return (ROOT / route.ROUTE_TEMPLATE_PATH).read_text()
    return FakeGit().render_broker_seed(
        source["broker_seed_input"],
        protection_enabled=target == route.BROKER_PROTECTION_TARGET,
    ).decode("utf-8")


def _create_event(
    intent: Mapping[str, Any],
    dispatch: Mapping[str, Any],
    now: datetime,
) -> dict[str, Any]:
    target = str(dispatch["target"])
    return {
        "eventID": EVENT_UUID,
        "eventTime": _ts(now - timedelta(seconds=30)),
        "requestID": REQUEST_UUID,
        "eventSource": "cloudformation.amazonaws.com",
        "eventName": "CreateChangeSet",
        "awsRegion": route.REGION,
        "recipientAccountId": dispatch["account_id"],
        "readOnly": False,
        "userIdentity": {"arn": _creator_arn(target)},
        "requestParameters": _cloudtrail_create_params(
            intent["targets"][target]["create_request"]
        ),
        "responseElements": {
            "id": dispatch["change_set_arn"],
            "stackId": dispatch["stack_arn"],
        },
    }


def _live_execution_records(
    source: Mapping[str, Any],
    intent: Mapping[str, Any],
    target: str,
    now: datetime,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    dispatch = _dispatch(intent, target, now)
    account_id = intent["targets"][target]["account_id"]
    attestation = aws.ConnectedSeedProvider(
        clients=_clients(
            sts=Identity(account_id, _creator_role(target), []),
            cfn=AttestCloudFormation(
                intent,
                dispatch,
                template_body=_template_body(source, target=target),
            ),
            trail=Trail(_create_event(intent, dispatch, now)),
        ),
        claims=Claims([]),
        clock=lambda: now,
    ).attest_change_set(
        seed_intent=intent,
        dispatch_receipt=dispatch,
    )
    authorization = route.materialize_execution_authorization(
        seed_intent=intent,
        create_attestation=attestation,
        authorization=(
            "I_AUTHORIZE_GUG376_"
            + target.upper().replace("-", "_")
            + "_SEED_EXECUTION"
        ),
        authorized_at=_ts(now),
        expires_at=_ts(now + timedelta(minutes=10)),
    )
    execution = route.materialize_execution_intent(
        seed_intent=intent,
        create_attestation=attestation,
        authorization=authorization,
    )
    return attestation, authorization, execution


def _execution(
    intent: Mapping[str, Any], target: str, now: datetime
) -> dict[str, Any]:
    return _execution_records(intent, target, now)[2]


def _creation_authorization(
    intent: Mapping[str, Any], target: str, now: datetime
) -> dict[str, Any]:
    return route.materialize_creation_authorization(
        seed_intent=intent,
        target=target,
        authorization=(
            "I_AUTHORIZE_GUG376_"
            + target.upper().replace("-", "_")
            + "_SEED_CREATION"
        ),
        authorized_at=_ts(now),
        expires_at=_ts(now + timedelta(minutes=10)),
    )


@pytest.mark.parametrize(
    ("target", "phrase", "seconds", "code"),
    [
        ("wrong", "I_AUTHORIZE_GUG376_ROUTE_SEED_CREATION", 600, "TARGET_INVALID"),
        ("route", "I_AUTHORIZE_GUG376_BROKER_SEED_CREATION", 600, "CREATION_AUTHORIZATION_INVALID"),
        ("route", "I_AUTHORIZE_GUG376_ROUTE_SEED_CREATION", 59, "CREATION_AUTHORIZATION_INVALID"),
        ("route", "I_AUTHORIZE_GUG376_ROUTE_SEED_CREATION", 901, "CREATION_AUTHORIZATION_INVALID"),
    ],
)
def test_creation_authorization_rejects_wrong_target_phrase_and_ttl(
    case: tuple[dict[str, Any], dict[str, Any], datetime],
    target: str,
    phrase: str,
    seconds: int,
    code: str,
) -> None:
    source, intent, now = case
    with pytest.raises(route.RouteSeedError, match=code):
        route.materialize_creation_authorization(
            seed_intent=intent,
            target=target,
            authorization=phrase,
            authorized_at=_ts(now),
            expires_at=_ts(now + timedelta(seconds=seconds)),
        )


def test_creation_authorization_rejects_expired_record(
    case: tuple[dict[str, Any], dict[str, Any], datetime]
) -> None:
    source, intent, now = case
    authorization = _creation_authorization(intent, "route", now)
    with pytest.raises(
        route.RouteSeedError, match="CREATION_AUTHORIZATION_INVALID"
    ):
        route.validate_creation_authorization(
            authorization,
            seed_intent=intent,
            target="route",
            now=now + timedelta(minutes=10),
        )
    with pytest.raises(
        route.RouteSeedError, match="CREATION_AUTHORIZATION_FIELDS_INVALID"
    ):
        route.validate_creation_authorization(
            {},
            seed_intent=intent,
            target="route",
            now=now,
        )


def test_execution_authorization_rejects_one_second_grant(
    case: tuple[dict[str, Any], dict[str, Any], datetime]
) -> None:
    _source, intent, now = case
    attestation = _attestation(intent, "route", now)
    with pytest.raises(route.RouteSeedError, match="AUTHORIZATION_INVALID"):
        route.materialize_execution_authorization(
            seed_intent=intent,
            create_attestation=attestation,
            authorization="I_AUTHORIZE_GUG376_ROUTE_SEED_EXECUTION",
            authorized_at=_ts(now),
            expires_at=_ts(now + timedelta(seconds=1)),
        )
    _attestation_record, authorization, _execution_record = _execution_records(
        intent,
        "route",
        now,
    )
    authorization["expires_at"] = _ts(now + timedelta(seconds=1))
    authorization.pop("authorization_digest")
    authorization = route.seal(authorization, "authorization_digest")
    with pytest.raises(route.RouteSeedError, match="AUTHORIZATION_INVALID"):
        route.materialize_execution_intent(
            seed_intent=intent,
            create_attestation=attestation,
            authorization=authorization,
        )


def test_execution_intent_requires_exact_authorization_window_and_uuid_arns(
    case: tuple[dict[str, Any], dict[str, Any], datetime]
) -> None:
    source, intent, now = case
    attestation, execution_authorization, execution = _live_execution_records(
        source, intent, "route", now
    )
    assert route.validate_execution_intent(execution) == execution
    assert set(execution["execute_request"]) == {
        "StackName",
        "ChangeSetName",
        "ClientRequestToken",
    }
    assert "DisableRollback" not in execution["execute_request"]
    assert execution["execute_request"]["StackName"].endswith(STACK_UUID)
    assert execution["execute_request"]["ChangeSetName"].endswith(CHANGE_UUID)
    assert execution["recovery_not_after"] == intent["recovery_not_after"]
    protection = _execution(
        intent, route.BROKER_PROTECTION_TARGET, now
    )
    assert protection["execute_request"]["DisableRollback"] is False
    assert set(protection["execute_request"]) == {
        "StackName",
        "ChangeSetName",
        "ClientRequestToken",
        "DisableRollback",
    }
    changed = copy.deepcopy(execution)
    changed["execute_request"]["ChangeSetName"] = route.ROUTE_CHANGE_SET_NAME
    changed["execute_request_digest"] = route.digest_value(changed["execute_request"])
    changed.pop("execution_intent_digest")
    changed = route.seal(changed, "execution_intent_digest")
    with pytest.raises(route.RouteSeedError, match="EXECUTION_INTENT_INVALID"):
        route.validate_execution_intent(changed)

    changed = copy.deepcopy(execution)
    changed["recovery_not_after"] = changed["route_not_after"]
    changed.pop("execution_intent_digest")
    changed = route.seal(changed, "execution_intent_digest")
    with pytest.raises(route.RouteSeedError, match="EXECUTION_INTENT_INVALID"):
        route.validate_execution_intent(changed)


def test_connected_recovery_horizon_is_exclusive(
    case: tuple[dict[str, Any], dict[str, Any], datetime]
) -> None:
    _source, intent, _now = case
    recovery_not_after = datetime.fromisoformat(
        intent["recovery_not_after"].replace("Z", "+00:00")
    )
    accepted = aws._recovery_window(
        intent, lambda: recovery_not_after - timedelta(seconds=1)
    )
    assert accepted == recovery_not_after - timedelta(seconds=1)
    with pytest.raises(aws.ConnectedRouteError, match="RECOVERY_WINDOW_CLOSED"):
        aws._recovery_window(intent, lambda: recovery_not_after)


def test_mutation_admission_closes_before_provider_recovery_horizon(
    case: tuple[dict[str, Any], dict[str, Any], datetime]
) -> None:
    _source, intent, _now = case
    route_not_after = datetime.fromisoformat(
        intent["route_not_after"].replace("Z", "+00:00")
    )
    admission_not_after = route_not_after - timedelta(
        seconds=route.MUTATION_COMPLETION_RESERVE_SECONDS
    )
    assert aws._window(
        intent, lambda: admission_not_after - timedelta(seconds=1)
    ) == admission_not_after - timedelta(seconds=1)
    with pytest.raises(
        aws.ConnectedRouteError, match="ROUTE_WINDOW_CLOSED"
    ):
        aws._window(intent, lambda: admission_not_after)

    authorized_at = admission_not_after - timedelta(seconds=120)
    route.materialize_creation_authorization(
        seed_intent=intent,
        target="route",
        authorization="I_AUTHORIZE_GUG376_ROUTE_SEED_CREATION",
        authorized_at=_ts(authorized_at),
        expires_at=_ts(admission_not_after),
    )
    with pytest.raises(
        route.RouteSeedError, match="CREATION_AUTHORIZATION_INVALID"
    ):
        route.materialize_creation_authorization(
            seed_intent=intent,
            target="route",
            authorization="I_AUTHORIZE_GUG376_ROUTE_SEED_CREATION",
            authorized_at=_ts(authorized_at),
            expires_at=_ts(admission_not_after + timedelta(seconds=1)),
        )


class Identity:
    def __init__(self, account: str, role: str, timeline: list[str]) -> None:
        self.account = account
        self.role = role
        self.timeline = timeline

    def get_caller_identity(self) -> dict[str, str]:
        self.timeline.append("sts")
        return {
            "Account": self.account,
            "Arn": (
                f"arn:aws:sts::{self.account}:assumed-role/"
                f"AWSReservedSSO_{self.role}_0123456789abcdef/cesar"
            ),
            "UserId": "AROATEST:cesar",
        }


class Claims:
    def __init__(self, timeline: list[str]) -> None:
        self.timeline = timeline
        self.seen: set[str] = set()
        self.records: dict[str, dict[str, Any]] = {}
        self.results: dict[str, dict[str, Any]] = {}

    def claim(self, key: str, record: Mapping[str, Any]) -> None:
        self.timeline.append("claim")
        if key in self.seen:
            raise aws.ConnectedRouteError("MUTATION_REPLAY_REJECTED")
        self.seen.add(key)
        self.records[key] = dict(record)

    def complete(self, key: str, record: Mapping[str, Any]) -> None:
        self.timeline.append("complete")
        assert key in self.seen
        current = self.results.get(key)
        assert current is None or current == record
        self.results[key] = dict(record)

    def read_claim(self, key: str) -> dict[str, Any]:
        self.timeline.append("read-claim")
        return dict(self.records[key])

    def read_result(self, key: str) -> dict[str, Any]:
        self.timeline.append("read-result")
        if key not in self.results:
            raise aws.ConnectedRouteError("MUTATION_RESULT_MISSING")
        return dict(self.results[key])

    def seed_create_result(
        self,
        *,
        intent: Mapping[str, Any],
        target: str,
        now: datetime,
    ) -> None:
        spec = intent["targets"][target]
        key = (
            f"create:{target}:{intent['intent_digest']}:"
            f"{spec['create_request_digest']}"
        )
        dispatch = _dispatch(intent, target, now)
        self.seen.add(key)
        self.records[key] = {
            "schema_version": 1,
            "record_type": aws.CLAIM_RECORD_TYPE,
            "operation": "CreateChangeSet",
            "target": target,
            "intent_digest": intent["intent_digest"],
            "request_digest": spec["create_request_digest"],
            "creation_authorization": dispatch["creation_authorization"],
            "creation_authorization_digest": dispatch[
                "creation_authorization_digest"
            ],
            "client_token": spec["create_request"]["ClientToken"],
            "stack_name": spec["create_request"]["StackName"],
            "change_set_name": spec["create_request"]["ChangeSetName"],
            "caller_arn_digest": route.digest_value(_creator_arn(target)),
            "claimed_at": dispatch["dispatched_at"],
            "retry_permitted": False,
            "production_authorized": False,
        }
        self.results[key] = dispatch


def test_claim_store_rejects_symlink_and_root_replacement(
    tmp_path: Path,
) -> None:
    target = tmp_path / "target"
    target.mkdir(mode=0o700)
    target.chmod(0o700)
    link = tmp_path / "link"
    link.symlink_to(target, target_is_directory=True)
    with pytest.raises(aws.ConnectedRouteError, match="CLAIM_ROOT_INVALID"):
        aws.OExclClaimStore(link)

    root = tmp_path / "claims"
    root.mkdir(mode=0o700)
    root.chmod(0o700)
    descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
    identity = os.fstat(descriptor)
    store = aws.OExclClaimStore(
        root,
        expected_root_identity=(identity.st_dev, identity.st_ino),
    )
    store.claim("persisted", {"effect": "claimed"})
    store.complete("persisted", {"effect": "complete"})
    assert store.read_result("persisted") == {"effect": "complete"}
    store.claim("effect", {"effect": "claimed"})
    moved = tmp_path / "claims-moved"
    root.rename(moved)
    root.mkdir(mode=0o700)
    root.chmod(0o700)
    try:
        with pytest.raises(
            aws.ConnectedRouteError, match="CLAIM_ROOT_CHANGED"
        ):
            store.complete("effect", {"effect": "complete"})
        with pytest.raises(
            aws.ConnectedRouteError, match="CLAIM_ROOT_CHANGED"
        ):
            store.read_claim("effect")
        with pytest.raises(
            aws.ConnectedRouteError, match="CLAIM_ROOT_CHANGED"
        ):
            store.read_result("persisted")
        with pytest.raises(
            aws.ConnectedRouteError, match="CLAIM_ROOT_CHANGED"
        ):
            aws.OExclClaimStore(
                root,
                expected_root_identity=(identity.st_dev, identity.st_ino),
            )
        assert not list(root.iterdir())
    finally:
        store.close()
        os.close(descriptor)


def test_connected_cli_binds_claim_store_to_open_private_root_before_sdk(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    spec = importlib.util.spec_from_file_location(
        "gug376_route_aws_cli_root_binding", AWS_CLI
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    root = tmp_path / "private"
    root.mkdir(mode=0o700)
    root.chmod(0o700)
    root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
    moved = tmp_path / "private-moved"
    root.rename(moved)
    root.mkdir(mode=0o700)
    root.chmod(0o700)
    sdk_setup: list[str] = []
    monkeypatch.setattr(
        module,
        "_environment",
        lambda _profile: sdk_setup.append("environment"),
    )
    try:
        with pytest.raises(
            aws.ConnectedRouteError, match="PRIVATE_ROOT_CHANGED"
        ):
            module._provider(  # noqa: SLF001
                root,
                root_fd,
                profile="839393571433_AWSAdministratorAccess",
            )
        assert sdk_setup == []
        assert not list(root.iterdir())
    finally:
        os.close(root_fd)


class CreateCloudFormation:
    def __init__(self, intent: Mapping[str, Any], target: str, timeline: list[str]) -> None:
        self.spec = intent["targets"][target]
        self.timeline = timeline

    def create_change_set(self, **request: Any) -> dict[str, Any]:
        self.timeline.append("mutate")
        assert request == self.spec["create_request"]
        return {
            "Id": (
                f"arn:aws:cloudformation:us-east-1:{self.spec['account_id']}:"
                f"changeSet/{self.spec['change_set_name']}/{CHANGE_UUID}"
            ),
            "StackId": (
                f"arn:aws:cloudformation:us-east-1:{self.spec['account_id']}:"
                f"stack/{self.spec['stack_name']}/{STACK_UUID}"
            ),
            "ResponseMetadata": {"RequestId": REQUEST_UUID},
        }


def _clients(*, sts: Any, cfn: Any, trail: Any = None, sso: Any = None) -> dict[str, Any]:
    unused = object()
    return {
        "sts": sts,
        "cloudformation": cfn,
        "cloudtrail": trail if trail is not None else unused,
        "sso-admin": sso if sso is not None else unused,
        "lambda": unused,
        "iam": unused,
        "dynamodb": unused,
        "kms": unused,
        "logs": unused,
    }


def test_connected_create_sts_then_durable_claim_then_one_effect_and_no_replay(
    case: tuple[dict[str, Any], dict[str, Any], datetime]
) -> None:
    source, intent, now = case
    timeline: list[str] = []
    claims = Claims(timeline)
    provider = aws.ConnectedSeedProvider(
        clients=_clients(
            sts=Identity(route.MANAGEMENT_ACCOUNT_ID, "AWSAdministratorAccess", timeline),
            cfn=CreateCloudFormation(intent, "route", timeline),
        ),
        claims=claims,
        clock=lambda: now,
    )
    authorization = _creation_authorization(intent, "route", now)
    receipt = provider.create_change_set(
        seed_input=source,
        seed_intent=intent,
        git=FakeGit(),
        target="route",
        creation_authorization=authorization,
    )
    assert timeline == ["sts", "claim", "mutate", "complete"]
    assert receipt["aws_mutations"] == 1
    with pytest.raises(aws.ConnectedRouteError, match="MUTATION_REPLAY_REJECTED"):
        provider.create_change_set(
            seed_input=source,
            seed_intent=intent,
            git=FakeGit(),
            target="route",
            creation_authorization=authorization,
        )
    assert timeline == ["sts", "claim", "mutate", "complete", "sts", "claim"]


def test_connected_create_rejects_authorization_before_any_aws_call(
    case: tuple[dict[str, Any], dict[str, Any], datetime]
) -> None:
    source, intent, now = case
    timeline: list[str] = []
    authorization = _creation_authorization(intent, "route", now)
    changed = copy.deepcopy(authorization)
    changed["target"] = "broker"
    changed.pop("authorization_digest")
    changed = route.seal(changed, "authorization_digest")
    provider = aws.ConnectedSeedProvider(
        clients=_clients(
            sts=Identity(
                route.MANAGEMENT_ACCOUNT_ID,
                "AWSAdministratorAccess",
                timeline,
            ),
            cfn=CreateCloudFormation(intent, "route", timeline),
        ),
        claims=Claims(timeline),
        clock=lambda: now,
    )
    with pytest.raises(
        aws.ConnectedRouteError, match="CREATION_AUTHORIZATION_INVALID"
    ):
        provider.create_change_set(
            seed_input=source,
            seed_intent=intent,
            git=FakeGit(),
            target="route",
            creation_authorization=changed,
        )
    assert timeline == []


def test_connected_create_resamples_clock_immediately_before_effect(
    case: tuple[dict[str, Any], dict[str, Any], datetime]
) -> None:
    source, intent, now = case
    timeline: list[str] = []
    samples = iter(
        (
            now,
            now + timedelta(minutes=9, seconds=59),
            now + timedelta(minutes=10),
        )
    )
    provider = aws.ConnectedSeedProvider(
        clients=_clients(
            sts=Identity(
                route.MANAGEMENT_ACCOUNT_ID,
                "AWSAdministratorAccess",
                timeline,
            ),
            cfn=CreateCloudFormation(intent, "route", timeline),
        ),
        claims=Claims(timeline),
        clock=lambda: next(samples),
    )
    with pytest.raises(
        aws.ConnectedRouteError,
        match="CREATION_AUTHORIZATION_INVALID",
    ):
        provider.create_change_set(
            seed_input=source,
            seed_intent=intent,
            git=FakeGit(),
            target="route",
            creation_authorization=_creation_authorization(
                intent,
                "route",
                now,
            ),
        )
    assert timeline == ["sts", "claim"]


def test_connected_create_rejects_resealed_forged_template_url_before_aws(
    case: tuple[dict[str, Any], dict[str, Any], datetime]
) -> None:
    source, intent, now = case
    forged = copy.deepcopy(intent)
    forged_request = forged["targets"]["route"]["create_request"]
    forged_request["TemplateURL"] = (
        "https://attacker.example.invalid/forged-route-template.yaml"
    )
    forged["targets"]["route"]["create_request_digest"] = route.digest_value(
        forged_request
    )
    forged.pop("intent_digest")
    forged = route.seal(forged, "intent_digest")

    # A self-consistent checksum and unchanged source-template digest are not
    # sufficient authorization for a different versioned artifact URL.
    assert route.validate_seed_intent_against_git(forged, git=FakeGit()) == forged
    with pytest.raises(
        route.RouteSeedError, match="INTENT_INPUT_BINDING_INVALID"
    ):
        route.validate_seed_intent_against_input(
            forged,
            seed_input=source,
            git=FakeGit(),
            now=now,
        )

    timeline: list[str] = []
    provider = aws.ConnectedSeedProvider(
        clients=_clients(
            sts=Identity(
                route.MANAGEMENT_ACCOUNT_ID,
                "AWSAdministratorAccess",
                timeline,
            ),
            cfn=CreateCloudFormation(forged, "route", timeline),
        ),
        claims=Claims(timeline),
        clock=lambda: now,
    )
    with pytest.raises(
        aws.ConnectedRouteError, match="INTENT_INPUT_BINDING_INVALID"
    ):
        provider.create_change_set(
            seed_input=source,
            seed_intent=forged,
            git=FakeGit(),
            target="route",
            creation_authorization=_creation_authorization(
                forged, "route", now
            ),
        )
    assert timeline == []


def test_connected_cli_validates_exact_seed_before_provider_session(
    case: tuple[dict[str, Any], dict[str, Any], datetime],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source, intent, now = case
    forged = copy.deepcopy(intent)
    forged_request = forged["targets"]["route"]["create_request"]
    forged_request["TemplateURL"] = (
        "https://attacker.example.invalid/forged-route-template.yaml"
    )
    forged["targets"]["route"]["create_request_digest"] = (
        route.digest_value(forged_request)
    )
    forged.pop("intent_digest")
    forged = route.seal(forged, "intent_digest")

    spec = importlib.util.spec_from_file_location(
        "gug376_route_aws_cli_seed_preflight",
        AWS_CLI,
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    monkeypatch.setattr(module.route, "SubprocessGit", lambda _root: FakeGit())
    provider_calls: list[str] = []
    monkeypatch.setattr(
        module,
        "_provider",
        lambda *_args, **_kwargs: provider_calls.append("provider"),
    )

    private = tmp_path / "private"
    private.mkdir(mode=0o700)
    private.chmod(0o700)
    records = {
        "seed-input.json": source,
        "seed-intent.json": forged,
        "creation-authorization.json": _creation_authorization(
            forged,
            "route",
            now,
        ),
    }
    for name, value in records.items():
        path = private / name
        path.write_text(route.canonical_json(value) + "\n", encoding="utf-8")
        path.chmod(0o600)

    assert module.main(
        [
            "create-change-set",
            "--profile",
            "839393571433_AWSAdministratorAccess",
            "--target",
            "route",
            "--source-root",
            os.fspath(ROOT),
            "--private-root",
            os.fspath(private),
            "--receipt-name",
            "receipt.json",
            "--input-name",
            "seed-input.json",
            "--intent-name",
            "seed-intent.json",
            "--authorization-name",
            "creation-authorization.json",
        ]
    ) == 2
    assert provider_calls == []
    assert not (private / "receipt.json").exists()


def test_connected_broker_protection_create_uses_exact_update_request(
    case: tuple[dict[str, Any], dict[str, Any], datetime]
) -> None:
    source, intent, now = case
    target = route.BROKER_PROTECTION_TARGET
    timeline: list[str] = []
    provider = aws.ConnectedSeedProvider(
        clients=_clients(
            sts=Identity(
                route.AUTHORITY_ACCOUNT_ID,
                "ScanalyzeGug376BrokerSeedCreator",
                timeline,
            ),
            cfn=CreateCloudFormation(intent, target, timeline),
        ),
        claims=Claims(timeline),
        clock=lambda: now,
    )
    receipt = provider.create_change_set(
        seed_input=source,
        seed_intent=intent,
        git=FakeGit(),
        target=target,
        creation_authorization=_creation_authorization(
            intent, target, now
        ),
    )
    assert receipt["target"] == target
    assert timeline == ["sts", "claim", "mutate", "complete"]
    request = intent["targets"][target]["create_request"]
    assert request["ChangeSetType"] == "UPDATE"
    assert "Parameters" not in request
    assert "OnStackFailure" not in request


def test_connected_execute_receipt_uses_pre_call_cloudtrail_boundary(
    case: tuple[dict[str, Any], dict[str, Any], datetime]
) -> None:
    source, intent, now = case
    attestation, execution_authorization, execution = _live_execution_records(
        source, intent, "route", now
    )
    timeline: list[str] = []
    current = [now]
    dispatch = _dispatch(intent, "route", now)

    def advance_clock() -> None:
        assert "DisableRollback" not in execution["execute_request"]
        current[0] = now + timedelta(seconds=30)

    claims = Claims(timeline)
    claims.seed_create_result(intent=intent, target="route", now=now)
    provider = aws.ConnectedSeedProvider(
        clients=_clients(
            sts=Identity(
                route.MANAGEMENT_ACCOUNT_ID,
                "AWSAdministratorAccess",
                timeline,
            ),
            cfn=ExecutingAttestCloudFormation(
                intent,
                dispatch,
                execution,
                timeline,
                template_body=_template_body(source, target="route"),
                on_execute=advance_clock,
            ),
            trail=Trail(_create_event(intent, dispatch, now), timeline),
        ),
        claims=claims,
        clock=lambda: current[0],
    )
    receipt = provider.execute_change_set(
        seed_input=source,
        seed_intent=intent,
        git=FakeGit(),
        create_attestation=attestation,
        execution_authorization=execution_authorization,
        execution_intent=execution,
    )
    assert timeline == [
        "read-claim",
        "read-result",
        "sts",
        "describe",
        "template",
        "cloudtrail",
        "claim",
        "mutate",
        "complete",
    ]
    assert receipt["dispatched_at"] == _ts(now)
    assert current[0] > now


def test_connected_execute_rejects_expired_authorization_before_sts(
    case: tuple[dict[str, Any], dict[str, Any], datetime]
) -> None:
    source, intent, now = case
    attestation, authorization, execution = _execution_records(
        intent, "route", now
    )
    timeline: list[str] = []
    provider = aws.ConnectedSeedProvider(
        clients=_clients(
            sts=Identity(
                route.MANAGEMENT_ACCOUNT_ID,
                "AWSAdministratorAccess",
                timeline,
            ),
            cfn=object(),
        ),
        claims=Claims(timeline),
        clock=lambda: now + timedelta(minutes=10),
    )
    with pytest.raises(aws.ConnectedRouteError, match="AUTHORIZATION_EXPIRED"):
        provider.execute_change_set(
            seed_input=source,
            seed_intent=intent,
            git=FakeGit(),
            create_attestation=attestation,
            execution_authorization=authorization,
            execution_intent=execution,
        )
    assert timeline == []


def test_connected_execute_resamples_clock_after_readback_before_effect(
    case: tuple[dict[str, Any], dict[str, Any], datetime]
) -> None:
    source, intent, now = case
    attestation, authorization, execution = _live_execution_records(
        source, intent, "route", now
    )
    timeline: list[str] = []
    claims = Claims(timeline)
    claims.seed_create_result(intent=intent, target="route", now=now)
    dispatch = _dispatch(intent, "route", now)
    samples = iter(
        (
            now + timedelta(minutes=9, seconds=58),
            now + timedelta(minutes=9, seconds=59),
            now + timedelta(minutes=10),
        )
    )
    provider = aws.ConnectedSeedProvider(
        clients=_clients(
            sts=Identity(
                route.MANAGEMENT_ACCOUNT_ID,
                "AWSAdministratorAccess",
                timeline,
            ),
            cfn=ExecutingAttestCloudFormation(
                intent,
                dispatch,
                execution,
                timeline,
                template_body=_template_body(source, target="route"),
            ),
            trail=Trail(_create_event(intent, dispatch, now), timeline),
        ),
        claims=claims,
        clock=lambda: next(samples),
    )
    with pytest.raises(aws.ConnectedRouteError, match="AUTHORIZATION_EXPIRED"):
        provider.execute_change_set(
            seed_input=source,
            seed_intent=intent,
            git=FakeGit(),
            create_attestation=attestation,
            execution_authorization=authorization,
            execution_intent=execution,
        )
    assert timeline == [
        "read-claim",
        "read-result",
        "sts",
        "describe",
        "template",
        "cloudtrail",
    ]


def test_connected_execute_rejects_alternate_same_name_change_set_uuid(
    case: tuple[dict[str, Any], dict[str, Any], datetime]
) -> None:
    source, intent, now = case
    attestation, authorization, execution = _live_execution_records(
        source, intent, "route", now
    )
    timeline: list[str] = []
    claims = Claims(timeline)
    claims.seed_create_result(intent=intent, target="route", now=now)
    dispatch = _dispatch(intent, "route", now)

    class AlternateUuid(ExecutingAttestCloudFormation):
        def describe_change_set(self, **request: Any) -> dict[str, Any]:
            response = super().describe_change_set(**request)
            response["ChangeSetId"] = (
                f"arn:aws:cloudformation:{route.REGION}:"
                f"{route.MANAGEMENT_ACCOUNT_ID}:changeSet/"
                f"{route.ROUTE_CHANGE_SET_NAME}/"
                "99999999-9999-4999-8999-999999999999"
            )
            return response

    provider = aws.ConnectedSeedProvider(
        clients=_clients(
            sts=Identity(
                route.MANAGEMENT_ACCOUNT_ID,
                "AWSAdministratorAccess",
                timeline,
            ),
            cfn=AlternateUuid(
                intent,
                dispatch,
                execution,
                timeline,
                template_body=_template_body(source, target="route"),
            ),
            trail=Trail(_create_event(intent, dispatch, now), timeline),
        ),
        claims=claims,
        clock=lambda: now,
    )
    with pytest.raises(
        aws.ConnectedRouteError,
        match="CHANGE_SET_READBACK_INVALID",
    ):
        provider.execute_change_set(
            seed_input=source,
            seed_intent=intent,
            git=FakeGit(),
            create_attestation=attestation,
            execution_authorization=authorization,
            execution_intent=execution,
        )
    assert "mutate" not in timeline


def test_connected_execute_rejects_alternate_bootstrap_principal_before_effect(
    case: tuple[dict[str, Any], dict[str, Any], datetime]
) -> None:
    source, intent, now = case
    attestation, authorization, execution = _live_execution_records(
        source, intent, "route", now
    )
    timeline: list[str] = []
    claims = Claims(timeline)
    claims.seed_create_result(intent=intent, target="route", now=now)
    dispatch = _dispatch(intent, "route", now)

    class AlternateBootstrapPrincipal(ExecutingAttestCloudFormation):
        def describe_change_set(self, **request: Any) -> dict[str, Any]:
            response = super().describe_change_set(**request)
            for parameter in response["Parameters"]:
                if parameter["ParameterKey"] == "BootstrapPrincipalId":
                    parameter["ParameterValue"] = (
                        "87654321-4321-4321-8321-210987654321"
                    )
                    break
            return response

    provider = aws.ConnectedSeedProvider(
        clients=_clients(
            sts=Identity(
                route.MANAGEMENT_ACCOUNT_ID,
                "AWSAdministratorAccess",
                timeline,
            ),
            cfn=AlternateBootstrapPrincipal(
                intent,
                dispatch,
                execution,
                timeline,
                template_body=_template_body(source, target="route"),
            ),
            trail=Trail(_create_event(intent, dispatch, now), timeline),
        ),
        claims=claims,
        clock=lambda: now,
    )
    with pytest.raises(
        aws.ConnectedRouteError,
        match="CHANGE_SET_READBACK_INVALID",
    ):
        provider.execute_change_set(
            seed_input=source,
            seed_intent=intent,
            git=FakeGit(),
            create_attestation=attestation,
            execution_authorization=authorization,
            execution_intent=execution,
        )
    assert timeline == ["read-claim", "read-result", "sts", "describe"]


def test_connected_execute_rejects_unattested_change_set_arn_before_aws(
    case: tuple[dict[str, Any], dict[str, Any], datetime]
) -> None:
    source, intent, now = case
    attestation, execution_authorization, execution = _execution_records(
        intent, "route", now
    )
    forged = copy.deepcopy(execution)
    forged_request = forged["execute_request"]
    forged_request["ChangeSetName"] = (
        f"arn:aws:cloudformation:{route.REGION}:{route.MANAGEMENT_ACCOUNT_ID}:"
        f"changeSet/{route.ROUTE_CHANGE_SET_NAME}/"
        "99999999-9999-4999-8999-999999999999"
    )
    operation_digest = route.digest_value(
        {
            "record_type": (
                "scanalyze.platform_authority."
                "plan_permission_repair_execute_operation.v1"
            ),
            "source_commit": forged["source_commit"],
            "target": forged["target"],
            "account_id": forged["account_id"],
            "stack_arn": forged_request["StackName"],
            "change_set_arn": forged_request["ChangeSetName"],
        }
    )
    forged["execute_operation_digest"] = operation_digest
    forged_request["ClientRequestToken"] = "gug376-" + operation_digest[7:55]
    forged["execute_request_digest"] = route.digest_value(forged_request)
    forged.pop("execution_intent_digest")
    forged = route.seal(forged, "execution_intent_digest")

    # The generic validator proves internal consistency only; connected
    # execution must bind the ARN back to the exact create attestation.
    assert route.validate_execution_intent(forged) == forged
    with pytest.raises(
        route.RouteSeedError, match="EXECUTION_CAUSAL_BINDING_INVALID"
    ):
        route.validate_execution_intent_against_causal_records(
            forged,
            seed_intent=intent,
            create_attestation=attestation,
            authorization=execution_authorization,
        )

    timeline: list[str] = []
    provider = aws.ConnectedSeedProvider(
        clients=_clients(
            sts=Identity(
                route.MANAGEMENT_ACCOUNT_ID,
                "AWSAdministratorAccess",
                timeline,
            ),
            cfn=object(),
        ),
        claims=Claims(timeline),
        clock=lambda: now,
    )
    with pytest.raises(
        aws.ConnectedRouteError, match="EXECUTION_CAUSAL_BINDING_INVALID"
    ):
        provider.execute_change_set(
            seed_input=source,
            seed_intent=intent,
            git=FakeGit(),
            create_attestation=attestation,
            execution_authorization=execution_authorization,
            execution_intent=forged,
        )
    assert timeline == []


def test_connected_execute_requires_persisted_create_result_before_aws(
    case: tuple[dict[str, Any], dict[str, Any], datetime]
) -> None:
    source, intent, now = case
    forged_attestation = copy.deepcopy(_attestation(intent, "route", now))
    forged_attestation["change_set_arn"] = (
        f"arn:aws:cloudformation:{route.REGION}:{route.MANAGEMENT_ACCOUNT_ID}:"
        f"changeSet/{route.ROUTE_CHANGE_SET_NAME}/"
        "99999999-9999-4999-8999-999999999999"
    )
    forged_attestation.pop("attestation_digest")
    forged_attestation = route.seal(
        forged_attestation,
        "attestation_digest",
    )
    authorization = route.materialize_execution_authorization(
        seed_intent=intent,
        create_attestation=forged_attestation,
        authorization="I_AUTHORIZE_GUG376_ROUTE_SEED_EXECUTION",
        authorized_at=_ts(now),
        expires_at=_ts(now + timedelta(minutes=10)),
    )
    execution = route.materialize_execution_intent(
        seed_intent=intent,
        create_attestation=forged_attestation,
        authorization=authorization,
    )
    assert (
        route.validate_execution_intent_against_causal_records(
            execution,
            seed_intent=intent,
            create_attestation=forged_attestation,
            authorization=authorization,
        )
        == execution
    )

    timeline: list[str] = []
    claims = Claims(timeline)
    claims.seed_create_result(intent=intent, target="route", now=now)
    provider = aws.ConnectedSeedProvider(
        clients=_clients(
            sts=Identity(
                route.MANAGEMENT_ACCOUNT_ID,
                "AWSAdministratorAccess",
                timeline,
            ),
            cfn=object(),
        ),
        claims=claims,
        clock=lambda: now,
    )
    with pytest.raises(
        aws.ConnectedRouteError,
        match="CREATE_ATTESTATION_DISPATCH_BINDING_INVALID",
    ):
        provider.execute_change_set(
            seed_input=source,
            seed_intent=intent,
            git=FakeGit(),
            create_attestation=forged_attestation,
            execution_authorization=authorization,
            execution_intent=execution,
        )
    assert timeline == ["read-claim", "read-result"]


def test_distinct_authorizations_share_one_stable_execute_claim_and_token(
    case: tuple[dict[str, Any], dict[str, Any], datetime]
) -> None:
    source, intent, now = case
    attestation = _live_execution_records(source, intent, "route", now)[0]

    def execution(
        authorized_at: datetime,
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        authorization = route.materialize_execution_authorization(
            seed_intent=intent,
            create_attestation=attestation,
            authorization="I_AUTHORIZE_GUG376_ROUTE_SEED_EXECUTION",
            authorized_at=_ts(authorized_at),
            expires_at=_ts(authorized_at + timedelta(minutes=10)),
        )
        execution_intent = route.materialize_execution_intent(
            seed_intent=intent,
            create_attestation=attestation,
            authorization=authorization,
        )
        return authorization, execution_intent

    first_authorization, first = execution(now)
    second_authorization, second = execution(now + timedelta(seconds=30))
    assert first["authorization_digest"] != second["authorization_digest"]
    assert first["execution_intent_digest"] != second["execution_intent_digest"]
    assert first["execute_operation_digest"] == second[
        "execute_operation_digest"
    ]
    assert first["execute_request"]["ClientRequestToken"] == second[
        "execute_request"
    ]["ClientRequestToken"]

    timeline: list[str] = []
    claims = Claims(timeline)
    claims.seed_create_result(intent=intent, target="route", now=now)
    dispatch = _dispatch(intent, "route", now)

    provider = aws.ConnectedSeedProvider(
        clients=_clients(
            sts=Identity(
                route.MANAGEMENT_ACCOUNT_ID,
                "AWSAdministratorAccess",
                timeline,
            ),
            cfn=ExecutingAttestCloudFormation(
                intent,
                dispatch,
                first,
                timeline,
                template_body=_template_body(source, target="route"),
            ),
            trail=Trail(_create_event(intent, dispatch, now), timeline),
        ),
        claims=claims,
        clock=lambda: now,
    )
    provider.execute_change_set(
        seed_input=source,
        seed_intent=intent,
        git=FakeGit(),
        create_attestation=attestation,
        execution_authorization=first_authorization,
        execution_intent=first,
    )
    provider._clock = lambda: now + timedelta(seconds=30)  # noqa: SLF001
    with pytest.raises(
        aws.ConnectedRouteError, match="MUTATION_REPLAY_REJECTED"
    ):
        provider.execute_change_set(
            seed_input=source,
            seed_intent=intent,
            git=FakeGit(),
            create_attestation=attestation,
            execution_authorization=second_authorization,
            execution_intent=second,
        )
    assert timeline.count("mutate") == 1


def test_connected_broker_protection_execute_keeps_rollback_enabled(
    case: tuple[dict[str, Any], dict[str, Any], datetime]
) -> None:
    source, intent, now = case
    attestation, execution_authorization, execution = _live_execution_records(
        source, intent, route.BROKER_PROTECTION_TARGET, now
    )
    timeline: list[str] = []
    dispatch = _dispatch(intent, route.BROKER_PROTECTION_TARGET, now)

    claims = Claims(timeline)
    claims.seed_create_result(
        intent=intent,
        target=route.BROKER_PROTECTION_TARGET,
        now=now,
    )
    receipt = aws.ConnectedSeedProvider(
        clients=_clients(
            sts=Identity(
                route.AUTHORITY_ACCOUNT_ID,
                "ScanalyzeGug376BrokerSeedExec",
                timeline,
            ),
            cfn=ExecutingAttestCloudFormation(
                intent,
                dispatch,
                execution,
                timeline,
                template_body=_template_body(
                    source,
                    target=route.BROKER_PROTECTION_TARGET,
                ),
            ),
            trail=Trail(_create_event(intent, dispatch, now), timeline),
        ),
        claims=claims,
        clock=lambda: now,
    ).execute_change_set(
        seed_input=source,
        seed_intent=intent,
        git=FakeGit(),
        create_attestation=attestation,
        execution_authorization=execution_authorization,
        execution_intent=execution,
    )
    assert receipt["target"] == route.BROKER_PROTECTION_TARGET
    assert timeline == [
        "read-claim",
        "read-result",
        "sts",
        "describe",
        "template",
        "cloudtrail",
        "claim",
        "mutate",
        "complete",
    ]


def test_create_recovery_uses_durable_claim_cloudtrail_and_readback_without_retry(
    case: tuple[dict[str, Any], dict[str, Any], datetime]
) -> None:
    source, intent, now = case
    target = "route"
    timeline: list[str] = []
    claims = Claims(timeline)
    caller = (
        "arn:aws:sts::839393571433:assumed-role/"
        "AWSReservedSSO_AWSAdministratorAccess_0123456789abcdef/cesar"
    )
    spec = intent["targets"][target]
    stack_arn = (
        f"arn:aws:cloudformation:us-east-1:{spec['account_id']}:"
        f"stack/{spec['stack_name']}/{STACK_UUID}"
    )
    change_set_arn = (
        f"arn:aws:cloudformation:us-east-1:{spec['account_id']}:"
        f"changeSet/{spec['change_set_name']}/{CHANGE_UUID}"
    )

    class LostCreateResponse:
        def create_change_set(self, **_request: Any) -> dict[str, Any]:
            timeline.append("mutate")
            raise TimeoutError("response lost")

    first = aws.ConnectedSeedProvider(
        clients=_clients(
            sts=Identity(
                route.MANAGEMENT_ACCOUNT_ID, "AWSAdministratorAccess", timeline
            ),
            cfn=LostCreateResponse(),
        ),
        claims=claims,
        clock=lambda: now,
    )
    initial_authorization = _creation_authorization(intent, target, now)
    with pytest.raises(
        aws.ConnectedRouteError, match="CREATE_CHANGE_SET_UNCERTAIN"
    ):
        first.create_change_set(
            seed_input=source,
            seed_intent=intent,
            git=FakeGit(),
            target=target,
            creation_authorization=initial_authorization,
        )
    assert timeline == ["sts", "claim", "mutate"]

    event = {
        "eventID": EVENT_UUID,
        "eventTime": _ts(now),
        "requestID": REQUEST_UUID,
        "eventSource": "cloudformation.amazonaws.com",
        "eventName": "CreateChangeSet",
        "awsRegion": route.REGION,
        "recipientAccountId": spec["account_id"],
        "readOnly": False,
        "userIdentity": {"arn": caller},
        "requestParameters": _cloudtrail_create_params(spec["create_request"]),
        "responseElements": {"id": change_set_arn, "stackId": stack_arn},
    }

    class RecoveryCloudFormation:
        def describe_change_set(self, **request: Any) -> dict[str, Any]:
            assert request == {
                "StackName": stack_arn,
                "ChangeSetName": change_set_arn,
            }
            return {
                "ChangeSetId": change_set_arn,
                "StackId": stack_arn,
                "StackName": spec["stack_name"],
                "ChangeSetName": spec["change_set_name"],
                "Description": spec["create_request"]["Description"],
                "ChangeSetType": spec["create_request"]["ChangeSetType"],
                    "Parameters": _observed_change_set_parameters(
                        spec["create_request"], target=target
                    ),
                "Capabilities": spec["create_request"]["Capabilities"],
                "Tags": spec["create_request"]["Tags"],
                "IncludeNestedStacks": False,
                "NotificationARNs": [],
                "RollbackConfiguration": spec["create_request"][
                    "RollbackConfiguration"
                ],
                "OnStackFailure": spec["create_request"]["OnStackFailure"],
            }

    # Recovery is read-only and remains causal after the mutation window has
    # closed.  It validates the original sealed authorization from the claim
    # at the original claim timestamp; it never extends creation authority.
    recovery_now = datetime.fromisoformat(
        intent["route_not_after"].replace("Z", "+00:00")
    ) + timedelta(seconds=1)
    recovered = aws.ConnectedSeedProvider(
        clients=_clients(
            sts=Identity(
                route.MANAGEMENT_ACCOUNT_ID, "AWSAdministratorAccess", timeline
            ),
            cfn=RecoveryCloudFormation(),
            trail=Trail(event),
        ),
        claims=claims,
        clock=lambda: recovery_now,
    ).recover_create_change_set(
        seed_intent=intent,
        target=target,
    )
    assert recovered["create_request_id"] == REQUEST_UUID
    assert recovered["dispatched_at"] == _ts(now)
    assert recovered["creation_authorization_digest"] == initial_authorization[
        "authorization_digest"
    ]
    assert recovered["creation_authorization"] == initial_authorization
    assert timeline.count("mutate") == 1
    assert timeline[-3:] == ["read-claim", "sts", "complete"]


def test_execute_recovery_uses_durable_claim_cloudtrail_and_stack_readback(
    case: tuple[dict[str, Any], dict[str, Any], datetime]
) -> None:
    source, intent, now = case
    attestation, execution_authorization, execution = _live_execution_records(
        source, intent, "route", now
    )
    timeline: list[str] = []
    claims = Claims(timeline)
    claims.seed_create_result(intent=intent, target="route", now=now)
    caller = (
        "arn:aws:sts::839393571433:assumed-role/"
        "AWSReservedSSO_AWSAdministratorAccess_0123456789abcdef/cesar"
    )

    dispatch = _dispatch(intent, "route", now)

    first = aws.ConnectedSeedProvider(
        clients=_clients(
            sts=Identity(
                route.MANAGEMENT_ACCOUNT_ID, "AWSAdministratorAccess", timeline
            ),
            cfn=ExecutingAttestCloudFormation(
                intent,
                dispatch,
                execution,
                timeline,
                template_body=_template_body(source, target="route"),
                execute_error=TimeoutError("response lost"),
            ),
            trail=Trail(_create_event(intent, dispatch, now), timeline),
        ),
        claims=claims,
        clock=lambda: now,
    )
    with pytest.raises(
        aws.ConnectedRouteError, match="EXECUTE_CHANGE_SET_UNCERTAIN"
    ):
        first.execute_change_set(
            seed_input=source,
            seed_intent=intent,
            git=FakeGit(),
            create_attestation=attestation,
            execution_authorization=execution_authorization,
            execution_intent=execution,
        )
    event = {
        "eventID": EVENT_UUID,
        "eventTime": _ts(now),
        "requestID": REQUEST_UUID,
        "eventSource": "cloudformation.amazonaws.com",
        "eventName": "ExecuteChangeSet",
        "awsRegion": route.REGION,
        "recipientAccountId": route.MANAGEMENT_ACCOUNT_ID,
        "readOnly": False,
        "userIdentity": {"arn": caller},
        "requestParameters": {
            "stackName": execution["execute_request"]["StackName"],
            "changeSetName": execution["execute_request"]["ChangeSetName"],
            "clientRequestToken": execution["execute_request"][
                "ClientRequestToken"
            ],
        },
        "responseElements": None,
    }

    class RecoveryCloudFormation:
        def describe_stacks(self, **request: Any) -> dict[str, Any]:
            assert request == {
                "StackName": execution["execute_request"]["StackName"]
            }
            return {
                "Stacks": [
                    {"StackId": execution["execute_request"]["StackName"]}
                ]
            }

    recovered = aws.ConnectedSeedProvider(
        clients=_clients(
            sts=Identity(
                route.MANAGEMENT_ACCOUNT_ID, "AWSAdministratorAccess", timeline
            ),
            cfn=RecoveryCloudFormation(),
            trail=Trail(event),
        ),
        claims=claims,
        clock=lambda: now,
    ).recover_execute_change_set(execution_intent=execution)
    assert recovered["execute_request_id"] == REQUEST_UUID
    assert recovered["dispatched_at"] == _ts(now)
    assert timeline.count("mutate") == 1
    assert timeline[-3:] == ["read-claim", "sts", "complete"]


def _dispatch(intent: Mapping[str, Any], target: str, now: datetime) -> dict[str, Any]:
    spec = intent["targets"][target]
    creation_authorization = _creation_authorization(
        intent, target, now - timedelta(minutes=1)
    )
    value = {
        "schema_version": 1,
        "record_type": aws.DISPATCH_RECORD_TYPE,
        "source_commit": SOURCE_COMMIT,
        "target": target,
        "account_id": spec["account_id"],
        "intent_digest": intent["intent_digest"],
        "create_request_digest": spec["create_request_digest"],
        "creation_authorization": creation_authorization,
        "creation_authorization_digest": creation_authorization[
            "authorization_digest"
        ],
        "stack_arn": (
            f"arn:aws:cloudformation:us-east-1:{spec['account_id']}:"
            f"stack/{spec['stack_name']}/{STACK_UUID}"
        ),
        "change_set_arn": (
            f"arn:aws:cloudformation:us-east-1:{spec['account_id']}:"
            f"changeSet/{spec['change_set_name']}/{CHANGE_UUID}"
        ),
        "create_request_id": REQUEST_UUID,
        "dispatched_at": _ts(now - timedelta(minutes=1)),
        "aws_mutations": 1,
        "retry_permitted": False,
        "production_authorized": False,
        "production_status": "NO-GO",
    }
    return route.seal(value, "dispatch_digest")


class AttestCloudFormation:
    def __init__(
        self,
        intent: Mapping[str, Any],
        dispatch: Mapping[str, Any],
        *,
        template_body: str | None = None,
    ) -> None:
        self.target = dispatch["target"]
        self.spec = intent["targets"][dispatch["target"]]
        self.dispatch = dispatch
        self.next_token: object | None = None
        self.template_body = template_body or (
            ROOT / route.ROUTE_TEMPLATE_PATH
        ).read_text()

    def describe_change_set(self, **request: Any) -> dict[str, Any]:
        assert request == {
            "StackName": self.dispatch["stack_arn"],
            "ChangeSetName": self.dispatch["change_set_arn"],
        }
        create = self.spec["create_request"]
        def update_details(logical_id: str) -> list[dict[str, Any]]:
            details: list[dict[str, Any]] = [
                {
                    "Target": {
                        "Attribute": "DeletionPolicy",
                    },
                    "Evaluation": "Static",
                    "ChangeSource": "DirectModification",
                },
                {
                    "Target": {
                        "Attribute": "UpdateReplacePolicy",
                    },
                    "Evaluation": "Static",
                    "ChangeSource": "DirectModification",
                },
            ]
            if logical_id == "BrokerLedger":
                details.append(
                    {
                        "Target": {
                            "Attribute": "Properties",
                            "Name": "DeletionProtectionEnabled",
                            "RequiresRecreation": "Never",
                        },
                        "Evaluation": "Static",
                        "ChangeSource": "DirectModification",
                    }
                )
            return details

        response = {
            "ChangeSetId": self.dispatch["change_set_arn"],
            "StackId": self.dispatch["stack_arn"],
            "StackName": self.spec["stack_name"],
            "ChangeSetName": self.spec["change_set_name"],
            "Status": "CREATE_COMPLETE",
            "ExecutionStatus": "AVAILABLE",
            "Description": create["Description"],
            "ChangeSetType": create["ChangeSetType"],
            "CreationTime": datetime.fromisoformat(
                self.dispatch["dispatched_at"].replace("Z", "+00:00")
            ),
            "Parameters": _observed_change_set_parameters(
                create, target=self.target
            ),
            "Capabilities": create["Capabilities"],
            "Tags": create["Tags"],
            "IncludeNestedStacks": False,
            "NotificationARNs": [],
            "RollbackConfiguration": create["RollbackConfiguration"],
            "Changes": [
                {
                    "Type": "Resource",
                    "ResourceChange": {
                        "Action": (
                            "Modify"
                            if create["ChangeSetType"] == "UPDATE"
                            else "Add"
                        ),
                        "LogicalResourceId": item["logical_resource_id"],
                        "ResourceType": item["resource_type"],
                        "Scope": (
                            sorted(
                                [
                                    "DeletionPolicy",
                                    "UpdateReplacePolicy",
                                    *(
                                        ["Properties"]
                                        if item["logical_resource_id"]
                                        == "BrokerLedger"
                                        else []
                                    ),
                                ]
                            )
                            if create["ChangeSetType"] == "UPDATE"
                            else []
                        ),
                        **(
                            {
                                "Replacement": "False",
                                "Details": update_details(
                                    item["logical_resource_id"]
                                ),
                            }
                            if create["ChangeSetType"] == "UPDATE"
                            else {}
                        ),
                    },
                }
                for item in self.spec["expected_changes"]
            ],
        }
        if create["ChangeSetType"] == "CREATE":
            response["OnStackFailure"] = create["OnStackFailure"]
        if self.next_token is not None:
            response["NextToken"] = self.next_token
        return response

    def get_template(self, **request: Any) -> dict[str, str]:
        assert request == {
            "ChangeSetName": self.dispatch["change_set_arn"],
            "TemplateStage": "Original",
        }
        return {"TemplateBody": self.template_body}


class ExecutingAttestCloudFormation(AttestCloudFormation):
    def __init__(
        self,
        intent: Mapping[str, Any],
        dispatch: Mapping[str, Any],
        execution: Mapping[str, Any],
        timeline: list[str],
        *,
        template_body: str,
        on_execute: Any = None,
        execute_error: Exception | None = None,
    ) -> None:
        super().__init__(intent, dispatch, template_body=template_body)
        self.execution = execution
        self.timeline = timeline
        self.on_execute = on_execute
        self.execute_error = execute_error

    def describe_change_set(self, **request: Any) -> dict[str, Any]:
        self.timeline.append("describe")
        return super().describe_change_set(**request)

    def get_template(self, **request: Any) -> dict[str, str]:
        self.timeline.append("template")
        return super().get_template(**request)

    def execute_change_set(self, **request: Any) -> dict[str, Any]:
        self.timeline.append("mutate")
        assert request == self.execution["execute_request"]
        if self.on_execute is not None:
            self.on_execute()
        if self.execute_error is not None:
            raise self.execute_error
        return {"ResponseMetadata": {"RequestId": REQUEST_UUID}}


class Trail:
    def __init__(
        self,
        event: Mapping[str, Any],
        timeline: list[str] | None = None,
    ) -> None:
        self.event = event
        self.timeline = timeline

    def lookup_events(self, **_request: Any) -> dict[str, Any]:
        if self.timeline is not None:
            self.timeline.append("cloudtrail")
        return {"Events": [{"CloudTrailEvent": json.dumps(self.event)}]}


def test_cloudtrail_pagination_reaches_second_page_and_rejects_token_cycles() -> None:
    class PagedTrail:
        def __init__(self, *, cycle: bool = False) -> None:
            self.cycle = cycle
            self.calls: list[dict[str, Any]] = []

        def lookup_events(self, **request: Any) -> dict[str, Any]:
            self.calls.append(request)
            if "NextToken" not in request:
                return {"Events": [], "NextToken": "page-2"}
            if self.cycle:
                return {"Events": [], "NextToken": "page-2"}
            return {
                "Events": [
                    {"CloudTrailEvent": json.dumps({"requestID": REQUEST_UUID})}
                ]
            }

    client = PagedTrail()
    events, page_count = aws._lookup_cloudtrail_events(
        client,
        request={"MaxResults": 50},
        error_code="CREATE_CLOUDTRAIL_AMBIGUOUS",
    )
    assert page_count == 2
    assert json.loads(events[0]["CloudTrailEvent"])["requestID"] == REQUEST_UUID
    assert client.calls[1]["NextToken"] == "page-2"
    with pytest.raises(
        aws.ConnectedRouteError, match="CREATE_CLOUDTRAIL_AMBIGUOUS"
    ):
        aws._lookup_cloudtrail_events(
            PagedTrail(cycle=True),
            request={"MaxResults": 50},
            error_code="CREATE_CLOUDTRAIL_AMBIGUOUS",
        )


@pytest.mark.parametrize("token", ["", 0, False, b"token", {}, []])
def test_cloudtrail_pagination_rejects_malformed_tokens(token: object) -> None:
    class MalformedTrail:
        def lookup_events(self, **_request: Any) -> dict[str, Any]:
            return {"Events": [], "NextToken": token}

    with pytest.raises(
        aws.ConnectedRouteError,
        match="CREATE_CLOUDTRAIL_AMBIGUOUS",
    ):
        aws._lookup_cloudtrail_events(
            MalformedTrail(),
            request={"MaxResults": 50},
            error_code="CREATE_CLOUDTRAIL_AMBIGUOUS",
        )


def test_tokenized_readback_pagination_exhausts_and_rejects_cycles() -> None:
    class PagedRead:
        def __init__(self, *, cycle: bool = False) -> None:
            self.cycle = cycle
            self.calls: list[dict[str, Any]] = []

        def list_items(self, **request: Any) -> dict[str, Any]:
            self.calls.append(request)
            if "Marker" not in request:
                return {
                    "Items": [{"id": "first"}],
                    "NextMarker": "page-2",
                    "Truncated": True,
                }
            if self.cycle:
                return {
                    "Items": [],
                    "NextMarker": "page-2",
                    "Truncated": True,
                }
            return {"Items": [{"id": "second"}], "Truncated": False}

    client = PagedRead()
    items, page_count = aws._paginate_tokenized_items(
        client.list_items,
        request={"Limit": 100},
        item_key="Items",
        request_token_key="Marker",
        response_token_key="NextMarker",
        truncated_key="Truncated",
        error_code="PAGINATED_READBACK_INVALID",
    )
    assert items == [{"id": "first"}, {"id": "second"}]
    assert page_count == 2
    assert client.calls[1]["Marker"] == "page-2"
    with pytest.raises(
        aws.ConnectedRouteError, match="PAGINATED_READBACK_INVALID"
    ):
        aws._paginate_tokenized_items(
            PagedRead(cycle=True).list_items,
            request={"Limit": 100},
            item_key="Items",
            request_token_key="Marker",
            response_token_key="NextMarker",
            truncated_key="Truncated",
            error_code="PAGINATED_READBACK_INVALID",
        )


@pytest.mark.parametrize(
    ("token", "truncated"),
    [
        (None, True),
        ("", True),
        (0, True),
        (False, True),
        (b"token", True),
        ({}, True),
        ([], True),
        ("unexpected", False),
    ],
)
def test_tokenized_readback_rejects_malformed_or_inconsistent_tokens(
    token: object, truncated: bool
) -> None:
    class MalformedReadback:
        def list_items(self, **_request: Any) -> dict[str, Any]:
            return {
                "Items": [],
                "NextMarker": token,
                "Truncated": truncated,
            }

    with pytest.raises(
        aws.ConnectedRouteError,
        match="PAGINATED_READBACK_INVALID",
    ):
        aws._paginate_tokenized_items(
            MalformedReadback().list_items,
            request={"Limit": 100},
            item_key="Items",
            request_token_key="Marker",
            response_token_key="NextMarker",
            truncated_key="Truncated",
            error_code="PAGINATED_READBACK_INVALID",
        )


@pytest.mark.parametrize(
    ("target", "phase", "account", "role"),
    [
        (
            "route",
            "creator",
            route.MANAGEMENT_ACCOUNT_ID,
            "AWSAdministratorAccess",
        ),
        (
            "broker",
            "creator",
            route.AUTHORITY_ACCOUNT_ID,
            "ScanalyzeGug376BrokerSeedCreator",
        ),
        (
            "broker",
            "executor",
            route.AUTHORITY_ACCOUNT_ID,
            "ScanalyzeGug376BrokerSeedExec",
        ),
        (
            route.BROKER_PROTECTION_TARGET,
            "creator",
            route.AUTHORITY_ACCOUNT_ID,
            "ScanalyzeGug376BrokerSeedCreator",
        ),
        (
            route.BROKER_PROTECTION_TARGET,
            "executor",
            route.AUTHORITY_ACCOUNT_ID,
            "ScanalyzeGug376BrokerSeedExec",
        ),
    ],
)
def test_sso_role_suffix_accepts_uppercase_hex(
    target: str, phase: str, account: str, role: str
) -> None:
    expected_account, pattern = aws._role_pattern(target=target, phase=phase)
    assert expected_account == account
    assert pattern.fullmatch(
        f"arn:aws:sts::{account}:assumed-role/"
        f"AWSReservedSSO_{role}_ABCDEF0123456789/cesar"
    )


def test_create_attestation_binds_full_cloudtrail_request_template_and_changes(
    case: tuple[dict[str, Any], dict[str, Any], datetime]
) -> None:
    _source, intent, now = case
    target = "route"
    dispatch = _dispatch(intent, target, now)
    create = intent["targets"][target]["create_request"]
    caller = (
        "arn:aws:sts::839393571433:assumed-role/"
        "AWSReservedSSO_AWSAdministratorAccess_0123456789abcdef/cesar"
    )
    event = {
        "eventID": EVENT_UUID,
        "eventTime": _ts(now - timedelta(seconds=30)),
        "requestID": REQUEST_UUID,
        "eventSource": "cloudformation.amazonaws.com",
        "eventName": "CreateChangeSet",
        "awsRegion": route.REGION,
        "recipientAccountId": route.MANAGEMENT_ACCOUNT_ID,
        "readOnly": False,
        "userIdentity": {"arn": caller},
        "requestParameters": _cloudtrail_create_params(create),
        "responseElements": {
            "id": dispatch["change_set_arn"],
            "stackId": dispatch["stack_arn"],
        },
    }
    provider = aws.ConnectedSeedProvider(
        clients=_clients(
            sts=Identity(
                route.MANAGEMENT_ACCOUNT_ID, "AWSAdministratorAccess", []
            ),
            cfn=AttestCloudFormation(intent, dispatch),
            trail=Trail(event),
        ),
        claims=Claims([]),
        clock=lambda: now,
    )
    receipt = provider.attest_change_set(
        seed_intent=intent, dispatch_receipt=dispatch
    )
    assert receipt["status"] == "CREATE_COMPLETE"
    assert receipt["template_digest"] == intent["targets"][target]["template_digest"]
    incomplete = AttestCloudFormation(intent, dispatch)
    incomplete.next_token = ""
    provider = aws.ConnectedSeedProvider(
        clients=_clients(
            sts=Identity(
                route.MANAGEMENT_ACCOUNT_ID, "AWSAdministratorAccess", []
            ),
            cfn=incomplete,
            trail=Trail(event),
        ),
        claims=Claims([]),
        clock=lambda: now,
    )
    with pytest.raises(
        aws.ConnectedRouteError,
        match="CHANGE_SET_READBACK_INCOMPLETE",
    ):
        provider.attest_change_set(
            seed_intent=intent,
            dispatch_receipt=dispatch,
        )
    drifted = copy.deepcopy(event)
    drifted["requestParameters"].pop("onStackFailure")
    provider = aws.ConnectedSeedProvider(
        clients=_clients(
            sts=Identity(
                route.MANAGEMENT_ACCOUNT_ID, "AWSAdministratorAccess", []
            ),
            cfn=AttestCloudFormation(intent, dispatch),
            trail=Trail(drifted),
        ),
        claims=Claims([]),
        clock=lambda: now,
    )
    with pytest.raises(aws.ConnectedRouteError, match="CREATE_CLOUDTRAIL_INVALID"):
        provider.attest_change_set(seed_intent=intent, dispatch_receipt=dispatch)


def test_broker_protection_attestation_accepts_only_exact_dual_template_update(
    case: tuple[dict[str, Any], dict[str, Any], datetime]
) -> None:
    source, intent, now = case
    target = route.BROKER_PROTECTION_TARGET
    dispatch = _dispatch(intent, target, now)
    create = intent["targets"][target]["create_request"]
    caller = (
        "arn:aws:sts::042360977644:assumed-role/"
        "AWSReservedSSO_ScanalyzeGug376BrokerSeedCreator_"
        "0123456789abcdef/cesar"
    )
    event = {
        "eventID": EVENT_UUID,
        "eventTime": _ts(now - timedelta(seconds=30)),
        "requestID": REQUEST_UUID,
        "eventSource": "cloudformation.amazonaws.com",
        "eventName": "CreateChangeSet",
        "awsRegion": route.REGION,
        "recipientAccountId": route.AUTHORITY_ACCOUNT_ID,
        "readOnly": False,
        "userIdentity": {"arn": caller},
        "requestParameters": _cloudtrail_create_params(create),
        "responseElements": {
            "id": dispatch["change_set_arn"],
            "stackId": dispatch["stack_arn"],
        },
    }
    receipt = aws.ConnectedSeedProvider(
        clients=_clients(
            sts=Identity(
                route.AUTHORITY_ACCOUNT_ID,
                "ScanalyzeGug376BrokerSeedCreator",
                [],
            ),
            cfn=AttestCloudFormation(
                intent,
                dispatch,
                template_body=FakeGit()
                .render_broker_seed(
                    source["broker_seed_input"], protection_enabled=True
                )
                .decode("utf-8"),
            ),
            trail=Trail(event),
        ),
        claims=Claims([]),
        clock=lambda: now,
    ).attest_change_set(
        seed_intent=intent, dispatch_receipt=dispatch
    )
    assert receipt["target"] == target
    assert receipt["status"] == "CREATE_COMPLETE"
    assert receipt["changes_digest"] == route.digest_value(
        intent["targets"][target]["expected_changes"]
    )

    class ParameterReferenceDrift(AttestCloudFormation):
        def describe_change_set(self, **request: Any) -> dict[str, Any]:
            response = super().describe_change_set(**request)
            detail = response["Changes"][0]["ResourceChange"]["Details"][0]
            detail["ChangeSource"] = "ParameterReference"
            detail["CausingEntity"] = "BrokerLedgerDeletionProtectionEnabled"
            return response

    with pytest.raises(
        aws.ConnectedRouteError, match="CHANGE_SET_CHANGES_INVALID"
    ):
        aws.ConnectedSeedProvider(
            clients=_clients(
                sts=Identity(
                    route.AUTHORITY_ACCOUNT_ID,
                    "ScanalyzeGug376BrokerSeedCreator",
                    [],
                ),
                cfn=ParameterReferenceDrift(
                    intent,
                    dispatch,
                    template_body=FakeGit()
                    .render_broker_seed(
                        source["broker_seed_input"],
                        protection_enabled=True,
                    )
                    .decode("utf-8"),
                ),
                trail=Trail(event),
            ),
            claims=Claims([]),
            clock=lambda: now,
        ).attest_change_set(
            seed_intent=intent,
            dispatch_receipt=dispatch,
        )


def _route_outputs() -> dict[str, str]:
    ps_prefix = f"arn:aws:sso:::permissionSet/ssoins-ABCDEFGHIJKLMNOP/"
    return {
        "ManagementBrokerCreatorRoleArn": (
            "arn:aws:iam::839393571433:role/scanalyze/platform-authority/"
            "ScanalyzeGug376RouteBrokerCreator"
        ),
        "ManagementBrokerExecutorRoleArn": (
            "arn:aws:iam::839393571433:role/scanalyze/platform-authority/"
            "ScanalyzeGug376RouteBrokerExecutor"
        ),
        "BrokerSeedCreatorPermissionSetArn": ps_prefix + "ps-AAAAAAAAAAAAAAAA",
        "BrokerSeedExecutorPermissionSetArn": ps_prefix + "ps-BBBBBBBBBBBBBBBB",
        "BrokerInvokerPermissionSetArn": ps_prefix + "ps-CCCCCCCCCCCCCCCC",
        "SeedAssignmentMode": "true",
        "BrokerInvokerAssignmentMode": "true",
        "CleanupOrder": "SEED_FALSE_KEEP_INVOKER_THEN_CLOSEOUT_FALSE_FALSE",
        "BrokerStackName": route.BROKER_STACK_NAME,
        "ProductionAuthorized": "false",
    }


class TerminalRouteCloudFormation:
    def __init__(
        self,
        intent: Mapping[str, Any],
        execution: Mapping[str, Any],
        dispatched_at: datetime,
        *,
        no_echo_mask: str = "*****",
    ) -> None:
        self.spec = intent["targets"]["route"]
        self.execution = execution
        self.dispatched_at = dispatched_at
        self.no_echo_mask = no_echo_mask
        self.stack_next_token: object | None = None
        self.resource_next_token: object | None = None

    def describe_stacks(self, **_request: Any) -> dict[str, Any]:
        outputs = _route_outputs()
        response = {
            "Stacks": [
                {
                    "StackId": self.execution["execute_request"]["StackName"],
                    "StackName": route.ROUTE_STACK_NAME,
                    "StackStatus": "CREATE_COMPLETE",
                    "CreationTime": self.dispatched_at,
                    "NotificationARNs": [],
                    "Capabilities": ["CAPABILITY_NAMED_IAM"],
                    "Tags": route.EXACT_TAGS,
                    "Parameters": [
                        {
                            "ParameterKey": item["ParameterKey"],
                            "ParameterValue": (
                                self.no_echo_mask
                                if item["ParameterKey"]
                                in route.ROUTE_NO_ECHO_PARAMETER_KEYS
                                else item["ParameterValue"]
                            ),
                        }
                        for item in self.spec["create_request"].get(
                            "Parameters", []
                        )
                    ],
                    "EnableTerminationProtection": False,
                    "Outputs": [
                        {"OutputKey": key, "OutputValue": value}
                        for key, value in outputs.items()
                    ],
                }
            ]
        }
        if self.stack_next_token is not None:
            response["NextToken"] = self.stack_next_token
        return response

    def list_stack_resources(self, **_request: Any) -> dict[str, Any]:
        response = {
            "StackResourceSummaries": [
                {
                    "LogicalResourceId": item["logical_resource_id"],
                    "ResourceType": item["resource_type"],
                    "PhysicalResourceId": "physical-" + item["logical_resource_id"],
                    "ResourceStatus": "CREATE_COMPLETE",
                }
                for item in self.spec["expected_resources"]
            ]
        }
        if self.resource_next_token is not None:
            response["NextToken"] = self.resource_next_token
        return response

    def get_template(self, **_request: Any) -> dict[str, str]:
        return {"TemplateBody": (ROOT / route.ROUTE_TEMPLATE_PATH).read_text()}


class Assignments:
    def __init__(self, contracts: Mapping[str, Mapping[str, Any]]) -> None:
        self.by_arn = {
            str(contract["permission_set_arn"]): contract
            for contract in contracts.values()
        }

    def _contract(self, request: Mapping[str, Any]) -> Mapping[str, Any]:
        return self.by_arn[str(request["PermissionSetArn"])]

    def describe_permission_set(self, **request: Any) -> dict[str, Any]:
        contract = self._contract(request)
        return {
            "PermissionSet": {
                "PermissionSetArn": contract["permission_set_arn"],
                "Name": contract["name"],
                "SessionDuration": contract["session_duration"],
            }
        }

    def get_inline_policy_for_permission_set(
        self, **request: Any
    ) -> dict[str, str]:
        return {
            "InlinePolicy": json.dumps(self._contract(request)["inline_policy"])
        }

    def get_permissions_boundary_for_permission_set(
        self, **_request: Any
    ) -> dict[str, Any]:
        return {}

    def list_managed_policies_in_permission_set(
        self, **_request: Any
    ) -> dict[str, Any]:
        return {"AttachedManagedPolicies": []}

    def list_customer_managed_policy_references_in_permission_set(
        self, **_request: Any
    ) -> dict[str, Any]:
        return {"CustomerManagedPolicyReferences": []}

    def list_tags_for_resource(self, **request: Any) -> dict[str, Any]:
        contract = self.by_arn[str(request["ResourceArn"])]
        return {"Tags": copy.deepcopy(contract["tags"])}

    def list_account_assignments(self, **request: Any) -> dict[str, Any]:
        return {
            "AccountAssignments": [
                {
                    "AccountId": route.AUTHORITY_ACCOUNT_ID,
                    "PermissionSetArn": request["PermissionSetArn"],
                    "PrincipalId": PRINCIPAL_ID,
                    "PrincipalType": "USER",
                }
            ]
        }


def _execution_receipt(execution: Mapping[str, Any], now: datetime) -> dict[str, Any]:
    value = {
        "schema_version": 1,
        "record_type": aws.EXECUTION_RECEIPT_RECORD_TYPE,
        "source_commit": SOURCE_COMMIT,
        "target": execution["target"],
        "account_id": execution["account_id"],
        "execution_intent_digest": execution["execution_intent_digest"],
        "stack_arn": execution["execute_request"]["StackName"],
        "change_set_arn": execution["execute_request"]["ChangeSetName"],
        "execute_request_id": REQUEST_UUID,
        "dispatched_at": _ts(now),
        "aws_mutations": 1,
        "retry_permitted": False,
        "production_authorized": False,
        "production_status": "NO-GO",
    }
    return route.seal(value, "receipt_digest")


def _reentry_execution(
    intent: Mapping[str, Any], target: str, now: datetime
) -> dict[str, Any]:
    spec = intent["targets"][target]
    stack_arn = (
        f"arn:aws:cloudformation:{route.REGION}:{spec['account_id']}:"
        f"stack/{spec['stack_name']}/{STACK_UUID}"
    )
    change_set_arn = (
        f"arn:aws:cloudformation:{route.REGION}:{spec['account_id']}:"
        "changeSet/"
        f"{recovery.REENTRY_CHANGE_SET_NAMES[target]}/{CHANGE_UUID}"
    )
    operation_digest = route.digest_value(
        {
            "record_type": recovery.REENTRY_EXECUTION_INTENT_RECORD_TYPE,
            "source_commit": SOURCE_COMMIT,
            "target": target,
            "stack_arn": stack_arn,
            "change_set_arn": change_set_arn,
            "attempt": 1,
        }
    )
    request: dict[str, Any] = {
        "StackName": stack_arn,
        "ChangeSetName": change_set_arn,
        "ClientRequestToken": "gug376-" + operation_digest[7:55],
    }
    if target == route.BROKER_PROTECTION_TARGET:
        request["DisableRollback"] = False
    value = {
        "schema_version": 1,
        "record_type": recovery.REENTRY_EXECUTION_INTENT_RECORD_TYPE,
        "source_commit": SOURCE_COMMIT,
        "target": target,
        "account_id": spec["account_id"],
        "parent_intent_digest": intent["intent_digest"],
        "reentry_intent_digest": "sha256:" + "5" * 64,
        "reentry_attestation_digest": "sha256:" + "6" * 64,
        "authorization_digest": "sha256:" + "7" * 64,
        "authorization_not_before": _ts(now),
        "authorization_expires_at": _ts(now + timedelta(minutes=10)),
        "route_not_before": intent["route_not_before"],
        "route_not_after": intent["route_not_after"],
        "recovery_not_after": intent["recovery_not_after"],
        "attempt": 1,
        "execute_operation_digest": operation_digest,
        "execute_request": request,
        "execute_request_digest": route.digest_value(request),
        "aws_calls": 0,
        "aws_mutations": 0,
        "retry_permitted": False,
        "production_authorized": False,
        "production_status": route.PRODUCTION_STATUS,
    }
    return route.seal(value, "execution_intent_digest")


def _reentry_execution_receipt(
    execution: Mapping[str, Any], now: datetime
) -> dict[str, Any]:
    return route.seal(
        {
            "schema_version": 1,
            "record_type": recovery.REENTRY_EXECUTION_RECEIPT_RECORD_TYPE,
            "source_commit": SOURCE_COMMIT,
            "target": execution["target"],
            "account_id": execution["account_id"],
            "execution_intent_digest": execution["execution_intent_digest"],
            "stack_arn": execution["execute_request"]["StackName"],
            "change_set_arn": execution["execute_request"]["ChangeSetName"],
            "execute_request_id": REQUEST_UUID,
            "dispatched_at": _ts(now),
            "attempt": 1,
            "aws_mutations": 1,
            "retry_permitted": False,
            "production_authorized": False,
            "production_status": route.PRODUCTION_STATUS,
        },
        "receipt_digest",
    )


def test_terminal_route_readback_binds_execute_cloudtrail_and_three_assignments(
    case: tuple[dict[str, Any], dict[str, Any], datetime]
) -> None:
    _source, intent, now = case
    execution = _execution(intent, "route", now)
    receipt = _execution_receipt(execution, now)
    caller = (
        "arn:aws:sts::839393571433:assumed-role/"
        "AWSReservedSSO_AWSAdministratorAccess_0123456789abcdef/cesar"
    )
    event = {
        "eventID": EVENT_UUID,
        # CloudTrail observes the request after the pre-call receipt boundary
        # but before the SDK response/terminal readback completes.
        "eventTime": _ts(now + timedelta(seconds=10)),
        "requestID": REQUEST_UUID,
        "eventSource": "cloudformation.amazonaws.com",
        "eventName": "ExecuteChangeSet",
        "awsRegion": route.REGION,
        "recipientAccountId": route.MANAGEMENT_ACCOUNT_ID,
        "readOnly": False,
        "userIdentity": {"arn": caller},
        "requestParameters": {
            "stackName": execution["execute_request"]["StackName"],
            "changeSetName": execution["execute_request"]["ChangeSetName"],
            "clientRequestToken": execution["execute_request"]["ClientRequestToken"],
        },
        "responseElements": None,
    }
    provider = aws.ConnectedSeedProvider(
        clients=_clients(
            sts=Identity(
                route.MANAGEMENT_ACCOUNT_ID, "AWSAdministratorAccess", []
            ),
            cfn=TerminalRouteCloudFormation(
                intent, execution, now + timedelta(seconds=10)
            ),
            trail=Trail(event),
            sso=Assignments(
                aws._route_permission_set_contracts(
                    template_body=(ROOT / route.ROUTE_TEMPLATE_PATH).read_text(),
                    create_parameters=intent["targets"]["route"][
                        "create_request"
                    ].get("Parameters", []),
                    outputs=_route_outputs(),
                )
            ),
        ),
        claims=Claims([]),
        clock=lambda: now + timedelta(seconds=30),
    )
    terminal = provider.terminal_readback(
        seed_intent=intent,
        execution_intent=execution,
        execution_receipt=receipt,
    )
    assert terminal["assignment_count"] == 3
    assert terminal["resource_count"] == 8
    assert terminal["aws_calls"] == 26
    assert terminal["execute_cloudtrail_event_digest"].startswith("sha256:")
    assert terminal["live_property_read_count"] == 18
    provider._cfn.stack_next_token = ""  # noqa: SLF001
    with pytest.raises(
        aws.ConnectedRouteError,
        match="TERMINAL_READBACK_INCOMPLETE",
    ):
        provider.terminal_readback(
            seed_intent=intent,
            execution_intent=execution,
            execution_receipt=receipt,
        )
    provider._cfn.stack_next_token = None  # noqa: SLF001
    provider._cfn.resource_next_token = 0  # noqa: SLF001
    with pytest.raises(
        aws.ConnectedRouteError,
        match="TERMINAL_RESOURCES_INCOMPLETE",
    ):
        provider.terminal_readback(
            seed_intent=intent,
            execution_intent=execution,
            execution_receipt=receipt,
        )


def test_terminal_route_readback_accepts_only_exact_claim_bound_reentry(
    case: tuple[dict[str, Any], dict[str, Any], datetime]
) -> None:
    _source, intent, now = case
    execution = _reentry_execution(intent, "route", now)
    receipt = _reentry_execution_receipt(execution, now)
    caller = (
        "arn:aws:sts::839393571433:assumed-role/"
        "AWSReservedSSO_AWSAdministratorAccess_0123456789abcdef/cesar"
    )
    event = {
        "eventID": EVENT_UUID,
        "eventTime": _ts(now + timedelta(seconds=10)),
        "requestID": REQUEST_UUID,
        "eventSource": "cloudformation.amazonaws.com",
        "eventName": "ExecuteChangeSet",
        "awsRegion": route.REGION,
        "recipientAccountId": route.MANAGEMENT_ACCOUNT_ID,
        "readOnly": False,
        "errorCode": None,
        "errorMessage": None,
        "userIdentity": {"arn": caller},
        "requestParameters": {
            "stackName": execution["execute_request"]["StackName"],
            "changeSetName": execution["execute_request"]["ChangeSetName"],
            "clientRequestToken": execution["execute_request"][
                "ClientRequestToken"
            ],
        },
        "responseElements": None,
    }
    timeline: list[str] = []
    claims = Claims(timeline)
    claim_key = (
        "reentry-execute:route:"
        f"{execution['parent_intent_digest']}"
    )
    claims.records[claim_key] = {
        "schema_version": 1,
        "record_type": recovery.CLAIM_RECORD_TYPE,
        "operation": "ExecuteChangeSet",
        "target": "route",
        "attempt": 1,
        "execution_intent_digest": execution["execution_intent_digest"],
        "request_digest": execution["execute_request_digest"],
        "client_request_token": execution["execute_request"][
            "ClientRequestToken"
        ],
        "stack_arn": receipt["stack_arn"],
        "change_set_arn": receipt["change_set_arn"],
        "caller_arn_digest": route.digest_value(caller),
        "claimed_at": _ts(now),
        "retry_permitted": False,
        "production_authorized": False,
    }
    provider = aws.ConnectedSeedProvider(
        clients=_clients(
            sts=Identity(
                route.MANAGEMENT_ACCOUNT_ID,
                "AWSAdministratorAccess",
                timeline,
            ),
            cfn=TerminalRouteCloudFormation(
                intent,
                execution,
                now + timedelta(seconds=10),
            ),
            trail=Trail(event),
            sso=Assignments(
                aws._route_permission_set_contracts(
                    template_body=(ROOT / route.ROUTE_TEMPLATE_PATH).read_text(),
                    create_parameters=intent["targets"]["route"][
                        "create_request"
                    ].get("Parameters", []),
                    outputs=_route_outputs(),
                )
            ),
        ),
        claims=claims,
        clock=lambda: now + timedelta(seconds=30),
    )
    terminal = provider.terminal_readback(
        seed_intent=intent,
        execution_intent=execution,
        execution_receipt=receipt,
    )
    assert terminal["stack_status"] == "CREATE_COMPLETE"
    assert "read-claim" in timeline

    changed = copy.deepcopy(receipt)
    changed["attempt"] = 2
    changed.pop("receipt_digest")
    changed = route.seal(changed, "receipt_digest")
    timeline_before = list(timeline)
    with pytest.raises(
        aws.ConnectedRouteError, match="EXECUTION_RECEIPT_INVALID"
    ):
        provider.terminal_readback(
            seed_intent=intent,
            execution_intent=execution,
            execution_receipt=changed,
        )
    assert timeline == timeline_before


class TerminalBrokerCloudFormation:
    def __init__(
        self,
        *,
        intent: Mapping[str, Any],
        execution: Mapping[str, Any],
        dispatched_at: datetime,
        template_body: str,
    ) -> None:
        self.target = str(execution["target"])
        self.spec = intent["targets"][self.target]
        self.execution = execution
        self.dispatched_at = dispatched_at
        self.template_body = template_body

    def describe_stacks(self, **_request: Any) -> dict[str, Any]:
        protection = self.target == route.BROKER_PROTECTION_TARGET
        stack: dict[str, Any] = {
            "StackId": self.execution["execute_request"]["StackName"],
            "StackName": route.BROKER_STACK_NAME,
            "StackStatus": (
                "UPDATE_COMPLETE" if protection else "CREATE_COMPLETE"
            ),
            "NotificationARNs": [],
            "Capabilities": ["CAPABILITY_NAMED_IAM"],
            "Tags": route.EXACT_TAGS,
            "Parameters": self.spec["create_request"].get("Parameters", []),
            "EnableTerminationProtection": False,
            "Outputs": [
                {"OutputKey": key, "OutputValue": value}
                for key, value in {
                    "BrokerLedgerName": (
                        "scanalyze-platform-authority-gug376-route-broker-ledger"
                    ),
                    "CreatorFunctionArn": (
                        "arn:aws:lambda:us-east-1:042360977644:function:"
                        "scanalyze-platform-authority-gug376-route-creator"
                    ),
                    "ExecutorFunctionArn": (
                        "arn:aws:lambda:us-east-1:042360977644:function:"
                        "scanalyze-platform-authority-gug376-route-executor"
                    ),
                    "CreateDispatchRecoveryAliasArn": (
                        "arn:aws:lambda:us-east-1:042360977644:function:"
                        "scanalyze-platform-authority-gug376-route-"
                        "create-dispatch-recovery:recover-v1"
                    ),
                    "ExecuteDispatchRecoveryAliasArn": (
                        "arn:aws:lambda:us-east-1:042360977644:function:"
                        "scanalyze-platform-authority-gug376-route-"
                        "execute-dispatch-recovery:recover-v1"
                    ),
                    "ManagementCreatorRoleArn": (
                        "arn:aws:iam::839393571433:role/scanalyze/"
                        "platform-authority/ScanalyzeGug376RouteBrokerCreator"
                    ),
                    "ManagementExecutorRoleArn": (
                        "arn:aws:iam::839393571433:role/scanalyze/"
                        "platform-authority/ScanalyzeGug376RouteBrokerExecutor"
                    ),
                    "ManagementRecoveryRoleArn": (
                        "arn:aws:iam::839393571433:role/scanalyze/"
                        "platform-authority/ScanalyzeGug376RouteBrokerRecovery"
                    ),
                    "ParametersAccepted": "false",
                    "BrokerLedgerDeletionProtectionMode": (
                        "true" if protection else "false"
                    ),
                    "ProductionAuthorized": "false",
                }.items()
            ],
        }
        stack[
            "LastUpdatedTime" if protection else "CreationTime"
        ] = self.dispatched_at
        return {"Stacks": [stack]}

    def list_stack_resources(self, **_request: Any) -> dict[str, Any]:
        protection = self.target == route.BROKER_PROTECTION_TARGET
        return {
            "StackResourceSummaries": [
                {
                    "LogicalResourceId": item["logical_resource_id"],
                    "ResourceType": item["resource_type"],
                    "PhysicalResourceId": "physical-"
                    + item["logical_resource_id"],
                    "ResourceStatus": (
                        "UPDATE_COMPLETE"
                        if protection
                        and item["logical_resource_id"] == "BrokerLedger"
                        else "CREATE_COMPLETE"
                    ),
                }
                for item in self.spec["expected_resources"]
            ]
        }

    def get_template(self, **_request: Any) -> dict[str, str]:
        return {"TemplateBody": self.template_body}


@pytest.mark.parametrize(
    ("target", "expected_status", "expected_protection"),
    [
        ("broker", "CREATE_COMPLETE", False),
        (route.BROKER_PROTECTION_TARGET, "UPDATE_COMPLETE", True),
    ],
)
def test_broker_terminal_status_and_live_protection_match_operation(
    case: tuple[dict[str, Any], dict[str, Any], datetime],
    target: str,
    expected_status: str,
    expected_protection: bool,
) -> None:
    source, intent, now = case
    execution = _execution(intent, target, now)
    receipt = _execution_receipt(execution, now)
    caller = (
        "arn:aws:sts::042360977644:assumed-role/"
        "AWSReservedSSO_ScanalyzeGug376BrokerSeedExec_"
        "0123456789abcdef/cesar"
    )
    params = {
        "stackName": execution["execute_request"]["StackName"],
        "changeSetName": execution["execute_request"]["ChangeSetName"],
        "clientRequestToken": execution["execute_request"][
            "ClientRequestToken"
        ],
    }
    if "DisableRollback" in execution["execute_request"]:
        params["disableRollback"] = False
    event = {
        "eventID": EVENT_UUID,
        "eventTime": _ts(now + timedelta(seconds=10)),
        "requestID": REQUEST_UUID,
        "eventSource": "cloudformation.amazonaws.com",
        "eventName": "ExecuteChangeSet",
        "awsRegion": route.REGION,
        "recipientAccountId": route.AUTHORITY_ACCOUNT_ID,
        "readOnly": False,
        "userIdentity": {"arn": caller},
        "requestParameters": params,
        "responseElements": None,
    }
    rendered = FakeGit().render_broker_seed(
        source["broker_seed_input"],
        protection_enabled=(target == route.BROKER_PROTECTION_TARGET),
    )
    provider = aws.ConnectedSeedProvider(
        clients=_clients(
            sts=Identity(
                route.AUTHORITY_ACCOUNT_ID,
                "ScanalyzeGug376BrokerSeedExec",
                [],
            ),
            cfn=TerminalBrokerCloudFormation(
                intent=intent,
                execution=execution,
                dispatched_at=now,
                template_body=rendered.decode("utf-8"),
            ),
            trail=Trail(event),
        ),
        claims=Claims([]),
        clock=lambda: now + timedelta(seconds=30),
    )
    observed: list[bool] = []
    provider._broker_live_readback = (  # type: ignore[method-assign]
        lambda **kwargs: (
            observed.append(kwargs["expected_deletion_protection"])
            or "sha256:"
            + "9" * 64,
            1,
        )
    )
    terminal = provider.terminal_readback(
        seed_intent=intent,
        execution_intent=execution,
        execution_receipt=receipt,
    )
    assert terminal["stack_status"] == expected_status
    assert observed == [expected_protection]


def _live_tags(logical_id: str) -> list[dict[str, str]]:
    return sorted(
        route.EXACT_TAGS
        + [
            {"Key": "component", "Value": "gug376-route-broker"},
            {"Key": "environment", "Value": "non-production"},
            {"Key": "production", "Value": "false"},
            {"Key": "source_commit", "Value": SOURCE_COMMIT},
            {
                "Key": "aws:cloudformation:logical-id",
                "Value": logical_id,
            },
            {
                "Key": "aws:cloudformation:stack-id",
                "Value": BROKER_STACK_ARN,
            },
            {
                "Key": "aws:cloudformation:stack-name",
                "Value": route.BROKER_STACK_NAME,
            },
        ],
        key=lambda item: item["Key"],
    )


class LiveLambda:
    code_signing_arn = (
        "arn:aws:lambda:us-east-1:042360977644:code-signing-config:csc-0123456789abcdef0"
    )

    def __init__(
        self,
        spec: Mapping[str, Any],
        *,
        runtime_config_json: str,
        concurrency: int = 1,
        public_policy: bool = False,
        public_policy_qualifier: str | None = None,
        function_tags: Mapping[str, str] | None = None,
        weighted_alias: bool = False,
        package_type: str = "Zip",
        provisioned_concurrency: bool = False,
    ) -> None:
        self.spec = spec
        self.runtime_config_json = runtime_config_json
        self.concurrency = concurrency
        self.public_policy = public_policy
        self.public_policy_qualifier = public_policy_qualifier
        self.function_tags = (
            dict(function_tags) if function_tags is not None else None
        )
        self.weighted_alias = weighted_alias
        self.package_type = package_type
        self.provisioned_concurrency = provisioned_concurrency

    @staticmethod
    def _creator(name: str) -> bool:
        return name.endswith("-creator")

    @staticmethod
    def _function_contract(name: str) -> tuple[str, str, str]:
        if name.endswith("-creator"):
            return (
                "CreatorFunction",
                "ScanalyzeGug376RouteBrokerCreator",
                "creator_handler",
            )
        if name.endswith("-executor"):
            return (
                "ExecutorFunction",
                "ScanalyzeGug376RouteBrokerExecutor",
                "executor_handler",
            )
        if name.endswith("-create-dispatch-recovery"):
            return (
                "CreateDispatchRecoveryFunction",
                "ScanalyzeGug376RouteCreateDispatchRecovery",
                "create_dispatch_recovery_handler",
            )
        if name.endswith("-execute-dispatch-recovery"):
            return (
                "ExecuteDispatchRecoveryFunction",
                "ScanalyzeGug376RouteExecuteDispatchRecovery",
                "execute_dispatch_recovery_handler",
            )
        raise AssertionError(name)

    @staticmethod
    def _version_label(name: str) -> str:
        if name.endswith("-creator"):
            return "creator"
        if name.endswith("-executor"):
            return "executor"
        if name.endswith("-create-dispatch-recovery"):
            return "create dispatch recovery"
        if name.endswith("-execute-dispatch-recovery"):
            return "execute dispatch recovery"
        raise AssertionError(name)

    @staticmethod
    def _aliases(name: str) -> tuple[str, ...]:
        if name.endswith("-dispatch-recovery"):
            return ("recover-v1",)
        if name.endswith("-creator"):
            return (
                "seed-revoke-create-v1",
                "delegation-create-v1",
                "pep-create-v1",
                "pep-protection-create-v1",
                "closeout-gate-v1",
                "delegation-revoke-create-v1",
                "route-revoke-create-v1",
            )
        return (
            "seed-revoke-execute-v1",
            "delegation-execute-v1",
            "pep-execute-v1",
            "pep-protection-execute-v1",
            "delegation-revoke-execute-v1",
            "route-revoke-execute-v1",
        )

    def get_code_signing_config(self, **_request: Any) -> dict[str, Any]:
        return {
            "CodeSigningConfig": {
                "CodeSigningConfigId": "csc-0123456789abcdef0",
                "CodeSigningConfigArn": self.code_signing_arn,
                "Description": "GUG-376 route broker signed code only",
                "AllowedPublishers": {
                    "SigningProfileVersionArns": [
                        self.spec["broker_signing_profile_version_arn"]
                    ]
                },
                "CodeSigningPolicies": {
                    "UntrustedArtifactOnDeployment": "Enforce"
                },
            }
        }

    def get_function(
        self, *, FunctionName: str, Qualifier: str | None = None
    ) -> dict[str, Any]:
        logical_id, role, handler_name = self._function_contract(FunctionName)
        handler = (
            "tooling.platform_authority_plan_permission_repair_route_broker."
            + handler_name
        )
        function_arn = (
            f"arn:aws:lambda:us-east-1:042360977644:function:{FunctionName}"
        )
        return {
            "Code": {
                "RepositoryType": "S3",
                "Location": "https://awslambda-us-east-1-tasks.s3.amazonaws.com/signed",
            },
            "Configuration": {
                "FunctionName": FunctionName,
                "FunctionArn": (
                    function_arn
                    + (f":{Qualifier}" if Qualifier is not None else "")
                ),
                "Runtime": "python3.12",
                "Handler": handler,
                "Role": f"arn:aws:iam::042360977644:role/{role}",
                "CodeSha256": self.spec["broker_code_sha256"],
                "Timeout": 900,
                "MemorySize": 256,
                "TracingConfig": {"Mode": "Active"},
                "State": "Active",
                "LastUpdateStatus": "Successful",
                "Architectures": ["x86_64"],
                "Version": Qualifier if Qualifier is not None else "$LATEST",
                "PackageType": self.package_type,
                "Description": (
                    f"GUG-376 {self._version_label(FunctionName)} "
                    f"{SOURCE_COMMIT} {self.spec['broker_config_digest']}"
                    if Qualifier is not None
                    else ""
                ),
                "EphemeralStorage": {"Size": 512},
                "SnapStart": {"ApplyOn": "None", "OptimizationStatus": "Off"},
                "VpcConfig": {
                    "SubnetIds": [],
                    "SecurityGroupIds": [],
                    "VpcId": "",
                    "Ipv6AllowedForDualStack": False,
                },
                "LoggingConfig": {
                    "LogFormat": "Text",
                    "LogGroup": f"/aws/lambda/{FunctionName}",
                },
                "RuntimeVersionConfig": {
                    "RuntimeVersionArn": (
                        "arn:aws:lambda:us-east-1::runtime:" + "a" * 64
                    )
                },
                "Environment": {
                    "Variables": {
                        "LEDGER_TABLE_NAME": (
                            "scanalyze-platform-authority-gug376-route-broker-ledger"
                        ),
                        "BROKER_LEDGER_KEY_ARN": (
                            "arn:aws:kms:us-east-1:042360977644:key/"
                            "77777777-7777-4777-8777-777777777777"
                        ),
                        "BROKER_CONFIG_JSON": self.runtime_config_json,
                    }
                },
            }
        }

    def get_function_concurrency(self, **_request: Any) -> dict[str, int]:
        return {"ReservedConcurrentExecutions": self.concurrency}

    def get_runtime_management_config(
        self, *, FunctionName: str, Qualifier: str | None = None
    ) -> dict[str, str]:
        return {
            "FunctionArn": (
                f"arn:aws:lambda:us-east-1:042360977644:function:{FunctionName}"
                + (f":{Qualifier}" if Qualifier is not None else "")
            ),
            "UpdateRuntimeOn": "FunctionUpdate",
        }

    def get_function_code_signing_config(self, **_request: Any) -> dict[str, str]:
        return {"CodeSigningConfigArn": self.code_signing_arn}

    def list_tags(self, *, Resource: str) -> dict[str, dict[str, str]]:
        logical_id, _role, _handler = self._function_contract(Resource)
        tags = (
            self.function_tags
            if self.function_tags is not None
            else {item["Key"]: item["Value"] for item in _live_tags(logical_id)}
        )
        return {"Tags": copy.deepcopy(tags)}

    def list_provisioned_concurrency_configs(
        self, *, FunctionName: str, **_request: Any
    ) -> dict[str, Any]:
        return {
            "ProvisionedConcurrencyConfigs": (
                [
                    {
                        "FunctionArn": (
                            f"arn:aws:lambda:us-east-1:042360977644:function:"
                            f"{FunctionName}:1"
                        ),
                        "RequestedProvisionedConcurrentExecutions": 1,
                        "AvailableProvisionedConcurrentExecutions": 1,
                        "AllocatedProvisionedConcurrentExecutions": 1,
                        "Status": "READY",
                    }
                ]
                if self.provisioned_concurrency
                else []
            )
        }

    def list_versions_by_function(self, *, FunctionName: str, **_request: Any) -> dict[str, Any]:
        return {
            "Versions": [
                {
                    "FunctionName": FunctionName,
                    "Version": "$LATEST",
                    "CodeSha256": self.spec["broker_code_sha256"],
                },
                {
                    "FunctionName": FunctionName,
                    "Version": "1",
                    "CodeSha256": self.spec["broker_code_sha256"],
                    "Description": (
                        f"GUG-376 {self._version_label(FunctionName)} "
                        f"{SOURCE_COMMIT} {self.spec['broker_config_digest']}"
                    ),
                },
            ]
        }

    def list_aliases(self, *, FunctionName: str, **_request: Any) -> dict[str, Any]:
        return {
            "Aliases": [
                {
                    "AliasArn": (
                        f"arn:aws:lambda:us-east-1:042360977644:function:"
                        f"{FunctionName}:{alias}"
                    ),
                    "Description": "",
                    "Name": alias,
                    "FunctionVersion": "1",
                    "RevisionId": f"revision-{alias}",
                    "RoutingConfig": (
                        {"AdditionalVersionWeights": {"2": 0.1}}
                        if self.weighted_alias and alias == self._aliases(FunctionName)[0]
                        else {}
                    ),
                }
                for alias in self._aliases(FunctionName)
            ]
        }

    def get_alias(self, *, FunctionName: str, Name: str) -> dict[str, Any]:
        return next(
            item
            for item in self.list_aliases(FunctionName=FunctionName)["Aliases"]
            if item["Name"] == Name
        )

    def get_function_event_invoke_config(
        self, *, FunctionName: str, Qualifier: str
    ) -> dict[str, Any]:
        return {
            "FunctionArn": (
                f"arn:aws:lambda:us-east-1:042360977644:function:"
                f"{FunctionName}:{Qualifier}"
            ),
            "MaximumRetryAttempts": 0,
            "MaximumEventAgeInSeconds": 60,
            "DestinationConfig": {},
        }

    def get_policy(self, **request: Any) -> dict[str, str]:
        if self.public_policy or (
            self.public_policy_qualifier is not None
            and request.get("Qualifier") == self.public_policy_qualifier
        ):
            return {"Policy": json.dumps({"Statement": [{"Effect": "Allow"}]})}

        class ResourceNotFoundException(Exception):
            def __init__(self) -> None:
                self.response = {
                    "Error": {"Code": "ResourceNotFoundException"},
                    "ResponseMetadata": {"HTTPStatusCode": 404},
                }

        raise ResourceNotFoundException()

    def list_function_url_configs(self, **_request: Any) -> dict[str, Any]:
        return {"FunctionUrlConfigs": []}

    def list_event_source_mappings(self, **_request: Any) -> dict[str, Any]:
        return {"EventSourceMappings": []}


class LiveIam:
    def __init__(self, projection: Mapping[str, Any]) -> None:
        self.projection = projection

    @staticmethod
    def _policy_name(role_name: str) -> str:
        return {
            "ScanalyzeGug376RouteBrokerCreator": "ExactBrokerCreation",
            "ScanalyzeGug376RouteBrokerExecutor": "ExactBrokerExecution",
            "ScanalyzeGug376RouteCreateDispatchRecovery": (
                "ExactCreateDispatchRecoveryReadback"
            ),
            "ScanalyzeGug376RouteExecuteDispatchRecovery": (
                "ExactExecuteDispatchRecoveryReadback"
            ),
        }[role_name]

    @staticmethod
    def _logical_id(role_name: str) -> str:
        return {
            "ScanalyzeGug376RouteBrokerCreator": "CreatorRole",
            "ScanalyzeGug376RouteBrokerExecutor": "ExecutorRole",
            "ScanalyzeGug376RouteCreateDispatchRecovery": (
                "CreateDispatchRecoveryRole"
            ),
            "ScanalyzeGug376RouteExecuteDispatchRecovery": (
                "ExecuteDispatchRecoveryRole"
            ),
        }[role_name]

    @staticmethod
    def _projection_name(role_name: str) -> str:
        return {
            "ScanalyzeGug376RouteBrokerCreator": "creator_role_inline_policy",
            "ScanalyzeGug376RouteBrokerExecutor": "executor_role_inline_policy",
            "ScanalyzeGug376RouteCreateDispatchRecovery": (
                "create_dispatch_recovery_role_inline_policy"
            ),
            "ScanalyzeGug376RouteExecuteDispatchRecovery": (
                "execute_dispatch_recovery_role_inline_policy"
            ),
        }[role_name]

    def get_role(self, *, RoleName: str) -> dict[str, Any]:
        return {
            "Role": {
                "RoleName": RoleName,
                "Path": "/",
                "Arn": f"arn:aws:iam::042360977644:role/{RoleName}",
                "MaxSessionDuration": 3600,
                "AssumeRolePolicyDocument": {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Principal": {"Service": "lambda.amazonaws.com"},
                            "Action": "sts:AssumeRole",
                        }
                    ],
                },
                "Tags": _live_tags(self._logical_id(RoleName)),
            }
        }

    def list_role_policies(self, *, RoleName: str) -> dict[str, Any]:
        return {
            "PolicyNames": [self._policy_name(RoleName)],
            "IsTruncated": False,
        }

    def list_attached_role_policies(self, **_request: Any) -> dict[str, Any]:
        return {"AttachedPolicies": [], "IsTruncated": False}

    def get_role_policy(self, *, RoleName: str, PolicyName: str) -> dict[str, Any]:
        assert PolicyName == self._policy_name(RoleName)
        projection_name = self._projection_name(RoleName)
        return {
            "RoleName": RoleName,
            "PolicyName": PolicyName,
            "PolicyDocument": copy.deepcopy(
                self.projection["policies"][projection_name]["document"]
            ),
        }


class LiveDynamo:
    table_name = "scanalyze-platform-authority-gug376-route-broker-ledger"
    table_arn = f"arn:aws:dynamodb:us-east-1:042360977644:table/{table_name}"

    def __init__(self, projection: Mapping[str, Any]) -> None:
        self.projection = projection

    def describe_table(self, **_request: Any) -> dict[str, Any]:
        return {
            "Table": {
                "TableName": self.table_name,
                "TableArn": self.table_arn,
                "TableStatus": "ACTIVE",
                "BillingModeSummary": {"BillingMode": "PAY_PER_REQUEST"},
                "AttributeDefinitions": [
                    {"AttributeName": "ledger_id", "AttributeType": "S"}
                ],
                "KeySchema": [{"AttributeName": "ledger_id", "KeyType": "HASH"}],
                "DeletionProtectionEnabled": True,
                "SSEDescription": {
                    "Status": "ENABLED",
                    "SSEType": "KMS",
                    "KMSMasterKeyArn": (
                        "arn:aws:kms:us-east-1:042360977644:key/"
                        + LiveKms.key_id
                    ),
                },
            }
        }

    def describe_time_to_live(self, **_request: Any) -> dict[str, Any]:
        return {"TimeToLiveDescription": {"TimeToLiveStatus": "DISABLED"}}

    def describe_continuous_backups(self, **_request: Any) -> dict[str, Any]:
        return {
            "ContinuousBackupsDescription": {
                "ContinuousBackupsStatus": "ENABLED",
                "PointInTimeRecoveryDescription": {
                    "PointInTimeRecoveryStatus": "ENABLED",
                    "RecoveryPeriodInDays": 35,
                },
            }
        }

    def get_resource_policy(self, **_request: Any) -> dict[str, str]:
        return {
            "Policy": json.dumps(
                self.projection["policies"][
                    "broker_ledger_resource_policy"
                ]["document"]
            )
        }

    def list_tags_of_resource(self, **_request: Any) -> dict[str, Any]:
        return {"Tags": _live_tags("BrokerLedger")}


class LiveKms:
    key_id = "77777777-7777-4777-8777-777777777777"

    def __init__(
        self,
        projection: Mapping[str, Any],
        *,
        foreign_grant: bool = False,
        service_principal_fields: bool = False,
    ) -> None:
        self.projection = projection
        self.foreign_grant = foreign_grant
        self.service_principal_fields = service_principal_fields

    def describe_key(self, **_request: Any) -> dict[str, Any]:
        return {
            "KeyMetadata": {
                "AWSAccountId": route.AUTHORITY_ACCOUNT_ID,
                "KeyId": self.key_id,
                "Arn": f"arn:aws:kms:us-east-1:042360977644:key/{self.key_id}",
                "Enabled": True,
                "KeyState": "Enabled",
                "KeyUsage": "ENCRYPT_DECRYPT",
                "Origin": "AWS_KMS",
                "KeyManager": "CUSTOMER",
                "MultiRegion": False,
                "Description": "GUG-376 route broker CAS ledger",
                "KeySpec": "SYMMETRIC_DEFAULT",
                "EncryptionAlgorithms": ["SYMMETRIC_DEFAULT"],
            }
        }

    def get_key_rotation_status(self, **_request: Any) -> dict[str, Any]:
        return {"KeyRotationEnabled": True, "RotationPeriodInDays": 365}

    def get_key_policy(self, **_request: Any) -> dict[str, str]:
        return {
            "Policy": json.dumps(
                self.projection["policies"]["broker_ledger_key_policy"][
                    "document"
                ]
            )
        }

    def list_resource_tags(self, **_request: Any) -> dict[str, Any]:
        return {
            "Tags": [
                {"TagKey": item["Key"], "TagValue": item["Value"]}
                for item in _live_tags("BrokerLedgerKey")
            ]
        }

    def list_aliases(self, **_request: Any) -> dict[str, Any]:
        return {
            "Aliases": [
                {
                    "AliasName": (
                        "alias/scanalyze/platform-authority/"
                        "gug376-route-broker-ledger"
                    ),
                    "AliasArn": (
                        "arn:aws:kms:us-east-1:042360977644:"
                        "alias/scanalyze/platform-authority/"
                        "gug376-route-broker-ledger"
                    ),
                    "TargetKeyId": self.key_id,
                }
            ],
            "Truncated": False,
        }

    def list_grants(self, **_request: Any) -> dict[str, Any]:
        dynamodb_principal = "dynamodb.us-east-1.amazonaws.com"
        principal_fields = (
            {
                "GranteeServicePrincipal": (
                    "lambda.amazonaws.com"
                    if self.foreign_grant
                    else dynamodb_principal
                ),
                "RetiringServicePrincipal": dynamodb_principal,
            }
            if self.service_principal_fields
            else {
                "GranteePrincipal": (
                    "lambda.amazonaws.com"
                    if self.foreign_grant
                    else dynamodb_principal
                ),
                "RetiringPrincipal": dynamodb_principal,
            }
        )
        return {
            "Grants": [
                {
                    "KeyId": (
                        f"arn:aws:kms:us-east-1:042360977644:key/{self.key_id}"
                    ),
                    "GrantId": "grant-77777777-7777-4777-8777-777777777777",
                    "Name": "",
                    "IssuingAccount": "arn:aws:iam::042360977644:root",
                    "Operations": [
                        "Decrypt",
                        "DescribeKey",
                        "Encrypt",
                        "GenerateDataKey",
                        "ReEncryptFrom",
                        "ReEncryptTo",
                        "RetireGrant",
                    ],
                    "Constraints": {
                        "EncryptionContextSubset": {
                            "aws:dynamodb:subscriberId": "042360977644",
                            "aws:dynamodb:tableName": (
                                "scanalyze-platform-authority-gug376-"
                                "route-broker-ledger"
                            ),
                        }
                    },
                    **principal_fields,
                }
            ],
            "Truncated": False,
        }


class LiveLogs:
    def __init__(
        self,
        *,
        tags: Mapping[str, str] | None = None,
        subscription: bool = False,
        resource_policy: bool = False,
        account_relevant_policy: bool = False,
    ) -> None:
        self.tags = dict(tags) if tags is not None else None
        self.subscription = subscription
        self.resource_policy = resource_policy
        self.account_relevant_policy = account_relevant_policy

    def describe_log_groups(self, **_request: Any) -> dict[str, Any]:
        names = (
            "/aws/lambda/scanalyze-platform-authority-gug376-route-creator",
            "/aws/lambda/scanalyze-platform-authority-gug376-route-executor",
            "/aws/lambda/scanalyze-platform-authority-gug376-route-create-dispatch-recovery",
            "/aws/lambda/scanalyze-platform-authority-gug376-route-execute-dispatch-recovery",
        )
        return {
            "logGroups": [
                {
                    "logGroupName": name,
                    "arn": f"arn:aws:logs:us-east-1:042360977644:log-group:{name}:*",
                    "logGroupArn": f"arn:aws:logs:us-east-1:042360977644:log-group:{name}",
                    "logGroupClass": "STANDARD",
                    "retentionInDays": 30,
                }
                for name in names
            ]
        }

    def list_tags_for_resource(self, *, resourceArn: str) -> dict[str, Any]:
        logical_id = {
            "-creator": "CreatorLogGroup",
            "-executor": "ExecutorLogGroup",
            "-create-dispatch-recovery": "CreateDispatchRecoveryLogGroup",
            "-execute-dispatch-recovery": "ExecuteDispatchRecoveryLogGroup",
        }[next(suffix for suffix in (
            "-create-dispatch-recovery",
            "-execute-dispatch-recovery",
            "-creator",
            "-executor",
        ) if resourceArn.endswith(suffix))]
        tags = (
            self.tags
            if self.tags is not None
            else {item["Key"]: item["Value"] for item in _live_tags(logical_id)}
        )
        return {"tags": copy.deepcopy(tags)}

    def describe_subscription_filters(
        self, *, logGroupName: str, **_request: Any
    ) -> dict[str, Any]:
        return {
            "subscriptionFilters": (
                [
                    {
                        "filterName": "unexpected-export",
                        "logGroupName": logGroupName,
                        "destinationArn": (
                            "arn:aws:lambda:us-east-1:042360977644:"
                            "function:unexpected-export"
                        ),
                    }
                ]
                if self.subscription
                else []
            )
        }

    def describe_resource_policies(
        self,
        *,
        policyScope: str,
        resourceArn: str | None = None,
        **_request: Any,
    ) -> dict[str, Any]:
        if policyScope == "RESOURCE":
            policies = (
                [
                    {
                        "policyName": "unexpected-resource-policy",
                        "policyDocument": json.dumps(
                            {
                                "Version": "2012-10-17",
                                "Statement": [
                                    {
                                        "Effect": "Allow",
                                        "Principal": {"Service": "es.amazonaws.com"},
                                        "Action": "logs:PutLogEvents",
                                        "Resource": f"{resourceArn}:*",
                                    }
                                ],
                            }
                        ),
                        "policyScope": "RESOURCE",
                        "resourceArn": resourceArn,
                        "revisionId": "resource-policy-revision",
                    }
                ]
                if self.resource_policy
                else []
            )
        elif policyScope == "ACCOUNT":
            target_arn = (
                "arn:aws:logs:us-east-1:042360977644:log-group:"
                + (
                    "/aws/lambda/scanalyze-platform-authority-"
                    "gug376-route-creator:*"
                    if self.account_relevant_policy
                    else "/aws/lambda/unrelated-function:*"
                )
            )
            policies = [
                {
                    "policyName": "account-log-delivery-policy",
                    "policyDocument": json.dumps(
                        {
                            "Version": "2012-10-17",
                            "Statement": [
                                {
                                    "Effect": "Allow",
                                    "Principal": {"Service": "es.amazonaws.com"},
                                    "Action": "logs:PutLogEvents",
                                    "Resource": target_arn,
                                }
                            ],
                        }
                    ),
                    "policyScope": "ACCOUNT",
                    "lastUpdatedTime": 1,
                }
            ]
        else:
            raise AssertionError(policyScope)
        return {"resourcePolicies": policies}


def _live_resources() -> dict[str, dict[str, str]]:
    return {
        "BrokerCodeSigningConfig": {"PhysicalResourceId": LiveLambda.code_signing_arn},
        "CreatorFunction": {
            "PhysicalResourceId": "scanalyze-platform-authority-gug376-route-creator"
        },
        "ExecutorFunction": {
            "PhysicalResourceId": "scanalyze-platform-authority-gug376-route-executor"
        },
        "CreateDispatchRecoveryFunction": {
            "PhysicalResourceId": (
                "scanalyze-platform-authority-gug376-route-create-dispatch-recovery"
            )
        },
        "ExecuteDispatchRecoveryFunction": {
            "PhysicalResourceId": (
                "scanalyze-platform-authority-gug376-route-execute-dispatch-recovery"
            )
        },
        "CreatorRole": {"PhysicalResourceId": "ScanalyzeGug376RouteBrokerCreator"},
        "ExecutorRole": {"PhysicalResourceId": "ScanalyzeGug376RouteBrokerExecutor"},
        "CreateDispatchRecoveryRole": {
            "PhysicalResourceId": "ScanalyzeGug376RouteCreateDispatchRecovery"
        },
        "ExecuteDispatchRecoveryRole": {
            "PhysicalResourceId": "ScanalyzeGug376RouteExecuteDispatchRecovery"
        },
        "BrokerLedger": {"PhysicalResourceId": LiveDynamo.table_name},
        "BrokerLedgerKey": {"PhysicalResourceId": LiveKms.key_id},
        "BrokerLedgerKeyAlias": {
            "PhysicalResourceId": (
                "alias/scanalyze/platform-authority/"
                "gug376-route-broker-ledger"
            )
        },
        "CreatorLogGroup": {
            "PhysicalResourceId": (
                "/aws/lambda/scanalyze-platform-authority-gug376-route-creator"
            )
        },
        "ExecutorLogGroup": {
            "PhysicalResourceId": (
                "/aws/lambda/scanalyze-platform-authority-gug376-route-executor"
            )
        },
        "CreateDispatchRecoveryLogGroup": {
            "PhysicalResourceId": (
                "/aws/lambda/scanalyze-platform-authority-gug376-route-"
                "create-dispatch-recovery"
            )
        },
        "ExecuteDispatchRecoveryLogGroup": {
            "PhysicalResourceId": (
                "/aws/lambda/scanalyze-platform-authority-gug376-route-"
                "execute-dispatch-recovery"
            )
        },
    }


def test_broker_terminal_live_readback_covers_runtime_iam_ledger_kms_and_logs(
    case: tuple[dict[str, Any], dict[str, Any], datetime],
) -> None:
    source, intent, _now = case
    runtime_config_json = broker.canonical_json(
        broker.encode_runtime_config(source["broker_seed_input"]["broker_config"])
    )
    spec = intent["targets"]["broker"]
    projection = spec["broker_effective_policy_projection"]
    clients = _clients(sts=object(), cfn=object())
    clients.update(
        {
            "lambda": LiveLambda(
                spec, runtime_config_json=runtime_config_json
            ),
            "iam": LiveIam(projection),
            "dynamodb": LiveDynamo(projection),
            "kms": LiveKms(projection),
            "logs": LiveLogs(),
        }
    )
    provider = aws.ConnectedSeedProvider(
        clients=clients, claims=Claims([]), clock=lambda: datetime.now(timezone.utc)
    )
    digest, calls = provider._broker_live_readback(
        seed=intent,
        spec=spec,
        resources=_live_resources(),
        stack_arn=BROKER_STACK_ARN,
        expected_deletion_protection=True,
    )
    assert digest.startswith("sha256:")
    assert calls == 143
    clients["kms"] = LiveKms(projection, service_principal_fields=True)
    provider = aws.ConnectedSeedProvider(
        clients=clients, claims=Claims([]), clock=lambda: datetime.now(timezone.utc)
    )
    service_principal_digest, service_principal_calls = provider._broker_live_readback(
        seed=intent,
        spec=spec,
        resources=_live_resources(),
        stack_arn=BROKER_STACK_ARN,
    )
    assert service_principal_digest == digest
    assert service_principal_calls == 143
    clients["kms"] = LiveKms(projection)
    clients["lambda"] = LiveLambda(
        spec, runtime_config_json=runtime_config_json, concurrency=2
    )
    provider = aws.ConnectedSeedProvider(
        clients=clients, claims=Claims([]), clock=lambda: datetime.now(timezone.utc)
    )
    with pytest.raises(aws.ConnectedRouteError, match="BROKER_FUNCTION_LIVE_INVALID"):
        provider._broker_live_readback(
            seed=intent,
            spec=spec,
            resources=_live_resources(),
            stack_arn=BROKER_STACK_ARN,
        )
    clients["lambda"] = LiveLambda(
        spec,
        runtime_config_json=runtime_config_json,
        provisioned_concurrency=True,
    )
    provider = aws.ConnectedSeedProvider(
        clients=clients, claims=Claims([]), clock=lambda: datetime.now(timezone.utc)
    )
    with pytest.raises(
        aws.ConnectedRouteError,
        match="BROKER_FUNCTION_PROVISIONED_CONCURRENCY_INVALID",
    ):
        provider._broker_live_readback(
            seed=intent,
            spec=spec,
            resources=_live_resources(),
            stack_arn=BROKER_STACK_ARN,
        )
    clients["lambda"] = LiveLambda(
        spec,
        runtime_config_json=runtime_config_json,
        public_policy_qualifier="1",
    )
    provider = aws.ConnectedSeedProvider(
        clients=clients, claims=Claims([]), clock=lambda: datetime.now(timezone.utc)
    )
    with pytest.raises(
        aws.ConnectedRouteError,
        match="BROKER_FUNCTION_INVOCATION_AUTHORITY_INVALID",
    ):
        provider._broker_live_readback(
            seed=intent,
            spec=spec,
            resources=_live_resources(),
            stack_arn=BROKER_STACK_ARN,
        )
    clients["lambda"] = LiveLambda(
        spec,
        runtime_config_json=runtime_config_json,
        function_tags={},
    )
    provider = aws.ConnectedSeedProvider(
        clients=clients, claims=Claims([]), clock=lambda: datetime.now(timezone.utc)
    )
    with pytest.raises(aws.ConnectedRouteError, match="BROKER_FUNCTION_LIVE_INVALID"):
        provider._broker_live_readback(
            seed=intent,
            spec=spec,
            resources=_live_resources(),
            stack_arn=BROKER_STACK_ARN,
        )
    clients["lambda"] = LiveLambda(
        spec,
        runtime_config_json=runtime_config_json,
        weighted_alias=True,
    )
    provider = aws.ConnectedSeedProvider(
        clients=clients, claims=Claims([]), clock=lambda: datetime.now(timezone.utc)
    )
    with pytest.raises(
        aws.ConnectedRouteError, match="BROKER_FUNCTION_ALIASES_INVALID"
    ):
        provider._broker_live_readback(
            seed=intent,
            spec=spec,
            resources=_live_resources(),
            stack_arn=BROKER_STACK_ARN,
        )
    clients["lambda"] = LiveLambda(
        spec,
        runtime_config_json=runtime_config_json,
        package_type="Image",
    )
    provider = aws.ConnectedSeedProvider(
        clients=clients, claims=Claims([]), clock=lambda: datetime.now(timezone.utc)
    )
    with pytest.raises(aws.ConnectedRouteError, match="BROKER_FUNCTION_LIVE_INVALID"):
        provider._broker_live_readback(
            seed=intent,
            spec=spec,
            resources=_live_resources(),
            stack_arn=BROKER_STACK_ARN,
        )
    clients["lambda"] = LiveLambda(
        spec, runtime_config_json=runtime_config_json
    )
    clients["kms"] = LiveKms(projection, foreign_grant=True)
    provider = aws.ConnectedSeedProvider(
        clients=clients, claims=Claims([]), clock=lambda: datetime.now(timezone.utc)
    )
    with pytest.raises(aws.ConnectedRouteError, match="BROKER_KMS_GRANTS_INVALID"):
        provider._broker_live_readback(
            seed=intent,
            spec=spec,
            resources=_live_resources(),
            stack_arn=BROKER_STACK_ARN,
        )
    clients["kms"] = LiveKms(projection)
    clients["logs"] = LiveLogs(subscription=True)
    provider = aws.ConnectedSeedProvider(
        clients=clients, claims=Claims([]), clock=lambda: datetime.now(timezone.utc)
    )
    with pytest.raises(
        aws.ConnectedRouteError, match="BROKER_LOG_SUBSCRIPTIONS_INVALID"
    ):
        provider._broker_live_readback(
            seed=intent,
            spec=spec,
            resources=_live_resources(),
            stack_arn=BROKER_STACK_ARN,
        )
    clients["logs"] = LiveLogs(resource_policy=True)
    provider = aws.ConnectedSeedProvider(
        clients=clients, claims=Claims([]), clock=lambda: datetime.now(timezone.utc)
    )
    with pytest.raises(
        aws.ConnectedRouteError, match="BROKER_LOG_RESOURCE_POLICIES_INVALID"
    ):
        provider._broker_live_readback(
            seed=intent,
            spec=spec,
            resources=_live_resources(),
            stack_arn=BROKER_STACK_ARN,
        )
    clients["logs"] = LiveLogs(account_relevant_policy=True)
    provider = aws.ConnectedSeedProvider(
        clients=clients, claims=Claims([]), clock=lambda: datetime.now(timezone.utc)
    )
    with pytest.raises(
        aws.ConnectedRouteError, match="BROKER_LOG_RESOURCE_POLICIES_INVALID"
    ):
        provider._broker_live_readback(
            seed=intent,
            spec=spec,
            resources=_live_resources(),
            stack_arn=BROKER_STACK_ARN,
        )
    clients["lambda"] = LiveLambda(
        spec, runtime_config_json=runtime_config_json
    )
    clients["logs"] = LiveLogs(tags={})
    provider = aws.ConnectedSeedProvider(
        clients=clients, claims=Claims([]), clock=lambda: datetime.now(timezone.utc)
    )
    with pytest.raises(aws.ConnectedRouteError, match="BROKER_LOG_GROUPS_INVALID"):
        provider._broker_live_readback(
            seed=intent,
            spec=spec,
            resources=_live_resources(),
            stack_arn=BROKER_STACK_ARN,
        )
    clients["lambda"] = LiveLambda(
        spec,
        runtime_config_json=runtime_config_json,
        public_policy=True,
    )
    clients["logs"] = LiveLogs()
    provider = aws.ConnectedSeedProvider(
        clients=clients, claims=Claims([]), clock=lambda: datetime.now(timezone.utc)
    )
    with pytest.raises(
        aws.ConnectedRouteError,
        match="BROKER_FUNCTION_INVOCATION_AUTHORITY_INVALID",
    ):
        provider._broker_live_readback(
            seed=intent,
            spec=spec,
            resources=_live_resources(),
            stack_arn=BROKER_STACK_ARN,
        )


def test_change_set_readback_requires_exact_route_parameter_values(
    case: tuple[dict[str, Any], dict[str, Any], datetime]
) -> None:
    _source, intent, _now = case
    request = intent["targets"]["route"]["create_request"]
    observed = _observed_change_set_parameters(request, target="route")
    assert aws._change_set_parameters_match(
        observed, request["Parameters"], target="route"
    )
    changed = copy.deepcopy(observed)
    for item in changed:
        if item["ParameterKey"] == "BootstrapPrincipalId":
            item["ParameterValue"] = "87654321-4321-4321-8321-210987654321"
            break
    assert not aws._change_set_parameters_match(
        changed, request["Parameters"], target="route"
    )


def _cloudtrail_create_params(request: Mapping[str, Any]) -> dict[str, Any]:
    result = {
        "stackName": request["StackName"],
        "changeSetName": request["ChangeSetName"],
        "changeSetType": request["ChangeSetType"],
        "description": request["Description"],
        "templateURL": request["TemplateURL"],
        "capabilities": request["Capabilities"],
        "tags": [
            {"key": item["Key"], "value": item["Value"]}
            for item in request["Tags"]
        ],
        "includeNestedStacks": False,
        "notificationARNs": [],
        "rollbackConfiguration": {
            "rollbackTriggers": [],
            "monitoringTimeInMinutes": 0,
        },
        "clientToken": request["ClientToken"],
    }
    if "Parameters" in request:
        result["parameters"] = [
            {"parameterKey": item["ParameterKey"]}
            for item in request["Parameters"]
        ]
    if "OnStackFailure" in request:
        result["onStackFailure"] = request["OnStackFailure"]
    return result


def test_sdk_is_lazy_zero_retry_and_clis_have_only_seed_commands(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, Any] = {}

    class Config:
        def __init__(self, **kwargs: Any) -> None:
            captured.update(kwargs)

    aws.sdk_client_config(Config)
    assert captured == {
        "connect_timeout": 3,
        "read_timeout": 8,
        "retries": {"total_max_attempts": 1, "mode": "standard"},
        "ignore_configured_endpoint_urls": True,
    }
    for path, expected, forbidden in (
        (
            OFFLINE_CLI,
            {
                "materialize-seeds",
                "validate-intent",
                "authorize-creation",
                "authorize-execution",
                "materialize-execution-intent",
                "materialize-broker-config",
            },
            {"delegation", "pep", "revoke", "capture"},
        ),
        (
            AWS_CLI,
            {
                "create-change-set",
                "recover-create-change-set",
                "attest-change-set",
                "execute-change-set",
                "recover-execute-change-set",
                "terminal-readback",
            },
            {"capture-delegation-readback", "create-execution-intent"},
        ),
    ):
        completed = subprocess.run(
            [sys.executable, os.fspath(path), "--help"],
            cwd=ROOT,
            check=True,
            capture_output=True,
            text=True,
        )
        assert all(item in completed.stdout for item in expected)
        assert not any(item in completed.stdout for item in forbidden)
    recover_help = subprocess.run(
        [
            sys.executable,
            os.fspath(AWS_CLI),
            "recover-create-change-set",
            "--help",
        ],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    assert "--authorization-name" not in recover_help.stdout
    create_help = subprocess.run(
        [
            sys.executable,
            os.fspath(AWS_CLI),
            "create-change-set",
            "--help",
        ],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    assert "--input-name" in create_help.stdout
    assert "--intent-name" in create_help.stdout
    assert "--authorization-name" in create_help.stdout
    execute_help = subprocess.run(
        [
            sys.executable,
            os.fspath(AWS_CLI),
            "execute-change-set",
            "--help",
        ],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    assert "--input-name" in execute_help.stdout
    assert "--intent-name" in execute_help.stdout
    assert "--create-attestation-name" in execute_help.stdout
    assert "--authorization-name" in execute_help.stdout
    assert "--execution-intent-name" in execute_help.stdout
    config_help = subprocess.run(
        [
            sys.executable,
            os.fspath(OFFLINE_CLI),
            "materialize-broker-config",
            "--help",
        ],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    assert "--plan-snapshot-name" in config_help.stdout
    source = "\n".join(
        [
            (ROOT / "tooling/platform_authority_plan_permission_repair_deployment_route.py").read_text(),
            (ROOT / "tooling/platform_authority_plan_permission_repair_deployment_route_aws.py").read_text(),
        ]
    )
    assert "import boto3" not in source


class _SdkBoundarySession:
    def __init__(
        self,
        *,
        profile: str = "839393571433_AWSAdministratorAccess",
        role: str = "AWSAdministratorAccess",
        credential_method: str = "sso",
    ) -> None:
        self.profile_name = profile
        self.region_name = route.REGION
        self.credential_method = credential_method
        self.client_names: list[str] = []
        self._session = SimpleNamespace(
            full_config={
                "profiles": {
                    profile: {
                        "region": route.REGION,
                        "sso_account_id": "839393571433",
                        "sso_role_name": role,
                        "sso_session": "scanalyze-gug376",
                    }
                },
                "sso_sessions": {
                    "scanalyze-gug376": {
                        "sso_region": route.REGION,
                        "sso_start_url": (
                            "https://scanalyze.awsapps.com/start"
                        ),
                    }
                },
            }
        )

    def get_credentials(self) -> Any:
        return SimpleNamespace(method=self.credential_method)

    def client(self, service: str, **_kwargs: Any) -> Any:
        self.client_names.append(service)
        host = {
            "sts": "sts.us-east-1.amazonaws.com",
            "cloudformation": "cloudformation.us-east-1.amazonaws.com",
            "cloudtrail": "cloudtrail.us-east-1.amazonaws.com",
            "sso-admin": "sso.us-east-1.amazonaws.com",
            "lambda": "lambda.us-east-1.amazonaws.com",
            "iam": "iam.amazonaws.com",
            "dynamodb": "dynamodb.us-east-1.amazonaws.com",
            "kms": "kms.us-east-1.amazonaws.com",
            "logs": "logs.us-east-1.amazonaws.com",
        }[service]
        return SimpleNamespace(
            meta=SimpleNamespace(
                endpoint_url="https://" + host,
                region_name=(
                    "aws-global" if service == "iam" else route.REGION
                ),
            )
        )


def test_connected_sdk_requires_exact_direct_sso_session_and_endpoints() -> None:
    captured: dict[str, Any] = {}

    class Config:
        def __init__(self, **kwargs: Any) -> None:
            captured.update(kwargs)

    session = _SdkBoundarySession()
    clients = aws.clients_from_session(
        session,
        Config,
        expected_profile=session.profile_name,
        environment={},
    )
    assert set(clients) == {
        "sts",
        "cloudformation",
        "cloudtrail",
        "sso-admin",
        "lambda",
        "iam",
        "dynamodb",
        "kms",
        "logs",
    }
    assert session.client_names[0] == "sts"
    assert captured["ignore_configured_endpoint_urls"] is True


@pytest.mark.parametrize(
    ("session", "environment", "code"),
    [
        (
            _SdkBoundarySession(credential_method="env"),
            {},
            "AWS_CREDENTIAL_SOURCE_INVALID",
        ),
        (
            _SdkBoundarySession(role="ForeignRole"),
            {},
            "AWS_SSO_CONFIGURATION_INVALID",
        ),
        (
            _SdkBoundarySession(),
            {"AWS_ACCESS_KEY_ID": "present"},
            "AMBIENT_AWS_CONFIGURATION_FORBIDDEN",
        ),
        (
            _SdkBoundarySession(),
            {"HTTPS_PROXY": "https://proxy.invalid"},
            "AMBIENT_AWS_CONFIGURATION_FORBIDDEN",
        ),
        (
            _SdkBoundarySession(),
            {"AWS_PROFILE": "default"},
            "AMBIENT_PROFILE_INVALID",
        ),
    ],
)
def test_connected_sdk_rejects_non_sso_and_ambient_override_boundaries(
    session: _SdkBoundarySession,
    environment: dict[str, str],
    code: str,
) -> None:
    with pytest.raises(aws.ConnectedRouteError, match=code):
        aws.clients_from_session(
            session,
            lambda **_kwargs: object(),
            expected_profile="839393571433_AWSAdministratorAccess",
            environment=environment,
        )
    assert session.client_names == []


def test_connected_sdk_rejects_profile_endpoint_override() -> None:
    session = _SdkBoundarySession()
    session._session.full_config["profiles"][session.profile_name][
        "endpoint_url"
    ] = "https://sts.invalid"
    with pytest.raises(
        aws.ConnectedRouteError,
        match="AWS_SSO_CONFIGURATION_INVALID",
    ):
        aws.clients_from_session(
            session,
            lambda **_kwargs: object(),
            expected_profile=session.profile_name,
            environment={},
        )
    assert session.client_names == []


def test_offline_private_writer_is_o_excl_and_mode_0600(tmp_path: Path) -> None:
    root = tmp_path / "private"
    root.mkdir(mode=0o700)
    spec = importlib.util.spec_from_file_location("gug376_offline_cli", OFFLINE_CLI)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    root_path, descriptor = module._private_root(root)
    try:
        module._write(root_path, descriptor, Path("intent.json"), {"ok": True})
        assert stat_mode(root / "intent.json") == 0o600
        with pytest.raises(route.RouteSeedError, match="PRIVATE_OUTPUT_EXISTS"):
            module._write(root_path, descriptor, Path("intent.json"), {"ok": True})
    finally:
        os.close(descriptor)


def stat_mode(path: Path) -> int:
    return path.stat().st_mode & 0o777


def test_broker_config_closes_ledger_id_principal_and_exact_change_set_names() -> None:
    source = (
        ROOT
        / "tests/test_deployment/test_gug376_plan_permission_repair_route_broker.py"
    ).read_text()
    assert 'ledger_id = "gug376-route-broker"' in source
    for name in (
        "gug376-temporary-route-seed-revoke",
        "gug376-plan-repair-delegation-create",
        "gug376-plan-repair-pep-create",
        "gug376-plan-repair-delegation-revoke",
        "gug376-temporary-route-invoker-revoke",
    ):
        assert name in source
    assert broker.ROUTE_LEDGER_ID == "gug376-route-broker"
