"""Offline policy-boundary checks, not deployed IAM or Batch compatibility proof."""

from __future__ import annotations

from collections import Counter
from fnmatch import fnmatchcase
from pathlib import Path
import re
from typing import Any

import pytest
import yaml
from yaml.constructor import ConstructorError


TEMPLATE = Path(__file__).resolve().parents[2] / "bootstrap/cfn-platform-authority-gug274-checksum-roles.yaml"
ACCOUNT = "042360977644"
REGION = "us-east-1"
REPORT_BUCKET = f"scanalyze-gug274-checksum-reports-{ACCOUNT}-{REGION}"
ARTIFACT_BUCKET = f"scanalyze-gug274-artifacts-{ACCOUNT}-{REGION}"
PREFIX = "scanalyze/platform-authority/gug-274/checksum/"
ROLE_PATH = "/scanalyze/platform-authority/"
MANIFEST_ROLE = f"arn:aws:iam::{ACCOUNT}:role{ROLE_PATH}ScanalyzeGug274ChecksumManifestWriter"
BATCH_ROLE = f"arn:aws:iam::{ACCOUNT}:role{ROLE_PATH}ScanalyzeGug274ChecksumBatchWriter"
INVOKER_ROLE = f"arn:aws:iam::{ACCOUNT}:role/SyntheticReviewedChecksumInvoker"
SOURCE_KEY = "scanalyze/platform-authority/gug-274/signed/00000000-0000-0000-0000-000000000001.zip"
MANIFEST_KEY = PREFIX + "manifests/synthetic-canary.csv"
RUN_ID = "synthetic-canary"
KMS_KEY = f"arn:aws:kms:{REGION}:{ACCOUNT}:key/00000000-0000-0000-0000-000000000002"
BATCH_BINDINGS = {"SignedArtifactKey", "SignedArtifactVersionId", "ArtifactKmsKeyArn", "InputManifestKey",
                  "InputManifestVersionId", "ReviewedReportRunId"}


class _CloudFormationLoader(yaml.SafeLoader):
    def construct_mapping(self, node: yaml.Node, deep: bool = False) -> Any:
        mapping: dict[Any, Any] = {}
        for key_node, value_node in node.value:
            key = self.construct_object(key_node, deep=deep)
            if key in mapping:
                raise ConstructorError("mapping", node.start_mark, "duplicate key", key_node.start_mark)
            mapping[key] = self.construct_object(value_node, deep=deep)
        return mapping


def _construct_intrinsic(loader: yaml.SafeLoader, tag: str, node: yaml.Node) -> Any:
    if isinstance(node, yaml.ScalarNode):
        value = loader.construct_scalar(node)
    elif isinstance(node, yaml.SequenceNode):
        value = loader.construct_sequence(node)
    else:
        value = loader.construct_mapping(node)
    return {tag: value}


_CloudFormationLoader.add_multi_constructor("!", _construct_intrinsic)


@pytest.fixture
def template() -> dict:
    return yaml.load(TEMPLATE.read_text(encoding="utf-8"), Loader=_CloudFormationLoader)


def _context(stage: str = "BatchBound") -> dict[str, str]:
    context = {
        "DeploymentStage": stage,
        "AWS::AccountId": ACCOUNT,
        "AWS::Region": REGION,
        "ApprovedHumanInvokerRoleArn": INVOKER_ROLE,
        "SignedArtifactKey": SOURCE_KEY,
        "SignedArtifactVersionId": "synthetic-source-version",
        "ArtifactKmsKeyArn": KMS_KEY,
        "InputManifestKey": MANIFEST_KEY,
        "InputManifestVersionId": "synthetic-manifest-version",
        "ReviewedReportRunId": RUN_ID,
        "TemplateDigest": "a" * 64,
        "ManifestWriterRole.Arn": MANIFEST_ROLE,
        "BatchWriterRole.Arn": BATCH_ROLE,
    }
    if stage == "ManifestOnly":
        context.update(dict.fromkeys(BATCH_BINDINGS, ""))
    return context


def _resolve(value: Any, context: dict[str, Any]) -> Any:
    if isinstance(value, list):
        return [_resolve(item, context) for item in value]
    if not isinstance(value, dict):
        return value
    if set(value) in ({"Ref"}, {"GetAtt"}):
        return context[next(iter(value.values()))]
    if set(value) == {"Sub"}:
        return re.sub(r"\$\{([^}]+)\}", lambda match: context[match[1]], value["Sub"])
    if set(value) == {"Equals"}:
        left, right = _resolve(value["Equals"], context)
        return left == right
    if set(value) == {"Contains"}:
        values, expected = _resolve(value["Contains"], context)
        return expected in values
    if set(value) == {"Not"}:
        (inner,) = _resolve(value["Not"], context)
        return not inner
    return {key: _resolve(item, context) for key, item in value.items()}


def _statements(template: dict, role: str) -> list[dict]:
    policies = template["Resources"][role]["Properties"]["Policies"]
    return [statement for policy in _resolve(policies, _context())
            for statement in policy["PolicyDocument"]["Statement"]]


def _values(value: Any) -> list:
    return value if isinstance(value, list) else [value]


def _allows(statements: list[dict], action: str, resource: str, context: dict[str, str]) -> bool:
    """Bounded matcher for these Allow statements, not a complete IAM simulator."""
    for statement in statements:
        if statement["Effect"] != "Allow":
            continue
        if not any(fnmatchcase(action, item) for item in _values(statement["Action"])):
            continue
        if not any(fnmatchcase(resource, item) for item in _values(statement["Resource"])):
            continue
        matches = True
        for operator, conditions in statement.get("Condition", {}).items():
            for key, expected in conditions.items():
                actual = context.get(key)
                if operator in {"StringEquals", "Bool"}:
                    valid = actual == expected
                elif operator == "StringLike":
                    valid = actual is not None and fnmatchcase(actual, expected)
                else:
                    raise AssertionError(f"Review new operator {operator}")
                matches = matches and valid
        if matches:
            return True
    return False


def _valid_parameter(template: dict, name: str, value: str) -> bool:
    parameter = template["Parameters"][name]
    if "AllowedValues" in parameter:
        return value in parameter["AllowedValues"]
    return (parameter.get("MinLength", 0) <= len(value) <= parameter.get("MaxLength", float("inf"))
            and re.fullmatch(parameter["AllowedPattern"], value) is not None)


def _rules_pass(template: dict, context: dict[str, str]) -> bool:
    return all(all(_resolve(item["Assert"], context) for item in rule["Assertions"])
               for rule in template["Rules"].values()
               if "RuleCondition" not in rule or _resolve(rule["RuleCondition"], context))


def _active_resources(template: dict, context: dict[str, str]) -> set[str]:
    conditions = {name: _resolve(value, context) for name, value in template["Conditions"].items()}
    return {name for name, resource in template["Resources"].items()
            if "Condition" not in resource or conditions[resource["Condition"]]}


@pytest.mark.parametrize(("account", "region", "accepted"), [
    (ACCOUNT, REGION, True), ("999900001111", REGION, False), (ACCOUNT, "us-west-2", False),
])
def test_account_and_region_rules_stop_outside_reviewed_scope(template: dict, account: str, region: str, accepted: bool) -> None:
    context = {**_context(), "AWS::AccountId": account, "AWS::Region": region}
    assertions = template["Rules"]["ExactInstallationScope"]["Assertions"]
    assert all(_resolve(item["Assert"], context) for item in assertions) is accepted


def test_only_two_new_retained_roles_without_operator_or_activation_resources(template: dict) -> None:
    resources = template["Resources"]
    assert Counter(resource["Type"] for resource in resources.values()) == {"AWS::IAM::Role": 2}
    assert set(resources) == {"ManifestWriterRole", "BatchWriterRole"}
    names = []
    for resource in resources.values():
        assert resource["DeletionPolicy"] == resource["UpdateReplacePolicy"] == "Retain"
        props = resource["Properties"]
        names.append(props["RoleName"])
        assert props["Path"] == ROLE_PATH
        assert props["MaxSessionDuration"] == 3600
        assert not {"ManagedPolicyArns", "PermissionsBoundary"} & props.keys()
    assert len(set(names)) == 2
    assert set(names) == {"ScanalyzeGug274ChecksumManifestWriter", "ScanalyzeGug274ChecksumBatchWriter"}
    assert "Transform" not in template
    assert template["Conditions"] == {"StageBatchBound": {"Equals": [{"Ref": "DeploymentStage"}, "BatchBound"]}}
    assert "Condition" not in resources["ManifestWriterRole"]
    assert resources["BatchWriterRole"]["Condition"] == "StageBatchBound"


def test_only_empty_batch_defaults_and_no_human_or_existing_candidate_adoption(template: dict) -> None:
    parameters = template["Parameters"]
    assert set(parameters) == {"DeploymentStage", "TemplateDigest", "ApprovedHumanInvokerRoleArn", "SignedArtifactKey",
                              "SignedArtifactVersionId", "ArtifactKmsKeyArn", "InputManifestKey",
                              "InputManifestVersionId", "ReviewedReportRunId"}
    for name, parameter in parameters.items():
        assert parameter["Type"] == "String"
        assert _valid_parameter(template, name, _context()[name])
        if name in BATCH_BINDINGS:
            assert parameter["Default"] == ""
            assert _valid_parameter(template, name, "")
        elif name == "DeploymentStage":
            assert parameter["Default"] == "ManifestOnly"
            assert parameter["AllowedValues"] == ["ManifestOnly", "BatchBound"]
        else:
            assert "Default" not in parameter
            assert not _valid_parameter(template, name, "")


@pytest.mark.parametrize(("stage", "active"), [
    ("ManifestOnly", {"ManifestWriterRole"}),
    ("BatchBound", {"ManifestWriterRole", "BatchWriterRole"}),
])
def test_manifest_can_exist_before_real_manifest_version_is_bound(template: dict, stage: str, active: set[str]) -> None:
    context = _context(stage)
    assert _rules_pass(template, context)
    assert _active_resources(template, context) == active
    if stage == "ManifestOnly":
        assert all(context[name] == "" for name in BATCH_BINDINGS)
        assert template["Outputs"]["ProposedBatchWriterRoleArn"]["Condition"] == "StageBatchBound"


@pytest.mark.parametrize("binding", sorted(BATCH_BINDINGS))
def test_manifest_only_rejects_partial_or_premature_batch_bindings(template: dict, binding: str) -> None:
    context = _context("ManifestOnly")
    context[binding] = _context()[binding]
    assert not _rules_pass(template, context)
    assert _active_resources(template, context) == {"ManifestWriterRole"}


@pytest.mark.parametrize("binding", sorted(BATCH_BINDINGS))
def test_batch_bound_rejects_every_missing_actual_binding(template: dict, binding: str) -> None:
    context = _context()
    context[binding] = ""
    assert not _rules_pass(template, context)


def test_empty_defaults_cannot_create_batch_with_fake_version_workaround(template: dict) -> None:
    context = {**_context("ManifestOnly"), "DeploymentStage": "BatchBound"}
    assert not _rules_pass(template, context)
    assert all(context[name] == "" for name in BATCH_BINDINGS)
    assert not _valid_parameter(template, "DeploymentStage", "BatchUnbound")


@pytest.mark.parametrize("role", [MANIFEST_ROLE, BATCH_ROLE])
def test_generated_writers_cannot_be_the_human_entry(template: dict, role: str) -> None:
    assertions = template["Rules"]["HumanInvokerMustNotBeGeneratedWriter"]["Assertions"]
    assert all(_resolve(item["Assert"], _context()) for item in assertions)
    context = {**_context(), "ApprovedHumanInvokerRoleArn": role}
    assert not all(_resolve(item["Assert"], context) for item in assertions)


@pytest.mark.parametrize("permission_set", [
    "AWSReadOnlyAccess", "ReadOnlyAccess", "ScanalyzeReleaseVsaSign", "ScanalyzeAuthorityBootApprove",
    "ScanalyzeAuthorityBootstrapApply", "ScanalyzeAuthorityBootstrapPlan", "ScanalyzeAuthorityRetireApprove",
    "ScanalyzeAuthorityRetireClass",
])
def test_observed_sso_read_sign_bootstrap_retirement_duties_are_not_reused(template: dict, permission_set: str) -> None:
    role = (f"arn:aws:iam::{ACCOUNT}:role/aws-reserved/sso.amazonaws.com/"
            f"AWSReservedSSO_{permission_set}_0000000000000001")
    assert not _valid_parameter(template, "ApprovedHumanInvokerRoleArn", role)


@pytest.mark.parametrize("invalid", [
    INVOKER_ROLE.replace(ACCOUNT, "999900001111"), f"arn:aws:iam::{ACCOUNT}:root",
    f"arn:aws:sts::{ACCOUNT}:assumed-role/SyntheticReviewedChecksumInvoker/session", INVOKER_ROLE + "*",
])
def test_human_entry_requires_one_exact_same_account_iam_role(template: dict, invalid: str) -> None:
    assert not _valid_parameter(template, "ApprovedHumanInvokerRoleArn", invalid)


def test_admin_name_is_not_autoselected_or_categorically_rejected(template: dict) -> None:
    role = (f"arn:aws:iam::{ACCOUNT}:role/aws-reserved/sso.amazonaws.com/"
            "AWSReservedSSO_AWSAdministratorAccess_0000000000000001")
    assert _valid_parameter(template, "ApprovedHumanInvokerRoleArn", role)
    assert "Default" not in template["Parameters"]["ApprovedHumanInvokerRoleArn"]


def test_trust_separates_exact_human_entry_from_only_the_batch_service(template: dict) -> None:
    human = _resolve(template["Resources"]["ManifestWriterRole"]["Properties"]["AssumeRolePolicyDocument"], _context())
    batch = _resolve(template["Resources"]["BatchWriterRole"]["Properties"]["AssumeRolePolicyDocument"], _context())
    assert human == {"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Principal": {"AWS": INVOKER_ROLE}, "Action": "sts:AssumeRole"}]}
    assert batch == {"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Principal": {"Service": "batchoperations.s3.amazonaws.com"}, "Action": "sts:AssumeRole"}]}
    # No undocumented confused-deputy request contexts or user assumption added to Batch.
    assert all("Condition" not in item for item in batch["Statement"])


@pytest.mark.parametrize(("name", "invalid"), [
    ("SignedArtifactKey", SOURCE_KEY.replace("/signed/", "/unsigned/")),
    ("SignedArtifactKey", SOURCE_KEY + "*"),
    ("SignedArtifactKey", "scanalyze/platform-authority/gug-274/signed/../candidate.zip"),
    ("SignedArtifactVersionId", "null"),
    ("InputManifestKey", PREFIX + "reports/synthetic.csv"),
    ("InputManifestKey", PREFIX + "manifests/../synthetic.csv"),
    ("InputManifestKey", PREFIX + "manifests/synthetic.json"),
    ("InputManifestVersionId", "null"),
    ("ReviewedReportRunId", "synthetic/other"),
    ("ReviewedReportRunId", "../synthetic"),
    ("ReviewedReportRunId", "synthetic*"),
    ("ArtifactKmsKeyArn", KMS_KEY.replace(ACCOUNT, "999900001111")),
    ("ArtifactKmsKeyArn", KMS_KEY.replace(REGION, "us-west-2")),
    ("ArtifactKmsKeyArn", f"arn:aws:kms:{REGION}:{ACCOUNT}:alias/synthetic"),
    ("TemplateDigest", "a" * 63),
])
def test_required_bindings_reject_cross_scope_or_unversioned_forms(template: dict, name: str, invalid: str) -> None:
    assert not _valid_parameter(template, name, invalid)


@pytest.mark.parametrize(("key", "secure", "accepted"), [
    (MANIFEST_KEY, "true", True),
    (MANIFEST_KEY, "false", False),
    (MANIFEST_KEY, None, False),
    (PREFIX + "reports/synthetic-canary/report.csv", "true", False),
    (PREFIX + "audit/synthetic.json", "true", False),
    (PREFIX + "manifests-other/synthetic.csv", "true", False),
])
def test_manifest_write_is_tls_and_manifest_namespace_only(template: dict, key: str, secure: str | None, accepted: bool) -> None:
    context = {} if secure is None else {"aws:SecureTransport": secure}
    assert _allows(_statements(template, "ManifestWriterRole"), "s3:PutObject",
                   f"arn:aws:s3:::{REPORT_BUCKET}/{key}", context) is accepted


@pytest.mark.parametrize(("prefix", "accepted"), [
    (PREFIX + "manifests/", True), (MANIFEST_KEY, True), (PREFIX, False),
    (PREFIX + "reports/", False), (PREFIX + "audit/", False), ("", False),
])
def test_manifest_version_observation_cannot_list_reports_or_audit(template: dict, prefix: str, accepted: bool) -> None:
    assert _allows(_statements(template, "ManifestWriterRole"), "s3:ListBucketVersions",
                   f"arn:aws:s3:::{REPORT_BUCKET}", {"s3:prefix": prefix, "aws:SecureTransport": "true"}) is accepted


@pytest.mark.parametrize(("key", "version", "accepted"), [
    (SOURCE_KEY, "synthetic-source-version", True),
    (SOURCE_KEY, "different-version", False),
    (SOURCE_KEY, "null", False),
    (SOURCE_KEY, None, False),
    (SOURCE_KEY.replace("000000000001.zip", "000000000003.zip"), "synthetic-source-version", False),
])
def test_batch_source_read_binds_one_object_and_exact_version(template: dict, key: str, version: str | None, accepted: bool) -> None:
    context = {} if version is None else {"s3:VersionId": version}
    assert _allows(_statements(template, "BatchWriterRole"), "s3:GetObjectVersion",
                   f"arn:aws:s3:::{ARTIFACT_BUCKET}/{key}", context) is accepted


@pytest.mark.parametrize(("key", "version", "accepted"), [
    (MANIFEST_KEY, "synthetic-manifest-version", True),
    (MANIFEST_KEY, "synthetic-source-version", False),
    (MANIFEST_KEY, None, False),
    (PREFIX + "manifests/other.csv", "synthetic-manifest-version", False),
    (PREFIX + "reports/synthetic-canary/report.csv", "synthetic-manifest-version", False),
])
def test_batch_manifest_read_binds_one_manifest_and_exact_version(template: dict, key: str, version: str | None, accepted: bool) -> None:
    context = {} if version is None else {"s3:VersionId": version}
    assert _allows(_statements(template, "BatchWriterRole"), "s3:GetObjectVersion",
                   f"arn:aws:s3:::{REPORT_BUCKET}/{key}", context) is accepted


@pytest.mark.parametrize(("key", "accepted"), [
    (PREFIX + f"reports/{RUN_ID}/manifest.json", True),
    (PREFIX + f"reports/{RUN_ID}/results/synthetic.csv", True),
    (PREFIX + "reports/other-run/synthetic.csv", False),
    (PREFIX + "reports/synthetic-canary-other/synthetic.csv", False),
    (MANIFEST_KEY, False),
    (PREFIX + "audit/synthetic.json", False),
])
def test_batch_report_write_is_one_reviewed_run_namespace(template: dict, key: str, accepted: bool) -> None:
    assert _allows(_statements(template, "BatchWriterRole"), "s3:PutObject",
                   f"arn:aws:s3:::{REPORT_BUCKET}/{key}", {}) is accepted


@pytest.mark.parametrize(("key", "service", "context_arn", "accepted"), [
    (KMS_KEY, "s3.us-east-1.amazonaws.com", f"arn:aws:s3:::{ARTIFACT_BUCKET}", True),
    (KMS_KEY, "s3.us-west-2.amazonaws.com", f"arn:aws:s3:::{ARTIFACT_BUCKET}", False),
    (KMS_KEY, None, f"arn:aws:s3:::{ARTIFACT_BUCKET}", False),
    (KMS_KEY, "s3.us-east-1.amazonaws.com", f"arn:aws:s3:::{REPORT_BUCKET}", False),
    (KMS_KEY, "s3.us-east-1.amazonaws.com", f"arn:aws:s3:::{ARTIFACT_BUCKET}/{SOURCE_KEY}", False),
    (KMS_KEY.replace("000000000002", "000000000003"), "s3.us-east-1.amazonaws.com", f"arn:aws:s3:::{ARTIFACT_BUCKET}", False),
])
def test_kms_decrypt_is_one_key_through_regional_s3_and_bucket_key_context(template: dict, key: str,
                                                                                       service: str | None,
                                                                                       context_arn: str,
                                                                                       accepted: bool) -> None:
    context = {"kms:EncryptionContext:aws:s3:arn": context_arn}
    if service is not None:
        context["kms:ViaService"] = service
    assert _allows(_statements(template, "BatchWriterRole"), "kms:Decrypt", key, context) is accepted


def test_no_content_read_for_manifest_writer_or_unversioned_restore_control_permissions(template: dict) -> None:
    manifest_statements = _statements(template, "ManifestWriterRole")
    batch_statements = _statements(template, "BatchWriterRole")
    assert {action for item in manifest_statements for action in _values(item["Action"])} == {
        "s3:PutObject", "s3:ListBucketVersions"}
    assert {action for item in batch_statements for action in _values(item["Action"])} == {
        "s3:GetObjectVersion", "s3:PutObject", "kms:Decrypt"}
    for statement in manifest_statements + batch_statements:
        assert statement["Effect"] == "Allow"
        assert "NotAction" not in statement and "NotResource" not in statement
        assert all(resource != "*" for resource in _values(statement["Resource"]))
        assert all("*" not in action for action in _values(statement["Action"]))
    forbidden = ["s3:GetObject", "s3:RestoreObject", "s3:PutObjectAcl", "s3:DeleteObject", "s3:DeleteObjectVersion",
                 "s3:PutBucketPolicy", "s3:PutLifecycleConfiguration", "s3:CreateJob", "iam:PassRole",
                 "kms:CreateGrant", "kms:GenerateDataKey", "kms:Encrypt"]
    for action in forbidden:
        assert not any(fnmatchcase(action, pattern) for item in manifest_statements + batch_statements
                       for pattern in _values(item["Action"]))


def test_outputs_are_role_arns_without_effective_permission_or_producer_claim(template: dict) -> None:
    outputs = _resolve(template["Outputs"], _context())
    assert outputs["ProposedManifestWriterRoleArn"]["Value"] == MANIFEST_ROLE
    assert outputs["ProposedBatchWriterRoleArn"]["Value"] == BATCH_ROLE
    assert "not producer evidence" in outputs["ProposedManifestWriterRoleArn"]["Description"]
    assert "not a passed role or executed job" in outputs["ProposedBatchWriterRoleArn"]["Description"]
