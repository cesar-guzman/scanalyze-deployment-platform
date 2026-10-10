"""Offline import-stage integrity checks; no AWS ownership or deployment proof."""

from __future__ import annotations

import hashlib
import json
from copy import deepcopy
from pathlib import Path
import re
from typing import Any

import pytest
import yaml
from yaml.constructor import ConstructorError


ROOT = Path(__file__).resolve().parents[2]
TEMPLATE = ROOT / "bootstrap/cfn-platform-authority-gug274-checksum-custody-import.yaml"
IMPORTS = ROOT / "bootstrap/gug274-checksum-custody-import-resources.json"
IMPORT_PARAMETERS = ROOT / "bootstrap/gug274-checksum-custody-recovery-import.parameters.json"
UPDATE_PARAMETERS = ROOT / "bootstrap/gug274-checksum-custody-recovery-update.parameters.json"
UPDATE_TEMPLATE = ROOT / "bootstrap/cfn-platform-authority-gug274-checksum-custody.yaml"
SOURCE_COMMIT = "6954e63a81657c6fb52aeedba12656836e67d897"
SOURCE_DIGEST = "59de32582c35fa1a283a8d3de7da7eff14fb286658b081abbc91be1e223db6f8"
UPDATE_DIGEST = "f7850f540ceeaf49fbb43af4ab48c12cd52c8b285cc5f580430400a09bbbacff"
ACCOUNT = "042360977644"
REGION = "us-east-1"
REPORT_BUCKET = f"scanalyze-gug274-checksum-reports-{ACCOUNT}-{REGION}"
AUDIT_BUCKET = f"scanalyze-gug274-checksum-audit-{ACCOUNT}-{REGION}"
ROLE_PATH = f"arn:aws:iam::{ACCOUNT}:role/scanalyze/platform-authority/"
BINDINGS = {
    "ReportBucketName": REPORT_BUCKET,
    "AuditBucketName": AUDIT_BUCKET,
    "TrailName": "scanalyze-gug274-checksum-custody",
    "TemplateDigest": SOURCE_DIGEST,
    "ApprovedManifestWriterRoleArn": ROLE_PATH + "ScanalyzeGug274ChecksumManifestWriter",
    "ApprovedBatchWriterRoleArn": ROLE_PATH + "ScanalyzeGug274ChecksumBatchWriter",
}
# Canonical hashes of the complete four resource definitions from SOURCE_COMMIT.
# They intentionally pin the original policy, not the later repaired template.
ORIGINAL_RESOURCES = {
    "ReportBucket": "15bd22d7858203e6de81af0f1f5a693ca5347545355ec6dce44e03c9b090a775",
    "AuditBucket": "19ad63672fb07acb1bb92753a7bc5d30ea5912c924d7cad22c4c80de24f1c1a0",
    "ReportBucketPolicy": "617d0134416d8e2e3f33aefa1e41962174de04927d8c8ef2006449baca1032b4",
    "AuditBucketPolicy": "85ba8adb31f24b2ea37f062f31833dc39848d78cfa00482225bd1ef729f8798d",
}


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


def _json_mapping(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    mapping: dict[str, Any] = {}
    for key, value in pairs:
        if key in mapping:
            raise ValueError("duplicate import JSON key")
        mapping[key] = value
    return mapping


def _parameter_bindings(path: Path) -> dict[str, str]:
    parameters = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_json_mapping)
    assert isinstance(parameters, list) and len(parameters) == len(BINDINGS)
    assert all(set(item) == {"ParameterKey", "ParameterValue"} for item in parameters)
    values = {item["ParameterKey"]: item["ParameterValue"] for item in parameters}
    assert len(values) == len(parameters)
    return values


def _resolve(value: Any, parameters: dict[str, str]) -> Any:
    context = {
        **parameters,
        "AWS::AccountId": ACCOUNT,
        "AWS::Region": REGION,
        "ReportBucket": parameters["ReportBucketName"],
        "AuditBucket": parameters["AuditBucketName"],
        "ReportBucket.Arn": f"arn:aws:s3:::{parameters['ReportBucketName']}",
        "AuditBucket.Arn": f"arn:aws:s3:::{parameters['AuditBucketName']}",
    }

    def resolve(item: Any) -> Any:
        if isinstance(item, list):
            return [resolve(child) for child in item]
        if not isinstance(item, dict):
            return item
        if set(item) in ({"Ref"}, {"GetAtt"}):
            return context[next(iter(item.values()))]
        if set(item) == {"Sub"}:
            return re.sub(r"\$\{([^}]+)\}", lambda match: context[match[1]], item["Sub"])
        return {key: resolve(child) for key, child in item.items()}

    return resolve(value)


@pytest.fixture
def template() -> dict:
    return yaml.load(TEMPLATE.read_text(encoding="utf-8"), Loader=_CloudFormationLoader)


@pytest.fixture
def imports() -> list[dict]:
    return json.loads(IMPORTS.read_text(encoding="utf-8"), object_pairs_hook=_json_mapping)


@pytest.mark.parametrize("logical_id", list(ORIGINAL_RESOURCES))
def test_import_preserves_each_complete_original_resource(template: dict, logical_id: str) -> None:
    resource = template["Resources"][logical_id]
    canonical = json.dumps(resource, sort_keys=True, separators=(",", ":")).encode("utf-8")
    assert hashlib.sha256(canonical).hexdigest() == ORIGINAL_RESOURCES[logical_id]


def test_import_stage_contains_only_four_retained_resources(template: dict) -> None:
    resources = template["Resources"]
    assert set(resources) == set(ORIGINAL_RESOURCES)
    for logical_id, resource in resources.items():
        expected_type = "AWS::S3::BucketPolicy" if logical_id.endswith("Policy") else "AWS::S3::Bucket"
        assert resource["Type"] == expected_type
        assert resource["DeletionPolicy"] == resource["UpdateReplacePolicy"] == "Retain"
    assert "Outputs" not in template
    assert "Transform" not in template
    assert "Conditions" not in template


def test_all_six_import_bindings_are_frozen_to_original_observed_values(template: dict) -> None:
    parameters = template["Parameters"]
    assert set(parameters) == set(BINDINGS)
    for name, expected in BINDINGS.items():
        assert parameters[name]["Type"] == "String"
        assert parameters[name]["Default"] == expected
        assert parameters[name]["AllowedValues"] == [expected]
    for bucket in ("ReportBucket", "AuditBucket"):
        tags = {item["Key"]: item["Value"] for item in template["Resources"][bucket]["Properties"]["Tags"]}
        assert tags["template_sha256"] == {"Ref": "TemplateDigest"}
    assert template["Metadata"]["SourceCommit"] == SOURCE_COMMIT
    assert template["Metadata"]["ObservedOriginalTemplateSha256"] == SOURCE_DIGEST
    assert hashlib.sha256(TEMPLATE.read_bytes()).hexdigest() != SOURCE_DIGEST


def test_import_keeps_account_region_and_separate_writer_rules(template: dict) -> None:
    rules = template["Rules"]
    assert set(rules) == {"ExactInstallationScope", "SeparateManifestAndReportWriters"}
    scope = [item["Assert"] for item in rules["ExactInstallationScope"]["Assertions"]]
    assert scope == [
        {"Equals": [{"Ref": "AWS::AccountId"}, ACCOUNT]},
        {"Equals": [{"Ref": "AWS::Region"}, REGION]},
    ]
    assert rules["SeparateManifestAndReportWriters"]["Assertions"][0]["Assert"] == {
        "Not": [{"Equals": [{"Ref": "ApprovedManifestWriterRoleArn"}, {"Ref": "ApprovedBatchWriterRoleArn"}]}],
    }


def test_import_has_no_missing_or_trail_resource_references(template: dict) -> None:
    allowed = set(template["Parameters"]) | set(template["Resources"]) | {"AWS::AccountId", "AWS::Region"}

    def check(value: Any) -> None:
        if isinstance(value, list):
            for item in value:
                check(item)
        elif isinstance(value, dict):
            if set(value) == {"Ref"}:
                assert value["Ref"] in allowed
            elif set(value) == {"GetAtt"}:
                assert value["GetAtt"].split(".", 1)[0] in template["Resources"]
            elif set(value) == {"Sub"}:
                for reference in re.findall(r"\$\{([^}]+)\}", value["Sub"]):
                    assert reference.split(".", 1)[0] in allowed
            else:
                for item in value.values():
                    check(item)

    check(template)


def test_explicit_import_identifiers_select_only_both_buckets_and_their_policies(imports: list[dict]) -> None:
    expected = [
        {"ResourceType": "AWS::S3::Bucket", "LogicalResourceId": "ReportBucket", "ResourceIdentifier": {"BucketName": REPORT_BUCKET}},
        {"ResourceType": "AWS::S3::Bucket", "LogicalResourceId": "AuditBucket", "ResourceIdentifier": {"BucketName": AUDIT_BUCKET}},
        {"ResourceType": "AWS::S3::BucketPolicy", "LogicalResourceId": "ReportBucketPolicy", "ResourceIdentifier": {"Bucket": REPORT_BUCKET}},
        {"ResourceType": "AWS::S3::BucketPolicy", "LogicalResourceId": "AuditBucketPolicy", "ResourceIdentifier": {"Bucket": AUDIT_BUCKET}},
    ]
    assert imports == expected
    assert len({item["LogicalResourceId"] for item in imports}) == 4


def test_import_parameter_artifact_matches_all_six_fixed_bindings(template: dict) -> None:
    parameters = _parameter_bindings(IMPORT_PARAMETERS)
    assert parameters == BINDINGS
    for name, value in parameters.items():
        assert template["Parameters"][name]["AllowedValues"] == [value]


def test_update_parameters_change_only_the_final_template_provenance() -> None:
    original = _parameter_bindings(IMPORT_PARAMETERS)
    updated = _parameter_bindings(UPDATE_PARAMETERS)
    assert hashlib.sha256(UPDATE_TEMPLATE.read_bytes()).hexdigest() == UPDATE_DIGEST
    assert updated == {**original, "TemplateDigest": UPDATE_DIGEST}


def test_stage_b_changes_only_two_bucket_tags_two_audit_statements_and_adds_stopped_trail(template: dict) -> None:
    update_template = yaml.load(UPDATE_TEMPLATE.read_text(encoding="utf-8"), Loader=_CloudFormationLoader)
    original = _resolve(template["Resources"], _parameter_bindings(IMPORT_PARAMETERS))
    updated = _resolve(update_template["Resources"], _parameter_bindings(UPDATE_PARAMETERS))
    assert set(updated) == set(original) | {"CustodyTrail"}
    expected = deepcopy(original)
    for bucket in ("ReportBucket", "AuditBucket"):
        tags = expected[bucket]["Properties"]["Tags"]
        assert [item["Value"] for item in tags if item["Key"] == "template_sha256"] == [SOURCE_DIGEST]
        for item in tags:
            if item["Key"] == "template_sha256":
                item["Value"] = UPDATE_DIGEST

    account_prefix = (
        f"arn:aws:s3:::{AUDIT_BUCKET}/scanalyze/platform-authority/gug-274/"
        f"checksum/audit/AWSLogs/{ACCOUNT}/*"
    )
    statements = expected["AuditBucketPolicy"]["Properties"]["PolicyDocument"]["Statement"]
    deny = next(item for item in statements if item["Sid"] == "DenyWritesOutsideExactTrailPaths")
    deny["Sid"] = "DenyWritesOutsideExactTrailAccountPrefix"
    deny["NotResource"] = [account_prefix]
    allow = next(item for item in statements if item["Sid"] == "ExactTrailLogAndDigestDelivery")
    allow["Resource"] = [account_prefix]

    # Compare complete effective definitions, so extra policy, storage, retention
    # or tag changes fail. The two provenance tag updates are explicit writes.
    assert {name: updated[name] for name in original} == expected
    trail = updated["CustodyTrail"]
    assert trail["Type"] == "AWS::CloudTrail::Trail"
    assert trail["DeletionPolicy"] == trail["UpdateReplacePolicy"] == "Retain"
    assert trail["DependsOn"] == "AuditBucketPolicy"
    assert trail["Properties"]["IsLogging"] is False
