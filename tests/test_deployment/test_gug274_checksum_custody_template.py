"""Offline checks of the dormant dedicated custody design, not deployed IAM proof."""

from __future__ import annotations

from collections import Counter
from fnmatch import fnmatchcase
from pathlib import Path
import re
from typing import Any

import pytest
import yaml
from yaml.constructor import ConstructorError


TEMPLATE = Path(__file__).resolve().parents[2] / "bootstrap/cfn-platform-authority-gug274-checksum-custody.yaml"
ACCOUNT = "042360977644"
REGION = "us-east-1"
REPORT_BUCKET = f"scanalyze-gug274-checksum-reports-{ACCOUNT}-{REGION}"
AUDIT_BUCKET = f"scanalyze-gug274-checksum-audit-{ACCOUNT}-{REGION}"
TRAIL = "scanalyze-gug274-checksum-custody"
TRAIL_ARN = f"arn:aws:cloudtrail:{REGION}:{ACCOUNT}:trail/{TRAIL}"
PREFIX = "scanalyze/platform-authority/gug-274/checksum/"
MANIFEST_ROLE = f"arn:aws:iam::{ACCOUNT}:role/SyntheticManifestWriter"
BATCH_ROLE = f"arn:aws:iam::{ACCOUNT}:role/SyntheticBatchWriter"


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
    if set(value) == {"Not"}:
        (inner,) = _resolve(value["Not"], context)
        return not inner
    return {key: _resolve(item, context) for key, item in value.items()}


def _context() -> dict[str, str]:
    return {
        "AWS::AccountId": ACCOUNT, "AWS::Region": REGION,
        "ReportBucketName": REPORT_BUCKET, "AuditBucketName": AUDIT_BUCKET,
        "ReportBucket": REPORT_BUCKET, "AuditBucket": AUDIT_BUCKET,
        "ReportBucket.Arn": f"arn:aws:s3:::{REPORT_BUCKET}",
        "AuditBucket.Arn": f"arn:aws:s3:::{AUDIT_BUCKET}",
        "TrailName": TRAIL, "ApprovedManifestWriterRoleArn": MANIFEST_ROLE,
        "ApprovedBatchWriterRoleArn": BATCH_ROLE, "TemplateDigest": "a" * 64,
    }


def _policy(template: dict, bucket: str) -> list[dict]:
    return _resolve(template["Resources"][bucket + "Policy"]["Properties"]["PolicyDocument"]["Statement"], _context())


def _values(value: Any) -> list:
    return value if isinstance(value, list) else [value]


def _matches(statement: dict, action: str, resource: str, context: dict[str, str]) -> bool:
    """Bounded model of only the template's policy operators, not an IAM simulator."""
    principal = statement["Principal"]
    if principal != "*" and principal != {"Service": context.get("aws:PrincipalServiceName")}:
        return False
    if not any(fnmatchcase(action, item) for item in _values(statement["Action"])):
        return False
    if "Resource" in statement and not any(fnmatchcase(resource, item) for item in _values(statement["Resource"])):
        return False
    if "NotResource" in statement and any(fnmatchcase(resource, item) for item in _values(statement["NotResource"])):
        return False
    for operator, conditions in statement.get("Condition", {}).items():
        for key, expected in conditions.items():
            actual = context.get(key)
            if operator == "Null":
                matches = (actual is None) == (expected == "true")
            elif operator in {"Bool", "StringEquals"}:
                matches = actual == expected
            elif operator in {"StringNotEquals", "ArnNotEquals", "StringNotEqualsIfExists", "ArnNotEqualsIfExists"}:
                matches = actual != expected
            else:
                raise AssertionError(f"Review new condition operator {operator}")
            if not matches:
                return False
    return True


def _denied(statements: list[dict], action: str, resource: str, context: dict[str, str]) -> bool:
    return any(s["Effect"] == "Deny" and _matches(s, action, resource, context) for s in statements)


def _audit_context() -> dict[str, str]:
    return {"aws:PrincipalServiceName": "cloudtrail.amazonaws.com", "aws:SourceArn": TRAIL_ARN,
            "aws:PrincipalIsAWSService": "true", "aws:SecureTransport": "true",
            "s3:x-amz-acl": "bucket-owner-full-control"}


def _audit_object(kind: str = "CloudTrail", region: str = REGION, account: str = ACCOUNT) -> str:
    return f"arn:aws:s3:::{AUDIT_BUCKET}/{PREFIX}audit/AWSLogs/{account}/{kind}/{region}/2030/01/01/synthetic.json.gz"


@pytest.mark.parametrize(("account", "region", "accepted"), [
    (ACCOUNT, REGION, True), ("999900001111", REGION, False), (ACCOUNT, "us-west-2", False),
])
def test_account_and_region_rules_fail_outside_scope(template: dict, account: str, region: str, accepted: bool) -> None:
    context = {**_context(), "AWS::AccountId": account, "AWS::Region": region}
    assertions = template["Rules"]["ExactInstallationScope"]["Assertions"]
    assert all(_resolve(item["Assert"], context) for item in assertions) is accepted


def test_names_are_fixed_and_roles_and_digest_are_mandatory(template: dict) -> None:
    parameters = template["Parameters"]
    assert set(parameters) == {"ReportBucketName", "AuditBucketName", "TrailName", "TemplateDigest",
                               "ApprovedManifestWriterRoleArn", "ApprovedBatchWriterRoleArn"}
    for name, expected in (("ReportBucketName", REPORT_BUCKET), ("AuditBucketName", AUDIT_BUCKET), ("TrailName", TRAIL)):
        assert parameters[name]["Default"] == expected
        assert parameters[name]["AllowedValues"] == [expected]
    for name in ("ApprovedManifestWriterRoleArn", "ApprovedBatchWriterRoleArn"):
        parameter = parameters[name]
        assert "Default" not in parameter
        assert re.fullmatch(parameter["AllowedPattern"], BATCH_ROLE)
        for invalid in ("", BATCH_ROLE.replace(ACCOUNT, "999900001111"), f"arn:aws:iam::{ACCOUNT}:root",
                        f"arn:aws:sts::{ACCOUNT}:assumed-role/SyntheticBatchWriter/session", BATCH_ROLE + "*"):
            assert re.fullmatch(parameter["AllowedPattern"], invalid) is None
    digest = parameters["TemplateDigest"]
    assert "Default" not in digest
    assert re.fullmatch(digest["AllowedPattern"], "a" * 64)
    assert all(re.fullmatch(digest["AllowedPattern"], item) is None for item in ("", "a" * 63, "x" * 64))


def test_manifest_and_report_writer_roles_must_be_distinct(template: dict) -> None:
    rule = template["Rules"]["SeparateManifestAndReportWriters"]["Assertions"]
    assert all(_resolve(item["Assert"], _context()) for item in rule)
    same_role = {**_context(), "ApprovedManifestWriterRoleArn": BATCH_ROLE}
    assert not all(_resolve(item["Assert"], same_role) for item in rule)


def test_only_dedicated_retained_resources_without_identity_or_existing_resource_changes(template: dict) -> None:
    resources = template["Resources"]
    assert Counter(r["Type"] for r in resources.values()) == {
        "AWS::S3::Bucket": 2, "AWS::S3::BucketPolicy": 2, "AWS::CloudTrail::Trail": 1,
    }
    for resource in resources.values():
        assert resource["DeletionPolicy"] == resource["UpdateReplacePolicy"] == "Retain"
    for bucket in ("ReportBucket", "AuditBucket"):
        props = resources[bucket]["Properties"]
        assert props["VersioningConfiguration"] == {"Status": "Enabled"}
        assert props["OwnershipControls"] == {"Rules": [{"ObjectOwnership": "BucketOwnerEnforced"}]}
        assert props["PublicAccessBlockConfiguration"] == dict.fromkeys(
            ["BlockPublicAcls", "BlockPublicPolicy", "IgnorePublicAcls", "RestrictPublicBuckets"], True)
        assert props["BucketEncryption"] == {
            "ServerSideEncryptionConfiguration": [{"ServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]}
        assert not {"LifecycleConfiguration", "ObjectLockConfiguration", "ObjectLockEnabled", "ReplicationConfiguration",
                    "NotificationConfiguration", "WebsiteConfiguration", "AccessControl"} & props.keys()
        assert resources[bucket + "Policy"]["Properties"]["Bucket"] == {"Ref": bucket}
        for statement in _policy(template, bucket):
            assert all(action.startswith("s3:") for action in _values(statement["Action"]))
    assert all(item["Effect"] == "Deny" for item in _policy(template, "ReportBucket"))
    allows = [item for item in _policy(template, "AuditBucket") if item["Effect"] == "Allow"]
    assert len(allows) == 2
    assert {item["Action"] for item in allows} == {"s3:GetBucketAcl", "s3:PutObject"}
    assert all(item["Principal"] == {"Service": "cloudtrail.amazonaws.com"} for item in allows)


def test_trail_is_hard_stopped_and_collects_only_all_report_writes(template: dict) -> None:
    trail = template["Resources"]["CustodyTrail"]
    props = _resolve(trail["Properties"], _context())
    assert props["IsLogging"] is False
    assert all(props[key] is False for key in ("IsMultiRegionTrail", "IsOrganizationTrail", "IncludeGlobalServiceEvents"))
    assert props["EnableLogFileValidation"] is True
    assert props["S3BucketName"] == AUDIT_BUCKET
    assert props["S3KeyPrefix"] == PREFIX + "audit"
    assert not {"KMSKeyId", "CloudWatchLogsLogGroupArn", "CloudWatchLogsRoleArn", "EventSelectors", "InsightSelectors"} & props.keys()
    selectors = props["AdvancedEventSelectors"]
    assert len(selectors) == 1
    assert {s["Field"]: {k: v for k, v in s.items() if k != "Field"} for s in selectors[0]["FieldSelectors"]} == {
        "eventCategory": {"Equals": ["Data"]}, "resources.type": {"Equals": ["AWS::S3::Object"]},
        "readOnly": {"Equals": ["false"]},
        "resources.ARN": {"StartsWith": [f"arn:aws:s3:::{REPORT_BUCKET}/{PREFIX}reports/"]},
    }
    assert trail["DependsOn"] == "AuditBucketPolicy"
    # No policy -> trail reference cycle; its SourceArn is deterministic from a fixed name.
    assert "CustodyTrail" not in repr(template["Resources"]["AuditBucketPolicy"])


@pytest.mark.parametrize(("role", "key", "denied"), [
    (MANIFEST_ROLE, PREFIX + "manifests/job.csv", False),
    (BATCH_ROLE, PREFIX + "reports/job/manifest.json", False),
    (MANIFEST_ROLE, PREFIX + "reports/job/manifest.json", True),
    (BATCH_ROLE, PREFIX + "manifests/job.csv", True),
    (BATCH_ROLE, PREFIX + "reports-other/job.csv", True),
    (BATCH_ROLE, PREFIX + "reports", True),
    (BATCH_ROLE, "unrelated/object.csv", True),
    (f"arn:aws:iam::{ACCOUNT}:root", PREFIX + "reports/job.csv", True),
    (None, PREFIX + "manifests/job.csv", True),
])
def test_report_prefix_and_writer_denies_survive_broad_identity_allows(template: dict, role: str | None, key: str, denied: bool) -> None:
    context = {"aws:SecureTransport": "true"}
    if role is not None:
        context["aws:PrincipalArn"] = role
    assert _denied(_policy(template, "ReportBucket"), "s3:PutObject", f"arn:aws:s3:::{REPORT_BUCKET}/{key}", context) is denied


@pytest.mark.parametrize(("service", "source", "denied"), [
    ("cloudtrail.amazonaws.com", TRAIL_ARN, False),
    ("cloudtrail.amazonaws.com", TRAIL_ARN + "-other", True),
    ("cloudtrail.amazonaws.com", None, True),
    ("other.amazonaws.com", TRAIL_ARN, True),
    (None, TRAIL_ARN, True), (None, None, True),
])
def test_audit_write_needs_both_exact_service_and_trail_even_with_identity_allow(
    template: dict, service: str | None, source: str | None, denied: bool,
) -> None:
    context = _audit_context()
    for key, value in (("aws:PrincipalServiceName", service), ("aws:SourceArn", source)):
        if value is None:
            context.pop(key)
        else:
            context[key] = value
    assert _denied(_policy(template, "AuditBucket"), "s3:PutObject", _audit_object(), context) is denied


@pytest.mark.parametrize("kind", ["CloudTrail", "CloudTrail-Digest"])
def test_service_delivery_allows_exact_log_and_digest_paths_with_owner_acl(template: dict, kind: str) -> None:
    policy = _policy(template, "AuditBucket")
    context = _audit_context()
    resource = _audit_object(kind)
    assert not _denied(policy, "s3:PutObject", resource, context)
    assert any(s["Effect"] == "Allow" and _matches(s, "s3:PutObject", resource, context) for s in policy)
    context.pop("s3:x-amz-acl")
    assert not any(s["Effect"] == "Allow" and _matches(s, "s3:PutObject", resource, context) for s in policy)
    context = _audit_context()
    context["aws:SourceArn"] += "-other"
    assert not any(s["Effect"] == "Allow" and _matches(s, "s3:GetBucketAcl", f"arn:aws:s3:::{AUDIT_BUCKET}", context) for s in policy)


@pytest.mark.parametrize("resource", [
    _audit_object(account="999900001111"),
    f"arn:aws:s3:::{AUDIT_BUCKET}/unrelated/object",
    f"arn:aws:s3:::{AUDIT_BUCKET}/{PREFIX}audit/AWSLogs/{ACCOUNT}-other/synthetic",
    f"arn:aws:s3:::{AUDIT_BUCKET}/{PREFIX}audit-other/AWSLogs/{ACCOUNT}/synthetic",
    f"arn:aws:s3:::{AUDIT_BUCKET}/{PREFIX}audit/AWSLogs/{ACCOUNT}",
])
def test_cloudtrail_cannot_write_outside_exact_account_delivery_prefix(template: dict, resource: str) -> None:
    assert _denied(_policy(template, "AuditBucket"), "s3:PutObject", resource, _audit_context())


def test_cloudtrail_delivery_policy_matches_documented_exact_account_contract(template: dict) -> None:
    # AWS documents prefix/AWSLogs/account/* for the CloudTrail delivery contract.
    # This is an offline policy check, not proof of CreateTrail acceptance.
    statements = _policy(template, "AuditBucket")
    delivery_prefix = f"arn:aws:s3:::{AUDIT_BUCKET}/{PREFIX}audit/AWSLogs/{ACCOUNT}/"
    outside = next(s for s in statements if s["Sid"] == "DenyWritesOutsideExactTrailAccountPrefix")
    delivery = next(s for s in statements if s["Sid"] == "ExactTrailLogAndDigestDelivery")
    assert outside["NotResource"] == [delivery_prefix + "*"]
    assert delivery["Resource"] == [delivery_prefix + "*"]
    assert delivery["Principal"] == {"Service": "cloudtrail.amazonaws.com"}
    assert delivery["Condition"] == {"StringEquals": {
        "aws:SourceArn": TRAIL_ARN, "s3:x-amz-acl": "bucket-owner-full-control",
    }}


@pytest.mark.parametrize("key", [
    "CloudTrail/us-east-1/2030/synthetic.json.gz",
    "CloudTrail-Digest/us-east-1/2030/synthetic.json.gz",
    "CloudTrail/us-west-2/2030/synthetic.json.gz",
    "synthetic-service-validation",
])
def test_documented_delivery_namespace_still_needs_exact_trail_and_service(template: dict, key: str) -> None:
    # Account-root delivery permissions and collection Region are distinct controls.
    # The separate trail test still requires us-east-1 and IsMultiRegionTrail=False.
    statements = _policy(template, "AuditBucket")
    resource = f"arn:aws:s3:::{AUDIT_BUCKET}/{PREFIX}audit/AWSLogs/{ACCOUNT}/{key}"
    context = _audit_context()
    assert not _denied(statements, "s3:PutObject", resource, context)
    assert any(s["Effect"] == "Allow" and _matches(s, "s3:PutObject", resource, context)
               for s in statements)
    assert _denied(statements, "s3:PutObject", resource,
                   {**context, "aws:SourceArn": TRAIL_ARN + "-other"})
    assert _denied(statements, "s3:PutObject", resource,
                   {**context, "aws:PrincipalServiceName": "other.amazonaws.com"})


@pytest.mark.parametrize("bucket", ["ReportBucket", "AuditBucket"])
@pytest.mark.parametrize(("headers", "denied"), [
    ({}, False), ({"s3:x-amz-server-side-encryption": "AES256"}, False),
    ({"s3:x-amz-server-side-encryption": "aws:kms"}, True),
    ({"s3:x-amz-server-side-encryption": "aws:kms:dsse"}, True),
    ({"s3:x-amz-server-side-encryption-customer-algorithm": "AES256"}, True),
])
def test_storage_policy_allows_default_sse_s3_but_rejects_unsafe_headers(template: dict, bucket: str, headers: dict, denied: bool) -> None:
    if bucket == "ReportBucket":
        resource = f"arn:aws:s3:::{REPORT_BUCKET}/{PREFIX}reports/job.csv"
        context = {"aws:PrincipalArn": BATCH_ROLE, "aws:SecureTransport": "true"}
    else:
        resource, context = _audit_object(), _audit_context()
    assert _denied(_policy(template, bucket), "s3:PutObject", resource, {**context, **headers}) is denied


@pytest.mark.parametrize("bucket", ["ReportBucket", "AuditBucket"])
def test_insecure_transport_denies_non_service_identities_for_reads_and_writes(
    template: dict, bucket: str,
) -> None:
    policy = _policy(template, bucket)
    name = REPORT_BUCKET if bucket == "ReportBucket" else AUDIT_BUCKET
    statement = next(item for item in policy if item["Sid"] == "DenyInsecureTransport")
    assert statement["Condition"] == {"Bool": {
        "aws:SecureTransport": "false", "aws:PrincipalIsAWSService": "false",
    }}
    context = {"aws:SecureTransport": "false", "aws:PrincipalIsAWSService": "false",
               "aws:PrincipalArn": BATCH_ROLE}
    for action in ("s3:GetObjectVersion", "s3:PutObject"):
        assert _matches(statement, action, f"arn:aws:s3:::{name}/{PREFIX}reports/job.csv", context)


@pytest.mark.parametrize("transport", ["true", "false", None])
def test_direct_cloudtrail_transport_exemption_keeps_service_source_and_prefix_restrictions(
    template: dict, transport: str | None,
) -> None:
    policy = _policy(template, "AuditBucket")
    context = _audit_context()
    if transport is None:
        context.pop("aws:SecureTransport")
    else:
        context["aws:SecureTransport"] = transport
    resource = _audit_object()
    assert not _denied(policy, "s3:PutObject", resource, context)
    assert any(s["Effect"] == "Allow" and _matches(s, "s3:PutObject", resource, context) for s in policy)
    assert _denied(policy, "s3:PutObject", resource, {**context, "aws:SourceArn": TRAIL_ARN + "-other"})
    assert _denied(policy, "s3:PutObject", resource, {**context, "aws:PrincipalServiceName": "other.amazonaws.com"})
    assert _denied(policy, "s3:PutObject", _audit_object(account="999900001111"), context)


@pytest.mark.parametrize("bucket", ["ReportBucket", "AuditBucket"])
@pytest.mark.parametrize("action", ["s3:DeleteObject", "s3:DeleteObjectVersion"])
def test_deletion_is_denied_even_for_expected_writer(template: dict, bucket: str, action: str) -> None:
    name = REPORT_BUCKET if bucket == "ReportBucket" else AUDIT_BUCKET
    assert _denied(_policy(template, bucket), action, f"arn:aws:s3:::{name}/any-object", {
        **_audit_context(), "aws:PrincipalArn": BATCH_ROLE,
    })
