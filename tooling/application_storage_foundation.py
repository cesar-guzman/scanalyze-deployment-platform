"""Offline application-storage preparation and independently bound readback.

The template prepares two baseline-owned keys and one private frontend bucket.
It creates no key ARN or installed-resource receipt. Receipt materialization
requires separately anchored observations; this module never calls AWS.
"""
from __future__ import annotations

import argparse
from copy import deepcopy
from datetime import UTC, datetime
import json
from pathlib import Path
import re

import jsonschema

from tooling.authorize_deployment_backend import load_json_strict
from tooling.destination_baseline_package import write_package
from tooling.workload_foundation import canonical_bytes, digest

ROOT = Path(__file__).resolve().parents[1]
TUPLE_FIELDS = ("customer_id", "deployment_id", "account_id", "region", "environment", "aws_partition")
KEY_NAMES = ("data", "cicd_artifacts")
KEY_PROPERTIES = {
    "key_state": "Enabled", "key_manager": "CUSTOMER", "key_spec": "SYMMETRIC_DEFAULT",
    "key_usage": "ENCRYPT_DECRYPT", "origin": "AWS_KMS", "multi_region": False,
    "rotation_enabled": True,
}
BUCKET_CONTROLS = {
    "encryption": "AES256", "versioning": "Enabled", "ownership": "BucketOwnerEnforced",
    "block_public_acls": True, "block_public_policy": True,
    "ignore_public_acls": True, "restrict_public_buckets": True,
}
UUID = r"[a-f0-9]{8}-(?:[a-f0-9]{4}-){3}[a-f0-9]{12}"
MAX_AGE_SECONDS = 900


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def _schema(value: dict, name: str) -> None:
    schema = load_json_strict(ROOT / "schemas" / f"application-storage-{name}.v1.schema.json")
    try:
        jsonschema.Draft202012Validator(schema).validate(value)
    except jsonschema.ValidationError as error:
        raise ValueError(f"storage {name} shape is invalid") from error


def record_digest(value: dict, field: str) -> str:
    return digest({key: item for key, item in value.items() if key != field})


def _identity(value: dict) -> dict:
    identity = {field: value[field] for field in TUPLE_FIELDS}
    partition = "aws-cn" if identity["region"].startswith("cn-") else "aws-us-gov" if identity["region"].startswith("us-gov-") else "aws"
    _require(identity["aws_partition"] == partition, "storage partition and region disagree")
    return identity


def _request_for(identity: dict) -> dict:
    result = {"schema_version": "1", "record_type": "application_storage_foundation_request",
              **identity, "ownership_mode": "baseline", "installation_mode": "greenfield"}
    result["request_digest"] = record_digest(result, "request_digest")
    return result


def verify_request(request: dict, anchor: dict, expected_request_digest: str) -> dict:
    _schema(request, "request")
    identity = _identity(request)
    _require(request["request_digest"] == record_digest(request, "request_digest") == expected_request_digest,
             "storage request external digest mismatch")
    _require(anchor == {"schema_version": "1", "deployment_id": request["deployment_id"],
                        "request_digest": expected_request_digest}, "storage request anchor mismatch")
    return identity


def resource_tags(identity: dict, name: str) -> dict:
    layer, purpose = {
        "data": ("data-foundation", "application-data-encryption"),
        "cicd_artifacts": ("cicd", "cicd-artifact-encryption"),
        "frontend": ("edge", "frontend-storage"),
    }[name]
    return {"customer_id": identity["customer_id"], "deployment_id": identity["deployment_id"],
            "environment": identity["environment"], "layer": layer, "purpose": purpose,
            "managed_by": "external-account-baseline"}


def key_alias(identity: dict, name: str) -> str:
    suffix = "data" if name == "data" else "cicd-artifacts"
    return f"alias/{identity['deployment_id']}-{suffix}"


def key_policy(identity: dict, name: str) -> dict:
    # Preserve the existing module's account-root delegation; terminal IAM and
    # boundaries still determine which principals may use/administer each key.
    principal = {"AWS": f"arn:{identity['aws_partition']}:iam::{identity['account_id']}:root"}
    statements = [{"Sid": "RootAccountAccess", "Effect": "Allow", "Principal": principal,
                   "Action": "kms:*", "Resource": "*"}]
    if name == "data":
        suffix = "amazonaws.com.cn" if identity["aws_partition"] == "aws-cn" else "amazonaws.com"
        statements.append({
            "Sid": "WorkloadEncryptDecrypt", "Effect": "Allow", "Principal": deepcopy(principal),
            "Action": ["kms:Decrypt", "kms:GenerateDataKey", "kms:GenerateDataKeyWithoutPlaintext", "kms:DescribeKey"],
            "Resource": "*", "Condition": {"StringEquals": {"kms:ViaService": [
                f"{service}.{identity['region']}.{suffix}" for service in ("s3", "dynamodb", "sqs")
            ]}},
        })
    return {"Version": "2012-10-17", "Statement": statements}


def frontend_policy(identity: dict, distribution_arn: str | None = None) -> dict:
    bucket = f"arn:{identity['aws_partition']}:s3:::scanalyze-{identity['account_id']}-frontend"
    policy = {"Version": "2012-10-17", "Statement": [{
        "Sid": "DenyNonTLS", "Effect": "Deny", "Principal": "*", "Action": "s3:*",
        "Resource": [bucket, bucket + "/*"], "Condition": {"Bool": {"aws:SecureTransport": "false"}},
    }]}
    if distribution_arn is not None:
        _require(identity["aws_partition"] == "aws" and re.fullmatch(
            rf"arn:aws:cloudfront::{identity['account_id']}:distribution/[A-Z0-9]{{1,64}}", distribution_arn) is not None,
            "storage OAC distribution identity is invalid")
        policy["Statement"].append({
            "Sid": "AllowDeploymentCloudFrontRead", "Effect": "Allow",
            "Principal": {"Service": "cloudfront.amazonaws.com"}, "Action": "s3:GetObject",
            "Resource": [f"{bucket}/releases/{identity['deployment_id']}/*", f"{bucket}/{identity['deployment_id']}/config.json"],
            "Condition": {"StringEquals": {"AWS:SourceArn": distribution_arn}},
        })
    return policy


def _template(identity: dict, request_digest: str, distribution_arn: str | None = None) -> dict:
    resources = {}
    outputs = {}
    for name, logical in (("data", "Data"), ("cicd_artifacts", "Artifacts")):
        resources[logical + "Key"] = {
            "Type": "AWS::KMS::Key", "DeletionPolicy": "Retain", "UpdateReplacePolicy": "Retain",
            "Properties": {"Description": f"{identity['deployment_id']} baseline-owned {name} encryption",
                           "Enabled": True, "EnableKeyRotation": True, "KeySpec": "SYMMETRIC_DEFAULT",
                           "KeyUsage": "ENCRYPT_DECRYPT", "MultiRegion": False, "PendingWindowInDays": 30,
                           "KeyPolicy": key_policy(identity, name),
                           "Tags": [{"Key": key, "Value": value} for key, value in sorted(resource_tags(identity, name).items())]},
        }
        resources[logical + "Alias"] = {
            "Type": "AWS::KMS::Alias", "DeletionPolicy": "Retain", "UpdateReplacePolicy": "Retain",
            "Properties": {"AliasName": key_alias(identity, name), "TargetKeyId": {"Ref": logical + "Key"}},
        }
        outputs[logical + "KeyArn"] = {"Value": {"Fn::GetAtt": [logical + "Key", "Arn"]}}
    resources["FrontendBucket"] = {
        "Type": "AWS::S3::Bucket", "DeletionPolicy": "Retain", "UpdateReplacePolicy": "Retain",
        "Properties": {
            "BucketName": f"scanalyze-{identity['account_id']}-frontend",
            "BucketEncryption": {"ServerSideEncryptionConfiguration": [{"ServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]},
            "VersioningConfiguration": {"Status": "Enabled"},
            "OwnershipControls": {"Rules": [{"ObjectOwnership": "BucketOwnerEnforced"}]},
            "PublicAccessBlockConfiguration": {key: True for key in ("BlockPublicAcls", "BlockPublicPolicy", "IgnorePublicAcls", "RestrictPublicBuckets")},
            "Tags": [{"Key": key, "Value": value} for key, value in sorted(resource_tags(identity, "frontend").items())],
        },
    }
    resources["FrontendBucketPolicy"] = {
        "Type": "AWS::S3::BucketPolicy", "DeletionPolicy": "Retain", "UpdateReplacePolicy": "Retain",
        "Properties": {"Bucket": {"Ref": "FrontendBucket"}, "PolicyDocument": frontend_policy(identity, distribution_arn)},
    }
    outputs["FrontendBucketName"] = {"Value": {"Ref": "FrontendBucket"}}
    return {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Description": "Greenfield baseline-owned application keys and private frontend storage; no application or OAC access.",
        "Metadata": {"Scanalyze": {"RequestDigest": request_digest, **identity}},
        "Rules": {"BoundDestination": {"Assertions": [
            {"Assert": {"Fn::Equals": [{"Ref": "AWS::AccountId"}, identity["account_id"]]},
             "AssertDescription": "Account must match the approved destination."},
            {"Assert": {"Fn::Equals": [{"Ref": "AWS::Region"}, identity["region"]]},
             "AssertDescription": "Region must match the approved destination."},
        ]}}, "Resources": resources, "Outputs": outputs,
    }


def build_storage_package(request: dict, anchor: dict, expected_request_digest: str) -> dict[str, bytes]:
    identity = verify_request(request, anchor, expected_request_digest)
    template = _template(identity, expected_request_digest)
    manifest = {"schema_version": "1", "status": "PREPARED_NOT_DEPLOYED", "request_digest": expected_request_digest,
                "template_sha256": digest(template), "resource_count": len(template["Resources"]),
                "key_aliases": {name: key_alias(identity, name) for name in KEY_NAMES},
                "key_policy_digests": {name: digest(key_policy(identity, name)) for name in KEY_NAMES},
                "frontend_bucket_name": f"scanalyze-{identity['account_id']}-frontend"}
    return {"cfn-application-storage-foundation.json": canonical_bytes(template), "manifest.json": canonical_bytes(manifest)}


def _time(value: str) -> datetime:
    _require(isinstance(value, str) and re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", value) is not None,
             "storage evidence timestamp is invalid")
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)


def _fresh(observed_at: str, evaluated_at: str) -> None:
    age = (_time(evaluated_at) - _time(observed_at)).total_seconds()
    _require(0 <= age <= MAX_AGE_SECONDS, "storage readback is stale or future-dated")


def _tags(observed: dict, expected: dict, stack_arn: str, logical_id: str) -> None:
    system = {"aws:cloudformation:stack-id": stack_arn,
              "aws:cloudformation:stack-name": stack_arn.split(":stack/", 1)[1].split("/")[0],
              "aws:cloudformation:logical-id": logical_id}
    _require({key: value for key, value in observed.items() if key not in system} == expected
             and all(value == system[key] for key, value in observed.items() if key in system),
             "storage resource ownership tags mismatch")


def _verified_bindings(readback: dict, identity: dict, request_digest: str, expected_template_sha256: str,
                       distribution_arn: str | None = None) -> dict:
    expected_template = _template(identity, request_digest, distribution_arn)
    _require(readback["request_digest"] == request_digest, "storage readback request mismatch")
    _require(digest(readback["actual_template"]) == digest(expected_template) == expected_template_sha256,
             "storage installed template or independent template digest mismatch")
    stack_pattern = rf"arn:{identity['aws_partition']}:cloudformation:{identity['region']}:{identity['account_id']}:stack/[A-Za-z][A-Za-z0-9-]{{0,127}}/{UUID}"
    _require(re.fullmatch(stack_pattern, readback["stack_arn"]) is not None, "storage stack identity mismatch")
    keys = {}
    for name, logical in (("data", "DataKey"), ("cicd_artifacts", "ArtifactsKey")):
        key = readback["keys"][name]
        arn = f"arn:{identity['aws_partition']}:kms:{identity['region']}:{identity['account_id']}:key/{key['key_id']}"
        _require(re.fullmatch(UUID, key["key_id"]) is not None and key["key_arn"] == arn,
                 "storage key ARN or ID mismatch")
        _require(key["alias_name"] == key_alias(identity, name) and key["alias_target_key_id"] == key["key_id"],
                 "storage key alias mismatch")
        _require(all(type(key[field]) is type(value) and key[field] == value for field, value in KEY_PROPERTIES.items()),
                 "storage key properties mismatch")
        _tags(key["tags"], resource_tags(identity, name), readback["stack_arn"], logical)
        _require(key["key_policy"] == key_policy(identity, name), "storage key policy mismatch")
        keys[name] = {field: deepcopy(value) for field, value in key.items() if field not in {"key_policy", "tags"}}
        keys[name].update(tags=resource_tags(identity, name), policy_sha256=digest(key["key_policy"]))
    _require(keys["data"]["key_arn"] != keys["cicd_artifacts"]["key_arn"], "storage keys must be distinct")
    bucket = readback["frontend_bucket"]
    expected_name = f"scanalyze-{identity['account_id']}-frontend"
    _require(bucket["name"] == expected_name and bucket["arn"] == f"arn:{identity['aws_partition']}:s3:::{expected_name}"
             and bucket["region"] == identity["region"] and bucket["owner_account_id"] == identity["account_id"],
             "storage bucket identity mismatch")
    _require(bucket["controls"] == BUCKET_CONTROLS, "storage bucket controls mismatch")
    _tags(bucket["tags"], resource_tags(identity, "frontend"), readback["stack_arn"], "FrontendBucket")
    _require(digest(bucket["bucket_policy"]) == digest(frontend_policy(identity, distribution_arn)), "storage frontend policy mismatch")
    _require(readback["stack_resources"] == {
        "DataKey": keys["data"]["key_id"], "DataAlias": key_alias(identity, "data"),
        "ArtifactsKey": keys["cicd_artifacts"]["key_id"], "ArtifactsAlias": key_alias(identity, "cicd_artifacts"),
        "FrontendBucket": expected_name, "FrontendBucketPolicy": expected_name,
    }, "storage stack physical resources mismatch")
    bucket_binding = {field: deepcopy(value) for field, value in bucket.items() if field not in {"bucket_policy", "tags"}}
    bucket_binding.update(tags=resource_tags(identity, "frontend"), policy_sha256=digest(bucket["bucket_policy"]))
    return {"keys": keys, "frontend_bucket": bucket_binding}


def verify_readback(readback: dict, *, expected_readback_digest: str, expected_tuple: dict,
                    expected_request_digest: str, expected_template_sha256: str, evaluated_at: str,
                    distribution_arn: str | None = None) -> dict:
    _schema(readback, "readback")
    _require(set(expected_tuple) == set(TUPLE_FIELDS) and _identity(readback) == expected_tuple,
             "storage readback target mismatch")
    _require(readback["readback_digest"] == record_digest(readback, "readback_digest") == expected_readback_digest,
             "storage readback external digest mismatch")
    _fresh(readback["observed_at"], evaluated_at)
    return _verified_bindings(readback, expected_tuple, expected_request_digest, expected_template_sha256, distribution_arn)


def materialize_receipt(request: dict, anchor: dict, expected_request_digest: str, readback: dict,
                        expected_readback_digest: str, expected_template_sha256: str, *, evaluated_at: str) -> dict:
    identity = verify_request(request, anchor, expected_request_digest)
    bindings = verify_readback(readback, expected_readback_digest=expected_readback_digest, expected_tuple=identity,
                               expected_request_digest=expected_request_digest, expected_template_sha256=expected_template_sha256,
                               evaluated_at=evaluated_at)
    receipt = {"schema_version": "1", "record_type": "application_storage_foundation_receipt", **identity,
               "ownership_mode": "baseline", "installation_mode": "greenfield", "request_digest": expected_request_digest,
               "template_sha256": expected_template_sha256, "initial_readback_digest": expected_readback_digest,
               "initial_observed_at": readback["observed_at"], **bindings}
    receipt["contract_digest"] = record_digest(receipt, "contract_digest")
    _schema(receipt, "receipt")
    return receipt


def verify_receipt(receipt: dict, expected_receipt_digest: str, expected_tuple: dict) -> dict:
    """Verify durable bindings. Their historical observation timestamp does not expire."""
    _schema(receipt, "receipt")
    _require(set(expected_tuple) == set(TUPLE_FIELDS) and _identity(receipt) == expected_tuple,
             "storage receipt target mismatch")
    _require(receipt["contract_digest"] == record_digest(receipt, "contract_digest") == expected_receipt_digest,
             "storage receipt external digest mismatch")
    request = _request_for(expected_tuple)
    _require(receipt["request_digest"] == request["request_digest"]
             and receipt["template_sha256"] == digest(_template(expected_tuple, request["request_digest"])),
             "storage receipt template/request binding mismatch")
    for name in KEY_NAMES:
        key = receipt["keys"][name]
        _require(key["key_arn"] == f"arn:{expected_tuple['aws_partition']}:kms:{expected_tuple['region']}:{expected_tuple['account_id']}:key/{key['key_id']}"
                 and key["alias_name"] == key_alias(expected_tuple, name) and key["alias_target_key_id"] == key["key_id"]
                 and key["tags"] == resource_tags(expected_tuple, name) and key["policy_sha256"] == digest(key_policy(expected_tuple, name))
                 and all(type(key[field]) is type(value) and key[field] == value for field, value in KEY_PROPERTIES.items()),
                 "storage receipt key bindings mismatch")
    _require(receipt["keys"]["data"]["key_arn"] != receipt["keys"]["cicd_artifacts"]["key_arn"], "storage keys must be distinct")
    bucket = receipt["frontend_bucket"]
    bucket_name = f"scanalyze-{expected_tuple['account_id']}-frontend"
    _require(bucket["name"] == bucket_name and bucket["arn"] == f"arn:{expected_tuple['aws_partition']}:s3:::{bucket_name}"
             and bucket["owner_account_id"] == expected_tuple["account_id"] and bucket["region"] == expected_tuple["region"]
             and bucket["controls"] == BUCKET_CONTROLS and bucket["tags"] == resource_tags(expected_tuple, "frontend")
             and bucket["policy_sha256"] == digest(frontend_policy(expected_tuple)), "storage receipt bucket bindings mismatch")
    _time(receipt["initial_observed_at"])
    return deepcopy(receipt)


def evaluate_live_evidence(receipt: dict, expected_receipt_digest: str, expected_tuple: dict,
                           readback: dict, expected_readback_digest: str, *, evaluated_at: str,
                           application_storage_access: dict | None = None,
                           expected_application_storage_access: dict | None = None) -> dict:
    durable = verify_receipt(receipt, expected_receipt_digest, expected_tuple)
    distribution_arn = None
    template_sha256 = durable["template_sha256"]
    if application_storage_access is not None or expected_application_storage_access is not None:
        from tooling.application_storage_oac import verify_access
        distribution_arn, template_sha256 = verify_access(
            durable, expected_tuple, application_storage_access, expected_application_storage_access, evaluated_at=evaluated_at)
    bindings = verify_readback(readback, expected_readback_digest=expected_readback_digest, expected_tuple=expected_tuple,
                               expected_request_digest=durable["request_digest"], expected_template_sha256=template_sha256,
                               evaluated_at=evaluated_at, distribution_arn=distribution_arn)
    expected_bindings = {key: deepcopy(durable[key]) for key in ("keys", "frontend_bucket")}
    expected_bindings["frontend_bucket"]["policy_sha256"] = digest(frontend_policy(expected_tuple, distribution_arn))
    _require(bindings == expected_bindings, "storage live bindings changed")
    return {"status": "FRESH_READBACK_MATCHES_DURABLE_BINDINGS", "receipt_digest": expected_receipt_digest,
            "readback_digest": expected_readback_digest, "observed_at": readback["observed_at"], "evaluated_at": evaluated_at}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    prepare = commands.add_parser("prepare")
    bind = commands.add_parser("materialize")
    evaluate = commands.add_parser("evaluate-live")
    for command in (prepare, bind):
        command.add_argument("--request", required=True, type=Path)
        command.add_argument("--request-anchor", required=True, type=Path)
        command.add_argument("--expected-request-digest", required=True)
        command.add_argument("--out-dir", required=True, type=Path)
    for command in (bind, evaluate):
        command.add_argument("--readback", required=True, type=Path)
        command.add_argument("--expected-readback-digest", required=True)
    bind.add_argument("--expected-template-sha256", required=True)
    evaluate.add_argument("--receipt", required=True, type=Path)
    evaluate.add_argument("--expected-receipt-digest", required=True)
    evaluate.add_argument("--expected-tuple", required=True, type=Path)
    evaluate.add_argument("--access", type=Path)
    evaluate.add_argument("--expected-access", type=Path)
    args = parser.parse_args(argv)
    try:
        now = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
        if args.command == "evaluate-live":
            result = evaluate_live_evidence(load_json_strict(args.receipt), args.expected_receipt_digest,
                                            load_json_strict(args.expected_tuple), load_json_strict(args.readback),
                                            args.expected_readback_digest, evaluated_at=now,
                                            application_storage_access=load_json_strict(args.access) if args.access else None,
                                            expected_application_storage_access=load_json_strict(args.expected_access) if args.expected_access else None)
            print(json.dumps(result, sort_keys=True))
            return 0
        request, anchor = load_json_strict(args.request), load_json_strict(args.request_anchor)
        if args.command == "prepare":
            artifacts = build_storage_package(request, anchor, args.expected_request_digest)
            status = "PREPARED_NOT_DEPLOYED"
        else:
            receipt = materialize_receipt(request, anchor, args.expected_request_digest, load_json_strict(args.readback),
                                          args.expected_readback_digest, args.expected_template_sha256, evaluated_at=now)
            artifacts = {"application-storage-foundation.json": canonical_bytes(receipt)}
            status = "READBACK_BOUND_REQUIRES_INDEPENDENT_RECEIPT_ANCHOR"
        write_package(artifacts, args.out_dir)
    except (ValueError, TypeError, KeyError, OSError):
        parser.exit(2, "STORAGE_FOUNDATION_REJECTED: input or output validation failed\n")
    print(status)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
