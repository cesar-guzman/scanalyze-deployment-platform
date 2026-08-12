"""Focused fail-closed tests for the GUG-363 retirement entrypoint.

The provider clients below are strict in-memory fakes.  No test loads ambient
AWS credentials, opens a network connection, or invokes the retirement broker.
"""

from __future__ import annotations

import base64
import copy
from datetime import UTC, datetime, timedelta
from hashlib import sha256
import importlib.util
from io import BytesIO
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
from typing import Any, Mapping
import warnings
import zipfile

import pytest


REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tooling.platform_authority_change_set_retirement_package import (  # noqa: E402
    SOURCE_PATHS,
    build_retirement_package,
)
from tooling import (  # noqa: E402
    platform_authority_retirement_entrypoint_materializer as materializer,
)


NOW = datetime(2030, 1, 1, 0, 5, tzinfo=UTC)
RUNTIME_ARN = f"arn:aws:lambda:{materializer.REGION}::runtime:" + "a" * 64
VERSION_BINDING = "sha256:" + "b" * 64
OWNER_AUTHORIZATION = "sha256:" + "c" * 64
EXCEPTION_DIGEST = "sha256:" + "d" * 64
CALLER_ARN = (
    f"arn:aws:sts::{materializer.AUTHORITY_ACCOUNT_ID}:"
    "assumed-role/ScanalyzeGug363Materializer/synthetic-operator"
)
CALLER_USER_ID = "AROASYNTHETIC:synthetic-operator"
STACK_ID = (
    f"arn:aws:cloudformation:{materializer.REGION}:"
    f"{materializer.AUTHORITY_ACCOUNT_ID}:stack/"
    f"{materializer.DEDICATED_STACK_NAME}/"
    "12345678-1234-1234-1234-1234567890ab"
)
SIGNING_JOB_ID = "11111111-2222-3333-4444-555555555555"
SIGNING_PROFILE_NAME = "ScanalyzeGug215Lambda"
SIGNING_PROFILE_VERSION = "AbCdEf1234"
SIGNING_PROFILE_VERSION_ARN = (
    f"arn:aws:signer:{materializer.REGION}:{materializer.AUTHORITY_ACCOUNT_ID}:"
    f"/signing-profiles/{SIGNING_PROFILE_NAME}/{SIGNING_PROFILE_VERSION}"
)
CODE_SIGNING_CONFIG_ARN = (
    f"arn:aws:lambda:{materializer.REGION}:"
    f"{materializer.AUTHORITY_ACCOUNT_ID}:"
    "code-signing-config:csc-0123456789abcdef"
)
ARTIFACT_PAYLOADS: dict[str, bytes] = {}


def _run_git(root: Path, *arguments: str) -> str:
    return subprocess.run(
        ["git", *arguments],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    ).stdout.strip()


def _synthetic_source(tmp_path: Path) -> tuple[Path, str, str, str]:
    """Create the smallest clean Git source accepted by the materializer."""

    source = tmp_path / "synthetic-source"
    template = source / materializer.TEMPLATE_PATH
    template.parent.mkdir(parents=True)
    shutil.copyfile(REPO_ROOT / materializer.TEMPLATE_PATH, template)
    _run_git(source, "init", "-q")
    _run_git(source, "config", "user.email", "synthetic@example.invalid")
    _run_git(source, "config", "user.name", "Synthetic Test")
    _run_git(source, "add", "--", materializer.TEMPLATE_PATH.as_posix())
    _run_git(source, "commit", "-q", "-m", "synthetic GUG-363 source")
    commit = _run_git(source, "rev-parse", "HEAD")
    tree = _run_git(source, "rev-parse", "HEAD^{tree}")
    template_digest = "sha256:" + sha256(template.read_bytes()).hexdigest()
    return source, commit, tree, template_digest


def _intent(
    *,
    commit: str,
    tree: str,
    template_digest: str,
    package_manifest: Mapping[str, Any],
    signed_archive: bytes,
) -> dict[str, Any]:
    unsigned_source = {
        "artifact_type": package_manifest["artifact_type"],
        "work_package": package_manifest["work_package"],
        "manifest_digest": package_manifest["manifest_digest"],
        "archive_sha256": package_manifest["archive_sha256"],
        "lambda_code_sha256": package_manifest["lambda_code_sha256"],
        "archive_size_bytes": package_manifest["archive_size_bytes"],
        "bucket": "scanalyze-gug363-synthetic-artifact",
        "key": (
            "scanalyze/platform-authority/gug-215/unsigned/"
            f"{commit}/"
            "scanalyze-gug215-change-set-retirement-broker.zip"
        ),
        "version_id": "synthetic-unsigned-version-0001",
        "sse_algorithm": "aws:kms",
        "sse_kms_key_arn": (
            f"arn:aws:kms:{materializer.REGION}:"
            f"{materializer.AUTHORITY_ACCOUNT_ID}:key/"
            "12345678-1234-1234-1234-1234567890ab"
        ),
    }
    signed_digest = sha256(signed_archive).digest()
    signed_destination = {
        "bucket": unsigned_source["bucket"],
        "key": (
            "scanalyze/platform-authority/gug-215/signed/"
            f"{SIGNING_JOB_ID}.zip"
        ),
        "version_id": "synthetic-signed-version-0001",
        "archive_sha256": signed_digest.hex(),
        "lambda_code_sha256": base64.b64encode(signed_digest).decode("ascii"),
        "archive_size_bytes": len(signed_archive),
        "sse_algorithm": "aws:kms",
        "sse_kms_key_arn": unsigned_source["sse_kms_key_arn"],
    }
    artifact_signing_contract = {
        "contract_version": 1,
        "unsigned_source": unsigned_source,
        "signer": {
            "job_id": SIGNING_JOB_ID,
            "status": "Succeeded",
            "job_owner": materializer.AUTHORITY_ACCOUNT_ID,
            "job_invoker": materializer.AUTHORITY_ACCOUNT_ID,
            "platform_id": materializer.SIGNING_PLATFORM,
            "profile_name": SIGNING_PROFILE_NAME,
            "profile_version_id": SIGNING_PROFILE_VERSION,
            "profile_version_arn": SIGNING_PROFILE_VERSION_ARN,
            "signature_expires_at": "2030-01-01T00:14:00Z",
        },
        "signed_destination": signed_destination,
        "code_signing_config": {
            "arn": CODE_SIGNING_CONFIG_ARN,
            "allowed_signing_profile_version_arns": [
                SIGNING_PROFILE_VERSION_ARN
            ],
            "untrusted_artifact_on_deployment": "Enforce",
        },
    }
    parameters = {
        "AuthorizationMode": materializer.AUTHORIZATION_MODE,
        "AuthorityAccountId": materializer.AUTHORITY_ACCOUNT_ID,
        "ChangeSetName": "scanalyze-platform-authority-bootstrap-20300101000500",
        "RetirementId": "gug215#sha256:" + "1" * 64,
        "ExpectedTemplateSha256": template_digest,
        "ExpectedEvidenceSha256": "sha256:" + "2" * 64,
        "ExpectedBrokerPolicySha256": "sha256:" + "3" * 64,
        materializer.PRIVATE_PARAMETER_PROJECTION_KEY: "",
        "BrokerArtifactBucket": signed_destination["bucket"],
        "BrokerArtifactKey": signed_destination["key"],
        "BrokerArtifactVersion": signed_destination["version_id"],
        "BrokerArtifactCodeSha256": signed_destination["lambda_code_sha256"],
        "BrokerCodeSigningConfigArn": CODE_SIGNING_CONFIG_ARN,
        "BrokerRuntimeVersionArn": RUNTIME_ARN,
        "BrokerVersionBindingSha256": VERSION_BINDING,
        "IdentityStoreArn": (
            f"arn:aws:identitystore::{materializer.AUTHORITY_ACCOUNT_ID}:"
            "identitystore/d-a1b2c3d4e5"
        ),
        "IdentityCenterInstanceArn": (
            "arn:aws:sso:::instance/ssoins-A1B2C3D4E5F6G7H8"
        ),
        "IdentityCenterApplicationArn": (
            f"arn:aws:sso::{materializer.AUTHORITY_ACCOUNT_ID}:application/"
            "ssoins-A1B2C3D4E5F6G7H8/apl-Z9Y8X7W6V5U4T3S2"
        ),
        "IdentityCenterRedirectUri": "http://127.0.0.1:49152/callback",
        "ClassifierIdentityStoreUserId": (
            "00000000-0000-4000-8000-000000000001"
        ),
        "ApproverIdentityStoreUserId": (
            "00000000-0000-4000-8000-000000000001"
        ),
        "ClassifierAssignmentSha256": "sha256:" + "4" * 64,
        "ApproverAssignmentSha256": "sha256:" + "5" * 64,
        "ClassifierInvokerPolicySha256": "sha256:" + "6" * 64,
        "ApproverInvokerPolicySha256": "sha256:" + "7" * 64,
        "ClassifierProofPolicySha256": "sha256:" + "8" * 64,
        "ApproverProofPolicySha256": "sha256:" + "9" * 64,
        "IdentityCenterApplicationActorPolicySha256": "sha256:" + "a" * 64,
        "ClassifierPermissionSetRoleArn": (
            f"arn:aws:iam::{materializer.AUTHORITY_ACCOUNT_ID}:role/"
            "aws-reserved/sso.amazonaws.com/us-east-1/"
            "AWSReservedSSO_ScanalyzeAuthorityRetireClass_0123456789abcdef"
        ),
        "ApproverPermissionSetRoleArn": (
            f"arn:aws:iam::{materializer.AUTHORITY_ACCOUNT_ID}:role/"
            "aws-reserved/sso.amazonaws.com/us-east-1/"
            "AWSReservedSSO_ScanalyzeAuthorityRetireApprove_fedcba9876543210"
        ),
        "SingleOperatorOwnerAuthorizationSha256": OWNER_AUTHORIZATION,
        "SingleOperatorExpectedAuthorizationSha256": EXCEPTION_DIGEST,
        "SingleOperatorExceptionCreatedAt": "2030-01-01T00:00:00Z",
        "SingleOperatorExceptionNotBefore": "2030-01-01T00:04:00Z",
        "SingleOperatorExceptionExpiresAt": "2030-01-01T00:14:00Z",
    }
    parameters[materializer.PRIVATE_PARAMETER_PROJECTION_KEY] = (
        materializer.private_parameter_projection_digest(parameters)
    )
    intent: dict[str, Any] = {
        "record_type": materializer.INTENT_TYPE,
        "schema_version": 1,
        "implementation_issue": materializer.IMPLEMENTATION_ISSUE,
        "live_issue": materializer.LIVE_ISSUE,
        "environment": "synthetic-non-production",
        "production": False,
        "deployment_authorized": False,
        "authorization_mode": materializer.AUTHORIZATION_MODE,
        "two_human_status": "NOT_PROVEN",
        "independent_approval_present": False,
        "target": {
            "authority_account_id": materializer.AUTHORITY_ACCOUNT_ID,
            "region": materializer.REGION,
            "stack_name": materializer.DEDICATED_STACK_NAME,
            "cloudformation_service_role_arn": (
                materializer.CLOUDFORMATION_SERVICE_ROLE_ARN
            ),
        },
        "source": {
            "commit": commit,
            "tree": tree,
            "template_path": materializer.TEMPLATE_PATH.as_posix(),
            "template_sha256": template_digest,
        },
        "artifact_signing_contract": artifact_signing_contract,
        "artifact_signing_contract_digest": (
            materializer.artifact_signing_contract_digest(
                artifact_signing_contract
            )
        ),
        "artifact_signing_evidence_digest": (
            materializer.artifact_signing_evidence_digest(
                artifact_signing_contract
            )
        ),
        "parameters": parameters,
        "owner_authorization_sha256": OWNER_AUTHORIZATION,
        "single_operator_exception_digest": EXCEPTION_DIGEST,
        "intent_digest": "",
    }
    intent["intent_digest"] = materializer.canonical_digest(
        {key: value for key, value in intent.items() if key != "intent_digest"}
    )
    return intent


@pytest.fixture
def bundle(tmp_path: Path) -> dict[str, Any]:
    source, commit, tree, template_digest = _synthetic_source(tmp_path)
    committed_sources = {
        path: b"" if path.as_posix() == "tooling/__init__.py" else b"# synthetic\n"
        for path in SOURCE_PATHS
    }
    built = build_retirement_package(
        source_root=source,
        source_commit=commit,
        broker_runtime_version_arn=RUNTIME_ARN,
        broker_version_binding_sha256=VERSION_BINDING,
        committed_sources=committed_sources,
    )
    signed_archive = built.archive + b"scanalyze-gug363-signer-envelope-v1"
    intent = _intent(
        commit=commit,
        tree=tree,
        template_digest=template_digest,
        package_manifest=built.manifest,
        signed_archive=signed_archive,
    )
    ARTIFACT_PAYLOADS.clear()
    ARTIFACT_PAYLOADS.update(
        {
            intent["artifact_signing_contract"]["unsigned_source"]["version_id"]: (
                built.archive
            ),
            intent["artifact_signing_contract"]["signed_destination"]["version_id"]: (
                signed_archive
            ),
        }
    )
    plan = materializer.build_materialization_plan(
        intent=intent,
        package_manifest=built.manifest,
        package_archive=built.archive,
        repo_root=source,
    )
    return {
        "repo": source,
        "intent": intent,
        "manifest": built.manifest,
        "archive": built.archive,
        "signed_archive": signed_archive,
        "plan": plan,
    }


def _plan_for_signed_archive(
    bundle: Mapping[str, Any], signed_archive: bytes
) -> dict[str, Any]:
    source_contract = bundle["intent"]["source"]
    intent = _intent(
        commit=source_contract["commit"],
        tree=source_contract["tree"],
        template_digest=source_contract["template_sha256"],
        package_manifest=bundle["manifest"],
        signed_archive=signed_archive,
    )
    plan = materializer.build_materialization_plan(
        intent=intent,
        package_manifest=bundle["manifest"],
        package_archive=bundle["archive"],
        repo_root=bundle["repo"],
    )
    ARTIFACT_PAYLOADS.clear()
    ARTIFACT_PAYLOADS.update(
        {
            plan["artifact_signing_contract"]["unsigned_source"]["version_id"]: (
                bundle["archive"]
            ),
            plan["artifact_signing_contract"]["signed_destination"]["version_id"]: (
                signed_archive
            ),
        }
    )
    return plan


def _signed_zip_variant(unsigned_archive: bytes, variant: str) -> bytes:
    source = zipfile.ZipFile(BytesIO(unsigned_archive), mode="r")
    output = BytesIO()
    with source, zipfile.ZipFile(output, mode="w", compression=zipfile.ZIP_STORED) as target:
        members = source.infolist()
        assert members
        for index, member in enumerate(members):
            payload = source.read(member)
            if variant == "changed-member" and index == 0:
                payload += b"tampered"
            target.writestr(member.filename, payload)
        if variant == "path-traversal":
            target.writestr("../escape.py", b"raise SystemExit")
        elif variant == "duplicate-member":
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", UserWarning)
                target.writestr(members[0].filename, source.read(members[0]))
        elif variant == "symlink-member":
            link = zipfile.ZipInfo("tooling/synthetic-link")
            link.create_system = 3
            link.external_attr = (stat.S_IFLNK | 0o777) << 16
            target.writestr(link, b"../../outside")
    return output.getvalue()


def _authorization(
    plan: Mapping[str, Any], *, caller_arn: str = CALLER_ARN
) -> dict[str, Any]:
    authorization: dict[str, Any] = {
        "record_type": materializer.AUTHORIZATION_TYPE,
        "schema_version": 1,
        "issue_id": materializer.LIVE_ISSUE,
        "environment": "synthetic-non-production",
        "production": False,
        "deployment_authorized": True,
        "authorization_mode": materializer.AUTHORIZATION_MODE,
        "two_human_status": "NOT_PROVEN",
        "independent_approval_present": False,
        "target": copy.deepcopy(plan["target"]),
        "plan_digest": plan["plan_digest"],
        "create_stack_request_digest": plan["create_stack_request_digest"],
        "operation_list_digest": plan["operation_list_digest"],
        "artifact_signing_contract_digest": plan[
            "artifact_signing_contract_digest"
        ],
        "artifact_signing_evidence_digest": plan[
            "artifact_signing_evidence_digest"
        ],
        "owner_authorization_sha256": plan["owner_authorization_sha256"],
        "caller_arn_sha256": materializer.digest_text(caller_arn),
        "caller_user_id_sha256": materializer.digest_text(CALLER_USER_ID),
        "live_checkpoint_digest": "sha256:" + "e" * 64,
        "live_before_state_digest": "sha256:" + "f" * 64,
        "service_role_evidence_digest": "sha256:" + "0" * 64,
        "operator_authority_evidence_digest": "sha256:" + "1" * 64,
        "allowed_action": "cloudformation:CreateStack",
        "forbidden_actions": list(materializer.PROHIBITED_OPERATIONS),
        "max_attempts": 1,
        "not_before": "2030-01-01T00:04:00Z",
        "expires_at": "2030-01-01T00:14:00Z",
    }
    authorization["authorization_digest"] = materializer.canonical_digest(
        authorization
    )
    return authorization


def _reseal(
    record: dict[str, Any], digest_field: str
) -> dict[str, Any]:
    record[digest_field] = materializer.canonical_digest(
        {key: value for key, value in record.items() if key != digest_field}
    )
    return record


def _expected_stack(
    plan: Mapping[str, Any],
    *,
    status: str = "CREATE_COMPLETE",
    role_arn: str | None = None,
    mask_no_echo: bool = True,
    deletion_mode: str | None = None,
) -> dict[str, Any]:
    parameters = copy.deepcopy(plan["parameter_projection"])
    if mask_no_echo:
        for parameter in parameters:
            if parameter["ParameterKey"] in materializer.NO_ECHO_PARAMETER_KEYS:
                parameter["ParameterValue"] = "****"
    stack = {
        "StackId": STACK_ID,
        "StackName": materializer.DEDICATED_STACK_NAME,
        "StackStatus": status,
        "Capabilities": list(materializer.CAPABILITIES),
        "DisableRollback": True,
        "EnableTerminationProtection": True,
        "NotificationARNs": [],
        "RetainExceptOnCreate": False,
        "RoleARN": (
            materializer.CLOUDFORMATION_SERVICE_ROLE_ARN
            if role_arn is None
            else role_arn
        ),
        "Parameters": parameters,
        "RollbackConfiguration": {
            "RollbackTriggers": [],
            "MonitoringTimeInMinutes": 0,
        },
        "Tags": [],
    }
    if deletion_mode is not None:
        stack["DeletionMode"] = deletion_mode
    return stack


def _head_response(plan: Mapping[str, Any]) -> dict[str, Any]:
    artifact = plan["artifact_signing_contract"]["signed_destination"]
    return {
        "VersionId": artifact["version_id"],
        "ContentLength": artifact["archive_size_bytes"],
        "ChecksumSHA256": artifact["lambda_code_sha256"],
        "ChecksumType": "FULL_OBJECT",
        "ServerSideEncryption": artifact["sse_algorithm"],
        "SSEKMSKeyId": artifact["sse_kms_key_arn"],
    }


class FakeAwsError(Exception):
    def __init__(self, code: str, message: str) -> None:
        self.response = {"Error": {"Code": code, "Message": message}}
        super().__init__(message)


class FakeSts:
    def __init__(
        self,
        calls: list[str],
        *,
        caller_arn: str = CALLER_ARN,
        caller_user_id: str = CALLER_USER_ID,
    ) -> None:
        self.calls = calls
        self.caller_arn = caller_arn
        self.caller_user_id = caller_user_id

    def get_caller_identity(self) -> dict[str, str]:
        self.calls.append("sts:GetCallerIdentity")
        return {
            "Account": materializer.AUTHORITY_ACCOUNT_ID,
            "Arn": self.caller_arn,
            "UserId": self.caller_user_id,
        }


class FakeS3:
    def __init__(
        self,
        calls: list[str],
        plan: Mapping[str, Any],
        response: Mapping[str, Any],
        *,
        mutations: Mapping[str, Any] | None = None,
    ) -> None:
        self.calls = calls
        self.plan = plan
        self.response = dict(response)
        self.mutations = dict(mutations or {})
        self.requests: list[dict[str, Any]] = []

    def _expected(self, version_id: str) -> Mapping[str, Any]:
        contract = self.plan["artifact_signing_contract"]
        for key in ("unsigned_source", "signed_destination"):
            expected = contract[key]
            if expected["version_id"] == version_id:
                return expected
        pytest.fail(f"unexpected artifact version: {version_id}")

    @staticmethod
    def _metadata(expected: Mapping[str, Any]) -> dict[str, Any]:
        return {
            "VersionId": expected["version_id"],
            "ContentLength": expected["archive_size_bytes"],
            "ChecksumSHA256": expected["lambda_code_sha256"],
            "ChecksumType": "FULL_OBJECT",
            "ServerSideEncryption": expected["sse_algorithm"],
            "SSEKMSKeyId": expected["sse_kms_key_arn"],
        }

    def _mutate(self, operation: str, response: dict[str, Any]) -> dict[str, Any]:
        mutation = self.mutations.get(operation)
        if isinstance(mutation, BaseException):
            raise mutation
        if callable(mutation):
            return mutation(copy.deepcopy(response))
        if isinstance(mutation, Mapping):
            response.update(copy.deepcopy(dict(mutation)))
        return response

    def get_bucket_versioning(self, **kwargs: Any) -> dict[str, Any]:
        self.calls.append("s3:GetBucketVersioning")
        self.requests.append(copy.deepcopy(kwargs))
        return self._mutate("s3:GetBucketVersioning", {"Status": "Enabled"})

    def head_object(self, **kwargs: Any) -> dict[str, Any]:
        self.calls.append("s3:HeadObject")
        self.requests.append(copy.deepcopy(kwargs))
        expected = self._expected(kwargs["VersionId"])
        response = self._metadata(expected)
        if expected is self.plan["artifact_signing_contract"]["signed_destination"]:
            response.update(copy.deepcopy(self.response))
        operation = (
            "s3:HeadObject:unsigned"
            if expected is self.plan["artifact_signing_contract"]["unsigned_source"]
            else "s3:HeadObject:signed"
        )
        return self._mutate(operation, response)

    def get_object(self, **kwargs: Any) -> dict[str, Any]:
        self.calls.append("s3:GetObject")
        self.requests.append(copy.deepcopy(kwargs))
        expected = self._expected(kwargs["VersionId"])
        payload = ARTIFACT_PAYLOADS[expected["version_id"]]
        response = {
            **self._metadata(expected),
            "Body": BytesIO(payload),
        }
        operation = (
            "s3:GetObject:unsigned"
            if expected is self.plan["artifact_signing_contract"]["unsigned_source"]
            else "s3:GetObject:signed"
        )
        return self._mutate(operation, response)

    def list_object_versions(self, **kwargs: Any) -> dict[str, Any]:
        self.calls.append("s3:ListObjectVersions")
        self.requests.append(copy.deepcopy(kwargs))
        expected = self.plan["artifact_signing_contract"]["signed_destination"]
        response = {
            "IsTruncated": False,
            "Name": expected["bucket"],
            "Prefix": expected["key"],
            "Versions": [
                {
                    "Key": expected["key"],
                    "VersionId": expected["version_id"],
                    "IsLatest": True,
                    "Size": expected["archive_size_bytes"],
                }
            ],
            "DeleteMarkers": [],
        }
        return self._mutate("s3:ListObjectVersions", response)


class FakeSigner:
    def __init__(
        self,
        calls: list[str],
        plan: Mapping[str, Any],
        *,
        mutations: Mapping[str, Any] | None = None,
    ) -> None:
        self.calls = calls
        self.plan = plan
        self.mutations = dict(mutations or {})

    def _mutate(self, operation: str, response: dict[str, Any]) -> dict[str, Any]:
        mutation = self.mutations.get(operation)
        if isinstance(mutation, BaseException):
            raise mutation
        if callable(mutation):
            return mutation(copy.deepcopy(response))
        if isinstance(mutation, Mapping):
            response.update(copy.deepcopy(dict(mutation)))
        return response

    def describe_signing_job(self, **kwargs: Any) -> dict[str, Any]:
        self.calls.append("signer:DescribeSigningJob")
        contract = self.plan["artifact_signing_contract"]
        signer = contract["signer"]
        unsigned = contract["unsigned_source"]
        signed = contract["signed_destination"]
        assert kwargs == {"jobId": signer["job_id"]}
        response = {
            "jobId": signer["job_id"],
            "status": signer["status"],
            "jobOwner": signer["job_owner"],
            "jobInvoker": signer["job_invoker"],
            "platformId": signer["platform_id"],
            "profileName": signer["profile_name"],
            "profileVersion": signer["profile_version_id"],
            "signatureExpiresAt": NOW.replace(minute=14),
            "source": {
                "s3": {
                    "bucketName": unsigned["bucket"],
                    "key": unsigned["key"],
                    "version": unsigned["version_id"],
                }
            },
            "signedObject": {
                "s3": {"bucketName": signed["bucket"], "key": signed["key"]}
            },
        }
        return self._mutate("signer:DescribeSigningJob", response)

    def get_signing_profile(self, **kwargs: Any) -> dict[str, Any]:
        self.calls.append("signer:GetSigningProfile")
        signer = self.plan["artifact_signing_contract"]["signer"]
        assert kwargs == {
            "profileName": signer["profile_name"],
            "profileOwner": materializer.AUTHORITY_ACCOUNT_ID,
        }
        response = {
            "profileName": signer["profile_name"],
            "profileVersion": signer["profile_version_id"],
            "profileVersionArn": signer["profile_version_arn"],
            "platformId": signer["platform_id"],
            "status": "Active",
        }
        return self._mutate("signer:GetSigningProfile", response)


class FakeLambda:
    def __init__(
        self,
        calls: list[str],
        plan: Mapping[str, Any],
        *,
        mutation: Any = None,
    ) -> None:
        self.calls = calls
        self.plan = plan
        self.mutation = mutation

    def get_code_signing_config(self, **kwargs: Any) -> dict[str, Any]:
        self.calls.append("lambda:GetCodeSigningConfig")
        expected = self.plan["artifact_signing_contract"]["code_signing_config"]
        assert kwargs == {"CodeSigningConfigArn": expected["arn"]}
        response = {
            "CodeSigningConfig": {
                "CodeSigningConfigId": expected["arn"].rsplit(":", 1)[-1],
                "CodeSigningConfigArn": expected["arn"],
                "AllowedPublishers": {
                    "SigningProfileVersionArns": expected[
                        "allowed_signing_profile_version_arns"
                    ]
                },
                "CodeSigningPolicies": {
                    "UntrustedArtifactOnDeployment": expected[
                        "untrusted_artifact_on_deployment"
                    ]
                },
                "LastModified": "2030-01-01T00:00:00Z",
            }
        }
        if isinstance(self.mutation, BaseException):
            raise self.mutation
        if callable(self.mutation):
            return self.mutation(copy.deepcopy(response))
        return response


class FakeCloudFormation:
    def __init__(
        self,
        *,
        calls: list[str],
        plan: Mapping[str, Any],
        name_descriptions: list[Mapping[str, Any] | None],
        post_create_stack: Mapping[str, Any] | None = None,
        create_error: BaseException | None = None,
        template_body: str | None = None,
        resources: list[Mapping[str, str]] | None = None,
        resource_status: str = "CREATE_COMPLETE",
        physical_ids_present: bool = True,
        event_token: str | None = None,
    ) -> None:
        self.calls = calls
        self.plan = plan
        self.name_descriptions = list(name_descriptions)
        self.post_create_stack = post_create_stack
        self.create_error = create_error
        self.template_body = (
            plan["create_stack_request"]["TemplateBody"]
            if template_body is None
            else template_body
        )
        self.resources = copy.deepcopy(
            plan["expected_resources"] if resources is None else resources
        )
        self.resource_status = resource_status
        self.physical_ids_present = physical_ids_present
        self.event_token = (
            plan["client_request_token"] if event_token is None else event_token
        )
        self.name_describe_count = 0
        self.create_requests: list[dict[str, Any]] = []

    def describe_stacks(self, *, StackName: str) -> dict[str, Any]:
        self.calls.append("cloudformation:DescribeStacks")
        if StackName == materializer.DEDICATED_STACK_NAME:
            index = min(
                self.name_describe_count,
                max(len(self.name_descriptions) - 1, 0),
            )
            self.name_describe_count += 1
            stack = self.name_descriptions[index] if self.name_descriptions else None
        elif StackName == STACK_ID:
            stack = self.post_create_stack
        else:
            stack = None
        if stack is None:
            raise FakeAwsError(
                "ValidationError",
                f"Stack with id {materializer.DEDICATED_STACK_NAME} does not exist",
            )
        return {"Stacks": [copy.deepcopy(stack)]}

    def create_stack(self, **kwargs: Any) -> dict[str, str]:
        self.calls.append("cloudformation:CreateStack")
        self.create_requests.append(copy.deepcopy(kwargs))
        if self.create_error is not None:
            raise self.create_error
        return {"StackId": STACK_ID}

    def get_template(self, **kwargs: Any) -> dict[str, str]:
        self.calls.append("cloudformation:GetTemplate")
        assert kwargs == {"StackName": STACK_ID, "TemplateStage": "Original"}
        return {"TemplateBody": self.template_body}

    def list_stack_resources(self, **kwargs: Any) -> dict[str, Any]:
        self.calls.append("cloudformation:ListStackResources")
        assert kwargs == {"StackName": STACK_ID}
        return {
            "StackResourceSummaries": [
                {
                    "LogicalResourceId": item["logical_resource_id"],
                    "ResourceType": item["resource_type"],
                    "ResourceStatus": self.resource_status,
                    **(
                        {
                            "PhysicalResourceId": (
                                f"synthetic-{item['logical_resource_id']}"
                            )
                        }
                        if self.physical_ids_present
                        else {}
                    ),
                }
                for item in self.resources
            ]
        }

    def describe_stack_events(self, **kwargs: Any) -> dict[str, Any]:
        self.calls.append("cloudformation:DescribeStackEvents")
        assert kwargs == {"StackName": STACK_ID}
        return {"StackEvents": [{"ClientRequestToken": self.event_token}]}


class FakeFactory:
    def __init__(
        self,
        *,
        calls: list[str],
        cfn: FakeCloudFormation,
        s3_response: Mapping[str, Any],
        signer_mutations: Mapping[str, Any] | None = None,
        s3_mutations: Mapping[str, Any] | None = None,
        lambda_mutation: Any = None,
        caller_arn: str = CALLER_ARN,
        caller_user_id: str = CALLER_USER_ID,
    ) -> None:
        self._sts = FakeSts(
            calls,
            caller_arn=caller_arn,
            caller_user_id=caller_user_id,
        )
        self._cfn = cfn
        self._signer = FakeSigner(
            calls, cfn.plan, mutations=signer_mutations
        )
        self._s3 = FakeS3(
            calls, cfn.plan, s3_response, mutations=s3_mutations
        )
        self._lambda = FakeLambda(calls, cfn.plan, mutation=lambda_mutation)

    def sts(self) -> FakeSts:
        return self._sts

    def cloudformation(self) -> FakeCloudFormation:
        return self._cfn

    def signer(self) -> FakeSigner:
        return self._signer

    def s3(self) -> FakeS3:
        return self._s3

    def lambda_client(self) -> FakeLambda:
        return self._lambda


def _ledger(
    plan: Mapping[str, Any], authorization: Mapping[str, Any]
) -> dict[str, Any]:
    return materializer.build_execution_ledger(
        plan=plan,
        authorization=authorization,
        caller_arn_sha256=materializer.digest_text(CALLER_ARN),
        claimed_at=NOW,
    )


def test_plan_is_reproducible_and_binds_the_only_exact_create_request(
    bundle: Mapping[str, Any],
) -> None:
    first = bundle["plan"]
    second = materializer.build_materialization_plan(
        intent=bundle["intent"],
        package_manifest=bundle["manifest"],
        package_archive=bundle["archive"],
        repo_root=bundle["repo"],
    )

    assert first == second
    request = first["create_stack_request"]
    assert request == {
        "StackName": materializer.DEDICATED_STACK_NAME,
        "TemplateBody": request["TemplateBody"],
        "Parameters": first["parameter_projection"],
        "Capabilities": ["CAPABILITY_NAMED_IAM"],
        "RoleARN": materializer.CLOUDFORMATION_SERVICE_ROLE_ARN,
        "OnFailure": "DO_NOTHING",
        "EnableTerminationProtection": True,
        "ClientRequestToken": first["client_request_token"],
    }
    assert request["RoleARN"].startswith(
        f"arn:aws:iam::{materializer.AUTHORITY_ACCOUNT_ID}:role/"
    )
    assert "assumed-role" not in request["RoleARN"]
    assert first["create_stack_request_digest"] == materializer.canonical_digest(
        request
    )
    assert first["operation_list_digest"] == materializer.canonical_digest(
        first["materialization_operations"]
    )
    assert first["materialization_operations"] == [
        {
            "sequence": 1,
            "service": "cloudformation",
            "api_action": "CreateStack",
            "effect": "CREATE_DEDICATED_ENTRYPOINT_STACK_ONLY",
            "target_digest": materializer.canonical_digest(first["target"]),
            "request_projection_digest": first["create_stack_request_digest"],
            "conditional_behavior": "TARGET_ABSENT_AFTER_TWO_EXACT_DESCRIBES",
            "client_request_token_sha256": materializer.digest_text(
                first["client_request_token"]
            ),
            "attempt_limit": 1,
            "retry_permitted": False,
            "expected_response_class": "CreateStackOutput.StackId",
            "immediate_readback": list(
                materializer.POST_WRITE_READBACK_OPERATIONS
            ),
            "unknown_outcome_reconciliation": list(
                materializer.RECONCILE_OPERATIONS
            ),
            "rollback": {
                "automatic": False,
                "delete_stack_authorized": False,
                "mode": "SEPARATE_OWNER_CHECKPOINT_REQUIRED",
            },
        }
    ]
    assert first["allowed_mutations"] == ["cloudformation:CreateStack"]
    assert first["mutation_retry_permitted"] is False
    assert first["ambiguous_outcome_mode"] == "RECONCILE_ONLY"
    assert set(first["prohibited_operations"]) == set(
        materializer.PROHIBITED_OPERATIONS
    )
    assert {
        "cloudformation:CreateChangeSet",
        "cloudformation:ExecuteChangeSet",
        "cloudformation:DeleteStack",
        "cloudformation:UpdateStack",
        "lambda:InvokeFunction",
        "terraform:apply",
    }.issubset(first["prohibited_operations"])
    assert "Tags" not in request
    assert "DisableRollback" not in request
    assert "NotificationARNs" not in request


def test_plan_hard_replaces_unsigned_artifact_with_exact_signed_handoff(
    bundle: Mapping[str, Any],
) -> None:
    plan = bundle["plan"]
    contract = plan["artifact_signing_contract"]
    unsigned = contract["unsigned_source"]
    signed = contract["signed_destination"]
    parameters = {
        item["ParameterKey"]: item["ParameterValue"]
        for item in plan["parameter_projection"]
    }

    assert "artifact" not in plan
    assert set(contract) == {
        "contract_version",
        "unsigned_source",
        "signer",
        "signed_destination",
        "code_signing_config",
    }
    assert contract["contract_version"] == 1
    assert unsigned["bucket"] == signed["bucket"]
    assert unsigned["sse_kms_key_arn"] == signed["sse_kms_key_arn"]
    assert unsigned["key"] != signed["key"]
    assert signed["key"].endswith(f"/{SIGNING_JOB_ID}.zip")
    assert plan["artifact_signing_contract_digest"] == (
        materializer.artifact_signing_contract_digest(contract)
    )
    assert plan["artifact_signing_evidence_digest"] == (
        materializer.artifact_signing_evidence_digest(contract)
    )
    assert parameters["BrokerArtifactBucket"] == signed["bucket"]
    assert parameters["BrokerArtifactKey"] == signed["key"]
    assert parameters["BrokerArtifactVersion"] == signed["version_id"]
    assert parameters["BrokerArtifactCodeSha256"] == signed[
        "lambda_code_sha256"
    ]
    assert parameters["BrokerCodeSigningConfigArn"] == contract[
        "code_signing_config"
    ]["arn"]
    assert materializer.PARAMETER_KEYS[7] == (
        materializer.PRIVATE_PARAMETER_PROJECTION_KEY
    )
    assert materializer.PRIVATE_PARAMETER_PROJECTION_KEY not in (
        materializer.NO_ECHO_PARAMETER_KEYS
    )
    assert parameters[materializer.PRIVATE_PARAMETER_PROJECTION_KEY] == (
        materializer.private_parameter_projection_digest(parameters)
    )


def test_private_parameter_projection_commitment_rejects_masked_value_drift(
    bundle: Mapping[str, Any],
) -> None:
    intent = copy.deepcopy(bundle["intent"])
    intent["parameters"]["IdentityCenterRedirectUri"] = (
        "http://127.0.0.1:49153/callback"
    )
    _reseal(intent, "intent_digest")

    with pytest.raises(
        materializer.RetirementEntrypointMaterializationError,
        match="PRIVATE_PARAMETER_PROJECTION_DIGEST_MISMATCH",
    ):
        materializer.validate_materialization_intent(intent)


@pytest.mark.parametrize("field", ("bucket", "sse_kms_key_arn"))
def test_signing_contract_requires_same_bucket_and_kms_key(
    bundle: Mapping[str, Any], field: str
) -> None:
    intent = copy.deepcopy(bundle["intent"])
    destination = intent["artifact_signing_contract"]["signed_destination"]
    if field == "bucket":
        destination[field] = "scanalyze-gug363-unreviewed-destination"
    else:
        destination[field] = (
            f"arn:aws:kms:{materializer.REGION}:"
            f"{materializer.AUTHORITY_ACCOUNT_ID}:key/"
            "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
        )
    intent["artifact_signing_contract_digest"] = (
        materializer.artifact_signing_contract_digest(
            intent["artifact_signing_contract"]
        )
    )
    intent["artifact_signing_evidence_digest"] = (
        materializer.artifact_signing_evidence_digest(
            intent["artifact_signing_contract"]
        )
    )
    _reseal(intent, "intent_digest")

    with pytest.raises(
        materializer.RetirementEntrypointMaterializationError,
        match="ARTIFACT_SIGNING_CAUSAL_BINDING_INVALID",
    ):
        materializer.validate_materialization_intent(intent)


def test_plan_authorization_and_ledger_bind_signing_digests(
    bundle: Mapping[str, Any],
) -> None:
    plan = bundle["plan"]
    authorization = _authorization(plan)
    ledger = _ledger(plan, authorization)

    for field in (
        "artifact_signing_contract_digest",
        "artifact_signing_evidence_digest",
    ):
        assert authorization[field] == plan[field]
    assert ledger["artifact_signing_contract_digest"] == plan[
        "artifact_signing_contract_digest"
    ]
    assert "artifact_signing_evidence_digest" not in ledger
    assert authorization["expires_at"] == plan["artifact_signing_contract"][
        "signer"
    ]["signature_expires_at"]


def test_prohibited_operations_include_every_signing_and_csc_mutation(
    bundle: Mapping[str, Any],
) -> None:
    assert {
        "signer:StartSigningJob",
        "s3:CopyObject",
        "s3:PutObject",
        "lambda:CreateCodeSigningConfig",
        "lambda:UpdateCodeSigningConfig",
        "lambda:DeleteCodeSigningConfig",
        "lambda:PutFunctionCodeSigningConfig",
        "lambda:DeleteFunctionCodeSigningConfig",
    }.issubset(bundle["plan"]["prohibited_operations"])


def test_plan_rejects_service_role_authority_drift(
    bundle: Mapping[str, Any],
) -> None:
    drifted = copy.deepcopy(bundle["plan"])
    drifted["create_stack_request"]["RoleARN"] = (
        f"arn:aws:iam::{materializer.AUTHORITY_ACCOUNT_ID}:role/"
        "unreviewed-cloudformation-role"
    )
    drifted["create_stack_request_digest"] = materializer.canonical_digest(
        drifted["create_stack_request"]
    )
    drifted["plan_digest"] = materializer.canonical_digest(
        {key: value for key, value in drifted.items() if key != "plan_digest"}
    )

    with pytest.raises(
        materializer.RetirementEntrypointMaterializationError,
        match="CREATE_STACK_REQUEST",
    ):
        materializer.validate_materialization_plan(drifted)


def test_plan_rejects_template_without_visible_private_parameter_commitment(
    tmp_path: Path,
) -> None:
    source, _commit, _tree, _digest = _synthetic_source(tmp_path)
    declaration = (
        "  PrivateParameterProjectionSha256:\n"
        "    Type: String\n"
        "    AllowedPattern: '^sha256:[a-f0-9]{64}$'\n"
    )
    template = source / materializer.TEMPLATE_PATH
    body = template.read_text(encoding="utf-8")
    assert declaration in body
    template.write_text(body.replace(declaration, ""), encoding="utf-8")
    _run_git(source, "add", "--", materializer.TEMPLATE_PATH.as_posix())
    _run_git(source, "commit", "-q", "--amend", "--no-edit")
    commit = _run_git(source, "rev-parse", "HEAD")
    tree = _run_git(source, "rev-parse", "HEAD^{tree}")
    template_digest = "sha256:" + sha256(template.read_bytes()).hexdigest()
    committed_sources = {
        path: b"" if path.as_posix() == "tooling/__init__.py" else b"# synthetic\n"
        for path in SOURCE_PATHS
    }
    built = build_retirement_package(
        source_root=source,
        source_commit=commit,
        broker_runtime_version_arn=RUNTIME_ARN,
        broker_version_binding_sha256=VERSION_BINDING,
        committed_sources=committed_sources,
    )
    signed_archive = built.archive + b"scanalyze-gug363-signer-envelope-v1"
    intent = _intent(
        commit=commit,
        tree=tree,
        template_digest=template_digest,
        package_manifest=built.manifest,
        signed_archive=signed_archive,
    )

    with pytest.raises(
        materializer.RetirementEntrypointMaterializationError,
        match="TEMPLATE_CONTROL_SET_INVALID",
    ):
        materializer.build_materialization_plan(
            intent=intent,
            package_manifest=built.manifest,
            package_archive=built.archive,
            repo_root=source,
        )


def test_log_group_and_effective_single_operator_resource_set_are_exact(
    bundle: Mapping[str, Any],
) -> None:
    plan = bundle["plan"]
    expected = dict(materializer.EXPECTED_RESOURCE_TYPES)

    assert len(expected) == 21
    assert expected["RetirementBrokerLogGroup"] == "AWS::Logs::LogGroup"
    assert plan["expected_resource_count"] == 21
    assert plan["expected_resources"] == [
        {"logical_resource_id": logical_id, "resource_type": resource_type}
        for logical_id, resource_type in materializer.EXPECTED_RESOURCE_TYPES
    ]
    assert plan["log_group"] == {
        "name": "/aws/lambda/scanalyze-platform-authority-gug215-retirement",
        "retention_days": 365,
        "encryption_mode": "AWS_OWNED_AT_REST",
    }
    assert not materializer.TWO_HUMAN_RESOURCE_IDS.intersection(expected)
    template = plan["create_stack_request"]["TemplateBody"]
    assert "Type: AWS::Logs::LogGroup" in template
    assert "RetentionInDays: 365" in template
    assert "ApplicationLogLevel: ERROR" in template
    assert "SystemLogLevel: WARN" in template
    assert "LogFormat: JSON" in template


def test_apply_is_sts_first_claims_ledger_then_calls_create_once_and_reads_back(
    bundle: Mapping[str, Any],
) -> None:
    plan = bundle["plan"]
    authorization = _authorization(plan)
    calls: list[str] = []
    cfn = FakeCloudFormation(
        calls=calls,
        plan=plan,
        name_descriptions=[None, None],
        post_create_stack=_expected_stack(plan),
    )
    factory = FakeFactory(
        calls=calls,
        cfn=cfn,
        s3_response=_head_response(plan),
    )
    claimed: list[dict[str, Any]] = []

    def claim(ledger: Mapping[str, Any]) -> None:
        assert cfn.create_requests == []
        calls.append("ledger:ClaimAttempt")
        claimed.append(copy.deepcopy(dict(ledger)))

    receipt, ledger = materializer.apply_materialization(
        plan=plan,
        authorization=authorization,
        repo_root=bundle["repo"],
        client_factory=factory,
        claim_attempt=claim,
        clock=lambda: NOW,
    )

    assert calls == [
        *materializer.PREFLIGHT_OPERATIONS,
        "ledger:ClaimAttempt",
        "cloudformation:CreateStack",
        *materializer.POST_WRITE_READBACK_OPERATIONS,
    ]
    assert cfn.create_requests == [plan["create_stack_request"]]
    assert ledger == claimed[0]
    assert ledger["attempt_limit"] == ledger["attempts"] == 1
    assert authorization["operation_list_digest"] == plan["operation_list_digest"]
    assert ledger["operation_list_digest"] == plan["operation_list_digest"]
    assert ledger["execution_gate_consumed"] is True
    assert ledger["mutation_retry_authorized"] is False
    assert receipt["status"] == "READBACK_VERIFIED"
    assert receipt["target_state"] == "COMPLETE"
    assert receipt["materializer_readback_scope"] == (
        "CLOUDFORMATION_CONTROL_PLANE_ONLY"
    )
    assert receipt["provider_certification_complete"] is False
    assert receipt["gug357_certification_required"] is True
    assert receipt["aws_mutation_count"] == 1
    assert receipt["artifact_signing_readback_complete"] is True
    assert receipt["readback_complete"] is True
    assert receipt["observed_resource_count"] == 21
    contract = plan["artifact_signing_contract"]
    unsigned = contract["unsigned_source"]
    signed = contract["signed_destination"]
    assert factory._s3.requests == [
        {
            "Bucket": unsigned["bucket"],
            "ExpectedBucketOwner": materializer.AUTHORITY_ACCOUNT_ID,
        },
        {
            "Bucket": unsigned["bucket"],
            "Key": unsigned["key"],
            "VersionId": unsigned["version_id"],
            "ExpectedBucketOwner": materializer.AUTHORITY_ACCOUNT_ID,
            "ChecksumMode": "ENABLED",
        },
        {
            "Bucket": unsigned["bucket"],
            "Key": unsigned["key"],
            "VersionId": unsigned["version_id"],
            "ExpectedBucketOwner": materializer.AUTHORITY_ACCOUNT_ID,
            "ChecksumMode": "ENABLED",
        },
        {
            "Bucket": signed["bucket"],
            "Prefix": signed["key"],
            "MaxKeys": 1000,
            "ExpectedBucketOwner": materializer.AUTHORITY_ACCOUNT_ID,
        },
        {
            "Bucket": signed["bucket"],
            "Key": signed["key"],
            "VersionId": signed["version_id"],
            "ExpectedBucketOwner": materializer.AUTHORITY_ACCOUNT_ID,
            "ChecksumMode": "ENABLED",
        },
        {
            "Bucket": signed["bucket"],
            "Key": signed["key"],
            "VersionId": signed["version_id"],
            "ExpectedBucketOwner": materializer.AUTHORITY_ACCOUNT_ID,
            "ChecksumMode": "ENABLED",
        },
    ]
    serialized = materializer.canonical_json(receipt)
    assert CALLER_ARN not in serialized
    assert STACK_ID not in serialized
    assert not set(receipt["aws_operations"]).intersection(
        materializer.PROHIBITED_OPERATIONS
    )


def test_artifact_head_drift_blocks_before_ledger_and_create_stack(
    bundle: Mapping[str, Any],
) -> None:
    plan = bundle["plan"]
    authorization = _authorization(plan)
    calls: list[str] = []
    drifted_head = _head_response(plan)
    drifted_head["ChecksumSHA256"] = "A" * 43 + "="
    cfn = FakeCloudFormation(
        calls=calls,
        plan=plan,
        name_descriptions=[None],
    )
    factory = FakeFactory(
        calls=calls,
        cfn=cfn,
        s3_response=drifted_head,
    )

    with pytest.raises(
        materializer.RetirementEntrypointMaterializationError,
        match="SIGNED_ARTIFACT_HEAD_MISMATCH",
    ):
        materializer.apply_materialization(
            plan=plan,
            authorization=authorization,
            repo_root=bundle["repo"],
            client_factory=factory,
            claim_attempt=lambda value: pytest.fail(
                f"unexpected ledger claim: {value}"
            ),
            clock=lambda: NOW,
        )

    assert calls == [
        *materializer.PREFLIGHT_OPERATIONS[:9],
    ]
    assert cfn.create_requests == []


@pytest.mark.parametrize(
    ("stage", "expected_code", "operation_count"),
    (
        ("job", "SIGNING_JOB_READBACK_MISMATCH", 3),
        ("profile", "SIGNING_PROFILE_READBACK_MISMATCH", 4),
        ("versioning", "ARTIFACT_BUCKET_VERSIONING_MISMATCH", 5),
        ("source-head", "UNSIGNED_ARTIFACT_HEAD_MISMATCH", 6),
        ("source-get", "UNSIGNED_ARTIFACT_BODY_MISMATCH", 7),
        ("destination-list", "SIGNED_ARTIFACT_VERSION_LIST_MISMATCH", 8),
        ("destination-head", "SIGNED_ARTIFACT_HEAD_MISMATCH", 9),
        ("destination-get", "SIGNED_ARTIFACT_BODY_MISMATCH", 10),
        ("code-signing-config", "CODE_SIGNING_CONFIG_READBACK_MISMATCH", 11),
    ),
)
def test_every_signing_readback_drift_fails_before_ledger_and_create(
    bundle: Mapping[str, Any],
    stage: str,
    expected_code: str,
    operation_count: int,
) -> None:
    plan = bundle["plan"]
    authorization = _authorization(plan)
    calls: list[str] = []
    cfn = FakeCloudFormation(
        calls=calls,
        plan=plan,
        name_descriptions=[None],
    )
    signer_mutations: dict[str, Any] = {}
    s3_mutations: dict[str, Any] = {}
    lambda_mutation: Any = None
    if stage == "job":
        signer_mutations["signer:DescribeSigningJob"] = {"status": "Failed"}
    elif stage == "profile":
        signer_mutations["signer:GetSigningProfile"] = {"status": "Revoked"}
    elif stage == "versioning":
        s3_mutations["s3:GetBucketVersioning"] = {"Status": "Suspended"}
    elif stage == "source-head":
        s3_mutations["s3:HeadObject:unsigned"] = {
            "ChecksumSHA256": "A" * 43 + "="
        }
    elif stage == "source-get":
        def mutate_source_get(response: dict[str, Any]) -> dict[str, Any]:
            response["Body"] = BytesIO(
                b"x" * plan["artifact_signing_contract"]["unsigned_source"][
                    "archive_size_bytes"
                ]
            )
            return response

        s3_mutations["s3:GetObject:unsigned"] = mutate_source_get
    elif stage == "destination-list":
        s3_mutations["s3:ListObjectVersions"] = {"Versions": []}
    elif stage == "destination-head":
        s3_mutations["s3:HeadObject:signed"] = {
            "ChecksumSHA256": "A" * 43 + "="
        }
    elif stage == "destination-get":
        def mutate_destination_get(response: dict[str, Any]) -> dict[str, Any]:
            response["Body"] = BytesIO(
                b"x" * plan["artifact_signing_contract"]["signed_destination"][
                    "archive_size_bytes"
                ]
            )
            return response

        s3_mutations["s3:GetObject:signed"] = mutate_destination_get
    else:
        def mutate_code_signing(response: dict[str, Any]) -> dict[str, Any]:
            response["CodeSigningConfig"]["AllowedPublishers"] = {
                "SigningProfileVersionArns": []
            }
            return response

        lambda_mutation = mutate_code_signing

    with pytest.raises(
        materializer.RetirementEntrypointMaterializationError,
        match=expected_code,
    ):
        materializer.apply_materialization(
            plan=plan,
            authorization=authorization,
            repo_root=bundle["repo"],
            client_factory=FakeFactory(
                calls=calls,
                cfn=cfn,
                s3_response=_head_response(plan),
                signer_mutations=signer_mutations,
                s3_mutations=s3_mutations,
                lambda_mutation=lambda_mutation,
            ),
            claim_attempt=lambda value: pytest.fail(
                f"unexpected ledger claim: {value}"
            ),
            clock=lambda: NOW,
        )

    assert calls == list(materializer.PREFLIGHT_OPERATIONS[:operation_count])
    assert cfn.create_requests == []


@pytest.mark.parametrize(
    ("variant", "expected_code"),
    (
        ("changed-member", "SIGNED_ARTIFACT_SEMANTIC_MISMATCH"),
        ("path-traversal", "SIGNED_ARTIFACT_ZIP_INVALID"),
        ("duplicate-member", "SIGNED_ARTIFACT_ZIP_INVALID"),
        ("symlink-member", "SIGNED_ARTIFACT_ZIP_INVALID"),
    ),
)
def test_signed_zip_must_preserve_safe_unsigned_members_and_bytes(
    bundle: Mapping[str, Any], variant: str, expected_code: str
) -> None:
    signed_archive = _signed_zip_variant(bundle["archive"], variant)
    plan = _plan_for_signed_archive(bundle, signed_archive)
    authorization = _authorization(plan)
    calls: list[str] = []
    cfn = FakeCloudFormation(
        calls=calls,
        plan=plan,
        name_descriptions=[None],
    )

    with pytest.raises(
        materializer.RetirementEntrypointMaterializationError,
        match=expected_code,
    ):
        materializer.apply_materialization(
            plan=plan,
            authorization=authorization,
            repo_root=bundle["repo"],
            client_factory=FakeFactory(
                calls=calls,
                cfn=cfn,
                s3_response=_head_response(plan),
            ),
            claim_attempt=lambda value: pytest.fail(
                f"unexpected ledger claim: {value}"
            ),
            clock=lambda: NOW,
        )

    assert calls == list(materializer.PREFLIGHT_OPERATIONS[:10])
    assert cfn.create_requests == []


@pytest.mark.parametrize(
    "mutations",
    (
        {
            "s3:HeadObject:unsigned": {
                "ChecksumSHA256": None,
                "ChecksumType": None,
            },
            "s3:GetObject:unsigned": {
                "ChecksumSHA256": None,
                "ChecksumType": None,
            },
            "s3:HeadObject:signed": {
                "ChecksumSHA256": None,
                "ChecksumType": None,
            },
            "s3:GetObject:signed": {
                "ChecksumSHA256": None,
                "ChecksumType": None,
            },
        },
        {
            "s3:HeadObject:unsigned": {
                "ChecksumSHA256": "composite-checksum-2",
                "ChecksumType": "COMPOSITE",
            },
            "s3:GetObject:unsigned": {
                "ChecksumSHA256": "composite-checksum-2",
                "ChecksumType": "COMPOSITE",
            },
            "s3:HeadObject:signed": {
                "ChecksumSHA256": "composite-checksum-3",
                "ChecksumType": "COMPOSITE",
            },
            "s3:GetObject:signed": {
                "ChecksumSHA256": "composite-checksum-3",
                "ChecksumType": "COMPOSITE",
            },
        },
        {
            "s3:HeadObject:unsigned": {"ChecksumType": None},
            "s3:GetObject:unsigned": {"ChecksumType": None},
            "s3:HeadObject:signed": {"ChecksumType": None},
            "s3:GetObject:signed": {"ChecksumType": None},
        },
    ),
)
def test_optional_or_composite_s3_checksum_uses_body_digest_as_authority(
    bundle: Mapping[str, Any], mutations: Mapping[str, Any]
) -> None:
    plan = bundle["plan"]
    authorization = _authorization(plan)
    calls: list[str] = []
    cfn = FakeCloudFormation(
        calls=calls,
        plan=plan,
        name_descriptions=[None, None],
        post_create_stack=_expected_stack(plan),
    )

    receipt, _ = materializer.apply_materialization(
        plan=plan,
        authorization=authorization,
        repo_root=bundle["repo"],
        client_factory=FakeFactory(
            calls=calls,
            cfn=cfn,
            s3_response=_head_response(plan),
            s3_mutations=mutations,
        ),
        claim_attempt=lambda _value: calls.append("ledger:ClaimAttempt"),
        clock=lambda: NOW,
    )

    assert receipt["readback_complete"] is True
    assert calls.count("cloudformation:CreateStack") == 1


@pytest.mark.parametrize(
    "mutation",
    (
        {"ChecksumSHA256": None, "ChecksumType": "FULL_OBJECT"},
        {"ChecksumSHA256": "", "ChecksumType": "COMPOSITE"},
        {"ChecksumSHA256": " bad", "ChecksumType": "COMPOSITE"},
        {"ChecksumSHA256": "A" * 43 + "=", "ChecksumType": "UNKNOWN"},
    ),
)
def test_s3_checksum_type_without_valid_checksum_is_rejected(
    bundle: Mapping[str, Any], mutation: Mapping[str, Any]
) -> None:
    plan = bundle["plan"]
    calls: list[str] = []
    cfn = FakeCloudFormation(calls=calls, plan=plan, name_descriptions=[None])

    with pytest.raises(
        materializer.RetirementEntrypointMaterializationError,
        match="UNSIGNED_ARTIFACT_HEAD_MISMATCH",
    ):
        materializer.apply_materialization(
            plan=plan,
            authorization=_authorization(plan),
            repo_root=bundle["repo"],
            client_factory=FakeFactory(
                calls=calls,
                cfn=cfn,
                s3_response=_head_response(plan),
                s3_mutations={"s3:HeadObject:unsigned": mutation},
            ),
            claim_attempt=lambda value: pytest.fail(
                f"invalid checksum reached ledger: {value}"
            ),
            clock=lambda: NOW,
        )


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("VersionId", "unreviewed-version"),
        ("ContentLength", 1),
        ("ServerSideEncryption", "AES256"),
        (
            "SSEKMSKeyId",
            f"arn:aws:kms:{materializer.REGION}:"
            f"{materializer.AUTHORITY_ACCOUNT_ID}:key/"
            "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
        ),
        ("DeleteMarker", True),
        ("ContentRange", "bytes 0-0/1"),
    ),
)
def test_s3_object_identity_size_and_encryption_are_strict(
    bundle: Mapping[str, Any], field: str, value: Any
) -> None:
    plan = bundle["plan"]
    calls: list[str] = []
    cfn = FakeCloudFormation(calls=calls, plan=plan, name_descriptions=[None])

    with pytest.raises(
        materializer.RetirementEntrypointMaterializationError,
        match="UNSIGNED_ARTIFACT_HEAD_MISMATCH",
    ):
        materializer.apply_materialization(
            plan=plan,
            authorization=_authorization(plan),
            repo_root=bundle["repo"],
            client_factory=FakeFactory(
                calls=calls,
                cfn=cfn,
                s3_response=_head_response(plan),
                s3_mutations={
                    "s3:HeadObject:unsigned": {field: value},
                },
            ),
            claim_attempt=lambda ledger: pytest.fail(
                f"artifact metadata drift reached ledger: {ledger}"
            ),
            clock=lambda: NOW,
        )

    assert calls == list(materializer.PREFLIGHT_OPERATIONS[:6])
    assert cfn.create_requests == []


def test_rotated_active_signing_profile_preserves_historical_job_binding(
    bundle: Mapping[str, Any],
) -> None:
    plan = bundle["plan"]
    calls: list[str] = []
    rotated_version = "ZyXwVu9876"
    rotated_arn = (
        f"arn:aws:signer:{materializer.REGION}:"
        f"{materializer.AUTHORITY_ACCOUNT_ID}:"
        f"/signing-profiles/{SIGNING_PROFILE_NAME}/{rotated_version}"
    )
    cfn = FakeCloudFormation(
        calls=calls,
        plan=plan,
        name_descriptions=[None, None],
        post_create_stack=_expected_stack(plan),
    )

    receipt, _ = materializer.apply_materialization(
        plan=plan,
        authorization=_authorization(plan),
        repo_root=bundle["repo"],
        client_factory=FakeFactory(
            calls=calls,
            cfn=cfn,
            s3_response=_head_response(plan),
            signer_mutations={
                "signer:GetSigningProfile": {
                    "profileVersion": rotated_version,
                    "profileVersionArn": rotated_arn,
                }
            },
        ),
        claim_attempt=lambda _ledger: calls.append("ledger:ClaimAttempt"),
        clock=lambda: NOW,
    )

    assert receipt["artifact_signing_readback_complete"] is True
    assert receipt["readback_complete"] is True
    assert plan["artifact_signing_contract"]["signer"]["profile_version_arn"] == (
        SIGNING_PROFILE_VERSION_ARN
    )


def test_signed_version_listing_paginates_and_filters_exact_key(
    bundle: Mapping[str, Any],
) -> None:
    plan = bundle["plan"]
    signed = plan["artifact_signing_contract"]["signed_destination"]
    calls: list[str] = []
    page = 0

    def paginated(response: dict[str, Any]) -> dict[str, Any]:
        nonlocal page
        page += 1
        if page == 1:
            neighbor_key = signed["key"] + ".neighbor"
            return {
                "IsTruncated": True,
                "Name": signed["bucket"],
                "Prefix": signed["key"],
                "Versions": [
                    {
                        "Key": neighbor_key,
                        "VersionId": "neighbor-version",
                        "IsLatest": True,
                        "Size": 1,
                    }
                ],
                "DeleteMarkers": [
                    {
                        "Key": neighbor_key,
                        "VersionId": "neighbor-delete-marker",
                        "IsLatest": False,
                    }
                ],
                "NextKeyMarker": neighbor_key,
                "NextVersionIdMarker": "neighbor-version",
            }
        return response

    cfn = FakeCloudFormation(
        calls=calls,
        plan=plan,
        name_descriptions=[None, None],
        post_create_stack=_expected_stack(plan),
    )
    factory = FakeFactory(
        calls=calls,
        cfn=cfn,
        s3_response=_head_response(plan),
        s3_mutations={"s3:ListObjectVersions": paginated},
    )

    receipt, _ = materializer.apply_materialization(
        plan=plan,
        authorization=_authorization(plan),
        repo_root=bundle["repo"],
        client_factory=factory,
        claim_attempt=lambda _ledger: calls.append("ledger:ClaimAttempt"),
        clock=lambda: NOW,
    )

    assert calls.count("s3:ListObjectVersions") == 2
    assert receipt["aws_operations"].count("s3:ListObjectVersions") == 1
    list_requests = [
        request for request in factory._s3.requests if "Prefix" in request
    ]
    assert list_requests == [
        {
            "Bucket": signed["bucket"],
            "Prefix": signed["key"],
            "MaxKeys": 1000,
            "ExpectedBucketOwner": materializer.AUTHORITY_ACCOUNT_ID,
        },
        {
            "Bucket": signed["bucket"],
            "Prefix": signed["key"],
            "MaxKeys": 1000,
            "ExpectedBucketOwner": materializer.AUTHORITY_ACCOUNT_ID,
            "KeyMarker": signed["key"] + ".neighbor",
            "VersionIdMarker": "neighbor-version",
        },
    ]
    assert receipt["readback_complete"] is True


def test_signed_version_listing_rejects_exact_delete_marker(
    bundle: Mapping[str, Any],
) -> None:
    plan = bundle["plan"]
    signed = plan["artifact_signing_contract"]["signed_destination"]
    calls: list[str] = []
    cfn = FakeCloudFormation(calls=calls, plan=plan, name_descriptions=[None])

    with pytest.raises(
        materializer.RetirementEntrypointMaterializationError,
        match="SIGNED_ARTIFACT_VERSION_LIST_MISMATCH",
    ):
        materializer.apply_materialization(
            plan=plan,
            authorization=_authorization(plan),
            repo_root=bundle["repo"],
            client_factory=FakeFactory(
                calls=calls,
                cfn=cfn,
                s3_response=_head_response(plan),
                s3_mutations={
                    "s3:ListObjectVersions": {
                        "DeleteMarkers": [
                            {
                                "Key": signed["key"],
                                "VersionId": "unexpected-delete-marker",
                                "IsLatest": False,
                            }
                        ]
                    }
                },
            ),
            claim_attempt=lambda ledger: pytest.fail(
                f"delete marker reached ledger: {ledger}"
            ),
            clock=lambda: NOW,
        )

    assert calls == list(materializer.PREFLIGHT_OPERATIONS[:8])
    assert cfn.create_requests == []


def test_signed_version_listing_has_bounded_pagination(
    bundle: Mapping[str, Any],
) -> None:
    plan = bundle["plan"]
    signed = plan["artifact_signing_contract"]["signed_destination"]
    calls: list[str] = []
    page = 0

    def endless_pages(_response: dict[str, Any]) -> dict[str, Any]:
        nonlocal page
        page += 1
        neighbor_key = f"{signed['key']}.neighbor-{page:02d}"
        return {
            "IsTruncated": True,
            "Name": signed["bucket"],
            "Prefix": signed["key"],
            "Versions": [],
            "DeleteMarkers": [],
            "NextKeyMarker": neighbor_key,
            "NextVersionIdMarker": f"neighbor-version-{page:02d}",
        }

    cfn = FakeCloudFormation(calls=calls, plan=plan, name_descriptions=[None])
    with pytest.raises(
        materializer.RetirementEntrypointMaterializationError,
        match="SIGNED_ARTIFACT_VERSION_PAGE_LIMIT",
    ):
        materializer.apply_materialization(
            plan=plan,
            authorization=_authorization(plan),
            repo_root=bundle["repo"],
            client_factory=FakeFactory(
                calls=calls,
                cfn=cfn,
                s3_response=_head_response(plan),
                s3_mutations={"s3:ListObjectVersions": endless_pages},
            ),
            claim_attempt=lambda ledger: pytest.fail(
                f"unbounded listing reached ledger: {ledger}"
            ),
            clock=lambda: NOW,
        )

    assert calls.count("s3:ListObjectVersions") == (
        materializer.MAX_S3_VERSION_PAGES
    )
    assert cfn.create_requests == []


def test_enabled_mfa_delete_is_accepted_and_unknown_value_is_rejected(
    bundle: Mapping[str, Any],
) -> None:
    plan = bundle["plan"]
    calls: list[str] = []
    cfn = FakeCloudFormation(
        calls=calls,
        plan=plan,
        name_descriptions=[None, None],
        post_create_stack=_expected_stack(plan),
    )
    receipt, _ = materializer.apply_materialization(
        plan=plan,
        authorization=_authorization(plan),
        repo_root=bundle["repo"],
        client_factory=FakeFactory(
            calls=calls,
            cfn=cfn,
            s3_response=_head_response(plan),
            s3_mutations={
                "s3:GetBucketVersioning": {
                    "Status": "Enabled",
                    "MFADelete": "Enabled",
                }
            },
        ),
        claim_attempt=lambda _value: calls.append("ledger:ClaimAttempt"),
        clock=lambda: NOW,
    )
    assert receipt["readback_complete"] is True

    blocked_calls: list[str] = []
    blocked_cfn = FakeCloudFormation(
        calls=blocked_calls,
        plan=plan,
        name_descriptions=[None],
    )
    with pytest.raises(
        materializer.RetirementEntrypointMaterializationError,
        match="ARTIFACT_BUCKET_VERSIONING_MISMATCH",
    ):
        materializer.apply_materialization(
            plan=plan,
            authorization=_authorization(plan),
            repo_root=bundle["repo"],
            client_factory=FakeFactory(
                calls=blocked_calls,
                cfn=blocked_cfn,
                s3_response=_head_response(plan),
                s3_mutations={
                    "s3:GetBucketVersioning": {
                        "Status": "Enabled",
                        "MFADelete": "Unexpected",
                    }
                },
            ),
            claim_attempt=lambda value: pytest.fail(
                f"invalid versioning reached ledger: {value}"
            ),
            clock=lambda: NOW,
        )


def test_claim_failure_blocks_before_create_stack(
    bundle: Mapping[str, Any],
) -> None:
    plan = bundle["plan"]
    authorization = _authorization(plan)
    calls: list[str] = []
    cfn = FakeCloudFormation(
        calls=calls,
        plan=plan,
        name_descriptions=[None, None],
    )

    def fail_claim(_ledger: Mapping[str, Any]) -> None:
        calls.append("ledger:ClaimAttempt")
        raise materializer.RetirementEntrypointMaterializationError(
            "PRIVATE_DIRECTORY_FSYNC_FAILED"
        )

    with pytest.raises(
        materializer.RetirementEntrypointMaterializationError,
        match="PRIVATE_DIRECTORY_FSYNC_FAILED",
    ):
        materializer.apply_materialization(
            plan=plan,
            authorization=authorization,
            repo_root=bundle["repo"],
            client_factory=FakeFactory(
                calls=calls,
                cfn=cfn,
                s3_response=_head_response(plan),
            ),
            claim_attempt=fail_claim,
            clock=lambda: NOW,
        )

    assert calls == [
        *materializer.PREFLIGHT_OPERATIONS,
        "ledger:ClaimAttempt",
    ]
    assert cfn.create_requests == []


def test_authorization_time_is_revalidated_after_provider_refresh(
    bundle: Mapping[str, Any],
) -> None:
    plan = bundle["plan"]
    authorization = _authorization(plan)
    calls: list[str] = []
    cfn = FakeCloudFormation(
        calls=calls,
        plan=plan,
        name_descriptions=[None, None],
    )
    times = iter((NOW, NOW + timedelta(minutes=10)))

    with pytest.raises(
        materializer.RetirementEntrypointMaterializationError,
        match="AUTHORIZATION_NOT_ACTIVE",
    ):
        materializer.apply_materialization(
            plan=plan,
            authorization=authorization,
            repo_root=bundle["repo"],
            client_factory=FakeFactory(
                calls=calls,
                cfn=cfn,
                s3_response=_head_response(plan),
            ),
            claim_attempt=lambda value: pytest.fail(
                f"expired authorization reached ledger: {value}"
            ),
            clock=lambda: next(times),
        )

    assert calls == list(materializer.PREFLIGHT_OPERATIONS)
    assert cfn.create_requests == []


def test_existing_exact_target_refreshes_signing_then_skips_ledger_and_create(
    bundle: Mapping[str, Any],
) -> None:
    plan = bundle["plan"]
    authorization = _authorization(plan)
    calls: list[str] = []
    cfn = FakeCloudFormation(
        calls=calls,
        plan=plan,
        name_descriptions=[_expected_stack(plan)],
    )
    factory = FakeFactory(
        calls=calls,
        cfn=cfn,
        s3_response=_head_response(plan),
    )

    receipt, ledger = materializer.apply_materialization(
        plan=plan,
        authorization=authorization,
        repo_root=bundle["repo"],
        client_factory=factory,
        claim_attempt=lambda value: pytest.fail(f"unexpected ledger claim: {value}"),
        clock=lambda: NOW,
    )

    assert calls == [
        *materializer.PREFLIGHT_OPERATIONS,
    ]
    assert cfn.create_requests == []
    assert ledger is None
    assert receipt["status"] == "READBACK_PENDING_NO_MUTATION"
    assert receipt["target_state"] == "AMBIGUOUS"
    assert receipt["artifact_signing_readback_complete"] is True
    assert receipt["readback_complete"] is False
    assert receipt["no_touch"] is True
    assert receipt["aws_mutation_count"] == 0


def test_preexisting_unmasked_parameters_remain_ambiguous_without_ledger(
    bundle: Mapping[str, Any],
) -> None:
    plan = bundle["plan"]
    calls: list[str] = []
    cfn = FakeCloudFormation(
        calls=calls,
        plan=plan,
        name_descriptions=[_expected_stack(plan, mask_no_echo=False)],
    )

    receipt, ledger = materializer.apply_materialization(
        plan=plan,
        authorization=_authorization(plan),
        repo_root=bundle["repo"],
        client_factory=FakeFactory(
            calls=calls,
            cfn=cfn,
            s3_response=_head_response(plan),
        ),
        claim_attempt=lambda value: pytest.fail(f"unexpected ledger claim: {value}"),
        clock=lambda: NOW,
    )

    assert calls == [
        *materializer.PREFLIGHT_OPERATIONS,
        *materializer.POST_WRITE_READBACK_OPERATIONS[1:],
    ]
    assert ledger is None
    assert cfn.create_requests == []
    assert receipt["status"] == "READBACK_PENDING_NO_MUTATION"
    assert receipt["target_state"] == "AMBIGUOUS"
    assert receipt["artifact_signing_readback_complete"] is True
    assert receipt["readback_complete"] is False
    assert receipt["no_touch"] is True


def test_visible_private_parameter_commitment_must_match_stack_exactly(
    bundle: Mapping[str, Any],
) -> None:
    plan = bundle["plan"]
    stack = _expected_stack(plan)
    commitment = next(
        parameter
        for parameter in stack["Parameters"]
        if parameter["ParameterKey"]
        == materializer.PRIVATE_PARAMETER_PROJECTION_KEY
    )
    commitment["ParameterValue"] = "sha256:" + "0" * 64
    calls: list[str] = []
    cfn = FakeCloudFormation(
        calls=calls,
        plan=plan,
        name_descriptions=[stack],
    )

    receipt, ledger = materializer.apply_materialization(
        plan=plan,
        authorization=_authorization(plan),
        repo_root=bundle["repo"],
        client_factory=FakeFactory(
            calls=calls,
            cfn=cfn,
            s3_response=_head_response(plan),
        ),
        claim_attempt=lambda value: pytest.fail(f"unexpected ledger claim: {value}"),
        clock=lambda: NOW,
    )

    assert ledger is None
    assert cfn.create_requests == []
    assert receipt["status"] == "BLOCKED_DRIFT"
    assert receipt["target_state"] == "DRIFTED"


def test_standard_deletion_mode_is_accepted_after_exact_create(
    bundle: Mapping[str, Any],
) -> None:
    plan = bundle["plan"]
    calls: list[str] = []
    cfn = FakeCloudFormation(
        calls=calls,
        plan=plan,
        name_descriptions=[None, None],
        post_create_stack=_expected_stack(plan, deletion_mode="STANDARD"),
    )

    receipt, _ = materializer.apply_materialization(
        plan=plan,
        authorization=_authorization(plan),
        repo_root=bundle["repo"],
        client_factory=FakeFactory(
            calls=calls,
            cfn=cfn,
            s3_response=_head_response(plan),
        ),
        claim_attempt=lambda _ledger: calls.append("ledger:ClaimAttempt"),
        clock=lambda: NOW,
    )

    assert receipt["status"] == "READBACK_VERIFIED"
    assert receipt["target_state"] == "COMPLETE"
    assert receipt["readback_complete"] is True


def test_existing_stack_with_cloudformation_role_drift_is_blocked_no_touch(
    bundle: Mapping[str, Any],
) -> None:
    plan = bundle["plan"]
    authorization = _authorization(plan)
    calls: list[str] = []
    cfn = FakeCloudFormation(
        calls=calls,
        plan=plan,
        name_descriptions=[
            _expected_stack(
                plan,
                role_arn=(
                    f"arn:aws:iam::{materializer.AUTHORITY_ACCOUNT_ID}:role/"
                    "operator-provider-authority"
                ),
            )
        ],
    )
    factory = FakeFactory(
        calls=calls,
        cfn=cfn,
        s3_response=_head_response(plan),
    )

    receipt, ledger = materializer.apply_materialization(
        plan=plan,
        authorization=authorization,
        repo_root=bundle["repo"],
        client_factory=factory,
        claim_attempt=lambda value: pytest.fail(f"unexpected ledger claim: {value}"),
        clock=lambda: NOW,
    )

    assert calls == list(materializer.PREFLIGHT_OPERATIONS)
    assert cfn.create_requests == []
    assert ledger is None
    assert receipt["status"] == "BLOCKED_DRIFT"
    assert receipt["target_state"] == "DRIFTED"
    assert receipt["no_touch"] is True


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("NotificationARNs", ["arn:aws:sns:us-east-1:042360977644:unexpected"]),
        ("Capabilities", []),
        ("Capabilities", ["CAPABILITY_IAM"]),
        ("ParentId", STACK_ID.replace("gug357-retirement-entrypoint", "parent")),
        ("RootId", STACK_ID.replace("gug357-retirement-entrypoint", "root")),
        (
            "ChangeSetId",
            "arn:aws:cloudformation:us-east-1:042360977644:"
            "changeSet/unexpected/00000000-0000-0000-0000-000000000000",
        ),
        ("DisableRollback", False),
        ("DeletionMode", None),
        ("DeletionMode", "FORCE_DELETE_STACK"),
        ("DeletionMode", "UNREVIEWED_MODE"),
        ("TimeoutInMinutes", 30),
        ("RollbackConfiguration", {"MonitoringTimeInMinutes": 5}),
        ("RetainExceptOnCreate", True),
        ("LastUpdatedTime", NOW),
    ),
)
def test_existing_stack_with_authority_metadata_drift_is_blocked_no_touch(
    bundle: Mapping[str, Any], field: str, value: Any
) -> None:
    plan = bundle["plan"]
    authorization = _authorization(plan)
    stack = _expected_stack(plan)
    stack[field] = value
    calls: list[str] = []
    cfn = FakeCloudFormation(
        calls=calls,
        plan=plan,
        name_descriptions=[stack],
    )

    receipt, ledger = materializer.apply_materialization(
        plan=plan,
        authorization=authorization,
        repo_root=bundle["repo"],
        client_factory=FakeFactory(
            calls=calls,
            cfn=cfn,
            s3_response=_head_response(plan),
        ),
        claim_attempt=lambda value: pytest.fail(f"unexpected ledger claim: {value}"),
        clock=lambda: NOW,
    )

    assert calls == list(materializer.PREFLIGHT_OPERATIONS)
    assert cfn.create_requests == []
    assert ledger is None
    assert receipt["status"] == "BLOCKED_DRIFT"
    assert receipt["target_state"] == "DRIFTED"
    assert receipt["no_touch"] is True


@pytest.mark.parametrize(
    ("resource_status", "physical_ids_present"),
    (("CREATE_FAILED", True), ("CREATE_COMPLETE", False)),
)
def test_complete_stack_requires_healthy_physical_resource_readback(
    bundle: Mapping[str, Any],
    resource_status: str,
    physical_ids_present: bool,
) -> None:
    plan = bundle["plan"]
    authorization = _authorization(plan)
    calls: list[str] = []
    cfn = FakeCloudFormation(
        calls=calls,
        plan=plan,
        name_descriptions=[_expected_stack(plan, mask_no_echo=False)],
        resource_status=resource_status,
        physical_ids_present=physical_ids_present,
    )
    factory = FakeFactory(
        calls=calls,
        cfn=cfn,
        s3_response=_head_response(plan),
    )

    receipt, ledger = materializer.apply_materialization(
        plan=plan,
        authorization=authorization,
        repo_root=bundle["repo"],
        client_factory=factory,
        claim_attempt=lambda value: pytest.fail(f"unexpected ledger claim: {value}"),
        clock=lambda: NOW,
    )

    assert ledger is None
    assert cfn.create_requests == []
    assert receipt["status"] == "BLOCKED_DRIFT"
    assert receipt["target_state"] == "DRIFTED"


def test_stack_appearing_during_preflight_is_read_back_without_create(
    bundle: Mapping[str, Any],
) -> None:
    plan = bundle["plan"]
    authorization = _authorization(plan)
    calls: list[str] = []
    cfn = FakeCloudFormation(
        calls=calls,
        plan=plan,
        name_descriptions=[None, _expected_stack(plan)],
    )
    factory = FakeFactory(
        calls=calls,
        cfn=cfn,
        s3_response=_head_response(plan),
    )

    receipt, ledger = materializer.apply_materialization(
        plan=plan,
        authorization=authorization,
        repo_root=bundle["repo"],
        client_factory=factory,
        claim_attempt=lambda value: pytest.fail(f"unexpected ledger claim: {value}"),
        clock=lambda: NOW,
    )

    assert calls == [
        *materializer.PREFLIGHT_OPERATIONS,
    ]
    assert cfn.create_requests == []
    assert ledger is None
    assert receipt["status"] == "READBACK_PENDING_NO_MUTATION"
    assert receipt["target_state"] == "AMBIGUOUS"
    assert receipt["readback_complete"] is False


def test_ambiguous_create_consumes_one_attempt_and_allows_reconcile_only(
    bundle: Mapping[str, Any],
) -> None:
    plan = bundle["plan"]
    authorization = _authorization(plan)
    calls: list[str] = []
    cfn = FakeCloudFormation(
        calls=calls,
        plan=plan,
        name_descriptions=[None, None],
        create_error=TimeoutError("sensitive provider diagnostic must be discarded"),
    )
    factory = FakeFactory(
        calls=calls,
        cfn=cfn,
        s3_response=_head_response(plan),
    )
    claimed: list[dict[str, Any]] = []

    def claim_once(ledger: Mapping[str, Any]) -> None:
        if claimed:
            raise materializer.RetirementEntrypointMaterializationError(
                "EXECUTION_LEDGER_ALREADY_CONSUMED"
            )
        calls.append("ledger:ClaimAttempt")
        claimed.append(copy.deepcopy(dict(ledger)))

    receipt, ledger = materializer.apply_materialization(
        plan=plan,
        authorization=authorization,
        repo_root=bundle["repo"],
        client_factory=factory,
        claim_attempt=claim_once,
        clock=lambda: NOW,
    )

    assert ledger == claimed[0]
    assert len(cfn.create_requests) == 1
    assert receipt["status"] == "UNCERTAIN_RECONCILE_ONLY"
    assert receipt["ambiguous_response"] is True
    assert receipt["retry_permitted"] is False
    assert receipt["mutation_retry_attempted"] is False
    assert "sensitive provider diagnostic" not in materializer.canonical_json(receipt)

    with pytest.raises(
        materializer.RetirementEntrypointMaterializationError,
        match="EXECUTION_LEDGER_ALREADY_CONSUMED",
    ):
        materializer.apply_materialization(
            plan=plan,
            authorization=authorization,
            repo_root=bundle["repo"],
            client_factory=factory,
            claim_attempt=claim_once,
            clock=lambda: NOW,
        )
    assert len(cfn.create_requests) == 1


def test_missing_create_event_token_is_uncertain_and_never_retried(
    bundle: Mapping[str, Any],
) -> None:
    plan = bundle["plan"]
    authorization = _authorization(plan)
    calls: list[str] = []
    cfn = FakeCloudFormation(
        calls=calls,
        plan=plan,
        name_descriptions=[None, None],
        post_create_stack=_expected_stack(plan),
        event_token="gug363-" + "0" * 48,
    )
    factory = FakeFactory(
        calls=calls,
        cfn=cfn,
        s3_response=_head_response(plan),
    )
    claimed: list[dict[str, Any]] = []

    receipt, ledger = materializer.apply_materialization(
        plan=plan,
        authorization=authorization,
        repo_root=bundle["repo"],
        client_factory=factory,
        claim_attempt=lambda value: claimed.append(copy.deepcopy(dict(value))),
        clock=lambda: NOW,
    )

    assert ledger == claimed[0]
    assert cfn.create_requests == [plan["create_stack_request"]]
    assert receipt["execution_mode"] == "APPLY"
    assert receipt["status"] == "UNCERTAIN_RECONCILE_ONLY"
    assert receipt["target_state"] == "AMBIGUOUS"
    assert receipt["ambiguous_response"] is True
    assert receipt["retry_permitted"] is False
    assert receipt["mutation_retry_attempted"] is False
    assert calls.count("cloudformation:CreateStack") == 1


def test_reconcile_accepts_expired_authorization_but_performs_only_read_calls(
    bundle: Mapping[str, Any],
) -> None:
    plan = bundle["plan"]
    authorization = _authorization(plan)
    ledger = _ledger(plan, authorization)
    calls: list[str] = []
    cfn = FakeCloudFormation(
        calls=calls,
        plan=plan,
        name_descriptions=[_expected_stack(plan)],
    )
    factory = FakeFactory(
        calls=calls,
        cfn=cfn,
        s3_response=_head_response(plan),
    )

    receipt = materializer.reconcile_materialization(
        plan=plan,
        authorization=authorization,
        ledger=ledger,
        repo_root=bundle["repo"],
        client_factory=factory,
        clock=lambda: NOW + timedelta(days=1),
    )

    assert calls == list(materializer.RECONCILE_OPERATIONS)
    assert cfn.create_requests == []
    assert receipt["status"] == "READBACK_VERIFIED"
    assert receipt["execution_mode"] == "RECONCILE"
    assert receipt["execution_ledger_digest"] == ledger["ledger_digest"]
    assert receipt["aws_mutation_attempted"] is False
    assert receipt["retry_permitted"] is False
    assert receipt["no_touch"] is True
    assert receipt["artifact_signing_readback_complete"] is True
    assert not set(receipt["aws_operations"]).intersection(
        materializer.PROHIBITED_OPERATIONS
    )


def test_reconcile_refresh_failure_is_ambiguous_and_never_claims_signing_readback(
    bundle: Mapping[str, Any],
) -> None:
    plan = bundle["plan"]
    authorization = _authorization(plan)
    ledger = _ledger(plan, authorization)
    calls: list[str] = []
    cfn = FakeCloudFormation(
        calls=calls,
        plan=plan,
        name_descriptions=[_expected_stack(plan)],
    )

    receipt = materializer.reconcile_materialization(
        plan=plan,
        authorization=authorization,
        ledger=ledger,
        repo_root=bundle["repo"],
        client_factory=FakeFactory(
            calls=calls,
            cfn=cfn,
            s3_response=_head_response(plan),
            signer_mutations={
                "signer:DescribeSigningJob": {"status": "Failed"}
            },
        ),
        clock=lambda: NOW + timedelta(days=1),
    )

    assert calls == list(materializer.RECONCILE_OPERATIONS[:3])
    assert receipt["target_state"] == "AMBIGUOUS"
    assert receipt["status"] == "READBACK_PENDING_NO_MUTATION"
    assert receipt["artifact_signing_readback_complete"] is False
    assert receipt["readback_complete"] is False
    assert receipt["aws_mutation_attempted"] is False
    assert cfn.create_requests == []


def test_caller_authorization_drift_stops_after_sts(
    bundle: Mapping[str, Any],
) -> None:
    plan = bundle["plan"]
    other_caller = (
        f"arn:aws:sts::{materializer.AUTHORITY_ACCOUNT_ID}:"
        "assumed-role/ScanalyzeGug363Materializer/other-synthetic-operator"
    )
    authorization = _authorization(plan, caller_arn=other_caller)
    calls: list[str] = []
    cfn = FakeCloudFormation(
        calls=calls,
        plan=plan,
        name_descriptions=[None],
    )
    factory = FakeFactory(
        calls=calls,
        cfn=cfn,
        s3_response=_head_response(plan),
    )

    with pytest.raises(
        materializer.RetirementEntrypointMaterializationError,
        match="CALLER_IDENTITY_MISMATCH",
    ):
        materializer.apply_materialization(
            plan=plan,
            authorization=authorization,
            repo_root=bundle["repo"],
            client_factory=factory,
            claim_attempt=lambda value: pytest.fail(
                f"unexpected ledger claim: {value}"
            ),
            clock=lambda: NOW,
        )

    assert calls == ["sts:GetCallerIdentity"]
    assert cfn.create_requests == []


def test_caller_user_id_drift_stops_after_sts(
    bundle: Mapping[str, Any],
) -> None:
    plan = bundle["plan"]
    authorization = _authorization(plan)
    calls: list[str] = []
    cfn = FakeCloudFormation(
        calls=calls,
        plan=plan,
        name_descriptions=[None],
    )
    factory = FakeFactory(
        calls=calls,
        cfn=cfn,
        s3_response=_head_response(plan),
        caller_user_id="AROADIFFERENT:synthetic-operator",
    )

    with pytest.raises(
        materializer.RetirementEntrypointMaterializationError,
        match="CALLER_IDENTITY_MISMATCH",
    ):
        materializer.apply_materialization(
            plan=plan,
            authorization=authorization,
            repo_root=bundle["repo"],
            client_factory=factory,
            claim_attempt=lambda value: pytest.fail(
                f"unexpected ledger claim: {value}"
            ),
            clock=lambda: NOW,
        )

    assert calls == ["sts:GetCallerIdentity"]
    assert cfn.create_requests == []


def test_authorization_outside_exception_window_fails_before_aws_clients(
    bundle: Mapping[str, Any],
) -> None:
    plan = bundle["plan"]
    authorization = _authorization(plan)
    authorization["not_before"] = "2030-01-01T00:03:59Z"
    _reseal(authorization, "authorization_digest")

    class AwsClientsMustNotBeUsed:
        def sts(self) -> Any:
            pytest.fail("authorization drift reached STS")

        def cloudformation(self) -> Any:
            pytest.fail("authorization drift reached CloudFormation")

        def s3(self) -> Any:
            pytest.fail("authorization drift reached S3")

    with pytest.raises(
        materializer.RetirementEntrypointMaterializationError,
        match="AUTHORIZATION_OUTSIDE_EXCEPTION_WINDOW",
    ):
        materializer.apply_materialization(
            plan=plan,
            authorization=authorization,
            repo_root=bundle["repo"],
            client_factory=AwsClientsMustNotBeUsed(),
            claim_attempt=lambda value: pytest.fail(
                f"unexpected ledger claim: {value}"
            ),
            clock=lambda: NOW,
        )


def test_authorization_requires_digest_sealed_live_evidence(
    bundle: Mapping[str, Any],
) -> None:
    plan = bundle["plan"]
    valid = _authorization(plan)
    materializer.validate_execution_authorization(
        valid,
        plan=plan,
        now=NOW,
        require_active=True,
    )
    evidence_fields = {
        "live_checkpoint_digest",
        "live_before_state_digest",
        "service_role_evidence_digest",
        "operator_authority_evidence_digest",
    }
    assert evidence_fields.issubset(valid)
    assert all(str(valid[field]).startswith("sha256:") for field in evidence_fields)

    missing = copy.deepcopy(valid)
    missing.pop("service_role_evidence_digest")
    _reseal(missing, "authorization_digest")
    with pytest.raises(
        materializer.RetirementEntrypointMaterializationError,
        match="AUTHORIZATION_FIELDS_INVALID",
    ):
        materializer.validate_execution_authorization(
            missing,
            plan=plan,
            now=NOW,
            require_active=True,
        )

    tampered = copy.deepcopy(valid)
    tampered["operator_authority_evidence_digest"] = "sha256:" + "2" * 64
    with pytest.raises(
        materializer.RetirementEntrypointMaterializationError,
        match="AUTHORIZATION_DIGEST_MISMATCH",
    ):
        materializer.validate_execution_authorization(
            tampered,
            plan=plan,
            now=NOW,
            require_active=True,
        )


def test_resealed_receipt_rejects_invalid_operation_and_invalid_order(
    bundle: Mapping[str, Any],
) -> None:
    plan = bundle["plan"]
    authorization = _authorization(plan)
    ledger = _ledger(plan, authorization)
    valid = materializer.build_materialization_receipt(
        plan=plan,
        authorization=authorization,
        execution_mode="APPLY",
        status="READBACK_VERIFIED",
        target_state="COMPLETE",
        ledger_digest=ledger["ledger_digest"],
        stack_id=STACK_ID,
        stack_status="CREATE_COMPLETE",
        observed_resources=plan["expected_resources"],
        aws_operations=[
            *materializer.PREFLIGHT_OPERATIONS,
            "cloudformation:CreateStack",
            *materializer.POST_WRITE_READBACK_OPERATIONS,
        ],
        aws_mutation_attempted=True,
        ambiguous_response=False,
        no_touch=False,
        artifact_signing_readback_complete=True,
        readback_complete=True,
        created_at=NOW,
    )

    invalid_order = copy.deepcopy(valid)
    invalid_order["aws_operations"][0:2] = reversed(
        invalid_order["aws_operations"][0:2]
    )
    _reseal(invalid_order, "receipt_digest")
    with pytest.raises(
        materializer.RetirementEntrypointMaterializationError,
        match="RECEIPT_COMPLETE_READBACK_SEQUENCE_INVALID",
    ):
        materializer.validate_materialization_receipt(
            invalid_order,
            plan=plan,
            authorization=authorization,
        )

    prohibited = copy.deepcopy(valid)
    prohibited["aws_operations"][-1] = "cloudformation:UpdateStack"
    _reseal(prohibited, "receipt_digest")
    with pytest.raises(
        materializer.RetirementEntrypointMaterializationError,
        match="RECEIPT_OPERATIONS_INVALID",
    ):
        materializer.validate_materialization_receipt(
            prohibited,
            plan=plan,
            authorization=authorization,
        )

    signing_overclaim = copy.deepcopy(valid)
    signing_overclaim["artifact_signing_readback_complete"] = False
    _reseal(signing_overclaim, "receipt_digest")
    with pytest.raises(
        materializer.RetirementEntrypointMaterializationError,
        match="RECEIPT_SIGNING_READBACK_REQUIRED",
    ):
        materializer.validate_materialization_receipt(
            signing_overclaim,
            plan=plan,
            authorization=authorization,
        )

    no_ledger_complete = copy.deepcopy(valid)
    no_ledger_complete["execution_ledger_digest"] = None
    no_ledger_complete["aws_operations"] = [
        *materializer.PREFLIGHT_OPERATIONS,
        *materializer.POST_WRITE_READBACK_OPERATIONS[1:],
    ]
    no_ledger_complete["aws_mutation_attempted"] = False
    no_ledger_complete["aws_mutation_count"] = 0
    no_ledger_complete["no_touch"] = True
    _reseal(no_ledger_complete, "receipt_digest")
    with pytest.raises(
        materializer.RetirementEntrypointMaterializationError,
        match="RECEIPT_STATE_INVALID",
    ):
        materializer.validate_materialization_receipt(
            no_ledger_complete,
            plan=plan,
            authorization=authorization,
        )


def test_complete_receipts_reject_each_missing_readback_suffix_operation(
    bundle: Mapping[str, Any],
) -> None:
    plan = bundle["plan"]
    authorization = _authorization(plan)
    ledger_digest = _ledger(plan, authorization)["ledger_digest"]
    cases = (
        {
            "execution_mode": "APPLY",
            "status": "READBACK_VERIFIED",
            "ledger_digest": ledger_digest,
            "operations": [
                *materializer.PREFLIGHT_OPERATIONS,
                "cloudformation:CreateStack",
                *materializer.POST_WRITE_READBACK_OPERATIONS,
            ],
            "suffix_start": len(materializer.PREFLIGHT_OPERATIONS) + 1,
            "aws_mutation_attempted": True,
            "no_touch": False,
        },
        {
            "execution_mode": "RECONCILE",
            "status": "READBACK_VERIFIED",
            "ledger_digest": ledger_digest,
            "operations": list(materializer.RECONCILE_OPERATIONS),
            "suffix_start": len(materializer.RECONCILE_OPERATIONS) - 3,
            "aws_mutation_attempted": False,
            "no_touch": True,
        },
    )

    for case in cases:
        valid = materializer.build_materialization_receipt(
            plan=plan,
            authorization=authorization,
            execution_mode=str(case["execution_mode"]),
            status=str(case["status"]),
            target_state="COMPLETE",
            ledger_digest=case["ledger_digest"],
            stack_id=STACK_ID,
            stack_status="CREATE_COMPLETE",
            observed_resources=plan["expected_resources"],
            aws_operations=case["operations"],
            aws_mutation_attempted=bool(case["aws_mutation_attempted"]),
            ambiguous_response=False,
            no_touch=bool(case["no_touch"]),
            artifact_signing_readback_complete=True,
            readback_complete=True,
            created_at=NOW,
        )
        for index in range(
            int(case["suffix_start"]), len(valid["aws_operations"])
        ):
            missing = copy.deepcopy(valid)
            del missing["aws_operations"][index]
            _reseal(missing, "receipt_digest")
            with pytest.raises(
                materializer.RetirementEntrypointMaterializationError,
                match="RECEIPT_COMPLETE_READBACK_SEQUENCE_INVALID",
            ):
                materializer.validate_materialization_receipt(
                    missing,
                    plan=plan,
                    authorization=authorization,
                )


def _load_cli() -> Any:
    path = (
        REPO_ROOT
        / "scripts/deployment/"
        "platform-authority-retirement-entrypoint-materializer.py"
    )
    spec = importlib.util.spec_from_file_location("gug363_materializer_cli_test", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_boto_factory_ignores_profile_endpoints_and_has_zero_retries(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cli = _load_cli()
    import boto3

    created_clients: list[str] = []

    class FakeSession:
        def __init__(self, *, profile_name: str, region_name: str) -> None:
            assert profile_name == "synthetic-approved-profile"
            assert region_name == materializer.REGION

        def client(self, service: str, **kwargs: Any) -> object:
            assert kwargs["region_name"] == materializer.REGION
            config = kwargs["config"]
            assert config.ignore_configured_endpoint_urls is True
            assert config.retries == {
                "total_max_attempts": 1,
                "mode": "standard",
            }
            created_clients.append(service)
            return object()

    for name in (
        *cli.FORBIDDEN_CREDENTIAL_ENV,
        *cli.FORBIDDEN_TRANSPORT_ENV,
        "AWS_PROFILE",
        "AWS_DEFAULT_PROFILE",
        "AWS_REGION",
        "AWS_DEFAULT_REGION",
    ):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(boto3, "Session", FakeSession)

    factory = cli.BotoClientFactory(
        profile="synthetic-approved-profile",
        region=materializer.REGION,
    )
    factory.sts()
    factory.cloudformation()
    factory.s3()

    assert created_clients == ["sts", "cloudformation", "s3"]


def test_private_create_is_file_synced_closed_then_directory_synced(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cli = _load_cli()
    private = tmp_path / "durable-private"
    private.mkdir(mode=0o700)
    private.chmod(0o700)
    events: list[str] = []
    real_fsync = os.fsync
    real_close = os.close

    def descriptor_kind(descriptor: int) -> str:
        mode = os.fstat(descriptor).st_mode
        return "directory" if stat.S_ISDIR(mode) else "file"

    def tracked_fsync(descriptor: int) -> None:
        events.append(f"fsync:{descriptor_kind(descriptor)}")
        real_fsync(descriptor)

    def tracked_close(descriptor: int) -> None:
        events.append(f"close:{descriptor_kind(descriptor)}")
        real_close(descriptor)

    monkeypatch.setattr(cli.os, "fsync", tracked_fsync)
    monkeypatch.setattr(cli.os, "close", tracked_close)

    cli._write_private_json(
        private / "execution-ledger.json",
        {"status": "MUTATION_WINDOW_CONSUMED"},
        exists_code="EXISTS",
    )

    file_sync = events.index("fsync:file")
    file_close = events.index("close:file", file_sync)
    directory_sync = events.index("fsync:directory", file_close)
    assert file_sync < file_close < directory_sync


def test_private_directory_fsync_failure_is_fail_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cli = _load_cli()
    private = tmp_path / "failed-durable-private"
    private.mkdir(mode=0o700)
    private.chmod(0o700)
    target = private / "execution-ledger.json"
    real_fsync = os.fsync

    def fail_directory_fsync(descriptor: int) -> None:
        if stat.S_ISDIR(os.fstat(descriptor).st_mode):
            raise OSError("synthetic directory fsync failure")
        real_fsync(descriptor)

    monkeypatch.setattr(cli.os, "fsync", fail_directory_fsync)

    with pytest.raises(
        materializer.RetirementEntrypointMaterializationError,
        match="PRIVATE_DIRECTORY_FSYNC_FAILED",
    ):
        cli._write_private_json(
            target,
            {"status": "MUTATION_WINDOW_CONSUMED"},
            exists_code="EXISTS",
        )

    assert target.exists()
    assert stat.S_IMODE(target.stat().st_mode) == 0o600


def test_cli_private_io_is_owner_only_create_only_and_rejects_symlinks(
    tmp_path: Path,
) -> None:
    cli = _load_cli()
    private = tmp_path / "private"
    private.mkdir(mode=0o700)
    private.chmod(0o700)
    source = private / "source.json"
    source.write_text('{"value":"synthetic"}\n', encoding="utf-8")
    source.chmod(0o600)

    assert cli._read_private_json(source) == {"value": "synthetic"}
    output = private / "output.json"
    cli._write_private_json(output, {"status": "synthetic"}, exists_code="EXISTS")
    assert stat.S_IMODE(output.stat().st_mode) == 0o600
    assert json.loads(output.read_text(encoding="utf-8")) == {
        "status": "synthetic"
    }
    with pytest.raises(
        materializer.RetirementEntrypointMaterializationError, match="EXISTS"
    ):
        cli._write_private_json(output, {}, exists_code="EXISTS")

    symlink = private / "source-link.json"
    os.symlink(source, symlink)
    with pytest.raises(
        materializer.RetirementEntrypointMaterializationError,
        match="PRIVATE_INPUT_INVALID",
    ):
        cli._read_private_json(symlink)
    with pytest.raises(
        materializer.RetirementEntrypointMaterializationError,
        match="PRIVATE_INPUT_INSIDE_REPOSITORY",
    ):
        cli._read_private_json(REPO_ROOT / "must-not-be-read.json")

    nonfinite = private / "nonfinite.json"
    nonfinite.write_text('{"value":NaN}\n', encoding="utf-8")
    nonfinite.chmod(0o600)
    with pytest.raises(
        materializer.RetirementEntrypointMaterializationError,
        match="PRIVATE_JSON_NONFINITE_NUMBER",
    ):
        cli._read_private_json(nonfinite)

    real_parent = tmp_path / "real-private-parent"
    real_parent.mkdir(mode=0o700)
    real_parent.chmod(0o700)
    linked_parent = tmp_path / "linked-private-parent"
    os.symlink(real_parent, linked_parent)
    with pytest.raises(
        materializer.RetirementEntrypointMaterializationError,
        match="PRIVATE_DIRECTORY_INVALID",
    ):
        cli._read_private_json(linked_parent / "input.json")

    permissive_parent = tmp_path / "permissive-parent"
    permissive_parent.mkdir(mode=0o755)
    permissive_parent.chmod(0o755)
    permissive_input = permissive_parent / "input.json"
    permissive_input.write_text("{}\n", encoding="utf-8")
    permissive_input.chmod(0o600)
    with pytest.raises(
        materializer.RetirementEntrypointMaterializationError,
        match="PRIVATE_DIRECTORY_MODE_INVALID",
    ):
        cli._read_private_json(permissive_input)


def test_cli_blocks_apply_without_explicit_flag_and_emits_only_public_status(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    cli = _load_cli()
    secret = "must-not-appear-in-cli-output"
    result = cli.main(
        [
            "apply",
            "--plan",
            str(tmp_path / secret),
            "--authorization",
            str(tmp_path / f"{secret}-authorization"),
            "--expected-plan-digest",
            "sha256:" + "1" * 64,
            "--expected-authorization-digest",
            "sha256:" + "2" * 64,
            "--expected-artifact-signing-contract-digest",
            "sha256:" + "3" * 64,
            "--profile",
            "synthetic-non-production",
            "--region",
            materializer.REGION,
            "--receipt-out",
            str(tmp_path / f"{secret}-receipt"),
        ]
    )

    captured = capsys.readouterr()
    assert result == 2
    assert captured.out == ""
    public = json.loads(captured.err)
    assert public == {
        "aws_mutation_attempted": False,
        "production_status": "NO-GO",
        "reason": "CREATE_STACK_NOT_AUTHORIZED",
        "retry_permitted": False,
        "status": "BLOCKED",
    }
    assert secret not in captured.err


def test_public_cli_projection_never_exposes_private_provider_fields() -> None:
    cli = _load_cli()
    projected = cli._public_status(
        {
            "status": "UNCERTAIN_RECONCILE_ONLY",
            "plan_digest": "sha256:" + "1" * 64,
            "receipt_digest": "sha256:" + "2" * 64,
            "aws_mutation_attempted": True,
            "caller_arn": CALLER_ARN,
            "stack_id": STACK_ID,
            "artifact_version": "private-version",
            "provider_error": "private-diagnostic",
        }
    )

    assert set(projected) == {
        "status",
        "plan_digest",
        "receipt_digest",
        "aws_mutation_attempted",
        "retry_permitted",
        "materializer_readback_scope",
        "provider_certification_complete",
        "gug357_certification_required",
        "production_status",
    }
    assert projected["retry_permitted"] is False
    assert projected["materializer_readback_scope"] == "NONE_PLAN_ONLY"
    assert projected["provider_certification_complete"] is False
    assert projected["gug357_certification_required"] is True
    assert projected["production_status"] == "NO-GO"
