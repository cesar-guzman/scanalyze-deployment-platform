"""AWS Signer-to-CloudFormation handoff tests for GUG-221."""

from __future__ import annotations

from datetime import UTC, datetime
import base64
from hashlib import sha256
from io import BytesIO
from pathlib import Path
import shutil
import subprocess
import sys
from zipfile import ZIP_STORED, ZipFile

import pytest


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tooling.platform_authority_lambda_audit_repair_package import (  # noqa: E402
    PROVENANCE_TOOL_PATHS,
    SOURCE_PATHS,
    build_repair_package,
)
from tooling.platform_authority_lambda_audit_repair_signed_artifact import (  # noqa: E402
    EXPECTED_VERIFIER_PROFILE,
    REQUIRED_GITHUB_CHECKS,
    SignedArtifactError,
    _build_signed_artifact_receipt,
    build_signed_artifact_receipt_from_aws,
    validate_signed_artifact_receipt,
    verify_github_merged_release,
)


SOURCE_COMMIT = "1" * 40
PROFILE_ARN = (
    "arn:aws:signer:us-east-1:042360977644:/signing-profiles/"
    "ScanalyzeGug221/ABCDEFGHIJ"
)
NOW = datetime(2026, 7, 21, tzinfo=UTC)
BUCKET = "scanalyze-gug221-artifacts-7644"
SOURCE_KEY = "scanalyze/platform-authority/gug-221/unsigned/repair.zip"
JOB_ID = "11111111-2222-4333-8444-555555555555"
SIGNED_KEY = f"scanalyze/platform-authority/gug-221/signed/{JOB_ID}.zip"


def _unsigned(boto3_version: str = "1.40.0"):
    return build_repair_package(
        source_root=ROOT,
        source_commit=SOURCE_COMMIT,
        expected_boto3_version=boto3_version,
        expected_botocore_version="1.40.0",
    )


def _job(*, expires: str = "2027-07-21T00:00:00Z") -> dict:
    return {
        "status": "Succeeded",
        "jobOwner": "042360977644",
        "jobInvoker": "042360977644",
        "platformId": "AWSLambda-SHA384-ECDSA",
        "profileName": "ScanalyzeGug221",
        "profileVersion": "ABCDEFGHIJ",
        "jobId": JOB_ID,
        "signatureExpiresAt": expires,
        "source": {
            "s3": {"bucketName": BUCKET, "key": SOURCE_KEY, "version": "UnsignedVersion1"}
        },
        "signedObject": {"s3": {"bucketName": BUCKET, "key": SIGNED_KEY}},
    }


def _signed(archive: bytes) -> bytes:
    # AWS Signer produces a distinct signed destination object. The synthetic
    # trailer keeps the ZIP readable while representing that byte distinction.
    return archive + b"SYNTHETIC-AWS-SIGNER-METADATA"


def _head(signed: bytes) -> dict:
    import base64

    digest = sha256(signed).digest()
    return {
        "bucket": BUCKET,
        "key": SIGNED_KEY,
        "version_id": "SignedVersion1",
        "content_length": len(signed),
        "checksum_sha256": base64.b64encode(digest).decode("ascii"),
    }


def _verifier() -> dict:
    return {
        "Account": "042360977644",
        "Arn": (
            "arn:aws:sts::042360977644:assumed-role/"
            "AWSReservedSSO_AWSReadOnlyAccess_1c38063fd41ea692/"
            "synthetic@example.invalid"
        ),
    }


def _source_review(source_commit: str = SOURCE_COMMIT) -> dict:
    return {
        "repository": "cesar-guzman/scanalyze-deployment-platform",
        "branch": "main",
        "source_commit": source_commit,
        "source_tree": "2" * 40,
        "pull_request_number": 36,
        "pull_request_head_commit": "3" * 40,
        "pull_request_head_tree": "2" * 40,
        "merged_at": "2026-07-21T00:00:00Z",
        "required_checks": [
            {
                "name": name,
                "conclusion": "success",
                "app_id": 15368,
                "app_slug": "github-actions",
            }
            for name in REQUIRED_GITHUB_CHECKS
        ],
        "branch_protection_strict": True,
        "evidence_status": "MERGED_MAIN_REQUIRED_CHECKS_VERIFIED",
    }


def _receipt() -> dict:
    unsigned = _unsigned()
    signed = _signed(unsigned.archive)
    return dict(
        _build_signed_artifact_receipt(
            unsigned_manifest=unsigned.manifest,
            downloaded_unsigned_archive=unsigned.archive,
            downloaded_signed_archive=signed,
            signing_job=_job(),
            signed_object_head=_head(signed),
            expected_profile_version_arn=PROFILE_ARN,
            verifier_identity=_verifier(),
            verifier_profile=EXPECTED_VERIFIER_PROFILE,
            source_review=_source_review(),
            now=NOW,
        )
    )


def test_signed_receipt_projects_one_exact_tuple_into_both_functions() -> None:
    receipt = _receipt()
    validate_signed_artifact_receipt(receipt)
    parameters = {
        item["ParameterKey"]: item["ParameterValue"]
        for item in receipt["cloudformation_parameters"]
    }
    assert parameters["SourceCommit"] == SOURCE_COMMIT
    assert parameters["ExpectedBoto3Version"] == "1.40.0"
    assert parameters["ExpectedBotocoreVersion"] == "1.40.0"
    for suffix in ("Bucket", "Key", "Version", "CodeSha256"):
        assert parameters[f"RepairArtifact{suffix}"] == parameters[
            f"ReconcileArtifact{suffix}"
        ]
    assert parameters["SigningProfileVersionArn"] == PROFILE_ARN
    assert receipt["evidence_status"] == "SIGNED_ARTIFACT_BOUND_FOR_CHANGE_SET_REVIEW"
    assert receipt["production_status"] == "NO-GO"


def test_signed_receipt_rejects_source_entry_substitution() -> None:
    reviewed = _unsigned()
    substituted = _unsigned(boto3_version="1.41.0")
    signed = _signed(substituted.archive)
    with pytest.raises(SignedArtifactError, match="SIGNED_ARCHIVE_SOURCE_ENTRY_DRIFT"):
        _build_signed_artifact_receipt(
            unsigned_manifest=reviewed.manifest,
            downloaded_unsigned_archive=reviewed.archive,
            downloaded_signed_archive=signed,
            signing_job=_job(),
            signed_object_head=_head(signed),
            expected_profile_version_arn=PROFILE_ARN,
            verifier_identity=_verifier(),
            verifier_profile=EXPECTED_VERIFIER_PROFILE,
            source_review=_source_review(),
            now=NOW,
        )


def test_signed_receipt_rejects_expired_signature_and_head_drift() -> None:
    unsigned = _unsigned()
    signed = _signed(unsigned.archive)
    with pytest.raises(SignedArtifactError, match="SIGNATURE_EXPIRED"):
        _build_signed_artifact_receipt(
            unsigned_manifest=unsigned.manifest,
            downloaded_unsigned_archive=unsigned.archive,
            downloaded_signed_archive=signed,
            signing_job=_job(expires="2026-07-20T00:00:00Z"),
            signed_object_head=_head(signed),
            expected_profile_version_arn=PROFILE_ARN,
            verifier_identity=_verifier(),
            verifier_profile=EXPECTED_VERIFIER_PROFILE,
            source_review=_source_review(),
            now=NOW,
        )
    drifted_head = _head(signed)
    drifted_head["content_length"] += 1
    with pytest.raises(SignedArtifactError, match="SIGNED_OBJECT_HEAD_MISMATCH"):
        _build_signed_artifact_receipt(
            unsigned_manifest=unsigned.manifest,
            downloaded_unsigned_archive=unsigned.archive,
            downloaded_signed_archive=signed,
            signing_job=_job(),
            signed_object_head=drifted_head,
            expected_profile_version_arn=PROFILE_ARN,
            verifier_identity=_verifier(),
            verifier_profile=EXPECTED_VERIFIER_PROFILE,
            source_review=_source_review(),
            now=NOW,
        )


def test_signed_receipt_rejects_cfn_parameter_substitution() -> None:
    receipt = _receipt()
    receipt["cloudformation_parameters"][8]["ParameterValue"] = (
        "scanalyze/platform-authority/gug-221/signed/foreign.zip"
    )
    with pytest.raises(SignedArtifactError, match="CFN_PARAMETER_BINDING_DRIFT"):
        validate_signed_artifact_receipt(receipt)


def test_signed_receipt_rejects_extra_executable_entry_and_missing_checksum() -> None:
    unsigned = _unsigned()
    buffer = BytesIO(unsigned.archive)
    with ZipFile(buffer, mode="a", compression=ZIP_STORED) as archive:
        archive.writestr("sitecustomize.py", b"raise RuntimeError('unexpected')\n")
    signed = _signed(buffer.getvalue())
    with pytest.raises(SignedArtifactError, match="SIGNED_ARCHIVE_PATH_SET_INVALID"):
        _build_signed_artifact_receipt(
            unsigned_manifest=unsigned.manifest,
            downloaded_unsigned_archive=unsigned.archive,
            downloaded_signed_archive=signed,
            signing_job=_job(),
            signed_object_head=_head(signed),
            expected_profile_version_arn=PROFILE_ARN,
            verifier_identity=_verifier(),
            verifier_profile=EXPECTED_VERIFIER_PROFILE,
            source_review=_source_review(),
            now=NOW,
        )

    signed = _signed(unsigned.archive)
    head = _head(signed)
    head["checksum_sha256"] = None
    with pytest.raises(SignedArtifactError, match="SIGNED_OBJECT_CHECKSUM_MISSING"):
        _build_signed_artifact_receipt(
            unsigned_manifest=unsigned.manifest,
            downloaded_unsigned_archive=unsigned.archive,
            downloaded_signed_archive=signed,
            signing_job=_job(),
            signed_object_head=head,
            expected_profile_version_arn=PROFILE_ARN,
            verifier_identity=_verifier(),
            verifier_profile=EXPECTED_VERIFIER_PROFILE,
            source_review=_source_review(),
            now=NOW,
        )


def _committed_source(tmp_path: Path) -> tuple[Path, str]:
    source = tmp_path / "source"
    source.mkdir()
    tracked_paths = (*SOURCE_PATHS, *PROVENANCE_TOOL_PATHS)
    for relative in tracked_paths:
        target = source / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / relative, target)
    commands = (
        ("init", "-q"),
        ("config", "user.email", "synthetic@example.invalid"),
        ("config", "user.name", "Synthetic Test"),
        ("add", "--", *[path.as_posix() for path in tracked_paths]),
        ("commit", "-q", "-m", "synthetic source"),
    )
    for command in commands:
        subprocess.run(["git", *command], cwd=source, check=True, timeout=30)
    commit = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=source,
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    ).stdout.strip()
    return source, commit


class _Sts:
    def get_caller_identity(self) -> dict:
        return {
            "Account": "042360977644",
            "Arn": (
                "arn:aws:sts::042360977644:assumed-role/"
                "AWSReservedSSO_AWSReadOnlyAccess_1c38063fd41ea692/"
                "synthetic@example.invalid"
            ),
        }


class _Signer:
    def __init__(self, job: dict) -> None:
        self.job = job

    def describe_signing_job(self, **kwargs) -> dict:
        assert kwargs == {"jobId": JOB_ID}
        return self.job


class _S3:
    def __init__(self, *, unsigned: bytes, signed: bytes) -> None:
        self.objects = {
            (SOURCE_KEY, "UnsignedVersion1"): unsigned,
            (SIGNED_KEY, "SignedVersion1"): signed,
        }

    def get_bucket_versioning(self, **kwargs) -> dict:
        assert kwargs["ExpectedBucketOwner"] == "042360977644"
        return {"Status": "Enabled"}

    def list_object_versions(self, **kwargs) -> dict:
        assert kwargs["Prefix"] == SIGNED_KEY
        return {
            "IsTruncated": False,
            "Versions": [
                {"Key": SIGNED_KEY, "VersionId": "SignedVersion1", "IsLatest": True}
            ],
        }

    def _response(self, kwargs: dict, *, include_body: bool) -> dict:
        payload = self.objects[(kwargs["Key"], kwargs["VersionId"])]
        result = {
            "VersionId": kwargs["VersionId"],
            "ContentLength": len(payload),
            "ChecksumSHA256": base64.b64encode(sha256(payload).digest()).decode("ascii"),
        }
        if include_body:
            result["Body"] = BytesIO(payload)
        return result

    def head_object(self, **kwargs) -> dict:
        return self._response(kwargs, include_body=False)

    def get_object(self, **kwargs) -> dict:
        return self._response(kwargs, include_body=True)


def test_aws_readback_rebuilds_clean_commit_and_rejects_self_asserted_source(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source, commit = _committed_source(tmp_path)
    monkeypatch.setattr(
        "tooling.platform_authority_lambda_audit_repair_signed_artifact."
        "verify_github_merged_release",
        lambda **_: _source_review(commit),
    )
    reviewed = build_repair_package(
        source_root=source,
        source_commit=commit,
        expected_boto3_version="1.40.0",
        expected_botocore_version="1.40.0",
    )
    signed = _signed(reviewed.archive)
    aws_job = _job()
    aws_job["signatureExpiresAt"] = datetime(2027, 7, 21, tzinfo=UTC)
    receipt = build_signed_artifact_receipt_from_aws(
        source_root=source,
        source_commit=commit,
        expected_boto3_version="1.40.0",
        expected_botocore_version="1.40.0",
        profile_name=EXPECTED_VERIFIER_PROFILE,
        job_id=JOB_ID,
        expected_profile_version_arn=PROFILE_ARN,
        sts_client=_Sts(),
        signer_client=_Signer(aws_job),
        s3_client=_S3(unsigned=reviewed.archive, signed=signed),
        now=NOW,
    )
    assert receipt["source_commit"] == commit
    assert receipt["signing_job"]["signature_expires_at"] == "2027-07-21T00:00:00Z"

    self_asserted = build_repair_package(
        source_root=source,
        source_commit=commit,
        expected_boto3_version="1.41.0",
        expected_botocore_version="1.40.0",
    )
    with pytest.raises(SignedArtifactError, match="REVIEWED_SOURCE_ARCHIVE_MISMATCH"):
        build_signed_artifact_receipt_from_aws(
            source_root=source,
            source_commit=commit,
            expected_boto3_version="1.40.0",
            expected_botocore_version="1.40.0",
            profile_name=EXPECTED_VERIFIER_PROFILE,
            job_id=JOB_ID,
            expected_profile_version_arn=PROFILE_ARN,
            sts_client=_Sts(),
            signer_client=_Signer(_job()),
            s3_client=_S3(
                unsigned=self_asserted.archive,
                signed=_signed(self_asserted.archive),
            ),
            now=NOW,
        )


def test_github_release_anchor_requires_current_main_protection_and_trusted_checks(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    head_commit = "3" * 40
    tree = "2" * 40

    def command_text(*, source_root: Path, command: list[str]) -> str:
        assert source_root == tmp_path
        if command[-3:] == ["remote", "get-url", "origin"]:
            return "https://github.com/cesar-guzman/scanalyze-deployment-platform.git"
        if command[-3:] == ["rev-parse", "--verify", "refs/remotes/origin/main"]:
            return SOURCE_COMMIT
        raise AssertionError(command)

    check_runs = [
        {
            "name": name,
            "head_sha": head_commit,
            "status": "completed",
            "conclusion": "success",
            "app": {"id": 15368, "slug": "github-actions"},
        }
        for name in REQUIRED_GITHUB_CHECKS
    ]

    def command_json(*, source_root: Path, command: list[str]):
        assert source_root == tmp_path
        endpoint = command[2]
        if endpoint.endswith("/branches/main"):
            return {"protected": True, "commit": {"sha": SOURCE_COMMIT}}
        if endpoint.endswith("/protection/required_status_checks"):
            return {
                "strict": True,
                "contexts": list(REQUIRED_GITHUB_CHECKS),
                "checks": [
                    {"context": name, "app_id": 15368}
                    for name in REQUIRED_GITHUB_CHECKS
                ],
            }
        if endpoint.endswith(f"/commits/{SOURCE_COMMIT}/pulls"):
            return [{
                "number": 36,
                "merged_at": "2026-07-21T00:00:00Z",
                "merge_commit_sha": SOURCE_COMMIT,
                "base": {"ref": "main"},
                "head": {"sha": head_commit},
            }]
        if endpoint.endswith(f"/git/commits/{SOURCE_COMMIT}"):
            return {"tree": {"sha": tree}}
        if endpoint.endswith(f"/git/commits/{head_commit}"):
            return {"tree": {"sha": tree}}
        if "/check-runs?" in endpoint:
            return {"total_count": len(check_runs), "check_runs": check_runs}
        raise AssertionError(command)

    monkeypatch.setattr(
        "tooling.platform_authority_lambda_audit_repair_signed_artifact._command_text",
        command_text,
    )
    monkeypatch.setattr(
        "tooling.platform_authority_lambda_audit_repair_signed_artifact._command_json",
        command_json,
    )
    evidence = verify_github_merged_release(
        source_root=tmp_path,
        source_commit=SOURCE_COMMIT,
    )
    assert evidence["branch_protection_strict"] is True
    assert evidence["source_tree"] == tree

    check_runs[0]["app"] = {"id": 1, "slug": "untrusted"}
    with pytest.raises(SignedArtifactError, match="SOURCE_CHECK_PROVENANCE_INVALID"):
        verify_github_merged_release(
            source_root=tmp_path,
            source_commit=SOURCE_COMMIT,
        )
