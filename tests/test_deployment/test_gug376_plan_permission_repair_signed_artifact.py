"""AWS Signer-to-CloudFormation handoff contracts for GUG-376."""

from __future__ import annotations

import base64
from datetime import UTC, datetime, timedelta
from functools import lru_cache
from hashlib import sha256, sha384
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import sys
from types import ModuleType, SimpleNamespace

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tooling.platform_authority_lambda_audit_repair_signed_artifact import (  # noqa: E402
    REQUIRED_GITHUB_CHECKS,
)
from tooling.platform_authority_plan_permission_repair_package import (  # noqa: E402
    CLOUDFORMATION_TEMPLATE_PATHS,
    PROVENANCE_TOOL_PATHS,
    SOURCE_PATHS,
    build_plan_permission_repair_package,
    verify_clean_source_commit,
)
from tooling.platform_authority_plan_permission_repair_signed_artifact import (  # noqa: E402
    EXPECTED_VERIFIER_PROFILE,
    PlanPermissionRepairSignedArtifactError,
    _build_signed_artifact_receipt_from_trusted_readbacks,
    _verify_revocation_status,
    build_signed_artifact_receipt_from_aws,
    validate_signed_artifact_receipt,
)
from tooling import (  # noqa: E402
    platform_authority_plan_permission_repair_signed_artifact as signed_module,
)


SOURCE_COMMIT = "1" * 40
EXPECTED_BOTO3_VERSION = "1.42.57"
EXPECTED_BOTOCORE_VERSION = "1.42.97"
PROFILE_ARN = (
    "arn:aws:signer:us-east-1:042360977644:/signing-profiles/"
    "ScanalyzeGug376/ABCDEFGHIJ"
)
NOW = datetime(2026, 8, 30, tzinfo=UTC)
BUCKET = "scanalyze-gug376-repair-artifacts-7644"
SOURCE_KEY = (
    "scanalyze/platform-authority/gug-376/plan-policy-repair/"
    "unsigned/repair.zip"
)
JOB_ID = "11111111-2222-4333-8444-555555555555"
SIGNED_KEY = (
    "scanalyze/platform-authority/gug-376/plan-policy-repair/"
    f"signed/{JOB_ID}.zip"
)
CERTIFICATE_ARN = (
    "arn:aws:acm:us-east-1:042360977644:certificate/"
    "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
)
JOB_ARN = (
    "arn:aws:signer:us-east-1:042360977644:"
    f"/signing-jobs/{JOB_ID}"
)


@lru_cache(maxsize=1)
def _certificate_material() -> tuple[str, str, str]:
    """Return a child, its CA, and the exact Signer composite hash."""

    root_key = ec.generate_private_key(ec.SECP384R1())
    root_name = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "Synthetic Signer Root")]
    )
    root = (
        x509.CertificateBuilder()
        .subject_name(root_name)
        .issuer_name(root_name)
        .public_key(root_key.public_key())
        .serial_number(1)
        .not_valid_before(datetime(2026, 1, 1, tzinfo=UTC))
        .not_valid_after(datetime(2030, 1, 1, tzinfo=UTC))
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=1),
            critical=True,
        )
        .sign(root_key, hashes.SHA384())
    )
    child_key = ec.generate_private_key(ec.SECP384R1())
    child_name = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "Synthetic Signer Leaf")]
    )
    child = (
        x509.CertificateBuilder()
        .subject_name(child_name)
        .issuer_name(root_name)
        .public_key(child_key.public_key())
        .serial_number(2)
        .not_valid_before(datetime(2026, 1, 1, tzinfo=UTC))
        .not_valid_after(datetime(2030, 1, 1, tzinfo=UTC))
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
        .sign(root_key, hashes.SHA384())
    )
    child_pem = child.public_bytes(serialization.Encoding.PEM).decode(
        "ascii"
    )
    root_pem = root.public_bytes(serialization.Encoding.PEM).decode("ascii")
    certificate_hash = (
        sha384(child.tbs_certificate_bytes).hexdigest()
        + sha384(root.tbs_certificate_bytes).hexdigest()
    )
    return child_pem, root_pem, certificate_hash


def _text_digest(value: str) -> str:
    return "sha256:" + sha256(value.encode("utf-8")).hexdigest()


def _template_digests(source_root: Path = ROOT) -> dict[str, str]:
    return {
        path.as_posix(): sha256((source_root / path).read_bytes()).hexdigest()
        for path in CLOUDFORMATION_TEMPLATE_PATHS
    }


def _revocation_check(checked_at: datetime = NOW) -> dict[str, str]:
    return {
        "status": "PROFILE_JOB_AND_CERTIFICATE_NOT_REVOKED",
        "checked_at": checked_at.isoformat().replace("+00:00", "Z"),
        "profile_version_arn_digest": _text_digest(PROFILE_ARN),
        "job_arn_digest": _text_digest(JOB_ARN),
        "certificate_hash_digest": _text_digest(
            _certificate_material()[2]
        ),
    }


def _unsigned(
    *,
    source_root: Path = ROOT,
    source_commit: str = SOURCE_COMMIT,
    committed_sources=None,
    boto3_version: str = EXPECTED_BOTO3_VERSION,
):
    return build_plan_permission_repair_package(
        source_root=source_root,
        source_commit=source_commit,
        expected_boto3_version=boto3_version,
        expected_botocore_version=EXPECTED_BOTOCORE_VERSION,
        committed_sources=committed_sources,
    )


def _job(
    *,
    expires: str = "2027-08-30T00:00:00Z",
    completed_at: datetime = NOW,
) -> dict:
    return {
        "status": "Succeeded",
        "jobOwner": "042360977644",
        "jobInvoker": "042360977644",
        "platformId": "AWSLambda-SHA384-ECDSA",
        "profileName": "ScanalyzeGug376",
        "profileVersion": "ABCDEFGHIJ",
        "jobId": JOB_ID,
        "completedAt": completed_at,
        "signatureExpiresAt": expires,
        "signingMaterial": {"certificateArn": CERTIFICATE_ARN},
        "source": {
            "s3": {
                "bucketName": BUCKET,
                "key": SOURCE_KEY,
                "version": "UnsignedVersion1",
            }
        },
        "signedObject": {
            "s3": {"bucketName": BUCKET, "key": SIGNED_KEY}
        },
    }


def _signed(archive: bytes) -> bytes:
    return archive + b"SYNTHETIC-AWS-SIGNER-METADATA"


def _head(signed: bytes) -> dict:
    digest = sha256(signed).digest()
    return {
        "bucket": BUCKET,
        "key": SIGNED_KEY,
        "version_id": "SignedVersion1",
        "content_length": len(signed),
        "checksum_sha256": base64.b64encode(digest).decode("ascii"),
        "checksum_provenance": "S3_SHA256_AND_LOCAL",
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
        "pull_request_number": 100,
        "pull_request_head_commit": "3" * 40,
        "pull_request_head_tree": "2" * 40,
        "merged_at": "2026-08-30T00:00:00Z",
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
        _build_signed_artifact_receipt_from_trusted_readbacks(
            unsigned_manifest=unsigned.manifest,
            downloaded_unsigned_archive=unsigned.archive,
            downloaded_signed_archive=signed,
            signing_job=_job(),
            signed_object_head=_head(signed),
            expected_profile_version_arn=PROFILE_ARN,
            verifier_identity=_verifier(),
            verifier_profile=EXPECTED_VERIFIER_PROFILE,
            source_review=_source_review(),
            revocation_check=_revocation_check(),
            cloudformation_template_digests=_template_digests(),
            now=NOW,
        )
    )


def test_signed_receipt_projects_one_exact_tuple_for_all_three_handlers() -> None:
    receipt = _receipt()
    validate_signed_artifact_receipt(receipt, now=NOW)
    parameters = {
        item["ParameterKey"]: item["ParameterValue"]
        for item in receipt["cloudformation_parameters"]
    }
    assert tuple(parameters) == (
        "SourceCommit",
        "SourceBundleDigest",
        "ExpectedBoto3Version",
        "ExpectedBotocoreVersion",
        "ArtifactBucket",
        "ArtifactKey",
        "ArtifactVersion",
        "ArtifactCodeSha256",
        "SigningProfileVersionArn",
    )
    assert parameters["SourceCommit"] == SOURCE_COMMIT
    assert parameters["SourceBundleDigest"] == receipt[
        "source_bundle_digest"
    ]
    assert parameters["ExpectedBoto3Version"] == EXPECTED_BOTO3_VERSION
    assert (
        parameters["ExpectedBotocoreVersion"]
        == EXPECTED_BOTOCORE_VERSION
    )
    assert parameters["ArtifactBucket"] == BUCKET
    assert parameters["ArtifactKey"] == SIGNED_KEY
    assert parameters["ArtifactVersion"] == "SignedVersion1"
    assert parameters["SigningProfileVersionArn"] == PROFILE_ARN
    assert receipt["evidence_status"] == (
        "SIGNED_ARTIFACT_BOUND_FOR_CHANGE_SET_REVIEW"
    )
    assert receipt["production_status"] == "NO-GO"
    assert receipt["signing_job"]["signature_timestamp"] == (
        "2026-08-30T00:00:00Z"
    )
    assert receipt["revocation_check"] == _revocation_check()
    assert receipt["cloudformation_templates"] == [
        {"path": path, "sha256": digest}
        for path, digest in _template_digests().items()
    ]


def test_signed_receipt_must_be_consumed_while_revocation_is_fresh() -> None:
    receipt = _receipt()
    validate_signed_artifact_receipt(
        receipt,
        now=NOW + timedelta(minutes=15),
    )
    with pytest.raises(
        PlanPermissionRepairSignedArtifactError,
        match="SIGNED_RECEIPT_STALE",
    ):
        validate_signed_artifact_receipt(
            receipt,
            now=NOW + timedelta(minutes=15, seconds=1),
        )


def test_signed_receipt_parameter_set_matches_cloudformation_contract() -> None:
    source = (
        ROOT
        / "bootstrap/cfn-platform-authority-bootstrap-plan-repair-pep.yaml"
    ).read_text(encoding="utf-8")
    receipt_keys = {
        item["ParameterKey"]
        for item in _receipt()["cloudformation_parameters"]
    }
    for key in receipt_keys:
        assert source.count(f"  {key}:\n") == 1
    for key, count in {
        "ArtifactBucket": 3,
        "ArtifactKey": 3,
        "ArtifactVersion": 3,
        "ArtifactCodeSha256": 6,
    }.items():
        assert source.count(f"!Ref {key}") == count
    assert source.count("!Ref SourceBundleDigest") == 3


def test_signed_receipt_rejects_source_entry_and_cfn_substitution() -> None:
    reviewed = _unsigned()
    substituted = _unsigned(boto3_version="1.42.58")
    signed = _signed(substituted.archive)
    with pytest.raises(
        PlanPermissionRepairSignedArtifactError,
        match="SIGNED_ARCHIVE_SOURCE_ENTRY_DRIFT",
    ):
        _build_signed_artifact_receipt_from_trusted_readbacks(
            unsigned_manifest=reviewed.manifest,
            downloaded_unsigned_archive=reviewed.archive,
            downloaded_signed_archive=signed,
            signing_job=_job(),
            signed_object_head=_head(signed),
            expected_profile_version_arn=PROFILE_ARN,
            verifier_identity=_verifier(),
            verifier_profile=EXPECTED_VERIFIER_PROFILE,
            source_review=_source_review(),
            revocation_check=_revocation_check(),
            cloudformation_template_digests=_template_digests(),
            now=NOW,
        )

    receipt = _receipt()
    receipt["cloudformation_parameters"][5]["ParameterValue"] = (
        "scanalyze/platform-authority/gug-376/plan-policy-repair/"
        f"signed/{'9' * 8}-2222-4333-8444-555555555555.zip"
    )
    with pytest.raises(
        PlanPermissionRepairSignedArtifactError,
        match="CFN_PARAMETER_BINDING_DRIFT",
    ):
        validate_signed_artifact_receipt(receipt, now=NOW)


def test_signed_receipt_rejects_expiry_checksum_and_source_review_drift() -> None:
    unsigned = _unsigned()
    signed = _signed(unsigned.archive)
    with pytest.raises(
        PlanPermissionRepairSignedArtifactError,
        match="SIGNATURE_EXPIRED",
    ):
        _build_signed_artifact_receipt_from_trusted_readbacks(
            unsigned_manifest=unsigned.manifest,
            downloaded_unsigned_archive=unsigned.archive,
            downloaded_signed_archive=signed,
            signing_job=_job(expires="2026-08-29T00:00:00Z"),
            signed_object_head=_head(signed),
            expected_profile_version_arn=PROFILE_ARN,
            verifier_identity=_verifier(),
            verifier_profile=EXPECTED_VERIFIER_PROFILE,
            source_review=_source_review(),
            revocation_check=_revocation_check(),
            cloudformation_template_digests=_template_digests(),
            now=NOW,
        )
    head = _head(signed)
    head["checksum_sha256"] = base64.b64encode(b"0" * 32).decode("ascii")
    with pytest.raises(
        PlanPermissionRepairSignedArtifactError,
        match="SIGNED_OBJECT_CHECKSUM_MISMATCH",
    ):
        _build_signed_artifact_receipt_from_trusted_readbacks(
            unsigned_manifest=unsigned.manifest,
            downloaded_unsigned_archive=unsigned.archive,
            downloaded_signed_archive=signed,
            signing_job=_job(),
            signed_object_head=head,
            expected_profile_version_arn=PROFILE_ARN,
            verifier_identity=_verifier(),
            verifier_profile=EXPECTED_VERIFIER_PROFILE,
            source_review=_source_review(),
            revocation_check=_revocation_check(),
            cloudformation_template_digests=_template_digests(),
            now=NOW,
        )
    with pytest.raises(
        PlanPermissionRepairSignedArtifactError,
        match="SOURCE_REVIEW_EVIDENCE_DRIFT",
    ):
        _build_signed_artifact_receipt_from_trusted_readbacks(
            unsigned_manifest=unsigned.manifest,
            downloaded_unsigned_archive=unsigned.archive,
            downloaded_signed_archive=signed,
            signing_job=_job(),
            signed_object_head=_head(signed),
            expected_profile_version_arn=PROFILE_ARN,
            verifier_identity=_verifier(),
            verifier_profile=EXPECTED_VERIFIER_PROFILE,
            source_review=_source_review("4" * 40),
            revocation_check=_revocation_check(),
            cloudformation_template_digests=_template_digests(),
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
    commands: tuple[tuple[str, ...], ...] = (
        ("init", "-q"),
        ("config", "user.email", "synthetic@example.invalid"),
        ("config", "user.name", "Synthetic Test"),
        ("add", "--", *[path.as_posix() for path in tracked_paths]),
        ("commit", "-q", "-m", "synthetic reviewed source"),
    )
    for command in commands:
        subprocess.run(
            ["git", *command],
            cwd=source,
            check=True,
            timeout=30,
        )
    commit = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=source,
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    ).stdout.strip()
    return source, commit


class _Body:
    def __init__(self, payload: bytes) -> None:
        self.payload = payload
        self.closed = False

    def read(self, amount: int) -> bytes:
        assert amount == len(self.payload) + 1
        return self.payload

    def close(self) -> None:
        self.closed = True


class _Sts:
    def __init__(self, events: list[str] | None = None) -> None:
        self.events = events

    def get_caller_identity(self) -> dict:
        if self.events is not None:
            self.events.append("sts:GetCallerIdentity")
        return _verifier()


class _WrongSts(_Sts):
    def get_caller_identity(self) -> dict:
        if self.events is not None:
            self.events.append("sts:GetCallerIdentity")
        return {
            "Account": "839393571433",
            "Arn": (
                "arn:aws:sts::839393571433:assumed-role/"
                "AWSReservedSSO_AWSReadOnlyAccess_1111111111111111/"
                "synthetic@example.invalid"
            ),
        }


class _Signer:
    def __init__(self, events: list[str] | None = None) -> None:
        self.events = events

    def describe_signing_job(self, **kwargs) -> dict:
        if self.events is not None:
            self.events.append("signer:DescribeSigningJob")
        assert kwargs == {"jobId": JOB_ID}
        return _job()


class _Acm:
    def __init__(self, events: list[str] | None = None) -> None:
        self.events = events

    def get_certificate(self, **kwargs) -> dict:
        if self.events is not None:
            self.events.append("acm:GetCertificate")
        assert kwargs == {"CertificateArn": CERTIFICATE_ARN}
        child_pem, root_pem, _ = _certificate_material()
        return {
            "Certificate": child_pem,
            "CertificateChain": root_pem,
        }


class _SignerData:
    def __init__(
        self,
        events: list[str] | None = None,
        revoked_entities: list[str] | None = None,
        omit_revoked_entities: bool = False,
        expected_signature_timestamp: datetime = NOW,
    ) -> None:
        self.events = events
        self.revoked_entities = revoked_entities or []
        self.omit_revoked_entities = omit_revoked_entities
        self.expected_signature_timestamp = expected_signature_timestamp

    def get_revocation_status(self, **kwargs) -> dict:
        if self.events is not None:
            self.events.append("signer-data:GetRevocationStatus")
        assert kwargs == {
            "signatureTimestamp": self.expected_signature_timestamp,
            "platformId": "AWSLambda-SHA384-ECDSA",
            "profileVersionArn": PROFILE_ARN,
            "jobArn": JOB_ARN,
            "certificateHashes": [_certificate_material()[2]],
        }
        if self.omit_revoked_entities:
            return {}
        return {"revokedEntities": list(self.revoked_entities)}


def test_revocation_readback_accepts_omitted_empty_list_and_fractional_time(
) -> None:
    completed_at = NOW.replace(microsecond=123456)
    result = _verify_revocation_status(
        signing_job=_job(completed_at=completed_at),
        profile_version_arn=PROFILE_ARN,
        acm_client=_Acm(),
        signer_data_client=_SignerData(
            omit_revoked_entities=True,
            expected_signature_timestamp=completed_at,
        ),
        checked_at=completed_at,
    )
    assert result["checked_at"] == "2026-08-30T00:00:00.123456Z"


def test_fractional_receipt_times_are_preserved_and_validated() -> None:
    evaluated = NOW.replace(microsecond=654321)
    completed_at = NOW.replace(microsecond=123456)
    unsigned = _unsigned()
    signed = _signed(unsigned.archive)
    receipt = _build_signed_artifact_receipt_from_trusted_readbacks(
        unsigned_manifest=unsigned.manifest,
        downloaded_unsigned_archive=unsigned.archive,
        downloaded_signed_archive=signed,
        signing_job=_job(completed_at=completed_at),
        signed_object_head=_head(signed),
        expected_profile_version_arn=PROFILE_ARN,
        verifier_identity=_verifier(),
        verifier_profile=EXPECTED_VERIFIER_PROFILE,
        source_review=_source_review(),
        revocation_check=_revocation_check(evaluated),
        cloudformation_template_digests=_template_digests(),
        now=evaluated,
    )
    assert receipt["evaluated_at"] == "2026-08-30T00:00:00.654321Z"
    assert receipt["signing_job"]["signature_timestamp"] == (
        "2026-08-30T00:00:00.123456Z"
    )
    validate_signed_artifact_receipt(receipt, now=evaluated)


class _S3:
    def __init__(
        self,
        *,
        unsigned: bytes,
        signed: bytes,
        events: list[str] | None = None,
        include_sha256: bool = True,
    ) -> None:
        self.events = events
        self.include_sha256 = include_sha256
        self.objects = {
            (SOURCE_KEY, "UnsignedVersion1"): unsigned,
            (SIGNED_KEY, "SignedVersion1"): signed,
        }

    def get_bucket_versioning(self, **kwargs) -> dict:
        if self.events is not None:
            self.events.append("s3:GetBucketVersioning")
        assert kwargs == {
            "Bucket": BUCKET,
            "ExpectedBucketOwner": "042360977644",
        }
        return {"Status": "Enabled"}

    def list_object_versions(self, **kwargs) -> dict:
        if self.events is not None:
            self.events.append("s3:ListObjectVersions")
        assert kwargs == {
            "Bucket": BUCKET,
            "Prefix": SIGNED_KEY,
            "ExpectedBucketOwner": "042360977644",
        }
        return {
            "IsTruncated": False,
            "Versions": [
                {
                    "Key": SIGNED_KEY,
                    "VersionId": "SignedVersion1",
                    "IsLatest": True,
                }
            ],
            "DeleteMarkers": [],
        }

    def head_object(self, **kwargs) -> dict:
        if self.events is not None:
            self.events.append(f"s3:HeadObject:{kwargs['VersionId']}")
        payload = self.objects[(kwargs["Key"], kwargs["VersionId"])]
        response = {
            "VersionId": kwargs["VersionId"],
            "ContentLength": len(payload),
        }
        if self.include_sha256:
            response["ChecksumSHA256"] = base64.b64encode(
                sha256(payload).digest()
            ).decode("ascii")
        return response

    def get_object(self, **kwargs) -> dict:
        if self.events is not None:
            self.events.append(f"s3:GetObject:{kwargs['VersionId']}")
        payload = self.objects[(kwargs["Key"], kwargs["VersionId"])]
        response = {
            "VersionId": kwargs["VersionId"],
            "ContentLength": len(payload),
            "Body": _Body(payload),
        }
        if self.include_sha256:
            response["ChecksumSHA256"] = base64.b64encode(
                sha256(payload).digest()
            ).decode("ascii")
        return response


def test_read_only_aws_adapter_rebuilds_git_object_bytes_before_binding(
    tmp_path: Path,
) -> None:
    source, commit = _committed_source(tmp_path)
    committed = verify_clean_source_commit(
        source_root=source,
        source_commit=commit,
    )
    unsigned = _unsigned(
        source_root=source,
        source_commit=commit,
        committed_sources=committed,
    )
    signed = _signed(unsigned.archive)
    events: list[str] = []
    receipt = build_signed_artifact_receipt_from_aws(
        source_root=source,
        source_commit=commit,
        expected_boto3_version=EXPECTED_BOTO3_VERSION,
        expected_botocore_version=EXPECTED_BOTOCORE_VERSION,
        profile_name=EXPECTED_VERIFIER_PROFILE,
        job_id=JOB_ID,
        expected_profile_version_arn=PROFILE_ARN,
        sts_client=_Sts(events),
        signer_client=_Signer(events),
        signer_data_client=_SignerData(events),
        acm_client=_Acm(events),
        s3_client=_S3(
            unsigned=unsigned.archive,
            signed=signed,
            events=events,
            include_sha256=False,
        ),
        now=NOW,
        source_review_verifier=lambda **_: _source_review(commit),
    )
    assert receipt["source_commit"] == commit
    assert receipt["unsigned_archive_sha256"] == sha256(
        unsigned.archive
    ).hexdigest()
    assert receipt["signed_artifact"]["archive_sha256"] == sha256(
        signed
    ).hexdigest()
    assert receipt["signed_artifact"]["checksum_provenance"] == (
        "LOCAL_SHA256_OF_EXACT_S3_VERSION"
    )
    assert receipt["unsigned_archive_sha256"] == sha256(
        unsigned.archive
    ).hexdigest()
    assert receipt["signing_job"]["source"]["version"] == (
        "UnsignedVersion1"
    )
    assert receipt["signed_artifact"]["version"] == "SignedVersion1"
    assert receipt["revocation_check"]["status"] == (
        "PROFILE_JOB_AND_CERTIFICATE_NOT_REVOKED"
    )
    assert receipt["cloudformation_templates"] == [
        {"path": path, "sha256": digest}
        for path, digest in _template_digests(source).items()
    ]
    assert events == [
        "sts:GetCallerIdentity",
        "signer:DescribeSigningJob",
        "s3:GetBucketVersioning",
        "s3:HeadObject:UnsignedVersion1",
        "s3:GetObject:UnsignedVersion1",
        "s3:ListObjectVersions",
        "s3:HeadObject:SignedVersion1",
        "s3:GetObject:SignedVersion1",
        "acm:GetCertificate",
        "signer-data:GetRevocationStatus",
    ]
    serialized = json.dumps(receipt, sort_keys=True)
    for forbidden in (
        "ResponseMetadata",
        "AccessKeyId",
        "SecretAccessKey",
        "SessionToken",
        "Credentials",
        "jobInvoker",
        "revocationRecord",
        CERTIFICATE_ARN,
        _certificate_material()[2],
    ):
        assert forbidden not in serialized


@pytest.mark.parametrize(
    "revoked_entity",
    ("SIGNING_PROFILE", "SIGNING_JOB", "CERTIFICATE"),
)
def test_read_only_aws_adapter_rejects_every_revoked_entity(
    tmp_path: Path,
    revoked_entity: str,
) -> None:
    source, commit = _committed_source(tmp_path)
    committed = verify_clean_source_commit(
        source_root=source,
        source_commit=commit,
    )
    unsigned = _unsigned(
        source_root=source,
        source_commit=commit,
        committed_sources=committed,
    )
    signed = _signed(unsigned.archive)
    events: list[str] = []
    with pytest.raises(
        PlanPermissionRepairSignedArtifactError,
        match="SIGNED_ARTIFACT_REVOKED",
    ):
        build_signed_artifact_receipt_from_aws(
            source_root=source,
            source_commit=commit,
            expected_boto3_version=EXPECTED_BOTO3_VERSION,
            expected_botocore_version=EXPECTED_BOTOCORE_VERSION,
            profile_name=EXPECTED_VERIFIER_PROFILE,
            job_id=JOB_ID,
            expected_profile_version_arn=PROFILE_ARN,
            sts_client=_Sts(events),
            signer_client=_Signer(events),
            signer_data_client=_SignerData(
                events,
                revoked_entities=[revoked_entity],
            ),
            acm_client=_Acm(events),
            s3_client=_S3(
                unsigned=unsigned.archive,
                signed=signed,
                events=events,
            ),
            now=NOW,
            source_review_verifier=lambda **_: _source_review(commit),
        )
    assert events[0] == "sts:GetCallerIdentity"
    assert events[-2:] == [
        "acm:GetCertificate",
        "signer-data:GetRevocationStatus",
    ]


def test_read_only_aws_adapter_rejects_profile_and_identity_before_signer() -> None:
    events: list[str] = []
    common = {
        "source_root": ROOT,
        "source_commit": SOURCE_COMMIT,
        "expected_boto3_version": EXPECTED_BOTO3_VERSION,
        "expected_botocore_version": EXPECTED_BOTOCORE_VERSION,
        "job_id": JOB_ID,
        "expected_profile_version_arn": PROFILE_ARN,
        "signer_client": _Signer(events),
        "signer_data_client": _SignerData(events),
        "acm_client": _Acm(events),
        "s3_client": _S3(unsigned=b"x", signed=b"y", events=events),
        "now": NOW,
        "source_review_verifier": lambda **_: _source_review(),
    }
    with pytest.raises(
        PlanPermissionRepairSignedArtifactError,
        match="VERIFIER_PROFILE_INVALID",
    ):
        build_signed_artifact_receipt_from_aws(
            profile_name="default",
            sts_client=_Sts(events),
            **common,
        )
    assert events == []

    with pytest.raises(
        PlanPermissionRepairSignedArtifactError,
        match="VERIFIER_IDENTITY_INVALID",
    ):
        build_signed_artifact_receipt_from_aws(
            profile_name=EXPECTED_VERIFIER_PROFILE,
            sts_client=_WrongSts(events),
            **common,
        )
    assert events == ["sts:GetCallerIdentity"]


def test_signed_artifact_cli_is_offline_on_help_and_code_has_no_mutation_calls(
    tmp_path: Path,
) -> None:
    script = (
        ROOT
        / "scripts/deployment/"
        "platform-authority-plan-permission-repair-signed-artifact.py"
    )
    result = subprocess.run(
        [sys.executable, "-I", str(script), "--help"],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=30,
        env={"PATH": str(Path(sys.executable).parent)},
    )
    assert result.returncode == 0, result.stderr
    assert EXPECTED_VERIFIER_PROFILE in result.stdout
    source = (
        ROOT
        / "tooling/"
        "platform_authority_plan_permission_repair_signed_artifact.py"
    ).read_text(encoding="utf-8")
    for forbidden in (
        ".put_object(",
        ".delete_object(",
        ".start_signing_job(",
        ".cancel_signing_profile(",
        ".put_signing_profile(",
    ):
        assert forbidden not in source


def test_only_aws_adapter_is_public_trusted_readback_constructor() -> None:
    assert "build_signed_artifact_receipt" not in signed_module.__dict__
    assert (
        "_build_signed_artifact_receipt_from_trusted_readbacks"
        not in signed_module.__all__
    )
    assert "build_signed_artifact_receipt_from_aws" in signed_module.__all__


def test_cli_sanitizes_session_setup_failure(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    script = (
        ROOT
        / "scripts/deployment/"
        "platform-authority-plan-permission-repair-signed-artifact.py"
    )
    spec = importlib.util.spec_from_file_location(
        "gug376_signed_artifact_cli_test", script
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    boto3_module = ModuleType("boto3")

    def fail_session(**_kwargs):
        raise RuntimeError("secret-local-profile-path")

    boto3_module.Session = fail_session  # type: ignore[attr-defined]
    botocore_module = ModuleType("botocore")
    config_module = ModuleType("botocore.config")
    config_module.Config = lambda **_kwargs: object()  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "boto3", boto3_module)
    monkeypatch.setitem(sys.modules, "botocore", botocore_module)
    monkeypatch.setitem(sys.modules, "botocore.config", config_module)
    monkeypatch.setattr(
        module,
        "parse_args",
        lambda: SimpleNamespace(
            profile=EXPECTED_VERIFIER_PROFILE,
            region="us-east-1",
            source_commit=SOURCE_COMMIT,
            expected_boto3_version=EXPECTED_BOTO3_VERSION,
            expected_botocore_version=EXPECTED_BOTOCORE_VERSION,
            job_id=JOB_ID,
            expected_profile_version_arn=PROFILE_ARN,
            output_receipt=Path("private-receipt.json"),
        ),
    )

    assert module.main() == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == (
        "GUG376_SIGNED_ARTIFACT_BLOCKED:AWS_CLIENT_SETUP_FAILED\n"
    )
    assert "secret-local-profile-path" not in captured.err
