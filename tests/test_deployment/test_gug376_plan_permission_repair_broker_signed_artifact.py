from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone
from functools import lru_cache
from hashlib import sha256
import importlib.util
from io import BytesIO
import json
from pathlib import Path
import stat
import subprocess
import sys
from types import SimpleNamespace
from typing import Any
from zipfile import ZIP_DEFLATED, ZipFile

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from tooling import platform_authority_plan_permission_repair_broker_seed as seed
from tooling import (
    platform_authority_plan_permission_repair_artifact_bootstrap as artifact_bootstrap,
)
from tooling import (
    platform_authority_plan_permission_repair_broker_signed_artifact as signed,
)
from tooling import (
    platform_authority_plan_permission_repair_template_readback as readback,
)


REPO_ROOT = Path(__file__).resolve().parents[2]
CLI = (
    REPO_ROOT
    / "scripts/deployment/"
    "platform-authority-plan-permission-repair-broker-signed-artifact.py"
)
PROFILE_ARN = (
    "arn:aws:signer:us-east-1:042360977644:/signing-profiles/"
    "ScanalyzeGug376/ABCDEFGHIJ"
)
JOB_ID = "12345678-1234-1234-1234-1234567890ab"
CALLER_ARN = (
    "arn:aws:sts::042360977644:assumed-role/"
    "AWSReservedSSO_AWSReadOnlyAccess_0123456789ABCDEF/cesar"
)
OPERATIONAL_CALLER_ARN = (
    "arn:aws:sts::042360977644:assumed-role/"
    "AWSReservedSSO_ScanalyzeGug376ArtifactBootstrap_"
    "0123456789ABCDEF/cesar"
)
OBSERVED = datetime(2026, 8, 30, 18, 45, tzinfo=timezone.utc)
BUCKET = "scanalyze-gug376-artifacts"
KMS_KEY_ARN = (
    "arn:aws:kms:us-east-1:042360977644:key/"
    "00000000-0000-4000-8000-000000000001"
)
CERTIFICATE_ARN = (
    "arn:aws:acm:us-east-1:042360977644:certificate/"
    "00000000-0000-4000-8000-000000000002"
)


def _digest(character: str) -> str:
    return "sha256:" + character * 64


def _upstream_plans() -> tuple[dict[str, Any], dict[str, Any]]:
    location = {
        "bucket": BUCKET,
        "sse_algorithm": "aws:kms",
        "sse_kms_key_arn": KMS_KEY_ARN,
    }
    gug363 = {
        "record_type": "scanalyze.platform_authority.retirement_entrypoint_plan.v1",
        "target": {
            "authority_account_id": signed.EXPECTED_ACCOUNT_ID,
            "region": signed.EXPECTED_REGION,
        },
        "production": False,
        "deployment_authorized": False,
        "plan_digest": _digest("1"),
        "artifact_signing_contract_digest": _digest("2"),
        "gug363_pre_function_binding_sha256": _digest("3"),
        "artifact_signing_contract": {
            "unsigned_source": dict(location),
            "signed_destination": dict(location),
        },
    }
    gug365 = {
        "record_type": (
            "scanalyze.platform_authority."
            "retirement_entrypoint_service_role_plan.v1"
        ),
        "implementation_issue": "GUG-365",
        "source_issue": "GUG-363",
        "production": False,
        "deployment_authorized": False,
        "aws_calls_performed": False,
        "plan_digest": _digest("4"),
        "gug363_pre_function_binding_sha256": _digest("3"),
        "gug363_artifact_signing_contract_digest": _digest("2"),
        "ledger_factory_artifact_signing_contract_digest": _digest("5"),
        "ledger_factory_artifact_signing_contract": {
            "unsigned_source": dict(location),
            "signed_destination": dict(location),
        },
        "signed_artifact_binding": {**location, "binding_digest": _digest("6")},
    }
    return gug363, gug365


def _storage_binding(
    root: Path,
    gug363_plan: dict[str, Any],
    gug365_plan: dict[str, Any],
) -> dict[str, Any]:
    return readback.derive_upstream_storage_binding(
        gug363_plan=gug363_plan,
        gug365_plan=gug365_plan,
        source_root=root,
        gug363_validator=lambda *_args, **_kwargs: None,
        gug365_validator=lambda *_args, **_kwargs: None,
    )


def _foundation_causality(commit: str) -> tuple[dict[str, Any], dict[str, Any]]:
    bootstrap = {
        "access_not_before": "2026-08-30T18:30:00Z",
        "access_not_after": "2026-08-30T19:30:00Z",
    }
    binding: dict[str, Any] = {
        "schema_version": 1,
        "record_type": signed.FOUNDATION_STORAGE_BINDING_TYPE,
        "source_commit": commit,
        "bootstrap_intent_digest": _digest("1"),
        "foundation_readback_digest": _digest("2"),
        "reviewed_sources_digest": _digest("3"),
        "access_update_intent_digest": _digest("4"),
        "access_readback_digest": _digest("5"),
        "route_template_receipt_digest": _digest("6"),
        "delegation_template_receipt_digest": _digest("7"),
        "route_template_sha256": _digest("8"),
        "delegation_template_sha256": _digest("9"),
        "route_template_version_digest": _digest("a"),
        "delegation_template_version_digest": _digest("b"),
        "access_not_after": bootstrap["access_not_after"],
        "bucket": BUCKET,
        "sse_algorithm": "aws:kms",
        "sse_kms_key_arn": KMS_KEY_ARN,
        "signing_profile_version_arn": PROFILE_ARN,
        "code_signing_config_arn": (
            "arn:aws:lambda:us-east-1:042360977644:"
            "code-signing-config:csc-12345678901234567"
        ),
        "foundation_readback": {},
        "reviewed_sources": {},
        "access_update": {},
        "access_readback": {},
        "route_template_receipt": {},
        "delegation_template_receipt": {},
        "source_marker": "VALIDATED_GUG376_FOUNDATION_PUBLISH_AUTHORITY",
        "aws_calls": 0,
        "aws_mutations": 0,
        "production_authorized": False,
        "production_status": "NO-GO",
    }
    binding["binding_digest"] = seed.digest_value(binding)
    return bootstrap, binding


def _pep_receipt(
    commit: str, storage_binding: dict[str, Any]
) -> dict[str, Any]:
    receipt = {
        "source_commit": commit,
        "expected_sdk_versions": {"boto3": "1.42.57", "botocore": "1.42.97"},
        "signed_artifact": {
            "bucket": storage_binding["bucket"],
            "sse_algorithm": storage_binding["sse_algorithm"],
            "sse_kms_key_arn": storage_binding["sse_kms_key_arn"],
            "lambda_code_sha256": "A" * 43 + "=",
        },
        "signing_job": {
            "profile_version_arn": PROFILE_ARN,
            "source": {
                "bucket": storage_binding["bucket"],
                "sse_algorithm": storage_binding["sse_algorithm"],
                "sse_kms_key_arn": storage_binding["sse_kms_key_arn"],
            },
        },
        "upstream_storage_binding": dict(storage_binding),
    }
    receipt["receipt_digest"] = seed.digest_value(receipt)
    return receipt


@lru_cache(maxsize=1)
def _certificate_material() -> tuple[str, str, str]:
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test CA")])
    ca = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(1)
        .not_valid_before(OBSERVED - timedelta(days=1))
        .not_valid_after(OBSERVED + timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), True)
        .sign(ca_key, hashes.SHA256())
    )
    child_key = ec.generate_private_key(ec.SECP256R1())
    child = (
        x509.CertificateBuilder()
        .subject_name(
            x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Signer")])
        )
        .issuer_name(ca.subject)
        .public_key(child_key.public_key())
        .serial_number(2)
        .not_valid_before(OBSERVED - timedelta(days=1))
        .not_valid_after(OBSERVED + timedelta(days=7))
        .sign(ca_key, hashes.SHA256())
    )
    child_pem = child.public_bytes(serialization.Encoding.PEM).decode("ascii")
    ca_pem = ca.public_bytes(serialization.Encoding.PEM).decode("ascii")
    return (
        child_pem,
        ca_pem,
        signed._certificate_revocation_hash(  # noqa: SLF001
            certificate_pem=child_pem,
            certificate_chain_pem=ca_pem,
        ),
    )


class _Meta:
    def __init__(self, service: str) -> None:
        host = {
            "sts": "sts.us-east-1.amazonaws.com",
            "s3": "s3.us-east-1.amazonaws.com",
            "signer": "signer.us-east-1.amazonaws.com",
            "acm": "acm.us-east-1.amazonaws.com",
            "signer-data": "data-signer.us-east-1.amazonaws.com",
        }[service]
        self.endpoint_url = f"https://{host}"


def _git(root: Path, *args: str) -> str:
    completed = subprocess.run(
        ["git", *args],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
        shell=False,
    )
    return completed.stdout.strip()


@pytest.fixture
def source_repo(tmp_path: Path) -> tuple[Path, str, bytes]:
    root = tmp_path / "source"
    root.mkdir()
    for relative in seed.PACKAGE_SOURCE_PATHS:
        destination = root / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes((REPO_ROOT / relative).read_bytes())
    _git(root, "init", "-b", "main")
    _git(root, "config", "user.name", "GUG-376 test")
    _git(root, "config", "user.email", "gug376@example.invalid")
    _git(root, "add", "--", *(item.as_posix() for item in seed.PACKAGE_SOURCE_PATHS))
    _git(root, "commit", "-m", "fixture: broker signed artifact")
    commit = _git(root, "rev-parse", "HEAD")
    return root, commit, seed.build_broker_package(
        source_root=root,
        source_commit=commit,
    )


class _Body:
    def __init__(self, value: bytes, *, chunk_size: int | None = None) -> None:
        self.value = value
        self.offset = 0
        self.chunk_size = chunk_size
        self.closed = False

    def read(self, limit: int) -> bytes:
        if self.offset >= len(self.value):
            return b""
        count = min(limit, self.chunk_size or limit)
        chunk = self.value[self.offset : self.offset + count]
        self.offset += len(chunk)
        return chunk

    def close(self) -> None:
        self.closed = True


class _Sts:
    def __init__(self, owner: "_Session") -> None:
        self.owner = owner
        self.meta = _Meta("sts")

    def get_caller_identity(self) -> dict[str, Any]:
        self.owner.calls.append("sts:get_caller_identity")
        return {
            "Account": self.owner.account,
            "Arn": self.owner.caller_arn,
            "UserId": "synthetic",
        }


class _S3:
    def __init__(self, owner: "_Session") -> None:
        self.owner = owner
        self.meta = _Meta("s3")

    def _payload(self, key: str) -> bytes:
        return (
            self.owner.unsigned_payload
            if "/unsigned/" in key
            else self.owner.signed_payload
        )

    def get_bucket_versioning(self, **_kwargs: Any) -> dict[str, str]:
        self.owner.calls.append("s3:get_bucket_versioning")
        return {"Status": "Enabled" if self.owner.versioning_enabled else "Suspended"}

    def head_object(self, **kwargs: Any) -> dict[str, Any]:
        self.owner.calls.append("s3:head_object")
        payload = self._payload(kwargs["Key"])
        checksum = base64.b64encode(sha256(payload).digest()).decode("ascii")
        if self.owner.bad_checksum:
            checksum = "A" * 43 + "="
        result = {
            "VersionId": kwargs["VersionId"],
            "ContentLength": len(payload),
            "ChecksumSHA256": checksum,
            "ChecksumType": self.owner.checksum_type,
            "ServerSideEncryption": self.owner.sse_algorithm,
            "SSEKMSKeyId": self.owner.kms_key_arn,
        }
        if self.owner.missing_sha256_checksum:
            result.pop("ChecksumSHA256")
        return result

    def get_object(self, **kwargs: Any) -> dict[str, Any]:
        self.owner.calls.append("s3:get_object")
        payload = self._payload(kwargs["Key"])
        result = {
            "VersionId": kwargs["VersionId"],
            "ContentLength": len(payload),
            "ChecksumSHA256": base64.b64encode(sha256(payload).digest()).decode(
                "ascii"
            ),
            "ChecksumType": self.owner.get_checksum_type,
            "ServerSideEncryption": self.owner.get_sse_algorithm,
            "SSEKMSKeyId": self.owner.get_kms_key_arn,
            "Body": _Body(payload, chunk_size=self.owner.body_chunk_size),
        }
        if self.owner.missing_sha256_checksum:
            result.pop("ChecksumSHA256")
        return result

    def list_object_versions(self, **kwargs: Any) -> dict[str, Any]:
        self.owner.calls.append("s3:list_object_versions")
        versions = [
            {
                "Key": kwargs["Prefix"],
                "VersionId": "signed-version-1",
                "IsLatest": self.owner.signed_version_latest,
            }
        ]
        if self.owner.duplicate_signed_version:
            versions.append(
                {
                    "Key": kwargs["Prefix"],
                    "VersionId": "signed-version-0",
                    "IsLatest": False,
                }
            )
        response: dict[str, Any] = {
            "IsTruncated": False,
            "Versions": versions,
            "DeleteMarkers": [],
        }
        if self.owner.version_next_key_marker is not None:
            response["NextKeyMarker"] = self.owner.version_next_key_marker
        if self.owner.version_next_id_marker is not None:
            response["NextVersionIdMarker"] = (
                self.owner.version_next_id_marker
            )
        if self.owner.malformed_version_item:
            response["Versions"].append("malformed")
        return response


class _Signer:
    def __init__(self, owner: "_Session") -> None:
        self.owner = owner
        self.meta = _Meta("signer")

    def describe_signing_job(self, **_kwargs: Any) -> dict[str, Any]:
        self.owner.calls.append("signer:describe_signing_job")
        value: dict[str, Any] = {
            "jobId": JOB_ID,
            "status": self.owner.job_status,
            "platformId": signed.SIGNING_PLATFORM_ID,
            "jobOwner": signed.EXPECTED_ACCOUNT_ID,
            "jobInvoker": signed.EXPECTED_ACCOUNT_ID,
            "profileName": "ScanalyzeGug376",
            "profileVersion": "ABCDEFGHIJ",
            "signingMaterial": {"certificateArn": CERTIFICATE_ARN},
            "createdAt": datetime(2026, 8, 30, 18, 35, tzinfo=timezone.utc),
            "completedAt": datetime(2026, 8, 30, 18, 40, tzinfo=timezone.utc),
            "signatureExpiresAt": datetime(
                2026, 9, 6, 18, 40, tzinfo=timezone.utc
            ),
            "source": {
                "s3": {
                    "bucketName": BUCKET,
                    "key": self.owner.unsigned_key,
                    "version": "unsigned-version-1",
                }
            },
            "signedObject": {
                "s3": {
                    "bucketName": BUCKET,
                    "key": self.owner.signed_key,
                }
            },
        }
        if self.owner.job_revoked:
            value["revocationRecord"] = {"reason": "synthetic"}
        elif self.owner.null_revocation_record:
            value["revocationRecord"] = None
        return value

    def get_signing_profile(self, **_kwargs: Any) -> dict[str, Any]:
        self.owner.calls.append("signer:get_signing_profile")
        value: dict[str, Any] = {
            "profileVersionArn": PROFILE_ARN,
            "profileVersion": "ABCDEFGHIJ",
            "status": "Active",
            "platformId": signed.SIGNING_PLATFORM_ID,
        }
        if self.owner.profile_revoked:
            value["revocationRecord"] = {"reason": "synthetic"}
        elif self.owner.null_revocation_record:
            value["revocationRecord"] = None
        return value


class _Acm:
    def __init__(self, owner: "_Session") -> None:
        self.owner = owner
        self.meta = _Meta("acm")

    def get_certificate(self, **kwargs: Any) -> dict[str, str]:
        self.owner.calls.append("acm:get_certificate")
        assert kwargs == {"CertificateArn": CERTIFICATE_ARN}
        child, chain, _certificate_hash = _certificate_material()
        return {"Certificate": child, "CertificateChain": chain}


class _SignerData:
    def __init__(self, owner: "_Session") -> None:
        self.owner = owner
        self.meta = _Meta("signer-data")

    def get_revocation_status(self, **kwargs: Any) -> dict[str, Any]:
        self.owner.calls.append("signer-data:get_revocation_status")
        self.owner.revocation_request = dict(kwargs)
        return {"revokedEntities": list(self.owner.revoked_entities)}


class _Session:
    def __init__(
        self,
        *,
        commit: str,
        unsigned_payload: bytes,
        operational: bool = False,
    ) -> None:
        self.calls: list[str] = []
        self.configs: list[Any] = []
        self.profile_name = (
            signed.EXPECTED_PROFILE
            if operational
            else signed.LEGACY_EXPECTED_PROFILE
        )
        self.region_name = signed.EXPECTED_REGION
        self._session = SimpleNamespace(
            full_config={
                "profiles": {
                    self.profile_name: {
                        "region": signed.EXPECTED_REGION,
                        "sso_account_id": signed.EXPECTED_ACCOUNT_ID,
                        "sso_role_name": (
                            signed.EXPECTED_SSO_ROLE
                            if operational
                            else signed.LEGACY_EXPECTED_SSO_ROLE
                        ),
                        "sso_session": "scanalyze-test",
                    }
                },
                "sso_sessions": {
                    "scanalyze-test": {
                        "sso_start_url": "https://example.awsapps.com/start",
                        "sso_region": signed.EXPECTED_REGION,
                    }
                },
            }
        )
        self.credential_method = "sso"
        self.account = signed.EXPECTED_ACCOUNT_ID
        self.caller_arn = (
            OPERATIONAL_CALLER_ARN if operational else CALLER_ARN
        )
        self.unsigned_payload = unsigned_payload
        signed_buffer = BytesIO(unsigned_payload)
        with ZipFile(signed_buffer, mode="a") as archive:
            archive.comment = b"AWS Signer synthetic signature metadata"
        self.signed_payload = signed_buffer.getvalue()
        self.unsigned_key = (
            "scanalyze/platform-authority/gug-376/plan-policy-repair/"
            f"broker/unsigned/{commit}/route-broker-unsigned.zip"
        )
        self.signed_key = (
            "scanalyze/platform-authority/gug-376/plan-policy-repair/"
            f"broker/signed/{commit}/{JOB_ID}.zip"
        )
        self.bad_checksum = False
        self.missing_sha256_checksum = False
        self.checksum_type: str | None = "FULL_OBJECT"
        self.sse_algorithm = "aws:kms"
        self.kms_key_arn = KMS_KEY_ARN
        self.get_checksum_type: str | None = "FULL_OBJECT"
        self.get_sse_algorithm = "aws:kms"
        self.get_kms_key_arn = KMS_KEY_ARN
        self.body_chunk_size: int | None = None
        self.versioning_enabled = True
        self.duplicate_signed_version = False
        self.signed_version_latest = True
        self.version_next_key_marker: object | None = None
        self.version_next_id_marker: object | None = None
        self.malformed_version_item = False
        self.job_status = "Succeeded"
        self.job_revoked = False
        self.profile_revoked = False
        self.null_revocation_record = False
        self.bad_endpoint = False
        self.revoked_entities: list[str] = []
        self.revocation_request: dict[str, Any] | None = None

    def get_credentials(self) -> Any:
        return SimpleNamespace(method=self.credential_method)

    def client(self, name: str, **kwargs: Any) -> Any:
        self.calls.append("client:" + name)
        self.configs.append(kwargs.get("config"))
        client = {
            "sts": _Sts(self),
            "s3": _S3(self),
            "signer": _Signer(self),
            "acm": _Acm(self),
            "signer-data": _SignerData(self),
        }[name]
        if self.bad_endpoint:
            client.meta.endpoint_url = "http://127.0.0.1:4566"
        return client


def _attest(
    root: Path,
    commit: str,
    session: _Session,
    *,
    environment: dict[str, str] | None = None,
    pep_receipt: dict[str, Any] | None = None,
) -> dict[str, Any]:
    sentinel_config = object()
    gug363_plan, gug365_plan = _upstream_plans()
    storage_binding = _storage_binding(root, gug363_plan, gug365_plan)
    receipt = pep_receipt or _pep_receipt(commit, storage_binding)
    return signed.attest_broker_signed_artifact(
        source_root=root,
        source_commit=commit,
        aws_profile=signed.LEGACY_EXPECTED_PROFILE,
        expected_account_id=signed.EXPECTED_ACCOUNT_ID,
        region=signed.EXPECTED_REGION,
        unsigned_bucket=BUCKET,
        unsigned_key=session.unsigned_key,
        unsigned_version="unsigned-version-1",
        signing_job_id=JOB_ID,
        signed_version="signed-version-1",
        pep_signed_artifact_receipt=receipt,
        gug363_plan=gug363_plan,
        gug365_plan=gug365_plan,
        upstream_source_root=root,
        session_factory=lambda _profile, _region: session,
        clock=lambda: OBSERVED,
        config_factory=lambda: sentinel_config,
        pep_receipt_validator=lambda _receipt, **_kwargs: None,
        gug363_validator=lambda *_args, **_kwargs: None,
        gug365_validator=lambda *_args, **_kwargs: None,
        allow_legacy_upstream_plans=True,
        environment={} if environment is None else environment,
    )


def test_read_only_handoff_binds_distinct_unsigned_and_signed_bytes(
    source_repo: tuple[Path, str, bytes], tmp_path: Path
) -> None:
    root, commit, package = source_repo
    session = _Session(commit=commit, unsigned_payload=package)
    handoff = _attest(root, commit, session)
    assert session.calls[:2] == ["client:sts", "sts:get_caller_identity"]
    assert len(session.configs) == 5
    assert all(item is session.configs[0] for item in session.configs)
    assert handoff["aws_calls"] == 11


    assert handoff["aws_mutations"] == 0
    receipt = handoff["broker_code"]
    assert receipt["unsigned_artifact"]["sha256"] != receipt["signed_artifact"][
        "sha256"
    ]
    assert receipt["unsigned_artifact"]["sha256"] == (
        "sha256:" + sha256(package).hexdigest()
    )
    assert receipt["unsigned_artifact"]["sse_kms_key_arn"] == KMS_KEY_ARN
    assert receipt["signed_artifact"]["sse_algorithm"] == "aws:kms"
    assert receipt["signing_job"]["certificate_arn"] == CERTIFICATE_ARN
    assert receipt["revocation_check"]["certificate_hash_digest"] == (
        seed.digest_value(_certificate_material()[2])
    )
    assert session.revocation_request == {
        "signatureTimestamp": datetime(
            2026, 8, 30, 18, 40, tzinfo=timezone.utc
        ),
        "platformId": signed.SIGNING_PLATFORM_ID,
        "profileVersionArn": PROFILE_ARN,
        "jobArn": (
            "arn:aws:signer:us-east-1:042360977644:/signing-jobs/" + JOB_ID
        ),
        "certificateHashes": [_certificate_material()[2]],
    }
    assert receipt["upstream_storage_binding"]["gug365_plan_digest"] == _digest(
        "4"
    )
    assert handoff["pep_runtime_binding"][
        "upstream_storage_binding_digest"
    ] == receipt["upstream_storage_binding"]["binding_digest"]
    seed.validate_broker_signing_receipt(
        receipt,
        source_commit=commit,
        now=OBSERVED,
        allow_legacy_upstream_storage_binding=True,
    )
    seed.validate_pep_runtime_binding(
        handoff["pep_runtime_binding"], source_commit=commit
    )
    private = tmp_path / "private"
    private.mkdir(mode=0o700)
    private.chmod(0o700)
    path = signed.write_private_handoff(
        private_root=private,
        output_name=signed.DEFAULT_OUTPUT_NAME,
        handoff=handoff,
    )
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert json.loads(path.read_text(encoding="utf-8"))["handoff_digest"] == (
        handoff["handoff_digest"]
    )
    with pytest.raises(signed.BrokerSignedArtifactError, match="PRIVATE_OUTPUT_EXISTS"):
        signed.write_private_handoff(
            private_root=private,
            output_name=signed.DEFAULT_OUTPUT_NAME,
            handoff=handoff,
        )


def test_foundation_publish_binding_is_the_explicit_production_causal_route(
    source_repo: tuple[Path, str, bytes],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root, commit, package = source_repo
    session = _Session(
        commit=commit, unsigned_payload=package, operational=True
    )
    bootstrap, binding = _foundation_causality(commit)
    pep_receipt = _pep_receipt(commit, binding)
    monkeypatch.setattr(
        signed,
        "validate_foundation_publish_binding",
        lambda value, *, bootstrap_intent: dict(value),
    )
    monkeypatch.setattr(
        artifact_bootstrap,
        "validate_foundation_publish_binding",
        lambda value, *, bootstrap_intent: dict(value),
    )
    handoff = signed.attest_broker_signed_artifact(
        source_root=root,
        source_commit=commit,
        aws_profile=signed.EXPECTED_PROFILE,
        expected_account_id=signed.EXPECTED_ACCOUNT_ID,
        region=signed.EXPECTED_REGION,
        unsigned_bucket=BUCKET,
        unsigned_key=session.unsigned_key,
        unsigned_version="unsigned-version-1",
        signing_job_id=JOB_ID,
        signed_version="signed-version-1",
        pep_signed_artifact_receipt=pep_receipt,
        bootstrap_intent=bootstrap,
        foundation_publish_binding=binding,
        session_factory=lambda _profile, _region: session,
        clock=lambda: OBSERVED,
        config_factory=object,
        pep_receipt_validator=lambda _receipt, **_kwargs: None,
        environment={},
    )
    assert handoff["broker_code"]["upstream_storage_binding"] == binding
    assert handoff["pep_runtime_binding"][
        "upstream_storage_binding_digest"
    ] == binding["binding_digest"]


def test_foundation_route_rejects_legacy_profile_before_session_creation(
    source_repo: tuple[Path, str, bytes],
) -> None:
    root, commit, package = source_repo
    session = _Session(
        commit=commit, unsigned_payload=package, operational=True
    )
    bootstrap, binding = _foundation_causality(commit)
    with pytest.raises(
        signed.BrokerSignedArtifactError,
        match="ATTESTATION_INPUT_INVALID",
    ):
        signed.attest_broker_signed_artifact(
            source_root=root,
            source_commit=commit,
            aws_profile=signed.LEGACY_EXPECTED_PROFILE,
            expected_account_id=signed.EXPECTED_ACCOUNT_ID,
            region=signed.EXPECTED_REGION,
            unsigned_bucket=BUCKET,
            unsigned_key=session.unsigned_key,
            unsigned_version="unsigned-version-1",
            signing_job_id=JOB_ID,
            signed_version="signed-version-1",
            pep_signed_artifact_receipt=_pep_receipt(commit, binding),
            bootstrap_intent=bootstrap,
            foundation_publish_binding=binding,
            session_factory=lambda _profile, _region: session,
            clock=lambda: OBSERVED,
            config_factory=object,
            pep_receipt_validator=lambda _receipt, **_kwargs: None,
            environment={},
        )
    assert session.calls == []


def test_legacy_plans_are_rejected_without_explicit_legacy_route(
    source_repo: tuple[Path, str, bytes],
) -> None:
    root, commit, package = source_repo
    session = _Session(commit=commit, unsigned_payload=package)
    gug363, gug365 = _upstream_plans()
    storage = _storage_binding(root, gug363, gug365)
    with pytest.raises(
        signed.BrokerSignedArtifactError,
        match="STORAGE_CAUSALITY_ROUTE_INVALID",
    ):
        signed.attest_broker_signed_artifact(
            source_root=root,
            source_commit=commit,
            aws_profile=signed.LEGACY_EXPECTED_PROFILE,
            expected_account_id=signed.EXPECTED_ACCOUNT_ID,
            region=signed.EXPECTED_REGION,
            unsigned_bucket=BUCKET,
            unsigned_key=session.unsigned_key,
            unsigned_version="unsigned-version-1",
            signing_job_id=JOB_ID,
            signed_version="signed-version-1",
            pep_signed_artifact_receipt=_pep_receipt(commit, storage),
            gug363_plan=gug363,
            gug365_plan=gug365,
            session_factory=lambda _profile, _region: session,
            clock=lambda: OBSERVED,
            config_factory=object,
            pep_receipt_validator=lambda _receipt, **_kwargs: None,
            environment={},
        )
    assert session.calls == []


def test_read_only_handoff_hashes_bytes_when_s3_sha256_is_absent(
    source_repo: tuple[Path, str, bytes],
) -> None:
    root, commit, package = source_repo
    session = _Session(commit=commit, unsigned_payload=package)
    session.missing_sha256_checksum = True
    session.checksum_type = None
    session.get_checksum_type = None
    handoff = _attest(root, commit, session)
    assert handoff["broker_code"]["signed_artifact"]["sha256"] == (
        "sha256:" + sha256(session.signed_payload).hexdigest()
    )


def test_read_only_handoff_reads_stream_to_eof_in_bounded_chunks(
    source_repo: tuple[Path, str, bytes],
) -> None:
    root, commit, package = source_repo
    session = _Session(commit=commit, unsigned_payload=package)
    session.body_chunk_size = 7
    assert _attest(root, commit, session)["broker_code"]["aws_calls"] == 11


def test_signed_zip_rejects_oversized_metadata_before_decompression() -> None:
    unsigned_buffer = BytesIO()
    with ZipFile(
        unsigned_buffer, mode="w", compression=ZIP_DEFLATED
    ) as archive:
        for index, relative in enumerate(seed.PACKAGE_SOURCE_PATHS):
            archive.writestr(
                relative.as_posix(),
                b"x" * (signed.MAX_PACKAGE_BYTES + 1)
                if index == 0
                else b"bounded",
            )
    signed_buffer = BytesIO(unsigned_buffer.getvalue())
    with ZipFile(signed_buffer, mode="a") as archive:
        archive.comment = b"synthetic signer metadata"
    with pytest.raises(
        signed.BrokerSignedArtifactError,
        match="SIGNED_PACKAGE_ENTRY_SIZE_INVALID",
    ):
        signed._verify_signed_package_semantics(  # noqa: SLF001
            unsigned_buffer.getvalue(), signed_buffer.getvalue()
        )


@pytest.mark.parametrize(
    ("mutate", "code"),
    [
        (lambda value: setattr(value, "account", "000000000000"), "AWS_IDENTITY_INVALID"),
        (
            lambda value: setattr(value, "versioning_enabled", False),
            "S3_BUCKET_VERSIONING_INVALID",
        ),
        (lambda value: setattr(value, "bad_checksum", True), "S3_OBJECT_CHECKSUM_MISMATCH"),
        (
            lambda value: setattr(value, "checksum_type", "COMPOSITE"),
            "S3_OBJECT_CHECKSUM_MISMATCH",
        ),
        (
            lambda value: setattr(value, "sse_algorithm", "AES256"),
            "S3_OBJECT_HEAD_INVALID",
        ),
        (
            lambda value: setattr(value, "get_sse_algorithm", "AES256"),
            "S3_OBJECT_BODY_INVALID",
        ),
        (
            lambda value: setattr(value, "get_checksum_type", "COMPOSITE"),
            "S3_OBJECT_CHECKSUM_MISMATCH",
        ),
        (
            lambda value: setattr(
                value,
                "kms_key_arn",
                "arn:aws:kms:us-east-1:042360977644:key/"
                "00000000-0000-4000-8000-000000000002",
            ),
            "S3_OBJECT_HEAD_INVALID",
        ),
        (lambda value: setattr(value, "job_status", "InProgress"), "SIGNING_JOB_INVALID"),
        (lambda value: setattr(value, "job_revoked", True), "SIGNING_JOB_INVALID"),
        (lambda value: setattr(value, "profile_revoked", True), "SIGNING_PROFILE_INVALID"),
        (
            lambda value: setattr(value, "revoked_entities", ["certificate"]),
            "SIGNED_ARTIFACT_REVOKED",
        ),
        (
            lambda value: setattr(value, "duplicate_signed_version", True),
            "SIGNED_OUTPUT_VERSION_NOT_UNIQUE",
        ),
        (
            lambda value: setattr(value, "signed_version_latest", False),
            "SIGNED_OUTPUT_VERSION_NOT_UNIQUE",
        ),
        (
            lambda value: setattr(
                value, "version_next_key_marker", "unexpected"
            ),
            "SIGNED_OUTPUT_VERSION_NOT_UNIQUE",
        ),
        (
            lambda value: setattr(value, "malformed_version_item", True),
            "SIGNED_OUTPUT_VERSION_NOT_UNIQUE",
        ),
        (
            lambda value: setattr(value, "signed_payload", value.unsigned_payload),
            "SIGNED_OUTPUT_NOT_DISTINCT",
        ),
        (
            lambda value: setattr(value, "signed_payload", b"not-a-zip"),
            "SIGNED_PACKAGE_INVALID",
        ),
    ],
)
def test_attestation_fails_closed_on_identity_signing_and_object_drift(
    source_repo: tuple[Path, str, bytes],
    mutate: Any,
    code: str,
) -> None:
    root, commit, package = source_repo
    session = _Session(commit=commit, unsigned_payload=package)
    mutate(session)
    with pytest.raises(signed.BrokerSignedArtifactError, match=code):
        _attest(root, commit, session)


def test_source_must_be_exact_clean_main_before_any_aws_call(
    source_repo: tuple[Path, str, bytes],
) -> None:
    root, commit, package = source_repo
    session = _Session(commit=commit, unsigned_payload=package)
    (root / "dirty.txt").write_text("dirty", encoding="utf-8")
    with pytest.raises(seed.BrokerSeedError, match="SOURCE_NOT_EXACT_CLEAN_MAIN"):
        _attest(root, commit, session)
    assert session.calls == []


def test_explicit_null_revocation_record_is_semantically_absent(
    source_repo: tuple[Path, str, bytes],
) -> None:
    root, commit, package = source_repo
    session = _Session(commit=commit, unsigned_payload=package)
    session.null_revocation_record = True
    assert _attest(root, commit, session)["broker_code"]["signing_job"][
        "job_revocation_record_absent"
    ] is True


def test_s3_version_ids_accept_aws_maximum_and_reject_overflow() -> None:
    maximum = "v" * 1024
    value = {"bucketName": BUCKET, "key": "irrelevant", "version": maximum}
    # The key contract is checked independently; exercise only the public
    # version ceiling through an otherwise exact source location.
    value["key"] = (
        "scanalyze/platform-authority/gug-376/plan-policy-repair/"
        "broker/unsigned/" + "a" * 40 + "/route-broker-unsigned.zip"
    )
    assert signed._validate_location(  # noqa: SLF001
        value,
        signed=False,
        source_commit="a" * 40,
    )[2] == maximum
    value["version"] = maximum + "v"
    with pytest.raises(
        signed.BrokerSignedArtifactError,
        match="SIGNING_JOB_LOCATION_INVALID",
    ):
        signed._validate_location(  # noqa: SLF001
            value,
            signed=False,
            source_commit="a" * 40,
        )


def test_upstream_gug365_bucket_or_kms_substitution_is_rejected_before_aws(
    source_repo: tuple[Path, str, bytes],
) -> None:
    root, commit, package = source_repo
    session = _Session(commit=commit, unsigned_payload=package)
    gug363_plan, gug365_plan = _upstream_plans()
    storage_binding = _storage_binding(root, gug363_plan, gug365_plan)
    gug365_plan["signed_artifact_binding"]["bucket"] = "foreign-artifacts"
    pep_receipt = _pep_receipt(commit, storage_binding)
    with pytest.raises(
        signed.BrokerSignedArtifactError,
        match="UPSTREAM_STORAGE_BINDING_INVALID",
    ):
        signed.attest_broker_signed_artifact(
            source_root=root,
            source_commit=commit,
            aws_profile=signed.LEGACY_EXPECTED_PROFILE,
            expected_account_id=signed.EXPECTED_ACCOUNT_ID,
            region=signed.EXPECTED_REGION,
            unsigned_bucket=BUCKET,
            unsigned_key=session.unsigned_key,
            unsigned_version="unsigned-version-1",
            signing_job_id=JOB_ID,
            signed_version="signed-version-1",
            pep_signed_artifact_receipt=pep_receipt,
            gug363_plan=gug363_plan,
            gug365_plan=gug365_plan,
            upstream_source_root=root,
            session_factory=lambda _profile, _region: session,
            clock=lambda: OBSERVED,
            config_factory=lambda: object(),
            pep_receipt_validator=lambda *_args, **_kwargs: None,
            gug363_validator=lambda *_args, **_kwargs: None,
            gug365_validator=lambda *_args, **_kwargs: None,
            allow_legacy_upstream_plans=True,
            environment={},
        )
    assert session.calls == []


def test_pep_storage_binding_must_equal_current_gug363_gug365_binding(
    source_repo: tuple[Path, str, bytes],
) -> None:
    root, commit, package = source_repo
    session = _Session(commit=commit, unsigned_payload=package)
    gug363_plan, gug365_plan = _upstream_plans()
    pep_receipt = _pep_receipt(
        commit,
        _storage_binding(root, gug363_plan, gug365_plan),
    )
    pep_storage = pep_receipt["upstream_storage_binding"]
    pep_storage["bucket"] = "foreign-artifacts"
    pep_storage["binding_digest"] = seed.digest_value(
        {
            key: item
            for key, item in pep_storage.items()
            if key != "binding_digest"
        }
    )
    pep_receipt["signed_artifact"]["bucket"] = "foreign-artifacts"
    pep_receipt["signing_job"]["source"]["bucket"] = "foreign-artifacts"
    pep_receipt["receipt_digest"] = seed.digest_value(
        {
            key: value
            for key, value in pep_receipt.items()
            if key != "receipt_digest"
        }
    )
    with pytest.raises(
        signed.BrokerSignedArtifactError,
        match="PEP_UPSTREAM_STORAGE_BINDING_MISMATCH",
    ):
        _attest(root, commit, session, pep_receipt=pep_receipt)
    assert session.calls == []


@pytest.mark.parametrize(
    "environment",
    [
        {"AWS_ACCESS_KEY_ID": "forbidden"},
        {"AWS_SHARED_CREDENTIALS_FILE": "/tmp/forbidden"},
        {"AWS_CONFIG_FILE": "/tmp/forbidden"},
        {"AWS_CA_BUNDLE": "/tmp/forbidden"},
        {"BOTO_CONFIG": "/tmp/forbidden"},
        {"HTTPS_PROXY": "http://127.0.0.1:8080"},
        {"AWS_ENDPOINT_URL": "http://127.0.0.1:4566"},
        {"AWS_ENDPOINT_URL_S3": "http://127.0.0.1:4566"},
        {"AWS_PROFILE": "default"},
        {"AWS_REGION": "us-west-2"},
    ],
)
def test_credential_endpoint_profile_and_region_environment_is_rejected(
    source_repo: tuple[Path, str, bytes], environment: dict[str, str]
) -> None:
    root, commit, package = source_repo
    session = _Session(commit=commit, unsigned_payload=package)
    with pytest.raises(signed.BrokerSignedArtifactError, match="AWS_"):
        _attest(root, commit, session, environment=environment)
    assert session.calls == []


def test_session_must_use_exact_sso_profile_document_and_source(
    source_repo: tuple[Path, str, bytes],
) -> None:
    root, commit, package = source_repo
    session = _Session(commit=commit, unsigned_payload=package)
    session.credential_method = "env"
    with pytest.raises(
        signed.BrokerSignedArtifactError,
        match="AWS_CREDENTIAL_SOURCE_INVALID",
    ):
        _attest(root, commit, session)
    assert session.calls == []

    session = _Session(commit=commit, unsigned_payload=package)
    session._session.full_config["profiles"][session.profile_name][
        "sso_role_name"
    ] = "AWSAdministratorAccess"
    with pytest.raises(
        signed.BrokerSignedArtifactError,
        match="AWS_PROFILE_CONFIGURATION_INVALID",
    ):
        _attest(root, commit, session)
    assert session.calls == []

    session = _Session(commit=commit, unsigned_payload=package)
    session._session.full_config["sso_sessions"]["scanalyze-test"][
        "sso_start_url"
    ] = "http://127.0.0.1/start"
    with pytest.raises(
        signed.BrokerSignedArtifactError,
        match="AWS_PROFILE_CONFIGURATION_INVALID",
    ):
        _attest(root, commit, session)
    assert session.calls == []

    session = _Session(commit=commit, unsigned_payload=package)
    session._session.full_config["sso_sessions"]["scanalyze-test"][
        "endpoint_url"
    ] = "https://example.invalid"
    with pytest.raises(
        signed.BrokerSignedArtifactError,
        match="AWS_PROFILE_CONFIGURATION_INVALID",
    ):
        _attest(root, commit, session)
    assert session.calls == []

    session = _Session(commit=commit, unsigned_payload=package)
    session._session.full_config["profiles"][session.profile_name][
        "sso_start_url"
    ] = "https://example.awsapps.com/start"
    with pytest.raises(
        signed.BrokerSignedArtifactError,
        match="AWS_PROFILE_CONFIGURATION_INVALID",
    ):
        _attest(root, commit, session)
    assert session.calls == []


def test_non_aws_https_endpoint_is_rejected_after_sts_client_creation(
    source_repo: tuple[Path, str, bytes],
) -> None:
    root, commit, package = source_repo
    session = _Session(commit=commit, unsigned_payload=package)
    session.bad_endpoint = True
    with pytest.raises(signed.BrokerSignedArtifactError, match="AWS_ENDPOINT_INVALID"):
        _attest(root, commit, session)
    assert session.calls == ["client:sts"]


def test_default_botocore_config_disables_sdk_retries() -> None:
    config = signed._client_config(None)
    assert config.connect_timeout == 3
    assert config.read_timeout == 5
    assert config.retries["total_max_attempts"] == 1
    assert config.s3 == {"us_east_1_regional_endpoint": "regional"}
    assert config.ignore_configured_endpoint_urls is True


def test_exact_client_accepts_real_botocore_endpoint_shapes_without_calls() -> None:
    import boto3

    session = boto3.session.Session(
        aws_access_key_id="synthetic",
        aws_secret_access_key="synthetic",
        aws_session_token="synthetic",
        region_name="us-east-1",
    )
    config = signed._client_config(None)
    for service in ("sts", "s3", "signer", "acm", "signer-data"):
        client = signed._exact_client(session, service, "us-east-1", config)
        assert client.meta.endpoint_url.startswith("https://")


def test_receipt_digest_and_unsigned_signed_roles_cannot_be_swapped(
    source_repo: tuple[Path, str, bytes],
) -> None:
    root, commit, package = source_repo
    session = _Session(commit=commit, unsigned_payload=package)
    receipt = _attest(root, commit, session)["broker_code"]
    receipt["unsigned_artifact"], receipt["signed_artifact"] = (
        receipt["signed_artifact"],
        receipt["unsigned_artifact"],
    )
    with pytest.raises(seed.BrokerSeedError, match="BROKER_SIGNING_RECEIPT_INVALID"):
        seed.validate_broker_signing_receipt(
            receipt,
            source_commit=commit,
            now=OBSERVED,
            allow_legacy_upstream_storage_binding=True,
        )


def test_receipt_rejects_aws_call_count_overclaim(
    source_repo: tuple[Path, str, bytes],
) -> None:
    root, commit, package = source_repo
    receipt = _attest(
        root,
        commit,
        _Session(commit=commit, unsigned_payload=package),
    )["broker_code"]
    receipt["aws_calls"] = 12
    receipt["receipt_digest"] = seed.digest_value(
        {key: value for key, value in receipt.items() if key != "receipt_digest"}
    )
    with pytest.raises(seed.BrokerSeedError, match="BROKER_SIGNING_RECEIPT_INVALID"):
        seed.validate_broker_signing_receipt(
            receipt,
            source_commit=commit,
            now=OBSERVED,
            allow_legacy_upstream_storage_binding=True,
        )


@pytest.mark.parametrize("mode", ["stale", "future", "extra"])
def test_signed_handoff_freshness_and_closed_schema_fail_closed(
    source_repo: tuple[Path, str, bytes], mode: str
) -> None:
    root, commit, package = source_repo
    session = _Session(commit=commit, unsigned_payload=package)
    receipt = _attest(root, commit, session)["broker_code"]
    if mode == "stale":
        receipt["observed_at"] = (OBSERVED - timedelta(minutes=16)).isoformat().replace(
            "+00:00", "Z"
        )
        receipt["signing_job"]["completed_at"] = receipt["observed_at"]
        receipt["revocation_check"]["checked_at"] = receipt["observed_at"]
    elif mode == "future":
        receipt["observed_at"] = (OBSERVED + timedelta(minutes=2)).isoformat().replace(
            "+00:00", "Z"
        )
        receipt["revocation_check"]["checked_at"] = receipt["observed_at"]
    else:
        receipt["operator_assertion"] = "forbidden"
    receipt["receipt_digest"] = seed.digest_value(
        {key: value for key, value in receipt.items() if key != "receipt_digest"}
    )
    with pytest.raises(seed.BrokerSeedError, match="BROKER_SIGNING_RECEIPT"):
        seed.validate_broker_signing_receipt(
            receipt,
            source_commit=commit,
            now=OBSERVED,
            allow_legacy_upstream_storage_binding=True,
        )


def test_cli_import_and_help_do_not_import_aws_sdk() -> None:
    spec = importlib.util.spec_from_file_location("broker_signed_cli", CLI)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    before = set(sys.modules)
    spec.loader.exec_module(module)
    assert not {"boto3", "botocore"} & (set(sys.modules) - before)
    completed = subprocess.run(
        [sys.executable, str(CLI), "--help"],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
        shell=False,
    )
    assert completed.returncode == 0
    assert "read-only AWS calls" in completed.stdout
    assert signed.EXPECTED_PROFILE in completed.stdout
    assert signed.LEGACY_EXPECTED_PROFILE not in completed.stdout


def test_cli_requires_owner_only_pep_receipt_before_any_aws_call(
    tmp_path: Path,
) -> None:
    private = tmp_path / "private"
    private.mkdir(mode=0o700)
    private.chmod(0o700)
    receipt = private / "pep-receipt.json"
    receipt.write_text("{}", encoding="utf-8")
    receipt.chmod(0o644)
    bootstrap_intent = private / "bootstrap-intent.json"
    foundation_binding = private / "foundation-publish-binding.json"
    for path in (bootstrap_intent, foundation_binding):
        path.write_text("{}", encoding="utf-8")
        path.chmod(0o600)
    commit = "a" * 40
    completed = subprocess.run(
        [
            sys.executable,
            str(CLI),
            "--source-root",
            str(REPO_ROOT),
            "--source-commit",
            commit,
            "--private-root",
            str(private),
            "--aws-profile",
            signed.EXPECTED_PROFILE,
            "--expected-account-id",
            signed.EXPECTED_ACCOUNT_ID,
            "--region",
            signed.EXPECTED_REGION,
            "--unsigned-bucket",
            "scanalyze-gug376-artifacts",
            "--unsigned-key",
            (
                "scanalyze/platform-authority/gug-376/plan-policy-repair/"
                f"broker/unsigned/{commit}/route-broker-unsigned.zip"
            ),
            "--unsigned-version",
            "version-1",
            "--signing-job-id",
            JOB_ID,
            "--signed-version",
            "version-2",
            "--pep-signed-artifact-receipt-name",
            receipt.name,
            "--bootstrap-intent-name",
            bootstrap_intent.name,
            "--foundation-publish-binding-name",
            foundation_binding.name,
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
        shell=False,
    )
    assert completed.returncode == 2
    assert json.loads(completed.stderr) == {"error": "PRIVATE_INPUT_INVALID"}
    assert "Traceback" not in completed.stderr
    assert str(private) not in completed.stderr
