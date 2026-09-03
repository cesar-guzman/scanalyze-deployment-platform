from __future__ import annotations

import base64
from copy import deepcopy
from datetime import datetime, timezone
from hashlib import sha256
import io
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace
from typing import Any, Callable, Mapping

import pytest

from tooling import platform_authority_plan_permission_repair_deployment_route as route
from tooling import platform_authority_plan_permission_repair_broker_seed as seed
from tooling import (
    platform_authority_plan_permission_repair_template_readback as subject,
)
from tests.test_deployment.gug376_foundation_fixtures import (
    build_foundation_contract,
)


SOURCE_COMMIT = "1" * 40
BUCKET = "scanalyze-gug365-artifacts"
KMS_KEY_ARN = (
    "arn:aws:kms:us-east-1:042360977644:key/"
    "12345678-1234-4234-8234-1234567890ab"
)
CALLER_ARN = (
    "arn:aws:sts::042360977644:assumed-role/"
    "AWSReservedSSO_AWSReadOnlyAccess_0123456789ABCDEF/cesar"
)
FOUNDATION_CALLER_ARN = (
    "arn:aws:sts::042360977644:assumed-role/"
    "AWSReservedSSO_ScanalyzeGug376ArtifactBootstrap_"
    "0123456789ABCDEF/cesar"
)
CLI = (
    Path(__file__).resolve().parents[2]
    / "scripts/deployment/"
    "platform-authority-plan-permission-repair-template-readback.py"
)


def _digest(character: str) -> str:
    return "sha256:" + character * 64


def _location(*, signed: bool = False) -> dict[str, Any]:
    result = {
        "bucket": BUCKET,
        "sse_algorithm": "aws:kms",
        "sse_kms_key_arn": KMS_KEY_ARN,
    }
    if signed:
        result["binding_digest"] = _digest("9")
    return result


def _plans() -> tuple[dict[str, Any], dict[str, Any]]:
    gug363 = {
        "record_type": (
            "scanalyze.platform_authority.retirement_entrypoint_plan.v1"
        ),
        "target": {
            "authority_account_id": subject.EXPECTED_ACCOUNT_ID,
            "region": subject.EXPECTED_REGION,
        },
        "production": False,
        "deployment_authorized": False,
        "plan_digest": _digest("1"),
        "artifact_signing_contract_digest": _digest("2"),
        "gug363_pre_function_binding_sha256": _digest("3"),
        "artifact_signing_contract": {
            "unsigned_source": _location(),
            "signed_destination": _location(),
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
            "unsigned_source": _location(),
            "signed_destination": _location(),
        },
        "signed_artifact_binding": _location(signed=True),
    }
    return gug363, gug365


def _accept(*_args: Any, **_kwargs: Any) -> None:
    return None


class FakeGit:
    def __init__(self, root: Path, payloads: Mapping[str, bytes]) -> None:
        self._root = root
        self._payloads = dict(payloads)

    def root(self) -> Path:
        return self._root

    def branch(self) -> str:
        return "main"

    def head(self) -> str:
        return SOURCE_COMMIT

    def origin_main(self) -> str:
        return SOURCE_COMMIT

    def status(self) -> str:
        return ""

    def read_at(self, commit: str, path: str) -> bytes:
        assert commit == SOURCE_COMMIT
        return self._payloads[path]


class Body:
    def __init__(self, payload: bytes) -> None:
        self._stream = io.BytesIO(payload)
        self.closed = False

    def read(self, size: int) -> bytes:
        return self._stream.read(size)

    def close(self) -> None:
        self.closed = True


class AccessDenied(Exception):
    response = {"Error": {"Code": "AccessDenied"}}


class Sts:
    def __init__(
        self, timeline: list[str], *, caller_arn: str = CALLER_ARN
    ) -> None:
        self.meta = SimpleNamespace(
            endpoint_url="https://sts.us-east-1.amazonaws.com"
        )
        self._timeline = timeline
        self._caller_arn = caller_arn

    def get_caller_identity(self) -> dict[str, str]:
        self._timeline.append("sts:GetCallerIdentity")
        return {
            "Account": subject.EXPECTED_ACCOUNT_ID,
            "Arn": self._caller_arn,
            "UserId": "synthetic",
        }


class S3:
    def __init__(
        self,
        timeline: list[str],
        payload: bytes,
        *,
        version: str,
        kms_key_arn: str = KMS_KEY_ARN,
        body_payload: bytes | None = None,
        get_error: Exception | None = None,
        versioning: str = "Enabled",
    ) -> None:
        self.meta = SimpleNamespace(
            endpoint_url="https://s3.us-east-1.amazonaws.com"
        )
        self._timeline = timeline
        self._payload = payload
        self._body_payload = payload if body_payload is None else body_payload
        self._version = version
        self._kms_key_arn = kms_key_arn
        self._get_error = get_error
        self._versioning = versioning
        self.requests: list[tuple[str, dict[str, Any]]] = []

    def get_bucket_versioning(self, **request: Any) -> dict[str, str]:
        self._timeline.append("s3:GetBucketVersioning")
        self.requests.append(("versioning", request))
        return {"Status": self._versioning, "MFADelete": "Disabled"}

    def _metadata(self) -> dict[str, Any]:
        checksum = base64.b64encode(sha256(self._payload).digest()).decode()
        return {
            "VersionId": self._version,
            "ContentLength": len(self._payload),
            "ServerSideEncryption": "aws:kms",
            "SSEKMSKeyId": self._kms_key_arn,
            "ChecksumSHA256": checksum,
            "ChecksumType": "FULL_OBJECT",
        }

    def head_object(self, **request: Any) -> dict[str, Any]:
        self._timeline.append("s3:HeadObject")
        self.requests.append(("head", request))
        return self._metadata()

    def get_object(self, **request: Any) -> dict[str, Any]:
        self._timeline.append("s3:GetObject")
        self.requests.append(("get", request))
        if self._get_error is not None:
            raise self._get_error
        return {**self._metadata(), "Body": Body(self._body_payload)}


class Session:
    def __init__(
        self,
        sts: Sts,
        s3: S3,
        timeline: list[str],
        *,
        profile: str = subject.LEGACY_EXPECTED_PROFILE,
        role: str = subject.LEGACY_EXPECTED_SSO_ROLE,
    ) -> None:
        self.profile_name = profile
        self.region_name = subject.EXPECTED_REGION
        self._sts = sts
        self._s3 = s3
        self._timeline = timeline
        self._session = SimpleNamespace(
            full_config={
                "profiles": {
                    profile: {
                        "region": subject.EXPECTED_REGION,
                        "sso_account_id": subject.EXPECTED_ACCOUNT_ID,
                        "sso_role_name": role,
                        "sso_session": "scanalyze",
                    }
                },
                "sso_sessions": {
                    "scanalyze": {
                        "sso_start_url": "https://scanalyze.awsapps.com/start",
                        "sso_region": "us-east-1",
                    }
                },
            }
        )

    def get_credentials(self) -> Any:
        return SimpleNamespace(method="sso")

    def client(self, service: str, **kwargs: Any) -> Any:
        assert kwargs == {"region_name": subject.EXPECTED_REGION, "config": "config"}
        self._timeline.append(f"client:{service}")
        return {"sts": self._sts, "s3": self._s3}[service]


def _run(
    tmp_path: Path,
    *,
    artifact_kind: str = "route_template",
    payload: bytes = b"AWSTemplateFormatVersion: '2010-09-09'\nResources: {}\n",
    private_artifact: bytes | None = None,
    materialization_receipt: Mapping[str, Any] | None = None,
    s3_factory: Any = None,
    plans: tuple[dict[str, Any], dict[str, Any]] | None = None,
    clock: Callable[[], datetime] | None = None,
) -> tuple[dict[str, Any], list[str], S3]:
    timeline: list[str] = []
    version = "exact-version-1"
    source_path = {
        "route_template": route.ROUTE_TEMPLATE_PATH,
        "delegation_template": route.DELEGATION_TEMPLATE_PATH,
        "pep_template": (
            "bootstrap/cfn-platform-authority-bootstrap-plan-repair-pep.yaml"
        ),
        "pep_protection_template": (
            "bootstrap/cfn-platform-authority-bootstrap-plan-repair-pep.yaml"
        ),
        "broker_template": route.BROKER_TEMPLATE_PATH,
        "broker_protection_template": route.BROKER_TEMPLATE_PATH,
    }[artifact_kind]
    if (
        artifact_kind in {"pep_template", "pep_protection_template"}
        and private_artifact is None
    ):
        protection_enabled = artifact_kind == "pep_protection_template"
        policy = "Retain" if protection_enabled else "Delete"
        output_name = (
            seed.PEP_PROTECTION_OUTPUT_NAME
            if protection_enabled
            else seed.PEP_OUTPUT_NAME
        )
        private_artifact = payload
        materialization_receipt = {
            "record_type": seed.PEP_TEMPLATE_RECEIPT_TYPE,
            "schema_version": 1,
            "source_commit": SOURCE_COMMIT,
            "source_path": seed.PEP_SOURCE_TEMPLATE_PATH.as_posix(),
            "source_sha256": route.bytes_digest(payload),
            "template_variant": "protection" if protection_enabled else "create",
            "output_name": output_name,
            "template_sha256": route.bytes_digest(private_artifact),
            "template_bytes": len(private_artifact),
            "ledger_deletion_protection_enabled": protection_enabled,
            "lifecycle_deletion_policy": policy,
            "lifecycle_update_replace_policy": policy,
            "lifecycle_resource_ids": list(seed.PEP_LIFECYCLE_RESOURCE_IDS),
            "variant_controls_parameterless": True,
            "private_mode": "0600",
            "aws_calls": 0,
            "aws_mutations": 0,
            "deployment_authorized": False,
            "production_status": seed.PRODUCTION_STATUS,
        }
        materialization_receipt["receipt_digest"] = seed.digest_value(
            materialization_receipt
        )
    artifact_payload = private_artifact if private_artifact is not None else payload
    s3 = (
        s3_factory(timeline, artifact_payload, version)
        if s3_factory is not None
        else S3(timeline, artifact_payload, version=version)
    )
    session = Session(Sts(timeline), s3, timeline)
    gug363, gug365 = plans or _plans()
    receipt = subject.attest_template_readback(
        source_root=tmp_path,
        source_commit=SOURCE_COMMIT,
        artifact_kind=artifact_kind,
        version=version,
        gug363_plan=gug363,
        gug365_plan=gug365,
        aws_profile=subject.LEGACY_EXPECTED_PROFILE,
        expected_account_id=subject.EXPECTED_ACCOUNT_ID,
        region=subject.EXPECTED_REGION,
        private_artifact=private_artifact,
        materialization_receipt=materialization_receipt,
        git=FakeGit(tmp_path, {source_path: payload}),
        session_factory=lambda profile, region: session,
        config_factory=lambda: "config",
        clock=clock
        or (lambda: datetime(2026, 8, 30, 12, 0, tzinfo=timezone.utc)),
        environment={},
        gug363_validator=_accept,
        gug365_validator=_accept,
        materialization_validator=(
            (lambda value: value) if materialization_receipt is not None else None
        ),
    )
    return receipt, timeline, s3


def _run_foundation(
    tmp_path: Path,
    *,
    aws_profile: str = subject.EXPECTED_PROFILE,
    clock_at: datetime | None = None,
    clock: Callable[[], datetime] | None = None,
    timeline: list[str] | None = None,
) -> tuple[dict[str, Any], list[str]]:
    contract_observed = datetime(2026, 8, 30, 12, 0, tzinfo=timezone.utc)
    observed = clock_at or contract_observed
    contract = build_foundation_contract(
        source_commit=SOURCE_COMMIT,
        observed_at=contract_observed,
    )
    binding = contract["foundation_publish_binding"]
    payload = b"AWSTemplateFormatVersion: '2010-09-09'\nResources: {}\n"
    timeline = timeline if timeline is not None else []
    version = "exact-foundation-version-1"
    s3 = S3(
        timeline,
        payload,
        version=version,
        kms_key_arn=binding["sse_kms_key_arn"],
    )
    session = Session(
        Sts(timeline, caller_arn=FOUNDATION_CALLER_ARN),
        s3,
        timeline,
        profile=subject.EXPECTED_PROFILE,
        role=subject.EXPECTED_SSO_ROLE,
    )
    receipt = subject.attest_template_readback(
        source_root=tmp_path,
        source_commit=SOURCE_COMMIT,
        artifact_kind="route_template",
        version=version,
        gug363_plan=None,
        gug365_plan=None,
        aws_profile=aws_profile,
        expected_account_id=subject.EXPECTED_ACCOUNT_ID,
        region=subject.EXPECTED_REGION,
        git=FakeGit(tmp_path, {route.ROUTE_TEMPLATE_PATH: payload}),
        session_factory=lambda profile, region: session,
        config_factory=lambda: "config",
        clock=clock or (lambda: observed),
        environment={},
        bootstrap_intent=contract["bootstrap_intent"],
        foundation_publish_binding=binding,
    )
    return receipt, timeline


def test_foundation_mode_uses_only_artifact_bootstrap_verifier(
    tmp_path: Path,
) -> None:
    receipt, timeline = _run_foundation(tmp_path)
    assert timeline[0:2] == ["client:sts", "sts:GetCallerIdentity"]
    assert receipt["verifier"] == {
        "account_id": subject.EXPECTED_ACCOUNT_ID,
        "caller_arn": FOUNDATION_CALLER_ARN,
        "profile": subject.EXPECTED_PROFILE,
        "region": subject.EXPECTED_REGION,
    }
    assert receipt["upstream_storage_binding"]["record_type"].endswith(
        "gug376_artifact_foundation_publish_binding.v1"
    )


def test_foundation_mode_rejects_legacy_profile_before_aws(tmp_path: Path) -> None:
    with pytest.raises(subject.TemplateReadbackError, match="ATTESTATION_INPUT_INVALID"):
        _run_foundation(tmp_path, aws_profile=subject.LEGACY_EXPECTED_PROFILE)


def test_foundation_mode_closes_exactly_at_access_not_after_before_sts(
    tmp_path: Path,
) -> None:
    timeline: list[str] = []
    with pytest.raises(subject.TemplateReadbackError) as raised:
        _run_foundation(
            tmp_path,
            clock_at=datetime(2026, 8, 30, 12, 45, tzinfo=timezone.utc),
            timeline=timeline,
        )
    assert raised.value.code == "FOUNDATION_ACCESS_WINDOW_CLOSED"
    assert timeline == []


def test_foundation_mode_rechecks_access_window_after_object_reads(
    tmp_path: Path,
) -> None:
    timeline: list[str] = []
    timestamps = iter(
        (
            datetime(2026, 8, 30, 12, 44, 59, tzinfo=timezone.utc),
            datetime(2026, 8, 30, 12, 45, 0, tzinfo=timezone.utc),
        )
    )

    with pytest.raises(subject.TemplateReadbackError) as raised:
        _run_foundation(
            tmp_path,
            clock=lambda: next(timestamps),
            timeline=timeline,
        )

    assert raised.value.code == "FOUNDATION_ACCESS_WINDOW_CLOSED"
    assert timeline[-1] == "s3:GetObject"


def test_foundation_receipt_rejects_resealed_post_window_observation(
    tmp_path: Path,
) -> None:
    receipt, _timeline = _run_foundation(tmp_path)
    boundary = receipt["upstream_storage_binding"]["access_not_after"]
    candidate = deepcopy(receipt)
    candidate["observed_at"] = boundary
    candidate.pop("receipt_digest")
    candidate = route.seal(candidate, "receipt_digest")
    with pytest.raises(subject.TemplateReadbackError) as raised:
        subject.validate_template_readback_receipt(
            candidate,
            artifact_kind="route_template",
            source_commit=SOURCE_COMMIT,
            now=datetime.fromisoformat(boundary[:-1] + "+00:00"),
            expected_storage_binding=candidate["upstream_storage_binding"],
        )
    assert raised.value.code == "FOUNDATION_ACCESS_WINDOW_CLOSED"


def test_product_cli_exposes_only_foundation_publication_inputs() -> None:
    completed = subprocess.run(
        [sys.executable, str(CLI), "--help"],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=30,
    )
    assert completed.returncode == 0
    assert "--bootstrap-intent-name" in completed.stdout
    assert "--foundation-publish-binding-name" in completed.stdout
    assert "--pep-protection-template-name" in completed.stdout
    assert "--pep-protection-materialization-receipt-name" in completed.stdout
    assert "--broker-protection-template-name" in completed.stdout
    assert "--broker-protection-materialization-receipt-name" in completed.stdout
    assert "--gug363-plan-name" not in completed.stdout
    assert "--gug365-plan-name" not in completed.stdout


def test_attests_exact_route_template_with_sts_as_first_aws_call(
    tmp_path: Path,
) -> None:
    receipt, timeline, s3 = _run(tmp_path)

    assert timeline == [
        "client:sts",
        "sts:GetCallerIdentity",
        "client:s3",
        "s3:GetBucketVersioning",
        "s3:HeadObject",
        "s3:GetObject",
    ]
    assert receipt["aws_calls"] == 4
    assert receipt["aws_mutations"] == 0
    assert receipt["bucket"] == BUCKET
    assert receipt["sse_kms_key_arn"] == KMS_KEY_ARN
    assert receipt["upstream_storage_binding"]["gug363_plan_digest"] == _digest(
        "1"
    )
    assert route.digest_value(
        {key: value for key, value in receipt.items() if key != "receipt_digest"}
    ) == receipt["receipt_digest"]
    expected_object_request = {
        "Bucket": BUCKET,
        "Key": (
            "scanalyze/platform-authority/gug-376/plan-policy-repair/"
            f"templates/{SOURCE_COMMIT}/"
            "cfn-platform-authority-gug376-temporary-change-set-route.yaml"
        ),
        "VersionId": "exact-version-1",
        "ExpectedBucketOwner": subject.EXPECTED_ACCOUNT_ID,
        "ChecksumMode": "ENABLED",
    }
    assert s3.requests == [
        (
            "versioning",
            {"Bucket": BUCKET, "ExpectedBucketOwner": subject.EXPECTED_ACCOUNT_ID},
        ),
        ("head", expected_object_request),
        ("get", expected_object_request),
    ]


def test_attestation_validates_freshness_at_completion_timestamp(
    tmp_path: Path,
) -> None:
    timestamps = iter(
        (
            datetime(2026, 8, 30, 12, 0, 0, tzinfo=timezone.utc),
            datetime(2026, 8, 30, 12, 0, 1, tzinfo=timezone.utc),
        )
    )

    receipt, _timeline, _s3 = _run(tmp_path, clock=lambda: next(timestamps))

    assert receipt["observed_at"] == "2026-08-30T12:00:01Z"


def test_attestation_rejects_a_regressive_completion_clock(tmp_path: Path) -> None:
    timestamps = iter(
        (
            datetime(2026, 8, 30, 12, 0, 0, 900_000, tzinfo=timezone.utc),
            datetime(2026, 8, 30, 12, 0, 0, 100_000, tzinfo=timezone.utc),
        )
    )

    with pytest.raises(subject.TemplateReadbackError) as raised:
        _run(tmp_path, clock=lambda: next(timestamps))

    assert raised.value.code == "CLOCK_INVALID"


def test_attests_pep_template_and_derives_closed_broker_seed_descriptor(
    tmp_path: Path,
) -> None:
    gug363, gug365 = _plans()
    receipt, timeline, _s3 = _run(
        tmp_path,
        artifact_kind="pep_template",
        payload=b"Resources:\n  Pep:\n    Type: AWS::IAM::Role\n",
        plans=(gug363, gug365),
    )

    descriptor = subject.pep_template_descriptor(
        receipt,
        source_commit=SOURCE_COMMIT,
        gug363_plan=gug363,
        gug365_plan=gug365,
        upstream_source_root=tmp_path,
        now=datetime(2026, 8, 30, 12, 0, tzinfo=timezone.utc),
        gug363_validator=_accept,
        gug365_validator=_accept,
    )
    assert timeline[1] == "sts:GetCallerIdentity"
    assert receipt["source_path"] == (
        "bootstrap/cfn-platform-authority-bootstrap-plan-repair-pep.yaml"
    )
    assert receipt["key"] == (
        "scanalyze/platform-authority/gug-376/plan-policy-repair/templates/"
        f"{SOURCE_COMMIT}/cfn-platform-authority-bootstrap-plan-repair-pep.yaml"
    )
    assert descriptor == {
        "bucket": receipt["bucket"],
        "key": receipt["key"],
        "version": receipt["version"],
        "url": receipt["template_url"],
    }


def test_pep_descriptor_rejects_resealed_storage_substitution(
    tmp_path: Path,
) -> None:
    gug363, gug365 = _plans()
    receipt, _timeline, _s3 = _run(
        tmp_path,
        artifact_kind="pep_template",
        plans=(gug363, gug365),
    )
    tampered = deepcopy(receipt)
    storage = dict(tampered["upstream_storage_binding"])
    storage["gug365_plan_digest"] = _digest("a")
    storage.pop("binding_digest")
    tampered["upstream_storage_binding"] = route.seal(
        storage, "binding_digest"
    )
    tampered.pop("receipt_digest")
    tampered = route.seal(tampered, "receipt_digest")

    with pytest.raises(
        subject.TemplateReadbackError,
        match="TEMPLATE_STORAGE_BINDING_INVALID|TEMPLATE_RECEIPT_DIGEST_INVALID",
    ):
        subject.pep_template_descriptor(
            tampered,
            source_commit=SOURCE_COMMIT,
            gug363_plan=gug363,
            gug365_plan=gug365,
            upstream_source_root=tmp_path,
            now=datetime(2026, 8, 30, 12, 0, tzinfo=timezone.utc),
            gug363_validator=_accept,
            gug365_validator=_accept,
        )


def test_pep_readback_rejects_crossed_materialization_variant(
    tmp_path: Path,
) -> None:
    payload = b"Resources:\n  Pep:\n    Type: AWS::IAM::Role\n"
    create, _timeline, _s3 = _run(
        tmp_path,
        artifact_kind="pep_template",
        payload=payload,
    )
    protection, _timeline, _s3 = _run(
        tmp_path,
        artifact_kind="pep_protection_template",
        payload=payload,
    )
    crossed = deepcopy(create)
    crossed["materialization_receipt"] = protection[
        "materialization_receipt"
    ]
    crossed.pop("receipt_digest")
    crossed = route.seal(crossed, "receipt_digest")
    with pytest.raises(
        subject.TemplateReadbackError,
        match="TEMPLATE_MATERIALIZATION_RECEIPT_INVALID",
    ):
        subject.validate_template_readback_receipt(
            crossed,
            artifact_kind="pep_template",
            source_commit=SOURCE_COMMIT,
            now=datetime(2026, 8, 30, 12, 0, tzinfo=timezone.utc),
        )


def test_rejects_upstream_bucket_substitution_before_aws(tmp_path: Path) -> None:
    gug363, gug365 = _plans()
    gug365["ledger_factory_artifact_signing_contract"]["unsigned_source"][
        "bucket"
    ] = "attacker-bucket"

    with pytest.raises(
        subject.TemplateReadbackError,
        match="UPSTREAM_STORAGE_BINDING_MISMATCH",
    ):
        _run(tmp_path, plans=(gug363, gug365))


def test_rejects_upstream_kms_substitution_before_aws(tmp_path: Path) -> None:
    gug363, gug365 = _plans()
    gug365["signed_artifact_binding"]["sse_kms_key_arn"] = (
        "arn:aws:kms:us-east-1:042360977644:key/"
        "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
    )

    with pytest.raises(
        subject.TemplateReadbackError,
        match="UPSTREAM_STORAGE_BINDING_MISMATCH",
    ):
        _run(tmp_path, plans=(gug363, gug365))


def test_rejects_invalid_causal_plan(tmp_path: Path) -> None:
    gug363, gug365 = _plans()

    with pytest.raises(subject.TemplateReadbackError, match="UPSTREAM_PLAN_INVALID"):
        subject.derive_upstream_storage_binding(
            gug363_plan=gug363,
            gug365_plan=gug365,
            source_root=tmp_path,
            gug363_validator=lambda *_args, **_kwargs: (_ for _ in ()).throw(
                ValueError("invalid")
            ),
            gug365_validator=_accept,
        )


@pytest.mark.parametrize(
    ("factory", "code"),
    [
        (
            lambda timeline, payload, version: S3(
                timeline,
                payload,
                version=version,
                kms_key_arn=(
                    "arn:aws:kms:us-east-1:042360977644:key/"
                    "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
                ),
            ),
            "S3_OBJECT_HEAD_INVALID",
        ),
        (
            lambda timeline, payload, version: S3(
                timeline, payload, version=version, versioning="Suspended"
            ),
            "S3_BUCKET_VERSIONING_INVALID",
        ),
        (
            lambda timeline, payload, version: S3(
                timeline,
                payload,
                version=version,
                body_payload=payload + b"substitution",
            ),
            "S3_OBJECT_BODY_INVALID",
        ),
        (
            lambda timeline, payload, version: _s3_with_endpoint(
                timeline,
                payload,
                version,
                "https://attacker.invalid",
            ),
            "AWS_ENDPOINT_INVALID",
        ),
    ],
)
def test_rejects_adversarial_s3_readbacks(
    tmp_path: Path, factory: Any, code: str
) -> None:
    with pytest.raises(subject.TemplateReadbackError, match=code):
        _run(tmp_path, s3_factory=factory)


def _s3_with_endpoint(
    timeline: list[str], payload: bytes, version: str, endpoint: str
) -> S3:
    client = S3(timeline, payload, version=version)
    client.meta.endpoint_url = endpoint
    return client


def test_reports_missing_s3_or_kms_decrypt_authority(tmp_path: Path) -> None:
    def factory(timeline: list[str], payload: bytes, version: str) -> S3:
        return S3(
            timeline,
            payload,
            version=version,
            get_error=AccessDenied(),
        )

    with pytest.raises(
        subject.TemplateReadbackError,
        match="S3_GET_OR_KMS_DECRYPT_AUTHORITY_REQUIRED",
    ):
        _run(tmp_path, s3_factory=factory)


def test_reports_kms_decrypt_authority_when_checksum_head_is_denied(
    tmp_path: Path,
) -> None:
    class HeadDeniedS3(S3):
        def head_object(self, **request: Any) -> dict[str, Any]:
            self._timeline.append("s3:HeadObject")
            self.requests.append(("head", request))
            raise AccessDenied

    def factory(timeline: list[str], payload: bytes, version: str) -> S3:
        return HeadDeniedS3(timeline, payload, version=version)

    with pytest.raises(
        subject.TemplateReadbackError,
        match="S3_GET_OR_KMS_DECRYPT_AUTHORITY_REQUIRED",
    ):
        _run(tmp_path, s3_factory=factory)


def test_rejects_ambient_endpoint_or_static_credential_override(
    tmp_path: Path,
) -> None:
    gug363, gug365 = _plans()
    payload = b"Resources: {}\n"

    for environment in (
        {"AWS_ENDPOINT_URL_S3": "https://attacker.invalid"},
        {"AWS_ACCESS_KEY_ID": "redacted"},
        {"HTTPS_PROXY": "https://attacker.invalid"},
    ):
        with pytest.raises(
            subject.TemplateReadbackError, match="AWS_ENVIRONMENT_UNSAFE"
        ):
            subject.attest_template_readback(
                source_root=tmp_path,
                source_commit=SOURCE_COMMIT,
                artifact_kind="route_template",
                version="version-1",
                gug363_plan=gug363,
                gug365_plan=gug365,
                aws_profile=subject.LEGACY_EXPECTED_PROFILE,
                expected_account_id=subject.EXPECTED_ACCOUNT_ID,
                region=subject.EXPECTED_REGION,
                git=FakeGit(tmp_path, {route.ROUTE_TEMPLATE_PATH: payload}),
                environment=environment,
                gug363_validator=_accept,
                gug365_validator=_accept,
            )


@pytest.mark.parametrize(
    "artifact_kind", ["broker_template", "broker_protection_template"]
)
def test_broker_template_requires_materialization_binding(
    tmp_path: Path, artifact_kind: str
) -> None:
    rendered = b"Resources:\n  Broker:\n    Type: AWS::Lambda::Function\n"
    materialization = {
        "source_commit": SOURCE_COMMIT,
        "template_sha256": route.bytes_digest(rendered),
        "template_bytes": len(rendered),
    }
    receipt, _timeline, _s3 = _run(
        tmp_path,
        artifact_kind=artifact_kind,
        payload=b"Parameters: {}\n",
        private_artifact=rendered,
        materialization_receipt=materialization,
    )
    assert receipt["source_sha256"] != receipt["artifact_sha256"]
    assert receipt["materialization_receipt"] == materialization

    drift = deepcopy(materialization)
    drift["template_sha256"] = _digest("a")
    with pytest.raises(
        subject.TemplateReadbackError,
        match="TEMPLATE_MATERIALIZATION_BINDING_MISMATCH",
    ):
        _run(
            tmp_path,
            artifact_kind=artifact_kind,
            payload=b"Parameters: {}\n",
            private_artifact=rendered,
            materialization_receipt=drift,
        )


def test_private_receipt_is_create_only_owner_readable(tmp_path: Path) -> None:
    private_root = tmp_path / "private"
    private_root.mkdir(mode=0o700)
    receipt = {"record_type": subject.RECORD_TYPE, "receipt_digest": _digest("f")}

    destination = subject.write_private_receipt(
        private_root=private_root,
        output_name="route-template-readback.json",
        receipt=receipt,
    )

    assert destination.stat().st_mode & 0o777 == 0o600
    with pytest.raises(subject.TemplateReadbackError, match="PRIVATE_OUTPUT_EXISTS"):
        subject.write_private_receipt(
            private_root=private_root,
            output_name="route-template-readback.json",
            receipt=receipt,
        )
