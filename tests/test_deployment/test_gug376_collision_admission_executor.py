from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from tests.test_deployment import (
    test_gug376_collision_admission as admission_data,
)
from tests.test_deployment import (
    test_gug376_collision_aws_provider as provider_data,
)
from tooling import platform_authority_gug376_collision_admission as contract
from tooling import (
    platform_authority_gug376_collision_admission_executor as executor,
)
from tooling import (
    platform_authority_gug376_collision_transcript_contract as transcript,
)
from tooling import platform_authority_gug376_collision_catalog as catalog_contract
from tooling import platform_authority_gug376_collision_policy as policy_contract


class _Clock:
    def __init__(
        self,
        values: list[datetime] | None = None,
    ) -> None:
        self._values = list(
            values
            or [
                admission_data.NOW + timedelta(seconds=offset)
                for offset in (
                    0, 0, 0, 0, 1, 1, 2, 3, 4,
                    4, 4, 4, 4, 4, 5, 6,
                    6, 6, 6, 6, 6, 7, 8, 9,
                    9, 9, 9, 9, 9, 9,
                )
            ]
        )

    def __call__(self) -> datetime:
        assert self._values, "executor requested an unexpected clock sample"
        return self._values.pop(0)


def _digest(label: str, **values: object) -> str:
    return contract.canonical_digest({"label": label, **values})


def _inventory_operation(target: dict[str, Any]) -> str:
    selector = target["selector"]
    if (
        target["scope"] == "code_signing_config"
        and selector["kind"]
        in {
            "cloudformation_stack_resource",
            "cloudformation_ownership_tags",
        }
    ):
        return "cloudformation:DescribeStackResource"
    return {
        ("cloudformation", "stack"): "cloudformation:DescribeStacks",
        ("dynamodb", "table"): "dynamodb:DescribeTable",
        ("iam", "role"): "iam:GetRole",
        ("kms", "alias"): "kms:ListAliases",
        ("lambda", "alias"): "lambda:GetAlias",
        ("lambda", "code_signing_config"): "lambda:GetCodeSigningConfig",
        ("lambda", "function"): "lambda:GetFunction",
        ("logs", "log_group"): "logs:DescribeLogGroups",
        ("s3", "bucket"): "s3:ListAllMyBuckets",
        ("signer", "signing_profile"): "signer:GetSigningProfile",
        ("sso", "application"): "sso:DescribeApplication",
        ("sso", "permission_set"): "sso:DescribePermissionSet",
    }[(target["service"], target["scope"])]


_LIST_DISCOVERY_OPERATIONS = {
    "cloudformation:ListStacks",
    "kms:ListAliases",
    "lambda:ListAliases",
    "lambda:ListCodeSigningConfigs",
    "lambda:ListFunctions",
    "logs:DescribeLogGroups",
    "s3:ListAllMyBuckets",
    "signer:ListSigningProfiles",
    "sso:ListApplications",
    "sso:ListPermissionSets",
}


class _SnapshotProvider:
    def __init__(
        self,
        *,
        owner: "_ProviderFactory",
        request: dict[str, Any],
        capture_index: int,
        purpose: str,
        mutating_event: bool = False,
    ) -> None:
        self.owner = owner
        self.request = request
        self.capture_index = capture_index
        self.purpose = purpose
        self.mutating_event = mutating_event
        self.events: list[dict[str, Any]] = []
        self.identity_read: set[str] = set()
        self.identities: dict[str, dict[str, Any]] = {}

    def _event(
        self,
        domain: str,
        operation: str,
        *,
        target_ids: list[str] | None = None,
        outcome: str = "SUCCESS",
        target_evidence_digests: dict[str, str] | None = None,
    ) -> None:
        identity = self.identities[domain]
        checked_target_ids = sorted(target_ids or [])
        evidence_digests = dict(target_evidence_digests or {})
        projection = {
            "page_item_digests": (
                [_digest("page-item", target_ids=checked_target_ids)]
                if checked_target_ids and outcome == "SUCCESS"
                else []
            ),
            "output_cursor_digest": None,
            "page_complete": True,
            "target_evidence_digests": evidence_digests,
        }
        event = {
            "ordinal": len(self.owner.events) + 1,
            "capture_index": self.capture_index,
            "domain": domain,
            "account_id": identity["account_id"],
            "region": contract.REGION,
            "session_digest": identity["session_digest"],
            "provider_implementation_digest": (
                transcript.COLLISION_PROVIDER_IMPLEMENTATION_DIGEST
            ),
            "operation": operation,
            "outcome": outcome,
            "request_digest": self.request["request_digest"],
            "operation_request_digest": "",
            "page_index": 1,
            "input_cursor_digest": None,
            "response_projection": projection,
            "response_digest": contract.canonical_digest(projection),
            "target_ids": checked_target_ids,
            "read_only": not self.mutating_event,
            "aws_mutations": 1 if self.mutating_event else 0,
        }
        event["operation_request_digest"] = contract.canonical_digest(
            transcript.operation_request_descriptor(
                request=self.request,
                event=event,
            )
        )
        self.events.append(event)
        self.owner.events.append(event)

    def read_identity(self, *, domain: str) -> dict[str, Any]:
        assert domain in {"authority", "management"}
        assert domain not in self.identity_read
        self.identity_read.add(domain)
        expected = self.request["expected_identities"][domain]
        identity = {
            "domain": domain,
            "account_id": expected["account_id"],
            "region": contract.REGION,
            "source": expected["source"],
            "chain_depth": expected["chain_depth"],
            "session_digest": _digest(
                "session", domain=domain, capture_index=self.capture_index
            ),
            "principal_digest": expected["principal_digest"],
            "sso_role_name_digest": expected["sso_role_name_digest"],
            "observed_at": admission_data._stamp(
                admission_data.NOW
                + timedelta(seconds=self.capture_index)
            ),
            "policy_digest": expected["policy_digest"],
            "authority_verification_digest": expected[
                "authority_verification_digest"
            ],
        }
        self.identities[domain] = identity
        self._event(domain, "sts:GetCallerIdentity")
        return identity

    def read_target_observations(
        self,
        *,
        domain: str,
        targets: list[dict[str, Any]],
        expected_dispositions: dict[str, str],
    ) -> dict[str, dict[str, Any]]:
        assert domain in self.identity_read
        assert {target["target_id"] for target in targets} == set(
            expected_dispositions
        )
        observations = {
            target_id: {
                "disposition": disposition,
                "facts_digest": _digest("facts", target_id=target_id),
                "ownership_binding_digest": (
                    _digest("ownership", target_id=target_id)
                    if disposition == "PRESENT_OWNED"
                    else None
                ),
            }
            for target_id, disposition in expected_dispositions.items()
        }
        for target in targets:
            target_id = str(target["target_id"])
            operation = _inventory_operation(dict(target))
            disposition = expected_dispositions[target_id]
            self._event(
                domain,
                operation,
                target_ids=[target_id],
                outcome=(
                    "SUCCESS"
                    if disposition == "PRESENT_OWNED"
                    or operation in _LIST_DISCOVERY_OPERATIONS
                    else "NOT_FOUND"
                ),
                target_evidence_digests={
                    target_id: contract.canonical_digest(
                        observations[target_id]
                    )
                },
            )
        return observations

    def transcript_events(self) -> list[dict[str, Any]]:
        return list(self.events)


class _ProviderFactory:
    provider_class = _SnapshotProvider

    def __init__(
        self,
        *,
        mutating_capture: int | None = None,
        reuse_session: bool = False,
    ) -> None:
        self.mutating_capture = mutating_capture
        self.reuse_session = reuse_session
        self.events: list[dict[str, Any]] = []
        self.opened: list[tuple[int, str]] = []
        self._first: _SnapshotProvider | None = None
        self.request_digest = ""

    def open_snapshot(
        self,
        *,
        request: dict[str, Any],
        capture_index: int,
        purpose: str,
    ) -> _SnapshotProvider:
        self.request_digest = str(request["request_digest"])
        self.opened.append((capture_index, purpose))
        if self.reuse_session and self._first is not None:
            return self._first
        provider = self.provider_class(
            owner=self,
            request=request,
            capture_index=capture_index,
            purpose=purpose,
            mutating_event=self.mutating_capture == capture_index,
        )
        self._first = self._first or provider
        return provider

    def transcript_events(self) -> list[dict[str, Any]]:
        return list(self.events)

    def transcript_summary(self) -> dict[str, Any]:
        return {
            "record_type": executor.TRANSCRIPT_SUMMARY_TYPE,
            "schema_version": 1,
            "request_digest": self.request_digest,
            "snapshot_count": 3,
            "provider_calls": len(self.events),
            "aws_calls": len(self.events),
            "aws_mutations": 0,
            "read_only": True,
            "transcript_digest": contract.canonical_digest(self.events),
        }


class _NoInventorySnapshot(_SnapshotProvider):
    def read_target_observations(
        self,
        *,
        domain: str,
        targets: list[dict[str, Any]],
        expected_dispositions: dict[str, str],
    ) -> dict[str, dict[str, Any]]:
        assert domain in self.identity_read
        assert {target["target_id"] for target in targets} == set(
            expected_dispositions
        )
        return {
            target_id: {
                "disposition": disposition,
                "facts_digest": _digest("facts", target_id=target_id),
                "ownership_binding_digest": (
                    _digest("ownership", target_id=target_id)
                    if disposition == "PRESENT_OWNED"
                    else None
                ),
            }
            for target_id, disposition in expected_dispositions.items()
        }


class _NoInventoryFactory(_ProviderFactory):
    provider_class = _NoInventorySnapshot


class _DirectSuccessForAbsentSnapshot(_SnapshotProvider):
    def read_target_observations(self, **kwargs: Any) -> dict[str, dict[str, Any]]:
        observations = super().read_target_observations(**kwargs)
        event = next(
            event
            for event in self.events
            if event["operation"] == "iam:GetRole"
        )
        event["outcome"] = "SUCCESS"
        return observations


class _DirectSuccessForAbsentFactory(_ProviderFactory):
    provider_class = _DirectSuccessForAbsentSnapshot


class _ListNotFoundSnapshot(_SnapshotProvider):
    def read_target_observations(self, **kwargs: Any) -> dict[str, dict[str, Any]]:
        observations = super().read_target_observations(**kwargs)
        event = next(
            event
            for event in self.events
            if event["operation"] == "kms:ListAliases"
        )
        event["outcome"] = "NOT_FOUND"
        return observations


class _ListNotFoundFactory(_ProviderFactory):
    provider_class = _ListNotFoundSnapshot


def _persist_request(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> tuple[Path, dict[str, Any]]:
    root = admission_data._root(tmp_path)
    lineage_root = admission_data._gug395_root(root)
    catalog = admission_data._catalog()
    catalog_bucket = str(catalog["artifact_bucket_name"])
    profiles = {
        "authority": {
            "expected_account_id": contract.AUTHORITY_ACCOUNT_ID,
            "expected_principal_digest": contract.canonical_digest(
                provider_data._principal("authority")
            ),
            "expected_sso_role_name_digest": contract.canonical_digest(
                provider_data._role("authority")
            ),
            "authority_verification_digest": contract.canonical_digest(
                {"authority": "authority"}
            ),
        },
        "identity_center": {
            "expected_account_id": contract.MANAGEMENT_ACCOUNT_ID,
            "expected_principal_digest": contract.canonical_digest(
                provider_data._principal("management")
            ),
            "expected_sso_role_name_digest": contract.canonical_digest(
                provider_data._role("management")
            ),
            "authority_verification_digest": contract.canonical_digest(
                {"authority": "management"}
            ),
        },
    }
    request395 = {
        "profiles": profiles,
        "policy_digests": {
            "authority": _digest("policy-authority"),
            "identity_center": _digest("policy-management"),
        },
        "targets": {
            "artifact_bucket": {
                "selector_kind": "ACCOUNT_REGIONAL_BUCKET_NAME_AND_TAG",
                "bucket_namespace": "account-regional",
                "name": catalog_bucket,
            }
        },
        "source_verification_digest": _digest("source-verification"),
        "private_custody_digest": contract._private_root_digest(lineage_root),
        "expires_at": admission_data._stamp(
            admission_data.NOW + timedelta(minutes=10)
        ),
    }
    evidence = {
        "request": request395,
        "request_digest": _digest("gug395-request"),
        "provider_evidence_digest": _digest("gug395-provider"),
    }
    receipt = {
        "source_commit_sha": admission_data.COMMIT,
        "source_tree_sha": admission_data.TREE,
        "sealed_at": admission_data._stamp(
            admission_data.NOW - timedelta(seconds=1)
        ),
        "receipt_digest": _digest("gug395-receipt"),
    }
    bundle = {"bundle_digest": _digest("gug395-bundle")}
    monkeypatch.setattr(
        contract,
        "_gug395_bundle",
        lambda _root: (bundle, evidence, receipt),
    )
    policy = provider_data._policy(catalog)
    request = contract.materialize_route_collision_admission_request(
        private_root=root,
        gug395_private_root=lineage_root,
        catalog=catalog,
        collision_policy_set=policy,
        phase="artifact-bridge",
        operation="bridge-create:dispatch",
        effect_request={
            "record_type": "scanalyze.test.gug376_effect_request.v1",
            "stack_name": "scanalyze-platform-authority-gug376-test",
        },
        source_commit_sha=admission_data.COMMIT,
        source_tree_sha=admission_data.TREE,
        bootstrap_intent_digest=admission_data.BOOTSTRAP_DIGEST,
        effect_private_root_digest=admission_data.EFFECT_ROOT_DIGEST,
        atomic_context_digest=admission_data.ATOMIC_CONTEXT_DIGEST,
        expected_gug395_request_digest=evidence["request_digest"],
        expected_gug395_receipt_digest=receipt["receipt_digest"],
        expected_gug395_bundle_digest=bundle["bundle_digest"],
        not_before=admission_data._stamp(
            admission_data.NOW - timedelta(minutes=1)
        ),
        expires_at=admission_data._stamp(
            admission_data.NOW + timedelta(minutes=10)
        ),
        created_at=admission_data._stamp(admission_data.NOW),
    )
    contract.persist_route_collision_admission_request(
        private_root=root,
        request=request,
    )
    return root, request


def _attested_factory(
    request: dict[str, Any],
    *,
    reuse_sdk_session: bool = False,
) -> Any:
    policy = provider_data._policy(dict(request["catalog"]))
    return provider_data.Harness(
        policy,
        reuse_sdk_session=reuse_sdk_session,
    ).factory


def test_executes_two_independent_and_one_pre_effect_snapshot_create_only(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    root, request = _persist_request(monkeypatch, tmp_path)
    provider = _attested_factory(request)

    result = executor.execute_route_collision_admission(
        provider_factory=provider,
        private_root=root,
        expected_request_digest=str(request["request_digest"]),
        clock=_Clock(),
    )

    assert len(result.private_evidence["snapshots"]) == 3
    assert result.public_receipt["action_time_recheck_present"] is True
    assert result.public_receipt["aws_mutations"] == 0
    assert contract.read_private_json(root, contract.DEFAULT_RESULT_FILE)[
        "public_receipt"
    ] == result.public_receipt

    with pytest.raises(contract.RouteCollisionAdmissionError):
        executor.execute_route_collision_admission(
            provider_factory=_attested_factory(request),
            private_root=root,
            expected_request_digest=str(request["request_digest"]),
            clock=_Clock(),
        )


def test_unattested_factory_is_rejected_before_claim(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    root, request = _persist_request(monkeypatch, tmp_path)

    with pytest.raises(
        contract.RouteCollisionAdmissionError,
        match="ROUTE_COLLISION_PROVIDER_NOT_ATTESTED",
    ):
        executor.execute_route_collision_admission(
            provider_factory=_ProviderFactory(mutating_capture=2),
            private_root=root,
            expected_request_digest=str(request["request_digest"]),
            clock=_Clock(),
        )

    assert not (root / contract.DEFAULT_CLAIM_FILE).exists()
    assert not (root / contract.DEFAULT_RESULT_FILE).exists()


def test_unattested_subclass_is_rejected_without_invocation(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    root, request = _persist_request(monkeypatch, tmp_path)

    class _BrokenFactory(_ProviderFactory):
        def open_snapshot(self, **kwargs: Any) -> _SnapshotProvider:
            raise RuntimeError("sensitive provider response")

    with pytest.raises(
        contract.RouteCollisionAdmissionError,
        match="ROUTE_COLLISION_PROVIDER_NOT_ATTESTED",
    ) as captured:
        executor.execute_route_collision_admission(
            provider_factory=_BrokenFactory(),
            private_root=root,
            expected_request_digest=str(request["request_digest"]),
            clock=_Clock(),
        )

    assert "sensitive" not in str(captured.value).lower()
    assert not (root / contract.DEFAULT_CLAIM_FILE).exists()
    assert not (root / contract.DEFAULT_RESULT_FILE).exists()


def test_unattested_provider_error_code_cannot_cross_executor_boundary(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    root, request = _persist_request(monkeypatch, tmp_path)

    class _ForgedCodeFactory(_ProviderFactory):
        def open_snapshot(self, **kwargs: Any) -> _SnapshotProvider:
            raise contract.RouteCollisionAdmissionError(
                "UNTRUSTED_PROVIDER_DETAIL"
            )

    with pytest.raises(
        contract.RouteCollisionAdmissionError,
        match="ROUTE_COLLISION_PROVIDER_NOT_ATTESTED",
    ) as captured:
        executor.execute_route_collision_admission(
            provider_factory=_ForgedCodeFactory(),
            private_root=root,
            expected_request_digest=str(request["request_digest"]),
            clock=_Clock(),
        )

    assert "untrusted" not in str(captured.value).lower()


def test_unattested_factory_cannot_bypass_inventory_contract(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    root, request = _persist_request(monkeypatch, tmp_path)

    with pytest.raises(
        contract.RouteCollisionAdmissionError,
        match="ROUTE_COLLISION_PROVIDER_NOT_ATTESTED",
    ):
        executor.execute_route_collision_admission(
            provider_factory=_NoInventoryFactory(),
            private_root=root,
            expected_request_digest=str(request["request_digest"]),
            clock=_Clock(),
        )


@pytest.mark.parametrize(
    "provider_factory",
    [_DirectSuccessForAbsentFactory, _ListNotFoundFactory],
)
def test_unattested_factory_cannot_override_absence_semantics(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    provider_factory: type[_ProviderFactory],
) -> None:
    root, request = _persist_request(monkeypatch, tmp_path)

    with pytest.raises(
        contract.RouteCollisionAdmissionError,
        match="ROUTE_COLLISION_PROVIDER_NOT_ATTESTED",
    ):
        executor.execute_route_collision_admission(
            provider_factory=provider_factory(),
            private_root=root,
            expected_request_digest=str(request["request_digest"]),
            clock=_Clock(),
        )


def test_reused_sdk_session_is_sanitized_and_rejected(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    root, request = _persist_request(monkeypatch, tmp_path)

    with pytest.raises(
        contract.RouteCollisionAdmissionError,
        match="ROUTE_COLLISION_PROVIDER_FAILED",
    ):
        executor.execute_route_collision_admission(
            provider_factory=_attested_factory(
                request,
                reuse_sdk_session=True,
            ),
            private_root=root,
            expected_request_digest=str(request["request_digest"]),
            clock=_Clock(),
        )


def test_expiry_before_pre_effect_snapshot_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    root, request = _persist_request(monkeypatch, tmp_path)
    times = [
        admission_data.NOW,
        admission_data.NOW,
        admission_data.NOW + timedelta(seconds=1),
        admission_data.NOW + timedelta(seconds=2),
        admission_data.NOW + timedelta(seconds=3),
        admission_data.NOW + timedelta(seconds=4),
        admission_data.NOW + timedelta(minutes=11),
    ]

    with pytest.raises(
        contract.RouteCollisionAdmissionError,
        match="ROUTE_COLLISION_REQUEST_NOT_ACTIVE",
    ):
        executor.execute_route_collision_admission(
            provider_factory=_attested_factory(request),
            private_root=root,
            expected_request_digest=str(request["request_digest"]),
            clock=_Clock(times),
        )

    assert not (root / contract.DEFAULT_RESULT_FILE).exists()


def test_attested_factory_policy_must_match_private_request(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    root, request = _persist_request(monkeypatch, tmp_path)

    mismatched_catalog = catalog_contract.materialize_route_collision_catalog(
        source_commit_sha=admission_data.COMMIT,
        source_tree_sha="d" * 40,
        bootstrap_intent_digest=admission_data.BOOTSTRAP_DIGEST,
        not_before=admission_data._stamp(
            admission_data.NOW - timedelta(minutes=1)
        ),
        expires_at=admission_data._stamp(
            admission_data.NOW + timedelta(minutes=10)
        ),
        artifact_bucket_name=str(request["catalog"]["artifact_bucket_name"]),
    )
    inventory_policy = policy_contract.materialize_route_collision_policy_set(
        mismatched_catalog
    )
    provider = provider_data.Harness(inventory_policy).factory

    with pytest.raises(
        contract.RouteCollisionAdmissionError,
        match="ROUTE_COLLISION_PROVIDER_ATTESTATION_INVALID",
    ):
        executor.execute_route_collision_admission(
            provider_factory=provider,
            private_root=root,
            expected_request_digest=str(request["request_digest"]),
            clock=_Clock(),
        )


def test_executor_source_has_no_direct_sdk_dependency() -> None:
    source = Path(executor.__file__).read_text(encoding="utf-8")

    assert "import boto3" not in source
    assert "from boto3" not in source
    assert "client(" not in source
