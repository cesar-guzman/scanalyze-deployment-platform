"""Mode-bound session tests for atomic GUG-376 collision admission."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from tests.test_deployment import test_gug376_collision_policy as policy_data
from tests.test_deployment import (
    test_gug395_preplan_collision_probe as gug395_data,
)
from tooling.platform_authority_gug365_upstream_inventory import canonical_digest
from tooling import platform_authority_gug376_collision_budget as budget_contract
from tooling import platform_authority_gug376_collision_direct_sso as subject
from tooling import platform_authority_gug376_collision_policy as policy
from tooling import platform_authority_gug395_preplan_collision_probe as gug395


class _SessionFactory:
    def __init__(self) -> None:
        self.source_sessions: list[object] = []
        self.read_sessions: list[object] = []

    def __call__(self, **kwargs: Any) -> object:
        session = SimpleNamespace(parameters=dict(kwargs))
        if "profile_name" in kwargs:
            self.source_sessions.append(session)
        else:
            self.read_sessions.append(session)
        return session


def _root(tmp_path: Path) -> tuple[Path, dict[str, Any]]:
    root = tmp_path / "admission"
    root.mkdir(mode=0o700)
    root.chmod(0o700)
    request, claim = gug395_data._write_result_custody(root)  # noqa: SLF001
    result = gug395_data._build_success_result(request=request)  # noqa: SLF001
    gug395.persist_collision_probe_result(
        private_root=root,
        result=result,
        expected_claim_digest=claim["claim_digest"],
    )
    return root.resolve(strict=True), request


def _catalog(
    request: dict[str, Any],
    *,
    not_before: str | None = None,
    expires_at: str | None = None,
) -> dict[str, Any]:
    return policy_data.catalog_contract.materialize_route_collision_catalog(
        source_commit_sha=request["source_commit_sha"],
        source_tree_sha=request["source_tree_sha"],
        bootstrap_intent_digest=canonical_digest({"intent": "gug376"}),
        not_before=not_before or request["not_before"],
        expires_at=expires_at or request["expires_at"],
        artifact_bucket_name=request["targets"]["artifact_bucket"]["name"],
    )


def _lineage(root: Path) -> dict[str, str]:
    bundle, evidence, receipt = subject.admission._gug395_bundle(  # noqa: SLF001
        root
    )
    return {
        "expected_gug395_request_digest": str(evidence["request_digest"]),
        "expected_gug395_receipt_digest": str(receipt["receipt_digest"]),
        "expected_gug395_bundle_digest": str(bundle["bundle_digest"]),
    }


def _install_sdk_fakes(
    monkeypatch: pytest.MonkeyPatch,
    factory: _SessionFactory,
    *,
    vend: bool,
    credential_expiry: datetime = datetime(2026, 8, 28, 1, 30, tzinfo=UTC),
) -> None:
    loaded = SimpleNamespace(
        session_factory=factory,
        config_factory=lambda **kwargs: SimpleNamespace(**kwargs),
        guard=lambda: None,
    )
    monkeypatch.setattr(subject.live, "_load_sdk", lambda _root: loaded)

    def validate(
        _session: object,
        *,
        profile_name: str,
        credential_vend_recorder: Any,
        **_kwargs: Any,
    ) -> tuple[datetime, str, object]:
        assert credential_expiry >= _kwargs["required_end"]
        if vend:
            credential_vend_recorder("sso:GetRoleCredentials")
        domain = "authority" if profile_name.startswith("042") else "management"
        frozen = SimpleNamespace(
            access_key=f"SYNTHETIC_{domain}_ACCESS",
            secret_key=f"SYNTHETIC_{domain}_SECRET",
            token=f"SYNTHETIC_{domain}_TOKEN",
        )
        return (
            credential_expiry,
            canonical_digest({"source_profile": profile_name}),
            frozen,
        )

    monkeypatch.setattr(subject.live, "_validate_direct_sso_profile", validate)
    monkeypatch.setattr(
        subject.live,
        "_profile_document",
        lambda _session, profile_name: (
            {},
            {
                "sso_role_name": (
                    "AuthorityReadOnly"
                    if profile_name.startswith("042")
                    else "ManagementReadOnly"
                )
            },
        ),
    )


def _kms_binding(request: dict[str, Any]) -> tuple[str, str]:
    instance_arn = request["targets"]["identity_center_application"][
        "instance_arn"
    ]
    key_arn = (
        "arn:aws:kms:us-east-1:839393571433:key/"
        "12345678-abcd-1234-abcd-1234567890ab"
    )
    return key_arn, canonical_digest(
        {
            "binding_name": "identity_center_kms_key_arn",
            "identity_center_instance_arn": instance_arn,
            "mode": "CUSTOMER_MANAGED_KEY",
            "key_arn": key_arn,
        }
    )


@pytest.mark.parametrize("vend", (False, True))
def test_pre_reader_mode_uses_two_source_bindings_for_ten_fresh_sdk_sessions(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    vend: bool,
) -> None:
    root, request = _root(tmp_path)
    catalog = _catalog(request)
    factory = _SessionFactory()
    _install_sdk_fakes(monkeypatch, factory, vend=vend)
    budget = budget_contract.build_collision_budget(
        session_mode=budget_contract.LOCAL_DIRECT_SSO,
        operation="route:create-change-set",
    )
    now = datetime(2026, 8, 28, 1, 10, tzinfo=UTC)
    key_arn, kms_binding_digest = _kms_binding(request)
    opener_factory = subject.build_direct_sso_policy_session_opener_factory(
        private_root=root,
        **_lineage(root),
        catalog=catalog,
        environment={},
        clock=lambda: now,
        expires_at=request["expires_at"],
        identity_center_instance_arn=request["targets"][
            "identity_center_application"
        ]["instance_arn"],
        identity_center_kms_mode="CUSTOMER_MANAGED_KEY",
        identity_center_kms_key_arn=key_arn,
        identity_center_kms_binding_digest=kms_binding_digest,
    )
    inventory = policy.materialize_route_collision_policy_set(catalog)
    candidate = policy_data._structural_candidate_policy(  # noqa: SLF001
        catalog,
        policy_data._discovery_evidence(catalog),  # noqa: SLF001
    )
    opened = []
    for policy_set, purposes in (
        (
            inventory,
            {
                1: "policy-discovery-independent-scan-1",
                2: "policy-discovery-independent-scan-2",
            },
        ),
        (
            candidate,
            {
                1: "independent-snapshot-1",
                2: "independent-snapshot-2",
                3: "pre-effect-snapshot",
            },
        ),
    ):
        opener = opener_factory(
            policy_set,
            budget,
            subject.LOCAL_DIRECT_SSO,
        )
        for capture_index, purpose in purposes.items():
            for domain, account in (
                ("authority", gug395_data.AUTHORITY_ACCOUNT),
                ("management", gug395_data.IDENTITY_ACCOUNT),
            ):
                opened.append(
                    opener(
                        domain=domain,
                        expected_account_id=account,
                        region="us-east-1",
                        capture_index=capture_index,
                        purpose=purpose,
                    )
                )

    assert len(opened) == 10
    assert len({id(item.sdk_session) for item in opened}) == 10
    assert len({item.session_nonce_digest for item in opened}) == 10
    assert {item.source for item in opened} == {"DIRECT_SSO"}
    assert {item.chain_depth for item in opened} == {0}
    assert all(item.role_arn is None for item in opened)
    assert all(item.session_policy_digest is None for item in opened)
    assert len(factory.source_sessions) == 2
    assert len(factory.read_sessions) == 10
    summary = budget.complete(transcript_events=[])
    events = budget.evidence_events()
    assert summary["session_mode"] == budget_contract.LOCAL_DIRECT_SSO
    assert summary["session_open_count"] == 10
    assert summary["direct_sso_session_opens"] == 10
    assert summary["assume_role_opens"] == 0
    assert summary["source_credential_bindings"] == 2
    assert summary["source_credential_vends"] == (2 if vend else 0)
    assert len([item for item in events if item["kind"] == "SESSION_OPEN"]) == 10
    assert len(
        [
            item
            for item in events
            if item["kind"] == "SOURCE_CREDENTIAL_BINDING"
        ]
    ) == 2


def test_direct_sso_adapter_cannot_self_select_post_reader_runtime(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root, request = _root(tmp_path)
    catalog = _catalog(request)
    factory = _SessionFactory()
    _install_sdk_fakes(monkeypatch, factory, vend=False)
    key_arn, kms_binding_digest = _kms_binding(request)
    opener_factory = subject.build_direct_sso_policy_session_opener_factory(
        private_root=root,
        **_lineage(root),
        catalog=catalog,
        environment={},
        clock=lambda: datetime(2026, 8, 28, 1, 10, tzinfo=UTC),
        expires_at=request["expires_at"],
        identity_center_instance_arn=request["targets"][
            "identity_center_application"
        ]["instance_arn"],
        identity_center_kms_mode="CUSTOMER_MANAGED_KEY",
        identity_center_kms_key_arn=key_arn,
        identity_center_kms_binding_digest=kms_binding_digest,
    )

    with pytest.raises(
        subject.DirectSsoCollisionAdapterError,
        match="COLLISION_DIRECT_SSO_MODE_FORBIDDEN",
    ):
        opener_factory(
            policy.materialize_route_collision_policy_set(catalog),
            budget_contract.build_collision_budget(
                session_mode=budget_contract.POST_READER_RUNTIME,
                operation="broker-protection:create-change-set",
            ),
            "POST_READER_RUNTIME",
        )
    assert factory.source_sessions == []
    assert factory.read_sessions == []


def test_direct_sso_adapter_uses_fresh_effect_window_after_baseline_expiry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root, request = _root(tmp_path)
    catalog = _catalog(
        request,
        not_before="2026-08-28T02:00:00Z",
        expires_at="2026-08-28T02:10:00Z",
    )
    factory = _SessionFactory()
    _install_sdk_fakes(
        monkeypatch,
        factory,
        vend=False,
        credential_expiry=datetime(2026, 8, 28, 3, 0, tzinfo=UTC),
    )
    key_arn, kms_binding_digest = _kms_binding(request)

    opener_factory = subject.build_direct_sso_policy_session_opener_factory(
        private_root=root,
        **_lineage(root),
        catalog=catalog,
        environment={},
        clock=lambda: datetime(2026, 8, 28, 2, 1, tzinfo=UTC),
        expires_at="2026-08-28T02:10:00Z",
        identity_center_instance_arn=request["targets"][
            "identity_center_application"
        ]["instance_arn"],
        identity_center_kms_mode="CUSTOMER_MANAGED_KEY",
        identity_center_kms_key_arn=key_arn,
        identity_center_kms_binding_digest=kms_binding_digest,
    )

    budget = budget_contract.build_collision_budget(
        session_mode=budget_contract.LOCAL_DIRECT_SSO,
        operation="foundation-create:dispatch",
    )
    opener = opener_factory(
        policy.materialize_route_collision_policy_set(catalog),
        budget,
        subject.LOCAL_DIRECT_SSO,
    )
    opened = opener(
        domain="authority",
        expected_account_id=gug395_data.AUTHORITY_ACCOUNT,
        region="us-east-1",
        capture_index=1,
        purpose="policy-discovery-independent-scan-1",
    )

    assert opened.source == "DIRECT_SSO"
    assert len(factory.source_sessions) == 1
    assert len(factory.read_sessions) == 1


def test_direct_sso_adapter_rejects_collision_blocked_baseline(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "admission"
    root.mkdir(mode=0o700)
    root.chmod(0o700)
    request, claim = gug395_data._write_result_custody(root)  # noqa: SLF001
    result = gug395_data._build_success_result(  # noqa: SLF001
        request=request,
        authority_collisions=["artifact_bucket"],
    )
    gug395.persist_collision_probe_result(
        private_root=root,
        result=result,
        expected_claim_digest=claim["claim_digest"],
    )
    catalog = _catalog(request)
    factory = _SessionFactory()
    _install_sdk_fakes(monkeypatch, factory, vend=False)
    key_arn, kms_binding_digest = _kms_binding(request)
    raw = gug395.read_collision_probe_result(private_root=root)
    bundle = subject.admission.read_private_json(
        root,
        gug395.DEFAULT_RESULT_FILE,
    )
    lineage = {
        "expected_gug395_request_digest": str(
            raw.private_evidence["request_digest"]
        ),
        "expected_gug395_receipt_digest": str(
            raw.public_receipt["receipt_digest"]
        ),
        "expected_gug395_bundle_digest": str(bundle["bundle_digest"]),
    }

    with pytest.raises(
        subject.DirectSsoCollisionAdapterError,
        match="COLLISION_DIRECT_SSO_GUG395_INVALID",
    ):
        subject.build_direct_sso_policy_session_opener_factory(
            private_root=root.resolve(strict=True),
            **lineage,
            catalog=catalog,
            environment={},
            clock=lambda: datetime(2026, 8, 28, 1, 10, tzinfo=UTC),
            expires_at=request["expires_at"],
            identity_center_instance_arn=request["targets"][
                "identity_center_application"
            ]["instance_arn"],
            identity_center_kms_mode="CUSTOMER_MANAGED_KEY",
            identity_center_kms_key_arn=key_arn,
            identity_center_kms_binding_digest=kms_binding_digest,
        )
    assert factory.source_sessions == []
    assert factory.read_sessions == []
