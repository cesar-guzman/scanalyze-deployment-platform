"""Create-only private context for the atomic GUG-376 collision loader."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
import re
from pathlib import Path
from typing import Any

from tooling.platform_authority_gug365_upstream_inventory import canonical_digest
from tooling.platform_authority_gug376_authority_inventory_collector import (
    private_target_absent,
    read_private_json,
    write_private_json,
)
from tooling import platform_authority_gug376_collision_admission as admission
from tooling.platform_authority_gug376_collision_atomic_admission import (
    AtomicCollisionAdmissionConfig,
    build_atomic_route_collision_admission_loader,
)
from tooling.platform_authority_gug376_collision_catalog import (
    materialize_route_collision_catalog,
    validate_route_collision_catalog,
)
from tooling.platform_authority_gug376_collision_direct_sso import (
    LOCAL_DIRECT_SSO,
    build_direct_sso_policy_session_opener_factory,
)
from tooling.platform_authority_gug395_preplan_collision_probe import (
    ABSENT_READY as GUG395_ABSENT_READY,
    DEFAULT_RESULT_FILE as GUG395_RESULT_FILE,
    read_collision_probe_result,
)


CONTEXT_FILE = "gug376-route-collision-atomic-context.json"
CONTEXT_TYPE = (
    "scanalyze.platform_authority.gug376_route_collision_atomic_context.v2"
)
PRIVATE_BINDINGS_TYPE = (
    "scanalyze.platform_authority.gug376_route_collision_private_bindings.v2"
)
PRIVATE_BINDINGS_SOURCE = "GUG395_ATTESTED_PREPLAN_COLLISION_RESULT"
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_INSTANCE = re.compile(r"^arn:aws:sso:::instance/ssoins-[A-Za-z0-9.-]{16}$")
_STORE = re.compile(r"^d-[A-Za-z0-9]{10}$")
_KMS = re.compile(
    r"^arn:aws:kms:us-east-1:839393571433:key/"
    r"(?:[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}|"
    r"mrk-[0-9a-f]{32})$"
)
_TIME = re.compile(
    r"^20[0-9]{2}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12][0-9]|3[01])T"
    r"(?:[01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]Z$"
)
_MAX_EFFECT_WINDOW = timedelta(minutes=15)


class AtomicCollisionContextError(RuntimeError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def _fail(code: str) -> None:
    raise AtomicCollisionContextError(code)


def _root_digest(root: Path) -> str:
    try:
        supplied = Path(root)
        resolved = supplied.resolve(strict=True)
        mode = resolved.stat().st_mode & 0o777
        if (
            not supplied.is_absolute()
            or supplied.is_symlink()
            or supplied != resolved
            or not resolved.is_dir()
            or mode != 0o700
        ):
            raise ValueError
        return admission._private_root_digest(resolved)  # noqa: SLF001
    except Exception:
        raise AtomicCollisionContextError(
            "ATOMIC_COLLISION_CONTEXT_ROOT_INVALID"
        ) from None


def _parse_time(value: object) -> datetime:
    if not isinstance(value, str) or _TIME.fullmatch(value) is None:
        _fail("ATOMIC_COLLISION_WINDOW_INVALID")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        _fail("ATOMIC_COLLISION_WINDOW_INVALID")
    normalized = parsed.astimezone(UTC).replace(microsecond=0)
    if normalized.isoformat().replace("+00:00", "Z") != value:
        _fail("ATOMIC_COLLISION_WINDOW_INVALID")
    return normalized


def _active_effect_window(
    *,
    not_before: object,
    expires_at: object,
    clock: Any,
) -> tuple[str, str]:
    if not callable(clock):
        _fail("ATOMIC_COLLISION_WINDOW_INVALID")
    start = _parse_time(not_before)
    end = _parse_time(expires_at)
    try:
        observed = clock()
    except Exception:
        raise AtomicCollisionContextError(
            "ATOMIC_COLLISION_WINDOW_INVALID"
        ) from None
    if not isinstance(observed, datetime) or observed.tzinfo is None:
        _fail("ATOMIC_COLLISION_WINDOW_INVALID")
    now = observed.astimezone(UTC).replace(microsecond=0)
    if not start <= now < end or end - start > _MAX_EFFECT_WINDOW:
        _fail("ATOMIC_COLLISION_WINDOW_INVALID")
    return (
        start.isoformat().replace("+00:00", "Z"),
        end.isoformat().replace("+00:00", "Z"),
    )


def _validate_bindings(value: object) -> dict[str, Any]:
    fields = {
        "record_type",
        "schema_version",
        "source",
        "identity_center_instance_arn",
        "identity_center_kms_mode",
        "identity_center_kms_key_arn",
        "identity_center_kms_binding_digest",
        "gug395_private_root_digest",
        "gug395_request_digest",
        "gug395_receipt_digest",
        "gug395_bundle_digest",
        "identity_center_snapshot_digests",
        "identity_authority_verification_digest",
        "external_verification_digest",
        "binding_digest",
    }
    if not isinstance(value, Mapping) or set(value) != fields:
        _fail("ATOMIC_COLLISION_PRIVATE_BINDINGS_INVALID")
    mode = value.get("identity_center_kms_mode")
    key = value.get("identity_center_kms_key_arn")
    if (
        value.get("record_type") != PRIVATE_BINDINGS_TYPE
        or value.get("schema_version") != 2
        or value.get("source") != PRIVATE_BINDINGS_SOURCE
        or _INSTANCE.fullmatch(
            str(value.get("identity_center_instance_arn"))
        )
        is None
        or mode not in {"AWS_OWNED_KMS_KEY", "CUSTOMER_MANAGED_KEY"}
        or (mode == "AWS_OWNED_KMS_KEY" and key is not None)
        or (mode == "CUSTOMER_MANAGED_KEY" and _KMS.fullmatch(str(key)) is None)
        or _DIGEST.fullmatch(
            str(value.get("identity_center_kms_binding_digest"))
        )
        is None
        or any(
            _DIGEST.fullmatch(str(value.get(field))) is None
            for field in (
                "gug395_private_root_digest",
                "gug395_request_digest",
                "gug395_receipt_digest",
                "gug395_bundle_digest",
                "identity_authority_verification_digest",
            )
        )
        or not isinstance(value.get("identity_center_snapshot_digests"), list)
        or len(value["identity_center_snapshot_digests"]) != 2
        or len(set(value["identity_center_snapshot_digests"])) != 2
        or any(
            not isinstance(item, str) or _DIGEST.fullmatch(item) is None
            for item in value["identity_center_snapshot_digests"]
        )
        or _DIGEST.fullmatch(
            str(value.get("external_verification_digest"))
        )
        is None
    ):
        _fail("ATOMIC_COLLISION_PRIVATE_BINDINGS_INVALID")
    checked = dict(value)
    supplied = checked.pop("binding_digest", None)
    if supplied != canonical_digest(checked):
        _fail("ATOMIC_COLLISION_PRIVATE_BINDINGS_INVALID")
    checked["binding_digest"] = supplied
    return checked


def _validate_distinct_roots(
    admission_private_root: Path,
    effect_private_root: Path,
    gug395_private_root: Path,
) -> None:
    try:
        admission = Path(admission_private_root).resolve(strict=True)
        effect = Path(effect_private_root).resolve(strict=True)
        gug395 = Path(gug395_private_root).resolve(strict=True)
        _root_digest(admission_private_root)
        _root_digest(effect_private_root)
        _root_digest(gug395_private_root)
        roots = {
            admission,
            effect,
            gug395,
        }
    except AtomicCollisionContextError:
        raise
    except OSError:
        _fail("ATOMIC_COLLISION_CONTEXT_ROOT_INVALID")
    if len(roots) != 3:
        _fail("ATOMIC_COLLISION_ROOT_REUSE_FORBIDDEN")


def _gug395_evidence(
    private_root: Path,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    try:
        bundle = read_private_json(private_root, GUG395_RESULT_FILE)
        result = read_collision_probe_result(private_root=private_root)
        request = dict(result.private_evidence["request"])
        receipt = dict(result.public_receipt)
    except Exception:
        raise AtomicCollisionContextError(
            "ATOMIC_COLLISION_GUG395_RESULT_INVALID"
        ) from None
    targets = request.get("targets")
    artifact = targets.get("artifact_bucket") if isinstance(targets, Mapping) else None
    selectors = (
        targets.get("identity_center_application"),
        targets.get("classifier_permission_set"),
        targets.get("approver_permission_set"),
    ) if isinstance(targets, Mapping) else ()
    instances = {
        item.get("instance_arn")
        for item in selectors
        if isinstance(item, Mapping)
    }
    if (
        request.get("private_custody_digest") != _root_digest(private_root)
        or receipt.get("classification") != GUG395_ABSENT_READY
        or receipt.get("read_only") is not True
        or receipt.get("aws_mutations") != 0
        or not isinstance(artifact, Mapping)
        or not isinstance(artifact.get("name"), str)
        or len(selectors) != 3
        or len(instances) != 1
        or _INSTANCE.fullmatch(str(next(iter(instances), ""))) is None
        or not isinstance(bundle, Mapping)
        or bundle.get("private_evidence") != result.private_evidence
        or bundle.get("public_receipt") != result.public_receipt
        or _DIGEST.fullmatch(str(bundle.get("bundle_digest"))) is None
    ):
        _fail("ATOMIC_COLLISION_GUG395_RESULT_INVALID")
    return request, receipt, dict(bundle)


def _derive_gug395_bindings(
    *,
    gug395_private_root: Path,
    gug395_request: Mapping[str, Any],
    gug395_receipt: Mapping[str, Any],
    gug395_bundle: Mapping[str, Any],
) -> dict[str, Any]:
    profiles = gug395_request.get("profiles")
    gug395_targets = gug395_request.get("targets")
    identity_profile = (
        profiles.get("identity_center")
        if isinstance(profiles, Mapping)
        else None
    )
    selectors = gug395_targets
    selector_instances = {
        selectors[name].get("instance_arn")
        for name in (
            "identity_center_application",
            "classifier_permission_set",
            "approver_permission_set",
        )
        if isinstance(selectors, Mapping)
        and isinstance(selectors.get(name), Mapping)
    }
    instance_arn = next(iter(selector_instances), None)
    private_evidence = gug395_bundle.get("private_evidence")
    snapshots = (
        private_evidence.get("identity_center_snapshots")
        if isinstance(private_evidence, Mapping)
        else None
    )
    mode = (
        identity_profile.get("identity_center_kms_mode")
        if isinstance(identity_profile, Mapping)
        else None
    )
    key_arn = (
        identity_profile.get("identity_center_kms_key_arn")
        if isinstance(identity_profile, Mapping)
        else None
    )
    verification_digest = (
        identity_profile.get("authority_verification_digest")
        if isinstance(identity_profile, Mapping)
        else None
    )
    if (
        not isinstance(identity_profile, Mapping)
        or _INSTANCE.fullmatch(str(instance_arn)) is None
        or selector_instances != {instance_arn}
        or mode not in {"AWS_OWNED_KMS_KEY", "CUSTOMER_MANAGED_KEY"}
        or (mode == "AWS_OWNED_KMS_KEY" and key_arn is not None)
        or (mode == "CUSTOMER_MANAGED_KEY" and _KMS.fullmatch(str(key_arn)) is None)
        or _DIGEST.fullmatch(str(verification_digest)) is None
        or not isinstance(snapshots, list)
        or len(snapshots) != 2
    ):
        _fail("ATOMIC_COLLISION_GUG395_KMS_BINDING_INVALID")

    snapshot_digests: list[str] = []
    described_instances: list[dict[str, Any]] = []
    for snapshot in snapshots:
        facts = snapshot.get("facts") if isinstance(snapshot, Mapping) else None
        described = facts.get("described_instance") if isinstance(facts, Mapping) else None
        encryption = (
            described.get("EncryptionConfigurationDetails")
            if isinstance(described, Mapping)
            else None
        )
        observed_mode = (
            encryption.get("KeyType") if isinstance(encryption, Mapping) else None
        )
        normalized_mode = observed_mode
        observed_key = (
            encryption.get("KmsKeyArn")
            if isinstance(encryption, Mapping)
            else None
        )
        snapshot_digest = (
            snapshot.get("snapshot_digest")
            if isinstance(snapshot, Mapping)
            else None
        )
        identity = snapshot.get("identity") if isinstance(snapshot, Mapping) else None
        if (
            not isinstance(described, Mapping)
            or described.get("InstanceArn") != instance_arn
            or _STORE.fullmatch(str(described.get("IdentityStoreId"))) is None
            or described.get("OwnerAccountId")
            != identity_profile.get("expected_account_id")
            or described.get("Status") != "ACTIVE"
            or not isinstance(encryption, Mapping)
            or encryption.get("EncryptionStatus") != "ENABLED"
            or normalized_mode != mode
            or observed_key != key_arn
            or _DIGEST.fullmatch(str(snapshot_digest)) is None
            or not isinstance(identity, Mapping)
            or identity.get("authority_verification_digest")
            != verification_digest
        ):
            _fail("ATOMIC_COLLISION_GUG395_KMS_BINDING_INVALID")
        snapshot_digests.append(str(snapshot_digest))
        described_instances.append(dict(described))
    if (
        len(set(snapshot_digests)) != 2
        or canonical_digest(described_instances[0])
        != canonical_digest(described_instances[1])
    ):
        _fail("ATOMIC_COLLISION_GUG395_KMS_BINDING_INVALID")

    kms_binding_digest = canonical_digest(
        {
            "binding_name": "identity_center_kms_key_arn",
            "identity_center_instance_arn": instance_arn,
            "mode": mode,
            "key_arn": key_arn,
        }
    )
    external_verification_digest = canonical_digest(
        {
            "gug395_private_root_digest": _root_digest(gug395_private_root),
            "gug395_request_digest": gug395_request["request_digest"],
            "gug395_receipt_digest": gug395_receipt["receipt_digest"],
            "gug395_bundle_digest": gug395_bundle["bundle_digest"],
            "identity_center_snapshot_digests": snapshot_digests,
            "identity_authority_verification_digest": verification_digest,
        }
    )
    body: dict[str, Any] = {
        "record_type": PRIVATE_BINDINGS_TYPE,
        "schema_version": 2,
        "source": PRIVATE_BINDINGS_SOURCE,
        "identity_center_instance_arn": instance_arn,
        "identity_center_kms_mode": mode,
        "identity_center_kms_key_arn": key_arn,
        "identity_center_kms_binding_digest": kms_binding_digest,
        "gug395_private_root_digest": _root_digest(gug395_private_root),
        "gug395_request_digest": gug395_request["request_digest"],
        "gug395_receipt_digest": gug395_receipt["receipt_digest"],
        "gug395_bundle_digest": gug395_bundle["bundle_digest"],
        "identity_center_snapshot_digests": snapshot_digests,
        "identity_authority_verification_digest": verification_digest,
        "external_verification_digest": external_verification_digest,
    }
    body["binding_digest"] = canonical_digest(body)
    return _validate_bindings(body)


def _build_expected_pre_reader_identity_bindings_factory(
    *,
    expected_gug395_request_digest: str,
    expected_gug395_receipt_digest: str,
    expected_gug395_bundle_digest: str,
) -> Any:
    """Bind every identity projection to one exact GUG-395 snapshot."""

    expected = (
        expected_gug395_request_digest,
        expected_gug395_receipt_digest,
        expected_gug395_bundle_digest,
    )
    if any(_DIGEST.fullmatch(value) is None for value in expected):
        _fail("ATOMIC_COLLISION_GUG395_LINEAGE_INVALID")

    def expected_bindings(
        *,
        private_root: Path,
        collision_policy_set: Mapping[str, Any],
        session_mode: str = LOCAL_DIRECT_SSO,
    ) -> Mapping[str, Any]:
        if session_mode != LOCAL_DIRECT_SSO:
            _fail("ATOMIC_COLLISION_SESSION_MODE_FORBIDDEN")
        digest = collision_policy_set.get("policy_set_digest")
        if not isinstance(digest, str) or _DIGEST.fullmatch(digest) is None:
            _fail("ATOMIC_COLLISION_POLICY_BINDING_INVALID")
        try:
            bundle, evidence, receipt = admission._gug395_bundle(  # noqa: SLF001
                private_root
            )
        except Exception:
            raise AtomicCollisionContextError(
                "ATOMIC_COLLISION_GUG395_LINEAGE_INVALID"
            ) from None
        if (
            evidence.get("request_digest")
            != expected_gug395_request_digest
            or receipt.get("receipt_digest")
            != expected_gug395_receipt_digest
            or bundle.get("bundle_digest")
            != expected_gug395_bundle_digest
        ):
            _fail("ATOMIC_COLLISION_GUG395_LINEAGE_CHANGED")
        request395 = evidence.get("request")
        if not isinstance(request395, Mapping):
            _fail("ATOMIC_COLLISION_GUG395_LINEAGE_INVALID")
        try:
            return admission.expected_route_collision_identity_bindings(
                request395,
                collision_policy_set_digest=digest,
            )
        except Exception:
            raise AtomicCollisionContextError(
                "ATOMIC_COLLISION_IDENTITY_BINDING_INVALID"
            ) from None

    return expected_bindings


def materialize_atomic_collision_context(
    *,
    admission_private_root: Path,
    effect_private_root: Path,
    gug395_private_root: Path,
    bootstrap_intent_digest: str,
    approval_reference_digest: str,
    approved_operation: str,
    authorized_at: str,
    expires_at: str,
    clock: Any = lambda: datetime.now(UTC),
) -> dict[str, Any]:
    """Create one effect context from immutable GUG-395 baseline lineage."""

    _validate_distinct_roots(
        admission_private_root,
        effect_private_root,
        gug395_private_root,
    )
    admission_digest = _root_digest(admission_private_root)
    effect_digest = _root_digest(effect_private_root)
    gug395_digest = _root_digest(gug395_private_root)
    if _DIGEST.fullmatch(bootstrap_intent_digest) is None:
        _fail("ATOMIC_COLLISION_BOOTSTRAP_BINDING_INVALID")
    if _DIGEST.fullmatch(approval_reference_digest) is None:
        _fail("ATOMIC_COLLISION_APPROVAL_REFERENCE_INVALID")
    try:
        admission.route_collision_operation_phase(approved_operation)
        admission.collision_session_mode_for_operation(
            approved_operation,
            execution_locus=admission.LOCAL_ATOMIC_CLI,
        )
    except Exception:
        raise AtomicCollisionContextError(
            "ATOMIC_COLLISION_APPROVED_OPERATION_INVALID"
        ) from None
    active_not_before, active_expires_at = _active_effect_window(
        not_before=authorized_at,
        expires_at=expires_at,
        clock=clock,
    )
    request395, receipt395, bundle395 = _gug395_evidence(
        gug395_private_root
    )
    bindings = _derive_gug395_bindings(
        gug395_private_root=gug395_private_root,
        gug395_request=request395,
        gug395_receipt=receipt395,
        gug395_bundle=bundle395,
    )
    targets = request395.get("targets")
    artifact = targets.get("artifact_bucket") if isinstance(targets, Mapping) else None
    artifact_name = artifact.get("name") if isinstance(artifact, Mapping) else None
    if (
        not isinstance(artifact_name, str)
    ):
        _fail("ATOMIC_COLLISION_GUG395_RESULT_INVALID")
    catalog = materialize_route_collision_catalog(
        source_commit_sha=str(request395["source_commit_sha"]),
        source_tree_sha=str(request395["source_tree_sha"]),
        bootstrap_intent_digest=bootstrap_intent_digest,
        not_before=active_not_before,
        expires_at=active_expires_at,
        artifact_bucket_name=artifact_name,
    )
    context: dict[str, Any] = {
        "record_type": CONTEXT_TYPE,
        "schema_version": 2,
        "admission_private_root_digest": admission_digest,
        "effect_private_root_digest": effect_digest,
        "gug395_private_root_digest": gug395_digest,
        "gug395_request_digest": request395["request_digest"],
        "gug395_receipt_digest": receipt395["receipt_digest"],
        "gug395_bundle_digest": bundle395["bundle_digest"],
        "approval_reference_digest": approval_reference_digest,
        "approved_operation": approved_operation,
        "authorized_at": active_not_before,
        "expires_at": active_expires_at,
        "catalog": catalog,
        "catalog_digest": catalog["catalog_digest"],
        "private_bindings": bindings,
        "private_bindings_digest": bindings["binding_digest"],
        "read_only_admission": True,
        "aws_mutations": 0,
    }
    context["context_digest"] = canonical_digest(context)
    try:
        private_target_absent(admission_private_root, CONTEXT_FILE)
        write_private_json(admission_private_root, CONTEXT_FILE, context)
        if read_private_json(admission_private_root, CONTEXT_FILE) != context:
            _fail("ATOMIC_COLLISION_CONTEXT_READBACK_MISMATCH")
    except AtomicCollisionContextError:
        raise
    except Exception:
        raise AtomicCollisionContextError(
            "ATOMIC_COLLISION_CONTEXT_PERSIST_FAILED"
        ) from None
    return context


def read_atomic_collision_context(
    *,
    admission_private_root: Path,
    effect_private_root: Path,
    gug395_private_root: Path,
    clock: Any = lambda: datetime.now(UTC),
) -> dict[str, Any]:
    _validate_distinct_roots(
        admission_private_root,
        effect_private_root,
        gug395_private_root,
    )
    try:
        value = read_private_json(admission_private_root, CONTEXT_FILE)
    except Exception:
        raise AtomicCollisionContextError(
            "ATOMIC_COLLISION_CONTEXT_INVALID"
        ) from None
    fields = {
        "record_type",
        "schema_version",
        "admission_private_root_digest",
        "effect_private_root_digest",
        "gug395_private_root_digest",
        "gug395_request_digest",
        "gug395_receipt_digest",
        "gug395_bundle_digest",
        "approval_reference_digest",
        "approved_operation",
        "authorized_at",
        "expires_at",
        "catalog",
        "catalog_digest",
        "private_bindings",
        "private_bindings_digest",
        "read_only_admission",
        "aws_mutations",
        "context_digest",
    }
    if not isinstance(value, Mapping) or set(value) != fields:
        _fail("ATOMIC_COLLISION_CONTEXT_INVALID")
    unsigned = dict(value)
    supplied = unsigned.pop("context_digest", None)
    catalog = value.get("catalog")
    bindings = _validate_bindings(value.get("private_bindings"))
    try:
        if isinstance(catalog, Mapping):
            validate_route_collision_catalog(catalog)
        else:
            raise ValueError
    except Exception:
        _fail("ATOMIC_COLLISION_CONTEXT_INVALID")
    _active_effect_window(
        not_before=value["authorized_at"],
        expires_at=value["expires_at"],
        clock=clock,
    )
    try:
        admission.route_collision_operation_phase(
            str(value["approved_operation"])
        )
        admission.collision_session_mode_for_operation(
            str(value["approved_operation"]),
            execution_locus=admission.LOCAL_ATOMIC_CLI,
        )
    except Exception:
        _fail("ATOMIC_COLLISION_CONTEXT_INVALID")
    (
        current_request395,
        current_receipt395,
        current_bundle395,
    ) = _gug395_evidence(
        gug395_private_root
    )
    current_bindings = _derive_gug395_bindings(
        gug395_private_root=gug395_private_root,
        gug395_request=current_request395,
        gug395_receipt=current_receipt395,
        gug395_bundle=current_bundle395,
    )
    current_catalog = materialize_route_collision_catalog(
        source_commit_sha=str(current_request395["source_commit_sha"]),
        source_tree_sha=str(current_request395["source_tree_sha"]),
        bootstrap_intent_digest=str(catalog["bootstrap_intent_digest"]),
        not_before=str(catalog["not_before"]),
        expires_at=str(catalog["expires_at"]),
        artifact_bucket_name=str(
            current_request395["targets"]["artifact_bucket"]["name"]
        ),
    )
    if (
        value.get("record_type") != CONTEXT_TYPE
        or value.get("schema_version") != 2
        or value.get("admission_private_root_digest")
        != _root_digest(admission_private_root)
        or value.get("effect_private_root_digest")
        != _root_digest(effect_private_root)
        or value.get("gug395_private_root_digest")
        != _root_digest(gug395_private_root)
        or value.get("gug395_request_digest")
        != current_request395.get("request_digest")
        or value.get("gug395_receipt_digest")
        != current_receipt395.get("receipt_digest")
        or value.get("gug395_bundle_digest")
        != current_bundle395.get("bundle_digest")
        or _DIGEST.fullmatch(
            str(value.get("approval_reference_digest"))
        )
        is None
        or value.get("authorized_at") != catalog.get("not_before")
        or value.get("expires_at") != catalog.get("expires_at")
        or catalog != current_catalog
        or bindings != current_bindings
        or value.get("catalog_digest") != catalog.get("catalog_digest")
        or value.get("private_bindings_digest") != bindings["binding_digest"]
        or value.get("read_only_admission") is not True
        or value.get("aws_mutations") != 0
        or supplied != canonical_digest(unsigned)
    ):
        _fail("ATOMIC_COLLISION_CONTEXT_INVALID")
    return dict(value)


def build_atomic_loader_from_private_context(
    *,
    admission_private_root: Path,
    effect_private_root: Path,
    gug395_private_root: Path,
    expected_approval_reference_digest: str,
    expected_authorized_at: str,
    expected_expires_at: str,
    expected_operation: str,
    expected_source_commit_sha: str,
    environment: Mapping[str, str],
    clock: Any = lambda: datetime.now(UTC),
) -> Any:
    """Build the concrete loader used by the three known mutation CLIs."""

    context = read_atomic_collision_context(
        admission_private_root=admission_private_root,
        effect_private_root=effect_private_root,
        gug395_private_root=gug395_private_root,
        clock=clock,
    )
    if (
        context.get("approval_reference_digest")
        != expected_approval_reference_digest
        or context.get("authorized_at") != expected_authorized_at
        or context.get("expires_at") != expected_expires_at
        or context.get("approved_operation") != expected_operation
    ):
        _fail("ATOMIC_COLLISION_AUTHORIZATION_BINDING_INVALID")
    if context["catalog"].get("source_commit_sha") != expected_source_commit_sha:
        _fail("ATOMIC_COLLISION_SOURCE_BINDING_INVALID")
    bindings = context["private_bindings"]
    catalog = context["catalog"]
    opener_factory = build_direct_sso_policy_session_opener_factory(
        private_root=gug395_private_root,
        catalog=catalog,
        environment=environment,
        clock=clock,
        expires_at=catalog["expires_at"],
        expected_gug395_request_digest=context[
            "gug395_request_digest"
        ],
        expected_gug395_receipt_digest=context[
            "gug395_receipt_digest"
        ],
        expected_gug395_bundle_digest=context[
            "gug395_bundle_digest"
        ],
        identity_center_instance_arn=bindings[
            "identity_center_instance_arn"
        ],
        identity_center_kms_mode=bindings["identity_center_kms_mode"],
        identity_center_kms_key_arn=bindings[
            "identity_center_kms_key_arn"
        ],
        identity_center_kms_binding_digest=bindings[
            "identity_center_kms_binding_digest"
        ],
    )
    return build_atomic_route_collision_admission_loader(
        config=AtomicCollisionAdmissionConfig(
            admission_private_root=admission_private_root,
            effect_private_root=effect_private_root,
            gug395_private_root=gug395_private_root,
            effect_private_root_digest=context[
                "effect_private_root_digest"
            ],
            atomic_context_digest=context["context_digest"],
            approval_reference_digest=context[
                "approval_reference_digest"
            ],
            approved_operation=context["approved_operation"],
            authorized_at=context["authorized_at"],
            expires_at=context["expires_at"],
            expected_gug395_request_digest=context[
                "gug395_request_digest"
            ],
            expected_gug395_receipt_digest=context[
                "gug395_receipt_digest"
            ],
            expected_gug395_bundle_digest=context[
                "gug395_bundle_digest"
            ],
            execution_locus=admission.LOCAL_ATOMIC_CLI,
            catalog=catalog,
            identity_center_instance_arn=bindings[
                "identity_center_instance_arn"
            ],
            identity_center_kms_binding_digest=bindings[
                "identity_center_kms_binding_digest"
            ],
            session_opener_factory=opener_factory,
            identity_bindings_factory=(
                _build_expected_pre_reader_identity_bindings_factory(
                    expected_gug395_request_digest=context[
                        "gug395_request_digest"
                    ],
                    expected_gug395_receipt_digest=context[
                        "gug395_receipt_digest"
                    ],
                    expected_gug395_bundle_digest=context[
                        "gug395_bundle_digest"
                    ],
                )
            ),
            clock=clock,
        )
    )


__all__ = [
    "CONTEXT_FILE",
    "CONTEXT_TYPE",
    "PRIVATE_BINDINGS_TYPE",
    "AtomicCollisionContextError",
    "build_atomic_loader_from_private_context",
    "materialize_atomic_collision_context",
    "read_atomic_collision_context",
]
