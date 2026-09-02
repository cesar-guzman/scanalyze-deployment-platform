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
from tooling import platform_authority_gug393_private_input_discovery as gug393
from tooling.platform_authority_gug395_preplan_collision_probe import (
    ABSENT_READY as GUG395_ABSENT_READY,
    DEFAULT_RESULT_FILE as GUG395_RESULT_FILE,
    read_collision_probe_result,
)


CONTEXT_FILE = "gug376-route-collision-atomic-context.json"
CONTEXT_TYPE = (
    "scanalyze.platform_authority.gug376_route_collision_atomic_context.v1"
)
PRIVATE_BINDINGS_TYPE = (
    "scanalyze.platform_authority.gug376_route_collision_private_bindings.v1"
)
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_INSTANCE = re.compile(r"^arn:aws:sso:::instance/ssoins-[A-Za-z0-9.-]{16}$")
_KMS = re.compile(
    r"^arn:aws:kms:us-east-1:839393571433:key/[A-Za-z0-9-]{8,128}$"
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
        "gug393_private_root_digest",
        "gug393_manifest_digest",
        "external_verification_digest",
        "binding_digest",
    }
    if not isinstance(value, Mapping) or set(value) != fields:
        _fail("ATOMIC_COLLISION_PRIVATE_BINDINGS_INVALID")
    mode = value.get("identity_center_kms_mode")
    key = value.get("identity_center_kms_key_arn")
    if (
        value.get("record_type") != PRIVATE_BINDINGS_TYPE
        or value.get("schema_version") != 1
        or value.get("source") != "GUG393_PERSISTED_MATERIALIZATION"
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
        or _DIGEST.fullmatch(str(value.get("gug393_private_root_digest")))
        is None
        or _DIGEST.fullmatch(str(value.get("gug393_manifest_digest")))
        is None
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


def _gug393_root(value: Path) -> Path:
    try:
        supplied = Path(value)
        resolved = supplied.resolve(strict=True)
        mode = resolved.stat().st_mode & 0o777
    except OSError:
        raise AtomicCollisionContextError(
            "ATOMIC_COLLISION_GUG393_ROOT_INVALID"
        ) from None
    if (
        not supplied.is_absolute()
        or supplied.is_symlink()
        or resolved != supplied
        or not resolved.is_dir()
        or mode != 0o700
    ):
        _fail("ATOMIC_COLLISION_GUG393_ROOT_INVALID")
    return resolved


def _gug393_root_digest(value: Path) -> str:
    root = _gug393_root(value)
    try:
        return gug393.private_root_binding_digest(root)
    except Exception:
        raise AtomicCollisionContextError(
            "ATOMIC_COLLISION_GUG393_ROOT_INVALID"
        ) from None


def _validate_distinct_roots(
    admission_private_root: Path,
    effect_private_root: Path,
    gug393_private_root: Path,
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
            _gug393_root(gug393_private_root),
            gug395,
        }
    except AtomicCollisionContextError:
        raise
    except OSError:
        _fail("ATOMIC_COLLISION_CONTEXT_ROOT_INVALID")
    if len(roots) != 4:
        _fail("ATOMIC_COLLISION_ROOT_REUSE_FORBIDDEN")


def _gug395_evidence(
    private_root: Path,
) -> tuple[dict[str, Any], dict[str, Any], str]:
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
    return request, receipt, str(bundle["bundle_digest"])


def _derive_gug393_bindings(
    *,
    gug393_private_root: Path,
    gug395_request: Mapping[str, Any],
) -> dict[str, Any]:
    root = _gug393_root(gug393_private_root)
    try:
        manifest = read_private_json(root, gug393.DEFAULT_MANIFEST_FILE)
        checked_manifest = gug393.validate_input_materialization_manifest(
            root,
            manifest,
        )
        authority_input = read_private_json(
            root, str(checked_manifest["authority_input_file"])
        )
        identity_input = read_private_json(
            root, str(checked_manifest["identity_center_input_file"])
        )
        authority_plan = read_private_json(
            root, str(checked_manifest["authority_plan_file"])
        )
        identity_plan = read_private_json(
            root, str(checked_manifest["identity_center_plan_file"])
        )
        decision = read_private_json(
            root, str(checked_manifest["decision_file"])
        )
        reopened_artifacts = {
            str(checked_manifest["authority_input_file"]): authority_input,
            str(checked_manifest["identity_center_input_file"]): (
                identity_input
            ),
            str(checked_manifest["authority_plan_file"]): authority_plan,
            str(checked_manifest["identity_center_plan_file"]): identity_plan,
            str(checked_manifest["decision_file"]): decision,
        }
        artifact_digests = checked_manifest["artifact_digests"]
        if set(reopened_artifacts) != set(artifact_digests) or any(
            canonical_digest(artifact) != artifact_digests[name]
            for name, artifact in reopened_artifacts.items()
        ):
            _fail("ATOMIC_COLLISION_GUG393_MATERIALIZATION_INVALID")
        recomputed = gug393.materialize_live_plans(
            authority_input=authority_input,
            identity_center_input=identity_input,
        )
    except Exception:
        raise AtomicCollisionContextError(
            "ATOMIC_COLLISION_GUG393_MATERIALIZATION_INVALID"
        ) from None
    if (
        recomputed.authority_plan != authority_plan
        or recomputed.identity_center_plan != identity_plan
        or checked_manifest.get("source_commit_sha")
        != gug395_request.get("source_commit_sha")
        or checked_manifest.get("source_tree_sha")
        != gug395_request.get("source_tree_sha")
    ):
        _fail("ATOMIC_COLLISION_GUG393_MATERIALIZATION_INVALID")
    profiles = gug395_request.get("profiles")
    gug395_targets = gug395_request.get("targets")
    authority_profile = (
        profiles.get("authority") if isinstance(profiles, Mapping) else None
    )
    identity_profile = (
        profiles.get("identity_center")
        if isinstance(profiles, Mapping)
        else None
    )
    if (
        not isinstance(authority_input, Mapping)
        or not isinstance(identity_input, Mapping)
        or not isinstance(authority_profile, Mapping)
        or not isinstance(identity_profile, Mapping)
        or authority_input.get("not_before") != gug395_request.get("not_before")
        or authority_input.get("not_after") != gug395_request.get("expires_at")
        or identity_input.get("not_before") != gug395_request.get("not_before")
        or identity_input.get("not_after") != gug395_request.get("expires_at")
        or authority_input.get("expected_account_id")
        != authority_profile.get("expected_account_id")
        or identity_input.get("expected_account_id")
        != identity_profile.get("expected_account_id")
        or canonical_digest(authority_input.get("expected_principal_arn"))
        != authority_profile.get("expected_principal_digest")
        or canonical_digest(identity_input.get("expected_principal_arn"))
        != identity_profile.get("expected_principal_digest")
        or authority_input.get("authority_verification_digest")
        != authority_profile.get("authority_verification_digest")
        or identity_input.get("authority_verification_digest")
        != identity_profile.get("authority_verification_digest")
    ):
        _fail("ATOMIC_COLLISION_GUG393_MATERIALIZATION_INVALID")
    authority_targets = authority_input.get("targets")
    artifact_selector = (
        gug395_targets.get("artifact_bucket")
        if isinstance(gug395_targets, Mapping)
        else None
    )
    artifact_name = (
        artifact_selector.get("name")
        if isinstance(artifact_selector, Mapping)
        else None
    )
    if (
        not isinstance(authority_targets, Mapping)
        or not isinstance(artifact_name, str)
        or authority_targets.get("artifact_bucket_arn")
        != f"arn:aws:s3:::{artifact_name}"
        or any(
            not str(authority_targets.get(name, "")).startswith(
                f"arn:aws:s3:::{artifact_name}/"
            )
            for name in (
                "broker_signed_object_arn",
                "broker_unsigned_object_arn",
                "ledger_factory_signed_object_arn",
                "ledger_factory_unsigned_object_arn",
            )
        )
    ):
        _fail("ATOMIC_COLLISION_GUG393_MATERIALIZATION_INVALID")
    state = identity_input.get("expected_state")
    private_targets = identity_input.get("private_targets")
    if not isinstance(state, Mapping) or not isinstance(private_targets, Mapping):
        _fail("ATOMIC_COLLISION_GUG393_MATERIALIZATION_INVALID")
    classification = state.get("classification")
    if classification == "ABSENT_READY":
        instance_record = state.get("instance")
        instance_arn = (
            instance_record.get("instance_arn")
            if isinstance(instance_record, Mapping)
            else None
        )
        if (
            not isinstance(instance_record, Mapping)
            or instance_record.get("owner_account_id")
            != identity_profile.get("expected_account_id")
        ):
            _fail("ATOMIC_COLLISION_GUG393_MATERIALIZATION_INVALID")
    elif classification == "EXACT_PRESENT_NO_TOUCH":
        targets = state.get("targets")
        facts = state.get("facts")
        discovery = facts.get("discovery") if isinstance(facts, Mapping) else None
        instances = (
            discovery.get("instances")
            if isinstance(discovery, Mapping)
            else None
        )
        instance_record = facts.get("instance") if isinstance(facts, Mapping) else None
        if (
            not isinstance(instances, list)
            or len(instances) != 1
            or not isinstance(instances[0], Mapping)
            or not isinstance(instance_record, Mapping)
            or instances[0].get("instance_arn")
            != instance_record.get("instance_arn")
            or instance_record.get("owner_account_id")
            != identity_profile.get("expected_account_id")
            or not isinstance(targets, Mapping)
            or targets.get("identity_center_instance_arn")
            != instance_record.get("instance_arn")
            or targets.get("identity_center_kms_key_arn")
            != private_targets.get("identity_center_kms_key_arn")
        ):
            _fail("ATOMIC_COLLISION_GUG393_MATERIALIZATION_INVALID")
        instance_arn = instance_record.get("instance_arn")
    else:
        _fail("ATOMIC_COLLISION_GUG393_MATERIALIZATION_INVALID")
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
    key_arn = private_targets.get("identity_center_kms_key_arn")
    if _INSTANCE.fullmatch(str(instance_arn)) is None or selector_instances != {
        instance_arn
    }:
        _fail("ATOMIC_COLLISION_GUG393_MATERIALIZATION_INVALID")
    if key_arn is None:
        mode = "AWS_OWNED_KMS_KEY"
    elif _KMS.fullmatch(str(key_arn)) is not None:
        mode = "CUSTOMER_MANAGED_KEY"
    else:
        _fail("ATOMIC_COLLISION_GUG393_MATERIALIZATION_INVALID")
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
            "private_root_digest": checked_manifest["private_root_digest"],
            "manifest_digest": checked_manifest["manifest_digest"],
            "artifact_digests": checked_manifest["artifact_digests"],
            "authority_plan_digest": canonical_digest(authority_plan),
            "identity_center_plan_digest": canonical_digest(identity_plan),
            "gug395_request_digest": gug395_request["request_digest"],
        }
    )
    body: dict[str, Any] = {
        "record_type": PRIVATE_BINDINGS_TYPE,
        "schema_version": 1,
        "source": "GUG393_PERSISTED_MATERIALIZATION",
        "identity_center_instance_arn": instance_arn,
        "identity_center_kms_mode": mode,
        "identity_center_kms_key_arn": key_arn,
        "identity_center_kms_binding_digest": kms_binding_digest,
        "gug393_private_root_digest": checked_manifest[
            "private_root_digest"
        ],
        "gug393_manifest_digest": checked_manifest["manifest_digest"],
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
    gug393_private_root: Path,
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
        gug393_private_root,
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
    request395, receipt395, bundle395_digest = _gug395_evidence(
        gug395_private_root
    )
    bindings = _derive_gug393_bindings(
        gug393_private_root=gug393_private_root,
        gug395_request=request395,
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
        "schema_version": 1,
        "admission_private_root_digest": admission_digest,
        "effect_private_root_digest": effect_digest,
        "gug395_private_root_digest": gug395_digest,
        "gug393_private_root_digest": bindings[
            "gug393_private_root_digest"
        ],
        "gug395_request_digest": request395["request_digest"],
        "gug395_receipt_digest": receipt395["receipt_digest"],
        "gug395_bundle_digest": bundle395_digest,
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
    gug393_private_root: Path,
    gug395_private_root: Path,
    clock: Any = lambda: datetime.now(UTC),
) -> dict[str, Any]:
    _validate_distinct_roots(
        admission_private_root,
        effect_private_root,
        gug393_private_root,
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
        "gug393_private_root_digest",
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
        current_bundle395_digest,
    ) = _gug395_evidence(
        gug395_private_root
    )
    current_bindings = _derive_gug393_bindings(
        gug393_private_root=gug393_private_root,
        gug395_request=current_request395,
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
        or value.get("schema_version") != 1
        or value.get("admission_private_root_digest")
        != _root_digest(admission_private_root)
        or value.get("effect_private_root_digest")
        != _root_digest(effect_private_root)
        or value.get("gug395_private_root_digest")
        != _root_digest(gug395_private_root)
        or value.get("gug393_private_root_digest")
        != _gug393_root_digest(gug393_private_root)
        or value.get("gug395_request_digest")
        != current_request395.get("request_digest")
        or value.get("gug395_receipt_digest")
        != current_receipt395.get("receipt_digest")
        or value.get("gug395_bundle_digest")
        != current_bundle395_digest
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
    gug393_private_root: Path,
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
        gug393_private_root=gug393_private_root,
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
