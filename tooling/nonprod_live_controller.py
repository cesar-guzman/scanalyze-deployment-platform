"""Connected controller for one protected DEV saved-plan phase.

This module composes the already-separated Plan, Apply, and shared-services
orchestrator authorities.  It never accepts caller-selected operational paths,
never replans during apply, consumes the apply attempt with CAS before invoking
Terraform, and classifies any lost terminal response as uncertain.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import subprocess
import sys
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Callable, Mapping, Protocol, Sequence

from tooling.authorize_deployment_backend import (
    AuthorizationError,
    canonical_digest,
    load_json_strict,
)
from tooling.nonprod_live_engine import (
    COST_BINDING_FIELDS,
    LEDGER_BINDING_FIELDS,
    MATERIALIZED_PLAN_BINDING_FIELDS,
    PLAN_BINDING_FIELDS,
    build_initial_ledger,
    build_health_receipt,
    build_reconciliation_receipt,
    build_saved_plan_approval,
    build_saved_plan_record,
    build_saved_plan_reviewer_packet,
    prepare_ledger_transition,
    prepare_pre_apply_reapproval,
    require_downstream_health,
    summarize_terraform_plan,
    validate_health_receipt_document,
    validate_contract_publication_receipt,
    validate_execution_ledger_document,
    validate_reconciliation_receipt_document,
    validate_saved_plan_cost_binding,
    validate_saved_plan_document,
)
from tooling.nonprod_live_github_approval import (
    GitHubApprovalError,
    load_private_approval_evidence,
    validate_approval_evidence,
)
from tooling.nonprod_live_input_materializer import (
    LiveInputMaterializationError,
    SOURCE_FILENAMES,
    load_repository_claim,
    revalidate_private_root_at_action_time,
    validate_claim,
)
from tooling.nonprod_live_orchestrator import (
    build_apply_intent,
    build_plan_intent,
    classify_apply_observation,
    validate_apply_intent,
    validate_plan_intent,
)
from tooling.nonprod_live_store import (
    AwsCliExecutionLedgerStore,
    AwsCliPlanStore,
    AwsCliTerminalSession,
)


REPO_ROOT = Path(__file__).resolve().parents[1]
CONTROLLER_SCRIPT = REPO_ROOT / "scripts/deployment/nonprod-live-controller.py"
SAVED_PLAN_RUNNER = REPO_ROOT / "scripts/deployment/terraform-saved-plan.sh"
DIGEST = re.compile(r"^sha256:[a-f0-9]{64}$")
GIT_SHA = re.compile(r"^[a-f0-9]{40}$")
PRIVATE_JSON_LIMIT = 2_097_152
PRIVATE_PLAN_JSON_LIMIT = 134_217_728


class TerminalSession(Protocol):
    def run_terminal_phase(self, **kwargs: Any) -> None: ...


class LedgerStore(Protocol):
    def verify_destination_separation(self, destination_account_id: str) -> Mapping[str, str]: ...
    def verify_orchestrator_identity(self, expected_role_arn: str, *, deployment_id: str) -> Mapping[str, str]: ...
    def put_plan_record_once(self, plan_record: Mapping[str, Any]) -> None: ...
    def get_plan_record(self, *, deployment_id: str, execution_id: str, layer: str) -> dict[str, Any]: ...
    def create_ledger(self, ledger: Mapping[str, Any]) -> None: ...
    def get_ledger(self, *, deployment_id: str, execution_id: str, layer: str) -> dict[str, Any]: ...
    def put_approval_record_once(self, approval_record: Mapping[str, Any], *, now: datetime) -> None: ...
    def get_approval_record(self, *, deployment_id: str, execution_id: str, layer: str, approval_digest: str, now: datetime) -> dict[str, Any]: ...
    def put_health_receipt_once(self, receipt: Mapping[str, Any]) -> None: ...
    def get_health_receipt(self, *, deployment_id: str, execution_id: str, layer: str) -> dict[str, Any]: ...
    def find_health_receipt(self, *, deployment_id: str, execution_id: str, layer: str) -> dict[str, Any] | None: ...
    def put_reconciliation_receipt_once(self, receipt: Mapping[str, Any]) -> None: ...
    def get_reconciliation_receipt(self, *, deployment_id: str, execution_id: str, layer: str) -> dict[str, Any]: ...
    def find_reconciliation_receipt(self, *, deployment_id: str, execution_id: str, layer: str) -> dict[str, Any] | None: ...
    def replace_ledger(self, **kwargs: Any) -> None: ...


CommandRunner = Callable[[Sequence[str]], str]
ProcessRunner = Callable[[Sequence[str]], int]
PlanShowRunner = Callable[[Sequence[str], int], int]
Clock = Callable[[], datetime]
PostApplyProbe = Callable[..., Mapping[str, Any]]
ContractPublisher = Callable[..., Mapping[str, Any]]


class AwsCliReadError(AuthorizationError):
    """Sanitized AWS CLI read failure retaining only its machine error code."""

    def __init__(self, error_code: str) -> None:
        self.error_code = error_code
        super().__init__(f"terminal AWS read failed ({error_code})")


def _observed_time(*, clock: Clock | None, fallback: datetime) -> datetime:
    """Return a timezone-aware, second-granularity action-time observation."""
    if fallback.tzinfo is None:
        raise AuthorizationError("controller fallback time must be timezone-aware")
    lower_bound = fallback.astimezone(UTC).replace(microsecond=0)
    observed = fallback if clock is None else clock()
    if observed.tzinfo is None:
        raise AuthorizationError("controller clock must be timezone-aware")
    normalized = observed.astimezone(UTC).replace(microsecond=0)
    if normalized < lower_bound:
        raise AuthorizationError("controller clock moved before the authorized observation")
    return normalized


@dataclass(frozen=True)
class LiveInputPackage:
    private_root: Path
    operation: str
    claim: Mapping[str, Any]
    context: Mapping[str, Any]
    bindings: Mapping[str, Any]
    backend_binding: Mapping[str, Any]
    plan_inputs: Mapping[str, str]
    apply_inputs: Mapping[str, str]
    manifest: Mapping[str, Any]
    receipt: Mapping[str, Any]

    @property
    def materialized_root(self) -> Path:
        return self.private_root / "materialized"

    @property
    def controller_root(self) -> Path:
        return self.materialized_root / "controller"


def _private_directory(path: Path) -> None:
    if path.is_symlink():
        raise AuthorizationError("private live directory custody is invalid")
    try:
        metadata = path.stat()
    except OSError as exc:
        raise AuthorizationError("private live directory custody is invalid") from exc
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        raise AuthorizationError("private live directory custody is invalid")


def _strict_json_object(content: bytes) -> dict[str, Any]:
    def reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise AuthorizationError(
                    "private live input contains duplicate JSON keys"
                )
            result[key] = value
        return result

    def reject_constant(_value: str) -> Any:
        raise AuthorizationError("private live input contains a non-finite number")

    try:
        document = json.loads(
            content.decode("utf-8"),
            object_pairs_hook=reject_duplicate_pairs,
            parse_constant=reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AuthorizationError("private live input JSON is invalid") from exc
    if not isinstance(document, dict):
        raise AuthorizationError("private live input JSON root is invalid")
    return document


def _private_json_descriptor(
    descriptor: int,
    *,
    max_bytes: int = PRIVATE_JSON_LIMIT,
) -> dict[str, Any]:
    try:
        before = os.fstat(descriptor)
    except OSError as exc:
        raise AuthorizationError("private live input custody is invalid") from exc
    if (
        not stat.S_ISREG(before.st_mode)
        or before.st_uid != os.geteuid()
        or stat.S_IMODE(before.st_mode) != 0o600
        or before.st_nlink != 1
        or before.st_size < 2
        or before.st_size > max_bytes
    ):
        raise AuthorizationError("private live input custody is invalid")
    content = bytearray()
    try:
        while True:
            block = os.read(
                descriptor,
                min(65_536, max_bytes + 1 - len(content)),
            )
            if not block:
                break
            content.extend(block)
            if len(content) > max_bytes:
                raise AuthorizationError("private live input custody is invalid")
        after = os.fstat(descriptor)
    except OSError as exc:
        raise AuthorizationError("private live input custody is invalid") from exc
    before_identity = (
        before.st_dev,
        before.st_ino,
        before.st_mode,
        before.st_uid,
        before.st_nlink,
        before.st_size,
        before.st_mtime_ns,
        before.st_ctime_ns,
    )
    after_identity = (
        after.st_dev,
        after.st_ino,
        after.st_mode,
        after.st_uid,
        after.st_nlink,
        after.st_size,
        after.st_mtime_ns,
        after.st_ctime_ns,
    )
    if before_identity != after_identity or len(content) != before.st_size:
        raise AuthorizationError("private live input changed while it was read")
    return _strict_json_object(bytes(content))


def _private_json(path: Path) -> dict[str, Any]:
    descriptor: int | None = None
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
        )
        return _private_json_descriptor(descriptor)
    except OSError as exc:
        raise AuthorizationError("private live input custody is invalid") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _revalidate_materialized_sources(package: LiveInputPackage) -> None:
    """Rebind every private source to the immutable materialization evidence."""
    current_manifest = _private_json(package.materialized_root / "manifest.json")
    current_receipt = _private_json(package.materialized_root / "receipt.json")
    if current_manifest != dict(package.manifest) or current_receipt != dict(
        package.receipt
    ):
        raise AuthorizationError(
            "materialized authority evidence changed after validation"
        )
    expected_digests = current_manifest.get("source_document_digests")
    if (
        not isinstance(expected_digests, Mapping)
        or set(expected_digests) != set(SOURCE_FILENAMES)
        or any(
            not isinstance(value, str) or not DIGEST.fullmatch(value)
            for value in expected_digests.values()
        )
    ):
        raise AuthorizationError("materialized source digest manifest is invalid")
    source_count = current_receipt.get("source_count")
    if (
        isinstance(source_count, bool)
        or not isinstance(source_count, int)
        or source_count != len(SOURCE_FILENAMES)
    ):
        raise AuthorizationError("materialized source count is invalid")

    directory_descriptor: int | None = None
    try:
        directory_descriptor = os.open(
            package.materialized_root / "sources",
            os.O_RDONLY
            | os.O_DIRECTORY
            | os.O_NOFOLLOW
            | getattr(os, "O_CLOEXEC", 0),
        )
        directory_metadata = os.fstat(directory_descriptor)
        if (
            not stat.S_ISDIR(directory_metadata.st_mode)
            or directory_metadata.st_uid != os.geteuid()
            or stat.S_IMODE(directory_metadata.st_mode) != 0o700
        ):
            raise AuthorizationError(
                "materialized source directory custody is invalid"
            )
        if set(os.listdir(directory_descriptor)) != set(SOURCE_FILENAMES.values()):
            raise AuthorizationError("materialized source set is not canonical")
        for key, filename in SOURCE_FILENAMES.items():
            descriptor: int | None = None
            try:
                descriptor = os.open(
                    filename,
                    os.O_RDONLY
                    | os.O_NOFOLLOW
                    | getattr(os, "O_CLOEXEC", 0),
                    dir_fd=directory_descriptor,
                )
                document = _private_json_descriptor(descriptor)
            finally:
                if descriptor is not None:
                    os.close(descriptor)
            if canonical_digest(document) != expected_digests[key]:
                raise AuthorizationError(
                    f"materialized source digest mismatch: {key}"
                )
    except OSError as exc:
        raise AuthorizationError("materialized source custody is invalid") from exc
    finally:
        if directory_descriptor is not None:
            os.close(directory_descriptor)


def write_private_json_once(path: Path, document: Mapping[str, Any]) -> None:
    """Write one controller-owned private JSON file without overwrite."""
    _private_directory(path.parent)
    content = (
        json.dumps(
            document,
            sort_keys=True,
            indent=2,
            ensure_ascii=True,
            allow_nan=False,
        )
        + "\n"
    ).encode("utf-8")
    descriptor: int | None = None
    created = False
    try:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags, 0o600)
        created = True
        offset = 0
        while offset < len(content):
            offset += os.write(descriptor, content[offset:])
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = None
        os.chmod(path, 0o600)
    except OSError as exc:
        if created:
            path.unlink(missing_ok=True)
        raise AuthorizationError("private controller output write failed") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _expected_input_maps(private_root: Path) -> tuple[dict[str, str], dict[str, str]]:
    materialized = private_root / "materialized"
    sources = materialized / "sources"
    controller = materialized / "controller"
    plan = {
        "plan_dir": str(materialized / "plan"),
        "resolved_input": str(sources / "contract-resolution.json"),
        "manifest": str(sources / "manifest.json"),
        "target_record": str(sources / "target-record.json"),
        "target_anchor": str(sources / "target-anchor.json"),
        "account_ready": str(sources / "account-ready.json"),
        "execution_lock": str(sources / "execution-lock.json"),
    }
    apply = {
        "apply_intent": str(controller / "apply-intent.json"),
        "context": str(materialized / "context.json"),
        "approved_ledger": str(controller / "approved-ledger.json"),
        "applying_ledger": str(controller / "applying-ledger.json"),
        "plan_record": str(controller / "plan-record.json"),
        "approval_record": str(controller / "approval-record.json"),
        "plan_readback": str(controller / "plan-readback.json"),
        "state_readback": str(controller / "state-readback.json"),
        "manifest": str(sources / "manifest.json"),
        "target_record": str(sources / "target-record.json"),
        "target_anchor": str(sources / "target-anchor.json"),
        "account_ready": str(sources / "account-ready.json"),
        "execution_lock": str(sources / "execution-lock.json"),
    }
    return plan, apply


def load_live_input_package(
    *,
    private_root: Path,
    operation: str,
    deployment_id: str,
    execution_id: str,
    change_id: str,
    layer: str,
    main_sha: str,
    region: str,
    claim_digest: str,
    receipt_digest: str,
    now: datetime,
) -> LiveInputPackage:
    """Revalidate the fixed materialized tuple before any authority transition."""
    if operation not in {"plan", "apply"}:
        raise AuthorizationError("live controller operation is invalid")
    if not private_root.is_absolute():
        raise AuthorizationError("private live root must be absolute")
    if not DIGEST.fullmatch(claim_digest) or not DIGEST.fullmatch(receipt_digest):
        raise AuthorizationError("live controller digest selector is invalid")
    if not GIT_SHA.fullmatch(main_sha):
        raise AuthorizationError("live controller source SHA is invalid")
    for directory in (
        private_root,
        private_root / "materialized",
        private_root / "materialized/sources",
        private_root / "materialized/controller",
        private_root / "materialized/plan",
    ):
        _private_directory(directory)
    materialized = private_root / "materialized"
    context = _private_json(materialized / "context.json")
    bindings = _private_json(materialized / "bindings.json")
    backend = _private_json(materialized / "backend-binding.json")
    plan_inputs = _private_json(materialized / "plan-inputs.json")
    apply_inputs = _private_json(materialized / "apply-inputs.json")
    manifest = _private_json(materialized / "manifest.json")
    receipt = _private_json(materialized / "receipt.json")

    expected_plan, expected_apply = _expected_input_maps(private_root)
    if plan_inputs != expected_plan or apply_inputs != expected_apply:
        raise AuthorizationError("materialized operational path map is not canonical")
    if receipt.get("receipt_digest") != receipt_digest or canonical_digest(
        {key: value for key, value in receipt.items() if key != "receipt_digest"}
    ) != receipt_digest:
        raise AuthorizationError("materialized receipt digest mismatch")
    required_receipt = {
        "status": "MATERIALIZED",
        "code": "LIVE_INPUTS_MATERIALIZED",
        "operation": operation,
        "layer": layer,
        "claim_digest": claim_digest,
        "materialization_valid": True,
        "controller_input_ready": True,
        "oidc_authorized": True,
        "terminal_operation_authorized": False,
        "aws_calls": 0,
        "aws_mutations": 0,
    }
    if any(receipt.get(field) != value for field, value in required_receipt.items()):
        raise AuthorizationError("materialized receipt does not authorize controller entry")
    if manifest.get("manifest_digest") != canonical_digest(
        {key: value for key, value in manifest.items() if key != "manifest_digest"}
    ):
        raise AuthorizationError("materialized manifest digest mismatch")
    if (
        receipt.get("manifest_digest") != manifest.get("manifest_digest")
        or receipt.get("context_digest") != context.get("context_digest")
        or receipt.get("binding_digest") != canonical_digest(bindings)
        or receipt.get("backend_binding_digest") != backend.get("binding_digest")
        or manifest.get("context_digest") != context.get("context_digest")
        or manifest.get("binding_digest") != canonical_digest(bindings)
        or manifest.get("backend_binding_digest") != backend.get("binding_digest")
    ):
        raise AuthorizationError("materialized evidence binding mismatch")
    expected_context = {
        "deployment_id": deployment_id,
        "execution_id": execution_id,
        "change_id": change_id,
        "layer": layer,
        "workflow_sha": main_sha,
        "main_sha": main_sha,
        "region": region,
        "environment": "dev",
    }
    if any(context.get(field) != value for field, value in expected_context.items()):
        raise AuthorizationError("live controller context selector mismatch")
    expected_bindings = {
        "deployment_id": deployment_id,
        "execution_id": execution_id,
        "change_id": change_id,
        "layer": layer,
        "region": region,
        "environment": "dev",
        "source_revision_digest": context.get("source_revision_digest"),
    }
    if any(bindings.get(field) != value for field, value in expected_bindings.items()):
        raise AuthorizationError("live controller saved-plan binding mismatch")
    if backend.get("binding_digest") != bindings.get("backend_binding_digest"):
        raise AuthorizationError("live controller backend binding mismatch")
    backend_body = {key: value for key, value in backend.items() if key != "binding_digest"}
    if canonical_digest(backend_body) != backend.get("binding_digest"):
        raise AuthorizationError("live controller backend digest mismatch")

    try:
        claim = load_repository_claim(
            repo_root=REPO_ROOT,
            deployment_id=deployment_id,
            layer=layer,
            operation=operation,
        )
        validate_claim(
            claim,
            deployment_id=deployment_id,
            layer=layer,
            operation=operation,
            claim_digest=claim_digest,
            now=now,
            repo_root=REPO_ROOT,
        )
    except LiveInputMaterializationError as exc:
        raise AuthorizationError("tracked live claim revalidation failed") from exc
    if (
        claim.get("execution_id") != execution_id
        or claim.get("change_id") != change_id
        or claim.get("region") != region
        or claim.get("release_digest") != bindings.get("release_digest")
        or receipt.get("maximum_cost_usd_micros")
        != claim.get("maximum_cost_usd_micros")
    ):
        raise AuthorizationError("tracked live claim controller binding mismatch")
    if any(
        receipt.get(field) != manifest.get(field)
        for field in COST_BINDING_FIELDS
    ):
        raise AuthorizationError("materialized cost evidence binding mismatch")
    for field in (
        "expected_approver_user_id",
        "approval_authority_digest",
    ):
        if (
            receipt.get(field) != manifest.get(field)
            or receipt.get(field) != context.get(field)
            or receipt.get(field) != bindings.get(field)
        ):
            raise AuthorizationError("materialized approval authority binding mismatch")
    if (
        receipt.get("github_environment_anchor_digest")
        != manifest.get("github_environment_anchor_digest")
        or receipt.get("github_environment_anchor_digest")
        != context.get("github_environment_anchor_digest")
    ):
        raise AuthorizationError("materialized Environment anchor binding mismatch")
    modeled = receipt.get("modeled_cost_upper_bound_usd_micros")
    maximum = receipt.get("maximum_cost_usd_micros")
    if (
        isinstance(modeled, bool)
        or not isinstance(modeled, int)
        or isinstance(maximum, bool)
        or not isinstance(maximum, int)
        or modeled < 0
        or modeled > maximum
    ):
        raise AuthorizationError("live controller cost ceiling is invalid")
    package = LiveInputPackage(
        private_root=private_root,
        operation=operation,
        claim=claim,
        context=context,
        bindings=bindings,
        backend_binding=backend,
        plan_inputs=plan_inputs,
        apply_inputs=apply_inputs,
        manifest=manifest,
        receipt=receipt,
    )
    _revalidate_materialized_sources(package)
    return package


def _default_command_runner(command: Sequence[str]) -> str:
    try:
        result = subprocess.run(
            list(command),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=True,
        )
    except subprocess.CalledProcessError as exc:
        error = str(exc.stderr or "")
        normalized = error.casefold().replace("_", "")
        if "accessdenied" in normalized or re.search(
            r"(?<!\d)403(?!\d)", error
        ):
            code = "AccessDenied"
        elif "nosuchkey" in normalized:
            code = "NoSuchKey"
        elif "notfound" in normalized or "not found" in normalized:
            code = "NotFound"
        elif re.search(r"(?<!\d)404(?!\d)", error):
            code = "404"
        else:
            code = "Unknown"
        raise AwsCliReadError(code) from exc
    except OSError as exc:
        raise AuthorizationError("terminal AWS read failed") from exc
    return result.stdout


def _default_process_runner(command: Sequence[str]) -> int:
    try:
        return subprocess.run(
            list(command),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
            env=os.environ.copy(),
        ).returncode
    except OSError as exc:
        raise AuthorizationError("terminal Terraform process failed") from exc


def _default_plan_show_runner(
    command: Sequence[str], output_descriptor: int
) -> int:
    try:
        return subprocess.run(
            list(command),
            stdin=subprocess.DEVNULL,
            stdout=output_descriptor,
            stderr=subprocess.DEVNULL,
            check=False,
            env=os.environ.copy(),
        ).returncode
    except OSError as exc:
        raise AuthorizationError("Terraform plan inspection failed") from exc


def _private_plan_fingerprint(path: Path) -> dict[str, Any]:
    """Hash a private plan through one no-follow descriptor."""
    descriptor: int | None = None
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.geteuid()
            or stat.S_IMODE(before.st_mode) != 0o600
            or before.st_nlink != 1
            or before.st_size < 1
            or before.st_size > 1_073_741_824
        ):
            raise AuthorizationError("saved plan custody is invalid")
        digest = hashlib.sha256()
        while True:
            block = os.read(descriptor, 1024 * 1024)
            if not block:
                break
            digest.update(block)
        after = os.fstat(descriptor)
        if (
            before.st_dev,
            before.st_ino,
            before.st_mode,
            before.st_uid,
            before.st_nlink,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        ) != (
            after.st_dev,
            after.st_ino,
            after.st_mode,
            after.st_uid,
            after.st_nlink,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        ):
            raise AuthorizationError("saved plan changed while it was hashed")
        return {
            "sha256": "sha256:" + digest.hexdigest(),
            "size_bytes": before.st_size,
        }
    except OSError as exc:
        raise AuthorizationError("saved plan custody is invalid") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)


def inspect_terraform_saved_plan(
    *,
    plan_path: Path,
    scratch_path: Path,
    runner: PlanShowRunner = _default_plan_show_runner,
) -> dict[str, Any]:
    """Inspect a saved plan structurally and delete the sensitive raw JSON."""
    _private_directory(scratch_path.parent)
    if scratch_path.exists() or scratch_path.is_symlink():
        raise AuthorizationError("Terraform plan inspection scratch is not exclusive")
    descriptor: int | None = None
    try:
        descriptor = os.open(
            scratch_path,
            os.O_RDWR
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        return_code = runner(
            ("terraform", "show", "-json", str(plan_path)), descriptor
        )
        os.fsync(descriptor)
        if return_code != 0:
            raise AuthorizationError("Terraform plan inspection failed")
        os.lseek(descriptor, 0, os.SEEK_SET)
        return summarize_terraform_plan(
            _private_json_descriptor(
                descriptor,
                max_bytes=PRIVATE_PLAN_JSON_LIMIT,
            )
        )
    except OSError as exc:
        raise AuthorizationError("Terraform plan inspection failed") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)
        scratch_path.unlink(missing_ok=True)


def _package_cost_binding(package: LiveInputPackage) -> dict[str, Any]:
    return {field: package.receipt.get(field) for field in COST_BINDING_FIELDS}


def read_exact_state(
    *,
    backend_binding: Mapping[str, Any],
    account_id: str,
    region: str,
    scratch_path: Path,
    runner: CommandRunner = _default_command_runner,
) -> dict[str, Any]:
    """Read one immutable state version, project lineage/serial, delete payload."""
    backend = backend_binding.get("backend")
    if not isinstance(backend, Mapping):
        raise AuthorizationError("Terraform backend binding is invalid")
    expected = {
        "region": region,
        "allowed_account_ids": [account_id],
        "encrypt": True,
        "use_lockfile": True,
    }
    if any(backend.get(field) != value for field, value in expected.items()):
        raise AuthorizationError("Terraform backend authority mismatch")
    if backend_binding.get("account_id") != account_id:
        raise AuthorizationError("Terraform backend account binding mismatch")
    bucket = backend.get("bucket")
    key = backend.get("key")
    if bucket != f"scanalyze-{account_id}-tf-state" or not isinstance(key, str):
        raise AuthorizationError("Terraform backend object location is not canonical")
    _private_directory(scratch_path.parent)
    if scratch_path.exists() or scratch_path.is_symlink():
        raise AuthorizationError("Terraform state scratch path is not exclusive")
    try:
        head_raw = runner(
            (
                "aws",
                "s3api",
                "head-object",
                "--region",
                region,
                "--bucket",
                bucket,
                "--key",
                key,
                "--output",
                "json",
            )
        )
    except AwsCliReadError as exc:
        if exc.error_code in {"404", "NoSuchKey", "NotFound"}:
            try:
                versions_raw = runner(
                    (
                        "aws",
                        "s3api",
                        "list-object-versions",
                        "--region",
                        region,
                        "--bucket",
                        bucket,
                        "--prefix",
                        key,
                        "--max-keys",
                        "1000",
                        "--output",
                        "json",
                    )
                )
                versions = json.loads(versions_raw)
            except (AwsCliReadError, TypeError, json.JSONDecodeError) as absence_exc:
                raise AuthorizationError(
                    "Terraform state absence could not be established"
                ) from absence_exc
            if not isinstance(versions, dict) or versions.get("IsTruncated") is not False:
                raise AuthorizationError("Terraform state absence response is invalid")
            for collection_name in ("Versions", "DeleteMarkers"):
                collection = versions.get(collection_name, [])
                if not isinstance(collection, list) or any(
                    not isinstance(item, Mapping) for item in collection
                ):
                    raise AuthorizationError("Terraform state absence response is invalid")
                if any(item.get("Key") == key for item in collection):
                    raise AuthorizationError(
                        "Terraform state absence is ambiguous in the versioned backend"
                    )
            return {
                "status": "ABSENT",
                "lineage": None,
                "serial": None,
                "object_version_id": None,
                "sha256": None,
                "size_bytes": None,
            }
        raise AuthorizationError("Terraform state metadata read failed") from exc
    try:
        head = json.loads(head_raw)
    except (TypeError, json.JSONDecodeError) as exc:
        raise AuthorizationError("Terraform state metadata response is invalid") from exc
    version_id = head.get("VersionId") if isinstance(head, dict) else None
    if not isinstance(version_id, str) or not version_id or version_id == "null":
        raise AuthorizationError("Terraform state immutable version is unavailable")
    descriptor: int | None = None
    try:
        descriptor = os.open(
            scratch_path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        os.close(descriptor)
        descriptor = None
        get_raw = runner(
            (
                "aws",
                "s3api",
                "get-object",
                "--region",
                region,
                "--bucket",
                bucket,
                "--key",
                key,
                "--version-id",
                version_id,
                "--output",
                "json",
                str(scratch_path),
            )
        )
        try:
            get_response = json.loads(get_raw)
        except (TypeError, json.JSONDecodeError) as exc:
            raise AuthorizationError("Terraform state read response is invalid") from exc
        if not isinstance(get_response, dict) or get_response.get("VersionId") != version_id:
            raise AuthorizationError("Terraform state version readback mismatch")
        fingerprint_before = _private_plan_fingerprint(scratch_path)
        state = _private_json(scratch_path)
        fingerprint_after = _private_plan_fingerprint(scratch_path)
        if fingerprint_after != fingerprint_before:
            raise AuthorizationError("Terraform state changed while it was inspected")
        lineage = state.get("lineage")
        serial = state.get("serial")
        if (
            not isinstance(lineage, str)
            or not re.fullmatch(r"^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$", lineage)
            or isinstance(serial, bool)
            or not isinstance(serial, int)
            or serial < 0
        ):
            raise AuthorizationError("Terraform state binding is invalid")
        return {
            "status": "PRESENT",
            "lineage": lineage,
            "serial": serial,
            "object_version_id": version_id,
            "sha256": fingerprint_before["sha256"],
            "size_bytes": fingerprint_before["size_bytes"],
        }
    finally:
        if descriptor is not None:
            os.close(descriptor)
        scratch_path.unlink(missing_ok=True)


def _expected_state(plan_record: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "status": plan_record["state_status"],
        "lineage": plan_record["state_lineage"],
        "serial": plan_record["state_serial"],
    }


def _matches_reviewed_state(
    state: Mapping[str, Any], plan_record: Mapping[str, Any]
) -> bool:
    return all(
        state.get(field) == value
        for field, value in _expected_state(plan_record).items()
    )


def _bindings_with_terminal_state(
    package: LiveInputPackage, state: Mapping[str, Any]
) -> dict[str, Any]:
    """Add the terminal role's exact state observation to stable bindings."""
    if set(package.bindings) != set(MATERIALIZED_PLAN_BINDING_FIELDS):
        raise AuthorizationError("materialized saved-plan bindings are incomplete")
    status = state.get("status")
    lineage = state.get("lineage")
    serial = state.get("serial")
    present = (
        status == "PRESENT"
        and isinstance(lineage, str)
        and isinstance(serial, int)
        and not isinstance(serial, bool)
        and serial >= 0
    )
    absent = status == "ABSENT" and lineage is None and serial is None
    if not present and not absent:
        raise AuthorizationError("terminal Terraform state binding is invalid")
    bindings = {
        **dict(package.bindings),
        "state_status": status,
        "state_lineage": lineage,
        "state_serial": serial,
    }
    if set(bindings) != set(PLAN_BINDING_FIELDS):
        raise AuthorizationError("terminal saved-plan bindings are incomplete")
    return bindings


def _durable_plan_bindings(
    package: LiveInputPackage, plan_record: Mapping[str, Any]
) -> dict[str, Any]:
    """Rebind stable inputs to the state-bearing durable saved plan."""
    if any(
        plan_record.get(field) != package.bindings.get(field)
        for field in MATERIALIZED_PLAN_BINDING_FIELDS
    ):
        raise AuthorizationError("durable saved plan differs from materialized bindings")
    try:
        return {field: plan_record[field] for field in PLAN_BINDING_FIELDS}
    except KeyError as exc:
        raise AuthorizationError("durable saved-plan bindings are incomplete") from exc


def _saved_plan_storage(package: LiveInputPackage) -> tuple[str, str]:
    """Derive the separate short-lived plan bucket from ACCOUNT_READY v2."""
    account_ready = _private_json(
        package.materialized_root / "sources/account-ready.json"
    )
    infrastructure = account_ready.get("state_infrastructure")
    if not isinstance(infrastructure, Mapping):
        raise AuthorizationError("ACCOUNT_READY saved-plan storage is invalid")
    account_id = package.context["destination_account_id"]
    region = package.context["region"]
    expected_bucket_arn = f"arn:aws:s3:::scanalyze-{account_id}-tf-plan"
    bucket_arn = infrastructure.get("plan_bucket")
    kms_key_arn = infrastructure.get("evidence_kms_key")
    if bucket_arn != expected_bucket_arn:
        raise AuthorizationError("ACCOUNT_READY plan bucket binding mismatch")
    if not isinstance(kms_key_arn, str) or not re.fullmatch(
        rf"^arn:aws(?:-[a-z]+)*:kms:{re.escape(region)}:{account_id}:"
        r"key/[A-Za-z0-9/_+=,.@:-]+$",
        kms_key_arn,
    ):
        raise AuthorizationError("ACCOUNT_READY evidence KMS binding mismatch")
    return expected_bucket_arn.removeprefix("arn:aws:s3:::"), kms_key_arn


def _terminal_kwargs(package: LiveInputPackage, operation: str, command: Sequence[str]) -> dict[str, Any]:
    context = package.context
    return {
        "orchestrator_role_arn": context["orchestrator_role_arn"],
        "role_arn": context[f"{operation}_role_arn"],
        "customer_id": context["customer_id"],
        "deployment_id": context["deployment_id"],
        "execution_id": context["execution_id"],
        "change_id": context["change_id"],
        "environment": "dev",
        "operation": operation,
        "layer": context["layer"],
        "command": tuple(command),
        "base_environment": os.environ,
    }


def _internal_command(package: LiveInputPackage, subcommand: str, *, receipt_digest: str) -> tuple[str, ...]:
    context = package.context
    return (
        sys.executable,
        str(CONTROLLER_SCRIPT),
        subcommand,
        "--private-root",
        str(package.private_root),
        "--claim-digest",
        str(package.claim["claim_digest"]),
        "--receipt-digest",
        receipt_digest,
        "--deployment-id",
        str(context["deployment_id"]),
        "--execution-id",
        str(context["execution_id"]),
        "--change-id",
        str(context["change_id"]),
        "--layer",
        str(context["layer"]),
        "--main-sha",
        str(context["main_sha"]),
        "--region",
        str(context["region"]),
    )


def _verify_orchestrator(package: LiveInputPackage, store: LedgerStore) -> None:
    store.verify_destination_separation(package.context["destination_account_id"])
    store.verify_orchestrator_identity(
        package.context["orchestrator_role_arn"],
        deployment_id=package.context["deployment_id"],
    )


def _create_once_confirmed(
    *,
    write: Callable[[], None],
    read: Callable[[], Mapping[str, Any]],
    proposed: Mapping[str, Any],
    label: str,
) -> dict[str, Any]:
    """Confirm an idempotent create-only write after a lost response."""
    last_error: Exception | None = None
    for attempt in range(2):
        try:
            write()
            last_error = None
        except Exception as exc:
            last_error = exc
        read_error: Exception | None = None
        durable: Mapping[str, Any] | None = None
        for _read_attempt in range(2):
            try:
                durable = read()
                break
            except Exception as exc:
                read_error = exc
        if durable is not None:
            if durable == proposed:
                return dict(durable)
            raise AuthorizationError(f"durable {label} conflicts with create-only write") from last_error
        if last_error is None:
            raise AuthorizationError(f"durable {label} could not be confirmed") from read_error
        if attempt == 1:
            break
    raise AuthorizationError(f"durable {label} write did not commit") from last_error


def run_plan_controller(
    package: LiveInputPackage,
    *,
    receipt_digest: str,
    terminal_session: TerminalSession,
    ledger_store: LedgerStore,
    now: datetime,
    clock: Clock | None = None,
) -> dict[str, Any]:
    """Run terminal plan/store, then persist and read back control records."""
    if package.operation != "plan":
        raise AuthorizationError("plan controller received non-plan inputs")
    _revalidate_materialized_sources(package)
    command = _internal_command(package, "_terminal-plan", receipt_digest=receipt_digest)
    terminal_session.run_terminal_phase(**_terminal_kwargs(package, "plan", command))

    planned_at = _observed_time(clock=clock, fallback=now)

    plan_record = _private_json(package.controller_root / "plan-record.json")
    validate_saved_plan_document(plan_record)
    reviewer_packet = build_saved_plan_reviewer_packet(plan_record)
    write_private_json_once(
        package.controller_root / "reviewer-packet.json", reviewer_packet
    )
    _verify_orchestrator(package, ledger_store)
    durable_plan = _create_once_confirmed(
        write=lambda: ledger_store.put_plan_record_once(plan_record),
        read=lambda: ledger_store.get_plan_record(
            deployment_id=package.context["deployment_id"],
            execution_id=package.context["execution_id"],
            layer=package.context["layer"],
        ),
        proposed=plan_record,
        label="saved-plan record",
    )
    ledger = build_initial_ledger(plan_record=plan_record, at=planned_at)
    durable_ledger = _create_once_confirmed(
        write=lambda: ledger_store.create_ledger(ledger),
        read=lambda: ledger_store.get_ledger(
            deployment_id=package.context["deployment_id"],
            execution_id=package.context["execution_id"],
            layer=package.context["layer"],
        ),
        proposed=ledger,
        label="PLANNED ledger",
    )
    result: dict[str, Any] = {
        "schema_version": "1",
        "record_type": "nonprod_live_controller_receipt",
        "operation": "plan",
        "status": "PLANNED",
        "claim_digest": package.claim["claim_digest"],
        "input_receipt_digest": receipt_digest,
        "plan_record_digest": plan_record["record_digest"],
        "reviewer_packet_digest": reviewer_packet["packet_digest"],
        "approval_authority_digest": plan_record["approval_authority_digest"],
        "ledger_digest": ledger["ledger_digest"],
        "apply_attempt_count": 0,
        "production_authorized": False,
    }
    result["receipt_digest"] = canonical_digest(result)
    write_private_json_once(package.controller_root / "controller-receipt.json", result)
    return result


def _replace_ledger(store: LedgerStore, current: Mapping[str, Any], proposed: Mapping[str, Any]) -> None:
    store.replace_ledger(
        ledger=proposed,
        expected_deployment_id=current["deployment_id"],
        expected_execution_id=current["execution_id"],
        expected_layer=current["layer"],
        expected_version=current["ledger_version"],
        expected_digest=current["ledger_digest"],
        expected_status=current["status"],
    )


def _replace_ledger_confirmed(
    store: LedgerStore,
    current: Mapping[str, Any],
    proposed: Mapping[str, Any],
) -> dict[str, Any]:
    """CAS one ledger transition and resolve a lost write response by readback."""
    last_error: Exception | None = None
    for attempt in range(2):
        try:
            _replace_ledger(store, current, proposed)
            last_error = None
        except Exception as exc:
            last_error = exc
        read_error: Exception | None = None
        durable: Mapping[str, Any] | None = None
        for _read_attempt in range(2):
            try:
                durable = store.get_ledger(
                    deployment_id=current["deployment_id"],
                    execution_id=current["execution_id"],
                    layer=current["layer"],
                )
                break
            except Exception as exc:
                read_error = exc
        if durable is None:
            if attempt == 0:
                # The CAS may already have committed. Retry the exact CAS/read
                # cycle so a later strong read can prove the proposed state;
                # never infer failure from a transient confirmation outage.
                last_error = read_error or last_error
                continue
            raise AuthorizationError(
                f"durable {proposed['status']} ledger could not be confirmed"
            ) from read_error
        if durable == proposed:
            return durable
        if durable != current:
            raise AuthorizationError(
                f"durable {proposed['status']} ledger conflicts with the CAS transition"
            ) from last_error
        if last_error is None:
            raise AuthorizationError(
                f"durable {proposed['status']} ledger readback mismatch"
            )
        if attempt == 1:
            break
    raise AuthorizationError(
        f"durable {proposed['status']} ledger write did not commit"
    ) from last_error


def _read_ledger_after_apply_error(
    *, store: LedgerStore, applying: Mapping[str, Any]
) -> tuple[dict[str, Any] | None, Exception | None]:
    """Strongly reread a consumed attempt without inferring a terminal state."""
    last_error: Exception | None = None
    for _attempt in range(3):
        try:
            return (
                store.get_ledger(
                    deployment_id=applying["deployment_id"],
                    execution_id=applying["execution_id"],
                    layer=applying["layer"],
                ),
                None,
            )
        except Exception as exc:
            last_error = exc
    return None, last_error


def _write_private_json_confirmed(
    path: Path,
    document: Mapping[str, Any],
) -> None:
    """Create one private artifact or confirm its exact prior contents."""
    if path.exists() and not path.is_symlink():
        if _private_json(path) != dict(document):
            raise AuthorizationError("private controller evidence conflicts")
        return
    try:
        write_private_json_once(path, document)
    except AuthorizationError:
        if not path.exists() or path.is_symlink() or _private_json(path) != dict(
            document
        ):
            raise


def _project_verified_outputs(
    raw_outputs: Any,
) -> tuple[dict[str, Any], str, int]:
    """Keep only explicitly non-sensitive Terraform outputs in private custody."""
    if not isinstance(raw_outputs, Mapping) or len(raw_outputs) > 128:
        raise AuthorizationError("post-apply Terraform outputs are invalid")
    projected: dict[str, Any] = {}
    for name, descriptor in raw_outputs.items():
        if (
            not isinstance(name, str)
            or not re.fullmatch(r"^[A-Za-z_][A-Za-z0-9_-]{0,127}$", name)
            or not isinstance(descriptor, Mapping)
            or set(descriptor) != {"sensitive", "value"}
            or not isinstance(descriptor.get("sensitive"), bool)
        ):
            raise AuthorizationError("post-apply Terraform output metadata is invalid")
        if descriptor["sensitive"]:
            continue
        projected[name] = descriptor["value"]
    document: dict[str, Any] = {
        "schema_version": "1",
        "record_type": "verified_non_sensitive_terraform_outputs",
        "outputs": projected,
    }
    try:
        encoded = json.dumps(
            document,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise AuthorizationError("post-apply Terraform output value is invalid") from exc
    if len(encoded) > PRIVATE_JSON_LIMIT:
        raise AuthorizationError("post-apply Terraform outputs exceed the private limit")
    return document, canonical_digest(document), len(projected)


def _expected_output_contract_digest(
    *,
    package: LiveInputPackage,
    plan_record: Mapping[str, Any],
    state_readback: Mapping[str, Any],
    outputs_digest: str,
) -> str:
    return canonical_digest(
        {
            "schema_version": "1",
            "record_type": "verified_non_sensitive_output_contract",
            "deployment_id": package.context["deployment_id"],
            "execution_id": package.context["execution_id"],
            "layer": package.context["layer"],
            "plan_record_digest": plan_record["record_digest"],
            "release_digest": plan_record["release_digest"],
            "state_object_version_id": state_readback.get("object_version_id"),
            "state_sha256": state_readback.get("sha256"),
            "outputs_digest": outputs_digest,
        }
    )


def _validate_contract_publication(
    publication: Mapping[str, Any],
    *,
    health_receipt: Mapping[str, Any],
) -> dict[str, Any]:
    validate_contract_publication_receipt(
        publication,
        health_receipt=health_receipt,
    )
    return dict(publication)


def _controller_status_receipt(
    *,
    package: LiveInputPackage,
    receipt_digest: str,
    plan_record: Mapping[str, Any],
    ledger: Mapping[str, Any],
    status: str,
    evidence: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "schema_version": "1",
        "record_type": "nonprod_live_controller_receipt",
        "operation": "apply",
        "status": status,
        "claim_digest": package.claim["claim_digest"],
        "input_receipt_digest": receipt_digest,
        "plan_record_digest": plan_record["record_digest"],
        "ledger_digest": ledger["ledger_digest"],
        "apply_attempt_count": ledger["attempt_count"],
        "retry_allowed": False,
        "production_authorized": False,
    }
    if evidence:
        result.update(dict(evidence))
    result["receipt_digest"] = canonical_digest(result)
    return result


def _finalize_applied(
    *,
    package: LiveInputPackage,
    receipt_digest: str,
    plan_record: Mapping[str, Any],
    current: Mapping[str, Any],
    ledger_store: LedgerStore,
    health_probe: PostApplyProbe,
    contract_publisher: ContractPublisher,
    now: datetime,
    clock: Clock | None,
) -> dict[str, Any]:
    """Prove no-change health, publish exact output contract, then CAS HEALTHY."""
    if current.get("status") not in {"APPLIED", "RECONCILED_APPLIED"}:
        raise AuthorizationError("post-apply health requires an applied execution")
    existing = ledger_store.find_health_receipt(
        deployment_id=current["deployment_id"],
        execution_id=current["execution_id"],
        layer=current["layer"],
    )
    action_observed_at = _observed_time(clock=clock, fallback=now)
    checked_at = action_observed_at
    if existing is not None:
        validate_health_receipt_document(existing)
        try:
            checked_at = datetime.fromisoformat(
                str(existing["checked_at"]).replace("Z", "+00:00")
            ).astimezone(UTC)
        except (KeyError, ValueError) as exc:
            raise AuthorizationError("durable health receipt time is invalid") from exc
        if checked_at > action_observed_at:
            raise AuthorizationError("durable health receipt was checked in the future")

    observation = health_probe(
        package=package,
        plan_record=dict(plan_record),
        ledger=dict(current),
        now=checked_at,
    )
    expected_observation_fields = {
        "state_before",
        "state_after",
        "speculative_plan_result",
        "speculative_plan_summary",
        "checks",
        "outputs",
    }
    if (
        not isinstance(observation, Mapping)
        or set(observation) != expected_observation_fields
        or observation.get("speculative_plan_result") != "NO_CHANGE"
        or not isinstance(observation.get("state_before"), Mapping)
        or not isinstance(observation.get("state_after"), Mapping)
        or not isinstance(observation.get("checks"), Sequence)
        or isinstance(observation.get("checks"), (str, bytes))
    ):
        raise AuthorizationError("post-apply read-only observation is invalid")
    checks = observation["checks"]
    if not any(
        isinstance(check, Mapping)
        and check.get("name") == "input_contracts"
        and check.get("passed") is True
        for check in checks
    ):
        raise AuthorizationError("post-apply input contracts are not verified")
    output_document, outputs_digest, output_count = _project_verified_outputs(
        observation["outputs"]
    )
    state_after = observation["state_after"]
    expected_contract_digest = _expected_output_contract_digest(
        package=package,
        plan_record=plan_record,
        state_readback=state_after,
        outputs_digest=outputs_digest,
    )
    candidate = build_health_receipt(
        plan_record=plan_record,
        ledger=current,
        state_before=observation["state_before"],
        state_after=state_after,
        speculative_plan_summary=observation["speculative_plan_summary"],
        outputs_digest=outputs_digest,
        output_count=output_count,
        expected_contract_digest=expected_contract_digest,
        checked_at=checked_at,
        checks=checks,
    )
    if candidate.get("status") != "PASSED":
        raise AuthorizationError("post-apply health evidence did not pass")
    if existing is not None and existing != candidate:
        raise AuthorizationError("durable health evidence cannot be reproduced")
    _write_private_json_confirmed(
        package.controller_root / "verified-non-sensitive-outputs.json",
        output_document,
    )
    durable_health = _create_once_confirmed(
        write=lambda: ledger_store.put_health_receipt_once(candidate),
        read=lambda: ledger_store.get_health_receipt(
            deployment_id=current["deployment_id"],
            execution_id=current["execution_id"],
            layer=current["layer"],
        ),
        proposed=candidate,
        label="health receipt",
    )
    publication = _validate_contract_publication(
        contract_publisher(
            package=package,
            plan_record=dict(plan_record),
            ledger=dict(current),
            health_receipt=dict(durable_health),
            verified_outputs=output_document,
        ),
        health_receipt=durable_health,
    )
    _write_private_json_confirmed(
        package.controller_root / "contract-publication-receipt.json",
        publication,
    )
    transition_at = _observed_time(clock=clock, fallback=now)
    healthy, _ = prepare_ledger_transition(
        current=current,
        next_status="HEALTHY",
        expected_version=current["ledger_version"],
        expected_digest=current["ledger_digest"],
        at=transition_at,
        health_receipt=durable_health,
        contract_publication_receipt=publication,
    )
    durable_healthy = _replace_ledger_confirmed(
        ledger_store,
        current,
        healthy,
    )
    result = _controller_status_receipt(
        package=package,
        receipt_digest=receipt_digest,
        plan_record=plan_record,
        ledger=durable_healthy,
        status="HEALTHY",
        evidence={
            "health_receipt_digest": durable_health["receipt_digest"],
            "contract_publication_receipt_digest": publication[
                "publication_receipt_digest"
            ],
            "reconciliation_required": False,
        },
    )
    _write_private_json_confirmed(
        package.controller_root / "post-apply-healthy-receipt.json",
        result,
    )
    return result


def _reconcile_uncertain(
    *,
    package: LiveInputPackage,
    receipt_digest: str,
    plan_record: Mapping[str, Any],
    current: Mapping[str, Any],
    ledger_store: LedgerStore,
    reconciliation_probe: PostApplyProbe,
    now: datetime,
    clock: Clock | None,
) -> dict[str, Any]:
    """Classify one uncertain attempt using read-only evidence only."""
    if current.get("status") != "UNCERTAIN":
        raise AuthorizationError("read-only reconciliation requires UNCERTAIN")
    existing = ledger_store.find_reconciliation_receipt(
        deployment_id=current["deployment_id"],
        execution_id=current["execution_id"],
        layer=current["layer"],
    )
    action_observed_at = _observed_time(clock=clock, fallback=now)
    checked_at = action_observed_at
    if existing is not None:
        validate_reconciliation_receipt_document(existing)
        try:
            checked_at = datetime.fromisoformat(
                str(existing["checked_at"]).replace("Z", "+00:00")
            ).astimezone(UTC)
        except (KeyError, ValueError) as exc:
            raise AuthorizationError(
                "durable reconciliation receipt time is invalid"
            ) from exc
        if checked_at > action_observed_at:
            raise AuthorizationError(
                "durable reconciliation receipt was checked in the future"
            )
    observation = reconciliation_probe(
        package=package,
        plan_record=dict(plan_record),
        ledger=dict(current),
        now=checked_at,
    )
    expected_fields = {
        "state_before",
        "state_after",
        "speculative_plan_result",
        "speculative_plan_summary",
        "contract_verified",
    }
    if (
        not isinstance(observation, Mapping)
        or set(observation) != expected_fields
        or not isinstance(observation.get("state_before"), Mapping)
        or not isinstance(observation.get("state_after"), Mapping)
        or not isinstance(observation.get("contract_verified"), bool)
    ):
        raise AuthorizationError("read-only reconciliation observation is invalid")
    candidate = build_reconciliation_receipt(
        plan_record=plan_record,
        ledger=current,
        state_before=observation["state_before"],
        state_after=observation["state_after"],
        speculative_plan_result=str(observation["speculative_plan_result"]),
        speculative_plan_summary=observation["speculative_plan_summary"],
        contract_verified=observation["contract_verified"],
        checked_at=checked_at,
    )
    if existing is not None and existing != candidate:
        raise AuthorizationError(
            "durable reconciliation evidence cannot be reproduced"
        )
    durable_receipt = _create_once_confirmed(
        write=lambda: ledger_store.put_reconciliation_receipt_once(candidate),
        read=lambda: ledger_store.get_reconciliation_receipt(
            deployment_id=current["deployment_id"],
            execution_id=current["execution_id"],
            layer=current["layer"],
        ),
        proposed=candidate,
        label="reconciliation receipt",
    )
    next_status = str(durable_receipt["decision"])
    proposed, _ = prepare_ledger_transition(
        current=current,
        next_status=next_status,
        expected_version=current["ledger_version"],
        expected_digest=current["ledger_digest"],
        at=_observed_time(clock=clock, fallback=now),
        reconciliation_receipt=durable_receipt,
    )
    durable = _replace_ledger_confirmed(
        ledger_store,
        current,
        proposed,
    )
    result = _controller_status_receipt(
        package=package,
        receipt_digest=receipt_digest,
        plan_record=plan_record,
        ledger=durable,
        status=next_status,
        evidence={
            "reconciliation_receipt_digest": durable_receipt["receipt_digest"],
            "reconciliation_required": next_status
            == "RECONCILIATION_REQUIRED",
        },
    )
    _write_private_json_confirmed(
        package.controller_root
        / f"post-apply-{next_status.casefold().replace('_', '-')}-receipt.json",
        result,
    )
    return result


def run_apply_controller(
    package: LiveInputPackage,
    *,
    receipt_digest: str,
    plan_record_digest: str,
    reviewer_packet_digest: str,
    expected_approver_user_id: int,
    terminal_session: TerminalSession,
    ledger_store: LedgerStore,
    now: datetime,
    clock: Clock | None = None,
    health_probe: PostApplyProbe | None = None,
    contract_publisher: ContractPublisher | None = None,
    reconciliation_probe: PostApplyProbe | None = None,
) -> dict[str, Any]:
    """Apply once or resume only the exact read-only post-apply state machine."""
    if (
        package.operation != "apply"
        or not DIGEST.fullmatch(plan_record_digest)
        or not DIGEST.fullmatch(reviewer_packet_digest)
        or isinstance(expected_approver_user_id, bool)
        or not isinstance(expected_approver_user_id, int)
        or expected_approver_user_id < 1
    ):
        raise AuthorizationError("apply controller selector is invalid")
    if expected_approver_user_id != package.context.get(
        "expected_approver_user_id"
    ):
        raise AuthorizationError("apply reviewer selector is not sealed")
    _revalidate_materialized_sources(package)
    _verify_orchestrator(package, ledger_store)
    plan_record = ledger_store.get_plan_record(
        deployment_id=package.context["deployment_id"],
        execution_id=package.context["execution_id"],
        layer=package.context["layer"],
    )
    validate_saved_plan_document(plan_record)
    if plan_record.get("record_digest") != plan_record_digest:
        raise AuthorizationError("apply saved-plan digest selector mismatch")
    expected_reviewer_packet = build_saved_plan_reviewer_packet(plan_record)
    if reviewer_packet_digest != expected_reviewer_packet["packet_digest"]:
        raise AuthorizationError("apply reviewer packet digest selector mismatch")
    durable_plan_bindings = _durable_plan_bindings(package, plan_record)
    validate_saved_plan_cost_binding(plan_record, _package_cost_binding(package))

    current = ledger_store.get_ledger(
        deployment_id=package.context["deployment_id"],
        execution_id=package.context["execution_id"],
        layer=package.context["layer"],
    )
    validate_execution_ledger_document(current)
    for field in LEDGER_BINDING_FIELDS:
        if current.get(field) != plan_record.get(field):
            raise AuthorizationError(
                f"execution ledger plan binding mismatch: {field}"
            )
    if current.get("plan_record_digest") != plan_record["record_digest"]:
        raise AuthorizationError("execution ledger durable plan binding mismatch")
    current_status = current.get("status")
    if current_status == "HEALTHY":
        health_receipt = ledger_store.get_health_receipt(
            deployment_id=current["deployment_id"],
            execution_id=current["execution_id"],
            layer=current["layer"],
        )
        require_downstream_health(
            current,
            plan_record=plan_record,
            expected_layer=package.context["layer"],
            health_receipt=health_receipt,
        )
        return _controller_status_receipt(
            package=package,
            receipt_digest=receipt_digest,
            plan_record=plan_record,
            ledger=current,
            status="HEALTHY",
            evidence={
                "health_receipt_digest": health_receipt["receipt_digest"],
                "reconciliation_required": False,
            },
        )
    if current_status in {"APPLIED", "RECONCILED_APPLIED"}:
        if (health_probe is None) != (contract_publisher is None):
            raise AuthorizationError(
                "post-apply health probe and contract publisher must be paired"
            )
        if health_probe is None or contract_publisher is None:
            return _controller_status_receipt(
                package=package,
                receipt_digest=receipt_digest,
                plan_record=plan_record,
                ledger=current,
                status=str(current_status),
                evidence={
                    "post_apply_pending": True,
                    "reconciliation_required": False,
                },
            )
        return _finalize_applied(
            package=package,
            receipt_digest=receipt_digest,
            plan_record=plan_record,
            current=current,
            ledger_store=ledger_store,
            health_probe=health_probe,
            contract_publisher=contract_publisher,
            now=now,
            clock=clock,
        )
    if current_status == "UNCERTAIN":
        if reconciliation_probe is None:
            raise AuthorizationError(
                "saved-plan apply is UNCERTAIN; read-only reconciliation is required"
            )
        return _reconcile_uncertain(
            package=package,
            receipt_digest=receipt_digest,
            plan_record=plan_record,
            current=current,
            ledger_store=ledger_store,
            reconciliation_probe=reconciliation_probe,
            now=now,
            clock=clock,
        )
    if current_status == "RECONCILIATION_REQUIRED":
        reconciliation_receipt = ledger_store.get_reconciliation_receipt(
            deployment_id=current["deployment_id"],
            execution_id=current["execution_id"],
            layer=current["layer"],
        )
        validate_reconciliation_receipt_document(reconciliation_receipt)
        if (
            reconciliation_receipt.get("decision")
            != "RECONCILIATION_REQUIRED"
            or current.get("outcome_receipt_digest")
            != reconciliation_receipt.get("receipt_digest")
            or reconciliation_receipt.get("source_ledger_version")
            != current["ledger_version"] - 1
            or reconciliation_receipt.get("plan_record_digest")
            != plan_record["record_digest"]
            or any(
                reconciliation_receipt.get(field) != current.get(field)
                for field in LEDGER_BINDING_FIELDS
            )
        ):
            raise AuthorizationError(
                "durable reconciliation-required evidence is inconsistent"
            )
        return _controller_status_receipt(
            package=package,
            receipt_digest=receipt_digest,
            plan_record=plan_record,
            ledger=current,
            status="RECONCILIATION_REQUIRED",
            evidence={
                "reconciliation_receipt_digest": reconciliation_receipt[
                    "receipt_digest"
                ],
                "reconciliation_required": True,
            },
        )
    if current.get("status") == "APPLYING":
        raise AuthorizationError(
            "prior apply is still APPLYING; the normal apply entry has no "
            "recovery authority and cannot mutate the durable ledger"
        )

    try:
        approval_evidence = load_private_approval_evidence(package.private_root)
        validate_approval_evidence(
            approval_evidence,
            repository=package.context["workflow_ref"].split("/.github/", 1)[0],
            repository_id=package.context["repository_id"],
            workflow_sha=package.context["workflow_sha"],
            workflow_run_id=package.context["workflow_run_id"],
            workflow_run_attempt=package.context["workflow_run_attempt"],
            github_environment=package.context["github_environment"],
            reviewer_packet_digest=reviewer_packet_digest,
            initiator_user_id=package.context["initiator_user_id"],
            expected_approver_user_id=expected_approver_user_id,
            apply_environment_anchor_digest=package.context[
                "github_environment_anchor_digest"
            ],
            approval_authority_digest=package.context[
                "approval_authority_digest"
            ],
            now=now,
        )
    except GitHubApprovalError as exc:
        raise AuthorizationError("independent GitHub Environment approval is invalid") from exc
    plan_expires = datetime.fromisoformat(
        str(plan_record["expires_at"]).replace("Z", "+00:00")
    ).astimezone(UTC)
    evidence_expires = datetime.fromisoformat(
        str(approval_evidence["expires_at"]).replace("Z", "+00:00")
    ).astimezone(UTC)
    approval_expires = min(plan_expires, evidence_expires)
    approval = build_saved_plan_approval(
        plan_record=plan_record,
        repository_owner_id=package.context["repository_owner_id"],
        repository_id=package.context["repository_id"],
        workflow_ref=package.context["workflow_ref"],
        workflow_sha=package.context["workflow_sha"],
        workflow_run_id=package.context["workflow_run_id"],
        workflow_run_attempt=package.context["workflow_run_attempt"],
        github_environment=package.context["github_environment"],
        environment_configuration_digest=package.context[
            "environment_configuration_digest"
        ],
        apply_environment_anchor_digest=package.context[
            "github_environment_anchor_digest"
        ],
        initiator_user_id=package.context["initiator_user_id"],
        expected_approver_user_id=expected_approver_user_id,
        approver_user_id=approval_evidence["approver_user_id"],
        reviewer_packet_digest=reviewer_packet_digest,
        approval_evidence_digest=approval_evidence["evidence_digest"],
        approval_window_started_at=datetime.fromisoformat(
            str(approval_evidence["workflow_run_created_at"]).replace("Z", "+00:00")
        ).astimezone(UTC),
        approval_observed_at=datetime.fromisoformat(
            str(approval_evidence["approval_observed_at"]).replace("Z", "+00:00")
        ).astimezone(UTC),
        freshness_basis=approval_evidence["freshness_basis"],
        expires_at=approval_expires,
    )
    durable_approval = _create_once_confirmed(
        write=lambda: ledger_store.put_approval_record_once(approval, now=now),
        read=lambda: ledger_store.get_approval_record(
            deployment_id=package.context["deployment_id"],
            execution_id=package.context["execution_id"],
            layer=package.context["layer"],
            approval_digest=approval["approval_digest"],
            now=now,
        ),
        proposed=approval,
        label="saved-plan approval",
    )
    current = ledger_store.get_ledger(
        deployment_id=package.context["deployment_id"],
        execution_id=package.context["execution_id"],
        layer=package.context["layer"],
    )
    if current.get("status") == "PLANNED":
        approved, _ = prepare_ledger_transition(
            current=current,
            next_status="APPROVED",
            expected_version=current["ledger_version"],
            expected_digest=current["ledger_digest"],
            at=now,
            approval_record=durable_approval,
        )
        durable_approved = _replace_ledger_confirmed(
            ledger_store, current, approved
        )
    elif (
        current.get("status") == "APPROVED"
        and current.get("attempt_count") == 0
        and current.get("approval_digest")
        == durable_approval["approval_digest"]
    ):
        approved = dict(current)
        durable_approved = dict(current)
    elif current.get("status") == "APPROVED" and current.get("attempt_count") == 0:
        approved, _ = prepare_pre_apply_reapproval(
            current=current,
            approval_record=durable_approval,
            expected_version=current["ledger_version"],
            expected_digest=current["ledger_digest"],
            at=now,
        )
        durable_approved = _replace_ledger_confirmed(
            ledger_store, current, approved
        )
    else:
        raise AuthorizationError(
            "saved plan approval cannot replace a consumed or terminal execution"
        )
    write_private_json_once(package.controller_root / "plan-record.json", plan_record)
    write_private_json_once(
        package.controller_root / "reviewer-packet.json", expected_reviewer_packet
    )
    write_private_json_once(
        package.controller_root / "approval-record.json", durable_approval
    )
    write_private_json_once(
        package.controller_root / "approved-ledger.json", durable_approved
    )

    fetch_command = _internal_command(
        package, "_terminal-fetch", receipt_digest=receipt_digest
    )
    terminal_session.run_terminal_phase(
        **_terminal_kwargs(package, "apply", fetch_command)
    )
    action_time = _observed_time(clock=clock, fallback=now)
    plan_path = package.controller_root / "controlled.tfplan"
    plan_readback = _private_json(package.controller_root / "plan-readback.json")
    state_readback = _private_json(package.controller_root / "state-readback.json")
    apply_intent = build_apply_intent(
        context=package.context,
        plan_record=plan_record,
        ledger=durable_approved,
        approval_record=durable_approval,
        expected_bindings=durable_plan_bindings,
        plan_readback=plan_readback,
        state_readback=state_readback,
        plan_binary_path=str(plan_path),
        apply_inputs=package.apply_inputs,
        now=action_time,
    )
    write_private_json_once(package.controller_root / "apply-intent.json", apply_intent)
    applying = apply_intent["proposed_ledger"]
    durable_applying = _replace_ledger_confirmed(
        ledger_store, durable_approved, applying
    )
    outcome: dict[str, Any] | None = None
    proposed_outcome: dict[str, Any] | None = None
    durable_outcome: dict[str, Any] | None = None
    try:
        write_private_json_once(
            package.controller_root / "applying-ledger.json", durable_applying
        )
        validate_apply_intent(
            intent=apply_intent,
            context=package.context,
            plan_record=plan_record,
            approval_record=durable_approval,
            approved_ledger=durable_approved,
            applying_ledger=durable_applying,
            plan_readback=plan_readback,
            state_readback=state_readback,
            now=action_time,
        )
        _revalidate_materialized_sources(package)
        apply_command = _internal_command(
            package, "_terminal-apply", receipt_digest=receipt_digest
        )
        terminal_session.run_terminal_phase(
            **_terminal_kwargs(package, "apply", apply_command)
        )
        outcome_at = _observed_time(clock=clock, fallback=action_time)
        outcome = classify_apply_observation(
            applying_ledger=durable_applying,
            observation="SUCCESS",
            at=outcome_at,
        )
        proposed_outcome = outcome["proposed_ledger"]
        durable_outcome = _replace_ledger_confirmed(
            ledger_store,
            durable_applying,
            proposed_outcome,
        )
    except Exception as exc:
        failure_at = action_time
        uncertain_confirmed = False
        try:
            try:
                failure_at = _observed_time(clock=clock, fallback=action_time)
            except Exception:
                failure_at = action_time
            uncertain_outcome = classify_apply_observation(
                applying_ledger=durable_applying,
                observation="RESPONSE_LOST",
                at=failure_at,
            )
            proposed_uncertain = uncertain_outcome["proposed_ledger"]
            durable_after_error, read_error = _read_ledger_after_apply_error(
                store=ledger_store,
                applying=durable_applying,
            )
            if (
                proposed_outcome is not None
                and durable_after_error == proposed_outcome
            ):
                # The APPLIED CAS committed and only its response/readback was
                # lost. Preserve the exact proven success and never overwrite
                # it with UNCERTAIN.
                durable_outcome = dict(durable_after_error)
            elif durable_after_error == proposed_uncertain:
                uncertain_confirmed = True
            elif durable_after_error in (None, durable_applying):
                try:
                    durable_uncertain = _replace_ledger_confirmed(
                        ledger_store,
                        durable_applying,
                        proposed_uncertain,
                    )
                    uncertain_confirmed = durable_uncertain == proposed_uncertain
                except Exception:
                    final_durable, final_read_error = _read_ledger_after_apply_error(
                        store=ledger_store,
                        applying=durable_applying,
                    )
                    if (
                        proposed_outcome is not None
                        and final_durable == proposed_outcome
                    ):
                        durable_outcome = dict(final_durable)
                    elif final_durable == proposed_uncertain:
                        uncertain_confirmed = True
                    else:
                        raise AuthorizationError(
                            "durable apply outcome conflicts after confirmation loss"
                        ) from (final_read_error or read_error)
            else:
                raise AuthorizationError(
                    "durable apply outcome conflicts after attempt consumption"
                )
        except Exception as persistence_exc:
            raise AuthorizationError(
                "saved-plan apply failed after attempt consumption; "
                "durable outcome could not be confirmed"
            ) from persistence_exc
        if durable_outcome is None:
            if not uncertain_confirmed:
                raise AuthorizationError(
                    "saved-plan apply failed after attempt consumption; "
                    "durable outcome could not be confirmed"
                ) from exc
            raise AuthorizationError(
                "saved-plan apply response is uncertain; reconciliation required"
            ) from exc
    if outcome is None or durable_outcome is None:
        raise AuthorizationError("saved-plan apply outcome is incomplete")
    if durable_outcome.get("status") == "APPLIED":
        if (health_probe is None) != (contract_publisher is None):
            raise AuthorizationError(
                "post-apply health probe and contract publisher must be paired"
            )
        if health_probe is not None and contract_publisher is not None:
            return _finalize_applied(
                package=package,
                receipt_digest=receipt_digest,
                plan_record=plan_record,
                current=durable_outcome,
                ledger_store=ledger_store,
                health_probe=health_probe,
                contract_publisher=contract_publisher,
                now=outcome_at,
                clock=clock,
            )
    result: dict[str, Any] = {
        "schema_version": "1",
        "record_type": "nonprod_live_controller_receipt",
        "operation": "apply",
        "status": outcome["next_status"],
        "claim_digest": package.claim["claim_digest"],
        "input_receipt_digest": receipt_digest,
        "plan_record_digest": plan_record_digest,
        "reviewer_packet_digest": reviewer_packet_digest,
        "approval_authority_digest": package.context[
            "approval_authority_digest"
        ],
        "approval_digest": approval["approval_digest"],
        "ledger_digest": durable_outcome["ledger_digest"],
        "apply_attempt_count": 1,
        "retry_allowed": False,
        "reconciliation_required": outcome["reconciliation_required"],
        "production_authorized": False,
    }
    result["receipt_digest"] = canonical_digest(result)
    write_private_json_once(package.controller_root / "controller-receipt.json", result)
    return result


def run_terminal_plan(
    package: LiveInputPackage,
    *,
    now: datetime,
    command_runner: CommandRunner = _default_command_runner,
    process_runner: ProcessRunner = _default_process_runner,
    plan_show_runner: PlanShowRunner = _default_plan_show_runner,
    clock: Clock | None = None,
) -> None:
    """Plan, bracket state, and store the immutable binary in one Plan session."""
    _revalidate_materialized_sources(package)
    context = package.context
    role_name = str(context["plan_role_arn"]).rsplit("/", 1)[-1]
    plan_store = AwsCliPlanStore(
        region=context["region"], account_id=context["destination_account_id"], runner=command_runner
    )
    plan_store.verify_terminal_identity(role_name)
    before = read_exact_state(
        backend_binding=package.backend_binding,
        account_id=context["destination_account_id"],
        region=context["region"],
        scratch_path=package.controller_root / ".state-before.json",
        runner=command_runner,
    )
    terminal_bindings = _bindings_with_terminal_state(package, before)
    domain = package.backend_binding.get("runtime_origin", {}).get("domain_name")
    intent = build_plan_intent(
        context=context,
        expected_bindings=terminal_bindings,
        plan_inputs=package.plan_inputs,
        domain_name=domain if isinstance(domain, str) else None,
    )
    validate_plan_intent(
        intent=intent,
        context=context,
        expected_bindings=terminal_bindings,
    )
    write_private_json_once(package.controller_root / "plan-intent.json", intent)
    command_spec = intent.get("command")
    if not isinstance(command_spec, Mapping) or command_spec.get("program") != SAVED_PLAN_RUNNER.relative_to(REPO_ROOT).as_posix():
        raise AuthorizationError("terminal Plan program is not canonical")
    argv = command_spec.get("argv")
    if not isinstance(argv, list) or not all(isinstance(item, str) for item in argv):
        raise AuthorizationError("terminal Plan command is invalid")
    if process_runner(("/bin/bash", str(SAVED_PLAN_RUNNER), *argv)) != 0:
        raise AuthorizationError("terminal Plan phase failed")
    plan_path = Path(str(intent["expected_plan_path"]))
    fingerprint_before = _private_plan_fingerprint(plan_path)
    plan_summary = inspect_terraform_saved_plan(
        plan_path=plan_path,
        scratch_path=package.controller_root / ".terraform-plan-inspection.json",
        runner=plan_show_runner,
    )
    fingerprint_after = _private_plan_fingerprint(plan_path)
    if fingerprint_after != fingerprint_before:
        raise AuthorizationError("saved plan changed during structural inspection")
    after = read_exact_state(
        backend_binding=package.backend_binding,
        account_id=context["destination_account_id"],
        region=context["region"],
        scratch_path=package.controller_root / ".state-after.json",
        runner=command_runner,
    )
    if after != before:
        raise AuthorizationError("Terraform state changed while the saved plan was created")
    bucket, evidence_kms_key = _saved_plan_storage(package)
    readback = plan_store.put_plan_once(
        path=plan_path,
        bucket=bucket,
        object_key=intent["expected_object_key"],
        kms_key_arn=evidence_kms_key,
    )
    fingerprint_after_upload = _private_plan_fingerprint(plan_path)
    if (
        fingerprint_after_upload != fingerprint_before
        or readback.get("sha256") != fingerprint_before["sha256"]
        or readback.get("size_bytes") != fingerprint_before["size_bytes"]
    ):
        raise AuthorizationError("saved plan upload digest or size mismatch")
    expires = datetime.fromisoformat(str(package.claim["expires_at"]).replace("Z", "+00:00"))
    created_at = _observed_time(clock=clock, fallback=now)
    plan_record = build_saved_plan_record(
        bindings=terminal_bindings,
        plan_environment_anchor_digest=package.context[
            "github_environment_anchor_digest"
        ],
        plan_sha256=readback["sha256"],
        plan_size_bytes=readback["size_bytes"],
        bucket=readback["bucket"],
        object_key=readback["object_key"],
        object_version_id=readback["object_version_id"],
        state_readback=before,
        plan_summary=plan_summary,
        cost_binding=_package_cost_binding(package),
        created_at=created_at,
        expires_at=expires,
    )
    write_private_json_once(package.controller_root / "plan-record.json", plan_record)


def run_terminal_fetch(
    package: LiveInputPackage,
    *,
    command_runner: CommandRunner = _default_command_runner,
) -> None:
    """Fetch one exact saved plan and current state under the Apply role."""
    _revalidate_materialized_sources(package)
    context = package.context
    role_name = str(context["apply_role_arn"]).rsplit("/", 1)[-1]
    plan_store = AwsCliPlanStore(
        region=context["region"], account_id=context["destination_account_id"], runner=command_runner
    )
    plan_store.verify_terminal_identity(role_name)
    plan_record = _private_json(package.controller_root / "plan-record.json")
    validate_saved_plan_document(plan_record)
    validate_saved_plan_cost_binding(plan_record, _package_cost_binding(package))
    storage = plan_record["storage"]
    plan_path = package.controller_root / "controlled.tfplan"
    readback = plan_store.get_plan_version(
        bucket=storage["bucket"],
        object_key=storage["object_key"],
        object_version_id=storage["object_version_id"],
        destination=plan_path,
    )
    state = read_exact_state(
        backend_binding=package.backend_binding,
        account_id=context["destination_account_id"],
        region=context["region"],
        scratch_path=package.controller_root / ".state-fetch.json",
        runner=command_runner,
    )
    if not _matches_reviewed_state(state, plan_record):
        plan_path.unlink(missing_ok=True)
        raise AuthorizationError("Terraform state changed after the saved plan was created")
    write_private_json_once(package.controller_root / "plan-readback.json", readback)
    write_private_json_once(package.controller_root / "state-readback.json", state)


def run_terminal_apply(
    package: LiveInputPackage,
    *,
    now: datetime,
    command_runner: CommandRunner = _default_command_runner,
    process_runner: ProcessRunner = _default_process_runner,
    clock: Clock | None = None,
) -> None:
    """Re-read state and execute the exact downloaded plan once under Apply."""
    _revalidate_materialized_sources(package)
    context = package.context
    role_name = str(context["apply_role_arn"]).rsplit("/", 1)[-1]
    AwsCliPlanStore(
        region=context["region"], account_id=context["destination_account_id"], runner=command_runner
    ).verify_terminal_identity(role_name)
    state = read_exact_state(
        backend_binding=package.backend_binding,
        account_id=context["destination_account_id"],
        region=context["region"],
        scratch_path=package.controller_root / ".state-apply.json",
        runner=command_runner,
    )
    state_readback = _private_json(package.controller_root / "state-readback.json")
    intent = _private_json(package.controller_root / "apply-intent.json")
    plan_record = _private_json(package.controller_root / "plan-record.json")
    validate_saved_plan_document(plan_record)
    if state != state_readback or not _matches_reviewed_state(state, plan_record):
        raise AuthorizationError("Terraform state changed immediately before apply")
    validate_saved_plan_cost_binding(plan_record, _package_cost_binding(package))
    approval = _private_json(package.controller_root / "approval-record.json")
    approved = _private_json(package.controller_root / "approved-ledger.json")
    applying = _private_json(package.controller_root / "applying-ledger.json")
    plan_readback = _private_json(package.controller_root / "plan-readback.json")
    validation_at = _observed_time(clock=clock, fallback=now)
    validate_apply_intent(
        intent=intent,
        context=context,
        plan_record=plan_record,
        approval_record=approval,
        approved_ledger=approved,
        applying_ledger=applying,
        plan_readback=plan_readback,
        state_readback=state_readback,
        now=validation_at,
    )
    command_spec = intent.get("command")
    if not isinstance(command_spec, Mapping) or command_spec.get("program") != SAVED_PLAN_RUNNER.relative_to(REPO_ROOT).as_posix():
        raise AuthorizationError("terminal Apply program is not canonical")
    argv = command_spec.get("argv")
    if not isinstance(argv, list) or not all(isinstance(item, str) for item in argv):
        raise AuthorizationError("terminal Apply command is invalid")
    if process_runner(("/bin/bash", str(SAVED_PLAN_RUNNER), *argv)) != 0:
        raise AuthorizationError("terminal saved-plan Apply response is not successful")


def validate_action_time_apply(
    package: LiveInputPackage,
    *,
    now: datetime,
    command_runner: CommandRunner = _default_command_runner,
) -> dict[str, Any]:
    """Rebuild all expiring authorities and reread state after init."""
    if package.operation != "apply":
        raise AuthorizationError("action-time validation requires apply inputs")
    _revalidate_materialized_sources(package)
    try:
        revalidate_private_root_at_action_time(
            private_root=package.private_root,
            deployment_id=package.context["deployment_id"],
            layer=package.context["layer"],
            operation="apply",
            claim_digest=package.claim["claim_digest"],
            environment=os.environ,
            now=now,
            repo_root=REPO_ROOT,
        )
    except LiveInputMaterializationError as exc:
        raise AuthorizationError(
            "action-time private authority is no longer current"
        ) from exc
    state = read_exact_state(
        backend_binding=package.backend_binding,
        account_id=package.context["destination_account_id"],
        region=package.context["region"],
        scratch_path=package.controller_root / ".state-action-time.json",
        runner=command_runner,
    )
    state_readback = _private_json(package.controller_root / "state-readback.json")
    plan_record = _private_json(package.controller_root / "plan-record.json")
    validate_saved_plan_document(plan_record)
    if state != state_readback or not _matches_reviewed_state(state, plan_record):
        raise AuthorizationError("Terraform state changed at action time")
    decision = validate_apply_intent(
        intent=_private_json(package.controller_root / "apply-intent.json"),
        context=package.context,
        plan_record=plan_record,
        approval_record=_private_json(package.controller_root / "approval-record.json"),
        approved_ledger=_private_json(package.controller_root / "approved-ledger.json"),
        applying_ledger=_private_json(package.controller_root / "applying-ledger.json"),
        plan_readback=_private_json(package.controller_root / "plan-readback.json"),
        state_readback=state_readback,
        now=now,
    )
    _revalidate_materialized_sources(package)
    return decision


def real_dependencies(package: LiveInputPackage) -> tuple[AwsCliTerminalSession, AwsCliExecutionLedgerStore]:
    context = package.context
    return (
        AwsCliTerminalSession(
            region=context["region"], account_id=context["destination_account_id"]
        ),
        AwsCliExecutionLedgerStore(
            region=context["region"],
            shared_services_account_id=context["platform_authority_account_id"],
            ledger_table="scanalyze-deployment-executions",
        ),
    )


__all__ = [
    "AwsCliReadError",
    "LiveInputPackage",
    "load_live_input_package",
    "read_exact_state",
    "real_dependencies",
    "run_apply_controller",
    "run_plan_controller",
    "run_terminal_apply",
    "validate_action_time_apply",
    "run_terminal_fetch",
    "run_terminal_plan",
    "write_private_json_once",
]
