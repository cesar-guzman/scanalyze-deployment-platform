"""Fail-closed materialization of repository-attested live ``dev`` inputs.

The materializer treats the protected Environment secret as untrusted transport.
Authority comes from one reviewed claim at a canonical repository path.  The
claim pins the exact canonical digest of one private sealed request.  Individual
source or output paths are never caller-selectable.

This module performs no network, GitHub API, AWS, Terraform, or subprocess
execution other than read-only Git ownership checks for the reviewed claim.
"""
from __future__ import annotations

import base64
import binascii
import copy
import json
import os
import re
import stat
import subprocess
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Mapping

import jsonschema
import yaml

from scripts.deployment.contract_projection import (
    ContractProjectionError,
    expected_resolvable_contracts,
    project_contracts,
)
from tooling.authorize_deployment_backend import (
    AuthorizationError,
    authorize_backend,
    canonical_digest,
    load_json_strict,
    load_yaml_strict,
)
from tooling.nonprod_live_engine import (
    MATERIALIZED_PLAN_BINDING_FIELDS,
    TERRAFORM_LAYERS,
    derive_approval_authority_digest,
)
from tooling.nonprod_live_orchestrator import (
    build_live_context,
    derive_source_revision_digest,
)
from tooling.validate_github_deployment_identity import (
    GitHubDeploymentIdentityError,
    derive_oidc_subject,
    environment_configuration_digest,
)


REPO_ROOT = Path(__file__).resolve().parents[1]
CLAIM_ROOT = Path("deployment/live-input-claims")
SEALED_REQUEST_NAME = "sealed-request.json"
SEALED_REQUEST_STAGE_NAME = ".sealed-request.json.stage"
GITHUB_EVIDENCE_DIR_NAME = "github-environment-evidence"
GITHUB_IDENTITY_FILENAME = "github-deployment-identity.json"
GITHUB_ANCHOR_FILENAME = "github-environment-anchor.json"
MATERIALIZED_DIR_NAME = "materialized"
SOURCE_DIR_NAME = "sources"
CONTROLLER_DIR_NAME = "controller"
PLAN_DIR_NAME = "plan"
# GitHub encrypted values are capped at 48 KB.  Keep the encoded payload below
# that control-plane limit and cap decoded bytes at the corresponding base64
# ceiling so an accepted request is transportable without an alternate path.
MAX_SEALED_REQUEST_BYTES = 36_000
MAX_ENCODED_REQUEST_BYTES = 48_000
SEALED_REQUEST_ENV = "SCANALYZE_LIVE_INPUT_BUNDLE_B64"
DIGEST = re.compile(r"^sha256:[a-f0-9]{64}$")
DEPLOYMENT_ID = re.compile(r"^dep_[0-9A-HJKMNP-TV-Z]{26}$")

SOURCE_FILENAMES = {
    "manifest": "manifest.json",
    "target_record": "target-record.json",
    "target_anchor": "target-anchor.json",
    "account_ready": "account-ready.json",
    "execution_lock": "execution-lock.json",
    "contract_resolution": "contract-resolution.json",
    "github_deployment_identity": "github-deployment-identity.json",
    "github_environment_anchor": "github-environment-anchor.json",
}
OUTPUT_FILENAMES = (
    "context.json",
    "bindings.json",
    "backend-binding.json",
    "plan-inputs.json",
    "apply-inputs.json",
    "manifest.json",
    "receipt.json",
)
RUNTIME_EVIDENCE_SOURCE_NAMES = frozenset({"github_environment_anchor"})
RUNTIME_ENVIRONMENT_FIELDS = {
    "event_name": "GITHUB_EVENT_NAME",
    "git_ref": "GITHUB_REF",
    "workflow_ref": "GITHUB_WORKFLOW_REF",
    "workflow_sha": "GITHUB_WORKFLOW_SHA",
    "main_sha": "GITHUB_SHA",
    "repository": "GITHUB_REPOSITORY",
    "repository_owner_id": "GITHUB_REPOSITORY_OWNER_ID",
    "repository_id": "GITHUB_REPOSITORY_ID",
    "workflow_run_id": "GITHUB_RUN_ID",
    "run_attempt": "GITHUB_RUN_ATTEMPT",
    "initiator_user_id": "GITHUB_ACTOR_ID",
}


class LiveInputMaterializationError(ValueError):
    """Stable, public-safe materialization failure."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def stable_sealed_request_digest(sealed_request: Mapping[str, Any]) -> str:
    """Digest only review-stable authority; runtime evidence self-digests later."""
    projection = copy.deepcopy(dict(sealed_request))
    projection.pop("sealed_request_digest", None)
    cost_model = projection.get("cost_model")
    if not isinstance(cost_model, dict):
        _fail("SEALED_REQUEST_INVALID")
    projection["cost_model"] = {
        key: cost_model.get(key)
        for key in (
            "currency",
            "modeled_cost_upper_bound_usd_micros",
        )
    }
    sources = projection.get("sources")
    if not isinstance(sources, dict):
        _fail("SEALED_REQUEST_INVALID")
    for name in RUNTIME_EVIDENCE_SOURCE_NAMES:
        sources.pop(name, None)
    resolution = sources.get("contract_resolution")
    if not isinstance(resolution, dict):
        _fail("SEALED_REQUEST_INVALID")
    sources["contract_resolution"] = {
        key: value
        for key, value in resolution.items()
        if key not in {"resolved_at", "resolution_digest"}
    }
    return canonical_digest(
        {
            "schema_version": "1",
            "record_type": "nonprod_live_stable_sealed_request_projection",
            "stable_request": projection,
        }
    )


@dataclass(frozen=True)
class MaterializedLiveInputs:
    """Complete private outputs and their sanitized deterministic receipt."""

    documents: Mapping[str, Mapping[str, Any]]
    source_documents: Mapping[str, Mapping[str, Any]]
    receipt: Mapping[str, Any]


def _fail(code: str) -> None:
    raise LiveInputMaterializationError(code)


def _schema(repo_root: Path, filename: str) -> dict[str, Any]:
    try:
        return load_json_strict(repo_root / "schemas" / filename)
    except AuthorizationError:
        _fail("MATERIALIZER_SCHEMA_INVALID")


def _validate_schema(
    document: Mapping[str, Any],
    *,
    repo_root: Path,
    filename: str,
    error_code: str,
) -> None:
    validator = jsonschema.Draft202012Validator(
        _schema(repo_root, filename),
        format_checker=jsonschema.FormatChecker(),
    )
    if next(iter(validator.iter_errors(document)), None) is not None:
        _fail(error_code)


def _parse_time(value: object, error_code: str) -> datetime:
    if not isinstance(value, str):
        _fail(error_code)
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        _fail(error_code)
    if parsed.tzinfo is None:
        _fail(error_code)
    return parsed.astimezone(UTC)


def _verify_digest(
    document: Mapping[str, Any], field: str, error_code: str
) -> None:
    claimed = document.get(field)
    expected = canonical_digest(
        {key: value for key, value in document.items() if key != field}
    )
    if claimed != expected:
        _fail(error_code)


def canonical_claim_path(
    *, deployment_id: str, layer: str, operation: str
) -> Path:
    """Derive the sole allowed repository claim path from typed selectors."""
    if not DEPLOYMENT_ID.fullmatch(deployment_id):
        _fail("CLAIM_SELECTOR_INVALID")
    if layer not in TERRAFORM_LAYERS or operation not in {"plan", "apply"}:
        _fail("CLAIM_SELECTOR_INVALID")
    return CLAIM_ROOT / deployment_id / layer / f"{operation}.json"


def _git_output(
    repo_root: Path,
    *arguments: str,
    error_code: str = "REPOSITORY_CLAIM_NOT_PROVEN",
) -> bytes:
    child_environment = os.environ.copy()
    child_environment.pop(SEALED_REQUEST_ENV, None)
    try:
        result = subprocess.run(
            ["git", "--no-pager", "-C", str(repo_root), *arguments],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=10,
            env=child_environment,
        )
    except (OSError, subprocess.SubprocessError):
        _fail(error_code)
    if result.returncode != 0:
        _fail(error_code)
    return result.stdout


def _read_repository_regular_file(
    repo_root: Path,
    relative: Path,
    *,
    error_code: str,
    maximum_bytes: int = 262_144,
) -> bytes:
    """Read one repository file through no-follow directory descriptors.

    Every repository-relative path component is opened from the already-open
    parent.  The final regular-file descriptor is then read exactly once.  This
    prevents a symlink substitution or pathname re-read from changing the
    bytes after they have been compared with the reviewed Git object.
    """
    parts = relative.parts
    if (
        relative.is_absolute()
        or not parts
        or any(part in {"", ".", ".."} for part in parts)
        or not hasattr(os, "O_NOFOLLOW")
        or not hasattr(os, "O_DIRECTORY")
    ):
        _fail(error_code)

    close_on_exec = getattr(os, "O_CLOEXEC", 0)
    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | close_on_exec
    file_flags = os.O_RDONLY | os.O_NOFOLLOW | close_on_exec
    descriptors: list[int] = []
    try:
        current = os.open(repo_root, directory_flags)
        descriptors.append(current)
        for part in parts[:-1]:
            current = os.open(part, directory_flags, dir_fd=current)
            descriptors.append(current)
        file_descriptor = os.open(parts[-1], file_flags, dir_fd=current)
        descriptors.append(file_descriptor)
        metadata = os.fstat(file_descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > maximum_bytes:
            _fail(error_code)

        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(file_descriptor, min(65_536, maximum_bytes + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > maximum_bytes:
                _fail(error_code)
        return b"".join(chunks)
    except (OSError, ValueError):
        _fail(error_code)
    finally:
        for descriptor in reversed(descriptors):
            try:
                os.close(descriptor)
            except OSError:
                pass


def _stable_head_bytes(
    repo_root: Path,
    relative: Path,
    *,
    error_code: str,
) -> bytes:
    """Return bytes from one stable reviewed HEAD commit."""
    relative_name = relative.as_posix()
    _git_output(
        repo_root,
        "ls-files",
        "--error-unmatch",
        "--",
        relative_name,
        error_code=error_code,
    )
    revision_bytes = _git_output(
        repo_root,
        "rev-parse",
        "--verify",
        "HEAD^{commit}",
        error_code=error_code,
    )
    try:
        revision = revision_bytes.decode("ascii").strip()
    except UnicodeDecodeError:
        _fail(error_code)
    if not re.fullmatch(r"[a-f0-9]{40,64}", revision):
        _fail(error_code)
    head_bytes = _git_output(
        repo_root,
        "show",
        f"{revision}:{relative_name}",
        error_code=error_code,
    )
    if (
        _git_output(
            repo_root,
            "rev-parse",
            "--verify",
            "HEAD^{commit}",
            error_code=error_code,
        )
        != revision_bytes
    ):
        _fail(error_code)
    return head_bytes


def _reject_duplicate_json_pairs(
    pairs: list[tuple[str, Any]],
) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


class _RepositoryBytesYamlLoader(yaml.SafeLoader):
    pass


def _construct_unique_yaml_mapping(
    loader: yaml.SafeLoader,
    node: yaml.nodes.MappingNode,
    deep: bool = False,
) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in result:
            raise ValueError("duplicate YAML key")
        result[key] = loader.construct_object(value_node, deep=deep)
    return result


_RepositoryBytesYamlLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_unique_yaml_mapping,
)


def _parse_repository_document_bytes(
    content: bytes,
    *,
    suffix: str,
    error_code: str,
) -> dict[str, Any]:
    """Strictly parse the exact byte string already proven against Git."""
    try:
        text = content.decode("utf-8")
        if suffix == ".json":
            value = json.loads(text, object_pairs_hook=_reject_duplicate_json_pairs)
        else:
            value = yaml.load(text, Loader=_RepositoryBytesYamlLoader)
    except (TypeError, UnicodeDecodeError, ValueError, yaml.YAMLError):
        _fail(error_code)
    if not isinstance(value, dict):
        _fail(error_code)
    return value


def load_repository_claim(
    *,
    repo_root: Path,
    deployment_id: str,
    layer: str,
    operation: str,
) -> dict[str, Any]:
    """Load one claim only when its working-tree bytes equal exact ``HEAD``."""
    relative = canonical_claim_path(
        deployment_id=deployment_id,
        layer=layer,
        operation=operation,
    )
    working_bytes = _read_repository_regular_file(
        repo_root,
        relative,
        error_code="REPOSITORY_CLAIM_NOT_PROVEN",
    )
    head_bytes = _stable_head_bytes(
        repo_root,
        relative,
        error_code="REPOSITORY_CLAIM_NOT_PROVEN",
    )
    if working_bytes != head_bytes:
        _fail("REPOSITORY_CLAIM_NOT_PROVEN")
    return _parse_repository_document_bytes(
        working_bytes,
        suffix=".json",
        error_code="CLAIM_INVALID",
    )


def load_repository_deployment_request(
    *,
    repo_root: Path,
    request_path: Path,
) -> dict[str, Any]:
    """Load one tracked request whose working bytes equal exact ``HEAD``."""
    if request_path.is_absolute():
        _fail("DEPLOYMENT_REQUEST_NOT_PROVEN")
    parts = request_path.parts
    if not parts or any(part in {"", ".", ".."} for part in parts):
        _fail("DEPLOYMENT_REQUEST_NOT_PROVEN")
    relative = Path(*parts)
    if relative.suffix not in {".json", ".yaml", ".yml"}:
        _fail("DEPLOYMENT_REQUEST_NOT_PROVEN")
    working_bytes = _read_repository_regular_file(
        repo_root,
        relative,
        error_code="DEPLOYMENT_REQUEST_NOT_PROVEN",
    )
    head_bytes = _stable_head_bytes(
        repo_root,
        relative,
        error_code="DEPLOYMENT_REQUEST_NOT_PROVEN",
    )
    if working_bytes != head_bytes:
        _fail("DEPLOYMENT_REQUEST_NOT_PROVEN")
    request = _parse_repository_document_bytes(
        working_bytes,
        suffix=relative.suffix,
        error_code="DEPLOYMENT_REQUEST_NOT_PROVEN",
    )
    _validate_schema(
        request,
        repo_root=repo_root,
        filename="deployment-request.schema.json",
        error_code="DEPLOYMENT_REQUEST_INVALID",
    )
    return request


def validate_repository_deployment_request_binding(
    *,
    claim: Mapping[str, Any],
    repo_root: Path,
    request_path: Path,
) -> None:
    request = load_repository_deployment_request(
        repo_root=repo_root,
        request_path=request_path,
    )
    embedded = claim.get("deployment_request")
    if (
        not isinstance(embedded, Mapping)
        or request != dict(embedded)
        or canonical_digest(request) != claim.get("deployment_request_digest")
    ):
        _fail("DEPLOYMENT_REQUEST_BINDING_MISMATCH")


def _validate_deployment_request(
    request: Mapping[str, Any],
    *,
    claim: Mapping[str, Any],
    repo_root: Path,
) -> None:
    _validate_schema(
        request,
        repo_root=repo_root,
        filename="deployment-request.schema.json",
        error_code="DEPLOYMENT_REQUEST_INVALID",
    )
    if (
        request.get("deployment_id") != claim.get("deployment_id")
        or request.get("environment") != "dev"
        or request.get("release_digest") != claim.get("release_digest")
        or request.get("non_sensitive_selectors", {}).get("region")
        != claim.get("region")
    ):
        _fail("DEPLOYMENT_REQUEST_BINDING_MISMATCH")
    target_matches = request.get("full_deployment") is True or request.get(
        "target_layer"
    ) == claim.get("layer")
    if not target_matches:
        _fail("DEPLOYMENT_REQUEST_BINDING_MISMATCH")
    approval = request.get("approval")
    if (
        not isinstance(approval, Mapping)
        or approval.get("status") != "approved"
        or approval.get("decided_by") == request.get("requested_by")
    ):
        _fail("DEPLOYMENT_REQUEST_NOT_APPROVED")


def validate_claim(
    claim: Mapping[str, Any],
    *,
    deployment_id: str,
    layer: str,
    operation: str,
    claim_digest: str,
    now: datetime,
    repo_root: Path = REPO_ROOT,
) -> None:
    """Validate schema, digest, selectors, approval, and bounded lifetime."""
    _validate_schema(
        claim,
        repo_root=repo_root,
        filename="nonprod-live-input-claim.v1.schema.json",
        error_code="CLAIM_INVALID",
    )
    _verify_digest(claim, "claim_digest", "CLAIM_DIGEST_MISMATCH")
    if not DIGEST.fullmatch(claim_digest) or claim.get("claim_digest") != claim_digest:
        _fail("CLAIM_DIGEST_MISMATCH")
    expected = {
        "deployment_id": deployment_id,
        "layer": layer,
        "operation": operation,
        "environment": "dev",
    }
    if any(claim.get(field) != value for field, value in expected.items()):
        _fail("CLAIM_SELECTOR_MISMATCH")
    current = now.astimezone(UTC) if now.tzinfo else None
    if current is None:
        _fail("VALIDATION_TIME_INVALID")
    valid_from = _parse_time(claim.get("valid_from"), "CLAIM_TIME_INVALID")
    expires_at = _parse_time(claim.get("expires_at"), "CLAIM_TIME_INVALID")
    if (
        expires_at <= valid_from
        or (expires_at - valid_from).total_seconds() > 86_400
        or current < valid_from
        or current >= expires_at
    ):
        _fail("CLAIM_NOT_CURRENT")
    request = claim.get("deployment_request")
    if not isinstance(request, Mapping):
        _fail("DEPLOYMENT_REQUEST_INVALID")
    if claim.get("deployment_request_digest") != canonical_digest(dict(request)):
        _fail("DEPLOYMENT_REQUEST_DIGEST_MISMATCH")
    _validate_deployment_request(request, claim=claim, repo_root=repo_root)


def _validate_private_root(private_root: Path, repo_root: Path) -> Path:
    if not private_root.is_absolute() or private_root.is_symlink():
        _fail("PRIVATE_ROOT_INVALID")
    try:
        root = private_root.resolve(strict=True)
        root_stat = root.stat()
    except OSError:
        _fail("PRIVATE_ROOT_INVALID")
    try:
        root.relative_to(repo_root.resolve())
    except ValueError:
        pass
    else:
        _fail("PRIVATE_ROOT_INVALID")
    if (
        not root.is_dir()
        or root_stat.st_uid != os.getuid()
        or stat.S_IMODE(root_stat.st_mode) != 0o700
    ):
        _fail("PRIVATE_ROOT_INVALID")
    return root


def _validate_private_file(path: Path, *, max_bytes: int) -> None:
    if path.is_symlink():
        _fail("SEALED_REQUEST_INVALID")
    try:
        file_stat = path.stat()
    except OSError:
        _fail("SEALED_REQUEST_INVALID")
    if (
        not path.is_file()
        or file_stat.st_uid != os.getuid()
        or stat.S_IMODE(file_stat.st_mode) != 0o600
        or file_stat.st_size < 2
        or file_stat.st_size > max_bytes
    ):
        _fail("SEALED_REQUEST_INVALID")


def stage_sealed_request_from_environment(
    *, private_root: Path, environment: Mapping[str, str] | None = None
) -> Path:
    """Stage a strictly decoded transport secret at the fixed input path."""
    destination = private_root / SEALED_REQUEST_NAME
    staging = private_root / SEALED_REQUEST_STAGE_NAME
    encoded = (
        os.environ.pop(SEALED_REQUEST_ENV, None)
        if environment is None
        else environment.get(SEALED_REQUEST_ENV)
    )
    if destination.exists() or destination.is_symlink():
        if encoded:
            _fail("SEALED_REQUEST_ALREADY_EXISTS")
        _validate_private_file(destination, max_bytes=MAX_SEALED_REQUEST_BYTES)
        return destination
    if staging.exists() or staging.is_symlink():
        _fail("SEALED_REQUEST_TRANSPORT_INVALID")
    if not isinstance(encoded, str) or not encoded:
        _fail("SEALED_REQUEST_TRANSPORT_MISSING")
    if len(encoded.encode("ascii", errors="ignore")) != len(encoded) or len(
        encoded
    ) > MAX_ENCODED_REQUEST_BYTES:
        _fail("SEALED_REQUEST_TRANSPORT_INVALID")

    decoded: bytearray | None = None
    view: memoryview | None = None
    descriptor: int | None = None
    directory_descriptor: int | None = None
    stage_created = False
    destination_created = False
    try:
        decoded = bytearray(base64.b64decode(encoded, validate=True))
        if not 2 <= len(decoded) <= MAX_SEALED_REQUEST_BYTES:
            _fail("SEALED_REQUEST_TRANSPORT_INVALID")
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(staging, flags, 0o600)
        stage_created = True
        view = memoryview(decoded)
        written = 0
        while written < len(view):
            written += os.write(descriptor, view[written:])
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = None
        os.chmod(staging, 0o600)
        os.link(staging, destination, follow_symlinks=False)
        destination_created = True
        staging.unlink()
        stage_created = False
        directory_flags = os.O_RDONLY
        if hasattr(os, "O_DIRECTORY"):
            directory_flags |= os.O_DIRECTORY
        directory_descriptor = os.open(private_root, directory_flags)
        os.fsync(directory_descriptor)
        os.close(directory_descriptor)
        directory_descriptor = None
    except (UnicodeEncodeError, binascii.Error, OSError, ValueError):
        if destination_created:
            destination.unlink(missing_ok=True)
        if stage_created:
            staging.unlink(missing_ok=True)
        _fail("SEALED_REQUEST_TRANSPORT_INVALID")
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if directory_descriptor is not None:
            os.close(directory_descriptor)
        if view is not None:
            view.release()
        if decoded is not None:
            decoded[:] = b"\x00" * len(decoded)
    _validate_private_file(destination, max_bytes=MAX_SEALED_REQUEST_BYTES)
    return destination


def _runtime_environment(environment: Mapping[str, str]) -> dict[str, Any]:
    values: dict[str, Any] = {}
    for field, variable in RUNTIME_ENVIRONMENT_FIELDS.items():
        value = environment.get(variable)
        if not isinstance(value, str) or not value or any(
            character in value for character in "\x00\r\n"
        ):
            _fail("GITHUB_RUNTIME_BINDING_INVALID")
        values[field] = value
    for field in (
        "repository_owner_id",
        "repository_id",
        "workflow_run_id",
        "run_attempt",
        "initiator_user_id",
    ):
        try:
            parsed = int(values[field])
        except ValueError:
            _fail("GITHUB_RUNTIME_BINDING_INVALID")
        if parsed < 1:
            _fail("GITHUB_RUNTIME_BINDING_INVALID")
        values[field] = parsed
    return values


def _validate_exact_git_runtime(
    *, runtime: Mapping[str, Any], claim: Mapping[str, Any], repo_root: Path
) -> None:
    if runtime.get("repository") != claim.get("repository"):
        _fail("GITHUB_RUNTIME_BINDING_MISMATCH")
    if (
        runtime.get("event_name") != "workflow_dispatch"
        or runtime.get("git_ref") != "refs/heads/main"
        or runtime.get("workflow_sha") != runtime.get("main_sha")
        or runtime.get("run_attempt") != 1
    ):
        _fail("GITHUB_RUNTIME_BINDING_MISMATCH")
    expected_ref = (
        f"{claim['repository']}/.github/workflows/"
        "nonprod-release.yml@refs/heads/main"
    )
    if runtime.get("workflow_ref") != expected_ref:
        _fail("GITHUB_RUNTIME_BINDING_MISMATCH")
    head_sha = _git_output(repo_root, "rev-parse", "HEAD").decode("ascii").strip()
    if runtime.get("main_sha") != head_sha:
        _fail("GITHUB_RUNTIME_BINDING_MISMATCH")


def _validate_github_approval_authority(
    *,
    claim: Mapping[str, Any],
    sealed_request: Mapping[str, Any],
    runtime: Mapping[str, Any],
    now: datetime,
    repo_root: Path,
) -> dict[str, Any]:
    """Bind one fresh independent Environment anchor to a reviewed identity."""
    sources = sealed_request["sources"]
    identity = sources["github_deployment_identity"]
    anchor = sources["github_environment_anchor"]
    release = sealed_request["release_bindings"]
    manifest = sources["manifest"]
    target = sources["target_record"]
    account_ready = sources["account_ready"]
    authority = sealed_request["authority_bindings"]
    _validate_schema(
        identity,
        repo_root=repo_root,
        filename="github-deployment-identity.v1.schema.json",
        error_code="GITHUB_DEPLOYMENT_IDENTITY_INVALID",
    )
    _verify_digest(
        identity,
        "contract_digest",
        "GITHUB_DEPLOYMENT_IDENTITY_DIGEST_MISMATCH",
    )
    _validate_schema(
        anchor,
        repo_root=repo_root,
        filename="github-environment-anchor.v1.schema.json",
        error_code="GITHUB_ENVIRONMENT_ANCHOR_INVALID",
    )
    _verify_digest(
        anchor,
        "evidence_digest",
        "GITHUB_ENVIRONMENT_ANCHOR_DIGEST_MISMATCH",
    )

    try:
        owner, repository_name = claim["repository"].split("/", 1)
        repository = identity["repository"]
        workflow = identity["workflow"]
        protection = identity["environment_protection"]
        oidc = identity["oidc"]
        reviewers = protection["required_reviewers"]
        if len(reviewers) != 1:
            _fail("GITHUB_ENVIRONMENT_REVIEWER_NOT_EXACT")
        reviewer = reviewers[0]
        if reviewer.get("type") != "User":
            _fail("GITHUB_ENVIRONMENT_REVIEWER_NOT_EXACT")
        reviewer_id = int(reviewer["id"])
        if reviewer_id < 1 or reviewer_id == runtime["initiator_user_id"]:
            _fail("GITHUB_ENVIRONMENT_REVIEWER_NOT_INDEPENDENT")
        github_environment = f"scanalyze-{claim['deployment_id']}-dev"
        identity_expected = {
            "customer_id": manifest["customer_id"],
            "deployment_id": claim["deployment_id"],
            "account_id": target["account_id"],
            "region": claim["region"],
            "environment": "dev",
        }
        if any(identity.get(key) != value for key, value in identity_expected.items()):
            _fail("GITHUB_DEPLOYMENT_IDENTITY_BINDING_MISMATCH")
        repository_expected = {
            "owner": owner,
            "name": repository_name,
            "owner_id": str(runtime["repository_owner_id"]),
            "repository_id": str(runtime["repository_id"]),
        }
        if any(repository.get(key) != value for key, value in repository_expected.items()):
            _fail("GITHUB_DEPLOYMENT_IDENTITY_BINDING_MISMATCH")
        workflow_expected = {
            "path": ".github/workflows/nonprod-release.yml",
            "ref": "refs/heads/main",
            "workflow_ref": runtime["workflow_ref"],
            "event_name": "workflow_dispatch",
            "execution_mode": "live",
            "github_environment": github_environment,
        }
        if workflow != workflow_expected:
            _fail("GITHUB_DEPLOYMENT_IDENTITY_BINDING_MISMATCH")
        if (
            oidc["subject"] != derive_oidc_subject(identity)
            or oidc["orchestrator_role_arn"] != authority["orchestrator_role_arn"]
            or protection["name"] != github_environment
        ):
            _fail("GITHUB_DEPLOYMENT_IDENTITY_BINDING_MISMATCH")

        expected_variables = {
            "CUSTOMER_ID": manifest["customer_id"],
            "DEPLOYMENT_ID": claim["deployment_id"],
            "AWS_ACCOUNT_ID": target["account_id"],
            "AWS_REGION": claim["region"],
            "LOGICAL_ENVIRONMENT": "dev",
            "OIDC_ORCHESTRATOR_ROLE_ARN": authority["orchestrator_role_arn"],
            "ORCHESTRATOR_ROLE_ARN": authority["orchestrator_role_arn"],
            "GENERIC_PLAN_ROLE_ARN": _select_role(account_ready, "global", "plan"),
            "GENERIC_APPLY_ROLE_ARN": _select_role(account_ready, "global", "apply"),
            "IDENTITY_PLAN_ROLE_ARN": _select_role(
                account_ready, "identity-control-plane", "plan"
            ),
            "IDENTITY_APPLY_ROLE_ARN": _select_role(
                account_ready, "identity-control-plane", "apply"
            ),
            "PLATFORM_AUTHORITY_ACCOUNT_ID": authority[
                "platform_authority_account_id"
            ],
            "REPOSITORY_ID": str(runtime["repository_id"]),
            "REPOSITORY_OWNER_ID": str(runtime["repository_owner_id"]),
            "SECOND_P0_REVIEWER_ID": str(reviewer_id),
            "GITHUB_ENVIRONMENT_COLLECTOR_APP_ID": identity[
                "collector_authority"
            ]["app_id"],
        }
        if protection["variables"] != expected_variables:
            _fail("GITHUB_ENVIRONMENT_VARIABLE_BINDING_MISMATCH")
        role_bindings = {
            "plan": expected_variables["GENERIC_PLAN_ROLE_ARN"],
            "apply": expected_variables["GENERIC_APPLY_ROLE_ARN"],
            "identity_plan": expected_variables["IDENTITY_PLAN_ROLE_ARN"],
            "identity_apply": expected_variables["IDENTITY_APPLY_ROLE_ARN"],
        }
        if any(
            identity["terminal_roles"][name]["role_arn"] != role_arn
            for name, role_arn in role_bindings.items()
        ):
            _fail("GITHUB_DEPLOYMENT_IDENTITY_BINDING_MISMATCH")
        configuration_digest = environment_configuration_digest(identity)
    except LiveInputMaterializationError:
        raise
    except (GitHubDeploymentIdentityError, KeyError, TypeError, ValueError):
        _fail("GITHUB_DEPLOYMENT_IDENTITY_INVALID")

    if (
        identity["contract_digest"] != release["github_deployment_identity_digest"]
        or configuration_digest != release["environment_configuration_digest"]
    ):
        _fail("GITHUB_ENVIRONMENT_CONFIGURATION_MISMATCH")
    anchor_expected = {
        "source": "github-api",
        "repository_owner_id": str(runtime["repository_owner_id"]),
        "repository_id": str(runtime["repository_id"]),
        "environment_name": github_environment,
        "configuration_digest": configuration_digest,
    }
    if any(anchor.get(key) != value for key, value in anchor_expected.items()):
        _fail("GITHUB_ENVIRONMENT_ANCHOR_BINDING_MISMATCH")
    captured_at = _parse_time(
        anchor.get("captured_at"), "GITHUB_ENVIRONMENT_ANCHOR_TIME_INVALID"
    )
    expires_at = _parse_time(
        anchor.get("expires_at"), "GITHUB_ENVIRONMENT_ANCHOR_TIME_INVALID"
    )
    current = now.astimezone(UTC) if now.tzinfo else None
    if (
        current is None
        or captured_at > current
        or current >= expires_at
        or not 0 < (expires_at - captured_at).total_seconds() <= 600
    ):
        _fail("GITHUB_ENVIRONMENT_ANCHOR_NOT_CURRENT")
    if authority["expected_approver_user_id"] != reviewer_id:
        _fail("GITHUB_ENVIRONMENT_REVIEWER_BINDING_MISMATCH")
    approval_authority_digest = derive_approval_authority_digest(
        github_environment=github_environment,
        expected_approver_user_id=reviewer_id,
        github_deployment_identity_digest=identity["contract_digest"],
        environment_configuration_digest=configuration_digest,
    )
    return {
        "expected_approver_user_id": reviewer_id,
        "github_environment_anchor_digest": anchor["evidence_digest"],
        "approval_authority_digest": approval_authority_digest,
    }


def _read_sealed_request(path: Path) -> dict[str, Any]:
    _validate_private_file(path, max_bytes=MAX_SEALED_REQUEST_BYTES)
    try:
        return load_json_strict(path)
    except AuthorizationError:
        _fail("SEALED_REQUEST_INVALID")


def _bind_collected_github_evidence(
    sealed_request: Mapping[str, Any], *, private_root: Path
) -> dict[str, Any]:
    """Bind a workflow-collected fresh anchor to the reviewed stable identity."""
    evidence_root = private_root / GITHUB_EVIDENCE_DIR_NAME
    if not evidence_root.exists() and not evidence_root.is_symlink():
        return copy.deepcopy(dict(sealed_request))
    try:
        metadata = evidence_root.stat(follow_symlinks=False)
    except OSError:
        _fail("GITHUB_ENVIRONMENT_EVIDENCE_INVALID")
    if (
        evidence_root.is_symlink()
        or not evidence_root.is_dir()
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        _fail("GITHUB_ENVIRONMENT_EVIDENCE_INVALID")
    identity = _read_private_output(evidence_root / GITHUB_IDENTITY_FILENAME)
    anchor = _read_private_output(evidence_root / GITHUB_ANCHOR_FILENAME)
    bound = copy.deepcopy(dict(sealed_request))
    try:
        sources = bound["sources"]
        if identity != sources["github_deployment_identity"]:
            _fail("GITHUB_DEPLOYMENT_IDENTITY_BINDING_MISMATCH")
        sources["github_environment_anchor"] = anchor
    except (KeyError, TypeError):
        _fail("SEALED_REQUEST_INVALID")
    return bound


def _validate_sealed_request(
    sealed_request: Mapping[str, Any],
    *,
    claim: Mapping[str, Any],
    repo_root: Path,
) -> None:
    _validate_schema(
        sealed_request,
        repo_root=repo_root,
        filename="nonprod-live-input-sealed-request.v1.schema.json",
        error_code="SEALED_REQUEST_INVALID",
    )
    if sealed_request.get("sealed_request_digest") != stable_sealed_request_digest(
        sealed_request
    ):
        _fail("SEALED_REQUEST_DIGEST_MISMATCH")
    if (
        sealed_request.get("sealed_request_digest")
        != claim.get("sealed_request_digest")
    ):
        _fail("SEALED_REQUEST_CLAIM_MISMATCH")


def _validate_cost_guard(
    *,
    claim: Mapping[str, Any],
    sealed_request: Mapping[str, Any],
    now: datetime,
) -> Mapping[str, Any]:
    cost_model = sealed_request.get("cost_model")
    if not isinstance(cost_model, Mapping):
        _fail("COST_MODEL_INVALID")
    _verify_digest(cost_model, "cost_model_digest", "COST_MODEL_DIGEST_MISMATCH")
    maximum = claim.get("maximum_cost_usd_micros")
    modeled = cost_model.get("modeled_cost_upper_bound_usd_micros")
    if (
        isinstance(maximum, bool)
        or not isinstance(maximum, int)
        or isinstance(modeled, bool)
        or not isinstance(modeled, int)
        or maximum < 0
        or modeled < 0
        or modeled > maximum
    ):
        _fail("COST_BOUND_EXCEEDED")
    modeled_at = _parse_time(cost_model.get("modeled_at"), "COST_MODEL_TIME_INVALID")
    expires_at = _parse_time(cost_model.get("expires_at"), "COST_MODEL_TIME_INVALID")
    current = now.astimezone(UTC) if now.tzinfo else None
    if (
        current is None
        or expires_at <= modeled_at
        or (expires_at - modeled_at).total_seconds() > 86_400
        or current < modeled_at
        or current >= expires_at
    ):
        _fail("COST_MODEL_NOT_CURRENT")
    return cost_model


def _validate_contract_resolution(
    resolution: Mapping[str, Any],
    *,
    claim: Mapping[str, Any],
    sealed_request: Mapping[str, Any],
    layer_catalog: Mapping[str, Any],
    now: datetime,
    repo_root: Path,
) -> None:
    _validate_schema(
        resolution,
        repo_root=repo_root,
        filename="contract-resolution.v3.schema.json",
        error_code="CONTRACT_RESOLUTION_INVALID",
    )
    _verify_digest(
        resolution, "resolution_digest", "CONTRACT_RESOLUTION_DIGEST_MISMATCH"
    )
    manifest = sealed_request["sources"]["manifest"]
    release = sealed_request["release_bindings"]
    expected = {
        "consumer_layer": claim["layer"],
        "customer_id": manifest["customer_id"],
        "deployment_id": claim["deployment_id"],
        "aws_account_id": manifest["aws_account_id"],
        "region": claim["region"],
        "release_version": release["release_version"],
        "release_digest": claim["release_digest"],
    }
    if any(resolution.get(field) != value for field, value in expected.items()):
        _fail("CONTRACT_RESOLUTION_BINDING_MISMATCH")

    resolved_at = _parse_time(
        resolution.get("resolved_at"), "CONTRACT_RESOLUTION_TIME_INVALID"
    )
    current = now.astimezone(UTC)
    max_age = resolution.get("max_contract_age_seconds")
    if (
        isinstance(max_age, bool)
        or not isinstance(max_age, int)
        or max_age < 1
        or resolved_at > current
        or (current - resolved_at).total_seconds() > max_age
    ):
        _fail("CONTRACT_RESOLUTION_NOT_CURRENT")

    try:
        contract_catalog = load_json_strict(
            repo_root / "deployment" / "contract-catalog.v1.json"
        )
        envelope_schema = load_json_strict(
            repo_root / "schemas" / "layer-contract.v2.schema.json"
        )
        expected_contracts = expected_resolvable_contracts(
            layer_catalog,
            contract_catalog,
            claim["layer"],
        )
    except (AuthorizationError, ContractProjectionError, KeyError, TypeError):
        _fail("CONTRACT_RESOLUTION_CATALOG_INVALID")
    evidence = resolution.get("required_contracts")
    if not isinstance(evidence, list):
        _fail("CONTRACT_RESOLUTION_INVALID")
    try:
        project_contracts(
            evidence,
            envelope_schema,
            catalog=contract_catalog,
            dag=layer_catalog,
            layer=claim["layer"],
            customer_id=manifest["customer_id"],
            deployment_id=claim["deployment_id"],
            account_id=manifest["aws_account_id"],
            region=claim["region"],
            release_digest=claim["release_digest"],
            release_version=release["release_version"],
            resolved_at=resolved_at,
            max_contract_age_seconds=max_age,
            required_contracts=expected_contracts,
            expected_account_ready_digest=sealed_request["sources"][
                "account_ready"
            ]["contract_digest"],
        )
    except (ContractProjectionError, KeyError, TypeError):
        _fail("CONTRACT_RESOLUTION_EVIDENCE_INVALID")


def _select_role(account_ready: Mapping[str, Any], layer: str, operation: str) -> str:
    prefix = "identity_" if layer == "identity-control-plane" else ""
    role = account_ready.get("roles", {}).get(f"{prefix}{operation}", {}).get("arn")
    if not isinstance(role, str):
        _fail("TERMINAL_ROLE_BINDING_INVALID")
    return role


def _build_context(
    *,
    claim: Mapping[str, Any],
    sealed_request: Mapping[str, Any],
    runtime: Mapping[str, Any],
    approval_authority: Mapping[str, Any],
) -> dict[str, Any]:
    manifest = sealed_request["sources"]["manifest"]
    target = sealed_request["sources"]["target_record"]
    account_ready = sealed_request["sources"]["account_ready"]
    authority = sealed_request["authority_bindings"]
    release = sealed_request["release_bindings"]
    try:
        return build_live_context(
            event_name=runtime["event_name"],
            git_ref=runtime["git_ref"],
            workflow_ref=runtime["workflow_ref"],
            workflow_sha=runtime["workflow_sha"],
            main_sha=runtime["main_sha"],
            repository_owner_id=runtime["repository_owner_id"],
            repository_id=runtime["repository_id"],
            workflow_run_id=runtime["workflow_run_id"],
            workflow_run_attempt=runtime["run_attempt"],
            initiator_user_id=runtime["initiator_user_id"],
            customer_id=manifest["customer_id"],
            deployment_id=claim["deployment_id"],
            execution_id=claim["execution_id"],
            change_id=claim["change_id"],
            destination_account_id=target["account_id"],
            platform_authority_account_id=authority[
                "platform_authority_account_id"
            ],
            region=claim["region"],
            environment="dev",
            github_environment=f"scanalyze-{claim['deployment_id']}-dev",
            layer=claim["layer"],
            release_digest=claim["release_digest"],
            source_revision_digest=derive_source_revision_digest(
                runtime["workflow_sha"]
            ),
            github_deployment_identity_digest=release[
                "github_deployment_identity_digest"
            ],
            environment_configuration_digest=release[
                "environment_configuration_digest"
            ],
            github_environment_anchor_digest=approval_authority[
                "github_environment_anchor_digest"
            ],
            expected_approver_user_id=approval_authority[
                "expected_approver_user_id"
            ],
            approval_authority_digest=approval_authority[
                "approval_authority_digest"
            ],
            platform_authority_digest=release["platform_authority_digest"],
            registry_record_digest=target["record_digest"],
            account_ready_digest=account_ready["contract_digest"],
            orchestrator_role_arn=authority["orchestrator_role_arn"],
            plan_role_arn=_select_role(account_ready, claim["layer"], "plan"),
            apply_role_arn=_select_role(account_ready, claim["layer"], "apply"),
            oidc_audience="sts.amazonaws.com",
            control_plane_session_duration_seconds=3600,
            terminal_session_duration_seconds=3600,
        )
    except (AuthorizationError, KeyError, TypeError):
        _fail("LIVE_CONTEXT_INVALID")


def _build_bindings(
    *,
    claim: Mapping[str, Any],
    sealed_request: Mapping[str, Any],
    context: Mapping[str, Any],
    backend_binding: Mapping[str, Any],
) -> dict[str, Any]:
    target = sealed_request["sources"]["target_record"]
    account_ready = sealed_request["sources"]["account_ready"]
    execution_lock = sealed_request["sources"]["execution_lock"]
    resolution = sealed_request["sources"]["contract_resolution"]
    release = sealed_request["release_bindings"]
    bindings: dict[str, Any] = {
        "customer_id": context["customer_id"],
        "deployment_id": claim["deployment_id"],
        "account_id": target["account_id"],
        "region": claim["region"],
        "environment": "dev",
        "execution_id": claim["execution_id"],
        "change_id": claim["change_id"],
        "layer": claim["layer"],
        "release_version": release["release_version"],
        "release_digest": claim["release_digest"],
        "release_policy_digest": release["release_policy_digest"],
        "release_projection_digest": release["release_projection_digest"],
        "plan_policy_digest": release["plan_policy_digest"],
        "github_environment": context["github_environment"],
        "github_deployment_identity_digest": context[
            "github_deployment_identity_digest"
        ],
        "environment_configuration_digest": context[
            "environment_configuration_digest"
        ],
        "expected_approver_user_id": context["expected_approver_user_id"],
        "approval_authority_digest": context["approval_authority_digest"],
        "platform_authority_digest": context["platform_authority_digest"],
        "registry_record_digest": target["record_digest"],
        "account_ready_digest": account_ready["contract_digest"],
        "execution_lock_digest": execution_lock["lock_digest"],
        "backend_binding_digest": backend_binding["binding_digest"],
        "contract_resolution_digest": resolution["resolution_digest"],
        "toolchain_digest": release["toolchain_digest"],
        "root_module_digest": release["root_module_digest"],
        "source_revision_digest": context["source_revision_digest"],
    }
    if set(bindings) != set(MATERIALIZED_PLAN_BINDING_FIELDS):
        _fail("SAVED_PLAN_BINDINGS_INCOMPLETE")
    for field in MATERIALIZED_PLAN_BINDING_FIELDS:
        if field.endswith("_digest") and not DIGEST.fullmatch(str(bindings[field])):
            _fail("SAVED_PLAN_BINDINGS_INVALID")
    return bindings


def _source_paths(private_root: Path) -> dict[str, str]:
    base = private_root / MATERIALIZED_DIR_NAME / SOURCE_DIR_NAME
    return {key: str(base / filename) for key, filename in SOURCE_FILENAMES.items()}


def _input_maps(private_root: Path) -> tuple[dict[str, str], dict[str, str]]:
    materialized = private_root / MATERIALIZED_DIR_NAME
    sources = _source_paths(private_root)
    plan = {
        "plan_dir": str(materialized / PLAN_DIR_NAME),
        "resolved_input": sources["contract_resolution"],
        "manifest": sources["manifest"],
        "target_record": sources["target_record"],
        "target_anchor": sources["target_anchor"],
        "account_ready": sources["account_ready"],
        "execution_lock": sources["execution_lock"],
    }
    controller = materialized / CONTROLLER_DIR_NAME
    apply = {
        "apply_intent": str(controller / "apply-intent.json"),
        "context": str(materialized / "context.json"),
        "approved_ledger": str(controller / "approved-ledger.json"),
        "applying_ledger": str(controller / "applying-ledger.json"),
        "plan_record": str(controller / "plan-record.json"),
        "approval_record": str(controller / "approval-record.json"),
        "plan_readback": str(controller / "plan-readback.json"),
        "state_readback": str(controller / "state-readback.json"),
        "manifest": sources["manifest"],
        "target_record": sources["target_record"],
        "target_anchor": sources["target_anchor"],
        "account_ready": sources["account_ready"],
        "execution_lock": sources["execution_lock"],
    }
    return plan, apply


def _semantic_input_digests(
    source_digests: Mapping[str, str], claim: Mapping[str, Any]
) -> tuple[str, str]:
    plan = canonical_digest(
        {
            "layer": claim["layer"],
            "operation": "plan",
            "source_digests": dict(source_digests),
            "plan_path_policy": "FIXED_PRIVATE_ROOT_LAYER_TFPLAN",
        }
    )
    apply = canonical_digest(
        {
            "layer": claim["layer"],
            "operation": "apply",
            "source_digests": dict(source_digests),
            "controller_paths": "FIXED_DURABLE_CONSISTENT_READ_SLOTS",
        }
    )
    return plan, apply


def materialize_live_inputs(
    *,
    claim: Mapping[str, Any],
    sealed_request: Mapping[str, Any],
    deployment_id: str,
    layer: str,
    operation: str,
    claim_digest: str,
    private_root: Path,
    runtime_environment: Mapping[str, str],
    now: datetime,
    repo_root: Path = REPO_ROOT,
) -> MaterializedLiveInputs:
    """Validate and build deterministic, private saved-plan input documents."""
    validate_claim(
        claim,
        deployment_id=deployment_id,
        layer=layer,
        operation=operation,
        claim_digest=claim_digest,
        now=now,
        repo_root=repo_root,
    )
    _validate_sealed_request(sealed_request, claim=claim, repo_root=repo_root)
    cost_model = _validate_cost_guard(
        claim=claim,
        sealed_request=sealed_request,
        now=now,
    )
    runtime = _runtime_environment(runtime_environment)
    _validate_exact_git_runtime(runtime=runtime, claim=claim, repo_root=repo_root)
    approval_authority = _validate_github_approval_authority(
        claim=claim,
        sealed_request=sealed_request,
        runtime=runtime,
        now=now,
        repo_root=repo_root,
    )

    sources = sealed_request["sources"]
    layer_catalog = load_yaml_strict(repo_root / "deployment" / "layers.yaml")
    try:
        backend_binding = authorize_backend(
            manifest=copy.deepcopy(sources["manifest"]),
            target=copy.deepcopy(sources["target_record"]),
            anchor=copy.deepcopy(sources["target_anchor"]),
            account_ready=copy.deepcopy(sources["account_ready"]),
            execution_lock=copy.deepcopy(sources["execution_lock"]),
            layer_catalog=layer_catalog,
            layer=layer,
            now=now,
            schema_dir=repo_root / "schemas",
        )
    except (AuthorizationError, KeyError, TypeError):
        _fail("BACKEND_AUTHORIZATION_DENIED")
    _validate_contract_resolution(
        sources["contract_resolution"],
        claim=claim,
        sealed_request=sealed_request,
        layer_catalog=layer_catalog,
        now=now,
        repo_root=repo_root,
    )
    context = _build_context(
        claim=claim,
        sealed_request=sealed_request,
        runtime=runtime,
        approval_authority=approval_authority,
    )
    bindings = _build_bindings(
        claim=claim,
        sealed_request=sealed_request,
        context=context,
        backend_binding=backend_binding,
    )
    plan_inputs, apply_inputs = _input_maps(private_root)

    source_documents = {
        key: copy.deepcopy(sources[key]) for key in SOURCE_FILENAMES
    }
    source_digests = {
        key: canonical_digest(dict(document))
        for key, document in sorted(source_documents.items())
    }
    plan_inputs_digest, apply_inputs_digest = _semantic_input_digests(
        source_digests, claim
    )
    runtime_binding_digest = canonical_digest(
        {
            "claim_digest": claim_digest,
            "context_digest": context["context_digest"],
            "run_attempt": runtime["run_attempt"],
        }
    )
    plan_ready = operation == "plan"
    durable_readback_required = operation == "apply"
    manifest: dict[str, Any] = {
        "schema_version": "1",
        "record_type": "nonprod_live_input_materialization_manifest",
        "operation": operation,
        "layer": layer,
        "claim_digest": claim_digest,
        "sealed_request_digest": sealed_request["sealed_request_digest"],
        "context_digest": context["context_digest"],
        "binding_digest": canonical_digest(bindings),
        "backend_binding_digest": backend_binding["binding_digest"],
        "cost_model_digest": cost_model["cost_model_digest"],
        "expected_approver_user_id": approval_authority[
            "expected_approver_user_id"
        ],
        "github_environment_anchor_digest": approval_authority[
            "github_environment_anchor_digest"
        ],
        "approval_authority_digest": approval_authority[
            "approval_authority_digest"
        ],
        "maximum_cost_usd_micros": claim["maximum_cost_usd_micros"],
        "modeled_cost_upper_bound_usd_micros": cost_model[
            "modeled_cost_upper_bound_usd_micros"
        ],
        "runtime_binding_digest": runtime_binding_digest,
        "source_document_digests": source_digests,
        "plan_inputs_digest": plan_inputs_digest,
        "apply_inputs_digest": apply_inputs_digest,
        "materialization_valid": True,
        "controller_input_ready": True,
        "plan_inputs_ready": plan_ready,
        "apply_inputs_ready": False,
        "durable_readback_required": durable_readback_required,
        "oidc_authorized": True,
        "terminal_operation_authorized": False,
        "output_policy": "PRIVATE_CREATE_ONLY_0600",
    }
    manifest["manifest_digest"] = canonical_digest(manifest)
    receipt: dict[str, Any] = {
        "schema_version": "1",
        "record_type": "nonprod_live_input_materialization_receipt",
        "status": "MATERIALIZED",
        "code": "LIVE_INPUTS_MATERIALIZED",
        "operation": operation,
        "layer": layer,
        "claim_digest": claim_digest,
        "sealed_request_digest": sealed_request["sealed_request_digest"],
        "context_digest": context["context_digest"],
        "binding_digest": manifest["binding_digest"],
        "backend_binding_digest": backend_binding["binding_digest"],
        "cost_model_digest": cost_model["cost_model_digest"],
        "expected_approver_user_id": approval_authority[
            "expected_approver_user_id"
        ],
        "github_environment_anchor_digest": approval_authority[
            "github_environment_anchor_digest"
        ],
        "approval_authority_digest": approval_authority[
            "approval_authority_digest"
        ],
        "maximum_cost_usd_micros": claim["maximum_cost_usd_micros"],
        "modeled_cost_upper_bound_usd_micros": cost_model[
            "modeled_cost_upper_bound_usd_micros"
        ],
        "runtime_binding_digest": runtime_binding_digest,
        "manifest_digest": manifest["manifest_digest"],
        "source_count": len(source_documents),
        "materialization_valid": True,
        "controller_input_ready": True,
        "durable_readback_required": durable_readback_required,
        "oidc_authorized": True,
        "terminal_operation_authorized": False,
        "aws_calls": 0,
        "aws_mutations": 0,
    }
    receipt["receipt_digest"] = canonical_digest(receipt)
    documents = {
        "context.json": context,
        "bindings.json": bindings,
        "backend-binding.json": backend_binding,
        "plan-inputs.json": plan_inputs,
        "apply-inputs.json": apply_inputs,
        "manifest.json": manifest,
        "receipt.json": receipt,
    }
    return MaterializedLiveInputs(
        documents=documents,
        source_documents=source_documents,
        receipt=receipt,
    )


def _json_bytes(document: Mapping[str, Any]) -> bytes:
    return (
        json.dumps(
            document,
            sort_keys=True,
            indent=2,
            ensure_ascii=True,
            allow_nan=False,
        )
        + "\n"
    ).encode("utf-8")


def _write_exclusive(path: Path, content: bytes) -> None:
    descriptor: int | None = None
    created = False
    try:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(path, flags, 0o600)
        created = True
        written = 0
        while written < len(content):
            written += os.write(descriptor, content[written:])
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = None
        os.chmod(path, 0o600)
    except OSError:
        if created:
            path.unlink(missing_ok=True)
        _fail("OUTPUT_WRITE_FAILED")
    finally:
        if descriptor is not None:
            os.close(descriptor)


def persist_materialized_live_inputs(
    *, private_root: Path, materialization: MaterializedLiveInputs
) -> None:
    """Write only the fixed private layout, never overwriting any artifact."""
    output_root = private_root / MATERIALIZED_DIR_NAME
    if output_root.exists() or output_root.is_symlink():
        _fail("OUTPUT_ALREADY_EXISTS")
    created_files: list[Path] = []
    created_dirs: list[Path] = []
    try:
        output_root.mkdir(mode=0o700)
        created_dirs.append(output_root)
        source_root = output_root / SOURCE_DIR_NAME
        source_root.mkdir(mode=0o700)
        created_dirs.append(source_root)
        controller_root = output_root / CONTROLLER_DIR_NAME
        controller_root.mkdir(mode=0o700)
        created_dirs.append(controller_root)
        plan_root = output_root / PLAN_DIR_NAME
        plan_root.mkdir(mode=0o700)
        created_dirs.append(plan_root)

        for key, filename in SOURCE_FILENAMES.items():
            destination = source_root / filename
            _write_exclusive(
                destination, _json_bytes(materialization.source_documents[key])
            )
            created_files.append(destination)
        for filename in OUTPUT_FILENAMES:
            destination = output_root / filename
            _write_exclusive(
                destination, _json_bytes(materialization.documents[filename])
            )
            created_files.append(destination)
    except LiveInputMaterializationError:
        for path in reversed(created_files):
            path.unlink(missing_ok=True)
        for path in reversed(created_dirs):
            try:
                path.rmdir()
            except OSError:
                pass
        raise
    except OSError:
        for path in reversed(created_files):
            path.unlink(missing_ok=True)
        for path in reversed(created_dirs):
            try:
                path.rmdir()
            except OSError:
                pass
        _fail("OUTPUT_WRITE_FAILED")


def _read_private_output(path: Path) -> dict[str, Any]:
    _validate_private_file(path, max_bytes=MAX_SEALED_REQUEST_BYTES)
    try:
        return load_json_strict(path)
    except AuthorizationError:
        _fail("MATERIALIZED_OUTPUT_INVALID")


def validate_materialized_live_inputs(
    *, private_root: Path, expected: MaterializedLiveInputs
) -> None:
    """Rebuild-and-compare every fixed output and reject controller prefill."""
    output_root = private_root / MATERIALIZED_DIR_NAME
    for directory in (
        output_root,
        output_root / SOURCE_DIR_NAME,
        output_root / CONTROLLER_DIR_NAME,
        output_root / PLAN_DIR_NAME,
    ):
        if directory.is_symlink():
            _fail("MATERIALIZED_OUTPUT_INVALID")
        try:
            mode = stat.S_IMODE(directory.stat().st_mode)
        except OSError:
            _fail("MATERIALIZED_OUTPUT_INVALID")
        if not directory.is_dir() or mode != 0o700:
            _fail("MATERIALIZED_OUTPUT_INVALID")
    expected_root_entries = {
        SOURCE_DIR_NAME,
        CONTROLLER_DIR_NAME,
        PLAN_DIR_NAME,
        *OUTPUT_FILENAMES,
    }
    if {path.name for path in output_root.iterdir()} != expected_root_entries:
        _fail("MATERIALIZED_OUTPUT_INVALID")
    if {
        path.name for path in (output_root / SOURCE_DIR_NAME).iterdir()
    } != set(SOURCE_FILENAMES.values()):
        _fail("MATERIALIZED_OUTPUT_INVALID")
    if any((output_root / CONTROLLER_DIR_NAME).iterdir()) or any(
        (output_root / PLAN_DIR_NAME).iterdir()
    ):
        _fail("CONTROLLER_INPUT_PREPOPULATED")

    for key, filename in SOURCE_FILENAMES.items():
        actual = _read_private_output(output_root / SOURCE_DIR_NAME / filename)
        if actual != dict(expected.source_documents[key]):
            _fail("MATERIALIZED_OUTPUT_MISMATCH")
    for filename in OUTPUT_FILENAMES:
        actual = _read_private_output(output_root / filename)
        if actual != dict(expected.documents[filename]):
            _fail("MATERIALIZED_OUTPUT_MISMATCH")


def materialize_private_root(
    *,
    private_root: Path,
    deployment_id: str,
    layer: str,
    operation: str,
    claim_digest: str,
    deployment_request_path: Path,
    environment: Mapping[str, str] | None = None,
    now: datetime | None = None,
    repo_root: Path = REPO_ROOT,
) -> MaterializedLiveInputs:
    """Stage, materialize, persist, and revalidate one fixed private root."""
    root = _validate_private_root(private_root, repo_root)
    current = now or datetime.now(tz=UTC)
    claim = load_repository_claim(
        repo_root=repo_root,
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
        now=current,
        repo_root=repo_root,
    )
    validate_repository_deployment_request_binding(
        claim=claim,
        repo_root=repo_root,
        request_path=deployment_request_path,
    )
    source_environment = os.environ if environment is None else environment
    sealed_path = stage_sealed_request_from_environment(
        private_root=root,
        environment=environment,
    )
    sealed_request = _bind_collected_github_evidence(
        _read_sealed_request(sealed_path),
        private_root=root,
    )
    materialization = materialize_live_inputs(
        claim=claim,
        sealed_request=sealed_request,
        deployment_id=deployment_id,
        layer=layer,
        operation=operation,
        claim_digest=claim_digest,
        private_root=root,
        runtime_environment=source_environment,
        now=current,
        repo_root=repo_root,
    )
    persist_materialized_live_inputs(
        private_root=root,
        materialization=materialization,
    )
    validate_materialized_live_inputs(
        private_root=root,
        expected=materialization,
    )
    return materialization


def validate_private_root(
    *,
    private_root: Path,
    deployment_id: str,
    layer: str,
    operation: str,
    claim_digest: str,
    deployment_request_path: Path,
    environment: Mapping[str, str] | None = None,
    now: datetime | None = None,
    repo_root: Path = REPO_ROOT,
) -> MaterializedLiveInputs:
    """Rebuild and compare an existing materialization without writing."""
    root = _validate_private_root(private_root, repo_root)
    current = now or datetime.now(tz=UTC)
    claim = load_repository_claim(
        repo_root=repo_root,
        deployment_id=deployment_id,
        layer=layer,
        operation=operation,
    )
    validate_repository_deployment_request_binding(
        claim=claim,
        repo_root=repo_root,
        request_path=deployment_request_path,
    )
    sealed_request = _bind_collected_github_evidence(
        _read_sealed_request(root / SEALED_REQUEST_NAME),
        private_root=root,
    )
    materialization = materialize_live_inputs(
        claim=claim,
        sealed_request=sealed_request,
        deployment_id=deployment_id,
        layer=layer,
        operation=operation,
        claim_digest=claim_digest,
        private_root=root,
        runtime_environment=os.environ if environment is None else environment,
        now=current,
        repo_root=repo_root,
    )
    validate_materialized_live_inputs(
        private_root=root,
        expected=materialization,
    )
    return materialization


def revalidate_private_root_at_action_time(
    *,
    private_root: Path,
    deployment_id: str,
    layer: str,
    operation: str,
    claim_digest: str,
    environment: Mapping[str, str],
    now: datetime,
    repo_root: Path = REPO_ROOT,
) -> MaterializedLiveInputs:
    """Rebuild every expiring private authority immediately before mutation."""
    root = _validate_private_root(private_root, repo_root)
    claim = load_repository_claim(
        repo_root=repo_root,
        deployment_id=deployment_id,
        layer=layer,
        operation=operation,
    )
    sealed_request = _bind_collected_github_evidence(
        _read_sealed_request(root / SEALED_REQUEST_NAME),
        private_root=root,
    )
    materialization = materialize_live_inputs(
        claim=claim,
        sealed_request=sealed_request,
        deployment_id=deployment_id,
        layer=layer,
        operation=operation,
        claim_digest=claim_digest,
        private_root=root,
        runtime_environment=environment,
        now=now,
        repo_root=repo_root,
    )
    validate_materialized_live_inputs(private_root=root, expected=materialization)
    return materialization


__all__ = [
    "LiveInputMaterializationError",
    "MaterializedLiveInputs",
    "canonical_claim_path",
    "load_repository_claim",
    "load_repository_deployment_request",
    "validate_repository_deployment_request_binding",
    "materialize_live_inputs",
    "materialize_private_root",
    "persist_materialized_live_inputs",
    "stable_sealed_request_digest",
    "stage_sealed_request_from_environment",
    "validate_claim",
    "validate_materialized_live_inputs",
    "validate_private_root",
    "revalidate_private_root_at_action_time",
]
