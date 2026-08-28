"""Read-only Git source verifier for private platform-authority inputs.

The verifier is intentionally isolated from the pure GUG-395 compiler.  It
executes only local, read-only Git commands, proves a clean checkout at an
exact remote-tracking ref, and compares every required working-tree byte with
the corresponding committed Git object before returning a digest-only record.
"""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
from typing import Any, Mapping, Sequence


VERIFIER_ID = "LOCAL_GIT_CLEAN_REMOTE_REF_V1"
RECORD_TYPE = "scanalyze.platform_authority.repository_source_verification.v1"

_SHA = re.compile(r"^[0-9a-f]{40}$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_REF = re.compile(r"^refs/remotes/[A-Za-z0-9](?:[A-Za-z0-9._/-]{0,253})$")
_PATH = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,1023}$")


class RepositorySourceVerificationError(RuntimeError):
    """One stable fail-closed source-verification error."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def _fail(code: str) -> None:
    raise RepositorySourceVerificationError(code)


def _canonical_json(value: Any) -> str:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


def _digest(value: Any) -> str:
    return "sha256:" + sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def _bytes_digest(value: bytes) -> str:
    return "sha256:" + sha256(value).hexdigest()


def _git(root: Path, args: Sequence[str], *, text: bool = True) -> str | bytes:
    git_binary = shutil.which("git", path=os.defpath)
    if git_binary is None or not Path(git_binary).is_absolute():
        _fail("SOURCE_VERIFICATION_UNAVAILABLE")
    environment = {
        "PATH": os.defpath,
        "LANG": "C",
        "LC_ALL": "C",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_OPTIONAL_LOCKS": "0",
    }
    try:
        result = subprocess.run(
            [git_binary, "-c", "core.fsmonitor=false", *args],
            cwd=root,
            env=environment,
            check=True,
            capture_output=True,
            text=text,
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise RepositorySourceVerificationError(
            "SOURCE_VERIFICATION_UNAVAILABLE"
        ) from exc
    return result.stdout


def _validated_required_sources(
    value: Mapping[str, str],
) -> dict[str, str]:
    if not isinstance(value, Mapping) or not value:
        _fail("SOURCE_SET_INVALID")
    result: dict[str, str] = {}
    for raw_path, raw_digest in sorted(value.items()):
        if (
            not isinstance(raw_path, str)
            or _PATH.fullmatch(raw_path) is None
            or raw_path.startswith("/")
            or ".." in Path(raw_path).parts
            or not isinstance(raw_digest, str)
            or _DIGEST.fullmatch(raw_digest) is None
        ):
            _fail("SOURCE_SET_INVALID")
        result[raw_path] = raw_digest
    return result


@dataclass(frozen=True, slots=True)
class RepositorySourceVerification:
    """Digest-only result of one local, read-only source verification."""

    document: dict[str, Any]


def verify_clean_repository_source(
    *,
    repo_root: Path,
    expected_commit_sha: str,
    expected_tree_sha: str,
    expected_remote_ref: str,
    required_source_digests: Mapping[str, str],
) -> RepositorySourceVerification:
    """Prove exact HEAD/tree/ref/bytes without modifying Git state."""

    if (
        not isinstance(repo_root, Path)
        or not repo_root.is_absolute()
        or _SHA.fullmatch(str(expected_commit_sha)) is None
        or _SHA.fullmatch(str(expected_tree_sha)) is None
        or _REF.fullmatch(str(expected_remote_ref)) is None
        or ".." in str(expected_remote_ref).split("/")
    ):
        _fail("SOURCE_VERIFICATION_INPUT_INVALID")
    try:
        root = repo_root.resolve(strict=True)
    except OSError as exc:
        raise RepositorySourceVerificationError(
            "SOURCE_ROOT_INVALID"
        ) from exc
    if root != repo_root or not root.is_dir():
        _fail("SOURCE_ROOT_INVALID")

    required = _validated_required_sources(required_source_digests)
    top = str(_git(root, ["rev-parse", "--show-toplevel"])).strip()

    def snapshot() -> tuple[str, str, str]:
        head_value = str(_git(root, ["rev-parse", "HEAD"])).strip()
        tree_value = str(_git(root, ["rev-parse", "HEAD^{tree}"])).strip()
        remote_value = str(
            _git(root, ["rev-parse", "--verify", expected_remote_ref])
        ).strip()
        return head_value, tree_value, remote_value

    def dirty_status() -> str:
        return str(
            _git(root, ["status", "--porcelain=v1", "--untracked-files=all"])
        )

    before = snapshot()
    first_dirty = dirty_status()
    after = snapshot()
    second_dirty = dirty_status()
    if before != after:
        _fail("SOURCE_CHECKOUT_CHANGED")
    head, tree, remote = after
    if Path(top).resolve() != root:
        _fail("SOURCE_ROOT_MISMATCH")
    if head != expected_commit_sha or tree != expected_tree_sha:
        _fail("SOURCE_SNAPSHOT_MISMATCH")
    if remote != expected_commit_sha:
        _fail("SOURCE_REMOTE_REF_MISMATCH")
    if first_dirty or second_dirty:
        _fail("SOURCE_TREE_DIRTY")

    tree_entries = bytes(
        _git(
            root,
            ["ls-tree", "-r", "-z", "--full-tree", expected_commit_sha],
            text=False,
        )
    )
    if not tree_entries:
        _fail("SOURCE_TREE_EMPTY")

    verified_sources: list[dict[str, str]] = []
    for relative, expected_digest in required.items():
        target = root / relative
        try:
            if target.is_symlink() or not target.is_file():
                raise OSError
            working = target.read_bytes()
        except OSError as exc:
            raise RepositorySourceVerificationError(
                "SOURCE_FILE_UNAVAILABLE"
            ) from exc
        committed = bytes(
            _git(root, ["show", f"{expected_commit_sha}:{relative}"], text=False)
        )
        if committed != working or _bytes_digest(committed) != expected_digest:
            _fail("SOURCE_FILE_COMMIT_DRIFT")
        verified_sources.append(
            {"repository_path": relative, "content_digest": expected_digest}
        )

    # Re-prove the complete checkout after every tree/object/working-byte read.
    # The second pair is intentional: it catches both a working-tree mutation
    # after the initial clean checks and a HEAD/remote-ref change around the
    # final status observation.
    final_before = snapshot()
    third_dirty = dirty_status()
    final_after = snapshot()
    fourth_dirty = dirty_status()
    if after != final_before or final_before != final_after:
        _fail("SOURCE_CHECKOUT_CHANGED")
    if third_dirty or fourth_dirty:
        _fail("SOURCE_TREE_DIRTY")
    head, tree, remote = final_after

    body: dict[str, Any] = {
        "record_type": RECORD_TYPE,
        "schema_version": 1,
        "verifier_id": VERIFIER_ID,
        "expected_remote_ref": expected_remote_ref,
        "source_commit_sha": expected_commit_sha,
        "source_tree_sha": expected_tree_sha,
        "remote_ref_commit_sha": remote,
        "checkout_clean": True,
        "required_source_count": len(verified_sources),
        "required_source_set_digest": _digest(verified_sources),
        "repository_tree_entries_digest": _bytes_digest(tree_entries),
        "aws_calls": 0,
        "aws_mutations": 0,
    }
    body["verification_digest"] = _digest(body)
    return RepositorySourceVerification(document=body)
