from __future__ import annotations

from hashlib import sha256
from pathlib import Path
import subprocess

import pytest

from tooling import platform_authority_repository_source_verifier as subject


def _git(root: Path, *args: str) -> str:
    completed = subprocess.run(
        ["git", *args],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    )
    return completed.stdout.strip()


def _repository(tmp_path: Path) -> tuple[Path, str, str, dict[str, str]]:
    root = tmp_path / "repository"
    root.mkdir()
    _git(root, "init", "--initial-branch=main")
    _git(root, "config", "user.name", "GUG395 Test")
    _git(root, "config", "user.email", "gug395@example.invalid")
    tracked = root / "tracked.txt"
    tracked.write_text("exact committed bytes\n", encoding="utf-8")
    _git(root, "add", "tracked.txt")
    _git(root, "commit", "-m", "test: source binding")
    commit = _git(root, "rev-parse", "HEAD")
    tree = _git(root, "rev-parse", "HEAD^{tree}")
    _git(root, "update-ref", "refs/remotes/origin/main", commit)
    required = {
        "tracked.txt": "sha256:" + sha256(tracked.read_bytes()).hexdigest()
    }
    return root.resolve(), commit, tree, required


def test_verifier_proves_clean_head_tree_remote_ref_and_committed_bytes(
    tmp_path: Path,
) -> None:
    root, commit, tree, required = _repository(tmp_path)
    result = subject.verify_clean_repository_source(
        repo_root=root,
        expected_commit_sha=commit,
        expected_tree_sha=tree,
        expected_remote_ref="refs/remotes/origin/main",
        required_source_digests=required,
    ).document
    assert result["source_commit_sha"] == commit
    assert result["source_tree_sha"] == tree
    assert result["remote_ref_commit_sha"] == commit
    assert result["checkout_clean"] is True
    assert result["required_source_count"] == 1
    assert result["aws_calls"] == result["aws_mutations"] == 0


@pytest.mark.parametrize("dirty_kind", ("tracked", "staged", "untracked"))
def test_verifier_rejects_every_dirty_checkout(
    tmp_path: Path, dirty_kind: str
) -> None:
    root, commit, tree, required = _repository(tmp_path)
    if dirty_kind == "tracked":
        (root / "tracked.txt").write_text("changed\n", encoding="utf-8")
    elif dirty_kind == "staged":
        (root / "tracked.txt").write_text("changed\n", encoding="utf-8")
        _git(root, "add", "tracked.txt")
    else:
        (root / "untracked.txt").write_text("untracked\n", encoding="utf-8")
    with pytest.raises(
        subject.RepositorySourceVerificationError,
        match="SOURCE_TREE_DIRTY",
    ):
        subject.verify_clean_repository_source(
            repo_root=root,
            expected_commit_sha=commit,
            expected_tree_sha=tree,
            expected_remote_ref="refs/remotes/origin/main",
            required_source_digests=required,
        )


def test_verifier_rejects_remote_ref_that_does_not_equal_head(
    tmp_path: Path,
) -> None:
    root, commit, tree, required = _repository(tmp_path)
    (root / "tracked.txt").write_text("second commit\n", encoding="utf-8")
    _git(root, "add", "tracked.txt")
    _git(root, "commit", "-m", "test: advance head only")
    new_commit = _git(root, "rev-parse", "HEAD")
    new_tree = _git(root, "rev-parse", "HEAD^{tree}")
    required["tracked.txt"] = "sha256:" + sha256(
        (root / "tracked.txt").read_bytes()
    ).hexdigest()
    assert new_commit != commit and new_tree != tree
    with pytest.raises(
        subject.RepositorySourceVerificationError,
        match="SOURCE_REMOTE_REF_MISMATCH",
    ):
        subject.verify_clean_repository_source(
            repo_root=root,
            expected_commit_sha=new_commit,
            expected_tree_sha=new_tree,
            expected_remote_ref="refs/remotes/origin/main",
            required_source_digests=required,
        )


def test_verifier_rejects_mutation_after_second_status_observation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root, commit, tree, required = _repository(tmp_path)
    original_git = subject._git
    status_calls = 0

    def mutate_after_second_status(
        observed_root: Path, args: list[str], *, text: bool = True
    ) -> str | bytes:
        nonlocal status_calls
        result = original_git(observed_root, args, text=text)
        if args == ["status", "--porcelain=v1", "--untracked-files=all"]:
            status_calls += 1
            if status_calls == 2:
                (observed_root / "late-untracked.txt").write_text(
                    "arrived after the initial clean proof\n", encoding="utf-8"
                )
        return result

    monkeypatch.setattr(subject, "_git", mutate_after_second_status)
    with pytest.raises(
        subject.RepositorySourceVerificationError,
        match="SOURCE_TREE_DIRTY",
    ):
        subject.verify_clean_repository_source(
            repo_root=root,
            expected_commit_sha=commit,
            expected_tree_sha=tree,
            expected_remote_ref="refs/remotes/origin/main",
            required_source_digests=required,
        )
    assert status_calls >= 3
