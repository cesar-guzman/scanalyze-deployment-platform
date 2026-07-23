#!/usr/bin/env python3
"""Validate the repository-local human contribution contract offline."""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path
from urllib.parse import unquote


REPO_ROOT = Path(__file__).resolve().parents[1]

REQUIRED_FILES = (
    Path("CONTRIBUTING.md"),
    Path("SECURITY.md"),
    Path("docs/engineering/CODE_REVIEW_STANDARD.md"),
    Path("docs/engineering/DOCUMENTATION_STANDARD.md"),
    Path("docs/engineering/GITHUB_ENFORCEMENT_BASELINE.md"),
    Path("docs/engineering/GITHUB_CONTRIBUTOR_WALKTHROUGH.md"),
    Path(".github/PULL_REQUEST_TEMPLATE.md"),
    Path(".github/ISSUE_TEMPLATE/engineering-change.yml"),
    Path(".github/ISSUE_TEMPLATE/config.yml"),
)

MARKDOWN_FILES = tuple(
    path
    for path in REQUIRED_FILES
    if path.suffix == ".md"
)

REQUIRED_TERMS = {
    Path("CONTRIBUTING.md"): (
        "one issue, one branch, one worktree, and one pull request",
        "definition of ready",
        "risk classification",
        "p0",
        "p1",
        "p2",
        "linear",
        "codeowners",
        "validation not run",
        "production remains **no-go**",
        "documented",
        "implemented",
        "evidenced",
        "tested",
        "approved",
        "deployed",
    ),
    Path("SECURITY.md"): (
        "report a vulnerability privately",
        "do not open a public github issue",
        "accidental secret or data disclosure",
    ),
    Path("docs/engineering/CODE_REVIEW_STANDARD.md"): (
        "[p0]",
        "[p1]",
        "[p2]",
        "[question]",
        "[suggestion]",
        "actionable comment format",
        "thread resolution",
    ),
    Path("docs/engineering/DOCUMENTATION_STANDARD.md"): (
        "current",
        "transitional",
        "target state",
        "deprecated",
        "no-go",
        "historical evidence",
        "change triggers",
    ),
    Path("docs/engineering/GITHUB_ENFORCEMENT_BASELINE.md"): (
        "required approving reviews",
        "codeowner review required",
        "stale approvals dismissed",
        "conversation resolution required",
        "microservices validation gate",
        "no repository, branch-protection, workflow, environment, or aws setting was changed",
    ),
    Path("docs/engineering/GITHUB_CONTRIBUTOR_WALKTHROUGH.md"): (
        "current repository access model",
        "secure command-line authentication",
        "read-only access verification",
        "what contributors see in github",
        "how to read a pull request",
        "reviewer walkthrough",
        "one isolated worktree",
        "open a draft pull request",
        "first-day supervised exercise",
        "github ui capability is therefore not business authorization",
        "no step in this walkthrough authorizes an aws mutation",
    ),
    Path(".github/PULL_REQUEST_TEMPLATE.md"): (
        "primary linear issue",
        "risk class",
        "security and privacy impact",
        "validation performed",
        "validation not run",
        "rollout, rollback, and recovery",
        "cloud and production boundary",
        "reviewer focus",
        "author checklist",
    ),
}

ISSUE_FORM_IDS = {
    "linear_issue",
    "owner",
    "risk",
    "component",
    "environment",
    "problem",
    "scope",
    "acceptance",
    "security",
    "validation",
    "rollout",
    "dependencies",
    "confirmations",
}

CODEOWNER_ENTRIES = (
    "CONTRIBUTING.md",
    "SECURITY.md",
    ".github/PULL_REQUEST_TEMPLATE.md",
    ".github/ISSUE_TEMPLATE/",
    "docs/engineering/",
    "tooling/validate_contributor_contract.py",
    "tests/test_contributor_contract.py",
)

LINK_RE = re.compile(r"!?\[[^\]]*]\(([^)]+)\)")
ISSUE_ID_RE = re.compile(r"(?m)^\s+-?\s*id:\s*([a-z0-9_]+)\s*$")
BASH_BLOCK_RE = re.compile(r"```bash\n(.*?)\n```", re.DOTALL)


def _read(repo_root: Path, relative_path: Path) -> str:
    return (repo_root / relative_path).read_text(encoding="utf-8")


def missing_required_files(repo_root: Path = REPO_ROOT) -> list[str]:
    return [
        f"missing required contributor artifact: {path}"
        for path in REQUIRED_FILES
        if not (repo_root / path).is_file()
    ]


def missing_required_terms(repo_root: Path = REPO_ROOT) -> list[str]:
    errors: list[str] = []
    for path, required_terms in REQUIRED_TERMS.items():
        absolute = repo_root / path
        if not absolute.is_file():
            continue
        content = " ".join(
            absolute.read_text(encoding="utf-8").lower().split()
        )
        for term in required_terms:
            if term not in content:
                errors.append(f"{path}: missing required term: {term}")
    return errors


def issue_form_errors(repo_root: Path = REPO_ROOT) -> list[str]:
    issue_form = repo_root / ".github/ISSUE_TEMPLATE/engineering-change.yml"
    config = repo_root / ".github/ISSUE_TEMPLATE/config.yml"
    if not issue_form.is_file() or not config.is_file():
        return []

    issue_text = issue_form.read_text(encoding="utf-8")
    found_ids = set(ISSUE_ID_RE.findall(issue_text))
    errors = [
        f"engineering issue form missing id: {field_id}"
        for field_id in sorted(ISSUE_FORM_IDS - found_ids)
    ]
    if issue_text.count("required: true") < len(ISSUE_FORM_IDS):
        errors.append("engineering issue form must require every contract field")

    config_text = config.read_text(encoding="utf-8").lower()
    if "blank_issues_enabled: false" not in config_text:
        errors.append("blank GitHub issues must remain disabled")
    if "/security/policy" not in config_text:
        errors.append("issue config must link to security reporting instructions")
    if "linear.app/" not in config_text:
        errors.append("issue config must route durable delivery work to Linear")
    return errors


def codeowner_errors(repo_root: Path = REPO_ROOT) -> list[str]:
    codeowners = repo_root / "CODEOWNERS"
    if not codeowners.is_file():
        return ["CODEOWNERS is missing"]
    content = codeowners.read_text(encoding="utf-8")
    return [
        f"CODEOWNERS missing contributor-governance path: {entry}"
        for entry in CODEOWNER_ENTRIES
        if entry not in content
    ]


def repository_entrypoint_errors(repo_root: Path = REPO_ROOT) -> list[str]:
    errors: list[str] = []
    readme = repo_root / "README.md"
    if not readme.is_file() or "(CONTRIBUTING.md)" not in readme.read_text(
        encoding="utf-8"
    ):
        errors.append("README.md must link to CONTRIBUTING.md")

    makefile = repo_root / "Makefile"
    if makefile.is_file():
        make_text = makefile.read_text(encoding="utf-8")
        if "contributor-docs-check:" not in make_text:
            errors.append("Makefile must define contributor-docs-check")
        if "docs-check: contributor-docs-check phase0-docs-check" not in make_text:
            errors.append(
                "docs-check must depend on contributor-docs-check and phase0-docs-check"
            )
    else:
        errors.append("Makefile is missing")
    return errors


def walkthrough_command_errors(repo_root: Path = REPO_ROOT) -> list[str]:
    walkthrough = (
        repo_root / "docs/engineering/GITHUB_CONTRIBUTOR_WALKTHROUGH.md"
    )
    if not walkthrough.is_file():
        return []

    errors: list[str] = []
    for block in BASH_BLOCK_RE.findall(
        walkthrough.read_text(encoding="utf-8")
    ):
        if (
            "gh pr create" in block
            and "--draft" in block
            and "--web" in block
        ):
            errors.append(
                "GitHub walkthrough must not combine gh pr create "
                "--draft and --web"
            )
    return errors


def _git_contains(repo_root: Path, relative_path: Path) -> bool:
    git_path = relative_path.as_posix().rstrip("/")
    result = subprocess.run(
        ["git", "cat-file", "-e", f"HEAD:{git_path}"],
        cwd=repo_root,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    return result.returncode == 0


def relative_link_errors(repo_root: Path = REPO_ROOT) -> list[str]:
    errors: list[str] = []
    for markdown_path in MARKDOWN_FILES:
        source = repo_root / markdown_path
        if not source.is_file():
            continue
        for raw_target in LINK_RE.findall(source.read_text(encoding="utf-8")):
            target = raw_target.strip().split()[0].strip("<>")
            if (
                not target
                or target.startswith(("#", "https://", "http://", "mailto:"))
            ):
                continue
            target = unquote(target.split("#", 1)[0])
            if not target:
                continue
            resolved = (source.parent / target).resolve()
            try:
                relative = resolved.relative_to(repo_root.resolve())
            except ValueError:
                errors.append(f"{markdown_path}: link escapes repository: {target}")
                continue
            if resolved.exists() or _git_contains(repo_root, relative):
                continue
            errors.append(f"{markdown_path}: broken relative link: {target}")
    return errors


def validate(repo_root: Path = REPO_ROOT) -> list[str]:
    errors: list[str] = []
    errors.extend(missing_required_files(repo_root))
    errors.extend(missing_required_terms(repo_root))
    errors.extend(issue_form_errors(repo_root))
    errors.extend(codeowner_errors(repo_root))
    errors.extend(repository_entrypoint_errors(repo_root))
    errors.extend(walkthrough_command_errors(repo_root))
    errors.extend(relative_link_errors(repo_root))
    return errors


def main() -> int:
    errors = validate()
    if errors:
        print("CONTRIBUTOR_CONTRACT_FAILED")
        for error in errors:
            print(f"- {error}")
        return 1
    print("CONTRIBUTOR_CONTRACT_VERIFIED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
