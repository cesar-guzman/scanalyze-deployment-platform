#!/usr/bin/env python3
"""Validate the repository-local human contribution contract offline."""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path
from urllib.parse import unquote

try:
    import yaml
except ImportError:  # pragma: no cover - exercised only without PyYAML
    yaml = None


REPO_ROOT = Path(__file__).resolve().parents[1]

REQUIRED_FILES = (
    Path("CONTRIBUTING.md"),
    Path("SECURITY.md"),
    Path("docs/engineering/CODE_REVIEW_STANDARD.md"),
    Path("docs/engineering/DOCUMENTATION_STANDARD.md"),
    Path("docs/engineering/GITHUB_ENFORCEMENT_BASELINE.md"),
    Path("docs/engineering/GITHUB_CONTRIBUTOR_WALKTHROUGH.md"),
    Path("docs/engineering/AI_ASSISTED_DEVELOPMENT_STANDARD.md"),
    Path("docs/engineering/CLAUDE_CODE_SETUP.md"),
    Path("docs/engineering/CLAUDE_CODE_ONBOARDING_REHEARSAL.md"),
    Path(".github/PULL_REQUEST_TEMPLATE.md"),
    Path(".github/ISSUE_TEMPLATE/engineering-change.yml"),
    Path(".github/ISSUE_TEMPLATE/config.yml"),
    Path(".claude/settings.json"),
)

# Claude Code repository baseline contract (GUG-262). No silent fallback.
CLAUDE_SETTINGS = Path(".claude/settings.json")
CLAUDE_EXPECTED_MODEL = "opusplan"
CLAUDE_EXPECTED_ENV = {
    "ANTHROPIC_DEFAULT_OPUS_MODEL": "claude-opus-4-8",
    "ANTHROPIC_DEFAULT_SONNET_MODEL": "claude-sonnet-5",
}
CLAUDE_FORBIDDEN_ENV = ("ANTHROPIC_MODEL", "ANTHROPIC_SMALL_FAST_MODEL")
CLAUDE_REQUIRED_DENY = (
    "Read(./**/*.tfstate)",
    "Read(./**/*.tfvars)",
    "Read(./**/credentials)",
    "Bash(git push:*)",
    "Bash(git push --force:*)",
    "Bash(git reset --hard:*)",
    "Bash(git clean:*)",
    "Bash(gh pr create:*)",
    "Bash(gh repo:*)",
    "Bash(terraform apply:*)",
    "Bash(terraform destroy:*)",
    "Bash(aws:*)",
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
    ".claude/",
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


def _field_is_required(item: dict) -> bool:
    """Return True only if the parsed issue-form field genuinely enforces input.

    For ``input``/``dropdown``/``textarea`` fields the field is required only
    when ``validations.required`` is the boolean ``True``. For ``checkboxes``
    fields, GitHub ignores ``validations.required``; requirement is expressed
    per option via ``required: true``, so every option must be required.
    """
    field_type = item.get("type")
    if field_type == "checkboxes":
        options = item.get("attributes", {}).get("options", [])
        return bool(options) and all(
            option.get("required") is True for option in options
        )
    validations = item.get("validations")
    if not isinstance(validations, dict):
        return False
    return validations.get("required") is True


def issue_form_errors(repo_root: Path = REPO_ROOT) -> list[str]:
    issue_form = repo_root / ".github/ISSUE_TEMPLATE/engineering-change.yml"
    config = repo_root / ".github/ISSUE_TEMPLATE/config.yml"
    if not issue_form.is_file() or not config.is_file():
        return []

    if yaml is None:
        return [
            "PyYAML is required to validate GitHub issue forms fail-closed "
            "(pip install pyyaml)"
        ]

    errors: list[str] = []

    # Parse the issue form and validate each required contract field explicitly,
    # instead of counting aggregate `required: true` occurrences (which per-option
    # checkbox requirements could otherwise mask). [GUG-262 P2]
    try:
        form = yaml.safe_load(issue_form.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as exc:
        return [f"engineering issue form is not valid YAML: {exc}"]

    body = form.get("body", []) if isinstance(form, dict) else []
    fields_by_id = {
        item.get("id"): item
        for item in body
        if isinstance(item, dict) and item.get("id")
    }
    for field_id in sorted(ISSUE_FORM_IDS):
        item = fields_by_id.get(field_id)
        if item is None:
            errors.append(f"engineering issue form missing id: {field_id}")
        elif not _field_is_required(item):
            errors.append(
                f"engineering issue form field must be required: {field_id}"
            )

    # Parse the top-level YAML value rather than substring-matching, so a stale
    # commented line cannot mask an active `blank_issues_enabled: true`. [GUG-262 P2]
    try:
        config_data = yaml.safe_load(config.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as exc:
        return errors + [f"issue config is not valid YAML: {exc}"]

    if config_data.get("blank_issues_enabled") is not False:
        errors.append("blank GitHub issues must remain disabled")

    config_text = config.read_text(encoding="utf-8").lower()
    if "/security/policy" not in config_text:
        errors.append("issue config must link to security reporting instructions")
    if "linear.app/" not in config_text:
        errors.append("issue config must route durable delivery work to Linear")
    return errors


def claude_baseline_errors(repo_root: Path = REPO_ROOT) -> list[str]:
    """Validate the Claude Code repository baseline contract offline. [GUG-262]"""
    settings_path = repo_root / CLAUDE_SETTINGS
    if not settings_path.is_file():
        return [f"missing Claude Code baseline: {CLAUDE_SETTINGS}"]

    try:
        settings = json.loads(settings_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        return [f"{CLAUDE_SETTINGS}: invalid JSON ({exc})"]

    errors: list[str] = []
    permissions = settings.get("permissions", {})

    if permissions.get("defaultMode") != "plan":
        errors.append(
            f"{CLAUDE_SETTINGS}: permissions.defaultMode must be 'plan' "
            f"(found {permissions.get('defaultMode')!r})"
        )

    if settings.get("model") != CLAUDE_EXPECTED_MODEL:
        errors.append(
            f"{CLAUDE_SETTINGS}: model must be {CLAUDE_EXPECTED_MODEL!r} "
            f"(found {settings.get('model')!r})"
        )

    env = settings.get("env", {})
    for key, expected in CLAUDE_EXPECTED_ENV.items():
        if env.get(key) != expected:
            errors.append(
                f"{CLAUDE_SETTINGS}: env.{key} must be pinned to {expected!r} "
                f"(found {env.get(key)!r}) — no silent fallback"
            )
    for key in CLAUDE_FORBIDDEN_ENV:
        if key in env:
            errors.append(
                f"{CLAUDE_SETTINGS}: deprecated env.{key} must be removed"
            )

    deny = permissions.get("deny", [])
    for rule in CLAUDE_REQUIRED_DENY:
        if rule not in deny:
            errors.append(f"{CLAUDE_SETTINGS}: missing required deny rule: {rule}")

    allow = permissions.get("allow", [])
    if "Bash(make:*)" in allow:
        errors.append(
            f"{CLAUDE_SETTINGS}: global 'Bash(make:*)' allow is forbidden; "
            "grant exact make targets instead"
        )

    sandbox = settings.get("sandbox")
    sandbox_enabled = sandbox is True or (
        isinstance(sandbox, dict) and sandbox.get("enabled") is True
    )
    if not sandbox_enabled:
        errors.append(f"{CLAUDE_SETTINGS}: sandbox must be enabled")

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
    errors.extend(claude_baseline_errors(repo_root))
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
