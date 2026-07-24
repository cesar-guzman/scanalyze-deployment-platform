#!/usr/bin/env python3
"""Validate the repository-local human contribution contract offline."""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path
from urllib.parse import unquote


REPO_ROOT = Path(__file__).resolve().parents[1]

REQUIRED_FILES = (
    Path("CONTRIBUTING.md"),
    Path("CLAUDE.md"),
    Path("SECURITY.md"),
    Path(".claude/settings.json"),
    Path("docs/engineering/AI_ASSISTED_DEVELOPMENT_STANDARD.md"),
    Path("docs/engineering/CLAUDE_CODE_SETUP.md"),
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
    Path("CLAUDE.md"): (
        "claude-opus-4-8",
        "claude-sonnet-5",
        "linear is the durable source",
        "one issue equals one branch, one isolated worktree, and one pull request",
        "do not run aws cli commands",
        "validation not run",
        "no unauthorized remote, aws, or production action occurred",
    ),
    Path("SECURITY.md"): (
        "report a vulnerability privately",
        "do not open a public github issue",
        "accidental secret or data disclosure",
    ),
    Path("docs/engineering/AI_ASSISTED_DEVELOPMENT_STANDARD.md"): (
        "human accountability",
        "control hierarchy",
        "linear is the delivery control plane",
        "claude-opus-4-8",
        "claude-sonnet-5",
        "automatic fallback",
        "human plan gate",
        "prompt injection",
        "ai output is not evidence",
        "enterprise control",
        "continuous improvement",
    ),
    Path("docs/engineering/CLAUDE_CODE_SETUP.md"): (
        "v2.1.197",
        "claude doctor",
        "claude auth status --text",
        "inspect before trusting project configuration",
        "claude --model opusplan --permission-mode plan",
        "/status",
        "/permissions",
        "/memory",
        "planning resolves to `claude-opus-4-8`",
        "execution resolves to `claude-sonnet-5`",
        "enterprise managed-settings target",
        "clean-room rehearsal",
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
        "ai assistance",
        "planning model",
        "execution model",
        "human verification performed",
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
    "CLAUDE.md",
    "SECURITY.md",
    ".claude/",
    ".github/PULL_REQUEST_TEMPLATE.md",
    ".github/ISSUE_TEMPLATE/",
    "docs/engineering/",
    "tooling/validate_contributor_contract.py",
    "tests/test_contributor_contract.py",
)

LINK_RE = re.compile(r"!?\[[^\]]*]\(([^)]+)\)")
ISSUE_ID_RE = re.compile(r"(?m)^\s+-?\s*id:\s*([a-z0-9_]+)\s*$")
BASH_BLOCK_RE = re.compile(r"```bash\n(.*?)\n```", re.DOTALL)

CLAUDE_REQUIRED_MODELS = {
    "opusplan",
    "claude-opus-4-8",
    "claude-sonnet-5",
}

CLAUDE_REQUIRED_DENIES = {
    "Read(.env)",
    "Read(.env.*)",
    "Read(**/*.tfstate)",
    "Read(~/.aws/**)",
    "Read(~/.ssh/**)",
    "Bash(git push *)",
    "Bash(git reset --hard *)",
    "Bash(git clean *)",
    "Bash(gh pr create *)",
    "Bash(gh pr review *)",
    "Bash(gh pr merge *)",
    "Bash(terraform apply *)",
    "Bash(terraform destroy *)",
    "Bash(aws *)",
    "Bash(rm *)",
}

CLAUDE_REQUIRED_DENIED_ENV_VARS = {
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
    "GH_TOKEN",
    "GITHUB_TOKEN",
    "ANTHROPIC_API_KEY",
    "ANTHROPIC_AUTH_TOKEN",
    "CLAUDE_CODE_OAUTH_TOKEN",
}


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
    elif (
        "AI_ASSISTED_DEVELOPMENT_STANDARD.md"
        not in readme.read_text(encoding="utf-8")
        or "CLAUDE_CODE_SETUP.md" not in readme.read_text(encoding="utf-8")
    ):
        errors.append(
            "README.md must link to the AI standard and Claude Code setup"
        )

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


def claude_configuration_errors(
    repo_root: Path = REPO_ROOT,
) -> list[str]:
    errors: list[str] = []
    settings_path = repo_root / ".claude/settings.json"
    if not settings_path.is_file():
        return errors

    try:
        settings = json.loads(settings_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        return [f".claude/settings.json is invalid JSON: {exc}"]

    if (
        settings.get("$schema")
        != "https://json.schemastore.org/claude-code-settings.json"
    ):
        errors.append("Claude settings must reference the official JSON schema")
    if settings.get("model") != "opusplan":
        errors.append("Claude settings model must be opusplan")
    if set(settings.get("availableModels", [])) != CLAUDE_REQUIRED_MODELS:
        errors.append(
            "Claude availableModels must contain only opusplan, "
            "claude-opus-4-8, and claude-sonnet-5"
        )
    if settings.get("fallbackModel") != []:
        errors.append("Claude fallbackModel must be an empty list")
    if settings.get("effortLevel") != "high":
        errors.append("Claude effortLevel must be high")
    if settings.get("disableAutoMode") != "disable":
        errors.append("Claude Auto mode must be disabled")
    if settings.get("disableRemoteControl") is not True:
        errors.append("Claude Remote Control must be disabled")
    if settings.get("disableArtifact") is not True:
        errors.append("Claude Artifact publication must be disabled")

    env = settings.get("env", {})
    if env.get("ANTHROPIC_DEFAULT_OPUS_MODEL") != "claude-opus-4-8":
        errors.append("Claude Opus alias must pin claude-opus-4-8")
    if env.get("ANTHROPIC_DEFAULT_SONNET_MODEL") != "claude-sonnet-5":
        errors.append("Claude Sonnet alias must pin claude-sonnet-5")

    permissions = settings.get("permissions", {})
    if permissions.get("defaultMode") != "plan":
        errors.append("Claude permissions.defaultMode must be plan")
    if permissions.get("disableBypassPermissionsMode") != "disable":
        errors.append("Claude bypass permissions mode must be disabled")
    denied = set(permissions.get("deny", []))
    for rule in sorted(CLAUDE_REQUIRED_DENIES - denied):
        errors.append(f"Claude settings missing deny rule: {rule}")

    sandbox = settings.get("sandbox", {})
    if sandbox.get("enabled") is not True:
        errors.append("Claude sandbox must be enabled")
    if sandbox.get("autoAllowBashIfSandboxed") is not False:
        errors.append("Claude sandbox must not auto-allow Bash")
    if sandbox.get("allowUnsandboxedCommands") is not False:
        errors.append("Claude unsandboxed command escape must be disabled")

    denied_env_vars = {
        entry.get("name")
        for entry in sandbox.get("credentials", {}).get("envVars", [])
        if entry.get("mode") == "deny"
    }
    for name in sorted(CLAUDE_REQUIRED_DENIED_ENV_VARS - denied_env_vars):
        errors.append(f"Claude sandbox must deny credential variable: {name}")

    instructions = repo_root / "CLAUDE.md"
    if instructions.is_file():
        line_count = len(instructions.read_text(encoding="utf-8").splitlines())
        if line_count > 200:
            errors.append(
                f"CLAUDE.md must stay at or below 200 lines; found {line_count}"
            )

    gitignore = repo_root / ".gitignore"
    if gitignore.is_file():
        ignored = set(gitignore.read_text(encoding="utf-8").splitlines())
        for required in ("CLAUDE.local.md", ".claude/settings.local.json"):
            if required not in ignored:
                errors.append(f".gitignore must exclude Claude local state: {required}")
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
    errors.extend(claude_configuration_errors(repo_root))
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
