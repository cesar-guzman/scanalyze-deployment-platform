#!/usr/bin/env python3
"""Validate the contributor workflow and Claude Code baseline contract.

This gate enforces, deterministically and offline:

  1. The contributor documents exist and are marked ``Status: CURRENT``.
  2. The README links the contributor guide (guide is reachable).
  3. ``.claude/settings.json`` pins model routing (Opus 4.8 plan / Sonnet 5
     execute) with no silent fallback and defaults to plan mode.
  4. The baseline denies secrets, destructive Git, remote publish, and
     Terraform/AWS mutation.
  5. Personal Claude overrides (``settings.local.json``) are git-ignored.

Exits 1 on any violation. No network, no AWS, no mutation.
"""

import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

CONTRIB_DIR = REPO / "docs" / "contributing"
REQUIRED_DOCS = [
    CONTRIB_DIR / "contributor-guide.md",
    CONTRIB_DIR / "ai-assisted-development.md",
    CONTRIB_DIR / "claude-code-setup.md",
    CONTRIB_DIR / "onboarding-rehearsal-checklist.md",
]

README = REPO / "README.md"
SETTINGS = REPO / ".claude" / "settings.json"
GITIGNORE = REPO / ".gitignore"

# Pinned model routing — no silent fallback.
EXPECTED_MODEL = "opusplan"
EXPECTED_PLAN_MODEL = "claude-opus-4-8"
EXPECTED_EXEC_MODEL = "claude-sonnet-5"

# Required deny rules (a representative floor; the baseline may deny more).
REQUIRED_DENY = [
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
]


def _fail(errors: list[str]) -> "None":
    print("\n=== Contributor Contract Check ===")
    print(f"Result: FAIL ({len(errors)} problem(s))\n")
    for e in errors:
        print(f"  ❌ {e}")
    print("\nFAIL: contributor workflow / Claude baseline contract violated")
    sys.exit(1)


def main() -> None:
    errors: list[str] = []

    # 1. Required docs exist and are marked CURRENT.
    for doc in REQUIRED_DOCS:
        if not doc.exists():
            errors.append(f"missing document: {doc.relative_to(REPO)}")
            continue
        text = doc.read_text(encoding="utf-8")
        if "Status: CURRENT" not in text:
            errors.append(
                f"{doc.relative_to(REPO)}: not marked 'Status: CURRENT'"
            )

    # 2. README links the contributor guide.
    if not README.exists():
        errors.append("missing README.md")
    else:
        readme = README.read_text(encoding="utf-8")
        if "docs/contributing/contributor-guide.md" not in readme:
            errors.append("README.md does not link the contributor guide")

    # 3 & 4. Claude Code baseline.
    if not SETTINGS.exists():
        errors.append(f"missing Claude baseline: {SETTINGS.relative_to(REPO)}")
    else:
        try:
            settings = json.loads(SETTINGS.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            errors.append(f"{SETTINGS.relative_to(REPO)}: invalid JSON ({exc})")
            settings = None

        if settings is not None:
            perms = settings.get("permissions", {})

            if perms.get("defaultMode") != "plan":
                errors.append(
                    "baseline: permissions.defaultMode must be 'plan' "
                    f"(found {perms.get('defaultMode')!r})"
                )

            if settings.get("model") != EXPECTED_MODEL:
                errors.append(
                    f"baseline: model must be {EXPECTED_MODEL!r} "
                    f"(found {settings.get('model')!r})"
                )

            env = settings.get("env", {})
            if env.get("ANTHROPIC_MODEL") != EXPECTED_PLAN_MODEL:
                errors.append(
                    "baseline: env.ANTHROPIC_MODEL must be pinned to "
                    f"{EXPECTED_PLAN_MODEL!r} (found "
                    f"{env.get('ANTHROPIC_MODEL')!r}) — no silent fallback"
                )
            if env.get("ANTHROPIC_SMALL_FAST_MODEL") != EXPECTED_EXEC_MODEL:
                errors.append(
                    "baseline: env.ANTHROPIC_SMALL_FAST_MODEL must be pinned to "
                    f"{EXPECTED_EXEC_MODEL!r} (found "
                    f"{env.get('ANTHROPIC_SMALL_FAST_MODEL')!r}) — no silent "
                    "fallback"
                )

            deny = perms.get("deny", [])
            for rule in REQUIRED_DENY:
                if rule not in deny:
                    errors.append(f"baseline: missing required deny rule: {rule}")

    # 5. settings.local.json is git-ignored.
    if not GITIGNORE.exists():
        errors.append("missing .gitignore")
    else:
        gi = GITIGNORE.read_text(encoding="utf-8")
        if "settings.local.json" not in gi:
            errors.append(
                ".gitignore does not ignore .claude/settings.local.json"
            )

    if errors:
        _fail(errors)

    print("=== Contributor Contract Check ===")
    print("Result: PASS")
    print(f"  Documents present and CURRENT: {len(REQUIRED_DOCS)}")
    print("  README links contributor guide: yes")
    print(f"  Model routing pinned: {EXPECTED_MODEL} "
          f"({EXPECTED_PLAN_MODEL} plan / {EXPECTED_EXEC_MODEL} execute)")
    print("  Plan-first default: yes")
    print(f"  Required deny rules present: {len(REQUIRED_DENY)}")
    print("\n✅ Contributor workflow / Claude baseline contract satisfied")
    sys.exit(0)


if __name__ == "__main__":
    main()
