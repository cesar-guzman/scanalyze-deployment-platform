#!/usr/bin/env python3
"""Validate the Phase 0 production-readiness documentation set offline."""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path
from urllib.parse import unquote


REPO_ROOT = Path(__file__).resolve().parents[1]
PHASE0_BASELINE = "7dd9647d93bbf2fd88dfdada97ece95f93e81eaf"

PHASE0_DOCUMENTS = (
    Path("ADR/ADR-019-production-readiness-foundation.md"),
    Path("docs/production-readiness/README.md"),
    Path("docs/production-readiness/architecture.md"),
    Path("docs/production-readiness/threat-model.md"),
    Path("docs/production-readiness/ownership-raci.md"),
    Path("docs/production-readiness/evidence-policy.md"),
    Path("docs/production-readiness/phase-gates.md"),
    Path("docs/production-readiness/work-packages.md"),
    Path("docs/operations/rollback-recovery-boundaries.md"),
    Path("playbooks/phase-0-foundation.md"),
    Path("_NotebookLM_Brain/10_Production_Readiness_Foundation.md"),
)

INDEX_DOCUMENTS = (
    Path("README.md"),
    Path("docs/deployment/README.md"),
    Path("_NotebookLM_Brain/00_INDEX_AND_SOURCE_MAP.md"),
)

SCANNED_SUPPORT_FILES = (
    Path("ARCHITECTURE_ACCEPTANCE_GATES.md"),
    Path("Makefile"),
    Path("docs/operations/rollback.md"),
    Path("required-artifacts.yaml"),
    Path("tests/test_phase0_docs.py"),
    Path("tooling/validate_phase0_docs.py"),
)

REQUIRED_TERMS = {
    Path("ADR/ADR-019-production-readiness-foundation.md"): (
        "production decision",
        "no-go",
        "exact saved-plan policy",
        "plan, apply, promotion, and validation",
        "production never rebuilds",
        "no forks",
        "single-region",
        "gug-128",
    ),
    Path("docs/production-readiness/architecture.md"): (
        "current state versus target state",
        "trust boundaries",
        "exact saved-plan lifecycle",
        "canonical stage sequence",
        "phases 0-11",
    ),
    Path("docs/production-readiness/threat-model.md"): (
        "actors",
        "assets",
        "trust boundaries",
        "github actions",
        "oidc",
        "terraform state",
        "ssm",
        "ecr",
        "ecs",
        "confused deputy",
        "severity calibration",
        "repository:",
        "version:",
    ),
    Path("docs/production-readiness/ownership-raci.md"): (
        "account-ready-gate",
        "no contract or artifact",
        "account bootstrap provider exclusively produces",
        "artifact-publication",
        "synthetic-validation",
        "single-maintainer risk",
        "independent production approver",
    ),
    Path("docs/production-readiness/evidence-policy.md"): (
        "implemented",
        "locally validated",
        "ci validated",
        "live validated",
        "target",
        "blocked",
        "dry-run",
        "notebooklm",
    ),
    Path("docs/production-readiness/phase-gates.md"): (
        "gug-116",
        "gug-117",
        "gug-118",
        "gug-121",
        "gug-122",
        "gug-123",
        "gug-124",
        "gug-125",
        "gug-126",
        "gug-127",
        "gug-128",
        "gug-129",
        "fresh-agent",
        "contradictory production-go",
        "automatic program no-go",
        "exception policy",
    ),
    Path("docs/operations/rollback-recovery-boundaries.md"): (
        "application rollback",
        "infrastructure rollback",
        "break-glass state recovery",
        "restore is never routine rollback",
    ),
    Path("_NotebookLM_Brain/10_Production_Readiness_Foundation.md"): (
        "producción continúa no-go",
        "fase 0 constituye evidencia aws",
        "un dry-run demuestra un deployment",
        "se permiten rebuilds en producción",
        "binding ambiguo o faltante",
        "terraform state restore es rollback rutinario",
    ),
}

EXPECTED_STAGES = {
    "account-ready-gate",
    "global",
    "network",
    "platform",
    "data-foundation",
    "cicd",
    "artifact-publication",
    "services",
    "edge-identity",
    "edge",
    "addons",
    "synthetic-validation",
}

FORBIDDEN_PATTERNS = {
    "aws_account_id": re.compile(r"(?<![0-9])[0-9]{12}(?![0-9])"),
    "aws_arn": re.compile(r"\barn:(?:aws|aws-us-gov|aws-cn):[^\s`\"'<>()]+"),
    "aws_access_key": re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    "github_token": re.compile(r"\b(?:github_pat_|gh[pousr]_)[A-Za-z0-9_]{20,}\b"),
    "jwt": re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}"),
    "private_key": re.compile(r"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----"),
    "email": re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.I),
    "terraform_state_or_plan": re.compile(
        r"\"(?:terraform_version|lineage|resource_changes)\"\s*:"
    ),
}

CONTRADICTORY_PATTERNS = {
    "production_go_claim": re.compile(
        r"\bproduction\s+(?:is|:)\s+(?:\*\*)?go\b", re.I
    ),
    "produccion_go_claim": re.compile(
        r"\bproducci[oó]n\s+(?:est[aá]|:)\s+(?:\*\*)?go\b", re.I
    ),
}

RACI_ROLE_CODES = {"TPO", "PE", "PS", "RE", "SRE", "APP", "COPS", "IPA"}

INLINE_LINK = re.compile(r"!?\[[^\]]*\]\(([^)]+)\)")
REFERENCE_LINK = re.compile(r"^\s*\[[^\]]+\]:\s*(\S+)")


def find_forbidden(text: str) -> set[str]:
    """Return detector names without exposing matching content."""

    return {
        detector
        for detector, pattern in FORBIDDEN_PATTERNS.items()
        if pattern.search(text)
    }


def find_contradictions(text: str) -> set[str]:
    """Return fail-open readiness claims without exposing matching content."""

    return {
        detector
        for detector, pattern in CONTRADICTORY_PATTERNS.items()
        if pattern.search(text)
    }


def document_hygiene_errors(path: Path) -> list[str]:
    """Return line-ending errors without exposing document content."""

    text = path.read_text(encoding="utf-8")
    errors = [
        f"trailing whitespace at line {line_number}"
        for line_number, line in enumerate(text.splitlines(), start=1)
        if line.endswith((" ", "\t"))
    ]
    if text and not text.endswith("\n"):
        errors.append("missing final newline")
    elif text.endswith("\n\n"):
        errors.append("extra blank line at EOF")
    return errors


def added_or_new_text(relative: Path) -> str:
    """Return added lines for baseline files or full content for new files."""

    baseline_object = subprocess.run(
        ["git", "cat-file", "-e", f"{PHASE0_BASELINE}:{relative.as_posix()}"],
        cwd=REPO_ROOT,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    path = REPO_ROOT / relative
    if baseline_object.returncode != 0:
        return path.read_text(encoding="utf-8")

    result = subprocess.run(
        [
            "git",
            "diff",
            "--no-ext-diff",
            "--unified=0",
            PHASE0_BASELINE,
            "--",
            relative.as_posix(),
        ],
        cwd=REPO_ROOT,
        check=True,
        stdout=subprocess.PIPE,
    )
    diff = result.stdout.decode("utf-8", "replace")
    return "\n".join(
        line[1:]
        for line in diff.splitlines()
        if line.startswith("+") and not line.startswith("+++ ")
    )


def missing_required_terms(text: str, required_terms: tuple[str, ...]) -> list[str]:
    """Return required decision terms that are absent from normalized text."""

    lowered = text.lower()
    return [term for term in required_terms if term.lower() not in lowered]


def relative_link_errors(path: Path, repo_root: Path = REPO_ROOT) -> list[int]:
    """Return line numbers with missing or escaping relative file links."""

    errors: list[int] = []
    text = path.read_text(encoding="utf-8")
    for line_number, line in enumerate(text.splitlines(), start=1):
        targets = INLINE_LINK.findall(line)
        reference = REFERENCE_LINK.match(line)
        if reference:
            targets.append(reference.group(1))

        for raw_target in targets:
            target = raw_target.strip().split(maxsplit=1)[0].strip("<>")
            if not target or target.startswith(("#", "http://", "https://", "mailto:")):
                continue

            decoded = unquote(target.split("#", 1)[0].split("?", 1)[0])
            candidate = (path.parent / decoded).resolve()
            try:
                candidate.relative_to(repo_root)
            except ValueError:
                errors.append(line_number)
                continue
            if not candidate.exists():
                errors.append(line_number)

    return errors


def stage_ownership_errors(text: str) -> list[str]:
    """Validate that every canonical stage has one complete ownership row."""

    errors: list[str] = []
    rows: dict[str, list[str]] = {}
    for line in text.splitlines():
        if not line.startswith("|"):
            continue
        cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
        if not cells:
            continue
        stage = cells[0].strip("`")
        if stage not in EXPECTED_STAGES:
            continue
        if stage in rows:
            errors.append(f"duplicate ownership row for stage: {stage}")
            continue
        rows[stage] = cells

    for stage in sorted(EXPECTED_STAGES):
        cells = rows.get(stage)
        if cells is None:
            errors.append(f"ownership matrix missing stage: {stage}")
            continue
        if len(cells) != 6:
            errors.append(f"ownership row has wrong column count: {stage}")
            continue
        for index, label in ((1, "input source"), (2, "output producer"),
                             (3, "state owner"), (4, "accountable owner")):
            value = cells[index].strip()
            if not value or value.lower() in {"tbd", "unknown", "pending"}:
                errors.append(f"stage {stage} missing {label}")
        accountable_owner = cells[4].strip()
        if accountable_owner and accountable_owner not in RACI_ROLE_CODES:
            errors.append(
                f"stage {stage} must have exactly one accountable owner"
            )

    return errors


def raci_accountability_errors(text: str) -> list[str]:
    """Require exactly one accountable role for every organizational activity."""

    errors: list[str] = []
    in_table = False
    for line in text.splitlines():
        if line.startswith("| Activity |"):
            in_table = True
            continue
        if not in_table:
            continue
        if not line.startswith("|"):
            break
        cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
        if not cells or set(cells[0]) <= {"-", ":"}:
            continue
        activity = cells[0]
        if len(cells) != 9:
            errors.append(f"RACI row has wrong column count: {activity}")
            continue
        accountable = sum(
            bool(re.match(r"^A(?:$|/|\s)", value)) for value in cells[1:]
        )
        if accountable != 1:
            errors.append(
                f"RACI activity must have exactly one accountable role: {activity}"
            )
    return errors


def validate() -> list[str]:
    errors: list[str] = []
    all_docs = PHASE0_DOCUMENTS + INDEX_DOCUMENTS
    scanned_change_scope = all_docs + SCANNED_SUPPORT_FILES

    for relative in scanned_change_scope:
        path = REPO_ROOT / relative
        if not path.is_file():
            errors.append(f"missing scanned change-scope file: {relative}")

    for relative in all_docs:
        path = REPO_ROOT / relative
        if not path.is_file():
            errors.append(f"missing required file: {relative}")
            continue

        link_lines = relative_link_errors(path)
        if link_lines:
            rendered = ",".join(str(line) for line in link_lines)
            errors.append(f"broken or escaping relative link: {relative}:{rendered}")

    for relative in scanned_change_scope:
        path = REPO_ROOT / relative
        if not path.is_file():
            continue
        for error in document_hygiene_errors(path):
            errors.append(f"document hygiene error in {relative}: {error}")

    for relative in scanned_change_scope:
        path = REPO_ROOT / relative
        if not path.is_file():
            continue
        detectors = sorted(find_forbidden(added_or_new_text(relative)))
        if detectors:
            errors.append(
                f"prohibited content class in {relative}: {','.join(detectors)}"
            )

    for relative in all_docs:
        path = REPO_ROOT / relative
        if path.is_file():
            contradictions = sorted(
                find_contradictions(path.read_text(encoding="utf-8"))
            )
            if contradictions:
                errors.append(
                    f"contradictory readiness claim in {relative}: "
                    f"{','.join(contradictions)}"
                )

    for relative, required_terms in REQUIRED_TERMS.items():
        path = REPO_ROOT / relative
        if not path.is_file():
            continue
        text = path.read_text(encoding="utf-8")
        for term in missing_required_terms(text, required_terms):
            errors.append(f"missing required term in {relative}: {term}")

    ownership_path = REPO_ROOT / "docs/production-readiness/ownership-raci.md"
    if ownership_path.is_file():
        ownership = ownership_path.read_text(encoding="utf-8")
        errors.extend(stage_ownership_errors(ownership))
        errors.extend(raci_accountability_errors(ownership))

    notebook_path = REPO_ROOT / "_NotebookLM_Brain/10_Production_Readiness_Foundation.md"
    if notebook_path.is_file():
        notebook = notebook_path.read_text(encoding="utf-8").lower()
        required_answers = (
            "sí. producción continúa **no-go**",
            "no. fase 0 produce decisiones",
            "no. un dry-run",
            "no. producción promueve",
            "el flujo falla antes de oidc",
            "no. es una operación break-glass",
        )
        for answer in required_answers:
            if answer not in notebook:
                errors.append(f"NotebookLM source missing fail-closed answer: {answer}")

    return errors


def main() -> int:
    errors = validate()
    if errors:
        print("Phase 0 documentation validation: FAIL")
        for error in errors:
            print(f"- {error}")
        return 1

    print(
        "Phase 0 documentation validation: PASS "
        f"({len(PHASE0_DOCUMENTS)} canonical documents; "
        f"{len(PHASE0_DOCUMENTS + INDEX_DOCUMENTS + SCANNED_SUPPORT_FILES)} "
        "change-scope files scanned; links and controls checked)"
    )
    print("Evidence status: LOCALLY_VALIDATED_DOCUMENTATION_ONLY; production NO-GO")
    return 0


if __name__ == "__main__":
    sys.exit(main())
