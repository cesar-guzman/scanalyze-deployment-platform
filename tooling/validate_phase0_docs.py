#!/usr/bin/env python3
"""Validate the Phase 0 production-readiness documentation set offline."""

from __future__ import annotations

import re
import subprocess
import sys
from html import unescape
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
    "identity-control-plane",
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

STATUS_ASSIGNMENT_PATTERNS = {
    "production_go_claim": (
        re.compile(
            r"^\|?\s*(?:the\s+)?production"
            r"(?:\s+(?:environment|status|decision|readiness|gate))?"
            r"\s*(?:\||:|=|[-–—]|\bis\b)\s*(?P<value>.+?)\s*\|?$",
            re.I,
        ),
        re.compile(
            r"^\|?\s*(?:the\s+)?production(?:\s+environment)?\s+"
            r"(?P<value>(?:a\s+)?go\b.*|approved\b.*|ready\b.*|"
            r"live\b.*|enabled\b.*|deployed\b.*|released\b.*)\s*\|?$",
            re.I,
        ),
    ),
    "produccion_go_claim": (
        re.compile(
            r"^\|?\s*(?:la\s+)?producci[oó]n"
            r"(?:\s+(?:estado|decisi[oó]n|preparaci[oó]n|gate))?"
            r"\s*(?:\||:|=|[-–—]|\best[aá]\b|\bes\b)\s*"
            r"(?P<value>.+?)\s*\|?$",
            re.I,
        ),
        re.compile(
            r"^\|?\s*(?:la\s+)?producci[oó]n\s+"
            r"(?P<value>go\b.*|aprobad[ao]\b.*|list[ao]\b.*|activ[ao]\b.*|"
            r"habilitad[ao]\b.*|desplegad[ao]\b.*|liberad[ao]\b.*)\s*\|?$",
            re.I,
        ),
    ),
}
DIRECT_STATUS_PATTERNS = {
    "production_go_claim": re.compile(
        r"(?:go\s+for\s+production|ready\s+for\s+production)[.!]?", re.I
    ),
    "produccion_go_claim": re.compile(
        r"(?:go\s+para\s+producci[oó]n|list[ao]\s+para\s+producci[oó]n)[.!]?",
        re.I,
    ),
}
STATUS_CONTINUATION_LABELS = (
    re.compile(
        r"^\|?\s*(?:the\s+)?production"
        r"(?:\s+(?:environment|status|decision|readiness|gate))?"
        r"\s*(?:\||:|=|[-–—]|\bis\b)\s*\|?$",
        re.I,
    ),
    re.compile(
        r"^\|?\s*(?:la\s+)?producci[oó]n"
        r"(?:\s+(?:estado|decisi[oó]n|preparaci[oó]n|gate))?"
        r"\s*(?:\||:|=|[-–—]|\best[aá]\b|\bes\b)\s*\|?$",
        re.I,
    ),
)
TERMINAL_STATUS_PATTERNS = {
    "production_go_claim": re.compile(
        r"^(?:(?:a\s+)?go|"
        r"ready(?:\s+(?:for\s+(?:deployment|production|launch)|to\s+go))?|"
        r"approved(?:\s+(?:to\s+go|for\s+(?:deployment|production|launch)))?|"
        r"live(?:\s+validated)?|enabled|deployed|released)$",
        re.I,
    ),
    "produccion_go_claim": re.compile(
        r"^(?:go|"
        r"list[ao](?:\s+para\s+(?:desplegar|producci[oó]n|go))?|"
        r"aprobad[ao](?:\s+para\s+(?:go|despliegue|producci[oó]n))?|"
        r"activ[ao]|habilitad[ao]|desplegad[ao]|liberad[ao])$",
        re.I,
    ),
}
STATUS_CLAUSE_SPLIT = re.compile(
    r"(?:\s*[.!;,/]\s*|\s*(?:->|→)\s*|[ \t]+[-–—][ \t]+|"
    r"\s*\b(?:and|but|although|while|however|nevertheless|y|pero|aunque)\b\s*|"
    r"\s*\bmientras(?:\s+que)?\b\s*|\s*(?<!not )\byet\b\s*|"
    r"\s*\bsin\s+embargo\b\s*)",
    re.I,
)
STATUS_MATRIX_VALUE = re.compile(r"^go\s*/\s*no-go$", re.I)
MARKDOWN_LINK_TEXT = re.compile(r"!?\[([^\]]+)\]\([^)]*\)")
MARKDOWN_REFERENCE_LINK_TEXT = re.compile(r"!?\[([^\]]+)\]\[[^\]]*\]")
HTML_TAG = re.compile(r"<[^>]+>")
PRODUCTION_TABLE_LABELS = {
    "production": "production_go_claim",
    "the production": "production_go_claim",
    "production environment": "production_go_claim",
    "production status": "production_go_claim",
    "production decision": "production_go_claim",
    "production readiness": "production_go_claim",
    "production gate": "production_go_claim",
    "producción": "produccion_go_claim",
    "produccion": "produccion_go_claim",
    "la producción": "produccion_go_claim",
    "la produccion": "produccion_go_claim",
    "producción estado": "produccion_go_claim",
    "produccion estado": "produccion_go_claim",
    "producción decisión": "produccion_go_claim",
    "produccion decision": "produccion_go_claim",
}

RACI_ROLE_CODES = {"TPO", "PE", "PS", "RE", "SRE", "APP", "COPS", "IPA"}
RACI_HEADER_COLUMNS = (
    "activity",
    "tpo",
    "pe",
    "ps",
    "re",
    "sre",
    "app",
    "cops",
    "ipa",
)
RACI_ROLE_VALUE = re.compile(r"^(?:A|R|C|I)(?:/(?:A|R|C|I))?$")
RACI_QUALIFIED_ROLE_VALUES = {
    "A for execution control",
    "C for production prerequisites",
    "C when production",
}
MARKDOWN_H2 = re.compile(r"^ {0,3}##(?!#)[ \t]+(.+?)[ \t]*#*[ \t]*$")
MARKDOWN_H1_OR_H2 = re.compile(r"^ {0,3}#{1,2}(?!#)[ \t]+")
MARKDOWN_SEPARATOR_CELL = re.compile(r"^:?-{3,}:?$")

INLINE_LINK = re.compile(r"!?\[[^\]]*\]\(([^)]+)\)")
REFERENCE_LINK = re.compile(r"^\s*\[[^\]]+\]:\s*(\S+)")


class BaselineUnavailableError(RuntimeError):
    """Raised when the immutable Phase 0 baseline is absent locally."""


def find_forbidden(text: str) -> set[str]:
    """Return detector names without exposing matching content."""

    return {
        detector
        for detector, pattern in FORBIDDEN_PATTERNS.items()
        if pattern.search(text)
    }


def _plain_inline_text(value: str) -> str:
    """Normalize rendered inline Markdown and HTML without changing semantics."""

    normalized = unescape(value)
    normalized = MARKDOWN_LINK_TEXT.sub(r"\1", normalized)
    normalized = MARKDOWN_REFERENCE_LINK_TEXT.sub(r"\1", normalized)
    normalized = HTML_TAG.sub("", normalized)
    normalized = re.sub(r"[*_`]", "", normalized)
    return re.sub(r"\s+", " ", normalized).strip()


def _normalized_claim_lines(text: str) -> tuple[str, ...]:
    """Return normalized lines plus supported label/value continuations."""

    normalized_lines: list[str] = []
    for line in text.splitlines():
        normalized = _plain_inline_text(line)
        normalized = re.sub(r"^\s*(?:>\s*)?(?:[-+]\s+)?", "", normalized)
        normalized = re.sub(r"^#{1,6}\s+", "", normalized)
        if normalized:
            normalized_lines.append(normalized)

    candidates = list(normalized_lines)
    for index, line in enumerate(normalized_lines[:-1]):
        if any(pattern.fullmatch(line) for pattern in STATUS_CONTINUATION_LABELS):
            candidates.append(f"{line} {normalized_lines[index + 1]}")
    return tuple(dict.fromkeys(candidates))


def _is_positive_status_value(value: str, detector: str) -> bool:
    """Classify explicit terminal status clauses without keyword inference."""

    normalized = _plain_inline_text(value).strip(" |").strip()
    if STATUS_MATRIX_VALUE.fullmatch(normalized.strip(".!?:")):
        return False
    clauses = tuple(
        clause.strip(" |.!?:")
        for clause in STATUS_CLAUSE_SPLIT.split(normalized)
        if clause.strip(" |.!?:")
    )
    for clause in clauses:
        if TERMINAL_STATUS_PATTERNS[detector].fullmatch(clause):
            return True
        for pattern in STATUS_ASSIGNMENT_PATTERNS[detector]:
            match = pattern.fullmatch(clause)
            if match and TERMINAL_STATUS_PATTERNS[detector].fullmatch(
                _plain_inline_text(match.group("value")).strip(" |.!?:")
            ):
                return True
        if DIRECT_STATUS_PATTERNS[detector].fullmatch(clause):
            return True
    return False


def find_contradictions(text: str) -> set[str]:
    """Return direct production-GO assertions without exposing matched content."""

    findings: set[str] = set()
    for line in _normalized_claim_lines(text):
        if line.lstrip().startswith("|"):
            cells = _markdown_table_cells(line)
            if cells is not None and len(cells) >= 2:
                label = _plain_inline_text(cells[0]).casefold()
                detector = PRODUCTION_TABLE_LABELS.get(label)
                if detector is not None:
                    if _is_positive_status_value(cells[1], detector):
                        findings.add(detector)
                    continue
        for detector, patterns in STATUS_ASSIGNMENT_PATTERNS.items():
            for pattern in patterns:
                match = pattern.fullmatch(line)
                if (
                    match
                    and _is_positive_status_value(match.group("value"), detector)
                ):
                    findings.add(detector)
                    break
            if DIRECT_STATUS_PATTERNS[detector].fullmatch(line):
                findings.add(detector)
    return findings


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


def added_or_new_text(
    relative: Path,
    repo_root: Path = REPO_ROOT,
    baseline: str = PHASE0_BASELINE,
) -> str:
    """Return added lines for baseline files or full content for new files."""

    baseline_commit = subprocess.run(
        ["git", "cat-file", "-e", f"{baseline}^{{commit}}"],
        cwd=repo_root,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    if baseline_commit.returncode != 0:
        raise BaselineUnavailableError(
            f"phase0 baseline unavailable: {baseline}; fetch repository history"
        )

    baseline_object = subprocess.run(
        ["git", "cat-file", "-e", f"{baseline}:{relative.as_posix()}"],
        cwd=repo_root,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    path = repo_root / relative
    if baseline_object.returncode != 0:
        return path.read_text(encoding="utf-8")

    result = subprocess.run(
        [
            "git",
            "diff",
            "--no-ext-diff",
            "--unified=0",
            baseline,
            "--",
            relative.as_posix(),
        ],
        cwd=repo_root,
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


def _normalized_h2_title(line: str) -> str | None:
    """Return a normalized level-two Markdown heading, if present."""

    match = MARKDOWN_H2.match(line)
    if match is None:
        return None
    title = re.sub(r"[*_`]", "", match.group(1))
    return re.sub(r"\s+", " ", title).strip().casefold()


def _markdown_table_cells(line: str) -> tuple[str, ...] | None:
    """Parse a simple rendered Markdown table row with optional outer pipes."""

    indentation = len(line) - len(line.lstrip(" "))
    if indentation > 3 or "\t" in line:
        return None
    stripped = line.strip()
    if "|" not in stripped:
        return None
    if stripped.startswith("|"):
        stripped = stripped[1:]
    if stripped.endswith("|"):
        stripped = stripped[:-1]
    cells = tuple(cell.strip() for cell in stripped.split("|"))
    return cells if len(cells) > 1 else None


def _is_markdown_separator(cells: tuple[str, ...]) -> bool:
    """Return whether every cell renders as a Markdown table separator."""

    return bool(cells) and all(MARKDOWN_SEPARATOR_CELL.fullmatch(cell) for cell in cells)


def raci_accountability_errors(text: str) -> list[str]:
    """Validate the single organizational RACI table and its accountability."""

    errors: list[str] = []
    lines = text.splitlines()
    section_indexes = [
        index
        for index, line in enumerate(lines)
        if _normalized_h2_title(line) == "organizational raci"
    ]
    if not section_indexes:
        return ["organizational RACI section missing"]
    if len(section_indexes) != 1:
        return ["organizational RACI section must appear exactly once"]

    section_start = section_indexes[0] + 1
    section_end = len(lines)
    for index in range(section_start, len(lines)):
        if MARKDOWN_H1_OR_H2.match(lines[index]):
            section_end = index
            break

    tables: list[tuple[int, tuple[str, ...], tuple[str, ...]]] = []
    for index in range(section_start, max(section_start, section_end - 1)):
        header = _markdown_table_cells(lines[index])
        separator = _markdown_table_cells(lines[index + 1])
        if header is not None and separator is not None and _is_markdown_separator(separator):
            tables.append((index, header, separator))

    if not tables:
        return ["organizational RACI table missing or malformed"]
    if len(tables) != 1:
        return ["organizational RACI table must appear exactly once"]

    header_index, header, separator = tables[0]
    normalized_header = tuple(cell.casefold() for cell in header)
    if normalized_header != RACI_HEADER_COLUMNS:
        return ["organizational RACI header does not match required role columns"]
    if len(separator) != len(RACI_HEADER_COLUMNS):
        return ["organizational RACI table separator has wrong column count"]

    activity_count = 0
    for line in lines[header_index + 2:section_end]:
        cells = _markdown_table_cells(line)
        if cells is None:
            break
        if _is_markdown_separator(cells):
            errors.append("organizational RACI table has an unexpected separator row")
            continue
        activity = cells[0]
        if len(cells) != 9:
            errors.append(f"RACI row has wrong column count: {activity}")
            activity_count += 1
            continue
        activity_count += 1
        if not activity:
            errors.append("organizational RACI activity name must not be empty")
            continue
        if any(
            RACI_ROLE_VALUE.fullmatch(value) is None
            and value not in RACI_QUALIFIED_ROLE_VALUES
            for value in cells[1:]
        ):
            errors.append(f"RACI activity has unsupported role value: {activity}")
            continue
        accountable = sum(
            "A" in value.split(maxsplit=1)[0].split("/") for value in cells[1:]
        )
        if accountable != 1:
            errors.append(
                f"RACI activity must have exactly one accountable role: {activity}"
            )
    if activity_count == 0:
        errors.append("organizational RACI table must contain at least one activity")
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
        try:
            added_text = added_or_new_text(relative)
        except BaselineUnavailableError as error:
            errors.append(str(error))
            break
        detectors = sorted(find_forbidden(added_text))
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
