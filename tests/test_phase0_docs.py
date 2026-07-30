import re
import subprocess
from pathlib import Path

import pytest

from tooling.validate_phase0_docs import (
    BaselineUnavailableError,
    REPO_ROOT,
    added_or_new_text,
    document_hygiene_errors,
    find_forbidden,
    find_contradictions,
    missing_required_terms,
    raci_accountability_errors,
    relative_link_errors,
    stage_ownership_errors,
    validate,
)


def _git(repo: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", *args],
        cwd=repo,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    return result.stdout.strip()


def test_phase0_document_set_is_complete_and_safe() -> None:
    assert validate() == []


def test_forbidden_detector_reports_classes_without_values() -> None:
    assert find_forbidden("account=" + ("1" * 12)) == {"aws_account_id"}
    arn_like = ":".join(("arn", "aws", "iam", "", "", "role/example"))
    assert find_forbidden(arn_like) == {"aws_arn"}
    assert find_forbidden("production remains NO-GO") == set()


def test_added_or_new_text_fails_closed_without_baseline(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "--quiet")

    with pytest.raises(BaselineUnavailableError, match="baseline unavailable"):
        added_or_new_text(
            Path("Makefile"),
            repo_root=repo,
            baseline="0" * 40,
        )


def test_added_or_new_text_excludes_preexisting_forbidden_content(
    tmp_path: Path,
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "--quiet")
    _git(repo, "config", "user.name", "Phase Zero Test")
    _git(repo, "config", "user.email", "phase-zero" + "@" + "example.invalid")

    arn_like = ":".join(("arn", "aws", "iam", "", "1" * 12, "role/example"))
    makefile = repo / "Makefile"
    makefile.write_text(f"detector={arn_like}\n", encoding="utf-8")
    _git(repo, "add", "Makefile")
    _git(repo, "commit", "--quiet", "-m", "baseline")
    baseline = _git(repo, "rev-parse", "HEAD")

    makefile.write_text(
        f"detector={arn_like}\nphase0-docs-check:\n\t@python validator.py\n",
        encoding="utf-8",
    )
    added_text = added_or_new_text(
        Path("Makefile"),
        repo_root=repo,
        baseline=baseline,
    )
    assert "phase0-docs-check" in added_text
    assert arn_like not in added_text
    assert find_forbidden(added_text) == set()

    makefile.write_text(
        f"detector={arn_like}\nnew-value={arn_like}\n",
        encoding="utf-8",
    )
    assert find_forbidden(
        added_or_new_text(
            Path("Makefile"),
            repo_root=repo,
            baseline=baseline,
        )
    ) == {"aws_account_id", "aws_arn"}

    new_file = repo / "new.md"
    new_file.write_text(f"new-value={arn_like}\n", encoding="utf-8")
    assert find_forbidden(
        added_or_new_text(
            Path("new.md"),
            repo_root=repo,
            baseline=baseline,
        )
    ) == {"aws_account_id", "aws_arn"}


@pytest.mark.parametrize(
    ("workflow_path", "job_name"),
    (
        (Path(".github/workflows/pr-validation.yml"), "lint-and-security"),
        (Path(".github/workflows/pr-validation.yml"), "python-tests"),
        (Path(".github/workflows/repro-check.yml"), "clean-clone-check"),
    ),
)
def test_phase0_ci_jobs_fetch_baseline_history(
    workflow_path: Path,
    job_name: str,
) -> None:
    workflow = workflow_path.read_text(encoding="utf-8")
    marker = f"  {job_name}:\n"
    start = workflow.index(marker) + len(marker)
    next_job = re.search(r"(?m)^  [a-z0-9-]+:\n", workflow[start:])
    end = start + next_job.start() if next_job else len(workflow)
    job = workflow[start:end]

    assert job.count("uses: actions/checkout@") == 1
    assert "fetch-depth: 0" in job


@pytest.mark.parametrize(
    ("claim", "detector"),
    (
        ("Production is GO.", "production_go_claim"),
        ("Production: GO.", "production_go_claim"),
        ("**Production:** **GO**", "production_go_claim"),
        ("`Production`: `GO`", "production_go_claim"),
        ("Production status: GO.", "production_go_claim"),
        ("Production is approved to GO.", "production_go_claim"),
        ("Production is ready for deployment.", "production_go_claim"),
        ("GO for production.", "production_go_claim"),
        ("Production approved to GO.", "production_go_claim"),
        ("Production is a GO.", "production_go_claim"),
        ("Production — GO.", "production_go_claim"),
        ("Production = GO.", "production_go_claim"),
        ("[Production](./status.md): GO.", "production_go_claim"),
        ("[Production][status]: GO.", "production_go_claim"),
        ("<strong>Production:</strong> GO.", "production_go_claim"),
        ("Production:\nGO.", "production_go_claim"),
        ("The production environment is GO.", "production_go_claim"),
        ("| Production | GO |", "production_go_claim"),
        ("Production status: blocked but GO.", "production_go_claim"),
        ("Production: disabled; production is GO.", "production_go_claim"),
        ("Production status: blocked. Production is GO.", "production_go_claim"),
        ("Production status: blocked although GO.", "production_go_claim"),
        ("Production status: blocked yet production is GO.", "production_go_claim"),
        ("Production status: disabled nevertheless approved.", "production_go_claim"),
        ("Production status: disabled and production is GO.", "production_go_claim"),
        ("Production status: blocked and GO.", "production_go_claim"),
        ("Production status: blocked while production is GO.", "production_go_claim"),
        ("Production status: blocked / GO.", "production_go_claim"),
        ("Production status: blocked/GO.", "production_go_claim"),
        ("Production status: blocked! Production is GO.", "production_go_claim"),
        ("Production status: blocked — Production is GO.", "production_go_claim"),
        ("Production status: pending -> GO.", "production_go_claim"),
        ("Producción está GO.", "produccion_go_claim"),
        ("Producción: GO.", "produccion_go_claim"),
        ("**Producción:** **GO**", "produccion_go_claim"),
        ("Producción lista para desplegar.", "produccion_go_claim"),
        ("Producción aprobada para GO.", "produccion_go_claim"),
        ("[Producción](./estado.md): GO.", "produccion_go_claim"),
        ("Producción: bloqueada pero GO.", "produccion_go_claim"),
        ("Producción: bloqueada y GO.", "produccion_go_claim"),
        (
            "Producción: bloqueada mientras producción está GO.",
            "produccion_go_claim",
        ),
        ("Producción estado: pendiente. Producción está GO.", "produccion_go_claim"),
    ),
)
def test_readiness_claim_checker_rejects_production_go(
    claim: str,
    detector: str,
) -> None:
    assert find_contradictions(claim) == {detector}


@pytest.mark.parametrize(
    "claim",
    (
        "Production is NO-GO.",
        "> **Production:** **NO-GO**",
        "> **Producción:** **NO-GO**",
        "# Production Readiness GO/NO-GO Matrix",
        "A successful workflow alone is not a production GO.",
        "Detect contradictory production-GO claims.",
        "Production is not approved to GO.",
        "Production requires independent GO approval.",
        "Production decision: GO/NO-GO.",
        "If production is ready for deployment, keep the gate closed.",
        "Production status: pending independent GO approval.",
        "Production status: not yet approved to GO.",
        "Production status: never approved to GO.",
        "Production status: blocked until independent GO approval.",
        "Production: disabled; independent GO is required.",
        "Production status: blocked, GO approval required.",
        "Production status: pending; GO requires independent approval.",
        "Production status: disabled, ready only after independent approval.",
        "Production status: pending; approved plan required.",
        "Production status: pending and independent GO approval is required.",
        "Production decision: GO / NO-GO.",
        (
            "| Production | Workflow disabled; no authorized pilot | "
            "Limited pilot after independent GO | Phase 10 |"
        ),
    ),
)
def test_readiness_claim_checker_preserves_non_go_policy_text(claim: str) -> None:
    assert find_contradictions(claim) == set()


def test_phase0_validation_rejects_contradictory_production_status(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = REPO_ROOT / "docs/production-readiness/README.md"
    original_read_text = Path.read_text

    def read_text_with_contradiction(path: Path, *args: object, **kwargs: object) -> str:
        text = original_read_text(path, *args, **kwargs)
        if path == target:
            return text + "Production: GO.\n"
        return text

    monkeypatch.setattr(Path, "read_text", read_text_with_contradiction)

    assert (
        "contradictory readiness claim in "
        "docs/production-readiness/README.md: production_go_claim"
    ) in validate()


def test_document_hygiene_checker_fails_closed(tmp_path: Path) -> None:
    path = tmp_path / "phase0.md"
    path.write_text("alpha  \nbeta\t\n\n", encoding="utf-8")
    assert document_hygiene_errors(path) == [
        "trailing whitespace at line 1",
        "trailing whitespace at line 2",
        "extra blank line at EOF",
    ]

    path.write_text("alpha\\\nbeta\n", encoding="utf-8")
    assert document_hygiene_errors(path) == []

    path.write_text("alpha", encoding="utf-8")
    assert document_hygiene_errors(path) == ["missing final newline"]


def test_relative_link_checker_rejects_escape(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    docs = repo / "docs"
    docs.mkdir(parents=True)
    path = docs / "example.md"
    path.write_text("[outside](../../outside.md)\n", encoding="utf-8")
    assert relative_link_errors(path, repo_root=repo) == [1]


def test_stage_ownership_checker_fails_closed_on_missing_owner() -> None:
    path = Path("docs/production-readiness/ownership-raci.md")
    ownership = path.read_text(encoding="utf-8")
    broken = ownership.replace(
        "| PE | Root and local contract output exist; live publication Blocked |",
        "|  | Root and local contract output exist; live publication Blocked |",
        1,
    )
    assert stage_ownership_errors(broken) == [
        "stage global missing accountable owner"
    ]


def test_stage_ownership_checker_fails_closed_on_dual_owner() -> None:
    path = Path("docs/production-readiness/ownership-raci.md")
    ownership = path.read_text(encoding="utf-8")
    broken = ownership.replace(
        "| PE | Root and local contract output exist; live publication Blocked |",
        "| PE + PS | Root and local contract output exists; live publication Blocked |",
        1,
    )
    assert stage_ownership_errors(broken) == [
        "stage global must have exactly one accountable owner"
    ]


def test_required_decision_checker_fails_closed_on_missing_decision() -> None:
    assert missing_required_terms(
        "Production remains NO-GO.",
        ("production remains no-go", "exact saved-plan policy"),
    ) == ["exact saved-plan policy"]


def _raci_document(
    header: str = "| Activity | TPO | PE | PS | RE | SRE | APP | COPS | IPA |",
    separator: str = "|---|---|---|---|---|---|---|---|---|",
    rows: tuple[str, ...] = (
        "| Approve a phase | A | R | C | I | I | I | I | I |",
    ),
) -> str:
    table = "\n".join((header, separator, *rows))
    return f"## Organizational RACI\n\n{table}\n\n## Next section\n"


@pytest.mark.parametrize(
    "header",
    (
        "| Activity | TPO | PE | PS | RE | SRE | APP | COPS | IPA |",
        "|Activity|TPO|PE|PS|RE|SRE|APP|COPS|IPA|",
        "  | activity | tpo | pe | ps | re | sre | app | cops | ipa |",
        "Activity | TPO | PE | PS | RE | SRE | APP | COPS | IPA",
    ),
)
def test_raci_checker_rejects_dual_accountability_for_supported_headers(
    header: str,
) -> None:
    raci = _raci_document(
        header=header,
        rows=("| Ambiguous approval | A | A | C | I | I | I | I | I |",),
    )
    assert raci_accountability_errors(raci) == [
        "RACI activity must have exactly one accountable role: Ambiguous approval"
    ]


@pytest.mark.parametrize(
    "header",
    (
        "| Activity | TPO | PE | PS | RE | SRE | APP | COPS | IPA |",
        "|Activity|TPO|PE|PS|RE|SRE|APP|COPS|IPA|",
        "  | activity | tpo | pe | ps | re | sre | app | cops | ipa |",
        "Activity | TPO | PE | PS | RE | SRE | APP | COPS | IPA",
    ),
)
def test_raci_checker_accepts_supported_markdown_headers(header: str) -> None:
    assert raci_accountability_errors(_raci_document(header=header)) == []


@pytest.mark.parametrize(
    "rendered_accountable",
    (
        "**A**",
        "_A_",
        "`A`",
        "[A](#accountable)",
        "<strong>A</strong>",
    ),
)
def test_raci_checker_rejects_formatted_accountability_bypass(
    rendered_accountable: str,
) -> None:
    raci = _raci_document(
        rows=(
            "| Ambiguous approval | A | "
            f"{rendered_accountable} | C | I | I | I | I | I |",
        ),
    )
    assert raci_accountability_errors(raci) == [
        "RACI activity has unsupported role value: Ambiguous approval"
    ]


@pytest.mark.parametrize("secondary_accountable", ("R/A", "C/A", "I/A"))
def test_raci_checker_counts_accountable_code_on_either_side_of_slash(
    secondary_accountable: str,
) -> None:
    raci = _raci_document(
        rows=(
            "| Ambiguous approval | A | "
            f"{secondary_accountable} | C | I | I | I | I | I |",
        ),
    )
    assert raci_accountability_errors(raci) == [
        "RACI activity must have exactly one accountable role: Ambiguous approval"
    ]


@pytest.mark.parametrize(
    "unsupported_qualifier",
    ("R when A", "C for A", "I when accountable"),
)
def test_raci_checker_rejects_open_ended_role_qualifiers(
    unsupported_qualifier: str,
) -> None:
    raci = _raci_document(
        rows=(
            "| Ambiguous approval | A | "
            f"{unsupported_qualifier} | C | I | I | I | I | I |",
        ),
    )
    assert raci_accountability_errors(raci) == [
        "RACI activity has unsupported role value: Ambiguous approval"
    ]


def test_raci_checker_fails_closed_without_organizational_section() -> None:
    raci = """\
| Activity | TPO | PE | PS | RE | SRE | APP | COPS | IPA |
|---|---|---|---|---|---|---|---|---|
| Approve a phase | A | R | C | I | I | I | I | I |
"""
    assert raci_accountability_errors(raci) == [
        "organizational RACI section missing"
    ]


def test_raci_checker_rejects_tab_indented_decoy_heading() -> None:
    raci = """\
\t## Organizational RACI

| Activity | TPO | PE | PS | RE | SRE | APP | COPS | IPA |
|---|---|---|---|---|---|---|---|---|
| Decoy approval | A | R | C | I | I | I | I | I |

## Actual approval matrix

| Activity | TPO | PE | PS | RE | SRE | APP | COPS | IPA |
|---|---|---|---|---|---|---|---|---|
| Ambiguous approval | A | A | C | I | I | I | I | I |
"""
    assert raci_accountability_errors(raci) == [
        "organizational RACI section missing"
    ]


def test_raci_checker_fails_closed_on_invalid_or_empty_table() -> None:
    invalid_header = _raci_document(
        header="| Responsibility | TPO | PE | PS | RE | SRE | APP | COPS | IPA |"
    )
    assert raci_accountability_errors(invalid_header) == [
        "organizational RACI header does not match required role columns"
    ]

    empty = _raci_document(rows=())
    assert raci_accountability_errors(empty) == [
        "organizational RACI table must contain at least one activity"
    ]


def test_raci_checker_fails_closed_on_duplicate_table() -> None:
    first = _raci_document().removesuffix("## Next section\n")
    duplicate = """\
| Activity | TPO | PE | PS | RE | SRE | APP | COPS | IPA |
|---|---|---|---|---|---|---|---|---|
| Approve production | C | I | C | I | I | I | I | A |

## Next section
"""
    assert raci_accountability_errors(first + duplicate) == [
        "organizational RACI table must appear exactly once"
    ]


def test_phase0_validation_rejects_raci_header_bypass(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = REPO_ROOT / "docs/production-readiness/ownership-raci.md"
    original_read_text = Path.read_text

    def read_text_with_raci_bypass(path: Path, *args: object, **kwargs: object) -> str:
        text = original_read_text(path, *args, **kwargs)
        if path != target:
            return text
        text = text.replace(
            "| Activity | TPO | PE | PS | RE | SRE | APP | COPS | IPA |",
            "|Activity|TPO|PE|PS|RE|SRE|APP|COPS|IPA|",
            1,
        )
        return text.replace(
            "| Accept architecture and phase-gate contract | A | R | C | I | C | C | I | I |",
            "| Accept architecture and phase-gate contract | A | A | C | I | C | C | I | I |",
            1,
        )

    monkeypatch.setattr(Path, "read_text", read_text_with_raci_bypass)

    assert (
        "RACI activity must have exactly one accountable role: "
        "Accept architecture and phase-gate contract"
    ) in validate()
