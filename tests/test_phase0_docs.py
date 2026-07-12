import re
import subprocess
from pathlib import Path

import pytest

from tooling.validate_phase0_docs import (
    BaselineUnavailableError,
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


def test_readiness_claim_checker_rejects_production_go() -> None:
    assert find_contradictions("Production is GO.") == {"production_go_claim"}
    assert find_contradictions("Producción está GO.") == {"produccion_go_claim"}
    assert find_contradictions("Production is NO-GO.") == set()


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


def test_raci_checker_rejects_dual_accountability() -> None:
    raci = """\
| Activity | TPO | PE | PS | RE | SRE | APP | COPS | IPA |
|---|---|---|---|---|---|---|---|---|
| Ambiguous approval | A | A | C | I | I | I | I | I |
"""
    assert raci_accountability_errors(raci) == [
        "RACI activity must have exactly one accountable role: Ambiguous approval"
    ]
