from pathlib import Path

from tooling.validate_phase0_docs import (
    find_forbidden,
    find_contradictions,
    missing_required_terms,
    raci_accountability_errors,
    relative_link_errors,
    stage_ownership_errors,
    validate,
)


def test_phase0_document_set_is_complete_and_safe() -> None:
    assert validate() == []


def test_forbidden_detector_reports_classes_without_values() -> None:
    assert find_forbidden("account=" + ("1" * 12)) == {"aws_account_id"}
    arn_like = ":".join(("arn", "aws", "iam", "", "", "role/example"))
    assert find_forbidden(arn_like) == {"aws_arn"}
    assert find_forbidden("production remains NO-GO") == set()


def test_readiness_claim_checker_rejects_production_go() -> None:
    assert find_contradictions("Production is GO.") == {"production_go_claim"}
    assert find_contradictions("Producción está GO.") == {"produccion_go_claim"}
    assert find_contradictions("Production is NO-GO.") == set()


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
