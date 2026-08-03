"""Canonical required-check contract shared by GitHub governance tooling."""

from __future__ import annotations

from collections.abc import Iterable


CANONICAL_REPOSITORY = "cesar-guzman/scanalyze-deployment-platform"
CANONICAL_DEFAULT_BRANCH = "main"
CANONICAL_EXPECTED_APP_SLUG = "github-actions"
CANONICAL_REQUIRED_CHECKS = (
    (
        "Lint, security, and schema checks",
        ".github/workflows/pr-validation.yml",
        "lint-and-security",
    ),
    (
        "Python tests",
        ".github/workflows/pr-validation.yml",
        "python-tests",
    ),
    (
        "Validate deployment manifest schema",
        ".github/workflows/pr-validation.yml",
        "manifest-validation",
    ),
    (
        "Terraform validate (no AWS)",
        ".github/workflows/pr-validation.yml",
        "terraform-validate",
    ),
    (
        "Verify clean clone reproducibility",
        ".github/workflows/repro-check.yml",
        "clean-clone-check",
    ),
    (
        "Microservices validation gate",
        ".github/workflows/microservices-build.yml",
        "validation_gate",
    ),
)


def is_canonical_repository(repository: str) -> bool:
    """Match GitHub's case-insensitive owner/repository identity semantics."""

    return repository.casefold() == CANONICAL_REPOSITORY.casefold()


def repository_contract_violation(
    *,
    default_branch: object,
    strict: object,
    expected_app_slug: object,
    checks: Iterable[tuple[object, object, object]],
) -> str | None:
    """Return the first fail-closed mismatch in the Scanalyze apply contract."""

    if default_branch != CANONICAL_DEFAULT_BRANCH:
        return (
            "canonical repository contract requires "
            f"default_branch={CANONICAL_DEFAULT_BRANCH!r}"
        )
    if strict is not True:
        return "canonical repository contract requires strict=true"
    if expected_app_slug != CANONICAL_EXPECTED_APP_SLUG:
        return (
            "canonical repository contract requires "
            f"expected_app_slug={CANONICAL_EXPECTED_APP_SLUG!r}"
        )

    return required_checks_contract_violation(checks)


def required_checks_contract_violation(
    checks: Iterable[tuple[object, object, object]],
) -> str | None:
    """Return a mismatch when the ordered context/workflow/job tuples drift."""

    try:
        observed_checks = tuple(tuple(check) for check in checks)
    except TypeError:
        observed_checks = ()
    if observed_checks != CANONICAL_REQUIRED_CHECKS:
        return (
            "canonical repository contract must preserve the exact six required "
            "checks and their workflow/job mappings"
        )
    return None
