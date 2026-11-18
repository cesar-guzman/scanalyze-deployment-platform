"""GUG-543 — validation expressions that can never pass must not come back.

Two Terraform behaviors made identity-control-plane and edge-identity
impossible to plan with real inputs:

* base64decode() rejects decoded bytes that are not valid UTF-8, so a check
  like can(base64decode(digest)) fails for almost every real SHA-256 digest.
* A typed list or map never equals a tuple or object literal, so
  `var.list_attribute == ["value"]` is always false.

CI does not run `terraform test`, so these static checks guard the fix.
The module runs in modules/identity-control-plane/tests/contract.tftest.hcl
cover real digests at plan time.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parent.parent
TERRAFORM_FILES = sorted(
    path
    for base in ("roots", "modules")
    for path in (REPO_ROOT / base).rglob("*.tf")
    if ".terraform" not in path.parts
)
ROOT_VALIDATIONS = sorted((REPO_ROOT / "roots").glob("*/contract_validation.tf"))


def _code_lines(path: Path) -> list[tuple[int, str]]:
    lines = []
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        code = line.split("#", 1)[0]
        if code.strip():
            lines.append((number, code))
    return lines


@pytest.mark.parametrize("path", TERRAFORM_FILES, ids=lambda path: str(path.relative_to(REPO_ROOT)))
def test_no_validation_decodes_a_digest(path: Path) -> None:
    offenders = [f"{number}: {code.strip()}" for number, code in _code_lines(path) if "base64decode(" in code]
    assert not offenders, (
        "base64decode() rejects non-UTF-8 bytes; validate digests with a canonical base64 regex instead: "
        + "; ".join(offenders)
    )


@pytest.mark.parametrize("path", ROOT_VALIDATIONS, ids=lambda path: str(path.relative_to(REPO_ROOT)))
def test_root_validations_do_not_compare_with_literals(path: Path) -> None:
    offenders = [
        f"{number}: {code.strip()}"
        for number, code in _code_lines(path)
        if re.search(r"==\s*(\[|\{|toset\(\[)", code)
    ]
    assert not offenders, (
        "typed lists and maps never equal tuple or object literals; compare with jsonencode(): "
        + "; ".join(offenders)
    )


def test_identity_digest_checks_use_the_canonical_32_byte_pattern() -> None:
    canonical = 'regex("^[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]=$"'
    root = (REPO_ROOT / "roots" / "identity-control-plane" / "contract_validation.tf").read_text(encoding="utf-8")
    module = (REPO_ROOT / "modules" / "identity-control-plane" / "variables.tf").read_text(encoding="utf-8")
    assert root.count(canonical) == 2
    assert module.count(canonical) == 2
