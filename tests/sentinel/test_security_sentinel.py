from hashlib import sha256
from pathlib import Path

import pytest

from tooling.security_sentinel import (
    AllowlistConfigurationError,
    PII_PATTERNS,
    is_allowlisted,
    load_allowlist,
    scan_file,
)
from tooling import security_sentinel


SYNTHETIC_CURP = "ABCD000101HDFXYZ09"
SYNTHETIC_CURP_HASH = sha256(SYNTHETIC_CURP.encode("utf-8")).hexdigest()


def _entry(line_pattern: str, match_hash: str = SYNTHETIC_CURP_HASH) -> str:
    return f"""allowlist:
  - path: fixtures/example.py
    line_pattern: '{line_pattern}'
    pattern_id: CURP
    match_sha256: {match_hash}
    reason: "Synthetic unit-test fixture"
    owner: security-testing
"""


def test_allowlist_requires_line_regex_and_exact_match_hash(tmp_path):
    allowlist_path = tmp_path / "allowlist.yaml"
    allowlist_path.write_text(_entry(r"identity_id="), encoding="utf-8")
    allowlist = load_allowlist(allowlist_path)
    line = f'identity_id="{SYNTHETIC_CURP}"'

    assert is_allowlisted(
        Path("fixtures/example.py"),
        "CURP",
        line,
        SYNTHETIC_CURP_HASH,
        allowlist,
    )
    assert not is_allowlisted(
        Path("fixtures/example.py"),
        "CURP",
        f'other_field="{SYNTHETIC_CURP}"',
        SYNTHETIC_CURP_HASH,
        allowlist,
    )
    assert not is_allowlisted(
        Path("fixtures/example.py"),
        "CURP",
        line,
        "0" * 64,
        allowlist,
    )


@pytest.mark.parametrize(
    "entry",
    [
        _entry("["),
        _entry(r"identity_id=", "not-a-sha256"),
        """allowlist:
  - path: fixtures/example.py
    line_pattern: 'identity_id='
    pattern_id: CURP
    reason: "Missing fingerprint"
    owner: security-testing
""",
    ],
)
def test_invalid_allowlist_entries_fail_closed(tmp_path, entry):
    allowlist_path = tmp_path / "allowlist.yaml"
    allowlist_path.write_text(entry, encoding="utf-8")

    with pytest.raises(AllowlistConfigurationError):
        load_allowlist(allowlist_path)


def test_scan_file_fingerprints_each_concrete_match(tmp_path):
    source = tmp_path / "fixture.py"
    source.write_text(
        f'first="{SYNTHETIC_CURP}" second="{SYNTHETIC_CURP}"\n',
        encoding="utf-8",
    )

    findings = scan_file(source, {"CURP": PII_PATTERNS["CURP"]})

    assert len(findings) == 2
    assert {finding[3] for finding in findings} == {
        f'first="{SYNTHETIC_CURP}" second="{SYNTHETIC_CURP}"\n'
    }
    assert {finding[4] for finding in findings} == {SYNTHETIC_CURP_HASH}


def test_repository_scan_has_no_unallowlisted_findings(monkeypatch):
    repo_root = Path(__file__).resolve().parents[2]
    monkeypatch.chdir(repo_root)

    with pytest.raises(SystemExit) as completed:
        security_sentinel.main()

    assert completed.value.code == 0
