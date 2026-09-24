from hashlib import sha256
from pathlib import Path

import pytest

from tooling.security_sentinel import (
    AllowlistConfigurationError,
    PII_PATTERNS,
    SECRET_PATTERNS,
    is_allowlisted,
    load_allowlist,
    scan_file,
    should_scan,
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


def test_generated_build_tree_is_excluded_without_excluding_source():
    assert not should_scan(Path("build/lib/tooling/generated.py"))
    assert should_scan(Path("tooling/generated.py"))


@pytest.mark.parametrize(
    "source_path",
    [
        "tooling/platform_authority_gug376_collision_direct_sso.py",
        "tooling/platform_authority_gug376_upstream_live_provider.py",
    ],
)
def test_gug376_temporary_sdk_credential_binding_is_narrowly_allowlisted(source_path):
    repo_root = Path(__file__).resolve().parents[2]
    source = repo_root / source_path
    allowlist = load_allowlist(repo_root / "sentinel_allowlist.yaml")
    findings = scan_file(source, {"AWS_SECRET_KEY": SECRET_PATTERNS["AWS_SECRET_KEY"]})

    assert len(findings) == 1
    pattern_id, _, _, line, fingerprint = findings[0]
    assert is_allowlisted(
        source.relative_to(repo_root),
        pattern_id,
        line,
        fingerprint,
        allowlist,
    )


@pytest.mark.parametrize(
    "mutation", ["path", "detector", "prefix", "suffix", "fingerprint", "reference"]
)
def test_gug432_upstream_sdk_binding_rejects_unreviewed_context(mutation):
    repo_root = Path(__file__).resolve().parents[2]
    path = Path("tooling/platform_authority_gug376_upstream_live_provider.py")
    allowlist = load_allowlist(repo_root / "sentinel_allowlist.yaml")
    findings = scan_file(
        repo_root / path, {"AWS_SECRET_KEY": SECRET_PATTERNS["AWS_SECRET_KEY"]}
    )
    assert len(findings) == 1
    pattern_id, _, _, line, fingerprint = findings[0]
    assert is_allowlisted(path, pattern_id, line, fingerprint, allowlist)

    if mutation == "path":
        path = Path("tooling/unreviewed_provider.py")
    elif mutation == "detector":
        pattern_id = "RFC"
    elif mutation == "prefix":
        line = "unreviewed " + line.lstrip()
    elif mutation == "suffix":
        line = line.rstrip() + " unreviewed\n"
    elif mutation == "fingerprint":
        fingerprint = "0" * 64
    else:
        line = line.replace("frozen.secret_key", "unreviewed.secret_key")

    assert not is_allowlisted(path, pattern_id, line, fingerprint, allowlist)


def test_gug432_upstream_sdk_binding_rejects_a_synthetic_literal(tmp_path):
    repo_root = Path(__file__).resolve().parents[2]
    path = Path("tooling/platform_authority_gug376_upstream_live_provider.py")
    patterns = {"AWS_SECRET_KEY": SECRET_PATTERNS["AWS_SECRET_KEY"]}
    allowlist = load_allowlist(repo_root / "sentinel_allowlist.yaml")
    findings = scan_file(repo_root / path, patterns)
    assert len(findings) == 1
    pattern_id, _, _, line, fingerprint = findings[0]
    assert is_allowlisted(path, pattern_id, line, fingerprint, allowlist)

    # Generate a deliberately synthetic value only in the temporary fixture.
    fixture = tmp_path / "provider.py"
    fixture.write_text(
        line.replace("frozen.secret_key", repr("synthetic" * 5)), encoding="utf-8"
    )
    literal_findings = scan_file(fixture, patterns)
    assert len(literal_findings) == 1
    literal_pattern, _, _, literal_line, literal_fingerprint = literal_findings[0]
    assert literal_fingerprint != fingerprint
    assert not is_allowlisted(
        path, literal_pattern, literal_line, literal_fingerprint, allowlist
    )


def test_gug432_upstream_sdk_binding_allowlist_has_no_secret_findings():
    repo_root = Path(__file__).resolve().parents[2]
    # Scan the rule metadata itself, without applying any allowlist exceptions.
    assert scan_file(repo_root / "sentinel_allowlist.yaml", SECRET_PATTERNS) == []


def test_repository_scan_has_no_unallowlisted_findings(monkeypatch):
    repo_root = Path(__file__).resolve().parents[2]
    monkeypatch.chdir(repo_root)

    with pytest.raises(SystemExit) as completed:
        security_sentinel.main()

    assert completed.value.code == 0


# These are public GitHub Actions identifiers, never identity-document values.
PUBLIC_VALIDATION_RUNS = (
    "35285451823",
    "34495798769",
    "34496159838",
    "34497827861",
    "34497913910",
    "35553633763",
    "35553633747",
)
VALIDATION_REPORT = Path("docs/operations/production-validation-20260921.md")
RUN_URL_PREFIX = "https://github.com/cesar-guzman/scanalyze-deployment-platform/actions/runs/"


@pytest.mark.parametrize("run_id", PUBLIC_VALIDATION_RUNS)
def test_public_validation_run_exception_accepts_only_pinned_metadata(run_id):
    allowlist = load_allowlist(Path(__file__).resolve().parents[2] / "sentinel_allowlist.yaml")
    line = f"[Workflow run]({RUN_URL_PREFIX}{run_id})."
    assert is_allowlisted(
        VALIDATION_REPORT, "NSS", line, sha256(run_id.encode()).hexdigest(), allowlist
    )


@pytest.mark.parametrize("mutation", ["value", "path", "context", "detector", "repository"])
def test_public_validation_run_exception_rejects_unreviewed_context(mutation):
    allowlist = load_allowlist(Path(__file__).resolve().parents[2] / "sentinel_allowlist.yaml")
    run_id = PUBLIC_VALIDATION_RUNS[0]
    path = VALIDATION_REPORT
    detector = "NSS"
    line = f"[Workflow run]({RUN_URL_PREFIX}{run_id})."
    if mutation == "value":
        run_id = "00000000000"  # Synthetic unmatched value, not a public run.
        line = f"[Workflow run]({RUN_URL_PREFIX}{run_id})."
    elif mutation == "path":
        path = Path("docs/operations/unreviewed.md")
    elif mutation == "context":
        line = f"identity_id={run_id}"
    elif mutation == "detector":
        detector = "RFC"
    else:
        line = line.replace("/cesar-guzman/", "/unreviewed-owner/")
    assert not is_allowlisted(
        path, detector, line, sha256(run_id.encode()).hexdigest(), allowlist
    )


def test_public_validation_run_exception_has_exact_fingerprint_set():
    allowlist = load_allowlist(Path(__file__).resolve().parents[2] / "sentinel_allowlist.yaml")
    entries = [entry for entry in allowlist if entry["path"] == VALIDATION_REPORT.as_posix()]
    assert len(entries) == 1
    assert entries[0]["pattern_id"] == "NSS"
    assert entries[0]["_match_hashes"] == {
        sha256(run_id.encode()).hexdigest() for run_id in PUBLIC_VALIDATION_RUNS
    }
