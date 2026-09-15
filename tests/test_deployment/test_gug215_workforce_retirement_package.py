"""Offline package v2 tests; no Git process, AWS, SDK or credential objects.

Synthetic commit values are test inputs, never proof of a reviewed commit.
Only the Git subprocess I/O is substituted in writer/CLI integration tests.
"""
from __future__ import annotations

import base64
import copy
from hashlib import sha256
import importlib.util
from io import BytesIO
import json
from pathlib import Path
import stat
import subprocess
import sys
from types import SimpleNamespace
from zipfile import ZIP_STORED, ZipFile

import pytest
from jsonschema import Draft202012Validator

from tooling import platform_authority_change_set_retirement_package as package


ROOT = Path(__file__).resolve().parents[2]
SYNTHETIC_COMMIT = "a" * 40
RUNTIME = "arn:aws:lambda:us-east-1::runtime:" + "b" * 64
LEGACY_BINDING = "sha256:" + "c" * 64
MODE = package.WORKFORCE_AUTHORIZATION_MODE
SCHEMA = ROOT / "schemas/platform-authority-change-set-retirement-package-manifest.v2.schema.json"


@pytest.fixture
def sources():
    # Source bytes only; no import or execution of the runtime or proof modules.
    return {path: (ROOT / path).read_bytes() for path in package.WORKFORCE_SOURCE_PATHS}


def build(sources, **overrides):
    kwargs = {"source_root": ROOT, "source_commit": SYNTHETIC_COMMIT,
        "broker_runtime_version_arn": RUNTIME, "committed_sources": sources,
        "authorization_mode": MODE}
    kwargs.update(overrides)
    return package.build_retirement_package(**kwargs)


def validate(manifest, archive=None):
    package.validate_retirement_package_manifest(manifest, archive=archive, authorization_mode=MODE)


def rehash(manifest):
    manifest["manifest_digest"] = package.canonical_digest({k: v for k, v in manifest.items() if k != "manifest_digest"})
    return manifest


def test_deterministic_v2_is_unsigned_source_and_has_real_runtime_contract(sources):
    one, two = build(sources), build(sources)
    assert one == two
    manifest = one.manifest
    validate(manifest, one.archive)
    validator = Draft202012Validator(json.loads(SCHEMA.read_text()))
    validator.check_schema(validator.schema)
    validator.validate(manifest)
    assert manifest["schema_version"] == 2 and manifest["authorization_mode"] == MODE
    assert manifest["artifact_stage"] == "UNSIGNED_SOURCE_NOT_DEPLOYABLE"
    assert manifest["configuration_binding_status"] == "CONFIGURATION_BINDING_PENDING_SIGNED_ARTIFACT"
    assert manifest["signed_artifact_binding"] is None
    assert manifest["human_authentication_evidence"] == "NOT_COLLECTED"
    assert manifest["source_and_ci_evidence"] == "NOT_ATTESTED_BY_MANIFEST"
    assert manifest["deployment_authorized"] is False and manifest["production_status"] == "NO-GO"
    assert manifest["independent_approval_present"] is False and manifest["two_human_status"] == "NOT_PROVEN"
    assert "broker_version_binding_sha256" not in manifest
    contract = manifest["runtime_configuration_contract"]
    assert contract["handler"] == package.HANDLER
    assert contract["configuration_environment_key"] == "GUG215_WORKFORCE_CONFIG_B64Z"
    assert contract["configuration_requires_signed_code_sha256"] is True
    assert contract["configuration_schema_version"] == "2"
    assert contract["function_version_source"] == "PROVIDER_LAMBDA_CONTEXT_NUMERIC_ARN"
    assert contract["deployed_stage_verification"] == "EDITABLE_AND_STAGE_EXPORT_EXACT_NUMERIC_VERSION"
    assert contract["configuration_validator"].endswith(".WorkforceRetirementConfig")
    with ZipFile(BytesIO(one.archive)) as archive:
        assert archive.namelist() == [path.as_posix() for path in package.WORKFORCE_SOURCE_PATHS]
        assert len(archive.infolist()) == 8
        for info in archive.infolist():
            assert archive.read(info.filename) == sources[Path(info.filename)]
            assert info.compress_type == ZIP_STORED and info.date_time == package.FIXED_ZIP_TIMESTAMP


def test_default_v1_manifest_and_zip_contract_are_unchanged(sources):
    defaults = dict(source_root=ROOT, source_commit=SYNTHETIC_COMMIT, broker_runtime_version_arn=RUNTIME,
                    broker_version_binding_sha256=LEGACY_BINDING,
                    committed_sources={p: sources[p] for p in package.SOURCE_PATHS})
    implicit = package.build_retirement_package(**defaults)
    explicit = package.build_retirement_package(**defaults, authorization_mode=package.AUTHORIZATION_MODE)
    assert implicit == explicit
    with ZipFile(BytesIO(implicit.archive)) as archive:
        assert archive.namelist() == [path.as_posix() for path in package.SOURCE_PATHS]
        assert len(archive.infolist()) == 7
    assert implicit.archive != build(sources).archive
    assert set(implicit.manifest) == {"artifact_type", "schema_version", "work_package", "authorization_mode",
        "two_human_status", "independent_approval_present", "production", "source_commit", "archive_name", "archive_format",
        "archive_sha256", "lambda_code_sha256", "archive_size_bytes", "handler", "runtime", "architecture",
        "runtime_dependency_mode", "broker_runtime_version_arn_digest", "broker_version_binding_sha256", "entries",
        "deployment_authorized", "production_status", "manifest_digest"}
    assert implicit.manifest["schema_version"] == 1
    assert implicit.manifest["authorization_mode"] == "SINGLE_OPERATOR_NONPROD_EXCEPTION"
    assert implicit.manifest["broker_version_binding_sha256"] == LEGACY_BINDING
    assert implicit.manifest["production"] is False
    package.validate_retirement_package_manifest(implicit.manifest, archive=implicit.archive)
    Draft202012Validator(json.loads((ROOT / package.PROVENANCE_PATHS[0]).read_text())).validate(implicit.manifest)


def test_existing_consumers_reject_v2_without_explicit_opt_in(sources):
    built = build(sources)
    with pytest.raises(package.RetirementPackageError):
        package.validate_retirement_package_manifest(built.manifest, archive=built.archive)


@pytest.mark.parametrize("field,value", [
    ("deployment_authorized", True), ("production", True), ("production_status", "GO"),
    ("independent_approval_present", True), ("two_human_status", "PROVEN"),
    ("human_authentication_evidence", "STS_EVALUATED_IDENTITY_CONTEXT"),
    ("source_and_ci_evidence", "VERIFIED"), ("artifact_stage", "SIGNED_DEPLOYABLE"),
    ("configuration_binding_status", "READY"), ("signed_artifact_binding", {}),
    ("authorization_mode", package.AUTHORIZATION_MODE), ("schema_version", 1),
    ("broker_version_binding_sha256", LEGACY_BINDING), ("configuration_digest", LEGACY_BINDING),
    ("owner_verified", True), ("ci_verified", True),
])
def test_self_rehashed_promotion_or_authority_claim_is_rejected(sources, field, value):
    manifest = copy.deepcopy(build(sources).manifest)
    manifest[field] = value
    rehash(manifest)
    with pytest.raises(package.RetirementPackageError):
        validate(manifest)
    assert not Draft202012Validator(json.loads(SCHEMA.read_text())).is_valid(manifest)


def test_unsigned_code_hash_cannot_be_promoted_to_signed_configuration(sources):
    manifest = copy.deepcopy(build(sources).manifest)
    manifest["signed_artifact_binding"] = {"expected_code_sha256": manifest["lambda_code_sha256"],
                                          "archive_sha256": manifest["archive_sha256"]}
    rehash(manifest)
    with pytest.raises(package.RetirementPackageError):
        validate(manifest)
    with pytest.raises(package.RetirementPackageError, match="WORKFORCE_PRE_SIGN_BINDING_FORBIDDEN"):
        build(sources, broker_version_binding_sha256=LEGACY_BINDING)


@pytest.mark.parametrize("mode", ["workforce", "", "TWO_HUMAN", None])
def test_unknown_mode_never_falls_back(sources, mode):
    with pytest.raises(package.RetirementPackageError, match="PACKAGE_AUTHORIZATION_MODE_INVALID"):
        build(sources, authorization_mode=mode)


@pytest.mark.parametrize("runtime", [RUNTIME.replace("us-east-1", "us-west-2"),
    RUNTIME.replace("arn:aws:", "arn:aws-us-gov:"), RUNTIME.replace("::runtime:", ":042360977644:runtime:")])
def test_workforce_runtime_scope_is_exact(sources, runtime):
    with pytest.raises(package.RetirementPackageError):
        build(sources, broker_runtime_version_arn=runtime)


def test_runtime_arn_and_its_digest_must_agree(sources):
    manifest = copy.deepcopy(build(sources).manifest)
    manifest["broker_runtime_version_arn"] = RUNTIME[:-1] + "c"
    rehash(manifest)
    with pytest.raises(package.RetirementPackageError, match="PACKAGE_MANIFEST_BINDING_INVALID"):
        validate(manifest)


@pytest.mark.parametrize("path,old,new", [
    ("tooling/platform_authority_change_set_retirement_broker.py", b'WORKFORCE_RETIREMENT_MODE = "WORKFORCE_SINGLE_OWNER_RETIREMENT_V1"', b'WORKFORCE_RETIREMENT_MODE = "OTHER"'),
    ("tooling/platform_authority_change_set_retirement_broker.py", b"class WorkforceRetirementConfig:", b"class OtherConfig:"),
    ("tooling/platform_authority_change_set_retirement_broker.py", b"GUG215_WORKFORCE_CONFIG_B64Z", b"OTHER_CONFIG"),
    ("tooling/platform_authority_identity_context_pep_runtime.py", b"def _workforce_handler(", b"def _other_handler("),
    ("tooling/platform_authority_change_set_retirement_broker.py", b"def bind_lambda_context(", b"def other_context("),
    ("tooling/platform_authority_workforce_stage_binding.py", b"def verify_workforce_deployed_stage(", b"def other_stage("),
])
def test_v2_label_cannot_package_runtime_without_workforce_contract(sources, path, old, new):
    changed = dict(sources)
    assert old in changed[Path(path)]
    changed[Path(path)] = changed[Path(path)].replace(old, new)
    with pytest.raises(package.RetirementPackageError, match="WORKFORCE_RUNTIME_SOURCE_INCOMPATIBLE"):
        build(changed)


def test_exact_eight_workforce_sources_and_snapshot_bytes_are_required(sources, monkeypatch):
    for changed in ({**sources, Path("tooling/foreign.py"): b"# foreign"}, {p: b for p, b in sources.items() if p != package.SOURCE_PATHS[0]}):
        with pytest.raises(package.RetirementPackageError, match="COMMITTED_SOURCE_SET_INVALID"):
            build(changed)
    monkeypatch.setattr(package, "_read_source", lambda *_: pytest.fail("committed snapshots must not be reread"))
    assert build(sources).archive


def test_workforce_stage_dependency_is_required_and_legacy_does_not_accept_it(sources):
    legacy = {p: sources[p] for p in package.SOURCE_PATHS}
    with pytest.raises(package.RetirementPackageError, match="COMMITTED_SOURCE_SET_INVALID"):
        build(legacy)
    with pytest.raises(package.RetirementPackageError, match="COMMITTED_SOURCE_SET_INVALID"):
        package.build_retirement_package(source_root=ROOT, source_commit=SYNTHETIC_COMMIT,
            broker_runtime_version_arn=RUNTIME, broker_version_binding_sha256=LEGACY_BINDING,
            committed_sources=sources)


def test_schema_rejects_missing_stage_dependency_even_with_resealed_manifest(sources):
    manifest = copy.deepcopy(build(sources).manifest)
    manifest["entries"] = [entry for entry in manifest["entries"]
                           if entry["path"] != "tooling/platform_authority_workforce_stage_binding.py"]
    rehash(manifest)
    with pytest.raises(package.RetirementPackageError, match="PACKAGE_MANIFEST_ENTRIES_INVALID"):
        validate(manifest)
    assert not Draft202012Validator(json.loads(SCHEMA.read_text())).is_valid(manifest)


def test_archive_modified_after_manifest_is_rejected(sources):
    built = build(sources)
    with pytest.raises(package.RetirementPackageError, match="PACKAGE_ARCHIVE_DIGEST_MISMATCH"):
        validate(built.manifest, built.archive + b"extra")


@pytest.mark.parametrize("kind", ["schema_float", "nested_bool", "source_integer", "entry_integer", "entry_bool_size"])
def test_v2_python_validator_does_not_accept_json_type_substitutions(sources, kind):
    manifest = copy.deepcopy(build(sources).manifest)
    if kind == "schema_float":
        manifest["schema_version"] = 2.0
    elif kind == "nested_bool":
        manifest["runtime_configuration_contract"]["configuration_requires_signed_code_sha256"] = 1
    elif kind == "source_integer":
        manifest["source_commit"] = int("1" * 40)
    elif kind == "entry_integer":
        manifest["entries"][0]["sha256"] = int("1" * 64)
    else:
        manifest["entries"][0]["size_bytes"] = True
    rehash(manifest)
    with pytest.raises(package.RetirementPackageError):
        validate(manifest)


@pytest.mark.parametrize("mutation", ["archive_comment", "symlink_mode", "member_size", "foreign_path"])
def test_rehashed_noncanonical_zip_is_rejected(sources, mutation):
    built = build(sources)
    buffer = BytesIO()
    with ZipFile(BytesIO(built.archive)) as original, ZipFile(buffer, "w", compression=ZIP_STORED) as target:
        for i, info in enumerate(original.infolist()):
            raw = original.read(info.filename)
            if i == 0:
                if mutation == "symlink_mode":
                    info.external_attr = 0o120644 << 16
                elif mutation == "foreign_path":
                    info.filename = "../foreign.py"
                elif mutation == "member_size":
                    raw += b"synthetic-extra-bytes"
            target.writestr(info, raw)
        if mutation == "archive_comment":
            target.comment = b"synthetic-extra-metadata"
    archive = buffer.getvalue()
    manifest = copy.deepcopy(built.manifest)
    manifest["archive_sha256"] = sha256(archive).hexdigest()
    manifest["lambda_code_sha256"] = base64.b64encode(sha256(archive).digest()).decode()
    manifest["archive_size_bytes"] = len(archive)
    rehash(manifest)
    with pytest.raises(package.RetirementPackageError):
        validate(manifest, archive)


def test_oversized_manifest_member_is_rejected_before_archive_read(sources, monkeypatch):
    built = build(sources)
    manifest = copy.deepcopy(built.manifest)
    manifest["entries"][0]["size_bytes"] = package.WORKFORCE_MAX_SOURCE_BYTES + 1
    rehash(manifest)
    monkeypatch.setattr(package.ZipFile, "read", lambda *_: pytest.fail("must reject declared member size before read"))
    with pytest.raises(package.RetirementPackageError):
        validate(manifest, built.archive)


@pytest.mark.parametrize("location", ["prefix", "trailer"])
def test_resealed_bytes_outside_zip_entries_are_rejected(sources, location):
    built = build(sources)
    extra = b"SYNTHETIC_UNACCOUNTED_WRAPPER_BYTES"
    archive = extra + built.archive if location == "prefix" else built.archive + extra
    manifest = copy.deepcopy(built.manifest)
    manifest["archive_sha256"] = sha256(archive).hexdigest()
    manifest["lambda_code_sha256"] = base64.b64encode(sha256(archive).digest()).decode()
    manifest["archive_size_bytes"] = len(archive)
    rehash(manifest)
    # The library still reads all eight exact members; only the complete-byte
    # canonical check closes this gap, independently of the resealed hashes.
    with ZipFile(BytesIO(archive)) as wrapped:
        assert wrapped.namelist() == [path.as_posix() for path in package.WORKFORCE_SOURCE_PATHS]
        assert all(wrapped.read(path.as_posix()) == payload for path, payload in sources.items())
    with pytest.raises(package.RetirementPackageError, match="PACKAGE_ARCHIVE_NOT_CANONICAL"):
        validate(manifest, archive)


class FakeGit:
    """Only public Git protocol results; never launches a Git process."""
    def __init__(self, source):
        self.source = source
        self.blobs = {path: (source / path).read_bytes() for path in (*package.WORKFORCE_SOURCE_PATHS, *package.WORKFORCE_PROVENANCE_PATHS)}
        self.calls = []
        self.head, self.dirty = SYNTHETIC_COMMIT, ""
        self.missing = None

    def run(self, args, **kwargs):
        self.calls.append(args)
        assert args[0] == "git" and kwargs["cwd"] == self.source
        assert kwargs["check"] is True and kwargs["capture_output"] is True and kwargs["timeout"] == 30
        if args == ["git", "rev-parse", "HEAD"]:
            return SimpleNamespace(stdout=self.head + "\n")
        if args == ["git", "status", "--porcelain=v1", "--untracked-files=all"]:
            return SimpleNamespace(stdout=self.dirty)
        assert args[1] == "show" and args[2].startswith(SYNTHETIC_COMMIT + ":")
        path = Path(args[2].split(":", 1)[1])
        if path == self.missing:
            raise subprocess.CalledProcessError(1, args)
        return SimpleNamespace(stdout=self.blobs[path])


@pytest.fixture
def checkout(tmp_path, monkeypatch):
    source = tmp_path / "public-source-fixture"
    source.mkdir(mode=0o700)
    for path in (*package.WORKFORCE_SOURCE_PATHS, *package.WORKFORCE_PROVENANCE_PATHS):
        dest = source / path
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes((ROOT / path).read_bytes())
    git = FakeGit(source)
    monkeypatch.setattr(package.subprocess, "run", git.run)
    return source, git, tmp_path / "unsigned-output"


def write(source, output, **overrides):
    kwargs = dict(source_root=source, source_commit=SYNTHETIC_COMMIT, broker_runtime_version_arn=RUNTIME,
                  output_directory=output, authorization_mode=MODE)
    kwargs.update(overrides)
    return package.write_retirement_package(**kwargs)


def test_actual_writer_uses_clean_head_blobs_and_v2_provenance(checkout):
    source, git, output = checkout
    archive, manifest, record = write(source, output)
    validate(json.loads(manifest.read_bytes()), archive.read_bytes())
    assert record["source_commit"] == SYNTHETIC_COMMIT  # Input claim, never authenticated by this fake I/O.
    assert stat.S_IMODE(output.stat().st_mode) == 0o700
    assert stat.S_IMODE(archive.stat().st_mode) == stat.S_IMODE(manifest.stat().st_mode) == 0o600
    expected = [SYNTHETIC_COMMIT + ":" + path.as_posix() for path in (*package.WORKFORCE_SOURCE_PATHS, *package.WORKFORCE_PROVENANCE_PATHS)]
    assert [args[2] for args in git.calls if args[1] == "show"] == expected
    with pytest.raises(package.RetirementPackageError, match="OUTPUT_WRITE_FAILED"):
        write(source, output)


@pytest.mark.parametrize("failure,code", [("dirty", "SOURCE_TREE_DIRTY"), ("head", "SOURCE_COMMIT_MISMATCH"),
    ("hidden_drift", "PACKAGE_SOURCE_COMMIT_DRIFT"), ("missing_schema", "PACKAGE_SOURCE_NOT_IN_COMMIT")])
def test_clean_source_gate_denies_before_output_creation(checkout, failure, code):
    source, git, output = checkout
    if failure == "dirty":
        git.dirty = " M tooling/platform_authority_identity_context_pep_runtime.py\n"
    elif failure == "head":
        git.head = "d" * 40
    elif failure == "hidden_drift":
        path = source / package.WORKFORCE_PROVENANCE_PATHS[-1]
        path.write_bytes(path.read_bytes() + b"\n")
    else:
        git.missing = package.WORKFORCE_PROVENANCE_PATHS[-2]
    with pytest.raises(package.RetirementPackageError, match=code):
        write(source, output)
    assert not output.exists()


def test_default_provenance_paths_remain_legacy(checkout):
    source, git, _output = checkout
    package.verify_clean_source_commit(source_root=source, source_commit=SYNTHETIC_COMMIT)
    assert [args[2] for args in git.calls if args[1] == "show"] == [SYNTHETIC_COMMIT + ":" + path.as_posix() for path in (*package.SOURCE_PATHS, *package.PROVENANCE_PATHS)]


def load_cli():
    path = ROOT / "scripts/deployment/platform-authority-change-set-retirement-package.py"
    spec = importlib.util.spec_from_file_location("gug215_package_cli_under_test", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_cli_explicit_v2_runs_real_writer_and_emits_only_pending_source(checkout, monkeypatch, capsys):
    source, _git, output = checkout
    cli = load_cli()
    monkeypatch.setattr(cli, "ROOT", source)
    monkeypatch.setattr(sys, "argv", ["package", "--source-commit", SYNTHETIC_COMMIT,
        "--broker-runtime-version-arn", RUNTIME, "--authorization-mode", MODE, "--output-directory", str(output)])
    assert cli.main() == 0
    public = json.loads(capsys.readouterr().out)
    assert public["artifact_stage"] == "UNSIGNED_SOURCE_NOT_DEPLOYABLE"
    assert public["configuration_binding_status"] == "CONFIGURATION_BINDING_PENDING_SIGNED_ARTIFACT"
    assert public["deployment_authorized"] is False and public["signed_artifact_binding"] is None
    assert public["aws_calls_performed"] is False
    validate(json.loads((output / package.MANIFEST_NAME).read_bytes()), (output / package.ARCHIVE_NAME).read_bytes())


@pytest.mark.parametrize("flags", [[], ["--authorization-mode", MODE, "--broker-version-binding-sha256", LEGACY_BINDING],
    ["--authorization-mode", "unknown"]])
def test_cli_invalid_or_conflicting_mode_flags_fail_before_writer(monkeypatch, flags):
    cli = load_cli()
    monkeypatch.setattr(cli, "write_retirement_package", lambda **_: pytest.fail("writer must not run"))
    monkeypatch.setattr(sys, "argv", ["package", "--source-commit", SYNTHETIC_COMMIT,
        "--broker-runtime-version-arn", RUNTIME, "--output-directory", "/synthetic-output-unused", *flags])
    with pytest.raises(SystemExit) as error:
        cli.main()
    assert error.value.code == 2


def test_cli_legacy_output_fields_remain_unchanged(checkout, monkeypatch, capsys):
    source, _git, output = checkout
    cli = load_cli()
    monkeypatch.setattr(cli, "ROOT", source)
    monkeypatch.setattr(sys, "argv", ["package", "--source-commit", SYNTHETIC_COMMIT,
        "--broker-runtime-version-arn", RUNTIME, "--broker-version-binding-sha256", LEGACY_BINDING,
        "--output-directory", str(output)])
    assert cli.main() == 0
    public = json.loads(capsys.readouterr().out)
    assert set(public) == {"status", "archive_name", "manifest_name", "manifest_digest", "lambda_code_sha256",
        "authorization_mode", "two_human_status", "independent_approval_present", "deployment_authorized",
        "aws_calls_performed", "aws_mutations", "production_status"}
    assert public["authorization_mode"] == package.AUTHORIZATION_MODE
