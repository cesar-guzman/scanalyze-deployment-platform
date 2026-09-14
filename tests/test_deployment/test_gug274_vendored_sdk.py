"""Real pinned SDK/package integration, with no AWS clients or network effects.

Set SCANALYZE_GUG274_SDK_RUNTIME_ROOT to the explicitly provisioned locked SDK.
These tests never download dependencies or treat installed host packages as pins.
"""
from __future__ import annotations

import copy
from hashlib import sha256
from io import BytesIO
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
from zipfile import ZipFile

import pytest

from tooling.platform_authority_bootstrap_artifact_package import (
    SOURCE_PATHS, _build_bootstrap_artifact_package,
    snapshot_reviewed_sdk, validate_bootstrap_artifact_package,
    BootstrapArtifactPackageError,
)
from tooling.platform_authority_bootstrap_sdk_lock import (
    SDK_DISTRIBUTION_LOCKS, sdk_entries, validate_sdk_entries, VendoredSDKError,
)
from tooling.platform_authority_bootstrap_signed_artifact import (
    _validate_signed_archive, BootstrapSignedArtifactError,
)

ROOT = Path(__file__).resolve().parents[2]
SYNTHETIC_COMMIT = "a" * 40


@pytest.fixture(scope="module")
def real_sdk() -> dict[str, bytes]:
    explicit = os.environ.get("SCANALYZE_GUG274_SDK_RUNTIME_ROOT")
    if not explicit:
        pytest.skip("explicit authenticated SDK closure is required for integration")
    return snapshot_reviewed_sdk(source_root=ROOT, sdk_runtime_root=Path(explicit))


@pytest.fixture(scope="module")
def built(real_sdk):
    return _build_bootstrap_artifact_package(
        source_root=ROOT, source_commit=SYNTHETIC_COMMIT,
        expected_boto3_version="1.42.57", expected_botocore_version="1.42.97",
        committed_sources={path: (ROOT / path).read_bytes() for path in SOURCE_PATHS},
        sdk_sources=real_sdk,
    )


@pytest.fixture
def package(built, tmp_path: Path) -> Path:
    output = tmp_path / "package"
    output.mkdir()
    # The production validator checks the closed paths before this test extracts.
    validate_bootstrap_artifact_package(manifest=built.manifest, archive=built.archive, expected_source_commit=SYNTHETIC_COMMIT)
    with ZipFile(BytesIO(built.archive)) as archive:
        archive.extractall(output)
    return output


def _probe(package: Path, prelude: str = "", body: str = "", *, env_extra=None):
    python = shutil.which("python3.12")
    if python is None:
        pytest.skip("Python 3.12 is required for the target-runtime import probe")
    code = '''from pathlib import Path
import sys,json,socket
def no_network(*args, **kwargs):
    raise AssertionError("network is forbidden in this probe")
socket.socket.connect=no_network
root=Path(sys.argv[1]);sys.path.insert(0,str(root))
from tooling.platform_authority_bootstrap_sdk_lock import import_vendored_sdk,VendoredSDKError
entries=json.loads((root/'gug274_runtime_lock.json').read_text())['sdk_entries']
''' + prelude + "\n" + body
    return subprocess.run([python, "-I", "-S", "-B", "-c", code, str(package)],
                          env={"PATH": "/usr/bin:/bin", "LANG": "C", **(env_extra or {})},
                          text=True, capture_output=True, check=False)


def test_actual_closure_is_complete_and_deterministic(real_sdk, built):
    assert len(real_sdk) == 2133
    assert sum(map(len, real_sdk.values())) == 21460247
    assert max(map(len, real_sdk.values())) == 1256900
    assert len(SDK_DISTRIBUTION_LOCKS) == 7
    second = _build_bootstrap_artifact_package(
        source_root=ROOT, source_commit=SYNTHETIC_COMMIT,
        expected_boto3_version="1.42.57", expected_botocore_version="1.42.97",
        committed_sources={path: (ROOT / path).read_bytes() for path in reversed(SOURCE_PATHS)},
        sdk_sources=dict(reversed(list(real_sdk.items()))),
    )
    assert built.archive == second.archive
    assert built.manifest == second.manifest
    assert len(built.archive) < 32 * 1024 * 1024
    assert not any(path.endswith((".pyc", ".pyo", "/RECORD", "/INSTALLER", "/REQUESTED")) for path in real_sdk)


@pytest.mark.parametrize("defect", ["missing", "bytes", "extra", "path", "case", "duplicate", "self_hash"])
def test_sdk_manifest_rejects_substitution_under_real_pins(real_sdk, defect):
    entries = sdk_entries(real_sdk)
    if defect == "missing": entries.pop()
    elif defect == "bytes": entries[0]["sha256"] = "0" * 64
    elif defect == "extra": entries.append({"path": "botocore/foreign.py", "sha256": "0" * 64, "size_bytes": 1})
    elif defect == "path": entries[0]["path"] = "../" + entries[0]["path"]
    elif defect == "case": entries[0]["path"] = entries[0]["path"].upper()
    elif defect == "duplicate": entries.insert(0, copy.deepcopy(entries[0]))
    else:
        entries[0]["sha256"] = sha256(b"self-rehashed foreign code").hexdigest()
        entries[0]["size_bytes"] = len(b"self-rehashed foreign code")
    with pytest.raises(VendoredSDKError): validate_sdk_entries(entries)


def test_python312_cold_warm_and_all_five_service_models(package):
    result = _probe(package, body='''boto3,botocore,Config=import_vendored_sdk(package_root=root,entries=entries)
assert (boto3.__version__,botocore.__version__)==('1.42.57','1.42.97')
assert import_vendored_sdk(package_root=root,entries=entries)[0] is boto3
from botocore.session import Session
session=Session()
for service in ('dynamodb','sso-oidc','sts','cloudformation','s3control'):
    assert session.get_service_model(service).service_name==service
assert import_vendored_sdk(package_root=root,entries=entries)[0] is boto3
assert Path(boto3.__file__).is_relative_to(root)
print('COLD_WARM_MODELS_PASS')
''')
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "COLD_WARM_MODELS_PASS"


def test_runtime_authority_loads_real_lock_and_same_vendored_sdk(package):
    result = _probe(package, body='''from types import SimpleNamespace
from tooling.platform_authority_bootstrap_artifact_authority import _validate_runtime_lock
# Exactly the config fields consumed by the real lock validator; no provider
# binding or client is needed to verify this production wiring.
config=SimpleNamespace(source_commit='a'*40,expected_boto3_version='1.42.57',expected_botocore_version='1.42.97')
runtime_entries=_validate_runtime_lock(config)
assert len(runtime_entries)==2133 and runtime_entries==entries
boto3,botocore,_=import_vendored_sdk(package_root=root,entries=runtime_entries)
assert (boto3.__version__,botocore.__version__)==('1.42.57','1.42.97')
assert import_vendored_sdk(package_root=root,entries=_validate_runtime_lock(config))[0] is boto3
''')
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize("name", ["boto3", "botocore.session", "brotli", "certifi", "backports"])
def test_authentic_looking_preloaded_module_is_rejected(package, name):
    result = _probe(package, prelude=f'''from types import ModuleType
from importlib.machinery import ModuleSpec
fake=ModuleType({name!r});fake.__file__=str(root/'boto3/__init__.py')
fake.__spec__=ModuleSpec({name!r},loader=None,origin=fake.__file__)
sys.modules[{name!r}]=fake
''', body='''try: import_vendored_sdk(package_root=root,entries=entries)
except VendoredSDKError as exc: assert str(exc)=='SDK_MODULE_PRELOADED_FORBIDDEN'
else: raise AssertionError('preloaded module accepted')
''')
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize("defect", ["removed", "changed", "symlink", "pyc"])
def test_bad_disk_closure_rejected_before_sdk_code(package, defect):
    candidate = package / "boto3/__init__.py"
    if defect == "removed": candidate.unlink()
    elif defect == "changed": candidate.write_bytes(b"raise AssertionError('foreign SDK executed')\n")
    elif defect == "symlink":
        candidate.unlink();candidate.symlink_to(package / "six.py")
    else:
        (package / "boto3/foreign.pyc").write_bytes(b"not source authority")
    result = _probe(package, body='''try: import_vendored_sdk(package_root=root,entries=entries)
except (VendoredSDKError,OSError): pass
else: raise AssertionError('bad closure accepted')
assert 'boto3' not in sys.modules
''')
    assert result.returncode == 0, result.stderr


def test_foreign_optional_modules_never_execute(package, tmp_path):
    foreign = tmp_path / "foreign";foreign.mkdir()
    for name in ("brotli", "brotlicffi", "certifi", "awscrt", "backports"):
        (foreign / (name + ".py")).write_text("raise AssertionError('foreign optional dependency executed')\n")
    result = _probe(package, prelude=f"sys.path.insert(0,{str(foreign)!r})", body='''import_vendored_sdk(package_root=root,entries=entries)
assert not {'brotli','brotlicffi','certifi','awscrt','backports'} & set(sys.modules)
''')
    assert result.returncode == 0, result.stderr


def test_plugin_override_fails_before_import(package):
    result = _probe(package, body='''try: import_vendored_sdk(package_root=root,entries=entries)
except VendoredSDKError as exc: assert str(exc)=='SDK_PLUGIN_OVERRIDE_FORBIDDEN'
else: raise AssertionError('plugin override accepted')
assert 'boto3' not in sys.modules
''', env_extra={"BOTOCORE_EXPERIMENTAL__PLUGINS": "foreign.module"})
    assert result.returncode == 0, result.stderr


def test_warm_module_replacement_breaks_custody(package):
    result = _probe(package, body='''boto3,_,_=import_vendored_sdk(package_root=root,entries=entries)
from types import ModuleType
replacement=ModuleType('boto3');replacement.__dict__.update(boto3.__dict__)
sys.modules['boto3']=replacement
try: import_vendored_sdk(package_root=root,entries=entries)
except VendoredSDKError as exc: assert str(exc)=='SDK_MODULE_CUSTODY_INVALID'
else: raise AssertionError('replaced warm module accepted')
''')
    assert result.returncode == 0, result.stderr


def test_warm_plugin_context_is_rejected(package):
    result = _probe(package, body='''import_vendored_sdk(package_root=root,entries=entries)
from botocore.plugin import PluginContext,set_plugin_context
set_plugin_context(PluginContext(plugins='example=foreign.module'))
try: import_vendored_sdk(package_root=root,entries=entries)
except VendoredSDKError as exc: assert str(exc)=='SDK_PLUGIN_CONTEXT_FORBIDDEN'
else: raise AssertionError('programmatic plugin context accepted')
''')
    assert result.returncode == 0, result.stderr


def test_collector_accepts_full_signed_byte_closure(built):
    signed = built.archive + b"SYNTHETIC-SIGNER-FOOTER"
    digest, _ = _validate_signed_archive(unsigned_manifest=built.manifest, signed_archive=signed)
    assert digest == sha256(signed).hexdigest()


def test_collector_rejects_size_lie_before_decompression(built, monkeypatch):
    altered = bytearray(built.archive)
    index = altered.index(b"PK\x01\x02")
    struct.pack_into("<I", altered, index + 24, 0x7fffffff)
    monkeypatch.setattr(ZipFile, "read", lambda *_: pytest.fail("read before central-directory size validation"))
    with pytest.raises(BootstrapSignedArtifactError, match="ENTRY_UNSAFE"):
        _validate_signed_archive(unsigned_manifest=built.manifest, signed_archive=bytes(altered))


def test_v2_manifest_schema_and_semantics(built):
    from jsonschema import Draft202012Validator
    from tooling.validate_schema import _validate_gug274_artifact_package_v2
    schema=json.loads((ROOT/'schemas/platform-authority-bootstrap-artifact-package.v2.schema.json').read_text())
    Draft202012Validator(schema).validate(built.manifest)
    assert _validate_gug274_artifact_package_v2(built.manifest) == []
