import os
from pathlib import Path
import re
import subprocess
import sys


SERVICE_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = SERVICE_ROOT / "src"


def _requirement_lines(path: Path) -> list[str]:
    return [
        line.strip()
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]


def _locked_requirements(path: Path) -> dict[str, tuple[str, tuple[str, ...]]]:
    locked: dict[str, tuple[str, tuple[str, ...]]] = {}
    current_name: str | None = None
    current_version: str | None = None
    current_hashes: list[str] = []

    def store_current() -> None:
        if current_name is not None and current_version is not None:
            locked[current_name] = (current_version, tuple(current_hashes))

    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        normalized = line.removesuffix("\\").rstrip()
        if normalized.startswith("--hash="):
            current_hashes.append(normalized)
            continue
        store_current()
        name, version = normalized.split("==", 1)
        current_name = name
        current_version = version
        current_hashes = []
    store_current()
    return locked


def test_runtime_dependency_closure_is_locked_and_used_by_docker():
    requirements = _requirement_lines(SERVICE_ROOT / "requirements.txt")
    lock = _locked_requirements(SERVICE_ROOT / "requirements.lock")
    dockerfile = (SERVICE_ROOT / "Dockerfile").read_text(encoding="utf-8")

    assert requirements == [
        "-c requirements.lock",
        "boto3==1.43.72",
        "pydantic==2.13.4",
        "structlog==26.1.0",
    ]
    assert {name: version for name, (version, _) in lock.items()} == {
        "annotated-types": "0.8.0",
        "boto3": "1.43.72",
        "botocore": "1.43.72",
        "jmespath": "1.1.0",
        "pydantic": "2.13.4",
        "pydantic-core": "2.46.4",
        "python-dateutil": "2.9.0.post0",
        "s3transfer": "0.19.2",
        "six": "1.17.0",
        "structlog": "26.1.0",
        "typing-extensions": "4.16.0",
        "typing-inspection": "0.4.4",
        "urllib3": "2.7.0",
    }
    assert all(
        len(hashes) == 1
        and re.fullmatch(r"--hash=sha256:[0-9a-f]{64}", hashes[0])
        for _, hashes in lock.values()
    )
    assert "expected = (3, 11, 14)" in dockerfile
    assert "COPY requirements.lock ." in dockerfile
    assert "COPY .wheelhouse/ /wheelhouse/" in dockerfile
    assert "--no-index" in dockerfile
    assert "--find-links=/wheelhouse" in dockerfile
    assert "--require-hashes" in dockerfile
    assert "COPY requirements.txt" not in dockerfile
    assert 'ENTRYPOINT ["python", "-m", "classifier_worker.main"]' in dockerfile


def test_canonical_package_imports_in_isolated_python():
    environment = {
        "PATH": os.defpath,
        "AWS_SHARED_CREDENTIALS_FILE": "/dev/null",
        "AWS_CONFIG_FILE": "/dev/null",
        "AWS_EC2_METADATA_DISABLED": "true",
        "AWS_REGION": "us-east-1",
        "AWS_DEFAULT_REGION": "us-east-1",
        "SCANALYZE_ENV": "test",
        "SCANALYZE_TENANT": "tenant-test",
        "SCANALYZE_DEPLOYMENT_CUSTOMER_ID": "cust_01ARZ3NDEKTSV4RRFFQ69G5FAW",
        "SCANALYZE_DEPLOYMENT_ID": "dep_01ARZ3NDEKTSV4RRFFQ69G5FAV",
    }
    import_script = (
        f"import sys; sys.path.insert(0, {str(SRC_ROOT)!r}); "
        "import classifier_worker.main; "
        "import classifier_worker.classifier; "
        "import classifier_worker.contracts"
    )

    completed = subprocess.run(
        [sys.executable, "-I", "-c", import_script],
        cwd=SERVICE_ROOT,
        env=environment,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )

    assert completed.returncode == 0, completed.stderr
