import os
from pathlib import Path
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


def test_runtime_dependency_closure_is_locked_and_used_by_docker():
    requirements = _requirement_lines(SERVICE_ROOT / "requirements.txt")
    lock = _requirement_lines(SERVICE_ROOT / "requirements.lock")
    dockerfile = (SERVICE_ROOT / "Dockerfile").read_text(encoding="utf-8")

    assert requirements == [
        "-c requirements.lock",
        "boto3==1.43.72",
        "pydantic==2.13.4",
        "structlog==26.1.0",
    ]
    assert all("==" in requirement for requirement in lock)
    assert {requirement.split("==", 1)[0] for requirement in lock} >= {
        "boto3",
        "pydantic",
        "structlog",
    }
    assert "COPY requirements.txt requirements.lock ./" in dockerfile
    assert "pip install --no-cache-dir -r requirements.txt" in dockerfile


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
        "import classifier_worker.main"
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
