#!/usr/bin/env python3
"""Fail-closed structural and portability checks for monorepo microservices."""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path


EXPECTED_SERVICES = (
    "ingest-api",
    "ocr-worker",
    "postprocess-worker",
    "classifier-worker",
    "bank-worker",
    "personal-worker",
    "gov-worker",
)

TEXT_SUFFIXES = {".md", ".py", ".sh", ".txt", ".toml", ".yaml", ".yml"}
FORBIDDEN_DIRECTORY_NAMES = {
    ".git",
    ".terraform",
    ".venv",
    "__pycache__",
    "build",
    "coverage",
    "dist",
    "logs",
    "node_modules",
    "venv",
}
FORBIDDEN_FILE_NAMES = {
    ".DS_Store",
    "tfplan",
    "tfplan.bin",
}
FORBIDDEN_SUFFIXES = {
    ".7z",
    ".crt",
    ".key",
    ".p12",
    ".pem",
    ".tfplan",
    ".tfstate",
    ".zip",
}
REQUIRED_DOCKERIGNORE_ENTRIES = {
    ".env",
    ".env.*",
    "**/.env",
    "**/.env.*",
    ".aws/",
    "**/.aws/",
    ".git",
    ".terraform/",
    ".venv/",
    ".generated/",
    "__pycache__/",
    "*.key",
    "*.pem",
    "**/*.key",
    "**/*.pem",
    "*.tfplan",
    "*.tfstate",
    "customer-documents/",
    "credentials",
    "**/credentials",
    "dumps/",
    "raw-documents/",
    "tests/",
    "uploads/",
}

HARDCODE_PATTERNS = {
    "account-specific ECR URI": re.compile(
        r"\b[0-9]{12}\.dkr\.ecr\.[a-z0-9-]+\.amazonaws\.com\b"
    ),
    "client-specific identifier": re.compile(r"\bbcm-corp\b", re.IGNORECASE),
}
PRODUCTION_REGION_PATTERN = re.compile(
    r"\b(?:af|ap|ca|cn|eu|il|me|mx|sa|us)(?:-gov)?-[a-z]+-[0-9]\b"
)
PRODUCTION_CONFIG_DEFAULT_PATTERN = re.compile(
    r"os\.(?:getenv|environ\.get)\(\s*['\"]SCANALYZE_(?:ENV|TENANT|TENANTS)['\"]"
    r"\s*,\s*['\"][^'\"]+['\"]"
)
PRODUCTION_DEPLOYMENT_LABEL_PATTERN = re.compile(r"\b(?:bcm-corp|demo)\b", re.IGNORECASE)
NUMBERED_DUPLICATE_PATTERN = re.compile(r" [0-9]+(?:\.[^/]+)?$")


def add_error(errors: list[str], path: Path, message: str) -> None:
    errors.append(f"{path.as_posix()}: {message}")


def is_production_source(path: Path, service_dir: Path) -> bool:
    relative = path.relative_to(service_dir)
    if "tests" in relative.parts:
        return False
    if path.suffix == ".md":
        return False
    return any(part in {"app", "src", "scripts"} for part in relative.parts)


def check_dockerfile(path: Path, errors: list[str]) -> None:
    text = path.read_text(encoding="utf-8")
    meaningful_lines = [
        line.strip()
        for line in text.splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]

    if len(meaningful_lines) < 2:
        add_error(errors, path, "Dockerfile is incomplete")
        return
    if meaningful_lines[0] != "ARG BASE_IMAGE":
        add_error(errors, path, "first instruction must be fail-closed ARG BASE_IMAGE")
    if meaningful_lines[1] != "FROM ${BASE_IMAGE}":
        add_error(errors, path, "FROM must consume the explicit BASE_IMAGE argument")
    from_lines = [
        line
        for line in meaningful_lines
        if re.match(r"(?i)^FROM(?:\s|$)", line)
    ]
    if from_lines != ["FROM ${BASE_IMAGE}"]:
        add_error(errors, path, "Dockerfile must contain exactly one parameterized FROM")
    if re.search(r"(?im)^\s*FROM\s+.+:latest(?:\s|$)", text):
        add_error(errors, path, "mutable latest base image is forbidden")

    users = re.findall(r"(?im)^\s*USER\s+([^\s#]+)", text)
    if not users or users[-1].lower() in {"0", "root"}:
        add_error(errors, path, "final runtime user must be non-root")


def check_dockerignore(path: Path, errors: list[str]) -> None:
    active_lines = [
        line.strip()
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
    if any(line.startswith("!") for line in active_lines):
        add_error(errors, path, "negated exclusions are forbidden in service build contexts")
    entries = set(active_lines)
    missing = sorted(REQUIRED_DOCKERIGNORE_ENTRIES - entries)
    if missing:
        add_error(
            errors,
            path,
            "missing required exclusions: " + ", ".join(missing),
        )


def main() -> int:
    repo_root = Path(__file__).resolve().parent.parent
    workers_root = repo_root / "backend" / "workers"
    errors: list[str] = []

    try:
        ignored_output = subprocess.run(
            [
                "git",
                "ls-files",
                "--others",
                "--ignored",
                "--exclude-standard",
                "-z",
                "--",
                "backend/workers",
            ],
            cwd=repo_root,
            check=True,
            capture_output=True,
        ).stdout
    except (OSError, subprocess.CalledProcessError) as exc:
        print(f"FAIL: unable to inventory ignored worker artifacts: {type(exc).__name__}")
        return 1
    ignored_files = {
        item.decode("utf-8", errors="surrogateescape")
        for item in ignored_output.split(b"\0")
        if item
    }

    if not workers_root.is_dir():
        print("FAIL: backend/workers does not exist")
        return 1

    expected_directories = {f"scanalyze-{service}" for service in EXPECTED_SERVICES}
    actual_directories = {path.name for path in workers_root.iterdir() if path.is_dir()}
    for missing in sorted(expected_directories - actual_directories):
        add_error(errors, workers_root / missing, "expected service directory is missing")
    for unexpected in sorted(actual_directories - expected_directories):
        add_error(errors, workers_root / unexpected, "unexpected service directory")

    for service in EXPECTED_SERVICES:
        service_dir = workers_root / f"scanalyze-{service}"
        if not service_dir.is_dir():
            continue

        required_paths = (
            service_dir / "Dockerfile",
            service_dir / ".dockerignore",
            service_dir / "requirements.txt",
            service_dir / "tests",
        )
        for required_path in required_paths:
            if not required_path.exists():
                add_error(errors, required_path, "required service artifact is missing")

        dockerfile = service_dir / "Dockerfile"
        dockerignore = service_dir / ".dockerignore"
        if dockerfile.is_file():
            check_dockerfile(dockerfile, errors)
        if dockerignore.is_file():
            check_dockerignore(dockerignore, errors)

        for path in sorted(service_dir.rglob("*")):
            service_relative = path.relative_to(service_dir)
            relative = path.relative_to(repo_root)
            if any(
                part in FORBIDDEN_DIRECTORY_NAMES
                for part in service_relative.parts
            ):
                if (path.is_file() or path.is_symlink()) and relative.as_posix() not in ignored_files:
                    add_error(
                        errors,
                        relative,
                        "trackable artifact is nested in a forbidden directory",
                    )
                continue

            if path.is_symlink():
                add_error(errors, relative, "symbolic links are not allowed in build contexts")
                continue

            if path.is_dir():
                continue

            if path.name.startswith(".env"):
                add_error(errors, relative, "environment file is forbidden")
            if path.name in FORBIDDEN_FILE_NAMES:
                add_error(errors, relative, "generated artifact is forbidden")
            if path.suffix.lower() in FORBIDDEN_SUFFIXES:
                add_error(errors, relative, "archive, key, or Terraform artifact is forbidden")
            if ".tfstate." in path.name:
                add_error(errors, relative, "Terraform state derivative is forbidden")
            if NUMBERED_DUPLICATE_PATTERN.search(path.name):
                add_error(errors, relative, "numbered duplicate artifact is forbidden")

            if path.name != "Dockerfile" and path.suffix.lower() not in TEXT_SUFFIXES:
                continue
            try:
                text = path.read_text(encoding="utf-8")
            except UnicodeDecodeError:
                add_error(errors, relative, "expected text file is not valid UTF-8")
                continue

            for rule, pattern in HARDCODE_PATTERNS.items():
                if pattern.search(text):
                    add_error(errors, relative, rule)
            if is_production_source(path, service_dir):
                if PRODUCTION_REGION_PATTERN.search(text):
                    add_error(errors, relative, "production AWS region must be injected")
                if PRODUCTION_CONFIG_DEFAULT_PATTERN.search(text):
                    add_error(errors, relative, "deployment identity must not have a nonempty default")
                if PRODUCTION_DEPLOYMENT_LABEL_PATTERN.search(text):
                    add_error(errors, relative, "deployment/customer label must be injected")

    if errors:
        print("Microservice policy check failed:")
        for error in errors:
            print(f"  - {error}")
        print(f"FAIL: {len(errors)} finding(s)")
        return 1

    print("PASS: 7/7 microservices satisfy monorepo portability and safety policy")
    return 0


if __name__ == "__main__":
    sys.exit(main())
