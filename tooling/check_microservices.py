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
    ".wheelhouse",
    "__pycache__",
    "build",
    "coverage",
    "dist",
    "logs",
    "node_modules",
    "venv",
}
OCR_WHEELHOUSE_GITIGNORE_ENTRY = (
    "backend/workers/scanalyze-ocr-worker/.wheelhouse/"
)
OCR_WHEELHOUSE_COPY_INSTRUCTION = "COPY .wheelhouse/ /wheelhouse/"
OCR_LOCK_COPY_INSTRUCTION = "COPY requirements.lock ."
OCR_HERMETIC_SCRIPTS = (
    "prepare-ocr-wheelhouse.sh",
    "verify-ocr-container.sh",
)
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


def add_error(errors: list[str], path: Path | str, message: str) -> None:
    path_str = path.as_posix() if isinstance(path, Path) else str(path)
    errors.append(f"{path_str}: {message}")


def is_production_source(path: Path, service_dir: Path | None = None) -> bool:
    if service_dir is not None:
        relative = path.relative_to(service_dir)
    else:
        relative = path
    if "tests" in relative.parts:
        return False
    if path.suffix == ".md":
        return False
    return any(part in {"app", "src", "scripts"} for part in relative.parts)

def check_source_text(relative_path: Path, is_prod_source: bool, text: str) -> list[str]:
    errors: list[str] = []
    for rule, pattern in HARDCODE_PATTERNS.items():
        if pattern.search(text):
            add_error(errors, relative_path, rule)
    if is_prod_source:
        if PRODUCTION_REGION_PATTERN.search(text):
            add_error(errors, relative_path, "production AWS region must be injected")
        if PRODUCTION_CONFIG_DEFAULT_PATTERN.search(text):
            add_error(errors, relative_path, "deployment identity must not have a nonempty default")
        matches = list(PRODUCTION_DEPLOYMENT_LABEL_PATTERN.finditer(text))
        if matches:
            exception_applies = False
            if relative_path.as_posix() == "backend/workers/scanalyze-ocr-worker/src/ocr_worker/environment_contract.py":
                import ast
                try:
                    tree = ast.parse(text)
                    valid_demo_spans = []
                    assignment_count = 0
                    for node in tree.body:
                        if isinstance(node, ast.Assign):
                            for target in node.targets:
                                if getattr(target, "id", None) == "SUPPORTED_RUNTIME_ENVIRONMENTS":
                                    assignment_count += 1
                                    if isinstance(node.value, ast.Set):
                                        for elt in node.value.elts:
                                            if isinstance(elt, ast.Constant) and isinstance(elt.value, str) and elt.value.lower() == "demo":
                                                valid_demo_spans.append((elt.lineno, elt.col_offset, getattr(elt, "end_lineno", elt.lineno), getattr(elt, "end_col_offset", elt.col_offset)))
                    
                    if assignment_count == 1 and valid_demo_spans:
                        lines = text.splitlines(keepends=True)
                        for sl, sc, el, ec in valid_demo_spans:
                            if sl == el:
                                lines[sl - 1] = lines[sl - 1][:sc] + " " * (ec - sc) + lines[sl - 1][ec:]
                            else:
                                lines[sl - 1] = lines[sl - 1][:sc] + " " * (len(lines[sl - 1]) - sc)
                                for l in range(sl, el - 1):
                                    lines[l] = " " * len(lines[l])
                                lines[el - 1] = " " * ec + lines[el - 1][ec:]
                        masked_text = "".join(lines)
                        
                        if not PRODUCTION_DEPLOYMENT_LABEL_PATTERN.search(masked_text):
                            exception_applies = True
                except Exception:
                    pass
            if not exception_applies:
                add_error(errors, relative_path, "deployment/customer label must be injected")
    return errors


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


def logical_dockerfile_instructions(text: str) -> list[str]:
    instructions: list[str] = []
    continued_parts: list[str] = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        continued = line.endswith("\\")
        continued_parts.append(line[:-1].rstrip() if continued else line)
        if not continued:
            instructions.append(" ".join(continued_parts))
            continued_parts.clear()
    if continued_parts:
        raise ValueError("Dockerfile ends with an incomplete continued instruction")
    return instructions


def exact_requirement_pins(
    path: Path,
    *,
    repo_root: Path,
    errors: list[str],
) -> dict[str, str]:
    pins: dict[str, str] = {}
    for line_number, raw_line in enumerate(
        path.read_text(encoding="utf-8").splitlines(),
        start=1,
    ):
        line = raw_line.strip()
        if not line or line.startswith("#") or line.startswith("--hash="):
            continue
        line = line.removesuffix("\\").rstrip()
        match = re.fullmatch(r"([A-Za-z0-9_.-]+)==([^\s;\\]+)", line)
        if match is None:
            add_error(
                errors,
                path.relative_to(repo_root),
                f"line {line_number} must be an exact name==version pin",
            )
            continue
        name = re.sub(r"[-_.]+", "-", match.group(1)).lower()
        if name in pins:
            add_error(
                errors,
                path.relative_to(repo_root),
                f"duplicate requirement pin for {name}",
            )
            continue
        pins[name] = match.group(2)
    return pins


def check_lock_hash_blocks(
    path: Path,
    *,
    repo_root: Path,
    errors: list[str],
) -> None:
    current_pin: str | None = None
    current_hashes = 0

    def close_current_block() -> None:
        if current_pin is not None and current_hashes == 0:
            add_error(
                errors,
                path.relative_to(repo_root),
                f"locked requirement {current_pin} must carry at least one reviewed hash",
            )

    for line_number, raw_line in enumerate(
        path.read_text(encoding="utf-8").splitlines(),
        start=1,
    ):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        normalized = line.removesuffix("\\").rstrip()
        if normalized.startswith("--hash="):
            if current_pin is None:
                add_error(
                    errors,
                    path.relative_to(repo_root),
                    f"line {line_number} contains an orphan lock hash",
                )
            elif re.fullmatch(r"--hash=sha256:[0-9a-f]{64}", normalized) is None:
                add_error(
                    errors,
                    path.relative_to(repo_root),
                    f"line {line_number} must be a lowercase sha256 lock hash",
                )
            else:
                current_hashes += 1
            continue

        close_current_block()
        current_pin = normalized
        current_hashes = 0

    close_current_block()


def check_ocr_hermetic_contract(repo_root: Path, errors: list[str]) -> None:
    service_dir = repo_root / "backend" / "workers" / "scanalyze-ocr-worker"
    dockerfile = service_dir / "Dockerfile"
    dockerignore = service_dir / ".dockerignore"
    requirements = service_dir / "requirements.txt"
    lock_file = service_dir / "requirements.lock"
    gitignore = repo_root / ".gitignore"
    scripts_dir = repo_root / "scripts" / "microservices"

    for script_name in OCR_HERMETIC_SCRIPTS:
        script = scripts_dir / script_name
        if not script.is_file():
            add_error(errors, script.relative_to(repo_root), "required OCR hermetic script is missing")
            continue
        if script.stat().st_mode & 0o111 == 0:
            add_error(errors, script.relative_to(repo_root), "OCR hermetic script must be executable")
        script_text = script.read_text(encoding="utf-8")
        if not script_text.startswith("#!/usr/bin/env bash\n"):
            add_error(errors, script.relative_to(repo_root), "OCR hermetic script must use the Bash entrypoint")
        if "set -euo pipefail" not in script_text:
            add_error(errors, script.relative_to(repo_root), "OCR hermetic script must fail closed")

    if not gitignore.is_file():
        add_error(errors, ".gitignore", "repository ignore policy is missing")
    else:
        active_gitignore = {
            line.strip()
            for line in gitignore.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        }
        if OCR_WHEELHOUSE_GITIGNORE_ENTRY not in active_gitignore:
            add_error(
                errors,
                ".gitignore",
                f"must ignore generated {OCR_WHEELHOUSE_GITIGNORE_ENTRY}",
            )

    if dockerignore.is_file():
        active_dockerignore = [
            line.strip()
            for line in dockerignore.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        ]
        if any("wheelhouse" in line.lower() for line in active_dockerignore):
            add_error(
                errors,
                dockerignore.relative_to(repo_root),
                "OCR .wheelhouse must remain in the Docker build context",
            )

    if not requirements.is_file():
        add_error(errors, requirements.relative_to(repo_root), "OCR requirements file is missing")
    if not lock_file.is_file():
        add_error(errors, lock_file.relative_to(repo_root), "OCR lock file is missing")
    if requirements.is_file() and lock_file.is_file():
        direct_pins = exact_requirement_pins(
            requirements,
            repo_root=repo_root,
            errors=errors,
        )
        locked_pins = exact_requirement_pins(
            lock_file,
            repo_root=repo_root,
            errors=errors,
        )
        for name, version in sorted(direct_pins.items()):
            if locked_pins.get(name) != version:
                add_error(
                    errors,
                    lock_file.relative_to(repo_root),
                    f"requirements.lock must match direct requirement {name}=={version}",
                )
        check_lock_hash_blocks(
            lock_file,
            repo_root=repo_root,
            errors=errors,
        )

    if not dockerfile.is_file():
        return
    try:
        instructions = logical_dockerfile_instructions(
            dockerfile.read_text(encoding="utf-8")
        )
    except ValueError as exc:
        add_error(errors, dockerfile.relative_to(repo_root), str(exc))
        return

    wheelhouse_copies = [
        instruction
        for instruction in instructions
        if instruction == OCR_WHEELHOUSE_COPY_INSTRUCTION
    ]
    if wheelhouse_copies != [OCR_WHEELHOUSE_COPY_INSTRUCTION]:
        add_error(
            errors,
            dockerfile.relative_to(repo_root),
            f"must contain exactly one {OCR_WHEELHOUSE_COPY_INSTRUCTION}",
        )

    lock_copies = [
        instruction
        for instruction in instructions
        if instruction == OCR_LOCK_COPY_INSTRUCTION
    ]
    if lock_copies != [OCR_LOCK_COPY_INSTRUCTION]:
        add_error(
            errors,
            dockerfile.relative_to(repo_root),
            f"must contain exactly one {OCR_LOCK_COPY_INSTRUCTION}",
        )

    offline_installs = [
        instruction
        for instruction in instructions
        if instruction.upper().startswith("RUN ")
        and "pip install" in instruction
        and "requirements.lock" in instruction
    ]
    if len(offline_installs) != 1:
        add_error(
            errors,
            dockerfile.relative_to(repo_root),
            "must contain exactly one locked requirements install instruction",
        )
    else:
        install = offline_installs[0]
        has_wheelhouse_link = (
            "--find-links=/wheelhouse" in install
            or "--find-links /wheelhouse" in install
        )
        if (
            "--no-index" not in install
            or "--require-hashes" not in install
            or not has_wheelhouse_link
        ):
            add_error(
                errors,
                dockerfile.relative_to(repo_root),
                "requirements.lock must install with hashes and --no-index from /wheelhouse",
            )
        if (
            wheelhouse_copies
            and instructions.index(OCR_WHEELHOUSE_COPY_INSTRUCTION)
            > instructions.index(install)
        ):
            add_error(
                errors,
                dockerfile.relative_to(repo_root),
                "wheelhouse COPY must precede the offline requirements install",
            )
        if (
            lock_copies
            and instructions.index(OCR_LOCK_COPY_INSTRUCTION)
            > instructions.index(install)
        ):
            add_error(
                errors,
                dockerfile.relative_to(repo_root),
                "requirements.lock COPY must precede the offline install",
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

    check_ocr_hermetic_contract(repo_root, errors)

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

            prod_source = is_production_source(path, service_dir)
            source_errors = check_source_text(relative, prod_source, text)
            errors.extend(source_errors)

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
