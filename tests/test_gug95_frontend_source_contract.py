"""Fail-closed source ownership contracts for the GUG-95 frontend prerequisite."""
from __future__ import annotations

import json
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker


ROOT = Path(__file__).resolve().parents[1]
FRONTEND = ROOT / "frontend" / "scanalyze-frontend-ui"
PROVENANCE = FRONTEND / "SOURCE_PROVENANCE.v1.json"
PROVENANCE_SCHEMA = ROOT / "schemas" / "frontend-source-provenance.v1.schema.json"


def _read(path: Path) -> str:
    assert path.is_file(), f"required frontend source artifact is missing: {path}"
    return path.read_text(encoding="utf-8")


def test_frontend_source_has_closed_machine_readable_provenance() -> None:
    schema = json.loads(_read(PROVENANCE_SCHEMA))
    record = json.loads(_read(PROVENANCE))
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema, format_checker=FormatChecker()).validate(record)

    assert schema["additionalProperties"] is False
    assert record["source_commit"] == "959b52e57fc0a6f70cc57725ced3dae07a6bf2db"
    assert record["source_tree"] == "fcee267a7cce115cfe8ab377335885e03f65a821"
    assert record["verification"] == "locally_cached_remote_tracking_ref"
    assert record["live_source_verified"] is False
    assert record["target_path"] == "frontend/scanalyze-frontend-ui"
    assert record["production_authorized"] is False
    assert record["excluded_classes"] == sorted(record["excluded_classes"])


def test_frontend_import_excludes_sensitive_and_imperative_artifacts() -> None:
    forbidden_names = {
        ".env",
        "config.json",
        "deploy.sh",
        "generate_config.sh",
        "buildspec.yml",
    }
    generated_dirs = {"node_modules", "dist", "playwright-report", "test-results"}
    imported = {
        path.relative_to(FRONTEND).as_posix()
        for path in FRONTEND.rglob("*")
        if path.is_file() and not any(part in generated_dirs for part in path.parts)
    }

    assert not {Path(path).name for path in imported} & forbidden_names
    assert not any(path.startswith("scanalyze_edge_auth_gate_") for path in imported)
    assert not any(path.endswith((".log", ".har", ".pem", ".key")) for path in imported)


def test_frontend_runtime_config_is_v2_only_and_fail_closed() -> None:
    source = "\n".join(
        (
            _read(FRONTEND / "src" / "config" / "index.ts"),
            _read(FRONTEND / "src" / "config" / "runtime.js"),
        )
    )

    for forbidden in (
        "import.meta.env",
        "localhost",
        "falling back",
        "VITE_",
    ):
        assert forbidden not in source

    for required in (
        "schema_version",
        "identity_values_authoritative",
        "allowed_token_uses",
        "policy_digest",
        "customer_id",
        "deployment_id",
    ):
        assert required in source


def test_frontend_package_exposes_one_reproducible_local_gate() -> None:
    package = json.loads(_read(FRONTEND / "package.json"))

    assert package["engines"]["node"] == ">=22.12.0 <26"
    assert package["scripts"]["check"] == (
        "npm run typecheck && npm run lint && npm run test:unit && npm run build"
    )
    assert package["scripts"]["test:e2e"] == "playwright test"
    assert package["scripts"]["audit"] == "npm audit --audit-level=low"


def test_frontend_ci_is_static_and_clean_clone_reproducible() -> None:
    pr_workflow = _read(ROOT / ".github" / "workflows" / "pr-validation.yml")
    repro_workflow = _read(ROOT / ".github" / "workflows" / "repro-check.yml")
    makefile = _read(ROOT / "Makefile")

    for source in (pr_workflow, repro_workflow):
        assert "actions/setup-node@" in source
        assert "npm ci" in source
        assert "npm run check" in source
        assert "npm run audit" in source

    assert "frontend-check:" in makefile
    assert "npm ci" in makefile
    assert "npm run check" in makefile
    assert "npm run audit" in makefile


def test_frontend_source_has_no_remote_page_assets_or_request_logging() -> None:
    index = _read(FRONTEND / "index.html")
    stylesheets = "\n".join(
        path.read_text(encoding="utf-8") for path in sorted((FRONTEND / "src").rglob("*.css"))
    )
    tests = "\n".join(
        path.read_text(encoding="utf-8") for path in sorted((FRONTEND / "tests").glob("*.ts"))
    )

    assert "https://" not in index
    assert "@import url(" not in stylesheets
    assert "vite.svg" not in index
    assert "page.on('request'" not in tests
    assert "page.on('response'" not in tests
    assert "BROWSER CONSOLE" not in tests


def test_frontend_external_effects_use_closed_browser_boundaries() -> None:
    source_files = sorted((FRONTEND / "src").rglob("*.ts*")) + sorted(
        (FRONTEND / "src").rglob("*.js")
    )
    sources = {path: path.read_text(encoding="utf-8") for path in source_files}
    combined = "\n".join(sources.values())
    boundary = FRONTEND / "src" / "security" / "browserBoundaries.js"

    assert "requireHttpsUrl(instruction.url)" in combined
    assert "auth.user?.access_token" not in combined
    assert "window.open(" in sources[boundary]
    assert sum(text.count("window.open(") for text in sources.values()) == 1
    assert "FORMULA_PREFIX" in sources[boundary]
    assert "noopener,noreferrer" in sources[boundary]
