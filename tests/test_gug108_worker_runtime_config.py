"""GUG-108 — the six workers share one environment runtime-config contract.

Each worker keeps its own copy of the helpers that read configuration from
SCANALYZE_CONFIG_<KEY> variables (ADR-001). These offline checks fail if the
copies drift, so Terraform can rely on a single naming rule.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parent.parent
WORKERS = REPO_ROOT / "backend" / "workers"
WORKER_CONFIGS = {
    "ocr-worker": WORKERS / "scanalyze-ocr-worker" / "src" / "ocr_worker" / "config.py",
    "classifier-worker": WORKERS / "scanalyze-classifier-worker" / "src" / "classifier_worker" / "config.py",
    "postprocess-worker": WORKERS / "scanalyze-postprocess-worker" / "src" / "postprocess_worker" / "config.py",
    "bank-worker": WORKERS / "scanalyze-bank-worker" / "src" / "bank_worker" / "config.py",
    "personal-worker": WORKERS / "scanalyze-personal-worker" / "src" / "personal_worker" / "config.py",
    "gov-worker": WORKERS / "scanalyze-gov-worker" / "src" / "gov_worker" / "config.py",
}
DOMAIN_WORKERS = {"bank-worker": "bank", "personal-worker": "personal", "gov-worker": "gov"}

SHARED_BLOCK = re.compile(r'RUNTIME_CONFIG_SOURCE_ENV = .*?\n    return value\.strip\(\)\n', re.S)


def _shared_block(service: str) -> str:
    match = SHARED_BLOCK.search(WORKER_CONFIGS[service].read_text(encoding="utf-8"))
    assert match, f"{service} lacks the environment runtime-config helpers"
    return match.group(0)


def test_every_worker_carries_the_same_helpers() -> None:
    blocks = {service: _shared_block(service) for service in WORKER_CONFIGS}
    reference = blocks["ocr-worker"]
    drifted = sorted(service for service, block in blocks.items() if block != reference)
    assert not drifted, f"environment runtime-config helpers drifted in: {drifted}"


def test_the_shared_contract_names_and_mapping() -> None:
    block = _shared_block("ocr-worker")
    assert 'RUNTIME_CONFIG_SOURCE_ENV = "SCANALYZE_RUNTIME_CONFIG_SOURCE"' in block
    assert 'RUNTIME_CONFIG_ENV_PREFIX = "SCANALYZE_CONFIG_"' in block
    assert 'PLATFORM_ROUTING_CONTEXT = "platform"' in block
    assert re.search(r'LEGACY_TENANT_SETTINGS = \("SCANALYZE_TENANT", "SCANALYZE_TENANTS", "SCANALYZE_PARAM_ROOT"\)', block)
    assert 're.sub(r"[^A-Z0-9]", "_", key.upper())' in block
    assert 'source = os.environ.get(RUNTIME_CONFIG_SOURCE_ENV, "ssm")' in block


@pytest.mark.parametrize("service", sorted(WORKER_CONFIGS))
def test_environment_mode_refuses_legacy_tenant_settings(service: str) -> None:
    source = WORKER_CONFIGS[service].read_text(encoding="utf-8")
    assert re.search(
        r'if self\.source == "environment":\n\s+reject_legacy_tenant_settings\(\)', source
    ), f"{service} must reject the legacy tenant settings in environment mode"


@pytest.mark.parametrize("service", sorted(DOMAIN_WORKERS))
def test_domain_workers_bind_their_processing_domain(service: str) -> None:
    source = WORKER_CONFIGS[service].read_text(encoding="utf-8")
    assert f'self.tenant = require_processing_domain("{DOMAIN_WORKERS[service]}")' in source


RUNTIME_WIRING_TF = REPO_ROOT / "modules" / "services" / "runtime_wiring.tf"
DATA_FOUNDATION_LOCALS = REPO_ROOT / "modules" / "data-foundation" / "locals.tf"
# config.get("key") or config.get(tenant, "key") with no default: the worker
# cannot start or process without it.
REQUIRED_KEY = re.compile(r'config\.get\(\s*(?:tenant\s*,\s*)?["\']([^"\']+)["\']\s*\)')


def _env_name(key: str) -> str:
    return "SCANALYZE_CONFIG_" + re.sub(r"[^A-Z0-9]", "_", key.upper())


def _required_keys(service: str) -> set[str]:
    source_root = WORKER_CONFIGS[service].parent
    keys: set[str] = set()
    for path in source_root.rglob("*.py"):
        text = path.read_text(encoding="utf-8")
        keys |= set(REQUIRED_KEY.findall(text))
        if 'config.get(f"queues/{route}_url")' in text:
            keys |= {f"queues/{route}_url" for route in ("bank-extract", "personal-extract", "gov-extract")}
    return keys


def _terraform_worker_variables() -> set[str]:
    wiring = RUNTIME_WIRING_TF.read_text(encoding="utf-8")
    names = set(re.findall(r'name = "([A-Z][A-Z0-9_]*)"', wiring))
    stages = re.findall(r'^\s*"?([a-z-]+)"?\s*=\s*\{\s*$', DATA_FOUNDATION_LOCALS.read_text(encoding="utf-8"), re.M)
    stages = [stage for stage in stages if stage not in ("queue_topology",)]
    assert {"ingest", "validate", "notify"} <= set(stages)
    names |= {f"SCANALYZE_CONFIG_QUEUES_{stage.upper().replace('-', '_')}_URL" for stage in stages}
    assert 'name  = "SCANALYZE_CONFIG_QUEUES_${upper(replace(stage, "-", "_"))}_URL"' in wiring
    return names


@pytest.mark.parametrize("service", sorted(WORKER_CONFIGS))
def test_terraform_injects_every_key_the_worker_requires(service: str) -> None:
    required = {_env_name(key) for key in _required_keys(service)}
    assert required, f"no required configuration keys found for {service}"
    missing = sorted(required - _terraform_worker_variables())
    assert not missing, f"{service} requires configuration Terraform does not inject: {missing}"
