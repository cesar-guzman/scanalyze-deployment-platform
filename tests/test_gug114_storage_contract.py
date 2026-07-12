from __future__ import annotations

import ast
import re
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
DYNAMODB_TF = REPO_ROOT / "modules" / "data-foundation" / "dynamodb.tf"
DOCUMENTS_REPOSITORY = (
    REPO_ROOT
    / "backend"
    / "workers"
    / "scanalyze-ingest-api"
    / "app"
    / "repositories"
    / "documents.py"
)
ANALYTICS_SERVICE = (
    REPO_ROOT
    / "backend"
    / "workers"
    / "scanalyze-ingest-api"
    / "app"
    / "services"
    / "analytics.py"
)


def _balanced_block(source: str, marker: str) -> str:
    start = source.index(marker)
    opening = source.index("{", start)
    depth = 0
    for position in range(opening, len(source)):
        if source[position] == "{":
            depth += 1
        elif source[position] == "}":
            depth -= 1
            if depth == 0:
                return source[start : position + 1]
    raise AssertionError(f"Unclosed HCL block for {marker!r}")


def _gsi_contracts(documents_resource: str) -> dict[str, dict[str, str]]:
    contracts: dict[str, dict[str, str]] = {}
    cursor = 0
    marker = "global_secondary_index"
    while True:
        start = documents_resource.find(marker, cursor)
        if start == -1:
            return contracts
        block = _balanced_block(documents_resource[start:], marker)
        cursor = start + len(block)
        fields = {
            key: value
            for key, value in re.findall(
                r'^\s*(name|hash_key|projection_type)\s*=\s*"([^"]+)"',
                block,
                flags=re.MULTILINE,
            )
        }
        contracts[fields["name"]] = fields


def test_documents_table_has_sparse_ownership_indexes() -> None:
    source = DYNAMODB_TF.read_text(encoding="utf-8")
    documents = _balanced_block(
        source,
        'resource "aws_dynamodb_table" "documents"',
    )

    assert 'billing_mode = "PAY_PER_REQUEST"' in documents
    for key_name in ("ownership_key", "ownership_batch_key"):
        assert re.search(
            rf'attribute\s*\{{\s*name\s*=\s*"{key_name}"\s*type\s*=\s*"S"\s*\}}',
            documents,
            flags=re.DOTALL,
        )

    contracts = _gsi_contracts(documents)
    assert contracts["OwnershipIndex"] == {
        "name": "OwnershipIndex",
        "hash_key": "ownership_key",
        "projection_type": "ALL",
    }
    assert contracts["BatchOwnershipIndex"] == {
        "name": "BatchOwnershipIndex",
        "hash_key": "ownership_batch_key",
        "projection_type": "ALL",
    }


def test_ingest_storage_consumers_use_the_declared_ownership_indexes() -> None:
    source = DOCUMENTS_REPOSITORY.read_text(encoding="utf-8")

    assert '"IndexName": "OwnershipIndex"' in source
    assert '"IndexName": "BatchOwnershipIndex"' in source
    assert '"IndexName": "BatchIndex"' not in source
    assert '"#ownership_key": "ownership_key"' in source
    assert '"#ownership_batch_key": "ownership_batch_key"' in source


def test_protected_ingest_analytics_does_not_scan_dynamodb() -> None:
    tree = ast.parse(ANALYTICS_SERVICE.read_text(encoding="utf-8"))
    scan_lines = [
        node.lineno
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "scan"
    ]

    assert scan_lines == [], f"Protected DynamoDB scan calls remain at lines {scan_lines}"
