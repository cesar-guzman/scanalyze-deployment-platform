import json
from pathlib import Path

import jsonschema
import pytest


ROOT = Path(__file__).resolve().parents[1]
SCHEMA = json.loads((ROOT / "schemas/object-ownership.v1.schema.json").read_text())
VALID = {
    "customer_id": "cust_01ARZ3NDEKTSV4RRFFQ69G5FAW",
    "deployment_id": "dep_01ARZ3NDEKTSV4RRFFQ69G5FAV",
    "ownership_schema_version": 1,
    "ownership_key": (
        "CUSTOMER#cust_01ARZ3NDEKTSV4RRFFQ69G5FAW#"
        "DEPLOYMENT#dep_01ARZ3NDEKTSV4RRFFQ69G5FAV"
    ),
}


def test_canonical_object_ownership_contract_accepts_exact_binding() -> None:
    jsonschema.Draft202012Validator(SCHEMA).validate(VALID)


@pytest.mark.parametrize(
    "field",
    ["customer_id", "deployment_id", "ownership_schema_version", "ownership_key"],
)
def test_canonical_object_ownership_contract_rejects_missing_fields(field: str) -> None:
    invalid = dict(VALID)
    invalid.pop(field)
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.Draft202012Validator(SCHEMA).validate(invalid)


def test_batch_membership_partition_contract_is_owner_bound() -> None:
    record = {
        **VALID,
        "ownership_batch_key": f'{VALID["ownership_key"]}#BATCH#batch-synthetic-0001',
    }
    jsonschema.Draft202012Validator(SCHEMA).validate(record)
