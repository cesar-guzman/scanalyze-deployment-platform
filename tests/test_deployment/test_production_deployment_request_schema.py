"""Git-safe production request v2 retains the existing closed intent boundary."""
from copy import deepcopy
import json
from pathlib import Path

import jsonschema
import pytest


ROOT = Path(__file__).resolve().parents[2]


def _validator(filename):
    return jsonschema.Draft202012Validator(
        json.loads((ROOT / "schemas" / filename).read_text()),
        format_checker=jsonschema.FormatChecker(),
    )


@pytest.fixture
def production_request():
    claim = json.loads((ROOT / "fixtures/valid/nonprod-live-input-claim-v1-synthetic.json").read_text())
    value = deepcopy(claim["deployment_request"])
    value.update(schema_version="2", environment="production")
    return value


def test_production_request_v2_accepts_intent_but_v1_rejects_it(production_request):
    _validator("deployment-request-production.v2.schema.json").validate(production_request)
    assert not _validator("deployment-request.schema.json").is_valid(production_request)
    assert not _validator("deployment-request-production.schema.json").is_valid(production_request)


@pytest.mark.parametrize("field,value", [
    ("environment", "dev"), ("environment", "staging"), ("environment", "sandbox"),
    ("schema_version", "1"), ("account_id", "111111111111"),
    ("role_arn", "arn:aws:iam::111111111111:role/example"),
    ("requested_by", "arn:aws:iam::111111111111:role/example"),
    ("full_deployment", True),
])
def test_production_request_rejects_cross_lane_resolved_authority_or_ambiguous_scope(production_request, field, value):
    production_request[field] = value
    assert not _validator("deployment-request-production.v2.schema.json").is_valid(production_request)


def test_production_request_preserves_approval_evidence_requirements(production_request):
    production_request["approval"].pop("decided_by")
    assert not _validator("deployment-request-production.v2.schema.json").is_valid(production_request)


def test_production_request_rejects_account_or_arn_in_selectors(production_request):
    for field, value in [("account_id", "111111111111"), ("role_arn", "arn:aws:iam::111111111111:role/example")]:
        mutated = deepcopy(production_request)
        mutated["non_sensitive_selectors"][field] = value
        assert not _validator("deployment-request-production.v2.schema.json").is_valid(mutated)
