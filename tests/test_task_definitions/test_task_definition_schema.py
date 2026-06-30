"""Tests for task-definition-input.v1.schema.json.

Validates that:
- All 7 service task definitions pass schema validation
- Mutable image tags (:latest) are rejected
- Legacy tenant identity as authoritative is rejected
- Missing customer_identity is rejected
- imagedefinitions.json ownership fields are rejected
- Leaked secret values (not ARN references) are rejected
- SCANALYZE_TENANT as canonical field is rejected
"""
import json
import pathlib
import pytest

try:
    import jsonschema
    from jsonschema import Draft202012Validator
    HAS_JSONSCHEMA = True
except ImportError:
    HAS_JSONSCHEMA = False

REPO_ROOT = pathlib.Path(__file__).parent.parent.parent
SCHEMA_PATH = REPO_ROOT / "schemas" / "task-definition-input.v1.schema.json"
VALID_DIR = REPO_ROOT / "fixtures" / "valid"
INVALID_DIR = REPO_ROOT / "fixtures" / "invalid"

SERVICES = [
    "ingest-api",
    "ocr-worker",
    "postprocess-worker",
    "classifier-worker",
    "bank-worker",
    "personal-worker",
    "gov-worker",
]


def _load_schema():
    with open(SCHEMA_PATH) as f:
        return json.load(f)


def _load_fixture(path):
    with open(path) as f:
        return json.load(f)


@pytest.mark.skipif(not HAS_JSONSCHEMA, reason="jsonschema not installed")
class TestValidTaskDefinitions:
    """All 7 service task definitions must pass schema validation."""

    @pytest.fixture(autouse=True)
    def setup(self):
        self.schema = _load_schema()
        self.validator = Draft202012Validator(self.schema)

    @pytest.mark.parametrize("service", SERVICES)
    def test_service_passes_validation(self, service):
        fixture = _load_fixture(VALID_DIR / f"task-definition-{service}.json")
        # Should not raise
        self.validator.validate(fixture)


@pytest.mark.skipif(not HAS_JSONSCHEMA, reason="jsonschema not installed")
class TestMutableImageTagRejected:
    """Image using :latest tag must be rejected."""

    def test_mutable_tag(self):
        schema = _load_schema()
        fixture = _load_fixture(INVALID_DIR / "task-definition-mutable-tag.json")
        with pytest.raises(jsonschema.ValidationError, match="sha256"):
            Draft202012Validator(schema).validate(fixture)


@pytest.mark.skipif(not HAS_JSONSCHEMA, reason="jsonschema not installed")
class TestLegacyTenantAuthoritative:
    """tenantId as canonical_field must be rejected."""

    def test_tenant_id_rejected(self):
        schema = _load_schema()
        fixture = _load_fixture(
            INVALID_DIR / "task-definition-legacy-tenant-authoritative.json"
        )
        with pytest.raises(jsonschema.ValidationError):
            Draft202012Validator(schema).validate(fixture)


@pytest.mark.skipif(not HAS_JSONSCHEMA, reason="jsonschema not installed")
class TestScanalyzeTenantCanonical:
    """SCANALYZE_TENANT as canonical_field must be rejected."""

    def test_scanalyze_tenant_rejected(self):
        schema = _load_schema()
        fixture = _load_fixture(
            INVALID_DIR / "task-definition-scanalyze-tenant-canonical.json"
        )
        with pytest.raises(jsonschema.ValidationError):
            Draft202012Validator(schema).validate(fixture)


@pytest.mark.skipif(not HAS_JSONSCHEMA, reason="jsonschema not installed")
class TestMissingCustomerIdentity:
    """Missing customer_identity field must be rejected."""

    def test_missing_identity(self):
        schema = _load_schema()
        fixture = _load_fixture(
            INVALID_DIR / "task-definition-missing-identity.json"
        )
        with pytest.raises(
            jsonschema.ValidationError, match="customer_identity"
        ):
            Draft202012Validator(schema).validate(fixture)


@pytest.mark.skipif(not HAS_JSONSCHEMA, reason="jsonschema not installed")
class TestImagedefinitionsOwnership:
    """Extra field from imagedefinitions.json ownership must be rejected."""

    def test_imagedefinitions_rejected(self):
        schema = _load_schema()
        fixture = _load_fixture(
            INVALID_DIR / "task-definition-imagedefinitions-owner.json"
        )
        with pytest.raises(
            jsonschema.ValidationError, match="imagedefinitions_source"
        ):
            Draft202012Validator(schema).validate(fixture)


@pytest.mark.skipif(not HAS_JSONSCHEMA, reason="jsonschema not installed")
class TestLeakedSecretValue:
    """Secret with plain value (not ARN) must be rejected."""

    def test_leaked_secret(self):
        schema = _load_schema()
        fixture = _load_fixture(
            INVALID_DIR / "task-definition-leaked-secret.json"
        )
        with pytest.raises(jsonschema.ValidationError, match="arn:aws"):
            Draft202012Validator(schema).validate(fixture)
