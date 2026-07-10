"""Unit tests for the Employee Profiles add-on module.

Tests cover: normalisation, masking, grouping, merging, completeness,
idempotency, exports, fingerprint, route collision, key sanitisation.

Note: Tests importing from the service module (botocore dependency)
are gated by try/except to allow pure-function tests to run without
AWS SDK installed locally.
"""
import csv
import io
import json
import pytest

# ── Masking ──────────────────────────────────────
from app.services.employee_profiles_masking import (
    mask_curp,
    mask_rfc,
    mask_clave_elector,
    mask_identifier,
)

# ── Grouping & normalisation ────────────────────
from app.services.employee_profiles_grouping import (
    normalize_name,
    normalize_identifier,
    normalize_date,
    derive_person_key,
    group_documents_by_person,
    merge_profile_fields,
    calculate_completeness,
    build_profile_id,
    build_job_id,
)

# ── Exports ─────────────────────────────────────
from app.services.employee_profiles_export import (
    export_profile_json,
    export_profiles_csv,
)

# ── Pure utilities (no AWS deps) ──────────────
from app.services.employee_profiles_utils import (
    compute_source_fingerprint,
    strip_internal_paths,
    sanitise_key,
)

# ── Router (optional — require fastapi) ──
try:
    from app.api.v1.addons.employee_profiles import router as ep_router
    HAS_ROUTER_IMPORTS = True
except ImportError:
    HAS_ROUTER_IMPORTS = False


# ═══════════════════════════════════════════════════
# 1. Normalisation
# ═══════════════════════════════════════════════════

class TestNormalization:
    def test_normalize_name_basic(self):
        assert normalize_name("  Juan  Pérez  López  ") == "JUAN PEREZ LOPEZ"

    def test_normalize_name_accents(self):
        assert normalize_name("María José García Ñuño") == "MARIA JOSE GARCIA NUNO"

    def test_normalize_name_empty(self):
        assert normalize_name("") == ""
        assert normalize_name(None) == ""

    def test_normalize_identifier_curp(self):
        assert normalize_identifier("GARC 850101 HDFRRL 09", "curp") == "GARC850101HDFRRL09"

    def test_normalize_identifier_rfc(self):
        assert normalize_identifier("garc-8501-01-9a8", "rfc") == "GARC8501019A8"

    def test_normalize_identifier_empty(self):
        assert normalize_identifier("", "curp") == ""
        assert normalize_identifier(None, "rfc") == ""

    def test_normalize_date_iso(self):
        assert normalize_date("1985-01-01") == "1985-01-01"
        assert normalize_date("1985-1-1") == "1985-01-01"

    def test_normalize_date_slash(self):
        assert normalize_date("01/01/1985") == "1985-01-01"

    def test_normalize_date_empty(self):
        assert normalize_date("") == ""
        assert normalize_date(None) == ""


# ═══════════════════════════════════════════════════
# 2. PII Masking
# ═══════════════════════════════════════════════════

class TestMasking:
    def test_mask_curp_standard(self):
        result = mask_curp("GARC850101HDFRRL09")
        assert result == "GARC************09"
        assert len(result) == 18

    def test_mask_rfc_standard(self):
        result = mask_rfc("GARC8501019A8")
        assert result == "GARC******9A8"
        assert len(result) == 13

    def test_mask_clave_elector(self):
        result = mask_clave_elector("GRLPMR85010112H300")
        assert result.startswith("GRLP")
        assert result.endswith("00")

    def test_mask_empty(self):
        assert mask_curp("") == ""
        assert mask_curp(None) == ""
        assert mask_rfc("") == ""

    def test_mask_short_value(self):
        assert mask_curp("ABCD") == "****"

    def test_mask_identifier_dispatch(self):
        assert mask_identifier("GARC850101HDFRRL09", "curp") == mask_curp("GARC850101HDFRRL09")
        assert mask_identifier("GARC8501019A8", "rfc") == mask_rfc("GARC8501019A8")


# ═══════════════════════════════════════════════════
# 3. Person Key Derivation
# ═══════════════════════════════════════════════════

class TestPersonKey:
    def test_person_key_by_curp(self):
        doc = {"identifiers": {"curp": "GARC850101HDFRRL09"}, "person": {}}
        key, source = derive_person_key(doc)
        assert key == "CURP:GARC850101HDFRRL09"
        assert source == "curp"

    def test_person_key_fallback_rfc(self):
        doc = {"identifiers": {"rfc": "GARC8501019A8"}, "person": {}}
        key, source = derive_person_key(doc)
        assert key == "RFC:GARC8501019A8"
        assert source == "rfc"

    def test_person_key_fallback_clave(self):
        doc = {"identifiers": {"claveElector": "GRLPMR85010112H300"}, "person": {}}
        key, source = derive_person_key(doc)
        assert key.startswith("CLAVE:")
        assert source == "claveElector"

    def test_person_key_fallback_name_dob(self):
        doc = {
            "identifiers": {},
            "person": {"fullName": "Juan Pérez", "dob": "01/01/1985"},
        }
        key, source = derive_person_key(doc)
        assert key.startswith("NAME_DOB:")
        assert source == "name_dob"

    def test_person_key_fallback_document(self):
        doc = {"identifiers": {}, "person": {}, "documentId": "abc123"}
        key, source = derive_person_key(doc)
        assert key == "DOCID:abc123"
        assert source == "document_fallback"


# ═══════════════════════════════════════════════════
# 4. Grouping
# ═══════════════════════════════════════════════════

class TestGrouping:
    def test_group_by_curp(self):
        docs = [
            {"identifiers": {"curp": "GARC850101HDFRRL09"}, "person": {"fullName": "Juan"}, "documentId": "d1"},
            {"identifiers": {"curp": "GARC850101HDFRRL09"}, "person": {"fullName": "Juan G"}, "documentId": "d2"},
        ]
        groups = group_documents_by_person(docs)
        assert len(groups) == 1
        assert len(list(groups.values())[0]) == 2

    def test_group_by_rfc(self):
        docs = [
            {"identifiers": {"rfc": "GARC8501019A8"}, "person": {}, "documentId": "d1"},
            {"identifiers": {"rfc": "GARC8501019A8"}, "person": {}, "documentId": "d2"},
        ]
        groups = group_documents_by_person(docs)
        assert len(groups) == 1

    def test_no_merge_different_curp(self):
        docs = [
            {"identifiers": {"curp": "GARC850101HDFRRL09"}, "person": {}, "documentId": "d1"},
            {"identifiers": {"curp": "XYZX990202MDFRRL01"}, "person": {}, "documentId": "d2"},
        ]
        groups = group_documents_by_person(docs)
        assert len(groups) == 2

    def test_no_merge_conflicting_ids(self):
        docs = [
            {
                "identifiers": {"curp": "AAAA111111HDFRRL01"},
                "person": {"fullName": "Juan Pérez", "dob": "1985-01-01"},
                "documentId": "d1",
            },
            {
                "identifiers": {"curp": "BBBB222222HDFRRL02"},
                "person": {"fullName": "Juan Pérez", "dob": "1985-01-01"},
                "documentId": "d2",
            },
        ]
        groups = group_documents_by_person(docs)
        assert len(groups) == 2


# ═══════════════════════════════════════════════════
# 5. Field Merging
# ═══════════════════════════════════════════════════

class TestMergeFields:
    def test_merge_basic(self):
        group = [
            {
                "identifiers": {"curp": "GARC850101HDFRRL09", "rfc": "GARC8501019A8", "claveElector": "GRLPMR85010112H300"},
                "person": {"fullName": "JUAN GARCIA", "givenNames": "JUAN", "surnames": "GARCIA", "dob": "1985-01-01", "sex": "H", "nationality": "MEXICANA", "address": "Calle 1 Col Centro"},
                "subType": "ine_mx",
                "documentId": "d1",
                "overallConfidence": 90.0,
            },
        ]
        result = merge_profile_fields(group, "CURP:GARC850101HDFRRL09")
        assert result["identifiers"]["curp"] == "GARC850101HDFRRL09"
        assert result["identifiers"]["rfc"] == "GARC8501019A8"
        assert result["fullName"] == "JUAN GARCIA"
        assert result["status"] == "COMPLETE"

    def test_merge_missing_fields(self):
        group = [
            {
                "identifiers": {"curp": "GARC850101HDFRRL09"},
                "person": {"fullName": "JUAN GARCIA"},
                "documentId": "d1",
            },
        ]
        result = merge_profile_fields(group, "CURP:GARC850101HDFRRL09")
        assert "dob" in result["missingFields"]
        assert "address" in result["missingFields"]

    def test_merge_conflict_warning(self):
        group = [
            {
                "identifiers": {"curp": "GARC850101HDFRRL09", "rfc": "AAA111"},
                "person": {"fullName": "JUAN"},
                "subType": "ine_mx",
                "documentId": "d1",
                "overallConfidence": 90.0,
            },
            {
                "identifiers": {"curp": "GARC850101HDFRRL09", "rfc": "BBB222"},
                "person": {"fullName": "JUAN"},
                "subType": "personal_doc",
                "documentId": "d2",
                "overallConfidence": 85.0,
            },
        ]
        result = merge_profile_fields(group, "CURP:GARC850101HDFRRL09")
        warning_codes = [w["code"] for w in result["warnings"]]
        assert "CONFLICT_RFC" in warning_codes


# ═══════════════════════════════════════════════════
# 6. Completeness
# ═══════════════════════════════════════════════════

class TestCompleteness:
    def test_full_profile(self):
        ids = {"curp": "X", "rfc": "Y", "claveElector": "Z", "cic": "W"}
        person = {"fullName": "Juan", "dob": "1985-01-01", "sex": "H", "nationality": "MX", "address": "Calle 1", "givenNames": "Juan", "surnames": "Garcia"}
        score = calculate_completeness(ids, person)
        assert score >= 0.95

    def test_minimal_profile(self):
        ids = {"curp": "X"}
        person = {"fullName": "Juan"}
        score = calculate_completeness(ids, person)
        assert 0.3 <= score <= 0.5


# ═══════════════════════════════════════════════════
# 7. Idempotent IDs
# ═══════════════════════════════════════════════════

class TestIdempotentIds:
    def test_profile_id_deterministic(self):
        id1 = build_profile_id("tenant1", "batch1", "CURP:ABC")
        id2 = build_profile_id("tenant1", "batch1", "CURP:ABC")
        assert id1 == id2

    def test_profile_id_different_inputs(self):
        id1 = build_profile_id("tenant1", "batch1", "CURP:ABC")
        id2 = build_profile_id("tenant1", "batch1", "CURP:XYZ")
        assert id1 != id2

    def test_job_id_deterministic(self):
        id1 = build_job_id("t1", "b1", "hash1")
        id2 = build_job_id("t1", "b1", "hash1")
        assert id1 == id2


# ═══════════════════════════════════════════════════
# 8. Exports
# ═══════════════════════════════════════════════════

class TestExports:
    def test_export_json(self):
        profile = {"profileId": "p1", "fullName": "Juan García", "identifiers": {"curp": "GARC850101HDFRRL09"}}
        result = export_profile_json(profile)
        parsed = json.loads(result)
        assert parsed["profileId"] == "p1"
        assert parsed["fullName"] == "Juan García"

    def test_export_csv_unmasked_default(self):
        """P0.8: CSV export should be UNMASKED by default."""
        profiles = [
            {
                "profileId": "p1",
                "fullName": "Juan García",
                "firstNames": "Juan",
                "lastNames": "García",
                "birthDate": "1985-01-01",
                "sex": "H",
                "nationality": "MX",
                "address": "Calle 1",
                "identifiers": {"curp": "GARC850101HDFRRL09", "rfc": "GARC8501019A8", "claveElector": ""},
                "status": "COMPLETE",
                "completenessScore": 0.85,
                "sourceDocuments": [{"documentId": "d1"}],
                "missingFields": [],
                "warnings": [],
                "generatedAt": "2026-01-01T00:00:00Z",
            }
        ]
        result = export_profiles_csv(profiles)  # default mask_pii=False
        reader = csv.reader(io.StringIO(result))
        rows = list(reader)
        assert len(rows) == 2
        curp_col_idx = rows[0].index("curp")
        assert rows[1][curp_col_idx] == "GARC850101HDFRRL09"

    def test_export_csv_masked(self):
        """Explicitly masked CSV."""
        profiles = [
            {
                "profileId": "p1",
                "fullName": "Juan",
                "firstNames": None,
                "lastNames": None,
                "birthDate": None,
                "sex": None,
                "nationality": None,
                "address": None,
                "identifiers": {"curp": "GARC850101HDFRRL09", "rfc": "GARC8501019A8", "claveElector": ""},
                "status": "PARTIAL",
                "completenessScore": 0.3,
                "sourceDocuments": [],
                "missingFields": ["dob"],
                "warnings": [],
                "generatedAt": "2026-01-01T00:00:00Z",
            }
        ]
        result = export_profiles_csv(profiles, mask_pii=True)
        reader = csv.reader(io.StringIO(result))
        rows = list(reader)
        curp_col_idx = rows[0].index("curp")
        assert "****" in rows[1][curp_col_idx]

    def test_export_csv_empty(self):
        result = export_profiles_csv([], mask_pii=False)
        reader = csv.reader(io.StringIO(result))
        rows = list(reader)
        assert len(rows) == 1  # header only


# ═══════════════════════════════════════════════════
# 9. Source Fingerprint (P0.7)
# ═══════════════════════════════════════════════════

@pytest.mark.skipif(not True, reason="botocore not installed")
class TestSourceFingerprint:
    def test_fingerprint_deterministic(self):
        docs = [
            {"documentId": "d1", "classificationRoute": "personal", "status": "COMPLETED", "updatedAt": "2026-01-01T00:00:00Z", "stages": {}},
            {"documentId": "d2", "classificationRoute": "personal", "status": "COMPLETED", "updatedAt": "2026-01-01T00:00:00Z", "stages": {}},
        ]
        fp1 = compute_source_fingerprint("t1", "b1", {}, docs)
        fp2 = compute_source_fingerprint("t1", "b1", {}, docs)
        assert fp1 == fp2

    def test_fingerprint_changes_with_new_doc(self):
        docs1 = [
            {"documentId": "d1", "classificationRoute": "personal", "status": "COMPLETED", "updatedAt": "2026-01-01", "stages": {}},
        ]
        docs2 = [
            {"documentId": "d1", "classificationRoute": "personal", "status": "COMPLETED", "updatedAt": "2026-01-01", "stages": {}},
            {"documentId": "d2", "classificationRoute": "personal", "status": "COMPLETED", "updatedAt": "2026-01-02", "stages": {}},
        ]
        fp1 = compute_source_fingerprint("t1", "b1", {}, docs1)
        fp2 = compute_source_fingerprint("t1", "b1", {}, docs2)
        assert fp1 != fp2

    def test_fingerprint_changes_with_updated_doc(self):
        docs1 = [
            {"documentId": "d1", "classificationRoute": "personal", "status": "COMPLETED", "updatedAt": "2026-01-01", "stages": {}},
        ]
        docs2 = [
            {"documentId": "d1", "classificationRoute": "personal", "status": "COMPLETED", "updatedAt": "2026-01-05", "stages": {}},
        ]
        fp1 = compute_source_fingerprint("t1", "b1", {}, docs1)
        fp2 = compute_source_fingerprint("t1", "b1", {}, docs2)
        assert fp1 != fp2

    def test_fingerprint_includes_artifact_key(self):
        docs1 = [
            {"documentId": "d1", "classificationRoute": "personal", "status": "COMPLETED", "stages": {"persist": {"artifactRef": {"key": "v1/data.json"}}}},
        ]
        docs2 = [
            {"documentId": "d1", "classificationRoute": "personal", "status": "COMPLETED", "stages": {"persist": {"artifactRef": {"key": "v2/data.json"}}}},
        ]
        fp1 = compute_source_fingerprint("t1", "b1", {}, docs1)
        fp2 = compute_source_fingerprint("t1", "b1", {}, docs2)
        assert fp1 != fp2


# ═══════════════════════════════════════════════════
# 10. S3 Key Sanitisation (P0.2)
# ═══════════════════════════════════════════════════

@pytest.mark.skipif(not True, reason="botocore not installed")
class TestS3KeySanitisation:
    def test_sanitise_key_normal(self):
        assert sanitise_key("tenant-123") == "tenant-123"

    def test_sanitise_key_special_chars(self):
        assert sanitise_key("tenant/with/../injection") == "tenant_with____injection"

    def test_sanitise_key_spaces(self):
        assert sanitise_key("  my tenant  ") == "my_tenant"

    def test_sanitise_key_max_length(self):
        long_key = "a" * 200
        assert len(sanitise_key(long_key)) == 128


# ═══════════════════════════════════════════════════
# 11. Strip Internal Paths (P1.3)
# ═══════════════════════════════════════════════════

@pytest.mark.skipif(not True, reason="botocore not installed")
class TestStripInternalPaths:
    def test_strips_s3_paths(self):
        sources = {
            "curp": {"documentType": "ine_mx", "confidence": 90.0, "bucket": "my-bucket", "key": "tenant/data.json"},
            "fullName": {"documentType": "ine_mx", "confidence": 85.0},
        }
        cleaned = strip_internal_paths(sources)
        assert "bucket" not in cleaned["curp"]
        assert "key" not in cleaned["curp"]
        assert cleaned["curp"]["documentType"] == "ine_mx"
        assert cleaned["curp"]["confidence"] == 90.0
        assert cleaned["fullName"]["documentType"] == "ine_mx"

    def test_preserves_non_dict_values(self):
        sources = {"someField": "stringValue"}
        cleaned = strip_internal_paths(sources)
        assert cleaned["someField"] == "stringValue"


# ═══════════════════════════════════════════════════
# 12. Route Collision Tests (P0.1 / P0.10)
# ═══════════════════════════════════════════════════

@pytest.mark.skipif(not HAS_ROUTER_IMPORTS, reason="fastapi not installed")
class TestRouteCollision:
    """Verify that FastAPI route order is correct."""

    def test_status_is_not_profileId(self):
        """GET /status must come before GET /{profile_id}."""
        routes = [(r.path, list(r.methods)) for r in ep_router.routes]
        status_idx = next(i for i, (p, _) in enumerate(routes) if p == "/status")
        detail_idx = next(i for i, (p, _) in enumerate(routes) if p == "/{profile_id}" and "GET" in _)
        assert status_idx < detail_idx

    def test_export_csv_is_not_profileId(self):
        """GET /export/csv must come before GET /{profile_id}."""
        routes = [(r.path, list(r.methods)) for r in ep_router.routes]
        csv_idx = next(i for i, (p, _) in enumerate(routes) if p == "/export/csv")
        detail_idx = next(i for i, (p, _) in enumerate(routes) if p == "/{profile_id}" and "GET" in _)
        assert csv_idx < detail_idx

    def test_jobs_is_not_profileId(self):
        routes = [(r.path, list(r.methods)) for r in ep_router.routes]
        jobs_idx = next(i for i, (p, _) in enumerate(routes) if p == "/jobs/{job_id}")
        detail_idx = next(i for i, (p, _) in enumerate(routes) if p == "/{profile_id}" and "GET" in _)
        assert jobs_idx < detail_idx

    def test_generate_exists(self):
        routes = [(r.path, list(r.methods)) for r in ep_router.routes]
        gen = [p for p, m in routes if p == "/generate" and "POST" in m]
        assert len(gen) == 1

    def test_individual_csv_export_exists(self):
        routes = [(r.path, list(r.methods)) for r in ep_router.routes]
        csv_ind = [p for p, m in routes if p == "/{profile_id}/export/csv" and "GET" in m]
        assert len(csv_ind) == 1

    def test_detail_route_is_last_get(self):
        get_routes = [(r.path, i) for i, r in enumerate(ep_router.routes) if "GET" in (r.methods or set())]
        detail = [(p, idx) for p, idx in get_routes if p == "/{profile_id}"]
        assert len(detail) == 1
        detail_idx = detail[0][1]
        for path, idx in get_routes:
            if path != "/{profile_id}" and not path.startswith("/{profile_id}/"):
                assert idx < detail_idx
