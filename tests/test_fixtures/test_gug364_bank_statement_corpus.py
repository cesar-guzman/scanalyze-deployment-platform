from __future__ import annotations

import base64
import copy
import hashlib
import io
import json
import re
import subprocess
import sys
import tempfile
import tomllib
from datetime import date, datetime
from pathlib import Path
from typing import Any

import jsonschema
import pydantic
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from pypdf import PdfReader, PdfWriter
from pypdf.generic import ArrayObject, DictionaryObject, IndirectObject

from tooling.generate_bank_statement_fixtures import PROMPT_VERSION, merge_overrides


REPO_ROOT = Path(__file__).resolve().parents[2]
FIXTURE_DIR = REPO_ROOT / "tests/fixtures/bank_statement/v1"
CATALOG_PATH = FIXTURE_DIR / "catalog.json"
CATALOG_SCHEMA_PATH = FIXTURE_DIR / "catalog.schema.json"
CONTROL_SCHEMA_PATH = FIXTURE_DIR / "control.schema.json"
PROFILE_SCHEMA_PATH = FIXTURE_DIR / "profile.schema.json"
RESULT_SCHEMA_PATH = REPO_ROOT / "schemas/scanalyze-document-journey-result.v1.schema.json"
GENERATOR_PATH = REPO_ROOT / "tooling/generate_bank_statement_fixtures.py"
INGEST_ROOT = REPO_ROOT / "backend/workers/scanalyze-ingest-api"
INGEST_TESTS = INGEST_ROOT / "tests"

for import_path in (str(INGEST_ROOT), str(INGEST_TESTS)):
    if import_path not in sys.path:
        sys.path.insert(0, import_path)

from app.errors import register_exception_handlers  # noqa: E402
import app.api.v2.router as journey_routes  # noqa: E402
from app.journey_contract import (  # noqa: E402
    CONTRACT_HEADER,
    CONTRACT_VERSION,
    IDEMPOTENCY_HEADER,
    DocumentLifecycle,
    FailureDisposition,
    MAX_DOCUMENT_BYTES,
    SafeFailureCode,
    adapt_internal_document_status,
    project_bank_statement_result,
)
import test_gug354_journey_service as journey_harness  # noqa: E402


EXPECTED_PROFILE_NAMES = {
    "01": "Single-page happy path",
    "02": "Multi-page statement",
    "03": "Multiple transactions",
    "04": "Nullable and optional fields",
    "05": "Zero-transaction statement",
    "06": "Warning-producing result",
    "07": "Low-confidence or incomplete extraction",
    "08": "Balance-reconciliation warning",
    "09": "Varied periods and currencies",
    "10": "Repeated deterministic replay",
}

ACTIVE_PDF_KEYS = {
    "/AA",
    "/AcroForm",
    "/EmbeddedFiles",
    "/ImportData",
    "/JS",
    "/JavaScript",
    "/Launch",
    "/OpenAction",
    "/RichMedia",
    "/SubmitForm",
    "/URI",
    "/XFA",
}
ACTIVE_PDF_VALUES = {
    "/FileAttachment",
    "/Filespec",
    "/GoToR",
    "/ImportData",
    "/JavaScript",
    "/Launch",
    "/RichMedia",
    "/SubmitForm",
    "/URI",
}

PROHIBITED_PATTERNS = {
    "email": re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"),
    "ssn": re.compile(r"(?<!\d)\d{3}-\d{2}-\d{4}(?!\d)"),
    "phone": re.compile(r"(?<!\d)\d{3}[-.]?\d{3}[-.]?\d{4}(?!\d)"),
    "aws_arn": re.compile(r"\barn:aws(?:-[a-z0-9-]+)?:[^\s]+"),
    "aws_account": re.compile(r"(?<!\d)\d{12}(?!\d)"),
    "payment_card": re.compile(r"(?<!\d)(?:\d[ -]?){13,16}(?!\d)"),
    "clabe": re.compile(r"(?<!\d)\d{18}(?!\d)"),
}

NON_CONTENT_JSON_KEYS = {
    "byteSize",
    "contentLength",
    "controlSpecSha256",
    "documentId",
    "expectedResultSha256",
    "fixtureId",
    "generatorSourceSha256",
    "idempotencyKey",
    "instanceId",
    "inputFixtureId",
    "inputFixtureIds",
    "pdfSha256",
    "profileId",
    "resultId",
    "sha256",
    "sourceSpecSha256",
    "value",
}


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def catalog() -> dict[str, Any]:
    return load_json(CATALOG_PATH)


@pytest.fixture(scope="module")
def positive_fixtures(catalog: dict[str, Any]) -> list[dict[str, Any]]:
    return [entry for entry in catalog["fixtures"] if entry["positiveOrNegative"] == "POSITIVE"]


@pytest.fixture(scope="module")
def negative_fixtures(catalog: dict[str, Any]) -> list[dict[str, Any]]:
    return [entry for entry in catalog["fixtures"] if entry["positiveOrNegative"] == "NEGATIVE"]


@pytest.fixture(scope="module")
def effective_profiles() -> dict[str, list[tuple[dict[str, Any], dict[str, Any]]]]:
    effective: dict[str, list[tuple[dict[str, Any], dict[str, Any]]]] = {}
    for path in sorted((FIXTURE_DIR / "profiles").glob("profile_*.json")):
        profile = load_json(path)
        effective[profile["id"]] = [
            (
                instance,
                merge_overrides(profile["commonDefaults"], instance["overrides"]),
            )
            for instance in profile["instances"]
        ]
    return effective


def _warning_codes(ground_truth: dict[str, Any]) -> list[str]:
    warnings: list[str] = []
    if ground_truth["quality"]["overallConfidence"] < 70:
        warnings.append("LOW_CONFIDENCE")
    if (
        ground_truth["bank"]["name"] is None
        or ground_truth["account"]["holder"] is None
        or ground_truth["statementPeriod"]["start"] is None
        or ground_truth["statementPeriod"]["end"] is None
        or not ground_truth["transactions"]
    ):
        warnings.append("INCOMPLETE_EXTRACTION")
    balances = ground_truth["balances"]
    if all(
        balances[field] is not None
        for field in ("opening", "closing", "totalCredits", "totalDebits")
    ) and balances["opening"] + balances["totalCredits"] - balances["totalDebits"] != balances["closing"]:
        warnings.append("BALANCE_RECONCILIATION_WARNING")
    return warnings


def _producer_artifact(ground_truth: dict[str, Any], document_id: str) -> dict[str, Any]:
    account = ground_truth["account"] or {}
    statement = ground_truth["statementPeriod"] or {}
    artifact = {
        "schema_version": "1.0",
        "prompt_version": PROMPT_VERSION,
        "tenant": "bank",
        "documentId": document_id,
        "docType": "bank_statement",
        "generatedAt": "2026-01-01T00:00:00Z",
        "model": {"provider": "bedrock", "modelId": "synthetic-model", "usage": None},
        "bank": ground_truth["bank"],
        "account": {
            "holder": account.get("holder"),
            "number": None,
            "numberMasked": account.get("numberMasked"),
            "clabe": None,
            "clabeMasked": account.get("clabeMasked"),
            "currency": account.get("currency"),
        },
        "statement": {
            "periodStart": statement.get("start"),
            "periodEnd": statement.get("end"),
        },
        "balances": ground_truth["balances"],
        "transactions": ground_truth["transactions"],
        "accountType": ground_truth["accountType"],
        "bankCountry": ground_truth["country"],
        "fees": ground_truth["fees"],
        "interestEarned": (ground_truth["interest"] or {}).get("earned"),
        "interestCharged": (ground_truth["interest"] or {}).get("charged"),
        "summaryText": ground_truth["summary"],
        "overallConfidence": ground_truth["quality"]["overallConfidence"],
        "fieldConfidence": {
            "balanceReconciliation": {
                "valid": "BALANCE_RECONCILIATION_WARNING" not in _warning_codes(ground_truth),
                "score": 100.0,
            }
        },
    }
    return artifact


def assert_no_active_pdf_content(reader: PdfReader) -> None:
    seen_indirect: set[tuple[int, int, int]] = set()
    seen_direct: set[int] = set()

    def resolve(value: Any) -> Any:
        while isinstance(value, IndirectObject):
            key = (id(value.pdf), value.idnum, value.generation)
            if key in seen_indirect:
                return None
            seen_indirect.add(key)
            value = value.get_object()
        return value

    def walk(value: Any) -> None:
        value = resolve(value)
        if value is None:
            return
        if isinstance(value, (DictionaryObject, dict)):
            if id(value) in seen_direct:
                return
            seen_direct.add(id(value))
            for raw_key, raw_child in value.items():
                key = str(raw_key)
                child = resolve(raw_child)
                assert key not in ACTIVE_PDF_KEYS, f"Found active PDF key {key}"
                if key in {"/S", "/Type", "/Subtype"}:
                    assert str(child) not in ACTIVE_PDF_VALUES, f"Found active PDF value {child}"
                walk(child)
        elif isinstance(value, (ArrayObject, list, tuple)):
            if id(value) in seen_direct:
                return
            seen_direct.add(id(value))
            for child in value:
                walk(child)

    walk(reader.trailer)


def find_prohibited_data(text: str) -> set[str]:
    return {
        name
        for name, pattern in PROHIBITED_PATTERNS.items()
        if pattern.search(text)
    }


def _iter_json_content(value: Any, key: str | None = None):
    if key in NON_CONTENT_JSON_KEYS:
        return
    if isinstance(value, dict):
        for child_key, child in value.items():
            yield from _iter_json_content(child, child_key)
    elif isinstance(value, list):
        for child in value:
            yield from _iter_json_content(child, key)
    elif isinstance(value, str):
        yield value


def _catalog_path(relative_path: str) -> Path:
    raw_path = FIXTURE_DIR / relative_path
    assert not raw_path.is_symlink(), f"Catalog path must not be a symlink: {relative_path}"
    resolved = raw_path.resolve(strict=True)
    assert resolved.is_relative_to(FIXTURE_DIR.resolve())
    assert resolved.is_file()
    return resolved


def assert_control_recipe_semantics(
    recipe: dict[str, Any],
    positive_by_id: dict[str, dict[str, Any]],
) -> None:
    steps = recipe["steps"]
    step_by_id = {step["stepId"]: step for step in steps}
    assert len(step_by_id) == len(steps)
    used_fixture_ids = {
        step["inputFixtureId"] for step in steps if "inputFixtureId" in step
    }
    assert set(recipe["inputFixtureIds"]) == used_fixture_ids

    owner = recipe["principals"]["owner"]
    other_actor = recipe["principals"]["otherActor"]
    other_deployment = recipe["principals"]["otherDeployment"]
    assert other_actor["subject"] != owner["subject"]
    assert other_actor["customerId"] == owner["customerId"]
    assert other_actor["deploymentId"] == owner["deploymentId"]
    assert other_deployment["subject"] == owner["subject"]
    assert other_deployment["customerId"] == owner["customerId"]
    assert other_deployment["deploymentId"] != owner["deploymentId"]

    for step in steps:
        reference = step.get("documentIdFromStep")
        if reference is not None:
            assert reference in step_by_id
            assert steps.index(step_by_id[reference]) < steps.index(step)
        fixture_id = step.get("inputFixtureId")
        if fixture_id is None:
            continue
        entry = positive_by_id[fixture_id]
        payload = _catalog_path(entry["filePath"]).read_bytes()
        assert hashlib.sha256(payload).hexdigest() == entry["pdfSha256"]
        declared_length = step["request"]["contentLength"]
        if recipe["controlId"] == "ctrl_04":
            assert declared_length == MAX_DOCUMENT_BYTES + 1
        else:
            assert declared_length == len(payload)

    control_id = recipe["controlId"]
    if control_id == "ctrl_01":
        malformed = _decode_artifact(steps[0])
        try:
            PdfReader(io.BytesIO(malformed), strict=True)
        except Exception:
            pass
        else:
            raise AssertionError("ctrl_01 artifact must be malformed")
        assert datetime.fromisoformat(steps[1]["evaluationTime"]) >= datetime.fromisoformat(
            steps[1]["internalStatus"]["updatedAt"]
        )
    elif control_id == "ctrl_02":
        try:
            reader = PdfReader(io.BytesIO(_decode_artifact(steps[0])), strict=True)
        except Exception as exc:
            raise AssertionError("ctrl_02 artifact must be a parseable PDF") from exc
        assert len(reader.pages) == steps[0]["artifact"]["pageCount"]
        extracted = "".join(page.extract_text() for page in reader.pages)
        assert len(extracted.strip()) <= steps[0]["expect"]["maximumTextCharacters"]
    elif control_id == "ctrl_03":
        assert steps[0]["request"]["contentType"] == "text/plain"
        assert Path(steps[0]["request"]["filename"]).suffix == ".txt"
    elif control_id == "ctrl_04":
        assert steps[0]["request"]["contentType"] == "application/pdf"
    elif control_id == "ctrl_05":
        first, conflict = steps
        assert first["idempotencyKey"] == conflict["idempotencyKey"]
        assert first["principal"] == conflict["principal"] == "owner"
        assert first["inputFixtureId"] != conflict["inputFixtureId"]
        assert first["request"] != conflict["request"]
        assert first["request"]["contentType"] == conflict["request"]["contentType"] == "application/pdf"
    elif control_id == "ctrl_06":
        create, reconcile, replay = steps
        assert create["discardResponse"] is True
        assert create["idempotencyKey"] == reconcile["idempotencyKey"] == replay["idempotencyKey"]
        assert create["inputFixtureId"] == replay["inputFixtureId"]
        assert create["request"] == replay["request"]
        assert create["request"]["contentType"] == "application/pdf"
    elif control_id in {"ctrl_07", "ctrl_08"}:
        create, read = steps
        assert create["request"]["contentType"] == "application/pdf"
        assert read["documentIdFromStep"] == create["stepId"]
        expected_principal = "otherActor" if control_id == "ctrl_07" else "otherDeployment"
        assert read["principal"] == expected_principal


def test_all_schemas_are_valid_draft_2020_12() -> None:
    for schema_path in (
        CATALOG_SCHEMA_PATH,
        CONTROL_SCHEMA_PATH,
        PROFILE_SCHEMA_PATH,
        RESULT_SCHEMA_PATH,
    ):
        jsonschema.Draft202012Validator.check_schema(load_json(schema_path))


def test_contract_executor_uses_the_exact_ingest_pydantic_version() -> None:
    runtime_requirements = (
        INGEST_ROOT / "requirements.txt"
    ).read_text(encoding="utf-8").splitlines()
    runtime_pin = next(line for line in runtime_requirements if line.startswith("pydantic=="))
    root_project = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    root_pin = next(
        dependency
        for dependency in root_project["project"]["optional-dependencies"]["test"]
        if dependency.startswith("pydantic==")
    )
    assert root_pin == runtime_pin == f"pydantic=={pydantic.__version__}"


def test_catalog_and_control_recipe_schemas(catalog: dict[str, Any]) -> None:
    jsonschema.Draft202012Validator(load_json(CATALOG_SCHEMA_PATH)).validate(catalog)
    control_validator = jsonschema.Draft202012Validator(load_json(CONTROL_SCHEMA_PATH))
    positive_by_id = {
        entry["fixtureId"]: entry
        for entry in catalog["fixtures"]
        if entry["positiveOrNegative"] == "POSITIVE"
    }
    for entry in catalog["fixtures"]:
        if entry["positiveOrNegative"] == "NEGATIVE":
            recipe = load_json(_catalog_path(entry["filePath"]))
            control_validator.validate(recipe)
            assert_control_recipe_semantics(recipe, positive_by_id)


def test_profile_and_result_schemas(
    positive_fixtures: list[dict[str, Any]],
) -> None:
    profile_validator = jsonschema.Draft202012Validator(load_json(PROFILE_SCHEMA_PATH))
    result_validator = jsonschema.Draft202012Validator(load_json(RESULT_SCHEMA_PATH))
    for profile_path in sorted((FIXTURE_DIR / "profiles").glob("profile_*.json")):
        profile_validator.validate(load_json(profile_path))
    for entry in positive_fixtures:
        result_validator.validate(load_json(_catalog_path(entry["expectedResultPath"])))


def test_catalog_counts_uniqueness_and_references(
    catalog: dict[str, Any],
    positive_fixtures: list[dict[str, Any]],
    negative_fixtures: list[dict[str, Any]],
) -> None:
    assert len(positive_fixtures) == 20
    assert len(negative_fixtures) == 8
    assert {entry["profileId"] for entry in positive_fixtures} == set(EXPECTED_PROFILE_NAMES)

    fixture_ids = [entry["fixtureId"] for entry in catalog["fixtures"]]
    file_paths = [entry["filePath"] for entry in catalog["fixtures"]]
    expected_paths = [entry["expectedResultPath"] for entry in positive_fixtures]
    assert len(fixture_ids) == len(set(fixture_ids))
    assert len(file_paths) == len(set(file_paths))
    assert len(expected_paths) == len(set(expected_paths))

    positive_by_id = {entry["fixtureId"]: entry for entry in positive_fixtures}
    positive_ids = set(positive_by_id)
    for entry in catalog["fixtures"]:
        assert entry["noRealDataAttestation"] is True
        assert entry["sensitivity"] == "SYNTHETIC"
        _catalog_path(entry["filePath"])
        _catalog_path(entry["sourceSpecPath"])
        for referenced_id in entry.get("inputFixtureIds", []):
            assert referenced_id in positive_ids

    for entry in negative_fixtures:
        recipe_path = _catalog_path(entry["filePath"])
        recipe_bytes = recipe_path.read_bytes()
        recipe = json.loads(recipe_bytes)
        assert entry["inputFixtureIds"] == recipe["inputFixtureIds"]
        used_fixture_ids = {
            step["inputFixtureId"] for step in recipe["steps"] if "inputFixtureId" in step
        }
        assert set(recipe["inputFixtureIds"]) == used_fixture_ids
        assert entry["controlSpecByteSize"] == len(recipe_bytes)
        assert entry["controlSpecSha256"] == hashlib.sha256(recipe_bytes).hexdigest()
        recipe_steps = {step["stepId"]: step for step in recipe["steps"]}

        for artifact in entry["inputArtifacts"]:
            assert set(artifact["stepIds"]) <= set(recipe_steps)
            if artifact["bindingType"] == "SHARED_POSITIVE_FIXTURE":
                source = positive_by_id[artifact["fixtureId"]]
                assert artifact["fixtureId"] in recipe["inputFixtureIds"]
                assert artifact["pdfSha256"] == source["pdfSha256"]
                assert artifact["byteSize"] == source["byteSize"]
                assert artifact["pageCount"] == source["pageCount"]
                for step_id in artifact["stepIds"]:
                    assert recipe_steps[step_id]["inputFixtureId"] == artifact["fixtureId"]
            else:
                assert artifact["bindingType"] == "EMBEDDED_CONTROL_ARTIFACT"
                step = recipe_steps[artifact["stepIds"][0]]
                payload = _decode_artifact(step)
                assert artifact["pdfSha256"] == hashlib.sha256(payload).hexdigest()
                assert artifact["byteSize"] == len(payload)


def test_effective_profile_matrix_matches_gug364(
    effective_profiles: dict[str, list[tuple[dict[str, Any], dict[str, Any]]]],
) -> None:
    assert set(effective_profiles) == set(EXPECTED_PROFILE_NAMES)
    for profile_id, instances in effective_profiles.items():
        profile = load_json(FIXTURE_DIR / f"profiles/profile_{profile_id}.json")
        assert profile["name"] == EXPECTED_PROFILE_NAMES[profile_id]
        assert len(instances) == 2
        for _instance, ground_truth in instances:
            assert ground_truth["expectedWarnings"] == _warning_codes(ground_truth)
            transactions = ground_truth["transactions"]
            total_credits = sum(
                transaction["amount"]
                for transaction in transactions
                if transaction["direction"] == "credit"
            )
            total_debits = sum(
                transaction["amount"]
                for transaction in transactions
                if transaction["direction"] == "debit"
            )
            assert ground_truth["balances"]["totalCredits"] == pytest.approx(total_credits)
            assert ground_truth["balances"]["totalDebits"] == pytest.approx(total_debits)

            running_balance = ground_truth["balances"]["opening"]
            for transaction in transactions:
                direction = 1 if transaction["direction"] == "credit" else -1
                running_balance += direction * transaction["amount"]
                assert transaction["balanceAfter"] == pytest.approx(running_balance)

    for _instance, ground_truth in effective_profiles["01"]:
        assert ground_truth["pages"] == 1
        assert len(ground_truth["transactions"]) >= 2
        assert ground_truth["expectedWarnings"] == []

    assert {ground_truth["pages"] for _, ground_truth in effective_profiles["02"]} == {2, 3}
    assert all(len(ground_truth["transactions"]) == 15 for _, ground_truth in effective_profiles["02"])
    assert all(len(ground_truth["transactions"]) >= 4 for _, ground_truth in effective_profiles["03"])

    for _instance, ground_truth in effective_profiles["04"]:
        assert ground_truth["bank"]["name"] is not None
        assert ground_truth["account"]["holder"] is not None
        assert ground_truth["statementPeriod"]["start"] is not None
        assert ground_truth["statementPeriod"]["end"] is not None
        assert ground_truth["transactions"]
        assert any(
            ground_truth[field] is None
            for field in ("accountType", "country", "fees", "interest", "summary")
        )

    for _instance, ground_truth in effective_profiles["05"]:
        assert ground_truth["transactions"] == []
        assert ground_truth["balances"] == {
            "opening": 1000.0,
            "closing": 1000.0,
            "totalCredits": 0.0,
            "totalDebits": 0.0,
        }
        assert ground_truth["expectedWarnings"] == ["INCOMPLETE_EXTRACTION"]

    for _instance, ground_truth in effective_profiles["06"]:
        missing_core = sum(
            value is None
            for value in (
                ground_truth["bank"]["name"],
                ground_truth["account"]["holder"],
                ground_truth["statementPeriod"]["start"],
                ground_truth["statementPeriod"]["end"],
            )
        )
        assert missing_core == 1
        assert ground_truth["expectedWarnings"] == ["INCOMPLETE_EXTRACTION"]

    for _instance, ground_truth in effective_profiles["07"]:
        assert ground_truth["quality"]["overallConfidence"] < 70
        assert "LOW_CONFIDENCE" in ground_truth["expectedWarnings"]

    for _instance, ground_truth in effective_profiles["08"]:
        assert ground_truth["expectedWarnings"] == ["BALANCE_RECONCILIATION_WARNING"]

    currencies = set()
    periods = set()
    for _instance, ground_truth in effective_profiles["09"]:
        currency = ground_truth["account"]["currency"]
        period = ground_truth["statementPeriod"]
        currencies.add(currency)
        periods.add((period["start"], period["end"]))
        start = date.fromisoformat(period["start"])
        end = date.fromisoformat(period["end"])
        assert all(start <= date.fromisoformat(tx["date"]) <= end for tx in ground_truth["transactions"])
    assert currencies == {"MXN", "USD"}
    assert len(periods) == 2


def test_expected_results_are_projected_by_the_production_contract(
    positive_fixtures: list[dict[str, Any]],
) -> None:
    for entry in positive_fixtures:
        profile = load_json(_catalog_path(entry["sourceSpecPath"]))
        instance = next(
            item for item in profile["instances"] if item["instanceId"] == entry["instanceId"]
        )
        ground_truth = merge_overrides(profile["commonDefaults"], instance["overrides"])
        expected = load_json(_catalog_path(entry["expectedResultPath"]))
        projected = project_bank_statement_result(
            _producer_artifact(ground_truth, expected["documentId"]),
            document_id=expected["documentId"],
        )
        assert projected.model_dump(mode="json", by_alias=True) == expected


def test_replay_profile_is_byte_identical_and_semantically_identical(
    positive_fixtures: list[dict[str, Any]],
) -> None:
    replay_entries = sorted(
        [entry for entry in positive_fixtures if entry["profileId"] == "10"],
        key=lambda entry: entry["replayOrdinal"],
    )
    assert [entry["replayOrdinal"] for entry in replay_entries] == [1, 2]
    assert len({entry["replayGroupId"] for entry in replay_entries}) == 1
    assert replay_entries[0]["pdfSha256"] == replay_entries[1]["pdfSha256"]
    assert _catalog_path(replay_entries[0]["filePath"]).read_bytes() == _catalog_path(
        replay_entries[1]["filePath"]
    ).read_bytes()

    expected = [load_json(_catalog_path(entry["expectedResultPath"])) for entry in replay_entries]
    for payload in expected:
        payload.pop("documentId")
        payload.pop("resultId")
    assert expected[0] == expected[1]

    non_replay_hashes = [entry["pdfSha256"] for entry in positive_fixtures if entry["profileId"] != "10"]
    assert len(non_replay_hashes) == len(set(non_replay_hashes)) == 18


def test_pdf_content_matches_ground_truth(
    positive_fixtures: list[dict[str, Any]],
) -> None:
    for entry in positive_fixtures:
        expected = load_json(_catalog_path(entry["expectedResultPath"]))
        reader = PdfReader(_catalog_path(entry["filePath"]))
        assert not reader.is_encrypted
        assert_no_active_pdf_content(reader)
        assert len(reader.pages) == entry["pageCount"]

        page_texts = [page.extract_text() for page in reader.pages]
        assert all(text.strip() for text in page_texts)
        assert len(page_texts) == len(set(page_texts))
        for page_number, text in enumerate(page_texts, start=1):
            assert "SYNTHETIC TEST FIXTURE" in text
            assert "NOT REAL CUSTOMER DATA" in text
            assert f"PAGE {page_number} OF {len(page_texts)}" in text
            assert "\\n" not in text
            assert max((len(line) for line in text.splitlines()), default=0) <= 74

        full_text = "\n".join(page_texts)
        data = expected["data"]
        for container_name in ("bank", "account", "statement", "balances", "fees"):
            container = data.get(container_name) or {}
            for value in container.values():
                if value is not None:
                    assert str(value) in full_text
        for field_name in ("accountType", "bankCountry", "interestEarned", "interestCharged", "summaryText"):
            if data.get(field_name) is not None:
                assert str(data[field_name]) in full_text
        for transaction in data["transactions"]:
            assert full_text.count(transaction["description"]) == 1
            if transaction["reference"] is not None:
                assert full_text.count(transaction["reference"]) == 1

        if entry["profileId"] == "02":
            assert all("SYNTHETIC TEST TRANSACTION" in text for text in page_texts)


@pytest.mark.parametrize("payload_kind", ["javascript", "attachment"])
def test_pdf_structure_walker_rejects_indirect_active_content(payload_kind: str) -> None:
    writer = PdfWriter()
    writer.add_blank_page(width=612, height=792)
    if payload_kind == "javascript":
        writer.add_js("app.alert('synthetic')")
    else:
        writer.add_attachment("synthetic.txt", b"synthetic")
    stream = io.BytesIO()
    writer.write(stream)
    with pytest.raises(AssertionError, match="active PDF"):
        assert_no_active_pdf_content(PdfReader(io.BytesIO(stream.getvalue())))


def test_exact_hashes_sizes_and_generator_provenance(catalog: dict[str, Any]) -> None:
    generator_sha = hashlib.sha256(GENERATOR_PATH.read_bytes()).hexdigest()
    for entry in catalog["fixtures"]:
        file_bytes = _catalog_path(entry["filePath"]).read_bytes()
        source_bytes = _catalog_path(entry["sourceSpecPath"]).read_bytes()
        assert hashlib.sha256(source_bytes).hexdigest() == entry["sourceSpecSha256"]
        assert entry["generatorSourceSha256"] == generator_sha
        if entry["positiveOrNegative"] == "POSITIVE":
            assert len(file_bytes) == entry["byteSize"]
            assert hashlib.sha256(file_bytes).hexdigest() == entry["pdfSha256"]
            expected_bytes = _catalog_path(entry["expectedResultPath"]).read_bytes()
            assert hashlib.sha256(expected_bytes).hexdigest() == entry["expectedResultSha256"]
        else:
            assert len(file_bytes) == entry["controlSpecByteSize"]
            assert hashlib.sha256(file_bytes).hexdigest() == entry["controlSpecSha256"]


def test_no_orphan_files(catalog: dict[str, Any]) -> None:
    registered = {
        CATALOG_PATH.resolve(),
        CATALOG_SCHEMA_PATH.resolve(),
        CONTROL_SCHEMA_PATH.resolve(),
        PROFILE_SCHEMA_PATH.resolve(),
        (FIXTURE_DIR / "README.md").resolve(),
    }
    for entry in catalog["fixtures"]:
        registered.add(_catalog_path(entry["filePath"]))
        registered.add(_catalog_path(entry["sourceSpecPath"]))
        if "expectedResultPath" in entry:
            registered.add(_catalog_path(entry["expectedResultPath"]))
    actual = {path.resolve() for path in FIXTURE_DIR.rglob("*") if path.is_file() and path.name != ".DS_Store"}
    assert actual == registered


def _generated_manifest(directory: Path) -> dict[str, str]:
    return {
        path.relative_to(directory).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in directory.rglob("*")
        if path.is_file() and (path.parent.name in {"pdf", "expected", "controls"} or path.name == "catalog.json")
    }


def test_two_directory_determinism() -> None:
    with tempfile.TemporaryDirectory() as first, tempfile.TemporaryDirectory() as second:
        first_path = Path(first)
        second_path = Path(second)
        for output in (first_path, second_path):
            subprocess.run(
                [sys.executable, str(GENERATOR_PATH), "--output-dir", str(output)],
                check=True,
                capture_output=True,
                text=True,
            )
        first_manifest = _generated_manifest(first_path)
        second_manifest = _generated_manifest(second_path)
        committed_manifest = _generated_manifest(FIXTURE_DIR)
        assert first_manifest == second_manifest == committed_manifest


@pytest.mark.parametrize("managed_directory", ["pdf", "expected", "controls"])
def test_generator_check_rejects_orphan_artifacts(managed_directory: str) -> None:
    with tempfile.TemporaryDirectory() as output:
        output_path = Path(output)
        subprocess.run(
            [sys.executable, str(GENERATOR_PATH), "--output-dir", str(output_path)],
            check=True,
            capture_output=True,
            text=True,
        )
        orphan = output_path / managed_directory / "orphan.fixture"
        orphan.write_bytes(b"orphan")
        completed = subprocess.run(
            [sys.executable, str(GENERATOR_PATH), "--check", "--output-dir", str(output_path)],
            check=False,
            capture_output=True,
            text=True,
        )
        assert completed.returncode == 1
        assert f"{managed_directory}/orphan.fixture" in completed.stdout


def test_catalog_schema_rejects_cross_variant_mutations(catalog: dict[str, Any]) -> None:
    validator = jsonschema.Draft202012Validator(load_json(CATALOG_SCHEMA_PATH))
    positive_index = next(
        index
        for index, entry in enumerate(catalog["fixtures"])
        if entry["positiveOrNegative"] == "POSITIVE"
    )
    negative_index = next(
        index
        for index, entry in enumerate(catalog["fixtures"])
        if entry["positiveOrNegative"] == "NEGATIVE"
    )
    mutations = []

    empty = copy.deepcopy(catalog)
    empty["fixtures"] = []
    mutations.append(empty)
    for field, value in (
        ("filePath", "/tmp/escape.pdf"),
        ("mimeType", "text/plain"),
        ("expectedErrorCode", "NOT_FOUND"),
    ):
        mutated = copy.deepcopy(catalog)
        mutated["fixtures"][positive_index][field] = value
        mutations.append(mutated)
    negative_with_pdf_fields = copy.deepcopy(catalog)
    negative_with_pdf_fields["fixtures"][negative_index]["pdfSha256"] = "a" * 64
    mutations.append(negative_with_pdf_fields)
    duplicate = copy.deepcopy(catalog)
    duplicate["fixtures"][-1] = copy.deepcopy(duplicate["fixtures"][0])
    mutations.append(duplicate)

    for mutated in mutations:
        assert list(validator.iter_errors(mutated)), mutated


def test_control_schema_rejects_incomplete_or_mismatched_steps(
    catalog: dict[str, Any],
) -> None:
    validator = jsonschema.Draft202012Validator(load_json(CONTROL_SCHEMA_PATH))
    positive_by_id = {
        entry["fixtureId"]: entry
        for entry in catalog["fixtures"]
        if entry["positiveOrNegative"] == "POSITIVE"
    }
    controls = {
        control_id: load_json(
            FIXTURE_DIR / f"controls/gug364_bank_statement_{control_id}.json"
        )
        for control_id in ("ctrl_01", "ctrl_02", "ctrl_03", "ctrl_05", "ctrl_06", "ctrl_07")
    }
    mutations: list[dict[str, Any]] = []

    missing_status_input = copy.deepcopy(controls["ctrl_01"])
    missing_status_input["steps"][1].pop("internalStatus")
    mutations.append(missing_status_input)

    unbound_create = copy.deepcopy(controls["ctrl_03"])
    unbound_create["steps"][0].pop("inputFixtureId")
    mutations.append(unbound_create)

    irrelevant_create_field = copy.deepcopy(controls["ctrl_03"])
    irrelevant_create_field["steps"][0]["artifact"] = {
        "encoding": "base64",
        "value": "AA==",
        "sha256": "0" * 64,
        "byteSize": 1,
    }
    mutations.append(irrelevant_create_field)

    missing_reconcile_target = copy.deepcopy(controls["ctrl_06"])
    missing_reconcile_target["steps"][1].pop("targetOperation")
    mutations.append(missing_reconcile_target)

    missing_document_reference = copy.deepcopy(controls["ctrl_07"])
    missing_document_reference["steps"][1].pop("documentIdFromStep")
    mutations.append(missing_document_reference)

    unknown_control = copy.deepcopy(controls["ctrl_03"])
    unknown_control["controlId"] = "ctrl_99"
    mutations.append(unknown_control)

    wrong_operation = copy.deepcopy(controls["ctrl_03"])
    wrong_operation["steps"] = copy.deepcopy(controls["ctrl_02"]["steps"])
    mutations.append(wrong_operation)

    duplicate_step_id = copy.deepcopy(controls["ctrl_05"])
    duplicate_step_id["steps"][1]["stepId"] = duplicate_step_id["steps"][0]["stepId"]
    mutations.append(duplicate_step_id)

    mismatched_idempotency_key = copy.deepcopy(controls["ctrl_05"])
    mismatched_idempotency_key["steps"][1]["idempotencyKey"] = (
        "00000000-0000-4000-8000-000000000099"
    )
    mutations.append(mismatched_idempotency_key)

    missing_discard = copy.deepcopy(controls["ctrl_06"])
    missing_discard["steps"][0].pop("discardResponse")
    mutations.append(missing_discard)

    dangling_document_reference = copy.deepcopy(controls["ctrl_07"])
    dangling_document_reference["steps"][1]["documentIdFromStep"] = "missing-step"
    mutations.append(dangling_document_reference)

    empty_invariants = copy.deepcopy(controls["ctrl_06"])
    empty_invariants["invariants"] = {}
    mutations.append(empty_invariants)

    malformed_replaced_with_blank = copy.deepcopy(controls["ctrl_01"])
    malformed_replaced_with_blank["steps"][0]["artifact"] = copy.deepcopy(
        controls["ctrl_02"]["steps"][0]["artifact"]
    )
    mutations.append(malformed_replaced_with_blank)

    evaluation_before_status = copy.deepcopy(controls["ctrl_01"])
    evaluation_before_status["steps"][1]["evaluationTime"] = "2025-12-31T23:59:00+00:00"
    mutations.append(evaluation_before_status)

    blank_replaced_with_malformed = copy.deepcopy(controls["ctrl_02"])
    blank_replaced_with_malformed["steps"][0]["artifact"] = copy.deepcopy(
        controls["ctrl_01"]["steps"][0]["artifact"]
    )
    mutations.append(blank_replaced_with_malformed)

    wrong_bound_length = copy.deepcopy(controls["ctrl_03"])
    wrong_bound_length["steps"][0]["request"]["contentLength"] = 1
    mutations.append(wrong_bound_length)

    conflict_same_filename = copy.deepcopy(controls["ctrl_05"])
    conflict_same_filename["steps"][1]["request"]["filename"] = (
        conflict_same_filename["steps"][0]["request"]["filename"]
    )
    mutations.append(conflict_same_filename)

    conflict_wrong_mime = copy.deepcopy(controls["ctrl_05"])
    conflict_wrong_mime["steps"][1]["request"]["contentType"] = "text/plain"
    mutations.append(conflict_wrong_mime)

    conflict_wrong_length = copy.deepcopy(controls["ctrl_05"])
    conflict_wrong_length["steps"][1]["request"]["contentLength"] += 1
    mutations.append(conflict_wrong_length)

    replay_different_request = copy.deepcopy(controls["ctrl_06"])
    replay_different_request["steps"][2]["request"]["filename"] = "different.pdf"
    mutations.append(replay_different_request)

    replay_wrong_mime = copy.deepcopy(controls["ctrl_06"])
    replay_wrong_mime["steps"][2]["request"]["contentType"] = "text/plain"
    mutations.append(replay_wrong_mime)

    authorization_wrong_mime = copy.deepcopy(controls["ctrl_07"])
    authorization_wrong_mime["steps"][0]["request"]["contentType"] = "text/plain"
    mutations.append(authorization_wrong_mime)

    same_actor = copy.deepcopy(controls["ctrl_07"])
    same_actor["principals"]["otherActor"] = copy.deepcopy(same_actor["principals"]["owner"])
    mutations.append(same_actor)

    same_deployment = copy.deepcopy(controls["ctrl_07"])
    same_deployment["principals"]["otherDeployment"] = copy.deepcopy(
        same_deployment["principals"]["owner"]
    )
    mutations.append(same_deployment)

    for mutated in mutations:
        if not list(validator.iter_errors(mutated)):
            with pytest.raises((AssertionError, KeyError, ValueError)):
                assert_control_recipe_semantics(mutated, positive_by_id)


@pytest.mark.parametrize(
    ("kind", "value"),
    [
        ("email", "alice@example.com"),
        ("phone", "555-123-4567"),
        ("phone", "5551234567"),
        ("phone", "555.123.4567"),
        ("ssn", "123-45-6789"),
        ("aws_account", "123456789012"),
        ("aws_arn", "arn:aws:iam::123456789012:role/example"),
        ("payment_card", "4111 1111 1111 1111"),
        ("clabe", "032180000" + "118359719"),
    ],
)
def test_privacy_scanner_rejects_mutations(kind: str, value: str) -> None:
    assert kind in find_prohibited_data(value)


def test_corpus_contains_no_prohibited_data() -> None:
    for path in FIXTURE_DIR.rglob("*"):
        if not path.is_file() or path.name == ".DS_Store":
            continue
        if path.suffix == ".json":
            for value in _iter_json_content(load_json(path)):
                assert not find_prohibited_data(value), f"Prohibited pattern in {path}: {value!r}"
        elif path.suffix == ".pdf":
            reader = PdfReader(path)
            for page in reader.pages:
                assert not find_prohibited_data(page.extract_text()), path
            info = reader.metadata
            if info is not None:
                for value in info.values():
                    metadata_value = str(value)
                    if metadata_value in {
                        "D:20260101000000Z",
                        "Scanalyze Test Generator",
                    }:
                        continue
                    assert not find_prohibited_data(metadata_value), path
            assert "Scanalyze Test Generator" in str((info or {}).get("/Producer", ""))
        elif path.suffix == ".md":
            assert not find_prohibited_data(path.read_text(encoding="utf-8")), path


def _decode_artifact(step: dict[str, Any]) -> bytes:
    artifact = step["artifact"]
    payload = base64.b64decode(artifact["value"], validate=True)
    assert len(payload) == artifact["byteSize"]
    assert hashlib.sha256(payload).hexdigest() == artifact["sha256"]
    return payload


def _auth_from_recipe(recipe: dict[str, Any], name: str):
    principal = recipe["principals"][name]
    return journey_harness._auth(
        actor=principal["subject"],
        customer=principal["customerId"],
        deployment=principal["deploymentId"],
    )


def _assert_http_error(response: Any, expected: dict[str, Any]) -> None:
    assert response.status_code == expected["httpStatus"]
    body = response.json()
    assert body["schemaVersion"] == "scanalyze.error.v1"
    assert body["code"] == expected["code"]
    assert body["retryClass"] == expected["retryClass"]
    assert body["correlationId"].startswith("ref_")


def test_artifact_controls_execute_against_pdf_and_status_contracts() -> None:
    malformed = load_json(FIXTURE_DIR / "controls/gug364_bank_statement_ctrl_01.json")
    parse_step = malformed["steps"][0]
    with pytest.raises(Exception):
        PdfReader(io.BytesIO(_decode_artifact(parse_step)), strict=True)
    status_step = malformed["steps"][1]
    projected = adapt_internal_document_status(
        status_step["internalStatus"],
        now=datetime.fromisoformat(status_step["evaluationTime"]),
    )
    expected = status_step["expect"]
    assert projected.lifecycle is DocumentLifecycle(expected["lifecycle"])
    assert projected.safe_failure_code is SafeFailureCode(expected["safeFailureCode"])
    assert projected.failure_disposition is FailureDisposition(expected["failureDisposition"])
    assert malformed["evidenceState"] == "NONPROD_REQUIRED"
    assert malformed["invariants"]["causalRuntimeOutcomeProven"] is False

    blank = load_json(FIXTURE_DIR / "controls/gug364_bank_statement_ctrl_02.json")
    blank_step = blank["steps"][0]
    reader = PdfReader(io.BytesIO(_decode_artifact(blank_step)), strict=True)
    extracted = "".join(page.extract_text() for page in reader.pages)
    assert len(extracted.strip()) <= blank_step["expect"]["maximumTextCharacters"]
    assert blank["evidenceState"] == "NOT_PROVEN"
    assert blank["invariants"]["terminalRuntimeOutcomeClaimed"] is False


@pytest.mark.parametrize("control_number", [3, 4, 5, 6, 7, 8])
def test_journey_control_recipes_execute_production_http_router(
    control_number: int,
    positive_fixtures: list[dict[str, Any]],
) -> None:
    recipe = load_json(
        FIXTURE_DIR / f"controls/gug364_bank_statement_ctrl_{control_number:02d}.json"
    )
    service, _operations, _batches, documents, _s3, _clock = journey_harness._service()
    positive_by_id = {entry["fixtureId"]: entry for entry in positive_fixtures}
    auth_state = {"value": _auth_from_recipe(recipe, "owner")}

    def current_auth():
        return auth_state["value"]

    application = FastAPI()
    application.include_router(journey_routes.router)
    register_exception_handlers(application)
    application.dependency_overrides[journey_routes._svc] = lambda: service
    for dependency in (
        journey_routes._CREATE_DOCUMENT_ACCESS,
        journey_routes._READ_DOCUMENT_ACCESS,
        journey_routes._reconciliation_access,
    ):
        application.dependency_overrides[dependency] = current_auth

    created_ids: list[str] = []
    document_ids_by_step: dict[str, str] = {}

    with TestClient(application, raise_server_exceptions=False) as client:
        for step in recipe["steps"]:
            operation = step["operation"]
            expected = step["expect"]
            auth_state["value"] = _auth_from_recipe(recipe, step["principal"])
            headers = {CONTRACT_HEADER: CONTRACT_VERSION}

            if operation == "documents.create":
                assert step["inputFixtureId"] in recipe["inputFixtureIds"]
                input_entry = positive_by_id[step["inputFixtureId"]]
                input_bytes = _catalog_path(input_entry["filePath"]).read_bytes()
                assert hashlib.sha256(input_bytes).hexdigest() == input_entry["pdfSha256"]
                declared_length = step["request"]["contentLength"]
                if declared_length <= MAX_DOCUMENT_BYTES:
                    assert declared_length == len(input_bytes)
                else:
                    assert declared_length == MAX_DOCUMENT_BYTES + 1

                headers[IDEMPOTENCY_HEADER] = step["idempotencyKey"]
                response = client.post(
                    "/api/v2/documents",
                    headers=headers,
                    json=step["request"],
                )
                if expected["kind"] == "errorEnvelope":
                    _assert_http_error(response, expected)
                    continue

                assert expected["kind"] == "documentCreateResponse"
                assert response.status_code == expected["httpStatus"]
                if step.get("discardResponse", False):
                    continue
                body = response.json()
                assert body["replayed"] is expected["replayed"]
                document_id = body["durableResponse"]["documentId"]
                created_ids.append(document_id)
                document_ids_by_step[step["stepId"]] = document_id
            elif operation == "operations.reconcile":
                headers[IDEMPOTENCY_HEADER] = step["idempotencyKey"]
                operation_path = {"DOCUMENT_CREATE": "documents.create"}[
                    step["targetOperation"]
                ]
                response = client.post(
                    f"/api/v2/operations/{operation_path}/reconciliation",
                    headers=headers,
                )
                assert response.status_code == expected["httpStatus"]
                body = response.json()
                assert body["ledgerState"] == expected["ledgerState"]
                document_id = body["durableResponse"]["documentId"]
                created_ids.append(document_id)
                document_ids_by_step[step["stepId"]] = document_id
            elif operation == "documents.get_status":
                document_id = document_ids_by_step[step["documentIdFromStep"]]
                response = client.get(
                    f"/api/v2/documents/{document_id}",
                    headers=headers,
                )
                _assert_http_error(response, expected)
            else:
                raise AssertionError(f"Unsupported recipe operation: {operation}")

    assert documents.create_effects == recipe["invariants"]["documentCreateEffects"]
    if recipe["invariants"].get("sameDocumentId"):
        assert len(set(created_ids)) == 1


def test_contract_limits_and_control_claims_are_exact() -> None:
    assert MAX_DOCUMENT_BYTES == 536_870_912
    catalog = load_json(CATALOG_PATH)
    negative = {
        entry["profileId"]: entry
        for entry in catalog["fixtures"]
        if entry["positiveOrNegative"] == "NEGATIVE"
    }
    assert negative["ctrl_01"]["expectedHttpStatus"] == 200
    assert negative["ctrl_01"]["expectedSafeFailureCode"] == "OCR_FAILED"
    assert negative["ctrl_01"]["lifecycleApplicability"] == "APPLICABLE"
    assert negative["ctrl_02"]["evidenceState"] == "NOT_PROVEN"
    assert (
        negative["ctrl_02"]["lifecycleApplicability"]
        == "UNDEFINED_BY_CURRENT_CONTRACT"
    )
    assert {
        negative[control_id]["lifecycleApplicability"]
        for control_id in ("ctrl_03", "ctrl_04", "ctrl_05", "ctrl_06", "ctrl_07", "ctrl_08")
    } == {"NOT_APPLICABLE"}
    assert negative["ctrl_03"]["expectedHttpStatus"] == 422
    assert negative["ctrl_04"]["expectedHttpStatus"] == 422
    assert negative["ctrl_07"]["expectedErrorCode"] == "NOT_FOUND"
    assert negative["ctrl_08"]["expectedErrorCode"] == "NOT_FOUND"
