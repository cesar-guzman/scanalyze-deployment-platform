"""Synthetic, offline tests of Batch checksum consistency, never custody."""

from __future__ import annotations

import base64
import copy
import csv
from dataclasses import replace
from datetime import UTC, datetime
import hashlib
import io
import json
from urllib.parse import quote

import pytest

from tooling.platform_authority_bootstrap_batch_checksum import (
    ACCOUNT_ID,
    REGION,
    ERROR_THEN_HTTP_SCHEMA,
    HTTP_THEN_ERROR_SCHEMA,
    MAX_MANIFEST_BYTES,
    MAX_REPORT_CSV_BYTES,
    MAX_REPORT_MANIFEST_BYTES,
    MAX_SIGNED_OBJECT_BYTES,
    BatchChecksumBinding,
    BatchChecksumError,
    ObjectVersion,
    validate_batch_checksum_readbacks,
)


def _csv(fields: list[str]) -> bytes:
    output = io.StringIO(newline="")
    csv.writer(output, lineterminator="\n").writerow(fields)
    return output.getvalue().encode("utf-8")


def _json(value: object) -> bytes:
    return json.dumps(value, separators=(",", ":")).encode("utf-8")


def _arguments(schema: str = ERROR_THEN_HTTP_SCHEMA) -> dict:
    job_id = "11111111-2222-4333-8444-555555555555"
    signed = ObjectVersion("synthetic-artifacts-7644", "signed/synthetic.zip", "SignedVersion1")
    manifest = ObjectVersion("synthetic-evidence-7644", "input/one.csv", "ManifestVersion1")
    root = f"checksum/job-{job_id}"
    binding = BatchChecksumBinding(
        job_id=job_id,
        role_arn=f"arn:aws:iam::{ACCOUNT_ID}:role/SyntheticBatchChecksum",
        signed_object=signed,
        signed_etag='"Synthetic-Opaque-ETag"',
        manifest=manifest,
        manifest_etag='"11111111111111111111111111111111"',
        report_bucket="synthetic-evidence-7644",
        report_prefix="checksum",
        report_manifest=ObjectVersion("synthetic-evidence-7644", root + "/manifest.json", "ReportManifestVersion1"),
        report_csv=ObjectVersion("synthetic-evidence-7644", root + "/results/one.csv", "ReportCSVVersion1"),
        report_schema=schema,
    )
    blob = b"synthetic signed bytes, not a real ZIP or signature"
    checksum = {
        "checksum_base64": base64.b64encode(hashlib.sha256(blob).digest()).decode("ascii"),
        "checksum_hex": hashlib.sha256(blob).hexdigest().upper(),
        "checksumAlgorithm": "SHA256",
        "checksumType": "FULL_OBJECT",
        "etag": "Synthetic-Opaque-ETag",
    }
    row = {"Bucket": signed.bucket, "Key": signed.key, "VersionId": signed.version_id,
           "TaskStatus": "succeeded", "ErrorCode": "", "HTTPStatusCode": "200",
           "ResultMessage": _json(checksum).decode("utf-8")}
    csv_bytes = _csv([row[field] for field in schema.split(", ")])
    report_manifest = {
        "Format": "Report_CSV_20180820",
        "ReportCreationDate": "2030-01-01T00:01:00Z",
        "ReportSchema": schema,
        "Results": [{"TaskExecutionStatus": "succeeded", "Bucket": binding.report_bucket,
                     "Key": binding.report_csv.key,
                     "MD5Checksum": hashlib.md5(csv_bytes, usedforsecurity=False).hexdigest()}],
    }
    job = {
        "JobId": job_id, "JobArn": f"arn:aws:s3:{REGION}:{ACCOUNT_ID}:job/{job_id}",
        "RoleArn": binding.role_arn,
        "Manifest": {"Location": {"ObjectArn": f"arn:aws:s3:::{manifest.bucket}/{manifest.key}",
                                   "ETag": binding.manifest_etag, "ObjectVersionId": manifest.version_id},
                     "Spec": {"Format": "S3BatchOperations_CSV_20180820", "Fields": ["Bucket", "Key", "VersionId"]}},
        "Operation": {"S3ComputeObjectChecksum": {"ChecksumAlgorithm": "SHA256", "ChecksumType": "FULL_OBJECT"}},
        "Report": {"Bucket": f"arn:aws:s3:::{binding.report_bucket}", "Enabled": True,
                   "ExpectedBucketOwner": ACCOUNT_ID, "Format": "Report_CSV_20180820",
                   "Prefix": binding.report_prefix, "ReportScope": "AllTasks"},
        "ProgressSummary": {"TotalNumberOfTasks": 1, "NumberOfTasksSucceeded": 1, "NumberOfTasksFailed": 0},
        "Status": "Complete", "CreationTime": datetime(2030, 1, 1, tzinfo=UTC),
        "TerminationDate": datetime(2030, 1, 1, 0, 2, tzinfo=UTC),
    }
    return {
        "job": job, "binding": binding,
        "manifest_bytes": _csv([signed.bucket, signed.key, signed.version_id]),
        "report_manifest_bytes": _json(report_manifest),
        "report_csv_bytes": csv_bytes, "signed_object_bytes": blob,
    }


def _replace_report_csv(args: dict, raw: bytes) -> None:
    args["report_csv_bytes"] = raw
    manifest = json.loads(args["report_manifest_bytes"])
    manifest["Results"][0]["MD5Checksum"] = hashlib.md5(raw, usedforsecurity=False).hexdigest()
    args["report_manifest_bytes"] = _json(manifest)


def _replace_report_row(args: dict, **changes: str) -> None:
    schema = args["binding"].report_schema.split(", ")
    row = dict(zip(schema, next(csv.reader(io.StringIO(args["report_csv_bytes"].decode()))), strict=True))
    row.update(changes)
    _replace_report_csv(args, _csv([row[key] for key in schema]))


def _replace_checksum(args: dict, **changes: object) -> None:
    row = next(csv.reader(io.StringIO(args["report_csv_bytes"].decode())))
    checksum = json.loads(row[-1])
    checksum.update(changes)
    _replace_report_row(args, ResultMessage=_json(checksum).decode())


@pytest.mark.parametrize("schema", [ERROR_THEN_HTTP_SCHEMA, HTTP_THEN_ERROR_SCHEMA])
def test_exact_provider_readback_consistency_under_explicit_dialect(schema: str) -> None:
    args = _arguments(schema)
    original = copy.deepcopy(args)
    evidence = validate_batch_checksum_readbacks(**args)
    assert args == original
    assert evidence["checksum"] == {
        "algorithm": "SHA256", "type": "FULL_OBJECT",
        "base64": base64.b64encode(hashlib.sha256(args["signed_object_bytes"]).digest()).decode(),
        "hex": hashlib.sha256(args["signed_object_bytes"]).hexdigest(),
    }
    assert evidence["manifest"]["version_id"] == "ManifestVersion1"
    assert evidence["report"]["csv"]["version_id"] == "ReportCSVVersion1"
    assert evidence["report"]["csv"]["sha256"] == hashlib.sha256(args["report_csv_bytes"]).hexdigest()
    assert evidence["report"]["manifest"]["sha256"] == hashlib.sha256(args["report_manifest_bytes"]).hexdigest()
    assert evidence["input_format"] == "s3_batch_operations_completion_report"
    assert evidence["validation_scope"] == "syntax_and_content_consistency_only"
    assert evidence["signed_object"]["etag"] == '"Synthetic-Opaque-ETag"'
    assert evidence["report"]["result_etag"] == "Synthetic-Opaque-ETag"
    assert not {"evidence_origin", "receipt_digest", "authorized", "production_status", "custody_verified"} & set(evidence)


@pytest.mark.parametrize(("field", "value"), [
    ("JobId", "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"),
    ("JobArn", f"arn:aws:s3:us-west-2:{ACCOUNT_ID}:job/11111111-2222-4333-8444-555555555555"),
    ("JobArn", "arn:aws:s3:us-east-1:999900001111:job/11111111-2222-4333-8444-555555555555"),
    ("RoleArn", f"arn:aws:iam::{ACCOUNT_ID}:role/OtherWriter"),
    ("Status", "Completing"), ("Status", "Failed"),
    ("FailureReasons", [{"FailureCode": "SyntheticFailure", "FailureReason": "synthetic"}]),
    ("ManifestGenerator", {}), ("GeneratedManifestDescriptor", {}),
    ("ConfirmationRequired", 1), ("Priority", True), ("Priority", -1),
])
def test_rejects_wrong_or_open_job(field: str, value: object) -> None:
    args = _arguments()
    args["job"][field] = value
    with pytest.raises(BatchChecksumError):
        validate_batch_checksum_readbacks(**args)


@pytest.mark.parametrize("field", ["TotalNumberOfTasks", "NumberOfTasksSucceeded", "NumberOfTasksFailed"])
@pytest.mark.parametrize("value", [None, True, 1.0, 2, -1])
def test_counts_require_exact_typed_single_success(field: str, value: object) -> None:
    args = _arguments()
    args["job"]["ProgressSummary"][field] = value
    with pytest.raises(BatchChecksumError):
        validate_batch_checksum_readbacks(**args)


@pytest.mark.parametrize(("algorithm", "coverage"), [
    ("CRC64NVME", "FULL_OBJECT"), ("SHA1", "FULL_OBJECT"),
    ("SHA256", "COMPOSITE"), ("UNKNOWN", "FULL_OBJECT"),
])
def test_no_algorithm_or_coverage_downgrade(algorithm: str, coverage: str) -> None:
    args = _arguments()
    args["job"]["Operation"]["S3ComputeObjectChecksum"] = {"ChecksumAlgorithm": algorithm, "ChecksumType": coverage}
    with pytest.raises(BatchChecksumError, match="OPERATION_INVALID"):
        validate_batch_checksum_readbacks(**args)
    args = _arguments()
    _replace_checksum(args, checksumAlgorithm=algorithm, checksumType=coverage)
    with pytest.raises(BatchChecksumError, match="ALGORITHM_INVALID"):
        validate_batch_checksum_readbacks(**args)


def test_no_extra_operation_or_manifest_field() -> None:
    args = _arguments()
    args["job"]["Operation"]["S3PutObjectCopy"] = {}
    with pytest.raises(BatchChecksumError):
        validate_batch_checksum_readbacks(**args)
    args = _arguments()
    args["job"]["Manifest"]["Location"]["Extra"] = "synthetic"
    with pytest.raises(BatchChecksumError):
        validate_batch_checksum_readbacks(**args)


@pytest.mark.parametrize(("section", "field", "value"), [
    ("Location", "ObjectVersionId", "OtherVersion"), ("Location", "ObjectVersionId", "null"),
    ("Location", "ETag", "OtherETag"), ("Location", "ObjectArn", "arn:aws:s3:::other/input.csv"),
    ("Spec", "Fields", ["Bucket", "Key"]), ("Spec", "Format", "S3InventoryReport_CSV_20161130"),
])
def test_manifest_descriptor_is_exact(section: str, field: str, value: object) -> None:
    args = _arguments()
    args["job"]["Manifest"][section][field] = value
    with pytest.raises(BatchChecksumError):
        validate_batch_checksum_readbacks(**args)


@pytest.mark.parametrize(("field", "value"), [
    ("ExpectedBucketOwner", "999900001111"), ("Bucket", "arn:aws:s3:::other-evidence"),
    ("Prefix", "other-prefix"), ("ReportScope", "FailedTasksOnly"),
    ("Enabled", False), ("Enabled", 1), ("Format", "UNKNOWN"),
])
def test_report_configuration_is_exact(field: str, value: object) -> None:
    args = _arguments()
    args["job"]["Report"][field] = value
    with pytest.raises(BatchChecksumError):
        validate_batch_checksum_readbacks(**args)


@pytest.mark.parametrize("report", [None, True, 1, [], "SYNTHETIC-INVALID-REPORT"])
def test_report_configuration_requires_mapping(report: object) -> None:
    args = _arguments()
    args["job"]["Report"] = report
    with pytest.raises(BatchChecksumError, match="^BATCH_CHECKSUM_REPORT_INVALID$"):
        validate_batch_checksum_readbacks(**args)


def test_non_mapping_report_cannot_claim_equality() -> None:
    class EqualToAnything:
        def __eq__(self, other: object) -> bool:
            raise AssertionError("Equality must not run on a non-mapping report")

        def __ne__(self, other: object) -> bool:
            raise AssertionError("Equality must not run on a non-mapping report")

    args = _arguments()
    args["job"]["Report"] = EqualToAnything()
    with pytest.raises(BatchChecksumError, match="^BATCH_CHECKSUM_REPORT_INVALID$"):
        validate_batch_checksum_readbacks(**args)


@pytest.mark.parametrize("etag", [
    "Different-Opaque-ETag", "synthetic-opaque-etag", '"Synthetic-Opaque-ETag"',
    " Synthetic-Opaque-ETag", "Synthetic-Opaque-ETag ", "Synthetic-\"Opaque-ETag",
])
def test_report_etag_must_equal_exact_unquoted_head_token(etag: str) -> None:
    args = _arguments()
    _replace_checksum(args, etag=etag)
    with pytest.raises(BatchChecksumError, match="ETAG_MISMATCH"):
        validate_batch_checksum_readbacks(**args)


@pytest.mark.parametrize("etag", [
    None, True, "", '""', "Synthetic-Opaque-ETag", '"Synthetic-Opaque-ETag',
    'Synthetic-Opaque-ETag"', '""Synthetic-Opaque-ETag""',
    '"Synthetic-\"Opaque-ETag"', '"Synthetic-\nOpaque-ETag"',
])
def test_bound_head_etag_requires_one_ascii_wrapper(etag: object) -> None:
    args = _arguments()
    args["binding"] = replace(args["binding"], signed_etag=etag)
    with pytest.raises(BatchChecksumError):
        validate_batch_checksum_readbacks(**args)


def test_self_consistent_checksum_does_not_supply_authority() -> None:
    args = _arguments()
    blob = b"entirely caller-provided synthetic bytes"
    args["signed_object_bytes"] = blob
    _replace_checksum(
        args, checksum_base64=base64.b64encode(hashlib.sha256(blob).digest()).decode(),
        checksum_hex=hashlib.sha256(blob).hexdigest(),
    )
    result = validate_batch_checksum_readbacks(**args)
    assert result["validation_scope"] == "syntax_and_content_consistency_only"
    assert set(result) == {
        "input_format", "validation_scope", "account_id", "region", "job",
        "signed_object", "checksum", "manifest", "report",
    }


@pytest.mark.parametrize("section", ["job", "report_manifest", "checksum"])
@pytest.mark.parametrize(("field", "value"), [
    ("receipt_digest", "a" * 64), ("authorized", True), ("custody_verified", True),
])
def test_caller_digest_or_boolean_cannot_promote_consistency_to_receipt(
    section: str, field: str, value: object,
) -> None:
    args = _arguments()
    if section == "job":
        args["job"][field] = value
    elif section == "report_manifest":
        document = json.loads(args["report_manifest_bytes"])
        document[field] = value
        args["report_manifest_bytes"] = _json(document)
    else:
        _replace_checksum(args, **{field: value})
    with pytest.raises(BatchChecksumError, match="SHAPE_INVALID"):
        validate_batch_checksum_readbacks(**args)


@pytest.mark.parametrize("field", ["signed_object", "manifest", "report_manifest", "report_csv"])
@pytest.mark.parametrize("version", ["", "null", "latest", "$LATEST", " a-version", "a\nversion"])
def test_all_bound_objects_require_real_opaque_versions(field: str, version: str) -> None:
    args = _arguments()
    args["binding"] = replace(args["binding"], **{field: replace(getattr(args["binding"], field), version_id=version)})
    with pytest.raises(BatchChecksumError):
        validate_batch_checksum_readbacks(**args)


@pytest.mark.parametrize("change", ["role-account", "report-bucket", "wrong-job-prefix", "csv-subdirectory", "dot-path", "input-alias", "schema"])
def test_bindings_reject_ambiguous_or_foreign_locations(change: str) -> None:
    args = _arguments()
    binding = args["binding"]
    if change == "role-account": binding = replace(binding, role_arn="arn:aws:iam::999900001111:role/SyntheticBatchChecksum")
    elif change == "report-bucket": binding = replace(binding, report_csv=replace(binding.report_csv, bucket="other-bucket"))
    elif change == "wrong-job-prefix": binding = replace(binding, report_prefix="other-prefix")
    elif change == "csv-subdirectory": binding = replace(binding, report_csv=replace(binding.report_csv, key=binding.report_csv.key.replace("results/", "results/nested/")))
    elif change == "dot-path": binding = replace(binding, manifest=replace(binding.manifest, key="input/../one.csv"))
    elif change == "input-alias": binding = replace(binding, manifest=binding.signed_object)
    else: binding = replace(binding, report_schema="Bucket,Key,VersionId,TaskStatus,ErrorCode,HTTPStatusCode,ResultMessage")
    args["binding"] = binding
    with pytest.raises(BatchChecksumError):
        validate_batch_checksum_readbacks(**args)


@pytest.mark.parametrize("defect", ["no-version", "wrong-version", "other-key", "duplicate", "extra-row", "blank-row", "bad-quote", "bad-escape", "double-escape"])
def test_single_manifest_row_is_closed_and_exact(defect: str) -> None:
    args = _arguments()
    signed = args["binding"].signed_object
    raw = args["manifest_bytes"]
    if defect == "no-version": raw = _csv([signed.bucket, signed.key])
    elif defect == "wrong-version": raw = _csv([signed.bucket, signed.key, "OtherVersion"])
    elif defect == "other-key": raw = _csv([signed.bucket, "signed/other.zip", signed.version_id])
    elif defect == "duplicate": raw *= 2
    elif defect == "extra-row": raw += b"another-bucket,other-key,another-version\n"
    elif defect == "blank-row": raw += b"\n"
    elif defect == "bad-quote": raw = b'"unterminated'
    elif defect == "bad-escape": raw = _csv([signed.bucket, "signed/%GG.zip", signed.version_id])
    else: raw = _csv([signed.bucket, "signed%252Fsynthetic.zip", signed.version_id])
    args["manifest_bytes"] = raw
    with pytest.raises(BatchChecksumError):
        validate_batch_checksum_readbacks(**args)


def test_canonical_url_encoding_preserves_literal_plus_and_space() -> None:
    args = _arguments()
    signed = replace(args["binding"].signed_object, key="signed/synthetic+ name.zip")
    args["binding"] = replace(args["binding"], signed_object=signed)
    encoded = quote(signed.key, safe="/")
    args["manifest_bytes"] = _csv([signed.bucket, encoded, signed.version_id])
    _replace_report_row(args, Key=encoded)
    assert validate_batch_checksum_readbacks(**args)["signed_object"]["key"] == signed.key


# Keep multi-megabyte boundary inputs out of verbose pytest node IDs.
@pytest.mark.parametrize(("field", "raw"), [
    ("manifest_bytes", b"x" * (MAX_MANIFEST_BYTES + 1)),
    ("report_manifest_bytes", b"x" * (MAX_REPORT_MANIFEST_BYTES + 1)),
    ("report_csv_bytes", b"x" * (MAX_REPORT_CSV_BYTES + 1)),
    ("signed_object_bytes", b"x" * (MAX_SIGNED_OBJECT_BYTES + 1)),
    ("manifest_bytes", b""), ("report_manifest_bytes", b""), ("report_csv_bytes", b""), ("signed_object_bytes", b""),
], ids=[
    "manifest-oversize",
    "report-manifest-oversize",
    "report-csv-oversize",
    "signed-object-oversize",
    "manifest-empty",
    "report-manifest-empty",
    "report-csv-empty",
    "signed-object-empty",
])
def test_bytes_are_nonempty_and_bounded(field: str, raw: bytes) -> None:
    args = _arguments()
    args[field] = raw
    with pytest.raises(BatchChecksumError):
        validate_batch_checksum_readbacks(**args)


@pytest.mark.parametrize("defect", ["duplicate-top", "duplicate-nested", "truncated", "unknown-field", "duplicate-result", "wrong-key", "wrong-bucket", "failed", "md5", "nan", "utf8"])
def test_report_manifest_rejects_malformed_or_substituted_contents(defect: str) -> None:
    args = _arguments()
    document = json.loads(args["report_manifest_bytes"])
    raw = args["report_manifest_bytes"]
    if defect == "duplicate-top": raw = raw.replace(b'{"Format":', b'{"Format":"Report_CSV_20180820","Format":', 1)
    elif defect == "duplicate-nested": raw = raw.replace(b'"TaskExecutionStatus":', b'"TaskExecutionStatus":"succeeded","TaskExecutionStatus":', 1)
    elif defect == "truncated": raw = raw[:-2]
    elif defect == "nan": raw = b'{"x":NaN}'
    elif defect == "utf8": raw = b'\xff'
    else:
        if defect == "unknown-field": document["Other"] = 1
        elif defect == "duplicate-result": document["Results"] *= 2
        elif defect == "wrong-key": document["Results"][0]["Key"] = "other.csv"
        elif defect == "wrong-bucket": document["Results"][0]["Bucket"] = "other-bucket"
        elif defect == "failed": document["Results"][0]["TaskExecutionStatus"] = "failed"
        else: document["Results"][0]["MD5Checksum"] = "0" * 32
        raw = _json(document)
    args["report_manifest_bytes"] = raw
    with pytest.raises(BatchChecksumError):
        validate_batch_checksum_readbacks(**args)


@pytest.mark.parametrize(("field", "value"), [
    ("Bucket", "other-bucket"), ("Key", "signed/other.zip"),
    ("VersionId", "OtherVersion"), ("VersionId", ""),
    ("TaskStatus", "failed"), ("HTTPStatusCode", "204"),
    ("ErrorCode", "SyntheticError"),
])
def test_report_task_remains_exact_even_when_report_transport_md5_is_updated(field: str, value: str) -> None:
    args = _arguments()
    _replace_report_row(args, **{field: value})
    with pytest.raises(BatchChecksumError):
        validate_batch_checksum_readbacks(**args)


@pytest.mark.parametrize("defect", ["duplicate", "truncated", "nul", "bom", "extra-column", "swapped-status-columns"])
def test_report_csv_never_guesses_dialect_or_accepts_extra_data(defect: str) -> None:
    args = _arguments()
    raw = args["report_csv_bytes"]
    if defect == "duplicate": raw *= 2
    elif defect == "truncated": raw = raw[:-8]
    elif defect == "nul": raw += b"\x00"
    elif defect == "bom": raw = b"\xef\xbb\xbf" + raw
    else:
        row = next(csv.reader(io.StringIO(raw.decode())))
        if defect == "extra-column": row.append("extra")
        else: row[4], row[5] = row[5], row[4]
        raw = _csv(row)
    _replace_report_csv(args, raw)
    with pytest.raises(BatchChecksumError):
        validate_batch_checksum_readbacks(**args)


def test_declared_report_schema_cannot_override_reviewed_dialect() -> None:
    args = _arguments()
    document = json.loads(args["report_manifest_bytes"])
    document["ReportSchema"] = HTTP_THEN_ERROR_SCHEMA
    args["report_manifest_bytes"] = _json(document)
    with pytest.raises(BatchChecksumError):
        validate_batch_checksum_readbacks(**args)


@pytest.mark.parametrize(("field", "value"), [
    ("checksum_base64", "YQ=="), ("checksum_base64", "!" * 44),
    ("checksum_base64", base64.b64encode(b"x" * 33).decode()),
    ("checksum_base64", "A" * 43 + "="), ("checksum_hex", "0" * 64),
    ("checksum_hex", "g" * 64), ("extra", "synthetic"),
])
def test_checksum_encoding_is_strict_and_digest_pairs_match(field: str, value: str) -> None:
    args = _arguments()
    _replace_checksum(args, **{field: value})
    with pytest.raises(BatchChecksumError):
        validate_batch_checksum_readbacks(**args)


def test_duplicate_checksum_json_keys_cannot_override_algorithm() -> None:
    args = _arguments()
    row = next(csv.reader(io.StringIO(args["report_csv_bytes"].decode())))
    result = row[-1].replace('"checksumAlgorithm":', '"checksumAlgorithm":"CRC64NVME","checksumAlgorithm":', 1)
    _replace_report_row(args, ResultMessage=result)
    with pytest.raises(BatchChecksumError):
        validate_batch_checksum_readbacks(**args)


def test_real_byte_comparison_rejects_altered_object() -> None:
    args = _arguments()
    args["signed_object_bytes"] += b"changed"
    with pytest.raises(BatchChecksumError, match="OBJECT_MISMATCH"):
        validate_batch_checksum_readbacks(**args)


@pytest.mark.parametrize(("field", "value"), [
    ("CreationTime", "not a timestamp"), ("CreationTime", "2030-01-01T00:00:00"),
    ("TerminationDate", "2029-12-31T23:59:59Z"),
])
def test_job_times_are_timezone_aware_and_ordered(field: str, value: str) -> None:
    args = _arguments()
    args["job"][field] = value
    with pytest.raises(BatchChecksumError):
        validate_batch_checksum_readbacks(**args)


def test_report_cannot_predate_job_creation() -> None:
    args = _arguments()
    document = json.loads(args["report_manifest_bytes"])
    document["ReportCreationDate"] = "2029-12-31T23:59:59Z"
    args["report_manifest_bytes"] = _json(document)
    with pytest.raises(BatchChecksumError):
        validate_batch_checksum_readbacks(**args)


def test_failures_never_echo_report_contents() -> None:
    args = _arguments()
    marker = "SYNTHETIC-SENSITIVE-MARKER"
    _replace_report_row(args, ResultMessage=marker)
    with pytest.raises(BatchChecksumError) as error:
        validate_batch_checksum_readbacks(**args)
    assert marker not in str(error.value)
