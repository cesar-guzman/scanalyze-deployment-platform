"""Small offline contract smoke test for the OCR handoff chain.

The behavior and security boundaries are covered by the collected test modules.
This legacy entrypoint remains runnable directly without AWS or credentials.
"""

from ocr_worker.contracts import (
    ClassifyMessage,
    ClassifyMeta,
    IngestMessage,
    MessageMetadata,
    OcrPollMessage,
    S3Location,
    TextractInfo,
)


CUSTOMER_ID = "cust_01ARZ3NDEKTSV4RRFFQ69G5FAW"
DEPLOYMENT_ID = "dep_01ARZ3NDEKTSV4RRFFQ69G5FAV"
DOCUMENT_ID = "doc-ocr-smoke"
RAW_KEY = (
    f"customers/{CUSTOMER_ID}/deployments/{DEPLOYMENT_ID}/"
    f"documents/{DOCUMENT_ID}/source.pdf"
)
OCR_KEY = (
    f"customers/{CUSTOMER_ID}/deployments/{DEPLOYMENT_ID}/"
    f"documents/{DOCUMENT_ID}/ocr.json"
)


def test_owner_bound_contract_chain_smoke():
    metadata = MessageMetadata(correlationId="correlation-smoke")
    ingest = IngestMessage(
        schemaVersion="scanalyze.ingest.v2",
        customer_id=CUSTOMER_ID,
        deployment_id=DEPLOYMENT_ID,
        ownership_schema_version=1,
        pipeline_stage="ingest",
        processing_domain=None,
        enqueue_id="enqueue-smoke",
        documentId=DOCUMENT_ID,
        raw=S3Location(bucket="raw-bucket", key=RAW_KEY),
        metadata=metadata,
    )
    poll = OcrPollMessage(
        schemaVersion="scanalyze.ocr-poll.v2",
        customer_id=ingest.customer_id,
        deployment_id=ingest.deployment_id,
        ownership_schema_version=1,
        pipeline_stage="ocr",
        documentId=ingest.documentId,
        textractJobId="job-smoke",
        sourceBucket=ingest.raw.bucket,
        sourceKey=ingest.raw.key,
        documentRoute="platform",
        artifactBucket="ocr-bucket",
        artifactKey=OCR_KEY,
        submittedAt="2026-07-12T00:00:00+00:00",
        metadata=metadata,
    )
    classify = ClassifyMessage(
        schemaVersion="scanalyze.classify.v2",
        customer_id=poll.customer_id,
        deployment_id=poll.deployment_id,
        ownership_schema_version=1,
        pipeline_stage="classify",
        documentId=poll.documentId,
        raw=S3Location(bucket=poll.sourceBucket, key=poll.sourceKey),
        ocr=S3Location(bucket=poll.artifactBucket, key=poll.artifactKey),
        textract=TextractInfo(jobId=poll.textractJobId),
        meta=ClassifyMeta(env="test", tenant="platform"),
        metadata=metadata,
    )

    assert classify.customer_id == ingest.customer_id
    assert classify.deployment_id == ingest.deployment_id
    assert classify.raw == ingest.raw


if __name__ == "__main__":
    test_owner_bound_contract_chain_smoke()
