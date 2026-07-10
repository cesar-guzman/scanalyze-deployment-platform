import json
import os
import signal
import sys
import threading
import time
from typing import Callable, Dict, Mapping

from .aws import sqs_client
from .config import config
from .contracts import (
    NOTIFY_SCHEMA_VERSION,
    PERSIST_SCHEMA_VERSION,
    VALIDATE_SCHEMA_VERSION,
)
from .logger import log_event, logger, setup_logging
from .processors.notify import process_notify_message
from .processors.persist import process_persist_message
from .processors.validate import process_validate_message
from .routing import route_is_allowed


Processor = Callable[[str, str, str, str], bool]

SCHEMA_PROCESSORS: Dict[str, Processor] = {
    VALIDATE_SCHEMA_VERSION: process_validate_message,
    PERSIST_SCHEMA_VERSION: process_persist_message,
    NOTIFY_SCHEMA_VERSION: process_notify_message,
}

SCHEMA_STAGES = {
    VALIDATE_SCHEMA_VERSION: "validate",
    PERSIST_SCHEMA_VERSION: "persist",
    NOTIFY_SCHEMA_VERSION: "notify",
}

shutdown_requested = False


def sigterm_handler(signum, frame):
    del frame
    global shutdown_requested
    logger.info("SIGTERM/SIGINT received. Initiating graceful shutdown...")
    log_event("shutdown_initiated", stage="worker_root", signal=signum)
    shutdown_requested = True


def build_queue_bindings(
    validate_url: str,
    persist_url: str,
    notify_url: str,
    worker_mode: str,
) -> Dict[str, Dict[str, Processor]]:
    """Group compatible schema processors so each queue URL has one poller."""
    mode = worker_mode.upper()
    bindings: Dict[str, Dict[str, Processor]] = {}

    stage_definitions = (
        ("VALIDATE", validate_url, VALIDATE_SCHEMA_VERSION),
        ("PERSIST", persist_url, PERSIST_SCHEMA_VERSION),
        ("NOTIFY", notify_url, NOTIFY_SCHEMA_VERSION),
    )
    for stage, queue_url, schema_version in stage_definitions:
        if mode not in ("ALL", "POSTPROCESS", stage):
            continue
        bindings.setdefault(queue_url, {})[schema_version] = SCHEMA_PROCESSORS[schema_version]

    return bindings


def dispatch_message(
    body: str,
    receipt_handle: str,
    queue_url: str,
    tenant: str,
    processors: Mapping[str, Processor],
) -> bool:
    """Dispatch only an explicitly supported schema and configured tenant route."""
    try:
        envelope = json.loads(body)
    except json.JSONDecodeError:
        log_event("poison_message", stage="dispatcher", reason="invalid_json")
        return False

    if not isinstance(envelope, dict):
        log_event("poison_message", stage="dispatcher", reason="invalid_envelope")
        return False

    schema_version = envelope.get("schemaVersion")
    processor = processors.get(schema_version) if isinstance(schema_version, str) else None
    if processor is None:
        log_event("schema_route_rejected", stage="dispatcher", reason="unsupported_schema")
        return False

    meta = envelope.get("meta")
    message_route = meta.get("tenant") if isinstance(meta, dict) else None
    if (
        not isinstance(message_route, str)
        or not route_is_allowed(tenant, message_route)
        or meta.get("env") != config.env
    ):
        log_event("message_route_mismatch", stage="dispatcher")
        return False

    return processor(body, receipt_handle, queue_url, tenant)


def poll_queue(
    queue_url: str,
    processors: Mapping[str, Processor],
    stage_name: str,
    tenant: str,
):
    logger.info("Starting long polling thread")
    log_event("poller_started", stage=stage_name, tenant=tenant)

    while not shutdown_requested:
        try:
            response = sqs_client.receive_message(
                QueueUrl=queue_url,
                MaxNumberOfMessages=10,
                WaitTimeSeconds=20,
                AttributeNames=["All"],
            )

            messages = response.get("Messages", [])
            if not messages:
                continue

            for message in messages:
                if shutdown_requested:
                    logger.info("Shutdown requested; skipping remaining messages")
                    break

                receipt_handle = message["ReceiptHandle"]
                body = message["Body"]
                message_id = message["MessageId"]
                logger.info("Received postprocess message")

                try:
                    success = dispatch_message(
                        body,
                        receipt_handle,
                        queue_url,
                        tenant,
                        processors,
                    )
                    if success:
                        sqs_client.delete_message(
                            QueueUrl=queue_url,
                            ReceiptHandle=receipt_handle,
                        )
                        logger.info("Successfully processed and deleted message")
                except Exception as error:
                    logger.error(
                        "Unhandled processing error",
                        extra={"errorType": type(error).__name__},
                    )
                    log_event(
                        "processing_error_unhandled",
                        stage=stage_name,
                        messageId=message_id,
                        errorType=type(error).__name__,
                    )

        except Exception as error:
            logger.error(
                "Queue poll error",
                extra={"errorType": type(error).__name__},
            )
            if not shutdown_requested:
                time.sleep(5)

    logger.info("Poller thread shut down cleanly")


def main():
    setup_logging()
    signal.signal(signal.SIGTERM, sigterm_handler)
    signal.signal(signal.SIGINT, sigterm_handler)

    logger.info("Starting postprocess worker")
    worker_mode = os.environ.get("WORKER_MODE", "ALL").upper()
    threads = []

    for tenant in config.tenants:
        logger.info("Initializing tenant postprocess routes")
        try:
            validate_url = config.get(tenant, "queues/validate_url")
            persist_url = config.get(tenant, "queues/persist_url")
            notify_url = config.get(tenant, "queues/notify_url")
            config.get(tenant, "data-foundation/documents_table_name")
            config.get(tenant, "data-foundation/structured_bucket_name")
        except Exception as error:
            logger.critical(
                "Failed to initialize tenant configuration",
                extra={"errorType": type(error).__name__},
            )
            continue

        queue_bindings = build_queue_bindings(
            validate_url,
            persist_url,
            notify_url,
            worker_mode,
        )
        for queue_url, processors in queue_bindings.items():
            stage_name = "+".join(SCHEMA_STAGES[schema] for schema in processors)
            thread = threading.Thread(
                target=poll_queue,
                args=(queue_url, processors, stage_name, tenant),
                daemon=True,
            )
            threads.append(thread)

    if not threads:
        logger.critical(
            "No threads to start. Check tenant configuration and WORKER_MODE"
        )
        sys.exit(1)

    for thread in threads:
        thread.start()

    while not shutdown_requested:
        time.sleep(1)

    logger.info("Waiting for poller threads to finish")
    for thread in threads:
        thread.join(timeout=30.0)

    logger.info("Main worker thread shut down cleanly")
    log_event("worker_stopped", stage="worker_root")


if __name__ == "__main__":
    main()
