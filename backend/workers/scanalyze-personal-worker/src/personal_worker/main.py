import os
import time
import signal
import sys
import logging

from .logger import setup_logging, log_event
from .config import config
from .aws import sqs_client
from .processors.extract import process_personal_extract_message

logger = logging.getLogger(__name__)

shutdown_requested = False

def sigterm_handler(signum, frame):
    """
    Señal de apagado limpio en ECS.
    """
    global shutdown_requested
    logger.info("SIGTERM/SIGINT received. Initiating graceful shutdown...")
    log_event("shutdown_initiated", signal=signum)
    shutdown_requested = True

def poll_queue(queue_url: str):
    logger.info("Starting long polling")
    log_event("worker_started", queue="personal-extract")
    
    while not shutdown_requested:
        try:
            response = sqs_client.receive_message(
                QueueUrl=queue_url,
                MaxNumberOfMessages=2,
                WaitTimeSeconds=20,
                AttributeNames=['All']
            )
            
            messages = response.get('Messages', [])
            if not messages:
                continue
                
            for msg in messages:
                if shutdown_requested:
                    logger.info("Shutdown requested, skipping remaining messages.")
                    break
                    
                receipt_handle = msg['ReceiptHandle']
                body = msg['Body']
                message_id = msg['MessageId']
                attributes = msg.get('Attributes', {})
                receive_count = int(attributes.get('ApproximateReceiveCount', 1))
                
                logger.info(f"Received message {message_id} (Attempt: {receive_count})")
                
                try:
                    success = process_personal_extract_message(body, receipt_handle, queue_url, receive_count)
                        
                    if success:
                        sqs_client.delete_message(
                            QueueUrl=queue_url,
                            ReceiptHandle=receipt_handle
                        )
                        logger.info(f"Successfully processed and deleted message {message_id}")
                except Exception as e:
                    # process_personal_extract_message is expected to handle specific errors,
                    # mark DLQ explicitly if needed, or raise for retry.
                    logger.error(
                        "Processing error bubbling up",
                        extra={"errorType": type(e).__name__},
                    )
                    log_event("processing_error", messageId=message_id, errorType=type(e).__name__)
                    
        except Exception as e:
            logger.error("Queue poll error", extra={"errorType": type(e).__name__})
            if not shutdown_requested:
                time.sleep(5) 

def main():
    setup_logging()
    signal.signal(signal.SIGTERM, sigterm_handler)
    signal.signal(signal.SIGINT, sigterm_handler)

    logger.info("Starting personal worker")
    
    try:
        # Pre-fetch config to crash early if something is missing
        queue_url = config.get("queues/personal-extract_url")
        # Validate other essential configs are there early on
        _ = config.get("data-foundation/ocr_bucket_name")
        _ = config.get("data-foundation/structured_bucket_name")
        _ = config.get("queues/validate_url")
        _ = config.get("data-foundation/documents_table_name")
    except Exception as e:
        logger.critical("Failed to initialize configuration", extra={"errorType": type(e).__name__})
        sys.exit(1)

    poll_queue(queue_url)
        
    logger.info("Worker shut down cleanly.")
    log_event("worker_stopped")

if __name__ == "__main__":
    main()
