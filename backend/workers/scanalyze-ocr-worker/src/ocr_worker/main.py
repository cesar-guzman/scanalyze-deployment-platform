import os
import time
import signal
import sys
import logging

from .logger import setup_logging, log_event, safe_error_details
from .config import config
from .aws import sqs_client
from .processors.ingest import process_ingest_message
from .processors.ocr_poll import process_ocr_poll_message

logger = logging.getLogger(__name__)

shutdown_requested = False

def sigterm_handler(signum, frame):
    """
    Manejador de señales para apagado limpio en ECS.
    Permite terminar de procesar los mensajes in-flight antes de matar el contenedor.
    """
    global shutdown_requested
    logger.info("SIGTERM/SIGINT received. Initiating graceful shutdown...")
    log_event("shutdown_initiated", signal=signum)
    shutdown_requested = True

def poll_queue(queue_url: str, processor_func, queue_name: str):
    logger.info(f"Starting long polling on {queue_name} queue")
    log_event("worker_started", queue=queue_name)
    
    while not shutdown_requested:
        try:
            # Long polling: WaitTimeSeconds=20, MaxNumberOfMessages=10
            response = sqs_client.receive_message(
                QueueUrl=queue_url,
                MaxNumberOfMessages=10,
                WaitTimeSeconds=20,
                AttributeNames=['All']
            )
            
            messages = response.get('Messages', [])
            if not messages:
                continue
                
            for msg in messages:
                if shutdown_requested:
                    logger.info("Shutdown requested, skipping remaining messages in batch to let them timeout.")
                    break
                    
                receipt_handle = msg['ReceiptHandle']
                body = msg['Body']
                message_id = msg['MessageId']
                
                logger.info(f"Received message {message_id} from {queue_name}")
                
                try:
                    attributes = msg.get('Attributes', {})
                    receive_count = int(attributes.get('ApproximateReceiveCount', 1))

                    # Ingest no necesita la queue_url (usualmente), OCR_POLL sí para reenviar
                    if queue_name == "OCR":
                        success = processor_func(body, receipt_handle, queue_url, message_id, receive_count)
                    else:
                        success = processor_func(body, receipt_handle, message_id, receive_count)
                        
                    if success:
                        sqs_client.delete_message(
                            QueueUrl=queue_url,
                            ReceiptHandle=receipt_handle
                        )
                        logger.info(f"Successfully processed and deleted message {message_id}")
                except ValueError as ve:
                    # Poison message schema erróneo
                    log_event(
                        "poison_message",
                        messageId=message_id,
                        **safe_error_details(ve),
                    )
                    # Borrar o mandar explícitamente a DLQ (dependiendo de la configuración SQS nativa)
                    # En ECS con retry robusto lo mejor es borrar el poison message si es strict validation
                    sqs_client.delete_message(QueueUrl=queue_url, ReceiptHandle=receipt_handle)
                except Exception as e:
                    # Transient error (boto throttling, S3 eventual consistency)
                    # Dejamos que el VisibilityTimeout expire y SQS haga retry
                    logger.error(
                        "Processing error",
                        extra={"errorType": type(e).__name__},
                    )
                    log_event("processing_error", messageId=message_id, errorType=type(e).__name__)
                    
        except Exception as e:
            logger.error(
                f"Queue poll error on {queue_name}",
                extra={"errorType": type(e).__name__},
            )
            if not shutdown_requested:
                # AWS API error generally. Backoff.
                time.sleep(5) 

def main():
    setup_logging()
    signal.signal(signal.SIGTERM, sigterm_handler)
    signal.signal(signal.SIGINT, sigterm_handler)

    worker_mode = os.environ.get("WORKER_MODE", "").upper()
    if worker_mode not in ["INGEST", "OCR_POLL"]:
        logger.critical(f"Invalid WORKER_MODE: '{worker_mode}'. Must be INGEST or OCR_POLL.")
        sys.exit(1)

    logger.info(f"Starting worker in {worker_mode} mode")
    
    try:
        # Pre-fetch SSM params al inicio
        # Esto valida también que el rol pueda leer SSM y que las llaves necesarias existan
        if worker_mode == "INGEST":
            _ = config.get("queues/ingest_url")
        elif worker_mode == "OCR_POLL":
            _ = config.get("queues/ocr_url")
    except Exception as e:
        logger.critical("Failed to initialize configuration", extra={"errorType": type(e).__name__})
        sys.exit(1)

    if worker_mode == "INGEST":
        queue_url = config.get("queues/ingest_url")
        poll_queue(queue_url, process_ingest_message, "INGEST")
    elif worker_mode == "OCR_POLL":
        queue_url = config.get("queues/ocr_url")
        poll_queue(queue_url, process_ocr_poll_message, "OCR")
    else:
        logger.error(f"Unknown WORKER_MODE: {worker_mode}. Must be INGEST or OCR_POLL.")
        sys.exit(1)
        
    logger.info("Worker shut down cleanly.")
    log_event("worker_stopped")

if __name__ == "__main__":
    main()
