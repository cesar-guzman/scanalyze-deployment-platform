import unittest
import json
from unittest.mock import patch, MagicMock
import os

os.environ["SCANALYZE_ENV"] = "test"
os.environ["SCANALYZE_TENANT"] = "tenant-test"
os.environ["AWS_REGION"] = "us-east-1"

mock_boto3 = MagicMock()
with patch.dict('sys.modules', {'boto3': mock_boto3}):
    from classifier_worker.contracts import ClassifyMessage
    from classifier_worker.main import process_message
    import classifier_worker.main as main_module

class TestClassifierWorker(unittest.TestCase):
    def setUp(self):
        self.mock_config = patch.object(main_module, 'config').start()
        self.mock_get_item = patch.object(main_module, 'get_document_item').start()
        self.mock_get_text = patch.object(main_module, 'get_ocr_text').start()
        self.mock_save = patch.object(main_module, 'save_classification_evidence').start()
        self.mock_mark = patch.object(main_module, 'mark_classification_enqueued').start()
        self.mock_enqueue = patch.object(main_module, 'enqueue_message').start()
        self.mock_delete = patch.object(main_module, 'delete_message').start()
        self.mock_classify = patch.object(main_module, 'classify_document').start()
        self.mock_config.env = "test"
        self.mock_config.ssm_client.get_parameter.return_value = {
            "Parameter": {"Value": "https://sqs/bank"}
        }

    def tearDown(self):
        patch.stopall()

    def test_happy_path_heuristic(self):
        # Arrange
        self.mock_config.get.side_effect = lambda k, **kw: {
            "queues/classify_url": "https://sqs/classify",
            "queues/bank-extract_url": "https://sqs/bank",
            "queues/personal-extract_url": "https://sqs/personal",
            "data-foundation/ocr_bucket_name": "test-bucket",
            "data-foundation/documents_table_name": "test-table",
            "features/bedrock_classification_enabled": "false"
        }.get(k, kw.get("default"))

        self.mock_get_item.return_value = {
            "documentId": "doc-123",
            "customer_id": "cust_01ARZ3NDEKTSV4RRFFQ69G5FAW",
            "deployment_id": "dep_01ARZ3NDEKTSV4RRFFQ69G5FAV",
            "ownership_schema_version": 1,
            "status": "OCR_COMPLETED",
            "documentRoute": "platform",
            "input": {"bucket": "raw-bucket", "key": "path/raw.pdf"},
            "artifacts": {"ocr": {"bucket": "test-bucket", "key": "path/obj.json"}},
        }
        self.mock_get_text.return_value = "This is a bank statement with account number 1234."
        self.mock_classify.return_value = ("bank_statement", 0.95, "bank-extract", "heuristic")

        msg_body = {
            "schemaVersion": "scanalyze.classify.v2",
            "documentId": "doc-123",
            "customer_id": "cust_01ARZ3NDEKTSV4RRFFQ69G5FAW",
            "deployment_id": "dep_01ARZ3NDEKTSV4RRFFQ69G5FAV",
            "ownership_schema_version": 1,
            "pipeline_stage": "classify",
            "processing_domain": None,
            "ocr": {"bucket": "test-bucket", "key": "path/obj.json"},
            "raw": {"bucket": "raw-bucket", "key": "path/raw.pdf"},
            "meta": {"env": "test", "tenant": "platform"}
        }

        sqs_msg = {
            "ReceiptHandle": "receipt-123",
            "Body": json.dumps(msg_body)
        }

        # Act
        process_message(sqs_msg)

        # Assert
        self.mock_get_text.assert_called_once_with("test-bucket", "path/obj.json")
        self.mock_classify.assert_called_once_with("This is a bank statement with account number 1234.", False)
        self.mock_save.assert_called_once_with(
            table_name="test-table",
            document_id="doc-123",
            customer_id="cust_01ARZ3NDEKTSV4RRFFQ69G5FAW",
            deployment_id="dep_01ARZ3NDEKTSV4RRFFQ69G5FAV",
            doc_type="bank_statement",
            confidence=0.95,
            route="bank-extract",
            processing_domain="bank",
            strategy="heuristic",
            classifier_version="v2"
        )
        self.mock_enqueue.assert_called_once()
        args, kwargs = self.mock_enqueue.call_args
        self.assertEqual(kwargs['queue_url'], "https://sqs/bank")
        self.assertEqual(kwargs['message_group_id'], "doc-123")
        self.assertEqual(
            kwargs['deduplication_id'],
            "dep_01ARZ3NDEKTSV4RRFFQ69G5FAV-doc-123-classify-v2",
        )
        
        self.mock_delete.assert_called_once_with("https://sqs/classify", "receipt-123")

    def test_poison_message(self):
        self.mock_config.get.return_value = "https://sqs/classify"
        sensitive_value = "SYNTHETIC-SENSITIVE-VALUE"
        sqs_msg = {
            "ReceiptHandle": "receipt-poison",
            "Body": json.dumps({
                "documentId": "missing-fields",
                "sensitive": sensitive_value,
            })
        }

        with patch.object(main_module, "log") as mock_log:
            process_message(sqs_msg)

        self.mock_delete.assert_not_called()
        logged = mock_log.error.call_args
        self.assertNotIn("body", logged.kwargs)
        self.assertNotIn("details", logged.kwargs)
        self.assertNotIn(sensitive_value, repr(logged))

if __name__ == '__main__':
    unittest.main()
