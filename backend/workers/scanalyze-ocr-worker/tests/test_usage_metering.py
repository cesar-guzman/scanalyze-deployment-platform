from unittest.mock import MagicMock, patch
import pytest
from botocore.exceptions import ClientError
from ocr_worker.usage import record_usage_metering_with_idempotency

@pytest.fixture
def mock_dynamo():
    return MagicMock()

@patch('ocr_worker.usage.resolve_usage_tables')
def test_metering_success(mock_resolve, mock_dynamo):
    mock_resolve.return_value = ("events-table", "rollups-table")
    mock_dynamo.transact_write_items.return_value = {}
    
    result = record_usage_metering_with_idempotency(
        dynamodb_client=mock_dynamo,
        tenant="default",
        doc_id="doc123",
        pages=5,
        uploader_user_id="user456",
        batch_id="batch789",
        doc_type="ine"
    )
    
    assert result is True
    # Verify TransactItems format
    mock_dynamo.transact_write_items.assert_called_once()
    kwargs = mock_dynamo.transact_write_items.call_args[1]
    items = kwargs['TransactItems']
    assert len(items) == 6  # 1 Put (events), 5 Updates (OVERALL, DAYS, USERS, BATCHES, DOCTYPES)
    
    # Check conditional check on the first item
    assert items[0]["Put"]["ConditionExpression"] == "attribute_not_exists(id)"
    assert items[0]["Put"]["Item"]["id"]["S"] == "doc123#PAGES_SCANNED"

@patch('ocr_worker.usage.resolve_usage_tables')
def test_metering_idempotency_already_metered(mock_resolve, mock_dynamo):
    mock_resolve.return_value = ("events-table", "rollups-table")
    
    # Simulate conditional check failed for TransactWriteItems
    error_response = {
        'Error': {'Code': 'TransactionCanceledException', 'Message': 'Transaction canceled'},
        'CancellationReasons': [{'Code': 'ConditionalCheckFailed'}, {'Code': 'None'}, {'Code': 'None'}]
    }
    mock_dynamo.transact_write_items.side_effect = ClientError(error_response, 'TransactWriteItems')
    
    result = record_usage_metering_with_idempotency(mock_dynamo, "default", "doc123", 5, "", "", "")
    # Should still return True and not bubble the exception since it just means it was idempotently skipped
    assert result is True

@patch('ocr_worker.usage.resolve_usage_tables')
def test_metering_error_bubbled(mock_resolve, mock_dynamo):
    mock_resolve.return_value = ("events-table", "rollups-table")
    
    # Simulate other AWS errors
    error_response = {
        'Error': {'Code': 'ProvisionedThroughputExceededException', 'Message': 'Too fast'}
    }
    mock_dynamo.transact_write_items.side_effect = ClientError(error_response, 'TransactWriteItems')
    
    result = record_usage_metering_with_idempotency(mock_dynamo, "default", "doc123", 5, "", "", "")
    # Should return False on real errors
    assert result is False
