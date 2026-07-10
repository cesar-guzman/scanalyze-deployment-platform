import os
import pytest
from unittest.mock import patch
from ocr_worker.aws import build_key

def test_build_key_default():
    with patch.dict(os.environ, {}, clear=True):
        key = build_key('test_table', 'doc-123')
        assert key == {'documentId': 'doc-123'}

def test_build_key_custom_pk():
    with patch.dict(os.environ, {
        "DOCUMENTS_TABLE_PK_NAME": "PK",
        "DOCUMENTS_TABLE_PK_TEMPLATE": "DOC#{document_id}"
    }, clear=True):
        key = build_key('test_table', 'doc-123')
        assert key == {'PK': 'DOC#doc-123'}

def test_build_key_with_sk():
    with patch.dict(os.environ, {
        "DOCUMENTS_TABLE_PK_NAME": "tenantId",
        "DOCUMENTS_TABLE_PK_TEMPLATE": "tenant-1",
        "DOCUMENTS_TABLE_SK_NAME": "documentId",
        "DOCUMENTS_TABLE_SK_TEMPLATE": "DOC#{document_id}"
    }, clear=True):
        key = build_key('test_table', 'doc-123')
        assert key == {
            'tenantId': 'tenant-1',
            'documentId': 'DOC#doc-123'
        }
