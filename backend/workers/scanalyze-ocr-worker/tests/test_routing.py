import pytest
from ocr_worker.routing import get_next_stage
from ocr_worker.storage import build_ocr_artifact_key

def test_routing_known_routes():
    assert get_next_stage('bank') == 'bank-extract'
    assert get_next_stage('personal') == 'personal-extract'
    assert get_next_stage('gov') == 'gov-extract'
    assert get_next_stage('platform') == 'classify'

def test_routing_unknown_route():
    with pytest.raises(ValueError):
        get_next_stage('unknown_custom')

def test_storage_builder():
    res = build_ocr_artifact_key(
        'cust_01ARZ3NDEKTSV4RRFFQ69G5FAW',
        'dep_01ARZ3NDEKTSV4RRFFQ69G5FAV',
        'doc-123',
    )
    assert res == (
        'customers/cust_01ARZ3NDEKTSV4RRFFQ69G5FAW/deployments/dep_01ARZ3NDEKTSV4RRFFQ69G5FAV/'
        'documents/doc-123/ocr.json'
    )
    
    with pytest.raises(ValueError):
        build_ocr_artifact_key('', 'dep_01ARZ3NDEKTSV4RRFFQ69G5FAV', 'doc-123')
