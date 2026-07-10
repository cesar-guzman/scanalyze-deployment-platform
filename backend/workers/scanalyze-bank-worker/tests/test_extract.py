import pytest
from bank_worker.processors.extract import chunk_text

def test_chunk_text_splits_correctly():
    text = "Line 1\nLine 2\nLine 3\nLine 4\nLine 5"
    
    # Chunk size of 15 should split:
    # "Line 1\nLine 2" (13 chars)
    # "Line 3\nLine 4" (13 chars)
    # "Line 5" (6 chars)
    
    chunks = list(chunk_text(text, chunk_size=15))
    
    assert len(chunks) == 3
    assert chunks[0] == "Line 1\nLine 2"
    assert chunks[1] == "Line 3\nLine 4"
    assert chunks[2] == "Line 5"

def test_chunk_text_single_large_chunk():
    text = "Line 1\nLine 2\nLine 3"
    
    # Chunk size of 100 should keep everything together
    chunks = list(chunk_text(text, chunk_size=100))
    
    assert len(chunks) == 1
    assert chunks[0] == "Line 1\nLine 2\nLine 3"

def test_chunk_text_empty_string():
    text = ""
    chunks = list(chunk_text(text, chunk_size=10))
    assert len(chunks) == 0

def test_chunk_text_long_line_no_newlines():
    # If a single line is longer than chunk_size, it is currently chunked at exactly chunk_size
    text = "ThisIsAVeryLongLineWithoutAnyNewlines"
    chunks = list(chunk_text(text, chunk_size=10))
    
    assert len(chunks) == 4
    assert chunks[0] == "ThisIsAVer"
    assert chunks[1] == "yLongLineW"
    assert chunks[2] == "ithoutAnyN"
    assert chunks[3] == "ewlines"
