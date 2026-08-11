# Synthetic Bank Statement Fixture Corpus v1

This directory contains the deterministic synthetic bank statement fixture corpus for the GUG-364 initiative.

## Generation

The fixtures are generated deterministically from source profiles. Do not manually edit the PDF or JSON files in this directory. If a change is needed, edit `tooling/generate_bank_statement_fixtures.py` or the profile JSON files, and regenerate.

To generate the fixtures:

```bash
python tooling/generate_bank_statement_fixtures.py
```

To verify that the current files match the expected deterministic output (useful for CI):

```bash
python tooling/generate_bank_statement_fixtures.py --check
```

## Corpus Structure

- `profiles/`: Source specifications for positive fixtures.
- `pdf/`: The generated synthetic PDF documents.
- `expected/`: The expected ground-truth extraction results in the scanalyze.document-result.v1 schema format.
- `controls/`: Negative control recipes for simulating error conditions.
- `catalog.json`: The central manifest mapping all fixtures and their checksums.
- `catalog.schema.json`: JSON Schema for validating `catalog.json`.

## Profiles

There are 10 positive profiles, each instantiated 2 times (20 positive documents total).
- 01: Standard basic statement
- 02: Multi-page statement
- 03: Missing account holder
- 04: Missing statement period
- 05: Missing opening balance
- 06: Missing closing balance
- 07: No transactions
- 08: All nulls / empty fields
- 09: Fees and interest inclusion
- 10: Mutating variant (Instance 1: MXN, Instance 2: USD)

## Negative Controls

There are 8 negative controls, generating predictable error conditions:
- ctrl_01: Malformed PDF (DOCUMENT_PROCESSING_FAILED)
- ctrl_02: Blank or low-text PDF (OCR_FAILED)
- ctrl_03: Unsupported MIME (UNSUPPORTED_MIME_TYPE)
- ctrl_04: Oversized-file boundary (FILE_TOO_LARGE)
- ctrl_05: Idempotency conflict (IDEMPOTENCY_CONFLICT)
- ctrl_06: Response-loss reconciliation (Success after safe retry)
- ctrl_07: Wrong-user access (AUTHORIZATION_DENIED)
- ctrl_08: Wrong-deployment access (AUTHORIZATION_DENIED)

## Validation

The test suite in `tests/test_fixtures/test_gug364_bank_statement_corpus.py` provides comprehensive validation of the corpus, including schema compliance, deterministic checksums, privacy requirements (no PII leak), PDF structural limits, and orphan file detection.
