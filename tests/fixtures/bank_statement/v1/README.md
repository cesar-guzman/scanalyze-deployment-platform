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
- `controls/`: Closed, executable negative-control recipes bound to the journey-v2 contract.
- `catalog.json`: The central manifest mapping all fixtures and their checksums.
- `catalog.schema.json`: JSON Schema for validating `catalog.json`.
- `control.schema.json`: JSON Schema for the executable negative-control recipes.

## Profiles

There are 10 positive profiles, each instantiated twice (20 positive documents total).

- 01: Single-page happy path.
- 02: Two- and three-page statements with transactions on every page.
- 03: Multiple balanced transactions, including fees and interest.
- 04: Nullable optional fields under `RENDER_NOT_AVAILABLE` and `OMIT` policies.
- 05: Valid zero-transaction statement with the contract-derived incomplete warning.
- 06: Warning-producing results with one visible missing core field per instance.
- 07: Low-confidence results, including one incomplete instance.
- 08: Balance-reconciliation warning.
- 09: Distinct periods, countries, and MXN/USD currencies.
- 10: Two byte-identical deterministic replay inputs in one explicit replay group.

## Negative Controls

There are 8 negative controls. Recipes contain an operation-discriminated sequence of contract operations, exact principals/requests/input bindings, expected public responses, and effect-count invariants. Catalog entries snapshot each shared or embedded input artifact's PDF SHA-256, byte size, page count, and consuming step IDs; the recipe itself has a separate hash and byte size.

The catalog records lifecycle applicability explicitly. `APPLICABLE` requires a lifecycle and terminal state, `NOT_APPLICABLE` identifies request/identity controls whose outcome occurs before or outside document completion, and `UNDEFINED_BY_CURRENT_CONTRACT` prevents an unproven terminal outcome from being invented. Every negative control is excluded from the accepted-document denominator.

- ctrl_01: Malformed PDF structure plus the `OCR_FAILED` status projection. The artifact and status policy are locally proven; the causal asynchronous runtime outcome remains `NONPROD_REQUIRED`.
- ctrl_02: Valid blank PDF with zero extracted text. No terminal outcome is claimed because the current production contract does not define one; evidence is `NOT_PROVEN` pending a product decision or non-production execution.
- ctrl_03: Unsupported document MIME, rejected as HTTP 422 `SEMANTIC_VALIDATION_FAILED`.
- ctrl_04: `contentLength` one byte above the 512 MiB contract maximum, rejected as HTTP 422 `SEMANTIC_VALIDATION_FAILED` without allocating a large file.
- ctrl_05: Same owner/idempotency key with different semantic requests, returning HTTP 409 `IDEMPOTENCY_CONFLICT` after exactly one create effect.
- ctrl_06: Lost create response followed by reconciliation and safe replay, preserving one document ID and one create effect.
- ctrl_07: Wrong-actor access hidden as HTTP 404 `NOT_FOUND`.
- ctrl_08: Wrong-deployment access hidden as HTTP 404 `NOT_FOUND`.

`DOCUMENT_PROCESSING_FAILED` and `OCR_FAILED` are safe failure codes on a successful status response, not HTTP error codes. The 5 MiB structured-result read limit is not an upload-size limit.

## Validation

The test suite in `tests/test_fixtures/test_gug364_bank_statement_corpus.py` validates the effective profile matrix and transaction arithmetic, full expected-result projection through the production contract, executable input-bound control recipes, strict schemas, deterministic checksums, privacy mutations, indirect PDF object traversal, rendered text, replay identity, and orphan-file drift.
