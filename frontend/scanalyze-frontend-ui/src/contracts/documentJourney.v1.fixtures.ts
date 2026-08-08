import type {
  BankStatementResult,
  BatchCreateResponse,
  DocumentCreateResponseV2,
  DocumentJourneyErrorEnvelope,
  DocumentStatusResponseV2,
  ReconciliationResponse,
} from "./documentJourney.v1";

// These objects remain JSON-compatible so the repository parity test can
// validate their exact values against the authoritative committed schemas.
export const BATCH_CREATE_RESPONSE_FIXTURE = {
  "schemaVersion": "scanalyze.operation-response.v1",
  "contractVersion": "scanalyze.document-journey.v1",
  "replayed": false,
  "durableResponse": {
    "schemaVersion": "scanalyze.batch-create-result.v1",
    "contractVersion": "scanalyze.document-journey.v1",
    "operation": "batches.create",
    "batchId": "11111111111111111111111111111111",
    "status": "OPEN",
    "createdAt": "2026-08-07T12:00:00Z"
  }
} as const satisfies BatchCreateResponse;

export const DOCUMENT_CREATE_RESPONSE_FIXTURE = {
  "schemaVersion": "scanalyze.operation-response.v1",
  "contractVersion": "scanalyze.document-journey.v1",
  "replayed": false,
  "durableResponse": {
    "schemaVersion": "scanalyze.document-create-result.v1",
    "contractVersion": "scanalyze.document-journey.v1",
    "operation": "documents.create",
    "documentId": "22222222222222222222222222222222",
    "batchId": "11111111111111111111111111111111",
    "status": "UPLOAD_PENDING",
    "contentType": "application/pdf",
    "createdAt": "2026-08-07T12:01:00Z"
  },
  "uploadCapability": {
    "method": "PUT",
    "url": "https://upload.invalid/synthetic-capability",
    "expiresAt": "2026-08-07T12:11:00Z",
    "requiredHeaders": {
      "Content-Type": "application/pdf"
    }
  }
} as const satisfies DocumentCreateResponseV2;

export const DOCUMENT_REPLAY_RESPONSE_WITHOUT_CAPABILITY_FIXTURE = {
  "schemaVersion": "scanalyze.operation-response.v1",
  "contractVersion": "scanalyze.document-journey.v1",
  "replayed": true,
  "durableResponse": {
    "schemaVersion": "scanalyze.document-create-result.v1",
    "contractVersion": "scanalyze.document-journey.v1",
    "operation": "documents.create",
    "documentId": "22222222222222222222222222222222",
    "batchId": "11111111111111111111111111111111",
    "status": "UPLOAD_PENDING",
    "contentType": "application/pdf",
    "createdAt": "2026-08-07T12:01:00Z"
  }
} as const satisfies DocumentCreateResponseV2;

export const RECONCILIATION_RESPONSE_FIXTURE = {
  "schemaVersion": "scanalyze.reconciliation.v1",
  "contractVersion": "scanalyze.document-journey.v1",
  "operation": "documents.create",
  "ledgerState": "SUCCEEDED",
  "durableResponse": {
    "schemaVersion": "scanalyze.document-create-result.v1",
    "contractVersion": "scanalyze.document-journey.v1",
    "operation": "documents.create",
    "documentId": "22222222222222222222222222222222",
    "batchId": "11111111111111111111111111111111",
    "status": "UPLOAD_PENDING",
    "contentType": "application/pdf",
    "createdAt": "2026-08-07T12:01:00Z"
  },
  "createdAt": "2026-08-07T12:01:00Z",
  "updatedAt": "2026-08-07T12:01:01Z",
  "completedAt": "2026-08-07T12:01:01Z",
  "expiresAt": "2026-09-06T12:01:00Z"
} as const satisfies ReconciliationResponse;

export const EXPIRED_RECONCILIATION_RESPONSE_FIXTURE = {
  "schemaVersion": "scanalyze.reconciliation.v1",
  "contractVersion": "scanalyze.document-journey.v1",
  "operation": "documents.create",
  "ledgerState": "EXPIRED",
  "failureCode": "OPERATION_EXPIRED",
  "createdAt": "2026-08-07T12:01:00Z",
  "updatedAt": "2026-09-07T12:01:00Z",
  "completedAt": "2026-08-07T12:01:01Z",
  "expiresAt": "2026-09-06T12:01:00Z"
} as const satisfies ReconciliationResponse;

export const DOCUMENT_STATUS_RESPONSE_FIXTURE = {
  "schemaVersion": "scanalyze.document-status.v1",
  "contractVersion": "scanalyze.document-journey.v1",
  "batchId": "11111111111111111111111111111111",
  "documentId": "22222222222222222222222222222222",
  "lifecycle": "COMPLETED",
  "currentStage": "TERMINAL",
  "stageState": "SUCCEEDED",
  "processingCondition": "NOT_APPLICABLE",
  "createdAt": "2026-08-07T12:01:00Z",
  "updatedAt": "2026-08-07T12:10:00Z",
  "terminalAt": "2026-08-07T12:10:00Z",
  "correlationReference": "corr.synthetic.0001",
  "progress": {
    "attempt": 1,
    "completedStages": 8,
    "totalStages": 8
  }
} as const satisfies DocumentStatusResponseV2;

export const DOCUMENT_PROCESSING_STATUS_RESPONSE_FIXTURE = {
  "schemaVersion": "scanalyze.document-status.v1",
  "contractVersion": "scanalyze.document-journey.v1",
  "batchId": "11111111111111111111111111111111",
  "documentId": "22222222222222222222222222222222",
  "lifecycle": "PROCESSING",
  "currentStage": "BANK_EXTRACT",
  "stageState": "RUNNING",
  "processingCondition": "ACTIVE",
  "createdAt": "2026-08-07T12:01:00Z",
  "updatedAt": "2026-08-07T12:08:00Z",
  "correlationReference": "corr.synthetic.0001",
  "progress": {
    "attempt": 1,
    "completedStages": 3,
    "totalStages": 7
  }
} as const satisfies DocumentStatusResponseV2;

export const ERROR_ENVELOPE_FIXTURE = {
  "schemaVersion": "scanalyze.error.v1",
  "code": "IDEMPOTENCY_CONFLICT",
  "message": "The idempotency key is bound to a different request.",
  "correlationId": "corr.synthetic.0002",
  "retryClass": "TERMINAL",
  "details": {
    "operation": "documents.create"
  }
} as const satisfies DocumentJourneyErrorEnvelope;

export const BANK_STATEMENT_RESULT_FIXTURE = {
  "schemaVersion": "scanalyze.document-result.v1",
  "contractVersion": "scanalyze.document-journey.v1",
  "documentType": "bank_statement",
  "resultType": "bank_statement",
  "documentId": "22222222222222222222222222222222",
  "resultId": "result_22222222222222222222222222222222_v1",
  "resultVersion": "1.0",
  "provenance": {
    "processor": "bank-extract",
    "producerSchemaVersion": "1.0",
    "promptVersion": "2.1.0",
    "generatedAt": "2026-08-07T12:09:00Z"
  },
  "data": {
    "bank": {
      "name": "Synthetic Bank"
    },
    "account": {
      "holder": "Synthetic Account Holder",
      "numberMasked": "****0001",
      "clabeMasked": null,
      "currency": "MXN"
    },
    "statement": {
      "periodStart": "2026-07-01",
      "periodEnd": "2026-07-31"
    },
    "balances": {
      "opening": 1000,
      "closing": 1250,
      "totalCredits": 500,
      "totalDebits": 250
    },
    "transactions": [
      {
        "date": "2026-07-05",
        "description": "Synthetic credit",
        "reference": null,
        "direction": "credit",
        "amount": 500,
        "balanceAfter": 1500,
        "category": "transferencia"
      },
      {
        "date": "2026-07-10",
        "description": "Synthetic debit",
        "reference": null,
        "direction": "debit",
        "amount": 250,
        "balanceAfter": 1250,
        "category": "pago_servicio"
      }
    ],
    "accountType": "cheques",
    "bankCountry": "MX",
    "fees": {
      "totalFees": 0,
      "ivaOnFees": 0
    },
    "interestEarned": null,
    "interestCharged": null,
    "summaryText": "Synthetic bank statement fixture."
  },
  "warnings": [],
  "quality": {
    "overallConfidence": 95
  }
} as const satisfies BankStatementResult;
