// Contract-derived frontend types.
// Authority: ../../../../schemas/scanalyze-document-journey.openapi.v1.json and
// ../../../../schemas/scanalyze-document-journey-result.v1.schema.json.
// tests/test_gug354_document_journey_schemas.py proves constants and fixtures
// against those sources; frontend code must not add independent enum values.

export const DOCUMENT_JOURNEY_API_NAMESPACE = "/api/v2" as const;
export const DOCUMENT_JOURNEY_CONTRACT_VERSION = "scanalyze.document-journey.v1" as const;
export const DOCUMENT_JOURNEY_CONTRACT_HEADER = "X-Scanalyze-Contract-Version" as const;
export const DOCUMENT_JOURNEY_IDEMPOTENCY_HEADER = "Idempotency-Key" as const;

export const DOCUMENT_JOURNEY_OPERATIONS = ["batches.create", "documents.create"] as const;
export const DOCUMENT_JOURNEY_LEDGER_STATES = ["PENDING", "SUCCEEDED", "FAILED_RETRYABLE", "FAILED_TERMINAL", "UNKNOWN_OR_QUARANTINED", "EXPIRED"] as const;
export const DOCUMENT_JOURNEY_CONTENT_TYPES = ["application/pdf", "image/jpeg", "image/png", "image/tiff"] as const;
export const DOCUMENT_LIFECYCLES = ["UPLOAD_PENDING", "SUBMITTED", "PROCESSING", "COMPLETED", "FAILED"] as const;
export const DOCUMENT_PIPELINE_STAGES = ["INGEST", "OCR", "CLASSIFY", "BANK_EXTRACT", "PERSONAL_EXTRACT", "VALIDATE", "TERMINAL"] as const;
export const DOCUMENT_STAGE_STATES = ["PENDING", "RUNNING", "SUCCEEDED", "FAILED"] as const;
export const DOCUMENT_PROCESSING_CONDITIONS = ["ACTIVE", "NOT_APPLICABLE"] as const;
export const DOCUMENT_FAILURE_DISPOSITIONS = ["RETRYABLE", "TERMINAL"] as const;
export const DOCUMENT_SAFE_FAILURE_CODES = ["DOCUMENT_PROCESSING_FAILED", "OCR_FAILED", "ENQUEUE_FAILED"] as const;
export const DOCUMENT_JOURNEY_RETRY_CLASSES = ["NOT_RETRYABLE", "RETRYABLE_WITH_BACKOFF", "RETRY_ONLY_AFTER_RECONCILIATION", "TERMINAL", "UNKNOWN_OR_QUARANTINED"] as const;
export const DOCUMENT_JOURNEY_ERROR_CODES = ["MALFORMED_REQUEST", "AUTHENTICATION_REQUIRED", "AUTHENTICATION_INVALID", "AUTHORIZATION_DENIED", "NOT_FOUND", "IDEMPOTENCY_CONFLICT", "RESULT_NOT_READY", "SEMANTIC_VALIDATION_FAILED", "RATE_LIMITED", "INTERNAL_ERROR", "UPSTREAM_ERROR", "SERVICE_UNAVAILABLE", "REQUEST_TIMEOUT", "UNSUPPORTED_CONTRACT_VERSION", "UNKNOWN_WRITE_OUTCOME", "STATE_CONFLICT", "UNSUPPORTED_STATE", "MALFORMED_INTERNAL_RESULT", "EXPIRED_OPERATION", "UNSUPPORTED_RESULT_TYPE"] as const;
export const BANK_STATEMENT_TRANSACTION_CATEGORIES = ["nómina", "transferencia", "spei", "comisión", "retiro_atm", "compra_pos", "pago_servicio", "interés", "dividendo", "cheque", "domiciliación", "otro"] as const;
export const BANK_STATEMENT_WARNING_CODES = ["BALANCE_RECONCILIATION_WARNING", "INCOMPLETE_EXTRACTION", "LOW_CONFIDENCE"] as const;

export type DocumentJourneyOperation = typeof DOCUMENT_JOURNEY_OPERATIONS[number];
export type DocumentJourneyLedgerState = typeof DOCUMENT_JOURNEY_LEDGER_STATES[number];
export type DocumentContentType = typeof DOCUMENT_JOURNEY_CONTENT_TYPES[number];
export type DocumentLifecycle = typeof DOCUMENT_LIFECYCLES[number];
export type DocumentPipelineStage = typeof DOCUMENT_PIPELINE_STAGES[number];
export type DocumentStageState = typeof DOCUMENT_STAGE_STATES[number];
export type DocumentProcessingCondition = typeof DOCUMENT_PROCESSING_CONDITIONS[number];
export type DocumentFailureDisposition = typeof DOCUMENT_FAILURE_DISPOSITIONS[number];
export type DocumentSafeFailureCode = typeof DOCUMENT_SAFE_FAILURE_CODES[number];
export type DocumentJourneyRetryClass = typeof DOCUMENT_JOURNEY_RETRY_CLASSES[number];
export type DocumentJourneyErrorCode = typeof DOCUMENT_JOURNEY_ERROR_CODES[number];
export type BankStatementTransactionCategory = typeof BANK_STATEMENT_TRANSACTION_CATEGORIES[number];
export type BankStatementWarningCode = typeof BANK_STATEMENT_WARNING_CODES[number];

export const DOCUMENT_JOURNEY_ERROR_POLICY = {
  "MALFORMED_REQUEST": { "httpStatus": 400, "message": "The request is malformed.", "retryClass": "NOT_RETRYABLE", "retryAfterAllowed": false },
  "AUTHENTICATION_REQUIRED": { "httpStatus": 401, "message": "Authentication is required.", "retryClass": "NOT_RETRYABLE", "retryAfterAllowed": false },
  "AUTHENTICATION_INVALID": { "httpStatus": 401, "message": "Authentication is invalid.", "retryClass": "NOT_RETRYABLE", "retryAfterAllowed": false },
  "AUTHORIZATION_DENIED": { "httpStatus": 403, "message": "The operation is not authorized.", "retryClass": "TERMINAL", "retryAfterAllowed": false },
  "NOT_FOUND": { "httpStatus": 404, "message": "The requested resource was not found.", "retryClass": "TERMINAL", "retryAfterAllowed": false },
  "IDEMPOTENCY_CONFLICT": { "httpStatus": 409, "message": "The idempotency key is bound to a different request.", "retryClass": "TERMINAL", "retryAfterAllowed": false },
  "RESULT_NOT_READY": { "httpStatus": 409, "message": "The document result is not ready.", "retryClass": "RETRYABLE_WITH_BACKOFF", "retryAfterAllowed": false },
  "SEMANTIC_VALIDATION_FAILED": { "httpStatus": 422, "message": "The request failed semantic validation.", "retryClass": "NOT_RETRYABLE", "retryAfterAllowed": false },
  "RATE_LIMITED": { "httpStatus": 429, "message": "The request rate is limited.", "retryClass": "RETRYABLE_WITH_BACKOFF", "retryAfterAllowed": true },
  "INTERNAL_ERROR": { "httpStatus": 500, "message": "The service could not complete the request.", "retryClass": "UNKNOWN_OR_QUARANTINED", "retryAfterAllowed": false },
  "UPSTREAM_ERROR": { "httpStatus": 502, "message": "A required service failed.", "retryClass": "RETRYABLE_WITH_BACKOFF", "retryAfterAllowed": false },
  "SERVICE_UNAVAILABLE": { "httpStatus": 503, "message": "The service is temporarily unavailable.", "retryClass": "RETRYABLE_WITH_BACKOFF", "retryAfterAllowed": true },
  "REQUEST_TIMEOUT": { "httpStatus": 503, "message": "The request outcome is not confirmed.", "retryClass": "RETRY_ONLY_AFTER_RECONCILIATION", "retryAfterAllowed": false },
  "UNSUPPORTED_CONTRACT_VERSION": { "httpStatus": 400, "message": "The contract version is not supported.", "retryClass": "NOT_RETRYABLE", "retryAfterAllowed": false },
  "UNKNOWN_WRITE_OUTCOME": { "httpStatus": 500, "message": "The write outcome requires reconciliation.", "retryClass": "RETRY_ONLY_AFTER_RECONCILIATION", "retryAfterAllowed": false },
  "STATE_CONFLICT": { "httpStatus": 409, "message": "The resource state conflicts with this operation.", "retryClass": "TERMINAL", "retryAfterAllowed": false },
  "UNSUPPORTED_STATE": { "httpStatus": 500, "message": "The resource state is not supported.", "retryClass": "UNKNOWN_OR_QUARANTINED", "retryAfterAllowed": false },
  "MALFORMED_INTERNAL_RESULT": { "httpStatus": 500, "message": "The document result is invalid.", "retryClass": "UNKNOWN_OR_QUARANTINED", "retryAfterAllowed": false },
  "EXPIRED_OPERATION": { "httpStatus": 409, "message": "The operation key has expired.", "retryClass": "TERMINAL", "retryAfterAllowed": false },
  "UNSUPPORTED_RESULT_TYPE": { "httpStatus": 422, "message": "The document result type is not supported.", "retryClass": "TERMINAL", "retryAfterAllowed": false }
} as const satisfies Record<DocumentJourneyErrorCode, {
  readonly httpStatus: 400 | 401 | 403 | 404 | 409 | 422 | 429 | 500 | 502 | 503;
  readonly message: string;
  readonly retryClass: DocumentJourneyRetryClass;
  readonly retryAfterAllowed: boolean;
}>;

export type BatchCreateRequest = Record<string, never>;

export interface DocumentCreateRequest {
  readonly filename?: string;
  readonly contentType: DocumentContentType;
  readonly contentLength?: number;
  readonly batchId?: string;
}

export interface BatchDurableResponse {
  readonly schemaVersion: "scanalyze.batch-create-result.v1";
  readonly contractVersion: typeof DOCUMENT_JOURNEY_CONTRACT_VERSION;
  readonly operation: "batches.create";
  readonly batchId: string;
  readonly status: "OPEN";
  readonly createdAt: string;
}

export interface DocumentDurableResponse {
  readonly schemaVersion: "scanalyze.document-create-result.v1";
  readonly contractVersion: typeof DOCUMENT_JOURNEY_CONTRACT_VERSION;
  readonly operation: "documents.create";
  readonly documentId: string;
  readonly batchId?: string;
  readonly status: "UPLOAD_PENDING";
  readonly contentType: DocumentContentType;
  readonly createdAt: string;
}

export interface UploadCapability {
  readonly method: "PUT";
  readonly url: string;
  readonly expiresAt: string;
  readonly requiredHeaders: {
    readonly "Content-Type": DocumentContentType;
  };
}

export interface BatchCreateResponse {
  readonly schemaVersion: "scanalyze.operation-response.v1";
  readonly contractVersion: typeof DOCUMENT_JOURNEY_CONTRACT_VERSION;
  readonly replayed: boolean;
  readonly durableResponse: BatchDurableResponse;
}

interface DocumentCreateResponseBase {
  readonly schemaVersion: "scanalyze.operation-response.v1";
  readonly contractVersion: typeof DOCUMENT_JOURNEY_CONTRACT_VERSION;
  readonly durableResponse: DocumentDurableResponse;
}

export type DocumentCreateResponseV2 = DocumentCreateResponseBase & (
  | {
      readonly replayed: false;
      readonly uploadCapability: UploadCapability;
    }
  | {
      readonly replayed: true;
      readonly uploadCapability?: UploadCapability;
    }
);

export interface SubmitDocumentRequest {
  readonly stage?: "ingest";
}

export interface SubmitDocumentResponseV2 {
  readonly schemaVersion: "scanalyze.document-submit.v1";
  readonly contractVersion: typeof DOCUMENT_JOURNEY_CONTRACT_VERSION;
  readonly documentId: string;
  readonly stage: "ingest";
  readonly enqueued: boolean;
}

export interface UploadCapabilityResponse {
  readonly schemaVersion: "scanalyze.upload-capability.v1";
  readonly contractVersion: typeof DOCUMENT_JOURNEY_CONTRACT_VERSION;
  readonly documentId: string;
  readonly uploadCapability: UploadCapability;
}

interface ReconciliationBase {
  readonly schemaVersion: "scanalyze.reconciliation.v1";
  readonly contractVersion: typeof DOCUMENT_JOURNEY_CONTRACT_VERSION;
  readonly createdAt: string;
  readonly updatedAt: string;
  readonly expiresAt: string;
}

type ReconciliationForOperation<
  Operation extends DocumentJourneyOperation,
  DurableResponse,
> = ReconciliationBase & { readonly operation: Operation } & (
  | {
      readonly ledgerState: "PENDING";
      readonly durableResponse?: never;
      readonly failureCode?: never;
      readonly completedAt?: never;
    }
  | {
      readonly ledgerState: "SUCCEEDED";
      readonly durableResponse: DurableResponse;
      readonly failureCode?: never;
      readonly completedAt: string;
    }
  | {
      readonly ledgerState: "FAILED_RETRYABLE";
      readonly durableResponse?: never;
      readonly failureCode: "CREATE_FAILED_RETRYABLE";
      readonly completedAt?: never;
    }
  | {
      readonly ledgerState: "FAILED_TERMINAL";
      readonly durableResponse?: never;
      readonly failureCode: "CREATE_FAILED_TERMINAL";
      readonly completedAt: string;
    }
  | {
      readonly ledgerState: "UNKNOWN_OR_QUARANTINED";
      readonly durableResponse?: never;
      readonly failureCode: "UNKNOWN_WRITE_OUTCOME";
      readonly completedAt: string;
    }
  | {
      readonly ledgerState: "EXPIRED";
      readonly durableResponse?: never;
      readonly failureCode: "OPERATION_EXPIRED";
      readonly completedAt: string;
    }
);

export type ReconciliationResponse =
  | ReconciliationForOperation<"batches.create", BatchDurableResponse>
  | ReconciliationForOperation<"documents.create", DocumentDurableResponse>;

export interface DocumentProgress {
  readonly attempt?: number;
  readonly completedStages?: number;
  readonly totalStages?: number;
}

interface DocumentStatusBase {
  readonly schemaVersion: "scanalyze.document-status.v1";
  readonly contractVersion: typeof DOCUMENT_JOURNEY_CONTRACT_VERSION;
  readonly batchId?: string;
  readonly documentId: string;
  readonly createdAt: string;
  readonly updatedAt: string;
  readonly correlationReference?: string;
  readonly progress?: DocumentProgress;
}

export type DocumentStatusResponseV2 = DocumentStatusBase & (
  | {
      readonly lifecycle: "UPLOAD_PENDING";
      readonly currentStage: "INGEST";
      readonly stageState: "PENDING";
      readonly processingCondition: "ACTIVE";
      readonly terminalAt?: never;
      readonly failureDisposition?: never;
      readonly safeFailureCode?: never;
    }
  | {
      readonly lifecycle: "SUBMITTED";
      readonly currentStage: "INGEST";
      readonly stageState: "PENDING" | "RUNNING";
      readonly processingCondition: "ACTIVE";
      readonly terminalAt?: never;
      readonly failureDisposition?: never;
      readonly safeFailureCode?: never;
    }
  | {
      readonly lifecycle: "PROCESSING";
      readonly currentStage: "INGEST" | "OCR" | "CLASSIFY" | "BANK_EXTRACT" | "PERSONAL_EXTRACT" | "VALIDATE";
      readonly stageState: "PENDING" | "RUNNING" | "SUCCEEDED";
      readonly processingCondition: "ACTIVE";
      readonly terminalAt?: never;
      readonly failureDisposition?: never;
      readonly safeFailureCode?: never;
    }
  | {
      readonly lifecycle: "SUBMITTED";
      readonly currentStage: "INGEST";
      readonly stageState: "FAILED";
      readonly processingCondition: "NOT_APPLICABLE";
      readonly terminalAt?: never;
      readonly failureDisposition: "RETRYABLE";
      readonly safeFailureCode: "ENQUEUE_FAILED";
    }
  | {
      readonly lifecycle: "COMPLETED";
      readonly currentStage: "TERMINAL";
      readonly stageState: "SUCCEEDED";
      readonly processingCondition: "NOT_APPLICABLE";
      readonly terminalAt: string;
      readonly failureDisposition?: never;
      readonly safeFailureCode?: never;
    }
  | {
      readonly lifecycle: "FAILED";
      readonly currentStage: "TERMINAL";
      readonly stageState: "FAILED";
      readonly processingCondition: "NOT_APPLICABLE";
      readonly terminalAt: string;
      readonly failureDisposition: "TERMINAL";
      readonly safeFailureCode: "DOCUMENT_PROCESSING_FAILED" | "OCR_FAILED";
    }
);

export interface DocumentJourneyErrorDetails {
  readonly field?: "body" | "contentLength" | "contentType" | "documentId" | "Idempotency-Key" | "operation" | "stage" | "X-Scanalyze-Contract-Version";
  readonly operation?: DocumentJourneyOperation;
}

export interface DocumentJourneyBackoffErrorDetails extends DocumentJourneyErrorDetails {
  readonly retryAfterSeconds?: number;
}

type DocumentJourneyErrorDetailsFor<Code extends DocumentJourneyErrorCode> =
  Code extends "RATE_LIMITED" | "SERVICE_UNAVAILABLE"
    ? DocumentJourneyBackoffErrorDetails
    : DocumentJourneyErrorDetails & { readonly retryAfterSeconds?: never };

type DocumentJourneyErrorEnvelopeFor<Code extends DocumentJourneyErrorCode> = {
  readonly schemaVersion: "scanalyze.error.v1";
  readonly code: Code;
  readonly message: typeof DOCUMENT_JOURNEY_ERROR_POLICY[Code]["message"];
  readonly correlationId: string;
  readonly retryClass: typeof DOCUMENT_JOURNEY_ERROR_POLICY[Code]["retryClass"];
  readonly details?: DocumentJourneyErrorDetailsFor<Code>;
};

export type DocumentJourneyErrorEnvelope = {
  [Code in DocumentJourneyErrorCode]: DocumentJourneyErrorEnvelopeFor<Code>
}[DocumentJourneyErrorCode];

export interface BankStatementTransaction {
  readonly date: string | null;
  readonly description: string | null;
  readonly reference: string | null;
  readonly direction: "credit" | "debit";
  readonly amount: number | null;
  readonly balanceAfter: number | null;
  readonly category: BankStatementTransactionCategory | null;
}

export interface BankStatementData {
  readonly bank: { readonly name: string | null };
  readonly account: {
    readonly holder: string | null;
    readonly numberMasked: string | null;
    readonly clabeMasked: string | null;
    readonly currency: string | null;
  };
  readonly statement: {
    readonly periodStart: string | null;
    readonly periodEnd: string | null;
  };
  readonly balances: {
    readonly opening: number | null;
    readonly closing: number | null;
    readonly totalCredits: number | null;
    readonly totalDebits: number | null;
  };
  readonly transactions: readonly BankStatementTransaction[];
  readonly accountType: "cheques" | "ahorro" | "crédito" | "inversión" | "nómina" | null;
  readonly bankCountry: string | null;
  readonly fees: {
    readonly totalFees: number | null;
    readonly ivaOnFees: number | null;
  } | null;
  readonly interestEarned: number | null;
  readonly interestCharged: number | null;
  readonly summaryText: string | null;
}

export interface BankStatementResult {
  readonly schemaVersion: "scanalyze.document-result.v1";
  readonly contractVersion: typeof DOCUMENT_JOURNEY_CONTRACT_VERSION;
  readonly documentType: "bank_statement";
  readonly resultType: "bank_statement";
  readonly documentId: string;
  readonly resultId: string;
  readonly resultVersion: "1.0";
  readonly provenance: {
    readonly processor: "bank-extract";
    readonly producerSchemaVersion: "1.0";
    readonly promptVersion: string;
    readonly generatedAt: string;
  };
  readonly data: BankStatementData;
  readonly warnings: readonly { readonly code: BankStatementWarningCode }[];
  readonly quality: { readonly overallConfidence: number };
}
