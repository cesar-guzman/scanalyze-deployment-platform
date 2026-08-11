export type UiStage = 'IDLE' | 'WAITING_SERVER' | 'UPLOADING' | 'PROCESSING_ACTIVE' | 'SUCCESS' | 'ERROR';

export type PipelineStage = 'INGEST' | 'OCR' | 'CLASSIFY' | 'BANK_EXTRACT' | 'PERSONAL_EXTRACT' | 'VALIDATE' | 'TERMINAL';
export type StageState = 'PENDING' | 'RUNNING' | 'SUCCEEDED' | 'FAILED';
export type DocumentLifecycle = 'UPLOAD_PENDING' | 'SUBMITTED' | 'PROCESSING' | 'COMPLETED' | 'FAILED';
export type ProcessingCondition = 'ACTIVE' | 'NOT_APPLICABLE';
export type FailureDisposition = 'RETRYABLE' | 'TERMINAL';

export interface Progress {
  attempt?: number;
  completedStages?: number;
  totalStages?: number;
}

export interface DocumentCreateResponse {
  schemaVersion: string;
  contractVersion: string;
  replayed: boolean;
  durableResponse: {
    schemaVersion: string;
    contractVersion: string;
    operation: string;
    documentId: string;
    batchId?: string;
    status: string;
    contentType: string;
    createdAt: string;
  };
  uploadCapability?: {
    url: string;
    method: 'PUT' | 'POST';
    expiresAt: string;
    requiredHeaders: Record<string, string>;
  };
}

export interface DocumentStatusResponse {
  schemaVersion: string;
  contractVersion: string;
  batchId?: string;
  documentId: string;
  lifecycle: DocumentLifecycle;
  currentStage: PipelineStage;
  stageState: StageState;
  processingCondition: ProcessingCondition;
  createdAt: string;
  updatedAt: string;
  terminalAt?: string;
  correlationReference?: string;
  progress?: Progress;
  failureDisposition?: FailureDisposition;
  safeFailureCode?: string;
}

export interface DocumentArtifact {
  artifactId?: string;
  bucketAlias?: string;
  filename?: string;
  contentType?: string;
  metadata?: Record<string, unknown>;
}

export interface DocumentArtifactsResponse {
  artifacts?: DocumentArtifact[];
}

export interface BankStatementData {
  account_holder_name?: string | null;
  bank_name?: string | null;
  account_number_mask?: string | null;
  statement_date?: string | null;
  opening_balance?: number | null;
  closing_balance?: number | null;
  currency?: string | null;
  transactions?: Array<{
    date: string;
    description: string;
    amount: number;
    type: 'CREDIT' | 'DEBIT';
  }>;
}

export interface DocumentResultResponse {
  schemaVersion: string;
  contractVersion: string;
  documentType: 'bank_statement';
  resultType: 'bank_statement';
  documentId: string;
  resultId: string;
  resultVersion: string;
  provenance: {
    processor: { engine: string; model: string; };
    producerSchemaVersion: string;
    promptVersion: string;
    generatedAt: string;
  };
  data: BankStatementData;
  warnings: Array<{ code: string; message: string; }>;
  quality: {
    overall_confidence: number;
    legibility_score: number;
  };
  downloadUrl?: string; // Appended by our API client wrapper
}
