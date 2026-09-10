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

export type {
  BankStatementData,
  BankStatementResult as DocumentResultResponse,
} from '../contracts/documentJourney.v1';
