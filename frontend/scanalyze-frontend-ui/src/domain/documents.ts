export type BackendStage =
  | 'RECEIVED'
  | 'UPLOADED'
  | 'OCR'
  | 'CLASSIFIED'
  | 'EXTRACTED'
  | 'VALIDATED'
  | 'COMPLETED';

export type BackendOverallStatus =
  | 'RECEIVED'
  | 'UPLOADED'
  | 'PROCESSING'
  | 'COMPLETED'
  | 'FAILED';

export type StageState = 'PENDING' | 'RUNNING' | 'SUCCEEDED' | 'FAILED' | 'SKIPPED';

export interface StageTimelineItem {
  stage: BackendStage;
  state: StageState;
  startedAt?: string;
  endedAt?: string;
  message?: string;
  error?: {
    code: string;
    message: string;
  };
}

export interface DocumentStatus {
  overallStatus: BackendOverallStatus;
  currentStage: BackendStage;
  createdAt: string;
  updatedAt: string;
  timeline: StageTimelineItem[];
}

// Modelado de UiStage
export type UiStage =
  | 'IDLE'
  | 'UPLOADING'
  | 'WAITING_SERVER'
  | 'PROCESSING_ACTIVE'
  | 'SUCCESS'
  | 'ERROR';

export interface StatusHistoryEntry {
  stage: BackendStage;
  state: StageState;
  at: Date;
  source: 'backend' | 'observed_in_ui';
}

export interface UploadInstruction {
  mode: 'S3_PRESIGNED_PUT';
  url: string;
  method: string;
  headers: Record<string, string>;
  expiresAt: string;
}

export interface DocumentCreateResponse {
  id: string;
  schemaVersion: string;
  status: DocumentStatus;
  upload?: UploadInstruction;
}

export interface DocumentStatusResponse {
  id: string;
  schemaVersion: string;
  status: DocumentStatus;
}
