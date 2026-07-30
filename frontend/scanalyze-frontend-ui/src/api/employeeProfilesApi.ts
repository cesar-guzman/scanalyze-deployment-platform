import { getApiClient } from './client';

// ─── Types ─────────────────────────────────────

export interface FeatureStatus {
  enabled: boolean;
  mode: string;
  tenantEnabled: boolean;
  maxDocumentsPerBatch: number;
}

export interface GenerateRequest {
  batchId: string;
  options?: { force?: boolean; includeIncomplete?: boolean };
}

export interface GenerateResponse {
  jobId: string;
  batchId: string;
  status: string;
  mode: string;
  existing: boolean;
  profileCount: number;
}

export interface JobStatus {
  entityType: string;
  tenantId: string;
  jobId: string;
  batchId: string;
  status: string;
  eligibleDocumentCount: number;
  processedDocumentCount: number;
  profileCount: number;
  warningCount: number;
  errorMessage: string | null;
  createdAt: string;
  updatedAt: string;
}

export interface ProfileListItem {
  profileId: string;
  fullName: string;
  status: string;
  completenessScore: number;
  maskedIdentifiers: Record<string, string>;
  sourceDocumentCount: number;
  missingFieldCount: number;
  warningCount: number;
  generatedAt: string;
  batchId: string;
}

export interface ProfileListResponse {
  profiles: ProfileListItem[];
  total: number;
  batchId: string;
}

export interface ProfileDetail {
  entityType: string;
  tenantId: string;
  profileId: string;
  batchId: string;
  personKey: string;
  status: string;
  completenessScore: number;
  fullName: string;
  firstNames: string;
  lastNames: string;
  birthDate: string;
  sex: string;
  nationality: string;
  address: string;
  phone?: string;
  email?: string;
  identifiers: Record<string, string | null>;
  maskedIdentifiers: Record<string, string>;
  fieldSources: Record<string, unknown>;
  sourceDocuments: Array<{
    documentId: string;
    documentType: string;
    batchId: string;
    status: string;
    usedFields: string[];
  }>;
  documentsDetected?: Record<string, string[]>;
  documentChecklist?: Record<string, string>;
  documentComponents?: Array<{
    componentId: string;
    sourceDocumentId: string;
    pageStart: number;
    pageEnd: number;
    detectedType: string;
    confidence: number;
    evidenceCodes: string[];
    extractionMethods: string[];
  }>;
  requiresComponentReview?: boolean;
  mergeEvidence?: Array<{ type: string; documents: string[] }>;
  missingFields: string[];
  warnings: Array<{ code: string; severity: string; message: string }>;
  generatedAt: string;
  generatedBy: string;
}

// ─── API Factory ───────────────────────────────

const DEFAULT_BASE = '/addons/employee-profiles';

/**
 * Create an Employee Profiles API client bound to a specific base path.
 *
 * Usage:
 *   const base = getApiBasePath('employee-profiles'); // from registry hook
 *   const api = createEmployeeProfilesApi(base);
 *   const profiles = await api.listProfiles({ batchId: '...' });
 *
 * If no base is provided, defaults to the in-process path.
 */
export function createEmployeeProfilesApi(apiBasePath?: string) {
  const BASE = apiBasePath || DEFAULT_BASE;

  return {
    /** Check if feature is enabled for current tenant */
    getStatus: async (): Promise<FeatureStatus> => {
      try {
        const client = getApiClient();
        const resp = await client.get(`${BASE}/status`);
        return resp.data as FeatureStatus;
      } catch {
        return { enabled: false, mode: 'disabled', tenantEnabled: false, maxDocumentsPerBatch: 200 };
      }
    },

    /** Generate profiles for a batch */
    generate: async (req: GenerateRequest): Promise<GenerateResponse> => {
      const client = getApiClient();
      const resp = await client.post(`${BASE}/generate`, req);
      return resp.data as GenerateResponse;
    },

    /** Get job status */
    getJob: async (jobId: string, batchId: string): Promise<JobStatus> => {
      const client = getApiClient();
      const resp = await client.get(`${BASE}/jobs/${jobId}?batchId=${batchId}`);
      return resp.data as JobStatus;
    },

    /** List profiles for a batch */
    listProfiles: async (params: {
      batchId: string;
      status?: string;
      q?: string;
      limit?: number;
    }): Promise<ProfileListResponse> => {
      const client = getApiClient();
      const searchParams = new URLSearchParams();
      searchParams.append('batchId', params.batchId);
      if (params.status) searchParams.append('status', params.status);
      if (params.q) searchParams.append('q', params.q);
      if (params.limit) searchParams.append('limit', String(params.limit));
      const resp = await client.get(`${BASE}?${searchParams.toString()}`);
      return resp.data as ProfileListResponse;
    },

    /** Get profile detail */
    getProfile: async (profileId: string, batchId: string): Promise<ProfileDetail> => {
      const client = getApiClient();
      const resp = await client.get(`${BASE}/${profileId}?batchId=${batchId}`);
      return resp.data as ProfileDetail;
    },

    /** Download JSON export for a single profile */
    exportJson: async (profileId: string, batchId: string): Promise<void> => {
      const client = getApiClient();
      const resp = await client.get(`${BASE}/${profileId}/export/json?batchId=${batchId}`, { responseType: 'blob' });
      downloadBlob(resp.data, `profile_${profileId.substring(0, 12)}.json`);
    },

    /** Download CSV export for a batch */
    exportCsv: async (batchId: string): Promise<void> => {
      const client = getApiClient();
      const resp = await client.get(`${BASE}/export/csv?batchId=${batchId}`, { responseType: 'blob' });
      downloadBlob(resp.data, `employee_profiles_${batchId.substring(0, 12)}.csv`);
    },

    /** Download CSV export for a single profile */
    exportCsvIndividual: async (profileId: string, batchId: string): Promise<void> => {
      const client = getApiClient();
      const resp = await client.get(`${BASE}/${profileId}/export/csv?batchId=${batchId}`, { responseType: 'blob' });
      downloadBlob(resp.data, `profile_${profileId.substring(0, 12)}.csv`);
    },
  };
}

/**
 * Backward-compatible default instance using in-process path.
 * Existing code can continue using this without changes.
 */
export const employeeProfilesApi = createEmployeeProfilesApi();

// ─── Helpers ───────────────────────────────────

function downloadBlob(data: Blob | string | ArrayBuffer, filename: string) {
  const ext = filename.split('.').pop()?.toLowerCase();
  const mimeType = ext === 'csv' ? 'text/csv;charset=utf-8' :
                   ext === 'json' ? 'application/json;charset=utf-8' :
                   'application/octet-stream';

  const blob = new Blob([data], { type: mimeType });
  const url = window.URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.style.display = 'none';
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  setTimeout(() => {
    window.URL.revokeObjectURL(url);
    document.body.removeChild(a);
  }, 200);
}
