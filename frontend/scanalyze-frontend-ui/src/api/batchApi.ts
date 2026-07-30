import { getApiClient } from './client';

export interface BatchMetadata {
  [key: string]: unknown;
}

export interface BatchResponse {
  batchId: string;
  tenantId: string;
  createdAt: string;
  createdBy?: string;
  status: string;
  metadata: BatchMetadata;
  counters: Record<string, number>;
}

export interface BatchDocumentResponse {
  documentId?: string;
  status?: string;
  createdAt?: string;
  input?: {
    filename?: string;
    contentType?: string;
  };
}

export const batchApi = {
  createBatch: async (metadata: BatchMetadata = {}): Promise<BatchResponse> => {
    const client = getApiClient();
    const response = await client.post('/batches', { metadata });
    return response.data as BatchResponse;
  },

  getBatch: async (batchId: string): Promise<BatchResponse> => {
    const client = getApiClient();
    const response = await client.get(`/batches/${batchId}`);
    return response.data as BatchResponse;
  },

  getBatchDocuments: async (batchId: string): Promise<BatchDocumentResponse[]> => {
    const client = getApiClient();
    const response = await client.get<BatchDocumentResponse[]>(`/batches/${batchId}/documents`);
    return response.data;
  },

  downloadManifest: async (batchId: string): Promise<void> => {
    const client = getApiClient();
    const response = await client.get(`/batches/${batchId}/manifest`);
    downloadBlob(new Blob([JSON.stringify(response.data, null, 2)], { type: 'application/json' }), `batch_${batchId}_manifest.json`);
  },

  downloadJson: async (batchId: string): Promise<void> => {
    const client = getApiClient();
    const response = await client.get(`/batches/${batchId}/exports/json`, { responseType: 'blob' });
    downloadBlob(response.data, `batch_${batchId}_consolidated.json`);
  },

  downloadCsv: async (batchId: string): Promise<void> => {
    const client = getApiClient();
    const response = await client.get(`/batches/${batchId}/exports/csv`, { responseType: 'blob' });
    downloadBlob(response.data, `batch_${batchId}_summary.csv`);
  },

  downloadZip: async (batchId: string): Promise<void> => {
    const client = getApiClient();
    const response = await client.get(`/batches/${batchId}/exports/zip`, { responseType: 'blob' });
    downloadBlob(response.data, `batch_${batchId}_export.zip`);
  }
};

function downloadBlob(blob: Blob, filename: string) {
  const url = window.URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.style.display = 'none';
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  window.URL.revokeObjectURL(url);
  document.body.removeChild(a);
}
