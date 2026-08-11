import { getApiClient } from './client';
import type { 
  DocumentCreateResponse, 
  DocumentStatusResponse, 
  DocumentArtifactsResponse,
  DocumentResultResponse
} from '../domain/documents';

export const documentApi = {
  createDocument: async (
    file: File,
    idempotencyKey?: string,
    batchId?: string
  ): Promise<DocumentCreateResponse> => {
    const client = getApiClient();
    const headers: Record<string, string> = {
      'X-Scanalyze-Contract-Version': 'scanalyze.document-journey.v1'
    };
    
    if (idempotencyKey) {
      headers['Idempotency-Key'] = idempotencyKey;
    }

    const payload: Record<string, string | number> = {
      filename: file.name,
      contentType: file.type || 'application/pdf',
      contentLength: file.size,
    };
    
    if (batchId) {
      payload.batchId = batchId;
    }

    const response = await client.post<DocumentCreateResponse>('/api/v2/documents', payload, { headers });
    return response.data;
  },

  submitDocument: async (id: string): Promise<void> => {
    const client = getApiClient();
    const headers = { 'X-Scanalyze-Contract-Version': 'scanalyze.document-journey.v1' };
    
    await client.post(`/api/v2/documents/${id}/submit`, { stage: 'ingest' }, { headers });
  },

  getDocumentStatus: async (id: string): Promise<DocumentStatusResponse> => {
    const client = getApiClient();
    const headers = { 'X-Scanalyze-Contract-Version': 'scanalyze.document-journey.v1' };
    
    const response = await client.get<DocumentStatusResponse>(`/api/v2/documents/${id}`, { headers });
    return response.data;
  },

  getDocumentResult: async (id: string): Promise<DocumentResultResponse> => {
    const client = getApiClient();
    const headers = { 'X-Scanalyze-Contract-Version': 'scanalyze.document-journey.v1' };
    
    const response = await client.get<DocumentResultResponse>(`/api/v2/documents/${id}/result`, { headers });
    return response.data;
  },

  listDocumentArtifacts: async (id: string): Promise<DocumentArtifactsResponse> => {
    const client = getApiClient();
    const headers = { 'X-Scanalyze-Contract-Version': 'scanalyze.document-journey.v1' };
    
    const response = await client.get<DocumentArtifactsResponse>(`/api/v2/documents/${id}/artifacts`, { headers });
    return response.data;
  },

  getArtifactDownloadUrl: async (documentId: string, artifactId: string): Promise<string> => {
    const client = getApiClient();
    const headers = { 'X-Scanalyze-Contract-Version': 'scanalyze.document-journey.v1' };
    
    // El backend nos retorna una URL firmada en un JSON
    const response = await client.get<{ downloadUrl: string }>(`/api/v2/documents/${documentId}/artifacts/${artifactId}/download`, { headers });
    return response.data.downloadUrl;
  }
};
