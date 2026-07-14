import { getApiClient } from './client';
import type { DocumentCreateResponse, DocumentStatusResponse } from '../domain/documents';

interface DocumentCreateApiResponse {
  documentId: string;
  uploadUrl: string;
  uploadMethod?: 'PUT';
  requiredHeaders?: Record<string, string>;
  expiresAt: string;
}

interface StageInfo {
  status?: string;
  startedAt?: string;
  endedAt?: string;
  message?: string;
  error?: string;
}

interface DocumentStatusApiResponse {
  documentId?: string;
  status?: string;
  createdAt?: string;
  updatedAt?: string;
  stages?: Record<string, StageInfo>;
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

export type DocumentResultResponse = Record<string, unknown> & { downloadUrl?: string };

export const documentApi = {
  createDocument: async (
    file: File,
    idempotencyKey?: string,
    batchId?: string
  ): Promise<DocumentCreateResponse> => {
    const client = getApiClient();
    const headers: Record<string, string> = {};
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

    const response = await client.post<DocumentCreateApiResponse>('/documents', payload, { headers });

    const data = response.data;
    return {
      id: data.documentId,
      schemaVersion: '1.0',
      status: {
        overallStatus: 'RECEIVED',
        currentStage: 'RECEIVED',
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
        timeline: []
      },
      upload: {
        mode: 'S3_PRESIGNED_PUT',
        url: data.uploadUrl,
        method: data.uploadMethod || 'PUT',
        headers: data.requiredHeaders || {},
        expiresAt: data.expiresAt
      }
    } as DocumentCreateResponse;
  },

  submitDocument: async (id: string): Promise<void> => {
    const client = getApiClient();
    await client.post(`/documents/${id}/submit`, {});
  },
  getDocumentStatus: async (id: string): Promise<DocumentStatusResponse> => {
    const client = getApiClient();
    const response = await client.get<DocumentStatusApiResponse>(`/documents/${id}`);
    const data = response.data;

    const stages = data.stages ?? {};
    const timeline = Object.entries(stages).map(([stageName, info]) => ({
      stage: stageName,
      state: info.status || 'PENDING',
      startedAt: info.startedAt,
      endedAt: info.endedAt,
      message: info.message,
      error: info.error
    }));

    const currentStage = timeline.length > 0 ? timeline[timeline.length - 1].stage : 'RECEIVED';

    return {
      id: data.documentId || id,
      schemaVersion: '1.0',
      status: {
        overallStatus: data.status || 'PROCESSING',
        currentStage: currentStage,
        createdAt: data.createdAt || new Date().toISOString(),
        updatedAt: data.updatedAt || new Date().toISOString(),
        timeline: timeline
      }
    } as DocumentStatusResponse;
  },
  getDocumentResult: async (id: string): Promise<DocumentResultResponse> => {
    const client = getApiClient();
    // 202 indica que aún no termina, 200 trae el result.
    const response = await client.get<DocumentResultResponse>(`/documents/${id}/result`);
    return response.data;
  },

  listDocumentArtifacts: async (id: string): Promise<DocumentArtifactsResponse> => {
    const client = getApiClient();
    const response = await client.get<DocumentArtifactsResponse>(`/documents/${id}/artifacts`);
    return response.data;
  },

  getArtifactDownloadUrl: async (documentId: string, artifactId: string): Promise<string> => {
    const client = getApiClient();
    const response = await client.get<{ downloadUrl: string }>(`/documents/${documentId}/artifacts/${artifactId}/download`);
    return response.data.downloadUrl;
  }
};
