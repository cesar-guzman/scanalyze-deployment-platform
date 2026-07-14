import axios, { type AxiosProgressEvent } from 'axios';
import type { UploadInstruction } from '../domain/documents';
import { requireHttpsUrl } from '../security/browserBoundaries.js';

/**
 * Se utiliza una instancia limpia de axios,
 * evitando el interceptor global de de auth que inyecta JWT.
 */
export const uploadFileToPresignedUrl = async (
  file: File,
  instruction: UploadInstruction,
  onProgress?: (progress: number) => void
): Promise<void> => {
  const cleanClient = axios.create();
  const uploadUrl = requireHttpsUrl(instruction.url);

  await cleanClient.request({
    url: uploadUrl,
    method: instruction.method || 'PUT',
    data: file,
    headers: {
      // Necesitamos asegurar que el Content-Type coincida
      // exactamente con lo que firmó el Backend
      ...(instruction.headers || {}),
      'Content-Type': instruction.headers?.['Content-Type'] || file.type || 'application/pdf',
    },
    onUploadProgress: (progressEvent: AxiosProgressEvent) => {
      if (progressEvent.total && onProgress) {
        const percentCompleted = Math.round(
          (progressEvent.loaded * 100) / progressEvent.total
        );
        onProgress(percentCompleted);
      }
    },
  });
};
