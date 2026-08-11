import axios, { type AxiosProgressEvent } from 'axios';
import { requireHttpsUrl } from '../security/browserBoundaries.js';
import type { DocumentCreateResponse } from '../domain/documents';

/**
 * Se utiliza una instancia limpia de axios,
 * evitando el interceptor global de auth que inyecta JWT.
 */
export const uploadFileToPresignedUrl = async (
  file: File,
  instruction: NonNullable<DocumentCreateResponse['uploadCapability']>,
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
      ...(instruction.requiredHeaders || {}),
      'Content-Type': instruction.requiredHeaders?.['Content-Type'] || file.type || 'application/pdf',
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
