export const UPLOAD_ACCEPT = 'application/pdf,image/jpeg,image/png,image/tiff';

const uploadTypes = new Set(UPLOAD_ACCEPT.split(','));

export function isSupportedUploadType(contentType: string): boolean {
  return uploadTypes.has(contentType);
}
