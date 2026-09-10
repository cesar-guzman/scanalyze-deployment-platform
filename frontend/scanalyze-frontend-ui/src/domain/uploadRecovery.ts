import axios from 'axios';
import { User } from 'oidc-client-ts';
import { getConfig } from '../config';
import { DOCUMENT_JOURNEY_CONTRACT_VERSION, DOCUMENT_JOURNEY_ERROR_POLICY } from '../contracts/documentJourney.v1';
import type { DocumentCreateResponse, DocumentStatusResponse } from './documents';

type UploadPhase = 'CREATE_UNKNOWN' | 'UPLOAD_PENDING' | 'UPLOADED' | 'SUBMIT_UNKNOWN' | 'STOPPED';

// Only opaque recovery references survive a reload. Files, filenames, tokens,
// signed capabilities and server error bodies must never enter this journal.
export interface UploadIntent {
  version: 1;
  key: string;
  fileDigest: string;
  phase: UploadPhase;
  documentId?: string;
}

const phases: readonly UploadPhase[] = ['CREATE_UNKNOWN', 'UPLOAD_PENDING', 'UPLOADED', 'SUBMIT_UNKNOWN', 'STOPPED'];
const documentIdPattern = /^[0-9a-f]{32}$/;
const keyPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const digestPattern = /^[0-9a-f]{64}$/;

export class UploadRecoveryError extends Error {}

const digest = async (value: ArrayBuffer): Promise<string> => (
  Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', value)), byte => byte.toString(16).padStart(2, '0')).join('')
);

const textDigest = (value: string): Promise<string> => digest(new TextEncoder().encode(value).buffer);

export async function uploadStorageKey(subject: string | undefined): Promise<string> {
  if (!subject) throw new UploadRecoveryError('La sesión no permite recuperar cargas. Inicia sesión de nuevo.');
  const config = getConfig();
  // This namespace only isolates browser UX. The API independently authorizes
  // every operation using the verified access token and resource ownership.
  const scope = [config.apiBaseUrl, config.cognitoIssuerUrl, config.cognitoClientId, config.customerId, config.deploymentId, subject];
  return `scanalyze.upload.v1:${await textDigest(JSON.stringify(scope))}`;
}

export function requireUploadSession(expectedSubject: string | undefined): void {
  try {
    const config = getConfig();
    const serialized = sessionStorage.getItem(`oidc.user:${config.cognitoIssuerUrl}:${config.cognitoClientId}`);
    if (!serialized || !expectedSubject) throw new Error();
    const current = User.fromStorageString(serialized);
    if (current.expired || !current.access_token || current.profile.sub !== expectedSubject) throw new Error();
  } catch {
    throw new UploadRecoveryError('La sesión cambió o expiró. Inicia sesión de nuevo para recuperar la carga original.');
  }
}

export async function fingerprintUpload(file: File): Promise<string> {
  const allowedTypes = ['application/pdf', 'image/jpeg', 'image/png', 'image/tiff'];
  const invalidName = !file.name.trim() || ['.', '..'].includes(file.name.trim())
    || Array.from(file.name).some(char => char.charCodeAt(0) < 32 || char.charCodeAt(0) === 127 || char === '/' || char === '\\');
  if (!allowedTypes.includes(file.type) || file.size > 536870912 || !file.size
      || file.name.length > 128 || invalidName) {
    throw new UploadRecoveryError('Selecciona un PDF, PNG, JPEG o TIFF válido de hasta 512 MiB, con un nombre de hasta 128 caracteres.');
  }
  // Hash fixed-size chunks to avoid buffering a 512 MiB file in the browser.
  // Including request metadata prevents replacing an uncertain CREATE intent.
  const chunks: string[] = [];
  for (let offset = 0; offset < file.size; offset += 1024 * 1024) {
    chunks.push(await digest(await file.slice(offset, offset + 1024 * 1024).arrayBuffer()));
  }
  return textDigest(JSON.stringify([file.name, file.type, file.size, chunks]));
}

export function readUploadIntent(storageKey: string): UploadIntent | null {
  try {
    const serialized = sessionStorage.getItem(storageKey);
    if (serialized === null) return null;
    if (serialized.length > 512) throw new Error();
    const value = JSON.parse(serialized) as UploadIntent;
    if (!value || typeof value !== 'object'
        || Object.keys(value).some(key => !['version', 'key', 'fileDigest', 'phase', 'documentId'].includes(key))
        || value.version !== 1 || !keyPattern.test(value.key) || !digestPattern.test(value.fileDigest)
        || !phases.includes(value.phase)
        || (value.documentId !== undefined && !documentIdPattern.test(value.documentId))
        || (['UPLOAD_PENDING', 'UPLOADED', 'SUBMIT_UNKNOWN'].includes(value.phase) && !value.documentId)) {
      throw new Error();
    }
    return value;
  } catch {
    throw new UploadRecoveryError('No se puede leer la recuperación de esta carga. Conserva esta pestaña y solicita revisión.');
  }
}

export function writeUploadIntent(storageKey: string, intent: UploadIntent, expectedKey: string | null): void {
  if ((readUploadIntent(storageKey)?.key ?? null) !== expectedKey) {
    throw new UploadRecoveryError('El estado de recuperación cambió. Vuelve a abrir la página de carga antes de continuar.');
  }
  try {
    const serialized = JSON.stringify(intent);
    sessionStorage.setItem(storageKey, serialized);
    if (sessionStorage.getItem(storageKey) !== serialized) throw new Error();
  } catch {
    throw new UploadRecoveryError('No se pudo guardar la recuperación. La carga se detuvo para evitar duplicados; conserva esta pestaña.');
  }
}

export function clearUploadIntent(storageKey: string, expectedKey: string): void {
  if (readUploadIntent(storageKey)?.key !== expectedKey) {
    throw new UploadRecoveryError('El estado de recuperación cambió. Vuelve a abrir la página de carga antes de continuar.');
  }
  try {
    sessionStorage.removeItem(storageKey);
    if (sessionStorage.getItem(storageKey) !== null) throw new Error();
  } catch {
    throw new UploadRecoveryError('No se pudo cerrar la recuperación. Consulta de nuevo el estado de la carga.');
  }
}

export function requireDurableDocument(value: DocumentCreateResponse['durableResponse']): string {
  if (!value || value.schemaVersion !== 'scanalyze.document-create-result.v1'
      || value.contractVersion !== DOCUMENT_JOURNEY_CONTRACT_VERSION
      || value.operation !== 'documents.create' || value.status !== 'UPLOAD_PENDING'
      || !documentIdPattern.test(value.documentId)) {
    throw new UploadRecoveryError('La respuesta de creación no es válida. Recupera la operación original.');
  }
  return value.documentId;
}

export function statusAllowsSubmit(status: DocumentStatusResponse, documentId: string): boolean {
  if (status.schemaVersion !== 'scanalyze.document-status.v1'
      || status.contractVersion !== DOCUMENT_JOURNEY_CONTRACT_VERSION || status.documentId !== documentId) {
    throw new UploadRecoveryError('El estado recibido no corresponde a esta carga. Solicita revisión.');
  }
  const createdAt = Date.parse(status.createdAt);
  const updatedAt = Date.parse(status.updatedAt);
  const terminalAt = status.terminalAt === undefined ? undefined : Date.parse(status.terminalAt);
  const terminal = status.lifecycle === 'COMPLETED' || status.lifecycle === 'FAILED';
  const hasFailure = status.failureDisposition !== undefined || status.safeFailureCode !== undefined;
  if (!Number.isFinite(createdAt) || !Number.isFinite(updatedAt) || createdAt > updatedAt
      || (terminal && (terminalAt === undefined || !Number.isFinite(terminalAt) || terminalAt < createdAt || terminalAt > updatedAt))
      || (!terminal && terminalAt !== undefined)
      || (hasFailure && status.lifecycle !== 'FAILED' && !(status.lifecycle === 'SUBMITTED' && status.stageState === 'FAILED'))) {
    throw new UploadRecoveryError('El estado recibido no permite continuar de forma segura. Solicita revisión.');
  }
  if (status.lifecycle === 'UPLOAD_PENDING' && status.currentStage === 'INGEST'
      && status.stageState === 'PENDING' && status.processingCondition === 'ACTIVE') return true;
  if (status.lifecycle === 'SUBMITTED' && status.currentStage === 'INGEST'
      && status.stageState === 'FAILED' && status.processingCondition === 'NOT_APPLICABLE'
      && status.failureDisposition === 'RETRYABLE' && status.safeFailureCode === 'ENQUEUE_FAILED') return true;
  if (status.lifecycle === 'SUBMITTED' && status.currentStage === 'INGEST'
      && ['PENDING', 'RUNNING'].includes(status.stageState) && status.processingCondition === 'ACTIVE') return false;
  // Match the reachable pairs enforced by the v2 runtime model's
  // _consistent_status; OpenAPI enum cross-products are broader than runtime.
  const processingPairs = [
    'OCR:RUNNING', 'OCR:SUCCEEDED', 'CLASSIFY:PENDING', 'CLASSIFY:SUCCEEDED',
    'BANK_EXTRACT:RUNNING', 'BANK_EXTRACT:SUCCEEDED',
    'PERSONAL_EXTRACT:RUNNING', 'PERSONAL_EXTRACT:SUCCEEDED', 'VALIDATE:SUCCEEDED',
  ];
  if (status.lifecycle === 'PROCESSING' && processingPairs.includes(`${status.currentStage}:${status.stageState}`)
      && status.processingCondition === 'ACTIVE') return false;
  if (status.lifecycle === 'COMPLETED' && status.currentStage === 'TERMINAL'
      && status.stageState === 'SUCCEEDED' && status.processingCondition === 'NOT_APPLICABLE') return false;
  if (status.lifecycle === 'FAILED' && status.currentStage === 'TERMINAL'
      && status.stageState === 'FAILED' && status.processingCondition === 'NOT_APPLICABLE'
      && status.failureDisposition === 'TERMINAL' && ['DOCUMENT_PROCESSING_FAILED', 'OCR_FAILED'].includes(status.safeFailureCode ?? '')) return false;
  throw new UploadRecoveryError('El estado recibido no permite continuar de forma segura. Solicita revisión.');
}

export function safeUploadError(error: unknown): { message: string; retryAfterMs: number } {
  if (error instanceof UploadRecoveryError) return { message: error.message, retryAfterMs: 0 };
  if (axios.isAxiosError(error)) {
    const data = error.response?.data;
    const code = data?.code;
    if (data?.schemaVersion === 'scanalyze.error.v1' && typeof code === 'string'
        && Object.hasOwn(DOCUMENT_JOURNEY_ERROR_POLICY, code)) {
      const policy = DOCUMENT_JOURNEY_ERROR_POLICY[code as keyof typeof DOCUMENT_JOURNEY_ERROR_POLICY];
      const delay = data?.details?.retryAfterSeconds;
      return {
        message: `La carga no se confirmó (${code}). Conservamos la operación para consultar su estado.`,
        retryAfterMs: policy.retryAfterAllowed && Number.isInteger(delay) && delay >= 1 && delay <= 3600 ? delay * 1000 : 1000,
      };
    }
  }
  // Never reflect transport/provider messages: they can contain capability URLs.
  return { message: 'No se pudo confirmar la carga. Usa Recuperar carga para consultar la misma operación.', retryAfterMs: 1000 };
}
