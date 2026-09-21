import { getApiClient } from '../api/client';
import { documentApi } from '../api/documentApi';
import { uploadFileToPresignedUrl } from '../api/uploadApi';
import { getConfig } from '../config';
import { DOCUMENT_JOURNEY_CONTRACT_VERSION as contract } from '../contracts/documentJourney.v1';
import {
  fingerprintUpload, readUploadIntent, requireDurableDocument, requireUploadSession,
  safeUploadError, statusAllowsSubmit, uploadStorageKey, UploadRecoveryError,
  writeUploadIntent, type UploadIntent,
} from './uploadRecovery';

type Item = { id: string; fileDigest: string; state: 'PENDING' | 'STARTED' | 'DONE' };
type Journal = {
  version: 1; key: string; phase: 'CREATE_UNKNOWN' | 'READY' | 'STOPPED';
  batchId?: string; items: Item[];
};
export interface BulkUploadTask {
  id: string; file?: File; documentId?: string; phase?: UploadIntent['phase'];
  status: 'PENDING' | 'UPLOADING' | 'WAITING_SERVER' | 'SUCCESS' | 'ERROR';
  progress: number; errorMsg?: string;
}
export interface BulkUploadSnapshot {
  batchId?: string; phase: Journal['phase']; tasks: BulkUploadTask[];
}

const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const opaqueId = /^[0-9a-f]{32}$/;
const hash = /^[0-9a-f]{64}$/;
const leases = new Set<string>();
const headers = (key: string) => ({ 'X-Scanalyze-Contract-Version': contract, 'Idempotency-Key': key });
const fail = (message = 'La recuperación del lote no es válida. Conserva esta pestaña y solicita revisión.'): never => {
  throw new UploadRecoveryError(message);
};
const record = (value: unknown): Record<string, unknown> => {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return fail();
  return value as Record<string, unknown>;
};
const exactKeys = (value: object, allowed: string[]) => Object.keys(value).every(key => allowed.includes(key));
const scope = () => {
  const c = getConfig();
  return JSON.stringify([c.apiBaseUrl, c.cognitoIssuerUrl, c.cognitoClientId, c.customerId, c.deploymentId]);
};
function batchId(value: unknown): string {
  const v = record(value);
  if (!exactKeys(v, ['schemaVersion', 'contractVersion', 'operation', 'batchId', 'status', 'createdAt'])
      || v.schemaVersion !== 'scanalyze.batch-create-result.v1' || v.contractVersion !== contract
      || v.operation !== 'batches.create' || v.status !== 'OPEN' || typeof v.batchId !== 'string'
      || !opaqueId.test(v.batchId) || typeof v.createdAt !== 'string' || !Number.isFinite(Date.parse(v.createdAt))) return fail();
  return v.batchId;
}
function envelope(value: unknown): Record<string, unknown> {
  const v = record(value);
  if (v.schemaVersion !== 'scanalyze.operation-response.v1' || v.contractVersion !== contract
      || typeof v.replayed !== 'boolean') return fail();
  return record(v.durableResponse);
}
function reconciliation(value: unknown, operation: 'batches.create' | 'documents.create'): Record<string, unknown> {
  const v = record(value);
  const time = (key: string) => typeof v[key] === 'string' ? Date.parse(v[key] as string) : NaN;
  const created = time('createdAt'), updated = time('updatedAt'), expires = time('expiresAt');
  const completed = time('completedAt');
  const failures: Record<string, string> = {
    FAILED_RETRYABLE: 'CREATE_FAILED_RETRYABLE', FAILED_TERMINAL: 'CREATE_FAILED_TERMINAL',
    UNKNOWN_OR_QUARANTINED: 'UNKNOWN_WRITE_OUTCOME', EXPIRED: 'OPERATION_EXPIRED',
  };
  if (v.schemaVersion !== 'scanalyze.reconciliation.v1' || v.contractVersion !== contract || v.operation !== operation
      || typeof v.ledgerState !== 'string' || !['SUCCEEDED', 'PENDING', ...Object.keys(failures)].includes(v.ledgerState)
      || ![created, updated, expires].every(Number.isFinite) || created > updated
      || (v.ledgerState === 'EXPIRED' ? !(created < expires && expires <= updated) : !(updated < expires))
      || (v.completedAt !== undefined && (!Number.isFinite(completed) || completed < created || completed > updated))) return fail();
  if (v.ledgerState === 'SUCCEEDED') {
    if (v.failureCode !== undefined || !Number.isFinite(completed)) return fail();
    record(v.durableResponse);
  } else {
    if (v.durableResponse !== undefined) return fail();
    if (v.ledgerState === 'PENDING') {
      if (v.failureCode !== undefined || v.completedAt !== undefined) return fail();
    } else if (v.failureCode !== failures[v.ledgerState]
      || (v.ledgerState === 'FAILED_RETRYABLE' ? v.completedAt !== undefined : !Number.isFinite(completed))) return fail();
  }
  return v;
}

/** One tab/actor journal. Files and all provider responses stay in memory.
 * A module lease spans async work and React remounts; React state is never a lock.
 */
export class BulkUploadRecovery {
  readonly namespace: string;
  private readonly configScope = scope();
  private files = new Map<string, File>();
  private views = new Map<string, Partial<BulkUploadTask>>();
  private retryAt = new Map<string, number>();
  private journalKey: string | undefined;
  private expectedRaw: string | null;
  private observedIntents = new Map<string, string | null>();
  private subject: string;
  private isCurrent: () => boolean;

  private constructor(namespace: string, subject: string, isCurrent: () => boolean) {
    this.namespace = `${namespace}:bulk`;
    this.subject = subject;
    this.isCurrent = isCurrent;
    this.journalKey = this.read()?.key;
    this.expectedRaw = sessionStorage.getItem(this.namespace);
  }
  static async open(subject: string | undefined, isCurrent: () => boolean): Promise<BulkUploadRecovery> {
    requireUploadSession(subject);
    const originalScope = scope();
    const namespace = await uploadStorageKey(subject);
    requireUploadSession(subject);
    if (!isCurrent() || scope() !== originalScope) return fail('La vista de carga cambió. Vuelve a abrir el lote.');
    return new BulkUploadRecovery(namespace, subject!, isCurrent);
  }
  private context(): void {
    if (!this.isCurrent() || scope() !== this.configScope) return fail('La sesión o la vista cambió. Recupera el lote con su usuario original.');
    requireUploadSession(this.subject);
    if (sessionStorage.getItem(this.namespace) !== this.expectedRaw) return fail();
    for (const [key, raw] of this.observedIntents) {
      if (sessionStorage.getItem(key) !== raw) return fail();
    }
  }
  private read(): Journal | null {
    try {
      const raw = sessionStorage.getItem(this.namespace);
      if (raw === null) return null;
      if (raw.length > 32768) return fail();
      const v = record(JSON.parse(raw));
      if (!exactKeys(v, ['version', 'key', 'phase', 'batchId', 'items']) || v.version !== 1
          || typeof v.key !== 'string' || !uuid.test(v.key)
          || !['CREATE_UNKNOWN', 'READY', 'STOPPED'].includes(v.phase as string)
          || (v.phase === 'READY' ? typeof v.batchId !== 'string' || !opaqueId.test(v.batchId) : v.batchId !== undefined)
          || !Array.isArray(v.items) || !v.items.length || v.items.length > 100) return fail();
      const ids = new Set();
      for (const entry of v.items) {
        const item = record(entry);
        if (!exactKeys(item, ['id', 'fileDigest', 'state']) || typeof item.id !== 'string' || !uuid.test(item.id)
            || ids.has(item.id) || typeof item.fileDigest !== 'string' || !hash.test(item.fileDigest)
            || !['PENDING', 'STARTED', 'DONE'].includes(item.state as string)
            || (v.phase !== 'READY' && item.state !== 'PENDING')) return fail();
        ids.add(item.id);
      }
      return v as unknown as Journal;
    } catch { return fail(); }
  }
  private current(): Journal {
    const journal = this.read();
    if (!journal || journal.key !== this.journalKey) return fail();
    return journal;
  }
  private save(next: Journal): void {
    this.context();
    if ((this.read()?.key) !== this.journalKey) return fail();
    try {
      const raw = JSON.stringify(next);
      sessionStorage.setItem(this.namespace, raw);
      if (sessionStorage.getItem(this.namespace) !== raw) return fail();
      this.journalKey = next.key;
      this.expectedRaw = raw;
    } catch { return fail('No se pudo guardar la recuperación. Conserva esta pestaña; no vuelvas a crear el lote.'); }
  }
  private itemKey(item: Item): string { return `${this.namespace}:item:${item.id}`; }
  private intent(item: Item): UploadIntent | null {
    const key = this.itemKey(item);
    const raw = sessionStorage.getItem(key);
    if (this.observedIntents.has(key) && this.observedIntents.get(key) !== raw) return fail();
    const intent = readUploadIntent(key);
    this.observedIntents.set(key, raw);
    if (intent && (intent.key !== item.id || intent.fileDigest !== item.fileDigest)) return fail();
    if (!intent && item.state !== 'PENDING') return fail();
    // PENDING may have a CREATE_UNKNOWN intent if its write succeeded before
    // the manifest advanced to STARTED. DONE must refer to a durable document;
    // resumed status reads can confirm it before the local submit phase.
    if (intent && item.state === 'PENDING' && intent.phase !== 'CREATE_UNKNOWN') return fail();
    if (item.state === 'DONE' && (!intent?.documentId
      || !['UPLOAD_PENDING', 'UPLOADED', 'SUBMIT_UNKNOWN'].includes(intent.phase))) return fail();
    return intent;
  }
  snapshot(): BulkUploadSnapshot | null {
    this.context();
    const journal = this.read();
    if (!journal) return null;
    if (journal.key !== this.journalKey) return fail();
    return { batchId: journal.batchId, phase: journal.phase, tasks: journal.items.map(item => {
      const intent = this.intent(item);
      return { id: item.id, file: this.files.get(item.id), documentId: intent?.documentId,
        phase: intent?.phase, status: item.state === 'DONE' ? 'SUCCESS' : intent?.phase === 'STOPPED' ? 'ERROR' : 'PENDING',
        progress: item.state === 'DONE' ? 100 : 0, ...this.views.get(item.id) };
    }) };
  }
  private async exclusive<T>(work: () => Promise<T>): Promise<T> {
    this.context();
    if (leases.has(this.namespace)) return fail('Hay una operación del lote en curso. Espera antes de recuperarlo.');
    leases.add(this.namespace);
    try { return await work(); } finally { leases.delete(this.namespace); }
  }
  async create(files: readonly File[]): Promise<BulkUploadSnapshot> {
    return this.exclusive(async () => {
      if (this.read()) return fail('Ya existe un lote guardado. Recupera esa operación.');
      if (!files.length || files.length > 100) return fail('Selecciona entre uno y cien archivos por lote.');
      const items: Item[] = [];
      for (const file of files) {
        const fileDigest = await fingerprintUpload(file);
        this.context();
        const id = crypto.randomUUID();
        items.push({ id, fileDigest, state: 'PENDING' });
        this.files.set(id, file);
      }
      const journal: Journal = { version: 1, key: crypto.randomUUID(), phase: 'CREATE_UNKNOWN', items };
      this.save(journal);
      const { data } = await getApiClient(this.subject).post('/v2/batches', {}, { headers: headers(journal.key) });
      this.context();
      this.save({ ...this.current(), phase: 'READY', batchId: batchId(envelope(data)) });
      return this.snapshot()!;
    });
  }
  async attach(files: readonly File[]): Promise<BulkUploadSnapshot> {
    return this.exclusive(async () => {
      const journal = this.current();
      const claimed = new Set<string>();
      const matched: [string, File][] = [];
      for (const file of files) {
        const fingerprint = await fingerprintUpload(file);
        this.context();
        const item = journal.items.find(i => i.state !== 'DONE' && !claimed.has(i.id) && i.fileDigest === fingerprint);
        if (!item) return fail('Un archivo no coincide con el lote original. Selecciona los archivos originales.');
        claimed.add(item.id);
        matched.push([item.id, file]);
      }
      this.current();
      for (const [id, file] of matched) this.files.set(id, file);
      return this.snapshot()!;
    });
  }
  async run(onUpdate: (snapshot: BulkUploadSnapshot) => void): Promise<BulkUploadSnapshot> {
    return this.exclusive(async () => {
      let journal = this.current();
      if (journal.phase === 'STOPPED') return fail('El lote requiere revisión. Conserva su recuperación.');
      if (journal.phase === 'CREATE_UNKNOWN') {
        const { data } = await getApiClient(this.subject).post('/v2/operations/batches.create/reconciliation', undefined, { headers: headers(journal.key) });
        this.context();
        const result = reconciliation(data, 'batches.create');
        if (result.ledgerState !== 'SUCCEEDED') {
          if (result.ledgerState !== 'PENDING') this.save({ ...this.current(), phase: 'STOPPED' });
          return fail('La creación del lote sigue sin confirmarse. Recupera la misma operación o solicita revisión.');
        }
        this.save({ ...this.current(), phase: 'READY', batchId: batchId(result.durableResponse) });
        journal = this.current();
      }
      const queue = journal.items.filter(item => item.state !== 'DONE');
      const update = (id: string, patch: Partial<BulkUploadTask>) => {
        this.views.set(id, { ...this.views.get(id), ...patch });
        if (this.isCurrent()) onUpdate(this.snapshot()!);
      };
      const worker = async () => {
        while (queue.length) {
          this.context();
          const item = queue.shift()!;
          const remaining = (this.retryAt.get(item.id) ?? 0) - Date.now();
          if (remaining > 0) {
            update(item.id, { status: 'ERROR', errorMsg: `Espera ${Math.ceil(remaining / 1000)} s antes de recuperar este archivo. Conservamos la misma operación.` });
            continue;
          }
          update(item.id, { status: 'WAITING_SERVER', errorMsg: undefined });
          try {
            await this.runItem(item, journal.batchId!, patch => update(item.id, patch));
            update(item.id, { status: 'SUCCESS', progress: 100 });
          } catch (error) {
            const safe = safeUploadError(error);
            this.retryAt.set(item.id, Date.now() + Math.max(1000, safe.retryAfterMs));
            update(item.id, { status: 'ERROR', errorMsg: safe.message });
          }
        }
      };
      // Workers take items synchronously, before their first await. A single
      // namespace lease also prevents a StrictMode remount from starting them.
      const outcomes = await Promise.allSettled(Array.from({ length: Math.min(3, queue.length) }, worker));
      const rejected = outcomes.find(outcome => outcome.status === 'rejected');
      if (rejected?.status === 'rejected') throw rejected.reason;
      this.context();
      return this.snapshot()!;
    });
  }
  private async runItem(item: Item, batch: string, update: (patch: Partial<BulkUploadTask>) => void): Promise<void> {
    this.context();
    let current = this.intent(item);
    let capability;
    const save = (next: UploadIntent) => {
      this.context();
      this.current();
      writeUploadIntent(this.itemKey(item), next, current?.key ?? null);
      this.observedIntents.set(this.itemKey(item), sessionStorage.getItem(this.itemKey(item)));
      current = next;
    };
    if (!current) {
      const file = this.files.get(item.id);
      if (!file || await fingerprintUpload(file) !== item.fileDigest) return fail('Selecciona el archivo original para continuar el mismo lote.');
      this.context();
      save({ version: 1, key: item.id, fileDigest: item.fileDigest, phase: 'CREATE_UNKNOWN' });
      const journal = this.current();
      this.save({ ...journal, items: journal.items.map(i => i.id === item.id ? { ...i, state: 'STARTED' } : i) });
      const created = await documentApi.createDocument(file, item.id, batch, this.subject);
      this.context();
      envelope(created);
      if (created.durableResponse.batchId !== undefined && created.durableResponse.batchId !== batch) return fail();
      const documentId = requireDurableDocument(created.durableResponse);
      save({ ...current!, documentId, phase: 'UPLOAD_PENDING' });
      capability = created.uploadCapability;
    } else if (current.phase === 'CREATE_UNKNOWN') {
      const result = reconciliation(await documentApi.reconcileCreate(current.key, this.subject), 'documents.create');
      this.context();
      if (result.ledgerState !== 'SUCCEEDED') {
        if (result.ledgerState !== 'PENDING') save({ ...current, phase: 'STOPPED' });
        return fail('La creación del documento sigue sin confirmarse. Conservamos su operación original.');
      }
      const durable = record(result.durableResponse);
      if (durable.batchId !== undefined && durable.batchId !== batch) return fail();
      const documentId = requireDurableDocument(durable as unknown as Parameters<typeof requireDurableDocument>[0]);
      save({ ...current, documentId, phase: 'UPLOAD_PENDING' });
    }
    if (!current?.documentId || current.phase === 'STOPPED') return fail('El documento requiere revisión antes de continuar.');
    const documentId = current.documentId;
    update({ documentId });
    // Any resumed document, especially SUBMIT_UNKNOWN, is read before writes.
    // Accepted processing/terminal states never resend CREATE, upload or submit.
    if (!capability) {
      this.context();
      const status = await documentApi.getDocumentStatus(documentId, this.subject);
      this.context();
      if (status.batchId !== undefined && status.batchId !== batch) return fail();
      if (!statusAllowsSubmit(status, documentId)) { this.complete(item.id); return; }
      if (status.lifecycle === 'SUBMITTED') save({ ...current, phase: 'UPLOADED' });
    }
    if (current.phase === 'UPLOAD_PENDING') {
      const file = this.files.get(item.id);
      if (!file || await fingerprintUpload(file) !== item.fileDigest) return fail('Selecciona el archivo original para continuar el mismo documento.');
      this.context();
      if (!capability) {
        const refreshed = await documentApi.refreshUploadCapability(documentId, this.subject);
        this.context();
        if (refreshed.documentId !== documentId || refreshed.schemaVersion !== 'scanalyze.upload-capability.v1' || refreshed.contractVersion !== contract) return fail();
        capability = refreshed.uploadCapability;
      }
      if (!capability) return fail();
      update({ status: 'UPLOADING' });
      this.context();
      await uploadFileToPresignedUrl(file, capability, progress => update({ progress }));
      this.context();
      save({ ...current, phase: 'UPLOADED' });
    }
    this.context();
    save({ ...current, phase: 'SUBMIT_UNKNOWN' });
    update({ status: 'WAITING_SERVER' });
    await documentApi.submitDocument(documentId, this.subject);
    this.context();
    // submitDocument intentionally returns void. Verify the durable status
    // before marking this journal entry done, including an optional batch bind.
    const submitted = await documentApi.getDocumentStatus(documentId, this.subject);
    this.context();
    if ((submitted.batchId !== undefined && submitted.batchId !== batch) || statusAllowsSubmit(submitted, documentId)) return fail('El envío aún no se confirmó. Recupera el mismo documento.');
    this.complete(item.id);
  }
  private complete(id: string): void {
    const journal = this.current();
    this.save({ ...journal, items: journal.items.map(i => i.id === id ? { ...i, state: 'DONE' } : i) });
    // Retain opaque completed intents: losing a cleanup write must never turn
    // an already accepted file into a fresh CREATE on reload.
  }
  async clearCompleted(): Promise<void> {
    return this.exclusive(async () => {
      const journal = this.current();
      if (journal.phase !== 'READY' || journal.items.some(item => item.state !== 'DONE')) return fail('El lote tiene operaciones pendientes. Conserva su recuperación.');
      // Validate every retained intent before deleting any recovery evidence.
      for (const item of journal.items) this.intent(item);
      this.context();
      sessionStorage.removeItem(this.namespace);
      if (sessionStorage.getItem(this.namespace) !== null) return fail();
      this.expectedRaw = null;
      this.journalKey = undefined;
      // All submissions are confirmed before removing the manifest. Leftover
      // opaque item records cannot start work without their manifest.
      for (const item of journal.items) sessionStorage.removeItem(this.itemKey(item));
      this.observedIntents.clear();
      this.files.clear();
      this.views.clear();
      this.retryAt.clear();
    });
  }
}
