import { expect, test, type Page, type Route } from '@playwright/test';
import {
  BATCH_CREATE_RESPONSE_FIXTURE,
  DOCUMENT_CREATE_RESPONSE_FIXTURE,
  DOCUMENT_STATUS_RESPONSE_FIXTURE,
} from '../src/contracts/documentJourney.v1.fixtures';
import { syntheticAuthState, syntheticOidcStorageKey, syntheticRuntimeConfig, syntheticTestOrigin } from './runtime';

// Synthetic browser/transport coverage only. All API and upload requests are
// intercepted locally; unmatched API and external requests cannot reach a server.
const contract = 'scanalyze.document-journey.v1';
const documentId = DOCUMENT_CREATE_RESPONSE_FIXTURE.durableResponse.documentId;
const batchId = BATCH_CREATE_RESPONSE_FIXTURE.durableResponse.batchId;
const uploadUrl = `https://localhost:${new URL(syntheticTestOrigin).port}/synthetic-upload/input?capability=never-persist`;
const file = { name: 'synthetic-original.pdf', mimeType: 'application/pdf', buffer: Buffer.from('synthetic document bytes') };
const capability = { method: 'PUT', url: uploadUrl, expiresAt: '2099-09-21T00:00:00Z', requiredHeaders: { 'Content-Type': 'application/pdf' } };
const created = { ...DOCUMENT_CREATE_RESPONSE_FIXTURE, uploadCapability: capability };

interface Scenario {
  batchUnknown?: boolean;
  createUnknown?: boolean;
  submitUnknown?: boolean;
  statusDenied?: number;
  reconciliationDenied?: boolean;
}

async function installScenario(page: Page, scenario: Scenario = {}) {
  const calls = {
    batchKeys: [] as string[], batchReconcileKeys: [] as string[],
    createKeys: [] as string[], reconcileKeys: [] as string[],
    upload: 0, submit: 0, refresh: 0, status: 0, history: 0,
    unexpected: [] as string[],
  };
  await page.route('**/*', async route => {
    const url = new URL(route.request().url());
    if (url.origin !== syntheticTestOrigin || url.pathname.startsWith('/api')) {
      calls.unexpected.push(`${route.request().method()} ${url.origin}${url.pathname}`);
      await route.abort('blockedbyclient');
      return;
    }
    await route.continue();
  });
  await page.route(url => url.origin === syntheticTestOrigin && url.pathname === '/config.json', route => route.fulfill({ json: syntheticRuntimeConfig }));
  await page.addInitScript(({ key, state, origin }) => {
    if (location.origin === origin && !sessionStorage.getItem(key)) sessionStorage.setItem(key, JSON.stringify(state));
  }, { key: syntheticOidcStorageKey, state: syntheticAuthState, origin: syntheticTestOrigin });

  const api = async (path: string, handler: (route: Route) => Promise<void>) => {
    await page.route(url => url.origin === syntheticTestOrigin && url.pathname === path, handler);
  };
  const operationKey = (route: Route) => {
    expect(route.request().method()).toBe('POST');
    expect(route.request().headers()['x-scanalyze-contract-version']).toBe(contract);
    const key = route.request().headers()['idempotency-key'];
    expect(key).toMatch(/^[0-9a-f-]{36}$/);
    return key;
  };
  const reconcile = (operation: 'batches.create' | 'documents.create') => ({
    schemaVersion: 'scanalyze.reconciliation.v1', contractVersion: contract, operation,
    ledgerState: 'SUCCEEDED',
    durableResponse: operation === 'batches.create' ? BATCH_CREATE_RESPONSE_FIXTURE.durableResponse : created.durableResponse,
    createdAt: '2026-09-21T00:00:00Z', updatedAt: '2026-09-21T00:01:00Z',
    completedAt: '2026-09-21T00:01:00Z', expiresAt: '2099-09-21T00:00:00Z',
  });
  await api('/api/v2/batches', async route => {
    calls.batchKeys.push(operationKey(route));
    expect(route.request().postDataJSON()).toEqual({});
    if (scenario.batchUnknown) return route.abort('failed');
    await route.fulfill({ status: 201, json: BATCH_CREATE_RESPONSE_FIXTURE });
  });
  await api('/api/v2/operations/batches.create/reconciliation', async route => {
    calls.batchReconcileKeys.push(operationKey(route));
    await route.fulfill({ json: reconcile('batches.create') });
  });
  await api('/api/v2/documents', async route => {
    calls.createKeys.push(operationKey(route));
    expect(route.request().postDataJSON()).toEqual({ filename: file.name, contentType: file.mimeType, contentLength: file.buffer.length, batchId });
    if (scenario.createUnknown) return route.abort('failed');
    await route.fulfill({ status: 201, json: created });
  });
  await api('/api/v2/operations/documents.create/reconciliation', async route => {
    calls.reconcileKeys.push(operationKey(route));
    if (scenario.reconciliationDenied) return route.fulfill({ status: 403, json: { schemaVersion: 'scanalyze.error.v1', code: 'AUTHORIZATION_DENIED', message: 'Synthetic denial', correlationId: 'corr.synthetic.denied', retryClass: 'TERMINAL' } });
    await route.fulfill({ json: reconcile('documents.create') });
  });
  await api(`/api/v2/documents/${documentId}/upload-capabilities`, async route => {
    expect(route.request().method()).toBe('POST');
    calls.refresh++;
    await route.fulfill({ json: { schemaVersion: 'scanalyze.upload-capability.v1', contractVersion: contract, documentId, uploadCapability: capability } });
  });
  await page.route(uploadUrl, async route => {
    expect(route.request().method()).toBe('PUT');
    expect(route.request().headers().authorization).toBeUndefined();
    expect(route.request().postDataBuffer()).toEqual(file.buffer);
    calls.upload++;
    await route.fulfill({ status: 200 });
  });
  await api(`/api/v2/documents/${documentId}/submit`, async route => {
    expect(route.request().method()).toBe('POST');
    expect(route.request().headers()['x-scanalyze-contract-version']).toBe(contract);
    expect(route.request().postDataJSON()).toEqual({ stage: 'ingest' });
    calls.submit++;
    if (scenario.submitUnknown) return route.abort('failed');
    await route.fulfill({ status: 202, json: { schemaVersion: 'scanalyze.document-submit.v1', contractVersion: contract, documentId, stage: 'ingest', enqueued: true } });
  });
  await api(`/api/v2/documents/${documentId}`, async route => {
    expect(route.request().method()).toBe('GET');
    expect(route.request().headers()['x-scanalyze-contract-version']).toBe(contract);
    calls.status++;
    if (scenario.statusDenied) return route.fulfill({ status: scenario.statusDenied, json: { schemaVersion: 'scanalyze.error.v1', code: 'AUTHORIZATION_DENIED', message: 'Synthetic denial', correlationId: 'corr.synthetic.denied', retryClass: 'TERMINAL' } });
    await route.fulfill({ json: calls.submit > 0 ? DOCUMENT_STATUS_RESPONSE_FIXTURE : {
      schemaVersion: 'scanalyze.document-status.v1', contractVersion: contract, documentId, batchId,
      lifecycle: 'UPLOAD_PENDING', currentStage: 'INGEST', stageState: 'PENDING', processingCondition: 'ACTIVE',
      createdAt: '2026-09-21T00:00:00Z', updatedAt: '2026-09-21T00:01:00Z',
    } });
  });
  await api('/api/analytics/docs', async route => {
    expect(route.request().method()).toBe('GET');
    expect(new URL(route.request().url()).searchParams.get('classRoute')).toBe('bank-extract');
    calls.history++;
    await route.fulfill({ json: { documents: [{ documentId: 'b'.repeat(32), filename: 'synthetic-previous.pdf', status: 'COMPLETED', createdAt: '2026-09-20T00:00:00Z' }], nextCursor: null } });
  });
  return calls;
}

async function openBank(page: Page) {
  await page.goto('/bank-statements');
  await expect(page.getByRole('heading', { name: 'Estados de Cuenta Bancarios', exact: true })).toBeVisible();
}

async function start(page: Page, bulk = false) {
  await page.locator('input[type="file"]').setInputFiles(file);
  await page.getByRole('button', { name: bulk ? '🚀 Iniciar Lote' : 'Iniciar envío', exact: true }).click();
}

async function savedJournal(page: Page) {
  const entries = await page.evaluate(() => Object.entries(sessionStorage).filter(([key]) => key.startsWith('scanalyze.upload.v1:')));
  const manifest = entries.find(([key]) => key.endsWith(':bulk'));
  const item = entries.find(([key]) => key.includes(':bulk:item:'));
  return { entries, manifest: manifest && JSON.parse(manifest[1]), item: item && JSON.parse(item[1]) };
}

async function assertOpaqueJournal(page: Page) {
  const saved = await savedJournal(page);
  const raw = JSON.stringify(saved.entries);
  for (const privateValue of [file.name, file.buffer.toString(), syntheticAuthState.access_token, uploadUrl, 'Synthetic denial']) expect(raw).not.toContain(privateValue);
  return saved;
}

async function expectConfirmed(page: Page) {
  await expect(page.getByRole('button', { name: 'Nuevo lote', exact: true })).toBeVisible();
  await expect.poll(async () => (await savedJournal(page)).manifest?.items[0].state).toBe('DONE');
}

test('bank lost document CREATE survives reload and reconciles its original key with the original file', async ({ page }) => {
  const calls = await installScenario(page, { createUnknown: true });
  await openBank(page);
  await start(page);
  await expect(page.getByRole('button', { name: 'Recuperar lote', exact: true })).toBeVisible();
  const before = await assertOpaqueJournal(page);
  expect(before.item.phase).toBe('CREATE_UNKNOWN');
  expect(before.item.key).toBe(calls.createKeys[0]);
  await page.reload();
  await expect(page.getByRole('button', { name: 'Recuperar lote', exact: true })).toBeVisible();
  expect(calls.reconcileKeys).toEqual([]); // Recovery requires explicit intent.
  await page.getByLabel('Seleccionar originales', { exact: true }).setInputFiles(file);
  await page.getByRole('button', { name: 'Recuperar lote', exact: true }).click();
  await expectConfirmed(page);
  expect(calls.batchKeys).toHaveLength(1);
  expect(calls.createKeys).toHaveLength(1);
  expect(calls.reconcileKeys).toEqual(calls.createKeys);
  expect(calls.refresh).toBe(1);
  expect(calls.upload).toBe(1);
  expect(calls.submit).toBe(1);
  expect((await assertOpaqueJournal(page)).manifest.key).toBe(before.manifest.key);
  expect(calls.unexpected).toEqual([]);
});

test('bank recovery rejects a missing or different original before upload and preserves the same document', async ({ page }) => {
  const calls = await installScenario(page, { createUnknown: true });
  await openBank(page);
  await start(page);
  await expect(page.getByRole('button', { name: 'Recuperar lote', exact: true })).toBeVisible();
  await page.reload();
  await page.getByRole('button', { name: 'Recuperar lote', exact: true }).click();
  await expect(page.getByText('Selecciona el archivo original para continuar el mismo documento.', { exact: true })).toBeVisible();
  await page.getByLabel('Seleccionar originales', { exact: true }).setInputFiles({ ...file, buffer: Buffer.from('different synthetic document bytes') });
  await expect(page.getByRole('alert')).toContainText('Un archivo no coincide');
  expect(calls.upload).toBe(0);
  expect(calls.refresh).toBe(0);
  expect((await savedJournal(page)).item.documentId).toBe(documentId);
  // A reload also proves the rejection did not destroy durable recovery state.
  await page.reload();
  await page.getByLabel('Seleccionar originales', { exact: true }).setInputFiles(file);
  await page.getByRole('button', { name: 'Recuperar lote', exact: true }).click();
  await expectConfirmed(page);
  expect(calls.createKeys).toHaveLength(1);
  expect(calls.reconcileKeys).toEqual(calls.createKeys);
  expect(calls.upload).toBe(1);
  expect(calls.unexpected).toEqual([]);
});

test('bank lost batch CREATE reconciles the original batch key before the first document write', async ({ page }) => {
  const calls = await installScenario(page, { batchUnknown: true });
  await openBank(page);
  await start(page);
  await expect(page.getByRole('button', { name: 'Recuperar lote', exact: true })).toBeVisible();
  const before = await assertOpaqueJournal(page);
  expect(before.manifest.phase).toBe('CREATE_UNKNOWN');
  expect(calls.createKeys).toEqual([]);
  await page.reload();
  await page.getByLabel('Seleccionar originales', { exact: true }).setInputFiles(file);
  await page.getByRole('button', { name: 'Recuperar lote', exact: true }).click();
  await expectConfirmed(page);
  expect(calls.batchKeys).toHaveLength(1);
  expect(calls.batchReconcileKeys).toEqual(calls.batchKeys);
  expect(calls.createKeys).toHaveLength(1);
  expect((await savedJournal(page)).manifest.batchId).toBe(batchId);
  expect(calls.unexpected).toEqual([]);
});

test('bank lost submit reads durable status after reload without repeating CREATE, PUT or submit', async ({ page }) => {
  const calls = await installScenario(page, { submitUnknown: true });
  await openBank(page);
  await start(page);
  await expect(page.getByRole('button', { name: 'Recuperar lote', exact: true })).toBeVisible();
  expect((await assertOpaqueJournal(page)).item.phase).toBe('SUBMIT_UNKNOWN');
  await page.reload();
  await page.getByRole('button', { name: 'Recuperar lote', exact: true }).click();
  await expectConfirmed(page);
  expect(calls.status).toBe(1);
  expect(calls.batchKeys).toHaveLength(1);
  expect(calls.createKeys).toHaveLength(1);
  expect(calls.upload).toBe(1);
  expect(calls.submit).toBe(1);
  expect(calls.refresh).toBe(0);
  expect(calls.unexpected).toEqual([]);
});

for (const statusDenied of [403, 404]) {
  test(`bank denied recovery status ${statusDenied} retains unknown submit without another write`, async ({ page }) => {
    const calls = await installScenario(page, { submitUnknown: true, statusDenied });
    await openBank(page);
    await start(page);
    await expect(page.getByRole('button', { name: 'Recuperar lote', exact: true })).toBeVisible();
    const before = await assertOpaqueJournal(page);
    await page.reload();
    await page.getByRole('button', { name: 'Recuperar lote', exact: true }).click();
    await expect(page.getByText(/La carga no se confirmó \(AUTHORIZATION_DENIED\)/)).toBeVisible();
    await expect(page.getByRole('button', { name: 'Nuevo lote', exact: true })).toHaveCount(0);
    expect((await assertOpaqueJournal(page)).item).toEqual(before.item);
    expect(calls.batchKeys).toHaveLength(1);
    expect(calls.createKeys).toHaveLength(1);
    expect(calls.upload).toBe(1);
    expect(calls.submit).toBe(1);
    expect(calls.refresh).toBe(0);
    expect(calls.unexpected).toEqual([]);
  });
}

test('bank denied CREATE reconciliation keeps the original key and performs no upload or submit', async ({ page }) => {
  const calls = await installScenario(page, { createUnknown: true, reconciliationDenied: true });
  await openBank(page);
  await start(page);
  await expect(page.getByRole('button', { name: 'Recuperar lote', exact: true })).toBeVisible();
  const before = await assertOpaqueJournal(page);
  await page.reload();
  await page.getByRole('button', { name: 'Recuperar lote', exact: true }).click();
  await expect(page.getByText(/La carga no se confirmó \(AUTHORIZATION_DENIED\)/)).toBeVisible();
  expect((await assertOpaqueJournal(page)).item).toEqual(before.item);
  expect(calls.createKeys).toHaveLength(1);
  expect(calls.reconcileKeys).toEqual(calls.createKeys);
  expect(calls.upload).toBe(0);
  expect(calls.submit).toBe(0);
  expect(calls.unexpected).toEqual([]);
});

test('bank current batch references remain distinct from account history and retain their journal', async ({ page }) => {
  const calls = await installScenario(page);
  await openBank(page);
  await start(page);
  await expectConfirmed(page);
  const before = await assertOpaqueJournal(page);
  await page.getByRole('button', { name: 'Resultados del lote', exact: true }).click();
  const current = page.getByRole('region', { name: 'Resultados del lote', exact: true });
  await expect(current.getByRole('link', { name: /synthetic-original\.pdf — Ver documento/ })).toHaveAttribute('href', `/document/${documentId}`);
  expect(calls.history).toBe(0);
  await expect(page.getByText('synthetic-previous.pdf', { exact: true })).toHaveCount(0);
  await page.getByRole('button', { name: 'Historial', exact: true }).click();
  await expect(page.getByRole('button', { name: /synthetic-previous\.pdf/ })).toBeVisible();
  expect(calls.history).toBe(1);
  await expect(page.getByRole('link', { name: /Ver documento/ })).toHaveCount(0);
  await page.getByRole('button', { name: 'Resultados del lote', exact: true }).click();
  await expect(current.getByRole('link', { name: /Ver documento/ })).toBeVisible();
  expect((await savedJournal(page)).entries).toEqual(before.entries);
  expect(calls.unexpected).toEqual([]);
});

test('bulk to bank navigation recovers the same journal and original CREATE key without automatic writes', async ({ page }) => {
  const calls = await installScenario(page, { createUnknown: true });
  await page.goto('/bulk-upload');
  await expect(page.getByRole('heading', { name: 'Carga Masiva de Documentos', exact: true })).toBeVisible();
  await start(page, true);
  await expect(page.getByRole('button', { name: 'Recuperar lote', exact: true })).toBeVisible();
  const before = await assertOpaqueJournal(page);
  await openBank(page);
  await expect(page.getByRole('button', { name: 'Recuperar lote', exact: true })).toBeVisible();
  expect((await savedJournal(page)).entries).toEqual(before.entries);
  expect(calls.createKeys).toHaveLength(1);
  expect(calls.reconcileKeys).toEqual([]);
  await page.getByLabel('Seleccionar originales', { exact: true }).setInputFiles(file);
  await page.getByRole('button', { name: 'Recuperar lote', exact: true }).click();
  await expectConfirmed(page);
  expect(calls.batchKeys).toHaveLength(1);
  expect(calls.createKeys).toHaveLength(1);
  expect(calls.reconcileKeys).toEqual(calls.createKeys);
  expect((await savedJournal(page)).manifest.key).toBe(before.manifest.key);
  expect(calls.unexpected).toEqual([]);
});

test('another actor cannot discover or resume the original bank recovery journal', async ({ page }) => {
  const calls = await installScenario(page, { createUnknown: true });
  await openBank(page);
  await start(page);
  await expect(page.getByRole('button', { name: 'Recuperar lote', exact: true })).toBeVisible();
  const before = await assertOpaqueJournal(page);
  await page.evaluate(key => {
    const stored = JSON.parse(sessionStorage.getItem(key)!);
    stored.profile.sub = 'synthetic-user-b';
    sessionStorage.setItem(key, JSON.stringify(stored));
  }, syntheticOidcStorageKey);
  await page.reload();
  await page.getByRole('button', { name: 'Resultados del lote', exact: true }).click();
  await expect(page.getByText('No hay un lote guardado en esta pestaña.', { exact: true })).toBeVisible();
  await expect(page.getByRole('link', { name: /Ver documento/ })).toHaveCount(0);
  await page.getByRole('button', { name: 'Subir', exact: true }).click();
  await expect(page.getByRole('button', { name: 'Recuperar lote', exact: true })).toHaveCount(0);
  expect((await savedJournal(page)).entries).toEqual(before.entries);
  expect(calls.reconcileKeys).toEqual([]);
  expect(calls.createKeys).toHaveLength(1);
  expect(calls.upload).toBe(0);
  expect(calls.unexpected).toEqual([]);
});
