import { expect, test, type Page } from '@playwright/test';
import { syntheticAuthState, syntheticOidcStorageKey, syntheticRuntimeConfig } from './runtime';

// Synthetic contract/transport tests only: no AWS, signed live URL or real file.
const documentId = 'a'.repeat(32);
const contractVersion = 'scanalyze.document-journey.v1';
const uploadUrl = 'https://synthetic-upload.invalid/input?capability=never-persist';
const file = { name: 'synthetic-original.pdf', mimeType: 'application/pdf', buffer: Buffer.from('synthetic document bytes') };
const durableResponse = {
  schemaVersion: 'scanalyze.document-create-result.v1', contractVersion,
  operation: 'documents.create', documentId, status: 'UPLOAD_PENDING',
  contentType: 'application/pdf', createdAt: '2026-09-09T00:00:00Z',
};
const capability = {
  method: 'PUT', url: uploadUrl, expiresAt: '2099-09-09T00:00:00Z',
  requiredHeaders: { 'Content-Type': 'application/pdf' },
};

interface Scenario {
  createUnknown?: boolean;
  uploadFails?: boolean;
  submitUnknown?: boolean;
  enqueueFails?: boolean;
  statusFails?: boolean;
  ledgerState?: string;
  changeActorAfterCreate?: boolean;
  statusOverride?: Record<string, unknown>;
  createResponseGates?: Promise<void>[];
  createUnknownAfterFirst?: boolean;
}

async function installScenario(page: Page, scenario: Scenario = {}) {
  const calls = { createKeys: [] as string[], reconcileKeys: [] as string[], upload: 0, submit: 0, refresh: 0 };
  await page.route('/config.json', route => route.fulfill({ json: syntheticRuntimeConfig }));
  await page.addInitScript(({ key, state }) => {
    if (!sessionStorage.getItem(key)) sessionStorage.setItem(key, JSON.stringify(state));
  }, { key: syntheticOidcStorageKey, state: { ...syntheticAuthState, profile: { sub: 'synthetic-user-a' } } });
  await page.route(url => url.pathname === '/api/v2/documents', async route => {
    expect(route.request().headers()['x-scanalyze-contract-version']).toBe(contractVersion);
    calls.createKeys.push(route.request().headers()['idempotency-key']);
    const createIndex = calls.createKeys.length - 1;
    await scenario.createResponseGates?.[createIndex];
    if (scenario.createUnknown || (scenario.createUnknownAfterFirst && createIndex > 0)) return route.abort('failed');
    if (scenario.changeActorAfterCreate) {
      await page.evaluate(key => {
        const stored = JSON.parse(sessionStorage.getItem(key)!);
        stored.profile.sub = 'synthetic-user-b';
        stored.access_token = 'synthetic-access-token-b';
        sessionStorage.setItem(key, JSON.stringify(stored));
      }, syntheticOidcStorageKey);
    }
    await route.fulfill({ status: 201, json: {
      schemaVersion: 'scanalyze.operation-response.v1', contractVersion, replayed: false,
      durableResponse, uploadCapability: capability,
    } });
  });
  await page.route(url => url.pathname === '/api/v2/operations/documents.create/reconciliation', async route => {
    expect(route.request().method()).toBe('POST');
    expect(route.request().headers()['x-scanalyze-contract-version']).toBe(contractVersion);
    calls.reconcileKeys.push(route.request().headers()['idempotency-key']);
    const ledgerState = scenario.ledgerState ?? 'SUCCEEDED';
    const failureCode = {
      FAILED_RETRYABLE: 'CREATE_FAILED_RETRYABLE', FAILED_TERMINAL: 'CREATE_FAILED_TERMINAL',
      UNKNOWN_OR_QUARANTINED: 'UNKNOWN_WRITE_OUTCOME', EXPIRED: 'OPERATION_EXPIRED',
    }[ledgerState];
    await route.fulfill({ json: {
      schemaVersion: 'scanalyze.reconciliation.v1', contractVersion, operation: 'documents.create',
      ledgerState,
      ...(ledgerState === 'SUCCEEDED' ? { durableResponse } : {}),
      ...(failureCode ? { failureCode } : {}),
      ...(['PENDING', 'FAILED_RETRYABLE'].includes(ledgerState) ? {} : { completedAt: '2026-09-09T00:01:00Z' }),
      createdAt: '2026-09-09T00:00:00Z', updatedAt: '2026-09-09T00:01:00Z',
      expiresAt: ledgerState === 'EXPIRED' ? '2026-09-09T00:01:00Z' : '2026-10-09T00:00:00Z',
    } });
  });
  await page.route(url => url.pathname === `/api/v2/documents/${documentId}/upload-capabilities`, async route => {
    calls.refresh += 1;
    await route.fulfill({ json: { schemaVersion: 'scanalyze.upload-capability.v1', contractVersion, documentId, uploadCapability: capability } });
  });
  await page.route(uploadUrl, async route => {
    calls.upload += 1;
    expect(route.request().method()).toBe('PUT');
    expect(route.request().headers().authorization).toBeUndefined();
    if (scenario.uploadFails && calls.upload === 1) return route.abort('failed');
    await route.fulfill({ status: 200 });
  });
  await page.route(url => url.pathname === `/api/v2/documents/${documentId}/submit`, async route => {
    calls.submit += 1;
    expect(route.request().postDataJSON()).toEqual({ stage: 'ingest' });
    if ((scenario.submitUnknown || scenario.enqueueFails) && calls.submit === 1) return route.abort('failed');
    await route.fulfill({ status: 202, json: {
      schemaVersion: 'scanalyze.document-submit.v1', contractVersion, documentId, stage: 'ingest', enqueued: true,
    } });
  });
  await page.route(url => url.pathname === `/api/v2/documents/${documentId}`, async route => {
    if (scenario.statusFails) return route.abort('failed');
    const status = scenario.enqueueFails && calls.submit === 1
      ? { lifecycle: 'SUBMITTED', currentStage: 'INGEST', stageState: 'FAILED', processingCondition: 'NOT_APPLICABLE', failureDisposition: 'RETRYABLE', safeFailureCode: 'ENQUEUE_FAILED' }
      : calls.submit > 0
        ? { lifecycle: 'PROCESSING', currentStage: 'OCR', stageState: 'RUNNING', processingCondition: 'ACTIVE' }
        : { lifecycle: 'UPLOAD_PENDING', currentStage: 'INGEST', stageState: 'PENDING', processingCondition: 'ACTIVE' };
    await route.fulfill({ json: {
      schemaVersion: 'scanalyze.document-status.v1', contractVersion, documentId,
      createdAt: '2026-09-09T00:00:00Z', updatedAt: '2026-09-09T00:01:00Z', ...status, ...scenario.statusOverride,
    } });
  });
  await page.goto('/upload');
  await expect(page.getByRole('heading', { name: 'Scanalyze Upload' })).toBeVisible();
  return calls;
}

async function startUpload(page: Page) {
  await page.locator('input[type="file"]').setInputFiles(file);
  await page.getByRole('button', { name: 'Subir Documento', exact: true }).click();
  await expect(page.getByRole('alert')).toBeVisible();
}

async function recover(page: Page) {
  await page.getByRole('button', { name: 'Recuperar carga', exact: true }).click();
}

async function journal(page: Page) {
  return page.evaluate(() => Object.entries(sessionStorage).filter(([key]) => key.startsWith('scanalyze.upload.v1:')));
}

test('response loss survives reload, reconciles original CREATE key and requires the original file', async ({ page }) => {
  const calls = await installScenario(page, { createUnknown: true });
  await startUpload(page);
  const saved = await journal(page);
  expect(saved).toHaveLength(1);
  expect(JSON.parse(saved[0][1]).phase).toBe('CREATE_UNKNOWN');
  expect(saved[0][1]).not.toContain(file.name);
  expect(saved[0][1]).not.toContain('synthetic document bytes');
  expect(saved[0][1]).not.toContain('synthetic-access-token');
  expect(saved[0][1]).not.toContain(uploadUrl);
  expect(calls.createKeys[0]).toMatch(/^[0-9a-f-]{36}$/);

  await page.reload();
  await recover(page);
  await expect(page.getByRole('alert')).toContainText('Selecciona el archivo original');
  await page.locator('input[type="file"]').setInputFiles({ ...file, buffer: Buffer.from('different synthetic document bytes') });
  await recover(page);
  await expect(page.getByRole('alert')).toContainText('El archivo no coincide');
  expect(calls.upload).toBe(0);
  await page.locator('input[type="file"]').setInputFiles(file);
  await recover(page);
  await expect(page).toHaveURL(`/document/${documentId}`);
  expect(calls.createKeys).toHaveLength(1);
  expect(calls.reconcileKeys).toEqual(calls.createKeys);
  expect(calls.refresh).toBe(1);
  expect(calls.upload).toBe(1);
  expect(calls.submit).toBe(1);
  expect(await journal(page)).toHaveLength(0);
});

test('failed PUT refreshes capability for the same durable document without another CREATE', async ({ page }) => {
  const calls = await installScenario(page, { uploadFails: true });
  await startUpload(page);
  await expect(page.getByRole('alert')).not.toContainText(uploadUrl);
  const saved = await journal(page);
  expect(saved[0][1]).not.toContain('capability');
  expect(JSON.parse(saved[0][1]).documentId).toBe(documentId);
  await recover(page);
  await expect(page).toHaveURL(`/document/${documentId}`);
  expect(calls.createKeys).toHaveLength(1);
  expect(calls.refresh).toBe(1);
  expect(calls.upload).toBe(2);
  expect(calls.submit).toBe(1);
});

test('unknown submit checks existing status after reload without CREATE, PUT or submit replay', async ({ page }) => {
  const calls = await installScenario(page, { submitUnknown: true });
  await startUpload(page);
  expect(JSON.parse((await journal(page))[0][1]).phase).toBe('SUBMIT_UNKNOWN');
  await page.reload();
  await recover(page);
  await expect(page).toHaveURL(`/document/${documentId}`);
  expect(calls.createKeys).toHaveLength(1);
  expect(calls.upload).toBe(1);
  expect(calls.submit).toBe(1);
  expect(calls.refresh).toBe(0);
});

test('confirmed retryable enqueue failure retries only submit for the original document', async ({ page }) => {
  const calls = await installScenario(page, { enqueueFails: true });
  await startUpload(page);
  await recover(page);
  await expect(page).toHaveURL(`/document/${documentId}`);
  expect(calls.createKeys).toHaveLength(1);
  expect(calls.upload).toBe(1);
  expect(calls.submit).toBe(2);
  expect(calls.refresh).toBe(0);
});

test('unavailable status keeps unknown submit recoverable without any repeated writes', async ({ page }) => {
  const calls = await installScenario(page, { submitUnknown: true, statusFails: true });
  await startUpload(page);
  await recover(page);
  await expect(page.getByRole('alert')).toBeVisible();
  expect(calls.createKeys).toHaveLength(1);
  expect(calls.upload).toBe(1);
  expect(calls.submit).toBe(1);
  expect(JSON.parse((await journal(page))[0][1]).phase).toBe('SUBMIT_UNKNOWN');
});

test('pending reconciliation preserves the original intent and never issues a second CREATE', async ({ page }) => {
  const calls = await installScenario(page, { createUnknown: true, ledgerState: 'PENDING' });
  await startUpload(page);
  await recover(page);
  await expect(page.getByRole('alert')).toContainText('La creación sigue pendiente');
  await recover(page);
  await expect(page.getByRole('alert')).toContainText('La creación sigue pendiente');
  expect(calls.createKeys).toHaveLength(1);
  expect(calls.reconcileKeys).toEqual([calls.createKeys[0], calls.createKeys[0]]);
  expect(calls.upload).toBe(0);
});

for (const ledgerState of ['FAILED_RETRYABLE', 'FAILED_TERMINAL', 'UNKNOWN_OR_QUARANTINED', 'EXPIRED']) {
  test(`${ledgerState} stops without a new CREATE or upload`, async ({ page }) => {
    const calls = await installScenario(page, { createUnknown: true, ledgerState });
    await startUpload(page);
    await recover(page);
    await expect(page.getByRole('alert')).toContainText('requiere revisión');
    await expect(page.getByRole('button', { name: 'Recuperar carga', exact: true })).toBeDisabled();
    expect(JSON.parse((await journal(page))[0][1]).phase).toBe('STOPPED');
    expect(calls.createKeys).toHaveLength(1);
    expect(calls.upload).toBe(0);
    expect(calls.submit).toBe(0);
  });
}

test('storage failure prevents CREATE before any write can occur', async ({ page }) => {
  const calls = await installScenario(page);
  await page.evaluate(() => {
    const original = Storage.prototype.setItem;
    Storage.prototype.setItem = function (key, value) {
      if (key.startsWith('scanalyze.upload.v1:')) throw new DOMException('Synthetic quota failure', 'QuotaExceededError');
      original.call(this, key, value);
    };
  });
  await startUpload(page);
  await expect(page.getByRole('alert')).toContainText('No se pudo guardar la recuperación');
  expect(calls.createKeys).toHaveLength(0);
  expect(calls.upload).toBe(0);
});

test('persistence failure after CREATE leaves the original key available for reconciliation', async ({ page }) => {
  const calls = await installScenario(page);
  await page.evaluate(() => {
    const original = Storage.prototype.setItem;
    let writes = 0;
    Storage.prototype.setItem = function (key, value) {
      if (key.startsWith('scanalyze.upload.v1:') && ++writes === 2) throw new DOMException('Synthetic quota failure', 'QuotaExceededError');
      original.call(this, key, value);
    };
  });
  await startUpload(page);
  expect(JSON.parse((await journal(page))[0][1]).phase).toBe('CREATE_UNKNOWN');
  await recover(page);
  await expect(page).toHaveURL(`/document/${documentId}`);
  expect(calls.createKeys).toHaveLength(1);
  expect(calls.reconcileKeys).toEqual(calls.createKeys);
});

test('a malformed saved intent is retained and blocks a replacement CREATE', async ({ page }) => {
  const calls = await installScenario(page, { createUnknown: true });
  await startUpload(page);
  const saved = await journal(page);
  await page.evaluate(key => sessionStorage.setItem(key, '{malformed'), saved[0][0]);
  await page.reload();
  await expect(page.getByRole('alert')).toContainText('No se puede leer la recuperación');
  await expect(page.getByRole('button', { name: 'Subir Documento', exact: true })).toBeDisabled();
  expect((await journal(page))[0][1]).toBe('{malformed');
  expect(calls.createKeys).toHaveLength(1);
});

test('actor change while CREATE is in flight preserves the original journal and stops before PUT', async ({ page }) => {
  const calls = await installScenario(page, { changeActorAfterCreate: true });
  await startUpload(page);
  await expect(page.getByRole('alert')).toContainText('La sesión cambió o expiró');
  const saved = await journal(page);
  expect(JSON.parse(saved[0][1]).documentId).toBe(documentId);
  expect(calls.createKeys).toHaveLength(1);
  expect(calls.upload).toBe(0);
  expect(calls.submit).toBe(0);
  await page.reload();
  await page.locator('input[type="file"]').setInputFiles(file);
  await expect(page.getByRole('button', { name: 'Subir Documento', exact: true })).toBeEnabled();
  await expect(page.getByRole('button', { name: 'Recuperar carga', exact: true })).toHaveCount(0);
  expect(await journal(page)).toEqual(saved);
});

test('the API interceptor rejects actor changes between journal persistence and request dispatch', async ({ page }) => {
  const calls = await installScenario(page);
  await page.evaluate(oidcKey => {
    const original = Storage.prototype.setItem;
    Storage.prototype.setItem = function (key, value) {
      original.call(this, key, value);
      if (key.startsWith('scanalyze.upload.v1:')) {
        const stored = JSON.parse(sessionStorage.getItem(oidcKey)!);
        stored.profile.sub = 'synthetic-user-b';
        stored.access_token = 'synthetic-access-token-b';
        original.call(sessionStorage, oidcKey, JSON.stringify(stored));
      }
    };
  }, syntheticOidcStorageKey);
  await startUpload(page);
  expect(calls.createKeys).toHaveLength(0);
  expect(calls.upload).toBe(0);
  expect(calls.submit).toBe(0);
  expect(JSON.parse((await journal(page))[0][1]).phase).toBe('CREATE_UNKNOWN');
});

for (const statusOverride of [
  { lifecycle: 'UNSUPPORTED_STATE' },
  { lifecycle: 'UPLOAD_PENDING', currentStage: 'INGEST', stageState: 'PENDING', processingCondition: 'ACTIVE', terminalAt: '2026-09-09T00:00:30Z' },
  { lifecycle: 'PROCESSING', currentStage: 'INGEST', stageState: 'RUNNING', processingCondition: 'ACTIVE' },
]) {
  test(`invalid status ${JSON.stringify(statusOverride)} cannot authorize a submit replay`, async ({ page }) => {
    const calls = await installScenario(page, { submitUnknown: true, statusOverride });
    await startUpload(page);
    await recover(page);
    await expect(page.getByRole('alert')).toContainText('no permite continuar');
    expect(calls.createKeys).toHaveLength(1);
    expect(calls.upload).toBe(1);
    expect(calls.submit).toBe(1);
    expect(JSON.parse((await journal(page))[0][1]).phase).toBe('SUBMIT_UNKNOWN');
  });
}

test('late response from an unmounted A upload cannot overwrite a new B recovery intent', async ({ page }) => {
  let releaseA!: () => void;
  let releaseB!: () => void;
  const gateA = new Promise<void>(resolve => { releaseA = resolve; });
  const gateB = new Promise<void>(resolve => { releaseB = resolve; });
  const calls = await installScenario(page, { createResponseGates: [gateA, gateB], createUnknownAfterFirst: true });
  await page.route(url => url.pathname.startsWith('/api/') && !url.pathname.startsWith('/api/v2/'), route => route.fulfill({ json: { items: [] } }));

  await page.locator('input[type="file"]').setInputFiles(file);
  await page.getByRole('button', { name: 'Subir Documento', exact: true }).click();
  await expect.poll(() => calls.createKeys.length).toBe(1);

  // Real SPA navigation unmounts A without unloading/aborting the browser page.
  await page.locator('a[href="/dashboard"]').first().click();
  await page.locator('a[href="/upload"]').click();
  await page.locator('input[type="file"]').setInputFiles(file);
  await recover(page);
  await expect(page).toHaveURL(`/document/${documentId}`);
  expect(calls.reconcileKeys).toEqual([calls.createKeys[0]]);
  expect(await journal(page)).toHaveLength(0);

  await page.locator('a[href="/dashboard"]').first().click();
  await page.locator('a[href="/upload"]').click();
  await page.locator('input[type="file"]').setInputFiles({ ...file, name: 'synthetic-b.pdf', buffer: Buffer.from('synthetic B bytes') });
  await page.getByRole('button', { name: 'Subir Documento', exact: true }).click();
  await expect.poll(() => calls.createKeys.length).toBe(2);
  const savedB = await journal(page);
  expect(JSON.parse(savedB[0][1]).key).toBe(calls.createKeys[1]);
  expect(calls.createKeys[1]).not.toBe(calls.createKeys[0]);

  const lateResponse = page.waitForResponse(response => new URL(response.url()).pathname === '/api/v2/documents');
  releaseA();
  await (await lateResponse).finished();
  // Allow the delayed XHR continuation to run before observing shared storage.
  await page.waitForTimeout(100);
  expect(await journal(page)).toEqual(savedB);
  expect(calls.upload).toBe(1);
  expect(calls.submit).toBe(1);

  releaseB();
  await expect(page.getByRole('alert')).toBeVisible();
  expect(await journal(page)).toEqual(savedB);
});
