import { expect, test, type Page } from '@playwright/test';
import { syntheticAuthState, syntheticOidcStorageKey, syntheticRuntimeConfig } from './runtime';

// Synthetic browser recovery evidence only. Every API/upload response is mocked;
// unexpected API requests and all other external traffic are blocked.
const origin = new URL(syntheticRuntimeConfig.api_endpoint).origin;
const contractVersion = 'scanalyze.document-journey.v1';
const batchId = 'b'.repeat(32);
const documentId = 'a'.repeat(32);
const timestamp = '2026-09-21T00:00:00Z';
const uploadUrl = 'https://synthetic-upload.invalid/bulk-integrity';
const file = {
  name: 'synthetic-bulk.pdf', mimeType: 'application/pdf',
  buffer: Buffer.from('synthetic document bytes'),
};

async function journal(page: Page) {
  return page.evaluate(() => Object.entries(sessionStorage)
    .filter(([key]) => key.startsWith('scanalyze.upload.v1:')).sort());
}

async function installScenario(page: Page, loseCreate = false) {
  const calls = { batches: 0, createKeys: [] as string[], upload: 0, submit: 0, status: 0 };
  const unexpected: string[] = [];
  await page.route('**/*', async route => {
    const url = new URL(route.request().url());
    if (url.origin !== origin || url.pathname.startsWith('/api')) {
      unexpected.push('UNEXPECTED_REQUEST');
      return route.abort('blockedbyclient');
    }
    return route.continue();
  });
  await page.route(url => url.origin === origin && url.pathname === '/config.json',
    route => route.fulfill({ json: syntheticRuntimeConfig }));
  await page.addInitScript(({ key, state, expectedOrigin }) => {
    if (location.origin === expectedOrigin && !sessionStorage.getItem(key)) {
      sessionStorage.setItem(key, JSON.stringify(state));
    }
  }, { key: syntheticOidcStorageKey, state: syntheticAuthState, expectedOrigin: origin });
  await page.route(url => url.origin === origin && url.pathname === '/api/v2/batches', async route => {
    expect(route.request().method()).toBe('POST');
    expect(route.request().headers()['x-scanalyze-contract-version']).toBe(contractVersion);
    calls.batches += 1;
    await route.fulfill({ status: 201, json: {
      schemaVersion: 'scanalyze.operation-response.v1', contractVersion, replayed: false,
      durableResponse: {
        schemaVersion: 'scanalyze.batch-create-result.v1', contractVersion,
        operation: 'batches.create', batchId, status: 'OPEN', createdAt: timestamp,
      },
    } });
  });
  await page.route(url => url.origin === origin && url.pathname === '/api/v2/documents', async route => {
    expect(route.request().method()).toBe('POST');
    expect(route.request().postDataJSON().batchId).toBe(batchId);
    calls.createKeys.push(route.request().headers()['idempotency-key']);
    if (loseCreate) return route.abort('failed');
    await route.fulfill({ status: 201, json: {
      schemaVersion: 'scanalyze.operation-response.v1', contractVersion, replayed: false,
      durableResponse: {
        schemaVersion: 'scanalyze.document-create-result.v1', contractVersion,
        operation: 'documents.create', documentId, batchId, status: 'UPLOAD_PENDING',
        contentType: 'application/pdf', createdAt: timestamp,
      },
      uploadCapability: {
        method: 'PUT', url: uploadUrl, expiresAt: '2099-01-01T00:00:00Z',
        requiredHeaders: { 'Content-Type': 'application/pdf' },
      },
    } });
  });
  await page.route(uploadUrl, async route => {
    expect(route.request().method()).toBe('PUT');
    expect(route.request().headers().authorization).toBeUndefined();
    calls.upload += 1;
    await route.fulfill({ status: 200 });
  });
  await page.route(url => url.origin === origin && url.pathname === `/api/v2/documents/${documentId}/submit`, async route => {
    expect(route.request().method()).toBe('POST');
    calls.submit += 1;
    await route.fulfill({ status: 202, json: {
      schemaVersion: 'scanalyze.document-submit.v1', contractVersion,
      documentId, stage: 'ingest', enqueued: true,
    } });
  });
  await page.route(url => url.origin === origin && url.pathname === `/api/v2/documents/${documentId}`, async route => {
    expect(route.request().method()).toBe('GET');
    calls.status += 1;
    await route.fulfill({ json: {
      schemaVersion: 'scanalyze.document-status.v1', contractVersion, documentId, batchId,
      lifecycle: 'SUBMITTED', currentStage: 'INGEST', stageState: 'PENDING',
      processingCondition: 'ACTIVE', createdAt: timestamp, updatedAt: timestamp,
    } });
  });
  await page.goto('/bulk-upload');
  await expect(page.getByRole('heading', { name: 'Carga Masiva de Documentos' })).toBeVisible();
  return { calls, unexpected };
}

test('local validation failure preserves an editable draft and allows a valid replacement', async ({ page }) => {
  const { calls, unexpected } = await installScenario(page);
  await page.locator('input[type="file"]').setInputFiles({ ...file, buffer: Buffer.alloc(0) });
  await page.getByRole('button', { name: /Iniciar Lote/ }).click();
  await expect(page.getByRole('alert')).toContainText('válido');
  expect(calls.batches).toBe(0);
  expect(calls.createKeys).toHaveLength(0);
  expect(await journal(page)).toEqual([]);

  await expect(page.getByRole('button', { name: /Iniciar Lote/ })).toBeVisible();
  await page.getByRole('button', { name: '✕', exact: true }).click();
  await expect(page.getByText(file.name, { exact: true })).toHaveCount(0);
  await page.locator('input[type="file"]').setInputFiles(file);
  await page.getByRole('button', { name: /Iniciar Lote/ }).click();
  await expect(page.getByText('Envíos confirmados', { exact: true })).toBeVisible();
  expect(calls).toEqual({ batches: 1, createKeys: [expect.stringMatching(/^[0-9a-f-]{36}$/)], upload: 1, submit: 1, status: 1 });
  await page.getByRole('button', { name: 'Nuevo lote', exact: true }).click();
  await expect(page.getByRole('button', { name: 'Seleccionar Archivos', exact: true })).toBeVisible();
  expect(await journal(page)).toEqual([]);
  expect(unexpected).toEqual([]);
});

test('DONE with an uncertain CREATE is rejected on reload without clearing evidence or creating again', async ({ page }) => {
  const { calls, unexpected } = await installScenario(page, true);
  await page.locator('input[type="file"]').setInputFiles(file);
  await page.getByRole('button', { name: /Iniciar Lote/ }).click();
  await expect(page.getByRole('button', { name: 'Recuperar lote', exact: true })).toBeVisible();
  const saved = await journal(page);
  const [manifestKey, manifestRaw] = saved.find(([key]) => key.endsWith(':bulk'))!;
  const intent = JSON.parse(saved.find(([key]) => key.includes(':item:'))![1]);
  expect(intent.phase).toBe('CREATE_UNKNOWN');
  expect(calls.createKeys).toEqual([intent.key]);
  const manifest = JSON.parse(manifestRaw);
  manifest.items[0].state = 'DONE';
  await page.evaluate(({ key, value }) => sessionStorage.setItem(key, value), {
    key: manifestKey, value: JSON.stringify(manifest),
  });
  const corruptJournal = await journal(page);

  await page.reload();
  await expect(page.getByRole('alert')).toContainText('recuperación del lote no es válida');
  await expect(page.getByRole('button', { name: 'Nuevo lote', exact: true })).toHaveCount(0);
  await expect(page.getByText('Envíos confirmados', { exact: true })).toHaveCount(0);
  expect(await journal(page)).toEqual(corruptJournal);
  expect(calls).toEqual({ batches: 1, createKeys: [intent.key], upload: 0, submit: 0, status: 0 });
  expect(unexpected).toEqual([]);
});
