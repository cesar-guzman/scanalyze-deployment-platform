import { test, expect } from '@playwright/test';
import { syntheticAuthState, syntheticOidcStorageKey, syntheticRuntimeConfig } from './runtime';

test.beforeEach(async ({ page }) => {
  await page.route('/config.json', async route => {
    await route.fulfill({ json: syntheticRuntimeConfig });
  });

  await page.goto('/');
  await page.evaluate((auth) => {
    sessionStorage.setItem(auth.key, JSON.stringify(auth.state));
  }, { key: syntheticOidcStorageKey, state: syntheticAuthState });
  await page.reload();
});

test('Happy Path: File Upload, Polling and Download JSON', async ({ page }) => {
  const docId = 'doc-12345';

  // 1. Intercept Calls
  await page.route('**/api/documents', async route => {
    await route.fulfill({
      json: {
        documentId: docId,
        uploadUrl: 'https://upload.synthetic.invalid/object',
        uploadMethod: 'PUT',
        requiredHeaders: { 'Content-Type': 'application/pdf' },
        expiresAt: new Date(Date.now() + 3600000).toISOString()
      }
    });
  });

  await page.route('https://upload.synthetic.invalid/object', async route => {
    await route.fulfill({ status: 200 }); // Mock S3 upload success
  });

  await page.route(`**/api/documents/${docId}/submit`, async route => {
    await route.fulfill({ status: 202 });
  });

  let pollingCount = 0;
  await page.route(`**/api/documents/${docId}`, async route => {
    pollingCount++;
    if (pollingCount === 1) {
      await route.fulfill({ json: { documentId: docId, status: 'PROCESSING', stages: { RECEIVED: { status: 'SUCCEEDED' }, OCR: { status: 'IN_PROGRESS' } } } });
    } else {
      await route.fulfill({ json: { documentId: docId, status: 'COMPLETED', stages: { RECEIVED: { status: 'SUCCEEDED' }, OCR: { status: 'SUCCEEDED' }, COMPLETED: { status: 'SUCCEEDED' } } } });
    }
  });

  await page.route(`**/api/documents/${docId}/result`, async route => {
    await route.fulfill({ json: {
      resultType: "BANK",
      processor: { engine: "mock-engine", model: "v1" },
      data: { extracted: true }
    }});
  });

  // 2. Perform UI Actions
  // Empezar en dashboard
  await page.goto('/dashboard');

  // Navegar a upload
  await page.click('text=Nuevo Espacio de Trabajo (Subida)');

  // Archivo falso
  const fileChooserPromise = page.waitForEvent('filechooser');
  await page.click('text=Seleccionar Documento');
  const fileChooser = await fileChooserPromise;
  await fileChooser.setFiles({
    name: 'test-statement.pdf',
    mimeType: 'application/pdf',
    buffer: Buffer.from('mock pdf content')
  });

  // Upload
  await page.click('text=🚀 Iniciar Subida');

  // Verify URL change to Document page
  await page.waitForURL(`**/document/${docId}`);

  // Verificar UI general y badge COMPLETED
  await expect(page.locator('h1', { hasText: 'Detalles del Documento' })).toBeVisible();
  await expect(page.locator('span', { hasText: 'COMPLETED' })).toBeVisible({ timeout: 10000 });

  // Tab Results visual
  await page.click('text=RESULT');
  await expect(page.locator('text=Type: BANK')).toBeVisible();

  // JSON Tab Download
  await page.click('text=JSON');
  await expect(page.locator('pre')).toContainText('"extracted": true');

  // Simular descarga de JSON file
  const [download] = await Promise.all([
    page.waitForEvent('download'),
    page.click('text=⬇ Download JSON')
  ]);

  expect(download.suggestedFilename()).toBe(`scanalyze-result-${docId}.json`);
});
