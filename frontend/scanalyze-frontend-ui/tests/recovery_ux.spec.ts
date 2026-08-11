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

test('Recovery UX: Handle network failures during create and upload', async ({ page }) => {
  // Mocks explicitly failing the first attempts
  let createAttempt = 0;
  await page.route('**/api/v2/documents', async route => {
    createAttempt++;
    if (createAttempt === 1) {
      await route.abort('failed'); // Simula error de red
    } else {
      await route.fulfill({ status: 500, json: { message: "Internal server error mock" } });
    }
  });

  await page.goto('/upload');

  const fileChooserPromise = page.waitForEvent('filechooser');
  await page.click('text=Arrastra tu archivo aquí');
  const fileChooser = await fileChooserPromise;
  await fileChooser.setFiles({
    name: 'fail-test.pdf',
    mimeType: 'application/pdf',
    buffer: Buffer.from('mock pdf content')
  });

  await page.click('text=Subir Documento');

  // Verify UI Shows Error
  await expect(page.locator('text=Error de carga')).toBeVisible();

  // Retry Button exists
  await expect(page.locator('button:has-text("Subir Documento")')).not.toBeDisabled();
});

test('Recovery UX: Handle backend terminal FAILED state gracefully', async ({ page }) => {
  const docId = 'doc-fail-123';

  // Direct access to polling page with FAILED state mock
  await page.route(`**/api/v2/documents/${docId}`, async route => {
    await route.fulfill({
      status: 200,
      json: {
        documentId: docId,
        lifecycle: 'FAILED',
        currentStage: 'TERMINAL',
        safeFailureCode: 'Unparseable pdf mock',
        failureDisposition: 'TERMINAL'
      }
    });
  });

  await page.goto(`/document/${docId}`);

  // Verify Timeline explicit error display
  await expect(page.locator('text=Unparseable pdf mock')).toBeVisible();

  // Verify Critical Error Box with Recovery Action
  await expect(page.locator('text=Error de Procesamiento')).toBeVisible();
  await expect(page.locator('text=Intentar de nuevo')).toBeVisible();
});
