import { expect, test } from '@playwright/test';


test('blocks the SPA when runtime ownership is missing', async ({ page }) => {
  await page.route('/config.json', async route => {
    await route.fulfill({
      json: {
        schema_version: '2',
        identity_values_authoritative: false,
      },
    });
  });

  await page.goto('/');

  await expect(page.getByRole('heading', { name: 'Configuración no disponible' })).toBeVisible();
  await expect(page.getByRole('alert')).toHaveText('RUNTIME_CONFIG_INVALID');
  await expect(page).toHaveURL('/');
});


test('blocks the SPA when config retrieval fails', async ({ page }) => {
  await page.route('/config.json', async route => {
    await route.fulfill({ status: 503, body: 'unavailable' });
  });

  await page.goto('/');

  await expect(page.getByRole('alert')).toHaveText('RUNTIME_CONFIG_UNAVAILABLE');
});
