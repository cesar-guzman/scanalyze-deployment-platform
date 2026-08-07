import { expect, test } from '@playwright/test';
import { syntheticRuntimeConfig } from './runtime';


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
  await expect(page.getByRole('alert')).toHaveText('RUNTIME_CONFIG_UPGRADE_REQUIRED');
  await expect(page).toHaveURL('/');
});


test('blocks the SPA when config retrieval fails', async ({ page }) => {
  await page.route('/config.json', async route => {
    await route.fulfill({ status: 503, body: 'unavailable' });
  });

  await page.goto('/');

  await expect(page.getByRole('alert')).toHaveText('RUNTIME_CONFIG_UNAVAILABLE');
});

test('config failure scrubs callback secrets before terminal rendering', async ({ page }) => {
  const authorizationCode = 'synthetic-code-must-leave-history';
  await page.route('/config.json', async route => {
    await route.fulfill({ status: 404, body: 'not found' });
  });

  await page.goto(`/callback?code=${authorizationCode}&state=synthetic-state`);

  await expect(page.getByRole('alert')).toHaveText('RUNTIME_CONFIG_UNAVAILABLE');
  await expect(page).toHaveURL('/callback');
  await expect(page.locator('body')).not.toContainText(authorizationCode);
});

for (const candidate of [
  { name: 'corrupt JSON', body: '{"schema_version":' },
  { name: 'empty document', body: '' },
  { name: 'duplicate keys', body: '{"schema_version":"3","schema_version":"2"}' },
]) {
  test(`fails closed for ${candidate.name}`, async ({ page }) => {
    await page.route('/config.json', async route => {
      await route.fulfill({ status: 200, contentType: 'application/json', body: candidate.body });
    });

    await page.goto('/');

    await expect(page.getByRole('alert')).toHaveText('RUNTIME_CONFIG_INVALID');
    await expect(page.getByRole('button', { name: 'Recargar configuración' })).toBeVisible();
  });
}

test('distinguishes config 404 without retrying automatically', async ({ page }) => {
  let requestCount = 0;
  await page.route('/config.json', async route => {
    requestCount += 1;
    await route.fulfill({ status: 404, body: 'not found' });
  });

  await page.goto('/');

  await expect(page.getByRole('alert')).toHaveText('RUNTIME_CONFIG_UNAVAILABLE');
  expect(requestCount).toBe(1);

  await page.getByRole('button', { name: 'Recargar configuración' }).click();
  await expect(page.getByRole('alert')).toHaveText('RUNTIME_CONFIG_UNAVAILABLE');
  expect(requestCount).toBe(2);
  await page.waitForTimeout(250);
  expect(requestCount).toBe(2);
});

test('config timeout exits progress with a stable safe code', async ({ page }) => {
  await page.route('/config.json', async route => {
    await new Promise(resolve => setTimeout(resolve, 8_000));
    await route.abort('timedout');
  });

  await page.goto('/');

  await expect(page.getByRole('alert')).toHaveText('RUNTIME_CONFIG_TIMEOUT', {
    timeout: 7_000,
  });
});

test('oversized config is rejected while the response body is still bounded', async ({ page }) => {
  await page.route('/config.json', async route => {
    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: `{"schema_version":"3","padding":"${'x'.repeat(65_536)}"}`,
    });
  });

  await page.goto('/');

  await expect(page.getByRole('alert')).toHaveText('RUNTIME_CONFIG_INVALID');
  await expect(page.locator('body')).not.toContainText('x'.repeat(128));
});

test('hostile API origin is rejected without rendering injected values', async ({ page }) => {
  const secretLikeValue = 'client_secret=must-not-render';
  await page.route('/config.json', async route => {
    await route.fulfill({
      json: {
        ...syntheticRuntimeConfig,
        api_endpoint: 'https://attacker.invalid/api',
        [secretLikeValue]: '<script>alert(1)</script>',
      },
    });
  });

  await page.goto('/');

  await expect(page.getByRole('alert')).toHaveText('RUNTIME_CONFIG_INVALID');
  await expect(page.locator('body')).not.toContainText(secretLikeValue);
  await expect(page.locator('body')).not.toContainText('attacker.invalid');
});
