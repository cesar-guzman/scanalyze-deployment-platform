import { expect, test, type Page } from '@playwright/test';
import {
  syntheticAuthState,
  syntheticOidcStorageKey,
  syntheticRuntimeConfig,
} from './runtime';

const issuer = syntheticRuntimeConfig.cognito.issuer_url;
const hostedUi = `https://${syntheticRuntimeConfig.cognito.hosted_ui_domain}`;

async function installRuntimeConfig(page: Page) {
  await page.route('/config.json', async route => {
    await route.fulfill({ json: syntheticRuntimeConfig });
  });
}

async function installOidcDiscovery(page: Page) {
  await page.route(`${issuer}/.well-known/openid-configuration`, async route => {
    await route.fulfill({
      json: {
        issuer,
        authorization_endpoint: `${hostedUi}/oauth2/authorize`,
        token_endpoint: `${issuer}/oauth2/token`,
        userinfo_endpoint: `${issuer}/oauth2/userInfo`,
        jwks_uri: `${issuer}/.well-known/jwks.json`,
        end_session_endpoint: `${hostedUi}/logout`,
      },
    });
  });
}

async function installSyntheticSession(page: Page) {
  await page.goto('/');
  await page.evaluate((auth) => {
    sessionStorage.setItem(auth.key, JSON.stringify(auth.state));
  }, { key: syntheticOidcStorageKey, state: syntheticAuthState });
}

test.beforeEach(async ({ page }) => {
  await installRuntimeConfig(page);
});

test('unauthenticated protected deep links fail closed to login', async ({ page }) => {
  await page.goto('/document/doc-deep-link');

  await expect(page).toHaveURL('/login');
  await expect(page.getByRole('button', { name: /Iniciar Sesión/u })).toBeVisible();
});

test('login preserves the reviewed OIDC authorization boundary', async ({ page }) => {
  await installOidcDiscovery(page);
  await page.route(`${hostedUi}/oauth2/authorize**`, async route => {
    await route.fulfill({
      contentType: 'text/html',
      body: '<!doctype html><title>Synthetic hosted UI</title>',
    });
  });

  await page.goto('/login');
  const authorizationRequest = page.waitForRequest(
    request => request.url().startsWith(`${hostedUi}/oauth2/authorize`),
  );
  await page.getByRole('button', { name: /Iniciar Sesión/u }).click();

  const authorizationUrl = new URL((await authorizationRequest).url());
  expect(authorizationUrl.searchParams.get('client_id')).toBe(
    syntheticRuntimeConfig.cognito.spa_client_id,
  );
  expect(authorizationUrl.searchParams.get('redirect_uri')).toBe(
    'http://localhost:5173/callback',
  );
  expect(authorizationUrl.searchParams.get('response_type')).toBe('code');
  expect(authorizationUrl.searchParams.get('scope')).toContain(
    syntheticRuntimeConfig.authorization.action_scopes.read,
  );
});

test('authenticated callback route returns to the protected upload path', async ({ page }) => {
  await installSyntheticSession(page);

  await page.goto('/callback');

  await expect(page).toHaveURL('/upload');
  await expect(page.getByRole('heading', { name: 'Arrastra un documento' })).toBeVisible();
});

test('logout preserves the reviewed post-logout redirect', async ({ page }) => {
  await installOidcDiscovery(page);
  await page.route(`${hostedUi}/logout**`, async route => {
    await route.fulfill({
      contentType: 'text/html',
      body: '<!doctype html><title>Synthetic logout</title>',
    });
  });
  await installSyntheticSession(page);
  await page.goto('/dashboard');

  const logoutRequest = page.waitForRequest(
    request => request.url().startsWith(`${hostedUi}/logout`),
  );
  await page.getByRole('button', { name: 'Cerrar Sesión' }).click();

  const logoutUrl = new URL((await logoutRequest).url());
  expect(logoutUrl.searchParams.get('client_id')).toBe(
    syntheticRuntimeConfig.cognito.spa_client_id,
  );
  expect(logoutUrl.searchParams.get('post_logout_redirect_uri')).toBe(
    'http://localhost:5173/',
  );
});
