import { expect, test, type Page } from '@playwright/test';
import {
  syntheticAuthState,
  syntheticOidcStorageKey,
  syntheticRuntimeConfig,
} from './runtime';

const issuer = syntheticRuntimeConfig.cognito.issuer_url;
const hostedUi = syntheticRuntimeConfig.cognito.hosted_ui_domain;

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
        token_endpoint: `${hostedUi}/oauth2/token`,
        userinfo_endpoint: `${hostedUi}/oauth2/userInfo`,
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

test('metadata seed prevents discovery endpoint substitution', async ({ page }) => {
  let attackerRequests = 0;
  await page.route('https://attacker.invalid/**', async route => {
    attackerRequests += 1;
    await route.abort('blockedbyclient');
  });
  await page.route(`${issuer}/.well-known/openid-configuration`, async route => {
    await route.fulfill({
      json: {
        issuer: 'https://attacker.invalid/issuer',
        authorization_endpoint: 'https://attacker.invalid/authorize',
        token_endpoint: 'https://attacker.invalid/token',
        userinfo_endpoint: 'https://attacker.invalid/userinfo',
        jwks_uri: 'https://attacker.invalid/jwks',
        end_session_endpoint: 'https://attacker.invalid/logout',
      },
    });
  });
  await page.route(`${hostedUi}/oauth2/authorize**`, async route => {
    await route.fulfill({
      contentType: 'text/html',
      body: '<!doctype html><title>Synthetic hosted UI</title>',
    });
  });

  await page.goto('/login');
  const reviewedRequest = page.waitForRequest(
    request => request.url().startsWith(`${hostedUi}/oauth2/authorize`),
  );
  await page.getByRole('button', { name: /Iniciar Sesión/u }).click();

  await reviewedRequest;
  expect(attackerRequests).toBe(0);
});

test('OIDC discovery timeout exits the secure-session spinner', async ({ page }) => {
  let discoveryRequests = 0;
  await page.route(`${issuer}/.well-known/openid-configuration`, async route => {
    discoveryRequests += 1;
    await new Promise(resolve => setTimeout(resolve, 8_000));
    await route.abort('timedout');
  });

  await page.goto('/login');
  await page.getByRole('button', { name: /Iniciar Sesión/u }).click();

  await expect(page.getByRole('alert')).toHaveText('OIDC_DISCOVERY_TIMEOUT', {
    timeout: 7_000,
  });
  expect(discoveryRequests).toBe(1);
});

test('malformed discovery reaches a terminal redacted error', async ({ page }) => {
  const secretLikeValue = 'client_secret=must-not-reach-ui-or-console';
  let discoveryRequests = 0;
  const consoleMessages: string[] = [];
  page.on('console', message => consoleMessages.push(message.text()));
  await page.route(`${issuer}/.well-known/openid-configuration`, async route => {
    discoveryRequests += 1;
    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: `{"issuer":"${secretLikeValue}"`,
    });
  });

  await page.goto('/login');
  await page.getByRole('button', { name: /Iniciar Sesión/u }).click();

  await expect(page.getByRole('alert')).toHaveText('OIDC_DISCOVERY_INVALID');
  await expect(page.locator('body')).not.toContainText(secretLikeValue);
  expect(consoleMessages.join('\n')).not.toContain(secretLikeValue);
  expect(discoveryRequests).toBe(1);
});

test('discovery retry is explicit and bounded', async ({ page }) => {
  let discoveryRequests = 0;
  await page.route(`${issuer}/.well-known/openid-configuration`, async route => {
    discoveryRequests += 1;
    if (discoveryRequests === 1) {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: '{"issuer":',
      });
      return;
    }
    await route.fulfill({
      json: {
        issuer,
        authorization_endpoint: `${hostedUi}/oauth2/authorize`,
        token_endpoint: `${hostedUi}/oauth2/token`,
        userinfo_endpoint: `${hostedUi}/oauth2/userInfo`,
        jwks_uri: `${issuer}/.well-known/jwks.json`,
        end_session_endpoint: `${hostedUi}/logout`,
      },
    });
  });
  await page.route(`${hostedUi}/oauth2/authorize**`, async route => {
    await route.fulfill({
      contentType: 'text/html',
      body: '<!doctype html><title>Synthetic hosted UI retry</title>',
    });
  });

  await page.goto('/login');
  await page.getByRole('button', { name: /Iniciar Sesión/u }).click();
  await expect(page.getByRole('alert')).toHaveText('OIDC_DISCOVERY_INVALID');
  expect(discoveryRequests).toBe(1);

  const authorizationRequest = page.waitForRequest(
    request => request.url().startsWith(`${hostedUi}/oauth2/authorize`),
  );
  await page.getByRole('button', { name: 'Intentar nuevamente' }).click();
  await authorizationRequest;
  await expect(page).toHaveTitle('Synthetic hosted UI retry');
  expect(discoveryRequests).toBe(2);
  await page.waitForTimeout(250);
  expect(discoveryRequests).toBe(2);
});

test('callback without state reaches a terminal safe error', async ({ page }) => {
  await page.goto('/callback?code=synthetic-code-without-state');

  await expect(page.getByRole('alert')).toHaveText('AUTH_CALLBACK_INVALID', {
    timeout: 2_000,
  });
  await expect(page).toHaveURL('/callback');
});

test('callback with unknown state reaches the same terminal safe error', async ({ page }) => {
  const authorizationCode = 'synthetic-sensitive-authorization-code';
  await page.goto(`/callback?code=${authorizationCode}&state=unknown-state`);

  await expect(page.getByRole('alert')).toHaveText('AUTH_CALLBACK_INVALID', {
    timeout: 2_000,
  });
  await expect(page).toHaveURL('/callback');
  await expect(page.locator('body')).not.toContainText(authorizationCode);
});

test('stale callback state is rejected before token exchange', async ({ page }) => {
  const state = 'stale-state-0000000000000001';
  const authorizationCode = 'synthetic-stale-authorization-code';
  let tokenRequests = 0;
  await page.route(`${hostedUi}/oauth2/token`, async route => {
    tokenRequests += 1;
    await route.abort('blockedbyclient');
  });
  await page.goto('/login');
  await page.evaluate(({ key, value }) => {
    sessionStorage.setItem(key, JSON.stringify(value));
  }, {
    key: `oidc.${state}`,
    value: {
      id: state,
      created: Math.floor(Date.now() / 1_000) - 301,
      request_type: 'si:r',
      code_verifier: 'a'.repeat(64),
      authority: issuer,
      client_id: syntheticRuntimeConfig.cognito.spa_client_id,
      redirect_uri: syntheticRuntimeConfig.cognito.redirect_uri,
      scope: 'openid',
    },
  });

  await page.goto(`/callback?code=${authorizationCode}&state=${state}`);

  await expect(page.getByRole('alert')).toHaveText('AUTH_CALLBACK_INVALID');
  await expect(page).toHaveURL('/callback');
  await expect(page.locator('body')).not.toContainText(authorizationCode);
  expect(tokenRequests).toBe(0);
});

test('provider-generated callback state passes preflight exactly once', async ({ page }) => {
  let generatedState: string | null = null;
  await installOidcDiscovery(page);
  await page.route(`${hostedUi}/oauth2/authorize**`, async route => {
    generatedState = new URL(route.request().url()).searchParams.get('state');
    await route.fulfill({
      contentType: 'text/html',
      body: '<!doctype html><title>Synthetic hosted UI</title>',
    });
  });

  await page.goto('/login');
  await page.getByRole('button', { name: /Iniciar Sesión/u }).click();
  await expect(page).toHaveTitle('Synthetic hosted UI');
  expect(generatedState).toMatch(/^[A-Za-z0-9._~-]{16,512}$/);

  let tokenRequests = 0;
  await page.route(`${hostedUi}/oauth2/token`, async route => {
    tokenRequests += 1;
    await route.fulfill({
      status: 400,
      contentType: 'application/json',
      body: '{"error":"invalid_grant"}',
    });
  });

  const authorizationCode = 'synthetic-provider-state-authorization-code';
  await page.goto(`/callback?code=${authorizationCode}&state=${generatedState}`);

  await expect(page.getByRole('alert')).toHaveText('AUTH_CALLBACK_INVALID');
  await expect(page).toHaveURL('/callback');
  await expect(page.locator('body')).not.toContainText(authorizationCode);
  expect(tokenRequests).toBe(1);
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
  expect(logoutUrl.searchParams.get('logout_uri')).toBe(
    'http://localhost:5173/',
  );
  expect(logoutUrl.searchParams.has('post_logout_redirect_uri')).toBe(false);
  expect(logoutUrl.searchParams.has('id_token_hint')).toBe(false);
});
