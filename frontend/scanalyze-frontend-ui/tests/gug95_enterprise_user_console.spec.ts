import { expect, test, type Page } from '@playwright/test';

import { syntheticOidcStorageKey, syntheticRuntimeConfig } from './runtime';

const CUSTOMER_ID = syntheticRuntimeConfig.customer_id;
const DEPLOYMENT_ID = syntheticRuntimeConfig.deployment_id;
const POLICY_DIGEST = syntheticRuntimeConfig.authorization.policy_digest;
const MEMBER_REFERENCE = `mbr_${'1'.repeat(32)}`;

const encode = (value: unknown) => Buffer.from(JSON.stringify(value)).toString('base64url');

const accessToken = (roleId: string, overrides: Record<string, unknown> = {}) => {
  const now = Math.floor(Date.now() / 1000);
  const claims = {
    sub: 'synthetic-user-subject',
    token_use: 'access',
    principal_type: 'user',
    'custom:customerId': CUSTOMER_ID,
    'custom:deployment_id': DEPLOYMENT_ID,
    membership_state: 'active',
    role_id: roleId,
    membership_version: '7',
    authz_schema_version: 'enterprise-authorization.v1',
    scope_catalog_version: 'scanalyze.api.v1',
    role_catalog_version: 'enterprise-roles.v1',
    policy_version: '1.0.0',
    policy_digest: POLICY_DIGEST,
    scope: roleId === 'customer_admin'
      ? 'scanalyze.api.v1/read scanalyze.api.v1/admin'
      : 'scanalyze.api.v1/read',
    iat: now - 30,
    auth_time: now - 60,
    exp: now + 300,
    ...overrides,
  };
  return `${encode({ alg: 'RS256', typ: 'JWT' })}.${encode(claims)}.synthetic-signature`;
};

const runtimeConfig = {
  ...syntheticRuntimeConfig,
  features: {
    ...syntheticRuntimeConfig.features,
    user_administration: true,
    audit_view: true,
  },
};

const bootstrap = async (
  page: Page,
  roleId: string,
  overrides: Record<string, unknown> = {},
) => {
  await page.route('/config.json', async route => route.fulfill({ json: runtimeConfig }));
  await page.goto('/');
  const token = accessToken(roleId, overrides);
  await page.evaluate(({ key, state }) => {
    sessionStorage.setItem(key, JSON.stringify(state));
  }, {
    key: syntheticOidcStorageKey,
    state: {
      profile: { sub: 'synthetic-user-subject' },
      access_token: token,
      token_type: 'Bearer',
      scope: roleId === 'customer_admin'
        ? 'scanalyze.api.v1/read scanalyze.api.v1/admin'
        : 'scanalyze.api.v1/read',
      expires_at: Math.floor(Date.now() / 1000) + 300,
    },
  });
  await page.reload();
};

const membership = (state = 'active', roleId = 'document_operator', version = '3') => ({
  membershipReference: MEMBER_REFERENCE,
  state,
  roleId,
  membershipVersion: version,
  createdAt: '2026-07-13T12:00:00Z',
  updatedAt: '2026-07-14T12:00:00Z',
  invitationExpiresAt: state === 'invited' ? '2026-07-14T13:00:00Z' : null,
});

test('customer admin lists and filters deployment-local memberships', async ({ page }) => {
  const membershipRequests: string[] = [];
  await page.route('**/api/v1/admin/roles', async route => route.fulfill({
    json: {
      schemaVersion: 'enterprise-roles.v1',
      roles: ['customer_admin', 'document_operator', 'document_reviewer', 'auditor'],
    },
    headers: { 'x-correlation-id': `ref_${'a'.repeat(32)}` },
  }));
  await page.route('**/api/v1/admin/memberships**', async route => {
    membershipRequests.push(route.request().url());
    await route.fulfill({
      json: { items: [membership()], nextCursor: null },
      headers: { 'x-correlation-id': `ref_${'b'.repeat(32)}` },
    });
  });
  await page.route('**/api/v1/admin/audit-events**', async route => route.fulfill({
    json: { items: [], nextCursor: null },
  }));

  await bootstrap(page, 'customer_admin');
  await page.goto('/admin/users');

  await expect(page.getByRole('heading', { name: 'Administración de usuarios' })).toBeVisible();
  await expect(page.getByRole('table', { name: 'Membresías enterprise' })).toContainText(MEMBER_REFERENCE);
  await page.getByLabel('Filtrar por estado').selectOption('active');
  await expect.poll(() => membershipRequests.some(url => url.includes('state=active'))).toBe(true);
});

for (const [name, roleId, overrides] of [
  ['operator', 'document_operator', {}],
  ['cross deployment', 'customer_admin', { 'custom:deployment_id': 'dep_01ARZ3NDEKTSV4RRFFQ69G5FAW' }],
] as const) {
  test(`direct console access fails closed for ${name}`, async ({ page }) => {
    let adminRequests = 0;
    await page.route('**/api/v1/admin/**', async route => {
      adminRequests += 1;
      await route.fulfill({ status: 403 });
    });
    await bootstrap(page, roleId, overrides);
    await page.goto('/admin/users');

    await expect(page.getByRole('heading', { name: 'Acceso no disponible' })).toBeVisible();
    expect(adminRequests).toBe(0);
  });
}

test('mutation confirmation omits identity authority and surfaces sanitized conflict correlation', async ({ page }) => {
  let mutationBody: Record<string, unknown> | undefined;
  await page.route('**/api/v1/admin/roles', async route => route.fulfill({
    json: { schemaVersion: 'enterprise-roles.v1', roles: ['customer_admin', 'document_operator'] },
  }));
  await page.route('**/api/v1/admin/memberships?**', async route => route.fulfill({
    json: { items: [membership()], nextCursor: null },
  }));
  await page.route('**/api/v1/admin/audit-events**', async route => route.fulfill({
    json: { items: [], nextCursor: null },
  }));
  await page.route(`**/api/v1/admin/memberships/${MEMBER_REFERENCE}/suspensions`, async route => {
    mutationBody = route.request().postDataJSON() as Record<string, unknown>;
    expect(route.request().headers()['idempotency-key']).toMatch(/^idem_[A-Za-z0-9_-]{16,64}$/);
    await route.fulfill({
      status: 409,
      json: { code: 'CONFLICT', message: 'conflict', details: {} },
      headers: {
        'access-control-expose-headers': 'X-Correlation-ID, X-Request-ID, X-Trace-ID',
        'x-correlation-id': `ref_${'c'.repeat(32)}`,
      },
    });
  });

  await bootstrap(page, 'customer_admin');
  await page.goto('/admin/users');
  await page.getByRole('button', { name: 'Suspender' }).click();
  await expect(page.getByRole('dialog', { name: 'Confirmar suspensión' })).toBeVisible();
  await page.getByLabel('Referencia de aprobación').fill(`apr_${'1'.repeat(32)}`);
  await page.getByLabel('Código de motivo').fill('security_review');
  await page.getByRole('button', { name: 'Confirmar acción' }).click();

  await expect(page.getByRole('alert')).toContainText('actualiza e intenta nuevamente');
  await expect(page.getByRole('alert')).toContainText(`ref_${'c'.repeat(32)}`);
  expect(mutationBody).toEqual({
    expected_membership_version: 3,
    approval_reference: `apr_${'1'.repeat(32)}`,
    reason_code: 'security_review',
    replacement_membership_reference: null,
  });
  expect(mutationBody).not.toHaveProperty('customer_id');
  expect(mutationBody).not.toHaveProperty('deployment_id');
});

test('auditor receives audit-only view and cannot enumerate memberships', async ({ page }) => {
  let membershipRequests = 0;
  await page.route('**/api/v1/admin/memberships**', async route => {
    membershipRequests += 1;
    await route.fulfill({ status: 403 });
  });
  await page.route('**/api/v1/admin/audit-events**', async route => route.fulfill({
    json: {
      items: [{
        eventReference: `ref_${'d'.repeat(32)}`,
        timestamp: '2026-07-14T12:00:00Z',
        action: 'membership.suspend',
        decision: 'allow',
        reasonCode: 'security_review',
        principalReference: `ref_${'e'.repeat(32)}`,
        correlationReference: `ref_${'f'.repeat(32)}`,
        beforeMembershipVersion: '3',
        afterMembershipVersion: '4',
      }],
      nextCursor: null,
    },
  }));

  await bootstrap(page, 'auditor');
  await page.goto('/admin/users');

  await expect(page.getByRole('heading', { name: 'Auditoría de lifecycle' })).toBeVisible();
  await expect(page.getByText('membership.suspend')).toBeVisible();
  await expect(page.getByRole('button', { name: 'Invitar usuario' })).toHaveCount(0);
  expect(membershipRequests).toBe(0);
});

test('admin API denial is generic and does not render foreign data', async ({ page }) => {
  await page.route('**/api/v1/admin/roles', async route => route.fulfill({ status: 403 }));
  await page.route('**/api/v1/admin/memberships**', async route => route.fulfill({
    status: 403,
    json: { code: 'FORBIDDEN', message: 'forbidden', details: { subject: 'must-not-render' } },
  }));
  await page.route('**/api/v1/admin/audit-events**', async route => route.fulfill({
    json: { items: [], nextCursor: null },
  }));

  await bootstrap(page, 'customer_admin');
  await page.goto('/admin/users');

  await expect(page.getByRole('alert')).toContainText('no está disponible para esta sesión');
  await expect(page.getByText('must-not-render')).toHaveCount(0);
  await expect(page.getByRole('table', { name: 'Membresías enterprise' })).toHaveCount(0);
});

test('expired backend session is handled without exposing response payloads', async ({ page }) => {
  await page.route('**/api/v1/admin/roles', async route => route.fulfill({ status: 401 }));
  await page.route('**/api/v1/admin/memberships**', async route => route.fulfill({
    status: 401,
    json: { token: 'must-not-render' },
  }));
  await page.route('**/api/v1/admin/audit-events**', async route => route.fulfill({
    json: { items: [], nextCursor: null },
  }));

  await bootstrap(page, 'customer_admin');
  await page.goto('/admin/users');

  await expect(page.getByRole('alert')).toContainText('La sesión expiró');
  await expect(page.getByText('must-not-render')).toHaveCount(0);
});

test('invitation form sends only reviewed lifecycle fields and supports keyboard dismissal', async ({ page }) => {
  let invitationBody: Record<string, unknown> | undefined;
  await page.route('**/api/v1/admin/roles', async route => route.fulfill({
    json: { schemaVersion: 'enterprise-roles.v1', roles: ['customer_admin', 'document_operator'] },
  }));
  await page.route('**/api/v1/admin/memberships**', async route => route.fulfill({
    json: { items: [], nextCursor: null },
  }));
  await page.route('**/api/v1/admin/audit-events**', async route => route.fulfill({
    json: { items: [], nextCursor: null },
  }));
  await page.route('**/api/v1/admin/invitations', async route => {
    invitationBody = route.request().postDataJSON() as Record<string, unknown>;
    await route.fulfill({
      json: { status: 'completed', operationReference: `op_${'1'.repeat(32)}` },
    });
  });

  await bootstrap(page, 'customer_admin');
  await page.goto('/admin/users');
  await page.getByRole('button', { name: 'Invitar usuario' }).click();
  await expect(page.getByRole('dialog', { name: 'Invitar usuario' })).toBeVisible();
  await page.keyboard.press('Escape');
  await expect(page.getByRole('dialog', { name: 'Invitar usuario' })).toHaveCount(0);
  await page.getByRole('button', { name: 'Invitar usuario' }).click();
  await page.getByLabel('Correo corporativo').fill('synthetic@example.invalid');
  await page.getByRole('combobox', { name: 'Rol' }).selectOption('document_operator');
  await page.getByLabel('Referencia de aprobación').fill(`apr_${'2'.repeat(32)}`);
  await page.getByRole('button', { name: 'Crear invitación' }).click();

  await expect.poll(() => invitationBody).toEqual({
    principal_locator: 'synthetic@example.invalid',
    role_id: 'document_operator',
    expires_in_seconds: 3600,
    approval_reference: `apr_${'2'.repeat(32)}`,
  });
  expect(invitationBody).not.toHaveProperty('customer_id');
  expect(invitationBody).not.toHaveProperty('deployment_id');
});
