import assert from 'node:assert/strict';
import test from 'node:test';

import {
  EnterpriseUxAuthorizationError,
  resolveEnterpriseUxAuthorization,
} from '../../src/security/enterpriseUxAuthorization.js';

const CONFIG = Object.freeze({
  customerId: 'cust_01ARZ3NDEKTSV4RRFFQ69G5FAV',
  deploymentId: 'dep_01ARZ3NDEKTSV4RRFFQ69G5FAV',
  policyDigest: 'sha256:34a639992f6c2312176ac7dc12c361daa38201adea6af0c0b1765a17a14754f8',
  actionScopes: Object.freeze({
    read: 'scanalyze.api.v1/read',
    write: 'scanalyze.api.v1/write',
    admin: 'scanalyze.api.v1/admin',
  }),
});

const NOW = 1_784_000_000;

const encode = (value) => Buffer.from(JSON.stringify(value)).toString('base64url');
const token = (claims) => `${encode({ alg: 'RS256', typ: 'JWT' })}.${encode(claims)}.synthetic-signature`;

const claims = (overrides = {}) => ({
  sub: 'synthetic-admin-subject',
  token_use: 'access',
  principal_type: 'user',
  'custom:customerId': CONFIG.customerId,
  'custom:deployment_id': CONFIG.deploymentId,
  membership_state: 'active',
  role_id: 'customer_admin',
  membership_version: '7',
  authz_schema_version: 'enterprise-authorization.v1',
  scope_catalog_version: 'scanalyze.api.v1',
  role_catalog_version: 'enterprise-roles.v1',
  policy_version: '1.0.0',
  policy_digest: CONFIG.policyDigest,
  scope: `${CONFIG.actionScopes.read} ${CONFIG.actionScopes.admin}`,
  iat: NOW - 30,
  auth_time: NOW - 60,
  exp: NOW + 300,
  ...overrides,
});

test('customer admin receives management and audit UX capabilities', () => {
  const result = resolveEnterpriseUxAuthorization(token(claims()), CONFIG, NOW);

  assert.deepEqual(result, {
    roleId: 'customer_admin',
    canManageUsers: true,
    canReadAudit: true,
  });
});

test('auditor receives audit-only UX capability', () => {
  const result = resolveEnterpriseUxAuthorization(
    token(claims({ role_id: 'auditor', scope: CONFIG.actionScopes.read })),
    CONFIG,
    NOW,
  );

  assert.equal(result.canManageUsers, false);
  assert.equal(result.canReadAudit, true);
});

test('non-administrator membership fails closed for the user console', () => {
  const result = resolveEnterpriseUxAuthorization(
    token(claims({ role_id: 'document_operator', scope: CONFIG.actionScopes.read })),
    CONFIG,
    NOW,
  );

  assert.equal(result.canManageUsers, false);
  assert.equal(result.canReadAudit, false);
});

for (const override of [
  { token_use: 'id' },
  { principal_type: 'm2m' },
  { 'custom:customerId': 'cust_01ARZ3NDEKTSV4RRFFQ69G5FAW' },
  { 'custom:deployment_id': 'dep_01ARZ3NDEKTSV4RRFFQ69G5FAW' },
  { membership_state: 'suspended' },
  { role_id: 'unknown_role' },
  { role_catalog_version: 'legacy-role-catalog' },
  { policy_digest: `sha256:${'0'.repeat(64)}` },
  { exp: NOW - 1 },
  { iat: NOW + 1 },
]) {
  test(`malformed or conflicting UX authority is rejected: ${JSON.stringify(override)}`, () => {
    assert.throws(
      () => resolveEnterpriseUxAuthorization(token(claims(override)), CONFIG, NOW),
      (error) => (
        error instanceof EnterpriseUxAuthorizationError
        && error.code === 'UX_AUTHORIZATION_DENIED'
        && !error.message.includes('synthetic-admin-subject')
      ),
    );
  });
}

test('opaque or oversized token input is rejected without decoding details', () => {
  for (const value of ['', 'not-a-jwt', `a.${'a'.repeat(20_000)}.b`]) {
    assert.throws(
      () => resolveEnterpriseUxAuthorization(value, CONFIG, NOW),
      EnterpriseUxAuthorizationError,
    );
  }
});
