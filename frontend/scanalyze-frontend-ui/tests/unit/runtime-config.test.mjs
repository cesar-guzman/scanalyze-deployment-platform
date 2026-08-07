import assert from 'node:assert/strict';
import test from 'node:test';

import {
  RuntimeConfigError,
  parseRuntimeConfig,
  parseStrictJson,
} from '../../src/config/runtime.js';

const ORIGIN = 'http://localhost:5173';
const DEPLOYMENT_ID = 'dep_01ARZ3NDEKTSV4RRFFQ69G5FAV';
const HOSTED_UI = 'https://dep-01arz3ndektsv4rrffq69g5fav-identity.auth.us-east-1.amazoncognito.com';

const validV3 = (origin = ORIGIN, environment = 'sandbox') => ({
  schema_version: '3',
  customer_id: 'cust_01ARZ3NDEKTSV4RRFFQ69G5FAV',
  deployment_id: DEPLOYMENT_ID,
  account_id: '123456789012',
  region: 'us-east-1',
  environment,
  api_endpoint: `${origin}/api`,
  cognito: {
    user_pool_id: 'us-east-1_SYNTHETIC01',
    spa_client_id: 'syntheticspaclient000000000001',
    issuer_url: 'https://cognito-idp.us-east-1.amazonaws.com/us-east-1_SYNTHETIC01',
    region: 'us-east-1',
    hosted_ui_domain: HOSTED_UI,
    redirect_uri: `${origin}/callback`,
    post_logout_redirect_uri: `${origin}/`,
    allowed_oauth_flows: ['code'],
    pkce_required: true,
    client_secret_embedded: false,
  },
  authorization: {
    allowed_token_uses: ['access'],
    action_scopes: {
      read: 'scanalyze.api.v1/read',
      write: 'scanalyze.api.v1/write',
      admin: 'scanalyze.api.v1/admin',
    },
    policy_version: '1.0.0',
    policy_digest: 'sha256:34a639992f6c2312176ac7dc12c361daa38201adea6af0c0b1765a17a14754f8',
    policy_canonicalization: 'rfc8785_json_canonicalization',
    customer_claim_name: 'custom:customerId',
    deployment_claim_name: 'custom:deployment_id',
    id_tokens_accepted: false,
  },
  identity_values_authoritative: false,
  features: {
    document_upload: true,
    batch_processing: true,
    audit_view: false,
    user_administration: false,
  },
  config_version: '2026.07.14',
});

const validV2 = () => {
  const candidate = structuredClone(validV3());
  candidate.schema_version = '2';
  candidate.config_version = 'legacy-v2';
  delete candidate.cognito.redirect_uri;
  delete candidate.cognito.post_logout_redirect_uri;
  return candidate;
};

const parse = (candidate, origin = ORIGIN) => parseRuntimeConfig(candidate, { origin });

const assertConfigError = (operation, code = 'RUNTIME_CONFIG_INVALID') => {
  assert.throws(operation, (error) => (
    error instanceof RuntimeConfigError
    && error.code === code
    && error.message === code
  ));
};

test('accepts the closed v3 contract and calendar release version', () => {
  const parsed = parse(validV3());
  assert.equal(parsed.schemaVersion, '3');
  assert.equal(parsed.sourceSchemaVersion, '3');
  assert.equal(parsed.compatibilityMode, 'native-v3');
  assert.equal(parsed.configVersion, '2026.07.14');
  assert.equal(parsed.redirectUri, `${ORIGIN}/callback`);
  assert.ok(Object.isFrozen(parsed));
});

test('accepts the repository release version with its leading v', () => {
  const candidate = validV3();
  candidate.config_version = 'v2.1.0';
  assert.equal(parse(candidate).configVersion, 'v2.1.0');
});

test('rejects config versions beyond the canonical 128-character limit', () => {
  const v3 = validV3();
  v3.config_version = `1.0.0-${'a'.repeat(123)}`;
  assertConfigError(() => parse(v3));

  const v2 = validV2();
  v2.config_version = `legacy-${'a'.repeat(122)}`;
  assertConfigError(() => parse(v2), 'RUNTIME_CONFIG_UPGRADE_REQUIRED');
});

test('migrates the safe v2 subset deterministically to the canonical v3 shape', () => {
  const parsed = parse(validV2());
  assert.equal(parsed.schemaVersion, '3');
  assert.equal(parsed.sourceSchemaVersion, '2');
  assert.equal(parsed.compatibilityMode, 'migrated-v2');
  assert.equal(parsed.configVersion, '2.0.0-compat');
  assert.equal(parsed.cognitoDomain, HOSTED_UI);
  assert.equal(parsed.redirectUri, `${ORIGIN}/callback`);
});

test('rejects v1 with the explicit upgrade requirement', () => {
  const candidate = validV3();
  candidate.schema_version = '1';
  assertConfigError(() => parse(candidate), 'RUNTIME_CONFIG_UPGRADE_REQUIRED');
});

test('rejects unknown schema versions with a safe unsupported-version code', () => {
  for (const version of ['4', 'future']) {
    const candidate = validV3();
    candidate.schema_version = version;
    assertConfigError(() => parse(candidate), 'RUNTIME_CONFIG_UNSUPPORTED_VERSION');
  }
});

test('rejects unsafe v2 compatibility inputs with an explicit upgrade requirement', () => {
  const missingDomain = validV2();
  delete missingDomain.cognito.hosted_ui_domain;
  assertConfigError(() => parse(missingDomain), 'RUNTIME_CONFIG_UPGRADE_REQUIRED');

  const missingVersion = validV2();
  delete missingVersion.config_version;
  assertConfigError(() => parse(missingVersion), 'RUNTIME_CONFIG_UPGRADE_REQUIRED');

  const externalApi = validV2();
  externalApi.api_endpoint = 'https://abc123def4.execute-api.us-east-1.amazonaws.com';
  assertConfigError(() => parse(externalApi), 'RUNTIME_CONFIG_UPGRADE_REQUIRED');

  const bareHostedUi = validV2();
  bareHostedUi.cognito.hosted_ui_domain = HOSTED_UI.replace('https://', '');
  assertConfigError(() => parse(bareHostedUi), 'RUNTIME_CONFIG_UPGRADE_REQUIRED');

  for (const mutate of [
    (candidate) => { candidate.customer_id = 42; },
    (candidate) => { candidate.apiBaseUrl = candidate.api_endpoint; },
    (candidate) => { candidate.cognito.cognitoDomain = candidate.cognito.hosted_ui_domain; },
    (candidate) => { candidate.cognito.redirect_uri = `${ORIGIN}/callback`; },
    (candidate) => { candidate.authorization.allowed_token_uses = ['id']; },
    (candidate) => { candidate.legacy_tenant = 'default'; },
  ]) {
    const candidate = validV2();
    mutate(candidate);
    assertConfigError(() => parse(candidate), 'RUNTIME_CONFIG_UPGRADE_REQUIRED');
  }
});

for (const field of [
  'customer_id',
  'deployment_id',
  'account_id',
  'region',
  'environment',
  'api_endpoint',
  'cognito',
  'authorization',
  'identity_values_authoritative',
  'config_version',
]) {
  test(`rejects v3 without required field ${field}`, () => {
    const candidate = validV3();
    delete candidate[field];
    assertConfigError(() => parse(candidate));
  });
}

for (const field of [
  'allowed_token_uses',
  'action_scopes',
  'policy_version',
  'policy_digest',
  'policy_canonicalization',
  'customer_claim_name',
  'deployment_claim_name',
  'id_tokens_accepted',
]) {
  test(`rejects v3 without required authorization field ${field}`, () => {
    const candidate = validV3();
    delete candidate.authorization[field];
    assertConfigError(() => parse(candidate));
  });
}

for (const field of ['read', 'write', 'admin']) {
  test(`rejects v3 without required action scope ${field}`, () => {
    const candidate = validV3();
    delete candidate.authorization.action_scopes[field];
    assertConfigError(() => parse(candidate));
  });
}

for (const field of [
  'user_pool_id',
  'spa_client_id',
  'issuer_url',
  'region',
  'hosted_ui_domain',
  'redirect_uri',
  'post_logout_redirect_uri',
  'allowed_oauth_flows',
  'pkce_required',
  'client_secret_embedded',
]) {
  test(`rejects v3 without required cognito field ${field}`, () => {
    const candidate = validV3();
    delete candidate.cognito[field];
    assertConfigError(() => parse(candidate));
  });
}

for (const mutate of [
  (candidate) => { candidate.customer_id = 'foreign-customer'; },
  (candidate) => { candidate.deployment_id = ''; },
  (candidate) => { candidate.account_id = 123456789012; },
  (candidate) => { candidate.region = 'invalid-region'; },
  (candidate) => { candidate.cognito.region = 'us-west-2'; },
  (candidate) => { candidate.cognito.client_secret_embedded = true; },
  (candidate) => { candidate.authorization.allowed_token_uses = ['id']; },
  (candidate) => { candidate.authorization.policy_digest = `sha256:${'0'.repeat(64)}`; },
  (candidate) => { candidate.identity_values_authoritative = true; },
  (candidate) => { candidate.legacy_tenant = 'default'; },
]) {
  test('rejects malformed, ambiguous, or legacy runtime authority', () => {
    const candidate = validV3();
    mutate(candidate);
    assertConfigError(() => parse(candidate));
  });
}

test('binds API and redirect URLs to the current origin', () => {
  for (const mutate of [
    (candidate) => { candidate.api_endpoint = 'https://attacker.invalid/api'; },
    (candidate) => { candidate.cognito.redirect_uri = 'https://attacker.invalid/callback'; },
    (candidate) => { candidate.cognito.post_logout_redirect_uri = 'https://attacker.invalid/'; },
  ]) {
    const candidate = validV3();
    mutate(candidate);
    assertConfigError(() => parse(candidate));
  }
});

test('binds hosted UI to the deployment identity in the configured region', () => {
  const attacker = validV3();
  attacker.cognito.hosted_ui_domain = 'https://attacker.auth.us-east-1.amazoncognito.com';
  assertConfigError(() => parse(attacker));

  const otherDeployment = validV3();
  otherDeployment.cognito.hosted_ui_domain = 'https://dep-01arz3ndektsv4rrffq69g5faa-identity.auth.us-east-1.amazoncognito.com';
  assertConfigError(() => parse(otherDeployment));

  const hostedPort = validV3();
  hostedPort.cognito.hosted_ui_domain = `${HOSTED_UI}:8443`;
  assertConfigError(() => parse(hostedPort));
});

test('allows HTTP only for reviewed local sandbox origins', () => {
  assert.equal(parse(validV3(), ORIGIN).apiBaseUrl, `${ORIGIN}/api`);

  const loopbackOrigin = 'http://127.0.0.1:5173';
  assert.equal(parse(validV3(loopbackOrigin), loopbackOrigin).apiBaseUrl, `${loopbackOrigin}/api`);

  const nonLocalOrigin = 'http://example.invalid';
  assertConfigError(() => parse(validV3(nonLocalOrigin), nonLocalOrigin));
  assertConfigError(() => parse(validV3('http://localhost'), 'http://localhost'));
  assertConfigError(() => parse(validV3(ORIGIN, 'staging'), ORIGIN));

  const publicPortOrigin = 'https://app.example.invalid:8443';
  assertConfigError(() => parse(validV3(publicPortOrigin, 'staging'), publicPortOrigin));
});

test('supports the reviewed aws-cn DNS suffixes', () => {
  const candidate = validV3();
  candidate.region = 'cn-north-1';
  candidate.cognito.region = 'cn-north-1';
  candidate.cognito.user_pool_id = 'cn-north-1_SYNTHETIC01';
  candidate.cognito.issuer_url = 'https://cognito-idp.cn-north-1.amazonaws.com.cn/cn-north-1_SYNTHETIC01';
  candidate.cognito.hosted_ui_domain = 'https://dep-01arz3ndektsv4rrffq69g5fav-identity.auth.cn-north-1.amazoncognito.com.cn';
  assert.equal(parse(candidate).cognitoRegion, 'cn-north-1');
});

test('strict JSON rejects duplicate keys including escaped duplicates', () => {
  assertConfigError(() => parseStrictJson('{"schema_version":"3","schema_version":"2"}'));
  assertConfigError(() => parseStrictJson('{"outer":{"cognito":1,"\\u0063ognito":2}}'));
});

test('strict JSON and the closed contract reject hostile object shapes', () => {
  const polluted = parseStrictJson('{"__proto__":{"polluted":true}}');
  assert.equal(Object.hasOwn(polluted, '__proto__'), true);
  assertConfigError(() => parse(polluted), 'RUNTIME_CONFIG_UNSUPPORTED_VERSION');

  const constructorField = validV3();
  Object.defineProperty(constructorField, 'constructor', { enumerable: true, value: {} });
  assertConfigError(() => parse(constructorField));

  const prototypeField = validV3();
  prototypeField.cognito.prototype = {};
  assertConfigError(() => parse(prototypeField));

  const inherited = Object.assign(Object.create({ polluted: true }), validV3());
  assertConfigError(() => parse(inherited));
});

test('strict JSON rejects empty, corrupt, and non-finite documents', () => {
  for (const serialized of [
    '',
    ' ',
    '{',
    '{"value":NaN}',
    '{"value":Infinity}',
    '{"value":1e999}',
  ]) {
    assertConfigError(() => parseStrictJson(serialized));
  }
});

test('errors never project hostile values', () => {
  const secretLike = 'client_secret=do-not-render-this-value';
  const candidate = validV3();
  candidate[secretLike] = '<script>alert(1)</script>';
  assert.throws(() => parse(candidate), (error) => (
    error instanceof RuntimeConfigError
    && error.message === 'RUNTIME_CONFIG_INVALID'
    && !error.message.includes(secretLike)
    && !error.stack.includes(secretLike)
  ));
});
