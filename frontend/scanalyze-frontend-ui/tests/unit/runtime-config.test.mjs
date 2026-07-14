import assert from 'node:assert/strict';
import test from 'node:test';

import { RuntimeConfigError, parseRuntimeConfig } from '../../src/config/runtime.js';

const validConfig = () => ({
  schema_version: '2',
  customer_id: 'cust_01ARZ3NDEKTSV4RRFFQ69G5FAV',
  deployment_id: 'dep_01ARZ3NDEKTSV4RRFFQ69G5FAV',
  account_id: '123456789012',
  region: 'us-east-1',
  environment: 'sandbox',
  api_endpoint: 'https://api.synthetic.invalid/api',
  cognito: {
    user_pool_id: 'us-east-1_SYNTHETIC01',
    spa_client_id: 'syntheticspaclient000000000001',
    issuer_url: 'https://cognito-idp.us-east-1.amazonaws.com/us-east-1_SYNTHETIC01',
    region: 'us-east-1',
    hosted_ui_domain: 'synthetic-login.auth.us-east-1.amazoncognito.com',
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
  features: { document_upload: true, batch_processing: true, audit_view: false },
  config_version: 'synthetic-v2',
});

test('accepts the closed v2 runtime contract', () => {
  const parsed = parseRuntimeConfig(validConfig());
  assert.equal(parsed.schemaVersion, '2');
  assert.equal(parsed.cognitoIssuerUrl, validConfig().cognito.issuer_url);
  assert.equal(parsed.identityValuesAuthoritative, false);
  assert.ok(Object.isFrozen(parsed));
});

for (const mutate of [
  (candidate) => { candidate.customer_id = 'foreign-customer'; },
  (candidate) => { candidate.deployment_id = ''; },
  (candidate) => { delete candidate.account_id; },
  (candidate) => { candidate.api_endpoint = 'http://api.synthetic.invalid'; },
  (candidate) => { candidate.cognito.region = 'us-west-2'; },
  (candidate) => { candidate.cognito.client_secret_embedded = true; },
  (candidate) => { candidate.authorization.allowed_token_uses = ['id']; },
  (candidate) => { candidate.authorization.policy_digest = 'sha256:' + '0'.repeat(64); },
  (candidate) => { candidate.identity_values_authoritative = true; },
  (candidate) => { candidate.legacy_tenant = 'default'; },
]) {
  test('rejects malformed, ambiguous, or legacy runtime authority', () => {
    const candidate = structuredClone(validConfig());
    mutate(candidate);
    assert.throws(() => parseRuntimeConfig(candidate), RuntimeConfigError);
  });
}
