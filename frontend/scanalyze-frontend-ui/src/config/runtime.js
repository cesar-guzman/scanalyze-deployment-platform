const POLICY_DIGEST = 'sha256:34a639992f6c2312176ac7dc12c361daa38201adea6af0c0b1765a17a14754f8';
const CUSTOMER_ID = /^cust_[0-9A-HJKMNP-TV-Z]{26}$/;
const DEPLOYMENT_ID = /^dep_[0-9A-HJKMNP-TV-Z]{26}$/;
const ACCOUNT_ID = /^[0-9]{12}$/;
const REGION = /^[a-z]{2}(-gov)?-[a-z]+-[0-9]+$/;
const USER_POOL_ID = /^[a-z]{2}(-gov)?-[a-z]+-[0-9]+_[A-Za-z0-9]+$/;
const CLIENT_ID = /^[A-Za-z0-9]{1,128}$/;
const CONFIG_VERSION = /^[A-Za-z0-9._-]+$/;
const ENVIRONMENTS = new Set(['sandbox', 'dev', 'staging', 'production']);
const TOP_LEVEL_KEYS = new Set([
  'schema_version',
  'customer_id',
  'deployment_id',
  'account_id',
  'region',
  'environment',
  'api_endpoint',
  'cognito',
  'authorization',
  'identity_values_authoritative',
  'features',
  'config_version',
]);
const COGNITO_KEYS = new Set([
  'user_pool_id',
  'spa_client_id',
  'issuer_url',
  'region',
  'hosted_ui_domain',
  'allowed_oauth_flows',
  'pkce_required',
  'client_secret_embedded',
]);
const AUTHORIZATION_KEYS = new Set([
  'allowed_token_uses',
  'action_scopes',
  'policy_version',
  'policy_digest',
  'policy_canonicalization',
  'customer_claim_name',
  'deployment_claim_name',
  'id_tokens_accepted',
]);
const ACTION_SCOPE_KEYS = new Set(['read', 'write', 'admin']);
const FEATURE_KEYS = new Set(['document_upload', 'batch_processing', 'audit_view']);

export class RuntimeConfigError extends Error {
  constructor(code = 'RUNTIME_CONFIG_INVALID') {
    super(code);
    this.name = 'RuntimeConfigError';
    this.code = code;
  }
}

const fail = () => {
  throw new RuntimeConfigError();
};

const isRecord = (value) => (
  value !== null && typeof value === 'object' && !Array.isArray(value)
);

const hasOnlyKeys = (value, keys) => (
  Object.keys(value).every((key) => keys.has(key))
);

const isExactArray = (value, expected) => (
  Array.isArray(value)
  && value.length === expected.length
  && value.every((item, index) => item === expected[index])
);

const isHttpsUrl = (value) => {
  if (typeof value !== 'string') return false;
  try {
    const parsed = new URL(value);
    return parsed.protocol === 'https:'
      && parsed.username === ''
      && parsed.password === ''
      && parsed.search === ''
      && parsed.hash === '';
  } catch {
    return false;
  }
};

const validateFeatures = (features) => {
  if (features === undefined) return;
  if (!isRecord(features) || !hasOnlyKeys(features, FEATURE_KEYS)) fail();
  if (Object.values(features).some((value) => typeof value !== 'boolean')) fail();
};

export const parseRuntimeConfig = (value) => {
  if (!isRecord(value) || !hasOnlyKeys(value, TOP_LEVEL_KEYS)) fail();
  if (value.schema_version !== '2') fail();
  if (typeof value.customer_id !== 'string' || !CUSTOMER_ID.test(value.customer_id)) fail();
  if (typeof value.deployment_id !== 'string' || !DEPLOYMENT_ID.test(value.deployment_id)) fail();
  if (typeof value.account_id !== 'string' || !ACCOUNT_ID.test(value.account_id)) fail();
  if (typeof value.region !== 'string' || !REGION.test(value.region)) fail();
  if (typeof value.environment !== 'string' || !ENVIRONMENTS.has(value.environment)) fail();
  if (!isHttpsUrl(value.api_endpoint)) fail();
  if (value.identity_values_authoritative !== false) fail();
  if (
    value.config_version !== undefined
    && (typeof value.config_version !== 'string' || !CONFIG_VERSION.test(value.config_version))
  ) fail();
  validateFeatures(value.features);

  const cognito = value.cognito;
  if (!isRecord(cognito) || !hasOnlyKeys(cognito, COGNITO_KEYS)) fail();
  if (typeof cognito.user_pool_id !== 'string' || !USER_POOL_ID.test(cognito.user_pool_id)) fail();
  if (typeof cognito.spa_client_id !== 'string' || !CLIENT_ID.test(cognito.spa_client_id)) fail();
  if (cognito.region !== value.region) fail();
  if (!isHttpsUrl(cognito.issuer_url)) fail();
  const expectedIssuer = `https://cognito-idp.${value.region}.amazonaws.com/${cognito.user_pool_id}`;
  if (cognito.issuer_url !== expectedIssuer) fail();
  if (
    cognito.hosted_ui_domain !== undefined
    && (typeof cognito.hosted_ui_domain !== 'string' || cognito.hosted_ui_domain.trim() === '')
  ) fail();
  if (!isExactArray(cognito.allowed_oauth_flows, ['code'])) fail();
  if (cognito.pkce_required !== true || cognito.client_secret_embedded !== false) fail();

  const authorization = value.authorization;
  if (!isRecord(authorization) || !hasOnlyKeys(authorization, AUTHORIZATION_KEYS)) fail();
  if (!isExactArray(authorization.allowed_token_uses, ['access'])) fail();
  if (authorization.policy_version !== '1.0.0') fail();
  if (authorization.policy_digest !== POLICY_DIGEST) fail();
  if (authorization.policy_canonicalization !== 'rfc8785_json_canonicalization') fail();
  if (authorization.customer_claim_name !== 'custom:customerId') fail();
  if (authorization.deployment_claim_name !== 'custom:deployment_id') fail();
  if (authorization.id_tokens_accepted !== false) fail();

  const scopes = authorization.action_scopes;
  if (!isRecord(scopes) || !hasOnlyKeys(scopes, ACTION_SCOPE_KEYS)) fail();
  if (scopes.read !== 'scanalyze.api.v1/read') fail();
  if (scopes.write !== 'scanalyze.api.v1/write') fail();
  if (scopes.admin !== 'scanalyze.api.v1/admin') fail();

  return Object.freeze({
    schemaVersion: value.schema_version,
    customerId: value.customer_id,
    deploymentId: value.deployment_id,
    accountId: value.account_id,
    region: value.region,
    environment: value.environment,
    apiBaseUrl: value.api_endpoint,
    cognitoRegion: cognito.region,
    cognitoUserPoolId: cognito.user_pool_id,
    cognitoClientId: cognito.spa_client_id,
    cognitoIssuerUrl: cognito.issuer_url,
    cognitoDomain: cognito.hosted_ui_domain ?? '',
    actionScopes: Object.freeze({ ...scopes }),
    policyDigest: authorization.policy_digest,
    identityValuesAuthoritative: false,
    features: Object.freeze({ ...(value.features ?? {}) }),
    configVersion: value.config_version ?? '',
  });
};
