const POLICY_DIGEST = 'sha256:34a639992f6c2312176ac7dc12c361daa38201adea6af0c0b1765a17a14754f8';
const CUSTOMER_ID = /^cust_[0-9A-HJKMNP-TV-Z]{26}$/;
const DEPLOYMENT_ID = /^dep_[0-9A-HJKMNP-TV-Z]{26}$/;
const ACCOUNT_ID = /^[0-9]{12}$/;
const REGION = /^[a-z]{2}(-gov)?-[a-z]+-[0-9]+$/;
const USER_POOL_ID = /^[a-z]{2}(-gov)?-[a-z]+-[0-9]+_[A-Za-z0-9]+$/;
const CLIENT_ID = /^[A-Za-z0-9]{1,128}$/;
const LEGACY_CONFIG_VERSION = /^[A-Za-z0-9._-]+$/;
const RELEASE_VERSION = /^v?[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$/;
const MAX_CONFIG_VERSION_LENGTH = 128;
const ENVIRONMENTS = new Set(['sandbox', 'dev', 'staging', 'production']);
const COMMON_TOP_LEVEL_KEYS = [
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
];
const V2_TOP_LEVEL_KEYS = new Set(COMMON_TOP_LEVEL_KEYS);
const V3_TOP_LEVEL_KEYS = new Set(COMMON_TOP_LEVEL_KEYS);
const V2_COGNITO_KEYS = new Set([
  'user_pool_id',
  'spa_client_id',
  'issuer_url',
  'region',
  'hosted_ui_domain',
  'allowed_oauth_flows',
  'pkce_required',
  'client_secret_embedded',
]);
const V3_COGNITO_KEYS = new Set([
  ...V2_COGNITO_KEYS,
  'redirect_uri',
  'post_logout_redirect_uri',
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
const FEATURE_KEYS = new Set([
  'document_upload',
  'batch_processing',
  'audit_view',
  'user_administration',
]);

export class RuntimeConfigError extends Error {
  constructor(code = 'RUNTIME_CONFIG_INVALID') {
    super(code);
    this.name = 'RuntimeConfigError';
    this.code = code;
  }
}

const fail = (code = 'RUNTIME_CONFIG_INVALID') => {
  throw new RuntimeConfigError(code);
};

const isRecord = (value) => {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
};

const hasOnlyKeys = (value, keys) => (
  Object.keys(value).every((key) => keys.has(key))
);

const isExactArray = (value, expected) => (
  Array.isArray(value)
  && value.length === expected.length
  && value.every((item, index) => item === expected[index])
);

export const parseStrictJson = (serialized) => {
  if (typeof serialized !== 'string') fail();
  let index = 0;
  const whitespace = new Set([' ', '\t', '\n', '\r']);
  const skipWhitespace = () => {
    while (whitespace.has(serialized[index])) index += 1;
  };
  const scanString = () => {
    if (serialized[index] !== '"') fail();
    const start = index;
    index += 1;
    while (index < serialized.length) {
      const character = serialized[index];
      if (character === '"') {
        index += 1;
        try {
          return JSON.parse(serialized.slice(start, index));
        } catch {
          fail();
        }
      }
      if (character.charCodeAt(0) < 0x20) fail();
      if (character === '\\') {
        index += 1;
        const escaped = serialized[index];
        if (escaped === 'u') {
          if (!/^[0-9A-Fa-f]{4}$/.test(serialized.slice(index + 1, index + 5))) fail();
          index += 5;
          continue;
        }
        if (!['"', '\\', '/', 'b', 'f', 'n', 'r', 't'].includes(escaped)) fail();
      }
      index += 1;
    }
    fail();
  };
  const scanNumber = () => {
    const match = serialized.slice(index).match(/^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/);
    if (!match) fail();
    if (!Number.isFinite(Number(match[0]))) fail();
    index += match[0].length;
  };
  const scanLiteral = (literal) => {
    if (!serialized.startsWith(literal, index)) fail();
    index += literal.length;
  };
  const scanValue = () => {
    skipWhitespace();
    const character = serialized[index];
    if (character === '{') {
      index += 1;
      skipWhitespace();
      const keys = new Set();
      if (serialized[index] === '}') {
        index += 1;
        return;
      }
      while (index < serialized.length) {
        const key = scanString();
        if (keys.has(key)) fail();
        keys.add(key);
        skipWhitespace();
        if (serialized[index] !== ':') fail();
        index += 1;
        scanValue();
        skipWhitespace();
        if (serialized[index] === '}') {
          index += 1;
          return;
        }
        if (serialized[index] !== ',') fail();
        index += 1;
        skipWhitespace();
      }
      fail();
    }
    if (character === '[') {
      index += 1;
      skipWhitespace();
      if (serialized[index] === ']') {
        index += 1;
        return;
      }
      while (index < serialized.length) {
        scanValue();
        skipWhitespace();
        if (serialized[index] === ']') {
          index += 1;
          return;
        }
        if (serialized[index] !== ',') fail();
        index += 1;
      }
      fail();
    }
    if (character === '"') {
      scanString();
      return;
    }
    if (character === 't') return scanLiteral('true');
    if (character === 'f') return scanLiteral('false');
    if (character === 'n') return scanLiteral('null');
    scanNumber();
  };

  scanValue();
  skipWhitespace();
  if (index !== serialized.length) fail();
  try {
    return JSON.parse(serialized);
  } catch {
    fail();
  }
};

const exactUrl = (value) => {
  if (typeof value !== 'string' || value === '' || value !== value.trim()) return null;
  try {
    const parsed = new URL(value);
    if (
      parsed.username !== ''
      || parsed.password !== ''
      || parsed.search !== ''
      || parsed.hash !== ''
    ) return null;
    return parsed;
  } catch {
    return null;
  }
};

const awsDnsSuffix = (region) => (region.startsWith('cn-') ? 'amazonaws.com.cn' : 'amazonaws.com');

const runtimeOrigin = (context, environment) => {
  const origin = context?.origin ?? globalThis.location?.origin;
  const parsed = exactUrl(origin);
  if (!parsed || parsed.origin !== origin || !['http:', 'https:'].includes(parsed.protocol)) fail();
  if (parsed.protocol === 'https:' && parsed.port !== '') fail();
  const localSandbox = environment === 'sandbox'
    && (parsed.hostname === 'localhost' || parsed.hostname === '127.0.0.1')
    && parsed.port !== '';
  if (parsed.protocol !== 'https:' && !localSandbox) fail();
  return parsed.origin;
};

const parseHostedUiOrigin = (value, sourceSchemaVersion, region, deploymentId) => {
  if (sourceSchemaVersion === '2' && value === undefined) {
    fail('RUNTIME_CONFIG_UPGRADE_REQUIRED');
  }
  if (typeof value !== 'string' || value === '' || value !== value.trim()) fail();
  if (sourceSchemaVersion === '2' && !value.startsWith('https://')) {
    fail('RUNTIME_CONFIG_UPGRADE_REQUIRED');
  }
  const parsed = exactUrl(value);
  if (
    !parsed
    || parsed.protocol !== 'https:'
    || parsed.port !== ''
    || parsed.origin !== value
    || parsed.pathname !== '/'
  ) fail(sourceSchemaVersion === '2' ? 'RUNTIME_CONFIG_UPGRADE_REQUIRED' : 'RUNTIME_CONFIG_INVALID');
  const cognitoSuffix = region.startsWith('cn-') ? 'amazoncognito.com.cn' : 'amazoncognito.com';
  const prefix = `${deploymentId.toLowerCase().replace('_', '-')}-identity`;
  const expected = `https://${prefix}.auth.${region}.${cognitoSuffix}`;
  if (parsed.origin !== expected) {
    fail(sourceSchemaVersion === '2' ? 'RUNTIME_CONFIG_UPGRADE_REQUIRED' : 'RUNTIME_CONFIG_INVALID');
  }
  return parsed.origin;
};

const validateApiEndpoint = (value, sourceSchemaVersion, origin) => {
  const parsed = exactUrl(value);
  if (!parsed) fail();
  const sameOriginApi = parsed.origin === origin && parsed.pathname === '/api';
  if (sourceSchemaVersion === '3') {
    if (!sameOriginApi || value !== `${origin}/api`) fail();
    return value;
  }
  if (sameOriginApi && value === `${origin}/api`) return value;
  fail('RUNTIME_CONFIG_UPGRADE_REQUIRED');
};

const validateFeatures = (features) => {
  if (features === undefined) return Object.freeze({});
  if (!isRecord(features) || !hasOnlyKeys(features, FEATURE_KEYS)) fail();
  if (Object.values(features).some((value) => typeof value !== 'boolean')) fail();
  return Object.freeze({ ...features });
};

const validateAuthorization = (authorization) => {
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
  return Object.freeze({ ...scopes });
};

const parseSupportedRuntimeConfig = (value, context, sourceSchemaVersion) => {
  const topLevelKeys = sourceSchemaVersion === '3' ? V3_TOP_LEVEL_KEYS : V2_TOP_LEVEL_KEYS;
  if (!hasOnlyKeys(value, topLevelKeys)) fail();

  if (typeof value.customer_id !== 'string' || !CUSTOMER_ID.test(value.customer_id)) fail();
  if (typeof value.deployment_id !== 'string' || !DEPLOYMENT_ID.test(value.deployment_id)) fail();
  if (typeof value.account_id !== 'string' || !ACCOUNT_ID.test(value.account_id)) fail();
  if (typeof value.region !== 'string' || !REGION.test(value.region)) fail();
  if (typeof value.environment !== 'string' || !ENVIRONMENTS.has(value.environment)) fail();
  const origin = runtimeOrigin(context, value.environment);
  if (value.identity_values_authoritative !== false) fail();

  let configVersion;
  if (sourceSchemaVersion === '3') {
    if (
      typeof value.config_version !== 'string'
      || value.config_version.length > MAX_CONFIG_VERSION_LENGTH
      || !RELEASE_VERSION.test(value.config_version)
    ) fail();
    configVersion = value.config_version;
  } else {
    if (value.config_version === undefined) fail('RUNTIME_CONFIG_UPGRADE_REQUIRED');
    if (
      typeof value.config_version !== 'string'
      || value.config_version.length > MAX_CONFIG_VERSION_LENGTH
      || !LEGACY_CONFIG_VERSION.test(value.config_version)
    ) fail();
    configVersion = '2.0.0-compat';
  }

  const apiBaseUrl = validateApiEndpoint(value.api_endpoint, sourceSchemaVersion, origin);
  const features = validateFeatures(value.features);
  const actionScopes = validateAuthorization(value.authorization);

  const cognito = value.cognito;
  const cognitoKeys = sourceSchemaVersion === '3' ? V3_COGNITO_KEYS : V2_COGNITO_KEYS;
  if (!isRecord(cognito) || !hasOnlyKeys(cognito, cognitoKeys)) fail();
  if (typeof cognito.user_pool_id !== 'string' || !USER_POOL_ID.test(cognito.user_pool_id)) fail();
  if (typeof cognito.spa_client_id !== 'string' || !CLIENT_ID.test(cognito.spa_client_id)) fail();
  if (cognito.region !== value.region) fail();
  const issuer = exactUrl(cognito.issuer_url);
  const expectedIssuer = `https://cognito-idp.${value.region}.${awsDnsSuffix(value.region)}/${cognito.user_pool_id}`;
  if (!issuer || issuer.protocol !== 'https:' || cognito.issuer_url !== expectedIssuer) fail();
  const cognitoDomain = parseHostedUiOrigin(
    cognito.hosted_ui_domain,
    sourceSchemaVersion,
    value.region,
    value.deployment_id,
  );
  if (!isExactArray(cognito.allowed_oauth_flows, ['code'])) fail();
  if (cognito.pkce_required !== true || cognito.client_secret_embedded !== false) fail();

  const redirectUri = `${origin}/callback`;
  const postLogoutRedirectUri = `${origin}/`;
  if (sourceSchemaVersion === '3') {
    if (cognito.redirect_uri !== redirectUri) fail();
    if (cognito.post_logout_redirect_uri !== postLogoutRedirectUri) fail();
  }

  return Object.freeze({
    schemaVersion: '3',
    sourceSchemaVersion,
    compatibilityMode: sourceSchemaVersion === '2' ? 'migrated-v2' : 'native-v3',
    customerId: value.customer_id,
    deploymentId: value.deployment_id,
    accountId: value.account_id,
    region: value.region,
    environment: value.environment,
    apiBaseUrl,
    cognitoRegion: cognito.region,
    cognitoUserPoolId: cognito.user_pool_id,
    cognitoClientId: cognito.spa_client_id,
    cognitoIssuerUrl: cognito.issuer_url,
    cognitoDomain,
    redirectUri,
    postLogoutRedirectUri,
    actionScopes,
    policyDigest: value.authorization.policy_digest,
    identityValuesAuthoritative: false,
    features,
    configVersion,
  });
};

export const parseRuntimeConfig = (value, context = {}) => {
  if (!isRecord(value)) fail();
  const sourceSchemaVersion = value.schema_version;
  if (sourceSchemaVersion === '1') fail('RUNTIME_CONFIG_UPGRADE_REQUIRED');
  if (sourceSchemaVersion !== '2' && sourceSchemaVersion !== '3') {
    fail('RUNTIME_CONFIG_UNSUPPORTED_VERSION');
  }

  try {
    return parseSupportedRuntimeConfig(value, context, sourceSchemaVersion);
  } catch (error) {
    if (sourceSchemaVersion === '2' && error instanceof RuntimeConfigError) {
      fail('RUNTIME_CONFIG_UPGRADE_REQUIRED');
    }
    throw error;
  }
};
