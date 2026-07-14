const MAX_TOKEN_LENGTH = 16_384;
const MAX_AUTH_AGE_SECONDS = 300;
const VERSION = Object.freeze({
  authz: 'enterprise-authorization.v1',
  scopes: 'scanalyze.api.v1',
  roles: 'enterprise-roles.v1',
  policy: '1.0.0',
});
const ROLES = new Set([
  'auditor',
  'customer_admin',
  'document_operator',
  'document_reviewer',
]);

export class EnterpriseUxAuthorizationError extends Error {
  constructor() {
    super('UX_AUTHORIZATION_DENIED');
    this.name = 'EnterpriseUxAuthorizationError';
    this.code = 'UX_AUTHORIZATION_DENIED';
  }
}

const deny = () => {
  throw new EnterpriseUxAuthorizationError();
};

const decodeClaims = (token) => {
  if (typeof token !== 'string' || token.length === 0 || token.length > MAX_TOKEN_LENGTH) deny();
  const segments = token.split('.');
  if (segments.length !== 3 || segments.some((segment) => segment.length === 0)) deny();
  try {
    const normalized = segments[1].replace(/-/gu, '+').replace(/_/gu, '/');
    const padding = '='.repeat((4 - (normalized.length % 4)) % 4);
    const binary = globalThis.atob(`${normalized}${padding}`);
    const bytes = Uint8Array.from(binary, (character) => character.charCodeAt(0));
    const parsed = JSON.parse(new TextDecoder().decode(bytes));
    if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) deny();
    return parsed;
  } catch (error) {
    if (error instanceof EnterpriseUxAuthorizationError) throw error;
    deny();
  }
};

const exactInteger = (value) => (
  typeof value === 'number' && Number.isSafeInteger(value) ? value : null
);

const exactString = (value, pattern) => (
  typeof value === 'string' && pattern.test(value) ? value : null
);

/**
 * Derives display-only capabilities from an access token. The backend PEP remains
 * authoritative for every request; these capabilities only prevent rendering
 * controls that the current session cannot use.
 */
export const resolveEnterpriseUxAuthorization = (token, config, nowEpoch = Date.now() / 1000) => {
  const claims = decodeClaims(token);
  if (config === null || typeof config !== 'object' || Array.isArray(config)) deny();
  const now = Math.floor(nowEpoch);
  const iat = exactInteger(claims.iat);
  const authTime = exactInteger(claims.auth_time);
  const exp = exactInteger(claims.exp);
  const roleId = exactString(claims.role_id, /^[a-z][a-z0-9_]{2,63}$/u);
  const membershipVersion = exactString(claims.membership_version, /^[1-9][0-9]*$/u);
  const subject = exactString(claims.sub, /^[A-Za-z0-9][A-Za-z0-9._:@-]{0,255}$/u);
  const scope = exactString(claims.scope, /^[A-Za-z0-9.:/_ -]{1,2048}$/u);

  if (
    !Number.isSafeInteger(now)
    || subject === null
    || claims.token_use !== 'access'
    || claims.principal_type !== 'user'
    || claims['custom:customerId'] !== config.customerId
    || claims['custom:deployment_id'] !== config.deploymentId
    || claims.membership_state !== 'active'
    || roleId === null
    || !ROLES.has(roleId)
    || membershipVersion === null
    || claims.authz_schema_version !== VERSION.authz
    || claims.scope_catalog_version !== VERSION.scopes
    || claims.role_catalog_version !== VERSION.roles
    || claims.policy_version !== VERSION.policy
    || claims.policy_digest !== config.policyDigest
    || iat === null
    || authTime === null
    || exp === null
    || iat > now
    || authTime > now
    || exp <= now
    || now - authTime > MAX_AUTH_AGE_SECONDS
    || scope === null
  ) deny();

  const scopes = new Set(scope.split(' ').filter(Boolean));
  const readScope = config.actionScopes?.read;
  const adminScope = config.actionScopes?.admin;
  if (typeof readScope !== 'string' || typeof adminScope !== 'string') deny();
  const canManageUsers = roleId === 'customer_admin' && scopes.has(adminScope);
  const canReadAudit = canManageUsers || (roleId === 'auditor' && scopes.has(readScope));

  return Object.freeze({ roleId, canManageUsers, canReadAudit });
};

export const resolveEnterpriseUxAuthorizationFromSession = (
  session,
  config,
  nowEpoch = Date.now() / 1000,
) => resolveEnterpriseUxAuthorization(session?.access_token, config, nowEpoch);
