export class EnterpriseUxAuthorizationError extends Error {
  readonly code: 'UX_AUTHORIZATION_DENIED';
}

export interface EnterpriseUxConfig {
  readonly customerId: string;
  readonly deploymentId: string;
  readonly policyDigest: string;
  readonly actionScopes: Readonly<{ read: string; admin: string }>;
}

export interface EnterpriseUxCapabilities {
  readonly roleId: 'auditor' | 'customer_admin' | 'document_operator' | 'document_reviewer';
  readonly canManageUsers: boolean;
  readonly canReadAudit: boolean;
}

export function resolveEnterpriseUxAuthorization(
  token: unknown,
  config: EnterpriseUxConfig,
  nowEpoch?: number,
): EnterpriseUxCapabilities;
export function resolveEnterpriseUxAuthorizationFromSession(
  session: { readonly access_token?: string } | null | undefined,
  config: EnterpriseUxConfig,
  nowEpoch?: number,
): EnterpriseUxCapabilities;
