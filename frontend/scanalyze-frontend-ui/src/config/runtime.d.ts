export type RuntimeConfigErrorCode =
  | 'RUNTIME_CONFIG_INVALID'
  | 'RUNTIME_CONFIG_UNAVAILABLE'
  | 'RUNTIME_CONFIG_TIMEOUT'
  | 'RUNTIME_CONFIG_NOT_LOADED'
  | 'RUNTIME_CONFIG_UPGRADE_REQUIRED'
  | 'RUNTIME_CONFIG_UNSUPPORTED_VERSION';

export class RuntimeConfigError extends Error {
  readonly code: RuntimeConfigErrorCode;
  constructor(code?: RuntimeConfigErrorCode);
}

export interface RuntimeConfigContext {
  readonly origin: string;
}

export type RuntimeEnvironment = 'sandbox' | 'dev' | 'staging' | 'production';

export interface FrontendRuntimeConfigV3Cognito {
  readonly user_pool_id: string;
  readonly spa_client_id: string;
  readonly issuer_url: string;
  readonly region: string;
  readonly hosted_ui_domain: string;
  readonly redirect_uri: string;
  readonly post_logout_redirect_uri: string;
  readonly allowed_oauth_flows: readonly ['code'];
  readonly pkce_required: true;
  readonly client_secret_embedded: false;
}

export interface FrontendRuntimeConfigV3Authorization {
  readonly allowed_token_uses: readonly ['access'];
  readonly action_scopes: Readonly<{
    read: 'scanalyze.api.v1/read';
    write: 'scanalyze.api.v1/write';
    admin: 'scanalyze.api.v1/admin';
  }>;
  readonly policy_version: '1.0.0';
  readonly policy_digest: 'sha256:34a639992f6c2312176ac7dc12c361daa38201adea6af0c0b1765a17a14754f8';
  readonly policy_canonicalization: 'rfc8785_json_canonicalization';
  readonly customer_claim_name: 'custom:customerId';
  readonly deployment_claim_name: 'custom:deployment_id';
  readonly id_tokens_accepted: false;
}

export interface FrontendRuntimeConfigV3 {
  readonly schema_version: '3';
  readonly config_version: string;
  readonly customer_id: string;
  readonly deployment_id: string;
  readonly account_id: string;
  readonly region: string;
  readonly environment: RuntimeEnvironment;
  readonly api_endpoint: string;
  readonly cognito: FrontendRuntimeConfigV3Cognito;
  readonly authorization: FrontendRuntimeConfigV3Authorization;
  readonly identity_values_authoritative: false;
  readonly features?: Readonly<Partial<Record<
    | 'document_upload'
    | 'batch_processing'
    | 'audit_view'
    | 'user_administration',
    boolean
  >>>;
}

export interface ParsedRuntimeConfig {
  readonly schemaVersion: '3';
  readonly sourceSchemaVersion: '2' | '3';
  readonly compatibilityMode: 'migrated-v2' | 'native-v3';
  readonly customerId: string;
  readonly deploymentId: string;
  readonly accountId: string;
  readonly region: string;
  readonly environment: RuntimeEnvironment;
  readonly apiBaseUrl: string;
  readonly cognitoRegion: string;
  readonly cognitoUserPoolId: string;
  readonly cognitoClientId: string;
  readonly cognitoIssuerUrl: string;
  readonly cognitoDomain: string;
  readonly redirectUri: string;
  readonly postLogoutRedirectUri: string;
  readonly actionScopes: Readonly<{ read: string; write: string; admin: string }>;
  readonly policyDigest: string;
  readonly identityValuesAuthoritative: false;
  readonly features: Readonly<Partial<Record<
    | 'document_upload'
    | 'batch_processing'
    | 'audit_view'
    | 'user_administration',
    boolean
  >>>;
  readonly configVersion: string;
}

export function parseRuntimeConfig(
  value: unknown,
  context: RuntimeConfigContext,
): Readonly<ParsedRuntimeConfig>;

export function parseStrictJson(serialized: string): unknown;
