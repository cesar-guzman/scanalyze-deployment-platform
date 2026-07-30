import { parseRuntimeConfig, RuntimeConfigError } from './runtime.js';

export interface AppConfig {
  schemaVersion: '2';
  customerId: string;
  deploymentId: string;
  accountId: string;
  region: string;
  environment: 'sandbox' | 'dev' | 'staging' | 'production';
  apiBaseUrl: string;
  cognitoRegion: string;
  cognitoUserPoolId: string;
  cognitoClientId: string;
  cognitoIssuerUrl: string;
  cognitoDomain: string;
  actionScopes: Readonly<{ read: string; write: string; admin: string }>;
  policyDigest: string;
  identityValuesAuthoritative: false;
  features: Readonly<Record<string, boolean>>;
  configVersion: string;
}

let config: AppConfig | null = null;

export const loadConfig = async (): Promise<AppConfig> => {
  if (config) return config;

  const controller = new AbortController();
  const timeout = window.setTimeout(() => controller.abort(), 5000);
  try {
    const response = await fetch('/config.json', {
      cache: 'no-store',
      credentials: 'same-origin',
      headers: { Accept: 'application/json' },
      signal: controller.signal,
    });
    if (!response.ok) throw new RuntimeConfigError('RUNTIME_CONFIG_UNAVAILABLE');
    const serialized = await response.text();
    if (serialized.length === 0 || serialized.length > 65_536) {
      throw new RuntimeConfigError();
    }
    const parsed: unknown = JSON.parse(serialized);
    config = parseRuntimeConfig(parsed) as AppConfig;
    return config;
  } catch (error: unknown) {
    if (error instanceof RuntimeConfigError) throw error;
    throw new RuntimeConfigError();
  } finally {
    window.clearTimeout(timeout);
  }
};

export const getConfig = (): AppConfig => {
  if (!config) {
    throw new RuntimeConfigError('RUNTIME_CONFIG_NOT_LOADED');
  }
  return config;
};

export { RuntimeConfigError };
