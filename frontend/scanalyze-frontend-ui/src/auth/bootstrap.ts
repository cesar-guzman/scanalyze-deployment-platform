import { useEffect, useState } from 'react';

export const AUTH_OPERATION_TIMEOUT_MS = 6_000;
export const AUTH_CALLBACK_STATE_MAX_AGE_SECONDS = 300;

interface CallbackStateBinding {
  readonly cognitoIssuerUrl: string;
  readonly cognitoClientId: string;
  readonly redirectUri: string;
}

export class AuthOperationTimeoutError extends Error {
  code: string;

  constructor(code: string) {
    super(code);
    this.name = 'AuthOperationTimeoutError';
    this.code = code;
  }
}

export const withAuthOperationTimeout = async <T>(
  operation: Promise<T>,
  code: string,
  timeoutMs = AUTH_OPERATION_TIMEOUT_MS,
): Promise<T> => {
  let timeout: ReturnType<typeof setTimeout> | undefined;
  const deadline = new Promise<never>((_resolve, reject) => {
    timeout = globalThis.setTimeout(
      () => reject(new AuthOperationTimeoutError(code)),
      timeoutMs,
    );
  });

  try {
    return await Promise.race([operation, deadline]);
  } finally {
    if (timeout !== undefined) globalThis.clearTimeout(timeout);
  }
};

export const buildCognitoLogoutUrl = (
  cognitoDomain: string,
  clientId: string,
  logoutUri: string,
): string => {
  const endpoint = new URL('/logout', `${cognitoDomain}/`);
  endpoint.searchParams.set('client_id', clientId);
  endpoint.searchParams.set('logout_uri', logoutUri);
  return endpoint.toString();
};

export const scrubAuthCallbackUrl = (): void => {
  if (window.location.pathname !== '/callback') return;
  if (window.location.search === '' && window.location.hash === '') return;
  window.history.replaceState({}, document.title, '/callback');
};

export const preflightAuthCallback = (binding: CallbackStateBinding): string | null => {
  if (window.location.pathname !== '/callback' || window.location.search === '') return null;

  const parameters = new URLSearchParams(window.location.search);
  const codes = parameters.getAll('code');
  const errors = parameters.getAll('error');
  const states = parameters.getAll('state');
  const hasResponse = codes.length > 0 || errors.length > 0;
  if (!hasResponse) return null;

  const responseIsClosed = (
    (codes.length === 1 && errors.length === 0 && codes[0] !== '')
    || (errors.length === 1 && codes.length === 0 && errors[0] !== '')
  );
  const state = states.length === 1 ? states[0] : '';
  const stateIsClosed = /^[A-Za-z0-9._~-]{16,512}$/.test(state);
  let stateIsValid = false;
  if (stateIsClosed) {
    try {
      const serialized = window.sessionStorage.getItem(`oidc.${state}`);
      if (serialized !== null && serialized.length <= 8_192) {
        const stored: unknown = JSON.parse(serialized);
        if (stored !== null && typeof stored === 'object' && !Array.isArray(stored)) {
          const candidate = stored as Record<string, unknown>;
          const created = candidate.created;
          const age = typeof created === 'number'
            ? Math.floor(Date.now() / 1_000) - created
            : -1;
          stateIsValid = (
            candidate.id === state
            && candidate.request_type === 'si:r'
            && typeof created === 'number'
            && Number.isInteger(created)
            && age >= 0
            && age <= AUTH_CALLBACK_STATE_MAX_AGE_SECONDS
            && candidate.authority === binding.cognitoIssuerUrl
            && candidate.client_id === binding.cognitoClientId
            && candidate.redirect_uri === binding.redirectUri
            && typeof candidate.code_verifier === 'string'
            && /^[A-Za-z0-9_-]{43,128}$/.test(candidate.code_verifier)
            && !Object.prototype.hasOwnProperty.call(candidate, 'client_secret')
          );
        }
      }
    } catch {
      stateIsValid = false;
    }
  }

  if (responseIsClosed && stateIsValid) return null;
  scrubAuthCallbackUrl();
  return 'AUTH_CALLBACK_INVALID';
};

const hasErrorName = (error: unknown, expected: string): boolean => {
  if (!error || typeof error !== 'object') return false;
  const candidate = error as { name?: unknown; innerError?: unknown };
  return candidate.name === expected || hasErrorName(candidate.innerError, expected);
};

export const isOidcTimeout = (error: unknown): boolean => (
  hasErrorName(error, 'ErrorTimeout') || hasErrorName(error, 'AbortError')
);

export const loginErrorCode = (error: unknown): string => (
  isOidcTimeout(error) ? 'OIDC_DISCOVERY_TIMEOUT' : 'OIDC_DISCOVERY_INVALID'
);

export const callbackErrorCode = (error: unknown): string => (
  isOidcTimeout(error) ? 'AUTH_CALLBACK_TIMEOUT' : 'AUTH_CALLBACK_INVALID'
);

export const useOperationTimeout = (
  active: boolean,
  timeoutMs = AUTH_OPERATION_TIMEOUT_MS,
): boolean => {
  const [timedOut, setTimedOut] = useState(false);

  useEffect(() => {
    if (!active) return undefined;
    const timeout = window.setTimeout(() => setTimedOut(true), timeoutMs);
    return () => window.clearTimeout(timeout);
  }, [active, timeoutMs]);

  return active && timedOut;
};
