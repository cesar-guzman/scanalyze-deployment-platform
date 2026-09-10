import { getConfig } from '../config';

function base64UrlDecode(base64Url: string) {
  const padding = '='.repeat((4 - base64Url.length % 4) % 4);
  const base64 = (base64Url + padding).replace(/-/g, '+').replace(/_/g, '/');
  const rawData = window.atob(base64);
  const outputArray = new Uint8Array(rawData.length);
  for (let i = 0; i < rawData.length; ++i) {
    outputArray[i] = rawData.charCodeAt(i);
  }
  return outputArray;
}

function arrayBufferToBase64Url(buffer: ArrayBuffer) {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return window.btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

export async function stepUpWithPasskey(username: string): Promise<string> {
  const config = getConfig();
  const baseUrl = config.apiBaseUrl;

  // 1. Initiate passkey auth
  const initResponse = await fetch(`${baseUrl}/auth/passkey/initiate`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username })
  });
  
  if (!initResponse.ok) {
    throw new Error('Failed to initiate passkey authentication');
  }
  
  const initData = await initResponse.json();
  const challengeParams = initData.challenge_parameters;
  const credentialRequestOptionsStr = challengeParams['CREDENTIAL_REQUEST_OPTIONS'];
  
  if (!credentialRequestOptionsStr) {
    throw new Error('No CREDENTIAL_REQUEST_OPTIONS returned');
  }

  const options = JSON.parse(credentialRequestOptionsStr);
  
  // Convert challenge string to Uint8Array
  if (options.challenge && typeof options.challenge === 'string') {
    options.challenge = base64UrlDecode(options.challenge);
  }
  // Convert allowCredentials ids
  if (options.allowCredentials) {
    for (const cred of options.allowCredentials) {
      if (typeof cred.id === 'string') {
        cred.id = base64UrlDecode(cred.id);
      }
    }
  }

  // 2. Browser native passkey request
  const assertion = await navigator.credentials.get({ publicKey: options }) as PublicKeyCredential;
  if (!assertion) {
    throw new Error('Passkey assertion failed or cancelled');
  }

  // 3. Prepare response for Cognito
  const authData = assertion.response as AuthenticatorAssertionResponse;
  
  const challengeResponses = {
    USERNAME: username,
    CREDENTIAL: JSON.stringify({
      id: assertion.id,
      rawId: arrayBufferToBase64Url(assertion.rawId),
      type: assertion.type,
      response: {
        authenticatorData: arrayBufferToBase64Url(authData.authenticatorData),
        clientDataJSON: arrayBufferToBase64Url(authData.clientDataJSON),
        signature: arrayBufferToBase64Url(authData.signature),
        userHandle: authData.userHandle ? arrayBufferToBase64Url(authData.userHandle) : undefined
      }
    })
  };

  // 4. Respond to challenge
  const respondResponse = await fetch(`${baseUrl}/auth/passkey/respond`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      username,
      session: initData.session,
      challenge_responses: challengeResponses
    })
  });

  if (!respondResponse.ok) {
    throw new Error('Failed to verify passkey');
  }

  const respondData = await respondResponse.json();
  if (!respondData.access_token) {
    throw new Error('Failed to get access token from passkey response');
  }

  return respondData.access_token;
}
