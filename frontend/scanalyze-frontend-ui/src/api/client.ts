import axios from 'axios';
import { getConfig } from '../config';
import { User } from 'oidc-client-ts';
import { stepUpWithPasskey } from '../auth/PasskeyService';

class AuthSessionError extends Error {
  constructor() {
    super('AUTH_SESSION_INVALID');
    this.name = 'AuthSessionError';
  }
}

export const getApiClient = (expectedSubject?: string) => {
  const config = getConfig();

  const client = axios.create({
    baseURL: config.apiBaseUrl,
    headers: {
      'Content-Type': 'application/json'
    }
  });

  const getUserStorageKey = () => `oidc.user:${config.cognitoIssuerUrl}:${config.cognitoClientId}`;

  client.interceptors.request.use((req) => {
    try {
      const key = getUserStorageKey();
      const userStr = sessionStorage.getItem(key);
      if (!userStr) throw new AuthSessionError();
      const user = User.fromStorageString(userStr);
      if (!user.access_token || user.expired) throw new AuthSessionError();
      if (expectedSubject !== undefined && user.profile.sub !== expectedSubject) throw new AuthSessionError();
      req.headers.Authorization = `Bearer ${user.access_token}`;
    } catch {
      throw new AuthSessionError();
    }
    return req;
  });

  // Response interceptor to handle step-up challenge
  client.interceptors.response.use(
    (response) => response,
    async (error) => {
      if (error.response && error.response.status === 403) {
        // Simple heuristic: if we get a 403 and the error message implies missing assurance or unauthorized scope
        // Explicit, machine-readable step-up challenge signal
        const isAssuranceError = error.response.data?.details?.step_up_required === true;
        
        if (isAssuranceError) {
          const key = getUserStorageKey();
          const userStr = sessionStorage.getItem(key);
          if (userStr) {
            const user = User.fromStorageString(userStr);
            const username = user.profile['cognito:username'] || user.profile.email;
            if (username) {
              try {
                // Trigger native WebAuthn
                const tokenData = await stepUpWithPasskey(username as string);
                const newAccessToken = tokenData.access_token;
                
                // Update existing user session in storage and refresh expiration
                user.access_token = newAccessToken;
                if (tokenData.id_token) user.id_token = tokenData.id_token;
                if (tokenData.refresh_token) user.refresh_token = tokenData.refresh_token;
                
                // Decode payload to set new expires_at
                const payloadStr = newAccessToken.split('.')[1];
                if (payloadStr) {
                    const payload = JSON.parse(window.atob(payloadStr.replace(/-/g, '+').replace(/_/g, '/')));
                    if (payload.exp) user.expires_at = payload.exp;
                }
                
                sessionStorage.setItem(key, user.toStorageString());
                
                // Retry the original request with the new token
                const originalRequest = error.config;
                originalRequest.headers.Authorization = `Bearer ${newAccessToken}`;
                return axios(originalRequest);
              } catch (stepUpError) {
                console.error("Step-up authentication failed", stepUpError);
                throw stepUpError;
              }
            }
          }
        }
      }
      return Promise.reject(error);
    }
  );

  return client;
};
