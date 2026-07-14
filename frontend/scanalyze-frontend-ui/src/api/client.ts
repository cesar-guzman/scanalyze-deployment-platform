import axios from 'axios';
import { getConfig } from '../config';
import { User } from 'oidc-client-ts';

class AuthSessionError extends Error {
  constructor() {
    super('AUTH_SESSION_INVALID');
    this.name = 'AuthSessionError';
  }
}

export const getApiClient = () => {
  const config = getConfig();

  const client = axios.create({
    baseURL: config.apiBaseUrl,
    headers: {
      'Content-Type': 'application/json'
    }
  });

  client.interceptors.request.use((req) => {
    try {
      const key = `oidc.user:${config.cognitoIssuerUrl}:${config.cognitoClientId}`;

      const userStr = sessionStorage.getItem(key);
      if (!userStr) throw new AuthSessionError();
      const user = User.fromStorageString(userStr);
      if (!user.access_token || user.expired) throw new AuthSessionError();
      req.headers.Authorization = `Bearer ${user.access_token}`;
    } catch {
      throw new AuthSessionError();
    }
    return req;
  });

  return client;
};
