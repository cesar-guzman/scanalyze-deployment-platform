import React, { useMemo } from 'react';
import type { ReactNode } from 'react';
import { AuthProvider as OidcProvider } from 'react-oidc-context';
import { WebStorageStateStore } from 'oidc-client-ts';
import { getConfig } from '../config';

export const AuthProvider: React.FC<{ children: ReactNode }> = ({ children }) => {
  const config = getConfig();
  const sessionStore = useMemo(
    () => new WebStorageStateStore({ store: window.sessionStorage }),
    [],
  );

  const oidcConfig = {
    authority: config.cognitoIssuerUrl,
    client_id: config.cognitoClientId,
    redirect_uri: config.redirectUri,
    response_type: 'code',
    scope: [
      'openid',
      'email',
      'profile',
      config.actionScopes.read,
      config.actionScopes.write,
      config.actionScopes.admin,
    ].join(' '),
    metadataSeed: {
      issuer: config.cognitoIssuerUrl,
      authorization_endpoint: `${config.cognitoDomain}/oauth2/authorize`,
      token_endpoint: `${config.cognitoDomain}/oauth2/token`,
      userinfo_endpoint: `${config.cognitoDomain}/oauth2/userInfo`,
      jwks_uri: `${config.cognitoIssuerUrl}/.well-known/jwks.json`,
      end_session_endpoint: `${config.cognitoDomain}/logout`,
    },
    requestTimeoutInSeconds: 5,
    staleStateAgeInSeconds: 300,
    stateStore: sessionStore,
    userStore: sessionStore,
    onSigninCallback: () => {
      window.history.replaceState(
        {},
        document.title,
        window.location.pathname
      );
    },
  };

  return (
    <OidcProvider {...oidcConfig}>
      {children}
    </OidcProvider>
  );
};
