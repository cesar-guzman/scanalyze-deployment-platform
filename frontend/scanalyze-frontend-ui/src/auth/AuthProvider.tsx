import React from 'react';
import type { ReactNode } from 'react';
import { AuthProvider as OidcProvider } from 'react-oidc-context';
import { WebStorageStateStore } from 'oidc-client-ts';
import { getConfig } from '../config';

export const AuthProvider: React.FC<{ children: ReactNode }> = ({ children }) => {
  const config = getConfig();
  const currentOrigin = window.location.origin;

  const oidcConfig = {
    authority: config.cognitoIssuerUrl,
    client_id: config.cognitoClientId,
    redirect_uri: `${currentOrigin}/callback`,
    post_logout_redirect_uri: `${currentOrigin}/`,
    response_type: 'code',
    scope: [
      'openid',
      'email',
      'profile',
      config.actionScopes.read,
      config.actionScopes.write,
      config.actionScopes.admin,
    ].join(' '),
    userStore: new WebStorageStateStore({ store: window.sessionStorage }),
    onSigninCallback: () => {
      window.history.replaceState(
        {},
        document.title,
        window.location.pathname
      );
    }
  };

  return (
    <OidcProvider {...oidcConfig}>
      {children}
    </OidcProvider>
  );
};
