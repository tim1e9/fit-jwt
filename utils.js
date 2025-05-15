// A helper method for retrieving environment variables.
const _getEnvVar = (varName, defaultValue, requiredField = false) => {
    const envVarVal = process.env[varName];
    if (!envVarVal && requiredField) {
        throw new Error(`Required environment variable missing: ${varName}`)
    }
    return envVarVal ? envVarVal : defaultValue;
}

// The JWT public key can be a bit hard to handle, so it gets special
const JWT_PUBLIC_KEY = `
-----BEGIN PUBLIC KEY-----
${_getEnvVar('OAUTH_JWT_PUBLIC_KEY', null, true)}
-----END PUBLIC KEY-----
`;

const getEnvironmentVariables = () => {
  // Load common environment variables
  const ev = {
      'OIDC_PROVIDER': _getEnvVar('OIDC_PROVIDER', null, true), // Which provider (e.g. keycloak)
      'OAUTH_HOST': _getEnvVar('OAUTH_HOST',null, true), 
      'OAUTH_REDIR_URI': _getEnvVar('OAUTH_REDIR_URI', '/auth/callback'), // The path relative to the host
      'CUR_HOSTNAME': _getEnvVar('CUR_HOSTNAME', null), // It's difficult to find the host, so specify it
      'CLIENT_ID':  _getEnvVar('CLIENT_ID', null, true),
      'CLIENT_SECRET': _getEnvVar('CLIENT_SECRET', null, true),
      'STATE': _getEnvVar('OAUTH_STATE', null, true),
      'RESPONSE_TYPE': _getEnvVar('OAUTH_RESP_TYPE', 'code'), // part of OAuth grant flow
      'JWT_PUBLIC_KEY': JWT_PUBLIC_KEY
  }

  // Load required and optional provider-specific variables
  const required_fields = _getEnvVar('PROVIDER_REQUIRED_FIELDS', null);
  if (required_fields) {
    for(const cur_reqd of required_fields.split(',')) {
      // non-intuitive: provider-specific env vars are prefixed
      // with the name of the provider (e.g. KEYCLOAK_REALM)
      // The env var is KEYCLOAK_REALM, but it saves it as REALM in ev.
      const trimmed = cur_reqd.replace(/^[^_]*_/, '');
      const val = _getEnvVar(cur_reqd, null, true);
      ev[trimmed] = val;
    }
  }
  const optional_fields = _getEnvVar('PROVIDER_OPTIONAL_FIELDS', null);
  if (optional_fields) {
    for(const cur_opt of optional_fields.split(',')) {
      const trimmed = cur_opt.replace(/^[^_]*_/, '');
      const val = _getEnvVar(cur_opt, null, false);
      ev[trimmed] = val;
    }
  }

  return ev;
}

// Let's face it - this is a big TODO right now
const getOidcProviderURL = (ev) => {
    let authURL;
    if (ev.OIDC_PROVIDER == 'keycloak') {
        authURL = `${ev.OAUTH_HOST}/realms/${ev.REALM_NAME}/protocol/openid-connect/auth?` 
           + `client_id=${ev.CLIENT_ID}&scope=${ev.SCOPE}&response_type=${ev.RESPONSE_TYPE}&`
           + `redirect_uri=${ev.REDIRECT_URI}&state=${ev.STATE}`;
    } else if (ev.OIDC_PROVIDER == 'google') {
      authURL = "foo";
    } else {
      throw new Error(`Unknown provider encountered: ${ev.OIDC_PROVIDER}`)
    }
    return authURL;
}

const getTokenURL = (ev) => {
  // The Keycloak-specific URL for requesting a token. (This differs from the authtication URL)
  const tokenURL = `${ev.OAUTH_HOST}/realms/${ev.REALM_NAME}/protocol/openid-connect/token`
  return tokenURL;
}

export { getEnvironmentVariables, getOidcProviderURL, getTokenURL }