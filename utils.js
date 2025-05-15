// @ts-check
import asn1 from 'asn1.js';

const RSAPublicKeyASN = asn1.define('RSAPublicKey', function () {
  this.seq().obj(this.key('n').int(), this.key('e').int());
});

const getPublicKey = (ev, key_id) => {
  // Find the correct key (by id), and assemble a standard public key
  const keys = ev['JWKS_KEYS'];
  const jwk = keys.find(k => k.kid === key_id);
  if (!jwk) {
    throw new Error(`No key found for key with ID: ${key_id}`);
  }

  const n = Buffer.from(jwk.n, 'base64url');
  const e = Buffer.from(jwk.e, 'base64url');
  const derKey = RSAPublicKeyASN.encode({
    n: new asn1.bignum(n),
    e: new asn1.bignum(e)
  }, 'der');

  const base64PublicKey = derKey.toString('base64');
  const fullPublicKey = `
-----BEGIN RSA PUBLIC KEY-----
${base64PublicKey}
-----END RSA PUBLIC KEY-----
`;
  return fullPublicKey;
}

// A helper method for retrieving environment variables.
const _getEnvVar = (varName, defaultValue, requiredField = false) => {
  const envVarVal = process.env[varName];
  if (!envVarVal && requiredField) {
    throw new Error(`Required environment variable missing: ${varName}`)
  }
  return envVarVal ? envVarVal : defaultValue;
}

const getEnvironmentVariables = async () => {
  // Load common environment variables
  const ev = {
    'OIDC_PROVIDER': _getEnvVar('OIDC_PROVIDER', null, true), // Which provider (e.g. keycloak)
    'OAUTH_HOST': _getEnvVar('OAUTH_HOST', null, true),
    'OAUTH_REDIR_URI': _getEnvVar('OAUTH_REDIR_URI', '/auth/callback'), // The path relative to the host
    'CUR_HOSTNAME': _getEnvVar('CUR_HOSTNAME', null), // It's difficult to find the host, so specify it
    'CLIENT_ID': _getEnvVar('CLIENT_ID', null, true),
    'CLIENT_SECRET': _getEnvVar('CLIENT_SECRET', null, true),
    'STATE': _getEnvVar('OAUTH_STATE', null, true),
    'RESPONSE_TYPE': _getEnvVar('OAUTH_RESP_TYPE', 'code'), // part of OAuth grant flow
    'JWKS_URL': _getEnvVar('JWKS_URL', null, true), // URL to pull public keys
    // 'JWT_PUBLIC_KEY': JWT_PUBLIC_KEY
  }

  // Load required and optional provider-specific variables
  const required_fields = _getEnvVar('PROVIDER_REQUIRED_FIELDS', null);
  if (required_fields) {
    for (const cur_reqd of required_fields.split(',')) {
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
    for (const cur_opt of optional_fields.split(',')) {
      const trimmed = cur_opt.replace(/^[^_]*_/, '');
      const val = _getEnvVar(cur_opt, null, false);
      ev[trimmed] = val;
    }
  }

  // Load the keys (JWKS)
  const res = await fetch(ev.JWKS_URL, {
    method: 'GET', headers: { 'Content-Type': 'application/json' }
  });
  const { keys } = await res.json();
  ev['JWKS_KEYS'] = keys;

  return ev;
}

// TODO - fix this
// Let's face it - this is a big TODO right now
const getOidcProviderURL = (ev) => {
  let authURL;
  if (ev.OIDC_PROVIDER == 'keycloak') {
    authURL = `${ev.OAUTH_HOST}/realms/${ev.REALM_NAME}/protocol/openid-connect/auth?`
      + `client_id=${ev.CLIENT_ID}&scope=${ev.SCOPE}&response_type=${ev.RESPONSE_TYPE}&`
      + `redirect_uri=${ev.CUR_HOSTNAME + ev.OAUTH_REDIR_URI}&state=${ev.STATE}`;
  } else if (ev.OIDC_PROVIDER == 'google') {
    authURL = `${ev.OAUTH_HOST}?`
      + `client_id=${ev.CLIENT_ID}&scope=${encodeURIComponent(ev.SCOPE)}&`
      + `response_type=${ev.RESPONSE_TYPE}&`
      + `redirect_uri=${encodeURIComponent(ev.CUR_HOSTNAME + ev.OAUTH_REDIR_URI)}&`
      + `state=${ev.STATE}`;
  } else {
    throw new Error(`Unknown provider encountered: ${ev.OIDC_PROVIDER}`)
  }
  return authURL;
}

const getTokenURL = (ev) => {
  let tokenURL;
  if (ev.OIDC_PROVIDER == 'keycloak') {
    // The Keycloak-specific URL for requesting a token. (This differs from the authtication URL)
    tokenURL = `${ev.OAUTH_HOST}/realms/${ev.REALM_NAME}/protocol/openid-connect/token`
  } else if (ev.OIDC_PROVIDER == 'google') {
    tokenURL = 'https://oauth2.googleapis.com/token';
  } else {
    throw new Error(`Unknown provider encountered: ${ev.OIDC_PROVIDER}`)
  }
  return tokenURL;
}

export { getEnvironmentVariables, getOidcProviderURL, getTokenURL, getPublicKey }