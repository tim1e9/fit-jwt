// @ts-check
import { Buffer } from 'buffer';

// ------------- Helper methods for converting key components into an RSA public key
function _encodeLength(len) {
  if (len < 128) {
    return Buffer.from([len]);
  } else {
    const hex = len.toString(16);
    const lenBytes = Buffer.from(hex.padStart(hex.length + (hex.length % 2), '0'), 'hex');
    return Buffer.concat([Buffer.from([0x80 + lenBytes.length]), lenBytes]);
  }
}

function _encodeASN1Integer(buf) {
  while (buf.length > 1 && buf[0] === 0x00 && (buf[1] & 0x80) === 0) {
    buf = buf.slice(1);
  }
  if (buf[0] & 0x80) {
    buf = Buffer.concat([Buffer.from([0x00]), buf]);
  }
  return Buffer.concat([Buffer.from([0x02]), _encodeLength(buf.length), buf]);
}

function _encodeASN1Sequence(bufs) {
  const totalLength = bufs.reduce((acc, buf) => acc + buf.length, 0);
  return Buffer.concat([Buffer.from([0x30]), _encodeLength(totalLength), ...bufs]);
}
// ------------------------------------------------------------------------------------------------

// Given a key ID, reconstitute an RSA public key. (They made this way harder than it needed to be.)
const getPublicKey = (ev, key_id) => {
  const keys = ev['JWKS_KEYS'];
  const jwk = keys.find(k => k.kid === key_id);
  if (!jwk) {
    throw new Error(`No key found for key with ID: ${key_id}. Retrieve new keys?`);
  }

  const n = Buffer.from(jwk.n, 'base64url');
  const e = Buffer.from(jwk.e, 'base64url');
  const der = _encodeASN1Sequence([
    _encodeASN1Integer(n),
    _encodeASN1Integer(e),
  ]);

  const base64PublicKey = der.toString('base64');
  const lines = base64PublicKey.match(/.{1,64}/g) || [];
  return ['-----BEGIN RSA PUBLIC KEY-----', lines.join('\n'), '-----END RSA PUBLIC KEY-----'].join('\n');
};


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
    'AUTH_ENDPOINT': _getEnvVar('AUTH_ENDPOINT', null, true),
    'TOKEN_ENDPOINT': _getEnvVar('TOKEN_ENDPOINT', null, true),
    'OAUTH_REDIR_URI': _getEnvVar('OAUTH_REDIR_URI', '/auth/callback'), // The path relative to the host
    'CUR_HOSTNAME': _getEnvVar('CUR_HOSTNAME', null), // It's difficult to find the host, so specify it
    'CLIENT_ID': _getEnvVar('CLIENT_ID', null, true),
    'CLIENT_SECRET': _getEnvVar('CLIENT_SECRET', null, true),
    'STATE': _getEnvVar('OAUTH_STATE', null, true),
    'SCOPE': _getEnvVar('OAUTH_SCOPE', null, true),
    'RESPONSE_TYPE': _getEnvVar('OAUTH_RESP_TYPE', 'code'), // part of OAuth grant flow
    'JWKS_URL': _getEnvVar('JWKS_URL', null, true), // URL to pull public keys
  }

  // Load the keys (JWKS)
  const res = await fetch(ev.JWKS_URL, {
    method: 'GET', headers: { 'Content-Type': 'application/json' }
  });
  const { keys } = await res.json();
  ev['JWKS_KEYS'] = keys;

  return ev;
}

const getOidcProviderURL = (ev) => {
  const params = new URLSearchParams({
    client_id: ev.CLIENT_ID,
    scope: ev.SCOPE,
    response_type: ev.RESPONSE_TYPE,
    redirect_uri: ev.CUR_HOSTNAME + ev.OAUTH_REDIR_URI,
    state: ev.STATE,
  });
  return `${ev.AUTH_ENDPOINT}?${params.toString()}`;
};

const getTokenURL = (ev) => {
  return ev.TOKEN_ENDPOINT;
}

export { getEnvironmentVariables, getOidcProviderURL, getTokenURL, getPublicKey }
