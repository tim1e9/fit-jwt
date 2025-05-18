// Use @ts-check intermittently, because this is actually JavaScript
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


const getEnvironmentVariables = async () => {
  // Load common environment variables
  const ev = {
    'AUTH_ENDPOINT': process.env['AUTH_ENDPOINT'],
    'TOKEN_ENDPOINT': process.env['TOKEN_ENDPOINT'],
    'OAUTH_REDIR_URI': process.env['OAUTH_REDIR_URI'] || '/auth/callback', // The path relative to the host
    'CUR_HOSTNAME': process.env['CUR_HOSTNAME'], // It's difficult to find the host, so specify it
    'CLIENT_ID': process.env['CLIENT_ID'],
    'CLIENT_SECRET': process.env['CLIENT_SECRET'],
    'STATE': process.env['OAUTH_STATE'],
    'SCOPE': process.env['OAUTH_SCOPE'],
    'RESPONSE_TYPE': process.env['OAUTH_RESP_TYPE'] || 'code', // part of OAuth grant flow
    'JWKS_URL': process.env['JWKS_URL'], // URL to pull public keys
  }
  if (Object.values(ev).some(v => !v)) {
    throw new Error(`Not all environment variables are defined. Please review all required fields.`)
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
