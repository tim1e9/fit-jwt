// @ts-check intermittently, because this is actually JavaScript
import { Buffer } from 'buffer';
import { createVerify } from 'crypto';

let ev; // Environment variables are stored here

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
const getPublicKey = (key_id) => {
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
  ev = {
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
  // @ts-ignore
  const res = await fetch(ev.JWKS_URL, {
    method: 'GET', headers: { 'Content-Type': 'application/json' }
  });
  const { keys } = await res.json();
  ev['JWKS_KEYS'] = keys;

  return ev;
}

const getOidcProviderURL = () => {
  const params = new URLSearchParams({
    client_id: ev.CLIENT_ID,
    scope: ev.SCOPE,
    response_type: ev.RESPONSE_TYPE,
    redirect_uri: ev.CUR_HOSTNAME + ev.OAUTH_REDIR_URI,
    state: ev.STATE,
  });
  return `${ev.AUTH_ENDPOINT}?${params.toString()}`;
};

const getTokenURL = () => {
  return ev.TOKEN_ENDPOINT;
}

// Some folks don't validate the signature. That would be a pretty big mistake
const _isValidSignature = (rawToken) => {
    try {
        const [ rawTokenHeader, rawTokenPayload, rawTokenSignature] = rawToken.split('.');
        const tokenSignature = Buffer.from(rawTokenSignature, 'base64url');

        // As of now, only RS256 is supported. Consider adding support for HS256
        const tokenHeader = JSON.parse(Buffer.from(rawTokenHeader, 'base64url').toString('utf-8'));
        if (tokenHeader.alg != "RS256") {
            console.error(`Only the RS256 algorithm is supported. Current algorithm: ${tokenHeader.alg}`)
            return false;
        }

        // Reconstitute the header and payload
        const contentToVerify = `${rawTokenHeader}.${rawTokenPayload}`
        const rs256verifier = createVerify('RSA-SHA256');
        rs256verifier.update(contentToVerify);
        const publicKey = getPublicKey(tokenHeader.kid);
        const result = rs256verifier.verify(publicKey, tokenSignature);
        return result;
    } catch(exc) {
        console.error(`Error verifying the JWT signature: ${exc.message}`);
        return false;
    }
}

const isTokenValid = (curToken, verifyTimestamp = true, verifySignature = true) => {
    try {
        const [_jwtHeader, jwtPayload, _jwtSignature] = curToken.split('.');
        if (verifySignature) {
            if (!_isValidSignature(curToken)) {
                throw new Error('The JSON signature is not valid.')
            }
        } else {
            console.warn('WARNING: Signature not verified. THIS IS A REALLY BAD IDEA!');
        }

        const jwtDetails = JSON.parse(Buffer.from(jwtPayload, 'base64url').toString());

        // More checks: An attacker could replay a valid token from another client or issuer
        // Make sure the returned values match what's expected
        if (jwtDetails.aud != ev.CLIENT_ID) {
            throw new Error(`The token audience doesn't match what was sent`)
        }
        // The issuer is the host, but a simple way to test is to see how it compares to the JWKS URL
        if (ev.JWKS_URL.substring(jwtDetails.iss) < 0) {
            throw new Error(`The issuer for the token is different from what is expected.`)
        }

        if (verifyTimestamp) {
            // Check to see if the token has expired
            const expTime = jwtDetails.exp * 1000;  // The time is in seconds; convert it to milliseconds
            const curTime = new Date().getTime();
            if (expTime < curTime) {
                throw new Error('The token has expired');
            }
        }

        return true;
    } catch(exc) {
        console.error(`Error parsing the jwtDetails from a token: ${exc.message}`);
    }
    return false;
}


export { getEnvironmentVariables, getOidcProviderURL, getTokenURL, getPublicKey, isTokenValid }
