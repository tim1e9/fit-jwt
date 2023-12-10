import axios from 'axios';
import { randomBytes, createHash, createVerify } from 'crypto';


const getEnvVar = (varName, defaultValue, requiredField = false) => {
        const envVarVal = process.env[varName];
        if (!envVarVal && requiredField) {
            throw new Error(`Required environment variable missing: ${varName}`)
        }
        return envVarVal ? envVarVal : defaultValue;
}

// Constants loaded from the environment (with defaults)
const CONST_REALM_NAME = getEnvVar('REALM_NAME', null, true);
const CONST_OAUTH_HOST = getEnvVar('OAUTH_HOST',null, true);
const CONST_CLIENT_ID = getEnvVar('CLIENT_ID', null, true);
const CONST_CLIENT_SECRET = getEnvVar('CLIENT_SECRET', null, true);
const CONST_STATE = getEnvVar('OAUTH_STATE', null, true);
const CONST_SCOPE = getEnvVar('OAUTH_SCOPE', 'openid');
const CONST_RESPONSE_TYPE = getEnvVar('OAUTH_RESP_TYPE', 'code');
const CONST_JWT_PUBLIC_KEY_RAW = getEnvVar('OAUTH_JWT_PUBLIC_KEY', null, true);
const CONST_JWT_PUBLIC_KEY = `
-----BEGIN PUBLIC KEY-----
${CONST_JWT_PUBLIC_KEY_RAW}
-----END PUBLIC KEY-----
`;

const CONST_CUR_HOSTNAME = getEnvVar('CUR_HOSTNAME', null);
const CONST_REDIRECT_URI = CONST_CUR_HOSTNAME + getEnvVar('OAUTH_REDIR_URI', '/auth/callback');

// Keycloak-specific URLs
const AUTH_URL = `${CONST_OAUTH_HOST}/realms/${CONST_REALM_NAME}/protocol/openid-connect/auth?` 
           + `client_id=${CONST_CLIENT_ID}&scope=${CONST_SCOPE}&response_type=${CONST_RESPONSE_TYPE}&`
           + `redirect_uri=${CONST_REDIRECT_URI}&state=${CONST_STATE}`;
const tokenURL = `${CONST_OAUTH_HOST}/realms/${CONST_REALM_NAME}/protocol/openid-connect/token`

const isValidSignature = (rawToken) => {
    try {
        const [ rawTokenHeader, rawTokenPayload, rawTokenSignature] = rawToken.split('.');
        const tokenSignature = Buffer.from(rawTokenSignature, 'base64');

        // As of now, only RS256 is supported. Consider adding support for HS256
        const tokenHeader = JSON.parse(Buffer.from(rawTokenHeader, 'base64').toString('utf-8'));
        if (tokenHeader.alg != "RS256") {
            console.error(`Only the RS256 algorithm is supported. Current algorithm: ${tokenHeader.alg}`)
            return false;
        }

        // Reconstitute the header and payload
        const contentToVerify = `${rawTokenHeader}.${rawTokenPayload}`
        const rs256verifier = createVerify('RSA-SHA256');
        rs256verifier.update(contentToVerify);
        const result = rs256verifier.verify(CONST_JWT_PUBLIC_KEY, tokenSignature);
        return result;
    } catch(exc) {
        console.error(`Error verifying the JWT signature: ${exc.message}`);
        return false;
    }
}

const getPkceDetails = (pkceMethod) => {
    const codeVerifier = randomBytes(32).toString('base64')
            .replace(/=/g, '').replace(/\+/g,'-',).replace(/\//,'_');
    const codeChallenge = createHash('sha256').update(codeVerifier).digest('base64')
            .replace(/=/g, '').replace(/\+/g,'-',).replace(/\//,'_');

    // If the pkecMethod is 'plain' then don't encode. Other wise, use S256
    return {
        codeVerifier: codeVerifier,
        codeChallenge: (pkceMethod == 'plain') ? codeVerifier : codeChallenge,
        method: pkceMethod
    };
}

const getAuthURL = (pkceDetails) => {
    return (!pkceDetails) ? AUTH_URL :
        AUTH_URL + `&code_challenge=${pkceDetails.codeChallenge}&code_challenge_method=${pkceDetails.method}`
}

const getJwtToken = async (code, codeVerifier) => {
    // The token request requires authentication (naturally). Unfortunately, it's not obvious
    // that it consists of the base64-encoded client ID and client secret. Now it is obvious.
    const base64Creds = Buffer.from(`${CONST_CLIENT_ID}:${CONST_CLIENT_SECRET}`).toString('base64');
    const authHeader = 'Basic ' + base64Creds;

    let response = {};
    try {
        response = await axios.post( tokenURL, {
                'code': code,
                'grant_type': 'authorization_code',
                'client_id': CONST_CLIENT_ID,
                'redirect_uri': CONST_REDIRECT_URI,
                'code_verifier': codeVerifier
            }, 
            {
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
                'Authorization': authHeader
            }
        });
    } catch(exc) {
        console.log(`Error: Exception thrown when attempting to obtain a token: ${exc.message}`);
        return null;
    }

    const jwtTokens = {
        'accessToken': response.data.access_token,
        'idToken': response.data.id_token,
        'refreshToken': response.data.refresh_token
    }
    return jwtTokens;
}

const refreshJwtToken = async (refreshToken) => {
    const base64Creds = Buffer.from(`${CONST_CLIENT_ID}:${CONST_CLIENT_SECRET}`).toString('base64');
    const authHeader = 'Basic ' + base64Creds;

    let response = {};
    try {
        response = await axios.post( tokenURL, {
                'grant_type': 'refresh_token',
                'client_id': CONST_CLIENT_ID,
                'refresh_token': refreshToken
            }, 
            {
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
                'Authorization': authHeader
            }
        });
    } catch(exc) {
        console.log(`Error: Exception thrown when attempting to refresh a token: ${exc.message}`);
        return null;
    }

    const jwtTokens = {
        'accessToken': response.data.access_token,
        'idToken': response.data.id_token,
        'refreshToken': response.data.refresh_token
    }
    return jwtTokens;
}


const getUserFromToken = (accessToken, verifyTimestamp = true, verifySignature = true) => {
    try {
        const [_jwtHeader, jwtPayload, _jwtSignature] = accessToken.split('.');
        if (verifySignature) {
            if (!isValidSignature(accessToken)) {
                console.error('ERROR: JSON Signature is not valid!')
                return null;
            }
        } else {
            console.warn('WARNING: Signature not verified. THIS IS A REALLY BAD IDEA!');
        }

        const user = JSON.parse(Buffer.from(jwtPayload, 'base64').toString());

        if (verifyTimestamp) {
            // Check to see if the token has expired
            const expTime = user.exp * 1000;  // The time is in seconds; convert it to milliseconds
            const curTime = new Date().getTime();
            if (expTime < curTime) {
                console.log('The token has expired');
                return null;
            }
        }

        return user;
    } catch(exc) {
        console.log(`Error parsing the user from a token: ${exc.message}`);
    }
    return null;
}

export {
    getAuthURL,
    getPkceDetails,
    getJwtToken,
    refreshJwtToken,
    getUserFromToken
}